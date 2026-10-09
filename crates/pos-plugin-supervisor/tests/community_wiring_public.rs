//! Black-box tests of the Driver adapter's wiring to the execution-time trust gate (ADR-061
//! revision 7 decisions 2, 3 and 8, #583).
//!
//! Every test drives a real `CommunityDriverV1` through the public `Driver` trait and the
//! handle's authorization slot. The authorizations come from the `test-support` constructor, so
//! no gate and no signed release is involved; a worker is the `test-support` probe or, where a
//! refusal must prove that none was started, a program that does not exist.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pos_core::{PluginId, TimelineId};
use pos_crypto::plugin_execution::PluginCapabilityDescriptorV1;
use pos_crypto::plugin_manifest::component_digest_v1;
use pos_plugin_release::ContentValidationV1;
use pos_plugin_supervisor::test_support::{
    self, err, negotiated_under, ok, AuthorizationFields, SMALL_BUDGET, TICK, TPS1_DIGEST,
};
use pos_plugin_supervisor::{
    CommunityDriverConfigV1, CommunityDriverSettingsV1, CommunityDriverV1, CommunityPluginHandleV1,
    CommunityPluginSupervisorV1, CommunityStateV1, InvocationBindingV1, InvocationContextSourceV1,
    InvocationContextV1, ReceiptDispositionV1, WorkerProgramV1,
};
use pos_runtime::community_plugin_host::{
    CommunityPassV1, CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1,
    CommunityPluginHostErrorV1, GatedCommunityReleaseV1, HostInputs, NegotiatedCommunityPluginV1,
    TrustDenialBasisV1,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};

type Error = CommunityPluginHostErrorV1;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
/// A program that does not exist: a launch would end `WorkerCrashed`.
const MISSING: &str = "/nonexistent/pos-plugin-worker";
const PLUGIN: &str = "plugin-a";
/// The probe's behaviour: one Event.
const DRAFT: &[u8] = b"draft:community.alpha";
/// The fixture invocation ID.
const INVOCATION_ID: [u8; 16] = [0x11; 16];
const UNAVAILABLE: Error = Error::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};
const NOT_ACTIVE: Error = Error::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::NotActive,
};

/// What the context source saw and what it will refuse.
#[derive(Default)]
struct Log {
    calls: usize,
    bindings: Vec<InvocationBindingV1>,
    refusals: VecDeque<Error>,
}

type SharedLog = Arc<Mutex<Log>>;

fn locked(log: &SharedLog) -> MutexGuard<'_, Log> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Count the call, keep its binding and take the refusal scripted for it, if any.
fn record(log: &SharedLog, binding: InvocationBindingV1) -> Option<Error> {
    let mut log = locked(log);
    log.calls += 1;
    log.bindings.push(binding);
    log.refusals.pop_front()
}

/// Copies the binding it is given into the fixture invocation, as a host source must.
struct Source(SharedLog);

impl InvocationContextSourceV1 for Source {
    fn context(
        &mut self,
        _: TimelineId,
        _: &ObservationView<'_>,
        binding: InvocationBindingV1,
    ) -> Result<InvocationContextV1, Error> {
        let refusal = record(&self.0, binding);
        refusal.map_or_else(
            || {
                Ok(InvocationContextV1 {
                    invocation: test_support::bound(
                        test_support::invocation(b"observation"),
                        binding,
                    ),
                    host_inputs: HostInputs { simulation_time: 1 },
                })
            },
            Err,
        )
    }
}

fn driver_settings(program: &str) -> (CommunityDriverSettingsV1, SharedLog) {
    let log = SharedLog::default();
    let supervisor = WorkerProgramV1::new(PathBuf::from(program))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, Duration::from_mins(1)));
    let settings = CommunityDriverSettingsV1 {
        plugin_id: PluginId::new(),
        name: "wiring",
        tick_interval: Duration::from_millis(100),
        subscriptions: Vec::new(),
        supervisor: supervisor
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor"))),
        source: Box::new(Source(Arc::clone(&log))),
        initial_state: CommunityStateV1 {
            schema: [9; 32],
            bytes: b"initial".to_vec(),
        },
    };
    (settings, log)
}

/// One Driver, its handle, and what is needed to authorize it.
struct Rig {
    driver: CommunityDriverV1,
    handle: CommunityPluginHandleV1,
    log: SharedLog,
    record: NegotiatedCommunityPluginV1,
    component: Vec<u8>,
}

impl Rig {
    fn under(
        program: &str,
        component: &[u8],
        profile: &CommunityPluginExecutionProfileV1,
    ) -> Self {
        let (settings, log) = driver_settings(program);
        let config = test_support::config_under(PLUGIN, component, profile, settings);
        let (driver, handle) = CommunityDriverV1::new(config);
        Self {
            driver,
            handle,
            log,
            record: negotiated_under(PLUGIN, SMALL_BUDGET, Vec::new(), profile),
            component: component.to_vec(),
        }
    }

    fn new(program: &str, component: &[u8]) -> Self {
        Self::under(program, component, &test_support::fixture_profile())
    }

    /// The authorization of this Driver's own release, bytes, Tick and TPS1 digest.
    fn authorization(&self) -> AuthorizationFields {
        AuthorizationFields::for_release(&self.record, &self.component)
    }

    /// Offer the Driver the authorization `fields` describe, in `pass`.
    fn offer_with(&self, fields: &AuthorizationFields, pass: &CommunityPassV1) {
        let authorization = fields.issue(pass);
        let () = ok(self.handle.offer_authorization(authorization));
    }

    /// Start a pass: offer the Driver its own authorization.
    fn offer(&self) {
        self.offer_with(&self.authorization(), &test_support::open_pass());
    }

    fn step(&mut self) -> Result<StepOutput, RuntimeError> {
        let observation = ObservationView::empty();
        self.driver.step(TimelineId::new(), observation)
    }

    /// The host error a failing step raises.
    fn refused(&mut self) -> Error {
        match err(self.step()) {
            RuntimeError::CommunityPlugin(error) => error,
            other => std::panic::resume_unwind(Box::new(format!("{other:?}"))),
        }
    }

    fn calls(&self) -> usize {
        locked(&self.log).calls
    }

    fn refuse_next(&self, error: Error) {
        locked(&self.log).refusals.push_back(error);
    }
}

/// R7-B1, R7-G11b: an empty slot is `TrustStateUnavailable` before the source runs.
#[test]
fn an_empty_slot_is_refused_before_the_source_runs() {
    let mut rig = Rig::new(MISSING, DRAFT);
    assert_eq!(rig.refused(), UNAVAILABLE);
    assert_eq!(rig.calls(), 0);
    assert_eq!(rig.handle.pass_failure(), Some(UNAVAILABLE));
    assert_eq!(rig.handle.pass_invocation_id(), None);
    assert!(rig.handle.receipts().is_empty());
}

/// R7-G11b: the first launch consumes the authorization, so a second step in the same pass finds
/// the slot empty and is refused before `source.context()` runs and with no worker started.
#[test]
fn a_second_step_in_the_same_pass_finds_the_slot_empty() {
    let mut rig = Rig::new(PROBE, DRAFT);
    rig.offer();
    let _staged = ok(rig.step());
    assert_eq!(rig.calls(), 1);
    assert_eq!(rig.refused(), UNAVAILABLE);
    assert_eq!(rig.calls(), 1);
    assert_eq!(rig.handle.receipts().len(), 1);
}

/// R7-B1: a step that fails before the launch leaves the authorization in the slot, and
/// `close_pass` drops it.
#[test]
fn a_step_that_fails_before_the_launch_keeps_the_authorization_until_the_pass_closes() {
    let mut rig = Rig::new(PROBE, DRAFT);
    rig.offer();
    rig.refuse_next(Error::InvalidManifest);
    assert_eq!(rig.refused(), Error::InvalidManifest);
    assert!(rig.handle.receipts().is_empty());
    // The authorization is still there: the retry launches with it.
    let _staged = ok(rig.step());
    assert_eq!(rig.calls(), 2);
    rig.offer();
    rig.handle.close_pass();
    assert_eq!(rig.refused(), UNAVAILABLE);
    assert_eq!(rig.calls(), 2);
}

/// R7-B1: an authorization of a closed pass is refused after the source ran, with no worker.
#[test]
fn an_authorization_of_a_closed_pass_is_refused_with_no_worker() {
    let mut rig = Rig::new(MISSING, DRAFT);
    let pass = test_support::open_pass();
    rig.offer_with(&rig.authorization(), &pass);
    pass.close_for_test();
    assert_eq!(rig.refused(), UNAVAILABLE);
    assert_eq!(rig.calls(), 1);
    let receipts = rig.handle.receipts();
    assert_eq!(receipts[0].failure, Some(UNAVAILABLE));
}

/// R7-B1: a `source.context()` error outranks `NotActive`, because the Driver calls the source
/// before the supervisor checks the authorization.
#[test]
fn a_context_error_outranks_a_foreign_authorization() {
    let mut rig = Rig::new(MISSING, DRAFT);
    let mut foreign = rig.authorization();
    foreign.plugin_id.push('x');
    rig.offer_with(&foreign, &test_support::open_pass());
    rig.refuse_next(Error::InvalidManifest);
    assert_eq!(rig.refused(), Error::InvalidManifest);
    assert_eq!(rig.refused(), NOT_ACTIVE);
    assert_eq!(rig.calls(), 2);
}

/// R7-B2: the source receives exactly the Tick and TPS1 digest of the authorization and the
/// profile digest of the record, and an invocation that copies them passes the supervisor.
#[test]
fn the_source_receives_the_bindings_and_a_copy_of_them_launches() {
    let mut rig = Rig::new(PROBE, DRAFT);
    rig.offer();
    let _staged = ok(rig.step());
    let expected = InvocationBindingV1 {
        tick: TICK,
        tps1_digest: TPS1_DIGEST,
        execution_profile_digest: rig.record.execution_profile_digest(),
    };
    assert!(expected.execution_profile_digest.is_some());
    assert_eq!(locked(&rig.log).bindings, [expected]);
}

/// R7-B2: a record without a profile digest gives the source a `None` digest, and the
/// supervisor refuses the launch with `InvalidInvocation`.
#[test]
fn a_record_without_a_profile_digest_is_an_invalid_invocation() {
    let profile = test_support::profile_without_digest();
    let mut rig = Rig::under(MISSING, DRAFT, &profile);
    rig.offer();
    assert_eq!(rig.refused(), Error::InvalidInvocation);
    let seen = locked(&rig.log).bindings[0];
    assert_eq!(seen.execution_profile_digest, None);
    assert_eq!(seen.tick, TICK);
    assert_eq!(seen.tps1_digest, TPS1_DIGEST);
}

/// R7-C2: held Component bytes that differ from the bytes the authorization names are
/// `NotActive` before any worker is spawned.
#[test]
fn other_bytes_than_the_authorization_names_are_not_active() {
    let mut rig = Rig::new(PROBE, DRAFT);
    let mut wrong = rig.authorization();
    wrong.component_digest = component_digest_v1(b"draft:community.beta");
    rig.offer_with(&wrong, &test_support::open_pass());
    assert_eq!(rig.refused(), NOT_ACTIVE);
    // The invocation ID was built before the supervisor refused.
    assert_eq!(rig.handle.pass_invocation_id(), Some(INVOCATION_ID));
    assert_eq!(rig.handle.pass_failure(), Some(NOT_ACTIVE));
    // Equal bytes launch.
    rig.handle.close_pass();
    rig.offer();
    let _staged = ok(rig.step());
}

/// R7-B5: the receipt records the content-validation fact and the profile digest.
#[test]
fn a_receipt_records_the_content_validation_and_the_profile_digest() {
    let mut rig = Rig::new(PROBE, DRAFT);
    rig.offer();
    let _staged = ok(rig.step());
    let receipts = rig.handle.receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].content_validation, ContentValidationV1::NotPerformed);
    let digest = receipts[0].negotiated.execution_profile_digest();
    assert_eq!(digest, rig.record.execution_profile_digest());
    assert!(digest.is_some());
}

/// R7-B8: a Driver is built only from a gated release of the expected Plugin ID.
#[test]
fn a_driver_is_built_only_for_the_expected_plugin_id() {
    let gated = || test_support::gated_with(PLUGIN, SMALL_BUDGET, Vec::new(), Vec::new());
    let build = |expected: &str, gated| {
        let (settings, _log) = driver_settings(MISSING);
        let abi = CommunityPluginHostAbiV1::v1();
        CommunityDriverConfigV1::from_gated(
            gated,
            &abi,
            &test_support::fixture_profile(),
            expected,
            settings,
        )
    };
    assert!(build(PLUGIN, gated()).is_ok());
    assert_eq!(build("plugin-b", gated()).err(), Some(NOT_ACTIVE));
    // The identity check precedes negotiation, which refuses a required capability.
    let mut required = test_support::optional_capability();
    required.required = true;
    assert_eq!(
        build(PLUGIN, with_capability(required)).err(),
        Some(Error::CapabilityDenied { index: 0 })
    );
}

fn with_capability(capability: PluginCapabilityDescriptorV1) -> GatedCommunityReleaseV1 {
    test_support::gated_with(PLUGIN, SMALL_BUDGET, vec![capability], Vec::new())
}

/// R7-B8: an offer into an occupied slot is refused with `InvalidInvocation` and leaves the
/// first authorization intact.
#[test]
fn an_offer_into_an_occupied_slot_is_refused_and_keeps_the_first() {
    let mut rig = Rig::new(PROBE, DRAFT);
    rig.offer();
    let mut later = rig.authorization();
    later.tick += 5;
    let second = later.issue(&test_support::open_pass());
    let refused = rig.handle.offer_authorization(second);
    assert_eq!(refused, Err(Error::InvalidInvocation));
    let _staged = ok(rig.step());
    assert_eq!(locked(&rig.log).bindings[0].tick, TICK);
}

/// R7-B9: a failing step and `record_refusal` set the pass failure, `invoke` sets the invocation
/// ID, and `offer_authorization` and `close_pass` clear both.
#[test]
fn the_pass_failure_and_the_invocation_id_live_for_one_pass() {
    let mut rig = Rig::new(PROBE, DRAFT);
    assert_eq!(rig.handle.pass_failure(), None);
    assert_eq!(rig.handle.pass_invocation_id(), None);
    // A failing step before the source answers sets the failure but no ID.
    rig.offer();
    rig.refuse_next(Error::InvalidManifest);
    assert_eq!(rig.refused(), Error::InvalidManifest);
    assert_eq!(rig.handle.pass_failure(), Some(Error::InvalidManifest));
    assert_eq!(rig.handle.pass_invocation_id(), None);
    rig.handle.close_pass();
    assert_eq!(rig.handle.pass_failure(), None);
    // A launch sets the ID; the next pass's offer clears it.
    rig.offer();
    let _staged = ok(rig.step());
    assert_eq!(rig.handle.pass_invocation_id(), Some(INVOCATION_ID));
    assert_eq!(rig.handle.pass_failure(), None);
    rig.offer();
    assert_eq!(rig.handle.pass_invocation_id(), None);
    // The host's own refusal is the pass failure and also the last failure.
    rig.handle.record_refusal(Error::WorkerCrashed);
    assert_eq!(rig.handle.pass_failure(), Some(Error::WorkerCrashed));
    assert_eq!(rig.handle.last_failure(), Some(Error::WorkerCrashed));
    rig.handle.close_pass();
    assert_eq!(rig.handle.pass_failure(), None);
    assert_eq!(rig.handle.last_failure(), Some(Error::WorkerCrashed));
}

/// R7-B9: `receipt_for` returns the newest receipt of a repeated ID and `None` for an unknown
/// one.
#[test]
fn receipt_for_returns_the_newest_match() {
    use ReceiptDispositionV1::{Committed, Staged};
    let mut rig = Rig::new(PROBE, DRAFT);
    rig.offer();
    let _first = ok(rig.step());
    rig.driver.commit_step();
    rig.offer();
    let _second = ok(rig.step());
    let dispositions: Vec<_> = rig
        .handle
        .receipts()
        .iter()
        .map(|receipt| receipt.disposition)
        .collect();
    assert_eq!(dispositions, [Committed, Staged]);
    let newest = rig.handle.receipt_for(INVOCATION_ID);
    assert_eq!(newest.map(|receipt| receipt.disposition), Some(Staged));
    assert!(rig.handle.receipt_for([0x77; 16]).is_none());
}
