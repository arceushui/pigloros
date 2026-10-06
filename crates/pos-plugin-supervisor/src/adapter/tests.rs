//! Unit tests of the adapter's mapping, staging, receipts, quarantine table
//! and registration. The pass-level tests are in `tests/community_pass.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_core::{
    ActionRejected, CanonicalBytes, Capability, CoreError, EntityId, EventDraft, Kind,
    PipelineOutcomeV1, ProposedAction,
};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, AtomicCommitFailureV1, ComponentTrapClassV1, EventDraftV1,
    GuestPluginErrorV1, PluginErrorCodeV1, TraceAnnotationV1, TrapReproductionV1,
};
use ulid::Ulid;

use super::failure::commit_failed;
use super::output::{approved_drafts, map_draft};
use super::*;
use crate::launch::WorkerProgramV1;
use crate::test_support::{self, METERING, SMALL_BUDGET};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

const DENIED: Error = commit_failed(AtomicCommitFailureV1::DeterministicTypedResult);

struct FixturePlugin {
    id: PluginId,
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "community-fixture"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("community.event")],
            has_driver: true,
            ..Capability::default()
        }
    }
}

/// Approves every proposal unchanged, counting the proposals it saw.
struct CountingApprover(Arc<AtomicUsize>);

impl ActionApprover for CountingApprover {
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert_eq!(proposal.capability.as_str(), APPROVAL_CAPABILITY_V1);
        Ok(EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
    }
}

/// Denies the payload `deny` and rewrites the payload `rewrite`.
struct ScriptedApprover;

impl ActionApprover for ScriptedApprover {
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        match proposal.payload.as_slice() {
            b"deny" => Err(ActionRejected::CapabilityNotGranted),
            b"rewrite" => Ok(EventDraft::new(
                proposal.actor_entity_id,
                proposal.event_type.clone(),
                CanonicalBytes::from_static(b"rewritten"),
            )),
            _ => Ok(EventDraft::new(
                proposal.actor_entity_id,
                proposal.event_type.clone(),
                proposal.payload.clone(),
            )),
        }
    }
}

/// A context source that counts its calls and answers with a fixed result.
struct FixedSource {
    calls: Arc<AtomicUsize>,
    refusal: Option<Error>,
}

impl InvocationContextSourceV1 for FixedSource {
    fn context(
        &mut self,
        _: TimelineId,
        _: &ObservationView<'_>,
    ) -> Result<InvocationContextV1, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.refusal.map_or_else(
            || {
                Ok(InvocationContextV1 {
                    invocation: test_support::invocation(b"observation"),
                    host_inputs: HostInputs { simulation_time: 1 },
                })
            },
            Err,
        )
    }
}

fn draft(event_type: &str, payload: &[u8]) -> EventDraftV1 {
    EventDraftV1 {
        event_schema_id: 1,
        entity_id: [7; 16],
        event_type: event_type.to_owned(),
        canonical_payload: payload.to_vec(),
        dependency_digests: Vec::new(),
    }
}

/// A valid output echoing the fixture invocation, with one annotation.
fn output(drafts: Vec<EventDraftV1>) -> PluginOutputV1 {
    let mut output = PluginOutputV1 {
        invocation_id: test_support::invocation(b"observation").invocation_id,
        event_drafts: drafts,
        next_state_schema: [5; 32],
        next_state_bytes: b"next".to_vec(),
        trace_annotations: vec![TraceAnnotationV1 {
            annotation_schema_id: 9,
            canonical_bytes: b"trace".to_vec(),
            dependency_digests: Vec::new(),
        }],
        consumed_dependencies: Vec::new(),
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    output
}

fn report(output: PluginOutputV1) -> InvocationReportV1<PluginOutputV1> {
    InvocationReportV1 {
        result: Ok(output),
        metering: METERING,
        operational_log: Vec::new(),
    }
}

fn initial() -> CommunityStateV1 {
    CommunityStateV1 {
        schema: [9; 32],
        bytes: b"initial".to_vec(),
    }
}

fn fixture(
    refusal: Option<Error>,
    approver: Box<dyn ActionApprover>,
) -> (CommunityDriverV1, CommunityPluginHandleV1, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let supervisor = WorkerProgramV1::new(PathBuf::from("/worker"))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, Duration::from_secs(1)));
    let (driver, handle) = CommunityDriverV1::new(CommunityDriverConfigV1 {
        plugin_id: PluginId::new(),
        name: "community-fixture",
        tick_interval: Duration::from_millis(250),
        subscriptions: vec![ProjectionKey::new(EntityId::new())],
        supervisor: supervisor
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor"))),
        negotiated: test_support::negotiated_with("plugin-a", SMALL_BUDGET, Vec::new()),
        component: b"component".to_vec(),
        source: Box::new(FixedSource {
            calls: Arc::clone(&calls),
            refusal,
        }),
        approver,
        initial_state: initial(),
    });
    (driver, handle, calls)
}

fn accepting() -> Box<dyn ActionApprover> {
    Box::new(ScriptedApprover)
}

fn every_error() -> Vec<(Error, Option<PluginAvailabilityV1>)> {
    use PluginAvailabilityV1 as Availability;
    let trap = Error::ComponentTrap {
        class: ComponentTrapClassV1::Other,
        reproduction: TrapReproductionV1::Unverified,
    };
    let exhausted = Some(Availability::ResourceExhausted);
    vec![
        (Error::InvalidManifest, None),
        (Error::ArtifactTrustDenied, None),
        (Error::ArtifactRevoked, Some(Availability::Revoked)),
        (Error::IncompatibleAbi, None),
        (Error::MissingFeature { index: 0 }, None),
        (Error::CapabilityDenied { index: 0 }, None),
        (Error::InvalidInvocation, None),
        (Error::InvalidGuestOutput, None),
        (Error::UnsupportedSchema, None),
        (Error::StateMigrationFailed, None),
        (Error::GuestDeclaredFailure, None),
        (trap, Some(Availability::Trapped)),
        (Error::WorkerCrashed, Some(Availability::Unavailable)),
        (Error::FuelExhausted, exhausted),
        (Error::MemoryLimitExceeded, exhausted),
        (Error::HostCallLimitExceeded, exhausted),
        (Error::OutputLimitExceeded, exhausted),
        (Error::DeterministicDeadlineExceeded, None),
        (Error::OperationalWatchdogStop, None),
        (DENIED, None),
    ]
}

#[test]
fn only_traps_resource_limits_revocation_and_crashes_quarantine() {
    for (error, expected) in every_error() {
        assert_eq!(quarantine_for(error), expected, "{error:?}");
    }
}

#[test]
fn a_failed_pass_is_classified_by_its_commit_contract() {
    let host = PassFailureV1::Host;
    let operational = commit_failed(AtomicCommitFailureV1::Operational);
    let rejected = Box::new(PipelineOutcomeV1::Rejected);
    let not_admitted = RuntimeError::ScheduledPassNotAdmitted(rejected);
    let unknown = RuntimeError::Store(CoreError::StorageOutcomeUnknown("lost".to_owned()));
    let frozen = RuntimeError::Store(CoreError::ErasureAccessFrozen);
    let crashed = RuntimeError::from(Error::WorkerCrashed);
    assert_eq!(classify_pass_failure(&not_admitted), host(DENIED));
    assert_eq!(classify_pass_failure(&unknown), PassFailureV1::InDoubt);
    assert_eq!(classify_pass_failure(&frozen), host(operational));
    assert_eq!(classify_pass_failure(&crashed), host(Error::WorkerCrashed));
    for unrelated in [
        RuntimeError::PendingDriverStep,
        RuntimeError::NoScheduledAdmissionInDoubt,
    ] {
        assert_eq!(classify_pass_failure(&unrelated), PassFailureV1::Unrelated);
    }
}

#[test]
fn a_draft_maps_to_an_event_draft_or_is_rejected() {
    let mapped = ok(map_draft(&EventDraftV1 {
        entity_id: *b"0123456789abcdef",
        ..draft("community.event", b"payload")
    }));
    let entity = EntityId::from_ulid(Ulid::from(u128::from_be_bytes(*b"0123456789abcdef")));
    assert_eq!(mapped.entity, entity);
    assert_eq!(mapped.event_type, Kind::new("community.event"));
    assert_eq!(mapped.payload.as_slice(), b"payload");
    assert_eq!(mapped.causation_id, None);

    let with_dependency = EventDraftV1 {
        dependency_digests: vec![[1; 32]],
        ..draft("community.event", b"p")
    };
    for rejected in [
        draft("Community.Event", b"p"),
        draft("", b"p"),
        with_dependency,
    ] {
        assert_eq!(map_draft(&rejected), Err(Error::InvalidGuestOutput));
    }
}

#[test]
fn drafts_are_mapped_then_approved_in_the_guests_order() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counting = CountingApprover(Arc::clone(&calls));
    let drafts = ok(approved_drafts(
        &counting,
        &output(vec![draft("a.b", b"one"), draft("c.d", b"two")]),
    ));
    let payloads: Vec<&[u8]> = drafts.iter().map(|d| d.payload.as_slice()).collect();
    assert_eq!(payloads, [&b"one"[..], &b"two"[..]]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // The approver's own draft is the committed one.
    let rewritten = ok(approved_drafts(
        &ScriptedApprover,
        &output(vec![draft("a.b", b"rewrite")]),
    ));
    assert_eq!(rewritten[0].payload.as_slice(), b"rewritten");

    // A draft that cannot map stops everything before any approval.
    calls.store(0, Ordering::SeqCst);
    let unmappable = output(vec![draft("a.b", b"one"), draft("BAD", b"two")]);
    assert_eq!(
        approved_drafts(&counting, &unmappable),
        Err(Error::InvalidGuestOutput)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_typed_denial_or_an_oversize_payload_is_a_deterministic_commit_failure() {
    let denied = output(vec![draft("a.b", b"ok"), draft("a.b", b"deny")]);
    assert_eq!(approved_drafts(&ScriptedApprover, &denied), Err(DENIED));
    let oversize = output(vec![draft("a.b", &[0; 4097])]);
    assert_eq!(approved_drafts(&ScriptedApprover, &oversize), Err(DENIED));
    let at_bound = output(vec![draft("a.b", &[0; 4096])]);
    assert_eq!(ok(approved_drafts(&ScriptedApprover, &at_bound)).len(), 1);
}

#[test]
fn a_valid_output_is_staged_with_a_receipt_until_the_batch_commits() {
    let (mut driver, handle, _) = fixture(None, accepting());
    let valid = output(vec![draft("community.event", b"payload")]);
    let digest = valid.output_digest;
    let staged = ok(driver.accept([3; 16], report(valid)));
    assert_eq!(staged.drafts.len(), 1);
    assert_eq!(
        driver.staged,
        Some(CommunityStateV1 {
            schema: [5; 32],
            bytes: b"next".to_vec()
        })
    );
    // The next state is not adopted before the batch commits.
    assert_eq!(handle.committed_state(), initial());
    let receipts = handle.receipts();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.invocation_id, [3; 16]);
    assert_eq!(receipt.negotiated, driver.negotiated);
    assert_eq!(receipt.output_digest, Some(digest));
    assert_eq!(receipt.limits, driver.negotiated.limits());
    assert_eq!(receipt.metering, METERING);
    assert_eq!(receipt.dropped_trace_annotations, 1);
    assert_eq!(receipt.disposition, ReceiptDispositionV1::Staged);

    driver.commit_step();
    assert_eq!(driver.staged, None);
    assert_eq!(handle.committed_state().bytes, b"next");
    assert_eq!(handle.committed_state().schema, [5; 32]);
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Committed
    );
    // A second commit has nothing staged and changes nothing.
    driver.commit_step();
    assert_eq!(handle.committed_state().bytes, b"next");
}

#[test]
fn an_abort_discards_the_staged_state_and_receipt() {
    let (mut driver, handle, _) = fixture(None, accepting());
    ok(driver.accept([3; 16], report(output(vec![draft("a.b", b"p")]))));
    driver.abort_step();
    assert_eq!(driver.staged, None);
    assert_eq!(handle.committed_state(), initial());
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Discarded
    );
    // A discarded receipt is never committed afterwards.
    driver.commit_step();
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Discarded
    );
}

#[test]
fn an_unmappable_denied_or_declared_failure_stages_nothing() {
    let (mut driver, handle, _) = fixture(None, accepting());
    let unmappable = output(vec![draft("BAD", b"p")]);
    let digest = unmappable.output_digest;
    assert_eq!(
        driver.accept([1; 16], report(unmappable)).err(),
        Some(Error::InvalidGuestOutput)
    );
    let denied = output(vec![draft("a.b", b"deny")]);
    assert_eq!(driver.accept([2; 16], report(denied)).err(), Some(DENIED));
    let declared = InvocationReportV1 {
        result: Err(GuestPluginErrorV1 {
            code: PluginErrorCodeV1::DeterministicBudgetExhausted,
            canonical_coordinate: None,
            related_digest: None,
        }),
        metering: METERING,
        operational_log: Vec::new(),
    };
    assert_eq!(
        driver.accept([3; 16], declared).err(),
        Some(Error::GuestDeclaredFailure)
    );
    assert_eq!(driver.staged, None);
    let receipts = handle.receipts();
    let digests: Vec<_> = receipts.iter().map(|r| r.output_digest).collect();
    assert_eq!(digests[0], Some(digest));
    assert_eq!(digests[2], None);
    assert!(receipts
        .iter()
        .all(|r| r.disposition == ReceiptDispositionV1::Discarded));
    assert_eq!(receipts[2].dropped_trace_annotations, 0);
    assert_eq!(receipts[0].dropped_trace_annotations, 1);
}

#[test]
fn the_prior_state_is_always_the_one_the_adapter_holds() {
    let mut invocation = test_support::invocation(b"observation");
    invocation.prior_state_schema = [0xee; 32];
    invocation.prior_state_bytes = b"host supplied".to_vec();
    let replaced = with_prior_state(invocation, &initial());
    assert_eq!(replaced.prior_state_schema, [9; 32]);
    assert_eq!(replaced.prior_state_bytes, b"initial");
}

#[test]
fn receipts_are_bounded_and_the_oldest_is_dropped() {
    let (driver, handle, _) = fixture(None, accepting());
    let limit = u64::try_from(MAX_RETAINED_RECEIPTS_V1).unwrap_or(u64::MAX);
    for index in 0..=limit {
        let mut receipt = driver_receipt(&driver);
        receipt.metering.host_calls = index;
        driver.shared.push_receipt(receipt);
    }
    let receipts = handle.receipts();
    assert_eq!(receipts.len(), MAX_RETAINED_RECEIPTS_V1);
    assert_eq!(receipts[0].metering.host_calls, 1);
    assert_eq!(receipts[MAX_RETAINED_RECEIPTS_V1 - 1].metering.host_calls, limit);
}

fn driver_receipt(driver: &CommunityDriverV1) -> CommunityInvocationReceiptV1 {
    CommunityInvocationReceiptV1 {
        invocation_id: [0; 16],
        negotiated: driver.negotiated.clone(),
        output_digest: None,
        limits: driver.negotiated.limits(),
        metering: METERING,
        dropped_trace_annotations: 0,
        disposition: ReceiptDispositionV1::Discarded,
    }
}

#[test]
fn a_refused_invocation_marks_or_quarantines_only_by_its_class() {
    for (error, quarantine) in every_error() {
        let (mut driver, handle, calls) = fixture(Some(error), accepting());
        let failed = err(driver.step(TimelineId::new(), ObservationView::empty()));
        assert!(
            matches!(failed, RuntimeError::CommunityPlugin(refused) if refused == error),
            "{error:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(handle.last_failure(), Some(error));
        assert_eq!(
            handle.availability(),
            quarantine.unwrap_or(PluginAvailabilityV1::Available),
            "{error:?}"
        );
    }
}

#[test]
fn a_quarantined_adapter_refuses_to_run_until_it_is_cleared() {
    let (mut driver, handle, calls) = fixture(Some(Error::FuelExhausted), accepting());
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let refused = err(driver.step(TimelineId::new(), ObservationView::empty()));
    assert!(matches!(
        refused,
        RuntimeError::Composition(PluginCompositionErrorV1::ImplementationUnavailable {
            plugin_id,
            availability: PluginAvailabilityV1::ResourceExhausted,
        }) if plugin_id == handle.plugin_id()
    ));
    // The refusal never reached the context source and is not a new failure.
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut registry = PluginRegistry::new();
    let plugin = FixturePlugin {
        id: handle.plugin_id(),
    };
    ok(registry.register_pinned_generated(
        &plugin,
        PluginRegistrationV1::new(community_pin(), PluginAvailabilityV1::Available),
        None,
        None,
    ));
    ok(handle.sync_registry(&mut registry));
    assert_eq!(
        registry.availability(plugin.id),
        Some(PluginAvailabilityV1::ResourceExhausted)
    );
    ok(handle.clear_quarantine(&mut registry));
    assert_eq!(
        registry.availability(plugin.id),
        Some(PluginAvailabilityV1::Available)
    );
    assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
    assert_eq!(handle.last_failure(), None);
    // Cleared, the adapter runs again and reaches its source.
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn syncing_an_unregistered_plugin_leaves_the_handle_quarantined() {
    let (mut driver, handle, _) = fixture(Some(Error::WorkerCrashed), accepting());
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    let mut registry = PluginRegistry::new();
    for result in [
        handle.sync_registry(&mut registry),
        handle.clear_quarantine(&mut registry),
    ] {
        assert!(matches!(
            err(result),
            RuntimeError::Composition(PluginCompositionErrorV1::MissingImplementation { .. })
        ));
    }
    assert_eq!(handle.availability(), PluginAvailabilityV1::Unavailable);
    assert_eq!(handle.last_failure(), Some(Error::WorkerCrashed));
}

#[test]
fn a_step_drops_a_stale_staged_state_first() {
    let (mut driver, handle, _) = fixture(Some(Error::InvalidInvocation), accepting());
    ok(driver.accept([1; 16], report(output(vec![draft("a.b", b"p")]))));
    assert!(driver.staged.is_some());
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    assert_eq!(driver.staged, None);
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Discarded
    );
}

#[test]
fn the_driver_reports_its_configuration() {
    let (driver, _, _) = fixture(None, accepting());
    assert_eq!(driver.name(), "community-fixture");
    assert_eq!(driver.tick_interval(), Duration::from_millis(250));
    assert_eq!(driver.subscriptions().len(), 1);
    assert!(!driver.requires_snapshot_anchor());
}

fn community_pin() -> PluginPinV1 {
    pin_with(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::GovernedCommunity,
    )
}

fn pin_with(kind: DomainImplementationKindV1, isolation: PluginIsolationV1) -> PluginPinV1 {
    ok(PluginPinV1::try_new(
        kind,
        isolation,
        pos_core::Hash::from_bytes([1; 32]),
        vec!["community".to_owned()],
    ))
}

#[test]
fn registration_is_pinned_community_and_non_participant() {
    let (driver, handle, _) = fixture(None, accepting());
    let plugin = FixturePlugin {
        id: handle.plugin_id(),
    };
    let mut registry = PluginRegistry::new();
    ok(register_community_driver(
        &mut registry,
        &plugin,
        community_pin(),
        &handle,
        driver,
    ));
    assert_eq!(
        registry.scheduled_binding(plugin.id),
        Some(ScheduledDriverBindingV1::NonParticipant)
    );
    assert_eq!(
        registry.availability(plugin.id),
        Some(PluginAvailabilityV1::Available)
    );
    assert_eq!(registry.driver_count(), 1);
}

#[test]
fn registration_rejects_a_foreign_plugin_or_a_non_community_pin() {
    let native = pin_with(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
    );
    let adapter = pin_with(
        DomainImplementationKindV1::PublicAdapter,
        PluginIsolationV1::GovernedCommunity,
    );
    let both = pin_with(
        DomainImplementationKindV1::PublicAdapter,
        PluginIsolationV1::OperatorTrustedNative,
    );
    for (pin, expected) in [
        (native, PluginPinFieldV1::Isolation),
        (adapter, PluginPinFieldV1::ImplementationKind),
        (both, PluginPinFieldV1::ImplementationKind),
    ] {
        let (driver, handle, _) = fixture(None, accepting());
        let plugin = FixturePlugin {
            id: handle.plugin_id(),
        };
        let mut registry = PluginRegistry::new();
        let rejected = err(register_community_driver(
            &mut registry,
            &plugin,
            pin,
            &handle,
            driver,
        ));
        assert!(matches!(
            rejected,
            RuntimeError::Composition(PluginCompositionErrorV1::IncompatibleImplementation {
                field,
                ..
            }) if field == expected
        ));
        assert_eq!(registry.driver_count(), 0);
    }

    let (driver, handle, _) = fixture(None, accepting());
    let foreign = FixturePlugin { id: PluginId::new() };
    let mut registry = PluginRegistry::new();
    let rejected = err(register_community_driver(
        &mut registry,
        &foreign,
        community_pin(),
        &handle,
        driver,
    ));
    assert!(matches!(
        rejected,
        RuntimeError::Composition(PluginCompositionErrorV1::InvalidMetadata)
    ));
    assert_eq!(registry.driver_count(), 0);
}
