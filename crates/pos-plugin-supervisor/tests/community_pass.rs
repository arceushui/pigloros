//! Pass-level tests of the community Plugin Driver adapter (ADR-061 r4, #543).
//!
//! Every test drives real scheduled passes through the registry, the local
//! admission host and an in-memory store, with the `test-support` probe worker
//! standing in for the Component worker. The probe's Component bytes name the
//! behaviour: `draft:<type>` returns one Event, `chain:<type>` echoes the
//! prior state into the Event and appends `+` to it, and the other names are
//! the probe's faults (see `tests/support/worker_probe.rs`).

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pos_core::{
    ActionApprover, ActionRejected, AppendDedupKey, AppendDedupScope, AppendIdentity,
    CanonicalBytes, Capability, CoreError, EntityId, ErasureContainmentGateV1, Event, EventDraft,
    EventStore, Hash, Kind, PipelineAdmissionBasisV1, PipelineAdmissionPortV1, PipelineAttemptIdV1,
    PipelineCommitReceiptV1, PipelineEvidenceRefV1, PipelineOutcomeV1, PipelineReceiptLookupV1,
    PipelineSecurityRevisionsV1, Plugin, PluginId, ProposedAction, PurgeOutcome, Seq, SeqRange,
    TimelineId,
};
use pos_plugin_supervisor::test_support::{self, negotiated_with, SMALL_BUDGET};
use pos_plugin_supervisor::{
    classify_pass_failure, register_community_driver, CommunityDriverConfigV1, CommunityDriverV1,
    CommunityPluginHandleV1, CommunityPluginSupervisorV1, CommunityStateV1,
    InvocationContextSourceV1, InvocationContextV1, PassFailureV1, ReceiptDispositionV1,
    WorkerProgramV1,
};
use pos_runtime::community_plugin_host::{
    AtomicCommitFailureV1, CommunityPluginHostErrorV1, ComponentTrapClassV1, HostInputs,
    TrapReproductionV1,
};
use pos_runtime::{
    DomainImplementationKindV1, LocalScheduledAdmissionHostV1, ObservationView,
    PluginAvailabilityV1, PluginCompositionErrorV1, PluginIsolationV1, PluginPinV1,
    PluginRegistry, RuntimeError, ScheduledDriverBindingV1, ScheduledPassAdmissionV1,
};
use pos_store::memory::MemoryStore;

type Error = CommunityPluginHostErrorV1;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
/// A generous watchdog for invocations that should finish promptly.
const PROMPT: Duration = Duration::from_mins(1);
/// A short watchdog for an invocation that must be stopped.
const SHORT: Duration = Duration::from_secs(1);
const DENIED: Error = Error::AtomicCommitFailed {
    failure: AtomicCommitFailureV1::DeterministicTypedResult,
};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

struct MemberPlugin {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
}

impl Plugin for MemberPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            has_driver: true,
            ..Capability::default()
        }
    }
}

/// The host's invocation inputs, one distinct invocation ID per member.
struct Source {
    invocation_id: [u8; 16],
}

impl InvocationContextSourceV1 for Source {
    fn context(
        &mut self,
        timeline: TimelineId,
        observation: &ObservationView<'_>,
    ) -> Result<InvocationContextV1, Error> {
        let mut invocation = test_support::invocation(b"observation");
        invocation.invocation_id = self.invocation_id;
        invocation.timeline_position.timeline_id = timeline.inner().to_bytes();
        invocation.timeline_position.seq = observation
            .anchor()
            .map_or(0, |anchor| anchor.observed_through().as_u64());
        Ok(InvocationContextV1 {
            invocation,
            host_inputs: HostInputs { simulation_time: 1 },
        })
    }
}

/// The host's approver: it approves every proposal unchanged.
struct Approver;

impl ActionApprover for Approver {
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        Ok(EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
    }
}

fn initial() -> CommunityStateV1 {
    CommunityStateV1 {
        schema: [9; 32],
        bytes: b"initial".to_vec(),
    }
}

/// Port that commits through the real store and then loses the outcome.
struct LostPort<'a>(&'a mut MemoryStore);

impl PipelineAdmissionPortV1 for LostPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.0.admit_pipeline_batch(basis).and_then(|_| {
            Err(CoreError::StorageOutcomeUnknown(
                "injected lost commit acknowledgement".to_owned(),
            ))
        })
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.0.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.0.purge_expired_pipeline_receipts_bounded(limit)
    }
}

/// One staged scheduled pass and the host inputs of its commit.
#[derive(Debug)]
struct Staged {
    head: Seq,
    revisions: PipelineSecurityRevisionsV1,
}

struct World {
    store: MemoryStore,
    registry: PluginRegistry,
    gate: Arc<ErasureContainmentGateV1>,
    timeline: TimelineId,
    members: u8,
    attempts: u8,
}

impl World {
    fn new() -> Self {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let mut store = MemoryStore::new();
        ok(store.bind_erasure_gate(Arc::clone(&gate)));
        let timeline = ok(store.create_timeline("community-pass")).id();
        Self {
            store,
            registry: PluginRegistry::new().with_erasure_gate(Arc::clone(&gate)),
            gate,
            timeline,
            members: 0,
            attempts: 0,
        }
    }

    /// Register one community Plugin whose Component bytes name the probe's
    /// behaviour.
    fn add(
        &mut self,
        name: &'static str,
        event_type: &'static str,
        component: &[u8],
        watchdog: Duration,
    ) -> CommunityPluginHandleV1 {
        self.members += 1;
        let plugin = MemberPlugin {
            id: PluginId::new(),
            name,
            event_type,
        };
        let supervisor = WorkerProgramV1::new(PathBuf::from(PROBE))
            .and_then(|program| CommunityPluginSupervisorV1::new(program, watchdog));
        let (driver, handle) = CommunityDriverV1::new(CommunityDriverConfigV1 {
            plugin_id: plugin.id,
            name,
            tick_interval: Duration::from_millis(100),
            subscriptions: Vec::new(),
            supervisor: supervisor
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor"))),
            negotiated: negotiated_with(name, SMALL_BUDGET, Vec::new()),
            component: component.to_vec(),
            source: Box::new(Source {
                invocation_id: [self.members; 16],
            }),
            approver: Box::new(Approver),
            initial_state: initial(),
        });
        let pin = ok(PluginPinV1::try_new(
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::GovernedCommunity,
            Hash::from_bytes([self.members; 32]),
            vec![format!("community-{name}")],
        ));
        ok(register_community_driver(
            &mut self.registry,
            &plugin,
            pin,
            &handle,
            driver,
        ));
        handle
    }

    /// Observe, then stage one anchored pass over the committed prefix.
    fn stage(&mut self) -> Result<Staged, RuntimeError> {
        let revisions = LocalScheduledAdmissionHostV1::shared()?.observe(
            &self.registry,
            &mut self.store,
            self.timeline,
        )?;
        let head = self.store.logical_head(self.timeline)?;
        let prefix = self.store.read(self.timeline, SeqRange::all())?;
        let chain = pos_core::fork_ancestry(&self.store, self.timeline)?;
        self.registry
            .step_all_anchored_with_events(self.timeline, &chain, head, &prefix)
            .map(|_| Staged { head, revisions })
    }

    /// The host's admission inputs for the staged pass, fresh each time.
    fn admission(&mut self, staged: &Staged) -> ScheduledPassAdmissionV1 {
        self.attempts += 1;
        let key = self.attempts;
        ScheduledPassAdmissionV1 {
            attempt_id: ok(PipelineAttemptIdV1::try_new([key; 16])),
            idempotency: AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([key; 32]),
                AppendDedupScope::from_keyed_hash([62; 32]),
            ),
            provider_validation: ok(PipelineEvidenceRefV1::try_new(Hash::from_bytes([60; 32]))),
            security_revisions: staged.revisions,
            commit_head: staged.head,
            commit_now_secs: 1,
        }
    }

    fn admit(&mut self, staged: &Staged) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let admission = self.admission(staged);
        self.registry
            .admit_scheduled_pass(&mut self.store, &admission)
    }

    /// Stage and atomically admit one whole pass.
    fn pass(&mut self) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let staged = self.stage()?;
        self.admit(&staged)
    }

    fn events(&self) -> Vec<Event> {
        ok(self.store.read(self.timeline, SeqRange::all()))
    }

    /// Mirror each handle's availability into the registry.
    fn sync(&mut self, handles: &[&CommunityPluginHandleV1]) {
        for handle in handles {
            ok(handle.sync_registry(&mut self.registry));
        }
    }
}

fn payloads(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .map(|event| event.payload.as_slice().to_vec())
        .collect()
}

fn dispositions(handle: &CommunityPluginHandleV1) -> Vec<ReceiptDispositionV1> {
    handle
        .receipts()
        .iter()
        .map(|receipt| receipt.disposition)
        .collect()
}

#[test]
fn a_pass_commits_every_draft_atomically_and_only_then_the_state() {
    let mut world = World::new();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"draft:community.beta", PROMPT);
    for handle in [&alpha, &beta] {
        let binding = world.registry.scheduled_binding(handle.plugin_id());
        assert_eq!(binding, Some(ScheduledDriverBindingV1::NonParticipant));
    }

    let staged = ok(world.stage());
    // Staged output commits nothing and adopts no state before the batch.
    assert!(world.events().is_empty());
    assert_eq!(alpha.committed_state(), initial());
    assert_eq!(beta.committed_state(), initial());
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Staged]);
    assert_eq!(dispositions(&beta), [ReceiptDispositionV1::Staged]);

    let receipt = ok(world.admit(&staged));
    assert_eq!(receipt.map(|r| r.committed_events().len()), Some(2));
    let events = world.events();
    assert_eq!(
        payloads(&events),
        [b"initial".to_vec(), b"community.beta".to_vec()]
    );
    let types: Vec<_> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(types, ["community.alpha", "community.beta"]);
    assert_eq!(alpha.committed_state().bytes, b"initial+");
    assert_eq!(beta.committed_state().bytes, b"next");
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Committed]);
    assert_eq!(dispositions(&beta), [ReceiptDispositionV1::Committed]);

    let receipts = alpha.receipts();
    assert_eq!(receipts[0].negotiated.plugin_id(), "alpha");
    assert_eq!(receipts[0].limits, receipts[0].negotiated.limits());
    assert_eq!(receipts[0].metering, test_support::METERING);
    assert!(receipts[0].output_digest.is_some());

    // The committed state is the prior state of the next invocation.
    ok(world.pass());
    assert_eq!(payloads(&world.events())[2], b"initial+");
    assert_eq!(alpha.committed_state().bytes, b"initial++");
}

/// One failing member in a pass beside one that succeeds.
struct Failure {
    component: &'static [u8],
    watchdog: Duration,
    error: Error,
    quarantine: Option<PluginAvailabilityV1>,
    receipts: usize,
}

fn failures() -> Vec<Failure> {
    let exhausted = Some(PluginAvailabilityV1::ResourceExhausted);
    let case = |component: &'static [u8], error, quarantine, receipts| Failure {
        component,
        watchdog: PROMPT,
        error,
        quarantine,
        receipts,
    };
    vec![
        case(b"fuel", Error::FuelExhausted, exhausted, 0),
        case(b"memory", Error::MemoryLimitExceeded, exhausted, 0),
        case(b"host-calls", Error::HostCallLimitExceeded, exhausted, 0),
        case(b"output-limit", Error::OutputLimitExceeded, exhausted, 0),
        case(
            b"trap",
            Error::ComponentTrap {
                class: ComponentTrapClassV1::StackExhausted,
                reproduction: TrapReproductionV1::Unverified,
            },
            Some(PluginAvailabilityV1::Trapped),
            0,
        ),
        case(
            b"exit",
            Error::WorkerCrashed,
            Some(PluginAvailabilityV1::Unavailable),
            0,
        ),
        case(
            b"abort",
            Error::WorkerCrashed,
            Some(PluginAvailabilityV1::Unavailable),
            0,
        ),
        case(b"bad-digest", Error::InvalidGuestOutput, None, 0),
        case(b"guest-error", Error::GuestDeclaredFailure, None, 1),
        case(b"deps:community.beta", Error::InvalidGuestOutput, None, 1),
        case(b"draft:Not.An.Id", Error::InvalidGuestOutput, None, 1),
        case(b"big:community.beta", DENIED, None, 1),
        Failure {
            watchdog: SHORT,
            ..case(b"hang", Error::OperationalWatchdogStop, None, 0)
        },
    ]
}

#[test]
fn any_plugin_failure_discards_the_whole_pass_and_marks_only_that_plugin() {
    for failure in failures() {
        let mut world = World::new();
        let alpha = world.add("alpha", "community.alpha", b"draft:community.alpha", PROMPT);
        let beta = world.add("beta", "community.beta", failure.component, failure.watchdog);

        let error = err(world.pass());
        let expected = PassFailureV1::Host(failure.error);
        assert_eq!(classify_pass_failure(&error), expected, "{}", failure.error);

        // Nothing committed: not the unaffected Plugin's Event, nor its state.
        assert!(world.events().is_empty(), "{}", failure.error);
        assert_eq!(alpha.committed_state(), initial());
        assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Discarded]);
        // The unaffected Plugin is never marked or quarantined.
        assert_eq!(alpha.last_failure(), None);
        assert_eq!(alpha.availability(), PluginAvailabilityV1::Available);

        assert_eq!(beta.last_failure(), Some(failure.error));
        let quarantine = failure.quarantine.unwrap_or(PluginAvailabilityV1::Available);
        assert_eq!(beta.availability(), quarantine, "{}", failure.error);
        assert_eq!(beta.receipts().len(), failure.receipts, "{}", failure.error);
        assert!(dispositions(&beta)
            .iter()
            .all(|disposition| *disposition == ReceiptDispositionV1::Discarded));

        world.sync(&[&alpha, &beta]);
        let (a, b) = (alpha.plugin_id(), beta.plugin_id());
        assert_eq!(
            world.registry.availability(a),
            Some(PluginAvailabilityV1::Available)
        );
        assert_eq!(world.registry.availability(b), Some(quarantine));
    }
}

#[test]
fn a_quarantined_plugin_blocks_passes_in_memory_until_the_host_clears_it() {
    let mut world = World::new();
    let alpha = world.add("alpha", "community.alpha", b"draft:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"fuel", PROMPT);
    let error = err(world.pass());
    assert_eq!(
        classify_pass_failure(&error),
        PassFailureV1::Host(Error::FuelExhausted)
    );
    world.sync(&[&alpha, &beta]);
    assert_eq!(alpha.receipts().len(), 1);

    // The registry refuses the pass before any Driver runs: no worker, no
    // state, no Event, and no new failure.
    let refused = err(world.pass());
    assert!(matches!(
        refused,
        RuntimeError::Composition(PluginCompositionErrorV1::ImplementationUnavailable {
            plugin_id,
            availability: PluginAvailabilityV1::ResourceExhausted,
        }) if plugin_id == beta.plugin_id()
    ));
    assert_eq!(classify_pass_failure(&refused), PassFailureV1::Unrelated);
    assert_eq!(alpha.receipts().len(), 1);
    assert!(world.events().is_empty());

    ok(beta.clear_quarantine(&mut world.registry));
    assert_eq!(beta.availability(), PluginAvailabilityV1::Available);
    assert_eq!(beta.last_failure(), None);
    // Cleared, the Plugin runs again, and fails again.
    let again = err(world.pass());
    assert_eq!(
        classify_pass_failure(&again),
        PassFailureV1::Host(Error::FuelExhausted)
    );
    assert_eq!(alpha.receipts().len(), 2);
}

#[test]
fn a_typed_non_commit_and_a_store_error_discard_the_pass_and_classify() {
    let mut world = World::new();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"draft:community.beta", PROMPT);

    // A typed non-committed outcome: an Event committed after staging moves
    // the Logical Head, so the store reports an admission conflict.
    let staged = ok(world.stage());
    ok(world.store.append(
        world.timeline,
        &[EventDraft::new(
            EntityId::new(),
            Kind::new("human.action"),
            CanonicalBytes::from_static(b"human"),
        )],
    ));
    let conflict = err(world.admit(&staged));
    assert!(matches!(
        conflict,
        RuntimeError::ScheduledPassNotAdmitted(ref outcome)
            if matches!(**outcome, PipelineOutcomeV1::AdmissionConflict)
    ));
    assert_eq!(
        classify_pass_failure(&conflict),
        PassFailureV1::Host(DENIED)
    );
    assert_eq!(world.events().len(), 1);

    // A store error: the erasure fence froze the Timeline after staging.
    let staged = ok(world.stage());
    world.gate.freeze_timeline_for_test(world.timeline);
    let frozen = err(world.admit(&staged));
    assert!(matches!(
        frozen,
        RuntimeError::Store(CoreError::ErasureAccessFrozen)
    ));
    let operational = Error::AtomicCommitFailed {
        failure: AtomicCommitFailureV1::Operational,
    };
    assert_eq!(
        classify_pass_failure(&frozen),
        PassFailureV1::Host(operational)
    );
    assert_eq!(world.events().len(), 1);

    // Both discarded every staged Driver output and quarantined nobody.
    for handle in [&alpha, &beta] {
        assert_eq!(handle.committed_state(), initial());
        assert_eq!(
            dispositions(handle),
            [ReceiptDispositionV1::Discarded, ReceiptDispositionV1::Discarded]
        );
        assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
        assert_eq!(handle.last_failure(), None);
    }
}

#[test]
fn a_lost_commit_outcome_keeps_the_staged_state_for_recovery() {
    let mut world = World::new();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"draft:community.beta", PROMPT);
    let staged = ok(world.stage());
    let admission = world.admission(&staged);
    let lost = err(world
        .registry
        .admit_scheduled_pass(&mut LostPort(&mut world.store), &admission));
    assert_eq!(classify_pass_failure(&lost), PassFailureV1::InDoubt);

    // Nothing was discarded and nothing adopted: the exact basis is retained.
    for handle in [&alpha, &beta] {
        assert_eq!(handle.committed_state(), initial());
        assert_eq!(dispositions(handle), [ReceiptDispositionV1::Staged]);
        assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
        assert_eq!(handle.last_failure(), None);
    }
    let blocked = err(world.stage());
    assert!(matches!(blocked, RuntimeError::PendingDriverStep));
    assert_eq!(alpha.receipts().len(), 1);

    // Recovery resubmits the retained basis: the state commits, no Driver
    // runs again.
    let recovered = ok(world.registry.recover_scheduled_pass(&mut world.store));
    assert_eq!(recovered.map(|r| r.committed_events().len()), Some(2));
    assert_eq!(world.events().len(), 2);
    assert_eq!(alpha.committed_state().bytes, b"initial+");
    assert_eq!(beta.committed_state().bytes, b"next");
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Committed]);
    assert_eq!(alpha.receipts().len(), 1);
}

#[test]
fn abandoning_an_in_doubt_pass_discards_the_staged_state() {
    let mut world = World::new();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let staged = ok(world.stage());
    let admission = world.admission(&staged);
    let lost = err(world
        .registry
        .admit_scheduled_pass(&mut LostPort(&mut world.store), &admission));
    assert_eq!(classify_pass_failure(&lost), PassFailureV1::InDoubt);
    world.registry.abort_step();
    assert_eq!(alpha.committed_state(), initial());
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Discarded]);
}
