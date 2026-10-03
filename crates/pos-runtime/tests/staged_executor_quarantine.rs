#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Quarantine of the process-global staged fold executor (ADR-113 §5;
//! acceptance cases 3, 17, 18 and 24 for the executor), and the worker's
//! last-resort containment of a host panic.
//!
//! Quarantine closes protected release for the whole process, so this
//! binary holds exactly one test.

use pos_core::staged_install::ProjectionSourceV1;
use pos_core::trusted_clock::{
    open_release_guard, reserve_trusted_clock, ReleaseGuardV1, ScriptedGuardMonotonicSourceV1,
    SystemGuardMonotonicSourceV1, SystemTrustedWallSourceV1, WaitBudgetV1,
};
use pos_core::trusted_clock_fixture::TrustedClockFixtureV1;
use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
    Capability, Plugin, PluginId, Reducer, State,
};
use pos_runtime::{
    require_staged_release, ExecutorHealthV1, GuardedFoldWindowV1, HostProjectionProviderV1,
    InstalledPluginFactoryV1, InstalledPluginProductV1, NoActionApproverV1, StagedFoldErrorV1,
    StagedFoldExecutorV1, StagedFoldPlanV1,
};
use pos_state::{ProtectedProjectionProviderV1, RecordedConsumerV1};
use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

include!("common/mod.rs");

const NAME: &str = "quarantine-fixture";

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

fn counted(entity: EntityId, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new("quarantine.counted"),
        payload: CanonicalBytes::from_vec(Vec::new()),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

/// Waits until the test releases it before each `apply`, when it holds a
/// release flag.
struct FixtureReducer(Option<Arc<AtomicBool>>);

impl Reducer for FixtureReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        if let Some(release) = &self.0 {
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        state.set("seen", serde_json::json!(true));
    }
}

struct FixturePlugin {
    id: PluginId,
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: Vec::new(),
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: true,
        }
    }
}

impl InstalledPluginFactoryV1 for FixturePlugin {
    type Configuration = Option<Arc<AtomicBool>>;
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(_configuration: &Self::Configuration) -> Vec<u8> {
        NAME.as_bytes().to_vec()
    }

    fn build(
        configuration: &Self::Configuration,
    ) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        InstalledPluginProductV1 {
            plugin: Self {
                id: PluginId::new(),
            },
            reducer: Some(Box::new(FixtureReducer(configuration.clone()))),
            approver: NoActionApproverV1,
        }
    }
}

fn admitted(
    release: Option<Arc<AtomicBool>>,
) -> (
    Arc<dyn ProtectedProjectionProviderV1 + Send + Sync>,
    RecordedConsumerV1,
) {
    let mut provider = HostProjectionProviderV1::default();
    let consumer = test_ok(provider.admit_fixture::<FixturePlugin>(Arc::new(release)));
    (Arc::new(provider), consumer)
}

fn guarded(port: &mut TrustedClockFixtureV1) -> ReleaseGuardV1<'_> {
    let mut store = port.clone();
    let mut wait = WaitBudgetV1::new();
    let reservation = test_ok(reserve_trusted_clock(
        &mut store,
        &mut SystemTrustedWallSourceV1,
        &mut SystemGuardMonotonicSourceV1,
        &mut wait,
        None,
    ));
    test_ok(open_release_guard(
        port,
        reservation,
        &mut wait,
        &mut SystemGuardMonotonicSourceV1,
    ))
}

fn plan(consumer: RecordedConsumerV1, events: &[Event]) -> StagedFoldPlanV1 {
    let source = ProjectionSourceV1::bound(TimelineId::new(), None);
    StagedFoldPlanV1::new(vec![consumer], events.to_vec(), source)
}

#[test]
fn an_abandoned_fold_quarantines_the_process_until_it_ends() {
    let release = Arc::new(AtomicBool::new(false));
    let (blocking, blocked) = admitted(Some(Arc::clone(&release)));
    let (counting, consumer) = admitted(None);
    let entity = EntityId::new();
    let events = [counted(entity, 1), counted(entity, 2)];
    let executor = test_ok(StagedFoldExecutorV1::acquire());
    assert_eq!(worker_threads(), 1);

    // Case 3: the guard thread decides failure at `g0 + 27 s` without the
    // callback returning, and quarantines the executor.
    let mut port = TrustedClockFixtureV1::new();
    let guard = guarded(&mut port);
    let window = GuardedFoldWindowV1::new(&guard);
    let mut guard_clock = ScriptedGuardMonotonicSourceV1::new([Duration::from_millis(26_500)]);
    let still = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let abandoned = plan(blocked, &events).with_worker_clock(Box::new(still));
    let outcome = executor.fold(&window, &mut guard_clock, blocking, abandoned);
    assert_eq!(outcome.err(), Some(StagedFoldErrorV1::DeadlineExceeded));
    assert!(window.is_cancelled());

    // Cases 17 and 24: every acquire, fold and protected release in the
    // process fails closed, and no new worker starts.
    assert_eq!(ExecutorHealthV1::current(), ExecutorHealthV1::Quarantined);
    assert_eq!(
        require_staged_release(),
        Err(StagedFoldErrorV1::ExecutorQuarantined)
    );
    assert_eq!(
        StagedFoldExecutorV1::acquire().err(),
        Some(StagedFoldErrorV1::ExecutorQuarantined)
    );
    let refused = executor.fold(
        &window,
        &mut SystemGuardMonotonicSourceV1,
        Arc::clone(&counting),
        plan(consumer, &events),
    );
    assert_eq!(refused.err(), Some(StagedFoldErrorV1::ExecutorQuarantined));
    assert_eq!(worker_threads(), 1);

    // Case 18: the abandoned job ends at its next check, its late result is
    // discarded, and only then does quarantine clear.
    release.store(true, Ordering::SeqCst);
    await_health(ExecutorHealthV1::Ready, 1_000);
    assert_eq!(ExecutorHealthV1::current(), ExecutorHealthV1::Ready);
    let executor = test_ok(StagedFoldExecutorV1::acquire());
    let mut port = TrustedClockFixtureV1::new();
    let guard = guarded(&mut port);
    let window = GuardedFoldWindowV1::new(&guard);
    let staged = test_ok(executor.fold(
        &window,
        &mut SystemGuardMonotonicSourceV1,
        Arc::clone(&counting),
        plan(consumer, &events),
    ));
    assert_eq!(staged.consumers(), &[consumer]);
    assert_eq!(worker_threads(), 1);

    // A panic in the worker's host code outside every callback ends the
    // job without killing the worker, and quarantines the executor for the
    // rest of the process instead of leaving it busy.
    let faulted = executor.fold(
        &window,
        &mut SystemGuardMonotonicSourceV1,
        counting,
        plan(consumer, &events).with_host_fault(),
    );
    assert!(faulted.is_err());
    await_health(ExecutorHealthV1::Quarantined, 1_000);
    assert_eq!(ExecutorHealthV1::current(), ExecutorHealthV1::Quarantined);
    assert_eq!(
        require_staged_release(),
        Err(StagedFoldErrorV1::ExecutorQuarantined)
    );
    assert_eq!(worker_threads(), 1);
}
