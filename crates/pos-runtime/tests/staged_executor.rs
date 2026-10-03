#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! The process-global staged fold executor (ADR-113 §4–§6; acceptance cases
//! 4–8, 10, 12, 14, 17, 20 and 26).
//!
//! Every test folds on the one worker of this test process, so the tests
//! hold one lock and run one fold at a time. Quarantine is covered by its
//! own test binary, because it closes the executor for the whole process.

use pos_core::staged_install::ProjectionSourceV1;
use pos_core::trusted_clock::{
    open_release_guard, reserve_trusted_clock, GuardMonotonicSourceV1, ReleaseGuardV1,
    ScriptedGuardMonotonicSourceV1, SystemGuardMonotonicSourceV1, SystemTrustedWallSourceV1,
    WaitBudgetV1,
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
    check_handoff_reserve, require_staged_release, teardown_signal, ExecutorHealthV1,
    GuardedFoldWindowV1, HostProjectionProviderV1, InstalledPluginFactoryV1,
    InstalledPluginProductV1, NoActionApproverV1, StagedFoldErrorV1, StagedFoldExecutorV1,
    StagedFoldPlanV1, GUARD_RELEASE_LATE_SIGNAL, MAX_STAGED_INPUT_BYTES_V1,
    STAGED_FOLD_WORKER_NAME_V1,
};
use pos_state::{
    CandidateBuildV1, InitialStateV1, ProjectionCandidateErrorV1, ProtectedProjectionProviderV1,
    RecordedConsumerV1, StagedProjectionV1, MAX_STAGED_ENTITIES_PER_CONSUMER_V1,
    MAX_STAGED_OUTPUT_BYTES_V1,
};
use std::{
    fmt::Debug,
    hint::black_box,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::Duration,
};

const NAME: &str = "staged-fixture";
const COUNTED: &str = "staged.counted";
const SENTINEL: &str = "staged-sentinel-7f3a";

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

fn test_err<T, E>(result: Result<T, E>) -> E {
    match result {
        Ok(_) => std::panic::resume_unwind(Box::new("unexpected successful fold")),
        Err(error) => error,
    }
}

const fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn event(entity: EntityId, event_type: &str, payload: CanonicalBytes, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload,
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

fn counted(entity: EntityId, seq: u64) -> Event {
    event(entity, COUNTED, CanonicalBytes::from_vec(Vec::new()), seq)
}

fn counted_run(entity: EntityId, count: u64) -> Vec<Event> {
    (1..=count).map(|seq| counted(entity, seq)).collect()
}

/// An Event whose blob State has exactly `staged_bytes` staged bytes: 16 for
/// the identifier, 1 for the field name and 2 for the JSON quotes.
fn blob(entity: EntityId, staged_bytes: u64, seq: u64) -> Event {
    let payload = CanonicalBytes::from_vec((staged_bytes - 19).to_le_bytes().to_vec());
    event(entity, COUNTED, payload, seq)
}

fn count_of(state: Option<&State>) -> Option<u64> {
    state
        .and_then(|state| state.get("count"))
        .and_then(serde_json::Value::as_u64)
}

fn source() -> ProjectionSourceV1 {
    ProjectionSourceV1::bound(TimelineId::new(), None)
}

// ── Reducers ────────────────────────────────────────────────────────────────

struct CountingReducer;

impl Reducer for CountingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        let count = count_of(Some(state)).unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

/// Stores a string as long as the payload's little-endian `u64` length.
struct BlobReducer;

impl Reducer for BlobReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        let mut length = [0_u8; 8];
        length.copy_from_slice(&event.payload.as_slice()[..8]);
        let length = usize::try_from(u64::from_le_bytes(length)).unwrap_or(0);
        state.set("b", serde_json::json!("a".repeat(length)));
    }
}

/// Where a [`PanickingReducer`] panics.
#[derive(Clone, Copy)]
enum PanicPoint {
    Initial,
    ProjectsEvent,
    ApplyAt(u64),
    PayloadDrop,
}

/// A payload whose own `Drop` panics again.
struct PanickingPayload;

impl Drop for PanickingPayload {
    fn drop(&mut self) {
        assert!(black_box(false), "{SENTINEL} payload drop");
    }
}

struct PanickingReducer(PanicPoint);

impl Reducer for PanickingReducer {
    fn initial(&self) -> State {
        assert!(!matches!(self.0, PanicPoint::Initial), "{SENTINEL} initial");
        State::new()
    }

    fn projects_event(&self, _event: &Event) -> bool {
        if matches!(self.0, PanicPoint::ProjectsEvent) {
            std::panic::resume_unwind(Box::new(SENTINEL.to_owned()));
        }
        true
    }

    fn apply(&self, state: &mut State, event: &Event) {
        match self.0 {
            PanicPoint::ApplyAt(seq) => {
                assert_ne!(event.seq, Seq::from_u64(seq), "{SENTINEL} apply");
            }
            PanicPoint::PayloadDrop => std::panic::resume_unwind(Box::new(PanickingPayload)),
            PanicPoint::Initial | PanicPoint::ProjectsEvent => {}
        }
        CountingReducer.apply(state, event);
    }
}

/// A reducer whose `Drop` panics once it is armed.
struct DropPanickingReducer {
    armed: bool,
}

impl Reducer for DropPanickingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        CountingReducer.apply(state, event);
    }
}

impl Drop for DropPanickingReducer {
    fn drop(&mut self) {
        assert!(!black_box(self.armed), "{SENTINEL} reducer drop");
    }
}

/// A reducer that waits until the test releases it before each `apply`.
struct BlockingReducer(Arc<AtomicBool>);

impl Reducer for BlockingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        while !self.0.load(Ordering::SeqCst) {
            std::thread::sleep(ms(1));
        }
        CountingReducer.apply(state, event);
    }
}

// ── Fixture factory ─────────────────────────────────────────────────────────

type BuildReducer = Box<dyn Fn(usize) -> Box<dyn Reducer> + Send + Sync>;

struct FixtureConfiguration {
    reducer: BuildReducer,
    builds: AtomicUsize,
    panic_on_build: Option<usize>,
    rename_from_build: Option<usize>,
}

impl FixtureConfiguration {
    fn new(reducer: impl Fn(usize) -> Box<dyn Reducer> + Send + Sync + 'static) -> Self {
        Self {
            reducer: Box::new(reducer),
            builds: AtomicUsize::new(0),
            panic_on_build: None,
            rename_from_build: None,
        }
    }
}

struct FixturePlugin {
    id: PluginId,
    name: &'static str,
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(COUNTED)],
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: true,
        }
    }
}

impl InstalledPluginFactoryV1 for FixturePlugin {
    type Configuration = FixtureConfiguration;
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(_configuration: &FixtureConfiguration) -> Vec<u8> {
        NAME.as_bytes().to_vec()
    }

    fn build(
        configuration: &FixtureConfiguration,
    ) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        let build = configuration.builds.fetch_add(1, Ordering::SeqCst);
        assert_ne!(
            configuration.panic_on_build,
            Some(build),
            "{SENTINEL} build"
        );
        let renamed = configuration
            .rename_from_build
            .is_some_and(|from| build >= from);
        InstalledPluginProductV1 {
            plugin: Self {
                id: PluginId::new(),
                name: if renamed { "renamed" } else { NAME },
            },
            reducer: Some((configuration.reducer)(build)),
            approver: NoActionApproverV1,
        }
    }
}

fn admitted(
    configuration: FixtureConfiguration,
) -> (Arc<HostProjectionProviderV1>, RecordedConsumerV1) {
    let mut provider = HostProjectionProviderV1::default();
    let consumer = test_ok(provider.admit_fixture::<FixturePlugin>(Arc::new(configuration)));
    (Arc::new(provider), consumer)
}

fn admitted_reducer(
    reducer: impl Fn(usize) -> Box<dyn Reducer> + Send + Sync + 'static,
) -> (Arc<HostProjectionProviderV1>, RecordedConsumerV1) {
    admitted(FixtureConfiguration::new(reducer))
}

fn counting() -> (Arc<HostProjectionProviderV1>, RecordedConsumerV1) {
    admitted_reducer(|_| Box::new(CountingReducer))
}

// ── Guard and fold ──────────────────────────────────────────────────────────

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

/// Clocks of one fold, created after the guard so they never precede `g0`.
#[derive(Default)]
struct Clocks {
    worker: Option<Vec<Duration>>,
    guard: Option<Duration>,
}

fn fold_in(
    provider: &Arc<HostProjectionProviderV1>,
    consumers: &[RecordedConsumerV1],
    events: Vec<Event>,
    source: ProjectionSourceV1,
    clocks: Clocks,
) -> Result<StagedProjectionV1, StagedFoldErrorV1> {
    let provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync> = provider.clone();
    fold_through(provider, consumers, events, source, clocks)
}

fn fold_through(
    provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync>,
    consumers: &[RecordedConsumerV1],
    events: Vec<Event>,
    source: ProjectionSourceV1,
    clocks: Clocks,
) -> Result<StagedProjectionV1, StagedFoldErrorV1> {
    let executor = test_ok(StagedFoldExecutorV1::acquire());
    let mut port = TrustedClockFixtureV1::new();
    let guard = guarded(&mut port);
    let window = GuardedFoldWindowV1::new(&guard);
    assert_eq!(window.guard_started_at(), guard.guard_started_at());
    let mut plan = StagedFoldPlanV1::new(consumers.to_vec(), events, source);
    if let Some(offsets) = clocks.worker {
        let worker = ScriptedGuardMonotonicSourceV1::new(offsets);
        plan = plan.with_worker_clock(Box::new(worker));
    }
    let mut guard_clock: Box<dyn GuardMonotonicSourceV1> = match clocks.guard {
        Some(at) => Box::new(ScriptedGuardMonotonicSourceV1::new([at])),
        None => Box::new(SystemGuardMonotonicSourceV1),
    };
    let outcome = executor.fold(&window, guard_clock.as_mut(), provider, plan);
    assert!(!window.is_cancelled());
    outcome
}

fn fold(
    provider: &Arc<HostProjectionProviderV1>,
    consumer: RecordedConsumerV1,
    events: &[Event],
) -> Result<StagedProjectionV1, StagedFoldErrorV1> {
    fold_in(
        provider,
        &[consumer],
        events.to_vec(),
        source(),
        Clocks::default(),
    )
}

fn assert_ready() {
    assert_eq!(ExecutorHealthV1::current(), ExecutorHealthV1::Ready);
    assert_eq!(require_staged_release(), Ok(()));
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Case 14 (executor part): a staged fold equals an unbounded candidate fold
/// of the same range, and the worker stays ready.
#[test]
fn a_staged_fold_equals_the_candidate_fold() {
    let _serial = serial();
    let (provider, consumer) = counting();
    let (first, second) = (EntityId::new(), EntityId::new());
    let events = [counted(first, 1), counted(second, 2), counted(first, 3)];

    let staged = test_ok(fold(&provider, consumer, &events));
    let mut expected =
        test_ok(provider.open_candidate(&[consumer], InitialStateV1::Empty, source()));
    expected.fold_events(&events);

    assert_eq!(staged.consumers(), &[consumer]);
    assert_eq!(
        count_of(expected.state_for(consumer.plugin_id(), &first)),
        Some(2)
    );
    assert!(staged.revoked_subjects().is_empty());
    assert_ready();
}

/// E2: closed failures decided on the guard thread before any callback.
#[test]
fn plans_failing_admission_never_reach_a_callback() {
    let _serial = serial();
    let builds = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&builds);
    let (provider, consumer) = admitted_reducer(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Box::new(CountingReducer)
    });
    let events = [counted(EntityId::new(), 1)];
    let mismatch = StagedFoldErrorV1::ConsumerSetMismatch;

    let none = fold_in(&provider, &[], events.to_vec(), source(), Clocks::default());
    assert_eq!(test_err(none), mismatch);
    let many: Vec<RecordedConsumerV1> = (0..65)
        .map(|_| RecordedConsumerV1::new(PluginId::new(), consumer.reducer_identity()))
        .collect();
    let too_many = fold_in(
        &provider,
        &many,
        events.to_vec(),
        source(),
        Clocks::default(),
    );
    assert_eq!(test_err(too_many), mismatch);
    let late = Clocks {
        guard: Some(ms(28_000)),
        ..Clocks::default()
    };
    let expired = fold_in(&provider, &[consumer], events.to_vec(), source(), late);
    assert_eq!(test_err(expired), StagedFoldErrorV1::DeadlineExceeded);
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert_ready();
}

/// Case 10 (input): 256 MiB of canonical Event bytes pass, one more fails.
///
/// Each plan takes its one large payload by move, and the zeroed buffer is
/// never written, so the test copies no payload.
#[test]
fn the_input_limit_is_exact() {
    let _serial = serial();
    let (provider, consumer) = counting();
    let entity = EntityId::new();
    let limit = MAX_STAGED_INPUT_BYTES_V1 - COUNTED.len() as u64;
    let largest = || {
        let payload = vec![0; usize::try_from(limit).unwrap_or(usize::MAX)];
        event(entity, COUNTED, CanonicalBytes::from_vec(payload), 1)
    };
    let fold_owned =
        |events: Vec<Event>| fold_in(&provider, &[consumer], events, source(), Clocks::default());
    test_ok(fold_owned(vec![largest()]));

    let over = vec![
        largest(),
        event(entity, "", CanonicalBytes::from_vec(vec![1]), 2),
    ];
    assert_eq!(test_err(fold_owned(over)), StagedFoldErrorV1::InputExceeded);
    assert_ready();
}

/// Provider failures inside the worker map to closed ordinal-free errors.
#[test]
fn candidate_open_failures_are_closed_errors() {
    let _serial = serial();
    let (provider, consumer) = counting();
    let events = [counted(EntityId::new(), 1)];
    let unknown = RecordedConsumerV1::new(PluginId::new(), consumer.reducer_identity());

    let not_admitted = fold(&provider, unknown, &events);
    assert_eq!(test_err(not_admitted), StagedFoldErrorV1::NotAdmitted);
    let repeated = fold_in(
        &provider,
        &[consumer, consumer],
        events.to_vec(),
        source(),
        Clocks::default(),
    );
    assert_eq!(test_err(repeated), StagedFoldErrorV1::ConsumerSetMismatch);
    let unbound = fold_in(
        &provider,
        &[consumer],
        events.to_vec(),
        ProjectionSourceV1::default(),
        Clocks::default(),
    );
    assert_eq!(test_err(unbound), StagedFoldErrorV1::SourceMismatch);
    assert_ready();
}

/// E2: an unbound or mixed source is refused on the guard thread before any
/// factory runs, so it never reaches the worker.
#[test]
fn unbound_or_mixed_sources_are_refused_before_any_build() {
    let _serial = serial();
    let builds = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&builds);
    let (provider, consumer) = admitted_reducer(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Box::new(CountingReducer)
    });
    let events = [counted(EntityId::new(), 1)];

    for source in [ProjectionSourceV1::default(), ProjectionSourceV1::mixed()] {
        let refused = fold_in(
            &provider,
            &[consumer],
            events.to_vec(),
            source,
            Clocks::default(),
        );
        assert_eq!(test_err(refused), StagedFoldErrorV1::SourceMismatch);
    }
    // Only the admission build ran.
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert_ready();
}

/// A provider that refuses the source while resolving the recorded set.
struct SourceRefusingProvider;

impl ProtectedProjectionProviderV1 for SourceRefusingProvider {
    fn candidate_builds(
        &self,
        _recorded_consumers: &[RecordedConsumerV1],
    ) -> Result<Vec<CandidateBuildV1<'_>>, ProjectionCandidateErrorV1> {
        Err(ProjectionCandidateErrorV1::SourceMismatch)
    }
}

/// A provider's own source refusal maps to the closed source error.
#[test]
fn a_provider_source_refusal_is_a_closed_error() {
    let _serial = serial();
    let consumer = RecordedConsumerV1::new(PluginId::new(), Hash::from_bytes([3; 32]));
    let refused = fold_through(
        Arc::new(SourceRefusingProvider),
        &[consumer],
        vec![counted(EntityId::new(), 1)],
        source(),
        Clocks::default(),
    );
    assert_eq!(test_err(refused), StagedFoldErrorV1::SourceMismatch);
    assert_ready();
}

/// Every candidate open re-checks that the built Plugin is the recorded one.
#[test]
fn a_rebuilt_plugin_other_than_the_recorded_one_is_refused() {
    let _serial = serial();
    let mut configuration = FixtureConfiguration::new(|_| Box::new(CountingReducer));
    configuration.rename_from_build = Some(2);
    let (provider, consumer) = admitted(configuration);
    let events = [counted(EntityId::new(), 1)];

    test_ok(fold(&provider, consumer, &events));
    let reopened = provider.open_candidate(&[consumer], InitialStateV1::Empty, source());
    assert_eq!(
        reopened.err(),
        Some(ProjectionCandidateErrorV1::PluginMismatch)
    );
    assert_eq!(
        test_err(fold(&provider, consumer, &events)),
        StagedFoldErrorV1::NotAdmitted
    );
    assert_ready();
}

/// Cases 6 and 7: a panic in `build`, `initial`, `projects_event`, `apply`,
/// a reducer `Drop` or a panic payload's own `Drop` is contained, reported
/// with ordinals only, and leaves the worker ready.
#[test]
fn panics_in_every_callback_are_contained() {
    let _serial = serial();
    let entity = EntityId::new();
    let events = counted_run(entity, 4);
    let panicked = |consumer_ordinal, event_ordinal| StagedFoldErrorV1::ReducerPanicked {
        consumer_ordinal,
        event_ordinal,
    };

    let mut configuration = FixtureConfiguration::new(|_| Box::new(CountingReducer));
    configuration.panic_on_build = Some(1);
    let (provider, consumer) = admitted(configuration);
    assert_eq!(test_err(fold(&provider, consumer, &events)), panicked(0, 0));

    for (point, expected) in [
        (PanicPoint::Initial, panicked(0, 0)),
        (PanicPoint::ProjectsEvent, panicked(0, 0)),
        (PanicPoint::ApplyAt(3), panicked(0, 2)),
        (PanicPoint::PayloadDrop, panicked(0, 0)),
    ] {
        let (provider, consumer) = admitted_reducer(move |_| Box::new(PanickingReducer(point)));
        let error = test_err(fold(&provider, consumer, &events));
        assert_eq!(error, expected);
        assert!(!format!("{error:?}").contains(SENTINEL));
        assert_ready();
    }

    let (provider, consumer) =
        admitted_reducer(|build| Box::new(DropPanickingReducer { armed: build > 0 }));
    assert_eq!(
        test_err(fold(&provider, consumer, &events)),
        panicked(0, u32::MAX)
    );
    assert_ready();
}

/// E3 and E4 run before and after each `build` against that consumer's own
/// admitted callback bound, and a failing `build` reports its consumer
/// ordinal.
#[test]
fn each_build_is_checked_against_its_own_callback_bound() {
    let _serial = serial();
    let fixture = || Arc::new(FixtureConfiguration::new(|_| Box::new(CountingReducer)));
    let mut provider = HostProjectionProviderV1::default();
    let relaxed = test_ok(provider.admit_fixture::<FixturePlugin>(fixture()));
    let tight =
        test_ok(provider.admit_fixture_with_callback_bound::<FixturePlugin>(fixture(), ms(50)));
    let provider = Arc::new(provider);
    let events = counted_run(EntityId::new(), 2);
    let fold_with = |worker: Vec<Duration>| {
        let clocks = Clocks {
            worker: Some(worker),
            guard: None,
        };
        fold_in(
            &provider,
            &[relaxed, tight],
            events.clone(),
            source(),
            clocks,
        )
    };

    // One mark before and one after each build.
    let opened = test_ok(fold_with(vec![ms(0), ms(250), ms(250), ms(300)]));
    assert_eq!(opened.consumers(), &[relaxed, tight]);
    // 51 ms fits the largest admissible bound and the whole open's 500 ms,
    // but not the tight consumer's own 50 ms.
    let over = fold_with(vec![ms(0), ms(0), ms(0), ms(51)]);
    assert_eq!(
        test_err(over),
        StagedFoldErrorV1::CallbackBoundExceeded {
            consumer_ordinal: 1,
            event_ordinal: 0,
        }
    );
    let slow_first = fold_with(vec![ms(0), ms(251)]);
    assert_eq!(
        test_err(slow_first),
        StagedFoldErrorV1::CallbackBoundExceeded {
            consumer_ordinal: 0,
            event_ordinal: 0,
        }
    );
    // E3 before the second build uses its own 50 ms bound: a start at
    // 26.9 s, which the largest bound would refuse, passes E3, and E4
    // catches the overrun.
    let late = fold_with(vec![ms(0), ms(0), ms(26_900), ms(26_960)]);
    assert_eq!(
        test_err(late),
        StagedFoldErrorV1::CallbackBoundExceeded {
            consumer_ordinal: 1,
            event_ordinal: 0,
        }
    );
    let too_late = fold_with(vec![ms(0), ms(0), ms(26_951)]);
    assert_eq!(test_err(too_late), StagedFoldErrorV1::DeadlineExceeded);

    let mut panicking = FixtureConfiguration::new(|_| Box::new(CountingReducer));
    panicking.panic_on_build = Some(1);
    let mut provider = HostProjectionProviderV1::default();
    let first = test_ok(provider.admit_fixture::<FixturePlugin>(fixture()));
    let second = test_ok(provider.admit_fixture::<FixturePlugin>(Arc::new(panicking)));
    let provider = Arc::new(provider);
    let panicked = fold_in(
        &provider,
        &[first, second],
        events,
        source(),
        Clocks::default(),
    );
    assert_eq!(
        test_err(panicked),
        StagedFoldErrorV1::ReducerPanicked {
            consumer_ordinal: 1,
            event_ordinal: 0,
        }
    );
    assert_ready();
}

/// Case 8: a fold failing at Event 1, n/2 or n yields no staged result.
#[test]
fn partial_folds_publish_nothing() {
    let _serial = serial();
    let events = counted_run(EntityId::new(), 6);
    for failing in [1_u32, 3, 6] {
        let at = u64::from(failing);
        let (provider, consumer) =
            admitted_reducer(move |_| Box::new(PanickingReducer(PanicPoint::ApplyAt(at))));
        assert_eq!(
            test_err(fold(&provider, consumer, &events)),
            StagedFoldErrorV1::ReducerPanicked {
                consumer_ordinal: 0,
                event_ordinal: failing - 1,
            }
        );
    }
    assert_ready();
}

/// Cases 4 and 5: E4 reports a callback over its bound with ordinals, and E3
/// stops cooperatively before `g0 + 27 s` while the worker stays ready.
#[test]
fn callback_bounds_and_the_fold_deadline_are_enforced_cooperatively() {
    let _serial = serial();
    let (provider, consumer) = counting();
    let events = counted_run(EntityId::new(), 3);
    let fold_with = |worker: Vec<Duration>| {
        let clocks = Clocks {
            worker: Some(worker),
            guard: None,
        };
        fold_in(&provider, &[consumer], events.clone(), source(), clocks)
    };

    let slow = fold_with(vec![ms(0), ms(0), ms(0), ms(0), ms(10), ms(311)]);
    assert_eq!(
        test_err(slow),
        StagedFoldErrorV1::CallbackBoundExceeded {
            consumer_ordinal: 0,
            event_ordinal: 1,
        }
    );
    let slow_open = fold_with(vec![ms(0), ms(251)]);
    assert_eq!(
        test_err(slow_open),
        StagedFoldErrorV1::CallbackBoundExceeded {
            consumer_ordinal: 0,
            event_ordinal: 0,
        }
    );
    let regressed = fold_with(vec![ms(10), ms(0)]);
    assert!(matches!(
        test_err(regressed),
        StagedFoldErrorV1::CallbackBoundExceeded { .. }
    ));
    let late_callback = fold_with(vec![ms(0), ms(0), ms(26_900)]);
    assert_eq!(test_err(late_callback), StagedFoldErrorV1::DeadlineExceeded);
    let late_open = fold_with(vec![ms(26_900)]);
    assert_eq!(test_err(late_open), StagedFoldErrorV1::DeadlineExceeded);
    // Two marks per callback: open, three Events, then the final pass.
    let mut late_pass = vec![ms(0); 8];
    late_pass.push(ms(26_800));
    assert_eq!(
        test_err(fold_with(late_pass)),
        StagedFoldErrorV1::DeadlineExceeded
    );
    assert_ready();
}

/// Case 10 (staged output, entities, growth) through the executor.
#[test]
fn staged_limits_fail_the_fold_deterministically() {
    let _serial = serial();
    let entity = EntityId::new();
    let (provider, consumer) = admitted_reducer(|_| Box::new(BlobReducer));
    let exact = test_ok(fold(
        &provider,
        consumer,
        &[blob(entity, MAX_STAGED_OUTPUT_BYTES_V1, 1)],
    ));
    assert_eq!(exact.consumers(), &[consumer]);
    let over = fold(
        &provider,
        consumer,
        &[blob(entity, MAX_STAGED_OUTPUT_BYTES_V1 + 1, 1)],
    );
    assert_eq!(test_err(over), StagedFoldErrorV1::StagedOutputExceeded);
    let growing = [blob(entity, 100, 1), blob(entity, 100_000, 2)];
    assert_eq!(
        test_err(fold(&provider, consumer, &growing)),
        StagedFoldErrorV1::GrowthBoundExceeded
    );

    let (provider, consumer) = counting();
    let entities: Vec<Event> = (0..=MAX_STAGED_ENTITIES_PER_CONSUMER_V1)
        .map(|_| counted(EntityId::new(), 1))
        .collect();
    assert_eq!(
        test_err(fold(&provider, consumer, &entities)),
        StagedFoldErrorV1::EntityLimitExceeded
    );
    assert_ready();
}

/// Case 20: one growing entity triggers an exact pass only when the
/// declared upper bound crosses 64 MiB, plus the final pass.
///
/// The worker takes one mark before and one after the one `build` and every
/// callback, and one before every exact pass. With 20,000 Events that is
/// 40,002 marks plus one per pass. Scripting the deadline at mark 40,004
/// fails the fold, and at mark 40,005 it does not, so exactly two passes
/// run: the one crossing 64 MiB and the final one.
#[test]
fn exact_passes_run_only_when_the_upper_bound_crosses_the_limit() {
    const EVENTS: usize = 20_000;
    const MARKS: usize = 2 + 2 * EVENTS + 2;
    let _serial = serial();
    let (provider, consumer) = counting();
    let entity = EntityId::new();
    // The fixture admission declares 4096 bytes per `apply`; 20,000 applies
    // cross 64 MiB once.
    let deadline_at = |mark: usize| {
        let mut worker = vec![ms(0); mark - 1];
        worker.push(ms(26_900));
        let clocks = Clocks {
            worker: Some(worker),
            guard: None,
        };
        fold_in(
            &provider,
            &[consumer],
            counted_run(entity, EVENTS as u64),
            source(),
            clocks,
        )
    };
    assert_eq!(
        test_err(deadline_at(MARKS)),
        StagedFoldErrorV1::DeadlineExceeded
    );
    let staged = test_ok(deadline_at(MARKS + 1));
    assert_eq!(staged.consumers(), &[consumer]);
    assert_ready();
}

/// Busy executor: a second fold is refused while one runs.
#[test]
fn a_second_fold_is_refused_while_one_runs() {
    let _serial = serial();
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::clone(&released);
    let (provider, consumer) =
        admitted_reducer(move |_| Box::new(BlockingReducer(Arc::clone(&release))));
    let events = [counted(EntityId::new(), 1)];
    let running = {
        let provider = Arc::clone(&provider);
        let events = events.clone();
        std::thread::spawn(move || {
            fold(&provider, consumer, &events).map(|staged| staged.consumers().len())
        })
    };
    let mut polls = 0;
    while ExecutorHealthV1::current() != ExecutorHealthV1::Busy && polls < 2_000 {
        std::thread::sleep(ms(5));
        polls += 1;
    }
    assert_eq!(ExecutorHealthV1::current(), ExecutorHealthV1::Busy);
    let (other, other_consumer) = counting();
    assert_eq!(
        test_err(fold(&other, other_consumer, &events)),
        StagedFoldErrorV1::ExecutorBusy
    );
    released.store(true, Ordering::SeqCst);
    let joined = match running.join() {
        Ok(joined) => joined,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert_eq!(joined, Ok(1));
    assert_ready();
}

/// Case 12 and case 17 (healthy part): the hook filters only staged
/// callbacks, and re-acquiring never starts another worker.
#[test]
fn the_panic_hook_and_worker_are_installed_once() {
    let _serial = serial();
    let _first = test_ok(StagedFoldExecutorV1::acquire());
    assert_eq!(worker_threads(), 1);
    let second = test_ok(StagedFoldExecutorV1::acquire());
    assert_eq!(worker_threads(), 1);
    assert!(format!("{second:?}").starts_with("StagedFoldExecutorV1"));

    let outside = std::thread::spawn(|| assert!(black_box(false), "outside a staged callback"));
    assert!(outside.join().is_err());
}

/// Threads of this process named as the staged-fold worker. Other test
/// threads start and end concurrently, so only the worker's name counts.
fn worker_threads() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, |tasks| {
        tasks
            .filter_map(Result::ok)
            .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
            .filter(|name| name.trim_end() == STAGED_FOLD_WORKER_NAME_V1)
            .count()
    })
}

/// P1 and P2 (case 26): handoff work must be planned by `g0 + 29 s`, and a
/// teardown predicted after `g0 + 30 s` emits the payload-free signal.
#[test]
fn handoff_and_teardown_reserves_are_predicted() {
    let _serial = serial();
    let mut port = TrustedClockFixtureV1::new();
    let guard = guarded(&mut port);
    let g0 = guard.guard_started_at();
    let at = |offset: Duration| ScriptedGuardMonotonicSourceV1::new([offset]);

    assert_eq!(check_handoff_reserve(&mut at(ms(0)), g0), Ok(()));
    assert_eq!(
        check_handoff_reserve(&mut at(ms(28_600)), g0),
        Err(StagedFoldErrorV1::DeadlineExceeded)
    );
    assert_eq!(teardown_signal(&mut at(ms(0)), g0), None);
    assert_eq!(
        teardown_signal(&mut at(ms(29_900)), g0),
        Some(GUARD_RELEASE_LATE_SIGNAL)
    );
}
