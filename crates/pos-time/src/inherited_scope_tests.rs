//! ADR-021 Revision 4 Decision 3: protected Compare and Replay of a Fork
//! fence every inherited ancestor scope (#499).
//!
//! Protected Snapshots are uniformly unavailable (ADR-113 §9), so no
//! Snapshot case exists here; #502 re-pins them when they return.
//!
//! The exact test host is MemoryStore-only. The `SQLite` and runtime
//! coverage of inherited gating lives in the `pos-store` and gateway
//! PPC1 tests.

use crate::test_support::{closure_for_host, open_exact_host, with_release, ProtectedFixture};
use pos_core::{
    CanonicalBytes, CoreError, EntityId, EventDraft, Kind, Reducer, Seq, State, TimelineId,
    WorldReplayClosureV1,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_state::ProjectionRegistry;

struct NoopReducer;

impl Reducer for NoopReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &pos_core::Event) {}
}

fn noop() -> Box<dyn Reducer> {
    Box::new(NoopReducer)
}

fn draft() -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new("world.test"),
        CanonicalBytes::from_vec(vec![5]),
    )
}

/// One root with two Forks at its second Event.
fn lineage(host: &mut ErasureExecutionHostV1, name: &str) -> (TimelineId, [TimelineId; 2]) {
    let mut commands = crate::test_support::test_ok(host.command_sender());
    let root = crate::test_support::test_ok(commands.create_timeline(name)).id();
    crate::test_support::test_ok(commands.append(root, &[draft(), draft()]));
    let mut fork = |label: &str| {
        crate::test_support::test_ok(commands.fork_timeline(root, Seq::from_u64(2), label)).id()
    };
    (root, [fork("first"), fork("second")])
}

fn closure_of(
    closures: &[(TimelineId, WorldReplayClosureV1)],
    timeline: TimelineId,
) -> &WorldReplayClosureV1 {
    closures
        .iter()
        .find(|(member, _)| *member == timeline)
        .map_or_else(
            || std::panic::resume_unwind(Box::new("closure fixture missing")),
            |(_, closure)| closure,
        )
}

struct Hosted {
    host: ErasureExecutionHostV1,
    fixture: ProtectedFixture,
    root: TimelineId,
    forks: [TimelineId; 2],
    unrelated: [TimelineId; 2],
    closures: Vec<(TimelineId, WorldReplayClosureV1)>,
}

impl Hosted {
    fn open() -> Self {
        let mut host = open_exact_host();
        let (root, forks) = lineage(&mut host, "root");
        let (_, unrelated) = lineage(&mut host, "unrelated");
        let closures = forks
            .into_iter()
            .chain(unrelated)
            .map(|timeline| (timeline, closure_for_host(&mut host, timeline)))
            .collect();
        Self {
            host,
            fixture: ProtectedFixture::new("count", noop),
            root,
            forks,
            unrelated,
            closures,
        }
    }

    fn registry(&self) -> ProjectionRegistry {
        self.fixture.registry(self.host.containment_gate())
    }

    fn compare(&mut self, timelines: [TimelineId; 2]) -> Result<(), CoreError> {
        let [mut first, mut second] = [self.registry(), self.registry()];
        let mut reads = crate::test_support::test_ok(self.host.read_sender());
        let (fold_a, fold_b) = (self.fixture.fold(), self.fixture.fold());
        with_release(|release| {
            crate::compare(
                &mut reads,
                timelines,
                Seq::from_u64(2),
                [&mut first, &mut second],
                [
                    closure_of(&self.closures, timelines[0]),
                    closure_of(&self.closures, timelines[1]),
                ],
                release,
                [&fold_a, &fold_b],
            )
        })
        .map(|_| ())
    }

    fn replay(&mut self, timeline: TimelineId) -> Result<(), CoreError> {
        let mut registry = self.registry();
        let mut reads = crate::test_support::test_ok(self.host.read_sender());
        with_release(|release| {
            crate::replay(
                &mut reads,
                timeline,
                &mut registry,
                closure_of(&self.closures, timeline),
                release,
                &self.fixture.fold(),
            )
        })
    }
}

const fn is_frozen(result: &Result<(), CoreError>) -> bool {
    matches!(result, Err(CoreError::ErasureAccessFrozen))
}

#[test]
fn comparison_and_replay_of_a_fork_fail_closed_on_a_frozen_ancestor() {
    let mut hosted = Hosted::open();
    let (forks, unrelated) = (hosted.forks, hosted.unrelated);
    crate::test_support::test_ok(hosted.compare(forks));
    crate::test_support::test_ok(hosted.replay(forks[1]));

    hosted.host.freeze_timeline_for_test(hosted.root);
    assert!(is_frozen(&hosted.compare(forks)));
    assert!(is_frozen(&hosted.compare([forks[0], unrelated[0]])));
    assert!(is_frozen(&hosted.compare([unrelated[0], forks[0]])));
    assert!(is_frozen(&hosted.replay(forks[1])));

    crate::test_support::test_ok(hosted.compare(unrelated));
    crate::test_support::test_ok(hosted.replay(unrelated[1]));
}
