//! ADR-021 Revision 4 Decision 3: `pos-time` snapshots, Fork comparison and
//! Replay of a Fork fence every inherited ancestor scope (#499).

use pos_core::{
    CanonicalBytes, CoreError, EntityId, ErasureGate, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureReplayClaimV1, Event, EventDraft, Hash, Kind, Reducer, SchemaVersion, Seq, State,
    TimelineId, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use pos_time::{compare, replay, snapshot, verify_snapshot_consistency, Snapshot, SnapshotError};
use std::{collections::HashMap, sync::Arc};

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

struct ExactVerifier;

impl WorldReplayVerifierV1 for ExactVerifier {
    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested_use: &WorldReplayUseV1,
        inventory_generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        Ok(pos_runtime::world_replay::test_verified_world_replay(
            closure,
            requested_use,
            inventory_generation,
            ErasureReplayClaimV1::Exact,
        ))
    }
}

struct NoopReducer;

impl Reducer for NoopReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &Event) {}
}

fn draft() -> EventDraft {
    EventDraft {
        entity: EntityId::new(),
        event_type: Kind::new("world.test"),
        payload: CanonicalBytes::from_vec(vec![5]),
        wall_time: None,
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
    }
}

/// Two Forks of one root and two Forks of an unrelated root, with World
/// Replay closures bound to the final inventory generation.
struct Hosted {
    host: ErasureExecutionHostV1,
    gate: Arc<dyn ErasureGate>,
    root: TimelineId,
    forks: [TimelineId; 2],
    unrelated: [TimelineId; 2],
    closures: HashMap<TimelineId, WorldReplayClosureV1>,
}

impl Hosted {
    fn open(config: StoreConfig) -> Self {
        let composition = ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(ExactVerifier));
        let mut host = ErasureExecutionHostV1::open_with_authority(
            config,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let mut commands = host.command_sender().test_ok();
        let mut lineage = |name: &str| {
            let root = commands.create_timeline(name).test_ok().id();
            commands.append(root, &[draft(), draft()]).test_ok();
            let first = commands
                .fork_timeline(root, Seq::from_u64(2), "first")
                .test_ok()
                .id();
            let second = commands
                .fork_timeline(root, Seq::from_u64(2), "second")
                .test_ok()
                .id();
            (root, [first, second])
        };
        let (root, forks) = lineage("root");
        let (_, unrelated) = lineage("unrelated");
        drop(commands);
        let mut reads = host.read_sender().test_ok();
        let closures = forks
            .into_iter()
            .chain(unrelated)
            .map(|timeline| {
                let (_, generation) = reads
                    .read_bounded_at_generation(
                        timeline,
                        pos_core::SeqRange::all(),
                        pos_core::EventReadBounds::new(1_024, 64, 8, 64),
                        None,
                    )
                    .test_ok();
                let closure = WorldReplayClosureV1::test_fixture_for_timeline_consumer(
                    timeline,
                    Hash::from_bytes(generation.digest()),
                    "count",
                )
                .test_ok();
                (timeline, closure)
            })
            .collect();
        drop(reads);
        let gate = host.containment_gate();
        Self {
            host,
            gate,
            root,
            forks,
            unrelated,
            closures,
        }
    }

    fn registry(&self) -> ProjectionRegistry {
        let mut registry = ProjectionRegistry::new().with_erasure_gate(Arc::clone(&self.gate));
        // The closure fixture authorizes the "count" consumer.
        registry.register("count", Box::new(NoopReducer));
        registry
    }

    fn snapshot(&mut self, timeline: TimelineId) -> Result<Snapshot, CoreError> {
        let mut registry = self.registry();
        let mut reads = self.host.read_sender().test_ok();
        snapshot(
            &mut reads,
            timeline,
            &mut registry,
            &self.closures[&timeline],
        )
    }

    fn verify(&mut self, captured: &Snapshot) -> Result<(), SnapshotError> {
        let mut registry = self.registry();
        let mut reads = self.host.read_sender().test_ok();
        let closure = &self.closures[&captured.timeline];
        verify_snapshot_consistency(&mut reads, captured, &mut registry, closure)
    }

    fn compare(&mut self, forks: [TimelineId; 2]) -> Result<(), CoreError> {
        let [mut first, mut second] = [self.registry(), self.registry()];
        let mut reads = self.host.read_sender().test_ok();
        compare(
            &mut reads,
            forks,
            Seq::from_u64(2),
            [&mut first, &mut second],
            [&self.closures[&forks[0]], &self.closures[&forks[1]]],
        )
        .map(|_| ())
    }

    fn replay(&mut self, timeline: TimelineId) -> Result<(), CoreError> {
        let mut registry = self.registry();
        let mut reads = self.host.read_sender().test_ok();
        replay(
            &mut reads,
            timeline,
            &mut registry,
            &self.closures[&timeline],
        )
        .map(|_| ())
    }
}

fn is_frozen<T>(result: &Result<T, CoreError>) -> bool {
    matches!(result, Err(CoreError::ErasureAccessFrozen))
}

#[test]
fn snapshots_comparison_and_replay_of_a_fork_fail_closed_on_a_frozen_ancestor() {
    for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
        let mut hosted = Hosted::open(config);
        let forks = hosted.forks;
        let unrelated = hosted.unrelated;
        let captured = hosted.snapshot(forks[0]).test_ok();
        hosted.verify(&captured).test_ok();
        hosted.compare(forks).test_ok();
        hosted.replay(forks[1]).test_ok();

        hosted.host.freeze_timeline_for_test(hosted.root);
        assert!(is_frozen(&hosted.snapshot(forks[0])));
        assert!(matches!(
            hosted.verify(&captured),
            Err(SnapshotError::Store(CoreError::ErasureAccessFrozen))
        ));
        assert!(is_frozen(&hosted.compare(forks)));
        assert!(is_frozen(&hosted.compare([forks[0], unrelated[0]])));
        assert!(is_frozen(&hosted.replay(forks[1])));

        let unaffected = hosted.snapshot(unrelated[0]).test_ok();
        hosted.verify(&unaffected).test_ok();
        hosted.compare(unrelated).test_ok();
        hosted.replay(unrelated[1]).test_ok();
    }
}
