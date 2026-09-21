use pos_core::{Event, Reducer, State, TimelineId};
use pos_runtime::ErasureExecutionHostV1;
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use pos_time::{snapshot, verify_snapshot_consistency};
use std::sync::Arc;

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected artifact snapshot fixture error: {error:?}"
            )))
        })
    }
}

struct NoopReducer;

impl Reducer for NoopReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &Event) {}
}

fn registry(gate: &Arc<pos_core::ErasureContainmentGateV1>) -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new().with_erasure_gate(Arc::clone(gate));
    registry.register("noop", Box::new(NoopReducer));
    registry
}

#[test]
fn snapshot_verification_requires_installed_world_verifier() {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok();
    let gate = host.containment_gate();
    let timeline = host
        .command_sender()
        .test_ok()
        .create_timeline("artifact-snapshot")
        .test_ok();
    let mut reads = host.read_sender().test_ok();
    let mut capture_registry = registry(&gate);
    let closure = pos_core::WorldReplayClosureV1::test_fixture();
    let result = snapshot(&mut reads, timeline.id(), &mut capture_registry, &closure);
    assert!(matches!(
        result,
        Err(pos_core::CoreError::ArtifactUnavailable)
    ));

    let mut rejected_registry = registry(&gate);
    let empty_snapshot = pos_time::Snapshot {
        timeline: timeline.id(),
        at_seq: pos_core::clock::Seq::ZERO,
        registry: std::collections::HashMap::new(),
    };
    let result = verify_snapshot_consistency(
        &mut reads,
        &empty_snapshot,
        &mut rejected_registry,
        &closure,
    );
    assert!(matches!(
        result,
        Err(pos_time::SnapshotError::ArtifactUnavailable)
    ));
}

#[test]
fn snapshot_and_verification_map_unknown_timeline_fence_errors() {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok();
    let gate = host.containment_gate();
    let unknown_timeline = TimelineId::new();
    let mut reads = host.read_sender().test_ok();

    let mut snapshot_registry = registry(&gate);
    assert!(snapshot(
        &mut reads,
        unknown_timeline,
        &mut snapshot_registry,
        &pos_core::WorldReplayClosureV1::test_fixture(),
    )
    .is_err());

    let mut verification_registry = registry(&gate);
    let unknown_snapshot = pos_time::Snapshot {
        timeline: unknown_timeline,
        at_seq: pos_core::clock::Seq::ZERO,
        registry: std::collections::HashMap::new(),
    };
    assert!(verify_snapshot_consistency(
        &mut reads,
        &unknown_snapshot,
        &mut verification_registry,
        &pos_core::WorldReplayClosureV1::test_fixture(),
    )
    .is_err());
}
