use pos_core::{
    ErasureReferenceV1, ErasureReplayClaimV1, Event, Hash, Reducer, State, TimelineId,
    WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
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
    let mut capture_registry = registry(&gate);
    let generation = gate.inventory_generation().test_ok();
    let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        timeline.id(),
        Hash::from_bytes(generation.digest()),
    )
    .test_ok();
    let mut reads = host.read_sender().test_ok();
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
fn snapshot_error_preserves_artifact_unavailability_as_a_typed_error() {
    assert!(matches!(
        pos_time::SnapshotError::from(pos_core::CoreError::ArtifactUnavailable),
        pos_time::SnapshotError::ArtifactUnavailable
    ));
    assert!(matches!(
        pos_time::SnapshotError::from(pos_core::CoreError::Storage("probe".to_owned())),
        pos_time::SnapshotError::Store(pos_core::CoreError::Storage(_))
    ));
}

#[test]
fn snapshot_and_verification_map_unknown_timeline_fence_errors() {
    let composition = ErasureCoordinatorCompositionV1::closed()
        .with_world_replay_verifier(Arc::new(ExactVerifier));
    let mut host = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Memory,
        &composition,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok();
    let gate = host.containment_gate();
    let known_timeline = host
        .command_sender()
        .test_ok()
        .create_timeline("known-snapshot-control")
        .test_ok();
    let unknown_timeline = TimelineId::new();
    let generation = Hash::from_bytes(gate.inventory_generation().test_ok().digest());
    let known_closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        known_timeline.id(),
        generation,
    )
    .test_ok();
    let unknown_closure =
        WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
            unknown_timeline,
            generation,
        )
        .test_ok();
    let mut reads = host.read_sender().test_ok();

    let mut known_registry = registry(&gate);
    let known_snapshot = snapshot(
        &mut reads,
        known_timeline.id(),
        &mut known_registry,
        &known_closure,
    )
    .test_ok();
    let mut known_verification_registry = registry(&gate);
    verify_snapshot_consistency(
        &mut reads,
        &known_snapshot,
        &mut known_verification_registry,
        &known_closure,
    )
    .test_ok();

    let mut snapshot_registry = registry(&gate);
    assert!(matches!(
        snapshot(
            &mut reads,
            unknown_timeline,
            &mut snapshot_registry,
            &unknown_closure,
        ),
        Err(pos_core::CoreError::ErasureContainmentUnavailable)
    ));

    let mut verification_registry = registry(&gate);
    let unknown_snapshot = pos_time::Snapshot {
        timeline: unknown_timeline,
        at_seq: pos_core::clock::Seq::ZERO,
        registry: std::collections::HashMap::new(),
    };
    assert!(matches!(
        verify_snapshot_consistency(
            &mut reads,
            &unknown_snapshot,
            &mut verification_registry,
            &unknown_closure,
        ),
        Err(pos_time::SnapshotError::Store(
            pos_core::CoreError::ErasureContainmentUnavailable
        ))
    ));
}
