//! Protected Snapshot capture and verification stay `Unavailable` until #502
//! (ADR-113 §9, acceptance case 16), on MemoryStore and SQLite.

use pos_core::{
    ErasureReferenceV1, ErasureReplayClaimV1, Event, Hash, Reducer, State, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use pos_time::{snapshot, verify_snapshot_consistency, Snapshot, SnapshotError};
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

struct CountReducer;

impl Reducer for CountReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _: &Event) {
        state.set("seen", serde_json::json!(true));
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

#[test]
fn protected_snapshot_capture_and_verification_are_unavailable() {
    for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
        let composition = ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(ExactVerifier));
        let mut host = ErasureExecutionHostV1::open_with_authority(
            config,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let entity = pos_core::EntityId::new();
        let (timeline, events) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("snapshot-source").test_ok().id();
            let draft = pos_core::EventDraft::new(
                entity,
                pos_core::Kind::new("test.tick"),
                pos_core::CanonicalBytes::from_vec(Vec::new()),
            );
            let events = commands.append(timeline, &[draft]).test_ok();
            (timeline, events)
        };
        let reads = host.read_sender().test_ok();
        let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
            timeline,
            Hash::from_bytes([3; 32]),
        )
        .test_ok();
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("count", Box::new(CountReducer));
        registry.fold_events(timeline, &events);
        let before = registry.state_for(timeline, &entity).test_ok();
        assert!(before.is_some());

        assert!(matches!(
            snapshot(&reads, timeline, &registry, &closure),
            Err(pos_core::CoreError::ArtifactUnavailable)
        ));
        let captured = Snapshot {
            timeline,
            at_seq: pos_core::clock::Seq::ZERO,
            registry: std::collections::HashMap::new(),
            inventory_generation: [3; 32],
        };
        assert!(matches!(
            verify_snapshot_consistency(&reads, &captured, &registry, &closure),
            Err(SnapshotError::ArtifactUnavailable)
        ));
        assert_eq!(registry.state_for(timeline, &entity).test_ok(), before);
    }
}

#[test]
fn snapshot_error_preserves_artifact_unavailability_as_a_typed_error() {
    assert!(matches!(
        SnapshotError::from(pos_core::CoreError::ArtifactUnavailable),
        SnapshotError::ArtifactUnavailable
    ));
    assert!(matches!(
        SnapshotError::from(pos_core::CoreError::Storage("probe".to_owned())),
        SnapshotError::Store(pos_core::CoreError::Storage(_))
    ));
}

#[test]
fn snapshot_wire_format_requires_the_inventory_generation() {
    let captured = Snapshot {
        timeline: pos_core::TimelineId::new(),
        at_seq: pos_core::clock::Seq::ZERO,
        registry: std::collections::HashMap::new(),
        inventory_generation: [5; 32],
    };
    let encoded = serde_json::to_value(&captured).test_ok();
    let mut missing_generation = encoded.clone();
    let removed_generation = missing_generation
        .as_object_mut()
        .and_then(|fields| fields.remove("inventory_generation"));
    assert!(removed_generation.is_some());
    assert!(serde_json::from_value::<Snapshot>(missing_generation).is_err());
    let mut null_generation = encoded;
    null_generation["inventory_generation"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Snapshot>(null_generation).is_err());
}
