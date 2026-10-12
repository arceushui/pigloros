//! Real imported native authority consumed by the public protected Replay seam.

#[path = "../../pos-store/tests/support/fae1_fixture.rs"]
pub mod fixture;

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use fixture::{Fallible, Port, Shape, Spec, World, PARENT_CUT, pin_policy, request_for};
use pos_core::{
    CoreError, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1,
    Hash, Reducer, Seq, State, TimelineId, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayForkSourceV1, WorldReplayUseV1, WorldReplayVerificationErrorV1,
    WorldReplayVerifierV1,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkReplayReadLimitsV1,
    ForkReplayRequirementV1, StoreConfig,
};

use crate::test_support::{ProtectedFixture, with_release};

struct Count;

impl Reducer for Count {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("n", serde_json::json!(0));
        state
    }

    fn apply(&self, state: &mut State, _event: &pos_core::Event) {
        let next = state.get("n").and_then(serde_json::Value::as_u64).unwrap_or(0) + 1;
        state.set("n", serde_json::json!(next));
    }
}

fn count() -> Box<dyn Reducer> {
    Box::new(Count)
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Omitted,
    Foreign,
    FinalIdentity,
    NoProfile,
}

struct ImportedVerifier {
    child: TimelineId,
    parent: TimelineId,
    requirement: ForkReplayRequirementV1,
    fault: Fault,
    admissions: AtomicUsize,
}

impl WorldReplayVerifierV1 for ImportedVerifier {
    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        let phase = self.admissions.fetch_add(1, Ordering::SeqCst);
        let mut requirement = self.requirement;
        if matches!(self.fault, Fault::Foreign) || (matches!(self.fault, Fault::FinalIdentity) && phase > 0) {
            requirement = ForkReplayRequirementV1::new(self.child, requirement.publication_logical_head(), Hash::from_bytes([0xff; 32]), requirement.authority_origin_digest())
                .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        }
        let sources = vec![
            WorldReplayForkSourceV1::new(self.child, Some(requirement))?,
            WorldReplayForkSourceV1::new(self.parent, None)?,
        ];
        let required = if matches!(self.fault, Fault::Omitted) { Vec::new() } else { vec![requirement] };
        let profile = if matches!(self.fault, Fault::NoProfile) { None } else { Some(Hash::from_bytes([0xe1; 32])) };
        let limits = ForkReplayReadLimitsV1::new(8, 1_024, 65_536, 64 * 1024 * 1024, 30_000_000)
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        Ok(pos_runtime::world_replay::test_verified_world_replay_with_fork_attribution(
            pos_runtime::world_replay::test_verified_world_replay(closure, requested, generation, ErasureReplayClaimV1::Exact),
            profile, sources, required, limits,
        ))
    }
}

fn populate<S: Port>(store: &mut S, world: &World, shape: Shape) -> Fallible<ForkReplayRequirementV1> {
    let built = world.build(&Spec::default())?;
    world.seed_destination(store)?;
    pin_policy(store, &built.policy)?;
    store.import_verified(&request_for(world, &built))?;
    let child = world.child_at(0)?.id;
    let head = PARENT_CUT + shape.events();
    let committed = store.read_committed(child, head)?;
    Ok(ForkReplayRequirementV1::new(child, Seq::from_u64(head), committed.record_id, committed.authority_origin_digest)?)
}

fn run_on_host(mut host: ErasureExecutionHostV1, child: TimelineId, fault: Fault) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let gate = host.containment_gate();
    let generation = gate.inventory_generation()?;
    let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(child, Hash::from_bytes(generation.digest()))?;
    let mut registry = fixture.registry(gate);
    let mut reads = host.read_sender()?;
    let result = with_release(|release| crate::replay(&mut reads, child, &mut registry, &closure, release, &fixture.fold()));
    match fault {
        Fault::None => {
            result?;
            with_release(|release| crate::replay_at(&mut reads, child, Seq::from_u64(2), &mut registry, &closure, release, &fixture.fold()))?;
        }
        _ => assert_eq!(result, Err(CoreError::ArtifactUnavailable)),
    }
    Ok(())
}

#[test]
fn imported_mixed_and_empty_sources_reach_replay_and_replay_at_on_both_adapters() -> Fallible<()> {
    for shape in [Shape::Mixed, Shape::EmptyClassified, Shape::EmptyUnclassified] {
        for fault in [Fault::None, Fault::Omitted, Fault::Foreign, Fault::FinalIdentity, Fault::NoProfile] {
            let world = World::new(shape, false)?;
            let child = world.child_at(0)?.id;
            let mut memory = MemoryStore::new();
            let requirement = populate(&mut memory, &world, shape)?;
            let verifier = || Arc::new(ImportedVerifier { child, parent: world.root, requirement, fault, admissions: AtomicUsize::new(0) });
            let composition = ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
            let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(memory, &composition, ErasureRecoveryLimitsV1::compiled_maximum())?;
            run_on_host(host, child, fault)?;
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("imported-replay.sqlite");
            let path = path.to_str().ok_or("utf-8 path")?;
            let mut sqlite = SqliteStore::open(path)?;
            assert_eq!(populate(&mut sqlite, &world, shape)?, requirement);
            drop(sqlite);
            let composition = ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
            let host = ErasureExecutionHostV1::open_with_authority(StoreConfig::Sqlite { path: path.to_owned() }, &composition, ErasureRecoveryLimitsV1::compiled_maximum())?;
            run_on_host(host, child, fault)?;
        }
    }
    Ok(())
}
