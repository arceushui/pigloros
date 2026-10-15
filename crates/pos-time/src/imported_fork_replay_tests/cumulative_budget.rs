//! Independent whole-Replay accounting, including both imported validation phases.
//!
//! The empty imported own segment still inherits four signed root Events.
//! Expected units come from public fixture fields and byte encoders, never a
//! measured ledger or the production canonical-length/debit helpers.

mod compare;

use super::{
    fixture::{pin_policy, request_for, Built, Fallible, Shape, Spec, World},
    Fault, ImportedVerifier,
};
use crate::test_support::{with_release, ProtectedFixture};
use pos_core::{
    store::{EventStore, SeqRange},
    CoreError, ErasureRecoveryLimitsV1, Event, ForkAttributionImportClosureV1, Hash,
    ImportedForkAttributionAdmissionV1, Reducer, Seq, State, WorldReplayClosureV1,
};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{
    memory::MemoryStore, ForkAttributionAuthorityImportPortV1, ForkManifestPublicationPortV1,
    ForkReplayReadLimitsV1, ForkReplayRequirementV1,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Count;

impl Reducer for Count {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("n", serde_json::json!(0));
        state
    }

    fn apply(&self, state: &mut State, _: &Event) {
        let n = state
            .get("n")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("n", serde_json::json!(n + 1));
    }
}

fn count() -> Box<dyn Reducer> {
    Box::new(Count)
}

/// Empty imported own segment, four root Events and no local attribution key.
/// Public encoders and fixture ancestry, not production length/debit methods.
pub(super) fn memory_authority_bytes(
    world: &World,
    built: &Built,
    admission: &ImportedForkAttributionAdmissionV1,
    child_index: usize,
) -> Fallible<usize> {
    let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
    let signed = closure.signed_manifest();
    let operation = closure.publication_operation();
    let owner = operation.projection().input().signing_identity.owner_id;
    assert!(world
        .registry
        .key_record(operation.projection().input().signing_identity)
        .is_none());
    assert!(closure.classifier().is_none());
    assert!(closure.append_operations().is_empty());
    assert!(signed.manifest().input().intervention_sequences.is_empty());
    assert!(built.envelope.unsigned().input().key_tombstone.is_none());
    let child = world.child_at(child_index)?;
    assert_eq!(operation.projection().input().child_timeline_id, child.id);
    assert_eq!(child.parent_cut, 4);
    assert!(world.source.read_own(child.id, SeqRange::all())?.is_empty());
    let ancestry = pos_core::fork_ancestry(&world.source, child.id)?;
    let parent_links = ancestry
        .iter()
        .filter(|member| member.fork_point.is_some())
        .count();
    let root = world.source.read(world.root, SeqRange::all())?;
    assert_eq!(root.len(), 4);
    for event in &root {
        assert_eq!(event.payload.len(), 6);
        assert_eq!(event.event_type.as_str(), "fae1.import.test");
    }
    let projection = 32 + 16 + 8 + 32 + 32 + owner.as_str().len() + 1 + 8 + 32 + 32 + 32 + 1;
    let binding = closure.publication_binding().to_canonical_cbor().len();
    let issuer = &admission.input().issuer;
    let admitted = issuer.issuer_id().len()
        + 2 * issuer.to_canonical_cbor().len()
        + admission.to_canonical_cbor().len()
        + 3 * closure.fork_admission().to_canonical_cbor().len();
    // Binding twice; projection three times; two origin carriers; retained key;
    // segment IDs/history entries and cuts; four Event hash inputs;
    // FSM1/FRM1 encodings and retained bytes; receipt; absent-key getter;
    // final imported FPO1 and three digest copies.
    let authority_bytes = 2 * binding
        + 3 * projection
        + 2 * (1 + 32)
        + admitted
        + built
            .envelope
            .unsigned()
            .input()
            .key_record
            .to_canonical_cbor()
            .len()
        + ancestry.len() * (16 + 16)
        + parent_links * 8
        + 4 * (26 + 6)
        + 2 * signed.to_canonical_cbor().len()
        + 2 * signed.manifest_bytes().len()
        + (32 + 16 + 8 + 32)
        + (owner.as_str().len() + 1 + 8 + 1 + 32 + 1 + 32)
        + operation.to_canonical_cbor().len()
        + 3 * 32;
    Ok(authority_bytes)
}

fn whole_memory_budget(
    world: &World,
    built: &Built,
    admission: &ImportedForkAttributionAdmissionV1,
    child_index: usize,
    folded_events: usize,
) -> Fallible<(usize, usize, usize)> {
    assert_eq!(world.child_at(child_index)?.parent, world.root);
    let authority_bytes = memory_authority_bytes(world, built, admission, child_index)?;
    // Runtime reads [child,root], then [root]: three native metadata carriers,
    // eight borrowed root Event candidates, one internal parent ID and one
    // Runtime parent/cut continuation. No name/payload/type String is copied.
    let lineage_bytes = (49 + 16) + 16 + (25 + 16) + 4 * 8 + 24 + (25 + 16) + 4 * 8;
    // The admission selection examines every actually installed import row.
    // Both callers import every child into an otherwise fresh destination.
    let authority_rows = 3 + (1 + world.children.len()) + 2 + 1 + 4;
    let lineage_rows = 3 + 2 * 4;
    // Five chain-hash visits, one empty suffix lookup and three lineage visits.
    let phase_visits = 5 + 1 + 3;
    Ok((
        2 * (authority_bytes + lineage_bytes) + folded_events * (6 + 16),
        2 * (authority_rows + lineage_rows),
        2 * phase_visits,
    ))
}

fn exercise(
    mut host: ErasureExecutionHostV1,
    world: &World,
    verifier: &ImportedVerifier,
    cut: Option<Seq>,
    succeeds: bool,
) -> Fallible<()> {
    let child = world.child_at(0)?.id;
    let fixture = ProtectedFixture::new("count", count);
    let gate = host.containment_gate();
    let generation = Hash::from_bytes(gate.inventory_generation()?.digest());
    let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        child, generation,
    )?;
    let mut registry = fixture.registry(gate);
    registry.bind_fork_ancestry(child, &pos_core::fork_ancestry(&world.source, child)?)?;
    let seed = world.source.read(world.root, SeqRange::all())?;
    let seed = seed.first().ok_or("root seed")?;
    registry.apply_event(child, seed);
    registry.apply_event(child, seed);
    let before = registry.state_snapshot(child)?;
    assert_eq!(before["count"].len(), 1);
    assert_eq!(
        before["count"]
            .get(&seed.entity)
            .and_then(|state| state.get("n")),
        Some(&serde_json::json!(2))
    );
    let mut reads = host.read_sender()?;
    let result = with_release(|release| match cut {
        None => crate::replay(
            &mut reads,
            child,
            &mut registry,
            &closure,
            release,
            &fixture.fold(),
        ),
        Some(cut) => crate::replay_at(
            &mut reads,
            child,
            cut,
            &mut registry,
            &closure,
            release,
            &fixture.fold(),
        ),
    });
    // Final admission occurs only after the staged fold. Each independent
    // one-under limit fits phase one and refuses in the final validation.
    assert_eq!(verifier.admissions.load(Ordering::SeqCst), 2);
    if succeeds {
        result?;
        let after = registry.state_snapshot(child)?;
        let folded_events = usize::try_from(cut.unwrap_or(Seq::from_u64(4)).as_u64())?;
        assert_eq!(after["count"].len(), folded_events);
        assert!(after["count"]
            .entries()
            .all(|(_, state)| state.get("n") == Some(&serde_json::json!(1))));
    } else {
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
        assert_eq!(registry.state_snapshot(child)?, before);
    }
    Ok(())
}

fn memory_replay_budget_cases(cut: Option<Seq>) -> Fallible<()> {
    let world = World::new(Shape::EmptyUnclassified, false)?;
    assert_eq!(world.children.len(), 1);
    let built = world.build(&Spec::default())?;
    let admission = ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?;
    let folded_events = usize::try_from(cut.unwrap_or(Seq::from_u64(4)).as_u64())?;
    let (bytes, rows, visits) = whole_memory_budget(&world, &built, &admission, 0, folded_events)?;
    assert_eq!((rows, visits), (46, 18));
    for (bytes, rows, visits, succeeds) in [
        (bytes, rows, visits, true),
        (bytes + 1, rows, visits, true),
        (bytes, rows + 1, visits, true),
        (bytes, rows, visits + 1, true),
        (bytes - 1, rows, visits, false),
        (bytes, rows - 1, visits, false),
        (bytes, rows, visits - 1, false),
    ] {
        let mut store = MemoryStore::new();
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        let imported = store.import_verified(&request_for(&world, &built))?;
        assert_eq!(imported.admission, admission);
        let child = world.child_at(0)?.id;
        let committed = store.read_committed(child, 4)?;
        let requirement = ForkReplayRequirementV1::new(
            child,
            Seq::from_u64(4),
            committed.record_id,
            committed.authority_origin_digest,
        )?;
        let verifier = Arc::new(ImportedVerifier {
            child,
            parent: world.root,
            requirement,
            secondary: None,
            fault: Fault::None,
            fault_target: None,
            limits_override: Some(ForkReplayReadLimitsV1::new(
                8, visits, rows, bytes, 30_000_000,
            )?),
            admissions: AtomicUsize::new(0),
        });
        let composition =
            ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
        let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
            store,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        exercise(host, &world, &verifier, cut, succeeds)?;
    }
    Ok(())
}

#[test]
fn imported_memory_replay_keeps_one_exact_budget_through_final_validation() -> Fallible<()> {
    memory_replay_budget_cases(None)
}

#[test]
fn imported_memory_replay_at_keeps_full_authority_budget_at_both_cuts() -> Fallible<()> {
    // The prefix folds two Events, but validates the entire four-Event signed
    // publication in both phases. The publication-cut control folds all four.
    for cut in [2, 4] {
        memory_replay_budget_cases(Some(Seq::from_u64(cut)))?;
    }
    Ok(())
}
