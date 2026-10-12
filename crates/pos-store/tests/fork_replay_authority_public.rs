#![cfg(feature = "sqlite")]

//! Diagnostic read-port parity; these structural reads cannot release Replay.

#[path = "support/fae1_fixture.rs"]
mod fixture;

use fixture::{pin_policy, request_for, Fallible, Port, Shape, Spec, World, PARENT_CUT};
use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
use pos_core::{ErasurePersistencePortV1, ErasureProtectedEffectDispositionV1, Hash, Seq};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkReplayAuthorityReadErrorV1 as Error,
    ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    ForkReplayRequirementV1,
};
use std::time::Duration;

fn exercise<S: Port + ForkReplayAuthorityReadPortV1 + ErasurePersistencePortV1>(
    store: &mut S,
    shape: Shape,
) -> Fallible<()> {
    let world = World::new(shape, false)?;
    let built = world.build(&Spec::default())?;
    world.seed_destination(store)?;
    pin_policy(store, &built.policy)?;
    let imported = store.import_verified(&request_for(&world, &built))?;
    let child = world.child_at(0)?.id;
    let head = PARENT_CUT + shape.events();
    let committed = store.read_committed(child, head)?;
    let requirement = ForkReplayRequirementV1::new(
        child,
        Seq::from_u64(head),
        committed.record_id,
        committed.authority_origin_digest,
    )?;
    let limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, 8 * 1024 * 1024, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let started = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
    let interval = store.begin_protected_effect_interval()?;
    let first = store.validate_fork_replay_authority(&requirement, &mut budget)?;
    let second = store.validate_fork_replay_authority(&requirement, &mut budget)?;
    assert_eq!(first, second);
    assert_eq!(first.requirement(), requirement);
    assert_eq!(
        first.operation_id(),
        committed.operation.input().operation_id
    );
    assert_eq!(
        first.admission_digest(),
        committed.operation.input().admission_digest
    );
    let decoded =
        pos_core::ImportedForkPublicationOperationV1::from_canonical_cbor(first.operation_bytes())?;
    assert_eq!(
        decoded.authority_origin_digest(),
        imported.admission.input().authority_origin_digest
    );
    let wrong = ForkReplayRequirementV1::new(
        child,
        Seq::from_u64(head),
        Hash::from_bytes([0xff; 32]),
        committed.authority_origin_digest,
    )?;
    assert_eq!(
        store.validate_fork_replay_authority(&wrong, &mut budget),
        Err(Error::CorruptAuthority)
    );
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    // Diagnostic validation neither signs nor repairs stored authority.
    assert_eq!(
        store.import_verified(&request_for(&world, &built))?,
        imported
    );
    Ok(())
}

#[test]
fn mixed_and_both_empty_imports_validate_identically_on_both_adapters() -> Fallible<()> {
    for shape in [
        Shape::Mixed,
        Shape::EmptyClassified,
        Shape::EmptyUnclassified,
    ] {
        exercise(&mut MemoryStore::new(), shape)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("fork-replay.sqlite");
        exercise(
            &mut SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?,
            shape,
        )?;
    }
    Ok(())
}

#[test]
fn sqlite_diagnostic_bridge_requires_an_existing_interval() -> Fallible<()> {
    let store = SqliteStore::open(":memory:")?;
    let requirement = ForkReplayRequirementV1::new(
        pos_core::TimelineId::new(),
        Seq::ZERO,
        Hash::from_bytes([1; 32]),
        None,
    )?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000)?;
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    assert_eq!(
        store.validate_fork_replay_authority(&requirement, &mut budget),
        Err(Error::StorageUnavailable)
    );
    Ok(())
}
