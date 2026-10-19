#![cfg(feature = "sqlite")]

//! Diagnostic read-port parity; these structural reads cannot release Replay.

#[path = "support/fae1_fixture.rs"]
pub mod fixture;

use fixture::{pin_policy, request_for, Fallible, Port, Shape, Spec, World, PARENT_CUT};
use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
use pos_core::{ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1, Hash, Seq};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkReplayAuthorityReadErrorV1 as Error,
    ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    ForkReplayRequirementV1,
};
use std::time::Duration;

fn exercise<S: Port + ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1>(
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
    let charged_bytes = limits.max_native_bytes() - budget.remaining_native_bytes();
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
    // Exercise the actual adapter read, not only ledger arithmetic. The exact
    // byte ceiling admits the same evidence; one byte less permanently fails.
    assert!(charged_bytes > 1);
    for (bytes, succeeds) in [(charged_bytes, true), (charged_bytes - 1, false)] {
        let edge_limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, bytes, 1_000_000)?;
        let mut edge_clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let edge_start = edge_clock.mark();
        let mut edge_budget =
            ForkReplayReadBudgetV1::new(edge_limits, edge_start, &mut edge_clock)?;
        let result = store.validate_fork_replay_authority(&requirement, &mut edge_budget);
        if succeeds {
            assert_eq!(result?, first);
            assert_eq!(edge_budget.remaining_native_bytes(), 0);
        } else {
            assert_eq!(result, Err(Error::BoundsExceeded));
            assert_eq!(edge_budget.check_time(), Err(Error::BoundsExceeded));
        }
    }
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

#[test]
fn unrelated_valid_fork_does_not_change_public_sqlite_authority_evidence_or_copies() -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    world.add_child(Shape::Mixed)?;
    let built = world.build(&Spec::default())?;
    let unrelated = world.build(&Spec::distinct(1))?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("child-local-authority.sqlite");
    let mut store = SqliteStore::open(path.to_str().ok_or("UTF-8 path")?)?;
    world.seed_destination(&mut store)?;
    pin_policy(&mut store, &built.policy)?;
    let imported = store.import_verified(&request_for(&world, &built))?;
    let child = world.child_at(0)?.id;
    let committed = store.read_committed(child, PARENT_CUT)?;
    let requirement = ForkReplayRequirementV1::new(child, Seq::from_u64(PARENT_CUT), committed.record_id, committed.authority_origin_digest)?;
    let mut results = Vec::new();
    for foreign in [false, true] {
        if foreign {
            pin_policy(&mut store, &unrelated.policy)?;
            store.import_verified(&request_for(&world, &unrelated))?;
        }
        let limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, 8 * 1024 * 1024, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let started = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
        let interval = store.begin_protected_effect_interval()?;
        let evidence = store.validate_fork_replay_authority(&requirement, &mut budget)?;
        budget.check_time()?;
        results.push((evidence, budget.remaining_native_bytes()));
        store.finish_protected_effect_interval(interval, ErasureProtectedEffectDispositionV1::Rollback)?;
        // The diagnostic read neither repairs nor rewrites imported authority.
        assert_eq!(store.import_verified(&request_for(&world, &built))?, imported);
    }
    assert_eq!(results.len(), 2);
    assert_eq!(results[0], results[1]);
    Ok(())
}
