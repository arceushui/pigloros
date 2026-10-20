//! Two complete imported validations share one independently sized ledger.

use super::super::{
    cumulative_budget::memory_authority_bytes,
    fixture::{Fallible, Shape, Spec, World},
};
use super::imported_host;
use pos_core::{
    store::SeqRange,
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    ErasureHostErrorV1, ErasureProtectedOperationV1, Hash, ImportedForkAttributionAdmissionV1, Seq,
    WorldReplayClosureV1,
};
use pos_runtime::WorldReplayUseV1;
use pos_store::{ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
use std::time::Duration;

fn exercise(
    world: &World,
    limits: ForkReplayReadLimitsV1,
    phase_bytes: usize,
    succeeds: bool,
) -> Fallible<()> {
    let parent = world.child_at(0)?.id;
    let leaf = world.child_at(1)?.id;
    let bytes = limits.max_native_bytes();
    let mut host = imported_host(world, limits, 2)?;
    let generation = Hash::from_bytes(host.containment_gate().inventory_generation()?.digest());
    let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        leaf, generation,
    )?;
    let requested = WorldReplayUseV1::new(
        leaf,
        ErasureProtectedOperationV1::Read,
        SeqRange::all(),
        Seq::from_u64(4),
        vec!["count".to_owned()],
        Vec::new(),
    )?;
    let mut reads = host.read_sender()?;
    let capability = reads.admit_world_replay(&closure, &requested)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::from_millis(1)]);
    let g0 = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, g0, &mut clock)?;
    let mut first = Err(ErasureHostErrorV1::Conflict);
    let mut second = Err(ErasureHostErrorV1::Conflict);
    reads.with_protected_ancestry_fence(
        leaf,
        ErasureProtectedOperationV1::Read,
        &mut |sender| {
            first = sender.validate_world_replay_forks(&capability, &mut budget);
            if first.is_ok() {
                assert_eq!(bytes - budget.remaining_native_bytes(), phase_bytes);
                second = sender.validate_world_replay_forks(&capability, &mut budget);
                if !succeeds {
                    assert_eq!(
                        second.as_ref().map(|_| ()),
                        Err(&ErasureHostErrorV1::AdapterFailure)
                    );
                    let remaining = budget.remaining_native_bytes();
                    assert_eq!(
                        sender
                            .validate_world_replay_forks(&capability, &mut budget)
                            .map(|_| ()),
                        Err(ErasureHostErrorV1::AdapterFailure)
                    );
                    assert!(budget.check_time().is_err());
                    assert_eq!(budget.remaining_native_bytes(), remaining);
                }
            }
        },
    )?;
    let first = first?;
    assert_eq!(first.len(), 2);
    for (evidence, child) in first.iter().zip([leaf, parent]) {
        assert_eq!(evidence.requirement().child_timeline_id(), child);
    }
    if succeeds {
        let second = second?;
        assert_eq!(second.len(), first.len());
        for (actual, expected) in second.iter().zip(&first) {
            assert_eq!(actual.requirement(), expected.requirement());
        }
        assert_eq!(budget.remaining_native_bytes(), bytes - 2 * phase_bytes);
        budget.check_time()?;
    }
    Ok(())
}

#[test]
fn imported_memory_runtime_repeats_complete_validation_without_resetting_budget() -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    let parent = world.child_at(0)?.id;
    world.add_child_at(parent, Seq::from_u64(4), Shape::EmptyUnclassified)?;
    let built = [
        world.build(&Spec::default())?,
        world.build(&Spec::distinct(1))?,
    ];
    let mut authority_bytes = 0;
    for (index, built) in built.iter().enumerate() {
        let admission = ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?;
        authority_bytes += memory_authority_bytes(&world, built, &admission, index)?;
    }
    // [leaf,parent,root], [parent,root], [root]: three Fork and three root
    // carriers, six remembered IDs, three internal parent IDs, two Runtime
    // parent/cut copies, and three scans of four root Event sequence fields.
    let lineage_bytes = 3 * 49 + 3 * 25 + 6 * 16 + 3 * 16 + 2 * 24 + 3 * 4 * 8;
    assert_eq!(lineage_bytes, 510);
    let phase_bytes = authority_bytes + lineage_bytes;
    // Each authority scans both installed import rows: thirteen rows each.
    // Lineage has six metadata rows + twelve Event candidates. Chain hash,
    // length and suffix visits are eight (leaf), six (parent), plus six lineage.
    let (total_rows, total_visits) = (2 * (2 * 13 + 6 + 12), 2 * (8 + 6 + 6));
    assert_eq!((total_rows, total_visits), (88, 40));
    for (bytes, rows, visits, succeeds) in [
        (2 * phase_bytes, total_rows, total_visits, true),
        (2 * phase_bytes + 1, total_rows, total_visits, true),
        (2 * phase_bytes, total_rows + 1, total_visits, true),
        (2 * phase_bytes, total_rows, total_visits + 1, true),
        (2 * phase_bytes - 1, total_rows, total_visits, false),
        (2 * phase_bytes, total_rows - 1, total_visits, false),
        (2 * phase_bytes, total_rows, total_visits - 1, false),
    ] {
        let limits = ForkReplayReadLimitsV1::new(2, visits, rows, bytes, 1_000_000)?;
        exercise(&world, limits, phase_bytes, succeeds)?;
    }
    Ok(())
}
