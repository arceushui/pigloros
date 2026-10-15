//! Two imported `SQLite` arms share one exact ledger through four validations.

use super::super::super::{
    fixture::{Built, Fallible, Shape, Spec, World},
    Fault, ImportedVerifier,
};
use super::super::compare::{exercise, import_arm};
use super::{whole_sqlite_budget, SqliteReplayAccess, SqliteReplayFixture};
use pos_core::{ErasureRecoveryLimitsV1, ImportedForkAttributionAdmissionV1, TimelineId};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{sqlite::SqliteStore, ForkReplayReadLimitsV1, StoreConfig};
use std::sync::{atomic::AtomicUsize, Arc};

struct SqliteCompareFixture<'a> {
    world: &'a World,
    built: &'a [Built; 2],
    admissions: &'a [ImportedForkAttributionAdmissionV1; 2],
}

fn sqlite_compare_case(
    access: SqliteReplayAccess,
    fixture: &SqliteCompareFixture<'_>,
    limits: ForkReplayReadLimitsV1,
    succeeds: bool,
) -> Fallible<()> {
    let directory = (access != SqliteReplayAccess::HeldMemory)
        .then(tempfile::tempdir)
        .transpose()?;
    let path = match &directory {
        Some(directory) => directory
            .path()
            .join("imported-compare-budget.sqlite")
            .to_str()
            .ok_or("UTF-8 path")?
            .to_owned(),
        None => format!(
            "file:pigloros-561-compare-{}?mode=memory&cache=shared",
            TimelineId::new(),
        ),
    };
    // Only retain the named database; the unbound keeper performs no work
    // while the recovered public host holds its protected interval.
    let keeper = if access == SqliteReplayAccess::HeldMemory {
        Some(SqliteStore::open(&path)?)
    } else {
        None
    };
    let mut store = SqliteStore::open(&path)?;
    fixture.world.seed_destination(&mut store)?;
    let requirements = [0, 1].map(|index| {
        import_arm(
            &mut store,
            fixture.world,
            &fixture.built[index],
            &fixture.admissions[index],
            index,
        )
    });
    let [left, right] = requirements;
    let requirements = [left?, right?];
    drop(store);
    let verifier = Arc::new(ImportedVerifier {
        child: requirements[0].child_timeline_id(),
        parent: fixture.world.root,
        requirement: requirements[0],
        secondary: Some((requirements[1].child_timeline_id(), requirements[1])),
        fault: Fault::None,
        fault_target: None,
        limits_override: Some(limits),
        admissions: AtomicUsize::new(0),
    });
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let recovery = ErasureRecoveryLimitsV1::compiled_maximum();
    let host = if access == SqliteReplayAccess::ReadOnly {
        ErasureExecutionHostV1::open_read_only_with_authority(&path, &composition, recovery)?
    } else {
        ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite { path },
            &composition,
            recovery,
        )?
    };
    // Shared public Compare exercise checks all four admissions, both entire
    // distinct nonempty seeded States on refusal, and both once-folded maps.
    exercise(host, fixture.world, &verifier, succeeds)?;
    drop(keeper);
    Ok(())
}

fn sqlite_compare_budget_cases(access: SqliteReplayAccess) -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    assert_eq!(world.children.len(), 2);
    let built = [
        world.build(&Spec::default())?,
        world.build(&Spec::distinct(1))?,
    ];
    let admissions = [
        ImportedForkAttributionAdmissionV1::from_envelope(&built[0].envelope, 1)?,
        ImportedForkAttributionAdmissionV1::from_envelope(&built[1].envelope, 1)?,
    ];
    let fixture = SqliteCompareFixture {
        world: &world,
        built: &built,
        admissions: &admissions,
    };
    let mut totals = (0, 0, 0);
    for (index, (built, admission)) in built.iter().zip(&admissions).enumerate() {
        let arm = SqliteReplayFixture {
            world: &world,
            built,
            admission,
        };
        let (bytes, rows, visits) = whole_sqlite_budget(&arm, index, 4)?;
        totals.0 += bytes;
        totals.1 += rows;
        totals.2 += visits;
    }
    let (bytes, rows, visits) = totals;
    // SQLite admission lookups select only this child, unlike Memory's scan
    // over every import row. Both complete per-arm budgets are still charged.
    assert_eq!((rows, visits), (248, 24));
    for (bytes, rows, visits, succeeds) in [
        (bytes, rows, visits, true),
        (bytes + 1, rows, visits, true),
        (bytes, rows + 1, visits, true),
        (bytes, rows, visits + 1, true),
        (bytes - 1, rows, visits, false),
        (bytes, rows - 1, visits, false),
        (bytes, rows, visits - 1, false),
    ] {
        sqlite_compare_case(
            access,
            &fixture,
            ForkReplayReadLimitsV1::new(8, visits, rows, bytes, 30_000_000)?,
            succeeds,
        )?;
    }
    Ok(())
}

#[test]
fn imported_sqlite_rw_compare_shares_one_exact_budget_across_both_arms() -> Fallible<()> {
    sqlite_compare_budget_cases(SqliteReplayAccess::ReadWrite)
}

#[test]
fn imported_sqlite_ro_compare_shares_one_exact_budget_across_both_arms() -> Fallible<()> {
    sqlite_compare_budget_cases(SqliteReplayAccess::ReadOnly)
}

#[test]
fn imported_sqlite_held_memory_compare_shares_one_exact_budget_across_both_arms() -> Fallible<()> {
    sqlite_compare_budget_cases(SqliteReplayAccess::HeldMemory)
}
