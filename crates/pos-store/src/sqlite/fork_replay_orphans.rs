//! Bounded actual orphan visits, retaining the ordinary child-selection rules.

use pos_core::TimelineId;
use rusqlite::{params, Connection, Row, Rows};

use crate::{fork_replay::NativeReadContextV1, ForkEventAuthorityErrorV1 as Error};

type Result<T> = std::result::Result<T, Error>;

// Each scalar subquery seeks the existing globally unique Event-ID index. A
// returned code represents one actually visited Event: 1 for this child, 2
// for another Timeline. Absence returns NULL, not an invented Event row.
const OPERATIONS: &str = "SELECT 1,
    (SELECT CASE WHEN timeline_id = ?1 THEN 1 ELSE 2 END FROM events
        WHERE event_id = fork_append_operations.event_id)
    FROM fork_append_operations WHERE child_id = ?1
    UNION ALL SELECT NULL, NULL";
const ORIGINS: &str = "SELECT 1,
    (SELECT CASE WHEN timeline_id = ?1 THEN 1 ELSE 2 END FROM events
        WHERE event_id = fork_event_origins.event_id)
    FROM fork_event_origins INDEXED BY idx_fork_event_origins_child_v1
    WHERE substr(eor1_cbor, 9, 16) = ?2 UNION ALL SELECT NULL, NULL";
const INTERVENTIONS: &str = "SELECT 1,
    (SELECT CASE WHEN timeline_id = ?1 THEN 1 ELSE 2 END FROM events
        WHERE event_id = fork_intervention_admissions.event_id)
    FROM fork_intervention_admissions INDEXED BY idx_fork_intervention_admissions_child_v1
    WHERE substr(fia1_cbor, 43, 16) = ?2 UNION ALL SELECT NULL, NULL";

#[derive(Clone, Copy)]
enum OrphanKindV1 {
    Operation,
    Origin,
    Intervention,
}

impl OrphanKindV1 {
    const fn selection(self) -> (&'static str, bool) {
        match self {
            Self::Operation => (OPERATIONS, false),
            Self::Origin => (ORIGINS, true),
            Self::Intervention => (INTERVENTIONS, true),
        }
    }
}

fn visit(row: &Row<'_>, context: &mut NativeReadContextV1<'_, '_>) -> Result<Option<bool>> {
    row.get::<_, Option<bool>>(0)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|claimed| {
            claimed
                .map(|claimed| {
                    row.get::<_, Option<i64>>(1)
                        .map_err(|_| Error::CorruptAuthority)
                        .and_then(|event| {
                            // The outer row is the actual FOP/EOR/FIA visit. Count
                            // the additional Event index result only when it exists.
                            let count = if event.is_some() {
                                context.suffix_row().map_err(|_| Error::CorruptAuthority)
                            } else {
                                Ok(())
                            };
                            count.map(|()| claimed && event != Some(1))
                        })
                })
                .transpose()
        })
}

fn scan(
    conn: &Connection,
    child: TimelineId,
    kind: OrphanKindV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<bool> {
    context
        .bytes(ulid::ULID_LEN)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            let key = child.to_string();
            let (sql, child_bytes) = kind.selection();
            context
                .check()
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| conn.prepare(sql).map_err(|_| Error::CorruptAuthority))
                .and_then(|mut statement| {
                    context
                        .check()
                        .map_err(|_| Error::CorruptAuthority)
                        .and_then(|()| {
                            if child_bytes {
                                statement.query(params![key, child.inner().to_bytes().as_slice()])
                            } else {
                                statement.query([&key])
                            }
                            .map_err(|_| Error::CorruptAuthority)
                        })
                        .and_then(|mut rows| scan_rows(&mut rows, context))
                })
        })
}

fn scan_rows(rows: &mut Rows<'_>, context: &mut NativeReadContextV1<'_, '_>) -> Result<bool> {
    loop {
        let next = context
            .row_available()
            .map_err(|_| Error::CorruptAuthority)
            .and_then(|()| rows.next().map_err(|_| Error::CorruptAuthority))
            .and_then(|row| row.ok_or(Error::CorruptAuthority))
            .and_then(|row| {
                context
                    .suffix_row()
                    .map_err(|_| Error::CorruptAuthority)
                    .and_then(|()| visit(row, context))
            })
            .and_then(|orphan| {
                context
                    .check()
                    .map(|()| orphan)
                    .map_err(|_| Error::CorruptAuthority)
            });
        match next {
            Ok(None) => return Ok(false), // real final scalar boundary row
            Ok(Some(true)) => return Ok(true),
            Ok(Some(false)) => {}
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn reject_orphans_with_context(
    conn: &Connection,
    child: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<()> {
    // Preserve all three ordinary checks, including provenance after an
    // operation orphan. Each EXISTS stops at its first orphan, but the later
    // independent checks still execute before the combined result is used.
    scan(conn, child, OrphanKindV1::Operation, context)
        .and_then(|operation| {
            scan(conn, child, OrphanKindV1::Origin, context).map(|origin| (operation, origin))
        })
        .and_then(|(operation, origin)| {
            scan(conn, child, OrphanKindV1::Intervention, context)
                .map(|intervention| operation || origin || intervention)
        })
        .and_then(|orphan| {
            if orphan {
                Err(Error::CorruptAuthority)
            } else {
                Ok(())
            }
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World},
        ForkAttributionAuthorityImportPortV1, ForkEventProvenanceAuthorityPortV1,
        ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
    use pos_core::{
        store::{EventStore, SeqRange},
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1,
    };
    use std::time::Duration;

    fn fixture(shape: Shape) -> Fallible<(tempfile::TempDir, super::super::SqliteStore, World)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("orphan-visits.sqlite3");
        let mut store = super::super::SqliteStore::open(path.to_str().ok_or("fixture path")?)?;
        let world = World::new(shape, false)?;
        let built = world.build(&Spec::default())?;
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        assert_eq!(
            u64::try_from(
                store
                    .read_fork_event_suffix(world.child_at(0)?.id, 1)?
                    .len()
            )?,
            shape.events()
        );
        Ok((directory, store, world))
    }

    fn read(
        conn: &Connection,
        child: TimelineId,
        rows: usize,
        bytes: usize,
    ) -> Fallible<(Result<()>, usize, bool)> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, rows, bytes, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = reject_orphans_with_context(
            conn,
            child,
            &mut NativeReadContextV1::protected(&mut budget),
        );
        Ok((
            result,
            budget.remaining_native_bytes(),
            budget.check_time().is_ok(),
        ))
    }

    #[test]
    fn actual_orphan_visits_and_boundary_rows_have_exact_shared_limits() -> Fallible<()> {
        for (shape, events, interventions) in [
            (Shape::Mixed, 4, 2),
            (Shape::EmptyClassified, 0, 0),
            (Shape::EmptyUnclassified, 0, 0),
        ] {
            let (_directory, store, world) = fixture(shape)?;
            let child = world.child_at(0)?.id;
            let bytes = 3 * child.to_string().len();
            let rows = 4 * events + 2 * interventions + 3;
            let interval = store.begin_protected_effect_interval()?;
            for (row_limit, byte_limit, success) in [
                (rows, bytes, true),
                (rows - 1, bytes, false),
                (rows, bytes - 1, false),
            ] {
                let (result, remaining, open) = read(&store.conn, child, row_limit, byte_limit)?;
                assert_eq!(result.is_ok(), success);
                assert_eq!(open, success);
                if success {
                    assert_eq!(remaining, 0);
                }
                assert!(!store.conn.is_autocommit());
            }
            for (row_limit, byte_limit, success) in [
                (rows * 2, bytes * 2, true),
                (rows * 2 - 1, bytes * 2, false),
                (rows * 2, bytes * 2 - 1, false),
            ] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, row_limit, byte_limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = (0..2).try_for_each(|_| {
                    reject_orphans_with_context(
                        &store.conn,
                        child,
                        &mut NativeReadContextV1::protected(&mut budget),
                    )
                });
                assert_eq!(result.is_ok(), success);
                assert_eq!(budget.check_time().is_ok(), success);
                if success {
                    assert_eq!(budget.remaining_native_bytes(), 0);
                }
            }
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
        Ok(())
    }

    #[test]
    fn unrelated_provenance_preserves_the_requested_childs_exact_budget() -> Fallible<()> {
        let (_directory, store, world) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        let root_event = store.read(world.root, SeqRange::all())?.remove(0);
        store.conn.execute(
            "INSERT INTO fork_event_origins VALUES (?1, x'00')",
            [pos_core::EventId::new().to_string()],
        )?;
        store.conn.execute(
            "INSERT INTO fork_event_origins VALUES (?1, 'malformed unrelated TEXT')",
            [root_event.id.to_string()],
        )?;
        store.conn.execute(
            "INSERT INTO fork_intervention_admissions VALUES (?1, x'00')",
            [pos_core::EventId::new().to_string()],
        )?;
        // The FOP scan is selected through the child's index, so an unrelated
        // native-corrupt FOP is not visited or decoded by this operation.
        store.conn.execute(
            "INSERT INTO fork_append_operations VALUES (?1, ?2, 1, ?3, x'00')",
            params![
                vec![222_u8; 32],
                TimelineId::new().to_string(),
                pos_core::EventId::new().to_string()
            ],
        )?;
        assert!(!super::super::sqlite_has_orphaned_fork_provenance(
            &store.conn,
            child
        )?);
        let bytes = 3 * child.to_string().len();
        // Only this child's four operations/origins, two interventions and
        // three boundary rows belong to this read. Foreign provenance is not
        // a reason to enlarge the independently derived 23-visit allowance.
        let (result, remaining, open) = read(&store.conn, child, 23, bytes)?;
        result?;
        assert_eq!(remaining, 0);
        assert!(open);
        let (result, _, open) = read(&store.conn, child, 22, bytes)?;
        assert_eq!(result, Err(Error::CorruptAuthority));
        assert!(!open);
        Ok(())
    }

    #[test]
    fn malformed_binary_child_claims_remain_selected_and_rejected() -> Fallible<()> {
        let (_directory, store, world) = fixture(Shape::EmptyUnclassified)?;
        let child = world.child_at(0)?.id;
        let root = store.read(world.root, SeqRange::all())?.remove(0).id.to_string();
        for (table, offset) in [("fork_event_origins", 8), ("fork_intervention_admissions", 42)] {
            for event in [pos_core::EventId::new().to_string(), root.clone()] {
                let mut malformed = vec![0_u8; offset + 16];
                malformed[offset..].copy_from_slice(&child.inner().to_bytes());
                store.conn.execute_batch("SAVEPOINT malformed_child_claim")?;
                store.conn.execute(&format!("INSERT INTO {table} VALUES (?1, ?2)"), params![event, malformed])?;
                assert!(super::super::sqlite_has_orphaned_fork_provenance(&store.conn, child)?);
                assert!(super::super::sqlite_fork_suffix_rows(&store.conn, child).is_err());
                assert_eq!(read(&store.conn, child, 32, 78)?.0, Err(Error::CorruptAuthority));
                store.conn.execute_batch("ROLLBACK TO malformed_child_claim; RELEASE malformed_child_claim")?;
            }
        }
        Ok(())
    }

    #[test]
    fn selected_orphans_and_cross_timeline_event_substitutions_preserve_rejection() -> Fallible<()>
    {
        let (_directory, store, world) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        let root = store
            .read(world.root, SeqRange::all())?
            .remove(0)
            .id
            .to_string();
        for table in [
            "fork_append_operations",
            "fork_event_origins",
            "fork_intervention_admissions",
        ] {
            for replacement in [pos_core::EventId::new().to_string(), root.clone()] {
                store.conn.execute_batch("SAVEPOINT orphan_fault")?;
                store.conn.execute(&format!("UPDATE {table} SET event_id = ?1 WHERE rowid = (SELECT min(rowid) FROM {table})"), [&replacement])?;
                assert!(super::super::sqlite_fork_suffix_rows(&store.conn, child).is_err());
                assert_eq!(
                    read(&store.conn, child, 128, 4096)?.0,
                    Err(Error::CorruptAuthority)
                );
                store
                    .conn
                    .execute_batch("ROLLBACK TO orphan_fault; RELEASE orphan_fault")?;
            }
        }
        Ok(())
    }

    #[test]
    fn actual_orphan_loops_keep_original_guard_checks_between_rows() -> Fallible<()> {
        let (_directory, store, world) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        for regression in [false, true] {
            let mut failures = 0;
            let mut successes = 0;
            for boundary in 2..=256 {
                let initial = if regression {
                    Duration::from_micros(1)
                } else {
                    Duration::ZERO
                };
                let later = if regression {
                    Duration::ZERO
                } else {
                    Duration::from_micros(11)
                };
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(initial, boundary).chain([later]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 23, 78, 10)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = reject_orphans_with_context(
                    &store.conn,
                    child,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if result.is_ok() {
                    successes += 1;
                } else {
                    failures += 1;
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
            }
            assert!(failures > 0);
            assert!(successes > 0);
        }
        Ok(())
    }

    #[test]
    fn pinned_backend_orphan_queries_use_indexed_event_seeks_without_sorting() -> Fallible<()> {
        let (_directory, store, world) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        for (kind, table, index) in [
            (OrphanKindV1::Operation, "fork_append_operations", ""),
            (
                OrphanKindV1::Origin,
                "fork_event_origins",
                "idx_fork_event_origins_child_v1",
            ),
            (
                OrphanKindV1::Intervention,
                "fork_intervention_admissions",
                "idx_fork_intervention_admissions_child_v1",
            ),
        ] {
            let (sql, child_bytes) = kind.selection();
            let mut statement = store.conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
            let mut rows = if child_bytes {
                statement.query(params![
                    child.to_string(),
                    child.inner().to_bytes().as_slice()
                ])?
            } else {
                statement.query([child.to_string()])?
            };
            let mut details = Vec::new();
            while let Some(row) = rows.next()? {
                details.push(row.get::<_, String>(3)?);
            }
            assert!(details
                .iter()
                .any(|line| line.contains("SEARCH events USING INDEX idx_events_event_id")));
            assert!(!details.iter().any(|line| line.contains("TEMP B-TREE")
                || line.contains("SCAN events")
                || line.contains(&format!("SCAN {table}"))));
            if matches!(kind, OrphanKindV1::Operation) {
                assert!(details.iter().any(|line| line
                    .contains("SEARCH fork_append_operations USING INDEX")
                    && line.contains("child_id=?")));
            } else {
                assert!(
                    details.iter().any(|line| line
                        .contains(&format!("SEARCH {table} USING INDEX {index}"))
                        && line.contains("<expr>=?")),
                    "{details:?}"
                );
            }
        }
        let mut statement = store.conn.prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            super::super::fork_provenance_indexes::ORPHANED_PROVENANCE
        ))?;
        let details = statement
            .query_map(
                params![child.to_string(), child.inner().to_bytes().as_slice()],
                |row| row.get::<_, String>(3),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (table, index) in [
            ("fork_event_origins", "idx_fork_event_origins_child_v1"),
            (
                "fork_intervention_admissions",
                "idx_fork_intervention_admissions_child_v1",
            ),
        ] {
            assert!(
                details.iter().any(|line| line
                    .contains(&format!("SEARCH {table} USING INDEX {index}"))
                    && line.contains("<expr>=?")),
                "{details:?}"
            );
        }
        assert_eq!(
            details
                .iter()
                .filter(|line| line.contains("SEARCH events USING INDEX idx_events_event_id"))
                .count(),
            2
        );
        assert!(!details.iter().any(|line| line.contains("TEMP B-TREE")
            || line.contains("SCAN events")
            || line.contains("SCAN fork_")));
        Ok(())
    }
}
