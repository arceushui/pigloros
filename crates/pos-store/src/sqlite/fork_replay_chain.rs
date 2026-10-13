//! Actual ancestry metadata rows, collection copies and logical-head checks.

use std::collections::HashSet;

use pos_core::{ForkAdmissionErrorV1 as Error, Seq, TimelineId};
use rusqlite::{Connection, Row};

use super::{
    fork_replay_row::{selected_field_with_context, SelectedRowV1},
    fork_segment_length, BoundedForkSegment, DecodedForkChainRow, ForkChainRow,
};
use crate::fork_replay::NativeReadContextV1;

type Result<T> = std::result::Result<T, Error>;

fn parent_length(row: &Row<'_>) -> Result<Option<usize>> {
    row.get::<_, bool>(0)
        .map_err(|_| Error::StorageIndeterminate)
        .and_then(|null| {
            if null {
                return Ok(None);
            }
            row.get::<_, bool>(1)
                .map_err(|_| Error::StorageIndeterminate)
                .and_then(|text| {
                    if !text {
                        return Err(Error::StorageIndeterminate);
                    }
                    row.get::<_, i64>(2)
                        .map_err(|_| Error::StorageIndeterminate)
                        .and_then(|length| {
                            // The existing ULID parser requires this width.
                            // Probe it before constructing the raw String.
                            if usize::try_from(length).ok() == Some(ulid::ULID_LEN) {
                                Ok(Some(ulid::ULID_LEN))
                            } else {
                                Err(Error::CorruptAuthority)
                            }
                        })
                })
        })
}

fn metadata_with_context(
    conn: &Connection,
    timeline: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<DecodedForkChainRow> {
    context
        .bytes(ulid::ULID_LEN)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            let key = timeline.to_string();
            selected_field_with_context(conn, SelectedRowV1::ChainProbe(&key), context, |row, _| {
                parent_length(row).and_then(|parent| {
                    row.get::<_, bool>(3)
                        .map_err(|_| Error::StorageIndeterminate)
                        .and_then(|fork_integer_or_null| {
                            row.get::<_, bool>(4)
                                .map_err(|_| Error::StorageIndeterminate)
                                .and_then(|head_integer| {
                                    if fork_integer_or_null && head_integer {
                                        Ok(parent)
                                    } else {
                                        Err(Error::StorageIndeterminate)
                                    }
                                })
                        })
                })
            })
            .and_then(|length| length.ok_or(Error::CorruptAuthority))
            .and_then(|parent| {
                selected_field_with_context(
                    conn,
                    SelectedRowV1::ChainFields(&key),
                    context,
                    |row, context| {
                        context
                            .bytes(parent.unwrap_or(0))
                            .map_err(|_| Error::CorruptAuthority)
                            .and_then(|()| {
                                ForkChainRow::read(row).map_err(|_| Error::StorageIndeterminate)
                            })
                            .and_then(|row| {
                                row.decode_fields().map_err(|_| Error::CorruptAuthority)
                            })
                    },
                )
                .and_then(|row| row.ok_or(Error::CorruptAuthority))
            })
        })
}

pub(super) fn chain_with_context(
    conn: &Connection,
    timeline: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Vec<BoundedForkSegment>> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current = timeline;
    loop {
        let next = context
            .node(chain.len())
            .map_err(|_| Error::CorruptAuthority)
            // Logical native unit of the actual cycle-set copy, not Rust
            // object size, padding, capacity or an invented serialization.
            .and_then(|()| context.bytes(16).map_err(|_| Error::CorruptAuthority))
            .and_then(|()| {
                if visited.insert(current) {
                    metadata_with_context(conn, current, context)
                } else {
                    Err(Error::CorruptAuthority)
                }
            })
            .and_then(|row| retain_segment_with_context(&mut chain, current, &row, context));
        match next {
            Ok(Some(parent)) => current = parent,
            Ok(None) => break,
            Err(error) => return Err(error),
        }
    }
    chain.reverse();
    context
        .check()
        .map(|()| chain)
        .map_err(|_| Error::CorruptAuthority)
}

fn retain_segment_with_context(
    chain: &mut Vec<BoundedForkSegment>,
    current: TimelineId,
    row: &DecodedForkChainRow,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<TimelineId>> {
    let (fork, parent, head) = match row {
        DecodedForkChainRow::Root { head } => (None, None, *head),
        DecodedForkChainRow::Fork { parent, fork, head } => (Some(*fork), Some(*parent), *head),
    };
    // Actual retained Timeline ID and head; non-root entries also retain a cut.
    context
        .bytes(16 + 8)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            if fork.is_some() {
                context.bytes(8).map_err(|_| Error::CorruptAuthority)
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            chain.push(BoundedForkSegment {
                id: current,
                fork,
                head,
            });
            context
                .check()
                .map(|()| parent)
                .map_err(|_| Error::CorruptAuthority)
        })
}

pub(super) fn logical_head_with_context(
    conn: &Connection,
    timeline: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Seq> {
    chain_with_context(conn, timeline, context)
        .and_then(|chain| logical_head_from_chain(&chain, context))
}

fn logical_head_from_chain(
    chain: &[BoundedForkSegment],
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Seq> {
    chain
        .iter()
        .enumerate()
        .try_fold(0_u64, |head, (index, segment)| {
            context
                .check()
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| {
                    // Reuse scalar heads from these exact rows in the
                    // already-held snapshot; no duplicate native query.
                    fork_segment_length(
                        segment.fork.map_or(0, Seq::as_u64),
                        segment.head,
                        chain
                            .get(index + 1)
                            .and_then(|next| next.fork)
                            .map(Seq::as_u64),
                    )
                    .map_err(|_| Error::CorruptAuthority)
                })
                .and_then(|length| head.checked_add(length).ok_or(Error::CorruptAuthority))
        })
        .and_then(|head| {
            context
                .check()
                .map(|()| Seq::from_u64(head))
                .map_err(|_| Error::CorruptAuthority)
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::{
        store::EventStore,
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        CanonicalBytes, EntityId, EventDraft, Kind,
    };
    use rusqlite::{params, types::Value};
    use std::{sync::Arc, time::Duration};

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn append(
        store: &mut super::super::SqliteStore,
        timeline: TimelineId,
        count: usize,
    ) -> Fallible<()> {
        let drafts: Vec<_> = (0..count)
            .map(|_| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new("ancestry.fixture"),
                    CanonicalBytes::from_vec(vec![0xf6]),
                )
            })
            .collect();
        store.append(timeline, &drafts)?;
        Ok(())
    }

    fn fixture(
        events: bool,
    ) -> Fallible<(
        tempfile::TempDir,
        super::super::SqliteStore,
        [TimelineId; 3],
    )> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ancestry.sqlite3");
        let mut store = super::super::SqliteStore::open(path.to_str().ok_or("ancestry path")?)?;
        // Public structural Fork setup, not an FCC or protected-use issuer.
        store.bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))?;
        let root = store.create_timeline("root")?.id();
        if events {
            append(&mut store, root, 3)?;
        }
        let child = store
            .fork(root, Seq::from_u64(if events { 2 } else { 0 }), "child")?
            .id();
        if events {
            append(&mut store, child, 2)?;
        }
        let grandchild = store
            .fork(
                child,
                Seq::from_u64(if events { 4 } else { 0 }),
                "grandchild",
            )?
            .id();
        if events {
            append(&mut store, grandchild, 1)?;
        }
        Ok((directory, store, [root, child, grandchild]))
    }

    fn expected_cost(ids: &[TimelineId]) -> usize {
        // Independent inventory of actual copies: cycle-set ID, query String,
        // retained segment ID/head, and for each non-root raw parent/cut.
        ids.iter()
            .enumerate()
            .map(|(index, id)| {
                16 + id.to_string().len()
                    + 16
                    + 8
                    + if index == 0 {
                        0
                    } else {
                        ids[index - 1].to_string().len() + 8
                    }
            })
            .sum()
    }

    #[test]
    fn file_backed_ancestry_charges_actual_rows_strings_and_collection_copies() -> Fallible<()> {
        let (_directory, store, ids) = fixture(false)?;
        store.conn.execute_batch("BEGIN IMMEDIATE")?;
        for count in 1..=ids.len() {
            let selected = &ids[..count];
            let expected = expected_cost(selected);
            let timeline = ids[count - 1];
            assert_eq!(store.logical_head(timeline)?, Seq::ZERO);
            for bytes in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits =
                    ForkReplayReadLimitsV1::new(count.max(1), count, count * 2, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = chain_with_context(
                    &store.conn,
                    timeline,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if bytes == expected {
                    let chain = result?;
                    assert_eq!(
                        chain.iter().map(|segment| segment.id).collect::<Vec<_>>(),
                        selected
                    );
                    assert!(chain.iter().all(|segment| segment.head == 0));
                    assert_eq!(chain[0].fork, None);
                    assert!(chain[1..]
                        .iter()
                        .all(|segment| segment.fork == Some(Seq::ZERO)));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    budget.check_time()?;
                } else {
                    assert!(result.is_err());
                    assert!(budget.check_time().is_err());
                }
                assert!(!store.conn.is_autocommit());
            }
        }
        store.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    #[test]
    fn ancestry_depth_resets_per_walk_but_visits_rows_and_bytes_accumulate() -> Fallible<()> {
        let (_directory, store, ids) = fixture(false)?;
        let cost = expected_cost(&ids);
        for (depth, visits, rows, bytes, walks, success) in [
            (2, 3, 6, cost, 1, true),
            (1, 3, 6, cost, 1, false),
            (2, 2, 6, cost, 1, false),
            (2, 3, 5, cost, 1, false),
            (2, 3, 6, cost - 1, 1, false),
            (2, 6, 12, cost * 2, 2, true),
            (2, 5, 12, cost * 2, 2, false),
            (2, 6, 11, cost * 2, 2, false),
            (2, 6, 12, cost * 2 - 1, 2, false),
        ] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(depth, visits, rows, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = (0..walks).try_for_each(|_| {
                logical_head_with_context(
                    &store.conn,
                    ids[2],
                    &mut NativeReadContextV1::protected(&mut budget),
                )
                .map(|head| assert_eq!(head, Seq::ZERO))
            });
            assert_eq!(result.is_ok(), success);
            if success {
                assert_eq!(budget.remaining_native_bytes(), 0);
                budget.check_time()?;
            } else {
                assert_eq!(result, Err(Error::CorruptAuthority));
                assert!(budget.check_time().is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn real_nested_cuts_keep_ordinary_heads_and_protected_genesis_identical() -> Fallible<()> {
        let (_directory, store, ids) = fixture(true)?;
        store.conn.execute_batch("BEGIN IMMEDIATE")?;
        for (index, expected_head) in [3, 4, 5].into_iter().enumerate() {
            let cost = expected_cost(&ids[..=index]);
            let ordinary = store.logical_head(ids[index])?;
            assert_eq!(ordinary.as_u64(), expected_head);
            for at in [0, expected_head + 1] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits =
                    ForkReplayReadLimitsV1::new(2, index + 1, (index + 1) * 2, cost, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let protected = super::super::SqliteStore::compute_chain_hash_at_with_context_on(
                    &store.conn,
                    store.hasher.as_ref(),
                    ids[index],
                    Seq::from_u64(at),
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                let public = store.compute_chain_hash_at(ids[index], Seq::from_u64(at));
                assert_eq!(
                    protected.map_err(|error| error.to_string()),
                    public.map_err(|error| error.to_string())
                );
                assert_eq!(budget.remaining_native_bytes(), 0);
                budget.check_time()?;
            }
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits =
                ForkReplayReadLimitsV1::new(2, index + 1, (index + 1) * 2, cost, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                logical_head_with_context(
                    &store.conn,
                    ids[index],
                    &mut NativeReadContextV1::protected(&mut budget)
                )?,
                ordinary
            );
        }
        store.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    fn raw_fixture() -> Fallible<(Connection, TimelineId, TimelineId)> {
        let conn = Connection::open_in_memory()?;
        // Narrow impossible-state injection with no affinity/constraints.
        conn.execute_batch("CREATE TABLE timelines (id, parent_id, fork_seq, head_seq)")?;
        let root = TimelineId::from_ulid(ulid::Ulid::from_bytes([0xab; 16]));
        let child = TimelineId::from_ulid(ulid::Ulid::from_bytes([0xcd; 16]));
        conn.execute(
            "INSERT INTO timelines VALUES (?1, NULL, NULL, 0)",
            [root.to_string()],
        )?;
        conn.execute(
            "INSERT INTO timelines VALUES (?1, ?2, 0, 0)",
            params![child.to_string(), root.to_string()],
        )?;
        Ok((conn, root, child))
    }

    fn protected_head(conn: &Connection, timeline: TimelineId) -> Result<Seq> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(4, 8, 16, 4096, 1_000_000)
            .map_err(|_| Error::CorruptAuthority)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)
            .map_err(|_| Error::CorruptAuthority)?;
        logical_head_with_context(
            conn,
            timeline,
            &mut NativeReadContextV1::protected(&mut budget),
        )
    }

    #[test]
    fn shared_metadata_validation_preserves_ordinary_error_precedence_and_ulid_aliases(
    ) -> Fallible<()> {
        let (conn, root, child) = raw_fixture()?;
        let parent = root.to_string();
        for (parent_value, fork_seq, head_seq, expected) in [
            (
                Some("invalid"),
                Some(-1),
                -1,
                format!("timeline {child} has a negative Event head"),
            ),
            (
                None,
                Some(-1),
                0,
                format!("root timeline {child} has Fork sequence metadata"),
            ),
            (
                Some("!!!!!!!!!!!!!!!!!!!!!!!!!!"),
                Some(-1),
                0,
                "invalid ULID: !!!!!!!!!!!!!!!!!!!!!!!!!!".to_owned(),
            ),
            (
                Some(parent.as_str()),
                Some(-1),
                0,
                format!("Fork timeline {child} has a negative Fork sequence"),
            ),
            (
                Some(parent.as_str()),
                None,
                0,
                format!("Fork timeline {child} is missing its Fork sequence"),
            ),
        ] {
            conn.execute(
                "UPDATE timelines SET parent_id = ?1, fork_seq = ?2, head_seq = ?3 WHERE id = ?4",
                params![parent_value, fork_seq, head_seq, child.to_string()],
            )?;
            let error = super::super::SqliteStore::logical_head_unchecked_on(&conn, child)
                .err()
                .ok_or("ordinary metadata must fail")?;
            assert!(error.to_string().contains(&expected), "{error}");
            assert_eq!(protected_head(&conn, child), Err(Error::CorruptAuthority));
        }
        let lowercase = parent.to_lowercase();
        assert_ne!(lowercase, parent);
        for parent in [&parent, &lowercase] {
            conn.execute(
                "UPDATE timelines SET parent_id = ?1, fork_seq = 0, head_seq = 0 WHERE id = ?2",
                params![parent, child.to_string()],
            )?;
            assert_eq!(protected_head(&conn, child)?, Seq::ZERO);
            assert_eq!(
                super::super::SqliteStore::logical_head_unchecked_on(&conn, child)?,
                Seq::ZERO
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_segment_cuts_overflow_cycles_absence_and_storage_fail_closed() -> Fallible<()> {
        let (conn, root, child) = raw_fixture()?;
        conn.execute(
            "UPDATE timelines SET fork_seq = 1 WHERE id = ?1",
            [child.to_string()],
        )?;
        let error = super::super::SqliteStore::logical_head_unchecked_on(&conn, child)
            .err()
            .ok_or("beyond parent")?;
        assert!(error
            .to_string()
            .contains("Fork point exceeds parent logical Event head"));
        assert_eq!(protected_head(&conn, child), Err(Error::CorruptAuthority));
        let grandchild = TimelineId::from_ulid(ulid::Ulid::from_bytes([0xef; 16]));
        conn.execute(
            "UPDATE timelines SET head_seq = 2 WHERE id = ?1",
            [root.to_string()],
        )?;
        conn.execute(
            "INSERT INTO timelines VALUES (?1, ?2, 0, 0)",
            params![grandchild.to_string(), child.to_string()],
        )?;
        let error = super::super::SqliteStore::logical_head_unchecked_on(&conn, grandchild)
            .err()
            .ok_or("before inherited")?;
        assert!(error
            .to_string()
            .contains("Fork point precedes inherited history"));
        assert_eq!(
            protected_head(&conn, grandchild),
            Err(Error::CorruptAuthority)
        );
        conn.execute("UPDATE timelines SET head_seq = ?1", [i64::MAX])?;
        conn.execute(
            "UPDATE timelines SET fork_seq = ?1 WHERE id = ?2",
            params![i64::MAX, child.to_string()],
        )?;
        conn.execute(
            "UPDATE timelines SET fork_seq = ?1 WHERE id = ?2",
            params![i64::MAX, grandchild.to_string()],
        )?;
        // These durable scalar maxima still fit the stitched u64 head.
        assert!(protected_head(&conn, grandchild).is_ok());
        conn.execute(
            "UPDATE timelines SET parent_id = ?1, fork_seq = 0 WHERE id = ?2",
            params![grandchild.to_string(), root.to_string()],
        )?;
        assert_eq!(
            protected_head(&conn, grandchild),
            Err(Error::CorruptAuthority)
        );
        assert!(super::super::SqliteStore::logical_head_unchecked_on(&conn, grandchild).is_err());
        conn.execute("DELETE FROM timelines WHERE id = ?1", [child.to_string()])?;
        assert_eq!(protected_head(&conn, child), Err(Error::CorruptAuthority));
        conn.execute_batch("DROP TABLE timelines")?;
        assert_eq!(
            protected_head(&conn, root),
            Err(Error::StorageIndeterminate)
        );
        Ok(())
    }

    #[test]
    fn checked_head_arithmetic_has_exact_and_one_over_witnesses() -> Fallible<()> {
        let (_conn, root, child) = raw_fixture()?;
        // A pure arithmetic witness, not a representable SQLite row or an
        // authority fixture. Exercise the actual retained-chain sum owner.
        for (prefix, last_head, expected) in [
            (u64::MAX - 1, 1, Ok(Seq::from_u64(u64::MAX))),
            (u64::MAX, 1, Err(Error::CorruptAuthority)),
        ] {
            let chain = [
                BoundedForkSegment {
                    id: root,
                    fork: None,
                    head: prefix,
                },
                BoundedForkSegment {
                    id: child,
                    fork: Some(Seq::from_u64(prefix)),
                    head: last_head,
                },
            ];
            assert_eq!(
                logical_head_from_chain(&chain, &mut NativeReadContextV1::ordinary()),
                expected
            );
            assert_eq!(
                super::super::SqliteStore::add_logical_segment(prefix, last_head)
                    .map(Seq::from_u64)
                    .map_err(|_| Error::CorruptAuthority),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn raw_parent_type_width_utf8_and_scalar_types_are_gated_before_getters() -> Fallible<()> {
        for (parent, fork_seq, head, expected) in [
            (
                Value::Blob(vec![1; 26]),
                Value::Integer(0),
                Value::Integer(0),
                Error::StorageIndeterminate,
            ),
            (
                Value::Text("x".repeat(25)),
                Value::Integer(0),
                Value::Integer(0),
                Error::CorruptAuthority,
            ),
            (
                Value::Text("x".repeat(27)),
                Value::Integer(0),
                Value::Integer(0),
                Error::CorruptAuthority,
            ),
            (
                Value::Null,
                Value::Text("0".into()),
                Value::Integer(0),
                Error::StorageIndeterminate,
            ),
            (
                Value::Null,
                Value::Real(0.0),
                Value::Integer(0),
                Error::StorageIndeterminate,
            ),
            (
                Value::Null,
                Value::Null,
                Value::Null,
                Error::StorageIndeterminate,
            ),
            (
                Value::Null,
                Value::Null,
                Value::Blob(vec![1]),
                Error::StorageIndeterminate,
            ),
        ] {
            let (conn, _, child) = raw_fixture()?;
            conn.execute(
                "UPDATE timelines SET parent_id = ?1, fork_seq = ?2, head_seq = ?3 WHERE id = ?4",
                params![parent, fork_seq, head, child.to_string()],
            )?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(2, 3, 6, 512, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                logical_head_with_context(
                    &conn,
                    child,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(expected)
            );
            assert_eq!(budget.remaining_native_bytes(), 512 - 16 - 26);
        }
        let (conn, _, child) = raw_fixture()?;
        conn.execute_batch("UPDATE timelines SET parent_id = CAST(X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' AS TEXT)")?;
        assert_eq!(
            protected_head(&conn, child),
            Err(Error::StorageIndeterminate)
        );
        Ok(())
    }

    #[test]
    fn ancestry_checks_original_epoch_at_every_metadata_and_copy_batch() -> Fallible<()> {
        let (_directory, store, ids) = fixture(false)?;
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..512 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(2, 3, 6, expected_cost(&ids), 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = logical_head_with_context(
                    &store.conn,
                    ids[2],
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if result.is_ok() {
                    assert_eq!(result?, Seq::ZERO);
                    completed = true;
                    break;
                }
                assert_eq!(result, Err(Error::CorruptAuthority));
                assert!(budget.check_time().is_err());
            }
            assert!(completed, "every ancestry checkpoint was reached");
        }
        Ok(())
    }
}
