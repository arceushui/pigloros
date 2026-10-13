//! Actual child-name and textual-lineage materialization during FCC recovery.

use pos_core::{ForkAdmissionErrorV1 as Error, ForkAdmissionRecordV1};
use rusqlite::{Connection, Row};

use super::fork_replay_row::{selected_field_with_context, SelectedRowV1};
use crate::fork_replay::NativeReadContextV1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
struct TextColumnV1 {
    null: usize,
    text: usize,
    length: usize,
    value: usize,
}

const NAME: TextColumnV1 = TextColumnV1 { null: 0, text: 1, length: 2, value: 0 };
const PARENT: TextColumnV1 = TextColumnV1 { null: 3, text: 4, length: 5, value: 1 };
const FORK_SEQ_TYPE: usize = 6;
const FORK_SEQ_VALUE: usize = 2;

struct ChildLengthsV1 {
    name: Option<usize>,
    parent: Option<usize>,
}

fn text_length(row: &Row<'_>, column: TextColumnV1) -> Result<Option<usize>> {
    row.get::<_, bool>(column.null)
        .map_err(|_| Error::StorageIndeterminate)
        .and_then(|null| {
            if null {
                return Ok(None);
            }
            row.get::<_, bool>(column.text)
                .map_err(|_| Error::StorageIndeterminate)
                .and_then(|text| {
                    if !text {
                        return Err(Error::StorageIndeterminate);
                    }
                    row.get::<_, i64>(column.length)
                        .map_err(|_| Error::StorageIndeterminate)
                        .and_then(|length| usize::try_from(length).map_err(|_| Error::CorruptAuthority))
                        .map(Some)
                })
        })
}

fn text_with_context(
    row: &Row<'_>,
    column: TextColumnV1,
    length: Option<usize>,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<String>> {
    context
        .bytes(length.unwrap_or(0))
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| row.get::<_, Option<String>>(column.value).map_err(|_| Error::StorageIndeterminate))
        .and_then(|value| context.check().map(|()| value).map_err(|_| Error::CorruptAuthority))
}

fn child_lengths(
    conn: &Connection,
    child_key: &str,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<ChildLengthsV1>> {
    selected_field_with_context(conn, SelectedRowV1::ChildProbe(child_key), context, |row, _| {
        text_length(row, NAME).and_then(|name| {
            text_length(row, PARENT).and_then(|parent| {
                row.get::<_, bool>(FORK_SEQ_TYPE)
                    .map_err(|_| Error::StorageIndeterminate)
                    .and_then(|integer_or_null| {
                        if integer_or_null {
                            Ok(ChildLengthsV1 { name, parent })
                        } else {
                            Err(Error::StorageIndeterminate)
                        }
                    })
            })
        })
    })
}

pub(super) fn child_name_with_context(
    conn: &Connection,
    admission: &ForkAdmissionRecordV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<String>> {
    context
        .bytes(ulid::ULID_LEN)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            let input = admission.input();
            let child_key = input.child_timeline_id.to_string();
            child_lengths(conn, &child_key, context).and_then(|lengths| {
                lengths.map_or(Ok(None), |lengths| {
                    selected_field_with_context(
                        conn, SelectedRowV1::ChildFields(&child_key), context, |row, context| {
                            text_with_context(row, NAME, lengths.name, context).and_then(|name| {
                                text_with_context(row, PARENT, lengths.parent, context).and_then(|parent| {
                                    row.get::<_, Option<i64>>(FORK_SEQ_VALUE)
                                        .map_err(|_| Error::StorageIndeterminate)
                                        .map(|fork_seq| (name, parent, fork_seq))
                                })
                            })
                        },
                    )
                    .and_then(|timeline| timeline.ok_or(Error::CorruptAuthority))
                    .and_then(|(name, parent, fork_seq)| {
                        context
                            .bytes(ulid::ULID_LEN)
                            .map_err(|_| Error::CorruptAuthority)
                            .and_then(|()| {
                                // Preserve canonical textual equality, not a
                                // more permissive ULID parse/normalization.
                                let parent_key = input.parent_timeline_id.to_string();
                                let matches = parent.as_deref() == Some(parent_key.as_str())
                                    && fork_seq.and_then(|seq| u64::try_from(seq).ok())
                                        .is_some_and(|seq| seq == input.parent_logical_head);
                                context
                                    .check()
                                    .map(|()| if matches { name } else { None })
                                    .map_err(|_| Error::CorruptAuthority)
                            })
                    })
                })
            })
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
        ForkAdmissionRecordInputV1, ForkAttributionOriginV1, Hash, OwnerIdV1, Seq, TimelineId,
    };
    use rusqlite::{params, types::Value};
    use std::{sync::Arc, time::Duration};

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn admission(parent: TimelineId, child: TimelineId) -> Fallible<ForkAdmissionRecordV1> {
        Ok(ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
            operation_id: Hash::from_bytes([1; 32]),
            principal_owner_binding_digest: Hash::from_bytes([2; 32]),
            creator: OwnerIdV1::new("owner")?,
            parent_timeline_id: parent,
            child_timeline_id: child,
            room_revision_descriptor_hash: Hash::from_bytes([3; 32]),
            parent_logical_head: 0,
            parent_chain_head_hash: Hash::from_bytes([4; 32]),
            completed_fold_cursor: 0,
            post_fold_tick_boundary: 0,
            plugin_composition_hash: Hash::from_bytes([5; 32]),
            attribution_required: false,
            origin: ForkAttributionOriginV1::Local,
        })?)
    }

    fn fixture(name: &str) -> Fallible<(tempfile::TempDir, super::super::SqliteStore, ForkAdmissionRecordV1)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("child.sqlite3");
        let mut store = super::super::SqliteStore::open(path.to_str().ok_or("child fixture path")?)?;
        // The ordinary fixture Fork must satisfy its erasure prerequisite;
        // this test gate does not mint FCC or protected Replay authority.
        store.bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))?;
        let parent = store.create_timeline("parent")?;
        let child = store.fork(parent.id(), Seq::ZERO, name)?;
        // A native structural FAR/metadata fixture. It does not claim a host
        // admission session, FCC commitment or public protected-use authority.
        Ok((directory, store, admission(parent.id(), child.id())?))
    }

    fn raw_fixture() -> Fallible<(Connection, ForkAdmissionRecordV1)> {
        let conn = Connection::open_in_memory()?;
        // No affinity/constraints in this isolated raw owner fixture: fault
        // values must reach this read boundary, not be coerced or rejected.
        conn.execute_batch("CREATE TABLE timelines (id, name, parent_id, fork_seq)")?;
        let parent = TimelineId::from_ulid(ulid::Ulid::from_bytes([0xab; 16]));
        let child = TimelineId::from_ulid(ulid::Ulid::from_bytes([0xcd; 16]));
        let admission = admission(parent, child)?;
        conn.execute(
            "INSERT INTO timelines VALUES (?1, 'child', ?2, 0)",
            params![child.to_string(), parent.to_string()],
        )?;
        Ok((conn, admission))
    }

    fn expected_cost(admission: &ForkAdmissionRecordV1, name: Option<&str>, parent: Option<&str>) -> usize {
        // Independent logical String lengths, not a native length/debit helper
        // or an observed ledger: query key, two raw fields, comparison key.
        admission.input().child_timeline_id.to_string().len()
            + name.map_or(0, str::len)
            + parent.map_or(0, str::len)
            + admission.input().parent_timeline_id.to_string().len()
    }

    #[test]
    fn file_backed_child_metadata_charges_each_actual_string_and_both_rows() -> Fallible<()> {
        for name in ["", "child", "é\0é", &"é".repeat(128)] {
            let (_directory, store, admission) = fixture(name)?;
            let parent = admission.input().parent_timeline_id.to_string();
            let expected = expected_cost(&admission, Some(name), Some(&parent));
            for bytes in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = super::super::sqlite_fork_admission_child_name_with_context(
                    &store.conn, &admission, &mut NativeReadContextV1::protected(&mut budget),
                );
                if bytes == expected {
                    assert_eq!(result?, Some(name.to_owned()));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
            }
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, expected, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &store.conn, &admission, &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::CorruptAuthority)
            );
            assert_eq!(budget.remaining_native_bytes(), expected - 26);
            assert!(budget.check_time().is_err());
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &store.conn, &admission, &mut NativeReadContextV1::ordinary()
                )?,
                Some(name.to_owned())
            );
        }
        Ok(())
    }

    #[test]
    fn child_metadata_checks_the_original_epoch_around_raw_fields_and_comparison() -> Fallible<()> {
        let (_directory, store, admission) = fixture("é\0é")?;
        let parent = admission.input().parent_timeline_id.to_string();
        let expected = expected_cost(&admission, Some("é\0é"), Some(&parent));
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..256 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, expected, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = super::super::sqlite_fork_admission_child_name_with_context(
                    &store.conn, &admission, &mut NativeReadContextV1::protected(&mut budget),
                );
                match result {
                    Ok(name) => {
                        assert_eq!(name.as_deref(), Some("é\0é"));
                        completed = true;
                        break;
                    }
                    Err(error) => {
                        assert_eq!(error, Error::CorruptAuthority);
                        assert!(budget.check_time().is_err());
                    }
                }
            }
            assert!(completed, "every child metadata checkpoint was reached");
        }
        Ok(())
    }

    #[test]
    fn child_metadata_preserves_nullable_fields_cut_and_canonical_textual_lineage() -> Fallible<()> {
        let (conn, admission) = raw_fixture()?;
        let parent = admission.input().parent_timeline_id.to_string();
        let lowercase = parent.to_lowercase();
        assert_ne!(parent, lowercase);
        for (name, parent_value, fork_seq, expected) in [
            (Some("child"), Some(parent.as_str()), Some(0), Some("child")),
            (None, Some(parent.as_str()), Some(0), None),
            (Some("child"), None, Some(0), None),
            (Some("child"), Some(parent.as_str()), None, None),
            (Some("child"), Some(parent.as_str()), Some(-1), None),
            (Some("child"), Some(parent.as_str()), Some(1), None),
            (Some("child"), Some(lowercase.as_str()), Some(0), None),
            (Some("child"), Some("not-a-parent"), Some(0), None),
        ] {
            conn.execute(
                "UPDATE timelines SET name = ?1, parent_id = ?2, fork_seq = ?3",
                params![name, parent_value, fork_seq],
            )?;
            let bytes = expected_cost(&admission, name, parent_value);
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &conn, &admission, &mut NativeReadContextV1::protected(&mut budget)
                )?.as_deref(),
                expected
            );
            assert_eq!(budget.remaining_native_bytes(), 0);
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &conn, &admission, &mut NativeReadContextV1::ordinary()
                )?.as_deref(),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn impossible_child_column_types_fail_before_raw_getters() -> Fallible<()> {
        for (name, parent, fork_seq) in [
            (Value::Blob(vec![1]), Value::Null, Value::Integer(0)),
            (Value::Text("child".into()), Value::Blob(vec![1]), Value::Integer(0)),
            (Value::Text("child".into()), Value::Null, Value::Blob(vec![1])),
            (Value::Text("child".into()), Value::Null, Value::Real(0.0)),
            (Value::Text("child".into()), Value::Null, Value::Text("0".into())),
        ] {
            let (conn, admission) = raw_fixture()?;
            conn.execute(
                "UPDATE timelines SET name = ?1, parent_id = ?2, fork_seq = ?3",
                params![name, parent, fork_seq],
            )?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 512, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &conn, &admission, &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::StorageIndeterminate)
            );
            assert_eq!(budget.remaining_native_bytes(), 512 - 26);
            budget.charge_rows(1)?;
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &conn, &admission, &mut NativeReadContextV1::ordinary()
                ),
                Err(Error::StorageIndeterminate)
            );
        }
        Ok(())
    }

    #[test]
    fn child_metadata_absence_and_storage_utf8_errors_preserve_owner_contracts() -> Fallible<()> {
        for column in ["name", "parent_id"] {
            let (conn, admission) = raw_fixture()?;
            conn.execute_batch(&format!("UPDATE timelines SET {column} = CAST(X'FF' AS TEXT)"))?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 512, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &conn, &admission, &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::StorageIndeterminate)
            );
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(
                    &conn, &admission, &mut NativeReadContextV1::ordinary()
                ),
                Err(Error::StorageIndeterminate)
            );
        }
        let (conn, admission) = raw_fixture()?;
        conn.execute("DELETE FROM timelines", [])?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 26, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            super::super::sqlite_fork_admission_child_name_with_context(
                &conn, &admission, &mut NativeReadContextV1::protected(&mut budget)
            )?,
            None
        );
        assert_eq!(budget.remaining_native_bytes(), 0); // The real query key.
        budget.charge_rows(1)?; // No returned row was charged.
        let conn = Connection::open_in_memory()?;
        for protected in [false, true] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 26, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let mut context = if protected {
                NativeReadContextV1::protected(&mut budget)
            } else {
                NativeReadContextV1::ordinary()
            };
            assert_eq!(
                super::super::sqlite_fork_admission_child_name_with_context(&conn, &admission, &mut context),
                Err(Error::StorageIndeterminate)
            );
        }
        Ok(())
    }
}
