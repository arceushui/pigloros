//! Selected immutable FCC1/POB1 operation facts before raw materialization.

use pos_core::{ForkAdmissionErrorV1 as Error, Hash, TimelineId};
use rusqlite::{params, Connection};

use super::{sqlite_hash, ForkAdmissionOperationKindV1, ForkAdmissionOperationRowV1};
use crate::fork_replay::NativeReadContextV1;

type Result<T> = std::result::Result<T, Error>;

const OPERATION_PROBE_SQL: &str = "SELECT
    typeof(evidence_digest) = 'blob', length(evidence_digest),
    typeof(commitment) = 'blob', length(commitment),
    typeof(result_digest) = 'blob', length(result_digest),
    child_id IS NULL, typeof(child_id) = 'text', length(CAST(child_id AS BLOB))
    FROM fork_admission_operations WHERE kind = ?1 AND operation_id = ?2";
const OPERATION_FETCH_SQL: &str = "SELECT evidence_digest, commitment, result_digest, child_id
    FROM fork_admission_operations WHERE kind = ?1 AND operation_id = ?2";
const HASH_BYTES: u8 = 32;

/// Resolve only the immutable POB1 operation selected by its result digest.
/// The probe and raw row are separately charged on the held snapshot.
pub(super) fn principal_operation_id_with_context(
    conn: &Connection,
    result_digest: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Hash> {
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut probe = conn
        .prepare(
            "SELECT typeof(operation_id) = 'blob', length(operation_id)
        FROM fork_admission_operations WHERE kind = 1 AND result_digest = ?1",
        )
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = probe
        .query(params![result_digest.as_bytes().as_slice()])
        .map_err(|_| Error::StorageIndeterminate)?;
    context.row_available().map_err(|_| Error::CorruptAuthority)?;
    let row = rows
        .next()
        .map_err(|_| Error::StorageIndeterminate)?
        .ok_or(Error::CorruptAuthority)?;
    context.suffix_row().map_err(|_| Error::CorruptAuthority)?;
    if !row
        .get::<_, bool>(0)
        .map_err(|_| Error::StorageIndeterminate)?
    {
        return Err(Error::StorageIndeterminate);
    }
    if row
        .get::<_, i64>(1)
        .map_err(|_| Error::StorageIndeterminate)?
        != i64::from(HASH_BYTES)
    {
        return Err(Error::CorruptAuthority);
    }
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut fetch = conn
        .prepare(
            "SELECT operation_id FROM fork_admission_operations
        WHERE kind = 1 AND result_digest = ?1",
        )
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = fetch
        .query(params![result_digest.as_bytes().as_slice()])
        .map_err(|_| Error::StorageIndeterminate)?;
    context.row_available().map_err(|_| Error::CorruptAuthority)?;
    let row = rows
        .next()
        .map_err(|_| Error::StorageIndeterminate)?
        .ok_or(Error::CorruptAuthority)?;
    context.suffix_row().map_err(|_| Error::CorruptAuthority)?;
    context
        .bytes(usize::from(HASH_BYTES))
        .map_err(|_| Error::CorruptAuthority)?;
    let bytes = row
        .get::<_, Vec<u8>>(0)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let operation = sqlite_hash(bytes)?;
    context
        .check()
        .map(|()| operation)
        .map_err(|_| Error::CorruptAuthority)
}

struct OperationLengthsV1 {
    child: Option<usize>,
}

fn operation_lengths(
    conn: &Connection,
    kind: ForkAdmissionOperationKindV1,
    operation: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<OperationLengthsV1>> {
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut statement = conn
        .prepare(OPERATION_PROBE_SQL)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = statement
        .query(params![
            i64::from(kind.wire()),
            operation.as_bytes().as_slice()
        ])
        .map_err(|_| Error::StorageIndeterminate)?;
    context
        .row_available()
        .map_err(|_| Error::CorruptAuthority)?;
    let Some(row) = rows.next().map_err(|_| Error::StorageIndeterminate)? else {
        return context
            .check()
            .map(|()| None)
            .map_err(|_| Error::CorruptAuthority);
    };
    context.suffix_row().map_err(|_| Error::CorruptAuthority)?;
    // Preserve the ordinary getter's StorageIndeterminate classification for
    // wrong types, before validating native widths/ULID parse bounds.
    for column in [0, 2, 4] {
        if !row
            .get::<_, bool>(column)
            .map_err(|_| Error::StorageIndeterminate)?
        {
            return Err(Error::StorageIndeterminate);
        }
    }
    let null: bool = row.get(6).map_err(|_| Error::StorageIndeterminate)?;
    let text: bool = row.get(7).map_err(|_| Error::StorageIndeterminate)?;
    if !null && !text {
        return Err(Error::StorageIndeterminate);
    }
    let child = if null {
        None
    } else {
        let length = row
            .get::<_, i64>(8)
            .map_err(|_| Error::StorageIndeterminate)?;
        let length = usize::try_from(length).map_err(|_| Error::CorruptAuthority)?;
        if length != ulid::ULID_LEN {
            return Err(Error::CorruptAuthority);
        }
        Some(length)
    };
    for column in [1, 3, 5] {
        let length = row
            .get::<_, i64>(column)
            .map_err(|_| Error::StorageIndeterminate)?;
        if length != i64::from(HASH_BYTES) {
            return Err(Error::CorruptAuthority);
        }
    }
    context
        .check()
        .map(|()| Some(OperationLengthsV1 { child }))
        .map_err(|_| Error::CorruptAuthority)
}

pub(super) fn operation_with_context(
    conn: &Connection,
    kind: ForkAdmissionOperationKindV1,
    operation_id: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<ForkAdmissionOperationRowV1>> {
    let Some(lengths) = operation_lengths(conn, kind, operation_id, context)? else {
        return Ok(None);
    };
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut statement = conn
        .prepare(OPERATION_FETCH_SQL)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = statement
        .query(params![
            i64::from(kind.wire()),
            operation_id.as_bytes().as_slice()
        ])
        .map_err(|_| Error::StorageIndeterminate)?;
    context
        .row_available()
        .map_err(|_| Error::CorruptAuthority)?;
    let row = rows
        .next()
        .map_err(|_| Error::StorageIndeterminate)?
        .ok_or(Error::CorruptAuthority)?;
    context.suffix_row().map_err(|_| Error::CorruptAuthority)?;
    context
        .bytes(usize::from(HASH_BYTES))
        .map_err(|_| Error::CorruptAuthority)?;
    let evidence_digest = row
        .get::<_, Vec<u8>>(0)
        .map_err(|_| Error::StorageIndeterminate)?;
    context
        .bytes(usize::from(HASH_BYTES))
        .map_err(|_| Error::CorruptAuthority)?;
    let commitment = row
        .get::<_, Vec<u8>>(1)
        .map_err(|_| Error::StorageIndeterminate)?;
    context
        .bytes(usize::from(HASH_BYTES))
        .map_err(|_| Error::CorruptAuthority)?;
    let result_digest = row
        .get::<_, Vec<u8>>(2)
        .map_err(|_| Error::StorageIndeterminate)?;
    if let Some(length) = lengths.child {
        context.bytes(length).map_err(|_| Error::CorruptAuthority)?;
    }
    let child = row
        .get::<_, Option<String>>(3)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let child_id = child
        .map(|id| {
            id.parse::<ulid::Ulid>()
                .map(TimelineId::from_ulid)
                .map_err(|_| Error::CorruptAuthority)
        })
        .transpose()?;
    let result = ForkAdmissionOperationRowV1 {
        kind,
        operation_id,
        child_id,
        evidence_digest: sqlite_hash(evidence_digest)?,
        commitment: sqlite_hash(commitment)?,
        result_digest: sqlite_hash(result_digest)?,
    };
    context
        .check()
        .map(|()| Some(result))
        .map_err(|_| Error::CorruptAuthority)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use std::time::Duration;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn fixture(
        kind: ForkAdmissionOperationKindV1,
    ) -> Fallible<(super::super::SqliteStore, ForkAdmissionOperationRowV1)> {
        let store = super::super::SqliteStore::open(":memory:")?;
        let row = ForkAdmissionOperationRowV1 {
            kind,
            operation_id: Hash::from_bytes([1; 32]),
            evidence_digest: Hash::from_bytes([2; 32]),
            commitment: Hash::from_bytes([3; 32]),
            result_digest: Hash::from_bytes([4; 32]),
            child_id: matches!(kind, ForkAdmissionOperationKindV1::Fork)
                .then_some(TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16]))),
        };
        // These typed operation facts exercise only the selected row reader;
        // they make no claim that FCC1/POB1 recovery or authority is admitted.
        super::super::sqlite_insert_fork_admission_operation(&store.conn, &row)?;
        Ok((store, row))
    }

    fn expected_bytes(row: &ForkAdmissionOperationRowV1) -> usize {
        // Three actual hash Vecs plus the optional ULID UTF-8 String.
        32 * 3 + row.child_id.map_or(0, |child| child.to_string().len())
    }

    #[test]
    fn operation_facts_charge_exact_hash_vectors_optional_child_and_rows() -> Fallible<()> {
        for kind in [
            ForkAdmissionOperationKindV1::Fork,
            ForkAdmissionOperationKindV1::PrincipalOwner,
        ] {
            let (store, row) = fixture(kind)?;
            let bytes = expected_bytes(&row);
            assert_eq!(
                operation_with_context(
                    &store.conn,
                    kind,
                    row.operation_id,
                    &mut NativeReadContextV1::ordinary()
                )?,
                Some(row.clone())
            );
            for limit in 1..=bytes {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = operation_with_context(
                    &store.conn,
                    kind,
                    row.operation_id,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if limit == bytes {
                    assert_eq!(result?, Some(row.clone()));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
            }
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                operation_with_context(
                    &store.conn,
                    kind,
                    row.operation_id,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::CorruptAuthority)
            );
            assert_eq!(budget.remaining_native_bytes(), bytes);
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    #[test]
    fn operation_original_epoch_expiry_and_regression_latch_at_every_checkpoint() -> Fallible<()> {
        for kind in [
            ForkAdmissionOperationKindV1::Fork,
            ForkAdmissionOperationKindV1::PrincipalOwner,
        ] {
            let (store, row) = fixture(kind)?;
            let bytes = expected_bytes(&row);
            for final_offset in [Duration::ZERO, Duration::from_secs(2)] {
                let mut completed = false;
                for marks in 2..128 {
                    let mut clock = ScriptedGuardMonotonicSourceV1::new(
                        std::iter::repeat_n(Duration::from_millis(1), marks).chain([final_offset]),
                    );
                    let start = clock.mark();
                    let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
                    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                    let result = operation_with_context(
                        &store.conn,
                        kind,
                        row.operation_id,
                        &mut NativeReadContextV1::protected(&mut budget),
                    );
                    if let Ok(value) = result {
                        assert_eq!(value, Some(row.clone()));
                        assert_eq!(budget.remaining_native_bytes(), 0);
                        completed = true;
                        break;
                    }
                    assert!(budget.check_time().is_err());
                }
                assert!(
                    completed,
                    "all operation expiry/regression checkpoints tested"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn absent_operation_has_no_row_or_raw_materialization() -> Fallible<()> {
        let store = super::super::SqliteStore::open(":memory:")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 128, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            operation_with_context(
                &store.conn,
                ForkAdmissionOperationKindV1::Fork,
                Hash::from_bytes([1; 32]),
                &mut NativeReadContextV1::protected(&mut budget)
            )?,
            None
        );
        assert_eq!(budget.remaining_native_bytes(), 128);
        budget.charge_rows(1)?;
        Ok(())
    }

    #[test]
    fn impossible_operation_types_and_widths_preserve_errors_before_raw_fetch() -> Fallible<()> {
        use rusqlite::types::Value;
        for column in [0, 1, 2, 3] {
            let cases = if column == 3 {
                vec![
                    (Value::Blob(vec![1; 26]), Error::StorageIndeterminate),
                    (Value::Text("x".repeat(27)), Error::CorruptAuthority),
                ]
            } else {
                vec![
                    (Value::Text("x".repeat(32)), Error::StorageIndeterminate),
                    (Value::Blob(vec![1; 31]), Error::CorruptAuthority),
                    (Value::Blob(vec![1; 33]), Error::CorruptAuthority),
                ]
            };
            for (value, expected) in cases {
                // This narrow owner fixture omits CHECK constraints solely to
                // inject impossible persisted types/widths, not valid authority.
                let conn = Connection::open_in_memory()?;
                conn.execute_batch(
                    "CREATE TABLE fork_admission_operations (
                    kind INTEGER, operation_id BLOB, evidence_digest BLOB,
                    commitment BLOB, result_digest BLOB, child_id TEXT)",
                )?;
                let mut fields = [
                    Value::Blob(vec![2; 32]),
                    Value::Blob(vec![3; 32]),
                    Value::Blob(vec![4; 32]),
                    Value::Text(TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])).to_string()),
                ];
                fields[column] = value;
                let operation = Hash::from_bytes([1; 32]);
                conn.execute(
                    "INSERT INTO fork_admission_operations VALUES (2, ?1, ?2, ?3, ?4, ?5)",
                    params![
                        operation.as_bytes().as_slice(),
                        fields[0],
                        fields[1],
                        fields[2],
                        fields[3]
                    ],
                )?;
                for protected in [false, true] {
                    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                    let start = clock.mark();
                    let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 128, 1_000_000)?;
                    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                    let mut context = if protected {
                        NativeReadContextV1::protected(&mut budget)
                    } else {
                        NativeReadContextV1::ordinary()
                    };
                    assert_eq!(
                        operation_with_context(
                            &conn,
                            ForkAdmissionOperationKindV1::Fork,
                            operation,
                            &mut context
                        ),
                        Err(expected)
                    );
                    assert_eq!(budget.remaining_native_bytes(), 128);
                    assert!(budget.check_time().is_ok());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn principal_result_key_lookup_charges_actual_fixed_digest_and_probe_fetch_rows(
    ) -> Fallible<()> {
        let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
        for bytes in 1..=32 {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = principal_operation_id_with_context(
                &store.conn,
                row.result_digest,
                &mut NativeReadContextV1::protected(&mut budget),
            );
            if bytes == 32 {
                assert_eq!(result?, row.operation_id);
                assert_eq!(budget.remaining_native_bytes(), 0);
            } else {
                assert_eq!(result, Err(Error::CorruptAuthority));
                assert!(budget.check_time().is_err());
            }
        }
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 32, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            principal_operation_id_with_context(
                &store.conn,
                row.result_digest,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(Error::CorruptAuthority)
        );
        assert!(budget.check_time().is_err());
        Ok(())
    }

    #[test]
    fn principal_result_key_lookup_rejects_impossible_type_width_and_absence() -> Fallible<()> {
        use rusqlite::types::Value;
        for (value, expected) in [
            (Value::Text("x".repeat(32)), Error::StorageIndeterminate),
            (Value::Blob(vec![1; 31]), Error::CorruptAuthority),
            (Value::Blob(vec![1; 33]), Error::CorruptAuthority),
        ] {
            let conn = Connection::open_in_memory()?;
            // Narrow impossible-state fixture, not an admitted operation.
            conn.execute_batch(
                "CREATE TABLE fork_admission_operations
                (kind INTEGER, operation_id BLOB, result_digest BLOB)",
            )?;
            let result = Hash::from_bytes([4; 32]);
            assert_eq!(
                conn.execute(
                    "INSERT INTO fork_admission_operations VALUES (1, ?1, ?2)",
                    params![value, result.as_bytes().as_slice()]
                )?,
                1
            );
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 32, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                principal_operation_id_with_context(
                    &conn,
                    result,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(expected)
            );
            assert_eq!(budget.remaining_native_bytes(), 32);
            assert!(budget.check_time().is_ok());
            conn.execute("DELETE FROM fork_admission_operations", [])?;
            assert_eq!(
                principal_operation_id_with_context(
                    &conn,
                    result,
                    &mut NativeReadContextV1::ordinary()
                ),
                Err(Error::CorruptAuthority)
            );
        }
        let conn = Connection::open_in_memory()?;
        assert_eq!(
            principal_operation_id_with_context(
                &conn,
                Hash::from_bytes([4; 32]),
                &mut NativeReadContextV1::ordinary()
            ),
            Err(Error::StorageIndeterminate)
        );
        Ok(())
    }

    #[test]
    fn principal_result_key_lookup_checks_every_original_epoch_boundary() -> Fallible<()> {
        let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..160 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 32, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = principal_operation_id_with_context(
                    &store.conn,
                    row.result_digest,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(operation_id) = result {
                    assert_eq!(operation_id, row.operation_id);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "all key lookup expiry/regression boundaries tested"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_bounded_child_is_parsed_only_after_its_actual_string_gate() -> Fallible<()> {
        let (store, row) = fixture(ForkAdmissionOperationKindV1::Fork)?;
        // The pinned ULID parser accepts lowercase alphabet characters;
        // use a character outside that alphabet without changing its policy.
        store.conn.execute(
            "UPDATE fork_admission_operations SET child_id = ?1",
            ["!".repeat(26)],
        )?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 122, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            operation_with_context(
                &store.conn,
                row.kind,
                row.operation_id,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(Error::CorruptAuthority)
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        assert!(budget.check_time().is_ok());
        Ok(())
    }
}
