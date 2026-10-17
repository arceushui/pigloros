//! Selected immutable FCC1/POB1 operation facts before raw materialization.

use pos_core::{ForkAdmissionErrorV1 as Error, Hash, TimelineId};
use rusqlite::{params, Connection, Params, Row};

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
const PRINCIPAL_PROBE_SQL: &str = "SELECT typeof(operation_id) = 'blob', length(operation_id)
        FROM fork_admission_operations WHERE kind = 1 AND result_digest = ?1";
const HASH_BYTES: u8 = 32;

/// Keep the selected statement and cursor alive throughout `read`, including
/// a nested raw fetch. Only actual rows are charged; the caller retains its
/// required/optional absence policy and all field-specific materialization.
fn with_selected_row<'budget, 'clock, T>(
    conn: &Connection,
    sql: &str,
    parameters: impl Params,
    context: &mut NativeReadContextV1<'budget, 'clock>,
    read: impl FnOnce(Option<&Row<'_>>, &mut NativeReadContextV1<'budget, 'clock>) -> Result<T>,
) -> Result<T> {
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut statement = conn.prepare(sql).map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = statement
        .query(parameters)
        .map_err(|_| Error::StorageIndeterminate)?;
    context
        .row_available()
        .map_err(|_| Error::CorruptAuthority)?;
    let row = rows.next().map_err(|_| Error::StorageIndeterminate)?;
    if row.is_some() {
        context.suffix_row().map_err(|_| Error::CorruptAuthority)?;
    }
    read(row, context)
}

/// Resolve only the immutable POB1 operation selected by its result digest.
/// The probe and raw row are separately charged on the held snapshot.
pub(super) fn principal_operation_id_with_context(
    conn: &Connection,
    result_digest: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Hash> {
    with_selected_row(
        conn,
        PRINCIPAL_PROBE_SQL,
        params![result_digest.as_bytes().as_slice()],
        context,
        |row, context| {
            let row = row.ok_or(Error::CorruptAuthority)?;
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
            with_selected_row(
                conn,
                "SELECT operation_id FROM fork_admission_operations
        WHERE kind = 1 AND result_digest = ?1",
                params![result_digest.as_bytes().as_slice()],
                context,
                principal_operation_fields,
            )
        },
    )
}

fn principal_operation_fields(
    row: Option<&Row<'_>>,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Hash> {
    let row = row.ok_or(Error::CorruptAuthority)?;
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

impl OperationLengthsV1 {
    fn read(
        row: Option<&Row<'_>>,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Result<Option<Self>> {
        let Some(row) = row else {
            return context
                .check()
                .map(|()| None)
                .map_err(|_| Error::CorruptAuthority);
        };
        // Preserve the ordinary getter's StorageIndeterminate classification
        // for wrong types, before native widths/ULID parse bounds.
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
            if usize::try_from(length).ok() != Some(ulid::ULID_LEN) {
                return Err(Error::CorruptAuthority);
            }
            Some(ulid::ULID_LEN)
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
            .map(|()| Some(Self { child }))
            .map_err(|_| Error::CorruptAuthority)
    }
}

fn operation_lengths(
    conn: &Connection,
    kind: ForkAdmissionOperationKindV1,
    operation: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<OperationLengthsV1>> {
    with_selected_row(
        conn,
        OPERATION_PROBE_SQL,
        params![i64::from(kind.wire()), operation.as_bytes().as_slice()],
        context,
        OperationLengthsV1::read,
    )
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
    with_selected_row(
        conn,
        OPERATION_FETCH_SQL,
        params![i64::from(kind.wire()), operation_id.as_bytes().as_slice()],
        context,
        |row, context| {
            let row = row.ok_or(Error::CorruptAuthority)?;
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
        },
    )
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
    fn native_principal_decoder_rejects_a_width_mismatch_without_refunding_work() -> Fallible<()> {
        let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(8, 1, 3, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        // The production probe promises 32 bytes. This actual 31-byte SQL
        // value tests the independent raw decoder defense against a bad shape.
        assert_eq!(
            with_selected_row(
                &store.conn,
                "SELECT zeroblob(31)",
                [],
                &mut NativeReadContextV1::protected(&mut budget),
                principal_operation_fields,
            ),
            Err(Error::CorruptAuthority)
        );
        assert_eq!(budget.remaining_native_bytes(), 32);
        budget.check_time()?;
        assert_eq!(
            principal_operation_id_with_context(
                &store.conn,
                row.result_digest,
                &mut NativeReadContextV1::protected(&mut budget),
            )?,
            row.operation_id
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        budget.check_time()?;
        assert!(budget.charge_rows(1).is_err());
        assert!(budget.check_time().is_err());
        Ok(())
    }

    #[test]
    fn native_operation_probe_decoder_rejects_a_nonboolean_null_marker() -> Fallible<()> {
        let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(8, 1, 3, 96, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        // IS NULL is always boolean in production SQL. The real text value
        // here tests the native probe decoder's independent type contract.
        let failed = with_selected_row(
            &store.conn,
            "SELECT 1,32,1,32,1,32,'not a boolean',0,NULL",
            [],
            &mut NativeReadContextV1::protected(&mut budget),
            OperationLengthsV1::read,
        )
        .map(|lengths| lengths.map(|lengths| lengths.child));
        assert_eq!(failed, Err(Error::StorageIndeterminate));
        assert_eq!(budget.remaining_native_bytes(), 96);
        budget.check_time()?;
        assert_eq!(
            operation_with_context(
                &store.conn,
                row.kind,
                row.operation_id,
                &mut NativeReadContextV1::protected(&mut budget),
            )?,
            Some(row)
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        budget.check_time()?;
        assert!(budget.charge_rows(1).is_err());
        assert!(budget.check_time().is_err());
        Ok(())
    }

    #[derive(Default)]
    struct InterStatementWrite {
        selects: usize,
        outcome: Option<rusqlite::Result<usize>>,
    }

    fn write_before_second_select(
        reader: &Connection,
        writer: Connection,
        sql: &'static str,
    ) -> rusqlite::Result<std::sync::Arc<std::sync::Mutex<InterStatementWrite>>> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::{Arc, Mutex};

        let observation = Arc::new(Mutex::new(InterStatementWrite::default()));
        let callback_observation = Arc::clone(&observation);
        reader.authorizer(Some(move |context: AuthContext<'_>| {
            if context.action == AuthAction::Select {
                let Ok(mut observation) = callback_observation.lock() else {
                    return Authorization::Deny;
                };
                observation.selects += 1;
                if observation.selects == 2 {
                    // The first statement has produced the size/type probe;
                    // the second is the raw fetch. Commit through a different
                    // native connection, not a fabricated Row/getter result.
                    observation.outcome = Some(writer.execute(sql, []));
                }
            }
            Authorization::Allow
        }))?;
        Ok(observation)
    }

    #[test]
    fn inter_statement_writes_refuse_ordinary_reads_but_do_not_change_a_held_snapshot(
    ) -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        let (_, row) = fixture(ForkAdmissionOperationKindV1::Fork)?;
        for (sql, expected) in [
            ("DELETE FROM fork_admission_operations", Error::CorruptAuthority),
            ("UPDATE fork_admission_operations SET evidence_digest = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'", Error::StorageIndeterminate),
            ("UPDATE fork_admission_operations SET commitment = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'", Error::StorageIndeterminate),
            ("UPDATE fork_admission_operations SET result_digest = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'", Error::StorageIndeterminate),
            ("UPDATE fork_admission_operations SET child_id = zeroblob(26)", Error::StorageIndeterminate),
            ("UPDATE fork_admission_operations SET evidence_digest = zeroblob(31)", Error::CorruptAuthority),
            ("UPDATE fork_admission_operations SET commitment = zeroblob(31)", Error::CorruptAuthority),
            ("UPDATE fork_admission_operations SET result_digest = zeroblob(31)", Error::CorruptAuthority),
        ] {
            for held_snapshot in [false, true] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("operation.sqlite");
                let store = super::super::SqliteStore::open(
                    path.to_str().ok_or("non-UTF-8 test path")?,
                )?;
                super::super::sqlite_insert_fork_admission_operation(&store.conn, &row)?;
                let writer = Connection::open(&path)?;
                writer.busy_timeout(Duration::ZERO)?;
                // Deliberate persisted-corruption injection for width cases.
                // This does not classify the altered facts as valid authority.
                writer.execute_batch("PRAGMA ignore_check_constraints=ON")?;
                if held_snapshot {
                    store.conn.execute_batch("BEGIN DEFERRED")?;
                }
                let observation = write_before_second_select(&store.conn, writer, sql)?;
                let result = operation_with_context(
                    &store.conn,
                    row.kind,
                    row.operation_id,
                    &mut NativeReadContextV1::ordinary(),
                );
                store.conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                let mut observation = observation.lock().map_err(|_| "observer poisoned")?;
                assert_eq!(observation.selects, 2);
                assert_eq!(observation.outcome.take().ok_or("writer was not scheduled")??, 1);
                drop(observation);
                if held_snapshot {
                    assert_eq!(result?, Some(row.clone()));
                    store.conn.execute_batch("ROLLBACK")?;
                } else {
                    assert_eq!(result, Err(expected));
                }
                // A new native read sees the committed change after rollback,
                // proving the successful control was snapshot isolation, not
                // a writer that failed or a mutation that had no effect.
                let changed = operation_with_context(
                    &store.conn,
                    row.kind,
                    row.operation_id,
                    &mut NativeReadContextV1::ordinary(),
                );
                if sql.starts_with("DELETE") {
                    assert_eq!(changed?, None);
                } else {
                    assert_eq!(changed, Err(expected));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn principal_probe_keeps_its_snapshot_until_the_raw_fetch_finishes() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        let (_, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
        for (sql, expected) in [
            ("DELETE FROM fork_admission_operations", Error::CorruptAuthority),
            ("UPDATE fork_admission_operations SET operation_id = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'", Error::StorageIndeterminate),
            ("UPDATE fork_admission_operations SET operation_id = zeroblob(31)", Error::CorruptAuthority),
        ] {
            for held_snapshot in [false, true] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("principal-operation.sqlite");
                let store = super::super::SqliteStore::open(
                    path.to_str().ok_or("non-UTF-8 test path")?,
                )?;
                super::super::sqlite_insert_fork_admission_operation(&store.conn, &row)?;
                assert_eq!(
                    principal_operation_id_with_context(
                        &store.conn,
                        row.result_digest,
                        &mut NativeReadContextV1::ordinary(),
                    )?,
                    row.operation_id,
                );
                let writer = Connection::open(&path)?;
                writer.busy_timeout(Duration::ZERO)?;
                // Only the short-hash case needs persisted-corruption injection.
                // None of these altered facts is admitted principal authority.
                writer.execute_batch("PRAGMA ignore_check_constraints=ON")?;
                if held_snapshot {
                    store.conn.execute_batch("BEGIN DEFERRED")?;
                }
                let observation = write_before_second_select(&store.conn, writer, sql)?;
                let result = principal_operation_id_with_context(
                    &store.conn,
                    row.result_digest,
                    &mut NativeReadContextV1::ordinary(),
                );
                store.conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                let mut observation = observation.lock().map_err(|_| "observer poisoned")?;
                assert_eq!(observation.selects, 2);
                assert_eq!(observation.outcome.take().ok_or("writer was not scheduled")??, 1);
                drop(observation);
                // The nested raw fetch runs before the probe cursor drops.
                // That live cursor preserves even the implicit read snapshot;
                // an explicit BEGIN is not required for this native owner.
                assert_eq!(result?, row.operation_id);
                if held_snapshot {
                    store.conn.execute_batch("ROLLBACK")?;
                }
                // Re-select by the unchanged result digest. A fresh snapshot
                // must observe the committed deletion or invalid operation ID.
                assert_eq!(
                    principal_operation_id_with_context(
                        &store.conn,
                        row.result_digest,
                        &mut NativeReadContextV1::ordinary(),
                    ),
                    Err(expected),
                );
                assert!(store.conn.is_autocommit());
            }
        }
        Ok(())
    }

    #[derive(Default)]
    struct PrincipalReadAuthorization {
        selects: usize,
        reads: Vec<(usize, String, bool)>,
    }

    fn ignore_principal_raw_column(
        conn: &Connection,
        column: &'static str,
    ) -> rusqlite::Result<std::sync::Arc<std::sync::Mutex<PrincipalReadAuthorization>>> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::{Arc, Mutex};

        let observed = Arc::new(Mutex::new(PrincipalReadAuthorization::default()));
        let callback_observed = Arc::clone(&observed);
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            let Ok(mut observed) = callback_observed.lock() else {
                return Authorization::Deny;
            };
            if context.action == AuthAction::Select {
                observed.selects += 1;
            }
            if let AuthAction::Read {
                table_name: "fork_admission_operations",
                column_name,
            } = context.action
            {
                let select = observed.selects;
                let ignored = select == 2 && column_name == column;
                observed
                    .reads
                    .push((select, column_name.to_owned(), ignored));
                if ignored {
                    return Authorization::Ignore;
                }
            }
            Authorization::Allow
        }))?;
        Ok(observed)
    }

    #[test]
    fn principal_raw_column_refusal_preserves_native_errors_and_exact_debits() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        // Backend-private driver faults, not a production authorization mode:
        // SQLITE_READ + IGNORE substitutes NULL at prepare time. The actual
        // probe, raw query, schema and cursor lifetime remain unchanged.
        for (column, expected, failed_rows, failed_bytes) in [
            ("operation_id", Error::StorageIndeterminate, 2, 32),
            ("result_digest", Error::CorruptAuthority, 1, 0),
        ] {
            for held_snapshot in [false, true] {
                let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(
                    1,
                    1,
                    failed_rows + 2,
                    failed_bytes + 32,
                    1_000_000,
                )?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                if held_snapshot {
                    store.conn.execute_batch("BEGIN DEFERRED")?;
                }
                let observed = ignore_principal_raw_column(&store.conn, column)?;
                let failed = principal_operation_id_with_context(
                    &store.conn,
                    row.result_digest,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                // Remove the native policy before propagating results or
                // asserting; the healthy control uses the unchanged query.
                store
                    .conn
                    .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                let observed = observed
                    .lock()
                    .map_err(|_| "authorizer observer poisoned")?;
                assert_eq!(observed.selects, 2);
                let reads: Vec<_> = observed
                    .reads
                    .iter()
                    .map(|(select, name, ignored)| (*select, name.as_str(), *ignored))
                    .collect();
                assert_eq!(
                    reads,
                    [
                        (1, "operation_id", false),
                        (1, "operation_id", false),
                        (1, "kind", false),
                        (1, "result_digest", false),
                        (2, "operation_id", column == "operation_id"),
                        (2, "kind", false),
                        (2, "result_digest", column == "result_digest"),
                    ],
                );
                drop(observed);
                assert_eq!(failed, Err(expected));
                assert_eq!(budget.remaining_native_bytes(), 32);
                budget.check_time()?;
                assert_eq!(
                    principal_operation_id_with_context(
                        &store.conn,
                        row.result_digest,
                        &mut NativeReadContextV1::protected(&mut budget),
                    )?,
                    row.operation_id,
                );
                assert_eq!(budget.remaining_native_bytes(), 0);
                budget.check_time()?;
                assert!(budget.charge_rows(1).is_err());
                assert!(budget.check_time().is_err());
                if held_snapshot {
                    store.conn.execute_batch("ROLLBACK")?;
                }
                assert!(store.conn.is_autocommit());
            }
        }
        Ok(())
    }

    #[derive(Default)]
    struct ProbeFunctionAuthorization {
        selects: usize,
        functions: Vec<(String, bool)>,
    }

    fn ignore_probe_function(
        conn: &Connection,
        ignored_index: usize,
    ) -> rusqlite::Result<std::sync::Arc<std::sync::Mutex<ProbeFunctionAuthorization>>> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::{Arc, Mutex};

        let observed = Arc::new(Mutex::new(ProbeFunctionAuthorization::default()));
        let callback_observed = Arc::clone(&observed);
        conn.authorizer(Some(move |request: AuthContext<'_>| {
            let Ok(mut observed) = callback_observed.lock() else {
                return Authorization::Deny;
            };
            if request.action == AuthAction::Select {
                observed.selects += 1;
            }
            if let AuthAction::Function { function_name } = request.action {
                let ignored = observed.functions.len() == ignored_index;
                observed.functions.push((function_name.to_owned(), ignored));
                if ignored {
                    return Authorization::Ignore;
                }
            }
            Authorization::Allow
        }))?;
        Ok(observed)
    }

    #[test]
    fn native_principal_function_refusals_preserve_probe_accounting() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        // Native SQLITE_FUNCTION + IGNORE replaces the selected expression
        // with NULL. No builtin, production query, schema or getter is replaced.
        for (label, ignored_index) in [("operation_type", 0), ("operation_length", 1)] {
            for held_snapshot in [false, true] {
                let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                // One failed probe followed by the unchanged two-row/32-byte read.
                let limits = ForkReplayReadLimitsV1::new(1, 1, 3, 32, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                if held_snapshot {
                    store.conn.execute_batch("BEGIN DEFERRED")?;
                }
                let observed = ignore_probe_function(&store.conn, ignored_index)?;
                let failed = principal_operation_id_with_context(
                    &store.conn,
                    row.result_digest,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                store
                    .conn
                    .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                let observed = observed.lock().map_err(|_| "function observer poisoned")?;
                assert_eq!(observed.selects, 1, "{label}");
                let actual: Vec<_> = observed
                    .functions
                    .iter()
                    .map(|(name, ignored)| (name.as_str(), *ignored))
                    .collect();
                let expected: Vec<_> = ["typeof", "length"]
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| (name, index == ignored_index))
                    .collect();
                assert_eq!(actual, expected, "{label}");
                drop(observed);
                assert_eq!(failed, Err(Error::StorageIndeterminate), "{label}");
                assert_eq!(budget.remaining_native_bytes(), 32, "{label}");
                budget.check_time()?;
                assert_eq!(
                    principal_operation_id_with_context(
                        &store.conn,
                        row.result_digest,
                        &mut NativeReadContextV1::protected(&mut budget),
                    )?,
                    row.operation_id,
                    "{label}"
                );
                assert_eq!(budget.remaining_native_bytes(), 0, "{label}");
                budget.check_time()?;
                assert!(budget.charge_rows(1).is_err(), "{label}");
                assert!(budget.check_time().is_err(), "{label}");
                if held_snapshot {
                    store.conn.execute_batch("ROLLBACK")?;
                }
                assert!(store.conn.is_autocommit(), "{label}");
            }
        }
        Ok(())
    }

    #[test]
    fn native_operation_function_refusals_preserve_probe_accounting() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        // One representative per distinct getter: the three hash columns
        // share their type/length loops; the non-null child has separate getters.
        for (label, ignored_index) in [
            ("evidence_type", 0),
            ("evidence_length", 1),
            ("child_type", 6),
            ("child_length", 7),
        ] {
            for held_snapshot in [false, true] {
                let (store, row) = fixture(ForkAdmissionOperationKindV1::Fork)?;
                let bytes = expected_bytes(&row);
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 3, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                if held_snapshot {
                    store.conn.execute_batch("BEGIN DEFERRED")?;
                }
                let observed = ignore_probe_function(&store.conn, ignored_index)?;
                let failed = operation_with_context(
                    &store.conn,
                    row.kind,
                    row.operation_id,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                store
                    .conn
                    .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                let observed = observed.lock().map_err(|_| "function observer poisoned")?;
                assert_eq!(observed.selects, 1, "{label}");
                let actual: Vec<_> = observed
                    .functions
                    .iter()
                    .map(|(name, ignored)| (name.as_str(), *ignored))
                    .collect();
                let expected: Vec<_> = [
                    "typeof", "length", "typeof", "length", "typeof", "length", "typeof", "length",
                ]
                .into_iter()
                .enumerate()
                .map(|(index, name)| (name, index == ignored_index))
                .collect();
                assert_eq!(actual, expected, "{label}");
                drop(observed);
                assert_eq!(failed, Err(Error::StorageIndeterminate), "{label}");
                assert_eq!(budget.remaining_native_bytes(), bytes, "{label}");
                budget.check_time()?;
                assert_eq!(
                    operation_with_context(
                        &store.conn,
                        row.kind,
                        row.operation_id,
                        &mut NativeReadContextV1::protected(&mut budget),
                    )?,
                    Some(row),
                    "{label}"
                );
                assert_eq!(budget.remaining_native_bytes(), 0, "{label}");
                budget.check_time()?;
                assert!(budget.charge_rows(1).is_err(), "{label}");
                assert!(budget.check_time().is_err(), "{label}");
                if held_snapshot {
                    store.conn.execute_batch("ROLLBACK")?;
                }
                assert!(store.conn.is_autocommit(), "{label}");
            }
        }
        Ok(())
    }

    fn operation_root(conn: &Connection) -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT rootpage FROM sqlite_schema
             WHERE type = 'table' AND name = 'fork_admission_operations'",
            [],
            |row| row.get(0),
        )
    }

    fn replace_operation_root(conn: &Connection, root: i64) -> rusqlite::Result<usize> {
        conn.execute_batch("PRAGMA writable_schema=ON")?;
        let changed = conn.execute(
            "UPDATE sqlite_schema SET rootpage = ?1
             WHERE type = 'table' AND name = 'fork_admission_operations'",
            [root],
        );
        // Reset disables writable_schema and reloads the native schema cache,
        // including when the preceding catalog update reported an error.
        let reset = conn.execute_batch("PRAGMA writable_schema=RESET");
        changed.and_then(|count| reset.map(|()| count))
    }

    #[test]
    fn corrupt_operation_btree_fails_at_step_without_spending_the_read_budget() -> Fallible<()> {
        use rusqlite::{params_from_iter, types::Value, ErrorCode};

        for principal_lookup in [false, true] {
            let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
            let table_root = operation_root(&store.conn)?;
            let index_root: i64 = store.conn.query_row(
                "SELECT rootpage FROM sqlite_schema WHERE type = 'index'
                 AND tbl_name = 'fork_admission_operations' AND rootpage > 0
                 ORDER BY name LIMIT 1",
                [],
                |row| row.get(0),
            )?;
            assert!(table_root > 0 && index_root > 0);
            assert_ne!(table_root, index_root);
            let (sql, parameters, bytes) = if principal_lookup {
                (
                    PRINCIPAL_PROBE_SQL,
                    vec![Value::Blob(row.result_digest.as_bytes().to_vec())],
                    32,
                )
            } else {
                (
                    OPERATION_PROBE_SQL,
                    vec![
                        Value::Integer(i64::from(row.kind.wire())),
                        Value::Blob(row.operation_id.as_bytes().to_vec()),
                    ],
                    expected_bytes(&row),
                )
            };
            // Preserve each native phase as a separate Result: an earlier
            // prepare/bind refusal cannot masquerade as the required step error.
            let probe = || {
                store.conn.prepare(sql).map(|mut statement| {
                    statement
                        .query(params_from_iter(parameters.iter()))
                        .map(|mut rows| rows.next().map(|row| row.is_some()))
                })
            };
            assert!(probe()???);
            let read = |context: &mut NativeReadContextV1<'_, '_>| {
                if principal_lookup {
                    principal_operation_id_with_context(&store.conn, row.result_digest, context)
                        .map(|actual| actual == row.operation_id)
                } else {
                    operation_with_context(&store.conn, row.kind, row.operation_id, context)
                        .map(|actual| actual.as_ref() == Some(&row))
                }
            };
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            // Genuine native catalog corruption, not admitted authority or a
            // fake query return: a rowid table points at its index's B-tree.
            let changed = replace_operation_root(&store.conn, index_root)?;
            let corrupt_root = operation_root(&store.conn);
            let failed_probe = probe();
            let failed_read = read(&mut NativeReadContextV1::protected(&mut budget));
            let remaining = budget.remaining_native_bytes();
            let healthy_clock = budget.check_time();
            // All statements/cursors are gone. Restore before assertions or
            // propagating captured errors; this database is test-owned memory.
            let restored = replace_operation_root(&store.conn, table_root)?;
            assert_eq!((changed, restored), (1, 1));
            assert_eq!(corrupt_root?, index_root);
            assert_eq!(operation_root(&store.conn)?, table_root);
            assert_eq!(
                failed_probe??
                    .err()
                    .and_then(|error| error.sqlite_error_code()),
                Some(ErrorCode::DatabaseCorrupt)
            );
            assert_eq!(failed_read, Err(Error::StorageIndeterminate));
            assert_eq!(remaining, bytes);
            healthy_clock?;
            assert!(probe()???);
            // Both actual rows and every byte are still available on the same
            // ledger. The restored read must consume exactly those two rows.
            assert!(read(&mut NativeReadContextV1::protected(&mut budget))?);
            assert_eq!(budget.remaining_native_bytes(), 0);
            budget.check_time()?;
            assert!(budget.charge_rows(1).is_err());
        }
        Ok(())
    }

    #[test]
    fn initial_operation_binding_failure_preserves_the_protected_read_budget() -> Fallible<()> {
        use rusqlite::{limits::Limit, ErrorCode};

        for principal_lookup in [false, true] {
            let (store, row) = fixture(ForkAdmissionOperationKindV1::PrincipalOwner)?;
            let bytes = if principal_lookup {
                32
            } else {
                expected_bytes(&row)
            };
            let read = |context: &mut NativeReadContextV1<'_, '_>| {
                if principal_lookup {
                    principal_operation_id_with_context(&store.conn, row.result_digest, context)
                        .map(|actual| assert_eq!(actual, row.operation_id))
                } else {
                    operation_with_context(&store.conn, row.kind, row.operation_id, context)
                        .map(|actual| assert_eq!(actual, Some(row.clone())))
                }
            };
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let previous = store.conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, 31)?;
            // An actual 32-byte parameter fails binding, before row stepping.
            // This is a native fault fixture, not malformed admitted authority.
            {
                let mut statement = store.conn.prepare("SELECT ?1")?;
                let error = statement
                    .query(params![row.operation_id.as_bytes().as_slice()])
                    .err();
                assert_eq!(
                    error.and_then(|error| error.sqlite_error_code()),
                    Some(ErrorCode::TooBig)
                );
            }
            assert_eq!(
                read(&mut NativeReadContextV1::protected(&mut budget)),
                Err(Error::StorageIndeterminate)
            );
            assert_eq!(budget.remaining_native_bytes(), bytes);
            budget.check_time()?;

            store.conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, previous)?;
            // Reuse the exact ledger: the valid probe + fetch need both rows
            // and every byte, proving that the binding fault debited neither.
            read(&mut NativeReadContextV1::protected(&mut budget))?;
            assert_eq!(budget.remaining_native_bytes(), 0);
            budget.check_time()?;
        }
        Ok(())
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
    fn principal_result_key_lookup_charges_actual_fixed_digest_and_probe_fetch_rows() -> Fallible<()>
    {
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
