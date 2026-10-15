//! Selected admission blobs, gated before their actual raw retrieval.

use rusqlite::{params, Connection, Row};

use super::FORK_ADMISSION_FAR1_SQL;
use crate::{fork_replay::NativeReadContextV1, ForkEventAuthorityErrorV1 as Error};

type Result<T> = std::result::Result<T, Error>;

enum BlobErrorV1 {
    Corrupt,
    Storage,
}

#[derive(Clone, Copy)]
pub(super) enum AdmissionRowV1 {
    Fork,
    Import,
}

impl AdmissionRowV1 {
    const fn queries(self) -> (&'static str, &'static str, usize) {
        match self {
            Self::Fork => (
                "SELECT typeof(far1_cbor) = 'blob', length(far1_cbor) FROM fork_admissions WHERE child_id = ?1",
                FORK_ADMISSION_FAR1_SQL,
                pos_core::MAX_FORK_ADMISSION_RECORD_BYTES_V1,
            ),
            Self::Import => (
                "SELECT typeof(ifa1_cbor) = 'blob', length(ifa1_cbor) FROM imported_fork_attribution_admissions WHERE child_id = ?1",
                "SELECT ifa1_cbor FROM imported_fork_attribution_admissions WHERE child_id = ?1",
                pos_core::MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1,
            ),
        }
    }
}

pub(super) fn admission_blob_with_context(
    conn: &Connection,
    kind: AdmissionRowV1,
    child_key: &str,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<Vec<u8>>> {
    selected_admission_blob(conn, kind, child_key, context).map_err(|_| Error::CorruptAuthority)
}

/// Recovery retains its distinct storage error table while using the same
/// actual selected FAR1 gate as the protected authority-read owner.
pub(super) fn recovery_admission_blob_with_context(
    conn: &Connection,
    child_key: &str,
    context: &mut NativeReadContextV1<'_, '_>,
) -> std::result::Result<Option<Vec<u8>>, pos_core::ForkAdmissionErrorV1> {
    selected_admission_blob(conn, AdmissionRowV1::Fork, child_key, context).map_err(|error| {
        match error {
            BlobErrorV1::Corrupt => pos_core::ForkAdmissionErrorV1::CorruptAuthority,
            BlobErrorV1::Storage => pos_core::ForkAdmissionErrorV1::StorageIndeterminate,
        }
    })
}

fn selected_admission_blob(
    conn: &Connection,
    kind: AdmissionRowV1,
    child_key: &str,
    context: &mut NativeReadContextV1<'_, '_>,
) -> std::result::Result<Option<Vec<u8>>, BlobErrorV1> {
    use BlobErrorV1::{Corrupt, Storage};
    let (probe, fetch, maximum) = kind.queries();
    context
        .check()
        .map_err(|_| Corrupt)
        .and_then(|()| conn.prepare(probe).map_err(|_| Storage))
        .and_then(|mut statement| {
            context
                .check()
                .map_err(|_| Corrupt)
                .and_then(|()| statement.query(params![child_key]).map_err(|_| Storage))
                .and_then(|mut rows| {
                    context
                        .row_available()
                        .map_err(|_| Corrupt)
                        .and_then(|()| rows.next().map_err(|_| Storage))
                        .and_then(|row| match row {
                            None => context.check().map(|()| None).map_err(|_| Corrupt),
                            Some(row) => context
                                .suffix_row()
                                .map_err(|_| Corrupt)
                                .and_then(|()| {
                                    admission_bytes_from_row(
                                        conn, row, fetch, maximum, child_key, context,
                                    )
                                })
                                .map(Some),
                        })
                })
        })
}

/// The caller holds the probe statement and `Rows` through fetch and post-check.
fn admission_bytes_from_row(
    conn: &Connection,
    row: &Row<'_>,
    fetch: &str,
    maximum: usize,
    child_key: &str,
    context: &mut NativeReadContextV1<'_, '_>,
) -> std::result::Result<Vec<u8>, BlobErrorV1> {
    use BlobErrorV1::{Corrupt, Storage};
    row.get::<_, bool>(0).map_err(|_| Storage).and_then(|blob| {
        if !blob {
            return Err(Storage);
        }
        row.get::<_, i64>(1)
            .map_err(|_| Storage)
            .and_then(|length| usize::try_from(length).map_err(|_| Corrupt))
            .and_then(|length| {
                if length > maximum {
                    return Err(Corrupt);
                }
                context
                    .check()
                    .map_err(|_| Corrupt)
                    .and_then(|()| context.suffix_row().map_err(|_| Corrupt))
                    .and_then(|()| context.bytes(length).map_err(|_| Corrupt))
                    .and_then(|()| {
                        conn.query_row(fetch, params![child_key], |row| row.get::<_, Vec<u8>>(0))
                            .map_err(|_| Storage)
                    })
                    .and_then(|bytes| context.check().map(|()| bytes).map_err(|_| Corrupt))
            })
    })
}

/// Independent test oracle: byte encoders and logical field lengths only.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn imported_admission_phase_cost(
    fork_bytes: &[u8],
    import_bytes: &[u8],
) -> std::result::Result<usize, Box<dyn std::error::Error>> {
    let fork = pos_core::ImportedForkAdmissionRecordV1::from_canonical_cbor(fork_bytes)?;
    let local = pos_core::ForkAdmissionRecordV1::new(fork.fields().clone())?.to_canonical_cbor();
    let import = pos_core::ImportedForkAttributionAdmissionV1::from_canonical_cbor(import_bytes)?;
    let issuer = &import.input().issuer;
    // FAR1: two raw fetches, matcher digest, accepted digest and native field
    // copy. The two local buffers are the real projection/equality Vecs.
    // IFA1: raw fetch plus equality; FAI1: equality plus separate nested Vec.
    Ok(ulid::ULID_LEN * 2
        + fork.to_canonical_cbor().len() * 5
        + local.len() * 2
        + fork.fields().creator.as_str().len() * 2
        + import.to_canonical_cbor().len() * 2
        + issuer.to_canonical_cbor().len() * 2
        + issuer.issuer_id().len())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{fae1_fixture::Fallible, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use std::time::Duration;

    #[test]
    fn admission_type_and_cap_probes_refuse_before_raw_retrieval() -> Fallible<()> {
        for (kind, sql, maximum) in [
            (
                AdmissionRowV1::Fork,
                "UPDATE fork_admissions SET far1_cbor = ?1",
                pos_core::MAX_FORK_ADMISSION_RECORD_BYTES_V1,
            ),
            (
                AdmissionRowV1::Import,
                "UPDATE imported_fork_attribution_admissions SET ifa1_cbor = ?1",
                pos_core::MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1,
            ),
        ] {
            // The IFA1 production table rejects >512 bytes at INSERT. This
            // isolated owner fixture omits only storage constraints to expose
            // impossible persisted bytes to the pre-getter gate. It is not an
            // authenticated import/public-consumer fixture.
            let conn = Connection::open_in_memory()?;
            conn.execute_batch(
                "CREATE TABLE fork_admissions (child_id TEXT, far1_cbor BLOB);
                CREATE TABLE imported_fork_attribution_admissions (child_id TEXT, ifa1_cbor BLOB);
                INSERT INTO fork_admissions VALUES ('child', X'00');
                INSERT INTO imported_fork_attribution_admissions VALUES ('child', X'00');",
            )?;
            let key = "child";
            for value in [
                rusqlite::types::Value::Blob(vec![0; maximum + 1]),
                rusqlite::types::Value::Text("not-a-blob".into()),
            ] {
                assert_eq!(conn.execute(sql, [value])?, 1);
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    admission_blob_with_context(
                        &conn,
                        kind,
                        key,
                        &mut NativeReadContextV1::protected(&mut budget)
                    ),
                    Err(Error::CorruptAuthority)
                );
                assert_eq!(budget.remaining_native_bytes(), 64);
                assert!(budget.check_time().is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn recovery_raw_gate_charges_actual_getter_bytes() -> Fallible<()> {
        use pos_core::ForkAdmissionErrorV1 as RecoveryError;
        let conn = Connection::open_in_memory()?;
        // This fixture tests only raw retrieval, not native admission or a
        // protected consumer. It deliberately has no admission constraints.
        conn.execute_batch("CREATE TABLE fork_admissions (child_id TEXT, far1_cbor BLOB)")?;
        let raw = vec![0; 50];
        assert_eq!(
            conn.execute("INSERT INTO fork_admissions VALUES ('child', ?1)", [&raw])?,
            1
        );
        for bytes in 1..=raw.len() {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = recovery_admission_blob_with_context(
                &conn,
                "child",
                &mut NativeReadContextV1::protected(&mut budget),
            );
            if bytes == raw.len() {
                assert_eq!(result?, Some(raw.clone()));
                assert_eq!(budget.remaining_native_bytes(), 0);
            } else {
                assert_eq!(result, Err(RecoveryError::CorruptAuthority));
                assert!(budget.check_time().is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn recovery_raw_gate_preserves_its_distinct_storage_and_corruption_errors() -> Fallible<()> {
        use pos_core::ForkAdmissionErrorV1 as RecoveryError;
        let conn = Connection::open_in_memory()?;
        // Impossible raw-state fixture, not native admission authority.
        conn.execute_batch(
            "CREATE TABLE fork_admissions (child_id TEXT, far1_cbor BLOB);
            INSERT INTO fork_admissions VALUES ('child', X'00')",
        )?;
        for (value, expected) in [
            (
                rusqlite::types::Value::Text("wrong-type".into()),
                RecoveryError::StorageIndeterminate,
            ),
            (
                rusqlite::types::Value::Blob(vec![
                    0;
                    pos_core::MAX_FORK_ADMISSION_RECORD_BYTES_V1 + 1
                ]),
                RecoveryError::CorruptAuthority,
            ),
        ] {
            assert_eq!(
                conn.execute("UPDATE fork_admissions SET far1_cbor = ?1", [value])?,
                1
            );
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                recovery_admission_blob_with_context(
                    &conn,
                    "child",
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(expected)
            );
            assert_eq!(budget.remaining_native_bytes(), 64);
            assert!(budget.check_time().is_ok());
            assert_eq!(
                admission_blob_with_context(
                    &conn,
                    AdmissionRowV1::Fork,
                    "child",
                    &mut NativeReadContextV1::ordinary()
                ),
                Err(Error::CorruptAuthority)
            );
        }
        Ok(())
    }

    #[test]
    fn recovery_raw_gate_absence_and_unavailable_table_preserve_contracts() -> Fallible<()> {
        use pos_core::ForkAdmissionErrorV1 as RecoveryError;
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE fork_admissions (child_id TEXT, far1_cbor BLOB)")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            recovery_admission_blob_with_context(
                &conn,
                "child",
                &mut NativeReadContextV1::protected(&mut budget)
            )?,
            None
        );
        assert_eq!(budget.remaining_native_bytes(), 64);
        budget.charge_rows(1)?;
        conn.execute_batch("DROP TABLE fork_admissions")?;
        assert_eq!(
            recovery_admission_blob_with_context(
                &conn,
                "child",
                &mut NativeReadContextV1::ordinary()
            ),
            Err(RecoveryError::StorageIndeterminate)
        );
        Ok(())
    }

    #[test]
    fn recovery_raw_gate_checks_each_original_epoch_boundary_and_fetch_row_limit() -> Fallible<()> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE fork_admissions (child_id TEXT, far1_cbor BLOB)")?;
        let raw = vec![0; 50];
        conn.execute("INSERT INTO fork_admissions VALUES ('child', ?1)", [&raw])?;
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..160 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, raw.len(), 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = recovery_admission_blob_with_context(
                    &conn,
                    "child",
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(value) = result {
                    assert_eq!(value, Some(raw.clone()));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "all recovery raw gate expiry/regression checkpoints tested"
            );
        }
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, raw.len(), 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            recovery_admission_blob_with_context(
                &conn,
                "child",
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        assert!(budget.check_time().is_err());
        Ok(())
    }

    #[test]
    fn absent_admission_key_has_no_stored_row_or_blob_unit() -> Fallible<()> {
        let store = super::super::SqliteStore::open(":memory:")?;
        for kind in [AdmissionRowV1::Fork, AdmissionRowV1::Import] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                admission_blob_with_context(
                    &store.conn,
                    kind,
                    "absent-key",
                    &mut NativeReadContextV1::protected(&mut budget)
                )?,
                None
            );
            assert_eq!(budget.remaining_native_bytes(), 64);
            budget.charge_rows(1)?;
        }
        Ok(())
    }
}
