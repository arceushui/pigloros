//! Actual protected FAH1 probe/fetch rows and bounded native decoding.

use pos_core::{ForkAdmissionErrorV1 as Error, ForkAdmissionHostRecordV1};
use rusqlite::Connection;

use crate::fork_replay::NativeReadContextV1;
use super::fork_replay_row::{selected_field_with_context, SelectedRowV1};

type Result<T> = std::result::Result<T, Error>;

fn host_length(
    conn: &Connection,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<usize>> {
    selected_field_with_context(conn, SelectedRowV1::HostProbe, context, |row, _| {
        row.get::<_, bool>(0)
            .map_err(|_| Error::StorageIndeterminate)
            .and_then(|blob| {
                if !blob {
                    return Err(Error::CorruptAuthority);
                }
                row.get::<_, i64>(1)
                    .map_err(|_| Error::StorageIndeterminate)
                    .and_then(|length| {
                        let exact = pos_core::MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1;
                        if usize::try_from(length).ok() != Some(exact) {
                            return Err(Error::CorruptAuthority);
                        }
                        row.get::<_, bool>(2)
                            .map_err(|_| Error::StorageIndeterminate)
                            .and_then(|fence| {
                                if fence {
                                    Ok(exact)
                                } else {
                                    Err(Error::CorruptAuthority)
                                }
                            })
                    })
            })
    })
}

pub(super) fn host_with_context(
    conn: &Connection,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<ForkAdmissionHostRecordV1>> {
    host_length(conn, context).and_then(|length| {
        length.map_or(Ok(None), |length| {
            selected_field_with_context(conn, SelectedRowV1::HostBlob, context, |row, context| {
                context
                    .bytes(length)
                    .map_err(|_| Error::CorruptAuthority)
                    .and_then(|()| {
                        row.get::<_, Vec<u8>>(0)
                            .map_err(|_| Error::StorageIndeterminate)
                    })
                    .and_then(|bytes| {
                        context
                            .check()
                            .map_err(|_| Error::CorruptAuthority)
                            .and_then(|()| {
                                context
                                    .host_record(&bytes)
                                    .map_err(|_| Error::CorruptAuthority)
                            })
                    })
            })
            .and_then(|host| host.map(Some).ok_or(Error::CorruptAuthority))
        })
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::{
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        Hash, PublicKey,
    };
    use rusqlite::types::Value;
    use std::time::Duration;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn host() -> Fallible<ForkAdmissionHostRecordV1> {
        Ok(ForkAdmissionHostRecordV1::new(
            Hash::from_bytes([1; 32]),
            PublicKey::from_bytes([2; 32]),
            Hash::from_bytes([3; 32]),
        )?)
    }

    fn fixture() -> Fallible<(
        tempfile::TempDir,
        super::super::SqliteStore,
        ForkAdmissionHostRecordV1,
    )> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("host.sqlite3");
        let store = super::super::SqliteStore::open(path.to_str().ok_or("host fixture path")?)?;
        let host = host()?;
        // A native typed immutable host-row fixture, not an initialized host
        // session or an admitted protected-consumer/public-authority fixture.
        super::super::insert_fork_admission_host_record(&store.conn, host)?;
        Ok((directory, store, host))
    }

    fn raw_fixture() -> Fallible<Connection> {
        let conn = Connection::open_in_memory()?;
        // This isolated schema omits storage constraints and affinity, to
        // expose impossible persisted types/caps/fences to the pre-getter gate.
        conn.execute_batch(
            "CREATE TABLE fork_admission_authority
            (singleton INTEGER, fah1_cbor, last_authority_wall_time)",
        )?;
        conn.execute(
            "INSERT INTO fork_admission_authority VALUES (1, ?1, 0)",
            [host()?.canonical_bytes()],
        )?;
        Ok(conn)
    }

    #[test]
    fn file_backed_host_recovery_charges_exact_raw_bytes_and_both_actual_rows() -> Fallible<()> {
        let (_directory, store, host) = fixture()?;
        let expected = host.canonical_bytes().len();
        for bytes in 1..=expected {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = super::super::sqlite_fork_admission_store_id_with_context(
                &store.conn,
                &mut NativeReadContextV1::protected(&mut budget),
            );
            if bytes == expected {
                assert_eq!(result?, host.store_id());
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
            super::super::sqlite_fork_admission_store_id_with_context(
                &store.conn,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(Error::CorruptAuthority)
        );
        assert_eq!(budget.remaining_native_bytes(), expected);
        assert!(budget.check_time().is_err());
        assert_eq!(
            super::super::sqlite_fork_admission_store_id_with_context(
                &store.conn,
                &mut NativeReadContextV1::ordinary()
            )?,
            host.store_id()
        );
        Ok(())
    }

    #[test]
    fn host_recovery_checks_original_epoch_around_every_raw_and_native_batch() -> Fallible<()> {
        let (_directory, store, host) = fixture()?;
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..256 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 109, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = super::super::sqlite_fork_admission_store_id_with_context(
                    &store.conn,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                match result {
                    Ok(store_id) => {
                        assert_eq!(store_id, host.store_id());
                        completed = true;
                        break;
                    }
                    Err(error) => {
                        assert_eq!(error, Error::CorruptAuthority);
                        assert!(budget.check_time().is_err());
                    }
                }
            }
            assert!(completed, "every host-recovery checkpoint was reached");
        }
        Ok(())
    }

    #[test]
    fn impossible_host_types_lengths_and_fences_refuse_before_raw_materialization() -> Fallible<()>
    {
        let native = host()?.canonical_bytes();
        for (host, fence) in [
            (Value::Null, Value::Integer(0)),
            (Value::Text("wrong-type".into()), Value::Integer(0)),
            (Value::Blob(vec![1; 108]), Value::Integer(0)),
            (Value::Blob(vec![1; 110]), Value::Integer(0)),
            (Value::Blob(native.clone()), Value::Integer(-1)),
            (Value::Blob(native.clone()), Value::Null),
            (Value::Blob(native.clone()), Value::Real(0.0)),
            (Value::Blob(native), Value::Text("0".into())),
        ] {
            let conn = raw_fixture()?;
            conn.execute(
                "UPDATE fork_admission_authority SET fah1_cbor = ?1, last_authority_wall_time = ?2",
                rusqlite::params![host, fence],
            )?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 109, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                host_with_context(&conn, &mut NativeReadContextV1::protected(&mut budget)),
                Err(Error::CorruptAuthority)
            );
            assert_eq!(budget.remaining_native_bytes(), 109);
            budget.charge_rows(1)?; // Only the returned probe row was charged.
            assert!(budget.check_time().is_ok());
            assert_eq!(
                super::super::sqlite_fork_admission_store_id_with_context(
                    &conn,
                    &mut NativeReadContextV1::ordinary()
                ),
                Err(Error::CorruptAuthority)
            );
        }
        Ok(())
    }

    #[test]
    fn ordinary_host_recovery_keeps_invalid_utf8_and_storage_error_contracts() -> Fallible<()> {
        for column in ["fah1_cbor", "last_authority_wall_time"] {
            let conn = raw_fixture()?;
            conn.execute_batch(&format!(
                "UPDATE fork_admission_authority SET {column} = CAST(X'FF' AS TEXT)"
            ))?;
            assert_eq!(
                super::super::sqlite_fork_admission_store_id_with_context(
                    &conn,
                    &mut NativeReadContextV1::ordinary()
                ),
                Err(Error::StorageIndeterminate)
            );
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 109, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                super::super::sqlite_fork_admission_store_id_with_context(
                    &conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::CorruptAuthority)
            );
            assert_eq!(budget.remaining_native_bytes(), 109);
        }
        let conn = Connection::open_in_memory()?;
        for protected in [false, true] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 109, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let mut context = if protected {
                NativeReadContextV1::protected(&mut budget)
            } else {
                NativeReadContextV1::ordinary()
            };
            assert_eq!(
                super::super::sqlite_fork_admission_store_id_with_context(&conn, &mut context),
                Err(Error::StorageIndeterminate)
            );
            assert_eq!(budget.remaining_native_bytes(), 109);
        }
        Ok(())
    }

    #[test]
    fn absent_host_has_no_phantom_row_or_byte_unit() -> Fallible<()> {
        let conn = raw_fixture()?;
        conn.execute("DELETE FROM fork_admission_authority", [])?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 109, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            host_with_context(&conn, &mut NativeReadContextV1::protected(&mut budget))?,
            None
        );
        assert_eq!(budget.remaining_native_bytes(), 109);
        budget.charge_rows(1)?;
        assert_eq!(
            super::super::sqlite_fork_admission_store_id_with_context(
                &conn,
                &mut NativeReadContextV1::ordinary()
            ),
            Err(Error::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn protected_host_carrier_matches_native_acceptance_without_decoder_buffers() -> Fallible<()> {
        let native = host()?.canonical_bytes();
        for offset in 0..native.len() {
            for replacement in [0, 255] {
                let mut bytes = native.clone();
                bytes[offset] = replacement;
                let expected = ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes).is_ok();
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    NativeReadContextV1::protected(&mut budget)
                        .host_record(&bytes)
                        .is_ok(),
                    expected
                );
                assert_eq!(budget.remaining_native_bytes(), 1);
                assert!(budget.check_time().is_ok());
                assert_eq!(
                    NativeReadContextV1::ordinary().host_record(&bytes).is_ok(),
                    expected
                );
            }
        }
        let conn = raw_fixture()?;
        for start in [9, 43, 77] {
            let mut bytes = native.clone();
            bytes[start..start + 32].fill(0);
            conn.execute(
                "UPDATE fork_admission_authority SET fah1_cbor = ?1",
                [bytes],
            )?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let epoch = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 109, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, epoch, &mut clock)?;
            assert_eq!(
                host_with_context(&conn, &mut NativeReadContextV1::protected(&mut budget)),
                Err(Error::CorruptAuthority)
            );
            assert_eq!(budget.remaining_native_bytes(), 0);
            assert!(budget.check_time().is_ok());
        }
        for bytes in [Vec::new(), vec![0xf6], vec![0; 110]] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let epoch = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, epoch, &mut clock)?;
            assert!(NativeReadContextV1::protected(&mut budget)
                .host_record(&bytes)
                .is_err());
            assert!(NativeReadContextV1::ordinary().host_record(&bytes).is_err());
            assert_eq!(budget.remaining_native_bytes(), 1);
        }
        Ok(())
    }
}
