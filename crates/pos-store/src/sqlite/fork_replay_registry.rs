//! Actual singleton registry probe and owned raw snapshot copy.
//!
//! This owner gates raw storage only; it does not replace the existing native
//! registry decoder/validator or claim their allocation/deadline completeness.

use pos_core::ForkAdmissionErrorV1 as Error;
use rusqlite::Connection;

use super::fork_replay_row::{selected_field_with_context, SelectedRowV1};
use crate::fork_replay::NativeReadContextV1;

type Result<T> = std::result::Result<T, Error>;

pub(super) fn stored_registry_with_context(
    conn: &Connection,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<Vec<u8>>> {
    selected_field_with_context(conn, SelectedRowV1::RegistryProbe, context, |row, _| {
        // This real scalar row represents both a present snapshot and absence.
        // No native registry cap is invented: the installed ledger is the cap.
        row.get::<_, Option<bool>>(0)
            .map_err(|_| Error::StorageIndeterminate)
            .and_then(|blob| {
                blob.map(|blob| {
                    if !blob {
                        return Err(Error::StorageIndeterminate);
                    }
                    row.get::<_, i64>(1)
                        .map_err(|_| Error::StorageIndeterminate)
                        .and_then(|length| {
                            usize::try_from(length).map_err(|_| Error::CorruptAuthority)
                        })
                })
                .transpose()
            })
    })
    .and_then(|probe| probe.ok_or(Error::StorageIndeterminate))
    .and_then(|length| {
        length.map_or(Ok(None), |length| {
            context
                .require_bytes(Some(length))
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| {
                    selected_field_with_context(
                        conn,
                        SelectedRowV1::RegistryBlob,
                        context,
                        |row, context| {
                            context
                                .bytes(length)
                                .map_err(|_| Error::CorruptAuthority)
                                .and_then(|()| {
                                    row.get::<_, Vec<u8>>(0)
                                        .map_err(|_| Error::StorageIndeterminate)
                                })
                        },
                    )
                })
                .and_then(|bytes| {
                    bytes
                        .filter(|bytes| bytes.len() == length)
                        .map(Some)
                        .ok_or(Error::CorruptAuthority)
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
        Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1,
        KeyRoleV1, OwnerIdV1, PublicKey,
    };
    use rusqlite::types::Value;
    use std::time::Duration;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn registries() -> Fallible<Vec<KeyRegistryStateV1>> {
        let mut live = KeyRegistryStateV1::new();
        let identity = KeyIdentityV1::new(
            OwnerIdV1::new("é".repeat(64))?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        );
        let material = Hash::from_bytes([1; 32]);
        live.register_key(KeyRegistrationV1::new(
            identity,
            material,
            Some(PublicKey::from_bytes([2; 32])),
        ))?;
        let mut destroyed = live.clone();
        let request = KeyDestructionRequestV1::new(identity, material, Hash::from_bytes([3; 32]));
        destroyed.begin_key_destruction(request)?;
        destroyed.complete_key_destruction(request, pos_core::deletion_receipt(&request))?;
        Ok(vec![KeyRegistryStateV1::new(), live, destroyed])
    }

    fn encoded(registry: &KeyRegistryStateV1) -> Fallible<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(registry, &mut bytes)?;
        Ok(bytes)
    }

    fn file_fixture(
        registry: &KeyRegistryStateV1,
    ) -> Fallible<(tempfile::TempDir, super::super::SqliteStore)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("registry-raw.sqlite3");
        let mut store =
            super::super::SqliteStore::open(path.to_str().ok_or("registry fixture path")?)?;
        store.save_key_registry(registry)?;
        assert_eq!(store.load_key_registry()?, Some(registry.clone()));
        Ok((directory, store))
    }

    #[test]
    fn registry_raw_copy_charges_exact_native_writer_bytes_and_both_rows() -> Fallible<()> {
        for registry in registries()? {
            let (_directory, store) = file_fixture(&registry)?;
            let bytes = encoded(&registry)?;
            for limit in 1..=bytes.len() {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let read = stored_registry_with_context(
                    &store.conn,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if limit == bytes.len() {
                    assert_eq!(read?, Some(bytes.clone()));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(read, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
            }
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, bytes.len(), 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                stored_registry_with_context(
                    &store.conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::CorruptAuthority)
            );
            assert_eq!(budget.remaining_native_bytes(), bytes.len());
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    #[test]
    fn registry_raw_repeated_and_missing_reads_do_not_reset_the_ledger() -> Fallible<()> {
        let registry = registries()?.pop().ok_or("destroyed registry")?;
        let (_directory, store) = file_fixture(&registry)?;
        let bytes = encoded(&registry)?;
        for limit in [bytes.len() * 2 - 1, bytes.len() * 2] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 4, limit, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                stored_registry_with_context(
                    &store.conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                )?,
                Some(bytes.clone())
            );
            let second = stored_registry_with_context(
                &store.conn,
                &mut NativeReadContextV1::protected(&mut budget),
            );
            if limit == bytes.len() * 2 {
                assert_eq!(second?, Some(bytes.clone()));
                assert_eq!(budget.remaining_native_bytes(), 0);
            } else {
                assert_eq!(second, Err(Error::CorruptAuthority));
                assert!(budget.check_time().is_err());
            }
        }
        let missing = super::super::SqliteStore::open_in_memory()?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 1, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        for _ in 0..2 {
            assert_eq!(
                stored_registry_with_context(
                    &missing.conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                )?,
                None
            );
        }
        assert_eq!(budget.remaining_native_bytes(), 1);
        assert_eq!(
            stored_registry_with_context(
                &missing.conn,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(Error::CorruptAuthority)
        );
        assert!(budget.check_time().is_err());
        assert_eq!(
            super::super::sqlite_load_key_registry_with_context(
                &missing.conn,
                &mut NativeReadContextV1::ordinary()
            )?,
            None
        );
        Ok(())
    }

    #[test]
    fn registry_raw_invalid_types_fail_before_owned_get_and_ordinary_contract_is_retained(
    ) -> Fallible<()> {
        let conn = Connection::open_in_memory()?;
        // Only storage-type fault injection: omit affinity/NOT NULL constraints
        // to reach the actual pre-getter gate. No public authority is claimed.
        conn.execute_batch(
            "CREATE TABLE key_registry (singleton INTEGER PRIMARY KEY, state_cbor)",
        )?;
        conn.execute("INSERT INTO key_registry VALUES (1, X'00')", [])?;
        for value in [
            Value::Null,
            Value::Integer(0),
            Value::Real(1.5),
            Value::Text("not a blob".to_owned()),
        ] {
            conn.execute("UPDATE key_registry SET state_cbor = ?1", [&value])?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                stored_registry_with_context(
                    &conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::StorageIndeterminate)
            );
            assert_eq!(budget.remaining_native_bytes(), 1);
            assert!(matches!(
                super::super::sqlite_load_key_registry_with_context(
                    &conn,
                    &mut NativeReadContextV1::ordinary()
                ),
                Err(pos_core::CoreError::Storage(_))
            ));
        }
        conn.execute("UPDATE key_registry SET state_cbor = X'00'", [])?;
        assert!(matches!(
            super::super::sqlite_load_key_registry_with_context(
                &conn,
                &mut NativeReadContextV1::ordinary()
            ),
            Err(pos_core::CoreError::Serialization(_))
        ));
        let registry = KeyRegistryStateV1::new();
        conn.execute(
            "UPDATE key_registry SET state_cbor = ?1",
            [encoded(&registry)?],
        )?;
        assert_eq!(
            super::super::sqlite_load_key_registry_with_context(
                &conn,
                &mut NativeReadContextV1::ordinary()
            )?,
            Some(registry)
        );
        conn.execute_batch("DROP TABLE key_registry")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            stored_registry_with_context(&conn, &mut NativeReadContextV1::protected(&mut budget)),
            Err(Error::StorageIndeterminate)
        );
        Ok(())
    }

    #[test]
    fn registry_raw_copy_checks_original_epoch_around_each_storage_batch() -> Fallible<()> {
        let registry = registries()?.pop().ok_or("destroyed registry")?;
        let (_directory, store) = file_fixture(&registry)?;
        let bytes = encoded(&registry)?;
        for regression in [false, true] {
            let mut failed = 0;
            let mut succeeded = 0;
            for boundary in 2..=128 {
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
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes.len(), 10)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let read = stored_registry_with_context(
                    &store.conn,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if read.is_ok() {
                    succeeded += 1;
                    assert_eq!(read?, Some(bytes.clone()));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    failed += 1;
                    assert_eq!(read, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
            }
            assert!(failed > 0 && succeeded > 0);
        }
        Ok(())
    }
}
