//! Actual singleton registry probe, raw copy and guarded native construction.
//!
//! Core owns the existing durable grammar and semantic rules. Its metadata-only
//! guard borrows this operation's original ledger; no second budget is created.

use pos_core::{
    ForkAdmissionErrorV1 as Error, KeyRegistryReadErrorV1, KeyRegistryReadGuardV1,
    KeyRegistryReadRefusedV1, KeyRegistryReadWorkV1, KeyRegistryStateV1,
};
use rusqlite::Connection;

use super::fork_replay_row::{selected_field_with_context, SelectedRowV1};
use crate::{
    fork_manifest_publication::{PublicationSourceErrorV1, PublicationSourceResultV1},
    fork_replay::NativeReadContextV1,
    ForkReplayAuthorityReadErrorV1 as ReadError,
};

type Result<T> = std::result::Result<T, Error>;

pub(super) fn loaded_registry_with_context(
    conn: &Connection,
    context: &mut NativeReadContextV1<'_, '_>,
) -> PublicationSourceResultV1<Option<KeyRegistryStateV1>> {
    stored_registry_with_context(conn, context)
        .map_err(|error| match error {
            Error::StorageIndeterminate => PublicationSourceErrorV1::Storage,
            _ => PublicationSourceErrorV1::Invalid,
        })
        .and_then(|bytes| {
            bytes.map_or(Ok(None), |bytes| {
                decoded_registry_with_context(&bytes, context)
                    .map(Some)
                    .map_err(|_| PublicationSourceErrorV1::Invalid)
            })
        })
}

fn decoded_registry_with_context(
    bytes: &[u8],
    context: &mut NativeReadContextV1<'_, '_>,
) -> std::result::Result<KeyRegistryStateV1, ReadError> {
    KeyRegistryStateV1::from_durable_cbor_with_read_guard(bytes, &mut RegistryReadGuard(context))
        .map_err(|error| native_read_error(error, context))
}

fn native_read_error(
    error: KeyRegistryReadErrorV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> ReadError {
    match error {
        KeyRegistryReadErrorV1::InvalidSnapshot => ReadError::CorruptAuthority,
        KeyRegistryReadErrorV1::ReadRefused => {
            context.refuse();
            ReadError::BoundsExceeded
        }
    }
}

struct RegistryReadGuard<'context, 'budget, 'clock>(
    &'context mut NativeReadContextV1<'budget, 'clock>,
);

impl KeyRegistryReadGuardV1 for RegistryReadGuard<'_, '_, '_> {
    fn observe(
        &mut self,
        work: KeyRegistryReadWorkV1,
    ) -> std::result::Result<(), KeyRegistryReadRefusedV1> {
        match work {
            KeyRegistryReadWorkV1::Checkpoint => self.0.check(),
            KeyRegistryReadWorkV1::MaterializeBytes(bytes) => self.0.bytes(bytes),
        }
        .map_err(|_| KeyRegistryReadRefusedV1)
    }
}

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
        let mut pending = live.clone();
        let request = KeyDestructionRequestV1::new(identity, material, Hash::from_bytes([3; 32]));
        pending.begin_key_destruction(request)?;
        let mut destroyed = pending.clone();
        destroyed.complete_key_destruction(request, pos_core::deletion_receipt(&request))?;
        Ok(vec![KeyRegistryStateV1::new(), live, pending, destroyed])
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
        // Native replacement intentionally rejects invented destruction history.
        // Persist the real lifecycle, including pending, before testing its raw
        // snapshot. The ordinary rejection must not be weakened for this fixture.
        if registry.pending_destruction_requests().next().is_some()
            || registry.committed_destruction_facts().next().is_some()
        {
            assert!(matches!(
                store.save_key_registry(registry),
                Err(pos_core::CoreError::Serialization(_))
            ));
            assert_eq!(store.load_key_registry()?, None);
        }
        for state in registries()? {
            state.validate()?;
            store.save_key_registry(&state)?;
            assert_eq!(store.load_key_registry()?, Some(state.clone()));
            if &state == registry {
                return Ok((directory, store));
            }
        }
        Err("unknown registry lifecycle fixture".into())
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
        assert_eq!(super::super::sqlite_load_key_registry(&missing.conn)?, None);
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
                super::super::sqlite_load_key_registry(&conn),
                Err(pos_core::CoreError::Storage(_))
            ));
        }
        conn.execute("UPDATE key_registry SET state_cbor = X'00'", [])?;
        assert!(matches!(
            super::super::sqlite_load_key_registry(&conn),
            Err(pos_core::CoreError::Serialization(_))
        ));
        let registry = KeyRegistryStateV1::new();
        conn.execute(
            "UPDATE key_registry SET state_cbor = ?1",
            [encoded(&registry)?],
        )?;
        assert_eq!(
            super::super::sqlite_load_key_registry(&conn)?,
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

    /// Independent ADR-116 fields for the four qualified lifecycle fixtures.
    /// No production carrier or measured remaining-budget total is consulted.
    fn native_fixture_units(index: usize) -> usize {
        let owner = "é".repeat(64).len();
        let identity = 2 * owner + 1 + 8;
        let scope = 2 * owner + 1;
        let digest = 32 + 32;
        match index {
            0 => 1,
            1 => 3 * identity + 2 * scope + 2 * digest + 8 + 1 + 4 * owner + 44,
            2 => 4 * identity + scope + 4 * digest + 8 + 1 + 3 * owner + 43,
            _ => 4 * identity + scope + 4 * digest + 8 + 1 + 2 * owner + 42,
        }
    }

    #[test]
    fn registry_native_factory_borrows_the_same_raw_copy_ledger() -> Fallible<()> {
        for (index, registry) in registries()?.into_iter().enumerate() {
            let (_directory, store) = file_fixture(&registry)?;
            let raw = encoded(&registry)?.len();
            let expected = raw + native_fixture_units(index);
            for limit in [raw - 1, raw, expected - 1, expected, expected + 1] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let read = super::super::sqlite_load_key_registry_with_context(
                    &store.conn,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if limit >= expected {
                    assert_eq!(read, Ok(Some(registry.clone())));
                    assert_eq!(budget.remaining_native_bytes(), limit - expected);
                    assert_eq!(budget.check_time(), Ok(()));
                } else {
                    assert_eq!(read, Err(PublicationSourceErrorV1::Invalid));
                    assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
                }
            }
            assert_eq!(store.load_key_registry()?, Some(registry));
        }
        Ok(())
    }

    #[test]
    fn registry_native_repeated_and_absent_reads_never_reset_or_refund() -> Fallible<()> {
        for (index, registry) in registries()?.into_iter().enumerate() {
            let (_directory, store) = file_fixture(&registry)?;
            let expected = encoded(&registry)?.len() + native_fixture_units(index);
            for limit in [2 * expected - 1, 2 * expected] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 4, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let mut context = NativeReadContextV1::protected(&mut budget);
                assert_eq!(
                    loaded_registry_with_context(&store.conn, &mut context),
                    Ok(Some(registry.clone()))
                );
                let second = loaded_registry_with_context(&store.conn, &mut context);
                if limit == 2 * expected {
                    assert_eq!(second, Ok(Some(registry.clone())));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(second, Err(PublicationSourceErrorV1::Invalid));
                    let remaining = budget.remaining_native_bytes();
                    assert_eq!(
                        loaded_registry_with_context(
                            &store.conn,
                            &mut NativeReadContextV1::protected(&mut budget)
                        ),
                        Err(PublicationSourceErrorV1::Invalid)
                    );
                    assert_eq!(budget.remaining_native_bytes(), remaining);
                    assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
                }
            }
        }
        let missing = super::super::SqliteStore::open_in_memory()?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 1, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        for _ in 0..2 {
            assert_eq!(
                loaded_registry_with_context(
                    &missing.conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Ok(None)
            );
        }
        assert_eq!(budget.remaining_native_bytes(), 1);
        assert_eq!(
            loaded_registry_with_context(
                &missing.conn,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(PublicationSourceErrorV1::Invalid)
        );
        assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
        Ok(())
    }

    #[test]
    fn registry_native_faults_keep_closed_storage_and_invalid_classifications() -> Fallible<()> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE key_registry (singleton INTEGER PRIMARY KEY, state_cbor)",
        )?;
        conn.execute("INSERT INTO key_registry VALUES (1, X'00')", [])?;
        for (value, expected) in [
            (Value::Null, PublicationSourceErrorV1::Storage),
            (
                Value::Text("not a blob".to_owned()),
                PublicationSourceErrorV1::Storage,
            ),
            (Value::Blob(vec![0]), PublicationSourceErrorV1::Invalid),
        ] {
            conn.execute("UPDATE key_registry SET state_cbor = ?1", [&value])?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 4_096, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                loaded_registry_with_context(
                    &conn,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(expected)
            );
            assert_eq!(budget.check_time(), Ok(()));
        }
        conn.execute_batch("DROP TABLE key_registry")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 4_096, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            loaded_registry_with_context(&conn, &mut NativeReadContextV1::protected(&mut budget)),
            Err(PublicationSourceErrorV1::Storage)
        );
        assert_eq!(budget.check_time(), Ok(()));
        Ok(())
    }

    #[test]
    fn registry_core_origin_refusal_permanently_latches_without_inventing_a_debit() -> Fallible<()>
    {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 4_096, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            native_read_error(
                KeyRegistryReadErrorV1::InvalidSnapshot,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            ReadError::CorruptAuthority
        );
        assert_eq!(budget.check_time(), Ok(()));
        // Narrow impossible-size fault injection: Core's checked native sum
        // can refuse without asking the adapter to observe a failed debit.
        // Supply that closed outcome to the actual adapter's error mapper.
        assert_eq!(
            native_read_error(
                KeyRegistryReadErrorV1::ReadRefused,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            ReadError::BoundsExceeded
        );
        assert_eq!(budget.remaining_native_bytes(), 4_096);
        assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
        assert_eq!(budget.charge_bytes(1), Err(ReadError::BoundsExceeded));
        assert_eq!(budget.remaining_native_bytes(), 4_096);
        assert_eq!(
            decoded_registry_with_context(
                &encoded(&KeyRegistryStateV1::new())?,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(ReadError::BoundsExceeded)
        );
        let mut ordinary = NativeReadContextV1::ordinary();
        ordinary.refuse();
        assert_eq!(ordinary.check(), Ok(()));
        Ok(())
    }

    #[test]
    fn registry_native_checkpoints_keep_original_epoch_inside_decode_and_validation() -> Fallible<()>
    {
        for (index, registry) in registries()?.into_iter().enumerate() {
            let (_directory, store) = file_fixture(&registry)?;
            let expected = encoded(&registry)?.len() + native_fixture_units(index);
            for regression in [false, true] {
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
                let mut native_only_failures = 0;
                let mut successes = 0;
                for boundary in 2..=4_096 {
                    let mut raw_clock = ScriptedGuardMonotonicSourceV1::new(
                        std::iter::repeat_n(initial, boundary).chain([later]),
                    );
                    let raw_start = raw_clock.mark();
                    let limits = ForkReplayReadLimitsV1::new(1, 1, 2, expected, 10)?;
                    let mut raw_budget =
                        ForkReplayReadBudgetV1::new(limits, raw_start, &mut raw_clock)?;
                    let raw = stored_registry_with_context(
                        &store.conn,
                        &mut NativeReadContextV1::protected(&mut raw_budget),
                    );
                    let mut clock = ScriptedGuardMonotonicSourceV1::new(
                        std::iter::repeat_n(initial, boundary).chain([later]),
                    );
                    let start = clock.mark();
                    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                    let read = loaded_registry_with_context(
                        &store.conn,
                        &mut NativeReadContextV1::protected(&mut budget),
                    );
                    if read.is_ok() {
                        successes += 1;
                        assert_eq!(read, Ok(Some(registry.clone())));
                        assert_eq!(budget.remaining_native_bytes(), 0);
                        break;
                    }
                    assert_eq!(read, Err(PublicationSourceErrorV1::Invalid));
                    assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
                    native_only_failures += usize::from(raw.is_ok());
                }
                assert!(native_only_failures > 0 && successes > 0);
            }
        }
        Ok(())
    }
}
