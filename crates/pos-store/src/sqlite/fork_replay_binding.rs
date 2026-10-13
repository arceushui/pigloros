//! Selected local POB1 fields at their actual `SQLite` materialization sites.

use pos_core::{ForkAdmissionErrorV1 as Error, Hash, PrincipalOwnerBindingV1};
use rusqlite::{params, Connection};

use crate::fork_replay::NativeReadContextV1;

type Result<T> = std::result::Result<T, Error>;

const BINDING_PROBE_SQL: &str = "SELECT
    typeof(principal_digest) = 'blob', length(principal_digest),
    typeof(pob1_cbor) = 'blob', length(pob1_cbor)
    FROM fork_principal_owner_bindings WHERE operation_id = ?1";
const BINDING_FETCH_SQL: &str = "SELECT principal_digest, pob1_cbor
    FROM fork_principal_owner_bindings WHERE operation_id = ?1";
const HASH_BYTES: u8 = 32;

fn binding_length(
    conn: &Connection,
    operation_id: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<usize>> {
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut statement = conn
        .prepare(BINDING_PROBE_SQL)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = statement
        .query(params![operation_id.as_bytes().as_slice()])
        .map_err(|_| Error::StorageIndeterminate)?;
    context.row_available().map_err(|_| Error::CorruptAuthority)?;
    let Some(row) = rows.next().map_err(|_| Error::StorageIndeterminate)? else {
        return context
            .check()
            .map(|()| None)
            .map_err(|_| Error::CorruptAuthority);
    };
    context.suffix_row().map_err(|_| Error::CorruptAuthority)?;
    for column in [0, 2] {
        if !row
            .get::<_, bool>(column)
            .map_err(|_| Error::StorageIndeterminate)?
        {
            return Err(Error::StorageIndeterminate);
        }
    }
    let principal_length = row
        .get::<_, i64>(1)
        .map_err(|_| Error::StorageIndeterminate)?;
    let length = row.get::<_, i64>(3).map_err(|_| Error::StorageIndeterminate)?;
    let length = usize::try_from(length).map_err(|_| Error::CorruptAuthority)?;
    if principal_length != i64::from(HASH_BYTES)
        || length > pos_core::MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1
    {
        return Err(Error::CorruptAuthority);
    }
    context
        .check()
        .map(|()| Some(length))
        .map_err(|_| Error::CorruptAuthority)
}

pub(super) fn binding_with_context(
    conn: &Connection,
    operation_id: Hash,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<PrincipalOwnerBindingV1>> {
    let Some(length) = binding_length(conn, operation_id, context)? else {
        return Ok(None);
    };
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut statement = conn
        .prepare(BINDING_FETCH_SQL)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    let mut rows = statement
        .query(params![operation_id.as_bytes().as_slice()])
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
    let principal_digest = row
        .get::<_, Vec<u8>>(0)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    context.bytes(length).map_err(|_| Error::CorruptAuthority)?;
    let bytes = row
        .get::<_, Vec<u8>>(1)
        .map_err(|_| Error::StorageIndeterminate)?;
    context.check().map_err(|_| Error::CorruptAuthority)?;
    // The query key is already a typed Hash. Do not allocate a synthetic key
    // Vec merely to compare it with the native binding's operation identity.
    let binding = context
        .local_principal_binding(&bytes)
        .map_err(|_| Error::CorruptAuthority)?;
    if binding.input().operation_id != operation_id
        || binding.input().principal_digest.as_bytes().as_slice() != principal_digest.as_slice()
    {
        return Err(Error::CorruptAuthority);
    }
    context
        .check()
        .map(|()| Some(binding))
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
        owner: &str,
    ) -> Fallible<(
        tempfile::TempDir,
        super::super::SqliteStore,
        PrincipalOwnerBindingV1,
    )> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("binding.sqlite3");
        let store = super::super::SqliteStore::open(path.to_str().ok_or("binding fixture path")?)?;
        let binding = PrincipalOwnerBindingV1::new(pos_core::PrincipalOwnerBindingInputV1 {
            operation_id: Hash::from_bytes([1; 32]),
            principal_digest: Hash::from_bytes([2; 32]),
            owner: pos_core::OwnerIdV1::new(owner)?,
            origin: pos_core::ForkAuthorityOriginV1::Local,
        })?;
        // This is a typed immutable binding-row fixture, not a claim of
        // admitted authority. Full public host/import fixtures remain intact.
        store.conn.execute(
            "INSERT INTO fork_principal_owner_bindings VALUES (?1, ?2, ?3)",
            params![
                binding.input().operation_id.as_bytes().as_slice(),
                binding.input().principal_digest.as_bytes().as_slice(),
                binding.to_canonical_cbor()
            ],
        )?;
        Ok((directory, store, binding))
    }

    fn binding_cost(binding: &PrincipalOwnerBindingV1) -> usize {
        // Actual principal BLOB, raw POB1, decoder owner and equality Vec.
        32 + binding.to_canonical_cbor().len() * 2 + binding.input().owner.as_str().len()
    }

    #[test]
    fn file_backed_binding_reader_charges_every_actual_byte_and_both_rows() -> Fallible<()> {
        for owner in ["owner".to_owned(), "é".repeat(64)] {
            let (_directory, store, binding) = fixture(&owner)?;
            let expected = binding_cost(&binding);
            assert_eq!(
                binding_with_context(
                    &store.conn,
                    binding.input().operation_id,
                    &mut NativeReadContextV1::ordinary()
                )?,
                Some(binding.clone())
            );
            for bytes in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = binding_with_context(
                    &store.conn,
                    binding.input().operation_id,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if bytes == expected {
                    assert_eq!(result?, Some(binding.clone()));
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
                binding_with_context(
                    &store.conn,
                    binding.input().operation_id,
                    &mut NativeReadContextV1::protected(&mut budget)
                ),
                Err(Error::CorruptAuthority)
            );
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    #[test]
    fn binding_lookup_checks_original_epoch_around_raw_and_native_batches() -> Fallible<()> {
        let (_directory, store, binding) = fixture(&"é".repeat(64))?;
        let expected = binding_cost(&binding);
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..256 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, expected, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = binding_with_context(
                    &store.conn,
                    binding.input().operation_id,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(value) = result {
                    assert_eq!(value, Some(binding.clone()));
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "all binding lookup expiry/regression checkpoints exercised"
            );
        }
        Ok(())
    }

    #[test]
    fn impossible_binding_types_widths_and_cap_refuse_before_raw_getters() -> Fallible<()> {
        use rusqlite::types::Value;
        for (principal, bytes, error) in [
            (
                Value::Text("x".repeat(32)),
                Value::Blob(vec![1]),
                Error::StorageIndeterminate,
            ),
            (
                Value::Blob(vec![2; 32]),
                Value::Text("wrong-type".into()),
                Error::StorageIndeterminate,
            ),
            (
                Value::Blob(vec![2; 31]),
                Value::Blob(vec![1]),
                Error::CorruptAuthority,
            ),
            (
                Value::Blob(vec![2; 33]),
                Value::Blob(vec![1]),
                Error::CorruptAuthority,
            ),
            (
                Value::Blob(vec![2; 32]),
                Value::Blob(vec![1; pos_core::MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1 + 1]),
                Error::CorruptAuthority,
            ),
        ] {
            // Isolated raw owner schema omits native storage constraints only
            // to reach impossible persisted type/width/cap cases. No authority.
            let conn = Connection::open_in_memory()?;
            conn.execute_batch(
                "CREATE TABLE fork_principal_owner_bindings
                (operation_id BLOB, principal_digest BLOB, pob1_cbor BLOB)",
            )?;
            let operation = Hash::from_bytes([1; 32]);
            assert_eq!(
                conn.execute(
                    "INSERT INTO fork_principal_owner_bindings VALUES (?1, ?2, ?3)",
                    params![operation.as_bytes().as_slice(), principal, bytes]
                )?,
                1
            );
            for protected in [false, true] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let mut context = if protected {
                    NativeReadContextV1::protected(&mut budget)
                } else {
                    NativeReadContextV1::ordinary()
                };
                assert_eq!(binding_with_context(&conn, operation, &mut context), Err(error));
                assert_eq!(budget.remaining_native_bytes(), 64);
                assert!(budget.check_time().is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn absent_selected_binding_has_no_row_or_byte_unit() -> Fallible<()> {
        let (_directory, store, _) = fixture("owner")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            binding_with_context(
                &store.conn,
                Hash::from_bytes([99; 32]),
                &mut NativeReadContextV1::protected(&mut budget)
            )?,
            None
        );
        assert_eq!(budget.remaining_native_bytes(), 64);
        budget.charge_rows(1)?;
        let conn = Connection::open_in_memory()?;
        assert_eq!(
            binding_with_context(
                &conn,
                Hash::from_bytes([99; 32]),
                &mut NativeReadContextV1::ordinary()
            ),
            Err(Error::StorageIndeterminate)
        );
        Ok(())
    }

    #[test]
    fn binding_reader_revalidates_native_bytes_and_both_durable_identities() -> Fallible<()> {
        for column in ["principal_digest", "pob1_cbor", "native-operation"] {
            let (_directory, store, binding) = fixture("owner")?;
            let bytes = match column {
                "pob1_cbor" => vec![0],
                "native-operation" => {
                    let mut input = binding.input().clone();
                    input.operation_id = Hash::from_bytes([3; 32]);
                    PrincipalOwnerBindingV1::new(input)?.to_canonical_cbor()
                }
                _ => Hash::zero().as_bytes().to_vec(),
            };
            let sql = if column == "principal_digest" {
                "UPDATE fork_principal_owner_bindings SET principal_digest = ?1"
            } else {
                "UPDATE fork_principal_owner_bindings SET pob1_cbor = ?1"
            };
            store.conn.execute(sql, [bytes])?;
            for protected in [false, true] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 1_024, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let mut context = if protected {
                    NativeReadContextV1::protected(&mut budget)
                } else {
                    NativeReadContextV1::ordinary()
                };
                assert_eq!(
                    binding_with_context(&store.conn, binding.input().operation_id, &mut context),
                    Err(Error::CorruptAuthority)
                );
                assert!(budget.check_time().is_ok());
            }
        }
        Ok(())
    }

    fn principal_result_cost(
        binding: &PrincipalOwnerBindingV1,
        store_id: Hash,
        evidence: Hash,
    ) -> Fallible<usize> {
        use ciborium::value::Value;
        // Independent five-field POC1 commitment preimage oracle: no private
        // emitter or production length helper is called by this calculation.
        let preimage = Value::Array(vec![
            Value::Bytes(store_id.as_bytes().to_vec()),
            Value::Bytes(binding.input().operation_id.as_bytes().to_vec()),
            Value::Bytes(evidence.as_bytes().to_vec()),
            Value::Bytes(binding.input().principal_digest.as_bytes().to_vec()),
            Value::Text(binding.input().owner.as_str().to_owned()),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&preimage, &mut bytes)?;
        Ok(binding_cost(binding) + binding.to_canonical_cbor().len() + bytes.len())
    }

    fn principal_row(
        binding: &PrincipalOwnerBindingV1,
        store_id: Hash,
        evidence: Hash,
    ) -> super::super::ForkAdmissionOperationRowV1 {
        super::super::ForkAdmissionOperationRowV1 {
            kind: super::super::ForkAdmissionOperationKindV1::PrincipalOwner,
            operation_id: binding.input().operation_id,
            evidence_digest: evidence,
            commitment: crate::fork_admission_authority::principal_owner_commitment(
                store_id, binding, evidence,
            ),
            result_digest: binding.digest(),
            child_id: None,
        }
    }

    #[test]
    fn principal_result_charges_digest_and_commitment_only_after_their_predecessors(
    ) -> Fallible<()> {
        let (_directory, store, binding) = fixture(&"é".repeat(64))?;
        let store_id = Hash::from_bytes([4; 32]);
        let evidence = Hash::from_bytes([5; 32]);
        let mut row = principal_row(&binding, store_id, evidence);
        let expected = principal_result_cost(&binding, store_id, evidence)?;
        for bytes in 1..=expected {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 2, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = super::super::sqlite_principal_owner_result_with_context(
                &store.conn,
                store_id,
                &row,
                &mut NativeReadContextV1::protected(&mut budget),
            );
            if bytes == expected {
                assert_eq!(result?, binding);
                assert_eq!(budget.remaining_native_bytes(), 0);
            } else {
                assert_eq!(result, Err(Error::CorruptAuthority));
                assert!(budget.check_time().is_err());
            }
        }
        row.result_digest = Hash::zero();
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let digest_only = binding_cost(&binding) + binding.to_canonical_cbor().len();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 2, digest_only, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            super::super::sqlite_principal_owner_result_with_context(
                &store.conn,
                store_id,
                &row,
                &mut NativeReadContextV1::protected(&mut budget)
            ),
            Err(Error::CorruptAuthority)
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        assert!(
            budget.check_time().is_ok(),
            "no phantom preimage after a mismatched digest"
        );
        row.result_digest = binding.digest();
        row.commitment = Hash::zero();
        assert_eq!(
            super::super::sqlite_principal_owner_result_with_context(
                &store.conn,
                store_id,
                &row,
                &mut NativeReadContextV1::ordinary()
            ),
            Err(Error::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn principal_result_checks_original_epoch_through_digest_and_commitment() -> Fallible<()> {
        let (_directory, store, binding) = fixture(&"é".repeat(64))?;
        let store_id = Hash::from_bytes([4; 32]);
        let evidence = Hash::from_bytes([5; 32]);
        let row = principal_row(&binding, store_id, evidence);
        let expected = principal_result_cost(&binding, store_id, evidence)?;
        for last in [Duration::ZERO, Duration::from_secs(2)] {
            let mut completed = false;
            for marks in 2..256 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(Duration::from_millis(1), marks).chain([last]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, expected, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = super::super::sqlite_principal_owner_result_with_context(
                    &store.conn,
                    store_id,
                    &row,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if let Ok(value) = result {
                    assert_eq!(value, binding);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    completed = true;
                    break;
                }
                assert!(budget.check_time().is_err());
            }
            assert!(
                completed,
                "all principal result expiry/regression checkpoints exercised"
            );
        }
        Ok(())
    }
}
