//! Selected admission blobs, gated before their actual raw retrieval.

use rusqlite::{params, Connection};

use super::FORK_ADMISSION_FAR1_SQL;
use crate::{fork_replay::NativeReadContextV1, ForkEventAuthorityErrorV1 as Error};

type Result<T> = std::result::Result<T, Error>;

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
    use Error::CorruptAuthority;
    let (probe, fetch, maximum) = kind.queries();
    context.check().map_err(|_| CorruptAuthority)?;
    let mut statement = conn.prepare(probe).map_err(|_| CorruptAuthority)?;
    context.check().map_err(|_| CorruptAuthority)?;
    let mut rows = statement
        .query(params![child_key])
        .map_err(|_| CorruptAuthority)?;
    context.row_available().map_err(|_| CorruptAuthority)?;
    let Some(row) = rows.next().map_err(|_| CorruptAuthority)? else {
        return context.check().map(|()| None).map_err(|_| CorruptAuthority);
    };
    context.suffix_row().map_err(|_| CorruptAuthority)?;
    let blob: bool = row.get(0).map_err(|_| CorruptAuthority)?;
    if !blob {
        return Err(CorruptAuthority);
    }
    let length = row.get::<_, i64>(1).map_err(|_| CorruptAuthority)?;
    let length = usize::try_from(length).map_err(|_| CorruptAuthority)?;
    if length > maximum {
        return Err(CorruptAuthority);
    }
    context.check().map_err(|_| CorruptAuthority)?;
    context.suffix_row().map_err(|_| CorruptAuthority)?;
    context.bytes(length).map_err(|_| CorruptAuthority)?;
    let bytes = conn
        .query_row(fetch, params![child_key], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| CorruptAuthority)?;
    context
        .check()
        .map(|()| Some(bytes))
        .map_err(|_| CorruptAuthority)
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
    use crate::{
        fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World},
        ForkAttributionAuthorityImportPortV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
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
            let world = World::new(Shape::Mixed, false)?;
            let built = world.build(&Spec::default())?;
            let mut store = super::super::SqliteStore::open(":memory:")?;
            world.seed_destination(&mut store)?;
            pin_policy(&mut store, &built.policy)?;
            store.import_verified(&request_for(&world, &built))?;
            let key = world.child_at(0)?.id.to_string();
            for value in [
                rusqlite::types::Value::Blob(vec![0; maximum + 1]),
                rusqlite::types::Value::Text("not-a-blob".into()),
            ] {
                // Stored-state injection isolates the pre-getter raw gate.
                store.conn.execute(sql, [value])?;
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    admission_blob_with_context(
                        &store.conn,
                        kind,
                        &key,
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
