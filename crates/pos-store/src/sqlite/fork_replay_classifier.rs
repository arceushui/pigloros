//! Closed selected classifier queries on the held native read snapshot.

use pos_core::{ForkClassifierRegistrationV1, ForkClassifierSourceV1, ForkClassifierTableV1, Hash, TimelineId};
use rusqlite::{Connection, ToSql};

use crate::{fork_replay::NativeReadContextV1, ForkEventAuthorityErrorV1 as Error};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub(super) enum ClassifierKeyV1<'a> {
    Table(TimelineId),
    Registration(TimelineId),
    LocalSource { descriptor: Hash, registrar: &'a str },
    ImportedSource(Hash),
}

fn raw_classifier_blob(
    conn: &Connection, probe: &str, fetch: &str, maximum: usize,
    arguments: &[&dyn ToSql], context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<Vec<u8>>> {
    use Error::CorruptAuthority;
    context.check().map_err(|_| CorruptAuthority)?;
    let mut statement = conn.prepare(probe).map_err(|_| CorruptAuthority)?;
    context.check().map_err(|_| CorruptAuthority)?;
    let mut rows = statement.query(arguments).map_err(|_| CorruptAuthority)?;
    context.row_available().map_err(|_| CorruptAuthority)?;
    let Some(row) = rows.next().map_err(|_| CorruptAuthority)? else {
        return context.check().map(|()| None).map_err(|_| CorruptAuthority);
    };
    context.suffix_row().map_err(|_| CorruptAuthority)?;
    let blob: bool = row.get(0).map_err(|_| CorruptAuthority)?;
    if !blob { return Err(CorruptAuthority); }
    let length = row.get::<_, i64>(1).map_err(|_| CorruptAuthority)?;
    let length = usize::try_from(length).map_err(|_| CorruptAuthority)?;
    if length > maximum { return Err(CorruptAuthority); }
    context.check().map_err(|_| CorruptAuthority)?;
    context.suffix_row().map_err(|_| CorruptAuthority)?;
    context.bytes(length).map_err(|_| CorruptAuthority)?;
    let bytes = conn.query_row(fetch, arguments, |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| CorruptAuthority)?;
    context.check().map(|()| Some(bytes)).map_err(|_| CorruptAuthority)
}

pub(super) fn classifier_blob_with_context(
    conn: &Connection, key: ClassifierKeyV1<'_>, context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<Vec<u8>>> {
    let maximum = pos_core::MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1;
    match key {
        ClassifierKeyV1::Table(child) | ClassifierKeyV1::Registration(child) => {
            context.bytes(ulid::ULID_LEN).map_err(|_| Error::CorruptAuthority)?;
            let child_key = child.to_string();
            let (probe, fetch, cap) = if matches!(key, ClassifierKeyV1::Table(_)) {
                ("SELECT typeof(fct1_cbor) = 'blob', length(fct1_cbor) FROM fork_classifier_tables WHERE child_id = ?1",
                 "SELECT fct1_cbor FROM fork_classifier_tables WHERE child_id = ?1", maximum)
            } else {
                ("SELECT typeof(fcr1_cbor) = 'blob', length(fcr1_cbor) FROM fork_classifier_registrations WHERE child_id = ?1",
                 super::FORK_CLASSIFIER_REGISTRATION_SQL, pos_core::MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1)
            };
            raw_classifier_blob(conn, probe, fetch, cap, &[&child_key], context)
        }
        ClassifierKeyV1::LocalSource { descriptor, registrar } => raw_classifier_blob(conn,
            "SELECT typeof(fcs1_cbor) = 'blob', length(fcs1_cbor) FROM fork_classifier_sources WHERE descriptor_hash = ?1 AND registrar_identifier = ?2",
            "SELECT fcs1_cbor FROM fork_classifier_sources WHERE descriptor_hash = ?1 AND registrar_identifier = ?2",
            maximum, &[&descriptor.as_bytes().as_slice(), &registrar], context),
        ClassifierKeyV1::ImportedSource(digest) => raw_classifier_blob(conn,
            "SELECT typeof(fcs1_cbor) = 'blob', length(fcs1_cbor) FROM imported_fork_classifier_sources WHERE fcs1_digest = ?1",
            "SELECT fcs1_cbor FROM imported_fork_classifier_sources WHERE fcs1_digest = ?1",
            maximum, &[&digest.as_bytes().as_slice()], context),
    }
}

pub(super) fn classifier_table_with_context(conn: &Connection, child: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>) -> Result<ForkClassifierTableV1> {
    let bytes = classifier_blob_with_context(conn, ClassifierKeyV1::Table(child), context)?
        .ok_or(Error::CorruptAuthority)?;
    context.classifier_table(&bytes).map_err(|_| Error::CorruptAuthority)
}

pub(super) fn classifier_registration_with_context(conn: &Connection, child: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>) -> Result<ForkClassifierRegistrationV1> {
    let bytes = classifier_blob_with_context(conn, ClassifierKeyV1::Registration(child), context)?
        .ok_or(Error::CorruptAuthority)?;
    context.classifier_registration(&bytes).map_err(|_| Error::CorruptAuthority)
}

pub(super) fn classifier_source_with_context(conn: &Connection, key: ClassifierKeyV1<'_>,
    context: &mut NativeReadContextV1<'_, '_>) -> Result<ForkClassifierSourceV1> {
    let bytes = classifier_blob_with_context(conn, key, context)?.ok_or(Error::CorruptAuthority)?;
    context.classifier_source(&bytes).map_err(|_| Error::CorruptAuthority)
}

/// Native encoders and logical fields only, independent of production gates.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn imported_classifier_phase_cost(records: Option<&pos_core::ForkAttributionClassifierRecordsV1>)
    -> std::result::Result<usize, Box<dyn std::error::Error>> {
    let Some(records) = records else { return Ok(ulid::ULID_LEN); };
    let source = ForkClassifierSourceV1::from_canonical_cbor(&records.source)?;
    let table = ForkClassifierTableV1::from_canonical_cbor(&records.table)?;
    let registration = ForkClassifierRegistrationV1::from_canonical_cbor(&records.registration)?;
    let source_fields = source.input().registrar_identifier.len() + source.input().routes.iter()
        .map(|route| route.source().route().len() + 32 + 1).sum::<usize>();
    let table_fields = table.input().registrar_identifier.len() + table.input().routes.iter()
        .map(|route| route.source().route().len() + 32 + 1).sum::<usize>();
    Ok(ulid::ULID_LEN * 2 + source.to_canonical_cbor().len() * 3 + table.to_canonical_cbor().len() * 3
        + registration.to_canonical_cbor().len() * 2 + source_fields + table_fields)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World},
        ForkAttributionAuthorityImportPortV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use std::time::Duration;

    #[test]
    fn classifier_type_and_cap_probes_refuse_before_raw_getters() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = super::super::SqliteStore::open(":memory:")?;
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        let child = world.child_at(0)?.id;
        let records = built.envelope.unsigned().input().classifier.as_ref().ok_or("classifier fixture")?;
        let source = ForkClassifierSourceV1::from_canonical_cbor(&records.source)?;
        store.conn.execute("INSERT INTO fork_classifier_sources (descriptor_hash, registrar_identifier, fcs1_cbor) VALUES (?1, ?2, ?3)",
            rusqlite::params![source.input().room_revision_descriptor_hash.as_bytes().as_slice(), source.input().registrar_identifier, records.source])?;
        for (key, sql, maximum) in [
            (ClassifierKeyV1::Table(child), "UPDATE fork_classifier_tables SET fct1_cbor = ?1", pos_core::MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1),
            (ClassifierKeyV1::Registration(child), "UPDATE fork_classifier_registrations SET fcr1_cbor = ?1", pos_core::MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1),
            (ClassifierKeyV1::ImportedSource(source.digest()), "UPDATE imported_fork_classifier_sources SET fcs1_cbor = ?1", pos_core::MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1),
            (ClassifierKeyV1::LocalSource { descriptor: source.input().room_revision_descriptor_hash, registrar: &source.input().registrar_identifier },
                "UPDATE fork_classifier_sources SET fcs1_cbor = ?1", pos_core::MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1),
        ] {
            for value in [rusqlite::types::Value::Blob(vec![0_u8; maximum + 1]), rusqlite::types::Value::Text("not-a-blob".into())] {
                // Narrow impossible stored-state injection isolates the raw gate.
                assert_eq!(store.conn.execute(sql, [value])?, 1);
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 2, 64, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(classifier_blob_with_context(&store.conn, key, &mut NativeReadContextV1::protected(&mut budget)), Err(Error::CorruptAuthority));
                let key_bytes = if matches!(key, ClassifierKeyV1::Table(_) | ClassifierKeyV1::Registration(_)) { ulid::ULID_LEN } else { 0 };
                assert_eq!(budget.remaining_native_bytes(), 64 - key_bytes);
                assert!(budget.check_time().is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn absent_classifier_keys_have_no_row_or_blob_unit() -> Fallible<()> {
        let store = super::super::SqliteStore::open(":memory:")?;
        let child = TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16]));
        for key in [ClassifierKeyV1::Table(child), ClassifierKeyV1::Registration(child),
            ClassifierKeyV1::ImportedSource(Hash::from_bytes([1; 32])),
            ClassifierKeyV1::LocalSource { descriptor: Hash::from_bytes([1; 32]), registrar: "absent" }] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(classifier_blob_with_context(&store.conn, key, &mut NativeReadContextV1::protected(&mut budget))?, None);
            let key_bytes = if matches!(key, ClassifierKeyV1::Table(_) | ClassifierKeyV1::Registration(_)) { ulid::ULID_LEN } else { 0 };
            assert_eq!(budget.remaining_native_bytes(), 64 - key_bytes);
            budget.charge_rows(1)?;
        }
        Ok(())
    }
}
