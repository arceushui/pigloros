//! Actual selected EOR1/FIA1 getters and their existing capped decoders.

use pos_core::{EventId, EventOriginRecordV1,
    ForkInterventionAdmissionV1, MAX_EVENT_ORIGIN_RECORD_BYTES_V1,
    MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1};
use rusqlite::Connection;

use super::fork_replay_row::{selected_field_with_context, SelectedRowV1};
use crate::{fork_replay::NativeReadContextV1, ForkEventAuthorityErrorV1 as Error};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
enum ProvenanceRecordV1 {
    Origin,
    Intervention,
}

struct ProvenanceSelectionV1<'key> {
    maximum: usize,
    probe: SelectedRowV1<'key>,
    blob: SelectedRowV1<'key>,
}

impl ProvenanceRecordV1 {
    const fn selection(self, key: &str) -> ProvenanceSelectionV1<'_> {
        match self {
            Self::Origin => ProvenanceSelectionV1 {
                maximum: MAX_EVENT_ORIGIN_RECORD_BYTES_V1,
                probe: SelectedRowV1::EventOriginProbe(key),
                blob: SelectedRowV1::EventOriginBlob(key),
            },
            Self::Intervention => ProvenanceSelectionV1 {
                maximum: MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
                probe: SelectedRowV1::InterventionProbe(key),
                blob: SelectedRowV1::InterventionBlob(key),
            },
        }
    }
}

fn stored_record(
    conn: &Connection,
    event: EventId,
    record: ProvenanceRecordV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<Vec<u8>>> {
    context.bytes(ulid::ULID_LEN).map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            let key = event.to_string();
            let selection = record.selection(&key);
            selected_field_with_context(conn, selection.probe, context, |row, _| {
                // The real scalar boundary row also represents absence; it
                // is charged without inventing a stored provenance row.
                row.get::<_, Option<bool>>(0).map_err(|_| pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
                    .and_then(|blob| blob.map(|blob| {
                        if !blob { return Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate); }
                        row.get::<_, i64>(1).map_err(|_| pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
                            .and_then(|length| usize::try_from(length).ok()
                                .filter(|length| *length <= selection.maximum)
                                .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority))
                    }).transpose())
            })
            .and_then(|probe| probe.ok_or(pos_core::ForkAdmissionErrorV1::StorageIndeterminate))
            .and_then(|length| length.map_or_else(|| Ok(None), |length| {
                context.bytes(length).map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority)
                    .and_then(|()| selected_field_with_context(conn, selection.blob, context, |row, _| {
                        row.get::<_, Vec<u8>>(0).map_err(|_| pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
                    }))
                    .and_then(|bytes| bytes.filter(|bytes| bytes.len() == length)
                        .map(Some).ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority))
            }))
            .map_err(|_| Error::CorruptAuthority)
        })
}

pub(super) fn event_origin_with_context(
    conn: &Connection,
    event: EventId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<EventOriginRecordV1> {
    stored_record(conn, event, ProvenanceRecordV1::Origin, context)
        .and_then(|bytes| bytes.ok_or(Error::CorruptAuthority))
        .and_then(|bytes| {
            // EOR1's borrowed fixed-field decoder owns no nested String/Vec.
            // This separate Vec is its exact canonical equality buffer.
            context.bytes(bytes.len()).map_err(|_| Error::CorruptAuthority)
                .and_then(|()| EventOriginRecordV1::from_canonical_cbor(&bytes)
                    .map_err(|_| Error::CorruptAuthority))
                .and_then(|record| context.check().map(|()| record).map_err(|_| Error::CorruptAuthority))
        })
}

pub(super) fn intervention_with_context(
    conn: &Connection,
    event: EventId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<ForkInterventionAdmissionV1>> {
    stored_record(conn, event, ProvenanceRecordV1::Intervention, context)
        .and_then(|bytes| bytes.map(|bytes| {
            // FIA1 has the same fixed-field decode ownership, with its own
            // native cap and separate canonical equality Vec.
            context.bytes(bytes.len()).map_err(|_| Error::CorruptAuthority)
                .and_then(|()| ForkInterventionAdmissionV1::from_canonical_cbor(&bytes)
                    .map_err(|_| Error::CorruptAuthority))
                .and_then(|record| context.check().map(|()| record).map_err(|_| Error::CorruptAuthority))
        }).transpose())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World},
        fork_event_authority::ValidatedOriginV1,
        ForkAttributionAuthorityImportPortV1, ForkEventProvenanceAuthorityPortV1,
        ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
    use pos_core::{
        store::{EventStore, SeqRange},
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        Event, ForkAppendOperationV1, ForkAttributionImportClosureV1,
        ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1,
    };
    use rusqlite::{params, types::Value};
    use std::time::Duration;

    type Records = (EventOriginRecordV1, Option<ForkInterventionAdmissionV1>);
    type Fixture = (tempfile::TempDir, super::super::SqliteStore, ForkAttributionImportClosureV1);

    fn fixture() -> Fallible<Fixture> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("classified-provenance.sqlite3");
        let mut store = super::super::SqliteStore::open(path.to_str().ok_or("UTF-8 fixture path")?)?;
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        // Public validator (b) accepts the complete signed imported predicate
        // before these selected-owner witnesses. This is not a Replay release.
        assert_eq!(store.read_fork_event_suffix(world.child_at(0)?.id, 1)?.len(), 4);
        Ok((directory, store, closure))
    }

    fn origin(closure: &ForkAttributionImportClosureV1) -> ValidatedOriginV1 {
        ValidatedOriginV1::Imported(closure.fork_admission().authority_origin_digest())
    }

    fn raw_event_cost(event: &Event) -> usize {
        // Independent public-value inventory of actual String/Vec getters,
        // not the production probe lengths, Rust layout, or capacity.
        event.id.to_string().len() + event.entity.to_string().len()
            + event.event_type.as_str().len() + event.payload.len()
            + event.causation_id.map_or(0, |id| id.to_string().len())
            + event.correlation_id.map_or(0, |id| id.to_string().len())
            + event.payload_hash.as_bytes().len()
            + event.signature.map_or(0, |_| 64)
            + event.signature_identity.map_or(0, |identity| identity.owner_id.as_str().len())
            + event.origin.map_or(0, |value| value.origin_timeline_id.to_string().len())
    }

    fn expected_cost(
        store: &super::super::SqliteStore,
        closure: &ForkAttributionImportClosureV1,
        operation: &ForkAppendOperationV1,
    ) -> Fallible<(usize, usize, Records)> {
        let graph = closure.classifier().ok_or("classifier fixture")?;
        let event = store.read_own(operation.input().child_timeline_id, SeqRange::all())?
            .into_iter().find(|event| event.id == operation.input().event_id).ok_or("fixture Event")?;
        let record = closure.event_origins().iter()
            .find(|record| record.input().event_id == event.id).ok_or("fixture EOR1")?.clone();
        let intervention = closure.intervention_admissions().iter()
            .find(|record| record.input().event_id == event.id).cloned();
        // Four independently allocated ULID query Strings; raw plus native
        // comparison plus digest Vec for each present EOR1/FIA1; one table
        // digest Vec and the classifier's actual retained route copies.
        let bytes = 4 * event.id.to_string().len() + raw_event_cost(&event)
            + 3 * record.to_canonical_cbor().len()
            + intervention.as_ref().map_or(0, |record| 3 * record.to_canonical_cbor().len())
            + graph.table.to_canonical_cbor().len()
            + graph.table.input().routes.iter().map(|route| {
                route.source().route().len() + route.source().schema_digest().as_bytes().len() + 1
            }).sum::<usize>();
        // Prefix row + exact Event probe/raw + EOR1 probe/raw + FIA1 probe;
        // only a present FIA1 adds its own raw row.
        Ok((bytes, 6 + usize::from(intervention.is_some()), (record, intervention)))
    }

    fn validate(
        store: &super::super::SqliteStore,
        closure: &ForkAttributionImportClosureV1,
        operation: &ForkAppendOperationV1,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Fallible<Result<Records>> {
        Ok(super::super::sqlite_validate_classified_records_with_context(
            &store.conn, operation, &closure.classifier().ok_or("fixture classifier")?.table,
            origin(closure), context,
        ))
    }

    #[test]
    fn complete_imported_predicate_classified_records_have_exact_actual_byte_prefixes() -> Fallible<()> {
        let (_directory, store, closure) = fixture()?;
        let interval = store.begin_protected_effect_interval()?;
        for operation in closure.append_operations() {
            let (bytes, rows, expected) = expected_cost(&store, &closure, operation)?;
            for limit in 1..=bytes {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, rows, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = validate(&store, &closure, operation, &mut NativeReadContextV1::protected(&mut budget))?;
                if limit == bytes {
                    assert_eq!(result?, expected);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                    assert!(budget.check_time().is_ok());
                } else {
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
                assert!(!store.conn.is_autocommit());
            }
        }
        store.finish_protected_effect_interval(interval, ErasureProtectedEffectDispositionV1::Rollback)?;
        Ok(())
    }

    #[test]
    fn real_classified_rows_absence_probes_and_repeated_prefix_visits_share_one_ledger() -> Fallible<()> {
        let (_directory, store, closure) = fixture()?;
        for operation in closure.append_operations() {
            let (bytes, rows, expected) = expected_cost(&store, &closure, operation)?;
            for (visits, row_limit, byte_limit, repeats, success) in [
                (1, rows, bytes, 1, true),
                (1, rows - 1, bytes, 1, false),
                (1, rows, bytes - 1, 1, false),
                (2, rows * 2, bytes * 2, 2, true),
                (1, rows * 2, bytes * 2, 2, false),
                (2, rows * 2 - 1, bytes * 2, 2, false),
                (2, rows * 2, bytes * 2 - 1, 2, false),
            ] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, visits, row_limit, byte_limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result: Fallible<()> = (0..repeats).try_for_each(|_| {
                    let actual = validate(&store, &closure, operation, &mut NativeReadContextV1::protected(&mut budget))??;
                    assert_eq!(actual, expected);
                    Ok(())
                });
                assert_eq!(result.is_ok(), success);
                assert_eq!(budget.check_time().is_ok(), success);
                if success { assert_eq!(budget.remaining_native_bytes(), 0); }
            }
        }
        Ok(())
    }

    #[test]
    fn classified_exact_lookup_preserves_narrow_metadata_and_event_selection() -> Fallible<()> {
        let (_directory, store, closure) = fixture()?;
        let operation = closure.append_operations().get(1).ok_or("second operation")?;
        let expected = super::super::sqlite_classified_event(&store.conn, operation)?;
        // This existing lookup reads fork_seq, not ancestry/name/head, and only
        // this exact Event. These impossible-state faults belong to broader
        // graph validation, which is deliberately not claimed by this witness.
        store.conn.execute("UPDATE timelines SET head_seq = -1, parent_id = 'bad', name = x'ff' WHERE id = ?1",
            [operation.input().child_timeline_id.to_string()])?;
        store.conn.execute("UPDATE events SET wall_time = -1 WHERE timeline_id = ?1 AND seq != 2",
            [operation.input().child_timeline_id.to_string()])?;
        assert_eq!(super::super::sqlite_classified_event(&store.conn, operation)?, expected);
        let bytes = 2 * ulid::ULID_LEN + raw_event_cost(&expected);
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 3, bytes, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let actual = super::super::fork_replay_event::classified_event_with_context(
            &store.conn, operation, &mut NativeReadContextV1::protected(&mut budget))?;
        assert_eq!(actual.event(), &expected);
        assert_eq!(budget.remaining_native_bytes(), 0);
        Ok(())
    }

    #[test]
    fn selected_provenance_type_cap_and_native_tamper_failures_stay_closed() -> Fallible<()> {
        for (table, column, value) in [
            ("fork_event_origins", "eor1_cbor", Value::Text("not a blob".to_owned())),
            ("fork_event_origins", "eor1_cbor", Value::Blob(vec![0; MAX_EVENT_ORIGIN_RECORD_BYTES_V1 + 1])),
            ("fork_event_origins", "eor1_cbor", Value::Blob(vec![0xf6])),
            ("fork_intervention_admissions", "fia1_cbor", Value::Text("not a blob".to_owned())),
            ("fork_intervention_admissions", "fia1_cbor", Value::Blob(vec![0; MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1 + 1])),
            ("fork_intervention_admissions", "fia1_cbor", Value::Blob(vec![0xf6])),
        ] {
            let (_directory, store, closure) = fixture()?;
            let operation = closure.append_operations().get(2).ok_or("intervention operation")?;
            store.conn.execute(&format!("UPDATE {table} SET {column} = ?1 WHERE event_id = ?2"),
                params![value, operation.input().event_id.to_string()])?;
            assert_eq!(validate(&store, &closure, operation, &mut NativeReadContextV1::ordinary())?, Err(Error::CorruptAuthority));
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 16, 16_384, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(validate(&store, &closure, operation, &mut NativeReadContextV1::protected(&mut budget))?, Err(Error::CorruptAuthority));
        }
        Ok(())
    }

    #[test]
    fn missing_and_mismatched_classified_bindings_preserve_ordinary_rejection() -> Fallible<()> {
        let (_directory, store, closure) = fixture()?;
        let operation = closure.append_operations().get(2).ok_or("intervention operation")?;
        let key = operation.input().child_timeline_id.to_string();
        for mutation in [
            "UPDATE timelines SET fork_seq = -1 WHERE id = ?1",
            "UPDATE timelines SET fork_seq = 100 WHERE id = ?1",
            "UPDATE events SET origin_logical_seq = 100 WHERE timeline_id = ?1 AND seq = 3",
            "UPDATE events SET event_id = '00000000000000000000000000' WHERE timeline_id = ?1 AND seq = 3",
            "DELETE FROM events WHERE timeline_id = ?1 AND seq = 3",
            "DELETE FROM timelines WHERE id = ?1",
        ] {
            store.conn.execute_batch("SAVEPOINT classified_fault")?;
            store.conn.execute(mutation, [&key])?;
            assert!(super::super::sqlite_classified_event(&store.conn, operation).is_err());
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 16, 16_384, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(super::super::fork_replay_event::classified_event_with_context(
                &store.conn, operation, &mut NativeReadContextV1::protected(&mut budget)).err(), Some(Error::CorruptAuthority));
            store.conn.execute_batch("ROLLBACK TO classified_fault; RELEASE classified_fault")?;
        }
        Ok(())
    }

    #[test]
    fn original_guard_expiry_and_regression_cover_classified_fetch_decode_and_digest_batches() -> Fallible<()> {
        let (_directory, store, closure) = fixture()?;
        let operation = closure.append_operations().get(2).ok_or("intervention operation")?;
        let (bytes, rows, expected) = expected_cost(&store, &closure, operation)?;
        for regression in [false, true] {
            let mut failures = 0;
            let mut successes = 0;
            for boundary in 2..=256 {
                let initial = if regression { Duration::from_micros(1) } else { Duration::ZERO };
                let later = if regression { Duration::ZERO } else { Duration::from_micros(11) };
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(initial, boundary).chain([later]));
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, rows, bytes, 10)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = validate(&store, &closure, operation, &mut NativeReadContextV1::protected(&mut budget))?;
                if let Ok(records) = result {
                    assert_eq!(records, expected);
                    successes += 1;
                } else {
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                    failures += 1;
                }
            }
            assert!(failures > 0);
            assert!(successes > 0);
        }
        Ok(())
    }

    #[test]
    fn selected_provenance_absence_and_valid_native_mismatches_preserve_rejection() -> Fallible<()> {
        let (_directory, store, closure) = fixture()?;
        let operation = closure.append_operations().get(2).ok_or("intervention operation")?;
        let (_, _, (record, intervention)) = expected_cost(&store, &closure, operation)?;
        let mut origin_input = record.input().clone();
        origin_input.classifier_revision_digest = pos_core::Hash::from_bytes([222; 32]);
        let bad_origin = EventOriginRecordV1::new(origin_input)?.to_canonical_cbor();
        let mut intervention_input = intervention.ok_or("fixture FIA1")?.input().clone();
        intervention_input.payload_hash = pos_core::Hash::from_bytes([223; 32]);
        let bad_intervention = ForkInterventionAdmissionV1::new(intervention_input)?.to_canonical_cbor();
        for (sql, value) in [
            ("DELETE FROM fork_event_origins WHERE event_id = ?2 AND ?1 IS NULL", Value::Null),
            ("DELETE FROM fork_intervention_admissions WHERE event_id = ?2 AND ?1 IS NULL", Value::Null),
            ("UPDATE fork_event_origins SET eor1_cbor = ?1 WHERE event_id = ?2", Value::Blob(bad_origin)),
            ("UPDATE fork_intervention_admissions SET fia1_cbor = ?1 WHERE event_id = ?2", Value::Blob(bad_intervention)),
        ] {
            store.conn.execute_batch("SAVEPOINT provenance_fault")?;
            store.conn.execute(sql, params![value, operation.input().event_id.to_string()])?;
            assert_eq!(validate(&store, &closure, operation, &mut NativeReadContextV1::ordinary())?, Err(Error::CorruptAuthority));
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 16, 16_384, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(validate(&store, &closure, operation, &mut NativeReadContextV1::protected(&mut budget))?, Err(Error::CorruptAuthority));
            store.conn.execute_batch("ROLLBACK TO provenance_fault; RELEASE provenance_fault")?;
        }
        Ok(())
    }

    #[test]
    fn maximum_classifier_reconstruction_charges_actual_routes_without_a_registrar_clone() -> Fallible<()> {
        let (_directory, _store, closure) = fixture()?;
        for count in [0, 2, pos_core::MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1] {
            let mut input = closure.classifier().ok_or("fixture classifier")?.table.input().clone();
            input.registrar_identifier = "é".repeat(32);
            input.routes = (0..count).map(|index| {
                Ok(pos_core::ForkExternalInputRouteV1::new(
                    pos_core::ForkEventSourceDescriptorV1::new(
                        format!("{index:04}{}", "é".repeat(62)), pos_core::Hash::from_bytes([7; 32]),
                    )?, index % 2 == 0,
                ))
            }).collect::<Fallible<Vec<_>>>()?;
            let table = pos_core::ForkClassifierTableV1::new(input)?;
            let expected = pos_core::ForkEventClassifierV1::from_table(&table);
            let bytes = table.to_canonical_cbor().len()
                + table.input().routes.iter().map(|route| {
                    route.source().route().len() + route.source().schema_digest().as_bytes().len() + 1
                }).sum::<usize>();
            for (limit, repeats, success) in [(bytes - 1, 1, false), (bytes, 1, true),
                (bytes * 2 - 1, 2, false), (bytes * 2, 2, true)] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = (0..repeats).try_for_each(|_| {
                    NativeReadContextV1::protected(&mut budget).classifier_from_table(&table)
                        .map(|classifier| assert_eq!(classifier, expected))
                });
                assert_eq!(result.is_ok(), success);
                assert_eq!(budget.check_time().is_ok(), success);
                if success { assert_eq!(budget.remaining_native_bytes(), 0); }
            }
        }
        Ok(())
    }
}
