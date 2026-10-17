//! Actual indexed suffix probes, FOP decode and retained native result fields.

use pos_core::{
    EventOriginRecordV1, ForkAppendOperationV1, ForkInterventionAdmissionV1, TimelineId,
    MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
};
use rusqlite::{Connection, Row};

use super::{
    fork_replay_event::origin_prefix_with_context,
    fork_replay_orphans::reject_orphans_with_context,
    fork_replay_row::{selected_field_with_context, SelectedRowV1},
    ForkEventSuffixV1, SqliteStore,
};
use crate::{
    fork_event_authority::AuthorityValidatorV1, fork_replay::NativeReadContextV1,
    ForkEventAuthorityErrorV1 as Error,
};

type Result<T> = std::result::Result<T, Error>;

macro_rules! suffix_probe_sql {
    ($range:literal) => { concat!("SELECT probe.* FROM (SELECT 1) AS boundary LEFT JOIN (
        SELECT events.rowid, typeof(events.seq) = 'integer', events.seq,
            typeof(events.event_id) = 'text', length(CAST(events.event_id AS BLOB)),
            fork_append_operations.rowid, typeof(fop1_cbor) IN ('null', 'blob'), length(fop1_cbor)
        FROM events LEFT JOIN fork_append_operations ON
            fork_append_operations.child_id = events.timeline_id
            AND fork_append_operations.event_id = events.event_id
        WHERE events.timeline_id = ?1", $range,
        " ORDER BY events.seq LIMIT 1) AS probe ON 1 = 1") };
}

pub(super) const FIRST_SUFFIX: &str = suffix_probe_sql!("");
pub(super) const AFTER_SUFFIX: &str = suffix_probe_sql!(" AND events.seq > ?2");
pub(super) const SUFFIX_FIELDS: &str = "SELECT events.event_id, events.seq, fork_append_operations.fop1_cbor
    FROM events LEFT JOIN fork_append_operations ON fork_append_operations.child_id = events.timeline_id
        AND fork_append_operations.event_id = events.event_id
    WHERE events.timeline_id = ?1 AND events.seq = ?2";

struct SuffixProbeV1 {
    seq: i64,
    fop_bytes: Option<usize>,
    has_fop: bool,
}

impl SuffixProbeV1 {
    fn read(
        row: &Row<'_>,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> std::result::Result<Option<Self>, pos_core::ForkAdmissionErrorV1> {
        use pos_core::ForkAdmissionErrorV1::CorruptAuthority;
        row.get::<_, Option<i64>>(0)
            .map_err(|_| CorruptAuthority)
            .and_then(|marker| {
                marker
                    .map(|_| {
                        row.get::<_, Option<i64>>(5)
                            .map_err(|_| CorruptAuthority)
                            .and_then(|fop| {
                                let count = if fop.is_some() {
                                    context.suffix_row().map_err(|_| CorruptAuthority)
                                } else {
                                    Ok(())
                                };
                                count.and_then(|()| {
                                    let integer: bool = row.get(1).map_err(|_| CorruptAuthority)?;
                                    let text: bool = row.get(3).map_err(|_| CorruptAuthority)?;
                                    let event_length: i64 =
                                        row.get(4).map_err(|_| CorruptAuthority)?;
                                    let blob_or_null: bool =
                                        row.get(6).map_err(|_| CorruptAuthority)?;
                                    if !integer
                                        || !text
                                        || usize::try_from(event_length).ok()
                                            != Some(ulid::ULID_LEN)
                                        || !blob_or_null
                                    {
                                        return Err(CorruptAuthority);
                                    }
                                    let length: Option<i64> =
                                        row.get(7).map_err(|_| CorruptAuthority)?;
                                    let length = length
                                        .map(|length| {
                                            usize::try_from(length)
                                                .ok()
                                                .filter(|length| {
                                                    *length
                                                        <= MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1
                                                })
                                                .ok_or(CorruptAuthority)
                                        })
                                        .transpose()?;
                                    row.get(2)
                                        .map(|seq| Self {
                                            seq,
                                            fop_bytes: length,
                                            has_fop: fop.is_some(),
                                        })
                                        .map_err(|_| CorruptAuthority)
                                })
                            })
                    })
                    .transpose()
            })
    }
}

fn next_row(
    conn: &Connection,
    key: &str,
    after: Option<i64>,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<(i64, super::SqliteForkSuffixRowV1)>> {
    selected_field_with_context(conn, SelectedRowV1::SuffixProbe(key, after), context, SuffixProbeV1::read)
        .and_then(|probe| probe.ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority))
        .and_then(|probe| probe.map(|probe| {
            context.require_bytes(probe.fop_bytes.unwrap_or(0).checked_add(ulid::ULID_LEN))
                .map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority)
                .and_then(|()| selected_field_with_context(conn, SelectedRowV1::SuffixFields(key, probe.seq), context, |row, context| {
                    let fop_visit = if probe.has_fop { context.suffix_row() } else { Ok(()) };
                    fop_visit.and_then(|()| context.bytes(ulid::ULID_LEN))
                        .map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority)
                        .and_then(|()| row.get::<_, String>(0).map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority))
                        .and_then(|id| row.get::<_, i64>(1).map(|seq| (id, seq)).map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority))
                        .and_then(|(id, seq)| context.bytes(probe.fop_bytes.unwrap_or(0)).map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority)
                            .and_then(|()| row.get::<_, Option<Vec<u8>>>(2).map(|bytes| (id, seq, bytes)).map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority)))
                }))
                .and_then(|row| row.ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority))
                .map(|row| (probe.seq, row))
        }).transpose())
        .map_err(|_| Error::CorruptAuthority)
}

fn retain(
    result: &mut ForkEventSuffixV1,
    records: (
        EventOriginRecordV1,
        Option<ForkInterventionAdmissionV1>,
        ForkAppendOperationV1,
    ),
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<()> {
    // Logical native fields actually retained in the result collection, not
    // Rust layout/capacity or an invented encoding. String backing buffers
    // transfer ownership without being cloned and are not charged again.
    let (_, intervention, operation) = &records;
    let mut bytes = 16 + 8 + 16 + 1 + 1 + 32 + 32; // EOR1
    if intervention.is_some() {
        bytes += 32 + 16 + 8 + 16 + 32 * 4;
    }
    let input = operation.input();
    bytes += 32 * 6 + 16 * 2 + 8 * 2 + 1; // FOP1 fixed fields and source code
    if input.intervention_admission_digest.is_some() {
        bytes += 32;
    }
    if let pos_core::ForkAppendSourceIdentityV1::ExternalInput { .. } = &input.source {
        bytes += 32;
    }
    context
        .bytes(bytes)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            result.push(records);
            context.check().map_err(|_| Error::CorruptAuthority)
        })
}

pub(super) fn read_suffix_with_context(
    store: &SqliteStore,
    child: TimelineId,
    from: u64,
    validator: AuthorityValidatorV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ForkEventSuffixV1> {
    origin_prefix_with_context(&store.conn, child, context)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|prefix| {
            reject_orphans_with_context(&store.conn, child, context).map(|()| prefix)
        })
        .and_then(|prefix| {
            let graph = super::sqlite_validated_graph(
                &store.conn,
                store.hasher.as_ref(),
                child,
                validator,
                context,
            );
            let scope = SuffixReadV1 {
                store,
                child,
                from,
                prefix,
                graph,
            };
            context
                .bytes(ulid::ULID_LEN)
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| {
                    let key = child.to_string();
                    let mut after = None;
                    let mut result = Vec::new();
                    loop {
                        let row = match next_row(&store.conn, &key, after, context) {
                            Ok(Some((seq, row))) => {
                                after = Some(seq);
                                row
                            }
                            Ok(None) => {
                                return context
                                    .check()
                                    .map(|()| result)
                                    .map_err(|_| Error::CorruptAuthority)
                            }
                            Err(error) => return Err(error),
                        };
                        let decoded = scope.validate_row(row, &mut result, context);
                        decoded
                            .and_then(|()| context.check().map_err(|_| Error::CorruptAuthority))?;
                    }
                })
        })
}

struct SuffixReadV1<'store> {
    store: &'store SqliteStore,
    child: TimelineId,
    from: u64,
    prefix: u64,
    graph: Result<crate::fork_event_authority::ValidatedGraphV1>,
}

impl SuffixReadV1<'_> {
    fn validate_row(
        &self,
        row: super::SqliteForkSuffixRowV1,
        result: &mut ForkEventSuffixV1,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Result<()> {
        super::sqlite_decode_fork_suffix_row_with_context(self.prefix, row, context)
            .ok_or(Error::CorruptAuthority)
            .and_then(|(event, logical, operation)| {
                self.graph
                    .as_ref()
                    .map_err(|error| *error)
                    .map(|graph| (event, logical, operation, graph))
            })
            .and_then(|(event, logical, operation, graph)| {
                if operation.input().child_timeline_id != self.child
                    || operation.input().fork_admission_digest != graph.admission.digest()
                {
                    return Err(Error::CorruptAuthority);
                }
                context
                    .canonical(graph.table.canonical_cbor_len())
                    .map_err(|_| Error::CorruptAuthority)
                    .and_then(|()| {
                        let digest = graph.table.digest();
                        context
                            .check()
                            .map_err(|_| Error::CorruptAuthority)
                            .and_then(|()| {
                                if operation.input().classifier_revision_digest != digest
                                    || operation.input().event_id != event
                                    || operation.input().logical_seq != logical
                                {
                                    return Err(Error::CorruptAuthority);
                                }
                                if logical < self.from {
                                    return Ok(());
                                }
                                super::sqlite_validate_classified_records_with_context(
                                    &self.store.conn,
                                    &operation,
                                    &graph.table,
                                    graph.admission.origin(),
                                    context,
                                )
                                .and_then(
                                    |(origin, intervention)| {
                                        retain(result, (origin, intervention, operation), context)
                                    },
                                )
                            })
                    })
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{pin_policy, request_for, Built, Fallible, Shape, Spec, World},
        ForkAttributionAuthorityImportPortV1, ForkEventProvenanceAuthorityPortV1,
        ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
    use pos_core::{
        store::{EventStore, SeqRange},
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1,
        ForkAppendSourceIdentityV1, ForkAttributionImportClosureV1,
    };
    use rusqlite::{params, types::Value};
    use std::time::Duration;

    fn fixture(shape: Shape) -> Fallible<(tempfile::TempDir, SqliteStore, World, Built)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("actual-suffix.sqlite3");
        let mut store = SqliteStore::open(path.to_str().ok_or("fixture path")?)?;
        let world = World::new(shape, false)?;
        let built = world.build(&Spec::default())?;
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        assert_eq!(
            u64::try_from(
                store
                    .read_fork_event_suffix(world.child_at(0)?.id, 1)?
                    .len()
            )?,
            shape.events()
        );
        Ok((directory, store, world, built))
    }

    fn event_cost(event: &pos_core::Event) -> usize {
        event.id.to_string().len()
            + event.entity.to_string().len()
            + event.event_type.as_str().len()
            + event.payload.len()
            + event.causation_id.map_or(0, |id| id.to_string().len())
            + event.correlation_id.map_or(0, |id| id.to_string().len())
            + event.payload_hash.as_bytes().len()
            + event.signature.map_or(0, |_| 64)
            + event
                .signature_identity
                .map_or(0, |identity| identity.owner_id.as_str().len())
            + event
                .origin
                .map_or(0, |origin| origin.origin_timeline_id.to_string().len())
    }

    fn costs(store: &SqliteStore, built: &Built, from: u64) -> Fallible<(usize, usize, usize)> {
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let child = closure.fork_admission().fields().child_timeline_id;
        let import: Vec<u8> = store.conn.query_row(
            "SELECT ifa1_cbor FROM imported_fork_attribution_admissions WHERE child_id = ?1",
            [child.to_string()],
            |row| row.get(0),
        )?;
        let mut bytes = 5 * child.to_string().len()
            + super::super::fork_replay_admission::imported_admission_phase_cost(
                &built.envelope.unsigned().input().records.fork_admission,
                &import,
            )?
            + super::super::fork_replay_classifier::imported_classifier_phase_cost(
                built.envelope.unsigned().input().classifier.as_ref(),
            )?;
        let count = closure.append_operations().len();
        let interventions = closure.intervention_admissions().len();
        let mut rows = 1 + 4 * count + 2 * interventions + 3 + 4 * count + 1;
        // Imported graph has six admission rows and, when present, six
        // classifier rows. Missing classifier retrieval adds no stored row.
        rows += if closure.classifier().is_some() {
            12
        } else {
            6
        };
        let mut visits = 1;
        let own = store.read_own(child, SeqRange::all())?;
        if let Some(graph) = closure.classifier() {
            let table = graph.table.to_canonical_cbor().len();
            let route_copies: usize = graph
                .table
                .input()
                .routes
                .iter()
                .map(|route| route.source().route().len() + 32 + 1)
                .sum();
            for operation in closure.append_operations() {
                let source_strings = match &operation.input().source {
                    ForkAppendSourceIdentityV1::HostInternal => 0,
                    ForkAppendSourceIdentityV1::ExternalInput {
                        adapter_identifier,
                        source,
                    } => adapter_identifier.len() + source.route().len(),
                };
                bytes += operation.input().event_id.to_string().len()
                    + 2 * operation.to_canonical_cbor().len()
                    + source_strings
                    + table;
                if operation.input().logical_seq < from {
                    continue;
                }
                let event = own
                    .iter()
                    .find(|event| event.id == operation.input().event_id)
                    .ok_or("fixture Event")?;
                let origin = closure
                    .event_origins()
                    .iter()
                    .find(|record| record.input().event_id == event.id)
                    .ok_or("fixture EOR1")?;
                let intervention = closure
                    .intervention_admissions()
                    .iter()
                    .find(|record| record.input().event_id == event.id);
                bytes += 4 * event.id.to_string().len()
                    + event_cost(event)
                    + 3 * origin.to_canonical_cbor().len()
                    + intervention.map_or(0, |record| 3 * record.to_canonical_cbor().len())
                    + table
                    + route_copies;
                // Independently enumerate the logical fixed fields moved
                // into the result, not the production retain helper or layout.
                bytes += 16 + 8 + 16 + 2 + 32 + 32;
                if intervention.is_some() {
                    bytes += 32 + 16 + 8 + 16 + 32 + 32 + 32 + 32;
                }
                bytes += 32 + 16 + 8 + 16 + 32 + 8 + 32 + 32 + 32 + 32 + 1;
                if operation.input().intervention_admission_digest.is_some() {
                    bytes += 32;
                }
                if let ForkAppendSourceIdentityV1::ExternalInput { source, .. } =
                    &operation.input().source
                {
                    bytes += source.schema_digest().as_bytes().len();
                }
                rows += 6 + usize::from(intervention.is_some());
                visits += 1;
            }
        }
        Ok((bytes, rows, visits))
    }

    fn read(
        store: &SqliteStore,
        child: TimelineId,
        from: u64,
        rows: usize,
        visits: usize,
        bytes: usize,
    ) -> Fallible<(Result<ForkEventSuffixV1>, usize, bool)> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, visits, rows, bytes, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = store.read_fork_event_suffix_in_transaction_with_context(
            child,
            from,
            AuthorityValidatorV1::CodeTwoAware,
            &mut NativeReadContextV1::protected(&mut budget),
        );
        Ok((
            result,
            budget.remaining_native_bytes(),
            budget.check_time().is_ok(),
        ))
    }

    #[test]
    fn full_actual_suffix_has_exact_native_byte_prefixes_for_all_imported_shapes() -> Fallible<()> {
        for shape in [
            Shape::Mixed,
            Shape::EmptyClassified,
            Shape::EmptyUnclassified,
        ] {
            let (_directory, store, world, built) = fixture(shape)?;
            let child = world.child_at(0)?.id;
            let expected = store.read_fork_event_suffix(child, 1)?;
            let (bytes, rows, visits) = costs(&store, &built, 1)?;
            let interval = store.begin_protected_effect_interval()?;
            for limit in 1..=bytes {
                let (result, remaining, open) = read(&store, child, 1, rows, visits, limit)?;
                if limit == bytes {
                    assert_eq!(result?, expected);
                    assert_eq!(remaining, 0);
                    assert!(open);
                } else {
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(!open);
                }
                assert!(!store.conn.is_autocommit());
            }
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
        Ok(())
    }

    #[test]
    fn full_suffix_repeats_actual_rows_prefix_visits_and_retained_copies_on_one_ledger(
    ) -> Fallible<()> {
        let (_directory, store, world, built) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        let expected = store.read_fork_event_suffix(child, 1)?;
        let (bytes, rows, visits) = costs(&store, &built, 1)?;
        for (row_limit, visit_limit, byte_limit, repeats, success) in [
            (rows, visits, bytes, 1, true),
            (rows - 1, visits, bytes, 1, false),
            (rows, visits - 1, bytes, 1, false),
            (rows, visits, bytes - 1, 1, false),
            (rows * 2, visits * 2, bytes * 2, 2, true),
            (rows * 2 - 1, visits * 2, bytes * 2, 2, false),
            (rows * 2, visits * 2 - 1, bytes * 2, 2, false),
            (rows * 2, visits * 2, bytes * 2 - 1, 2, false),
        ] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits =
                ForkReplayReadLimitsV1::new(1, visit_limit, row_limit, byte_limit, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = (0..repeats).try_for_each(|_| {
                store
                    .read_fork_event_suffix_in_transaction_with_context(
                        child,
                        1,
                        AuthorityValidatorV1::CodeTwoAware,
                        &mut NativeReadContextV1::protected(&mut budget),
                    )
                    .map(|actual| assert_eq!(actual, expected))
            });
            assert_eq!(result.is_ok(), success);
            assert_eq!(budget.check_time().is_ok(), success);
            if success {
                assert_eq!(budget.remaining_native_bytes(), 0);
            }
        }
        Ok(())
    }

    #[test]
    fn suffix_cut_filters_results_without_skipping_later_or_earlier_operation_validation(
    ) -> Fallible<()> {
        let (_directory, store, world, built) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        for from in [1, 6, 9] {
            let expected = store.read_fork_event_suffix(child, from)?;
            let (bytes, rows, visits) = costs(&store, &built, from)?;
            let (actual, remaining, open) = read(&store, child, from, rows, visits, bytes)?;
            assert_eq!(actual?, expected);
            assert_eq!(remaining, 0);
            assert!(open);
        }
        for local in [1, 4] {
            store.conn.execute_batch("SAVEPOINT suffix_fault")?;
            store.conn.execute("UPDATE fork_append_operations SET fop1_cbor = x'00' WHERE child_id = ?1 AND local_seq = ?2", params![child.to_string(), local])?;
            assert!(store.read_fork_event_suffix(child, 9).is_err());
            assert_eq!(
                read(&store, child, 9, 256, 32, 65_536)?.0,
                Err(Error::CorruptAuthority)
            );
            store
                .conn
                .execute_batch("ROLLBACK TO suffix_fault; RELEASE suffix_fault")?;
        }
        Ok(())
    }

    #[test]
    fn actual_suffix_probes_close_storage_type_width_and_native_cap_faults_before_getters(
    ) -> Fallible<()> {
        let (_directory, store, world, _built) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        for (column, after, value) in [
            ("event_id", None, Value::Blob(vec![1; 26])),
            ("event_id", None, Value::Text("x".repeat(27))),
            ("seq", Some(i64::MAX), Value::Text("bad".to_owned())),
        ] {
            store.conn.execute_batch("SAVEPOINT suffix_fault")?;
            store.conn.execute(
                &format!("UPDATE events SET {column} = ?1 WHERE timeline_id = ?2 AND seq = 1"),
                params![value, child.to_string()],
            )?;
            // Exercise the actual indexed raw owner directly: a changed Event
            // key can be rejected even earlier by the full orphan closure.
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 8, 4096, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert!(next_row(
                &store.conn,
                &child.to_string(),
                after,
                &mut NativeReadContextV1::protected(&mut budget)
            )
            .is_err());
            store
                .conn
                .execute_batch("ROLLBACK TO suffix_fault; RELEASE suffix_fault")?;
        }
        for value in [
            Value::Text("not BLOB".to_owned()),
            Value::Blob(vec![0; MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1 + 1]),
        ] {
            store.conn.execute_batch("SAVEPOINT suffix_fault")?;
            store.conn.execute("UPDATE fork_append_operations SET fop1_cbor = ?1 WHERE child_id = ?2 AND local_seq = 1", params![value, child.to_string()])?;
            assert_eq!(
                read(&store, child, 1, 256, 32, 65_536)?.0,
                Err(Error::CorruptAuthority)
            );
            store
                .conn
                .execute_batch("ROLLBACK TO suffix_fault; RELEASE suffix_fault")?;
        }
        Ok(())
    }

    #[test]
    fn native_event_id_redaction_refuses_suffix_length_before_materialization() -> Fallible<()> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        for held_snapshot in [false, true] {
            let (_directory, store, world, _built) = fixture(Shape::Mixed)?;
            let key = world.child_at(0)?.id.to_string();
            let expected = next_row(
                &store.conn,
                &key,
                None,
                &mut NativeReadContextV1::ordinary(),
            )?
            .ok_or("fixture suffix row")?;
            let (_, (_, _, fop)) = &expected;
            let bytes = ulid::ULID_LEN + fop.as_ref().ok_or("fixture FOP1")?.len();
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            // The ignored Event ID prevents the FOP join from matching: one
            // failed probe row, then four rows for the complete healthy retry.
            let limits = ForkReplayReadLimitsV1::new(1, 1, 5, bytes, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            if held_snapshot {
                store.conn.execute_batch("BEGIN DEFERRED")?;
            }
            let ignored_reads = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&ignored_reads);
            // Backend-private driver contract, not a production authorizer:
            // SQLite substitutes NULL in the unchanged indexed probe query.
            store
                .conn
                .authorizer(Some(move |request: AuthContext<'_>| {
                    if request.action
                        == (AuthAction::Read {
                            table_name: "events",
                            column_name: "event_id",
                        })
                    {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Authorization::Ignore
                    } else {
                        Authorization::Allow
                    }
                }))?;
            let failed = next_row(
                &store.conn,
                &key,
                None,
                &mut NativeReadContextV1::protected(&mut budget),
            );
            store
                .conn
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
            // typeof, length(CAST(... AS BLOB)), and the FOP join each read
            // this column. Remove the policy before assertions or retry SQL.
            assert_eq!(ignored_reads.load(Ordering::SeqCst), 3);
            assert_eq!(failed, Err(Error::CorruptAuthority));
            assert_eq!(budget.remaining_native_bytes(), bytes);
            budget.check_time()?;
            assert_eq!(
                next_row(
                    &store.conn,
                    &key,
                    None,
                    &mut NativeReadContextV1::protected(&mut budget),
                )?,
                Some(expected),
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
        Ok(())
    }

    #[derive(Default)]
    struct SuffixFunctionAuthorization {
        functions: Vec<(String, bool)>,
    }

    fn ignore_suffix_probe_function(
        conn: &Connection,
        ignored_index: usize,
    ) -> rusqlite::Result<std::sync::Arc<std::sync::Mutex<SuffixFunctionAuthorization>>> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::{Arc, Mutex};

        let observed = Arc::new(Mutex::new(SuffixFunctionAuthorization::default()));
        let callback_observed = Arc::clone(&observed);
        conn.authorizer(Some(move |request: AuthContext<'_>| {
            if let AuthAction::Function { function_name } = request.action {
                let Ok(mut observed) = callback_observed.lock() else {
                    return Authorization::Deny;
                };
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
    fn native_suffix_function_refusals_preserve_joined_probe_accounting() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        for (label, ignored_index) in [("sequence_type", 0), ("event_id_type", 1), ("fop_type", 3)]
        {
            for held_snapshot in [false, true] {
                let (_directory, store, world, _built) = fixture(Shape::Mixed)?;
                let key = world.child_at(0)?.id.to_string();
                let expected = next_row(
                    &store.conn,
                    &key,
                    None,
                    &mut NativeReadContextV1::ordinary(),
                )?
                .ok_or("fixture suffix row")?;
                let (_, (_, _, fop)) = &expected;
                let bytes = ulid::ULID_LEN + fop.as_ref().ok_or("fixture FOP1")?.len();
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                // Function redaction preserves the FOP join: two failed probe
                // rows, then four rows and all bytes for the healthy retry.
                let limits = ForkReplayReadLimitsV1::new(1, 1, 6, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                if held_snapshot {
                    store.conn.execute_batch("BEGIN DEFERRED")?;
                }
                let observed = ignore_suffix_probe_function(&store.conn, ignored_index)?;
                let failed = next_row(
                    &store.conn,
                    &key,
                    None,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                store
                    .conn
                    .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                let observed = observed.lock().map_err(|_| "function observer poisoned")?;
                let actual: Vec<_> = observed
                    .functions
                    .iter()
                    .map(|(name, ignored)| (name.as_str(), *ignored))
                    .collect();
                let expected_functions: Vec<_> = ["typeof", "typeof", "length", "typeof", "length"]
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| (name, index == ignored_index))
                    .collect();
                assert_eq!(actual, expected_functions, "{label}");
                drop(observed);
                assert_eq!(failed, Err(Error::CorruptAuthority), "{label}");
                assert_eq!(budget.remaining_native_bytes(), bytes, "{label}");
                budget.check_time()?;
                assert_eq!(
                    next_row(
                        &store.conn,
                        &key,
                        None,
                        &mut NativeReadContextV1::protected(&mut budget)
                    )?,
                    Some(expected),
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
    fn complete_suffix_batches_keep_original_guard_expiry_and_regression() -> Fallible<()> {
        let (_directory, store, world, built) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        let (bytes, rows, visits) = costs(&store, &built, 1)?;
        for regression in [false, true] {
            let mut failures = 0;
            let mut successes = 0;
            for boundary in 2..=2048 {
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
                let limits = ForkReplayReadLimitsV1::new(1, visits, rows, bytes, 10)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = read_suffix_with_context(
                    &store,
                    child,
                    1,
                    AuthorityValidatorV1::CodeTwoAware,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if result.is_ok() {
                    successes += 1;
                } else {
                    failures += 1;
                    assert_eq!(result, Err(Error::CorruptAuthority));
                    assert!(budget.check_time().is_err());
                }
            }
            assert!(failures > 0);
            assert!(successes > 0);
        }
        Ok(())
    }

    #[test]
    fn missing_operation_and_graph_are_rejected_even_when_no_result_is_selected() -> Fallible<()> {
        let (_directory, store, world, _built) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        for sql in [
            "DELETE FROM fork_append_operations WHERE child_id = ?1 AND local_seq = 4",
            "DELETE FROM fork_classifier_tables WHERE child_id = ?1",
            "UPDATE fork_append_operations SET fop1_cbor = x'' WHERE child_id = ?1 AND local_seq = 4",
        ] {
            store.conn.execute_batch("SAVEPOINT missing_suffix")?;
            store.conn.execute(sql, [child.to_string()])?;
            assert!(store.read_fork_event_suffix(child, 9).is_err());
            assert_eq!(read(&store, child, 9, 256, 32, 65_536)?.0, Err(Error::CorruptAuthority));
            store.conn.execute_batch("ROLLBACK TO missing_suffix; RELEASE missing_suffix")?;
        }
        Ok(())
    }

    #[test]
    fn protected_publication_rejects_independently_corrupted_operation_digests() -> Fallible<()> {
        use crate::{
            ForkManifestPublicationPortV1, ForkReplayAuthorityReadErrorV1,
            ForkReplayAuthorityReadPortV1, ForkReplayRequirementV1,
        };

        let (_directory, store, world, built) = fixture(Shape::Mixed)?;
        let child = world.child_at(0)?.id;
        let head = crate::fae1_fixture::PARENT_CUT + Shape::Mixed.events();
        let committed = store.read_committed(child, head)?;
        let requirement = ForkReplayRequirementV1::new(
            child,
            pos_core::Seq::from_u64(head),
            committed.record_id,
            committed.authority_origin_digest,
        )?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let original = closure
            .append_operations()
            .iter()
            .find(|operation| operation.input().intervention_admission_digest.is_some())
            .ok_or("intervention operation")?;
        let interval = store.begin_protected_effect_interval()?;
        for fault in 0..4 {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, 8 * 1024 * 1024, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                store
                    .validate_fork_replay_authority(&requirement, &mut budget)?
                    .requirement(),
                requirement
            );
            store
                .conn
                .execute_batch("SAVEPOINT changed_operation_digest")?;
            let mut input = original.input().clone();
            let foreign = pos_core::Hash::from_bytes([0x96; 32]);
            match fault {
                0 => input.fork_admission_digest = foreign,
                1 => input.classifier_revision_digest = foreign,
                2 => input.event_origin_digest = foreign,
                _ => input.intervention_admission_digest = Some(foreign),
            }
            let changed = ForkAppendOperationV1::new(input)?;
            assert_eq!(
                store.conn.execute(
                    "UPDATE fork_append_operations SET fop1_cbor=?1 WHERE operation_id=?2",
                    params![
                        changed.to_canonical_cbor(),
                        original.input().operation_id.as_bytes().as_slice(),
                    ],
                )?,
                1
            );
            assert_eq!(
                store.validate_fork_replay_authority(&requirement, &mut budget),
                Err(ForkReplayAuthorityReadErrorV1::CorruptAuthority),
                "accepted corrupted operation digest {fault}"
            );
            budget.check_time()?;
            store.conn.execute_batch(
                "ROLLBACK TO changed_operation_digest; RELEASE changed_operation_digest",
            )?;
        }
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        assert_eq!(store.read_committed(child, head)?, committed);
        Ok(())
    }
}
