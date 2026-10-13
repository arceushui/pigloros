//! ADR-114 attribution reads on the already-held `SQLite` read transaction.

use std::collections::HashSet;

use pos_core::{store::EventStore, TimelineId};
use rusqlite::OptionalExtension;

use super::SqliteStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1, fork_replay::NativeReadContextV1,
    ForkReplayAuthorityEvidenceV1, ForkReplayAuthorityReadErrorV1 as Error,
    ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayRequirementV1,
};

type ReadResult<T> = Result<T, Error>;

impl ForkReplayAuthorityReadPortV1 for SqliteStore {
    fn validate_fork_replay_authority(
        &self,
        requirement: &ForkReplayRequirementV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<ForkReplayAuthorityEvidenceV1> {
        // A readonly host must also hold its separate writer reservation. No
        // BEGIN/COMMIT occurs here; the release owner owns both lifecycles.
        if self.conn.is_autocommit()
            || self
                .writer_reservation_connection
                .as_ref()
                .is_some_and(rusqlite::Connection::is_autocommit)
        {
            return Err(Error::StorageUnavailable);
        }
        self.preflight_fork_replay_ancestry(requirement.child_timeline_id(), budget)?;
        self.preflight_fork_replay_records(requirement, budget)?;
        let committed = self.read_committed_fork_publication_with_context(
            requirement.child_timeline_id(),
            requirement.publication_logical_head().as_u64(),
            AuthorityValidatorV1::CodeTwoAware,
            &mut NativeReadContextV1::protected(budget),
        );
        budget.check_time()?;
        let committed = committed.map_err(|_| Error::CorruptAuthority)?;
        ForkReplayAuthorityEvidenceV1::from_committed(*requirement, &committed, budget)
    }
}

impl SqliteStore {
    fn preflight_fork_replay_ancestry(
        &self,
        child: TimelineId,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<()> {
        let mut visited = HashSet::new();
        let mut next = Some(child);
        let mut depth = 0;
        while let Some(timeline) = next {
            budget.charge_node(depth)?;
            if !visited.insert(timeline) {
                return Err(Error::CorruptAuthority);
            }
            // Measure metadata before get_timeline can clone variable fields.
            let metadata_bytes = self
                .conn
                .query_row(
                    "SELECT coalesce(length(CAST(name AS BLOB)), 0) +
                 coalesce(length(CAST(parent_id AS BLOB)), 0)
                 FROM timelines WHERE id = ?1",
                    [timeline.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|_| Error::StorageUnavailable)?
                .ok_or(Error::Unavailable)?;
            budget.charge_bytes(
                usize::try_from(metadata_bytes).map_err(|_| Error::CorruptAuthority)?,
            )?;
            let mut statement = self
                .conn
                .prepare(
                    "SELECT length(payload), length(CAST(event_type AS BLOB))
                 FROM events WHERE timeline_id = ?1 ORDER BY seq",
                )
                .map_err(|_| Error::StorageUnavailable)?;
            let mut events = statement
                .query([timeline.to_string()])
                .map_err(|_| Error::StorageUnavailable)?;
            while let Some(row) = events.next().map_err(|_| Error::StorageUnavailable)? {
                budget.charge_rows(1)?;
                let payload = row_length(row, 0)?;
                let kind = row_length(row, 1)?;
                budget.charge_bytes(payload)?;
                budget.charge_bytes(kind)?;
            }
            let meta = self
                .get_timeline(timeline)
                .map_err(|_| Error::Unavailable)?
                .ok_or(Error::Unavailable)?
                .meta;
            next = meta.fork_point.map(|(parent, _)| parent);
            depth += 1;
        }
        Ok(())
    }

    /// Length/count preflight happens on the held snapshot. It retrieves no
    /// variable-size blob before it has been charged against the ledger.
    fn preflight_fork_replay_records(
        &self,
        requirement: &ForkReplayRequirementV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<()> {
        let child = requirement.child_timeline_id();
        let child_key = child.to_string();
        for (table, column, selection) in [
            ("fork_append_operations", "fop1_cbor", "child_id = ?1"),
            (
                "fork_event_origins",
                "eor1_cbor",
                "event_id IN (SELECT event_id FROM events WHERE timeline_id = ?1)",
            ),
            (
                "fork_intervention_admissions",
                "fia1_cbor",
                "event_id IN (SELECT event_id FROM events WHERE timeline_id = ?1)",
            ),
        ] {
            self.preflight_selected_records(table, column, selection, &[&child_key], budget)?;
        }
        self.preflight_selected_records(
            "key_registry",
            "state_cbor",
            "singleton = 1",
            &[],
            budget,
        )?;
        // Native orphan-provenance detection examines the fixed child bytes of
        // every EOR1/FIA1, including unrelated rows, without fetching blobs.
        for table in ["fork_event_origins", "fork_intervention_admissions"] {
            let count = self
                .conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| Error::StorageUnavailable)?;
            budget.charge_rows(usize::try_from(count).map_err(|_| Error::CorruptAuthority)?)?;
        }
        budget.check_time()
    }

    fn preflight_selected_records(
        &self,
        table: &str,
        column: &str,
        selection: &str,
        arguments: &[&dyn rusqlite::ToSql],
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<()> {
        let sql = format!(
            "SELECT typeof({column}) = 'blob', length({column}) FROM {table} WHERE {selection}"
        );
        let mut statement = self
            .conn
            .prepare(&sql)
            .map_err(|_| Error::StorageUnavailable)?;
        let mut records = statement
            .query(arguments)
            .map_err(|_| Error::StorageUnavailable)?;
        while let Some(row) = records.next().map_err(|_| Error::StorageUnavailable)? {
            budget.charge_rows(1)?;
            let blob: bool = row.get(0).map_err(|_| Error::StorageUnavailable)?;
            if blob {
                budget.charge_bytes(row_length(row, 1)?)?;
            } else {
                return Err(Error::CorruptAuthority);
            }
        }
        budget.check_time()
    }
}

fn row_length(row: &rusqlite::Row<'_>, column: usize) -> ReadResult<usize> {
    let length = row
        .get::<_, i64>(column)
        .map_err(|_| Error::CorruptAuthority)?;
    usize::try_from(length).map_err(|_| Error::CorruptAuthority)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World, PARENT_CUT},
        ForkAttributionAuthorityImportPortV1, ForkManifestPublicationErrorV1,
        ForkManifestPublicationPortV1, ForkReplayReadLimitsV1,
    };
    use pos_core::{
        store::SeqRange,
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1,
        SignedForkReproManifestV1,
    };
    use std::time::Duration;

    /// Byte encoders and logical fields are an independent oracle: no
    /// production length, carrier, debit helper or measured ledger is used.
    fn publication_phase_cost(committed: &crate::CommittedForkManifestV1) -> Fallible<usize> {
        let owner = committed
            .operation
            .input()
            .signing_identity
            .owner_id
            .as_str()
            .len();
        let projection = 32 + 16 + 8 + 32 + 32 + owner + 1 + 8 + 32 + 32 + 32 + 1;
        let local = committed.operation.to_canonical_cbor().len();
        let operation = pos_core::ImportedForkPublicationOperationV1::from_local(
            committed.operation.clone(),
            committed.authority_origin_digest.ok_or("no origin")?,
        )
        .to_canonical_cbor()
        .len();
        let artifact =
            pos_core::ForkPublicationArtifactV1::new(pos_core::ForkPublicationArtifactInputV1 {
                signed_manifest_record_id: committed.record_id,
                operation_id: committed.operation.input().operation_id,
                signed_manifest_bytes: committed.outer_bytes.clone(),
            })?;
        let signed = artifact.signed_manifest();
        let artifact_decode = committed.outer_bytes.len() * 3
            + signed.manifest_bytes().len() * 3
            + signed.identity().owner_id.as_str().len()
            + signed.manifest().input().intervention_sequences.len() * 8
            + artifact.to_canonical_cbor().len();
        Ok(committed.receipt.child_timeline_id.to_string().len()
            + committed.binding.to_canonical_cbor().len() * 3
            + operation
            + owner * 2
            + local * 2
            + projection
            + 1
            + 32
            + artifact.to_canonical_cbor().len()
            + artifact_decode)
    }

    fn publication_deadline_sweep(
        store: &SqliteStore,
        committed: &crate::CommittedForkManifestV1,
        expected: usize,
    ) -> Fallible<()> {
        for marks in 2..512 {
            let mut clock = ScriptedGuardMonotonicSourceV1::new(
                std::iter::repeat_n(Duration::ZERO, marks).chain([Duration::from_secs(2)]),
            );
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 6, expected, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = store.committed_publication_rows_with_context(
                committed.receipt.child_timeline_id,
                committed.receipt.final_logical_head,
                AuthorityValidatorV1::CodeTwoAware,
                &mut NativeReadContextV1::protected(&mut budget),
            );
            if result.is_ok() {
                assert_eq!(budget.remaining_native_bytes(), 0);
                return Ok(());
            }
            assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
        }
        Err("no complete publication read within checkpoint cap".into())
    }

    #[test]
    fn file_backed_publication_rows_charge_exact_raw_decode_and_copy_work() -> Fallible<()> {
        for shape in [
            Shape::Mixed,
            Shape::EmptyClassified,
            Shape::EmptyUnclassified,
        ] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("publication-rows.sqlite");
            let mut store = SqliteStore::open(path.to_str().ok_or("UTF-8 path")?)?;
            let world = World::new(shape, false)?;
            let built = world.build(&Spec::default())?;
            world.seed_destination(&mut store)?;
            pin_policy(&mut store, &built.policy)?;
            store.import_verified(&request_for(&world, &built))?;
            let child = world.child_at(0)?.id;
            let head = PARENT_CUT + shape.events();
            let committed = store.read_committed(child, head)?;
            let expected = publication_phase_cost(&committed)?;
            let interval = store.begin_protected_effect_interval()?;
            // Every byte prefix reaches each pre-copy/decoder debit separately.
            for limit in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 6, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = store.committed_publication_rows_with_context(
                    child,
                    head,
                    AuthorityValidatorV1::CodeTwoAware,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if limit == expected {
                    let rows = result?;
                    assert_eq!(rows.operation, committed.operation);
                    assert_eq!(rows.binding, committed.binding);
                    assert_eq!(
                        rows.artifact.input().signed_manifest_bytes,
                        committed.outer_bytes
                    );
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert!(result.is_err());
                    assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
                }
            }
            for rows in 1..6 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, rows, expected, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert!(store
                    .committed_publication_rows_with_context(
                        child,
                        head,
                        AuthorityValidatorV1::CodeTwoAware,
                        &mut NativeReadContextV1::protected(&mut budget)
                    )
                    .is_err());
                assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
            }
            publication_deadline_sweep(&store, &committed, expected)?;
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
        Ok(())
    }

    #[test]
    fn file_backed_shared_native_batches_charge_exact_buffers_and_latch_expiry() -> Fallible<()> {
        for shape in [
            Shape::Mixed,
            Shape::EmptyClassified,
            Shape::EmptyUnclassified,
        ] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("native-context.sqlite");
            let mut store = SqliteStore::open(path.to_str().ok_or("UTF-8 path")?)?;
            let world = World::new(shape, false)?;
            let built = world.build(&Spec::default())?;
            world.seed_destination(&mut store)?;
            pin_policy(&mut store, &built.policy)?;
            store.import_verified(&request_for(&world, &built))?;
            let child = world.child_at(0)?.id;
            let head = PARENT_CUT + shape.events();
            let committed = store.read_committed(child, head)?;
            let import_bytes: Vec<u8> = store.conn.query_row(
                "SELECT ifa1_cbor FROM imported_fork_attribution_admissions WHERE child_id = ?1",
                [child.to_string()],
                |row| row.get(0),
            )?;
            let expected = shared_native_phase_cost(&committed, &built, &world, &import_bytes)?;
            let interval = store.begin_protected_effect_interval()?;
            for (bytes, succeeds) in [(expected, true), (expected - 1, false)] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, bytes, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = store.read_committed_fork_publication_with_context(
                    child,
                    head,
                    AuthorityValidatorV1::CodeTwoAware,
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if succeeds {
                    let actual = result.map_err(|error| format!(
                        "{shape:?} shared native exact budget {expected} failed: {error}; guard={:?}",
                        budget.check_time(),
                    ))?;
                    assert_eq!(actual, committed);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(
                        result,
                        Err(ForkManifestPublicationErrorV1::PublicationConflict)
                    );
                    assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
                }
            }
            let mut clock = ScriptedGuardMonotonicSourceV1::new(
                std::iter::repeat_n(Duration::ZERO, 4).chain([Duration::from_secs(2)]),
            );
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, expected, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                store.read_committed_fork_publication_with_context(
                    child,
                    head,
                    AuthorityValidatorV1::CodeTwoAware,
                    &mut NativeReadContextV1::protected(&mut budget),
                ),
                Err(ForkManifestPublicationErrorV1::PublicationConflict)
            );
            assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
            assert_eq!(store.read_committed(child, head)?, committed);
        }
        Ok(())
    }

    /// Independent byte encoders and logical fields; this oracle does not
    /// call production length/carrier/ledger helpers or measure a used budget.
    fn shared_native_phase_cost(
        committed: &crate::CommittedForkManifestV1,
        built: &crate::fae1_fixture::Built,
        world: &World,
        import_bytes: &[u8],
    ) -> Fallible<usize> {
        let signed = SignedForkReproManifestV1::from_canonical_cbor(&committed.outer_bytes)?;
        let owner_bytes = committed
            .operation
            .input()
            .signing_identity
            .owner_id
            .as_str()
            .len();
        let receipt_copy = 32 + 16 + 8 + 32;
        let projection_copy = 32 + 16 + 8 + 32 + 32 + owner_bytes + 1 + 8 + 32 + 32 + 32 + 1;
        let origin_copy = 1 + 32;
        let absent_key_copy = owner_bytes + 1 + 8 + 1 + 32 + 1 + 32;
        let key = &built.envelope.unsigned().input().key_record;
        let retained_key_phase =
            key.to_canonical_cbor().len() * 3 + key.identity().owner_id.as_str().len();
        let admission_phase = super::super::fork_replay_admission::imported_admission_phase_cost(
            &built.envelope.unsigned().input().records.fork_admission,
            import_bytes,
        )?;
        let classifier_phase =
            super::super::fork_replay_classifier::imported_classifier_phase_cost(
                built.envelope.unsigned().input().classifier.as_ref(),
            )?;
        // The fixture persists exactly this public registry through the
        // ordinary Ciborium writer. Count its newly contextual raw fetch,
        // independently of production probes or measured ledger usage.
        let mut registry_bytes = Vec::new();
        ciborium::into_writer(&world.registry, &mut registry_bytes)?;
        Ok(publication_phase_cost(committed)?
            + retained_key_phase
            + admission_phase * 2
            + classifier_phase
            + committed.outer_bytes.len() * 2
            + signed.manifest_bytes().len() * 2
            + signed.manifest().input().intervention_sequences.len() * std::mem::size_of::<u64>()
            + committed.binding.to_canonical_cbor().len()
            + receipt_copy
            + projection_copy
            + origin_copy
            + absent_key_copy
            + registry_bytes.len()
            + final_event_hash_phase_cost(world, committed)?
            + classified_records_phase_cost(world, built)?)
    }

    fn raw_event_cost(event: &pos_core::Event) -> usize {
        // Independently inventory successful SQLite String/Vec getters. This
        // oracle does not ask the production probe, carrier or ledger for a
        // total; signature/origin units come from public committed values.
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

    fn final_event_hash_phase_cost(
        world: &World,
        committed: &crate::CommittedForkManifestV1,
    ) -> Fallible<usize> {
        let root = world.root;
        let child = committed.receipt.child_timeline_id;
        // The fixture has one root and one Fork, not arbitrary ancestry. Count
        // query Strings, visited-set IDs and retained segment ID/head/cut
        // fields, plus the non-root row's actually fetched parent String.
        let root_fields = root.to_string().len() + 2 * root.inner().to_bytes().len()
            + 0_u64.to_be_bytes().len();
        let child_fields = child.to_string().len() + 2 * child.inner().to_bytes().len()
            + 2 * 0_u64.to_be_bytes().len() + root.to_string().len();
        let parent = world.source.read(root, SeqRange::bounded(
            pos_core::Seq::from_u64(1), pos_core::Seq::from_u64(PARENT_CUT),
        ))?;
        let own = world.source.read_own(child, SeqRange::all())?;
        let event_work = parent.iter().chain(&own).map(|event| {
            raw_event_cost(event) + event.id.to_string().len() + event.payload.len()
        }).sum::<usize>();
        Ok(root_fields + child_fields + root.to_string().len() + child.to_string().len() + event_work)
    }

    fn classified_records_phase_cost(world: &World, built: &crate::fae1_fixture::Built) -> Fallible<usize> {
        let closure = pos_core::ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let Some(graph) = closure.classifier() else {
            return Ok(5 * closure.fork_admission().fields().child_timeline_id.to_string().len());
        };
        let own = world.source.read_own(closure.fork_admission().fields().child_timeline_id, SeqRange::all())?;
        let classifier = graph.table.to_canonical_cbor().len()
            + graph.table.input().routes.iter().map(|route| {
                route.source().route().len() + route.source().schema_digest().as_bytes().len() + 1
            }).sum::<usize>();
        closure.append_operations().iter().try_fold(5 * closure.fork_admission().fields().child_timeline_id.to_string().len(), |sum, operation| {
            let event = own.iter().find(|event| event.id == operation.input().event_id)
                .ok_or("classified fixture Event")?;
            let origin = closure.event_origins().iter().find(|record| record.input().event_id == event.id)
                .ok_or("classified fixture EOR1")?;
            let intervention = closure.intervention_admissions().iter()
                .find(|record| record.input().event_id == event.id);
            // Four classified-lookup query Strings plus the raw suffix Event
            // ID String. Whole-suffix prefix/orphan/cursor keys are counted
            // separately above. Include real FOP raw/comparison/source work,
            // table binding and classifier buffers, and retained fixed fields.
            let source_strings = match &operation.input().source {
                pos_core::ForkAppendSourceIdentityV1::HostInternal => 0,
                pos_core::ForkAppendSourceIdentityV1::ExternalInput { adapter_identifier, source } => adapter_identifier.len() + source.route().len(),
            };
            let mut retained = 16 + 8 + 16 + 2 + 32 + 32;
            if intervention.is_some() { retained += 32 + 16 + 8 + 16 + 32 + 32 + 32 + 32; }
            retained += 32 + 16 + 8 + 16 + 32 + 8 + 32 + 32 + 32 + 32 + 1;
            if operation.input().intervention_admission_digest.is_some() { retained += 32; }
            if let pos_core::ForkAppendSourceIdentityV1::ExternalInput { source, .. } = &operation.input().source { retained += source.schema_digest().as_bytes().len(); }
            Ok(sum + 5 * event.id.to_string().len() + raw_event_cost(event)
                + 3 * origin.to_canonical_cbor().len()
                + intervention.map_or(0, |record| 3 * record.to_canonical_cbor().len())
                + classifier + graph.table.to_canonical_cbor().len()
                + 2 * operation.to_canonical_cbor().len() + source_strings + retained)
        })
    }
}
