//! ADR-114 attribution reads on the already-held `SQLite` read transaction.

use std::collections::HashSet;

use pos_core::{store::EventStore, TimelineId};
use rusqlite::OptionalExtension;

use super::SqliteStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1, ForkReplayAuthorityEvidenceV1,
    ForkReplayAuthorityReadErrorV1 as Error, ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1,
    ForkReplayRequirementV1,
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
        let committed = self
            .read_committed_fork_publication(
                requirement.child_timeline_id(),
                requirement.publication_logical_head().as_u64(),
                AuthorityValidatorV1::CodeTwoAware,
            )
            .map_err(|_| Error::CorruptAuthority)?;
        budget.check_time()?;
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
        let head = i64::try_from(requirement.publication_logical_head().as_u64()).map_err(|_| Error::Unavailable)?;
        for (table, column, selection) in [
            ("fork_admissions", "far1_cbor", "child_id = ?1"),
            ("fork_classifier_tables", "fct1_cbor", "child_id = ?1"),
            ("fork_classifier_registrations", "fcr1_cbor", "child_id = ?1"),
            ("fork_append_operations", "fop1_cbor", "child_id = ?1"),
            ("fork_event_origins", "eor1_cbor", "event_id IN (SELECT event_id FROM events WHERE timeline_id = ?1)"),
            ("fork_intervention_admissions", "fia1_cbor", "event_id IN (SELECT event_id FROM events WHERE timeline_id = ?1)"),
            ("fork_publication_operations", "fpo1_cbor", "operation_id IN (SELECT operation_id FROM fork_publication_bindings WHERE child_id = ?1 AND final_logical_head = ?2)"),
            ("fork_publication_bindings", "fpb1_cbor", "child_id = ?1 AND final_logical_head = ?2"),
            ("fork_publication_artifacts", "fpa1_cbor", "record_id IN (SELECT record_id FROM fork_publication_bindings WHERE child_id = ?1 AND final_logical_head = ?2)"),
            ("imported_fork_attribution_admissions", "ifa1_cbor", "child_id = ?1"),
            ("imported_fork_key_evidence", "ikr1_cbor", "import_operation_id IN (SELECT import_operation_id FROM imported_fork_attribution_admissions WHERE child_id = ?1)"),
            ("imported_fork_key_evidence", "ikt1_cbor", "import_operation_id IN (SELECT import_operation_id FROM imported_fork_attribution_admissions WHERE child_id = ?1)"),
        ] {
            let arguments: &[&dyn rusqlite::ToSql] = if selection.contains("?2") { &[&child_key, &head] } else { &[&child_key] };
            self.preflight_selected_records(table, column, selection, arguments, budget)?;
        }
        // Derive source keys only from the selected native FCT1. Its fetched
        // bytes and decoder re-encoding are charged before either allocates.
        let table_bytes = self.conn.query_row("SELECT length(fct1_cbor) FROM fork_classifier_tables WHERE child_id = ?1", [&child_key], |row| row.get::<_, i64>(0)).optional().map_err(|_| Error::StorageUnavailable)?;
        if let Some(bytes) = table_bytes {
            let bytes = usize::try_from(bytes).map_err(|_| Error::CorruptAuthority)?;
            budget.charge_bytes(bytes)?;
            budget.charge_bytes(bytes)?;
            let table = super::sqlite_fork_classifier_table(&self.conn, child).map_err(|_| Error::CorruptAuthority)?.ok_or(Error::CorruptAuthority)?;
            let input = table.input();
            self.preflight_selected_records("imported_fork_classifier_sources", "fcs1_cbor", "fcs1_digest = ?1", &[&input.source_configuration_revision_digest.as_bytes().as_slice()], budget)?;
            self.preflight_selected_records("fork_classifier_sources", "fcs1_cbor", "descriptor_hash = ?1 AND registrar_identifier = ?2", &[&input.room_revision_descriptor_hash.as_bytes().as_slice(), &input.registrar_identifier], budget)?;
        }
        self.preflight_selected_records("key_registry", "state_cbor", "singleton = 1", &[], budget)?;
        // Native orphan-provenance detection examines the fixed child bytes of
        // every EOR1/FIA1, including unrelated rows, without fetching blobs.
        for table in ["fork_event_origins", "fork_intervention_admissions"] {
            let count = self.conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get::<_, i64>(0)).map_err(|_| Error::StorageUnavailable)?;
            budget.charge_rows(usize::try_from(count).map_err(|_| Error::CorruptAuthority)?)?;
        }
        budget.check_time()
    }

    fn preflight_selected_records(&self, table: &str, column: &str, selection: &str, arguments: &[&dyn rusqlite::ToSql], budget: &mut ForkReplayReadBudgetV1<'_>) -> ReadResult<()> {
        let sql = format!("SELECT typeof({column}) = 'blob', length({column}) FROM {table} WHERE {selection}");
        let mut statement = self.conn.prepare(&sql).map_err(|_| Error::StorageUnavailable)?;
        let mut records = statement.query(arguments).map_err(|_| Error::StorageUnavailable)?;
        while let Some(row) = records.next().map_err(|_| Error::StorageUnavailable)? {
            budget.charge_rows(1)?;
            let blob: bool = row.get(0).map_err(|_| Error::StorageUnavailable)?;
            if blob {
                budget.charge_bytes(row_length(row, 1)?)?;
            } else if column != "ikt1_cbor" || row.get::<_, Option<i64>>(1).map_err(|_| Error::StorageUnavailable)?.is_some() {
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
