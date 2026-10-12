//! ADR-114 attribution reads on the already-held SQLite read transaction.

use std::collections::HashSet;

use pos_core::{store::EventStore, TimelineId};
use rusqlite::{params, OptionalExtension};

use super::SqliteStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1,
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
        if self.conn.is_autocommit() || self.writer_reservation_connection.as_ref()
            .is_some_and(rusqlite::Connection::is_autocommit)
        {
            return Err(Error::StorageUnavailable);
        }
        self.preflight_fork_replay_ancestry(requirement.child_timeline_id(), budget)?;
        self.preflight_fork_replay_records(budget)?;
        let committed = self.read_committed_fork_publication(
            requirement.child_timeline_id(),
            requirement.publication_logical_head().as_u64(),
            AuthorityValidatorV1::CodeTwoAware,
        ).map_err(|_| Error::CorruptAuthority)?;
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
            let metadata_bytes = self.conn.query_row(
                "SELECT coalesce(length(CAST(name AS BLOB)), 0) +
                 coalesce(length(CAST(parent_id AS BLOB)), 0)
                 FROM timelines WHERE id = ?1",
                [timeline.to_string()], |row| row.get::<_, i64>(0),
            ).optional().map_err(|_| Error::StorageUnavailable)?
                .ok_or(Error::Unavailable)?;
            budget.charge_bytes(usize::try_from(metadata_bytes).map_err(|_| Error::CorruptAuthority)?)?;
            let mut statement = self.conn.prepare(
                "SELECT length(payload), length(CAST(event_type AS BLOB))
                 FROM events WHERE timeline_id = ?1 ORDER BY seq",
            ).map_err(|_| Error::StorageUnavailable)?;
            let mut events = statement.query([timeline.to_string()])
                .map_err(|_| Error::StorageUnavailable)?;
            while let Some(row) = events.next().map_err(|_| Error::StorageUnavailable)? {
                budget.charge_rows(1)?;
                let payload = row_length(row, 0)?;
                let kind = row_length(row, 1)?;
                budget.charge_bytes(payload)?;
                budget.charge_bytes(kind)?;
            }
            let meta = self.get_timeline(timeline).map_err(|_| Error::Unavailable)?
                .ok_or(Error::Unavailable)?.meta;
            next = meta.fork_point.map(|(parent, _)| parent);
            depth += 1;
        }
        Ok(())
    }

    /// Length/count preflight happens on the held snapshot. It retrieves no
    /// variable-size blob before it has been charged against the ledger.
    fn preflight_fork_replay_records(&self, budget: &mut ForkReplayReadBudgetV1<'_>) -> ReadResult<()> {
        for (table, column) in [
            ("fork_principal_owner_bindings", "pob1_cbor"),
            ("imported_fork_principal_owner_bindings", "pob1_cbor"),
            ("fork_admissions", "far1_cbor"),
            ("fork_classifier_sources", "fcs1_cbor"),
            ("imported_fork_classifier_sources", "fcs1_cbor"),
            ("fork_classifier_tables", "fct1_cbor"),
            ("fork_classifier_registrations", "fcr1_cbor"),
            ("fork_append_operations", "fop1_cbor"),
            ("fork_event_origins", "eor1_cbor"),
            ("fork_intervention_admissions", "fia1_cbor"),
            ("fork_publication_operations", "fpo1_cbor"),
            ("fork_publication_bindings", "fpb1_cbor"),
            ("fork_publication_artifacts", "fpa1_cbor"),
            ("imported_fork_attribution_admissions", "ifa1_cbor"),
            ("imported_fork_key_evidence", "ikr1_cbor"),
            ("imported_fork_key_evidence", "ikt1_cbor"),
            ("key_registry", "state_cbor"),
        ] {
            // Both identifiers come exclusively from this fixed list.
            let sql = format!("SELECT typeof({column}), length({column}) FROM {table}");
            let mut statement = self.conn.prepare(&sql).map_err(|_| Error::StorageUnavailable)?;
            let mut records = statement.query(params![]).map_err(|_| Error::StorageUnavailable)?;
            while let Some(row) = records.next().map_err(|_| Error::StorageUnavailable)? {
                budget.charge_rows(1)?;
                let kind: String = row.get(0).map_err(|_| Error::StorageUnavailable)?;
                match kind.as_str() {
                    "null" if column == "ikt1_cbor" => {}
                    "blob" => budget.charge_bytes(
                        row_length(row, 1)?,
                    )?,
                    _ => return Err(Error::CorruptAuthority),
                }
            }
        }
        budget.check_time()
    }
}

fn row_length(row: &rusqlite::Row<'_>, column: usize) -> ReadResult<usize> {
    let length = row.get::<_, i64>(column).map_err(|_| Error::CorruptAuthority)?;
    usize::try_from(length).map_err(|_| Error::CorruptAuthority)
}
