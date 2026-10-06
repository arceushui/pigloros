//! `SQLite` adapter for the ADR-105 `FAE1` authority import.
//!
//! The import is one `BEGIN IMMEDIATE` transaction on the single database
//! file: the occupancy re-check, the staged child Timeline, the staged-range
//! check, and every row insert become visible at commit or not at all.
//! Imported code-2 `FAR1` and `FPO1` bytes sit in the same per-child tables as
//! local rows, where the strict local decoders reject them, so every trusted
//! read stays closed to code 2 until #519. An imported `POB1` lives in
//! `imported_fork_principal_owner_bindings`, keyed by its import operation ID,
//! so several imports can share one Principal and Owner (erratum E10) without
//! a second row in the local Principal table. The additive
//! `imported_fork_classifier_sources` store holds imported `FCS1` custody
//! apart from `fork_classifier_sources`.

use pos_core::{
    store::{EventStore, TimelineExport},
    EventId, ForkAdmissionErrorV1, Hash, ImportedPrincipalOwnerBindingV1, OwnerIdV1, TimelineId,
};
use rusqlite::{params, types::Value, Connection, OptionalExtension};

use super::{begin_immediate_sql, SqliteStore};
use crate::fork_attribution_authority_import::{
    run_import, ForkAttributionAuthorityImportErrorV1 as ImportError,
    ForkAttributionAuthorityImportPortV1, ForkAttributionAuthorityImportReceiptV1,
    ForkAttributionAuthorityImportRequestV1, ImportBackendV1, InstallPlanV1, InstalledRowsV1,
    StoredImportV1,
};

const STORED_IMPORT_SQL: &str = "SELECT ifa1_cbor, fae1_cbor, full_envelope_digest
    FROM imported_fork_attribution_admissions WHERE import_operation_id = ?1";
const KEY_EVIDENCE_PRESENT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM imported_fork_key_evidence
    WHERE import_operation_id = ?1)";
const KEY_EVIDENCE_SQL: &str = "SELECT ikr1_cbor, ikt1_cbor FROM imported_fork_key_evidence
    WHERE import_operation_id = ?1";
const BINDING_SQL: &str = "SELECT pob1_cbor FROM imported_fork_principal_owner_bindings
    WHERE import_operation_id = ?1";
const IMPORTED_BINDING_OPERATION_SQL: &str = "SELECT EXISTS(SELECT 1
    FROM imported_fork_principal_owner_bindings WHERE import_operation_id = ?1)";
const IMPORTED_PRINCIPAL_SQL: &str = "SELECT pob1_cbor FROM imported_fork_principal_owner_bindings
    WHERE principal_digest = ?1";
const ADMISSION_SQL: &str = "SELECT far1_cbor FROM fork_admissions WHERE child_id = ?1";
const ORIGIN_SQL: &str = "SELECT eor1_cbor FROM fork_event_origins WHERE event_id = ?1";
const INTERVENTION_SQL: &str =
    "SELECT fia1_cbor FROM fork_intervention_admissions WHERE event_id = ?1";
const SOURCE_SQL: &str =
    "SELECT fcs1_cbor FROM imported_fork_classifier_sources WHERE fcs1_digest = ?1";
const TABLE_SQL: &str = "SELECT fct1_cbor FROM fork_classifier_tables WHERE child_id = ?1";
const REGISTRATION_SQL: &str =
    "SELECT fcr1_cbor FROM fork_classifier_registrations WHERE child_id = ?1";
const OPERATIONS_SQL: &str =
    "SELECT fop1_cbor FROM fork_append_operations WHERE child_id = ?1 ORDER BY local_seq";
const PUBLICATION_OPERATION_SQL: &str =
    "SELECT fpo1_cbor FROM fork_publication_operations WHERE operation_id = ?1";
const PUBLICATION_BINDING_SQL: &str = "SELECT fpb1_cbor FROM fork_publication_bindings
    WHERE child_id = ?1 AND final_logical_head = ?2";
const PUBLICATION_ARTIFACT_SQL: &str =
    "SELECT fpa1_cbor FROM fork_publication_artifacts WHERE record_id = ?1";

/// Every semantic key of one import that is not an Event: the child, the
/// `POB1`, `FCR1`, and publication operation IDs, the publication head, and the
/// `FSM1` record ID. The parameters are the child ID, the final head, the
/// `POB1` operation ID, the publication operation ID, the record ID, and the
/// `FCR1` operation ID, which is `NULL` without a classifier.
const KEYS_HELD_SQL: &str = "SELECT
    EXISTS(SELECT 1 FROM timelines WHERE id = ?1)
    OR EXISTS(SELECT 1 FROM fork_admissions WHERE child_id = ?1)
    OR EXISTS(SELECT 1 FROM fork_classifier_tables WHERE child_id = ?1)
    OR EXISTS(SELECT 1 FROM fork_classifier_registrations
              WHERE child_id = ?1 OR operation_id = ?6)
    OR EXISTS(SELECT 1 FROM fork_append_operations WHERE child_id = ?1)
    OR EXISTS(SELECT 1 FROM imported_fork_attribution_admissions WHERE child_id = ?1)
    OR EXISTS(SELECT 1 FROM fork_principal_owner_bindings WHERE operation_id = ?3)
    OR EXISTS(SELECT 1 FROM imported_fork_principal_owner_bindings
              WHERE import_operation_id = ?3)
    OR EXISTS(SELECT 1 FROM fork_publication_bindings
              WHERE (child_id = ?1 AND final_logical_head = ?2)
                 OR operation_id = ?4 OR record_id = ?5)
    OR EXISTS(SELECT 1 FROM fork_publication_operations
              WHERE operation_id = ?4 OR record_id = ?5)
    OR EXISTS(SELECT 1 FROM fork_publication_artifacts
              WHERE operation_id = ?4 OR record_id = ?5)";
/// The keys of one Event: its ID in any table, its `FOP1` operation ID, and
/// its `EOR1` and `FIA1`. The parameters are the Event ID and the operation ID.
const EVENT_HELD_SQL: &str = "SELECT
    EXISTS(SELECT 1 FROM events WHERE event_id = ?1)
    OR EXISTS(SELECT 1 FROM fork_append_operations
              WHERE event_id = ?1 OR operation_id = ?2)
    OR EXISTS(SELECT 1 FROM fork_event_origins WHERE event_id = ?1)
    OR EXISTS(SELECT 1 FROM fork_intervention_admissions WHERE event_id = ?1)";

impl From<rusqlite::Error> for ImportError {
    /// Storage failure; for writes the commit state is unknown. No `SQLite`
    /// failure is trusted to prove what was or was not committed.
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageIndeterminate
    }
}

impl ForkAttributionAuthorityImportPortV1 for SqliteStore {
    fn import_verified(
        &mut self,
        request: &ForkAttributionAuthorityImportRequestV1<'_>,
    ) -> Result<ForkAttributionAuthorityImportReceiptV1, ImportError> {
        run_import(self, request)
    }
}

fn blob(hash: Hash) -> Value {
    Value::Blob(hash.as_bytes().to_vec())
}

fn child_key(child: TimelineId) -> Value {
    Value::Text(child.to_string())
}

fn event_key(event_id: EventId) -> Value {
    Value::Text(event_id.to_string())
}

/// One stored blob under one key, if any.
fn optional_blob(conn: &Connection, sql: &str, key: &Value) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row(sql, params![key], |row| row.get::<_, Vec<u8>>(0))
        .optional()
}

fn held(conn: &Connection, sql: &str, key: &Value) -> rusqlite::Result<bool> {
    conn.query_row(sql, params![key], |row| row.get::<_, bool>(0))
}

/// Whether the `POB1` Principal is bound to another Owner (erratum E10: an
/// equal Owner is no conflict; its operation ID is checked with the other
/// keys).
fn binding_held(conn: &Connection, plan: &InstallPlanV1<'_>) -> Result<bool, ImportError> {
    let binding = plan.closure().principal_owner_binding().input();
    let local = super::sqlite_principal_owner_binding(conn, binding.principal_digest)
        .map_err(admission_failure)?;
    if local.is_some_and(|record| record.input().owner != binding.owner) {
        return Ok(true);
    }
    imported_other_owner(conn, binding.principal_digest, binding.owner)
}

/// Whether an imported `POB1` binds `principal` to an Owner other than
/// `owner`.
pub(super) fn imported_other_owner(
    conn: &Connection,
    principal: Hash,
    owner: OwnerIdV1,
) -> Result<bool, ImportError> {
    let mut statement = conn.prepare(IMPORTED_PRINCIPAL_SQL)?;
    let rows: Vec<Vec<u8>> = statement
        .query_map(params![blob(principal)], |row| row.get::<_, Vec<u8>>(0))
        .and_then(Iterator::collect)?;
    for bytes in rows {
        let record = ImportedPrincipalOwnerBindingV1::from_canonical_cbor(&bytes)
            .map_err(|_| ImportError::CorruptAuthority)?;
        if record.input().owner != owner {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether an import already holds `operation_id` as its `POB1` operation ID.
pub(super) fn imported_binding_operation_held(
    conn: &Connection,
    operation_id: Hash,
) -> Result<bool, ImportError> {
    Ok(held(conn, IMPORTED_BINDING_OPERATION_SQL, &blob(operation_id))?)
}

/// Map a local Principal-binding read failure.
const fn admission_failure(error: ForkAdmissionErrorV1) -> ImportError {
    if matches!(error, ForkAdmissionErrorV1::StorageIndeterminate) {
        ImportError::StorageIndeterminate
    } else {
        ImportError::CorruptAuthority
    }
}

/// Map an imported Principal-binding read failure for a local `POB1`.
pub(super) const fn imported_owner_failure(error: ImportError) -> ForkAdmissionErrorV1 {
    if matches!(error, ImportError::StorageIndeterminate) {
        ForkAdmissionErrorV1::StorageIndeterminate
    } else {
        ForkAdmissionErrorV1::CorruptAuthority
    }
}

/// Whether any non-Event key of the import is held.
fn keys_held(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<bool> {
    let closure = plan.closure();
    let operation = closure.publication_operation().fields();
    let registration = closure
        .classifier()
        .map(|graph| blob(graph.registration.input().operation_id));
    conn.query_row(
        KEYS_HELD_SQL,
        params![
            child_key(plan.child()),
            plan.final_head(),
            blob(closure.principal_owner_binding().input().operation_id),
            blob(operation.operation_id),
            blob(operation.signed_manifest_record_id),
            registration,
        ],
        |row| row.get::<_, bool>(0),
    )
}

/// Whether any Event key of the import is held.
fn events_held(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<bool> {
    for record in plan.closure().append_operations() {
        let input = record.input();
        let held = conn.query_row(
            EVENT_HELD_SQL,
            params![event_key(input.event_id), blob(input.operation_id)],
            |row| row.get::<_, bool>(0),
        )?;
        if held {
            return Ok(true);
        }
    }
    Ok(false)
}

/// An identical imported `FCS1` row is reused; any other row under the same
/// digest is corrupt.
fn source_is_reusable(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<bool> {
    let Some(graph) = plan.closure().classifier() else {
        return Ok(true);
    };
    let stored = optional_blob(conn, SOURCE_SQL, &blob(graph.source.digest()))?;
    Ok(stored.is_none_or(|bytes| bytes == graph.source.to_canonical_cbor()))
}

fn read_operations(conn: &Connection, child: TimelineId) -> rusqlite::Result<Vec<Vec<u8>>> {
    let mut statement = conn.prepare(OPERATIONS_SQL)?;
    statement
        .query_map(params![child_key(child)], |row| row.get::<_, Vec<u8>>(0))
        .and_then(Iterator::collect)
}

fn read_event_rows(
    conn: &Connection,
    sql: &str,
    plan: &InstallPlanV1<'_>,
) -> rusqlite::Result<Vec<Option<Vec<u8>>>> {
    plan.event_ids()
        .into_iter()
        .map(|event_id| optional_blob(conn, sql, &event_key(event_id)))
        .collect()
}

/// The `FCR1`, `FCT1`, and `FCS1` rows under the keys of `plan`.
fn read_classifier_rows(
    conn: &Connection,
    plan: &InstallPlanV1<'_>,
) -> rusqlite::Result<[Option<Vec<u8>>; 3]> {
    let child = child_key(plan.child());
    let source = plan
        .closure()
        .classifier()
        .map(|graph| optional_blob(conn, SOURCE_SQL, &blob(graph.source.digest())))
        .transpose()?
        .flatten();
    Ok([
        source,
        optional_blob(conn, TABLE_SQL, &child)?,
        optional_blob(conn, REGISTRATION_SQL, &child)?,
    ])
}

/// The `FPO1`, `FPB1`, and `FPA1` rows under the keys of `plan`.
fn read_publication_rows(
    conn: &Connection,
    plan: &InstallPlanV1<'_>,
) -> rusqlite::Result<[Option<Vec<u8>>; 3]> {
    let closure = plan.closure();
    let operation_id = closure.publication_operation().fields().operation_id;
    let record_id = closure
        .publication_artifact()
        .input()
        .signed_manifest_record_id;
    let binding = conn
        .query_row(
            PUBLICATION_BINDING_SQL,
            params![child_key(plan.child()), plan.final_head()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok([
        optional_blob(conn, PUBLICATION_OPERATION_SQL, &blob(operation_id))?,
        binding,
        optional_blob(conn, PUBLICATION_ARTIFACT_SQL, &blob(record_id))?,
    ])
}

/// The stored `IKR1` and `IKT1` bytes of one import.
type KeyEvidenceRowsV1 = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The imported `IKR1` and optional `IKT1` stored for one import.
fn read_key_evidence(
    conn: &Connection,
    import_operation_id: Hash,
) -> rusqlite::Result<KeyEvidenceRowsV1> {
    let row = conn
        .query_row(
            KEY_EVIDENCE_SQL,
            params![blob(import_operation_id)],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .optional()?;
    Ok(row.map_or((None, None), |(record, tombstone)| {
        (Some(record), tombstone)
    }))
}

fn insert_authority_rows(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<()> {
    let closure = plan.closure();
    let binding = closure.principal_owner_binding();
    conn.execute(
        "INSERT INTO imported_fork_principal_owner_bindings
         (import_operation_id, principal_digest, pob1_cbor)
         VALUES (?1, ?2, ?3)",
        params![
            blob(binding.input().operation_id),
            blob(binding.input().principal_digest),
            binding.to_canonical_cbor(),
        ],
    )?;
    conn.execute(
        "INSERT INTO fork_admissions (child_id, far1_cbor) VALUES (?1, ?2)",
        params![
            child_key(plan.child()),
            closure.fork_admission().to_canonical_cbor()
        ],
    )?;
    Ok(())
}

fn insert_event_rows(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<()> {
    let closure = plan.closure();
    for record in closure.event_origins() {
        conn.execute(
            "INSERT INTO fork_event_origins (event_id, eor1_cbor) VALUES (?1, ?2)",
            params![
                event_key(record.input().event_id),
                record.to_canonical_cbor()
            ],
        )?;
    }
    for record in closure.intervention_admissions() {
        conn.execute(
            "INSERT INTO fork_intervention_admissions (event_id, fia1_cbor) VALUES (?1, ?2)",
            params![
                event_key(record.input().event_id),
                record.to_canonical_cbor()
            ],
        )?;
    }
    let sequences = plan.local_sequences();
    for (record, local_seq) in closure.append_operations().iter().zip(sequences) {
        conn.execute(
            "INSERT INTO fork_append_operations
             (operation_id, child_id, local_seq, event_id, fop1_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                blob(record.input().operation_id),
                child_key(plan.child()),
                local_seq,
                event_key(record.input().event_id),
                record.to_canonical_cbor(),
            ],
        )?;
    }
    Ok(())
}

fn insert_classifier_rows(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<()> {
    let Some(graph) = plan.closure().classifier() else {
        return Ok(());
    };
    conn.execute(
        "INSERT OR IGNORE INTO imported_fork_classifier_sources (fcs1_digest, fcs1_cbor)
         VALUES (?1, ?2)",
        params![
            blob(graph.source.digest()),
            graph.source.to_canonical_cbor()
        ],
    )?;
    conn.execute(
        "INSERT INTO fork_classifier_tables (child_id, fct1_digest, fct1_cbor)
         VALUES (?1, ?2, ?3)",
        params![
            child_key(plan.child()),
            blob(graph.table.digest()),
            graph.table.to_canonical_cbor(),
        ],
    )?;
    conn.execute(
        "INSERT INTO fork_classifier_registrations (operation_id, child_id, fcr1_cbor)
         VALUES (?1, ?2, ?3)",
        params![
            blob(graph.registration.input().operation_id),
            child_key(plan.child()),
            graph.registration.to_canonical_cbor(),
        ],
    )?;
    Ok(())
}

fn insert_publication_rows(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<()> {
    let closure = plan.closure();
    let operation = closure.publication_operation();
    let operation_id = operation.fields().operation_id;
    let record_id = operation.fields().signed_manifest_record_id;
    conn.execute(
        "INSERT INTO fork_publication_operations (operation_id, record_id, fpo1_cbor)
         VALUES (?1, ?2, ?3)",
        params![
            blob(operation_id),
            blob(record_id),
            operation.to_canonical_cbor()
        ],
    )?;
    conn.execute(
        "INSERT INTO fork_publication_bindings
         (child_id, final_logical_head, operation_id, record_id, fpb1_cbor)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            child_key(plan.child()),
            plan.final_head(),
            blob(operation_id),
            blob(record_id),
            closure.publication_binding().to_canonical_cbor(),
        ],
    )?;
    conn.execute(
        "INSERT INTO fork_publication_artifacts (record_id, operation_id, fpa1_cbor)
         VALUES (?1, ?2, ?3)",
        params![
            blob(record_id),
            blob(operation_id),
            closure.publication_artifact().to_canonical_cbor(),
        ],
    )?;
    Ok(())
}

fn insert_admission_rows(conn: &Connection, plan: &InstallPlanV1<'_>) -> rusqlite::Result<()> {
    let operation_id = blob(plan.import_operation_id());
    let tombstone = plan
        .key_tombstone()
        .map(|record| record.to_canonical_cbor());
    conn.execute(
        "INSERT INTO imported_fork_key_evidence (import_operation_id, ikr1_cbor, ikt1_cbor)
         VALUES (?1, ?2, ?3)",
        params![
            operation_id,
            plan.key_record().to_canonical_cbor(),
            tombstone
        ],
    )?;
    conn.execute(
        "INSERT INTO imported_fork_attribution_admissions
         (import_operation_id, child_id, full_envelope_digest, ifa1_cbor, fae1_cbor)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            operation_id,
            child_key(plan.child()),
            blob(plan.admission.input().full_envelope_digest),
            plan.admission.to_canonical_cbor(),
            plan.prepared.bytes,
        ],
    )?;
    Ok(())
}

/// Commit a successful body or roll back a failed one; any unknown commit or
/// rollback outcome is `StorageIndeterminate`.
fn finish_import<T>(conn: &Connection, result: Result<T, ImportError>) -> Result<T, ImportError> {
    let committed = result.and_then(|value| {
        conn.execute_batch("COMMIT")
            .map(|()| value)
            .map_err(ImportError::from)
    });
    let Err(error) = committed else {
        return committed;
    };
    // A failed body or commit is rolled back; if that fails too, the outcome
    // of the whole transaction is unknown.
    let rolled_back = conn.execute_batch("ROLLBACK").is_ok();
    Err(if rolled_back {
        error
    } else {
        ImportError::StorageIndeterminate
    })
}

impl ImportBackendV1 for SqliteStore {
    fn read_stored_import(
        &self,
        import_operation_id: Hash,
    ) -> Result<Option<StoredImportV1>, ImportError> {
        let row = self
            .conn
            .query_row(
                STORED_IMPORT_SQL,
                params![blob(import_operation_id)],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, [u8; 32]>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(
            row.map(|(admission_bytes, envelope_bytes, digest)| StoredImportV1 {
                admission_bytes,
                envelope_bytes,
                envelope_digest: Hash::from_bytes(digest),
            }),
        )
    }

    fn has_key_evidence(&self, import_operation_id: Hash) -> Result<bool, ImportError> {
        Ok(held(
            &self.conn,
            KEY_EVIDENCE_PRESENT_SQL,
            &blob(import_operation_id),
        )?)
    }

    fn read_installed(&self, plan: &InstallPlanV1<'_>) -> Result<InstalledRowsV1, ImportError> {
        let conn = &self.conn;
        let binding = plan
            .closure()
            .principal_owner_binding()
            .input()
            .operation_id;
        let [source, table, registration] = read_classifier_rows(conn, plan)?;
        let [publication_operation, publication_binding, publication_artifact] =
            read_publication_rows(conn, plan)?;
        let (key_record, key_tombstone) = read_key_evidence(conn, plan.import_operation_id())?;
        Ok(InstalledRowsV1 {
            binding: optional_blob(conn, BINDING_SQL, &blob(binding))?,
            admission: optional_blob(conn, ADMISSION_SQL, &child_key(plan.child()))?,
            origins: read_event_rows(conn, ORIGIN_SQL, plan)?,
            interventions: read_event_rows(conn, INTERVENTION_SQL, plan)?,
            source,
            table,
            registration,
            operations: read_operations(conn, plan.child())?,
            publication_operation,
            publication_binding,
            publication_artifact,
            key_record,
            key_tombstone,
        })
    }

    fn occupied(&self, plan: &InstallPlanV1<'_>) -> Result<bool, ImportError> {
        let conn = &self.conn;
        if !source_is_reusable(conn, plan)? {
            return Err(ImportError::CorruptAuthority);
        }
        Ok(keys_held(conn, plan)? || binding_held(conn, plan)? || events_held(conn, plan)?)
    }

    fn stage_child(&mut self, export: &TimelineExport) -> Result<(), ImportError> {
        self.create_timeline_with_meta(export.timeline.meta.clone())?;
        self.append_committed(export.timeline.id(), &export.events)?;
        Ok(())
    }

    fn install_rows(&mut self, plan: &InstallPlanV1<'_>) -> Result<(), ImportError> {
        let conn = &self.conn;
        insert_authority_rows(conn, plan)?;
        insert_event_rows(conn, plan)?;
        insert_classifier_rows(conn, plan)?;
        insert_publication_rows(conn, plan)?;
        insert_admission_rows(conn, plan)?;
        Ok(())
    }

    fn atomically<T, F>(&mut self, _child: TimelineId, body: F) -> Result<T, ImportError>
    where
        F: FnOnce(&mut Self) -> Result<T, ImportError>,
    {
        self.conn.execute_batch(begin_immediate_sql())?;
        let result = body(self);
        finish_import(&self.conn, result)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::ForkAttributionImportClosureV1;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    use super::*;
    use crate::fae1_fixture::{
        first, hash, pin_policy, request_for, Built, Fallible, Shape, Spec, World, PARENT_CUT,
    };

    type Outcome = Result<ForkAttributionAuthorityImportReceiptV1, ImportError>;

    const CORRUPT: ImportError = ImportError::CorruptAuthority;
    const INDETERMINATE: ImportError = ImportError::StorageIndeterminate;

    /// The tables that hold one import, in install order.
    const IMPORT_TABLES: [&str; 13] = [
        "imported_fork_principal_owner_bindings",
        "fork_admissions",
        "fork_event_origins",
        "fork_intervention_admissions",
        "fork_append_operations",
        "imported_fork_classifier_sources",
        "fork_classifier_tables",
        "fork_classifier_registrations",
        "fork_publication_operations",
        "fork_publication_bindings",
        "fork_publication_artifacts",
        "imported_fork_key_evidence",
        "imported_fork_attribution_admissions",
    ];

    /// The keys of the default import, as SQL literals.
    struct Keys {
        child: String,
        event: String,
        operation: String,
        registration: String,
        binding: String,
        publication: String,
        record: String,
        head: u64,
    }

    fn literal(value: Hash) -> String {
        let digits = value
            .as_bytes()
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 15])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect::<String>();
        format!("x'{digits}'")
    }

    fn import_keys(world: &World, closure: &ForkAttributionImportClosureV1) -> Fallible<Keys> {
        let binding = closure.principal_owner_binding().input();
        let graph = closure.classifier().ok_or("no classifier")?;
        let publication = closure.publication_operation().fields();
        Ok(Keys {
            child: format!("'{}'", world.child_at(0)?.id),
            event: format!("'{}'", first(closure.event_origins())?.input().event_id),
            operation: literal(first(closure.append_operations())?.input().operation_id),
            registration: literal(graph.registration.input().operation_id),
            binding: literal(binding.operation_id),
            publication: literal(publication.operation_id),
            record: literal(publication.signed_manifest_record_id),
            head: PARENT_CUT + 4,
        })
    }

    fn prepared(world: &World, built: &Built) -> Fallible<SqliteStore> {
        let mut store = SqliteStore::open_in_memory()?;
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        Ok(store)
    }

    /// A default import in a store, plus everything needed to tamper with it.
    struct Imported {
        world: World,
        built: Built,
        store: SqliteStore,
        keys: Keys,
    }

    impl Imported {
        fn new() -> Fallible<Self> {
            let world = World::new(Shape::Mixed, false)?;
            let built = world.build(&Spec::default())?;
            let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
            let keys = import_keys(&world, &closure)?;
            let mut store = prepared(&world, &built)?;
            store.import_verified(&request_for(&world, &built))?;
            Ok(Self {
                world,
                built,
                store,
                keys,
            })
        }

        fn retry(&mut self) -> Outcome {
            self.store
                .import_verified(&request_for(&self.world, &self.built))
        }

        fn execute(&self, statement: &str) -> Fallible<()> {
            self.store.conn.execute_batch(statement)?;
            Ok(())
        }
    }

    fn deny(store: &SqliteStore, denied: TransactionOperation) -> rusqlite::Result<()> {
        store.conn.authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Transaction { operation } if operation == denied
            ) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))
    }

    fn allow_all(store: &SqliteStore) -> rusqlite::Result<()> {
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
    }

    fn row_count(store: &SqliteStore, table: &str) -> rusqlite::Result<i64> {
        store
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
    }

    fn assert_nothing_installed(store: &SqliteStore, world: &World) -> Fallible<()> {
        for table in IMPORT_TABLES {
            assert_eq!(row_count(store, table)?, 0, "{table} must be empty");
        }
        assert_eq!(store.get_timeline(world.child_at(0)?.id)?, None);
        Ok(())
    }

    #[test]
    fn every_import_table_holds_the_committed_graph() -> Fallible<()> {
        let imported = Imported::new()?;
        for table in IMPORT_TABLES {
            assert!(row_count(&imported.store, table)? >= 1, "{table} is empty");
        }
        assert_eq!(row_count(&imported.store, "fork_append_operations")?, 4);
        assert_eq!(
            row_count(&imported.store, "fork_intervention_admissions")?,
            2
        );
        Ok(())
    }

    /// Statements that each break one committed import.
    fn tamperings(keys: &Keys) -> Vec<String> {
        let Keys {
            child,
            event,
            operation,
            ..
        } = keys;
        let mut all = vec![
            format!("DELETE FROM fork_append_operations WHERE operation_id = {operation}"),
            format!("DELETE FROM fork_classifier_tables WHERE child_id = {child}"),
            format!("DELETE FROM fork_classifier_registrations WHERE child_id = {child}"),
            format!("DELETE FROM fork_event_origins WHERE event_id = {event}"),
            format!("DELETE FROM fork_admissions WHERE child_id = {child}"),
            "DELETE FROM imported_fork_principal_owner_bindings".to_owned(),
            "DELETE FROM fork_publication_operations".to_owned(),
            "DELETE FROM fork_publication_bindings".to_owned(),
            "DELETE FROM fork_publication_artifacts".to_owned(),
            "DELETE FROM imported_fork_classifier_sources".to_owned(),
            "DELETE FROM imported_fork_key_evidence".to_owned(),
            // An orphan: the key evidence outlives its admission row.
            "DELETE FROM imported_fork_attribution_admissions".to_owned(),
            format!(
                "INSERT INTO fork_intervention_admissions (event_id, fia1_cbor)
                 VALUES ({event}, x'00')"
            ),
            format!(
                "INSERT INTO fork_append_operations
                 (operation_id, child_id, local_seq, event_id, fop1_cbor)
                 VALUES (zeroblob(32), {child}, 99, 'extra-event', x'00')"
            ),
            format!("DELETE FROM events WHERE timeline_id = {child} AND seq = 4"),
            "UPDATE imported_fork_attribution_admissions SET fae1_cbor = x'00'".to_owned(),
            "UPDATE imported_fork_attribution_admissions SET ifa1_cbor = x'00'".to_owned(),
            "UPDATE imported_fork_attribution_admissions
             SET full_envelope_digest = zeroblob(32)"
                .to_owned(),
            "UPDATE fork_attribution_issuer_policies SET fip1_cbor = x'00'".to_owned(),
        ];
        for (table, column) in [
            ("fork_admissions", "far1_cbor"),
            ("fork_classifier_tables", "fct1_cbor"),
            ("fork_classifier_registrations", "fcr1_cbor"),
            ("fork_append_operations", "fop1_cbor"),
            ("fork_event_origins", "eor1_cbor"),
            ("fork_intervention_admissions", "fia1_cbor"),
            ("imported_fork_principal_owner_bindings", "pob1_cbor"),
            ("fork_publication_operations", "fpo1_cbor"),
            ("fork_publication_bindings", "fpb1_cbor"),
            ("fork_publication_artifacts", "fpa1_cbor"),
            ("imported_fork_classifier_sources", "fcs1_cbor"),
            ("imported_fork_key_evidence", "ikr1_cbor"),
        ] {
            all.push(format!(
                "UPDATE {table} SET {column} = x'00'
                 WHERE rowid = (SELECT MIN(rowid) FROM {table})"
            ));
        }
        all
    }

    #[test]
    fn a_missing_extra_or_altered_installed_row_is_corrupt() -> Fallible<()> {
        let count = tamperings(&Imported::new()?.keys).len();
        for index in 0..count {
            // Every statement names the keys of its own world.
            let mut state = Imported::new()?;
            let statement = tamperings(&state.keys)
                .into_iter()
                .nth(index)
                .ok_or("no such statement")?;
            state.execute(&statement)?;
            assert_eq!(state.retry(), Err(CORRUPT), "{statement}");
        }
        Ok(())
    }

    #[test]
    fn an_unreadable_table_is_indeterminate_for_a_retry_and_a_new_import() -> Fallible<()> {
        for table in IMPORT_TABLES.into_iter().chain(["events"]) {
            let mut state = Imported::new()?;
            state.execute(&format!("DROP TABLE {table}"))?;
            assert_eq!(state.retry(), Err(INDETERMINATE), "{table}");
        }
        for table in IMPORT_TABLES {
            let world = World::new(Shape::Mixed, false)?;
            let built = world.build(&Spec::default())?;
            let mut store = prepared(&world, &built)?;
            store.conn.execute_batch(&format!("DROP TABLE {table}"))?;
            let outcome = store.import_verified(&request_for(&world, &built));
            assert_eq!(outcome, Err(INDETERMINATE), "{table}");
        }
        Ok(())
    }

    #[test]
    fn a_tampered_shared_source_blocks_a_second_import() -> Fallible<()> {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::Mixed)?;
        let initial = world.build(&Spec::default())?;
        let second = world.build(&Spec::distinct(1))?;
        let mut store = prepared(&world, &initial)?;
        store.import_verified(&request_for(&world, &initial))?;
        store
            .conn
            .execute_batch("UPDATE imported_fork_classifier_sources SET fcs1_cbor = x'00'")?;
        let outcome = store.import_verified(&request_for(&world, &second));
        assert_eq!(outcome, Err(CORRUPT));
        assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
        Ok(())
    }

    /// Statements that occupy a key naming the child Fork.
    fn child_occupations(keys: &Keys) -> Vec<String> {
        let child = &keys.child;
        vec![
            format!(
                "INSERT INTO timelines (id, mode, chain_head)
                 VALUES ({child}, 'Historical', zeroblob(32))"
            ),
            format!("INSERT INTO fork_admissions (child_id, far1_cbor) VALUES ({child}, x'00')"),
            format!(
                "INSERT INTO fork_classifier_tables (child_id, fct1_digest, fct1_cbor)
                 VALUES ({child}, zeroblob(32), x'00')"
            ),
            format!(
                "INSERT INTO fork_classifier_registrations (operation_id, child_id, fcr1_cbor)
                 VALUES (zeroblob(32), {child}, x'00')"
            ),
            format!(
                "INSERT INTO fork_append_operations
                 (operation_id, child_id, local_seq, event_id, fop1_cbor)
                 VALUES (zeroblob(32), {child}, 1, 'other-event', x'00')"
            ),
            format!(
                "INSERT INTO imported_fork_attribution_admissions
                 (import_operation_id, child_id, full_envelope_digest, ifa1_cbor, fae1_cbor)
                 VALUES (zeroblob(32), {child}, zeroblob(32), x'00', x'00')"
            ),
        ]
    }

    /// Statements that occupy an operation, Principal, or Event key.
    fn key_occupations(keys: &Keys) -> Vec<String> {
        let Keys {
            event,
            operation,
            registration,
            binding,
            ..
        } = keys;
        vec![
            format!(
                "INSERT INTO fork_principal_owner_bindings
                 (operation_id, principal_digest, pob1_cbor)
                 VALUES ({binding}, zeroblob(32), x'00')"
            ),
            format!(
                "INSERT INTO imported_fork_principal_owner_bindings
                 (import_operation_id, principal_digest, pob1_cbor)
                 VALUES ({binding}, zeroblob(32), x'00')"
            ),
            format!(
                "INSERT INTO fork_classifier_registrations (operation_id, child_id, fcr1_cbor)
                 VALUES ({registration}, 'other-child', x'00')"
            ),
            format!(
                "INSERT INTO fork_append_operations
                 (operation_id, child_id, local_seq, event_id, fop1_cbor)
                 VALUES ({operation}, 'other-child', 1, 'other-event', x'00')"
            ),
            format!(
                "INSERT INTO fork_append_operations
                 (operation_id, child_id, local_seq, event_id, fop1_cbor)
                 VALUES (zeroblob(32), 'other-child', 1, {event}, x'00')"
            ),
            format!("INSERT INTO fork_event_origins (event_id, eor1_cbor) VALUES ({event}, x'00')"),
            format!(
                "INSERT INTO fork_intervention_admissions (event_id, fia1_cbor)
                 VALUES ({event}, x'00')"
            ),
            format!(
                "INSERT INTO events (timeline_id, seq, event_id, entity_id, event_type, payload,
                 wall_time, schema_version, payload_hash, origin_timeline_id, origin_logical_seq)
                 VALUES ('other-child', 1, {event}, 'entity', 'kind', x'00', 0, 1, zeroblob(32),
                 'other-child', 1)"
            ),
        ]
    }

    /// Statements that occupy a publication Fork and head, operation, or
    /// record key.
    fn publication_occupations(keys: &Keys) -> Vec<String> {
        let Keys {
            child,
            publication,
            record,
            head,
            ..
        } = keys;
        vec![
            format!(
                "INSERT INTO fork_publication_bindings
                 (child_id, final_logical_head, operation_id, record_id, fpb1_cbor)
                 VALUES ({child}, {head}, zeroblob(32), randomblob(32), x'00')"
            ),
            format!(
                "INSERT INTO fork_publication_bindings
                 (child_id, final_logical_head, operation_id, record_id, fpb1_cbor)
                 VALUES ('other-child', 1, {publication}, randomblob(32), x'00')"
            ),
            format!(
                "INSERT INTO fork_publication_bindings
                 (child_id, final_logical_head, operation_id, record_id, fpb1_cbor)
                 VALUES ('other-child', 1, randomblob(32), {record}, x'00')"
            ),
            format!(
                "INSERT INTO fork_publication_operations (operation_id, record_id, fpo1_cbor)
                 VALUES ({publication}, randomblob(32), x'00')"
            ),
            format!(
                "INSERT INTO fork_publication_operations (operation_id, record_id, fpo1_cbor)
                 VALUES (randomblob(32), {record}, x'00')"
            ),
            format!(
                "INSERT INTO fork_publication_artifacts (record_id, operation_id, fpa1_cbor)
                 VALUES ({record}, randomblob(32), x'00')"
            ),
            format!(
                "INSERT INTO fork_publication_artifacts (record_id, operation_id, fpa1_cbor)
                 VALUES (randomblob(32), {publication}, x'00')"
            ),
        ]
    }

    #[test]
    fn every_occupied_key_is_a_conflict() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let keys = import_keys(&world, &closure)?;
        let occupations = child_occupations(&keys)
            .into_iter()
            .chain(key_occupations(&keys))
            .chain(publication_occupations(&keys));
        for occupation in occupations {
            let mut store = prepared(&world, &built)?;
            store.conn.execute_batch(&occupation)?;
            let outcome = store.import_verified(&request_for(&world, &built));
            assert_eq!(outcome, Err(ImportError::Conflict), "{occupation}");
            let seeded = occupation.contains("INTO imported_fork_attribution_admissions");
            let admissions = row_count(&store, "imported_fork_attribution_admissions")?;
            assert_eq!(admissions, i64::from(seeded), "{occupation}");
            assert_eq!(row_count(&store, "imported_fork_key_evidence")?, 0);
        }
        Ok(())
    }

    #[test]
    fn a_principal_forking_twice_keeps_one_owner_and_its_own_pob1_per_import() -> Fallible<()> {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::Mixed)?;
        let initial = world.build(&Spec::default())?;
        let second = world.build(&Spec {
            principal_seed: 0x22,
            ..Spec::distinct(1)
        })?;
        let mut store = prepared(&world, &initial)?;
        let one = store.import_verified(&request_for(&world, &initial))?;
        let two = store.import_verified(&request_for(&world, &second))?;
        assert_ne!(one, two);
        assert_eq!(row_count(&store, "fork_principal_owner_bindings")?, 0);
        assert_eq!(
            row_count(&store, "imported_fork_principal_owner_bindings")?,
            2
        );
        assert_eq!(
            store.import_verified(&request_for(&world, &initial)),
            Ok(one)
        );
        assert_eq!(
            store.import_verified(&request_for(&world, &second)),
            Ok(two)
        );
        Ok(())
    }

    #[test]
    fn another_owner_for_an_imported_principal_is_a_conflict() -> Fallible<()> {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::Mixed)?;
        let initial = world.build(&Spec::default())?;
        let other = world.build(&Spec {
            creator: "creator-b",
            principal_seed: 0x22,
            ..Spec::distinct(1)
        })?;
        let mut store = prepared(&world, &initial)?;
        store.import_verified(&request_for(&world, &initial))?;
        let outcome = store.import_verified(&request_for(&world, &other));
        assert_eq!(outcome, Err(ImportError::Conflict));
        assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
        assert_eq!(
            row_count(&store, "imported_fork_principal_owner_bindings")?,
            1
        );
        Ok(())
    }

    #[test]
    fn a_local_principal_binding_conflicts_only_for_another_owner() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        for (creator, expected) in [
            ("creator-a", None),
            ("creator-b", Some(ImportError::Conflict)),
        ] {
            let local =
                pos_core::PrincipalOwnerBindingV1::new(pos_core::PrincipalOwnerBindingInputV1 {
                    operation_id: hash(0x5a),
                    principal_digest: hash(0x22),
                    owner: pos_core::OwnerIdV1::new(creator)?,
                    origin: pos_core::ForkAuthorityOriginV1::Local,
                })?;
            let mut store = prepared(&world, &built)?;
            store.conn.execute(
                "INSERT INTO fork_principal_owner_bindings
                 (operation_id, principal_digest, pob1_cbor) VALUES (?1, ?2, ?3)",
                params![
                    hash(0x5a).as_bytes().as_slice(),
                    hash(0x22).as_bytes().as_slice(),
                    local.to_canonical_cbor(),
                ],
            )?;
            let outcome = store.import_verified(&request_for(&world, &built));
            assert_eq!(outcome.err(), expected, "{creator}");
            assert_eq!(row_count(&store, "fork_principal_owner_bindings")?, 1);
        }
        Ok(())
    }

    #[test]
    fn an_unreadable_imported_principal_binding_is_corrupt() -> Fallible<()> {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::Mixed)?;
        let initial = world.build(&Spec::default())?;
        let second = world.build(&Spec {
            principal_seed: 0x22,
            ..Spec::distinct(1)
        })?;
        let mut store = prepared(&world, &initial)?;
        store.import_verified(&request_for(&world, &initial))?;
        store
            .conn
            .execute_batch("UPDATE imported_fork_principal_owner_bindings SET pob1_cbor = x'00'")?;
        let outcome = store.import_verified(&request_for(&world, &second));
        assert_eq!(outcome, Err(CORRUPT));
        Ok(())
    }

    #[test]
    fn principal_failures_map_to_import_and_admission_errors() {
        use pos_core::ForkAdmissionErrorV1 as Admission;
        assert_eq!(admission_failure(Admission::StorageIndeterminate), INDETERMINATE);
        assert_eq!(admission_failure(Admission::CorruptAuthority), CORRUPT);
        assert_eq!(
            imported_owner_failure(INDETERMINATE),
            Admission::StorageIndeterminate
        );
        assert_eq!(imported_owner_failure(CORRUPT), Admission::CorruptAuthority);
    }

    #[test]
    fn an_unreadable_imported_principal_store_is_indeterminate() -> Fallible<()> {
        let owner = pos_core::OwnerIdV1::new("creator-a")?;
        let mut state = Imported::new()?;
        // A text value where a blob belongs fails the row read.
        state.execute("UPDATE imported_fork_principal_owner_bindings SET pob1_cbor = 'text'")?;
        assert_eq!(
            imported_other_owner(&state.store.conn, hash(0x22), owner),
            Err(INDETERMINATE)
        );
        state.execute("DROP TABLE imported_fork_principal_owner_bindings")?;
        assert_eq!(
            imported_other_owner(&state.store.conn, hash(0x22), owner),
            Err(INDETERMINATE)
        );
        Ok(())
    }

    #[test]
    fn an_unreadable_local_principal_binding_is_corrupt() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = prepared(&world, &built)?;
        store.conn.execute(
            "INSERT INTO fork_principal_owner_bindings
             (operation_id, principal_digest, pob1_cbor) VALUES (?1, ?2, x'00')",
            params![hash(0x5a).as_bytes().as_slice(), hash(0x22).as_bytes().as_slice()],
        )?;
        let outcome = store.import_verified(&request_for(&world, &built));
        assert_eq!(outcome, Err(CORRUPT));
        Ok(())
    }

    #[test]
    fn a_stored_row_of_the_wrong_type_is_indeterminate() -> Fallible<()> {
        let tampers = [
            "UPDATE imported_fork_key_evidence SET ikr1_cbor = 'text'",
            "UPDATE imported_fork_key_evidence SET ikt1_cbor = 'text'",
            "UPDATE imported_fork_attribution_admissions SET ifa1_cbor = 'text'",
            "UPDATE imported_fork_attribution_admissions SET fae1_cbor = 'text'",
            "UPDATE imported_fork_attribution_admissions
             SET full_envelope_digest = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
        ];
        for tamper in tampers {
            let mut state = Imported::new()?;
            state.execute(tamper)?;
            assert_eq!(state.retry(), Err(INDETERMINATE), "{tamper}");
        }
        Ok(())
    }

    #[test]
    fn local_classifier_custody_is_never_read_or_changed() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = prepared(&world, &built)?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let graph = closure.classifier().ok_or("no classifier")?;
        let source = graph.source.input();
        store.conn.execute(
            "INSERT INTO fork_classifier_sources (descriptor_hash, registrar_identifier, fcs1_cbor)
             VALUES (?1, ?2, x'00')",
            params![
                source.room_revision_descriptor_hash.as_bytes().as_slice(),
                source.registrar_identifier,
            ],
        )?;
        store.import_verified(&request_for(&world, &built))?;
        assert_eq!(row_count(&store, "fork_classifier_sources")?, 1);
        assert_eq!(row_count(&store, "imported_fork_classifier_sources")?, 1);
        Ok(())
    }

    #[test]
    fn begin_commit_and_rollback_failures_are_indeterminate() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = prepared(&world, &built)?;
        deny(&store, TransactionOperation::Begin)?;
        let outcome = store.import_verified(&request_for(&world, &built));
        assert_eq!(outcome, Err(INDETERMINATE));
        allow_all(&store)?;
        assert_nothing_installed(&store, &world)?;

        // A denied COMMIT rolls back, so the identical retry installs it.
        deny(&store, TransactionOperation::Unknown)?;
        let outcome = store.import_verified(&request_for(&world, &built));
        assert_eq!(outcome, Err(INDETERMINATE));
        allow_all(&store)?;
        assert_nothing_installed(&store, &world)?;
        let receipt = store.import_verified(&request_for(&world, &built))?;
        assert_eq!(
            store.import_verified(&request_for(&world, &built)),
            Ok(receipt)
        );

        // A failed body whose rollback is also denied is indeterminate.
        let wrong = world.build(&Spec {
            final_hash: Some(hash(0x99)),
            import_seed: 0x13,
            ..Spec::distinct(0)
        })?;
        let mut store = prepared(&world, &wrong)?;
        deny(&store, TransactionOperation::Rollback)?;
        let outcome = store.import_verified(&request_for(&world, &wrong));
        assert_eq!(outcome, Err(INDETERMINATE));
        Ok(())
    }

    #[test]
    fn a_failed_insert_stage_or_append_installs_nothing() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        for table in IMPORT_TABLES.into_iter().chain(["timelines", "events"]) {
            let mut store = prepared(&world, &built)?;
            store.conn.execute_batch(&format!(
                "CREATE TRIGGER fault BEFORE INSERT ON {table}
                 BEGIN SELECT RAISE(ABORT, 'injected fault'); END;"
            ))?;
            let outcome = store.import_verified(&request_for(&world, &built));
            assert_eq!(outcome, Err(INDETERMINATE), "{table}");
            store.conn.execute_batch("DROP TRIGGER fault")?;
            // The rollback left nothing behind, so the retry installs it.
            assert!(store.import_verified(&request_for(&world, &built)).is_ok());
        }
        Ok(())
    }

    #[test]
    fn a_range_failure_rolls_the_staged_child_back() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let wrong = world.build(&Spec {
            final_hash: Some(hash(0x99)),
            ..Spec::default()
        })?;
        let mut store = prepared(&world, &wrong)?;
        let outcome = store.import_verified(&request_for(&world, &wrong));
        assert_eq!(outcome, Err(ImportError::InvalidRangeEvidence));
        assert_nothing_installed(&store, &world)?;
        Ok(())
    }

    #[test]
    fn the_admission_table_ceiling_matches_the_ifa1_bound() {
        let bound = format!(
            "CHECK (length(ifa1_cbor) BETWEEN 1 AND {})",
            pos_core::MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1
        );
        let found = crate::sqlite::FORK_ADMISSION_SCHEMA_TABLES
            .iter()
            .filter(|table| table.name == "imported_fork_attribution_admissions")
            .flat_map(|table| table.constraints.iter().copied())
            .any(|constraint| constraint == bound);
        assert!(found);
    }
}
