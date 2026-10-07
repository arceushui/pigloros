//! `SQLite` side of the ADR-105 r6 R6.9 trusted reads.
//!
//! Validator (a) is the existing local-only admission and classified graph,
//! which every write path keeps. Validator (b) is this module: for a local
//! `FAR1` it is exactly validator (a), and for a code-2 `FAR1` it replaces
//! only the `FCC1` admission row, with the import admission row, and the local
//! `FCS1` custody table, with the imported `FCS1` table keyed by `FCT1` field
//! 6. An imported `FAR1` sits in `fork_admissions` next to the local rows, where
//! the strict local decoder rejects it, so only this module decodes code 2.

use pos_core::{
    ForkClassifierRegistrationV1, ForkClassifierSourceV1, Hasher, ImportedForkAdmissionRecordV1,
    ImportedForkAttributionAdmissionV1, ImportedForkClassifierGraphV1, ImportedKeyRecordV1,
    ImportedKeyTombstoneV1, TimelineId,
};
use rusqlite::{params, Connection, OptionalExtension, ToSql};

use super::{
    sqlite_classified_authority_graph, sqlite_fork_classifier_table, sqlite_local_fork_admission,
    FORK_ADMISSION_FAR1_SQL, FORK_CLASSIFIER_REGISTRATION_SQL,
};
use crate::{
    fork_event_authority::{
        imported_admission_matches, imported_graph_matches, AuthorityValidatorV1,
        ValidatedAdmissionV1, ValidatedGraphV1,
    },
    fork_manifest_publication::{
        PublicationSourceErrorV1, PublicationSourceResultV1, RetainedImportedKeyV1,
        RetainedKeyEvidenceV1,
    },
    ForkEventAuthorityErrorV1 as AuthorityError,
};

const IMPORT_ADMISSION_SQL: &str =
    "SELECT ifa1_cbor FROM imported_fork_attribution_admissions WHERE child_id = ?1";
const IMPORTED_SOURCE_SQL: &str =
    "SELECT fcs1_cbor FROM imported_fork_classifier_sources WHERE fcs1_digest = ?1";
/// The `IKR1` and `IKT1` of an import, selected through the import admission
/// whose stored full-envelope digest is the `IFA1` one (ADR-105 erratum E12).
const RETAINED_KEY_SQL: &str = "SELECT evidence.ikr1_cbor, evidence.ikt1_cbor
    FROM imported_fork_key_evidence AS evidence
    JOIN imported_fork_attribution_admissions AS admission
      ON admission.import_operation_id = evidence.import_operation_id
    WHERE evidence.import_operation_id = ?1 AND admission.full_envelope_digest = ?2";

/// Read one child's `FAR1` under an explicit R6.9 validator.
pub(super) fn sqlite_validated_admission(
    conn: &Connection,
    hasher: &dyn Hasher,
    child_timeline_id: TimelineId,
    validator: AuthorityValidatorV1,
) -> Result<ValidatedAdmissionV1, AuthorityError> {
    let local = sqlite_local_fork_admission(conn, hasher, child_timeline_id)
        .map(|admission| ValidatedAdmissionV1::local(&admission));
    match validator {
        AuthorityValidatorV1::LocalOnly => local,
        AuthorityValidatorV1::CodeTwoAware => {
            local.or_else(|_| sqlite_imported_admission(conn, child_timeline_id))
        }
    }
}

/// Read one child's classified authority graph under an explicit R6.9
/// validator.
pub(super) fn sqlite_validated_graph(
    conn: &Connection,
    hasher: &dyn Hasher,
    child_timeline_id: TimelineId,
    validator: AuthorityValidatorV1,
) -> Result<ValidatedGraphV1, AuthorityError> {
    let local = sqlite_classified_authority_graph(conn, hasher, child_timeline_id).map(
        |(admission, table, _)| ValidatedGraphV1 {
            admission: ValidatedAdmissionV1::local(&admission),
            table,
        },
    );
    match validator {
        AuthorityValidatorV1::LocalOnly => local,
        AuthorityValidatorV1::CodeTwoAware => {
            local.or_else(|_| sqlite_imported_graph(conn, child_timeline_id))
        }
    }
}

/// One stored blob under one key, if any. A read failure is none, like every
/// read of validator (a), so it ends in corrupt authority.
fn stored_blob(conn: &Connection, sql: &str, key: &dyn ToSql) -> Option<Vec<u8>> {
    conn.query_row(sql, [key], |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .ok()
        .flatten()
}

/// The `IKR1` and `IKT1` that retain the signing key of an imported publication
/// (ADR-105 erratum E12). A missing, undecodable, or unselected row is
/// invalid and a storage failure is a storage failure; a live-registry sidecar
/// never reads them.
pub(super) fn sqlite_retained_key_evidence(
    conn: &Connection,
    admission: &PublicationSourceResultV1<ValidatedAdmissionV1>,
) -> PublicationSourceResultV1<RetainedKeyEvidenceV1> {
    admission
        .as_ref()
        .ok()
        .and_then(ValidatedAdmissionV1::import)
        .map_or(Ok(RetainedKeyEvidenceV1::LiveRegistry), |import| {
            conn.query_row(
                RETAINED_KEY_SQL,
                params![
                    import.import_operation_id.as_bytes().as_slice(),
                    import.full_envelope_digest.as_bytes().as_slice()
                ],
                |row| {
                    row.get::<_, Vec<u8>>(0).and_then(|record| {
                        row.get::<_, Option<Vec<u8>>>(1)
                            .map(|tombstone| (record, tombstone))
                    })
                },
            )
            .optional()
            .map_err(|_| PublicationSourceErrorV1::Storage)
            .and_then(|stored| {
                stored
                    .and_then(|(record, tombstone)| {
                        ImportedKeyRecordV1::from_canonical_cbor(&record).ok().zip(
                            tombstone
                                .map(|bytes| ImportedKeyTombstoneV1::from_canonical_cbor(&bytes))
                                .transpose()
                                .ok(),
                        )
                    })
                    .map(|(record, tombstone)| {
                        RetainedKeyEvidenceV1::Imported(Box::new(RetainedImportedKeyV1 {
                            record,
                            tombstone,
                        }))
                    })
                    .ok_or(PublicationSourceErrorV1::Invalid)
            })
        })
}

/// R6.9 (b), `FAR1` admission: the code-2 `FAR1` of the child has its one
/// import admission row (the table is `UNIQUE` on the child), which names this
/// child, this origin, and this `FAR1` digest.
fn sqlite_imported_admission(
    conn: &Connection,
    child_timeline_id: TimelineId,
) -> Result<ValidatedAdmissionV1, AuthorityError> {
    let key = child_timeline_id.to_string();
    let admission = stored_blob(conn, FORK_ADMISSION_FAR1_SQL, &key)
        .and_then(|bytes| ImportedForkAdmissionRecordV1::from_canonical_cbor(&bytes).ok())
        .ok_or(AuthorityError::CorruptAuthority)?;
    stored_blob(conn, IMPORT_ADMISSION_SQL, &key)
        .and_then(|bytes| ImportedForkAttributionAdmissionV1::from_canonical_cbor(&bytes).ok())
        .filter(|record| imported_admission_matches(&admission, record, child_timeline_id))
        .map(|record| ValidatedAdmissionV1::imported(&admission, &record))
        .ok_or(AuthorityError::CorruptAuthority)
}

/// R6.9 (b), `FCS1` resolution: the imported `FCS1` is looked up by `FCT1`
/// field 6, and the triple must satisfy G1-G8 against the code-2 `FAR1`.
fn sqlite_imported_graph(
    conn: &Connection,
    child_timeline_id: TimelineId,
) -> Result<ValidatedGraphV1, AuthorityError> {
    let admission = sqlite_imported_admission(conn, child_timeline_id)?;
    let table = sqlite_fork_classifier_table(conn, child_timeline_id)
        .ok()
        .flatten()
        .ok_or(AuthorityError::CorruptAuthority)?;
    let registration = stored_blob(
        conn,
        FORK_CLASSIFIER_REGISTRATION_SQL,
        &child_timeline_id.to_string(),
    )
    .and_then(|bytes| ForkClassifierRegistrationV1::from_canonical_cbor(&bytes).ok())
    .ok_or(AuthorityError::CorruptAuthority)?;
    let source = stored_blob(
        conn,
        IMPORTED_SOURCE_SQL,
        &table
            .input()
            .source_configuration_revision_digest
            .as_bytes()
            .as_slice(),
    )
    .and_then(|bytes| ForkClassifierSourceV1::from_canonical_cbor(&bytes).ok())
    .ok_or(AuthorityError::CorruptAuthority)?;
    let graph = ImportedForkClassifierGraphV1 {
        source,
        table,
        registration,
    };
    imported_graph_matches(&graph, &admission)
        .then_some(ValidatedGraphV1 {
            admission,
            table: graph.table,
        })
        .ok_or(AuthorityError::CorruptAuthority)
}
