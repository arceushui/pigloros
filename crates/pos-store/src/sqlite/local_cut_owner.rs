//! `SQLite` persistence for the installed local-cut owner (LCS2 seals, LCC1
//! commits, and LCQ1 receipts).
//!
//! The owner state, its Timeline roster, and every immutable visible cut live
//! beside the manifest-owner admission tables so one transaction can publish a
//! cut together with the admitted owner's receipt and inventory generation.

use std::collections::BTreeMap;

use pos_core::{
    collect_manifest_owner_link_ancestors_v1, collect_manifest_owner_link_branches_v1,
    local_cut_owner_intent_digest_v1, validate_local_cut_owner_predecessors_v1,
    validate_local_cut_owner_recordings_v1, validate_local_cut_owner_result_v1,
    validate_local_cut_owner_successor_v1, CanonicalBytes, CoreError, Hash, LocalCutCommitV1,
    LocalCutCompositionBindingRowV1, LocalCutExpectedHeadRowV1, LocalCutManifestBindingTableV1,
    LocalCutOwnerCommitKindV1, LocalCutOwnerCommitV1, LocalCutOwnerErrorV1,
    LocalCutOwnerPersistencePortV1, LocalCutOwnerRequestV1, LocalCutOwnerStateV1,
    LocalCutReceiptV1, LocalCutRecordingContextRowV1, LocalCutResultHeadRowV1, LocalCutSealInputV2,
    LocalCutSealV2, LocalCutTableRefV1, LocalCutWorldRecordingV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionInputV1, ManifestOwnerAdmissionOwnerStateV1,
    ManifestOwnerAdmissionPersistencePortV1, ManifestOwnerLinkAncestorV1,
    ManifestOwnerLinkCutIdentityV1, ManifestOwnerLinkReadPortV1, ManifestOwnerLinkSnapshotV1,
    PluginId, PreparedLocalCutOwnerCommitV1, TimelineId, WorldClosureBindingV1,
    WorldDependencyBranchV1, WorldRecordingReceiptV1, MAX_LOCAL_CUT_OWNER_ROWS_V1,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    begin_immediate_scope, finish_owner_scope, sqlite_manifest_owner_has_rows,
    sqlite_read_manifest_owner_current_state, SqliteManifestOwnerAdmissionGenerationV1,
    SqliteStore,
};

pub(super) const LOCAL_CUT_OWNER_SCHEMA_SQL: &str =
    "CREATE TABLE IF NOT EXISTS local_cut_owner_state (
         owner_id BLOB PRIMARY KEY CHECK (length(owner_id) = 32),
         last_visible_cut_id BLOB NOT NULL CHECK (length(last_visible_cut_id) = 8),
         last_visible_tick BLOB NOT NULL CHECK (length(last_visible_tick) = 8),
         membership_epoch BLOB NOT NULL CHECK (length(membership_epoch) = 4),
         configuration_generation BLOB NOT NULL CHECK (length(configuration_generation) = 8),
         previous_visible_lcq1_hash BLOB NOT NULL CHECK (length(previous_visible_lcq1_hash) = 32),
         inventory_generation BLOB NOT NULL CHECK (length(inventory_generation) = 32)
     );
     CREATE TABLE IF NOT EXISTS local_cut_owner_state_timelines (
         owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),
         timeline_id BLOB NOT NULL CHECK (length(timeline_id) = 16),
         PRIMARY KEY (owner_id, timeline_id),
         FOREIGN KEY (owner_id) REFERENCES local_cut_owner_state(owner_id)
     );
     CREATE TABLE IF NOT EXISTS local_cut_owner_cuts (
         owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),
         cut_id BLOB NOT NULL CHECK (length(cut_id) = 8),
         operation_id BLOB NOT NULL CHECK (length(operation_id) = 32),
         intent_digest BLOB NOT NULL CHECK (length(intent_digest) = 32),
         request_bytes BLOB NOT NULL CHECK (length(request_bytes) <= 536870912),
         commit_cbor BLOB NOT NULL CHECK (length(commit_cbor) <= 2048),
         receipt_cbor BLOB NOT NULL CHECK (length(receipt_cbor) <= 256),
         PRIMARY KEY (owner_id, cut_id),
         UNIQUE (owner_id, operation_id)
     );
     CREATE TABLE IF NOT EXISTS local_cut_world_recordings (
         owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),
         cut_id BLOB NOT NULL CHECK (length(cut_id) = 8),
         timeline_id BLOB NOT NULL CHECK (length(timeline_id) = 16),
         scope BLOB NOT NULL CHECK (length(scope) = 32),
         binding_hash BLOB NOT NULL UNIQUE CHECK (length(binding_hash) = 32),
         binding_cbor BLOB NOT NULL CHECK (length(binding_cbor) <= 1024),
         receipt_cbor BLOB NOT NULL CHECK (length(receipt_cbor) <= 1024),
         expected_head_cbor BLOB NOT NULL CHECK (length(expected_head_cbor) <= 198),
         result_head_cbor BLOB NOT NULL CHECK (length(result_head_cbor) <= 147),
         PRIMARY KEY (owner_id, cut_id, timeline_id)
     );
     CREATE INDEX IF NOT EXISTS local_cut_world_recordings_by_timeline
         ON local_cut_world_recordings (owner_id, timeline_id, cut_id);
     CREATE TABLE IF NOT EXISTS world_dependency_branches (
         scope BLOB NOT NULL CHECK (length(scope) = 32),
         node_hash BLOB NOT NULL CHECK (length(node_hash) = 32),
         node_cbor BLOB NOT NULL CHECK (length(node_cbor) <= 65536),
         PRIMARY KEY (scope, node_hash)
     );";

const SQLITE_MAX_LOCAL_CUT_OWNER_REQUEST_BYTES_V1: usize = 536_870_912;
const SQLITE_LOCAL_CUT_OWNER_REQUEST_MAGIC_V1: &[u8] = b"LCOQ1";

fn sqlite_local_cut_owner_has_rows(
    connection: &Connection,
    owner_id: [u8; 32],
) -> Result<bool, LocalCutOwnerErrorV1> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM local_cut_owner_state_timelines WHERE owner_id = ?1
                 UNION ALL
                 SELECT 1 FROM local_cut_owner_cuts WHERE owner_id = ?1
             )",
            params![owner_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)
}

fn sqlite_local_cut_owner_u64(bytes: &[u8]) -> Result<u64, LocalCutOwnerErrorV1> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    Ok(u64::from_be_bytes(bytes))
}

fn sqlite_local_cut_owner_u32(bytes: &[u8]) -> Result<u32, LocalCutOwnerErrorV1> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    Ok(u32::from_be_bytes(bytes))
}

fn sqlite_local_cut_owner_hash(bytes: &[u8]) -> Result<Hash, LocalCutOwnerErrorV1> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    Ok(Hash::from_bytes(bytes))
}

fn sqlite_local_cut_owner_timeline(bytes: &[u8]) -> Result<TimelineId, LocalCutOwnerErrorV1> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(bytes)))
}

struct SqliteLocalCutOwnerCursorV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SqliteLocalCutOwnerCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], LocalCutOwnerErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(LocalCutOwnerErrorV1::CorruptState)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(LocalCutOwnerErrorV1::CorruptState)?;
        self.offset = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], LocalCutOwnerErrorV1> {
        let bytes = *self
            .bytes
            .get(self.offset..)
            .and_then(<[u8]>::first_chunk::<N>)
            .ok_or(LocalCutOwnerErrorV1::CorruptState)?;
        self.offset += N;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, LocalCutOwnerErrorV1> {
        let [byte] = self.array()?;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32, LocalCutOwnerErrorV1> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, LocalCutOwnerErrorV1> {
        self.array().map(u64::from_be_bytes)
    }

    fn hash(&mut self) -> Result<Hash, LocalCutOwnerErrorV1> {
        self.array().map(Hash::from_bytes)
    }

    fn timeline(&mut self) -> Result<TimelineId, LocalCutOwnerErrorV1> {
        let bytes = self.array()?;
        Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(bytes)))
    }

    fn plugin(&mut self) -> Result<PluginId, LocalCutOwnerErrorV1> {
        let bytes = self.array()?;
        Ok(PluginId::from_ulid(ulid::Ulid::from_bytes(bytes)))
    }

    fn length(&mut self, maximum: usize) -> Result<usize, LocalCutOwnerErrorV1> {
        // A length beyond the address space saturates and fails the bound.
        let length = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if length > maximum {
            return Err(LocalCutOwnerErrorV1::CorruptState);
        }
        Ok(length)
    }

    fn count(&mut self) -> Result<usize, LocalCutOwnerErrorV1> {
        match self.length(MAX_LOCAL_CUT_OWNER_ROWS_V1)? {
            0 => Err(LocalCutOwnerErrorV1::CorruptState),
            count => Ok(count),
        }
    }

    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], LocalCutOwnerErrorV1> {
        let length = self.length(maximum)?;
        self.take(length)
    }

    fn optional_hash(&mut self) -> Result<Option<Hash>, LocalCutOwnerErrorV1> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.hash().map(Some),
            _ => Err(LocalCutOwnerErrorV1::CorruptState),
        }
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, LocalCutOwnerErrorV1> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            _ => Err(LocalCutOwnerErrorV1::CorruptState),
        }
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

// Encoded counts and lengths stay far below `u32::MAX`: the encoder only sees
// requests whose intent digest accepted at most `MAX_LOCAL_CUT_OWNER_ROWS_V1`
// rows per table, 64-byte Plugin versions, and canonical 64 KiB records.
fn sqlite_append_local_cut_owner_u32(out: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).unwrap_or(u32::MAX);
    out.extend_from_slice(&value.to_be_bytes());
}

fn sqlite_append_local_cut_owner_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    sqlite_append_local_cut_owner_u32(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn sqlite_append_local_cut_owner_optional_hash(out: &mut Vec<u8>, value: Option<Hash>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(value.as_bytes());
        }
        None => out.push(0),
    }
}

fn sqlite_append_local_cut_owner_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
        None => out.push(0),
    }
}

fn sqlite_append_local_cut_owner_table(out: &mut Vec<u8>, table: LocalCutTableRefV1) {
    out.extend_from_slice(&table.row_count().to_be_bytes());
    sqlite_append_local_cut_owner_optional_hash(out, table.root_hash());
}

fn sqlite_read_local_cut_owner_table(
    cursor: &mut SqliteLocalCutOwnerCursorV1<'_>,
) -> Result<LocalCutTableRefV1, LocalCutOwnerErrorV1> {
    LocalCutTableRefV1::new(cursor.u64()?, cursor.optional_hash()?)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)
}

/// Encode a request that `local_cut_owner_intent_digest_v1` already accepted.
///
/// The kind-4 and kind-5 rows are stored per Timeline beside each WCB1, not
/// here. With at most 1,048,576 rows per table, the kind-14 records take at
/// most 16,384 pages of 9,909 bytes plus 70 branches (about 163.1 MB), the
/// kind-1 rows 222 bytes each (232.8 MB), and the kind-8 rows 113 bytes each
/// (118.5 MB). With the seal and fixed fields this caps the encoding at about
/// 514.3 MB, below `SQLITE_MAX_LOCAL_CUT_OWNER_REQUEST_BYTES_V1` (536.9 MB),
/// so no accepted request can exceed the stored column limit.
fn sqlite_local_cut_owner_request_bytes(request: &LocalCutOwnerRequestV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(SQLITE_LOCAL_CUT_OWNER_REQUEST_MAGIC_V1);
    out.push(1);
    out.extend_from_slice(request.operation_id.as_bytes());
    sqlite_append_local_cut_owner_blob(&mut out, &request.seal.to_canonical_cbor());
    out.extend_from_slice(request.manifest_hash.as_bytes());
    sqlite_append_local_cut_owner_u32(&mut out, request.manifest_binding_table.records().len());
    for record in request.manifest_binding_table.records() {
        sqlite_append_local_cut_owner_blob(&mut out, record);
    }
    sqlite_append_local_cut_owner_u32(&mut out, request.composition_rows.len());
    for row in &request.composition_rows {
        out.extend_from_slice(&row.plugin_id.inner().to_bytes());
        out.extend_from_slice(&row.timeline_id.inner().to_bytes());
        sqlite_append_local_cut_owner_blob(&mut out, row.plugin_version.as_bytes());
        out.extend_from_slice(row.implementation_hash.as_bytes());
        out.extend_from_slice(row.eop1_native_digest.as_bytes());
        sqlite_append_local_cut_owner_optional_u64(&mut out, row.driver_interval_ns);
        sqlite_append_local_cut_owner_optional_u64(&mut out, row.last_due_ns);
        out.extend_from_slice(&row.event_cursor.to_be_bytes());
        out.extend_from_slice(row.participant_native_state_hash.as_bytes());
    }
    sqlite_append_local_cut_owner_u32(&mut out, request.recording_context_rows.len());
    for row in &request.recording_context_rows {
        out.extend_from_slice(&row.timeline_id.inner().to_bytes());
        out.extend_from_slice(row.wcs_hash.as_bytes());
        out.extend_from_slice(row.retention_lease_hash.as_bytes());
        sqlite_append_local_cut_owner_optional_hash(&mut out, row.predecessor_wcb_hash);
    }
    out.extend_from_slice(&request.partition_ledger_seq.to_be_bytes());
    for table in [
        request.result_heads_table,
        request.participant_successor_table,
        request.cpu_completion_table,
        request.action_disposition_table,
        request.candidate_bases_table,
        request.invocation_bridges_table,
    ] {
        sqlite_append_local_cut_owner_table(&mut out, table);
    }
    out.extend_from_slice(request.result_inventory_generation.as_bytes());
    out.extend_from_slice(request.release_fence_proof_digest.as_bytes());
    out
}

fn sqlite_local_cut_owner_request_cursor(
    bytes: &[u8],
) -> Result<SqliteLocalCutOwnerCursorV1<'_>, LocalCutOwnerErrorV1> {
    if bytes.len() > SQLITE_MAX_LOCAL_CUT_OWNER_REQUEST_BYTES_V1 {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    let mut cursor = SqliteLocalCutOwnerCursorV1::new(bytes);
    if cursor.take(SQLITE_LOCAL_CUT_OWNER_REQUEST_MAGIC_V1.len())?
        != SQLITE_LOCAL_CUT_OWNER_REQUEST_MAGIC_V1
        || cursor.u8()? != 1
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(cursor)
}

fn sqlite_decode_local_cut_owner_records(
    cursor: &mut SqliteLocalCutOwnerCursorV1<'_>,
) -> Result<Vec<Vec<u8>>, LocalCutOwnerErrorV1> {
    let record_count = cursor.count()?;
    let mut records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        records.push(cursor.blob(1_048_576)?.to_vec());
    }
    Ok(records)
}

fn sqlite_decode_local_cut_owner_composition_rows(
    cursor: &mut SqliteLocalCutOwnerCursorV1<'_>,
) -> Result<Vec<LocalCutCompositionBindingRowV1>, LocalCutOwnerErrorV1> {
    let composition_count = cursor.count()?;
    let mut composition_rows = Vec::with_capacity(composition_count);
    for _ in 0..composition_count {
        let plugin_id = cursor.plugin()?;
        let timeline_id = cursor.timeline()?;
        let plugin_version = String::from_utf8(cursor.blob(64)?.to_vec())
            .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
        composition_rows.push(LocalCutCompositionBindingRowV1 {
            plugin_id,
            timeline_id,
            plugin_version,
            implementation_hash: cursor.hash()?,
            eop1_native_digest: cursor.hash()?,
            driver_interval_ns: cursor.optional_u64()?,
            last_due_ns: cursor.optional_u64()?,
            event_cursor: cursor.u64()?,
            participant_native_state_hash: cursor.hash()?,
        });
    }
    Ok(composition_rows)
}

fn sqlite_decode_local_cut_owner_recording_contexts(
    cursor: &mut SqliteLocalCutOwnerCursorV1<'_>,
) -> Result<Vec<LocalCutRecordingContextRowV1>, LocalCutOwnerErrorV1> {
    let context_count = cursor.count()?;
    let mut recording_context_rows = Vec::with_capacity(context_count);
    for _ in 0..context_count {
        recording_context_rows.push(LocalCutRecordingContextRowV1 {
            timeline_id: cursor.timeline()?,
            wcs_hash: cursor.hash()?,
            retention_lease_hash: cursor.hash()?,
            predecessor_wcb_hash: cursor.optional_hash()?,
        });
    }
    Ok(recording_context_rows)
}

/// Read the six LCC1 table references in their encoded order.
fn sqlite_read_local_cut_owner_tables(
    cursor: &mut SqliteLocalCutOwnerCursorV1<'_>,
) -> Result<[LocalCutTableRefV1; 6], LocalCutOwnerErrorV1> {
    Ok([
        sqlite_read_local_cut_owner_table(cursor)?,
        sqlite_read_local_cut_owner_table(cursor)?,
        sqlite_read_local_cut_owner_table(cursor)?,
        sqlite_read_local_cut_owner_table(cursor)?,
        sqlite_read_local_cut_owner_table(cursor)?,
        sqlite_read_local_cut_owner_table(cursor)?,
    ])
}

/// Decode a stored request and rejoin the kind-4 and kind-5 rows read from
/// its cut's per-Timeline WCB1 rows before re-deriving the intent digest.
fn sqlite_decode_local_cut_owner_request(
    bytes: &[u8],
    heads: SqliteLocalCutHeadRowsV1,
) -> Result<(LocalCutOwnerRequestV1, Hash), LocalCutOwnerErrorV1> {
    let mut cursor = sqlite_local_cut_owner_request_cursor(bytes)?;
    let operation_id = cursor.hash()?;
    let seal_bytes = cursor.blob(4096)?;
    let seal = LocalCutSealV2::from_canonical_cbor(seal_bytes)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let manifest_hash = cursor.hash()?;
    let records = sqlite_decode_local_cut_owner_records(&mut cursor)?;
    let composition_rows = sqlite_decode_local_cut_owner_composition_rows(&mut cursor)?;
    let recording_context_rows = sqlite_decode_local_cut_owner_recording_contexts(&mut cursor)?;
    let partition_ledger_seq = cursor.u64()?;
    let [result_heads_table, participant_successor_table, cpu_completion_table, action_disposition_table, candidate_bases_table, invocation_bridges_table] =
        sqlite_read_local_cut_owner_tables(&mut cursor)?;
    let result_inventory_generation = cursor.hash()?;
    let release_fence_proof_digest = cursor.hash()?;
    if !cursor.is_finished() {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    let seal_input = seal.as_input();
    let manifest_binding_table = LocalCutManifestBindingTableV1::from_records(
        seal_input.owner_id,
        seal_input.cut_id,
        seal_input.manifest_binding_table,
        &records,
    )
    .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let request = LocalCutOwnerRequestV1 {
        operation_id,
        seal,
        manifest_hash,
        manifest_binding_table,
        composition_rows,
        recording_context_rows,
        expected_head_rows: heads.expected,
        result_head_rows: heads.result,
        partition_ledger_seq,
        result_heads_table,
        participant_successor_table,
        cpu_completion_table,
        action_disposition_table,
        candidate_bases_table,
        invocation_bridges_table,
        result_inventory_generation,
        release_fence_proof_digest,
    };
    let intent_digest = local_cut_owner_intent_digest_v1(&request)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    if sqlite_local_cut_owner_request_bytes(&request) != bytes {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok((request, intent_digest))
}

/// One undecoded `local_cut_world_recordings` row.
struct SqliteWorldRecordingRowV1 {
    timeline_id: [u8; 16],
    scope: [u8; 32],
    binding_hash: [u8; 32],
    binding_cbor: Vec<u8>,
    receipt_cbor: Vec<u8>,
    expected_head_cbor: Vec<u8>,
    result_head_cbor: Vec<u8>,
}

/// One cut's kind-4 and kind-5 rows, in Timeline order.
#[derive(Default)]
struct SqliteLocalCutHeadRowsV1 {
    expected: Vec<LocalCutExpectedHeadRowV1>,
    result: Vec<LocalCutResultHeadRowV1>,
}

/// One cut's WCB1/WCR1 recordings and their kind-4 and kind-5 rows.
#[derive(Default)]
struct SqliteLocalCutWorldRowsV1 {
    recordings: Vec<LocalCutWorldRecordingV1>,
    heads: SqliteLocalCutHeadRowsV1,
}

#[derive(Clone)]
struct SqliteLocalCutOwnerCutV1 {
    intent_digest: Hash,
    request: LocalCutOwnerRequestV1,
    result: LocalCutOwnerCommitV1,
}

fn sqlite_validate_local_cut_owner_cut(
    owner_id: [u8; 32],
    cut_id: u64,
    cut: &SqliteLocalCutOwnerCutV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    validate_local_cut_owner_result_v1(owner_id, cut_id, &cut.result)?;
    let commit = cut.result.commit.as_input();
    let request = &cut.request;
    // Stored and expected bindings are compared pairwise, so both tuples must
    // list their fields in the same order.
    let stored = (
        &commit.partition_ledger_seq,
        &commit.manifest_hash,
        &commit.result_heads_table,
        &commit.participant_successor_table,
        &commit.cpu_completion_table,
        &commit.action_disposition_table,
        &commit.candidate_bases_table,
        &commit.invocation_bridges_table,
        &commit.result_inventory_generation,
        &commit.release_fence_proof_digest,
    );
    let expected = (
        &request.partition_ledger_seq,
        &request.manifest_hash,
        &request.result_heads_table,
        &request.participant_successor_table,
        &request.cpu_completion_table,
        &request.action_disposition_table,
        &request.candidate_bases_table,
        &request.invocation_bridges_table,
        &request.result_inventory_generation,
        &request.release_fence_proof_digest,
    );
    if stored != expected {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    validate_local_cut_owner_recordings_v1(request, &cut.result)
}

fn sqlite_local_cut_owner_cut_by_id(
    connection: &Connection,
    owner_id: [u8; 32],
    cut_id: u64,
) -> Result<Option<SqliteLocalCutOwnerCutV1>, LocalCutOwnerErrorV1> {
    let cut_id_bytes = cut_id.to_be_bytes();
    let row = connection
        .query_row(
            "SELECT operation_id, intent_digest, request_bytes, commit_cbor, receipt_cbor
             FROM local_cut_owner_cuts
             WHERE owner_id = ?1 AND cut_id = ?2",
            params![owner_id.as_slice(), cut_id_bytes.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    let Some((operation_id, intent_digest, request_bytes, commit_bytes, receipt_bytes)) = row
    else {
        return Ok(None);
    };
    let operation_id = sqlite_local_cut_owner_hash(&operation_id)?;
    let intent_digest = sqlite_local_cut_owner_hash(&intent_digest)?;
    let world = sqlite_local_cut_world_recordings(connection, owner_id, cut_id)?;
    let (request, decoded_intent) =
        sqlite_decode_local_cut_owner_request(&request_bytes, world.heads)?;
    let commit = LocalCutCommitV1::from_canonical_cbor(&commit_bytes)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let receipt = LocalCutReceiptV1::from_canonical_cbor(&receipt_bytes)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    if request.operation_id != operation_id || decoded_intent != intent_digest {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    let seal = request.seal;
    let cut = SqliteLocalCutOwnerCutV1 {
        intent_digest,
        request,
        result: LocalCutOwnerCommitV1 {
            kind: LocalCutOwnerCommitKindV1::Applied,
            seal,
            commit,
            receipt,
            recordings: world.recordings,
        },
    };
    sqlite_validate_local_cut_owner_cut(owner_id, cut_id, &cut).map(|()| Some(cut))
}

/// Read one cut's WCB1/WCR1 rows and their kind-4/kind-5 rows in Timeline order.
fn sqlite_local_cut_world_recordings(
    connection: &Connection,
    owner_id: [u8; 32],
    cut_id: u64,
) -> Result<SqliteLocalCutWorldRowsV1, LocalCutOwnerErrorV1> {
    let cut_id = cut_id.to_be_bytes();
    let rows = connection
        .prepare(
            "SELECT timeline_id, scope, binding_hash, binding_cbor, receipt_cbor,
                    expected_head_cbor, result_head_cbor
             FROM local_cut_world_recordings
             WHERE owner_id = ?1 AND cut_id = ?2 ORDER BY timeline_id",
        )
        .and_then(|mut statement| {
            statement
                .query_map(params![owner_id.as_slice(), cut_id.as_slice()], |row| {
                    Ok(SqliteWorldRecordingRowV1 {
                        timeline_id: row.get(0)?,
                        scope: row.get(1)?,
                        binding_hash: row.get(2)?,
                        binding_cbor: row.get(3)?,
                        receipt_cbor: row.get(4)?,
                        expected_head_cbor: row.get(5)?,
                        result_head_cbor: row.get(6)?,
                    })
                })
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        })
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    let mut world = SqliteLocalCutWorldRowsV1::default();
    for row in &rows {
        sqlite_decode_local_cut_world_recording(connection, row, &mut world)?;
    }
    Ok(world)
}

/// Decode one stored WCB1/WCR1 row against its key, digest index and WDB1 root,
/// and append it with the Timeline's kind-4 and kind-5 rows to `world`.
///
/// The head rows are not checked against the key here: the caller rejoins
/// them to the stored request, whose re-derived intent digest pins every row,
/// its Timeline included.
fn sqlite_decode_local_cut_world_recording(
    connection: &Connection,
    row: &SqliteWorldRecordingRowV1,
    world: &mut SqliteLocalCutWorldRowsV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let binding = WorldClosureBindingV1::from_canonical_cbor(&row.binding_cbor)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let receipt = WorldRecordingReceiptV1::from_canonical_cbor(&row.receipt_cbor)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let expected = LocalCutExpectedHeadRowV1::from_canonical_cbor(&row.expected_head_cbor)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let result = LocalCutResultHeadRowV1::from_canonical_cbor(&row.result_head_cbor)
        .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
    let scope = Hash::from_bytes(row.scope);
    let root = binding.as_input().dependency_root_hash;
    if row.timeline_id != binding.as_input().timeline_id.inner().to_bytes()
        || row.binding_hash != *binding.digest().as_bytes()
        || !sqlite_world_dependency_branch_exists(connection, scope, root)?
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    world.recordings.push(LocalCutWorldRecordingV1 {
        scope,
        binding,
        receipt,
    });
    world.heads.expected.push(expected);
    world.heads.result.push(result);
    Ok(())
}

fn sqlite_world_dependency_branch_exists(
    connection: &Connection,
    scope: Hash,
    node_hash: Hash,
) -> Result<bool, LocalCutOwnerErrorV1> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM world_dependency_branches WHERE scope = ?1 AND node_hash = ?2
             )",
            params![scope.as_bytes().as_slice(), node_hash.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)
}

/// Read the WCB1 digest of the owner's last visible cut containing a Timeline.
fn sqlite_latest_local_cut_world_binding(
    connection: &Connection,
    owner_id: [u8; 32],
    timeline_id: TimelineId,
) -> Result<Option<Hash>, LocalCutOwnerErrorV1> {
    let timeline_id = timeline_id.inner().to_bytes();
    connection
        .query_row(
            "SELECT binding_hash FROM local_cut_world_recordings
             WHERE owner_id = ?1 AND timeline_id = ?2
             ORDER BY cut_id DESC LIMIT 1",
            params![owner_id.as_slice(), timeline_id.as_slice()],
            |row| row.get::<_, [u8; 32]>(0),
        )
        .optional()
        .map(|binding_hash| binding_hash.map(Hash::from_bytes))
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)
}

/// Check a prepared successor and each WCB1 predecessor inside the commit.
fn sqlite_validate_local_cut_successor(
    connection: &Connection,
    batch: &PreparedLocalCutOwnerCommitV1,
    admission: &ManifestOwnerAdmissionOwnerStateV1,
    current_state: Option<&LocalCutOwnerStateV1>,
) -> Result<(), LocalCutOwnerErrorV1> {
    validate_local_cut_owner_successor_v1(batch, admission, current_state)?;
    let owner_id = batch.successor_state().owner_id;
    validate_local_cut_owner_predecessors_v1(batch, |timeline_id| {
        sqlite_latest_local_cut_world_binding(connection, owner_id, timeline_id)
    })
}

/// Insert one cut's WCB1/WCR1 rows and any WDB1 node new to its scope.
fn sqlite_insert_local_cut_world_recordings(
    connection: &Connection,
    batch: &PreparedLocalCutOwnerCommitV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let owner_id = batch.successor_state().owner_id;
    let request = batch.request();
    let cut_id = request.seal.as_input().cut_id.to_be_bytes();
    // Preparation matched the kind-4, kind-5 and WCB1 rows to the same
    // admitted Timelines in the same order.
    let heads = request
        .expected_head_rows
        .iter()
        .zip(&request.result_head_rows);
    for (recording, (expected, result)) in batch.recordings().iter().zip(heads) {
        let binding = recording.binding;
        let timeline_id = binding.as_input().timeline_id.inner().to_bytes();
        connection
            .execute(
                "INSERT INTO local_cut_world_recordings
                 (owner_id, cut_id, timeline_id, scope, binding_hash, binding_cbor, receipt_cbor,
                  expected_head_cbor, result_head_cbor)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    owner_id.as_slice(),
                    cut_id.as_slice(),
                    timeline_id.as_slice(),
                    recording.scope.as_bytes().as_slice(),
                    binding.digest().as_bytes().as_slice(),
                    binding.to_canonical_cbor(),
                    recording.receipt.to_canonical_cbor(),
                    expected.to_canonical_cbor(),
                    result.to_canonical_cbor(),
                ],
            )
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    }
    for directory in batch.dependency_directories() {
        for branch in directory.branches() {
            connection
                .execute(
                    "INSERT INTO world_dependency_branches (scope, node_hash, node_cbor)
                     VALUES (?1, ?2, ?3) ON CONFLICT (scope, node_hash) DO NOTHING",
                    params![
                        directory.scope().as_bytes().as_slice(),
                        branch.digest().as_bytes().as_slice(),
                        branch.encode().as_slice(),
                    ],
                )
                .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        }
    }
    Ok(())
}

// Load a cut whose identity was read from `local_cut_owner_cuts` in the same
// transaction, so the row is present.
fn sqlite_local_cut_owner_existing_cut(
    connection: &Connection,
    owner_id: [u8; 32],
    cut_id: u64,
) -> Result<SqliteLocalCutOwnerCutV1, LocalCutOwnerErrorV1> {
    sqlite_local_cut_owner_cut_by_id(connection, owner_id, cut_id)
        .and_then(|cut| cut.ok_or(LocalCutOwnerErrorV1::CorruptState))
}

fn sqlite_local_cut_owner_cut_by_operation(
    connection: &Connection,
    owner_id: [u8; 32],
    operation_id: Hash,
) -> Result<Option<SqliteLocalCutOwnerCutV1>, LocalCutOwnerErrorV1> {
    let row = connection
        .query_row(
            "SELECT cut_id FROM local_cut_owner_cuts
             WHERE owner_id = ?1 AND operation_id = ?2",
            params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    row.map(|cut_id| {
        let cut_id = sqlite_local_cut_owner_u64(&cut_id)?;
        sqlite_local_cut_owner_existing_cut(connection, owner_id, cut_id)
    })
    .transpose()
}

fn sqlite_local_cut_owner_state_raw(
    connection: &Connection,
    owner_id: [u8; 32],
) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1> {
    let row = connection
        .query_row(
            "SELECT last_visible_cut_id, last_visible_tick, membership_epoch,
                    configuration_generation, previous_visible_lcq1_hash, inventory_generation
             FROM local_cut_owner_state WHERE owner_id = ?1",
            params![owner_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    let Some((
        last_visible_cut_id,
        last_visible_tick,
        membership_epoch,
        generation,
        previous,
        inventory,
    )) = row
    else {
        return Ok(None);
    };
    let mut statement = connection
        .prepare(
            "SELECT timeline_id FROM local_cut_owner_state_timelines
             WHERE owner_id = ?1 ORDER BY timeline_id",
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    let timeline_rows = statement
        .query_map(params![owner_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    let timelines = timeline_rows
        .iter()
        .map(|bytes| sqlite_local_cut_owner_timeline(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let state = LocalCutOwnerStateV1 {
        owner_id,
        last_visible_cut_id: sqlite_local_cut_owner_u64(&last_visible_cut_id)?,
        last_visible_tick: sqlite_local_cut_owner_u64(&last_visible_tick)?,
        membership_epoch: sqlite_local_cut_owner_u32(&membership_epoch)?,
        configuration_generation: sqlite_local_cut_owner_u64(&generation)?,
        previous_visible_lcq1_hash: Some(sqlite_local_cut_owner_hash(&previous)?),
        inventory_generation: sqlite_local_cut_owner_hash(&inventory)?,
        timelines,
    };
    state.validate()?;
    Ok(Some(state))
}

/// Report admitted-owner or local-cut rows that lack an admitted state row.
pub(super) fn sqlite_manifest_or_local_cut_owner_has_rows(
    connection: &Connection,
    owner_id: [u8; 32],
) -> Result<bool, ManifestOwnerAdmissionErrorV1> {
    if sqlite_manifest_owner_has_rows(connection, owner_id)? {
        return Ok(true);
    }
    sqlite_local_cut_owner_has_rows(connection, owner_id)
        .map_err(ManifestOwnerAdmissionErrorV1::from)
}

/// Check the owner's local-cut rows against the admitted state just read.
///
/// After a visible cut, the local-cut row must carry the admitted generation,
/// receipt, inventory, and roster. Before one, the admitted receipt and
/// inventory must still be those of the admitted generation's own rows.
pub(super) fn sqlite_validate_local_cut_owner_admission(
    connection: &Connection,
    owner_id: [u8; 32],
    configuration_generation: u64,
    previous_visible_lcq1_hash: Option<Hash>,
    inventory_generation: Hash,
    generation_rows: &SqliteManifestOwnerAdmissionGenerationV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    match sqlite_local_cut_owner_state_raw(connection, owner_id)? {
        // The raw read already validated the row and keyed it by `owner_id`.
        Some(local_cut_state) => {
            if local_cut_state.configuration_generation != configuration_generation
                || local_cut_state.previous_visible_lcq1_hash != previous_visible_lcq1_hash
                || local_cut_state.inventory_generation != inventory_generation
                || local_cut_state.timelines != generation_rows.timelines
            {
                return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
            }
        }
        None => {
            if sqlite_local_cut_owner_has_rows(connection, owner_id)?
                || generation_rows.previous_visible_lcq1_hash != previous_visible_lcq1_hash
                || generation_rows.inventory_generation != inventory_generation
            {
                return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
            }
        }
    }
    Ok(())
}

/// Read the owner state and fully validate only its current visible cut.
///
/// This hot path checks the admitted header, rejects any retained cut after
/// the last visible cut, and decodes only that last cut. Older cuts are decoded
/// when a read or retry returns one, and by
/// [`LocalCutOwnerPersistencePortV1::verify_local_cut_owner_history_v1`].
fn sqlite_read_local_cut_owner_state(
    connection: &Connection,
    owner_id: [u8; 32],
) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1> {
    let Some(state) = sqlite_local_cut_owner_state_raw(connection, owner_id)? else {
        return if sqlite_local_cut_owner_has_rows(connection, owner_id)? {
            Err(LocalCutOwnerErrorV1::CorruptState)
        } else {
            Ok(None)
        };
    };
    // The admitted-state read compares this same local-cut row with the admitted
    // generation, roster, receipt, and inventory. Its local-cut rows make a
    // missing admitted row corrupt there, so it never returns `None` here.
    sqlite_read_manifest_owner_current_state(connection, owner_id)?;
    let last_visible_cut_id = state.last_visible_cut_id.to_be_bytes();
    // Cut identities are stored big-endian, so SQLite's bytewise blob order is
    // their numeric order and `cut_id > ?2` selects exactly the later cuts.
    let has_later_cut: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM local_cut_owner_cuts WHERE owner_id = ?1 AND cut_id > ?2
             )",
            params![owner_id.as_slice(), last_visible_cut_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    if has_later_cut {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    let current =
        sqlite_local_cut_owner_cut_by_id(connection, owner_id, state.last_visible_cut_id)?
            .ok_or(LocalCutOwnerErrorV1::CorruptState)?;
    if state.previous_visible_lcq1_hash != Some(current.result.receipt.digest()) {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(Some(state))
}

/// Classify a failed local-cut query; a mistyped stored column is corrupt.
const fn sqlite_local_cut_query_error(error: &rusqlite::Error) -> LocalCutOwnerErrorV1 {
    if matches!(error, rusqlite::Error::InvalidColumnType(..)) {
        LocalCutOwnerErrorV1::CorruptState
    } else {
        LocalCutOwnerErrorV1::StorageFailure
    }
}

/// List one owner's raw retained cut identities in ascending order.
///
/// A retained `cut_id` that is not a blob fails the typed `Vec<u8>` read with
/// `rusqlite::Error::InvalidColumnType`. That is the signal for a corrupt row,
/// so it maps to `CorruptState`; every other error is a `StorageFailure`.
fn sqlite_local_cut_owner_cut_ids(
    connection: &Connection,
    owner_id: [u8; 32],
) -> Result<Vec<Vec<u8>>, LocalCutOwnerErrorV1> {
    connection
        .prepare(
            "SELECT cut_id FROM local_cut_owner_cuts
             WHERE owner_id = ?1 ORDER BY cut_id",
        )
        .and_then(|mut statement| {
            statement
                .query_map(params![owner_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        })
        .map_err(|error| sqlite_local_cut_query_error(&error))
}

/// Fully validate the owner state and every retained cut, oldest first.
fn sqlite_verify_local_cut_owner_history(
    connection: &Connection,
    owner_id: [u8; 32],
) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1> {
    let state = sqlite_read_local_cut_owner_state(connection, owner_id)?;
    for cut_bytes in sqlite_local_cut_owner_cut_ids(connection, owner_id)? {
        let cut_id = sqlite_local_cut_owner_u64(&cut_bytes)?;
        sqlite_local_cut_owner_existing_cut(connection, owner_id, cut_id)?;
    }
    Ok(state)
}

fn sqlite_resolve_local_cut_owner_retry(
    connection: &Connection,
    owner_id: [u8; 32],
    operation_id: Hash,
    intent_digest: Hash,
) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1> {
    let Some(cut) = sqlite_local_cut_owner_cut_by_operation(connection, owner_id, operation_id)?
    else {
        return Ok(None);
    };
    if cut.intent_digest != intent_digest {
        return Err(LocalCutOwnerErrorV1::Conflict);
    }
    let mut retry = cut.result;
    retry.kind = LocalCutOwnerCommitKindV1::ExactRetry;
    Ok(Some(retry))
}

fn sqlite_insert_local_cut_owner_cut(
    connection: &Connection,
    batch: &PreparedLocalCutOwnerCommitV1,
) -> Result<LocalCutOwnerCommitV1, LocalCutOwnerErrorV1> {
    let request = batch.request();
    let owner_id = batch.successor_state().owner_id;
    let cut_id_bytes = request.seal.as_input().cut_id.to_be_bytes();
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM local_cut_owner_cuts
                 WHERE owner_id = ?1 AND (cut_id = ?2 OR operation_id = ?3)
             )",
            params![
                owner_id.as_slice(),
                cut_id_bytes.as_slice(),
                request.operation_id.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    if exists {
        return Err(LocalCutOwnerErrorV1::Conflict);
    }
    let result = batch.applied_result();
    let request_bytes = sqlite_local_cut_owner_request_bytes(request);
    connection
        .execute(
            "INSERT INTO local_cut_owner_cuts
             (owner_id, cut_id, operation_id, intent_digest, request_bytes, commit_cbor, receipt_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                owner_id.as_slice(),
                cut_id_bytes.as_slice(),
                request.operation_id.as_bytes().as_slice(),
                batch.intent_digest().as_bytes().as_slice(),
                request_bytes,
                result.commit.to_canonical_cbor(),
                result.receipt.to_canonical_cbor(),
            ],
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    sqlite_insert_local_cut_world_recordings(connection, batch).map(|()| result)
}

fn sqlite_write_local_cut_owner_state(
    connection: &Connection,
    current_state: Option<&LocalCutOwnerStateV1>,
    successor: &LocalCutOwnerStateV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    successor.validate()?;
    let owner_id = successor.owner_id;
    let previous = successor
        .previous_visible_lcq1_hash
        .ok_or(LocalCutOwnerErrorV1::CorruptState)?;
    let changed = match current_state {
        Some(current_state) => connection
            .execute(
                "UPDATE local_cut_owner_state
                 SET last_visible_cut_id = ?1, last_visible_tick = ?2, membership_epoch = ?3,
                     configuration_generation = ?4, previous_visible_lcq1_hash = ?5,
                     inventory_generation = ?6
                 WHERE owner_id = ?7 AND last_visible_cut_id = ?8 AND last_visible_tick = ?9
                   AND membership_epoch = ?10 AND configuration_generation = ?11
                   AND previous_visible_lcq1_hash = ?12 AND inventory_generation = ?13",
                params![
                    successor.last_visible_cut_id.to_be_bytes().as_slice(),
                    successor.last_visible_tick.to_be_bytes().as_slice(),
                    successor.membership_epoch.to_be_bytes().as_slice(),
                    successor.configuration_generation.to_be_bytes().as_slice(),
                    previous.as_bytes().as_slice(),
                    successor.inventory_generation.as_bytes().as_slice(),
                    owner_id.as_slice(),
                    current_state.last_visible_cut_id.to_be_bytes().as_slice(),
                    current_state.last_visible_tick.to_be_bytes().as_slice(),
                    current_state.membership_epoch.to_be_bytes().as_slice(),
                    current_state
                        .configuration_generation
                        .to_be_bytes()
                        .as_slice(),
                    current_state
                        .previous_visible_lcq1_hash
                        .map(|hash| hash.as_bytes().to_vec()),
                    current_state.inventory_generation.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?,
        None => connection
            .execute(
                "INSERT INTO local_cut_owner_state
                 (owner_id, last_visible_cut_id, last_visible_tick, membership_epoch,
                  configuration_generation, previous_visible_lcq1_hash, inventory_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    owner_id.as_slice(),
                    successor.last_visible_cut_id.to_be_bytes().as_slice(),
                    successor.last_visible_tick.to_be_bytes().as_slice(),
                    successor.membership_epoch.to_be_bytes().as_slice(),
                    successor.configuration_generation.to_be_bytes().as_slice(),
                    previous.as_bytes().as_slice(),
                    successor.inventory_generation.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?,
    };
    if changed != 1 {
        return Err(LocalCutOwnerErrorV1::Conflict);
    }
    connection
        .execute(
            "DELETE FROM local_cut_owner_state_timelines WHERE owner_id = ?1",
            params![owner_id.as_slice()],
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    for timeline_id in &successor.timelines {
        let timeline_bytes = timeline_id.inner().to_bytes();
        connection
            .execute(
                "INSERT INTO local_cut_owner_state_timelines (owner_id, timeline_id)
                 VALUES (?1, ?2)",
                params![owner_id.as_slice(), timeline_bytes.as_slice()],
            )
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    }
    Ok(())
}

fn sqlite_update_manifest_owner_state_after_local_cut(
    connection: &Connection,
    current: &ManifestOwnerAdmissionOwnerStateV1,
    result: &LocalCutOwnerCommitV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let receipt_hash = result.receipt.digest();
    let changed = connection
        .execute(
            "UPDATE manifest_owner_admission_state
             SET previous_visible_lcq1_hash = ?1, inventory_generation = ?2
             WHERE owner_id = ?3 AND configuration_generation = ?4
               AND previous_visible_lcq1_hash IS ?5 AND inventory_generation = ?6",
            params![
                receipt_hash.as_bytes().as_slice(),
                result
                    .commit
                    .as_input()
                    .result_inventory_generation
                    .as_bytes()
                    .as_slice(),
                current.owner_id.as_slice(),
                current.configuration_generation.to_be_bytes().as_slice(),
                current
                    .previous_visible_lcq1_hash
                    .map(|hash| hash.as_bytes().to_vec()),
                current.inventory_generation.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(LocalCutOwnerErrorV1::Conflict)
    }
}

impl LocalCutOwnerPersistencePortV1 for SqliteStore {
    fn read_local_cut_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1> {
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        let state = sqlite_read_local_cut_owner_state(&transaction, owner_id)?;
        transaction
            .commit()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        Ok(state)
    }

    fn resolve_local_cut_owner_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1> {
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        sqlite_read_local_cut_owner_state(&transaction, owner_id)?;
        let retry = sqlite_resolve_local_cut_owner_retry(
            &transaction,
            owner_id,
            operation_id,
            intent_digest,
        )?;
        transaction
            .commit()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        Ok(retry)
    }

    fn commit_local_cut_owner_v1(
        &mut self,
        batch: PreparedLocalCutOwnerCommitV1,
    ) -> Result<LocalCutOwnerCommitV1, LocalCutOwnerErrorV1> {
        let scope =
            begin_immediate_scope(&self.conn).map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        let result = (|| {
            let owner_id = batch.successor_state().owner_id;
            let operation_id = batch.request().operation_id;
            let admission = sqlite_read_manifest_owner_current_state(&self.conn, owner_id)?
                .ok_or(LocalCutOwnerErrorV1::Conflict)?;
            let current_state = sqlite_read_local_cut_owner_state(&self.conn, owner_id)?;
            if let Some(retry) = sqlite_resolve_local_cut_owner_retry(
                &self.conn,
                owner_id,
                operation_id,
                batch.intent_digest(),
            )? {
                return Ok(retry);
            }
            sqlite_validate_local_cut_successor(
                &self.conn,
                &batch,
                &admission,
                current_state.as_ref(),
            )?;
            let applied = sqlite_insert_local_cut_owner_cut(&self.conn, &batch)?;
            sqlite_write_local_cut_owner_state(
                &self.conn,
                current_state.as_ref(),
                batch.successor_state(),
            )?;
            sqlite_update_manifest_owner_state_after_local_cut(&self.conn, &admission, &applied)?;
            Ok(applied)
        })();
        finish_owner_scope(
            &self.conn,
            scope,
            result,
            LocalCutOwnerErrorV1::StorageFailure,
        )
    }

    fn read_local_cut_owner_commit_v1(
        &self,
        owner_id: [u8; 32],
        cut_id: u64,
    ) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1> {
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        sqlite_read_local_cut_owner_state(&transaction, owner_id)?;
        let cut = sqlite_local_cut_owner_cut_by_id(&transaction, owner_id, cut_id)?;
        transaction
            .commit()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        Ok(cut.map(|cut| cut.result))
    }

    // Every read-write open runs this pass for each owner with local-cut rows.
    // A read-only open does not, so its callers invoke the port method directly.
    fn verify_local_cut_owner_history_v1(
        &self,
        owner_id: [u8; 32],
    ) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1> {
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        let state = sqlite_verify_local_cut_owner_history(&transaction, owner_id)?;
        transaction
            .commit()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        Ok(state)
    }
}

/// Find the owner's first visible cut, in cut order, whose WCR1 for
/// `timeline_id` the identity selects, through the Timeline recording index.
fn sqlite_owner_link_cut(
    connection: &Connection,
    owner_id: [u8; 32],
    identity: ManifestOwnerLinkCutIdentityV1,
    timeline_id: TimelineId,
) -> Result<Option<u64>, LocalCutOwnerErrorV1> {
    let timeline_id = timeline_id.inner().to_bytes();
    let rows = connection
        .prepare(
            "SELECT cut_id, receipt_cbor FROM local_cut_world_recordings
             WHERE owner_id = ?1 AND timeline_id = ?2 ORDER BY cut_id",
        )
        .and_then(|mut statement| {
            statement
                .query_map(
                    params![owner_id.as_slice(), timeline_id.as_slice()],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        })
        .map_err(|error| sqlite_local_cut_query_error(&error))?;
    for (cut_id, receipt) in rows {
        let receipt = WorldRecordingReceiptV1::from_canonical_cbor(&receipt)
            .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
        if identity.selects(&receipt) {
            return sqlite_local_cut_owner_u64(&cut_id).map(Some);
        }
    }
    Ok(None)
}

/// The owner's visible cuts before `seal`, newest first, each loaded only
/// when the ancestry walk reads it.
fn sqlite_owner_link_earlier_cuts<'a>(
    connection: &'a Connection,
    owner_id: [u8; 32],
    seal: &LocalCutSealInputV2,
    cut_ids: &'a [Vec<u8>],
) -> impl Iterator<Item = Result<ManifestOwnerLinkAncestorV1, LocalCutOwnerErrorV1>> + 'a {
    let sealed_cut = seal.cut_id;
    cut_ids
        .iter()
        .rev()
        .map(|bytes| sqlite_local_cut_owner_u64(bytes))
        .filter(move |cut_id| !matches!(cut_id, Ok(cut_id) if *cut_id >= sealed_cut))
        .map(move |cut_id| {
            let cut = cut_id.and_then(|cut_id| {
                sqlite_local_cut_owner_existing_cut(connection, owner_id, cut_id)
            });
            cut.map(|cut| ManifestOwnerLinkAncestorV1::of_result(&cut.result))
        })
}

/// Read one retained WDB1 node of `scope` by digest, if it is retained.
fn sqlite_owner_link_branch(
    connection: &Connection,
    scope: Hash,
    digest: Hash,
) -> Result<Option<WorldDependencyBranchV1>, LocalCutOwnerErrorV1> {
    let (scope, digest) = (*scope.as_bytes(), *digest.as_bytes());
    let encoded = connection
        .query_row(
            "SELECT node_cbor FROM world_dependency_branches WHERE scope = ?1 AND node_hash = ?2",
            params![scope.as_slice(), digest.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| sqlite_local_cut_query_error(&error))?;
    encoded
        .map(|bytes| {
            WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(bytes))
                .map_err(|_| LocalCutOwnerErrorV1::CorruptState)
        })
        .transpose()
}

/// Read one selected cut, its kind-14 admissions, the earlier cuts its
/// ancestry walk needs and its Timeline's WDB1 nodes inside the caller's
/// read transaction.
fn sqlite_owner_link_snapshot(
    store: &SqliteStore,
    connection: &Connection,
    owner_id: [u8; 32],
    identity: ManifestOwnerLinkCutIdentityV1,
    timeline_id: TimelineId,
) -> Result<Option<ManifestOwnerLinkSnapshotV1>, LocalCutOwnerErrorV1> {
    let Some(owner_state) = sqlite_read_local_cut_owner_state(connection, owner_id)? else {
        return Ok(None);
    };
    let Some(cut_id) = sqlite_owner_link_cut(connection, owner_id, identity, timeline_id)? else {
        return Ok(None);
    };
    let cut = sqlite_local_cut_owner_existing_cut(connection, owner_id, cut_id)?;
    let seal = cut.result.seal.as_input();
    let generation = seal.configuration_generation;
    let admissions = cut
        .request
        .manifest_binding_table
        .rows()
        .iter()
        .map(|row| store.read_manifest_owner_admission_v1(owner_id, generation, row.timeline_id))
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>, _>>()?;
    let admission = admissions
        .iter()
        .find(|admission| admission.timeline.timeline_id == timeline_id);
    let cut_ids = sqlite_local_cut_owner_cut_ids(connection, owner_id)?;
    let earlier = sqlite_owner_link_earlier_cuts(connection, owner_id, seal, &cut_ids);
    let ancestors = collect_manifest_owner_link_ancestors_v1(seal, admission, earlier)?;
    let mut dependency_branches = BTreeMap::new();
    let selected = cut
        .result
        .recordings
        .iter()
        .filter(|recording| recording.binding.as_input().timeline_id == timeline_id);
    for recording in selected {
        let root = recording.binding.as_input().dependency_root_hash;
        let nodes = collect_manifest_owner_link_branches_v1(root, |digest| {
            sqlite_owner_link_branch(connection, recording.scope, digest)
        })?;
        dependency_branches.extend(nodes);
    }
    Ok(Some(ManifestOwnerLinkSnapshotV1 {
        owner_state,
        request: cut.request,
        result: cut.result,
        ancestors,
        admissions,
        dependency_branches,
    }))
}

impl ManifestOwnerLinkReadPortV1 for SqliteStore {
    fn read_manifest_owner_link_snapshot_v1(
        &self,
        owner_id: [u8; 32],
        identity: ManifestOwnerLinkCutIdentityV1,
        timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerLinkSnapshotV1>, LocalCutOwnerErrorV1> {
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        let snapshot =
            sqlite_owner_link_snapshot(self, &transaction, owner_id, identity, timeline_id)?;
        transaction
            .commit()
            .map_err(|_| LocalCutOwnerErrorV1::StorageFailure)?;
        Ok(snapshot)
    }
}

impl SqliteStore {
    /// Verify the complete local-cut history of every owner with local-cut rows.
    pub(super) fn verify_local_cut_owner_histories(&self) -> Result<(), CoreError> {
        let owners = self
            .conn
            .prepare(
                "SELECT owner_id FROM local_cut_owner_state
                 UNION SELECT owner_id FROM local_cut_owner_state_timelines
                 UNION SELECT owner_id FROM local_cut_owner_cuts",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, [u8; 32]>(0))
                    .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            })
            .map_err(Self::into_storage_error)?;
        for owner_id in owners {
            self.verify_local_cut_owner_history_v1(owner_id)
                .map_err(|error| {
                    CoreError::Storage(format!("local-cut owner history is invalid: {error}"))
                })?;
        }
        Ok(())
    }
}

pub(super) fn sqlite_sync_local_cut_owner_after_admission(
    connection: &Connection,
    input: &ManifestOwnerAdmissionInputV1,
    current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let owner_id = input.catalog.as_input().owner_id;
    let Some(local_cut_state) = sqlite_local_cut_owner_state_raw(connection, owner_id)? else {
        return if sqlite_local_cut_owner_has_rows(connection, owner_id)? {
            Err(ManifestOwnerAdmissionErrorV1::CorruptState)
        } else {
            Ok(())
        };
    };
    let current_state = current_state.ok_or(ManifestOwnerAdmissionErrorV1::CorruptState)?;
    if local_cut_state.configuration_generation != current_state.configuration_generation
        || local_cut_state.previous_visible_lcq1_hash != current_state.previous_visible_lcq1_hash
        || local_cut_state.inventory_generation != current_state.inventory_generation
        || local_cut_state.timelines != current_state.timelines
        || input.expected_configuration_generation != Some(local_cut_state.configuration_generation)
        || input.previous_visible_lcq1_hash != local_cut_state.previous_visible_lcq1_hash
        || input.expected_inventory_generation != Some(local_cut_state.inventory_generation)
    {
        return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
    }
    let timelines = input
        .timelines
        .iter()
        .map(|timeline| timeline.timeline_id)
        .collect::<Vec<_>>();
    let membership_epoch = if timelines == local_cut_state.timelines {
        local_cut_state.membership_epoch
    } else {
        local_cut_state
            .membership_epoch
            .checked_add(1)
            .ok_or(ManifestOwnerAdmissionErrorV1::Conflict)?
    };
    let changed = connection
        .execute(
            "UPDATE local_cut_owner_state
             SET membership_epoch = ?1, configuration_generation = ?2,
                 previous_visible_lcq1_hash = ?3, inventory_generation = ?4
             WHERE owner_id = ?5 AND last_visible_cut_id = ?6 AND last_visible_tick = ?7
               AND membership_epoch = ?8 AND configuration_generation = ?9
               AND previous_visible_lcq1_hash = ?10 AND inventory_generation = ?11",
            params![
                membership_epoch.to_be_bytes().as_slice(),
                input
                    .catalog
                    .as_input()
                    .configuration_generation
                    .to_be_bytes()
                    .as_slice(),
                input
                    .previous_visible_lcq1_hash
                    .map(|hash| hash.as_bytes().to_vec()),
                input.resulting_inventory_generation.as_bytes().as_slice(),
                owner_id.as_slice(),
                local_cut_state.last_visible_cut_id.to_be_bytes().as_slice(),
                local_cut_state.last_visible_tick.to_be_bytes().as_slice(),
                local_cut_state.membership_epoch.to_be_bytes().as_slice(),
                local_cut_state
                    .configuration_generation
                    .to_be_bytes()
                    .as_slice(),
                local_cut_state
                    .previous_visible_lcq1_hash
                    .map(|hash| hash.as_bytes().to_vec()),
                local_cut_state.inventory_generation.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| ManifestOwnerAdmissionErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(ManifestOwnerAdmissionErrorV1::Conflict);
    }
    connection
        .execute(
            "DELETE FROM local_cut_owner_state_timelines WHERE owner_id = ?1",
            params![owner_id.as_slice()],
        )
        .map_err(|_| ManifestOwnerAdmissionErrorV1::StorageFailure)?;
    for timeline_id in timelines {
        let timeline_bytes = timeline_id.inner().to_bytes();
        connection
            .execute(
                "INSERT INTO local_cut_owner_state_timelines (owner_id, timeline_id)
                 VALUES (?1, ?2)",
                params![owner_id.as_slice(), timeline_bytes.as_slice()],
            )
            .map_err(|_| ManifestOwnerAdmissionErrorV1::StorageFailure)?;
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod local_cut_owner_coverage {
    use super::*;
    use crate::manifest_owner_fixtures::{
        catalog, member_classes, timeline_request, zero_event_inputs, zero_event_results,
        READ_LIMITS, SOURCE_GENESIS,
    };
    use pos_core::{
        prepare_local_cut_owner_commit_v1, prepare_manifest_owner_admission_v1,
        LocalCutHeadsTableV1, LocalCutManifestBindingRowV1, LocalCutOwnerVerifierV1,
        LocalCutReceiptInputV1, ManifestAdmissionCatalogV1, ManifestOwnerAdmissionCommitKindV1,
        ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionSnapshotV1,
        ManifestOwnerAdmissionVerifierV1, ManifestOwnerClassifiedLeafV1,
        ManifestOwnerPolicyCopiesV1, ManifestOwnerScopeMembersV1,
        ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
        ManifestSlotAdmissionReceiptV1, PreparedManifestOwnerAdmissionV1,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    use super::super::FAIL_BEGIN_IMMEDIATE;

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
    type TestResult = Fallible<()>;
    type LocalError = LocalCutOwnerErrorV1;
    type AdmissionError = ManifestOwnerAdmissionErrorV1;

    const OWNER: [u8; 32] = [41; 32];
    const TIMELINES: [TimelineId; 2] = [timeline(1), timeline(2)];
    const SUCCESSOR_TIMELINES: [TimelineId; 2] = [timeline(3), timeline(4)];
    const FIRST_CUT: CutShape = CutShape {
        cut_id: 5,
        tick: 1,
        operation_id: hash(102),
        result_inventory: hash(111),
    };
    const SECOND_CUT: CutShape = CutShape {
        cut_id: 6,
        tick: 2,
        operation_id: hash(118),
        result_inventory: hash(113),
    };
    const THIRD_CUT: CutShape = CutShape {
        cut_id: 7,
        tick: 3,
        operation_id: hash(116),
        result_inventory: hash(114),
    };
    // Cut identities 255 and 256 order oppositely as little-endian bytes.
    const BYTE_EDGE_CUT: CutShape = CutShape {
        cut_id: 255,
        tick: 1,
        operation_id: hash(140),
        result_inventory: hash(141),
    };
    const BYTE_CARRY_CUT: CutShape = CutShape {
        cut_id: 256,
        tick: 2,
        operation_id: hash(142),
        result_inventory: hash(143),
    };
    const OLD_CUT: &str = "WHERE cut_id = X'0000000000000005'";
    const FIRST_TIMELINE_ROW: &str = "WHERE timeline_id = X'01010101010101010101010101010101'";
    // A well-formed kind-5 row recorded for the other Timeline of the cut.
    const SECOND_TIMELINE_RESULT_ROW: &str = "(SELECT result_head_cbor \
         FROM local_cut_world_recordings \
         WHERE timeline_id = X'02020202020202020202020202020202')";
    const CORRUPTION_PRAGMAS: &str =
        "PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON";
    const STATE_UPDATE_ABORT: &str = "CREATE TRIGGER fault \
         BEFORE UPDATE ON local_cut_owner_state \
         BEGIN SELECT RAISE(ABORT, 'state update fault'); END";
    const STATE_UPDATE_IGNORE: &str = "CREATE TRIGGER fault \
         BEFORE UPDATE ON local_cut_owner_state \
         BEGIN SELECT RAISE(IGNORE); END";
    const TIMELINE_DELETE_ABORT: &str = "CREATE TRIGGER fault \
         BEFORE DELETE ON local_cut_owner_state_timelines \
         BEGIN SELECT RAISE(ABORT, 'timeline delete fault'); END";
    const TIMELINE_INSERT_ABORT: &str = "CREATE TRIGGER fault \
         BEFORE INSERT ON local_cut_owner_state_timelines \
         BEGIN SELECT RAISE(ABORT, 'timeline insert fault'); END";
    const ADMISSION_UPDATE_IGNORE: &str = "CREATE TRIGGER fault \
         BEFORE UPDATE ON manifest_owner_admission_state \
         BEGIN SELECT RAISE(IGNORE); END";
    const RECORDING_INSERT_ABORT: &str = "CREATE TRIGGER fault \
         BEFORE INSERT ON local_cut_world_recordings \
         BEGIN SELECT RAISE(ABORT, 'recording insert fault'); END";
    const BRANCH_INSERT_ABORT: &str = "CREATE TRIGGER fault \
         BEFORE INSERT ON world_dependency_branches \
         BEGIN SELECT RAISE(ABORT, 'branch insert fault'); END";

    const fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    const fn plugin(byte: u8) -> PluginId {
        PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
    }

    const fn timeline(byte: u8) -> TimelineId {
        TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
    }

    // Structural stand-in for the installed manifest owner; it isolates the store port.
    struct AdmissionOwner;

    impl ManifestOwnerAdmissionVerifierV1 for AdmissionOwner {
        fn verify_complete_composition(
            &self,
            _catalog: &ManifestAdmissionCatalogV1,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn verify_complete_owned_scope_set(
            &self,
            _owner_id: [u8; 32],
            _timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn verify_coordinator_receipt(
            &self,
            _receipt: &ManifestSlotAdmissionReceiptV1,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn verify_owner_prestate_and_allocation(
            &self,
            _request: &ManifestOwnerAdmissionRequestV1,
            _current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn sign_coordinator_receipt(
            &self,
            draft: ManifestSlotAdmissionReceiptDraftV1,
        ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
            draft
                .with_evidence_and_signature(hash(90), [0x5a; 64])
                .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }

        fn verify_native_policy_copies(
            &self,
            _timeline_id: TimelineId,
            _scope: Hash,
            _copies: &ManifestOwnerPolicyCopiesV1,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn classify_scope_member_leaves(
            &self,
            _timeline_id: TimelineId,
            _scope: Hash,
            members: &ManifestOwnerScopeMembersV1,
        ) -> Result<Vec<ManifestOwnerClassifiedLeafV1>, ManifestOwnerAdmissionErrorV1> {
            Ok(member_classes(members))
        }
    }

    // Structural stand-in for the installed local-cut owner and coordinator signer.
    struct CutOwner;

    impl LocalCutOwnerVerifierV1 for CutOwner {
        fn verify_authenticated_cut(
            &self,
            _request: &LocalCutOwnerRequestV1,
            _current_state: Option<&LocalCutOwnerStateV1>,
            _admission_state: &ManifestOwnerAdmissionOwnerStateV1,
            _admissions: &[ManifestOwnerAdmissionSnapshotV1],
        ) -> Result<(), LocalCutOwnerErrorV1> {
            Ok(())
        }

        fn source_genesis_hash(
            &self,
            _timeline_id: TimelineId,
        ) -> Result<Hash, LocalCutOwnerErrorV1> {
            Ok(SOURCE_GENESIS)
        }

        fn sign_local_cut_receipt(
            &self,
            commit: &LocalCutCommitV1,
        ) -> Result<LocalCutReceiptV1, LocalCutOwnerErrorV1> {
            receipt_for(commit.digest()).map_err(|_| LocalCutOwnerErrorV1::OwnerRejected)
        }

        fn verify_local_cut_receipt(
            &self,
            _receipt: &LocalCutReceiptV1,
            _commit: &LocalCutCommitV1,
            _admissions: &[ManifestOwnerAdmissionSnapshotV1],
        ) -> Result<(), LocalCutOwnerErrorV1> {
            Ok(())
        }
    }

    fn receipt_for(commit_record_hash: Hash) -> Fallible<LocalCutReceiptV1> {
        Ok(LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
            commit_record_hash,
            coordinator_key_evidence_hash: hash(90),
            signature: [90; 64],
        })?)
    }

    fn admission_request(
        generation: u64,
        prestate: Option<&ManifestOwnerAdmissionOwnerStateV1>,
        timeline_ids: &[TimelineId],
        operation_id: Hash,
        resulting_inventory: Hash,
    ) -> Fallible<ManifestOwnerAdmissionRequestV1> {
        let (catalog, sources) = catalog(OWNER, generation)?;
        let mut timelines = Vec::with_capacity(timeline_ids.len());
        for timeline_id in timeline_ids {
            timelines.push(timeline_request(OWNER, *timeline_id, &sources)?);
        }
        Ok(ManifestOwnerAdmissionRequestV1 {
            operation_id,
            catalog,
            expected_configuration_generation: prestate.map(|s| s.configuration_generation),
            previous_visible_lcq1_hash: prestate.and_then(|s| s.previous_visible_lcq1_hash),
            expected_inventory_generation: prestate.map(|s| s.inventory_generation),
            resulting_inventory_generation: resulting_inventory,
            read_limits: READ_LIMITS,
            timelines,
        })
    }

    #[derive(Clone, Copy)]
    struct CutShape {
        cut_id: u64,
        tick: u64,
        operation_id: Hash,
        result_inventory: Hash,
    }

    type ResultHeads<'a> =
        &'a dyn Fn(&LocalCutSealV2, &[LocalCutRecordingContextRowV1]) -> ResultHeadRows;
    type ResultHeadRows = Fallible<Vec<LocalCutResultHeadRowV1>>;

    struct RequestParts<'a> {
        shape: CutShape,
        configuration_generation: u64,
        previous: Option<Hash>,
        expected_inventory: Hash,
        binding_rows: Vec<LocalCutManifestBindingRowV1>,
        composition_rows: Vec<LocalCutCompositionBindingRowV1>,
        recording_context_rows: Vec<LocalCutRecordingContextRowV1>,
        expected_head_rows: Vec<LocalCutExpectedHeadRowV1>,
        result_heads: ResultHeads<'a>,
    }

    fn table(row_count: u64, byte: u8) -> Fallible<LocalCutTableRefV1> {
        Ok(LocalCutTableRefV1::new(
            row_count,
            (row_count != 0).then(|| hash(byte)),
        )?)
    }

    fn request_from_parts(parts: RequestParts<'_>) -> Fallible<LocalCutOwnerRequestV1> {
        let cut_id = parts.shape.cut_id;
        let manifest_binding_table =
            LocalCutManifestBindingTableV1::new(OWNER, cut_id, parts.binding_rows)?;
        let expected_table =
            LocalCutHeadsTableV1::expected_heads(OWNER, cut_id, &parts.expected_head_rows)?;
        let membership_rows = u64::try_from(manifest_binding_table.rows().len())?;
        let composition_rows = u64::try_from(parts.composition_rows.len())?;
        let recording_rows = u64::try_from(parts.recording_context_rows.len())?;
        let seal = LocalCutSealV2::new(LocalCutSealInputV2 {
            owner_id: OWNER,
            cut_id: parts.shape.cut_id,
            tick: parts.shape.tick,
            membership_epoch: 0,
            configuration_generation: parts.configuration_generation,
            schedule_ns: 0,
            previous_visible_receipt_hash: parts.previous,
            expected_inventory_generation: parts.expected_inventory,
            membership_table: table(membership_rows, 94)?,
            composition_table: table(composition_rows, 92)?,
            inbox_table: table(0, 95)?,
            invocation_table: table(0, 96)?,
            expected_heads_table: expected_table.table_ref(),
            ebp_native_hash: hash(98),
            execution_profile_native_hash: hash(99),
            recording_context_table: table(recording_rows, 93)?,
            owner_operational_policy_hash: hash(100),
            explicit_attempt_hash: None,
            ingress_preallocation_native_hash: hash(101),
            manifest_binding_table: manifest_binding_table.table_ref(),
        })?;
        let result_head_rows = (parts.result_heads)(&seal, &parts.recording_context_rows)?;
        let result_table = LocalCutHeadsTableV1::result_heads(OWNER, cut_id, &result_head_rows)?;
        Ok(LocalCutOwnerRequestV1 {
            operation_id: parts.shape.operation_id,
            seal,
            manifest_hash: hash(103),
            manifest_binding_table,
            composition_rows: parts.composition_rows,
            recording_context_rows: parts.recording_context_rows,
            expected_head_rows: parts.expected_head_rows,
            result_head_rows,
            partition_ledger_seq: parts.shape.cut_id,
            result_heads_table: result_table.table_ref(),
            participant_successor_table: table(1, 106)?,
            cpu_completion_table: table(0, 107)?,
            action_disposition_table: table(1, 108)?,
            candidate_bases_table: table(0, 109)?,
            invocation_bridges_table: table(0, 110)?,
            result_inventory_generation: parts.shape.result_inventory,
            release_fence_proof_digest: hash(112),
        })
    }

    // A structurally complete request with no admitted owner behind it.
    fn synthetic_request(binding_count: u8) -> Fallible<LocalCutOwnerRequestV1> {
        let binding_rows = (1..=binding_count)
            .map(|index| LocalCutManifestBindingRowV1 {
                timeline_id: timeline(index),
                scope: hash(index),
                wcs_hash: hash(index),
                msr_hash: hash(index),
                msb_hash: hash(index),
            })
            .collect();
        request_from_parts(RequestParts {
            shape: CutShape {
                cut_id: 1,
                tick: 1,
                operation_id: hash(120),
                result_inventory: hash(121),
            },
            configuration_generation: 1,
            previous: None,
            expected_inventory: hash(122),
            binding_rows,
            composition_rows: vec![LocalCutCompositionBindingRowV1 {
                plugin_id: plugin(1),
                timeline_id: timeline(1),
                plugin_version: "1.0.0".to_owned(),
                implementation_hash: hash(123),
                eop1_native_digest: hash(124),
                driver_interval_ns: Some(7),
                last_due_ns: Some(3),
                event_cursor: 4,
                participant_native_state_hash: hash(125),
            }],
            recording_context_rows: vec![LocalCutRecordingContextRowV1 {
                timeline_id: timeline(1),
                wcs_hash: hash(126),
                retention_lease_hash: hash(127),
                predecessor_wcb_hash: Some(hash(128)),
            }],
            expected_head_rows: vec![LocalCutExpectedHeadRowV1 {
                timeline_id: timeline(1),
                logical_head: 3,
                stitched_chain_hash: hash(129),
                source_timeline_id: timeline(2),
                source_segment_head: 4,
                source_chain_hash: hash(130),
                logical_prefix: 5,
                lineage_proof_hash: Some(hash(131)),
                predecessor_wcb_hash: Some(hash(128)),
            }],
            result_heads: &|_, _| {
                Ok(vec![LocalCutResultHeadRowV1 {
                    timeline_id: timeline(1),
                    result_logical_head: 6,
                    result_stitched_hash: hash(132),
                    result_source_segment_head: 7,
                    result_source_chain_hash: hash(133),
                    successor_wcb_hash: hash(134),
                    event_count: 8,
                }])
            },
        })
    }

    fn cut_request(
        store: &SqliteStore,
        state: &ManifestOwnerAdmissionOwnerStateV1,
        snapshots: &[ManifestOwnerAdmissionSnapshotV1],
        shape: CutShape,
    ) -> Fallible<LocalCutOwnerRequestV1> {
        let binding_rows = snapshots
            .iter()
            .map(|snapshot| LocalCutManifestBindingRowV1 {
                timeline_id: snapshot.timeline.timeline_id,
                scope: snapshot.timeline.scope,
                wcs_hash: snapshot.timeline.wcs1.digest(),
                msr_hash: snapshot.timeline.receipt.digest(),
                msb_hash: snapshot.timeline.binding.digest(),
            })
            .collect();
        let mut composition_rows = Vec::new();
        for snapshot in snapshots {
            composition_rows.extend(snapshot.catalog.as_input().rows.iter().map(|row| {
                LocalCutCompositionBindingRowV1 {
                    plugin_id: row.plugin_id,
                    timeline_id: snapshot.timeline.timeline_id,
                    plugin_version: row.plugin_version.clone(),
                    implementation_hash: row.implementation_hash,
                    eop1_native_digest: row.eop1_native_digest,
                    driver_interval_ns: Some(0),
                    last_due_ns: None,
                    event_cursor: 0,
                    participant_native_state_hash: hash(91),
                }
            }));
        }
        composition_rows.sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
        let predecessor = |timeline_id| {
            sqlite_latest_local_cut_world_binding(&store.conn, OWNER, timeline_id)
                .ok()
                .flatten()
        };
        let (recording_context_rows, expected_head_rows) =
            zero_event_inputs(snapshots, &predecessor)?;
        let result_heads = |seal: &LocalCutSealV2, contexts: &[LocalCutRecordingContextRowV1]| {
            zero_event_results(shape.operation_id, seal, snapshots, contexts)
        };
        request_from_parts(RequestParts {
            shape,
            configuration_generation: state.configuration_generation,
            previous: state.previous_visible_lcq1_hash,
            expected_inventory: state.inventory_generation,
            binding_rows,
            composition_rows,
            recording_context_rows,
            expected_head_rows,
            result_heads: &result_heads,
        })
    }

    struct Admitted {
        store: SqliteStore,
        state: ManifestOwnerAdmissionOwnerStateV1,
        snapshots: Vec<ManifestOwnerAdmissionSnapshotV1>,
    }

    struct Committed {
        store: SqliteStore,
        genesis: ManifestOwnerAdmissionOwnerStateV1,
        snapshots: Vec<ManifestOwnerAdmissionSnapshotV1>,
        batch: PreparedLocalCutOwnerCommitV1,
    }

    fn snapshots_for(
        store: &SqliteStore,
        state: &ManifestOwnerAdmissionOwnerStateV1,
    ) -> Fallible<Vec<ManifestOwnerAdmissionSnapshotV1>> {
        let mut snapshots = Vec::with_capacity(state.timelines.len());
        for timeline_id in &state.timelines {
            let generation = state.configuration_generation;
            let found = store.read_manifest_owner_admission_v1(OWNER, generation, *timeline_id)?;
            snapshots.push(found.ok_or("missing admitted owner snapshot")?);
        }
        Ok(snapshots)
    }

    fn admitted() -> Fallible<Admitted> {
        admitted_in(SqliteStore::open_in_memory()?)
    }

    fn admitted_in(mut store: SqliteStore) -> Fallible<Admitted> {
        let request = admission_request(1, None, &TIMELINES, hash(41), hash(40))?;
        let prepared = prepare_manifest_owner_admission_v1(request, &AdmissionOwner, None)?;
        let applied = store.commit_manifest_owner_admission_v1(prepared)?;
        assert_eq!(applied.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
        store.conn.execute_batch(CORRUPTION_PRAGMAS)?;
        let state = store
            .read_manifest_owner_state_v1(OWNER)?
            .ok_or("missing admitted owner state")?;
        let snapshots = snapshots_for(&store, &state)?;
        Ok(Admitted {
            store,
            state,
            snapshots,
        })
    }

    fn prepare_cut(
        request: LocalCutOwnerRequestV1,
        current_state: Option<&LocalCutOwnerStateV1>,
        owner: &ManifestOwnerAdmissionOwnerStateV1,
        snapshots: &[ManifestOwnerAdmissionSnapshotV1],
    ) -> Fallible<PreparedLocalCutOwnerCommitV1> {
        Ok(prepare_local_cut_owner_commit_v1(
            request,
            current_state,
            owner,
            snapshots,
            &CutOwner,
        )?)
    }

    fn committed() -> Fallible<Committed> {
        committed_in(admitted()?)
    }

    fn committed_in(fixture: Admitted) -> Fallible<Committed> {
        let request = cut_request(
            &fixture.store,
            &fixture.state,
            &fixture.snapshots,
            FIRST_CUT,
        )?;
        let batch = prepare_cut(request, None, &fixture.state, &fixture.snapshots)?;
        let mut store = fixture.store;
        let applied = store.commit_local_cut_owner_v1(batch.clone())?;
        assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
        Ok(Committed {
            store,
            genesis: fixture.state,
            snapshots: fixture.snapshots,
            batch,
        })
    }

    // Commits the next cut on top of the current admitted and local-cut state.
    fn commit_next(
        store: &mut SqliteStore,
        snapshots: &[ManifestOwnerAdmissionSnapshotV1],
        shape: CutShape,
    ) -> Fallible<PreparedLocalCutOwnerCommitV1> {
        let current = current_admission(store)?;
        let local = store
            .read_local_cut_owner_state_v1(OWNER)?
            .ok_or("missing local-cut owner state")?;
        let request = cut_request(store, &current, snapshots, shape)?;
        let batch = prepare_cut(request, Some(&local), &current, snapshots)?;
        let applied = store.commit_local_cut_owner_v1(batch.clone())?;
        assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
        Ok(batch)
    }

    // Two visible cuts: FIRST_CUT is history and SECOND_CUT is current.
    fn with_history() -> Fallible<(Committed, PreparedLocalCutOwnerCommitV1)> {
        let mut fixture = committed()?;
        let second = commit_next(&mut fixture.store, &fixture.snapshots, SECOND_CUT)?;
        Ok((fixture, second))
    }

    fn current_admission(store: &SqliteStore) -> Fallible<ManifestOwnerAdmissionOwnerStateV1> {
        Ok(store
            .read_manifest_owner_state_v1(OWNER)?
            .ok_or("missing current owner admission")?)
    }

    // Runs one probe against temporarily corrupted rows, then restores them.
    fn with_rollback<T>(
        connection: &Connection,
        setup: &str,
        probe: impl FnOnce(&Connection) -> T,
    ) -> Fallible<T> {
        connection.execute_batch("BEGIN")?;
        connection.execute_batch(setup)?;
        let outcome = probe(connection);
        connection.execute_batch("ROLLBACK")?;
        Ok(outcome)
    }

    fn deny_read(
        connection: &Connection,
        table: &'static str,
        column: &'static str,
        allowed: usize,
    ) -> TestResult {
        let mut seen = 0_usize;
        connection.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                if table_name == table && column_name == column {
                    seen += 1;
                    if seen > allowed {
                        return Authorization::Deny;
                    }
                }
            }
            Authorization::Allow
        }))?;
        Ok(())
    }

    fn clear_authorizer(connection: &Connection) -> TestResult {
        connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        Ok(())
    }

    // Decode with the kind-4/kind-5 rows a stored cut reads from its WCB1 rows.
    fn decode_request(
        bytes: &[u8],
        request: &LocalCutOwnerRequestV1,
    ) -> Result<(LocalCutOwnerRequestV1, Hash), LocalError> {
        let heads = SqliteLocalCutHeadRowsV1 {
            expected: request.expected_head_rows.clone(),
            result: request.result_head_rows.clone(),
        };
        sqlite_decode_local_cut_owner_request(bytes, heads)
    }

    fn patched(bytes: &[u8], offset: usize, patch: &[u8]) -> Fallible<Vec<u8>> {
        let mut out = bytes.to_vec();
        out.get_mut(offset..offset + patch.len())
            .ok_or("patch outside the encoded request")?
            .copy_from_slice(patch);
        Ok(out)
    }

    fn after_cut_update<T>(
        connection: &Connection,
        assignments: &str,
        values: &[Vec<u8>],
        probe: impl FnOnce(&Connection) -> T,
    ) -> Fallible<T> {
        connection.execute_batch("BEGIN")?;
        connection.execute(
            &format!("UPDATE local_cut_owner_cuts SET {assignments}"),
            rusqlite::params_from_iter(values),
        )?;
        let outcome = probe(connection);
        connection.execute_batch("ROLLBACK")?;
        Ok(outcome)
    }

    fn assert_read_ports_fail(store: &SqliteStore, expected: LocalError) {
        assert_eq!(store.read_local_cut_owner_state_v1(OWNER), Err(expected));
        assert_eq!(
            store.resolve_local_cut_owner_retry_v1(OWNER, hash(1), hash(2)),
            Err(expected)
        );
        assert_eq!(
            store.read_local_cut_owner_commit_v1(OWNER, 1),
            Err(expected)
        );
        assert_eq!(
            store.verify_local_cut_owner_history_v1(OWNER),
            Err(expected)
        );
        let identity = ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(hash(3));
        assert_eq!(
            store.read_manifest_owner_link_snapshot_v1(OWNER, identity, timeline(1)),
            Err(expected)
        );
    }

    fn row_count(connection: &Connection, table: &str) -> Fallible<i64> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        Ok(connection.query_row(&sql, [], |row| row.get(0))?)
    }

    fn first_recording_update(assignment: &str) -> String {
        format!("UPDATE local_cut_world_recordings SET {assignment} {FIRST_TIMELINE_ROW}")
    }

    fn seeded_owner_state() -> Fallible<SqliteStore> {
        let store = SqliteStore::open_in_memory()?;
        store.conn.execute(
            "INSERT INTO local_cut_owner_state VALUES (?1, ?2, ?2, ?3, ?2, ?4, ?5)",
            params![
                OWNER.as_slice(),
                1_u64.to_be_bytes().as_slice(),
                0_u32.to_be_bytes().as_slice(),
                hash(9).as_bytes().as_slice(),
                hash(10).as_bytes().as_slice(),
            ],
        )?;
        store.conn.execute(
            "INSERT INTO local_cut_owner_state_timelines VALUES (?1, ?2)",
            params![OWNER.as_slice(), timeline(1).inner().to_bytes().as_slice()],
        )?;
        store.conn.execute_batch(CORRUPTION_PRAGMAS)?;
        Ok(store)
    }

    fn owner_state(last_visible_cut_id: u64, previous: Option<Hash>) -> LocalCutOwnerStateV1 {
        LocalCutOwnerStateV1 {
            owner_id: OWNER,
            last_visible_cut_id,
            last_visible_tick: last_visible_cut_id,
            membership_epoch: 0,
            configuration_generation: 1,
            previous_visible_lcq1_hash: previous,
            inventory_generation: hash(10),
            timelines: vec![timeline(1)],
        }
    }

    fn successor_admission(
        current: &ManifestOwnerAdmissionOwnerStateV1,
    ) -> Fallible<PreparedManifestOwnerAdmissionV1> {
        let request =
            admission_request(2, Some(current), &SUCCESSOR_TIMELINES, hash(141), hash(142))?;
        Ok(prepare_manifest_owner_admission_v1(
            request,
            &AdmissionOwner,
            Some(current),
        )?)
    }

    #[test]
    fn fixed_width_fields_and_cursor_reject_short_or_unknown_input() {
        let short = [1_u8; 3];
        let corrupt = Some(LocalError::CorruptState);
        assert_eq!(sqlite_local_cut_owner_u64(&short).err(), corrupt);
        assert_eq!(sqlite_local_cut_owner_u32(&short).err(), corrupt);
        assert_eq!(sqlite_local_cut_owner_hash(&short).err(), corrupt);
        assert_eq!(sqlite_local_cut_owner_timeline(&short).err(), corrupt);

        let mut overflowing = SqliteLocalCutOwnerCursorV1 {
            bytes: &short,
            offset: usize::MAX,
        };
        assert_eq!(overflowing.take(1), Err(LocalError::CorruptState));
        let mut empty = SqliteLocalCutOwnerCursorV1::new(&[]);
        assert_eq!(empty.u8(), Err(LocalError::CorruptState));
        assert_eq!(empty.u32(), Err(LocalError::CorruptState));
        assert_eq!(empty.u64(), Err(LocalError::CorruptState));
        assert_eq!(empty.hash(), Err(LocalError::CorruptState));
        assert_eq!(empty.timeline(), Err(LocalError::CorruptState));
        assert_eq!(empty.plugin(), Err(LocalError::CorruptState));
        assert_eq!(empty.count(), Err(LocalError::CorruptState));
        assert_eq!(empty.blob(1), Err(LocalError::CorruptState));
        assert_eq!(empty.optional_hash(), Err(LocalError::CorruptState));
        assert_eq!(empty.optional_u64(), Err(LocalError::CorruptState));
        assert_eq!(
            sqlite_read_local_cut_owner_table(&mut empty).err(),
            Some(LocalError::CorruptState)
        );

        let oversized_blob = [0_u8, 0, 0, 2, 9, 9];
        let mut oversized = SqliteLocalCutOwnerCursorV1::new(&oversized_blob);
        assert_eq!(oversized.blob(1), Err(LocalError::CorruptState));
        let unknown_tag = [2_u8];
        let mut unknown_hash = SqliteLocalCutOwnerCursorV1::new(&unknown_tag);
        assert_eq!(unknown_hash.optional_hash(), Err(LocalError::CorruptState));
        let mut unknown_u64 = SqliteLocalCutOwnerCursorV1::new(&unknown_tag);
        assert_eq!(unknown_u64.optional_u64(), Err(LocalError::CorruptState));
        let unknown_root = [0_u8, 0, 0, 0, 0, 0, 0, 1, 2];
        let mut table_cursor = SqliteLocalCutOwnerCursorV1::new(&unknown_root);
        assert_eq!(
            sqlite_read_local_cut_owner_table(&mut table_cursor).err(),
            Some(LocalError::CorruptState)
        );
    }

    #[test]
    fn request_header_and_length_bounds_are_enforced() {
        // Zeroed allocation is lazily mapped; the length check rejects it unread.
        let oversized = vec![0_u8; SQLITE_MAX_LOCAL_CUT_OWNER_REQUEST_BYTES_V1 + 1];
        assert_eq!(
            sqlite_local_cut_owner_request_cursor(&oversized).err(),
            Some(LocalError::CorruptState)
        );
        let headers: [&[u8]; 4] = [b"LC", b"LCOQ1", b"LCOQ2\x01", b"LCOQ1\x02"];
        for header in headers {
            assert_eq!(
                sqlite_local_cut_owner_request_cursor(header).err(),
                Some(LocalError::CorruptState)
            );
        }
    }

    #[test]
    fn request_decoder_rejects_every_truncated_prefix() -> TestResult {
        let request = synthetic_request(1)?;
        let bytes = sqlite_local_cut_owner_request_bytes(&request);
        let (decoded, intent_digest) = decode_request(&bytes, &request)?;
        assert_eq!(decoded, request);
        assert_eq!(intent_digest, local_cut_owner_intent_digest_v1(&request)?);
        for length in 0..bytes.len() {
            assert_eq!(
                decode_request(&bytes[..length], &request).err(),
                Some(LocalError::CorruptState),
                "{length}"
            );
        }
        Ok(())
    }

    #[test]
    fn request_decoder_rejects_structurally_invalid_fields() -> TestResult {
        let request = synthetic_request(1)?;
        let bytes = sqlite_local_cut_owner_request_bytes(&request);
        // Magic, version, operation, then the length-prefixed LCS2 seal.
        let seal_at = 42;
        let records_at = seal_at + request.seal.to_canonical_cbor().len() + 32;
        let records_len = request
            .manifest_binding_table
            .records()
            .iter()
            .map(|record| 4 + record.len())
            .sum::<usize>();
        let composition_at = records_at + 4 + records_len;
        // Plugin, Timeline, version blob, two hashes, two optional u64s, cursor, hash.
        let contexts_at = composition_at + 4 + 16 + 16 + 4 + 5 + 32 + 32 + 9 + 9 + 8 + 32;
        let mut trailing = bytes.clone();
        trailing.push(0);
        let candidates = [
            patched(&bytes, seal_at, &[0xff])?,
            patched(&bytes, records_at, &[0; 4])?,
            patched(&bytes, composition_at - 1, &[0xee])?,
            patched(&bytes, composition_at, &[0; 4])?,
            patched(&bytes, composition_at + 4 + 36, &[0xff])?,
            patched(&bytes, contexts_at, &[0; 4])?,
            patched(&bytes, 6, &[0; 32])?,
            trailing,
        ];
        for candidate in candidates {
            assert_eq!(
                decode_request(&candidate, &request).err(),
                Some(LocalError::CorruptState)
            );
        }
        Ok(())
    }

    #[test]
    fn request_decoder_rejects_reordered_manifest_records() -> TestResult {
        let request = synthetic_request(65)?;
        let bytes = sqlite_local_cut_owner_request_bytes(&request);
        let records = request.manifest_binding_table.records();
        let first_record_at = 42 + request.seal.to_canonical_cbor().len() + 32 + 4;
        let records_len = records.iter().map(|record| 4 + record.len()).sum::<usize>();
        let prefix = bytes.get(..first_record_at).ok_or("short request")?;
        let mut reordered = prefix.to_vec();
        for record in records.iter().rev() {
            sqlite_append_local_cut_owner_blob(&mut reordered, record);
        }
        let suffix = bytes
            .get(first_record_at + records_len..)
            .ok_or("short request")?;
        reordered.extend_from_slice(suffix);
        assert!(records.len() > 1);
        assert_eq!(reordered.len(), bytes.len());
        assert_ne!(reordered, bytes);
        assert_eq!(
            decode_request(&reordered, &request).err(),
            Some(LocalError::CorruptState)
        );
        Ok(())
    }

    #[test]
    fn read_ports_fail_closed_without_a_snapshot_or_commit() -> TestResult {
        let store = SqliteStore::open_in_memory()?;
        store.conn.execute_batch("BEGIN")?;
        assert_read_ports_fail(&store, LocalError::StorageFailure);
        store.conn.execute_batch("ROLLBACK")?;
        store.conn.authorizer(Some(|context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Transaction {
                    operation: TransactionOperation::Unknown
                }
            ) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))?;
        assert_read_ports_fail(&store, LocalError::StorageFailure);
        clear_authorizer(&store.conn)?;

        let orphaned = SqliteStore::open_in_memory()?;
        orphaned.conn.execute(
            "INSERT INTO local_cut_owner_cuts VALUES (?1, ?2, ?3, ?3, X'00', X'00', X'00')",
            params![
                OWNER.as_slice(),
                1_u64.to_be_bytes().as_slice(),
                hash(1).as_bytes().as_slice(),
            ],
        )?;
        assert_read_ports_fail(&orphaned, LocalError::CorruptState);
        Ok(())
    }

    #[test]
    fn owner_reads_report_missing_row_tables() -> TestResult {
        let store = SqliteStore::open_in_memory()?;
        store
            .conn
            .execute_batch("DROP TABLE local_cut_owner_cuts")?;
        assert_eq!(
            store.read_local_cut_owner_state_v1(OWNER),
            Err(LocalError::StorageFailure)
        );
        assert_eq!(
            store.read_manifest_owner_state_v1(OWNER),
            Err(AdmissionError::StorageFailure)
        );
        let store = SqliteStore::open_in_memory()?;
        store
            .conn
            .execute_batch("DROP TABLE manifest_owner_policy_copies")?;
        assert_eq!(
            store.read_manifest_owner_state_v1(OWNER),
            Err(AdmissionError::StorageFailure)
        );
        Ok(())
    }

    #[test]
    fn raw_owner_state_rejects_each_malformed_column() -> TestResult {
        let store = seeded_owner_state()?;
        let connection = &store.conn;
        assert!(sqlite_local_cut_owner_state_raw(connection, OWNER)?.is_some());
        assert_eq!(
            sqlite_read_local_cut_owner_state(connection, OWNER),
            Err(LocalError::CorruptState)
        );
        let mut mutations = Vec::new();
        for column in [
            "last_visible_cut_id",
            "last_visible_tick",
            "membership_epoch",
            "configuration_generation",
            "previous_visible_lcq1_hash",
            "inventory_generation",
        ] {
            let update = format!("UPDATE local_cut_owner_state SET {column}");
            mutations.push((format!("{update} = 7"), LocalError::StorageFailure));
            mutations.push((format!("{update} = X'01'"), LocalError::CorruptState));
        }
        for (mutation, expected) in [
            (
                "UPDATE local_cut_owner_state SET configuration_generation = zeroblob(8)",
                LocalError::CorruptState,
            ),
            (
                "UPDATE local_cut_owner_state_timelines SET timeline_id = 7",
                LocalError::StorageFailure,
            ),
            (
                "UPDATE local_cut_owner_state_timelines SET timeline_id = X'01'",
                LocalError::CorruptState,
            ),
            (
                "DROP TABLE local_cut_owner_state_timelines",
                LocalError::StorageFailure,
            ),
        ] {
            mutations.push((mutation.to_owned(), expected));
        }
        for (mutation, expected) in mutations {
            let outcome = with_rollback(connection, &mutation, |connection| {
                sqlite_local_cut_owner_state_raw(connection, OWNER)
            })?;
            assert_eq!(outcome, Err(expected), "{mutation}");
            let read = with_rollback(connection, &mutation, |connection| {
                sqlite_read_local_cut_owner_state(connection, OWNER)
            })?;
            assert_eq!(read, Err(expected), "{mutation}");
        }
        Ok(())
    }

    #[test]
    fn owner_state_writes_reject_invalid_successors_and_failed_rows() -> TestResult {
        let store = SqliteStore::open_in_memory()?;
        let connection = &store.conn;
        let successor = owner_state(1, Some(hash(9)));
        let mut ownerless = successor.clone();
        ownerless.owner_id = [0; 32];
        assert_eq!(
            sqlite_write_local_cut_owner_state(connection, None, &ownerless),
            Err(LocalError::CorruptState)
        );
        assert_eq!(
            sqlite_write_local_cut_owner_state(connection, None, &owner_state(0, None)),
            Err(LocalError::CorruptState)
        );
        sqlite_write_local_cut_owner_state(connection, None, &successor)?;
        let stale = owner_state(2, Some(hash(8)));
        let cases = [
            ("", None, LocalError::StorageFailure),
            ("", Some(&stale), LocalError::Conflict),
            (
                STATE_UPDATE_ABORT,
                Some(&successor),
                LocalError::StorageFailure,
            ),
            (
                "DROP TABLE local_cut_owner_state_timelines",
                Some(&successor),
                LocalError::StorageFailure,
            ),
            (
                TIMELINE_INSERT_ABORT,
                Some(&successor),
                LocalError::StorageFailure,
            ),
        ];
        for (setup, current, expected) in cases {
            let outcome = with_rollback(connection, setup, |connection| {
                sqlite_write_local_cut_owner_state(connection, current, &successor)
            })?;
            assert_eq!(outcome, Err(expected), "{setup}");
        }
        Ok(())
    }

    #[test]
    fn admitted_state_update_after_cut_requires_the_current_row() -> TestResult {
        let fixture = committed()?;
        let applied = fixture.batch.applied_result();
        let current = current_admission(&fixture.store)?;
        let connection = &fixture.store.conn;
        assert_eq!(
            sqlite_update_manifest_owner_state_after_local_cut(
                connection,
                &fixture.genesis,
                &applied,
            ),
            Err(LocalError::Conflict)
        );
        let drop_state = "DROP TABLE manifest_owner_admission_state";
        let dropped = with_rollback(connection, drop_state, |connection| {
            sqlite_update_manifest_owner_state_after_local_cut(connection, &current, &applied)
        })?;
        assert_eq!(dropped, Err(LocalError::StorageFailure));
        Ok(())
    }

    #[test]
    fn stored_cut_rows_reject_each_malformed_column() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let cut = FIRST_CUT.cut_id;
        let by_id = |conn: &Connection| sqlite_local_cut_owner_cut_by_id(conn, OWNER, cut).err();
        assert_eq!(by_id(connection), None);
        for column in [
            "operation_id",
            "intent_digest",
            "request_bytes",
            "commit_cbor",
            "receipt_cbor",
        ] {
            let typed = after_cut_update(connection, &format!("{column} = 7"), &[], by_id)?;
            assert_eq!(typed, Some(LocalError::StorageFailure), "{column}");
            let short = after_cut_update(connection, &format!("{column} = X'01'"), &[], by_id)?;
            assert_eq!(short, Some(LocalError::CorruptState), "{column}");
        }
        Ok(())
    }

    #[test]
    fn stored_cut_rows_reject_substituted_identities_and_records() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let cut = FIRST_CUT.cut_id;
        let by_id = |conn: &Connection| sqlite_local_cut_owner_cut_by_id(conn, OWNER, cut).err();
        let mut commit_input = *fixture.batch.commit().as_input();
        commit_input.partition_ledger_seq += 1;
        let substituted = LocalCutCommitV1::new(commit_input)?;
        let foreign_receipt = receipt_for(hash(79))?.to_canonical_cbor();
        let substituted_receipt = receipt_for(substituted.digest())?.to_canonical_cbor();
        let cases = [
            ("operation_id = ?1", vec![hash(77).as_bytes().to_vec()]),
            ("intent_digest = ?1", vec![hash(78).as_bytes().to_vec()]),
            ("receipt_cbor = ?1", vec![foreign_receipt]),
            (
                "commit_cbor = ?1, receipt_cbor = ?2",
                vec![substituted.to_canonical_cbor(), substituted_receipt],
            ),
        ];
        for (assignments, values) in cases {
            let outcome = after_cut_update(connection, assignments, &values, by_id)?;
            assert_eq!(outcome, Some(LocalError::CorruptState), "{assignments}");
        }
        Ok(())
    }

    #[test]
    fn operation_lookup_and_insert_reject_corrupt_or_existing_cuts() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let batch = &fixture.batch;
        let op_id = batch.request().operation_id;
        let intent = batch.intent_digest();
        let by_operation =
            |conn: &Connection| sqlite_local_cut_owner_cut_by_operation(conn, OWNER, op_id).err();
        let retry = |conn: &Connection| {
            sqlite_resolve_local_cut_owner_retry(conn, OWNER, op_id, intent).err()
        };
        let insert = |conn: &Connection| sqlite_insert_local_cut_owner_cut(conn, batch).err();
        let corrupt = Some(LocalError::CorruptState);
        assert_eq!(
            after_cut_update(connection, "cut_id = 7", &[], by_operation)?,
            Some(LocalError::StorageFailure)
        );
        let short_id = after_cut_update(connection, "cut_id = X'01'", &[], by_operation)?;
        assert_eq!(short_id, corrupt);
        let damaged = "receipt_cbor = X'01'";
        let damaged_lookup = after_cut_update(connection, damaged, &[], by_operation)?;
        assert_eq!(damaged_lookup, corrupt);
        assert_eq!(after_cut_update(connection, damaged, &[], retry)?, corrupt);
        let conflict = Some(LocalError::Conflict);
        assert_eq!(insert(connection), conflict);
        let moved = [9_u64.to_be_bytes().to_vec()];
        let moved_insert = after_cut_update(connection, "cut_id = ?1", &moved, insert)?;
        assert_eq!(moved_insert, conflict);
        let renamed = [hash(119).as_bytes().to_vec()];
        let renamed_insert = after_cut_update(connection, "operation_id = ?1", &renamed, insert)?;
        assert_eq!(renamed_insert, conflict);
        deny_read(connection, "local_cut_owner_cuts", "operation_id", 0)?;
        assert_eq!(insert(connection), Some(LocalError::StorageFailure));
        clear_authorizer(connection)?;
        Ok(())
    }

    #[test]
    fn owner_state_read_rejects_inconsistent_visible_cuts() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let read = |conn: &Connection| sqlite_read_local_cut_owner_state(conn, OWNER).err();
        let corrupt = Some(LocalError::CorruptState);
        assert_eq!(read(connection), None);
        // A non-blob identity hides the current cut from the keyed lookup.
        let typed_id = after_cut_update(connection, "cut_id = 7", &[], read)?;
        assert_eq!(typed_id, corrupt);
        let short_id = after_cut_update(connection, "cut_id = X'01'", &[], read)?;
        assert_eq!(short_id, corrupt);
        let damaged = after_cut_update(connection, "receipt_cbor = X'01'", &[], read)?;
        assert_eq!(damaged, corrupt);
        for setup in [
            "UPDATE local_cut_owner_state SET last_visible_cut_id = X'0000000000000003'",
            "UPDATE local_cut_owner_state SET last_visible_cut_id = X'0000000000000007'",
            "UPDATE local_cut_owner_state SET previous_visible_lcq1_hash = randomblob(32);
             UPDATE manifest_owner_admission_state SET previous_visible_lcq1_hash =
                 (SELECT previous_visible_lcq1_hash FROM local_cut_owner_state)",
        ] {
            assert_eq!(with_rollback(connection, setup, read)?, corrupt, "{setup}");
        }
        deny_read(connection, "local_cut_owner_cuts", "cut_id", 0)?;
        assert_eq!(
            fixture.store.read_local_cut_owner_state_v1(OWNER),
            Err(LocalError::StorageFailure)
        );
        clear_authorizer(connection)?;
        deny_read(connection, "local_cut_owner_cuts", "receipt_cbor", 1)?;
        assert_eq!(
            fixture
                .store
                .read_local_cut_owner_commit_v1(OWNER, FIRST_CUT.cut_id),
            Err(LocalError::StorageFailure)
        );
        clear_authorizer(connection)?;
        Ok(())
    }

    #[test]
    fn cut_commit_rolls_back_each_failed_step() -> TestResult {
        let fixture = admitted()?;
        let request = cut_request(
            &fixture.store,
            &fixture.state,
            &fixture.snapshots,
            FIRST_CUT,
        )?;
        let batch = prepare_cut(request, None, &fixture.state, &fixture.snapshots)?;
        let mut unadmitted = SqliteStore::open_in_memory()?;
        assert_eq!(
            unadmitted.commit_local_cut_owner_v1(batch.clone()),
            Err(LocalError::Conflict)
        );
        let mut store = fixture.store;
        FAIL_BEGIN_IMMEDIATE.with(|fail| fail.set(true));
        let unavailable = store.commit_local_cut_owner_v1(batch.clone());
        FAIL_BEGIN_IMMEDIATE.with(|fail| fail.set(false));
        assert_eq!(unavailable, Err(LocalError::StorageFailure));
        for (setup, expected) in [
            (
                "UPDATE manifest_owner_admission_state SET inventory_generation = X'01'",
                LocalError::CorruptState,
            ),
            (TIMELINE_INSERT_ABORT, LocalError::StorageFailure),
            (RECORDING_INSERT_ABORT, LocalError::StorageFailure),
            (BRANCH_INSERT_ABORT, LocalError::StorageFailure),
            (ADMISSION_UPDATE_IGNORE, LocalError::Conflict),
        ] {
            store.conn.execute_batch("BEGIN")?;
            store.conn.execute_batch(setup)?;
            let outcome = store.commit_local_cut_owner_v1(batch.clone());
            store.conn.execute_batch("ROLLBACK")?;
            assert_eq!(outcome, Err(expected), "{setup}");
        }
        let applied = store.commit_local_cut_owner_v1(batch.clone())?;
        assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
        let retry = store.commit_local_cut_owner_v1(batch)?;
        assert_eq!(retry.kind, LocalCutOwnerCommitKindV1::ExactRetry);
        Ok(())
    }

    #[test]
    fn cut_commit_rejects_corrupt_history_and_stale_successors() -> TestResult {
        let mut fixture = committed()?;
        let stale_shape = CutShape {
            operation_id: hash(119),
            ..FIRST_CUT
        };
        let stale_request = cut_request(
            &fixture.store,
            &fixture.genesis,
            &fixture.snapshots,
            stale_shape,
        )?;
        let stale = prepare_cut(stale_request, None, &fixture.genesis, &fixture.snapshots)?;
        assert_eq!(
            fixture.store.commit_local_cut_owner_v1(stale.clone()),
            Err(LocalError::Conflict)
        );
        // Reusing the committed operation for another intent conflicts on retry lookup.
        let reused_shape = CutShape {
            result_inventory: hash(117),
            ..FIRST_CUT
        };
        let reused_request = cut_request(
            &fixture.store,
            &fixture.genesis,
            &fixture.snapshots,
            reused_shape,
        )?;
        let reused = prepare_cut(reused_request, None, &fixture.genesis, &fixture.snapshots)?;
        assert_ne!(reused.intent_digest(), fixture.batch.intent_digest());
        assert_eq!(
            fixture.store.commit_local_cut_owner_v1(reused),
            Err(LocalError::Conflict)
        );
        fixture
            .store
            .conn
            .execute_batch("BEGIN; UPDATE local_cut_owner_cuts SET receipt_cbor = X'01'")?;
        let corrupt = fixture.store.commit_local_cut_owner_v1(stale);
        fixture.store.conn.execute_batch("ROLLBACK")?;
        assert_eq!(corrupt, Err(LocalError::CorruptState));
        Ok(())
    }

    #[test]
    fn batch_validation_rejects_mismatched_owner_prestates() -> TestResult {
        let fixture = committed()?;
        let batch = &fixture.batch;
        let genesis = &fixture.genesis;
        let conflict = Err(LocalError::Conflict);
        let mut advanced = genesis.clone();
        advanced.configuration_generation += 1;
        assert_eq!(
            validate_local_cut_owner_successor_v1(batch, &advanced, None),
            conflict
        );
        let exhausted = LocalCutOwnerStateV1 {
            last_visible_tick: u64::MAX,
            ..batch.successor_state().clone()
        };
        assert_eq!(
            validate_local_cut_owner_successor_v1(batch, genesis, Some(&exhausted)),
            conflict
        );
        let ahead = LocalCutOwnerStateV1 {
            last_visible_cut_id: 9,
            last_visible_tick: 0,
            ..batch.successor_state().clone()
        };
        assert_eq!(
            validate_local_cut_owner_successor_v1(batch, genesis, Some(&ahead)),
            conflict
        );
        let current = current_admission(&fixture.store)?;
        let local = fixture
            .store
            .read_local_cut_owner_state_v1(OWNER)?
            .ok_or("missing local-cut owner state")?;
        let second_shape = CutShape {
            cut_id: 6,
            tick: 2,
            operation_id: hash(118),
            result_inventory: hash(113),
        };
        let second_request =
            cut_request(&fixture.store, &current, &fixture.snapshots, second_shape)?;
        let second = prepare_cut(second_request, Some(&local), &current, &fixture.snapshots)?;
        assert_eq!(
            validate_local_cut_owner_successor_v1(&second, &current, None),
            conflict
        );
        assert_eq!(
            validate_local_cut_owner_successor_v1(&second, &current, Some(&local)),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn nested_cut_scope_reports_released_savepoints() -> TestResult {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("BEGIN")?;
        let scope = begin_immediate_scope(&connection)?;
        assert_eq!(
            finish_owner_scope(&connection, scope, Ok(3), LocalError::StorageFailure),
            Ok(3)
        );
        let scope = begin_immediate_scope(&connection)?;
        let rejected: Result<(), LocalError> = Err(LocalError::Conflict);
        assert_eq!(
            finish_owner_scope(&connection, scope, rejected, LocalError::StorageFailure),
            rejected
        );
        for result in [Ok(()), rejected] {
            let scope = begin_immediate_scope(&connection)?;
            connection.execute_batch("RELEASE SAVEPOINT pigloros_protected_effect")?;
            assert_eq!(
                finish_owner_scope(&connection, scope, result, LocalError::StorageFailure),
                Err(LocalError::StorageFailure)
            );
        }
        connection.execute_batch("ROLLBACK")?;
        Ok(())
    }

    #[test]
    fn admitted_state_read_rejects_divergent_local_cut_rows() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let read = |conn: &Connection| sqlite_read_manifest_owner_current_state(conn, OWNER).err();
        assert_eq!(read(connection), None);
        for setup in [
            "UPDATE local_cut_owner_state SET membership_epoch = X'01'",
            "UPDATE local_cut_owner_state SET inventory_generation = randomblob(32)",
        ] {
            let outcome = with_rollback(connection, setup, read)?;
            assert_eq!(outcome, Some(AdmissionError::CorruptState), "{setup}");
        }
        Ok(())
    }

    #[test]
    fn admitted_state_read_rejects_orphan_or_unreadable_local_cut_rows() -> TestResult {
        let fixture = admitted()?;
        let connection = &fixture.store.conn;
        let read = |conn: &Connection| sqlite_read_manifest_owner_current_state(conn, OWNER).err();
        assert_eq!(read(connection), None);
        let orphan = "INSERT INTO local_cut_owner_state_timelines
             SELECT owner_id, zeroblob(16) FROM manifest_owner_admission_state";
        let orphaned = with_rollback(connection, orphan, read)?;
        assert_eq!(orphaned, Some(AdmissionError::CorruptState));
        deny_read(connection, "local_cut_owner_state_timelines", "owner_id", 0)?;
        assert_eq!(read(connection), Some(AdmissionError::StorageFailure));
        clear_authorizer(connection)?;
        let damaged = "UPDATE manifest_owner_admissions SET scope = X'01'
             WHERE timeline_id = (SELECT MAX(timeline_id) FROM manifest_owner_admissions)";
        let store = &fixture.store;
        let snapshot = with_rollback(connection, damaged, |_| {
            store.read_manifest_owner_admission_v1(OWNER, 1, TIMELINES[0])
        })?;
        assert_eq!(snapshot.err(), Some(AdmissionError::CorruptState));
        Ok(())
    }

    #[test]
    fn successor_admission_sync_rejects_divergent_or_failed_local_cut_rows() -> TestResult {
        let mut fixture = committed()?;
        let current = current_admission(&fixture.store)?;
        let successor = successor_admission(&current)?;
        let input = successor.input();
        let connection = &fixture.store.conn;
        let corrupt = Err(AdmissionError::CorruptState);
        assert_eq!(
            sqlite_sync_local_cut_owner_after_admission(connection, input, None),
            corrupt
        );
        let mut advanced = current.clone();
        advanced.configuration_generation += 1;
        assert_eq!(
            sqlite_sync_local_cut_owner_after_admission(connection, input, Some(&advanced)),
            corrupt
        );
        let sync = |conn: &Connection| {
            sqlite_sync_local_cut_owner_after_admission(conn, input, Some(&current))
        };
        assert_eq!(with_rollback(connection, "", sync)?, Ok(()));
        for (setup, expected) in [
            (
                "UPDATE local_cut_owner_state SET membership_epoch = X'01'",
                AdmissionError::CorruptState,
            ),
            (
                "UPDATE local_cut_owner_state SET membership_epoch = X'FFFFFFFF'",
                AdmissionError::Conflict,
            ),
            (STATE_UPDATE_IGNORE, AdmissionError::Conflict),
            (TIMELINE_DELETE_ABORT, AdmissionError::StorageFailure),
            (TIMELINE_INSERT_ABORT, AdmissionError::StorageFailure),
            (
                "DELETE FROM local_cut_owner_state",
                AdmissionError::CorruptState,
            ),
            (
                "DELETE FROM local_cut_owner_state_timelines;
                 DELETE FROM local_cut_owner_state;
                 DROP TABLE local_cut_owner_cuts",
                AdmissionError::StorageFailure,
            ),
        ] {
            let outcome = with_rollback(connection, setup, sync)?;
            assert_eq!(outcome, Err(expected), "{setup}");
        }
        fixture.store.conn.execute_batch(STATE_UPDATE_ABORT)?;
        assert_eq!(
            fixture.store.commit_manifest_owner_admission_v1(successor),
            Err(AdmissionError::StorageFailure)
        );
        Ok(())
    }

    #[test]
    fn cut_commit_persists_and_returns_each_wcb1_wcr1_and_wdb1_node() -> TestResult {
        let (fixture, second) = with_history()?;
        let connection = &fixture.store.conn;
        let first = fixture.batch.applied_result();
        assert_eq!(first.recordings.len(), TIMELINES.len());
        assert_eq!(
            fixture
                .store
                .read_local_cut_owner_commit_v1(OWNER, FIRST_CUT.cut_id)?,
            Some(first.clone())
        );
        for (earlier, later) in first.recordings.iter().zip(second.recordings()) {
            let timeline_id = later.binding.as_input().timeline_id;
            let chained = later.binding.as_input().predecessor_binding_hash;
            assert_eq!(chained, Some(earlier.binding.digest()));
            assert_eq!(
                sqlite_latest_local_cut_world_binding(connection, OWNER, timeline_id)?,
                Some(later.binding.digest())
            );
        }
        let unknown = sqlite_latest_local_cut_world_binding(connection, OWNER, timeline(9))?;
        assert_eq!(unknown, None);
        assert_eq!(row_count(connection, "local_cut_world_recordings")?, 4);
        let nodes = fixture
            .batch
            .dependency_directories()
            .iter()
            .map(|directory| directory.branches().len())
            .sum::<usize>();
        let stored = row_count(connection, "world_dependency_branches")?;
        assert_eq!(usize::try_from(stored)?, nodes);
        Ok(())
    }

    #[test]
    fn cut_commit_rejects_a_stale_wcb1_predecessor() -> TestResult {
        let mut fixture = committed()?;
        let current = current_admission(&fixture.store)?;
        let local = fixture.store.read_local_cut_owner_state_v1(OWNER)?;
        let unrecorded = SqliteStore::open_in_memory()?;
        let request = cut_request(&unrecorded, &current, &fixture.snapshots, SECOND_CUT)?;
        let batch = prepare_cut(request, local.as_ref(), &current, &fixture.snapshots)?;
        assert_eq!(
            fixture.store.commit_local_cut_owner_v1(batch),
            Err(LocalError::Conflict)
        );
        Ok(())
    }

    #[test]
    fn stored_world_recordings_report_mistyped_columns() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let cut = FIRST_CUT.cut_id;
        let by_id = |conn: &Connection| sqlite_local_cut_owner_cut_by_id(conn, OWNER, cut).err();
        for column in [
            "timeline_id",
            "scope",
            "binding_hash",
            "binding_cbor",
            "receipt_cbor",
            "expected_head_cbor",
            "result_head_cbor",
        ] {
            // Same-length TEXT keeps every CHECK satisfied while breaking the BLOB type.
            let text = format!("{column} = substr(hex({column}), 1, length({column}))");
            let setup = first_recording_update(&text);
            let outcome = with_rollback(connection, &setup, by_id)?;
            assert_eq!(outcome, Some(LocalError::StorageFailure), "{column}");
        }
        Ok(())
    }

    #[test]
    fn stored_world_recordings_reject_each_unlinked_column() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        let cut = FIRST_CUT.cut_id;
        let by_id = |conn: &Connection| sqlite_local_cut_owner_cut_by_id(conn, OWNER, cut).err();
        assert_eq!(by_id(connection), None);
        for setup in [
            first_recording_update("binding_cbor = X'01'"),
            first_recording_update("receipt_cbor = X'01'"),
            first_recording_update("timeline_id = X'09090909090909090909090909090909'"),
            first_recording_update("binding_hash = zeroblob(32)"),
            first_recording_update("expected_head_cbor = X'01'"),
            first_recording_update("result_head_cbor = X'01'"),
            first_recording_update(
                "expected_head_cbor = CAST(expected_head_cbor || X'00' AS BLOB)",
            ),
            first_recording_update(&format!("result_head_cbor = {SECOND_TIMELINE_RESULT_ROW}")),
            format!("DELETE FROM local_cut_world_recordings {FIRST_TIMELINE_ROW}"),
            "DELETE FROM world_dependency_branches".to_owned(),
        ] {
            let outcome = with_rollback(connection, &setup, by_id)?;
            assert_eq!(outcome, Some(LocalError::CorruptState), "{setup}");
        }
        Ok(())
    }

    #[test]
    fn world_recording_reads_report_unreadable_rows() -> TestResult {
        let fixture = committed()?;
        let connection = &fixture.store.conn;
        deny_read(connection, "local_cut_world_recordings", "receipt_cbor", 0)?;
        let recordings = sqlite_local_cut_world_recordings(connection, OWNER, FIRST_CUT.cut_id);
        assert_eq!(recordings.err(), Some(LocalError::StorageFailure));
        clear_authorizer(connection)?;
        deny_read(connection, "local_cut_world_recordings", "binding_hash", 0)?;
        let latest = sqlite_latest_local_cut_world_binding(connection, OWNER, timeline(1));
        assert_eq!(latest, Err(LocalError::StorageFailure));
        clear_authorizer(connection)?;
        deny_read(connection, "world_dependency_branches", "node_hash", 0)?;
        let exists = sqlite_world_dependency_branch_exists(connection, hash(1), hash(2));
        assert_eq!(exists, Err(LocalError::StorageFailure));
        clear_authorizer(connection)?;
        Ok(())
    }

    #[test]
    fn hot_paths_decode_only_the_current_and_returned_cuts() -> TestResult {
        let (mut fixture, second) = with_history()?;
        let current = fixture.store.read_local_cut_owner_state_v1(OWNER)?;
        assert_eq!(
            fixture.store.verify_local_cut_owner_history_v1(OWNER)?,
            current
        );
        fixture.store.verify_local_cut_owner_histories()?;
        fixture.store.conn.execute(
            &format!("UPDATE local_cut_owner_cuts SET request_bytes = X'01' {OLD_CUT}"),
            [],
        )?;
        // Current-state reads, retries, commits, and current-cut reads never
        // decode the damaged older cut.
        assert_eq!(fixture.store.read_local_cut_owner_state_v1(OWNER)?, current);
        let retry = fixture
            .store
            .resolve_local_cut_owner_retry_v1(
                OWNER,
                SECOND_CUT.operation_id,
                second.intent_digest(),
            )?
            .ok_or("missing current-cut retry")?;
        assert_eq!(retry.kind, LocalCutOwnerCommitKindV1::ExactRetry);
        let third = commit_next(&mut fixture.store, &fixture.snapshots, THIRD_CUT)?;
        assert_eq!(
            fixture
                .store
                .read_local_cut_owner_commit_v1(OWNER, THIRD_CUT.cut_id)?,
            Some(third.applied_result())
        );
        // Every path that returns the damaged cut, and the integrity pass, fail closed.
        let corrupt = Err(LocalError::CorruptState);
        assert_eq!(
            fixture
                .store
                .read_local_cut_owner_commit_v1(OWNER, FIRST_CUT.cut_id),
            corrupt
        );
        assert_eq!(
            fixture.store.resolve_local_cut_owner_retry_v1(
                OWNER,
                FIRST_CUT.operation_id,
                fixture.batch.intent_digest(),
            ),
            corrupt
        );
        assert_eq!(
            fixture.store.verify_local_cut_owner_history_v1(OWNER),
            Err(LocalError::CorruptState)
        );
        let opened = fixture.store.verify_local_cut_owner_histories();
        assert!(matches!(
            opened,
            Err(CoreError::Storage(message)) if message.starts_with("local-cut owner history")
        ));
        Ok(())
    }

    #[test]
    fn history_verification_rejects_unreadable_older_cut_identities() -> TestResult {
        let (fixture, _) = with_history()?;
        let connection = &fixture.store.conn;
        let probe = |conn: &Connection| {
            (
                sqlite_read_local_cut_owner_state(conn, OWNER).err(),
                sqlite_verify_local_cut_owner_history(conn, OWNER).err(),
            )
        };
        for (assignment, expected) in [
            ("cut_id = 4", LocalError::CorruptState),
            ("cut_id = X'00'", LocalError::CorruptState),
            ("receipt_cbor = X'01'", LocalError::CorruptState),
        ] {
            let setup = format!("UPDATE local_cut_owner_cuts SET {assignment} {OLD_CUT}");
            let outcome = with_rollback(connection, &setup, probe)?;
            assert_eq!(outcome, (None, Some(expected)), "{assignment}");
        }
        Ok(())
    }

    #[test]
    fn open_history_pass_reports_unreadable_owner_rows() -> TestResult {
        let (fixture, _) = with_history()?;
        let store = &fixture.store;
        let rejected = |_: &Connection| store.verify_local_cut_owner_histories().is_err();
        for setup in [
            "DROP TABLE local_cut_owner_state_timelines",
            "INSERT INTO local_cut_owner_state_timelines VALUES (X'01', zeroblob(16))",
        ] {
            assert!(with_rollback(&store.conn, setup, rejected)?, "{setup}");
        }
        Ok(())
    }

    #[test]
    fn later_cut_check_orders_cut_ids_numerically() -> TestResult {
        // Cut 255 precedes cut 256 only under the big-endian blob encoding that
        // the `cut_id > ?2` later-cut check relies on.
        let mut fixture = admitted()?;
        let request = cut_request(
            &fixture.store,
            &fixture.state,
            &fixture.snapshots,
            BYTE_EDGE_CUT,
        )?;
        let batch = prepare_cut(request, None, &fixture.state, &fixture.snapshots)?;
        let applied = fixture.store.commit_local_cut_owner_v1(batch)?;
        assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
        commit_next(&mut fixture.store, &fixture.snapshots, BYTE_CARRY_CUT)?;
        let current = fixture.store.read_local_cut_owner_state_v1(OWNER)?;
        assert_eq!(
            current.as_ref().map(|state| state.last_visible_cut_id),
            Some(BYTE_CARRY_CUT.cut_id)
        );
        assert_eq!(
            fixture.store.verify_local_cut_owner_history_v1(OWNER)?,
            current
        );
        Ok(())
    }

    #[test]
    fn reopening_a_store_verifies_every_retained_cut() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("local-cut-owner.sqlite");
        let path = path.to_str().ok_or("non-UTF-8 test path")?;
        let fixture = committed_in(admitted_in(SqliteStore::open(path)?)?)?;
        let mut store = fixture.store;
        commit_next(&mut store, &fixture.snapshots, SECOND_CUT)?;
        drop(store);
        let reopened = SqliteStore::open(path)?;
        let verified = reopened.verify_local_cut_owner_history_v1(OWNER)?;
        assert_eq!(
            verified.map(|state| state.last_visible_cut_id),
            Some(SECOND_CUT.cut_id)
        );
        reopened.conn.execute(
            &format!("UPDATE local_cut_owner_cuts SET request_bytes = X'01' {OLD_CUT}"),
            [],
        )?;
        drop(reopened);
        let rejected = SqliteStore::open(path)
            .err()
            .ok_or("reopened a store with a damaged older cut")?;
        assert!(matches!(
            rejected,
            CoreError::Storage(message) if message.starts_with("local-cut owner history")
        ));
        Ok(())
    }

    fn link_identity(
        batch: &PreparedLocalCutOwnerCommitV1,
    ) -> Fallible<ManifestOwnerLinkCutIdentityV1> {
        let recording = batch.recordings().first().ok_or("missing recording")?;
        let digest = recording.receipt.digest();
        Ok(ManifestOwnerLinkCutIdentityV1::WorldRecordingReceipt(
            digest,
        ))
    }

    fn link_snapshot(
        store: &SqliteStore,
        connection: &Connection,
        identity: ManifestOwnerLinkCutIdentityV1,
    ) -> Result<Option<ManifestOwnerLinkSnapshotV1>, LocalError> {
        sqlite_owner_link_snapshot(store, connection, OWNER, identity, timeline(1))
    }

    #[test]
    fn owner_link_snapshot_reads_one_cut_with_its_ancestors_and_nodes() -> TestResult {
        let (fixture, second) = with_history()?;
        let store = &fixture.store;
        let identity = link_identity(&second)?;
        let newest = store.read_manifest_owner_link_snapshot_v1(OWNER, identity, timeline(1))?;
        let newest = newest.ok_or("missing newest snapshot")?;
        assert_eq!(&newest.request, second.request());
        assert_eq!(newest.ancestors.len(), 1);
        assert_eq!(newest.admissions, fixture.snapshots);
        assert!(!newest.dependency_branches.is_empty());
        let receipt = fixture.batch.receipt().digest();
        let by_receipt = ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(receipt);
        let oldest = link_snapshot(store, &store.conn, by_receipt)?;
        let oldest = oldest.ok_or("missing oldest snapshot")?;
        assert!(oldest.ancestors.is_empty());
        let unknown = ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(hash(0x77));
        assert_eq!(link_snapshot(store, &store.conn, unknown)?, None);
        let owner = [0x42; 32];
        let other = sqlite_owner_link_snapshot(store, &store.conn, owner, by_receipt, timeline(1))?;
        assert_eq!(other, None);
        Ok(())
    }

    #[test]
    fn owner_link_snapshot_rejects_mistyped_or_undecodable_rows() -> TestResult {
        let (fixture, second) = with_history()?;
        let store = &fixture.store;
        let newest = link_identity(&second)?;
        let oldest = link_identity(&fixture.batch)?;
        let old_row = format!("{OLD_CUT} AND timeline_id = X'01010101010101010101010101010101'");
        let row = |set: &str| format!("UPDATE local_cut_world_recordings SET {set} {old_row}");
        let cut = |set: &str| format!("UPDATE local_cut_owner_cuts SET {set} {OLD_CUT}");
        let nodes = |set: &str| format!("UPDATE world_dependency_branches SET {set}");
        let corruptions = [
            (row("cut_id = 'abcdefgh'"), newest),
            (row("receipt_cbor = 'r'"), newest),
            (row("receipt_cbor = X'00'"), newest),
            (cut("commit_cbor = X'00'"), oldest),
            (cut("commit_cbor = X'00'"), newest),
            (cut("cut_id = 'abcdefgh'"), newest),
            (cut("cut_id = X'00'"), newest),
            (nodes("node_cbor = 'node'"), newest),
            (nodes("node_cbor = X'00'"), newest),
        ];
        for (setup, identity) in corruptions {
            let read = with_rollback(&store.conn, &setup, |connection| {
                link_snapshot(store, connection, identity)
            })?;
            assert_eq!(read, Err(LocalError::CorruptState));
        }
        deny_read(&store.conn, "world_dependency_branches", "node_cbor", 0)?;
        let denied = link_snapshot(store, &store.conn, newest);
        clear_authorizer(&store.conn)?;
        assert_eq!(denied, Err(LocalError::StorageFailure));
        Ok(())
    }

    #[test]
    fn owner_link_snapshot_rejects_a_corrupt_historical_admission() -> TestResult {
        let mut fixture = committed()?;
        let oldest = link_identity(&fixture.batch)?;
        let current = current_admission(&fixture.store)?;
        fixture
            .store
            .commit_manifest_owner_admission_v1(successor_admission(&current)?)?;
        let store = &fixture.store;
        let setup = "UPDATE manifest_owner_admissions SET receipt_cbor = X'00'
                     WHERE configuration_generation = X'0000000000000001'";
        let read = with_rollback(&store.conn, setup, |connection| {
            link_snapshot(store, connection, oldest)
        })?;
        assert_eq!(read, Err(LocalError::CorruptState));
        let intact = link_snapshot(store, &store.conn, oldest)?;
        let intact = intact.ok_or("missing historical snapshot")?;
        assert_eq!(intact.admissions, fixture.snapshots);
        Ok(())
    }
}
