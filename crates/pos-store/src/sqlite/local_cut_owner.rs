//! `SQLite` persistence for the installed local-cut owner (LCS2 seals, LCC1
//! commits, and LCQ1 receipts).
//!
//! The owner state, its Timeline roster, and every immutable visible cut live
//! beside the manifest-owner admission tables so one transaction can publish a
//! cut together with the admitted owner's receipt and inventory generation.

use pos_core::{
    local_cut_owner_intent_digest_v1, validate_local_cut_owner_result_v1,
    validate_local_cut_owner_successor_v1, CoreError, Hash, LocalCutCommitV1,
    LocalCutCompositionBindingRowV1, LocalCutManifestBindingTableV1, LocalCutOwnerCommitKindV1,
    LocalCutOwnerCommitV1, LocalCutOwnerErrorV1, LocalCutOwnerPersistencePortV1,
    LocalCutOwnerRequestV1, LocalCutOwnerStateV1, LocalCutReceiptV1, LocalCutRecordingContextRowV1,
    LocalCutSealV2, LocalCutTableRefV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionInputV1, ManifestOwnerAdmissionOwnerStateV1, PluginId,
    PreparedLocalCutOwnerCommitV1, TimelineId, MAX_LOCAL_CUT_OWNER_ROWS_V1,
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
/// Those request bounds cap the encoding near 520 MB, below
/// `SQLITE_MAX_LOCAL_CUT_OWNER_REQUEST_BYTES_V1`, so no accepted request can
/// exceed the stored column limit.
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

fn sqlite_decode_local_cut_owner_request(
    bytes: &[u8],
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
    if commit.partition_ledger_seq != cut.request.partition_ledger_seq
        || commit.manifest_hash != cut.request.manifest_hash
        || commit.result_heads_table != cut.request.result_heads_table
        || commit.participant_successor_table != cut.request.participant_successor_table
        || commit.cpu_completion_table != cut.request.cpu_completion_table
        || commit.action_disposition_table != cut.request.action_disposition_table
        || commit.candidate_bases_table != cut.request.candidate_bases_table
        || commit.invocation_bridges_table != cut.request.invocation_bridges_table
        || commit.result_inventory_generation != cut.request.result_inventory_generation
        || commit.release_fence_proof_digest != cut.request.release_fence_proof_digest
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(())
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
    let (request, decoded_intent) = sqlite_decode_local_cut_owner_request(&request_bytes)?;
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
        },
    };
    sqlite_validate_local_cut_owner_cut(owner_id, cut_id, &cut)?;
    Ok(Some(cut))
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
        .map_err(|error| match error {
            rusqlite::Error::InvalidColumnType(..) => LocalCutOwnerErrorV1::CorruptState,
            _ => LocalCutOwnerErrorV1::StorageFailure,
        })
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
    Ok(result)
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
            validate_local_cut_owner_successor_v1(&batch, &admission, current_state.as_ref())?;
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
    use crate::manifest_owner_fixtures::{catalog, member_classes, timeline_request, READ_LIMITS};
    use pos_core::{
        prepare_local_cut_owner_commit_v1, prepare_manifest_owner_admission_v1,
        LocalCutManifestBindingRowV1, LocalCutOwnerVerifierV1, LocalCutReceiptInputV1,
        LocalCutSealInputV2, ManifestAdmissionCatalogV1, ManifestOwnerAdmissionCommitKindV1,
        ManifestOwnerAdmissionPersistencePortV1, ManifestOwnerAdmissionRequestV1,
        ManifestOwnerAdmissionSnapshotV1, ManifestOwnerAdmissionVerifierV1,
        ManifestOwnerMemberLeafClassV1, ManifestOwnerPolicyCopiesV1, ManifestOwnerScopeMembersV1,
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
        ) -> Result<Vec<ManifestOwnerMemberLeafClassV1>, ManifestOwnerAdmissionErrorV1> {
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

    struct RequestParts {
        shape: CutShape,
        configuration_generation: u64,
        previous: Option<Hash>,
        expected_inventory: Hash,
        binding_rows: Vec<LocalCutManifestBindingRowV1>,
        composition_rows: Vec<LocalCutCompositionBindingRowV1>,
        recording_context_rows: Vec<LocalCutRecordingContextRowV1>,
    }

    fn table(row_count: u64, byte: u8) -> Fallible<LocalCutTableRefV1> {
        Ok(LocalCutTableRefV1::new(
            row_count,
            (row_count != 0).then(|| hash(byte)),
        )?)
    }

    fn request_from_parts(parts: RequestParts) -> Fallible<LocalCutOwnerRequestV1> {
        let manifest_binding_table =
            LocalCutManifestBindingTableV1::new(OWNER, parts.shape.cut_id, parts.binding_rows)?;
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
            expected_heads_table: table(1, 105)?,
            ebp_native_hash: hash(98),
            execution_profile_native_hash: hash(99),
            recording_context_table: table(recording_rows, 93)?,
            owner_operational_policy_hash: hash(100),
            explicit_attempt_hash: None,
            ingress_preallocation_native_hash: hash(101),
            manifest_binding_table: manifest_binding_table.table_ref(),
        })?;
        Ok(LocalCutOwnerRequestV1 {
            operation_id: parts.shape.operation_id,
            seal,
            manifest_hash: hash(103),
            manifest_binding_table,
            composition_rows: parts.composition_rows,
            recording_context_rows: parts.recording_context_rows,
            partition_ledger_seq: parts.shape.cut_id,
            result_heads_table: table(1, 105)?,
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
        })
    }

    fn cut_request(
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
        let recording_context_rows = snapshots
            .iter()
            .map(|snapshot| LocalCutRecordingContextRowV1 {
                timeline_id: snapshot.timeline.timeline_id,
                wcs_hash: snapshot.timeline.wcs1.digest(),
                retention_lease_hash: hash(104),
                predecessor_wcb_hash: None,
            })
            .collect();
        request_from_parts(RequestParts {
            shape,
            configuration_generation: state.configuration_generation,
            previous: state.previous_visible_lcq1_hash,
            expected_inventory: state.inventory_generation,
            binding_rows,
            composition_rows,
            recording_context_rows,
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
        let request = cut_request(&fixture.state, &fixture.snapshots, FIRST_CUT)?;
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
        let request = cut_request(&current, snapshots, shape)?;
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
        let (decoded, intent_digest) = sqlite_decode_local_cut_owner_request(&bytes)?;
        assert_eq!(decoded, request);
        assert_eq!(intent_digest, local_cut_owner_intent_digest_v1(&request)?);
        for length in 0..bytes.len() {
            assert_eq!(
                sqlite_decode_local_cut_owner_request(&bytes[..length]).err(),
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
                sqlite_decode_local_cut_owner_request(&candidate).err(),
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
            sqlite_decode_local_cut_owner_request(&reordered).err(),
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
        let request = cut_request(&fixture.state, &fixture.snapshots, FIRST_CUT)?;
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
        let stale_request = cut_request(&fixture.genesis, &fixture.snapshots, stale_shape)?;
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
        let reused_request = cut_request(&fixture.genesis, &fixture.snapshots, reused_shape)?;
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
        let second_request = cut_request(&current, &fixture.snapshots, second_shape)?;
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
        let request = cut_request(&fixture.state, &fixture.snapshots, BYTE_EDGE_CUT)?;
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
}
