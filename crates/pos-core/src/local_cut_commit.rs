//! Canonical LCC1 and LCQ1 records for a locally owned cut.
//!
//! These records bind a completed local cut structurally. An installed owner
//! still has to authenticate the selected admission, fresh authority fence,
//! and coordinator signing role before treating either record as a visible cut.

use crate::local_cut_seal::{LocalCutSealErrorV2, LocalCutTableRefV1};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};

/// Largest accepted canonical LCC1 record.
pub const MAX_LOCAL_CUT_COMMIT_BYTES_V1: usize = 2_048;
/// Largest accepted canonical LCQ1 record.
pub const MAX_LOCAL_CUT_RECEIPT_BYTES_V1: usize = 256;

const COMMIT_DOMAIN: &[u8] = b"pigloros.local-cut.commit.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"pigloros.local-cut.receipt.v1\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"pigloros.local-cut.receipt-signature.v1\0";

/// Closed structural errors for LCC1 and LCQ1 records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalCutCommitErrorV1 {
    /// The CBOR shape, fixed byte length, or trailing input is invalid.
    #[error("invalid local-cut commit encoding")]
    InvalidEncoding,
    /// The unique preferred CBOR representation was not used.
    #[error("noncanonical local-cut commit encoding")]
    NonCanonical,
    /// The record uses a wire version that this implementation does not support.
    #[error("unsupported local-cut commit version")]
    UnsupportedVersion,
    /// A record exceeds its accepted size or an encoded field is out of range.
    #[error("local-cut commit field is out of bounds")]
    FieldOutOfBounds,
    /// A required owner, coordinate, content address, or table reference is invalid.
    #[error("local-cut commit contains an invalid identity or content address")]
    InvalidIdentity,
    /// One embedded table reference is structurally invalid.
    #[error("local-cut commit table reference is invalid")]
    InvalidTableReference,
}

/// Untrusted immutable LCC1 fields selected by the local owner transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutCommitInputV1 {
    /// The exclusive local owner identity.
    pub owner_id: [u8; 32],
    /// Globally allocated local cut identity.
    pub cut_id: u64,
    /// Positive partition commit-ledger coordinate.
    pub partition_ledger_seq: u64,
    /// Exact selected LCS2 digest.
    pub seal_hash: Hash,
    /// Exact selected LCM1 digest.
    pub manifest_hash: Hash,
    /// Complete result-head table reference.
    pub result_heads_table: LocalCutTableRefV1,
    /// Complete participant-successor table reference.
    pub participant_successor_table: LocalCutTableRefV1,
    /// Complete CPU-completion table reference.
    pub cpu_completion_table: LocalCutTableRefV1,
    /// Complete action-disposition table reference.
    pub action_disposition_table: LocalCutTableRefV1,
    /// Complete private candidate-base table reference.
    pub candidate_bases_table: LocalCutTableRefV1,
    /// Complete private invocation-bridge table reference.
    pub invocation_bridges_table: LocalCutTableRefV1,
    /// Resulting opaque owner inventory generation.
    pub result_inventory_generation: Hash,
    /// Fresh serialized release-fence proof digest.
    pub release_fence_proof_digest: Hash,
}

/// Canonical immutable LCC1 commit record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutCommitV1(LocalCutCommitInputV1);

impl LocalCutCommitV1 {
    /// Validate the LCC1 structural fields without authenticating an owner.
    ///
    /// # Errors
    /// Returns an error for zero identities or addresses, invalid table
    /// references, and absent positive cut or ledger coordinates.
    pub fn new(input: LocalCutCommitInputV1) -> Result<Self, LocalCutCommitErrorV1> {
        if input.owner_id == [0; 32]
            || input.cut_id == 0
            || input.partition_ledger_seq == 0
            || [
                input.seal_hash,
                input.manifest_hash,
                input.result_inventory_generation,
                input.release_fence_proof_digest,
            ]
            .contains(&Hash::zero())
        {
            return Err(LocalCutCommitErrorV1::InvalidIdentity);
        }
        for table in [
            input.result_heads_table,
            input.participant_successor_table,
            input.cpu_completion_table,
            input.action_disposition_table,
            input.candidate_bases_table,
            input.invocation_bridges_table,
        ] {
            LocalCutTableRefV1::new(table.row_count(), table.root_hash())
                .map_err(map_table_error)?;
        }
        Ok(Self(input))
    }

    /// Borrow the exact validated LCC1 fields.
    #[must_use]
    pub const fn as_input(&self) -> &LocalCutCommitInputV1 {
        &self.0
    }

    /// Encode the unique preferred fifteen-field LCC1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = self.as_input();
        let mut out = Vec::with_capacity(512);
        encode_head(&mut out, 4, 15);
        encode_bytes(&mut out, b"LCC1", 2);
        encode_head(&mut out, 0, 1);
        encode_bytes(&mut out, &input.owner_id, 2);
        encode_head(&mut out, 0, input.cut_id);
        encode_head(&mut out, 0, input.partition_ledger_seq);
        encode_hash(&mut out, input.seal_hash);
        encode_hash(&mut out, input.manifest_hash);
        for table in [
            input.result_heads_table,
            input.participant_successor_table,
            input.cpu_completion_table,
            input.action_disposition_table,
            input.candidate_bases_table,
            input.invocation_bridges_table,
        ] {
            encode_table_ref(&mut out, table);
        }
        encode_hash(&mut out, input.result_inventory_generation);
        encode_hash(&mut out, input.release_fence_proof_digest);
        out
    }

    /// Derive the approved LCC1 content address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(COMMIT_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode one complete, bounded, preferred LCC1 record.
    ///
    /// # Errors
    /// Returns an error for malformed, nonpreferred, unsupported, or invalid
    /// structural LCC1 input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, LocalCutCommitErrorV1> {
        if bytes.len() > MAX_LOCAL_CUT_COMMIT_BYTES_V1 {
            return Err(LocalCutCommitErrorV1::FieldOutOfBounds);
        }
        let mut cursor = CborCursor::new(bytes);
        read_commit(&mut cursor).and_then(|input| {
            if !cursor.is_finished() {
                return Err(LocalCutCommitErrorV1::InvalidEncoding);
            }
            Self::new(input).and_then(|record| {
                if record.to_canonical_cbor().as_slice() == bytes {
                    Ok(record)
                } else {
                    Err(LocalCutCommitErrorV1::NonCanonical)
                }
            })
        })
    }
}

/// Untrusted LCQ1 fields signed by the installed coordinator role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutReceiptInputV1 {
    /// Exact LCC1 content address.
    pub commit_record_hash: Hash,
    /// Retained coordinator-key evidence address.
    pub coordinator_key_evidence_hash: Hash,
    /// Exact installed-role signature over the LCQ1 preimage.
    pub signature: [u8; 64],
}

/// Canonical immutable LCQ1 local-cut receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutReceiptV1(LocalCutReceiptInputV1);

impl LocalCutReceiptV1 {
    /// Validate the LCQ1 structural fields without authenticating its signer.
    ///
    /// # Errors
    /// Returns an error when either required content address is zero.
    pub fn new(input: LocalCutReceiptInputV1) -> Result<Self, LocalCutCommitErrorV1> {
        if [
            input.commit_record_hash,
            input.coordinator_key_evidence_hash,
        ]
        .contains(&Hash::zero())
        {
            return Err(LocalCutCommitErrorV1::InvalidIdentity);
        }
        Ok(Self(input))
    }

    /// Borrow the exact validated LCQ1 fields.
    #[must_use]
    pub const fn as_input(&self) -> &LocalCutReceiptInputV1 {
        &self.0
    }

    /// Return the exact installed-coordinator LCQ1 signing preimage.
    ///
    /// This binds the LCC1 content address and retained coordinator-key
    /// evidence before the signature bytes become part of the receipt.
    #[must_use]
    pub fn signature_preimage(&self) -> Vec<u8> {
        receipt_signature_preimage(
            self.0.commit_record_hash,
            self.0.coordinator_key_evidence_hash,
        )
    }

    /// Encode the unique preferred five-field LCQ1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = self.as_input();
        let mut out = Vec::with_capacity(160);
        encode_head(&mut out, 4, 5);
        encode_bytes(&mut out, b"LCQ1", 2);
        encode_head(&mut out, 0, 1);
        encode_hash(&mut out, input.commit_record_hash);
        encode_hash(&mut out, input.coordinator_key_evidence_hash);
        encode_bytes(&mut out, &input.signature, 2);
        out
    }

    /// Derive the approved LCQ1 content address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(RECEIPT_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode one complete, bounded, preferred LCQ1 record.
    ///
    /// # Errors
    /// Returns an error for malformed, nonpreferred, unsupported, or invalid
    /// structural LCQ1 input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, LocalCutCommitErrorV1> {
        if bytes.len() > MAX_LOCAL_CUT_RECEIPT_BYTES_V1 {
            return Err(LocalCutCommitErrorV1::FieldOutOfBounds);
        }
        let mut cursor = CborCursor::new(bytes);
        read_receipt(&mut cursor).and_then(|input| {
            if !cursor.is_finished() {
                return Err(LocalCutCommitErrorV1::InvalidEncoding);
            }
            Self::new(input).and_then(|record| {
                if record.to_canonical_cbor().as_slice() == bytes {
                    Ok(record)
                } else {
                    Err(LocalCutCommitErrorV1::NonCanonical)
                }
            })
        })
    }
}

fn read_commit(
    cursor: &mut CborCursor<'_>,
) -> Result<LocalCutCommitInputV1, LocalCutCommitErrorV1> {
    expect_array(cursor, 15)?;
    expect_bytes(cursor, b"LCC1")?;
    expect_version(cursor)?;
    let owner_id = read_fixed(cursor)?;
    let cut_id = read_positive(cursor)?;
    let partition_ledger_seq = read_positive(cursor)?;
    let seal_hash = read_hash(cursor)?;
    let manifest_hash = read_hash(cursor)?;
    let result_heads_table = read_table_ref(cursor)?;
    let participant_successor_table = read_table_ref(cursor)?;
    let cpu_completion_table = read_table_ref(cursor)?;
    let action_disposition_table = read_table_ref(cursor)?;
    let candidate_bases_table = read_table_ref(cursor)?;
    let invocation_bridges_table = read_table_ref(cursor)?;
    let result_inventory_generation = read_hash(cursor)?;
    let release_fence_proof_digest = read_hash(cursor)?;
    Ok(LocalCutCommitInputV1 {
        owner_id,
        cut_id,
        partition_ledger_seq,
        seal_hash,
        manifest_hash,
        result_heads_table,
        participant_successor_table,
        cpu_completion_table,
        action_disposition_table,
        candidate_bases_table,
        invocation_bridges_table,
        result_inventory_generation,
        release_fence_proof_digest,
    })
}

fn read_receipt(
    cursor: &mut CborCursor<'_>,
) -> Result<LocalCutReceiptInputV1, LocalCutCommitErrorV1> {
    expect_array(cursor, 5)?;
    expect_bytes(cursor, b"LCQ1")?;
    expect_version(cursor)?;
    let commit_record_hash = read_hash(cursor)?;
    let coordinator_key_evidence_hash = read_hash(cursor)?;
    let signature = read_fixed(cursor)?;
    Ok(LocalCutReceiptInputV1 {
        commit_record_hash,
        coordinator_key_evidence_hash,
        signature,
    })
}

fn expect_array(cursor: &mut CborCursor<'_>, expected: u64) -> Result<(), LocalCutCommitErrorV1> {
    match cursor.head(4) {
        Ok(actual) if actual == expected => Ok(()),
        _ => Err(LocalCutCommitErrorV1::InvalidEncoding),
    }
}

fn expect_bytes(cursor: &mut CborCursor<'_>, expected: &[u8]) -> Result<(), LocalCutCommitErrorV1> {
    let length = cursor
        .head(2)
        .map_err(|_| LocalCutCommitErrorV1::InvalidEncoding)?;
    if length != expected.len() as u64 {
        return Err(LocalCutCommitErrorV1::InvalidEncoding);
    }
    cursor
        .fixed(expected)
        .map_err(|_| LocalCutCommitErrorV1::InvalidEncoding)
}

fn expect_version(cursor: &mut CborCursor<'_>) -> Result<(), LocalCutCommitErrorV1> {
    match cursor.head(0) {
        Ok(1) => Ok(()),
        Ok(_) => Err(LocalCutCommitErrorV1::UnsupportedVersion),
        Err(_) => Err(LocalCutCommitErrorV1::InvalidEncoding),
    }
}

fn read_positive(cursor: &mut CborCursor<'_>) -> Result<u64, LocalCutCommitErrorV1> {
    match cursor.head(0) {
        Ok(value) if value > 0 => Ok(value),
        Ok(_) => Err(LocalCutCommitErrorV1::FieldOutOfBounds),
        Err(_) => Err(LocalCutCommitErrorV1::InvalidEncoding),
    }
}

fn read_fixed<const N: usize>(
    cursor: &mut CborCursor<'_>,
) -> Result<[u8; N], LocalCutCommitErrorV1> {
    let length = cursor
        .head(2)
        .map_err(|_| LocalCutCommitErrorV1::InvalidEncoding)?;
    if length != N as u64 {
        return Err(LocalCutCommitErrorV1::InvalidEncoding);
    }
    let bytes = cursor
        .take(N)
        .map_err(|_| LocalCutCommitErrorV1::InvalidEncoding)?;
    let mut value = [0; N];
    value.copy_from_slice(bytes);
    Ok(value)
}

fn read_hash(cursor: &mut CborCursor<'_>) -> Result<Hash, LocalCutCommitErrorV1> {
    read_fixed(cursor).map(Hash::from_bytes)
}

fn encode_table_ref(out: &mut Vec<u8>, table: LocalCutTableRefV1) {
    encode_head(out, 4, 2);
    encode_head(out, 0, table.row_count());
    if let Some(root_hash) = table.root_hash() {
        encode_hash(out, root_hash);
    } else {
        out.push(0xf6);
    }
}

fn read_table_ref(
    cursor: &mut CborCursor<'_>,
) -> Result<LocalCutTableRefV1, LocalCutCommitErrorV1> {
    expect_array(cursor, 2)?;
    let row_count = cursor
        .head(0)
        .map_err(|_| LocalCutCommitErrorV1::InvalidEncoding)?;
    let root_hash = if cursor.consume_if(0xf6) {
        None
    } else {
        Some(read_hash(cursor)?)
    };
    LocalCutTableRefV1::new(row_count, root_hash).map_err(map_table_error)
}

const fn map_table_error(error: LocalCutSealErrorV2) -> LocalCutCommitErrorV1 {
    match error {
        LocalCutSealErrorV2::FieldOutOfBounds => LocalCutCommitErrorV1::FieldOutOfBounds,
        LocalCutSealErrorV2::InvalidTableReference | LocalCutSealErrorV2::ZeroContentAddress => {
            LocalCutCommitErrorV1::InvalidTableReference
        }
        LocalCutSealErrorV2::InvalidEncoding
        | LocalCutSealErrorV2::NonCanonical
        | LocalCutSealErrorV2::UnsupportedVersion
        | LocalCutSealErrorV2::RowsNotSorted
        | LocalCutSealErrorV2::InvalidTableNode
        | LocalCutSealErrorV2::TableMismatch => LocalCutCommitErrorV1::InvalidTableReference,
    }
}

/// Build the exact LCQ1 coordinator-signature preimage from validated addresses.
///
/// # Errors
/// Returns an error when either content address is absent.
pub fn local_cut_receipt_signature_preimage_v1(
    commit_record_hash: Hash,
    coordinator_key_evidence_hash: Hash,
) -> Result<Vec<u8>, LocalCutCommitErrorV1> {
    if [commit_record_hash, coordinator_key_evidence_hash].contains(&Hash::zero()) {
        return Err(LocalCutCommitErrorV1::InvalidIdentity);
    }
    Ok(receipt_signature_preimage(
        commit_record_hash,
        coordinator_key_evidence_hash,
    ))
}

fn receipt_signature_preimage(
    commit_record_hash: Hash,
    coordinator_key_evidence_hash: Hash,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + 72);
    out.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
    encode_head(&mut out, 4, 2);
    encode_hash(&mut out, commit_record_hash);
    encode_hash(&mut out, coordinator_key_evidence_hash);
    out
}

fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
