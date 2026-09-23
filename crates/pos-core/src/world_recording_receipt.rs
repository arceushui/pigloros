//! Immutable ADR-081 WCR1 structural recording receipts.
//!
//! A content address here does not authenticate the actual commit receipt,
//! installed inventory generation, or any Exact Replay claim.

use crate::Hash;

/// Maximum accepted size of one canonical WCR1 record.
pub const MAX_WORLD_RECORDING_RECEIPT_BYTES_V1: usize = 1024;

const DOMAIN: &[u8] = b"pigloros.world-evidence.recording-receipt.v1\0";
const ENCODED_LEN: usize = 143;
const HASH_HEAD_OFFSETS: [usize; 4] = [7, 41, 75, 109];

/// Closed structural WCR1 errors; none report native owner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldRecordingReceiptErrorV1 {
    /// Malformed or nonpreferred CBOR, a wrong field type/width, or trailing data.
    #[error("invalid WCR1 encoding")]
    InvalidEncoding,
    /// The record version is unsupported.
    #[error("unsupported WCR1 version")]
    UnsupportedVersion,
    /// The encoded input exceeds the accepted bound.
    #[error("WCR1 record is too large")]
    FieldOutOfBounds,
    /// A referenced WCB1 binding or actual commit receipt address is zero.
    #[error("WCR1 content address is zero")]
    ZeroContentAddress,
}

/// Untrusted values recorded in one WCR1; owners verify their meaning later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldRecordingReceiptInputV1 {
    pub binding_hash: Hash,
    pub operation_id: Hash,
    pub actual_commit_receipt_digest: Hash,
    pub installed_inventory_generation: Hash,
}

/// Validated immutable structural WCR1, without commit or Replay authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldRecordingReceiptV1(WorldRecordingReceiptInputV1);

impl WorldRecordingReceiptV1 {
    /// Validate the two content addresses while preserving opaque owner values.
    ///
    /// # Errors
    /// Rejects a zero WCB1 binding or actual commit receipt address.
    pub fn new(input: WorldRecordingReceiptInputV1) -> Result<Self, WorldRecordingReceiptErrorV1> {
        if input.binding_hash == Hash::zero() || input.actual_commit_receipt_digest == Hash::zero()
        {
            return Err(WorldRecordingReceiptErrorV1::ZeroContentAddress);
        }
        Ok(Self(input))
    }

    /// Borrow the exact untrusted values retained by this structural record.
    #[must_use]
    pub const fn as_input(&self) -> &WorldRecordingReceiptInputV1 {
        &self.0
    }

    /// Encode the unique preferred definite six-field WCR1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCODED_LEN);
        bytes.extend_from_slice(&[0x86, 0x44]);
        bytes.extend_from_slice(b"WCR1");
        bytes.push(1);
        for hash in [
            self.0.binding_hash,
            self.0.operation_id,
            self.0.actual_commit_receipt_digest,
            self.0.installed_inventory_generation,
        ] {
            bytes.extend_from_slice(&[0x58, 0x20]);
            bytes.extend_from_slice(hash.as_bytes());
        }
        bytes
    }

    /// Ordinary BLAKE3 of the accepted domain, NUL and canonical WCR1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode exactly one bounded preferred definite WCR1 record.
    ///
    /// # Errors
    /// Rejects oversized, malformed, nonpreferred, trailing or invalid input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WorldRecordingReceiptErrorV1> {
        if bytes.len() > MAX_WORLD_RECORDING_RECEIPT_BYTES_V1 {
            return Err(WorldRecordingReceiptErrorV1::FieldOutOfBounds);
        }
        if bytes.len() != ENCODED_LEN
            || bytes[0..2] != [0x86, 0x44]
            || bytes[2..6] != *b"WCR1"
            || HASH_HEAD_OFFSETS
                .iter()
                .any(|&offset| bytes[offset..offset + 2] != [0x58, 0x20])
        {
            return Err(WorldRecordingReceiptErrorV1::InvalidEncoding);
        }
        if bytes[6] != 1 {
            return Err(WorldRecordingReceiptErrorV1::UnsupportedVersion);
        }
        Self::new(WorldRecordingReceiptInputV1 {
            binding_hash: read_hash(bytes, HASH_HEAD_OFFSETS[0]),
            operation_id: read_hash(bytes, HASH_HEAD_OFFSETS[1]),
            actual_commit_receipt_digest: read_hash(bytes, HASH_HEAD_OFFSETS[2]),
            installed_inventory_generation: read_hash(bytes, HASH_HEAD_OFFSETS[3]),
        })
    }
}

fn read_hash(bytes: &[u8], header_offset: usize) -> Hash {
    let mut hash = [0; 32];
    hash.copy_from_slice(&bytes[header_offset + 2..header_offset + 34]);
    Hash::from_bytes(hash)
}
