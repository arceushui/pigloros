//! The SNL1 nonce-ledger artifact selected by Accepted ADR-110 E16.
//!
//! This codec validates bytes and row ordering only. A decoded device/inode
//! pair is untrusted metadata, not a canonical store binding or an encryption
//! permit. The owner adapter must establish the registry/root/store identity,
//! hold the lifetime lock, and durably commit each reservation before use.
//! Missing or suspect ledger state must never be recreated for a registered
//! identity. None of those operations or production activation occur here.
//!
//! The pure format is available on every target; store-file tag 1 describes
//! Linux. Decoding it does not enable owner operations on another platform.

use thiserror::Error;

use crate::strict_cbor::{Reader, StrictCborError};
use crate::subject_cbor::{self, ROLE, VERSION};
use crate::subject_ciphertext::MAX_SUBJECT_NONCE_COUNTER;
use crate::subject_key::{parse_subject_owner_id, SUBJECT_OWNER_BYTES};

/// Maximum complete SNL1 file size: 1 MiB, including every CBOR header.
pub const MAX_SUBJECT_NONCE_LEDGER_BYTES: usize = 1_048_576;
/// A next-counter value that records exhaustion and cannot be used as an IV.
pub const EXHAUSTED_SUBJECT_NONCE_COUNTER: u64 = MAX_SUBJECT_NONCE_COUNTER + 1;

const MAGIC: [u8; 4] = *b"SNL1";
const LINUX_STORE_FILE_TAG: u64 = 1;

/// A closed, payload-free SNL1 structural failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SubjectNonceLedgerErrorV1 {
    /// Wrong magic, type, cardinality, noncanonical CBOR, truncation or suffix.
    #[error("invalid SNL1 encoding")]
    InvalidEncoding,
    /// The complete encoding, declared collection or owner text is too large.
    #[error("SNL1 bound exceeded")]
    BoundsExceeded,
    /// An invalid subject owner, role, zero epoch or out-of-range next counter.
    #[error("invalid SNL1 row")]
    InvalidRow,
    /// Row identities repeat or are not strictly increasing in wire order.
    #[error("SNL1 identities are not strictly ordered")]
    InvalidOrder,
    /// The ledger version is not 1.
    #[error("unsupported SNL1 version")]
    UnsupportedVersion,
    /// A store-file identity uses a tag other than the selected Linux tag 1.
    #[error("unsupported SNL1 store-file tag")]
    UnsupportedPlatform,
}

impl StrictCborError for SubjectNonceLedgerErrorV1 {
    fn invalid_encoding(_: u8) -> Self {
        Self::InvalidEncoding
    }

    fn bounds_exceeded(_: u8) -> Self {
        Self::BoundsExceeded
    }
}

/// Untrusted row data for the role-0 subject-data identity in SNL1.
///
/// Constructing this value establishes no authority. [`SubjectNonceLedgerV1`]
/// validates its wire grammar; the owner adapter must independently verify
/// the root digest and the descriptor-derived device/inode against its store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectNonceLedgerRowV1 {
    /// Exact `subject:` plus 32 lowercase hex digits of a non-nil subject.
    pub owner_id: String,
    /// Positive subject-key epoch.
    pub epoch: u64,
    /// Public material digest of the subject root, never the private root.
    pub root_material_digest: [u8; 32],
    /// Untrusted Linux `[st_dev, st_ino]` metadata; encoding adds tag 1.
    pub store_file_id: [u64; 2],
    /// Next data counter in `1..=2^32`, with `2^32` meaning exhausted.
    pub data_next: u64,
    /// Independent bootstrap counter with the same range and sentinel.
    pub bootstrap_next: u64,
}

/// One bounded, canonical SNL1 artifact with strictly ordered unique rows.
///
/// This structural value cannot reserve a nonce or authorize encryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectNonceLedgerV1 {
    rows: Vec<SubjectNonceLedgerRowV1>,
    bytes: Vec<u8>,
}

impl SubjectNonceLedgerV1 {
    /// Encode rows already sorted by the deterministic encoding of their
    /// `(owner, role 0, epoch)` identity. An empty ledger is representable.
    ///
    /// # Errors
    /// Rejects invalid row values, repeated or descending identities, and a
    /// complete encoding above 1 MiB. Collection stops on the first refusal.
    pub fn new(
        rows: impl IntoIterator<Item = SubjectNonceLedgerRowV1>,
    ) -> Result<Self, SubjectNonceLedgerErrorV1> {
        let mut validated = Vec::new();
        let mut encoded_rows = Vec::new();
        let mut previous: Option<Vec<u8>> = None;
        for row in rows {
            validate_row(&row)?;
            let identity = identity_bytes(&row);
            if previous.as_ref().is_some_and(|last| last >= &identity) {
                return Err(SubjectNonceLedgerErrorV1::InvalidOrder);
            }
            append_row(&mut encoded_rows, &row, &identity);
            if header(validated.len() + 1).len() + encoded_rows.len()
                > MAX_SUBJECT_NONCE_LEDGER_BYTES
            {
                return Err(SubjectNonceLedgerErrorV1::BoundsExceeded);
            }
            previous = Some(identity);
            validated.push(row);
        }
        let mut bytes = header(validated.len());
        bytes.extend_from_slice(&encoded_rows);
        Ok(Self {
            rows: validated,
            bytes,
        })
    }

    /// Decode exactly one canonical SNL1 artifact, checking the whole-file
    /// bound before parsing or allocating rows. Declared counts never cause
    /// allocation in advance of actually decoded rows.
    ///
    /// # Errors
    /// Returns a closed error for invalid framing, bounds, unsupported version
    /// or store-file tag, invalid row values, duplicate or unordered identities.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SubjectNonceLedgerErrorV1> {
        if bytes.len() > MAX_SUBJECT_NONCE_LEDGER_BYTES {
            return Err(SubjectNonceLedgerErrorV1::BoundsExceeded);
        }
        let mut reader = Reader::<SubjectNonceLedgerErrorV1>::new(bytes);
        reader.fixed_array(3)?;
        if reader.bytes::<4>()? != MAGIC {
            return Err(SubjectNonceLedgerErrorV1::InvalidEncoding);
        }
        if reader.unsigned()? != VERSION {
            return Err(SubjectNonceLedgerErrorV1::UnsupportedVersion);
        }
        let count = reader.array(MAX_SUBJECT_NONCE_LEDGER_BYTES)?;
        let mut rows = Vec::new();
        for _ in 0..count {
            rows.push(read_row(&mut reader)?);
        }
        reader.finish()?;
        Self::new(rows)
    }

    /// The exact deterministic-CBOR file bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Structurally validated rows in canonical identity order.
    pub fn rows(&self) -> impl ExactSizeIterator<Item = &SubjectNonceLedgerRowV1> {
        self.rows.iter()
    }
}

fn validate_row(row: &SubjectNonceLedgerRowV1) -> Result<(), SubjectNonceLedgerErrorV1> {
    if parse_subject_owner_id(&row.owner_id).is_err()
        || row.epoch == 0
        || !(1..=EXHAUSTED_SUBJECT_NONCE_COUNTER).contains(&row.data_next)
        || !(1..=EXHAUSTED_SUBJECT_NONCE_COUNTER).contains(&row.bootstrap_next)
    {
        return Err(SubjectNonceLedgerErrorV1::InvalidRow);
    }
    Ok(())
}

fn header(rows: usize) -> Vec<u8> {
    let mut bytes = vec![0x83];
    subject_cbor::byte_string(&mut bytes, &MAGIC);
    subject_cbor::unsigned(&mut bytes, VERSION);
    subject_cbor::head(&mut bytes, 4, rows as u64);
    bytes
}

fn identity_bytes(row: &SubjectNonceLedgerRowV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    subject_cbor::text(&mut bytes, &row.owner_id);
    subject_cbor::unsigned(&mut bytes, u64::from(ROLE));
    subject_cbor::unsigned(&mut bytes, row.epoch);
    bytes
}

fn append_row(output: &mut Vec<u8>, row: &SubjectNonceLedgerRowV1, identity: &[u8]) {
    output.push(0x87);
    output.extend_from_slice(identity);
    subject_cbor::byte_string(output, &row.root_material_digest);
    output.push(0x83);
    subject_cbor::unsigned(output, LINUX_STORE_FILE_TAG);
    subject_cbor::unsigned(output, row.store_file_id[0]);
    subject_cbor::unsigned(output, row.store_file_id[1]);
    subject_cbor::unsigned(output, row.data_next);
    subject_cbor::unsigned(output, row.bootstrap_next);
}

fn read_row(
    reader: &mut Reader<'_, SubjectNonceLedgerErrorV1>,
) -> Result<SubjectNonceLedgerRowV1, SubjectNonceLedgerErrorV1> {
    reader.fixed_array(7)?;
    let owner_id = reader.text(SUBJECT_OWNER_BYTES)?.to_owned();
    if reader.unsigned()? != u64::from(ROLE) {
        return Err(SubjectNonceLedgerErrorV1::InvalidRow);
    }
    let epoch = reader.unsigned()?;
    let root_material_digest = reader.bytes()?;
    reader.fixed_array(3)?;
    if reader.unsigned()? != LINUX_STORE_FILE_TAG {
        return Err(SubjectNonceLedgerErrorV1::UnsupportedPlatform);
    }
    Ok(SubjectNonceLedgerRowV1 {
        owner_id,
        epoch,
        root_material_digest,
        store_file_id: [reader.unsigned()?, reader.unsigned()?],
        data_next: reader.unsigned()?,
        bootstrap_next: reader.unsigned()?,
    })
}
