//! ADR-097 section 3: the exact `subject.data.v1` (SDP1) payload.
//!
//! This structural codec supplies the complete clear header for SDC1's
//! context binding. It does not register a field schema, authenticate an
//! Event, authorize a key, or activate an encryption consumer. Those checks
//! remain mandatory at the owner adapter before encryption or decryption.

use pos_core::EntityId;
use thiserror::Error;
use ulid::Ulid;

use crate::strict_cbor::{Reader, StrictCborError};
use crate::subject_cbor;
use crate::subject_ciphertext::{
    SubjectCiphertextErrorV1, SubjectCiphertextV1, MAX_SUBJECT_CIPHERTEXT_BYTES,
    MAX_SUBJECT_FIELD_TAG_BYTES,
};
use crate::subject_key::SubjectKeyUseV1;

/// The containing Event payload limit, including the outer SDP1 envelope.
pub const MAX_SUBJECT_DATA_BYTES: usize = 262_144;
/// The Event type whose payload has the SDP1 schema.
pub const SUBJECT_DATA_EVENT_TYPE: &str = "subject.data.v1";
const MAGIC: [u8; 4] = *b"SDP1";

/// A payload-free structural SDP1 failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SubjectDataErrorV1 {
    /// Wrong CBOR type, noncanonical encoding, cardinality or trailing data.
    #[error("invalid SDP1 encoding")]
    InvalidEncoding,
    /// The complete payload or field tag exceeds its accepted bound.
    #[error("SDP1 bound exceeded")]
    BoundsExceeded,
    /// Magic, version, subject, tag or nested schema fields do not match.
    #[error("invalid SDP1 header")]
    InvalidHeader,
    /// The nested SDC1 envelope is structurally invalid.
    #[error(transparent)]
    Ciphertext(#[from] SubjectCiphertextErrorV1),
}

impl StrictCborError for SubjectDataErrorV1 {
    fn invalid_encoding(_: u8) -> Self {
        Self::InvalidEncoding
    }

    fn bounds_exceeded(_: u8) -> Self {
        Self::BoundsExceeded
    }
}

/// Encode the exact four-field SDP1 public header before SDC1 encryption.
///
/// The caller must independently establish that `field_tag` is registered
/// for an actual subject field; this validates only its wire grammar.
///
/// # Errors
/// Returns a closed error for a nil subject, an empty/non-ASCII field tag,
/// or a field tag longer than 128 bytes.
pub fn subject_data_public_header(
    subject: EntityId,
    field_tag: &str,
) -> Result<Vec<u8>, SubjectDataErrorV1> {
    if field_tag.len() > MAX_SUBJECT_FIELD_TAG_BYTES {
        return Err(SubjectDataErrorV1::BoundsExceeded);
    }
    if subject.inner().to_bytes() == [0; 16] || field_tag.is_empty() || !field_tag.is_ascii() {
        return Err(SubjectDataErrorV1::InvalidHeader);
    }
    Ok(encode_header(subject, field_tag))
}

/// A structurally validated SDP1 payload, retaining its exact canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectDataV1 {
    ciphertext: SubjectCiphertextV1,
    bytes: Vec<u8>,
}

impl SubjectDataV1 {
    /// Wrap a data-use SDC1 envelope in its exact containing Event payload.
    ///
    /// # Errors
    /// Rejects a wrong SDC1 use, Event type or schema, or a payload above
    /// 256 KiB including outer framing. No allocation of that payload occurs
    /// until its final size is checked.
    pub fn new(ciphertext: SubjectCiphertextV1) -> Result<Self, SubjectDataErrorV1> {
        if ciphertext.key_use() != SubjectKeyUseV1::Data
            || ciphertext.event_type() != SUBJECT_DATA_EVENT_TYPE
            || ciphertext.schema_version() != 1
        {
            return Err(SubjectDataErrorV1::InvalidHeader);
        }
        let mut bytes = encode_header(ciphertext.subject_id(), ciphertext.field_tag());
        let mut length = Vec::new();
        subject_cbor::head(&mut length, 2, ciphertext.as_bytes().len() as u64);
        if bytes.len() + length.len() + ciphertext.as_bytes().len() > MAX_SUBJECT_DATA_BYTES {
            return Err(SubjectDataErrorV1::BoundsExceeded);
        }
        bytes[0] = 0x85;
        bytes.extend_from_slice(&length);
        bytes.extend_from_slice(ciphertext.as_bytes());
        Ok(Self { ciphertext, bytes })
    }

    /// Decode exactly one bounded canonical payload and compare every field
    /// duplicated in SDC1. This does not verify its authentication tag.
    ///
    /// # Errors
    /// Returns a closed error for framing, bounds, invalid nested ciphertext,
    /// or a mismatch between the outer subject/tag and the nested envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SubjectDataErrorV1> {
        if bytes.len() > MAX_SUBJECT_DATA_BYTES {
            return Err(SubjectDataErrorV1::BoundsExceeded);
        }
        let mut reader = Reader::<SubjectDataErrorV1>::new(bytes);
        reader.fixed_array(5)?;
        if reader.bytes::<4>()? != MAGIC || reader.unsigned()? != 1 {
            return Err(SubjectDataErrorV1::InvalidHeader);
        }
        let subject = EntityId::from_ulid(Ulid::from_bytes(reader.bytes()?));
        let tag = reader.text(MAX_SUBJECT_FIELD_TAG_BYTES)?;
        let ciphertext =
            SubjectCiphertextV1::from_bytes(reader.byte_string(MAX_SUBJECT_CIPHERTEXT_BYTES)?)?;
        reader.finish()?;
        if subject != ciphertext.subject_id() || tag != ciphertext.field_tag() {
            return Err(SubjectDataErrorV1::InvalidHeader);
        }
        Self::new(ciphertext)
    }

    /// The exact canonical containing Event payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The complete four-field public header, excluding only ciphertext.
    #[must_use]
    pub fn public_header(&self) -> Vec<u8> {
        encode_header(self.ciphertext.subject_id(), self.ciphertext.field_tag())
    }

    /// The nested ciphertext. Authentication still requires a verified
    /// committed Event, this payload's complete header and the registered tag.
    #[must_use]
    pub const fn ciphertext(&self) -> &SubjectCiphertextV1 {
        &self.ciphertext
    }
}

fn encode_header(subject: EntityId, field_tag: &str) -> Vec<u8> {
    let mut bytes = vec![0x84];
    subject_cbor::byte_string(&mut bytes, &MAGIC);
    subject_cbor::unsigned(&mut bytes, 1);
    subject_cbor::byte_string(&mut bytes, &subject.inner().to_bytes());
    subject_cbor::text(&mut bytes, field_tag);
    bytes
}
