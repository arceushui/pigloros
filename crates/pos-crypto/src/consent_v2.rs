//! Accepted ADR-097 section 3: CGV2 and its complete clear-policy header.
//!
//! A structurally decoded payload is not an authenticated grant. The host
//! must verify its committed Event and coordinates before restoring policy,
//! and authorize the exact key before reading purpose. This codec neither
//! issues capabilities nor decrypts purpose; locked or destroyed purpose
//! cannot change the clear policy it represents.

use pos_core::{consent::MAX_PURPOSE_BYTES, EntityId};
use thiserror::Error;
use ulid::Ulid;

use crate::strict_cbor::{Reader, StrictCborError};
use crate::subject_cbor;
use crate::subject_ciphertext::{
    SubjectCiphertextErrorV1, SubjectCiphertextV1, MAX_SUBJECT_CIPHERTEXT_BYTES,
};
use crate::subject_key::SubjectKeyUseV1;

/// The complete containing Event payload bound.
pub const MAX_CONSENT_V2_BYTES: usize = 262_144;
/// The Event type whose exact payload is CGV2.
pub const CONSENT_GRANTED_V2_EVENT_TYPE: &str = "consent.granted.v2";
const MAGIC: [u8; 4] = *b"CGV2";
// Canonical CBOR text of at most 128 UTF-8 bytes has at most a two-byte
// string head; AES-GCM appends its full 16-byte tag.
const MAX_SEALED_PURPOSE_BYTES: usize = MAX_PURPOSE_BYTES + 2 + 16;

/// A closed, payload-free CGV2 failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsentV2Error {
    /// Wrong type, noncanonical CBOR, cardinality or trailing bytes.
    #[error("invalid CGV2 encoding")]
    InvalidEncoding,
    /// The payload or encrypted purpose exceeds its schema bound.
    #[error("CGV2 bound exceeded")]
    BoundsExceeded,
    /// Wrong magic/version, invalid policy, or inconsistent SDC1 context.
    #[error("invalid CGV2 policy or context")]
    InvalidPolicy,
    /// The nested SDC1 envelope is structurally invalid.
    #[error(transparent)]
    Ciphertext(#[from] SubjectCiphertextErrorV1),
}

impl StrictCborError for ConsentV2Error {
    fn invalid_encoding(_: u8) -> Self {
        Self::InvalidEncoding
    }

    fn bounds_exceeded(_: u8) -> Self {
        Self::BoundsExceeded
    }
}

/// The clear fields of a V2 grant. These values alone confer no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsentPolicyV2 {
    /// The non-nil subject and committed Event entity.
    pub subject_id: EntityId,
    /// The non-nil grantee.
    pub grantee_id: EntityId,
    /// The same four modality bits as `ConsentGrantedV1`.
    pub modalities: u8,
    /// 0 = no floor, 1 = the ADR-026 geographic floor.
    pub min_geo_resolution: u8,
    /// Whether the grant permits a Fork.
    pub fork_permitted: bool,
    /// Whether the grant permits export.
    pub export_permitted: bool,
    /// 0 remains session-only.
    pub retention_days: u16,
    /// 0 remains no expiry.
    pub expiry_secs: u32,
    /// The positive committed logical sequence and first-commit origin sequence.
    pub grant_seq: u64,
}

impl ConsentPolicyV2 {
    /// Encode all eleven clear fields, omitting only encrypted purpose.
    /// Use these exact bytes as SDC1's public header before encryption.
    ///
    /// # Errors
    /// Rejects nil IDs, unknown modality bits, an unsupported geographic
    /// floor, or a zero grant sequence.
    pub fn public_header(&self) -> Result<Vec<u8>, ConsentV2Error> {
        self.validate().map(|()| encode_header(self))
    }

    fn validate(&self) -> Result<(), ConsentV2Error> {
        if self.subject_id.inner().to_bytes() == [0; 16]
            || self.grantee_id.inner().to_bytes() == [0; 16]
            || self.modalities & !0x0f != 0
            || self.min_geo_resolution > 1
            || self.grant_seq == 0
        {
            Err(ConsentV2Error::InvalidPolicy)
        } else {
            Ok(())
        }
    }
}

/// One canonical CGV2 grant payload and its structurally valid SDC1 purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentGrantedV2 {
    policy: ConsentPolicyV2,
    purpose: SubjectCiphertextV1,
    bytes: Vec<u8>,
}

impl ConsentGrantedV2 {
    /// Construct the exact payload from validated clear policy and ciphertext.
    /// Purpose plaintext must separately be a canonical CBOR text string of
    /// at most 128 UTF-8 bytes; this checks the possible ciphertext length.
    ///
    /// # Errors
    /// Rejects invalid policy, oversized purpose, and a mismatch with the
    /// SDC1 subject, origin sequence, use, Event type, schema or field tag.
    pub fn new(
        policy: ConsentPolicyV2,
        purpose: SubjectCiphertextV1,
    ) -> Result<Self, ConsentV2Error> {
        policy.validate()?;
        if purpose.subject_id() != policy.subject_id
            || purpose.origin_logical_seq() != policy.grant_seq
            || purpose.key_use() != SubjectKeyUseV1::Bootstrap
            || purpose.event_type() != CONSENT_GRANTED_V2_EVENT_TYPE
            || purpose.schema_version() != 1
            || purpose.field_tag() != "purpose"
        {
            return Err(ConsentV2Error::InvalidPolicy);
        }
        if purpose.ciphertext_and_tag().len() > MAX_SEALED_PURPOSE_BYTES {
            return Err(ConsentV2Error::BoundsExceeded);
        }
        let mut bytes = vec![0x8c];
        encode_parties(&mut bytes, &policy);
        subject_cbor::byte_string(&mut bytes, purpose.as_bytes());
        encode_permissions(&mut bytes, &policy);
        Ok(Self {
            policy,
            purpose,
            bytes,
        })
    }

    /// Decode exactly one canonical payload without keys or authority access.
    /// No allocation of attacker-selected bytes precedes the payload bound.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized or inconsistent CGV2/SDC1
    /// fields. Event authentication and purpose plaintext validation remain
    /// the consuming host's responsibility.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConsentV2Error> {
        if bytes.len() > MAX_CONSENT_V2_BYTES {
            return Err(ConsentV2Error::BoundsExceeded);
        }
        let mut reader = Reader::<ConsentV2Error>::new(bytes);
        reader.fixed_array(12)?;
        if reader.bytes::<4>()? != MAGIC || reader.unsigned()? != 2 {
            return Err(ConsentV2Error::InvalidPolicy);
        }
        let subject_id = EntityId::from_ulid(Ulid::from_bytes(reader.bytes()?));
        let grantee_id = EntityId::from_ulid(Ulid::from_bytes(reader.bytes()?));
        let purpose =
            SubjectCiphertextV1::from_bytes(reader.byte_string(MAX_SUBJECT_CIPHERTEXT_BYTES)?)?;
        let policy = ConsentPolicyV2 {
            subject_id,
            grantee_id,
            modalities: u8::try_from(reader.unsigned()?)
                .map_err(|_| ConsentV2Error::InvalidPolicy)?,
            min_geo_resolution: u8::try_from(reader.unsigned()?)
                .map_err(|_| ConsentV2Error::InvalidPolicy)?,
            fork_permitted: reader.boolean()?,
            export_permitted: reader.boolean()?,
            retention_days: u16::try_from(reader.unsigned()?)
                .map_err(|_| ConsentV2Error::InvalidPolicy)?,
            expiry_secs: u32::try_from(reader.unsigned()?)
                .map_err(|_| ConsentV2Error::InvalidPolicy)?,
            grant_seq: reader.unsigned()?,
        };
        reader.finish()?;
        Self::new(policy, purpose)
    }

    /// The exact canonical containing Event payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Every clear field as an eleven-field definite array.
    #[must_use]
    pub fn public_header(&self) -> Vec<u8> {
        encode_header(&self.policy)
    }

    /// The clear policy, which is independent of purpose availability.
    #[must_use]
    pub const fn policy(&self) -> &ConsentPolicyV2 {
        &self.policy
    }

    /// The structurally parsed purpose envelope. This access authenticates
    /// neither the Event nor the purpose and releases no plaintext.
    #[must_use]
    pub const fn encrypted_purpose(&self) -> &SubjectCiphertextV1 {
        &self.purpose
    }
}

fn encode_header(policy: &ConsentPolicyV2) -> Vec<u8> {
    let mut bytes = vec![0x8b];
    encode_parties(&mut bytes, policy);
    encode_permissions(&mut bytes, policy);
    bytes
}

fn encode_parties(bytes: &mut Vec<u8>, policy: &ConsentPolicyV2) {
    subject_cbor::byte_string(bytes, &MAGIC);
    subject_cbor::unsigned(bytes, 2);
    subject_cbor::byte_string(bytes, &policy.subject_id.inner().to_bytes());
    subject_cbor::byte_string(bytes, &policy.grantee_id.inner().to_bytes());
}

fn encode_permissions(bytes: &mut Vec<u8>, policy: &ConsentPolicyV2) {
    subject_cbor::unsigned(bytes, u64::from(policy.modalities));
    subject_cbor::unsigned(bytes, u64::from(policy.min_geo_resolution));
    bytes.push(if policy.fork_permitted { 0xf5 } else { 0xf4 });
    bytes.push(if policy.export_permitted { 0xf5 } else { 0xf4 });
    subject_cbor::unsigned(bytes, u64::from(policy.retention_days));
    subject_cbor::unsigned(bytes, u64::from(policy.expiry_secs));
    subject_cbor::unsigned(bytes, policy.grant_seq);
}
