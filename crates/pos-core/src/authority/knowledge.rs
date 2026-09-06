//! Canonical participant observation and knowledge contracts (ADR-059).
//!
//! These values contain no store, projection, network, clock, or host-service
//! handles. Only the trusted host may turn authoritative state into these
//! immutable, participant-specific records.

use ciborium::Value;

use super::{
    bytes, decode_bounded_array, decode_entity, decode_hash, decode_optional_hash, decode_text,
    decode_timeline, decode_u64, decode_u8, encode_value, entity_bytes, expect_header, hash_value,
    optional_hash_value, text, timeline_bytes, uint, validate_entity_id, validate_hash,
    validate_text, validate_timeline_id, AuthorityErrorV1, VERSION,
};
use crate::{CanonicalBytes, EntityId, Hash, Seq, TimelineId};

const OBSERVATION_RECORD_MAGIC: [u8; 4] = *b"OBR1";

/// Maximum canonical OBR1 record size.
pub const MAX_OBSERVATION_RECORD_BYTES: usize = 4 * 1_024;
/// Maximum bytes in one immutable observation-value artifact.
pub const MAX_OBSERVATION_ARTIFACT_BYTES: usize = 1_024 * 1_024;

/// Immutable content-addressed value bytes referenced by an observation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationArtifactV1 {
    bytes: CanonicalBytes,
    digest: Hash,
}

impl ObservationArtifactV1 {
    /// Validate and content-address one bounded observation value.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::FieldOutOfBounds`] for an empty or oversized value.
    pub fn try_new(bytes: CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_OBSERVATION_ARTIFACT_BYTES {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        let digest = Hash::from_bytes(*blake3::hash(bytes.as_slice()).as_bytes());
        Ok(Self { bytes, digest })
    }

    #[must_use]
    pub const fn bytes(&self) -> &CanonicalBytes {
        &self.bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }
}

/// Closed typed-presence state for one requested observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservationStatusV1 {
    Present,
    Unknown,
    Unauthorized,
    Deleted,
    Unavailable,
    NotObserved,
}

impl ObservationStatusV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Present => 0,
            Self::Unknown => 1,
            Self::Unauthorized => 2,
            Self::Deleted => 3,
            Self::Unavailable => 4,
            Self::NotObserved => 5,
        }
    }

    const fn from_code(code: u8) -> Result<Self, AuthorityErrorV1> {
        match code {
            0 => Ok(Self::Present),
            1 => Ok(Self::Unknown),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::Deleted),
            4 => Ok(Self::Unavailable),
            5 => Ok(Self::NotObserved),
            _ => Err(AuthorityErrorV1::UnknownEnum),
        }
    }
}

/// Unvalidated fields for one participant-specific observation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationRecordDraftV1 {
    pub participant_id: EntityId,
    pub resource: String,
    pub data_category: String,
    pub status: ObservationStatusV1,
    pub artifact_digest: Option<Hash>,
    pub source_timeline: TimelineId,
    pub source_position: Seq,
    pub schema: String,
    pub source_digest: Hash,
    pub projection_digest: Option<Hash>,
    pub provenance_digest: Hash,
    pub minimization_revision: Hash,
}

/// Canonical OBR1 reference to one minimized observation value or typed absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationRecordV1 {
    participant_id: EntityId,
    resource: String,
    data_category: String,
    status: ObservationStatusV1,
    artifact_digest: Option<Hash>,
    source_timeline: TimelineId,
    source_position: Seq,
    schema: String,
    source_digest: Hash,
    projection_digest: Option<Hash>,
    provenance_digest: Hash,
    minimization_revision: Hash,
    digest: Hash,
}

impl ObservationRecordV1 {
    /// Validate and bind every record field into its immutable digest.
    ///
    /// # Errors
    /// Returns a closed validation error for invalid identity, text, provenance,
    /// minimization, or typed-presence fields.
    pub fn try_from_draft(draft: ObservationRecordDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_entity_id(draft.participant_id)?;
        validate_text(&draft.resource)?;
        validate_text(&draft.data_category)?;
        validate_timeline_id(draft.source_timeline)?;
        validate_text(&draft.schema)?;
        validate_hash(draft.source_digest)?;
        if let Some(digest) = draft.projection_digest {
            validate_hash(digest)?;
        }
        validate_hash(draft.provenance_digest)?;
        validate_hash(draft.minimization_revision)?;
        match (draft.status, draft.artifact_digest) {
            (ObservationStatusV1::Present, Some(digest)) => validate_hash(digest)?,
            (ObservationStatusV1::Present, None) => {
                return Err(AuthorityErrorV1::SourceUnavailable);
            }
            (ObservationStatusV1::Unauthorized, Some(_)) => {
                return Err(AuthorityErrorV1::UnauthorizedSource);
            }
            (_, Some(_)) => return Err(AuthorityErrorV1::FieldOutOfBounds),
            (_, None) => {}
        }
        let mut record = Self {
            participant_id: draft.participant_id,
            resource: draft.resource,
            data_category: draft.data_category,
            status: draft.status,
            artifact_digest: draft.artifact_digest,
            source_timeline: draft.source_timeline,
            source_position: draft.source_position,
            schema: draft.schema,
            source_digest: draft.source_digest,
            projection_digest: draft.projection_digest,
            provenance_digest: draft.provenance_digest,
            minimization_revision: draft.minimization_revision,
            digest: Hash::zero(),
        };
        record.digest = record.binding_digest()?;
        if record.encode()?.len() > MAX_OBSERVATION_RECORD_BYTES {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        Ok(record)
    }

    #[must_use]
    pub const fn participant_id(&self) -> EntityId {
        self.participant_id
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    #[must_use]
    pub fn data_category(&self) -> &str {
        &self.data_category
    }

    #[must_use]
    pub const fn status(&self) -> ObservationStatusV1 {
        self.status
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> Option<Hash> {
        self.artifact_digest
    }

    #[must_use]
    pub const fn source_timeline(&self) -> TimelineId {
        self.source_timeline
    }

    #[must_use]
    pub const fn source_position(&self) -> Seq {
        self.source_position
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub const fn source_digest(&self) -> Hash {
        self.source_digest
    }

    #[must_use]
    pub const fn projection_digest(&self) -> Option<Hash> {
        self.projection_digest
    }

    #[must_use]
    pub const fn provenance_digest(&self) -> Hash {
        self.provenance_digest
    }

    #[must_use]
    pub const fn minimization_revision(&self) -> Hash {
        self.minimization_revision
    }

    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    /// Encode the exact deterministic-CBOR OBR1 record.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&self.value_with_digest(self.digest)).map(CanonicalBytes::from_vec)
    }

    /// Decode and validate one exact deterministic-CBOR OBR1 record.
    ///
    /// # Errors
    /// Returns a closed codec, validation, or digest error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        let fields = decode_bounded_array(bytes.as_slice(), MAX_OBSERVATION_RECORD_BYTES, 15)?;
        expect_header(&fields, OBSERVATION_RECORD_MAGIC)?;
        let decoded_digest = decode_hash(&fields[14])?;
        let record = Self::try_from_draft(ObservationRecordDraftV1 {
            participant_id: decode_entity(&fields[2])?,
            resource: decode_text(&fields[3])?,
            data_category: decode_text(&fields[4])?,
            status: ObservationStatusV1::from_code(decode_u8(&fields[5])?)?,
            artifact_digest: decode_optional_hash(&fields[6])?,
            source_timeline: decode_timeline(&fields[7])?,
            source_position: Seq::from_u64(decode_u64(&fields[8])?),
            schema: decode_text(&fields[9])?,
            source_digest: decode_hash(&fields[10])?,
            projection_digest: decode_optional_hash(&fields[11])?,
            provenance_digest: decode_hash(&fields[12])?,
            minimization_revision: decode_hash(&fields[13])?,
        })?;
        if record.digest == decoded_digest {
            Ok(record)
        } else {
            Err(AuthorityErrorV1::DigestMismatch)
        }
    }

    fn binding_digest(&self) -> Result<Hash, AuthorityErrorV1> {
        let encoded = encode_value(&self.value_without_digest())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.ObservationRecord.v1\0");
        hasher.update(&encoded);
        Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
    }

    fn value_without_digest(&self) -> Value {
        Value::Array(vec![
            bytes(&OBSERVATION_RECORD_MAGIC),
            uint(VERSION),
            bytes(&entity_bytes(self.participant_id)),
            text(&self.resource),
            text(&self.data_category),
            uint(self.status.code()),
            optional_hash_value(self.artifact_digest),
            bytes(&timeline_bytes(self.source_timeline)),
            uint(self.source_position.as_u64()),
            text(&self.schema),
            hash_value(self.source_digest),
            optional_hash_value(self.projection_digest),
            hash_value(self.provenance_digest),
            hash_value(self.minimization_revision),
        ])
    }

    fn value_with_digest(&self, digest: Hash) -> Value {
        let Value::Array(mut fields) = self.value_without_digest() else {
            unreachable!("record encoder always builds an array")
        };
        fields.push(hash_value(digest));
        Value::Array(fields)
    }
}
