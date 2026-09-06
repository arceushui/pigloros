//! Canonical participant observation and knowledge contracts (ADR-059).
//!
//! These values contain no store, projection, network, clock, or host-service
//! handles. Only the trusted host may turn authoritative state into these
//! immutable, participant-specific records.

use ciborium::Value;

use super::{
    bytes, decode_bounded_array, decode_entity, decode_hash, decode_optional_hash, decode_plugin,
    decode_principal_value, decode_text, decode_timeline, decode_u64, decode_u8, encode_principal,
    encode_value, entity_bytes, exact_array, expect_header, hash_value, optional_hash_value,
    plugin_bytes, text, timeline_bytes, uint, validate_entity_id, validate_hash,
    validate_optional_plugin_id, validate_text, validate_timeline_id, AuthorityErrorV1,
    PersistedAuthorityV1, PrincipalRefV1, MAX_AUTHORITY_DELEGATION_DEPTH, VERSION,
};
use crate::{CanonicalBytes, EntityId, Hash, PluginId, Seq, TimelineId};

const OBSERVATION_RECORD_MAGIC: [u8; 4] = *b"OBR1";
const OBSERVATION_SNAPSHOT_MAGIC: [u8; 4] = *b"OBS1";
const KNOWLEDGE_SNAPSHOT_MAGIC: [u8; 4] = *b"KNS1";

/// Maximum canonical OBR1 record size.
pub const MAX_OBSERVATION_RECORD_BYTES: usize = 4 * 1_024;
/// Maximum bytes in one immutable observation-value artifact.
pub const MAX_OBSERVATION_ARTIFACT_BYTES: usize = 1_024 * 1_024;
/// Maximum canonical OBS1 snapshot size.
pub const MAX_OBSERVATION_SNAPSHOT_BYTES: usize = 1_024 * 1_024;
/// Maximum records in one OBS1 snapshot.
pub const MAX_OBSERVATION_SNAPSHOT_RECORDS: usize = 4_096;
/// Maximum canonical KNS1 snapshot size.
pub const MAX_KNOWLEDGE_SNAPSHOT_BYTES: usize = 2 * 1_024 * 1_024;
/// Maximum combined observations and beliefs in one KNS1 snapshot.
pub const MAX_KNOWLEDGE_SNAPSHOT_RECORDS: usize = 4_096;

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
        let encoded = encode_value(&Value::Array(self.fields_without_digest()))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.ObservationRecord.v1\0");
        hasher.update(&encoded);
        Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
    }

    fn fields_without_digest(&self) -> Vec<Value> {
        vec![
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
        ]
    }

    fn value_with_digest(&self, digest: Hash) -> Value {
        let mut fields = self.fields_without_digest();
        fields.push(hash_value(digest));
        Value::Array(fields)
    }

    fn canonical_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source_timeline
            .cmp(&other.source_timeline)
            .then_with(|| self.source_position.cmp(&other.source_position))
            .then_with(|| self.schema.cmp(&other.schema))
            .then_with(|| self.digest.cmp(&other.digest))
    }
}

/// Unvalidated fields for one participant-specific immutable observation snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSnapshotDraftV1 {
    pub principal: PrincipalRefV1,
    pub participant_id: EntityId,
    pub plugin_id: PluginId,
    pub installation_id: [u8; 16],
    pub timeline_id: TimelineId,
    pub observed_through: Seq,
    pub authority_timeline: TimelineId,
    pub authority_position: Seq,
    pub authorization_request_digest: Hash,
    pub authorization_decision_digest: Hash,
    pub grant_chain_bindings: Vec<Hash>,
    pub consent_policy_revision: Hash,
    pub capability_policy_revision: Hash,
    pub revocation_epoch: u64,
    pub visibility_policy_revision: Hash,
    pub schema_revision: Hash,
    pub minimization_revision: Hash,
    pub records: Vec<ObservationRecordV1>,
    pub artifacts: Vec<ObservationArtifactV1>,
    pub prior_snapshot_digest: Option<Hash>,
    pub provenance_digest: Hash,
}

/// Canonical OBS1 participant input issued by the trusted host at a Tick Boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSnapshotV1 {
    principal: PrincipalRefV1,
    participant_id: EntityId,
    plugin_id: PluginId,
    installation_id: [u8; 16],
    timeline_id: TimelineId,
    observed_through: Seq,
    authority_timeline: TimelineId,
    authority_position: Seq,
    authorization_request_digest: Hash,
    authorization_decision_digest: Hash,
    grant_chain_bindings: Vec<Hash>,
    consent_policy_revision: Hash,
    capability_policy_revision: Hash,
    revocation_epoch: u64,
    visibility_policy_revision: Hash,
    schema_revision: Hash,
    minimization_revision: Hash,
    records: Vec<ObservationRecordV1>,
    artifacts: Vec<ObservationArtifactV1>,
    prior_snapshot_digest: Option<Hash>,
    provenance_digest: Hash,
    digest: Hash,
}

impl ObservationSnapshotV1 {
    /// Validate authorization bindings, canonical ordering, artifact references,
    /// and snapshot bounds before calculating the immutable digest.
    ///
    /// # Errors
    /// Returns a closed validation or codec error for incomplete or noncanonical input.
    pub fn try_from_draft(draft: ObservationSnapshotDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_entity_id(draft.participant_id)?;
        validate_optional_plugin_id(Some(draft.plugin_id))?;
        if draft.installation_id == [0; 16] {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        validate_timeline_id(draft.timeline_id)?;
        validate_timeline_id(draft.authority_timeline)?;
        for digest in [
            draft.authorization_request_digest,
            draft.authorization_decision_digest,
            draft.consent_policy_revision,
            draft.capability_policy_revision,
            draft.visibility_policy_revision,
            draft.schema_revision,
            draft.minimization_revision,
            draft.provenance_digest,
        ] {
            validate_hash(digest)?;
        }
        if let Some(digest) = draft.prior_snapshot_digest {
            validate_hash(digest)?;
        }
        validate_grant_bindings(&draft.grant_chain_bindings)?;
        validate_snapshot_records(
            draft.participant_id,
            draft.minimization_revision,
            &draft.records,
        )?;
        validate_snapshot_artifacts(&draft.records, &draft.artifacts)?;

        let mut snapshot = Self {
            principal: draft.principal,
            participant_id: draft.participant_id,
            plugin_id: draft.plugin_id,
            installation_id: draft.installation_id,
            timeline_id: draft.timeline_id,
            observed_through: draft.observed_through,
            authority_timeline: draft.authority_timeline,
            authority_position: draft.authority_position,
            authorization_request_digest: draft.authorization_request_digest,
            authorization_decision_digest: draft.authorization_decision_digest,
            grant_chain_bindings: draft.grant_chain_bindings,
            consent_policy_revision: draft.consent_policy_revision,
            capability_policy_revision: draft.capability_policy_revision,
            revocation_epoch: draft.revocation_epoch,
            visibility_policy_revision: draft.visibility_policy_revision,
            schema_revision: draft.schema_revision,
            minimization_revision: draft.minimization_revision,
            records: draft.records,
            artifacts: draft.artifacts,
            prior_snapshot_digest: draft.prior_snapshot_digest,
            provenance_digest: draft.provenance_digest,
            digest: Hash::zero(),
        };
        snapshot.digest = snapshot.binding_digest()?;
        if snapshot.encode()?.len() > MAX_OBSERVATION_SNAPSHOT_BYTES {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        Ok(snapshot)
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }

    #[must_use]
    pub const fn participant_id(&self) -> EntityId {
        self.participant_id
    }

    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    #[must_use]
    pub const fn installation_id(&self) -> [u8; 16] {
        self.installation_id
    }

    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn observed_through(&self) -> Seq {
        self.observed_through
    }

    #[must_use]
    pub const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }

    #[must_use]
    pub const fn authority_position(&self) -> Seq {
        self.authority_position
    }

    #[must_use]
    pub const fn authorization_request_digest(&self) -> Hash {
        self.authorization_request_digest
    }

    #[must_use]
    pub const fn authorization_decision_digest(&self) -> Hash {
        self.authorization_decision_digest
    }

    #[must_use]
    pub fn grant_chain_bindings(&self) -> &[Hash] {
        &self.grant_chain_bindings
    }

    #[must_use]
    pub const fn consent_policy_revision(&self) -> Hash {
        self.consent_policy_revision
    }

    #[must_use]
    pub const fn capability_policy_revision(&self) -> Hash {
        self.capability_policy_revision
    }

    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    #[must_use]
    pub const fn visibility_policy_revision(&self) -> Hash {
        self.visibility_policy_revision
    }

    #[must_use]
    pub const fn schema_revision(&self) -> Hash {
        self.schema_revision
    }

    #[must_use]
    pub const fn minimization_revision(&self) -> Hash {
        self.minimization_revision
    }

    #[must_use]
    pub fn records(&self) -> &[ObservationRecordV1] {
        &self.records
    }

    /// Resolve a present record's immutable value without exposing a store handle.
    #[must_use]
    pub fn artifact(&self, digest: Hash) -> Option<&ObservationArtifactV1> {
        self.artifacts
            .binary_search_by_key(&digest, ObservationArtifactV1::digest)
            .ok()
            .map(|index| &self.artifacts[index])
    }

    #[must_use]
    pub const fn prior_snapshot_digest(&self) -> Option<Hash> {
        self.prior_snapshot_digest
    }

    #[must_use]
    pub const fn provenance_digest(&self) -> Hash {
        self.provenance_digest
    }

    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    /// Revalidate the snapshot's complete grant and revocation identity at a
    /// later authority fence before staged work may commit.
    ///
    /// # Errors
    /// Returns a closed fail-closed error when the authority state is stale,
    /// advanced to a new revocation epoch, changed grant chain, expired, or revoked.
    pub fn validate_authority_fence(
        &self,
        authority: &PersistedAuthorityV1,
        at_position: Seq,
    ) -> Result<(), AuthorityErrorV1> {
        if at_position < self.authority_position {
            return Err(AuthorityErrorV1::RevocationStateStale);
        }
        match authority.revocation_epoch().cmp(&self.revocation_epoch) {
            std::cmp::Ordering::Less => return Err(AuthorityErrorV1::RevocationStateStale),
            std::cmp::Ordering::Greater => return Err(AuthorityErrorV1::RevokedAtFence),
            std::cmp::Ordering::Equal => {}
        }
        let grants = authority.chain().grants();
        let bindings = grants
            .iter()
            .map(super::CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>()?;
        if bindings != self.grant_chain_bindings
            || grants
                .iter()
                .any(|grant| grant.issuance_timeline() != self.authority_timeline)
        {
            return Err(AuthorityErrorV1::DelegationInvalid);
        }
        let Some(leaf) = grants.last() else {
            return Err(AuthorityErrorV1::DelegationInvalid);
        };
        if leaf.grantee().principal() != &self.principal
            || leaf.grantee().plugin_id() != Some(self.plugin_id)
            || leaf.grantee().installation_id() != Some(self.installation_id)
            || leaf.scope().plugin_id() != Some(self.plugin_id)
            || leaf
                .scope()
                .participant_ids()
                .binary_search(&self.participant_id)
                .is_err()
            || leaf.policy_revision() != self.capability_policy_revision
        {
            return Err(AuthorityErrorV1::DelegationInvalid);
        }
        if grants.iter().any(|grant| {
            grant
                .revocation_fence()
                .is_some_and(|fence| fence <= at_position)
        }) {
            return Err(AuthorityErrorV1::RevokedAtFence);
        }
        if grants.iter().any(|grant| {
            at_position < grant.valid_from_position() || at_position >= grant.valid_until_position()
        }) {
            return Err(AuthorityErrorV1::CapabilityMissing);
        }
        Ok(())
    }

    /// Encode the exact deterministic-CBOR OBS1 snapshot.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&self.value_with_digest(self.digest)?).map(CanonicalBytes::from_vec)
    }

    /// Decode and validate one exact deterministic-CBOR OBS1 snapshot.
    ///
    /// # Errors
    /// Returns a closed codec, validation, or digest error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        let fields = decode_bounded_array(bytes.as_slice(), MAX_OBSERVATION_SNAPSHOT_BYTES, 24)?;
        expect_header(&fields, OBSERVATION_SNAPSHOT_MAGIC)?;
        let records = decode_values(&fields[19])?
            .iter()
            .map(decode_observation_record)
            .collect::<Result<Vec<_>, _>>()?;
        let artifacts = decode_values(&fields[20])?
            .iter()
            .map(decode_observation_artifact)
            .collect::<Result<Vec<_>, _>>()?;
        let decoded_digest = decode_hash(&fields[23])?;
        let snapshot = Self::try_from_draft(ObservationSnapshotDraftV1 {
            principal: decode_principal_value(&fields[2])?,
            participant_id: decode_entity(&fields[3])?,
            plugin_id: decode_plugin(&fields[4])?,
            installation_id: decode_fixed_bytes::<16>(&fields[5])?,
            timeline_id: decode_timeline(&fields[6])?,
            observed_through: Seq::from_u64(decode_u64(&fields[7])?),
            authority_timeline: decode_timeline(&fields[8])?,
            authority_position: Seq::from_u64(decode_u64(&fields[9])?),
            authorization_request_digest: decode_hash(&fields[10])?,
            authorization_decision_digest: decode_hash(&fields[11])?,
            grant_chain_bindings: decode_hash_array(&fields[12])?,
            consent_policy_revision: decode_hash(&fields[13])?,
            capability_policy_revision: decode_hash(&fields[14])?,
            revocation_epoch: decode_u64(&fields[15])?,
            visibility_policy_revision: decode_hash(&fields[16])?,
            schema_revision: decode_hash(&fields[17])?,
            minimization_revision: decode_hash(&fields[18])?,
            records,
            artifacts,
            prior_snapshot_digest: decode_optional_hash(&fields[21])?,
            provenance_digest: decode_hash(&fields[22])?,
        })?;
        if snapshot.digest == decoded_digest {
            Ok(snapshot)
        } else {
            Err(AuthorityErrorV1::DigestMismatch)
        }
    }

    fn binding_digest(&self) -> Result<Hash, AuthorityErrorV1> {
        let encoded = encode_value(&Value::Array(self.fields_without_digest()?))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.ObservationSnapshot.v1\0");
        hasher.update(&encoded);
        Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
    }

    fn fields_without_digest(&self) -> Result<Vec<Value>, AuthorityErrorV1> {
        let records = self
            .records
            .iter()
            .map(ObservationRecordV1::encode)
            .map(|result| result.map(|encoded| bytes(encoded.as_slice())))
            .collect::<Result<Vec<_>, _>>()?;
        let artifacts = self
            .artifacts
            .iter()
            .map(|artifact| {
                Value::Array(vec![
                    hash_value(artifact.digest),
                    bytes(artifact.bytes.as_slice()),
                ])
            })
            .collect();
        Ok(vec![
            bytes(&OBSERVATION_SNAPSHOT_MAGIC),
            uint(VERSION),
            encode_principal(&self.principal),
            bytes(&entity_bytes(self.participant_id)),
            bytes(&plugin_bytes(self.plugin_id)),
            bytes(&self.installation_id),
            bytes(&timeline_bytes(self.timeline_id)),
            uint(self.observed_through.as_u64()),
            bytes(&timeline_bytes(self.authority_timeline)),
            uint(self.authority_position.as_u64()),
            hash_value(self.authorization_request_digest),
            hash_value(self.authorization_decision_digest),
            Value::Array(
                self.grant_chain_bindings
                    .iter()
                    .copied()
                    .map(hash_value)
                    .collect(),
            ),
            hash_value(self.consent_policy_revision),
            hash_value(self.capability_policy_revision),
            uint(self.revocation_epoch),
            hash_value(self.visibility_policy_revision),
            hash_value(self.schema_revision),
            hash_value(self.minimization_revision),
            Value::Array(records),
            Value::Array(artifacts),
            optional_hash_value(self.prior_snapshot_digest),
            hash_value(self.provenance_digest),
        ])
    }

    fn value_with_digest(&self, digest: Hash) -> Result<Value, AuthorityErrorV1> {
        let mut fields = self.fields_without_digest()?;
        fields.push(hash_value(digest));
        Ok(Value::Array(fields))
    }
}

fn validate_grant_bindings(bindings: &[Hash]) -> Result<(), AuthorityErrorV1> {
    if bindings.is_empty()
        || bindings.len() > usize::from(MAX_AUTHORITY_DELEGATION_DEPTH) + 1
        || bindings.iter().any(|binding| *binding == Hash::zero())
        || bindings
            .iter()
            .enumerate()
            .any(|(index, binding)| bindings[..index].contains(binding))
    {
        Err(AuthorityErrorV1::ProvenanceMissing)
    } else {
        Ok(())
    }
}

fn validate_snapshot_records(
    participant_id: EntityId,
    minimization_revision: Hash,
    records: &[ObservationRecordV1],
) -> Result<(), AuthorityErrorV1> {
    if records.len() > MAX_OBSERVATION_SNAPSHOT_RECORDS {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
    }
    if records.iter().any(|record| {
        record.participant_id != participant_id
            || record.minimization_revision != minimization_revision
    }) {
        return Err(AuthorityErrorV1::UnauthorizedSource);
    }
    if records
        .windows(2)
        .any(|pair| pair[0].canonical_cmp(&pair[1]) != std::cmp::Ordering::Less)
    {
        return Err(AuthorityErrorV1::NonCanonicalOrder);
    }
    Ok(())
}

fn validate_snapshot_artifacts(
    records: &[ObservationRecordV1],
    artifacts: &[ObservationArtifactV1],
) -> Result<(), AuthorityErrorV1> {
    if artifacts.len() > MAX_OBSERVATION_SNAPSHOT_RECORDS {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
    }
    if artifacts
        .windows(2)
        .any(|pair| pair[0].digest >= pair[1].digest)
    {
        return Err(AuthorityErrorV1::NonCanonicalOrder);
    }
    let has_unbound_artifact = artifacts.iter().any(|artifact| {
        !records
            .iter()
            .any(|record| record.artifact_digest == Some(artifact.digest))
    });
    let has_missing_artifact = records.iter().any(|record| {
        record.artifact_digest.is_some_and(|digest| {
            artifacts
                .binary_search_by_key(&digest, ObservationArtifactV1::digest)
                .is_err()
        })
    });
    if has_unbound_artifact || has_missing_artifact {
        Err(AuthorityErrorV1::ProvenanceMissing)
    } else {
        Ok(())
    }
}

fn decode_values(value: &Value) -> Result<&[Value], AuthorityErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}

fn decode_observation_record(value: &Value) -> Result<ObservationRecordV1, AuthorityErrorV1> {
    match value {
        Value::Bytes(encoded) => {
            ObservationRecordV1::decode(&CanonicalBytes::from_vec(encoded.clone()))
        }
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}

fn decode_observation_artifact(value: &Value) -> Result<ObservationArtifactV1, AuthorityErrorV1> {
    let fields = exact_array(value, 2)?;
    let declared_digest = decode_hash(&fields[0])?;
    let bytes = match &fields[1] {
        Value::Bytes(bytes) => CanonicalBytes::from_vec(bytes.clone()),
        _ => return Err(AuthorityErrorV1::InvalidEncoding),
    };
    let artifact = ObservationArtifactV1::try_new(bytes)?;
    if artifact.digest == declared_digest {
        Ok(artifact)
    } else {
        Err(AuthorityErrorV1::DigestMismatch)
    }
}

fn decode_hash_array(value: &Value) -> Result<Vec<Hash>, AuthorityErrorV1> {
    decode_values(value)?.iter().map(decode_hash).collect()
}

fn decode_fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], AuthorityErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityErrorV1::InvalidEncoding),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}

/// Fixed-point confidence in millionths, from 0.0 through 1.0 inclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfidenceV1(u32);

impl ConfidenceV1 {
    /// Construct a bounded confidence value.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::FieldOutOfBounds`] above one million.
    pub const fn try_new(millionths: u32) -> Result<Self, AuthorityErrorV1> {
        if millionths <= 1_000_000 {
            Ok(Self(millionths))
        } else {
            Err(AuthorityErrorV1::FieldOutOfBounds)
        }
    }

    #[must_use]
    pub const fn millionths(self) -> u32 {
        self.0
    }
}

macro_rules! revision_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name(Hash);

        impl $name {
            /// Construct a non-zero immutable revision reference.
            ///
            /// # Errors
            /// Returns [`AuthorityErrorV1::FieldOutOfBounds`] for the zero digest.
            pub fn try_new(digest: Hash) -> Result<Self, AuthorityErrorV1> {
                validate_hash(digest).map(|()| Self(digest))
            }

            #[must_use]
            pub const fn digest(self) -> Hash {
                self.0
            }
        }
    };
}

revision_type!(
    PreferenceValueRevisionV1,
    "Revision of participant Preference/value evidence; never an AI goal."
);
revision_type!(
    AiGoalPolicyRevisionV1,
    "Revision of AI goal/policy evidence; never a participant Preference."
);
revision_type!(
    MemoryPolicyRevisionV1,
    "Revision governing memory retention, forgetting, and recall."
);

/// Unvalidated fields for one participant belief.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeliefRecordDraftV1 {
    pub entity_id: EntityId,
    pub predicate: String,
    pub confidence: ConfidenceV1,
    pub provenance_digest: Hash,
    pub observation_record_digests: Vec<Hash>,
}

/// One typed belief in a participant's non-authoritative knowledge snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeliefRecordV1 {
    entity_id: EntityId,
    predicate: String,
    confidence: ConfidenceV1,
    provenance_digest: Hash,
    observation_record_digests: Vec<Hash>,
    digest: Hash,
}

impl BeliefRecordV1 {
    /// Validate and bind one typed belief.
    ///
    /// # Errors
    /// Returns a closed validation error for malformed or noncanonical evidence.
    pub fn try_from_draft(draft: BeliefRecordDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_entity_id(draft.entity_id)?;
        validate_text(&draft.predicate)?;
        validate_hash(draft.provenance_digest)?;
        validate_strict_hashes(
            &draft.observation_record_digests,
            MAX_KNOWLEDGE_SNAPSHOT_RECORDS,
        )?;
        let mut belief = Self {
            entity_id: draft.entity_id,
            predicate: draft.predicate,
            confidence: draft.confidence,
            provenance_digest: draft.provenance_digest,
            observation_record_digests: draft.observation_record_digests,
            digest: Hash::zero(),
        };
        belief.digest = belief.binding_digest()?;
        Ok(belief)
    }

    #[must_use]
    pub const fn entity_id(&self) -> EntityId {
        self.entity_id
    }

    #[must_use]
    pub fn predicate(&self) -> &str {
        &self.predicate
    }

    #[must_use]
    pub const fn confidence(&self) -> ConfidenceV1 {
        self.confidence
    }

    #[must_use]
    pub const fn provenance_digest(&self) -> Hash {
        self.provenance_digest
    }

    #[must_use]
    pub fn observation_record_digests(&self) -> &[Hash] {
        &self.observation_record_digests
    }

    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    fn binding_digest(&self) -> Result<Hash, AuthorityErrorV1> {
        let encoded = encode_value(&Value::Array(self.fields_without_digest()))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.BeliefRecord.v1\0");
        hasher.update(&encoded);
        Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
    }

    fn fields_without_digest(&self) -> Vec<Value> {
        vec![
            bytes(&entity_bytes(self.entity_id)),
            text(&self.predicate),
            uint(u64::from(self.confidence.millionths())),
            hash_value(self.provenance_digest),
            Value::Array(
                self.observation_record_digests
                    .iter()
                    .copied()
                    .map(hash_value)
                    .collect(),
            ),
        ]
    }

    fn value_with_digest(&self) -> Value {
        let mut fields = self.fields_without_digest();
        fields.push(hash_value(self.digest));
        Value::Array(fields)
    }

    fn canonical_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.entity_id
            .cmp(&other.entity_id)
            .then_with(|| self.predicate.cmp(&other.predicate))
            .then_with(|| self.provenance_digest.cmp(&other.provenance_digest))
    }
}

/// Unvalidated fields for one participant's non-authoritative knowledge snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnowledgeSnapshotDraftV1 {
    pub principal: PrincipalRefV1,
    pub participant_id: EntityId,
    pub timeline_id: TimelineId,
    pub observed_through: Seq,
    pub observation_snapshot_digest: Hash,
    pub observations: Vec<ObservationRecordV1>,
    pub beliefs: Vec<BeliefRecordV1>,
    pub preference_value_revision: Option<PreferenceValueRevisionV1>,
    pub ai_goal_policy_revision: Option<AiGoalPolicyRevisionV1>,
    pub memory_policy_revision: MemoryPolicyRevisionV1,
    pub prior_snapshot_digest: Option<Hash>,
    pub external_provenance: Vec<Hash>,
    pub provenance_digest: Hash,
}

/// Canonical KNS1 record of what one participant may know at one Timeline position.
///
/// This is epistemic evidence, never authoritative world state. It deliberately
/// cannot contain a Projection, `EventStore`, host handle, or action authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnowledgeSnapshotV1 {
    principal: PrincipalRefV1,
    participant_id: EntityId,
    timeline_id: TimelineId,
    observed_through: Seq,
    observation_snapshot_digest: Hash,
    observations: Vec<ObservationRecordV1>,
    beliefs: Vec<BeliefRecordV1>,
    preference_value_revision: Option<PreferenceValueRevisionV1>,
    ai_goal_policy_revision: Option<AiGoalPolicyRevisionV1>,
    memory_policy_revision: MemoryPolicyRevisionV1,
    prior_snapshot_digest: Option<Hash>,
    external_provenance: Vec<Hash>,
    provenance_digest: Hash,
    digest: Hash,
}

impl KnowledgeSnapshotV1 {
    /// Validate observation and belief provenance and calculate the KNS1 digest.
    ///
    /// # Errors
    /// Returns a closed validation or codec error for incomplete, unbounded, or
    /// noncanonical participant knowledge.
    pub fn try_from_draft(draft: KnowledgeSnapshotDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_entity_id(draft.participant_id)?;
        validate_timeline_id(draft.timeline_id)?;
        validate_hash(draft.observation_snapshot_digest)?;
        validate_hash(draft.provenance_digest)?;
        if let Some(digest) = draft.prior_snapshot_digest {
            validate_hash(digest)?;
        }
        if draft.observations.len().saturating_add(draft.beliefs.len())
            > MAX_KNOWLEDGE_SNAPSHOT_RECORDS
        {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        if let Some(first) = draft.observations.first() {
            validate_snapshot_records(
                draft.participant_id,
                first.minimization_revision(),
                &draft.observations,
            )?;
        }
        if draft
            .beliefs
            .windows(2)
            .any(|pair| pair[0].canonical_cmp(&pair[1]) != std::cmp::Ordering::Less)
        {
            return Err(AuthorityErrorV1::NonCanonicalOrder);
        }
        let observation_digests = draft
            .observations
            .iter()
            .map(ObservationRecordV1::digest)
            .collect::<Vec<_>>();
        if draft.beliefs.iter().any(|belief| {
            belief
                .observation_record_digests
                .iter()
                .any(|digest| !observation_digests.contains(digest))
        }) {
            return Err(AuthorityErrorV1::ProvenanceMissing);
        }
        validate_strict_hashes(&draft.external_provenance, MAX_KNOWLEDGE_SNAPSHOT_RECORDS)?;

        let mut snapshot = Self {
            principal: draft.principal,
            participant_id: draft.participant_id,
            timeline_id: draft.timeline_id,
            observed_through: draft.observed_through,
            observation_snapshot_digest: draft.observation_snapshot_digest,
            observations: draft.observations,
            beliefs: draft.beliefs,
            preference_value_revision: draft.preference_value_revision,
            ai_goal_policy_revision: draft.ai_goal_policy_revision,
            memory_policy_revision: draft.memory_policy_revision,
            prior_snapshot_digest: draft.prior_snapshot_digest,
            external_provenance: draft.external_provenance,
            provenance_digest: draft.provenance_digest,
            digest: Hash::zero(),
        };
        snapshot.digest = snapshot.binding_digest()?;
        if snapshot.encode()?.len() > MAX_KNOWLEDGE_SNAPSHOT_BYTES {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        Ok(snapshot)
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }

    #[must_use]
    pub const fn participant_id(&self) -> EntityId {
        self.participant_id
    }

    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn observed_through(&self) -> Seq {
        self.observed_through
    }

    #[must_use]
    pub const fn observation_snapshot_digest(&self) -> Hash {
        self.observation_snapshot_digest
    }

    #[must_use]
    pub fn observations(&self) -> &[ObservationRecordV1] {
        &self.observations
    }

    #[must_use]
    pub fn beliefs(&self) -> &[BeliefRecordV1] {
        &self.beliefs
    }

    #[must_use]
    pub const fn preference_value_revision(&self) -> Option<PreferenceValueRevisionV1> {
        self.preference_value_revision
    }

    #[must_use]
    pub const fn ai_goal_policy_revision(&self) -> Option<AiGoalPolicyRevisionV1> {
        self.ai_goal_policy_revision
    }

    #[must_use]
    pub const fn memory_policy_revision(&self) -> MemoryPolicyRevisionV1 {
        self.memory_policy_revision
    }

    #[must_use]
    pub const fn prior_snapshot_digest(&self) -> Option<Hash> {
        self.prior_snapshot_digest
    }

    #[must_use]
    pub fn external_provenance(&self) -> &[Hash] {
        &self.external_provenance
    }

    #[must_use]
    pub const fn provenance_digest(&self) -> Hash {
        self.provenance_digest
    }

    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    /// Encode the exact deterministic-CBOR KNS1 snapshot.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&self.value_with_digest()?).map(CanonicalBytes::from_vec)
    }

    /// Decode and validate one exact deterministic-CBOR KNS1 snapshot.
    ///
    /// # Errors
    /// Returns a closed codec, validation, or digest error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        let fields = decode_bounded_array(bytes.as_slice(), MAX_KNOWLEDGE_SNAPSHOT_BYTES, 16)?;
        expect_header(&fields, KNOWLEDGE_SNAPSHOT_MAGIC)?;
        let observations = decode_values(&fields[7])?
            .iter()
            .map(decode_observation_record)
            .collect::<Result<Vec<_>, _>>()?;
        let beliefs = decode_values(&fields[8])?
            .iter()
            .map(decode_belief)
            .collect::<Result<Vec<_>, _>>()?;
        let decoded_digest = decode_hash(&fields[15])?;
        let snapshot = Self::try_from_draft(KnowledgeSnapshotDraftV1 {
            principal: decode_principal_value(&fields[2])?,
            participant_id: decode_entity(&fields[3])?,
            timeline_id: decode_timeline(&fields[4])?,
            observed_through: Seq::from_u64(decode_u64(&fields[5])?),
            observation_snapshot_digest: decode_hash(&fields[6])?,
            observations,
            beliefs,
            preference_value_revision: decode_optional_preference_revision(&fields[9])?,
            ai_goal_policy_revision: decode_optional_ai_revision(&fields[10])?,
            memory_policy_revision: MemoryPolicyRevisionV1::try_new(decode_hash(&fields[11])?)?,
            prior_snapshot_digest: decode_optional_hash(&fields[12])?,
            external_provenance: decode_hash_array(&fields[13])?,
            provenance_digest: decode_hash(&fields[14])?,
        })?;
        if snapshot.digest == decoded_digest {
            Ok(snapshot)
        } else {
            Err(AuthorityErrorV1::DigestMismatch)
        }
    }

    fn binding_digest(&self) -> Result<Hash, AuthorityErrorV1> {
        let encoded = encode_value(&Value::Array(self.fields_without_digest()?))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.KnowledgeSnapshot.v1\0");
        hasher.update(&encoded);
        Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
    }

    fn fields_without_digest(&self) -> Result<Vec<Value>, AuthorityErrorV1> {
        let observations = self
            .observations
            .iter()
            .map(ObservationRecordV1::encode)
            .map(|result| result.map(|encoded| bytes(encoded.as_slice())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(vec![
            bytes(&KNOWLEDGE_SNAPSHOT_MAGIC),
            uint(VERSION),
            encode_principal(&self.principal),
            bytes(&entity_bytes(self.participant_id)),
            bytes(&timeline_bytes(self.timeline_id)),
            uint(self.observed_through.as_u64()),
            hash_value(self.observation_snapshot_digest),
            Value::Array(observations),
            Value::Array(
                self.beliefs
                    .iter()
                    .map(BeliefRecordV1::value_with_digest)
                    .collect(),
            ),
            optional_hash_value(
                self.preference_value_revision
                    .map(PreferenceValueRevisionV1::digest),
            ),
            optional_hash_value(
                self.ai_goal_policy_revision
                    .map(AiGoalPolicyRevisionV1::digest),
            ),
            hash_value(self.memory_policy_revision.digest()),
            optional_hash_value(self.prior_snapshot_digest),
            Value::Array(
                self.external_provenance
                    .iter()
                    .copied()
                    .map(hash_value)
                    .collect(),
            ),
            hash_value(self.provenance_digest),
        ])
    }

    fn value_with_digest(&self) -> Result<Value, AuthorityErrorV1> {
        let mut fields = self.fields_without_digest()?;
        fields.push(hash_value(self.digest));
        Ok(Value::Array(fields))
    }
}

fn validate_strict_hashes(values: &[Hash], max: usize) -> Result<(), AuthorityErrorV1> {
    if values.len() > max || values.iter().any(|value| *value == Hash::zero()) {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AuthorityErrorV1::NonCanonicalOrder);
    }
    Ok(())
}

fn decode_belief(value: &Value) -> Result<BeliefRecordV1, AuthorityErrorV1> {
    let fields = exact_array(value, 6)?;
    let confidence = u32::try_from(decode_u64(&fields[2])?)
        .map_err(|_| AuthorityErrorV1::FieldOutOfBounds)
        .and_then(ConfidenceV1::try_new)?;
    let decoded_digest = decode_hash(&fields[5])?;
    let belief = BeliefRecordV1::try_from_draft(BeliefRecordDraftV1 {
        entity_id: decode_entity(&fields[0])?,
        predicate: decode_text(&fields[1])?,
        confidence,
        provenance_digest: decode_hash(&fields[3])?,
        observation_record_digests: decode_hash_array(&fields[4])?,
    })?;
    if belief.digest == decoded_digest {
        Ok(belief)
    } else {
        Err(AuthorityErrorV1::DigestMismatch)
    }
}

fn decode_optional_preference_revision(
    value: &Value,
) -> Result<Option<PreferenceValueRevisionV1>, AuthorityErrorV1> {
    decode_optional_hash(value)?
        .map(PreferenceValueRevisionV1::try_new)
        .transpose()
}

fn decode_optional_ai_revision(
    value: &Value,
) -> Result<Option<AiGoalPolicyRevisionV1>, AuthorityErrorV1> {
    decode_optional_hash(value)?
        .map(AiGoalPolicyRevisionV1::try_new)
        .transpose()
}
