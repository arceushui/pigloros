//! Portable local-origin Fork attribution records from ADR-099.
//!
//! These codecs establish neither host admission nor publication authority.
//! In particular, a valid `FSM1` is only a mathematical signature until the
//! local publication authority has committed and read it.
//!
//! The ADR-105 `FAE1` authority-import envelope and its nested records live in
//! private submodules and are re-exported here. They carry the ADR-099
//! records as exact opaque bytes, so authority-origin code 2 stays fail
//! closed in every decoder in this module. Only the import-only typed decoders
//! of `authority_import` accept code 2, for the `FAE1` closure validator.

use crate::{Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1, PublicKey, Signature, TimelineId};

mod authority_admission;
mod authority_closure;
mod authority_envelope;
mod authority_evidence;
mod authority_import;
mod authority_issuer;
mod authority_wire;

pub use authority_admission::{
    ImportedForkAttributionAdmissionInputV1, ImportedForkAttributionAdmissionV1,
    MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1,
};
pub use authority_closure::{
    ForkAttributionImportClosureErrorV1, ForkAttributionImportClosureV1,
    ImportedForkClassifierGraphV1,
};
pub use authority_envelope::{
    fork_attribution_authority_origin_digest_v1, fork_attribution_closure_leaf_v1,
    ForkAttributionAuthorityEnvelopeInputV1, ForkAttributionAuthorityEnvelopeV1,
    ForkAttributionAuthorityRecordsV1, ForkAttributionAuthorityUnsignedEnvelopeV1,
    ForkAttributionClassifierRecordsV1, ForkAttributionClosureLeafTypeV1,
    MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1, MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
    MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1,
    MAX_FORK_ATTRIBUTION_AUTHORITY_PAYLOAD_BYTES_V1, MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1,
};
pub use authority_evidence::{
    ForkEventEvidenceV1, ForkTimelineImportInputV1, ForkTimelineImportV1, ImportedKeyRecordV1,
    ImportedKeyTombstoneV1, MAX_FORK_EVENT_EVIDENCE_BYTES_V1, MAX_FORK_TIMELINE_IMPORT_BYTES_V1,
    MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1, MAX_IMPORTED_KEY_RECORD_BYTES_V1,
    MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1,
};
pub use authority_import::{
    ImportedForkAdmissionRecordV1, ImportedForkPublicationOperationV1,
    ImportedPrincipalOwnerBindingV1,
};
pub use authority_issuer::{
    ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
    ForkAttributionIssuerPolicyV1, ForkAttributionIssuerStateV1, ForkAttributionIssuerV1,
    MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1, MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1,
    MAX_FORK_ATTRIBUTION_ISSUER_POLICY_BYTES_V1, MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1,
};

/// Maximum accepted `FAR1` bytes.
pub const MAX_FORK_ADMISSION_RECORD_BYTES_V1: usize = 768;
/// Maximum accepted `FRM1` bytes.
pub const MAX_FORK_REPRO_MANIFEST_BYTES_V1: usize = 16_384;
/// Maximum accepted `FSM1` bytes.
pub const MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1: usize = 16_640;
/// Maximum accepted `FPO1` bytes.
pub const MAX_FORK_PUBLICATION_OPERATION_BYTES_V1: usize = 1_024;
/// Maximum accepted `FPB1` bytes.
pub const MAX_FORK_PUBLICATION_BINDING_BYTES_V1: usize = 192;
/// Maximum accepted `FPA1` bytes.
pub const MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1: usize = 17_024;
/// Upper bound on the derived `FPR1` encoding produced by
/// [`ForkPublicationReceiptV1::to_canonical_cbor`].
///
/// `FPR1` is encode-only under ADR-099: no decoder accepts caller `FPR1` bytes,
/// so this bounds derived output rather than gating decoder input.
pub const MAX_FORK_PUBLICATION_RECEIPT_BYTES_V1: usize = 192;
/// Maximum intervention coordinates in one `FRM1`.
pub const MAX_FORK_MANIFEST_INTERVENTIONS_V1: usize = 1_024;

const ADMISSION_DOMAIN: &[u8] = b"pigloros/fork-admission/v1";
const RECORD_DOMAIN: &[u8] = b"pigloros/fork-signed-manifest/v1";

/// Closed errors for the portable attribution codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAttributionCodecErrorV1 {
    #[error("invalid Fork attribution encoding")]
    InvalidEncoding,
    #[error("noncanonical Fork attribution encoding")]
    NonCanonical,
    #[error("unsupported Fork attribution version")]
    UnsupportedVersion,
    #[error("Fork attribution field is out of bounds")]
    FieldOutOfBounds,
    #[error("Fork attribution origin is unavailable")]
    ImportedAuthorityUnavailable,
    #[error("Fork attribution fields do not agree")]
    FieldMismatch,
    #[error("Fork intervention coordinates are not strictly increasing")]
    InterventionOrder,
}

/// The only currently usable authority origin.
///
/// The reserved wire code 2 is rejected until #447 installs its authenticated
/// atomic import boundary; it has no public value variant here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAttributionOriginV1 {
    /// Locally committed authority bytes.
    Local,
}

/// Construction fields for one portable local `FAR1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecordInputV1 {
    pub operation_id: Hash,
    pub principal_owner_binding_digest: Hash,
    pub creator: OwnerIdV1,
    pub parent_timeline_id: TimelineId,
    pub child_timeline_id: TimelineId,
    pub room_revision_descriptor_hash: Hash,
    pub parent_logical_head: u64,
    pub parent_chain_head_hash: Hash,
    pub completed_fold_cursor: u64,
    pub post_fold_tick_boundary: u64,
    pub plugin_composition_hash: Hash,
    pub attribution_required: bool,
    pub origin: ForkAttributionOriginV1,
}

impl ForkAdmissionRecordInputV1 {
    const fn cut_coordinates(&self) -> CutCoordinatesV1 {
        CutCoordinatesV1 {
            parent_timeline_id: self.parent_timeline_id,
            fork_timeline_id: self.child_timeline_id,
            room_revision_descriptor_hash: self.room_revision_descriptor_hash,
            parent_logical_head: self.parent_logical_head,
            parent_chain_head_hash: self.parent_chain_head_hash,
            post_fold_tick_boundary: self.post_fold_tick_boundary,
            plugin_composition_hash: self.plugin_composition_hash,
        }
    }
}

/// Fork cut coordinates duplicated from `FAR1` into `FRM1`.
///
/// This private projection keeps the copy in `from_admission` and the
/// comparison in `validate_against_admission` over one field list. It is not a
/// wire type; both records keep their own ADR-099 field order.
#[derive(Eq, PartialEq)]
struct CutCoordinatesV1 {
    parent_timeline_id: TimelineId,
    fork_timeline_id: TimelineId,
    room_revision_descriptor_hash: Hash,
    parent_logical_head: u64,
    parent_chain_head_hash: Hash,
    post_fold_tick_boundary: u64,
    plugin_composition_hash: Hash,
}

/// Strict portable `FAR1` bytes. This value does not prove host admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecordV1(ForkAdmissionRecordInputV1);

impl ForkAdmissionRecordV1 {
    /// Validate the local structural and duplicated-cut invariants.
    ///
    /// # Errors
    /// Rejects zero required identifiers, duplicate Timeline IDs, or inconsistent cut coordinates.
    pub fn new(input: ForkAdmissionRecordInputV1) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.operation_id == Hash::zero()
            || input.principal_owner_binding_digest == Hash::zero()
            || input.room_revision_descriptor_hash == Hash::zero()
            || input.plugin_composition_hash == Hash::zero()
            || input.parent_timeline_id == input.child_timeline_id
            || input.completed_fold_cursor != input.parent_logical_head
            || input.post_fold_tick_boundary != input.parent_logical_head
        {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkAdmissionRecordInputV1 {
        &self.0
    }

    /// Encode the exact 15-field deterministic-CBOR `FAR1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(320);
        array(&mut out, 15);
        text(&mut out, "FAR1");
        uint(&mut out, 1);
        hash(&mut out, value.operation_id);
        hash(&mut out, value.principal_owner_binding_digest);
        text(&mut out, value.creator.as_str());
        timeline(&mut out, value.parent_timeline_id);
        timeline(&mut out, value.child_timeline_id);
        hash(&mut out, value.room_revision_descriptor_hash);
        uint(&mut out, value.parent_logical_head);
        hash(&mut out, value.parent_chain_head_hash);
        uint(&mut out, value.completed_fold_cursor);
        uint(&mut out, value.post_fold_tick_boundary);
        hash(&mut out, value.plugin_composition_hash);
        uint(&mut out, u64::from(value.attribution_required));
        authority_origin(&mut out, value.origin);
        out
    }

    /// Return the domain-separated digest over complete canonical `FAR1` bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(ADMISSION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode only exact canonical local-origin `FAR1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, noncanonical, or imported-origin bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_ADMISSION_RECORD_BYTES_V1)?;
        wire.array(15)?;
        wire.magic("FAR1")?;
        wire.version()?;
        let operation_id = wire.hash()?;
        let principal_owner_binding_digest = wire.hash()?;
        let creator = wire.owner()?;
        let parent_timeline_id = wire.timeline()?;
        let child_timeline_id = wire.timeline()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let parent_logical_head = wire.uint()?;
        let parent_chain_head_hash = wire.hash()?;
        let completed_fold_cursor = wire.uint()?;
        let post_fold_tick_boundary = wire.uint()?;
        let plugin_composition_hash = wire.hash()?;
        let attribution_required = wire.bool()?;
        let origin = wire.authority_origin()?;
        wire.finish()?;
        let record = Self::new(ForkAdmissionRecordInputV1 {
            operation_id,
            principal_owner_binding_digest,
            creator,
            parent_timeline_id,
            child_timeline_id,
            room_revision_descriptor_hash,
            parent_logical_head,
            parent_chain_head_hash,
            completed_fold_cursor,
            post_fold_tick_boundary,
            plugin_composition_hash,
            attribution_required,
            origin,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for one portable `FRM1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkReproManifestInputV1 {
    pub parent_timeline_id: TimelineId,
    pub fork_timeline_id: TimelineId,
    pub admission_digest: Hash,
    pub room_revision_descriptor_hash: Hash,
    pub parent_logical_head: u64,
    pub parent_chain_head_hash: Hash,
    pub post_fold_tick_boundary: u64,
    pub plugin_composition_hash: Hash,
    pub intervention_sequences: Vec<u64>,
    pub final_fork_logical_head: u64,
    pub final_fork_chain_head_hash: Hash,
}

impl ForkReproManifestInputV1 {
    const fn cut_coordinates(&self) -> CutCoordinatesV1 {
        CutCoordinatesV1 {
            parent_timeline_id: self.parent_timeline_id,
            fork_timeline_id: self.fork_timeline_id,
            room_revision_descriptor_hash: self.room_revision_descriptor_hash,
            parent_logical_head: self.parent_logical_head,
            parent_chain_head_hash: self.parent_chain_head_hash,
            post_fold_tick_boundary: self.post_fold_tick_boundary,
            plugin_composition_hash: self.plugin_composition_hash,
        }
    }
}

/// Strict portable `FRM1` bytes, without publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkReproManifestV1(ForkReproManifestInputV1);

impl ForkReproManifestV1 {
    /// Construct `FRM1` from the duplicated coordinates in local `FAR1`.
    ///
    /// This constructor establishes only byte agreement with supplied local
    /// admission data. It does not establish that the supplied `FAR1` was
    /// durably committed or authorized for publication.
    ///
    /// # Errors
    ///
    /// Rejects invalid final Fork coordinates or intervention sequences.
    pub fn from_admission(
        admission: &ForkAdmissionRecordV1,
        intervention_sequences: Vec<u64>,
        final_fork_logical_head: u64,
        final_fork_chain_head_hash: Hash,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        let CutCoordinatesV1 {
            parent_timeline_id,
            fork_timeline_id,
            room_revision_descriptor_hash,
            parent_logical_head,
            parent_chain_head_hash,
            post_fold_tick_boundary,
            plugin_composition_hash,
        } = admission.input().cut_coordinates();
        Self::new(ForkReproManifestInputV1 {
            parent_timeline_id,
            fork_timeline_id,
            admission_digest: admission.digest(),
            room_revision_descriptor_hash,
            parent_logical_head,
            parent_chain_head_hash,
            post_fold_tick_boundary,
            plugin_composition_hash,
            intervention_sequences,
            final_fork_logical_head,
            final_fork_chain_head_hash,
        })
    }

    /// Validate exact structural coordinate bounds.
    ///
    /// # Errors
    /// Rejects invalid coordinates, a post-fold Tick Boundary unequal to the
    /// parent cut, or intervention ordering and bounds.
    pub fn new(input: ForkReproManifestInputV1) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.parent_timeline_id == input.fork_timeline_id
            || input.post_fold_tick_boundary != input.parent_logical_head
            || input.admission_digest == Hash::zero()
            || input.room_revision_descriptor_hash == Hash::zero()
            || input.plugin_composition_hash == Hash::zero()
            || input.final_fork_logical_head < input.parent_logical_head
            || input.intervention_sequences.len() > MAX_FORK_MANIFEST_INTERVENTIONS_V1
        {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        if input
            .intervention_sequences
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ForkAttributionCodecErrorV1::InterventionOrder);
        }
        if input.intervention_sequences.iter().any(|sequence| {
            *sequence <= input.parent_logical_head || *sequence > input.final_fork_logical_head
        }) {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkReproManifestInputV1 {
        &self.0
    }

    /// Require every duplicated provenance coordinate to equal local `FAR1`.
    ///
    /// # Errors
    /// Rejects any mismatch between the manifest and admission authority.
    pub fn validate_against_admission(
        &self,
        admission: &ForkAdmissionRecordV1,
    ) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.0.admission_digest != admission.digest()
            || self.0.cut_coordinates() != admission.input().cut_coordinates()
        {
            return Err(ForkAttributionCodecErrorV1::FieldMismatch);
        }
        Ok(())
    }

    /// Encode exact deterministic-CBOR `FRM1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(512 + value.intervention_sequences.len() * 9);
        array(&mut out, 13);
        text(&mut out, "FRM1");
        uint(&mut out, 1);
        timeline(&mut out, value.parent_timeline_id);
        timeline(&mut out, value.fork_timeline_id);
        hash(&mut out, value.admission_digest);
        hash(&mut out, value.room_revision_descriptor_hash);
        uint(&mut out, value.parent_logical_head);
        hash(&mut out, value.parent_chain_head_hash);
        uint(&mut out, value.post_fold_tick_boundary);
        hash(&mut out, value.plugin_composition_hash);
        array(&mut out, value.intervention_sequences.len() as u64);
        for sequence in &value.intervention_sequences {
            uint(&mut out, *sequence);
        }
        uint(&mut out, value.final_fork_logical_head);
        hash(&mut out, value.final_fork_chain_head_hash);
        out
    }

    /// Decode exact canonical `FRM1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, or noncanonical manifest bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_REPRO_MANIFEST_BYTES_V1)?;
        wire.array(13)?;
        wire.magic("FRM1")?;
        wire.version()?;
        let parent_timeline_id = wire.timeline()?;
        let fork_timeline_id = wire.timeline()?;
        let admission_digest = wire.hash()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let parent_logical_head = wire.uint()?;
        let parent_chain_head_hash = wire.hash()?;
        let post_fold_tick_boundary = wire.uint()?;
        let plugin_composition_hash = wire.hash()?;
        let count = wire.array_len()?;
        if count > MAX_FORK_MANIFEST_INTERVENTIONS_V1 {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        let mut intervention_sequences = Vec::with_capacity(count);
        for _ in 0..count {
            intervention_sequences.push(wire.uint()?);
        }
        let final_fork_logical_head = wire.uint()?;
        let final_fork_chain_head_hash = wire.hash()?;
        wire.finish()?;
        let record = Self::new(ForkReproManifestInputV1 {
            parent_timeline_id,
            fork_timeline_id,
            admission_digest,
            room_revision_descriptor_hash,
            parent_logical_head,
            parent_chain_head_hash,
            post_fold_tick_boundary,
            plugin_composition_hash,
            intervention_sequences,
            final_fork_logical_head,
            final_fork_chain_head_hash,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Strict portable `FSM1` wrapper. It remains a signature-only value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedForkReproManifestV1 {
    identity: KeyIdentityV1,
    manifest: ForkReproManifestV1,
    signature: Signature,
}

impl SignedForkReproManifestV1 {
    /// Construct a signature-only wrapper bound to supplied local `FAR1`.
    ///
    /// The creator is derived from `FAR1`, and the `FRM1` duplicated fields
    /// must agree with it. This does not treat caller-supplied `FAR1` as
    /// trusted admission or publication authority.
    ///
    /// # Errors
    ///
    /// Rejects a zero epoch or any creator or manifest mismatch.
    pub fn new_from_admission(
        admission: &ForkAdmissionRecordV1,
        epoch: u64,
        manifest: ForkReproManifestV1,
        signature: Signature,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        Self::new(
            KeyIdentityV1::from_parts(
                admission.input().creator,
                KeyRoleV1::SubjectAttributionSigning,
                epoch,
            ),
            manifest,
            signature,
        )
        .and_then(|record| {
            record
                .validate_against_admission(admission)
                .map(|()| record)
        })
    }

    /// Require the wrapper creator and manifest fields to agree with local `FAR1`.
    ///
    /// # Errors
    ///
    /// Rejects a different creator or any mismatched duplicated manifest field.
    pub fn validate_against_admission(
        &self,
        admission: &ForkAdmissionRecordV1,
    ) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.identity.owner_id != admission.input().creator {
            return Err(ForkAttributionCodecErrorV1::FieldMismatch);
        }
        self.manifest.validate_against_admission(admission)
    }

    /// Construct a signature-only wrapper for the exact inner canonical bytes.
    ///
    /// # Errors
    /// Rejects an identity without the attribution-signing role or positive epoch.
    pub fn new(
        identity: KeyIdentityV1,
        manifest: ForkReproManifestV1,
        signature: Signature,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        if identity.role != KeyRoleV1::SubjectAttributionSigning || identity.epoch == 0 {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self {
            identity,
            manifest,
            signature,
        })
    }
    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }
    #[must_use]
    pub const fn manifest(&self) -> &ForkReproManifestV1 {
        &self.manifest
    }
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
    /// Replace only the mathematical signature, keeping the identity and inner
    /// manifest unchanged. The new signature is not verified here, and this
    /// grants neither admission nor publication authority.
    #[must_use]
    pub const fn with_signature(mut self, signature: Signature) -> Self {
        self.signature = signature;
        self
    }
    /// Return canonical inner `FRM1` bytes used by ADR-065 role signing.
    #[must_use]
    pub fn manifest_bytes(&self) -> Vec<u8> {
        self.manifest.to_canonical_cbor()
    }
    /// Encode exact deterministic-CBOR `FSM1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let inner = self.manifest_bytes();
        let mut out = Vec::with_capacity(inner.len() + 192);
        array(&mut out, 7);
        text(&mut out, "FSM1");
        uint(&mut out, 1);
        text(&mut out, self.identity.owner_id.as_str());
        uint(&mut out, u64::from(self.identity.role.code()));
        uint(&mut out, self.identity.epoch);
        bytes(&mut out, &inner);
        bytes(&mut out, self.signature.as_bytes());
        out
    }
    /// Return the ADR-099 record identifier over complete `FSM1` bytes.
    #[must_use]
    pub fn record_id(&self) -> Hash {
        domain_digest(RECORD_DOMAIN, &self.to_canonical_cbor())
    }
    /// Decode exact canonical `FSM1` bytes; this does not verify the signature.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, or noncanonical signed-record bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1)?;
        wire.array(7)?;
        wire.magic("FSM1")?;
        wire.version()?;
        let owner = wire.owner()?;
        let role = KeyRoleV1::from_code(
            u8::try_from(wire.uint()?).map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?,
        )
        .map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?;
        let epoch = wire.uint()?;
        let inner = wire.bytes(MAX_FORK_REPRO_MANIFEST_BYTES_V1)?;
        let signature = Signature::from_bytes(wire.fixed::<64>()?);
        wire.finish()?;
        let manifest = ForkReproManifestV1::from_canonical_cbor(inner)?;
        let record = Self::new(
            KeyIdentityV1::from_parts(owner, role, epoch),
            manifest,
            signature,
        )?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for a local `FPO1` publication-operation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkPublicationOperationInputV1 {
    pub operation_id: Hash,
    pub child_timeline_id: TimelineId,
    pub final_logical_head: u64,
    pub final_chain_head_hash: Hash,
    pub admission_digest: Hash,
    pub signing_identity: KeyIdentityV1,
    pub private_material_digest: Hash,
    pub public_verification_key: PublicKey,
    pub signed_manifest_record_id: Hash,
    pub origin: ForkAttributionOriginV1,
}

/// Strict portable `FPO1` bytes. This value does not prove authorized issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkPublicationOperationV1(ForkPublicationOperationInputV1);

impl ForkPublicationOperationV1 {
    /// Construct a local publication-operation projection with a role-bound signer.
    ///
    /// The final chain head hash may be the zero genesis hash of an empty
    /// Fork, exactly as `FAR1` and `FRM1` permit for an empty parent cut.
    ///
    /// # Errors
    /// Returns an error when required publication fields or the signing identity are invalid.
    pub fn new(
        input: ForkPublicationOperationInputV1,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.operation_id == Hash::zero()
            || input.admission_digest == Hash::zero()
            || input.private_material_digest == Hash::zero()
            || input.signed_manifest_record_id == Hash::zero()
            || input.signing_identity.role != KeyRoleV1::SubjectAttributionSigning
            || input.signing_identity.epoch == 0
        {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkPublicationOperationInputV1 {
        &self.0
    }

    /// Encode the exact 14-field deterministic-CBOR `FPO1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(512);
        array(&mut out, 14);
        text(&mut out, "FPO1");
        uint(&mut out, 1);
        hash(&mut out, value.operation_id);
        timeline(&mut out, value.child_timeline_id);
        uint(&mut out, value.final_logical_head);
        hash(&mut out, value.final_chain_head_hash);
        hash(&mut out, value.admission_digest);
        text(&mut out, value.signing_identity.owner_id.as_str());
        uint(&mut out, u64::from(value.signing_identity.role.code()));
        uint(&mut out, value.signing_identity.epoch);
        hash(&mut out, value.private_material_digest);
        bytes(&mut out, value.public_verification_key.as_bytes());
        hash(&mut out, value.signed_manifest_record_id);
        authority_origin(&mut out, value.origin);
        out
    }

    /// Decode only exact canonical local-origin `FPO1` bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, out of bounds, or imported.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_PUBLICATION_OPERATION_BYTES_V1)?;
        wire.array(14)?;
        wire.magic("FPO1")?;
        wire.version()?;
        let operation_id = wire.hash()?;
        let child_timeline_id = wire.timeline()?;
        let final_logical_head = wire.uint()?;
        let final_chain_head_hash = wire.hash()?;
        let admission_digest = wire.hash()?;
        let owner_id = wire.owner()?;
        let role = KeyRoleV1::from_code(
            u8::try_from(wire.uint()?).map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?,
        )
        .map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?;
        let epoch = wire.uint()?;
        let private_material_digest = wire.hash()?;
        let public_verification_key = PublicKey::from_bytes(wire.fixed()?);
        let signed_manifest_record_id = wire.hash()?;
        let origin = wire.authority_origin()?;
        wire.finish()?;
        let record = Self::new(ForkPublicationOperationInputV1 {
            operation_id,
            child_timeline_id,
            final_logical_head,
            final_chain_head_hash,
            admission_digest,
            signing_identity: KeyIdentityV1::from_parts(owner_id, role, epoch),
            private_material_digest,
            public_verification_key,
            signed_manifest_record_id,
            origin,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for a portable `FPB1` publication binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkPublicationBindingInputV1 {
    pub child_timeline_id: TimelineId,
    pub final_logical_head: u64,
    pub operation_id: Hash,
    pub signed_manifest_record_id: Hash,
}

/// Strict portable `FPB1` bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkPublicationBindingV1(ForkPublicationBindingInputV1);

impl ForkPublicationBindingV1 {
    /// Construct one nonzero publication binding.
    ///
    /// # Errors
    /// Returns an error when an operation or signed-manifest record ID is zero.
    pub fn new(input: ForkPublicationBindingInputV1) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.operation_id == Hash::zero() || input.signed_manifest_record_id == Hash::zero() {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkPublicationBindingInputV1 {
        &self.0
    }

    /// Encode the exact six-field deterministic-CBOR `FPB1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(128);
        array(&mut out, 6);
        text(&mut out, "FPB1");
        uint(&mut out, 1);
        timeline(&mut out, value.child_timeline_id);
        uint(&mut out, value.final_logical_head);
        hash(&mut out, value.operation_id);
        hash(&mut out, value.signed_manifest_record_id);
        out
    }

    /// Decode exact canonical `FPB1` bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, or out of bounds.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_PUBLICATION_BINDING_BYTES_V1)?;
        wire.array(6)?;
        wire.magic("FPB1")?;
        wire.version()?;
        let record = Self::new(ForkPublicationBindingInputV1 {
            child_timeline_id: wire.timeline()?,
            final_logical_head: wire.uint()?,
            operation_id: wire.hash()?,
            signed_manifest_record_id: wire.hash()?,
        })?;
        wire.finish()?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for a portable `FPA1` publication artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkPublicationArtifactInputV1 {
    pub signed_manifest_record_id: Hash,
    pub operation_id: Hash,
    pub signed_manifest_bytes: Vec<u8>,
}

/// Strict portable `FPA1` bytes carrying the sole complete `FSM1` copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkPublicationArtifactV1 {
    input: ForkPublicationArtifactInputV1,
    signed_manifest: SignedForkReproManifestV1,
}

impl ForkPublicationArtifactV1 {
    /// Construct an artifact only when its exact nested `FSM1` identifier agrees.
    ///
    /// # Errors
    /// Returns an error when identifiers are zero, nested bytes are invalid, or IDs disagree.
    pub fn new(input: ForkPublicationArtifactInputV1) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.signed_manifest_record_id == Hash::zero() || input.operation_id == Hash::zero() {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        let signed_manifest =
            SignedForkReproManifestV1::from_canonical_cbor(&input.signed_manifest_bytes)?;
        if signed_manifest.record_id() != input.signed_manifest_record_id {
            return Err(ForkAttributionCodecErrorV1::FieldMismatch);
        }
        Ok(Self {
            input,
            signed_manifest,
        })
    }

    #[must_use]
    pub const fn input(&self) -> &ForkPublicationArtifactInputV1 {
        &self.input
    }

    /// Return the exact nested `FSM1`, decoded once by [`Self::new`].
    ///
    /// Its signature is not verified here.
    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedForkReproManifestV1 {
        &self.signed_manifest
    }

    /// Encode the exact five-field deterministic-CBOR `FPA1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.input;
        let mut out = Vec::with_capacity(value.signed_manifest_bytes.len() + 96);
        array(&mut out, 5);
        text(&mut out, "FPA1");
        uint(&mut out, 1);
        hash(&mut out, value.signed_manifest_record_id);
        hash(&mut out, value.operation_id);
        bytes(&mut out, &value.signed_manifest_bytes);
        out
    }

    /// Decode exact canonical `FPA1` bytes and its nested `FSM1` bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, out of bounds, or inconsistent.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1)?;
        wire.array(5)?;
        wire.magic("FPA1")?;
        wire.version()?;
        let record = Self::new(ForkPublicationArtifactInputV1 {
            signed_manifest_record_id: wire.hash()?,
            operation_id: wire.hash()?,
            signed_manifest_bytes: wire
                .bytes(MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1)?
                .to_vec(),
        })?;
        wire.finish()?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Derived receipt fields returned only after a complete publication commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkPublicationReceiptV1 {
    pub operation_id: Hash,
    pub child_timeline_id: TimelineId,
    pub final_logical_head: u64,
    pub signed_manifest_record_id: Hash,
}

impl ForkPublicationReceiptV1 {
    /// Derive a receipt from matching committed operation and binding records.
    ///
    /// # Errors
    /// Returns an error when the duplicated operation, Fork, head, or record ID differs.
    pub fn from_records(
        operation: &ForkPublicationOperationV1,
        binding: &ForkPublicationBindingV1,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        let value = operation.input();
        let bound = binding.input();
        if value.operation_id != bound.operation_id
            || value.child_timeline_id != bound.child_timeline_id
            || value.final_logical_head != bound.final_logical_head
            || value.signed_manifest_record_id != bound.signed_manifest_record_id
        {
            return Err(ForkAttributionCodecErrorV1::FieldMismatch);
        }
        Ok(Self {
            operation_id: value.operation_id,
            child_timeline_id: value.child_timeline_id,
            final_logical_head: value.final_logical_head,
            signed_manifest_record_id: value.signed_manifest_record_id,
        })
    }

    /// Encode the exact six-field deterministic-CBOR derived `FPR1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        array(&mut out, 6);
        text(&mut out, "FPR1");
        uint(&mut out, 1);
        hash(&mut out, self.operation_id);
        timeline(&mut out, self.child_timeline_id);
        uint(&mut out, self.final_logical_head);
        hash(&mut out, self.signed_manifest_record_id);
        out
    }
}

fn domain_digest(domain: &[u8], bytes_in: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes_in);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
fn hash(out: &mut Vec<u8>, value: Hash) {
    bytes(out, value.as_bytes());
}
fn timeline(out: &mut Vec<u8>, value: TimelineId) {
    bytes(out, &value.inner().to_bytes());
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// Encode ADR-099 `authority-origin-v1`; only the local `[1]` form exists in V1.
fn authority_origin(out: &mut Vec<u8>, origin: ForkAttributionOriginV1) {
    match origin {
        ForkAttributionOriginV1::Local => {
            array(out, 1);
            uint(out, 1);
        }
    }
}

fn array(out: &mut Vec<u8>, value: u64) {
    head(out, 4, value);
}
fn uint(out: &mut Vec<u8>, value: u64) {
    head(out, 0, value);
}
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    if value < 24 {
        out.push(tag | value.to_be_bytes()[7]);
    } else if let Ok(value) = u8::try_from(value) {
        out.extend_from_slice(&[tag | 0x18, value]);
    } else if let Ok(value) = u16::try_from(value) {
        out.push(tag | 0x19);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(tag | 0x1a);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(tag | 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}
fn canonical(actual: &[u8], expected: &[u8]) -> Result<(), ForkAttributionCodecErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, ForkAttributionCodecErrorV1> {
        if bytes.len() > maximum {
            Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self { bytes, offset: 0 })
        }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ForkAttributionCodecErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ForkAttributionCodecErrorV1::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ForkAttributionCodecErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
    fn head(&mut self, major: u8) -> Result<u64, ForkAttributionCodecErrorV1> {
        let first = self.take(1)?[0];
        if first >> 5 != major {
            return Err(ForkAttributionCodecErrorV1::InvalidEncoding);
        }
        let additional = first & 31;
        let width = match additional {
            0..=23 => return Ok(u64::from(additional)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(ForkAttributionCodecErrorV1::InvalidEncoding),
        };
        let mut value = 0;
        for byte in self.take(width)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }
    fn array(&mut self, expected: u64) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.head(4)? == expected {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        }
    }
    /// Decode ADR-099 `authority-origin-v1 = [1] / [2, bstr .size 32]` as the
    /// final record field. A well-formed import origin stays unavailable until
    /// #447 installs its authenticated import boundary.
    fn authority_origin(&mut self) -> Result<ForkAttributionOriginV1, ForkAttributionCodecErrorV1> {
        match (self.head(4)?, self.uint()?) {
            (1, 1) => Ok(ForkAttributionOriginV1::Local),
            (2, 2) => self.fixed::<32>().and_then(|_| self.finish()).and(Err(
                ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable,
            )),
            _ => Err(ForkAttributionCodecErrorV1::InvalidEncoding),
        }
    }
    fn array_len(&mut self) -> Result<usize, ForkAttributionCodecErrorV1> {
        usize::try_from(self.head(4)?).map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)
    }
    fn uint(&mut self) -> Result<u64, ForkAttributionCodecErrorV1> {
        self.head(0)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ForkAttributionCodecErrorV1> {
        if self.head(2)? != N as u64 {
            return Err(ForkAttributionCodecErrorV1::InvalidEncoding);
        }
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], ForkAttributionCodecErrorV1> {
        let length = usize::try_from(self.head(2)?)
            .map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)?;
        if length > maximum {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        self.take(length)
    }
    /// Read a 1..=128-byte owner, leaving emptiness to `OwnerIdV1` itself.
    fn owner(&mut self) -> Result<OwnerIdV1, ForkAttributionCodecErrorV1> {
        // A length that does not fit `usize` is necessarily over the bound.
        let length = usize::try_from(self.head(3)?).unwrap_or(usize::MAX);
        if length > 128 {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?;
        OwnerIdV1::new(value).map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)
    }
    fn hash(&mut self) -> Result<Hash, ForkAttributionCodecErrorV1> {
        Ok(Hash::from_bytes(self.fixed()?))
    }
    fn timeline(&mut self) -> Result<TimelineId, ForkAttributionCodecErrorV1> {
        Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
    }
    fn bool(&mut self) -> Result<bool, ForkAttributionCodecErrorV1> {
        match self.uint()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ForkAttributionCodecErrorV1::InvalidEncoding),
        }
    }
    /// Read the raw bytes of one text string.
    fn text_bytes(&mut self) -> Result<&'a [u8], ForkAttributionCodecErrorV1> {
        // A length that does not fit `usize` is necessarily unavailable to `take`.
        let length = usize::try_from(self.head(3)?).unwrap_or(usize::MAX);
        self.take(length)
    }
    /// Compare a text-string marker byte-for-byte; any other length or
    /// content is an invalid encoding.
    fn magic(&mut self, expected: &str) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.text_bytes()? == expected.as_bytes() {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        }
    }
    fn version(&mut self) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.uint()? == 1 {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::UnsupportedVersion)
        }
    }
    const fn finish(&self) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        }
    }
}
