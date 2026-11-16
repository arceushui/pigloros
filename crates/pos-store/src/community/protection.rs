//! ADR-128 artifact protection for one scope cohort (ADR-129 §3 "Per-scope
//! protection control operations"; ADR-128 §2–§3).
//!
//! A [`CommunityArtifactProtectorV1`] is one `ProtectArtifacts` control
//! suboperation: a fresh nonzero protection ID, its CKP1 key intent with
//! freshly generated material, and the CCI1 key-vault copy descriptor of that
//! material. Every record it protects is sealed in the ADR-128 order:
//!
//! 1. the record's COE1, under a COH1 whose operation is the protection
//!    control ID and whose scope cover is the caller's CSB1 commitment;
//! 2. its CAR1 classification proof, encrypted as a kind-8 COE1 with the
//!    same key and context and a fresh nonce;
//! 3. the COW1 holding both envelopes;
//! 4. the exact ARD1 fields of that COW1, derived but not published.
//!
//! The caller supplies the COB1 owner-binding, CSB1 scope-cover and CPV1
//! provenance commitments, which its own evidence records fix before
//! encryption, and later the CAU1 digest for the COA1. Nothing here publishes
//! a registration, commits an object or grants any read: the community
//! extractor and the atomic commit do that (#560 A3c-2b′/2c).

use pos_core::community_lifecycle::{
    community_catalogue_owner_reference_v1, CommunityArtifactAdmissionInputV1,
    CommunityArtifactAdmissionV1, CommunityArtifactChildrenV1, CommunityArtifactHeaderInputV1,
    CommunityArtifactHeaderV1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityClassificationProofInputV1,
    CommunityClassificationProofV1, CommunityCopyHolderV1, CommunityCopyInventoryInputV1,
    CommunityCopyInventoryV1, CommunityCopyStateV1, CommunityEncryptedEnvelopeV1,
    CommunityKeyIntentInputV1, CommunityKeyIntentV1, CommunityLifecycleErrorV1 as Error,
    CommunityMemberSlotsV1, CommunityProtectedObjectV1, CommunityRecordKindsV1,
    MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationFieldsV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    AuthorityTrustRootSealV1, ErasureArtifactClassV1, Hash, KeyIdentityV1, KeyRoleV1, TimelineId,
    MAX_ARTIFACT_REGISTRATION_CHILDREN_V1,
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use super::private_hash::plaintext_commitment;
use super::vault::{fresh_identity, VaultKeyV1};

/// One prepared scope cohort: the parent operation, key partition, actual
/// scope set and horizon a `ProtectArtifacts` suboperation protects.
#[derive(Clone, Copy)]
pub struct CommunityProtectionCohortV1 {
    /// Original pass, initialization or control parent.
    pub parent_operation: CommunityArtifactOperationV1,
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// Key purpose partition.
    pub purpose: CommunityArtifactPurposeV1,
    /// `H("ScopeSet", rows)` of the cohort's exact scope members.
    pub scope_set_digest: Hash,
    /// The CSB1 `ScopeCover` commitment every COH1 of the cohort carries.
    pub scope_cover_digest: Hash,
    /// Original finite horizon.
    pub evidence_not_after_micros: u64,
    /// Record kinds the key may protect; must include `ClassificationProof`
    /// for the CAR1 envelopes.
    pub allowed_record_kinds: CommunityRecordKindsV1,
    /// Admitted roster slots the key may protect.
    pub member_slots: CommunityMemberSlotsV1,
    /// Exact current-authority request digest that admitted the intent.
    pub authority_request_digest: Hash,
}

/// The caller's evidence commitments for one protected record.
#[derive(Clone, Copy)]
pub struct CommunityRecordEvidenceV1<'a> {
    /// The COB1 owner-binding commitment.
    pub owner_binding_digest: Hash,
    /// The CPV1 original-provenance commitment.
    pub host_provenance_digest: Hash,
    /// The record's direct ARD1 children, as its native extractor derives
    /// them, in strict `(class, digest, address)` order.
    pub children: &'a [ArtifactChildEdgeV1],
}

/// One `ProtectArtifacts` suboperation: its key and copy descriptor.
///
/// It has no material getter and no decryption API.
pub struct CommunityArtifactProtectorV1 {
    cohort: CommunityProtectionCohortV1,
    protection_id: [u8; 16],
    key: VaultKeyV1,
    copy: CommunityCopyInventoryV1,
}

impl CommunityArtifactProtectorV1 {
    /// Allocate fresh protection and copy IDs and key material.
    ///
    /// The material's fingerprint is bound into the CKP1 intent, and the
    /// key-vault copy is described as CCI1 revision 1, `KeyVault`, `Owned`,
    /// with the cohort horizon as deadline.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], provisions a protector:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{CommunityArtifactProtectorV1, CommunityProtectionCohortV1};
    /// fn forge(cohort: CommunityProtectionCohortV1) {
    ///     let _ = CommunityArtifactProtectorV1::provision(cohort);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `StorageUnavailable` when the OS CSPRNG fails, and the CKP1 or
    /// CCI1 refusal (`InvalidBinding`, `BoundsExceeded`) for an invalid
    /// cohort.
    pub fn provision(
        _seal: &'static AuthorityTrustRootSealV1,
        cohort: CommunityProtectionCohortV1,
    ) -> Result<Self, Error> {
        fresh_identity().and_then(|protection_id| {
            fresh_identity().and_then(|copy_id| {
                VaultKeyV1::provision(CommunityKeyIntentInputV1 {
                    protection_operation_id: protection_id,
                    parent_operation: cohort.parent_operation,
                    timeline: cohort.timeline,
                    generation: cohort.generation,
                    purpose: cohort.purpose,
                    scope_set_digest: cohort.scope_set_digest,
                    evidence_not_after_micros: cohort.evidence_not_after_micros,
                    allowed_record_kinds: cohort.allowed_record_kinds,
                    member_slots: cohort.member_slots,
                    material_fingerprint: Hash::zero(),
                    authority_request_digest: cohort.authority_request_digest,
                })
                .and_then(|key| {
                    CommunityCopyInventoryV1::new(CommunityCopyInventoryInputV1 {
                        copy_id,
                        revision: 1,
                        predecessor: None,
                        parent_operation: cohort.parent_operation,
                        timeline: cohort.timeline,
                        generation: cohort.generation,
                        holder: CommunityCopyHolderV1::KeyVault,
                        holder_digest: key.intent().digest(),
                        purpose: cohort.purpose,
                        scope_set_digest: cohort.scope_set_digest,
                        object_commitment: None,
                        state: CommunityCopyStateV1::Owned,
                        deadline_micros: cohort.evidence_not_after_micros,
                    })
                    .map(|copy| Self {
                        cohort,
                        protection_id,
                        key,
                        copy,
                    })
                })
            })
        })
    }

    /// The clear CKP1 intent of this suboperation's key.
    #[must_use]
    pub const fn key_intent(&self) -> &CommunityKeyIntentV1 {
        self.key.intent()
    }

    /// The CCI1 key-vault copy descriptor of this suboperation's material.
    #[must_use]
    pub const fn copy_descriptor(&self) -> &CommunityCopyInventoryV1 {
        &self.copy
    }

    /// Protect one plaintext record: COE1, encrypted CAR1, COW1 and the
    /// exact ARD1 fields, in that order. Each protection burns two credits.
    ///
    /// Every check of the record and its evidence runs before any
    /// encryption (ADR-128 §2), so a refused record burns no credit.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a `ClassificationProof` record, a kind
    /// the key's intent does not allow, an intent that does not allow
    /// `ClassificationProof`, a zero evidence commitment, or zero, unordered
    /// or repeated children; `BoundsExceeded` for a record over 3 MiB or more
    /// than 2048 children; and `CapacityExhausted` once the key's credits or
    /// cipher are spent.
    pub fn protect(
        &mut self,
        kind: CommunityArtifactKindV1,
        plaintext: &[u8],
        evidence: CommunityRecordEvidenceV1<'_>,
    ) -> Result<CommunityProtectedRecordV1, Error> {
        let allowed = self.cohort.allowed_record_kinds;
        if kind == CommunityArtifactKindV1::ClassificationProof
            || !allowed.contains(kind)
            || !allowed.contains(CommunityArtifactKindV1::ClassificationProof)
        {
            return Err(Error::InvalidBinding);
        }
        validate_record(plaintext, evidence)
            .and_then(|()| self.header(kind))
            .and_then(|header| {
                let identity = header.key_identity();
                self.key
                    .seal_envelope(header, plaintext)
                    .map(|content| (identity, content))
            })
            .and_then(|(identity, content)| {
                self.seal_proof(kind, plaintext, &content, evidence)
                    .and_then(|proof| self.object(&content, &proof, evidence, identity))
            })
    }

    fn header(&self, kind: CommunityArtifactKindV1) -> Result<CommunityArtifactHeaderV1, Error> {
        CommunityArtifactHeaderV1::new(CommunityArtifactHeaderInputV1 {
            timeline: self.cohort.timeline,
            generation: self.cohort.generation,
            purpose: self.cohort.purpose,
            operation: CommunityArtifactOperationV1::Control(self.protection_id),
            record_kind: kind,
            scope_cover_digest: self.cohort.scope_cover_digest,
            evidence_not_after_micros: self.cohort.evidence_not_after_micros,
        })
    }

    /// Build the CAR1 over the content envelope and seal it as kind 8.
    fn seal_proof(
        &mut self,
        kind: CommunityArtifactKindV1,
        plaintext: &[u8],
        content: &[u8],
        evidence: CommunityRecordEvidenceV1<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        CommunityEncryptedEnvelopeV1::from_canonical_cbor(content).and_then(|envelope| {
            CommunityClassificationProofV1::new(CommunityClassificationProofInputV1 {
                header: envelope.header(),
                owner_binding_digest: evidence.owner_binding_digest,
                plaintext_commitment: plaintext_commitment(kind, plaintext),
                envelope_address: envelope.address(),
                children: CommunityArtifactChildrenV1::from_children(evidence.children),
                host_provenance_digest: evidence.host_provenance_digest,
            })
            .map(|proof| proof.to_canonical_cbor())
            .and_then(|proof| {
                self.header(CommunityArtifactKindV1::ClassificationProof)
                    .and_then(|header| self.key.seal_envelope(header, &proof))
            })
        })
    }

    /// Frame the COW1 and derive its exact ARD1.
    fn object(
        &self,
        content: &[u8],
        proof: &[u8],
        evidence: CommunityRecordEvidenceV1<'_>,
        identity: KeyIdentityV1,
    ) -> Result<CommunityProtectedRecordV1, Error> {
        CommunityProtectedObjectV1::new(content, proof).and_then(|object| {
            let bytes = object.to_canonical_cbor();
            self.registration(&bytes, evidence.children, identity)
                .map(|registration| CommunityProtectedRecordV1 {
                    object_address: object.address(),
                    object: bytes,
                    registration,
                    owner_binding_digest: evidence.owner_binding_digest,
                    scope_cover_digest: self.cohort.scope_cover_digest,
                    evidence_not_after_micros: self.cohort.evidence_not_after_micros,
                })
        })
    }

    /// The ARD1 fields of ADR-128 §3. Optionality and the transition rule
    /// follow the record's purpose (owner decision on #560, 2026-11-16):
    /// `Required` for `ExecutionState` and `LifecycleControl`, `Optional` for
    /// `PresentationTrace` and `ReplayEvidence`, and `Remove` for all four.
    /// The community extractor must check the same mapping.
    fn registration(
        &self,
        object: &[u8],
        children: &[ArtifactChildEdgeV1],
        identity: KeyIdentityV1,
    ) -> Result<ArtifactRegistrationV1, Error> {
        let class = artifact_class(self.cohort.purpose);
        community_catalogue_owner_reference_v1(self.cohort.timeline, self.cohort.generation)
            .and_then(|owner_reference| {
                ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
                    artifact_class: class,
                    artifact_digest: ArtifactRegistrationV1::artifact_digest(class, object),
                    owner_reference,
                    data_class: ArtifactDataClassV1::PrivateSubjectData,
                    optionality: optionality(self.cohort.purpose),
                    transition_rule: ArtifactTransitionRuleV1::Remove,
                    required_key_roles: vec![KeyRoleV1::CommunityArtifactEncryption],
                    key_dependencies: vec![ArtifactKeyDependencyV1 {
                        identity,
                        material_digest: self.key.intent().as_input().material_fingerprint,
                        private_material_required: true,
                    }],
                    child_artifacts: children.to_vec(),
                })
                .ok()
                .ok_or(Error::InvalidBinding)
            })
    }
}

/// One protected record: the exact COW1, its address and its unpublished
/// ARD1. It grants no read and is not yet admitted.
pub struct CommunityProtectedRecordV1 {
    object: Zeroizing<Vec<u8>>,
    object_address: Hash,
    registration: ArtifactRegistrationV1,
    owner_binding_digest: Hash,
    scope_cover_digest: Hash,
    evidence_not_after_micros: u64,
}

impl CommunityProtectedRecordV1 {
    /// The exact canonical COW1 bytes.
    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    /// `H("ProtectedObject", COW1)`, the physical address.
    #[must_use]
    pub const fn object_address(&self) -> Hash {
        self.object_address
    }

    /// The exact ARD1 of this COW1, derived but not published.
    #[must_use]
    pub const fn registration(&self) -> &ArtifactRegistrationV1 {
        &self.registration
    }

    /// Build this record's COA1 at the trusted composition root.
    ///
    /// The CAU1 commitment and inventory generation come from the caller;
    /// the object, ARD1, COB1, scope-cover and horizon fields come from the
    /// protected record itself. The COA1 is historical admission evidence,
    /// never a read permit.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero CAU1 digest.
    pub fn admission(
        &self,
        _seal: &'static AuthorityTrustRootSealV1,
        admission_inventory_generation: u64,
        authority_evidence_digest: Hash,
    ) -> Result<CommunityArtifactAdmissionV1, Error> {
        CommunityArtifactAdmissionV1::new(CommunityArtifactAdmissionInputV1 {
            protected_object_address: self.object_address,
            artifact_digest: self.registration.fields().artifact_digest,
            registration_address: self.registration.address(),
            owner_binding_digest: self.owner_binding_digest,
            scope_cover_digest: self.scope_cover_digest,
            evidence_not_after_micros: self.evidence_not_after_micros,
            admission_inventory_generation,
            authority_evidence_digest,
        })
    }
}

/// ADR-128 §3 / ADR-129 annex §1 class of each purpose's records.
const fn artifact_class(purpose: CommunityArtifactPurposeV1) -> ErasureArtifactClassV1 {
    match purpose {
        CommunityArtifactPurposeV1::ExecutionState
        | CommunityArtifactPurposeV1::LifecycleControl => ErasureArtifactClassV1::TimelineReplay,
        CommunityArtifactPurposeV1::PresentationTrace => ErasureArtifactClassV1::CausalTrace,
        CommunityArtifactPurposeV1::ReplayEvidence => ErasureArtifactClassV1::ReproManifest,
    }
}

/// Owner decision on #560 (2026-11-16): required state and control records,
/// optional trace and Replay records.
const fn optionality(purpose: CommunityArtifactPurposeV1) -> ArtifactOptionalityV1 {
    match purpose {
        CommunityArtifactPurposeV1::ExecutionState
        | CommunityArtifactPurposeV1::LifecycleControl => ArtifactOptionalityV1::Required,
        CommunityArtifactPurposeV1::PresentationTrace
        | CommunityArtifactPurposeV1::ReplayEvidence => ArtifactOptionalityV1::Optional,
    }
}

/// Refuse a record before any encryption, so a refusal burns no credit:
/// the record bound, the nonzero COB1 and CPV1 commitments, and children
/// both CAR1 and ARD1 admit (at most 2048, nonzero, strictly ordered by
/// class, digest and address, each registration address once).
fn validate_record(plaintext: &[u8], evidence: CommunityRecordEvidenceV1<'_>) -> Result<(), Error> {
    let children = evidence.children;
    if plaintext.len() > MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1
        || children.len() > MAX_ARTIFACT_REGISTRATION_CHILDREN_V1
    {
        return Err(Error::BoundsExceeded);
    }
    let mut addresses = BTreeSet::new();
    let invalid = evidence.owner_binding_digest == Hash::zero()
        || evidence.host_provenance_digest == Hash::zero()
        || children.iter().any(|child| {
            child.artifact_digest == Hash::zero()
                || child.registration_address == Hash::zero()
                || !addresses.insert(child.registration_address)
        })
        || !children.is_sorted_by(|a, b| {
            (a.artifact_class, a.artifact_digest, a.registration_address)
                < (b.artifact_class, b.artifact_digest, b.registration_address)
        });
    if invalid {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
