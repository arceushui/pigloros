//! Protected-object and registration sizes before encryption, and the ARD1
//! graph terms of a pass (ADR-129 revision 11, R11.3(2)–(3)).
//!
//! A record with plaintext length `p` and `c` ARD1 children is protected as
//! one COW1 holding two COE1s under the same COH1 context: the content, with
//! ciphertext `p + 16`, and its CAR1 proof with the `c` children, with
//! ciphertext `|CAR1| + 16`. Its ARD1 has one key dependency and the `c`
//! children. Every other field has a fixed width for a given `(T, G)`: the
//! templates below are encoded once with placeholder fixed-width values and
//! the widest horizon, and the variable parts are added arithmetically.

use super::{
    head_len, CommunityArtifactChildrenV1, CommunityArtifactHeaderInputV1,
    CommunityArtifactHeaderV1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityClassificationProofInputV1,
    CommunityClassificationProofV1, CommunityEncryptedEnvelopeV1,
    CommunityLifecycleErrorV1 as Error, Result, WIDEST_HORIZON_MICROS,
};
use crate::{
    ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationFieldsV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1, Hash, KeyRoleV1, TimelineId,
};

/// A nonzero fixed-width placeholder digest.
const PLACEHOLDER: Hash = Hash::from_bytes([0xff; 32]);

/// One child edge in both CAR1 and ARD1: array head, class, two digests and
/// the required flag.
const CHILD_BYTES: u64 = 71;

/// The AEAD tag every COE1 ciphertext carries.
const TAG_BYTES: u64 = 16;

/// `[registrations, edges, keys, registration_bytes, artifact_bytes]` that
/// records add to an ARD1 closure. Depth is bounded separately (R11.3(4)).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommunityPassGraphTermsV1 {
    /// New registrations.
    pub registrations: u64,
    /// New ARD1 child edges.
    pub edges: u64,
    /// New key identities.
    pub keys: u64,
    /// Encoded ARD1 bytes.
    pub registration_bytes: u64,
    /// Encoded COW1 bytes.
    pub artifact_bytes: u64,
}

impl CommunityPassGraphTermsV1 {
    /// The field-wise saturating sum.
    #[must_use]
    pub const fn plus(self, other: Self) -> Self {
        Self {
            registrations: self.registrations.saturating_add(other.registrations),
            edges: self.edges.saturating_add(other.edges),
            keys: self.keys.saturating_add(other.keys),
            registration_bytes: self
                .registration_bytes
                .saturating_add(other.registration_bytes),
            artifact_bytes: self.artifact_bytes.saturating_add(other.artifact_bytes),
        }
    }
}

/// The COW1 and ARD1 sizes of `(T, G)`'s protected records (R11.3(2)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityProtectionSizesV1 {
    /// A COE1 whose ciphertext is only the 16-byte tag.
    envelope: u64,
    /// A CAR1 with no children.
    proof: u64,
    /// An ARD1 with one key dependency and no children.
    registration: u64,
}

impl CommunityProtectionSizesV1 {
    /// Encode the COH1, COE1, CAR1 and ARD1 templates of `(T, G)`.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero Timeline or generation.
    pub fn new(timeline: TimelineId, generation: [u8; 16]) -> Result<Self> {
        let header = {
            CommunityArtifactHeaderV1::new(CommunityArtifactHeaderInputV1 {
                timeline,
                generation,
                purpose: CommunityArtifactPurposeV1::ExecutionState,
                operation: CommunityArtifactOperationV1::Control([0xff; 16]),
                record_kind: CommunityArtifactKindV1::StateContent,
                scope_cover_digest: PLACEHOLDER,
                evidence_not_after_micros: WIDEST_HORIZON_MICROS,
            })
        };
        header.and_then(|content| {
            proof_len(&content).and_then(|proof| {
                registration_len(&content).and_then(|registration| {
                    CommunityEncryptedEnvelopeV1::new(content, [0; 12], &[0; 16]).map(|envelope| {
                        Self {
                            envelope: envelope.to_canonical_cbor().len() as u64,
                            proof,
                            registration,
                        }
                    })
                })
            })
        })
    }

    /// The canonical COE1 size for a `plaintext`-byte payload.
    const fn envelope_len(&self, plaintext: u64) -> u64 {
        let ciphertext = plaintext.saturating_add(TAG_BYTES);
        bytes_len(ciphertext)
            .saturating_add(self.envelope)
            .saturating_sub(bytes_len(TAG_BYTES))
    }

    /// The canonical CAR1 size with `children` children.
    const fn proof_len(&self, children: u64) -> u64 {
        array_len(children, CHILD_BYTES).saturating_add(self.proof - 1)
    }

    /// `W_cow(p, c)`: the canonical COW1 size of a `plaintext`-byte record
    /// with `children` ARD1 children.
    #[must_use]
    pub const fn object_len(&self, plaintext: u64, children: u64) -> u64 {
        // The COW1 prefix (array head, magic and version) and two COE1 bstrs.
        bytes_len(self.envelope_len(plaintext))
            .saturating_add(bytes_len(self.envelope_len(self.proof_len(children))))
            .saturating_add(7)
    }

    /// `W_ard(c)`: the canonical ARD1 size with `children` children.
    #[must_use]
    pub const fn registration_len(&self, children: u64) -> u64 {
        array_len(children, CHILD_BYTES).saturating_add(self.registration - 1)
    }

    /// One new registration with `children` edges: its ARD1 and COW1 bytes.
    #[must_use]
    pub const fn record(&self, plaintext: u64, children: u64) -> CommunityPassGraphTermsV1 {
        CommunityPassGraphTermsV1 {
            registrations: 1,
            edges: children,
            keys: 0,
            registration_bytes: self.registration_len(children),
            artifact_bytes: self.object_len(plaintext, children),
        }
    }
}

/// A bstr of `length` bytes: its head and its bytes.
const fn bytes_len(length: u64) -> u64 {
    length.saturating_add(head_len(length) as u64)
}

/// An array of `count` rows of `row` bytes: its head and its rows.
const fn array_len(count: u64, row: u64) -> u64 {
    count
        .saturating_mul(row)
        .saturating_add(head_len(count) as u64)
}

fn proof_len(header: &CommunityArtifactHeaderV1) -> Result<u64> {
    CommunityClassificationProofV1::new(CommunityClassificationProofInputV1 {
        header,
        owner_binding_digest: PLACEHOLDER,
        plaintext_commitment: PLACEHOLDER,
        envelope_address: PLACEHOLDER,
        children: CommunityArtifactChildrenV1::from_children(&[]),
        host_provenance_digest: PLACEHOLDER,
    })
    .map(|proof| proof.to_canonical_cbor().len() as u64)
}

fn registration_len(header: &CommunityArtifactHeaderV1) -> Result<u64> {
    ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: PLACEHOLDER,
        owner_reference: PLACEHOLDER,
        data_class: ArtifactDataClassV1::PrivateSubjectData,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::Remove,
        required_key_roles: vec![KeyRoleV1::CommunityArtifactEncryption],
        key_dependencies: vec![ArtifactKeyDependencyV1 {
            identity: header.key_identity(),
            material_digest: PLACEHOLDER,
            private_material_required: true,
        }],
        child_artifacts: Vec::new(),
    })
    .ok()
    .map(|registration| registration.canonical_cbor().len() as u64)
    .ok_or(Error::InvalidBinding)
}
