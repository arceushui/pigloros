//! The protected envelopes decrypt to the exact record and its CAR1 proof.
//!
//! Decryption has no public API, so these checks live beside the key.

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityClassificationProofV1, CommunityEncryptedEnvelopeV1, CommunityMemberSlotsV1,
    CommunityProtectedObjectV1, CommunityRecordKindsV1,
};
use pos_core::{
    ArtifactChildEdgeV1, AuthorityTrustRootSealV1, ErasureArtifactClassV1, Hash, TimelineId,
};

use super::super::private_hash::plaintext_commitment;
use super::{CommunityArtifactProtectorV1, CommunityProtectionCohortV1, CommunityRecordEvidenceV1};

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

#[test]
fn both_envelopes_decrypt_to_the_record_and_its_proof() -> Result<(), Box<dyn std::error::Error>> {
    let mut protector = CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            parent_operation: CommunityArtifactOperationV1::Initialization([3; 16]),
            timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([4; 16])),
            generation: [5; 16],
            purpose: CommunityArtifactPurposeV1::ExecutionState,
            scope_set_digest: hash(6),
            scope_cover_digest: hash(7),
            evidence_not_after_micros: 1_000,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(CommunityArtifactKindV1::StateContent)
                .with(CommunityArtifactKindV1::ClassificationProof),
            member_slots: CommunityMemberSlotsV1::new(&[0])?,
            authority_request_digest: hash(8),
        },
    )?;
    let children = [ArtifactChildEdgeV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(20),
        registration_address: hash(21),
        required: true,
    }];
    let record = protector.protect(
        CommunityArtifactKindV1::StateContent,
        b"state bytes",
        CommunityRecordEvidenceV1 {
            owner_binding_digest: hash(9),
            host_provenance_digest: hash(10),
            children: &children,
        },
    )?;
    let object = CommunityProtectedObjectV1::from_canonical_cbor(record.object())?;
    let plaintext = protector.key.open_envelope(object.content_envelope())?;
    assert_eq!(plaintext.as_slice(), b"state bytes");

    let content = CommunityEncryptedEnvelopeV1::from_canonical_cbor(object.content_envelope())?;
    let proof_bytes = protector.key.open_envelope(object.proof_envelope())?;
    let proof =
        CommunityClassificationProofV1::from_canonical_cbor(&proof_bytes, content.header())?;
    let proof = proof.as_input();
    assert_eq!(proof.owner_binding_digest, hash(9));
    assert_eq!(proof.host_provenance_digest, hash(10));
    assert_eq!(proof.envelope_address, content.address());
    assert_eq!(
        proof.plaintext_commitment,
        plaintext_commitment(CommunityArtifactKindV1::StateContent, b"state bytes")
    );
    assert_eq!(proof.children.iter().collect::<Vec<_>>(), children.to_vec());
    // Two encryptions, one content and one proof.
    assert_eq!(protector.key.burned_credits(), 2);
    Ok(())
}
