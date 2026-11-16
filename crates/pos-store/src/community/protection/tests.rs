//! The protected envelopes decrypt to the exact record and its CAR1 proof,
//! and a refused record burns no encryption credit.
//!
//! Decryption and credits have no public API, so these checks live beside
//! the key. Every expected commitment is computed with `blake3` from the
//! ADR-128 formula, not through the production helpers.

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityClassificationProofV1, CommunityEncryptedEnvelopeV1, CommunityLifecycleErrorV1,
    CommunityMemberSlotsV1, CommunityProtectedObjectV1, CommunityRecordKindsV1,
};
use pos_core::{
    ArtifactChildEdgeV1, AuthorityTrustRootSealV1, ErasureArtifactClassV1, Hash, TimelineId,
};

use super::{CommunityArtifactProtectorV1, CommunityProtectionCohortV1, CommunityRecordEvidenceV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn domain(prefix: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix);
    for part in parts {
        hasher.update(part);
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn protector() -> Result<CommunityArtifactProtectorV1, Box<dyn std::error::Error>> {
    Ok(CommunityArtifactProtectorV1::provision(
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
    )?)
}

const fn evidence(children: &[ArtifactChildEdgeV1]) -> CommunityRecordEvidenceV1<'_> {
    CommunityRecordEvidenceV1 {
        owner_binding_digest: hash(9),
        host_provenance_digest: hash(10),
        children,
    }
}

#[test]
fn both_envelopes_decrypt_to_the_record_and_its_proof() -> TestResult {
    let mut protector = protector()?;
    let children = [ArtifactChildEdgeV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(20),
        registration_address: hash(21),
        required: true,
    }];
    let record = protector.protect(
        CommunityArtifactKindV1::StateContent,
        b"state bytes",
        evidence(&children),
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
    // COE1 address: H("Envelope", canonical COE1).
    assert_eq!(
        proof.envelope_address,
        domain(
            b"PiglorOS.Community.Envelope.v1\0",
            &[object.content_envelope()]
        )
    );
    // Owner commitment: H("OwnerPlaintext", kind_u16 || len_u64 || plaintext).
    let kind = CommunityArtifactKindV1::StateContent.code().to_be_bytes();
    let length = 11_u64.to_be_bytes();
    assert_eq!(
        proof.plaintext_commitment,
        domain(
            b"PiglorOS.Community.OwnerPlaintext.v1\0",
            &[&kind, &length, b"state bytes"]
        )
    );
    assert_eq!(proof.children.iter().collect::<Vec<_>>(), children.to_vec());
    // Two encryptions, one content and one proof.
    assert_eq!(protector.key.burned_credits(), 2);

    // A tampered or non-canonical envelope does not open.
    let mut tampered = object.content_envelope().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        protector.key.open_envelope(&tampered).err(),
        Some(CommunityLifecycleErrorV1::EvidenceUnavailable)
    );
    assert!(protector.key.open_envelope(&tampered[..last]).is_err());
    Ok(())
}

/// Every refusal comes before any encryption: it burns no credit.
#[test]
fn a_refused_record_burns_no_credit() -> TestResult {
    let mut protector = protector()?;
    let ordered = [
        ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: hash(20),
            registration_address: hash(21),
            required: true,
        },
        ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: hash(22),
            registration_address: hash(21),
            required: true,
        },
    ];
    let reversed = [ordered[1], ordered[0]];
    let oversized = vec![0; 3 * 1024 * 1024 + 1];
    for (plaintext, evidence) in [
        (
            &b"record"[..],
            CommunityRecordEvidenceV1 {
                owner_binding_digest: Hash::zero(),
                ..evidence(&[])
            },
        ),
        (
            &b"record"[..],
            CommunityRecordEvidenceV1 {
                host_provenance_digest: Hash::zero(),
                ..evidence(&[])
            },
        ),
        (&b"record"[..], evidence(&ordered)),
        (&b"record"[..], evidence(&reversed)),
        (&oversized[..], evidence(&[])),
    ] {
        assert!(protector
            .protect(CommunityArtifactKindV1::StateContent, plaintext, evidence)
            .is_err());
        assert_eq!(protector.key.burned_credits(), 0);
    }
    Ok(())
}
