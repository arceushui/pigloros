//! Real codec/AEAD composition; this does not qualify a native owner or vault.

use pos_core::community_lifecycle::{
    CommunityArtifactChildrenV1 as Children, CommunityArtifactHeaderInputV1 as Input,
    CommunityArtifactHeaderV1 as Header, CommunityArtifactKindV1 as Kind,
    CommunityArtifactOperationV1 as Operation, CommunityArtifactPurposeV1 as Purpose,
    CommunityClassificationProofInputV1 as ProofInput, CommunityClassificationProofV1 as Proof,
    CommunityEncryptedEnvelopeV1 as Envelope, CommunityProtectedObjectV1 as Object,
    CommunityStateContentV1 as State,
};
use pos_core::{Hash, TimelineId};
use pos_crypto::community_cipher::{CommunityArtifactCipherV1 as Cipher, CommunityCipherErrorV1};
use zeroize::Zeroizing;

const fn context() -> Input {
    Input {
        timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        generation: [2; 16],
        purpose: Purpose::ExecutionState,
        operation: Operation::Control([3; 16]),
        record_kind: Kind::StateContent,
        scope_cover_digest: Hash::from_bytes([4; 32]),
        evidence_not_after_micros: 5,
    }
}

#[test]
fn protected_object_authenticates_state_and_its_bound_classification_proof(
) -> Result<(), Box<dyn std::error::Error>> {
    let state = State::new(Hash::from_bytes([7; 32]), b"retained State")?;
    let state_bytes = state.to_canonical_cbor();
    let header = Header::new(context())?;
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([8; 32])), 2)?;
    let sealed_state = cipher.seal(&state_bytes, header.associated_data_digest().as_bytes())?;
    let envelope = Envelope::new(
        header,
        *sealed_state.nonce(),
        sealed_state.ciphertext_and_tag(),
    )?;
    let envelope_bytes = envelope.to_canonical_cbor();

    // Independent accepted owner-commitment preimage, kept in private staging.
    // These fixtures are data, not a qualified host authority or extractor.
    let mut preimage = Zeroizing::new(Vec::with_capacity(state_bytes.len() + 64));
    preimage.extend_from_slice(b"PiglorOS.Community.OwnerPlaintext.v1\0");
    preimage.extend_from_slice(&0_u16.to_be_bytes());
    preimage.extend_from_slice(&(state_bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&state_bytes);
    let commitment = Hash::from_bytes(*blake3::hash(&preimage).as_bytes());
    let proof = Proof::new(ProofInput {
        header: envelope.header(),
        owner_binding_digest: Hash::from_bytes([9; 32]),
        plaintext_commitment: commitment,
        envelope_address: envelope.address(),
        children: Children::from_children(&[]),
        host_provenance_digest: Hash::from_bytes([10; 32]),
    })?;
    let proof_bytes = proof.to_canonical_cbor();
    let proof_header = Header::new(Input {
        record_kind: Kind::ClassificationProof,
        ..context()
    })?;
    let sealed_proof = cipher.seal(
        &proof_bytes,
        proof_header.associated_data_digest().as_bytes(),
    )?;
    let companion = Envelope::new(
        proof_header,
        *sealed_proof.nonce(),
        sealed_proof.ciphertext_and_tag(),
    )?;
    let companion_bytes = companion.to_canonical_cbor();
    let object = Object::new(&envelope_bytes, &companion_bytes)?;
    let object_bytes = object.to_canonical_cbor();
    let decoded = Object::from_canonical_cbor(&object_bytes)?;
    let decoded_state = Envelope::from_canonical_cbor(decoded.content_envelope())?;
    let decoded_proof = Envelope::from_canonical_cbor(decoded.proof_envelope())?;
    cipher.close_encryption();
    let proof_staging = cipher.open(
        decoded_proof.nonce(),
        decoded_proof.ciphertext_and_tag(),
        decoded_proof.header().associated_data_digest().as_bytes(),
    )?;
    let recovered_proof = Proof::from_canonical_cbor(&proof_staging, decoded_state.header())?;
    assert_eq!(
        recovered_proof.as_input().envelope_address,
        decoded_state.address()
    );
    assert_eq!(recovered_proof.as_input().plaintext_commitment, commitment);
    let state_staging = cipher.open(
        decoded_state.nonce(),
        decoded_state.ciphertext_and_tag(),
        decoded_state.header().associated_data_digest().as_bytes(),
    )?;
    assert_eq!(
        State::from_canonical_cbor(&state_staging)?.state_bytes(),
        b"retained State"
    );
    assert_eq!(cipher.remaining_encryptions(), 0);
    Ok(())
}

#[test]
fn state_envelope_authenticates_exact_scope_horizon_kind_and_purpose(
) -> Result<(), Box<dyn std::error::Error>> {
    let content = State::new(Hash::from_bytes([7; 32]), b"opaque State fixture")?;
    let content_bytes = content.to_canonical_cbor();
    let header = Header::new(context())?;
    let identity = header.key_identity();
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([8; 32])), 1)?;
    let sealed = cipher.seal(&content_bytes, header.associated_data_digest().as_bytes())?;
    let envelope = Envelope::new(header, *sealed.nonce(), sealed.ciphertext_and_tag())?;
    let encoded = envelope.to_canonical_cbor();
    let decoded = Envelope::from_canonical_cbor(&encoded)?;
    assert_eq!(decoded.header().key_identity(), identity);
    let staging = cipher.open(
        decoded.nonce(),
        decoded.ciphertext_and_tag(),
        decoded.header().associated_data_digest().as_bytes(),
    )?;
    let recovered = State::from_canonical_cbor(&staging)?;
    assert_eq!(recovered.schema_digest(), Hash::from_bytes([7; 32]));
    assert_eq!(recovered.state_bytes(), b"opaque State fixture");

    for substitute in [
        Input {
            scope_cover_digest: Hash::from_bytes([9; 32]),
            ..context()
        },
        Input {
            evidence_not_after_micros: 6,
            ..context()
        },
        Input {
            record_kind: Kind::StateRevisionOrHead,
            ..context()
        },
        Input {
            purpose: Purpose::PresentationTrace,
            record_kind: Kind::TraceAnnotation,
            ..context()
        },
    ] {
        let changed = Envelope::new(
            Header::new(substitute)?,
            *sealed.nonce(),
            sealed.ciphertext_and_tag(),
        )?;
        assert_ne!(changed.address(), envelope.address());
        assert!(
            cipher
                .open(
                    changed.nonce(),
                    changed.ciphertext_and_tag(),
                    changed.header().associated_data_digest().as_bytes()
                )
                .err()
                == Some(CommunityCipherErrorV1::AuthenticationFailed)
        );
    }
    Ok(())
}
