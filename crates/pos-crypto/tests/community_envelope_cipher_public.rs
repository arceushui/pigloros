//! Real codec/AEAD composition; this does not qualify a native owner or vault.

use pos_core::community_lifecycle::{
    CommunityArtifactHeaderInputV1 as Input, CommunityArtifactHeaderV1 as Header,
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1 as Operation,
    CommunityArtifactPurposeV1 as Purpose, CommunityEncryptedEnvelopeV1 as Envelope,
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
