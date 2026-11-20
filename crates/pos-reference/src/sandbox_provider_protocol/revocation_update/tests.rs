//! The RCA1 producer (ADR-069 R11 §8.3 step 6), oracled by the selector's
//! RCA1 authentication.

use ed25519_dalek::{Signer, SigningKey};

use super::{
    RevocationAcknowledgement, RevocationAcknowledgementFields, RevocationUpdateRequest,
    SandboxRevocationUpdateError,
};
use crate::sandbox_provider_protocol::SandboxProviderProtocolError;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fields() -> RevocationAcknowledgementFields {
    RevocationAcknowledgementFields {
        request_id: [1; 16],
        revocation_digest: [2; 32],
        sir1_digest: [3; 32],
        previous_provider_binding_digest: [4; 32],
        cancelled_attempt_ids: vec![[5; 16], [6; 16]],
        runtime_attestation_key_id: "runtime".to_owned(),
    }
}

/// Sign `fields` with `key` and verify the signature under `key`.
fn signed(
    fields: RevocationAcknowledgementFields,
    key: &SigningKey,
) -> TestResult<RevocationAcknowledgement> {
    let record = RevocationAcknowledgement::self_digested(fields)?;
    let signature = key.sign(&record.signature_message()).to_bytes();
    let verified = record.verify(signature, &key.verifying_key())?;
    Ok(RevocationAcknowledgement::new(
        verified,
        &key.verifying_key(),
    )?)
}

#[test]
fn a_produced_rca1_authenticates_as_the_selector_reads_it() -> TestResult {
    let key = SigningKey::from_bytes(&[9; 32]);
    let bytes = signed(fields(), &key)?.to_canonical_cbor()?;
    let read = RevocationAcknowledgement::authenticate(&bytes, "runtime", &key.verifying_key())?;
    assert_eq!(
        (
            read.request_id,
            read.revocation_digest,
            read.sir1_digest,
            read.previous_provider_binding_digest,
            read.cancelled_attempt_ids.clone(),
            read.runtime_attestation_key_id.as_str(),
        ),
        (
            [1; 16],
            [2; 32],
            [3; 32],
            [4; 32],
            vec![[5; 16], [6; 16]],
            "runtime"
        )
    );
    assert_eq!(read.to_canonical_cbor()?, bytes);
    // An empty cancelled set is valid.
    let empty = RevocationAcknowledgementFields {
        cancelled_attempt_ids: Vec::new(),
        ..fields()
    };
    let bytes = signed(empty, &key)?.to_canonical_cbor()?;
    assert!(
        RevocationAcknowledgement::authenticate(&bytes, "runtime", &key.verifying_key())?
            .cancelled_attempt_ids
            .is_empty()
    );
    Ok(())
}

#[test]
fn the_rca1_producer_refuses_invalid_fields_and_a_foreign_key() -> TestResult {
    let out_of_bounds =
        SandboxRevocationUpdateError::Protocol(SandboxProviderProtocolError::FieldOutOfBounds);
    for changed in [
        RevocationAcknowledgementFields {
            request_id: [0; 16],
            ..fields()
        },
        RevocationAcknowledgementFields {
            revocation_digest: [0; 32],
            ..fields()
        },
        RevocationAcknowledgementFields {
            sir1_digest: [0; 32],
            ..fields()
        },
        RevocationAcknowledgementFields {
            previous_provider_binding_digest: [0; 32],
            ..fields()
        },
        RevocationAcknowledgementFields {
            runtime_attestation_key_id: String::new(),
            ..fields()
        },
    ] {
        assert_eq!(
            RevocationAcknowledgement::self_digested(changed).err(),
            Some(out_of_bounds.clone())
        );
    }
    let unordered = RevocationAcknowledgementFields {
        cancelled_attempt_ids: vec![[6; 16], [5; 16]],
        ..fields()
    };
    assert_eq!(
        RevocationAcknowledgement::self_digested(unordered).err(),
        Some(SandboxRevocationUpdateError::Protocol(
            SandboxProviderProtocolError::NonCanonicalOrder
        ))
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let record = RevocationAcknowledgement::self_digested(fields())?;
    let signature = key.sign(&record.signature_message()).to_bytes();
    let verified = record.verify(signature, &key.verifying_key())?;
    let foreign = SigningKey::from_bytes(&[8; 32]).verifying_key();
    assert_eq!(
        RevocationAcknowledgement::new(verified, &foreign).err(),
        Some(SandboxRevocationUpdateError::Protocol(
            SandboxProviderProtocolError::SignatureInvalid
        ))
    );
    Ok(())
}

/// The RCA1 record names the key ID of its fields, which the signer checks
/// against the admitted key, and it authenticates under that key ID only.
#[test]
fn an_rca1_names_and_authenticates_under_its_own_key_id() -> TestResult {
    let seed = blake3::Hasher::new()
        .update(b"PiglorOS.RevocationAcknowledgementTestKey.v1\0")
        .finalize();
    let key = SigningKey::from_bytes(seed.as_bytes());
    let record = RevocationAcknowledgement::self_digested(fields())?;
    assert_eq!(record.key_id(), "runtime");
    let other = RevocationAcknowledgement::self_digested(RevocationAcknowledgementFields {
        runtime_attestation_key_id: "other".to_owned(),
        ..fields()
    })?;
    assert_eq!(other.key_id(), "other");
    let bytes = signed(fields(), &key)?.to_canonical_cbor()?;
    RevocationAcknowledgement::authenticate(&bytes, "runtime", &key.verifying_key())?;
    assert_eq!(
        RevocationAcknowledgement::authenticate(&bytes, "other", &key.verifying_key()).err(),
        Some(SandboxRevocationUpdateError::AcknowledgementMismatch)
    );
    Ok(())
}

#[test]
fn claimed_digests_need_an_rcu1_wrapper() {
    assert!(RevocationUpdateRequest::claimed_revocation_digests(b"\xff").is_err());
}
