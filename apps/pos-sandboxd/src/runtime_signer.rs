//! The one runtime-attestation signer of the provider (ADR-069 R9 §5).
//!
//! [`RuntimeAttestationSigner`] is the only signing port. It accepts nothing
//! but a sealed [`SelfDigested`] record of a [`RuntimeSigned`] kind, built by
//! the `pos_reference` record encoders, and signs the message that record
//! derives: `PiglorOS.<M>.Signature.v1\0 || self_digest`. It is given no
//! bytes, digest or kind, so it is no signing oracle. [`sign_verified`]
//! verifies each signature under the admitted runtime key before it is
//! returned: a signature that does not verify is never emitted.
//!
//! The shipped adapter, [`KeyFileRuntimeSigner`], holds the provider's
//! Ed25519 key, which the ADR-069 R11 §4.4 key file held: the provider
//! installation's `RuntimeKey` (#1066) is the one loader of that file and its
//! contract. The key never leaves the process. The runtime-attestation key ID
//! comes from the admitted SPM1, never from the file.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pos_reference::sandbox_provider_protocol::{
    ExecutionRelease, ExecutionReleaseFields, RuntimeSigned, SandboxProviderProtocolError,
    SelfDigested, Verified,
};

/// The signing port for the provider's runtime-attestation key.
pub trait RuntimeAttestationSigner {
    /// The SPM1-named runtime-attestation key ID this signer holds.
    fn runtime_attestation_key_id(&self) -> &str;

    /// Sign the message `record` derives and return the Ed25519 signature.
    fn sign<M: RuntimeSigned>(&self, record: &SelfDigested<M>) -> [u8; 64];
}

/// The admitted runtime-attestation key: its SPM1 key ID and the public key
/// that TRS1 authorizes. Every emitted signature verifies under it.
#[derive(Clone, Copy, Debug)]
pub struct AdmittedRuntimeKey<'a> {
    key_id: &'a str,
    key: &'a VerifyingKey,
}

impl<'a> AdmittedRuntimeKey<'a> {
    /// The admitted key `key_id`, whose public key is `key`.
    #[must_use]
    pub const fn new(key_id: &'a str, key: &'a VerifyingKey) -> Self {
        Self { key_id, key }
    }

    /// The admitted key ID.
    #[must_use]
    pub(crate) const fn key_id(&self) -> &'a str {
        self.key_id
    }

    /// The admitted public key.
    #[must_use]
    pub(crate) const fn key(&self) -> &'a VerifyingKey {
        self.key
    }
}

/// Closed failures of the runtime-attestation signing boundary.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeSignerError {
    /// The signer or the record names another key than the admitted one.
    #[error("runtime-attestation key id differs from the admitted key")]
    KeyIdMismatch,
    /// The signature does not verify under the admitted key; nothing is
    /// emitted and the provider fault closes admission.
    #[error("the runtime-attestation signature does not verify")]
    Unverified,
    /// The record fields or signature are invalid.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
}

/// Sign `record` with `signer`, and return it signed only once the signature
/// verified under the admitted key (R9 §5, "verify before emission").
///
/// # Errors
/// `KeyIdMismatch` when the signer or the record names another key than the
/// admitted one, and `Unverified` when the signature does not verify.
pub fn sign_verified<S, M>(
    signer: &S,
    admitted: AdmittedRuntimeKey<'_>,
    record: SelfDigested<M>,
) -> Result<Verified<M>, RuntimeSignerError>
where
    S: RuntimeAttestationSigner,
    M: RuntimeSigned,
{
    if signer.runtime_attestation_key_id() != admitted.key_id || record.key_id() != admitted.key_id
    {
        return Err(RuntimeSignerError::KeyIdMismatch);
    }
    let signature = signer.sign(&record);
    record
        .verify(signature, admitted.key)
        .map_err(|_| RuntimeSignerError::Unverified)
}

/// Ed25519 signer of the key the R11 §4.4 key file held.
#[derive(Debug)]
pub struct KeyFileRuntimeSigner {
    key: SigningKey,
    key_id: String,
}

impl KeyFileRuntimeSigner {
    /// The signer of `key` for the SPM1-admitted `key_id`.
    ///
    /// This bypasses the R11 §4.4 key-file contract: it trusts that `key`
    /// came from the key file. Only the provider's composition root calls
    /// it, through `RuntimeKey::into_signer` with the key it loaded and
    /// checked (#1066); tests build signers from a fixed key.
    #[must_use]
    pub(crate) const fn from_signing_key(key: SigningKey, key_id: String) -> Self {
        Self { key, key_id }
    }
}

impl RuntimeAttestationSigner for KeyFileRuntimeSigner {
    fn runtime_attestation_key_id(&self) -> &str {
        &self.key_id
    }

    fn sign<M: RuntimeSigned>(&self, record: &SelfDigested<M>) -> [u8; 64] {
        self.key.sign(&record.signature_message()).to_bytes()
    }
}

/// Build, sign and verify one `ReleaseV1` under the admitted key.
///
/// # Errors
/// `Protocol` for invalid fields or for a signature that verified under
/// another key than the admitted one, `KeyIdMismatch` if the fields or the
/// signer name another key than the admitted one, and `Unverified` for a
/// signature that does not verify.
pub fn issue_release<S>(
    signer: &S,
    admitted: AdmittedRuntimeKey<'_>,
    fields: ExecutionReleaseFields,
) -> Result<ExecutionRelease, RuntimeSignerError>
where
    S: RuntimeAttestationSigner,
{
    ExecutionRelease::self_digested(fields)
        .map_err(RuntimeSignerError::from)
        .and_then(|record| sign_verified(signer, admitted, record))
        .and_then(|verified| ExecutionRelease::new(verified, admitted.key).map_err(Into::into))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;

    use pos_reference::sandbox_provider_protocol::{
        RevocationAcknowledgement, RevocationAcknowledgementFields, SandboxDescribeResponse,
        SandboxDescribeResponseFields, SandboxProviderError, SandboxProviderErrorCode,
        SandboxProviderErrorFields, SandboxRevocationUpdateError,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn fields(key_id: &str) -> ExecutionReleaseFields {
        ExecutionReleaseFields {
            attempt_id: [1; 16],
            nonce: [2; 32],
            ready1_digest: [3; 32],
            trs1_digest: [4; 32],
            rvs1_digest: [5; 32],
            apt1_digest: [6; 32],
            trust_epoch: 1,
            revocation_epoch: 2,
            policy_epoch: 3,
            expected_readback_digest: [7; 32],
            observed_readback_digest: [8; 32],
            deadline_monotonic_ns: 9,
            runtime_attestation_key_id: key_id.to_owned(),
        }
    }

    fn signer(seed: [u8; 32]) -> KeyFileRuntimeSigner {
        KeyFileRuntimeSigner::from_signing_key(SigningKey::from_bytes(&seed), "runtime".to_owned())
    }

    #[test]
    fn the_key_signs_a_verifiable_release() -> TestResult {
        let signer = signer([42; 32]);
        assert_eq!(signer.runtime_attestation_key_id(), "runtime");
        let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &public);
        assert_eq!(admitted.key_id(), "runtime");
        let release = issue_release(&signer, admitted, fields("runtime"))?;
        release.verify_signature(&public)?;
        let decoded = ExecutionRelease::from_canonical_cbor(&release.to_canonical_cbor()?)?;
        assert_eq!(decoded, release);
        Ok(())
    }

    #[test]
    fn a_release_naming_another_key_or_invalid_fields_is_not_signed() {
        let signer = signer([42; 32]);
        let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &public);
        assert!(matches!(
            issue_release(&signer, admitted, fields("other")),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        let other = AdmittedRuntimeKey::new("other", &public);
        assert!(matches!(
            issue_release(&signer, other, fields("other")),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        let mut invalid = fields("runtime");
        invalid.deadline_monotonic_ns = 0;
        assert!(matches!(
            issue_release(&signer, admitted, invalid),
            Err(RuntimeSignerError::Protocol(_))
        ));
    }

    #[test]
    fn a_signature_that_does_not_verify_under_the_admitted_key_is_never_emitted() -> TestResult {
        let signer = signer([42; 32]);
        let foreign = SigningKey::from_bytes(&[43; 32]).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &foreign);
        assert!(matches!(
            issue_release(&signer, admitted, fields("runtime")),
            Err(RuntimeSignerError::Unverified)
        ));
        let record = ExecutionRelease::self_digested(fields("runtime"))?;
        assert!(matches!(
            sign_verified(&signer, admitted, record.clone()),
            Err(RuntimeSignerError::Unverified)
        ));
        let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        // A record naming another key is not signed for the admitted one.
        let other = ExecutionRelease::self_digested(fields("other"))?;
        assert!(matches!(
            sign_verified(&signer, AdmittedRuntimeKey::new("runtime", &public), other),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        let verified = sign_verified(&signer, AdmittedRuntimeKey::new("runtime", &public), record)?;
        assert_eq!(verified.key(), &public);
        ExecutionRelease::new(verified, &public)?.verify_signature(&public)?;
        Ok(())
    }

    #[test]
    fn describe_responses_and_provider_errors_are_signed_only_for_the_admitted_key() -> TestResult {
        let signer = signer([42; 32]);
        let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &public);
        let describe = |key_id: &str| SandboxDescribeResponseFields {
            request_id: [1; 16],
            spm1_digest: [2; 32],
            provider_binary_digest: [3; 32],
            hcp1_digest: [4; 32],
            active_apt1_digest: [5; 32],
            runtime_attestation_key_id: key_id.to_owned(),
        };
        let refusal = |key_id: &str| SandboxProviderErrorFields {
            operation: Some(1),
            request_id: Some([6; 16]),
            request_digest: Some([7; 32]),
            attempt_id: Some([8; 16]),
            code: SandboxProviderErrorCode::SandboxUnavailable,
            safe_detail: None,
            runtime_attestation_key_id: key_id.to_owned(),
        };
        let record = SandboxDescribeResponse::self_digested(describe("runtime"))?;
        let response =
            SandboxDescribeResponse::new(sign_verified(&signer, admitted, record)?, &public)?;
        SandboxDescribeResponse::from_canonical_cbor(&response.to_canonical_cbor()?)?
            .verify_signature(&public)?;
        let record = SandboxProviderError::self_digested(refusal("runtime"))?;
        let error = SandboxProviderError::new(sign_verified(&signer, admitted, record)?, &public)?;
        SandboxProviderError::from_canonical_cbor(&error.to_canonical_cbor()?)?
            .verify_signature(&public)?;
        // A record naming another key than the admitted one is not signed.
        let other = SandboxDescribeResponse::self_digested(describe("other"))?;
        assert!(matches!(
            sign_verified(&signer, admitted, other),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        let other = SandboxProviderError::self_digested(refusal("other"))?;
        assert!(matches!(
            sign_verified(&signer, admitted, other),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        Ok(())
    }

    #[test]
    fn revocation_acknowledgements_verify_only_under_the_key_id_they_name() -> TestResult {
        let seed = *blake3::hash(b"PiglorOS.test.runtime-signer.RCA1").as_bytes();
        let signer = signer(seed);
        let public = SigningKey::from_bytes(&seed).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &public);
        let acknowledgement = |key_id: &str| RevocationAcknowledgementFields {
            request_id: [1; 16],
            revocation_digest: [2; 32],
            sir1_digest: [3; 32],
            previous_provider_binding_digest: [4; 32],
            cancelled_attempt_ids: vec![[5; 16]],
            runtime_attestation_key_id: key_id.to_owned(),
        };
        // The record names the key ID of its fields, so it is signed for
        // that admitted key and authenticates under that key ID only.
        let record = RevocationAcknowledgement::self_digested(acknowledgement("runtime"))?;
        assert_eq!(record.key_id(), "runtime");
        let acknowledged =
            RevocationAcknowledgement::new(sign_verified(&signer, admitted, record)?, &public)?;
        let bytes = acknowledged.to_canonical_cbor()?;
        assert_eq!(
            RevocationAcknowledgement::authenticate(&bytes, "runtime", &public)?,
            acknowledged
        );
        assert!(matches!(
            RevocationAcknowledgement::authenticate(&bytes, "other", &public),
            Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
        ));
        // An RCA1 naming another key is not signed for the admitted one.
        let other = RevocationAcknowledgement::self_digested(acknowledgement("other"))?;
        assert_eq!(other.key_id(), "other");
        assert!(matches!(
            sign_verified(&signer, admitted, other),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        Ok(())
    }
}
