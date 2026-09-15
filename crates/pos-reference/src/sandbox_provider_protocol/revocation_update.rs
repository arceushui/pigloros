//! Stateful selector validation for RCU1 revocation updates and RCA1 acknowledgements.

use ciborium::value::Value;

use super::codec::{
    bounded_array, byte_string, decode_document, digest32, id16, key_id, require_canonical_order,
    signed, uint, verify_digest, verify_signature,
};
use super::{
    SandboxProviderProtocolError, SandboxRevocationSnapshot, SandboxTrustError, SandboxTrustRole,
    SandboxTrustSnapshot,
};

/// Closed selector-side revocation-update failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxRevocationUpdateError {
    /// A request or acknowledgement violates its wire contract.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// A signer or authority snapshot is invalid.
    #[error(transparent)]
    Trust(#[from] SandboxTrustError),
    /// RCA1 does not acknowledge the exact pending update and cancellation set.
    #[error("sandbox revocation acknowledgement does not match the pending update")]
    AcknowledgementMismatch,
}

/// Administrator-authenticated RCU1 request and its next RVS1 snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationUpdateRequest {
    /// Stable idempotency identity.
    pub request_id: [u8; 16],
    /// RVS1 that was current when this update began.
    pub previous_revocation_digest: [u8; 32],
    /// Authenticated immediate-successor RVS1.
    pub next_revocation: SandboxRevocationSnapshot,
    /// Fresh selector nonce.
    pub selector_nonce: [u8; 16],
    /// Administrator-policy signer.
    pub policy_signer_key_id: String,
    /// Exact RCU1 self-digest.
    pub request_digest: [u8; 32],
    signature: [u8; 64],
}

impl RevocationUpdateRequest {
    /// Authenticate one RCU1 against the selector's current trust and revocation state.
    ///
    /// # Errors
    /// Rejects malformed, forged, stale, skipped, or internally inconsistent updates.
    pub fn authenticate(
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        current: &SandboxRevocationSnapshot,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        let document = decode_document(bytes)?;
        let (fields, request_digest, signature) = signed::<8>(&document, "RCU1")?;
        let next_bytes = byte_string(&fields[4])?;
        let request = Self {
            request_id: id16(&fields[2])?,
            previous_revocation_digest: digest32(&fields[3])?,
            next_revocation: SandboxRevocationSnapshot::authenticate(next_bytes, trust)?,
            selector_nonce: id16(&fields[6])?,
            policy_signer_key_id: key_id(&fields[7])?,
            request_digest,
            signature,
        };
        request.validate(fields, trust, current)?;
        Ok(request)
    }

    fn validate(
        &self,
        unsigned: &[Value; 8],
        trust: &SandboxTrustSnapshot,
        current: &SandboxRevocationSnapshot,
    ) -> Result<(), SandboxRevocationUpdateError> {
        if self.previous_revocation_digest != current.snapshot_digest()
            || digest32(&unsigned[5])? != self.next_revocation.snapshot_digest()
        {
            return Err(SandboxTrustError::AuthorityMismatch.into());
        }
        current.validate_immediate_epoch_for_same_registry(&self.next_revocation)?;
        verify_digest("RCU1", unsigned, self.request_digest)?;
        let key = current.active_key(
            trust,
            &self.policy_signer_key_id,
            SandboxTrustRole::AdministratorPolicy,
        )?;
        verify_signature("RCU1", &self.request_digest, &self.signature, &key).map_err(Into::into)
    }
}

/// Runtime-authenticated RCA1 acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationAcknowledgement {
    /// RCU1 request identity.
    pub request_id: [u8; 16],
    /// Newly installed RVS1 digest.
    pub revocation_digest: [u8; 32],
    /// Exact committed SIR1 identity.
    pub recovery_digest: [u8; 32],
    /// Exact previous provider/runtime binding committed by SIR1.
    pub previous_provider_binding_digest: [u8; 32],
    /// Canonically ordered attempts cancelled before acknowledgement.
    pub cancelled_attempt_ids: Vec<[u8; 16]>,
    /// Runtime-attestation signer.
    pub runtime_attestation_key_id: String,
    /// Exact RCA1 self-digest.
    pub acknowledgement_digest: [u8; 32],
    signature: [u8; 64],
}

impl RevocationAcknowledgement {
    /// Authenticate one RCA1 against its exact previous-runtime authority.
    ///
    /// Relationship checks against the committed SIR1 and RCC1 remain the
    /// root selector's responsibility.
    ///
    /// # Errors
    /// Rejects malformed, forged, noncanonical, nonterminal, or foreign-key
    /// acknowledgements.
    pub fn authenticate(
        bytes: &[u8],
        runtime_key_id: &str,
        runtime_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        let document = decode_document(bytes)?;
        let (fields, acknowledgement_digest, signature) = signed::<9>(&document, "RCA1")?;
        if uint(&fields[7])? != 0 {
            return Err(SandboxProviderProtocolError::InconsistentFields.into());
        }
        let cancelled_values = bounded_array(&fields[6], 0)?;
        require_canonical_order(cancelled_values)?;
        let acknowledgement = Self {
            request_id: id16(&fields[2])?,
            revocation_digest: digest32(&fields[3])?,
            recovery_digest: digest32(&fields[4])?,
            previous_provider_binding_digest: digest32(&fields[5])?,
            cancelled_attempt_ids: cancelled_values
                .iter()
                .map(id16)
                .collect::<Result<Vec<_>, _>>()?,
            runtime_attestation_key_id: key_id(&fields[8])?,
            acknowledgement_digest,
            signature,
        };
        verify_digest("RCA1", fields, acknowledgement.acknowledgement_digest)?;
        if acknowledgement.runtime_attestation_key_id != runtime_key_id {
            return Err(SandboxRevocationUpdateError::AcknowledgementMismatch);
        }
        verify_signature(
            "RCA1",
            &acknowledgement.acknowledgement_digest,
            &acknowledgement.signature,
            runtime_key,
        )?;
        Ok(acknowledgement)
    }
}
