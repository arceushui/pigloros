//! Selector-side SCQ1 and SRQ1 requests and the authentication of their
//! signed SCY1 and SRY1 answers (ADR-069 R15 §3.5, N8).

use super::{AdmittedSandboxProvider, SandboxAdmissionError};
use crate::sandbox_provider_protocol::{
    ReconciliationEvidence, ReconciliationEvidenceFields, RequestAuthority, SandboxCancelRequest,
    SandboxCancelResponse, SandboxProviderProtocolError, SandboxReconcileRequest,
    SandboxReconcileResponse,
};

/// How far the selector could check an answer against the terminal response
/// it accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalEvidenceCheck {
    /// The selector compared the answer with its accepted terminal response
    /// and they agree: for SRY1 the recomputed tuple digest (R15 §3.5 rule 2),
    /// for SCY1 the bound SPY1 digest.
    Compared,
    /// The selector holds no accepted terminal response, so only the
    /// signature and identities were checked (R15 §3.5 rule 3).
    Unverified,
}

/// One SRY1 that passed every selector check.
///
/// Only [`AdmittedSandboxProvider::authenticate_reconcile_response`] builds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReconciliation {
    response: SandboxReconcileResponse,
    check: TerminalEvidenceCheck,
}

impl AuthenticatedReconciliation {
    /// The signed response.
    #[must_use]
    pub const fn response(&self) -> &SandboxReconcileResponse {
        &self.response
    }

    /// How the evidence digest was checked.
    #[must_use]
    pub const fn check(&self) -> TerminalEvidenceCheck {
        self.check
    }
}

/// One SCY1 that passed every selector check.
///
/// Only [`AdmittedSandboxProvider::authenticate_cancel_response`] builds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCancellation {
    response: SandboxCancelResponse,
    check: TerminalEvidenceCheck,
}

impl AuthenticatedCancellation {
    /// The signed response.
    #[must_use]
    pub const fn response(&self) -> &SandboxCancelResponse {
        &self.response
    }

    /// Whether the bound SPY1 digest was compared with the accepted one.
    #[must_use]
    pub const fn check(&self) -> TerminalEvidenceCheck {
        self.check
    }
}

const fn contradiction() -> SandboxAdmissionError {
    SandboxAdmissionError::Protocol(SandboxProviderProtocolError::InconsistentFields)
}

impl AdmittedSandboxProvider {
    const fn request_authority(&self, request_id: [u8; 16], nonce: [u8; 16]) -> RequestAuthority {
        RequestAuthority {
            request_id,
            apt1_digest: self.policy.policy_digest(),
            policy_epoch: self.policy.policy_epoch(),
            nonce,
        }
    }

    /// Build the SCQ1 that cancels `attempt_id`, bound to its AGR1 digest and
    /// to this provider's active APT1 and epoch.
    ///
    /// # Errors
    /// Rejects a zero request ID, nonce, attempt ID or AGR1 digest.
    pub fn cancel_request(
        &self,
        request_id: [u8; 16],
        nonce: [u8; 16],
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<(SandboxCancelRequest, Vec<u8>), SandboxProviderProtocolError> {
        SandboxCancelRequest::canonical(
            self.request_authority(request_id, nonce),
            attempt_id,
            agr1_digest,
        )
    }

    /// Build the SRQ1 that reconciles `attempt_id`, bound to its AGR1 digest
    /// and to this provider's active APT1 and epoch.
    ///
    /// # Errors
    /// Rejects a zero request ID, nonce, attempt ID or AGR1 digest.
    pub fn reconcile_request(
        &self,
        request_id: [u8; 16],
        nonce: [u8; 16],
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<(SandboxReconcileRequest, Vec<u8>), SandboxProviderProtocolError> {
        SandboxReconcileRequest::canonical(
            self.request_authority(request_id, nonce),
            attempt_id,
            agr1_digest,
        )
    }

    /// Authenticate one SCY1 against the SCQ1 it answers.
    ///
    /// The key ID is compared with the admitted manifest first, then the
    /// signature is verified under the admitted runtime key, then the request
    /// identities are checked. When the selector accepted the attempt's
    /// terminal SPY1, `accepted_spy1_digest` must equal the digest the SCY1
    /// binds (R15 §3.5, "also equals every SCY1 SPY1 digest"). That check is
    /// an addition to R15 §3.3 to §3.5, not a prescribed selector rule, and
    /// refuses with `InconsistentFields` by analogy with SRY1.
    ///
    /// # Errors
    /// Rejects a malformed, foreign-keyed, forged, unbound or contradicting
    /// response.
    pub fn authenticate_cancel_response(
        &self,
        bytes: &[u8],
        request: &SandboxCancelRequest,
        accepted_spy1_digest: Option<[u8; 32]>,
    ) -> Result<AuthenticatedCancellation, SandboxAdmissionError> {
        let response = SandboxCancelResponse::from_canonical_cbor(bytes)?;
        self.require_runtime_key_id(&response.runtime_attestation_key_id)?;
        response.verify_signature(&self.runtime_key)?;
        response.validate_for_request(request)?;
        accepted_spy1_digest
            .map_or(Ok(TerminalEvidenceCheck::Unverified), |accepted| {
                (accepted == response.terminal_spy1_digest)
                    .then_some(TerminalEvidenceCheck::Compared)
                    .ok_or_else(contradiction)
            })
            .map(|check| AuthenticatedCancellation { response, check })
    }

    /// Authenticate one SRY1 against the SRQ1 it answers (R15 §3.5, N8).
    ///
    /// 1. The key ID is compared with the admitted manifest, then the
    ///    signature is verified under the admitted runtime key, then the
    ///    identities are validated against the request.
    /// 2. With `accepted` terminal digests, the selector recomputes
    ///    `reconciliation-evidence-v1` and requires a byte-equal digest. A
    ///    mismatch is a signed provider contradiction and is refused.
    /// 3. Without them, the digest is accepted on rule 1 alone and reported
    ///    as [`TerminalEvidenceCheck::Unverified`].
    ///
    /// # Errors
    /// Rejects a malformed, foreign-keyed, forged, unbound or contradicting
    /// response, and `accepted` digests that do not name the requested attempt.
    pub fn authenticate_reconcile_response(
        &self,
        bytes: &[u8],
        request: &SandboxReconcileRequest,
        accepted: Option<&ReconciliationEvidenceFields>,
    ) -> Result<AuthenticatedReconciliation, SandboxAdmissionError> {
        let response = SandboxReconcileResponse::from_canonical_cbor(bytes)?;
        self.require_runtime_key_id(&response.runtime_attestation_key_id)?;
        response.verify_signature(&self.runtime_key)?;
        response.validate_for_request(request)?;
        accepted
            .map_or(Ok(TerminalEvidenceCheck::Unverified), |fields| {
                recompute_matches(fields, request, &response)
                    .then_some(TerminalEvidenceCheck::Compared)
                    .ok_or_else(contradiction)
            })
            .map(|check| AuthenticatedReconciliation { response, check })
    }

    fn require_runtime_key_id(&self, key_id: &str) -> Result<(), SandboxAdmissionError> {
        (key_id == self.manifest.runtime_attestation_key_id)
            .then_some(())
            .ok_or(SandboxAdmissionError::ConformanceMismatch)
    }
}

/// R15 §3.5 rule 2: the tuple names the requested attempt and AGR1, and its
/// digest equals the signed one.
fn recompute_matches(
    fields: &ReconciliationEvidenceFields,
    request: &SandboxReconcileRequest,
    response: &SandboxReconcileResponse,
) -> bool {
    fields.attempt_id == request.attempt_id
        && fields.agr1_digest == request.agr1_digest
        && ReconciliationEvidence::new(fields)
            .is_ok_and(|evidence| evidence.digest() == response.reconciliation_evidence_digest)
}

#[cfg(test)]
mod tests;
