//! Selector cancel and reconcile over the provider's execute socket
//! (ADR-069 R15 §3.3, §3.5 and N13).
//!
//! One SCQ1 or SRQ1 per connection. The answer is a signed SCY1 or SRY1, or an
//! authenticated SPE1 that is mapped to a closed refusal.

use std::time::Duration;

use super::{
    record_magic, Deadline, ProviderControlError, ProviderControlRefusal, ProviderTransport,
};
use crate::sandbox_provider_protocol::{
    AdmittedSandboxProvider, AuthenticatedCancellation, AuthenticatedReconciliation,
    ReconciliationEvidenceFields, RequestAuthority, SandboxCancelRequest, SandboxProviderOperation,
    SandboxReconcileRequest,
};

/// The request identities an SPE1 answer must bind.
struct ControlRequest<'a> {
    operation: SandboxProviderOperation,
    authority: &'a RequestAuthority,
    request_digest: [u8; 32],
    attempt_id: [u8; 16],
    bytes: &'a [u8],
}

impl ProviderTransport {
    /// Send one SCQ1 and authenticate its SCY1.
    ///
    /// `accepted_spy1_digest` is the SPY1 digest the caller accepted, if any. The
    /// production selector passes `None`; the test-support guest client may not.
    ///
    /// # Errors
    /// [`ProviderControlError`] for an unreachable provider, an authenticated
    /// refusal, or an unauthenticated or contradicting answer.
    pub(crate) fn cancel(
        &self,
        admitted: &AdmittedSandboxProvider,
        request: &SandboxCancelRequest,
        bytes: &[u8],
        accepted_spy1_digest: Option<[u8; 32]>,
        timeout: Duration,
    ) -> Result<AuthenticatedCancellation, ProviderControlError> {
        let control = ControlRequest {
            operation: SandboxProviderOperation::Cancel,
            authority: &request.request,
            request_digest: request.request_digest,
            attempt_id: request.attempt_id,
            bytes,
        };
        self.control_answer(admitted, &control, timeout)
            .and_then(|answer| {
                admitted
                    .authenticate_cancel_response(&answer, request, accepted_spy1_digest)
                    .map_err(ProviderControlError::from)
            })
    }

    /// Send one SRQ1 and authenticate its SRY1, recomputing the R15 tuple
    /// when `accepted` is given (N8).
    ///
    /// # Errors
    /// [`ProviderControlError`] for an unreachable provider, an authenticated
    /// refusal, or an unauthenticated or contradicting answer.
    pub(crate) fn reconcile(
        &self,
        admitted: &AdmittedSandboxProvider,
        request: &SandboxReconcileRequest,
        bytes: &[u8],
        accepted: Option<&ReconciliationEvidenceFields>,
        timeout: Duration,
    ) -> Result<AuthenticatedReconciliation, ProviderControlError> {
        let control = ControlRequest {
            operation: SandboxProviderOperation::Reconcile,
            authority: &request.request,
            request_digest: request.request_digest,
            attempt_id: request.attempt_id,
            bytes,
        };
        self.control_answer(admitted, &control, timeout)
            .and_then(|answer| {
                admitted
                    .authenticate_reconcile_response(&answer, request, accepted)
                    .map_err(ProviderControlError::from)
            })
    }

    /// The one answer frame, or the refusal an authenticated SPE1 carries.
    fn control_answer(
        &self,
        admitted: &AdmittedSandboxProvider,
        control: &ControlRequest<'_>,
        timeout: Duration,
    ) -> Result<Vec<u8>, ProviderControlError> {
        Deadline::new(timeout)
            .and_then(|deadline| {
                self.exchange_on_execute_socket(control.bytes, &deadline, |process| {
                    self.require_admitted_process(process)
                })
            })
            .map_err(ProviderControlError::from)
            .and_then(|(answer, _)| {
                if record_magic(&answer).is_ok_and(|magic| magic == "SPE1") {
                    admitted
                        .authenticate_control_error(
                            &answer,
                            control.operation,
                            control.authority,
                            control.request_digest,
                            control.attempt_id,
                        )
                        .map_err(ProviderControlError::from)
                        .and_then(|code| {
                            Err(ProviderControlError::Refused(
                                ProviderControlRefusal::from_code(code),
                            ))
                        })
                } else {
                    Ok(answer)
                }
            })
    }
}

#[cfg(test)]
mod tests;
