//! The selector's SCQ1 and SRQ1 toward one provider attempt (ADR-069 R15
//! §3.3 and §3.5; owner decisions on #1503).
//!
//! SRQ1 follows every terminal the selector writes to the evaluator, while it
//! still holds the accepted digests of the N8 recompute. SCQ1 follows an
//! exhausted recovery or an evaluator that hung up while the attempt ran.
//! Every request ID and nonce is derived in code from the attempt, the
//! operation and the retry index, so an exact repeat is byte-identical (R15
//! N11). The provider keeps at most 4 SCQ1/SRQ1 entries per attempt, so one
//! call sends at most 4 distinct requests, and all of them, with the exact
//! repeat, share one overall budget: the provider holds a control-pool worker
//! for each (R15 N13).

use std::time::{Duration, Instant};

use super::recovery_pending::report_diagnostic;
use super::{DiagnosticSink, ProviderExecutor};
use crate::provider_transport::ProviderControlError;
use crate::sandbox_provider_protocol::{
    AdmittedSandboxProvider, ReconciliationEvidenceFields, SandboxAdmissionError,
    SandboxProviderOperation, SandboxProviderProtocolError, TerminalEvidenceCheck,
};
use crate::selector::SelectorBoundaryError;

const MAX_DISTINCT_REQUESTS: u8 = 4;
/// The BHC1 limit ID of the provider's pending-response wait, in
/// milliseconds (ADR-069 R15 §3.3, R11 Amendment 1 P1).
const PENDING_WAIT_LIMIT_ID: u8 = 16;
/// What the selector adds to the provider's own wait for framing, signing and
/// scheduling.
const CONTROL_MARGIN: Duration = Duration::from_secs(5);
const REQUEST_ID_DOMAIN: &[u8] = b"PiglorOS.SelectorControlRequestId.v1\0";
const NONCE_DOMAIN: &[u8] = b"PiglorOS.SelectorControlNonce.v1\0";

fn derive(
    domain: &[u8],
    attempt_id: [u8; 16],
    operation: SandboxProviderOperation,
    index: u8,
) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&attempt_id);
    hasher.update(&operation.wire_code().to_be_bytes());
    hasher.update(&[index]);
    let mut identity = [0; 16];
    identity.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    identity
}

/// The exchange budget of one control operation: the provider waits up to
/// BHC1 limit 16 for a pending response, read here from the same installed
/// caps, plus a fixed margin.
pub(super) fn control_budget(admitted: &AdmittedSandboxProvider) -> Duration {
    let wait = admitted
        .broker_hard_caps()
        .iter()
        .find(|limit| limit.limit_id == PENDING_WAIT_LIMIT_ID)
        .map_or(0, |limit| limit.value);
    Duration::from_millis(wait).saturating_add(CONTROL_MARGIN)
}

/// One attempt of one admitted provider runtime.
pub(super) struct AttemptControl<'a, T: ProviderExecutor> {
    pub(super) transport: &'a T,
    pub(super) admitted: &'a AdmittedSandboxProvider,
    pub(super) attempt_id: [u8; 16],
    pub(super) agr1_digest: [u8; 32],
    /// The overall budget of SRQ1 (see [`control_budget`]).
    pub(super) timeout: Duration,
    /// How long the attempt itself may still run: SCQ1 waits for it to end
    /// before the provider's own interval starts (R15 §3.6 item 2(a)).
    pub(super) active_wait: Duration,
    pub(super) diagnostics: &'a DiagnosticSink,
}

impl<T: ProviderExecutor> AttemptControl<'_, T> {
    /// The request ID and nonce of retry `index` of `operation`.
    fn identities(&self, operation: SandboxProviderOperation, index: u8) -> ([u8; 16], [u8; 16]) {
        (
            derive(REQUEST_ID_DOMAIN, self.attempt_id, operation, index),
            derive(NONCE_DOMAIN, self.attempt_id, operation, index),
        )
    }

    /// Reconcile the attempt whose terminal the selector accepted, and
    /// report what the evidence check could and could not prove.
    pub(super) fn reconcile(&self, accepted: Option<&ReconciliationEvidenceFields>) {
        let result = retrying(self.timeout, |index, left| {
            let (request_id, nonce) = self.identities(SandboxProviderOperation::Reconcile, index);
            self.admitted
                .reconcile_request(request_id, nonce, self.attempt_id, self.agr1_digest)
                .map_err(protocol_failure)
                .and_then(|(request, bytes)| {
                    self.transport
                        .reconcile(self.admitted, &request, &bytes, accepted, left)
                })
        });
        match result {
            Ok(verified) if verified.check() == TerminalEvidenceCheck::Unverified => {
                self.report(
                    "provider reconcile digest is unverified",
                    &"no accepted terminal",
                );
            }
            Ok(_) => {}
            Err(error) => self.report("provider reconcile failed", &error),
        }
    }

    /// After an exhausted recovery: cancel the attempt, then reconcile it
    /// with no accepted terminal, because the selector wrote a terminal to
    /// the evaluator all the same (owner decisions on #1503).
    pub(super) fn settle_exhausted(&self) {
        self.cancel();
        self.reconcile(None);
    }

    /// SCQ1 waits for a still running attempt to end, then for the provider's
    /// own interval.
    const fn cancel_budget(&self) -> Duration {
        self.timeout.saturating_add(self.active_wait)
    }

    /// Cancel the attempt: its recovery was exhausted, or the evaluator hung
    /// up while it ran.
    pub(super) fn cancel(&self) {
        let result = retrying(self.cancel_budget(), |index, left| {
            let (request_id, nonce) = self.identities(SandboxProviderOperation::Cancel, index);
            self.admitted
                .cancel_request(request_id, nonce, self.attempt_id, self.agr1_digest)
                .map_err(protocol_failure)
                .and_then(|(request, bytes)| {
                    self.transport
                        .cancel(self.admitted, &request, &bytes, None, left)
                })
        });
        if let Err(error) = result {
            self.report("provider cancel failed", &error);
        }
    }

    fn report(&self, what: &str, error: &impl std::fmt::Display) {
        report_diagnostic(self.diagnostics, what, error);
    }
}

fn protocol_failure(error: SandboxProviderProtocolError) -> ProviderControlError {
    ProviderControlError::from(SandboxAdmissionError::from(error))
}

/// What remains of `budget` after `elapsed`, if anything.
fn remaining(budget: Duration, elapsed: Duration) -> Option<Duration> {
    budget.checked_sub(elapsed).filter(|left| !left.is_zero())
}

/// Only a transient failure of the exchange is worth one exact repeat; a
/// replaced endpoint or a foreign process is not.
const fn is_transient(error: SelectorBoundaryError) -> bool {
    matches!(
        error,
        SelectorBoundaryError::SelectorUnavailable | SelectorBoundaryError::Io
    )
}

/// Send `attempt(index, left)` within one overall `budget`. A transient
/// failure gets one exact repeat. A retryable refusal gets the next distinct
/// request, up to the N11 bound.
fn retrying<R>(
    budget: Duration,
    mut attempt: impl FnMut(u8, Duration) -> Result<R, ProviderControlError>,
) -> Result<R, ProviderControlError> {
    let started = Instant::now();
    let mut index = 0;
    let mut repeated = false;
    loop {
        let Some(left) = remaining(budget, started.elapsed()) else {
            return Err(ProviderControlError::Boundary(
                SelectorBoundaryError::SelectorUnavailable,
            ));
        };
        match attempt(index, left) {
            Err(ProviderControlError::Boundary(error)) if !repeated && is_transient(error) => {
                repeated = true;
            }
            Err(ProviderControlError::Refused(refusal))
                if refusal.is_retryable() && index + 1 < MAX_DISTINCT_REQUESTS =>
            {
                index += 1;
            }
            outcome => return outcome,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
