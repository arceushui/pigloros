//! The guest test client's view of the selector provider transport.
//!
//! Compiled only with the `test-support` feature. It wraps the one selector
//! transport (execute, SCQ1 and SRQ1) without a second protocol
//! implementation: the endpoint stays root-owned and every connection must
//! come from the named provider process (ADR-069 R11 §5.0 step 8).

use std::io::{Read, Seek};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::Duration;

use super::{
    process_start_time_ticks, provider_transport, require_root_owned_endpoint,
    AuthenticatedProviderExecution, AuthenticatedProviderTerminal, PostAdmissionProviderFailure,
    ProviderControlError, ProviderControlRefusal, ProviderTransport, ProviderTransportError,
    SelectedProviderEndpoint, UnfencedProviderRequest, ROOT_UID,
};
use crate::evaluator_protocol::EvaluationRequest;
use crate::sandbox_provider_protocol::{
    AdmittedSandboxProvider, AuthenticatedCancellation, AuthenticatedReconciliation,
    PayloadDescriptor, ReconciliationEvidenceFields, SandboxAdmissionError, SandboxCancelRequest,
    SandboxReconcileRequest, SelectorGrantCommitment,
};
use crate::selector::SelectorBoundaryError;

/// The selector provider transport of one guest test run.
#[derive(Debug)]
pub struct GuestProviderClient(ProviderTransport);

impl GuestProviderClient {
    /// A client for the root-owned execute socket of the provider process
    /// `main_pid`; its start time is read here.
    ///
    /// # Errors
    /// Fails closed when the socket is absent, replaced, insecure or outside
    /// a root-owned directory chain, or when the process is not running.
    pub fn for_provider_process(
        execute_socket: &Path,
        main_pid: NonZeroU64,
    ) -> Result<Self, SelectorBoundaryError> {
        Self::bound_to_process(
            execute_socket,
            ROOT_UID,
            require_root_owned_endpoint,
            main_pid,
        )
    }

    fn bound_to_process<'a>(
        execute_socket: &'a Path,
        owner: u32,
        validate: impl Fn(&'a Path) -> Result<&'a Path, SelectorBoundaryError>,
        main_pid: NonZeroU64,
    ) -> Result<Self, SelectorBoundaryError> {
        process_start_time_ticks(main_pid).and_then(|ticks| {
            SelectedProviderEndpoint::from_paths_with_validation(
                execute_socket,
                execute_socket,
                owner,
                validate,
            )
            .map(|(execute, control)| {
                Self(provider_transport(execute, control).expecting(main_pid.get(), ticks))
            })
        })
    }

    /// Run one SPX1 exchange with its staged input.
    ///
    /// # Errors
    /// [`GuestExecuteError`] says whether an AGR1 was authenticated.
    pub fn execute(
        &self,
        admitted: &AdmittedSandboxProvider,
        commitment: &SelectorGrantCommitment,
        evaluation: &EvaluationRequest,
        spx1: &[u8],
        input: &mut (impl Read + Seek),
        watchdog: Duration,
    ) -> Result<GuestTerminal, GuestExecuteError> {
        self.0
            .execute_staged(
                admitted,
                commitment,
                evaluation,
                spx1,
                input,
                watchdog,
                &mut UnfencedProviderRequest,
            )
            .map(GuestTerminal::from)
            .map_err(GuestExecuteError::from)
    }

    /// Send one SCQ1 and authenticate its SCY1.
    ///
    /// # Errors
    /// [`GuestControlError`] for an unreachable provider, a refusal, or an
    /// answer that fails authentication.
    pub fn cancel(
        &self,
        admitted: &AdmittedSandboxProvider,
        request: &SandboxCancelRequest,
        bytes: &[u8],
        accepted_spy1_digest: Option<[u8; 32]>,
        timeout: Duration,
    ) -> Result<AuthenticatedCancellation, GuestControlError> {
        self.0
            .cancel(admitted, request, bytes, accepted_spy1_digest, timeout)
            .map_err(GuestControlError::from)
    }

    /// Send one SRQ1 and authenticate its SRY1, recomputing the tuple when
    /// `accepted` is given.
    ///
    /// # Errors
    /// [`GuestControlError`] for an unreachable provider, a refusal, or an
    /// answer that fails authentication or contradicts `accepted`.
    pub fn reconcile(
        &self,
        admitted: &AdmittedSandboxProvider,
        request: &SandboxReconcileRequest,
        bytes: &[u8],
        accepted: Option<&ReconciliationEvidenceFields>,
        timeout: Duration,
    ) -> Result<AuthenticatedReconciliation, GuestControlError> {
        self.0
            .reconcile(admitted, request, bytes, accepted, timeout)
            .map_err(GuestControlError::from)
    }
}

/// One authenticated reply of the provider.
#[derive(Debug)]
pub enum GuestTerminal {
    /// AGR1, SPR1, SPY1 and the SAU1 chain.
    Execution(GuestExecution),
    /// The exact authenticated SPE1 bytes of a pre-admission refusal.
    Error(Vec<u8>),
}

impl From<AuthenticatedProviderTerminal> for GuestTerminal {
    fn from(terminal: AuthenticatedProviderTerminal) -> Self {
        match terminal {
            AuthenticatedProviderTerminal::Execution(execution) => {
                Self::Execution(GuestExecution(execution))
            }
            AuthenticatedProviderTerminal::Error(error) => Self::Error(error),
        }
    }
}

/// Complete provider evidence, authenticated against the admitted provider.
#[derive(Debug)]
pub struct GuestExecution(AuthenticatedProviderExecution);

impl GuestExecution {
    /// The AGR1 self-digest.
    #[must_use]
    pub const fn agr1_digest(&self) -> [u8; 32] {
        self.0.agr1_digest()
    }

    /// The digests the selector recomputes the reconciliation tuple from.
    #[must_use]
    pub fn accepted_evidence(&self, attempt_id: [u8; 16]) -> Option<ReconciliationEvidenceFields> {
        self.0.accepted_evidence(attempt_id)
    }

    /// The exact AGR1 bytes.
    #[must_use]
    pub fn agr1_bytes(&self) -> &[u8] {
        self.0.agr1_bytes()
    }

    /// The exact SPR1 bytes.
    #[must_use]
    pub fn spr1_bytes(&self) -> &[u8] {
        self.0.spr1_bytes()
    }

    /// The exact terminal SPY1 bytes.
    #[must_use]
    pub fn spy1_bytes(&self) -> &[u8] {
        self.0.spy1_bytes()
    }

    /// The exact SAU1 bytes in received order.
    #[must_use]
    pub fn sau1_frames(&self) -> &[Vec<u8>] {
        self.0.sau1_frames()
    }

    /// The verified output descriptor with a stream of its exact bytes.
    ///
    /// # Errors
    /// A closed I/O failure, or the failure `compose` returns.
    pub fn with_verified_output<T>(
        &mut self,
        compose: impl FnOnce(&PayloadDescriptor, &mut dyn Read) -> Result<T, SelectorBoundaryError>,
    ) -> Result<Option<T>, SelectorBoundaryError> {
        self.0.with_verified_output(compose)
    }

    /// The evidence and the verified output stream together.
    ///
    /// # Errors
    /// A closed I/O failure, or the failure `compose` returns.
    pub fn with_verified_reply_output<T>(
        &mut self,
        compose: impl FnOnce(
            &[u8],
            &[u8],
            &[u8],
            &[Vec<u8>],
            &PayloadDescriptor,
            &mut dyn Read,
        ) -> Result<T, SelectorBoundaryError>,
    ) -> Result<Option<T>, SelectorBoundaryError> {
        self.0.with_verified_reply_output(compose)
    }
}

/// Why an execute exchange produced no authenticated terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestExecuteError {
    /// No AGR1 was authenticated.
    #[error("provider execution failed before admission")]
    BeforeAdmission,
    /// An authenticated AGR1 forbids fallback, and no terminal arrived.
    #[error("provider terminal unavailable after admission")]
    TerminalUnavailable {
        /// The authenticated AGR1 digest.
        agr1_digest: [u8; 32],
    },
    /// A frame or relationship after the AGR1 was invalid.
    #[error("provider evidence invalid after admission")]
    EvidenceInvalid {
        /// The authenticated AGR1 digest.
        agr1_digest: [u8; 32],
    },
}

impl From<ProviderTransportError> for GuestExecuteError {
    fn from(error: ProviderTransportError) -> Self {
        match error {
            ProviderTransportError::BeforeAdmission => Self::BeforeAdmission,
            ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure: PostAdmissionProviderFailure::TerminalUnavailable,
            } => Self::TerminalUnavailable { agr1_digest },
            ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure: PostAdmissionProviderFailure::EvidenceInvalid,
            } => Self::EvidenceInvalid { agr1_digest },
        }
    }
}

/// The class of an authenticated SPE1 answering SCQ1 or SRQ1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestRefusal {
    /// SPE1 `11`: the response was still pending.
    Pending,
    /// SPE1 `12`: the control pool or the request ledger is full.
    Busy,
    /// SPE1 `14`: the attempt cannot be proved clean now.
    CleanupFailed,
    /// SPE1 `15`: the attempt and grant pair is unknown.
    UnknownAttempt,
    /// SPE1 `16`: the request ID was reused with other bytes.
    RequestIdReuse,
    /// Any other authenticated code.
    Other,
}

impl From<ProviderControlRefusal> for GuestRefusal {
    fn from(refusal: ProviderControlRefusal) -> Self {
        match refusal {
            ProviderControlRefusal::Pending11 => Self::Pending,
            ProviderControlRefusal::Busy12 => Self::Busy,
            ProviderControlRefusal::CleanupFailed14 => Self::CleanupFailed,
            ProviderControlRefusal::UnknownAttempt15 => Self::UnknownAttempt,
            ProviderControlRefusal::RequestIdReuse16 => Self::RequestIdReuse,
            ProviderControlRefusal::Other => Self::Other,
        }
    }
}

/// Why one cancel or reconcile produced no authenticated success.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestControlError {
    /// The provider could not be reached or framed its answer incorrectly.
    #[error("provider control exchange failed: {0}")]
    Unreachable(SelectorBoundaryError),
    /// The provider answered with an authenticated SPE1.
    #[error("provider refused the control request: {0:?}")]
    Refused(GuestRefusal),
    /// The answer failed authentication or contradicted the selector.
    #[error("provider control answer was rejected: {0}")]
    Rejected(SandboxAdmissionError),
}

impl From<ProviderControlError> for GuestControlError {
    fn from(error: ProviderControlError) -> Self {
        match error {
            ProviderControlError::Boundary(error) => Self::Unreachable(error),
            ProviderControlError::Refused(refusal) => Self::Refused(refusal.into()),
            ProviderControlError::Evidence(error) => Self::Rejected(error),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
