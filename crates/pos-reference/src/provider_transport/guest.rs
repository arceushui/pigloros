//! The guest test client's view of the selector provider transport.
//!
//! Compiled only with the `test-support` feature. It wraps the one selector
//! transport (execute, status via SDQ1, SCQ1 and SRQ1) without a second protocol
//! implementation: the endpoint stays root-owned and every connection must
//! come from the named provider process (ADR-069 R11 §5.0 step 8).
//!
//! [`GuestExecuteError`], [`GuestRefusal`] and [`GuestControlError`] mirror the
//! crate-private transport enums by design: the transport types stay private,
//! and only this feature exposes their closed classes.

use std::fmt::Write as _;
use std::io::{Read, Seek};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{
    process_start_time_ticks, provider_transport, require_root_owned_endpoint,
    AuthenticatedProviderExecution, AuthenticatedProviderTerminal, PostAdmissionProviderFailure,
    ProviderControlError, ProviderControlRefusal, ProviderTransport, ProviderTransportError,
    SelectedProviderEndpoint, UnfencedProviderRequest, ROOT_UID,
};
use crate::evaluator_protocol::EvaluationRequest;
use crate::root_selector::selected_image_and_launch;
use crate::sandbox_provider_protocol::{
    AdmittedSandboxProvider, AuthenticatedCancellation, AuthenticatedReconciliation,
    PayloadDescriptor, ReconciliationEvidenceFields, SandboxAdmissionError, SandboxCancelRequest,
    SandboxProviderError, SandboxProviderErrorCode, SandboxProviderReceipt, SandboxProviderResult,
    SandboxReconcileRequest, SelectorGrantCommitment,
};
use crate::selector::installation::authority::AdmittedSelectorProvider;
use crate::selector::SelectorBoundaryError;

/// How long a guest execute waits, after one `Starting` or `ReconcileFailed` refusal, before it
/// asks again.
const OPEN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

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

    /// [`Self::for_provider_process`] for the execute socket that SIC1 names.
    ///
    /// # Errors
    /// As [`Self::for_provider_process`].
    pub fn for_admitted_provider(
        admitted: &AdmittedSelectorProvider,
        main_pid: NonZeroU64,
    ) -> Result<Self, SelectorBoundaryError> {
        Self::for_provider_process(admitted.selected_provider_sockets().0, main_pid)
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

    /// The grant commitment and watchdog the selector derives for case `ordinal` of `evaluation`.
    ///
    /// This is exactly the selector's three steps (`root_selector`): resolve the installed case,
    /// select and admit the image and launch policy at `now_secs`, and derive the commitment from
    /// the admitted provider, the EVR1 request and the case's EAI1 attempt, with no network plan.
    ///
    /// # Errors
    /// [`GuestCommitmentError`] when the evaluation names no sandbox requirement, the case does
    /// not resolve, the image or launch policy is refused, or the commitment cannot be derived.
    pub fn commitment(
        admitted: &AdmittedSelectorProvider,
        evaluation: &EvaluationRequest,
        ordinal: u16,
        now_secs: u64,
    ) -> Result<GuestCommitment, GuestCommitmentError> {
        let requirement = evaluation
            .sandbox_requirement
            .as_ref()
            .ok_or(GuestCommitmentError)?;
        let resolved = admitted
            .bootstrap()
            .resolve_installed_case(evaluation, ordinal)
            .map_err(commitment_refused)?;
        let (image, launch) = selected_image_and_launch(admitted, requirement, now_secs)
            .map_err(commitment_refused)?;
        let commitment = admitted
            .provider()
            .derive_selector_grant_commitment(
                &image.image,
                &launch,
                evaluation,
                resolved.attempt(),
                &[],
            )
            .map_err(commitment_refused)?;
        Ok(GuestCommitment {
            commitment,
            watchdog: Duration::from_millis(resolved.attempt().watchdog_ms),
        })
    }

    /// Run one SPX1 exchange, asking again while the provider answers `Starting` or
    /// `ReconcileFailed` (SPE1 `11`), until `window` has elapsed on `clock`.
    ///
    /// # Errors
    /// [`GuestWaitError`]: a transport failure, or the last refusal once the window is over or
    /// for any other refusal.
    pub fn execute_when_open(
        &self,
        admitted: &AdmittedSandboxProvider,
        grant: &GuestCommitment,
        job: &GuestExecuteJob<'_>,
        input: &mut (impl Read + Seek),
        clock: &impl GuestClock,
        window: Duration,
    ) -> Result<GuestExecution, GuestWaitError> {
        until_open(
            || {
                self.execute(
                    admitted,
                    &grant.commitment,
                    job.evaluation,
                    job.spx1,
                    &mut *input,
                    grant.watchdog,
                )
                .map(classify)
            },
            clock,
            window,
        )
    }

    /// [`Self::execute_when_open`] reported as text: the lines of [`GuestExecution::report`], or
    /// the one `execute` line of an exchange that produced no execution.
    ///
    /// An execution whose records cannot be reported is the one line `execute unreportable`, which
    /// the guest checker refuses.
    pub fn execute_report(
        &self,
        admitted: &AdmittedSandboxProvider,
        grant: &GuestCommitment,
        job: &GuestExecuteJob<'_>,
        input: &mut (impl Read + Seek),
        clock: &impl GuestClock,
        window: Duration,
    ) -> Vec<String> {
        match self.execute_when_open(admitted, grant, job, input, clock, window) {
            Ok(execution) => executed_lines(execution),
            Err(error) => vec![failure_line(error)],
        }
    }

    /// Status: one SDQ1 whose runtime-signed SDY1 proves that the provider
    /// has activated the admitted policy (the selector's own revocation
    /// synchronisation).
    ///
    /// # Errors
    /// Fails closed when the provider is unreachable or its answer fails
    /// authentication.
    pub fn describe(
        &self,
        admitted: &AdmittedSandboxProvider,
        request_id: [u8; 16],
        nonce: [u8; 16],
        timeout: Duration,
    ) -> Result<(), SelectorBoundaryError> {
        self.0
            .synchronize_revocation(admitted, request_id, nonce, timeout)
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

/// The EVR1 request and the SPX1 bytes of one execute.
#[derive(Clone, Copy, Debug)]
pub struct GuestExecuteJob<'a> {
    /// The authenticated EVR1 request.
    pub evaluation: &'a EvaluationRequest,
    /// The exact SPX1 bytes.
    pub spx1: &'a [u8],
}

/// What the selector derives for one case before an execute.
#[derive(Debug)]
pub struct GuestCommitment {
    /// The grant commitment of the SPX1 request.
    pub commitment: SelectorGrantCommitment,
    /// The attempt's watchdog.
    pub watchdog: Duration,
}

/// The selector could not derive a grant commitment for the case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the selector could not derive the grant commitment of the case")]
pub struct GuestCommitmentError;

fn commitment_refused<E>(_: E) -> GuestCommitmentError {
    GuestCommitmentError
}

/// The monotonic time and pause that `execute_when_open` waits with.
pub trait GuestClock {
    /// The time elapsed since the wait began.
    fn elapsed(&self) -> Duration;
    /// Wait `interval` before asking again.
    fn pause(&self, interval: Duration);
}

/// The system's monotonic clock, from the moment it is created.
#[derive(Debug)]
pub struct GuestInstantClock(Instant);

impl GuestInstantClock {
    /// A clock that starts now.
    #[must_use]
    pub fn start() -> Self {
        Self(Instant::now())
    }
}

impl GuestClock for GuestInstantClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    fn pause(&self, interval: Duration) {
        std::thread::sleep(interval);
    }
}

/// How one exchange ended, as the wait sees it.
#[derive(Debug, Eq, PartialEq)]
enum Exchange<T> {
    /// The provider executed and answered.
    Done(T),
    /// The provider refused with an authenticated SPE1 of this code, if it decodes.
    Refused(Option<SandboxProviderErrorCode>),
}

fn classify(terminal: GuestTerminal) -> Exchange<GuestExecution> {
    match terminal {
        GuestTerminal::Execution(execution) => Exchange::Done(execution),
        error @ GuestTerminal::Error(_) => Exchange::Refused(error.refusal_code()),
    }
}

/// Ask again after an SPE1 `11` answer while `clock` is inside `window` when it arrives.
///
/// The window bounds when a refused exchange is asked again. It does not bound one exchange,
/// which the case's own deadline bounds, so one slow exchange may spend the whole window.
fn until_open<T>(
    mut exchange: impl FnMut() -> Result<Exchange<T>, GuestExecuteError>,
    clock: &impl GuestClock,
    window: Duration,
) -> Result<T, GuestWaitError> {
    loop {
        match exchange().map_err(GuestWaitError::Execute)? {
            Exchange::Done(value) => return Ok(value),
            Exchange::Refused(Some(SandboxProviderErrorCode::SandboxUnavailable))
                if clock.elapsed() < window =>
            {
                clock.pause(OPEN_RETRY_INTERVAL);
            }
            Exchange::Refused(code) => return Err(GuestWaitError::Refused(code)),
        }
    }
}

/// Why `execute_when_open` produced no execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestWaitError {
    /// The exchange failed.
    #[error("provider execute failed: {0}")]
    Execute(GuestExecuteError),
    /// The provider refused, with this closed code if its SPE1 decodes. `Starting` and
    /// `ReconcileFailed` (`11`) are the last answer when the window ended.
    #[error("provider refused the execute: {0:?}")]
    Refused(Option<SandboxProviderErrorCode>),
}

/// One authenticated reply of the provider.
#[derive(Debug)]
pub enum GuestTerminal {
    /// AGR1, SPR1, SPY1 and the SAU1 chain.
    Execution(GuestExecution),
    /// The exact authenticated SPE1 bytes of a pre-admission refusal.
    Error(Vec<u8>),
}

impl GuestTerminal {
    /// The closed failure code of an authenticated SPE1 refusal, if it decodes.
    #[must_use]
    pub fn refusal_code(&self) -> Option<SandboxProviderErrorCode> {
        match self {
            Self::Error(bytes) => SandboxProviderError::from_canonical_cbor(bytes)
                .ok()
                .map(|error| error.code),
            Self::Execution(_) => None,
        }
    }
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
    pub const fn accepted_evidence(&self, attempt_id: [u8; 16]) -> ReconciliationEvidenceFields {
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

    /// The guest evidence of this execution: `execute executed`, then one `NAME<TAB>VALUE` line
    /// each.
    ///
    /// These are the selector's own observations: the SPY1 outcome and SAU1 event codes, whether
    /// SPR1 names a `ReadyV1` and a `ReleaseV1`, the RQE1, KOE1 and TME1 digests SPR1 carries, the
    /// BLAKE3 digests of the signed raw bytes and, when the execution staged an output, the length
    /// and digest of the verified output bytes.
    /// The RQE1, KOE1 and TME1 records themselves are not delivered to the selector.
    ///
    /// # Errors
    /// [`GuestReportError`] when a signed record does not decode or the output cannot be read.
    pub fn report(&mut self) -> Result<Vec<String>, GuestReportError> {
        let result =
            SandboxProviderResult::from_canonical_cbor(self.spy1_bytes()).map_err(unreportable)?;
        let receipt =
            SandboxProviderReceipt::from_canonical_cbor(self.spr1_bytes()).map_err(unreportable)?;
        let mut lines = vec!["execute\texecuted".to_owned()];
        lines.extend(outcome_lines(&result, &receipt));
        lines.extend(raw_lines(self));
        lines.extend(self.output_line()?);
        Ok(lines)
    }

    /// The output's line, when the result names an output.
    fn output_line(&mut self) -> Result<Option<String>, GuestReportError> {
        self.with_verified_output(|_, reader| {
            let mut hasher = blake3::Hasher::new();
            let length = std::io::copy(reader, &mut hasher).map_err(super::io_error)?;
            Ok(format!(
                "output\t{length}\t{}",
                lower_hex(hasher.finalize().as_bytes())
            ))
        })
        .map_err(unreportable)
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
}

/// The report of an execution, or the one line `execute unreportable`.
fn executed_lines(mut execution: GuestExecution) -> Vec<String> {
    execution
        .report()
        .unwrap_or_else(|_| vec!["execute\tunreportable".to_owned()])
}

/// The report line of an exchange that produced no execution.
fn failure_line(error: GuestWaitError) -> String {
    match error {
        GuestWaitError::Refused(Some(code)) => format!("execute\trefused\t{code:?}"),
        GuestWaitError::Refused(None) => "execute\trefused\tundecodable".to_owned(),
        GuestWaitError::Execute(error) => format!("execute\tfailed\t{error}"),
    }
}

/// The execution's records could not be reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the execution's signed records could not be reported")]
pub struct GuestReportError;

fn unreportable<E>(_: E) -> GuestReportError {
    GuestReportError
}

fn presence(digest: Option<&[u8; 32]>) -> &'static str {
    digest.map_or("absent", |_| "present")
}

fn outcome_lines(result: &SandboxProviderResult, receipt: &SandboxProviderReceipt) -> Vec<String> {
    vec![
        format!("outcome\t{:?}", result.outcome),
        format!(
            "events\t{}",
            result
                .operational_events
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
        format!("ready1\t{}", presence(receipt.ready1_digest.as_ref())),
        format!("release1\t{}", presence(receipt.release1_digest.as_ref())),
        format!(
            "rqe1\t{}",
            lower_hex(&receipt.requested_configuration_evidence)
        ),
        format!("koe1\t{}", lower_hex(&receipt.kernel_observation_evidence)),
        format!("tme1\t{}", lower_hex(&receipt.termination_evidence)),
    ]
}

fn raw_lines(execution: &GuestExecution) -> Vec<String> {
    let digest = |bytes: &[u8]| lower_hex(blake3::hash(bytes).as_bytes());
    let mut lines = vec![
        format!("agr1\t{}", lower_hex(&execution.agr1_digest())),
        format!("raw\tagr1\t{}", digest(execution.agr1_bytes())),
        format!("raw\tspr1\t{}", digest(execution.spr1_bytes())),
        format!("raw\tspy1\t{}", digest(execution.spy1_bytes())),
    ];
    lines.extend(
        execution
            .sau1_frames()
            .iter()
            .enumerate()
            .map(|(index, frame)| format!("raw\tsau1\t{index}\t{}", digest(frame))),
    );
    lines
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").ok();
        hex
    })
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
