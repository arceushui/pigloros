//! Provider-owned policy admission for one authenticated execute exchange
//! (ADR-122 as amended by ADR-122 Amendment 1).
//!
//! [`ExecuteSource::read`] reads EVR1 and SPX1 exactly once from a root peer's
//! execute connection, charged before allocation, and takes ownership of the
//! stream. The only factory, [`PreparedProviderExecution::admit`], consumes
//! that source and reconstructs the selected case from the provider admission
//! retained at runtime startup; only its held-image join opens SIC1. The
//! prepared state holds the exact policy, the lifecycle claim and the
//! reservations before AGR1. Its private staging file is created before AGR1
//! ([`StagingDirectory::create_input`]), then [`StagedInput::send_grant`]
//! writes AGR1. Only complete SBC1 and EAI1 verification can produce the
//! admitted state. Every refusal before the AGR1 write returns the stream
//! ([`ExecuteRefusal`]); none follows once the write began.

mod budget;
mod source;
mod staging;

use std::{convert::Infallible, fs::File, io, os::unix::net::UnixStream, sync::Arc, time::Instant};

use crate::{
    evaluator::CaseAttempt,
    sandbox_provider_protocol::{
        AdmissionLedger, LaunchFailure, PayloadDescriptor, SandboxExecutionMode, SandboxLimit,
        SelectorGrantCommitment, TransferRecord,
    },
    selector::SelectorBoundaryError,
};

use super::{AdmittedAuthority, ProviderImageSnapshot};

pub use source::{
    ExecutePeer, ExecuteSource, OtherRequest, SourceFrames, SourceRefusal, UnchargedSource,
};
pub use staging::{
    AdmittedEntry, GrantedInput, StagedInput, StagingDirectory, VerifiedStagedInput,
};

pub use budget::{ControlFloor, StagingCharge, StagingLedger, StagingLimits, StagingUsage};

/// Closed failures of source admission, resource reservation and input staging.
///
/// Each failure before AGR1 has one SPE1 code (ADR-069 R11 Amendment 1
/// §7.5). Variants the composed execute port cannot reach are not
/// representable: the stream is owned from the single read on, so no
/// connection can change, and the grant is written by consuming the staged
/// state, so it can be neither repeated nor missing (ADR-122 Amendment 1
/// T7):
///
/// ```compile_fail
/// let _ = pos_reference::provider_admission::execution::StagingError::ConnectionChanged;
/// ```
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    /// The two source records do not identify the independently resolved case.
    #[error("execute source does not match authenticated authority")]
    InvalidSource,
    /// The received bytes do not reproduce the expected complete EAI1 stream.
    #[error("staged input differs from the admitted case")]
    InvalidInput,
    /// The initial control deadline expired (R11 Amendment 1 item P1).
    #[error("provider initial control deadline expired")]
    ControlExpired,
    /// The ELM1 ID 16 input window expired.
    #[error("provider input window expired")]
    InputWindowExpired,
    /// The runtime signer failed, or its AGR1 failed verify-before-emit.
    #[error("the runtime signer failed")]
    SignerFault,
    /// The signed AGR1 failed the provider's own commitment check.
    #[error("the signed grant differs from the derived commitment")]
    GrantCommitmentMismatch,
    /// The reconstructed execution mode is not one this provider serves.
    #[error("the execution mode is not supported")]
    CapabilityMissing,
    /// The image or the provider binary failed its identity check.
    #[error("image or provider binary identity differs")]
    ImageIdentity,
    /// The independently admitted bootstrap permits no additional source reader.
    #[error("pending control slots are exhausted")]
    ControlSlotsExhausted,
    /// The candidate or a live queued input forbids another queued transfer.
    #[error("staging queue is full")]
    QueueFull,
    /// The admitted epochs are below the live provider control floor.
    #[error("admission is below the provider control floor")]
    BelowControlFloor,
    /// A current installation no longer matches the admitted authority, at
    /// the release recheck of an admitted execution.
    #[error("installed authority differs from the admitted authority")]
    AuthorityChanged,
    /// The candidate or a live attempt forbids another attempt.
    #[error("staging attempt slots are exhausted")]
    AttemptsExhausted,
    /// A checked byte sum would exceed the provider's aggregate cap.
    #[error("staging aggregate cap would be exceeded")]
    AggregateExceeded,
    /// A failed private-file cleanup permanently closed this live ledger.
    #[error("staging admission is closed after a cleanup failure")]
    CleanupFailed,
    /// The independently derived input ceiling forbids the declared input.
    #[error("input exceeds ELM1 InputBytes")]
    InputTooLarge,
    /// A staging directory is not private and provider-owned.
    #[error("staging directory is unsafe")]
    UnsafeDirectory,
    /// The peer ended the input before its declared complete length.
    #[error("staged input is incomplete")]
    Incomplete,
    /// Fixed-installation admission failed.
    #[error(transparent)]
    Source(#[from] SelectorBoundaryError),
    /// A stream or descriptor operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Why an exchange was refused before its AGR1 write began.
#[derive(Debug)]
pub enum RefusalCause<E = Infallible> {
    /// The source, its admission, a resource or the staging file.
    Staging(StagingError),
    /// The caller's lifecycle claim or its conversion.
    Claim(E),
}

/// An exchange refused before its AGR1 write began (ADR-122 Amendment 1
/// change C): its execute stream, returned for the SPE1, and why.
///
/// Every policy, slot, charge, claim and reservation the exchange held was
/// released before this was returned (R11 Amendment 1, change A).
#[derive(Debug)]
pub struct ExecuteRefusal<E = Infallible> {
    stream: UnixStream,
    cause: RefusalCause<E>,
}

impl<E> ExecuteRefusal<E> {
    /// The execute stream and why it was refused.
    #[must_use]
    pub fn into_parts(self) -> (UnixStream, RefusalCause<E>) {
        (self.stream, self.cause)
    }
}

/// Why [`StagedInput::send_grant`] wrote no complete AGR1.
#[derive(Debug)]
pub enum GrantFailure<E = Infallible> {
    /// Refused before the write began: the exchange may still be answered.
    Refused(Box<ExecuteRefusal<E>>),
    /// The write began and failed. No byte follows: SPE1 cannot follow AGR1
    /// (base ADR-069 §4), and the selector never authenticated a grant.
    Interrupted(StagingError),
}

/// Why the attempt's one output reservation of exactly ELM1\[8\] bytes was
/// refused (ADR-069 R10 §4.7).
///
/// The request is the policy's own ID 8 limit and the attempt's only one, so
/// an oversized or a second reservation cannot be expressed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutputReservationRefused {
    /// The aggregate staging ledger is full (TME1 `launch-failure` 3).
    #[error("staging aggregate cap would be exceeded")]
    AggregateExceeded,
    /// The ledger was closed after a cleanup failure (TME1 `launch-failure`
    /// 5, quarantine).
    #[error("staging admission is closed after a cleanup failure")]
    AdmissionClosed,
}

/// TME1 `launch-failure` of a refused output reservation (ADR-069 R10 §4.7):
/// a full aggregate ledger is 3, a ledger closed after a cleanup failure 5.
impl From<OutputReservationRefused> for LaunchFailure {
    fn from(refused: OutputReservationRefused) -> Self {
        match refused {
            OutputReservationRefused::AggregateExceeded => Self::OutputReservationRefused,
            OutputReservationRefused::AdmissionClosed => Self::AdmissionClosed,
        }
    }
}

/// The AGR1 one exchange completely wrote, and the admission facts of that
/// moment (ADR-069 R9 §4.6.3).
///
/// Only a completed grant write creates one. Its bytes are the exact
/// canonical AGR1 the selector received, retained for the stored response,
/// with the admitted facts the attempt's terminal records need whether or
/// not its input arrives (Redmine #443 journal 22723): the ELM1 limits, the
/// execution mode, and the provider binary and negative-probe digests that
/// SPR1 carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedGrant {
    bytes: Arc<[u8]>,
    digest: [u8; 32],
    admission: AdmissionLedger,
    issued_at: Option<u64>,
    admitted: Arc<GrantedFacts>,
}

/// The admitted facts an [`IssuedGrant`] retains.
#[derive(Debug, Eq, PartialEq)]
struct GrantedFacts {
    limits: Vec<SandboxLimit>,
    limits_digest: [u8; 32],
    mode: SandboxExecutionMode,
    provider_binary_digest: [u8; 32],
    negative_probe_evidence: [u8; 32],
}

impl IssuedGrant {
    /// The exact canonical AGR1 bytes that were sent.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The AGR1 self-digest, which every later cancel and reconcile request
    /// must name.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// TME1 `admission`: the live attempts (ELM1 ID 13), including this one,
    /// and the incomplete inputs (ID 14) when AGR1 was issued.
    #[must_use]
    pub const fn admission(&self) -> AdmissionLedger {
        self.admission
    }

    /// When AGR1 was completely written, in `CLOCK_MONOTONIC` nanoseconds;
    /// `None` if the clock could not report it, which TME1 records as
    /// missing evidence.
    #[must_use]
    pub const fn issued_at(&self) -> Option<u64> {
        self.issued_at
    }

    /// The ELM1 limits AGR1 committed to by `elm1-digest`.
    #[must_use]
    pub fn effective_limits(&self) -> &[SandboxLimit] {
        &self.admitted.limits
    }

    /// The ELM1 self-digest AGR1 names.
    #[must_use]
    pub fn effective_limits_digest(&self) -> [u8; 32] {
        self.admitted.limits_digest
    }

    /// The admitted execution mode.
    #[must_use]
    pub fn execution_mode(&self) -> SandboxExecutionMode {
        self.admitted.mode
    }

    /// The admitted SPM1 provider binary digest: SPR1's
    /// `provider-binary-digest`.
    #[must_use]
    pub fn provider_binary_digest(&self) -> [u8; 32] {
        self.admitted.provider_binary_digest
    }

    /// Ordinal 7 of the HCP1 AGR1 admitted: SPR1 ordinal 21 (ADR-069 R9
    /// §4.5).
    #[must_use]
    pub fn negative_probe_evidence(&self) -> [u8; 32] {
        self.admitted.negative_probe_evidence
    }
}

/// An input that failed after its AGR1 was completely sent (ADR-069 §4).
///
/// Its staged bytes and reservations are already released. The grant, its
/// attempt and the incomplete transfer remain: the attempt is admitted, so
/// it ends in a stored `UnavailableAfterAdmission`, never in SPE1.
#[derive(Debug)]
pub struct FailedInput {
    error: StagingError,
    attempt_id: [u8; 16],
    grant: IssuedGrant,
    transfer: Option<TransferRecord>,
}

impl FailedInput {
    /// Why the input was refused.
    #[must_use]
    pub const fn error(&self) -> &StagingError {
        &self.error
    }

    /// The admitted `AttemptId`.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The AGR1 the attempt was admitted under.
    #[must_use]
    pub const fn grant(&self) -> &IssuedGrant {
        &self.grant
    }

    /// TME1 `input`: the transfer as far as it got; `None` if the clock
    /// could not report when it finished.
    #[must_use]
    pub const fn transfer(&self) -> Option<TransferRecord> {
        self.transfer
    }
}

#[cfg(any(test, feature = "test-support"))]
impl IssuedGrant {
    /// A grant under the AGR1 digest `digest`, with filler AGR1 bytes, the
    /// ELM1 `limits` under a filler digest, the execution `mode`, issued at
    /// 2 with this attempt live and its input incomplete, for tests that
    /// authenticate nothing.
    #[must_use]
    pub fn fixture(
        digest: [u8; 32],
        limits: Vec<SandboxLimit>,
        mode: SandboxExecutionMode,
    ) -> Self {
        Self {
            bytes: Arc::from([0xa6_u8].as_slice()),
            digest,
            admission: AdmissionLedger {
                active_attempts: 1,
                incomplete_inputs: 1,
            },
            issued_at: Some(2),
            admitted: Arc::new(GrantedFacts {
                limits,
                limits_digest: [0xe1; 32],
                mode,
                provider_binary_digest: [0xb1; 32],
                negative_probe_evidence: [0x97; 32],
            }),
        }
    }

    /// The same grant whose AGR1 is the canonical `bytes`, for tests that
    /// authenticate the stored response it heads.
    #[must_use]
    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.bytes = Arc::from(bytes);
        self
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FailedInput {
    /// A failed input of `attempt_id` under the AGR1 digest `grant_digest`,
    /// with filler grant bytes and an empty, incomplete transfer, for tests
    /// that authenticate nothing.
    #[must_use]
    pub fn fixture(attempt_id: [u8; 16], grant_digest: [u8; 32]) -> Self {
        Self {
            error: StagingError::Incomplete,
            attempt_id,
            grant: IssuedGrant::fixture(
                grant_digest,
                (0..17)
                    .map(|limit_id| SandboxLimit { limit_id, value: 1 })
                    .collect(),
                SandboxExecutionMode::AirGapped,
            ),
            transfer: Some(TransferRecord {
                start: 1,
                deadline: 4,
                finish: 3,
                expected_bytes: 1,
                accepted_bytes: 0,
                complete: false,
            }),
        }
    }

    /// The same failed input whose AGR1 is the canonical `bytes`, for tests
    /// that sign the stored response it ends in.
    #[must_use]
    pub fn with_grant_bytes(mut self, bytes: &[u8]) -> Self {
        self.grant = self.grant.with_bytes(bytes);
        self
    }
}

/// The input-transfer window in `CLOCK_MONOTONIC` nanoseconds: its start
/// once the complete SPX1 frame was read, and the enforced input deadline,
/// the ELM1 ID 16 window from that same instant under any stricter
/// transport bound.
#[derive(Clone, Copy, Debug)]
struct TransferWindow {
    start: u64,
    deadline: u64,
}

impl TransferWindow {
    /// The window that started at `started`, sampled as `start`
    /// nanoseconds at or after that instant, and is enforced until
    /// `deadline`. Sampling the clock after the instant keeps the recorded
    /// deadline at or after the enforced one.
    fn new(started: Instant, start: u64, deadline: Instant) -> Self {
        let length = u64::try_from(deadline.saturating_duration_since(started).as_nanos())
            .unwrap_or(u64::MAX);
        Self {
            start,
            deadline: start.saturating_add(length),
        }
    }

    /// The transfer as far as it got: `accepted` of `expected` bytes,
    /// finished at `finish` (R9 §6 rule 9).
    const fn record(self, expected: u64, accepted: u64, finish: u64) -> TransferRecord {
        TransferRecord {
            start: self.start,
            deadline: self.deadline,
            finish,
            expected_bytes: expected,
            accepted_bytes: accepted,
            complete: accepted == expected && finish <= self.deadline,
        }
    }
}

/// A source of `CLOCK_MONOTONIC` nanoseconds. Production always uses
/// [`monotonic_ns`]; only this crate's tests supply another.
type Clock = fn() -> io::Result<u64>;

/// The current `CLOCK_MONOTONIC` time in nanoseconds.
///
/// # Errors
/// `InvalidData` for a time the clock cannot report in unsigned
/// nanoseconds, such as a negative one.
fn monotonic_ns() -> io::Result<u64> {
    timespec_ns(rustix::time::clock_gettime(
        rustix::time::ClockId::Monotonic,
    ))
}

/// `now` in nanoseconds.
///
/// # Errors
/// `InvalidData` for a negative time or one beyond `u64` nanoseconds.
fn timespec_ns(now: rustix::time::Timespec) -> io::Result<u64> {
    u64::try_from(now.tv_sec)
        .ok()
        .zip(u64::try_from(now.tv_nsec).ok())
        .and_then(|(seconds, nanoseconds)| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|whole| whole.checked_add(nanoseconds))
        })
        .ok_or(io::ErrorKind::InvalidData)
        .map_err(io::Error::from)
}

/// Immutable policy derived only from the independently reconstructed case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderExecutionPolicy {
    request_digest: [u8; 32],
    input: PayloadDescriptor,
    commitment: SelectorGrantCommitment,
}

impl ProviderExecutionPolicy {
    /// The exact canonical SPX1 identity, including its EVR1/source bindings.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// The expected complete canonical EAI1 stream descriptor.
    #[must_use]
    pub const fn input_descriptor(&self) -> &PayloadDescriptor {
        &self.input
    }

    /// All seventeen independently derived ELM1 records in canonical order.
    #[must_use]
    pub fn effective_limits(&self) -> &[SandboxLimit] {
        self.commitment.effective_limits()
    }

    /// The ELM1 digest reproduced by AGR1.
    #[must_use]
    pub const fn effective_limits_digest(&self) -> [u8; 32] {
        self.commitment.effective_limits_digest()
    }

    /// The independently derived expected RBS1 commitment.
    #[must_use]
    pub const fn expected_readback_digest(&self) -> [u8; 32] {
        self.commitment.expected_readback_set_digest()
    }

    fn limit(&self, id: usize) -> u64 {
        self.effective_limits()[id].value
    }
}

#[derive(Debug)]
struct ExecutionSource {
    snapshot: ProviderImageSnapshot,
    expected: RetainedCase,
    policy: ProviderExecutionPolicy,
    // Canonical source bytes remain available for the attempt's evidence closure.
    _records: [source::RetainedControl; 2],
}

#[derive(Debug)]
struct RetainedCase {
    attempt: CaseAttempt,
    // Field order keeps the charge until the actual case buffers are dropped.
    _charge: StagingCharge,
}

/// What a prepared or granted exchange holds for its input: the retained
/// source, the counted attempt, the input charge and its deadlines. Field
/// order keeps the retained source and the attempt before the input charge.
#[derive(Debug)]
struct Execution {
    source: Arc<ExecutionSource>,
    slot: Arc<budget::AttemptSlot>,
    input: StagingCharge,
    ledger: StagingLedger,
    input_deadline: Instant,
    window: TransferWindow,
    clock: Clock,
}

/// Derived policy, the caller's lifecycle claim and atomic reservations,
/// before any adapter input is admitted. It owns the execute stream.
///
/// [`Self::admit`] over an [`ExecuteSource`] is its only constructor; the
/// stream-taking `receive` is gone (ADR-122 Amendment 1 T8):
///
/// ```compile_fail
/// use pos_reference::provider_admission::execution::PreparedProviderExecution;
/// let _ = PreparedProviderExecution::<()>::receive;
/// ```
#[derive(Debug)]
pub struct PreparedProviderExecution<C = ()> {
    execution: Execution,
    claim: C,
    initial_deadline: Instant,
    stream: UnixStream,
}

/// An exchange whose AGR1 was completely written, awaiting its input.
#[derive(Debug)]
struct GrantedExecution {
    execution: Execution,
    grant: IssuedGrant,
    stream: UnixStream,
}

/// Exact, descriptor-bound input admitted under one independently derived policy.
#[derive(Debug)]
pub struct AdmittedProviderExecution {
    source: Arc<ExecutionSource>,
    verified_input: File,
    root_image: File,
    proof: Arc<crate::sandbox_provider_protocol::VerifiedSandboxImageProof>,
    authority: AdmittedAuthority,
    grant: IssuedGrant,
    transfer: Option<TransferRecord>,
    // The descriptor pins staged storage even after its private name is unlinked.
    // Close owned resources before releasing bytes, then the counted attempt.
    _input: StagingCharge,
    slot: Arc<budget::AttemptSlot>,
}
