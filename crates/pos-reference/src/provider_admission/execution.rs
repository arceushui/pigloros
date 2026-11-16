//! Provider-owned policy admission for one authenticated execute exchange.
//!
//! The only production constructor reads EVR1 and SPX1 from a root peer and
//! reconstructs the selected case from the retained SIC1 installation. The
//! prepared state holds the exact policy and reservations before AGR1. Only
//! complete SBC1 and EAI1 verification can produce the admitted state.

mod budget;
mod source;
mod staging;

use std::{fs::File, io, os::unix::net::UnixStream, sync::Arc, time::Instant};

use crate::{
    evaluator::CaseAttempt,
    sandbox_provider_protocol::{
        AdmissionLedger, LaunchFailure, PayloadDescriptor, SandboxLimit, SelectorGrantCommitment,
        TransferRecord,
    },
    selector::SelectorBoundaryError,
};

use super::{AdmittedAuthority, ProviderImageSnapshot};

pub use staging::{AdmittedEntry, StagedInput, StagingDirectory, VerifiedStagedInput};

pub use budget::{ControlFloor, StagingCharge, StagingLedger, StagingLimits, StagingUsage};

/// Closed failures of source admission, resource reservation and input staging.
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    /// The execute connection is not owned by root.
    #[error("execute peer is not root")]
    UnauthenticatedPeer,
    /// The two source records do not identify the independently resolved case.
    #[error("execute source does not match authenticated authority")]
    InvalidSource,
    /// The received bytes do not reproduce the expected complete EAI1 stream.
    #[error("staged input differs from the admitted case")]
    InvalidInput,
    /// The original control or input-transfer deadline has expired.
    #[error("provider transfer deadline expired")]
    Expired,
    /// A different connection was supplied after source admission.
    #[error("execute connection changed")]
    ConnectionChanged,
    /// This prepared exchange has already attempted to write its grant.
    #[error("admission grant is single use")]
    GrantAlreadyIssued,
    /// Input cannot be admitted before AGR1 was completely written.
    #[error("admission grant has not been sent")]
    GrantRequired,
    /// The supplied signature is not made by the admitted runtime key.
    #[error("admission signature differs from the admitted runtime key")]
    InvalidSignature,
    /// The independently admitted bootstrap permits no additional source reader.
    #[error("pending control slots are exhausted")]
    ControlSlotsExhausted,
    /// The candidate or a live queued input forbids another queued transfer.
    #[error("staging queue is full")]
    QueueFull,
    /// The admitted epochs are below the live provider control floor.
    #[error("admission is below the provider control floor")]
    BelowControlFloor,
    /// A current installation no longer matches the admitted authority.
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
    /// A write would exceed its exact reservation.
    #[error("staged input exceeds its reservation")]
    ExceedsReservation,
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

/// Why the attempt's one output reservation of exactly ELM1[8] bytes was
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
/// canonical AGR1 the selector received, retained for the stored response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedGrant {
    bytes: Arc<[u8]>,
    digest: [u8; 32],
    admission: AdmissionLedger,
    issued_at: Option<u64>,
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
impl FailedInput {
    /// A failed input of `attempt_id` under the AGR1 digest `grant_digest`,
    /// with filler grant bytes and an empty, incomplete transfer, for tests
    /// that authenticate nothing.
    #[must_use]
    pub fn fixture(attempt_id: [u8; 16], grant_digest: [u8; 32]) -> Self {
        Self {
            error: StagingError::Incomplete,
            attempt_id,
            grant: IssuedGrant {
                bytes: Arc::from([0xa6_u8].as_slice()),
                digest: grant_digest,
                admission: AdmissionLedger {
                    active_attempts: 1,
                    incomplete_inputs: 1,
                },
                issued_at: Some(2),
            },
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
}

/// Why staged input was not admitted.
#[derive(Debug, thiserror::Error)]
pub enum InputRefusal {
    /// No AGR1 was completely sent: the exchange fails before admission.
    #[error(transparent)]
    NotGranted(StagingError),
    /// AGR1 was sent: the admitted attempt's input failed.
    #[error("admitted input failed: {}", .0.error)]
    Failed(Box<FailedInput>),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectionIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GrantState {
    Prepared,
    Writing,
    /// AGR1 was written completely.
    Granted(IssuedGrant),
}

/// Derived policy and atomic reservations, before any adapter input is admitted.
#[derive(Debug)]
pub struct PreparedProviderExecution {
    source: Arc<ExecutionSource>,
    slot: Arc<budget::AttemptSlot>,
    input: StagingCharge,
    ledger: StagingLedger,
    connection: ConnectionIdentity,
    initial_deadline: Instant,
    input_deadline: Instant,
    window: TransferWindow,
    clock: Clock,
    grant: GrantState,
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

impl PreparedProviderExecution {
    /// Authenticate root, read EVR1 then SPX1, and reserve their derived policy.
    ///
    /// No listener is opened. Installation recovery and source/byte/deadline
    /// checks all precede AGR1; this creates no execution or mount permit.
    ///
    /// # Errors
    /// Refuses non-root peers, invalid source/installation, expired transfers
    /// and any exhausted independently derived or aggregate resource ceiling.
    pub fn receive(stream: &mut UnixStream, ledger: &StagingLedger) -> Result<Self, StagingError> {
        source::receive(stream, ledger, monotonic_ns)
    }
}
