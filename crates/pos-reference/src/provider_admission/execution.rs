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
    sandbox_provider_protocol::{PayloadDescriptor, SandboxLimit, SelectorGrantCommitment},
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
    /// The independently derived output ceiling forbids the declared output.
    #[error("output exceeds ELM1 OutputBytes")]
    OutputTooLarge,
    /// One attempt cannot open a second output transfer.
    #[error("output transfer is single use")]
    OutputAlreadyReserved,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantState {
    Prepared,
    Writing,
    Granted,
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
    grant: GrantState,
}

/// Exact, descriptor-bound input admitted under one independently derived policy.
#[derive(Debug)]
pub struct AdmittedProviderExecution {
    source: Arc<ExecutionSource>,
    slot: Arc<budget::AttemptSlot>,
    _input: StagingCharge,
    verified_input: File,
    root_image: File,
    proof: Arc<crate::sandbox_provider_protocol::VerifiedSandboxImageProof>,
    authority: AdmittedAuthority,
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
        source::receive(stream, ledger)
    }
}
