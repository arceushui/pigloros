//! The closed community Plugin host failure surface (ADR-061).

/// How one host failure binds the authoritative record (ADR-061 failure table).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFailureClassV1 {
    /// A deterministic result under the pinned Component, runtime and profile.
    ///
    /// The entire guest output is discarded and the typed failure is the
    /// recorded outcome.
    Authoritative,
    /// An operational non-pass.
    ///
    /// No authoritative Event, state, retry or guest failure is fabricated
    /// from it, and it never substitutes for a deterministic outcome.
    Operational,
}

/// The profile-defined canonical trap class (ADR-061 revision 4 decision 6).
///
/// `OutOfFuel`, `Interrupt`, resource-limiter denials and canonical-ABI lift
/// failures are never a trap class; they map to their own host errors.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComponentTrapClassV1 {
    /// `unreachable`.
    Unreachable,
    /// `memory-out-of-bounds`.
    MemoryOutOfBounds,
    /// `table-out-of-bounds`.
    TableOutOfBounds,
    /// `indirect-call`.
    IndirectCall,
    /// `integer-arithmetic`.
    IntegerArithmetic,
    /// `stack-exhausted`; the profile pins `max_wasm_stack`.
    StackExhausted,
    /// `other`, including every runtime code the table does not list.
    Other,
}

impl ComponentTrapClassV1 {
    /// Every class in ADR table order.
    pub const ALL: [Self; 7] = [
        Self::Unreachable,
        Self::MemoryOutOfBounds,
        Self::TableOutOfBounds,
        Self::IndirectCall,
        Self::IntegerArithmetic,
        Self::StackExhausted,
        Self::Other,
    ];

    /// The exact ADR-061 class name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::MemoryOutOfBounds => "memory-out-of-bounds",
            Self::TableOutOfBounds => "table-out-of-bounds",
            Self::IndirectCall => "indirect-call",
            Self::IntegerArithmetic => "integer-arithmetic",
            Self::StackExhausted => "stack-exhausted",
            Self::Other => "other",
        }
    }
}

/// Whether a failed approval or atomic store has a deterministic typed result.
///
/// ADR-061 makes `AtomicCommitFailed` authoritative only when the underlying
/// public contract defines a deterministic typed result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicCommitFailureV1 {
    /// The public approval or store contract defines this typed result.
    DeterministicTypedResult,
    /// The contract defines no deterministic result for this failure.
    Operational,
}

/// The closed community Plugin host error (ADR-061 corrective amendment).
///
/// Each variant carries only a closed class, a safe index or a trap class:
/// never runtime messages, backtraces, paths or guest bytes. Indices point
/// into the PMF1 V1 list named by the variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommunityPluginHostErrorV1 {
    /// The release manifest failed PMF1 V1 validation.
    #[error("invalid community Plugin manifest")]
    InvalidManifest,
    /// The release is not authorized by the admitted trust evidence.
    #[error("community Plugin artifact trust denied")]
    ArtifactTrustDenied,
    /// The release or one of its descriptors is revoked.
    #[error("community Plugin artifact revoked")]
    ArtifactRevoked,
    /// No common ABI minor, or an ABI major other than 0.
    #[error("community Plugin ABI is incompatible with the host")]
    IncompatibleAbi,
    /// The host does not provide a required feature.
    #[error("community Plugin requires unsupported feature {index}")]
    MissingFeature {
        /// Position in PMF1 field 8.
        index: usize,
    },
    /// A required capability that ABI 0.x cannot grant.
    #[error("community Plugin capability {index} denied")]
    CapabilityDenied {
        /// Position in PMF1 field 14.
        index: usize,
    },
    /// The host-built invocation failed validation.
    #[error("invalid community Plugin invocation")]
    InvalidInvocation,
    /// A guest return failed digest, order, schema or bound validation.
    #[error("invalid community Plugin guest output")]
    InvalidGuestOutput,
    /// A referenced schema is not supported.
    #[error("unsupported community Plugin schema")]
    UnsupportedSchema,
    /// A state migration failed; a V1 host never invokes `migrate-state`.
    #[error("community Plugin state migration failed")]
    StateMigrationFailed,
    /// The guest returned its own `plugin-error`.
    #[error("community Plugin guest declared a failure")]
    GuestDeclaredFailure,
    /// The Component trapped with a canonical trap class.
    #[error("community Plugin Component trapped: {}", .class.name())]
    ComponentTrap {
        /// The profile-defined canonical trap class.
        class: ComponentTrapClassV1,
    },
    /// The worker crashed, was signalled, lost its IPC, or framed it badly.
    #[error("community Plugin worker crashed")]
    WorkerCrashed,
    /// The pinned runtime's fuel ran out (`Trap::OutOfFuel`).
    #[error("community Plugin fuel exhausted")]
    FuelExhausted,
    /// The resource limiter denied a memory growth.
    #[error("community Plugin memory limit exceeded")]
    MemoryLimitExceeded,
    /// The guest exceeded its host-call limit.
    #[error("community Plugin host-call limit exceeded")]
    HostCallLimitExceeded,
    /// The guest exceeded an Event, output, state or log limit.
    #[error("community Plugin output limit exceeded")]
    OutputLimitExceeded,
    /// A deterministic deadline passed; V1 defines none and never produces it.
    #[error("community Plugin deterministic deadline exceeded")]
    DeterministicDeadlineExceeded,
    /// The wall-time watchdog stopped the worker (`Trap::Interrupt`).
    #[error("community Plugin operational watchdog stop")]
    OperationalWatchdogStop,
    /// Approval or the one atomic Tick-Boundary commit failed.
    #[error("community Plugin atomic commit failed")]
    AtomicCommitFailed {
        /// Whether the public contract defines a deterministic typed result.
        failure: AtomicCommitFailureV1,
    },
}

impl CommunityPluginHostErrorV1 {
    /// The exact closed ADR-061 error name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidManifest => "InvalidManifest",
            Self::ArtifactTrustDenied => "ArtifactTrustDenied",
            Self::ArtifactRevoked => "ArtifactRevoked",
            Self::IncompatibleAbi => "IncompatibleAbi",
            Self::MissingFeature { .. } => "MissingFeature",
            Self::CapabilityDenied { .. } => "CapabilityDenied",
            Self::InvalidInvocation => "InvalidInvocation",
            Self::InvalidGuestOutput => "InvalidGuestOutput",
            Self::UnsupportedSchema => "UnsupportedSchema",
            Self::StateMigrationFailed => "StateMigrationFailed",
            Self::GuestDeclaredFailure => "GuestDeclaredFailure",
            Self::ComponentTrap { .. } => "ComponentTrap",
            Self::WorkerCrashed => "WorkerCrashed",
            Self::FuelExhausted => "FuelExhausted",
            Self::MemoryLimitExceeded => "MemoryLimitExceeded",
            Self::HostCallLimitExceeded => "HostCallLimitExceeded",
            Self::OutputLimitExceeded => "OutputLimitExceeded",
            Self::DeterministicDeadlineExceeded => "DeterministicDeadlineExceeded",
            Self::OperationalWatchdogStop => "OperationalWatchdogStop",
            Self::AtomicCommitFailed { .. } => "AtomicCommitFailed",
        }
    }

    /// The ADR-061 failure-table classification of this error.
    ///
    /// Worker crashes and watchdog stops are operational. An atomic commit
    /// failure is authoritative only with a deterministic typed result. Every
    /// other error is a deterministic function of the pinned release, runtime,
    /// profile and invocation, and is authoritative.
    #[must_use]
    pub const fn class(self) -> HostFailureClassV1 {
        match self {
            Self::WorkerCrashed
            | Self::OperationalWatchdogStop
            | Self::AtomicCommitFailed {
                failure: AtomicCommitFailureV1::Operational,
            } => HostFailureClassV1::Operational,
            _ => HostFailureClassV1::Authoritative,
        }
    }

    /// Whether a V1 host can produce this error.
    ///
    /// V1 defines no deterministic deadline and never invokes
    /// `migrate-state` (ADR-061 revision 4).
    #[must_use]
    pub const fn produced_in_v1(self) -> bool {
        !matches!(
            self,
            Self::DeterministicDeadlineExceeded | Self::StateMigrationFailed
        )
    }
}
