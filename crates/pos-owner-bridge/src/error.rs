//! Closed error taxonomy for the owner bridge (ADR-110 §11).
//!
//! No error carries payload bytes, ceremony identifiers, challenges, or PRF
//! material. Nothing is retried automatically: "user-retryable" means the user
//! may start a fresh ceremony with a new identifier, challenge and environment.

use thiserror::Error;

/// Reasons the owner surface cannot run a ceremony until configuration or a restart changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableCode {
    /// The surface factory refused the operating system.
    PlatformUnsupported,
    /// The runtime folder failed its integrity or version readback.
    RuntimeIntegrity,
    /// An environment or registry override is present.
    OverridePresent,
    /// A required CPU feature is missing.
    CpuFeatures,
    /// The loopback port could not be bound exclusively.
    PortUnavailable,
    /// The IPv6 loopback appeared after the IPv4-only fallback was chosen.
    LoopbackChanged,
    /// The bytes the listener served did not match the pinned response digest.
    AssetIntegrity,
    /// A required interface is unavailable.
    ///
    /// ADR-110 §11 has no finer code, so this one is shared by a missing `WebView` interface,
    /// a cleanup store that cannot write or be read, a restart check that cannot read the
    /// store, and a ceremony refused because another one is already running.
    InterfaceUnavailable,
    /// The operating-system random generator failed.
    RngUnavailable,
    /// The per-process generation counter reached its limit.
    GenerationExhausted,
    /// The authenticator did not return a correctly shaped PRF result.
    PrfUnsupported,
}

/// Security rejections of a ceremony reply.
///
/// ADR-110 §11 names a finer set of verification reasons (origin, RP ID hash, client-data
/// type and challenge, flags, algorithm, key, counter, backup flags and so on). The merged
/// `pos-owner-bridge-codec` verifier collapses every verification failure into one error,
/// so the bridge can report only the two codes below until Redmine #563 lets the codec
/// report its reason. The missing variants are deliberately absent rather than defined and
/// never produced; #563 adds them together with the code that produces them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectedCode {
    /// A Create reply failed verification. Until #563 this covers every Create verification
    /// failure the codec reports: client data, origin, flags, attestation format, algorithm and key.
    AttestationFormat,
    /// A Get reply failed verification. Until #563 this covers every Get verification
    /// failure the codec reports: client data, flags, signature, counter and backup flags.
    Signature,
    /// The credential ID did not match the stored credential.
    CredentialMismatch,
    /// The reply user handle was present and not the stored handle.
    ///
    /// A user handle that is not exactly 32 bytes never reaches this check: the codec rejects
    /// it while decoding the reply, which the bridge reports as a protocol error.
    UserHandleMismatch,
    /// The D2 enrollment confirmation failed.
    EnrollmentConfirmation,
    /// Another binding already holds the credential ID.
    CredentialAlreadyBound,
}

/// Malformed, replayed or cross-request replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolCode {
    /// The ceremony identifiers were not all equal.
    CeremonyIdMismatch,
    /// A reply header byte other than length or state changed.
    HeaderTampered,
    /// The reply generation was not the host generation.
    GenerationMismatch,
    /// The reply kind did not match the request kind.
    KindMismatch,
    /// The reply state word held an illegal value.
    UnexpectedState,
    /// The two reply copies differed or tore.
    CopyMismatch,
    /// A length was outside its closed bound.
    LengthOutOfBounds,
    /// A payload encoding was not canonical.
    NonCanonical,
    /// A payload was malformed.
    Malformed,
    /// The owner document was served more than once in one generation.
    DuplicateDocumentLoad,
}

/// Lifecycle failures of one ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCode {
    /// The surface navigated away from the owner document.
    NavigationViolation,
    /// A frame was created.
    FrameCreated,
    /// The renderer or browser process failed.
    RendererFailed,
    /// The controller was lost.
    ControllerLost,
    /// Readiness was not reached in time.
    ReadinessTimeout,
    /// The user did not finish in time.
    InteractionTimeout,
    /// The challenge outlived its time to live.
    ChallengeExpired,
    /// The page reported a cancel or `WebAuthn` error.
    ClientFailed,
    /// The ceremony window could not take the foreground. The Windows shim (Redmine #535) is the
    /// only producer: this portable crate never checks the foreground.
    ForegroundUnavailable,
    /// The enrollment budget ran out.
    EnrollmentBudgetExceeded,
}

/// Cleanup failures that quarantine the owner surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineCode {
    /// The browser process did not exit in time.
    CleanupTimeout,
    /// The controller could not be closed.
    ControllerCloseFailed,
    /// A recorded browser process is still present at restart.
    StaleProcessPresent,
}

/// Kinds of owner-port failure, defined by the owner adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerErrorKind {
    /// Wrapping or authenticated unwrapping failed.
    Wrap,
    /// Registry state refused the operation.
    Registry,
    /// A durable write failed.
    DurableWrite,
}

/// An owner-port failure that carries no payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerError {
    kind: OwnerErrorKind,
}

impl OwnerError {
    /// Create an owner-port failure of `kind`.
    #[must_use]
    pub const fn new(kind: OwnerErrorKind) -> Self {
        Self { kind }
    }

    /// Return the failure kind.
    #[must_use]
    pub const fn kind(self) -> OwnerErrorKind {
        self.kind
    }
}

/// The class column of the ADR-110 §11 table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    /// Needs a capability, configuration or restart change.
    Unavailable,
    /// A security rejection.
    Rejected,
    /// A protocol violation.
    Protocol,
    /// A lifecycle failure.
    Lifecycle,
    /// A quarantine.
    Quarantine,
    /// A wrapped owner-port failure.
    Owner,
}

/// One closed bridge failure: a class and the code within it.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BridgeError {
    /// The surface is unavailable.
    #[error("owner bridge unavailable: {0:?}")]
    Unavailable(UnavailableCode),
    /// A security rejection.
    #[error("owner bridge rejected the ceremony: {0:?}")]
    Rejected(RejectedCode),
    /// A protocol violation.
    #[error("owner bridge protocol violation: {0:?}")]
    Protocol(ProtocolCode),
    /// A lifecycle failure.
    #[error("owner bridge lifecycle failure: {0:?}")]
    Lifecycle(LifecycleCode),
    /// The surface is quarantined.
    #[error("owner bridge quarantined: {0:?}")]
    Quarantine(QuarantineCode),
    /// An owner port failed.
    #[error("owner port failed: {0:?}")]
    Owner(OwnerError),
}

impl BridgeError {
    /// Return the class of this error.
    #[must_use]
    pub const fn class(self) -> ErrorClass {
        match self {
            Self::Unavailable(_) => ErrorClass::Unavailable,
            Self::Rejected(_) => ErrorClass::Rejected,
            Self::Protocol(_) => ErrorClass::Protocol,
            Self::Lifecycle(_) => ErrorClass::Lifecycle,
            Self::Quarantine(_) => ErrorClass::Quarantine,
            Self::Owner(_) => ErrorClass::Owner,
        }
    }

    /// Return whether the user may start a fresh ceremony after this error.
    #[must_use]
    pub const fn is_user_retryable(self) -> bool {
        matches!(
            self.class(),
            ErrorClass::Rejected | ErrorClass::Protocol | ErrorClass::Lifecycle
        )
    }
}
