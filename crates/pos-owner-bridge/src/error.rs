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
    /// A required `WebView` interface is unavailable.
    InterfaceUnavailable,
    /// The operating-system random generator failed.
    RngUnavailable,
    /// The per-process generation counter reached its limit.
    GenerationExhausted,
    /// The authenticator did not return a correctly shaped PRF result.
    PrfUnsupported,
}

/// Security rejections of a ceremony reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectedCode {
    /// The origin was not the fixed owner origin.
    Origin,
    /// The RP ID hash was wrong.
    RpIdHash,
    /// The client data type was wrong.
    ClientDataType,
    /// The client data challenge was wrong.
    Challenge,
    /// A cross-origin marker was present.
    CrossOrigin,
    /// User presence was not asserted.
    UserPresence,
    /// User verification was not asserted.
    UserVerification,
    /// The attestation was not the `none` format, or was invalid.
    AttestationFormat,
    /// The algorithm was not ES256.
    Algorithm,
    /// The COSE key was invalid.
    CoseKey,
    /// The assertion signature did not verify.
    Signature,
    /// The credential ID did not match.
    CredentialMismatch,
    /// The user handle did not match.
    UserHandleMismatch,
    /// The signature counter did not advance.
    CounterRegression,
    /// The backup flags changed illegally.
    BackupFlags,
    /// The authenticator extension data was malformed.
    Extensions,
    /// The PRF result was malformed.
    PrfMalformed,
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
    /// The reply named no outstanding ceremony.
    UnknownCeremony,
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
    /// The ceremony window could not take the foreground.
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
