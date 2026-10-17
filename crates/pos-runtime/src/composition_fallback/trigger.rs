//! ADR-119 section 4.2 trigger eligibility: a pure function from a closed
//! cause to an eligible trigger code.
//!
//! The outcome reader (slice 6) maps a failed or refused pass's
//! `gates[i].launch_failure`, a [`PassFailureV1`], or a restart-composition
//! fact to one [`FallbackTriggerCauseV1`]. The classifier never reads a pass,
//! a handle or the registry.

use pos_core::{FallbackActivationOriginV1, FallbackTriggerBasisV1, FallbackTriggerCodeV1 as Code};

use crate::community_plugin_host::{CommunityPluginHostErrorV1, PassFailureV1, TrapReproductionV1};

use self::FallbackTriggerCauseV1 as Cause;

/// The closed failure cause an ADR-119 trigger is classified from.
///
/// Its `u16` code is the cause code of `trigger_basis`. Only the causes the
/// classifier maps to a code can ever be recorded; the others exist so that
/// every observed failure has a cause and the never-eligible list is explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum FallbackTriggerCauseV1 {
    /// `MissingImplementation` during restart composition: code 1.
    MissingImplementation = 1,
    /// `InvalidManifest`: never eligible.
    InvalidManifest = 2,
    /// `ArtifactTrustDenied`, every basis including `TrustStateUnavailable`: never eligible.
    ArtifactTrustDenied = 3,
    /// `ArtifactRevoked`, every basis: code 4 (Q6 (a) confirmed).
    ArtifactRevoked = 4,
    /// `IncompatibleAbi`: never eligible.
    IncompatibleAbi = 5,
    /// `MissingFeature`: never eligible.
    MissingFeature = 6,
    /// `CapabilityDenied`: never eligible.
    CapabilityDenied = 7,
    /// `InvalidInvocation`: never eligible.
    InvalidInvocation = 8,
    /// `InvalidGuestOutput`: never eligible.
    InvalidGuestOutput = 9,
    /// `UnsupportedSchema`: never eligible.
    UnsupportedSchema = 10,
    /// `StateMigrationFailed`: never eligible.
    StateMigrationFailed = 11,
    /// `GuestDeclaredFailure`: never eligible.
    GuestDeclaredFailure = 12,
    /// `ComponentTrap` with `Unverified` reproduction: not eligible until FU-7.
    ComponentTrapUnverified = 13,
    /// `ComponentTrap` that conformance reproduces: code 2.
    ComponentTrapReproduced = 14,
    /// `WorkerCrashed`: code 5, which an entry opts into through its triggers.
    WorkerCrashed = 15,
    /// `FuelExhausted`: code 3.
    FuelExhausted = 16,
    /// `MemoryLimitExceeded`: code 3.
    MemoryLimitExceeded = 17,
    /// `HostCallLimitExceeded`: code 3.
    HostCallLimitExceeded = 18,
    /// `OutputLimitExceeded`: code 3.
    OutputLimitExceeded = 19,
    /// `DeterministicDeadlineExceeded`, which V1 never produces: never eligible.
    DeterministicDeadlineExceeded = 20,
    /// The wall-time watchdog (`OperationalWatchdogStop`): never eligible.
    OperationalWatchdogStop = 21,
    /// `AtomicCommitFailed`, either class: never eligible.
    AtomicCommitFailed = 22,
    /// An in-doubt store outcome: never eligible; it waits for recovery.
    InDoubt = 23,
    /// A later pass's `Composition(ImplementationUnavailable)`: never a source.
    ImplementationUnavailable = 24,
    /// An `Incompatible` or `Unpinned` implementation, or an order or mode
    /// mismatch: misconfiguration or possible tampering, never eligible.
    CompositionMismatch = 25,
    /// Not a community host failure: authority, consent, knowledge,
    /// erasure-fence and capability refusals, approver denials, proposal
    /// rejections, `NoAction`, `ProviderUnavailable` and every other host
    /// error (`PassFailureV1::Unrelated`). Never eligible.
    Unrelated = 26,
    /// A failure of the composition boundary transaction itself: never eligible.
    BoundaryTransactionFailed = 27,
}

/// The cause of each community host error, by its closed ADR-061 name.
///
/// `ComponentTrap` is listed with its `Unverified` cause; a reproduced trap is
/// recognized before this table is read.
const HOST_CAUSES: [(&str, Cause); 20] = [
    ("InvalidManifest", Cause::InvalidManifest),
    ("ArtifactTrustDenied", Cause::ArtifactTrustDenied),
    ("ArtifactRevoked", Cause::ArtifactRevoked),
    ("IncompatibleAbi", Cause::IncompatibleAbi),
    ("MissingFeature", Cause::MissingFeature),
    ("CapabilityDenied", Cause::CapabilityDenied),
    ("InvalidInvocation", Cause::InvalidInvocation),
    ("InvalidGuestOutput", Cause::InvalidGuestOutput),
    ("UnsupportedSchema", Cause::UnsupportedSchema),
    ("StateMigrationFailed", Cause::StateMigrationFailed),
    ("GuestDeclaredFailure", Cause::GuestDeclaredFailure),
    ("ComponentTrap", Cause::ComponentTrapUnverified),
    ("WorkerCrashed", Cause::WorkerCrashed),
    ("FuelExhausted", Cause::FuelExhausted),
    ("MemoryLimitExceeded", Cause::MemoryLimitExceeded),
    ("HostCallLimitExceeded", Cause::HostCallLimitExceeded),
    ("OutputLimitExceeded", Cause::OutputLimitExceeded),
    (
        "DeterministicDeadlineExceeded",
        Cause::DeterministicDeadlineExceeded,
    ),
    ("OperationalWatchdogStop", Cause::OperationalWatchdogStop),
    ("AtomicCommitFailed", Cause::AtomicCommitFailed),
];

/// Every eligible cause and its trigger code (ADR-119 section 4.2, owner
/// decisions Q2 (c) and Q6 (a)). Every other cause is never eligible.
const ELIGIBLE: [(Cause, Code); 8] = [
    (Cause::MissingImplementation, Code::MissingImplementation),
    (Cause::ComponentTrapReproduced, Code::ComponentTrap),
    (Cause::FuelExhausted, Code::ResourceLimit),
    (Cause::MemoryLimitExceeded, Code::ResourceLimit),
    (Cause::HostCallLimitExceeded, Code::ResourceLimit),
    (Cause::OutputLimitExceeded, Code::ResourceLimit),
    (Cause::ArtifactRevoked, Code::ArtifactRevoked),
    (Cause::WorkerCrashed, Code::WorkerCrashed),
];

impl FallbackTriggerCauseV1 {
    /// Every cause, in ascending code order.
    pub const ALL: [Self; 27] = [
        Self::MissingImplementation,
        Self::InvalidManifest,
        Self::ArtifactTrustDenied,
        Self::ArtifactRevoked,
        Self::IncompatibleAbi,
        Self::MissingFeature,
        Self::CapabilityDenied,
        Self::InvalidInvocation,
        Self::InvalidGuestOutput,
        Self::UnsupportedSchema,
        Self::StateMigrationFailed,
        Self::GuestDeclaredFailure,
        Self::ComponentTrapUnverified,
        Self::ComponentTrapReproduced,
        Self::WorkerCrashed,
        Self::FuelExhausted,
        Self::MemoryLimitExceeded,
        Self::HostCallLimitExceeded,
        Self::OutputLimitExceeded,
        Self::DeterministicDeadlineExceeded,
        Self::OperationalWatchdogStop,
        Self::AtomicCommitFailed,
        Self::InDoubt,
        Self::ImplementationUnavailable,
        Self::CompositionMismatch,
        Self::Unrelated,
        Self::BoundaryTransactionFailed,
    ];

    /// Return the `trigger_basis` cause code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Return the cause with this code, if V1 defines one.
    #[must_use]
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.code() == code)
    }

    /// The cause of one community host error.
    ///
    /// A `ComponentTrap` is `ComponentTrapReproduced` only when conformance
    /// reproduces it (`TrapReproductionV1::ReproducedByConformance`). The
    /// host emits only `Unverified` until FU-7, so code 2 stays ineligible
    /// until then: this is the owner's Q2 (c) gate.
    #[must_use]
    pub fn from_host_error(error: CommunityPluginHostErrorV1) -> Self {
        let reproduced = matches!(
            error,
            CommunityPluginHostErrorV1::ComponentTrap {
                reproduction: TrapReproductionV1::ReproducedByConformance,
                ..
            }
        );
        let cause = HOST_CAUSES
            .iter()
            .find(|(name, _)| *name == error.name())
            .map_or(Self::Unrelated, |(_, cause)| *cause);
        if reproduced {
            Self::ComponentTrapReproduced
        } else {
            cause
        }
    }

    /// The cause of one classified scheduled-pass failure.
    #[must_use]
    pub fn from_pass_failure(failure: PassFailureV1) -> Self {
        match failure {
            PassFailureV1::Host(error) => Self::from_host_error(error),
            PassFailureV1::InDoubt => Self::InDoubt,
            PassFailureV1::Unrelated => Self::Unrelated,
        }
    }

    /// The `trigger_basis` that records this cause with `origin`.
    #[must_use]
    pub const fn basis(self, origin: FallbackActivationOriginV1) -> FallbackTriggerBasisV1 {
        FallbackTriggerBasisV1 {
            cause: self.code(),
            origin,
        }
    }
}

/// The trigger code `cause` is eligible for, or `None` when it never is.
///
/// A pure function of the closed cause (ADR-119 section 4.2): codes 1, 3 and
/// 4 are eligible, code 2 only for a reproduced trap, and code 5 for a worker
/// crash. Whether an entry acts on a code is its declared trigger list; see
/// [`declared_fallback_trigger_v1`].
#[must_use]
pub fn classify_fallback_trigger_v1(cause: FallbackTriggerCauseV1) -> Option<Code> {
    ELIGIBLE
        .iter()
        .find(|(eligible, _)| *eligible == cause)
        .map(|(_, code)| *code)
}

/// The trigger code `cause` fires for an entry whose declared triggers are
/// `triggers`, or `None`.
///
/// Every code is opt-in through the entry's DFP1 trigger list; code 5
/// (`WorkerCrashed`) fires only for an entry that declares it.
#[must_use]
pub fn declared_fallback_trigger_v1(
    cause: FallbackTriggerCauseV1,
    triggers: &[Code],
) -> Option<Code> {
    classify_fallback_trigger_v1(cause).filter(|code| triggers.contains(code))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "trigger_tests.rs"]
mod tests;
