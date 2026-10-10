//! Quarantine mapping and pass-level failure classification.

use pos_core::CoreError;

use super::error::{AtomicCommitFailureV1, CommunityPluginHostErrorV1};
use crate::{PluginAvailabilityV1, RuntimeError};

/// The availability a Plugin's failure puts it in, if the failure quarantines.
///
/// - a trap is `Trapped`;
/// - a deterministic resource-limit failure is `ResourceExhausted`;
/// - a revoked artifact, whatever its basis, is `Revoked`;
/// - a worker crash is `Unavailable`: ADR-061 quarantines and reports it, and
///   it fabricates no Event, state or guest failure.
///
/// A trust denial, whatever its basis, and `UnsupportedSchema` quarantine
/// nothing: the Plugin is gated again at the next pass.
///
/// Every other failure discards the pass and marks only the failing Plugin;
/// it quarantines nothing. The operational wall-time watchdog stop is such a
/// failure: it is a safe stop, not a crash.
#[must_use]
pub const fn quarantine_for(error: CommunityPluginHostErrorV1) -> Option<PluginAvailabilityV1> {
    use CommunityPluginHostErrorV1 as Error;
    match error {
        Error::ComponentTrap { .. } => Some(PluginAvailabilityV1::Trapped),
        // Every deterministic resource-limit failure, including the host-call
        // and output limits, is `ResourceExhausted`.
        Error::FuelExhausted
        | Error::MemoryLimitExceeded
        | Error::HostCallLimitExceeded
        | Error::OutputLimitExceeded => Some(PluginAvailabilityV1::ResourceExhausted),
        Error::ArtifactRevoked { .. } => Some(PluginAvailabilityV1::Revoked),
        Error::WorkerCrashed => Some(PluginAvailabilityV1::Unavailable),
        Error::InvalidManifest
        | Error::ArtifactTrustDenied { .. }
        | Error::IncompatibleAbi
        | Error::MissingFeature { .. }
        | Error::CapabilityDenied { .. }
        | Error::InvalidInvocation
        | Error::InvalidGuestOutput
        | Error::UnsupportedSchema
        | Error::StateMigrationFailed
        | Error::GuestDeclaredFailure
        | Error::DeterministicDeadlineExceeded
        | Error::OperationalWatchdogStop
        | Error::AtomicCommitFailed { .. } => None,
    }
}

/// How a failed scheduled pass relates to the community Plugin host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassFailureV1 {
    /// The closed host error that discarded the whole pass.
    Host(CommunityPluginHostErrorV1),
    /// The store outcome is unknown. The registry retains the exact basis for
    /// `recover_scheduled_pass`; nothing was discarded, no staged state may
    /// be dropped, and no host error is yet decided.
    InDoubt,
    /// Not a community Plugin host failure; the host handles the original
    /// runtime error.
    Unrelated,
}

/// Classify the error of a failed scheduled pass (ADR-061 failure table).
///
/// - A typed non-committed pipeline outcome, surfaced as
///   `ScheduledPassNotAdmitted`, is `AtomicCommitFailed` with a deterministic
///   typed result, so it is authoritative.
/// - A storage error is `AtomicCommitFailed` and operational, because the
///   store's public contract defines no deterministic result for it.
/// - `StorageOutcomeUnknown` is [`PassFailureV1::InDoubt`].
/// - A community host error raised while staging is carried as it is.
///
/// A commit failure has no failing Plugin, so nothing here marks a handle:
/// the adapter that failed while staging already marked itself in its own
/// `step`. Every other runtime error (consent, contract, authority, pending
/// step and so on) is the host's own and is `Unrelated`; the variants are
/// deliberately not enumerated, so a new runtime error is never silently
/// classified as a community host failure.
#[must_use]
pub const fn classify_pass_failure(error: &RuntimeError) -> PassFailureV1 {
    match error {
        RuntimeError::CommunityPlugin(host) => PassFailureV1::Host(*host),
        RuntimeError::ScheduledPassNotAdmitted(_) => PassFailureV1::Host(commit_failed(
            AtomicCommitFailureV1::DeterministicTypedResult,
        )),
        RuntimeError::Store(CoreError::StorageOutcomeUnknown(_)) => PassFailureV1::InDoubt,
        RuntimeError::Store(_) => {
            PassFailureV1::Host(commit_failed(AtomicCommitFailureV1::Operational))
        }
        // Not a community host failure: see the function documentation.
        _ => PassFailureV1::Unrelated,
    }
}

/// `AtomicCommitFailed` with the given class.
const fn commit_failed(failure: AtomicCommitFailureV1) -> CommunityPluginHostErrorV1 {
    CommunityPluginHostErrorV1::AtomicCommitFailed { failure }
}
