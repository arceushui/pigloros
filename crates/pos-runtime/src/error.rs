use pos_core::ids::{PluginId, TimelineId};
use pos_core::{ActionRejected, ConsentError, ErasureContainmentErrorV1};
use thiserror::Error;

/// Closed failure classes for an installed World Live backend.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WorldInstallationErrorV1 {
    #[error("unsupported Live platform")]
    UnsupportedPlatform,
    #[error("unsupported World profile")]
    UnsupportedProfile,
    #[error("unsupported World backend factory")]
    UnsupportedFactory,
    #[error("process image could not be opened")]
    MeasurementOpenFailed,
    #[error("process image could not be read")]
    MeasurementReadFailed,
    #[error("process image metadata could not be read")]
    MeasurementMetadataFailed,
    #[error("process image is empty")]
    MeasurementEmpty,
    #[error("process image changed during measurement")]
    MeasurementChanged,
    #[error("retained World configuration is missing")]
    RetainedConfigMissing,
    #[error("retained World configuration is malformed")]
    RetainedConfigMalformed,
    #[error("retained World configuration is ambiguous")]
    RetainedConfigAmbiguous,
    #[error("retained World configuration is out of order")]
    RetainedConfigOutOfOrder,
    #[error("World backend ID differs from the installed backend")]
    BackendIdMismatch,
    #[error("World backend version differs from the installed backend")]
    BackendVersionMismatch,
    #[error("World backend digest differs from the installed backend")]
    BackendDigestMismatch,
    #[error("World profile differs from the installed profile")]
    ProfileMismatch,
}

/// Closed result of one Timeline-bound proposed-action admission.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActionSubmissionError {
    /// The capability, payload, ownership, or Plugin domain policy rejected the action.
    #[error(transparent)]
    Rejected(#[from] ActionRejected),
    /// No host-owned erasure gate was installed for the action boundary.
    #[error("proposed action requires a host-bound erasure containment gate")]
    ErasureOperationUnavailable,
    /// The installed erasure fence rejected the action before Plugin invocation.
    #[error(transparent)]
    ErasureContainment(#[from] ErasureContainmentErrorV1),
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    ManifestRegistration(#[from] crate::ManifestRegistrationErrorV1),
    #[error(transparent)]
    ManifestSlot(#[from] crate::ManifestSlotErrorV1),
    /// An output-admission failure. `From` remaps
    /// [`crate::OutputAdmissionErrorV1::Composition`] to
    /// [`RuntimeError::Composition`], so a conversion never wraps it here.
    #[error(transparent)]
    OutputAdmission(crate::OutputAdmissionErrorV1),
    #[error(transparent)]
    WorldInstallation(#[from] WorldInstallationErrorV1),

    #[error(transparent)]
    Composition(#[from] crate::PluginCompositionErrorV1),

    #[error("plugin '{name}' (id={id}) is already registered")]
    DuplicatePlugin { id: PluginId, name: String },

    #[error("unknown event type '{0}' — no plugin owns this schema")]
    UnknownEventType(String),

    #[error("payload validation failed for event type '{event_type}': {reason}")]
    InvalidPayload { event_type: String, reason: String },

    #[error("plugin '{name}' has no driver but was asked to step")]
    NoDriver { name: String },

    #[error("driver '{name}' panicked; its Tick Boundary was aborted")]
    DriverPanicked { name: String },

    #[error("driver '{name}' panicked while aborting; its Tick Boundary was discarded")]
    DriverAbortPanicked { name: String },

    #[error("driver '{name}' panicked while committing; the runtime is faulted")]
    DriverCommitPanicked { name: String },

    #[error("driver '{name}' panicked while restoring; the runtime is faulted")]
    DriverRestorePanicked { name: String },

    #[error("driver '{name}' panicked during Fork handoff; the runtime is faulted")]
    DriverForkPanicked { name: String },

    #[error("driver '{name}' panicked during Fork handoff and child rollback failed: {source}")]
    DriverForkRollbackFailed {
        name: String,
        source: pos_core::CoreError,
    },

    #[error(
        "driver '{driver}' exceeded its deterministic resource budget: requested={requested}, limit={limit}"
    )]
    ResourceExhausted {
        driver: String,
        requested: u64,
        limit: u64,
    },

    #[error("plugin '{name}' capability mismatch: {reason}")]
    CapabilityMismatch { name: String, reason: String },

    #[error("plugin '{name}' cannot claim core-owned geographic event type '{event_type}'")]
    ReservedGeographicEventType { name: String, event_type: String },

    #[error("driver emitted core-owned geographic event type '{event_type}'")]
    GeographicDraft { event_type: String },

    #[error("plugin '{name}' cannot claim Gateway-owned consent event type '{event_type}'")]
    ReservedConsentEventType { name: String, event_type: String },

    #[error("driver emitted Gateway-owned consent event type '{event_type}'")]
    ConsentDraft { event_type: String },

    #[error("protected operation requires a host-bound consent authority")]
    ConsentOperationUnavailable,

    #[error("protected operation requires a host-bound erasure containment gate")]
    ErasureOperationUnavailable,

    #[error("protected operation failed its consent fence: {0}")]
    Consent(ConsentError),

    #[error("protected operation failed its erasure containment fence: {0}")]
    ErasureContainment(ErasureContainmentErrorV1),

    #[error("participant observation authority failed closed: {0}")]
    Authority(#[from] pos_core::AuthorityErrorV1),

    #[error("participant-authorized Driver work requires a fresh authority fence")]
    AuthorityFenceRequired,

    #[error(transparent)]
    ScheduledProfile(#[from] crate::ScheduledProfileErrorV1),

    #[error("scheduled admission authority persistence failed closed: {0}")]
    AuthorityPersistence(pos_core::AuthorityPersistenceErrorV1),

    #[error("scheduled pass admission basis is invalid: {0}")]
    PipelineContract(pos_core::PipelineContractErrorV1),

    #[error("scheduled pass was not admitted: {}", outcome_discriminant(.0))]
    ScheduledPassNotAdmitted(Box<pos_core::PipelineOutcomeV1>),

    #[error("no scheduled pass admission is in doubt")]
    NoScheduledAdmissionInDoubt,

    #[error(
        "driver '{driver}' cadence overflow: previous={previous_ns}ns, interval={interval_ns}ns"
    )]
    CadenceOverflow {
        driver: String,
        previous_ns: u128,
        interval_ns: u128,
    },

    #[error("driver '{driver}' requires a snapshot anchor")]
    MissingSnapshotAnchor { driver: String },

    #[error("snapshot Timeline mismatch: expected {expected}, got {actual}")]
    SnapshotTimelineMismatch {
        expected: TimelineId,
        actual: TimelineId,
    },

    #[error("an anchored Driver step is already pending")]
    PendingDriverStep,

    #[error("nonempty Driver output must be appended before the step can be committed")]
    UnappendedDriverOutput,

    #[error("driver '{driver}' must be fresh before recovery")]
    DriverRecoveryNotFresh { driver: String },

    #[error("driver '{driver}' committed tick exceeds the V1 range")]
    DriverTickOverflow { driver: String },

    #[error("invalid driver recovery evidence: {reason}")]
    InvalidRecoveryEvidence { reason: &'static str },

    /// A community Plugin host failure (ADR-061), the registry's only error
    /// channel for the closed typed host error.
    #[error(transparent)]
    CommunityPlugin(#[from] crate::community_plugin_host::CommunityPluginHostErrorV1),

    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),

    #[error("recorder mode mismatch: expected {expected}, got {got}")]
    ModeMismatch { expected: String, got: String },
}

/// A composition failure found while building an output binding is the same
/// closed composition error on every registration path (ADR-024 Revision 1).
impl From<crate::OutputAdmissionErrorV1> for RuntimeError {
    fn from(error: crate::OutputAdmissionErrorV1) -> Self {
        match error {
            crate::OutputAdmissionErrorV1::Composition(error) => Self::Composition(error),
            error => Self::OutputAdmission(error),
        }
    }
}

/// Name only the outcome discriminant so a rendered error never carries
/// receipt data such as Event identities or digests.
const fn outcome_discriminant(outcome: &pos_core::PipelineOutcomeV1) -> &'static str {
    use pos_core::PipelineOutcomeV1 as Outcome;
    match outcome {
        Outcome::Rejected => "Rejected",
        Outcome::InvalidObservation => "InvalidObservation",
        Outcome::AuthorityRevoked => "AuthorityRevoked",
        Outcome::AuthorityExpired => "AuthorityExpired",
        Outcome::PolicyIndeterminate => "PolicyIndeterminate",
        Outcome::ResourceExhausted => "ResourceExhausted",
        Outcome::InvalidPluginResult => "InvalidPluginResult",
        Outcome::InvalidProviderResult => "InvalidProviderResult",
        Outcome::Committed(_) => "Committed",
        Outcome::RecoveredDuplicate(_) => "RecoveredDuplicate",
        _ => conflict_outcome_discriminant(outcome),
    }
}

/// The discriminant of the outcomes that name a conflict or a dependency fault.
const fn conflict_outcome_discriminant(outcome: &pos_core::PipelineOutcomeV1) -> &'static str {
    use pos_core::PipelineOutcomeV1 as Outcome;
    match outcome {
        Outcome::DomainConflict => "DomainConflict",
        Outcome::AdmissionConflict => "AdmissionConflict",
        Outcome::InvalidDependencyDeclaration => "InvalidDependencyDeclaration",
        _ => "DependencySetExhausted",
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::ids::{PluginId, TimelineId};

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn duplicate_plugin_displays() {
        let e = RuntimeError::DuplicatePlugin {
            id: PluginId::new(),
            name: "my-plugin".to_owned(),
        };
        assert!(e.to_string().contains("my-plugin"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn unknown_event_type_displays() {
        let e = RuntimeError::UnknownEventType("world.unknown".to_owned());
        assert!(e.to_string().contains("world.unknown"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn invalid_payload_displays() {
        let e = RuntimeError::InvalidPayload {
            event_type: "agent.action".to_owned(),
            reason: "missing required field".to_owned(),
        };
        assert!(e.to_string().contains("agent.action"));
        assert!(e.to_string().contains("missing required field"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn no_driver_displays() {
        let e = RuntimeError::NoDriver {
            name: "static-plugin".to_owned(),
        };
        assert!(e.to_string().contains("static-plugin"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_panicked_displays() {
        let error = RuntimeError::DriverPanicked {
            name: "unstable".to_owned(),
        };
        assert!(error.to_string().contains("unstable"));
        assert!(error.to_string().contains("aborted"));
    }

    #[test]
    fn resource_exhausted_displays() {
        let error = RuntimeError::ResourceExhausted {
            driver: "bounded".to_owned(),
            requested: 11,
            limit: 10,
        };
        assert!(error.to_string().contains("bounded"));
        assert!(error.to_string().contains("requested=11"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn capability_mismatch_displays() {
        let e = RuntimeError::CapabilityMismatch {
            name: "agent".to_owned(),
            reason: "has_driver=true but no driver provided".to_owned(),
        };
        assert!(e.to_string().contains("agent"));
        assert!(e.to_string().contains("has_driver"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reserved_geographic_event_type_displays() {
        let error = RuntimeError::ReservedGeographicEventType {
            name: "malicious".to_owned(),
            event_type: pos_core::GEOGRAPHIC_EVENT_TYPE.to_owned(),
        };
        assert!(error.to_string().contains("core-owned"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mode_mismatch_displays() {
        let e = RuntimeError::ModeMismatch {
            expected: "Live".to_owned(),
            got: "Replay".to_owned(),
        };
        assert!(e.to_string().contains("Live"));
        assert!(e.to_string().contains("Replay"));
    }

    #[test]
    fn the_dependency_outcomes_are_named_by_their_discriminant() {
        use pos_core::PipelineOutcomeV1;

        for (outcome, name) in [
            (
                PipelineOutcomeV1::InvalidDependencyDeclaration,
                "InvalidDependencyDeclaration",
            ),
            (
                PipelineOutcomeV1::DependencySetExhausted,
                "DependencySetExhausted",
            ),
        ] {
            assert_eq!(
                RuntimeError::ScheduledPassNotAdmitted(Box::new(outcome)).to_string(),
                format!("scheduled pass was not admitted: {name}")
            );
        }
    }

    #[test]
    fn a_community_host_error_is_carried_verbatim() {
        use crate::community_plugin_host::CommunityPluginHostErrorV1;

        let error = RuntimeError::from(CommunityPluginHostErrorV1::WorkerCrashed);
        assert_eq!(error.to_string(), "community Plugin worker crashed");
        assert!(matches!(
            error,
            RuntimeError::CommunityPlugin(CommunityPluginHostErrorV1::WorkerCrashed)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn anchored_driver_errors_report_only_host_owned_context() {
        let expected = TimelineId::new();
        let actual = TimelineId::new();
        let missing = RuntimeError::MissingSnapshotAnchor {
            driver: "provider-agent".to_owned(),
        };
        let mismatch = RuntimeError::SnapshotTimelineMismatch { expected, actual };
        let pending = RuntimeError::PendingDriverStep;
        let overflow = RuntimeError::DriverTickOverflow {
            driver: "provider-agent".to_owned(),
        };

        assert_eq!(
            missing.to_string(),
            "driver 'provider-agent' requires a snapshot anchor"
        );
        assert_eq!(
            mismatch.to_string(),
            format!("snapshot Timeline mismatch: expected {expected}, got {actual}")
        );
        assert_eq!(
            pending.to_string(),
            "an anchored Driver step is already pending"
        );
        assert_eq!(
            overflow.to_string(),
            "driver 'provider-agent' committed tick exceeds the V1 range"
        );
    }
}
