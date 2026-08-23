use pos_core::ids::{PluginId, TimelineId};
use pos_core::ConsentError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
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

    #[error("protected operation failed its consent fence: {0}")]
    Consent(ConsentError),

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

    #[error("driver '{driver}' must be fresh before recovery")]
    DriverRecoveryNotFresh { driver: String },

    #[error("driver '{driver}' committed tick exceeds the V1 range")]
    DriverTickOverflow { driver: String },

    #[error("invalid driver recovery evidence: {reason}")]
    InvalidRecoveryEvidence { reason: &'static str },

    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),

    #[error("recorder mode mismatch: expected {expected}, got {got}")]
    ModeMismatch { expected: String, got: String },
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
