use pos_core::ids::PluginId;
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

    #[error("plugin '{name}' capability mismatch: {reason}")]
    CapabilityMismatch { name: String, reason: String },

    #[error("plugin '{name}' cannot claim core-owned geographic event type '{event_type}'")]
    ReservedGeographicEventType { name: String, event_type: String },

    #[error("driver emitted core-owned geographic event type '{event_type}'")]
    GeographicDraft { event_type: String },

    #[error(
        "driver '{driver}' cadence overflow: previous={previous_ns}ns, interval={interval_ns}ns"
    )]
    CadenceOverflow {
        driver: String,
        previous_ns: u128,
        interval_ns: u128,
    },

    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),

    #[error("recorder mode mismatch: expected {expected}, got {got}")]
    ModeMismatch { expected: String, got: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::ids::PluginId;

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
}
