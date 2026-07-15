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
    fn duplicate_plugin_displays() {
        let e = RuntimeError::DuplicatePlugin {
            id: PluginId::new(),
            name: "my-plugin".to_owned(),
        };
        assert!(e.to_string().contains("my-plugin"));
    }

    #[test]
    fn unknown_event_type_displays() {
        let e = RuntimeError::UnknownEventType("world.unknown".to_owned());
        assert!(e.to_string().contains("world.unknown"));
    }

    #[test]
    fn invalid_payload_displays() {
        let e = RuntimeError::InvalidPayload {
            event_type: "agent.action".to_owned(),
            reason: "missing required field".to_owned(),
        };
        assert!(e.to_string().contains("agent.action"));
        assert!(e.to_string().contains("missing required field"));
    }

    #[test]
    fn no_driver_displays() {
        let e = RuntimeError::NoDriver { name: "static-plugin".to_owned() };
        assert!(e.to_string().contains("static-plugin"));
    }

    #[test]
    fn mode_mismatch_displays() {
        let e = RuntimeError::ModeMismatch {
            expected: "Live".to_owned(),
            got: "Replay".to_owned(),
        };
        assert!(e.to_string().contains("Live"));
        assert!(e.to_string().contains("Replay"));
    }
}
