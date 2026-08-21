use serde::{Deserialize, Serialize};

use crate::event::{CanonicalBytes, EventDraft, Kind};
use crate::ids::{EntityId, PluginId};

/// Maximum payload size allowed for a proposed action (4,096 bytes per ADR-057).
pub const MAX_PROPOSED_ACTION_PAYLOAD_BYTES: usize = 4096;

/// What a plugin can do — the capabilities it registers with the runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Event types this plugin declares and owns.
    pub owned_event_types: Vec<Kind>,
    /// Entity kind names this plugin introduces.
    pub owned_entity_kinds: Vec<String>,
    /// Whether this plugin provides a Driver/Stepper.
    pub has_driver: bool,
    /// Whether this plugin provides a Reducer.
    pub has_reducer: bool,
}

/// Minimal plugin descriptor. The runtime (piglor-runtime) implements full registration.
/// The kernel only carries this as a type — no I/O, no execution here.
pub trait Plugin: Send + Sync {
    fn id(&self) -> PluginId;
    fn name(&self) -> &'static str;
    fn capability(&self) -> Capability;
    /// Crate version string (e.g. "0.1.0"). Defaults to "0.1.0".
    fn version(&self) -> &'static str {
        "0.1.0"
    }
}

/// A proposed action submitted through the capability-checked envelope (ADR-057).
///
/// Proposed actions are validated and approved by the owning plugin's [`ActionApprover`]
/// before an event reaches the Timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedAction {
    /// The target event type (e.g. `"world.action"`).
    pub event_type: Kind,
    /// The entity ID of the actor submitting the action.
    pub actor_entity_id: EntityId,
    /// The opaque canonical payload bytes. The value is untrusted until it
    /// crosses [`PluginRegistry::submit_action`](https://docs.rs/pos-runtime/latest/pos_runtime/struct.PluginRegistry.html#method.submit_action)
    /// or is created with [`Self::try_new`].
    pub payload: CanonicalBytes,
    /// The declared capability string (e.g. `"world.action.submit"`).
    pub capability: Kind,
}

impl ProposedAction {
    /// Create a new proposed action.
    #[must_use]
    pub const fn new(
        event_type: Kind,
        actor_entity_id: EntityId,
        payload: CanonicalBytes,
        capability: Kind,
    ) -> Self {
        Self {
            event_type,
            actor_entity_id,
            payload,
            capability,
        }
    }

    /// Create a proposed action while enforcing the canonical payload bound.
    ///
    /// # Errors
    /// Returns [`ActionRejected::PayloadTooLarge`] when `payload` exceeds 4,096 bytes.
    pub fn try_new(
        event_type: Kind,
        actor_entity_id: EntityId,
        payload: CanonicalBytes,
        capability: Kind,
    ) -> Result<Self, ActionRejected> {
        if payload.len() > MAX_PROPOSED_ACTION_PAYLOAD_BYTES {
            return Err(ActionRejected::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
            });
        }
        Ok(Self::new(event_type, actor_entity_id, payload, capability))
    }
}

/// Reason for rejection of a proposed action (ADR-057).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionRejected {
    /// No plugin owns or approves the requested event type.
    UnknownEventType,
    /// The caller does not possess the required capability.
    CapabilityNotGranted,
    /// The actor entity ID does not match the authenticated principal.
    InvalidActorEntityId,
    /// Domain-specific validation failed in the owning plugin.
    DomainValidationFailed(String),
    /// The proposed payload exceeded the size limit.
    PayloadTooLarge { size: usize, max: usize },
}

impl std::fmt::Display for ActionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEventType => write!(f, "unknown event type"),
            Self::CapabilityNotGranted => write!(f, "capability not granted"),
            Self::InvalidActorEntityId => write!(f, "invalid actor entity ID"),
            Self::DomainValidationFailed(msg) => write!(f, "domain validation failed: {msg}"),
            Self::PayloadTooLarge { size, max } => {
                write!(
                    f,
                    "payload too large: size {size} bytes exceeds maximum {max} bytes"
                )
            }
        }
    }
}

impl std::error::Error for ActionRejected {}

/// Trait implemented by plugins that validate and approve proposed actions (ADR-057).
pub trait ActionApprover: Send + Sync {
    /// Validate and approve a proposed action, returning an [`EventDraft`] on success.
    ///
    /// # Errors
    /// Returns [`ActionRejected`] if validation or capability checks fail.
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        id: PluginId,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            "test-plugin"
        }
        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![Kind::new("test.event")],
                owned_entity_kinds: vec!["test.entity".to_owned()],
                has_driver: true,
                has_reducer: true,
            }
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_json_round_trip() {
        let cap = Capability {
            owned_event_types: vec![Kind::new("world.observation"), Kind::new("agent.decision")],
            owned_entity_kinds: vec!["agent".to_owned()],
            has_driver: true,
            has_reducer: false,
        };
        let back: Capability = serde_json::from_str(&serde_json::to_string(&cap).unwrap()).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_cbor_round_trip() {
        let cap = Capability {
            owned_event_types: vec![Kind::new("sensor.reading")],
            owned_entity_kinds: vec![],
            has_driver: false,
            has_reducer: true,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&cap, &mut buf).unwrap();
        let back: Capability = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_trait_is_implemented() {
        let p = TestPlugin {
            id: PluginId::new(),
        };
        assert_eq!(p.name(), "test-plugin");
        assert_eq!(p.capability().owned_event_types.len(), 1);
        assert_eq!(p.capability().owned_entity_kinds[0], "test.entity");
        assert!(p.capability().has_driver);
        assert_eq!(p.version(), "0.1.0");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_capability_is_empty() {
        let cap = Capability::default();
        assert!(cap.owned_event_types.is_empty());
        assert!(cap.owned_entity_kinds.is_empty());
        assert!(!cap.has_driver);
        assert!(!cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn proposed_action_try_new_enforces_payload_bound() {
        let actor = EntityId::new();
        let payload = CanonicalBytes::from_vec(vec![0u8; MAX_PROPOSED_ACTION_PAYLOAD_BYTES + 1]);
        let result = ProposedAction::try_new(
            Kind::new("test.event"),
            actor,
            payload,
            Kind::new("test.event.submit"),
        );
        assert_eq!(
            result,
            Err(ActionRejected::PayloadTooLarge {
                size: MAX_PROPOSED_ACTION_PAYLOAD_BYTES + 1,
                max: MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
            })
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_returned_by_id_method() {
        let expected_id = PluginId::new();
        let p = TestPlugin { id: expected_id };
        assert_eq!(p.id(), expected_id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn proposed_action_new_and_fields() {
        let entity = EntityId::new();
        let payload = CanonicalBytes::from_vec(vec![1, 2, 3]);
        let proposal = ProposedAction::new(
            Kind::new("test.action"),
            entity,
            payload.clone(),
            Kind::new("test.action.submit"),
        );
        assert_eq!(proposal.event_type.as_str(), "test.action");
        assert_eq!(proposal.actor_entity_id, entity);
        assert_eq!(proposal.payload, payload);
        assert_eq!(proposal.capability.as_str(), "test.action.submit");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn proposed_action_serde_round_trip() {
        let entity = EntityId::new();
        let payload = CanonicalBytes::from_vec(vec![1, 2, 3]);
        let proposal = ProposedAction::new(
            Kind::new("test.action"),
            entity,
            payload,
            Kind::new("test.action.submit"),
        );
        let serialized = serde_json::to_string(&proposal).unwrap();
        let deserialized: ProposedAction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(proposal, deserialized);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn action_rejected_display_and_error() {
        let errors = vec![
            (ActionRejected::UnknownEventType, "unknown event type"),
            (
                ActionRejected::CapabilityNotGranted,
                "capability not granted",
            ),
            (
                ActionRejected::InvalidActorEntityId,
                "invalid actor entity ID",
            ),
            (
                ActionRejected::DomainValidationFailed("bad data".to_owned()),
                "domain validation failed: bad data",
            ),
            (
                ActionRejected::PayloadTooLarge {
                    size: 5000,
                    max: 4096,
                },
                "payload too large: size 5000 bytes exceeds maximum 4096 bytes",
            ),
        ];

        for (err, expected_msg) in errors {
            assert_eq!(err.to_string(), expected_msg);
            let json = serde_json::to_string(&err).unwrap();
            let back: ActionRejected = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }
}
