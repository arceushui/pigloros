#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-rule-agent` — deterministic rule-based agent plugin.
//!
//! Owns event type `"agent.decision"` and entity kind `"rule-agent"`.
//! On each driver step it cycles through a fixed action list and emits
//! one `agent.decision` event with a CBOR payload.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::TimelineId,
    ids::{EntityId, PluginId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    store::EventStore,
};
use pos_runtime::{Driver, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};

/// The entity kind string for rule agents.
pub const ENTITY_KIND: &str = "rule-agent";

/// The event type for agent decisions.
pub const EVENT_TYPE_DECISION: &str = "agent.decision";

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DecisionPayload {
    action: String,
    tick: u32,
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// A deterministic rule-based agent plugin.
pub struct RuleAgentPlugin {
    id: PluginId,
    actions: Vec<String>,
}

impl Default for RuleAgentPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleAgentPlugin {
    /// Create a plugin with the default four-action cycle: idle, move, interact, observe.
    #[must_use]
    pub fn new() -> Self {
        Self::with_actions(vec![
            "idle".to_owned(),
            "move".to_owned(),
            "interact".to_owned(),
            "observe".to_owned(),
        ])
    }

    /// Create a plugin with a custom action list.
    ///
    /// # Panics
    ///
    /// Panics if `actions` is empty.
    #[must_use]
    pub fn with_actions(actions: Vec<String>) -> Self {
        assert!(!actions.is_empty(), "actions list must not be empty");
        Self {
            id: PluginId::new(),
            actions,
        }
    }

    /// Return the actions list (for constructing drivers and reducers).
    #[must_use]
    pub fn actions(&self) -> &[String] {
        &self.actions
    }
}

impl Plugin for RuleAgentPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "rule-agent"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_DECISION)],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Produces one `agent.decision` event per step, cycling through the action list.
pub struct RuleAgentDriver {
    entity: EntityId,
    tick: u32,
    actions: Vec<String>,
}

impl RuleAgentDriver {
    /// Create a new driver for the given entity.
    #[must_use]
    pub fn new(entity: EntityId, actions: Vec<String>) -> Self {
        Self {
            entity,
            tick: 0,
            actions,
        }
    }
}

impl Driver for RuleAgentDriver {
    fn name(&self) -> &'static str {
        "rule-agent-driver"
    }

    fn step(
        &mut self,
        _store: &dyn EventStore,
        _timeline: TimelineId,
    ) -> Result<StepOutput, RuntimeError> {
        let action = self.actions[self.tick as usize % self.actions.len()].clone();
        let payload = DecisionPayload {
            action,
            tick: self.tick,
        };

        let mut buf = Vec::new();
        // Writing to Vec<u8> is infallible with ciborium.
        ciborium::into_writer(&payload, &mut buf).expect("ciborium write to Vec<u8> is infallible");

        let draft = pos_core::event::EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE_DECISION),
            CanonicalBytes::from_vec(buf),
        );

        self.tick += 1;
        Ok(StepOutput::new(vec![draft]))
    }
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/// Tracks per-agent decision count in State.
pub struct RuleAgentReducer;

impl Reducer for RuleAgentReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("decisions", serde_json::Value::Number(0.into()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_DECISION {
            let decisions = state
                .get("decisions")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "decisions",
                serde_json::Value::Number((decisions + 1).into()),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, SchemaVersion},
        ids::{EntityId, EventId},
    };
    use pos_store::{open_store, StoreConfig};

    fn make_decision_event(entity: EntityId) -> Event {
        // Build a minimal valid decision payload
        let payload = DecisionPayload {
            action: "idle".to_owned(),
            tick: 0,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_DECISION),
            payload: CanonicalBytes::from_vec(buf),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_registers_correct_capability() {
        let plugin = RuleAgentPlugin::new();
        let cap = plugin.capability();

        assert_eq!(cap.owned_event_types.len(), 1);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_DECISION);
        assert_eq!(cap.owned_entity_kinds.len(), 1);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_produces_decision_events() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let plugin = RuleAgentPlugin::new();
        let mut driver = RuleAgentDriver::new(entity, plugin.actions().to_vec());

        let expected = ["idle", "move", "interact", "observe"];
        for expected_action in &expected {
            let out = driver.step(store.as_ref(), tl.id()).unwrap();
            assert_eq!(out.drafts.len(), 1);
            assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_DECISION);

            // Decode the payload and verify the action
            let payload: DecisionPayload =
                ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();
            assert_eq!(&payload.action, expected_action);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_counts_decisions() {
        let reducer = RuleAgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state.get("decisions").and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for _ in 0..3 {
            let event = make_decision_event(entity);
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state.get("decisions").and_then(serde_json::Value::as_u64),
            Some(3)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_creates_plugin_with_four_actions() {
        let plugin = RuleAgentPlugin::default();
        assert_eq!(plugin.actions().len(), 4);
        assert_eq!(plugin.actions()[0], "idle");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_and_name() {
        let plugin = RuleAgentPlugin::new();
        let _id = plugin.id(); // covers Plugin::id()
        assert_eq!(plugin.name(), "rule-agent");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_name_is_correct() {
        let entity = EntityId::new();
        let driver = RuleAgentDriver::new(entity, vec!["a".to_owned()]);
        assert_eq!(driver.name(), "rule-agent-driver");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cbor_payload_is_valid() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let plugin = RuleAgentPlugin::new();
        let mut driver = RuleAgentDriver::new(entity, plugin.actions().to_vec());

        let out = driver.step(store.as_ref(), tl.id()).unwrap();
        assert_eq!(out.drafts.len(), 1);

        let payload: DecisionPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();

        assert_eq!(payload.action, "idle");
        assert_eq!(payload.tick, 0);
    }
}
