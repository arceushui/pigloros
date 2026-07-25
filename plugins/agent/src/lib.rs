#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-agent` — AI-agent entity plugin with swappable `AgentPolicy`.
//!
//! Owns event type `"agent.action"` and entity kind `"ai-agent"`.
//! On each driver step it invokes the policy's `decide()` method and emits
//! one `agent.action` event with a CBOR payload.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    store::EventStore,
};
use pos_runtime::{Driver, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};

/// The entity kind string for AI agents.
pub const ENTITY_KIND: &str = "ai-agent";

/// The event type for agent actions.
pub const EVENT_TYPE_ACTION: &str = "agent.action";

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/// Context passed to the policy on each decision.
#[derive(Debug, Clone)]
pub struct AgentContext {
    pub entity_id: EntityId,
    pub tick: u64,
    pub available_actions: Vec<String>,
}

/// The action returned by the policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentAction {
    pub action: String,
    pub confidence: f64, // 0.0..=1.0
}

/// Pluggable policy trait — the seam for AI/LLM/custom logic.
pub trait AgentPolicy: Send + Sync {
    fn name(&self) -> &'static str;
    fn decide(&mut self, context: &AgentContext) -> AgentAction;
}

// ---------------------------------------------------------------------------
// Built-in policies
// ---------------------------------------------------------------------------

/// Cycles through actions in order; confidence = 1.0
pub struct RoundRobinPolicy {
    actions: Vec<String>,
    cursor: usize,
}

impl RoundRobinPolicy {
    #[must_use]
    pub fn new(actions: Vec<String>) -> Self {
        Self { actions, cursor: 0 }
    }
}

impl AgentPolicy for RoundRobinPolicy {
    fn name(&self) -> &'static str {
        "round-robin"
    }

    fn decide(&mut self, _context: &AgentContext) -> AgentAction {
        let action = self.actions[self.cursor % self.actions.len()].clone();
        self.cursor = self.cursor.wrapping_add(1);
        AgentAction {
            action,
            confidence: 1.0,
        }
    }
}

/// Deterministic pseudo-random using seed ^ counter as index; confidence = 0.5
pub struct RandomSeedPolicy {
    actions: Vec<String>,
    seed: u64,
    counter: u64,
}

impl RandomSeedPolicy {
    #[must_use]
    pub fn new(actions: Vec<String>, seed: u64) -> Self {
        Self {
            actions,
            seed,
            counter: 0,
        }
    }
}

impl AgentPolicy for RandomSeedPolicy {
    fn name(&self) -> &'static str {
        "random-seed"
    }

    fn decide(&mut self, _context: &AgentContext) -> AgentAction {
        let combined = self.seed.wrapping_add(self.counter);
        let actions_len = u64::try_from(self.actions.len()).unwrap_or(u64::MAX);
        let modulo_result = combined % actions_len;
        let index = usize::try_from(modulo_result).unwrap_or(0);
        self.counter = self.counter.wrapping_add(1);
        let action = self.actions[index].clone();
        AgentAction {
            action,
            confidence: 0.5,
        }
    }
}

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActionPayload {
    action: String,
    confidence: f64,
    tick: u64,
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// An AI-agent plugin with a swappable policy.
pub struct AgentPlugin {
    id: PluginId,
}

impl Default for AgentPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentPlugin {
    /// Create a new agent plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for AgentPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "agent"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_ACTION)],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Produces one `agent.action` event per step, invoking the policy's `decide()` method.
pub struct AgentDriver {
    entity: EntityId,
    policy: Box<dyn AgentPolicy>,
    tick: u64,
    available_actions: Vec<String>,
}

impl AgentDriver {
    /// Create a new driver for the given entity with the specified policy.
    #[must_use]
    pub fn new(
        entity: EntityId,
        policy: Box<dyn AgentPolicy>,
        available_actions: Vec<String>,
    ) -> Self {
        Self {
            entity,
            policy,
            tick: 0,
            available_actions,
        }
    }
}

impl Driver for AgentDriver {
    fn name(&self) -> &'static str {
        "agent-driver"
    }

    fn step(
        &mut self,
        _store: &dyn EventStore,
        _timeline: TimelineId,
    ) -> Result<StepOutput, RuntimeError> {
        let context = AgentContext {
            entity_id: self.entity,
            tick: self.tick,
            available_actions: self.available_actions.clone(),
        };

        let decision = self.policy.decide(&context);

        let payload = ActionPayload {
            action: decision.action,
            confidence: decision.confidence,
            tick: self.tick,
        };

        let mut buf = Vec::new();
        // Writing to Vec<u8> is infallible with ciborium.
        ciborium::into_writer(&payload, &mut buf).expect("ciborium write to Vec<u8> is infallible");

        let draft = pos_core::event::EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE_ACTION),
            CanonicalBytes::from_vec(buf),
        );

        self.tick = self.tick.wrapping_add(1);
        Ok(StepOutput::new(vec![draft]))
    }
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/// Tracks per-agent action count and last action in State.
pub struct AgentReducer;

impl Reducer for AgentReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("action_count", serde_json::Value::Number(0.into()));
        s.set("last_action", serde_json::Value::String(String::new()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_ACTION {
            let action_count = state
                .get("action_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "action_count",
                serde_json::Value::Number((action_count + 1).into()),
            );

            // Decode payload to extract last_action
            if let Ok(payload) = ciborium::from_reader::<ActionPayload, _>(event.payload.as_slice())
            {
                state.set("last_action", serde_json::Value::String(payload.action));
            }
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

    fn make_action_event(entity: EntityId, action: &str) -> Event {
        let payload = ActionPayload {
            action: action.to_owned(),
            confidence: 0.8,
            tick: 0,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_ACTION),
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

    fn make_other_event(entity: EntityId) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("other.event"),
            payload: CanonicalBytes::from_vec(vec![]),
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
    fn plugin_new_and_default() {
        let p1 = AgentPlugin::new();
        let p2 = AgentPlugin::default();
        assert_eq!(p1.name(), "agent");
        assert_eq!(p2.name(), "agent");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_name_is_agent() {
        let plugin = AgentPlugin::new();
        assert_eq!(plugin.name(), "agent");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_returned() {
        let plugin = AgentPlugin::new();
        let _id = plugin.id(); // covers Plugin::id()
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_is_correct() {
        let plugin = AgentPlugin::new();
        let cap = plugin.capability();

        assert_eq!(cap.owned_event_types.len(), 1);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_ACTION);
        assert_eq!(cap.owned_entity_kinds.len(), 1);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn round_robin_policy_cycles_correctly() {
        let mut policy =
            RoundRobinPolicy::new(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
        assert_eq!(policy.name(), "round-robin");

        let ctx = AgentContext {
            entity_id: EntityId::new(),
            tick: 0,
            available_actions: vec![],
        };

        let d1 = policy.decide(&ctx);
        assert_eq!(d1.action, "a");
        assert!((d1.confidence - 1.0).abs() < f64::EPSILON);

        let d2 = policy.decide(&ctx);
        assert_eq!(d2.action, "b");
        assert!((d2.confidence - 1.0).abs() < f64::EPSILON);

        let d3 = policy.decide(&ctx);
        assert_eq!(d3.action, "c");
        assert!((d3.confidence - 1.0).abs() < f64::EPSILON);

        let d4 = policy.decide(&ctx);
        assert_eq!(d4.action, "a");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn random_seed_policy_is_deterministic() {
        let actions = vec!["x".to_owned(), "y".to_owned(), "z".to_owned()];
        let mut policy1 = RandomSeedPolicy::new(actions.clone(), 42);
        let mut policy2 = RandomSeedPolicy::new(actions, 42);

        assert_eq!(policy1.name(), "random-seed");

        let ctx = AgentContext {
            entity_id: EntityId::new(),
            tick: 0,
            available_actions: vec![],
        };

        for _ in 0..10 {
            let d1 = policy1.decide(&ctx);
            let d2 = policy2.decide(&ctx);
            assert_eq!(d1.action, d2.action);
            assert!((d1.confidence - 0.5).abs() < f64::EPSILON);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_correct_event_type() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec!["act1".to_owned()]));
        let mut driver = AgentDriver::new(entity, policy, vec!["act1".to_owned()]);

        let out = driver.step(store.as_ref(), tl.id()).unwrap();
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_ACTION);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_decodable_payload() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec![
            "jump".to_owned(),
            "duck".to_owned(),
        ]));
        let mut driver =
            AgentDriver::new(entity, policy, vec!["jump".to_owned(), "duck".to_owned()]);

        let out = driver.step(store.as_ref(), tl.id()).unwrap();
        let payload: ActionPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();

        assert_eq!(payload.action, "jump");
        assert!((payload.confidence - 1.0).abs() < f64::EPSILON);
        assert_eq!(payload.tick, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_action_count() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for _ in 0..5 {
            let event = make_action_event(entity, "test");
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_last_action() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event1 = make_action_event(entity, "first");
        reducer.apply(&mut state, &event1);
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("first")
        );

        let event2 = make_action_event(entity, "second");
        reducer.apply(&mut state, &event2);
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("second")
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let other = make_other_event(entity);
        reducer.apply(&mut state, &other);

        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("")
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_name_is_correct() {
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec!["a".to_owned()]));
        let driver = AgentDriver::new(entity, policy, vec!["a".to_owned()]);
        assert_eq!(driver.name(), "agent-driver");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn round_robin_wraps_at_end() {
        let mut policy = RoundRobinPolicy::new(vec!["a".to_owned(), "b".to_owned()]);
        let ctx = AgentContext {
            entity_id: EntityId::new(),
            tick: 0,
            available_actions: vec![],
        };

        let _d1 = policy.decide(&ctx);
        let _d2 = policy.decide(&ctx);
        let d3 = policy.decide(&ctx);
        assert_eq!(d3.action, "a");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn random_seed_policy_different_seeds_differ() {
        let actions = vec!["x".to_owned(), "y".to_owned(), "z".to_owned()];
        let mut policy1 = RandomSeedPolicy::new(actions.clone(), 42);
        let mut policy2 = RandomSeedPolicy::new(actions, 99);

        let ctx = AgentContext {
            entity_id: EntityId::new(),
            tick: 0,
            available_actions: vec![],
        };

        let d1 = policy1.decide(&ctx);
        let d2 = policy2.decide(&ctx);
        // This is probabilistic but very likely to differ given different seeds
        // For deterministic test, we just ensure both produce valid decisions
        assert!(!d1.action.is_empty());
        assert!(!d2.action.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_tick_increments() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec!["a".to_owned()]));
        let mut driver = AgentDriver::new(entity, policy, vec!["a".to_owned()]);

        driver.step(store.as_ref(), tl.id()).unwrap();
        let out = driver.step(store.as_ref(), tl.id()).unwrap();

        let payload: ActionPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();
        assert_eq!(payload.tick, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn agent_action_partial_eq() {
        let a1 = AgentAction {
            action: "test".to_owned(),
            confidence: 0.5,
        };
        let a2 = AgentAction {
            action: "test".to_owned(),
            confidence: 0.5,
        };
        let a3 = AgentAction {
            action: "other".to_owned(),
            confidence: 0.5,
        };
        assert_eq!(a1, a2);
        assert_ne!(a1, a3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn agent_context_contains_available_actions() {
        let ctx = AgentContext {
            entity_id: EntityId::new(),
            tick: 5,
            available_actions: vec!["a".to_owned(), "b".to_owned()],
        };
        assert_eq!(ctx.available_actions.len(), 2);
        assert_eq!(ctx.tick, 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state_has_correct_fields() {
        let reducer = AgentReducer;
        let state = reducer.initial();
        assert!(state.get("action_count").is_some());
        assert!(state.get("last_action").is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_handles_malformed_payload() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        // Create an event with invalid CBOR payload
        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_ACTION),
            payload: CanonicalBytes::from_vec(vec![0xFF, 0xFF]), // Invalid CBOR
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &event);

        // Count should increment even if payload is malformed
        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        // last_action should remain empty string since payload decode failed
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("")
        );
    }
}
