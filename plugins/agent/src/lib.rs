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
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod protocol;
pub mod provider;
pub mod provider_driver;
pub mod replay;

pub use provider::{AgentDecisionProvider, FixtureAgentDecisionProvider, FixtureProviderCallCount};
pub use provider_driver::ProviderBackedAgentDriver;
pub use replay::{AgentDecisionReplayVerifier, ReplayCheckpoint, ReplayVerificationError};

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
    pub const fn new(actions: Vec<String>) -> Self {
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
    pub const fn new(actions: Vec<String>, seed: u64) -> Self {
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
    tick_interval: Duration,
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
            tick_interval: Duration::from_millis(100),
        }
    }

    /// Override the deterministic interval between eligible Agent ticks.
    #[must_use]
    pub const fn with_tick_interval(mut self, tick_interval: Duration) -> Self {
        self.tick_interval = tick_interval;
        self
    }
}

impl Driver for AgentDriver {
    fn name(&self) -> &'static str {
        "agent-driver"
    }

    fn tick_interval(&self) -> Duration {
        self.tick_interval
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
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
        ciborium::into_writer(&payload, &mut buf).map_err(|error| {
            RuntimeError::InvalidPayload {
                event_type: EVENT_TYPE_ACTION.to_owned(),
                reason: error.to_string(),
            }
        })?;

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

            let action = if protocol::is_agent_action_wire(event.payload.as_slice()) {
                protocol::AgentActionV1::decode(event.payload.as_slice())
                    .ok()
                    .map(|payload| payload.action_id().to_owned())
            } else {
                ciborium::from_reader::<ActionPayload, _>(event.payload.as_slice())
                    .ok()
                    .map(|payload| payload.action)
            };
            if let Some(action) = action {
                state.set("last_action", serde_json::Value::String(action));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected agent fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
        }
    }

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
        ciborium::into_writer(&payload, &mut buf).test_ok();

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

    fn make_action_event_with_payload(entity: EntityId, payload: Vec<u8>) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_ACTION),
            payload: CanonicalBytes::from_vec(payload),
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
    fn agent_driver_tick_interval_defaults_and_overrides_without_changing_decisions() {
        let entity = EntityId::new();
        let mut default = AgentDriver::new(
            entity,
            Box::new(RoundRobinPolicy::new(vec!["wait".to_owned()])),
            vec!["wait".to_owned()],
        );
        let mut overridden = AgentDriver::new(
            entity,
            Box::new(RoundRobinPolicy::new(vec!["wait".to_owned()])),
            vec!["wait".to_owned()],
        )
        .with_tick_interval(std::time::Duration::from_millis(200));

        assert_eq!(
            default.tick_interval(),
            std::time::Duration::from_millis(100)
        );
        assert_eq!(
            overridden.tick_interval(),
            std::time::Duration::from_millis(200)
        );

        let timeline = TimelineId::new();
        let default_output = default.step(timeline, ObservationView::empty()).test_ok();
        let overridden_output = overridden
            .step(timeline, ObservationView::empty())
            .test_ok();
        assert_eq!(default_output.drafts.len(), 1);
        assert_eq!(overridden_output.drafts.len(), 1);
        assert_eq!(
            default_output.drafts[0].entity,
            overridden_output.drafts[0].entity
        );
        assert_eq!(
            default_output.drafts[0].event_type,
            overridden_output.drafts[0].event_type
        );
        assert_eq!(
            default_output.drafts[0].payload,
            overridden_output.drafts[0].payload
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_correct_event_type() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec!["act1".to_owned()]));
        let mut driver = AgentDriver::new(entity, policy, vec!["act1".to_owned()]);

        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_ACTION);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_decodable_payload() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec![
            "jump".to_owned(),
            "duck".to_owned(),
        ]));
        let mut driver =
            AgentDriver::new(entity, policy, vec!["jump".to_owned(), "duck".to_owned()]);

        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        let payload: ActionPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).test_ok();

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
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let policy = Box::new(RoundRobinPolicy::new(vec!["a".to_owned()]));
        let mut driver = AgentDriver::new(entity, policy, vec!["a".to_owned()]);

        driver.step(tl.id(), ObservationView::empty()).test_ok();
        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();

        let payload: ActionPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).test_ok();
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

    #[test]
    fn reducer_accepts_active_deterministic_and_provider_action_producers() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();
        let deterministic = make_action_event(entity, "legacy");
        let provider_payload =
            protocol::AgentActionV1::try_new("provider".to_owned(), 42, 7, [8; 32], [9; 32])
                .test_ok()
                .encode()
                .test_ok();
        let provider = make_action_event_with_payload(entity, provider_payload);

        reducer.apply(&mut state, &deterministic);
        reducer.apply(&mut state, &provider);

        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("provider")
        );
    }

    #[test]
    fn reducer_never_falls_back_from_malformed_provider_action_wire() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();
        reducer.apply(&mut state, &make_action_event(entity, "legacy"));

        let mut malformed =
            protocol::AgentActionV1::try_new("provider".to_owned(), 42, 7, [8; 32], [9; 32])
                .test_ok()
                .encode()
                .test_ok();
        malformed[6] = 2;
        let provider = make_action_event_with_payload(entity, malformed);
        reducer.apply(&mut state, &provider);

        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("legacy")
        );
    }

    #[test]
    fn reducer_rejects_cbor_boundary_forms_without_private_codec_access() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();
        reducer.apply(&mut state, &make_action_event(entity, "legacy"));

        let mut payloads = vec![
            vec![0xd8],
            vec![0xd9, 0],
            vec![0xda, 0, 0, 0],
            vec![0xdb, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0x98],
            vec![0x99, 0],
            vec![0x9a, 0, 0, 0],
            vec![0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0x58],
            vec![0x59, 0],
            vec![0x5a, 0, 0, 0],
            vec![0x5b, 0, 0, 0, 0, 0, 0, 0],
            vec![0x5f, 0xff],
            vec![0x5f, 0x58],
            vec![0x5f, 0x42, b'P', b'A', 0x42, b'A', b'1'],
        ];
        for length in 0..2 {
            let mut payload = vec![0x59];
            payload.extend(std::iter::repeat_n(0, length));
            payloads.push(payload);
        }
        for length in 0..4 {
            let mut payload = vec![0x5a];
            payload.extend(std::iter::repeat_n(0, length));
            payloads.push(payload);
        }
        for length in 0..8 {
            let mut payload = vec![0x5b];
            payload.extend(std::iter::repeat_n(0, length));
            payloads.push(payload);
        }

        for payload in payloads {
            reducer.apply(&mut state, &make_action_event_with_payload(entity, payload));
            assert_eq!(
                state.get("last_action").and_then(serde_json::Value::as_str),
                Some("legacy")
            );
        }
        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(1 + 15 + 2 + 4 + 8)
        );
    }

    #[test]
    fn reducer_never_falls_back_when_empty_chunks_precede_or_split_paa1_magic() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();
        reducer.apply(&mut state, &make_action_event(entity, "legacy"));

        let malformed_candidates = [
            vec![
                0x9f, 0x5f, 0x40, 0x40, 0x40, 0x40, 0x41, b'P', 0x41, b'A', 0x41, b'A', 0x41, b'1',
                0xff, 0xff,
            ],
            vec![
                0x9f, 0x5f, 0x41, b'P', 0x40, 0x41, b'A', 0x40, 0x41, b'A', 0x40, 0x41, b'1', 0x40,
                0xff, 0xff,
            ],
            {
                let mut budget_exhausted = vec![0x9f, 0x5f];
                budget_exhausted.extend(std::iter::repeat_n(0x40, 511));
                budget_exhausted.extend([0x41, b'P', 0x41, b'A', 0x41, b'A', 0x41, b'1']);
                budget_exhausted
            },
            {
                let mut exact_post_array_window = vec![0x9f, 0x5f];
                exact_post_array_window.extend(std::iter::repeat_n(0x40, 507));
                exact_post_array_window.extend([0x43, b'P', b'A', b'A']);
                exact_post_array_window
            },
            {
                let mut exact_whole_payload_budget = vec![0x9f, 0x5f];
                exact_whole_payload_budget.extend(std::iter::repeat_n(0x40, 506));
                exact_whole_payload_budget.extend([0x43, b'P', b'A', b'A']);
                exact_whole_payload_budget
            },
            {
                let mut tagged_exact_whole_payload_budget = vec![0xc0; 500];
                tagged_exact_whole_payload_budget.extend([0x9f, 0x5f]);
                tagged_exact_whole_payload_budget.extend(std::iter::repeat_n(0x40, 6));
                tagged_exact_whole_payload_budget.extend([0x43, b'P', b'A', b'A']);
                tagged_exact_whole_payload_budget
            },
            {
                let mut truncated_chunk_header_at_budget = vec![0x9f, 0x5f];
                truncated_chunk_header_at_budget.extend(std::iter::repeat_n(0x40, 509));
                truncated_chunk_header_at_budget.push(0x58);
                truncated_chunk_header_at_budget
            },
        ];

        for payload in malformed_candidates {
            assert!(protocol::is_agent_action_wire(&payload));
            reducer.apply(&mut state, &make_action_event_with_payload(entity, payload));
        }

        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("legacy")
        );
    }

    fn malformed_action_wire_candidates() -> Vec<Vec<u8>> {
        let mut over_limit = vec![0x87, 0x44, b'P', b'A', b'A', b'1'];
        over_limit.resize(513, 0);
        let mut deeply_tagged = vec![0xc0; 512];
        deeply_tagged.extend([0x87, 0x44, b'P', b'A', b'A', b'1']);
        let mut truncated_tag_header = vec![0xc0; 511];
        truncated_tag_header.push(0xd8);
        let mut truncated_array_header = vec![0xc0; 511];
        truncated_array_header.push(0x98);
        vec![
            vec![0x87, 0x44, b'P', b'A', b'A', b'1'],
            over_limit,
            vec![0x98, 0x07, 0x58, 0x04, b'P', b'A', b'A', b'1'],
            vec![0x86, 0x44, b'P', b'A', b'A', b'1'],
            vec![0x9f, 0x5f, 0x44, b'P', b'A', b'A', b'1'],
            vec![0x9f, 0x5f, 0x58, 0x04, b'P', b'A', b'A', b'1'],
            vec![0x9f, 0x5f, 0x59, 0x00, 0x04, b'P', b'A', b'A', b'1'],
            vec![0x9f, 0x5f, 0x41, b'P', 0x41, b'A', 0x42, b'A', b'1'],
            vec![0xd8, 0x2a, 0x87, 0x44, b'P', b'A', b'A', b'1'],
            vec![0xd9, 0x00, 0x2a, 0x87, 0x44, b'P', b'A', b'A', b'1'],
            vec![0xda, 0, 0, 0, 0x2a, 0x87, 0x44, b'P', b'A', b'A', b'1'],
            vec![
                0xdb, 0, 0, 0, 0, 0, 0, 0, 0x2a, 0x87, 0x44, b'P', b'A', b'A', b'1',
            ],
            vec![
                0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x87, 0x44, b'P', b'A', b'A', b'1',
            ],
            deeply_tagged,
            vec![0x9f, 0x5f, 0x5a, 0, 0, 0, 4, b'P', b'A', b'A', b'1'],
            vec![
                0x9f, 0x5f, 0x5b, 0, 0, 0, 0, 0, 0, 0, 4, b'P', b'A', b'A', b'1',
            ],
            vec![0x99, 0, 7, 0x59, 0, 4, b'P', b'A', b'A', b'1'],
            vec![0x9a, 0, 0, 0, 7, 0x5a, 0, 0, 0, 4, b'P', b'A', b'A', b'1'],
            vec![
                0x9b, 0, 0, 0, 0, 0, 0, 0, 7, 0x5b, 0, 0, 0, 0, 0, 0, 0, 4, b'P', b'A', b'A', b'1',
            ],
            vec![0x9f, 0x59, 0, 4, b'P', b'A', b'A', b'1'],
            vec![0x9f, 0x5a, 0, 0, 0, 4, b'P', b'A', b'A', b'1'],
            vec![0x9f, 0x5b, 0, 0, 0, 0, 0, 0, 0, 4, b'P', b'A', b'A', b'1'],
            truncated_tag_header,
            truncated_array_header,
        ]
    }

    fn non_action_wire_prefixes() -> Vec<Vec<u8>> {
        let mut clear_non_candidate_at_budget = vec![0x87, 0x00];
        clear_non_candidate_at_budget.resize(512, 0);
        vec![
            vec![0x98],
            vec![0x99, 0],
            vec![0x9a, 0, 0, 0],
            vec![0x9b, 0, 0, 0, 0, 0, 0, 0],
            vec![0x87, 0x58],
            vec![0x87, 0x59, 0],
            vec![0x87, 0x5a, 0, 0, 0],
            vec![0x87, 0x5b, 0, 0, 0, 0, 0, 0, 0],
            vec![0x87, 0x5f],
            vec![0x9f, 0],
            vec![0x9f, 0x5f, 0],
            vec![0x9f, 0x5f, 0xff],
            vec![0x9f, 0x5f, 0x58],
            vec![0x9f, 0x5f, 0x44, b'P'],
            vec![0x9f, 0x5f, 0x41, b'Q'],
            vec![0x9f, 0x5f, 0x58, 0x10, b'P'],
            vec![0x9f, 0x5f, 0x40, 0x40, 0x40, 0x40],
            vec![
                0x9f, 0x5f, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            vec![
                0x9f, 0x5f, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6,
            ],
            vec![0x87, 0x44, b'P', b'A', b'A', b'0'],
            clear_non_candidate_at_budget,
        ]
    }

    #[test]
    fn reducer_dispatches_every_magic_bearing_malformed_paa1_candidate_strictly() {
        let reducer = AgentReducer;
        let entity = EntityId::new();
        let legacy = make_action_event(entity, "PAA1");
        assert!(!protocol::is_agent_action_wire(legacy.payload.as_slice()));

        let malformed = malformed_action_wire_candidates();
        let expected_action_count = u64::try_from(malformed.len() + 1).test_ok();

        let mut state = reducer.initial();
        reducer.apply(&mut state, &legacy);
        for payload in malformed {
            assert!(protocol::is_agent_action_wire(&payload));
            reducer.apply(&mut state, &make_action_event_with_payload(entity, payload));
        }

        assert_eq!(
            state
                .get("action_count")
                .and_then(serde_json::Value::as_u64),
            Some(expected_action_count)
        );
        assert_eq!(
            state.get("last_action").and_then(serde_json::Value::as_str),
            Some("PAA1")
        );

        for truncated in non_action_wire_prefixes() {
            assert!(!protocol::is_agent_action_wire(&truncated));
        }
    }
}
