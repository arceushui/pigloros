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
    event::{CanonicalBytes, Kind},
    ids::TimelineId,
    ids::{EntityId, PluginId},
    plugin::{Capability, Plugin},
};
use pos_runtime::{
    Driver, InstalledPluginFactoryV1, InstalledPluginProductV1, NoActionApproverV1,
    ObservationView, RuntimeError, StepOutput,
};
use serde::{Deserialize, Serialize};

mod reducer;

pub use reducer::RuleAgentReducer;

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

// Reviewed staged Reducer catalogue factory (ADR-113 §1): every protected
// candidate builds a fresh `RuleAgentReducer` here and keeps only the reducer.
impl InstalledPluginFactoryV1 for RuleAgentPlugin {
    type Configuration = ();
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(_configuration: &()) -> Vec<u8> {
        pos_runtime::EMPTY_CONFIGURATION_DETAILS_V1.to_vec()
    }

    fn build(_configuration: &()) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        InstalledPluginProductV1 {
            plugin: Self::new(),
            reducer: Some(Box::new(RuleAgentReducer)),
            approver: NoActionApproverV1,
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
    pub const fn new(entity: EntityId, actions: Vec<String>) -> Self {
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
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        if self.actions.is_empty() {
            return Err(RuntimeError::InvalidPayload {
                event_type: EVENT_TYPE_DECISION.to_owned(),
                reason: "rule-agent action catalogue is empty".to_owned(),
            });
        }
        let action = self.actions[self.tick as usize % self.actions.len()].clone();
        let payload = DecisionPayload {
            action,
            tick: self.tick,
        };

        let mut buf = Vec::new();
        // `Vec<u8>` is an infallible CBOR sink.
        drop(ciborium::into_writer(&payload, &mut buf));

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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected rule-agent fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing rule-agent fixture value"))
            })
        }
    }

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Event, SchemaVersion},
        ids::{EntityId, EventId},
        state::Reducer,
    };
    use pos_store::{open_store, StoreConfig};

    fn make_decision_event(entity: EntityId) -> Event {
        // Build a minimal valid decision payload
        let payload = DecisionPayload {
            action: "idle".to_owned(),
            tick: 0,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).test_ok();

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
            signature_identity: None,
            origin: None,
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
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let plugin = RuleAgentPlugin::new();
        let mut driver = RuleAgentDriver::new(entity, plugin.actions().to_vec());

        let expected = ["idle", "move", "interact", "observe"];
        for expected_action in &expected {
            let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
            assert_eq!(out.drafts.len(), 1);
            assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_DECISION);

            // Decode the payload and verify the action
            let payload: DecisionPayload =
                ciborium::from_reader(out.drafts[0].payload.as_slice()).test_ok();
            assert_eq!(&payload.action, expected_action);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_action_catalogue_fails_closed() {
        let mut driver = RuleAgentDriver::new(EntityId::new(), Vec::new());
        let result = driver.step(TimelineId::new(), ObservationView::empty());
        assert!(matches!(
            result,
            Err(RuntimeError::InvalidPayload { event_type, .. })
                if event_type == EVENT_TYPE_DECISION
        ));
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
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let plugin = RuleAgentPlugin::new();
        let mut driver = RuleAgentDriver::new(entity, plugin.actions().to_vec());

        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out.drafts.len(), 1);

        let payload: DecisionPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).test_ok();

        assert_eq!(payload.action, "idle");
        assert_eq!(payload.tick, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn staged_factory_builds_a_fresh_reducer_per_candidate() {
        use pos_runtime::{
            fold_detached_candidate_v1, HostProjectionProviderV1, InitialStateV1,
            ProtectedProjectionProviderV1, StagedReducerAdmissionErrorV1,
        };

        let mut provider = HostProjectionProviderV1::default();
        assert_eq!(
            RuleAgentPlugin::configuration_details(&()),
            pos_runtime::EMPTY_CONFIGURATION_DETAILS_V1
        );
        assert_eq!(
            provider.admit::<RuleAgentPlugin>(std::sync::Arc::new(())),
            Err(StagedReducerAdmissionErrorV1::ConformanceEvidenceMissing)
        );
        let consumer = provider
            .admit_fixture::<RuleAgentPlugin>(std::sync::Arc::new(()))
            .test_ok();
        let source =
            pos_core::staged_install::ProjectionSourceV1::bound(pos_core::TimelineId::new(), None);
        let open = || provider.open_candidate(&[consumer], InitialStateV1::Empty, source);
        let mut folded = open().test_ok();
        let fresh = open().test_ok();
        let entity = EntityId::new();
        let event = make_decision_event(entity);
        fold_detached_candidate_v1(&mut folded, std::slice::from_ref(&event));

        let mut expected = RuleAgentReducer.initial();
        RuleAgentReducer.apply(&mut expected, &event);
        assert_eq!(
            folded.state_for(consumer.plugin_id(), &entity),
            Some(&expected)
        );
        assert!(fresh.state_for(consumer.plugin_id(), &entity).is_none());
    }
}
