#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-world` — spatial + embodiment plugin (rapier-free stub for Wave 5).
//!
//! Owns event types `"world.observation"`, `"world.action"` and entity kind `"world-body"`.
//! For Wave 5 we build the interface and a simple 2D position model (no rapier dependency —
//! rapier is deferred to Wave 6 when we need 3D physics).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    store::EventStore,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};

/// The entity kind string for world bodies.
pub const ENTITY_KIND: &str = "world-body";

/// The event type for world observations.
pub const EVENT_TYPE_OBSERVATION: &str = "world.observation";

/// The event type for world actions.
pub const EVENT_TYPE_ACTION: &str = "world.action";

// ---------------------------------------------------------------------------
// World backend trait (physics seam)
// ---------------------------------------------------------------------------

/// A swappable physics backend.
///
/// For Wave 5 we provide a simple kinematic backend. Wave 6 will add rapier-based 3D physics.
pub trait WorldBackend: Send + Sync {
    /// Human-readable name for this backend.
    fn name(&self) -> &'static str;

    /// Simulate one step and return observations for all bodies.
    fn step(&mut self, bodies: &[Body]) -> Vec<WorldObservation>;
}

/// A body in the world.
#[derive(Debug, Clone, PartialEq)]
pub struct Body {
    pub entity_id: EntityId,
    pub x: f64,
    pub y: f64,
    pub vx: f64,
    pub vy: f64,
}

/// An observation of a body's position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorldObservation {
    pub entity_id: EntityId,
    pub x: f64,
    pub y: f64,
}

// ---------------------------------------------------------------------------
// Built-in backend: SimpleKinematicBackend
// ---------------------------------------------------------------------------

/// Simple Euler integration: x += vx, y += vy per step (no physics).
#[derive(Default)]
pub struct SimpleKinematicBackend;

impl SimpleKinematicBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl WorldBackend for SimpleKinematicBackend {
    fn name(&self) -> &'static str {
        "simple-kinematic"
    }

    fn step(&mut self, bodies: &[Body]) -> Vec<WorldObservation> {
        bodies
            .iter()
            .map(|body| WorldObservation {
                entity_id: body.entity_id,
                x: body.x + body.vx,
                y: body.y + body.vy,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorldObservationPayload {
    entity_id: String,
    x: f64,
    y: f64,
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// World simulation plugin.
pub struct WorldPlugin {
    id: PluginId,
}

impl Default for WorldPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl WorldPlugin {
    /// Create a new world plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for WorldPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "world"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new(EVENT_TYPE_OBSERVATION),
                Kind::new(EVENT_TYPE_ACTION),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Produces one `world.observation` event per body per step.
pub struct WorldDriver {
    entities: Vec<Body>,
    backend: Box<dyn WorldBackend>,
    tick: u64,
}

impl WorldDriver {
    /// Create a new world driver with the given backend.
    #[must_use]
    pub fn new(entities: Vec<Body>, backend: Box<dyn WorldBackend>) -> Self {
        Self {
            entities,
            backend,
            tick: 0,
        }
    }
}

impl Driver for WorldDriver {
    fn name(&self) -> &'static str {
        "world-driver"
    }

    fn step(
        &mut self,
        _store: &dyn EventStore,
        _timeline: TimelineId,
        _observations: ObservationView,
    ) -> Result<StepOutput, RuntimeError> {
        let observations = self.backend.step(&self.entities);

        // Update entities with new positions
        for obs in &observations {
            if let Some(body) = self
                .entities
                .iter_mut()
                .find(|b| b.entity_id == obs.entity_id)
            {
                body.x = obs.x;
                body.y = obs.y;
            }
        }

        // Create event drafts for each observation
        let mut drafts = Vec::new();
        for obs in &observations {
            let payload = WorldObservationPayload {
                entity_id: obs.entity_id.to_string(),
                x: obs.x,
                y: obs.y,
            };

            let mut buf = Vec::new();
            // Writing to Vec<u8> is infallible with ciborium.
            ciborium::into_writer(&payload, &mut buf)
                .expect("ciborium write to Vec<u8> is infallible");

            let draft = pos_core::event::EventDraft::new(
                obs.entity_id,
                Kind::new(EVENT_TYPE_OBSERVATION),
                CanonicalBytes::from_vec(buf),
            );

            drafts.push(draft);
        }

        self.tick = self.tick.wrapping_add(1);
        Ok(StepOutput::new(drafts))
    }
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/// Tracks `observation_count` and `body_count` in State.
pub struct WorldReducer;

impl Reducer for WorldReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("observation_count", serde_json::Value::Number(0.into()));
        s.set("body_count", serde_json::Value::Number(0.into()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_OBSERVATION {
            let observation_count = state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "observation_count",
                serde_json::Value::Number((observation_count + 1).into()),
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

    fn make_observation_event(entity: EntityId) -> Event {
        let payload = WorldObservationPayload {
            entity_id: entity.to_string(),
            x: 1.0,
            y: 2.0,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_OBSERVATION),
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
        let p1 = WorldPlugin::new();
        let p2 = WorldPlugin::default();
        assert_eq!(p1.name(), "world");
        assert_eq!(p2.name(), "world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_name_is_world() {
        let plugin = WorldPlugin::new();
        assert_eq!(plugin.name(), "world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_returned() {
        let plugin = WorldPlugin::new();
        let _id = plugin.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_is_correct() {
        let plugin = WorldPlugin::new();
        let cap = plugin.capability();

        assert_eq!(cap.owned_event_types.len(), 2);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_OBSERVATION);
        assert_eq!(cap.owned_event_types[1].as_str(), EVENT_TYPE_ACTION);
        assert_eq!(cap.owned_entity_kinds.len(), 1);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_new() {
        let backend = SimpleKinematicBackend::new();
        assert_eq!(backend.name(), "simple-kinematic");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_name_is_correct() {
        let backend = SimpleKinematicBackend::new();
        assert_eq!(backend.name(), "simple-kinematic");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_step_moves_bodies() {
        let mut backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 2.0,
        }];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].entity_id, entity);
        assert!((observations[0].x - 1.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_step_multiple_bodies() {
        let mut backend = SimpleKinematicBackend::new();
        let entity1 = EntityId::new();
        let entity2 = EntityId::new();
        let bodies = vec![
            Body {
                entity_id: entity1,
                x: 0.0,
                y: 0.0,
                vx: 1.0,
                vy: 0.0,
            },
            Body {
                entity_id: entity2,
                x: 10.0,
                y: 10.0,
                vx: -1.0,
                vy: -1.0,
            },
        ];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 2);
        assert!((observations[0].x - 1.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 0.0).abs() < f64::EPSILON);
        assert!((observations[1].x - 9.0).abs() < f64::EPSILON);
        assert!((observations[1].y - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_name_is_correct() {
        let backend = Box::new(SimpleKinematicBackend::new());
        let driver = WorldDriver::new(vec![], backend);
        assert_eq!(driver.name(), "world-driver");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_correct_event_type() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend);

        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_OBSERVATION);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_decodable_payload() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 5.0,
            y: 10.0,
            vx: 2.0,
            vy: 3.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend);

        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        let payload: WorldObservationPayload =
            ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();

        assert!((payload.x - 7.0).abs() < f64::EPSILON);
        assert!((payload.y - 13.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_updates_body_positions() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend);

        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 1.0).abs() < f64::EPSILON);

        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert!((driver.entities[0].x - 2.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
    }

    struct UnknownEntityBackend;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl WorldBackend for UnknownEntityBackend {
        fn name(&self) -> &'static str {
            "unknown-entity"
        }

        fn step(&mut self, _bodies: &[Body]) -> Vec<WorldObservation> {
            vec![WorldObservation {
                entity_id: EntityId::new(),
                x: 9.0,
                y: 9.0,
            }]
        }
    }

    struct MixedEntityBackend {
        extra: EntityId,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl WorldBackend for MixedEntityBackend {
        fn name(&self) -> &'static str {
            "mixed-entity"
        }

        fn step(&mut self, bodies: &[Body]) -> Vec<WorldObservation> {
            let mut out: Vec<WorldObservation> = bodies
                .iter()
                .map(|body| WorldObservation {
                    entity_id: body.entity_id,
                    x: body.x + body.vx,
                    y: body.y + body.vy,
                })
                .collect();
            out.push(WorldObservation {
                entity_id: self.extra,
                x: 0.0,
                y: 0.0,
            });
            out
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_ignores_observations_for_unknown_entities() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let known = EntityId::new();
        let body = Body {
            entity_id: known,
            x: 1.0,
            y: 2.0,
            vx: 0.0,
            vy: 0.0,
        };
        let mut driver = WorldDriver::new(vec![body], Box::new(UnknownEntityBackend));
        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert_eq!(out.drafts.len(), 1);
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_updates_known_and_skips_unknown_in_same_step() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let known = EntityId::new();
        let unknown = EntityId::new();
        let body = Body {
            entity_id: known,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 2.0,
        };
        let mut driver =
            WorldDriver::new(vec![body], Box::new(MixedEntityBackend { extra: unknown }));
        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state_has_correct_fields() {
        let reducer = WorldReducer;
        let state = reducer.initial();
        assert!(state.get("observation_count").is_some());
        assert!(state.get("body_count").is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_observation_count() {
        let reducer = WorldReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for _ in 0..5 {
            let event = make_observation_event(entity);
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = WorldReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let other = make_other_event(entity);
        reducer.apply(&mut state, &other);

        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn body_partial_eq() {
        let entity = EntityId::new();
        let b1 = Body {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            vx: 0.0,
            vy: 0.0,
        };
        let b2 = Body {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            vx: 0.0,
            vy: 0.0,
        };
        let b3 = Body {
            entity_id: entity,
            x: 3.0,
            y: 4.0,
            vx: 0.0,
            vy: 0.0,
        };
        assert_eq!(b1, b2);
        assert_ne!(b1, b3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_partial_eq() {
        let entity = EntityId::new();
        let o1 = WorldObservation {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
        };
        let o2 = WorldObservation {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
        };
        let o3 = WorldObservation {
            entity_id: entity,
            x: 3.0,
            y: 4.0,
        };
        assert_eq!(o1, o2);
        assert_ne!(o1, o3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_empty_bodies_produces_no_events() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![], backend);

        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert_eq!(out.drafts.len(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_step_with_zero_velocity() {
        let mut backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 5.0,
            y: 7.0,
            vx: 0.0,
            vy: 0.0,
        }];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 1);
        assert!((observations[0].x - 5.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_step_with_negative_velocity() {
        let mut backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 10.0,
            y: 10.0,
            vx: -2.0,
            vy: -3.0,
        }];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 1);
        assert!((observations[0].x - 8.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_tick_increments() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend);

        assert_eq!(driver.tick, 0);
        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert_eq!(driver.tick, 1);
        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert_eq!(driver.tick, 2);
    }
}
