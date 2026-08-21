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
    ActionApprover, ActionRejected, ProposedAction, WorldCoordinateV1, WorldTransformError,
    MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

/// A world body represented by a core-owned named ENU coordinate.
#[derive(Clone, Copy, PartialEq)]
pub struct WorldCoordinateBody {
    entity_id: EntityId,
    position: WorldCoordinateV1,
    east_velocity_metres_per_step: f64,
    north_velocity_metres_per_step: f64,
    up_velocity_metres_per_step: f64,
}

impl WorldCoordinateBody {
    /// Construct a body with one-step East/North/Up velocity components.
    #[must_use]
    pub const fn new(
        entity_id: EntityId,
        position: WorldCoordinateV1,
        east_velocity_metres_per_step: f64,
        north_velocity_metres_per_step: f64,
        up_velocity_metres_per_step: f64,
    ) -> Self {
        Self {
            entity_id,
            position,
            east_velocity_metres_per_step,
            north_velocity_metres_per_step,
            up_velocity_metres_per_step,
        }
    }

    /// Return the entity identifier.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.entity_id
    }

    /// Return the current named world coordinate.
    #[must_use]
    pub const fn position(self) -> WorldCoordinateV1 {
        self.position
    }
}

/// A world-body observation represented by a named ENU coordinate.
#[derive(Clone, Copy, PartialEq)]
pub struct WorldCoordinateObservation {
    entity_id: EntityId,
    position: WorldCoordinateV1,
}

impl WorldCoordinateObservation {
    /// Return the observed entity identifier.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.entity_id
    }

    /// Return the observed named world coordinate.
    #[must_use]
    pub const fn position(self) -> WorldCoordinateV1 {
        self.position
    }
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

    /// Advance named ENU bodies by one step.
    ///
    /// # Errors
    ///
    /// Returns [`WorldTransformError::NonFiniteCoordinate`] when a velocity
    /// component or translated coordinate is not finite.
    pub fn step_coordinates(
        &mut self,
        bodies: &[WorldCoordinateBody],
    ) -> Result<Vec<WorldCoordinateObservation>, WorldTransformError> {
        bodies
            .iter()
            .map(|body| {
                let position = body.position.translated_by(
                    body.east_velocity_metres_per_step,
                    body.north_velocity_metres_per_step,
                    body.up_velocity_metres_per_step,
                )?;
                Ok(WorldCoordinateObservation {
                    entity_id: body.entity_id,
                    position,
                })
            })
            .collect()
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

/// A structured world action payload (ADR-047 / ADR-057).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorldAction {
    pub actor_entity_id: EntityId,
    pub body_entity_id: EntityId,
    pub action_kind: String,
    pub params: Vec<u8>,
    pub action_scope: u8,
    pub catalogue_version: u32,
    pub tick: u64,
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// World simulation plugin.
#[derive(Clone)]
pub struct WorldPlugin {
    id: PluginId,
    allowed_action_kinds: Vec<String>,
    catalogue_version: u32,
    known_bodies: HashSet<EntityId>,
}

impl Default for WorldPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl WorldPlugin {
    /// Create a new world plugin with default actuator allow-list (`["impulse", "target_velocity"]`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
            allowed_action_kinds: vec!["impulse".to_owned(), "target_velocity".to_owned()],
            catalogue_version: 1,
            known_bodies: HashSet::new(),
        }
    }

    /// Pinned catalogue version.
    #[must_use]
    pub const fn catalogue_version(&self) -> u32 {
        self.catalogue_version
    }

    /// Configure allowed action kinds.
    #[must_use]
    pub fn with_allowed_actions(mut self, actions: impl IntoIterator<Item = String>) -> Self {
        self.allowed_action_kinds = actions.into_iter().collect();
        self
    }

    /// Configure known body entities.
    #[must_use]
    pub fn with_bodies(mut self, bodies: impl IntoIterator<Item = EntityId>) -> Self {
        self.known_bodies = bodies.into_iter().collect();
        self
    }

    /// Configure pinned catalogue version.
    #[must_use]
    pub const fn with_catalogue_version(mut self, version: u32) -> Self {
        self.catalogue_version = version;
        self
    }

    /// Add a known body entity ID.
    pub fn add_body(&mut self, body: EntityId) {
        self.known_bodies.insert(body);
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

impl ActionApprover for WorldPlugin {
    fn approve(
        &self,
        proposal: &ProposedAction,
    ) -> Result<pos_core::event::EventDraft, ActionRejected> {
        if proposal.event_type.as_str() != EVENT_TYPE_ACTION {
            return Err(ActionRejected::UnknownEventType);
        }
        if proposal.capability.as_str() != "world.action.submit" {
            return Err(ActionRejected::CapabilityNotGranted);
        }
        if proposal.payload.len() > MAX_PROPOSED_ACTION_PAYLOAD_BYTES {
            return Err(ActionRejected::PayloadTooLarge {
                size: proposal.payload.len(),
                max: MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
            });
        }

        let action: WorldAction = match ciborium::from_reader(proposal.payload.as_slice()) {
            Ok(action) => action,
            Err(_) => {
                return Err(ActionRejected::DomainValidationFailed(
                    "malformed world.action payload".to_owned(),
                ));
            }
        };

        if action.actor_entity_id != proposal.actor_entity_id {
            return Err(ActionRejected::InvalidActorEntityId);
        }

        if action.action_scope != 0 {
            return Err(ActionRejected::DomainValidationFailed(format!(
                "invalid action scope: expected 0, got {}",
                action.action_scope
            )));
        }

        if action.catalogue_version != self.catalogue_version {
            return Err(ActionRejected::DomainValidationFailed(format!(
                "catalogue version mismatch: expected {}, got {}",
                self.catalogue_version, action.catalogue_version
            )));
        }

        if !self.allowed_action_kinds.contains(&action.action_kind) {
            return Err(ActionRejected::DomainValidationFailed(format!(
                "action kind '{}' not in allow-list",
                action.action_kind
            )));
        }

        if !self.known_bodies.contains(&action.body_entity_id) {
            return Err(ActionRejected::DomainValidationFailed(
                "unknown body entity ID".to_owned(),
            ));
        }

        Ok(pos_core::event::EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
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
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
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
    fn simple_kinematic_backend_steps_named_world_coordinates() {
        let capability = pos_core::WorldGeographicEvidenceCapabilityV1::for_trusted_core();
        let origin = pos_core::WorldOriginV1::new(
            &capability,
            [21; 16],
            [22; 16],
            1,
            pos_core::Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture origin is valid"),
            [23; 32],
            10_000.0,
        )
        .expect("fixture origin is valid");
        let transform = pos_core::WorldTransformV1::new(&capability, origin)
            .expect("fixture transform is valid");
        let position = transform
            .forward(
                &capability,
                pos_core::Wgs84PositionV1::new(35.001, -119.999, 120.0)
                    .expect("fixture position is valid"),
            )
            .expect("fixture position is in range");
        let body = WorldCoordinateBody::new(EntityId::new(), position, 1.5, -2.0, 0.25);
        assert!((body.position().east_metres() - position.east_metres()).abs() < f64::EPSILON);
        assert!((body.position().north_metres() - position.north_metres()).abs() < f64::EPSILON);
        assert!((body.position().up_metres() - position.up_metres()).abs() < f64::EPSILON);

        let mut backend = SimpleKinematicBackend::new();
        let observations = backend
            .step_coordinates(&[body])
            .expect("named coordinate step is finite");

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].entity_id(), body.entity_id());
        assert!(
            (observations[0].position().east_metres() - (position.east_metres() + 1.5)).abs()
                < f64::EPSILON
        );
        assert!(
            (observations[0].position().north_metres() - (position.north_metres() - 2.0)).abs()
                < f64::EPSILON
        );
        assert!(
            (observations[0].position().up_metres() - (position.up_metres() + 0.25)).abs()
                < f64::EPSILON
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_rejects_non_finite_coordinate_steps() {
        let capability = pos_core::WorldGeographicEvidenceCapabilityV1::for_trusted_core();
        let origin = pos_core::WorldOriginV1::new(
            &capability,
            [24; 16],
            [25; 16],
            1,
            pos_core::Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture is valid"),
            [26; 32],
            10_000.0,
        )
        .expect("fixture origin is valid");
        let transform = pos_core::WorldTransformV1::new(&capability, origin)
            .expect("fixture transform is valid");
        let position = transform
            .forward(
                &capability,
                pos_core::Wgs84PositionV1::new(35.001, -119.999, 120.0)
                    .expect("fixture position is valid"),
            )
            .expect("fixture position is in range");
        let body = WorldCoordinateBody::new(EntityId::new(), position, f64::INFINITY, 0.0, 0.0);
        let mut backend = SimpleKinematicBackend::new();

        assert!(matches!(
            backend.step_coordinates(&[body]),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
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

        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
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

        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
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

        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 1.0).abs() < f64::EPSILON);

        driver.step(tl.id(), ObservationView::empty()).unwrap();
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
        assert_eq!(UnknownEntityBackend.name(), "unknown-entity");
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
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
        assert_eq!(MixedEntityBackend { extra: unknown }.name(), "mixed-entity");
        driver.step(tl.id(), ObservationView::empty()).unwrap();
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

        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
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
        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(driver.tick, 1);
        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(driver.tick, 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_builders_and_accessors() {
        let body_id = EntityId::new();
        let plugin = WorldPlugin::new()
            .with_catalogue_version(2)
            .with_allowed_actions(vec!["custom_action".to_owned()])
            .with_bodies(vec![body_id]);

        assert_eq!(plugin.catalogue_version(), 2);
        assert_eq!(plugin.allowed_action_kinds, vec!["custom_action"]);
        assert!(plugin.known_bodies.contains(&body_id));

        let mut plugin2 = WorldPlugin::default();
        let body_id2 = EntityId::new();
        plugin2.add_body(body_id2);
        assert!(plugin2.known_bodies.contains(&body_id2));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_requires_complete_envelope() {
        let incomplete = serde_json::json!({
            "actor_entity_id": EntityId::new(),
            "body_entity_id": EntityId::new(),
            "action_kind": "impulse"
        });
        let result = serde_json::from_value::<WorldAction>(incomplete);
        assert!(result.is_err());
    }

    // ─── helpers ──────────────────────────────────────────────────────────────

    /// Serialise `action` to CBOR and wrap it in a [`ProposedAction`].
    fn cbor_proposal(action: &WorldAction, actor: EntityId) -> ProposedAction {
        let mut buf = Vec::new();
        ciborium::into_writer(action, &mut buf).unwrap();
        ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_vec(buf),
            Kind::new("world.action.submit"),
        )
    }

    /// Build a canonical `WorldAction` with sensible defaults.
    fn default_action(actor: EntityId, body: EntityId) -> WorldAction {
        WorldAction {
            actor_entity_id: actor,
            body_entity_id: body,
            action_kind: "impulse".to_owned(),
            params: vec![1, 2, 3],
            action_scope: 0,
            catalogue_version: 1,
            tick: 10,
        }
    }

    // ─── approver happy-path tests ────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_approver_happy_paths() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let plugin = WorldPlugin::new().with_bodies(vec![body]);
        let action = default_action(actor, body);

        // 1. Valid CBOR proposal
        let proposal = cbor_proposal(&action, actor);
        let draft = plugin
            .approve(&proposal)
            .expect("CBOR proposal should be approved");
        assert_eq!(draft.entity, actor);
        assert_eq!(draft.event_type.as_str(), EVENT_TYPE_ACTION);

        // 2. Unknown event type
        let wrong_type = ProposedAction::new(
            Kind::new("wrong.event"),
            actor,
            proposal.payload.clone(),
            Kind::new("world.action.submit"),
        );
        assert_eq!(
            plugin.approve(&wrong_type),
            Err(ActionRejected::UnknownEventType)
        );
    }

    // ─── approver early-rejection tests ──────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_approver_rejects_early_checks() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let plugin = WorldPlugin::new().with_bodies(vec![body]);
        let action = default_action(actor, body);
        let proposal = cbor_proposal(&action, actor);

        // 4. Capability not granted
        let wrong_cap = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            proposal.payload.clone(),
            Kind::new("wrong.capability"),
        );
        assert_eq!(
            plugin.approve(&wrong_cap),
            Err(ActionRejected::CapabilityNotGranted)
        );

        // 5. Payload too large (>4096)
        let large_payload = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_vec(vec![0u8; 5000]),
            Kind::new("world.action.submit"),
        );
        assert_eq!(
            plugin.approve(&large_payload),
            Err(ActionRejected::PayloadTooLarge {
                size: 5000,
                max: 4096
            })
        );

        // 6. Malformed payload
        let malformed = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_vec(vec![0xff, 0xff, 0xff]),
            Kind::new("world.action.submit"),
        );
        assert_eq!(
            plugin.approve(&malformed),
            Err(ActionRejected::DomainValidationFailed(
                "malformed world.action payload".to_owned()
            ))
        );

        // 7. Actor entity mismatch
        let other_actor = EntityId::new();
        let wrong_actor = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            other_actor,
            proposal.payload.clone(),
            Kind::new("world.action.submit"),
        );
        assert_eq!(
            plugin.approve(&wrong_actor),
            Err(ActionRejected::InvalidActorEntityId)
        );
    }

    // ─── approver domain-validation tests ────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_approver_rejects_domain_checks() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let plugin = WorldPlugin::new().with_bodies(vec![body]);

        // 8. Invalid action scope (!= 0)
        let scope_prop = cbor_proposal(
            &WorldAction {
                actor_entity_id: actor,
                body_entity_id: body,
                action_kind: "impulse".to_owned(),
                params: vec![],
                action_scope: 1,
                catalogue_version: 1,
                tick: 0,
            },
            actor,
        );
        assert_eq!(
            plugin.approve(&scope_prop),
            Err(ActionRejected::DomainValidationFailed(
                "invalid action scope: expected 0, got 1".to_owned()
            ))
        );

        // 9. Catalogue version mismatch
        let ver_prop = cbor_proposal(
            &WorldAction {
                actor_entity_id: actor,
                body_entity_id: body,
                action_kind: "impulse".to_owned(),
                params: vec![],
                action_scope: 0,
                catalogue_version: 99,
                tick: 0,
            },
            actor,
        );
        assert_eq!(
            plugin.approve(&ver_prop),
            Err(ActionRejected::DomainValidationFailed(
                "catalogue version mismatch: expected 1, got 99".to_owned()
            ))
        );

        // 10. Unknown action kind
        let kind_prop = cbor_proposal(
            &WorldAction {
                actor_entity_id: actor,
                body_entity_id: body,
                action_kind: "fly_to_moon".to_owned(),
                params: vec![],
                action_scope: 0,
                catalogue_version: 1,
                tick: 0,
            },
            actor,
        );
        assert_eq!(
            plugin.approve(&kind_prop),
            Err(ActionRejected::DomainValidationFailed(
                "action kind 'fly_to_moon' not in allow-list".to_owned()
            ))
        );

        // 11. Unknown body entity ID
        let unknown_body = EntityId::new();
        let unk_prop = cbor_proposal(
            &WorldAction {
                actor_entity_id: actor,
                body_entity_id: unknown_body,
                action_kind: "impulse".to_owned(),
                params: vec![],
                action_scope: 0,
                catalogue_version: 1,
                tick: 0,
            },
            actor,
        );
        assert_eq!(
            plugin.approve(&unk_prop),
            Err(ActionRejected::DomainValidationFailed(
                "unknown body entity ID".to_owned()
            ))
        );
    }
}
