//! Driver/Stepper interface.
//!
//! A `Driver` is a plugin component that, given the current state of a timeline,
//! produces the next batch of events. This is the heartbeat of the simulation loop.
//!
//! # Modes
//! - `Live` — the driver produces new events (nondeterministic sources go through the `Recorder`)
//! - `Replay` — the driver reads events from the log (bit-exact)

use pos_core::{
    event::EventDraft,
    ids::{EntityId, TimelineId},
    store::EventStore,
    State,
};

use crate::error::RuntimeError;

/// The output of a single driver step.
#[derive(Debug, Default)]
pub struct StepOutput {
    /// Drafts to be appended to the timeline.
    pub drafts: Vec<EventDraft>,
}

/// Identifies a Timeline entity whose projection state is observed by a driver on a tick.
///
/// A driver declares these keys up front so the scheduler only reads the
/// projections it will observe on that tick.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProjectionKey(EntityId);

impl ProjectionKey {
    #[must_use]
    pub fn new(entity: EntityId) -> Self {
        Self(entity)
    }

    #[must_use]
    pub fn entity_id(&self) -> &EntityId {
        &self.0
    }
}

/// Read-only projection states materialized for one driver tick.
///
/// This view contains exactly the keys declared by a driver's subscriptions.
/// Missing projection state is represented by `None`, allowing a driver to
/// distinguish a subscribed-but-unseen entity from an undeclared dependency.
pub struct ObservationView<'a> {
    states: std::collections::HashMap<ProjectionKey, Option<&'a State>>,
}

impl<'a> ObservationView<'a> {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            states: std::collections::HashMap::new(),
        }
    }

    #[must_use]
    pub(crate) fn from_subscriptions(
        subscriptions: &[ProjectionKey],
        state_for: impl Fn(&ProjectionKey) -> Option<&'a State>,
    ) -> Self {
        let mut states = std::collections::HashMap::with_capacity(subscriptions.len());
        for key in subscriptions {
            states.insert(key.clone(), state_for(key));
        }
        Self { states }
    }

    #[must_use]
    pub fn state_for(&self, key: &ProjectionKey) -> Option<&'a State> {
        self.states.get(key).copied().flatten()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

impl StepOutput {
    #[must_use]
    pub fn new(drafts: Vec<EventDraft>) -> Self {
        Self { drafts }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self { drafts: Vec::new() }
    }
}

/// A plugin component that produces events on each simulation tick.
///
/// Drivers are called by the runtime's step loop. They receive read-only access
/// to the store (for reading current state via replay) and the timeline id.
///
/// Nondeterministic outputs (LLM calls, sensor reads, RNG) must go through the
/// [`crate::recorder::Recorder`] so replay is bit-exact.
pub trait Driver: Send + Sync {
    /// Produce the next batch of events for this driver's plugin.
    ///
    /// Called once per tick. `observations` contains exactly the projection
    /// states declared in [`Self::subscriptions()`].
    ///
    /// # Errors
    /// Returns [`RuntimeError`] on step failure.
    fn step(
        &mut self,
        store: &dyn EventStore,
        timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError>;

    /// Human-readable name for this driver (used in logs/diagnostics).
    fn name(&self) -> &'static str;

    /// Minimum interval between ticks (default 100ms = 10 Hz).
    fn tick_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(100)
    }

    /// Projection states this driver observes (default empty).
    fn subscriptions(&self) -> &[ProjectionKey] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
    };
    use pos_store::{open_store, StoreConfig};

    struct TickDriver {
        entity: EntityId,
        ticks: u32,
    }

    impl Driver for TickDriver {
        fn name(&self) -> &'static str {
            "tick"
        }
        fn step(
            &mut self,
            _store: &dyn EventStore,
            _timeline: TimelineId,
            _observations: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            self.ticks += 1;
            let draft = EventDraft::new(
                self.entity,
                Kind::new("tick.event"),
                CanonicalBytes::from_vec(self.ticks.to_le_bytes().to_vec()),
            );
            Ok(StepOutput::new(vec![draft]))
        }
    }

    struct IdleDriver;
    impl Driver for IdleDriver {
        fn name(&self) -> &'static str {
            "idle"
        }
        fn step(
            &mut self,
            _: &dyn EventStore,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_produces_drafts() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let mut driver = TickDriver { entity, ticks: 0 };
        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), "tick.event");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_tick_increments() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let mut driver = TickDriver { entity, ticks: 0 };
        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        // tick 3 — payload contains 3u32 as le bytes
        assert_eq!(out.drafts[0].payload.as_slice(), &3u32.to_le_bytes());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn idle_driver_returns_empty() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut driver = IdleDriver;
        let out = driver
            .step(store.as_ref(), tl.id(), ObservationView::empty())
            .unwrap();
        assert!(out.drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_output_new_and_empty() {
        let out = StepOutput::new(vec![]);
        assert!(out.drafts.is_empty());
        let out2 = StepOutput::empty();
        assert!(out2.drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_tick_interval_is_100ms() {
        let d = TickDriver {
            entity: EntityId::new(),
            ticks: 0,
        };
        assert_eq!(d.tick_interval(), std::time::Duration::from_millis(100));
        let idle = IdleDriver;
        assert_eq!(idle.tick_interval(), std::time::Duration::from_millis(100));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_subscriptions_are_empty() {
        let d = TickDriver {
            entity: EntityId::new(),
            ticks: 0,
        };
        assert!(d.subscriptions().is_empty());
        assert!(IdleDriver.subscriptions().is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn observation_view_returns_only_declared_state() {
        assert!(ObservationView::empty().is_empty());
        let seen = ProjectionKey::new(EntityId::new());
        let absent = ProjectionKey::new(EntityId::new());
        let mut state = State::new();
        state.set("ticks", serde_json::json!(3));
        let subscriptions = [seen.clone(), absent.clone()];
        let view = ObservationView::from_subscriptions(&subscriptions, |key| {
            (key == &seen).then_some(&state)
        });
        assert_eq!(view.len(), 2);
        assert!(!view.is_empty());
        assert_eq!(view.state_for(&seen), Some(&state));
        assert_eq!(view.state_for(&absent), None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_name() {
        let d = TickDriver {
            entity: EntityId::new(),
            ticks: 0,
        };
        assert_eq!(d.name(), "tick");
        let idle = IdleDriver;
        assert_eq!(idle.name(), "idle");
    }
}
