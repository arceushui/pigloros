//! Driver/Stepper interface.
//!
//! A `Driver` is a plugin component that, given the current state of a timeline,
//! produces the next batch of events. This is the heartbeat of the simulation loop.
//!
//! # Modes
//! - `Live` — the driver produces new events (nondeterministic sources go through the `Recorder`)
//! - `Replay` — the driver reads events from the log (bit-exact)

use pos_core::{
    clock::Seq,
    event::EventDraft,
    ids::{EntityId, TimelineId},
    State,
};

use crate::error::RuntimeError;
use std::collections::{hash_map::Entry, HashSet};

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

/// Immutable projection state captured at a tick boundary.
///
/// The scheduler creates one snapshot before it steps any driver. Its views own
/// cloned state, so every driver observes the same committed projection state
/// even if later tick work changes the live registry.
#[derive(Default)]
pub(crate) struct ObservationSnapshot {
    anchor: Option<SnapshotAnchor>,
    states: std::collections::HashMap<ProjectionKey, State>,
}

/// Identifies the immutable Timeline prefix observed by every Driver in one
/// host-owned tick boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotAnchor {
    timeline_id: TimelineId,
    observed_through: Seq,
}

impl SnapshotAnchor {
    #[must_use]
    pub const fn new(timeline_id: TimelineId, observed_through: Seq) -> Self {
        Self {
            timeline_id,
            observed_through,
        }
    }

    #[must_use]
    pub const fn timeline_id(self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn observed_through(self) -> Seq {
        self.observed_through
    }
}

impl ObservationSnapshot {
    #[must_use]
    pub(crate) fn from_subscriptions<'a>(
        subscriptions: impl IntoIterator<Item = &'a ProjectionKey>,
        state_for: impl Fn(&ProjectionKey) -> Option<State>,
    ) -> Self {
        Self::capture(None, subscriptions, state_for)
    }

    fn capture<'a>(
        anchor: Option<SnapshotAnchor>,
        subscriptions: impl IntoIterator<Item = &'a ProjectionKey>,
        state_for: impl Fn(&ProjectionKey) -> Option<State>,
    ) -> Self {
        let mut states = std::collections::HashMap::new();
        for key in subscriptions {
            if let Entry::Vacant(entry) = states.entry(key.clone()) {
                if let Some(state) = state_for(key) {
                    entry.insert(state);
                }
            }
        }
        Self { anchor, states }
    }

    #[must_use]
    pub(crate) fn view_for<'a>(&'a self, subscriptions: &[ProjectionKey]) -> ObservationView<'a> {
        let mut unique = 0usize;
        let mut seen = HashSet::with_capacity(subscriptions.len());
        for key in subscriptions {
            if seen.insert(key.clone()) {
                unique += 1;
            }
        }
        ObservationView {
            snapshot: Some(self),
            len: unique,
        }
    }
}

/// Read-only projection states materialized for one driver tick.
///
/// This view contains the distinct keys declared by a driver's subscriptions.
/// Repeated subscription keys are coalesced because lookup is keyed by
/// [`ProjectionKey`]. Missing projection state is represented by `None`, allowing
/// a driver to distinguish a subscribed-but-unseen entity from an undeclared
/// dependency.
pub struct ObservationView<'a> {
    snapshot: Option<&'a ObservationSnapshot>,
    len: usize,
}

impl ObservationView<'_> {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            snapshot: None,
            len: 0,
        }
    }

    #[must_use]
    pub fn state_for(&self, key: &ProjectionKey) -> Option<&State> {
        self.snapshot.and_then(|snapshot| snapshot.states.get(key))
    }

    #[must_use]
    pub fn anchor(&self) -> Option<SnapshotAnchor> {
        self.snapshot.and_then(|snapshot| snapshot.anchor)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
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
/// Drivers are called by the runtime's step loop. They receive only the
/// Timeline id and the scoped projection observations they declared; raw
/// `EventStore` access is deliberately unavailable.
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

    /// Whether this Driver requires a host-owned immutable-prefix anchor.
    fn requires_snapshot_anchor(&self) -> bool {
        false
    }

    /// Commit state staged by the preceding successful anchored step.
    fn commit_step(&mut self) {}

    /// Discard state staged by the preceding anchored step.
    fn abort_step(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::Seq,
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
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
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
        driver.step(tl.id(), ObservationView::empty()).unwrap();
        driver.step(tl.id(), ObservationView::empty()).unwrap();
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
        // tick 3 — payload contains 3u32 as le bytes
        assert_eq!(out.drafts[0].payload.as_slice(), &3u32.to_le_bytes());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn idle_driver_returns_empty() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut driver = IdleDriver;
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
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
    fn empty_snapshot_views_are_empty() {
        let snapshot = ObservationSnapshot::default();
        assert!(snapshot.view_for(&[]).is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_anchor_is_shared_and_legacy_driver_hooks_are_noops() {
        let anchor = SnapshotAnchor::new(TimelineId::new(), Seq::from_u64(7));
        let snapshot = ObservationSnapshot {
            anchor: Some(anchor),
            states: std::collections::HashMap::new(),
        };

        assert_eq!(snapshot.view_for(&[]).anchor(), Some(anchor));
        assert_eq!(
            anchor.timeline_id(),
            snapshot.view_for(&[]).anchor().unwrap().timeline_id()
        );
        assert_eq!(anchor.observed_through(), Seq::from_u64(7));
        assert_eq!(ObservationView::empty().anchor(), None);

        let mut legacy = IdleDriver;
        assert!(!legacy.requires_snapshot_anchor());
        legacy.commit_step();
        legacy.abort_step();
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
        let snapshot = ObservationSnapshot::from_subscriptions(&subscriptions, |key| {
            (key == &seen).then(|| state.clone())
        });
        let view = snapshot.view_for(&subscriptions);
        assert_eq!(view.len(), 2);
        assert!(!view.is_empty());
        assert_eq!(view.state_for(&seen), Some(&state));
        assert_eq!(view.state_for(&absent), None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn observation_view_state_for_none_when_empty() {
        let view = ObservationView::empty();
        let unknown = ProjectionKey::new(EntityId::new());

        assert!(view.state_for(&unknown).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn observation_view_is_empty_uses_len_for_non_empty_view() {
        let seen = ProjectionKey::new(EntityId::new());
        let snapshot = ObservationSnapshot::from_subscriptions(std::slice::from_ref(&seen), |_| {
            Some(State::new())
        });
        let view = snapshot.view_for(std::slice::from_ref(&seen));

        assert_eq!(view.len(), 1);
        assert!(!view.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn observation_view_coalesces_duplicate_subscription_keys() {
        let key = ProjectionKey::new(EntityId::new());
        let mut state = State::new();
        state.set("ticks", serde_json::json!(3));
        let subscriptions = [key.clone(), key.clone()];
        let snapshot =
            ObservationSnapshot::from_subscriptions(&subscriptions, |_| Some(state.clone()));
        let view = snapshot.view_for(&subscriptions);

        assert_eq!(view.len(), 1);
        assert_eq!(view.state_for(&key), Some(&state));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn observation_snapshot_keeps_tick_state_immutable() {
        let key = ProjectionKey::new(EntityId::new());
        let subscriptions = [key.clone()];
        let mut live_state = State::new();
        live_state.set("ticks", serde_json::json!(3));
        let snapshot =
            ObservationSnapshot::from_subscriptions(&subscriptions, |_| Some(live_state.clone()));
        live_state.set("ticks", serde_json::json!(4));

        let first_driver_view = snapshot.view_for(&subscriptions);
        let second_driver_view = snapshot.view_for(&subscriptions);
        let expected = Some(&serde_json::json!(3));
        assert_eq!(
            first_driver_view
                .state_for(&key)
                .and_then(|state| state.get("ticks")),
            expected
        );
        assert_eq!(
            second_driver_view
                .state_for(&key)
                .and_then(|state| state.get("ticks")),
            expected
        );
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
