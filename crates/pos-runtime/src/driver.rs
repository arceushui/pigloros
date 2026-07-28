//! Driver/Stepper interface.
//!
//! A `Driver` is a plugin component that, given the current state of a timeline,
//! produces the next batch of events. This is the heartbeat of the simulation loop.
//!
//! # Modes
//! - `Live` — the driver produces new events (nondeterministic sources go through the `Recorder`)
//! - `Replay` — the driver reads events from the log (bit-exact)

use pos_core::{event::EventDraft, ids::TimelineId, store::EventStore};

use crate::error::RuntimeError;

/// The output of a single driver step.
#[derive(Debug, Default)]
pub struct StepOutput {
    /// Drafts to be appended to the timeline.
    pub drafts: Vec<EventDraft>,
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
    /// Called once per tick. Returns [`StepOutput::empty()`] to indicate
    /// the driver is idle this tick.
    ///
    /// # Errors
    /// Returns [`RuntimeError`] on step failure.
    fn step(
        &mut self,
        store: &dyn EventStore,
        timeline: TimelineId,
    ) -> Result<StepOutput, RuntimeError>;

    /// Human-readable name for this driver (used in logs/diagnostics).
    fn name(&self) -> &'static str;

    /// Minimum interval between ticks (default 100ms = 10 Hz).
    fn tick_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(100)
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
        fn step(&mut self, _: &dyn EventStore, _: TimelineId) -> Result<StepOutput, RuntimeError> {
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
        let out = driver.step(store.as_ref(), tl.id()).unwrap();
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
        driver.step(store.as_ref(), tl.id()).unwrap();
        driver.step(store.as_ref(), tl.id()).unwrap();
        let out = driver.step(store.as_ref(), tl.id()).unwrap();
        // tick 3 — payload contains 3u32 as le bytes
        assert_eq!(out.drafts[0].payload.as_slice(), &3u32.to_le_bytes());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn idle_driver_returns_empty() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut driver = IdleDriver;
        let out = driver.step(store.as_ref(), tl.id()).unwrap();
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
