//! `TickScheduler` — cadence-aware step driver per `ADR-019` Decision 2.
//!
//! Wraps a [`PluginRegistry`] and delegates to `tick_cadenced()`,
//! skipping drivers whose `tick_interval()` has not yet elapsed.

use crate::{registry::PluginRegistry, RuntimeError};
use pos_core::{event::EventDraft, ids::TimelineId, store::EventStore};

pub struct TickScheduler {
    /// The plugin registry being driven.
    registry: PluginRegistry,
}

impl TickScheduler {
    #[must_use]
    pub fn new(registry: PluginRegistry) -> Self {
        Self { registry }
    }

    /// Step ready drivers, returning all drafts from eligible plugins.
    ///
    /// Only drivers whose `tick_interval()` has elapsed since their last
    /// tick will fire.
    ///
    /// `now_ns` is a nanosecond wall-clock timestamp (e.g. from [`WallTime`]).
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers.
    pub fn tick(
        &mut self,
        store: &dyn EventStore,
        timeline: TimelineId,
        now_ns: u128,
    ) -> Result<Vec<EventDraft>, RuntimeError> {
        self.registry.tick_cadenced(store, timeline, now_ns)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::driver::{Driver, StepOutput};
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
    };
    use pos_store::{open_store, StoreConfig};
    use std::time::Duration;

    struct SlowDriver {
        entity: EntityId,
        ticks: u32,
        interval: Duration,
    }

    impl SlowDriver {
        fn new(interval: Duration) -> Self {
            SlowDriver {
                entity: EntityId::new(),
                ticks: 0,
                interval,
            }
        }
    }

    impl Driver for SlowDriver {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn step(
            &mut self,
            _store: &dyn EventStore,
            _timeline: TimelineId,
            _observations: crate::driver::ObservationView,
        ) -> Result<StepOutput, RuntimeError> {
            self.ticks += 1;
            Ok(StepOutput::new(vec![EventDraft::new(
                self.entity,
                Kind::new("slow.tick"),
                CanonicalBytes::from_vec(vec![]),
            )]))
        }
        fn tick_interval(&self) -> Duration {
            self.interval
        }
    }

    struct FastDriver {
        entity: EntityId,
        ticks: u32,
    }

    impl FastDriver {
        fn new() -> Self {
            FastDriver {
                entity: EntityId::new(),
                ticks: 0,
            }
        }
    }

    impl Driver for FastDriver {
        fn name(&self) -> &'static str {
            "fast"
        }
        fn tick_interval(&self) -> Duration {
            Duration::ZERO
        }
        fn step(
            &mut self,
            _store: &dyn EventStore,
            _timeline: TimelineId,
            _observations: crate::driver::ObservationView,
        ) -> Result<StepOutput, RuntimeError> {
            self.ticks += 1;
            Ok(StepOutput::new(vec![EventDraft::new(
                self.entity,
                Kind::new("fast.tick"),
                CanonicalBytes::from_vec(vec![]),
            )]))
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn all_drivers_fire_on_first_tick() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut reg = PluginRegistry::new();
        reg.register_driver(Box::new(SlowDriver::new(Duration::from_secs(1))));
        reg.register_driver(Box::new(FastDriver::new()));
        let mut sched = TickScheduler::new(reg);
        let drafts = sched.tick(store.as_ref(), tl.id(), 0).unwrap();
        assert_eq!(drafts.len(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn slow_driver_skipped_when_interval_not_elapsed() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut reg = PluginRegistry::new();
        reg.register_driver(Box::new(SlowDriver::new(Duration::from_secs(10))));
        reg.register_driver(Box::new(FastDriver::new()));
        let mut sched = TickScheduler::new(reg);
        sched.tick(store.as_ref(), tl.id(), 0).unwrap();
        let drafts = sched.tick(store.as_ref(), tl.id(), 1).unwrap();
        assert_eq!(drafts.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn slow_driver_fires_after_interval_elapsed() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut reg = PluginRegistry::new();
        reg.register_driver(Box::new(SlowDriver::new(Duration::from_millis(100))));
        reg.register_driver(Box::new(FastDriver::new()));
        let mut sched = TickScheduler::new(reg);
        sched.tick(store.as_ref(), tl.id(), 0).unwrap();
        let d = sched.tick(store.as_ref(), tl.id(), 50_000_000).unwrap();
        assert_eq!(d.len(), 1);
        let d = sched.tick(store.as_ref(), tl.id(), 100_000_000).unwrap();
        assert_eq!(d.len(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_registry_returns_empty() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let reg = PluginRegistry::new();
        let mut sched = TickScheduler::new(reg);
        let drafts = sched.tick(store.as_ref(), tl.id(), 0).unwrap();
        assert!(drafts.is_empty());
    }
}
