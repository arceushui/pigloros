//! `TickScheduler` — cadence-aware step driver per `ADR-019` Decision 2.
//!
//! Wraps a [`PluginRegistry`] and delegates to `tick_cadenced()`,
//! skipping drivers whose `tick_interval()` has not yet elapsed.

use crate::{registry::PluginRegistry, RuntimeError};
use pos_core::{event::EventDraft, ids::TimelineId};

pub struct TickScheduler {
    /// The plugin registry being driven.
    registry: PluginRegistry,
}

impl TickScheduler {
    #[must_use]
    pub const fn new(registry: PluginRegistry) -> Self {
        Self { registry }
    }

    /// Step ready drivers, returning all drafts from eligible plugins.
    ///
    /// Only drivers whose `tick_interval()` has elapsed since their last
    /// tick will fire.
    ///
    /// `now_ns` is a nanosecond wall-clock timestamp (e.g. from [`pos_core::WallTime`]).
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers.
    pub fn tick(
        &mut self,
        timeline: TimelineId,
        now_ns: u128,
    ) -> Result<Vec<EventDraft>, RuntimeError> {
        self.registry.tick_cadenced(timeline, now_ns)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::driver::{Driver, StepOutput};
    use pos_core::{
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, PluginId},
        output_policy::{
            OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1, OutputPolicyInputV1,
            OutputPolicyV1,
        },
        ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1,
        PluginCpuReservationV1, WorkloadProfileV1,
    };
    use pos_store::{open_store, StoreConfig};
    use std::time::Duration;

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected scheduler fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing scheduler fixture value"))
            })
        }
    }

    fn register_output_driver(
        registry: &mut PluginRegistry,
        event_type: &str,
        driver: Box<dyn Driver>,
    ) {
        let plugin_id = PluginId::new();
        let budget = ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
            revision: 1,
            workload_profile: WorkloadProfileV1::Interactive,
            cut_budget_family: 0,
            max_event_bytes: 4_096,
            fidelity_budgets: [
                FidelityBudgetV1 {
                    level: 0,
                    max_events: 1_000,
                    max_bytes: 64 * 1024 * 1024,
                    max_cpu_us: 500_000,
                    shared_host_cpu_reservation_us: 0,
                },
                FidelityBudgetV1 {
                    level: 1,
                    max_events: 1_000,
                    max_bytes: 64 * 1024 * 1024,
                    max_cpu_us: 250_000,
                    shared_host_cpu_reservation_us: 0,
                },
                FidelityBudgetV1 {
                    level: 2,
                    max_events: 1_000,
                    max_bytes: 16 * 1024 * 1024,
                    max_cpu_us: 50_000,
                    shared_host_cpu_reservation_us: 0,
                },
            ],
            plugin_cpu_reservations: vec![PluginCpuReservationV1 {
                plugin_id,
                cpu_reservations_us: [10; 3],
            }],
            accounting_semantics: 0,
            execution_profile_hash: Hash::from_bytes([0x41; 32]),
            max_pass_wall_duration_us: 1_000,
        })
        .test_ok();
        let declaration = OutputDeclarationV1::new(
            event_type.to_owned(),
            OutputAuthorityV1::Authoritative,
            OutputFidelityV1::L0,
            4_096,
            None,
            None,
        )
        .test_ok();
        let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
            plugin_id,
            plugin_version: "test".to_owned(),
            implementation_hash: Hash::from_bytes([0x42; 32]),
            base_configuration_digest: Hash::from_bytes([0x43; 32]),
            executable_profile_hash: budget.digest(),
            retention_policy_hash: Hash::from_bytes([0x44; 32]),
            policy_revision: 1,
            output_declarations: vec![declaration],
        })
        .test_ok();
        registry
            .register_test_driver_with_output_policy(plugin_id, "test", policy, budget, driver)
            .test_ok();
    }

    struct SlowDriver {
        entity: EntityId,
        ticks: u32,
        interval: Duration,
    }

    impl SlowDriver {
        fn new(interval: Duration) -> Self {
            Self {
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
            _timeline: TimelineId,
            _observations: crate::driver::ObservationView<'_>,
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
            Self {
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
            _timeline: TimelineId,
            _observations: crate::driver::ObservationView<'_>,
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
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let mut reg = PluginRegistry::new();
        register_output_driver(
            &mut reg,
            "slow.tick",
            Box::new(SlowDriver::new(Duration::from_secs(1))),
        );
        register_output_driver(&mut reg, "fast.tick", Box::new(FastDriver::new()));
        let mut sched = TickScheduler::new(reg);
        let drafts = sched.tick(tl.id(), 0).test_ok();
        assert_eq!(drafts.len(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn slow_driver_skipped_when_interval_not_elapsed() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let mut reg = PluginRegistry::new();
        register_output_driver(
            &mut reg,
            "slow.tick",
            Box::new(SlowDriver::new(Duration::from_secs(10))),
        );
        register_output_driver(&mut reg, "fast.tick", Box::new(FastDriver::new()));
        let mut sched = TickScheduler::new(reg);
        sched.tick(tl.id(), 0).test_ok();
        let drafts = sched.tick(tl.id(), 1).test_ok();
        assert_eq!(drafts.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn slow_driver_fires_after_interval_elapsed() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let mut reg = PluginRegistry::new();
        register_output_driver(
            &mut reg,
            "slow.tick",
            Box::new(SlowDriver::new(Duration::from_millis(100))),
        );
        register_output_driver(&mut reg, "fast.tick", Box::new(FastDriver::new()));
        let mut sched = TickScheduler::new(reg);
        sched.tick(tl.id(), 0).test_ok();
        let d = sched.tick(tl.id(), 50_000_000).test_ok();
        assert_eq!(d.len(), 1);
        let d = sched.tick(tl.id(), 100_000_000).test_ok();
        assert_eq!(d.len(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_registry_returns_empty() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let reg = PluginRegistry::new();
        let mut sched = TickScheduler::new(reg);
        let drafts = sched.tick(tl.id(), 0).test_ok();
        assert!(drafts.is_empty());
    }
}
