//! Opening and durable writes count inside the existing readiness/budget window.

use super::{create_plan, honest, new_driver, DriverRig, TestResult};
use pos_owner_bridge::ceremony::driver::StepEnv;
use pos_owner_bridge::ceremony::plan::Budget;
use pos_owner_bridge::ceremony::timing::READINESS;
use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::fake::host::FakeStore;
use pos_owner_bridge::fake::stepper::FakeStepper;
use pos_owner_bridge::fake::surface::{SurfaceConfig, SurfaceFaults};
use pos_owner_bridge::{
    BridgeError, CleanupError, CleanupStore, LifecycleCode, MonotonicClock, NavigationId,
    OwnerWebSurface, PostGuard, ProcessIdentity, ReplyImage, RequestImage, SurfaceError,
    SurfaceEvent, SurfaceSpec, UnavailableCode,
};
use std::time::Duration;

struct DelayedOpening<'a> {
    inner: &'a mut dyn OwnerWebSurface,
    clock: FakeClock,
    delay: Duration,
}

impl OwnerWebSurface for DelayedOpening<'_> {
    fn open(&mut self, spec: &SurfaceSpec) -> Result<ProcessIdentity, SurfaceError> {
        let result = self.inner.open(spec);
        self.clock.advance(self.delay);
        result
    }
    fn navigate(&mut self) -> Result<NavigationId, SurfaceError> {
        self.inner.navigate()
    }
    fn create_and_write(
        &mut self,
        request: &RequestImage,
        reply_header: &[u8; 64],
    ) -> Result<(), SurfaceError> {
        self.inner.create_and_write(request, reply_header)
    }
    fn post(&mut self, guard: &PostGuard) -> Result<(), SurfaceError> {
        self.inner.post(guard)
    }
    fn reply_load_state(&self) -> Result<u32, SurfaceError> {
        self.inner.reply_load_state()
    }
    fn reply_compare_exchange(&self, current: u32, new: u32) -> Result<bool, SurfaceError> {
        self.inner.reply_compare_exchange(current, new)
    }
    fn reply_copy(&self, out: &mut ReplyImage) -> Result<(), SurfaceError> {
        self.inner.reply_copy(out)
    }
    fn zero_close_buffers(&mut self) -> Result<(), SurfaceError> {
        self.inner.zero_close_buffers()
    }
    fn close_controller(&mut self) -> Result<(), SurfaceError> {
        self.inner.close_controller()
    }
    fn take_event(&mut self) -> Option<SurfaceEvent> {
        self.inner.take_event()
    }
    fn finish(&mut self) -> Result<(), SurfaceError> {
        self.inner.finish()
    }
}

struct DelayedStore {
    inner: FakeStore,
    clock: FakeClock,
    delay: Duration,
}

impl CleanupStore for DelayedStore {
    fn write_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        let result = self.inner.write_record(record);
        self.clock.advance(self.delay);
        result
    }
    fn delete_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        self.inner.delete_record(record)
    }
    fn records(&mut self) -> Result<Vec<Vec<u8>>, CleanupError> {
        self.inner.records()
    }
    fn folders(&mut self) -> Result<Vec<String>, CleanupError> {
        self.inner.folders()
    }
    fn remove_folder(&mut self, folder: &str) -> Result<(), CleanupError> {
        self.inner.remove_folder(folder)
    }
}

#[test]
fn opening_and_durable_write_time_expire_before_navigation_or_buffer_creation() -> TestResult {
    for budget in [None, Some(Duration::from_secs(5))] {
        for (opening, failure) in [(true, false), (true, true), (false, false)] {
            let mut rig = DriverRig::new(
                honest(0),
                SurfaceConfig {
                    faults: SurfaceFaults {
                        open: failure.then_some(BridgeError::Unavailable(
                            UnavailableCode::InterfaceUnavailable,
                        )),
                        ..SurfaceFaults::default()
                    },
                    ..SurfaceConfig::default()
                },
            )?;
            let mut plan = create_plan(&rig.clock);
            if let Some(limit) = budget {
                plan = plan.with_budget(Budget::with_limit(rig.clock.now(), limit));
            }
            let delay = budget.unwrap_or(READINESS) + Duration::from_millis(1);
            let mut driver = new_driver(plan);
            let mut surface = DelayedOpening {
                inner: &mut rig.surface,
                clock: rig.clock.clone(),
                delay: if opening { delay } else { Duration::ZERO },
            };
            let mut store = DelayedStore {
                inner: rig.store.clone(),
                clock: rig.clock.clone(),
                delay: if opening { Duration::ZERO } else { delay },
            };
            let mut env = StepEnv {
                surface: &mut surface,
                clock: &rig.clock,
                loopback: &mut rig.loopback,
                store: &mut store,
            };
            let result = FakeStepper::new(rig.clock.clone()).run(&mut driver, &mut env);
            let expected = if budget.is_some() {
                LifecycleCode::EnrollmentBudgetExceeded
            } else {
                LifecycleCode::ReadinessTimeout
            };
            assert!(matches!(result, Err(BridgeError::Lifecycle(code)) if code == expected));
            assert_eq!(rig.handle.pair_count(), 0);
            assert_eq!(rig.loopback.resets(), 0);
            assert_eq!(rig.handle.finished(), u32::from(!failure));
            assert!(rig.store.records_now().is_empty());
            assert!(driver.request_clear());
        }
    }
    Ok(())
}
