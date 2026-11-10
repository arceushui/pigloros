//! Opening and durable writes count inside the existing readiness/budget window.

use super::{create_plan, honest, new_driver, DriverRig, TestResult};
use pos_owner_bridge::ceremony::driver::{Step, StepEnv};
use pos_owner_bridge::ceremony::plan::Budget;
use pos_owner_bridge::ceremony::timing::READINESS;
use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeStepper;
use pos_owner_bridge::fake::surface::{SurfaceConfig, SurfaceFaults};
use pos_owner_bridge::{
    BridgeError, CleanupError, CleanupStore, LifecycleCode, LoopbackPort, MonotonicClock,
    NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity, ReplyImage, RequestImage,
    ServedSnapshot, SurfaceError, SurfaceEvent, SurfaceSpec, UnavailableCode,
};
use std::collections::VecDeque;
use std::task::Poll;
use std::time::Duration;

struct DelayedOpening<'a> {
    inner: &'a mut dyn OwnerWebSurface,
    clock: FakeClock,
    delay: Duration,
    open_pending: u32,
    navigation_pending: u32,
    navigation: Poll<Result<NavigationId, SurfaceError>>,
    owner_observation: Option<&'a mut Vec<Option<u64>>>,
    mapping_delays: VecDeque<Duration>,
    close_delays: VecDeque<Duration>,
}

impl OwnerWebSurface for DelayedOpening<'_> {
    fn open(
        &mut self,
        spec: &SurfaceSpec,
    ) -> std::task::Poll<Result<ProcessIdentity, SurfaceError>> {
        if let Some(observed) = self.owner_observation.as_deref_mut() {
            observed.push(spec.owner_window);
        }
        if self.open_pending > 0 {
            self.open_pending -= 1;
            return Poll::Pending;
        }
        let result = self.inner.open(spec);
        self.clock.advance(self.delay);
        result
    }
    fn navigate(&mut self) -> std::task::Poll<Result<NavigationId, SurfaceError>> {
        if self.navigation.is_pending() {
            self.navigation = self.inner.navigate();
        }
        if self.navigation_pending > 0 {
            self.navigation_pending -= 1;
            Poll::Pending
        } else {
            self.navigation
        }
    }
    fn create_and_write(
        &mut self,
        request: &RequestImage,
        reply_header: &[u8; 64],
    ) -> Result<(), SurfaceError> {
        let result = self.inner.create_and_write(request, reply_header);
        self.clock
            .advance(self.mapping_delays.pop_front().unwrap_or_default());
        result
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
        let result = self.inner.zero_close_buffers();
        self.clock
            .advance(self.close_delays.pop_front().unwrap_or_default());
        result
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

struct DelayedProbe {
    inner: FakeLoopback,
    clock: FakeClock,
    delays: VecDeque<Duration>,
}

impl LoopbackPort for DelayedProbe {
    fn begin_navigation(&mut self) {
        self.inner.begin_navigation();
    }
    fn served(&self) -> ServedSnapshot {
        self.inner.served()
    }
    fn probe_ipv6(&mut self) -> Result<(), BridgeError> {
        let result = self.inner.probe_ipv6();
        self.clock
            .advance(self.delays.pop_front().unwrap_or_default());
        result
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
fn test_plan_owner_window_reaches_the_surface_open_port() -> TestResult {
    for owner in [None, Some(0x1234_5678_9abc_def0)] {
        let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
        let plan = create_plan(&rig.clock);
        let plan = match owner {
            Some(value) => plan.with_test_owner_window(value),
            None => plan,
        };
        let mut driver = new_driver(plan);
        let mut store = rig.store.clone();
        let mut loopback = rig.loopback.clone();
        let mut observed = Vec::new();
        let mut surface = DelayedOpening {
            inner: &mut rig.surface,
            clock: rig.clock.clone(),
            delay: Duration::ZERO,
            open_pending: 1,
            navigation_pending: 0,
            navigation: Poll::Pending,
            owner_observation: Some(&mut observed),
            mapping_delays: VecDeque::new(),
            close_delays: VecDeque::new(),
        };
        let mut env = StepEnv {
            surface: &mut surface,
            clock: &rig.clock,
            loopback: &mut loopback,
            store: &mut store,
        };
        assert!(matches!(driver.step(&mut env), Step::Pending));
        assert_eq!(observed, vec![owner]);
    }
    Ok(())
}

#[test]
fn pending_open_and_navigation_return_control_and_preserve_early_load() -> TestResult {
    let mut rig = DriverRig::new(
        honest(0),
        SurfaceConfig {
            load_delay: Duration::ZERO,
            ..SurfaceConfig::default()
        },
    )?;
    let mut driver = new_driver(create_plan(&rig.clock));
    let mut store = rig.store.clone();
    let mut loopback = rig.loopback.clone();
    let mut surface = DelayedOpening {
        inner: &mut rig.surface,
        clock: rig.clock.clone(),
        delay: Duration::ZERO,
        open_pending: 2,
        navigation_pending: 2,
        navigation: Poll::Pending,
        owner_observation: None,
        mapping_delays: VecDeque::new(),
        close_delays: VecDeque::new(),
    };
    let mut env = StepEnv {
        surface: &mut surface,
        clock: &rig.clock,
        loopback: &mut loopback,
        store: &mut store,
    };
    let started = rig.clock.now();
    for _ in 0..2 {
        assert!(matches!(driver.step(&mut env), Step::Pending));
        assert!(rig.store.records_now().is_empty());
        assert_eq!(rig.handle.pair_count(), 0);
        assert_eq!(rig.clock.now(), started);
    }
    // Opening finishes once; navigation has started but its ID is still withheld.
    assert!(matches!(driver.step(&mut env), Step::Pending));
    let record = rig.store.records_now();
    assert_eq!(record.len(), 1);
    assert_eq!(rig.loopback.resets(), 1);
    // DOMContentLoaded is already queued before navigate returns Ready.
    assert!(matches!(driver.step(&mut env), Step::Pending));
    assert!(matches!(driver.step(&mut env), Step::Pending));
    assert_eq!(rig.store.records_now(), record);
    assert_eq!(rig.loopback.resets(), 1);
    assert_eq!(rig.handle.pair_count(), 0);
    let result = FakeStepper::new(rig.clock.clone()).run(&mut driver, &mut env);
    assert!(result.is_ok());
    assert!(rig.store.records_now().is_empty());
    assert_eq!(rig.handle.finished(), 1);
    Ok(())
}

#[test]
fn pending_stages_do_not_restart_the_readiness_deadline() -> TestResult {
    for opening in [true, false] {
        let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
        let mut driver = new_driver(create_plan(&rig.clock));
        let mut store = rig.store.clone();
        let mut loopback = rig.loopback.clone();
        let mut surface = DelayedOpening {
            inner: &mut rig.surface,
            clock: rig.clock.clone(),
            delay: Duration::ZERO,
            open_pending: if opening { u32::MAX } else { 0 },
            navigation_pending: if opening { 0 } else { u32::MAX },
            navigation: Poll::Pending,
            owner_observation: None,
            mapping_delays: VecDeque::new(),
            close_delays: VecDeque::new(),
        };
        let mut env = StepEnv {
            surface: &mut surface,
            clock: &rig.clock,
            loopback: &mut loopback,
            store: &mut store,
        };
        assert!(matches!(driver.step(&mut env), Step::Pending));
        rig.clock.advance(READINESS);
        let result = FakeStepper::new(rig.clock.clone()).run(&mut driver, &mut env);
        assert!(matches!(
            result,
            Err(BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout))
        ));
        assert_eq!(rig.handle.pair_count(), 0);
        assert!(rig.store.records_now().is_empty());
        assert!(driver.request_clear());
    }
    Ok(())
}

#[test]
fn late_open_results_do_not_resurrect_a_cancelled_or_timed_out_driver() -> TestResult {
    for cancelled in [false, true] {
        for failed in [false, true] {
            let mut rig = DriverRig::new(honest(0), SurfaceConfig::default())?;
            let started = rig.clock.now();
            let mut driver = new_driver(create_plan(&rig.clock));
            let mut store = rig.store.clone();
            let mut loopback = rig.loopback.clone();
            let mut observed = Vec::new();
            {
                let mut surface = DelayedOpening {
                    inner: &mut rig.surface,
                    clock: rig.clock.clone(),
                    delay: Duration::ZERO,
                    open_pending: u32::MAX,
                    navigation_pending: 0,
                    navigation: Poll::Pending,
                    owner_observation: Some(&mut observed),
                    mapping_delays: VecDeque::new(),
                    close_delays: VecDeque::new(),
                };
                {
                    let mut env = StepEnv {
                        surface: &mut surface,
                        clock: &rig.clock,
                        loopback: &mut loopback,
                        store: &mut store,
                    };
                    assert!(matches!(driver.step(&mut env), Step::Pending));
                    let expected = if cancelled {
                        rig.handle
                            .schedule(Duration::ZERO, SurfaceEvent::ControllerLost);
                        LifecycleCode::ControllerLost
                    } else {
                        rig.clock.advance(READINESS);
                        LifecycleCode::ReadinessTimeout
                    };
                    let result = FakeStepper::new(rig.clock.clone()).run(&mut driver, &mut env);
                    assert_eq!(result.err(), Some(BridgeError::Lifecycle(expected)));
                }
                // Supply a modeled late port result only after the caller has
                // finished. Native handler custody is tested at the Windows seam.
                surface.open_pending = 0;
                rig.handle.set_faults(SurfaceFaults {
                    open: failed.then_some(BridgeError::Unavailable(
                        UnavailableCode::InterfaceUnavailable,
                    )),
                    ..SurfaceFaults::default()
                });
                let before = rig.handle.log();
                let generation = driver.generation();
                let mut env = StepEnv {
                    surface: &mut surface,
                    clock: &rig.clock,
                    loopback: &mut loopback,
                    store: &mut store,
                };
                for _ in 0..2 {
                    assert!(matches!(driver.step(&mut env), Step::Done));
                }
                assert_eq!(driver.generation(), generation);
                assert_eq!(rig.handle.log(), before);
            }
            assert_eq!(observed.len(), 1);
            assert_eq!(driver.t0(), started);
            assert!(driver.request_clear());
            assert!(driver.prf().iter().all(|byte| *byte == 0));
            assert_eq!(driver.posts(), 0);
            assert_eq!(rig.handle.pair_count(), 0);
            assert_eq!(rig.loopback.resets(), 0);
            assert!(rig.store.records_now().is_empty());
        }
    }
    Ok(())
}

#[test]
fn duplicate_document_completion_while_navigation_is_pending_prevents_posting() -> TestResult {
    let mut rig = DriverRig::new(
        honest(0),
        SurfaceConfig {
            load_delay: Duration::ZERO,
            ..SurfaceConfig::default()
        },
    )?;
    let mut driver = new_driver(create_plan(&rig.clock));
    let mut store = rig.store.clone();
    let mut loopback = rig.loopback.clone();
    let mut surface = DelayedOpening {
        inner: &mut rig.surface,
        clock: rig.clock.clone(),
        delay: Duration::ZERO,
        open_pending: 0,
        navigation_pending: 2,
        navigation: Poll::Pending,
        owner_observation: None,
        mapping_delays: VecDeque::new(),
        close_delays: VecDeque::new(),
    };
    let mut env = StepEnv {
        surface: &mut surface,
        clock: &rig.clock,
        loopback: &mut loopback,
        store: &mut store,
    };
    assert!(matches!(driver.step(&mut env), Step::Pending));
    rig.handle.schedule(
        Duration::ZERO,
        SurfaceEvent::DomContentLoaded(NavigationId(1)),
    );
    let result = FakeStepper::new(rig.clock.clone()).run(&mut driver, &mut env);
    assert!(matches!(
        result,
        Err(BridgeError::Lifecycle(LifecycleCode::NavigationViolation))
    ));
    assert_eq!(rig.handle.pair_count(), 0);
    assert!(rig.store.records_now().is_empty());
    Ok(())
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
                open_pending: 0,
                navigation_pending: 0,
                navigation: Poll::Pending,
                owner_observation: None,
                mapping_delays: VecDeque::new(),
                close_delays: VecDeque::new(),
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

#[test]
fn expiration_during_mapping_or_retry_retirement_prevents_late_posts() -> TestResult {
    use pos_owner_bridge::fake::buffers::LogEntry;

    for scenario in 0..4 {
        for budget in [None, Some(Duration::from_secs(5))] {
            let mut rig = DriverRig::new(honest(20_000), SurfaceConfig::default())?;
            let mut plan = create_plan(&rig.clock);
            if let Some(limit) = budget {
                plan = plan.with_budget(Budget::with_limit(rig.clock.now(), limit));
            }
            let delay = budget.unwrap_or(READINESS) + Duration::from_millis(1);
            let mut driver = new_driver(plan);
            let mut surface = DelayedOpening {
                inner: &mut rig.surface,
                clock: rig.clock.clone(),
                delay: Duration::ZERO,
                open_pending: 0,
                navigation_pending: 0,
                navigation: Poll::Pending,
                owner_observation: None,
                mapping_delays: match scenario {
                    0 => VecDeque::from([delay]),
                    1 => VecDeque::from([Duration::ZERO, delay]),
                    _ => VecDeque::new(),
                },
                close_delays: if scenario == 2 {
                    VecDeque::from([delay])
                } else {
                    VecDeque::new()
                },
            };
            let mut loopback = DelayedProbe {
                inner: rig.loopback.clone(),
                clock: rig.clock.clone(),
                delays: if scenario == 3 {
                    VecDeque::from([Duration::ZERO, delay])
                } else {
                    VecDeque::new()
                },
            };
            let mut env = StepEnv {
                surface: &mut surface,
                clock: &rig.clock,
                loopback: &mut loopback,
                store: &mut rig.store,
            };
            let result = FakeStepper::new(rig.clock.clone()).run(&mut driver, &mut env);
            let expected = if budget.is_some() {
                LifecycleCode::EnrollmentBudgetExceeded
            } else {
                LifecycleCode::ReadinessTimeout
            };
            assert_eq!(result.err(), Some(BridgeError::Lifecycle(expected)));
            let posts = rig
                .handle
                .log()
                .iter()
                .filter(|entry| matches!(entry, LogEntry::Post { .. }))
                .count();
            assert_eq!(posts, usize::from(matches!(scenario, 1 | 2)));
            assert_eq!(driver.posts(), u8::from(matches!(scenario, 1 | 2)));
            assert_eq!(
                rig.handle.pair_count(),
                match scenario {
                    0 | 2 => 1,
                    1 => 2,
                    _ => 0,
                }
            );
            assert!(driver.request_clear());
            assert!(driver.prf().iter().all(|byte| *byte == 0));
            assert!(rig.store.records_now().is_empty());
            assert_eq!(rig.handle.finished(), 1);
            rig.handle.with_buffers(|buffers| {
                assert!(buffers
                    .pairs
                    .iter()
                    .all(|pair| pair.host_closed && pair.request.iter().all(|byte| *byte == 0)));
                assert!(buffers
                    .log
                    .iter()
                    .any(|entry| matches!(entry, LogEntry::ExitObserved)));
            });
        }
    }
    Ok(())
}
