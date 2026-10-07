//! The test stepper and the test host: step a driver and advance the fake clock between steps.
//!
//! A production host owns this loop on its surface thread (ADR-110 §6); the portable core never
//! sleeps.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use super::clock::FakeClock;
use super::host::{FakeLoopback, FakeStore};
use super::surface::FakeSurface;
use crate::ceremony::driver::{CeremonyDriver, Step, StepEnv};
use crate::ceremony::plan::Verified;
use crate::ceremony::timing::TIMER_INTERVAL;
use crate::channel::{SurfaceEndpoint, SurfaceRequest};
use crate::{BridgeError, CeremonyHost, CeremonyReply, ProtocolCode, QuarantineKeeper};

/// The most steps one ceremony may take under the default limit. A legitimate ceremony ends in a
/// few thousand: the longest wait is the two-minute interaction bound at a 50 ms cadence.
pub const DEFAULT_STEP_LIMIT: u32 = 100_000;

const STUCK: BridgeError = BridgeError::Protocol(ProtocolCode::UnexpectedState);

/// A stepper that steps the driver, then moves the fake clock to the driver's next wake.
#[derive(Clone)]
pub struct FakeStepper {
    clock: FakeClock,
    limit: u32,
    steps: Rc<Cell<u32>>,
}

impl FakeStepper {
    /// A stepper over `clock` with the default step limit.
    #[must_use]
    pub fn new(clock: FakeClock) -> Self {
        Self {
            clock,
            limit: DEFAULT_STEP_LIMIT,
            steps: Rc::new(Cell::new(0)),
        }
    }

    /// Give up after `limit` steps per run, so a stuck driver fails a test instead of hanging it.
    #[must_use]
    pub const fn with_step_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// How many steps this stepper has taken in total.
    #[must_use]
    pub fn steps(&self) -> u32 {
        self.steps.get()
    }

    /// A shared view of the step count, readable after the stepper moved into a host.
    #[must_use]
    pub fn steps_counter(&self) -> Rc<Cell<u32>> {
        Rc::clone(&self.steps)
    }

    /// Step until the driver finishes.
    ///
    /// # Errors
    ///
    /// Returns the ceremony's failure, or `Protocol(UnexpectedState)` when the step limit is
    /// reached first or the driver had already finished.
    pub fn run(
        &mut self,
        driver: &mut CeremonyDriver,
        env: &mut StepEnv<'_>,
    ) -> Result<Verified, BridgeError> {
        for _ in 0..self.limit {
            self.steps.set(self.steps.get() + 1);
            match driver.step(env) {
                Step::Finished(result) => return result,
                Step::Done => return Err(STUCK),
                Step::Pending => self.clock.skip(TIMER_INTERVAL, driver.next_wake()),
            }
        }
        Err(STUCK)
    }
}

/// A host that owns a `FakeSurface` and the host ports and runs every ceremony on the calling
/// thread, with the fake clock advanced by a [`FakeStepper`].
pub struct FakeHost {
    surface: FakeSurface,
    loopback: FakeLoopback,
    store: FakeStore,
    clock: FakeClock,
    stepper: FakeStepper,
    keeper: QuarantineKeeper,
    t0s: Rc<RefCell<Vec<Duration>>>,
}

impl FakeHost {
    /// A host over `surface`, `loopback` and `store`, all driven by `clock`.
    #[must_use]
    pub fn new(
        clock: FakeClock,
        surface: FakeSurface,
        loopback: FakeLoopback,
        store: FakeStore,
    ) -> Self {
        Self {
            surface,
            loopback,
            store,
            stepper: FakeStepper::new(clock.clone()),
            clock,
            keeper: QuarantineKeeper::new(),
            t0s: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Serve the surface thread's half of the hand-off until the owner side goes away: take each
    /// command, run it here, and reply. Build the host on the thread that calls this, because the
    /// fakes are not `Send`.
    pub fn serve(mut self, endpoint: &SurfaceEndpoint) {
        loop {
            let next = endpoint.recv();
            let Some(request) = next else {
                return;
            };
            let delivered = match request {
                SurfaceRequest::Run(driver) => endpoint.reply_run(self.run(*driver)),
                SurfaceRequest::PollQuarantine => endpoint.reply_poll(self.poll_quarantine()),
            };
            if !delivered {
                return;
            }
        }
    }

    /// A shared view of the stepper's step count.
    #[must_use]
    pub fn steps_counter(&self) -> Rc<Cell<u32>> {
        self.stepper.steps_counter()
    }

    /// A shared log of each ceremony's T0, as an offset from the clock's start.
    #[must_use]
    pub fn t0_log(&self) -> Rc<RefCell<Vec<Duration>>> {
        Rc::clone(&self.t0s)
    }
}

impl CeremonyHost for FakeHost {
    fn run(&mut self, mut driver: CeremonyDriver) -> CeremonyReply {
        // The owner thread drew T0 from its own clock; fake time starts this run at exactly T0.
        self.clock.align_to(driver.t0());
        self.t0s
            .borrow_mut()
            .push(self.clock.offset_of(driver.t0()));
        let mut env = StepEnv {
            surface: &mut self.surface,
            clock: &self.clock,
            loopback: &mut self.loopback,
            store: &mut self.store,
        };
        let result = self.stepper.run(&mut driver, &mut env);
        self.keeper.finish(driver, result)
    }

    fn poll_quarantine(&mut self) -> Option<CeremonyDriver> {
        let mut env = StepEnv {
            surface: &mut self.surface,
            clock: &self.clock,
            loopback: &mut self.loopback,
            store: &mut self.store,
        };
        self.keeper.poll(|driver| driver.poll_cleanup(&mut env))
    }
}
