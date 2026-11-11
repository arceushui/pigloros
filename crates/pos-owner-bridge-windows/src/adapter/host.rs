#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{sync_channel, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pos_owner_bridge::ceremony::driver::{CeremonyDriver, Step, StepEnv};
use pos_owner_bridge::channel::{channel, ChannelHost, SurfaceEndpoint, SurfaceRequest};
use pos_owner_bridge::{
    BridgeError, CeremonyHost, CeremonyReply, CleanupStore, QuarantineKeeper, QuarantinePoll,
    SystemClock, UnavailableCode,
};

use super::surface::Surface;
use super::{loopback::SharedLoopback, store::WindowsCleanupStore};
use crate::{NativePulse, VerifiedRuntime};

const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// Owner-side channel facade and ownership of its dedicated native STA thread.
/// Dropping the facade joins that thread; accepted or quarantined native owners
/// remain alive until their cleanup completes.
pub struct WindowsOwnerHost {
    channel: Option<ChannelHost>,
    worker: Option<JoinHandle<()>>,
}

impl WindowsOwnerHost {
    /// Start the dedicated STA with the verified runtime and protected state root.
    ///
    /// The supplied store implements the portable cleanup durability contract.
    /// Every clone used by restart admission and the surface shares this store.
    ///
    /// # Errors
    ///
    /// Refuses an unprotected root, unavailable exclusive listener, or failed
    /// apartment, message timer or surface initialization.
    pub fn start(
        runtime: VerifiedRuntime,
        root: PathBuf,
        store: impl CleanupStore + Send + 'static,
    ) -> Result<Self, BridgeError> {
        Self::start_with_profile(runtime, root, store, crate::require_windows_profile)
    }

    fn start_with_profile(
        runtime: VerifiedRuntime,
        root: PathBuf,
        store: impl CleanupStore + Send + 'static,
        profile: fn() -> Result<(), BridgeError>,
    ) -> Result<Self, BridgeError> {
        profile()?;
        crate::refuse_overrides()?;
        crate::verify_private_directory(&root)?;
        let loopback = SharedLoopback::start()?;
        Self::spawn(runtime, root, loopback, WindowsCleanupStore::new(store))
    }

    #[cfg(test)]
    // Hosted Server exercises override, root and listener admission with the
    // same worker underneath the independently tested desktop-profile check.
    pub(super) fn start_fixture(
        runtime: VerifiedRuntime,
        root: PathBuf,
        store: impl CleanupStore + Send + 'static,
    ) -> Result<Self, BridgeError> {
        Self::start_with_profile(runtime, root, store, || Ok(()))
    }

    pub(super) fn spawn(
        runtime: VerifiedRuntime,
        root: PathBuf,
        loopback: SharedLoopback,
        store: WindowsCleanupStore,
    ) -> Result<Self, BridgeError> {
        Self::spawn_with_factory(runtime, root, loopback, store, crate::Native::owner_factory)
    }

    fn spawn_with_factory<F: crate::NativeFactory + 'static>(
        runtime: VerifiedRuntime,
        root: PathBuf,
        loopback: SharedLoopback,
        store: WindowsCleanupStore,
        make_factory: impl FnOnce() -> crate::NativeResult<F> + Send + 'static,
    ) -> Result<Self, BridgeError> {
        let (owner, endpoint) = channel();
        let (ready, started) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("piglor-owner-sta".to_owned())
            .spawn(move || {
                let Ok(factory) = make_factory() else {
                    let _sent = ready.send(Err(UNAVAILABLE));
                    return;
                };
                let factory = Rc::new(factory);
                let shared_factory = Rc::clone(&factory);
                let surface = Surface::new(
                    shared_factory,
                    Arc::new(runtime),
                    root,
                    Box::new(loopback.clone()),
                    Box::new(store.clone()),
                    Box::new(SystemClock),
                );
                let Ok(surface) = surface else {
                    let _sent = ready.send(Err(UNAVAILABLE));
                    return;
                };
                // A caller never receives a host whose apartment, independent
                // timer and initial native session have not been constructed.
                if ready.send(Ok(())).is_ok() {
                    Worker::new(endpoint, surface, loopback, store).run();
                }
                // Surface/driver/keeper owners have all gone before the last
                // factory and apartment are released on this creating thread.
                let factory = Rc::try_unwrap(factory);
                if let Ok(mut factory) = factory {
                    let _stopped = factory.stop();
                }
            })
            .map_err(|_| UNAVAILABLE)?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                channel: Some(owner),
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _joined = worker.join();
                Err(error)
            }
            Err(_) => {
                let _joined = worker.join();
                Err(UNAVAILABLE)
            }
        }
    }
}

#[cfg(test)]
mod tests;

impl CeremonyHost for WindowsOwnerHost {
    fn run(&mut self, driver: CeremonyDriver) -> CeremonyReply {
        match &mut self.channel {
            Some(channel) => channel.run(driver),
            None => CeremonyReply {
                result: Err(UNAVAILABLE),
                driver: Some(driver),
            },
        }
    }
    fn poll_quarantine(&mut self) -> QuarantinePoll {
        self.channel
            .as_mut()
            .map_or_else(QuarantinePoll::default, CeremonyHost::poll_quarantine)
    }
}

impl Drop for WindowsOwnerHost {
    fn drop(&mut self) {
        // Disconnect first so the STA can finish its retained work and leave.
        self.channel = None;
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}

struct Worker {
    endpoint: SurfaceEndpoint,
    surface: Surface,
    loopback: SharedLoopback,
    store: WindowsCleanupStore,
    active: Option<CeremonyDriver>,
    keeper: QuarantineKeeper,
    recovered: VecDeque<CeremonyDriver>,
    quarantined: bool,
    disconnected: bool,
}

impl Worker {
    const fn new(
        endpoint: SurfaceEndpoint,
        surface: Surface,
        loopback: SharedLoopback,
        store: WindowsCleanupStore,
    ) -> Self {
        Self {
            endpoint,
            surface,
            loopback,
            store,
            active: None,
            keeper: QuarantineKeeper::new(),
            recovered: VecDeque::new(),
            quarantined: false,
            disconnected: false,
        }
    }

    fn run(mut self) {
        loop {
            self.receive();
            self.step();
            self.cleanup();
            if self.disconnected
                && self.active.is_none()
                && !self.quarantined
                && self.surface.idle()
            {
                return;
            }
            self.pump();
        }
    }

    fn pump(&self) {
        match self.surface.pump() {
            Ok(NativePulse::Timer | NativePulse::Dispatched) => {}
            Ok(NativePulse::Quit) => self.surface.controller_lost(),
            Err(_) => {
                self.surface.controller_lost();
                // Keep accepted owners on their STA after a pump failure,
                // while avoiding a tight retry loop. Only this host sleeps.
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn receive(&mut self) {
        match self.endpoint.try_recv() {
            Ok(SurfaceRequest::Run(driver)) => {
                if self.active.is_some() || self.quarantined || !self.surface.idle() {
                    let _delivered = self.endpoint.reply_run(CeremonyReply {
                        result: Err(UNAVAILABLE),
                        driver: Some(*driver),
                    });
                } else {
                    if let Some(deadline) = driver.next_wake() {
                        self.surface.set_deadline(deadline);
                    }
                    self.active = Some(*driver);
                }
            }
            Ok(SurfaceRequest::PollQuarantine) => {
                let driver = self.recovered.pop_front();
                let remaining = self.quarantined || !self.recovered.is_empty();
                let _delivered = self
                    .endpoint
                    .reply_poll(QuarantinePoll { driver, remaining });
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => self.disconnected = true,
        }
    }

    fn step(&mut self) {
        let Some(driver) = &mut self.active else {
            return;
        };
        let outcome = driver.step(&mut StepEnv {
            surface: &mut self.surface,
            clock: &SystemClock,
            loopback: &mut self.loopback,
            store: &mut self.store,
        });
        let result = match outcome {
            Step::Pending => return,
            Step::Finished(result) => result,
            Step::Done => Err(UNAVAILABLE),
        };
        if let Some(driver) = self.active.take() {
            self.surface.abandon_opening();
            let reply = self.keeper.finish(driver, result);
            self.quarantined |= reply.driver.is_none();
            let _delivered = self.endpoint.reply_run(reply);
        }
    }

    fn cleanup(&mut self) {
        let surface = &mut self.surface;
        let loopback = &mut self.loopback;
        let store = &mut self.store;
        let poll = self.keeper.poll(|driver| {
            driver.poll_cleanup(&mut StepEnv {
                surface: &mut *surface,
                clock: &SystemClock,
                loopback: &mut *loopback,
                store: &mut *store,
            })
        });
        self.quarantined = poll.remaining;
        if let Some(driver) = poll.driver {
            self.recovered.push_back(driver);
        }
        if self.active.is_none() && !self.quarantined {
            // An opening that failed before a complete process identity has
            // its own retained environment/callback retirement path.
            let _retired_or_retained = self.surface.poll_failed_open();
        }
    }
}
