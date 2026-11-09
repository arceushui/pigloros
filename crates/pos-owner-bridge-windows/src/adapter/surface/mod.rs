#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use pos_owner_bridge::{
    BridgeError, CleanupStore, LifecycleCode, LoopbackPort, MonotonicClock, NavigationId,
    OwnerWebSurface, PostGuard, ProcessIdentity, ProtocolCode, ReplyImage, RequestImage,
    SurfaceError, SurfaceEvent, SurfaceSpec, UnavailableCode,
};
use pos_owner_bridge_codec::{ControlRole, ControlState, OwnerBridgeControlV1};

use super::events::Events;
use crate::VerifiedRuntime;
use crate::{BufferSlot, ClientBounds, NativeFactory, NativeOperations, OWNER_URL};

mod opening;
mod retirement;

#[cfg(test)]
mod tests;

const WIDTH: u32 = 480;
const HEIGHT: u32 = 640;

type Result<T> = std::result::Result<T, SurfaceError>;

pub(super) trait RuntimeAdmission {
    fn root(&self) -> &Path;
    fn identity(&self, pid: u32) -> std::result::Result<ProcessIdentity, BridgeError>;
}

impl RuntimeAdmission for VerifiedRuntime {
    fn root(&self) -> &Path {
        Self::root(self)
    }
    fn identity(&self, pid: u32) -> std::result::Result<ProcessIdentity, BridgeError> {
        self.browser_identity(pid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ownership {
    Idle,
    Folder,
    Window,
    CreatingEnvironment,
    Environment,
    CreatingController,
    Controller,
    ControllerClosed,
    EnvironmentDropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloseState {
    Idle,
    Pending,
}

pub(super) struct Surface {
    factory: Rc<dyn NativeFactory>,
    clock: Box<dyn MonotonicClock>,
    native: Box<dyn NativeOperations>,
    runtime: Arc<dyn RuntimeAdmission>,
    root: PathBuf,
    loopback: Box<dyn LoopbackPort>,
    store: Box<dyn CleanupStore>,
    deadline: Instant,
    events: Rc<Events>,
    folder: Option<String>,
    identity: Option<ProcessIdentity>,
    ownership: Ownership,
    generation: Option<u32>,
    buffers: bool,
    activation_error: Option<SurfaceError>,
    failed_open: bool,
    opening_spec: Option<SurfaceSpec>,
    foreground_deadline: Option<Instant>,
    navigation_issued: bool,
    close: CloseState,
    dpi: Cell<Option<u32>>,
    client: Cell<Option<ClientBounds>>,
}

/// A fault authority is minted only from the live admitted Surface, and retains
/// its event observer so a callback can invalidate topology during discovery.
#[cfg(test)]
pub(crate) struct FaultAuthority {
    browser: ProcessIdentity,
    target: crate::ProcessFaultTarget,
    events: Rc<Events>,
    trace: Rc<std::cell::RefCell<Vec<crate::ProcessFaultMark>>>,
}

#[cfg(test)]
impl FaultAuthority {
    pub(crate) const fn browser(&self) -> ProcessIdentity {
        self.browser
    }
    pub(crate) const fn target(&self) -> crate::ProcessFaultTarget {
        self.target
    }
    pub(crate) fn valid(&self) -> bool {
        !self.events.invalid() && self.events.exited().is_none()
    }
    pub(crate) fn record(&self, mark: crate::ProcessFaultMark) {
        self.trace.borrow_mut().push(mark);
    }
}

impl Surface {
    pub(super) fn new(
        factory: Rc<dyn NativeFactory>,
        runtime: Arc<dyn RuntimeAdmission>,
        root: PathBuf,
        loopback: Box<dyn LoopbackPort>,
        store: Box<dyn CleanupStore>,
        clock: Box<dyn MonotonicClock>,
    ) -> Result<Self> {
        let native = factory.session().map_err(unavailable)?;
        let deadline = clock.now();
        Ok(Self {
            factory,
            clock,
            native,
            runtime,
            root,
            loopback,
            store,
            deadline,
            events: Rc::new(Events::default()),
            folder: None,
            identity: None,
            ownership: Ownership::Idle,
            generation: None,
            buffers: false,
            activation_error: None,
            failed_open: false,
            opening_spec: None,
            foreground_deadline: None,
            navigation_issued: false,
            close: CloseState::Idle,
            dpi: Cell::new(None),
            client: Cell::new(None),
        })
    }

    #[cfg(test)]
    pub(in crate::adapter) fn posted_fault_state(
        &self,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultState, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
            || !self.buffers
            || !self.navigation_issued
            || self.events.loaded().is_none()
            || self.loopback.served().count != 1
            || !self.loopback.served().integrity_ok
            || !crate::Native::process_failure_observations().is_empty()
        {
            return Err(());
        }
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        let browser = self.identity.ok_or(())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        // The caller is the sealed single-view fixture; subscriptions were
        // installed before its only navigation, and every frame/popup callback
        // invalidates these events. The policy binds the fixture asset bytes.
        let state = crate::ProcessFaultState {
            phase: crate::ProcessFaultPhase::PostedReceipt,
            topology: crate::ProcessFaultTopology::SealedSingleViewFrameFree,
            generation: self.generation.ok_or(())?,
            reply_state: self.native.load_state().map_err(|_| ())?,
            record_count: self.store.records().map_err(|_| ())?.len(),
            posts,
        };
        if state.generation != 1 || state.record_count != 1 || state.posts != 1 {
            return Err(());
        }
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn posted_fault_event(
        &self,
        target: crate::ProcessFaultTarget,
    ) -> std::result::Result<Option<crate::ProcessFaultMark>, ()> {
        match target {
            crate::ProcessFaultTarget::Renderer => {
                let failures = crate::Native::process_failure_observations();
                if failures.is_empty() {
                    return Ok(None);
                }
                if failures != [Some(true)] || !self.events.renderer_failure_pending() {
                    return Err(());
                }
                Ok(Some(crate::ProcessFaultMark::MainRendererExited))
            }
            crate::ProcessFaultTarget::Browser => {
                let browser = self.identity.ok_or(())?;
                match self.events.exited() {
                    None => Ok(None),
                    Some(pid) if pid == browser.browser_pid => {
                        Ok(Some(crate::ProcessFaultMark::OwnBrowserExited))
                    }
                    Some(_) => Err(()),
                }
            }
        }
    }

    #[cfg(test)]
    pub(in crate::adapter) fn fault_owners_retained(&self) -> bool {
        self.ownership == Ownership::Controller
            && self.folder.is_some()
            && self.identity.is_some()
            && self.buffers
            && self.store.records().is_ok_and(|records| records.len() == 1)
            && self.native.fault_owners_retained()
    }

    /// Declared post-receipt fault only; this is never a cleanup operation.
    #[cfg(test)]
    pub(in crate::adapter) fn inject_posted_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::adapter::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
            || self.generation != Some(1)
            || !self.buffers
            || !self.navigation_issued
            || self.events.loaded().is_none()
            || self.loopback.served().count != 1
            || !self.loopback.served().integrity_ok
        {
            return Err(());
        }
        let folder = self.folder.as_ref().ok_or(())?;
        let folder = self.root.join(folder);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        let browser = self.identity.ok_or(())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        let authority = FaultAuthority {
            browser,
            target,
            events: Rc::clone(&self.events),
            trace: seal.trace(),
        };
        self.native.inject_process_fault(&authority)
    }

    pub(super) const fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
    pub(super) fn idle(&self) -> bool {
        self.ownership == Ownership::Idle && !self.native.pending()
    }

    pub(super) fn controller_lost(&self) {
        self.events.controller_lost();
    }

    pub(super) fn pump(&self) -> crate::NativeResult<crate::NativePulse> {
        self.factory.next()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn fixture_progress(&self) -> String {
        format!(
            "ownership={:?} close={:?} pending={} pid={:?} started={:?} loaded={:?} exited={:?}",
            self.ownership,
            self.close,
            self.native.pending(),
            self.identity.map(|identity| identity.browser_pid),
            self.events.started(),
            self.events.loaded(),
            self.events.exited(),
        )
    }

    pub(super) fn refresh(&self) -> Result<()> {
        if matches!(
            self.ownership,
            Ownership::Idle | Ownership::Folder | Ownership::EnvironmentDropped
        ) {
            return Ok(());
        }
        let snapshot = self.native.window().map_err(unavailable)?;
        if !snapshot.exists || snapshot.close_requested {
            return Err(lost());
        }
        let dpi_changed = self
            .dpi
            .replace(Some(snapshot.dpi))
            .is_some_and(|dpi| dpi != snapshot.dpi);
        if dpi_changed {
            self.native
                .resize_window(WIDTH, HEIGHT, snapshot.dpi)
                .map_err(unavailable)?;
        }
        let client_changed = self.client.replace(Some(snapshot.client)) != Some(snapshot.client);
        if (dpi_changed || client_changed) && self.ownership == Ownership::Controller {
            self.native.fit_controller().map_err(unavailable)?;
        }
        Ok(())
    }

    fn guarded(&self, guard: &PostGuard) -> Result<()> {
        self.refresh()?;
        let served = self.loopback.served();
        if !served.integrity_ok || served.count == 0 {
            return Err(SurfaceError::new(BridgeError::Unavailable(
                UnavailableCode::AssetIntegrity,
            )));
        }
        if served.count > 1 {
            return Err(SurfaceError::new(BridgeError::Protocol(
                ProtocolCode::DuplicateDocumentLoad,
            )));
        }
        if self.ownership != Ownership::Controller
            || self.events.invalid()
            || self.generation != Some(guard.generation)
            || guard.served_count != 1
            || self.events.started() != Some(guard.navigation_id)
            || self.events.loaded() != Some(guard.navigation_id)
            || self.native.source().map_err(unavailable)?.as_str() != OWNER_URL
        {
            return Err(navigation_lost());
        }
        Ok(())
    }
}

impl OwnerWebSurface for Surface {
    fn open(&mut self, spec: &SurfaceSpec) -> Poll<Result<ProcessIdentity>> {
        if let Some(opening) = &self.opening_spec {
            if opening != spec || self.failed_open {
                return Poll::Ready(Err(unavailable(())));
            }
        } else {
            if !self.idle() {
                return Poll::Ready(Err(unavailable(())));
            }
            self.native = match self.factory.session() {
                Ok(native) => native,
                Err(error) => return Poll::Ready(Err(unavailable(error))),
            };
            self.events = Rc::new(Events::default());
            self.activation_error = None;
            self.generation = None;
            self.foreground_deadline = None;
            self.navigation_issued = false;
            self.close = CloseState::Idle;
            self.dpi.set(None);
            self.client.set(None);
            self.opening_spec = Some(spec.clone());
        }
        let result = self.open_native(spec);
        self.failed_open = result.is_err() && !self.idle();
        if result.is_err() && self.idle() {
            self.opening_spec = None;
        }
        match result {
            Ok(poll) => poll.map(Ok),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn navigate(&mut self) -> Poll<Result<NavigationId>> {
        match self.navigate_native() {
            Ok(poll) => poll.map(Ok),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn create_and_write(&mut self, request: &RequestImage, reply_header: &[u8; 64]) -> Result<()> {
        if self.buffers || self.events.invalid() {
            return Err(unavailable(()));
        }
        let header = request
            .as_bytes()
            .get(..64)
            .ok_or_else(|| unavailable(()))?;
        let request_control = OwnerBridgeControlV1::decode(header).map_err(unavailable)?;
        let reply_control = OwnerBridgeControlV1::decode(reply_header).map_err(unavailable)?;
        if request_control.role() != ControlRole::Request
            || reply_control.role() != ControlRole::Reply
            || request_control.state() != ControlState::Ready
            || reply_control.state() != ControlState::Empty
            || request_control.generation() != reply_control.generation()
            || request_control.kind() != reply_control.kind()
            || request_control.ceremony_id() != reply_control.ceremony_id()
            || request.as_bytes().len() != request_control.total_capacity() as usize
        {
            return Err(unavailable(()));
        }
        self.native
            .create_buffers(request_control.kind(), request.as_bytes(), reply_header)
            .map_err(unavailable)?;
        self.generation = Some(request_control.generation());
        self.buffers = true;
        Ok(())
    }

    fn post(&mut self, guard: &PostGuard) -> Result<()> {
        self.guarded(guard)?;
        self.native.post(BufferSlot::Request).map_err(unavailable)?;
        // Reentrant callbacks/served completions during the first SDK call
        // cannot authorize the second post using a stale observation.
        self.guarded(guard)?;
        self.native.post(BufferSlot::Reply).map_err(unavailable)
    }

    fn reply_load_state(&self) -> Result<u32> {
        self.native.load_state().map_err(unavailable)
    }
    fn reply_compare_exchange(&self, current: u32, new: u32) -> Result<bool> {
        self.native
            .compare_exchange(current, new)
            .map_err(unavailable)
    }
    fn reply_copy(&self, out: &mut ReplyImage) -> Result<()> {
        self.native.copy_reply(out).map_err(unavailable)
    }
    fn zero_close_buffers(&mut self) -> Result<()> {
        let result = self.native.close_buffers().map_err(unavailable);
        self.buffers = false;
        result
    }

    fn close_controller(&mut self) -> Result<()> {
        self.close = CloseState::Pending;
        let buffers = self.zero_close_buffers();
        let removed = self.native.unsubscribe_view().map_err(unavailable);
        let closed = self.native.close_controller().map_err(unavailable);
        if closed.is_ok() {
            self.ownership = Ownership::ControllerClosed;
        }
        buffers.and(removed).and(closed)?;
        if self.native.buffer_close_uncertain() {
            Err(unavailable(()))
        } else {
            self.close = CloseState::Idle;
            Ok(())
        }
    }

    fn take_event(&mut self) -> Option<SurfaceEvent> {
        if self.close == CloseState::Pending {
            // The driver may already have returned quarantine. Continue native
            // retirement on its keeper's ordinary STA ticks without new clocks.
            let _closed_or_retained = self.close_controller();
        }
        if self.refresh().is_err() {
            self.events.controller_lost();
        }
        #[cfg(test)]
        if self.events.renderer_failure_pending() {
            // Capture before the driver handles this event and wipes mappings.
            // A crash before posting cannot produce this generation/state/record
            // evidence. The sealed fault page marks WRITING immediately before
            // its prohibited request-buffer write; normal G3 is unchanged.
            crate::Native::record_renderer_state(crate::RendererStateObservation {
                generation: self.generation,
                reply_state: self.native.load_state().ok(),
                record_count: self.store.records().ok().map(|records| records.len()),
            });
        }
        self.events.take()
    }

    fn finish(&mut self) -> Result<()> {
        let identity = self.identity.ok_or_else(|| unavailable(()))?;
        if self.events.exited() != Some(identity.browser_pid) {
            return Err(unavailable(()));
        }
        self.native.unsubscribe_view().map_err(unavailable)?;
        self.native.unsubscribe_exit().map_err(unavailable)?;
        self.native.drop_environment().map_err(unavailable)?;
        self.ownership = Ownership::EnvironmentDropped;
        self.finish_folder()?;
        self.identity = None;
        self.failed_open = false;
        self.close = CloseState::Idle;
        self.opening_spec = None;
        self.ownership = Ownership::Idle;
        Ok(())
    }
}

fn unavailable<T>(_: T) -> SurfaceError {
    SurfaceError::new(BridgeError::Unavailable(
        UnavailableCode::InterfaceUnavailable,
    ))
}
const fn lost() -> SurfaceError {
    SurfaceError::new(BridgeError::Lifecycle(LifecycleCode::ControllerLost))
}
const fn navigation_lost() -> SurfaceError {
    SurfaceError::new(BridgeError::Lifecycle(LifecycleCode::NavigationViolation))
}
