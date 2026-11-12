#![cfg(windows)]
#![forbid(unsafe_code)]

#[cfg(test)]
use std::io::Write as _;

#[cfg(test)]
fn pending_opening_diagnostic(message: &'static str) {
    let _logged_or_unavailable = writeln!(std::io::stderr(), "{message}");
}

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
mod diagnostics;

#[cfg(test)]
mod controller_qualification;

#[cfg(test)]
mod exit_boundary;

#[cfg(test)]
pub(in crate::adapter) use exit_boundary::ExitBoundary;

#[cfg(test)]
pub(in crate::adapter) mod tests;

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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::adapter) enum PreEnvironmentRetention {
    Active,
    Abandoned,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::adapter) struct CloseObservation {
    pub(in crate::adapter) removed: crate::NativeResult<()>,
    pub(in crate::adapter) closed: crate::NativeResult<()>,
    pub(in crate::adapter) buffers_closed: bool,
    pub(in crate::adapter) buffers_uncertain: bool,
    pub(in crate::adapter) had_controller: bool,
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
    #[cfg(test)]
    recordless_fault: Option<ProcessIdentity>,
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
    #[cfg(test)]
    cleanup_trace: diagnostics::CleanupTrace,
    #[cfg(test)]
    initial_buffer_close: Option<bool>,
    #[cfg(test)]
    initial_close: Option<CloseObservation>,
    #[cfg(test)]
    readiness_timing: diagnostics::ReadinessTiming,
    #[cfg(test)]
    exit_capture: Option<exit_boundary::ExitCapture>,
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
            #[cfg(test)]
            recordless_fault: None,
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
            #[cfg(test)]
            cleanup_trace: diagnostics::CleanupTrace::default(),
            #[cfg(test)]
            initial_buffer_close: None,
            #[cfg(test)]
            initial_close: None,
            #[cfg(test)]
            readiness_timing: diagnostics::ReadinessTiming::default(),
            #[cfg(test)]
            exit_capture: None,
        })
    }

    #[cfg(test)]
    pub(in crate::adapter) fn begin_readiness_timing(&mut self, case: u64, started: Instant) {
        self.readiness_timing.begin(case, started);
    }

    #[cfg(test)]
    pub(in crate::adapter) fn report_readiness_timing(&mut self) {
        self.readiness_timing.report();
    }

    #[cfg(test)]
    pub(in crate::adapter) fn pre_environment_retention(
        &mut self,
        ceremony: &pos_owner_bridge_codec::CeremonyId,
    ) -> Option<PreEnvironmentRetention> {
        let opening = self.opening_spec.as_ref()?;
        if &opening.ceremony_id != ceremony
            || self.folder.as_ref()? != &pos_owner_bridge::folder_name(ceremony)
            || self.identity.is_some()
            || self.buffers
            || self.generation.is_some()
            || !self.native.window().ok()?.exists
            || !self.store.records().ok()?.is_empty()
        {
            return None;
        }
        let folder = self.root.join(self.folder.as_ref()?);
        crate::verify_private_directory(&folder).ok()?;
        match (self.ownership, self.failed_open) {
            (Ownership::CreatingEnvironment, false) => Some(PreEnvironmentRetention::Active),
            (Ownership::CreatingEnvironment | Ownership::Environment, true) => {
                Some(PreEnvironmentRetention::Abandoned)
            }
            _ => None,
        }
    }

    #[cfg(test)]
    pub(in crate::adapter) fn pre_environment_completion(
        &mut self,
    ) -> std::result::Result<Option<bool>, ()> {
        if self.ownership != Ownership::CreatingEnvironment
            || self.failed_open
            || self.identity.is_some()
            || self.buffers
            || !self.native.pending()
            || self.folder.is_none()
            || !self.store.records().map_err(|_| ())?.is_empty()
            || self.events.invalid()
            || self.events.exited().is_some()
        {
            return Err(());
        }
        Ok(self.native.environment_creation_completion())
    }

    #[cfg(test)]
    pub(in crate::adapter) fn recordless_opening_ready(&self) -> bool {
        self.ownership == Ownership::CreatingController
            && !self.failed_open
            && self.identity.is_none()
            && self.recordless_fault.is_none()
            && !self.buffers
            && self.native.pending()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn recordless_controller_completion(&self) -> Option<bool> {
        if !self.recordless_opening_ready() {
            return None;
        }
        self.native.recordless_controller_completion()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn prepare_recordless_browser(
        &mut self,
    ) -> std::result::Result<ProcessIdentity, ()> {
        if !self.recordless_opening_ready()
            || !self.native.recordless_fault_owners_retained()
            || self.events.invalid()
            || self.events.exited().is_some()
            || !self.store.records().map_err(|_| ())?.is_empty()
        {
            return Err(());
        }
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        let browser = self.native.recordless_browser_candidate()?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        self.events.expect_browser(browser.browser_pid);
        self.recordless_fault = Some(browser);
        Ok(browser)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_recordless_browser(
        &mut self,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if self.ownership != Ownership::CreatingController
            || self.failed_open
            || self.identity.is_some()
            || self.buffers
            || self.events.invalid()
            || self.events.exited().is_some()
            || !self.native.recordless_fault_owners_retained()
            || !self.store.records().map_err(|_| ())?.is_empty()
        {
            return Err(());
        }
        let browser = self.recordless_fault.ok_or(())?;
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser
            || self.native.recordless_browser_candidate()? != browser
        {
            return Err(());
        }
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target: crate::ProcessFaultTarget::Browser,
            lifecycle: crate::ProcessFaultLifecycle::RecordlessOpening,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && !events.invalid()
                    && events.exited().is_none()
            }),
            trace,
        };
        self.native.inject_process_fault(&authority)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn prepare_pending_opening_browser(
        &mut self,
    ) -> std::result::Result<Option<ProcessIdentity>, ()> {
        if !self.recordless_opening_ready() {
            let _logged_or_unavailable =
                writeln!(std::io::stderr(), "NATIVE_PENDING_OPENING failure=phase");
            return Err(());
        }
        if !self.native.pending_opening_owners_retained() {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=native-owners");
            return Err(());
        }
        if self.native.recordless_controller_completion().is_some() {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=callback-before");
            return Err(());
        }
        if self.events.invalid() {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=invalid-event");
            return Err(());
        }
        if self.events.exited().is_some() {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=prior-exit");
            return Err(());
        }
        let records = self.store.records().map_err(|_| {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=records-unreadable");
        })?;
        if !records.is_empty() {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=records-present");
            return Err(());
        }
        let folder = self.root.join(self.folder.as_ref().ok_or_else(|| {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=folder-missing");
        })?);
        crate::verify_private_directory(&folder).map_err(|_| {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=folder-verification");
        })?;
        self.admit_environment(&folder).map_err(|_| {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=environment-admission");
        })?;
        let browser = self
            .native
            .pending_opening_browser_candidate()
            .map_err(|()| {
                pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=candidate");
            })?;
        let Some(browser) = browser else {
            if !self.recordless_opening_ready()
                || !self.native.pending_opening_owners_retained()
                || self.native.recordless_controller_completion().is_some()
                || self.events.invalid()
                || self.events.exited().is_some()
            {
                return Err(());
            }
            return Ok(None);
        };
        let actual = self.runtime.identity(browser.browser_pid).map_err(|_| {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=runtime-identity-read");
        })?;
        if actual != browser {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=runtime-identity-mismatch");
            return Err(());
        }
        if self.native.recordless_controller_completion().is_some() {
            pending_opening_diagnostic("NATIVE_PENDING_OPENING failure=callback-after");
            return Err(());
        }
        pending_opening_diagnostic(
            "NATIVE_PENDING_OPENING after-candidate=identity-matched-callback-pending",
        );
        self.events.expect_browser(browser.browser_pid);
        self.recordless_fault = Some(browser);
        Ok(Some(browser))
    }

    #[cfg(test)]
    pub(in crate::adapter) fn pending_opening_owners_retained(&mut self) -> bool {
        self.ownership == Ownership::CreatingController
            && self.folder.is_some()
            && self.identity.is_none()
            && self.recordless_fault.is_some()
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.is_empty())
            && self.native.pending_opening_owners_retained()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn pending_opening_completion(&self) -> Option<bool> {
        self.native.recordless_controller_completion()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_pending_opening_browser(
        &mut self,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if !self.pending_opening_owners_retained()
            || self.native.recordless_controller_completion().is_some()
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
        {
            return Err(());
        }
        let browser = self.recordless_fault.ok_or(())?;
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser
            || self.native.pending_opening_browser_candidate()? != Some(browser)
        {
            return Err(());
        }
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target: crate::ProcessFaultTarget::Browser,
            lifecycle: crate::ProcessFaultLifecycle::PendingOpening,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && !events.invalid()
                    && events.exited().is_none()
            }),
            trace,
        };
        self.native.inject_process_fault(&authority)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn recordless_fault_event(
        &self,
    ) -> std::result::Result<Option<crate::ProcessFaultMark>, ()> {
        let browser = self.recordless_fault.ok_or(())?;
        match self.events.exited() {
            None => Ok(None),
            Some(pid) if pid == browser.browser_pid => {
                Ok(Some(crate::ProcessFaultMark::OwnBrowserExited))
            }
            Some(_) => Err(()),
        }
    }

    #[cfg(test)]
    pub(in crate::adapter) fn recordless_fault_owners_retained(&mut self) -> bool {
        self.ownership == Ownership::CreatingController
            && self.folder.is_some()
            && self.identity.is_none()
            && self.recordless_fault.is_some()
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.is_empty())
            && self.native.recordless_fault_owners_retained()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn early_renderer_presence(
        &self,
    ) -> std::result::Result<crate::RendererPresence, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
            || self.buffers
            || !self.native.preload_fault_owners_retained()
            || !crate::Native::process_failure_observations().is_empty()
        {
            return Err(());
        }
        let browser = self.identity.ok_or(())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        let presence = self.native.early_renderer_presence()?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser
            || self.events.invalid()
            || self.events.exited().is_some()
        {
            return Err(());
        }
        Ok(presence)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn awaiting_load_fault_ready(&self) -> bool {
        self.ownership == Ownership::Controller
            && self.close == CloseState::Idle
            && !self.failed_open
            && !self.events.invalid()
            && self.events.exited().is_none()
            && self.navigation_issued
            && self.events.started().is_some()
            && self.events.loaded().is_none()
            && self.loopback.served().count <= 1
            && self.loopback.served().integrity_ok
            && !self.buffers
            && self.native.preload_fault_owners_retained()
            && crate::Native::process_failure_observations().is_empty()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn awaiting_load_fault_state(
        &mut self,
        generation: u32,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultMark, ()> {
        if !self.awaiting_load_fault_ready() || generation != 1 || posts != 0 {
            return Err(());
        }
        let browser = self.identity.ok_or(())?;
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        let record_count = self.store.records().map_err(|_| ())?.len();
        if record_count != 1 {
            return Err(());
        }
        Ok(crate::ProcessFaultMark::AwaitingLoad {
            generation,
            record_count,
        })
    }

    #[cfg(test)]
    pub(in crate::adapter) fn awaiting_load_fault_owners_retained(&mut self) -> bool {
        self.ownership == Ownership::Controller
            && self.folder.is_some()
            && self.identity.is_some()
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.len() == 1)
            && self.native.preload_fault_owners_retained()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_awaiting_load_fault(
        &mut self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        self.awaiting_load_fault_state(1, 0)?;
        let browser = self.identity.ok_or(())?;
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target,
            lifecycle: crate::ProcessFaultLifecycle::AwaitingLoad,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && !events.invalid()
                    && events.exited().is_none()
                    && events.started().is_some()
                    && events.loaded().is_none()
            }),
            trace,
        };
        self.native.inject_process_fault(&authority)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn navigating_fault_ready(&self) -> bool {
        self.ownership == Ownership::Controller
            && self.close == CloseState::Idle
            && !self.failed_open
            && !self.events.invalid()
            && self.events.exited().is_none()
            && self.navigation_issued
            && self.events.started().is_none()
            && self.events.loaded().is_none()
            && self.loopback.served().count <= 1
            && self.loopback.served().integrity_ok
            && !self.buffers
            && self.native.preload_fault_owners_retained()
            && crate::Native::process_failure_observations().is_empty()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn navigating_fault_state(
        &mut self,
        generation: u32,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultMark, ()> {
        if !self.navigating_fault_ready() || generation != 1 || posts != 0 {
            return Err(());
        }
        let browser = self.identity.ok_or(())?;
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        let record_count = self.store.records().map_err(|_| ())?.len();
        if record_count != 1 {
            return Err(());
        }
        Ok(crate::ProcessFaultMark::Navigating {
            generation,
            record_count,
        })
    }

    #[cfg(test)]
    pub(in crate::adapter) fn navigating_fault_owners_retained(&mut self) -> bool {
        self.ownership == Ownership::Controller
            && self.folder.is_some()
            && self.identity.is_some()
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.len() == 1)
            && self.native.preload_fault_owners_retained()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_navigating_fault(
        &mut self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        self.navigating_fault_state(1, 0)?;
        let browser = self.identity.ok_or(())?;
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target,
            lifecycle: crate::ProcessFaultLifecycle::Navigating,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && !events.invalid()
                    && events.exited().is_none()
                    && events.started().is_none()
                    && events.loaded().is_none()
            }),
            trace,
        };
        self.native.inject_process_fault(&authority)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn before_record_fault_state(
        &mut self,
    ) -> std::result::Result<ProcessIdentity, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || self.activation_error.is_some()
            || self.events.invalid()
            || self.events.exited().is_some()
            || self.navigation_issued
            || self.buffers
            || !self.native.preload_fault_owners_retained()
            || !self.store.records().map_err(|_| ())?.is_empty()
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
        Ok(browser)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn before_record_owners_retained(&mut self) -> bool {
        self.ownership == Ownership::Controller
            && self.folder.is_some()
            && self.identity.is_some()
            && !self.navigation_issued
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.is_empty())
            && self.native.preload_fault_owners_retained()
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_before_record_fault(
        &mut self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        let browser = self.before_record_fault_state()?;
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target,
            lifecycle: crate::ProcessFaultLifecycle::BeforeRecord,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && !events.invalid()
                    && events.exited().is_none()
            }),
            trace,
        };
        self.native.inject_process_fault(&authority)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn posted_fault_state(
        &mut self,
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
    pub(in crate::adapter) fn posted_retry_fault_state(
        &mut self,
        posts: u8,
        point: crate::RetryPoint,
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
            phase: crate::ProcessFaultPhase::PostedRetry,
            topology: crate::ProcessFaultTopology::SealedSingleViewFrameFree,
            generation: self.generation.ok_or(())?,
            reply_state: self.native.load_state().map_err(|_| ())?,
            record_count: self.store.records().map_err(|_| ())?.len(),
            posts,
        };
        if state.generation != u32::from(point.post())
            || state.record_count != 1
            || state.posts != point.post()
            || ControlState::try_from(state.reply_state).ok() != Some(ControlState::Empty)
        {
            return Err(());
        }
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn posted_empty_fault_state(
        &mut self,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultState, ()> {
        let mut state = self.posted_fault_state(posts)?;
        if ControlState::try_from(state.reply_state).ok() != Some(ControlState::Empty) {
            return Err(());
        }
        state.phase = crate::ProcessFaultPhase::PostedEmpty;
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn posted_writing_fault_state(
        &mut self,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultState, ()> {
        let mut state = self.posted_fault_state(posts)?;
        if ControlState::try_from(state.reply_state).ok() != Some(ControlState::Writing) {
            return Err(());
        }
        state.phase = crate::ProcessFaultPhase::PostedWriting;
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn posted_ready_fault_state(
        &mut self,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultState, ()> {
        let mut state = self.posted_fault_state(posts)?;
        if ControlState::try_from(state.reply_state).ok() != Some(ControlState::Ready) {
            return Err(());
        }
        state.phase = crate::ProcessFaultPhase::PostedReady;
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn releasing_fault_state(
        &mut self,
        posts: u8,
    ) -> std::result::Result<crate::ProcessFaultState, ()> {
        let mut state = self.posted_fault_state(posts)?;
        if ControlState::try_from(state.reply_state).ok() != Some(ControlState::ReleaseRequested) {
            return Err(());
        }
        state.phase = crate::ProcessFaultPhase::ReleasingSuccess;
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn exit_fault_phase_reached(&self) -> bool {
        self.ownership == Ownership::ControllerClosed
    }

    #[cfg(test)]
    pub(in crate::adapter) fn exit_fault_owners_retained(&mut self) -> bool {
        self.exit_fault_phase_reached()
            && self.folder.is_some()
            && self.identity.is_some()
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.len() == 1)
            && self.native.exit_fault_owners_retained()
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
    pub(in crate::adapter) fn fault_owners_retained(&mut self) -> bool {
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
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::Received)
        {
            return Err(());
        }
        self.inject_view_fault(target, seal, crate::ProcessFaultLifecycle::PostedReceipt)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_posted_empty_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::Empty)
        {
            return Err(());
        }
        self.inject_view_fault(target, seal, crate::ProcessFaultLifecycle::PostedEmpty)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_posted_writing_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::Writing)
        {
            return Err(());
        }
        self.inject_view_fault(target, seal, crate::ProcessFaultLifecycle::PostedWriting)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_posted_ready_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::Ready)
        {
            return Err(());
        }
        self.inject_view_fault(target, seal, crate::ProcessFaultLifecycle::PostedReady)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_posted_retry_fault(
        &self,
        target: crate::ProcessFaultTarget,
        point: crate::RetryPoint,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::Empty)
        {
            return Err(());
        }
        self.inject_view_fault(
            target,
            seal,
            crate::ProcessFaultLifecycle::PostedRetry(point),
        )
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_posted_consuming_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::Consuming)
        {
            return Err(());
        }
        self.inject_view_fault(target, seal, crate::ProcessFaultLifecycle::PostedConsuming)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_releasing_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if ControlState::try_from(self.native.load_state().map_err(|_| ())?).ok()
            != Some(ControlState::ReleaseRequested)
        {
            return Err(());
        }
        self.inject_view_fault(target, seal, crate::ProcessFaultLifecycle::ReleasingSuccess)
    }

    #[cfg(test)]
    fn inject_view_fault(
        &self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
        lifecycle: crate::ProcessFaultLifecycle,
    ) -> std::result::Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
            || self.generation
                != Some(match lifecycle {
                    crate::ProcessFaultLifecycle::PostedRetry(point) => u32::from(point.post()),
                    _ => 1,
                })
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
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target,
            lifecycle,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && !events.invalid()
                    && events.exited().is_none()
            }),
            trace,
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

    #[cfg(test)]
    pub(in crate::adapter) fn release_quarantine_owners_retained(&mut self) -> bool {
        self.ownership == Ownership::ControllerClosed
            && self.close == CloseState::Pending
            && self.folder.is_some()
            && self
                .identity
                .is_some_and(|id| self.events.exited() == Some(id.browser_pid))
            && !self.buffers
            && self.store.records().is_ok_and(|records| records.len() == 1)
    }

    #[cfg(test)]
    pub(in crate::adapter) const fn initial_close_observation(&self) -> Option<CloseObservation> {
        self.initial_close
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
            #[cfg(test)]
            {
                self.recordless_fault = None;
                self.initial_buffer_close = None;
                self.initial_close = None;
                self.exit_capture = None;
            }
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
        let state = self.native.load_state().map_err(unavailable);
        #[cfg(test)]
        if matches!(state.as_ref(), Ok(value) if *value == ControlState::Releasing as u32) {
            self.readiness_timing.releasing();
        }
        state
    }
    fn reply_compare_exchange(&self, current: u32, new: u32) -> Result<bool> {
        let result = self
            .native
            .compare_exchange(current, new)
            .map_err(unavailable);
        #[cfg(test)]
        if new == ControlState::ReleaseRequested as u32 && matches!(result.as_ref(), Ok(true)) {
            self.readiness_timing.cas();
        }
        result
    }
    fn reply_copy(&self, out: &mut ReplyImage) -> Result<()> {
        self.native.copy_reply(out).map_err(unavailable)
    }
    fn zero_close_buffers(&mut self) -> Result<()> {
        let result = self.native.close_buffers().map_err(unavailable);
        #[cfg(test)]
        if self.initial_buffer_close.is_none() {
            self.initial_buffer_close = Some(result.is_ok());
        }
        self.buffers = false;
        result
    }

    fn close_controller(&mut self) -> Result<()> {
        #[cfg(test)]
        self.readiness_timing.close_enter();
        self.close = CloseState::Pending;
        let buffers = self.zero_close_buffers();
        #[cfg(test)]
        self.cleanup_trace.enter("close.unsubscribe_view");
        let removed = self.native.unsubscribe_view();
        #[cfg(test)]
        self.cleanup_trace
            .returned("close.unsubscribe_view", removed);
        #[cfg(test)]
        let observed_removed = removed;
        let removed = removed.map_err(unavailable);
        #[cfg(test)]
        self.capture_before_controller_close();
        #[cfg(test)]
        let had_controller = self.native.has_controller() == Ok(true);
        #[cfg(test)]
        self.cleanup_trace.enter("close.close_controller");
        let closed = self.native.close_controller();
        #[cfg(test)]
        self.readiness_timing.close_return();
        #[cfg(test)]
        self.cleanup_trace
            .returned("close.close_controller", closed);
        #[cfg(test)]
        if self.initial_close.is_none() {
            self.initial_close = Some(CloseObservation {
                removed: observed_removed,
                closed,
                buffers_closed: self.initial_buffer_close == Some(true) && buffers.is_ok(),
                buffers_uncertain: self.native.buffer_close_uncertain(),
                had_controller,
            });
        }
        let closed = closed.map_err(unavailable);
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
        #[cfg(test)]
        self.cleanup_trace.enter("finish.unsubscribe_view");
        let removed = self.native.unsubscribe_view();
        #[cfg(test)]
        self.cleanup_trace
            .returned("finish.unsubscribe_view", removed);
        removed.map_err(unavailable)?;
        #[cfg(test)]
        self.cleanup_trace.enter("finish.unsubscribe_exit");
        let removed = self.native.unsubscribe_exit();
        #[cfg(test)]
        self.cleanup_trace
            .returned("finish.unsubscribe_exit", removed);
        removed.map_err(unavailable)?;
        #[cfg(test)]
        self.cleanup_trace.enter("finish.drop_environment");
        let dropped = self.native.drop_environment();
        #[cfg(test)]
        self.cleanup_trace
            .returned("finish.drop_environment", dropped);
        dropped.map_err(unavailable)?;
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
