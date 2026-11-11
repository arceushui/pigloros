#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use crate::ExitMembershipKind::{Browser, Other};
use crate::{
    BoolProperty, BufferSlot, ClientBounds, EnvironmentOptions, EnvironmentSnapshot, EventSink,
    Failure, NativeError, NativeFactory, NativeOperations, NativePath, NativePulse, NativeResult,
    NativeText, Operation, StaPump, WindowSnapshot,
};
use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::CeremonyKind;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::adapter) enum Creation {
    SynchronousFailure,
    CallbackFailure,
    MissingView,
    Pending,
    Ready,
}

pub(in crate::adapter) struct Factory {
    pub(in crate::adapter) creation: Cell<Creation>,
    pub(super) environment_creation: Cell<Creation>,
    pub(super) environment_completions: Cell<u32>,
    pub(super) controller_completions: Cell<u32>,
    pub(in crate::adapter) calls: RefCell<Vec<&'static str>>,
    pub(in crate::adapter) sink: RefCell<Option<Rc<dyn EventSink>>>,
    pub(super) foreground: Cell<bool>,
    pub(in crate::adapter) navigation_succeeds: Cell<bool>,
    pub(in crate::adapter) failure: Cell<Option<&'static str>>,
    pub(super) mismatched_setting: Cell<Option<BoolProperty>>,
    pub(super) source: RefCell<String>,
    pub(super) state: Cell<u32>,
    pub(super) invalidate_request: Cell<bool>,
    pub(super) close_uncertain: Cell<bool>,
    pub(super) dpi: Cell<u32>,
    pub(super) window_exists: Cell<bool>,
    pub(super) close_requested: Cell<bool>,
    pub(super) exit_code: Cell<Option<u32>>,
    pub(super) preload_owners: Cell<bool>,
    pub(super) renderer_presence: Cell<Option<crate::RendererPresence>>,
    pub(in crate::adapter) pending_browser: Cell<Option<pos_owner_bridge::ProcessIdentity>>,
    pub(super) client: Cell<ClientBounds>,
    clock: FakeClock,
}

impl Factory {
    pub(in crate::adapter) fn new(creation: Creation, clock: FakeClock) -> Rc<Self> {
        Rc::new(Self {
            creation: Cell::new(creation),
            environment_creation: Cell::new(Creation::Ready),
            environment_completions: Cell::new(0),
            controller_completions: Cell::new(0),
            calls: RefCell::new(Vec::new()),
            sink: RefCell::new(None),
            foreground: Cell::new(true),
            navigation_succeeds: Cell::new(false),
            failure: Cell::new(None),
            mismatched_setting: Cell::new(None),
            source: RefCell::new(crate::OWNER_URL.to_owned()),
            state: Cell::new(0),
            invalidate_request: Cell::new(false),
            close_uncertain: Cell::new(false),
            dpi: Cell::new(96),
            window_exists: Cell::new(true),
            close_requested: Cell::new(false),
            exit_code: Cell::new(None),
            preload_owners: Cell::new(false),
            renderer_presence: Cell::new(None),
            pending_browser: Cell::new(None),
            client: Cell::new(ClientBounds {
                left: 0,
                top: 0,
                right: 480,
                bottom: 640,
            }),
            clock,
        })
    }
}

impl StaPump for Rc<Factory> {
    fn next(&self) -> NativeResult<NativePulse> {
        if self.failure.get() == Some("pump") {
            return Err(NativeError {
                operation: Operation::Sta,
                failure: Failure::CallFailed,
            });
        }
        if self.creation.get() == Creation::Pending
            && self.calls.borrow().contains(&"create_controller")
        {
            self.clock.advance(Duration::from_secs(31));
        }
        Ok(NativePulse::Timer)
    }
    fn stop(&mut self) -> NativeResult<()> {
        Ok(())
    }
}

impl NativeFactory for Rc<Factory> {
    fn session(&self) -> NativeResult<Box<dyn NativeOperations>> {
        if self.failure.get() == Some("session") {
            return Err(failed());
        }
        Ok(Box::new(Session {
            factory: Self::clone(self),
            folder: PathBuf::new(),
            environment_pending: false,
            controller_pending: false,
            controller: false,
        }))
    }
}

struct Session {
    factory: Rc<Factory>,
    folder: PathBuf,
    environment_pending: bool,
    controller_pending: bool,
    controller: bool,
}

struct ExitHandle {
    factory: Rc<Factory>,
    identity: pos_owner_bridge::ProcessIdentity,
}

impl crate::ProcessFaultHandle for ExitHandle {
    fn identity(&self) -> pos_owner_bridge::ProcessIdentity {
        self.identity
    }
    fn exit_code(&self) -> Result<Option<u32>, ()> {
        if self.factory.failure.get() == Some("exit_final_query") {
            Err(())
        } else {
            Ok(self.factory.exit_code.get())
        }
    }
}

impl crate::RetainedExitHandle for ExitHandle {
    fn identity(&self) -> pos_owner_bridge::ProcessIdentity {
        self.identity
    }
    fn observe(&self) -> Result<Option<u32>, ()> {
        if self.factory.failure.get() == Some("exit_observation") {
            Err(())
        } else {
            Ok(self.factory.exit_code.get())
        }
    }
    fn terminate(&mut self, authority: &crate::FaultAuthority) -> Result<(), ()> {
        if !authority.valid() || self.factory.exit_code.get().is_some() {
            return Err(());
        }
        self.factory.calls.borrow_mut().push("terminate_exit");
        self.factory.exit_code.set(Some(0x535));
        Ok(())
    }
    fn into_fault(self: Box<Self>) -> Box<dyn crate::ProcessFaultHandle> {
        self
    }
}

impl Session {
    fn call(&self, name: &'static str) {
        self.factory.calls.borrow_mut().push(name);
    }
    fn check(&self, name: &'static str) -> NativeResult<()> {
        if self.factory.failure.get() == Some(name) {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn effect(&self, name: &'static str) -> NativeResult<()> {
        self.call(name);
        self.check(name)
    }
}

impl NativeOperations for Session {
    fn preload_fault_owners_retained(&self) -> bool {
        self.controller
            && self.factory.preload_owners.get()
            && self.factory.sink.borrow().is_some()
            && self.factory.failure.get() != Some("preload-owner")
    }

    fn early_renderer_presence(&self) -> Result<crate::RendererPresence, ()> {
        self.check("early_renderer_presence").map_err(|_| ())?;
        self.factory.renderer_presence.get().ok_or(())
    }

    fn retained_exit_membership(&self, handle: &dyn crate::RetainedExitHandle) -> Result<(), ()> {
        if self.controller
            || self.factory.failure.get() == Some("exit_membership")
            || handle.identity().browser_pid != 42
        {
            return Err(());
        }
        let entries = match self.factory.failure.get() {
            Some("exit_membership_missing") => vec![(41, Other)],
            Some("exit_membership_malformed") => vec![(42, Browser), (42, Other)],
            Some("exit_membership_empty") => Vec::new(),
            _ => vec![(42, Browser)],
        };
        crate::retained_exit_membership(&entries, handle.identity().browser_pid)
    }

    fn retain_exit_browser(
        &self,
        authority: &crate::FaultAuthority,
    ) -> Result<Box<dyn crate::RetainedExitHandle>, ()> {
        if !self.controller
            || !authority.valid()
            || self.factory.failure.get() == Some("retain_exit")
            || self.factory.exit_code.get().is_some()
        {
            return Err(());
        }
        let mut identity = authority.browser();
        if self.factory.failure.get() == Some("mismatched_exit_handle") {
            identity.creation_filetime += 1;
        }
        Ok(Box::new(ExitHandle {
            factory: Rc::clone(&self.factory),
            identity,
        }))
    }
    fn exit_fault_owners_retained(&self) -> bool {
        self.factory.sink.borrow().is_some()
            && !self.controller
            && self.factory.failure.get() != Some("exit_owners")
    }

    fn pending_opening_owners_retained(&self) -> bool {
        self.controller_pending
            && self.factory.failure.get() != Some("pending-owner")
            && (self.factory.failure.get() != Some("pending-owner-after")
                || !self.factory.calls.borrow().contains(&"pending_candidate"))
    }

    fn pending_opening_browser_candidate(
        &self,
    ) -> Result<Option<pos_owner_bridge::ProcessIdentity>, ()> {
        self.call("pending_candidate");
        self.check("pending_candidate").map_err(|_| ())?;
        Ok(self.factory.pending_browser.get())
    }

    fn recordless_controller_completion(&self) -> Option<bool> {
        (self.factory.failure.get() == Some("pending-callback-after")
            && self.factory.calls.borrow().contains(&"pending_candidate"))
        .then_some(true)
    }

    fn create_window(&mut self, _: Option<u64>, _: u32, _: u32) -> NativeResult<()> {
        self.effect("create_window")
    }
    fn window(&self) -> NativeResult<WindowSnapshot> {
        self.check("window")?;
        Ok(WindowSnapshot {
            exists: self.factory.window_exists.get(),
            close_requested: self.factory.close_requested.get(),
            dpi: self.factory.dpi.get(),
            client: self.factory.client.get(),
            foreground: self.factory.foreground.get(),
        })
    }
    fn resize_window(&self, _: u32, _: u32, _: u32) -> NativeResult<()> {
        self.effect("resize_window")
    }
    fn show_window(&self) -> NativeResult<()> {
        self.effect("show_window")
    }
    fn fit_controller(&self) -> NativeResult<()> {
        self.effect("fit_controller")
    }
    fn focus_controller(&self) -> NativeResult<()> {
        self.effect("focus_controller")
    }
    fn create_environment(
        &mut self,
        _: &Path,
        folder: &Path,
        _: EnvironmentOptions,
        sink: Rc<dyn EventSink>,
    ) -> NativeResult<()> {
        self.effect("create_environment")?;
        self.folder = folder.to_owned();
        *self.factory.sink.borrow_mut() = Some(sink);
        self.environment_pending = true;
        Ok(())
    }
    fn environment_completion(&mut self) -> Option<NativeResult<()>> {
        if self.factory.environment_creation.get() == Creation::Pending
            || !std::mem::take(&mut self.environment_pending)
        {
            return None;
        }
        self.factory
            .environment_completions
            .set(self.factory.environment_completions.get().saturating_add(1));
        Some(
            if self.factory.environment_creation.get() == Creation::CallbackFailure {
                Err(failed())
            } else {
                Ok(())
            },
        )
    }
    fn environment(&self) -> NativeResult<EnvironmentSnapshot> {
        self.check("environment")?;
        Ok(EnvironmentSnapshot {
            version: NativeText::fixture("153.0.4234.48"),
            folder: NativePath::from_utf16(
                &self.folder.as_os_str().encode_wide().collect::<Vec<_>>(),
            )?,
            arguments: NativeText::fixture(""),
            options: super::super::super::settings::OPTIONS,
        })
    }
    fn create_controller(&mut self) -> NativeResult<()> {
        self.call("create_controller");
        if self.factory.creation.get() == Creation::SynchronousFailure {
            return Err(failed());
        }
        self.controller_pending = true;
        Ok(())
    }
    fn controller_completion(&mut self) -> Option<NativeResult<()>> {
        if self.factory.creation.get() == Creation::Pending {
            return None;
        }
        if !std::mem::take(&mut self.controller_pending) {
            return None;
        }
        self.factory
            .controller_completions
            .set(self.factory.controller_completions.get().saturating_add(1));
        let creation = self.factory.creation.get();
        self.controller = creation != Creation::CallbackFailure;
        Some(if creation == Creation::Ready {
            Ok(())
        } else {
            Err(failed())
        })
    }
    fn has_controller(&self) -> NativeResult<bool> {
        Ok(self.controller)
    }
    fn browser_pid(&self) -> NativeResult<u32> {
        if self.factory.creation.get() == Creation::MissingView {
            Err(failed())
        } else {
            Ok(42)
        }
    }
    fn require_shared_interfaces(&mut self) -> NativeResult<()> {
        self.effect("require_shared_interfaces")
    }
    fn subscribe_view(&mut self, _: Rc<dyn EventSink>) -> NativeResult<()> {
        self.effect("subscribe_view")
    }
    fn set_bool(&self, _: BoolProperty, _: bool) -> NativeResult<()> {
        self.check("set_bool")
    }
    fn get_bool(&self, property: BoolProperty) -> NativeResult<bool> {
        self.check("get_bool")?;
        Ok((property == BoolProperty::Script)
            != (self.factory.mismatched_setting.get() == Some(property)))
    }
    fn navigate_owner(&self) -> NativeResult<()> {
        self.call("navigate");
        if self.factory.navigation_succeeds.get() {
            Ok(())
        } else {
            Err(failed())
        }
    }
    fn source(&self) -> NativeResult<NativeText> {
        self.check("source")?;
        Ok(NativeText::fixture(&self.factory.source.borrow()))
    }
    fn create_buffers(&mut self, _: CeremonyKind, _: &[u8], _: &[u8; 64]) -> NativeResult<()> {
        self.effect("create_buffers")
    }
    fn post(&self, slot: BufferSlot) -> NativeResult<()> {
        self.call("post");
        self.effect(match slot {
            BufferSlot::Request => "post_request",
            BufferSlot::Reply => "post_reply",
        })?;
        if slot == BufferSlot::Request && self.factory.invalidate_request.get() {
            if let Some(sink) = self.factory.sink.borrow().as_ref() {
                sink.event(crate::NativeEvent::ProcessFailed);
            }
        }
        Ok(())
    }
    fn load_state(&self) -> NativeResult<u32> {
        self.check("load_state")?;
        Ok(self.factory.state.get())
    }
    fn compare_exchange(&self, current: u32, new: u32) -> NativeResult<bool> {
        self.check("compare_exchange")?;
        let matched = self.factory.state.get() == current;
        if matched {
            self.factory.state.set(new);
        }
        Ok(matched)
    }
    fn copy_reply(&self, out: &mut ReplyImage) -> NativeResult<()> {
        self.check("copy_reply")?;
        out.as_mut_bytes().fill(0x5a);
        Ok(())
    }
    fn close_buffers(&mut self) -> NativeResult<()> {
        self.effect("close_buffers")
    }
    fn buffer_close_uncertain(&self) -> bool {
        self.factory.close_uncertain.get()
    }
    fn unsubscribe_view(&mut self) -> NativeResult<()> {
        self.effect("unsubscribe_view")
    }
    fn close_controller(&mut self) -> NativeResult<()> {
        self.effect("close_controller")?;
        self.controller = false;
        self.factory.exit_code.set(Some(0));
        Ok(())
    }
    fn unsubscribe_exit(&mut self) -> NativeResult<()> {
        self.effect("unsubscribe_exit")
    }
    fn drop_environment(&mut self) -> NativeResult<()> {
        self.effect("drop_environment")
    }
    fn destroy_window(&mut self) -> NativeResult<()> {
        self.effect("destroy_window")
    }
    fn pending(&self) -> bool {
        self.environment_pending || self.controller_pending
    }
}

const fn failed() -> NativeError {
    NativeError {
        operation: Operation::Controller,
        failure: Failure::CallFailed,
    }
}
