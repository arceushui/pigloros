#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use crate::{
    BoolProperty, BufferSlot, ClientBounds, EnvironmentOptions, EnvironmentSnapshot, EventSink,
    Failure, NativeError, NativeFactory, NativeOperations, NativePath, NativePulse, NativeResult,
    NativeText, Operation, StaPump, WindowSnapshot,
};
use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::CeremonyKind;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Creation {
    SynchronousFailure,
    CallbackFailure,
    MissingView,
    Pending,
    Ready,
}

pub(super) struct Factory {
    pub(super) creation: Cell<Creation>,
    pub(super) calls: RefCell<Vec<&'static str>>,
    pub(super) sink: RefCell<Option<Rc<dyn EventSink>>>,
    pub(super) foreground: Cell<bool>,
    pub(super) navigation_succeeds: Cell<bool>,
    clock: FakeClock,
}

impl Factory {
    pub(super) fn new(creation: Creation, clock: FakeClock) -> Rc<Self> {
        Rc::new(Self {
            creation: Cell::new(creation),
            calls: RefCell::new(Vec::new()),
            sink: RefCell::new(None),
            foreground: Cell::new(true),
            navigation_succeeds: Cell::new(false),
            clock,
        })
    }
}

impl StaPump for Rc<Factory> {
    fn next(&self) -> NativeResult<NativePulse> {
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

impl Session {
    fn call(&self, name: &'static str) {
        self.factory.calls.borrow_mut().push(name);
    }
}

impl NativeOperations for Session {
    fn create_window(&mut self, _: Option<u64>, _: u32, _: u32) -> NativeResult<()> {
        self.call("create_window");
        Ok(())
    }
    fn window(&self) -> NativeResult<WindowSnapshot> {
        Ok(WindowSnapshot {
            exists: true,
            close_requested: false,
            dpi: 96,
            client: ClientBounds {
                left: 0,
                top: 0,
                right: 480,
                bottom: 640,
            },
            foreground: self.factory.foreground.get(),
        })
    }
    fn resize_window(&self, _: u32, _: u32, _: u32) -> NativeResult<()> {
        Ok(())
    }
    fn show_window(&self) -> NativeResult<()> {
        Ok(())
    }
    fn fit_controller(&self) -> NativeResult<()> {
        Ok(())
    }
    fn focus_controller(&self) -> NativeResult<()> {
        Ok(())
    }
    fn create_environment(
        &mut self,
        _: &Path,
        folder: &Path,
        _: EnvironmentOptions,
        sink: Rc<dyn EventSink>,
    ) -> NativeResult<()> {
        self.call("create_environment");
        self.folder = folder.to_owned();
        *self.factory.sink.borrow_mut() = Some(sink);
        self.environment_pending = true;
        Ok(())
    }
    fn environment_completion(&mut self) -> Option<NativeResult<()>> {
        std::mem::take(&mut self.environment_pending).then_some(Ok(()))
    }
    fn environment(&self) -> NativeResult<EnvironmentSnapshot> {
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
        Ok(())
    }
    fn subscribe_view(&mut self, _: Rc<dyn EventSink>) -> NativeResult<()> {
        Ok(())
    }
    fn set_bool(&self, _: BoolProperty, _: bool) -> NativeResult<()> {
        Ok(())
    }
    fn get_bool(&self, property: BoolProperty) -> NativeResult<bool> {
        Ok(property == BoolProperty::Script)
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
        Err(failed())
    }
    fn create_buffers(&mut self, _: CeremonyKind, _: &[u8], _: &[u8; 64]) -> NativeResult<()> {
        self.call("create_buffers");
        Err(failed())
    }
    fn post(&self, _: BufferSlot) -> NativeResult<()> {
        self.call("post");
        Err(failed())
    }
    fn load_state(&self) -> NativeResult<u32> {
        Err(failed())
    }
    fn compare_exchange(&self, _: u32, _: u32) -> NativeResult<bool> {
        Err(failed())
    }
    fn copy_reply(&self, _: &mut ReplyImage) -> NativeResult<()> {
        Err(failed())
    }
    fn close_buffers(&mut self) -> NativeResult<()> {
        self.call("close_buffers");
        Ok(())
    }
    fn buffer_close_uncertain(&self) -> bool {
        false
    }
    fn unsubscribe_view(&mut self) -> NativeResult<()> {
        self.call("unsubscribe_view");
        Ok(())
    }
    fn close_controller(&mut self) -> NativeResult<()> {
        self.call("close_controller");
        self.controller = false;
        Ok(())
    }
    fn unsubscribe_exit(&mut self) -> NativeResult<()> {
        self.call("unsubscribe_exit");
        Ok(())
    }
    fn drop_environment(&mut self) -> NativeResult<()> {
        self.call("drop_environment");
        Ok(())
    }
    fn destroy_window(&mut self) -> NativeResult<()> {
        self.call("destroy_window");
        Ok(())
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
