#![cfg(windows)]

use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;

use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::CeremonyKind;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Controller, ICoreWebView2_17,
    COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC,
};
use windows::core::{w, Interface};

use crate::native_api::{
    BoolProperty, BufferSlot, EnvironmentOptions, EnvironmentSnapshot, EventSink, Failure,
    NativeError, NativeFactory, NativeOperations, NativePulse, NativeResult, NativeText, Operation,
    StaPump, WindowSnapshot,
};

use super::{buffers::Pair, creation, environment::Environment, events, pump, settings, window};

struct Factory(pump::Pump);

impl crate::Native {
    pub(crate) fn owner_factory() -> NativeResult<impl NativeFactory> {
        Factory::new()
    }
}

impl Factory {
    pub(super) fn new() -> NativeResult<Self> {
        window::prepare_class().and_then(|()| pump::Pump::new().map(Self))
    }
}

impl StaPump for Factory {
    fn next(&self) -> NativeResult<NativePulse> {
        self.0.next()
    }
    fn stop(&mut self) -> NativeResult<()> {
        self.0.stop_timer()
    }
}

impl NativeFactory for Factory {
    fn session(&self) -> NativeResult<Box<dyn NativeOperations>> {
        self.0.token.check()?;
        Ok(Box::new(Session {
            window: None,
            environment_creation: None,
            controller_creation: None,
            environment: None,
            controller: None,
            view: None,
            shared: None,
            subscriptions: events::Subscriptions::default(),
            buffers: None,
            close_uncertain: Rc::new(Cell::new(false)),
            sink: None,
            token: Rc::clone(&self.0.token),
        }))
    }
}

struct Session {
    window: Option<window::Window>,
    environment_creation: Option<creation::EnvironmentCreation>,
    controller_creation: Option<creation::ControllerCreation>,
    environment: Option<Environment>,
    controller: Option<ICoreWebView2Controller>,
    view: Option<ICoreWebView2>,
    shared: Option<ICoreWebView2_17>,
    subscriptions: events::Subscriptions,
    buffers: Option<Pair>,
    close_uncertain: Rc<Cell<bool>>,
    sink: Option<Rc<dyn EventSink>>,
    // Last field: the apartment remains initialized through every COM release.
    token: Rc<pump::StaToken>,
}

impl Session {
    fn check(&self) -> NativeResult<()> {
        self.token.check()
    }
    fn window_ref(&self) -> NativeResult<&window::Window> {
        self.check()?;
        self.window.as_ref().ok_or_else(closed)
    }
    fn environment_ref(&self) -> NativeResult<&Environment> {
        self.check()?;
        self.environment.as_ref().ok_or_else(closed)
    }
    fn controller_ref(&self) -> NativeResult<&ICoreWebView2Controller> {
        self.check()?;
        self.controller.as_ref().ok_or_else(closed)
    }
    fn view_ref(&self) -> NativeResult<&ICoreWebView2> {
        self.check()?;
        self.view.as_ref().ok_or_else(closed)
    }
    fn pair(&self) -> NativeResult<&Pair> {
        self.check()?;
        self.buffers.as_ref().ok_or_else(closed)
    }
}

impl NativeOperations for Session {
    fn create_window(&mut self, owner: Option<u64>, width: u32, height: u32) -> NativeResult<()> {
        self.check()?;
        if self.window.is_some() {
            return Err(closed());
        }
        self.window = Some(window::Window::create(owner, width, height)?);
        Ok(())
    }
    fn window(&self) -> NativeResult<WindowSnapshot> {
        self.window_ref()?.snapshot()
    }
    fn resize_window(&self, width: u32, height: u32, dpi: u32) -> NativeResult<()> {
        self.window_ref()?.resize(width, height, dpi)
    }
    fn show_window(&self) -> NativeResult<()> {
        self.window_ref()?.show();
        Ok(())
    }
    fn fit_controller(&self) -> NativeResult<()> {
        let bounds = self.window_ref()?.bounds()?;
        let controller = self.controller_ref()?;
        // SAFETY: retained creating-STA controller and copied initialized client RECT.
        unsafe { controller.SetBounds(bounds) }.map_err(failed)
    }
    fn focus_controller(&self) -> NativeResult<()> {
        let controller = self.controller_ref()?;
        // SAFETY: retained creating-STA controller; fixed programmatic focus reason.
        unsafe { controller.MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC) }.map_err(failed)
    }

    fn create_environment(
        &mut self,
        runtime: &Path,
        folder: &Path,
        options: EnvironmentOptions,
        sink: Rc<dyn EventSink>,
    ) -> NativeResult<()> {
        self.check()?;
        if self.environment.is_some() || self.environment_creation.is_some() {
            return Err(closed());
        }
        self.environment_creation = Some(creation::EnvironmentCreation::start(
            runtime, folder, options,
        )?);
        self.sink = Some(sink);
        Ok(())
    }
    fn environment_completion(&mut self) -> Option<NativeResult<()>> {
        if let Err(error) = self.check() {
            return Some(Err(error));
        }
        let creation = self.environment_creation.as_ref()?;
        let completed = creation.take()?;
        let options = creation.options.clone();
        self.environment_creation = None;
        Some(completed.and_then(|raw| {
            let sink = self.sink.as_ref().ok_or_else(closed)?;
            self.environment = Some(Environment::subscribe(raw, options, sink)?);
            Ok(())
        }))
    }
    fn environment(&self) -> NativeResult<EnvironmentSnapshot> {
        self.environment_ref()?.snapshot()
    }
    fn create_controller(&mut self) -> NativeResult<()> {
        self.check()?;
        if self.controller.is_some() || self.controller_creation.is_some() {
            return Err(closed());
        }
        let creation = creation::ControllerCreation::start(
            &self.environment_ref()?.raw,
            self.window_ref()?.handle(),
        )?;
        self.controller_creation = Some(creation);
        Ok(())
    }
    fn controller_completion(&mut self) -> Option<NativeResult<()>> {
        if let Err(error) = self.check() {
            return Some(Err(error));
        }
        let completed = self.controller_creation.as_ref()?.take()?;
        self.controller_creation = None;
        Some(completed.and_then(|controller| {
            self.controller = Some(controller);
            let controller = self.controller_ref()?;
            // SAFETY: successfully completed retained controller on its creating STA.
            self.view = Some(unsafe { controller.CoreWebView2() }.map_err(failed)?);
            Ok(())
        }))
    }
    fn has_controller(&self) -> NativeResult<bool> {
        self.check().map(|()| self.controller.is_some())
    }

    fn browser_pid(&self) -> NativeResult<u32> {
        let view = self.view_ref()?;
        let mut pid = 0;
        // SAFETY: retained creating-STA view and initialized unique PID output.
        unsafe { view.BrowserProcessId(&raw mut pid) }.map_err(failed)?;
        Ok(pid)
    }
    fn require_shared_interfaces(&mut self) -> NativeResult<()> {
        let _environment = self.environment_ref()?.shared()?;
        self.shared = Some(self.view_ref()?.cast().map_err(failed)?);
        Ok(())
    }
    fn subscribe_view(&mut self, sink: Rc<dyn EventSink>) -> NativeResult<()> {
        let view = self.view_ref()?.clone();
        let environment = self.environment_ref()?.raw.clone();
        events::install(&view, &environment, &sink, &mut self.subscriptions)
    }
    fn set_bool(&self, property: BoolProperty, value: bool) -> NativeResult<()> {
        settings::set_bool(self.view_ref()?, self.controller_ref()?, property, value)
    }
    fn get_bool(&self, property: BoolProperty) -> NativeResult<bool> {
        settings::get_bool(self.view_ref()?, self.controller_ref()?, property)
    }
    fn navigate_owner(&self) -> NativeResult<()> {
        let view = self.view_ref()?;
        // SAFETY: retained creating-STA view and the fixed packaged owner document URL.
        unsafe { view.Navigate(w!("http://localhost:49291/owner.html")) }.map_err(failed)
    }
    fn source(&self) -> NativeResult<NativeText> {
        events::source(self.view_ref()?)
    }
    fn create_buffers(
        &mut self,
        kind: CeremonyKind,
        request: &[u8],
        header: &[u8; 64],
    ) -> NativeResult<()> {
        self.check()?;
        if self.buffers.is_some() || self.close_uncertain.get() {
            return Err(closed());
        }
        let environment = self.environment_ref()?.shared()?;
        self.buffers = Some(Pair::new(
            &environment,
            kind,
            request,
            header,
            Rc::clone(&self.close_uncertain),
        )?);
        Ok(())
    }
    fn post(&self, slot: BufferSlot) -> NativeResult<()> {
        self.check()?;
        let view = self.shared.as_ref().ok_or_else(closed)?;
        let pair = self.pair()?;
        match slot {
            BufferSlot::Request => pair.post_request(view),
            BufferSlot::Reply => pair.post_reply(view),
        }
    }
    fn load_state(&self) -> NativeResult<u32> {
        self.pair()?.load_state()
    }
    fn compare_exchange(&self, current: u32, new: u32) -> NativeResult<bool> {
        self.pair()?.compare_exchange(current, new)
    }
    fn copy_reply(&self, out: &mut ReplyImage) -> NativeResult<()> {
        self.pair()?.copy_reply(out)
    }
    fn close_buffers(&mut self) -> NativeResult<()> {
        self.check()?;
        self.buffers.take().map_or(Ok(()), |mut pair| pair.close())
    }
    fn buffer_close_uncertain(&self) -> bool {
        self.check().is_err() || self.close_uncertain.get()
    }
    fn unsubscribe_view(&mut self) -> NativeResult<()> {
        self.check()?;
        self.subscriptions.close()
    }
    fn close_controller(&mut self) -> NativeResult<()> {
        self.check()?;
        if let Some(controller) = &self.controller {
            // SAFETY: retained creating-STA controller; all buffer borrows ended.
            // Failure retains the COM owner so the safe policy can quarantine/retry.
            unsafe { controller.Close() }.map_err(failed)?;
            self.shared = None;
            self.view = None;
            self.controller = None;
        }
        Ok(())
    }
    fn unsubscribe_exit(&mut self) -> NativeResult<()> {
        self.check()?;
        self.environment
            .as_mut()
            .map_or(Ok(()), Environment::unsubscribe)
    }
    fn drop_environment(&mut self) -> NativeResult<()> {
        self.check()?;
        if self.pending()
            || self.buffers.is_some()
            || self
                .environment
                .as_ref()
                .is_some_and(Environment::subscribed)
        {
            return Err(closed());
        }
        // The safe surface authorizes this operation only after its exact
        // environment exit, or before any controller request was issued.
        // A failed earlier Close can leave disconnected COM owners; releasing
        // them here must not require that failed HRESULT to become successful.
        self.shared = None;
        self.view = None;
        self.controller = None;
        self.environment = None;
        self.sink = None;
        Ok(())
    }
    fn destroy_window(&mut self) -> NativeResult<()> {
        self.check()?;
        if self.pending() || self.controller.is_some() {
            return Err(closed());
        }
        if let Some(window) = &mut self.window {
            window.destroy()?;
        }
        self.window = None;
        Ok(())
    }
    fn pending(&self) -> bool {
        self.check().is_err()
            || self.environment_creation.is_some()
            || self.controller_creation.is_some()
    }
}

fn failed(_: windows::core::Error) -> NativeError {
    NativeError {
        operation: Operation::Controller,
        failure: Failure::CallFailed,
    }
}
const fn closed() -> NativeError {
    NativeError {
        operation: Operation::Controller,
        failure: Failure::Closed,
    }
}
