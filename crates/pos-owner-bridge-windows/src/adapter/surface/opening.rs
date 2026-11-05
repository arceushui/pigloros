#![cfg(windows)]
#![forbid(unsafe_code)]

use super::super::settings;
use super::{lost, unavailable, Ownership, Result, Surface, HEIGHT, WIDTH};
use crate::{EventSink, NativePulse};
use pos_owner_bridge::{
    folder_name, BridgeError, LifecycleCode, ProcessIdentity, SurfaceError, SurfaceSpec,
    UnavailableCode,
};
use std::time::Duration;

impl Surface {
    pub(super) fn open_native(&mut self, spec: &SurfaceSpec) -> Result<ProcessIdentity> {
        self.before_deadline()?;
        if spec.folder_name != folder_name(&spec.ceremony_id) {
            return Err(unavailable(()));
        }
        let path = self.root.join(&spec.folder_name);
        crate::create_private_directory(&path).map_err(SurfaceError::new)?;
        self.folder = Some(spec.folder_name.clone());
        self.ownership = Ownership::Folder;
        self.native
            .create_window(spec.owner_window, WIDTH, HEIGHT)
            .map_err(unavailable)?;
        self.ownership = Ownership::Window;
        let sink: std::rc::Rc<dyn EventSink> = self.events.clone();
        self.ownership = Ownership::CreatingEnvironment;
        self.native
            .create_environment(self.runtime.root(), &path, settings::OPTIONS, sink)
            .map_err(unavailable)?;
        self.await_environment()?;
        self.ownership = Ownership::Environment;
        self.admit_environment(&path)?;
        self.ownership = Ownership::CreatingController;
        self.native.create_controller().map_err(unavailable)?;
        self.await_controller()?;
        self.ownership = Ownership::Controller;
        let identity = self.observe_controller()?;
        // The portable driver records this complete identity before navigate
        // reports a later activation failure. No navigation or buffer can occur
        // when the required settings, capabilities or foreground did not pass.
        self.activation_error = self.prepare_controller().err();
        Ok(identity)
    }

    fn admit_environment(&self, folder: &std::path::Path) -> Result<()> {
        let snapshot = self.native.environment().map_err(unavailable)?;
        settings::verify_options(&snapshot)?;
        if snapshot.version.as_str() != "153.0.4234.48"
            || !snapshot.folder.as_path().is_absolute()
            || snapshot
                .folder
                .as_path()
                .canonicalize()
                .map_err(|_| integrity())?
                != folder.canonicalize().map_err(|_| integrity())?
        {
            return Err(integrity());
        }
        Ok(())
    }

    pub(super) fn observe_controller(&mut self) -> Result<ProcessIdentity> {
        let pid = self.native.browser_pid().map_err(unavailable)?;
        let identity = self.runtime.identity(pid).map_err(SurfaceError::new)?;
        self.events.expect_browser(identity.browser_pid);
        self.identity = Some(identity);
        Ok(identity)
    }

    fn prepare_controller(&mut self) -> Result<()> {
        self.native
            .require_shared_interfaces()
            .map_err(unavailable)?;
        let sink: std::rc::Rc<dyn EventSink> = self.events.clone();
        self.native.subscribe_view(sink).map_err(unavailable)?;
        settings::apply(self.native.as_ref())?;
        self.native.fit_controller().map_err(unavailable)?;
        self.native.show_window().map_err(unavailable)?;
        self.native.focus_controller().map_err(unavailable)?;
        let focus_deadline = (self.clock.now() + Duration::from_secs(1)).min(self.deadline);
        while !self.native.window().map_err(unavailable)?.foreground {
            if self.clock.now() >= focus_deadline {
                return Err(SurfaceError::new(BridgeError::Lifecycle(
                    LifecycleCode::ForegroundUnavailable,
                )));
            }
            self.pulse()?;
        }
        Ok(())
    }

    fn await_environment(&mut self) -> Result<()> {
        loop {
            if let Some(result) = self.native.environment_completion() {
                return result.map_err(unavailable);
            }
            self.pulse()?;
        }
    }

    fn await_controller(&mut self) -> Result<()> {
        loop {
            if let Some(result) = self.native.controller_completion() {
                return result.map_err(unavailable);
            }
            self.pulse()?;
        }
    }

    pub(super) fn pulse(&self) -> Result<()> {
        self.before_deadline()?;
        if self.factory.next().map_err(unavailable)? == NativePulse::Quit {
            return Err(lost());
        }
        self.refresh()
    }

    pub(super) fn before_deadline(&self) -> Result<()> {
        if self.clock.now() >= self.deadline {
            Err(SurfaceError::new(BridgeError::Lifecycle(
                LifecycleCode::ReadinessTimeout,
            )))
        } else {
            Ok(())
        }
    }
}

const fn integrity() -> SurfaceError {
    SurfaceError::new(BridgeError::Unavailable(UnavailableCode::RuntimeIntegrity))
}
