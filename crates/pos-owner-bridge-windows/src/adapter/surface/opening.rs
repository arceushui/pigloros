#![cfg(windows)]
#![forbid(unsafe_code)]

use super::super::settings;
use super::{unavailable, Ownership, Result, Surface, HEIGHT, WIDTH};
use crate::EventSink;
use pos_owner_bridge::{
    folder_name, BridgeError, LifecycleCode, ProcessIdentity, SurfaceError, SurfaceSpec,
    UnavailableCode,
};
use std::task::Poll;
use std::time::Duration;

impl Surface {
    pub(super) fn open_native(&mut self, spec: &SurfaceSpec) -> Result<Poll<ProcessIdentity>> {
        self.before_deadline()?;
        match self.ownership {
            Ownership::Idle => self.start_opening(spec),
            Ownership::CreatingEnvironment => self.poll_environment(),
            Ownership::CreatingController => self.poll_controller(),
            _ => Err(unavailable(())),
        }
    }

    fn start_opening(&mut self, spec: &SurfaceSpec) -> Result<Poll<ProcessIdentity>> {
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
        Ok(Poll::Pending)
    }

    fn poll_environment(&mut self) -> Result<Poll<ProcessIdentity>> {
        let Some(completion) = self.native.environment_completion() else {
            return Ok(Poll::Pending);
        };
        self.ownership = Ownership::Environment;
        completion.map_err(unavailable)?;
        let folder = self.folder.as_ref().ok_or_else(|| unavailable(()))?;
        self.admit_environment(&self.root.join(folder))?;
        self.ownership = Ownership::CreatingController;
        self.native.create_controller().map_err(unavailable)?;
        Ok(Poll::Pending)
    }

    fn poll_controller(&mut self) -> Result<Poll<ProcessIdentity>> {
        let Some(completion) = self.native.controller_completion() else {
            return Ok(Poll::Pending);
        };
        completion.map_err(unavailable)?;
        self.ownership = Ownership::Controller;
        let identity = self.observe_controller()?;
        // The portable driver records this complete identity before navigate
        // reports a later activation failure. No navigation or buffer can occur
        // when the required settings, capabilities or foreground did not pass.
        self.activation_error = self.prepare_controller().err();
        Ok(Poll::Ready(identity))
    }

    pub(super) fn admit_environment(&self, folder: &std::path::Path) -> Result<()> {
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
        Ok(())
    }

    fn activate_controller(&mut self) -> Result<()> {
        self.foreground_deadline =
            Some((self.clock.now() + Duration::from_secs(1)).min(self.deadline));
        self.native.show_window().map_err(unavailable)?;
        {
            #[cfg(test)]
            let _duration = crate::Native::readiness_span("focus");
            self.native.focus_controller().map_err(unavailable)?;
        }
        Ok(())
    }

    pub(super) fn navigate_native(&mut self) -> Result<Poll<pos_owner_bridge::NavigationId>> {
        if let Some(error) = self.activation_error {
            return Err(error);
        }
        self.refresh()?;
        self.before_deadline()?;
        if self.events.invalid() {
            return Err(super::navigation_lost());
        }
        if !self.navigation_issued {
            if self.foreground_deadline.is_none() {
                if let Err(error) = self.activate_controller() {
                    self.activation_error = Some(error);
                    return Err(error);
                }
            }
            let deadline = self.foreground_deadline.ok_or_else(|| unavailable(()))?;
            self.check_foreground_deadline(deadline)?;
            let foreground = self.native.window().map_err(unavailable)?.foreground;
            self.check_foreground_deadline(deadline)?;
            if self.events.invalid() {
                return Err(super::navigation_lost());
            }
            if !foreground {
                return Ok(Poll::Pending);
            }
            self.events.begin();
            {
                #[cfg(test)]
                let _duration = crate::Native::readiness_span("navigation-issue");
                self.native.navigate_owner().map_err(unavailable)?;
            }
            self.navigation_issued = true;
        }
        if self.events.invalid() {
            return Err(super::navigation_lost());
        }
        Ok(self.events.started().map_or(Poll::Pending, Poll::Ready))
    }

    fn check_foreground_deadline(&self, deadline: std::time::Instant) -> Result<()> {
        let now = self.clock.now();
        if now >= self.deadline {
            return Err(SurfaceError::new(BridgeError::Lifecycle(
                LifecycleCode::ReadinessTimeout,
            )));
        }
        if now >= deadline {
            return Err(SurfaceError::new(BridgeError::Lifecycle(
                LifecycleCode::ForegroundUnavailable,
            )));
        }
        Ok(())
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
