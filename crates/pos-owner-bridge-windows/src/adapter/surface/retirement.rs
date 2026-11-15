#![cfg(windows)]
#![forbid(unsafe_code)]

use super::{unavailable, Ownership, Result, Surface};
use pos_owner_bridge::OwnerWebSurface;

impl Surface {
    pub(in crate::adapter) fn abandon_opening(&mut self) {
        if self.identity.is_none() && !self.idle() {
            self.failed_open = true;
        }
    }

    pub(in crate::adapter) fn poll_failed_open(&mut self) -> Result<bool> {
        if !self.failed_open {
            return Ok(self.idle());
        }
        if self.ownership == Ownership::CreatingEnvironment {
            if self.native.environment_completion().is_some() {
                self.ownership = Ownership::Environment;
            }
            if self.native.pending() {
                return Ok(false);
            }
        }
        if matches!(
            self.ownership,
            Ownership::Folder
                | Ownership::Window
                | Ownership::CreatingEnvironment
                | Ownership::Environment
        ) {
            // No controller request was ever issued, so no browser collection
            // was started. Pending environment callbacks have all completed.
            self.retire_unrecorded(false)?;
            return Ok(true);
        }
        if self.ownership == Ownership::CreatingController {
            if self.native.controller_completion().is_some() {
                self.ownership = Ownership::Controller;
            }
            if self.native.pending() {
                return Ok(false);
            }
            if !self.native.has_controller().map_err(unavailable)? {
                // A completed failed creation owns no controller or mapping.
                // This says nothing about a browser process having existed:
                // preserve its recordless folder for the conservative restart
                // orphan sweep instead of waiting for an exit that may not exist.
                self.retire_unrecorded(false)?;
                return Ok(true);
            }
        }
        if matches!(
            self.ownership,
            Ownership::CreatingController | Ownership::Controller
        ) {
            if self.identity.is_none() {
                // A late completion may identify its browser, but never gains
                // authority to navigate, activate, allocate or post a mapping.
                let _observed = self.observe_controller();
            }
            let _closing = self.close_controller();
        }
        let Some(exited) = self.events.exited() else {
            return Ok(false);
        };
        if self
            .identity
            .is_some_and(|identity| identity.browser_pid != exited)
        {
            return Ok(false);
        }
        // Only this fresh exclusive environment's own callback can retire a
        // pre-identity open. No PBCR/mapping ever existed and no PID-absence
        // inference is made. Recorded cleanup uses the stricter finish path.
        self.retire_unrecorded(true)?;
        Ok(true)
    }

    fn retire_unrecorded(&mut self, remove_folder: bool) -> Result<()> {
        self.native.unsubscribe_view().map_err(unavailable)?;
        self.native.unsubscribe_exit().map_err(unavailable)?;
        self.native.drop_environment().map_err(unavailable)?;
        self.native.destroy_window().map_err(unavailable)?;
        // Sharing failure leaves a recognized recordless orphan. The next
        // portable restart sweep retries it; no PBCR is fabricated.
        if let Some(folder) = self.folder.take().filter(|_| remove_folder) {
            let _removed_or_deferred = self.store.remove_folder(&folder);
        }
        self.identity = None;
        self.failed_open = false;
        self.opening_spec = None;
        self.ownership = Ownership::Idle;
        Ok(())
    }

    pub(super) fn finish_folder(&mut self) -> Result<()> {
        self.native.destroy_window().map_err(unavailable)?;
        self.folder.as_ref().map_or(Ok(()), |folder| {
            self.store.remove_folder(folder).map_err(unavailable)
        })?;
        self.folder = None;
        Ok(())
    }
}
