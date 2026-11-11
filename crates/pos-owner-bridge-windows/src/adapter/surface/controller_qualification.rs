#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge_codec::CeremonyId;

use super::{CloseState, Ownership, PreEnvironmentRetention, Surface};

impl Surface {
    fn controller_creation_custody(
        &mut self,
        ceremony: &CeremonyId,
        window_exists: bool,
    ) -> Option<PreEnvironmentRetention> {
        if self.ownership != Ownership::CreatingController
            || self.opening_spec.as_ref()?.ceremony_id != *ceremony
            || self.folder.as_ref()? != &pos_owner_bridge::folder_name(ceremony)
            || self.identity.is_some()
            || self.recordless_fault.is_some()
            || self.buffers
            || self.generation.is_some()
            || self.close != CloseState::Idle
            || !self.store.records().ok()?.is_empty()
            || !self.native.pending_opening_owners_retained()
            || self.native.window().ok()?.exists != window_exists
            || !self.native.pending()
        {
            return None;
        }
        let folder = self.root.join(self.folder.as_ref()?);
        crate::verify_private_directory(&folder).ok()?;
        Some(if self.failed_open {
            PreEnvironmentRetention::Abandoned
        } else {
            PreEnvironmentRetention::Active
        })
    }

    pub(in crate::adapter) fn controller_creation_retention(
        &mut self,
        ceremony: &CeremonyId,
    ) -> Option<PreEnvironmentRetention> {
        let state = self.controller_creation_custody(ceremony, true)?;
        if self.native.recordless_controller_completion().is_some() {
            None
        } else {
            Some(state)
        }
    }

    pub(in crate::adapter) fn controller_result_retention(
        &mut self,
        ceremony: &CeremonyId,
    ) -> Option<(PreEnvironmentRetention, bool)> {
        let state = self.controller_creation_custody(ceremony, true)?;
        let result = self.native.recordless_controller_completion()?;
        Some((state, result))
    }

    pub(in crate::adapter) fn lose_pending_controller_parent(
        &mut self,
        ceremony: &CeremonyId,
    ) -> std::result::Result<(), ()> {
        if self.controller_creation_retention(ceremony) != Some(PreEnvironmentRetention::Active)
            || std::time::Instant::now() >= self.deadline
        {
            return Err(());
        }
        self.native
            .lose_controller_parent(crate::ControllerParentLossSeal {
                deadline: self.deadline,
            })
    }

    pub(in crate::adapter) fn lost_controller_parent_retention(
        &mut self,
        ceremony: &CeremonyId,
    ) -> Option<PreEnvironmentRetention> {
        let state = self.controller_creation_custody(ceremony, false)?;
        (self.native.recordless_controller_completion() == Some(false)).then_some(state)
    }

    pub(in crate::adapter) fn abandoned_completed_browser(
        &mut self,
        ceremony: &CeremonyId,
    ) -> std::result::Result<pos_owner_bridge::ProcessIdentity, ()> {
        if self.ownership != Ownership::CreatingController
            || !self.failed_open
            || self.opening_spec.as_ref().ok_or(())?.ceremony_id != *ceremony
            || self.folder.as_ref().ok_or(())? != &pos_owner_bridge::folder_name(ceremony)
            || self.identity.is_some()
            || self.recordless_fault.is_some()
            || self.buffers
            || self.generation.is_some()
            || self.close != CloseState::Idle
            || !self.store.records().map_err(|_| ())?.is_empty()
            || !self.native.pending_opening_owners_retained()
            || !self.native.window().map_err(|_| ())?.exists
            || self.native.recordless_controller_completion() != Some(true)
            || self.events.exited().is_some()
        {
            return Err(());
        }
        let folder = self.root.join(self.folder.as_ref().ok_or(())?);
        crate::verify_private_directory(&folder).map_err(|_| ())?;
        self.admit_environment(&folder).map_err(|_| ())?;
        let browser = self.native.recordless_browser_candidate()?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser
            || self.native.recordless_controller_completion() != Some(true)
            || self.events.exited().is_some()
        {
            return Err(());
        }
        self.events.expect_browser(browser.browser_pid);
        self.recordless_fault = Some(browser);
        Ok(browser)
    }
}
