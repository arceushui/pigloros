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
            || self
                .opening_spec
                .as_ref()
                .is_none_or(|spec| spec.ceremony_id != *ceremony)
            || self
                .folder
                .as_ref()
                .is_none_or(|folder| *folder != pos_owner_bridge::folder_name(ceremony))
            || self.identity.is_some()
            || self.recordless_fault.is_some()
            || self.buffers
            || self.generation.is_some()
            || self.close != CloseState::Idle
            || !self.store.records().is_ok_and(|records| records.is_empty())
            || !self.native.pending_opening_owners_retained()
            || !self
                .native
                .window()
                .is_ok_and(|window| window.exists == window_exists)
            || !self.native.pending()
            || self.folder.as_ref().is_none_or(|folder| {
                crate::verify_private_directory(&self.root.join(folder)).is_err()
            })
        {
            return None;
        }
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
        self.controller_creation_custody(ceremony, false)
            .filter(|_| self.native.recordless_controller_completion() == Some(false))
    }

    pub(in crate::adapter) fn abandoned_completed_browser(
        &mut self,
        ceremony: &CeremonyId,
    ) -> std::result::Result<pos_owner_bridge::ProcessIdentity, ()> {
        if self.ownership != Ownership::CreatingController
            || !self.failed_open
            || self
                .opening_spec
                .as_ref()
                .is_none_or(|spec| spec.ceremony_id != *ceremony)
            || self
                .folder
                .as_ref()
                .is_none_or(|folder| *folder != pos_owner_bridge::folder_name(ceremony))
            || self.identity.is_some()
            || self.recordless_fault.is_some()
            || self.buffers
            || self.generation.is_some()
            || self.close != CloseState::Idle
            || !self.store.records().is_ok_and(|records| records.is_empty())
            || !self.native.pending_opening_owners_retained()
            || !self.native.window().is_ok_and(|window| window.exists)
            || self.native.recordless_controller_completion() != Some(true)
            || self.events.exited().is_some()
        {
            return Err(());
        }
        let browser = self
            .verify_fault_environment()
            .and_then(|()| self.native.recordless_browser_candidate())
            .and_then(|browser| self.verify_fault_identity(browser).map(|()| browser))
            .ok()
            .filter(|_| {
                self.native.recordless_controller_completion() == Some(true)
                    && self.events.exited().is_none()
            })
            .ok_or(())?;
        self.events.expect_browser(browser.browser_pid);
        self.recordless_fault = Some(browser);
        Ok(browser)
    }
}
