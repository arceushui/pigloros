#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge_codec::CeremonyId;

use super::{CloseState, Ownership, PreEnvironmentRetention, Surface};

impl Surface {
    pub(in crate::adapter) fn controller_creation_retention(
        &mut self,
        ceremony: &CeremonyId,
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
            || !self.native.window().ok()?.exists
            || !self.native.pending()
            || self.native.recordless_controller_completion().is_some()
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
    pub(in crate::adapter) fn controller_result_retention(
        &mut self,
        ceremony: &CeremonyId,
    ) -> Option<(PreEnvironmentRetention, bool)> {
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
            || !self.native.window().ok()?.exists
            || !self.native.pending()
        {
            return None;
        }
        let result = self.native.recordless_controller_completion()?;
        let folder = self.root.join(self.folder.as_ref()?);
        crate::verify_private_directory(&folder).ok()?;
        let state = if self.failed_open {
            PreEnvironmentRetention::Abandoned
        } else {
            PreEnvironmentRetention::Active
        };
        Some((state, result))
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
