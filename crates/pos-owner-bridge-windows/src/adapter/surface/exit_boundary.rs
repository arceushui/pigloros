#![cfg(windows)]
#![forbid(unsafe_code)]

use std::time::Instant;

use super::{CloseState, Surface};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::adapter) enum ExitBoundary {
    Live(crate::ProcessExitState),
    AlreadyExited(crate::ProcessExitState),
}

impl Surface {
    /// Classify only what is already observable at the original cut point.
    pub(in crate::adapter) fn classify_exit_boundary(
        &mut self,
        deadline: Instant,
    ) -> std::result::Result<ExitBoundary, ()> {
        if Instant::now() >= deadline {
            return Err(());
        }
        if self.events.exited().is_none() {
            return self.exit_fault_state().map(ExitBoundary::Live);
        }
        let browser = self.identity.ok_or(())?;
        if !self.exit_fault_phase_reached()
            || self.close != CloseState::Idle
            || self.failed_open
            || self.buffers
            || !self.events.matching_exit_at_boundary(browser.browser_pid)
            || !self.native.exit_fault_owners_retained()
            || !crate::Native::process_failure_observations().is_empty()
        {
            return Err(());
        }
        let close = self.initial_close.ok_or(())?;
        if close.removed.is_err()
            || close.closed.is_err()
            || !close.buffers_closed
            || close.buffers_uncertain
            || !close.had_controller
        {
            return Err(());
        }
        let spec = self.opening_spec.as_ref().ok_or(())?;
        let folder = self.folder.as_ref().ok_or(())?;
        crate::verify_private_directory(&self.root.join(folder)).map_err(|_| ())?;
        self.admit_environment(&self.root.join(folder))
            .map_err(|_| ())?;
        let records = self.store.records().map_err(|_| ())?;
        let [bytes] = records.as_slice() else {
            return Err(());
        };
        let record = pos_owner_bridge_codec::decode_cleanup_record(bytes).map_err(|_| ())?;
        if record.ceremony_id() != spec.ceremony_id
            || record.folder_name() != folder.as_str()
            || record.browser_pid() != browser.browser_pid
            || record.creation_filetime() != browser.creation_filetime
            || record.image_path_sha256() != browser.image_path_sha256
            || self.generation != Some(1)
            || Instant::now() >= deadline
        {
            return Err(());
        }
        Ok(ExitBoundary::AlreadyExited(crate::ProcessExitState {
            generation: 1,
            record_count: 1,
        }))
    }
}
