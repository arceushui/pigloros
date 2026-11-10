#![cfg(windows)]
#![forbid(unsafe_code)]

use std::rc::Rc;
use std::time::Instant;

use super::{CloseState, Ownership, Surface};

pub(super) struct ExitCapture {
    ceremony: pos_owner_bridge_codec::CeremonyId,
    trace: crate::FaultTrace,
    deadline: Instant,
    attempted: bool,
    consumed: bool,
    handle: Option<Box<dyn crate::RetainedExitHandle>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::adapter) enum ExitBoundary {
    ActiveStatus(crate::ProcessExitState),
    ObjectExitedAwaitingSdk(crate::ProcessExitState),
    AlreadyExited(crate::ProcessExitState),
}

impl Surface {
    pub(in crate::adapter) fn fresh_success_provenance(
        &mut self,
        ceremony: pos_owner_bridge_codec::CeremonyId,
    ) -> Result<pos_owner_bridge::ProcessIdentity, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || !self.buffers
            || self.generation != Some(1)
            || self.events.invalid()
            || self.events.exited().is_some()
        {
            return Err(());
        }
        let spec = self.opening_spec.as_ref().ok_or(())?;
        let folder = self.folder.as_ref().ok_or(())?;
        let browser = self.identity.ok_or(())?;
        if spec.ceremony_id != ceremony || *folder != pos_owner_bridge::folder_name(&ceremony) {
            return Err(());
        }
        let records = self.store.records().map_err(|_| ())?;
        let [bytes] = records.as_slice() else {
            return Err(());
        };
        let record = pos_owner_bridge_codec::decode_cleanup_record(bytes).map_err(|_| ())?;
        if record.ceremony_id() != ceremony
            || record.folder_name() != folder.as_str()
            || record.browser_pid() != browser.browser_pid
            || record.creation_filetime() != browser.creation_filetime
            || record.image_path_sha256() != browser.image_path_sha256
        {
            return Err(());
        }
        Ok(browser)
    }

    pub(in crate::adapter) fn fresh_success_own_exit(
        &self,
        browser: pos_owner_bridge::ProcessIdentity,
    ) -> bool {
        self.idle() && self.events.matching_exit_at_boundary(browser.browser_pid)
    }

    pub(in crate::adapter) fn arm_exit_capture(
        &mut self,
        ceremony: pos_owner_bridge_codec::CeremonyId,
        trace: crate::FaultTrace,
        deadline: Instant,
    ) -> Result<(), ()> {
        if Instant::now() >= deadline {
            return Err(());
        }
        if let Some(capture) = &mut self.exit_capture {
            if capture.attempted
                || capture.ceremony != ceremony
                || !Rc::ptr_eq(&capture.trace, &trace)
            {
                return Err(());
            }
            capture.deadline = deadline;
        } else {
            self.exit_capture = Some(ExitCapture {
                ceremony,
                trace,
                deadline,
                attempted: false,
                consumed: false,
                handle: None,
            });
        }
        Ok(())
    }

    pub(super) fn capture_before_controller_close(&mut self) {
        let Some(mut capture) = self.exit_capture.take() else {
            return;
        };
        if !capture.attempted && !capture.consumed {
            capture.attempted = true;
            capture.handle = self.acquire_exit_handle(&capture).ok();
        }
        self.exit_capture = Some(capture);
    }

    fn acquire_exit_handle(
        &mut self,
        capture: &ExitCapture,
    ) -> Result<Box<dyn crate::RetainedExitHandle>, ()> {
        if Instant::now() >= capture.deadline
            || self.ownership != Ownership::Controller
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
            || self.buffers
            || self.initial_buffer_close != Some(true)
            || self.native.buffer_close_uncertain()
            || self.generation != Some(1)
        {
            return Err(());
        }
        let browser = self.identity.ok_or(())?;
        let folder = self.folder.as_ref().ok_or(())?;
        let spec = self.opening_spec.as_ref().ok_or(())?;
        if spec.ceremony_id != capture.ceremony
            || *folder != pos_owner_bridge::folder_name(&capture.ceremony)
        {
            return Err(());
        }
        let records = self.store.records().map_err(|_| ())?;
        let [bytes] = records.as_slice() else {
            return Err(());
        };
        let record = pos_owner_bridge_codec::decode_cleanup_record(bytes).map_err(|_| ())?;
        if record.ceremony_id() != capture.ceremony
            || record.folder_name() != folder.as_str()
            || record.browser_pid() != browser.browser_pid
            || record.creation_filetime() != browser.creation_filetime
            || record.image_path_sha256() != browser.image_path_sha256
        {
            return Err(());
        }
        let path = self.root.join(folder);
        crate::verify_private_directory(&path).map_err(|_| ())?;
        self.admit_environment(&path).map_err(|_| ())?;
        if self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser {
            return Err(());
        }
        let events = Rc::clone(&self.events);
        let deadline = capture.deadline;
        let authority = crate::FaultAuthority {
            browser,
            target: crate::ProcessFaultTarget::Browser,
            lifecycle: crate::ProcessFaultLifecycle::AwaitingExitSuccess,
            valid: Rc::new(move || {
                Instant::now() < deadline && !events.invalid() && events.exited().is_none()
            }),
            trace: Rc::clone(&capture.trace),
        };
        let handle = self.native.retain_exit_browser(&authority)?;
        let _logged = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!(
                "NATIVE_EXIT_PRE_CLOSE ceremony={:?} identity={browser:?} generation=1 records=1\n",
                capture.ceremony
            ),
        );
        Ok(handle)
    }
    /// Classify only what is already observable at the original cut point.
    pub(in crate::adapter) fn classify_exit_boundary(
        &mut self,
        deadline: Instant,
    ) -> std::result::Result<ExitBoundary, ()> {
        if Instant::now() >= deadline {
            return Err(());
        }
        let browser = self.identity.ok_or(())?;
        if !self.exit_fault_phase_reached()
            || self.close != CloseState::Idle
            || self.failed_open
            || self.buffers
            || match self.events.exited() {
                None => self.events.invalid(),
                Some(_) => !self.events.matching_exit_at_boundary(browser.browser_pid),
            }
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
        let capture = self.exit_capture.as_ref().ok_or(())?;
        let handle = capture.handle.as_ref().ok_or(())?;
        if capture.consumed
            || capture.deadline != deadline
            || capture.ceremony != spec.ceremony_id
            || handle.identity() != browser
        {
            return Err(());
        }
        self.native.retained_exit_membership(handle.as_ref())?;
        let code = handle.observe()?;
        if Instant::now() >= deadline {
            return Err(());
        }
        if self.events.exited().is_some()
            && !self.events.matching_exit_at_boundary(browser.browser_pid)
        {
            return Err(());
        }
        let state = crate::ProcessExitState {
            generation: 1,
            record_count: 1,
        };
        match (self.events.exited(), code) {
            (None, None) => Ok(ExitBoundary::ActiveStatus(state)),
            (None, Some(0)) => Ok(ExitBoundary::ObjectExitedAwaitingSdk(state)),
            (Some(_), Some(0)) => Ok(ExitBoundary::AlreadyExited(state)),
            _ => Err(()),
        }
    }

    pub(in crate::adapter) fn consume_exit_capture(
        &mut self,
        deadline: Instant,
        inject: bool,
    ) -> Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        let boundary = self.classify_exit_boundary(deadline);
        let capture = self.exit_capture.as_mut().ok_or(())?;
        if capture.consumed {
            return Err(());
        }
        capture.consumed = true;
        let boundary = boundary?;
        let capture = self.exit_capture.as_mut().ok_or(())?;
        let handle = capture.handle.as_mut().ok_or(())?;
        if inject {
            if !matches!(boundary, ExitBoundary::ActiveStatus(_)) {
                return Err(());
            }
            let events = Rc::clone(&self.events);
            let authority = crate::FaultAuthority {
                browser: handle.identity(),
                target: crate::ProcessFaultTarget::Browser,
                lifecycle: crate::ProcessFaultLifecycle::AwaitingExitSuccess,
                valid: Rc::new(move || {
                    Instant::now() < deadline && !events.invalid() && events.exited().is_none()
                }),
                trace: Rc::clone(&capture.trace),
            };
            handle.terminate(&authority)?;
        }
        Ok(capture.handle.take().ok_or(())?.into_fault())
    }

    pub(in crate::adapter) fn matching_exit_event(&self) -> bool {
        self.identity
            .is_some_and(|identity| self.events.matching_exit_at_boundary(identity.browser_pid))
    }
}
