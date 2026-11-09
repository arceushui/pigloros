#![cfg(windows)]
#![cfg(test)]

//! Declared faults on processes discovered from the current owned environment.

use pos_owner_bridge::ProcessIdentity;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Environment, ICoreWebView2Environment8, COREWEBVIEW2_PROCESS_KIND,
    COREWEBVIEW2_PROCESS_KIND_BROWSER, COREWEBVIEW2_PROCESS_KIND_RENDERER,
};
use windows::core::Interface;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

use crate::{ProcessFaultHandle, ProcessFaultTarget};

const ACTIVE: u32 = 259;
const FAULT_EXIT: u32 = 0x535;

struct Retained {
    handle: HANDLE,
    identity: ProcessIdentity,
}

impl Drop for Retained {
    fn drop(&mut self) {
        // SAFETY: this owner holds the one handle returned by OpenProcess.
        let _closed = unsafe { CloseHandle(self.handle) };
    }
}

impl ProcessFaultHandle for Retained {
    fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    fn exit_code(&self) -> Result<Option<u32>, ()> {
        let mut code = 0;
        // SAFETY: the owned process handle stays live and the output is writable.
        unsafe { GetExitCodeProcess(self.handle, &raw mut code) }.map_err(|_| ())?;
        Ok((code != ACTIVE).then_some(code))
    }
}

fn candidates(
    environment: &ICoreWebView2Environment,
) -> Result<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>, ()> {
    let environment: ICoreWebView2Environment8 = environment.cast().map_err(|_| ())?;
    // SAFETY: retained environment is called on its creating STA.
    let collection = unsafe { environment.GetProcessInfos() }.map_err(|_| ())?;
    let mut count = 0;
    // SAFETY: the collection is live and count is a unique output.
    unsafe { collection.Count(&raw mut count) }.map_err(|_| ())?;
    if count > 64 {
        return Err(());
    }
    let mut entries = Vec::new();
    for index in 0..count {
        // SAFETY: index is within the checked collection count on the creating STA.
        let info = unsafe { collection.GetValueAtIndex(index) }.map_err(|_| ())?;
        let mut pid = 0;
        let mut kind = COREWEBVIEW2_PROCESS_KIND::default();
        // SAFETY: live item and distinct initialized output pointers.
        unsafe { info.ProcessId(&raw mut pid) }.map_err(|_| ())?;
        // SAFETY: live item and initialized unique kind output.
        unsafe { info.Kind(&raw mut kind) }.map_err(|_| ())?;
        let pid = u32::try_from(pid).ok().filter(|pid| *pid != 0).ok_or(())?;
        if entries.iter().any(|(existing, _)| *existing == pid) {
            return Err(());
        }
        entries.push((pid, kind));
    }
    Ok(entries)
}

fn select(
    entries: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
    kind: COREWEBVIEW2_PROCESS_KIND,
) -> Result<u32, ()> {
    let mut matches = entries.iter().filter(|(_, entry_kind)| *entry_kind == kind);
    let pid = matches.next().ok_or(())?.0;
    if matches.next().is_some() {
        return Err(());
    }
    Ok(pid)
}

/// Discovery has no caller-provided PID and confers no termination authority.
pub(super) fn browser_candidate(
    environment: &ICoreWebView2Environment,
) -> Result<ProcessIdentity, ()> {
    let first = candidates(environment)?;
    let pid = select(&first, COREWEBVIEW2_PROCESS_KIND_BROWSER)?;
    let (identity, image) = super::process::inspect(pid)?.ok_or(())?;
    let second = candidates(environment)?;
    if select(&second, COREWEBVIEW2_PROCESS_KIND_BROWSER)? != pid
        || super::process::inspect(pid)?.ok_or(())? != (identity, image)
    {
        return Err(());
    }
    Ok(identity)
}

pub(super) fn inject(
    environment: &ICoreWebView2Environment,
    authority: &crate::FaultAuthority,
    buffers: Option<&super::buffers::Pair>,
    pending_controller: Option<&super::creation::ControllerCreation>,
) -> Result<Box<dyn ProcessFaultHandle>, ()> {
    if !authority.valid() {
        return Err(());
    }
    let first = candidates(environment)?;
    let browser_pid = select(&first, COREWEBVIEW2_PROCESS_KIND_BROWSER)?;
    let expected = authority.browser();
    if browser_pid != expected.browser_pid {
        return Err(());
    }
    let (browser, browser_path) = super::process::inspect(browser_pid)?.ok_or(())?;
    if browser != expected {
        return Err(());
    }
    let kind = match authority.target() {
        ProcessFaultTarget::Browser => COREWEBVIEW2_PROCESS_KIND_BROWSER,
        ProcessFaultTarget::Renderer => COREWEBVIEW2_PROCESS_KIND_RENDERER,
    };
    let pid = select(&first, kind)?;
    // SAFETY: PID was selected only from this environment; rights and inheritance are fixed.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            pid,
        )
    }
    .map_err(|_| ())?;
    // Retain the handle on every subsequent failure path.
    let mut retained = Retained {
        handle,
        identity: expected,
    };
    let (observed, path) = super::process::read_identity(handle, pid)?;
    if path != browser_path || (kind == COREWEBVIEW2_PROCESS_KIND_BROWSER && observed != expected) {
        return Err(());
    }
    retained.identity = observed;
    if retained.exit_code()?.is_some() {
        return Err(());
    }
    let second = candidates(environment)?;
    if select(&second, COREWEBVIEW2_PROCESS_KIND_BROWSER)? != browser_pid
        || super::process::inspect(browser_pid)?.ok_or(())? != (browser, browser_path)
        || select(&second, kind)? != pid
        || super::process::read_identity(handle, pid)? != (observed, path)
        || !authority.valid()
        || match authority.lifecycle() {
            crate::ProcessFaultLifecycle::PostedEmpty
            | crate::ProcessFaultLifecycle::PostedRetry(_) => {
                buffers.ok_or(())?.load_state().map_err(|_| ())?
                    != pos_owner_bridge_codec::ControlState::Empty as u32
            }
            crate::ProcessFaultLifecycle::PostedWriting => {
                buffers.ok_or(())?.load_state().map_err(|_| ())?
                    != pos_owner_bridge_codec::ControlState::Writing as u32
            }
            crate::ProcessFaultLifecycle::PostedReady => {
                buffers.ok_or(())?.load_state().map_err(|_| ())?
                    != pos_owner_bridge_codec::ControlState::Ready as u32
            }
            _ => false,
        }
        || (authority.lifecycle() == crate::ProcessFaultLifecycle::PendingOpening
            && pending_controller.ok_or(())?.succeeded().is_some())
        || retained.exit_code()?.is_some()
    {
        return Err(());
    }
    authority.record(crate::ProcessFaultMark::Selected(observed));
    authority.record(crate::ProcessFaultMark::TerminationCall);
    // SAFETY: this is the retained, revalidated process object from the owned
    // environment, at the declared fault point, with a fixed non-active code.
    unsafe { TerminateProcess(handle, FAULT_EXIT) }.map_err(|_| ())?;
    Ok(Box::new(retained))
}

#[cfg(test)]
mod tests {
    use super::{select, COREWEBVIEW2_PROCESS_KIND_BROWSER, COREWEBVIEW2_PROCESS_KIND_RENDERER};

    #[test]
    fn selection_refuses_absent_and_ambiguous_process_classes() {
        assert!(select(&[], COREWEBVIEW2_PROCESS_KIND_BROWSER).is_err());
        let one_browser = [(11, COREWEBVIEW2_PROCESS_KIND_BROWSER)];
        assert_eq!(
            select(&one_browser, COREWEBVIEW2_PROCESS_KIND_BROWSER),
            Ok(11)
        );
        assert!(select(&one_browser, COREWEBVIEW2_PROCESS_KIND_RENDERER).is_err());
        let ambiguous = [
            (11, COREWEBVIEW2_PROCESS_KIND_BROWSER),
            (12, COREWEBVIEW2_PROCESS_KIND_BROWSER),
        ];
        assert!(select(&ambiguous, COREWEBVIEW2_PROCESS_KIND_BROWSER).is_err());
    }
}
