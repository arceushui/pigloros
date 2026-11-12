#![cfg(windows)]
#![cfg(test)]

//! Declared faults on processes discovered from the current owned environment.

#[cfg(test)]
use std::io::Write as _;

#[cfg(test)]
fn fault_diagnostic(message: &'static str) {
    let _logged_or_unavailable = writeln!(std::io::stderr(), "{message}");
}

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

struct ExitRetained {
    retained: Retained,
    image: std::path::PathBuf,
    attempted: bool,
}

impl ProcessFaultHandle for ExitRetained {
    fn identity(&self) -> ProcessIdentity {
        self.retained.identity
    }

    fn exit_code(&self) -> Result<Option<u32>, ()> {
        self.retained.exit_code()
    }
}

impl ExitRetained {
    fn verified_exit_code(&self) -> Result<Option<u32>, ()> {
        verified_exit_observation(
            self.retained.identity,
            &self.image,
            || {
                super::process::read_identity(
                    self.retained.handle,
                    self.retained.identity.browser_pid,
                )
            },
            || self.retained.exit_code(),
        )
    }
}

fn verified_exit_observation(
    expected: ProcessIdentity,
    expected_image: &std::path::Path,
    identity: impl FnOnce() -> Result<(ProcessIdentity, std::path::PathBuf), ()>,
    exit_code: impl FnOnce() -> Result<Option<u32>, ()>,
) -> Result<Option<u32>, ()> {
    let (identity, image) = identity().map_err(|()| {
        fault_diagnostic("NATIVE_EXIT_QUERY stage=required_identity result=query_failed");
    })?;
    if image != expected_image {
        fault_diagnostic("NATIVE_EXIT_QUERY stage=required_identity result=image_mismatch");
        return Err(());
    }
    if identity != expected {
        fault_diagnostic("NATIVE_EXIT_QUERY stage=required_identity result=identity_mismatch");
        return Err(());
    }
    exit_code()
}

impl crate::RetainedExitHandle for ExitRetained {
    fn identity(&self) -> ProcessIdentity {
        self.retained.identity
    }

    fn observe(&self) -> Result<Option<u32>, ()> {
        self.verified_exit_code()
    }

    fn terminate(&mut self, authority: &crate::FaultAuthority) -> Result<(), ()> {
        if self.attempted
            || !authority.valid()
            || authority.browser() != self.retained.identity
            || authority.target() != ProcessFaultTarget::Browser
            || authority.lifecycle() != crate::ProcessFaultLifecycle::AwaitingExitSuccess
            || self.observe()?.is_some()
            || !authority.valid()
        {
            return Err(());
        }
        self.attempted = true;
        authority.record(crate::ProcessFaultMark::Selected(self.retained.identity));
        if !authority.valid() {
            return Err(());
        }
        authority.record(crate::ProcessFaultMark::TerminationCall);
        terminate_owned_process(self.retained.handle)
    }

    fn into_fault(self: Box<Self>) -> Box<dyn ProcessFaultHandle> {
        self
    }
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
        unsafe { GetExitCodeProcess(self.handle, &raw mut code) }
            .map_err(|error| write_exit_query_failure(&mut std::io::stderr(), error.code().0))?;
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

fn select_optional(
    entries: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
    kind: COREWEBVIEW2_PROCESS_KIND,
) -> Result<Option<u32>, ()> {
    let mut matches = entries.iter().filter(|(_, entry_kind)| *entry_kind == kind);
    let Some((pid, _)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(());
    }
    Ok(Some(*pid))
}

fn select(
    entries: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
    kind: COREWEBVIEW2_PROCESS_KIND,
) -> Result<u32, ()> {
    select_optional(entries, kind)?.ok_or(())
}

fn retained_browser_membership(
    entries: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
    expected: u32,
) -> Result<(), ()> {
    let entries: Vec<_> = entries
        .iter()
        .map(|(pid, kind)| {
            let kind = if *kind == COREWEBVIEW2_PROCESS_KIND_BROWSER {
                crate::ExitMembershipKind::Browser
            } else {
                crate::ExitMembershipKind::Other
            };
            (*pid, kind)
        })
        .collect();
    crate::retained_exit_membership(&entries, expected)
}

pub(super) fn observe_retained_exit_membership(
    environment: &ICoreWebView2Environment,
    handle: &dyn crate::RetainedExitHandle,
) -> Result<(), ()> {
    retained_browser_membership(&candidates(environment)?, handle.identity().browser_pid)
}

fn open_owned_process(pid: u32) -> Result<HANDLE, ()> {
    // SAFETY: callers select PID from the current environment; the fixed rights
    // and non-inheritable handle are solely for the declared unit-test fault.
    unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            pid,
        )
    }
    .map_err(|_| ())
}

fn terminate_owned_process(handle: HANDLE) -> Result<(), ()> {
    // SAFETY: the caller retains and revalidates the owned process object at
    // the declared fault boundary, using the fixed non-active exit code.
    unsafe { TerminateProcess(handle, FAULT_EXIT) }.map_err(|_| ())
}

pub(super) fn retain_exit_browser(
    environment: &ICoreWebView2Environment,
    authority: &crate::FaultAuthority,
) -> Result<Box<dyn crate::RetainedExitHandle>, ()> {
    if !authority.valid()
        || authority.target() != ProcessFaultTarget::Browser
        || authority.lifecycle() != crate::ProcessFaultLifecycle::AwaitingExitSuccess
    {
        return Err(());
    }
    let expected = authority.browser();
    let first = candidates(environment)?;
    if select(&first, COREWEBVIEW2_PROCESS_KIND_BROWSER)? != expected.browser_pid {
        return Err(());
    }
    let retained = Retained {
        handle: open_owned_process(expected.browser_pid)?,
        identity: expected,
    };
    let (identity, image) = check_pre_close_identity(
        super::process::read_identity(retained.handle, expected.browser_pid),
        expected,
        None,
        &fault_diagnostic,
    )?;
    if retained.exit_code()?.is_some()
        || select(&candidates(environment)?, COREWEBVIEW2_PROCESS_KIND_BROWSER)?
            != expected.browser_pid
    {
        return Err(());
    }
    check_pre_close_identity(
        super::process::read_identity(retained.handle, expected.browser_pid),
        identity,
        Some(&image),
        &fault_diagnostic,
    )?;
    if retained.exit_code()?.is_some() || !authority.valid() {
        return Err(());
    }
    Ok(Box::new(ExitRetained {
        retained,
        image,
        attempted: false,
    }))
}

/// A successful, stable complete snapshot; no target or termination capability escapes.
pub(super) fn renderer_presence(
    environment: &ICoreWebView2Environment,
    expected: ProcessIdentity,
) -> Result<crate::RendererPresence, ()> {
    renderer_presence_from_observations(
        expected,
        || candidates(environment),
        super::process::inspect,
    )
}

fn renderer_presence_from_observations(
    expected: ProcessIdentity,
    mut snapshot: impl FnMut() -> Result<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>, ()>,
    mut inspect: impl FnMut(u32) -> Result<Option<(ProcessIdentity, std::path::PathBuf)>, ()>,
) -> Result<crate::RendererPresence, ()> {
    let first = snapshot()?;
    if select(&first, COREWEBVIEW2_PROCESS_KIND_BROWSER)? != expected.browser_pid {
        return Err(());
    }
    let (browser, browser_path) = inspect(expected.browser_pid)?.ok_or(())?;
    if browser != expected {
        return Err(());
    }
    let renderer = select_optional(&first, COREWEBVIEW2_PROCESS_KIND_RENDERER)?;
    let observed = match renderer {
        Some(pid) => {
            let (identity, path) = inspect(pid)?.ok_or(())?;
            if path != browser_path {
                return Err(());
            }
            Some((identity, path))
        }
        None => None,
    };
    let second = snapshot()?;
    if select(&second, COREWEBVIEW2_PROCESS_KIND_BROWSER)? != expected.browser_pid
        || inspect(expected.browser_pid)?.ok_or(())? != (browser, browser_path)
        || select_optional(&second, COREWEBVIEW2_PROCESS_KIND_RENDERER)? != renderer
    {
        return Err(());
    }
    match (renderer, observed) {
        (None, None) => Ok(crate::RendererPresence::Absent),
        (Some(pid), Some(observed)) if inspect(pid)?.ok_or(())? == observed => {
            Ok(crate::RendererPresence::Unique)
        }
        _ => Err(()),
    }
}

/// Discovery has no caller-provided PID and confers no termination authority.
pub(super) fn browser_candidate(
    environment: &ICoreWebView2Environment,
) -> Result<ProcessIdentity, ()> {
    let first = candidates(environment).map_err(|()| {
        fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=first-snapshot-incomplete");
    })?;
    browser_candidate_from_first(environment, &first)
}

pub(super) fn pending_browser_candidate(
    environment: &ICoreWebView2Environment,
) -> Result<Option<ProcessIdentity>, ()> {
    let Some(first) = pending_snapshot(|| candidates(environment))? else {
        return Ok(None);
    };
    browser_candidate_from_first(environment, &first).map(Some)
}

fn pending_snapshot(
    mut observe: impl FnMut() -> Result<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>, ()>,
) -> Result<Option<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>>, ()> {
    let first = observe()?;
    if !first.is_empty() {
        return Ok(Some(first));
    }
    let second = observe()?;
    if second.is_empty() {
        Ok(None)
    } else {
        Ok(Some(second))
    }
}

#[test]
fn pending_snapshot_requires_two_complete_empty_observations() {
    let browser = vec![(1, COREWEBVIEW2_PROCESS_KIND_BROWSER)];
    let mut observations = [Ok(Vec::new()), Ok(Vec::new())].into_iter();
    assert!(matches!(
        pending_snapshot(|| observations.next().unwrap_or(Err(()))),
        Ok(None)
    ));
    let mut observations = [Ok(Vec::new()), Ok(browser.clone())].into_iter();
    assert!(matches!(
        pending_snapshot(|| observations.next().unwrap_or(Err(()))),
        Ok(Some(result)) if result == browser
    ));
    let mut observations = [Ok(Vec::new()), Err(())].into_iter();
    assert!(pending_snapshot(|| observations.next().unwrap_or(Err(()))).is_err());
    assert!(pending_snapshot(|| Err(())).is_err());
    let mut observations = std::iter::once(Ok(browser));
    assert!(matches!(
        pending_snapshot(|| observations.next().unwrap_or(Err(()))),
        Ok(Some(_))
    ));
}

fn browser_candidate_from_first(
    environment: &ICoreWebView2Environment,
    first: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
) -> Result<ProcessIdentity, ()> {
    browser_candidate_from_observations(first, || candidates(environment), super::process::inspect)
}

fn browser_candidate_from_observations(
    first: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
    snapshot: impl FnOnce() -> Result<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>, ()>,
    mut inspect: impl FnMut(u32) -> Result<Option<(ProcessIdentity, std::path::PathBuf)>, ()>,
) -> Result<ProcessIdentity, ()> {
    let _logged_or_unavailable = writeln!(
        std::io::stderr(),
        "NATIVE_PROCESS_SNAPSHOT first-snapshot={}",
        if first.is_empty() {
            "empty"
        } else {
            "nonempty"
        }
    );
    let pid = select(first, COREWEBVIEW2_PROCESS_KIND_BROWSER).map_err(|()| {
        let count = first
            .iter()
            .filter(|(_, kind)| *kind == COREWEBVIEW2_PROCESS_KIND_BROWSER)
            .count();
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "NATIVE_PROCESS_SNAPSHOT first-browser={}",
            if count == 0 { "zero" } else { "multiple" }
        );
    })?;
    let (identity, image) = inspect(pid)
        .map_err(|()| {
            fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=first-identity-error");
        })?
        .ok_or_else(|| {
            fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=first-identity-absent");
        })?;
    let second = snapshot().map_err(|()| {
        fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=second-snapshot-incomplete");
    })?;
    let _logged_or_unavailable = writeln!(
        std::io::stderr(),
        "NATIVE_PROCESS_SNAPSHOT second-snapshot={}",
        if second.is_empty() {
            "empty"
        } else {
            "nonempty"
        }
    );
    let second_pid = select(&second, COREWEBVIEW2_PROCESS_KIND_BROWSER).map_err(|()| {
        let count = second
            .iter()
            .filter(|(_, kind)| *kind == COREWEBVIEW2_PROCESS_KIND_BROWSER)
            .count();
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "NATIVE_PROCESS_SNAPSHOT second-browser={}",
            if count == 0 { "zero" } else { "multiple" }
        );
    })?;
    if second_pid != pid {
        fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=browser-changed");
        return Err(());
    }
    let second_identity = inspect(pid)
        .map_err(|()| {
            fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=second-identity-error");
        })?
        .ok_or_else(|| {
            fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=second-identity-absent");
        })?;
    if second_identity != (identity, image) {
        fault_diagnostic("NATIVE_PROCESS_SNAPSHOT failure=identity-changed");
        return Err(());
    }
    Ok(identity)
}

mod candidate_tests;

fn write_exit_query_failure(output: &mut dyn std::io::Write, code: i32) {
    let _logged_or_unavailable = writeln!(
        output,
        "NATIVE_EXIT_QUERY stage=exit_code result=query_failed hresult={code:#x}"
    );
}

fn check_pre_close_identity(
    observation: Result<(ProcessIdentity, std::path::PathBuf), ()>,
    expected: ProcessIdentity,
    expected_image: Option<&std::path::Path>,
    report: &dyn Fn(&'static str),
) -> Result<(ProcessIdentity, std::path::PathBuf), ()> {
    let second = expected_image.is_some();
    let (identity, image) = observation.map_err(|()| {
        report(if second {
            "NATIVE_EXIT_QUERY stage=pre_close_second result=query_failed"
        } else {
            "NATIVE_EXIT_QUERY stage=pre_close_first result=query_failed"
        });
    })?;
    if expected_image.is_some_and(|expected| image.as_path() != expected) {
        report("NATIVE_EXIT_QUERY stage=pre_close_second result=image_mismatch");
        return Err(());
    }
    if identity != expected {
        report(if second {
            "NATIVE_EXIT_QUERY stage=pre_close_second result=identity_mismatch"
        } else {
            "NATIVE_EXIT_QUERY stage=pre_close_first result=identity_mismatch"
        });
        return Err(());
    }
    Ok((identity, image))
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
    let handle = open_owned_process(pid)?;
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
            crate::ProcessFaultLifecycle::PostedConsuming => {
                buffers.ok_or(())?.load_state().map_err(|_| ())?
                    != pos_owner_bridge_codec::ControlState::Consuming as u32
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
    terminate_owned_process(handle)?;
    Ok(Box::new(retained))
}

#[cfg(test)]
mod tests {
    use super::{
        retained_browser_membership, select, select_optional, COREWEBVIEW2_PROCESS_KIND_BROWSER,
        COREWEBVIEW2_PROCESS_KIND_RENDERER,
    };

    #[test]
    fn retained_browser_requires_empty_or_unique_matching_membership() {
        assert_eq!(retained_browser_membership(&[], 11), Ok(()));
        assert_eq!(
            retained_browser_membership(&[(11, COREWEBVIEW2_PROCESS_KIND_BROWSER)], 11),
            Ok(())
        );
        assert!(
            retained_browser_membership(&[(12, COREWEBVIEW2_PROCESS_KIND_BROWSER)], 11).is_err()
        );
        assert!(
            retained_browser_membership(&[(12, COREWEBVIEW2_PROCESS_KIND_RENDERER)], 11).is_err()
        );
        assert!(retained_browser_membership(
            &[
                (11, COREWEBVIEW2_PROCESS_KIND_BROWSER),
                (12, COREWEBVIEW2_PROCESS_KIND_BROWSER)
            ],
            11
        )
        .is_err());
    }

    #[test]
    fn selection_refuses_absent_and_ambiguous_process_classes() {
        assert!(select(&[], COREWEBVIEW2_PROCESS_KIND_BROWSER).is_err());
        assert_eq!(
            select_optional(&[], COREWEBVIEW2_PROCESS_KIND_RENDERER),
            Ok(None)
        );
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
        assert!(select_optional(&ambiguous, COREWEBVIEW2_PROCESS_KIND_BROWSER).is_err());
    }
}
