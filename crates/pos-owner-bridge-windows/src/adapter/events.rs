#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use crate::{EventKind, EventSink, NativeAction, NativeError, NativeEvent, OWNER_URL};
use pos_owner_bridge::{NavigationId, SurfaceEvent};

const MAX_EVENTS: usize = 16;

/// One fresh, separately owned policy/queue per environment. Native callbacks
/// retain this object, never a reference to the surface that owns their session.
#[derive(Default)]
pub(super) struct Events {
    queue: RefCell<VecDeque<SurfaceEvent>>,
    invalid: Cell<bool>,
    lost_emitted: Cell<bool>,
    allow_start: Cell<bool>,
    started: Cell<Option<NavigationId>>,
    loaded: Cell<Option<NavigationId>>,
    source_seen: Cell<bool>,
    content_seen: Cell<bool>,
    expected_pid: Cell<Option<u32>>,
    exited: Cell<Option<u32>>,
    #[cfg(test)]
    exit_boundary_invalid: Cell<bool>,
    blocked_resources: Cell<u32>,
}

impl Events {
    pub(super) fn begin(&self) {
        self.allow_start.set(true);
    }
    pub(super) const fn started(&self) -> Option<NavigationId> {
        self.started.get()
    }
    pub(super) const fn loaded(&self) -> Option<NavigationId> {
        self.loaded.get()
    }
    pub(super) const fn invalid(&self) -> bool {
        self.invalid.get()
    }
    pub(super) const fn exited(&self) -> Option<u32> {
        self.exited.get()
    }
    #[cfg(test)]
    pub(super) const fn blocked_resources(&self) -> u32 {
        self.blocked_resources.get()
    }

    pub(super) fn expect_browser(&self, pid: u32) {
        self.expected_pid.set(Some(pid));
        if self.exited.get() == Some(pid) {
            #[cfg(test)]
            self.exit_boundary_invalid.set(true);
            self.invalid.set(true);
        }
    }

    #[cfg(test)]
    pub(super) fn matching_exit_at_boundary(&self, pid: u32) -> bool {
        !self.exit_boundary_invalid.get()
            && self.expected_pid.get() == Some(pid)
            && self.exited.get() == Some(pid)
    }

    pub(super) fn take(&self) -> Option<SurfaceEvent> {
        self.queue.borrow_mut().pop_front()
    }
    #[cfg(test)]
    pub(super) fn renderer_failure_pending(&self) -> bool {
        self.queue.borrow().front() == Some(&SurfaceEvent::RendererFailed)
    }
    pub(super) fn controller_lost(&self) {
        self.emit(SurfaceEvent::ControllerLost);
    }

    fn emit(&self, event: SurfaceEvent) {
        if event == SurfaceEvent::ControllerLost && self.lost_emitted.replace(true) {
            return;
        }
        #[cfg(test)]
        if !matches!(event, SurfaceEvent::DomContentLoaded(_))
            && !matches!(event, SurfaceEvent::BrowserExited { browser_pid } if self.expected_pid.get() == Some(browser_pid))
        {
            self.exit_boundary_invalid.set(true);
        }
        let invalid = match event {
            SurfaceEvent::DomContentLoaded(_) => false,
            SurfaceEvent::BrowserExited { browser_pid } => {
                self.expected_pid.get() == Some(browser_pid)
            }
            _ => true,
        };
        if invalid {
            self.invalid.set(true);
        }
        let mut queue = self.queue.borrow_mut();
        if queue.len() == MAX_EVENTS {
            #[cfg(test)]
            self.exit_boundary_invalid.set(true);
            self.invalid.set(true);
            self.lost_emitted.set(true);
            queue.clear();
            queue.push_back(SurfaceEvent::ControllerLost);
        } else {
            queue.push_back(event);
        }
    }

    fn violation(&self) {
        self.emit(SurfaceEvent::NavigationViolation);
    }

    fn navigation(&self, uri: &str, id: u64, redirected: bool) -> NativeAction {
        #[cfg(test)]
        if let Some(stage) = permission_diagnostic(uri) {
            use std::io::Write as _;
            let _written = writeln!(std::io::stderr(), "NATIVE_PERMISSION stage={stage}");
        }
        if self.allow_start.replace(false)
            && self.started.get().is_none()
            && uri == OWNER_URL
            && !redirected
        {
            self.started.set(Some(NavigationId(id)));
            NativeAction::Allow
        } else {
            self.violation();
            NativeAction::Cancel
        }
    }

    fn source(&self, uri: &str) {
        if self.started.get().is_none() || self.source_seen.replace(true) || uri != OWNER_URL {
            self.violation();
        }
    }

    fn content(&self, id: u64, error_page: bool) {
        if self.started.get() != Some(NavigationId(id))
            || self.content_seen.replace(true)
            || error_page
        {
            self.violation();
        }
    }

    fn loaded_document(&self, id: u64, uri: &str) {
        let navigation = NavigationId(id);
        if self.started.get() != Some(navigation) || self.loaded.get().is_some() || uri != OWNER_URL
        {
            self.violation();
        } else {
            self.loaded.set(Some(navigation));
            self.emit(SurfaceEvent::DomContentLoaded(navigation));
        }
    }

    fn resource(&self, uri: &str, document: bool) -> NativeAction {
        if uri == OWNER_URL && document {
            NativeAction::Allow
        } else {
            self.blocked_resources
                .set(self.blocked_resources.get().saturating_add(1));
            NativeAction::BlockResource
        }
    }

    fn browser_exit(&self, pid: u32) {
        #[cfg(test)]
        if self.exited.get().is_some() {
            self.exit_boundary_invalid.set(true);
        }
        if pid == 0 {
            self.controller_lost();
            return;
        }
        if self
            .expected_pid
            .get()
            .is_none_or(|expected| expected == pid)
        {
            self.exited.set(Some(pid));
        }
        self.emit(SurfaceEvent::BrowserExited { browser_pid: pid });
    }
}

#[cfg(test)]
fn permission_diagnostic(uri: &str) -> Option<&'static str> {
    match uri {
        "http://localhost:49291/permission-diag/denied" => Some("denied"),
        "http://localhost:49291/permission-diag/default" => Some("default"),
        "http://localhost:49291/permission-diag/unexpectedgranted" => Some("unexpectedgranted"),
        "http://localhost:49291/permission-diag/unexpectedstate" => Some("unexpectedstate"),
        "http://localhost:49291/permission-diag/rejected" => Some("rejected"),
        "http://localhost:49291/permission-diag/exception" => Some("exception"),
        "http://localhost:49291/permission-diag/unavailable" => Some("unavailable"),
        "http://localhost:49291/permission-diag/noresult" => Some("noresult"),
        "http://localhost:49291/permission-diag/unknown" => Some("unknown"),
        _ => None,
    }
}

impl EventSink for Events {
    fn event(&self, event: NativeEvent) -> NativeAction {
        match event {
            NativeEvent::Navigation {
                uri,
                id,
                redirected,
            } => return self.navigation(uri.as_str(), id, redirected),
            NativeEvent::Resource { uri, document } => {
                return self.resource(uri.as_str(), document)
            }
            NativeEvent::Source { uri } => self.source(uri.as_str()),
            NativeEvent::Content { id, error_page } => self.content(id, error_page),
            NativeEvent::DomLoaded { id, uri } => self.loaded_document(id, uri.as_str()),
            NativeEvent::NavigationCompleted { id, success } => {
                if self.started.get() != Some(NavigationId(id)) || !success {
                    self.violation();
                }
            }
            NativeEvent::Frame => self.emit(SurfaceEvent::FrameCreated),
            NativeEvent::ProcessFailed => self.emit(SurfaceEvent::RendererFailed),
            NativeEvent::CloseRequested => self.controller_lost(),
            NativeEvent::NewWindow => {
                self.violation();
                return NativeAction::Handled;
            }
            NativeEvent::Permission => {
                self.violation();
                return NativeAction::Deny;
            }
            NativeEvent::Download | NativeEvent::ExternalUri | NativeEvent::Authentication => {
                self.violation();
                return NativeAction::Cancel;
            }
            NativeEvent::ScriptDialog => self.violation(),
            NativeEvent::BrowserExited { pid } => self.browser_exit(pid),
        }
        NativeAction::Observe
    }

    fn failed(&self, kind: EventKind, _error: NativeError) -> NativeAction {
        self.controller_lost();
        match kind {
            EventKind::Navigation
            | EventKind::Download
            | EventKind::ExternalUri
            | EventKind::Authentication => NativeAction::Cancel,
            EventKind::NewWindow => NativeAction::Handled,
            EventKind::Permission => NativeAction::Deny,
            EventKind::Resource => {
                self.blocked_resources
                    .set(self.blocked_resources.get().saturating_add(1));
                NativeAction::BlockResource
            }
            EventKind::Source
            | EventKind::Content
            | EventKind::DomLoaded
            | EventKind::NavigationCompleted
            | EventKind::BrowserExited => NativeAction::Observe,
        }
    }
}

#[cfg(test)]
mod tests;
