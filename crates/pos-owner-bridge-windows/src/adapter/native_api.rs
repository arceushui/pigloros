#![cfg(windows)]
#![forbid(unsafe_code)]

//! Private seam between native SDK ownership and the safe surface policy.
//! Both production and fixture adapters implement these same capabilities.

use std::ffi::OsString;
use std::fmt;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use pos_owner_bridge::ReplyImage;
use pos_owner_bridge_codec::CeremonyKind;

pub(crate) const OWNER_URL: &str = "http://localhost:49291/owner.html";
pub(crate) const MAX_TEXT_UNITS: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Sta,
    Window,
    Environment,
    Controller,
    Subscription,
    Settings,
    Buffers,
    Text,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    CallFailed,
    InvalidOutput,
    TooLarge,
    WrongSta,
    MissingInterface,
    InvalidAction,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeError {
    pub(crate) operation: Operation,
    pub(crate) failure: Failure,
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {:?}", self.operation, self.failure)
    }
}

impl std::error::Error for NativeError {}

pub(crate) type NativeResult<T> = Result<T, NativeError>;

/// Native extraction bounds the UTF-16 scan before allocation. This owned value
/// additionally validates the length and encoding at the safe seam.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NativeText(String);

impl NativeText {
    #[cfg(test)]
    pub(crate) fn fixture(value: &str) -> Self {
        Self(value.to_owned())
    }

    pub(crate) fn from_utf16(units: &[u16]) -> NativeResult<Self> {
        if units.len() > MAX_TEXT_UNITS {
            return Err(NativeError {
                operation: Operation::Text,
                failure: Failure::TooLarge,
            });
        }
        String::from_utf16(units)
            .map(Self)
            .map_err(|_| NativeError {
                operation: Operation::Text,
                failure: Failure::InvalidOutput,
            })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NativeText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeText")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NativePath(PathBuf);

impl NativePath {
    pub(crate) fn from_utf16(units: &[u16]) -> NativeResult<Self> {
        if units.len() > MAX_TEXT_UNITS {
            return Err(NativeError {
                operation: Operation::Text,
                failure: Failure::TooLarge,
            });
        }
        if units.contains(&0) {
            return Err(NativeError {
                operation: Operation::Text,
                failure: Failure::InvalidOutput,
            });
        }
        Ok(Self(PathBuf::from(OsString::from_wide(units))))
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoolProperty {
    Script,
    WebMessage,
    ScriptDialogs,
    StatusBar,
    DevTools,
    ContextMenus,
    HostObjects,
    Zoom,
    BuiltInErrorPage,
    BrowserAccelerators,
    PasswordAutosave,
    Autofill,
    PinchZoom,
    SwipeNavigation,
    ReputationChecking,
    ExternalDrop,
}

#[derive(Clone, Copy)]
pub(crate) struct EnvironmentOptions {
    pub(crate) extensions: bool,
    pub(crate) custom_crash_reporting: bool,
    pub(crate) exclusive_folder: bool,
}

pub(crate) struct EnvironmentSnapshot {
    pub(crate) version: NativeText,
    // The path has its own bounded, lossless native UTF-16 extraction; paths
    // are never converted through the diagnostic/display string interface.
    pub(crate) folder: NativePath,
    pub(crate) arguments: NativeText,
    pub(crate) options: EnvironmentOptions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientBounds {
    pub(crate) left: i32,
    pub(crate) top: i32,
    pub(crate) right: i32,
    pub(crate) bottom: i32,
}

pub(crate) struct WindowSnapshot {
    pub(crate) exists: bool,
    pub(crate) close_requested: bool,
    pub(crate) dpi: u32,
    pub(crate) client: ClientBounds,
    pub(crate) foreground: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BufferSlot {
    Request,
    Reply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativePulse {
    Timer,
    Dispatched,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventKind {
    Navigation,
    Source,
    Content,
    DomLoaded,
    NavigationCompleted,
    NewWindow,
    Permission,
    Download,
    ExternalUri,
    Authentication,
    Resource,
    BrowserExited,
}

pub(crate) enum NativeEvent {
    Navigation {
        uri: NativeText,
        id: u64,
        redirected: bool,
    },
    Source {
        uri: NativeText,
    },
    Content {
        id: u64,
        error_page: bool,
    },
    DomLoaded {
        id: u64,
        uri: NativeText,
    },
    NavigationCompleted {
        id: u64,
        success: bool,
    },
    Frame,
    ProcessFailed,
    CloseRequested,
    NewWindow,
    Permission,
    Download,
    ExternalUri,
    Authentication,
    ScriptDialog,
    Resource {
        uri: NativeText,
        document: bool,
    },
    BrowserExited {
        pid: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeAction {
    Observe,
    Allow,
    Cancel,
    Handled,
    Deny,
    BlockResource,
}

/// Callbacks own an Rc to a separate safe policy/queue object. They never borrow
/// the surface that owns their COM session, and cannot cross the STA thread.
pub(crate) trait EventSink {
    fn event(&self, event: NativeEvent) -> NativeAction;
    fn failed(&self, kind: EventKind, error: NativeError) -> NativeAction;
}

pub(crate) trait StaPump {
    fn next(&self) -> NativeResult<NativePulse>;
    fn stop(&mut self) -> NativeResult<()>;
}

/// A session can only be issued by the pump's own STA factory. The private
/// surface constructor accepts one factory, never an independently paired
/// session/pump. Native implementations additionally retain and check the same
/// opaque !Send STA token on every operation.
pub(crate) trait NativeFactory: StaPump {
    fn session(&self) -> NativeResult<Box<dyn NativeOperations>>;
}

/// Native ownership operations; lifecycle outcomes are selected by the adapter.
/// No SDK pointer, HRESULT, token, arbitrary property ID, script, header, URL,
/// buffer offset, or caller-provided COM callback crosses this interface.
pub(crate) trait NativeOperations {
    fn create_window(
        &mut self,
        owner: Option<u64>,
        logical_width: u32,
        logical_height: u32,
    ) -> NativeResult<()>;
    fn window(&self) -> NativeResult<WindowSnapshot>;
    fn resize_window(&self, logical_width: u32, logical_height: u32, dpi: u32) -> NativeResult<()>;
    fn show_window(&self) -> NativeResult<()>;
    fn fit_controller(&self) -> NativeResult<()>;
    fn focus_controller(&self) -> NativeResult<()>;

    fn create_environment(
        &mut self,
        runtime: &Path,
        folder: &Path,
        options: EnvironmentOptions,
        sink: Rc<dyn EventSink>,
    ) -> NativeResult<()>;
    fn environment_completion(&mut self) -> Option<NativeResult<()>>;
    fn environment(&self) -> NativeResult<EnvironmentSnapshot>;
    fn create_controller(&mut self) -> NativeResult<()>;
    fn controller_completion(&mut self) -> Option<NativeResult<()>>;
    fn has_controller(&self) -> NativeResult<bool>;
    fn browser_pid(&self) -> NativeResult<u32>;
    fn require_shared_interfaces(&mut self) -> NativeResult<()>;
    fn subscribe_view(&mut self, sink: Rc<dyn EventSink>) -> NativeResult<()>;

    fn set_bool(&self, property: BoolProperty, value: bool) -> NativeResult<()>;
    fn get_bool(&self, property: BoolProperty) -> NativeResult<bool>;
    fn navigate_owner(&self) -> NativeResult<()>;
    fn source(&self) -> NativeResult<NativeText>;

    /// Acquire both mappings before writing either secret-bearing image. The
    /// native capability always verifies capacities, pointers, alignment and
    /// exact access ranges; the adapter has already admitted codec semantics.
    fn create_buffers(
        &mut self,
        kind: CeremonyKind,
        request: &[u8],
        reply_header: &[u8; 64],
    ) -> NativeResult<()>;
    fn post(&self, slot: BufferSlot) -> NativeResult<()>;
    fn load_state(&self) -> NativeResult<u32>;
    fn compare_exchange(&self, current: u32, new: u32) -> NativeResult<bool>;
    fn copy_reply(&self, out: &mut ReplyImage) -> NativeResult<()>;
    fn close_buffers(&mut self) -> NativeResult<()>;
    fn buffer_close_uncertain(&self) -> bool;

    fn unsubscribe_view(&mut self) -> NativeResult<()>;
    fn close_controller(&mut self) -> NativeResult<()>;
    fn unsubscribe_exit(&mut self) -> NativeResult<()>;
    fn drop_environment(&mut self) -> NativeResult<()>;
    fn destroy_window(&mut self) -> NativeResult<()>;
    fn pending(&self) -> bool;
}

#[cfg(test)]
mod tests;
