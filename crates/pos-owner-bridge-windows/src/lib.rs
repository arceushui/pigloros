#![cfg(windows)]

//! Windows-specific owner-bridge adapter boundary.
//!
//! Native Win32 operations are confined to inventoried `ffi` modules. The
//! process probe preserves inspection failure as an indeterminate observation.
//!
//! This crate root deliberately carries no crate-wide `#![forbid(unsafe_code)]`:
//! an inner forbid at the root cannot be relaxed in `ffi`. Every non-ffi `mod`
//! declared here carries `#[forbid(unsafe_code)]` instead, and the policy
//! checker enforces it.

mod ffi;
// Safe entry points implemented by the private native boundary. The type and
// its associated operations are accessible only inside this crate.
struct Native;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCallbackMoment {
    EnvironmentCompletion(bool),
    ControllerCompletion(bool),
    BrowserExit(u32),
    DriverTimeout,
    Overflow,
}

#[cfg(test)]
std::thread_local! {
    static CALLBACK_ORDER: std::cell::RefCell<Option<Vec<NativeCallbackMoment>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
impl Native {
    fn arm_callback_order() {
        CALLBACK_ORDER.with(|order| *order.borrow_mut() = Some(Vec::new()));
    }

    fn record_callback(moment: NativeCallbackMoment) {
        CALLBACK_ORDER.with(|order| {
            if let Some(order) = order.borrow_mut().as_mut() {
                if order.len() < 64 {
                    order.push(moment);
                } else if order.last() != Some(&NativeCallbackMoment::Overflow) {
                    order.push(NativeCallbackMoment::Overflow);
                }
            }
        });
    }

    fn callback_order() -> Vec<NativeCallbackMoment> {
        CALLBACK_ORDER.with(|order| order.borrow().as_ref().cloned().unwrap_or_default())
    }

    fn disarm_callback_order() {
        CALLBACK_ORDER.with(|order| *order.borrow_mut() = None);
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCreationMoment {
    EnvironmentReturned(bool),
    EnvironmentCallback(CreationCallback),
    ControllerReturned(bool),
    ControllerCallback(CreationCallback),
    Overflow,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationCallback {
    Success,
    NativeFailure,
    MissingInterface,
    Inconsistent,
}

#[cfg(test)]
std::thread_local! {
    static CREATION_ORDER: std::cell::RefCell<Option<Vec<NativeCreationMoment>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
impl Native {
    fn arm_creation_order() {
        CREATION_ORDER.with(|order| *order.borrow_mut() = Some(Vec::new()));
    }
    fn creation_moment(moment: NativeCreationMoment) {
        CREATION_ORDER.with(|order| {
            if let Some(order) = order.borrow_mut().as_mut() {
                if order.len() < 32 {
                    order.push(moment);
                } else if order.last() != Some(&NativeCreationMoment::Overflow) {
                    order.push(NativeCreationMoment::Overflow);
                }
            }
        });
    }
    fn creation_order() -> Vec<NativeCreationMoment> {
        CREATION_ORDER.with(|order| order.borrow().as_ref().cloned().unwrap_or_default())
    }
    fn disarm_creation_order() {
        CREATION_ORDER.with(|order| *order.borrow_mut() = None);
    }
}
#[forbid(unsafe_code)]
mod adapter {
    // The inline boundary and each child file are separate lint scopes. This
    // retains both ADR-110 checks without duplicate attributes on one module.
    mod directory;
    mod events;
    mod host;
    mod loopback;
    mod overrides;
    mod platform;
    mod process;
    mod runtime;
    mod settings;
    mod socket;
    mod store;
    mod surface;

    #[cfg(test)]
    mod native_tests;

    pub use directory::{create_private_directory, verify_private_directory};
    pub use host::WindowsOwnerHost;
    pub use overrides::refuse_overrides;
    pub use platform::{cpu_requirements, owner_startup, require_windows_profile, CpuFeatures};
    pub use process::{process_identity, WindowsProcessProbe};
    pub use runtime::{verify_fixed_runtime, VerifiedRuntime};
    pub use socket::WindowsLoopbackBinder;
    pub use store::WindowsCleanupStore;
}

pub use adapter::{
    cpu_requirements, create_private_directory, owner_startup, process_identity, refuse_overrides,
    require_windows_profile, verify_fixed_runtime, verify_private_directory, CpuFeatures,
    VerifiedRuntime, WindowsCleanupStore, WindowsLoopbackBinder, WindowsOwnerHost,
    WindowsProcessProbe,
};

// Private, SDK-neutral capabilities shared by sibling safe/native modules.
// Root declarations avoid contradictory private-module visibility lints while
// keeping every capability inaccessible to consumers of this crate.
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

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum ResourceDenialFixture {
    Normal,
    SwallowFailure,
    PropagateFailure,
    RetryStop,
    UncertainComplete,
    MissingDeferral,
    DriverRetry,
}

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

/// Unit-test evidence captured from live native mappings before Close.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeZeroObservation {
    pub(crate) slot: BufferSlot,
    pub(crate) before_nonzero: Option<bool>,
    pub(crate) zeroed: Option<bool>,
    pub(crate) header_present: Option<bool>,
    pub(crate) header_unchanged: Option<bool>,
}

/// Classified callback evidence; a normal matching browser-exit event is separate.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeProcessFailure {
    MainRendererExited,
    BrowserExited,
    Other,
    Unavailable,
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlFault {
    Normal,
    RetryDenial,
    MissingDeferral,
    UncertainComplete,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlObservation {
    pub(crate) kind: EventKind,
    pub(crate) deferred: bool,
    pub(crate) attempts: u32,
    pub(crate) readback: Option<bool>,
    pub(crate) completions: u32,
    pub(crate) retired: bool,
    pub(crate) overflowed: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RendererStateObservation {
    pub(crate) generation: Option<u32>,
    pub(crate) reply_state: Option<u32>,
    pub(crate) record_count: Option<usize>,
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFaultTarget {
    Browser,
    Renderer,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RendererPresence {
    Absent,
    Unique,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFaultLifecycle {
    Quarantined,
    PostedReceipt,
    PostedEmpty,
    PostedWriting,
    PostedReady,
    PostedConsuming,
    BeforeRecord,
    PostedRetry(RetryPoint),
    AwaitingLoad,
    Navigating,
    ReleasingSuccess,
    AwaitingExitSuccess,
    RecordlessOpening,
    PendingOpening,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryPoint {
    Second,
    Third,
    Fourth,
    Fifth,
    Sixth,
    Seventh,
    Eighth,
}

#[cfg(test)]
impl RetryPoint {
    const fn post(self) -> u8 {
        match self {
            Self::Second => 2,
            Self::Third => 3,
            Self::Fourth => 4,
            Self::Fifth => 5,
            Self::Sixth => 6,
            Self::Seventh => 7,
            Self::Eighth => 8,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFaultPhase {
    PostedReceipt,
    PostedEmpty,
    PostedWriting,
    PostedReady,
    PostedConsuming,
    PostedRetry,
    ReleasingSuccess,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFaultTopology {
    SealedSingleViewFrameFree,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessFaultState {
    pub(crate) phase: ProcessFaultPhase,
    pub(crate) topology: ProcessFaultTopology,
    pub(crate) generation: u32,
    pub(crate) reply_state: u32,
    pub(crate) record_count: usize,
    pub(crate) posts: u8,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessExitState {
    pub(crate) generation: u32,
    pub(crate) record_count: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFaultMark {
    ReachedQuarantined(ProcessExitState),
    Reached(ProcessFaultState),
    ReachedExit(ProcessExitState),
    RendererPresence(RendererPresence),
    AwaitingLoad {
        generation: u32,
        record_count: usize,
    },
    Navigating {
        generation: u32,
        record_count: usize,
    },
    RecordlessOpening {
        generation: u32,
        record_count: usize,
    },
    PendingOpening {
        generation: u32,
        record_count: usize,
    },
    ControllerCompletion(bool),
    RecordWritten,
    BeforeRecord {
        generation: u32,
        record_count: usize,
    },
    Selected(pos_owner_bridge::ProcessIdentity),
    TerminationCall,
    MainRendererExited,
    OwnBrowserExited,
    ExitCode(u32),
}

#[cfg(test)]
pub(crate) trait ProcessFaultHandle {
    fn identity(&self) -> pos_owner_bridge::ProcessIdentity;
    fn exit_code(&self) -> Result<Option<u32>, ()>;
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum ExitMembershipKind {
    Browser,
    Other,
}

#[cfg(test)]
fn retained_exit_membership(
    entries: &[(u32, ExitMembershipKind)],
    expected: u32,
) -> Result<(), ()> {
    if entries.len() > 64 || expected == 0 {
        return Err(());
    }
    let mut browser = None;
    for (index, &(pid, kind)) in entries.iter().enumerate() {
        if pid == 0 || entries[..index].iter().any(|(earlier, _)| *earlier == pid) {
            return Err(());
        }
        if kind == ExitMembershipKind::Browser && browser.replace(pid).is_some() {
            return Err(());
        }
    }
    if entries.is_empty() || browser == Some(expected) {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
trait RetainedExitHandle {
    fn identity(&self) -> pos_owner_bridge::ProcessIdentity;
    fn observe(&self) -> Result<Option<u32>, ()>;
    fn terminate(&mut self, authority: &FaultAuthority) -> Result<(), ()>;
    fn into_fault(self: Box<Self>) -> Box<dyn ProcessFaultHandle>;
}

#[cfg(test)]
type FaultTrace = Rc<std::cell::RefCell<Vec<ProcessFaultMark>>>;

/// A one-use test capability constructed only by the sealed fault fixture.
#[cfg(test)]
struct FaultSeal {
    trace: FaultTrace,
    deadline: std::time::Instant,
}

#[cfg(test)]
impl FaultSeal {
    fn into_parts(self) -> (FaultTrace, std::time::Instant) {
        (self.trace, self.deadline)
    }
}

/// One-use authority for the current owned parent during controller creation.
#[cfg(test)]
struct ControllerParentLossSeal {
    deadline: std::time::Instant,
}

#[cfg(test)]
impl ControllerParentLossSeal {
    const fn into_deadline(self) -> std::time::Instant {
        self.deadline
    }
}

/// Bound to the exact Surface observer and validated process identity.
#[cfg(test)]
struct FaultAuthority {
    browser: pos_owner_bridge::ProcessIdentity,
    target: ProcessFaultTarget,
    lifecycle: ProcessFaultLifecycle,
    valid: Rc<dyn Fn() -> bool>,
    trace: FaultTrace,
}

#[cfg(test)]
impl FaultAuthority {
    const fn browser(&self) -> pos_owner_bridge::ProcessIdentity {
        self.browser
    }
    const fn target(&self) -> ProcessFaultTarget {
        self.target
    }
    const fn lifecycle(&self) -> ProcessFaultLifecycle {
        self.lifecycle
    }
    fn valid(&self) -> bool {
        (self.valid)()
    }
    fn record(&self, mark: ProcessFaultMark) {
        self.trace.borrow_mut().push(mark);
    }
}

/// Native ownership operations; lifecycle outcomes are selected by the adapter.
/// No SDK pointer, HRESULT, token, arbitrary property ID, script, header, URL,
/// buffer offset, or caller-provided COM callback crosses this interface.
pub(crate) trait NativeOperations {
    #[cfg(test)]
    fn observe_closed_wrappers(&mut self) -> NativeResult<()> {
        Err(NativeError {
            operation: Operation::Controller,
            failure: Failure::Closed,
        })
    }

    #[cfg(test)]
    fn retain_exit_browser(
        &self,
        _authority: &FaultAuthority,
    ) -> Result<Box<dyn RetainedExitHandle>, ()> {
        Err(())
    }

    #[cfg(test)]
    fn retained_exit_membership(&self, _handle: &dyn RetainedExitHandle) -> Result<(), ()> {
        Err(())
    }
    #[cfg(test)]
    fn inject_process_fault(
        &self,
        _authority: &FaultAuthority,
    ) -> Result<Box<dyn ProcessFaultHandle>, ()> {
        Err(())
    }

    #[cfg(test)]
    fn environment_creation_completion(&self) -> Option<bool> {
        None
    }

    #[cfg(test)]
    fn early_renderer_presence(&self) -> Result<RendererPresence, ()> {
        Err(())
    }

    #[cfg(test)]
    fn lose_controller_parent(&mut self, _seal: ControllerParentLossSeal) -> Result<(), ()> {
        Err(())
    }

    #[cfg(test)]
    fn pending_opening_owners_retained(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn pending_opening_browser_candidate(
        &self,
    ) -> Result<Option<pos_owner_bridge::ProcessIdentity>, ()> {
        Err(())
    }

    #[cfg(test)]
    fn recordless_controller_completion(&self) -> Option<bool> {
        None
    }

    #[cfg(test)]
    fn preload_fault_owners_retained(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn exit_fault_owners_retained(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn recordless_browser_candidate(&self) -> Result<pos_owner_bridge::ProcessIdentity, ()> {
        Err(())
    }

    #[cfg(test)]
    fn recordless_fault_owners_retained(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn fault_owners_retained(&self) -> bool {
        false
    }

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
#[forbid(unsafe_code)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};

    use pos_owner_bridge::listener::bind::LoopbackBinder;

    use crate::WindowsLoopbackBinder;

    mod native_api;

    impl crate::Native {
        pub(crate) fn fixed_port_fixture() -> std::sync::MutexGuard<'static, ()> {
            static PORT: std::sync::Mutex<()> = std::sync::Mutex::new(());
            PORT.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    #[test]
    fn native_window_environment_and_buffers_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_window_environment_and_buffers_lifecycle()
    }

    #[test]
    fn native_owned_window_reads_owner_dpi() -> crate::NativeResult<()> {
        crate::Native::verify_owned_window_dpi()
    }

    #[test]
    fn native_resource_denial_callback_failure_does_not_contact_listener(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_resource_denial_failure()
    }

    #[test]
    fn native_control_callbacks_deny_and_retain_through_own_exit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_control_denials()
    }

    #[test]
    fn native_readonly_write_crashes_the_exact_renderer_and_retires(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_readonly_renderer_failure()
    }

    #[test]
    fn native_delivery_adversaries_retry_without_stale_receipt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_delivery_adversaries()
    }

    #[test]
    fn native_verified_owned_process_faults_retire() -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_verified_owned_process_faults_retire()
    }

    #[test]
    fn native_controller_failure_from_owned_parent_loss() -> Result<(), Box<dyn std::error::Error>>
    {
        crate::Native::native_controller_failure_from_owned_parent_loss()
    }

    #[test]
    fn native_host_fixture_child() -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_host_fixture_child()
    }

    #[test]
    fn native_host_opens_fresh_environments_and_retires_before_reuse(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::native_host_parent_fixture()
    }

    #[test]
    fn runtime_checks_all_members_metadata_cache_and_per_start_binaries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::Native::verify_runtime_cache_fixture()
    }

    #[test]
    fn exclusive_loopback_sockets_block_a_reusing_competitor() {
        let _port = crate::Native::fixed_port_fixture();
        let mut fixed = WindowsLoopbackBinder::default();
        // No connections/TIME_WAIT on the port used by later lifecycle fixtures.
        assert!(fixed
            .bind_v4()
            .is_ok_and(|v4| fixed.bind_v6().is_ok_and(|v6| {
                assert!(v4
                    .local_addr()
                    .is_ok_and(|address| address.port() == 49_291));
                assert!(v6
                    .local_addr()
                    .is_ok_and(|address| address.port() == 49_291));
                assert!(fixed.bind_v4().is_err());
                assert!(fixed.bind_v6().is_err());
                true
            })));
        let mut binder = WindowsLoopbackBinder::ephemeral();
        assert!(binder.bind_v4().as_ref().is_ok_and(exercise_v4));
        assert!(binder.bind_v6().as_ref().is_ok_and(exercise_v6));
        assert_eq!(binder.probe_v6(), Ok(()));
    }

    fn exercise_v4(listener: &TcpListener) -> bool {
        listener.local_addr().is_ok_and(|address| {
            assert_eq!(address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert!(TcpStream::connect(address).is_ok_and(|client| {
                let accepted = listener
                    .accept()
                    .is_ok_and(|(_, peer)| peer.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST));
                drop(client);
                accepted
            }));
            assert!(TcpListener::bind(address).is_err());
            assert!(
                crate::Native::competing_reuse(address.port()).is_err_and(|error| {
                    [io::ErrorKind::AddrInUse, io::ErrorKind::PermissionDenied]
                        .contains(&error.kind())
                })
            );
            true
        })
    }

    fn exercise_v6(listener: &TcpListener) -> bool {
        listener.local_addr().is_ok_and(|address| {
            assert_eq!(address.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
            assert!(TcpStream::connect(address).is_ok_and(|client| {
                let accepted = listener.accept().is_ok();
                drop(client);
                accepted
            }));
            assert!(TcpListener::bind(address).is_err());
            true
        })
    }
}
