#![cfg(windows)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};
use std::sync::OnceLock;

use crate::native_api::{
    ClientBounds, Failure, NativeError, NativeResult, Operation, WindowSnapshot,
};
use windows::core::{w, PCSTR};
use windows::Win32::Foundation::{FARPROC, HINSTANCE, HWND, RECT};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTOPRIMARY,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, GetDpiForSystem, GetDpiForWindow, SetProcessDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, GetClientRect, GetForegroundWindow, GetWindow, IsWindow,
    RegisterClassW, SetForegroundWindow, SetWindowPos, ShowWindow, GW_OWNER, MSG, SC_CLOSE,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SW_SHOWNORMAL, WINDOW_EX_STYLE, WM_CLOSE,
    WM_SYSCOMMAND, WNDCLASSW, WNDPROC, WS_OVERLAPPEDWINDOW,
};

type Result<T> = NativeResult<T>;

#[derive(Default)]
pub(super) struct WindowSignals {
    pub(super) close_requested: Cell<bool>,
    pub(super) destroyed: Cell<bool>,
}

thread_local! {
    // Window procedures borrow no controller or CeremonyDriver state. Native
    // callbacks merely signal the owning STA loop, so dispatch cannot reenter
    // a mutable driver/surface borrow. Weak entries cannot keep a window alive.
    static WINDOWS: RefCell<BTreeMap<usize, Weak<WindowSignals>>> = const { RefCell::new(BTreeMap::new()) };
}

// Only queued messages for an owned ceremony HWND are intercepted. Sent
// messages bypass this filter; refresh detects destruction on every STA tick.
pub(super) fn intercept(message: &MSG) -> bool {
    let close = message.message == WM_CLOSE
        || (message.message == WM_SYSCOMMAND && message.wParam.0 & 0xfff0 == SC_CLOSE as usize);
    if !close {
        return false;
    }
    WINDOWS.with(|windows| {
        let signal = windows
            .borrow()
            .get(&(message.hwnd.0 as usize))
            .and_then(Weak::upgrade);
        if let Some(signal) = signal {
            signal.close_requested.set(true);
            true
        } else {
            false
        }
    })
}

fn prepare_class_once() -> Result<()> {
    static CLASS: OnceLock<std::result::Result<(), ()>> = OnceLock::new();
    CLASS
        .get_or_init(register_class)
        .map_err(|()| unavailable())
}

fn register_class() -> std::result::Result<(), ()> {
    // SAFETY: process-once setup before any ceremony window; incompatible
    // existing awareness refuses activation rather than silently degrading DPI.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }
        .map_err(|_| ())?;
    // SAFETY: borrow the already-loaded fixed system module; never load a DLL
    // or accept a caller-selected search path. This handle is never released.
    let module = unsafe { GetModuleHandleW(w!("user32.dll")) }.map_err(|_| ())?;
    // SAFETY: fixed exact ASCII export name, with its terminating NUL, from the
    // system module; no ordinal lookup and no caller-selected symbol.
    let procedure = unsafe { GetProcAddress(module, PCSTR(c"DefWindowProcW".as_ptr().cast())) };
    if procedure.is_none() {
        return Err(());
    }
    // SAFETY: Microsoft's User32 DefWindowProcW export has exactly WNDPROC's
    // HWND/u32/WPARAM/LPARAM -> LRESULT signature and system ABI. Both values
    // are function-pointer Options; no integer round-trip or app ABI definition.
    let procedure = unsafe { std::mem::transmute::<FARPROC, WNDPROC>(procedure) };
    // SAFETY: borrow the current executable module for the process-lifetime
    // registered class; no ownership transfer or FreeLibrary obligation.
    let executable = unsafe { GetModuleHandleW(None) }.map_err(|_| ())?;
    let class = WNDCLASSW {
        lpfnWndProc: procedure,
        hInstance: HINSTANCE(executable.0),
        lpszClassName: w!("PiglorOS.OwnerBridge.v1"),
        ..WNDCLASSW::default()
    };
    // SAFETY: fixed class name and system procedure remain valid for the
    // process lifetime; initialized class references a live executable module.
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(());
    }
    Ok(())
}

pub(super) struct Window {
    hwnd: HWND,
    pub(super) signals: Rc<WindowSignals>,
}

pub(super) fn prepare_class() -> Result<()> {
    prepare_class_once()
}

impl Window {
    pub(super) fn create(owner: Option<u64>, width: u32, height: u32) -> Result<Self> {
        prepare_class_once()?;
        // SAFETY: borrowed current executable module matches the registered
        // class instance; no reference is released or transferred by this call.
        let executable = unsafe { GetModuleHandleW(None) }.map_err(|_| unavailable())?;
        let owner = owner
            .map(|value| usize::try_from(value).map(|value| HWND(value as *mut core::ffi::c_void)))
            .transpose()
            .map_err(|_| unavailable())?;
        let dpi = initial_dpi(owner);
        let rectangle = outer_rectangle(width, height, dpi)?;
        let (width, height) = dimensions(&rectangle)?;
        let (x, y) = centered(owner, width, height)?;
        // SAFETY: registered system-procedure class and static title;
        // checked scalar placement/size and optional opaque owner HWND. The
        // window is top-level, never child or message-only, and starts hidden.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("PiglorOS.OwnerBridge.v1"),
                w!("PiglorOS — confirm identity"),
                WS_OVERLAPPEDWINDOW,
                x,
                y,
                width,
                height,
                owner,
                None,
                Some(HINSTANCE(executable.0)),
                None,
            )
        }
        .map_err(|_| unavailable())?;
        let signals = Rc::new(WindowSignals::default());
        WINDOWS.with(|windows| {
            windows
                .borrow_mut()
                .insert(hwnd.0 as usize, Rc::downgrade(&signals))
        });
        Ok(Self { hwnd, signals })
    }

    pub(super) const fn handle(&self) -> HWND {
        self.hwnd
    }

    pub(super) fn show(&self) {
        // SAFETY: live owned top-level window on this STA. This return value
        // reports prior visibility, not whether showing succeeded.
        let _previous_visibility = unsafe { ShowWindow(self.hwnd, SW_SHOWNORMAL) };
        // SAFETY: live owned window. Foreground rights may deny the request;
        // the caller independently verifies the actual foreground within 1s.
        let _requested = unsafe { SetForegroundWindow(self.hwnd) };
    }

    pub(super) fn foreground(&self) -> bool {
        // SAFETY: a scalar observation of the current foreground HWND.
        let mut foreground = unsafe { GetForegroundWindow() };
        let mut seen = std::collections::BTreeSet::new();
        while !foreground.0.is_null() && seen.insert(foreground.0 as usize) {
            if foreground == self.hwnd {
                return true;
            }
            // SAFETY: HWNDs are opaque identifiers checked by Windows. This
            // queries the owner chain without dereferencing process memory.
            let owner = unsafe { GetWindow(foreground, GW_OWNER) };
            let Ok(owner) = owner else {
                return false;
            };
            foreground = owner;
        }
        false
    }

    pub(super) fn bounds(&self) -> Result<RECT> {
        let mut rectangle = RECT::default();
        // SAFETY: live owned window and distinct initialized writable RECT.
        unsafe { GetClientRect(self.hwnd, &raw mut rectangle) }.map_err(|_| unavailable())?;
        Ok(rectangle)
    }

    pub(super) fn snapshot(&self) -> Result<WindowSnapshot> {
        // SAFETY: scalar existence observation of our STA-owned HWND. No new
        // ceremony window is created before this session's retirement ends.
        let exists = unsafe { IsWindow(Some(self.hwnd)) }.as_bool();
        if !exists {
            self.signals.destroyed.set(true);
            return Ok(WindowSnapshot {
                exists: false,
                close_requested: self.signals.close_requested.get(),
                dpi: 0,
                client: ClientBounds {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
                foreground: false,
            });
        }
        // SAFETY: our still-live creating-STA HWND; scalar observation only.
        let dpi = unsafe { GetDpiForWindow(self.hwnd) };
        let bounds = self.bounds()?;
        Ok(WindowSnapshot {
            exists: true,
            close_requested: self.signals.close_requested.get(),
            dpi,
            client: ClientBounds {
                left: bounds.left,
                top: bounds.top,
                right: bounds.right,
                bottom: bounds.bottom,
            },
            foreground: self.foreground(),
        })
    }

    pub(super) fn resize(&self, width: u32, height: u32, dpi: u32) -> Result<()> {
        let (width, height) = dimensions(&outer_rectangle(width, height, dpi)?)?;
        // SAFETY: checked dimensions and live STA HWND, preserving position,
        // stacking and activation. No retained application pointer.
        unsafe {
            SetWindowPos(
                self.hwnd,
                None,
                0,
                0,
                width,
                height,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            )
        }
        .map_err(|_| unavailable())
    }

    pub(super) fn destroy(&mut self) -> Result<()> {
        if self.hwnd.0.is_null() {
            return Ok(());
        }
        if !self.signals.destroyed.get() {
            // SAFETY: exactly one successful destruction of this STA-owned
            // window after normal controller/buffer/environment cleanup.
            unsafe { DestroyWindow(self.hwnd) }.map_err(|_| unavailable())?;
        }
        WINDOWS.with(|windows| windows.borrow_mut().remove(&(self.hwnd.0 as usize)));
        self.hwnd = HWND::default();
        Ok(())
    }
}

fn initial_dpi(owner: Option<HWND>) -> u32 {
    if let Some(owner) = owner {
        // SAFETY: query the supplied opaque owner HWND; a zero readback fails
        // later checked dimension conversion rather than selecting a fallback.
        unsafe { GetDpiForWindow(owner) }
    } else {
        // SAFETY: scalar system DPI query for placement on the primary monitor.
        unsafe { GetDpiForSystem() }
    }
}

fn outer_rectangle(width: u32, height: u32, dpi: u32) -> Result<RECT> {
    if dpi == 0 {
        return Err(unavailable());
    }
    let scaled = |logical: u32| {
        i32::try_from((u64::from(logical) * u64::from(dpi) + 48) / 96).map_err(|_| unavailable())
    };
    let mut rectangle = RECT {
        left: 0,
        top: 0,
        right: scaled(width)?,
        bottom: scaled(height)?,
    };
    // SAFETY: initialized writable client RECT, fixed top-level style, no menu,
    // checked nonzero DPI and no retained pointer.
    unsafe {
        AdjustWindowRectExForDpi(
            &raw mut rectangle,
            WS_OVERLAPPEDWINDOW,
            false,
            WINDOW_EX_STYLE(0),
            dpi,
        )
    }
    .map_err(|_| unavailable())?;
    Ok(rectangle)
}

fn dimensions(rectangle: &RECT) -> Result<(i32, i32)> {
    rectangle
        .right
        .checked_sub(rectangle.left)
        .zip(rectangle.bottom.checked_sub(rectangle.top))
        .filter(|(width, height)| *width > 0 && *height > 0)
        .ok_or_else(unavailable)
}

fn centered(owner: Option<HWND>, width: i32, height: i32) -> Result<(i32, i32)> {
    // SAFETY: opaque optional owner HWND; Windows selects its monitor or the
    // primary monitor when no window is supplied. No application pointer.
    let monitor = unsafe { MonitorFromWindow(owner.unwrap_or_default(), MONITOR_DEFAULTTOPRIMARY) };
    let mut information = MONITORINFO {
        cbSize: 40,
        ..MONITORINFO::default()
    };
    // SAFETY: monitor returned by Windows, initialized MONITORINFO of its
    // documented 40-byte layout, distinct writable output.
    if !unsafe { GetMonitorInfoW(monitor, &raw mut information) }.as_bool() {
        return Err(unavailable());
    }
    let work = information.rcWork;
    let (work_width, work_height) = dimensions(&work)?;
    work.left
        .checked_add((work_width - width) / 2)
        .zip(work.top.checked_add((work_height - height) / 2))
        .ok_or_else(unavailable)
}

const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Window,
        failure: Failure::CallFailed,
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // Normal finish checks destruction. Failed opening has no secret-bearing
        // buffers; the host retains any pending COM operation separately.
        let _destroyed = self.destroy();
    }
}
