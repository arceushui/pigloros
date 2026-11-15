#![cfg(windows)]
#![forbid(unsafe_code)]

use windows::Win32::Foundation::{RECT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{MSG, SC_CLOSE, WM_CLOSE, WM_SYSCOMMAND};

use super::{dimensions, intercept, outer_rectangle, Window};
use crate::NativeError;

#[test]
fn close_interception_signals_only_the_registered_owned_window() -> Result<(), NativeError> {
    let mut first = Window::create(None, 320, 240)?;
    let mut second = Window::create(None, 320, 240)?;
    let unrelated_message = MSG {
        hwnd: first.handle(),
        ..MSG::default()
    };
    assert!(!intercept(&unrelated_message));
    assert!(!first.snapshot()?.close_requested);
    let close = MSG {
        hwnd: first.handle(),
        message: WM_CLOSE,
        ..MSG::default()
    };
    assert!(intercept(&close));
    assert!(first.snapshot()?.close_requested);
    assert!(!second.snapshot()?.close_requested);
    let system_close = MSG {
        hwnd: second.handle(),
        message: WM_SYSCOMMAND,
        wParam: WPARAM(SC_CLOSE as usize | 0x0001),
        ..MSG::default()
    };
    assert!(intercept(&system_close));
    assert!(second.snapshot()?.close_requested);
    first.destroy()?;
    let retired = first.snapshot()?;
    assert!(!retired.exists);
    assert!(retired.close_requested);
    assert_eq!(retired.dpi, 0);
    assert_eq!(
        retired.client,
        crate::ClientBounds {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        }
    );
    assert!(!intercept(&close));
    assert!(!intercept(&MSG {
        message: WM_CLOSE,
        ..MSG::default()
    }));
    second.destroy()
}

#[test]
fn window_geometry_refuses_zero_dpi_and_unrepresentable_dimensions() {
    assert!(outer_rectangle(480, 640, 0).is_err());
    assert!(outer_rectangle(u32::MAX, 640, u32::MAX).is_err());
    assert!(dimensions(&RECT::default()).is_err());
    assert!(dimensions(&RECT {
        left: i32::MIN,
        top: 0,
        right: i32::MAX,
        bottom: 1,
    })
    .is_err());
}
