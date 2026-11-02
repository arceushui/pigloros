#![cfg(windows)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_ANY,
    RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY,
};

pub(super) fn query_policy(
    machine: bool,
    view64: bool,
    subkey: &[u16],
    name: &[u16],
) -> WIN32_ERROR {
    let root = if machine {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let view = if view64 {
        RRF_SUBKEY_WOW6464KEY
    } else {
        RRF_SUBKEY_WOW6432KEY
    };
    // SAFETY: both strings are owned, NUL-terminated UTF-16 supplied by the
    // private adapter. The predefined hive is borrowed; no output buffer or
    // handle is acquired, and the synchronous call retains no pointer.
    unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_ANY | RRF_NOEXPAND | view,
            None,
            None,
            None,
        )
    }
}
