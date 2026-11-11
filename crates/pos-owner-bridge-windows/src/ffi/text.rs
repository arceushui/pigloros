#![cfg(windows)]

use webview2_com::CoTaskMemPWSTR;
use windows::core::PWSTR;

use crate::{
    Failure, NativeError, NativePath, NativeResult, NativeText, Operation, MAX_TEXT_UNITS,
};

fn extract(read: impl FnOnce(*mut PWSTR) -> windows::core::Result<()>) -> NativeResult<Vec<u16>> {
    let mut raw = PWSTR::null();
    let result = read(&raw mut raw);
    let _memory = CoTaskMemPWSTR::from(raw);
    result.map_err(|_| failure(Failure::CallFailed))?;
    if raw.is_null() {
        return Ok(Vec::new());
    }
    bounded_units(|index| {
        // SAFETY: the successful getter transfers a valid NUL-terminated COM
        // allocation retained by _memory. Read only through its first NUL or
        // the fixed extraction bound, whichever occurs first. No unbounded
        // length scan, borrowed native string, or native allocation escapes.
        unsafe { raw.0.wrapping_add(index).read() }
    })
}

fn bounded_units(mut read: impl FnMut(usize) -> u16) -> NativeResult<Vec<u16>> {
    let mut units = Vec::new();
    for index in 0..=MAX_TEXT_UNITS {
        let unit = read(index);
        if unit == 0 {
            return Ok(units);
        }
        if index < MAX_TEXT_UNITS {
            units.push(unit);
        }
    }
    Err(failure(Failure::TooLarge))
}

pub(super) fn read_text(
    read: impl FnOnce(*mut PWSTR) -> windows::core::Result<()>,
) -> NativeResult<NativeText> {
    NativeText::from_utf16(&extract(read)?)
}

pub(super) fn read_path(
    read: impl FnOnce(*mut PWSTR) -> windows::core::Result<()>,
) -> NativeResult<NativePath> {
    NativePath::from_utf16(&extract(read)?)
}

const fn failure(failure: Failure) -> NativeError {
    NativeError {
        operation: Operation::Text,
        failure,
    }
}

#[cfg(test)]
mod tests;
