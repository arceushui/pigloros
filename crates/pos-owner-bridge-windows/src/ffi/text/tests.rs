#![cfg(windows)]
#![forbid(unsafe_code)]

use super::{bounded_units, read_path, read_text};
use crate::{Failure, NativeError, MAX_TEXT_UNITS};
use windows::core::{Error, HRESULT};

#[test]
fn native_text_getter_null_and_failure_have_distinct_results() -> Result<(), NativeError> {
    assert_eq!(read_text(|_| Ok(()))?.as_str(), "");
    assert!(read_path(|_| Ok(()))?.as_path().as_os_str().is_empty());
    let getter_error = Error::from_hresult(HRESULT(-1));
    assert_eq!(
        read_text(|_| Err(getter_error))
            .err()
            .map(|error| error.failure),
        Some(Failure::CallFailed)
    );
    Ok(())
}

#[test]
fn native_text_scan_bounds_and_first_nul_are_exact() -> Result<(), NativeError> {
    let units = [0x61, 0x20ac, 0, 0x62];
    let mut reads = Vec::new();
    assert_eq!(
        bounded_units(|index| {
            reads.push(index);
            units[index]
        })?,
        [0x61, 0x20ac]
    );
    assert_eq!(reads, [0, 1, 2]);
    let exact = bounded_units(|index| if index == MAX_TEXT_UNITS { 0 } else { 0x61 })?;
    assert_eq!(exact.len(), MAX_TEXT_UNITS);
    let mut count = 0;
    assert_eq!(
        bounded_units(|_| {
            count += 1;
            0x61
        })
        .err()
        .map(|error| error.failure),
        Some(Failure::TooLarge)
    );
    assert_eq!(count, MAX_TEXT_UNITS + 1);
    Ok(())
}
