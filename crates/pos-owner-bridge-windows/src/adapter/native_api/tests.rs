#![cfg(windows)]
#![forbid(unsafe_code)]

use super::{Failure, NativeError, NativePath, NativeText, Operation, MAX_TEXT_UNITS};

#[test]
fn bounded_native_snapshots_preserve_paths_and_reject_invalid_display_text(
) -> Result<(), NativeError> {
    let display = NativeText::from_utf16(&[0x61, 0x20ac])?;
    assert_eq!(display.as_str(), "a€");
    assert_eq!(NativeText::from_utf16(&[])?.as_str(), "");
    assert_eq!(
        NativeText::from_utf16(&[0xd800])
            .err()
            .map(|error| error.failure),
        Some(Failure::InvalidOutput)
    );
    let excessive = vec![0x61; MAX_TEXT_UNITS + 1];
    assert_eq!(
        NativeText::from_utf16(&excessive)
            .err()
            .map(|error| error.failure),
        Some(Failure::TooLarge)
    );
    assert_eq!(
        NativePath::from_utf16(&excessive)
            .err()
            .map(|error| error.failure),
        Some(Failure::TooLarge)
    );
    assert_eq!(
        NativePath::from_utf16(&[0x61, 0])
            .err()
            .map(|error| error.failure),
        Some(Failure::InvalidOutput)
    );
    let path = NativePath::from_utf16(&[0x43, 0x3a, 0x5c, 0xd800])?;
    use std::os::windows::ffi::OsStrExt;
    assert_eq!(
        path.as_path().as_os_str().encode_wide().collect::<Vec<_>>(),
        [0x43, 0x3a, 0x5c, 0xd800]
    );
    let debug = format!("{display:?}");
    assert!(!debug.contains('€'));
    assert!(debug.contains("bytes"));
    let error = NativeError {
        operation: Operation::Text,
        failure: Failure::InvalidOutput,
    };
    assert_eq!(error.to_string(), "Text: InvalidOutput");
    Ok(())
}
