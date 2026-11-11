#![cfg(windows)]
#![forbid(unsafe_code)]

use crate::{Failure, NativeError, NativePath, NativeText, Operation, MAX_TEXT_UNITS};
use std::os::windows::ffi::OsStrExt;

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

#[test]
fn modeled_retained_membership_requires_nonzero_pid_and_bounded_count() {
    use crate::ExitMembershipKind::{Browser, Other};
    assert!(crate::retained_exit_membership(&[], 0).is_err());
    assert!(crate::retained_exit_membership(&[], 42).is_ok());
    let mut entries = vec![(42, Browser)];
    entries.extend((100..163).map(|pid| (pid, Other)));
    assert!(crate::retained_exit_membership(&entries, 42).is_ok());
    entries.push((163, Other));
    assert!(crate::retained_exit_membership(&entries, 42).is_err());
}
