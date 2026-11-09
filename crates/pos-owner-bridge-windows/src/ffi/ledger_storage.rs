#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

pub fn replace_ledger(temporary: &Path, ledger: &Path) -> Result<(), ()> {
    let temporary: Vec<u16> = temporary.as_os_str().encode_wide().chain([0]).collect();
    let ledger: Vec<u16> = ledger.as_os_str().encode_wide().chain([0]).collect();
    if temporary[..temporary.len() - 1].contains(&0) || ledger[..ledger.len() - 1].contains(&0) {
        return Err(());
    }
    // SAFETY: both terminated paths remain live through the call; the caller
    // qualified their same directory and flushed and closed the temporary file.
    // No cross-volume copy is requested; uncertainty is left for recovery.
    unsafe {
        MoveFileExW(
            PCWSTR(temporary.as_ptr()),
            PCWSTR(ledger.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| ())
}
