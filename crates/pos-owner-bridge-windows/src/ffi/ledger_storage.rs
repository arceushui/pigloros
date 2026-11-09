#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]

use std::fs::File;
use std::os::windows::ffi::OsStrExt;
#[cfg(test)]
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::core::PCWSTR;
#[cfg(test)]
use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, MoveFileExW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

use super::directory::LocalMemory;

impl crate::Native {
    #[cfg(test)]
    pub(crate) fn fixture_handle_not_inheritable(file: &File) -> bool {
        let mut flags = 0_u32;
        // SAFETY: the borrowed File owns a live handle; flags is initialized,
        // writable, and the read-only query neither closes nor transfers it.
        unsafe { GetHandleInformation(HANDLE(file.as_raw_handle()), &raw mut flags) }.is_ok()
            && flags & HANDLE_FLAG_INHERIT.0 == 0
    }

    pub(crate) fn create_private_ledger_file(path: &Path) -> Result<File, ()> {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        if path[..path.len() - 1].contains(&0) {
            return Err(());
        }
        let sid = super::directory::current_sid()?;
        let text: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut output = PSECURITY_DESCRIPTOR::default();
        // SAFETY: terminated SID-derived descriptor input and initialized output
        // remain live; a successful allocation transfers into LocalMemory.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &raw mut output,
                None,
            )
        }
        .map_err(|_| ())?;
        let security = LocalMemory(HLOCAL(output.0));
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| ())?,
            lpSecurityDescriptor: security.0 .0,
            bInheritHandle: false.into(),
        };
        // SAFETY: path and descriptor are terminated/live; attributes are valid
        // and non-inheritable. CREATE_NEW never opens an existing target.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                Some(&raw const attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                None,
            )
        }
        .map_err(|_| ())?;
        // SAFETY: successful CreateFileW yields a valid uniquely owned handle;
        // transfer exactly once to OwnedHandle, then File, with no second close.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        Ok(File::from(owned))
    }

    pub(crate) fn replace_ledger(temporary: &Path, ledger: &Path) -> Result<(), ()> {
        let temporary: Vec<u16> = temporary.as_os_str().encode_wide().chain([0]).collect();
        let ledger: Vec<u16> = ledger.as_os_str().encode_wide().chain([0]).collect();
        if temporary[..temporary.len() - 1].contains(&0) || ledger[..ledger.len() - 1].contains(&0)
        {
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
}
