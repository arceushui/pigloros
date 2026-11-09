#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]

use std::fs::File;
use std::os::windows::io::AsRawHandle;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    SetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ,
};
use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

use super::directory::current_sid;

struct LocalMemory(HLOCAL);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: this owner frees exactly one successful LocalAlloc output.
        let _released = unsafe { LocalFree(Some(self.0)) };
    }
}

fn descriptor_text(descriptor: &LocalMemory) -> Result<String, ()> {
    // Normalize automatic-inheritance bookkeeping on this allocated copy only;
    // keep DACL protection, every ACE flag and all permissions unchanged.
    // SAFETY: the Windows-allocated descriptor is writable and uniquely owned.
    unsafe {
        SetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(descriptor.0 .0),
            SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ,
            SECURITY_DESCRIPTOR_CONTROL(0),
        )
    }
    .map_err(|_| ())?;
    let mut output = PWSTR::null();
    // SAFETY: the descriptor is live; the initialized output receives a newly
    // allocated NUL-terminated string, which is freed after the copy.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(descriptor.0 .0),
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut output,
            None,
        )
    }
    .map_err(|_| ())?;
    let _allocation = LocalMemory(HLOCAL(output.0.cast()));
    // SAFETY: the successful conversion returned an allocated terminated string
    // that remains live until this Rust-owned copy has been constructed.
    unsafe { output.to_string() }.map_err(|_| ())
}

fn expected(sid: &str, protected: bool, inherited: bool) -> Result<String, ()> {
    let protection = if protected { "P" } else { "" };
    let inheritance = if inherited { "ID" } else { "" };
    let text: Vec<u16> = format!("O:{sid}D:{protection}(A;{inheritance};FA;;;{sid})")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut output = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SID-derived terminated SDDL and initialized output remain
    // live during the call; the successful allocation has exactly one owner.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &raw mut output,
            None,
        )
    }
    .map_err(|_| ())?;
    descriptor_text(&LocalMemory(HLOCAL(output.0)))
}

pub fn require_private_file(file: &File) -> Result<(), ()> {
    let mut output = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the borrowed File keeps its handle live throughout this query;
    // output is uniquely writable and its successful allocation is freed once.
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut output),
        )
    }
    .ok()
    .map_err(|_| ())?;
    let actual = descriptor_text(&LocalMemory(HLOCAL(output.0)))?;
    let sid = current_sid()?;
    for protected in [false, true] {
        for inherited in [false, true] {
            if actual == expected(&sid, protected, inherited)? {
                return Ok(());
            }
        }
    }
    Err(())
}

pub fn file_link_count(file: &File) -> Result<u32, ()> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the borrowed File keeps its handle live, and the initialized
    // output is uniquely writable for the duration of this synchronous query.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information) }
        .map_err(|_| ())?;
    Ok(information.nNumberOfLinks)
}
