#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, SetSecurityDescriptorControl, TokenUser, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR_CONTROL, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct LocalMemory(HLOCAL);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: this owner holds exactly one successful Windows LocalAlloc
        // output. Every borrowed descriptor/string has finished using it.
        let _released = unsafe { LocalFree(Some(self.0)) };
    }
}

fn allocated_text(text: PWSTR) -> Result<String, ()> {
    let _allocation = LocalMemory(HLOCAL(text.0.cast()));
    // SAFETY: a successful SID/descriptor conversion returned an allocated,
    // NUL-terminated UTF-16 string, kept live by _allocation through this copy.
    unsafe { text.to_string() }.map_err(|_| ())
}

fn current_sid() -> Result<String, ()> {
    // SAFETY: this API returns a borrowed pseudo-handle for the current process.
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: query-only access to our current process token; initialized output
    // is uniquely owned after success and is closed on every later result.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.map_err(|_| ())?;
    let result = token_sid(token);
    // SAFETY: this is the single close of the token acquired above, after the
    // SID and every query output have been copied to Rust-owned storage.
    let closed = unsafe { CloseHandle(token) }.map_err(|_| ());
    result.and_then(|sid| closed.map(|()| sid))
}

fn token_sid(token: HANDLE) -> Result<String, ()> {
    // TOKEN_USER plus the largest Windows SID fits well inside 1024 bytes.
    // u64 storage supplies TOKEN_USER alignment on the supported x64 profile.
    let mut storage = [0_u64; 128];
    let mut length = 0_u32;
    // SAFETY: live query-only token; initialized, aligned 1024-byte output and
    // a distinct writable returned-length value remain live through the call.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            1024,
            &raw mut length,
        )
    }
    .map_err(|_| ())?;
    if length < u32::try_from(std::mem::size_of::<TOKEN_USER>()).map_err(|_| ())? || length > 1024 {
        return Err(());
    }
    // SAFETY: successful TokenUser wrote a TOKEN_USER at this aligned base.
    // Copying the POD leaves its SID pointing into storage, which stays live.
    let user = unsafe { storage.as_ptr().cast::<TOKEN_USER>().read() };
    let mut text = PWSTR::null();
    // SAFETY: the successful TokenUser result supplies the valid SID within
    // storage; the conversion allocates its own independent string output.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut text) }.map_err(|_| ())?;
    allocated_text(text)
}

fn expected_descriptor() -> Result<LocalMemory, ()> {
    let sid = current_sid()?;
    let text: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: owned NUL-terminated SDDL from the OS's own SID representation;
    // initialized output is transferred exactly once to LocalMemory on success.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|_| ())?;
    Ok(LocalMemory(HLOCAL(descriptor.0)))
}

fn descriptor_text(descriptor: &LocalMemory) -> Result<String, ()> {
    // Automatic-propagation bookkeeping may change after an ACL edit even
    // when owner, protection, sole principal, rights and ACE flags are restored.
    // Normalize only those two bookkeeping bits in this allocated COPY.
    // SAFETY: writable Windows-allocated descriptor remains uniquely owned.
    // This never changes filesystem security, SE_DACL_PROTECTED or any ACE.
    unsafe {
        SetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(descriptor.0 .0),
            SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ,
            SECURITY_DESCRIPTOR_CONTROL(0),
        )
    }
    .map_err(|_| ())?;
    let mut text = PWSTR::null();
    // SAFETY: the live LocalMemory holds a valid security descriptor returned
    // by Windows. Only owner/DACL information is requested; output is owned.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(descriptor.0 .0),
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    }
    .map_err(|_| ())?;
    allocated_text(text)
}

fn read_descriptor(path: &[u16]) -> Result<LocalMemory, ()> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: owned NUL-terminated path; initialized descriptor output; other
    // outputs are omitted. Successful output is owned until its LocalFree.
    unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &raw mut descriptor,
        )
    }
    .ok()
    .map_err(|_| ())?;
    Ok(LocalMemory(HLOCAL(descriptor.0)))
}

impl crate::Native {
    pub(crate) fn file_identity(file: &std::fs::File) -> Result<(u32, u64), ()> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the borrowed File retains its live handle throughout this
        // synchronous metadata query; the initialized output is uniquely writable.
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information) }
            .map_err(|_| ())
            .map(|()| {
                (
                    information.dwVolumeSerialNumber,
                    (u64::from(information.nFileIndexHigh) << 32)
                        | u64::from(information.nFileIndexLow),
                )
            })
    }

    pub(crate) fn private_directory(path: &Path, create: bool) -> Result<(), ()> {
        let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
        if path.contains(&0) {
            return Err(());
        }
        path.push(0);
        let expected = expected_descriptor()?;
        if create {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .map_err(|_| ())?,
                lpSecurityDescriptor: expected.0 .0,
                bInheritHandle: false.into(),
            };
            // SAFETY: path and the complete initialized SECURITY_ATTRIBUTES
            // outlive this synchronous call. Its descriptor is live, protected,
            // current-SID-only, and handle inheritance is disabled.
            unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&raw const attributes)) }
                .map_err(|_| ())?;
        }
        let actual = read_descriptor(&path)?;
        // Both descriptors use Windows' same canonical SDDL conversion. An
        // additional ACE, inherited DACL, different owner or weaker mask fails.
        if descriptor_text(&actual)? != descriptor_text(&expected)? {
            return Err(());
        }
        Ok(())
    }
}
