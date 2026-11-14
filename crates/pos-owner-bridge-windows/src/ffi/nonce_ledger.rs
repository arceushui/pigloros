#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]

use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use super::directory::{current_sid, LocalMemory};

static PROCESS_ADMISSION: AtomicBool = AtomicBool::new(false);

fn descriptor(sid: &str) -> Result<LocalMemory, ()> {
    descriptor_for(sid, sid)
}

fn descriptor_for(owner: &str, principal: &str) -> Result<LocalMemory, ()> {
    // MUTEX_ALL_ACCESS is 0x001f0001; an explicit mask avoids generic mapping
    // differences between a newly constructed descriptor and an object readback.
    let text: Vec<u16> = format!("O:{owner}D:P(A;;0x001f0001;;;{principal})")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut output = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the NUL-terminated SDDL and initialized output live throughout
    // the call; the successful allocated descriptor transfers to LocalMemory.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &raw mut output,
            None,
        )
    }
    .map_err(|_| ())?;
    Ok(LocalMemory(HLOCAL(output.0)))
}

fn descriptor_text(descriptor: &LocalMemory) -> Result<String, ()> {
    let mut output = PWSTR::null();
    // SAFETY: descriptor points to a live Windows-allocated security descriptor;
    // successful output is a separate allocation owned below.
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
    // SAFETY: successful conversion returned a NUL-terminated string which
    // remains allocated until the copied Rust string has been constructed.
    unsafe { output.to_string() }.map_err(|_| ())
}

fn validate_descriptor(handle: HANDLE, expected: &LocalMemory) -> Result<(), ()> {
    let mut output = PSECURITY_DESCRIPTOR::default();
    // SAFETY: handle is live and has READ_CONTROL, and output is initialized and
    // uniquely writable; the successful descriptor is freed exactly once.
    unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
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
    let observed = LocalMemory(HLOCAL(output.0));
    if descriptor_text(&observed)? != descriptor_text(expected)? {
        return Err(());
    }
    Ok(())
}

impl std::fmt::Debug for crate::SubjectMutex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubjectMutex")
            .finish_non_exhaustive()
    }
}

impl crate::SubjectMutex {
    pub(crate) fn acquire() -> Result<Self, ()> {
        if PROCESS_ADMISSION
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(());
        }
        if let Ok((handle, abandoned)) = acquire_inner() {
            #[cfg(not(test))]
            let _ = abandoned;
            Ok(Self {
                handle,
                #[cfg(test)]
                abandoned,
                _thread_bound: std::marker::PhantomData,
            })
        } else {
            PROCESS_ADMISSION.store(false, Ordering::Release);
            Err(())
        }
    }

    #[cfg(test)]
    pub(crate) fn retain_second_handle() -> Result<crate::RetainedMutex, ()> {
        open_verified().map(crate::RetainedMutex)
    }

    #[cfg(test)]
    pub(crate) const fn was_abandoned(&self) -> bool {
        self.abandoned
    }

    #[cfg(test)]
    pub(crate) fn exercise_security_refusals() -> Result<(), ()> {
        if descriptor("not-a-sid").is_ok() {
            return Err(());
        }
        let expected = descriptor(&current_sid()?)?;
        if validate_descriptor(HANDLE::default(), &expected).is_ok() {
            return Err(());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn create_wrong_acl_fixture() -> Result<crate::RetainedMutex, ()> {
        let sid = current_sid()?;
        let security = descriptor_for(&sid, "S-1-1-0")?;
        let name: Vec<u16> = format!("Global\\pigloros.subject-encryptor.v1.{sid}")
            .encode_utf16()
            .chain([0])
            .collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| ())?,
            lpSecurityDescriptor: security.0 .0,
            bInheritHandle: false.into(),
        };
        // SAFETY: terminated SID-derived name and initialized attributes stay
        // live; ownership is false and the fixture closes its handle once.
        let handle =
            unsafe { CreateMutexW(Some(&raw const attributes), false, PCWSTR(name.as_ptr())) }
                .map_err(|_| ())?;
        let fixture = crate::RetainedMutex(handle);
        validate_descriptor(handle, &security)?;
        Ok(fixture)
    }
}

fn open_verified() -> Result<HANDLE, ()> {
    let sid = current_sid()?;
    let security = descriptor(&sid)?;
    let name: Vec<u16> = format!("Global\\pigloros.subject-encryptor.v1.{sid}")
        .encode_utf16()
        .chain([0])
        .collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| ())?,
        lpSecurityDescriptor: security.0 .0,
        bInheritHandle: false.into(),
    };
    // SAFETY: the SID-derived name and complete attributes outlive the call;
    // initial ownership is false and the returned handle is non-inheritable.
    let handle = unsafe { CreateMutexW(Some(&raw const attributes), false, PCWSTR(name.as_ptr())) }
        .map_err(|_| ())?;
    if validate_descriptor(handle, &security).is_err() {
        // SAFETY: initial ownership was false; this closes the one handle
        // returned by CreateMutexW without releasing the mutex.
        let _closed = unsafe { CloseHandle(handle) };
        return Err(());
    }
    Ok(handle)
}

fn acquire_inner() -> Result<(HANDLE, bool), ()> {
    let handle = open_verified()?;
    // SAFETY: the live mutex handle is not closed during this zero-time wait.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 => Ok((handle, false)),
        WAIT_ABANDONED => Ok((handle, true)),
        _ => {
            // SAFETY: this wait did not acquire the mutex, so the one open
            // handle is closed without attempting a release.
            let _closed = unsafe { CloseHandle(handle) };
            Err(())
        }
    }
}

#[cfg(test)]
impl Drop for crate::RetainedMutex {
    fn drop(&mut self) {
        // SAFETY: this fixture never waited on its separately opened handle;
        // its sole ownership is the handle and it is closed exactly once.
        let _closed = unsafe { CloseHandle(self.0) };
    }
}

impl Drop for crate::SubjectMutex {
    fn drop(&mut self) {
        // SAFETY: the non-Send guard is dropped by its owning thread, after
        // exactly one successful or abandoned wait and before handle close.
        let released = unsafe { ReleaseMutex(self.handle) }.is_ok();
        // SAFETY: this guard owns exactly one open mutex handle, now closed once.
        let closed = unsafe { CloseHandle(self.handle) }.is_ok();
        if released && closed {
            PROCESS_ADMISSION.store(false, Ordering::Release);
        }
    }
}
