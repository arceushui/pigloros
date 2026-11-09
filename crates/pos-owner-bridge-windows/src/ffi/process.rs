#![cfg(windows)]

//! One limited-information handle; no enumeration, signalling or termination.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use pos_owner_bridge::ProcessIdentity;
use pos_owner_bridge_codec::ImagePathSha256;
use sha2::{Digest, Sha256};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

pub(super) fn inspect(pid: u32) -> Result<Option<(ProcessIdentity, PathBuf)>, ()> {
    // PID zero is a special invalid argument, not evidence of a missing process.
    if pid == 0 {
        return Err(());
    }
    // SAFETY: the access mask is fixed to query-only, inheritance is disabled,
    // and the supplied PID is only an identifier; no caller pointer is passed.
    let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let handle = match opened {
        Ok(handle) => handle,
        // All other arguments are fixed valid values. A nonzero invalid PID is
        // absence; access denial and every other failed inspection stay unknown.
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(None),
        Err(_) => return Err(()),
    };
    let observed = read_identity(handle, pid);
    // SAFETY: this is the single close of the successfully opened handle, after
    // every query finishes. All query failures pass through this same close.
    let closed = unsafe { CloseHandle(handle) };
    observed.and_then(|identity| closed.map(|()| Some(identity)).map_err(|_| ()))
}

pub(super) fn read_identity(handle: HANDLE, pid: u32) -> Result<(ProcessIdentity, PathBuf), ()> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the live handle with query rights outlives this call; the four output
    // pointers refer to distinct initialized, writable FILETIME values.
    let times = unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    times.map_err(|_| ()).and_then(|()| {
        image_digest(handle).map(|(image_path_sha256, path)| {
            (
                ProcessIdentity {
                    browser_pid: pid,
                    creation_filetime: (u64::from(creation.dwHighDateTime) << 32)
                        | u64::from(creation.dwLowDateTime),
                    image_path_sha256,
                },
                path,
            )
        })
    })
}

fn image_digest(handle: HANDLE) -> Result<(ImagePathSha256, PathBuf), ()> {
    // The Win32 extended path bound. An insufficient buffer is indeterminate;
    // it never changes the observation to absence.
    let mut image = vec![0_u16; 32_768].into_boxed_slice();
    let mut length = 32_768_u32;
    // SAFETY: image owns length UTF-16 code units for the duration of the call;
    // the handle is live and length is an initialized in/out bound.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(image.as_mut_ptr()),
            &raw mut length,
        )
    };
    queried.map_err(|_| ()).and_then(|()| {
        let image = image
            .get(..length as usize)
            .filter(|image| !image.is_empty())
            .ok_or(())?;
        // PBCR stores the exact returned UTF-16LE path digest, without lossy
        // conversion. The same handle observation supplies the activation path.
        let mut digest = Sha256::new();
        for unit in image {
            digest.update(unit.to_le_bytes());
        }
        Ok((
            ImagePathSha256::from_bytes(digest.finalize().into()),
            PathBuf::from(OsString::from_wide(image)),
        ))
    })
}
