#![cfg(windows)]

use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetVolumeInformationByHandleW, GetVolumeInformationW, GetVolumePathNameW,
    MoveFileExW, MOVEFILE_WRITE_THROUGH,
};

fn wide(path: &Path) -> Result<Vec<u16>, ()> {
    let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.contains(&0) {
        return Err(());
    }
    units.push(0);
    Ok(units)
}

impl crate::Native {
    pub(crate) fn cleanup_path_ntfs(path: &Path) -> Result<(), ()> {
        let path = wide(path)?;
        let mut mount = vec![0_u16; crate::MAX_TEXT_UNITS];
        // SAFETY: owned NUL-terminated DOS path and distinct initialized bounded
        // writable mount-point storage remain live for this synchronous query.
        unsafe { GetVolumePathNameW(PCWSTR(path.as_ptr()), &mut mount) }.map_err(|_| ())?;
        let end = mount.iter().position(|unit| *unit == 0).ok_or(())?;
        if end == 0 {
            return Err(());
        }
        mount.truncate(end + 1);
        // SAFETY: the successful mount query supplied this owned NUL-terminated
        // root. Only the OS drive classification is queried, without side effects.
        if unsafe { GetDriveTypeW(PCWSTR(mount.as_ptr())) } != 3 {
            return Err(());
        }
        let mut filesystem = [0_u16; 32];
        // SAFETY: live mount string and initialized distinct filesystem output;
        // unused outputs are absent and no volume-wide flush is requested.
        unsafe {
            GetVolumeInformationW(
                PCWSTR(mount.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut filesystem),
            )
        }
        .map_err(|_| ())?;
        require_ntfs(&filesystem)
    }

    pub(crate) fn cleanup_file_volume(file: &File) -> Result<u32, ()> {
        let mut serial = 0_u32;
        let mut filesystem = [0_u16; 32];
        // SAFETY: File retains the borrowed live handle throughout this query;
        // initialized serial and filesystem outputs are distinct and writable.
        unsafe {
            GetVolumeInformationByHandleW(
                HANDLE(file.as_raw_handle()),
                None,
                Some(&raw mut serial),
                None,
                None,
                Some(&mut filesystem),
            )
        }
        .map_err(|_| ())?;
        require_ntfs(&filesystem)?;
        Ok(serial)
    }

    pub(crate) fn publish_cleanup(pending: &Path, committed: &Path) -> Result<(), ()> {
        let pending = wide(pending)?;
        let committed = wide(committed)?;
        // SAFETY: owned NUL-terminated same-directory paths. WRITE_THROUGH alone
        // never requests replacement or cross-volume copy; the store owns the
        // flushed, closed pending file and preserves either name on uncertainty.
        unsafe {
            MoveFileExW(
                PCWSTR(pending.as_ptr()),
                PCWSTR(committed.as_ptr()),
                MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| ())
    }
}

fn require_ntfs(filesystem: &[u16; 32]) -> Result<(), ()> {
    if filesystem[..5] != [78, 84, 70, 83, 0] {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    #[test]
    fn modeled_volume_name_requires_the_exact_ntfs_terminated_prefix() {
        let mut name = [0_u16; 32];
        name[..5].copy_from_slice(&[78, 84, 70, 83, 0]);
        assert_eq!(super::require_ntfs(&name), Ok(()));
        name[5] = 42;
        assert_eq!(super::require_ntfs(&name), Ok(()));
        for prefix in [
            [110, 116, 102, 115, 0],
            [78, 84, 70, 83, 88],
            [78, 0, 70, 83, 0],
            [70, 65, 84, 0, 0],
            [0, 0, 0, 0, 0],
        ] {
            name[..5].copy_from_slice(&prefix);
            assert_eq!(super::require_ntfs(&name), Err(()));
        }
    }
}
