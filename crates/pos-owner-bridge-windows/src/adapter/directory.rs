#![cfg(windows)]
#![forbid(unsafe_code)]

use std::os::windows::fs::MetadataExt;
use std::path::Path;

use pos_owner_bridge::{BridgeError, UnavailableCode};

/// Create a fresh directory with a protected, current-SID-only DACL and read it back.
///
/// # Errors
///
/// Refuses an existing target, relative path, reparse point or failed ACL operation.
pub fn create_private_directory(path: &Path) -> Result<(), BridgeError> {
    inspect_path(path, true)
        .and_then(|()| crate::Native::private_directory(path, true).map_err(|()| unavailable()))
}

/// Verify an existing directory's owner, protected DACL and sole inheritable full-control ACE.
///
/// # Errors
///
/// Refuses a missing directory, relative path, reparse point or differing ACL.
pub fn verify_private_directory(path: &Path) -> Result<(), BridgeError> {
    inspect_path(path, false)
        .and_then(|()| crate::Native::private_directory(path, false).map_err(|()| unavailable()))
}

pub(super) fn inspect_path(path: &Path, create: bool) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(unavailable());
    }
    for (index, ancestor) in path.ancestors().enumerate() {
        if create && index == 0 {
            continue;
        }
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| unavailable())?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(unavailable());
        }
    }
    Ok(())
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}
