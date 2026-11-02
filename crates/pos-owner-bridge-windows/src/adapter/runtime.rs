#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use pos_owner_bridge::{BridgeError, UnavailableCode};
use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

mod manifest;

const PER_START: [&str; 4] = [
    "msedgewebview2.exe",
    "msedge.dll",
    "msedge_elf.dll",
    "EBWebView/x64/EmbeddedBrowserWebView.dll",
];
const MARKER_NAME: &str = "owner-runtime-v1.cache";

struct RuntimeFile {
    path: &'static str,
    size: u64,
    sha256: [u8; 32],
}

/// A runtime directory admitted against the compiled-in Fixed Version manifest.
///
/// It contains no authority to activate encryption or bypass the subsequent
/// environment-version, user-data-folder and browser-image readbacks.
pub struct VerifiedRuntime {
    root: PathBuf,
}

impl VerifiedRuntime {
    /// The canonical directory to pass explicitly to the WebView2 loader.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Verify all runtime members and use only a current-SID-only metadata cache.
///
/// A missing, malformed or stale cache causes a full hash check. A matching
/// cache still requires exact inventory/sizes/timestamps and rehashes all four
/// per-start binaries. The marker never substitutes for those checks.
///
/// # Errors
///
/// Returns `Unavailable(RuntimeIntegrity)` on an inventory/hash mismatch,
/// unsupported path, reparse point, inaccessible member or failed marker write.
pub fn verify_fixed_runtime(
    root: &Path,
    marker_directory: &Path,
) -> Result<VerifiedRuntime, BridgeError> {
    verify_installation(root, marker_directory, manifest::FILES, &manifest::DIGEST)
        .map(|root| VerifiedRuntime { root })
        .map_err(|()| BridgeError::Unavailable(UnavailableCode::RuntimeIntegrity))
}

fn verify_installation(
    root: &Path,
    marker_directory: &Path,
    expected: &[RuntimeFile],
    manifest_digest: &[u8; 32],
) -> Result<PathBuf, ()> {
    super::directory::inspect_path(root, false).map_err(|_| ())?;
    let root = root.canonicalize().map_err(|_| ())?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&root)
        .map_err(|_| ())?;
    let (volume, index) = crate::Native::file_identity(&directory)?;
    let mut members = BTreeMap::new();
    collect_members(&root, &root, &mut members)?;
    if members.len() != expected.len() {
        return Err(());
    }
    let mut cache = b"PBWV\x01".to_vec();
    cache.extend_from_slice(manifest_digest);
    cache.extend_from_slice(&volume.to_le_bytes());
    cache.extend_from_slice(&index.to_le_bytes());
    for entry in expected {
        let (path, metadata) = members.get(entry.path).ok_or(())?;
        if metadata.len() != entry.size || !path.starts_with(&root) {
            return Err(());
        }
        cache.extend_from_slice(&metadata.last_write_time().to_le_bytes());
    }
    match std::fs::symlink_metadata(marker_directory) {
        Ok(_) => super::verify_private_directory(marker_directory).map_err(|_| ())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            super::create_private_directory(marker_directory).map_err(|_| ())?;
        }
        Err(_) => return Err(()),
    }
    let marker = marker_directory.join(MARKER_NAME);
    let cached = read_marker(&marker, cache.len()).is_ok_and(|bytes| bytes == cache);
    for entry in expected {
        if !cached || PER_START.contains(&entry.path) {
            let (path, _) = members.get(entry.path).ok_or(())?;
            if hash_file(path)? != entry.sha256 {
                return Err(());
            }
        }
    }
    // A cache record holds public metadata only. A partial write is simply a
    // cache miss next start, so it needs no durable cleanup-file protocol.
    if !cached {
        write_marker(&marker, &cache)?;
    }
    Ok(root)
}

fn collect_members(
    root: &Path,
    directory: &Path,
    members: &mut BTreeMap<String, (PathBuf, std::fs::Metadata)>,
) -> Result<(), ()> {
    for entry in std::fs::read_dir(directory).map_err(|_| ())? {
        let path = entry.map_err(|_| ())?.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| ())?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(());
        }
        if metadata.is_dir() {
            collect_members(root, &path, members)?;
        } else if metadata.is_file() {
            let name = path
                .strip_prefix(root)
                .map_err(|_| ())?
                .to_str()
                .ok_or(())?
                .replace('\\', "/");
            if members.insert(name, (path, metadata)).is_some() {
                return Err(());
            }
        } else {
            return Err(());
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32], ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| ())?;
    if file.metadata().map_err(|_| ())?.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1_048_576].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().into())
}

fn read_marker(path: &Path, length: usize) -> Result<Vec<u8>, ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| ())?
        .take(u64::try_from(length).map_err(|_| ())? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    Ok(bytes)
}

fn write_marker(path: &Path, cache: &[u8]) -> Result<(), ()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
            return Err(());
        }
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| ())?
        .write_all(cache)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests;
