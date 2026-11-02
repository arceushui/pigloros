#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use pos_owner_bridge::{BridgeError, ProcessIdentity, UnavailableCode};
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
    /// The canonical directory to pass explicitly to the `WebView2` loader.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Require the reported browser process image to lie inside this runtime.
    ///
    /// Creation time, exact UTF-16LE path digest and the path readback come from
    /// one query-only process handle, so PID reuse cannot mix two observations.
    ///
    /// # Errors
    ///
    /// Incomplete inspection returns `Unavailable(InterfaceUnavailable)`; an
    /// inaccessible or outside-runtime image returns `Unavailable(RuntimeIntegrity)`.
    pub fn browser_identity(&self, pid: u32) -> Result<ProcessIdentity, BridgeError> {
        admit_image(&self.root, crate::Native::inspect_process_with_image(pid))
    }
}

fn admit_image(
    root: &Path,
    observation: Result<Option<(ProcessIdentity, PathBuf)>, ()>,
) -> Result<ProcessIdentity, BridgeError> {
    let (identity, path) = observation.ok().flatten().ok_or(BridgeError::Unavailable(
        UnavailableCode::InterfaceUnavailable,
    ))?;
    let path = path.canonicalize().map_err(integrity)?;
    if !path.starts_with(root) {
        return Err(integrity(()));
    }
    Ok(identity)
}

fn integrity<T>(_: T) -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::RuntimeIntegrity)
}

fn failed<T>(_: T) {}

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
        .map_err(integrity)
}

fn verify_installation(
    root: &Path,
    marker_directory: &Path,
    expected: &[RuntimeFile],
    manifest_digest: &[u8; 32],
) -> Result<PathBuf, ()> {
    super::directory::inspect_path(root, false).map_err(failed)?;
    let root = root.canonicalize().map_err(failed)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&root)
        .map_err(failed)?;
    let (volume, index) = crate::Native::file_identity(&directory)?;
    let mut members = BTreeMap::new();
    collect_members(&root, "", &mut members)?;
    if members.len() != expected.len() {
        return Err(());
    }
    let mut cache = b"PBWV\x01".to_vec();
    cache.extend_from_slice(manifest_digest);
    cache.extend_from_slice(&volume.to_le_bytes());
    cache.extend_from_slice(&index.to_le_bytes());
    let mut admitted = Vec::with_capacity(expected.len());
    for entry in expected {
        let (path, metadata) = members.get(entry.path).ok_or(())?;
        if metadata.len() != entry.size {
            return Err(());
        }
        cache.extend_from_slice(&metadata.last_write_time().to_le_bytes());
        admitted.push((entry, path));
    }
    match std::fs::symlink_metadata(marker_directory) {
        Ok(_) => super::verify_private_directory(marker_directory).map_err(failed)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            super::create_private_directory(marker_directory).map_err(failed)?;
        }
        Err(_) => return Err(()),
    }
    let marker = marker_directory.join(MARKER_NAME);
    let cached = read_marker(&marker, cache.len()).is_ok_and(|bytes| bytes == cache);
    for (entry, path) in admitted {
        if (!cached || PER_START.contains(&entry.path)) && hash_file(path)? != entry.sha256 {
            return Err(());
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
    directory: &Path,
    prefix: &str,
    members: &mut BTreeMap<String, (PathBuf, std::fs::Metadata)>,
) -> Result<(), ()> {
    for entry in std::fs::read_dir(directory).map_err(failed)? {
        let entry = entry.map_err(failed)?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(failed)?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(());
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or(())?;
        let relative = format!("{prefix}{name}");
        if metadata.is_file() {
            // Directory enumeration gives each exact relative name once. The
            // path is assembled from that same entry; no prefix fallbacks,
            // normalization aliases or second fallible lookup are needed.
            let _previous = members.insert(relative, (path, metadata));
        } else {
            // Directories recurse. An unsupported non-file kind fails at
            // read_dir, so it cannot enter the admitted file inventory.
            collect_members(&path, &format!("{relative}/"), members)?;
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32], ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(failed)?;
    if file.metadata().map_err(failed)?.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1_048_576].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(failed)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().into())
}

fn read_marker(path: &Path, length: usize) -> Result<Vec<u8>, ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(failed)?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(failed)?
        .take(u64::try_from(length).map_err(failed)? + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
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
        .map_err(failed)?
        .write_all(cache)
        .map_err(failed)
}

#[cfg(test)]
mod tests;
