#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use pos_owner_bridge::{BridgeError, ProcessIdentity, UnavailableCode};
use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

mod io;
mod manifest;
use io::{OsIo, RuntimeIo};

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
        .map_err(integrity)
}

fn verify_installation(
    root: &Path,
    marker_directory: &Path,
    expected: &[RuntimeFile],
    manifest_digest: &[u8; 32],
) -> Result<VerifiedRuntime, ()> {
    verify_with_io(root, marker_directory, expected, manifest_digest, &OsIo)
        .map(|root| VerifiedRuntime { root })
}

fn verify_with_io(
    root: &Path,
    marker_directory: &Path,
    expected: &[RuntimeFile],
    manifest_digest: &[u8; 32],
    io: &dyn RuntimeIo,
) -> Result<PathBuf, ()> {
    super::directory::inspect_path(root, false).map_err(failed)?;
    let root = io.canonicalize(root).map_err(failed)?;
    let directory = io
        .open(
            &root,
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0),
        )
        .map_err(failed)?;
    let (volume, index) = io.identity(&directory)?;
    let mut members = BTreeMap::new();
    collect_members(io, &root, "", &mut members)?;
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
    match io.metadata(marker_directory) {
        Ok(_) => io.private_directory(marker_directory, false)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            io.private_directory(marker_directory, true)?;
        }
        Err(_) => return Err(()),
    }
    let marker = marker_directory.join(MARKER_NAME);
    let cached = read_marker(io, &marker, cache.len()).is_ok_and(|bytes| bytes == cache);
    for (entry, path) in admitted {
        if (!cached || PER_START.contains(&entry.path)) && hash_file(io, path)? != entry.sha256 {
            return Err(());
        }
    }
    // A cache record holds public metadata only. A partial write is simply a
    // cache miss next start, so it needs no durable cleanup-file protocol.
    if !cached {
        write_marker(io, &marker, &cache)?;
    }
    Ok(root)
}

fn collect_members(
    io: &dyn RuntimeIo,
    directory: &Path,
    prefix: &str,
    members: &mut BTreeMap<String, (PathBuf, std::fs::Metadata)>,
) -> Result<(), ()> {
    for entry in io.entries(directory).map_err(failed)? {
        let path = entry.map_err(failed)?;
        let metadata = io.metadata(&path).map_err(failed)?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(());
        }
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(())?;
        let relative = format!("{prefix}{name}");
        if metadata.is_file() {
            // Directory enumeration gives each exact relative name once. The
            // path is assembled from that same entry; no prefix fallbacks,
            // normalization aliases or second fallible lookup are needed.
            let _previous = members.insert(relative, (path, metadata));
        } else {
            // Directories recurse. An unsupported non-file kind fails at
            // read_dir, so it cannot enter the admitted file inventory.
            collect_members(io, &path, &format!("{relative}/"), members)?;
        }
    }
    Ok(())
}

fn hash_file(io: &dyn RuntimeIo, path: &Path) -> Result<[u8; 32], ()> {
    let mut file = io
        .open(
            path,
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0),
        )
        .map_err(failed)?;
    if io.file_metadata(&file).map_err(failed)?.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1_048_576].into_boxed_slice();
    loop {
        let read = io.read(&mut file, &mut buffer).map_err(failed)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().into())
}

fn read_marker(io: &dyn RuntimeIo, path: &Path, length: usize) -> Result<Vec<u8>, ()> {
    let metadata = io.metadata(path).map_err(failed)?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    let mut file = io
        .open(
            path,
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0),
        )
        .map_err(failed)?;
    // Windows pointer widths are at most 64 bits, so this widening conversion
    // cannot fail. The bound is the already-allocated cache length plus one.
    io.read_bounded(&mut file, length as u64 + 1)
        .map_err(failed)
}

fn write_marker(io: &dyn RuntimeIo, path: &Path, cache: &[u8]) -> Result<(), ()> {
    match io.metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
                return Err(());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(()),
    }
    let mut file = io
        .open(
            path,
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0),
        )
        .map_err(failed)?;
    io.write(&mut file, cache).map_err(failed)
}

#[cfg(test)]
mod tests;
