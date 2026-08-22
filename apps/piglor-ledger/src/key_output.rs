//! Secure signing-key file creation.
//!
//! On Unix, every existing path component is checked without following its
//! final component. The containing directory must not be writable by group or
//! other users; higher ancestors may be writable only when the sticky bit is
//! set. The output itself is opened with create-new semantics and mode `0o600`,
//! then its effective mode is verified before the key is persisted. The key
//! file and containing directory are synchronized before success.
//!
//! Safe `std` APIs cannot bind ancestor validation and path-based creation into
//! one atomic `openat` walk. A same-principal actor able to rename an ancestor
//! between validation and creation remains a residual TOCTOU boundary. Callers
//! should therefore choose a stable private directory. The final output
//! component is still protected atomically by create-new semantics.
use std::path::Path;

use crate::CliError;

#[cfg(unix)]
const NO_OUTPUT: &str = "no output was created; retry is safe";

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultStage {
    ResolveRelative,
    InspectAncestor,
    OpenParent,
    InspectOutput,
    Create,
    InspectCreated,
    ForceInsecureMode,
    Write,
    FileSync,
    DirectorySync,
    CleanupRemove,
    CleanupDirectorySync,
}

#[cfg(all(test, unix))]
mod injected_fault {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::FaultStage;

    static PLAN: Mutex<Option<(PathBuf, Vec<FaultStage>)>> = Mutex::new(None);

    pub(super) fn install(path: &Path, stages: &[FaultStage]) {
        let mut plan = PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *plan = Some((path.to_path_buf(), stages.to_vec()));
    }

    pub(super) fn clear() {
        let mut plan = PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *plan = None;
    }

    pub(super) fn take(path: &Path, stage: FaultStage) -> bool {
        let mut plan = PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((planned_path, stages)) = plan.as_mut() else {
            drop(plan);
            return false;
        };
        if planned_path != path {
            drop(plan);
            return false;
        }
        let Some(index) = stages.iter().position(|candidate| *candidate == stage) else {
            drop(plan);
            return false;
        };
        stages.remove(index);
        drop(plan);
        true
    }
}

#[cfg(all(test, unix))]
pub(crate) fn install_faults(path: &Path, stages: &[FaultStage]) {
    injected_fault::install(path, stages);
}

#[cfg(all(test, unix))]
pub(crate) fn clear_faults() {
    injected_fault::clear();
}

#[cfg(all(test, unix))]
fn injected_fault_result(path: &Path, stage: FaultStage) -> std::io::Result<()> {
    if injected_fault::take(path, stage) {
        Err(std::io::Error::other(format!(
            "injected keygen {stage:?} failure"
        )))
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
macro_rules! fault {
    ($path:expr_2021, $stage:expr_2021) => {
        injected_fault_result($path, $stage)
    };
}

#[cfg(all(not(test), unix))]
macro_rules! fault {
    ($path:expr_2021, $stage:expr_2021) => {{
        let _ = ($path, $stage);
        Ok::<(), std::io::Error>(())
    }};
}

#[cfg(unix)]
struct ValidatedOutput {
    path: std::path::PathBuf,
    parent: std::fs::File,
}

/// Create and durably persist a new signing-key file.
///
/// # Errors
///
/// Returns a path-specific safety or I/O error. Any failure after creation
/// attempts to remove the partial output and synchronize its containing
/// directory; the error reports whether retry is safe or cleanup is uncertain.
#[cfg(unix)]
pub fn write_new_secret_key(out: &Path, key: &[u8]) -> Result<(), CliError> {
    validate_output(out).and_then(|validated| create_and_persist(validated, key))
}

#[cfg(not(unix))]
pub fn write_new_secret_key(out: &Path, _key: &[u8]) -> Result<(), CliError> {
    Err(CliError::UnsupportedKeyOutput {
        path: out.display().to_string(),
    })
}

#[cfg(unix)]
fn validate_output(out: &Path) -> Result<ValidatedOutput, CliError> {
    absolute_output(out).and_then(|path| {
        let parent_path = path
            .parent()
            .map_or_else(|| Path::new("/").to_path_buf(), Path::to_path_buf);
        validate_ancestors(&path, &parent_path).and_then(|()| {
            inspect_output(&path).and_then(|()| {
                fault!(&path, FaultStage::OpenParent)
                    .and_then(|()| std::fs::File::open(&parent_path))
                    .map(|parent| ValidatedOutput { path, parent })
                    .map_err(|source| key_io("open containing directory", out, source, NO_OUTPUT))
            })
        })
    })
}

#[cfg(unix)]
fn absolute_output(out: &Path) -> Result<std::path::PathBuf, CliError> {
    if out.is_absolute() {
        Ok(out.to_path_buf())
    } else {
        fault!(out, FaultStage::ResolveRelative)
            .and_then(|()| std::env::current_dir())
            .map(|cwd| cwd.join(out))
            .map_err(|source| key_io("resolve relative path", out, source, NO_OUTPUT))
    }
}

#[cfg(unix)]
fn validate_ancestors(out: &Path, parent: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;

    for (distance, ancestor) in parent.ancestors().enumerate() {
        let metadata = match fault!(out, FaultStage::InspectAncestor)
            .and_then(|()| std::fs::symlink_metadata(ancestor))
        {
            Ok(metadata) => metadata,
            Err(source) => {
                return Err(key_io("inspect ancestor", out, source, NO_OUTPUT));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(unsafe_key(
                out,
                format!("ancestor {} is a symlink", ancestor.display()),
                NO_OUTPUT,
            ));
        }
        if !metadata.is_dir() {
            return Err(unsafe_key(
                out,
                format!("ancestor {} is not a directory", ancestor.display()),
                NO_OUTPUT,
            ));
        }
        let mode = metadata.mode();
        let writable_by_others = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        if writable_by_others && (distance == 0 || !sticky) {
            return Err(unsafe_key(
                out,
                format!(
                    "directory {} has insecure mode {:04o}; remove group/other write permission",
                    ancestor.display(),
                    mode & 0o7777
                ),
                NO_OUTPUT,
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_output(out: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;

    match fault!(out, FaultStage::InspectOutput).and_then(|()| std::fs::symlink_metadata(out)) {
        Ok(metadata) => {
            let reason = if metadata.file_type().is_symlink() {
                "output is a symlink".to_owned()
            } else if metadata.is_file() && metadata.mode() & 0o077 != 0 {
                format!(
                    "existing file has insecure mode {:04o} and will not be overwritten",
                    metadata.mode() & 0o7777
                )
            } else {
                "output already exists and will not be overwritten".to_owned()
            };
            Err(unsafe_key(out, reason, NO_OUTPUT))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(key_io("inspect output", out, source, NO_OUTPUT)),
    }
}

#[cfg(unix)]
fn create_and_persist(validated: ValidatedOutput, key: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path = validated.path;
    let file_result = fault!(&path, FaultStage::Create).and_then(|()| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
    });
    let mut file = match file_result {
        Ok(file) => file,
        Err(source) => {
            return Err(key_io("create", &path, source, NO_OUTPUT));
        }
    };
    let cleanup = || cleanup_output(&path, &validated.parent);

    let metadata = match fault!(&path, FaultStage::InspectCreated).and_then(|()| file.metadata()) {
        Ok(metadata) => metadata,
        Err(source) => {
            drop(file);
            return Err(key_io("verify created file", &path, source, cleanup()));
        }
    };
    let forced_insecure = fault!(&path, FaultStage::ForceInsecureMode).is_err();
    if forced_insecure || metadata.mode() & 0o077 != 0 {
        drop(file);
        return Err(unsafe_key(
            &path,
            format!(
                "created file has non-owner permission bits {:04o}",
                metadata.mode() & 0o7777
            ),
            cleanup(),
        ));
    }

    if let Err(source) = fault!(&path, FaultStage::Write).and_then(|()| file.write_all(key)) {
        drop(file);
        return Err(key_io("write", &path, source, cleanup()));
    }
    if let Err(source) = fault!(&path, FaultStage::FileSync).and_then(|()| file.sync_all()) {
        drop(file);
        return Err(key_io("synchronize file", &path, source, cleanup()));
    }
    drop(file);

    fault!(&path, FaultStage::DirectorySync)
        .and_then(|()| validated.parent.sync_all())
        .map_err(|source| key_io("synchronize containing directory", &path, source, cleanup()))
}

#[cfg(unix)]
fn cleanup_output(path: &Path, parent: &std::fs::File) -> String {
    match fault!(path, FaultStage::CleanupRemove).and_then(|()| std::fs::remove_file(path)) {
        Ok(()) => match fault!(path, FaultStage::CleanupDirectorySync)
            .and_then(|()| parent.sync_all())
        {
            Ok(()) => "partial output was removed and its directory synchronized; retry is safe"
                .to_owned(),
            Err(source) => format!(
                "partial output was removed, but directory cleanup sync failed ({source}); \
                 cleanup durability is uncertain—inspect the path before retrying"
            ),
        },
        Err(source) => format!(
            "could not remove partial output ({source}); cleanup is uncertain—inspect and remove \
             the path before retrying"
        ),
    }
}

#[cfg(unix)]
fn key_io(
    action: &'static str,
    path: &Path,
    source: std::io::Error,
    cleanup: impl Into<String>,
) -> CliError {
    CliError::KeyOutputIo {
        action,
        path: path.display().to_string(),
        source,
        cleanup: cleanup.into(),
    }
}

#[cfg(unix)]
fn unsafe_key(path: &Path, reason: String, cleanup: impl Into<String>) -> CliError {
    CliError::UnsafeKeyOutput {
        path: path.display().to_string(),
        reason,
        cleanup: cleanup.into(),
    }
}
