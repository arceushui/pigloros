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

#[cfg(all(test, unix))]
macro_rules! deletion_fault {
    ($path:expr_2021, $stage:expr_2021) => {
        injected_fault_result($path, $stage)
    };
}

#[cfg(all(not(test), unix))]
macro_rules! deletion_fault {
    ($path:expr_2021, $stage:expr_2021) => {{
        let _ = ($path, $stage);
        Ok::<(), std::io::Error>(())
    }};
}

/// Delete the application-owned signing-key file after registry authorization
/// has entered `DestructionPending`.
///
/// The exact file bytes are checked against the pending material digest before
/// removal. Success requires synchronizing both the file and its containing
/// directory; an absent file is idempotent only after the directory sync.
/// This removes the supported path to the private bytes. Filesystem snapshots
/// and copies held outside this owner are outside this deletion boundary.
///
/// # Errors
/// Returns a closed storage error when the path is unsafe, the file does not
/// match the pending material, or durable deletion cannot be confirmed.
#[cfg(unix)]
pub fn delete_owned_secret_key(
    path: &Path,
    request: pos_core::KeyDestructionRequestV1,
) -> Result<pos_core::Hash, pos_core::CoreError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let storage_error = |error: &dyn std::fmt::Display| {
        pos_core::CoreError::Storage(format!("owned signing-key deletion: {error}"))
    };
    let absolute = absolute_output(path).map_err(|error| storage_error(&error))?;
    let parent_path = absolute.parent().ok_or_else(|| {
        pos_core::CoreError::Storage("owned signing-key path has no parent".to_owned())
    })?;
    validate_ancestors(&absolute, parent_path).map_err(|error| storage_error(&error))?;
    let parent = deletion_fault!(&absolute, FaultStage::DeleteOpenParent)
        .and_then(|()| std::fs::File::open(parent_path))
        .map_err(|error| storage_error(&error))?;
    let opened = deletion_fault!(&absolute, FaultStage::DeleteOpenFile).and_then(|()| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&absolute)
    });
    let mut file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            deletion_fault!(&absolute, FaultStage::DeleteAbsentDirectorySync)
                .and_then(|()| parent.sync_all())
                .map_err(|error| storage_error(&error))?;
            return Ok(pos_core::deletion_receipt(&request));
        }
        Err(error) => return Err(storage_error(&error)),
    };
    let metadata = deletion_fault!(&absolute, FaultStage::DeleteMetadata)
        .and_then(|()| file.metadata())
        .map_err(|error| storage_error(&error))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(pos_core::CoreError::Storage(
            "owned signing-key file is not a private single-link regular file".to_owned(),
        ));
    }
    if metadata.len() > 128 {
        return Err(pos_core::CoreError::Storage(
            "owned signing-key file exceeds the supported size".to_owned(),
        ));
    }
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    deletion_fault!(&absolute, FaultStage::DeleteRead)
        .and_then(|()| file.read_to_end(&mut encoded))
        .map_err(|error| storage_error(&error))?;
    let text = std::str::from_utf8(&encoded).map_err(|error| storage_error(&error))?;
    let decoded = zeroize::Zeroizing::new(
        crate::hex::hex_decode(text.trim()).map_err(|error| storage_error(&error))?,
    );
    let seed = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(decoded.as_slice()).map_err(|error| storage_error(&error))?,
    );
    if pos_crypto::key_roles::key_material_digest(&seed) != request.expected_material_digest {
        return Err(pos_core::CoreError::Storage(
            "owned signing-key file does not match the pending material digest".to_owned(),
        ));
    }
    deletion_fault!(&absolute, FaultStage::DeletePreRemoveFileSync)
        .and_then(|()| file.sync_all())
        .map_err(|error| storage_error(&error))?;
    #[cfg(test)]
    swap_deletion_target_for_test(&absolute);
    let current = deletion_fault!(&absolute, FaultStage::DeleteInspectCurrent)
        .and_then(|()| std::fs::symlink_metadata(&absolute))
        .map_err(|error| storage_error(&error))?;
    if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
        return Err(pos_core::CoreError::Storage(
            "owned signing-key file changed before deletion".to_owned(),
        ));
    }
    deletion_fault!(&absolute, FaultStage::DeleteRemove)
        .and_then(|()| std::fs::remove_file(&absolute))
        .map_err(|error| storage_error(&error))?;
    deletion_fault!(&absolute, FaultStage::DeletePostRemoveFileSync)
        .and_then(|()| file.sync_all())
        .map_err(|error| storage_error(&error))?;
    deletion_fault!(&absolute, FaultStage::DeleteDirectorySync)
        .and_then(|()| parent.sync_all())
        .map_err(|error| storage_error(&error))?;
    Ok(pos_core::deletion_receipt(&request))
}

/// Non-Unix platforms have no confirmed durable file-deletion adapter.
///
/// # Errors
/// Always returns an unsupported storage error.
#[cfg(not(unix))]
pub fn delete_owned_secret_key(
    _path: &Path,
    _request: pos_core::KeyDestructionRequestV1,
) -> Result<pos_core::Hash, pos_core::CoreError> {
    Err(pos_core::CoreError::Storage(
        "owned signing-key file deletion is unsupported on this platform".to_owned(),
    ))
}

/// Durably destroy an owned signing-key file and commit its tombstone.
///
/// Calling this again with the same request resumes a pending request after a
/// crash or an uncertain directory sync.
///
/// # Errors
/// Returns the registry or owned-file error. A failure after the first commit
/// leaves `DestructionPending` and cannot restore signing authorization.
pub fn destroy_owned_secret_key<S: pos_core::EventStore + ?Sized>(
    store: &mut S,
    path: &Path,
    request: pos_core::KeyDestructionRequestV1,
) -> Result<pos_core::KeyDestructionOutcomeV1, pos_core::CoreError> {
    store.begin_key_registry_destruction(request)?;
    let receipt = delete_owned_secret_key(path, request)?;
    store
        .complete_key_registry_destruction(request, receipt)
        .map(|(outcome, _)| outcome)
}

#[cfg(unix)]
const NO_OUTPUT: &str = "no output was created; retry is safe";

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultStage {
    DeleteOpenParent,
    DeleteOpenFile,
    DeleteAbsentDirectorySync,
    DeleteMetadata,
    DeleteRead,
    DeletePreRemoveFileSync,
    DeleteSwapBeforeInspect,
    DeleteInspectCurrent,
    DeleteRemove,
    DeletePostRemoveFileSync,
    DeleteDirectorySync,
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod injected_fault {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use super::FaultStage;

    thread_local! {
        static PLAN: RefCell<Option<(PathBuf, Vec<FaultStage>)>> = const { RefCell::new(None) };
    }

    pub(super) fn install(path: &Path, stages: &[FaultStage]) {
        PLAN.with(|plan| *plan.borrow_mut() = Some((path.to_path_buf(), stages.to_vec())));
    }

    pub(super) fn clear() {
        PLAN.with(|plan| *plan.borrow_mut() = None);
    }

    pub(super) fn take(path: &Path, stage: FaultStage) -> bool {
        PLAN.with(|plan| {
            let mut plan = plan.borrow_mut();
            let Some((planned_path, stages)) = plan.as_mut() else {
                return false;
            };
            if planned_path != path {
                return false;
            }
            let Some(index) = stages.iter().position(|candidate| *candidate == stage) else {
                return false;
            };
            stages.remove(index);
            true
        })
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
#[cfg_attr(coverage_nightly, coverage(off))]
fn swap_deletion_target_for_test(path: &Path) {
    if injected_fault::take(path, FaultStage::DeleteSwapBeforeInspect) {
        let replacement = path.with_extension("replacement");
        assert!(std::fs::write(&replacement, b"replacement").is_ok());
        assert!(std::fs::rename(replacement, path).is_ok());
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

#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod deletion_tests {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use super::{clear_faults, delete_owned_secret_key, install_faults, FaultStage};
    use pos_core::{Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRoleV1};

    fn request() -> KeyDestructionRequestV1 {
        KeyDestructionRequestV1::new(
            KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1),
            pos_crypto::key_roles::key_material_digest(&[9; 32]),
            Hash::from_bytes([7; 32]),
        )
    }

    fn write_owned_key(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(crate::hex_encode(&[9; 32]).as_bytes())?;
        Ok(())
    }

    #[test]
    fn injected_deletion_storage_failures_leave_no_success_receipt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relative = Path::new("injected-deletion-relative.key");
        install_faults(relative, &[FaultStage::ResolveRelative]);
        assert!(delete_owned_secret_key(relative, request()).is_err());
        clear_faults();

        for stage in [
            FaultStage::InspectAncestor,
            FaultStage::DeleteOpenParent,
            FaultStage::DeleteOpenFile,
            FaultStage::DeleteMetadata,
            FaultStage::DeleteRead,
            FaultStage::DeletePreRemoveFileSync,
            FaultStage::DeleteSwapBeforeInspect,
            FaultStage::DeleteInspectCurrent,
            FaultStage::DeleteRemove,
            FaultStage::DeletePostRemoveFileSync,
            FaultStage::DeleteDirectorySync,
        ] {
            let directory = tempfile::TempDir::new()?;
            let key = directory.path().join("secret.key");
            write_owned_key(&key)?;
            install_faults(&key, &[stage]);
            let result = delete_owned_secret_key(&key, request());
            clear_faults();
            assert!(result.is_err(), "{stage:?}");
        }

        let directory = tempfile::TempDir::new()?;
        let missing = directory.path().join("missing.key");
        install_faults(&missing, &[FaultStage::DeleteAbsentDirectorySync]);
        let result = delete_owned_secret_key(&missing, request());
        clear_faults();
        assert!(result.is_err());
        Ok(())
    }
}
