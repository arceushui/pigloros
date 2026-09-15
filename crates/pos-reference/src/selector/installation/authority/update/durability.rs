//! Durable SIR1 commit and live successor publication.

use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{
    fchmod, fsync, mkdirat, openat2, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags,
    RenameFlags, ResolveFlags,
};

use super::ValidatedInstallationUpdate;
use crate::evaluator_protocol::encode_with_limit;
use crate::sandbox_provider_protocol::{
    AuthenticatedRevocationAcknowledgement, RecoveryCancellationContext, RevocationAcknowledgement,
};
use crate::selector::installation::authority::{
    fresh_selector_id, AdmittedSelectorProvider, InstallationRecoverySnapshot,
};
use crate::selector::installation::{
    ensure_no_pending_recovery, hex_name, open_directory_chain, open_immutable_file,
    read_complete_file, InstallationObjectKind, InstalledSelectorState, MANIFEST_LIMIT,
    MANIFEST_NAME, RECOVERY_NAME,
};
use crate::selector::SelectorBoundaryError;

const STAGING_NAME: &str = ".installation-update-staging";
const RECOVERY_LIMIT: usize = 48 * 1024 * 1024;
const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const PRIVATE_DIRECTORY_MODE: Mode = Mode::RWXU;
const RECORD_MODE: Mode = Mode::RUSR;

/// One durably committed SIR1 awaiting the timely provider acknowledgement.
#[derive(Debug)]
pub struct CommittedInstallationUpdate {
    admitted: Arc<AdmittedSelectorProvider>,
    update: ValidatedInstallationUpdate,
    snapshot: InstallationRecoverySnapshot,
    sir1_digest: [u8; 32],
    recovery_file: File,
    recovery_bytes: Vec<u8>,
}

impl CommittedInstallationUpdate {
    /// Exact durable SIR1 bytes.
    #[must_use]
    pub fn recovery_bytes(&self) -> &[u8] {
        &self.recovery_bytes
    }

    /// Exact committed SIR1 self-digest.
    #[must_use]
    pub const fn sir1_digest(&self) -> [u8; 32] {
        self.sir1_digest
    }

    /// Exact administrator-signed RCU1 bytes.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        self.update.revocation_update_bytes()
    }

    /// Construct the exact RCC1 paired with this SIR1 and RCU1.
    ///
    /// # Errors
    /// Rejects an internally inconsistent retained transaction.
    pub fn cancellation_context(
        &self,
    ) -> Result<RecoveryCancellationContext, SelectorBoundaryError> {
        RecoveryCancellationContext::for_committed_recovery(
            self.sir1_digest,
            self.snapshot.previous_provider_digest()?,
            self.update.revocation_update_bytes(),
            self.snapshot.previous_live_attempt_ids().to_vec(),
            self.snapshot.required_cancelled_attempt_ids().to_vec(),
        )
        .map_err(invalid)
    }

    /// Authenticate one RCA1 against this exact committed live transaction.
    ///
    /// Transport framing, EOF, and the absolute deadline must already have
    /// succeeded before this method is called.
    ///
    /// # Errors
    /// Rejects a forged runtime signature or any committed-identity mismatch.
    pub fn authenticate_live_acknowledgement(
        &self,
        bytes: &[u8],
    ) -> Result<AuthenticatedRevocationAcknowledgement, SelectorBoundaryError> {
        let context = self.cancellation_context()?;
        let (runtime_key_id, runtime_public_key) = self.snapshot.runtime_key();
        let runtime_key = VerifyingKey::from_bytes(&runtime_public_key).map_err(invalid)?;
        RevocationAcknowledgement::authenticate_for_context(
            bytes,
            runtime_key_id,
            &runtime_key,
            &context,
            self.update.revocation_update().request_id,
            self.update
                .revocation_update()
                .next_revocation
                .snapshot_digest(),
        )
        .map_err(invalid)
    }

    /// Recheck the retained SIR1 descriptor and current SIC1 recovery floor.
    ///
    /// # Errors
    /// Rejects replaced, unsafe, truncated, or altered durable state.
    pub fn verify_recovery_floor(&self) -> Result<(), SelectorBoundaryError> {
        let root = &self.admitted.bootstrap().installed().root;
        let owner = root.metadata().map_err(io)?.uid();
        let current = read_bounded_immutable(root, MANIFEST_NAME, owner, MANIFEST_LIMIT)?;
        if current != self.update.previous_manifest_bytes()
            && current != self.update.next_manifest_bytes()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        verify_recovery_identity(root, owner, &self.recovery_file, &self.recovery_bytes)
    }

    /// Publish successor SIC1, remove SIR1, and admit only the successor state.
    ///
    /// # Errors
    /// Rejects a foreign acknowledgement or changed recovery floor. Every
    /// failure after SIR1 commit leaves previous-state admission closed.
    pub fn complete_live_update(
        self,
        acknowledgement: &AuthenticatedRevocationAcknowledgement,
    ) -> Result<AdmittedSelectorProvider, SelectorBoundaryError> {
        self.verify_recovery_floor()?;
        let context = self.cancellation_context()?;
        if !acknowledgement.matches_context(
            &context,
            self.update.revocation_update().request_id,
            self.update
                .revocation_update()
                .next_revocation
                .snapshot_digest(),
        ) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let root = &self.admitted.bootstrap().installed().root;
        let owner = root.metadata().map_err(io)?.uid();
        publish_successor(
            root,
            owner,
            self.update.previous_manifest_bytes(),
            self.update.next_manifest_bytes(),
            &self.recovery_file,
            &self.recovery_bytes,
        )?
        .authenticate_bootstrap()?
        .admit_provider()
    }
}

impl AdmittedSelectorProvider {
    /// Durably commit the exact fenced update snapshot as SIR1.
    ///
    /// This consumes previous-state admission authority. A successful commit
    /// can only proceed through live completion or #349 recovery.
    ///
    /// # Errors
    /// Rejects stale authority, pending recovery, unsafe staging state,
    /// changed successor records, oversized SIR1, or synchronization failure.
    pub fn commit_update(
        self: Arc<Self>,
        update: ValidatedInstallationUpdate,
        snapshot: InstallationRecoverySnapshot,
    ) -> Result<CommittedInstallationUpdate, SelectorBoundaryError> {
        let installed = self.bootstrap().installed();
        if installed.manifest_bytes() != update.previous_manifest_bytes() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let owner = installed.root.metadata().map_err(io)?.uid();
        if read_bounded_immutable(&installed.root, MANIFEST_NAME, owner, MANIFEST_LIMIT)?
            != update.previous_manifest_bytes()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        ensure_no_pending_recovery(&installed.root)?;
        let (recovery_bytes, sir1_digest) = recovery_bytes(&update, &snapshot)?;
        synchronize_successor_records(installed, &update, owner)?;
        let staging = open_staging_directory(&installed.root, owner)?;
        let recovery_file = write_recovery(&staging, &installed.root, owner, &recovery_bytes)?;
        Ok(CommittedInstallationUpdate {
            admitted: self,
            update,
            snapshot,
            sir1_digest,
            recovery_file,
            recovery_bytes,
        })
    }
}

fn recovery_bytes(
    update: &ValidatedInstallationUpdate,
    snapshot: &InstallationRecoverySnapshot,
) -> Result<(Vec<u8>, [u8; 32]), SelectorBoundaryError> {
    let records = [
        update.previous_manifest_bytes(),
        update.next_manifest_bytes(),
        update.revocation_update_bytes(),
    ];
    if records
        .iter()
        .any(|record| record.is_empty() || record.len() > CONTROL_LIMIT)
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let unsigned = Value::Array(vec![
        Value::Text("SIR1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(records[0].to_vec()),
        Value::Bytes(records[1].to_vec()),
        Value::Bytes(records[2].to_vec()),
        snapshot.previous_provider_value(),
        snapshot.recovery_slot_value(),
        attempt_values(snapshot.previous_live_attempt_ids()),
        attempt_values(snapshot.required_cancelled_attempt_ids()),
    ]);
    let unsigned_bytes = encode_with_limit(&unsigned, RECOVERY_LIMIT).map_err(invalid)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&unsigned_bytes);
    let sir1_digest = *hasher.finalize().as_bytes();
    let encoded = encode_with_limit(
        &Value::Array(vec![unsigned, Value::Bytes(sir1_digest.to_vec())]),
        RECOVERY_LIMIT,
    )
    .map_err(invalid)?;
    Ok((encoded, sir1_digest))
}

fn attempt_values(attempts: &[[u8; 16]]) -> Value {
    Value::Array(
        attempts
            .iter()
            .map(|attempt| Value::Bytes(attempt.to_vec()))
            .collect(),
    )
}

fn synchronize_successor_records(
    installed: &InstalledSelectorState,
    update: &ValidatedInstallationUpdate,
    owner: u32,
) -> Result<(), SelectorBoundaryError> {
    let directory = open_directory_chain(
        installed.root.try_clone().map_err(io)?,
        Path::new("authority"),
        owner,
    )?;
    for (kind, held) in [
        (
            InstallationObjectKind::ADMINISTRATOR_POLICY,
            update.record_files()[0],
        ),
        (
            InstallationObjectKind::REVOCATION_SNAPSHOT,
            update.record_files()[1],
        ),
    ] {
        let identity = update.next_manifest().authority_digests()[usize::from(kind.code())];
        let object = update
            .next_manifest()
            .object(kind, identity)
            .map_err(invalid)?;
        let reopened = open_immutable_file(
            &directory,
            &hex_name(object.content_digest()),
            kind.required_mode(),
            object.byte_length(),
            owner,
        )?;
        let reopened_metadata = reopened.metadata().map_err(io)?;
        let held_metadata = held.metadata().map_err(io)?;
        if reopened_metadata.dev() != held_metadata.dev()
            || reopened_metadata.ino() != held_metadata.ino()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        fsync(held).map_err(io)?;
    }
    fsync(&directory).map_err(io)?;
    fsync(&installed.root).map_err(io)
}

fn open_staging_directory(root: &File, owner: u32) -> Result<File, SelectorBoundaryError> {
    let created = match mkdirat(root, STAGING_NAME, PRIVATE_DIRECTORY_MODE) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(_) => return Err(SelectorBoundaryError::Io),
    };
    let staging = openat2(
        root,
        STAGING_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(invalid)?;
    if created {
        fchmod(&staging, PRIVATE_DIRECTORY_MODE).map_err(io)?;
        fsync(&staging).map_err(io)?;
        fsync(root).map_err(io)?;
    }
    let metadata = staging.metadata().map_err(io)?;
    let root_metadata = root.metadata().map_err(io)?;
    if !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o700
        || metadata.dev() != root_metadata.dev()
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(staging)
}

fn write_recovery(
    staging: &File,
    root: &File,
    owner: u32,
    bytes: &[u8],
) -> Result<File, SelectorBoundaryError> {
    let temporary_name = temporary_name("sir1")?;
    let mut temporary = create_staging_file(staging, &temporary_name, owner)?;
    temporary.write_all(bytes).map_err(io)?;
    fsync(&temporary).map_err(io)?;
    renameat_with(
        staging,
        &temporary_name,
        root,
        RECOVERY_NAME,
        RenameFlags::NOREPLACE,
    )
    .map_err(invalid)?;
    let recovery = open_immutable_file(
        root,
        RECOVERY_NAME,
        0o400,
        u64::try_from(bytes.len()).map_err(invalid)?,
        owner,
    )?;
    verify_file_identity(&temporary, &recovery)?;
    fsync(root).map_err(io)?;
    Ok(recovery)
}

fn publish_successor(
    root: &File,
    owner: u32,
    previous: &[u8],
    next: &[u8],
    retained_recovery: &File,
    recovery_bytes: &[u8],
) -> Result<InstalledSelectorState, SelectorBoundaryError> {
    let current = read_bounded_immutable(root, MANIFEST_NAME, owner, MANIFEST_LIMIT)?;
    if current != previous && current != next {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    verify_recovery_identity(root, owner, retained_recovery, recovery_bytes)?;
    if current != next {
        let staging = open_staging_directory(root, owner)?;
        let temporary_name = temporary_name("sic1")?;
        let mut temporary = create_staging_file(&staging, &temporary_name, owner)?;
        temporary.write_all(next).map_err(io)?;
        fsync(&temporary).map_err(io)?;
        renameat_with(
            &staging,
            &temporary_name,
            root,
            MANIFEST_NAME,
            RenameFlags::empty(),
        )
        .map_err(io)?;
        fsync(root).map_err(io)?;
    }
    verify_recovery_identity(root, owner, retained_recovery, recovery_bytes)?;
    unlinkat(root, RECOVERY_NAME, AtFlags::empty()).map_err(io)?;
    fsync(root).map_err(io)?;
    InstalledSelectorState::open_at_for_owner(root, owner)
}

fn create_staging_file(
    staging: &File,
    name: &str,
    owner: u32,
) -> Result<File, SelectorBoundaryError> {
    let file = openat2(
        staging,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        RECORD_MODE,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(io)?;
    fchmod(&file, RECORD_MODE).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != 0
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(file)
}

fn read_bounded_immutable(
    root: &File,
    name: &str,
    owner: u32,
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let metadata = statat(root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    let length = u64::try_from(metadata.st_size).map_err(invalid)?;
    if length == 0 || length > limit {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let file = open_immutable_file(root, name, 0o400, length, owner)?;
    read_complete_file(&file, limit)
}

fn verify_recovery_identity(
    root: &File,
    owner: u32,
    retained: &File,
    expected_bytes: &[u8],
) -> Result<(), SelectorBoundaryError> {
    let current = open_immutable_file(
        root,
        RECOVERY_NAME,
        0o400,
        u64::try_from(expected_bytes.len()).map_err(invalid)?,
        owner,
    )?;
    verify_file_identity(retained, &current)?;
    if read_complete_file(&current, RECOVERY_LIMIT as u64)? != expected_bytes {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}

fn verify_file_identity(left: &File, right: &File) -> Result<(), SelectorBoundaryError> {
    let left = left.metadata().map_err(io)?;
    let right = right.metadata().map_err(io)?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}

fn temporary_name(prefix: &str) -> Result<String, SelectorBoundaryError> {
    let id = fresh_selector_id()?;
    let mut name = String::with_capacity(prefix.len() + 39);
    name.push_str(prefix);
    name.push('-');
    for byte in id {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").map_err(io)?;
    }
    name.push_str(".cbor");
    Ok(name)
}

fn invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn io<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn durable_root() -> Result<(tempfile::TempDir, File, u32), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let root = File::open(directory.path())?;
        let owner = root.metadata()?.uid();
        Ok((directory, root, owner))
    }

    #[test]
    fn staging_directory_and_files_are_private_and_exclusive() -> TestResult {
        let (_directory, root, owner) = durable_root()?;
        let staging = open_staging_directory(&root, owner)?;
        let metadata = staging.metadata()?;
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        verify_file_identity(&staging, &open_staging_directory(&root, owner)?)?;

        let name = temporary_name("coverage")?;
        assert!(name.starts_with("coverage-"));
        assert_eq!(
            Path::new(&name).extension(),
            Some(std::ffi::OsStr::new("cbor"))
        );
        let file = create_staging_file(&staging, &name, owner)?;
        let metadata = file.metadata()?;
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert!(matches!(
            create_staging_file(&staging, &name, owner),
            Err(SelectorBoundaryError::Io)
        ));
        Ok(())
    }

    #[test]
    fn staging_directory_rejects_occupied_and_unsafe_entries() -> TestResult {
        let (occupied, root, owner) = durable_root()?;
        fs::write(occupied.path().join(STAGING_NAME), b"occupied")?;
        assert!(matches!(
            open_staging_directory(&root, owner),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let (unsafe_directory, root, owner) = durable_root()?;
        let staging = unsafe_directory.path().join(STAGING_NAME);
        fs::create_dir(&staging)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            open_staging_directory(&root, owner),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let regular = tempfile::NamedTempFile::new()?;
        assert!(matches!(
            open_staging_directory(regular.as_file(), owner),
            Err(SelectorBoundaryError::Io)
        ));

        let (_directory, root, owner) = durable_root()?;
        let staging = open_staging_directory(&root, owner)?;
        assert!(matches!(
            create_staging_file(&staging, "foreign-owner.cbor", owner.saturating_add(1)),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let ordinary_file = tempfile::NamedTempFile::new()?;
        assert!(matches!(
            create_staging_file(ordinary_file.as_file(), "child", owner),
            Err(SelectorBoundaryError::Io)
        ));

        let (symlink_root, root, owner) = durable_root()?;
        std::os::unix::fs::symlink("missing", symlink_root.path().join(STAGING_NAME))?;
        assert!(matches!(
            open_staging_directory(&root, owner),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn bounded_immutable_reads_reject_missing_empty_and_oversized_files() -> TestResult {
        let (directory, root, owner) = durable_root()?;
        assert!(matches!(
            read_bounded_immutable(&root, "missing", owner, 8),
            Err(SelectorBoundaryError::Io)
        ));

        let empty = directory.path().join("empty");
        fs::write(&empty, [])?;
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o400))?;
        assert!(matches!(
            read_bounded_immutable(&root, "empty", owner, 8),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let record = directory.path().join("record");
        fs::write(&record, b"record")?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o400))?;
        assert_eq!(
            read_bounded_immutable(&root, "record", owner, 8)?,
            b"record"
        );
        assert!(matches!(
            read_bounded_immutable(&root, "record", owner, 5),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn recovery_write_and_identity_checks_fail_closed() -> TestResult {
        let (directory, root, owner) = durable_root()?;
        let staging = open_staging_directory(&root, owner)?;
        let recovery = write_recovery(&staging, &root, owner, b"recovery")?;
        verify_recovery_identity(&root, owner, &recovery, b"recovery")?;
        assert!(write_recovery(&staging, &root, owner, b"second").is_err());

        fs::set_permissions(
            directory.path().join(RECOVERY_NAME),
            fs::Permissions::from_mode(0o600),
        )?;
        fs::write(directory.path().join(RECOVERY_NAME), b"changed!")?;
        fs::set_permissions(
            directory.path().join(RECOVERY_NAME),
            fs::Permissions::from_mode(0o400),
        )?;
        assert!(matches!(
            verify_recovery_identity(&root, owner, &recovery, b"recovery"),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let other_path = directory.path().join("other");
        fs::write(&other_path, b"other")?;
        let other = File::open(other_path)?;
        assert!(matches!(
            verify_file_identity(&recovery, &other),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }
}
