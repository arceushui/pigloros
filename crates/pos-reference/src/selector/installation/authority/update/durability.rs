//! Durable, pre-send SIR1 installation-recovery commits.
//!
//! This module deliberately stops at the durable recovery floor. Provider
//! cancellation, RCA1 authentication, successor SIC1 installation, and SIR1
//! removal belong to the subsequent completion operation.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ciborium::value::Value;
use rustix::fs::{
    fchmod, fsync, mkdirat, openat2, renameat_with, Mode, OFlags, RenameFlags, ResolveFlags,
};

use super::{InstalledSelectorAuthority, ValidatedInstallationUpdate};
use crate::evaluator_protocol::encode;
use crate::selector::installation::{open_directory_chain, InstallationObjectKind};
use crate::selector::{digest_name, SelectorBoundaryError};

const RECOVERY_NAME: &str = "installation-update.cbor";
const STAGING_NAME: &str = ".installation-update-staging";
const RECOVERY_LIMIT: usize = 48 * 1024 * 1024;
const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const PRIVATE_DIRECTORY_MODE: Mode = Mode::RUSR | Mode::WUSR | Mode::XUSR;
const RECOVERY_MODE: Mode = Mode::RUSR;

/// A sealed SIR1 commit that keeps both installation generations alive.
///
/// The transaction is intentionally opaque: it grants no provider send,
/// acknowledgement, completion, or normal-admission operation. Its retained
/// descriptors are the inputs for the later, closed recovery/completion path.
#[derive(Debug)]
pub struct CommittedInstallationUpdate {
    authority: InstalledSelectorAuthority,
    update: ValidatedInstallationUpdate,
    recovery_file: File,
    recovery_bytes: Vec<u8>,
}

impl CommittedInstallationUpdate {
    /// Exact durable SIR1 bytes, including the prior SIC1, next SIC1, and RCU1.
    #[must_use]
    pub fn recovery_bytes(&self) -> &[u8] {
        &self.recovery_bytes
    }

    /// Exact prior SIC1 retained for the future recovery/completion operation.
    #[must_use]
    pub fn previous_manifest_bytes(&self) -> &[u8] {
        self.update.previous_manifest_bytes()
    }

    /// Exact successor SIC1 retained for the future recovery/completion operation.
    #[must_use]
    pub fn next_manifest_bytes(&self) -> &[u8] {
        self.update.next_manifest_bytes()
    }

    /// Exact authenticated RCU1 retained for the future recovery/completion operation.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        self.update.revocation_update_bytes()
    }
}

impl InstalledSelectorAuthority {
    /// Commit one matching validated update as the durable SIR1 restart floor.
    ///
    /// This consumes the authority so that a caller cannot continue normal
    /// admission with the old generation after beginning a durable transition.
    /// It never sends RCU1, accepts RCA1, installs successor SIC1, or removes
    /// SIR1.
    ///
    /// # Errors
    /// Rejects a stale or foreign validated update, any pending recovery,
    /// unsafe staging state, a missing successor record, an oversized SIR1, or
    /// failure to synchronize the required files and directories. Once the
    /// no-replace rename succeeds, any later failure leaves SIR1 in place.
    pub fn commit_update(
        self,
        update: ValidatedInstallationUpdate,
    ) -> Result<CommittedInstallationUpdate, SelectorBoundaryError> {
        if self.installed.manifest_bytes() != update.previous_manifest_bytes() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        self.installed.require_no_pending_recovery()?;
        let recovery_bytes = recovery_bytes(&update)?;
        let owner = self
            .installed
            .root
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?
            .uid();
        synchronize_successor_records(&self, &update, owner)?;
        let staging = open_staging_directory(&self.installed.root, owner)?;
        let recovery_file = write_recovery(&staging, &self.installed.root, owner, &recovery_bytes)?;
        Ok(CommittedInstallationUpdate {
            authority: self,
            update,
            recovery_file,
            recovery_bytes,
        })
    }
}

fn recovery_bytes(update: &ValidatedInstallationUpdate) -> Result<Vec<u8>, SelectorBoundaryError> {
    let records = [
        update.previous_manifest_bytes(),
        update.next_manifest_bytes(),
        update.revocation_update_bytes(),
    ];
    if records.iter().any(|record| record.len() > CONTROL_LIMIT) {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let encoded = encode(&Value::Array(vec![
        Value::Text("SIR1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(records[0].to_vec()),
        Value::Bytes(records[1].to_vec()),
        Value::Bytes(records[2].to_vec()),
    ]))
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    if encoded.len() > RECOVERY_LIMIT {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(encoded)
}

fn synchronize_successor_records(
    authority: &InstalledSelectorAuthority,
    update: &ValidatedInstallationUpdate,
    owner: u32,
) -> Result<(), SelectorBoundaryError> {
    let directory = open_directory_chain(
        authority
            .installed
            .root
            .try_clone()
            .map_err(|_| SelectorBoundaryError::Io)?,
        Path::new("authority"),
        owner,
    )?;
    for (kind, identity, held) in [
        (
            InstallationObjectKind::from_code(1)
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?,
            update.next_manifest.authority_digests()[1],
            &update.next_revocation_file.file,
        ),
        (
            InstallationObjectKind::from_code(2)
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?,
            update.next_manifest.authority_digests()[2],
            &update.next_policy_file.file,
        ),
    ] {
        let entry = update
            .next_manifest
            .object(kind, identity)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let installed = openat2(
            &directory,
            digest_name(entry.content_digest()),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let installed_metadata = installed
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?;
        let held_metadata = held.metadata().map_err(|_| SelectorBoundaryError::Io)?;
        if !installed_metadata.is_file()
            || installed_metadata.uid() != owner
            || installed_metadata.mode() & 0o7777 != 0o400
            || installed_metadata.nlink() != 1
            || installed_metadata.dev() != held_metadata.dev()
            || installed_metadata.ino() != held_metadata.ino()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        fsync(held).map_err(|_| SelectorBoundaryError::Io)?;
    }
    fsync(&directory).map_err(|_| SelectorBoundaryError::Io)?;
    fsync(&authority.installed.root).map_err(|_| SelectorBoundaryError::Io)
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
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    if created {
        fchmod(&staging, PRIVATE_DIRECTORY_MODE).map_err(|_| SelectorBoundaryError::Io)?;
        fsync(&staging).map_err(|_| SelectorBoundaryError::Io)?;
        fsync(root).map_err(|_| SelectorBoundaryError::Io)?;
    }
    let metadata = staging.metadata().map_err(|_| SelectorBoundaryError::Io)?;
    let root_metadata = root.metadata().map_err(|_| SelectorBoundaryError::Io)?;
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
    let temporary_name = temporary_name();
    let mut file = openat2(
        staging,
        &temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        RECOVERY_MODE,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::Io)?;
    fchmod(&file, RECOVERY_MODE).map_err(|_| SelectorBoundaryError::Io)?;
    let metadata = file.metadata().map_err(|_| SelectorBoundaryError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != 0
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    file.write_all(bytes)
        .map_err(|_| SelectorBoundaryError::Io)?;
    fsync(&file).map_err(|_| SelectorBoundaryError::Io)?;
    renameat_with(
        staging,
        &temporary_name,
        root,
        RECOVERY_NAME,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    fsync(root).map_err(|_| SelectorBoundaryError::Io)?;
    Ok(file)
}

fn temporary_name() -> String {
    let nonce: u128 = rand::random();
    format!("sir1-{nonce:032x}.cbor")
}
