//! Durable, pre-send SIR1 installation-recovery commits.
//!
//! This module deliberately stops at the durable recovery floor. Provider
//! cancellation, RCA1 authentication, successor SIC1 installation, and SIR1
//! removal belong to the subsequent completion operation.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ciborium::value::Value;
use rustix::fs::{
    fchmod, fsync, mkdirat, openat2, renameat_with, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
    ResolveFlags,
};

use super::{InstalledSelectorAuthority, ValidatedInstallationUpdate};
use crate::evaluator_protocol::encode_with_limit;
#[cfg(test)]
use crate::sandbox_provider_protocol::SelectorRevocationState;
use crate::sandbox_provider_protocol::{
    AuthenticatedRevocationAcknowledgement, RecoveryCancellationContext,
};
use crate::selector::installation::authority::recovery::InstallationRecoverySnapshot;
use crate::selector::installation::{
    open_directory_chain, open_file, InstallationObjectKind, InstalledSelectorObjects,
    MANIFEST_LIMIT,
};
use crate::selector::{digest_name, SelectorBoundaryError};

const RECOVERY_NAME: &str = "installation-update.cbor";
const STAGING_NAME: &str = ".installation-update-staging";
const RECOVERY_LIMIT: usize = 48 * 1024 * 1024;
const RECOVERY_LIMIT_U64: u64 = 48 * 1024 * 1024;
const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const PRIVATE_DIRECTORY_MODE: Mode = Mode::RWXU;
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
    snapshot: InstallationRecoverySnapshot,
    sir1_digest: [u8; 32],
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

    /// Exact committed SIR1 self-digest.
    #[must_use]
    pub const fn sir1_digest(&self) -> [u8; 32] {
        self.sir1_digest
    }

    /// Exact RCC1 paired with this transaction's retained RCU1.
    ///
    /// # Errors
    /// Rejects any internally inconsistent retained recovery identity.
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
        .or(Err(SelectorBoundaryError::ArtifactInvalid))
    }

    #[cfg(test)]
    pub(crate) fn authenticate_live_acknowledgement(
        &self,
        acknowledgement_bytes: &[u8],
        elapsed_ms: u64,
    ) -> Result<AuthenticatedRevocationAcknowledgement, SelectorBoundaryError> {
        if elapsed_ms > 100 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let context = self.cancellation_context()?;
        let mut state = SelectorRevocationState::new(
            self.authority.revocation().clone(),
            self.authority.trust(),
            self.snapshot.runtime_key_id(),
        )
        .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        state
            .begin_update(
                self.update.revocation_update_bytes(),
                self.authority.trust(),
                context,
                0,
            )
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        state
            .acknowledge(acknowledgement_bytes, elapsed_ms)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))
    }

    /// Recheck the retained SIR1 descriptor and the on-disk SIC1 recovery floor.
    ///
    /// This is a fail-closed prerequisite for the later completion operation.
    /// It does not send RCU1, receive RCA1, install successor SIC1, remove SIR1,
    /// or reopen admission.
    ///
    /// # Errors
    /// Rejects a replaced, unsafe, truncated, or altered SIR1 file, or a current
    /// SIC1 that is neither the exact retained previous nor successor manifest.
    pub fn verify_recovery_floor(&self) -> Result<(), SelectorBoundaryError> {
        let owner = self
            .authority
            .installed
            .root
            .metadata()
            .or(Err(SelectorBoundaryError::Io))?
            .uid();
        let current = read_current_manifest(&self.authority, owner)?;
        if current != self.update.previous_manifest_bytes()
            && current != self.update.next_manifest_bytes()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let current_recovery = open_file(
            &self.authority.installed.root,
            RECOVERY_NAME,
            owner,
            0o400,
            RECOVERY_LIMIT_U64,
        )?;
        let current_metadata = current_recovery
            .metadata()
            .or(Err(SelectorBoundaryError::Io))?;
        let retained_metadata = self
            .recovery_file
            .metadata()
            .or(Err(SelectorBoundaryError::Io))?;
        let recovery_length = u64::try_from(self.recovery_bytes.len())
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        if current_metadata.dev() != retained_metadata.dev()
            || current_metadata.ino() != retained_metadata.ino()
            || current_metadata.len() != retained_metadata.len()
            || current_metadata.len() != recovery_length
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let retained = read_retained_recovery(&self.recovery_file)?;
        if retained != self.recovery_bytes {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(())
    }

    /// Complete a timely live update after exact RCA1 authentication.
    ///
    /// This atomically publishes and synchronizes next SIC1 before removing and
    /// synchronizing SIR1. No previous-state admission object is returned.
    ///
    /// # Errors
    /// Rejects a foreign acknowledgement or changed recovery floor. Every
    /// failure after SIR1 commit leaves recovery mandatory.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the authenticated acknowledgement is a single-use capability"
    )]
    pub fn complete_live_update(
        self,
        acknowledgement: AuthenticatedRevocationAcknowledgement,
    ) -> Result<InstalledSelectorObjects, SelectorBoundaryError> {
        self.verify_recovery_floor()?;
        let context = self.cancellation_context()?;
        if !acknowledgement.matches_context(
            &context,
            self.update
                .revocation_update()
                .next_revocation
                .snapshot_digest(),
        ) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let owner = self
            .authority
            .installed
            .root
            .metadata()
            .or(Err(SelectorBoundaryError::Io))?
            .uid();
        publish_successor(
            &self.authority.installed.root,
            owner,
            self.update.previous_manifest_bytes(),
            self.update.next_manifest_bytes(),
            &self.recovery_file,
            &self.recovery_bytes,
        )
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
        snapshot: InstallationRecoverySnapshot,
    ) -> Result<CommittedInstallationUpdate, SelectorBoundaryError> {
        if self.installed.manifest_bytes() != update.previous_manifest_bytes() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let owner = self
            .installed
            .root
            .metadata()
            .or(Err(SelectorBoundaryError::Io))?
            .uid();
        if read_current_manifest(&self, owner)? != update.previous_manifest_bytes() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        self.installed.require_no_pending_recovery()?;
        snapshot.validate_against(&self)?;
        let (recovery_bytes, sir1_digest) = recovery_bytes(&update, &snapshot)?;
        synchronize_successor_records(&self, &update, owner)?;
        let staging = open_staging_directory(&self.installed.root, owner)?;
        let recovery_file = write_recovery(&staging, &self.installed.root, owner, &recovery_bytes)?;
        Ok(CommittedInstallationUpdate {
            authority: self,
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
    if records.iter().any(|record| record.len() > CONTROL_LIMIT) {
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
    let unsigned_bytes = encode_with_limit(&unsigned, RECOVERY_LIMIT)
        .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&unsigned_bytes);
    let sir1_digest = *hasher.finalize().as_bytes();
    let encoded = encode_with_limit(
        &Value::Array(vec![unsigned, Value::Bytes(sir1_digest.to_vec())]),
        RECOVERY_LIMIT,
    )
    .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
    if encoded.len() > RECOVERY_LIMIT {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
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

fn read_current_manifest(
    authority: &InstalledSelectorAuthority,
    owner: u32,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let file = open_file(
        &authority.installed.root,
        "installation.cbor",
        owner,
        0o400,
        MANIFEST_LIMIT,
    )?;
    read_bounded(file, MANIFEST_LIMIT)
}

fn read_retained_recovery(file: &File) -> Result<Vec<u8>, SelectorBoundaryError> {
    let retained = file.try_clone().or(Err(SelectorBoundaryError::Io))?;
    read_bounded(retained, RECOVERY_LIMIT_U64)
}

fn read_bounded(mut file: File, limit: u64) -> Result<Vec<u8>, SelectorBoundaryError> {
    let metadata = file.metadata().or(Err(SelectorBoundaryError::Io))?;
    if metadata.len() > limit {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let capacity =
        usize::try_from(metadata.len()).or(Err(SelectorBoundaryError::ArtifactInvalid))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.seek(SeekFrom::Start(0))
        .or(Err(SelectorBoundaryError::Io))?;
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .or(Err(SelectorBoundaryError::Io))?;
    if bytes.len() != capacity {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(bytes)
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
            .or(Err(SelectorBoundaryError::Io))?,
        Path::new("authority"),
        owner,
    )?;
    for (kind, identity, held) in [
        (
            InstallationObjectKind::from_code(1).or(Err(SelectorBoundaryError::ArtifactInvalid))?,
            update.next_manifest.authority_digests()[1],
            &update.next_revocation_file.file,
        ),
        (
            InstallationObjectKind::from_code(2).or(Err(SelectorBoundaryError::ArtifactInvalid))?,
            update.next_manifest.authority_digests()[2],
            &update.next_policy_file.file,
        ),
    ] {
        let entry = update
            .next_manifest
            .object(kind, identity)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        let installed = openat2(
            &directory,
            digest_name(entry.content_digest()),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        let installed_metadata = installed.metadata().or(Err(SelectorBoundaryError::Io))?;
        let held_metadata = held.metadata().or(Err(SelectorBoundaryError::Io))?;
        if !installed_metadata.is_file()
            || installed_metadata.uid() != owner
            || installed_metadata.mode() & 0o7777 != 0o400
            || installed_metadata.nlink() != 1
            || installed_metadata.dev() != held_metadata.dev()
            || installed_metadata.ino() != held_metadata.ino()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        fsync(held).or(Err(SelectorBoundaryError::Io))?;
    }
    fsync(&directory).or(Err(SelectorBoundaryError::Io))?;
    fsync(&authority.installed.root).or(Err(SelectorBoundaryError::Io))
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
    .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
    if created {
        fchmod(&staging, PRIVATE_DIRECTORY_MODE).or(Err(SelectorBoundaryError::Io))?;
        fsync(&staging).or(Err(SelectorBoundaryError::Io))?;
        fsync(root).or(Err(SelectorBoundaryError::Io))?;
    }
    let metadata = staging.metadata().or(Err(SelectorBoundaryError::Io))?;
    let root_metadata = root.metadata().or(Err(SelectorBoundaryError::Io))?;
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
    let mut temporary = openat2(
        staging,
        &temporary_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        RECOVERY_MODE,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .or(Err(SelectorBoundaryError::Io))?;
    fchmod(&temporary, RECOVERY_MODE).or(Err(SelectorBoundaryError::Io))?;
    let metadata = temporary.metadata().or(Err(SelectorBoundaryError::Io))?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != 0
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    temporary
        .write_all(bytes)
        .or(Err(SelectorBoundaryError::Io))?;
    fsync(&temporary).or(Err(SelectorBoundaryError::Io))?;
    renameat_with(
        staging,
        &temporary_name,
        root,
        RECOVERY_NAME,
        RenameFlags::NOREPLACE,
    )
    .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
    let recovery = open_file(root, RECOVERY_NAME, owner, 0o400, RECOVERY_LIMIT_U64)?;
    let temporary_metadata = temporary.metadata().or(Err(SelectorBoundaryError::Io))?;
    let recovery_metadata = recovery.metadata().or(Err(SelectorBoundaryError::Io))?;
    let recovery_length =
        u64::try_from(bytes.len()).or(Err(SelectorBoundaryError::ArtifactInvalid))?;
    if temporary_metadata.dev() != recovery_metadata.dev()
        || temporary_metadata.ino() != recovery_metadata.ino()
        || recovery_metadata.len() != recovery_length
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    fsync(root).or(Err(SelectorBoundaryError::Io))?;
    Ok(recovery)
}

fn temporary_name() -> String {
    let nonce: u128 = rand::random();
    format!("sir1-{nonce:032x}.cbor")
}

pub(crate) fn publish_successor(
    root: &File,
    owner: u32,
    previous: &[u8],
    next: &[u8],
    retained_recovery: &File,
    recovery_bytes: &[u8],
) -> Result<InstalledSelectorObjects, SelectorBoundaryError> {
    let current = open_file(root, "installation.cbor", owner, 0o400, MANIFEST_LIMIT)?;
    let current_bytes = read_bounded(
        current.try_clone().or(Err(SelectorBoundaryError::Io))?,
        MANIFEST_LIMIT,
    )?;
    if current_bytes != previous && current_bytes != next {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    verify_recovery_identity(root, owner, retained_recovery, recovery_bytes)?;
    if current_bytes != next {
        let staging = open_staging_directory(root, owner)?;
        let temporary_name = format!("sic1-{:032x}.cbor", rand::random::<u128>());
        let mut temporary = openat2(
            &staging,
            &temporary_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            RECOVERY_MODE,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .or(Err(SelectorBoundaryError::Io))?;
        fchmod(&temporary, RECOVERY_MODE).or(Err(SelectorBoundaryError::Io))?;
        temporary
            .write_all(next)
            .or(Err(SelectorBoundaryError::Io))?;
        fsync(&temporary).or(Err(SelectorBoundaryError::Io))?;
        renameat_with(
            &staging,
            &temporary_name,
            root,
            "installation.cbor",
            RenameFlags::empty(),
        )
        .or(Err(SelectorBoundaryError::Io))?;
        fsync(root).or(Err(SelectorBoundaryError::Io))?;
    }
    verify_recovery_identity(root, owner, retained_recovery, recovery_bytes)?;
    unlinkat(root, RECOVERY_NAME, AtFlags::empty()).or(Err(SelectorBoundaryError::Io))?;
    fsync(root).or(Err(SelectorBoundaryError::Io))?;
    InstalledSelectorObjects::open_at(root, owner)
}

fn verify_recovery_identity(
    root: &File,
    owner: u32,
    retained: &File,
    expected_bytes: &[u8],
) -> Result<(), SelectorBoundaryError> {
    let current = open_file(root, RECOVERY_NAME, owner, 0o400, RECOVERY_LIMIT_U64)?;
    let current_metadata = current.metadata().or(Err(SelectorBoundaryError::Io))?;
    let retained_metadata = retained.metadata().or(Err(SelectorBoundaryError::Io))?;
    if current_metadata.dev() != retained_metadata.dev()
        || current_metadata.ino() != retained_metadata.ino()
        || read_bounded(current, RECOVERY_LIMIT_U64)? != expected_bytes
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}
