//! Durable local ownership of role-4 recipient key material.

use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

use pos_core::{
    export_timeline_own, recipient_owner_id_from_grantee, ConsentAuthority, ConsentError,
    ConsentGate, EntityId, ErasureArtifactClassV1, ErasureProtectedOperationV1, EventStore,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryErrorV1,
    KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, RecipientKeyDescriptorV1, Seq, TimelineExport,
    TimelineId,
};
use pos_crypto::key_roles::key_material_digest;
use pos_crypto::recipient_export::{
    decrypt_timeline_export_v1, encrypt_timeline_export_v1, DecryptedTimelineExportV1,
    RecipientExportErrorV1, RecipientTimelineExportV1,
};
use pos_crypto::recipient_key::recipient_public_key_from_private_v1;
use rand::{
    rngs::{StdRng, SysRng},
    SeedableRng, TryRng,
};
use rusqlite::{Connection, OptionalExtension};
use rustix::fs::{
    fsync, openat2, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
    ResolveFlags,
};
use zeroize::Zeroizing;

use super::{
    begin_immediate_sql, finish_immediate_transaction, finish_transaction, parse_timeline_id,
    sqlite_load_key_registry, CoreError, PublishedRecipientExportV1,
    RecipientExportDecryptionErrorV1, RecipientExportPublicationErrorV1, RecipientExportRequestV1,
    SqliteRollbackOnDrop, SqliteStore,
};
#[cfg(feature = "test-support")]
use super::{RecipientExportPublicationTestArtifactsV1, RecipientExportPublicationTestFaultV1};

const RECIPIENT_REGISTRY_UNAVAILABLE: RecipientExportDecryptionErrorV1 =
    RecipientExportDecryptionErrorV1::Registry(KeyRegistryErrorV1::RegistryUnavailable);
/// Passed to the decryption port for an absent identity, or a destroyed one
/// whose record carries no digest. The port rejects both before comparing
/// fingerprints. A pending record keeps its digest, so it never reaches this.
const ABSENT_MATERIAL_DIGEST: pos_core::Hash = pos_core::Hash::from_bytes([0; 32]);

struct RecipientExportPlaintextStagingV1 {
    source: TimelineExport,
    scrubbed: bool,
}

impl RecipientExportPlaintextStagingV1 {
    fn new(source: TimelineExport) -> Result<Self, CoreError> {
        if !source.plaintext_staging_is_exclusively_owned() {
            return Err(CoreError::Storage(
                "recipient export plaintext staging has shared payload buffers".to_owned(),
            ));
        }
        Ok(Self {
            source,
            scrubbed: false,
        })
    }

    const fn source(&self) -> &TimelineExport {
        &self.source
    }

    fn zeroize(&mut self) -> Result<(), CoreError> {
        if self.scrubbed || self.source.zeroize_plaintext_staging() {
            self.scrubbed = true;
            Ok(())
        } else {
            Err(CoreError::Storage(
                "recipient export plaintext staging lost exclusive ownership".to_owned(),
            ))
        }
    }
}

impl Drop for RecipientExportPlaintextStagingV1 {
    fn drop(&mut self) {
        if !self.scrubbed {
            let _ = self.source.zeroize_plaintext_staging();
        }
    }
}

/// Require the envelope to name the expected export and the owner's recipient.
fn check_envelope_identity(
    envelope: &RecipientTimelineExportV1,
    expected_export_id: [u8; 16],
    expected_recipient: RecipientKeyDescriptorV1,
    owner: &RecipientKeyOwnerV1,
) -> Result<(), RecipientExportDecryptionErrorV1> {
    if envelope.header.export_id == expected_export_id
        && envelope.header.recipient == expected_recipient
        && expected_recipient.is_for_grantee(owner.grantee_id)
    {
        Ok(())
    } else {
        Err(RecipientExportDecryptionErrorV1::Export(
            RecipientExportErrorV1::IdentityMismatch,
        ))
    }
}

/// The registered material fingerprint, or the never-matching placeholder
/// that leaves absent and destroyed identities to the port's own denial.
fn registered_material_digest_or_absent_sentinel(
    registry: &KeyRegistryStateV1,
    identity: KeyIdentityV1,
) -> pos_core::Hash {
    registry
        .key_record(identity)
        .and_then(|record| record.private_material_digest)
        .unwrap_or(ABSENT_MATERIAL_DIGEST)
}

fn storage_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::Storage(error.to_string())
}

fn recipient_rng_error(error: &std::io::Error) -> CoreError {
    CoreError::Storage(format!("recipient key RNG failed: {error}"))
}

#[cfg(test)]
thread_local! {
    static RECIPIENT_FSYNC_FAILURE: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
    static RECIPIENT_FSYNC_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static RECIPIENT_UNLINK_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_OPEN_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_STAT_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_RANDOM_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_RANDOM_OVERRIDE: std::cell::RefCell<Option<Vec<u8>>> = const {
        std::cell::RefCell::new(None)
    };
    static RECIPIENT_READ_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_READ_PAUSE: std::cell::RefCell<Option<(
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    )>> = const {
        std::cell::RefCell::new(None)
    };
    static RECIPIENT_WRITE_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_FILE_OWNER_MISMATCH: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static RECIPIENT_OPEN_REPLACEMENT: std::cell::RefCell<Option<(PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
    static RECIPIENT_DURABILITY_SYNCHRONOUS_OVERRIDE: std::cell::Cell<Option<i64>> = const {
        std::cell::Cell::new(None)
    };
    static RECIPIENT_DURABILITY_SYNCHRONOUS_READ_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(feature = "test-support")]
thread_local! {
    static RECIPIENT_EXPORT_PUBLICATION_TEST_FAULT: std::cell::Cell<
        Option<RecipientExportPublicationTestFaultV1>,
    > = const { std::cell::Cell::new(None) };
    static RECIPIENT_EXPORT_PUBLICATION_TEST_NAMED_PLAINTEXT_OBSERVED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static RECIPIENT_EXPORT_PUBLICATION_TEST_COMMIT_HOOK_INSTALLED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static RECIPIENT_EXPORT_PUBLICATION_TEST_EXPORT_ID: std::cell::Cell<Option<[u8; 16]>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(feature = "test-support")]
struct RecipientExportPublicationTestFencePause {
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(feature = "test-support")]
static RECIPIENT_EXPORT_PUBLICATION_TEST_FENCE_PAUSES: std::sync::Mutex<
    Vec<(TimelineId, RecipientExportPublicationTestFencePause)>,
> = std::sync::Mutex::new(Vec::new());

#[cfg(feature = "test-support")]
struct RecipientExportPublicationTestFaultGuard;

#[cfg(feature = "test-support")]
impl Drop for RecipientExportPublicationTestFaultGuard {
    fn drop(&mut self) {
        RECIPIENT_EXPORT_PUBLICATION_TEST_FAULT.with(|fault| fault.set(None));
        RECIPIENT_EXPORT_PUBLICATION_TEST_EXPORT_ID.with(|export_id| export_id.set(None));
    }
}

#[cfg(feature = "test-support")]
fn pause_recipient_export_publication_after_fences(timeline: TimelineId) -> Result<(), CoreError> {
    RECIPIENT_EXPORT_PUBLICATION_TEST_FENCE_PAUSES
        .lock()
        .map_err(|_| CoreError::Storage("recipient export test pause is unavailable".to_owned()))
        .map(|mut pauses| {
            pauses
                .iter()
                .position(|(configured, _)| *configured == timeline)
                .map(|index| pauses.swap_remove(index).1)
        })
        .and_then(|pause| {
            pause.map_or(Ok(()), |pause| {
                pause
                    .entered
                    .send(())
                    .map_err(|_| {
                        CoreError::Storage(
                            "recipient export test pause observer is unavailable".to_owned(),
                        )
                    })
                    .and_then(|()| {
                        pause.release.recv().map_err(|_| {
                            CoreError::Storage(
                                "recipient export test pause release is unavailable".to_owned(),
                            )
                        })
                    })
            })
        })
}

#[cfg(feature = "test-support")]
fn take_recipient_export_publication_test_fault(
    expected: RecipientExportPublicationTestFaultV1,
) -> bool {
    RECIPIENT_EXPORT_PUBLICATION_TEST_FAULT.with(|fault| {
        if fault.get() == Some(expected) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(feature = "test-support")]
fn recipient_export_publication_test_sync_fault(
    fault: RecipientExportPublicationTestFaultV1,
) -> Result<(), CoreError> {
    if take_recipient_export_publication_test_fault(fault) {
        Err(CoreError::Storage(
            "injected recipient export sync failure".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "test-support")]
fn install_recipient_export_publication_test_commit_abort(
    connection: &Connection,
) -> Result<(), CoreError> {
    if !take_recipient_export_publication_test_fault(
        RecipientExportPublicationTestFaultV1::CatalogCommit,
    ) {
        return Ok(());
    }
    let abort_once = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let callback_abort_once = std::sync::Arc::clone(&abort_once);
    connection
        .commit_hook(Some(move || {
            callback_abort_once.swap(false, std::sync::atomic::Ordering::AcqRel)
        }))
        .map_err(storage_error)?;
    RECIPIENT_EXPORT_PUBLICATION_TEST_COMMIT_HOOK_INSTALLED.with(|installed| installed.set(true));
    Ok(())
}

#[cfg(feature = "test-support")]
fn clear_recipient_export_publication_test_commit_hook(
    connection: &Connection,
) -> Result<(), CoreError> {
    let installed = RECIPIENT_EXPORT_PUBLICATION_TEST_COMMIT_HOOK_INSTALLED
        .with(|installed| installed.replace(false));
    if installed {
        connection
            .commit_hook::<fn() -> bool>(None)
            .map_err(storage_error)?;
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_fsync(fd: impl rustix::fd::AsFd) -> Result<(), rustix::io::Errno> {
    let fail = RECIPIENT_FSYNC_FAILURE.with(|failure| {
        RECIPIENT_FSYNC_CALLS.with(|calls| {
            let call = calls.get();
            calls.set(call + 1);
            failure.get() == Some(call)
        })
    });
    if fail {
        Err(rustix::io::Errno::IO)
    } else {
        fsync(fd)
    }
}

#[cfg(not(test))]
fn recipient_fsync(fd: impl rustix::fd::AsFd) -> Result<(), rustix::io::Errno> {
    fsync(fd)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_random_bytes(bytes: &mut [u8]) -> std::io::Result<()> {
    if RECIPIENT_RANDOM_FAILURE.with(std::cell::Cell::get) {
        Err(std::io::Error::other("injected recipient RNG failure"))
    } else if let Some(override_bytes) =
        RECIPIENT_RANDOM_OVERRIDE.with(|override_bytes| override_bytes.borrow_mut().take())
    {
        if override_bytes.len() != bytes.len() {
            return Err(std::io::Error::other(
                "injected recipient RNG length mismatch",
            ));
        }
        bytes.copy_from_slice(&override_bytes);
        Ok(())
    } else {
        SysRng
            .try_fill_bytes(bytes)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

#[cfg(not(test))]
fn recipient_random_bytes(bytes: &mut [u8]) -> std::io::Result<()> {
    SysRng.try_fill_bytes(bytes).map_err(std::io::Error::other)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_read_exact(file: &mut File, bytes: &mut [u8]) -> std::io::Result<()> {
    if RECIPIENT_READ_FAILURE.with(std::cell::Cell::get) {
        Err(std::io::Error::other("injected recipient read failure"))
    } else {
        RECIPIENT_READ_PAUSE
            .with(|pause| {
                pause
                    .borrow_mut()
                    .take()
                    .map_or(Ok(()), |(started, release)| {
                        started
                            .send(())
                            .map_err(|_| {
                                std::io::Error::other("recipient read pause was abandoned")
                            })
                            .and_then(|()| {
                                release.recv().map_err(|_| {
                                    std::io::Error::other("recipient read pause was abandoned")
                                })
                            })
                    })
            })
            .and_then(|()| file.read_exact(bytes))
    }
}

#[cfg(not(test))]
fn recipient_read_exact(file: &mut File, bytes: &mut [u8]) -> std::io::Result<()> {
    file.read_exact(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_write_all(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(feature = "test-support")]
    if take_recipient_export_publication_test_fault(
        RecipientExportPublicationTestFaultV1::StagingWrite,
    ) {
        return Err(std::io::Error::other(
            "injected recipient export staging write failure",
        ));
    }
    if RECIPIENT_WRITE_FAILURE.with(std::cell::Cell::get) {
        Err(std::io::Error::other("injected recipient write failure"))
    } else {
        file.write_all(bytes)
    }
}

#[cfg(not(test))]
fn recipient_write_all(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(feature = "test-support")]
    if take_recipient_export_publication_test_fault(
        RecipientExportPublicationTestFaultV1::StagingWrite,
    ) {
        return Err(std::io::Error::other(
            "injected recipient export staging write failure",
        ));
    }
    file.write_all(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_private_file_identity(metadata: &std::fs::Metadata) -> RecipientPrivateFileIdentityV1 {
    let mut identity = RecipientPrivateFileIdentityV1::from_metadata(metadata);
    if RECIPIENT_FILE_OWNER_MISMATCH.with(std::cell::Cell::get) {
        identity.uid[0] ^= 1;
    }
    identity
}

#[cfg(not(test))]
fn recipient_private_file_identity(metadata: &std::fs::Metadata) -> RecipientPrivateFileIdentityV1 {
    RecipientPrivateFileIdentityV1::from_metadata(metadata)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_openat2(
    directory: impl rustix::fd::AsFd,
    path: impl rustix::path::Arg,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    if RECIPIENT_OPEN_FAILURE.with(std::cell::Cell::get) {
        Err(rustix::io::Errno::IO)
    } else {
        let opened = openat2(directory, path, flags, mode, resolve)?;
        RECIPIENT_OPEN_REPLACEMENT.with(|replacement| {
            if let Some((directory, replacement)) = replacement.borrow_mut().take() {
                std::fs::rename(&directory, directory.with_extension("original"))
                    .map_err(|_| rustix::io::Errno::IO)?;
                std::fs::rename(replacement, directory).map_err(|_| rustix::io::Errno::IO)?;
            }
            Ok(opened)
        })
    }
}

#[cfg(not(test))]
fn recipient_openat2(
    directory: impl rustix::fd::AsFd,
    path: impl rustix::path::Arg,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    openat2(directory, path, flags, mode, resolve)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_unlinkat(
    directory: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
    flags: AtFlags,
) -> Result<(), rustix::io::Errno> {
    if RECIPIENT_UNLINK_FAILURE.with(std::cell::Cell::get) {
        Err(rustix::io::Errno::IO)
    } else {
        unlinkat(directory, name, flags)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_statat(
    directory: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
    flags: AtFlags,
) -> Result<rustix::fs::Stat, rustix::io::Errno> {
    if RECIPIENT_STAT_FAILURE.with(std::cell::Cell::get) {
        Err(rustix::io::Errno::IO)
    } else {
        statat(directory, name, flags)
    }
}

#[cfg(not(test))]
fn recipient_statat(
    directory: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
    flags: AtFlags,
) -> Result<rustix::fs::Stat, rustix::io::Errno> {
    statat(directory, name, flags)
}

#[cfg(not(test))]
fn recipient_unlinkat(
    directory: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
    flags: AtFlags,
) -> Result<(), rustix::io::Errno> {
    unlinkat(directory, name, flags)
}

/// An owner-managed Linux directory for one consent grantee's role-4 keys.
#[derive(Debug)]
pub struct RecipientKeyOwnerV1 {
    directory: PathBuf,
    /// Retained descriptor for the private directory. Every material operation
    /// is relative to this descriptor, so a later pathname swap cannot redirect
    /// a read, deletion, or quarantine action.
    directory_file: File,
    grantee_id: EntityId,
    directory_uid: u32,
    directory_identity: RecipientPrivateDirectoryIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecipientPrivateDirectoryIdentityV1 {
    device: [u8; 8],
    inode: [u8; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecipientPrivateFileIdentityV1 {
    device: [u8; 8],
    inode: [u8; 8],
    uid: [u8; 4],
}

struct StoredRecipientKeyInventoryV1 {
    descriptor: Vec<u8>,
    material_digest: Vec<u8>,
    private_path: Vec<u8>,
    file_device: Vec<u8>,
    file_inode: Vec<u8>,
    file_uid: Vec<u8>,
}

fn recipient_inventory_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<StoredRecipientKeyInventoryV1, rusqlite::Error> {
    row.get(0).and_then(|descriptor| {
        row.get(1).and_then(|material_digest| {
            row.get(2).and_then(|private_path| {
                row.get(3).and_then(|file_device| {
                    row.get(4).and_then(|file_inode| {
                        row.get(5).map(|file_uid| StoredRecipientKeyInventoryV1 {
                            descriptor,
                            material_digest,
                            private_path,
                            file_device,
                            file_inode,
                            file_uid,
                        })
                    })
                })
            })
        })
    })
}

impl RecipientPrivateDirectoryIdentityV1 {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            device: metadata.dev().to_be_bytes(),
            inode: metadata.ino().to_be_bytes(),
        }
    }
}

impl RecipientPrivateFileIdentityV1 {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            device: metadata.dev().to_be_bytes(),
            inode: metadata.ino().to_be_bytes(),
            uid: metadata.uid().to_be_bytes(),
        }
    }

    fn from_inventory(inventory: &StoredRecipientKeyInventoryV1) -> Result<Self, CoreError> {
        inventory
            .file_device
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Storage("recipient key inventory device is invalid".to_owned()))
            .and_then(|device| {
                inventory
                    .file_inode
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                        CoreError::Storage("recipient key inventory inode is invalid".to_owned())
                    })
                    .and_then(|inode| {
                        inventory
                            .file_uid
                            .as_slice()
                            .try_into()
                            .map_err(|_| {
                                CoreError::Storage(
                                    "recipient key inventory owner is invalid".to_owned(),
                                )
                            })
                            .map(|uid| Self { device, inode, uid })
                    })
            })
    }
}

impl RecipientKeyOwnerV1 {
    /// Bind recipient custody to one existing private directory and grantee.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the directory is unavailable or unsafe.
    pub fn open(directory: impl Into<PathBuf>, grantee_id: EntityId) -> Result<Self, CoreError> {
        use std::os::unix::fs::MetadataExt;

        let directory = directory.into();
        let metadata = std::fs::symlink_metadata(&directory).map_err(storage_error)?;
        if !metadata.is_dir() {
            return Err(CoreError::Storage(
                "recipient key directory is not a directory".to_owned(),
            ));
        }
        if metadata.mode() & 0o777 != 0o700 || metadata.file_type().is_symlink() {
            return Err(CoreError::Storage(
                "recipient key directory is not private".to_owned(),
            ));
        }
        recipient_openat2(
            rustix::fs::CWD,
            &directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(storage_error)
        .and_then(|directory_file| {
            directory_file
                .metadata()
                .map_err(storage_error)
                .and_then(|retained_metadata| {
                    if retained_metadata.uid() != metadata.uid()
                        || retained_metadata.ino() != metadata.ino()
                        || retained_metadata.dev() != metadata.dev()
                    {
                        return Err(CoreError::Storage(
                            "recipient key directory changed while opening".to_owned(),
                        ));
                    }
                    std::fs::symlink_metadata(&directory)
                        .map_err(storage_error)
                        .and_then(|current_metadata| {
                            if !current_metadata.is_dir()
                                || current_metadata.file_type().is_symlink()
                                || current_metadata.mode() & 0o777 != 0o700
                                || current_metadata.uid() != retained_metadata.uid()
                                || current_metadata.ino() != retained_metadata.ino()
                                || current_metadata.dev() != retained_metadata.dev()
                            {
                                return Err(CoreError::Storage(
                                    "recipient key directory changed while opening".to_owned(),
                                ));
                            }
                            Ok(Self {
                                directory,
                                directory_file,
                                grantee_id,
                                directory_uid: metadata.uid(),
                                directory_identity:
                                    RecipientPrivateDirectoryIdentityV1::from_metadata(
                                        &retained_metadata,
                                    ),
                            })
                        })
                })
        })
    }
}

impl SqliteStore {
    /// Stage and durably enroll a fresh role-4 recipient key.
    ///
    /// The private file and RKP1 descriptor are synced before the `SQLite`
    /// registry/inventory transaction makes the identity active. A failed
    /// transaction cannot activate the staged material.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the custody directory is unsafe, entropy
    /// acquisition fails, material cannot be durably written, or the
    /// registry/inventory transaction cannot commit.
    pub fn enroll_recipient_key(
        &mut self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<RecipientKeyDescriptorV1, CoreError> {
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id).map_err(storage_error)?;
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(storage_error)?;
        let result = (|| {
            validate_owner_directory(owner)?;
            ensure_recipient_custody_tables(&self.conn)?;
            claim_recipient_custody_directory(&self.conn, owner)?;
            let registry = self
                .load_key_registry()?
                .unwrap_or_else(KeyRegistryStateV1::new);
            let epoch = registry
                .highest_epoch(&owner_id, KeyRoleV1::ExportRecipientEncryption)
                .map_or(Ok(1), |highest| {
                    highest.checked_add(1).ok_or_else(|| {
                        CoreError::Storage("recipient key epoch overflow".to_owned())
                    })
                })?;
            let identity =
                KeyIdentityV1::from_parts(owner_id, KeyRoleV1::ExportRecipientEncryption, epoch);
            let mut ikm = Zeroizing::new([0_u8; 32]);
            recipient_random_bytes(&mut *ikm).map_err(|error| recipient_rng_error(&error))?;
            let (private_key, public_key) =
                pos_crypto::recipient_key::derive_recipient_keypair_v1(&ikm);
            let private_key = Zeroizing::new(private_key);
            let descriptor =
                RecipientKeyDescriptorV1::for_grantee(owner.grantee_id, epoch, public_key)
                    .map_err(storage_error)?;
            let private_path = recipient_private_path(&owner.directory, descriptor);
            let file_identity = write_private_key(owner, &private_path, &private_key)?;
            let material_digest = pos_crypto::key_roles::key_material_digest(&private_key);
            let mut next = registry;
            next.register_key(KeyRegistrationV1::new(identity, material_digest, None))
                .map_err(storage_error)?;
            self.conn.execute("INSERT INTO recipient_key_inventory_v1 (owner_id, epoch, descriptor, material_digest, private_path, file_device, file_inode, file_uid) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", rusqlite::params![identity.owner_id.as_str(), i64::try_from(epoch).map_err(storage_error)?, descriptor.encode(), material_digest.as_bytes().as_slice(), private_path.as_os_str().as_encoded_bytes(), file_identity.device.as_slice(), file_identity.inode.as_slice(), file_identity.uid.as_slice()])
                .map_err(storage_error)?;
            self.save_key_registry_in_transaction(&next)?;
            Ok(descriptor)
        })();
        finish_immediate_transaction(&self.conn, result)
    }

    /// Reopen every registered recipient key that is still safe and complete.
    ///
    /// Missing, corrupt, or descriptor-mismatched material fails closed; this
    /// method never derives a replacement from public RKP1 data. Epochs pending
    /// destruction are skipped: they are never opened or returned, and they do
    /// not block recovery of live epochs.
    ///
    /// After validation, unregistered staged material is first quarantined
    /// under a durable `.orphan` name and then purged under the same writer
    /// reservation. One call removes at most 256 quarantined entries; any
    /// remainder is purged by a later recovery.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the custody directory, registry, inventory,
    /// or private material is absent, unsafe, corrupt, or inconsistent.
    pub fn recover_recipient_keys(
        &self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<Vec<RecipientKeyDescriptorV1>, CoreError> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(storage_error)?;
        let result = validate_owner_directory(owner)
            .and_then(|()| ensure_recipient_custody_tables(&self.conn))
            .and_then(|()| claim_recipient_custody_directory(&self.conn, owner))
            .and_then(|()| recipient_owner_id_from_grantee(owner.grantee_id).map_err(storage_error))
            .and_then(|owner_id| {
                self.load_key_registry().and_then(|registry| {
                    registry.map_or_else(
                        || {
                            quarantine_unregistered_owned_staged_material(owner).and_then(|()| {
                                Err(CoreError::Storage(
                                    "recipient registry is unavailable".to_owned(),
                                ))
                            })
                        },
                        |registry| {
                        self.conn
                            .prepare("SELECT descriptor, material_digest, private_path, file_device, file_inode, file_uid FROM recipient_key_inventory_v1 WHERE owner_id = ?1 ORDER BY epoch")
                            .map_err(storage_error)
                            .and_then(|mut statement| {
                                statement
                                    .query_map(
                                        rusqlite::params![owner_id.as_str()],
                                        recipient_inventory_from_row,
                                    )
                                    .map_err(storage_error)
                                    .and_then(|rows| {
                                        rows.collect::<Result<Vec<_>, _>>()
                                            .map_err(storage_error)
                                    })
                            })
                            .and_then(|inventories| {
                                validate_recipient_key_inventory(
                                    owner,
                                    &owner_id,
                                    &registry,
                                    &inventories,
                                )
                                .and_then(|descriptors| {
                                    quarantine_unregistered_staged_material(owner, &inventories)
                                        .and_then(|()| purge_quarantined_material(owner))
                                        .map(|()| descriptors)
                                })
                            })
                        },
                    )
                })
            });
        finish_immediate_transaction(&self.conn, result)
    }

    /// Decrypt one TRX1 export with a retained, live recipient epoch.
    ///
    /// The envelope syntax, suite, expected export ID, and exact recorded RKP1
    /// descriptor are checked before any registry access. The decryption-only
    /// registry port then admits the exact owner, role 4, and epoch under the
    /// `SQLite` writer reservation, which stays held while the bound private
    /// file is read and HPKE runs; rotation or destruction therefore either
    /// precedes and denies this call or follows it. An older epoch may decrypt
    /// after rotation, but this never authorizes encryption. The private file
    /// must match the registered material fingerprint and derive the
    /// descriptor's public key. The transaction never commits; any first-use
    /// custody table or directory-claim writes are rolled back.
    ///
    /// ADR-098's "missing live key reports unavailable" is read as missing
    /// material for a registered identity: an identity the registry never
    /// registered is a denial ([`KeyRegistryErrorV1::NotFound`]), while a held
    /// writer lock or an unreadable registry is
    /// [`KeyRegistryErrorV1::RegistryUnavailable`].
    ///
    /// # Errors
    ///
    /// Returns [`RecipientExportDecryptionErrorV1::Export`] for an invalid,
    /// mismatched, or unauthenticated envelope;
    /// [`RecipientExportDecryptionErrorV1::Registry`] when the registry is
    /// locked or unavailable, or the identity is unregistered, pending
    /// destruction, destroyed, or bound to another public key; and
    /// [`RecipientExportDecryptionErrorV1::MaterialUnavailable`] when the
    /// registered private material is missing, unsafe, or corrupt.
    pub fn decrypt_recipient_export(
        &self,
        owner: &RecipientKeyOwnerV1,
        encoded: &[u8],
        expected_export_id: [u8; 16],
        expected_recipient: RecipientKeyDescriptorV1,
    ) -> Result<DecryptedTimelineExportV1, RecipientExportDecryptionErrorV1> {
        // A read-only handle reserves the writer through its separate writable
        // connection, exactly as the generic decryption-only port does.
        let connection = self
            .writer_reservation_connection
            .as_ref()
            .unwrap_or(&self.conn);
        // This decode is a pre-check before any registry or private-key access,
        // as ADR-098 requires; HPKE decodes again inside the #430 codec API.
        RecipientTimelineExportV1::decode(encoded)
            .map_err(RecipientExportDecryptionErrorV1::Export)
            .and_then(|envelope| {
                check_envelope_identity(&envelope, expected_export_id, expected_recipient, owner)
            })
            .and_then(|()| {
                connection
                    .execute_batch(begin_immediate_sql())
                    .map_err(|_| RECIPIENT_REGISTRY_UNAVAILABLE)
            })
            .and_then(|()| {
                let _rollback = SqliteRollbackOnDrop(connection);
                // A load failure and an absent registry both deliberately
                // report the registry unavailable.
                let mut registry = sqlite_load_key_registry(connection)
                    .ok()
                    .flatten()
                    .ok_or(RECIPIENT_REGISTRY_UNAVAILABLE)?;
                let identity = expected_recipient.identity();
                let registered_digest =
                    registered_material_digest_or_absent_sentinel(&registry, identity);
                registry
                    .with_decryption_authorization(identity, registered_digest, || {
                        Self::decrypt_with_registered_material(
                            connection,
                            owner,
                            registered_digest,
                            encoded,
                            expected_export_id,
                            expected_recipient,
                        )
                    })
                    .map_err(RecipientExportDecryptionErrorV1::Registry)
                    .flatten()
            })
    }

    /// Open the bound private file and decrypt inside the held authorization.
    ///
    /// Any custody, inventory, file-binding, or fingerprint failure leaves the
    /// key unavailable. Registered material that derives another public key
    /// than the presented RKP1 descriptor is an encryption-key mismatch.
    fn decrypt_with_registered_material(
        connection: &Connection,
        owner: &RecipientKeyOwnerV1,
        registered_digest: pos_core::Hash,
        encoded: &[u8],
        expected_export_id: [u8; 16],
        expected_recipient: RecipientKeyDescriptorV1,
    ) -> Result<DecryptedTimelineExportV1, RecipientExportDecryptionErrorV1> {
        ensure_recipient_custody_tables(connection)
            .and_then(|()| claim_recipient_custody_directory(connection, owner))
            .and_then(|()| {
                Self::recipient_inventory_path(connection, owner, expected_recipient.identity())
            })
            .and_then(
                |(stored_descriptor, path, file_identity, inventory_digest)| {
                    if inventory_digest == registered_digest {
                        read_bound_private_key(owner, &path, file_identity)
                            .map(|material| (stored_descriptor, material))
                    } else {
                        Err(CoreError::Storage(
                            "recipient key inventory does not match the registered material"
                                .to_owned(),
                        ))
                    }
                },
            )
            .ok()
            .filter(|(_, material)| key_material_digest(material) == registered_digest)
            .ok_or(RecipientExportDecryptionErrorV1::MaterialUnavailable)
            .and_then(|(stored_descriptor, material)| {
                if recipient_public_key_from_private_v1(&material)
                    == expected_recipient.public_key()
                {
                    // Preserve a forged input descriptor's registry denial:
                    // only material that does match it can expose corrupt
                    // locally recorded RKP1 metadata as unavailable.
                    if stored_descriptor == expected_recipient {
                        decrypt_timeline_export_v1(
                            encoded,
                            expected_export_id,
                            expected_recipient,
                            &material,
                        )
                        .map_err(RecipientExportDecryptionErrorV1::Export)
                    } else {
                        Err(RecipientExportDecryptionErrorV1::MaterialUnavailable)
                    }
                } else {
                    Err(RecipientExportDecryptionErrorV1::Registry(
                        KeyRegistryErrorV1::EncryptionKeyMismatch,
                    ))
                }
            })
    }

    /// Publish one consent-authorized Timeline snapshot as a durable TRX1 object.
    ///
    /// The concrete [`ConsentAuthority`] lock is held first, followed by the
    /// erasure export fence, the `SQLite` writer reservation, and then the
    /// active role-4 registry authorization. The ciphertext is staged and
    /// synced in the owner-bound private directory before a catalog row makes
    /// it visible to readers.
    ///
    /// # Errors
    ///
    /// Returns a closed consent, erasure, registry, crypto, or storage error.
    /// A failed publication does not add a catalog row. Its non-serving
    /// pending record lets a later recovery call remove only the exact
    /// interrupted object names.
    pub fn publish_recipient_export(
        &mut self,
        authority: &ConsentAuthority,
        owner: &RecipientKeyOwnerV1,
        request: &RecipientExportRequestV1<'_>,
    ) -> Result<PublishedRecipientExportV1, RecipientExportPublicationErrorV1> {
        #[cfg(feature = "test-support")]
        let _test_fault_guard = RecipientExportPublicationTestFaultGuard;
        if self.consent_authority_permit != Some(authority.append_permit()) {
            return Err(RecipientExportPublicationErrorV1::Consent(
                ConsentError::NoConsent,
            ));
        }
        if request.token.timeline_id() != request.timeline_id {
            return Err(RecipientExportPublicationErrorV1::Consent(
                ConsentError::NoConsent,
            ));
        }
        if !request.token.export_permitted() {
            return Err(RecipientExportPublicationErrorV1::Consent(
                ConsentError::ExportNotPermitted,
            ));
        }
        if request.token.grantee_id() != owner.grantee_id
            || !request.recipient.is_for_grantee(owner.grantee_id)
        {
            return Err(RecipientExportPublicationErrorV1::RecipientMismatch);
        }
        request
            .evaluation
            .require_authoritative_use(ErasureArtifactClassV1::Export, request.artifact_digest)
            .map_err(|_| RecipientExportPublicationErrorV1::ArtifactUnavailable)?;

        // This is metadata only. The held writer reservation below rechecks
        // it before reading source events, and the concrete consent fence
        // validates the token at this exact expected logical head.
        let expected_logical_head =
            Self::logical_head_unchecked_on(&self.conn, request.timeline_id)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
        let gate = self
            .validated_erasure_gate()
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        #[cfg(feature = "test-support")]
        self.apply_recipient_export_publication_test_race(request.timeline_id)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        // SQLite disallows changing this connection-local setting inside a
        // transaction, so establish the ADR-098 durability floor before the
        // writer reservation is taken.
        let previous_synchronous = ensure_recipient_export_durability(&self.conn)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let mut result = Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage("recipient export consent fence did not execute".to_owned()),
        ));
        let mut under_consent_fence = || {
            result = gate
                .with_fence_value(
                    request.timeline_id,
                    ErasureProtectedOperationV1::Export,
                    || {
                        self.publish_recipient_export_under_fences(
                            owner,
                            request,
                            expected_logical_head,
                        )
                    },
                )
                .map_err(pos_core::store::erasure_containment_error)
                .map_err(RecipientExportPublicationErrorV1::Store)
                .and_then(|publication| publication);
        };
        let result = ConsentGate::with_token_fence(
            authority,
            request.timeline_id,
            request.token,
            expected_logical_head.as_u64(),
            request.now_secs,
            &mut under_consent_fence,
        )
        .map_err(RecipientExportPublicationErrorV1::Consent)
        .and(result);
        finish_recipient_export_durability(&self.conn, previous_synchronous, result)
    }

    #[cfg(feature = "test-support")]
    fn apply_recipient_export_publication_test_race(
        &mut self,
        timeline: TimelineId,
    ) -> Result<(), CoreError> {
        if take_recipient_export_publication_test_fault(
            RecipientExportPublicationTestFaultV1::SourceHeadChanged,
        ) {
            self.append(
                timeline,
                &[pos_core::EventDraft::new(
                    EntityId::new(),
                    pos_core::Kind::new("recipient.export.test-source-change.v1"),
                    pos_core::CanonicalBytes::from_static(b"recipient-export-test-source-change"),
                )],
            )?;
        }
        Ok(())
    }

    fn publish_recipient_export_under_fences(
        &self,
        owner: &RecipientKeyOwnerV1,
        request: &RecipientExportRequestV1<'_>,
        expected_logical_head: Seq,
    ) -> Result<PublishedRecipientExportV1, RecipientExportPublicationErrorV1> {
        #[cfg(feature = "test-support")]
        pause_recipient_export_publication_after_fences(request.timeline_id)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        self.recover_recipient_exports_under_writer(owner)?;
        let export_id = self.reserve_recipient_export_id(owner)?;
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(storage_error)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let pre_authorization = (|| {
            validate_owner_directory(owner).map_err(RecipientExportPublicationErrorV1::Store)?;
            ensure_recipient_custody_tables(&self.conn)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            claim_recipient_custody_directory(&self.conn, owner)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            ensure_recipient_export_catalog(&self.conn)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            if !recipient_export_pending_belongs_to(&self.conn, owner, export_id)
                .map_err(RecipientExportPublicationErrorV1::Store)?
            {
                return Err(RecipientExportPublicationErrorV1::Store(
                    CoreError::Storage("recipient export reservation is unavailable".to_owned()),
                ));
            }

            let logical_head = Self::logical_head_unchecked_on(&self.conn, request.timeline_id)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            if logical_head != expected_logical_head {
                return Err(RecipientExportPublicationErrorV1::SourceChanged);
            }
            if Self::timeline_owner_in_transaction(&self.conn, request.timeline_id)
                .map_err(RecipientExportPublicationErrorV1::Store)?
                != Some(request.token.subject_id())
            {
                return Err(RecipientExportPublicationErrorV1::Consent(
                    ConsentError::NoConsent,
                ));
            }

            let registry = self
                .load_key_registry()
                .map_err(RecipientExportPublicationErrorV1::Store)?
                .ok_or(RecipientExportPublicationErrorV1::Registry(
                    KeyRegistryErrorV1::RegistryUnavailable,
                ))?;
            let identity = request.recipient.identity();
            let registered_digest =
                registered_material_digest_or_absent_sentinel(&registry, identity);
            Ok((registry, identity, registered_digest, logical_head))
        })();
        let (mut registry, identity, registered_digest, logical_head) = match pre_authorization {
            Ok(value) => value,
            Err(error) => return finish_recipient_export_transaction(&self.conn, Err(error)),
        };
        let result =
            match registry.with_encryption_authorization(identity, registered_digest, || {
                // The registry authorization includes the commit itself. The
                // SQLite writer reservation prevents a concurrent rotation or
                // destruction from changing the active role-4 identity between
                // this check and the catalog visibility marker.
                let result = self.publish_recipient_export_with_registered_material(
                    owner,
                    request,
                    registered_digest,
                    export_id,
                    logical_head,
                );
                finish_recipient_export_transaction(&self.conn, result)
            }) {
                Ok(publication) => publication,
                Err(error) => finish_recipient_export_transaction(
                    &self.conn,
                    Err(RecipientExportPublicationErrorV1::Registry(error)),
                ),
            };
        #[cfg(feature = "test-support")]
        clear_recipient_export_publication_test_commit_hook(&self.conn)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        result
    }

    fn publish_recipient_export_with_registered_material(
        &self,
        owner: &RecipientKeyOwnerV1,
        request: &RecipientExportRequestV1<'_>,
        registered_digest: pos_core::Hash,
        export_id: [u8; 16],
        logical_head: Seq,
    ) -> Result<PublishedRecipientExportV1, RecipientExportPublicationErrorV1> {
        let recipient = request.recipient;
        let (stored_descriptor, private_path, file_identity, inventory_digest) =
            Self::recipient_inventory_path(&self.conn, owner, recipient.identity())
                .map_err(|_| RecipientExportPublicationErrorV1::MaterialUnavailable)?;
        if stored_descriptor != recipient || inventory_digest != registered_digest {
            return Err(RecipientExportPublicationErrorV1::MaterialUnavailable);
        }
        let material = read_bound_private_key(owner, &private_path, file_identity)
            .map_err(|_| RecipientExportPublicationErrorV1::MaterialUnavailable)?;
        if key_material_digest(&material) != registered_digest {
            return Err(RecipientExportPublicationErrorV1::MaterialUnavailable);
        }
        if recipient_public_key_from_private_v1(&material) != recipient.public_key() {
            return Err(RecipientExportPublicationErrorV1::Registry(
                KeyRegistryErrorV1::EncryptionKeyMismatch,
            ));
        }

        let source = export_timeline_own(
            self,
            request.timeline_id,
            request.artifact_digest,
            request.evaluation,
        )
        .map_err(RecipientExportPublicationErrorV1::Store)?;
        let mut source = RecipientExportPlaintextStagingV1::new(source)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let timeline_id = source.source().timeline.id();
        let local_head = source.source().timeline.head;
        let mut seed = Zeroizing::new([0_u8; 32]);
        recipient_random_bytes(&mut *seed).map_err(|error| {
            RecipientExportPublicationErrorV1::Store(recipient_rng_error(&error))
        })?;
        let mut rng = StdRng::from_seed(*seed);
        let encoded = encrypt_timeline_export_v1(source.source(), recipient, export_id, &mut rng)
            .map_err(RecipientExportPublicationErrorV1::Export)?
            .encode();
        source
            .zeroize()
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let ciphertext_length = u64::try_from(encoded.len())
            .map_err(|error| RecipientExportPublicationErrorV1::Store(storage_error(error)))?;
        let ciphertext_digest = pos_core::Hash::from_bytes(*blake3::hash(&encoded).as_bytes());
        write_recipient_export_ciphertext(owner, export_id, &encoded)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let publication = PublishedRecipientExportV1 {
            export_id,
            recipient,
            timeline_id,
            local_head,
            logical_head,
            ciphertext_length,
            ciphertext_digest,
        };
        record_recipient_export_catalog(&self.conn, owner, &publication)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        remove_recipient_export_pending(&self.conn, export_id)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        #[cfg(feature = "test-support")]
        install_recipient_export_publication_test_commit_abort(&self.conn)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        Ok(publication)
    }

    fn reserve_recipient_export_id(
        &self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<[u8; 16], RecipientExportPublicationErrorV1> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(storage_error)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let result = (|| -> Result<[u8; 16], RecipientExportPublicationErrorV1> {
            validate_owner_directory(owner).map_err(RecipientExportPublicationErrorV1::Store)?;
            ensure_recipient_custody_tables(&self.conn)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            claim_recipient_custody_directory(&self.conn, owner)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            ensure_recipient_export_catalog(&self.conn)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            let export_id = fresh_recipient_export_id()?;
            if recipient_export_catalog_contains(&self.conn, export_id)
                .map_err(RecipientExportPublicationErrorV1::Store)?
                || recipient_export_pending_contains(&self.conn, export_id)
                    .map_err(RecipientExportPublicationErrorV1::Store)?
            {
                return Err(RecipientExportPublicationErrorV1::IdentifierCollision);
            }
            record_recipient_export_pending(&self.conn, owner, export_id)
                .map_err(RecipientExportPublicationErrorV1::Store)?;
            Ok(export_id)
        })();
        finish_recipient_export_transaction(&self.conn, result)
    }

    fn recover_recipient_exports_under_writer(
        &self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<(), RecipientExportPublicationErrorV1> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(storage_error)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let result =
            (|| -> Result<RecipientExportRecoveryProgressV1, RecipientExportPublicationErrorV1> {
                validate_owner_directory(owner)
                    .map_err(RecipientExportPublicationErrorV1::Store)?;
                ensure_recipient_custody_tables(&self.conn)
                    .map_err(RecipientExportPublicationErrorV1::Store)?;
                claim_recipient_custody_directory(&self.conn, owner)
                    .map_err(RecipientExportPublicationErrorV1::Store)?;
                ensure_recipient_export_catalog(&self.conn)
                    .map_err(RecipientExportPublicationErrorV1::Store)?;
                reconcile_recipient_export_objects(&self.conn, owner)
                    .map_err(RecipientExportPublicationErrorV1::Store)
            })();
        match finish_recipient_export_transaction(&self.conn, result)? {
            RecipientExportRecoveryProgressV1::Complete => Ok(()),
            RecipientExportRecoveryProgressV1::Incomplete => {
                Err(RecipientExportPublicationErrorV1::RecoveryIncomplete)
            }
        }
    }

    /// Read one catalog-visible ciphertext object and verify every immutable binding.
    ///
    /// This returns only the encrypted TRX1 bytes. It never decrypts or imports
    /// the candidate Timeline into the local event store.
    ///
    /// # Errors
    ///
    /// Returns [`RecipientExportPublicationErrorV1::ArtifactUnavailable`] for
    /// an absent, malformed, or digest-mismatched catalog object.
    pub fn read_recipient_export(
        &self,
        owner: &RecipientKeyOwnerV1,
        export_id: [u8; 16],
    ) -> Result<Vec<u8>, RecipientExportPublicationErrorV1> {
        validate_owner_directory(owner).map_err(RecipientExportPublicationErrorV1::Store)?;
        let stored = load_recipient_export_catalog(&self.conn, export_id)
            .map_err(RecipientExportPublicationErrorV1::Store)?
            .ok_or(RecipientExportPublicationErrorV1::ArtifactUnavailable)?;
        let expected = stored
            .validate_for(owner)
            .ok_or(RecipientExportPublicationErrorV1::ArtifactUnavailable)?;
        let encoded =
            read_recipient_export_ciphertext(owner, export_id, expected.ciphertext_length)
                .map_err(|_| RecipientExportPublicationErrorV1::ArtifactUnavailable)?;
        if pos_core::Hash::from_bytes(*blake3::hash(&encoded).as_bytes())
            != expected.ciphertext_digest
        {
            return Err(RecipientExportPublicationErrorV1::ArtifactUnavailable);
        }
        let envelope = RecipientTimelineExportV1::decode(&encoded)
            .map_err(|_| RecipientExportPublicationErrorV1::ArtifactUnavailable)?;
        if envelope.header.export_id != export_id
            || envelope.header.recipient != expected.recipient
            || envelope.header.timeline_id != expected.timeline_id
            || envelope.header.local_head != expected.local_head
        {
            return Err(RecipientExportPublicationErrorV1::ArtifactUnavailable);
        }
        Ok(encoded)
    }

    /// Recover one bounded batch of pending staging and final ciphertext files.
    ///
    /// Recovery never scans the directory, creates catalog entries, or
    /// reconstructs an export. The `SQLite` catalog remains the only visibility
    /// marker.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the durable directory or catalog cannot be
    /// inspected under the `SQLite` writer reservation. Returns
    /// [`RecipientExportPublicationErrorV1::RecoveryIncomplete`] after committing
    /// a bounded batch when another pass is required.
    pub fn recover_recipient_exports(
        &mut self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<(), RecipientExportPublicationErrorV1> {
        let previous_synchronous = ensure_recipient_export_durability(&self.conn)
            .map_err(RecipientExportPublicationErrorV1::Store)?;
        let result = self.recover_recipient_exports_under_writer(owner);
        finish_recipient_export_durability(&self.conn, previous_synchronous, result)
    }

    /// Fix the next acceptance-test publication identifier.
    ///
    /// This exists only behind the nondefault test-support feature so an
    /// external test can inspect the exact interrupted object identity.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] for a zero identifier or when another
    /// test identifier is already configured on this thread.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn set_recipient_export_publication_test_export_id(
        &self,
        export_id: [u8; 16],
    ) -> Result<(), CoreError> {
        if export_id == [0; 16] {
            return Err(CoreError::Storage(
                "recipient export test ID must be nonzero".to_owned(),
            ));
        }
        RECIPIENT_EXPORT_PUBLICATION_TEST_EXPORT_ID.with(|configured| {
            if configured.get().is_some() {
                return Err(CoreError::Storage(
                    "recipient export test ID is already configured".to_owned(),
                ));
            }
            configured.set(Some(export_id));
            Ok(())
        })
    }

    /// Pause the next test publication for one Timeline after its fences hold.
    ///
    /// This exists only behind the nondefault test-support feature so an
    /// external test can prove that neither competing lifecycle operation
    /// can pass its real fence before catalog publication linearizes.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when another pause is already configured
    /// or test synchronization is unavailable.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn pause_recipient_export_publication_after_fences_for_test(
        &self,
        timeline: TimelineId,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), CoreError> {
        RECIPIENT_EXPORT_PUBLICATION_TEST_FENCE_PAUSES
            .lock()
            .map_err(|_| {
                CoreError::Storage("recipient export test pause is unavailable".to_owned())
            })
            .and_then(|mut pauses| {
                if pauses.iter().any(|(configured, _)| *configured == timeline) {
                    return Err(CoreError::Storage(
                        "recipient export test pause is already configured".to_owned(),
                    ));
                }
                pauses.push((
                    timeline,
                    RecipientExportPublicationTestFencePause { entered, release },
                ));
                Ok(())
            })
    }

    /// Inject one narrow recipient-export boundary failure for an acceptance
    /// test. The fault is consumed by the normal publication path.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when another test fault is already
    /// configured on this thread.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn inject_recipient_export_publication_test_fault(
        &self,
        fault: RecipientExportPublicationTestFaultV1,
    ) -> Result<(), CoreError> {
        RECIPIENT_EXPORT_PUBLICATION_TEST_NAMED_PLAINTEXT_OBSERVED
            .with(|observed| observed.set(false));
        RECIPIENT_EXPORT_PUBLICATION_TEST_FAULT.with(|configured| {
            if configured.replace(Some(fault)).is_some() {
                return Err(CoreError::Storage(
                    "recipient export test fault is already configured".to_owned(),
                ));
            }
            Ok(())
        })
    }

    /// Inspect only the exact opaque object names derived from one test export
    /// identifier. This never accepts a filesystem path or scans a directory.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the owner directory cannot be
    /// validated or either exact object name cannot be inspected.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn inspect_recipient_export_publication_test_artifacts(
        &self,
        owner: &RecipientKeyOwnerV1,
        export_id: [u8; 16],
    ) -> Result<RecipientExportPublicationTestArtifactsV1, CoreError> {
        validate_owner_directory(owner)?;
        let named_plaintext_observed = RECIPIENT_EXPORT_PUBLICATION_TEST_NAMED_PLAINTEXT_OBSERVED
            .with(|observed| observed.replace(false));
        Ok(RecipientExportPublicationTestArtifactsV1 {
            staging_ciphertext_exists: recipient_export_test_object_exists(
                owner,
                recipient_export_staging_name(export_id)?.as_c_str(),
            )?,
            final_ciphertext_exists: recipient_export_test_object_exists(
                owner,
                recipient_export_final_name(export_id)?.as_c_str(),
            )?,
            named_plaintext_observed,
        })
    }

    /// Mark one recipient epoch pending, durably remove its owned key file,
    /// then commit the irreversible registry tombstone.
    ///
    /// Destruction means durable deletion of the inventory-bound file: the
    /// exact bound name is unlinked relative to the retained private directory
    /// descriptor and the directory is synced before the receipt commits.
    /// Accepted ADR-098 says the adapter "durably deletes the owned file with
    /// a receipt bound to its original path and file identity"; it does
    /// not require overwriting the 32 key bytes, which journaling,
    /// copy-on-write, and flash-translation storage would not guarantee to
    /// erase anyway. Process copies are zeroized when dropped.
    ///
    /// Retrying a pending destruction resumes it. If an earlier attempt already
    /// unlinked the exact bound name but stopped before committing, the retry
    /// syncs the directory and commits the receipt from the stored inventory
    /// path and file identity instead of leaving the epoch pending forever.
    ///
    /// A destruction receipt therefore attests that the inventory-bound name
    /// is durably absent after an authorized destruction request. The name may
    /// already have been absent before this call (for example, unlinked by an
    /// interrupted earlier attempt); the receipt does not claim that this call
    /// performed the unlink.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the requested identity is unavailable, its
    /// material cannot be safely removed, or a durable custody transition
    /// cannot commit.
    pub fn destroy_recipient_key(
        &mut self,
        owner: &RecipientKeyOwnerV1,
        epoch: u64,
        authorization_digest: pos_core::Hash,
    ) -> Result<(), CoreError> {
        let begun = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(storage_error)
            .and_then(|owner_id| {
                let identity = KeyIdentityV1::from_parts(
                    owner_id,
                    KeyRoleV1::ExportRecipientEncryption,
                    epoch,
                );
                self.conn
                    .execute_batch(begin_immediate_sql())
                    .map_err(storage_error)
                    .and_then(|()| ensure_recipient_custody_tables(&self.conn))
                    .and_then(|()| claim_recipient_custody_directory(&self.conn, owner))
                    .and_then(|()| self.load_key_registry())
                    .and_then(|registry| {
                        registry.ok_or_else(|| {
                            CoreError::Storage("recipient registry is unavailable".to_owned())
                        })
                    })
                    .and_then(|mut registry| {
                        let record = registry.key_record(identity).ok_or_else(|| {
                            CoreError::Storage("recipient identity is unavailable".to_owned())
                        })?;
                        let digest = record.private_material_digest.ok_or_else(|| {
                            CoreError::Storage("recipient identity is already destroyed".to_owned())
                        })?;
                        let request =
                            KeyDestructionRequestV1::new(identity, digest, authorization_digest);
                        registry
                            .begin_key_destruction(request)
                            .map_err(storage_error)
                            .and_then(|outcome| {
                                if matches!(
                                    outcome,
                                    pos_core::KeyDestructionBeginOutcomeV1::Started
                                ) {
                                    self.save_key_registry_in_transaction(&registry)
                                        .map(|()| (request, outcome))
                                } else {
                                    Ok((request, outcome))
                                }
                            })
                    })
            });
        let (request, _) = finish_immediate_transaction(&self.conn, begun)?;
        self.finish_recipient_key_destruction(owner, request)
    }

    /// Resume the exact pending request under the `SQLite` writer reservation.
    ///
    /// The receipt row and registry tombstone commit together only after the
    /// directory-relative unlink and directory sync. If a process stopped after
    /// unlinking but before that commit, the exact inventory-bound name is
    /// absent; the retry re-syncs the directory and records the receipt from
    /// the inventory row's stored path and file identity. The pending epoch is
    /// never reactivated.
    fn finish_recipient_key_destruction(
        &self,
        owner: &RecipientKeyOwnerV1,
        request: KeyDestructionRequestV1,
    ) -> Result<(), CoreError> {
        let result = self
            .conn
            .execute_batch(begin_immediate_sql())
            .map_err(storage_error)
            .and_then(|()| ensure_recipient_custody_tables(&self.conn))
            .and_then(|()| claim_recipient_custody_directory(&self.conn, owner))
            .and_then(|()| self.load_key_registry())
            .and_then(|registry| {
                registry.ok_or_else(|| {
                    CoreError::Storage("recipient registry is unavailable".to_owned())
                })
            })
            .and_then(|mut registry| {
                if registry.tombstone(request.identity).is_some() {
                    return Ok(());
                }
                if !registry
                    .pending_destruction_requests()
                    .any(|pending| pending == request)
                {
                    return Err(CoreError::Storage(
                        "recipient destruction request is no longer pending".to_owned(),
                    ));
                }
                let (_, path, bound_file, inventory_digest) =
                    Self::recipient_inventory_path(&self.conn, owner, request.identity)?;
                if inventory_digest != request.expected_material_digest {
                    return Err(CoreError::Storage(
                        "recipient inventory material differs from pending destruction".to_owned(),
                    ));
                }
                delete_bound_private_key(owner, &path, bound_file, inventory_digest)?;
                let receipt = pos_core::deletion_receipt(&request);
                record_recipient_destruction_receipt(
                    &self.conn, request, &path, bound_file, receipt,
                )?;
                registry
                    .complete_key_destruction(request, receipt)
                    .map_err(storage_error)
                    .and_then(|_| {
                        i64::try_from(request.identity.epoch)
                            .map_err(storage_error)
                            .and_then(|epoch| {
                                self.conn.execute(
                    "DELETE FROM recipient_key_inventory_v1 WHERE owner_id = ?1 AND epoch = ?2",
                    rusqlite::params![
                        request.identity.owner_id.as_str(),
                        epoch
                    ],
                ).map_err(storage_error)
                            })
                    })
                    .and_then(|removed| {
                        if removed != 1 {
                            return Err(CoreError::Storage(
                                "recipient key inventory changed during destruction".to_owned(),
                            ));
                        }
                        self.save_key_registry_in_transaction(&registry)
                    })
            });
        finish_immediate_transaction(&self.conn, result)
    }

    fn recipient_inventory_path(
        connection: &Connection,
        owner: &RecipientKeyOwnerV1,
        identity: KeyIdentityV1,
    ) -> Result<
        (
            RecipientKeyDescriptorV1,
            PathBuf,
            RecipientPrivateFileIdentityV1,
            pos_core::Hash,
        ),
        CoreError,
    > {
        use std::os::unix::ffi::OsStringExt;

        i64::try_from(identity.epoch)
            .map_err(storage_error)
            .and_then(|epoch| {
                connection.query_row(
                "SELECT descriptor, material_digest, private_path, file_device, file_inode, file_uid FROM recipient_key_inventory_v1 WHERE owner_id = ?1 AND epoch = ?2",
                rusqlite::params![
                    identity.owner_id.as_str(),
                    epoch
                ],
                recipient_inventory_from_row,
            )
                .map_err(storage_error)
            })
            .and_then(|inventory| {
                RecipientKeyDescriptorV1::decode(&inventory.descriptor)
                    .map_err(storage_error)
                    .and_then(|descriptor| {
                        if descriptor.identity() != identity
                            || !descriptor.is_for_grantee(owner.grantee_id)
                        {
                            return Err(CoreError::Storage(
                                "recipient key inventory identity is invalid".to_owned(),
                            ));
                        }
                        // The writer-reserved directory claim validates the descriptor-derived
                        // filename before this identity-specific inventory lookup.
                        let path = PathBuf::from(std::ffi::OsString::from_vec(
                            inventory.private_path.clone(),
                        ));
                        inventory
                            .material_digest
                            .as_slice()
                            .try_into()
                            .map_err(|_| {
                                CoreError::Storage(
                                    "recipient key inventory material digest is invalid".to_owned(),
                                )
                            })
                            .and_then(|material_digest| {
                                RecipientPrivateFileIdentityV1::from_inventory(&inventory).map(
                                    |file_identity| {
                                        (
                                            descriptor,
                                            path,
                                            file_identity,
                                            pos_core::Hash::from_bytes(material_digest),
                                        )
                                    },
                                )
                            })
                    })
            })
    }
}

const RECIPIENT_EXPORT_PREFIX: &[u8] = b"recipient-export-";
const RECIPIENT_EXPORT_FINAL_SUFFIX: &[u8] = b".trx1";
const RECIPIENT_EXPORT_STAGING_SUFFIX: &[u8] = b".trx1.staging";
const MAX_RECIPIENT_EXPORT_RECOVERY_PER_PASS: usize = 256;
const MAX_RECIPIENT_EXPORT_CIPHERTEXT_BYTES: u64 = (1_u64 << 30) + (2 * 1024 * 1024);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecipientExportRecoveryProgressV1 {
    Complete,
    Incomplete,
}

struct StoredRecipientExportV1 {
    owner_id: String,
    recipient_epoch: i64,
    recipient_descriptor: Vec<u8>,
    timeline_id: String,
    local_head: i64,
    logical_head: i64,
    ciphertext_length: i64,
    ciphertext_digest: Vec<u8>,
}

struct ValidatedRecipientExportCatalogV1 {
    recipient: RecipientKeyDescriptorV1,
    timeline_id: TimelineId,
    local_head: Seq,
    ciphertext_length: u64,
    ciphertext_digest: pos_core::Hash,
}

impl StoredRecipientExportV1 {
    fn validate_for(
        self,
        owner: &RecipientKeyOwnerV1,
    ) -> Option<ValidatedRecipientExportCatalogV1> {
        let expected_owner = recipient_owner_id_from_grantee(owner.grantee_id).ok()?;
        let recipient = RecipientKeyDescriptorV1::decode(&self.recipient_descriptor).ok()?;
        let recipient_epoch = u64::try_from(self.recipient_epoch).ok()?;
        let local_head = Seq::from_u64(u64::try_from(self.local_head).ok()?);
        let _logical_head = Seq::from_u64(u64::try_from(self.logical_head).ok()?);
        let ciphertext_length = u64::try_from(self.ciphertext_length).ok()?;
        if ciphertext_length > MAX_RECIPIENT_EXPORT_CIPHERTEXT_BYTES {
            return None;
        }
        let ciphertext_digest: [u8; 32] = self.ciphertext_digest.try_into().ok()?;
        if self.owner_id != expected_owner.as_str()
            || recipient.identity().owner_id != expected_owner
            || recipient.identity().epoch != recipient_epoch
            || !recipient.is_for_grantee(owner.grantee_id)
        {
            return None;
        }
        Some(ValidatedRecipientExportCatalogV1 {
            recipient,
            timeline_id: parse_timeline_id(&self.timeline_id).ok()?,
            local_head,
            ciphertext_length,
            ciphertext_digest: pos_core::Hash::from_bytes(ciphertext_digest),
        })
    }
}

fn current_sqlite_synchronous_level(connection: &Connection) -> Result<i64, CoreError> {
    connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(storage_error)
}

fn recipient_export_synchronous_level(connection: &Connection) -> Result<i64, CoreError> {
    #[cfg(test)]
    if let Some(synchronous) = RECIPIENT_DURABILITY_SYNCHRONOUS_OVERRIDE.with(std::cell::Cell::take)
    {
        return Ok(synchronous);
    }
    #[cfg(test)]
    if RECIPIENT_DURABILITY_SYNCHRONOUS_READ_FAILURE.with(std::cell::Cell::get) {
        return Err(CoreError::Storage(
            "injected recipient export synchronous read failure".to_owned(),
        ));
    }
    current_sqlite_synchronous_level(connection)
}

fn restore_recipient_export_synchronous_level(
    connection: &Connection,
    previous_synchronous: i64,
) -> Result<(), CoreError> {
    connection
        .pragma_update(None, "synchronous", previous_synchronous)
        .map_err(storage_error)
}

fn ensure_recipient_export_durability(connection: &Connection) -> Result<i64, CoreError> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(storage_error)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(CoreError::Storage(
            "recipient export publication requires SQLite WAL".to_owned(),
        ));
    }
    let previous_synchronous = current_sqlite_synchronous_level(connection)?;
    connection
        .execute_batch("PRAGMA synchronous=FULL")
        .map_err(storage_error)?;
    match recipient_export_synchronous_level(connection) {
        Ok(synchronous) if synchronous >= 2 => Ok(previous_synchronous),
        Ok(_) => {
            restore_recipient_export_synchronous_level(connection, previous_synchronous)?;
            Err(CoreError::Storage(
                "recipient export publication requires SQLite synchronous=FULL".to_owned(),
            ))
        }
        Err(error) => {
            restore_recipient_export_synchronous_level(connection, previous_synchronous)?;
            Err(error)
        }
    }
}

fn finish_recipient_export_durability<T>(
    connection: &Connection,
    previous_synchronous: i64,
    result: Result<T, RecipientExportPublicationErrorV1>,
) -> Result<T, RecipientExportPublicationErrorV1> {
    // The transaction outcome is already conclusive. A best-effort setting
    // restoration failure leaves the safer FULL mode enabled and must not
    // reclassify a committed publication as failed.
    drop(restore_recipient_export_synchronous_level(
        connection,
        previous_synchronous,
    ));
    result
}

fn finish_recipient_export_transaction<T>(
    connection: &Connection,
    result: Result<T, RecipientExportPublicationErrorV1>,
) -> Result<T, RecipientExportPublicationErrorV1> {
    finish_transaction(
        connection,
        result,
        |commit_error, rollback_error| {
            RecipientExportPublicationErrorV1::Store(rollback_error.map_or_else(
                || CoreError::Storage(format!("transaction commit failed: {commit_error}")),
                |rollback_error| {
                    CoreError::StorageOutcomeUnknown(format!(
                        "transaction commit failed: {commit_error}; rollback failed: {rollback_error}"
                    ))
                },
            ))
        },
        |error, rollback_error| {
            RecipientExportPublicationErrorV1::Store(CoreError::StorageOutcomeUnknown(format!(
                "{error}; rollback failed: {rollback_error}"
            )))
        },
    )
}

fn ensure_recipient_export_catalog(connection: &Connection) -> Result<(), CoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS recipient_export_catalog_v1 (
                export_id BLOB NOT NULL PRIMARY KEY CHECK (length(export_id) = 16),
                owner_id TEXT NOT NULL,
                recipient_epoch INTEGER NOT NULL CHECK (recipient_epoch > 0),
                recipient_descriptor BLOB NOT NULL,
                timeline_id TEXT NOT NULL,
                local_head INTEGER NOT NULL CHECK (local_head >= 0),
                logical_head INTEGER NOT NULL CHECK (logical_head >= 0),
                ciphertext_length INTEGER NOT NULL CHECK (ciphertext_length >= 0),
                ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32)
            );
            CREATE TABLE IF NOT EXISTS recipient_export_pending_v1 (
                export_id BLOB NOT NULL PRIMARY KEY CHECK (length(export_id) = 16),
                owner_id TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS recipient_export_pending_owner_v1
                ON recipient_export_pending_v1 (owner_id, export_id);",
        )
        .map_err(storage_error)
}

fn record_recipient_export_catalog(
    connection: &Connection,
    owner: &RecipientKeyOwnerV1,
    publication: &PublishedRecipientExportV1,
) -> Result<(), CoreError> {
    let owner_id = recipient_owner_id_from_grantee(owner.grantee_id).map_err(storage_error)?;
    let epoch = i64::try_from(publication.recipient.identity().epoch).map_err(storage_error)?;
    let local_head = i64::try_from(publication.local_head.as_u64()).map_err(storage_error)?;
    let logical_head = i64::try_from(publication.logical_head.as_u64()).map_err(storage_error)?;
    let ciphertext_length = i64::try_from(publication.ciphertext_length).map_err(storage_error)?;
    connection
        .execute(
            "INSERT INTO recipient_export_catalog_v1
             (export_id, owner_id, recipient_epoch, recipient_descriptor, timeline_id,
              local_head, logical_head, ciphertext_length, ciphertext_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                publication.export_id.as_slice(),
                owner_id.as_str(),
                epoch,
                publication.recipient.encode(),
                publication.timeline_id.to_string(),
                local_head,
                logical_head,
                ciphertext_length,
                publication.ciphertext_digest.as_bytes().as_slice(),
            ],
        )
        .map(|_| ())
        .map_err(storage_error)
}

fn recipient_export_catalog_exists(connection: &Connection) -> Result<bool, CoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'recipient_export_catalog_v1'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(storage_error)
}

fn load_recipient_export_catalog(
    connection: &Connection,
    export_id: [u8; 16],
) -> Result<Option<StoredRecipientExportV1>, CoreError> {
    if !recipient_export_catalog_exists(connection)? {
        return Ok(None);
    }
    connection
        .query_row(
            "SELECT owner_id, recipient_epoch, recipient_descriptor, timeline_id,
                    local_head, logical_head, ciphertext_length, ciphertext_digest
             FROM recipient_export_catalog_v1 WHERE export_id = ?1",
            rusqlite::params![export_id.as_slice()],
            |row| {
                Ok(StoredRecipientExportV1 {
                    owner_id: row.get(0)?,
                    recipient_epoch: row.get(1)?,
                    recipient_descriptor: row.get(2)?,
                    timeline_id: row.get(3)?,
                    local_head: row.get(4)?,
                    logical_head: row.get(5)?,
                    ciphertext_length: row.get(6)?,
                    ciphertext_digest: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(storage_error)
}

fn recipient_export_catalog_contains(
    connection: &Connection,
    export_id: [u8; 16],
) -> Result<bool, CoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM recipient_export_catalog_v1 WHERE export_id = ?1)",
            rusqlite::params![export_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage_error)
}

fn recipient_export_pending_contains(
    connection: &Connection,
    export_id: [u8; 16],
) -> Result<bool, CoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM recipient_export_pending_v1 WHERE export_id = ?1)",
            rusqlite::params![export_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage_error)
}

fn recipient_export_pending_belongs_to(
    connection: &Connection,
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
) -> Result<bool, CoreError> {
    let owner_id = recipient_owner_id_from_grantee(owner.grantee_id).map_err(storage_error)?;
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM recipient_export_pending_v1
                WHERE export_id = ?1 AND owner_id = ?2
            )",
            rusqlite::params![export_id.as_slice(), owner_id.as_str()],
            |row| row.get(0),
        )
        .map_err(storage_error)
}

fn record_recipient_export_pending(
    connection: &Connection,
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
) -> Result<(), CoreError> {
    let owner_id = recipient_owner_id_from_grantee(owner.grantee_id).map_err(storage_error)?;
    connection
        .execute(
            "INSERT INTO recipient_export_pending_v1 (export_id, owner_id) VALUES (?1, ?2)",
            rusqlite::params![export_id.as_slice(), owner_id.as_str()],
        )
        .map(|_| ())
        .map_err(storage_error)
}

fn remove_recipient_export_pending(
    connection: &Connection,
    export_id: [u8; 16],
) -> Result<(), CoreError> {
    let removed = connection
        .execute(
            "DELETE FROM recipient_export_pending_v1 WHERE export_id = ?1",
            rusqlite::params![export_id.as_slice()],
        )
        .map_err(storage_error)?;
    if removed == 1 {
        Ok(())
    } else {
        Err(CoreError::Storage(
            "recipient export reservation is unavailable".to_owned(),
        ))
    }
}

fn load_recipient_export_pending(
    connection: &Connection,
    owner: &RecipientKeyOwnerV1,
) -> Result<(Vec<[u8; 16]>, bool), CoreError> {
    let owner_id = recipient_owner_id_from_grantee(owner.grantee_id).map_err(storage_error)?;
    let limit = i64::try_from(MAX_RECIPIENT_EXPORT_RECOVERY_PER_PASS.saturating_add(1))
        .map_err(storage_error)?;
    let mut statement = connection
        .prepare(
            "SELECT export_id FROM recipient_export_pending_v1
             WHERE owner_id = ?1 ORDER BY export_id LIMIT ?2",
        )
        .map_err(storage_error)?;
    let rows = statement
        .query_map(rusqlite::params![owner_id.as_str(), limit], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(storage_error)?;
    let mut export_ids = Vec::new();
    for row in rows {
        let export_id: [u8; 16] = row.map_err(storage_error)?.try_into().map_err(|_| {
            CoreError::Storage("recipient export reservation is invalid".to_owned())
        })?;
        export_ids.push(export_id);
    }
    let incomplete = export_ids.len() > MAX_RECIPIENT_EXPORT_RECOVERY_PER_PASS;
    if incomplete {
        let _ = export_ids.pop();
    }
    Ok((export_ids, incomplete))
}

fn fresh_recipient_export_id() -> Result<[u8; 16], RecipientExportPublicationErrorV1> {
    #[cfg(feature = "test-support")]
    let configured_export_id =
        RECIPIENT_EXPORT_PUBLICATION_TEST_EXPORT_ID.with(std::cell::Cell::take);
    #[cfg(not(feature = "test-support"))]
    let configured_export_id = None;

    let export_id = configured_export_id.map_or_else(
        || {
            let mut export_id = [0_u8; 16];
            recipient_random_bytes(&mut export_id)
                .map_err(|error| {
                    RecipientExportPublicationErrorV1::Store(recipient_rng_error(&error))
                })
                .map(|()| export_id)
        },
        Ok,
    )?;
    if export_id == [0; 16] {
        return Err(RecipientExportPublicationErrorV1::Export(
            RecipientExportErrorV1::FieldOutOfBounds,
        ));
    }
    Ok(export_id)
}

fn recipient_export_name(export_id: [u8; 16], suffix: &[u8]) -> Result<CString, CoreError> {
    let mut name =
        Vec::with_capacity(RECIPIENT_EXPORT_PREFIX.len() + (export_id.len() * 2) + suffix.len());
    name.extend_from_slice(RECIPIENT_EXPORT_PREFIX);
    for byte in export_id {
        name.push(b"0123456789abcdef"[usize::from(byte >> 4)]);
        name.push(b"0123456789abcdef"[usize::from(byte & 0x0f)]);
    }
    name.extend_from_slice(suffix);
    CString::new(name).map_err(storage_error)
}

fn recipient_export_final_name(export_id: [u8; 16]) -> Result<CString, CoreError> {
    recipient_export_name(export_id, RECIPIENT_EXPORT_FINAL_SUFFIX)
}

fn recipient_export_staging_name(export_id: [u8; 16]) -> Result<CString, CoreError> {
    recipient_export_name(export_id, RECIPIENT_EXPORT_STAGING_SUFFIX)
}

#[cfg(feature = "test-support")]
fn recipient_export_test_object_exists(
    owner: &RecipientKeyOwnerV1,
    name: &std::ffi::CStr,
) -> Result<bool, CoreError> {
    match recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(storage_error(error)),
    }
}

fn validate_recipient_export_file(
    metadata: &std::fs::Metadata,
    owner: &RecipientKeyOwnerV1,
    expected_length: u64,
) -> Result<(), CoreError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != owner.directory_uid
        || metadata.len() != expected_length
    {
        return Err(CoreError::Storage(
            "recipient export object is not a private single-link file".to_owned(),
        ));
    }
    Ok(())
}

fn verify_recipient_export_entry(
    owner: &RecipientKeyOwnerV1,
    name: &std::ffi::CStr,
    expected_length: u64,
) -> Result<(), CoreError> {
    recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(storage_error)
        .and_then(|metadata| {
            if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG
                || metadata.st_nlink != 1
                || metadata.st_mode & 0o777 != 0o600
                || metadata.st_uid != owner.directory_uid
                || u64::try_from(metadata.st_size).ok() != Some(expected_length)
            {
                return Err(CoreError::Storage(
                    "recipient export object is not a private single-link file".to_owned(),
                ));
            }
            Ok(())
        })
}

fn write_recipient_export_ciphertext(
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
    encoded: &[u8],
) -> Result<(), CoreError> {
    let expected_length = u64::try_from(encoded.len()).map_err(storage_error)?;
    validate_owner_directory(owner)?;
    let staging = recipient_export_staging_name(export_id)?;
    let final_name = recipient_export_final_name(export_id)?;
    #[cfg(feature = "test-support")]
    RECIPIENT_EXPORT_PUBLICATION_TEST_NAMED_PLAINTEXT_OBSERVED.with(|observed| {
        observed.set(observed.get() | RecipientTimelineExportV1::decode(encoded).is_err());
    });
    recipient_openat2(
        &owner.directory_file,
        staging.as_c_str(),
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(storage_error)
    .and_then(|mut file| {
        file.metadata().map_err(storage_error).and_then(|metadata| {
            validate_recipient_export_file(&metadata, owner, 0)
                .and_then(|()| recipient_write_all(&mut file, encoded).map_err(storage_error))
                .and_then(|()| {
                    #[cfg(feature = "test-support")]
                    recipient_export_publication_test_sync_fault(
                        RecipientExportPublicationTestFaultV1::FileSync,
                    )?;
                    recipient_fsync(&file).map_err(storage_error)
                })
                .and_then(|()| file.metadata().map_err(storage_error))
                .and_then(|metadata| {
                    validate_recipient_export_file(&metadata, owner, expected_length)
                })
                .and_then(|()| {
                    verify_recipient_export_entry(owner, staging.as_c_str(), expected_length)
                })
                .and_then(|()| {
                    renameat_with(
                        &owner.directory_file,
                        staging.as_c_str(),
                        &owner.directory_file,
                        final_name.as_c_str(),
                        RenameFlags::NOREPLACE,
                    )
                    .map_err(storage_error)
                })
                .and_then(|()| {
                    #[cfg(feature = "test-support")]
                    recipient_export_publication_test_sync_fault(
                        RecipientExportPublicationTestFaultV1::DirectorySync,
                    )?;
                    recipient_fsync(&owner.directory_file).map_err(storage_error)
                })
                .and_then(|()| {
                    verify_recipient_export_entry(owner, final_name.as_c_str(), expected_length)
                })
        })
    })
}

fn read_recipient_export_ciphertext(
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
    expected_length: u64,
) -> Result<Vec<u8>, CoreError> {
    if expected_length > MAX_RECIPIENT_EXPORT_CIPHERTEXT_BYTES {
        return Err(CoreError::Storage(
            "recipient export object exceeds the TRX1 bound".to_owned(),
        ));
    }
    let capacity = usize::try_from(expected_length).map_err(storage_error)?;
    validate_owner_directory(owner)?;
    let name = recipient_export_final_name(export_id)?;
    recipient_openat2(
        &owner.directory_file,
        name.as_c_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(storage_error)
    .and_then(|mut file| {
        file.metadata().map_err(storage_error).and_then(|metadata| {
            validate_recipient_export_file(&metadata, owner, expected_length).and_then(|()| {
                let mut encoded = vec![0_u8; capacity];
                recipient_read_exact(&mut file, &mut encoded)
                    .map_err(storage_error)
                    .and_then(|()| {
                        verify_recipient_export_entry(owner, name.as_c_str(), expected_length)
                    })
                    .map(|()| encoded)
            })
        })
    })
}

const fn is_safe_recipient_export_entry(
    owner: &RecipientKeyOwnerV1,
    metadata: &rustix::fs::Stat,
) -> bool {
    (metadata.st_mode & libc::S_IFMT) == libc::S_IFREG
        && metadata.st_nlink == 1
        && metadata.st_mode & 0o777 == 0o600
        && metadata.st_uid == owner.directory_uid
}

fn remove_pending_recipient_export_object(
    owner: &RecipientKeyOwnerV1,
    name: &std::ffi::CStr,
) -> Result<bool, CoreError> {
    match recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => {
            if !is_safe_recipient_export_entry(owner, &metadata) {
                return Err(CoreError::Storage(
                    "recipient export recovery found an unsafe object".to_owned(),
                ));
            }
            recipient_unlinkat(&owner.directory_file, name, AtFlags::empty())
                .map_err(storage_error)?;
            Ok(true)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(storage_error(error)),
    }
}

fn reconcile_recipient_export_objects(
    connection: &Connection,
    owner: &RecipientKeyOwnerV1,
) -> Result<RecipientExportRecoveryProgressV1, CoreError> {
    let (export_ids, incomplete) = load_recipient_export_pending(connection, owner)?;
    let mut changed_directory = false;
    for export_id in export_ids {
        if recipient_export_catalog_contains(connection, export_id)? {
            remove_recipient_export_pending(connection, export_id)?;
            continue;
        }
        let staging = recipient_export_staging_name(export_id)?;
        let final_name = recipient_export_final_name(export_id)?;
        changed_directory |= remove_pending_recipient_export_object(owner, staging.as_c_str())?;
        changed_directory |= remove_pending_recipient_export_object(owner, final_name.as_c_str())?;
        remove_recipient_export_pending(connection, export_id)?;
    }
    if changed_directory {
        recipient_fsync(&owner.directory_file).map_err(storage_error)?;
    }
    Ok(if incomplete {
        RecipientExportRecoveryProgressV1::Incomplete
    } else {
        RecipientExportRecoveryProgressV1::Complete
    })
}

fn validate_recipient_key_inventory(
    owner: &RecipientKeyOwnerV1,
    owner_id: &OwnerIdV1,
    registry: &KeyRegistryStateV1,
    inventories: &[StoredRecipientKeyInventoryV1],
) -> Result<Vec<RecipientKeyDescriptorV1>, CoreError> {
    let expected_identities = registry
        .key_records()
        .filter(|record| {
            record.identity.owner_id == *owner_id
                && record.identity.role == KeyRoleV1::ExportRecipientEncryption
                && record.private_material_digest.is_some()
        })
        .map(|record| record.identity)
        .collect::<BTreeSet<_>>();
    let pending_identities = registry
        .pending_destruction_requests()
        .map(|pending| pending.identity)
        .collect::<BTreeSet<_>>();
    let mut inventory_identities = BTreeSet::new();
    let mut descriptors = Vec::new();
    for inventory in inventories {
        let descriptor =
            RecipientKeyDescriptorV1::decode(&inventory.descriptor).map_err(storage_error)?;
        if !descriptor.is_for_grantee(owner.grantee_id) || inventory.material_digest.len() != 32 {
            return Err(CoreError::Storage(
                "recipient key inventory is invalid".to_owned(),
            ));
        }
        let mut inventory_digest = [0_u8; 32];
        inventory_digest.copy_from_slice(&inventory.material_digest);
        let inventory_digest = pos_core::Hash::from_bytes(inventory_digest);
        let identity = descriptor.identity();
        if !inventory_identities.insert(identity) {
            return Err(CoreError::Storage(
                "recipient key inventory repeats an identity".to_owned(),
            ));
        }
        if registry.key_record(identity).is_none_or(|record| {
            record.private_material_digest != Some(inventory_digest)
                || registry.tombstone(identity).is_some()
        }) {
            return Err(CoreError::Storage(
                "recipient key inventory is not an exact live registry identity".to_owned(),
            ));
        }
        // A pending destruction stays unavailable without blocking live
        // epochs: its material is neither opened nor returned.
        if pending_identities.contains(&identity) {
            continue;
        }
        // The writer-reserved directory claim has already validated this
        // descriptor-derived filename for every inventory row.
        let path = PathBuf::from(std::ffi::OsString::from_vec(inventory.private_path.clone()));
        let file_identity = RecipientPrivateFileIdentityV1::from_inventory(inventory)?;
        let material = read_bound_private_key(owner, &path, file_identity)?;
        if pos_crypto::key_roles::key_material_digest(&material).as_bytes()
            != inventory.material_digest.as_slice()
        {
            return Err(CoreError::Storage(
                "recipient private key digest differs from inventory".to_owned(),
            ));
        }
        if pos_crypto::recipient_key::recipient_public_key_from_private_v1(&material)
            != descriptor.public_key()
        {
            return Err(CoreError::Storage(
                "recipient private key does not match descriptor public key".to_owned(),
            ));
        }
        descriptors.push(descriptor);
    }
    if inventory_identities != expected_identities {
        return Err(CoreError::Storage(
            "recipient key inventory does not cover live registry identities".to_owned(),
        ));
    }
    Ok(descriptors)
}

fn recipient_private_path(directory: &Path, descriptor: RecipientKeyDescriptorV1) -> PathBuf {
    let mut name = format!("recipient-{}-", descriptor.identity().epoch);
    for byte in descriptor.fingerprint().as_bytes() {
        name.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        name.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    name.push_str(".key");
    directory.join(name)
}

fn is_expected_recipient_private_path(
    path: &Path,
    descriptor: RecipientKeyDescriptorV1,
) -> Result<bool, CoreError> {
    let expected = recipient_private_path(Path::new("."), descriptor);
    bound_name(path)
        .and_then(|name| bound_name(&expected).map(|expected_name| name == expected_name))
}

fn ensure_recipient_custody_tables(connection: &rusqlite::Connection) -> Result<(), CoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS recipient_key_inventory_v1 (
                owner_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                descriptor BLOB NOT NULL,
                material_digest BLOB NOT NULL,
                private_path BLOB NOT NULL,
                file_device BLOB NOT NULL CHECK (length(file_device) = 8),
                file_inode BLOB NOT NULL CHECK (length(file_inode) = 8),
                file_uid BLOB NOT NULL CHECK (length(file_uid) = 4),
                PRIMARY KEY(owner_id, epoch)
            );
            CREATE TABLE IF NOT EXISTS recipient_custody_directory_claims_v1 (
                directory_device BLOB NOT NULL CHECK (length(directory_device) = 8),
                directory_inode BLOB NOT NULL CHECK (length(directory_inode) = 8),
                grantee_id TEXT NOT NULL,
                PRIMARY KEY(directory_device, directory_inode)
            );
            CREATE TABLE IF NOT EXISTS recipient_key_destruction_receipts_v1 (
                owner_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                request_receipt BLOB NOT NULL CHECK (length(request_receipt) = 32),
                deletion_receipt BLOB NOT NULL CHECK (length(deletion_receipt) = 32),
                private_path BLOB NOT NULL,
                file_device BLOB NOT NULL CHECK (length(file_device) = 8),
                file_inode BLOB NOT NULL CHECK (length(file_inode) = 8),
                file_uid BLOB NOT NULL CHECK (length(file_uid) = 4),
                PRIMARY KEY(owner_id, epoch)
            );",
        )
        .map_err(storage_error)
}

fn claim_recipient_custody_directory(
    connection: &rusqlite::Connection,
    owner: &RecipientKeyOwnerV1,
) -> Result<(), CoreError> {
    let grantee_id = owner.grantee_id.to_string();
    let claimed_grantee = connection
        .query_row(
            "SELECT grantee_id FROM recipient_custody_directory_claims_v1
             WHERE directory_device = ?1 AND directory_inode = ?2",
            rusqlite::params![
                owner.directory_identity.device.as_slice(),
                owner.directory_identity.inode.as_slice(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(storage_error)?;
    if let Some(claimed_grantee) = claimed_grantee {
        if claimed_grantee == grantee_id {
            return validate_directory_inventory_grantees(connection, owner);
        }
        return Err(CoreError::Storage(
            "recipient key directory is already claimed by another grantee".to_owned(),
        ));
    }

    validate_directory_inventory_grantees(connection, owner)?;
    connection
        .execute(
            "INSERT INTO recipient_custody_directory_claims_v1
             (directory_device, directory_inode, grantee_id) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                owner.directory_identity.device.as_slice(),
                owner.directory_identity.inode.as_slice(),
                grantee_id,
            ],
        )
        .map(|_| ())
        .map_err(storage_error)
}

fn validate_directory_inventory_grantees(
    connection: &rusqlite::Connection,
    owner: &RecipientKeyOwnerV1,
) -> Result<(), CoreError> {
    use std::os::unix::ffi::OsStringExt;

    connection
        .prepare(
            "SELECT descriptor, material_digest, private_path, file_device, file_inode, file_uid
             FROM recipient_key_inventory_v1",
        )
        .map_err(storage_error)
        .and_then(|mut statement| {
            statement
                .query_map([], recipient_inventory_from_row)
                .map_err(storage_error)
                .and_then(|rows| rows.collect::<Result<Vec<_>, _>>().map_err(storage_error))
        })
        .and_then(|inventories| {
            for inventory in inventories {
                let descriptor = RecipientKeyDescriptorV1::decode(&inventory.descriptor)
                    .map_err(storage_error)?;
                let path =
                    PathBuf::from(std::ffi::OsString::from_vec(inventory.private_path.clone()));
                if !is_expected_recipient_private_path(&path, descriptor)? {
                    return Err(CoreError::Storage(
                        "recipient key inventory path does not match descriptor".to_owned(),
                    ));
                }
                let file_identity = RecipientPrivateFileIdentityV1::from_inventory(&inventory)?;
                let name = bound_name(&path)?;
                let is_path_alias_here = path.parent().is_some_and(|parent| {
                    std::fs::symlink_metadata(parent).is_ok_and(|metadata| {
                        metadata.is_dir()
                            && !metadata.file_type().is_symlink()
                            && RecipientPrivateDirectoryIdentityV1::from_metadata(&metadata)
                                == owner.directory_identity
                    })
                });
                let entry =
                    recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW);
                let is_bound_here = match entry {
                    Ok(metadata) => {
                        let matches_inventory = metadata.st_dev.to_be_bytes()
                            == file_identity.device
                            && metadata.st_ino.to_be_bytes() == file_identity.inode
                            && metadata.st_uid.to_be_bytes() == file_identity.uid;
                        if is_path_alias_here && !matches_inventory {
                            return Err(CoreError::Storage(
                                "recipient directory conflicts with registered inventory"
                                    .to_owned(),
                            ));
                        }
                        matches_inventory
                    }
                    Err(rustix::io::Errno::NOENT) => false,
                    Err(error) => return Err(CoreError::Storage(error.to_string())),
                };
                if (is_bound_here || is_path_alias_here)
                    && !descriptor.is_for_grantee(owner.grantee_id)
                {
                    return Err(CoreError::Storage(
                        "recipient directory inventory belongs to another grantee".to_owned(),
                    ));
                }
            }
            Ok(())
        })
}

fn record_recipient_destruction_receipt(
    connection: &rusqlite::Connection,
    request: KeyDestructionRequestV1,
    path: &Path,
    identity: RecipientPrivateFileIdentityV1,
    receipt: pos_core::Hash,
) -> Result<(), CoreError> {
    let request_receipt = pos_core::deletion_receipt(&request);
    i64::try_from(request.identity.epoch)
        .map_err(storage_error)
        .and_then(|epoch| {
            connection
                .execute(
            "INSERT INTO recipient_key_destruction_receipts_v1
             (owner_id, epoch, request_receipt, deletion_receipt, private_path, file_device, file_inode, file_uid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                request.identity.owner_id.as_str(),
                epoch,
                request_receipt.as_bytes().as_slice(),
                receipt.as_bytes().as_slice(),
                path.as_os_str().as_encoded_bytes(),
                identity.device.as_slice(),
                identity.inode.as_slice(),
                identity.uid.as_slice(),
            ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
}

fn quarantine_unregistered_staged_material(
    owner: &RecipientKeyOwnerV1,
    inventory: &[StoredRecipientKeyInventoryV1],
) -> Result<(), CoreError> {
    use std::os::unix::ffi::OsStrExt;

    let registered_names = inventory
        .iter()
        .filter_map(|entry| Path::new(std::ffi::OsStr::from_bytes(&entry.private_path)).file_name())
        .map(std::ffi::OsStr::as_encoded_bytes)
        .map(<[u8]>::to_vec)
        .collect::<BTreeSet<_>>();
    rustix::fs::Dir::read_from(&owner.directory_file)
        .map_err(storage_error)
        .and_then(|mut directory| {
            std::iter::from_fn(|| directory.read()).try_for_each(|entry| {
                entry.map_err(storage_error).and_then(|entry| {
                    let name = entry.file_name();
                    let bytes = name.to_bytes();
                    if !bytes.starts_with(b"recipient-")
                        || !bytes.ends_with(b".key")
                        || registered_names.contains(bytes)
                    {
                        Ok(())
                    } else {
                        quarantine_staged_entry(owner, name)
                    }
                })
            })
        })
}

/// Upper bound on quarantined entries one writer-serialized recovery removes,
/// so a directory flooded with orphans cannot hold the writer reservation for
/// an unbounded time. Remaining entries are purged by later recoveries.
const MAX_QUARANTINE_PURGE_PER_RECOVERY: usize = 256;

fn is_quarantined_recipient_name(name: &[u8]) -> bool {
    name.starts_with(b".recipient-") && name.ends_with(b".key.orphan")
}

/// Delete quarantined unregistered private material.
///
/// Quarantine only renames material that no durable inventory row names, so
/// a `.recipient-*.key.orphan` entry is never registered custody. Names are
/// collected before unlinking so directory iteration is not mutated in place.
/// Only regular files are purged: quarantine never produces any other entry
/// type, so a matching directory, symlink, or special file is left in place
/// rather than failing recovery or consuming the per-recovery purge budget.
fn purge_quarantined_material(owner: &RecipientKeyOwnerV1) -> Result<(), CoreError> {
    rustix::fs::Dir::read_from(&owner.directory_file)
        .map_err(storage_error)
        .and_then(|mut directory| {
            std::iter::from_fn(|| directory.read())
                .filter_map(|entry| {
                    entry
                        .and_then(|entry| quarantined_regular_file_name(owner, &entry))
                        .transpose()
                })
                .take(MAX_QUARANTINE_PURGE_PER_RECOVERY)
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)
        })
        .and_then(|names| {
            names.iter().try_for_each(|name| {
                recipient_unlinkat(&owner.directory_file, name.as_c_str(), AtFlags::empty())
                    .map_err(storage_error)
            })
        })
        .and_then(|()| recipient_fsync(&owner.directory_file).map_err(storage_error))
}

fn quarantined_regular_file_name(
    owner: &RecipientKeyOwnerV1,
    entry: &rustix::fs::DirEntry,
) -> Result<Option<std::ffi::CString>, rustix::io::Errno> {
    let name = entry.file_name();
    if !is_quarantined_recipient_name(name.to_bytes()) {
        return Ok(None);
    }
    recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW).map(|metadata| {
        ((metadata.st_mode & libc::S_IFMT) == libc::S_IFREG).then(|| name.to_owned())
    })
}

fn quarantine_unregistered_owned_staged_material(
    owner: &RecipientKeyOwnerV1,
) -> Result<(), CoreError> {
    use std::os::unix::ffi::OsStrExt;

    rustix::fs::Dir::read_from(&owner.directory_file)
        .map_err(storage_error)
        .and_then(|mut directory| {
            std::iter::from_fn(|| directory.read()).try_for_each(|entry| {
                entry.map_err(storage_error).and_then(|entry| {
                    let name = entry.file_name();
                    let path = Path::new(std::ffi::OsStr::from_bytes(name.to_bytes()));
                    staged_recipient_epoch(path.as_os_str()).map_or_else(
                        || Ok(()),
                        |epoch| {
                            read_unregistered_staged_private_key(owner, path).and_then(|material| {
                                let public_key =
                                    pos_crypto::recipient_key::recipient_public_key_from_private_v1(
                                        &material,
                                    );
                                RecipientKeyDescriptorV1::for_grantee(
                                    owner.grantee_id,
                                    epoch,
                                    public_key,
                                )
                                .map_err(storage_error)
                                .and_then(|descriptor| {
                                    bound_name(&recipient_private_path(
                                        &owner.directory,
                                        descriptor,
                                    ))
                                    .and_then(|expected| {
                                        if expected == path {
                                            quarantine_staged_entry(owner, name)
                                        } else {
                                            Ok(())
                                        }
                                    })
                                })
                            })
                        },
                    )
                })
            })
        })
}

fn staged_recipient_epoch(name: &std::ffi::OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let epoch = name
        .strip_prefix("recipient-")?
        .strip_suffix(".key")?
        .split_once('-')?
        .0;
    let epoch = epoch.parse().ok()?;
    (epoch != 0).then_some(epoch)
}

fn read_unregistered_staged_private_key(
    owner: &RecipientKeyOwnerV1,
    name: &Path,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    validate_owner_directory(owner).and_then(|()| {
        recipient_openat2(
            &owner.directory_file,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(storage_error)
        .and_then(|mut file| {
            file.metadata().map_err(storage_error).and_then(|metadata| {
                let identity = recipient_private_file_identity(&metadata);
                if identity.uid != owner.directory_uid.to_be_bytes() {
                    return Err(CoreError::Storage(
                        "recipient private file owner differs from private directory owner"
                            .to_owned(),
                    ));
                }
                validate_private_file(&metadata, identity).and_then(|()| {
                    let mut material = Zeroizing::new([0_u8; 32]);
                    recipient_read_exact(&mut file, &mut *material)
                        .map_err(storage_error)
                        .and_then(|()| verify_bound_entry(owner, name, identity).map(|()| material))
                })
            })
        })
    })
}

fn quarantine_staged_entry(
    owner: &RecipientKeyOwnerV1,
    name: &std::ffi::CStr,
) -> Result<(), CoreError> {
    let bytes = name.to_bytes();
    let mut quarantine = Vec::with_capacity(bytes.len() + 8);
    quarantine.extend_from_slice(b".");
    quarantine.extend_from_slice(bytes);
    quarantine.extend_from_slice(b".orphan");
    std::ffi::CString::new(quarantine)
        .map_err(storage_error)
        .and_then(|quarantine| {
            renameat_with(
                &owner.directory_file,
                name,
                &owner.directory_file,
                quarantine.as_c_str(),
                RenameFlags::NOREPLACE,
            )
            .map_err(storage_error)
        })
        .and_then(|()| recipient_fsync(&owner.directory_file).map_err(storage_error))
}

fn validate_owner_directory(owner: &RecipientKeyOwnerV1) -> Result<(), CoreError> {
    use std::os::unix::fs::MetadataExt;

    owner
        .directory_file
        .metadata()
        .map_err(storage_error)
        .and_then(|metadata| {
            if !metadata.is_dir()
                || metadata.mode() & 0o777 != 0o700
                || metadata.uid() != owner.directory_uid
                || RecipientPrivateDirectoryIdentityV1::from_metadata(&metadata)
                    != owner.directory_identity
            {
                return Err(CoreError::Storage(
                    "recipient key directory is no longer private and owner-bound".to_owned(),
                ));
            }
            Ok(())
        })
}

fn bound_name(path: &Path) -> Result<&Path, CoreError> {
    let Some(name) = path.file_name() else {
        return Err(CoreError::Storage(
            "recipient private key path has no file name".to_owned(),
        ));
    };
    Ok(Path::new(name))
}

fn validate_private_file(
    metadata: &std::fs::Metadata,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<(), CoreError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 32
        || RecipientPrivateFileIdentityV1::from_metadata(metadata) != expected
    {
        return Err(CoreError::Storage(
            "recipient private file is not the bound private single-link file".to_owned(),
        ));
    }
    Ok(())
}

fn verify_bound_entry(
    owner: &RecipientKeyOwnerV1,
    name: &Path,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<(), CoreError> {
    recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(storage_error)
        .and_then(|metadata| {
            if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG
                || metadata.st_nlink != 1
                || metadata.st_mode & 0o777 != 0o600
                || metadata.st_size != 32
                || metadata.st_dev.to_be_bytes() != expected.device
                || metadata.st_ino.to_be_bytes() != expected.inode
                || metadata.st_uid.to_be_bytes() != expected.uid
            {
                return Err(CoreError::Storage(
                    "recipient private file is not the bound private single-link file".to_owned(),
                ));
            }
            Ok(())
        })
}

fn read_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    validate_owner_directory(owner).and_then(|()| {
        bound_name(path).and_then(|name| {
            recipient_openat2(
                &owner.directory_file,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map(File::from)
            .map_err(storage_error)
            .and_then(|mut file| {
                file.metadata().map_err(storage_error).and_then(|metadata| {
                    validate_private_file(&metadata, expected).and_then(|()| {
                        let mut material = Zeroizing::new([0_u8; 32]);
                        recipient_read_exact(&mut file, &mut *material)
                            .map_err(storage_error)
                            .and_then(|()| {
                                verify_bound_entry(owner, name, expected).map(|()| material)
                            })
                    })
                })
            })
        })
    })
}

/// Durably remove the inventory-bound private file for a pending destruction.
///
/// A previous attempt may have unlinked the exact inventory-bound name and then
/// stopped before its receipt/registry commit. When that name is now absent
/// under the writer reservation, the directory is synced again so the earlier
/// unlink is durable, and the caller records the receipt from the stored
/// inventory path and file identity. No material digest is re-derived for an
/// absent file; the pending request already binds the registered digest.
///
/// The resulting receipt attests only that the inventory-bound name is absent
/// after an authorized destruction request, not that this call unlinked it.
fn delete_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
    material_digest: pos_core::Hash,
) -> Result<(), CoreError> {
    validate_owner_directory(owner).and_then(|()| {
        bound_name(path).and_then(|name| {
            match recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {
                    recipient_fsync(&owner.directory_file).map_err(storage_error)
                }
                _ => unlink_present_private_key(owner, name, expected, material_digest),
            }
        })
    })
}

fn unlink_present_private_key(
    owner: &RecipientKeyOwnerV1,
    name: &Path,
    expected: RecipientPrivateFileIdentityV1,
    material_digest: pos_core::Hash,
) -> Result<(), CoreError> {
    recipient_openat2(
        &owner.directory_file,
        name,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(storage_error)
    .and_then(|mut file| {
        file.metadata().map_err(storage_error).and_then(|metadata| {
            validate_private_file(&metadata, expected).and_then(|()| {
                let mut material = Zeroizing::new([0_u8; 32]);
                recipient_read_exact(&mut file, &mut *material)
                    .map_err(storage_error)
                    .map(|()| material)
                    .and_then(|material| {
                        if pos_crypto::key_roles::key_material_digest(&material) != material_digest
                        {
                            return Err(CoreError::Storage(
                                "recipient private key digest differs from pending destruction"
                                    .to_owned(),
                            ));
                        }
                        recipient_fsync(&file)
                            .map_err(storage_error)
                            .and_then(|()| {
                                verify_bound_entry(owner, name, expected).and_then(|()| {
                                    recipient_unlinkat(
                                        &owner.directory_file,
                                        name,
                                        AtFlags::empty(),
                                    )
                                    .map_err(storage_error)
                                    .and_then(|()| {
                                        recipient_fsync(&owner.directory_file)
                                            .map_err(storage_error)
                                    })
                                })
                            })
                    })
            })
        })
    })
}

fn write_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    private_key: &[u8; 32],
) -> Result<RecipientPrivateFileIdentityV1, CoreError> {
    validate_owner_directory(owner).and_then(|()| {
        bound_name(path).and_then(|name| {
            recipient_openat2(
                &owner.directory_file,
                name,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK
                    | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map(File::from)
            .map_err(storage_error)
            .and_then(|mut file| {
                file.metadata().map_err(storage_error).and_then(|metadata| {
                    let identity = recipient_private_file_identity(&metadata);
                    if identity.uid != owner.directory_uid.to_be_bytes() {
                        return Err(CoreError::Storage(
                            "recipient private file owner differs from private directory owner"
                                .to_owned(),
                        ));
                    }
                    recipient_write_all(&mut file, private_key)
                        .map_err(storage_error)
                        .and_then(|()| recipient_fsync(&file).map_err(storage_error))
                        .and_then(|()| file.metadata().map_err(storage_error))
                        .and_then(|metadata| validate_private_file(&metadata, identity))
                        .and_then(|()| {
                            recipient_fsync(&owner.directory_file).map_err(storage_error)
                        })
                        .and_then(|()| verify_bound_entry(owner, name, identity))
                        .map(|()| identity)
                })
            })
        })
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{mpsc, Arc},
        time::Duration,
    };

    use pos_core::{
        ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
        ArtifactTransitionRuleV1, CanonicalBytes, ConsentAuthority, ConsentCapabilityToken,
        ConsentGrantedV1, ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureReferenceV1,
        ErasureReplayClaimV1, Event, EventDraft, EventId, Hash, Kind, RegisteredArtifactV1,
        ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, SchemaVersion, Seq, Timeline,
        TimelineExport, TimelineId, TimelineMeta, TimelineMode, WallTime,
    };
    use pos_crypto::recipient_export::encrypt_timeline_export_v1;
    use rand::{rngs::StdRng, SeedableRng};
    use ulid::Ulid;

    use super::*;

    type RecipientTestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const TEST_RECIPIENT_EXPORT_DIGEST: ErasureReferenceV1 =
        ErasureReferenceV1::from_digest([241; 32]);

    struct RecipientPublicationFixture {
        _temporary: tempfile::TempDir,
        store: SqliteStore,
        owner: RecipientKeyOwnerV1,
        authority: ConsentAuthority,
        token: ConsentCapabilityToken,
        timeline: TimelineId,
        descriptor: RecipientKeyDescriptorV1,
        evaluation: ReplayClaimEvaluationV1,
    }

    fn owner_fixture() -> Result<(tempfile::TempDir, SqliteStore, RecipientKeyOwnerV1), CoreError> {
        let temporary =
            tempfile::tempdir().map_err(|error| CoreError::Storage(error.to_string()))?;
        let directory = temporary.path().join("recipient-private");
        std::fs::create_dir(&directory).map_err(|error| CoreError::Storage(error.to_string()))?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let store = SqliteStore::open(
            temporary
                .path()
                .join("recipient.sqlite")
                .to_str()
                .ok_or_else(|| CoreError::Storage("database path is not UTF-8".to_owned()))?,
        )?;
        let owner = RecipientKeyOwnerV1::open(directory, EntityId::new())?;
        Ok((temporary, store, owner))
    }

    fn recipient_publication_evaluation() -> RecipientTestResult<ReplayClaimEvaluationV1> {
        ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[ArtifactClaimInputV1 {
                registration: RegisteredArtifactV1::new(
                    ErasureArtifactClassV1::Export,
                    TEST_RECIPIENT_EXPORT_DIGEST,
                    ArtifactDataClassV1::StructuralAuditMetadata,
                    None,
                    ErasureReferenceV1::from_digest([242; 32]),
                    ArtifactOptionalityV1::Required,
                    ArtifactTransitionRuleV1::PreserveExact,
                ),
                current_claim: ErasureReplayClaimV1::Exact,
                state: ArtifactStateV1::Retained,
            }],
        )
        .map_err(|error| error.to_string().into())
    }

    fn recipient_publication_fixture() -> RecipientTestResult<RecipientPublicationFixture> {
        let (temporary, mut store, owner) = owner_fixture()?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let subject = EntityId::new();
        let timeline = store.create_timeline_with_meta(TimelineMeta::root_owned(
            "recipient-publication",
            subject,
        ))?;
        store.append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("recipient.publication.coverage.v1"),
                CanonicalBytes::from_static(b"recipient-publication"),
            )],
        )?;
        let authority = ConsentAuthority::new();
        store.bind_consent_authority(authority.append_permit())?;
        let token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: owner.grantee_id,
                purpose: "recipient-publication-coverage".to_owned(),
                modalities: pos_core::MODALITY_EXPORT,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: true,
                retention_days: 1,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let descriptor = store.enroll_recipient_key(&owner)?;
        Ok(RecipientPublicationFixture {
            _temporary: temporary,
            store,
            owner,
            authority,
            token,
            timeline: timeline.id(),
            descriptor,
            evaluation: recipient_publication_evaluation()?,
        })
    }

    const fn recipient_publication_request<'a>(
        timeline: TimelineId,
        recipient: RecipientKeyDescriptorV1,
        evaluation: &'a ReplayClaimEvaluationV1,
        token: &'a ConsentCapabilityToken,
    ) -> RecipientExportRequestV1<'a> {
        RecipientExportRequestV1 {
            timeline_id: timeline,
            recipient,
            artifact_digest: TEST_RECIPIENT_EXPORT_DIGEST,
            evaluation,
            token,
            now_secs: 1,
        }
    }

    const TEST_EXPORT_ID: [u8; 16] = [7; 16];

    fn encrypted_export(descriptor: RecipientKeyDescriptorV1) -> Result<Vec<u8>, CoreError> {
        let payload = b"recipient export".to_vec();
        let payload_hash = Hash::from_bytes(*blake3::hash(&payload).as_bytes());
        let export = TimelineExport {
            timeline: Timeline {
                meta: TimelineMeta {
                    id: TimelineId::from_ulid(Ulid::from(3_u128)),
                    mode: TimelineMode::Live,
                    name: None,
                    owner: Some(EntityId::from_ulid(Ulid::from(4_u128))),
                    fork_point: None,
                },
                head: Seq::from_u64(1),
            },
            events: vec![Event {
                id: EventId::from_ulid(Ulid::from(101_u128)),
                entity: EntityId::from_ulid(Ulid::from(200_u128)),
                event_type: Kind::new("test.event"),
                payload: CanonicalBytes::from_vec(payload),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                origin: None,
                payload_hash,
            }],
            parent_fork_hash: None,
        };
        let mut rng = StdRng::from_seed([1; 32]);
        encrypt_timeline_export_v1(&export, descriptor, TEST_EXPORT_ID, &mut rng)
            .map(|encrypted| encrypted.encode())
            .map_err(storage_error)
    }

    fn plaintext_staging_export(payload: CanonicalBytes) -> TimelineExport {
        let payload_hash = Hash::from_bytes(*blake3::hash(payload.as_slice()).as_bytes());
        TimelineExport {
            timeline: Timeline {
                meta: TimelineMeta {
                    id: TimelineId::from_ulid(Ulid::from(31_u128)),
                    mode: TimelineMode::Live,
                    name: Some("recipient plaintext staging".to_owned()),
                    owner: Some(EntityId::from_ulid(Ulid::from(32_u128))),
                    fork_point: None,
                },
                head: Seq::from_u64(1),
            },
            events: vec![Event {
                id: EventId::from_ulid(Ulid::from(33_u128)),
                entity: EntityId::from_ulid(Ulid::from(34_u128)),
                event_type: Kind::new("recipient.plaintext.staging"),
                payload,
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                origin: None,
                payload_hash,
            }],
            parent_fork_hash: None,
        }
    }

    fn pause_on_next_recipient_read(started: mpsc::Sender<()>, release: mpsc::Receiver<()>) {
        RECIPIENT_READ_PAUSE.with(|pause| {
            assert!(pause.replace(Some((started, release))).is_none());
        });
    }

    fn fail_fsync_at(call: usize) {
        RECIPIENT_FSYNC_CALLS.with(|calls| calls.set(0));
        RECIPIENT_FSYNC_FAILURE.with(|failure| failure.set(Some(call)));
    }

    fn clear_fsync_fault() {
        RECIPIENT_FSYNC_FAILURE.with(|failure| failure.set(None));
        RECIPIENT_FSYNC_CALLS.with(|calls| calls.set(0));
    }

    fn set_unlink_failure(enabled: bool) {
        RECIPIENT_UNLINK_FAILURE.with(|failure| failure.set(enabled));
    }

    fn set_open_failure(enabled: bool) {
        RECIPIENT_OPEN_FAILURE.with(|failure| failure.set(enabled));
    }

    fn set_stat_failure(enabled: bool) {
        RECIPIENT_STAT_FAILURE.with(|failure| failure.set(enabled));
    }

    fn set_random_failure(enabled: bool) {
        RECIPIENT_RANDOM_FAILURE.with(|failure| failure.set(enabled));
    }

    fn set_recipient_export_synchronous_read_failure(enabled: bool) {
        RECIPIENT_DURABILITY_SYNCHRONOUS_READ_FAILURE.with(|failure| failure.set(enabled));
    }

    fn override_next_recipient_random_bytes(bytes: Vec<u8>) {
        RECIPIENT_RANDOM_OVERRIDE.with(|override_bytes| {
            assert!(override_bytes.replace(Some(bytes)).is_none());
        });
    }

    fn set_read_failure(enabled: bool) {
        RECIPIENT_READ_FAILURE.with(|failure| failure.set(enabled));
    }

    fn set_write_failure(enabled: bool) {
        RECIPIENT_WRITE_FAILURE.with(|failure| failure.set(enabled));
    }

    fn set_file_owner_mismatch(enabled: bool) {
        RECIPIENT_FILE_OWNER_MISMATCH.with(|mismatch| mismatch.set(enabled));
    }

    fn set_begin_failure(enabled: bool) {
        super::super::FAIL_BEGIN_IMMEDIATE.with(|failure| failure.set(enabled));
    }

    fn replace_directory_after_open(directory: PathBuf, replacement: PathBuf) {
        RECIPIENT_OPEN_REPLACEMENT.with(|fault| fault.replace(Some((directory, replacement))));
    }

    #[test]
    fn recipient_export_plaintext_staging_requires_owned_payloads_and_scrubs_source(
    ) -> RecipientTestResult {
        let shared_payload = CanonicalBytes::from_vec(b"shared plaintext".to_vec());
        let retained_payload = shared_payload.clone();
        let mut shared_export = plaintext_staging_export(shared_payload);
        assert!(!shared_export.plaintext_staging_is_exclusively_owned());
        assert!(!shared_export.zeroize_plaintext_staging());
        assert_eq!(retained_payload.as_slice(), b"shared plaintext");
        assert!(RecipientExportPlaintextStagingV1::new(shared_export).is_err());

        let mut lost_ownership = RecipientExportPlaintextStagingV1::new(plaintext_staging_export(
            CanonicalBytes::from_vec(b"lost ownership".to_vec()),
        ))?;
        let retained_lost_ownership = lost_ownership.source.events[0].payload.clone();
        assert!(matches!(
            lost_ownership.zeroize(),
            Err(CoreError::Storage(message)) if message.contains("lost exclusive ownership")
        ));
        assert_eq!(retained_lost_ownership.as_slice(), b"lost ownership");

        let unique_export =
            plaintext_staging_export(CanonicalBytes::from_vec(b"owned plaintext".to_vec()));
        let mut staging = RecipientExportPlaintextStagingV1::new(unique_export)?;
        staging.zeroize()?;
        assert_eq!(staging.source().timeline.meta.name.as_deref(), Some(""));
        assert_eq!(staging.source().events[0].event_type.as_str(), "");
        assert!(staging.source().events[0]
            .payload
            .as_slice()
            .iter()
            .all(|byte| *byte == 0));
        staging.zeroize()?;

        let dropped_staging = RecipientExportPlaintextStagingV1::new(plaintext_staging_export(
            CanonicalBytes::from_vec(b"drop plaintext".to_vec()),
        ))?;
        drop(dropped_staging);
        Ok(())
    }

    #[test]
    fn recipient_export_durability_requires_wal_and_full_synchronous_mode() -> RecipientTestResult {
        let fixture = recipient_publication_fixture()?;
        fixture
            .store
            .conn
            .execute_batch("PRAGMA journal_mode=DELETE")?;
        assert!(matches!(
            ensure_recipient_export_durability(&fixture.store.conn),
            Err(CoreError::Storage(message)) if message.contains("requires SQLite WAL")
        ));

        let fixture = recipient_publication_fixture()?;
        fixture
            .store
            .conn
            .execute_batch("PRAGMA synchronous=NORMAL")?;
        let expected_synchronous = current_sqlite_synchronous_level(&fixture.store.conn)?;
        RECIPIENT_DURABILITY_SYNCHRONOUS_OVERRIDE.with(|override_value| {
            override_value.set(Some(1));
        });
        assert!(matches!(
            ensure_recipient_export_durability(&fixture.store.conn),
            Err(CoreError::Storage(message)) if message.contains("synchronous=FULL")
        ));
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );
        set_recipient_export_synchronous_read_failure(true);
        let synchronous_read_failure = ensure_recipient_export_durability(&fixture.store.conn);
        set_recipient_export_synchronous_read_failure(false);
        assert!(matches!(
            synchronous_read_failure,
            Err(CoreError::Storage(message))
                if message.contains("injected recipient export synchronous read failure")
        ));
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );
        let previous_synchronous = ensure_recipient_export_durability(&fixture.store.conn)?;
        assert!(current_sqlite_synchronous_level(&fixture.store.conn)? >= 2);
        restore_recipient_export_synchronous_level(&fixture.store.conn, previous_synchronous)?;
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );
        Ok(())
    }

    #[test]
    fn recipient_export_operations_restore_connection_synchronous_mode() -> RecipientTestResult {
        let mut fixture = recipient_publication_fixture()?;
        fixture
            .store
            .conn
            .execute_batch("PRAGMA synchronous=NORMAL")?;
        let expected_synchronous = current_sqlite_synchronous_level(&fixture.store.conn)?;
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );

        fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?;
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );

        set_random_failure(true);
        let failed_publication =
            fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request);
        set_random_failure(false);
        assert!(failed_publication.is_err());
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );

        set_begin_failure(true);
        let failed_recovery = fixture.store.recover_recipient_exports(&fixture.owner);
        set_begin_failure(false);
        assert!(failed_recovery.is_err());
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );

        fixture.store.recover_recipient_exports(&fixture.owner)?;
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            expected_synchronous
        );
        Ok(())
    }

    #[test]
    fn fresh_recipient_export_id_rejects_zero_bytes() {
        override_next_recipient_random_bytes(vec![0; 16]);
        assert!(matches!(
            fresh_recipient_export_id(),
            Err(RecipientExportPublicationErrorV1::Export(
                RecipientExportErrorV1::FieldOutOfBounds
            ))
        ));
    }

    #[test]
    fn recipient_custody_sync_failures_leave_enrollment_and_destruction_unfinalized(
    ) -> Result<(), CoreError> {
        for failure in [0, 1] {
            let (_temporary, mut store, owner) = owner_fixture()?;
            fail_fsync_at(failure);
            assert!(store.enroll_recipient_key(&owner).is_err());
            clear_fsync_fault();
            assert!(store.load_key_registry()?.is_none());
            assert!(store.recover_recipient_keys(&owner).is_err());
            let names = std::fs::read_dir(&owner.directory)
                .map_err(|error| CoreError::Storage(error.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| CoreError::Storage(error.to_string()))?
                .into_iter()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(!names.iter().any(|name| {
                std::path::Path::new(name).extension() == Some(std::ffi::OsStr::new("key"))
            }));
            assert!(names.iter().any(|name| name.ends_with(".orphan")));
        }

        for failure in [0, 1] {
            let (_temporary, mut store, owner) = owner_fixture()?;
            let descriptor = store.enroll_recipient_key(&owner)?;
            let authorization = pos_core::Hash::from_bytes([47; 32]);
            fail_fsync_at(failure);
            assert!(store
                .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
                .is_err());
            clear_fsync_fault();
            let registry = store
                .load_key_registry()?
                .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
            assert!(registry.tombstone(descriptor.identity()).is_none());
            // Failure 0 leaves the bound file in place; failure 1 has already
            // unlinked it. Either retry resumes and finalizes the destruction.
            store.destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)?;
            let registry = store
                .load_key_registry()?
                .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
            assert!(registry.tombstone(descriptor.identity()).is_some());
        }
        Ok(())
    }

    #[test]
    fn recipient_custody_open_failures_preserve_closed_lifecycle() -> Result<(), CoreError> {
        let temporary =
            tempfile::tempdir().map_err(|error| CoreError::Storage(error.to_string()))?;
        let directory = temporary.path().join("recipient-private");
        std::fs::create_dir(&directory).map_err(|error| CoreError::Storage(error.to_string()))?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        set_open_failure(true);
        assert!(RecipientKeyOwnerV1::open(&directory, EntityId::new()).is_err());
        set_open_failure(false);

        let (_temporary, mut store, owner) = owner_fixture()?;
        set_open_failure(true);
        assert!(store.enroll_recipient_key(&owner).is_err());
        set_open_failure(false);
        assert!(store.load_key_registry()?.is_none());

        let descriptor = store.enroll_recipient_key(&owner)?;
        set_open_failure(true);
        assert!(store.recover_recipient_keys(&owner).is_err());
        assert!(store
            .destroy_recipient_key(
                &owner,
                descriptor.identity().epoch,
                pos_core::Hash::from_bytes([50; 32]),
            )
            .is_err());
        set_open_failure(false);
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        assert!(registry.tombstone(descriptor.identity()).is_none());
        Ok(())
    }

    #[test]
    fn recipient_custody_unlink_failure_leaves_destruction_pending() -> Result<(), CoreError> {
        let (_temporary, mut store, owner) = owner_fixture()?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let authorization = pos_core::Hash::from_bytes([48; 32]);
        set_unlink_failure(true);
        assert!(store
            .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
            .is_err());
        set_unlink_failure(false);
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        assert!(registry.tombstone(descriptor.identity()).is_none());
        assert!(registry
            .pending_destruction_requests()
            .any(|request| request.identity == descriptor.identity()));
        Ok(())
    }
    #[test]
    fn recipient_custody_rejects_a_directory_replaced_during_owner_open() -> Result<(), CoreError> {
        let temporary =
            tempfile::tempdir().map_err(|error| CoreError::Storage(error.to_string()))?;
        let directory = temporary.path().join("recipient-private");
        let replacement = temporary.path().join("replacement-private");
        std::fs::create_dir(&directory).map_err(|error| CoreError::Storage(error.to_string()))?;
        std::fs::create_dir(&replacement).map_err(|error| CoreError::Storage(error.to_string()))?;
        for path in [&directory, &replacement] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| CoreError::Storage(error.to_string()))?;
        }
        replace_directory_after_open(directory.clone(), replacement);

        assert!(RecipientKeyOwnerV1::open(&directory, EntityId::new()).is_err());
        Ok(())
    }

    #[test]
    fn recipient_custody_rejects_epoch_overflow_without_registering_material(
    ) -> Result<(), CoreError> {
        let (_temporary, mut store, owner) = owner_fixture()?;
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let identity =
            KeyIdentityV1::from_parts(owner_id, KeyRoleV1::ExportRecipientEncryption, u64::MAX);
        let mut registry = KeyRegistryStateV1::new();
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                pos_core::Hash::from_bytes([1; 32]),
                None,
            ))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        store.save_key_registry(&registry)?;

        assert!(store.enroll_recipient_key(&owner).is_err());
        assert_eq!(store.load_key_registry()?, Some(registry));
        Ok(())
    }

    #[test]
    fn recipient_custody_rejects_injected_directory_inventory_stat_fault() -> Result<(), CoreError>
    {
        let (_temporary, store, owner) = owner_fixture()?;
        let mut store = store;
        store.enroll_recipient_key(&owner)?;
        set_stat_failure(true);
        assert!(store.recover_recipient_keys(&owner).is_err());
        set_stat_failure(false);
        Ok(())
    }

    #[test]
    fn recipient_custody_injected_entropy_and_material_io_failures_remain_closed(
    ) -> Result<(), CoreError> {
        {
            let (_temporary, mut store, owner) = owner_fixture()?;
            set_random_failure(true);
            assert!(store.enroll_recipient_key(&owner).is_err());
            set_random_failure(false);
            assert!(store.load_key_registry()?.is_none());
        }

        {
            let (_temporary, mut store, owner) = owner_fixture()?;
            set_write_failure(true);
            assert!(store.enroll_recipient_key(&owner).is_err());
            set_write_failure(false);
            assert!(store.load_key_registry()?.is_none());
        }

        {
            let (_temporary, mut store, owner) = owner_fixture()?;
            set_file_owner_mismatch(true);
            assert!(store.enroll_recipient_key(&owner).is_err());
            set_file_owner_mismatch(false);
            assert!(store.load_key_registry()?.is_none());
        }

        let (_temporary, mut store, owner) = owner_fixture()?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        set_read_failure(true);
        assert!(store.recover_recipient_keys(&owner).is_err());
        assert!(store
            .destroy_recipient_key(
                &owner,
                descriptor.identity().epoch,
                pos_core::Hash::from_bytes([51; 32]),
            )
            .is_err());
        set_read_failure(false);
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        assert!(registry.tombstone(descriptor.identity()).is_none());
        assert!(registry
            .pending_destruction_requests()
            .any(|request| request.identity == descriptor.identity()));
        Ok(())
    }

    #[test]
    fn recipient_custody_begin_failures_leave_each_lifecycle_step_closed() -> Result<(), CoreError>
    {
        {
            let (_temporary, mut store, owner) = owner_fixture()?;
            set_begin_failure(true);
            assert!(store.enroll_recipient_key(&owner).is_err());
            set_begin_failure(false);
            assert!(store.load_key_registry()?.is_none());
        }

        {
            let (_temporary, mut store, owner) = owner_fixture()?;
            let descriptor = store.enroll_recipient_key(&owner)?;
            set_begin_failure(true);
            assert!(store.recover_recipient_keys(&owner).is_err());
            set_begin_failure(false);
            assert_eq!(store.recover_recipient_keys(&owner)?, vec![descriptor]);
        }

        {
            let (_temporary, mut store, owner) = owner_fixture()?;
            let descriptor = store.enroll_recipient_key(&owner)?;
            set_begin_failure(true);
            assert!(store
                .destroy_recipient_key(
                    &owner,
                    descriptor.identity().epoch,
                    pos_core::Hash::from_bytes([53; 32]),
                )
                .is_err());
            set_begin_failure(false);
            let registry = store
                .load_key_registry()?
                .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
            assert!(registry.tombstone(descriptor.identity()).is_none());
            assert!(registry
                .key_record(descriptor.identity())
                .and_then(|record| record.private_material_digest)
                .is_some());
        }

        let (_temporary, mut store, owner) = owner_fixture()?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        let digest = registry
            .key_record(descriptor.identity())
            .and_then(|record| record.private_material_digest)
            .ok_or_else(|| CoreError::Storage("recipient material is absent".to_owned()))?;
        let request = KeyDestructionRequestV1::new(
            descriptor.identity(),
            digest,
            pos_core::Hash::from_bytes([54; 32]),
        );
        store.begin_key_registry_destruction(request)?;
        set_begin_failure(true);
        assert!(store
            .finish_recipient_key_destruction(&owner, request)
            .is_err());
        set_begin_failure(false);
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        assert!(registry.tombstone(descriptor.identity()).is_none());
        assert!(registry
            .pending_destruction_requests()
            .any(|pending| pending == request));
        Ok(())
    }

    #[test]
    fn recipient_custody_rejects_unavailable_or_unpending_finish_requests() -> Result<(), CoreError>
    {
        let (_temporary, store, owner) = owner_fixture()?;
        let identity = KeyIdentityV1::from_parts(
            recipient_owner_id_from_grantee(owner.grantee_id)
                .map_err(|error| CoreError::Storage(error.to_string()))?,
            KeyRoleV1::ExportRecipientEncryption,
            1,
        );
        let unavailable = KeyDestructionRequestV1::new(
            identity,
            pos_core::Hash::from_bytes([2; 32]),
            pos_core::Hash::from_bytes([3; 32]),
        );
        assert!(store
            .finish_recipient_key_destruction(&owner, unavailable)
            .is_err());

        let mut store = store;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        let digest = registry
            .key_record(descriptor.identity())
            .and_then(|record| record.private_material_digest)
            .ok_or_else(|| CoreError::Storage("recipient material is absent".to_owned()))?;
        let unpending = KeyDestructionRequestV1::new(
            descriptor.identity(),
            digest,
            pos_core::Hash::from_bytes([4; 32]),
        );
        assert!(store
            .finish_recipient_key_destruction(&owner, unpending)
            .is_err());
        Ok(())
    }

    #[test]
    fn recipient_custody_retries_an_already_receipted_destruction() -> Result<(), CoreError> {
        let (_temporary, mut store, owner) = owner_fixture()?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let authorization = pos_core::Hash::from_bytes([52; 32]);
        let registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        let digest = registry
            .key_record(descriptor.identity())
            .and_then(|record| record.private_material_digest)
            .ok_or_else(|| CoreError::Storage("recipient material is absent".to_owned()))?;
        let request = KeyDestructionRequestV1::new(descriptor.identity(), digest, authorization);
        store.destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)?;
        store.finish_recipient_key_destruction(&owner, request)
    }

    #[test]
    fn recipient_custody_rejects_inventory_identity_and_post_open_binding_mismatches(
    ) -> Result<(), CoreError> {
        let (temporary, mut store, owner) = owner_fixture()?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let foreign = RecipientKeyDescriptorV1::for_grantee(
            EntityId::new(),
            descriptor.identity().epoch,
            descriptor.public_key(),
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        connection
            .execute(
                "UPDATE recipient_key_inventory_v1 SET descriptor = ?1",
                [foreign.encode()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        assert!(
            SqliteStore::recipient_inventory_path(&store.conn, &owner, descriptor.identity())
                .is_err()
        );

        connection
            .execute(
                "UPDATE recipient_key_inventory_v1 SET descriptor = ?1",
                [descriptor.encode()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let path = recipient_private_path(&owner.directory, descriptor);
        let name = bound_name(&path)?;
        let metadata =
            std::fs::metadata(&path).map_err(|error| CoreError::Storage(error.to_string()))?;
        let mut wrong = RecipientPrivateFileIdentityV1::from_metadata(&metadata);
        wrong.inode[0] ^= 1;
        assert!(verify_bound_entry(&owner, name, wrong).is_err());
        Ok(())
    }

    #[test]
    fn recipient_decryption_absent_digest_sentinel_never_authorizes_material(
    ) -> Result<(), CoreError> {
        let (_temporary, mut store, owner) = owner_fixture()?;
        let descriptor = store.enroll_recipient_key(&owner)?;
        let mut registry = store
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is absent".to_owned()))?;
        let registered =
            registered_material_digest_or_absent_sentinel(&registry, descriptor.identity());
        assert_ne!(registered, ABSENT_MATERIAL_DIGEST);
        assert_ne!(key_material_digest(&[0; 32]), ABSENT_MATERIAL_DIGEST);
        let public_key = descriptor.public_key();
        let absent = RecipientKeyDescriptorV1::for_grantee(owner.grantee_id, 2, public_key)
            .map_err(|error| CoreError::Storage(error.to_string()))?
            .identity();
        assert_eq!(
            registered_material_digest_or_absent_sentinel(&registry, absent),
            ABSENT_MATERIAL_DIGEST
        );
        let called = std::cell::Cell::new(false);
        let mark = || called.set(true);
        assert_eq!(
            registry.with_decryption_authorization(absent, ABSENT_MATERIAL_DIGEST, mark),
            Err(KeyRegistryErrorV1::NotFound)
        );
        assert_eq!(
            registry.with_decryption_authorization(
                descriptor.identity(),
                ABSENT_MATERIAL_DIGEST,
                mark,
            ),
            Err(KeyRegistryErrorV1::EncryptionKeyMismatch)
        );
        assert!(!called.get());
        Ok(())
    }

    #[test]
    fn recipient_decryption_holds_writer_reservation_through_private_material_use(
    ) -> Result<(), CoreError> {
        let (temporary, mut writer, owner) = owner_fixture()?;
        let descriptor = writer.enroll_recipient_key(&owner)?;
        let encoded = encrypted_export(descriptor)?;
        let digest = writer
            .load_key_registry()?
            .and_then(|registry| {
                registry
                    .key_record(descriptor.identity())
                    .and_then(|record| record.private_material_digest)
            })
            .ok_or_else(|| CoreError::Storage("recipient material is absent".to_owned()))?;
        let database = temporary.path().join("recipient.sqlite");
        let database_path = database
            .to_str()
            .ok_or_else(|| CoreError::Storage("database path is not UTF-8".to_owned()))?
            .to_owned();
        let directory = owner.directory.clone();
        let grantee = owner.grantee_id;
        drop(writer);

        let decrypting_store = SqliteStore::open(&database_path)?;
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let decryption = scope.spawn(move || {
                pause_on_next_recipient_read(entered_tx, release_rx);
                decrypting_store.decrypt_recipient_export(
                    &owner,
                    &encoded,
                    TEST_EXPORT_ID,
                    descriptor,
                )
            });
            let entered = entered_rx.recv_timeout(Duration::from_secs(5));
            if entered.is_err() {
                assert!(
                    release_tx.send(()).is_ok(),
                    "decryption read must be released"
                );
            }
            assert!(
                entered.is_ok(),
                "decryption did not reach the private-key read"
            );

            let blocked =
                Connection::open(&database)
                    .map_err(storage_error)
                    .and_then(|connection| {
                        connection
                            .busy_timeout(Duration::ZERO)
                            .map_err(storage_error)
                            .and_then(|()| {
                                connection
                                    .execute_batch(begin_immediate_sql())
                                    .map_err(storage_error)
                            })
                    });
            assert!(
                blocked.is_err_and(|error| error.to_string().contains("database is locked")),
                "the direct decrypt must retain SQLite's writer reservation through key use"
            );
            assert!(
                release_tx.send(()).is_ok(),
                "decryption read must be released"
            );
            assert!(
                decryption.join().is_ok_and(|result| result.is_ok()),
                "the direct decrypt must succeed before a competing destruction"
            );
        });

        let request =
            KeyDestructionRequestV1::new(descriptor.identity(), digest, Hash::from_bytes([78; 32]));
        let mut mutator = SqliteStore::open(&database_path)?;
        mutator.begin_key_registry_destruction(request)?;
        let verifier = SqliteStore::open(&database_path)?;
        let owner = RecipientKeyOwnerV1::open(directory, grantee)?;
        assert_eq!(
            verifier
                .decrypt_recipient_export(
                    &owner,
                    &encrypted_export(descriptor)?,
                    TEST_EXPORT_ID,
                    descriptor
                )
                .err(),
            Some(RecipientExportDecryptionErrorV1::Registry(
                KeyRegistryErrorV1::DestructionPending
            ))
        );
        Ok(())
    }

    #[test]
    fn recipient_publication_rolls_back_stale_source_and_rejects_unknown_artifact(
    ) -> RecipientTestResult {
        let mut fixture = recipient_publication_fixture()?;
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );
        assert!(matches!(
            fixture.store.publish_recipient_export_under_fences(
                &fixture.owner,
                &request,
                Seq::ZERO,
            ),
            Err(RecipientExportPublicationErrorV1::SourceChanged)
        ));

        let unsupported_artifact = RecipientExportRequestV1 {
            timeline_id: request.timeline_id,
            recipient: request.recipient,
            artifact_digest: ErasureReferenceV1::from_digest([243; 32]),
            evaluation: request.evaluation,
            token: request.token,
            now_secs: request.now_secs,
        };
        assert!(matches!(
            fixture.store.publish_recipient_export(
                &fixture.authority,
                &fixture.owner,
                &unsupported_artifact,
            ),
            Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
        ));

        let publication =
            fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?;
        assert!(!fixture
            .store
            .read_recipient_export(&fixture.owner, publication.export_id)?
            .is_empty());
        Ok(())
    }

    #[test]
    fn recipient_publication_faults_leave_no_catalog_visible_object() -> RecipientTestResult {
        for failure in [0_usize, 1] {
            let mut fixture = recipient_publication_fixture()?;
            let export_id = [u8::try_from(failure + 1)?; 16];
            override_next_recipient_random_bytes(export_id.to_vec());
            let request = recipient_publication_request(
                fixture.timeline,
                fixture.descriptor,
                &fixture.evaluation,
                &fixture.token,
            );
            fail_fsync_at(failure);
            assert!(fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request)
                .is_err());
            clear_fsync_fault();
            fixture.store.recover_recipient_exports(&fixture.owner)?;
            assert!(matches!(
                fixture
                    .store
                    .read_recipient_export(&fixture.owner, export_id),
                Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
            ));
        }

        for fault in [
            set_open_failure as fn(bool),
            set_read_failure,
            set_stat_failure,
            set_write_failure,
        ] {
            let mut fixture = recipient_publication_fixture()?;
            let request = recipient_publication_request(
                fixture.timeline,
                fixture.descriptor,
                &fixture.evaluation,
                &fixture.token,
            );
            fault(true);
            assert!(fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request)
                .is_err());
            fault(false);
            fixture.store.recover_recipient_exports(&fixture.owner)?;
            let entries = std::fs::read_dir(&fixture.owner.directory)?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(!entries
                .iter()
                .any(|name| name.starts_with("recipient-export-")));
        }

        let mut fixture = recipient_publication_fixture()?;
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );
        set_random_failure(true);
        assert!(fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request)
            .is_err());
        set_random_failure(false);
        fixture.store.recover_recipient_exports(&fixture.owner)?;
        assert!(matches!(
            fixture
                .store
                .read_recipient_export(&fixture.owner, [255; 16]),
            Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn recipient_publication_rejects_identifier_collisions_without_replacing_ciphertext(
    ) -> RecipientTestResult {
        let mut fixture = recipient_publication_fixture()?;
        let export_id = [31; 16];
        override_next_recipient_random_bytes(export_id.to_vec());
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );
        let publication =
            fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?;
        assert_eq!(publication.export_id, export_id);
        let original = fixture
            .store
            .read_recipient_export(&fixture.owner, export_id)?;

        override_next_recipient_random_bytes(export_id.to_vec());
        let error = fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request)
            .err()
            .ok_or("recipient export ID collision unexpectedly succeeded")?;
        assert!(matches!(
            error,
            RecipientExportPublicationErrorV1::IdentifierCollision
        ));
        assert_eq!(
            fixture
                .store
                .read_recipient_export(&fixture.owner, export_id)?,
            original
        );
        Ok(())
    }

    #[test]
    fn recipient_publication_reader_rejects_each_invalid_catalog_binding() -> RecipientTestResult {
        for mutation in [
            "UPDATE recipient_export_catalog_v1 SET owner_id = 'wrong-owner'",
            "UPDATE recipient_export_catalog_v1 SET recipient_epoch = 2",
            "UPDATE recipient_export_catalog_v1 SET recipient_descriptor = X'00'",
            "UPDATE recipient_export_catalog_v1 SET timeline_id = 'not-a-timeline'",
            "PRAGMA ignore_check_constraints = ON;
             UPDATE recipient_export_catalog_v1 SET local_head = -1;
             PRAGMA ignore_check_constraints = OFF",
            "PRAGMA ignore_check_constraints = ON;
             UPDATE recipient_export_catalog_v1 SET logical_head = -1;
             PRAGMA ignore_check_constraints = OFF",
            "UPDATE recipient_export_catalog_v1 SET ciphertext_length = 1075838977",
            "PRAGMA ignore_check_constraints = ON;
             UPDATE recipient_export_catalog_v1 SET ciphertext_digest = X'00';
             PRAGMA ignore_check_constraints = OFF",
        ] {
            let mut fixture = recipient_publication_fixture()?;
            let request = recipient_publication_request(
                fixture.timeline,
                fixture.descriptor,
                &fixture.evaluation,
                &fixture.token,
            );
            let publication = fixture.store.publish_recipient_export(
                &fixture.authority,
                &fixture.owner,
                &request,
            )?;
            fixture.store.conn.execute_batch(mutation)?;
            assert!(matches!(
                fixture
                    .store
                    .read_recipient_export(&fixture.owner, publication.export_id),
                Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
            ));
        }
        Ok(())
    }

    #[test]
    fn recipient_publication_reader_rejects_a_tampered_ciphertext() -> RecipientTestResult {
        let mut fixture = recipient_publication_fixture()?;
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );
        let publication =
            fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?;
        let name = recipient_export_final_name(publication.export_id)?;
        let path = fixture.owner.directory.join(
            std::str::from_utf8(name.as_bytes())
                .map_err(|error| CoreError::Storage(error.to_string()))?,
        );
        let mut encoded =
            std::fs::read(&path).map_err(|error| CoreError::Storage(error.to_string()))?;
        let first = encoded
            .first_mut()
            .ok_or_else(|| CoreError::Storage("recipient ciphertext is empty".to_owned()))?;
        *first ^= 1;
        std::fs::write(path, encoded).map_err(|error| CoreError::Storage(error.to_string()))?;
        assert!(matches!(
            fixture
                .store
                .read_recipient_export(&fixture.owner, publication.export_id),
            Err(RecipientExportPublicationErrorV1::ArtifactUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn recipient_publication_pending_journal_recovers_only_recorded_objects() -> RecipientTestResult
    {
        let export_id = [32; 16];
        let final_name = recipient_export_final_name(export_id)?;
        let staging_name = recipient_export_staging_name(export_id)?;
        assert_ne!(final_name, staging_name);

        let mut fixture = recipient_publication_fixture()?;
        override_next_recipient_random_bytes(export_id.to_vec());
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );
        let publication =
            fixture
                .store
                .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?;
        let encoded = fixture
            .store
            .read_recipient_export(&fixture.owner, publication.export_id)?;
        let orphan_name = recipient_export_final_name([33; 16])?;
        let orphan = fixture.owner.directory.join(
            std::str::from_utf8(orphan_name.as_bytes())
                .map_err(|error| CoreError::Storage(error.to_string()))?,
        );
        std::fs::write(&orphan, b"orphan")?;
        std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o600))?;
        record_recipient_export_pending(&fixture.store.conn, &fixture.owner, [33; 16])?;

        let untracked_name = recipient_export_final_name([34; 16])?;
        let untracked = fixture.owner.directory.join(
            std::str::from_utf8(untracked_name.as_bytes())
                .map_err(|error| CoreError::Storage(error.to_string()))?,
        );
        std::fs::write(&untracked, b"untracked")?;
        std::fs::set_permissions(&untracked, std::fs::Permissions::from_mode(0o600))?;

        fixture.store.recover_recipient_exports(&fixture.owner)?;
        assert!(!orphan.exists());
        assert!(untracked.exists());
        assert_eq!(
            fixture
                .store
                .read_recipient_export(&fixture.owner, publication.export_id)?,
            encoded
        );

        for index in 0..=MAX_RECIPIENT_EXPORT_RECOVERY_PER_PASS {
            let mut pending = [0; 16];
            pending[..8].copy_from_slice(&u64::try_from(index + 1)?.to_be_bytes());
            pending[15] = 44;
            record_recipient_export_pending(&fixture.store.conn, &fixture.owner, pending)?;
        }
        assert!(matches!(
            fixture.store.recover_recipient_exports(&fixture.owner),
            Err(RecipientExportPublicationErrorV1::RecoveryIncomplete)
        ));
        fixture.store.recover_recipient_exports(&fixture.owner)?;
        assert!(untracked.exists());
        Ok(())
    }
}
