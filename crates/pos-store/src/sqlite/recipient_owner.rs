//! Durable local ownership of role-4 recipient key material.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

use pos_core::{
    recipient_owner_id_from_grantee, EntityId, EventStore, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, RecipientKeyDescriptorV1,
};
use rand::{rngs::SysRng, TryRng};
use rusqlite::OptionalExtension;
use rustix::fs::{
    fsync, openat2, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
    ResolveFlags,
};
use zeroize::Zeroizing;

use super::{begin_immediate_sql, finish_immediate_transaction, CoreError, SqliteStore};

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
    static RECIPIENT_READ_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
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
        file.read_exact(bytes)
    }
}

#[cfg(not(test))]
fn recipient_read_exact(file: &mut File, bytes: &mut [u8]) -> std::io::Result<()> {
    file.read_exact(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn recipient_write_all(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    if RECIPIENT_WRITE_FAILURE.with(std::cell::Cell::get) {
        Err(std::io::Error::other("injected recipient write failure"))
    } else {
        file.write_all(bytes)
    }
}

#[cfg(not(test))]
fn recipient_write_all(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
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

/// An owner-managed Unix directory for one consent grantee's role-4 keys.
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
        let directory = directory.into();
        let metadata = std::fs::symlink_metadata(&directory).map_err(storage_error)?;
        if !metadata.is_dir() {
            return Err(CoreError::Storage(
                "recipient key directory is not a directory".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
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
    /// method never derives a replacement from public RKP1 data.
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
                                        .map(|()| descriptors)
                                })
                            })
                        },
                    )
                })
            });
        finish_immediate_transaction(&self.conn, result)
    }

    /// Mark one recipient epoch pending, durably remove its owned key file,
    /// then commit the irreversible registry tombstone.
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
    /// directory-relative unlink and directory sync. If a process stops after
    /// unlinking but before that commit, the request remains pending and this
    /// method refuses to manufacture a receipt from the missing pathname.
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
                let (path, bound_file, inventory_digest) =
                    self.recipient_inventory_path(owner, request.identity)?;
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
        &self,
        owner: &RecipientKeyOwnerV1,
        identity: KeyIdentityV1,
    ) -> Result<(PathBuf, RecipientPrivateFileIdentityV1, pos_core::Hash), CoreError> {
        use std::os::unix::ffi::OsStringExt;

        i64::try_from(identity.epoch)
            .map_err(storage_error)
            .and_then(|epoch| {
                self.conn.query_row(
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
                || registry
                    .pending_destruction_requests()
                    .any(|pending| pending.identity == identity)
        }) {
            return Err(CoreError::Storage(
                "recipient key inventory is not an exact live registry identity".to_owned(),
            ));
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

fn delete_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
    material_digest: pos_core::Hash,
) -> Result<(), CoreError> {
    validate_owner_directory(owner).and_then(|()| {
        bound_name(path).and_then(|name| {
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
                file.metadata()
                    .map_err(storage_error)
                    .and_then(|metadata| {
                        validate_private_file(&metadata, expected).and_then(|()| {
                            let mut material = Zeroizing::new([0_u8; 32]);
                            recipient_read_exact(&mut file, &mut *material)
                                .map_err(storage_error)
                                .map(|()| material)
                                .and_then(|material| {
                                    if pos_crypto::key_roles::key_material_digest(&material)
                                        != material_digest
                                    {
                                        return Err(CoreError::Storage(
                                            "recipient private key digest differs from pending destruction"
                                                .to_owned(),
                                        ));
                                    }
                                    recipient_fsync(&file)
                                        .map_err(storage_error)
                                        .and_then(|()| {
                                            verify_bound_entry(owner, name, expected).and_then(
                                                |()| {
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
                                                },
                                            )
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
    use std::os::unix::fs::PermissionsExt;

    use super::*;

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
            if failure == 1 {
                assert!(store
                    .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
                    .is_err());
            }
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
        assert!(store
            .recipient_inventory_path(&owner, descriptor.identity())
            .is_err());

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
}
