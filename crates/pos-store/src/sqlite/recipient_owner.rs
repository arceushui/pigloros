//! Durable local ownership of role-4 recipient key material.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use pos_core::{
    recipient_owner_id_from_grantee, EntityId, EventStore, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, RecipientKeyDescriptorV1,
};
use rand::{rngs::SysRng, TryRng};
use rustix::fs::{
    fsync, openat2, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
    ResolveFlags,
};
use zeroize::Zeroizing;

use super::{begin_immediate_sql, finish_immediate_transaction, CoreError, SqliteStore};

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
        Ok(Self {
            device: inventory.file_device.as_slice().try_into().map_err(|_| {
                CoreError::Storage("recipient key inventory device is invalid".to_owned())
            })?,
            inode: inventory.file_inode.as_slice().try_into().map_err(|_| {
                CoreError::Storage("recipient key inventory inode is invalid".to_owned())
            })?,
            uid: inventory.file_uid.as_slice().try_into().map_err(|_| {
                CoreError::Storage("recipient key inventory owner is invalid".to_owned())
            })?,
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
        let metadata = std::fs::symlink_metadata(&directory)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
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
            let directory_file = openat2(
                rustix::fs::CWD,
                &directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map(File::from)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
            let retained_metadata = directory_file
                .metadata()
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if retained_metadata.uid() != metadata.uid()
                || retained_metadata.ino() != metadata.ino()
                || retained_metadata.dev() != metadata.dev()
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
    /// Returns a storage error if the custody directory is unsafe, entropy or
    /// key derivation fails, material cannot be durably written, or the
    /// registry/inventory transaction cannot commit.
    pub fn enroll_recipient_key(
        &mut self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<RecipientKeyDescriptorV1, CoreError> {
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result = (|| {
            validate_owner_directory(owner)?;
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
            SysRng.try_fill_bytes(&mut *ikm).map_err(|error| {
                CoreError::Storage(format!("recipient key RNG failed: {error}"))
            })?;
            let (private_key, public_key) =
                pos_crypto::recipient_key::derive_recipient_keypair_v1(&ikm)
                    .map_err(|error| CoreError::Storage(error.to_string()))?;
            let private_key = Zeroizing::new(private_key);
            let descriptor =
                RecipientKeyDescriptorV1::for_grantee(owner.grantee_id, epoch, public_key)
                    .map_err(|error| CoreError::Storage(error.to_string()))?;
            let private_path = recipient_private_path(&owner.directory, descriptor);
            let file_identity = write_private_key(owner, &private_path, &private_key)?;
            let material_digest = pos_crypto::key_roles::key_material_digest(&private_key);
            let mut next = registry;
            next.register_key(KeyRegistrationV1::new(identity, material_digest, None))
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            ensure_recipient_custody_tables(&self.conn)?;
            self.conn.execute("INSERT INTO recipient_key_inventory_v1 (owner_id, epoch, descriptor, material_digest, private_path, file_device, file_inode, file_uid) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", rusqlite::params![identity.owner_id.as_str(), i64::try_from(epoch).map_err(|error| CoreError::Storage(error.to_string()))?, descriptor.encode(), material_digest.as_bytes().as_slice(), private_path.as_os_str().as_encoded_bytes(), file_identity.device.as_slice(), file_identity.inode.as_slice(), file_identity.uid.as_slice()])
                .map_err(|error| CoreError::Storage(error.to_string()))?;
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
        use std::os::unix::ffi::OsStringExt;

        validate_owner_directory(owner)?;
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let registry = self
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is unavailable".to_owned()))?;
        let mut statement = self.conn.prepare("SELECT descriptor, material_digest, private_path, file_device, file_inode, file_uid FROM recipient_key_inventory_v1 WHERE owner_id = ?1 ORDER BY epoch")
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let rows = statement
            .query_map(rusqlite::params![owner_id.as_str()], |row| {
                Ok(StoredRecipientKeyInventoryV1 {
                    descriptor: row.get(0)?,
                    material_digest: row.get(1)?,
                    private_path: row.get(2)?,
                    file_device: row.get(3)?,
                    file_inode: row.get(4)?,
                    file_uid: row.get(5)?,
                })
            })
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let inventories = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        quarantine_unregistered_staged_material(owner, &inventories)?;
        let mut descriptors = Vec::new();
        for inventory in inventories {
            let descriptor = RecipientKeyDescriptorV1::decode(&inventory.descriptor)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if !descriptor.is_for_grantee(owner.grantee_id) || inventory.material_digest.len() != 32
            {
                return Err(CoreError::Storage(
                    "recipient key inventory is invalid".to_owned(),
                ));
            }
            let mut inventory_digest = [0_u8; 32];
            inventory_digest.copy_from_slice(&inventory.material_digest);
            let inventory_digest = pos_core::Hash::from_bytes(inventory_digest);
            let identity = descriptor.identity();
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
            let path = PathBuf::from(std::ffi::OsString::from_vec(inventory.private_path.clone()));
            if path != recipient_private_path(&owner.directory, descriptor) {
                return Err(CoreError::Storage(
                    "recipient key inventory path does not match descriptor".to_owned(),
                ));
            }
            let file_identity = RecipientPrivateFileIdentityV1::from_inventory(&inventory)?;
            let material = read_bound_private_key(owner, &path, file_identity)?;
            if pos_crypto::key_roles::key_material_digest(&material).as_bytes()
                != inventory.material_digest.as_slice()
            {
                return Err(CoreError::Storage(
                    "recipient private key digest differs from inventory".to_owned(),
                ));
            }
            if pos_crypto::recipient_key::recipient_public_key_from_private_v1(&material)
                .map_err(|error| CoreError::Storage(error.to_string()))?
                != descriptor.public_key()
            {
                return Err(CoreError::Storage(
                    "recipient private key does not match descriptor public key".to_owned(),
                ));
            }
            descriptors.push(descriptor);
        }
        Ok(descriptors)
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
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let identity =
            KeyIdentityV1::from_parts(owner_id, KeyRoleV1::ExportRecipientEncryption, epoch);
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let begun = (|| {
            ensure_recipient_custody_tables(&self.conn)?;
            let mut registry = self.load_key_registry()?.ok_or_else(|| {
                CoreError::Storage("recipient registry is unavailable".to_owned())
            })?;
            let record = registry.key_record(identity).ok_or_else(|| {
                CoreError::Storage("recipient identity is unavailable".to_owned())
            })?;
            let digest = record.private_material_digest.ok_or_else(|| {
                CoreError::Storage("recipient identity is already destroyed".to_owned())
            })?;
            let request = KeyDestructionRequestV1::new(identity, digest, authorization_digest);
            let outcome = registry
                .begin_key_destruction(request)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if matches!(outcome, pos_core::KeyDestructionBeginOutcomeV1::Started) {
                self.save_key_registry_in_transaction(&registry)?;
            }
            Ok((request, outcome))
        })();
        let (request, outcome) = finish_immediate_transaction(&self.conn, begun)?;
        if matches!(
            outcome,
            pos_core::KeyDestructionBeginOutcomeV1::AlreadyDestroyed(_)
        ) {
            return Ok(());
        }
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
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result = (|| {
            let mut registry = self.load_key_registry()?.ok_or_else(|| {
                CoreError::Storage("recipient registry is unavailable".to_owned())
            })?;
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
            record_recipient_destruction_receipt(&self.conn, request, &path, bound_file, receipt)?;
            registry
                .complete_key_destruction(request, receipt)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            self.save_key_registry_in_transaction(&registry)
        })();
        finish_immediate_transaction(&self.conn, result)
    }

    fn recipient_inventory_path(
        &self,
        owner: &RecipientKeyOwnerV1,
        identity: KeyIdentityV1,
    ) -> Result<(PathBuf, RecipientPrivateFileIdentityV1, pos_core::Hash), CoreError> {
        use std::os::unix::ffi::OsStringExt;

        let inventory = self
            .conn
            .query_row(
                "SELECT descriptor, material_digest, private_path, file_device, file_inode, file_uid FROM recipient_key_inventory_v1 WHERE owner_id = ?1 AND epoch = ?2",
                rusqlite::params![
                    identity.owner_id.as_str(),
                    i64::try_from(identity.epoch)
                        .map_err(|error| CoreError::Storage(error.to_string()))?
                ],
                |row| {
                    Ok(StoredRecipientKeyInventoryV1 {
                        descriptor: row.get(0)?,
                        material_digest: row.get(1)?,
                        private_path: row.get(2)?,
                        file_device: row.get(3)?,
                        file_inode: row.get(4)?,
                        file_uid: row.get(5)?,
                    })
                },
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let descriptor = RecipientKeyDescriptorV1::decode(&inventory.descriptor)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        if descriptor.identity() != identity || !descriptor.is_for_grantee(owner.grantee_id) {
            return Err(CoreError::Storage(
                "recipient key inventory identity is invalid".to_owned(),
            ));
        }
        let path = PathBuf::from(std::ffi::OsString::from_vec(inventory.private_path.clone()));
        if path != recipient_private_path(&owner.directory, descriptor) {
            return Err(CoreError::Storage(
                "recipient key inventory path does not match descriptor".to_owned(),
            ));
        }
        let material_digest = inventory
            .material_digest
            .as_slice()
            .try_into()
            .map_err(|_| {
                CoreError::Storage("recipient key inventory material digest is invalid".to_owned())
            })?;
        Ok((
            path,
            RecipientPrivateFileIdentityV1::from_inventory(&inventory)?,
            pos_core::Hash::from_bytes(material_digest),
        ))
    }
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
        .map_err(|error| CoreError::Storage(error.to_string()))
}

fn record_recipient_destruction_receipt(
    connection: &rusqlite::Connection,
    request: KeyDestructionRequestV1,
    path: &Path,
    identity: RecipientPrivateFileIdentityV1,
    receipt: pos_core::Hash,
) -> Result<(), CoreError> {
    let request_receipt = pos_core::deletion_receipt(&request);
    connection
        .execute(
            "INSERT INTO recipient_key_destruction_receipts_v1
             (owner_id, epoch, request_receipt, deletion_receipt, private_path, file_device, file_inode, file_uid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                request.identity.owner_id.as_str(),
                i64::try_from(request.identity.epoch)
                    .map_err(|error| CoreError::Storage(error.to_string()))?,
                request_receipt.as_bytes().as_slice(),
                receipt.as_bytes().as_slice(),
                path.as_os_str().as_encoded_bytes(),
                identity.device.as_slice(),
                identity.inode.as_slice(),
                identity.uid.as_slice(),
            ],
        )
        .map(|_| ())
        .map_err(|error| CoreError::Storage(error.to_string()))
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
    let mut directory = rustix::fs::Dir::read_from(&owner.directory_file)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    while let Some(entry) = directory.read() {
        let entry = entry.map_err(|error| CoreError::Storage(error.to_string()))?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if !bytes.starts_with(b"recipient-")
            || !bytes.ends_with(b".key")
            || registered_names.contains(bytes)
        {
            continue;
        }
        let mut quarantine = Vec::with_capacity(bytes.len() + 8);
        quarantine.extend_from_slice(b".");
        quarantine.extend_from_slice(bytes);
        quarantine.extend_from_slice(b".orphan");
        let quarantine = std::ffi::CString::new(quarantine)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        renameat_with(
            &owner.directory_file,
            name,
            &owner.directory_file,
            quarantine.as_c_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        fsync(&owner.directory_file).map_err(|error| CoreError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn validate_owner_directory(owner: &RecipientKeyOwnerV1) -> Result<(), CoreError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = owner
        .directory_file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    if !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != owner.directory_uid
    {
        return Err(CoreError::Storage(
            "recipient key directory is no longer private and owner-bound".to_owned(),
        ));
    }
    Ok(())
}

fn bound_name(path: &Path) -> Result<&Path, CoreError> {
    let Some(name) = path.file_name() else {
        return Err(CoreError::Storage(
            "recipient private key path has no file name".to_owned(),
        ));
    };
    if Path::new(name).components().count() != 1 {
        return Err(CoreError::Storage(
            "recipient private key path is not a directory entry".to_owned(),
        ));
    }
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

fn validate_new_private_file(
    metadata: &std::fs::Metadata,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<(), CoreError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || RecipientPrivateFileIdentityV1::from_metadata(metadata) != expected
    {
        return Err(CoreError::Storage(
            "recipient new private file is not the bound private single-link file".to_owned(),
        ));
    }
    Ok(())
}

fn verify_bound_entry(
    owner: &RecipientKeyOwnerV1,
    name: &Path,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<(), CoreError> {
    let metadata = statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
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
}

fn read_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    validate_owner_directory(owner)?;
    let name = bound_name(path)?;
    let mut file = openat2(
        &owner.directory_file,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|error| CoreError::Storage(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    validate_private_file(&metadata, expected)?;
    let mut material = Zeroizing::new(Vec::with_capacity(32));
    file.read_to_end(&mut material)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    verify_bound_entry(owner, name, expected)?;
    material
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Storage("recipient private key width is invalid".to_owned()))
}

fn delete_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
    material_digest: pos_core::Hash,
) -> Result<(), CoreError> {
    validate_owner_directory(owner)?;
    let name = bound_name(path)?;
    let mut file = openat2(
        &owner.directory_file,
        name,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|error| CoreError::Storage(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    validate_private_file(&metadata, expected)?;
    let mut material = Zeroizing::new(Vec::with_capacity(32));
    file.read_to_end(&mut material)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    let material =
        Zeroizing::new(material.as_slice().try_into().map_err(|_| {
            CoreError::Storage("recipient private key width is invalid".to_owned())
        })?);
    if pos_crypto::key_roles::key_material_digest(&material) != material_digest {
        return Err(CoreError::Storage(
            "recipient private key digest differs from pending destruction".to_owned(),
        ));
    }
    fsync(&file).map_err(|error| CoreError::Storage(error.to_string()))?;
    verify_bound_entry(owner, name, expected)?;
    unlinkat(&owner.directory_file, name, AtFlags::empty())
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    fsync(&owner.directory_file).map_err(|error| CoreError::Storage(error.to_string()))
}

fn write_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    private_key: &[u8; 32],
) -> Result<RecipientPrivateFileIdentityV1, CoreError> {
    validate_owner_directory(owner)?;
    let name = bound_name(path)?;
    let mut file = openat2(
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
    .map_err(|error| CoreError::Storage(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    let identity = RecipientPrivateFileIdentityV1::from_metadata(&metadata);
    if identity.uid != owner.directory_uid.to_be_bytes() {
        return Err(CoreError::Storage(
            "recipient private file owner differs from private directory owner".to_owned(),
        ));
    }
    validate_new_private_file(&metadata, identity)?;
    file.write_all(private_key)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    fsync(&file).map_err(|error| CoreError::Storage(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    validate_private_file(&metadata, identity)?;
    fsync(&owner.directory_file).map_err(|error| CoreError::Storage(error.to_string()))?;
    verify_bound_entry(owner, name, identity)?;
    Ok(identity)
}
