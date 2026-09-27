//! Durable local ownership of role-4 recipient key material.

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use pos_core::{
    recipient_owner_id_from_grantee, EntityId, EventStore, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, RecipientKeyDescriptorV1,
};
use rand::{rngs::SysRng, TryRng};
use zeroize::Zeroizing;

use super::{begin_immediate_sql, finish_immediate_transaction, CoreError, SqliteStore};

/// An owner-managed Unix directory for one consent grantee's role-4 keys.
#[derive(Clone, Debug)]
pub struct RecipientKeyOwnerV1 {
    directory: PathBuf,
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
            Ok(Self {
                directory,
                grantee_id,
                directory_uid: metadata.uid(),
            })
        }
    }
}

impl SqliteStore {
    /// Stage and durably enroll a fresh role-4 recipient key.
    ///
    /// The private file and RKP1 descriptor are synced before the SQLite
    /// registry/inventory transaction makes the identity active. A failed
    /// transaction cannot activate the staged material.
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
            self.conn.execute_batch("CREATE TABLE IF NOT EXISTS recipient_key_inventory_v1 (owner_id TEXT NOT NULL, epoch INTEGER NOT NULL, descriptor BLOB NOT NULL, material_digest BLOB NOT NULL, private_path BLOB NOT NULL, file_device BLOB NOT NULL CHECK (length(file_device) = 8), file_inode BLOB NOT NULL CHECK (length(file_inode) = 8), file_uid BLOB NOT NULL CHECK (length(file_uid) = 4), PRIMARY KEY(owner_id, epoch));")
                .map_err(|error| CoreError::Storage(error.to_string()))?;
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
    pub fn recover_recipient_keys(
        &self,
        owner: &RecipientKeyOwnerV1,
    ) -> Result<Vec<RecipientKeyDescriptorV1>, CoreError> {
        use std::os::unix::ffi::OsStringExt;

        validate_owner_directory(owner)?;
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
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
        let mut descriptors = Vec::new();
        for row in rows {
            let inventory = row.map_err(|error| CoreError::Storage(error.to_string()))?;
            let descriptor = RecipientKeyDescriptorV1::decode(&inventory.descriptor)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if !descriptor.is_for_grantee(owner.grantee_id) || inventory.material_digest.len() != 32
            {
                return Err(CoreError::Storage(
                    "recipient key inventory is invalid".to_owned(),
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
        let (path, bound_file, inventory_digest) =
            self.recipient_inventory_path(owner, identity)?;
        let registry = self
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("recipient registry is unavailable".to_owned()))?;
        let record = registry
            .key_record(identity)
            .ok_or_else(|| CoreError::Storage("recipient identity is unavailable".to_owned()))?;
        let digest = record.private_material_digest.ok_or_else(|| {
            CoreError::Storage("recipient identity is already destroyed".to_owned())
        })?;
        let request = KeyDestructionRequestV1::new(identity, digest, authorization_digest);
        let mut pending = registry;
        pending
            .begin_key_destruction(request)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.save_key_registry(&pending)?;
        if inventory_digest != digest {
            return Err(CoreError::Storage(
                "recipient inventory material differs from pending destruction".to_owned(),
            ));
        }
        delete_bound_private_key(owner, &path, bound_file, digest)?;
        pending
            .complete_key_destruction(request, pos_core::deletion_receipt(&request))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.save_key_registry(&pending)
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
        let path = PathBuf::from(std::ffi::OsString::from_vec(inventory.private_path));
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
    use std::fmt::Write as _;

    let mut name = format!("recipient-{}-", descriptor.identity().epoch);
    for byte in descriptor.fingerprint().as_bytes() {
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name.push_str(".key");
    directory.join(name)
}

fn validate_owner_directory(owner: &RecipientKeyOwnerV1) -> Result<(), CoreError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(&owner.directory)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != owner.directory_uid
    {
        return Err(CoreError::Storage(
            "recipient key directory is no longer private and owner-bound".to_owned(),
        ));
    }
    Ok(())
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

fn verify_bound_path(
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<(), CoreError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| CoreError::Storage(error.to_string()))?;
    validate_private_file(&metadata, expected)
}

fn read_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
) -> Result<[u8; 32], CoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    validate_owner_directory(owner)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    validate_private_file(&metadata, expected)?;
    let mut material = Zeroizing::new(Vec::with_capacity(32));
    file.read_to_end(&mut material)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    verify_bound_path(path, expected)?;
    material
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Storage("recipient private key width is invalid".to_owned()))
}

fn delete_bound_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    expected: RecipientPrivateFileIdentityV1,
    material_digest: pos_core::Hash,
) -> Result<(), CoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    validate_owner_directory(owner)?;
    let parent = std::fs::File::open(&owner.directory)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    validate_private_file(&metadata, expected)?;
    let mut material = Zeroizing::new(Vec::with_capacity(32));
    file.read_to_end(&mut material)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    if pos_crypto::key_roles::key_material_digest(&material) != material_digest {
        return Err(CoreError::Storage(
            "recipient private key digest differs from pending destruction".to_owned(),
        ));
    }
    file.sync_all()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    verify_bound_path(path, expected)?;
    std::fs::remove_file(path).map_err(|error| CoreError::Storage(error.to_string()))?;
    file.sync_all()
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    parent
        .sync_all()
        .map_err(|error| CoreError::Storage(error.to_string()))
}

fn write_private_key(
    owner: &RecipientKeyOwnerV1,
    path: &Path,
    private_key: &[u8; 32],
) -> Result<RecipientPrivateFileIdentityV1, CoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
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
    validate_private_file(&metadata, identity)?;
    file.write_all(private_key)
        .and_then(|()| file.sync_all())
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    drop(file);
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| CoreError::Storage("recipient key directory missing".to_owned()))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| CoreError::Storage(error.to_string()))?;
    verify_bound_path(path, identity)?;
    Ok(identity)
}
