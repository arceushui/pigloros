//! Durable local ownership of role-4 recipient key material.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use pos_core::{
    recipient_owner_id_from_grantee, EntityId, EventStore, KeyDestructionPortV1,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryPortV1,
    KeyRegistryStateV1, KeyRoleV1, RecipientKeyDescriptorV1,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng, Rng};
use zeroize::Zeroizing;

use super::{begin_immediate_sql, finish_immediate_transaction, CoreError, SqliteStore};

/// An owner-managed Unix directory for one consent grantee's role-4 keys.
#[derive(Clone, Debug)]
pub struct RecipientKeyOwnerV1 {
    directory: PathBuf,
    grantee_id: EntityId,
}

impl RecipientKeyOwnerV1 {
    /// Bind recipient custody to one existing private directory and grantee.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the directory is unavailable or unsafe.
    pub fn open(directory: impl Into<PathBuf>, grantee_id: EntityId) -> Result<Self, CoreError> {
        let directory = directory.into();
        let metadata =
            std::fs::metadata(&directory).map_err(|error| CoreError::Storage(error.to_string()))?;
        if !metadata.is_dir() {
            return Err(CoreError::Storage(
                "recipient key directory is not a directory".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0
                || std::fs::symlink_metadata(&directory)
                    .map_err(|error| CoreError::Storage(error.to_string()))?
                    .file_type()
                    .is_symlink()
            {
                return Err(CoreError::Storage(
                    "recipient key directory is not private".to_owned(),
                ));
            }
        }
        Ok(Self {
            directory,
            grantee_id,
        })
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
        let registry = self
            .load_key_registry()?
            .unwrap_or_else(KeyRegistryStateV1::new);
        let epoch = match registry.active_key(&owner_id, KeyRoleV1::ExportRecipientEncryption) {
            Some(record) => record
                .identity
                .epoch
                .checked_add(1)
                .ok_or_else(|| CoreError::Storage("recipient key epoch overflow".to_owned()))?,
            None => 1,
        };
        let identity =
            KeyIdentityV1::from_parts(owner_id, KeyRoleV1::ExportRecipientEncryption, epoch);
        let mut ikm = Zeroizing::new([0_u8; 32]);
        let mut csprng = UnwrapErr(SysRng);
        csprng.fill(&mut *ikm);
        let (private_key, public_key) =
            pos_crypto::recipient_key::derive_recipient_keypair_v1(&ikm)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
        let private_key = Zeroizing::new(private_key);
        let descriptor = RecipientKeyDescriptorV1::for_grantee(owner.grantee_id, epoch, public_key)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let private_path = owner.directory.join(format!("recipient-{epoch}.key"));
        write_private_key(&private_path, &private_key)?;
        let material_digest = pos_crypto::key_roles::key_material_digest(&private_key);
        let mut next = registry;
        next.register_key(KeyRegistrationV1::new(identity, material_digest, None))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result = self.save_key_registry_in_transaction(&next).and_then(|()| {
            self.conn.execute_batch("CREATE TABLE IF NOT EXISTS recipient_key_inventory_v1 (owner_id TEXT NOT NULL, epoch INTEGER NOT NULL, descriptor BLOB NOT NULL, material_digest BLOB NOT NULL, private_path BLOB NOT NULL, PRIMARY KEY(owner_id, epoch));")
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            self.conn.execute("INSERT INTO recipient_key_inventory_v1 (owner_id, epoch, descriptor, material_digest, private_path) VALUES (?1, ?2, ?3, ?4, ?5)", rusqlite::params![identity.owner_id.as_str(), i64::try_from(epoch).map_err(|error| CoreError::Storage(error.to_string()))?, descriptor.encode(), material_digest.as_bytes().as_slice(), private_path.as_os_str().as_encoded_bytes()])
                .map(|_| descriptor)
                .map_err(|error| CoreError::Storage(error.to_string()))
        });
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
        let owner_id = recipient_owner_id_from_grantee(owner.grantee_id)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let mut statement = self.conn.prepare("SELECT descriptor, material_digest, private_path FROM recipient_key_inventory_v1 WHERE owner_id = ?1 ORDER BY epoch")
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let rows = statement
            .query_map(rusqlite::params![owner_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let mut descriptors = Vec::new();
        for row in rows {
            let (descriptor, digest, path) =
                row.map_err(|error| CoreError::Storage(error.to_string()))?;
            let descriptor = RecipientKeyDescriptorV1::decode(&descriptor)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if !descriptor.is_for_grantee(owner.grantee_id) || digest.len() != 32 {
                return Err(CoreError::Storage(
                    "recipient key inventory is invalid".to_owned(),
                ));
            }
            let path = PathBuf::from(std::ffi::OsString::from_vec(path));
            if !path.starts_with(&owner.directory) {
                return Err(CoreError::Storage(
                    "recipient key inventory path escaped owner directory".to_owned(),
                ));
            }
            let material =
                std::fs::read(path).map_err(|error| CoreError::Storage(error.to_string()))?;
            let material: [u8; 32] = material.try_into().map_err(|_| {
                CoreError::Storage("recipient private key width is invalid".to_owned())
            })?;
            if pos_crypto::key_roles::key_material_digest(&material).as_bytes() != digest.as_slice()
            {
                return Err(CoreError::Storage(
                    "recipient private key digest differs from inventory".to_owned(),
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
        let path = owner.directory.join(format!("recipient-{epoch}.key"));
        std::fs::remove_file(&path).map_err(|error| CoreError::Storage(error.to_string()))?;
        std::fs::File::open(&owner.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        pending
            .complete_key_destruction(request, pos_core::deletion_receipt(&request))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.save_key_registry(&pending)
    }
}

fn write_private_key(path: &Path, private_key: &[u8; 32]) -> Result<(), CoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    file.write_all(private_key)
        .and_then(|()| file.sync_all())
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    drop(file);
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| CoreError::Storage("recipient key directory missing".to_owned()))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| CoreError::Storage(error.to_string()))
}
