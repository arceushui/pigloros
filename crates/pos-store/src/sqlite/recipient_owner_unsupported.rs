//! Explicitly unsupported recipient-key custody outside Unix.

use std::path::PathBuf;

use pos_core::{CoreError, EntityId, Hash, RecipientKeyDescriptorV1};

use super::SqliteStore;

/// A role-4 recipient owner is unavailable without Unix private-file support.
#[derive(Clone, Debug)]
pub struct RecipientKeyOwnerV1;

impl RecipientKeyOwnerV1 {
    /// Refuse recipient custody on platforms without the required file boundary.
    pub fn open(_directory: impl Into<PathBuf>, _grantee_id: EntityId) -> Result<Self, CoreError> {
        Err(CoreError::Storage(
            "recipient key custody requires Unix".to_owned(),
        ))
    }
}

impl SqliteStore {
    /// Refuse enrollment on platforms without the required file boundary.
    pub fn enroll_recipient_key(
        &mut self,
        _owner: &RecipientKeyOwnerV1,
    ) -> Result<RecipientKeyDescriptorV1, CoreError> {
        Err(CoreError::Storage(
            "recipient key custody requires Unix".to_owned(),
        ))
    }

    /// Refuse recovery on platforms without the required file boundary.
    pub fn recover_recipient_keys(
        &self,
        _owner: &RecipientKeyOwnerV1,
    ) -> Result<Vec<RecipientKeyDescriptorV1>, CoreError> {
        Err(CoreError::Storage(
            "recipient key custody requires Unix".to_owned(),
        ))
    }

    /// Refuse destruction on platforms without the required file boundary.
    pub fn destroy_recipient_key(
        &mut self,
        _owner: &RecipientKeyOwnerV1,
        _epoch: u64,
        _authorization_digest: Hash,
    ) -> Result<(), CoreError> {
        Err(CoreError::Storage(
            "recipient key custody requires Unix".to_owned(),
        ))
    }
}
