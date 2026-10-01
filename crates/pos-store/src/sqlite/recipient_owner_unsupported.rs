//! Explicitly unsupported recipient-key custody outside Linux.
//!
//! The custody adapter depends on Linux-only `openat2` resolve flags and
//! `renameat2(RENAME_NOREPLACE)`, so every other target fails closed here.
//!
//! This Linux-only narrowing is deliberate, not a portability gap: accepted
//! ADR-098 allows a target without the required custody durability
//! guarantees to report recipient custody as unsupported rather than weaken
//! those guarantees.

use std::path::PathBuf;

use pos_core::{CoreError, EntityId, Hash, RecipientKeyDescriptorV1};

use super::SqliteStore;

const UNSUPPORTED: &str = "recipient key custody requires Linux";

/// A role-4 recipient owner is unavailable without Linux private-file support.
#[derive(Debug)]
pub struct RecipientKeyOwnerV1;

impl RecipientKeyOwnerV1 {
    /// Refuse recipient custody on platforms without the required file boundary.
    ///
    /// # Errors
    ///
    /// Always returns a storage error naming the Linux requirement.
    pub fn open(_directory: impl Into<PathBuf>, _grantee_id: EntityId) -> Result<Self, CoreError> {
        Err(CoreError::Storage(UNSUPPORTED.to_owned()))
    }
}

impl SqliteStore {
    /// Refuse enrollment on platforms without the required file boundary.
    ///
    /// # Errors
    ///
    /// Always returns a storage error naming the Linux requirement.
    pub fn enroll_recipient_key(
        &mut self,
        _owner: &RecipientKeyOwnerV1,
    ) -> Result<RecipientKeyDescriptorV1, CoreError> {
        Err(CoreError::Storage(UNSUPPORTED.to_owned()))
    }

    /// Refuse recovery on platforms without the required file boundary.
    ///
    /// # Errors
    ///
    /// Always returns a storage error naming the Linux requirement.
    pub fn recover_recipient_keys(
        &self,
        _owner: &RecipientKeyOwnerV1,
    ) -> Result<Vec<RecipientKeyDescriptorV1>, CoreError> {
        Err(CoreError::Storage(UNSUPPORTED.to_owned()))
    }

    /// Refuse destruction on platforms without the required file boundary.
    ///
    /// # Errors
    ///
    /// Always returns a storage error naming the Linux requirement.
    pub fn destroy_recipient_key(
        &mut self,
        _owner: &RecipientKeyOwnerV1,
        _epoch: u64,
        _authorization_digest: Hash,
    ) -> Result<(), CoreError> {
        Err(CoreError::Storage(UNSUPPORTED.to_owned()))
    }
}
