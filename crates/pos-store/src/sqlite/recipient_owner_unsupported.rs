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

use pos_core::{ConsentAuthority, CoreError, EntityId, Hash, RecipientKeyDescriptorV1};
use pos_crypto::recipient_export::DecryptedTimelineExportV1;

use super::{
    PublishedRecipientExportV1, RecipientExportDecryptionErrorV1,
    RecipientExportPublicationErrorV1, RecipientExportRequestV1, SqliteStore,
};

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

    /// Refuse decryption on platforms without the required file boundary.
    ///
    /// No recipient key can be enrolled here, so the Linux adapter's
    /// envelope-first precedence is skipped: the result is always
    /// [`RecipientExportDecryptionErrorV1::MaterialUnavailable`].
    ///
    /// # Errors
    ///
    /// Always reports the recipient private material as unavailable.
    pub const fn decrypt_recipient_export(
        &self,
        _owner: &RecipientKeyOwnerV1,
        _encoded: &[u8],
        _expected_export_id: [u8; 16],
        _expected_recipient: RecipientKeyDescriptorV1,
    ) -> Result<DecryptedTimelineExportV1, RecipientExportDecryptionErrorV1> {
        Err(RecipientExportDecryptionErrorV1::MaterialUnavailable)
    }

    /// Refuse recipient-export publication without Linux private-file support.
    ///
    /// # Errors
    ///
    /// Always reports the Linux custody requirement.
    pub fn publish_recipient_export(
        &mut self,
        _authority: &ConsentAuthority,
        _owner: &RecipientKeyOwnerV1,
        _request: &RecipientExportRequestV1<'_>,
    ) -> Result<PublishedRecipientExportV1, RecipientExportPublicationErrorV1> {
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage(UNSUPPORTED.to_owned()),
        ))
    }

    /// Refuse recipient-export retrieval without Linux private-file support.
    ///
    /// # Errors
    ///
    /// Always reports the Linux custody requirement.
    pub fn read_recipient_export(
        &self,
        _owner: &RecipientKeyOwnerV1,
        _export_id: [u8; 16],
    ) -> Result<Vec<u8>, RecipientExportPublicationErrorV1> {
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage(UNSUPPORTED.to_owned()),
        ))
    }

    /// Refuse recipient-export recovery without Linux private-file support.
    ///
    /// # Errors
    ///
    /// Always reports the Linux custody requirement.
    pub fn recover_recipient_exports(
        &mut self,
        _owner: &RecipientKeyOwnerV1,
    ) -> Result<(), RecipientExportPublicationErrorV1> {
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage(UNSUPPORTED.to_owned()),
        ))
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
