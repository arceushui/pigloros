#![cfg(any(test, feature = "test-support"))]
//! The matrix's bound store: the durable subject key staging store (ADR-137
//! P1, P3, P3a and P5) behind the owner adapter's store traits.
//!
//! `DurableEnrollmentStore` implements [`EnrollmentStore`] and [`UnlockStore`]
//! over the plain-value methods of `SqliteStore`. It holds what those traits
//! leave out of their calls: the bound store's file identity, which
//! `commit_staging_record` returns and the store takes as input, and the
//! Timeline of each subject, which keys the B6 fence in the store while the
//! traits key it by subject. The wrapper for the owner executable is part of
//! the activation (#1438); this one exists for the acceptance matrix only.
//! The type itself lives in the matrix root, whose lints admit no `pub` item
//! in a private module.

use pos_core::{
    error::CoreError, ids::TimelineId, EntityId, EventStore, Hash, KeyRegistryStateV1, KeyRoleV1,
};
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use pos_owner_adapter::enrollment::{EnrollmentStore, SubjectKeyRegistration};
use pos_owner_adapter::unlock::UnlockStore;
use pos_owner_bridge::{OwnerError, OwnerErrorKind};
use pos_store::sqlite::SqliteStore;

use super::{DurableEnrollmentStore, Registered};

const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);

impl DurableEnrollmentStore {
    /// A store whose proven file identity is `file_id`, whose SNL1 store-file
    /// encoding is `file_bytes`, and that knows the Timeline of each subject.
    pub(super) fn new(
        file_id: SubjectStoreFileIdV1,
        file_bytes: &[u8],
        timelines: impl IntoIterator<Item = (EntityId, TimelineId)>,
    ) -> Result<Self, CoreError> {
        SqliteStore::open_in_memory()
            .and_then(|mut store| {
                store
                    .save_key_registry(&KeyRegistryStateV1::new())
                    .map(|()| store)
            })
            .map(|store| Self {
                store,
                file_id,
                file_bytes: file_bytes.to_vec(),
                timelines: timelines.into_iter().collect(),
            })
    }

    /// The `(owner_id, epoch)` staging records of this store left for P5, in
    /// order. It reads them through the store's own P5 recovery, which also
    /// deletes foreign and settled records, so a stray settled record is not
    /// visible here.
    pub(super) fn staging_records(&self) -> Result<Vec<(String, u64)>, CoreError> {
        self.store
            .recover_subject_key_staging(&self.file_bytes)
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| (record.owner_id, record.epoch))
                    .collect()
            })
    }

    /// The live `SubjectDataEncryption` identities of the registry.
    pub(super) fn registrations(&self) -> Result<Vec<Registered>, CoreError> {
        self.store.load_key_registry().map(|registry| {
            registry
                .map(|registry| {
                    registry
                        .key_records()
                        .filter(|record| record.identity.role == KeyRoleV1::SubjectDataEncryption)
                        .filter_map(|record| {
                            record.private_material_digest.map(|digest| {
                                (
                                    record.identity.owner_id.as_str().to_owned(),
                                    record.identity.epoch,
                                    *digest.as_bytes(),
                                )
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    /// The Timeline of `subject`; an unknown subject refuses.
    fn timeline(&self, subject_id: EntityId) -> Result<TimelineId, OwnerError> {
        self.timelines.get(&subject_id).copied().ok_or(REGISTRY)
    }
}

/// Every store failure becomes the one registry refusal, as the volatile
/// store's: the adapter cannot tell a definite refusal from an unknown commit.
fn sealed<T>(result: Result<T, CoreError>) -> Result<T, OwnerError> {
    result.map_err(|_| REGISTRY)
}

impl EnrollmentStore for DurableEnrollmentStore {
    fn registry_epoch_ceiling(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
    ) -> Result<u64, OwnerError> {
        self.timeline(subject_id).and_then(|timeline| {
            sealed(
                self.store
                    .subject_registry_epoch_ceiling(owner_id, timeline),
            )
        })
    }

    fn commit_staging_record(
        &mut self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<SubjectStoreFileIdV1, OwnerError> {
        sealed(
            self.store
                .commit_subject_key_staging_record(owner_id, epoch, &self.file_bytes),
        )
        .map(|()| self.file_id)
    }

    fn register(&mut self, registration: &SubjectKeyRegistration) -> Result<(), OwnerError> {
        self.timeline(registration.subject_id).and_then(|timeline| {
            sealed(self.store.register_subject_key(
                &registration.owner_id,
                timeline,
                registration.epoch,
                &self.file_bytes,
                Hash::from_bytes(registration.root_material_digest),
            ))
        })
    }

    fn delete_staging_record(&mut self, owner_id: &str, epoch: u64) -> Result<(), OwnerError> {
        sealed(
            self.store
                .delete_subject_key_staging_record(owner_id, epoch, &self.file_bytes),
        )
    }
}

impl UnlockStore for DurableEnrollmentStore {
    fn registered_root_material_digest(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
        epoch: u64,
    ) -> Result<[u8; 32], OwnerError> {
        self.timeline(subject_id).and_then(|_| {
            sealed(
                self.store
                    .registered_subject_root_material_digest(owner_id, epoch),
            )
            .map(|digest| *digest.as_bytes())
        })
    }
}
