#![cfg(any(test, feature = "test-support"))]
//! The test-support `EnrollmentStore`: the ADR-137 P3 steps 2, 3 and 6 and
//! the P5 record deletion.
#![cfg(target_os = "linux")]

use pos_core::EntityId;
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use pos_owner_adapter::enrollment::{
    EnrollmentStore, SubjectKeyRegistration, VolatileEnrollmentStore,
};
use pos_owner_bridge::{OwnerError, OwnerErrorKind};
use sha2::{Digest, Sha256};
use ulid::Ulid;

/// `N` bytes derived one-way from `label`, so no literal key material is used.
///
/// Byte `i` comes from `SHA-256(label || block)` with `block = i / 32`. The block counter
/// saturates, which no caller reaches because every caller asks for at most 32 bytes.
fn derived<const N: usize>(label: &str) -> [u8; N] {
    std::array::from_fn(|index| {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update([u8::try_from(index / 32).unwrap_or(u8::MAX)]);
        hasher.finalize()[index % 32]
    })
}

const FILE: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: 7,
    inode: 9,
};
const OWNER: &str = "subject:10101010101010101010101010101010";
const OTHER: &str = "subject:20202020202020202020202020202020";
const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);

const fn subject(byte: u8) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([byte; 16]))
}

fn registration(epoch: u64) -> SubjectKeyRegistration {
    SubjectKeyRegistration {
        owner_id: OWNER.to_owned(),
        subject_id: subject(0x10),
        epoch,
        root_material_digest: derived("registration root material digest"),
    }
}

fn staged(store: &VolatileEnrollmentStore) -> Vec<(String, u64)> {
    store
        .staging_records()
        .map(|(owner_id, epoch)| (owner_id.to_owned(), epoch))
        .collect()
}

#[test]
fn the_ceiling_is_the_highest_epoch_recorded_for_the_owner() {
    let mut store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(store.registry_epoch_ceiling(OWNER, subject(0x10)), Ok(0));
    store.record_epoch(OWNER, 4);
    store.record_epoch(OWNER, 2);
    store.record_epoch(OTHER, 9);
    assert_eq!(store.registry_epoch_ceiling(OWNER, subject(0x10)), Ok(4));
    assert_eq!(store.registry_epoch_ceiling(OTHER, subject(0x20)), Ok(9));
}

#[test]
fn a_b6_fence_refuses_the_ceiling_and_registration_of_its_subject_only() {
    let mut store = VolatileEnrollmentStore::new(FILE);
    store.fence(subject(0x10));
    assert_eq!(
        store.registry_epoch_ceiling(OWNER, subject(0x10)),
        Err(REGISTRY)
    );
    assert_eq!(store.registry_epoch_ceiling(OTHER, subject(0x20)), Ok(0));
    assert_eq!(store.commit_staging_record(OWNER, 1), Ok(FILE));
    assert_eq!(store.register(&registration(1)), Err(REGISTRY));
    assert_eq!(staged(&store), [(OWNER.to_owned(), 1)]);
    assert!(store.registrations().is_empty());
}

#[test]
fn a_staging_record_is_unique_and_returns_the_bound_store_identity() {
    let mut store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(store.commit_staging_record(OWNER, 1), Ok(FILE));
    assert_eq!(store.commit_staging_record(OWNER, 1), Err(REGISTRY));
    assert_eq!(store.commit_staging_record(OTHER, 1), Ok(FILE));
    assert_eq!(
        staged(&store),
        [(OWNER.to_owned(), 1), (OTHER.to_owned(), 1)]
    );
}

#[test]
fn registration_needs_its_staging_record_and_an_epoch_above_the_mark() {
    let mut store = VolatileEnrollmentStore::new(FILE);
    // Above the mark, but never staged.
    assert_eq!(store.register(&registration(1)), Err(REGISTRY));
    // Staged, but not above the mark.
    assert_eq!(store.commit_staging_record(OWNER, 1), Ok(FILE));
    store.record_epoch(OWNER, 1);
    assert_eq!(store.register(&registration(1)), Err(REGISTRY));
    // Staged and above the mark: registered, and the record is deleted.
    assert_eq!(store.commit_staging_record(OWNER, 2), Ok(FILE));
    assert_eq!(store.register(&registration(2)), Ok(()));
    assert_eq!(staged(&store), [(OWNER.to_owned(), 1)]);
    assert_eq!(store.registrations(), [registration(2)]);
    assert_eq!(store.registry_epoch_ceiling(OWNER, subject(0x10)), Ok(2));
}

#[test]
fn deleting_a_staging_record_removes_exactly_it_and_repeats() {
    let mut store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(store.commit_staging_record(OWNER, 1), Ok(FILE));
    assert_eq!(store.commit_staging_record(OWNER, 2), Ok(FILE));
    assert_eq!(store.commit_staging_record(OTHER, 1), Ok(FILE));
    assert_eq!(store.delete_staging_record(OWNER, 1), Ok(()));
    assert_eq!(
        staged(&store),
        [(OWNER.to_owned(), 2), (OTHER.to_owned(), 1)]
    );
    // A missing record is an idempotent success.
    assert_eq!(store.delete_staging_record(OWNER, 1), Ok(()));
    assert_eq!(staged(&store).len(), 2);
    // The epoch is free to stage again.
    assert_eq!(store.commit_staging_record(OWNER, 1), Ok(FILE));
}
