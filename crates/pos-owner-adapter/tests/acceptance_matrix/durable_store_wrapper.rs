#![cfg(any(test, feature = "test-support"))]
//! The matrix's durable store wrapper keeps what the traits leave out of
//! their calls (the bound file identity and the subject's Timeline) and
//! refuses what the durable store refuses.

use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerRowV1, SubjectNonceLedgerV1};
use pos_owner_adapter::enrollment::{EnrollmentStore, SubjectKeyRegistration};
use pos_owner_adapter::unlock::UnlockStore;

use super::{
    entity, owner, timeline, DurableEnrollmentStore, SubjectId, TestResult, FILE, FILE_BYTES,
    OTHER, REGISTRY, SUBJECT,
};

const DIGEST: [u8; 32] = [3; 32];

fn store(subjects: &[SubjectId]) -> TestResult<DurableEnrollmentStore> {
    Ok(DurableEnrollmentStore::new(
        FILE,
        &FILE_BYTES,
        subjects
            .iter()
            .map(|subject| (entity(*subject), timeline(*subject))),
    )?)
}

fn registration(epoch: u64) -> SubjectKeyRegistration {
    SubjectKeyRegistration {
        owner_id: owner(SUBJECT),
        subject_id: entity(SUBJECT),
        epoch,
        root_material_digest: DIGEST,
    }
}

#[test]
fn the_store_file_bytes_are_the_snl1_encoding_of_the_file_identity() -> TestResult {
    let ledger = SubjectNonceLedgerV1::new(vec![SubjectNonceLedgerRowV1 {
        owner_id: owner(SUBJECT),
        epoch: 1,
        root_material_digest: DIGEST,
        store_file_id: FILE,
        data_next: 1,
        bootstrap_next: 1,
    }])?;
    assert!(ledger
        .as_bytes()
        .windows(FILE_BYTES.len())
        .any(|window| window == FILE_BYTES));
    Ok(())
}

#[test]
fn a_subject_without_a_timeline_is_refused_by_every_read_of_the_registry() -> TestResult {
    let mut store = store(&[OTHER])?;
    assert_eq!(
        store.registry_epoch_ceiling(&owner(SUBJECT), entity(SUBJECT)),
        Err(REGISTRY)
    );
    assert_eq!(store.register(&registration(1)), Err(REGISTRY));
    assert_eq!(
        store.registered_root_material_digest(&owner(SUBJECT), entity(SUBJECT), 1),
        Err(REGISTRY)
    );
    Ok(())
}

#[test]
fn a_staging_record_names_the_bound_file_and_is_deleted_idempotently() -> TestResult {
    let mut store = store(&[SUBJECT])?;
    assert_eq!(store.commit_staging_record(&owner(SUBJECT), 1), Ok(FILE));
    assert_eq!(
        store.commit_staging_record(&owner(SUBJECT), 1),
        Err(REGISTRY)
    );
    assert_eq!(store.staging_records()?, [(owner(SUBJECT), 1)]);
    assert_eq!(store.delete_staging_record(&owner(SUBJECT), 1), Ok(()));
    assert_eq!(store.delete_staging_record(&owner(SUBJECT), 1), Ok(()));
    assert!(store.staging_records()?.is_empty());
    Ok(())
}

#[test]
fn registering_consumes_the_record_and_raises_the_ceiling() -> TestResult {
    let mut store = store(&[SUBJECT])?;
    let subject = entity(SUBJECT);
    assert_eq!(
        store.registry_epoch_ceiling(&owner(SUBJECT), subject),
        Ok(0)
    );
    assert_eq!(store.register(&registration(1)), Err(REGISTRY));
    assert_eq!(store.commit_staging_record(&owner(SUBJECT), 1), Ok(FILE));
    assert_eq!(store.register(&registration(1)), Ok(()));
    assert!(store.staging_records()?.is_empty());
    assert_eq!(store.registrations()?, [(owner(SUBJECT), 1, DIGEST)]);
    assert_eq!(
        store.registry_epoch_ceiling(&owner(SUBJECT), subject),
        Ok(1)
    );
    assert_eq!(
        store.registered_root_material_digest(&owner(SUBJECT), subject, 1),
        Ok(DIGEST)
    );
    assert_eq!(
        store.registered_root_material_digest(&owner(SUBJECT), subject, 2),
        Err(REGISTRY)
    );
    Ok(())
}
