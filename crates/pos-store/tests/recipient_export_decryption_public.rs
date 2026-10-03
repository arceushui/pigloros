#![cfg(all(feature = "sqlite", target_os = "linux"))]

//! Public black-box contracts for retained role-4 recipient export decryption.

use std::{error::Error as _, os::unix::fs::PermissionsExt};

use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, EventStore, Hash, KeyDestructionRequestV1,
    KeyRegistryErrorV1, Kind, RecipientKeyDescriptorV1, SchemaVersion, Seq, Timeline,
    TimelineExport, TimelineId, TimelineMeta, TimelineMode, WallTime,
};
use pos_crypto::recipient_export::{
    encrypt_timeline_export_v1, EncryptedTimelineExportV1, RecipientExportErrorV1,
    RecipientTimelineExportV1,
};
use pos_crypto::recipient_key::derive_recipient_keypair_v1;
use pos_store::sqlite::{RecipientExportDecryptionErrorV1, RecipientKeyOwnerV1, SqliteStore};
use rand::{rngs::StdRng, SeedableRng};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT_ID: [u8; 16] = [5; 16];
const DESTRUCTION_AUTHORIZATION: Hash = Hash::from_bytes([8; 32]);

fn private_directory(root: &std::path::Path, name: &str) -> TestResult<std::path::PathBuf> {
    let directory = root.join(name);
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn database(temporary: &tempfile::TempDir) -> std::path::PathBuf {
    temporary.path().join("recipient.sqlite")
}

fn owner_for(
    grantee: EntityId,
) -> TestResult<(tempfile::TempDir, SqliteStore, RecipientKeyOwnerV1)> {
    let temporary = tempfile::tempdir()?;
    let directory = private_directory(temporary.path(), "recipient-private")?;
    let path = database(&temporary);
    let store = SqliteStore::open(path.to_str().ok_or("database path is not UTF-8")?)?;
    let owner = RecipientKeyOwnerV1::open(directory, grantee)?;
    Ok((temporary, store, owner))
}

fn source_export() -> TimelineExport {
    let payload = b"recipient export".to_vec();
    let payload_hash = Hash::from_bytes(*blake3::hash(&payload).as_bytes());
    TimelineExport {
        timeline: Timeline {
            meta: TimelineMeta {
                id: TimelineId::from_ulid(Ulid::from(3_u128)),
                mode: TimelineMode::Live,
                name: None,
                owner: Some(EntityId::from_ulid(Ulid::from(4_u128))),
                fork_point: None,
            },
            head: Seq::from_u64(1),
        },
        events: vec![Event {
            id: EventId::from_ulid(Ulid::from(101_u128)),
            entity: EntityId::from_ulid(Ulid::from(200_u128)),
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(payload),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash,
        }],
        parent_fork_hash: None,
    }
}

fn encrypt(
    descriptor: RecipientKeyDescriptorV1,
    seed: u8,
) -> TestResult<EncryptedTimelineExportV1> {
    let mut rng = StdRng::from_seed([seed; 32]);
    let encrypted = encrypt_timeline_export_v1(&source_export(), descriptor, EXPORT_ID, &mut rng)?;
    Ok(encrypted)
}

fn denied(
    store: &SqliteStore,
    owner: &RecipientKeyOwnerV1,
    encoded: &[u8],
    export_id: [u8; 16],
    descriptor: RecipientKeyDescriptorV1,
) -> Option<RecipientExportDecryptionErrorV1> {
    store
        .decrypt_recipient_export(owner, encoded, export_id, descriptor)
        .err()
}

const fn registry_denial(error: KeyRegistryErrorV1) -> Option<RecipientExportDecryptionErrorV1> {
    Some(RecipientExportDecryptionErrorV1::Registry(error))
}

const fn export_denial(error: RecipientExportErrorV1) -> Option<RecipientExportDecryptionErrorV1> {
    Some(RecipientExportDecryptionErrorV1::Export(error))
}

fn assert_decrypts(
    store: &SqliteStore,
    owner: &RecipientKeyOwnerV1,
    descriptor: RecipientKeyDescriptorV1,
    encrypted: &EncryptedTimelineExportV1,
) -> TestResult {
    let encoded = encrypted.encode();
    let decrypted = store.decrypt_recipient_export(owner, &encoded, EXPORT_ID, descriptor)?;
    let source = source_export();
    assert_eq!(decrypted.payload_digest, encrypted.payload_digest);
    assert_eq!(decrypted.export.timeline.id(), source.timeline.id());
    assert_eq!(decrypted.export.timeline.head, source.timeline.head);
    assert_eq!(
        decrypted.export.events.first().map(|event| event.id),
        source.events.first().map(|event| event.id)
    );
    Ok(())
}

fn material_digest(store: &SqliteStore, descriptor: RecipientKeyDescriptorV1) -> TestResult<Hash> {
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    let digest = registry
        .key_record(descriptor.identity())
        .and_then(|record| record.private_material_digest)
        .ok_or("recipient material digest is absent")?;
    Ok(digest)
}

fn only_private_file(directory: &std::path::Path) -> TestResult<std::path::PathBuf> {
    let mut entries = std::fs::read_dir(directory)?;
    let path = entries.next().ok_or("private key file is absent")??.path();
    if entries.next().is_some() {
        return Err("private directory has more than one entry".into());
    }
    Ok(path)
}

#[test]
fn recipient_decryption_public_contract_decrypts_active_and_retained_epochs_only_encrypting_active(
) -> TestResult {
    let (_temporary, mut store, owner) = owner_for(EntityId::new())?;
    let old = store.enroll_recipient_key(&owner)?;
    let old_export = encrypt(old, 1)?;
    let current = store.enroll_recipient_key(&owner)?;
    let current_export = encrypt(current, 2)?;

    assert_decrypts(&store, &owner, old, &old_export)?;
    assert_decrypts(&store, &owner, current, &current_export)?;
    // Decryption is repeatable and leaves no durable authorization state.
    assert_decrypts(&store, &owner, old, &old_export)?;

    let old_digest = material_digest(&store, old)?;
    let current_digest = material_digest(&store, current)?;
    let mut registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    let called = std::cell::Cell::new(false);
    assert_eq!(
        registry.with_encryption_authorization(old.identity(), old_digest, || called.set(true)),
        Err(KeyRegistryErrorV1::InactiveKey)
    );
    assert!(!called.get());
    assert_eq!(
        registry.with_encryption_authorization(current.identity(), current_digest, || "new")?,
        "new"
    );
    Ok(())
}

#[test]
fn recipient_decryption_public_contract_checks_the_envelope_before_the_locked_registry(
) -> TestResult {
    let (temporary, mut store, owner) = owner_for(EntityId::new())?;
    let old = store.enroll_recipient_key(&owner)?;
    let current = store.enroll_recipient_key(&owner)?;
    let encrypted = encrypt(old, 1)?;
    let encoded = encrypted.encode();
    let mut trailing = encoded.clone();
    trailing.push(0);
    let codec_error = RecipientTimelineExportV1::decode(&trailing).err();
    assert!(codec_error.is_some());
    let foreign = RecipientKeyOwnerV1::open(
        private_directory(temporary.path(), "foreign-private")?,
        EntityId::new(),
    )?;

    let contender = rusqlite::Connection::open(database(&temporary))?;
    contender.execute_batch("BEGIN IMMEDIATE")?;
    assert_eq!(
        denied(&store, &owner, &trailing, EXPORT_ID, old),
        codec_error.map(RecipientExportDecryptionErrorV1::Export)
    );
    assert_eq!(
        denied(&store, &owner, &encoded, [6; 16], old),
        export_denial(RecipientExportErrorV1::IdentityMismatch)
    );
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, current),
        export_denial(RecipientExportErrorV1::IdentityMismatch)
    );
    assert_eq!(
        denied(&store, &foreign, &encoded, EXPORT_ID, old),
        export_denial(RecipientExportErrorV1::IdentityMismatch)
    );
    // A held writer reservation leaves the live key unavailable, not denied.
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, old),
        registry_denial(KeyRegistryErrorV1::RegistryUnavailable)
    );
    contender.execute_batch("ROLLBACK")?;
    assert_decrypts(&store, &owner, old, &encrypted)
}

#[test]
fn recipient_decryption_public_contract_denies_absent_registry_and_unregistered_identities(
) -> TestResult {
    let grantee = EntityId::new();
    let (_temporary, store, owner) = owner_for(grantee)?;
    let (_, public_key) = derive_recipient_keypair_v1(&[9; 32]);
    let unenrolled = RecipientKeyDescriptorV1::for_grantee(grantee, 1, public_key)?;
    let encoded = encrypt(unenrolled, 1)?.encode();
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, unenrolled),
        registry_denial(KeyRegistryErrorV1::RegistryUnavailable)
    );

    let grantee = EntityId::new();
    let (temporary, mut store, owner) = owner_for(grantee)?;
    let enrolled = store.enroll_recipient_key(&owner)?;
    let next_epoch = RecipientKeyDescriptorV1::for_grantee(grantee, 2, public_key)?;
    let encoded = encrypt(next_epoch, 1)?.encode();
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, next_epoch),
        registry_denial(KeyRegistryErrorV1::NotFound)
    );

    let encoded = encrypt(enrolled, 1)?.encode();
    rusqlite::Connection::open(database(&temporary))?
        .execute_batch("UPDATE key_registry SET state_cbor = X'01'")?;
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, enrolled),
        registry_denial(KeyRegistryErrorV1::RegistryUnavailable)
    );
    Ok(())
}

#[test]
fn recipient_decryption_public_contract_denies_a_public_key_not_bound_to_the_material(
) -> TestResult {
    let grantee = EntityId::new();
    let (_temporary, mut store, owner) = owner_for(grantee)?;
    let enrolled = store.enroll_recipient_key(&owner)?;
    let (_, public_key) = derive_recipient_keypair_v1(&[9; 32]);
    let forged = RecipientKeyDescriptorV1::for_grantee(grantee, 1, public_key)?;
    assert_eq!(forged.identity(), enrolled.identity());
    let encoded = encrypt(forged, 1)?.encode();
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, forged),
        registry_denial(KeyRegistryErrorV1::EncryptionKeyMismatch)
    );
    Ok(())
}

#[test]
fn recipient_decryption_public_contract_reports_missing_or_corrupt_material_unavailable(
) -> TestResult {
    let unavailable = Some(RecipientExportDecryptionErrorV1::MaterialUnavailable);

    let (temporary, mut store, owner) = owner_for(EntityId::new())?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let encoded = encrypt(descriptor, 1)?.encode();
    let directory = temporary.path().join("recipient-private");
    std::fs::remove_file(only_private_file(&directory)?)?;
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, descriptor),
        unavailable
    );

    let (temporary, mut store, owner) = owner_for(EntityId::new())?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let encoded = encrypt(descriptor, 1)?.encode();
    let directory = temporary.path().join("recipient-private");
    std::fs::write(only_private_file(&directory)?, [17_u8; 32])?;
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, descriptor),
        unavailable
    );

    let (temporary, mut store, owner) = owner_for(EntityId::new())?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let encoded = encrypt(descriptor, 1)?.encode();
    rusqlite::Connection::open(database(&temporary))?
        .execute_batch("DELETE FROM recipient_key_inventory_v1")?;
    assert_eq!(
        denied(&store, &owner, &encoded, EXPORT_ID, descriptor),
        unavailable
    );
    Ok(())
}

/// Count the durable recipient custody directory claims.
fn directory_claims(temporary: &tempfile::TempDir) -> TestResult<i64> {
    let connection = rusqlite::Connection::open(database(temporary))?;
    Ok(connection.query_row(
        "SELECT count(*) FROM recipient_custody_directory_claims_v1",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn recipient_decryption_public_contract_rolls_back_a_first_use_directory_claim() -> TestResult {
    let grantee = EntityId::new();
    let (temporary, mut store, owner) = owner_for(grantee)?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let encoded = encrypt(descriptor, 1)?.encode();
    // Decrypting through a fresh directory claims it inside the transaction,
    // then finds no bound file there; the claim must not survive the call.
    let fresh = private_directory(temporary.path(), "fresh-private")?;
    let first_use = RecipientKeyOwnerV1::open(fresh.clone(), grantee)?;
    let claims_before = directory_claims(&temporary)?;
    assert_eq!(
        denied(&store, &first_use, &encoded, EXPORT_ID, descriptor),
        Some(RecipientExportDecryptionErrorV1::MaterialUnavailable)
    );
    // The only durable claim, before and after, is the enrolled directory's
    // own; the fresh directory's first-use claim was rolled back.
    assert_eq!(claims_before, 1);
    assert_eq!(directory_claims(&temporary)?, claims_before);
    // A persisted claim for the first grantee would refuse this enrollment.
    let other_grantee = EntityId::new();
    let other = RecipientKeyOwnerV1::open(fresh, other_grantee)?;
    let enrolled = store.enroll_recipient_key(&other)?;
    assert!(enrolled.is_for_grantee(other_grantee));
    Ok(())
}

#[test]
fn recipient_decryption_public_contract_rejects_tampered_ciphertext_without_plaintext(
) -> TestResult {
    let (_temporary, mut store, owner) = owner_for(EntityId::new())?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let mut envelope = encrypt(descriptor, 1)?.envelope;
    let byte = envelope
        .ciphertext_chunks
        .first_mut()
        .and_then(|chunk| chunk.first_mut())
        .ok_or("ciphertext chunk is empty")?;
    *byte ^= 1;
    assert_eq!(
        denied(&store, &owner, &envelope.encode(), EXPORT_ID, descriptor),
        export_denial(RecipientExportErrorV1::AuthenticationFailed)
    );
    Ok(())
}

#[test]
fn recipient_decryption_public_contract_orders_rotation_pending_and_destroyed_epochs(
) -> TestResult {
    let (temporary, mut store, owner) = owner_for(EntityId::new())?;
    let old = store.enroll_recipient_key(&owner)?;
    let old_export = encrypt(old, 1)?;
    let current = store.enroll_recipient_key(&owner)?;
    let current_export = encrypt(current, 2)?;
    let old_digest = material_digest(&store, old)?;

    store.begin_key_registry_destruction(KeyDestructionRequestV1::new(
        old.identity(),
        old_digest,
        DESTRUCTION_AUTHORIZATION,
    ))?;
    assert_eq!(
        denied(&store, &owner, &old_export.encode(), EXPORT_ID, old),
        registry_denial(KeyRegistryErrorV1::DestructionPending)
    );
    assert_decrypts(&store, &owner, current, &current_export)?;

    store.destroy_recipient_key(&owner, old.identity().epoch, DESTRUCTION_AUTHORIZATION)?;
    let directory = temporary.path().join("recipient-private");
    assert_eq!(std::fs::read_dir(&directory)?.count(), 1);
    assert_eq!(
        denied(&store, &owner, &old_export.encode(), EXPORT_ID, old),
        registry_denial(KeyRegistryErrorV1::Destroyed)
    );
    assert_decrypts(&store, &owner, current, &current_export)
}

#[test]
fn recipient_decryption_public_contract_errors_display_their_closed_cause() {
    let cases = [
        (
            RecipientExportDecryptionErrorV1::Export(RecipientExportErrorV1::AuthenticationFailed),
            RecipientExportErrorV1::AuthenticationFailed.to_string(),
        ),
        (
            RecipientExportDecryptionErrorV1::Registry(KeyRegistryErrorV1::Destroyed),
            KeyRegistryErrorV1::Destroyed.to_string(),
        ),
        (
            RecipientExportDecryptionErrorV1::MaterialUnavailable,
            "recipient private key material is unavailable".to_owned(),
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
}
