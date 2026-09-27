#![cfg(feature = "sqlite")]

use std::{cell::Cell, sync::mpsc, time::Duration};

use pos_core::{
    deletion_receipt, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryErrorV1, KeyRegistryHistoricalDecryptionPortV1, KeyRegistryStateV1, KeyRoleV1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

const fn digest(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn wait_for_worker(started_rx: &mpsc::Receiver<()>, release_tx: &mpsc::Sender<()>, worker: &str) {
    let started = started_rx.recv_timeout(Duration::from_secs(5));
    if started.is_err() {
        assert!(release_tx.send(()).is_ok(), "callback must be released");
    }
    assert!(started.is_ok(), "{worker} did not start: {started:?}");
}

fn deny(
    store: &mut impl KeyRegistryHistoricalDecryptionPortV1,
    identity: KeyIdentityV1,
    material: Hash,
    expected: KeyRegistryErrorV1,
) {
    let called = Cell::new(false);
    assert_eq!(
        store.with_decryption_authorization(identity, material, || {
            called.set(true);
        }),
        Err(expected)
    );
    assert!(!called.get());
}

fn exercise_adapter<S: EventStore + KeyRegistryHistoricalDecryptionPortV1>(
    mut store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let old = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let current = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 2);
    deny(
        &mut store,
        KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 0),
        digest(1),
        KeyRegistryErrorV1::InvalidEpoch,
    );
    deny(
        &mut store,
        KeyIdentityV1::new("subject-owner", KeyRoleV1::ExportRecipientEncryption, 1),
        digest(1),
        KeyRegistryErrorV1::HistoricalDecryptionRoleRequired,
    );
    deny(
        &mut store,
        old,
        digest(1),
        KeyRegistryErrorV1::RegistryUnavailable,
    );

    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(old, digest(1), None))?;
    registry.register_key(KeyRegistrationV1::new(current, digest(2), None))?;
    store.save_key_registry(&registry)?;
    assert_eq!(
        store.with_decryption_authorization(old, digest(1), || "retained ciphertext")?,
        "retained ciphertext"
    );
    assert_eq!(
        store.with_decryption_authorization(current, digest(2), || "current ciphertext")?,
        "current ciphertext"
    );
    deny(
        &mut store,
        KeyIdentityV1::new("different-owner", KeyRoleV1::SubjectDataEncryption, 1),
        digest(1),
        KeyRegistryErrorV1::NotFound,
    );
    deny(
        &mut store,
        KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 3),
        digest(1),
        KeyRegistryErrorV1::NotFound,
    );
    deny(
        &mut store,
        old,
        digest(2),
        KeyRegistryErrorV1::EncryptionKeyMismatch,
    );

    let request = KeyDestructionRequestV1::new(old, digest(1), digest(3));
    store.begin_key_registry_destruction(request)?;
    deny(
        &mut store,
        old,
        digest(1),
        KeyRegistryErrorV1::DestructionPending,
    );
    store.complete_key_registry_destruction(request, deletion_receipt(&request))?;
    deny(&mut store, old, digest(1), KeyRegistryErrorV1::Destroyed);
    assert_eq!(
        store.with_decryption_authorization(current, digest(2), || "still live")?,
        "still live"
    );
    Ok(())
}

#[test]
fn memory_historical_decryption_holds_one_registry_owner() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_adapter(MemoryStore::new())
}

#[test]
fn sqlite_historical_decryption_uses_persisted_registry() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_adapter(SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_historical_decryption_serializes_rotation_and_destruction(
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone, Copy)]
    enum CompetingMutation {
        Rotate,
        BeginDestruction,
    }

    let old = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let current = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 2);
    for mutation in [
        CompetingMutation::Rotate,
        CompetingMutation::BeginDestruction,
    ] {
        let database = tempfile::NamedTempFile::new()?;
        let path = database
            .path()
            .to_str()
            .ok_or("database path is not UTF-8")?;
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(old, digest(1), None))?;
        let mut rotated = registry.clone();
        rotated.register_key(KeyRegistrationV1::new(current, digest(2), None))?;
        let request = KeyDestructionRequestV1::new(old, digest(1), digest(3));
        let mut setup = SqliteStore::open(path)?;
        setup.save_key_registry(&registry)?;
        drop(setup);

        let mut decrypting_store = SqliteStore::open(path)?;
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let decryption = scope.spawn(move || {
                decrypting_store.with_decryption_authorization(old, digest(1), || {
                    assert!(
                        entered_tx.send(()).is_ok(),
                        "callback entry must be observed"
                    );
                    assert!(release_rx.recv().is_ok(), "callback must be released");
                    "plaintext"
                })
            });
            wait_for_worker(&entered_rx, &release_tx, "decryption callback");
            let blocked = (|| {
                let contender = rusqlite::Connection::open(path)?;
                contender.busy_timeout(Duration::ZERO)?;
                contender.execute_batch("BEGIN IMMEDIATE")
            })();
            assert!(release_tx.send(()).is_ok(), "callback must be released");
            assert!(decryption
                .join()
                .is_ok_and(|result| result == Ok("plaintext")));
            assert!(
                blocked.is_err_and(|error| error.to_string().contains("database is locked")),
                "the held decryption callback must retain SQLite's writer reservation"
            );
        });

        let mut mutating_store = SqliteStore::open(path)?;
        match mutation {
            CompetingMutation::Rotate => mutating_store.save_key_registry(&rotated)?,
            CompetingMutation::BeginDestruction => {
                mutating_store.begin_key_registry_destruction(request)?;
            }
        }

        let mut verify = SqliteStore::open(path)?;
        match mutation {
            CompetingMutation::Rotate => {
                assert_eq!(
                    verify.with_decryption_authorization(old, digest(1), || "old plaintext")?,
                    "old plaintext"
                );
            }
            CompetingMutation::BeginDestruction => {
                deny(
                    &mut verify,
                    old,
                    digest(1),
                    KeyRegistryErrorV1::DestructionPending,
                );
            }
        }
    }
    Ok(())
}
