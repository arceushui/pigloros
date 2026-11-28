#![cfg(any(test, feature = "test-support"))]
//! The owner field-read port over a qualified store: B6 first, the indexed
//! latest lookup over the stitched Fork chain, exactly one delivery, and the
//! closed outer results of ADR-121 §5.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Arc;

use pos_core::{deletion_receipt, KeyDestructionRequestV1};
use pos_core::{
    CanonicalBytes, ErasureContainmentGateV1, EventDraft, EventStore, FieldStateV1,
    GatewayModeBindingHostV1, GatewayModeBindingPortV1, GatewayModeProfileRefV1, KeyRegistrationV1,
    KeyRoleV1, Kind, OwnerIdV1, PublicKey,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_crypto::signing::generate_keypair;
use pos_crypto::subject_data::SUBJECT_DATA_EVENT_TYPE;
use pos_crypto::subject_field_read::SubjectFieldReadError;
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyWrapParamsV1, SubjectKeyWrapV1, SubjectPrfOutputV1,
    SubjectRootKeyV1,
};
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, SubjectStoreFileIdV1,
};
use rusqlite::Connection;
use ulid::Ulid;

use super::*;
use crate::owner_store_admission::OwnerStoreAdmissionV1;
use crate::owner_store_binding::{release_identity, OwnerStoreContextV1};
use crate::owner_store_installation::install_owner_store_namespace_v1;
use crate::owner_store_interlock::OwnerStoreFileInterlockV1;
use crate::subject_data_consumer::{
    append_subject_preference_weights, SubjectDataAppendV1, SubjectDataConsumerErrorV1 as Refusal,
    VolatileSubjectNonceLedgerV1,
};

/// The ADR-137 A3 lookup index, copied from the revocation journal slice
/// (#1553), which owns it in the production schema.
const EVENTS_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS idx_events_entity_type
    ON events(timeline_id, entity_id, event_type, seq)";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Outcome = (
    Result<(), SubjectFieldOwnerReadErrorV1>,
    Vec<SubjectFieldReadResultV1>,
);

const MAIN: &str = "store.db";
const SUBJECT: EntityId = EntityId::from_ulid(Ulid::from_bytes([0x22; 16]));
const OTHER: EntityId = EntityId::from_ulid(Ulid::from_bytes([0x33; 16]));

/// Distinct, non-repeating bytes for one seed.
fn pattern<const N: usize>(seed: u8) -> [u8; N] {
    let mut next = seed;
    std::array::from_fn(|_| {
        next = next.wrapping_mul(31).wrapping_add(17);
        next
    })
}

/// The accepted ADR-097 B4 plaintext `{name: [0.5, 1.0]}` for a short name.
fn weight_set(name: &str) -> Vec<u8> {
    let mut bytes = vec![0xa1, 0x60 + u8::try_from(name.len()).unwrap_or(u8::MAX)];
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(&[0x82, 0xf9, 0x38, 0x00, 0xf9, 0x3c, 0x00]);
    bytes
}

fn present(name: &str) -> Outcome {
    (
        Ok(()),
        vec![Ok(FieldStateV1::Present(CanonicalBytes::from_vec(
            weight_set(name),
        )))],
    )
}

fn field(result: SubjectFieldReadResultV1) -> Outcome {
    (Ok(()), vec![result])
}

const fn refused(error: SubjectFieldOwnerReadErrorV1) -> Outcome {
    (Err(error), Vec::new())
}

fn signing(owner: &'static str) -> (SigningKeyMaterial, KeyIdentityV1) {
    let (key, _) = generate_keypair();
    (
        SigningKeyMaterial::new(key),
        KeyIdentityV1::new(owner, KeyRoleV1::TimelineIntegritySigning, 1),
    )
}

/// An ordinary writable store holding the subject's committed data, before it
/// is closed and installed as an owner store.
struct Seed {
    store: SqliteStore,
    directory: tempfile::TempDir,
    timeline: TimelineId,
    owner: SigningKeyMaterial,
    owner_identity: KeyIdentityV1,
    keys: SubjectKeyringV1,
    nonces: VolatileSubjectNonceLedgerV1,
}

fn private_directory() -> TestResult<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?)
}

fn open_bound_store(directory: &tempfile::TempDir) -> TestResult<SqliteStore> {
    let path = directory.path().join(MAIN);
    let mut store = SqliteStore::open(path.to_str().ok_or("path")?)?;
    store.bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(
        GatewayModeProfileRefV1::try_new("owner-subject-field-read-test", [7; 32])?,
    ))?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(store)
}

fn subject_wrap() -> TestResult<SubjectKeyWrapV1> {
    Ok(SubjectKeyWrapV1::seal(
        SubjectKeyWrapParamsV1 {
            subject_id: SUBJECT,
            epoch: 1,
            rp_id: "localhost".to_owned(),
            credential_id: pattern::<16>(0x12).to_vec(),
            prf_input: pattern(0x13),
            wrap_salt: pattern(0x14),
            subkey_salt: pattern(0x15),
            wrap_nonce: pattern(0x16),
        },
        &SubjectRootKeyV1::from_bytes(pattern(0x10)),
        &SubjectPrfOutputV1::from_bytes(pattern(0x11)),
    )?)
}

fn root_digest() -> Hash {
    SubjectRootKeyV1::from_bytes(pattern(0x10)).material_digest()
}

fn register_signing(
    registry: &mut KeyRegistryStateV1,
    identity: KeyIdentityV1,
    material: &SigningKeyMaterial,
) -> TestResult {
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    Ok(())
}

fn register_encryption(registry: &mut KeyRegistryStateV1) -> TestResult {
    let encryption = KeyIdentityV1::new(
        OwnerIdV1::new(subject_owner_id(SUBJECT)?)?,
        KeyRoleV1::SubjectDataEncryption,
        1,
    );
    registry.register_key(KeyRegistrationV1::new(encryption, root_digest(), None))?;
    Ok(())
}

fn unlocked_keyring(identity: KeyIdentityV1, public: PublicKey) -> TestResult<SubjectKeyringV1> {
    let mut keys = SubjectKeyringV1::new(SUBJECT, identity, public)?;
    keys.unlock(
        subject_wrap()?,
        &SubjectPrfOutputV1::from_bytes(pattern(0x11)),
    )?;
    Ok(keys)
}

fn nonce_ledger() -> TestResult<VolatileSubjectNonceLedgerV1> {
    Ok(VolatileSubjectNonceLedgerV1::new(
        SubjectNonceLedgerV1::new([SubjectNonceLedgerRowV1 {
            owner_id: subject_owner_id(SUBJECT)?,
            epoch: 1,
            root_material_digest: *root_digest().as_bytes(),
            store_file_id: SubjectStoreFileIdV1::Linux {
                device: 0,
                inode: 0,
            },
            data_next: 1,
            bootstrap_next: 1,
        }])?,
    ))
}

fn seed() -> TestResult<Seed> {
    let directory = private_directory()?;
    let mut store = open_bound_store(&directory)?;
    let (owner, owner_identity) = signing("piglor-owner");
    let (gateway, gateway_identity) = signing("timeline-owner");
    let mut registry = KeyRegistryStateV1::new();
    register_signing(&mut registry, owner_identity, &owner)?;
    register_signing(&mut registry, gateway_identity, &gateway)?;
    register_encryption(&mut registry)?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("subject-data")?.id();
    let keys = unlocked_keyring(owner_identity, owner.public_verification_key())?;
    Ok(Seed {
        store,
        directory,
        timeline,
        owner,
        owner_identity,
        keys,
        nonces: nonce_ledger()?,
    })
}

/// Create the lookup index on a raw connection and make the file owner-only.
fn index_and_restrict(path: &std::path::Path) -> TestResult {
    Connection::open(path)?.execute_batch(EVENTS_INDEX_SQL)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn file_identity(path: &std::path::Path) -> TestResult<SubjectStoreFileIdV1> {
    let metadata = std::fs::metadata(path)?;
    Ok(SubjectStoreFileIdV1::Linux {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

impl Seed {
    fn append(&mut self, timeline: TimelineId, name: &str) -> Result<Event, Refusal> {
        append_subject_preference_weights(
            &mut self.store,
            &mut self.keys,
            &mut self.nonces,
            &SubjectDataAppendV1 {
                timeline_id: timeline,
                epoch: 1,
                signing: &self.owner,
                weights: &weight_set(name),
            },
        )
    }

    /// A clear Event that is not the subject's field value: another type of
    /// this subject, and another subject's Event of any type.
    fn append_noise(&mut self, timeline: TimelineId) -> TestResult {
        self.store.append(
            timeline,
            &[
                EventDraft::new(
                    SUBJECT,
                    Kind::new("timeline.note.v1"),
                    CanonicalBytes::from_static(b"clear note"),
                ),
                EventDraft::new(
                    OTHER,
                    Kind::new("timeline.note.v1"),
                    CanonicalBytes::from_static(b"another subject"),
                ),
            ],
        )?;
        Ok(())
    }

    /// Another subject's `subject.data.v1` Event, newer than everything so far.
    fn append_other_subject_data(&mut self, timeline: TimelineId) -> TestResult {
        self.store.append(
            timeline,
            &[EventDraft::new(
                OTHER,
                Kind::new(SUBJECT_DATA_EVENT_TYPE),
                CanonicalBytes::from_static(b"another subject's data"),
            )],
        )?;
        Ok(())
    }

    /// Replace the committed registry with `change` applied to it.
    fn change_registry(
        &mut self,
        change: impl FnOnce(&mut KeyRegistryStateV1) -> Result<(), KeyRegistryErrorV1>,
    ) -> TestResult {
        let mut registry = self.store.load_key_registry()?.ok_or("registry")?;
        change(&mut registry)?;
        self.store.save_key_registry(&registry)?;
        Ok(())
    }

    fn fork(&mut self, parent: TimelineId, at: u64, name: &str) -> TestResult<TimelineId> {
        Ok(self.store.fork(parent, Seq::from_u64(at), name)?.id())
    }

    /// Close the ordinary store, create the lookup index on a raw connection and install the namespace.
    fn install(self) -> TestResult<World> {
        let Self {
            store,
            directory,
            timeline,
            keys,
            owner_identity,
            owner,
            ..
        } = self;
        drop(store);
        let path = directory.path().join(MAIN);
        index_and_restrict(&path)?;
        install_owner_store_namespace_v1(directory.path(), MAIN)?;
        Ok(World {
            key: file_identity(&path)?,
            directory,
            context: Arc::new(OwnerStoreContextV1::default()),
            timeline,
            keys,
            owner_identity,
            owner_public: owner.public_verification_key(),
        })
    }
}

/// An installed owner store: closed on disk, ready to be qualified.
struct World {
    directory: tempfile::TempDir,
    key: SubjectStoreFileIdV1,
    context: Arc<OwnerStoreContextV1>,
    timeline: TimelineId,
    keys: SubjectKeyringV1,
    owner_identity: KeyIdentityV1,
    owner_public: PublicKey,
}

impl Drop for World {
    /// Close every connection a test retained or quarantined, after its
    /// assertions, and forget the claim so a reused inode is not seen as claimed.
    fn drop(&mut self) {
        crate::sqlite::owner_store_binding::retained::reclaim();
        if let SubjectStoreFileIdV1::Linux { device, inode } = self.key {
            release_identity([device, inode]);
        }
    }
}

impl World {
    fn open(&self) -> TestResult<QualifiedSqliteStoreV1> {
        Ok(QualifiedSqliteStoreV1::open(
            Arc::clone(&self.context),
            self.directory.path(),
            MAIN,
            self.key,
        )?)
    }

    fn locked_keys(&self) -> TestResult<SubjectKeyringV1> {
        Ok(SubjectKeyringV1::new(
            SUBJECT,
            self.owner_identity,
            self.owner_public,
        )?)
    }

    fn read(&self, store: &mut QualifiedSqliteStoreV1, timeline: TimelineId) -> Outcome {
        read_as(store, &self.keys, timeline, SUBJECT)
    }
}

/// Change the store through its own guarded transaction and commit.
///
/// A second connection that writes the file moves the WAL companion's native
/// witness, so the next guarded operation would quarantine (ADR-123 §6).
fn exec(store: &mut QualifiedSqliteStoreV1, sql: &str) -> TestResult {
    store.guarded(|binding| binding.store().conn.execute_batch(sql))??;
    Ok(())
}

/// Insert one ADR-097 B6 fence row for `timeline`.
fn fence(store: &mut QualifiedSqliteStoreV1, timeline: TimelineId, lifecycle: i64) -> TestResult {
    exec(
        store,
        &format!(
            "INSERT INTO erasure_fence_rows (timeline_id, erasure_request_id, lifecycle_code)
             VALUES ('{timeline}', x'{}', {lifecycle})",
            "09".repeat(32)
        ),
    )
}

fn read_as(
    store: &mut QualifiedSqliteStoreV1,
    keys: &SubjectKeyringV1,
    timeline: TimelineId,
    subject: EntityId,
) -> Outcome {
    let mut delivered = Vec::new();
    let outcome = OwnerSubjectFieldReaderV1::new(store, keys).with_subject_field_read(
        timeline,
        subject,
        SubjectFieldSelectorV1::PersonaPreferenceWeights,
        &mut |result| {
            delivered.push(result);
            Ok(())
        },
    );
    (outcome, delivered)
}

fn closed(store: QualifiedSqliteStoreV1) -> TestResult {
    store.close().map_err(|error| format!("{error:?}").into())
}

/// Run `action` with the transaction-ending seam set.
fn with_early_end<T>(action: impl FnOnce() -> T) -> T {
    END_TRANSACTION_EARLY.with(|flag| flag.set(true));
    let result = action();
    END_TRANSACTION_EARLY.with(|flag| flag.set(false));
    result
}

#[test]
fn delivers_the_latest_value_once_and_leaves_the_store_idle() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    seed.append_noise(timeline)?;
    seed.append(timeline, "second")?;
    seed.append_noise(timeline)?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(world.read(&mut store, world.timeline), present("second"));
    assert_eq!(world.read(&mut store, world.timeline), present("second"));
    closed(store)
}

#[test]
fn another_subject_or_no_value_or_a_locked_key_delivers_its_own_outcome() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append_noise(timeline)?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(
        world.read(&mut store, world.timeline),
        field(Err(SubjectFieldReadError::NoValue))
    );
    closed(store)?;

    let mut seed = self::seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(
        read_as(&mut store, &world.keys, world.timeline, OTHER),
        field(Err(SubjectFieldReadError::Integrity))
    );
    assert_eq!(
        read_as(&mut store, &world.locked_keys()?, world.timeline, SUBJECT),
        field(Err(SubjectFieldReadError::KeyUnavailable))
    );
    closed(store)
}

#[test]
fn the_latest_value_follows_the_stitched_fork_chain() -> TestResult {
    let mut seed = seed()?;
    let parent = seed.timeline;
    seed.append(parent, "first")?;
    let child = seed.fork(parent, 1, "child")?;
    let sibling = seed.fork(parent, 1, "sibling")?;
    seed.append_noise(child)?;
    seed.append(child, "second")?;
    let grandchild = seed.fork(child, 4, "grandchild")?;
    seed.append(parent, "third")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(world.read(&mut store, parent), present("third"));
    assert_eq!(world.read(&mut store, child), present("second"));
    assert_eq!(world.read(&mut store, grandchild), present("second"));
    assert_eq!(world.read(&mut store, sibling), present("first"));

    // Only the exact Timeline is fenced: no Fork ancestor or descendant is.
    fence(&mut store, parent, 2)?;
    assert_eq!(
        world.read(&mut store, parent),
        refused(SubjectFieldOwnerReadErrorV1::ErasureFenced)
    );
    assert_eq!(world.read(&mut store, child), present("second"));
    assert_eq!(world.read(&mut store, grandchild), present("second"));
    closed(store)
}

#[test]
fn an_exact_timeline_fence_row_refuses_before_any_delivery() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    let fenced = refused(SubjectFieldOwnerReadErrorV1::ErasureFenced);

    fence(&mut store, TimelineId::new(), 3)?;
    assert_eq!(world.read(&mut store, world.timeline), present("first"));

    fence(&mut store, world.timeline, 2)?;
    assert_eq!(world.read(&mut store, world.timeline), fenced);
    exec(&mut store, "DELETE FROM erasure_fence_rows")?;
    assert_eq!(world.read(&mut store, world.timeline), present("first"));

    // A row the check cannot parse still refuses.
    exec(&mut store, "PRAGMA ignore_check_constraints = ON")?;
    fence(&mut store, world.timeline, 9)?;
    assert_eq!(world.read(&mut store, world.timeline), fenced);
    exec(&mut store, "DELETE FROM erasure_fence_rows")?;

    // An unreadable table refuses too.
    exec(&mut store, "DROP TABLE erasure_fence_rows")?;
    assert_eq!(world.read(&mut store, world.timeline), fenced);
    closed(store)
}

#[test]
fn a_callback_failure_or_panic_finishes_the_transaction_and_keeps_the_store_usable() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    let mut calls = 0;
    let failed = OwnerSubjectFieldReaderV1::new(&mut store, &world.keys).with_subject_field_read(
        world.timeline,
        SUBJECT,
        SubjectFieldSelectorV1::PersonaPreferenceWeights,
        &mut |_| {
            calls += 1;
            Err(SubjectFieldReadCallbackErrorV1::Failed)
        },
    );
    assert_eq!(
        (failed, calls),
        (Err(SubjectFieldOwnerReadErrorV1::CallbackFailed), 1)
    );

    let mut port = OwnerSubjectFieldReaderV1::new(&mut store, &world.keys);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        port.with_subject_field_read(
            world.timeline,
            SUBJECT,
            SubjectFieldSelectorV1::PersonaPreferenceWeights,
            &mut |_| std::panic::resume_unwind(Box::new("callback unwind")),
        )
    }));
    assert_eq!(
        unwound
            .err()
            .and_then(|payload| payload.downcast_ref::<&str>().copied()),
        Some("callback unwind")
    );
    assert_eq!(world.read(&mut store, world.timeline), present("first"));
    closed(store)
}

#[test]
fn shared_admission_and_a_busy_interlock_refuse_before_any_delivery() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;

    let active = world
        .context
        .admission()
        .try_enter()
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        world.read(&mut store, world.timeline),
        refused(SubjectFieldOwnerReadErrorV1::OperationActive)
    );
    active.complete_cleanly();

    let other = OwnerStoreAdmissionV1::new();
    let operation = other.try_enter().map_err(|error| format!("{error:?}"))?;
    let interlock =
        OwnerStoreFileInterlockV1::try_acquire(&operation, world.directory.path(), MAIN)?;
    assert_eq!(
        world.read(&mut store, world.timeline),
        refused(SubjectFieldOwnerReadErrorV1::ReadUnavailableBeforeDelivery)
    );
    drop(interlock);
    operation.complete_cleanly();
    assert_eq!(world.read(&mut store, world.timeline), present("first"));

    drop(
        world
            .context
            .admission()
            .try_enter()
            .map_err(|error| format!("{error:?}"))?,
    );
    assert_eq!(
        world.read(&mut store, world.timeline),
        refused(SubjectFieldOwnerReadErrorV1::ContextQuarantined)
    );
    Ok(())
}

#[test]
fn a_missing_index_or_timeline_refuses_as_unavailable_and_never_scans() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    let unavailable = refused(SubjectFieldOwnerReadErrorV1::ReadUnavailableBeforeDelivery);

    assert_eq!(world.read(&mut store, TimelineId::new()), unavailable);
    exec(&mut store, "DROP INDEX idx_events_entity_type")?;
    assert_eq!(world.read(&mut store, world.timeline), unavailable);
    exec(&mut store, EVENTS_INDEX_SQL)?;
    assert_eq!(world.read(&mut store, world.timeline), present("first"));
    closed(store)
}

#[test]
fn an_unproved_rollback_quarantines_with_the_classification_of_how_the_read_ended() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(
        with_early_end(|| world.read(&mut store, world.timeline)),
        (
            Err(SubjectFieldOwnerReadErrorV1::TransactionFinishFailedAfterDelivery),
            vec![Ok(FieldStateV1::Present(CanonicalBytes::from_vec(
                weight_set("first")
            )))]
        )
    );
    assert_eq!(
        world.read(&mut store, world.timeline),
        refused(SubjectFieldOwnerReadErrorV1::ContextQuarantined)
    );

    let mut seed = self::seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    fence(&mut store, world.timeline, 2)?;
    assert_eq!(
        with_early_end(|| world.read(&mut store, world.timeline)),
        refused(SubjectFieldOwnerReadErrorV1::ErasureFencedTransactionFinishFailed)
    );

    let mut seed = self::seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    exec(&mut store, "DROP INDEX idx_events_entity_type")?;
    assert_eq!(
        with_early_end(|| world.read(&mut store, world.timeline)),
        refused(SubjectFieldOwnerReadErrorV1::TransactionFinishFailedBeforeDelivery)
    );
    Ok(())
}

/// The destruction request of the subject's encryption key.
fn destruction_request() -> TestResult<KeyDestructionRequestV1> {
    Ok(KeyDestructionRequestV1::new(
        KeyIdentityV1::new(
            OwnerIdV1::new(subject_owner_id(SUBJECT)?)?,
            KeyRoleV1::SubjectDataEncryption,
            1,
        ),
        SubjectRootKeyV1::from_bytes(pattern(0x10)).material_digest(),
        Hash::from_bytes([0x44; 32]),
    ))
}

#[test]
fn a_registry_that_denies_decryption_wins_over_an_unlocked_keyring() -> TestResult {
    // Pending destruction: the keyring still holds the root, the registry
    // refuses, and no plaintext reaches the callback.
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let request = destruction_request()?;
    seed.change_registry(|registry| registry.begin_key_destruction(request).map(|_| ()))?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(
        world.read(&mut store, world.timeline),
        field(Err(SubjectFieldReadError::KeyUnavailable))
    );
    closed(store)?;

    // Committed destruction: the value reads as redacted, never as plaintext.
    let mut seed = self::seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    // A replacement may only finish a destruction that is already durably
    // pending, so the two steps are two commits.
    seed.change_registry(|registry| registry.begin_key_destruction(request).map(|_| ()))?;
    seed.change_registry(|registry| {
        registry
            .complete_key_destruction(request, deletion_receipt(&request))
            .map(|_| ())
    })?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(
        world.read(&mut store, world.timeline),
        field(Ok(FieldStateV1::RedactedDestroyed))
    );
    closed(store)?;

    // No registry at all: nothing verifies, so the outcome is `Integrity`.
    let mut seed = self::seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    exec(&mut store, "DELETE FROM key_registry")?;
    assert_eq!(
        world.read(&mut store, world.timeline),
        field(Err(SubjectFieldReadError::Integrity))
    );
    closed(store)
}

#[test]
fn another_subjects_data_event_never_answers_this_subjects_read() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    seed.append_other_subject_data(timeline)?;
    let world = seed.install()?;
    let mut store = world.open()?;
    assert_eq!(world.read(&mut store, world.timeline), present("first"));
    assert_eq!(
        read_as(&mut store, &world.keys, world.timeline, OTHER),
        field(Err(SubjectFieldReadError::Integrity))
    );
    closed(store)
}

#[test]
fn a_failing_callback_with_an_unproved_rollback_is_a_finish_failure_after_delivery() -> TestResult {
    let mut seed = seed()?;
    let timeline = seed.timeline;
    seed.append(timeline, "first")?;
    let world = seed.install()?;
    let mut store = world.open()?;
    let mut calls = 0;
    let outcome = with_early_end(|| {
        OwnerSubjectFieldReaderV1::new(&mut store, &world.keys).with_subject_field_read(
            world.timeline,
            SUBJECT,
            SubjectFieldSelectorV1::PersonaPreferenceWeights,
            &mut |_| {
                calls += 1;
                Err(SubjectFieldReadCallbackErrorV1::Failed)
            },
        )
    });
    assert_eq!(
        (outcome, calls),
        (
            Err(SubjectFieldOwnerReadErrorV1::TransactionFinishFailedAfterDelivery),
            1
        )
    );
    Ok(())
}

#[test]
fn a_connection_without_a_write_transaction_is_unavailable_not_fenced() -> TestResult {
    let seed = seed()?;
    let mut calls = 0;
    let end = read_in_transaction(
        &seed.store,
        &seed.keys,
        (seed.timeline, SUBJECT),
        SubjectFieldSelectorV1::PersonaPreferenceWeights,
        &mut |_| {
            calls += 1;
            Ok(())
        },
    );
    assert!(matches!(end, Ok(ReadEndV1::Unavailable)));
    assert_eq!(calls, 0);
    Ok(())
}
