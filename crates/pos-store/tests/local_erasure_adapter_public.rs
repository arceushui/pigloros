//! ADR-136 §2.5 and §4a adapter methods, with `MemoryStore`/`SQLite` parity
//! (acceptance test 3a and the retain, owner-effect and sweep contracts).

use std::sync::Arc;

use pos_core::{
    deletion_receipt, ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1,
    ErasureContainmentGateV1, ErasureErrorV1, ErasureInventoryPersistencePortV1,
    ErasurePersistencePortV1, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureRetainedObjectV1,
    EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, LocalErasureNegativeResultV1, LocalErasureOwnerResultV1,
    LocalOwnerEffectV1, Seq, TimelineId, TimelineMeta, TimelineMode,
    ERASURE_RETAINED_OBJECT_MAX_BYTES_V1, LOCAL_OWNER_EFFECT_MAX_BYTES_V1,
    LOCAL_OWNER_RESULT_MAX_BYTES_V1,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

trait LocalErasureStore:
    EventStore + ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1
{
}

impl<T> LocalErasureStore for T where
    T: EventStore + ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1
{
}

/// One canonical definite CBOR record `[tag, 1, value]`.
fn record(tag: &str, value: u8) -> Result<Vec<u8>, std::num::TryFromIntError> {
    u8::try_from(tag.len()).map(|length| {
        let mut bytes = vec![0x83, 0x60 | length];
        bytes.extend_from_slice(tag.as_bytes());
        bytes.push(0x01);
        if value < 24 {
            bytes.push(value);
        } else {
            bytes.extend_from_slice(&[0x18, value]);
        }
        bytes
    })
}

/// One canonical record `[tag, 1, bytes]` of exactly `total` bytes, padded
/// by a byte string of 256 to 65,535 bytes.
fn sized_record(tag: &str, total: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let header = 1 + 1 + tag.len() + 1 + 3;
    let padding = u16::try_from(total.checked_sub(header).ok_or("record too small")?)?;
    let mut bytes = vec![0x83, 0x60 | u8::try_from(tag.len())?];
    bytes.extend_from_slice(tag.as_bytes());
    bytes.push(0x01);
    bytes.push(0x59);
    bytes.extend_from_slice(&padding.to_be_bytes());
    bytes.resize(total, 0);
    Ok(bytes)
}

fn address(bytes: &[u8]) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    ErasureRetainedObjectV1::new(bytes, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)
        .map(|object| object.reference())
}

const fn limits() -> Result<ErasureRecoveryLimitsV1, ErasureErrorV1> {
    ErasureRecoveryLimitsV1::from_maximum_requests(16)
}

const fn timeline_id(byte: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([byte; 16]))
}

const fn owner() -> pos_core::EntityId {
    pos_core::EntityId::from_ulid(Ulid::from_bytes([9; 16]))
}

/// One unowned root, one owned root and an owned Fork of it, with fixed
/// identities so both adapters hold the same topology.
fn seed_topology(store: &mut impl LocalErasureStore) -> TestResult {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.create_timeline_with_meta(TimelineMeta {
        id: timeline_id(1),
        mode: TimelineMode::Live,
        name: Some("unowned".to_owned()),
        owner: None,
        fork_point: None,
    })?;
    store.create_timeline_with_meta(TimelineMeta {
        id: timeline_id(2),
        mode: TimelineMode::Live,
        name: Some("owned".to_owned()),
        owner: Some(owner()),
        fork_point: None,
    })?;
    store.create_timeline_with_meta(TimelineMeta {
        id: timeline_id(3),
        mode: TimelineMode::Live,
        name: Some("fork".to_owned()),
        owner: Some(owner()),
        fork_point: Some((timeline_id(2), Seq::ZERO)),
    })?;
    Ok(())
}

fn expected_rows() -> Vec<ErasureAuthorityTimelineRowV1> {
    vec![
        ErasureAuthorityTimelineRowV1 {
            id: timeline_id(1),
            owner: None,
            fork_point: None,
        },
        ErasureAuthorityTimelineRowV1 {
            id: timeline_id(2),
            owner: Some(owner()),
            fork_point: None,
        },
        ErasureAuthorityTimelineRowV1 {
            id: timeline_id(3),
            owner: Some(owner()),
            fork_point: Some((timeline_id(2), Seq::ZERO)),
        },
    ]
}

fn snapshot_and_identity(
    store: &mut impl LocalErasureStore,
) -> Result<ErasureAuthoritySnapshotV1, Box<dyn std::error::Error>> {
    seed_topology(store)?;
    let empty = store.erasure_authority_snapshot_with_limits(limits()?)?;
    assert_eq!(empty.store_identity(), None);
    assert_eq!(empty.timelines(), expected_rows().as_slice());
    assert_eq!(empty.timeline(timeline_id(3)), Some(&expected_rows()[2]));
    assert_eq!(empty.timeline(timeline_id(4)), None);
    assert_eq!(empty.inventory().topology().len(), 3);

    let identity = Hash::from_bytes([7; 32]);
    assert_eq!(store.erasure_store_identity()?, None);
    assert_eq!(store.init_erasure_store_identity(identity)?, identity);
    assert_eq!(store.init_erasure_store_identity(identity)?, identity);
    assert_eq!(
        store.init_erasure_store_identity(Hash::from_bytes([8; 32])),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(store.erasure_store_identity()?, Some(identity));
    let snapshot = store.erasure_authority_snapshot_with_limits(limits()?)?;
    assert_eq!(snapshot.store_identity(), Some(identity));
    Ok(snapshot)
}

#[test]
fn authority_snapshot_and_store_identity_have_adapter_parity() -> TestResult {
    let memory = snapshot_and_identity(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority-snapshot.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let sqlite = snapshot_and_identity(&mut pos_store::sqlite::SqliteStore::open(path)?)?;
    assert_eq!(memory, sqlite);

    // The identity row is durable and stays write-once after a reopen.
    let mut reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.erasure_store_identity()?,
        Some(Hash::from_bytes([7; 32]))
    );
    assert_eq!(
        reopened.init_erasure_store_identity(Hash::from_bytes([8; 32])),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        reopened.erasure_authority_snapshot_with_limits(limits()?)?,
        sqlite
    );
    Ok(())
}

#[test]
fn snapshot_rows_must_name_exactly_the_topology() -> TestResult {
    let mut store = MemoryStore::new();
    seed_topology(&mut store)?;
    let inventory = store.erasure_authority_snapshot_with_limits(limits()?)?;
    let mut missing = expected_rows();
    missing.pop();
    assert_eq!(
        ErasureAuthoritySnapshotV1::new(inventory.inventory().clone(), missing, None),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut reordered = expected_rows();
    reordered.swap(0, 1);
    assert_eq!(
        ErasureAuthoritySnapshotV1::new(inventory.inventory().clone(), reordered, None),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn sqlite_snapshot_refuses_a_malformed_owner_row() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("malformed-owner.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    seed_topology(&mut store)?;
    rusqlite::Connection::open(path)?.execute(
        "UPDATE timeline_owners SET owner_id = 'not-a-ulid' WHERE timeline_id = ?1",
        [timeline_id(2).to_string()],
    )?;
    assert_eq!(
        store.erasure_authority_snapshot_with_limits(limits()?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn retain_contract(store: &mut impl LocalErasureStore) -> TestResult {
    let els1 = record("ELS1", 1)?;
    let reference = store.retain_erasure_object(&els1, 1_024)?;
    assert_eq!(reference, address(&els1)?);
    assert_eq!(store.retain_erasure_object(&els1, 1_024)?, reference);
    assert_eq!(store.read_object(reference)?, els1);
    assert_eq!(
        store.retain_erasure_object(&els1, els1.len() - 1),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        store.retain_erasure_object(&[0x82, 0x01, 0x02], 1_024),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn retained_objects_are_idempotent_and_bounded_on_both_adapters() -> TestResult {
    retain_contract(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retain.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    retain_contract(&mut store)
}

fn key_identity() -> KeyIdentityV1 {
    KeyIdentityV1::new(
        "local-erasure-test",
        KeyRoleV1::CommunityArtifactEncryption,
        1,
    )
}

fn key_request() -> KeyDestructionRequestV1 {
    KeyDestructionRequestV1::new(
        key_identity(),
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
    )
}

fn seed_pending_destruction(store: &mut impl LocalErasureStore) -> TestResult {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        key_identity(),
        Hash::from_bytes([1; 32]),
        None,
    ))?;
    store.save_key_registry(&registry)?;
    store.begin_key_registry_destruction(key_request())?;
    Ok(())
}

/// Each owner record has its own ADR-136 size bound: exactly the bound is
/// admitted and one byte over is refused. An ELNEG1 commits only as a
/// canonical record bound by its ELO1, so its own decoder bounds it.
fn owner_effect_bounds(store: &mut impl LocalErasureStore) -> TestResult {
    for (tag, bound, seed) in [
        ("ELAD1", LOCAL_OWNER_EFFECT_MAX_BYTES_V1, 30),
        ("ELCG1", LOCAL_OWNER_EFFECT_MAX_BYTES_V1, 31),
        ("ELRP1", LOCAL_OWNER_EFFECT_MAX_BYTES_V1, 33),
    ] {
        let effect = |bytes: Vec<u8>| match tag {
            "ELAD1" => LocalOwnerEffectV1::ArtifactDisposition(bytes),
            "ELCG1" => LocalOwnerEffectV1::CacheGeneration(bytes),
            _ => LocalOwnerEffectV1::ReplicaPurge(bytes),
        };
        let at_bound = sized_record(tag, bound)?;
        assert_eq!(at_bound.len(), bound);
        let elo1 = record("ELO1", seed)?;
        assert_eq!(
            store.commit_local_owner_effect(effect(at_bound), &elo1)?,
            address(&elo1)?
        );
        assert_eq!(
            store.commit_local_owner_effect(
                effect(sized_record(tag, bound + 1)?),
                &record("ELO1", seed + 10)?
            ),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    let at_bound = sized_record("ELO1", LOCAL_OWNER_RESULT_MAX_BYTES_V1)?;
    assert_eq!(at_bound.len(), LOCAL_OWNER_RESULT_MAX_BYTES_V1);
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", 40)?),
            &at_bound
        )?,
        address(&at_bound)?
    );
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", 41)?),
            &sized_record("ELO1", LOCAL_OWNER_RESULT_MAX_BYTES_V1 + 1)?
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

fn owner_effect_contract(store: &mut impl LocalErasureStore) -> TestResult {
    seed_pending_destruction(store)?;
    for (effect, tag, seed) in [
        (
            LocalOwnerEffectV1::ArtifactDisposition(record("ELAD1", 1)?),
            "ELAD1",
            10,
        ),
        (
            LocalOwnerEffectV1::CacheGeneration(record("ELCG1", 1)?),
            "ELCG1",
            11,
        ),
        (
            LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", 1)?),
            "ELRP1",
            13,
        ),
    ] {
        let elo1 = record("ELO1", seed)?;
        assert_eq!(
            store.commit_local_owner_effect(effect, &elo1)?,
            address(&elo1)?
        );
        assert_eq!(store.read_object(address(&elo1)?)?, elo1);
        assert_eq!(
            store.read_object(address(&record(tag, 1)?)?)?,
            record(tag, 1)?
        );
    }

    // A negative effect commits with the ELO1 carrying its closed error code.
    let negative = LocalErasureNegativeResultV1 {
        command: ErasureReferenceV1::from_digest([12; 32]),
        owner_ref: ErasureReferenceV1::from_digest([13; 32]),
        error: ErasureErrorV1::ArtifactDeletionFailed,
    };
    let elneg1 = negative.to_canonical_cbor()?;
    let negative_elo1 = LocalErasureOwnerResultV1 {
        request: ErasureReferenceV1::from_digest([14; 32]),
        attempt: ErasureReferenceV1::from_digest([15; 32]),
        obligation: ErasureReferenceV1::from_digest([16; 32]),
        command: negative.command,
        owner_ref: negative.owner_ref,
        error: Some(negative.error),
        effect_digest: negative.reference()?,
    }
    .to_canonical_cbor()?;
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::Negative(elneg1.clone()),
            &negative_elo1
        )?,
        address(&negative_elo1)?
    );
    assert_eq!(store.read_object(address(&negative_elo1)?)?, negative_elo1);
    assert_eq!(store.read_object(address(&elneg1)?)?, elneg1);

    owner_effect_bounds(store)?;

    // A record effect under the wrong tag, or a non-ELO1 owner result,
    // commits nothing.
    let refused = record("ELO1", 100)?;
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::ArtifactDisposition(record("ELCG1", 2)?),
            &refused
        ),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", 2)?),
            &record("ELS1", 2)?
        ),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::ReplicaPurge(record("ELNEG1", 3)?),
            &refused
        ),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        store.read_object(address(&refused)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    // The tombstone and its ELO1 commit together.
    let tombstone = LocalOwnerEffectV1::KeyTombstone {
        request: Box::new(key_request()),
        deletion_receipt: deletion_receipt(&key_request()),
    };
    let elo1 = record("ELO1", 200)?;
    assert_eq!(
        store.commit_local_owner_effect(tombstone.clone(), &elo1)?,
        address(&elo1)?
    );
    let registry = store.load_key_registry()?.ok_or("missing registry")?;
    assert!(registry.tombstone(key_identity()).is_some());
    assert_eq!(store.read_object(address(&elo1)?)?, elo1);

    // Repeating the committed tombstone is idempotent: a positive result
    // bound to the existing effect.
    let repeated = record("ELO1", 201)?;
    assert_eq!(
        store.commit_local_owner_effect(tombstone, &repeated)?,
        address(&repeated)?
    );

    // A tombstone the registry refuses commits no ELO1.
    let refused_tombstone = LocalOwnerEffectV1::KeyTombstone {
        request: Box::new(key_request()),
        deletion_receipt: Hash::from_bytes([3; 32]),
    };
    let late = record("ELO1", 202)?;
    assert_eq!(
        store.commit_local_owner_effect(refused_tombstone, &late),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    assert_eq!(
        store.read_object(address(&late)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn owner_effects_commit_with_their_owner_result_on_both_adapters() -> TestResult {
    owner_effect_contract(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-effect.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    owner_effect_contract(&mut store)
}

fn sweep_contract(store: &mut impl LocalErasureStore) -> TestResult {
    let kept_bytes = record("ELS1", 1)?;
    let kept = store.retain_erasure_object(&kept_bytes, 1_024)?;
    let mut swept = std::collections::BTreeMap::new();
    for seed in 2..=4 {
        let bytes = record("ELS1", seed)?;
        swept.insert(store.retain_erasure_object(&bytes, 1_024)?, bytes);
    }
    let other_bytes = record("ELO1", 1)?;
    let other_tag = store.retain_erasure_object(&other_bytes, 1_024)?;

    // The sweep goes in increasing address order and stops at `max`.
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ELS1"], &[kept], 2)?,
        2
    );
    let mut remaining = swept.into_iter();
    for (reference, _) in remaining.by_ref().take(2) {
        assert_eq!(
            store.read_object(reference),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    for (reference, bytes) in remaining {
        assert_eq!(store.read_object(reference)?, bytes);
    }
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ELS1"], &[kept], 16)?,
        1
    );
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ELS1"], &[kept], 16)?,
        0
    );
    assert_eq!(store.sweep_unreferenced_erasure_objects(&[], &[], 16)?, 0);
    assert_eq!(store.read_object(kept)?, kept_bytes);
    assert_eq!(store.read_object(other_tag)?, other_bytes);
    Ok(())
}

#[test]
fn sweep_deletes_only_unkept_retained_objects_of_the_named_tags() -> TestResult {
    sweep_contract(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("sweep.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    sweep_contract(&mut store)
}

fn retained_read_contract(store: &mut impl LocalErasureStore) -> TestResult {
    assert!(store.retained_erasure_objects("TPS1", 0)?.is_empty());
    let mut expected = std::collections::BTreeMap::new();
    for seed in 1..=3 {
        let bytes = record("TPS1", seed)?;
        expected.insert(store.retain_erasure_object(&bytes, 1_024)?, bytes);
    }
    let other = record("ELB1", 1)?;
    store.retain_erasure_object(&other, 1_024)?;
    // Exactly `max` objects of the tag are read whole, in address order.
    assert_eq!(
        store.retained_erasure_objects("TPS1", 3)?,
        expected.into_values().collect::<Vec<_>>()
    );
    assert_eq!(store.retained_erasure_objects("ELB1", 1)?, vec![other]);
    // One object over `max` refuses the read instead of truncating it.
    assert_eq!(
        store.retained_erasure_objects("TPS1", 2),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert!(store.retained_erasure_objects("ELO1", 0)?.is_empty());
    Ok(())
}

#[test]
fn retained_objects_are_read_by_tag_and_bounded_on_both_adapters() -> TestResult {
    retained_read_contract(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retained.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    retained_read_contract(&mut store)
}

#[test]
fn a_retained_row_without_its_bytes_is_missing_provenance() -> TestResult {
    // MemoryStore changes the row and its bytes together, so only SQLite,
    // whose rows carry no foreign key, can lose the bytes under a row.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retained-orphan.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let bytes = record("TPS1", 1)?;
    let orphan = store.retain_erasure_object(&bytes, 1_024)?;
    assert_eq!(store.retained_erasure_objects("TPS1", 1)?, vec![bytes]);
    rusqlite::Connection::open(path)?.execute(
        "DELETE FROM erasure_evidence WHERE reference_digest = ?1",
        rusqlite::params![orphan.digest().as_slice()],
    )?;
    assert_eq!(
        store.retained_erasure_objects("TPS1", 1),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn retained_record_tags_follow_the_record_grammar() -> TestResult {
    for (tag, accepted) in [
        ("ELB1S", true),
        ("ELIDEM1", true),
        ("E", false),
        ("ELIDEMPO1", false),
        ("eLS1", false),
        ("1LS1", false),
        ("EL-1", false),
    ] {
        assert_eq!(
            ErasureRetainedObjectV1::new(&record(tag, 1)?, 1_024).is_ok(),
            accepted,
            "{tag}"
        );
    }
    let not_text = [0x81, 0x01];
    assert_eq!(
        ErasureRetainedObjectV1::new(&[0x01], 1_024),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureRetainedObjectV1::new(&not_text, 1_024),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let object = ErasureRetainedObjectV1::new(&record("ELS1", 1)?, 1_024);
    assert_eq!(
        object.as_ref().map(ErasureRetainedObjectV1::tag),
        Ok("ELS1")
    );
    assert_eq!(
        object.as_ref().map(ErasureRetainedObjectV1::canonical_cbor),
        Ok(record("ELS1", 1)?.as_slice())
    );
    Ok(())
}

fn rejoin_proof() -> Result<pos_core::ErasureRejoinProofV1, ErasureErrorV1> {
    let reference = |seed: u8| ErasureReferenceV1::from_digest([seed; 32]);
    pos_core::ErasureRejoinProofV1::new(pos_core::ErasureRejoinProofInputV1 {
        request: reference(1),
        terminal_receipt: reference(2),
        replica_set: reference(3),
        replica_id: reference(4),
        inventory_generation: reference(5),
        entries: Vec::new(),
        attestation: reference(6),
    })
}

/// The evidence path and the retain path address the same bytes
/// differently, and the sweep takes only what the retain path inserted.
///
/// `store_rejoin_proof` writes an ERRJ1 at `proof.reference()`, the ADR-060
/// V1 self-digest over the record's core array (the record without its own
/// digest field). `retain_erasure_object` addresses a record by its ADR-136
/// §4a content address, the domain-separated digest of the full canonical
/// bytes. Re-retaining the same ERRJ1 bytes therefore inserts a second,
/// distinct object, and only that copy is a sweep candidate.
fn evidence_object_survives_while_its_retained_copy_is_swept(
    store: &mut (impl LocalErasureStore + pos_store::ErasureRejoinPersistencePortV1),
) -> TestResult {
    let proof = rejoin_proof()?;
    store.store_rejoin_proof(&proof)?;
    let bytes = proof.to_canonical_cbor()?;
    // (a) The evidence-path object is not a sweep candidate. It is not in the
    // retained table at all; the "address already present, so not marked"
    // rule is covered through the coordinator CAS in
    // `erasure_persistence.rs` (committed ERAH1 pages).
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ERRJ1"], &[], 16)?,
        0
    );
    assert_eq!(store.read_object(proof.reference())?, bytes);
    // (b) The same bytes retained again get their content address.
    let copy = store.retain_erasure_object(&bytes, 1_024)?;
    assert_ne!(copy, proof.reference());
    // The content address, computed independently of the production
    // derivation: BLAKE3 over the tag, a zero byte and the full bytes.
    let content_address = [b"ERRJ1".as_slice(), &[0], &bytes].concat();
    assert_eq!(
        copy,
        ErasureReferenceV1::from_digest(*blake3::hash(&content_address).as_bytes())
    );
    // (c) The sweep removes exactly that copy and keeps the evidence object.
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ERRJ1"], &[], 16)?,
        1
    );
    assert_eq!(
        store.read_object(copy),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.read_object(proof.reference())?, bytes);
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ERRJ1"], &[], 16)?,
        0
    );
    Ok(())
}

#[test]
fn sweep_takes_only_the_retained_copy_of_an_evidence_object() -> TestResult {
    evidence_object_survives_while_its_retained_copy_is_swept(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("coordinator-object.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    evidence_object_survives_while_its_retained_copy_is_swept(&mut store)
}

fn unbound_registry_refuses(store: &mut impl LocalErasureStore) -> TestResult {
    let elo1 = record("ELO1", 1)?;
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::KeyTombstone {
                request: Box::new(key_request()),
                deletion_receipt: deletion_receipt(&key_request()),
            },
            &elo1
        ),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    assert_eq!(
        store.read_object(address(&elo1)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn a_tombstone_without_a_key_registry_fails_alike_on_both_adapters() -> TestResult {
    unbound_registry_refuses(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unbound-registry.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    unbound_registry_refuses(&mut store)
}

/// A write from another connection makes the installed inventory stale. The
/// authority snapshot does not rebind it, so the tombstone stays refused until
/// the inventory snapshot is installed again.
#[test]
fn sqlite_authority_snapshot_does_not_rebind_a_stale_inventory() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("stale-inventory.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    seed_pending_destruction(&mut store)?;
    store.complete_erasure_inventory_snapshot_with_limits(limits()?)?;

    let mut peer = pos_store::sqlite::SqliteStore::open(path)?;
    peer.retain_erasure_object(&record("ELS1", 1)?, 1_024)?;
    store.erasure_authority_snapshot_with_limits(limits()?)?;

    let tombstone = || LocalOwnerEffectV1::KeyTombstone {
        request: Box::new(key_request()),
        deletion_receipt: deletion_receipt(&key_request()),
    };
    let stale = record("ELO1", 1)?;
    assert_eq!(
        store.commit_local_owner_effect(tombstone(), &stale),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    assert_eq!(
        store.read_object(address(&stale)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    store.complete_erasure_inventory_snapshot_with_limits(limits()?)?;
    let current = record("ELO1", 2)?;
    assert_eq!(
        store.commit_local_owner_effect(tombstone(), &current)?,
        address(&current)?
    );
    Ok(())
}

/// A store that never published a recipient export answers every
/// publication read with the empty list, at any bound: `MemoryStore` has no
/// publication path and a fresh `SQLite` store has no publication catalog.
fn empty_publication_contract(store: &mut impl LocalErasureStore) -> TestResult {
    let timelines = [
        TimelineId::from_ulid(Ulid::from(7_u128)),
        TimelineId::from_ulid(Ulid::from(3_u128)),
    ];
    assert!(store
        .recipient_export_publications(&timelines, 0)?
        .is_empty());
    assert!(store.recipient_export_publications(&[], 4_096)?.is_empty());
    Ok(())
}

#[test]
fn recipient_export_publications_are_empty_without_a_publication() -> TestResult {
    empty_publication_contract(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("publications.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    empty_publication_contract(&mut store)
}

/// A key registry that fails to load refuses the tombstone like an absent
/// one, and the claim stays transactional: the ELO1 is not inserted. Once the
/// registry loads again the same tombstone commits, so the load error alone
/// flipped the outcome.
#[test]
fn sqlite_tombstone_with_an_unloadable_registry_inserts_no_owner_result() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unloadable-registry.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    seed_pending_destruction(&mut store)?;
    let peer = rusqlite::Connection::open(path)?;
    let saved: Vec<u8> = peer.query_row(
        "SELECT state_cbor FROM key_registry WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    peer.execute(
        "UPDATE key_registry SET state_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    store.complete_erasure_inventory_snapshot_with_limits(limits()?)?;

    let tombstone = || LocalOwnerEffectV1::KeyTombstone {
        request: Box::new(key_request()),
        deletion_receipt: deletion_receipt(&key_request()),
    };
    let refused = record("ELO1", 1)?;
    assert_eq!(
        store.commit_local_owner_effect(tombstone(), &refused),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    assert_eq!(
        store.read_object(address(&refused)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    peer.execute(
        "UPDATE key_registry SET state_cbor = ?1 WHERE singleton = 1",
        rusqlite::params![saved],
    )?;
    store.complete_erasure_inventory_snapshot_with_limits(limits()?)?;
    let committed = record("ELO1", 2)?;
    assert_eq!(
        store.commit_local_owner_effect(tombstone(), &committed)?,
        address(&committed)?
    );
    Ok(())
}
