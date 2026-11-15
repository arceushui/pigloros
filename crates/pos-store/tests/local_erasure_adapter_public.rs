//! ADR-136 §2.5 and §4a adapter methods, with `MemoryStore`/`SQLite` parity
//! (acceptance test 3a and the retain, owner-effect and sweep contracts).

use std::sync::Arc;

use pos_core::{
    deletion_receipt, ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1,
    ErasureContainmentGateV1, ErasureErrorV1, ErasureInventoryPersistencePortV1,
    ErasurePersistencePortV1, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureRetainedObjectV1,
    EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, LocalOwnerEffectV1, Seq, TimelineId, TimelineMeta, TimelineMode,
    ERASURE_RETAINED_OBJECT_MAX_BYTES_V1,
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
fn record(tag: &str, value: u8) -> Vec<u8> {
    let mut bytes = vec![0x83, 0x60 | u8::try_from(tag.len()).unwrap_or(0)];
    bytes.extend_from_slice(tag.as_bytes());
    bytes.push(0x01);
    if value < 24 {
        bytes.push(value);
    } else {
        bytes.extend_from_slice(&[0x18, value]);
    }
    bytes
}

fn address(bytes: &[u8]) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    ErasureRetainedObjectV1::new(bytes, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)
        .map(|object| object.reference())
}

fn limits() -> Result<ErasureRecoveryLimitsV1, ErasureErrorV1> {
    ErasureRecoveryLimitsV1::from_maximum_requests(16)
}

fn timeline_id(byte: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([byte; 16]))
}

fn owner() -> pos_core::EntityId {
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
    let els1 = record("ELS1", 1);
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
    retain_contract(&mut pos_store::sqlite::SqliteStore::open(path)?)
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

fn owner_effect_contract(store: &mut impl LocalErasureStore) -> TestResult {
    seed_pending_destruction(store)?;
    for (effect, tag) in [
        (
            LocalOwnerEffectV1::ArtifactDisposition(record("ELAD1", 1)),
            "ELAD1",
        ),
        (
            LocalOwnerEffectV1::CacheGeneration(record("ELCG1", 1)),
            "ELCG1",
        ),
        (LocalOwnerEffectV1::Negative(record("ELNEG1", 1)), "ELNEG1"),
    ] {
        let elo1 = record("ELO1", tag.as_bytes()[3]);
        assert_eq!(
            store.commit_local_owner_effect(effect, &elo1)?,
            address(&elo1)?
        );
        assert_eq!(store.read_object(address(&elo1)?)?, elo1);
        assert_eq!(
            store.read_object(address(&record(tag, 1))?)?,
            record(tag, 1)
        );
    }

    // A record effect under the wrong tag, or a non-ELO1 owner result,
    // commits nothing.
    let refused = record("ELO1", 100);
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::ArtifactDisposition(record("ELCG1", 2)),
            &refused
        ),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        store.commit_local_owner_effect(
            LocalOwnerEffectV1::Negative(record("ELNEG1", 2)),
            &record("ELS1", 2)
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
    let elo1 = record("ELO1", 200);
    assert_eq!(
        store.commit_local_owner_effect(tombstone.clone(), &elo1)?,
        address(&elo1)?
    );
    let registry = store.load_key_registry()?.ok_or("missing registry")?;
    assert!(registry.tombstone(key_identity()).is_some());
    assert_eq!(store.read_object(address(&elo1)?)?, elo1);

    // Repeating the committed tombstone is idempotent: a positive result
    // bound to the existing effect.
    let repeated = record("ELO1", 201);
    assert_eq!(
        store.commit_local_owner_effect(tombstone, &repeated)?,
        address(&repeated)?
    );

    // A tombstone the registry refuses commits no ELO1.
    let refused_tombstone = LocalOwnerEffectV1::KeyTombstone {
        request: Box::new(key_request()),
        deletion_receipt: Hash::from_bytes([3; 32]),
    };
    let late = record("ELO1", 202);
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
    owner_effect_contract(&mut pos_store::sqlite::SqliteStore::open(path)?)
}

fn sweep_contract(store: &mut impl LocalErasureStore) -> TestResult {
    let kept = store.retain_erasure_object(&record("ELS1", 1), 1_024)?;
    let swept = [
        store.retain_erasure_object(&record("ELS1", 2), 1_024)?,
        store.retain_erasure_object(&record("ELS1", 3), 1_024)?,
        store.retain_erasure_object(&record("ELS1", 4), 1_024)?,
    ];
    let other_tag = store.retain_erasure_object(&record("ELO1", 1), 1_024)?;
    let mut ordered = swept;
    ordered.sort_unstable();

    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ELS1"], &[kept], 2)?,
        2
    );
    assert_eq!(
        store.read_object(ordered[0]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.read_object(ordered[1]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.read_object(ordered[2])?,
        record_for(&swept, ordered[2])
    );
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ELS1"], &[kept], 16)?,
        1
    );
    assert_eq!(
        store.sweep_unreferenced_erasure_objects(&["ELS1"], &[kept], 16)?,
        0
    );
    assert_eq!(store.read_object(kept)?, record("ELS1", 1));
    assert_eq!(store.read_object(other_tag)?, record("ELO1", 1));
    Ok(())
}

fn record_for(swept: &[ErasureReferenceV1; 3], reference: ErasureReferenceV1) -> Vec<u8> {
    let index = swept
        .iter()
        .position(|candidate| *candidate == reference)
        .unwrap_or(0);
    record("ELS1", u8::try_from(index).unwrap_or(0) + 2)
}

#[test]
fn sweep_deletes_only_unkept_retained_objects_of_the_named_tags() -> TestResult {
    sweep_contract(&mut MemoryStore::new())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("sweep.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    sweep_contract(&mut pos_store::sqlite::SqliteStore::open(path)?)
}

#[test]
fn retained_record_tags_follow_the_record_grammar() {
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
            ErasureRetainedObjectV1::new(&record(tag, 1), 1_024).is_ok(),
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
    let object = ErasureRetainedObjectV1::new(&record("ELS1", 1), 1_024);
    assert_eq!(
        object.as_ref().map(ErasureRetainedObjectV1::tag),
        Ok("ELS1")
    );
    assert_eq!(
        object.as_ref().map(ErasureRetainedObjectV1::canonical_cbor),
        Ok(record("ELS1", 1).as_slice())
    );
}
