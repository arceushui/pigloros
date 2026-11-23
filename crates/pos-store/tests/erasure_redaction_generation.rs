//! The store's redaction generation (ADR-136 follow-up F2, #1407) on
//! `MemoryStore` and `SqliteStore`: it starts at 0, rises by exactly one in
//! the transaction of each newly committed ELCG1 cache generation and for no
//! other owner effect, a failed commit changes neither the effect nor the
//! generation, and a `SQLite` generation survives a reopen. A generation the
//! adapter cannot read or raise, one above the JSON-safe
//! `REDACTION_GENERATION_MAX_V1` and a lost `SQLite` row beside a committed
//! ELCG1 fail closed.
#![cfg(feature = "sqlite")]

use pos_core::{
    deletion_receipt, ErasureErrorV1, ErasureInventoryPersistencePortV1, ErasurePersistencePortV1,
    ErasureReferenceV1, ErasureRetainedObjectV1, Hash, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRoleV1, LocalOwnerEffectV1, LocalOwnerResultBindingV1, PreparedLocalOwnerEffectV1,
    ERASURE_RETAINED_OBJECT_MAX_BYTES_V1, REDACTION_GENERATION_MAX_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

trait RedactionStore: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 {}

impl<T> RedactionStore for T where T: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 {}

/// One canonical definite CBOR record `[tag, 1, value]`.
fn record(tag: &str, value: u8) -> Vec<u8> {
    let mut bytes = vec![0x83, 0x65];
    bytes.extend_from_slice(tag.as_bytes());
    bytes.extend_from_slice(&[0x01, value]);
    bytes
}

/// The ELO1 binding of seed `seed`, positive.
fn binding(seed: u8) -> LocalOwnerResultBindingV1 {
    let at = |offset: u8| ErasureReferenceV1::from_digest([seed.wrapping_add(offset); 32]);
    LocalOwnerResultBindingV1 {
        request: at(0),
        attempt: at(1),
        obligation: at(2),
        command: at(3),
        owner_ref: at(4),
        error: None,
    }
}

fn address(bytes: &[u8]) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    ErasureRetainedObjectV1::new(bytes, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)
        .map(|object| object.reference())
}

/// Commit `effect` under the binding of `seed`.
fn commit(
    store: &mut dyn RedactionStore,
    effect: LocalOwnerEffectV1,
    seed: u8,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    PreparedLocalOwnerEffectV1::new(effect, binding(seed))
        .and_then(|prepared| store.commit_local_owner_effect(prepared))
}

/// The ELCG1 cache generation of `value`.
fn elcg1(value: u8) -> LocalOwnerEffectV1 {
    LocalOwnerEffectV1::CacheGeneration(record("ELCG1", value))
}

/// A key tombstone over a store without a key registry, which both adapters
/// refuse.
fn refused_tombstone() -> LocalOwnerEffectV1 {
    let request = KeyDestructionRequestV1::new(
        KeyIdentityV1::new("redaction-test", KeyRoleV1::CommunityArtifactEncryption, 1),
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
    );
    LocalOwnerEffectV1::KeyTombstone {
        request: Box::new(request),
        deletion_receipt: deletion_receipt(&request),
    }
}

/// The generation contract of one adapter.
fn generation_contract(store: &mut dyn RedactionStore) -> TestResult {
    assert_eq!(store.redaction_generation()?, 0);
    // Every other owner effect commits without raising it.
    for (effect, seed) in [
        (
            LocalOwnerEffectV1::ArtifactDisposition(record("ELAD1", 1)),
            10,
        ),
        (LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", 1)), 11),
    ] {
        commit(store, effect, seed)?;
        assert_eq!(store.redaction_generation()?, 0, "seed {seed}");
    }
    // Each new ELCG1 raises it by exactly one, with the ELCG1 committed.
    commit(store, elcg1(1), 20)?;
    assert_eq!(store.redaction_generation()?, 1);
    assert_eq!(
        store.read_object(address(&record("ELCG1", 1))?)?,
        record("ELCG1", 1)
    );
    // The same ELCG1 again, even bound by another ELO1, retains nothing new.
    commit(store, elcg1(1), 20)?;
    commit(store, elcg1(1), 21)?;
    assert_eq!(store.redaction_generation()?, 1);
    commit(store, elcg1(2), 22)?;
    assert_eq!(store.redaction_generation()?, 2);
    // A refused commit changes neither its ELO1 nor the generation.
    assert_eq!(
        commit(store, refused_tombstone(), 30),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    assert_eq!(store.redaction_generation()?, 2);
    Ok(())
}

fn sqlite_path(directory: &tempfile::TempDir, name: &str) -> Result<String, &'static str> {
    directory
        .path()
        .join(name)
        .to_str()
        .map(str::to_owned)
        .ok_or("temporary database path is not UTF-8")
}

#[test]
fn each_new_cache_generation_raises_it_once_on_both_adapters() -> TestResult {
    generation_contract(&mut MemoryStore::new())?;
    let directory = tempdir()?;
    let mut store = SqliteStore::open(&sqlite_path(&directory, "generation.sqlite3")?)?;
    generation_contract(&mut store)
}

#[test]
fn a_sqlite_generation_survives_a_reopen() -> TestResult {
    let directory = tempdir()?;
    let path = sqlite_path(&directory, "reopen.sqlite3")?;
    commit(&mut SqliteStore::open(&path)?, elcg1(1), 1)?;
    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(reopened.redaction_generation()?, 1);
    commit(&mut reopened, elcg1(2), 2)?;
    drop(reopened);
    assert_eq!(SqliteStore::open(&path)?.redaction_generation()?, 2);
    Ok(())
}

/// Overwrite the `SQLite` store at `path` with redaction generation
/// `generation`, as a raw row.
fn stored_generation(path: &str, generation: i64) -> TestResult {
    rusqlite::Connection::open(path)?.execute(
        "INSERT INTO erasure_redaction_generation (singleton, generation) VALUES (1, ?1)
         ON CONFLICT (singleton) DO UPDATE SET generation = excluded.generation",
        [generation],
    )?;
    Ok(())
}

/// A `SQLite` generation one below `REDACTION_GENERATION_MAX_V1`, the
/// JSON-safe bound of the Gateway contract, still rises to it; at the bound
/// it cannot be raised: the ELCG1 commit fails and rolls back, so neither
/// the ELCG1 nor its ELO1 is retained and the generation is unchanged, while
/// an effect that raises nothing still commits.
#[test]
fn a_sqlite_generation_that_cannot_be_raised_rolls_the_commit_back() -> TestResult {
    let directory = tempdir()?;
    let path = sqlite_path(&directory, "saturated.sqlite3")?;
    drop(SqliteStore::open(&path)?);
    let largest = REDACTION_GENERATION_MAX_V1;
    stored_generation(&path, i64::try_from(largest - 1)?)?;
    let mut store = SqliteStore::open(&path)?;
    commit(&mut store, elcg1(1), 1)?;
    assert_eq!(store.redaction_generation()?, largest);
    assert_eq!(
        commit(&mut store, elcg1(2), 2),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        store.read_object(address(&record("ELCG1", 2))?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.redaction_generation()?, largest);
    commit(
        &mut store,
        LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", 1)),
        3,
    )?;
    assert_eq!(store.redaction_generation()?, largest);
    Ok(())
}

/// A persisted `SQLite` generation above `REDACTION_GENERATION_MAX_V1`, up
/// to the largest `SQLite` integer, is one the Gateway contract cannot carry:
/// the read fails closed and an ELCG1 commit fails without retaining it.
#[test]
fn a_sqlite_generation_above_the_bound_fails_closed() -> TestResult {
    let directory = tempdir()?;
    let path = sqlite_path(&directory, "above.sqlite3")?;
    drop(SqliteStore::open(&path)?);
    for stored in [i64::try_from(REDACTION_GENERATION_MAX_V1 + 1)?, i64::MAX] {
        stored_generation(&path, stored)?;
        let mut store = SqliteStore::open(&path)?;
        assert_eq!(
            store.redaction_generation(),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        assert_eq!(
            commit(&mut store, elcg1(1), 1),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        assert_eq!(
            store.read_object(address(&record("ELCG1", 1))?),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}

/// A `SQLite` store that lost its generation row while it retains a
/// committed ELCG1 would read 0 and let the generation decrease: the read
/// fails closed instead, and the next ELCG1 commit fails and rolls back,
/// leaving the row absent.
#[test]
fn a_lost_sqlite_generation_row_fails_closed() -> TestResult {
    let directory = tempdir()?;
    let path = sqlite_path(&directory, "lost.sqlite3")?;
    commit(&mut SqliteStore::open(&path)?, elcg1(1), 1)?;
    let raw = rusqlite::Connection::open(&path)?;
    raw.execute("DELETE FROM erasure_redaction_generation", [])?;
    let mut store = SqliteStore::open(&path)?;
    assert_eq!(
        store.redaction_generation(),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        commit(&mut store, elcg1(2), 2),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        store.read_object(address(&record("ELCG1", 2))?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    drop(store);
    let rows: i64 = raw.query_row(
        "SELECT count(*) FROM erasure_redaction_generation",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(rows, 0);
    Ok(())
}

/// A row the `CHECK` would refuse, written with the checks off, is a
/// generation the adapter cannot read: the read fails rather than answer 0,
/// an ELCG1 commit fails without retaining anything, and the row is left as
/// it was.
#[test]
fn an_unreadable_sqlite_generation_fails_closed() -> TestResult {
    let directory = tempdir()?;
    let path = sqlite_path(&directory, "corrupt.sqlite3")?;
    drop(SqliteStore::open(&path)?);
    let raw = rusqlite::Connection::open(&path)?;
    raw.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         INSERT INTO erasure_redaction_generation (singleton, generation) VALUES (1, -1);",
    )?;
    let mut store = SqliteStore::open(&path)?;
    assert_eq!(
        store.redaction_generation(),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        commit(&mut store, elcg1(1), 1),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        store.read_object(address(&record("ELCG1", 1))?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    drop(store);
    let stored: i64 = raw.query_row(
        "SELECT generation FROM erasure_redaction_generation WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stored, -1);
    Ok(())
}
