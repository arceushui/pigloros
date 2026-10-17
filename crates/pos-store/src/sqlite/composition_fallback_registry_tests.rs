//! Crate-internal vectors of the `SQLite` composition fallback registry (slice #663): the
//! durability protocol, poison and recovery, a fault at each write, the append-only ledger, the
//! strict schema, statement failures, and stored rows that diverge from their fold. They write
//! raw SQL against the adapter's tables and drive the durability fault hooks of the parent
//! module.
// The gate below is also what `scripts/check_composition_fallback_registry_impls.py` reads to
// treat this file as test code, so it is not redundant.
#![cfg(any(test, feature = "test-support"))]

use std::sync::Arc;

use pos_core::{store::EventStore, DomainFallbackPolicyV1, ErasureContainmentGateV1};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;

use super::seam::{Step, FAULT};
use crate::composition_fallback_fixtures::{
    policy, Backend, Harness, Registry, TestResult, ALPHA, SCOPE,
};
use crate::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as Error, CompositionFallbackRegistryV1,
    FallbackCommitOutcomeV1, FallbackCommitReceiptV1, FallbackConformanceSetsV1,
    FallbackDeclareRequestV1, FallbackProvisionOutcomeV1,
};
use crate::sqlite::SqliteStore;

type H = Harness<SqliteStore>;

/// Makes one durability step fail on this thread until dropped.
struct Injected;

impl Injected {
    fn step(step: Step) -> Self {
        FAULT.with(|fault| fault.set(Some(step)));
        Self
    }
}

impl Drop for Injected {
    fn drop(&mut self) {
        FAULT.with(|fault| fault.set(None));
    }
}

fn level(store: &SqliteStore) -> TestResult<i64> {
    Ok(store
        .conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))?)
}

fn raw(h: &H, sql: &str) -> TestResult {
    h.store.conn.execute_batch(sql)?;
    Ok(())
}

/// A harness with the `alpha` policy declared, and that policy.
fn declared() -> TestResult<(H, DomainFallbackPolicyV1)> {
    let mut h = H::open()?;
    let first = policy(vec![h.world.alpha()?], None)?;
    h.declare(&first)??;
    Ok((h, first))
}

/// A declaration of the successor of `first` at revision 1, built without reading the registry,
/// which may be poisoned or corrupt.
fn successor_request(
    h: &H,
    first: &DomainFallbackPolicyV1,
) -> TestResult<FallbackDeclareRequestV1> {
    let next = policy(vec![h.world.alpha()?], Some(first.policy_digest()))?;
    Ok(FallbackDeclareRequestV1 {
        scope: SCOPE.to_owned(),
        target: h.target(),
        expected_state_revision: 1,
        expected_logical_head: h.head()?,
        policy_bytes: next.to_canonical_cbor(),
        conformance: FallbackConformanceSetsV1::default(),
    })
}

fn declare_successor(
    h: &mut H,
    first: &DomainFallbackPolicyV1,
) -> TestResult<Registry<FallbackCommitReceiptV1>> {
    let request = successor_request(h, first)?;
    Ok(h.store.declare(&request))
}

/// The Events, the ledger, and the row, read without the registry where the registry may be
/// poisoned or corrupt.
fn snapshot(h: &H) -> TestResult<(usize, i64, i64)> {
    let count = |table: &str| {
        let sql = format!("SELECT count(*) FROM {table}");
        h.store.conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
    };
    let ledger = count("composition_fallback_ledger")?;
    let entries = count("composition_fallback_entries")?;
    Ok((h.events()?, ledger, entries))
}

fn path_of(h: &H) -> TestResult<String> {
    let directory = h.guard.directory.as_ref().ok_or("no directory")?;
    let path = directory.path().join("composition-fallback.db");
    Ok(path.to_str().ok_or("non-UTF-8 path")?.to_owned())
}

// ---------------------------------------------------------------------------
// Durability level, WAL, and nesting
// ---------------------------------------------------------------------------

#[test]
fn the_entry_level_is_restored_after_a_commit_and_after_a_refusal() -> TestResult {
    let (mut h, first) = declared()?;
    raw(&h, "PRAGMA synchronous=NORMAL")?;
    let entry = level(&h.store)?;
    let replay = h.declare(&first)??;
    assert_eq!(replay.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    assert_eq!(level(&h.store)?, entry);
    let orphan = policy(vec![h.world.alpha()?, h.world.beta()?], None)?;
    let mut stale = h.declaration(&orphan)?;
    stale.expected_state_revision = 1;
    assert_eq!(h.store.declare(&stale).err(), Some(Error::StalePolicy));
    assert_eq!(level(&h.store)?, entry);
    declare_successor(&mut h, &first)??;
    assert_eq!(level(&h.store)?, entry);
    Ok(())
}

#[test]
fn a_store_that_is_not_in_wal_mode_is_refused() -> TestResult {
    let mut store = SqliteStore::open_in_memory()?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let timeline = store.create_timeline("composition")?.id();
    let entry = level(&store)?;
    assert_eq!(store.provision_fallback_registry(), Err(Error::WalRequired));
    let h = H::open()?;
    let first = policy(vec![h.world.alpha()?], None)?;
    let mut request = h.declaration(&first)?;
    request.target.timeline = timeline;
    assert_eq!(store.declare(&request).err(), Some(Error::WalRequired));
    assert_eq!(level(&store)?, entry);
    Ok(())
}

#[test]
fn an_operation_inside_a_transaction_is_nested() -> TestResult {
    let (mut h, first) = declared()?;
    raw(&h, "BEGIN")?;
    let nested = declare_successor(&mut h, &first)?;
    raw(&h, "ROLLBACK")?;
    assert_eq!(nested.err(), Some(Error::NestedTransaction));
    let receipt = declare_successor(&mut h, &first)??;
    assert_eq!(receipt.row().state_revision(), 2);
    Ok(())
}

#[test]
fn a_failed_probe_of_the_journal_or_the_entry_level_changes_nothing() -> TestResult {
    for step in [Step::ReadJournal, Step::ReadEntry] {
        let (mut h, first) = declared()?;
        let before = snapshot(&h)?;
        let fault = Injected::step(step);
        let refused = declare_successor(&mut h, &first)?;
        drop(fault);
        assert_eq!(refused.err(), Some(Error::StorageFailed), "{step:?}");
        assert_eq!(snapshot(&h)?, before, "{step:?}");
    }
    Ok(())
}

#[test]
fn a_failed_begin_restores_the_level_and_changes_nothing() -> TestResult {
    let (mut h, first) = declared()?;
    let entry = level(&h.store)?;
    let before = snapshot(&h)?;
    let request = successor_request(&h, &first)?;
    crate::sqlite::FAIL_BEGIN_IMMEDIATE.with(|fail| fail.set(true));
    let refused = h.store.declare(&request);
    crate::sqlite::FAIL_BEGIN_IMMEDIATE.with(|fail| fail.set(false));
    assert_eq!(refused.err(), Some(Error::StorageFailed));
    assert_eq!(level(&h.store)?, entry);
    assert_eq!(snapshot(&h)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// Indeterminate outcomes, poison, and recovery
// ---------------------------------------------------------------------------

#[test]
fn a_failed_set_or_read_back_of_full_is_indeterminate_and_restores() -> TestResult {
    for step in [Step::SetFull, Step::ReadBackFull] {
        let (mut h, first) = declared()?;
        let entry = level(&h.store)?;
        let before = snapshot(&h)?;
        let fault = Injected::step(step);
        let refused = declare_successor(&mut h, &first)?;
        drop(fault);
        assert_eq!(refused.err(), Some(Error::StorageIndeterminate), "{step:?}");
        assert_eq!(level(&h.store)?, entry, "{step:?}");
        assert_eq!(snapshot(&h)?, before, "{step:?}");
        declare_successor(&mut h, &first)??;
    }
    Ok(())
}

fn assert_poisoned(h: &mut H, first: &DomainFallbackPolicyV1) -> TestResult {
    let poisoned = Some(Error::StorePoisoned);
    assert_eq!(h.store.registry_row(SCOPE, h.timeline).err(), poisoned);
    assert_eq!(h.store.fallback_ledger(SCOPE, h.timeline).err(), poisoned);
    let digest = first.policy_digest();
    assert_eq!(h.store.retained_policy(digest).err(), poisoned);
    assert_eq!(h.store.provision_fallback_registry().err(), poisoned);
    assert_eq!(declare_successor(h, first)?.err(), poisoned);
    Ok(())
}

#[test]
fn a_failed_restore_poisons_the_handle_until_it_is_reopened() -> TestResult {
    for step in [Step::Restore, Step::ReadBackRestore] {
        let (mut h, first) = declared()?;
        let request = successor_request(&h, &first)?;
        let fault = Injected::step(step);
        let refused = h.store.declare(&request);
        drop(fault);
        assert_eq!(refused.err(), Some(Error::StorageIndeterminate), "{step:?}");
        assert_poisoned(&mut h, &first)?;
        // The commit was durable: a reopened handle replays the retry.
        let path = path_of(&h)?;
        let Harness { store, guard, .. } = h;
        drop(store);
        let mut reopened = SqliteStore::open(&path)?;
        reopened.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let retry = reopened.declare(&request)?;
        assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
        drop(guard);
    }
    Ok(())
}

#[test]
fn a_rollback_that_cannot_reach_autocommit_poisons_the_handle() -> TestResult {
    let (mut h, first) = declared()?;
    let orphan = policy(vec![h.world.alpha()?, h.world.beta()?], None)?;
    let mut stale = h.declaration(&orphan)?;
    stale.expected_state_revision = 1;
    let fault = Injected::step(Step::Rollback);
    let refused = h.store.declare(&stale);
    drop(fault);
    raw(&h, "ROLLBACK")?;
    assert_eq!(refused.err(), Some(Error::StorageIndeterminate));
    assert_poisoned(&mut h, &first)
}

#[test]
fn a_lost_acknowledgement_commits_and_recovery_finds_the_record() -> TestResult {
    let (mut h, first) = declared()?;
    let (a, b) = (h.world.a.clone(), h.world.b.clone());
    let request = h.activation(ALPHA, 0, &a, &b)?;
    let lost = Injected::step(Step::LostAcknowledgement);
    let refused = h.activate(&request);
    drop(lost);
    assert_eq!(refused.err(), Some(Error::StorageIndeterminate));
    assert_eq!(h.events()?, 2);
    let found = h.store.lookup_activation(SCOPE, h.timeline, ALPHA, 0)?;
    let retry = h.activate(&request)?;
    assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    assert_eq!(Some(retry.row()), found.as_ref());
    assert_eq!(h.events()?, 2);
    let digest = first.policy_digest();
    let declaration = h.store.lookup_declaration(SCOPE, h.timeline, digest)?;
    assert!(declaration.is_some());
    Ok(())
}

#[test]
fn a_failed_commit_is_rolled_back_and_the_handle_keeps_working() -> TestResult {
    let (mut h, first) = declared()?;
    let before = snapshot(&h)?;
    let entry = level(&h.store)?;
    // A deferred foreign-key violation makes the real `COMMIT` fail and leaves the transaction
    // open, so the production commit and the rollback that follows it run.
    raw(
        &h,
        "PRAGMA foreign_keys = ON;
         CREATE TABLE zz_parent (id INTEGER PRIMARY KEY);
         CREATE TABLE zz_child (
             parent INTEGER REFERENCES zz_parent (id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER zz_commit_fails BEFORE INSERT ON composition_fallback_ledger
         BEGIN INSERT INTO zz_child VALUES (1); END;",
    )?;
    let refused = declare_successor(&mut h, &first)?;
    raw(&h, "DROP TRIGGER zz_commit_fails")?;
    assert_eq!(refused.err(), Some(Error::StorageIndeterminate));
    assert!(h.store.conn.is_autocommit());
    assert_eq!(level(&h.store)?, entry);
    assert_eq!(snapshot(&h)?, before);
    let retry = declare_successor(&mut h, &first)??;
    assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::Committed);
    Ok(())
}

// ---------------------------------------------------------------------------
// A fault at each write
// ---------------------------------------------------------------------------

const WRITES: [(&str, &str); 6] = [
    ("INSERT", "events"),
    ("UPDATE", "composition_fallback_rows"),
    ("DELETE", "composition_fallback_entries"),
    ("INSERT", "composition_fallback_entries"),
    ("INSERT", "composition_fallback_policies"),
    ("INSERT", "composition_fallback_ledger"),
];

#[test]
fn a_fault_at_each_write_rolls_everything_back() -> TestResult {
    for (timing, table) in WRITES {
        let (mut h, first) = declared()?;
        let before = snapshot(&h)?;
        raw(
            &h,
            &format!(
                "CREATE TRIGGER inject_fault BEFORE {timing} ON {table}
                 BEGIN SELECT RAISE(ABORT, 'injected'); END"
            ),
        )?;
        let refused = declare_successor(&mut h, &first)?;
        let expected = if table == "events" {
            Error::EventRejected
        } else {
            Error::StorageFailed
        };
        assert_eq!(refused.err(), Some(expected), "{table}");
        raw(&h, "DROP TRIGGER inject_fault")?;
        assert_eq!(snapshot(&h)?, before, "{table}");
        declare_successor(&mut h, &first)??;
    }
    Ok(())
}

#[test]
fn the_ledger_and_the_retained_policies_are_append_only() -> TestResult {
    let (h, _) = declared()?;
    for sql in [
        "UPDATE composition_fallback_ledger SET tick = 1",
        "DELETE FROM composition_fallback_ledger",
        "UPDATE composition_fallback_policies SET policy_bytes = X'00'",
        "DELETE FROM composition_fallback_policies",
    ] {
        assert!(h.store.conn.execute_batch(sql).is_err(), "{sql}");
    }
    assert_eq!(h.store.fallback_ledger(SCOPE, h.timeline)?.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Strict schema
// ---------------------------------------------------------------------------

fn assert_corrupt_everywhere(h: &mut H, first: &DomainFallbackPolicyV1) -> TestResult {
    let corrupt = Some(Error::CorruptState);
    assert_eq!(h.store.registry_row(SCOPE, h.timeline).err(), corrupt);
    assert_eq!(h.store.fallback_ledger(SCOPE, h.timeline).err(), corrupt);
    let digest = first.policy_digest();
    assert_eq!(h.store.retained_policy(digest).err(), corrupt);
    assert_eq!(h.store.provision_fallback_registry().err(), corrupt);
    assert_eq!(declare_successor(h, first)?.err(), corrupt);
    Ok(())
}

#[test]
fn a_partial_or_different_table_set_is_corrupt_and_never_recreated() -> TestResult {
    let (mut h, first) = declared()?;
    raw(&h, "DROP TABLE composition_fallback_entries")?;
    assert_corrupt_everywhere(&mut h, &first)?;
    raw(
        &h,
        "CREATE TABLE composition_fallback_entries (scope TEXT NOT NULL PRIMARY KEY) STRICT",
    )?;
    assert_corrupt_everywhere(&mut h, &first)
}

#[test]
fn a_reviewed_trigger_without_its_tables_is_not_an_unprovisioned_store() -> TestResult {
    let (mut store, _guard) = SqliteStore::build(None)?;
    store.conn.execute_batch(
        "CREATE TABLE zz (id INTEGER);
         CREATE TRIGGER composition_fallback_ledger_no_update BEFORE UPDATE ON zz
         BEGIN SELECT 1; END;",
    )?;
    let timeline = store.create_timeline("composition")?.id();
    let corrupt = Some(Error::CorruptState);
    assert_eq!(store.registry_row(SCOPE, timeline).err(), corrupt);
    assert_eq!(store.provision_fallback_registry().err(), corrupt);
    Ok(())
}

#[test]
fn a_failing_schema_creation_is_storage_failed_and_leaves_no_tables() -> TestResult {
    let (mut store, _guard) = SqliteStore::build(None)?;
    // The probe and protocol statements are short; every `CREATE` is longer than the limit.
    store.conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 150)?;
    let refused = store.provision_fallback_registry();
    store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 1_000_000)?;
    assert_eq!(refused, Err(Error::StorageFailed));
    let timeline = store.create_timeline("composition")?.id();
    let missing = store.registry_row(SCOPE, timeline);
    assert_eq!(missing, Err(Error::MissingState));
    let created = store.provision_fallback_registry()?;
    assert_eq!(created, FallbackProvisionOutcomeV1::Created);
    Ok(())
}

// ---------------------------------------------------------------------------
// Statement failures
// ---------------------------------------------------------------------------

fn deny_reads_of(h: &H, denied: &'static str) -> TestResult {
    h.store
        .conn
        .authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Read { table_name, .. } if table_name == denied => Authorization::Deny,
            _ => Authorization::Allow,
        }))?;
    Ok(())
}

fn allow_all(h: &H) -> TestResult {
    h.store
        .conn
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
    Ok(())
}

#[test]
fn a_denied_read_of_each_registry_table_is_storage_failed() -> TestResult {
    let tables = [
        "composition_fallback_rows",
        "composition_fallback_ledger",
        "composition_fallback_policies",
    ];
    for table in tables {
        let (mut h, first) = declared()?;
        let before = snapshot(&h)?;
        let request = successor_request(&h, &first)?;
        deny_reads_of(&h, table)?;
        let refused = h.store.declare(&request);
        let read = match table {
            "composition_fallback_rows" => h.store.registry_row(SCOPE, h.timeline).err(),
            "composition_fallback_ledger" => h.store.fallback_ledger(SCOPE, h.timeline).err(),
            _ => h.store.retained_policy(first.policy_digest()).err(),
        };
        allow_all(&h)?;
        assert_eq!(refused.err(), Some(Error::StorageFailed), "{table}");
        assert_eq!(read, Some(Error::StorageFailed), "{table}");
        assert_eq!(snapshot(&h)?, before, "{table}");
    }
    Ok(())
}

#[test]
fn a_target_timeline_that_cannot_be_read_is_unavailable() -> TestResult {
    let (mut h, first) = declared()?;
    let before = snapshot(&h)?;
    let request = successor_request(&h, &first)?;
    deny_reads_of(&h, "events")?;
    let refused = h.store.declare(&request);
    allow_all(&h)?;
    assert_eq!(refused.err(), Some(Error::TimelineUnavailable));
    assert_eq!(snapshot(&h)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// Stored rows that diverge from their fold
// ---------------------------------------------------------------------------

fn ledger_insert(h: &H, columns: &str, values: &str) -> TestResult {
    let timeline = h.timeline;
    raw(
        h,
        &format!(
            "INSERT INTO composition_fallback_ledger
                 (scope, timeline, entity, policy_digest, request_digest, event_id,
                  event_payload_digest, {columns})
             VALUES ('scope', '{timeline}', zeroblob(16), zeroblob(32), zeroblob(32),
                     zeroblob(16), zeroblob(32), {values})"
        ),
    )
}

#[test]
fn a_ledger_row_that_breaks_its_kind_is_corrupt_state() -> TestResult {
    let (mut h, first) = declared()?;
    let columns = "row_seq, kind, state_revision, event_seq";
    ledger_insert(&h, columns, "2, 2, 1, 1")?;
    let corrupt = Some(Error::CorruptState);
    assert_eq!(h.store.fallback_ledger(SCOPE, h.timeline).err(), corrupt);
    assert_eq!(declare_successor(&mut h, &first)?.err(), corrupt);
    Ok(())
}

#[test]
fn a_stored_row_that_differs_from_its_fold_is_corrupt_state() -> TestResult {
    let divergences = [
        "UPDATE composition_fallback_rows SET state_revision = 7",
        "UPDATE composition_fallback_entries SET tenure_ordinal = 4",
        "DELETE FROM composition_fallback_rows",
    ];
    for sql in divergences {
        let (mut h, first) = declared()?;
        raw(&h, sql)?;
        let refused = declare_successor(&mut h, &first)?;
        assert_eq!(refused.err(), Some(Error::CorruptState), "{sql}");
    }
    // A ledger whose last row names another revision than the row.
    let (mut h, first) = declared()?;
    let columns = "row_seq, kind, state_revision, event_seq, declared_digest, conformance_digest";
    ledger_insert(&h, columns, "2, 1, 5, 1, zeroblob(32), zeroblob(32)")?;
    let refused = declare_successor(&mut h, &first)?;
    assert_eq!(refused.err(), Some(Error::CorruptState));
    Ok(())
}
