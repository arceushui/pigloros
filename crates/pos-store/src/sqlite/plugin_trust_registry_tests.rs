//! Crate-internal vectors of the `SQLite` Plugin trust policy registry (slice #569): T1-T4, E5,
//! F3, the `SQLite` clauses of E2, and the partial-floor vector of H1; and the in-crate vectors of
//! the read-only current-release evaluation (ADR-103 revision 5, slice #580): the `SQLite` rows of
//! EV2 and EV5, EV9, EV9b, and EV10 to EV14. They write raw SQL against the adapter's tables and
//! drive the durability fault hooks of the parent module.
// The gate below is also what `scripts/check_plugin_trust_registry_impls.py` reads to treat this
// file as test code, so it is not redundant.
#![cfg(any(test, feature = "test-support"))]

use std::cell::RefCell;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};

use pos_core::{
    store::{EventStore, SeqRange},
    ErasureContainmentGateV1, ErasureProtectedOperationV1, TimelineId,
};
use rusqlite::{functions::FunctionFlags, limits::Limit, Connection};

use super::seam::{Step, FAULT, LEVEL_AT_COMMIT, RESTORE_PROBE, SNAPSHOT_PROBE};
use crate::plugin_trust_registry::{
    CurrentReleaseEvaluationV1, PluginTrustCommitOutcomeV1,
    PluginTrustPolicyRegistryErrorV1 as Error, PluginTrustPolicyRegistryV1, ProvisionOutcomeV1,
};
use crate::plugin_trust_registry_fixtures::{
    activation, release_one, release_three, release_two, Backend, Env, Gate, Guard, Harness,
    ManifestSpec, Material, TestResult,
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

fn path_of(guard: &Guard) -> TestResult<String> {
    let directory = guard.directory.as_ref().ok_or("no directory")?;
    Ok(directory
        .path()
        .join("plugin-trust.db")
        .to_str()
        .ok_or("non-UTF-8 path")?
        .to_owned())
}

fn open_gated(path: &str) -> TestResult<SqliteStore> {
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(store)
}

fn raw(h: &H, sql: &str) -> TestResult {
    h.store.conn.execute_batch(sql)?;
    Ok(())
}

/// A harness whose gate the test also holds.
fn gated_harness() -> TestResult<(H, Arc<ErasureContainmentGateV1>)> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let (mut store, guard) = SqliteStore::build(Gate::Bound(Arc::clone(&gate)), None)?;
    let timeline = store.create_timeline("plugin-activation")?.id();
    let env = Env::new("scope")?;
    store.provision(&env.anchor, &env.genesis_tps1)?;
    Ok((
        Harness {
            store,
            env,
            timeline,
            guard,
        },
        gate,
    ))
}

// ---------------------------------------------------------------------------
// T1: durability level
// ---------------------------------------------------------------------------

#[test]
fn the_entry_level_is_recorded_and_restored_on_every_exit_path() -> TestResult {
    for forced in [None, Some(0), Some(1), Some(2), Some(3)] {
        let mut h = Harness::<SqliteStore>::open()?;
        if let Some(forced) = forced {
            raw(&h, &format!("PRAGMA synchronous={forced}"))?;
        }
        let entry = level(&h.store)?;
        if forced.is_none() {
            assert_eq!(entry, 1, "a freshly created store runs at NORMAL");
        }
        let genesis = h.env.genesis()?;
        h.advance(&genesis)??;
        assert_eq!(LEVEL_AT_COMMIT.with(std::cell::Cell::get), Some(2));
        assert_eq!(level(&h.store)?, entry);
        let earlier = h.same_policy(40, 5)?;
        h.assert_advance_denied(&earlier, Error::TrustedTimeRegressed)?;
        assert_eq!(level(&h.store)?, entry);

        let path = path_of(&h.guard)?;
        let holder = Connection::open(&path)?;
        holder.execute_batch("BEGIN IMMEDIATE")?;
        h.store.conn.busy_timeout(Duration::ZERO)?;
        assert_eq!(h.advance(&genesis)?, Err(Error::StorageBusy));
        assert_eq!(level(&h.store)?, entry);
        assert_eq!(
            h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
            Err(Error::StorageBusy)
        );
        assert_eq!(level(&h.store)?, entry);
        assert_eq!(
            h.admit(&genesis, &release_one(), 1)?,
            Err(Error::StorageBusy)
        );
        assert_eq!(level(&h.store)?, entry);
        assert_eq!(
            h.rollback(&genesis, &release_one(), 1)?,
            Err(Error::StorageBusy)
        );
        assert_eq!(level(&h.store)?, entry);
        holder.execute_batch("ROLLBACK")?;
    }
    Ok(())
}

#[test]
fn a_reopened_store_runs_at_full_and_stays_there() -> TestResult {
    let h = Harness::<SqliteStore>::open()?;
    let path = path_of(&h.guard)?;
    let Harness {
        store, env, guard, ..
    } = h;
    drop(store);
    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(level(&reopened)?, 2);
    assert_eq!(
        reopened.provision(&env.anchor, &env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Unchanged)
    );
    assert_eq!(level(&reopened)?, 2);
    drop(guard);
    Ok(())
}

// A read-only handle (observed on CI, entry level 2): an identical re-provision plans no write
// and commits an empty transaction, so it is `Unchanged`; every call that must write fails at its
// first write with `StorageFailed` (whether that is `BEGIN IMMEDIATE` or the first write
// statement cannot be told apart from outside). `admit` and `rollback` reach their activation
// Event append as the first write, and the append refuses with `ActivationEventRejected`. The
// entry level is restored after every call.
#[test]
fn a_read_only_handle_cannot_write_and_restores_the_level() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let (one, two, three) = (release_one(), release_two(), release_three());
    h.admit(&genesis, &one, 1)??;
    h.admit(&genesis, &two, 2)??;
    let path = path_of(&h.guard)?;
    let mut read_only = SqliteStore::open_read_only(&path)?;
    let entry = level(&read_only)?;
    assert_eq!(
        read_only.provision(&h.env.anchor, &h.env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Unchanged)
    );
    assert_eq!(level(&read_only)?, entry);
    let other = Env::new("scope-two")?;
    assert_eq!(
        read_only.provision(&other.anchor, &other.genesis_tps1),
        Err(Error::StorageFailed)
    );
    assert_eq!(level(&read_only)?, entry);
    let trusted = genesis.trusted()?;
    assert_eq!(
        read_only.advance_policy(
            &h.env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            trusted,
            genesis.tick
        ),
        Err(Error::StorageFailed)
    );
    assert_eq!(level(&read_only)?, entry);

    // R3 is the direct successor of the active R2, and a rollback to R1 is legal: both reach the
    // Event append on the real Timeline.
    read_only.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    assert_eq!(
        read_only.admit(
            &h.env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &three.projection()?,
            trusted,
            genesis.tick,
            activation(h.timeline, 3),
        ),
        Err(Error::ActivationEventRejected)
    );
    assert_eq!(level(&read_only)?, entry);
    assert_eq!(
        read_only.rollback(
            &h.env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &one.projection()?,
            trusted,
            genesis.tick,
            activation(h.timeline, 3),
        ),
        Err(Error::ActivationEventRejected)
    );
    assert_eq!(level(&read_only)?, entry);
    Ok(())
}

#[test]
fn a_store_that_is_not_in_wal_mode_is_refused() -> TestResult {
    let mut store = SqliteStore::open_in_memory()?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let env = Env::new("scope")?;
    let genesis = env.genesis()?;
    let entry = level(&store)?;
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1),
        Err(Error::WalRequired)
    );
    assert_eq!(
        store.advance_policy(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            genesis.trusted()?,
            genesis.tick
        ),
        Err(Error::WalRequired)
    );
    assert_eq!(
        store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &release_one().projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(TimelineId::new(), 1)
        ),
        Err(Error::WalRequired)
    );
    assert_eq!(level(&store)?, entry);
    Ok(())
}

#[test]
fn an_operation_inside_a_transaction_or_savepoint_is_nested() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    for open in ["BEGIN", "SAVEPOINT outer_scope"] {
        raw(&h, open)?;
        assert_eq!(h.advance(&genesis)?, Err(Error::NestedTransaction));
        assert_eq!(
            h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
            Err(Error::NestedTransaction)
        );
        assert_eq!(
            h.admit(&genesis, &release_one(), 1)?,
            Err(Error::NestedTransaction)
        );
        raw(&h, "ROLLBACK")?;
    }
    h.advance(&genesis)??;
    Ok(())
}

#[test]
fn a_failed_probe_of_the_journal_or_the_entry_level_changes_nothing() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    for step in [Step::ReadJournal, Step::ReadEntry] {
        let before = h.snapshot(&[])?;
        let entry = level(&h.store)?;
        let fault = Injected::step(step);
        assert_eq!(h.advance(&genesis)?, Err(Error::StorageFailed));
        drop(fault);
        assert_eq!(h.snapshot(&[])?, before);
        assert_eq!(level(&h.store)?, entry);
    }
    h.advance(&genesis)??;
    Ok(())
}

// ---------------------------------------------------------------------------
// T2 and F3: indeterminate outcomes, poison, and recovery
// ---------------------------------------------------------------------------

#[test]
fn a_failed_set_or_read_back_of_full_is_indeterminate_and_restores() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let entry = level(&h.store)?;
    for step in [Step::SetFull, Step::ReadBackFull] {
        let fault = Injected::step(step);
        assert_eq!(h.advance(&genesis)?, Err(Error::StorageIndeterminate));
        drop(fault);
        assert_eq!(level(&h.store)?, entry);
        assert_eq!(h.ledger()?.len(), 1);
    }
    h.advance(&genesis)??;
    Ok(())
}

#[test]
fn a_failed_commit_is_rolled_back_and_the_handle_keeps_working() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    let entry = level(&h.store)?;
    // A deferred foreign-key violation makes the real `COMMIT` fail and leaves the transaction
    // open, so the production commit and the rollback that follows it run.
    raw(
        &h,
        "PRAGMA foreign_keys = ON;
         CREATE TABLE zz_parent (id INTEGER PRIMARY KEY);
         CREATE TABLE zz_child (
             parent INTEGER REFERENCES zz_parent (id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER zz_commit_fails BEFORE INSERT ON plugin_trust_ledger
         BEGIN INSERT INTO zz_child VALUES (1); END;",
    )?;
    assert_eq!(
        h.admit(&genesis, &one, 1)?,
        Err(Error::StorageIndeterminate)
    );
    raw(&h, "DROP TRIGGER zz_commit_fails")?;
    assert!(h.store.conn.is_autocommit());
    assert_eq!(level(&h.store)?, entry);
    assert_eq!(h.snapshot(&[&one])?, before);
    let retry = h.admit(&genesis, &one, 1)??;
    assert_eq!(retry.outcome(), PluginTrustCommitOutcomeV1::Committed);

    // A commit that SQLite itself turns into a rollback behaves the same.
    let two = release_two();
    h.store.conn.commit_hook(Some(|| true))?;
    assert_eq!(
        h.admit(&genesis, &two, 2)?,
        Err(Error::StorageIndeterminate)
    );
    h.store.conn.commit_hook::<fn() -> bool>(None)?;
    assert!(h.store.conn.is_autocommit());
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), one.pmf1_digest());
    h.admit(&genesis, &two, 2)??;
    Ok(())
}

#[test]
fn a_failed_restore_poisons_the_handle_until_it_is_reopened() -> TestResult {
    for step in [Step::Restore, Step::ReadBackRestore] {
        let mut h = Harness::<SqliteStore>::open()?;
        let genesis = h.env.genesis()?;
        let one = release_one();
        let fault = Injected::step(step);
        assert_eq!(
            h.admit(&genesis, &one, 1)?,
            Err(Error::StorageIndeterminate)
        );
        drop(fault);
        let store = &h.store;
        assert_eq!(
            store.retained_policy_state("scope"),
            Err(Error::StorePoisoned)
        );
        assert_eq!(store.ledger("scope"), Err(Error::StorePoisoned));
        assert_eq!(
            store.active_release("scope", "plugin-a"),
            Err(Error::StorePoisoned)
        );
        assert_eq!(
            store.retained_release_decision("scope", one.pmf1_digest()),
            Err(Error::StorePoisoned)
        );
        assert_eq!(h.admit(&genesis, &one, 1)?, Err(Error::StorePoisoned));
        assert_eq!(h.advance(&genesis)?, Err(Error::StorePoisoned));
        assert_eq!(h.rollback(&genesis, &one, 1)?, Err(Error::StorePoisoned));
        assert_eq!(
            h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
            Err(Error::StorePoisoned)
        );

        // The commit was durable: reopening restores service and a retry replays.
        let path = path_of(&h.guard)?;
        let Harness {
            store,
            env,
            timeline,
            guard,
        } = h;
        drop(store);
        let mut reopened = open_gated(&path)?;
        let receipt = reopened.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &one.projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(timeline, 1),
        )?;
        assert_eq!(
            receipt.outcome(),
            PluginTrustCommitOutcomeV1::IdempotentReplay
        );
        assert_eq!(reopened.read(timeline, SeqRange::all())?.len(), 1);
        drop(guard);
    }
    Ok(())
}

#[test]
fn a_rollback_that_cannot_reach_autocommit_poisons_the_handle() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    h.advance(&genesis)??;
    let earlier = h.same_policy(40, 5)?;
    let fault = Injected::step(Step::Rollback);
    assert_eq!(h.advance(&earlier)?, Err(Error::StorageIndeterminate));
    drop(fault);
    assert_eq!(h.advance(&genesis)?, Err(Error::StorePoisoned));
    Ok(())
}

#[test]
fn a_lost_acknowledgement_commits_and_the_retry_replays_the_original() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    let lost = Injected::step(Step::LostAcknowledgement);
    assert_eq!(
        h.admit(&genesis, &one, 1)?,
        Err(Error::StorageIndeterminate)
    );
    drop(lost);
    assert_eq!(h.events()?.len(), 1);
    let retry = h.admit(&genesis, &one, 1)??;
    assert_eq!(
        retry.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(h.events()?.len(), 1);

    h.admit(&genesis, &two, 2)??;
    let lost = Injected::step(Step::LostAcknowledgement);
    assert_eq!(
        h.rollback(&genesis, &one, 3)?,
        Err(Error::StorageIndeterminate)
    );
    drop(lost);
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), one.pmf1_digest());
    let events = h.events()?.len();
    let replay = h.rollback(&genesis, &one, 3)??;
    assert_eq!(
        replay.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(h.events()?.len(), events);
    Ok(())
}

// ---------------------------------------------------------------------------
// T3: trigger faults at each write
// ---------------------------------------------------------------------------

fn inject(h: &H, timing: &str, table: &str) -> TestResult {
    raw(
        h,
        &format!(
            "CREATE TRIGGER inject_fault BEFORE {timing} ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected'); END"
        ),
    )
}

#[test]
fn a_fault_at_each_write_of_admit_rolls_everything_back() -> TestResult {
    let one = release_one();
    for (timing, table, expected) in [
        ("UPDATE", "plugin_trust_scopes", Error::StorageFailed),
        ("INSERT", "plugin_trust_decisions", Error::StorageFailed),
        ("INSERT", "plugin_trust_active", Error::StorageFailed),
        ("INSERT", "plugin_trust_ledger", Error::StorageFailed),
        ("INSERT", "events", Error::ActivationEventRejected),
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        let genesis = h.env.genesis()?;
        let before = h.snapshot(&[&one])?;
        let entry = level(&h.store)?;
        inject(&h, timing, table)?;
        assert_eq!(h.admit(&genesis, &one, 1)?, Err(expected), "{table}");
        assert_eq!(level(&h.store)?, entry);
        raw(&h, "DROP TRIGGER inject_fault")?;
        assert_eq!(h.snapshot(&[&one])?, before, "{table}");
        assert!(h.events()?.is_empty());
        h.admit(&genesis, &one, 1)??;
    }
    Ok(())
}

#[test]
fn a_fault_at_each_write_of_rollback_rolls_everything_back() -> TestResult {
    let (one, two) = (release_one(), release_two());
    for (timing, table, expected) in [
        ("UPDATE", "plugin_trust_scopes", Error::StorageFailed),
        ("INSERT", "plugin_trust_active", Error::StorageFailed),
        ("INSERT", "plugin_trust_ledger", Error::StorageFailed),
        ("INSERT", "events", Error::ActivationEventRejected),
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        let genesis = h.env.genesis()?;
        h.admit(&genesis, &one, 1)??;
        h.admit(&genesis, &two, 2)??;
        let before = h.snapshot(&[&one, &two])?;
        inject(&h, timing, table)?;
        assert_eq!(h.rollback(&genesis, &one, 3)?, Err(expected), "{table}");
        raw(&h, "DROP TRIGGER inject_fault")?;
        assert_eq!(h.snapshot(&[&one, &two])?, before, "{table}");
        h.rollback(&genesis, &one, 3)??;
    }
    Ok(())
}

#[test]
fn a_fault_at_each_write_of_advance_and_provision_rolls_back() -> TestResult {
    for (timing, table) in [
        ("UPDATE", "plugin_trust_scopes"),
        ("INSERT", "plugin_trust_ledger"),
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        let genesis = h.env.genesis()?;
        let before = h.snapshot(&[])?;
        inject(&h, timing, table)?;
        assert_eq!(h.advance(&genesis)?, Err(Error::StorageFailed), "{table}");
        raw(&h, "DROP TRIGGER inject_fault")?;
        assert_eq!(h.snapshot(&[])?, before);
        h.advance(&genesis)??;
    }
    for (timing, table) in [
        ("INSERT", "plugin_trust_scopes"),
        ("INSERT", "plugin_trust_ledger"),
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        let other = Env::new("scope-two")?;
        inject(&h, timing, table)?;
        assert_eq!(
            h.store.provision(&other.anchor, &other.genesis_tps1),
            Err(Error::StorageFailed),
            "{table}"
        );
        raw(&h, "DROP TRIGGER inject_fault")?;
        assert_eq!(
            h.store.retained_policy_state("scope-two"),
            Err(Error::MissingState)
        );
        assert_eq!(h.ledger()?.len(), 1);
    }
    Ok(())
}

#[test]
fn a_write_that_changes_no_row_fails_instead_of_silently_succeeding() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    raw(
        &h,
        "CREATE TRIGGER ignore_update BEFORE UPDATE ON plugin_trust_scopes
         BEGIN SELECT RAISE(IGNORE); END",
    )?;
    assert_eq!(h.advance(&genesis)?, Err(Error::StorageFailed));
    Ok(())
}

#[test]
fn the_ledger_is_append_only() -> TestResult {
    let h = Harness::<SqliteStore>::open()?;
    for sql in [
        "UPDATE plugin_trust_ledger SET tick = 1",
        "DELETE FROM plugin_trust_ledger",
        "INSERT OR REPLACE INTO plugin_trust_ledger (scope, row_seq, kind, tps1_digest,
             tps1_epoch, tps1_effective_position) VALUES ('scope', 1, 1, zeroblob(32), 1, 1)",
    ] {
        assert!(h.store.conn.execute_batch(sql).is_err(), "{sql}");
    }
    assert_eq!(h.ledger()?.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// T4: schema and stored-invariant corruption
// ---------------------------------------------------------------------------

fn assert_reads_corrupt(h: &H) {
    let store = &h.store;
    assert_eq!(
        store.retained_policy_state("scope"),
        Err(Error::CorruptState)
    );
    assert_eq!(store.ledger("scope"), Err(Error::CorruptState));
    assert_eq!(
        store.active_release("scope", "plugin-a"),
        Err(Error::CorruptState)
    );
    assert_eq!(
        store.retained_release_decision("scope", [1; 32]),
        Err(Error::CorruptState)
    );
}

fn assert_writes_corrupt(h: &mut H) -> TestResult {
    let genesis = h.env.genesis()?;
    let one = release_one();
    assert_eq!(h.advance(&genesis)?, Err(Error::CorruptState));
    assert_eq!(h.admit(&genesis, &one, 1)?, Err(Error::CorruptState));
    assert_eq!(h.rollback(&genesis, &one, 1)?, Err(Error::CorruptState));
    Ok(())
}

#[test]
fn a_partial_table_set_is_corrupt_everywhere_including_provision() -> TestResult {
    for table in [
        "plugin_trust_scopes",
        "plugin_trust_decisions",
        "plugin_trust_active",
        "plugin_trust_ledger",
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        let entry = level(&h.store)?;
        raw(&h, &format!("DROP TABLE {table}"))?;
        assert_eq!(
            h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
            Err(Error::CorruptState),
            "{table}"
        );
        assert_writes_corrupt(&mut h)?;
        assert_reads_corrupt(&h);
        assert_eq!(level(&h.store)?, entry);
    }
    Ok(())
}

#[test]
fn a_different_shape_is_corrupt_and_never_recreated() -> TestResult {
    for sql in [
        "ALTER TABLE plugin_trust_scopes ADD COLUMN extra TEXT",
        "DROP TRIGGER plugin_trust_ledger_no_update",
        "DROP TRIGGER plugin_trust_ledger_no_delete",
        "DROP TRIGGER plugin_trust_ledger_no_replace",
        "ALTER TABLE plugin_trust_active RENAME COLUMN release_digest TO release_hash",
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        raw(&h, sql)?;
        assert_eq!(
            h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
            Err(Error::CorruptState),
            "{sql}"
        );
        assert_writes_corrupt(&mut h)?;
        assert_reads_corrupt(&h);
    }
    Ok(())
}

#[test]
fn a_partial_floor_pair_or_a_corrupt_scope_row_is_corrupt_state() -> TestResult {
    for sql in [
        "UPDATE plugin_trust_scopes SET prv1_epoch = NULL, prv1_digest = NULL",
        "UPDATE plugin_trust_scopes SET ptr1_version = NULL, ptr1_digest = NULL",
        "UPDATE plugin_trust_scopes SET prv1_epoch = NULL",
        "UPDATE plugin_trust_scopes SET tps1_digest = zeroblob(32)",
        "UPDATE plugin_trust_scopes SET anchor_operator_role = 'other'",
    ] {
        let mut h = Harness::<SqliteStore>::open()?;
        let genesis = h.env.genesis()?;
        h.advance(&genesis)??;
        raw(&h, sql)?;
        assert_eq!(
            h.store.retained_policy_state("scope"),
            Err(Error::CorruptState),
            "{sql}"
        );
        assert_writes_corrupt(&mut h)?;
    }
    Ok(())
}

#[test]
fn ledger_rows_that_break_their_kind_are_corrupt() -> TestResult {
    for kind in [9, 2, 3, 4] {
        let h = Harness::<SqliteStore>::open()?;
        raw(
            &h,
            &format!(
                "PRAGMA ignore_check_constraints = ON;
                 INSERT INTO plugin_trust_ledger (scope, row_seq, kind, tps1_digest, tps1_epoch,
                     tps1_effective_position) VALUES ('scope', 2, {kind}, zeroblob(32), 1, 1);
                 PRAGMA ignore_check_constraints = OFF;"
            ),
        )?;
        assert_eq!(h.store.ledger("scope"), Err(Error::CorruptState), "{kind}");
    }
    Ok(())
}

#[test]
fn decision_and_pointer_rows_with_a_bad_event_are_corrupt() -> TestResult {
    let h = Harness::<SqliteStore>::open()?;
    raw(
        &h,
        "INSERT INTO plugin_trust_decisions VALUES ('scope', zeroblob(32), 'p', zeroblob(32),
             NULL, zeroblob(32), 1, 1, 1, zeroblob(32), 1, zeroblob(32), 1, 1, 'x', 'x', 1, 't',
             1, zeroblob(32), NULL);
         INSERT INTO plugin_trust_active VALUES ('scope', 'p', zeroblob(32), zeroblob(32), 'x',
             'x', 1, 't', 1, zeroblob(32), NULL);",
    )?;
    assert_eq!(
        h.store.retained_release_decision("scope", [0; 32]),
        Err(Error::CorruptState)
    );
    assert_eq!(
        h.store.active_release("scope", "p"),
        Err(Error::CorruptState)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// E2 (SQLite clauses) and E5: guards and lock order
//
// The Memory adapter's fork and hidden-Timeline guard tests (unit tests in its own module) and
// the SQLite tests below exercise the same shared `guarded_generic_append` chain through
// adapter-specific setup (private maps there, raw rows here), so they are not a shared vector.
// ---------------------------------------------------------------------------

fn assert_activation_refused(h: &mut H) -> TestResult {
    let genesis = h.env.genesis()?;
    let one = release_one();
    let policy = h.policy()?;
    let ledger = h.ledger()?;
    let entry = level(&h.store)?;
    assert_eq!(
        h.admit(&genesis, &one, 1)?,
        Err(Error::ActivationEventRejected)
    );
    assert_eq!(h.policy()?, policy);
    assert_eq!(h.ledger()?, ledger);
    assert_eq!(h.store.active_release("scope", "plugin-a")?, None);
    assert_eq!(level(&h.store)?, entry);
    Ok(())
}

#[test]
fn a_hidden_or_fork_activation_timeline_is_rejected() -> TestResult {
    let mut hidden = Harness::<SqliteStore>::open()?;
    let timeline = hidden.timeline.to_string();
    hidden.store.conn.execute(
        "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)",
        [timeline],
    )?;
    assert_activation_refused(&mut hidden)?;

    let mut fork = Harness::<SqliteStore>::open()?;
    let timeline = fork.timeline.to_string();
    fork.store.conn.execute(
        "INSERT INTO fork_admissions (child_id, far1_cbor) VALUES (?1, x'00')",
        [timeline],
    )?;
    assert_activation_refused(&mut fork)
}

#[test]
fn a_poisoned_or_blocked_gate_refuses_before_any_transaction() -> TestResult {
    let (mut blocked, gate) = gated_harness()?;
    gate.block_timeline(blocked.timeline);
    assert_activation_refused(&mut blocked)?;
    let (mut poisoned, gate) = gated_harness()?;
    gate.poison();
    assert_activation_refused(&mut poisoned)
}

/// Whether another thread is kept out of the activation Timeline's erasure fence.
fn fence_is_held(gate: &Arc<ErasureContainmentGateV1>, timeline: TimelineId) -> bool {
    let (sender, receiver) = mpsc::channel();
    let gate = Arc::clone(gate);
    std::thread::spawn(move || {
        let entered = gate
            .with_fence_value(timeline, ErasureProtectedOperationV1::Append, || ())
            .is_ok();
        let _delivered = sender.send(entered);
    });
    receiver.recv_timeout(Duration::from_millis(300)).is_err()
}

#[test]
fn the_fence_is_held_during_the_writes_and_during_commit() -> TestResult {
    let (mut h, gate) = gated_harness()?;
    let genesis = h.env.genesis()?;
    let in_writes = Arc::new(AtomicBool::new(false));
    let in_commit = Arc::new(AtomicBool::new(false));
    let timeline = h.timeline;
    {
        let (gate, flag) = (Arc::clone(&gate), Arc::clone(&in_writes));
        h.store.conn.create_scalar_function(
            "probe_fence",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_context| {
                flag.store(fence_is_held(&gate, timeline), Ordering::SeqCst);
                Ok(0_i64)
            },
        )?;
    }
    raw(
        &h,
        "CREATE TRIGGER probe BEFORE INSERT ON plugin_trust_ledger
         BEGIN SELECT probe_fence(); END",
    )?;
    {
        let (gate, flag) = (Arc::clone(&gate), Arc::clone(&in_commit));
        h.store.conn.commit_hook(Some(move || {
            flag.store(fence_is_held(&gate, timeline), Ordering::SeqCst);
            false
        }))?;
    }
    h.admit(&genesis, &release_one(), 1)??;
    assert!(in_writes.load(Ordering::SeqCst));
    assert!(in_commit.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn the_fence_is_entered_before_begin_immediate() -> TestResult {
    let (mut h, gate) = gated_harness()?;
    let genesis = h.env.genesis()?;
    let path = path_of(&h.guard)?;
    let holder = Connection::open(&path)?;
    holder.execute_batch("BEGIN IMMEDIATE")?;
    h.store.conn.busy_timeout(Duration::from_millis(1500))?;
    let timeline = h.timeline;
    let start = Instant::now();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        let entered = gate
            .with_fence_value(timeline, ErasureProtectedOperationV1::Append, || ())
            .is_ok();
        let _delivered = sender.send(if entered {
            start.elapsed()
        } else {
            Duration::ZERO
        });
    });
    assert_eq!(
        h.admit(&genesis, &release_one(), 1)?,
        Err(Error::StorageBusy)
    );
    let entered = receiver.recv_timeout(Duration::from_secs(10))?;
    // Another writer got the fence only after the busy `BEGIN IMMEDIATE` gave up inside it.
    assert!(entered >= Duration::from_secs(1), "{entered:?}");
    holder.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn the_fence_is_still_held_when_the_level_is_restored() -> TestResult {
    let (mut h, gate) = gated_harness()?;
    let genesis = h.env.genesis()?;
    let held = Arc::new(AtomicBool::new(false));
    let timeline = h.timeline;
    let flag = Arc::clone(&held);
    RESTORE_PROBE.with(|probe| {
        *probe.borrow_mut() = Some(Box::new(move || {
            flag.store(fence_is_held(&gate, timeline), Ordering::SeqCst);
        }));
    });
    let admitted = h.admit(&genesis, &release_one(), 1);
    RESTORE_PROBE.with(|probe| *probe.borrow_mut() = None);
    admitted??;
    assert!(held.load(Ordering::SeqCst));
    Ok(())
}

// The gate serialises writers: a registry call made while another writer holds the fence waits
// for it and then succeeds; it is not refused.
#[test]
fn a_fence_held_by_another_writer_is_waited_for() -> TestResult {
    let (mut h, gate) = gated_harness()?;
    let genesis = h.env.genesis()?;
    let timeline = h.timeline;
    let (entered, entered_receiver) = mpsc::channel();
    let released = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&released);
    std::thread::spawn(move || {
        let _held = gate.with_fence_value(timeline, ErasureProtectedOperationV1::Append, || {
            let _sent = entered.send(());
            std::thread::sleep(Duration::from_millis(400));
            // Set while the fence is still held, before it is released.
            flag.store(true, Ordering::SeqCst);
        });
    });
    entered_receiver.recv_timeout(Duration::from_secs(10))?;
    h.admit(&genesis, &release_one(), 1)??;
    assert!(
        released.load(Ordering::SeqCst),
        "the registry call returned before the other writer released the fence"
    );
    Ok(())
}

#[test]
fn a_reviewed_object_without_its_tables_is_not_an_unprovisioned_store() -> TestResult {
    let (mut store, _guard) = SqliteStore::build(Gate::open(), None)?;
    let env = Env::new("scope")?;
    store.conn.execute_batch(
        "CREATE TABLE unrelated (x INTEGER);
         CREATE TRIGGER plugin_trust_ledger_no_update BEFORE UPDATE ON unrelated
         BEGIN SELECT 1; END;",
    )?;
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1),
        Err(Error::CorruptState)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Statement failures: SQLite limits make each class of statement fail for real
// ---------------------------------------------------------------------------

#[test]
fn a_failing_read_statement_is_storage_failed() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    h.admit(&genesis, &one, 1)??;
    // `SELECT *` of the scope, decision, and ledger tables exceeds the column limit; the schema
    // probe (three columns) and the existence probe (one) still run.
    h.store.conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 12)?;
    assert_eq!(
        h.store.retained_policy_state("scope"),
        Err(Error::StorageFailed)
    );
    assert_eq!(
        h.store
            .retained_release_decision("scope", one.pmf1_digest()),
        Err(Error::StorageFailed)
    );
    assert_eq!(h.store.ledger("scope"), Err(Error::StorageFailed));
    h.store.conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 2000)?;
    assert_eq!(h.ledger()?.len(), 2);
    Ok(())
}

#[test]
fn a_failing_write_statement_is_storage_failed() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let other = Env::new("scope-two")?;
    // The schema probe binds seven variables; every insert binds more.
    h.store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 7)?;
    assert_eq!(
        h.store.provision(&other.anchor, &other.genesis_tps1),
        Err(Error::StorageFailed)
    );
    h.store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 32_766)?;
    assert_eq!(
        h.store.retained_policy_state("scope-two"),
        Err(Error::MissingState)
    );
    Ok(())
}

#[test]
fn a_failing_schema_probe_is_storage_failed_everywhere() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    h.store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 6)?;
    assert_eq!(h.advance(&genesis)?, Err(Error::StorageFailed));
    assert_eq!(h.store.ledger("scope"), Err(Error::StorageFailed));
    assert_eq!(
        h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
        Err(Error::StorageFailed)
    );
    Ok(())
}

#[test]
fn a_failing_schema_creation_is_storage_failed_and_leaves_no_tables() -> TestResult {
    let (mut store, _guard) = SqliteStore::build(Gate::open(), None)?;
    let env = Env::new("scope")?;
    // The probe statements are short; every `CREATE TABLE` is longer than the limit.
    store.conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 300)?;
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1),
        Err(Error::StorageFailed)
    );
    store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 1_000_000)?;
    assert_eq!(
        store.retained_policy_state("scope"),
        Err(Error::MissingState)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-103 revision 5: the read-only current-release evaluation
// ---------------------------------------------------------------------------

/// A harness with `release_one` active under the genesis policy at UTC second 50 and Tick 5.
fn admitted() -> TestResult<H> {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &release_one(), 1)??;
    Ok(h)
}

/// Evaluate on `store`, which may be another handle on the harness's file.
fn evaluate_on(
    store: &SqliteStore,
    h: &H,
    material: &Material,
    manifest: &ManifestSpec,
) -> TestResult<Result<CurrentReleaseEvaluationV1, Error>> {
    Ok(store.evaluate_current_release(
        &h.env.anchor,
        &material.tps1,
        &material.evidence,
        &manifest.projection()?,
        material.trusted()?,
        material.tick,
    ))
}

/// Installs the evaluation snapshot probe and clears it when dropped.
struct Probe;

impl Probe {
    fn set(probe: impl Fn() + 'static) -> Self {
        SNAPSHOT_PROBE.with(|slot| *slot.borrow_mut() = Some(Box::new(probe)));
        Self
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        SNAPSHOT_PROBE.with(|slot| *slot.borrow_mut() = None);
    }
}

// EV2, step 2: a schema difference, a partial table set, and an undecodable scope row are
// `CorruptState` before the anchor is compared, and the read transaction is rolled back.
#[test]
fn an_evaluation_reports_schema_and_scope_row_corruption_before_the_anchor() -> TestResult {
    let one = release_one();
    let cases = [
        "DROP TABLE plugin_trust_decisions",
        "DROP TABLE plugin_trust_ledger",
        "ALTER TABLE plugin_trust_scopes ADD COLUMN extra TEXT",
        "DROP TRIGGER plugin_trust_ledger_no_update",
        "UPDATE plugin_trust_scopes SET prv1_epoch = NULL",
        "UPDATE plugin_trust_scopes SET ptr1_digest = NULL",
        "UPDATE plugin_trust_scopes SET tps1_digest = zeroblob(32)",
        "UPDATE plugin_trust_scopes SET anchor_operator_role = 'other'",
        "PRAGMA ignore_check_constraints = ON;
         UPDATE plugin_trust_scopes SET anchor_operator_key = zeroblob(31);
         PRAGMA ignore_check_constraints = OFF;",
    ];
    for sql in cases {
        let h = admitted()?;
        raw(&h, sql)?;
        let genesis = h.env.genesis()?;
        for anchor in h.env.anchors_with_one_changed_field()? {
            let result = h.store.evaluate_current_release(
                &anchor,
                &genesis.tps1,
                &genesis.evidence,
                &one.projection()?,
                genesis.trusted()?,
                genesis.tick,
            );
            assert_eq!(result, Err(Error::CorruptState), "{sql}");
            assert!(h.store.conn.is_autocommit(), "{sql}");
        }
        let evaluated = h.evaluate(&genesis, &one)?;
        assert_eq!(evaluated, Err(Error::CorruptState), "{sql}");
    }
    Ok(())
}

// EV2, step 2 and 3: one floor present and the other absent decodes (each pair is whole) and is
// `CorruptState` after the anchor comparison and before the UTC check.
#[test]
fn a_single_absent_floor_is_corrupt_after_the_anchor_and_before_the_clock() -> TestResult {
    let one = release_one();
    for sql in [
        "UPDATE plugin_trust_scopes SET prv1_epoch = NULL, prv1_digest = NULL",
        "UPDATE plugin_trust_scopes SET ptr1_version = NULL, ptr1_digest = NULL",
    ] {
        let h = admitted()?;
        raw(&h, sql)?;
        let genesis = h.env.genesis()?;
        for anchor in h.env.anchors_with_one_changed_field()? {
            let result = h.store.evaluate_current_release(
                &anchor,
                &genesis.tps1,
                &genesis.evidence,
                &one.projection()?,
                genesis.trusted()?,
                genesis.tick,
            );
            assert_eq!(result, Err(Error::AnchorMismatch), "{sql}");
        }
        let stale = h.same_policy(40, 5)?;
        assert_eq!(h.evaluate(&stale, &one)?, Err(Error::CorruptState), "{sql}");
    }
    Ok(())
}

// EV2, step 2: an unprovisioned store is `MissingState`, and EV13: a failing work ends with
// `ROLLBACK`, returns the work's error, and leaves the connection in autocommit.
#[test]
fn a_failing_evaluation_rolls_back_and_returns_the_works_error() -> TestResult {
    let (store, _guard) = SqliteStore::build(Gate::open(), None)?;
    let env = Env::new("scope")?;
    let genesis = env.genesis()?;
    let result = store.evaluate_current_release(
        &env.anchor,
        &genesis.tps1,
        &genesis.evidence,
        &release_one().projection()?,
        genesis.trusted()?,
        genesis.tick,
    );
    assert_eq!(result, Err(Error::MissingState));
    assert!(store.conn.is_autocommit());

    let h = admitted()?;
    let one = release_one();
    let stale = h.same_policy(49, 5)?;
    assert_eq!(h.evaluate(&stale, &one)?, Err(Error::TrustedTimeRegressed));
    assert!(h.store.conn.is_autocommit());
    assert!(h.evaluate(&h.env.genesis()?, &one)?.is_ok());
    Ok(())
}

// EV2, faults: a failing read statement and a failing schema probe are `StorageFailed` and end
// through `ROLLBACK`; `StorageBusy` fires at the first read of a locked rollback-journal store.
#[test]
fn a_failing_read_statement_or_schema_probe_fails_an_evaluation_cleanly() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    h.store.conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 12)?;
    assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorageFailed));
    assert!(h.store.conn.is_autocommit());
    h.store.conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 2000)?;
    h.store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 6)?;
    assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorageFailed));
    assert!(h.store.conn.is_autocommit());
    h.store
        .conn
        .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 32_766)?;
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    Ok(())
}

#[test]
fn a_locked_rollback_journal_store_is_busy_at_the_first_read_and_needs_no_wal() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let mode: String = h
        .store
        .conn
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    assert_eq!(mode, "delete");
    h.store.conn.busy_timeout(Duration::ZERO)?;
    let holder = Connection::open(path_of(&h.guard)?)?;
    holder.execute_batch("BEGIN EXCLUSIVE")?;
    assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorageBusy));
    assert!(h.store.conn.is_autocommit());
    holder.execute_batch("ROLLBACK")?;
    // The read path does not require WAL: the same call now succeeds on the DELETE-mode store.
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    Ok(())
}

// EV5, corruption rows with the pointer equal to the authorization.
#[test]
fn an_evaluation_with_a_missing_or_inconsistent_decision_is_corrupt_state() -> TestResult {
    let one = release_one();
    let cases = [
        // (a) The pointer's decision is absent.
        "DELETE FROM plugin_trust_decisions",
        // (b) The decision has another Plugin ID than the pointer.
        "UPDATE plugin_trust_decisions SET plugin_id = 'plugin-b'",
        // (c) Only the decision's release digest changed.
        "UPDATE plugin_trust_decisions SET release_digest = zeroblob(32)",
        // (d) The pointer and the decision agree on a release digest the authorization lacks.
        "UPDATE plugin_trust_decisions SET release_digest = zeroblob(32);
         UPDATE plugin_trust_active SET release_digest = zeroblob(32);",
        // (e) Only the pointer's release digest is wrong.
        "UPDATE plugin_trust_active SET release_digest = zeroblob(32)",
    ];
    for sql in cases {
        let h = admitted()?;
        raw(&h, sql)?;
        let genesis = h.env.genesis()?;
        assert_eq!(
            h.evaluate(&genesis, &one)?,
            Err(Error::CorruptState),
            "{sql}"
        );
        assert!(h.store.conn.is_autocommit(), "{sql}");
    }
    Ok(())
}

// EV9: a read-only handle evaluates, and (like any handle) is poisoned by a stuck `ROLLBACK`.
#[test]
fn a_read_only_handle_evaluates_and_is_poisoned_by_a_stuck_rollback() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let read_only = SqliteStore::open_read_only(&path_of(&h.guard)?)?;
    let entry = level(&read_only)?;
    let evaluation = evaluate_on(&read_only, &h, &genesis, &one)??;
    assert_eq!(evaluation.pmf1_digest(), one.pmf1_digest());
    assert_eq!(level(&read_only)?, entry);

    let stale = h.same_policy(40, 5)?;
    let stuck = Injected::step(Step::Rollback);
    assert_eq!(
        evaluate_on(&read_only, &h, &stale, &one)?,
        Err(Error::TrustedTimeRegressed)
    );
    drop(stuck);
    assert!(!read_only.conn.is_autocommit());
    assert_eq!(
        evaluate_on(&read_only, &h, &genesis, &one)?,
        Err(Error::StorePoisoned)
    );
    // The flag is per handle: the writer handle is unaffected.
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    Ok(())
}

// EV9b: a read-write handle poisoned by a restore failure refuses an evaluation.
#[test]
fn a_handle_poisoned_by_a_restore_failure_refuses_an_evaluation() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let fault = Injected::step(Step::Restore);
    assert_eq!(
        h.admit(&genesis, &one, 1)?,
        Err(Error::StorageIndeterminate)
    );
    drop(fault);
    assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorePoisoned));
    Ok(())
}

// EV10: the evaluation reads one committed snapshot. A second handle commits a successor release
// after the evaluation's schema check; the evaluation does not observe it.
#[test]
fn an_evaluation_reads_one_snapshot_while_a_second_handle_commits() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let (one, two) = (release_one(), release_two());
    let writer = RefCell::new(open_gated(&path_of(&h.guard)?)?);
    let env = Env::new("scope")?;
    let material = env.genesis()?;
    let projection = two.projection()?;
    let timeline = h.timeline;
    let committed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&committed);
    let probe = Probe::set(move || {
        let admitted = material.trusted().is_ok_and(|utc| {
            let receipt = writer.borrow_mut().admit(
                &env.anchor,
                &material.tps1,
                &material.evidence,
                &projection,
                utc,
                material.tick,
                activation(timeline, 2),
            );
            receipt.is_ok()
        });
        flag.store(admitted, Ordering::SeqCst);
    });
    let evaluation = h.evaluate(&genesis, &one)??;
    drop(probe);
    assert!(committed.load(Ordering::SeqCst));
    assert_eq!(evaluation.pmf1_digest(), one.pmf1_digest());
    // The commit is visible to the next call, which finds the predecessor no longer active.
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), two.pmf1_digest());
    h.assert_evaluate_denied(&genesis, &one, Error::ReleaseNotActive)?;
    assert!(h.evaluate(&genesis, &two)?.is_ok());
    Ok(())
}

// EV12: inside a caller's transaction or savepoint the nested `BEGIN` fails with `StorageFailed`,
// no `ROLLBACK` is issued, the caller's work survives, and the handle is not poisoned.
#[test]
fn an_evaluation_inside_a_callers_transaction_fails_and_leaves_it_untouched() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    for (open, close) in [
        ("BEGIN", "COMMIT"),
        ("SAVEPOINT outer_scope", "RELEASE outer_scope"),
    ] {
        raw(&h, open)?;
        raw(&h, "CREATE TABLE zz_marker (x INTEGER)")?;
        assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorageFailed));
        assert!(!h.store.conn.is_autocommit());
        let rows: i64 = h
            .store
            .conn
            .query_row("SELECT count(*) FROM zz_marker", [], |row| row.get(0))?;
        assert_eq!(rows, 0);
        raw(&h, close)?;
        assert!(h.store.conn.is_autocommit());
        raw(&h, "DROP TABLE zz_marker")?;
        assert!(h.evaluate(&genesis, &one)?.is_ok());
    }
    Ok(())
}

// EV13: a `COMMIT` that succeeds but reports failure is `StorageFailed`; the `ROLLBACK` that
// follows is a no-op, the connection ends in autocommit, and the handle keeps working.
#[test]
fn a_lost_commit_acknowledgement_fails_an_evaluation_without_poisoning() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let lost = Injected::step(Step::LostAcknowledgement);
    assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorageFailed));
    drop(lost);
    assert!(h.store.conn.is_autocommit());
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    Ok(())
}

// EV14: a `ROLLBACK` that never runs (the seam holds one fault, so no `COMMIT` failure can be
// combined) leaves the work's own transaction open: the call returns the work's error and every
// later call returns `StorePoisoned` until the store is reopened.
#[test]
fn a_stuck_rollback_after_a_failed_evaluation_poisons_every_later_call() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let stale = h.same_policy(49, 5)?;
    let stuck = Injected::step(Step::Rollback);
    assert_eq!(h.evaluate(&stale, &one)?, Err(Error::TrustedTimeRegressed));
    drop(stuck);
    // The connection is still in the evaluation's transaction, and the next call is refused
    // before it could try a nested `BEGIN`.
    assert!(!h.store.conn.is_autocommit());
    assert_eq!(h.evaluate(&genesis, &one)?, Err(Error::StorePoisoned));
    assert_eq!(h.advance(&genesis)?, Err(Error::StorePoisoned));
    assert_eq!(h.admit(&genesis, &one, 2)?, Err(Error::StorePoisoned));
    let store = &h.store;
    assert_eq!(
        store.retained_policy_state("scope"),
        Err(Error::StorePoisoned)
    );
    assert_eq!(store.ledger("scope"), Err(Error::StorePoisoned));
    assert_eq!(
        store.active_release("scope", "plugin-a"),
        Err(Error::StorePoisoned)
    );

    // Reopening restores service; nothing was written.
    let path = path_of(&h.guard)?;
    let Harness {
        store, env, guard, ..
    } = h;
    drop(store);
    let reopened = open_gated(&path)?;
    let evaluation = reopened.evaluate_current_release(
        &env.anchor,
        &genesis.tps1,
        &genesis.evidence,
        &one.projection()?,
        genesis.trusted()?,
        genesis.tick,
    )?;
    assert_eq!(evaluation.pmf1_digest(), one.pmf1_digest());
    drop(guard);
    Ok(())
}
