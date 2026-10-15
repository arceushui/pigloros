//! Read-only protected intervals retain exact transaction ownership on refusal.

use super::fixture_store;
use crate::sqlite::SqliteStore;
use pos_core::{
    store::EventStore, ErasureContainmentGateV1, ErasureErrorV1, ErasureInventoryPersistencePortV1,
    ErasureProtectedEffectDispositionV1, ErasureProtectedEffectIntervalV1,
};
use rusqlite::{
    hooks::{AuthAction, AuthContext, Authorization, TransactionOperation},
    Connection,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

struct ReadOnlyFixture {
    database: tempfile::NamedTempFile,
    store: SqliteStore,
    gate: Arc<ErasureContainmentGateV1>,
}

impl ReadOnlyFixture {
    fn new() -> Fallible<Self> {
        let database = tempfile::NamedTempFile::new()?;
        let path = database.path().to_str().ok_or("database path")?;
        let mut seed = fixture_store(SqliteStore::open(path)?);
        seed.create_timeline("interval-liveness")?;
        drop(seed);
        let mut store = SqliteStore::open_read_only(path)?;
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        store.bind_erasure_gate(Arc::clone(&gate))?;
        let fixture = Self {
            database,
            store,
            gate,
        };
        assert!(fixture.store.conn.is_autocommit());
        assert!(fixture.writer()?.is_autocommit());
        Ok(fixture)
    }

    fn writer(&self) -> Fallible<&Connection> {
        self.store
            .writer_reservation_connection
            .as_ref()
            .ok_or_else(|| "missing writer reservation".into())
    }

    fn assert_released(&self) -> Fallible<()> {
        assert!(self.store.conn.is_autocommit());
        assert!(self.writer()?.is_autocommit());
        let writer = Connection::open(self.database.path())?;
        writer.execute_batch("BEGIN IMMEDIATE")?;
        assert_eq!(
            writer.execute(
                "UPDATE timelines SET name = name WHERE name = 'interval-liveness'",
                [],
            )?,
            1
        );
        writer.execute_batch("ROLLBACK")?;
        assert!(writer.is_autocommit());
        Ok(())
    }
}

// Private native faults: public store constructors cannot deny one transaction
// statement. No production hook or extra public adapter is exposed for them.
fn deny_transaction(
    connection: &Connection,
    denied: TransactionOperation,
) -> Fallible<Arc<AtomicUsize>> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    connection.authorizer(Some(move |context: AuthContext<'_>| {
        if context.action == (AuthAction::Transaction { operation: denied }) {
            observed.fetch_add(1, Ordering::SeqCst);
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    }))?;
    Ok(attempts)
}

fn allow_all(connection: &Connection) -> Fallible<()> {
    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
    Ok(())
}

#[test]
fn read_only_reader_begin_refusals_release_only_the_owned_writer() -> Fallible<()> {
    for preexisting_reader in [false, true] {
        let fixture = ReadOnlyFixture::new()?;
        let attempts = if preexisting_reader {
            // Private lifecycle invariant: do not borrow an older reader
            // transaction, or roll it back as if this interval had owned it.
            fixture.store.conn.execute_batch("BEGIN DEFERRED")?;
            None
        } else {
            Some(deny_transaction(
                &fixture.store.conn,
                TransactionOperation::Begin,
            )?)
        };
        assert_eq!(
            fixture.store.begin_protected_effect_interval(),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        assert!(fixture.writer()?.is_autocommit());
        assert_eq!(fixture.store.conn.is_autocommit(), !preexisting_reader);
        if let Some(attempts) = attempts {
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
        allow_all(&fixture.store.conn)?;
        if preexisting_reader {
            fixture.store.conn.execute_batch("ROLLBACK")?;
        }
        fixture.assert_released()?;
    }
    Ok(())
}

#[test]
fn read_only_data_version_refusal_releases_reader_and_writer() -> Fallible<()> {
    let fixture = ReadOnlyFixture::new()?;
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    fixture
        .store
        .conn
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Pragma { pragma_name, .. }
                    if pragma_name.eq_ignore_ascii_case("data_version")
            ) {
                observed.fetch_add(1, Ordering::SeqCst);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))?;
    assert_eq!(
        fixture.store.begin_protected_effect_interval(),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    allow_all(&fixture.store.conn)?;
    fixture.assert_released()
}

#[test]
fn read_only_public_stale_generation_releases_both_transactions() -> Fallible<()> {
    let fixture = ReadOnlyFixture::new()?;
    // A real public write commits before the interval, never under its fence.
    let path = fixture.database.path().to_str().ok_or("database path")?;
    let mut writer = fixture_store(SqliteStore::open(path)?);
    writer.create_timeline("intervening-public-writer")?;
    drop(writer);
    assert_eq!(
        fixture.store.begin_protected_effect_interval(),
        Err(ErasureErrorV1::StaleGeneration)
    );
    fixture.assert_released()
}

#[test]
fn read_only_public_gate_removal_releases_both_transactions() -> Fallible<()> {
    let mut fixture = ReadOnlyFixture::new()?;
    fixture.store = fixture.store.without_erasure_gate();
    assert_eq!(
        fixture.store.begin_protected_effect_interval(),
        Err(ErasureErrorV1::StaleGeneration)
    );
    fixture.assert_released()
}

#[test]
fn read_only_public_gate_poisoning_releases_both_transactions() -> Fallible<()> {
    let fixture = ReadOnlyFixture::new()?;
    fixture.gate.poison();
    assert_eq!(
        fixture.store.begin_protected_effect_interval(),
        Err(ErasureErrorV1::StaleGeneration)
    );
    fixture.assert_released()
}

#[test]
fn read_only_reader_rollback_refusal_still_releases_the_writer() -> Fallible<()> {
    let fixture = ReadOnlyFixture::new()?;
    let interval = fixture.store.begin_protected_effect_interval()?;
    assert_eq!(interval, ErasureProtectedEffectIntervalV1::Owned);
    let attempts = deny_transaction(&fixture.store.conn, TransactionOperation::Rollback)?;
    assert_eq!(
        fixture.store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Commit
        ),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(fixture.writer()?.is_autocommit());
    assert!(!fixture.store.conn.is_autocommit());
    // Refused cleanup is not successful cleanup. Remove the injection and
    // explicitly settle the reader before checking independent writer progress.
    allow_all(&fixture.store.conn)?;
    fixture.store.conn.execute_batch("ROLLBACK")?;
    fixture.assert_released()
}

#[test]
fn read_only_writer_commit_refusal_falls_back_to_rollback() -> Fallible<()> {
    let fixture = ReadOnlyFixture::new()?;
    let interval = fixture.store.begin_protected_effect_interval()?;
    assert_eq!(interval, ErasureProtectedEffectIntervalV1::Owned);
    // Pinned rusqlite maps COMMIT to Unknown, not Release or a Commit variant.
    let attempts = deny_transaction(fixture.writer()?, TransactionOperation::Unknown)?;
    assert_eq!(
        fixture.store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Commit
        ),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    allow_all(fixture.writer()?)?;
    fixture.assert_released()
}

#[test]
fn read_only_writer_rollback_refusal_attempts_fallback_without_claiming_release() -> Fallible<()> {
    let fixture = ReadOnlyFixture::new()?;
    let interval = fixture.store.begin_protected_effect_interval()?;
    assert_eq!(interval, ErasureProtectedEffectIntervalV1::Owned);
    let attempts = deny_transaction(fixture.writer()?, TransactionOperation::Rollback)?;
    assert_eq!(
        fixture.store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        ),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(fixture.store.conn.is_autocommit());
    assert!(!fixture.writer()?.is_autocommit());
    allow_all(fixture.writer()?)?;
    fixture.writer()?.execute_batch("ROLLBACK")?;
    fixture.assert_released()
}
