//! Gateway-managed revisions (#304) shared by `MemoryStore` and
//! `SqliteStore`: admission under the persisted mode binding, idempotent
//! retries, head-only parents and erasure to a payload-free tombstone.
#![cfg(feature = "sqlite")]

use std::{num::NonZeroU64, path::Path, sync::Arc};

use pos_core::{
    EntityId, ErasureContainmentGateV1, EventStore, GatewayModeBindingHostV1,
    GatewayModeBindingPortV1, GatewayModeBindingRecordV1, GatewayModeProfileRefV1,
    GatewayRevisionCommitV1, GatewayRevisionDraftV1, GatewayRevisionErasureHostV1,
    GatewayRevisionErrorV1, GatewayRevisionIdempotencyV1, GatewayRevisionKeyV1,
    GatewayRevisionKindV1, GatewayRevisionPortV1, GatewayRevisionStateV1,
    ERASED_GATEWAY_REVISION_REQUEST_DIGEST,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;

trait Store: EventStore + GatewayModeBindingPortV1 + GatewayRevisionPortV1 {}

impl<T: EventStore + GatewayModeBindingPortV1 + GatewayRevisionPortV1> Store for T {}

const LOCAL: &str = "gateway-mode-local-v1";
const KIND: GatewayRevisionKindV1 = GatewayRevisionKindV1::Preference;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn revision(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap_or(NonZeroU64::MIN)
}

fn binding() -> GatewayModeBindingRecordV1 {
    GatewayModeBindingRecordV1::new(
        ok(GatewayModeProfileRefV1::try_new(LOCAL, [7; 32])),
        NonZeroU64::MIN,
    )
}

fn bind(store: &mut dyn Store) {
    let profile = ok(GatewayModeProfileRefV1::try_new(LOCAL, [7; 32]));
    ok(store.bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(profile)));
}

fn gate(store: &mut dyn Store) {
    ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
}

fn stores() -> Vec<(&'static str, Box<dyn Store>)> {
    let mut memory = MemoryStore::new();
    let mut sqlite = ok(SqliteStore::open_in_memory());
    for store in [&mut memory as &mut dyn Store, &mut sqlite] {
        gate(store);
        bind(store);
    }
    let memory: Box<dyn Store> = Box::new(memory);
    let sqlite: Box<dyn Store> = Box::new(sqlite);
    vec![("memory", memory), ("sqlite", sqlite)]
}

/// A draft of `subject` for `resource` after `parent`, keyed by `key` with
/// request digest `request`.
fn draft(
    resource: u8,
    parent: Option<u64>,
    subject: EntityId,
    key: u8,
    request: u8,
) -> GatewayRevisionDraftV1 {
    ok(GatewayRevisionDraftV1::try_new(
        GatewayRevisionIdempotencyV1::new([1; 16], KIND, [key; 32], [request; 32]),
        [resource; 16],
        parent.map(revision),
        subject,
        [resource ^ request; 32],
        vec![resource, request],
    ))
}

fn key(resource: u8, value: u64) -> GatewayRevisionKeyV1 {
    GatewayRevisionKeyV1::new(KIND, [resource; 16], revision(value))
}

fn committed(outcome: GatewayRevisionCommitV1) -> pos_core::GatewayRevisionRecordV1 {
    match outcome {
        GatewayRevisionCommitV1::Committed(record) => record,
        GatewayRevisionCommitV1::Replayed(state) => {
            std::panic::resume_unwind(Box::new(format!("unexpected replay: {state:?}")))
        }
    }
}

fn erase(
    store: &mut dyn Store,
    key: GatewayRevisionKeyV1,
) -> Result<Option<pos_core::GatewayRevisionTombstoneV1>, GatewayRevisionErrorV1> {
    store.erase_gateway_revision(GatewayRevisionErasureHostV1::new().authorize_erasure(key))
}

#[test]
fn a_revision_commits_once_with_its_binding_and_replays_exactly() {
    let subject = EntityId::new();
    for (name, mut store) in stores() {
        let first = committed(ok(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1))
        ));
        assert_eq!(first.tombstone().key(), key(1, 1), "{name}");
        assert_eq!(first.tombstone().subject(), subject, "{name}");
        assert_eq!(first.tombstone().digest(), [0; 32], "{name}");
        assert_eq!(first.principal_id(), [1; 16], "{name}");
        assert_eq!(first.mode(), &binding(), "{name}");
        assert_eq!(first.content(), [1, 1], "{name}");
        let present = GatewayRevisionStateV1::Present(first.clone());
        assert_eq!(
            ok(store.load_gateway_revision(key(1, 1))),
            Some(present.clone()),
            "{name}"
        );
        assert_eq!(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1)),
            Ok(GatewayRevisionCommitV1::Replayed(present)),
            "{name}"
        );
        assert_eq!(
            store.commit_gateway_revision(draft(2, None, subject, 1, 2)),
            Err(GatewayRevisionErrorV1::IdempotencyConflict),
            "{name}"
        );
        assert_eq!(ok(store.load_gateway_revision(key(2, 1))), None, "{name}");
        assert_eq!(ok(store.load_gateway_revision(key(1, 2))), None, "{name}");
    }
}

#[test]
fn a_next_revision_names_the_available_head_of_its_subject() {
    let subject = EntityId::new();
    for (name, mut store) in stores() {
        committed(ok(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1))
        ));
        let second = committed(ok(store.commit_gateway_revision(draft(
            1,
            Some(1),
            subject,
            2,
            2,
        ))));
        assert_eq!(second.tombstone().key(), key(1, 2), "{name}");
        for (draft, error) in [
            // The head moved past revision 1.
            (
                draft(1, Some(1), subject, 3, 3),
                GatewayRevisionErrorV1::ParentNotHead,
            ),
            // A new resource that already exists.
            (
                draft(1, None, subject, 4, 4),
                GatewayRevisionErrorV1::ParentNotHead,
            ),
            // Another subject's parent and an unknown one.
            (
                draft(1, Some(2), EntityId::new(), 5, 5),
                GatewayRevisionErrorV1::ParentUnavailable,
            ),
            (
                draft(9, Some(1), subject, 6, 6),
                GatewayRevisionErrorV1::ParentUnavailable,
            ),
        ] {
            assert_eq!(store.commit_gateway_revision(draft), Err(error), "{name}");
        }
        // A refused draft records no idempotency: the same key commits later.
        committed(ok(store.commit_gateway_revision(draft(
            1,
            Some(2),
            subject,
            3,
            3,
        ))));
    }
}

#[test]
fn erasure_keeps_only_a_tombstone_and_fences_the_revision() {
    let subject = EntityId::new();
    for (name, mut store) in stores() {
        let first = committed(ok(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1))
        ));
        let tombstone = *first.tombstone();
        assert_eq!(
            erase(store.as_mut(), key(1, 1)),
            Ok(Some(tombstone)),
            "{name}"
        );
        assert_eq!(
            erase(store.as_mut(), key(1, 1)),
            Ok(Some(tombstone)),
            "{name}"
        );
        assert_eq!(erase(store.as_mut(), key(5, 1)), Ok(None), "{name}");
        let erased = GatewayRevisionStateV1::Erased(tombstone);
        assert_eq!(erased.tombstone(), &tombstone, "{name}");
        assert_eq!(
            ok(store.load_gateway_revision(key(1, 1))),
            Some(erased.clone()),
            "{name}"
        );
        // The retry answers the tombstone, the erased parent is
        // unavailable, and the erased revision still holds its number.
        assert_eq!(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1)),
            Ok(GatewayRevisionCommitV1::Replayed(erased)),
            "{name}"
        );
        // Erasure cleared the request digest the record kept, so a retry
        // with any request under the key answers the tombstone.
        assert_eq!(
            store.commit_gateway_revision(draft(1, None, subject, 1, 9)),
            Ok(GatewayRevisionCommitV1::Replayed(
                GatewayRevisionStateV1::Erased(tombstone)
            )),
            "{name}"
        );
        assert_eq!(
            store.commit_gateway_revision(draft(1, Some(1), subject, 2, 2)),
            Err(GatewayRevisionErrorV1::ParentUnavailable),
            "{name}"
        );
        assert_eq!(
            store.commit_gateway_revision(draft(1, None, subject, 3, 3)),
            Err(GatewayRevisionErrorV1::ParentNotHead),
            "{name}"
        );
    }
}

#[test]
fn an_unbound_or_unattached_writer_commits_nothing() {
    let subject = EntityId::new();
    let mut memory = MemoryStore::new();
    let mut sqlite = ok(SqliteStore::open_in_memory());
    for store in [&mut memory as &mut dyn Store, &mut sqlite] {
        gate(store);
        assert_eq!(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1)),
            Err(GatewayRevisionErrorV1::ModeBindingStale)
        );
        assert_eq!(ok(store.load_gateway_revision(key(1, 1))), None);
    }
    // A second adapter of a bound store that never attached is stale.
    let directory = ok(tempdir());
    let path = directory.path().join("bound.db");
    let mut writer = open_file(&path);
    bind(&mut writer);
    let mut unattached = open_file(&path);
    assert_eq!(
        unattached.commit_gateway_revision(draft(1, None, subject, 1, 1)),
        Err(GatewayRevisionErrorV1::ModeBindingStale)
    );
    committed(ok(
        writer.commit_gateway_revision(draft(1, None, subject, 1, 1))
    ));
}

fn open_file(path: &Path) -> SqliteStore {
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    gate(&mut store);
    store
}

fn execute(path: &Path, sql: &str) {
    ok(ok(rusqlite::Connection::open(path)).execute_batch(sql));
}

#[test]
fn sqlite_revisions_survive_a_reopen_and_their_erasure_destroys_the_row() {
    let directory = ok(tempdir());
    let path = directory.path().join("revisions.db");
    let subject = EntityId::new();
    let first = {
        let mut store = open_file(&path);
        bind(&mut store);
        committed(ok(
            store.commit_gateway_revision(draft(1, None, subject, 1, 1))
        ))
    };
    let mut reopened = open_file(&path);
    assert_eq!(
        ok(reopened.load_gateway_revision(key(1, 1))),
        Some(GatewayRevisionStateV1::Present(first.clone()))
    );
    assert_eq!(
        erase(&mut reopened, key(1, 1)),
        Ok(Some(*first.tombstone()))
    );
    let connection = ok(rusqlite::Connection::open(&path));
    let rows: i64 = ok(
        connection.query_row("SELECT COUNT(*) FROM gateway_revisions", [], |row| {
            row.get(0)
        }),
    );
    assert_eq!(rows, 0);
    let tombstones: i64 = ok(connection.query_row(
        "SELECT COUNT(*) FROM gateway_revision_tombstones",
        [],
        |row| row.get(0),
    ));
    assert_eq!(tombstones, 1);
    // No byte derived from the erased content survives: the idempotency
    // record keeps the constant digest, and no row holds the content.
    let kept: Vec<u8> = ok(connection.query_row(
        "SELECT request_digest FROM gateway_revision_requests",
        [],
        |row| row.get(0),
    ));
    assert_eq!(kept, ERASED_GATEWAY_REVISION_REQUEST_DIGEST);
    let content_rows: i64 = ok(connection.query_row(
        "SELECT COUNT(*) FROM gateway_revision_requests WHERE request_digest = ?1",
        [vec![1_u8; 32]],
        |row| row.get(0),
    ));
    assert_eq!(content_rows, 0);
}

/// A trigger that makes the next `COMMIT` fail on a deferred foreign key
/// once a row is inserted into `table`.
fn fail_commit_after_insert(path: &Path, table: &str) {
    execute(
        path,
        &format!(
            "CREATE TABLE commit_parent (id INTEGER PRIMARY KEY);
             CREATE TABLE commit_child (parent_id INTEGER REFERENCES commit_parent(id)
                 DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER fail_commit AFTER INSERT ON {table}
             BEGIN INSERT INTO commit_child (parent_id) VALUES (1); END;"
        ),
    );
}

#[test]
fn sqlite_a_failed_commit_rolls_the_revision_back_and_closes_the_transaction() {
    let directory = ok(tempdir());
    let path = directory.path().join("commit.db");
    let subject = EntityId::new();
    let mut store = open_file(&path);
    bind(&mut store);
    fail_commit_after_insert(&path, "gateway_revision_requests");
    assert_eq!(
        store.commit_gateway_revision(draft(1, None, subject, 1, 1)),
        Err(GatewayRevisionErrorV1::Unavailable)
    );
    assert_eq!(ok(store.load_gateway_revision(key(1, 1))), None);
    // The transaction was closed: another connection can change the schema
    // and this one commits the same request afterwards.
    execute(&path, "DROP TRIGGER fail_commit");
    committed(ok(
        store.commit_gateway_revision(draft(1, None, subject, 1, 1))
    ));
}

#[test]
fn sqlite_a_failed_binding_commit_rolls_back_and_closes_the_transaction() {
    let directory = ok(tempdir());
    let path = directory.path().join("binding.db");
    let mut store = open_file(&path);
    fail_commit_after_insert(&path, "gateway_mode_binding_history");
    let profile = ok(GatewayModeProfileRefV1::try_new(LOCAL, [7; 32]));
    assert_eq!(
        store.bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(profile)),
        Err(pos_core::GatewayModeBindingErrorV1::Unavailable)
    );
    assert_eq!(ok(store.load_mode_binding()), None);
    execute(&path, "DROP TRIGGER fail_commit");
    bind(&mut store);
    assert_eq!(ok(store.load_mode_binding()), Some(binding()));
}

#[test]
fn sqlite_an_untrustworthy_or_unreadable_revision_fails_closed() {
    let directory = ok(tempdir());
    let path = directory.path().join("corrupt.db");
    let subject = EntityId::new();
    let mut store = open_file(&path);
    bind(&mut store);
    committed(ok(
        store.commit_gateway_revision(draft(1, None, subject, 1, 1))
    ));
    committed(ok(
        store.commit_gateway_revision(draft(2, None, subject, 2, 2))
    ));
    execute(
        &path,
        "UPDATE gateway_revisions SET mode_profile_id = 'Not Canonical' WHERE content = x'0101'",
    );
    assert_eq!(
        store.load_gateway_revision(key(1, 1)),
        Err(GatewayRevisionErrorV1::InvalidRecord)
    );
    // An idempotency record whose revision vanished is invalid as well.
    execute(
        &path,
        "DELETE FROM gateway_revisions WHERE content = x'0202'",
    );
    assert_eq!(
        store.commit_gateway_revision(draft(2, None, subject, 2, 2)),
        Err(GatewayRevisionErrorV1::InvalidRecord)
    );
    // A store that refuses the tombstone rolls the erasure back.
    execute(
        &path,
        "CREATE TRIGGER deny_tombstone BEFORE INSERT ON gateway_revision_tombstones
         BEGIN SELECT RAISE(ABORT, 'denied'); END;
         UPDATE gateway_revisions SET mode_profile_id = 'gateway-mode-local-v1';",
    );
    assert_eq!(
        erase(&mut store, key(1, 1)),
        Err(GatewayRevisionErrorV1::Unavailable)
    );
    assert!(matches!(
        ok(store.load_gateway_revision(key(1, 1))),
        Some(GatewayRevisionStateV1::Present(_))
    ));
    // A store that refuses the idempotency record commits no revision.
    execute(
        &path,
        "CREATE TRIGGER deny_request BEFORE INSERT ON gateway_revision_requests
         BEGIN SELECT RAISE(ABORT, 'denied'); END;",
    );
    assert_eq!(
        store.commit_gateway_revision(draft(3, None, subject, 3, 3)),
        Err(GatewayRevisionErrorV1::Unavailable)
    );
    assert_eq!(ok(store.load_gateway_revision(key(3, 1))), None);
    execute(&path, "DROP TABLE gateway_revision_tombstones");
    assert_eq!(
        store.load_gateway_revision(key(9, 1)),
        Err(GatewayRevisionErrorV1::Unavailable)
    );
}

#[test]
fn sqlite_an_incompatible_revision_table_refuses_to_open() {
    let directory = ok(tempdir());
    let path = directory.path().join("incompatible.db");
    execute(&path, "CREATE TABLE gateway_revisions (kind INTEGER)");
    assert!(SqliteStore::open(path.to_str().unwrap_or_default()).is_err());
}
