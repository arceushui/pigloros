//! ADR-134 §8 Gateway mode binding shared by `MemoryStore` and `SqliteStore`:
//! the empty-store bind, one-hop rotation, migration, history, and the
//! commit-epoch evidence the append choke point records.
#![cfg(feature = "sqlite")]

use std::{num::NonZeroU64, path::Path, sync::Arc};

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, CoreError, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, EventDraft,
    GatewayModeBindingErrorV1, GatewayModeBindingHostV1, GatewayModeBindingKindV1,
    GatewayModeBindingPortV1, GatewayModeBindingRecordV1, GatewayModeProfileRefV1, Kind,
    RegisteredArtifactV1, ReplayClaimEvaluatorV1, Seq, TimelineId,
};
use pos_store::{
    export_timeline, import_timeline_with_id, memory::MemoryStore, sqlite::SqliteStore, EventStore,
    SeqRange,
};
use tempfile::tempdir;

trait Store: EventStore + GatewayModeBindingPortV1 {}

impl<T: EventStore + GatewayModeBindingPortV1> Store for T {}

const LOCAL: &str = "gateway-mode-local-v1";
const AIR_GAPPED: &str = "gateway-mode-air-gapped-v1";

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn profile(id: &str, byte: u8) -> GatewayModeProfileRefV1 {
    ok(GatewayModeProfileRefV1::try_new(id, [byte; 32]))
}

const fn epoch(value: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(value)
}

fn record(id: &str, byte: u8, value: u64) -> GatewayModeBindingRecordV1 {
    GatewayModeBindingRecordV1::new(
        profile(id, byte),
        NonZeroU64::new(value).unwrap_or(NonZeroU64::MIN),
    )
}

fn stores() -> Vec<(&'static str, Box<dyn Store>)> {
    let mut memory = MemoryStore::new();
    let mut sqlite = ok(SqliteStore::open_in_memory());
    for store in [&mut memory as &mut dyn Store, &mut sqlite] {
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    }
    let memory: Box<dyn Store> = Box::new(memory);
    let sqlite: Box<dyn Store> = Box::new(sqlite);
    vec![("memory", memory), ("sqlite", sqlite)]
}

fn open_file(path: &Path) -> SqliteStore {
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    store
}

fn bind(
    store: &mut dyn Store,
    id: &str,
    byte: u8,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    store.bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(profile(id, byte)))
}

fn rotate(
    store: &mut dyn Store,
    from: u8,
    to: u8,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    let permit = ok(GatewayModeBindingHostV1::new()
        .authorize_rotation(profile(LOCAL, from), profile(LOCAL, to)));
    store.rotate_mode(permit)
}

fn migrate(
    store: &mut dyn Store,
    from: &GatewayModeProfileRefV1,
    to: &GatewayModeProfileRefV1,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    let permit = ok(GatewayModeBindingHostV1::new().authorize_migration(from.clone(), to.clone()));
    store.migrate_mode(permit)
}

fn append(store: &mut dyn EventStore, timeline: TimelineId, value: u8) -> Result<(), CoreError> {
    store
        .append(
            timeline,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("gateway.mode.test"),
                CanonicalBytes::from_vec(vec![value]),
            )],
        )
        .map(drop)
}

fn event_count(store: &dyn EventStore, timeline: TimelineId) -> usize {
    ok(store.read(timeline, SeqRange::all())).len()
}

fn commit_epoch(store: &dyn Store, timeline: TimelineId, seq: u64) -> Option<NonZeroU64> {
    ok(store.load_commit_epoch(timeline, Seq::from_u64(seq)))
}

fn kinds(store: &dyn Store) -> Vec<(GatewayModeBindingKindV1, GatewayModeBindingRecordV1)> {
    ok(store.load_mode_binding_history())
        .into_iter()
        .map(|entry| (entry.kind(), entry.record().clone()))
        .collect()
}

#[test]
fn an_empty_store_binds_once_at_epoch_one() {
    for (name, mut store) in stores() {
        assert_eq!(ok(store.load_mode_binding()), None, "{name}");
        assert_eq!(
            bind(store.as_mut(), LOCAL, 1),
            Ok(record(LOCAL, 1, 1)),
            "{name}"
        );
        assert_eq!(
            ok(store.load_mode_binding()),
            Some(record(LOCAL, 1, 1)),
            "{name}"
        );
        assert_eq!(
            kinds(store.as_ref()),
            [(GatewayModeBindingKindV1::Bind, record(LOCAL, 1, 1))],
            "{name}"
        );
        assert_eq!(
            bind(store.as_mut(), AIR_GAPPED, 2),
            Err(GatewayModeBindingErrorV1::AlreadyBound),
            "{name}"
        );
        assert_eq!(
            ok(store.attach_mode_binding()),
            record(LOCAL, 1, 1),
            "{name}"
        );
        assert_eq!(kinds(store.as_ref()).len(), 1, "{name}");
    }
}

#[test]
fn a_populated_unbound_store_can_never_be_bound() {
    for (name, mut store) in stores() {
        let timeline = ok(store.create_timeline("populated")).id();
        assert_eq!(
            bind(store.as_mut(), LOCAL, 1),
            Err(GatewayModeBindingErrorV1::PopulatedUnbound),
            "{name}"
        );
        assert_eq!(
            store.attach_mode_binding(),
            Err(GatewayModeBindingErrorV1::Unbound),
            "{name}"
        );
        assert_eq!(
            rotate(store.as_mut(), 1, 2),
            Err(GatewayModeBindingErrorV1::Unbound),
            "{name}"
        );
        assert_eq!(
            migrate(store.as_mut(), &profile(LOCAL, 1), &profile(AIR_GAPPED, 1)),
            Err(GatewayModeBindingErrorV1::Unbound),
            "{name}"
        );
        assert_eq!(ok(store.load_mode_binding()), None, "{name}");
        assert!(kinds(store.as_ref()).is_empty(), "{name}");
        // An unbound store keeps accepting unattached writes and records no
        // commit-epoch evidence for them.
        ok(append(store.as_mut(), timeline, 1));
        assert_eq!(commit_epoch(store.as_ref(), timeline, 1), None, "{name}");
    }
}

#[test]
fn rotation_and_migration_advance_one_epoch_from_the_current_binding() {
    for (name, mut store) in stores() {
        ok(bind(store.as_mut(), LOCAL, 1));
        assert_eq!(
            rotate(store.as_mut(), 9, 2),
            Err(GatewayModeBindingErrorV1::Mismatch),
            "{name}"
        );
        assert_eq!(
            rotate(store.as_mut(), 1, 2),
            Ok(record(LOCAL, 2, 2)),
            "{name}"
        );
        assert_eq!(
            migrate(store.as_mut(), &profile(LOCAL, 1), &profile(AIR_GAPPED, 3)),
            Err(GatewayModeBindingErrorV1::Mismatch),
            "{name}"
        );
        assert_eq!(
            migrate(store.as_mut(), &profile(LOCAL, 2), &profile(AIR_GAPPED, 3)),
            Ok(record(AIR_GAPPED, 3, 3)),
            "{name}"
        );
        assert_eq!(
            ok(store.load_mode_binding()),
            Some(record(AIR_GAPPED, 3, 3)),
            "{name}"
        );
        assert_eq!(
            ok(store.attach_mode_binding()),
            record(AIR_GAPPED, 3, 3),
            "{name}"
        );
        assert_eq!(
            kinds(store.as_ref()),
            [
                (GatewayModeBindingKindV1::Bind, record(LOCAL, 1, 1)),
                (GatewayModeBindingKindV1::Rotate, record(LOCAL, 2, 2)),
                (GatewayModeBindingKindV1::Migrate, record(AIR_GAPPED, 3, 3)),
            ],
            "{name}"
        );
    }
}

#[test]
fn every_committed_range_keeps_the_epoch_it_committed_under() {
    for (name, mut store) in stores() {
        ok(bind(store.as_mut(), LOCAL, 1));
        let parent = ok(store.create_timeline("parent")).id();
        ok(append(store.as_mut(), parent, 1));
        ok(append(store.as_mut(), parent, 2));
        let child = ok(store.fork(parent, Seq::from_u64(2), "child")).id();
        ok(rotate(store.as_mut(), 1, 2));
        ok(append(store.as_mut(), parent, 3));
        ok(append(store.as_mut(), child, 4));

        assert_eq!(commit_epoch(store.as_ref(), parent, 1), epoch(1), "{name}");
        assert_eq!(commit_epoch(store.as_ref(), parent, 2), epoch(1), "{name}");
        assert_eq!(commit_epoch(store.as_ref(), parent, 3), epoch(2), "{name}");
        assert_eq!(commit_epoch(store.as_ref(), parent, 4), None, "{name}");
        // The Fork's segment records only its own Event; its inherited prefix
        // keeps the parent's evidence.
        assert_eq!(commit_epoch(store.as_ref(), child, 1), epoch(2), "{name}");
        assert_eq!(commit_epoch(store.as_ref(), child, 2), None, "{name}");
        assert_eq!(
            commit_epoch(store.as_ref(), TimelineId::new(), 1),
            None,
            "{name}"
        );
        // The history entry of epoch 1 never changes.
        assert_eq!(kinds(store.as_ref())[0].1, record(LOCAL, 1, 1), "{name}");
    }
}

fn export_evaluation() -> pos_core::ReplayClaimEvaluationV1 {
    ok(ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                ErasureReferenceV1::from_digest([181; 32]),
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([182; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    ))
}

#[test]
fn an_import_is_recorded_under_the_importing_epoch() {
    let mut source = MemoryStore::new();
    ok(source.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    let exported = ok(source.create_timeline("exported")).id();
    ok(append(&mut source, exported, 1));
    ok(append(&mut source, exported, 2));
    let export = ok(export_timeline(
        &source,
        exported,
        ErasureReferenceV1::from_digest([181; 32]),
        &export_evaluation(),
    ));
    for (name, mut store) in stores() {
        ok(bind(store.as_mut(), LOCAL, 1));
        ok(rotate(store.as_mut(), 1, 2));
        let imported = ok(import_timeline_with_id(store.as_mut(), export.clone())).id();
        assert_eq!(event_count(store.as_ref(), imported), 2, "{name}");
        assert_eq!(
            commit_epoch(store.as_ref(), imported, 1),
            epoch(2),
            "{name}"
        );
        assert_eq!(
            commit_epoch(store.as_ref(), imported, 2),
            epoch(2),
            "{name}"
        );
    }
}

#[test]
fn sqlite_an_unattached_instance_cannot_write_a_bound_store() {
    let directory = ok(tempdir());
    let path = directory.path().join("bound.db");
    let mut binder = open_file(&path);
    ok(bind(&mut binder, LOCAL, 1));
    let timeline = ok(binder.create_timeline("bound")).id();
    drop(binder);

    let mut unattached = open_file(&path);
    assert!(matches!(
        append(&mut unattached, timeline, 1),
        Err(CoreError::ModeBindingStale)
    ));
    assert_eq!(event_count(&unattached, timeline), 0);

    assert_eq!(ok(unattached.attach_mode_binding()), record(LOCAL, 1, 1));
    ok(append(&mut unattached, timeline, 2));
    assert_eq!(event_count(&unattached, timeline), 1);
    assert_eq!(commit_epoch(&unattached, timeline, 1), epoch(1));
    drop(unattached);

    // A process holding a pre-rotation epoch is stale once the binding moves.
    let mut stale = open_file(&path);
    ok(stale.attach_mode_binding());
    let mut rotator = open_file(&path);
    ok(rotator.attach_mode_binding());
    ok(rotate(&mut rotator, 1, 2));
    assert!(append(&mut stale, timeline, 3).is_err());
    assert_eq!(event_count(&rotator, timeline), 1);
    ok(append(&mut rotator, timeline, 4));
    assert_eq!(commit_epoch(&rotator, timeline, 2), epoch(2));
}

#[test]
fn sqlite_an_unbound_file_accepts_unattached_instances() {
    let directory = ok(tempdir());
    let path = directory.path().join("unbound.db");
    let timeline = ok(open_file(&path).create_timeline("unbound")).id();
    let mut writer = open_file(&path);
    ok(append(&mut writer, timeline, 1));
    assert_eq!(commit_epoch(&writer, timeline, 1), None);
    assert_eq!(
        writer.attach_mode_binding(),
        Err(GatewayModeBindingErrorV1::Unbound)
    );
}

fn execute(path: &Path, sql: &str) {
    ok(ok(rusqlite::Connection::open(path)).execute_batch(sql));
}

#[test]
fn sqlite_an_untrustworthy_binding_is_an_invalid_record() {
    let directory = ok(tempdir());
    let path = directory.path().join("corrupt.db");
    ok(bind(&mut open_file(&path), LOCAL, 1));
    execute(
        &path,
        "UPDATE gateway_mode_binding SET profile_id = 'Not Canonical';
         UPDATE gateway_mode_binding_history SET profile_id = 'Not Canonical';",
    );
    let mut store = open_file(&path);
    assert_eq!(
        store.load_mode_binding(),
        Err(GatewayModeBindingErrorV1::InvalidRecord)
    );
    assert_eq!(
        store.attach_mode_binding(),
        Err(GatewayModeBindingErrorV1::InvalidRecord)
    );
    assert_eq!(
        rotate(&mut store, 1, 2),
        Err(GatewayModeBindingErrorV1::InvalidRecord)
    );
    assert_eq!(
        store.load_mode_binding_history(),
        Err(GatewayModeBindingErrorV1::InvalidRecord)
    );
}

#[test]
fn sqlite_an_unreadable_binding_is_unavailable() {
    let directory = ok(tempdir());
    let path = directory.path().join("unavailable.db");
    let mut store = open_file(&path);
    execute(&path, "DROP TABLE gateway_mode_binding_history");
    assert_eq!(
        bind(&mut store, LOCAL, 1),
        Err(GatewayModeBindingErrorV1::Unavailable)
    );
    assert_eq!(ok(store.load_mode_binding()), None);
    assert_eq!(
        store.load_mode_binding_history(),
        Err(GatewayModeBindingErrorV1::Unavailable)
    );
    execute(&path, "DROP TABLE gateway_mode_commit_epochs");
    assert_eq!(
        store.load_commit_epoch(TimelineId::new(), Seq::from_u64(1)),
        Err(GatewayModeBindingErrorV1::Unavailable)
    );
    execute(&path, "DROP TABLE gateway_mode_binding");
    assert_eq!(
        store.load_mode_binding(),
        Err(GatewayModeBindingErrorV1::Unavailable)
    );
    assert_eq!(
        store.attach_mode_binding(),
        Err(GatewayModeBindingErrorV1::Unavailable)
    );
}

#[test]
fn sqlite_a_failed_commit_epoch_record_rolls_the_append_back() {
    let directory = ok(tempdir());
    let path = directory.path().join("evidence-fault.db");
    let mut store = open_file(&path);
    ok(bind(&mut store, LOCAL, 1));
    let timeline = ok(store.create_timeline("evidence-fault")).id();
    drop(store);
    execute(
        &path,
        "CREATE TRIGGER deny_commit_epoch BEFORE INSERT ON gateway_mode_commit_epochs
         BEGIN SELECT RAISE(ABORT, 'injected fault'); END;",
    );
    let mut store = open_file(&path);
    ok(store.attach_mode_binding());
    assert!(matches!(
        append(&mut store, timeline, 1),
        Err(CoreError::Storage(_))
    ));
    assert_eq!(event_count(&store, timeline), 0);
}

#[test]
fn sqlite_rejects_a_reshaped_mode_binding_table() {
    for table in [
        "CREATE TABLE gateway_mode_binding (singleton INTEGER PRIMARY KEY,
             binding_epoch INTEGER NOT NULL, profile_id TEXT NOT NULL,
             profile_digest BLOB NOT NULL)",
        "CREATE TABLE gateway_mode_binding_history (binding_epoch INTEGER PRIMARY KEY,
             profile_id TEXT NOT NULL, profile_digest BLOB NOT NULL, kind INTEGER NOT NULL)",
        "CREATE TABLE gateway_mode_commit_epochs (timeline_id TEXT NOT NULL,
             first_local_seq INTEGER NOT NULL, last_local_seq INTEGER NOT NULL,
             binding_epoch INTEGER NOT NULL, PRIMARY KEY (timeline_id, first_local_seq))",
    ] {
        let directory = ok(tempdir());
        let path = directory.path().join("reshaped.db");
        drop(open_file(&path));
        let name = table
            .split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .to_owned();
        execute(&path, &format!("DROP TABLE {name}; {table};"));
        let error = SqliteStore::open(path.to_str().unwrap_or_default())
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains(&name), "{name}: {error}");
        assert!(error.contains("incompatible schema"), "{name}: {error}");
    }
}
