//! Black-box deduplication contracts for the documented `pos-store` factory seam.

use pos_store::{
    open_store, AppendDedupKey, AppendDedupScope, AppendIdentity, AppendOrDuplicateOutcome,
    CanonicalBytes, EntityId, EventDraft, Kind, StoreConfig, WallTime,
};

fn identity() -> AppendIdentity {
    AppendIdentity::new(
        AppendDedupKey::from_keyed_hash([1; 32]),
        AppendDedupScope::from_keyed_hash([2; 32]),
    )
}

fn draft() -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new("factory.timeline-deletion"),
        CanonicalBytes::from_vec(b"opaque retained content".to_vec()),
    )
}

fn assert_appended(outcome: &AppendOrDuplicateOutcome) {
    match outcome {
        AppendOrDuplicateOutcome::Appended(_) => {}
        AppendOrDuplicateOutcome::Duplicate { .. } | AppendOrDuplicateOutcome::Conflict => {
            panic!("identity should be available for a new append")
        }
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_factory_releases_identity_when_timeline_is_deleted() {
    let mut store = open_store(StoreConfig::SqliteInMemory).unwrap();
    let original = store.create_timeline("original").unwrap();
    let draft = draft();
    let first = store
        .append_or_duplicate(
            original.id(),
            identity(),
            WallTime::from_micros(1),
            draft.clone(),
        )
        .unwrap();
    assert_appended(&first);
    store.delete_timeline(original.id()).unwrap();

    let replacement = store.create_timeline("replacement").unwrap();
    let retry = store
        .append_or_duplicate(
            replacement.id(),
            identity(),
            WallTime::from_micros(2),
            draft,
        )
        .unwrap();
    assert_appended(&retry);
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_factory_runs_the_bounded_root_count_contract() {
    let mut store = open_store(StoreConfig::SqliteInMemory).unwrap();
    store.create_timeline("root").unwrap();
    assert_eq!(store.root_timeline_count_bounded(1).unwrap(), 1);
}
