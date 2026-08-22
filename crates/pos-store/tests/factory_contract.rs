//! Black-box deduplication contracts for the documented `pos-store` factory seam.

use pos_store::{
    open_store, AppendDedupKey, AppendDedupScope, AppendIdentity, AppendOrDuplicateOutcome,
    CanonicalBytes, EntityId, EventDraft, Kind, StoreConfig, WallTime,
};

trait TestResultExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestResultExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }
}

const fn identity() -> AppendIdentity {
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
            std::panic::resume_unwind(Box::new("identity should be available for a new append"));
        }
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_factory_releases_identity_when_timeline_is_deleted() {
    let mut store = open_store(StoreConfig::SqliteInMemory).test_ok();
    let original = store.create_timeline("original").test_ok();
    let draft = draft();
    let first = store
        .append_or_duplicate(
            original.id(),
            identity(),
            WallTime::from_micros(1),
            draft.clone(),
        )
        .test_ok();
    assert_appended(&first);
    store.delete_timeline(original.id()).test_ok();

    let replacement = store.create_timeline("replacement").test_ok();
    let retry = store
        .append_or_duplicate(
            replacement.id(),
            identity(),
            WallTime::from_micros(2),
            draft,
        )
        .test_ok();
    assert_appended(&retry);
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_factory_runs_the_bounded_root_count_contract() {
    let mut store = open_store(StoreConfig::SqliteInMemory).test_ok();
    store.create_timeline("root").test_ok();
    assert_eq!(store.root_timeline_count_bounded(1).test_ok(), 1);
}
