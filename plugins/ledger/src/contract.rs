//! Port contract test suite (ADR-017 Decision 1: one interface, every adapter
//! must pass the same tests).

use crate::{
    store::{LedgerStore, NewPrediction},
    LedgerOutcome,
};

/// Minimum inputs for a valid registration.
#[must_use]
pub fn sample_new_prediction(resolve_by: &str) -> NewPrediction {
    NewPrediction {
        title: "Kyoto vs Osaka".to_owned(),
        statement: "Kyoto will be chosen".to_owned(),
        predicted_outcome: "Kyoto".to_owned(),
        confidence: 0.8,
        scenario: None,
        made_at: "2026-07-20T12:00:00Z".to_owned(),
        resolve_by: resolve_by.to_owned(),
        osf_link: "https://osf.io/example".to_owned(),
    }
}

/// Run every contract scenario against an adapter factory.
///
/// `make(dir)` creates a fresh empty adapter rooted at the given directory.
/// Each sub-test gets its own instance so state never leaks.
///
/// # Panics
/// On any assertion failure.
pub fn run(make: &mut dyn FnMut(&std::path::Path) -> Box<dyn LedgerStore>) {
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    load_empty_ledger(make(tmp.path()).as_mut());
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    register_and_load(make(tmp.path()).as_mut());
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    resolve_and_load(make(tmp.path()).as_mut());
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    double_resolve_rejected(make(tmp.path()).as_mut());
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    unknown_prediction_rejected(make(tmp.path()).as_mut());
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    invalid_prediction_rejected(make(tmp.path()).as_mut());
    let tmp = tempfile::TempDir::new().expect("contract tempdir");
    multiple_predictions_preserve_order(make(tmp.path()).as_mut());
}

fn load_empty_ledger(store: &mut dyn LedgerStore) {
    let ledger = store.load("2026-07-25").unwrap();
    assert!(ledger.entries().is_empty(), "empty store -> empty ledger");
    assert!(ledger.warnings().is_empty(), "no warnings from empty store");
    assert_eq!(ledger.n_pending(), 0);
    assert_eq!(ledger.n_overdue(), 0);
    assert_eq!(ledger.n_resolved(), 0);
    assert_eq!(ledger.mean_brier(), None);
}

fn register_and_load(store: &mut dyn LedgerStore) {
    let new = sample_new_prediction("2026-08-01");
    let id = store.register(new).expect("register should succeed");
    assert!(!id.is_empty(), "register returns a non-empty id");
    assert!(
        ulid::Ulid::from_string(&id).is_ok(),
        "register returns a ULID"
    );

    let ledger = store.load("2026-07-25").expect("load after register");
    assert_eq!(ledger.entries().len(), 1, "one entry after one register");
    assert_eq!(ledger.entries()[0].prediction.prediction_id, id);
    assert_eq!(ledger.entries()[0].status.as_str(), "pending");
    assert!(ledger.entries()[0].resolution.is_none());
    assert_eq!(ledger.n_pending(), 1);
    assert_eq!(ledger.n_resolved(), 0);
}

fn resolve_and_load(store: &mut dyn LedgerStore) {
    let id = store
        .register(sample_new_prediction("2026-08-01"))
        .expect("register");
    store
        .resolve(
            LedgerOutcome::new(id.clone(), true, "2026-07-30T09:00:00Z".to_owned())
                .expect("LedgerOutcome::new"),
        )
        .expect("resolve");
    let ledger = store.load("2026-07-25").expect("load after resolve");
    assert_eq!(ledger.entries().len(), 1);
    assert_eq!(ledger.entries()[0].status.as_str(), "resolved");
    let resolution = ledger.entries()[0]
        .resolution
        .as_ref()
        .expect("resolution present");
    assert!(resolution.outcome);
    assert_eq!(resolution.resolved_at, "2026-07-30T09:00:00Z");
    assert!(ledger.entries()[0].brier_score().is_some());
    assert_eq!(ledger.n_resolved(), 1);
}

fn double_resolve_rejected(store: &mut dyn LedgerStore) {
    let id = store
        .register(sample_new_prediction("2026-08-01"))
        .expect("register");
    store
        .resolve(
            LedgerOutcome::new(id.clone(), true, "2026-07-30T09:00:00Z".to_owned())
                .expect("LedgerOutcome::new"),
        )
        .expect("first resolve");
    let err = store
        .resolve(
            LedgerOutcome::new(id.clone(), false, "2026-07-31T09:00:00Z".to_owned())
                .expect("LedgerOutcome::new"),
        )
        .expect_err("double resolve rejected");
    assert!(
        err.to_string().contains("already resolved"),
        "expected AlreadyResolved, got {err:?}"
    );
}

fn unknown_prediction_rejected(store: &mut dyn LedgerStore) {
    let err = store
        .resolve(
            LedgerOutcome::new(
                "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
                true,
                "2026-07-30T09:00:00Z".to_owned(),
            )
            .expect("LedgerOutcome::new"),
        )
        .expect_err("unknown prediction rejected");
    assert!(
        err.to_string().contains("unknown prediction"),
        "expected UnknownPrediction, got {err:?}"
    );
}

fn invalid_prediction_rejected(store: &mut dyn LedgerStore) {
    let mut bad = sample_new_prediction("2026-08-01");
    bad.confidence = 2.0;
    let err = store
        .register(bad)
        .expect_err("invalid prediction rejected");
    assert!(
        err.to_string().contains("invalid prediction"),
        "expected InvalidPrediction, got {err:?}"
    );
}

fn multiple_predictions_preserve_order(store: &mut dyn LedgerStore) {
    let id_a = store
        .register(sample_new_prediction("2026-08-01"))
        .expect("register A");
    let id_b = store
        .register(sample_new_prediction("2026-09-01"))
        .expect("register B");
    let ledger = store.load("2026-07-25").expect("load");
    // Unresolved sorted by resolve_by ascending.
    assert_eq!(ledger.entries().len(), 2);
    assert_eq!(ledger.entries()[0].prediction.prediction_id, id_a);
    assert_eq!(ledger.entries()[1].prediction.prediction_id, id_b);
}
