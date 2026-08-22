//! Port contract test suite (ADR-017 Decision 1: one interface, every adapter
//! must pass the same tests).

use crate::{
    store::{LedgerStore, NewPrediction},
    LedgerOutcome,
};

/// Minimum inputs for a valid registration.
#[must_use]
pub(crate) fn sample_new_prediction(resolve_by: &str) -> NewPrediction {
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
type StoreFactory =
    dyn FnMut(&std::path::Path) -> Result<Box<dyn LedgerStore>, Box<dyn std::error::Error>>;

pub(crate) fn run(make: &mut StoreFactory) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let store = make(tmp.path())?;
    load_empty_ledger(store.as_ref())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    register_and_load(store.as_mut())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    resolve_and_load(store.as_mut())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    double_resolve_rejected(store.as_mut())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    unknown_prediction_rejected(store.as_mut())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    invalid_prediction_rejected(store.as_mut())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    multiple_predictions_preserve_order(store.as_mut())?;
    let tmp = tempfile::TempDir::new()?;
    let mut store = make(tmp.path())?;
    invalid_outcome_rejected(store.as_mut())?;
    Ok(())
}

fn load_empty_ledger(store: &dyn LedgerStore) -> Result<(), Box<dyn std::error::Error>> {
    let ledger = store.load("2026-07-25")?;
    assert!(ledger.entries().is_empty(), "empty store -> empty ledger");
    assert!(ledger.warnings().is_empty(), "no warnings from empty store");
    assert_eq!(ledger.n_pending(), 0);
    assert_eq!(ledger.n_overdue(), 0);
    assert_eq!(ledger.n_resolved(), 0);
    assert_eq!(ledger.mean_brier(), None);
    Ok(())
}

fn register_and_load(store: &mut dyn LedgerStore) -> Result<(), Box<dyn std::error::Error>> {
    let new = sample_new_prediction("2026-08-01");
    let id = store.register(new)?;
    assert!(!id.is_empty(), "register returns a non-empty id");
    assert!(
        ulid::Ulid::from_string(&id).is_ok(),
        "register returns a ULID"
    );

    let ledger = store.load("2026-07-25")?;
    assert_eq!(ledger.entries().len(), 1, "one entry after one register");
    assert_eq!(ledger.entries()[0].prediction.prediction_id, id);
    assert_eq!(ledger.entries()[0].status.as_str(), "pending");
    assert!(ledger.entries()[0].resolution.is_none());
    assert_eq!(ledger.n_pending(), 1);
    assert_eq!(ledger.n_resolved(), 0);
    Ok(())
}

fn resolve_and_load(store: &mut dyn LedgerStore) -> Result<(), Box<dyn std::error::Error>> {
    let id = store.register(sample_new_prediction("2026-08-01"))?;
    store.resolve(LedgerOutcome::try_new(
        id,
        true,
        "2026-07-30T09:00:00Z".to_owned(),
    )?)?;
    let ledger = store.load("2026-07-25")?;
    assert_eq!(ledger.entries().len(), 1);
    assert_eq!(ledger.entries()[0].status.as_str(), "resolved");
    let resolution = ledger.entries()[0]
        .resolution
        .as_ref()
        .ok_or("resolution present")?;
    assert!(resolution.outcome);
    assert_eq!(resolution.resolved_at, "2026-07-30T09:00:00Z");
    assert!(ledger.entries()[0].brier_score().is_some());
    assert_eq!(ledger.n_resolved(), 1);
    Ok(())
}

fn double_resolve_rejected(store: &mut dyn LedgerStore) -> Result<(), Box<dyn std::error::Error>> {
    let id = store.register(sample_new_prediction("2026-08-01"))?;
    store.resolve(LedgerOutcome::try_new(
        id.clone(),
        true,
        "2026-07-30T09:00:00Z".to_owned(),
    )?)?;
    let err = store
        .resolve(LedgerOutcome::try_new(
            id,
            false,
            "2026-07-31T09:00:00Z".to_owned(),
        )?)
        .err()
        .ok_or("double resolve rejected")?;
    assert!(
        err.to_string().contains("already resolved"),
        "expected AlreadyResolved, got {err:?}"
    );
    Ok(())
}

fn unknown_prediction_rejected(
    store: &mut dyn LedgerStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let err = store
        .resolve(LedgerOutcome::try_new(
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
            true,
            "2026-07-30T09:00:00Z".to_owned(),
        )?)
        .err()
        .ok_or("unknown prediction rejected")?;
    assert!(
        err.to_string().contains("unknown prediction"),
        "expected UnknownPrediction, got {err:?}"
    );
    Ok(())
}

fn invalid_prediction_rejected(
    store: &mut dyn LedgerStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bad = sample_new_prediction("2026-08-01");
    bad.confidence = 2.0;
    let err = store
        .register(bad)
        .err()
        .ok_or("invalid prediction rejected")?;
    assert!(
        err.to_string().contains("invalid prediction"),
        "expected InvalidPrediction, got {err:?}"
    );
    Ok(())
}

fn invalid_outcome_rejected(store: &mut dyn LedgerStore) -> Result<(), Box<dyn std::error::Error>> {
    let err = store
        .resolve(LedgerOutcome {
            prediction_id: "not-a-ulid".to_owned(),
            outcome: true,
            resolved_at: "2026-07-30T09:00:00Z".to_owned(),
        })
        .err()
        .ok_or("resolve rejects invalid outcome")?;
    assert!(
        err.to_string().contains("invalid resolution"),
        "expected InvalidResolution, got {err:?}"
    );
    Ok(())
}

fn multiple_predictions_preserve_order(
    store: &mut dyn LedgerStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let id_a = store.register(sample_new_prediction("2026-08-01"))?;
    let id_b = store.register(sample_new_prediction("2026-09-01"))?;
    let ledger = store.load("2026-07-25")?;
    // Unresolved sorted by resolve_by ascending.
    assert_eq!(ledger.entries().len(), 2);
    assert_eq!(ledger.entries()[0].prediction.prediction_id, id_a);
    assert_eq!(ledger.entries()[1].prediction.prediction_id, id_b);
    Ok(())
}
