//! Store-level vectors of the ADR-119 composition fallback registry port on the `SQLite` adapter
//! (slice #663, conformance case 7 at store level), plus restart retention.
#![cfg(feature = "sqlite")]

#[path = "support/composition_fallback_fixtures.rs"]
pub mod fixtures;

mod vectors {
    type Store = pos_store::sqlite::SqliteStore;
    include!("support/composition_fallback_registry_vectors.rs");
}

use std::sync::Arc;

use fixtures::{policy, Harness, TestResult, SCOPE};
use pos_core::{store::EventStore, ErasureContainmentGateV1};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryV1, FallbackCommitOutcomeV1, FallbackProvisionOutcomeV1,
};
use pos_store::sqlite::SqliteStore;

#[test]
fn a_reopened_store_retains_the_row_the_policy_and_the_ledger() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let first = policy(vec![h.world.alpha()?], None)?;
    let request = h.declaration(&first)?;
    let receipt = h.store.declare(&request)?;
    let row = h.store.registry_row(SCOPE, h.timeline)?;
    let directory = h.guard.directory.as_ref().ok_or("no directory")?;
    let path = directory.path().join("composition-fallback.db");
    let path = path.to_str().ok_or("non-UTF-8 path")?.to_owned();
    let Harness { store, timeline, .. } = h;
    drop(store);
    let mut reopened = SqliteStore::open(&path)?;
    reopened.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let again = reopened.provision_fallback_registry()?;
    assert_eq!(again, FallbackProvisionOutcomeV1::Unchanged);
    assert_eq!(reopened.registry_row(SCOPE, timeline)?, row);
    let retained = reopened.retained_policy(first.policy_digest())?;
    assert_eq!(retained, Some(first.to_canonical_cbor()));
    let ledger = reopened.fallback_ledger(SCOPE, timeline)?;
    assert_eq!(ledger, vec![receipt.row().clone()]);
    let retry = reopened.declare(&request)?;
    assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    Ok(())
}
