//! Store-level vectors of the ADR-119 composition fallback registry port on the Memory adapter
//! (slice #663, conformance case 7 at store level).
//!
//! The vectors are written once, in `support/composition_fallback_registry_vectors.rs`, and run
//! unchanged on the `SQLite` adapter in `composition_fallback_registry_sqlite_public.rs`.

#[path = "support/composition_fallback_fixtures.rs"]
pub mod fixtures;

mod vectors {
    type Store = pos_store::memory::MemoryStore;
    include!("support/composition_fallback_registry_vectors.rs");
}

/// Memory-only: a store without an erasure gate refuses every Event-bearing operation.
mod ungated {
    use super::fixtures::{policy, Harness, RegistryError, TestResult, SCOPE};
    use pos_store::composition_fallback_registry::CompositionFallbackRegistryV1;
    use pos_store::memory::MemoryStore;

    #[test]
    fn a_store_without_an_erasure_gate_refuses_the_event() -> TestResult {
        let mut h = Harness::<MemoryStore>::open()?;
        let first = policy(vec![h.world.alpha()?], None)?;
        let request = h.declaration(&first)?;
        let store = std::mem::take(&mut h.store);
        let mut ungated = store.without_erasure_gate();
        let refused = ungated.declare(&request);
        assert_eq!(refused.err(), Some(RegistryError::EventRejected));
        assert_eq!(ungated.fallback_ledger(SCOPE, h.timeline)?, Vec::new());
        Ok(())
    }
}
