//! Public acceptance vectors for the ADR-103 revisions 4 and 5 Plugin trust policy registry port on
//! the Memory adapter (slice #568): C1, D1-D3, E1-E3, and F1-F2.
//!
//! The vectors are written once, in `support/plugin_trust_registry_vectors_core.rs`, and run
//! unchanged on the `SQLite` adapter in `plugin_trust_registry_sqlite_public.rs`.
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod core_vectors {
    type Store = pos_store::memory::MemoryStore;
    include!("support/plugin_trust_registry_vectors_core.rs");
}

/// Vector E2 on an erased Timeline: Memory-only, because erasure completion is driven through the
/// test-open gate that the `SQLite` store builds differently.
mod erased_activation {
    use super::fixtures::{activation, release_one, Env, RegistryError, TestResult};
    use pos_core::store::EventStore;
    use pos_store::{memory::MemoryStore, plugin_trust_registry::PluginTrustPolicyRegistryV1};

    #[test]
    fn an_erased_activation_timeline_refuses_the_activation_event() -> TestResult {
        let gate = std::sync::Arc::new(pos_core::ErasureContainmentGateV1::new_test_open());
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(std::sync::Arc::clone(&gate))?;
        let timeline = store.create_timeline("erased")?.id();
        let env = Env::new("scope")?;
        store.provision(&env.anchor, &env.genesis_tps1)?;
        let genesis = env.genesis()?;
        assert_eq!(
            gate.complete_timeline_erasure_for_test(timeline),
            Ok(pos_core::ErasureLifecycleV1::Complete)
        );
        let before_policy = store.retained_policy_state("scope")?;
        let before_ledger = store.ledger("scope")?;
        assert_eq!(
            store.admit(
                &env.anchor,
                &genesis.tps1,
                &genesis.evidence,
                &release_one().projection()?,
                genesis.trusted()?,
                genesis.tick,
                activation(timeline, 1)
            ),
            Err(RegistryError::ActivationEventRejected)
        );
        assert_eq!(store.retained_policy_state("scope")?, before_policy);
        assert_eq!(store.ledger("scope")?, before_ledger);
        assert_eq!(store.active_release("scope", "plugin-a")?, None);
        assert_eq!(store.retained_release_decision("scope", [0x01; 32])?, None);
        Ok(())
    }
}
