//! Public acceptance vectors for the ADR-103 revisions 4 and 5 Plugin trust policy registry port on
//! the Memory adapter (slice #568): G1, H1, R1-R6, S1, S2, X1, and the retained-record
//! accessors.
//!
//! The vectors are written once, in `support/plugin_trust_registry_vectors_policy.rs`, and run
//! unchanged on the `SQLite` adapter in `plugin_trust_registry_sqlite_policy_public.rs`.
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod policy_vectors {
    type Store = pos_store::memory::MemoryStore;
    include!("support/plugin_trust_registry_vectors_policy.rs");
}
