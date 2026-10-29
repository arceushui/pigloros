//! Public acceptance vectors for the ADR-103 revisions 4, 5 and 7 Plugin trust policy registry
//! port on the Memory adapter (slice #568): G1, H1, R1-R6, S1, S2, X1, the retained-record
//! accessors, and the revision 7 release proof vectors R7-T3 to R7-T5.
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
