//! Public acceptance vectors for the ADR-103 revisions 4 and 5 Plugin trust policy registry port on
//! the `SQLite` adapter (slice #569): the shared vectors G1, H1, R1-R6, S1, S2, X1, and the
//! retained-record accessors.
#![cfg(all(target_os = "linux", feature = "sqlite"))]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod policy_vectors {
    type Store = pos_store::sqlite::SqliteStore;
    include!("support/plugin_trust_registry_vectors_policy.rs");
}
