//! Public acceptance vectors for the ADR-103 revisions 4, 5 and 7 Plugin trust policy registry
//! port on the `SQLite` adapter (slice #569): the shared vectors G1, H1, R1-R6, S1, S2, X1, the
//! retained-record accessors, and the revision 7 release proof vectors R7-T3 to R7-T5.
#![cfg(all(target_os = "linux", feature = "sqlite"))]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod policy_vectors {
    type Store = pos_store::sqlite::SqliteStore;
    include!("support/plugin_trust_registry_vectors_policy.rs");
}
