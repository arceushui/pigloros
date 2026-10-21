//! Public acceptance vectors for the ADR-103 revision 5 read-only current-release evaluation on
//! the `SQLite` adapter (slice #580): the shared vectors EV1 to EV8 and EV11.
#![cfg(all(target_os = "linux", feature = "sqlite"))]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod evaluation_vectors {
    type Store = pos_store::sqlite::SqliteStore;
    include!("support/plugin_trust_registry_vectors_evaluation.rs");
}
