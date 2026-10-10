//! Public acceptance vectors for the ADR-103 revision 5 read-only current-release evaluation on
//! the Memory adapter (slice #580): EV1 to EV8 and EV11.
//!
//! The vectors are written once, in `support/plugin_trust_registry_vectors_evaluation.rs`, and
//! run unchanged on the `SQLite` adapter in `plugin_trust_registry_sqlite_evaluation_public.rs`.
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod evaluation_vectors {
    type Store = pos_store::memory::MemoryStore;
    include!("support/plugin_trust_registry_vectors_evaluation.rs");
}
