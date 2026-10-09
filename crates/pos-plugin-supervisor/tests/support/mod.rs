#![cfg(any(test, feature = "test-support"))]
//! The pass harness: a registry over an in-memory store, community Drivers registered on the
//! probe or real worker, and the admission ports of the pass vectors (ADR-061 revision 7, #584).
//!
//! Compiled only with the `test-support` feature, which `scripts/check_test_support_features.py`
//! keeps out of deployable builds. Nothing here grants authority. The harness stays under
//! `tests/support`, outside the production-coverage glob, and is included by `#[path]` from
//! `src/lib.rs`; `cargo-shear` is told about its optional dependency and its root file through
//! `[package.metadata.cargo-shear]`. The worker program is a parameter of [`world::World::new`],
//! so the supervisor's tests pass the probe and another crate's tests pass the real worker.
//!
//! [`world::World`] registers Drivers built from the `test-support` fixtures (`add`) or from a
//! gated release (`add_gated`), stages and admits passes by hand, and prepares the inputs of
//! `CommunityPluginHostV1::run_pass`. [`ports`] holds the admission-port wrappers.

pub mod ports;
pub mod world;

pub use ports::{LostPort, StampedPort};
pub use world::{initial, GatedMember, GatedSpec, PanickingSource, Prepared, Source, Staged, World};
