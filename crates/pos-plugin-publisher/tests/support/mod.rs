#![cfg(any(test, feature = "test-support"))]
//! The shared signed-release test world (`test-support` fixtures only).
//!
//! Compiled only with the `test-support` feature, which
//! `scripts/check_test_support_features.py` keeps out of deployable builds.
//! Nothing here grants authority: the world signs and publishes releases with
//! fixture keys, builds trust evidence from independently encoded PTR1, PRV1,
//! and TPS1 records, provisions the Memory adapter of the Plugin trust policy
//! registry, and installs through the real installer. Policy advance and
//! operator rollback are fixtures here because production has no entry point
//! for either.
//!
//! A test of another crate enables the feature from its `[dev-dependencies]`,
//! builds a [`world::World`], publishes a [`release::Shape`], and installs it.
//! [`encoding`] holds the record encoders, [`release`] the drafts and the OCI
//! closure, and [`spy_registry`] the call-recording registry wrapper.

pub mod encoding;
pub mod release;
pub mod spy_registry;
pub mod world;

// Re-exports, so that a test of another crate that gates or installs a release on this world
// needs no direct dependency for the release, anchor and clock types it passes around.
pub use pos_conformance::PluginTrustPolicyAnchorV1;
pub use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
pub use pos_crypto::plugin_trust::TrustedPluginRootAnchorV1;
pub use pos_plugin_release::{
    build_oci_closure_v1, BundleAddressV1, ReleaseClosureInputV1, ReleaseSourceV1,
};

/// A boxed error result, the result type of every fixture step.
pub type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;
