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

/// A boxed error result, the result type of every fixture step.
pub type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;
