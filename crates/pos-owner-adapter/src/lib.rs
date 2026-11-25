//! The ADR-091 owner adapter behind the ADR-110 owner-bridge ports.
//!
//! It keeps the subject root key, its `SubjectKeyWrapV1` and the
//! `SubjectCredentialBindingV1` on the owner side, and runs the ADR-137 P3
//! staging order. It lives apart from `pos-owner-bridge` so that the Gateway's
//! dependency graph never contains it.
//!
//! Until subject-encryption activation (ADR-110 E15, #1438) every item is
//! compiled only for this crate's tests or with the `test-support` feature,
//! and only on Linux, where the E16 encryptor lock exists. A normal build of
//! this crate is empty.

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub mod enrollment;
