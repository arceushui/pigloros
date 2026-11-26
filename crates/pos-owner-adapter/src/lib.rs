//! The ADR-091 owner adapter behind the ADR-110 owner-bridge ports.
//!
//! It keeps the subject root key, its `SubjectKeyWrapV1` and the
//! `SubjectCredentialBindingV1` on the owner side, runs the ADR-137 P3
//! staging order for enrollment and the ADR-110 §8 unlock steps. It lives
//! apart from `pos-owner-bridge` so that the Gateway's dependency graph never
//! contains it.
//!
//! Until subject-encryption activation (ADR-110 E15, #1438) every item is
//! compiled only for this crate's tests or with the `test-support` feature,
//! and only on Linux, where the E16 encryptor lock exists. A normal build of
//! this crate is empty.

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub mod enrollment;
// The artifact inventory both adapters read. Its items are crate-only, but in
// a private module Clippy's `redundant_pub_crate` rejects `pub(crate)` and
// `pub(super)` while `pub` trips `unreachable_pub`; public module reachability
// satisfies both, as for pos-crypto's `subject_cbor`.
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
#[doc(hidden)]
pub mod inventory;
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub mod unlock;

/// The relying party of every owner credential (ADR-097 §5).
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
const RP_ID: &str = "localhost";
