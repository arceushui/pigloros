//! The deployment-owned executor an ELB1 bundle binds (ADR-136 §4; owner
//! decision Q6 of 2026-11-17 on #1412).
//!
//! The binding is deterministic and reviewable: an executor id and
//! `CA("ELEXV1", [executor_id, version])`. The version changes only when the
//! owner semantics of the Local executor change, and a new version needs a
//! re-issued bundle.

use pos_core::{ErasureReferenceV1, LocalErasureExecutionBindingV1};

/// The ELB1 `executor_id` of the Local erasure executor.
pub const LOCAL_ERASURE_EXECUTOR_ID_V1: &str = "pigloros.local-erasure-executor";

/// The owner-semantics version of the Local erasure executor.
pub const LOCAL_ERASURE_EXECUTOR_VERSION_V1: u64 = 1;

/// The ELB1 `executor_version_digest` of the Local erasure executor.
///
/// It is `CA("ELEXV1", [LOCAL_ERASURE_EXECUTOR_ID_V1,
/// LOCAL_ERASURE_EXECUTOR_VERSION_V1])`; a public test recomputes it with
/// `local_erasure_executor_version_v1`.
pub const LOCAL_ERASURE_EXECUTOR_VERSION_DIGEST_V1: ErasureReferenceV1 =
    ErasureReferenceV1::from_digest(EXECUTOR_VERSION_DIGEST);

const EXECUTOR_VERSION_DIGEST: [u8; 32] = [
    0x7c, 0x59, 0xc7, 0x9f, 0x1d, 0x7a, 0x59, 0x0c, 0x39, 0x82, 0x6b, 0xd0, 0xc0, 0xbf, 0x7d, 0xba,
    0x10, 0xc5, 0x96, 0x9a, 0xb6, 0x69, 0x4b, 0x05, 0xa9, 0xc3, 0x73, 0xcb, 0x9f, 0x37, 0x60, 0x5f,
];

/// The execution binding of the Local erasure executor this binary
/// composes, which provisioning writes into ELB1 and composition requires.
#[must_use]
pub fn local_erasure_execution_binding_v1() -> LocalErasureExecutionBindingV1 {
    LocalErasureExecutionBindingV1 {
        executor_id: LOCAL_ERASURE_EXECUTOR_ID_V1.to_owned(),
        executor_version_digest: LOCAL_ERASURE_EXECUTOR_VERSION_DIGEST_V1,
    }
}
