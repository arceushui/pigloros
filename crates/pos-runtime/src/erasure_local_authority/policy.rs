//! The ELP1 policy compiled into this binary (ADR-136 §4; owner decision 9
//! of 2026-11-15 on #1403).
//!
//! Composition requires an installed bundle to name exactly this policy, so
//! a changed constant here is a new `CA(ELP1)` and needs a re-issued bundle.

use pos_core::{ArtifactDataClassV1, ErasureErrorV1, ErasureReferenceV1, LocalErasurePolicyV1};

/// Automatic retries of a transient owner result.
pub const LOCAL_ERASURE_AUTO_RETRY_MAX_V1: u64 = 3;

/// The lifetime attempt quota of one request.
pub const LOCAL_ERASURE_QUOTA_ATTEMPTS_V1: u64 = 64;

/// Request heads reserved store-wide for administrative resolution and
/// corrected submission.
pub const LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1: u64 = 512;

/// Re-prepares of one lifecycle step before the driver defers it.
pub const LOCAL_ERASURE_MAX_REPREPARE_V1: u64 = 3;

/// The ELP1 this binary serves.
///
/// Every class but the two destruction-eligible ones is always retained
/// (ADR-136 §3). The classification rows wait for the owner's
/// `artifact_class` mapping (#1411), which the ADR §3 and §5 tables leave
/// open, so the policy holds none yet.
#[must_use]
pub fn compiled_local_erasure_policy_v1() -> LocalErasurePolicyV1 {
    LocalErasurePolicyV1 {
        retained_classes: vec![
            ArtifactDataClassV1::PublicRecord,
            ArtifactDataClassV1::AggregateData,
            ArtifactDataClassV1::StructuralAuditMetadata,
        ],
        classification: Vec::new(),
        auto_retry_max: LOCAL_ERASURE_AUTO_RETRY_MAX_V1,
        quota_attempts: LOCAL_ERASURE_QUOTA_ATTEMPTS_V1,
        store_request_reserve: LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1,
        max_reprepare: LOCAL_ERASURE_MAX_REPREPARE_V1,
    }
}

/// `CA(ELP1)` of [`compiled_local_erasure_policy_v1`], the policy digest an
/// installed bundle must name.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn compiled_local_erasure_policy_reference_v1() -> Result<ErasureReferenceV1, ErasureErrorV1> {
    compiled_local_erasure_policy_v1().reference()
}
