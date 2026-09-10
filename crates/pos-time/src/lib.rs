#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-time` — timeline replay, snapshots, and fork-comparison utilities.
//!
//! Builds on top of `pos-core` (traits/types), `pos-store` (backend factory),
//! and `pos-state` (projection registry).
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`mod@replay`] | Fold all (or partial) events through a `ProjectionRegistry` |
//! | [`mod@snapshot`] | Capture and verify state snapshots |
//! | [`compare()`] | Diff two divergent timelines after a fork |
//! | [`merge()`] | Conflict-free / strategy-guided timeline merge |
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod compare;
pub mod merge;
pub mod replay;
pub mod snapshot;

pub use compare::{compare, ForkDiff};
pub use merge::{
    can_merge_conflict_free, merge, merge_with_strategy, MergeConflict, MergeResult, MergeSpec,
    MergeStrategy,
};
pub use replay::{replay, replay_at};
pub use snapshot::{snapshot, verify_snapshot_consistency, Snapshot, SnapshotError};

const fn host_error_to_core(error: pos_core::ErasureHostErrorV1) -> pos_core::CoreError {
    match error {
        pos_core::ErasureHostErrorV1::AccessFrozen => pos_core::CoreError::ErasureAccessFrozen,
        pos_core::ErasureHostErrorV1::RecoveryUnavailable
        | pos_core::ErasureHostErrorV1::StaleGeneration => {
            pos_core::CoreError::ErasureContainmentUnavailable
        }
        pos_core::ErasureHostErrorV1::AuthorizationDenied
        | pos_core::ErasureHostErrorV1::Conflict
        | pos_core::ErasureHostErrorV1::AdapterFailure => pos_core::CoreError::ArtifactUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::host_error_to_core;
    use pos_core::{CoreError, ErasureHostErrorV1};

    #[test]
    fn host_errors_map_to_stable_public_time_errors() {
        assert!(matches!(
            host_error_to_core(ErasureHostErrorV1::AccessFrozen),
            CoreError::ErasureAccessFrozen
        ));
        for host in [
            ErasureHostErrorV1::RecoveryUnavailable,
            ErasureHostErrorV1::StaleGeneration,
        ] {
            assert!(matches!(
                host_error_to_core(host),
                CoreError::ErasureContainmentUnavailable
            ));
        }
        for host in [
            ErasureHostErrorV1::AuthorizationDenied,
            ErasureHostErrorV1::Conflict,
            ErasureHostErrorV1::AdapterFailure,
        ] {
            assert!(matches!(
                host_error_to_core(host),
                CoreError::ArtifactUnavailable
            ));
        }
    }
}
