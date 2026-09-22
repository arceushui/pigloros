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

fn require_world_replay(
    sender: &mut pos_runtime::ErasureReadSenderV1<'_>,
    closure: &pos_core::WorldReplayClosureV1,
    requested_use: &pos_runtime::WorldReplayUseV1,
) -> Result<pos_core::EventReadBounds, pos_core::CoreError> {
    let verified = sender
        .admit_world_replay(closure, requested_use)
        .map_err(host_error_to_core)?;
    verified
        .require_authoritative_use()
        .map_err(|_| pos_core::CoreError::ArtifactUnavailable)?;
    Ok(verified.read_bounds())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_support {
    use std::{fmt::Debug, sync::Arc};

    use pos_core::{
        ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1, Hash,
        WorldReplayClosureV1,
    };
    use pos_runtime::{
        ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
        WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
    };
    use pos_store::StoreConfig;

    struct ExactWorldReplayVerifier;

    impl WorldReplayVerifierV1 for ExactWorldReplayVerifier {
        fn verify(
            &self,
            closure: &WorldReplayClosureV1,
            requested_use: &WorldReplayUseV1,
            inventory_generation: ErasureReferenceV1,
        ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
            Ok(pos_runtime::world_replay::test_verified_world_replay(
                closure,
                requested_use,
                inventory_generation,
                ErasureReplayClaimV1::Exact,
            ))
        }
    }

    pub(crate) fn open_exact_host() -> ErasureExecutionHostV1 {
        let composition = ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(ExactWorldReplayVerifier));
        test_ok(ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        ))
    }

    pub(crate) fn closure_for_host(
        host: &ErasureExecutionHostV1,
        timeline: pos_core::TimelineId,
    ) -> WorldReplayClosureV1 {
        let generation = test_ok(host.containment_gate().inventory_generation());
        test_ok(
            WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                timeline,
                Hash::from_bytes(generation.digest()),
            ),
        )
    }

    pub(crate) fn test_ok<T, E: Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected test fixture error: {error:?}"
            )))
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
