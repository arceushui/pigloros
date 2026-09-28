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

fn read_complete_world_replay(
    sender: &mut pos_runtime::ErasureReadSenderV1<'_>,
    timeline: pos_core::TimelineId,
    range: pos_core::SeqRange,
    bounds: pos_core::EventReadBounds,
) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
    use pos_core::CoreError;

    let head = sender
        .logical_head(timeline)
        .map_err(host_error_to_core)?
        .as_u64();
    if range.to.is_some_and(|to| to.as_u64() > head) {
        return Err(CoreError::ArtifactUnavailable);
    }
    let first = range.from.as_u64().max(1);
    let last = range.to.map_or(head, pos_core::Seq::as_u64);
    if first > head.saturating_add(1) {
        return Err(CoreError::ArtifactUnavailable);
    }
    let expected = if first > last { 0 } else { last - first + 1 };
    // An unrepresentable count cannot fit a verifier's finite max_events.
    let expected = usize::try_from(expected).unwrap_or(usize::MAX);
    if expected > bounds.max_events() {
        return Err(CoreError::ArtifactUnavailable);
    }

    let events = sender
        .read_bounded(timeline, range, bounds)
        .map_err(host_error_to_core)?;
    if events.len() != expected
        || events.iter().enumerate().any(|(index, event)| {
            event.seq.as_u64() != first + u64::try_from(index).unwrap_or(u64::MAX)
        })
    {
        return Err(CoreError::ArtifactUnavailable);
    }
    Ok(events)
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
        host: &mut ErasureExecutionHostV1,
        timeline: pos_core::TimelineId,
    ) -> WorldReplayClosureV1 {
        closure_for_host_consumer(host, timeline, "count")
    }

    pub(crate) fn closure_for_host_consumer(
        host: &mut ErasureExecutionHostV1,
        timeline: pos_core::TimelineId,
        consumer_id: &str,
    ) -> WorldReplayClosureV1 {
        let (_, generation) = test_ok(test_ok(host.read_sender()).read_bounded_at_generation(
            timeline,
            pos_core::store::SeqRange::all(),
            pos_core::store::EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            None,
        ));
        test_ok(WorldReplayClosureV1::test_fixture_for_timeline_consumer(
            timeline,
            Hash::from_bytes(generation.digest()),
            consumer_id,
        ))
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
    use super::{host_error_to_core, read_complete_world_replay};
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        store::{EventReadBounds, SeqRange},
        CoreError, EntityId, ErasureHostErrorV1, Seq,
    };

    #[test]
    fn complete_replay_rejects_ranges_past_head_and_insufficient_bounds() {
        let mut host = crate::test_support::open_exact_host();
        let timeline = {
            let mut commands = crate::test_support::test_ok(host.command_sender());
            let timeline = crate::test_support::test_ok(commands.create_timeline("bounded-replay"));
            let draft = EventDraft::new(
                EntityId::new(),
                Kind::new("test.tick"),
                CanonicalBytes::from_vec(Vec::new()),
            );
            crate::test_support::test_ok(commands.append(timeline.id(), &[draft.clone(), draft]));
            timeline.id()
        };
        let mut sender = crate::test_support::test_ok(host.read_sender());
        let sufficient = EventReadBounds::new(65_536, 128, 8, 2);
        assert!(matches!(
            read_complete_world_replay(
                &mut sender,
                timeline,
                SeqRange::bounded(Seq::ZERO, Seq::from_u64(3)),
                sufficient,
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert!(matches!(
            read_complete_world_replay(
                &mut sender,
                timeline,
                SeqRange::from_seq(Seq::from_u64(4)),
                sufficient,
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert!(matches!(
            read_complete_world_replay(
                &mut sender,
                timeline,
                SeqRange::all(),
                EventReadBounds::new(65_536, 128, 8, 1),
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert!(crate::test_support::test_ok(read_complete_world_replay(
            &mut sender,
            timeline,
            SeqRange::from_seq(Seq::from_u64(3)),
            sufficient,
        ))
        .is_empty());
        assert_eq!(
            crate::test_support::test_ok(read_complete_world_replay(
                &mut sender,
                timeline,
                SeqRange::bounded(Seq::ZERO, Seq::from_u64(1)),
                sufficient,
            ))
            .len(),
            1
        );
        assert_eq!(
            crate::test_support::test_ok(read_complete_world_replay(
                &mut sender,
                timeline,
                SeqRange::all(),
                sufficient,
            ))
            .len(),
            2
        );
        assert!(read_complete_world_replay(
            &mut sender,
            pos_core::TimelineId::new(),
            SeqRange::all(),
            sufficient,
        )
        .is_err());
        assert!(read_complete_world_replay(
            &mut sender,
            timeline,
            SeqRange::all(),
            EventReadBounds::new(65_536, 0, 8, 2),
        )
        .is_err());
    }

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
