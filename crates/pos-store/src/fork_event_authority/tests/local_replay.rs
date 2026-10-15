//! Local publication evidence through the same public native Replay read port.
//!
//! This diagnostic control does not authorize a protected Replay release.

use super::{
    commit_counting_signer, create_lifecycle, publication_fixture, PublicationTestStoreV1,
};
use crate::{
    memory::MemoryStore, ForkReplayAuthorityReadErrorV1, ForkReplayAuthorityReadPortV1,
    ForkReplayReadBudgetV1, ForkReplayReadLimitsV1, ForkReplayRequirementV1,
};
use pos_core::{
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1,
    ErasureProtectedEffectIntervalV1, Hash, Seq,
};
use std::{error::Error, time::Duration};

fn local_original_epoch_refusals<S: ForkReplayAuthorityReadPortV1>(
    store: &S,
    requirement: &ForkReplayRequirementV1,
    expected_operation: &[u8],
    limits: ForkReplayReadLimitsV1,
) -> Result<(), Box<dyn Error>> {
    for final_offset in [Duration::ZERO, Duration::from_secs(2)] {
        let mut completed = false;
        let mut refused = false;
        for prefix in 2..2048 {
            // A bad sample is followed by in-budget ticks. Native error
            // translation must not erase the original ledger's refusal.
            let mut probe_clock = ScriptedGuardMonotonicSourceV1::new(
                std::iter::repeat_n(Duration::from_millis(1), prefix)
                    .chain([final_offset, Duration::from_millis(1)]),
            );
            let probe_start = probe_clock.mark();
            let mut probe_budget =
                ForkReplayReadBudgetV1::new(limits, probe_start, &mut probe_clock)?;
            match store.validate_fork_replay_authority(requirement, &mut probe_budget) {
                Ok(evidence) => {
                    assert_eq!(evidence.requirement(), *requirement);
                    assert_eq!(evidence.operation_bytes(), expected_operation);
                    completed = true;
                    break;
                }
                Err(error) => {
                    assert_eq!(
                        error,
                        ForkReplayAuthorityReadErrorV1::BoundsExceeded,
                        "prefix={prefix}, terminal offset={final_offset:?}",
                    );
                    assert!(probe_budget.check_time().is_err());
                    refused = true;
                }
            }
        }
        assert!(
            refused,
            "the Local reader must observe the bad clock sample"
        );
        assert!(completed, "the Local reader must reach its known positive");
    }
    Ok(())
}

fn local_publication_evidence<S>(
    store: &mut S,
    expected_interval: ErasureProtectedEffectIntervalV1,
) -> Result<(), Box<dyn Error>>
where
    S: PublicationTestStoreV1 + ForkReplayAuthorityReadPortV1 + ErasureInventoryPersistencePortV1,
{
    let lifecycle = create_lifecycle(store)?;
    let fixture = publication_fixture(store, &lifecycle, 122, 0)?;
    let (receipt, signatures) = commit_counting_signer(store, &fixture, fixture.request.clone());
    assert_eq!(signatures, 1);
    let receipt = receipt?;
    let child = lifecycle.fork.child_id;
    let committed = store.read_committed(child, 0)?;
    assert_eq!(committed.receipt, receipt);
    assert_ne!(committed.record_id, Hash::zero());
    assert!(committed.authority_origin_digest.is_none());
    let expected_bytes = committed.operation.to_canonical_cbor();
    let requirement = ForkReplayRequirementV1::new(child, Seq::ZERO, committed.record_id, None)?;
    let limits = ForkReplayReadLimitsV1::new(8, 128, 4_096, 8 * 1024 * 1024, 1_000_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let started = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
    let interval = store.begin_protected_effect_interval()?;
    assert_eq!(interval, expected_interval);
    let mut remaining = budget.remaining_native_bytes();
    for _ in 0..2 {
        let evidence = store.validate_fork_replay_authority(&requirement, &mut budget)?;
        assert_eq!(evidence.requirement(), requirement);
        assert_eq!(evidence.operation_bytes(), expected_bytes.as_slice());
        assert_eq!(
            evidence.operation_id(),
            committed.operation.input().operation_id
        );
        assert_eq!(
            evidence.admission_digest(),
            committed.operation.input().admission_digest
        );
        // Observe continued charging, not a measured-ledger oracle for limits.
        assert!(budget.remaining_native_bytes() < remaining);
        remaining = budget.remaining_native_bytes();
        assert_eq!(budget.check_time(), Ok(()));
    }
    local_original_epoch_refusals(store, &requirement, &expected_bytes, limits)?;
    store.finish_protected_effect_interval(
        interval,
        ErasureProtectedEffectDispositionV1::Rollback,
    )?;
    assert_eq!(store.read_committed(child, 0)?, committed);
    Ok(())
}

#[test]
fn local_memory_native_replay_evidence_matches_the_published_operation(
) -> Result<(), Box<dyn Error>> {
    local_publication_evidence(
        &mut MemoryStore::new(),
        ErasureProtectedEffectIntervalV1::Unowned,
    )
}

#[cfg(feature = "sqlite")]
#[test]
fn local_sqlite_native_replay_evidence_matches_the_published_operation(
) -> Result<(), Box<dyn Error>> {
    local_publication_evidence(
        &mut crate::sqlite::SqliteStore::open_in_memory()?,
        ErasureProtectedEffectIntervalV1::Owned,
    )
}
