//! ADR-114's public cumulative ledger, tested independently of adapters.

use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
use pos_core::{Hash, Seq, TimelineId};
use pos_store::{ForkReplayAuthorityReadErrorV1 as Error, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1, ForkReplayRequirementV1};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn limits_are_finite_and_their_units_are_independent() -> TestResult {
    let limits = ForkReplayReadLimitsV1::new(2, 12, 30, 1_024, 10_000)?;
    assert_eq!(limits.max_fork_depth_per_traversal(), 2);
    assert_eq!(limits.max_ancestry_node_visits(), 12);
    assert_eq!(limits.max_suffix_rows(), 30);
    assert_eq!(limits.max_native_bytes(), 1_024);
    assert_eq!(limits.max_elapsed_micros(), 10_000);
    for (depth, visits, rows, bytes, time) in [
        (0, 1, 1, 1, 1), (1, 0, 1, 1, 1), (1, 1, 0, 1, 1), (1, 1, 1, 0, 1),
        (usize::MAX, 1, 1, 1, 1), (1, usize::MAX, 1, 1, 1),
        (1, 1, usize::MAX, 1, 1), (1, 1, 1, usize::MAX, 1),
        (1, 1, 1, 256 * 1024 * 1024 + 1, 1), (1, 1, 1, 1, 0),
        (1, 1, 1, 1, 30_000_001),
    ] {
        assert_eq!(ForkReplayReadLimitsV1::new(depth, visits, rows, bytes, time), Err(Error::BoundsExceeded));
    }
    assert!(ForkReplayReadLimitsV1::new(1, 1, 1, 256 * 1024 * 1024, 30_000_000).is_ok());
    Ok(())
}

#[test]
fn phases_and_compare_arms_cannot_reset_the_same_ledger() -> TestResult {
    let limits = ForkReplayReadLimitsV1::new(1, 4, 6, 10, 1_000)?;
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    assert_eq!(budget.limits(), limits);
    // Two depth-1 traversals fit exactly; depth is not the cumulative counter.
    for _ in 0..2 {
        budget.charge_node(0)?;
        budget.charge_node(1)?;
    }
    // Arm A consumes most of the shared work; B uses exactly the remainder.
    budget.charge_rows(5)?;
    budget.charge_bytes(9)?;
    budget.charge_rows(1)?;
    budget.charge_bytes(1)?;
    assert_eq!(budget.charge_bytes(1), Err(Error::BoundsExceeded));
    assert_eq!(budget.charge_bytes(0), Err(Error::BoundsExceeded));
    assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
    Ok(())
}

#[test]
fn each_exhausted_dimension_and_arithmetic_overflow_closes_the_ledger() -> TestResult {
    for case in 0..4 {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let rejected = match case {
            0 => { budget.charge_node(1)?; budget.charge_node(1) },
            1 => budget.charge_node(2),
            2 => { budget.charge_rows(1)?; budget.charge_rows(usize::MAX) },
            _ => { budget.charge_bytes(1)?; budget.charge_bytes(usize::MAX) },
        };
        assert_eq!(rejected, Err(Error::BoundsExceeded));
        assert_eq!(budget.charge_rows(0), Err(Error::BoundsExceeded));
    }
    Ok(())
}

#[test]
fn elapsed_checks_share_the_original_guard_epoch_and_reject_regression() -> TestResult {
    for next in [Duration::from_micros(12), Duration::ZERO] {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::from_micros(1), next]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 10)?;
        assert!(ForkReplayReadBudgetV1::new(limits, start, &mut clock).is_err());
    }
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO, Duration::from_micros(10), Duration::from_micros(11)]);
    let start = clock.mark();
    let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 10)?;
    let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
    assert_eq!(budget.check_time(), Err(Error::BoundsExceeded));
    Ok(())
}

#[test]
fn required_coordinates_preserve_local_and_imported_origins() -> TestResult {
    let child = TimelineId::new();
    let record = Hash::from_bytes([1; 32]);
    let origin = Hash::from_bytes([2; 32]);
    for value in [None, Some(origin)] {
        let requirement = ForkReplayRequirementV1::new(child, Seq::ZERO, record, value)?;
        assert_eq!(requirement.child_timeline_id(), child);
        assert_eq!(requirement.publication_logical_head(), Seq::ZERO);
        assert_eq!(requirement.signed_manifest_record_id(), record);
        assert_eq!(requirement.authority_origin_digest(), value);
    }
    assert!(ForkReplayRequirementV1::new(child, Seq::ZERO, Hash::zero(), None).is_err());
    assert!(ForkReplayRequirementV1::new(child, Seq::ZERO, record, Some(Hash::zero())).is_err());
    for error in [Error::Unavailable, Error::CorruptAuthority, Error::BoundsExceeded, Error::StorageUnavailable] {
        assert!(error.to_string().starts_with("Fork Replay"));
    }
    Ok(())
}
