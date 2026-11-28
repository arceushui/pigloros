//! A context's life beyond one recovery window (ADR-129 revision 13,
//! R13.7 I140, as amended by revision 14 RN.5): the State records live to
//! `H_g`, not to the first pass's `H_r`, so a later Reserve past the first
//! pass's recovery window still passes, its outcome horizon is its own, and
//! an owner horizon at or below its decision bound gives 13.

use super::*;
use crate::community::pass_planner::decision_bound;

/// A Reserve of the retained observation on T at the trusted sample
/// `sample`, under the identity `operation`.
fn at(
    sample: u64,
    operation: [u8; 16],
) -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    let call = CommunityReserveInputV1 {
        reservation_operation_id: operation,
        reservation_sample_micros: sample,
        ..reuse()?
    };
    Ok(bound(call)?)
}

/// Stage and apply the Reserve at `sample`, then resolve it by an Abort.
fn reserved_and_aborted(
    domain: &mut MemoryCommunityDomainV1,
    sample: u64,
    operation: [u8; 16],
) -> TestResult {
    let staged = domain.stage_reserve(at(sample, operation)?)?;
    domain.apply_reserve(&SEAL, staged)?;
    let abort = domain.stage_abort(id(1), operation, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    Ok(())
}

/// The outcome horizon `H_r` of the pass `operation` of T.
fn outcome_horizon(
    domain: &MemoryCommunityDomainV1,
    operation: [u8; 16],
) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(domain
        .pass_record(id(1), operation)
        .ok_or("pass record")?
        .reserved
        .outcome_horizon_micros)
}

/// Set the installed recovery window.
fn set_window(
    domain: &mut MemoryCommunityDomainV1,
    micros: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    domain
        .pass_horizons
        .as_mut()
        .ok_or("horizons")?
        .retention
        .recovery_window_micros = micros;
    Ok(())
}

/// I140: a context passes, waits past the first pass's recovery window and
/// passes again without 13, for the fixture's window and for the spec's
/// (`recovery_window` 1 s, wait 3 s). The second pass has its own `H_r`,
/// clamped to `H_g`; the first stays retained and still counts toward the
/// retained outcomes. Discovery of the first pass then gives 13
/// (`original_reserve`, tested with the publication).
#[test]
fn a_context_passes_again_beyond_one_recovery_window() -> TestResult {
    for (window, wait) in [(WINDOW, 1_000_000), (1_000_000, 3_000_000)] {
        let mut domain = domain()?;
        set_recording(&mut domain, 2 * GENERATION_HORIZON)?;
        set_window(&mut domain, window)?;
        reserved_and_aborted(&mut domain, SAMPLE, [1; 16])?;
        let first = outcome_horizon(&domain, [1; 16])?;
        assert_eq!(first, SAMPLE + window);

        // `wait` past the first pass's `H_r`, still before `H_g`.
        let later = first + wait;
        reserved_and_aborted(&mut domain, later, [2; 16])?;
        assert_eq!(
            outcome_horizon(&domain, [2; 16])?,
            GENERATION_HORIZON.min(later + window)
        );
        assert!(outcome_horizon(&domain, [2; 16])? > first);
        // Both passes are retained as resolved outcomes, the first beyond
        // its own `H_r`: they count toward the retained outcomes.
        assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 2);
        assert_eq!(domain.pass_records.len(), 2);
        for operation in [[1; 16], [2; 16]] {
            assert_eq!(
                domain.pass_status(id(1), operation),
                Some(CommunityPassStatusV1::Aborted)
            );
        }
    }
    Ok(())
}

/// R15.8(2): an owner horizon at or below the next pass's decision bound
/// gives 13, and one past it passes: `H_g <= decision_bound` is the refusal.
#[test]
fn an_owner_horizon_at_the_decision_bound_gives_13() -> TestResult {
    let mut domain = domain()?;
    set_recording(&mut domain, 2 * GENERATION_HORIZON)?;
    let bound = decision_bound(SAMPLE);
    // The decision deadline is 27 s (R10.7 4f), from the sample.
    assert_eq!(bound, SAMPLE + 27_000_000);
    for (evidence, refused) in [(bound - 1, true), (bound, true), (bound + 1, false)] {
        set_evidence(&mut domain, evidence)?;
        let refusal = domain.stage_reserve(at(SAMPLE, [3; 16])?).err();
        assert_eq!(
            refusal == Some(Error::EvidenceExpired),
            refused,
            "{evidence}"
        );
        // A pass past the bound is accepted, not merely not 13.
        assert_eq!(refusal.is_none(), !refused, "{evidence}");
    }
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 0);
    Ok(())
}
