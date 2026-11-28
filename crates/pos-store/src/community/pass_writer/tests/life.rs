//! A context's life beyond one recovery window (ADR-129 revision 13,
//! R13.7 I140, as amended by revision 14 RN.5): the State records live to
//! `H_g`, not to the first pass's `H_r`, so a later Reserve past the first
//! pass's recovery window still passes, its outcome horizon is its own, and
//! an owner horizon below its decision bound gives 13.

use super::*;

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

/// I140: a context passes, waits past the first pass's recovery window and
/// passes again without 13. The second pass has its own `H_r`, clamped to
/// `H_g`; the first stays retained and still counts toward the retained
/// outcomes. With `evidence_micros` below the next pass's decision bound the
/// pass gives 13 (R15.8(2)).
#[test]
fn a_context_passes_again_beyond_one_recovery_window() -> TestResult {
    let mut domain = domain()?;
    set_recording(&mut domain, 2 * GENERATION_HORIZON)?;
    reserved_and_aborted(&mut domain, SAMPLE, [1; 16])?;
    assert_eq!(outcome_horizon(&domain, [1; 16])?, OUTCOME);

    // One second past the first pass's `H_r`, still before `H_g`.
    let later = OUTCOME + 1_000_000;
    reserved_and_aborted(&mut domain, later, [2; 16])?;
    assert_eq!(
        outcome_horizon(&domain, [2; 16])?,
        GENERATION_HORIZON.min(later + WINDOW)
    );
    assert!(outcome_horizon(&domain, [2; 16])? > outcome_horizon(&domain, [1; 16])?);
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 2);

    // An owner horizon below the next pass's decision bound ends the
    // context's passes with 13.
    let last = later + 1_000;
    set_evidence(&mut domain, last)?;
    assert_eq!(
        domain.stage_reserve(at(last, [3; 16])?).err(),
        Some(Error::EvidenceExpired)
    );
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 2);
    Ok(())
}
