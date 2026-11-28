//! The `(T, M_id)` Control-namespace index (ADR-129 R9.7, R16.9(4)): a
//! committed minting Reserve inserts its materialization's control identity.
//! The reverse check (a materialization whose `M_id` equals a committed
//! control identity gives 4) is the observation preparation's, 5f
//! (`pass_planner/tests.rs`), and the writer repeats it at the stage and at
//! the apply: the prepare, the stage and the apply are separate calls, and a
//! control of T may commit between them (no fence keeps a Reserve and a
//! control from interleaving before the Reserve is pending).

use super::*;
use pos_core::community_lifecycle::community_observation_materialization_id_v1;

/// The `M_id` of T's materialization under `operation`.
fn m_id(operation: [u8; 16]) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    Ok(community_observation_materialization_id_v1(
        id(1),
        operation,
    )?)
}

/// A committed minting Reserve indexes its `M_id`, derived from T and the
/// reservation operation; a reusing Reserve mints no materialization and
/// indexes nothing.
#[test]
fn a_minting_reserve_indexes_its_materialization_id() -> TestResult {
    let mut reusing = domain()?;
    let staged = reusing.stage_reserve(reuse()?)?;
    reusing.apply_reserve(&SEAL, staged)?;
    assert!(reusing.materialization_ids.is_empty());
    let mut minting = domain()?;
    let staged = minting.stage_reserve(input()?)?;
    minting.apply_reserve(&SEAL, staged)?;
    assert_eq!(
        minting.materialization_ids.iter().collect::<Vec<_>>(),
        [&(id(1), m_id(OPERATION)?)]
    );
    Ok(())
}

/// A retained control of T under the `M_id` of `operation`.
fn control(domain: &mut MemoryCommunityDomainV1, operation: [u8; 16]) -> TestResult {
    let identity = m_id(operation)?;
    domain.quarantine_controls.insert(
        (id(1), identity),
        crate::community::quarantine::CommittedQuarantineControlV1::reset_at(id(1), identity),
    );
    Ok(())
}

/// R16.9(4): a control committed between the prepare and the stage gives 4
/// with nothing staged; the reusing Reserve mints no `M_id` and is not
/// refused.
#[test]
fn a_control_committed_before_the_stage_conflicts() -> TestResult {
    let mut domain = domain()?;
    let before = snapshot(&domain)?;
    control(&mut domain, OPERATION)?;
    assert_eq!(domain.stage_reserve(input()?).err(), Some(Error::Conflict));
    assert_eq!(snapshot(&domain)?, before);
    assert!(domain.materialization_ids.is_empty());
    assert!(domain.stage_reserve(reuse()?).is_ok());
    Ok(())
}

/// A control committed between the stage and the apply gives 4 at the
/// apply, which publishes nothing.
#[test]
fn a_control_committed_before_the_apply_conflicts() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    let before = snapshot(&domain)?;
    control(&mut domain, OPERATION)?;
    assert_eq!(
        domain.apply_reserve(&SEAL, staged).err(),
        Some(Error::Conflict)
    );
    assert_eq!(snapshot(&domain)?, before);
    assert!(domain.materialization_ids.is_empty());
    Ok(())
}
