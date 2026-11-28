//! The `(T, M_id)` Control-namespace index (ADR-129 R9.7, R16.9(4)): a
//! committed minting Reserve inserts its materialization's control identity.
//! The reverse check (a materialization whose `M_id` equals a committed
//! control identity gives 4) is the observation preparation's, 5f
//! (`observation/tests.rs`).

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
