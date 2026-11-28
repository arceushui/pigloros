//! The `(T, M_id)` Control-namespace index (ADR-129 R9.7, R10.7 5f, R16.9
//! (3)-(4), I251): a committed minting Reserve inserts its materialization's
//! control identity, and a materialization whose `M_id` equals a committed
//! control identity of T gives 4 with nothing committed.

use super::*;
use crate::community::quarantine::{
    CommittedQuarantineControlV1, CommunityQuarantineReceiptV1, ResetBoundV1, RetainedControlV1,
};
use pos_core::community_lifecycle::{community_observation_materialization_id_v1, ArtifactRefV1};
use zeroize::Zeroizing;

/// The `M_id` of T's materialization under `operation`.
fn m_id(operation: [u8; 16]) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    Ok(community_observation_materialization_id_v1(
        id(1),
        operation,
    )?)
}

/// A retained reset under `identity`, standing for any committed control.
fn control_at(identity: [u8; 16]) -> CommittedQuarantineControlV1 {
    let reference = ArtifactRefV1 {
        schema_id: 1,
        byte_length: 1,
        digest: [1; 32],
    };
    CommittedQuarantineControlV1 {
        kind: RetainedControlV1::Reset(ResetBoundV1 {
            key: hash(1),
            expected_ledger: hash(2),
            reasons: Vec::new(),
            expected_generation: GENERATION,
            expected_head: hash(30),
            trust_snapshot_digest: hash(3),
            principal_ref: reference,
            authorization_ref: reference,
            authorization_not_after_micros: 1,
        }),
        receipt: CommunityQuarantineReceiptV1 {
            timeline: id(1),
            control_operation_id: identity,
            request_digest: hash(4),
            selected_ledger_digest: hash(5),
            already_quarantined: false,
            outcome: Zeroizing::new(Vec::new()),
        },
    }
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

/// I251: a materialization whose `M_id` equals a committed control identity
/// of T gives 4 and commits nothing; another Timeline's identity, another
/// reservation operation and a reusing Reserve are not refused.
#[test]
fn a_materialization_id_equal_to_a_control_id_gives_4() -> TestResult {
    let mut domain = domain()?;
    domain
        .quarantine_controls
        .insert((id(1), m_id(OPERATION)?), control_at(m_id(OPERATION)?));
    let before = snapshot(&domain)?;
    assert_eq!(domain.stage_reserve(input()?).err(), Some(Error::Conflict));
    assert_eq!(snapshot(&domain)?, before);
    assert!(domain.stage_reserve(reuse()?).is_ok());
    // The same identity on another Timeline is that Timeline's.
    domain.quarantine_controls.clear();
    domain
        .quarantine_controls
        .insert((id(2), m_id(OPERATION)?), control_at(m_id(OPERATION)?));
    assert!(domain.stage_reserve(input()?).is_ok());
    Ok(())
}
