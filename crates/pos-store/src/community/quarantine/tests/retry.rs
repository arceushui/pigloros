//! The `SetReason` retry and the control namespace (ADR-129 R16.9(1)-(2),
//! I245, I246): a retry at or after the retained CQO1's horizon gives 13
//! before the CQO1 is opened, and a `SetReason` under a committed
//! materialization's `M_id` gives 4.

use super::super::CommittedQuarantineControlV1;
use super::*;
use pos_core::community_lifecycle::{
    CommunityQuarantineOutcomeInputV1, CommunityQuarantineOutcomeV1,
};

/// The retained control of the `SetReason` `CONTROL`, to tamper with.
fn retained(case: &mut QuarantineCase) -> Fallible<&mut CommittedQuarantineControlV1> {
    Ok(case
        .domain
        .world
        .domain
        .quarantine_controls
        .get_mut(&(target(), CONTROL))
        .ok_or("the SetReason is retained")?)
}

/// I246: a retry of a committed `SetReason` returns the original outcome
/// while its CQO1 is live and gives 13 once the sample is at or after the
/// CQO1's `evidence_not_after_micros`, judged before the CQO1 is opened (the
/// replaced receipt bytes would not open as the sealed record).
#[test]
fn a_retry_at_the_cqo1_horizon_gives_13() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let receipt = set_reason(&mut case, claim(Basis::Artifact))??;
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))??.outcome(),
        receipt.outcome()
    );
    let expired = CommunityQuarantineOutcomeV1::new(CommunityQuarantineOutcomeInputV1 {
        control_operation_id: CONTROL,
        control_request_digest: receipt.request_digest(),
        prior_ledger_digest: None,
        selected_ledger_digest: receipt.selected_ledger_digest(),
        disposition: Disposition::Applied,
        evidence_not_after_micros: 1,
    })?;
    retained(&mut case)?.receipt.outcome = expired.to_canonical_cbor();
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))?.err(),
        Some(Error::EvidenceExpired)
    );
    Ok(())
}

/// An undecodable CQO1 plaintext on the receipt is not a horizon: the retry
/// goes on to the byte-for-byte comparison with the sealed CQO1, which gives
/// 12.
#[test]
fn an_undecodable_receipt_outcome_gives_12() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    set_reason(&mut case, claim(Basis::Artifact))??;
    retained(&mut case)?.receipt.outcome = zeroize::Zeroizing::new(vec![0xff]);
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// I245: a standalone `SetReason` whose `control_operation_id` equals a
/// committed materialization's `M_id` of T gives 4, and commits nothing.
#[test]
fn a_set_reason_under_a_materialization_id_gives_4() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    case.domain
        .world
        .domain
        .materialization_ids
        .insert((target(), CONTROL));
    let before = domain(&case).keys.len();
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))?.err(),
        Some(Error::Conflict)
    );
    assert!(domain(&case).quarantine_controls.is_empty());
    assert_eq!(domain(&case).keys.len(), before);
    Ok(())
}
