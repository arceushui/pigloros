//! Public contracts for ADR-060 erasure supporting records.

use ciborium::value::Value;
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionActionV1,
    ErasureAdministrativeResolutionInputV1, ErasureAdministrativeResolutionV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureErrorV1, ErasureLifecycleV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureReferenceV1,
    ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1, ErasureSupportingRecordsInputV1,
    ErasureSupportingRecordsV1, ERASURE_MAX_ATTEMPT_OUTCOMES, ERASURE_PORTABLE_RECORD_MAX_BYTES,
    ERASURE_RETRY_ADMISSION_MAX_BYTES,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn roundtrip<T>(
    value: &T,
    encode: impl Fn(&T) -> Result<Vec<u8>, ErasureErrorV1>,
    decode: impl Fn(&[u8]) -> Result<T, ErasureErrorV1>,
) -> Result<T, ErasureErrorV1> {
    let bytes = encode(value)?;
    let decoded = decode(&bytes)?;
    assert_eq!(encode(&decoded)?, bytes);
    Ok(decoded)
}

fn changed_array(bytes: &[u8], change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let decoded: Result<Value, _> = ciborium::from_reader(bytes);
    assert!(decoded.is_ok());
    let Value::Array(mut fields) = decoded.unwrap_or(Value::Null) else {
        return Vec::new();
    };
    change(&mut fields);
    let mut changed = Vec::new();
    assert!(ciborium::into_writer(&Value::Array(fields), &mut changed).is_ok());
    changed
}

#[test]
fn correction_provenance_roundtrips_and_rejects_shape_changes() -> Result<(), ErasureErrorV1> {
    let record = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: reference(2),
        correction_reason: reference(3),
        authorization_provenance: reference(4),
    })?;
    let decoded = roundtrip(
        &record,
        ErasureCorrectionProvenanceV1::to_canonical_cbor,
        ErasureCorrectionProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.rejected_request(), reference(1));
    assert_eq!(decoded.rejected_terminal_state(), reference(2));
    assert_eq!(decoded.correction_reason(), reference(3));
    assert_eq!(decoded.authorization_provenance(), reference(4));
    assert_eq!(decoded.reference(), record.digest());

    let bytes = record.to_canonical_cbor()?;
    let trailing = changed_array(&bytes, |fields| fields.push(Value::Null));
    let wrong_tag = changed_array(&bytes, |fields| {
        fields[0] = Value::Text("ERCP2".to_owned());
    });
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&wrong_tag),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

fn retry_input() -> ErasureRetryAdmissionInputV1 {
    ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 1,
        source_receipt: Some(reference(2)),
        unresolved_obligations: vec![reference(5), reference(3)],
        command_identities: vec![reference(15), reference(13)],
        policy: reference(6),
        trust: reference(7),
        admitted_position: 20,
        deadline_position: 30,
        authorization_provenance: reference(8),
    }
}

#[test]
fn retry_admission_normalizes_pairs_and_preserves_all_identity_fields() -> Result<(), ErasureErrorV1>
{
    let record = ErasureRetryAdmissionV1::new(retry_input())?;
    let decoded = roundtrip(
        &record,
        ErasureRetryAdmissionV1::to_canonical_cbor,
        ErasureRetryAdmissionV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.attempt_ordinal(), 1);
    assert_eq!(decoded.source_receipt(), Some(reference(2)));
    assert_eq!(
        decoded.unresolved_obligations(),
        &[reference(3), reference(5)]
    );
    assert_eq!(
        decoded.command_identities(),
        &[reference(13), reference(15)]
    );
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.admitted_position(), 20);
    assert_eq!(decoded.deadline_position(), 30);
    assert_eq!(decoded.authorization_provenance(), reference(8));
    assert_eq!(decoded.reference(), record.digest());
    Ok(())
}

#[test]
fn retry_admission_rejects_invalid_ordinals_deadlines_and_obligation_sets() {
    let mut first_with_predecessor = retry_input();
    first_with_predecessor.attempt_ordinal = 0;
    assert_eq!(
        ErasureRetryAdmissionV1::new(first_with_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut later_without_predecessor = retry_input();
    later_without_predecessor.source_receipt = None;
    assert_eq!(
        ErasureRetryAdmissionV1::new(later_without_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut expired_before_admission = retry_input();
    expired_before_admission.deadline_position = 19;
    assert_eq!(
        ErasureRetryAdmissionV1::new(expired_before_admission),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut mismatched_commands = retry_input();
    mismatched_commands.command_identities.pop();
    assert_eq!(
        ErasureRetryAdmissionV1::new(mismatched_commands),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut empty_obligations = retry_input();
    empty_obligations.unresolved_obligations.clear();
    empty_obligations.command_identities.clear();
    assert_eq!(
        ErasureRetryAdmissionV1::new(empty_obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut duplicate_obligations = retry_input();
    duplicate_obligations.unresolved_obligations[1] = reference(5);
    assert_eq!(
        ErasureRetryAdmissionV1::new(duplicate_obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut duplicate_commands = retry_input();
    duplicate_commands.command_identities[1] = reference(15);
    assert_eq!(
        ErasureRetryAdmissionV1::new(duplicate_commands),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn acknowledgement_provenance_roundtrips_with_attempt_scoped_identity() -> Result<(), ErasureErrorV1>
{
    let record =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: reference(1),
            command: reference(2),
            attempt: reference(3),
            obligation: reference(4),
            owner: reference(5),
            scope: reference(6),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(7),
            policy: reference(8),
            trust: reference(9),
        })?;
    let decoded = roundtrip(
        &record,
        ErasureAcknowledgementProvenanceV1::to_canonical_cbor,
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.command(), reference(2));
    assert_eq!(decoded.attempt(), reference(3));
    assert_eq!(decoded.obligation(), reference(4));
    assert_eq!(decoded.owner(), reference(5));
    assert_eq!(decoded.scope(), reference(6));
    assert_eq!(
        decoded.outcome(),
        ErasureAcknowledgementOutcomeV1::Acknowledged
    );
    assert_eq!(decoded.evidence(), reference(7));
    assert_eq!(decoded.policy(), reference(8));
    assert_eq!(decoded.trust(), reference(9));
    assert_eq!(decoded.reference(), record.digest());

    let bytes = record.to_canonical_cbor()?;
    let unknown_outcome = changed_array(&bytes, |fields| {
        fields[8] = Value::Integer(99.into());
    });
    assert_eq!(
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor(&unknown_outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn attempt_outcome_accepts_only_attempt_terminal_destruction_results() -> Result<(), ErasureErrorV1>
{
    let input = ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: reference(2),
        source_receipt: Some(reference(3)),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        selected_obligations: reference(4),
        acknowledgement_inventory: reference(5),
        terminal_position: 40,
        policy: reference(6),
        trust: reference(7),
    };
    let record = ErasureAttemptOutcomeV1::new(input)?;
    let decoded = roundtrip(
        &record,
        ErasureAttemptOutcomeV1::to_canonical_cbor,
        ErasureAttemptOutcomeV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.attempt(), reference(2));
    assert_eq!(decoded.source_receipt(), Some(reference(3)));
    assert_eq!(decoded.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(decoded.selected_obligations(), reference(4));
    assert_eq!(decoded.acknowledgement_inventory(), reference(5));
    assert_eq!(decoded.terminal_position(), 40);
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.reference(), record.digest());

    let mut invalid = input;
    invalid.lifecycle = ErasureLifecycleV1::AwaitingAcknowledgements;
    assert_eq!(
        ErasureAttemptOutcomeV1::new(invalid),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert!(ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        ..input
    })
    .is_ok());
    Ok(())
}

#[test]
fn receipt_provenance_enforces_the_nonbranching_ordinal_shape() -> Result<(), ErasureErrorV1> {
    let input = ErasureReceiptProvenanceInputV1 {
        request: reference(1),
        attempt: reference(2),
        attempt_ordinal: 1,
        predecessor_receipt: Some(reference(3)),
        terminal_state: reference(4),
        evidence_set: reference(5),
        policy: reference(6),
        trust: reference(7),
        issue_position: 50,
    };
    let record = ErasureReceiptProvenanceV1::new(input)?;
    let decoded = roundtrip(
        &record,
        ErasureReceiptProvenanceV1::to_canonical_cbor,
        ErasureReceiptProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.attempt(), reference(2));
    assert_eq!(decoded.attempt_ordinal(), 1);
    assert_eq!(decoded.predecessor_receipt(), Some(reference(3)));
    assert_eq!(decoded.terminal_state(), reference(4));
    assert_eq!(decoded.evidence_set(), reference(5));
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.issue_position(), 50);
    assert_eq!(decoded.reference(), record.digest());

    let mut zero_with_predecessor = input;
    zero_with_predecessor.attempt_ordinal = 0;
    assert_eq!(
        ErasureReceiptProvenanceV1::new(zero_with_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut later_without_predecessor = input;
    later_without_predecessor.predecessor_receipt = None;
    assert_eq!(
        ErasureReceiptProvenanceV1::new(later_without_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut over_bound = input;
    over_bound.attempt_ordinal = ERASURE_MAX_ATTEMPT_OUTCOMES as u64;
    assert_eq!(
        ErasureReceiptProvenanceV1::new(over_bound),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn administrative_resolution_normalizes_evidence_and_rejects_duplicates(
) -> Result<(), ErasureErrorV1> {
    let input = ErasureAdministrativeResolutionInputV1 {
        request: reference(1),
        affected_digests: vec![reference(4), reference(2)],
        action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
        scope_commitment: reference(5),
        policy: reference(6),
        trust: reference(7),
        principal: reference(8),
        authorization_provenance: reference(9),
        reason: reference(10),
        issue_position: 60,
        predecessor_resolution: Some(reference(11)),
    };
    let record = ErasureAdministrativeResolutionV1::new(input.clone())?;
    let decoded = roundtrip(
        &record,
        ErasureAdministrativeResolutionV1::to_canonical_cbor,
        ErasureAdministrativeResolutionV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.affected_digests(), &[reference(2), reference(4)]);
    assert_eq!(
        decoded.action(),
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence
    );
    assert_eq!(decoded.scope_commitment(), reference(5));
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.principal(), reference(8));
    assert_eq!(decoded.authorization_provenance(), reference(9));
    assert_eq!(decoded.reason(), reference(10));
    assert_eq!(decoded.issue_position(), 60);
    assert_eq!(decoded.predecessor_resolution(), Some(reference(11)));
    assert_eq!(decoded.reference(), record.digest());

    let mut duplicate = input.clone();
    duplicate.affected_digests = vec![reference(2), reference(2)];
    assert_eq!(
        ErasureAdministrativeResolutionV1::new(duplicate),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut empty = input;
    empty.affected_digests.clear();
    assert_eq!(
        ErasureAdministrativeResolutionV1::new(empty),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(0)?,
        ErasureAdministrativeResolutionActionV1::CloseContainment
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(1)?,
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(2),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn lifecycle_distinguishes_request_terminality_from_attempt_terminality() {
    assert!(ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::PartialFailure));
    assert!(ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::Complete));
    assert!(!ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::Authorized));
    assert!(!ErasureLifecycleV1::PartialFailure.is_terminal());
    assert!(ErasureLifecycleV1::PartialFailure.is_attempt_terminal());
    assert!(ErasureLifecycleV1::Complete.is_terminal());
    assert!(ErasureLifecycleV1::Rejected.is_terminal());
}

#[test]
fn supporting_record_decoders_enforce_their_public_size_bounds() {
    let oversized = vec![0; ERASURE_PORTABLE_RECORD_MAX_BYTES + 1];
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAttemptOutcomeV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureReceiptProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let oversized_retry = vec![0; ERASURE_RETRY_ADMISSION_MAX_BYTES + 1];
    assert_eq!(
        ErasureRetryAdmissionV1::from_canonical_cbor(&oversized_retry),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn supporting_records_accept_one_active_attempt_and_a_nonbranching_resolution(
) -> Result<(), ErasureErrorV1> {
    let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![reference(2)],
        command_identities: vec![reference(3)],
        policy: reference(4),
        trust: reference(5),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(6),
    })?;
    let acknowledgement =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: reference(1),
            command: reference(3),
            attempt: admission.reference(),
            obligation: reference(2),
            owner: reference(7),
            scope: reference(8),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(9),
            policy: reference(4),
            trust: reference(5),
        })?;
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: reference(1),
            affected_digests: vec![reference(9)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: reference(8),
            policy: reference(4),
            trust: reference(5),
            principal: reference(10),
            authorization_provenance: reference(11),
            reason: reference(12),
            issue_position: 21,
            predecessor_resolution: None,
        })?;
    let records = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        retry_admissions: vec![admission.clone()],
        acknowledgement_provenance: vec![acknowledgement.clone()],
        administrative_resolutions: vec![resolution.clone()],
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    assert!(records.correction_provenance().is_none());
    assert_eq!(records.retry_admissions(), &[admission]);
    assert_eq!(records.acknowledgement_provenance(), &[acknowledgement]);
    assert!(records.attempt_outcomes().is_empty());
    assert!(records.receipts().is_empty());
    assert!(records.receipt_provenance().is_empty());
    assert_eq!(records.administrative_resolutions(), &[resolution]);
    let duplicate_arrival = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        retry_admissions: records.retry_admissions().to_vec(),
        acknowledgement_provenance: vec![
            records.acknowledgement_provenance()[0],
            records.acknowledgement_provenance()[0],
        ],
        administrative_resolutions: records.administrative_resolutions().to_vec(),
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    assert_eq!(duplicate_arrival, records);
    Ok(())
}
