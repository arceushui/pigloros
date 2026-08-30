//! Public contracts for ADR-060 erasure supporting records.

use ciborium::value::Value;
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureCoordinatorRecordPartsV1,
    ErasureCoordinatorRecordV1, ErasureCorrectionProvenanceInputV1, ErasureCorrectionProvenanceV1,
    ErasureErrorV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1,
    ErasureLifecycleV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1, ErasureScopeV1,
    ErasureStateV1, ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1,
    ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS, ERASURE_MAX_ATTEMPT_OUTCOMES,
    ERASURE_PORTABLE_RECORD_MAX_BYTES, ERASURE_RETRY_ADMISSION_MAX_BYTES,
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

fn assert_each_field_rejects<T>(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let decoded: Value =
        ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(fields) = decoded else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    for (index, _) in fields.iter().enumerate() {
        let malformed = changed_array(bytes, |changed| changed[index] = Value::Bool(false));
        assert!(decode(&malformed).is_err(), "field {index} accepted a bool");
    }
    Ok(())
}

const fn required_target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(30),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(31),
        replica_set: reference(32),
        replica_id: reference(33),
    }
}

const fn acknowledgement() -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        target: required_target(),
        owner: reference(33),
        evidence: reference(34),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    }
}

const fn inventory() -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: required_target(),
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(35),
            owner: reference(36),
            acknowledgements: reference(37),
            provenance: reference(38),
        },
        retained_disclosure: reference(39),
    }
}

fn complete_receipt(request: ErasureReferenceV1) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request,
        terminal_state: reference(40),
        coordinator: reference(41),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 10,
        required_targets: vec![required_target()],
        acknowledgements: vec![acknowledgement()],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory()],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(4),
        trust: reference(5),
        provenance: reference(42),
        issue_position: 20,
        signature: reference(43),
        receipt_digest: reference(0),
    })
}

fn initial_admission(
    request: ErasureReferenceV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![reference(2)],
        command_identities: vec![reference(3)],
        policy: reference(4),
        trust: reference(5),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(6),
    })
}

const fn acknowledgement_provenance_input(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
) -> ErasureAcknowledgementProvenanceInputV1 {
    ErasureAcknowledgementProvenanceInputV1 {
        request,
        command: reference(3),
        attempt,
        obligation: reference(2),
        owner: reference(33),
        scope: reference(44),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        evidence: reference(34),
        policy: reference(4),
        trust: reference(5),
    }
}

fn administrative_resolution(
    request: ErasureReferenceV1,
    predecessor_resolution: Option<ErasureReferenceV1>,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request,
        affected_digests: vec![reference(48)],
        action: ErasureAdministrativeResolutionActionV1::CloseContainment,
        scope_commitment: reference(49),
        policy: reference(4),
        trust: reference(5),
        principal: reference(50),
        authorization_provenance: reference(51),
        reason: reference(52),
        issue_position: 21,
        predecessor_resolution,
    })
}

fn complete_supporting_input(
    request: ErasureReferenceV1,
) -> Result<ErasureSupportingRecordsInputV1, ErasureErrorV1> {
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(70),
        rejected_terminal_state: reference(71),
        correction_reason: reference(72),
        authorization_provenance: reference(73),
    })?;
    let admission = initial_admission(request)?;
    let receipt = complete_receipt(request)?;
    let attempt = admission.reference();
    Ok(ErasureSupportingRecordsInputV1 {
        correction_provenance: Some(correction),
        retry_admissions: vec![admission],
        acknowledgement_provenance: vec![ErasureAcknowledgementProvenanceV1::new(
            acknowledgement_provenance_input(request, attempt),
        )?],
        attempt_outcomes: vec![ErasureAttemptOutcomeV1::new(
            ErasureAttemptOutcomeInputV1 {
                request,
                attempt,
                source_receipt: None,
                lifecycle: ErasureLifecycleV1::Complete,
                selected_obligations: reference(45),
                acknowledgement_inventory: reference(46),
                terminal_position: 20,
                policy: reference(4),
                trust: reference(5),
            },
        )?],
        receipts: vec![receipt.clone()],
        receipt_provenance: vec![ErasureReceiptProvenanceV1::new(
            ErasureReceiptProvenanceInputV1 {
                request,
                attempt,
                attempt_ordinal: 0,
                predecessor_receipt: None,
                terminal_state: receipt.terminal_state(),
                evidence_set: reference(47),
                policy: reference(4),
                trust: reference(5),
                issue_position: 20,
            },
        )?],
        administrative_resolutions: vec![administrative_resolution(request, None)?],
    })
}

#[test]
fn correction_provenance_roundtrips_and_rejects_shape_changes() -> Result<(), ErasureErrorV1> {
    let record = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: reference(2),
        correction_reason: reference(3),
        authorization_provenance: reference(4),
    })?;
    assert_ne!(record.reference(), reference(0));
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
    assert_ne!(record.reference(), reference(0));
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

    let mut deadline_at_admission = retry_input();
    deadline_at_admission.deadline_position = deadline_at_admission.admitted_position;
    assert!(ErasureRetryAdmissionV1::new(deadline_at_admission).is_ok());

    let mut ordinal_at_bound = retry_input();
    ordinal_at_bound.attempt_ordinal = ERASURE_MAX_ATTEMPT_OUTCOMES as u64;
    assert_eq!(
        ErasureRetryAdmissionV1::new(ordinal_at_bound),
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

    let mut oversized_obligations = retry_input();
    oversized_obligations.unresolved_obligations =
        vec![reference(20); ERASURE_MAX_INVENTORY_RESULTS + 1];
    oversized_obligations.command_identities =
        vec![reference(21); ERASURE_MAX_INVENTORY_RESULTS + 1];
    assert_eq!(
        ErasureRetryAdmissionV1::new(oversized_obligations),
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
    assert_ne!(record.reference(), reference(0));
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
    assert_ne!(record.reference(), reference(0));
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
    assert_ne!(record.reference(), reference(0));
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
    assert_ne!(record.reference(), reference(0));
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
    assert!(ErasureLifecycleV1::PartialFailure.blocks_generic_timeline_access());
    assert!(!ErasureLifecycleV1::Rejected.blocks_generic_timeline_access());
}

#[test]
fn supporting_record_decoders_enforce_their_public_size_bounds() {
    assert_eq!(ERASURE_PORTABLE_RECORD_MAX_BYTES, 1_048_576);
    assert_eq!(ERASURE_RETRY_ADMISSION_MAX_BYTES, 16_777_216);

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
        acknowledgement_provenance: vec![acknowledgement],
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

#[test]
fn complete_supporting_records_expose_every_persisted_collection() -> Result<(), ErasureErrorV1> {
    let records = ErasureSupportingRecordsV1::new(complete_supporting_input(reference(1))?)?;
    assert!(records.correction_provenance().is_some());
    assert_eq!(records.retry_admissions().len(), 1);
    assert_eq!(records.acknowledgement_provenance().len(), 1);
    assert_eq!(records.attempt_outcomes().len(), 1);
    assert_eq!(records.receipts().len(), 1);
    assert_eq!(records.receipt_provenance().len(), 1);
    assert_eq!(records.administrative_resolutions().len(), 1);
    Ok(())
}

#[test]
fn every_portable_decoder_rejects_a_wrong_type_in_every_field() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let correction = input
        .correction_provenance
        .as_ref()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_each_field_rejects(
        &correction.to_canonical_cbor()?,
        ErasureCorrectionProvenanceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.retry_admissions[0].to_canonical_cbor()?,
        ErasureRetryAdmissionV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.acknowledgement_provenance[0].to_canonical_cbor()?,
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.attempt_outcomes[0].to_canonical_cbor()?,
        ErasureAttemptOutcomeV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.receipt_provenance[0].to_canonical_cbor()?,
        ErasureReceiptProvenanceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.administrative_resolutions[0].to_canonical_cbor()?,
        ErasureAdministrativeResolutionV1::from_canonical_cbor,
    )?;
    Ok(())
}

#[test]
fn portable_reference_decoders_reject_duplicate_entries() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let retry = input.retry_admissions[0].to_canonical_cbor()?;
    for field in [5, 6] {
        let duplicate = changed_array(&retry, |fields| {
            fields[field] =
                Value::Array(vec![Value::Bytes(vec![9; 32]), Value::Bytes(vec![9; 32])]);
        });
        assert_eq!(
            ErasureRetryAdmissionV1::from_canonical_cbor(&duplicate),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    let resolution = input.administrative_resolutions[0].to_canonical_cbor()?;
    let duplicate = changed_array(&resolution, |fields| {
        fields[3] = Value::Array(vec![Value::Bytes(vec![9; 32]), Value::Bytes(vec![9; 32])]);
    });
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&duplicate),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn portable_decoders_reject_unknown_closed_enum_codes() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let outcome = changed_array(&input.attempt_outcomes[0].to_canonical_cbor()?, |fields| {
        fields[5] = Value::Integer(99.into());
    });
    assert_eq!(
        ErasureAttemptOutcomeV1::from_canonical_cbor(&outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let resolution = changed_array(
        &input.administrative_resolutions[0].to_canonical_cbor()?,
        |fields| {
            fields[4] = Value::Integer(99.into());
        },
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&resolution),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

fn coordinator_with_complete_supporting_records(
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(70),
        rejected_terminal_state: reference(71),
        correction_reason: reference(72),
        authorization_provenance: reference(73),
    })?;
    let request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(60),
        subject: reference(61),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(62)],
        requester: reference(63),
        authorization: reference(64),
        policy: reference(65),
        request_position: 10,
        horizon_position: 20,
        provenance: correction.reference(),
    })?;
    let coordinator = reference(66);
    let state = ErasureStateV1::submitted(request.reference(), coordinator, reference(67))?;
    let supporting_records =
        ErasureSupportingRecordsV1::new(complete_supporting_input(request.reference())?)?;
    ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request,
            state,
            reserved_targets: Vec::new(),
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            freeze_admission: None,
            dispatch_provenance: None,
            supporting_records,
        },
        coordinator,
    )
}

fn changed_supporting_records(bytes: &[u8], change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    changed_array(bytes, |record_fields| {
        let Value::Array(supporting_fields) = &mut record_fields[12] else {
            return;
        };
        change(supporting_fields);
    })
}

#[test]
fn coordinator_decoder_exercises_every_supporting_record_path() -> Result<(), ErasureErrorV1> {
    let record = coordinator_with_complete_supporting_records()?;
    let bytes = record.to_canonical_cbor()?;
    assert!(record.validate_replacement(&record).is_ok());
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes)?,
        record
    );
    for index in [0, 1, 2, 3, 4, 5, 6] {
        let malformed = changed_supporting_records(&bytes, |fields| {
            fields[index] = Value::Bool(false);
        });
        assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&malformed).is_err());
    }
    for index in [0, 1, 2, 3, 4, 5, 6] {
        let malformed = changed_supporting_records(&bytes, |fields| {
            fields[index] = if index == 0 {
                Value::Array(Vec::new())
            } else {
                Value::Array(vec![Value::Array(Vec::new())])
            };
        });
        assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&malformed).is_err());
    }
    let wrong_request = changed_supporting_records(&bytes, |fields| {
        let Value::Array(resolutions) = &mut fields[6] else {
            return;
        };
        let Value::Array(resolution) = &mut resolutions[0] else {
            return;
        };
        resolution[2] = Value::Bytes(vec![99; 32]);
    });
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&wrong_request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let wrong_correction = changed_supporting_records(&bytes, |fields| {
        let Value::Array(correction) = &mut fields[0] else {
            return;
        };
        correction[4] = Value::Bytes(vec![99; 32]);
    });
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&wrong_correction),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let malformed_correction = changed_supporting_records(&bytes, |fields| {
        let Value::Array(correction) = &mut fields[0] else {
            return;
        };
        correction[2] = Value::Bool(false);
    });
    assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&malformed_correction).is_err());
    Ok(())
}

#[test]
fn supporting_attempt_chain_rejects_gaps_and_identity_mismatches() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    assert!(ErasureSupportingRecordsV1::new(input.clone()).is_ok());

    let mut missing_admission = input.clone();
    missing_admission.retry_admissions.clear();
    assert_eq!(
        ErasureSupportingRecordsV1::new(missing_admission),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut unequal_lengths = input.clone();
    unequal_lengths.receipt_provenance.clear();
    assert_eq!(
        ErasureSupportingRecordsV1::new(unequal_lengths),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut wrong_ordinal = input.clone();
    wrong_ordinal.retry_admissions[0] =
        ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            attempt_ordinal: 1,
            source_receipt: Some(reference(99)),
            ..retry_input()
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_ordinal),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut wrong_outcome = input.clone();
    wrong_outcome.attempt_outcomes[0] =
        ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
            request: reference(1),
            attempt: reference(99),
            source_receipt: None,
            lifecycle: ErasureLifecycleV1::Complete,
            selected_obligations: reference(45),
            acknowledgement_inventory: reference(46),
            terminal_position: 20,
            policy: reference(4),
            trust: reference(5),
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_outcome),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_provenance = input;
    let attempt = wrong_provenance.retry_admissions[0].reference();
    wrong_provenance.receipt_provenance[0] =
        ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
            request: reference(1),
            attempt,
            attempt_ordinal: 0,
            predecessor_receipt: None,
            terminal_state: reference(99),
            evidence_set: reference(47),
            policy: reference(4),
            trust: reference(5),
            issue_position: 20,
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_provenance),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn supporting_attempt_chain_links_one_active_retry_to_the_previous_receipt(
) -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let previous_receipt = input.receipts[0].receipt_digest();
    let retry_input = ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 1,
        source_receipt: Some(previous_receipt),
        unresolved_obligations: vec![reference(8)],
        command_identities: vec![reference(9)],
        policy: reference(4),
        trust: reference(5),
        admitted_position: 21,
        deadline_position: 30,
        authorization_provenance: reference(10),
    };
    let mut active_retry = input.clone();
    active_retry
        .retry_admissions
        .push(ErasureRetryAdmissionV1::new(retry_input.clone())?);
    assert!(ErasureSupportingRecordsV1::new(active_retry).is_ok());

    let mut wrong_predecessor = retry_input;
    wrong_predecessor.source_receipt = Some(reference(99));
    let mut invalid_retry = input;
    invalid_retry
        .retry_admissions
        .push(ErasureRetryAdmissionV1::new(wrong_predecessor)?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(invalid_retry),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_ledger_rejects_acknowledgement_and_resolution_forks() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let attempt = input.retry_admissions[0].reference();
    let mut wrong_command = input.clone();
    wrong_command.acknowledgement_provenance[0] =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            command: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_command),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut duplicate_identity = input.clone();
    duplicate_identity
        .acknowledgement_provenance
        .push(ErasureAcknowledgementProvenanceV1::new(
            ErasureAcknowledgementProvenanceInputV1 {
                evidence: reference(98),
                ..acknowledgement_provenance_input(reference(1), attempt)
            },
        )?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(duplicate_identity),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut resolution_fork = input;
    resolution_fork.administrative_resolutions[0] =
        administrative_resolution(reference(1), Some(reference(99)))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(resolution_fork),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_acknowledgements_fail_closed_at_each_admission_binding() -> Result<(), ErasureErrorV1>
{
    let input = complete_supporting_input(reference(1))?;
    let attempt = input.retry_admissions[0].reference();
    let variants = [
        ErasureAcknowledgementProvenanceInputV1 {
            attempt: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)
        },
        ErasureAcknowledgementProvenanceInputV1 {
            request: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)
        },
        ErasureAcknowledgementProvenanceInputV1 {
            policy: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)
        },
        ErasureAcknowledgementProvenanceInputV1 {
            trust: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)
        },
    ];
    for variant in variants {
        let mut invalid = input.clone();
        invalid.acknowledgement_provenance[0] = ErasureAcknowledgementProvenanceV1::new(variant)?;
        assert_eq!(
            ErasureSupportingRecordsV1::new(invalid),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}

#[test]
fn supporting_resolution_chain_accepts_an_exact_predecessor() -> Result<(), ErasureErrorV1> {
    let mut input = complete_supporting_input(reference(1))?;
    let predecessor = input.administrative_resolutions[0].reference();
    input
        .administrative_resolutions
        .push(administrative_resolution(reference(1), Some(predecessor))?);
    assert!(ErasureSupportingRecordsV1::new(input).is_ok());
    Ok(())
}

#[test]
fn supporting_ledger_bounds_each_attempt_scoped_collection() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let too_many = ERASURE_MAX_ATTEMPT_OUTCOMES + 1;

    let admissions = ErasureSupportingRecordsInputV1 {
        retry_admissions: vec![input.retry_admissions[0].clone(); too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(admissions),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let outcomes = ErasureSupportingRecordsInputV1 {
        attempt_outcomes: vec![input.attempt_outcomes[0]; too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(outcomes),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let receipts = ErasureSupportingRecordsInputV1 {
        receipts: vec![input.receipts[0].clone(); too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(receipts),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let provenance = ErasureSupportingRecordsInputV1 {
        receipt_provenance: vec![input.receipt_provenance[0]; too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(provenance),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let resolutions = ErasureSupportingRecordsInputV1 {
        administrative_resolutions: vec![
            input.administrative_resolutions[0].clone();
            ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS + 1
        ],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(resolutions),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}
