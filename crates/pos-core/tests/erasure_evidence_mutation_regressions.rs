//! Public-interface regressions for the ADR-060 erasure evidence contracts.

#[path = "support/erasure.rs"]
pub mod erasure_support;

use ciborium::value::Value;
use erasure_support::{freeze_evidence_fixture as freeze_evidence, FreezeEvidenceFixtureInput};
use pos_core::{
    acknowledgement_inventory_reference, destruction_command_reference,
    erasure_evidence_set_reference, selected_obligations_reference,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureCoordinatorRecordPartsV1,
    ErasureCoordinatorRecordV1, ErasureErrorV1, ErasureFreezeFailureInputV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationSetInputV1, ErasureObligationSetV1,
    ErasureObligationV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeV1, ErasureStateV1,
    ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1,
};

fn replace_cbor_field(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let Value::Array(mut fields) =
        ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?
    else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let field = fields
        .get_mut(index)
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    *field = replacement;
    let mut changed = Vec::new();
    ciborium::into_writer(&Value::Array(fields), &mut changed)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(changed)
}

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn coordinator() -> ErasureReferenceV1 {
    reference(90)
}

fn roundtrip<T>(
    value: &T,
    encode: impl Fn(&T) -> Result<Vec<u8>, ErasureErrorV1>,
    decode: impl Fn(&[u8]) -> Result<T, ErasureErrorV1>,
) -> Result<T, ErasureErrorV1>
where
    T: std::fmt::Debug + Eq,
{
    let bytes = encode(value)?;
    assert!(bytes.len() > 1);
    let decoded = decode(&bytes)?;
    assert_eq!(&decoded, value);
    assert_eq!(encode(&decoded)?, bytes);
    Ok(decoded)
}

fn administrative_resolution(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    action: ErasureAdministrativeResolutionActionV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request,
        affected_digests: vec![reference(2)],
        action,
        scope_commitment,
        policy: reference(4),
        trust: reference(5),
        principal: reference(6),
        authorization_provenance: reference(7),
        reason: reference(8),
        issue_position: 9,
        predecessor_resolution: None,
    })
}

#[test]
fn administrative_resolution_action_code_is_bound_to_public_wire_roundtrip(
) -> Result<(), ErasureErrorV1> {
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::CloseContainment.code(),
        0
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence.code(),
        1
    );

    let close = administrative_resolution(
        reference(1),
        reference(3),
        ErasureAdministrativeResolutionActionV1::CloseContainment,
    )?;
    let recover = administrative_resolution(
        reference(1),
        reference(3),
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
    )?;
    let close_bytes = close.to_canonical_cbor()?;
    let recover_bytes = recover.to_canonical_cbor()?;
    assert_ne!(close_bytes, recover_bytes);
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&close_bytes)?.action(),
        ErasureAdministrativeResolutionActionV1::CloseContainment
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&recover_bytes)?.action(),
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence
    );
    Ok(())
}

const fn scope_input(
    request: ErasureReferenceV1,
    scope_members: Vec<ErasureReferenceV1>,
    target_closure: ErasureReferenceV1,
    lineage_rule: Option<ErasureReferenceV1>,
) -> ErasureScopeCommitmentInputV1 {
    ErasureScopeCommitmentInputV1 {
        request,
        scope_members,
        target_closure,
        lineage_rule,
    }
}

fn scope_commitment(
    request: ErasureReferenceV1,
    scope_members: Vec<ErasureReferenceV1>,
    target_closure: ErasureReferenceV1,
    lineage_rule: Option<ErasureReferenceV1>,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(scope_input(
        request,
        scope_members,
        target_closure,
        lineage_rule,
    ))
}

#[test]
fn scope_commitment_binds_scope_extension_encoding_and_content_address(
) -> Result<(), ErasureErrorV1> {
    let input = scope_input(
        reference(1),
        vec![reference(2), reference(3)],
        reference(4),
        None,
    );
    let record = ErasureScopeCommitmentV1::new(input)?;
    assert_eq!(record.scope_members(), &[reference(2), reference(3)]);
    assert_eq!(record.lineage_rule(), None);
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureScopeCommitmentV1::to_canonical_cbor,
        ErasureScopeCommitmentV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.lineage_rule(), None);

    let changed_target = ErasureScopeCommitmentV1::new(scope_input(
        reference(1),
        vec![reference(2), reference(3)],
        reference(5),
        None,
    ))?;
    assert_ne!(changed_target.reference(), record.reference());

    let extended = ErasureScopeCommitmentV1::new(scope_input(
        reference(1),
        vec![reference(2), reference(3)],
        reference(4),
        Some(reference(6)),
    ))?;
    assert_eq!(extended.lineage_rule(), Some(reference(6)));
    assert_ne!(extended.reference(), record.reference());
    roundtrip(
        &extended,
        ErasureScopeCommitmentV1::to_canonical_cbor,
        ErasureScopeCommitmentV1::from_canonical_cbor,
    )?;

    let empty_scope =
        ErasureScopeCommitmentV1::new(scope_input(reference(1), Vec::new(), reference(4), None));
    assert_eq!(empty_scope, Err(ErasureErrorV1::ScopeInvalid));
    Ok(())
}

#[test]
fn public_atomic_freeze_decision_binds_explicit_category_obligations_and_exact_matrix(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let target = required_target();
    let mut obligations = ErasureInventoryCategoryV1::CANONICAL
        .into_iter()
        .enumerate()
        .map(|(index, category)| {
            ErasureObligationV1::new(ErasureObligationInputV1 {
                category,
                target,
                owner: reference([20, 21, 22, 23][index]),
                command_identity: pos_core::destruction_command_reference(request, target),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(4),
        trust: reference(5),
    })?;
    let scope = ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: pos_core::erasure::target_closure_digest(&[target]),
        lineage_rule: Some(reference(3)),
    };
    let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
    let targets = [target];
    let (freeze_admission_evidence, freeze_authorization_evidence) =
        freeze_evidence(FreezeEvidenceFixtureInput {
            request,
            scope_commitment: scope_reference,
            obligation_set: &obligation_set,
            targets: &targets,
            obligations: &obligations,
            freeze_position: 0,
            evidence: &[6],
        })?;
    let admission = ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
        targets: vec![target],
        scope,
        obligations: obligations.clone(),
        obligation_set: obligation_set.clone(),
        freeze_position: 0,
        freeze_admission_evidence,
        freeze_authorization_evidence,
    })?;
    assert_eq!(admission.freeze_position(), 0);
    assert_eq!(admission.obligations(), obligations.as_slice());
    assert_eq!(admission.obligation_set(), &obligation_set);
    let invalid_scope = ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: reference(0),
        lineage_rule: Some(reference(3)),
    };
    let invalid_scope_reference = ErasureScopeCommitmentV1::new(invalid_scope.clone())?.reference();
    let (freeze_admission_evidence, freeze_authorization_evidence) =
        freeze_evidence(FreezeEvidenceFixtureInput {
            request,
            scope_commitment: invalid_scope_reference,
            obligation_set: &obligation_set,
            targets: &targets,
            obligations: &obligations,
            freeze_position: 0,
            evidence: &[6],
        })?;
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: vec![target],
            scope: invalid_scope,
            obligations,
            obligation_set,
            freeze_position: 0,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

const fn freeze_input(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    obligation_set: ErasureReferenceV1,
    host_evidence: ErasureReferenceV1,
) -> ErasureFreezeProvenanceInputV1 {
    ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment,
        obligation_set,
        freeze_position: 10,
        host_evidence,
    }
}

#[test]
fn freeze_provenance_binds_obligation_matrix_encoding_and_content_address(
) -> Result<(), ErasureErrorV1> {
    let input = freeze_input(reference(1), reference(2), reference(3), reference(4));
    let record = ErasureFreezeProvenanceV1::new(input)?;
    assert_eq!(record.obligation_set(), reference(3));
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureFreezeProvenanceV1::to_canonical_cbor,
        ErasureFreezeProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.host_evidence(), reference(4));

    let changed_evidence = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        reference(2),
        reference(3),
        reference(5),
    ))?;
    assert_ne!(changed_evidence.reference(), record.reference());

    let changed_matrix = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        reference(2),
        reference(6),
        reference(4),
    ))?;
    assert_ne!(changed_matrix.reference(), record.reference());
    Ok(())
}

const fn freeze_failure_input(
    request: ErasureReferenceV1,
    error: ErasureErrorV1,
    evidence: ErasureReferenceV1,
) -> ErasureFreezeFailureInputV1 {
    ErasureFreezeFailureInputV1 {
        request,
        error,
        authorization_provenance: reference(2),
        evidence,
    }
}

#[test]
fn freeze_failure_binds_error_encoding_and_content_address() -> Result<(), ErasureErrorV1> {
    let record = ErasureFreezeFailureV1::new(freeze_failure_input(
        reference(1),
        ErasureErrorV1::ScopeInvalid,
        reference(3),
    ))?;
    assert_eq!(record.error(), ErasureErrorV1::ScopeInvalid);
    assert_eq!(record.evidence(), reference(3));
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureFreezeFailureV1::to_canonical_cbor,
        ErasureFreezeFailureV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.error(), ErasureErrorV1::ScopeInvalid);

    let changed_evidence = ErasureFreezeFailureV1::new(freeze_failure_input(
        reference(1),
        ErasureErrorV1::ScopeInvalid,
        reference(4),
    ))?;
    assert_ne!(changed_evidence.reference(), record.reference());

    let changed_error = ErasureFreezeFailureV1::new(freeze_failure_input(
        reference(1),
        ErasureErrorV1::AccessFreezeFailed,
        reference(3),
    ))?;
    assert_ne!(changed_error.reference(), record.reference());

    assert_eq!(
        ErasureFreezeFailureV1::new(freeze_failure_input(
            reference(1),
            ErasureErrorV1::Unauthorized,
            reference(3),
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn evidence_decoders_reject_each_malformed_public_field() -> Result<(), ErasureErrorV1> {
    let scope = scope_commitment(reference(1), vec![reference(2)], reference(3), None)?;
    let scope_bytes = scope.to_canonical_cbor()?;
    for index in [0, 2, 3, 4] {
        let changed = replace_cbor_field(&scope_bytes, index, Value::Null)?;
        assert!(ErasureScopeCommitmentV1::from_canonical_cbor(&changed).is_err());
    }

    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        scope.reference(),
        reference(4),
        reference(5),
    ))?;
    let freeze_bytes = freeze.to_canonical_cbor()?;
    for index in [0, 2, 3, 4, 5] {
        let changed = replace_cbor_field(&freeze_bytes, index, Value::Null)?;
        assert!(ErasureFreezeProvenanceV1::from_canonical_cbor(&changed).is_err());
    }

    let failure = ErasureFreezeFailureV1::new(freeze_failure_input(
        reference(1),
        ErasureErrorV1::ScopeInvalid,
        reference(4),
    ))?;
    let failure_bytes = failure.to_canonical_cbor()?;
    for index in [0, 2, 3, 4, 5] {
        let changed = replace_cbor_field(&failure_bytes, index, Value::Null)?;
        assert!(ErasureFreezeFailureV1::from_canonical_cbor(&changed).is_err());
    }
    let unknown_error = replace_cbor_field(&failure_bytes, 3, Value::Integer(99.into()))?;
    assert_eq!(
        ErasureFreezeFailureV1::from_canonical_cbor(&unknown_error),
        Err(ErasureErrorV1::InvalidEncoding)
    );
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

fn obligation(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner,
        command_identity: destruction_command_reference(request, target),
    })
}

fn acknowledgement(
    request: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let target = required_target();
    let obligation = obligation(request, target, reference(36))?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target,
        owner: reference(36),
        evidence: reference(34),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    })
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

fn admission(
    request: ErasureReferenceV1,
    unresolved_obligations: Vec<ErasureReferenceV1>,
    command_identities: Vec<ErasureReferenceV1>,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations,
        command_identities,
        policy: reference(4),
        trust: reference(5),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(6),
    })
}

fn acknowledgement_provenance(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
    obligation: ErasureReferenceV1,
    command: ErasureReferenceV1,
    owner: ErasureReferenceV1,
    scope: ErasureReferenceV1,
    policy: ErasureReferenceV1,
    trust: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
    ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
        request,
        command,
        attempt,
        obligation,
        owner,
        scope,
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        evidence: reference(34),
        policy,
        trust,
    })
}

fn receipt_provenance(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
    terminal_state: ErasureReferenceV1,
    evidence_set: ErasureReferenceV1,
    issue_position: u64,
) -> Result<ErasureReceiptProvenanceV1, ErasureErrorV1> {
    ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request,
        attempt,
        attempt_ordinal: 0,
        predecessor_receipt: None,
        terminal_state,
        evidence_set,
        policy: reference(4),
        trust: reference(5),
        issue_position,
    })
}

fn receipt(
    request: ErasureReferenceV1,
    provenance: ErasureReferenceV1,
) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request,
        terminal_state: reference(40),
        coordinator: reference(41),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 10,
        acknowledgements: vec![acknowledgement(request)?],
        frozen_targets: vec![required_target()],
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
        provenance,
        issue_position: 20,
        signature: reference(43),
        receipt_digest: reference(0),
    })
}

fn attempt_outcome(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
    selected_obligations: ErasureReferenceV1,
    acknowledgement_inventory: ErasureReferenceV1,
    terminal_position: u64,
) -> Result<ErasureAttemptOutcomeV1, ErasureErrorV1> {
    ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request,
        attempt,
        source_receipt: None,
        lifecycle: ErasureLifecycleV1::Complete,
        selected_obligations,
        acknowledgement_inventory,
        terminal_position,
        policy: reference(4),
        trust: reference(5),
    })
}

fn complete_supporting_input(
    request: ErasureReferenceV1,
) -> Result<ErasureSupportingRecordsInputV1, ErasureErrorV1> {
    let target = required_target();
    let obligation = obligation(request, target, reference(36))?;
    let acknowledged = acknowledgement(request)?;
    let scope = scope_commitment(
        request,
        vec![reference(2)],
        pos_core::erasure::target_closure_digest(&[target]),
        None,
    )?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let (freeze_admission_evidence, freeze_authorization_evidence) =
        freeze_evidence(FreezeEvidenceFixtureInput {
            request,
            scope_commitment: scope.reference(),
            obligation_set: &obligation_set,
            targets: &[target],
            obligations: &[obligation],
            freeze_position: 10,
            evidence: &[6],
        })?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        request,
        scope.reference(),
        obligation_set.reference(),
        freeze_admission_evidence.reference(),
    ))?;
    let admission = admission(
        request,
        vec![obligation.reference()],
        vec![obligation.command_identity()],
    )?;
    let attempt = admission.reference();
    let acknowledgement_provenance = acknowledgement_provenance(
        request,
        attempt,
        acknowledged.obligation,
        obligation.command_identity(),
        acknowledged.owner,
        scope.reference(),
        reference(4),
        reference(5),
    )?;
    let acknowledgement_reference = acknowledgement_provenance.reference();
    let evidence_set = erasure_evidence_set_reference(&[acknowledgement_reference]);
    let receipt_provenance = receipt_provenance(request, attempt, reference(40), evidence_set, 20)?;
    let receipt = receipt(request, receipt_provenance.reference())?;
    Ok(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        freeze_admission_evidence: Some(freeze_admission_evidence),
        freeze_authorization_evidence: Some(freeze_authorization_evidence),
        freeze_provenance: Some(freeze),
        obligations: vec![obligation],
        obligation_set: Some(obligation_set),
        retry_admissions: vec![admission],
        acknowledgement_provenance: vec![acknowledgement_provenance],
        attempt_outcomes: vec![attempt_outcome(
            request,
            attempt,
            selected_obligations_reference(&[acknowledged.obligation]),
            acknowledgement_inventory_reference(&[acknowledgement_reference]),
            20,
        )?],
        receipts: vec![receipt],
        receipt_provenance: vec![receipt_provenance],
        administrative_resolutions: vec![administrative_resolution(
            request,
            scope.reference(),
            ErasureAdministrativeResolutionActionV1::CloseContainment,
        )?],
        ..ErasureSupportingRecordsInputV1::default()
    })
}

#[test]
fn supporting_records_roundtrip_every_populated_collection() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let records = ErasureSupportingRecordsV1::new(complete_supporting_input(request)?)?;
    roundtrip(
        &records,
        ErasureSupportingRecordsV1::to_canonical_cbor,
        ErasureSupportingRecordsV1::from_canonical_cbor,
    )?;

    let failure = ErasureFreezeFailureV1::new(freeze_failure_input(
        request,
        ErasureErrorV1::ScopeInvalid,
        reference(5),
    ))?;
    let failed = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        freeze_failure: Some(failure),
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    roundtrip(
        &failed,
        ErasureSupportingRecordsV1::to_canonical_cbor,
        ErasureSupportingRecordsV1::from_canonical_cbor,
    )?;
    Ok(())
}

#[test]
fn supporting_record_decoder_rejects_each_malformed_nested_collection() -> Result<(), ErasureErrorV1>
{
    let bytes = ErasureSupportingRecordsV1::default().to_canonical_cbor()?;
    for index in [0, 1, 2, 3, 4, 5, 6, 8] {
        let changed = replace_cbor_field(&bytes, index, Value::Array(Vec::new()))?;
        assert!(ErasureSupportingRecordsV1::from_canonical_cbor(&changed).is_err());
    }
    for index in [7, 9, 10, 11, 12, 13, 14, 15, 16] {
        let wrong_collection = replace_cbor_field(&bytes, index, Value::Null)?;
        assert!(ErasureSupportingRecordsV1::from_canonical_cbor(&wrong_collection).is_err());
    }

    for index in [7, 9, 10, 11, 12, 13, 14, 15, 16] {
        let malformed_entry =
            replace_cbor_field(&bytes, index, Value::Array(vec![Value::Array(Vec::new())]))?;
        assert!(ErasureSupportingRecordsV1::from_canonical_cbor(&malformed_entry).is_err());
    }
    Ok(())
}

#[test]
fn supporting_records_freeze_requires_matching_scope_extension() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let target = required_target();
    let obligation = obligation(request, target, reference(36))?;
    let obligations = vec![obligation];
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let scope = scope_commitment(
        request,
        vec![reference(2)],
        pos_core::erasure::target_closure_digest(&[target]),
        None,
    )?;
    let (freeze_admission_evidence, freeze_authorization_evidence) =
        freeze_evidence(FreezeEvidenceFixtureInput {
            request,
            scope_commitment: scope.reference(),
            obligation_set: &obligation_set,
            targets: &[target],
            obligations: &obligations,
            freeze_position: 10,
            evidence: &[6],
        })?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        request,
        scope.reference(),
        obligation_set.reference(),
        freeze_admission_evidence.reference(),
    ))?;
    let valid = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        freeze_admission_evidence: Some(freeze_admission_evidence.clone()),
        freeze_authorization_evidence: Some(freeze_authorization_evidence.clone()),
        freeze_provenance: Some(freeze),
        obligations: obligations.clone(),
        obligation_set: Some(obligation_set.clone()),
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    assert_eq!(valid.scope_commitment(), Some(&scope));
    assert_eq!(valid.freeze_provenance(), Some(freeze));

    let mismatched_matrix = ErasureFreezeProvenanceV1::new(freeze_input(
        request,
        scope.reference(),
        reference(99),
        freeze_admission_evidence.reference(),
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope.clone()),
            freeze_admission_evidence: Some(freeze_admission_evidence.clone()),
            freeze_authorization_evidence: Some(freeze_authorization_evidence.clone()),
            freeze_provenance: Some(mismatched_matrix),
            obligations: obligations.clone(),
            obligation_set: Some(obligation_set.clone()),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mismatched_scope = ErasureFreezeProvenanceV1::new(freeze_input(
        request,
        reference(6),
        obligation_set.reference(),
        freeze_admission_evidence.reference(),
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope.clone()),
            freeze_admission_evidence: Some(freeze_admission_evidence),
            freeze_authorization_evidence: Some(freeze_authorization_evidence),
            freeze_provenance: Some(mismatched_scope),
            obligations: obligations.clone(),
            obligation_set: Some(obligation_set.clone()),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        request,
        reference(6),
        obligation_set.reference(),
        reference(7),
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            freeze_provenance: Some(freeze),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    assert_freeze_failure_conflicts(scope, obligations, obligation_set)
}

fn assert_freeze_failure_conflicts(
    scope: ErasureScopeCommitmentV1,
    obligations: Vec<ErasureObligationV1>,
    obligation_set: ErasureObligationSetV1,
) -> Result<(), ErasureErrorV1> {
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        scope.reference(),
        obligation_set.reference(),
        reference(6),
    ))?;
    let failure = ErasureFreezeFailureV1::new(freeze_failure_input(
        reference(1),
        ErasureErrorV1::ScopeInvalid,
        reference(5),
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope.clone()),
            freeze_provenance: Some(freeze),
            freeze_failure: Some(failure),
            obligations,
            obligation_set: Some(obligation_set),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope),
            freeze_failure: Some(failure),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_records_attempt_chain_rejects_each_derived_evidence_near_miss(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let base = complete_supporting_input(request)?;
    assert!(ErasureSupportingRecordsV1::new(base.clone()).is_ok());
    let attempt = base.retry_admissions[0].reference();
    let acknowledgement_reference = base.acknowledgement_provenance[0].reference();
    let selected = selected_obligations_reference(&[acknowledgement(request)?.obligation]);
    let inventory = acknowledgement_inventory_reference(&[acknowledgement_reference]);
    let evidence_set = erasure_evidence_set_reference(&[acknowledgement_reference]);

    let mut wrong_provenance = base.clone();
    let provenance = receipt_provenance(request, attempt, reference(99), evidence_set, 20)?;
    wrong_provenance.receipt_provenance[0] = provenance;
    wrong_provenance.receipts[0] = receipt(request, provenance.reference())?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_provenance),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_selected = base.clone();
    wrong_selected.attempt_outcomes[0] =
        attempt_outcome(request, attempt, reference(99), inventory, 20)?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_selected),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_inventory = base.clone();
    wrong_inventory.attempt_outcomes[0] =
        attempt_outcome(request, attempt, selected, reference(99), 20)?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_inventory),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_position = base.clone();
    wrong_position.attempt_outcomes[0] =
        attempt_outcome(request, attempt, selected, inventory, 99)?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_position),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_evidence_set = base;
    let provenance = receipt_provenance(request, attempt, reference(40), reference(99), 20)?;
    wrong_evidence_set.receipt_provenance[0] = provenance;
    wrong_evidence_set.receipts[0] = receipt(request, provenance.reference())?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_evidence_set),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn two_acknowledgement_records() -> Result<ErasureSupportingRecordsV1, ErasureErrorV1> {
    let request = reference(1);
    let first_target = required_target();
    let second_target = ErasureRequiredTargetV1 {
        replica_id: reference(37),
        ..first_target
    };
    let first_obligation = obligation(request, first_target, reference(36))?;
    let second_obligation = obligation(request, second_target, reference(38))?;
    let mut obligations = vec![first_obligation, second_obligation];
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    let scope = scope_commitment(
        request,
        vec![reference(2)],
        pos_core::erasure::target_closure_digest(&[first_target, second_target]),
        None,
    )?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(4),
        trust: reference(5),
    })?;
    let admission = admission(
        request,
        obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        obligations
            .iter()
            .map(ErasureObligationV1::command_identity)
            .collect(),
    )?;
    let first = acknowledgement_provenance(
        request,
        admission.reference(),
        first_obligation.reference(),
        first_obligation.command_identity(),
        first_obligation.owner(),
        scope.reference(),
        reference(4),
        reference(5),
    )?;
    let second = acknowledgement_provenance(
        request,
        admission.reference(),
        second_obligation.reference(),
        second_obligation.command_identity(),
        second_obligation.owner(),
        scope.reference(),
        reference(4),
        reference(5),
    )?;
    let mut acknowledgements = vec![first, second];
    acknowledgements.sort_unstable_by_key(|acknowledgement| {
        (
            acknowledgement.command(),
            acknowledgement.attempt(),
            acknowledgement.owner(),
            acknowledgement.reference(),
        )
    });
    ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        obligations,
        obligation_set: Some(obligation_set),
        retry_admissions: vec![admission],
        acknowledgement_provenance: acknowledgements,
        ..ErasureSupportingRecordsInputV1::default()
    })
}

fn reverse_acknowledgement_provenance(bytes: &[u8]) -> Result<Vec<u8>, ErasureErrorV1> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(mut fields) = value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Some(Value::Array(acknowledgements)) = fields.get_mut(12) else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    acknowledgements.reverse();
    let mut changed = Vec::new();
    ciborium::into_writer(&Value::Array(fields), &mut changed)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(changed)
}

#[test]
fn supporting_acknowledgements_bind_policy_trust_and_strict_arrival_order(
) -> Result<(), ErasureErrorV1> {
    let base = complete_supporting_input(reference(1))?;
    let attempt = base.retry_admissions[0].reference();
    let acknowledged = acknowledgement(reference(1))?;
    let scope = base
        .scope_commitment
        .as_ref()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .reference();

    for (policy, trust) in [(reference(99), reference(5)), (reference(4), reference(99))] {
        let mut invalid = base.clone();
        invalid.acknowledgement_provenance[0] = acknowledgement_provenance(
            reference(1),
            attempt,
            acknowledged.obligation,
            destruction_command_reference(reference(1), required_target()),
            acknowledged.owner,
            scope,
            policy,
            trust,
        )?;
        assert_eq!(
            ErasureSupportingRecordsV1::new(invalid),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    let ordered = two_acknowledgement_records()?;
    let bytes = ordered.to_canonical_cbor()?;
    assert_eq!(
        ErasureSupportingRecordsV1::from_canonical_cbor(&bytes)?,
        ordered
    );
    let reversed = reverse_acknowledgement_provenance(&bytes)?;
    assert_eq!(
        ErasureSupportingRecordsV1::from_canonical_cbor(&reversed),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn request(
    selectors: Vec<ErasureReferenceV1>,
    request_position: u64,
    horizon_position: u64,
) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors,
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position,
        horizon_position,
        provenance: reference(6),
    })
}

#[test]
fn request_selectors_and_zero_one_position_boundaries_are_publicly_enforced(
) -> Result<(), ErasureErrorV1> {
    let zero = request(vec![reference(2), reference(1)], 0, 0)?;
    assert_eq!(zero.selectors(), &[reference(1), reference(2)]);
    assert_eq!(zero.request_position(), 0);
    assert_eq!(zero.horizon_position(), 0);

    let one = request(vec![reference(1)], 1, 1)?;
    assert_eq!(one.request_position(), 1);
    assert_eq!(one.horizon_position(), 1);

    let mixed = request(vec![reference(1)], 0, 1)?;
    assert_eq!(mixed.request_position(), 0);
    assert_eq!(mixed.horizon_position(), 1);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&mixed.to_canonical_cbor()?)?,
        mixed
    );

    assert_eq!(request(Vec::new(), 0, 0), Err(ErasureErrorV1::ScopeInvalid));
    assert_eq!(
        request(vec![reference(1)], 1, 0),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

fn submitted_record(
    request: ErasureRequestV1,
    supporting_records: ErasureSupportingRecordsV1,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let state = ErasureStateV1::submitted(request.reference(), coordinator(), reference(91))?;
    ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request,
            state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records,
        },
        coordinator(),
    )
}

fn assert_request_binding_rejected(
    supporting_records: ErasureSupportingRecordsV1,
) -> Result<(), ErasureErrorV1> {
    assert_eq!(
        submitted_record(request(vec![reference(1)], 0, 1)?, supporting_records),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn supporting_records_validate_every_public_request_binding() -> Result<(), ErasureErrorV1> {
    assert!(submitted_record(
        request(vec![reference(1)], 0, 1)?,
        ErasureSupportingRecordsV1::default(),
    )
    .is_ok());

    let scope = scope_commitment(reference(2), vec![reference(3)], reference(4), None)?;
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(
        ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope),
            ..ErasureSupportingRecordsInputV1::default()
        },
    )?)?;

    let freeze_request = reference(2);
    let target = required_target();
    let scope = scope_commitment(
        freeze_request,
        vec![reference(3)],
        pos_core::erasure::target_closure_digest(&[target]),
        None,
    )?;
    let obligation = obligation(freeze_request, target, reference(36))?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: freeze_request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let (freeze_admission_evidence, freeze_authorization_evidence) =
        freeze_evidence(FreezeEvidenceFixtureInput {
            request: freeze_request,
            scope_commitment: scope.reference(),
            obligation_set: &obligation_set,
            targets: &[target],
            obligations: &[obligation],
            freeze_position: 10,
            evidence: &[6],
        })?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        freeze_request,
        scope.reference(),
        obligation_set.reference(),
        freeze_admission_evidence.reference(),
    ))?;
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(
        ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope),
            freeze_admission_evidence: Some(freeze_admission_evidence),
            freeze_authorization_evidence: Some(freeze_authorization_evidence),
            freeze_provenance: Some(freeze),
            obligations: vec![obligation],
            obligation_set: Some(obligation_set),
            ..ErasureSupportingRecordsInputV1::default()
        },
    )?)?;

    let freeze_failure = ErasureFreezeFailureV1::new(freeze_failure_input(
        reference(2),
        ErasureErrorV1::ScopeInvalid,
        reference(5),
    ))?;
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(
        ErasureSupportingRecordsInputV1 {
            freeze_failure: Some(freeze_failure),
            ..ErasureSupportingRecordsInputV1::default()
        },
    )?)?;

    let retry = admission(reference(2), vec![reference(7)], vec![reference(8)])?;
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(
        ErasureSupportingRecordsInputV1 {
            retry_admissions: vec![retry],
            ..ErasureSupportingRecordsInputV1::default()
        },
    )?)?;

    let complete_for_other_collections =
        ErasureSupportingRecordsV1::new(complete_supporting_input(reference(2))?)?;
    assert_request_binding_rejected(complete_for_other_collections)?;

    let mut receipt_only_near_miss = complete_supporting_input(reference(1))?;
    receipt_only_near_miss.receipts[0] = receipt(
        reference(2),
        receipt_only_near_miss.receipts[0].provenance(),
    )?;
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(receipt_only_near_miss)?)?;
    Ok(())
}
