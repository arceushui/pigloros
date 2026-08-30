//! Public-interface regressions for the ADR-060 erasure evidence contracts.

use ciborium::value::Value;
use pos_core::{
    acknowledgement_inventory_reference, erasure_evidence_set_reference,
    inventory_obligation_reference, selected_obligations_reference,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureCoordinatorRecordPartsV1,
    ErasureCoordinatorRecordV1, ErasureErrorV1, ErasureFreezeFailureInputV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptProvenanceInputV1,
    ErasureReceiptProvenanceV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeV1, ErasureStateV1, ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1,
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
    action: ErasureAdministrativeResolutionActionV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request,
        affected_digests: vec![reference(2)],
        action,
        scope_commitment: reference(3),
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
        ErasureAdministrativeResolutionActionV1::CloseContainment,
    )?;
    let recover = administrative_resolution(
        reference(1),
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
    affected_scope: Vec<ErasureReferenceV1>,
    target_closure: ErasureReferenceV1,
    extension_head: Option<ErasureReferenceV1>,
) -> ErasureScopeCommitmentInputV1 {
    ErasureScopeCommitmentInputV1 {
        request,
        affected_scope,
        target_closure,
        extension_head,
    }
}

fn scope_commitment(
    request: ErasureReferenceV1,
    affected_scope: Vec<ErasureReferenceV1>,
    target_closure: ErasureReferenceV1,
    extension_head: Option<ErasureReferenceV1>,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(scope_input(
        request,
        affected_scope,
        target_closure,
        extension_head,
    ))
}

#[test]
fn scope_commitment_binds_scope_extension_encoding_and_content_address(
) -> Result<(), ErasureErrorV1> {
    let input = scope_input(
        reference(1),
        vec![reference(3), reference(2)],
        reference(4),
        None,
    );
    let record = ErasureScopeCommitmentV1::new(input)?;
    assert_eq!(record.affected_scope(), &[reference(2), reference(3)]);
    assert_eq!(record.extension_head(), None);
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureScopeCommitmentV1::to_canonical_cbor,
        ErasureScopeCommitmentV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.extension_head(), None);

    let changed_target = ErasureScopeCommitmentV1::new(scope_input(
        reference(1),
        vec![reference(3), reference(2)],
        reference(5),
        None,
    ))?;
    assert_ne!(changed_target.reference(), record.reference());

    let extended = ErasureScopeCommitmentV1::new(scope_input(
        reference(1),
        vec![reference(3), reference(2)],
        reference(4),
        Some(reference(6)),
    ))?;
    assert_eq!(extended.extension_head(), Some(reference(6)));
    assert_ne!(extended.reference(), record.reference());

    let empty_scope =
        ErasureScopeCommitmentV1::new(scope_input(reference(1), Vec::new(), reference(4), None));
    assert_eq!(empty_scope, Err(ErasureErrorV1::ScopeInvalid));
    Ok(())
}

const fn freeze_input(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    evidence: ErasureReferenceV1,
    extension_head: Option<ErasureReferenceV1>,
) -> ErasureFreezeProvenanceInputV1 {
    ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment,
        freeze_position: 10,
        evidence,
        extension_head,
    }
}

#[test]
fn freeze_provenance_binds_optional_extension_encoding_and_content_address(
) -> Result<(), ErasureErrorV1> {
    let input = freeze_input(reference(1), reference(2), reference(3), None);
    let record = ErasureFreezeProvenanceV1::new(input)?;
    assert_eq!(record.extension_head(), None);
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureFreezeProvenanceV1::to_canonical_cbor,
        ErasureFreezeProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.extension_head(), None);

    let changed_evidence = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        reference(2),
        reference(4),
        None,
    ))?;
    assert_ne!(changed_evidence.reference(), record.reference());

    let extended = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        reference(2),
        reference(3),
        Some(reference(5)),
    ))?;
    assert_eq!(extended.extension_head(), Some(reference(5)));
    assert_ne!(extended.reference(), record.reference());
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
        None,
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

fn acknowledgement() -> ErasureAcknowledgementV1 {
    let target = required_target();
    ErasureAcknowledgementV1 {
        obligation: inventory_obligation_reference(
            ErasureInventoryCategoryV1::Artifact,
            target,
            reference(36),
        ),
        target,
        owner: reference(36),
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
    policy: ErasureReferenceV1,
    trust: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
    ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
        request,
        command,
        attempt,
        obligation,
        owner,
        scope: reference(44),
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
        acknowledgements: vec![acknowledgement()],
        required_targets: vec![required_target()],
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
    let acknowledged = acknowledgement();
    let admission = admission(request, vec![acknowledged.obligation], vec![reference(3)])?;
    let attempt = admission.reference();
    let acknowledgement_provenance = acknowledgement_provenance(
        request,
        attempt,
        acknowledged.obligation,
        reference(3),
        acknowledged.owner,
        reference(4),
        reference(5),
    )?;
    let acknowledgement_reference = acknowledgement_provenance.reference();
    let evidence_set = erasure_evidence_set_reference(&[acknowledgement_reference]);
    let receipt_provenance = receipt_provenance(request, attempt, reference(40), evidence_set, 20)?;
    let receipt = receipt(request, receipt_provenance.reference())?;
    Ok(ErasureSupportingRecordsInputV1 {
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
            ErasureAdministrativeResolutionActionV1::CloseContainment,
        )?],
        ..ErasureSupportingRecordsInputV1::default()
    })
}

#[test]
fn supporting_records_roundtrip_every_populated_collection() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = scope_commitment(request, vec![reference(2)], reference(3), None)?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        request,
        scope.reference(),
        reference(4),
        None,
    ))?;
    let mut input = complete_supporting_input(request)?;
    input.scope_commitment = Some(scope);
    input.freeze_provenance = Some(freeze);
    let records = ErasureSupportingRecordsV1::new(input)?;
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
fn supporting_records_freeze_requires_matching_scope_extension() -> Result<(), ErasureErrorV1> {
    let scope = scope_commitment(reference(1), vec![reference(2)], reference(3), None)?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        scope.reference(),
        reference(4),
        None,
    ))?;
    let valid = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        freeze_provenance: Some(freeze),
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    assert_eq!(valid.scope_commitment(), Some(&scope));
    assert_eq!(valid.freeze_provenance(), Some(freeze));

    let mismatched_extension = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        scope.reference(),
        reference(4),
        Some(reference(5)),
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope.clone()),
            freeze_provenance: Some(mismatched_extension),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mismatched_scope = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        reference(6),
        reference(4),
        None,
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope),
            freeze_provenance: Some(mismatched_scope),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        reference(6),
        reference(4),
        None,
    ))?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            freeze_provenance: Some(freeze),
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let scope = scope_commitment(reference(1), vec![reference(2)], reference(3), None)?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(1),
        scope.reference(),
        reference(4),
        None,
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
    let selected = selected_obligations_reference(&[acknowledgement().obligation]);
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
    let admission = admission(
        request,
        vec![reference(2), reference(3)],
        vec![reference(12), reference(13)],
    )?;
    let first = acknowledgement_provenance(
        request,
        admission.reference(),
        reference(2),
        reference(12),
        reference(14),
        reference(4),
        reference(5),
    )?;
    let second = acknowledgement_provenance(
        request,
        admission.reference(),
        reference(3),
        reference(13),
        reference(15),
        reference(4),
        reference(5),
    )?;
    ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        retry_admissions: vec![admission],
        acknowledgement_provenance: vec![second, first],
        ..ErasureSupportingRecordsInputV1::default()
    })
}

fn reverse_acknowledgement_provenance(bytes: &[u8]) -> Result<Vec<u8>, ErasureErrorV1> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(mut fields) = value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Some(Value::Array(acknowledgements)) = fields.get_mut(5) else {
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
    let acknowledged = acknowledgement();

    for (policy, trust) in [(reference(99), reference(5)), (reference(4), reference(99))] {
        let mut invalid = base.clone();
        invalid.acknowledgement_provenance[0] = acknowledgement_provenance(
            reference(1),
            attempt,
            acknowledged.obligation,
            reference(3),
            acknowledged.owner,
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

    let scope = scope_commitment(reference(1), vec![reference(3)], reference(4), None)?;
    let freeze = ErasureFreezeProvenanceV1::new(freeze_input(
        reference(2),
        scope.reference(),
        reference(5),
        None,
    ))?;
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(
        ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope),
            freeze_provenance: Some(freeze),
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

    let mut acknowledgement_input = ErasureSupportingRecordsInputV1::default();
    let retry = admission(reference(2), vec![reference(7)], vec![reference(8)])?;
    acknowledgement_input.retry_admissions = vec![retry.clone()];
    acknowledgement_input.acknowledgement_provenance = vec![acknowledgement_provenance(
        reference(2),
        retry.reference(),
        reference(7),
        reference(8),
        reference(9),
        reference(4),
        reference(5),
    )?];
    assert_request_binding_rejected(ErasureSupportingRecordsV1::new(acknowledgement_input)?)?;

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
