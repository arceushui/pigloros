use super::{
    applicability_matrix_cardinality_is_valid, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementV1, ErasureAdministrativeResolutionActionV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAttemptQuotaReservationV1, ErasureCasEffectV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeV1,
    ErasureStateV1, TimelineId, ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1,
    ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1, ERASURE_ATTEMPT_OUTCOME_TAG_V1,
    ERASURE_AUTHORIZATION_REJECTION_TAG_V1, ERASURE_CAS_EFFECT_TAG_V1,
    ERASURE_CORRECTION_PROVENANCE_TAG_V1, ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1,
    ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES, ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1,
    ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1, ERASURE_FREEZE_FAILURE_TAG_V1,
    ERASURE_FREEZE_PROVENANCE_TAG_V1, ERASURE_INVENTORY_CATEGORY_COUNT,
    ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT, ERASURE_MAX_ATTEMPT_OUTCOMES,
    ERASURE_MAX_INVENTORY_RESULTS, ERASURE_MAX_INVENTORY_TIMELINES, ERASURE_MAX_OBLIGATIONS,
    ERASURE_MAX_OUTCOME_OWNERS, ERASURE_MAX_REFERENCES, ERASURE_MAX_SCOPE_EXTENSIONS,
    ERASURE_MAX_TARGETS, ERASURE_OBLIGATION_SET_MAX_BYTES, ERASURE_OBLIGATION_SET_TAG_V1,
    ERASURE_OBLIGATION_TAG_V1, ERASURE_PORTABLE_RECORD_MAX_BYTES,
    ERASURE_RECEIPT_PROVENANCE_TAG_V1, ERASURE_RECEIPT_TAG_V1, ERASURE_RECOVERY_ERROR_TAG_V1,
    ERASURE_RETRY_ADMISSION_MAX_BYTES, ERASURE_RETRY_ADMISSION_TAG_V1,
    ERASURE_SCOPE_COMMITMENT_TAG_V1, ERASURE_SCOPE_EXTENSION_TAG_V1,
    ERASURE_SCOPE_LEDGER_MAX_BYTES, ERQ1, ERS1, VERSION,
};
use ciborium::value::Value;

pub(super) fn cas_effect_value(effect: &ErasureCasEffectV1) -> Value {
    let (kind, subject, payload) = match effect {
        ErasureCasEffectV1::None => (0, Value::Null, Value::Array(Vec::new())),
        ErasureCasEffectV1::AttemptAdmission {
            reservation,
            commands,
        } => (
            1,
            digest(reservation.admission()),
            Value::Array(vec![
                digest(reservation.reference()),
                Value::Array(commands.iter().map(command_value).collect()),
            ]),
        ),
        ErasureCasEffectV1::AcknowledgementAdmission { acknowledgement } => {
            (2, digest(*acknowledgement), Value::Array(Vec::new()))
        }
        ErasureCasEffectV1::ReceiptAdmission { receipt } => {
            (3, digest(*receipt), Value::Array(Vec::new()))
        }
    };
    Value::Array(vec![
        text(ERASURE_CAS_EFFECT_TAG_V1),
        uint(VERSION),
        uint(kind),
        subject,
        payload,
    ])
}

pub(super) fn cas_effect_from_fields(
    fields: &[Value],
) -> Result<ErasureCasEffectV1, ErasureErrorV1> {
    header(fields, ERASURE_CAS_EFFECT_TAG_V1)?;
    match unsigned(&fields[2])? {
        0 if matches!(&fields[3], Value::Null) && exact_array(&fields[4], 0).is_ok() => {
            Ok(ErasureCasEffectV1::None)
        }
        1 => {
            let admission = bytes32(&fields[3])?;
            let payload = exact_array(&fields[4], 2)?;
            let reservation =
                ErasureAttemptQuotaReservationV1::new(admission, bytes32(&payload[0])?);
            let commands = array(&payload[1], super::ERASURE_MAX_OBLIGATIONS)?
                .iter()
                .map(command_from_value)
                .collect::<Result<Vec<_>, _>>()?;
            if commands
                .iter()
                .all(|command| command.provenance == admission)
            {
                Ok(ErasureCasEffectV1::AttemptAdmission {
                    reservation,
                    commands,
                })
            } else {
                Err(ErasureErrorV1::ProvenanceMissing)
            }
        }
        2 if exact_array(&fields[4], 0).is_ok() => {
            Ok(ErasureCasEffectV1::AcknowledgementAdmission {
                acknowledgement: bytes32(&fields[3])?,
            })
        }
        3 if exact_array(&fields[4], 0).is_ok() => Ok(ErasureCasEffectV1::ReceiptAdmission {
            receipt: bytes32(&fields[3])?,
        }),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

fn command_value(command: &ErasureDestructionCommandV1) -> Value {
    Value::Array(vec![
        digest(command.obligation),
        uint(command.category.code()),
        target_value(command.target),
        digest(command.owner),
        digest(command.command),
        digest(command.provenance),
    ])
}

fn command_from_value(value: &Value) -> Result<ErasureDestructionCommandV1, ErasureErrorV1> {
    let fields = exact_array(value, 6)?;
    Ok(ErasureDestructionCommandV1 {
        obligation: bytes32(&fields[0])?,
        category: ErasureInventoryCategoryV1::from_code(unsigned(&fields[1])?)?,
        target: target_from_value(&fields[2])?,
        owner: bytes32(&fields[3])?,
        command: bytes32(&fields[4])?,
        provenance: bytes32(&fields[5])?,
    })
}

pub(super) fn request_value(input: &ErasureRequestInputV1) -> Value {
    Value::Array(vec![
        text(ERQ1),
        uint(VERSION),
        digest(input.request),
        digest(input.subject),
        uint(input.scope.code()),
        references_value(&input.selectors),
        digest(input.requester),
        digest(input.authorization),
        digest(input.policy),
        uint(input.request_position),
        uint(input.horizon_position),
        digest(input.provenance),
    ])
}
pub(super) fn request_from_fields(fields: &[Value]) -> Result<ErasureRequestV1, ErasureErrorV1> {
    header(fields, ERQ1)
        .and_then(|()| request_identity(fields))
        .and_then(|(request, subject, scope, selectors)| {
            request_authority(fields).and_then(|(requester, authorization, policy)| {
                request_positions(fields).and_then(
                    |(request_position, horizon_position, provenance)| {
                        ErasureRequestV1::new(ErasureRequestInputV1 {
                            request,
                            subject,
                            scope,
                            selectors,
                            requester,
                            authorization,
                            policy,
                            request_position,
                            horizon_position,
                            provenance,
                        })
                    },
                )
            })
        })
}

pub(super) fn correction_provenance_value(record: &ErasureCorrectionProvenanceV1) -> Value {
    let input = &record.input;
    Value::Array(vec![
        text(ERASURE_CORRECTION_PROVENANCE_TAG_V1),
        uint(VERSION),
        digest(input.rejected_request),
        digest(input.rejected_terminal_state),
        digest(input.correction_reason),
        digest(input.authorization_provenance),
    ])
}

pub(super) fn correction_provenance_from_fields(
    fields: &[Value],
) -> Result<ErasureCorrectionProvenanceV1, ErasureErrorV1> {
    header(fields, ERASURE_CORRECTION_PROVENANCE_TAG_V1)?;
    ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: bytes32(&fields[2])?,
        rejected_terminal_state: bytes32(&fields[3])?,
        correction_reason: bytes32(&fields[4])?,
        authorization_provenance: bytes32(&fields[5])?,
    })
}

pub(super) fn recovery_error_value(record: &ErasureRecoveryErrorV1) -> Value {
    Value::Array(vec![
        text(ERASURE_RECOVERY_ERROR_TAG_V1),
        uint(VERSION),
        digest(record.request()),
        optional_digest(record.manifest()),
        digest(record.failure_subject()),
        uint(record.error().code()),
    ])
}

pub(super) fn recovery_error_from_fields(
    fields: &[Value],
) -> Result<ErasureRecoveryErrorV1, ErasureErrorV1> {
    header(fields, ERASURE_RECOVERY_ERROR_TAG_V1)?;
    ErasureRecoveryErrorV1::new(
        bytes32(&fields[2])?,
        optional_bytes32(&fields[3])?,
        bytes32(&fields[4])?,
        ErasureErrorV1::from_code(unsigned(&fields[5])?)?,
    )
}

pub(super) fn authorization_rejection_value(record: &ErasureAuthorizationRejectionV1) -> Value {
    Value::Array(vec![
        text(ERASURE_AUTHORIZATION_REJECTION_TAG_V1),
        uint(VERSION),
        digest(record.input.request),
        digest(record.input.authorization_provenance),
    ])
}

pub(super) fn authorization_rejection_from_fields(
    fields: &[Value],
) -> Result<ErasureAuthorizationRejectionV1, ErasureErrorV1> {
    header(fields, ERASURE_AUTHORIZATION_REJECTION_TAG_V1)?;
    ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: bytes32(&fields[2])?,
        authorization_provenance: bytes32(&fields[3])?,
    })
}

pub(super) fn scope_commitment_value(record: &ErasureScopeCommitmentV1) -> Value {
    Value::Array(vec![
        text(ERASURE_SCOPE_COMMITMENT_TAG_V1),
        uint(VERSION),
        digest(record.input.request),
        affected_scope_value(record),
        digest(record.input.target_closure),
        optional_digest(record.input.lineage_rule),
    ])
}

fn affected_scope_value(record: &ErasureScopeCommitmentV1) -> Value {
    // Encode both canonical entry kinds in the single ADR-060 affected-scope array.
    Value::Array(
        record
            .input
            .scope_members
            .iter()
            .copied()
            .map(|reference| Value::Array(vec![uint(0), digest(reference)]))
            .chain(
                record
                    .input
                    .scope_timeline_ids
                    .iter()
                    .copied()
                    .map(|timeline| Value::Array(vec![uint(1), timeline_id_value(timeline)])),
            )
            .collect(),
    )
}

fn affected_scope_from_value(
    value: &Value,
) -> Result<(Vec<ErasureReferenceV1>, Vec<TimelineId>), ErasureErrorV1> {
    let entries = array(value, ERASURE_MAX_INVENTORY_TIMELINES)?;
    let mut scope_members = Vec::new();
    let mut scope_timeline_ids = Vec::new();
    let mut timeline_entries_started = false;
    for entry in entries {
        let fields = exact_array(entry, 2)?;
        match unsigned(&fields[0])? {
            0 if !timeline_entries_started => {
                scope_members.push(bytes32(&fields[1])?);
            }
            1 => {
                timeline_entries_started = true;
                scope_timeline_ids.push(timeline_id_from_value(&fields[1])?);
            }
            _ => return Err(ErasureErrorV1::InvalidEncoding),
        }
    }
    Ok((scope_members, scope_timeline_ids))
}

pub(super) fn scope_commitment_from_fields(
    fields: &[Value],
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    header(fields, ERASURE_SCOPE_COMMITMENT_TAG_V1)?;
    let (scope_members, scope_timeline_ids) = affected_scope_from_value(&fields[3])?;
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: bytes32(&fields[2])?,
        scope_members,
        scope_timeline_ids,
        target_closure: bytes32(&fields[4])?,
        lineage_rule: optional_bytes32(&fields[5])?,
    })
}

pub(super) fn freeze_provenance_value(record: &ErasureFreezeProvenanceV1) -> Value {
    Value::Array(vec![
        text(ERASURE_FREEZE_PROVENANCE_TAG_V1),
        uint(VERSION),
        digest(record.input.request),
        digest(record.input.scope_commitment),
        digest(record.input.obligation_set),
        uint(record.input.freeze_position),
        digest(record.input.host_evidence),
    ])
}

pub(super) fn freeze_provenance_from_fields(
    fields: &[Value],
) -> Result<ErasureFreezeProvenanceV1, ErasureErrorV1> {
    header(fields, ERASURE_FREEZE_PROVENANCE_TAG_V1)?;
    ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: bytes32(&fields[2])?,
        scope_commitment: bytes32(&fields[3])?,
        obligation_set: bytes32(&fields[4])?,
        freeze_position: unsigned(&fields[5])?,
        host_evidence: bytes32(&fields[6])?,
    })
}

fn applicability_row_value(row: ErasureFreezeApplicabilityRowV1) -> Value {
    Value::Array(vec![
        uint(row.category().code()),
        uint(row.target_index()),
        uint(row.decision().code()),
        optional_digest(row.owner()),
    ])
}

fn applicability_row_from_value(
    value: &Value,
) -> Result<ErasureFreezeApplicabilityRowV1, ErasureErrorV1> {
    let fields = exact_array(value, 4)?;
    ErasureFreezeApplicabilityRowV1::new(
        ErasureInventoryCategoryV1::from_code(unsigned(&fields[0])?)?,
        unsigned(&fields[1])?,
        ErasureApplicabilityDecisionV1::from_code(unsigned(&fields[2])?)?,
        optional_bytes32(&fields[3])?,
    )
}

fn applicability_matrix_value(rows: &[ErasureFreezeApplicabilityRowV1]) -> Value {
    Value::Array(rows.iter().copied().map(applicability_row_value).collect())
}

fn applicability_matrix_from_value(
    value: &Value,
) -> Result<Vec<ErasureFreezeApplicabilityRowV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_OBLIGATIONS)?
        .iter()
        .map(applicability_row_from_value)
        .collect()
}

pub(super) fn freeze_admission_authorization_value(
    evidence: &ErasureFreezeAdmissionEvidenceV1,
) -> Value {
    Value::Array(vec![
        text(ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1),
        uint(VERSION),
        digest(evidence.input.request),
        digest(evidence.input.scope_commitment),
        digest(evidence.input.obligation_set),
        applicability_matrix_value(&evidence.input.applicability_matrix),
        uint(evidence.input.freeze_position),
        digest(evidence.input.policy),
        digest(evidence.input.trust),
    ])
}

pub(super) fn freeze_admission_evidence_value(
    evidence: &ErasureFreezeAdmissionEvidenceV1,
) -> Value {
    Value::Array(vec![
        text(ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1),
        uint(VERSION),
        digest(evidence.input.request),
        digest(evidence.input.scope_commitment),
        digest(evidence.input.obligation_set),
        applicability_matrix_value(&evidence.input.applicability_matrix),
        uint(evidence.input.freeze_position),
        digest(evidence.input.policy),
        digest(evidence.input.trust),
        digest(evidence.input.authorization_provenance),
    ])
}

pub(super) fn freeze_admission_evidence_from_fields(
    fields: &[Value],
) -> Result<ErasureFreezeAdmissionEvidenceV1, ErasureErrorV1> {
    header(fields, ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1)?;
    ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        request: bytes32(&fields[2])?,
        scope_commitment: bytes32(&fields[3])?,
        obligation_set: bytes32(&fields[4])?,
        applicability_matrix: applicability_matrix_from_value(&fields[5])?,
        freeze_position: unsigned(&fields[6])?,
        policy: bytes32(&fields[7])?,
        trust: bytes32(&fields[8])?,
        authorization_provenance: bytes32(&fields[9])?,
    })
}

pub(super) fn freeze_authorization_evidence_value(
    evidence: &ErasureFreezeAuthorizationEvidenceV1,
) -> Value {
    Value::Array(vec![
        text(ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1),
        uint(VERSION),
        digest(evidence.input.admission_body_digest),
        digest(evidence.input.policy),
        digest(evidence.input.trust),
        Value::Bytes(evidence.input.evidence.clone()),
    ])
}

pub(super) fn freeze_authorization_evidence_from_fields(
    fields: &[Value],
) -> Result<ErasureFreezeAuthorizationEvidenceV1, ErasureErrorV1> {
    header(fields, ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1)?;
    let Value::Bytes(evidence) = &fields[5] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
        admission_body_digest: bytes32(&fields[2])?,
        policy: bytes32(&fields[3])?,
        trust: bytes32(&fields[4])?,
        evidence: evidence.clone(),
    })
}

pub(super) fn freeze_failure_value(record: &ErasureFreezeFailureV1) -> Value {
    Value::Array(vec![
        text(ERASURE_FREEZE_FAILURE_TAG_V1),
        uint(VERSION),
        digest(record.input.request),
        uint(record.input.error.code()),
        digest(record.input.authorization_provenance),
        digest(record.input.evidence),
    ])
}

pub(super) fn freeze_failure_from_fields(
    fields: &[Value],
) -> Result<ErasureFreezeFailureV1, ErasureErrorV1> {
    header(fields, ERASURE_FREEZE_FAILURE_TAG_V1)?;
    ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: bytes32(&fields[2])?,
        error: ErasureErrorV1::from_code(unsigned(&fields[3])?)?,
        authorization_provenance: bytes32(&fields[4])?,
        evidence: bytes32(&fields[5])?,
    })
}

pub(super) fn obligation_value(record: &ErasureObligationV1) -> Value {
    Value::Array(vec![
        text(ERASURE_OBLIGATION_TAG_V1),
        uint(VERSION),
        uint(record.input.category.code()),
        target_value(record.input.target),
        digest(record.input.owner),
        digest(record.input.command_identity),
    ])
}

pub(super) fn obligation_from_fields(
    fields: &[Value],
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    header(fields, ERASURE_OBLIGATION_TAG_V1)?;
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::from_code(unsigned(&fields[2])?)?,
        target: target_from_value(&fields[3])?,
        owner: bytes32(&fields[4])?,
        command_identity: bytes32(&fields[5])?,
    })
}

pub(super) fn obligation_set_value(record: &ErasureObligationSetV1) -> Value {
    Value::Array(vec![
        text(ERASURE_OBLIGATION_SET_TAG_V1),
        uint(VERSION),
        digest(record.input.request),
        references_value(&record.input.obligations),
        digest(record.input.policy),
        digest(record.input.trust),
    ])
}

pub(super) fn obligation_set_from_fields(
    fields: &[Value],
) -> Result<ErasureObligationSetV1, ErasureErrorV1> {
    header(fields, ERASURE_OBLIGATION_SET_TAG_V1)?;
    ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: bytes32(&fields[2])?,
        obligations: bounded_references_from_value(&fields[3], ERASURE_MAX_OBLIGATIONS, false)?,
        policy: bytes32(&fields[4])?,
        trust: bytes32(&fields[5])?,
    })
}

pub(super) fn scope_extension_value(record: &ErasureScopeExtensionV1) -> Value {
    Value::Array(vec![
        text(ERASURE_SCOPE_EXTENSION_TAG_V1),
        uint(VERSION),
        digest(record.input.request),
        digest(record.input.scope_commitment),
        fork_scope_reference_value(record.input.fork, record.input.child_timeline),
        digest(record.input.lineage_rule),
        optional_digest(record.input.predecessor_extension),
        digest(record.input.admission_provenance),
    ])
}

fn fork_scope_reference_value(fork: ErasureReferenceV1, child_timeline: TimelineId) -> Value {
    // Keep the Fork reference and its child Timeline as one typed scope reference.
    Value::Array(vec![digest(fork), timeline_id_value(child_timeline)])
}

fn fork_scope_reference_from_value(
    value: &Value,
) -> Result<(ErasureReferenceV1, TimelineId), ErasureErrorV1> {
    exact_array(value, 2).and_then(|fields| {
        bytes32(&fields[0]).and_then(|fork| {
            timeline_id_from_value(&fields[1]).map(|child_timeline| (fork, child_timeline))
        })
    })
}

pub(super) fn scope_extension_from_fields(
    fields: &[Value],
) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
    header(fields, ERASURE_SCOPE_EXTENSION_TAG_V1)?;
    let (fork, child_timeline) = fork_scope_reference_from_value(&fields[4])?;
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: bytes32(&fields[2])?,
        scope_commitment: bytes32(&fields[3])?,
        fork,
        child_timeline,
        lineage_rule: bytes32(&fields[5])?,
        predecessor_extension: optional_bytes32(&fields[6])?,
        admission_provenance: bytes32(&fields[7])?,
    })
}

pub(super) fn retry_admission_value(record: &ErasureRetryAdmissionV1) -> Value {
    let input = &record.input;
    Value::Array(vec![
        text(ERASURE_RETRY_ADMISSION_TAG_V1),
        uint(VERSION),
        digest(input.request),
        uint(input.attempt_ordinal),
        optional_digest(input.source_receipt),
        references_value(&input.unresolved_obligations),
        references_value(&input.command_identities),
        digest(input.policy),
        digest(input.trust),
        uint(input.admitted_position),
        uint(input.deadline_position),
        digest(input.authorization_provenance),
    ])
}

pub(super) fn retry_admission_from_fields(
    fields: &[Value],
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    header(fields, ERASURE_RETRY_ADMISSION_TAG_V1)?;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: bytes32(&fields[2])?,
        attempt_ordinal: unsigned(&fields[3])?,
        source_receipt: optional_bytes32(&fields[4])?,
        unresolved_obligations: bounded_references_from_value(
            &fields[5],
            ERASURE_MAX_OBLIGATIONS,
            false,
        )?,
        // Command identities are positionally aligned with the sorted obligation
        // references. They are not an independently ordered set: multiple
        // obligations may also refer to the same destruction command.
        command_identities: unordered_references_from_value(&fields[6], ERASURE_MAX_OBLIGATIONS)?,
        policy: bytes32(&fields[7])?,
        trust: bytes32(&fields[8])?,
        admitted_position: unsigned(&fields[9])?,
        deadline_position: unsigned(&fields[10])?,
        authorization_provenance: bytes32(&fields[11])?,
    })
}

pub(super) fn acknowledgement_provenance_value(
    record: &ErasureAcknowledgementProvenanceV1,
) -> Value {
    let input = &record.input;
    Value::Array(vec![
        text(ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1),
        uint(VERSION),
        digest(input.request),
        digest(input.command),
        digest(input.attempt),
        digest(input.obligation),
        digest(input.owner),
        digest(input.scope),
        uint(input.outcome.code()),
        digest(input.evidence),
        digest(input.policy),
        digest(input.trust),
    ])
}

pub(super) fn acknowledgement_provenance_from_fields(
    fields: &[Value],
) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
    header(fields, ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1)?;
    ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
        request: bytes32(&fields[2])?,
        command: bytes32(&fields[3])?,
        attempt: bytes32(&fields[4])?,
        obligation: bytes32(&fields[5])?,
        owner: bytes32(&fields[6])?,
        scope: bytes32(&fields[7])?,
        outcome: ErasureAcknowledgementOutcomeV1::from_code(unsigned(&fields[8])?)?,
        evidence: bytes32(&fields[9])?,
        policy: bytes32(&fields[10])?,
        trust: bytes32(&fields[11])?,
    })
}

pub(super) fn attempt_outcome_value(record: &ErasureAttemptOutcomeV1) -> Value {
    let input = &record.input;
    Value::Array(vec![
        text(ERASURE_ATTEMPT_OUTCOME_TAG_V1),
        uint(VERSION),
        digest(input.request),
        digest(input.attempt),
        optional_digest(input.source_receipt),
        uint(input.lifecycle.code()),
        digest(input.selected_obligations),
        digest(input.acknowledgement_inventory),
        uint(input.terminal_position),
        digest(input.policy),
        digest(input.trust),
    ])
}

pub(super) fn attempt_outcome_from_fields(
    fields: &[Value],
) -> Result<ErasureAttemptOutcomeV1, ErasureErrorV1> {
    header(fields, ERASURE_ATTEMPT_OUTCOME_TAG_V1)?;
    ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request: bytes32(&fields[2])?,
        attempt: bytes32(&fields[3])?,
        source_receipt: optional_bytes32(&fields[4])?,
        lifecycle: ErasureLifecycleV1::from_code(unsigned(&fields[5])?)?,
        selected_obligations: bytes32(&fields[6])?,
        acknowledgement_inventory: bytes32(&fields[7])?,
        terminal_position: unsigned(&fields[8])?,
        policy: bytes32(&fields[9])?,
        trust: bytes32(&fields[10])?,
    })
}

pub(super) fn receipt_provenance_value(record: &ErasureReceiptProvenanceV1) -> Value {
    let input = &record.input;
    Value::Array(vec![
        text(ERASURE_RECEIPT_PROVENANCE_TAG_V1),
        uint(VERSION),
        digest(input.request),
        digest(input.attempt),
        uint(input.attempt_ordinal),
        optional_digest(input.predecessor_receipt),
        digest(input.terminal_state),
        digest(input.evidence_set),
        digest(input.policy),
        digest(input.trust),
        uint(input.issue_position),
    ])
}

pub(super) fn receipt_provenance_from_fields(
    fields: &[Value],
) -> Result<ErasureReceiptProvenanceV1, ErasureErrorV1> {
    header(fields, ERASURE_RECEIPT_PROVENANCE_TAG_V1)?;
    ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request: bytes32(&fields[2])?,
        attempt: bytes32(&fields[3])?,
        attempt_ordinal: unsigned(&fields[4])?,
        predecessor_receipt: optional_bytes32(&fields[5])?,
        terminal_state: bytes32(&fields[6])?,
        evidence_set: bytes32(&fields[7])?,
        policy: bytes32(&fields[8])?,
        trust: bytes32(&fields[9])?,
        issue_position: unsigned(&fields[10])?,
    })
}

pub(super) fn administrative_resolution_value(record: &ErasureAdministrativeResolutionV1) -> Value {
    let input = &record.input;
    Value::Array(vec![
        text(ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1),
        uint(VERSION),
        digest(input.request),
        references_value(&input.affected_digests),
        uint(input.action.code()),
        digest(input.scope_commitment),
        digest(input.policy),
        digest(input.trust),
        digest(input.principal),
        digest(input.authorization_provenance),
        digest(input.reason),
        uint(input.issue_position),
        optional_digest(input.predecessor_resolution),
    ])
}

pub(super) fn administrative_resolution_from_fields(
    fields: &[Value],
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    header(fields, ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1)?;
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request: bytes32(&fields[2])?,
        affected_digests: portable_references_from_value(&fields[3])?,
        action: ErasureAdministrativeResolutionActionV1::from_code(unsigned(&fields[4])?)?,
        scope_commitment: bytes32(&fields[5])?,
        policy: bytes32(&fields[6])?,
        trust: bytes32(&fields[7])?,
        principal: bytes32(&fields[8])?,
        authorization_provenance: bytes32(&fields[9])?,
        reason: bytes32(&fields[10])?,
        issue_position: unsigned(&fields[11])?,
        predecessor_resolution: optional_bytes32(&fields[12])?,
    })
}
pub(super) fn request_identity(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureReferenceV1,
        ErasureScopeV1,
        Vec<ErasureReferenceV1>,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[2]).and_then(|request| {
        bytes32(&fields[3]).and_then(|subject| {
            unsigned(&fields[4])
                .and_then(ErasureScopeV1::from_code)
                .and_then(|scope| {
                    references_from_value(&fields[5], true)
                        .map(|selectors| (request, subject, scope, selectors))
                })
        })
    })
}
pub(super) fn request_authority(
    fields: &[Value],
) -> Result<(ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1), ErasureErrorV1> {
    bytes32(&fields[6]).and_then(|requester| {
        bytes32(&fields[7]).and_then(|authorization| {
            bytes32(&fields[8]).map(|policy| (requester, authorization, policy))
        })
    })
}
pub(super) fn request_positions(
    fields: &[Value],
) -> Result<(u64, u64, ErasureReferenceV1), ErasureErrorV1> {
    unsigned(&fields[9]).and_then(|request_position| {
        unsigned(&fields[10]).and_then(|horizon_position| {
            bytes32(&fields[11]).map(|provenance| (request_position, horizon_position, provenance))
        })
    })
}
pub(super) fn state_core_value(state: &ErasureStateV1) -> Value {
    Value::Array(vec![
        text(ERS1),
        uint(VERSION),
        digest(state.request),
        uint(state.lifecycle.code()),
        optional_uint(state.freeze_position),
        digest(state.coordinator),
        references_value(&state.pending_owners),
        references_value(&state.failed_owners),
        uint(state.replay_claim.code()),
        optional_digest(state.previous_state),
        digest(state.provenance),
    ])
}
pub(super) fn state_value(state: &ErasureStateV1) -> Value {
    Value::Array(vec![
        text(ERS1),
        uint(VERSION),
        digest(state.request),
        uint(state.lifecycle.code()),
        optional_uint(state.freeze_position),
        digest(state.coordinator),
        references_value(&state.pending_owners),
        references_value(&state.failed_owners),
        uint(state.replay_claim.code()),
        optional_digest(state.previous_state),
        digest(state.provenance),
        digest(state.state_digest),
    ])
}
pub(super) fn state_from_fields(fields: &[Value]) -> Result<ErasureStateV1, ErasureErrorV1> {
    header(fields, ERS1)
        .and_then(|()| state_identity(fields))
        .and_then(|(request, lifecycle, freeze_position, coordinator)| {
            state_owners(fields).and_then(|(pending_owners, failed_owners, replay_claim)| {
                state_provenance(fields).and_then(|(previous_state, provenance, state_digest)| {
                    let state = ErasureStateV1 {
                        request,
                        lifecycle,
                        freeze_position,
                        coordinator,
                        pending_owners,
                        failed_owners,
                        replay_claim,
                        previous_state,
                        provenance,
                        state_digest,
                    };
                    state
                        .validate()
                        .and_then(|()| state.clone().with_digest())
                        .and_then(|expected| {
                            if expected.state_digest == state.state_digest {
                                Ok(state)
                            } else {
                                Err(ErasureErrorV1::ProvenanceMissing)
                            }
                        })
                })
            })
        })
}
pub(super) fn state_identity(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureLifecycleV1,
        Option<u64>,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[2]).and_then(|request| {
        unsigned(&fields[3])
            .and_then(ErasureLifecycleV1::from_code)
            .and_then(|lifecycle| {
                optional_unsigned(&fields[4]).and_then(|freeze_position| {
                    bytes32(&fields[5])
                        .map(|coordinator| (request, lifecycle, freeze_position, coordinator))
                })
            })
    })
}
pub(super) fn state_owners(
    fields: &[Value],
) -> Result<
    (
        Vec<ErasureReferenceV1>,
        Vec<ErasureReferenceV1>,
        ErasureReplayClaimV1,
    ),
    ErasureErrorV1,
> {
    bounded_references_from_value(&fields[6], ERASURE_MAX_OUTCOME_OWNERS, false).and_then(
        |pending_owners| {
            bounded_references_from_value(&fields[7], ERASURE_MAX_OUTCOME_OWNERS, false).and_then(
                |failed_owners| {
                    unsigned(&fields[8])
                        .and_then(ErasureReplayClaimV1::from_code)
                        .map(|replay_claim| (pending_owners, failed_owners, replay_claim))
                },
            )
        },
    )
}
pub(super) fn state_provenance(
    fields: &[Value],
) -> Result<
    (
        Option<ErasureReferenceV1>,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    optional_bytes32(&fields[9]).and_then(|previous_state| {
        bytes32(&fields[10]).and_then(|provenance| {
            bytes32(&fields[11]).map(|state_digest| (previous_state, provenance, state_digest))
        })
    })
}
pub(super) fn receipt_fields(input: &ErasureReceiptInputV1) -> Vec<Value> {
    vec![
        text(ERASURE_RECEIPT_TAG_V1),
        uint(VERSION),
        digest(input.request),
        digest(input.terminal_state),
        uint(input.lifecycle.code()),
        uint(input.freeze_position),
        targets_value(&input.frozen_targets),
        Value::Array(
            input
                .acknowledgements
                .iter()
                .copied()
                .map(acknowledgement_value)
                .collect(),
        ),
        references_value(&input.pending_owners),
        references_value(&input.failed_owners),
        inventories_value(&input.inventories),
        uint(input.replay_claim.code()),
        digest(input.policy),
        digest(input.trust),
        digest(input.provenance),
        uint(input.issue_position),
        digest(input.receipt_digest),
        digest(input.signature),
        digest(input.coordinator),
    ]
}
pub(super) fn receipt_value(input: &ErasureReceiptInputV1) -> Value {
    Value::Array(receipt_fields(input))
}
pub(super) fn receipt_core_value(input: &ErasureReceiptInputV1) -> Value {
    let mut fields = receipt_fields(input);
    fields.remove(16);
    Value::Array(fields)
}
pub(super) fn acknowledgement_value(ack: ErasureAcknowledgementV1) -> Value {
    Value::Array(vec![
        digest(ack.obligation),
        target_value(ack.target),
        digest(ack.owner),
        digest(ack.evidence),
        uint(ack.outcome.code()),
    ])
}
pub(super) fn receipt_from_fields(fields: &[Value]) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    header(fields, ERASURE_RECEIPT_TAG_V1)?;
    let request = bytes32(&fields[2])?;
    let terminal_state = bytes32(&fields[3])?;
    let lifecycle = ErasureLifecycleV1::from_code(unsigned(&fields[4])?)?;
    let freeze_position = unsigned(&fields[5])?;
    let frozen_targets = targets_from_value(&fields[6])?;
    let acknowledgements = acknowledgements_from_value(&fields[7])?;
    let pending_owners =
        bounded_references_from_value(&fields[8], ERASURE_MAX_OUTCOME_OWNERS, false)?;
    let failed_owners =
        bounded_references_from_value(&fields[9], ERASURE_MAX_OUTCOME_OWNERS, false)?;
    let inventories = inventories_from_value(&fields[10])?;
    let replay_claim = ErasureReplayClaimV1::from_code(unsigned(&fields[11])?)?;
    let (policy, trust, provenance, issue_position, receipt_digest, signature) =
        receipt_proof(&fields[12..18])?;
    let coordinator = bytes32(&fields[18])?;
    let receipt = ErasureReceiptInputV1 {
        request,
        terminal_state,
        coordinator,
        lifecycle,
        freeze_position,
        acknowledgements,
        frozen_targets,
        pending_owners,
        failed_owners,
        inventories,
        replay_claim,
        policy,
        trust,
        provenance,
        issue_position,
        signature,
        receipt_digest,
    };
    let expected = ErasureReceiptV1::new(receipt)?;
    if expected.receipt_digest() != receipt_digest {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    Ok(expected)
}
pub(super) fn receipt_proof(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureReferenceV1,
        ErasureReferenceV1,
        u64,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[0]).and_then(|policy| {
        bytes32(&fields[1]).and_then(|trust| {
            bytes32(&fields[2]).and_then(|provenance| {
                unsigned(&fields[3]).and_then(|issue_position| {
                    bytes32(&fields[4]).and_then(|receipt_digest| {
                        bytes32(&fields[5]).map(|signature| {
                            (
                                policy,
                                trust,
                                provenance,
                                issue_position,
                                receipt_digest,
                                signature,
                            )
                        })
                    })
                })
            })
        })
    })
}
pub(super) fn acknowledgements_from_value(
    value: &Value,
) -> Result<Vec<ErasureAcknowledgementV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT).and_then(|values| {
        values
            .iter()
            .map(|value| {
                exact_array(value, 5).and_then(|fields| {
                    bytes32(&fields[0]).and_then(|obligation| {
                        target_from_value(&fields[1]).and_then(|target| {
                            bytes32(&fields[2]).and_then(|owner| {
                                bytes32(&fields[3]).and_then(|evidence| {
                                    unsigned(&fields[4])
                                        .and_then(ErasureAcknowledgementOutcomeV1::from_code)
                                        .map(|outcome| ErasureAcknowledgementV1 {
                                            obligation,
                                            target,
                                            owner,
                                            evidence,
                                            outcome,
                                        })
                                })
                            })
                        })
                    })
                })
            })
            .collect::<Result<Vec<_>, ErasureErrorV1>>()
            .and_then(|acknowledgements| {
                if strictly_increasing(&acknowledgements) {
                    Ok(acknowledgements)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
pub(super) fn target_value(target: ErasureRequiredTargetV1) -> Value {
    Value::Array(vec![
        uint(target.artifact_class.code()),
        digest(target.artifact_digest),
        uint(target.key_role.code()),
        digest(target.key_digest),
        digest(target.replica_set),
        digest(target.replica_id),
    ])
}
pub(super) fn target_from_value(value: &Value) -> Result<ErasureRequiredTargetV1, ErasureErrorV1> {
    exact_array(value, 6).and_then(|fields| {
        unsigned(&fields[0])
            .and_then(ErasureArtifactClassV1::from_code)
            .and_then(|artifact_class| {
                bytes32(&fields[1]).and_then(|artifact_digest| {
                    unsigned(&fields[2])
                        .and_then(ErasureKeyRoleV1::from_code)
                        .and_then(|key_role| {
                            bytes32(&fields[3]).and_then(|key_digest| {
                                bytes32(&fields[4]).and_then(|replica_set| {
                                    bytes32(&fields[5]).map(|replica_id| ErasureRequiredTargetV1 {
                                        artifact_class,
                                        artifact_digest,
                                        key_role,
                                        key_digest,
                                        replica_set,
                                        replica_id,
                                    })
                                })
                            })
                        })
                })
            })
    })
}
pub(super) fn targets_value(targets: &[ErasureRequiredTargetV1]) -> Value {
    Value::Array(targets.iter().copied().map(target_value).collect())
}
pub(super) fn targets_from_value(
    value: &Value,
) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_TARGETS).and_then(|values| {
        values
            .iter()
            .map(target_from_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|targets| {
                if strictly_increasing(&targets) {
                    Ok(targets)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
pub(super) fn transition_value(transition: ErasureArtifactTransitionV1) -> Value {
    Value::Array(vec![
        uint(transition.from.code()),
        uint(transition.to.code()),
        digest(transition.reason),
        digest(transition.owner),
        digest(transition.acknowledgements),
        digest(transition.provenance),
    ])
}
pub(super) fn transition_from_value(
    value: &Value,
) -> Result<ErasureArtifactTransitionV1, ErasureErrorV1> {
    exact_array(value, 6).and_then(|fields| {
        unsigned(&fields[0])
            .and_then(ErasureReplayClaimV1::from_code)
            .and_then(|from| {
                unsigned(&fields[1])
                    .and_then(ErasureReplayClaimV1::from_code)
                    .and_then(|to| {
                        bytes32(&fields[2]).and_then(|reason| {
                            bytes32(&fields[3]).and_then(|owner| {
                                bytes32(&fields[4]).and_then(|acknowledgements| {
                                    bytes32(&fields[5]).map(|provenance| {
                                        ErasureArtifactTransitionV1 {
                                            from,
                                            to,
                                            reason,
                                            owner,
                                            acknowledgements,
                                            provenance,
                                        }
                                    })
                                })
                            })
                        })
                    })
            })
    })
}
pub(super) fn inventory_result_value(result: &ErasureInventoryResultV1) -> Value {
    Value::Array(vec![
        uint(result.category.code()),
        target_value(result.target),
        transition_value(result.transition),
        digest(result.retained_disclosure),
    ])
}
pub(super) fn inventory_result_from_value(
    value: &Value,
) -> Result<ErasureInventoryResultV1, ErasureErrorV1> {
    exact_array(value, 4).and_then(|fields| {
        unsigned(&fields[0])
            .and_then(ErasureInventoryCategoryV1::from_code)
            .and_then(|category| {
                target_from_value(&fields[1]).and_then(|target| {
                    transition_from_value(&fields[2]).and_then(|transition| {
                        bytes32(&fields[3]).map(|retained_disclosure| ErasureInventoryResultV1 {
                            category,
                            target,
                            transition,
                            retained_disclosure,
                        })
                    })
                })
            })
    })
}
pub(super) fn inventory_value(inventory: &[ErasureInventoryResultV1]) -> Value {
    Value::Array(inventory.iter().map(inventory_result_value).collect())
}
pub(super) fn inventory_from_value(
    value: &Value,
) -> Result<Vec<ErasureInventoryResultV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(inventory_result_from_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|results| {
                if strictly_increasing(&results) {
                    Ok(results)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
pub(super) fn inventories_value(inventories: &ErasureReceiptInventoriesV1) -> Value {
    Value::Array(vec![
        inventory_value(&inventories.artifacts),
        inventory_value(&inventories.keys),
        inventory_value(&inventories.replicas),
        inventory_value(&inventories.backups),
    ])
}
pub(super) fn inventories_from_value(
    value: &Value,
) -> Result<ErasureReceiptInventoriesV1, ErasureErrorV1> {
    exact_array(value, 4).and_then(|fields| {
        inventory_from_value(&fields[0]).and_then(|artifacts| {
            inventory_from_value(&fields[1]).and_then(|keys| {
                inventory_from_value(&fields[2]).and_then(|replicas| {
                    inventory_from_value(&fields[3]).map(|backups| ErasureReceiptInventoriesV1 {
                        artifacts,
                        keys,
                        replicas,
                        backups,
                    })
                })
            })
        })
    })
}
pub(super) const fn inventories_exceed_bound(inventories: &ErasureReceiptInventoriesV1) -> bool {
    inventories.artifacts.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.keys.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.replicas.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.backups.len() > ERASURE_MAX_INVENTORY_RESULTS
}
pub(super) fn sort_inventories(inventories: &mut ErasureReceiptInventoriesV1) {
    inventories.artifacts.sort_unstable();
    inventories.keys.sort_unstable();
    inventories.replicas.sort_unstable();
    inventories.backups.sort_unstable();
}
pub(super) fn inventories_have_duplicate_targets(
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    has_duplicate_by_inventory_target(&inventories.artifacts)
        || has_duplicate_by_inventory_target(&inventories.keys)
        || has_duplicate_by_inventory_target(&inventories.replicas)
        || has_duplicate_by_inventory_target(&inventories.backups)
}
pub(super) fn inventory_categories_match(inventories: &ErasureReceiptInventoriesV1) -> bool {
    inventories
        .artifacts
        .iter()
        .all(|entry| entry.category == ErasureInventoryCategoryV1::Artifact)
        && inventories
            .keys
            .iter()
            .all(|entry| entry.category == ErasureInventoryCategoryV1::Key)
        && inventories
            .replicas
            .iter()
            .all(|entry| entry.category == ErasureInventoryCategoryV1::Replica)
        && inventories
            .backups
            .iter()
            .all(|entry| entry.category == ErasureInventoryCategoryV1::Backup)
}
pub(super) fn has_duplicate_by_inventory_target(entries: &[ErasureInventoryResultV1]) -> bool {
    entries
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target)
}
pub(super) fn inventory_transitions_preserve_or_weaken(
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .all(|entry| {
        entry
            .transition
            .from
            .preserves_or_weakens(entry.transition.to)
    })
}

pub(super) fn inventory_replay_claim(
    inventories: &ErasureReceiptInventoriesV1,
) -> ErasureReplayClaimV1 {
    inventories
        .artifacts
        .iter()
        .chain(&inventories.keys)
        .chain(&inventories.replicas)
        .chain(&inventories.backups)
        .fold(ErasureReplayClaimV1::Exact, |claim, entry| {
            claim.weakened_to(entry.transition.to)
        })
}
pub(super) fn inventories_are_within_closure(
    frozen_targets: &[ErasureRequiredTargetV1],
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    inventories
        .artifacts
        .iter()
        .chain(&inventories.keys)
        .chain(&inventories.replicas)
        .chain(&inventories.backups)
        .map(|entry| entry.target)
        .all(|target| frozen_targets.binary_search(&target).is_ok())
}
pub(super) fn has_duplicate_acknowledgement_identity(
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    acknowledgements
        .windows(2)
        .any(|pair| (pair[0].obligation, pair[0].owner) == (pair[1].obligation, pair[1].owner))
}
pub(super) fn acknowledgements_are_closure_subset(
    frozen_targets: &[ErasureRequiredTargetV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    acknowledgements.iter().all(|acknowledgement| {
        frozen_targets
            .binary_search(&acknowledgement.target)
            .is_ok()
    })
}
pub(super) fn references_value(references: &[ErasureReferenceV1]) -> Value {
    Value::Array(references.iter().copied().map(digest).collect())
}
pub(super) fn timeline_id_value(timeline: TimelineId) -> Value {
    Value::Bytes(timeline.inner().to_bytes().to_vec())
}
fn timeline_id_from_value(value: &Value) -> Result<TimelineId, ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map(ulid::Ulid::from_bytes)
            .map(TimelineId::from_ulid)
            .map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn references_from_value(
    value: &Value,
    required: bool,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    bounded_references_from_value(value, ERASURE_MAX_REFERENCES, required)
}

pub(super) fn portable_references_from_value(
    value: &Value,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    bounded_references_from_value(value, ERASURE_MAX_OBLIGATIONS, false)
}

pub(super) fn bounded_references_from_value(
    value: &Value,
    maximum: usize,
    required: bool,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    unordered_references_from_value(value, maximum).and_then(|references| {
        if (required && references.is_empty()) || !strictly_increasing(&references) {
            Err(ErasureErrorV1::ScopeInvalid)
        } else {
            Ok(references)
        }
    })
}

pub(super) fn unordered_references_from_value(
    value: &Value,
    maximum: usize,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    array(value, maximum).and_then(|values| values.iter().map(bytes32).collect())
}

pub(super) fn header(fields: &[Value], contract: &str) -> Result<(), ErasureErrorV1> {
    string(&fields[0]).and_then(|found_contract| {
        if found_contract == contract {
            unsigned(&fields[1]).and_then(|version| {
                if version == VERSION {
                    Ok(())
                } else {
                    Err(ErasureErrorV1::UnsupportedVersion)
                }
            })
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
pub(super) fn invalid_owner_sets(
    pending: &[ErasureReferenceV1],
    failed: &[ErasureReferenceV1],
) -> bool {
    pending.len().saturating_add(failed.len()) > ERASURE_MAX_OUTCOME_OWNERS
        || !strictly_increasing(pending)
        || !strictly_increasing(failed)
        || pending
            .iter()
            .any(|reference| failed.binary_search(reference).is_ok())
}
pub(super) fn has_duplicate<T: Eq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}
pub(super) fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
pub(super) fn freeze_is_monotonic(previous: Option<u64>, next: Option<u64>) -> bool {
    previous.is_none() || previous == next
}
pub(super) const fn reference_zero() -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([0; 32])
}
pub(super) fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
pub(super) fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
pub(super) fn digest(reference: ErasureReferenceV1) -> Value {
    Value::Bytes(reference.digest().to_vec())
}
pub(super) fn optional_digest(reference: Option<ErasureReferenceV1>) -> Value {
    reference.map_or(Value::Null, digest)
}
pub(super) fn optional_uint(value: Option<u64>) -> Value {
    value.map_or(Value::Null, uint)
}
pub(super) fn encode_canonical(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
pub(super) fn encode_limited(value: &Value, maximum: usize) -> Result<Vec<u8>, ErasureErrorV1> {
    encode_canonical(value).and_then(|bytes| {
        if bytes.len() <= maximum {
            Ok(bytes)
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    })
}
pub(super) fn decode_limited(
    bytes: &[u8],
    maximum: usize,
    maximum_array: usize,
) -> Result<Value, ErasureErrorV1> {
    decode_limited_value(bytes, maximum, maximum_array)
}

fn decode_limited_value(
    bytes: &[u8],
    maximum: usize,
    maximum_array: usize,
) -> Result<Value, ErasureErrorV1> {
    if bytes.len() > maximum {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    cbor_shape_is_bounded(bytes, maximum_array)?;
    // `cbor_shape_is_bounded` admits only the canonical, bounded subset that
    // this protocol uses: definite arrays, primitive values, and minimally
    // encoded arguments. Maps, tags, floats, and indefinite items are
    // rejected before the CBOR decoder is invoked.
    ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)
}
pub(super) fn cbor_shape_is_bounded(
    bytes: &[u8],
    maximum_array: usize,
) -> Result<(), ErasureErrorV1> {
    cbor_item_end(bytes, 0, 0, maximum_array).and_then(|end| {
        if end == bytes.len() {
            Ok(())
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
pub(super) fn cbor_item_end(
    bytes: &[u8],
    offset: usize,
    depth: usize,
    maximum_array: usize,
) -> Result<usize, ErasureErrorV1> {
    if depth > 16 || offset >= bytes.len() {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let initial = bytes[offset];
    let major = initial >> 5;
    cbor_argument(bytes, offset + 1, initial & 0x1f).and_then(|(argument, next)| match major {
        0 | 1 => Ok(next),
        2 | 3 => match usize::try_from(argument) {
            Ok(length) if length <= bytes.len().saturating_sub(next) => next
                .checked_add(length)
                .ok_or(ErasureErrorV1::InvalidEncoding),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        },
        4 if argument <= maximum_array as u64 => cbor_array_end(
            bytes,
            next,
            depth.saturating_add(1),
            argument,
            maximum_array,
        ),
        7 if argument <= 22 => Ok(next),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    })
}
pub(super) fn cbor_array_end(
    bytes: &[u8],
    mut offset: usize,
    depth: usize,
    count: u64,
    maximum_array: usize,
) -> Result<usize, ErasureErrorV1> {
    for _ in 0..count {
        let Ok(next) = cbor_item_end(bytes, offset, depth, maximum_array) else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        offset = next;
    }
    Ok(offset)
}
pub(super) fn cbor_argument(
    bytes: &[u8],
    offset: usize,
    additional: u8,
) -> Result<(u64, usize), ErasureErrorV1> {
    match additional {
        0..=23 => Ok((u64::from(additional), offset)),
        24 => cbor_argument_bytes(bytes, offset, 1, 24),
        25 => cbor_argument_bytes(bytes, offset, 2, 256),
        26 => cbor_argument_bytes(bytes, offset, 4, 65_536),
        27 => cbor_argument_bytes(bytes, offset, 8, 4_294_967_296),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn cbor_argument_bytes(
    bytes: &[u8],
    offset: usize,
    width: usize,
    minimum: u64,
) -> Result<(u64, usize), ErasureErrorV1> {
    let end = offset.saturating_add(width);
    if end > bytes.len() {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let mut encoded = [0_u8; 8];
    encoded[8 - width..].copy_from_slice(&bytes[offset..end]);
    let value = u64::from_be_bytes(encoded);
    if value < minimum {
        Err(ErasureErrorV1::InvalidEncoding)
    } else {
        Ok((value, end))
    }
}
pub(super) fn array(value: &Value, maximum: usize) -> Result<&[Value], ErasureErrorV1> {
    match value {
        Value::Array(values) => bounded_array(values, maximum),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
const fn bounded_array(values: &[Value], maximum: usize) -> Result<&[Value], ErasureErrorV1> {
    if values.len() <= maximum {
        Ok(values)
    } else {
        Err(ErasureErrorV1::ScopeInvalid)
    }
}
pub(super) fn exact_array(value: &Value, expected: usize) -> Result<&[Value], ErasureErrorV1> {
    match value {
        Value::Array(values) if values.len() == expected => Ok(values),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

pub(super) fn string(value: &Value) -> Result<&str, ErasureErrorV1> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn unsigned(value: &Value) -> Result<u64, ErasureErrorV1> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn optional_unsigned(value: &Value) -> Result<Option<u64>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        unsigned(value).map(Some)
    }
}
pub(super) fn bytes32(value: &Value) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map(ErasureReferenceV1::from_digest)
            .map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn optional_bytes32(
    value: &Value,
) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes32(value).map(Some)
    }
}
pub(super) fn domain_digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

/// Immutable, payload-free, non-authoritative evidence that one durable ERCRP1
/// graph failed recovery.
///
/// This diagnostic never authorizes containment and never proves that the
/// recovered graph is invalid. Consumers that need authority must use a
/// successfully verified state instead of treating the presence of this record
/// as an authority grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureRecoveryErrorV1 {
    pub(super) request: ErasureReferenceV1,
    pub(super) manifest: Option<ErasureReferenceV1>,
    pub(super) failure_subject: ErasureReferenceV1,
    pub(super) error: ErasureErrorV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureRecoveryErrorV1 {
    /// Construct and content-address one recovery failure.
    ///
    /// The record retains only minimized references and the closed error code;
    /// it never copies erased or application payload bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding or size-bound error.
    pub fn new(
        request: ErasureReferenceV1,
        manifest: Option<ErasureReferenceV1>,
        failure_subject: ErasureReferenceV1,
        error: ErasureErrorV1,
    ) -> Result<Self, ErasureErrorV1> {
        Self {
            request,
            manifest,
            failure_subject,
            error,
            content_digest: ErasureReferenceV1::from_digest([0; 32]),
        }
        .with_digest()
    }

    /// Return the ERQ1 request whose recovery failed.
    #[must_use]
    pub const fn request(self) -> ErasureReferenceV1 {
        self.request
    }

    /// Return the ERCRP1 manifest that was being recovered.
    #[must_use]
    pub const fn manifest(self) -> Option<ErasureReferenceV1> {
        self.manifest
    }

    /// Return the minimized reference that identifies the failed recovery subject.
    #[must_use]
    pub const fn failure_subject(self) -> ErasureReferenceV1 {
        self.failure_subject
    }

    /// Return the closed recovery error.
    #[must_use]
    pub const fn error(self) -> ErasureErrorV1 {
        self.error
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact deterministic ERRE1 record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding or size-bound error.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &recovery_error_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical ERRE1 record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(bytes, ERASURE_PORTABLE_RECORD_MAX_BYTES, 6)
            .and_then(|value| exact_array(&value, 6).and_then(recovery_error_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &recovery_error_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_RECOVERY_ERROR_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureCorrectionProvenanceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureCorrectionProvenanceInputV1 {
    /// Rejected ERQ1 digest.
    pub rejected_request: ErasureReferenceV1,
    /// Rejected terminal ERS1 digest.
    pub rejected_terminal_state: ErasureReferenceV1,
    /// Digest of the correction reason.
    pub correction_reason: ErasureReferenceV1,
    /// Host authorization provenance digest.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Content-addressed provenance for a corrected rejected request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCorrectionProvenanceV1 {
    pub(super) input: ErasureCorrectionProvenanceInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureCorrectionProvenanceV1 {
    /// Construct and content-address a correction-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if the record exceeds its bound.
    pub fn new(input: ErasureCorrectionProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the rejected ERQ1 digest.
    #[must_use]
    pub const fn rejected_request(&self) -> ErasureReferenceV1 {
        self.input.rejected_request
    }

    /// Return the rejected terminal ERS1 digest.
    #[must_use]
    pub const fn rejected_terminal_state(&self) -> ErasureReferenceV1 {
        self.input.rejected_terminal_state
    }

    /// Return the correction-reason digest.
    #[must_use]
    pub const fn correction_reason(&self) -> ErasureReferenceV1 {
        self.input.correction_reason
    }

    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &correction_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical correction-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 6).and_then(correction_provenance_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &correction_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_CORRECTION_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an immutable resolved-scope commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeCommitmentInputV1 {
    /// ERQ1 digest whose selectors were resolved.
    pub request: ErasureReferenceV1,
    /// Canonical Timeline/Fork members resolved by the host.
    pub scope_members: Vec<ErasureReferenceV1>,
    /// Exact affected Timeline/Fork identifiers resolved at the initial freeze.
    pub scope_timeline_ids: Vec<TimelineId>,
    /// Digest of the exact frozen target closure.
    pub target_closure: ErasureReferenceV1,
    /// Immutable future-Fork lineage-expansion rule admitted before freeze.
    ///
    /// `None` means that the initial affected scope is the entire effective
    /// scope for this ERQ1. A mutable extension head is deliberately not part
    /// of this immutable content-addressed object.
    pub lineage_rule: Option<ErasureReferenceV1>,
}

/// Content-addressed resolved scope frozen before destructive work begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeCommitmentV1 {
    pub(super) input: ErasureScopeCommitmentInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureScopeCommitmentV1 {
    /// Validate and content-address one resolved scope.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an empty, duplicate, or oversized scope.
    pub fn new(input: ErasureScopeCommitmentInputV1) -> Result<Self, ErasureErrorV1> {
        if input.scope_members.is_empty()
            || !strictly_increasing(&input.scope_members)
            || input.scope_timeline_ids.len() > ERASURE_MAX_INVENTORY_TIMELINES
            || input
                .scope_members
                .len()
                .saturating_add(input.scope_timeline_ids.len())
                > ERASURE_MAX_INVENTORY_TIMELINES
            || !strictly_increasing(&input.scope_timeline_ids)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return canonical Timeline/Fork members.
    #[must_use]
    pub fn scope_members(&self) -> &[ErasureReferenceV1] {
        &self.input.scope_members
    }
    /// Return the exact Timeline/Fork identifiers included by the initial freeze.
    #[must_use]
    pub fn scope_timeline_ids(&self) -> &[TimelineId] {
        &self.input.scope_timeline_ids
    }
    /// Return the frozen target-closure digest.
    #[must_use]
    pub const fn target_closure(&self) -> ErasureReferenceV1 {
        self.input.target_closure
    }
    /// Return the immutable future-Fork lineage rule, when admitted.
    #[must_use]
    pub const fn lineage_rule(&self) -> Option<ErasureReferenceV1> {
        self.input.lineage_rule
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Encode the deterministic portable record.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds the portable bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &scope_commitment_value(self),
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
        )
    }
    /// Decode one canonical scope commitment.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
            ERASURE_MAX_INVENTORY_TIMELINES,
        )
        .and_then(|value| exact_array(&value, 6).and_then(scope_commitment_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &scope_commitment_value(&self),
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_SCOPE_COMMITMENT_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Closed policy-applicability decision for one category and target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureApplicabilityDecisionV1 {
    /// Policy determined that no obligation applies.
    Inapplicable,
    /// Policy admitted one category-scoped owner obligation.
    Applicable,
}

impl ErasureApplicabilityDecisionV1 {
    pub(super) const fn code(self) -> u64 {
        match self {
            Self::Inapplicable => 0,
            Self::Applicable => 1,
        }
    }

    pub(super) const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Inapplicable),
            1 => Ok(Self::Applicable),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// One canonical row in the complete category-by-target applicability matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeApplicabilityRowV1 {
    pub(super) category: ErasureInventoryCategoryV1,
    pub(super) target_index: u64,
    pub(super) decision: ErasureApplicabilityDecisionV1,
    pub(super) owner: Option<ErasureReferenceV1>,
}

impl ErasureFreezeApplicabilityRowV1 {
    /// Construct one exact applicability row.
    ///
    /// # Errors
    ///
    /// Returns a scope error unless owner presence exactly matches the decision.
    pub const fn new(
        category: ErasureInventoryCategoryV1,
        target_index: u64,
        decision: ErasureApplicabilityDecisionV1,
        owner: Option<ErasureReferenceV1>,
    ) -> Result<Self, ErasureErrorV1> {
        if matches!(
            (decision, owner),
            (ErasureApplicabilityDecisionV1::Applicable, Some(_))
                | (ErasureApplicabilityDecisionV1::Inapplicable, None)
        ) {
            Ok(Self {
                category,
                target_index,
                decision,
                owner,
            })
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    }

    /// Return the closed obligation category.
    #[must_use]
    pub const fn category(self) -> ErasureInventoryCategoryV1 {
        self.category
    }

    /// Return the index into the canonical target closure.
    #[must_use]
    pub const fn target_index(self) -> u64 {
        self.target_index
    }

    /// Return the policy-applicability decision.
    #[must_use]
    pub const fn decision(self) -> ErasureApplicabilityDecisionV1 {
        self.decision
    }

    /// Return the category-scoped owner for an applicable row.
    #[must_use]
    pub const fn owner(self) -> Option<ErasureReferenceV1> {
        self.owner
    }
}

/// Construction fields for retained #187-owned authorization evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAuthorizationEvidenceInputV1 {
    /// Digest of the exact domain-separated ERFA1 authorization preimage.
    pub admission_body_digest: ErasureReferenceV1,
    /// Policy revision under which the evidence was admitted.
    pub policy: ErasureReferenceV1,
    /// Trust revision under which the evidence was admitted.
    pub trust: ErasureReferenceV1,
    /// Canonical proof or signature material interpreted by #187.
    pub evidence: Vec<u8>,
}

/// Retained canonical evidence authenticating one freeze-admission body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAuthorizationEvidenceV1 {
    pub(super) input: ErasureFreezeAuthorizationEvidenceInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureFreezeAuthorizationEvidenceV1 {
    /// Construct and content-address retained host authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed error for empty or oversized proof material.
    pub fn new(input: ErasureFreezeAuthorizationEvidenceInputV1) -> Result<Self, ErasureErrorV1> {
        if input.evidence.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the authenticated ERFA1 authorization-body digest.
    #[must_use]
    pub const fn admission_body_digest(&self) -> ErasureReferenceV1 {
        self.input.admission_body_digest
    }

    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return the opaque canonical #187 evidence bytes.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.input.evidence
    }

    /// Return this evidence object's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Verify that this evidence names the exact supplied admission body.
    ///
    /// This verifies the canonical digest binding only. The host-owned
    /// [`ErasureFreezeAuthorizationVerifierV1`][super::ErasureFreezeAuthorizationVerifierV1]
    /// remains responsible for
    /// interpreting the retained policy, trust, and proof material.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization error when the body digest differs, or
    /// propagates a canonical-encoding error from the admission body.
    pub fn verify_admission_body_binding(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        admission
            .authorization_body_digest()
            .and_then(|body_digest| {
                (self.admission_body_digest() == body_digest)
                    .then_some(())
                    .ok_or(ErasureErrorV1::Unauthorized)
            })
    }

    /// Encode the exact retained authorization-evidence object.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds 16 MiB.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_authorization_evidence_value(self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
    }

    /// Decode one exact retained authorization-evidence object.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| {
            exact_array(&value, 6).and_then(freeze_authorization_evidence_from_fields)
        })
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_authorization_evidence_value(&self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for the canonical freeze-admission applicability object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAdmissionEvidenceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Resolved scope-commitment address.
    pub scope_commitment: ErasureReferenceV1,
    /// Frozen obligation-set address.
    pub obligation_set: ErasureReferenceV1,
    /// Complete category-major applicability matrix.
    pub applicability_matrix: Vec<ErasureFreezeApplicabilityRowV1>,
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Retained authorization-evidence content address.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Complete, content-addressed freeze-admission applicability evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAdmissionEvidenceV1 {
    pub(super) input: ErasureFreezeAdmissionEvidenceInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureFreezeAdmissionEvidenceV1 {
    /// Construct and validate one exact `ERFA1` object.
    ///
    /// # Errors
    ///
    /// Returns a scope error unless the matrix is complete and category-major.
    pub fn new(input: ErasureFreezeAdmissionEvidenceInputV1) -> Result<Self, ErasureErrorV1> {
        validate_applicability_matrix(&input.applicability_matrix)?;
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return the resolved scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }

    /// Return the frozen obligation set.
    #[must_use]
    pub const fn obligation_set(&self) -> ErasureReferenceV1 {
        self.input.obligation_set
    }

    /// Return the complete category-major applicability matrix.
    #[must_use]
    pub fn applicability_matrix(&self) -> &[ErasureFreezeApplicabilityRowV1] {
        &self.input.applicability_matrix
    }

    /// Return the authoritative freeze position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.input.freeze_position
    }

    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return the retained authorization-evidence address.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return the exact domain-separated authorization-body digest.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the canonical preimage exceeds 16 MiB.
    pub fn authorization_body_digest(&self) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        encode_limited(
            &freeze_admission_authorization_value(self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
        .map(|bytes| {
            ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1,
                &bytes,
            ))
        })
    }

    /// Return this admission object's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact `ERFA1` object.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds 16 MiB.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_admission_evidence_value(self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
    }

    /// Decode one exact `ERFA1` object.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| exact_array(&value, 10).and_then(freeze_admission_evidence_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_admission_evidence_value(&self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

fn validate_applicability_matrix(
    matrix: &[ErasureFreezeApplicabilityRowV1],
) -> Result<(), ErasureErrorV1> {
    if !applicability_matrix_cardinality_is_valid(matrix.len()) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    let target_count = matrix.len() / ERASURE_INVENTORY_CATEGORY_COUNT;
    for category in ErasureInventoryCategoryV1::CANONICAL {
        let offset = category.index() * target_count;
        for (target_index, row) in matrix[offset..offset + target_count].iter().enumerate() {
            if row.category() != category || row.target_index() != target_index as u64 {
                return Err(ErasureErrorV1::ScopeInvalid);
            }
        }
    }
    Ok(())
}

/// Construction fields for immutable access-freeze provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Scope commitment frozen by this operation.
    pub scope_commitment: ErasureReferenceV1,
    /// Frozen policy-selected obligation set.
    pub obligation_set: ErasureReferenceV1,
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Host-authenticated freeze-admission evidence.
    pub host_evidence: ErasureReferenceV1,
}

/// Content-addressed proof of one successful access freeze.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeProvenanceV1 {
    pub(super) input: ErasureFreezeProvenanceInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureFreezeProvenanceV1 {
    /// Content-address one successful freeze.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the portable bound is exceeded.
    pub fn new(input: ErasureFreezeProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the immutable scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }
    /// Return the frozen obligation-set commitment.
    #[must_use]
    pub const fn obligation_set(&self) -> ErasureReferenceV1 {
        self.input.obligation_set
    }
    /// Return the authoritative freeze position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.input.freeze_position
    }
    /// Return host-authenticated freeze-admission evidence.
    #[must_use]
    pub const fn host_evidence(&self) -> ErasureReferenceV1 {
        self.input.host_evidence
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Encode the deterministic portable record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the portable bound is exceeded.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }
    /// Decode one canonical freeze provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 7).and_then(freeze_provenance_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for a canonical access-freeze failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeFailureInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Closed failure returned by scope resolution or access freeze.
    pub error: ErasureErrorV1,
    /// Authorization evidence for the failed attempt.
    pub authorization_provenance: ErasureReferenceV1,
    /// Host failure evidence, or the authorization reference when unavailable.
    pub evidence: ErasureReferenceV1,
}

/// Content-addressed failure proving why an authorized request was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeFailureV1 {
    pub(super) input: ErasureFreezeFailureInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureFreezeFailureV1 {
    /// Construct one closed failure record.
    ///
    /// # Errors
    ///
    /// Returns policy conflict unless the error belongs to scope/freeze admission.
    pub fn new(input: ErasureFreezeFailureInputV1) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            input.error,
            ErasureErrorV1::ScopeInvalid | ErasureErrorV1::AccessFreezeFailed
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the closed failure.
    #[must_use]
    pub const fn error(&self) -> ErasureErrorV1 {
        self.input.error
    }
    /// Return authorization evidence.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }
    /// Return host failure evidence.
    #[must_use]
    pub const fn evidence(&self) -> ErasureReferenceV1 {
        self.input.evidence
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Encode the deterministic portable record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the portable bound is exceeded.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_failure_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }
    /// Decode one canonical failure record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 6).and_then(freeze_failure_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_failure_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_FAILURE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for a rejection that occurs before scope/freeze work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorizationRejectionInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Host-authenticated authorization or policy rejection evidence.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Content-addressed evidence for a pre-authorization rejection.
///
/// This is intentionally distinct from [`ErasureFreezeFailureV1`]: an
/// authorization/policy rejection did not resolve scope or attempt a freeze,
/// while a scope/freeze rejection must carry canonical failure provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorizationRejectionV1 {
    pub(super) input: ErasureAuthorizationRejectionInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureAuthorizationRejectionV1 {
    /// Construct and content-address a pre-authorization rejection.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the record exceeds its bound.
    pub fn new(input: ErasureAuthorizationRejectionInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the rejected ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return host-authenticated rejection evidence.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &authorization_rejection_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical pre-authorization rejection record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 4).and_then(authorization_rejection_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &authorization_rejection_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_AUTHORIZATION_REJECTION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureRetryAdmissionV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRetryAdmissionInputV1 {
    /// ERQ1 digest being retried.
    pub request: ErasureReferenceV1,
    /// Zero-based attempt ordinal.
    pub attempt_ordinal: u64,
    /// ERC1 digest immediately preceding this attempt, if any.
    pub source_receipt: Option<ErasureReferenceV1>,
    /// Unresolved obligations selected for this attempt.
    pub unresolved_obligations: Vec<ErasureReferenceV1>,
    /// Stable `(ERQ1, target)` command identities corresponding to obligations.
    pub command_identities: Vec<ErasureReferenceV1>,
    /// Pinned retry-policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Authoritative logical position admitting the retry.
    pub admitted_position: u64,
    /// Deterministically derived logical deadline.
    pub deadline_position: u64,
    /// Host authorization-provenance digest.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Content-addressed admission for one destruction attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRetryAdmissionV1 {
    pub(super) input: ErasureRetryAdmissionInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureRetryAdmissionV1 {
    /// Construct, normalize, and content-address a retry admission.
    ///
    /// # Errors
    ///
    /// Returns a closed policy or scope error for an invalid attempt.
    pub fn new(mut input: ErasureRetryAdmissionInputV1) -> Result<Self, ErasureErrorV1> {
        normalize_retry_admission(&mut input)?;
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return the zero-based attempt ordinal.
    #[must_use]
    pub const fn attempt_ordinal(&self) -> u64 {
        self.input.attempt_ordinal
    }

    /// Return the preceding ERC1 digest, if this is a retry.
    #[must_use]
    pub const fn source_receipt(&self) -> Option<ErasureReferenceV1> {
        self.input.source_receipt
    }

    /// Return unresolved obligations in bytewise order.
    #[must_use]
    pub fn unresolved_obligations(&self) -> &[ErasureReferenceV1] {
        &self.input.unresolved_obligations
    }

    /// Return stable command identities aligned with [`Self::unresolved_obligations`].
    #[must_use]
    pub fn command_identities(&self) -> &[ErasureReferenceV1] {
        &self.input.command_identities
    }

    /// Return the pinned retry-policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return the logical position that admitted the retry.
    #[must_use]
    pub const fn admitted_position(&self) -> u64 {
        self.input.admitted_position
    }

    /// Return the immutable logical deadline.
    #[must_use]
    pub const fn deadline_position(&self) -> u64 {
        self.input.deadline_position
    }

    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &retry_admission_value(self),
            ERASURE_RETRY_ADMISSION_MAX_BYTES,
        )
    }

    /// Decode one canonical retry-admission record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_RETRY_ADMISSION_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| exact_array(&value, 12).and_then(retry_admission_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &retry_admission_value(&self),
            ERASURE_RETRY_ADMISSION_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_RETRY_ADMISSION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureAcknowledgementProvenanceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAcknowledgementProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Stable `(ERQ1, target)` command identity.
    pub command: ErasureReferenceV1,
    /// Attempt identity.
    pub attempt: ErasureReferenceV1,
    /// Immutable obligation identity.
    pub obligation: ErasureReferenceV1,
    /// Immutable owner identity.
    pub owner: ErasureReferenceV1,
    /// Immutable resolved-scope identity.
    pub scope: ErasureReferenceV1,
    /// Closed owner outcome.
    pub outcome: ErasureAcknowledgementOutcomeV1,
    /// Underlying evidence digest.
    pub evidence: ErasureReferenceV1,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
}

/// Content-addressed provenance for one acknowledgement result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAcknowledgementProvenanceV1 {
    pub(super) input: ErasureAcknowledgementProvenanceInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureAcknowledgementProvenanceV1 {
    /// Construct and content-address acknowledgement provenance.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if the record exceeds its bound.
    pub fn new(input: ErasureAcknowledgementProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the stable command identity.
    #[must_use]
    pub const fn command(&self) -> ErasureReferenceV1 {
        self.input.command
    }
    /// Return the attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> ErasureReferenceV1 {
        self.input.attempt
    }
    /// Return the immutable obligation identity.
    #[must_use]
    pub const fn obligation(&self) -> ErasureReferenceV1 {
        self.input.obligation
    }
    /// Return the immutable owner identity.
    #[must_use]
    pub const fn owner(&self) -> ErasureReferenceV1 {
        self.input.owner
    }
    /// Return the immutable scope identity.
    #[must_use]
    pub const fn scope(&self) -> ErasureReferenceV1 {
        self.input.scope
    }
    /// Return the closed acknowledgement outcome.
    #[must_use]
    pub const fn outcome(&self) -> ErasureAcknowledgementOutcomeV1 {
        self.input.outcome
    }
    /// Return the underlying evidence digest.
    #[must_use]
    pub const fn evidence(&self) -> ErasureReferenceV1 {
        self.input.evidence
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &acknowledgement_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical acknowledgement-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 12).and_then(acknowledgement_provenance_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &acknowledgement_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureAttemptOutcomeV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAttemptOutcomeInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Attempt identity.
    pub attempt: ErasureReferenceV1,
    /// ERC1 digest immediately preceding this attempt, if any.
    pub source_receipt: Option<ErasureReferenceV1>,
    /// Attempt outcome lifecycle; only `PartialFailure` or `Complete`.
    pub lifecycle: ErasureLifecycleV1,
    /// Digest of the selected-obligation set.
    pub selected_obligations: ErasureReferenceV1,
    /// Digest of the canonical acknowledgement inventory.
    pub acknowledgement_inventory: ErasureReferenceV1,
    /// Terminal logical position for the attempt.
    pub terminal_position: u64,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
}

/// Content-addressed outcome of one destruction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAttemptOutcomeV1 {
    pub(super) input: ErasureAttemptOutcomeInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureAttemptOutcomeV1 {
    /// Construct and validate one attempt outcome.
    ///
    /// # Errors
    ///
    /// Returns a closed policy error unless the attempt has an outcome.
    pub fn new(input: ErasureAttemptOutcomeInputV1) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            input.lifecycle,
            ErasureLifecycleV1::PartialFailure | ErasureLifecycleV1::Complete
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> ErasureReferenceV1 {
        self.input.attempt
    }
    /// Return the preceding ERC1 digest, if any.
    #[must_use]
    pub const fn source_receipt(&self) -> Option<ErasureReferenceV1> {
        self.input.source_receipt
    }
    /// Return the attempt outcome lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.input.lifecycle
    }
    /// Return the selected-obligation-set digest.
    #[must_use]
    pub const fn selected_obligations(&self) -> ErasureReferenceV1 {
        self.input.selected_obligations
    }
    /// Return the canonical acknowledgement-inventory digest.
    #[must_use]
    pub const fn acknowledgement_inventory(&self) -> ErasureReferenceV1 {
        self.input.acknowledgement_inventory
    }
    /// Return the terminal logical position.
    #[must_use]
    pub const fn terminal_position(&self) -> u64 {
        self.input.terminal_position
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &attempt_outcome_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical attempt-outcome record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 11).and_then(attempt_outcome_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &attempt_outcome_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ATTEMPT_OUTCOME_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureReceiptProvenanceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureReceiptProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Attempt identity.
    pub attempt: ErasureReferenceV1,
    /// Zero-based attempt ordinal.
    pub attempt_ordinal: u64,
    /// Immediately preceding ERC1 digest, absent only for ordinal zero.
    pub predecessor_receipt: Option<ErasureReferenceV1>,
    /// Terminal ERS1 digest.
    pub terminal_state: ErasureReferenceV1,
    /// Canonical evidence-set digest.
    pub evidence_set: ErasureReferenceV1,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Issue logical position.
    pub issue_position: u64,
}

/// Content-addressed provenance for one ERC1 receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureReceiptProvenanceV1 {
    pub(super) input: ErasureReceiptProvenanceInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureReceiptProvenanceV1 {
    /// Construct and validate one receipt-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed policy error for an invalid ordinal or predecessor.
    pub fn new(input: ErasureReceiptProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        if input.attempt_ordinal >= ERASURE_MAX_ATTEMPT_OUTCOMES as u64
            || (input.attempt_ordinal == 0) != input.predecessor_receipt.is_none()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> ErasureReferenceV1 {
        self.input.attempt
    }
    /// Return the zero-based attempt ordinal.
    #[must_use]
    pub const fn attempt_ordinal(&self) -> u64 {
        self.input.attempt_ordinal
    }
    /// Return the preceding ERC1 digest, if any.
    #[must_use]
    pub const fn predecessor_receipt(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_receipt
    }
    /// Return the terminal ERS1 digest.
    #[must_use]
    pub const fn terminal_state(&self) -> ErasureReferenceV1 {
        self.input.terminal_state
    }
    /// Return the canonical evidence-set digest.
    #[must_use]
    pub const fn evidence_set(&self) -> ErasureReferenceV1 {
        self.input.evidence_set
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return the issue logical position.
    #[must_use]
    pub const fn issue_position(&self) -> u64 {
        self.input.issue_position
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &receipt_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical receipt-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 11).and_then(receipt_provenance_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &receipt_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_RECEIPT_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureAdministrativeResolutionV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAdministrativeResolutionInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Affected state/evidence digests in bytewise order.
    pub affected_digests: Vec<ErasureReferenceV1>,
    /// Closed recovery action.
    pub action: ErasureAdministrativeResolutionActionV1,
    /// Affected scope-commitment digest.
    pub scope_commitment: ErasureReferenceV1,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Authorizing Principal digest.
    pub principal: ErasureReferenceV1,
    /// Host authorization-provenance digest.
    pub authorization_provenance: ErasureReferenceV1,
    /// Digest of the resolution reason.
    pub reason: ErasureReferenceV1,
    /// Issue logical position.
    pub issue_position: u64,
    /// Immediately preceding resolution digest, if any.
    pub predecessor_resolution: Option<ErasureReferenceV1>,
}

/// Content-addressed administrative recovery resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAdministrativeResolutionV1 {
    pub(super) input: ErasureAdministrativeResolutionInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureAdministrativeResolutionV1 {
    /// Construct, normalize, and content-address an administrative resolution.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an empty, duplicate, or oversized set.
    pub fn new(mut input: ErasureAdministrativeResolutionInputV1) -> Result<Self, ErasureErrorV1> {
        if input.affected_digests.is_empty()
            || input.affected_digests.len() > ERASURE_MAX_REFERENCES
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.affected_digests.sort_unstable();
        if has_duplicate(&input.affected_digests) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return affected state/evidence digests in bytewise order.
    #[must_use]
    pub fn affected_digests(&self) -> &[ErasureReferenceV1] {
        &self.input.affected_digests
    }

    /// Return the closed recovery action.
    #[must_use]
    pub const fn action(&self) -> ErasureAdministrativeResolutionActionV1 {
        self.input.action
    }

    /// Return the affected scope-commitment digest.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }

    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return the authorizing Principal digest.
    #[must_use]
    pub const fn principal(&self) -> ErasureReferenceV1 {
        self.input.principal
    }

    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return the resolution-reason digest.
    #[must_use]
    pub const fn reason(&self) -> ErasureReferenceV1 {
        self.input.reason
    }

    /// Return the issue logical position.
    #[must_use]
    pub const fn issue_position(&self) -> u64 {
        self.input.issue_position
    }

    /// Return the preceding resolution digest, if any.
    #[must_use]
    pub const fn predecessor_resolution(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_resolution
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &administrative_resolution_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical administrative-resolution record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 13).and_then(administrative_resolution_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &administrative_resolution_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

fn normalize_retry_admission(
    input: &mut ErasureRetryAdmissionInputV1,
) -> Result<(), ErasureErrorV1> {
    if !(0..ERASURE_MAX_ATTEMPT_OUTCOMES as u64).contains(&input.attempt_ordinal)
        || (input.attempt_ordinal == 0) != input.source_receipt.is_none()
        || input
            .deadline_position
            .checked_sub(input.admitted_position)
            .is_none()
    {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if input.unresolved_obligations.len() != input.command_identities.len()
        || input.unresolved_obligations.len() > ERASURE_MAX_OBLIGATIONS
    {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    let mut pairs = input
        .unresolved_obligations
        .iter()
        .copied()
        .zip(input.command_identities.iter().copied())
        .collect::<Vec<_>>();
    pairs.sort_unstable_by_key(|(obligation, _)| *obligation);
    let obligations = pairs
        .iter()
        .map(|(obligation, _)| *obligation)
        .collect::<Vec<_>>();
    if has_duplicate(&obligations) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    input.unresolved_obligations = obligations;
    input.command_identities = pairs.iter().map(|(_, command)| *command).collect();
    Ok(())
}

/// Construction fields for one frozen category/target/owner obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureObligationInputV1 {
    /// Policy-admitted category for this target.
    pub category: ErasureInventoryCategoryV1,
    /// Canonical target in the admitted freeze closure.
    pub target: ErasureRequiredTargetV1,
    /// Independently admitted category-scoped owner identity.
    pub owner: ErasureReferenceV1,
    /// Stable `(ERQ1, target)` destruction-command identity.
    pub command_identity: ErasureReferenceV1,
}

/// Immutable policy-selected obligation persisted at access freeze.
///
/// The canonical wire record is `ERO1 = [tag, version, category, target,
/// owner, command_identity]`. Its content address, rather than an inferred
/// `(category, target)` tuple, is the durable obligation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureObligationV1 {
    pub(super) input: ErasureObligationInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureObligationV1 {
    /// Construct and content-address an immutable obligation.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the record exceeds its bound.
    pub fn new(input: ErasureObligationInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the policy-selected category.
    #[must_use]
    pub const fn category(&self) -> ErasureInventoryCategoryV1 {
        self.input.category
    }

    /// Return the canonical frozen target.
    #[must_use]
    pub const fn target(&self) -> ErasureRequiredTargetV1 {
        self.input.target
    }

    /// Return the independently admitted category-scoped owner identity.
    #[must_use]
    pub const fn owner(&self) -> ErasureReferenceV1 {
        self.input.owner
    }

    /// Return the stable destruction-command identity.
    #[must_use]
    pub const fn command_identity(&self) -> ErasureReferenceV1 {
        self.input.command_identity
    }

    /// Return this obligation's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact `ERO1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(&obligation_value(self), ERASURE_PORTABLE_RECORD_MAX_BYTES)
    }

    /// Decode and validate one exact `ERO1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_TARGETS,
        )
        .and_then(|value| exact_array(&value, 6).and_then(obligation_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(&obligation_value(&self), ERASURE_PORTABLE_RECORD_MAX_BYTES).map(|bytes| {
            Self {
                content_digest: ErasureReferenceV1::from_digest(domain_digest(
                    ERASURE_OBLIGATION_TAG_V1,
                    &bytes,
                )),
                ..self
            }
        })
    }
}

/// Construction fields for a frozen set of immutable obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureObligationSetInputV1 {
    /// ERQ1 whose policy admitted this exact set.
    pub request: ErasureReferenceV1,
    /// Strictly bytewise-increasing `ERO1` content addresses.
    pub obligations: Vec<ErasureReferenceV1>,
    /// Policy revision pinned by ERQ1.
    pub policy: ErasureReferenceV1,
    /// Trust revision admitted by the host at freeze.
    pub trust: ErasureReferenceV1,
}

/// Content-addressed frozen set of admitted obligations for an ERQ1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureObligationSetV1 {
    pub(super) input: ErasureObligationSetInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureObligationSetV1 {
    /// Construct one exact `EROS1` record without normalizing its references.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for a duplicate, unordered, or oversized
    /// obligation collection. An empty set is valid when every applicability
    /// row is inapplicable.
    pub fn new(input: ErasureObligationSetInputV1) -> Result<Self, ErasureErrorV1> {
        if input.obligations.len() > ERASURE_MAX_OBLIGATIONS
            || !strictly_increasing(&input.obligations)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return the exact ordered obligation addresses.
    #[must_use]
    pub fn obligations(&self) -> &[ErasureReferenceV1] {
        &self.input.obligations
    }

    /// Return the ERQ1-pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the host-admitted trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return this obligation set's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact `EROS1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds the V1 bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &obligation_set_value(self),
            ERASURE_OBLIGATION_SET_MAX_BYTES,
        )
    }

    /// Decode and validate one exact `EROS1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_OBLIGATION_SET_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| exact_array(&value, 6).and_then(obligation_set_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &obligation_set_value(&self),
            ERASURE_OBLIGATION_SET_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_OBLIGATION_SET_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for one append-only future-Fork scope extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureScopeExtensionInputV1 {
    /// ERQ1 protected by the extension.
    pub request: ErasureReferenceV1,
    /// Initial immutable scope-commitment address.
    pub scope_commitment: ErasureReferenceV1,
    /// Canonical Timeline/Fork scope reference being appended.
    pub fork: ErasureReferenceV1,
    /// Exact child Timeline/Fork identifier admitted by this extension.
    pub child_timeline: TimelineId,
    /// The non-null lineage rule pinned by the initial commitment.
    pub lineage_rule: ErasureReferenceV1,
    /// Immediately preceding extension address, if one exists.
    pub predecessor_extension: Option<ErasureReferenceV1>,
    /// Host-authenticated #186 future-Fork admission evidence.
    pub admission_provenance: ErasureReferenceV1,
}

/// Immutable future-Fork scope extension (`ERSE1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureScopeExtensionV1 {
    pub(super) input: ErasureScopeExtensionInputV1,
    pub(super) content_digest: ErasureReferenceV1,
}

impl ErasureScopeExtensionV1 {
    /// Construct and content-address one exact `ERSE1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the record exceeds its bound.
    pub fn new(input: ErasureScopeExtensionInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return the immutable initial scope-commitment address.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }

    /// Return the admitted future Timeline/Fork scope reference.
    #[must_use]
    pub const fn fork(&self) -> ErasureReferenceV1 {
        self.input.fork
    }

    /// Return the exact child Timeline/Fork identifier admitted by this extension.
    #[must_use]
    pub const fn child_timeline(&self) -> TimelineId {
        self.input.child_timeline
    }

    /// Return the pinned lineage-expansion rule.
    #[must_use]
    pub const fn lineage_rule(&self) -> ErasureReferenceV1 {
        self.input.lineage_rule
    }

    /// Return the immediately preceding extension address, if any.
    #[must_use]
    pub const fn predecessor_extension(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_extension
    }

    /// Return host-authenticated future-Fork admission evidence.
    #[must_use]
    pub const fn admission_provenance(&self) -> ErasureReferenceV1 {
        self.input.admission_provenance
    }

    /// Return this extension's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode one exact `ERSE1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &scope_extension_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode and validate one exact `ERSE1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_SCOPE_EXTENSIONS,
        )
        .and_then(|value| exact_array(&value, 8).and_then(scope_extension_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &scope_extension_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_SCOPE_EXTENSION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn evidence_decoders_reject_unknown_codes_and_invalid_text() {
        let digest = Value::Bytes(vec![0; 32]);
        assert_eq!(
            command_from_value(&Value::Array(vec![
                digest.clone(),
                uint(99),
                Value::Null,
                digest.clone(),
                digest.clone(),
                digest,
            ])),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            applicability_row_from_value(&Value::Array(vec![
                uint(99),
                uint(0),
                uint(0),
                Value::Null,
            ])),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            applicability_row_from_value(&Value::Array(vec![
                uint(0),
                uint(0),
                uint(99),
                Value::Null,
            ])),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            decode_limited(&[0x61, 0xff], 2, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }

    #[test]
    fn bounded_cbor_helpers_fail_closed_at_each_shape_boundary() {
        assert_eq!(
            bounded_array(&[Value::Null], 0),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(array(&Value::Null, 1), Err(ErasureErrorV1::InvalidEncoding));
        assert_eq!(
            exact_array(&Value::Null, 0),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            exact_array(&Value::Array(Vec::new()), 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        assert_eq!(
            cbor_shape_is_bounded(&[0, 0], 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_item_end(&[], 0, 0, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_item_end(&[0x9f], 0, 0, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_item_end(&[0x1f], 0, 0, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_item_end(&[0x81, 0x1f], 0, 0, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_argument(&[], 0, 31),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_argument_bytes(&[0], 0, 2, 256),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            cbor_argument_bytes(&[0], 0, 1, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            decode_limited(&[0x18, 0x00], 2, 1),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
}
