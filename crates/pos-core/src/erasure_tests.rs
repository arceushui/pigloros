//! Unit coverage for the raw erasure records, codecs, and prepared CAS deltas.

use ciborium::value::Value;

use super::*;

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

struct EmptyStateResolver;

impl ErasureStateResolverV1 for EmptyStateResolver {
    fn resolve_state(
        &self,
        _digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        Ok(None)
    }
}

#[test]
fn lifecycle_permits_exactly_the_adr_edges() {
    let lifecycles = [
        ErasureLifecycleV1::Submitted,
        ErasureLifecycleV1::Authorized,
        ErasureLifecycleV1::AccessFrozen,
        ErasureLifecycleV1::DestructionDispatched,
        ErasureLifecycleV1::AwaitingAcknowledgements,
        ErasureLifecycleV1::Complete,
        ErasureLifecycleV1::PartialFailure,
        ErasureLifecycleV1::Rejected,
    ];
    let permitted = [
        (
            ErasureLifecycleV1::Submitted,
            ErasureLifecycleV1::Authorized,
        ),
        (ErasureLifecycleV1::Submitted, ErasureLifecycleV1::Rejected),
        (
            ErasureLifecycleV1::Authorized,
            ErasureLifecycleV1::AccessFrozen,
        ),
        (ErasureLifecycleV1::Authorized, ErasureLifecycleV1::Rejected),
        (
            ErasureLifecycleV1::AccessFrozen,
            ErasureLifecycleV1::DestructionDispatched,
        ),
        (
            ErasureLifecycleV1::DestructionDispatched,
            ErasureLifecycleV1::AwaitingAcknowledgements,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::Complete,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::PartialFailure,
        ),
        (
            ErasureLifecycleV1::PartialFailure,
            ErasureLifecycleV1::PartialFailure,
        ),
        (
            ErasureLifecycleV1::PartialFailure,
            ErasureLifecycleV1::Complete,
        ),
    ];

    for current in lifecycles {
        for next in lifecycles {
            assert_eq!(
                current.permits(next),
                permitted.contains(&(current, next)),
                "unexpected {current:?} -> {next:?} lifecycle decision"
            );
        }
    }
}

const fn target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(10),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(11),
        replica_set: reference(12),
        replica_id: reference(13),
    }
}

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(7)],
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(6),
    })
}

fn scope() -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members: vec![reference(7)],
        target_closure: reference(8),
        lineage_rule: Some(reference(9)),
    })
}

fn obligation() -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: target(),
        owner: reference(13),
        command_identity: reference(14),
    })
}

fn obligation_set() -> Result<ErasureObligationSetV1, ErasureErrorV1> {
    ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: reference(1),
        obligations: vec![obligation()?.reference()],
        policy: reference(5),
        trust: reference(6),
    })
}

fn freeze_admission() -> Result<ErasureFreezeAdmissionEvidenceV1, ErasureErrorV1> {
    let matrix = ErasureInventoryCategoryV1::CANONICAL
        .into_iter()
        .map(|category| {
            ErasureFreezeApplicabilityRowV1::new(
                category,
                0,
                ErasureApplicabilityDecisionV1::Inapplicable,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        request: reference(1),
        scope_commitment: reference(8),
        obligation_set: reference(9),
        applicability_matrix: matrix,
        freeze_position: 10,
        policy: reference(5),
        trust: reference(6),
        authorization_provenance: reference(11),
    })
}

fn receipt() -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(2),
        coordinator: reference(3),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 10,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(5),
        trust: reference(6),
        provenance: reference(7),
        issue_position: 11,
        signature: reference(8),
        receipt_digest: reference(0),
    })
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}

fn decode_value(bytes: &[u8]) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)
}

fn replace_field(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut value = decode_value(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    *fields
        .get_mut(index)
        .ok_or(ErasureErrorV1::InvalidEncoding)? = replacement;
    encode_value(&value)
}

fn append_field(bytes: &[u8]) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut value = decode_value(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields.push(Value::Null);
    encode_value(&value)
}

macro_rules! roundtrip {
    ($name:ident, $ty:ty, $value:expr_2021) => {
        #[test]
        fn $name() -> Result<(), ErasureErrorV1> {
            let original: $ty = $value?;
            let bytes = original.to_canonical_cbor()?;
            let decoded = <$ty>::from_canonical_cbor(&bytes)?;
            assert_eq!(decoded, original);
            assert_eq!(decoded.to_canonical_cbor()?, bytes);
            Ok(())
        }
    };
}

roundtrip!(request_codec_roundtrips, ErasureRequestV1, request());
roundtrip!(state_codec_roundtrips, ErasureStateV1, {
    ErasureStateV1::submitted(reference(1), reference(2), reference(3))
});
roundtrip!(
    correction_codec_roundtrips,
    ErasureCorrectionProvenanceV1,
    {
        ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: reference(1),
            rejected_terminal_state: reference(2),
            correction_reason: reference(3),
            authorization_provenance: reference(4),
        })
    }
);
roundtrip!(
    rejection_codec_roundtrips,
    ErasureAuthorizationRejectionV1,
    {
        ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
            request: reference(1),
            authorization_provenance: reference(2),
        })
    }
);
roundtrip!(scope_codec_roundtrips, ErasureScopeCommitmentV1, scope());
roundtrip!(
    freeze_provenance_codec_roundtrips,
    ErasureFreezeProvenanceV1,
    {
        ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
            request: reference(1),
            scope_commitment: reference(2),
            obligation_set: reference(3),
            freeze_position: 10,
            host_evidence: reference(4),
        })
    }
);
roundtrip!(freeze_failure_codec_roundtrips, ErasureFreezeFailureV1, {
    ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::AccessFreezeFailed,
        authorization_provenance: reference(2),
        evidence: reference(3),
    })
});
roundtrip!(
    freeze_admission_codec_roundtrips,
    ErasureFreezeAdmissionEvidenceV1,
    { freeze_admission() }
);
roundtrip!(
    freeze_authorization_codec_roundtrips,
    ErasureFreezeAuthorizationEvidenceV1,
    {
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: reference(1),
            policy: reference(2),
            trust: reference(3),
            evidence: vec![1, 2, 3],
        })
    }
);
roundtrip!(
    obligation_codec_roundtrips,
    ErasureObligationV1,
    obligation()
);
roundtrip!(
    obligation_set_codec_roundtrips,
    ErasureObligationSetV1,
    obligation_set()
);
roundtrip!(scope_extension_codec_roundtrips, ErasureScopeExtensionV1, {
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        fork: reference(3),
        lineage_rule: reference(4),
        predecessor_extension: None,
        admission_provenance: reference(5),
    })
});
roundtrip!(retry_admission_codec_roundtrips, ErasureRetryAdmissionV1, {
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
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
    })
});
roundtrip!(
    acknowledgement_provenance_codec_roundtrips,
    ErasureAcknowledgementProvenanceV1,
    {
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
        })
    }
);
roundtrip!(attempt_outcome_codec_roundtrips, ErasureAttemptOutcomeV1, {
    ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: reference(2),
        source_receipt: None,
        lifecycle: ErasureLifecycleV1::Complete,
        selected_obligations: reference(3),
        acknowledgement_inventory: reference(4),
        terminal_position: 20,
        policy: reference(5),
        trust: reference(6),
    })
});
roundtrip!(
    receipt_provenance_codec_roundtrips,
    ErasureReceiptProvenanceV1,
    {
        ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
            request: reference(1),
            attempt: reference(2),
            attempt_ordinal: 0,
            predecessor_receipt: None,
            terminal_state: reference(3),
            evidence_set: reference(4),
            policy: reference(5),
            trust: reference(6),
            issue_position: 20,
        })
    }
);
roundtrip!(
    administrative_resolution_codec_roundtrips,
    ErasureAdministrativeResolutionV1,
    {
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: reference(1),
            affected_digests: vec![reference(2), reference(3)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: reference(4),
            policy: reference(5),
            trust: reference(6),
            principal: reference(7),
            authorization_provenance: reference(8),
            reason: reference(9),
            issue_position: 20,
            predecessor_resolution: None,
        })
    }
);
roundtrip!(receipt_codec_roundtrips, ErasureReceiptV1, receipt());

macro_rules! codec_shape_guards {
    ($bytes:expr_2021, $decoder:expr_2021) => {{
        let bytes = $bytes;
        let wrong_tag = replace_field(&bytes, 0, Value::Text("wrong".to_owned()))?;
        let wrong_version = replace_field(&bytes, 1, Value::Text("wrong".to_owned()))?;
        let extra_field = append_field(&bytes)?;
        assert!(($decoder)(&wrong_tag).is_err());
        assert!(($decoder)(&wrong_version).is_err());
        assert!(($decoder)(&extra_field).is_err());
    }};
}

#[test]
fn request_and_submission_codecs_reject_header_and_length_mutations() -> Result<(), ErasureErrorV1>
{
    let request = request()?;
    codec_shape_guards!(
        request.to_canonical_cbor()?,
        ErasureRequestV1::from_canonical_cbor
    );
    let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    codec_shape_guards!(
        state.to_canonical_cbor()?,
        ErasureStateV1::from_canonical_cbor
    );
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: reference(2),
        correction_reason: reference(3),
        authorization_provenance: reference(4),
    })?;
    codec_shape_guards!(
        correction.to_canonical_cbor()?,
        ErasureCorrectionProvenanceV1::from_canonical_cbor
    );
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: reference(1),
        authorization_provenance: reference(2),
    })?;
    codec_shape_guards!(
        rejection.to_canonical_cbor()?,
        ErasureAuthorizationRejectionV1::from_canonical_cbor
    );
    Ok(())
}

#[test]
fn freeze_and_scope_codecs_reject_header_and_length_mutations() -> Result<(), ErasureErrorV1> {
    let scope = scope()?;
    codec_shape_guards!(
        scope.to_canonical_cbor()?,
        ErasureScopeCommitmentV1::from_canonical_cbor
    );
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        obligation_set: reference(3),
        freeze_position: 10,
        host_evidence: reference(4),
    })?;
    codec_shape_guards!(
        freeze.to_canonical_cbor()?,
        ErasureFreezeProvenanceV1::from_canonical_cbor
    );
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::ScopeInvalid,
        authorization_provenance: reference(2),
        evidence: reference(3),
    })?;
    codec_shape_guards!(
        failure.to_canonical_cbor()?,
        ErasureFreezeFailureV1::from_canonical_cbor
    );
    codec_shape_guards!(
        freeze_admission()?.to_canonical_cbor()?,
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor
    );
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: reference(1),
            policy: reference(2),
            trust: reference(3),
            evidence: vec![1],
        })?;
    codec_shape_guards!(
        authorization.to_canonical_cbor()?,
        ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor
    );
    codec_shape_guards!(
        obligation()?.to_canonical_cbor()?,
        ErasureObligationV1::from_canonical_cbor
    );
    codec_shape_guards!(
        obligation_set()?.to_canonical_cbor()?,
        ErasureObligationSetV1::from_canonical_cbor
    );
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        fork: reference(3),
        lineage_rule: reference(4),
        predecessor_extension: None,
        admission_provenance: reference(5),
    })?;
    codec_shape_guards!(
        extension.to_canonical_cbor()?,
        ErasureScopeExtensionV1::from_canonical_cbor
    );
    Ok(())
}

#[test]
fn attempt_and_receipt_codecs_reject_header_and_length_mutations() -> Result<(), ErasureErrorV1> {
    let retry = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
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
    codec_shape_guards!(
        retry.to_canonical_cbor()?,
        ErasureRetryAdmissionV1::from_canonical_cbor
    );
    let acknowledgement =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: reference(1),
            command: reference(2),
            attempt: reference(3),
            obligation: reference(4),
            owner: reference(5),
            scope: reference(6),
            outcome: ErasureAcknowledgementOutcomeV1::Negative,
            evidence: reference(7),
            policy: reference(8),
            trust: reference(9),
        })?;
    codec_shape_guards!(
        acknowledgement.to_canonical_cbor()?,
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor
    );
    let outcome = ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: reference(2),
        source_receipt: None,
        lifecycle: ErasureLifecycleV1::PartialFailure,
        selected_obligations: reference(3),
        acknowledgement_inventory: reference(4),
        terminal_position: 20,
        policy: reference(5),
        trust: reference(6),
    })?;
    codec_shape_guards!(
        outcome.to_canonical_cbor()?,
        ErasureAttemptOutcomeV1::from_canonical_cbor
    );
    let provenance = ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request: reference(1),
        attempt: reference(2),
        attempt_ordinal: 0,
        predecessor_receipt: None,
        terminal_state: reference(3),
        evidence_set: reference(4),
        policy: reference(5),
        trust: reference(6),
        issue_position: 20,
    })?;
    codec_shape_guards!(
        provenance.to_canonical_cbor()?,
        ErasureReceiptProvenanceV1::from_canonical_cbor
    );
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: reference(1),
            affected_digests: vec![reference(2)],
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: reference(3),
            policy: reference(4),
            trust: reference(5),
            principal: reference(6),
            authorization_provenance: reference(7),
            reason: reference(8),
            issue_position: 20,
            predecessor_resolution: None,
        })?;
    codec_shape_guards!(
        resolution.to_canonical_cbor()?,
        ErasureAdministrativeResolutionV1::from_canonical_cbor
    );
    codec_shape_guards!(
        receipt()?.to_canonical_cbor()?,
        ErasureReceiptV1::from_canonical_cbor
    );
    Ok(())
}

#[test]
fn predecessor_chain_bounds_fail_closed_for_invalid_roots_and_zero_depth(
) -> Result<(), ErasureErrorV1> {
    let invalid_root = ErasureStateV1 {
        request: reference(1),
        lifecycle: ErasureLifecycleV1::Authorized,
        freeze_position: None,
        coordinator: reference(2),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        previous_state: None,
        provenance: reference(3),
        state_digest: reference(4),
    };

    let failure = verify_predecessor_chain_bounded(invalid_root, &EmptyStateResolver, 1)
        .err()
        .ok_or(ErasureErrorV1::PolicyConflict)?;
    assert_eq!(failure.error(), ErasureErrorV1::ProvenanceMissing);
    assert_eq!(failure.subject(), reference(4));

    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let failure = verify_predecessor_chain_bounded(submitted, &EmptyStateResolver, 0)
        .err()
        .ok_or(ErasureErrorV1::PolicyConflict)?;
    assert_eq!(failure.error(), ErasureErrorV1::ProvenanceMissing);
    Ok(())
}

#[test]
fn freeze_validation_rejects_invalid_rows_and_authorization_bindings() -> Result<(), ErasureErrorV1>
{
    let admission = freeze_admission()?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: reference(99),
            policy: reference(5),
            trust: reference(6),
            evidence: vec![1],
        })?;
    assert_eq!(
        authorization.verify_admission_body_binding(&admission),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut matrix = ErasureInventoryCategoryV1::CANONICAL
        .into_iter()
        .map(|category| {
            ErasureFreezeApplicabilityRowV1::new(
                category,
                0,
                ErasureApplicabilityDecisionV1::Inapplicable,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    matrix[0] = ErasureFreezeApplicabilityRowV1::new(
        ErasureInventoryCategoryV1::Artifact,
        u64::MAX,
        ErasureApplicabilityDecisionV1::Inapplicable,
        None,
    )?;
    let targets = [target()];
    assert_eq!(
        validate_applicability_obligations(&matrix, &targets, &[]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
