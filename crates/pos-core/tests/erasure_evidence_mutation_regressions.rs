//! Evidence codec mutation regressions for the direct V1 records.

#[path = "support/erasure_codec.rs"]
mod erasure_support;

use ciborium::value::Value;
use erasure_support::{reference, replay_target, request as fixture_request, RequestFixtureInput};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionActionV1,
    ErasureAdministrativeResolutionInputV1, ErasureAdministrativeResolutionV1,
    ErasureApplicabilityDecisionV1, ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1,
    ErasureAttemptQuotaReservationV1, ErasureAuthorizationRejectionInputV1,
    ErasureAuthorizationRejectionV1, ErasureCasEffectV1, ErasureCorrectionProvenanceV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeApplicabilityRowV1,
    ErasureFreezeAuthorizationEvidenceInputV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeFailureInputV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1,
    ErasureFreezeProvenanceV1, ErasureInventoryCategoryV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationSetInputV1, ErasureObligationSetV1,
    ErasureObligationV1, ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1,
    ErasureRequestV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateV1,
};

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    fixture_request(RequestFixtureInput {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 10,
        horizon_position: 20,
        provenance: reference(7),
    })
}

fn encode(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}

fn decode(bytes: &[u8]) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)
}

fn replace(bytes: &[u8], index: usize) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut value = decode(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    *fields
        .get_mut(index)
        .ok_or(ErasureErrorV1::InvalidEncoding)? = Value::Text("mutated".to_owned());
    encode(&value)
}

macro_rules! evidence_roundtrip {
    ($name:ident, $ty:ty, $value:expr_2021) => {
        #[test]
        fn $name() -> Result<(), ErasureErrorV1> {
            let value: $ty = $value?;
            let bytes = value.to_canonical_cbor()?;
            assert_eq!(<$ty>::from_canonical_cbor(&bytes)?, value);
            assert_eq!(
                <$ty>::from_canonical_cbor(&replace(&bytes, 0)?),
                Err(ErasureErrorV1::InvalidEncoding)
            );
            Ok(())
        }
    };
}

evidence_roundtrip!(
    correction_evidence_roundtrips,
    ErasureCorrectionProvenanceV1,
    {
        pos_core::ErasureCorrectionProvenanceV1::new(pos_core::ErasureCorrectionProvenanceInputV1 {
            rejected_request: reference(1),
            rejected_terminal_state: reference(2),
            correction_reason: reference(3),
            authorization_provenance: reference(4),
        })
    }
);

evidence_roundtrip!(
    authorization_rejection_roundtrips,
    ErasureAuthorizationRejectionV1,
    {
        ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
            request: reference(1),
            authorization_provenance: reference(2),
        })
    }
);

evidence_roundtrip!(scope_commitment_roundtrips, ErasureScopeCommitmentV1, {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members: vec![reference(2)],
        target_closure: reference(3),
        lineage_rule: Some(reference(4)),
    })
});

evidence_roundtrip!(freeze_provenance_roundtrips, ErasureFreezeProvenanceV1, {
    ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        obligation_set: reference(3),
        freeze_position: 10,
        host_evidence: reference(4),
    })
});

evidence_roundtrip!(freeze_failure_roundtrips, ErasureFreezeFailureV1, {
    ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::ScopeInvalid,
        authorization_provenance: reference(2),
        evidence: reference(3),
    })
});

evidence_roundtrip!(
    freeze_authorization_roundtrips,
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

evidence_roundtrip!(obligation_roundtrips, ErasureObligationV1, {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: replay_target(10),
        owner: reference(4),
        command_identity: reference(5),
    })
});

evidence_roundtrip!(obligation_set_roundtrips, ErasureObligationSetV1, {
    ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: reference(1),
        obligations: vec![reference(2)],
        policy: reference(3),
        trust: reference(4),
    })
});

evidence_roundtrip!(scope_extension_roundtrips, ErasureScopeExtensionV1, {
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        fork: reference(3),
        lineage_rule: reference(4),
        predecessor_extension: None,
        admission_provenance: reference(5),
    })
});

evidence_roundtrip!(retry_admission_roundtrips, ErasureRetryAdmissionV1, {
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

evidence_roundtrip!(
    acknowledgement_provenance_roundtrips,
    ErasureAcknowledgementProvenanceV1,
    {
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: reference(1),
            command: reference(2),
            attempt: reference(3),
            obligation: reference(4),
            owner: reference(5),
            scope: reference(6),
            outcome: ErasureAcknowledgementOutcomeV1::Stale,
            evidence: reference(7),
            policy: reference(8),
            trust: reference(9),
        })
    }
);

evidence_roundtrip!(attempt_outcome_roundtrips, ErasureAttemptOutcomeV1, {
    ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: reference(2),
        source_receipt: None,
        lifecycle: ErasureLifecycleV1::PartialFailure,
        selected_obligations: reference(3),
        acknowledgement_inventory: reference(4),
        terminal_position: 20,
        policy: reference(5),
        trust: reference(6),
    })
});

evidence_roundtrip!(receipt_provenance_roundtrips, ErasureReceiptProvenanceV1, {
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
});

evidence_roundtrip!(
    administrative_resolution_roundtrips,
    ErasureAdministrativeResolutionV1,
    {
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
        })
    }
);

#[test]
fn freeze_admission_roundtrip_preserves_the_complete_applicability_matrix(
) -> Result<(), ErasureErrorV1> {
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
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        obligation_set: reference(3),
        applicability_matrix: matrix.clone(),
        freeze_position: 10,
        policy: reference(4),
        trust: reference(5),
        authorization_provenance: reference(6),
    })?;
    let bytes = admission.to_canonical_cbor()?;
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&bytes)?,
        admission
    );
    assert!(ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&replace(&bytes, 5)?).is_err());

    let mut misordered_matrix = matrix;
    misordered_matrix[1] = ErasureFreezeApplicabilityRowV1::new(
        ErasureInventoryCategoryV1::Artifact,
        0,
        ErasureApplicabilityDecisionV1::Inapplicable,
        None,
    )?;
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
            request: reference(1),
            scope_commitment: reference(2),
            obligation_set: reference(3),
            applicability_matrix: misordered_matrix,
            freeze_position: 10,
            policy: reference(4),
            trust: reference(5),
            authorization_provenance: reference(6),
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn request_and_state_codec_mutations_fail_closed() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let request_bytes = request.to_canonical_cbor()?;
    assert!(ErasureRequestV1::from_canonical_cbor(&replace(&request_bytes, 5)?).is_err());
    let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let state_bytes = state.to_canonical_cbor()?;
    assert!(ErasureStateV1::from_canonical_cbor(&replace(&state_bytes, 2)?).is_err());
    Ok(())
}

#[test]
fn cas_effect_codec_roundtrips_every_durable_variant() -> Result<(), ErasureErrorV1> {
    let admission = reference(20);
    let effects = [
        ErasureCasEffectV1::None,
        ErasureCasEffectV1::AttemptAdmission {
            reservation: ErasureAttemptQuotaReservationV1::new(admission, reference(21)),
            commands: vec![ErasureDestructionCommandV1 {
                obligation: reference(22),
                category: ErasureInventoryCategoryV1::Artifact,
                target: replay_target(10),
                owner: reference(23),
                command: reference(24),
                provenance: admission,
            }],
        },
        ErasureCasEffectV1::AcknowledgementAdmission {
            acknowledgement: reference(25),
        },
        ErasureCasEffectV1::ReceiptAdmission {
            receipt: reference(26),
        },
    ];
    for effect in effects {
        let bytes = effect.to_canonical_cbor()?;
        assert_eq!(ErasureCasEffectV1::from_canonical_cbor(&bytes)?, effect);
        assert_eq!(
            ErasureCasEffectV1::from_canonical_cbor(&replace(&bytes, 0)?),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn cas_effect_codec_rejects_unknown_kinds_and_mismatched_command_provenance(
) -> Result<(), ErasureErrorV1> {
    let admission = reference(20);
    let effect = ErasureCasEffectV1::AttemptAdmission {
        reservation: ErasureAttemptQuotaReservationV1::new(admission, reference(21)),
        commands: vec![ErasureDestructionCommandV1 {
            obligation: reference(22),
            category: ErasureInventoryCategoryV1::Key,
            target: replay_target(10),
            owner: reference(23),
            command: reference(24),
            provenance: admission,
        }],
    };
    let mut value = decode(&effect.to_canonical_cbor()?)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[2] = Value::Integer(9.into());
    assert_eq!(
        ErasureCasEffectV1::from_canonical_cbor(&encode(&value)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut value = decode(&effect.to_canonical_cbor()?)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(payload) = &mut fields[4] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(commands) = &mut payload[1] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(command) = &mut commands[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    command[5] = Value::Bytes(reference(99).digest().to_vec());
    assert_eq!(
        ErasureCasEffectV1::from_canonical_cbor(&encode(&value)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
