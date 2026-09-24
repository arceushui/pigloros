//! Unit coverage for the raw erasure records, codecs, and prepared CAS deltas.

use ciborium::value::Value;

use super::*;

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

#[test]
fn canonical_inventory_lengths_use_shortest_definite_cbor_headers() {
    let cases: &[(usize, &[u8])] = &[
        (23, &[0x97]),
        (24, &[0x98, 24]),
        (256, &[0x99, 1, 0]),
        (65_536, &[0x9a, 0, 1, 0, 0]),
    ];

    for (length, expected) in cases {
        let (actual, actual_length) = canonical_cbor_major_length(0x80, *length);
        assert_eq!(&actual[..actual_length], *expected);
    }

    #[cfg(target_pointer_width = "64")]
    {
        let (actual, actual_length) = canonical_cbor_major_length(0x80, 4_294_967_296);
        assert_eq!(&actual[..actual_length], &[0x9b, 0, 0, 0, 1, 0, 0, 0, 0],);
    }
}

enum TestStateResolver {
    Missing,
    Error(ErasureErrorV1),
    State(Box<ErasureStateV1>),
}

impl ErasureStateResolverV1 for TestStateResolver {
    fn resolve_state(
        &self,
        _digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        match self {
            Self::Missing => Ok(None),
            Self::Error(error) => Err(*error),
            Self::State(state) => Ok(Some(state.as_ref().clone())),
        }
    }
}

struct TestVerifiedStateQuery {
    state: Option<ErasureVerifiedStateV1>,
}

impl ErasureVerifiedStateQueryV1 for TestVerifiedStateQuery {
    fn verified_state(
        &mut self,
        _request: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedStateV1>, ErasureErrorV1> {
        Ok(self.state.clone())
    }
}

struct ErrorStateQuery;

impl ErasureVerifiedStateQueryV1 for ErrorStateQuery {
    fn verified_state(
        &mut self,
        _request: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedStateV1>, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn verified_state_with_topology(
        &mut self,
        _request: ErasureReferenceV1,
    ) -> Result<Option<(ErasureVerifiedStateV1, ErasureVerifiedTopologyProofV1)>, ErasureErrorV1>
    {
        Err(ErasureErrorV1::ProvenanceMissing)
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
    scope_with_members(vec![reference(7)])
}

fn scope_with_members(
    scope_members: Vec<ErasureReferenceV1>,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members,
        scope_timeline_ids: Vec::new(),
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

#[test]
fn scope_commitment_binds_canonical_initial_timeline_ids() -> Result<(), ErasureErrorV1> {
    let first = TimelineId::from_ulid(ulid::Ulid::from(1_u128));
    let second = TimelineId::from_ulid(ulid::Ulid::from(2_u128));
    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members: vec![reference(7)],
        scope_timeline_ids: vec![first, second],
        target_closure: reference(8),
        lineage_rule: Some(reference(9)),
    })?;
    assert_eq!(scope.scope_timeline_ids(), &[first, second]);
    assert_eq!(
        ErasureScopeCommitmentV1::from_canonical_cbor(&scope.to_canonical_cbor()?)?,
        scope
    );

    let mut malformed = decode_value(&scope.to_canonical_cbor()?)?;
    let Value::Array(fields) = &mut malformed else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[4] = Value::Array(vec![Value::Bytes(vec![1])]);
    assert_eq!(
        ErasureScopeCommitmentV1::from_canonical_cbor(&encode_value(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    for scope_timeline_ids in [vec![second, first], vec![first, first]] {
        assert_eq!(
            ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
                request: reference(1),
                scope_members: vec![reference(7)],
                scope_timeline_ids,
                target_closure: reference(8),
                lineage_rule: Some(reference(9)),
            }),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    assert_eq!(
        ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request: reference(1),
            scope_members: vec![reference(7)],
            scope_timeline_ids: vec![first; ERASURE_MAX_INVENTORY_TIMELINES + 1],
            target_closure: reference(8),
            lineage_rule: Some(reference(9)),
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
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
        child_timeline: TimelineId::new(),
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
        child_timeline: TimelineId::new(),
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

    let failure = verify_predecessor_chain_bounded(invalid_root, &TestStateResolver::Missing, 1)
        .err()
        .ok_or(ErasureErrorV1::PolicyConflict)?;
    assert_eq!(failure.error(), ErasureErrorV1::ProvenanceMissing);
    assert_eq!(failure.subject(), reference(4));

    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let failure = verify_predecessor_chain_bounded(submitted, &TestStateResolver::Missing, 0)
        .err()
        .ok_or(ErasureErrorV1::PolicyConflict)?;
    assert_eq!(failure.error(), ErasureErrorV1::ProvenanceMissing);

    let root = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let current = ErasureStateV1 {
        request: root.request(),
        lifecycle: ErasureLifecycleV1::Authorized,
        freeze_position: None,
        coordinator: root.coordinator(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        previous_state: Some(root.state_digest()),
        provenance: reference(5),
        state_digest: reference(6),
    };
    let missing = verify_predecessor_chain_bounded(current.clone(), &TestStateResolver::Missing, 2)
        .err()
        .ok_or(ErasureErrorV1::PolicyConflict)?;
    assert_eq!(missing.subject(), root.state_digest());
    let resolver_error = verify_predecessor_chain_bounded(
        current.clone(),
        &TestStateResolver::Error(ErasureErrorV1::TrustSnapshotInvalid),
        2,
    )
    .err()
    .ok_or(ErasureErrorV1::PolicyConflict)?;
    assert_eq!(resolver_error.error(), ErasureErrorV1::TrustSnapshotInvalid);
    assert_eq!(
        verify_predecessor_chain_bounded(current, &TestStateResolver::State(Box::new(root)), 2,),
        Ok(())
    );
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

fn verified_state_for_containment(
    lifecycle: ErasureLifecycleV1,
    scope: Option<ErasureScopeCommitmentV1>,
    extensions: Vec<ErasureScopeExtensionV1>,
) -> Result<ErasureVerifiedStateV1, ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let state = ErasureStateV1 {
        request: reference(1),
        lifecycle,
        freeze_position: matches!(
            lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        )
        .then_some(10),
        coordinator: reference(2),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        previous_state: (lifecycle != ErasureLifecycleV1::Submitted)
            .then_some(submitted.state_digest()),
        provenance: reference(3),
        state_digest: reference(4),
    };
    Ok(ErasureVerifiedStateV1::from_parts(
        reference(5),
        request()?,
        state,
        scope,
        extensions,
    ))
}

fn collect_fork_retry_scope_requirements(
    inventory: &ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
) -> Result<Vec<ErasureForkRetryScopeRequirementV1>, ErasureErrorV1> {
    collect_fork_retry_scope_requirements_for_scope(inventory, parent, child, reference(35))
}

fn collect_fork_retry_scope_requirements_for_scope(
    inventory: &ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
    child_scope: ErasureReferenceV1,
) -> Result<Vec<ErasureForkRetryScopeRequirementV1>, ErasureErrorV1> {
    inventory
        .fork_retry_scope_requirements(parent, child, child_scope)?
        .collect()
}

#[test]
fn containment_blocks_only_effective_frozen_scope() -> Result<(), ErasureErrorV1> {
    let frozen = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        Vec::new(),
    )?;
    assert_eq!(
        frozen.permit_protected_operation(reference(7)),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    assert_eq!(frozen.permit_protected_operation(reference(99)), Ok(()));

    let submitted =
        verified_state_for_containment(ErasureLifecycleV1::Submitted, None, Vec::new())?;
    assert_eq!(submitted.permit_protected_operation(reference(7)), Ok(()));
    Ok(())
}

#[test]
fn containment_keeps_frozen_scope_blocked_after_terminal_outcomes() -> Result<(), ErasureErrorV1> {
    for lifecycle in [
        ErasureLifecycleV1::DestructionDispatched,
        ErasureLifecycleV1::AwaitingAcknowledgements,
        ErasureLifecycleV1::Complete,
        ErasureLifecycleV1::PartialFailure,
    ] {
        let state = verified_state_for_containment(lifecycle, Some(scope()?), Vec::new())?;
        assert_eq!(
            state.permit_protected_operation(reference(7)),
            Err(ErasureContainmentErrorV1::AccessFrozen)
        );
    }
    Ok(())
}

#[test]
fn containment_includes_admitted_future_fork_extensions() -> Result<(), ErasureErrorV1> {
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: scope()?.reference(),
        fork: reference(33),
        child_timeline: TimelineId::new(),
        lineage_rule: reference(9),
        predecessor_extension: None,
        admission_provenance: reference(34),
    })?;
    let state = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        vec![extension],
    )?;
    assert_eq!(
        state.permit_protected_operation(reference(33)),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    Ok(())
}

#[test]
fn fork_retry_requirements_verify_the_complete_predecessor_and_child_inventory(
) -> Result<(), ErasureErrorV1> {
    let parent = TimelineId::new();
    let child = TimelineId::new();
    let first_child = TimelineId::new();
    let scope = scope()?;
    let first_extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: scope.reference(),
        fork: reference(33),
        child_timeline: first_child,
        lineage_rule: reference(9),
        predecessor_extension: None,
        admission_provenance: reference(34),
    })?;
    let second_extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: scope.reference(),
        fork: reference(35),
        child_timeline: child,
        lineage_rule: reference(9),
        predecessor_extension: Some(first_extension.reference()),
        admission_provenance: reference(36),
    })?;
    let first_fork = first_extension.fork();
    let second_fork = second_extension.fork();
    let state = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope.clone()),
        vec![first_extension, second_extension],
    )?;
    let inventory = ErasureVerifiedInventoryV1::from_verified_recovery(
        vec![(
            state,
            ErasureVerifiedTopologyProofV1::from_verified_recovery(
                reference(5),
                vec![
                    (parent, reference(7)),
                    (first_child, first_fork),
                    (child, second_fork),
                ],
                Vec::new(),
            ),
        )],
        vec![parent, first_child, child],
        4,
    )?;

    let requirements = collect_fork_retry_scope_requirements(&inventory, parent, child)?;
    assert_eq!(requirements.len(), 1);
    assert_eq!(requirements[0].requirement().request(), reference(1));
    assert_eq!(
        requirements[0].requirement().scope_commitment(),
        scope.reference()
    );
    assert_eq!(
        requirements[0].requirement().predecessor_extension(),
        Some(first_extension.reference())
    );
    assert_eq!(requirements[0].extension(), &second_extension);

    // A later request can include this historical child directly and then
    // admit another Fork whose child-scope reference matches the old Fork.
    // That later extension is not part of the old operation's proof.
    let directly_included_state = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope),
        vec![first_extension, second_extension],
    )?;
    let directly_included = ErasureVerifiedInventoryV1::from_verified_recovery(
        vec![(
            directly_included_state,
            ErasureVerifiedTopologyProofV1::from_verified_recovery(
                reference(5),
                vec![(parent, reference(7)), (child, reference(7))],
                Vec::new(),
            ),
        )],
        vec![parent, child],
        4,
    )?;
    assert!(collect_fork_retry_scope_requirements_for_scope(
        &directly_included,
        parent,
        child,
        second_extension.fork(),
    )?
    .is_empty());

    let excluded_state =
        verified_state_for_containment(ErasureLifecycleV1::Submitted, None, Vec::new())?;
    let excluded = ErasureVerifiedInventoryV1::from_verified_recovery(
        vec![(
            excluded_state,
            ErasureVerifiedTopologyProofV1::from_verified_recovery(
                reference(5),
                Vec::new(),
                vec![parent, child],
            ),
        )],
        vec![parent, child],
        4,
    )?;
    assert!(collect_fork_retry_scope_requirements(&excluded, parent, child)?.is_empty());

    assert_fork_retry_rejects_missing_classifications(&inventory, parent, child);
    assert_fork_retry_rejects_no_lineage(parent, child)?;
    assert_fork_retry_rejects_excluded_parent_with_included_child(&inventory, parent, child)?;
    assert_fork_retry_rejects_parent_corruption(&inventory, parent, child)?;
    assert_fork_retry_rejects_child_corruption(&inventory, parent, child)?;
    assert_fork_retry_rejects_included_excluded_child(excluded, parent, child)?;

    assert_empty_fork_batch_proof_round_trip(parent)?;
    Ok(())
}

fn assert_empty_fork_batch_proof_round_trip(parent: TimelineId) -> Result<(), ErasureErrorV1> {
    let empty = ErasureVerifiedInventoryV1::from_verified_recovery(Vec::new(), vec![parent], 4)?;
    let empty_generation = empty.generation();
    let child_without_name = crate::TimelineMeta {
        id: TimelineId::new(),
        mode: crate::TimelineMode::Historical,
        name: None,
        owner: None,
        fork_point: Some((parent, crate::Seq::ZERO)),
    };
    let batch = empty.prepare_fork_batch(
        ErasureForkAdmissionInputV1 {
            operation: reference(41),
            expected_inventory_generation: empty_generation,
            child_scope: reference(42),
            child: child_without_name,
        },
        Vec::new(),
    )?;
    assert!(batch.recovery_result().is_ok());
    let proof = batch.recovery_proof()?;
    let proof_bytes = proof.to_canonical_cbor()?;
    assert_eq!(
        ErasureForkRecoveryProofV1::from_canonical_cbor(&proof_bytes)?,
        proof
    );
    assert_eq!(proof.validate(&batch.recovery_result()?), Ok(()));
    assert_eq!(
        proof.content_digest()?,
        ErasureForkRecoveryProofV1::from_canonical_cbor(&proof_bytes)?.content_digest()?
    );
    assert_eq!(
        ErasureForkRecoveryProofV1::bytes_digest(b"proof"),
        ErasureReferenceV1::from_digest(*blake3::hash(b"proof").as_bytes())
    );
    Ok(())
}

fn assert_fork_retry_rejects_missing_classifications(
    inventory: &ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
) {
    assert_eq!(
        collect_fork_retry_scope_requirements(inventory, TimelineId::new(), child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        collect_fork_retry_scope_requirements(inventory, parent, TimelineId::new()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
}

fn assert_fork_retry_rejects_no_lineage(
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), ErasureErrorV1> {
    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members: vec![reference(7)],
        scope_timeline_ids: Vec::new(),
        target_closure: reference(8),
        lineage_rule: None,
    })?;
    let state = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope.clone()),
        Vec::new(),
    )?;
    let inventory = ErasureVerifiedInventoryV1::from_verified_recovery(
        vec![(
            state,
            ErasureVerifiedTopologyProofV1::from_verified_recovery(
                reference(5),
                Vec::new(),
                vec![parent, child],
            ),
        )],
        vec![parent, child],
        4,
    )?;
    assert!(collect_fork_retry_scope_requirements(&inventory, parent, child)?.is_empty());
    let mut child_included = inventory;
    child_included
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == child)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .membership = ErasureInventoryMembershipV1::Included(scope.reference());
    assert_eq!(
        collect_fork_retry_scope_requirements(&child_included, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn assert_fork_retry_rejects_excluded_parent_with_included_child(
    inventory: &ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), ErasureErrorV1> {
    let mut parent_excluded = inventory.clone();
    parent_excluded
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == parent)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .membership = ErasureInventoryMembershipV1::Excluded;
    assert_eq!(
        collect_fork_retry_scope_requirements(&parent_excluded, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    parent_excluded
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == child)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .membership = ErasureInventoryMembershipV1::Excluded;
    assert!(collect_fork_retry_scope_requirements(&parent_excluded, parent, child)?.is_empty());
    Ok(())
}

fn assert_fork_retry_rejects_parent_corruption(
    inventory: &ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), ErasureErrorV1> {
    let mut incomplete_classifications = inventory.clone();
    incomplete_classifications
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == parent)
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .1
        .clear();
    assert_eq!(
        collect_fork_retry_scope_requirements(&incomplete_classifications, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut mismatched_parent = inventory.clone();
    mismatched_parent
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == parent)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .request = reference(37);
    assert_eq!(
        collect_fork_retry_scope_requirements(&mismatched_parent, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut missing_state_scope = inventory.clone();
    missing_state_scope.members[0].0.scope = None;
    assert_eq!(
        collect_fork_retry_scope_requirements(&missing_state_scope, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn assert_fork_retry_rejects_child_corruption(
    inventory: &ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), ErasureErrorV1> {
    let mut missing_child_request = inventory.clone();
    missing_child_request
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == child)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .request = reference(38);
    assert_eq!(
        collect_fork_retry_scope_requirements(&missing_child_request, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut excluded_child = inventory.clone();
    excluded_child
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == child)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .membership = ErasureInventoryMembershipV1::Excluded;
    assert!(collect_fork_retry_scope_requirements(&excluded_child, parent, child)?.is_empty());

    let mut wrong_extension = inventory.clone();
    wrong_extension
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == child)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .membership = ErasureInventoryMembershipV1::Included(reference(40));
    assert_eq!(
        collect_fork_retry_scope_requirements(&wrong_extension, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn assert_fork_retry_rejects_included_excluded_child(
    mut excluded: ErasureVerifiedInventoryV1,
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), ErasureErrorV1> {
    excluded
        .classifications
        .iter_mut()
        .find(|(timeline, _)| *timeline == child)
        .and_then(|(_, classifications)| classifications.first_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .membership = ErasureInventoryMembershipV1::Included(reference(39));
    assert_eq!(
        collect_fork_retry_scope_requirements(&excluded, parent, child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn containment_gate_blocks_bound_timeline_and_preserves_unrelated_timeline(
) -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_test_open();
    let frozen = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        Vec::new(),
    )?;
    gate.publish_verified_state(frozen);
    let affected = TimelineId::new();
    let unrelated = TimelineId::new();
    gate.bind_timeline(affected, reference(7))
        .map_err(|_| ErasureErrorV1::ScopeInvalid)?;
    assert_eq!(
        gate.authorize(affected, ErasureProtectedOperationV1::Read),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    assert_eq!(
        gate.authorize(unrelated, ErasureProtectedOperationV1::Read),
        Ok(())
    );
    assert_eq!(gate.bind_timeline(affected, reference(7)), Ok(()));
    assert_eq!(
        gate.bind_timeline(affected, reference(8)),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    let mut invoked = false;
    assert_eq!(
        gate.with_fence(unrelated, ErasureProtectedOperationV1::Export, &mut || {
            invoked = true;
        },),
        Ok(())
    );
    assert!(invoked);
    Ok(())
}

#[test]
fn containment_gate_requires_verified_state_for_bound_scope() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    assert_eq!(gate.bind_timeline(timeline, reference(71)), Ok(()));
    assert_eq!(
        gate.authorize(timeline, ErasureProtectedOperationV1::Snapshot),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    gate.block_timeline(timeline);
    let mut invoked = false;
    assert_eq!(
        gate.with_fence(timeline, ErasureProtectedOperationV1::Snapshot, &mut || {
            invoked = true;
        },),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    assert!(!invoked);
}

#[test]
fn containment_gate_installs_verified_query_and_scope_bindings() -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    let state = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        Vec::new(),
    )?;
    let mut query = TestVerifiedStateQuery { state: Some(state) };
    gate.install_from_verified_query(&mut query, reference(1), &[(timeline, reference(7))])
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        gate.authorize(timeline, ErasureProtectedOperationV1::Read),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    Ok(())
}

#[test]
fn containment_gate_requires_query_topology_proof() -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_fail_closed();
    let mut query = TestVerifiedStateQuery {
        state: Some(verified_state_for_containment(
            ErasureLifecycleV1::AccessFrozen,
            Some(scope()?),
            Vec::new(),
        )?),
    };
    assert_eq!(
        gate.install_from_verified_query_with_topology(&mut query, reference(1)),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

#[test]
fn containment_gate_blocks_bindings_when_verified_query_fails() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    let mut query = TestVerifiedStateQuery { state: None };
    assert_eq!(
        gate.install_from_verified_query(&mut query, reference(1), &[(timeline, reference(7))]),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    assert_eq!(
        gate.authorize(timeline, ErasureProtectedOperationV1::Read),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
}

#[test]
fn containment_gate_denies_legacy_combined_query_and_maps_errors() -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_fail_closed();
    let mut state_query = ErrorStateQuery;
    assert_eq!(
        gate.install_from_verified_query_with_topology(&mut state_query, reference(2)),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );

    let mut topology_query = TestVerifiedStateQuery {
        state: Some(verified_state_for_containment(
            ErasureLifecycleV1::AccessFrozen,
            Some(scope()?),
            Vec::new(),
        )?),
    };
    assert_eq!(
        gate.install_from_verified_query_with_topology(&mut topology_query, reference(3)),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

#[test]
fn containment_gate_does_not_downgrade_a_frozen_state() -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    gate.publish_verified_state(verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        Vec::new(),
    )?);
    gate.publish_verified_state(verified_state_for_containment(
        ErasureLifecycleV1::Submitted,
        None,
        Vec::new(),
    )?);
    gate.bind_timeline(timeline, reference(7))
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        gate.authorize(timeline, ErasureProtectedOperationV1::Read),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    Ok(())
}

#[test]
fn containment_gate_allows_nested_store_fences() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    let mut invoked = false;
    assert_eq!(
        gate.with_fence(timeline, ErasureProtectedOperationV1::Read, &mut || {
            assert_eq!(
                gate.authorize(timeline, ErasureProtectedOperationV1::Read),
                Ok(())
            );
            assert_eq!(
                gate.with_fence(timeline, ErasureProtectedOperationV1::Read, &mut || {
                    invoked = true;
                }),
                Ok(())
            );
        })
        .map_err(|_| ErasureErrorV1::ProvenanceMissing),
        Ok(())
    );
    assert!(invoked);
}

#[test]
fn containment_gate_rechecks_nested_timeline_authorization() -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_test_open();
    let frozen = TimelineId::new();
    let allowed = TimelineId::new();
    gate.publish_verified_state(verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        Vec::new(),
    )?);
    gate.bind_timeline(frozen, reference(7))
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    let mut invoked = false;
    assert_eq!(
        gate.with_fence(allowed, ErasureProtectedOperationV1::Read, &mut || {
            assert_eq!(
                gate.with_fence(frozen, ErasureProtectedOperationV1::Read, &mut || {
                    invoked = true;
                }),
                Err(ErasureContainmentErrorV1::AccessFrozen)
            );
        })
        .map_err(|_| ErasureErrorV1::ProvenanceMissing),
        Ok(())
    );
    assert!(!invoked);
    Ok(())
}

#[test]
fn containment_gate_rejects_duplicate_timeline_bindings() -> Result<(), ErasureErrorV1> {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    let state =
        verified_state_for_containment(ErasureLifecycleV1::Submitted, Some(scope()?), Vec::new())?;
    assert_eq!(
        gate.install_verified_state(
            &state,
            &[(timeline, reference(7)), (timeline, reference(7))],
        ),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

#[test]
fn containment_gate_rejects_incomplete_and_conflicting_installations() -> Result<(), ErasureErrorV1>
{
    let timeline = TimelineId::new();
    let other_timeline = TimelineId::new();

    let gate = ErasureContainmentGateV1::new_test_open();
    let state = verified_state_for_containment(
        ErasureLifecycleV1::AccessFrozen,
        Some(scope()?),
        Vec::new(),
    )?;
    assert_eq!(
        gate.install_verified_state(&state, &[(timeline, reference(99))]),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    assert_eq!(
        gate.install_verified_state(&state, &[]),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );

    gate.install_verified_state(&state, &[(timeline, reference(7))])
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    let submitted =
        verified_state_for_containment(ErasureLifecycleV1::Submitted, Some(scope()?), Vec::new())?;
    assert_eq!(
        gate.install_verified_state(&submitted, &[(timeline, reference(7))]),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );

    let conflicting_scope = scope_with_members(vec![reference(7), reference(8)])?;
    let conflicting_state = verified_state_for_containment(
        ErasureLifecycleV1::Submitted,
        Some(conflicting_scope),
        Vec::new(),
    )?;
    let fresh_gate = ErasureContainmentGateV1::new_test_open();
    fresh_gate
        .bind_timeline(timeline, reference(7))
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        fresh_gate.install_verified_state(
            &conflicting_state,
            &[(timeline, reference(8)), (other_timeline, reference(7))],
        ),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

#[test]
fn containment_gate_covers_public_error_codes_and_safe_scope_paths() -> Result<(), ErasureErrorV1> {
    assert_eq!(ErasureContainmentErrorV1::AccessFrozen.code(), 0);
    assert_eq!(ErasureContainmentErrorV1::RecoveryUnavailable.code(), 1);
    assert_eq!(
        ErasureContainmentErrorV1::RecoveryUnavailable.to_string(),
        "erasure containment error 1"
    );
    let _: ErasureContainmentGateV1 = ErasureContainmentGateV1::default();

    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    gate.publish_verified_state(verified_state_for_containment(
        ErasureLifecycleV1::Authorized,
        Some(scope()?),
        Vec::new(),
    )?);
    gate.publish_verified_state(verified_state_for_containment(
        ErasureLifecycleV1::Submitted,
        Some(scope()?),
        Vec::new(),
    )?);
    gate.bind_timeline(timeline, reference(7))
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        gate.authorize(timeline, ErasureProtectedOperationV1::Read),
        Ok(())
    );

    let invalid =
        verified_state_for_containment(ErasureLifecycleV1::AccessFrozen, None, Vec::new())?;
    assert_eq!(
        invalid.permit_protected_operation(reference(7)),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

#[test]
fn stale_generation_error_has_a_stable_round_trip_code() {
    assert_eq!(ErasureErrorV1::StaleGeneration.code(), 16);
    assert_eq!(
        ErasureErrorV1::from_code(16),
        Ok(ErasureErrorV1::StaleGeneration)
    );
}

#[test]
fn erasure_host_errors_have_stable_payload_free_codes() {
    let errors = [
        ErasureHostErrorV1::RecoveryUnavailable,
        ErasureHostErrorV1::AccessFrozen,
        ErasureHostErrorV1::StaleGeneration,
        ErasureHostErrorV1::AuthorizationDenied,
        ErasureHostErrorV1::Conflict,
        ErasureHostErrorV1::AdapterFailure,
    ];
    assert_eq!(errors.map(ErasureHostErrorV1::code), [0_u64, 1, 2, 3, 4, 5]);
    assert_eq!(
        ErasureHostErrorV1::from(ErasureContainmentErrorV1::AccessFrozen),
        ErasureHostErrorV1::AccessFrozen
    );
    assert_eq!(
        ErasureHostErrorV1::from(ErasureContainmentErrorV1::RecoveryUnavailable),
        ErasureHostErrorV1::RecoveryUnavailable
    );
    assert_eq!(
        ErasureHostErrorV1::Conflict.to_string(),
        "erasure host error 4"
    );
}

#[test]
fn fail_closed_gate_rejects_unbound_timeline() {
    let gate = ErasureContainmentGateV1::new_fail_closed();
    assert_eq!(
        gate.authorize(TimelineId::new(), ErasureProtectedOperationV1::Read),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
}

#[test]
fn poisoned_containment_fence_fails_closed() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let timeline = TimelineId::new();
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut panic_during_effect = || {
            std::panic::resume_unwind(Box::new("poison containment fence"));
        };
        assert!(gate
            .with_fence(
                timeline,
                ErasureProtectedOperationV1::Read,
                &mut panic_during_effect,
            )
            .is_ok());
    }));
    assert!(panic_result.is_err());
    assert_eq!(
        gate.authorize(timeline, ErasureProtectedOperationV1::Read),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
}
