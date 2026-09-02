//! Public integration coverage for the direct-replacement erasure contracts.
//!
//! These cases deliberately enter through public constructors and codecs. They
//! exercise optional fields, normalized collections, receipt closure rules, and
//! malformed nested values without depending on private implementation seams.

use ciborium::value::Value;
use pos_core::erasure::{target_closure_digest, ERASURE_CAS_EFFECT_TAG_V1};
use pos_core::{
    acknowledgement_inventory_reference, destruction_command_reference,
    erasure_evidence_set_reference, selected_obligations_reference,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionActionV1,
    ErasureAdministrativeResolutionInputV1, ErasureAdministrativeResolutionV1,
    ErasureApplicabilityDecisionV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureAttemptQuotaReservationV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCasEffectV1,
    ErasureCasOutcomeV1, ErasureCorrectionProvenanceInputV1, ErasureCorrectionProvenanceV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeApplicabilityRowV1,
    ErasureFreezeAuthorizationEvidenceInputV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeFailureInputV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1,
    ErasureFreezeProvenanceV1, ErasureIndexInsertV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptProvenanceInputV1,
    ErasureReceiptProvenanceV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeV1, ErasureStateResolverV1, ErasureStateV1, StoredErasureManifestV1,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn target(seed: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: match seed % 7 {
            0 => ErasureArtifactClassV1::TimelineReplay,
            1 => ErasureArtifactClassV1::ReproManifest,
            2 => ErasureArtifactClassV1::CausalTrace,
            3 => ErasureArtifactClassV1::CalibrationReport,
            4 => ErasureArtifactClassV1::Export,
            5 => ErasureArtifactClassV1::ForkOrSnapshot,
            _ => ErasureArtifactClassV1::ConformanceReport,
        },
        artifact_digest: reference(seed),
        key_role: match seed % 4 {
            0 => ErasureKeyRoleV1::DataEncryption,
            1 => ErasureKeyRoleV1::Signing,
            2 => ErasureKeyRoleV1::BackupEnvelope,
            _ => ErasureKeyRoleV1::ReplicaTransport,
        },
        key_digest: reference(seed.wrapping_add(1)),
        replica_set: reference(seed.wrapping_add(2)),
        replica_id: reference(seed.wrapping_add(3)),
    }
}

fn request(
    scope: ErasureScopeV1,
    selectors: Vec<ErasureReferenceV1>,
) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope,
        selectors,
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 10,
        horizon_position: 20,
        provenance: reference(6),
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

fn replace_path(
    bytes: &[u8],
    path: &[usize],
    replacement: Value,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut value = decode_value(bytes)?;
    let mut current = &mut value;
    for index in path {
        current = match current {
            Value::Array(values) => values
                .get_mut(*index)
                .ok_or(ErasureErrorV1::InvalidEncoding)?,
            _ => return Err(ErasureErrorV1::InvalidEncoding),
        };
    }
    *current = replacement;
    encode_value(&value)
}

fn applicability_matrix(
    target_count: usize,
    applicable: Option<(ErasureInventoryCategoryV1, usize, ErasureReferenceV1)>,
) -> Result<Vec<ErasureFreezeApplicabilityRowV1>, ErasureErrorV1> {
    let mut matrix = Vec::with_capacity(target_count.saturating_mul(4));
    for category in ErasureInventoryCategoryV1::CANONICAL {
        for target_index in 0..target_count {
            let selected = applicable
                .filter(|(candidate, index, _)| *candidate == category && *index == target_index)
                .map(|(_, _, owner)| owner);
            let (decision, owner) = selected.map_or(
                (ErasureApplicabilityDecisionV1::Inapplicable, None),
                |owner| (ErasureApplicabilityDecisionV1::Applicable, Some(owner)),
            );
            matrix.push(ErasureFreezeApplicabilityRowV1::new(
                category,
                target_index as u64,
                decision,
                owner,
            )?);
        }
    }
    Ok(matrix)
}

fn freeze_evidence_pair() -> Result<
    (
        ErasureFreezeAdmissionEvidenceV1,
        ErasureFreezeAuthorizationEvidenceV1,
    ),
    ErasureErrorV1,
> {
    let matrix = applicability_matrix(
        2,
        Some((ErasureInventoryCategoryV1::Artifact, 1, reference(44))),
    )?;
    let input = ErasureFreezeAdmissionEvidenceInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        obligation_set: reference(3),
        applicability_matrix: matrix,
        freeze_position: 40,
        policy: reference(4),
        trust: reference(5),
        authorization_provenance: reference(6),
    };
    let provisional = ErasureFreezeAdmissionEvidenceV1::new(input.clone())?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: reference(4),
            trust: reference(5),
            evidence: vec![1, 2, 3, 4],
        })?;
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        authorization_provenance: authorization.reference(),
        ..input
    })?;
    Ok((admission, authorization))
}

fn obligation(
    request: ErasureReferenceV1,
    category: ErasureInventoryCategoryV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })
}

fn inventory(
    category: ErasureInventoryCategoryV1,
    target: ErasureRequiredTargetV1,
    to: ErasureReplayClaimV1,
    seed: u8,
) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to,
            reason: reference(seed),
            owner: target.replica_id,
            acknowledgements: reference(seed.wrapping_add(1)),
            provenance: reference(seed.wrapping_add(2)),
        },
        retained_disclosure: reference(seed.wrapping_add(3)),
    }
}

fn complete_receipt_input(
) -> Result<(ErasureReceiptInputV1, Vec<ErasureObligationV1>), ErasureErrorV1> {
    let entries = [
        inventory(
            ErasureInventoryCategoryV1::Artifact,
            target(10),
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            60,
        ),
        inventory(
            ErasureInventoryCategoryV1::Key,
            target(20),
            ErasureReplayClaimV1::StructuralOnly,
            70,
        ),
        inventory(
            ErasureInventoryCategoryV1::Replica,
            target(30),
            ErasureReplayClaimV1::UnverifiableArtifactsMissing,
            80,
        ),
        inventory(
            ErasureInventoryCategoryV1::Backup,
            target(40),
            ErasureReplayClaimV1::IncompatibleProfile,
            90,
        ),
    ];
    let mut frozen_targets = entries.iter().map(|entry| entry.target).collect::<Vec<_>>();
    frozen_targets.reverse();
    let obligations = entries
        .iter()
        .map(|entry| obligation(reference(1), entry.category, entry.target))
        .collect::<Result<Vec<_>, _>>()?;
    let mut acknowledgements = entries
        .iter()
        .zip(&obligations)
        .enumerate()
        .map(
            |(index, (entry, obligation))| pos_core::ErasureAcknowledgementV1 {
                obligation: obligation.reference(),
                target: entry.target,
                owner: entry.transition.owner,
                evidence: reference(100 + index as u8),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
        )
        .collect::<Vec<_>>();
    acknowledgements.reverse();
    Ok((
        ErasureReceiptInputV1 {
            request: reference(1),
            terminal_state: reference(101),
            coordinator: reference(102),
            lifecycle: ErasureLifecycleV1::Complete,
            freeze_position: 40,
            acknowledgements,
            frozen_targets,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: vec![entries[0]],
                keys: vec![entries[1]],
                replicas: vec![entries[2]],
                backups: vec![entries[3]],
            },
            replay_claim: ErasureReplayClaimV1::Exact,
            policy: reference(4),
            trust: reference(5),
            provenance: reference(103),
            issue_position: 50,
            signature: reference(104),
            receipt_digest: reference(0),
        },
        obligations,
    ))
}

#[derive(Clone)]
enum ResolverReply {
    Missing,
    Error(ErasureErrorV1),
    State(ErasureStateV1),
}

impl ErasureStateResolverV1 for ResolverReply {
    fn resolve_state(
        &self,
        _digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        match self {
            Self::Missing => Ok(None),
            Self::Error(error) => Err(*error),
            Self::State(state) => Ok(Some(state.clone())),
        }
    }
}

#[test]
fn public_errors_lifecycles_and_digest_helpers_are_closed() {
    let errors = [
        ErasureErrorV1::InvalidEncoding,
        ErasureErrorV1::UnsupportedVersion,
        ErasureErrorV1::Unauthorized,
        ErasureErrorV1::ScopeInvalid,
        ErasureErrorV1::PolicyConflict,
        ErasureErrorV1::AccessFreezeFailed,
        ErasureErrorV1::KeyRegistryUnavailable,
        ErasureErrorV1::KeyDestructionFailed,
        ErasureErrorV1::ArtifactDeletionFailed,
        ErasureErrorV1::ReplicaTimeout,
        ErasureErrorV1::ReplicaNegativeAcknowledgement,
        ErasureErrorV1::BackupInventoryIncomplete,
        ErasureErrorV1::BackupDeletionPending,
        ErasureErrorV1::ReceiptCommitFailed,
        ErasureErrorV1::TrustSnapshotInvalid,
        ErasureErrorV1::ProvenanceMissing,
    ];
    for (code, error) in errors.into_iter().enumerate() {
        assert_eq!(error.code(), code as u64);
        assert_eq!(ErasureErrorV1::from_code(code as u64), Ok(error));
        assert_eq!(error.to_string(), format!("erasure contract error {code}"));
    }
    assert_eq!(
        ErasureErrorV1::from_code(errors.len() as u64),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let actions = [
        ErasureAdministrativeResolutionActionV1::CloseContainment,
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
    ];
    for (code, action) in actions.into_iter().enumerate() {
        assert_eq!(action.code(), code as u64);
        assert_eq!(
            ErasureAdministrativeResolutionActionV1::from_code(code as u64),
            Ok(action)
        );
    }
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(2),
        Err(ErasureErrorV1::InvalidEncoding)
    );

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
    for lifecycle in lifecycles {
        for next in lifecycles {
            let _ = lifecycle.permits(next);
        }
        assert_eq!(
            lifecycle.is_terminal(),
            matches!(
                lifecycle,
                ErasureLifecycleV1::Complete | ErasureLifecycleV1::Rejected
            )
        );
        assert_eq!(
            lifecycle.is_attempt_terminal(),
            matches!(
                lifecycle,
                ErasureLifecycleV1::Complete
                    | ErasureLifecycleV1::PartialFailure
                    | ErasureLifecycleV1::Rejected
            )
        );
    }
    assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Rejected));
    assert!(!ErasureLifecycleV1::Complete.permits(ErasureLifecycleV1::Submitted));

    let first = reference(10);
    let second = reference(20);
    assert_eq!(first.digest(), [10; 32]);
    assert_eq!(
        selected_obligations_reference(&[second, first]),
        selected_obligations_reference(&[first, second])
    );
    assert_eq!(
        acknowledgement_inventory_reference(&[second, first]),
        acknowledgement_inventory_reference(&[first, second])
    );
    assert_eq!(
        erasure_evidence_set_reference(&[second, first]),
        erasure_evidence_set_reference(&[first, second])
    );
    assert_ne!(
        selected_obligations_reference(&[first]),
        acknowledgement_inventory_reference(&[first])
    );

    let mut targets = vec![target(21), target(11)];
    let unsorted_closure = target_closure_digest(&targets);
    targets.sort_unstable();
    assert_ne!(unsorted_closure, target_closure_digest(&targets));
}

#[test]
fn request_and_portable_records_cover_optional_and_normalized_forms() -> Result<(), ErasureErrorV1>
{
    for scope in [
        ErasureScopeV1::PrivateSubjectData,
        ErasureScopeV1::ConsentedSharedData,
        ErasureScopeV1::PublicRecord,
        ErasureScopeV1::Aggregate,
        ErasureScopeV1::StructuralAuditMetadata,
    ] {
        let value = request(scope, vec![reference(30), reference(20)])?;
        assert_eq!(value.selectors(), &[reference(20), reference(30)]);
        let bytes = value.to_canonical_cbor()?;
        assert_eq!(ErasureRequestV1::from_canonical_cbor(&bytes)?, value);
    }
    assert_eq!(
        request(ErasureScopeV1::PrivateSubjectData, Vec::new()),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(ErasureRequestInputV1 {
            request: reference(1),
            subject: reference(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors: vec![reference(20), reference(20)],
            requester: reference(3),
            authorization: reference(4),
            policy: reference(5),
            request_position: 10,
            horizon_position: 9,
            provenance: reference(6),
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: reference(2),
        correction_reason: reference(3),
        authorization_provenance: reference(4),
    })?;
    assert_eq!(correction.digest(), correction.reference());
    assert_eq!(correction.rejected_request(), reference(1));
    assert_eq!(correction.rejected_terminal_state(), reference(2));
    assert_eq!(correction.correction_reason(), reference(3));
    assert_eq!(correction.authorization_provenance(), reference(4));
    let correction_bytes = correction.to_canonical_cbor()?;
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&correction_bytes)?,
        correction
    );

    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members: vec![reference(2), reference(8)],
        target_closure: reference(9),
        lineage_rule: None,
    })?;
    assert_eq!(scope.lineage_rule(), None);
    assert_eq!(scope.scope_members(), &[reference(2), reference(8)]);
    let scope_bytes = scope.to_canonical_cbor()?;
    assert_eq!(
        ErasureScopeCommitmentV1::from_canonical_cbor(&scope_bytes)?,
        scope
    );
    assert_eq!(
        ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request: reference(1),
            scope_members: vec![reference(8), reference(2)],
            target_closure: reference(9),
            lineage_rule: None,
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let (admission, authorization) = freeze_evidence_pair()?;
    assert_eq!(admission.applicability_matrix().len(), 8);
    assert_eq!(
        admission.applicability_matrix()[0].category(),
        ErasureInventoryCategoryV1::Artifact
    );
    assert_eq!(admission.applicability_matrix()[1].target_index(), 1);
    assert_eq!(
        admission.applicability_matrix()[1].decision(),
        ErasureApplicabilityDecisionV1::Applicable
    );
    assert_eq!(
        admission.applicability_matrix()[1].owner(),
        Some(reference(44))
    );
    assert_eq!(authorization.evidence(), &[1, 2, 3, 4]);
    assert_eq!(authorization.policy(), reference(4));
    assert_eq!(authorization.trust(), reference(5));
    assert_eq!(
        authorization.admission_body_digest(),
        admission.authorization_body_digest()?
    );
    assert_eq!(
        authorization.verify_admission_body_binding(&admission),
        Ok(())
    );
    let mut changed_admission = admission.clone();
    let changed_bytes = replace_path(
        &changed_admission.to_canonical_cbor()?,
        &[6],
        Value::Integer(41.into()),
    )?;
    changed_admission = ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&changed_bytes)?;
    assert_eq!(
        authorization.verify_admission_body_binding(&changed_admission),
        Err(ErasureErrorV1::Unauthorized)
    );
    assert_eq!(
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: reference(1),
            policy: reference(2),
            trust: reference(3),
            evidence: Vec::new(),
        },),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let admission_bytes = admission.to_canonical_cbor()?;
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&admission_bytes)?,
        admission
    );
    let authorization_bytes = authorization.to_canonical_cbor()?;
    assert_eq!(
        ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor(&authorization_bytes)?,
        authorization
    );

    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        obligation_set: reference(3),
        freeze_position: 40,
        host_evidence: reference(4),
    })?;
    assert_eq!(freeze.freeze_position(), 40);
    assert_eq!(
        ErasureFreezeProvenanceV1::from_canonical_cbor(&freeze.to_canonical_cbor()?)?,
        freeze
    );
    for error in [
        ErasureErrorV1::ScopeInvalid,
        ErasureErrorV1::AccessFreezeFailed,
    ] {
        let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
            request: reference(1),
            error,
            authorization_provenance: reference(2),
            evidence: reference(3),
        })?;
        assert_eq!(failure.error(), error);
        assert_eq!(
            ErasureFreezeFailureV1::from_canonical_cbor(&failure.to_canonical_cbor()?)?,
            failure
        );
    }
    assert_eq!(
        ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
            request: reference(1),
            error: ErasureErrorV1::Unauthorized,
            authorization_provenance: reference(2),
            evidence: reference(3),
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: reference(1),
        authorization_provenance: reference(2),
    })?;
    assert_eq!(rejection.request(), reference(1));
    assert_eq!(rejection.authorization_provenance(), reference(2));
    assert_eq!(
        ErasureAuthorizationRejectionV1::from_canonical_cbor(&rejection.to_canonical_cbor()?)?,
        rejection
    );

    let retry = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 2,
        source_receipt: Some(reference(50)),
        unresolved_obligations: vec![reference(30), reference(20)],
        command_identities: vec![reference(31), reference(21)],
        policy: reference(4),
        trust: reference(5),
        admitted_position: 41,
        deadline_position: 49,
        authorization_provenance: reference(6),
    })?;
    assert_eq!(retry.source_receipt(), Some(reference(50)));
    assert_eq!(
        retry.unresolved_obligations(),
        &[reference(20), reference(30)]
    );
    assert_eq!(retry.command_identities(), &[reference(21), reference(31)]);
    assert_eq!(retry.admitted_position(), 41);
    assert_eq!(retry.deadline_position(), 49);
    assert_eq!(
        ErasureRetryAdmissionV1::from_canonical_cbor(&retry.to_canonical_cbor()?)?,
        retry
    );
    assert_eq!(
        ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            request: reference(1),
            attempt_ordinal: 0,
            source_receipt: Some(reference(50)),
            unresolved_obligations: vec![],
            command_identities: vec![],
            policy: reference(4),
            trust: reference(5),
            admitted_position: 1,
            deadline_position: 2,
            authorization_provenance: reference(6),
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );

    for outcome in [
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        ErasureAcknowledgementOutcomeV1::Negative,
        ErasureAcknowledgementOutcomeV1::Stale,
    ] {
        let provenance =
            ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
                request: reference(1),
                command: reference(2),
                attempt: reference(3),
                obligation: reference(4),
                owner: reference(5),
                scope: reference(6),
                outcome,
                evidence: reference(7),
                policy: reference(8),
                trust: reference(9),
            })?;
        assert_eq!(provenance.outcome(), outcome);
        assert_eq!(
            ErasureAcknowledgementProvenanceV1::from_canonical_cbor(
                &provenance.to_canonical_cbor()?
            )?,
            provenance
        );
    }

    let attempt_outcome = ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: reference(2),
        source_receipt: Some(reference(3)),
        lifecycle: ErasureLifecycleV1::Complete,
        selected_obligations: reference(4),
        acknowledgement_inventory: reference(5),
        terminal_position: 50,
        policy: reference(6),
        trust: reference(7),
    })?;
    assert_eq!(attempt_outcome.source_receipt(), Some(reference(3)));
    assert_eq!(
        ErasureAttemptOutcomeV1::from_canonical_cbor(&attempt_outcome.to_canonical_cbor()?)?,
        attempt_outcome
    );
    assert_eq!(
        ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
            request: reference(1),
            attempt: reference(2),
            source_receipt: None,
            lifecycle: ErasureLifecycleV1::Authorized,
            selected_obligations: reference(4),
            acknowledgement_inventory: reference(5),
            terminal_position: 50,
            policy: reference(6),
            trust: reference(7),
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let receipt_provenance = ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request: reference(1),
        attempt: reference(2),
        attempt_ordinal: 1,
        predecessor_receipt: Some(reference(3)),
        terminal_state: reference(4),
        evidence_set: reference(5),
        policy: reference(6),
        trust: reference(7),
        issue_position: 50,
    })?;
    assert_eq!(receipt_provenance.predecessor_receipt(), Some(reference(3)));
    assert_eq!(
        ErasureReceiptProvenanceV1::from_canonical_cbor(&receipt_provenance.to_canonical_cbor()?)?,
        receipt_provenance
    );
    assert_eq!(
        ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
            request: reference(1),
            attempt: reference(2),
            attempt_ordinal: 1,
            predecessor_receipt: None,
            terminal_state: reference(4),
            evidence_set: reference(5),
            policy: reference(6),
            trust: reference(7),
            issue_position: 50,
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: reference(1),
            affected_digests: vec![reference(30), reference(20)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: reference(4),
            policy: reference(5),
            trust: reference(6),
            principal: reference(7),
            authorization_provenance: reference(8),
            reason: reference(9),
            issue_position: 50,
            predecessor_resolution: Some(reference(10)),
        })?;
    assert_eq!(
        resolution.affected_digests(),
        &[reference(20), reference(30)]
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&resolution.to_canonical_cbor()?)?,
        resolution
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            affected_digests: vec![reference(20), reference(20)],
            ..ErasureAdministrativeResolutionInputV1 {
                request: reference(1),
                affected_digests: vec![reference(20), reference(20)],
                action: ErasureAdministrativeResolutionActionV1::CloseContainment,
                scope_commitment: reference(4),
                policy: reference(5),
                trust: reference(6),
                principal: reference(7),
                authorization_provenance: reference(8),
                reason: reference(9),
                issue_position: 50,
                predecessor_resolution: None,
            }
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn atomic_freeze_admission_exposes_its_complete_public_commitments() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let frozen_target = target(11);
    let targets = vec![frozen_target];
    let frozen_obligation =
        obligation(request, ErasureInventoryCategoryV1::Artifact, frozen_target)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![frozen_obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let scope = ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: target_closure_digest(&targets),
        lineage_rule: Some(reference(3)),
    };
    let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
    let matrix = applicability_matrix(
        1,
        Some((
            ErasureInventoryCategoryV1::Artifact,
            0,
            frozen_target.replica_id,
        )),
    )?;
    let admission_input = ErasureFreezeAdmissionEvidenceInputV1 {
        request,
        scope_commitment: scope_reference,
        obligation_set: obligation_set.reference(),
        applicability_matrix: matrix,
        freeze_position: 40,
        policy: reference(4),
        trust: reference(5),
        authorization_provenance: reference(6),
    };
    let provisional = ErasureFreezeAdmissionEvidenceV1::new(admission_input.clone())?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: reference(4),
            trust: reference(5),
            evidence: vec![9, 8, 7],
        })?;
    let freeze_admission =
        ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
            authorization_provenance: authorization.reference(),
            ..admission_input
        })?;
    let admission = ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
        targets: targets.clone(),
        scope: scope.clone(),
        obligations: vec![frozen_obligation],
        obligation_set: obligation_set.clone(),
        freeze_position: 40,
        freeze_admission_evidence: freeze_admission.clone(),
        freeze_authorization_evidence: authorization.clone(),
    })?;
    assert_eq!(admission.targets(), targets.as_slice());
    assert_eq!(admission.scope(), &scope);
    assert_eq!(admission.obligations(), &[frozen_obligation]);
    assert_eq!(admission.obligation_set(), &obligation_set);
    assert_eq!(admission.freeze_position(), 40);
    assert_eq!(admission.freeze_admission_evidence(), &freeze_admission);
    assert_eq!(admission.freeze_authorization_evidence(), &authorization);
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: Vec::new(),
            scope,
            obligations: vec![frozen_obligation],
            obligation_set,
            freeze_position: 40,
            freeze_admission_evidence: freeze_admission,
            freeze_authorization_evidence: authorization,
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureFreezeApplicabilityRowV1::new(
            ErasureInventoryCategoryV1::Artifact,
            0,
            ErasureApplicabilityDecisionV1::Applicable,
            None,
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureFreezeApplicabilityRowV1::new(
            ErasureInventoryCategoryV1::Artifact,
            0,
            ErasureApplicabilityDecisionV1::Inapplicable,
            Some(reference(9)),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn receipt_covers_complete_partial_and_negative_public_closures() -> Result<(), ErasureErrorV1> {
    let (input, obligations) = complete_receipt_input()?;
    let receipt = ErasureReceiptV1::new(input.clone())?;
    assert_eq!(receipt.request(), reference(1));
    assert_eq!(receipt.terminal_state(), reference(101));
    assert_eq!(receipt.coordinator(), reference(102));
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(
        receipt.replay_claim(),
        ErasureReplayClaimV1::IncompatibleProfile
    );
    assert_eq!(receipt.freeze_position(), 40);
    assert_eq!(receipt.policy(), reference(4));
    assert_eq!(receipt.trust(), reference(5));
    assert_eq!(receipt.issue_position(), 50);
    assert_eq!(receipt.signature(), reference(104));
    assert_eq!(receipt.frozen_targets().len(), 4);
    assert_eq!(receipt.acknowledgements().len(), 4);
    assert_eq!(receipt.inventories().artifacts.len(), 1);
    assert_eq!(receipt.inventories().keys.len(), 1);
    assert_eq!(receipt.inventories().replicas.len(), 1);
    assert_eq!(receipt.inventories().backups.len(), 1);
    assert_eq!(receipt.validate_frozen_obligations(&obligations), Ok(()));
    let bytes = receipt.to_canonical_cbor()?;
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&bytes)?, receipt);

    let partial_target = target(80);
    let partial_obligation = obligation(
        reference(1),
        ErasureInventoryCategoryV1::Artifact,
        partial_target,
    )?;
    let partial_input = ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(201),
        coordinator: reference(202),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        freeze_position: 40,
        acknowledgements: Vec::new(),
        frozen_targets: vec![partial_target],
        pending_owners: vec![partial_target.replica_id],
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory(
                ErasureInventoryCategoryV1::Artifact,
                partial_target,
                ErasureReplayClaimV1::StructuralOnly,
                120,
            )],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(4),
        trust: reference(5),
        provenance: reference(203),
        issue_position: 50,
        signature: reference(204),
        receipt_digest: reference(0),
    };
    let partial = ErasureReceiptV1::new(partial_input)?;
    assert_eq!(partial.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(partial.replay_claim(), ErasureReplayClaimV1::StructuralOnly);
    assert_eq!(
        partial.validate_frozen_obligations(&[partial_obligation]),
        Ok(())
    );

    let negative_target = target(90);
    let negative_obligation = obligation(
        reference(1),
        ErasureInventoryCategoryV1::Artifact,
        negative_target,
    )?;
    let negative_ack = pos_core::ErasureAcknowledgementV1 {
        obligation: negative_obligation.reference(),
        target: negative_target,
        owner: negative_target.replica_id,
        evidence: reference(220),
        outcome: ErasureAcknowledgementOutcomeV1::Negative,
    };
    let negative = ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(221),
        coordinator: reference(222),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        freeze_position: 40,
        acknowledgements: vec![negative_ack],
        frozen_targets: vec![negative_target],
        pending_owners: Vec::new(),
        failed_owners: vec![negative_target.replica_id],
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory(
                ErasureInventoryCategoryV1::Artifact,
                negative_target,
                ErasureReplayClaimV1::UnverifiableArtifactsMissing,
                130,
            )],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(4),
        trust: reference(5),
        provenance: reference(223),
        issue_position: 50,
        signature: reference(224),
        receipt_digest: reference(0),
    })?;
    assert_eq!(negative.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(
        negative.validate_frozen_obligations(&[negative_obligation]),
        Ok(())
    );
    Ok(())
}

#[test]
fn receipt_rejects_inconsistent_closures_and_history_sources() -> Result<(), ErasureErrorV1> {
    let (input, obligations) = complete_receipt_input()?;
    assert_eq!(
        ErasureReceiptV1::new(ErasureReceiptInputV1 {
            lifecycle: ErasureLifecycleV1::Authorized,
            ..input.clone()
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(ErasureReceiptInputV1 {
            issue_position: 39,
            ..input.clone()
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut invalid_transition = input.clone();
    invalid_transition.inventories.artifacts[0].transition.from =
        ErasureReplayClaimV1::StructuralOnly;
    invalid_transition.inventories.artifacts[0].transition.to = ErasureReplayClaimV1::Exact;
    assert_eq!(
        ErasureReceiptV1::new(invalid_transition),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut wrong_category = input.clone();
    wrong_category
        .inventories
        .keys
        .push(wrong_category.inventories.artifacts[0]);
    assert_eq!(
        ErasureReceiptV1::new(wrong_category),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut duplicate_target = input.clone();
    duplicate_target
        .inventories
        .artifacts
        .push(duplicate_target.inventories.artifacts[0]);
    assert_eq!(
        ErasureReceiptV1::new(duplicate_target),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut outside_ack = input.clone();
    outside_ack
        .acknowledgements
        .push(pos_core::ErasureAcknowledgementV1 {
            obligation: reference(230),
            target: target(230),
            owner: reference(231),
            evidence: reference(232),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        });
    assert_eq!(
        ErasureReceiptV1::new(outside_ack),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut overlap = input.clone();
    overlap.pending_owners = vec![reference(10)];
    overlap.failed_owners = vec![reference(10)];
    assert_eq!(
        ErasureReceiptV1::new(overlap),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut incomplete_complete = input.clone();
    incomplete_complete.acknowledgements.clear();
    incomplete_complete.pending_owners = input
        .inventories
        .artifacts
        .iter()
        .chain(&input.inventories.keys)
        .chain(&input.inventories.replicas)
        .chain(&input.inventories.backups)
        .map(|entry| entry.transition.owner)
        .collect();
    assert_eq!(
        ErasureReceiptV1::new(incomplete_complete),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut resolved_partial = input.clone();
    resolved_partial.lifecycle = ErasureLifecycleV1::PartialFailure;
    assert_eq!(
        ErasureReceiptV1::new(resolved_partial),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let receipt = ErasureReceiptV1::new(input)?;
    assert_eq!(
        receipt.validate_frozen_obligations(&obligations[..3]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut wrong_owner = obligations.clone();
    wrong_owner[0] = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: wrong_owner[0].category(),
        target: wrong_owner[0].target(),
        owner: reference(240),
        command_identity: wrong_owner[0].command_identity(),
    })?;
    assert_eq!(
        receipt.validate_frozen_obligations(&wrong_owner),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let root = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(
        root.validate_predecessor(&root),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        root.verify_predecessor_chain(&ResolverReply::Missing),
        Ok(())
    );
    assert_eq!(
        receipt.verify_history(&ResolverReply::Missing),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&ResolverReply::Error(ErasureErrorV1::TrustSnapshotInvalid)),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    assert_eq!(
        receipt.verify_history(&ResolverReply::State(root)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn state_manifest_and_cas_effect_public_boundaries_are_exercised() -> Result<(), ErasureErrorV1> {
    let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(state.lifecycle(), ErasureLifecycleV1::Submitted);
    assert_eq!(state.request(), reference(1));
    assert_eq!(state.coordinator(), reference(2));
    assert_eq!(state.provenance(), reference(3));
    assert_eq!(state.freeze_position(), None);
    assert_eq!(state.previous_state(), None);
    assert_eq!(state.pending_owners(), &[]);
    assert_eq!(state.failed_owners(), &[]);
    assert_eq!(state.replay_claim(), ErasureReplayClaimV1::Exact);
    let state_bytes = state.to_canonical_cbor()?;
    assert_eq!(ErasureStateV1::from_canonical_cbor(&state_bytes)?, state);

    let manifest_bytes = vec![0x01];
    let mut domain_input = b"ERCRP1".to_vec();
    domain_input.push(0);
    domain_input.extend_from_slice(&manifest_bytes);
    let manifest_digest = ErasureReferenceV1::from_digest(*blake3::hash(&domain_input).as_bytes());
    let manifest = StoredErasureManifestV1::new(manifest_digest, manifest_bytes.clone())?;
    assert_eq!(manifest.digest(), manifest_digest);
    assert_eq!(manifest.canonical_cbor(), manifest_bytes.as_slice());
    assert_eq!(
        StoredErasureManifestV1::new(reference(250), manifest_bytes),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let admission = reference(10);
    let command_target = target(11);
    let command = ErasureDestructionCommandV1 {
        obligation: reference(12),
        category: ErasureInventoryCategoryV1::Replica,
        target: command_target,
        owner: reference(13),
        command: destruction_command_reference(admission, command_target),
        provenance: admission,
    };
    let reservation = ErasureAttemptQuotaReservationV1::new(admission, reference(14));
    assert_eq!(reservation.admission(), admission);
    assert_eq!(reservation.reference(), reference(14));
    let effects = [
        ErasureCasEffectV1::None,
        ErasureCasEffectV1::AttemptAdmission {
            reservation,
            commands: vec![command],
        },
        ErasureCasEffectV1::AcknowledgementAdmission {
            acknowledgement: reference(15),
        },
        ErasureCasEffectV1::ReceiptAdmission {
            receipt: reference(16),
        },
    ];
    for effect in effects {
        let bytes = effect.to_canonical_cbor()?;
        assert_eq!(ErasureCasEffectV1::from_canonical_cbor(&bytes)?, effect);
        let decoded = ErasureCasEffectV1::from_canonical_cbor(&bytes)?;
        assert_eq!(decoded.identity(), effect.identity());
        match effect {
            ErasureCasEffectV1::None => assert_eq!(effect.subject(), None),
            ErasureCasEffectV1::AttemptAdmission { .. } => {
                assert_eq!(effect.subject(), Some(admission))
            }
            ErasureCasEffectV1::AcknowledgementAdmission { acknowledgement } => {
                assert_eq!(effect.subject(), Some(acknowledgement))
            }
            ErasureCasEffectV1::ReceiptAdmission { receipt } => {
                assert_eq!(effect.subject(), Some(receipt))
            }
        }
    }
    assert_ne!(
        ErasureCasEffectV1::None.identity(),
        ErasureCasEffectV1::AcknowledgementAdmission {
            acknowledgement: reference(15)
        }
        .identity()
    );
    assert_ne!(
        ErasureCasOutcomeV1::Applied,
        ErasureCasOutcomeV1::ExactRetry
    );

    let indexes = [
        ErasureIndexInsertV1::AttemptPage {
            ordinal: 0,
            reference: reference(20),
        },
        ErasureIndexInsertV1::ScopeNode {
            ordinal: 1,
            reference: reference(21),
        },
        ErasureIndexInsertV1::AdministrativeResolution {
            ordinal: 2,
            reference: reference(22),
        },
    ];
    for index in indexes {
        match index {
            ErasureIndexInsertV1::AttemptPage { ordinal, .. }
            | ErasureIndexInsertV1::ScopeNode { ordinal, .. }
            | ErasureIndexInsertV1::AdministrativeResolution { ordinal, .. } => {
                assert!(ordinal <= 2);
            }
        }
    }
    Ok(())
}

#[test]
fn nested_codecs_reject_wrong_versions_shapes_and_closed_values() -> Result<(), ErasureErrorV1> {
    let request = request(ErasureScopeV1::PrivateSubjectData, vec![reference(20)])?;
    let request_bytes = request.to_canonical_cbor()?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&replace_path(
            &request_bytes,
            &[1],
            Value::Integer(2.into()),
        )?),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&replace_path(
            &request_bytes,
            &[0],
            Value::Text("ERQ0".to_owned()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&replace_path(
            &request_bytes,
            &[4],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&replace_path(
            &request_bytes,
            &[5],
            Value::Array(Vec::new()),
        )?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&replace_path(
            &request_bytes,
            &[6],
            Value::Text("requester".to_owned()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut trailing = request_bytes.clone();
    trailing.push(0);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&[0x18, 0x00]),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&[0xff]),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let state_bytes = state.to_canonical_cbor()?;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&replace_path(
            &state_bytes,
            &[3],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&replace_path(
            &state_bytes,
            &[6],
            Value::Text("owners".to_owned()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&replace_path(
            &state_bytes,
            &[11],
            Value::Bytes(reference(99).digest().to_vec()),
        )?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let (admission, _) = freeze_evidence_pair()?;
    let admission_bytes = admission.to_canonical_cbor()?;
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&replace_path(
            &admission_bytes,
            &[5],
            Value::Array(Vec::new()),
        )?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&replace_path(
            &admission_bytes,
            &[5, 0, 0],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let (receipt_input, _) = complete_receipt_input()?;
    let receipt = ErasureReceiptV1::new(receipt_input)?;
    let receipt_bytes = receipt.to_canonical_cbor()?;
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&replace_path(
            &receipt_bytes,
            &[4],
            Value::Integer(1.into()),
        )?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&replace_path(
            &receipt_bytes,
            &[6, 0, 0],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&replace_path(
            &receipt_bytes,
            &[7, 0, 4],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&replace_path(
            &receipt_bytes,
            &[10, 0, 0, 0],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&replace_path(
            &receipt_bytes,
            &[16],
            Value::Bytes(reference(99).digest().to_vec()),
        )?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let effect = ErasureCasEffectV1::AcknowledgementAdmission {
        acknowledgement: reference(15),
    };
    let effect_bytes = effect.to_canonical_cbor()?;
    assert_eq!(
        ErasureCasEffectV1::from_canonical_cbor(&replace_path(
            &effect_bytes,
            &[2],
            Value::Integer(99.into()),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureCasEffectV1::from_canonical_cbor(&replace_path(
            &effect_bytes,
            &[3],
            Value::Bytes(vec![1]),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureCasEffectV1::from_canonical_cbor(&replace_path(
            &effect_bytes,
            &[4],
            Value::Array(vec![Value::Null]),
        )?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut malformed = effect_bytes;
    malformed.extend_from_slice(&[0, 0]);
    assert_eq!(
        ErasureCasEffectV1::from_canonical_cbor(&malformed),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(ERASURE_CAS_EFFECT_TAG_V1, "ERCE1");
    Ok(())
}

#[test]
fn destruction_commands_and_inventory_ordering_use_public_contracts() -> Result<(), ErasureErrorV1>
{
    let request = reference(1);
    let first_target = target(12);
    let second_target = target(13);
    let first = obligation(request, ErasureInventoryCategoryV1::Artifact, first_target)?;
    let second = obligation(request, ErasureInventoryCategoryV1::Artifact, second_target)?;
    let first_command = ErasureDestructionCommandV1::from_obligation(&first, reference(20));
    let second_command = ErasureDestructionCommandV1::from_obligation(&second, reference(21));
    assert_eq!(first_command.obligation, first.reference());
    assert_eq!(first_command.category, first.category());
    assert_eq!(first_command.target, first.target());
    assert_eq!(first_command.owner, first.owner());
    assert_eq!(first_command.command, first.command_identity());
    assert_eq!(first_command.provenance, reference(20));
    assert_ne!(first_command.command, second_command.command);

    let mut targets = vec![second_target, first_target];
    targets.sort_unstable();
    assert!(targets[0] < targets[1]);
    let mut inventories = vec![
        inventory(
            ErasureInventoryCategoryV1::Artifact,
            second_target,
            ErasureReplayClaimV1::StructuralOnly,
            30,
        ),
        inventory(
            ErasureInventoryCategoryV1::Artifact,
            first_target,
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            40,
        ),
    ];
    inventories.sort_unstable();
    assert_eq!(inventories[0].target, first_target.min(second_target));
    assert_eq!(
        target_closure_digest(&targets),
        target_closure_digest(&[targets[0], targets[1]])
    );
    Ok(())
}
