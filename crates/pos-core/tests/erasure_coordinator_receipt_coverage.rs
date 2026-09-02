//! Public integration coverage for the direct-replacement erasure contracts.
//!
//! These cases deliberately enter through public constructors and codecs. They
//! exercise optional fields, normalized collections, receipt closure rules, and
//! malformed nested values without depending on private implementation seams.

#[path = "support/coordinator.rs"]
pub mod coordinator_support;
#[path = "support/erasure.rs"]
pub mod erasure_support;

use ciborium::value::Value;
use pos_core::erasure::{
    target_closure_digest, ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1, ERASURE_CAS_EFFECT_TAG_V1,
    ERASURE_FREEZE_PROVENANCE_TAG_V1, ERASURE_SCOPE_COMMITMENT_TAG_V1,
    ERASURE_TARGET_CLOSURE_TAG_V1,
};
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
    ErasureCasOutcomeV1, ErasureCoordinator, ErasureCoordinatorStateMachineV1,
    ErasureCorrectionProvenanceInputV1, ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1,
    ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeFailureInputV1, ErasureFreezeFailureV1,
    ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1, ErasureIndexInsertV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationSetInputV1, ErasureObligationSetV1,
    ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1,
    ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1,
    ErasureStateTransitionV1, ErasureStateV1, StoredErasureManifestV1,
    ERASURE_ATTEMPT_OUTCOME_TAG_V1,
};

use coordinator_support::{
    PublicCoordinatorFault, PublicCoordinatorOperation, PublicCoordinatorPort,
    PublicCoordinatorPortConfig,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target(seed: u8) -> ErasureRequiredTargetV1 {
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

fn reject_each_top_level_field<T>(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let Value::Array(fields) = decode_value(bytes)? else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    for index in 0..fields.len() {
        let malformed = replace_path(bytes, &[index], Value::Bool(true))?;
        assert!(
            decode(&malformed).is_err(),
            "field {index} accepted a boolean"
        );
    }
    Ok(())
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

fn atomic_freeze_input(
    mut targets: Vec<ErasureRequiredTargetV1>,
    mut obligations: Vec<ErasureObligationV1>,
    applicability_matrix: Vec<ErasureFreezeApplicabilityRowV1>,
) -> Result<ErasureAtomicFreezeAdmissionInputV1, ErasureErrorV1> {
    let request = reference(1);
    targets.sort_unstable();
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
        target_closure: target_closure_digest(&targets),
        lineage_rule: Some(reference(3)),
    };
    let evidence_input = ErasureFreezeAdmissionEvidenceInputV1 {
        request,
        scope_commitment: ErasureScopeCommitmentV1::new(scope.clone())?.reference(),
        obligation_set: obligation_set.reference(),
        applicability_matrix,
        freeze_position: 40,
        policy: reference(4),
        trust: reference(5),
        authorization_provenance: reference(6),
    };
    let provisional = ErasureFreezeAdmissionEvidenceV1::new(evidence_input.clone())?;
    let freeze_authorization_evidence =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: reference(4),
            trust: reference(5),
            evidence: vec![9, 8, 7],
        })?;
    let freeze_admission_evidence =
        ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
            authorization_provenance: freeze_authorization_evidence.reference(),
            ..evidence_input
        })?;
    Ok(ErasureAtomicFreezeAdmissionInputV1 {
        targets,
        scope,
        obligations,
        obligation_set,
        freeze_position: 40,
        freeze_admission_evidence,
        freeze_authorization_evidence,
    })
}

fn assert_atomic_freeze_rejected(
    input: ErasureAtomicFreezeAdmissionInputV1,
    expected: ErasureErrorV1,
) {
    assert_eq!(ErasureAtomicFreezeAdmissionV1::new(input), Err(expected));
}

fn atomic_freeze_fixture() -> Result<
    (
        ErasureRequiredTargetV1,
        ErasureObligationV1,
        Vec<ErasureFreezeApplicabilityRowV1>,
    ),
    ErasureErrorV1,
> {
    let frozen_target = target(11);
    Ok((
        frozen_target,
        obligation(
            reference(1),
            ErasureInventoryCategoryV1::Artifact,
            frozen_target,
        )?,
        applicability_matrix(
            1,
            Some((
                ErasureInventoryCategoryV1::Artifact,
                0,
                frozen_target.replica_id,
            )),
        )?,
    ))
}

const fn inventory(
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
        .zip(100_u8..)
        .map(
            |((entry, obligation), evidence_seed)| pos_core::ErasureAcknowledgementV1 {
                obligation: obligation.reference(),
                target: entry.target,
                owner: entry.transition.owner,
                evidence: reference(evidence_seed),
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

const COORDINATOR: ErasureReferenceV1 = reference(200);

fn coordinator_request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    request(ErasureScopeV1::PrivateSubjectData, vec![reference(20)])
}

fn corrected_request(provenance: ErasureReferenceV1) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(50),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(20)],
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 11,
        horizon_position: 20,
        provenance,
    })
}

fn correction_for(
    rejected_request: ErasureReferenceV1,
    rejected_terminal_state: ErasureReferenceV1,
    correction_reason: ErasureReferenceV1,
) -> Result<ErasureCorrectionProvenanceV1, ErasureErrorV1> {
    ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request,
        rejected_terminal_state,
        correction_reason,
        authorization_provenance: reference(23),
    })
}

fn coordinator_port(
    targets: Vec<ErasureRequiredTargetV1>,
    lineage_rule: Option<ErasureReferenceV1>,
) -> PublicCoordinatorPort {
    PublicCoordinatorPort::new(PublicCoordinatorPortConfig {
        targets,
        fail_commits: false,
        policy: reference(5),
        trust: reference(6),
        scope_member: reference(7),
        freeze_evidence: reference(8),
        lineage_rule,
        freeze_rejection: None,
        operation_fault: None,
    })
}

const fn coordinator_freeze_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(9),
    }
}

fn coordinator_admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    attempt_ordinal: u64,
    source_receipt: Option<ErasureReferenceV1>,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = obligation(request, ErasureInventoryCategoryV1::Artifact, target)?;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal,
        source_receipt,
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: reference(5),
        trust: reference(6),
        admitted_position: 11 + attempt_ordinal,
        deadline_position: 20 + attempt_ordinal,
        authorization_provenance: reference(10),
    })
}

fn coordinator_acknowledgement(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    evidence: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> Result<pos_core::ErasureAcknowledgementV1, ErasureErrorV1> {
    let obligation = obligation(request, ErasureInventoryCategoryV1::Artifact, target)?;
    Ok(pos_core::ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target,
        owner: target.replica_id,
        evidence,
        outcome,
    })
}

fn coordinator_receipt_input(
    target: ErasureRequiredTargetV1,
    issue_position: u64,
) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request: reference(0),
        terminal_state: reference(0),
        coordinator: reference(0),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: vec![target],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory(
                ErasureInventoryCategoryV1::Artifact,
                target,
                ErasureReplayClaimV1::StructuralOnly,
                150,
            )],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(0),
        trust: reference(0),
        provenance: reference(0),
        issue_position,
        signature: reference(151),
        receipt_digest: reference(0),
    }
}

fn coordinator_scope(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    lineage_rule: ErasureReferenceV1,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(7)],
        target_closure: target_closure_digest(&[target]),
        lineage_rule: Some(lineage_rule),
    })
}

fn coordinator_extension(
    request: ErasureReferenceV1,
    scope: &ErasureScopeCommitmentV1,
    lineage_rule: ErasureReferenceV1,
    predecessor_extension: Option<ErasureReferenceV1>,
) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request,
        scope_commitment: scope.reference(),
        fork: reference(160),
        lineage_rule,
        predecessor_extension,
        admission_provenance: reference(161),
    })
}

#[derive(Clone)]
enum ResolverReply {
    Missing,
    Error(ErasureErrorV1),
    State(Box<ErasureStateV1>),
}

impl ErasureStateResolverV1 for ResolverReply {
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

fn reject_invalid_acknowledgements(
    api: &mut dyn ErasureCoordinator,
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<(), ErasureErrorV1> {
    let foreign_target = crate::target(11);
    assert_eq!(
        api.acknowledge(
            request,
            coordinator_acknowledgement(
                request,
                foreign_target,
                reference(30),
                ErasureAcknowledgementOutcomeV1::Acknowledged,
            )?,
        ),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut unknown_obligation = coordinator_acknowledgement(
        request,
        target,
        reference(31),
        ErasureAcknowledgementOutcomeV1::Acknowledged,
    )?;
    unknown_obligation.obligation = reference(202);
    assert_eq!(
        api.acknowledge(request, unknown_obligation),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut wrong_owner = coordinator_acknowledgement(
        request,
        target,
        reference(32),
        ErasureAcknowledgementOutcomeV1::Acknowledged,
    )?;
    wrong_owner.owner = reference(203);
    assert_eq!(
        api.acknowledge(request, wrong_owner),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

fn verify_rejection_path(request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
    let port = coordinator_port(Vec::new(), None);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    let api: &mut dyn ErasureCoordinator = &mut coordinator;
    api.submit(request.clone())?;
    let rejected = api.reject(request.reference(), reference(35))?;
    assert_eq!(rejected.lifecycle(), ErasureLifecycleV1::Rejected);
    assert_eq!(api.reject(request.reference(), reference(35))?, rejected);
    assert_eq!(
        api.reject(request.reference(), reference(36)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        api.authorize(request.reference(), reference(37)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn verify_administrative_resolution(
    api: &mut dyn ErasureCoordinator,
    request: ErasureReferenceV1,
    terminal_state: ErasureReferenceV1,
    scope: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request,
            affected_digests: vec![terminal_state],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: scope,
            policy: reference(5),
            trust: reference(6),
            principal: reference(173),
            authorization_provenance: reference(174),
            reason: reference(175),
            issue_position: 31,
            predecessor_resolution: None,
        })?;
    let state = api.resolve_administratively(request, resolution.clone())?;
    assert_eq!(api.resolve_administratively(request, resolution)?, state);
    let wrong_resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request,
            affected_digests: vec![terminal_state],
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: scope,
            policy: reference(176),
            trust: reference(6),
            principal: reference(173),
            authorization_provenance: reference(174),
            reason: reference(177),
            issue_position: 32,
            predecessor_resolution: None,
        })?;
    assert_eq!(
        api.resolve_administratively(request, wrong_resolution),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn submit_authorize_and_freeze(
    api: &mut dyn ErasureCoordinator,
    request: &ErasureRequestV1,
) -> Result<(), ErasureErrorV1> {
    let submitted = api.submit(request.clone())?;
    assert_eq!(submitted.lifecycle(), ErasureLifecycleV1::Submitted);
    assert_eq!(api.submit(request.clone())?, submitted);
    assert_eq!(
        api.freeze_access(request.reference(), coordinator_freeze_transition()),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        api.acknowledge(
            request.reference(),
            coordinator_acknowledgement(
                request.reference(),
                target(10),
                reference(98),
                ErasureAcknowledgementOutcomeV1::Acknowledged,
            )?,
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let conflicting_request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: request.reference(),
        subject: reference(99),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(20)],
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 10,
        horizon_position: 20,
        provenance: reference(6),
    })?;
    assert_eq!(
        api.submit(conflicting_request),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let authorized = api.authorize(request.reference(), reference(21))?;
    assert_eq!(authorized.lifecycle(), ErasureLifecycleV1::Authorized);
    assert_eq!(
        api.authorize(request.reference(), reference(21))?,
        authorized
    );
    assert_eq!(
        api.authorize(request.reference(), reference(22)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        api.reject(request.reference(), reference(23)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        api.dispatch_destruction(
            request.reference(),
            coordinator_admission(request.reference(), target(10), 0, None)?,
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let freeze_transition = coordinator_freeze_transition();
    let frozen = api.freeze_access(request.reference(), freeze_transition.clone())?;
    assert_eq!(frozen.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(
        api.freeze_access(request.reference(), freeze_transition)?,
        frozen
    );
    assert_eq!(
        api.freeze_access(
            request.reference(),
            ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::Authorized,
                ..coordinator_freeze_transition()
            },
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

struct CompletedGraph {
    adapter: PublicCoordinatorPort,
    request: ErasureRequestV1,
    admission: ErasureRetryAdmissionV1,
    receipt: ErasureReceiptV1,
    acknowledgement: ErasureReferenceV1,
}

struct ActiveGraph {
    adapter: PublicCoordinatorPort,
    request: ErasureRequestV1,
    admission: ErasureRetryAdmissionV1,
}

fn active_persisted_graph() -> Result<ActiveGraph, ErasureErrorV1> {
    let target = target(10);
    let request = coordinator_request()?;
    let port = coordinator_port(vec![target], None);
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    submit_authorize_and_freeze(&mut coordinator, &request)?;
    let admission = coordinator_admission(request.reference(), target, 0, None)?;
    coordinator.dispatch_attempt(request.reference(), &admission)?;
    Ok(ActiveGraph {
        adapter,
        request,
        admission,
    })
}

fn complete_persisted_graph(
    lineage_rule: Option<ErasureReferenceV1>,
) -> Result<CompletedGraph, ErasureErrorV1> {
    let target = target(10);
    let request = coordinator_request()?;
    let port = coordinator_port(vec![target], lineage_rule);
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    submit_authorize_and_freeze(&mut coordinator, &request)?;
    let admission = coordinator_admission(request.reference(), target, 0, None)?;
    coordinator.dispatch_attempt(request.reference(), &admission)?;
    coordinator.acknowledge(
        request.reference(),
        coordinator_acknowledgement(
            request.reference(),
            target,
            reference(33),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )?,
    )?;
    let acknowledgement = match adapter
        .last_mutation()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .effect()
    {
        ErasureCasEffectV1::AcknowledgementAdmission { acknowledgement } => *acknowledgement,
        _ => return Err(ErasureErrorV1::ProvenanceMissing),
    };
    let receipt =
        coordinator.finalize(request.reference(), coordinator_receipt_input(target, 30))?;
    Ok(CompletedGraph {
        adapter,
        request,
        admission,
        receipt,
        acknowledgement,
    })
}

fn assert_public_recovery_fails(adapter: PublicCoordinatorPort, request: &ErasureRequestV1) {
    assert!(ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
        .submit(request.clone(), request.provenance())
        .is_err());
}

fn assert_graph_mutation_rejected(
    mutate: impl FnOnce(&CompletedGraph) -> Result<(), ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let graph = complete_persisted_graph(None)?;
    mutate(&graph)?;
    assert_public_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

fn assert_active_graph_mutation_rejected(
    mutate: impl FnOnce(&ActiveGraph) -> Result<(), ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let graph = active_persisted_graph()?;
    mutate(&graph)?;
    assert_public_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

fn assert_scope_graph_mutation_rejected(
    mutate: impl FnOnce(&CompletedGraph) -> Result<(), ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let lineage_rule = reference(170);
    let graph = complete_persisted_graph(Some(lineage_rule))?;
    let scope = coordinator_scope(graph.request.reference(), target(10), lineage_rule)?;
    let extension = coordinator_extension(graph.request.reference(), &scope, lineage_rule, None)?;
    ErasureCoordinatorStateMachineV1::new(graph.adapter.clone(), COORDINATOR)
        .append_scope_extension(graph.request.reference(), extension)?;
    mutate(&graph)?;
    assert_public_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

fn assert_resolution_graph_mutation_rejected(
    mutate: impl FnOnce(&CompletedGraph) -> Result<(), ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let lineage_rule = reference(170);
    let graph = complete_persisted_graph(Some(lineage_rule))?;
    let scope = coordinator_scope(graph.request.reference(), target(10), lineage_rule)?;
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: graph.request.reference(),
            affected_digests: vec![graph.receipt.terminal_state()],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: scope.reference(),
            policy: reference(5),
            trust: reference(6),
            principal: reference(173),
            authorization_provenance: reference(174),
            reason: reference(175),
            issue_position: 31,
            predecessor_resolution: None,
        })?;
    ErasureCoordinatorStateMachineV1::new(graph.adapter.clone(), COORDINATOR)
        .resolve_administratively(graph.request.reference(), &resolution)?;
    mutate(&graph)?;
    assert_public_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

fn assert_manifest_object_rejected(
    field: usize,
    reference: ErasureReferenceV1,
    canonical_cbor: Vec<u8>,
) -> Result<(), ErasureErrorV1> {
    assert_graph_mutation_rejected(|graph| {
        graph.adapter.insert_object(reference, canonical_cbor);
        graph.adapter.replace_manifest_field(
            graph.request.reference(),
            field,
            Value::Bytes(reference.digest().to_vec()),
        )
    })
}

fn assert_manifest_object_field_rejected(
    manifest_field: usize,
    object_tag: &str,
    object_field: usize,
    replacement: Value,
) -> Result<(), ErasureErrorV1> {
    assert_graph_mutation_rejected(|graph| {
        graph.adapter.replace_manifest_object_field(
            graph.request.reference(),
            manifest_field,
            object_tag,
            object_field,
            replacement,
        )
    })
}

fn assert_fault_occurrences_rejected(
    operation: PublicCoordinatorOperation,
) -> Result<(), ErasureErrorV1> {
    let probe = complete_persisted_graph(None)?;
    let adapter = probe.adapter.with_operation_fault(PublicCoordinatorFault {
        operation,
        occurrence: u64::MAX,
    });
    let observer = adapter.clone();
    ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
        .submit(probe.request.clone(), probe.request.provenance())?;
    let occurrences = observer.operation_fault_hits();
    assert!(occurrences > 0, "operation {operation:?} was not exercised");

    for occurrence in 0..occurrences {
        let graph = complete_persisted_graph(None)?;
        let adapter = graph.adapter.with_operation_fault(PublicCoordinatorFault {
            operation,
            occurrence,
        });
        assert_eq!(
            ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
                .submit(graph.request.clone(), graph.request.provenance()),
            Err(ErasureErrorV1::TrustSnapshotInvalid),
            "operation {operation:?} occurrence {occurrence} did not propagate"
        );
    }
    Ok(())
}

fn exercise_coordinator_dependencies(port: PublicCoordinatorPort) -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let request = coordinator_request()?;
    let lineage_rule = reference(170);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    let api: &mut dyn ErasureCoordinator = &mut coordinator;
    submit_authorize_and_freeze(api, &request)?;
    api.dispatch_destruction(
        request.reference(),
        coordinator_admission(request.reference(), target, 0, None)?,
    )?;
    api.acknowledge(
        request.reference(),
        coordinator_acknowledgement(
            request.reference(),
            target,
            reference(33),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )?,
    )?;
    let receipt = api.finalize(request.reference(), coordinator_receipt_input(target, 30))?;
    let scope = coordinator_scope(request.reference(), target, lineage_rule)?;
    api.append_scope_extension(
        request.reference(),
        coordinator_extension(request.reference(), &scope, lineage_rule, None)?,
    )?;
    verify_administrative_resolution(
        api,
        request.reference(),
        receipt.terminal_state(),
        scope.reference(),
    )
}

fn assert_dependency_fault_occurrences_rejected(
    operation: PublicCoordinatorOperation,
) -> Result<(), ErasureErrorV1> {
    let probe = coordinator_port(vec![target(10)], Some(reference(170))).with_operation_fault(
        PublicCoordinatorFault {
            operation,
            occurrence: u64::MAX,
        },
    );
    let observer = probe.clone();
    exercise_coordinator_dependencies(probe)?;
    let occurrences = observer.operation_fault_hits();
    assert!(occurrences > 0, "operation {operation:?} was not exercised");

    for occurrence in 0..occurrences {
        let port = coordinator_port(vec![target(10)], Some(reference(170))).with_operation_fault(
            PublicCoordinatorFault {
                operation,
                occurrence,
            },
        );
        assert_eq!(
            exercise_coordinator_dependencies(port),
            Err(ErasureErrorV1::TrustSnapshotInvalid),
            "operation {operation:?} occurrence {occurrence} did not propagate"
        );
    }
    Ok(())
}

#[test]
fn coordinator_public_lifecycle_rejects_conflicts_and_retries() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let request = coordinator_request()?;
    let port = coordinator_port(vec![target], None);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    let api: &mut dyn ErasureCoordinator = &mut coordinator;

    submit_authorize_and_freeze(api, &request)?;

    let admission = coordinator_admission(request.reference(), target, 0, None)?;
    for (invalid, expected) in [
        (
            coordinator_admission(reference(201), target, 0, None)?,
            ErasureErrorV1::PolicyConflict,
        ),
        (
            coordinator_admission(request.reference(), target, 1, Some(reference(202)))?,
            ErasureErrorV1::PolicyConflict,
        ),
        (
            ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
                request: request.reference(),
                attempt_ordinal: 0,
                source_receipt: None,
                unresolved_obligations: Vec::new(),
                command_identities: Vec::new(),
                policy: reference(5),
                trust: reference(6),
                admitted_position: 11,
                deadline_position: 20,
                authorization_provenance: reference(32),
            })?,
            ErasureErrorV1::ScopeInvalid,
        ),
    ] {
        assert_eq!(
            api.dispatch_destruction(request.reference(), invalid),
            Err(expected)
        );
    }
    let invalid_admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: admission.request(),
        attempt_ordinal: admission.attempt_ordinal(),
        source_receipt: admission.source_receipt(),
        unresolved_obligations: admission.unresolved_obligations().to_vec(),
        command_identities: vec![reference(201)],
        policy: admission.policy(),
        trust: admission.trust(),
        admitted_position: admission.admitted_position(),
        deadline_position: admission.deadline_position(),
        authorization_provenance: admission.authorization_provenance(),
    })?;
    assert_eq!(
        api.dispatch_destruction(request.reference(), invalid_admission),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let awaiting = api.dispatch_destruction(request.reference(), admission.clone())?;
    assert_eq!(
        awaiting.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(
        api.dispatch_destruction(request.reference(), admission)?,
        awaiting
    );

    reject_invalid_acknowledgements(api, request.reference(), target)?;

    let acknowledgement = coordinator_acknowledgement(
        request.reference(),
        target,
        reference(33),
        ErasureAcknowledgementOutcomeV1::Acknowledged,
    )?;
    assert_eq!(
        api.acknowledge(request.reference(), acknowledgement)?,
        awaiting
    );
    assert_eq!(
        api.acknowledge(request.reference(), acknowledgement)?,
        awaiting
    );
    let conflicting_acknowledgement = coordinator_acknowledgement(
        request.reference(),
        target,
        reference(34),
        ErasureAcknowledgementOutcomeV1::Acknowledged,
    )?;
    assert_eq!(
        api.acknowledge(request.reference(), conflicting_acknowledgement),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut incomplete_inventory = coordinator_receipt_input(target, 30);
    incomplete_inventory.inventories.artifacts.clear();
    assert_eq!(
        api.finalize(request.reference(), incomplete_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let terminal_input = coordinator_receipt_input(target, 30);
    let receipt = api.finalize(request.reference(), terminal_input.clone())?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(api.finalize(request.reference(), terminal_input)?, receipt);

    verify_rejection_path(&request)
}

#[test]
fn coordinator_corrected_submission_recovers_rejected_predecessor() -> Result<(), ErasureErrorV1> {
    let original = coordinator_request()?;
    let port = coordinator_port(Vec::new(), None);
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(original.clone(), original.provenance())?;
    let rejected = coordinator.reject(original.reference(), reference(21))?;
    let correction = correction_for(original.reference(), rejected.state_digest(), reference(22))?;
    let corrected = corrected_request(correction.reference())?;
    let mut faulted = ErasureCoordinatorStateMachineV1::new(
        adapter.with_operation_fault(PublicCoordinatorFault {
            operation: PublicCoordinatorOperation::AdmitCorrectedSubmission,
            occurrence: 0,
        }),
        COORDINATOR,
    );
    assert_eq!(
        faulted.submit_corrected(corrected.clone(), correction.clone()),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    let wrong_terminal = correction_for(original.reference(), reference(99), reference(22))?;
    let wrong_terminal_request = corrected_request(wrong_terminal.reference())?;
    let api: &mut dyn ErasureCoordinator = &mut coordinator;
    assert_eq!(
        api.submit_corrected(wrong_terminal_request, wrong_terminal),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let corrected_state = api.submit_corrected(corrected.clone(), correction.clone())?;
    assert_eq!(corrected_state.lifecycle(), ErasureLifecycleV1::Submitted);
    assert_eq!(
        api.submit_corrected(corrected, correction.clone())?,
        corrected_state
    );
    let conflicting_correction =
        correction_for(original.reference(), rejected.state_digest(), reference(98))?;
    let conflicting_request = corrected_request(conflicting_correction.reference())?;
    assert_eq!(
        api.submit_corrected(conflicting_request, conflicting_correction),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let wrong_request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(51),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(20)],
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 12,
        horizon_position: 20,
        provenance: reference(52),
    })?;
    assert_eq!(
        api.submit_corrected(wrong_request, correction),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn coordinator_persists_typed_freeze_rejection_and_rejects_wrong_provenance(
) -> Result<(), ErasureErrorV1> {
    let request = coordinator_request()?;
    for (authorization, expected) in [
        (reference(21), Ok(ErasureLifecycleV1::Rejected)),
        (reference(22), Err(ErasureErrorV1::ProvenanceMissing)),
    ] {
        let port = PublicCoordinatorPort::new(PublicCoordinatorPortConfig {
            targets: Vec::new(),
            fail_commits: false,
            policy: reference(5),
            trust: reference(6),
            scope_member: reference(7),
            freeze_evidence: reference(8),
            lineage_rule: None,
            freeze_rejection: Some((ErasureErrorV1::ScopeInvalid, authorization)),
            operation_fault: None,
        });
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
        coordinator.submit(request.clone(), request.provenance())?;
        coordinator.authorize(request.reference(), reference(21))?;
        let result = coordinator
            .freeze_inventory(request.reference(), &coordinator_freeze_transition())
            .map(|state| state.lifecycle());
        assert_eq!(result, expected);
        if result.is_ok() {
            assert_eq!(
                coordinator
                    .freeze_inventory(request.reference(), &coordinator_freeze_transition())?
                    .lifecycle(),
                ErasureLifecycleV1::Rejected
            );
        }
    }
    Ok(())
}

#[test]
fn coordinator_rejects_freeze_admission_for_another_policy() -> Result<(), ErasureErrorV1> {
    let request = coordinator_request()?;
    let port = PublicCoordinatorPort::new(PublicCoordinatorPortConfig {
        targets: vec![target(10)],
        fail_commits: false,
        policy: reference(99),
        trust: reference(6),
        scope_member: reference(7),
        freeze_evidence: reference(8),
        lineage_rule: None,
        freeze_rejection: None,
        operation_fault: None,
    });
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(21))?;
    assert_eq!(
        coordinator.freeze_inventory(request.reference(), &coordinator_freeze_transition()),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_wrong_type_in_every_manifest_field() -> Result<(), ErasureErrorV1> {
    for index in 0..21 {
        let request = coordinator_request()?;
        let port = coordinator_port(Vec::new(), None);
        let adapter = port.clone();
        ErasureCoordinatorStateMachineV1::new(port, COORDINATOR)
            .submit(request.clone(), request.provenance())?;
        adapter.replace_manifest_field(request.reference(), index, Value::Bool(true))?;
        let result = ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
            .submit(request.clone(), request.provenance());
        assert!(result.is_err(), "manifest field {index} accepted a boolean");
    }
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_manifest_and_state_request_mismatches() -> Result<(), ErasureErrorV1>
{
    assert_graph_mutation_rejected(|graph| {
        graph.adapter.replace_manifest_field(
            graph.request.reference(),
            2,
            Value::Bytes(reference(240).digest().to_vec()),
        )
    })?;

    assert_graph_mutation_rejected(|graph| {
        let foreign = ErasureStateV1::submitted(reference(240), COORDINATOR, reference(241))?;
        graph
            .adapter
            .insert_state(foreign.state_digest(), foreign.to_canonical_cbor()?);
        graph.adapter.replace_manifest_field(
            graph.request.reference(),
            3,
            Value::Bytes(foreign.state_digest().digest().to_vec()),
        )
    })
}

#[test]
fn coordinator_recovery_rejects_each_unresolved_manifest_reference() -> Result<(), ErasureErrorV1> {
    let missing = Value::Bytes(reference(240).digest().to_vec());
    for index in [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 17, 18, 19, 20] {
        let request = coordinator_request()?;
        let port = coordinator_port(Vec::new(), None);
        let adapter = port.clone();
        ErasureCoordinatorStateMachineV1::new(port, COORDINATOR)
            .submit(request.clone(), request.provenance())?;
        adapter.replace_manifest_field(request.reference(), index, missing.clone())?;
        let result = ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
            .submit(request.clone(), request.provenance());
        assert!(
            result.is_err(),
            "manifest field {index} accepted a missing object"
        );
    }
    let request = coordinator_request()?;
    let port = coordinator_port(Vec::new(), None);
    let adapter = port.clone();
    ErasureCoordinatorStateMachineV1::new(port, COORDINATOR)
        .submit(request.clone(), request.provenance())?;
    adapter.replace_manifest_field(
        request.reference(),
        14,
        Value::Array(vec![
            Value::Integer(0.into()),
            missing,
            Value::Array(Vec::new()),
        ]),
    )?;
    assert!(ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
        .submit(request.clone(), request.provenance())
        .is_err());
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_missing_attempt_graph_components() -> Result<(), ErasureErrorV1> {
    let graph = complete_persisted_graph(None)?;
    graph.adapter.remove_object(graph.request.reference());
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(None)?;
    graph.adapter.remove_state(graph.receipt.terminal_state());
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(None)?;
    graph
        .adapter
        .remove_attempt_page(graph.request.reference(), 0);
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(None)?;
    let page = graph
        .adapter
        .attempt_page_ref(graph.request.reference(), 0)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    graph.adapter.remove_object(page);
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(None)?;
    graph
        .adapter
        .remove_effect_for_subject(graph.admission.reference());
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(None)?;
    graph
        .adapter
        .remove_effect_for_subject(graph.acknowledgement);
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(None)?;
    graph.adapter.remove_object(graph.receipt.receipt_digest());
    assert_public_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_active_and_completed_dispatch_mismatches(
) -> Result<(), ErasureErrorV1> {
    assert_active_graph_mutation_rejected(|graph| {
        graph.adapter.replace_manifest_field(
            graph.request.reference(),
            14,
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(graph.admission.reference().digest().to_vec()),
                Value::Array(Vec::new()),
            ]),
        )
    })?;
    assert_active_graph_mutation_rejected(|graph| {
        graph
            .adapter
            .replace_manifest_field(graph.request.reference(), 20, Value::Null)
    })?;
    assert_graph_mutation_rejected(|graph| {
        graph
            .adapter
            .replace_manifest_field(graph.request.reference(), 20, Value::Null)
    })
}

#[test]
fn coordinator_recovery_rejects_mismatched_persisted_effects() -> Result<(), ErasureErrorV1> {
    assert_active_graph_mutation_rejected(|graph| {
        graph.adapter.replace_effect_for_subject(
            graph.admission.reference(),
            &ErasureCasEffectV1::AttemptAdmission {
                reservation: ErasureAttemptQuotaReservationV1::new(
                    graph.admission.reference(),
                    reference(240),
                ),
                commands: Vec::new(),
            },
        )
    })?;
    assert_active_graph_mutation_rejected(|graph| {
        graph.adapter.replace_effect_for_subject(
            graph.admission.reference(),
            &ErasureCasEffectV1::ReceiptAdmission {
                receipt: reference(240),
            },
        )
    })?;
    assert_graph_mutation_rejected(|graph| {
        graph.adapter.replace_effect_for_subject(
            graph.acknowledgement,
            &ErasureCasEffectV1::ReceiptAdmission {
                receipt: reference(240),
            },
        )
    })
}

#[test]
fn coordinator_recovery_rejects_scope_chain_mismatches() -> Result<(), ErasureErrorV1> {
    for (field, replacement) in [
        (2, Value::Bytes(reference(240).digest().to_vec())),
        (3, Value::Bytes(reference(240).digest().to_vec())),
        (4, Value::Bytes(reference(240).digest().to_vec())),
        (5, Value::Integer(1.into())),
        (6, Value::Bytes(reference(240).digest().to_vec())),
    ] {
        assert_scope_graph_mutation_rejected(|graph| {
            graph
                .adapter
                .replace_scope_node_field(graph.request.reference(), 0, field, replacement)
        })?;
    }
    for (field, replacement) in [
        (2, Value::Bytes(reference(240).digest().to_vec())),
        (3, Value::Bytes(reference(240).digest().to_vec())),
        (6, Value::Bytes(reference(240).digest().to_vec())),
    ] {
        assert_scope_graph_mutation_rejected(|graph| {
            graph.adapter.replace_scope_extension_field(
                graph.request.reference(),
                0,
                field,
                replacement,
            )
        })?;
    }
    assert_scope_graph_mutation_rejected(|graph| {
        graph.adapter.replace_manifest_field(
            graph.request.reference(),
            13,
            Value::Bytes(reference(240).digest().to_vec()),
        )
    })
}

#[test]
fn coordinator_recovery_rejects_resolution_chain_mismatches() -> Result<(), ErasureErrorV1> {
    for (field, replacement) in [
        (2, Value::Bytes(reference(240).digest().to_vec())),
        (12, Value::Bytes(reference(240).digest().to_vec())),
    ] {
        assert_resolution_graph_mutation_rejected(|graph| {
            graph
                .adapter
                .replace_resolution_field(graph.request.reference(), 0, field, replacement)
        })?;
    }
    assert_resolution_graph_mutation_rejected(|graph| {
        graph.adapter.replace_manifest_field(
            graph.request.reference(),
            18,
            Value::Bytes(reference(240).digest().to_vec()),
        )
    })
}

#[test]
fn coordinator_recovery_rejects_readdressed_attempt_page_conflicts() -> Result<(), ErasureErrorV1> {
    assert_graph_mutation_rejected(|graph| {
        graph.adapter.replace_attempt_page_field(
            graph.request.reference(),
            0,
            2,
            Value::Bytes(reference(240).digest().to_vec()),
        )
    })
}

#[test]
fn coordinator_recovery_rejects_readdressed_inventory_conflicts() -> Result<(), ErasureErrorV1> {
    for (page_field, object_field, replacement) in [
        (5, 2, Value::Bytes(reference(240).digest().to_vec())),
        (6, 5, Value::Array(Vec::new())),
    ] {
        assert_graph_mutation_rejected(|graph| {
            graph.adapter.replace_attempt_component_field(
                graph.request.reference(),
                0,
                page_field,
                ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1,
                object_field,
                replacement,
            )
        })?;
    }
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_readdressed_fixed_evidence_conflicts() -> Result<(), ErasureErrorV1>
{
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(227),
        error: ErasureErrorV1::AccessFreezeFailed,
        authorization_provenance: reference(228),
        evidence: reference(229),
    })?;
    assert_manifest_object_rejected(11, failure.reference(), failure.to_canonical_cbor()?)?;

    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: reference(230),
        obligations: vec![reference(231)],
        policy: reference(5),
        trust: reference(6),
    })?;
    assert_manifest_object_rejected(
        12,
        obligation_set.reference(),
        obligation_set.to_canonical_cbor()?,
    )
}

#[test]
fn coordinator_recovery_rejects_cross_object_freeze_bindings() -> Result<(), ErasureErrorV1> {
    let wrong_reference = Value::Bytes(reference(250).digest().to_vec());
    for (manifest_field, object_tag, object_field) in [
        (4, ERASURE_TARGET_CLOSURE_TAG_V1, 2),
        (7, ERASURE_SCOPE_COMMITMENT_TAG_V1, 4),
        (10, ERASURE_FREEZE_PROVENANCE_TAG_V1, 3),
    ] {
        assert_manifest_object_field_rejected(
            manifest_field,
            object_tag,
            object_field,
            wrong_reference.clone(),
        )?;
    }
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_each_incomplete_freeze_graph() -> Result<(), ErasureErrorV1> {
    for manifest_field in [7, 9] {
        assert_graph_mutation_rejected(|graph| {
            graph.adapter.replace_manifest_field(
                graph.request.reference(),
                manifest_field,
                Value::Null,
            )
        })?;
    }
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_readdressed_outcome_conflicts() -> Result<(), ErasureErrorV1> {
    assert_graph_mutation_rejected(|graph| {
        graph.adapter.replace_attempt_component_field(
            graph.request.reference(),
            0,
            7,
            ERASURE_ATTEMPT_OUTCOME_TAG_V1,
            2,
            Value::Bytes(reference(210).digest().to_vec()),
        )
    })
}

#[test]
fn coordinator_recovery_propagates_every_observed_persistence_fault() -> Result<(), ErasureErrorV1>
{
    for operation in [
        PublicCoordinatorOperation::LoadManifest,
        PublicCoordinatorOperation::ReadObject,
        PublicCoordinatorOperation::ResolveState,
        PublicCoordinatorOperation::EffectManifest,
        PublicCoordinatorOperation::ReadEffect,
        PublicCoordinatorOperation::AttemptIndexCount,
        PublicCoordinatorOperation::AttemptPageRef,
        PublicCoordinatorOperation::ScopeIndexCount,
        PublicCoordinatorOperation::ResolutionIndexCount,
    ] {
        assert_fault_occurrences_rejected(operation)?;
    }
    Ok(())
}

#[test]
fn coordinator_propagates_every_host_dependency_fault() -> Result<(), ErasureErrorV1> {
    for operation in [
        PublicCoordinatorOperation::CompareAndSwap,
        PublicCoordinatorOperation::ValidateFreezeAuthorization,
        PublicCoordinatorOperation::AdmitAuthorization,
        PublicCoordinatorOperation::AdmitAtomicFreeze,
        PublicCoordinatorOperation::AdmitAttempt,
        PublicCoordinatorOperation::AdmitAcknowledgement,
        PublicCoordinatorOperation::AdmitReceipt,
        PublicCoordinatorOperation::AdmitScopeExtension,
        PublicCoordinatorOperation::AdmitAdministrativeResolution,
    ] {
        assert_dependency_fault_occurrences_rejected(operation)?;
    }
    Ok(())
}

#[test]
fn coordinator_propagates_rejection_admission_failure() -> Result<(), ErasureErrorV1> {
    let request = coordinator_request()?;
    let port = coordinator_port(Vec::new(), None).with_operation_fault(PublicCoordinatorFault {
        operation: PublicCoordinatorOperation::AdmitAuthorization,
        occurrence: 0,
    });
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;
    assert_eq!(
        coordinator.reject(request.reference(), reference(21)),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    Ok(())
}

#[test]
fn coordinator_recovery_rejects_missing_scope_and_resolution_indexes() -> Result<(), ErasureErrorV1>
{
    let lineage_rule = reference(170);
    let graph = complete_persisted_graph(Some(lineage_rule))?;
    let target = target(10);
    let scope = coordinator_scope(graph.request.reference(), target, lineage_rule)?;
    let extension = coordinator_extension(graph.request.reference(), &scope, lineage_rule, None)?;
    ErasureCoordinatorStateMachineV1::new(graph.adapter.clone(), COORDINATOR)
        .append_scope_extension(graph.request.reference(), extension)?;
    graph
        .adapter
        .remove_scope_node(graph.request.reference(), 0);
    assert_public_recovery_fails(graph.adapter, &graph.request);

    let graph = complete_persisted_graph(Some(lineage_rule))?;
    let scope = coordinator_scope(graph.request.reference(), target, lineage_rule)?;
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: graph.request.reference(),
            affected_digests: vec![graph.receipt.terminal_state()],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: scope.reference(),
            policy: reference(5),
            trust: reference(6),
            principal: reference(173),
            authorization_provenance: reference(174),
            reason: reference(175),
            issue_position: 31,
            predecessor_resolution: None,
        })?;
    ErasureCoordinatorStateMachineV1::new(graph.adapter.clone(), COORDINATOR)
        .resolve_administratively(graph.request.reference(), &resolution)?;
    graph
        .adapter
        .remove_resolution(graph.request.reference(), 0);
    assert_public_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

#[test]
fn coordinator_public_partial_retry_and_extension_paths_close() -> Result<(), ErasureErrorV1> {
    let target = target(12);
    let request = coordinator_request()?;
    let lineage_rule = reference(170);
    let port = coordinator_port(vec![target], Some(lineage_rule));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    let api: &mut dyn ErasureCoordinator = &mut coordinator;

    api.submit(request.clone())?;
    api.authorize(request.reference(), reference(21))?;
    api.freeze_access(request.reference(), coordinator_freeze_transition())?;
    let first_admission = coordinator_admission(request.reference(), target, 0, None)?;
    api.dispatch_destruction(request.reference(), first_admission)?;
    api.acknowledge(
        request.reference(),
        coordinator_acknowledgement(
            request.reference(),
            target,
            reference(171),
            ErasureAcknowledgementOutcomeV1::Negative,
        )?,
    )?;
    assert_eq!(
        api.finalize(request.reference(), coordinator_receipt_input(target, 19)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let partial = api.finalize(request.reference(), coordinator_receipt_input(target, 20))?;
    assert_eq!(partial.lifecycle(), ErasureLifecycleV1::PartialFailure);

    let retry = coordinator_admission(
        request.reference(),
        target,
        1,
        Some(partial.receipt_digest()),
    )?;
    let retry_state = api.dispatch_destruction(request.reference(), retry)?;
    assert_eq!(retry_state.lifecycle(), ErasureLifecycleV1::PartialFailure);
    api.acknowledge(
        request.reference(),
        coordinator_acknowledgement(
            request.reference(),
            target,
            reference(172),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )?,
    )?;
    let complete = api.finalize(request.reference(), coordinator_receipt_input(target, 30))?;
    assert_eq!(complete.lifecycle(), ErasureLifecycleV1::Complete);

    let scope = coordinator_scope(request.reference(), target, lineage_rule)?;
    let extension = coordinator_extension(request.reference(), &scope, lineage_rule, None)?;
    let extension_state = api.append_scope_extension(request.reference(), extension)?;
    assert_eq!(
        api.append_scope_extension(request.reference(), extension)?,
        extension_state
    );
    let wrong_extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(204),
        scope_commitment: scope.reference(),
        fork: reference(160),
        lineage_rule,
        predecessor_extension: None,
        admission_provenance: reference(161),
    })?;
    assert_eq!(
        api.append_scope_extension(request.reference(), wrong_extension),
        Err(ErasureErrorV1::PolicyConflict)
    );

    verify_administrative_resolution(
        api,
        request.reference(),
        complete.terminal_state(),
        scope.reference(),
    )
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
            std::hint::black_box(lifecycle.permits(next));
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
    assert_eq!(unsorted_closure, target_closure_digest(&targets));
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
    Ok(())
}

#[test]
fn freeze_evidence_records_cover_bindings_and_round_trips() -> Result<(), ErasureErrorV1> {
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
    Ok(())
}

#[test]
fn freeze_failure_and_rejection_records_cover_closed_errors() -> Result<(), ErasureErrorV1> {
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
        assert_eq!(failure.request(), reference(1));
        assert_eq!(failure.error(), error);
        assert_eq!(failure.authorization_provenance(), reference(2));
        assert_eq!(failure.evidence(), reference(3));
        assert_ne!(failure.reference(), reference(0));
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
    Ok(())
}

#[test]
fn retry_and_acknowledgement_records_cover_public_forms() -> Result<(), ErasureErrorV1> {
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
    assert_eq!(retry.request(), reference(1));
    assert_eq!(retry.attempt_ordinal(), 2);
    assert_eq!(retry.source_receipt(), Some(reference(50)));
    assert_eq!(
        retry.unresolved_obligations(),
        &[reference(20), reference(30)]
    );
    assert_eq!(retry.command_identities(), &[reference(21), reference(31)]);
    assert_eq!(retry.admitted_position(), 41);
    assert_eq!(retry.deadline_position(), 49);
    assert_eq!(retry.policy(), reference(4));
    assert_eq!(retry.trust(), reference(5));
    assert_eq!(retry.authorization_provenance(), reference(6));
    assert_eq!(retry.digest(), retry.reference());
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
        assert_eq!(provenance.request(), reference(1));
        assert_eq!(provenance.command(), reference(2));
        assert_eq!(provenance.attempt(), reference(3));
        assert_eq!(provenance.obligation(), reference(4));
        assert_eq!(provenance.owner(), reference(5));
        assert_eq!(provenance.scope(), reference(6));
        assert_eq!(provenance.outcome(), outcome);
        assert_eq!(provenance.evidence(), reference(7));
        assert_eq!(provenance.policy(), reference(8));
        assert_eq!(provenance.trust(), reference(9));
        assert_eq!(provenance.digest(), provenance.reference());
        assert_eq!(
            ErasureAcknowledgementProvenanceV1::from_canonical_cbor(
                &provenance.to_canonical_cbor()?
            )?,
            provenance
        );
    }
    Ok(())
}

#[test]
fn attempt_and_receipt_provenance_cover_retry_lineage() -> Result<(), ErasureErrorV1> {
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
    assert_eq!(attempt_outcome.request(), reference(1));
    assert_eq!(attempt_outcome.attempt(), reference(2));
    assert_eq!(attempt_outcome.source_receipt(), Some(reference(3)));
    assert_eq!(attempt_outcome.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(attempt_outcome.selected_obligations(), reference(4));
    assert_eq!(attempt_outcome.acknowledgement_inventory(), reference(5));
    assert_eq!(attempt_outcome.terminal_position(), 50);
    assert_eq!(attempt_outcome.policy(), reference(6));
    assert_eq!(attempt_outcome.trust(), reference(7));
    assert_eq!(attempt_outcome.digest(), attempt_outcome.reference());
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
    assert_eq!(receipt_provenance.request(), reference(1));
    assert_eq!(receipt_provenance.attempt(), reference(2));
    assert_eq!(receipt_provenance.attempt_ordinal(), 1);
    assert_eq!(receipt_provenance.predecessor_receipt(), Some(reference(3)));
    assert_eq!(receipt_provenance.terminal_state(), reference(4));
    assert_eq!(receipt_provenance.evidence_set(), reference(5));
    assert_eq!(receipt_provenance.policy(), reference(6));
    assert_eq!(receipt_provenance.trust(), reference(7));
    assert_eq!(receipt_provenance.issue_position(), 50);
    assert_eq!(receipt_provenance.digest(), receipt_provenance.reference());
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
    Ok(())
}

#[test]
fn administrative_resolution_normalizes_and_rejects_duplicates() -> Result<(), ErasureErrorV1> {
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
    assert_eq!(resolution.request(), reference(1));
    assert_eq!(
        resolution.affected_digests(),
        &[reference(20), reference(30)]
    );
    assert_eq!(
        resolution.action(),
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence
    );
    assert_eq!(resolution.scope_commitment(), reference(4));
    assert_eq!(resolution.policy(), reference(5));
    assert_eq!(resolution.trust(), reference(6));
    assert_eq!(resolution.principal(), reference(7));
    assert_eq!(resolution.authorization_provenance(), reference(8));
    assert_eq!(resolution.reason(), reference(9));
    assert_eq!(resolution.issue_position(), 50);
    assert_eq!(resolution.predecessor_resolution(), Some(reference(10)));
    assert_eq!(resolution.digest(), resolution.reference());
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
fn public_constructors_reject_each_bounded_collection_violation() {
    assert_eq!(
        request(
            ErasureScopeV1::PrivateSubjectData,
            vec![reference(20); 10_000]
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: reference(1),
            affected_digests: Vec::new(),
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: reference(2),
            policy: reference(3),
            trust: reference(4),
            principal: reference(5),
            authorization_provenance: reference(6),
            reason: reference(7),
            issue_position: 8,
            predecessor_resolution: None,
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    for (obligations, commands, admitted, deadline, expected) in [
        (
            vec![reference(10)],
            Vec::new(),
            1,
            2,
            ErasureErrorV1::ScopeInvalid,
        ),
        (
            vec![reference(10), reference(10)],
            vec![reference(11), reference(12)],
            1,
            2,
            ErasureErrorV1::ScopeInvalid,
        ),
        (
            vec![reference(10)],
            vec![reference(11)],
            2,
            1,
            ErasureErrorV1::PolicyConflict,
        ),
    ] {
        assert_eq!(
            ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
                request: reference(1),
                attempt_ordinal: 0,
                source_receipt: None,
                unresolved_obligations: obligations,
                command_identities: commands,
                policy: reference(2),
                trust: reference(3),
                admitted_position: admitted,
                deadline_position: deadline,
                authorization_provenance: reference(4),
            }),
            Err(expected)
        );
    }
    for obligations in [
        vec![reference(2), reference(1)],
        vec![reference(1), reference(1)],
        vec![reference(1); 10_000],
    ] {
        assert_eq!(
            ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
                request: reference(1),
                obligations,
                policy: reference(2),
                trust: reference(3),
            }),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
}

#[test]
fn atomic_freeze_admission_exposes_its_complete_public_commitments() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let frozen_target = target(11);
    let frozen_obligation =
        obligation(request, ErasureInventoryCategoryV1::Artifact, frozen_target)?;
    let matrix = applicability_matrix(
        1,
        Some((
            ErasureInventoryCategoryV1::Artifact,
            0,
            frozen_target.replica_id,
        )),
    )?;
    let input = atomic_freeze_input(vec![frozen_target], vec![frozen_obligation], matrix)?;
    let admission = ErasureAtomicFreezeAdmissionV1::new(input.clone())?;
    assert_eq!(admission.targets(), input.targets.as_slice());
    assert_eq!(admission.scope(), &input.scope);
    assert_eq!(admission.obligations(), &[frozen_obligation]);
    assert_eq!(admission.obligation_set(), &input.obligation_set);
    assert_eq!(admission.freeze_position(), 40);
    assert_eq!(
        admission.freeze_admission_evidence(),
        &input.freeze_admission_evidence
    );
    assert_eq!(
        admission.freeze_authorization_evidence(),
        &input.freeze_authorization_evidence
    );
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: Vec::new(),
            ..input
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
fn atomic_freeze_admission_rejects_inconsistent_public_commitments() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let (frozen_target, valid_obligation, applicable) = atomic_freeze_fixture()?;

    let mut mismatched_evidence = atomic_freeze_input(
        vec![frozen_target],
        vec![valid_obligation],
        applicable.clone(),
    )?;
    mismatched_evidence.freeze_position += 1;
    assert_atomic_freeze_rejected(mismatched_evidence, ErasureErrorV1::ProvenanceMissing);

    let mut mismatched_set = atomic_freeze_input(
        vec![frozen_target],
        vec![valid_obligation],
        applicable.clone(),
    )?;
    mismatched_set.obligations[0] = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: frozen_target,
        owner: reference(44),
        command_identity: destruction_command_reference(request, frozen_target),
    })?;
    assert_atomic_freeze_rejected(mismatched_set, ErasureErrorV1::ScopeInvalid);

    let outside_target = target(12);
    let outside_obligation = obligation(
        request,
        ErasureInventoryCategoryV1::Artifact,
        outside_target,
    )?;
    assert_atomic_freeze_rejected(
        atomic_freeze_input(
            vec![frozen_target],
            vec![outside_obligation],
            applicability_matrix(
                1,
                Some((
                    ErasureInventoryCategoryV1::Artifact,
                    0,
                    outside_target.replica_id,
                )),
            )?,
        )?,
        ErasureErrorV1::ScopeInvalid,
    );

    let wrong_command = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: frozen_target,
        owner: frozen_target.replica_id,
        command_identity: reference(88),
    })?;
    assert_atomic_freeze_rejected(
        atomic_freeze_input(vec![frozen_target], vec![wrong_command], applicable.clone())?,
        ErasureErrorV1::ScopeInvalid,
    );

    let duplicate_target = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: frozen_target,
        owner: reference(45),
        command_identity: destruction_command_reference(request, frozen_target),
    })?;
    assert_atomic_freeze_rejected(
        atomic_freeze_input(
            vec![frozen_target],
            vec![valid_obligation, duplicate_target],
            applicable,
        )?,
        ErasureErrorV1::ScopeInvalid,
    );
    Ok(())
}

#[test]
fn atomic_freeze_admission_rejects_duplicate_and_missing_applicability(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let (frozen_target, valid_obligation, _) = atomic_freeze_fixture()?;
    let duplicate_command_owner = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Key,
        target: frozen_target,
        owner: frozen_target.replica_id,
        command_identity: destruction_command_reference(request, frozen_target),
    })?;
    let mut two_applicable = applicability_matrix(
        1,
        Some((
            ErasureInventoryCategoryV1::Artifact,
            0,
            frozen_target.replica_id,
        )),
    )?;
    two_applicable[1] = ErasureFreezeApplicabilityRowV1::new(
        ErasureInventoryCategoryV1::Key,
        0,
        ErasureApplicabilityDecisionV1::Applicable,
        Some(frozen_target.replica_id),
    )?;
    assert_atomic_freeze_rejected(
        atomic_freeze_input(
            vec![frozen_target],
            vec![valid_obligation, duplicate_command_owner],
            two_applicable,
        )?,
        ErasureErrorV1::ScopeInvalid,
    );

    let wrong_owner_matrix = applicability_matrix(
        1,
        Some((ErasureInventoryCategoryV1::Artifact, 0, reference(99))),
    )?;
    assert_atomic_freeze_rejected(
        atomic_freeze_input(
            vec![frozen_target],
            vec![valid_obligation],
            wrong_owner_matrix,
        )?,
        ErasureErrorV1::ScopeInvalid,
    );
    assert_atomic_freeze_rejected(
        atomic_freeze_input(
            vec![frozen_target],
            vec![valid_obligation],
            applicability_matrix(1, None)?,
        )?,
        ErasureErrorV1::ScopeInvalid,
    );
    Ok(())
}

#[test]
fn receipt_covers_complete_partial_and_negative_public_closures() -> Result<(), ErasureErrorV1> {
    let (input, obligations) = complete_receipt_input()?;
    let receipt = ErasureReceiptV1::new(input)?;
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
    Ok(())
}

#[test]
fn partial_receipt_closes_pending_owner_contract() -> Result<(), ErasureErrorV1> {
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
    Ok(())
}

#[test]
fn negative_receipt_closes_failed_owner_contract() -> Result<(), ErasureErrorV1> {
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
    let (input, _) = complete_receipt_input()?;
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

    let mut resolved_partial = input;
    resolved_partial.lifecycle = ErasureLifecycleV1::PartialFailure;
    assert_eq!(
        ErasureReceiptV1::new(resolved_partial),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn receipt_rejects_inventory_and_derived_owner_gaps() -> Result<(), ErasureErrorV1> {
    let (input, _) = complete_receipt_input()?;
    let mut acknowledgement_without_inventory = input.clone();
    acknowledgement_without_inventory
        .inventories
        .artifacts
        .clear();
    assert_eq!(
        ErasureReceiptV1::new(acknowledgement_without_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut wrong_derived_owners = input.clone();
    wrong_derived_owners.pending_owners = vec![input.inventories.artifacts[0].transition.owner];
    assert_eq!(
        ErasureReceiptV1::new(wrong_derived_owners),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut inventory_outside_closure = input;
    let old_target = inventory_outside_closure.inventories.artifacts[0].target;
    let outside_target = target(250);
    inventory_outside_closure.inventories.artifacts[0].target = outside_target;
    inventory_outside_closure.inventories.artifacts[0]
        .transition
        .owner = outside_target.replica_id;
    inventory_outside_closure
        .acknowledgements
        .retain(|acknowledgement| acknowledgement.target != old_target);
    inventory_outside_closure.lifecycle = ErasureLifecycleV1::PartialFailure;
    inventory_outside_closure.pending_owners = vec![outside_target.replica_id];
    assert_eq!(
        ErasureReceiptV1::new(inventory_outside_closure),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn receipt_rejects_wrong_obligations_and_history_sources() -> Result<(), ErasureErrorV1> {
    let (input, obligations) = complete_receipt_input()?;
    let receipt = ErasureReceiptV1::new(input)?;
    assert_eq!(
        receipt.validate_frozen_obligations(&obligations[..3]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut wrong_owner = obligations;
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
    let mut changed_identity = wrong_owner;
    changed_identity[0] = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: changed_identity[0].category(),
        target: changed_identity[0].target(),
        owner: changed_identity[0].target().replica_id,
        command_identity: reference(241),
    })?;
    assert_eq!(
        receipt.validate_frozen_obligations(&changed_identity),
        Err(ErasureErrorV1::PolicyConflict)
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
        receipt.verify_history(&ResolverReply::State(Box::new(root))),
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
                assert_eq!(effect.subject(), Some(admission));
            }
            ErasureCasEffectV1::AcknowledgementAdmission { acknowledgement } => {
                assert_eq!(effect.subject(), Some(acknowledgement));
            }
            ErasureCasEffectV1::ReceiptAdmission { receipt } => {
                assert_eq!(effect.subject(), Some(receipt));
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
    Ok(())
}

#[test]
fn erasure_index_variants_expose_ordinals() {
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
}

#[test]
fn portable_decoders_reject_wrong_types_in_every_foundation_field() -> Result<(), ErasureErrorV1> {
    let request = request(ErasureScopeV1::PrivateSubjectData, vec![reference(20)])?;
    reject_each_top_level_field(&request.to_canonical_cbor()?, |bytes| {
        ErasureRequestV1::from_canonical_cbor(bytes)
    })?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: reference(2),
        correction_reason: reference(3),
        authorization_provenance: reference(4),
    })?;
    reject_each_top_level_field(&correction.to_canonical_cbor()?, |bytes| {
        ErasureCorrectionProvenanceV1::from_canonical_cbor(bytes)
    })?;
    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: reference(1),
        scope_members: vec![reference(2)],
        target_closure: reference(3),
        lineage_rule: Some(reference(4)),
    })?;
    reject_each_top_level_field(&scope.to_canonical_cbor()?, |bytes| {
        ErasureScopeCommitmentV1::from_canonical_cbor(bytes)
    })?;
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: scope.reference(),
        fork: reference(5),
        lineage_rule: reference(4),
        predecessor_extension: Some(reference(6)),
        admission_provenance: reference(7),
    })?;
    reject_each_top_level_field(&extension.to_canonical_cbor()?, |bytes| {
        ErasureScopeExtensionV1::from_canonical_cbor(bytes)
    })?;
    let obligation = obligation(
        reference(1),
        ErasureInventoryCategoryV1::Artifact,
        target(10),
    )?;
    reject_each_top_level_field(&obligation.to_canonical_cbor()?, |bytes| {
        ErasureObligationV1::from_canonical_cbor(bytes)
    })?;
    let set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: reference(1),
        obligations: vec![obligation.reference()],
        policy: reference(8),
        trust: reference(9),
    })?;
    reject_each_top_level_field(&set.to_canonical_cbor()?, |bytes| {
        ErasureObligationSetV1::from_canonical_cbor(bytes)
    })?;
    let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    reject_each_top_level_field(&state.to_canonical_cbor()?, |bytes| {
        ErasureStateV1::from_canonical_cbor(bytes)
    })
}

#[test]
fn portable_decoders_reject_wrong_types_in_every_evidence_field() -> Result<(), ErasureErrorV1> {
    let (admission, authorization) = freeze_evidence_pair()?;
    reject_each_top_level_field(&admission.to_canonical_cbor()?, |bytes| {
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(bytes)
    })?;
    reject_each_top_level_field(&authorization.to_canonical_cbor()?, |bytes| {
        ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor(bytes)
    })?;
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        obligation_set: reference(3),
        freeze_position: 4,
        host_evidence: reference(5),
    })?;
    reject_each_top_level_field(&freeze.to_canonical_cbor()?, |bytes| {
        ErasureFreezeProvenanceV1::from_canonical_cbor(bytes)
    })?;
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::ScopeInvalid,
        authorization_provenance: reference(2),
        evidence: reference(3),
    })?;
    reject_each_top_level_field(&failure.to_canonical_cbor()?, |bytes| {
        ErasureFreezeFailureV1::from_canonical_cbor(bytes)
    })?;
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: reference(1),
        authorization_provenance: reference(2),
    })?;
    reject_each_top_level_field(&rejection.to_canonical_cbor()?, |bytes| {
        ErasureAuthorizationRejectionV1::from_canonical_cbor(bytes)
    })?;
    Ok(())
}

#[test]
fn portable_decoders_reject_wrong_types_in_attempt_and_terminal_fields(
) -> Result<(), ErasureErrorV1> {
    let retry = coordinator_admission(reference(1), target(10), 1, Some(reference(2)))?;
    reject_each_top_level_field(&retry.to_canonical_cbor()?, |bytes| {
        ErasureRetryAdmissionV1::from_canonical_cbor(bytes)
    })?;
    let acknowledgement =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: reference(1),
            command: reference(2),
            attempt: retry.reference(),
            obligation: reference(3),
            owner: reference(4),
            scope: reference(5),
            outcome: ErasureAcknowledgementOutcomeV1::Stale,
            evidence: reference(6),
            policy: reference(7),
            trust: reference(8),
        })?;
    reject_each_top_level_field(&acknowledgement.to_canonical_cbor()?, |bytes| {
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor(bytes)
    })?;
    let outcome = ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: retry.reference(),
        source_receipt: Some(reference(2)),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        selected_obligations: reference(3),
        acknowledgement_inventory: reference(4),
        terminal_position: 20,
        policy: reference(5),
        trust: reference(6),
    })?;
    reject_each_top_level_field(&outcome.to_canonical_cbor()?, |bytes| {
        ErasureAttemptOutcomeV1::from_canonical_cbor(bytes)
    })?;
    let provenance = ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request: reference(1),
        attempt: retry.reference(),
        attempt_ordinal: 1,
        predecessor_receipt: Some(reference(2)),
        terminal_state: reference(3),
        evidence_set: reference(4),
        policy: reference(5),
        trust: reference(6),
        issue_position: 20,
    })?;
    reject_each_top_level_field(&provenance.to_canonical_cbor()?, |bytes| {
        ErasureReceiptProvenanceV1::from_canonical_cbor(bytes)
    })
}

#[test]
fn terminal_and_effect_decoders_reject_wrong_types_in_every_field() -> Result<(), ErasureErrorV1> {
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
            predecessor_resolution: Some(reference(9)),
        })?;
    reject_each_top_level_field(&resolution.to_canonical_cbor()?, |bytes| {
        ErasureAdministrativeResolutionV1::from_canonical_cbor(bytes)
    })?;
    let (input, _) = complete_receipt_input()?;
    let receipt = ErasureReceiptV1::new(input)?;
    reject_each_top_level_field(&receipt.to_canonical_cbor()?, |bytes| {
        ErasureReceiptV1::from_canonical_cbor(bytes)
    })?;
    let obligation = obligation(
        reference(1),
        ErasureInventoryCategoryV1::Artifact,
        target(10),
    )?;
    let effects = [
        ErasureCasEffectV1::None,
        ErasureCasEffectV1::AttemptAdmission {
            reservation: ErasureAttemptQuotaReservationV1::new(reference(10), reference(11)),
            commands: vec![ErasureDestructionCommandV1::from_obligation(
                &obligation,
                reference(12),
            )],
        },
        ErasureCasEffectV1::AcknowledgementAdmission {
            acknowledgement: reference(13),
        },
        ErasureCasEffectV1::ReceiptAdmission {
            receipt: reference(14),
        },
    ];
    for effect in effects {
        reject_each_top_level_field(&effect.to_canonical_cbor()?, |bytes| {
            ErasureCasEffectV1::from_canonical_cbor(bytes)
        })?;
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

    let mut trailing = request_bytes;
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
    Ok(())
}

#[test]
fn public_request_codec_rejects_every_bounded_cbor_shape_family() {
    let invalid_encodings: &[&[u8]] = &[
        &[0x00],
        &[0x20],
        &[0x40],
        &[0x60],
        &[0x80],
        &[0xa0],
        &[0xc0, 0x00],
        &[0xf6],
        &[0x58, 0x20],
        &[0x78, 0x20],
        &[0x98, 0xff],
        &[0x9f, 0xff],
        &[0x18],
        &[0x19, 0x01],
        &[0x1a, 0x00, 0x01, 0x00],
        &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        &[0x18, 0x00],
        &[0x19, 0x00, 0xff],
        &[0x1a, 0x00, 0x00, 0xff, 0xff],
        &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        &[0x19, 0x01, 0x00],
        &[0x1a, 0x00, 0x01, 0x00, 0x00],
        &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
    ];
    for bytes in invalid_encodings {
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(bytes),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0_u8; 2 * 1024 * 1024]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn state_and_freeze_codecs_reject_wrong_shapes() -> Result<(), ErasureErrorV1> {
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
    Ok(())
}

#[test]
fn receipt_codec_rejects_wrong_shapes_and_digest() -> Result<(), ErasureErrorV1> {
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
    Ok(())
}

#[test]
fn cas_effect_codec_rejects_wrong_shapes_and_trailing_data() -> Result<(), ErasureErrorV1> {
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
    let mut inventories = [
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
