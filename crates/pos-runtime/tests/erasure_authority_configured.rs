//! Contract tests for the host-configured erasure authority Plugin.

use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactClassV1, ErasureAuthorizationDecisionV1,
    ErasureDestructionCommandV1, ErasureForkAdmissionInputV1, ErasureFreezeAuthorizationVerifierV1,
    ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequiredTargetV1,
    ErasureRetryAdmissionInputV1, ErasureScopeExtensionInputV1, ErasureScopeExtensionV1,
    ErasureScopeV1, ErasureStateTransitionV1, Seq, TimelineId, TimelineMeta,
};
use pos_runtime::{
    ErasureAuthorityConfigurationInputV1, ErasureAuthorityConfigurationV1,
    ErasureAuthorityFreezeProfileV1, ErasureAuthorityTopologyBindingV1,
    ErasureCoordinatorAuthorityV1, HostConfiguredErasureCoordinatorAuthorityV1,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn persistence_request() -> Result<pos_core::ErasureRequestV1, pos_core::ErasureErrorV1> {
    pos_core::ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 9,
        horizon_position: 20,
        provenance: reference(7),
    })
}

const fn persistence_target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(10),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(11),
        replica_set: reference(12),
        replica_id: reference(13),
    }
}

fn authority() -> Result<HostConfiguredErasureCoordinatorAuthorityV1, Box<dyn std::error::Error>> {
    let request = reference(1);
    let target = persistence_target();
    let profile = ErasureAuthorityFreezeProfileV1::new(
        vec![reference(9)],
        vec![target],
        [reference(21), reference(22), reference(23), reference(24)],
        Some(reference(25)),
        reference(26),
    )?;
    let topology = vec![
        ErasureAuthorityTopologyBindingV1::new(request, TimelineId::new(), Some(reference(9))),
        ErasureAuthorityTopologyBindingV1::new(request, TimelineId::new(), None),
    ];
    let configuration =
        ErasureAuthorityConfigurationV1::new(ErasureAuthorityConfigurationInputV1 {
            policy: reference(6),
            trust: reference(8),
            topology,
            freeze: profile,
            principal: reference(40),
            authorization_evidence: b"host-proof".to_vec(),
            lifecycle_provenance: reference(7),
            allow_rejection: true,
        })?;
    Ok(HostConfiguredErasureCoordinatorAuthorityV1::new(
        configuration,
    )?)
}

#[test]
fn configured_authority_admits_public_lifecycle_seams() -> Result<(), Box<dyn std::error::Error>> {
    let authority = authority()?;
    let request = persistence_request()?;
    let request_reference = request.reference();
    assert!(authority
        .verified_topology_observation(request_reference, reference(50))?
        .is_some());
    assert!(authority
        .verified_topology_observation(reference(99), reference(50))?
        .is_none());
    authority.authenticate(&request)?;
    authority.admit_authorization(
        request_reference,
        reference(7),
        ErasureAuthorizationDecisionV1::Authorized,
    )?;

    let correction = pos_core::ErasureCorrectionProvenanceV1::new(
        pos_core::ErasureCorrectionProvenanceInputV1 {
            rejected_request: request_reference,
            rejected_terminal_state: reference(51),
            correction_reason: reference(52),
            authorization_provenance: reference(7),
        },
    )?;
    authority.admit_corrected_submission(&request, &correction)?;

    let transition = ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(7),
    };
    let result = authority.admit_atomic_freeze(request_reference, &transition)?;
    let admission = match result {
        pos_core::ErasureAtomicFreezeResultV1::Admitted(admission) => admission,
        pos_core::ErasureAtomicFreezeResultV1::Rejected(_) => {
            return Err("configured authority unexpectedly rejected freeze".into())
        }
    };
    authority.validate_freeze_authorization(
        admission.freeze_admission_evidence(),
        admission.freeze_authorization_evidence(),
    )?;

    let commands = admission
        .obligations()
        .iter()
        .map(|obligation| ErasureDestructionCommandV1::from_obligation(obligation, reference(7)))
        .collect::<Vec<_>>();
    authority.dispatch_destruction(request_reference, &commands)?;

    let retry = pos_core::ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: request_reference,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: admission
            .obligations()
            .iter()
            .map(pos_core::ErasureObligationV1::reference)
            .collect(),
        command_identities: admission
            .obligations()
            .iter()
            .map(pos_core::ErasureObligationV1::command_identity)
            .collect(),
        policy: reference(6),
        trust: reference(8),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(7),
    })?;
    let reservation = authority.admit_attempt(&retry)?;
    assert_eq!(reservation.admission(), retry.reference());

    let first = admission.obligations()[0];
    let acknowledgement =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: request_reference,
            command: first.command_identity(),
            attempt: retry.reference(),
            obligation: first.reference(),
            owner: first.owner(),
            scope: target_closure_digest(&[first.target()]),
            outcome: pos_core::ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(53),
            policy: reference(6),
            trust: reference(8),
        })?;
    authority.admit_acknowledgement(&acknowledgement)?;

    let receipt = ErasureReceiptInputV1 {
        request: request_reference,
        terminal_state: reference(54),
        coordinator: reference(55),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 10,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: pos_core::ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(6),
        trust: reference(8),
        provenance: reference(7),
        issue_position: 11,
        signature: reference(56),
        receipt_digest: reference(57),
    };
    authority.admit_receipt(&receipt)?;

    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: request_reference,
            affected_digests: vec![reference(58)],
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: reference(59),
            policy: reference(6),
            trust: reference(8),
            principal: reference(40),
            authorization_provenance: reference(7),
            reason: reference(60),
            issue_position: 12,
            predecessor_resolution: None,
        })?;
    authority.admit_administrative_resolution(&resolution)?;

    let parent = TimelineId::new();
    let child = TimelineMeta::forked_from(parent, Seq::ZERO, "configured-child");
    let child_scope = authority.resolve_fork_child_scope(parent, &child)?;
    assert_eq!(child_scope, reference(26));
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: request_reference,
        scope_commitment: reference(59),
        fork: child_scope,
        lineage_rule: reference(25),
        predecessor_extension: None,
        admission_provenance: reference(7),
    })?;
    authority.admit_scope_extension(&extension)?;
    authority.admit_fork_scope_extension(
        &extension,
        &ErasureForkAdmissionInputV1 {
            operation: reference(61),
            expected_inventory_generation: reference(62),
            child_scope,
            child,
        },
    )?;
    Ok(())
}
