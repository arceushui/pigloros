//! Contract tests for the host-configured erasure authority Plugin.

use std::sync::Arc;

use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureAuthorizationDecisionV1, ErasureDestructionCommandV1,
    ErasureForkAdmissionInputV1, ErasureFreezeAuthorizationVerifierV1, ErasureLifecycleV1,
    ErasureReceiptInputV1, ErasureReplayClaimV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureStateTransitionV1, Seq, TimelineId, TimelineMeta,
};
use pos_runtime::{
    ErasureAuthorityConfigurationV1, ErasureAuthorityEvidenceKindV1,
    ErasureAuthorityEvidenceVerifierV1, ErasureAuthorityFreezeProfileV1,
    ErasureAuthorityRequestBindingV1, ErasureAuthorityTopologyBindingV1,
    ErasureCoordinatorAuthorityV1, HostConfiguredErasureCoordinatorAuthorityV1,
};

#[path = "../../pos-core/tests/support/erasure.rs"]
#[expect(dead_code, unreachable_pub)]
mod erasure_support;

use erasure_support::{persistence_request, persistence_target, reference, retry_admission};

#[derive(Debug)]
struct TestEvidenceVerifier;

impl ErasureAuthorityEvidenceVerifierV1 for TestEvidenceVerifier {
    fn verify(
        &self,
        _kind: ErasureAuthorityEvidenceKindV1,
        _request: &pos_core::ErasureRequestV1,
        context: &[u8],
        evidence: &[u8],
    ) -> Result<(), pos_core::ErasureErrorV1> {
        if !context.is_empty() && evidence == b"host-proof" {
            Ok(())
        } else {
            Err(pos_core::ErasureErrorV1::Unauthorized)
        }
    }
}

fn authority() -> Result<HostConfiguredErasureCoordinatorAuthorityV1, Box<dyn std::error::Error>> {
    let request = persistence_request()?;
    let request_reference = request.reference();
    let target = persistence_target();
    let profile = ErasureAuthorityFreezeProfileV1::new(
        vec![reference(9)],
        vec![target],
        [reference(21), reference(22), reference(23), reference(24)],
        Some(reference(25)),
        reference(26),
    )?;
    let topology = vec![
        ErasureAuthorityTopologyBindingV1::new(
            request_reference,
            reference(50),
            TimelineId::new(),
            Some(reference(9)),
        ),
        ErasureAuthorityTopologyBindingV1::new(
            request_reference,
            reference(50),
            TimelineId::new(),
            None,
        ),
    ];
    let request_binding = ErasureAuthorityRequestBindingV1::new(
        request,
        topology,
        profile,
        reference(40),
        b"host-proof".to_vec(),
        reference(7),
        true,
    )?;
    let configuration =
        ErasureAuthorityConfigurationV1::new(reference(6), reference(8), vec![request_binding])?;
    Ok(HostConfiguredErasureCoordinatorAuthorityV1::new(
        configuration,
        Arc::new(TestEvidenceVerifier),
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
        .verified_topology_observation(request_reference, reference(51))?
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

    admit_destruction_and_receipt(&authority, request_reference, &admission)?;
    admit_resolution_and_fork(&authority, request_reference)?;
    Ok(())
}

fn admit_destruction_and_receipt(
    authority: &HostConfiguredErasureCoordinatorAuthorityV1,
    request_reference: pos_core::ErasureReferenceV1,
    admission: &pos_core::ErasureAtomicFreezeAdmissionV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let commands = admission
        .obligations()
        .iter()
        .map(|obligation| ErasureDestructionCommandV1::from_obligation(obligation, reference(7)))
        .collect::<Vec<_>>();
    authority.dispatch_destruction(request_reference, &commands)?;
    let retry = retry_admission(erasure_support::RetryAdmissionFixture {
        request: request_reference,
        attempt_ordinal: 0,
        source_receipt: None,
        obligations: admission.obligations(),
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
    authority.admit_receipt(&ErasureReceiptInputV1 {
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
    })?;
    Ok(())
}

fn admit_resolution_and_fork(
    authority: &HostConfiguredErasureCoordinatorAuthorityV1,
    request_reference: pos_core::ErasureReferenceV1,
) -> Result<(), Box<dyn std::error::Error>> {
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
