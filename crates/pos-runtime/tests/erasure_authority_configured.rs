//! Contract tests for the host-configured erasure authority Plugin.

use std::sync::Arc;

use ed25519_dalek::Signer;
use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureAttemptQuotaReservationV1,
    ErasureAuthorizationDecisionV1, ErasureDestructionCommandV1, ErasureForkAdmissionInputV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRetryAdmissionV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureStateTransitionV1, Seq,
    TimelineId, TimelineMeta,
};
use pos_runtime::{
    Ed25519ErasureAuthorityEvidenceVerifierV1, ErasureAuthorityConfigurationV1,
    ErasureAuthorityEvidenceKindV1, ErasureAuthorityEvidenceVerifierV1,
    ErasureAuthorityExecutionV1, ErasureAuthorityFreezeProfileV1, ErasureAuthorityRequestBindingV1,
    ErasureAuthorityTopologyBindingV1, ErasureCoordinatorAuthorityV1,
    HostConfiguredErasureCoordinatorAuthorityV1,
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

#[derive(Debug)]
struct TestExecution;

impl ErasureAuthorityExecutionV1 for TestExecution {
    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), pos_core::ErasureErrorV1> {
        (!commands.is_empty())
            .then_some(())
            .ok_or(pos_core::ErasureErrorV1::ScopeInvalid)
    }

    fn reserve_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, pos_core::ErasureErrorV1> {
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            reference(99),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &pos_core::ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), pos_core::ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(
        &self,
        _input: &ErasureReceiptInputV1,
    ) -> Result<(), pos_core::ErasureErrorV1> {
        Ok(())
    }
}

fn authority() -> Result<HostConfiguredErasureCoordinatorAuthorityV1, Box<dyn std::error::Error>> {
    authority_with(true)
}

fn authority_with(
    allow_rejection: bool,
) -> Result<HostConfiguredErasureCoordinatorAuthorityV1, Box<dyn std::error::Error>> {
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
        allow_rejection,
    )?;
    let configuration =
        ErasureAuthorityConfigurationV1::new(reference(6), reference(8), vec![request_binding])?;
    Ok(HostConfiguredErasureCoordinatorAuthorityV1::new(
        configuration,
        Arc::new(TestEvidenceVerifier),
        Arc::new(TestExecution),
    ))
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
            rejected_request: reference(99),
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

#[test]
fn ed25519_evidence_verifier_requires_exact_signed_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public_key = pos_core::PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
    let verifier = Ed25519ErasureAuthorityEvidenceVerifierV1::new(public_key)?;
    let request = persistence_request()?;
    let context = b"request-context";
    let signature = signing_key.sign(context);
    let mut evidence = (u32::try_from(context.len())?).to_be_bytes().to_vec();
    evidence.extend_from_slice(context);
    evidence.extend_from_slice(&signature.to_bytes());
    verifier.verify(
        ErasureAuthorityEvidenceKindV1::Request,
        &request,
        context,
        &evidence,
    )?;
    assert!(verifier
        .verify(
            ErasureAuthorityEvidenceKindV1::Request,
            &request,
            b"different-context",
            &evidence,
        )
        .is_err());
    assert!(verifier
        .verify(
            ErasureAuthorityEvidenceKindV1::Request,
            &request,
            context,
            &[0, 0, 0],
        )
        .is_err());
    let mut truncated = evidence.clone();
    truncated.push(0);
    assert!(verifier
        .verify(
            ErasureAuthorityEvidenceKindV1::Request,
            &request,
            context,
            &truncated,
        )
        .is_err());
    let mut duplicate = evidence.clone();
    duplicate.extend_from_slice(&evidence);
    assert!(verifier
        .verify(
            ErasureAuthorityEvidenceKindV1::Request,
            &request,
            context,
            &duplicate,
        )
        .is_err());
    assert!(
        Ed25519ErasureAuthorityEvidenceVerifierV1::new(pos_core::PublicKey::from_bytes([0; 32]),)
            .is_err()
    );
    let oversized = vec![0; pos_runtime::MAX_ERASURE_AUTHORITY_EVIDENCE_BYTES + 1];
    assert!(verifier
        .verify(
            ErasureAuthorityEvidenceKindV1::Request,
            &request,
            context,
            &oversized,
        )
        .is_err());
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

#[test]
fn configured_authority_rejects_unbound_and_invalid_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = authority()?;
    let request = persistence_request()?;
    let request_reference = request.reference();
    assert!(authority
        .verified_topology_observation(reference(99), reference(50))
        .is_err());
    assert!(authority
        .verified_topology_observation(request_reference, ErasureReferenceV1::from_digest([0; 32]))
        .is_err());
    let foreign_request = erasure_support::request(erasure_support::RequestFixtureInput {
        request: reference(99),
        subject: reference(2),
        scope: pos_core::ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 9,
        horizon_position: 20,
        provenance: reference(7),
    })?;
    assert!(authority.authenticate(&foreign_request).is_err());
    let same_request_correction = pos_core::ErasureCorrectionProvenanceV1::new(
        pos_core::ErasureCorrectionProvenanceInputV1 {
            rejected_request: request_reference,
            rejected_terminal_state: reference(51),
            correction_reason: reference(52),
            authorization_provenance: reference(7),
        },
    )?;
    assert!(authority
        .admit_corrected_submission(&request, &same_request_correction)
        .is_err());
    assert!(authority
        .admit_authorization(
            request_reference,
            reference(99),
            ErasureAuthorizationDecisionV1::Authorized
        )
        .is_err());
    assert!(authority
        .admit_atomic_freeze(
            request_reference,
            &ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::Authorized,
                freeze_position: Some(10),
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim: ErasureReplayClaimV1::Exact,
                provenance: reference(7),
            },
        )
        .is_err());
    assert!(authority
        .admit_atomic_freeze(
            request_reference,
            &ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::AccessFrozen,
                freeze_position: None,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim: ErasureReplayClaimV1::Exact,
                provenance: reference(7),
            },
        )
        .is_err());
    Ok(())
}

#[test]
fn configured_authority_rejects_malformed_configuration() -> Result<(), Box<dyn std::error::Error>>
{
    let target = persistence_target();
    assert!(ErasureAuthorityFreezeProfileV1::new(
        Vec::new(),
        vec![target],
        [reference(1), reference(2), reference(3), reference(4)],
        None,
        reference(5),
    )
    .is_err());
    let mut malformed_target = target;
    malformed_target.artifact_digest = ErasureReferenceV1::from_digest([0; 32]);
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1)],
        vec![malformed_target],
        [reference(2), reference(3), reference(4), reference(5)],
        None,
        reference(6),
    )
    .is_err());
    let request = persistence_request()?;
    assert!(ErasureAuthorityRequestBindingV1::new(
        request,
        Vec::new(),
        ErasureAuthorityFreezeProfileV1::new(
            vec![reference(9)],
            vec![target],
            [reference(21), reference(22), reference(23), reference(24)],
            Some(reference(25)),
            reference(26),
        )?,
        reference(40),
        Vec::new(),
        reference(7),
        true,
    )
    .is_err());
    assert!(ErasureAuthorityConfigurationV1::new(
        ErasureReferenceV1::from_digest([0; 32]),
        reference(8),
        Vec::new(),
    )
    .is_err());
    Ok(())
}
