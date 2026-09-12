//! Contract tests for the host-configured erasure authority Plugin.

use std::sync::Arc;

use ed25519_dalek::Signer;
use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureAuthorizationDecisionV1, ErasureDestructionCommandV1,
    ErasureForkAdmissionInputV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureStateTransitionV1, Seq, TimelineId, TimelineMeta,
};
use pos_runtime::{
    Ed25519ErasureAuthorityEvidenceVerifierV1, ErasureAuthorityConfigurationV1,
    ErasureAuthorityEvidenceKindV1, ErasureAuthorityEvidenceVerifierV1,
    ErasureAuthorityFreezeProfileV1, ErasureAuthorityRequestBindingV1,
    ErasureAuthorityTopologyBindingV1, ErasureCoordinatorAuthorityV1,
    ErasureCoordinatorCompositionV1, HostConfiguredErasureCoordinatorAuthorityV1,
};

#[path = "../../pos-core/tests/support/erasure.rs"]
#[expect(dead_code, unreachable_pub)]
mod erasure_support;

#[path = "support/configured_authority.rs"]
pub mod configured_authority_support;

use configured_authority_support::{TestEvidenceVerifier, TestExecution};
use erasure_support::{persistence_request, persistence_target, reference, retry_admission};

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

fn simple_profile(
    child_scope: u8,
    lineage_rule: Option<u8>,
) -> Result<ErasureAuthorityFreezeProfileV1, Box<dyn std::error::Error>> {
    Ok(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(9)],
        vec![persistence_target()],
        [reference(21), reference(22), reference(23), reference(24)],
        lineage_rule.map(reference),
        reference(child_scope),
    )?)
}

fn simple_binding(
    request: pos_core::ErasureRequestV1,
    child_scope: u8,
) -> Result<ErasureAuthorityRequestBindingV1, Box<dyn std::error::Error>> {
    Ok(ErasureAuthorityRequestBindingV1::new(
        request,
        Vec::new(),
        simple_profile(child_scope, Some(25))?,
        reference(40),
        b"host-proof".to_vec(),
        reference(7),
        true,
    )?)
}

fn frozen_admission(
    authority: &HostConfiguredErasureCoordinatorAuthorityV1,
    request: &pos_core::ErasureRequestV1,
) -> Result<pos_core::ErasureAtomicFreezeAdmissionV1, Box<dyn std::error::Error>> {
    let result = authority.admit_atomic_freeze(
        request.reference(),
        &ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            provenance: reference(7),
        },
    )?;
    match result {
        pos_core::ErasureAtomicFreezeResultV1::Admitted(admission) => Ok(*admission),
        pos_core::ErasureAtomicFreezeResultV1::Rejected(_) => {
            Err("configured authority unexpectedly rejected freeze".into())
        }
    }
}

const fn receipt_input(
    request: ErasureReferenceV1,
    lifecycle: ErasureLifecycleV1,
    terminal_state: ErasureReferenceV1,
) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request,
        terminal_state,
        coordinator: reference(55),
        lifecycle,
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
    }
}

fn acknowledgement(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
    obligation: ErasureReferenceV1,
    command: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementProvenanceV1, Box<dyn std::error::Error>> {
    Ok(ErasureAcknowledgementProvenanceV1::new(
        ErasureAcknowledgementProvenanceInputV1 {
            request,
            command,
            attempt,
            obligation,
            owner: reference(21),
            scope: reference(9),
            outcome: pos_core::ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(53),
            policy: reference(6),
            trust: reference(8),
        },
    )?)
}

fn authority_with_multiple_child_scopes(
) -> Result<HostConfiguredErasureCoordinatorAuthorityV1, Box<dyn std::error::Error>> {
    let first = persistence_request()?;
    let second = erasure_support::request(erasure_support::RequestFixtureInput {
        request: reference(90),
        subject: reference(91),
        scope: pos_core::ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(92)],
        requester: reference(93),
        authorization: reference(94),
        policy: reference(6),
        request_position: 12,
        horizon_position: 24,
        provenance: reference(95),
    })?;
    let configuration = ErasureAuthorityConfigurationV1::new(
        reference(6),
        reference(8),
        vec![simple_binding(first, 26)?, simple_binding(second, 27)?],
    )?;
    Ok(HostConfiguredErasureCoordinatorAuthorityV1::new(
        configuration,
        Arc::new(TestEvidenceVerifier),
        Arc::new(TestExecution),
    ))
}

#[test]
fn configured_composition_constructs_from_host_material() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = authority()?;
    let _composition = ErasureCoordinatorCompositionV1::from_host_configuration(
        authority.configuration().clone(),
        Arc::new(TestEvidenceVerifier),
        Arc::new(TestExecution),
        reference(70),
    )?;
    assert!(ErasureCoordinatorCompositionV1::from_host_configuration(
        authority.configuration().clone(),
        Arc::new(TestEvidenceVerifier),
        Arc::new(TestExecution),
        ErasureReferenceV1::from_digest([0; 32]),
    )
    .is_err());
    Ok(())
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
    // An all-zero compressed point is accepted by the crypto library; use the
    // known-invalid encoding covered by pos-crypto's public-key tests.
    let mut invalid_public_key = [0; 32];
    invalid_public_key[31] = 0xff;
    assert!(
        Ed25519ErasureAuthorityEvidenceVerifierV1::new(pos_core::PublicKey::from_bytes(
            invalid_public_key
        ),)
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
    ErasureRecoveryAuthorizationVerifierV1::validate_administrative_resolution(
        authority,
        &resolution,
    )?;
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
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1); pos_core::ERASURE_MAX_REFERENCES + 1],
        vec![target],
        [reference(2), reference(3), reference(4), reference(5)],
        None,
        reference(6),
    )
    .is_err());
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1)],
        vec![target; pos_core::ERASURE_MAX_TARGETS + 1],
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

#[test]
fn configured_authority_rejects_profile_binding_and_configuration_duplicates(
) -> Result<(), Box<dyn std::error::Error>> {
    let target = persistence_target();
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1), reference(1)],
        vec![target],
        [reference(2), reference(3), reference(4), reference(5)],
        Some(reference(6)),
        reference(7),
    )
    .is_err());
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1)],
        vec![target, target],
        [reference(2), reference(3), reference(4), reference(5)],
        Some(reference(6)),
        reference(7),
    )
    .is_err());
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1)],
        vec![target],
        [reference(2); 4],
        Some(reference(6)),
        reference(7),
    )
    .is_err());
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1)],
        vec![target],
        [reference(2), reference(3), reference(4), reference(5)],
        Some(ErasureReferenceV1::from_digest([0; 32])),
        reference(7),
    )
    .is_err());
    assert!(ErasureAuthorityFreezeProfileV1::new(
        vec![reference(1)],
        vec![target],
        [reference(2), reference(3), reference(4), reference(5)],
        Some(reference(6)),
        ErasureReferenceV1::from_digest([0; 32]),
    )
    .is_err());

    let request = persistence_request()?;
    let profile = simple_profile(26, Some(25))?;
    let topology_entry = ErasureAuthorityTopologyBindingV1::new(
        request.reference(),
        reference(50),
        TimelineId::new(),
        None,
    );
    assert!(ErasureAuthorityRequestBindingV1::new(
        request.clone(),
        vec![topology_entry; pos_core::ERASURE_MAX_REFERENCES + 1],
        profile.clone(),
        reference(40),
        b"host-proof".to_vec(),
        reference(7),
        true,
    )
    .is_err());
    assert!(ErasureAuthorityRequestBindingV1::new(
        request.clone(),
        Vec::new(),
        profile.clone(),
        reference(40),
        vec![1; pos_runtime::MAX_ERASURE_AUTHORITY_EVIDENCE_BYTES + 1],
        reference(7),
        true,
    )
    .is_err());
    assert!(ErasureAuthorityRequestBindingV1::new(
        request.clone(),
        vec![topology_entry, topology_entry],
        profile,
        reference(40),
        b"host-proof".to_vec(),
        reference(7),
        true,
    )
    .is_err());
    let duplicate_binding = simple_binding(request, 26)?;
    assert!(ErasureAuthorityConfigurationV1::new(
        reference(6),
        reference(8),
        vec![duplicate_binding.clone(), duplicate_binding],
    )
    .is_err());
    Ok(())
}

#[test]
fn configured_authority_rejects_lifecycle_boundary_inputs() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = authority()?;
    let request = persistence_request()?;
    let request_reference = request.reference();
    let admission = frozen_admission(&authority, &request)?;
    let wrong_authorization = pos_core::ErasureFreezeAuthorizationEvidenceV1::new(
        ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: admission
                .freeze_admission_evidence()
                .authorization_body_digest()?,
            policy: reference(6),
            trust: reference(8),
            evidence: b"different-proof".to_vec(),
        },
    )?;
    assert!(authority
        .validate_freeze_authorization(admission.freeze_admission_evidence(), &wrong_authorization,)
        .is_err());

    let malformed_extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: request_reference,
        scope_commitment: ErasureReferenceV1::from_digest([0; 32]),
        fork: reference(26),
        lineage_rule: reference(25),
        predecessor_extension: None,
        admission_provenance: reference(7),
    })?;
    assert!(
        ErasureRecoveryAuthorizationVerifierV1::validate_scope_extension(
            &authority,
            &malformed_extension,
        )
        .is_err()
    );

    let rejecting_authority = authority_with(false)?;
    assert!(rejecting_authority
        .admit_authorization(
            request_reference,
            reference(7),
            ErasureAuthorizationDecisionV1::Rejected,
        )
        .is_err());
    let malformed_correction = pos_core::ErasureCorrectionProvenanceV1::new(
        pos_core::ErasureCorrectionProvenanceInputV1 {
            rejected_request: reference(99),
            rejected_terminal_state: ErasureReferenceV1::from_digest([0; 32]),
            correction_reason: reference(52),
            authorization_provenance: reference(7),
        },
    )?;
    assert!(authority
        .admit_corrected_submission(&request, &malformed_correction)
        .is_err());

    let valid_extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: request_reference,
        scope_commitment: reference(59),
        fork: reference(26),
        lineage_rule: reference(25),
        predecessor_extension: None,
        admission_provenance: reference(7),
    })?;
    assert!(authority
        .admit_fork_scope_extension(
            &valid_extension,
            &ErasureForkAdmissionInputV1 {
                operation: ErasureReferenceV1::from_digest([0; 32]),
                expected_inventory_generation: reference(62),
                child_scope: reference(26),
                child: TimelineMeta::forked_from(TimelineId::new(), Seq::ZERO, "invalid-input"),
            },
        )
        .is_err());

    let actual_parent = TimelineId::new();
    let child = TimelineMeta::forked_from(actual_parent, Seq::ZERO, "wrong-parent");
    assert!(authority
        .resolve_fork_child_scope(TimelineId::new(), &child)
        .is_err());
    assert!(authority
        .dispatch_destruction(request_reference, &[])
        .is_err());
    let mut malformed_command =
        ErasureDestructionCommandV1::from_obligation(&admission.obligations()[0], reference(7));
    malformed_command.command = ErasureReferenceV1::from_digest([0; 32]);
    assert!(authority
        .dispatch_destruction(request_reference, &[malformed_command])
        .is_err());
    Ok(())
}

#[test]
fn configured_authority_rejects_attempt_receipt_and_scope_edges(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = authority()?;
    let request = persistence_request()?;
    let request_reference = request.reference();
    let admission = frozen_admission(&authority, &request)?;
    let first = admission.obligations()[0];

    let unknown_retry = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: request_reference,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![reference(99)],
        command_identities: vec![reference(98)],
        policy: reference(6),
        trust: reference(8),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(7),
    })?;
    assert!(authority.admit_attempt(&unknown_retry).is_err());
    let zero_retry = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: request_reference,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![ErasureReferenceV1::from_digest([0; 32])],
        command_identities: vec![reference(98)],
        policy: reference(6),
        trust: reference(8),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(7),
    })?;
    assert!(authority.admit_attempt(&zero_retry).is_err());

    let missing_ack = acknowledgement(
        request_reference,
        reference(60),
        first.reference(),
        ErasureReferenceV1::from_digest([0; 32]),
    )?;
    assert!(authority.admit_acknowledgement(&missing_ack).is_err());
    let unknown_ack = acknowledgement(
        request_reference,
        reference(60),
        reference(99),
        first.command_identity(),
    )?;
    assert!(authority.admit_acknowledgement(&unknown_ack).is_err());
    assert!(authority
        .admit_receipt(&receipt_input(
            request_reference,
            ErasureLifecycleV1::AccessFrozen,
            reference(54),
        ))
        .is_err());
    assert!(authority
        .admit_receipt(&receipt_input(
            request_reference,
            ErasureLifecycleV1::Complete,
            ErasureReferenceV1::from_digest([0; 32]),
        ))
        .is_err());

    let malformed_resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: request_reference,
            affected_digests: vec![reference(58)],
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: ErasureReferenceV1::from_digest([0; 32]),
            policy: reference(6),
            trust: reference(8),
            principal: reference(40),
            authorization_provenance: reference(7),
            reason: reference(60),
            issue_position: 12,
            predecessor_resolution: None,
        })?;
    assert!(authority
        .admit_administrative_resolution(&malformed_resolution)
        .is_err());

    let multiple_scopes = authority_with_multiple_child_scopes()?;
    let parent = TimelineId::new();
    let child = TimelineMeta::forked_from(parent, Seq::ZERO, "multiple-scopes");
    assert!(multiple_scopes
        .resolve_fork_child_scope(parent, &child)
        .is_err());
    Ok(())
}
