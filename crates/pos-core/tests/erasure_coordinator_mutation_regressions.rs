//! Public mutation regressions for the raw ERCRP1 persistence contract.

#[path = "support/coordinator.rs"]
mod coordinator_support;
#[path = "support/erasure.rs"]
pub mod erasure_support;

use coordinator_support::{PublicCoordinatorPort, PublicCoordinatorPortConfig};
use pos_core::erasure::destruction_command_reference;
use pos_core::{
    ErasureAtomicFreezeAdmissionV1, ErasureCasEffectV1, ErasureCasOutcomeV1,
    ErasureCoordinatorStateMachineV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureErrorV1, ErasureInventoryCategoryV1, ErasureKeyRoleV1,
    ErasureLifecycleV1, ErasureObligationInputV1, ErasureObligationV1, ErasurePersistencePortV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1, ErasureScopeV1,
    ErasureStateTransitionV1,
};

const COORDINATOR: ErasureReferenceV1 = reference(200);

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: pos_core::ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(10),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(11),
        replica_set: reference(12),
        replica_id: reference(13),
    }
}

fn request_with(
    request: ErasureReferenceV1,
    provenance: ErasureReferenceV1,
) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request,
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 9,
        horizon_position: 20,
        provenance,
    })
}

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    request_with(reference(1), reference(7))
}

fn config(
    targets: Vec<ErasureRequiredTargetV1>,
    fail_commits: bool,
) -> PublicCoordinatorPortConfig {
    PublicCoordinatorPortConfig {
        targets,
        fail_commits,
        policy: reference(6),
        trust: reference(8),
        scope_member: reference(9),
        freeze_evidence: reference(10),
        lineage_rule: None,
    }
}

fn freeze_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(11),
    }
}

fn admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })?;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: reference(6),
        trust: reference(8),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: reference(12),
    })
}

#[test]
fn exact_retry_replays_the_same_prepared_delta() -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(Vec::new(), false));
    let observer = port.clone();
    let request = request()?;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;

    let mutation = observer
        .last_mutation()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let expected_effect = mutation.effect().identity();
    let next_manifest = mutation.next_manifest().digest();
    let mut retry_port = observer.clone();
    assert_eq!(
        retry_port.compare_and_swap(mutation)?,
        ErasureCasOutcomeV1::ExactRetry
    );
    assert_eq!(observer.effect(next_manifest), Some(expected_effect));
    Ok(())
}

#[test]
fn stale_cached_head_is_rejected_after_another_coordinator_advances_it(
) -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(Vec::new(), false));
    let request = request()?;
    let mut first = ErasureCoordinatorStateMachineV1::new(port.clone(), COORDINATOR);
    let mut second = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    first.submit(request.clone(), request.provenance())?;
    second.submit(request.clone(), request.provenance())?;
    first.authorize(request.reference(), reference(21))?;
    assert_eq!(
        second.authorize(request.reference(), reference(22)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn restart_recovers_the_state_from_the_raw_manifest() -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(Vec::new(), false));
    let request = request()?;
    {
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port.clone(), COORDINATOR);
        coordinator.submit(request.clone(), request.provenance())?;
        coordinator.authorize(request.reference(), reference(21))?;
    }
    let mut restarted = ErasureCoordinatorStateMachineV1::new(port.clone(), COORDINATOR);
    let recovered = restarted.submit(request.clone(), request.provenance())?;
    assert_eq!(recovered.lifecycle(), ErasureLifecycleV1::Authorized);
    assert_eq!(restarted.existing(request.reference()), Some(&recovered));
    Ok(())
}

#[test]
fn restart_recovers_a_frozen_state_and_verifies_retained_authorization(
) -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(vec![target()], false));
    let request = request()?;
    {
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port.clone(), COORDINATOR);
        coordinator.submit(request.clone(), request.provenance())?;
        coordinator.authorize(request.reference(), reference(21))?;
        coordinator.freeze_inventory(request.reference(), freeze_transition())?;
    }
    let mut restarted = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    let recovered = restarted.submit(request.clone(), request.provenance())?;
    assert_eq!(recovered.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    Ok(())
}

#[test]
fn attempt_admission_is_coupled_to_the_raw_cas_effect() -> Result<(), ErasureErrorV1> {
    let target = target();
    let port = PublicCoordinatorPort::new(config(vec![target], false));
    let observer = port.clone();
    let request = request()?;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(21))?;
    coordinator.freeze_inventory(request.reference(), freeze_transition())?;
    let admission = admission(request.reference(), target)?;
    coordinator.dispatch_attempt(request.reference(), &admission)?;

    let mutation = observer
        .last_mutation()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert!(matches!(
        mutation.effect(),
        ErasureCasEffectV1::AttemptAdmission { reservation, commands }
            if reservation.admission() == admission.reference()
                && commands.len() == 1
    ));
    assert_eq!(
        observer.effect(mutation.next_manifest().digest()),
        Some(mutation.effect().identity())
    );
    Ok(())
}

#[test]
fn failed_commit_does_not_publish_a_manifest() -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(Vec::new(), true));
    let observer = port.clone();
    let request = request()?;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    assert_eq!(
        coordinator.submit(request.clone(), request.provenance()),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert!(observer.current_manifest(request.reference()).is_none());
    Ok(())
}

#[test]
fn corrected_submission_retains_correction_as_a_raw_object() -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(Vec::new(), false));
    let request = request()?;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port.clone(), COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;
    let rejected = coordinator.reject(request.reference(), reference(21))?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: request.reference(),
        rejected_terminal_state: rejected.state_digest(),
        correction_reason: reference(22),
        authorization_provenance: reference(23),
    })?;
    let corrected = request_with(reference(30), correction.reference())?;
    let corrected_state = coordinator.submit_corrected(corrected.clone(), correction)?;
    assert_eq!(corrected_state.lifecycle(), ErasureLifecycleV1::Submitted);
    assert!(port.current_manifest(corrected.reference()).is_some());
    Ok(())
}

#[test]
fn raw_state_reads_are_missing_until_a_cas_publishes_them() -> Result<(), ErasureErrorV1> {
    let port = PublicCoordinatorPort::new(config(Vec::new(), false));
    let request = request()?;
    assert!(port.resolve_state(reference(90))?.is_none());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port.clone(), COORDINATOR);
    let state = coordinator.submit(request.clone(), request.provenance())?;
    assert_eq!(port.resolve_state(state.state_digest())?, Some(state));
    Ok(())
}
