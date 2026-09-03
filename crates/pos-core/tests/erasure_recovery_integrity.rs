//! Focused recovery-integrity coverage for the bounded ERCRP1 graph.
//!
//! These tests keep rollback, ordering, and host-admission checks separate from
//! the broad public lifecycle coverage so each recovery invariant has a small,
//! readable fixture.

#[path = "support/coordinator.rs"]
pub mod coordinator_support;
#[path = "support/erasure.rs"]
pub mod erasure_support;

use coordinator_support::{
    PublicCoordinatorFault, PublicCoordinatorOperation, PublicCoordinatorPort,
    PublicCoordinatorPortConfig,
};
use pos_core::erasure::{destruction_command_reference, target_closure_digest};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureCoordinator, ErasureCoordinatorStateMachineV1, ErasureErrorV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureScopeV1,
    ErasureStateTransitionV1,
};

const COORDINATOR: ErasureReferenceV1 = reference(200);

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target(seed: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(seed),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(seed.wrapping_add(1)),
        replica_set: reference(seed.wrapping_add(2)),
        replica_id: reference(seed.wrapping_add(3)),
    }
}

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(20)],
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 10,
        horizon_position: 20,
        provenance: reference(6),
    })
}

fn port(
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
        attempt_reservation_admission: None,
    })
}

const fn freeze_transition() -> ErasureStateTransitionV1 {
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

fn obligation(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })
}

fn admission(
    request: ErasureReferenceV1,
    targets: &[ErasureRequiredTargetV1],
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let mut obligations = targets
        .iter()
        .copied()
        .map(|target| obligation(request, target))
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        command_identities: obligations
            .iter()
            .map(ErasureObligationV1::command_identity)
            .collect(),
        policy: reference(5),
        trust: reference(6),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: reference(10),
    })
}

fn acknowledgement(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    evidence: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let obligation = obligation(request, target)?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target,
        owner: target.replica_id,
        evidence,
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    })
}

const fn inventory(target: ErasureRequiredTargetV1, seed: u8) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(seed),
            owner: target.replica_id,
            acknowledgements: reference(seed.wrapping_add(1)),
            provenance: reference(seed.wrapping_add(2)),
        },
        retained_disclosure: reference(seed.wrapping_add(3)),
    }
}

fn receipt_input(targets: &[ErasureRequiredTargetV1]) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request: reference(0),
        terminal_state: reference(0),
        coordinator: reference(0),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: targets.to_vec(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: targets
                .iter()
                .copied()
                .enumerate()
                .map(|(index, target)| {
                    inventory(target, u8::try_from(160 + index).unwrap_or(u8::MAX))
                })
                .collect(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(0),
        trust: reference(0),
        provenance: reference(0),
        issue_position: 30,
        signature: reference(151),
        receipt_digest: reference(0),
    }
}

struct CompletedGraph {
    adapter: PublicCoordinatorPort,
    request: ErasureRequestV1,
    receipt: pos_core::ErasureReceiptV1,
}

struct ActiveGraph {
    adapter: PublicCoordinatorPort,
    request: ErasureRequestV1,
}

fn completed_graph(
    mut targets: Vec<ErasureRequiredTargetV1>,
    lineage_rule: Option<ErasureReferenceV1>,
) -> Result<CompletedGraph, ErasureErrorV1> {
    targets.sort_unstable();
    let request = request()?;
    let port = port(targets.clone(), lineage_rule);
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(21))?;
    coordinator.freeze_access(request.reference(), freeze_transition())?;
    coordinator.dispatch_attempt(
        request.reference(),
        &admission(request.reference(), &targets)?,
    )?;
    for (index, target) in targets.iter().copied().enumerate() {
        coordinator.acknowledge(
            request.reference(),
            acknowledgement(
                request.reference(),
                target,
                reference(u8::try_from(171 + index).unwrap_or(u8::MAX)),
            )?,
        )?;
    }
    let receipt = coordinator.finalize(request.reference(), receipt_input(&targets))?;
    Ok(CompletedGraph {
        adapter,
        request,
        receipt,
    })
}

fn active_graph(
    mut targets: Vec<ErasureRequiredTargetV1>,
    lineage_rule: Option<ErasureReferenceV1>,
) -> Result<ActiveGraph, ErasureErrorV1> {
    targets.sort_unstable();
    let request = request()?;
    let port = port(targets.clone(), lineage_rule);
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(21))?;
    coordinator.freeze_access(request.reference(), freeze_transition())?;
    coordinator.dispatch_attempt(
        request.reference(),
        &admission(request.reference(), &targets)?,
    )?;
    Ok(ActiveGraph { adapter, request })
}

fn scope(
    request: ErasureReferenceV1,
    targets: &[ErasureRequiredTargetV1],
    lineage_rule: ErasureReferenceV1,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(7)],
        target_closure: target_closure_digest(targets),
        lineage_rule: Some(lineage_rule),
    })
}

fn extension(
    request: ErasureReferenceV1,
    scope: &ErasureScopeCommitmentV1,
    lineage_rule: ErasureReferenceV1,
) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request,
        scope_commitment: scope.reference(),
        fork: reference(160),
        lineage_rule,
        predecessor_extension: None,
        admission_provenance: reference(161),
    })
}

fn resolution(
    request: ErasureReferenceV1,
    terminal_state: ErasureReferenceV1,
    scope: ErasureReferenceV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
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
    })
}

fn assert_recovery_fails(adapter: PublicCoordinatorPort, request: &ErasureRequestV1) {
    assert_eq!(
        ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
            .submit(request.clone(), request.provenance()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
}

#[test]
fn recovery_rejects_manifest_state_rollback_after_a_completed_attempt() -> Result<(), ErasureErrorV1>
{
    let graph = completed_graph(vec![target(10)], None)?;
    graph.adapter.replace_manifest_with_state_lifecycle(
        graph.request.reference(),
        ErasureLifecycleV1::AwaitingAcknowledgements,
    )?;
    assert_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

#[test]
fn recovery_rejects_reordered_persisted_acknowledgement_inventory() -> Result<(), ErasureErrorV1> {
    let graph = completed_graph(vec![target(10), target(20)], None)?;
    graph
        .adapter
        .reverse_attempt_inventory(graph.request.reference(), 0, 5)?;
    assert_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

#[test]
fn recovery_accepts_an_untampered_completed_graph() -> Result<(), ErasureErrorV1> {
    let graph = completed_graph(vec![target(10)], None)?;
    let recovered = ErasureCoordinatorStateMachineV1::new(graph.adapter, COORDINATOR)
        .submit(graph.request.clone(), graph.request.provenance())?;
    assert_eq!(recovered.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[test]
fn recovery_rejects_an_active_graph_with_a_non_pending_state() -> Result<(), ErasureErrorV1> {
    let graph = active_graph(vec![target(10)], None)?;
    graph.adapter.replace_manifest_with_state_lifecycle(
        graph.request.reference(),
        ErasureLifecycleV1::DestructionDispatched,
    )?;
    assert_recovery_fails(graph.adapter, &graph.request);
    Ok(())
}

#[test]
fn recovery_revalidates_scope_and_resolution_host_admissions() -> Result<(), ErasureErrorV1> {
    let lineage_rule = reference(170);
    let graph = completed_graph(vec![target(10)], Some(lineage_rule))?;
    let targets = vec![target(10)];
    let scope_commitment = scope(graph.request.reference(), &targets, lineage_rule)?;
    let extension = extension(graph.request.reference(), &scope_commitment, lineage_rule)?;
    ErasureCoordinatorStateMachineV1::new(graph.adapter.clone(), COORDINATOR)
        .append_scope_extension(graph.request.reference(), extension)?;
    let faulted = graph.adapter.with_operation_fault(PublicCoordinatorFault {
        operation: PublicCoordinatorOperation::ValidateScopeExtension,
        occurrence: 0,
    });
    assert_eq!(
        ErasureCoordinatorStateMachineV1::new(faulted, COORDINATOR)
            .submit(graph.request.clone(), graph.request.provenance()),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );

    let graph = completed_graph(vec![target(10)], Some(lineage_rule))?;
    let scope_commitment = scope(graph.request.reference(), &targets, lineage_rule)?;
    let resolution = resolution(
        graph.request.reference(),
        graph.receipt.terminal_state(),
        scope_commitment.reference(),
    )?;
    ErasureCoordinatorStateMachineV1::new(graph.adapter.clone(), COORDINATOR)
        .resolve_administratively(graph.request.reference(), &resolution)?;
    let faulted = graph.adapter.with_operation_fault(PublicCoordinatorFault {
        operation: PublicCoordinatorOperation::ValidateAdministrativeResolution,
        occurrence: 0,
    });
    assert_eq!(
        ErasureCoordinatorStateMachineV1::new(faulted, COORDINATOR)
            .submit(graph.request, reference(6)),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    Ok(())
}
