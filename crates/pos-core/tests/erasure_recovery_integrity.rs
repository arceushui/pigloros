//! Focused recovery-integrity coverage for the bounded ERCRP1 graph.
//!
//! These tests keep rollback, ordering, and host-admission checks separate from
//! the broad public lifecycle coverage so each recovery invariant has a small,
//! readable fixture.

use std::collections::BTreeMap;

#[path = "support/coordinator.rs"]
pub mod coordinator_support;
#[path = "support/erasure.rs"]
pub mod erasure_support;

use coordinator_support::{
    PublicCoordinatorFault, PublicCoordinatorOperation, PublicCoordinatorPort,
    PublicCoordinatorPortConfig,
};
use erasure_support::{
    obligation as fixture_obligation, reference, replay_target as target,
    request as fixture_request, retry_admission as fixture_retry_admission, RequestFixtureInput,
    RetryAdmissionFixture,
};
use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactTransitionV1, ErasureCoordinator,
    ErasureCoordinatorStateMachineV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureLifecycleV1, ErasureObligationV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureRecoveryErrorV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1, ErasureScopeExtensionV1,
    ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1, ErasureStateV1,
    ErasureVerifiedStateQueryV1,
};

const COORDINATOR: ErasureReferenceV1 = reference(200);

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    fixture_request(RequestFixtureInput {
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

fn admission(
    request: ErasureReferenceV1,
    targets: &[ErasureRequiredTargetV1],
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let mut obligations = targets
        .iter()
        .copied()
        .map(|target| fixture_obligation(request, target))
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    fixture_retry_admission(RetryAdmissionFixture {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        obligations: &obligations,
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
    let obligation = fixture_obligation(request, target)?;
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

struct StateMapResolver(BTreeMap<ErasureReferenceV1, ErasureStateV1>);

impl ErasureStateResolverV1 for StateMapResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        Ok(self.0.get(&digest).cloned())
    }
}

fn assert_recovery_fails(adapter: PublicCoordinatorPort, request: &ErasureRequestV1) {
    assert_eq!(
        ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR)
            .submit(request.clone(), request.provenance()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
}

#[test]
fn verified_state_query_reloads_scope_and_fence_after_restart() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let lineage_rule = reference(170);
    let port = port(vec![target], Some(lineage_rule));
    let observer = port.clone();
    let request = request()?;
    let extension_record;
    {
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, COORDINATOR);
        coordinator.submit(request.clone(), request.provenance())?;
        coordinator.authorize(request.reference(), reference(21))?;
        coordinator.freeze_inventory(request.reference(), &freeze_transition())?;
        let scope = coordinator
            .verified_state(request.reference())?
            .and_then(|verified| verified.scope().cloned())
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        extension_record = extension(request.reference(), &scope, lineage_rule)?;
        coordinator.append_scope_extension(request.reference(), extension_record)?;
    }

    let mut restarted = ErasureCoordinatorStateMachineV1::new(observer.clone(), COORDINATOR);
    let verified = <ErasureCoordinatorStateMachineV1<PublicCoordinatorPort> as
        ErasureVerifiedStateQueryV1>::verified_state(&mut restarted, request.reference())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(verified.request(), &request);
    assert_eq!(verified.state().request(), request.reference());
    assert_eq!(verified.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(verified.freeze_position(), Some(10));
    let scope = verified.scope().ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(scope.request(), request.reference());
    assert_eq!(scope.scope_members(), &[reference(7)]);
    assert_eq!(verified.scope_extensions(), &[extension_record]);
    assert_eq!(
        verified.scope_forks().collect::<Vec<_>>(),
        vec![reference(160)]
    );
    assert_eq!(
        verified.manifest_digest(),
        observer
            .current_manifest(request.reference())
            .ok_or(ErasureErrorV1::ProvenanceMissing)?
            .digest()
    );
    assert!(restarted.verified_state(reference(240))?.is_none());
    Ok(())
}

#[test]
fn recovery_failures_are_retained_and_exact_retries_are_idempotent(
) -> Result<(), ErasureErrorV1> {
    let graph = active_graph(vec![target(10)], None)?;
    let request = graph.request.reference();
    let manifest = graph
        .adapter
        .current_manifest(request)
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .digest();
    let adapter = graph.adapter;
    adapter.remove_object(request);

    let mut coordinator = ErasureCoordinatorStateMachineV1::new(adapter.clone(), COORDINATOR);
    assert_eq!(
        coordinator.verified_state(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        coordinator.verified_state(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    adapter.insert_object(request, graph.request.to_canonical_cbor()?);
    let closure = target_closure_digest(&[target(10)]);
    adapter.remove_object(closure);
    assert_eq!(
        coordinator.verified_state(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        coordinator.verified_state(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let failures = coordinator.recovery_errors(request)?;
    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].request(), request);
    assert_eq!(failures[0].manifest(), Some(manifest));
    assert_eq!(failures[0].failure_subject(), request);
    assert_eq!(failures[0].error(), ErasureErrorV1::ProvenanceMissing);
    assert_eq!(failures[1].manifest(), Some(manifest));
    assert_eq!(failures[1].failure_subject(), closure);
    assert_eq!(failures[1].error(), ErasureErrorV1::ProvenanceMissing);
    let bytes = failures[0].to_canonical_cbor()?;
    assert_eq!(
        ErasureRecoveryErrorV1::from_canonical_cbor(&bytes)?,
        failures[0]
    );
    assert_eq!(
        ErasureRecoveryErrorV1::from_canonical_cbor(&[]),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn manifest_read_failures_are_retained_without_a_manifest_reference(
) -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let adapter = port(vec![], None).with_operation_fault(PublicCoordinatorFault {
        operation: PublicCoordinatorOperation::LoadManifest,
        occurrence: 0,
    });
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(adapter, COORDINATOR);

    assert_eq!(
        coordinator.verified_state(request.reference()),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    let failures = coordinator.recovery_errors(request.reference())?;
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].request(), request.reference());
    assert_eq!(failures[0].manifest(), None);
    assert_eq!(failures[0].failure_subject(), request.reference());
    assert_eq!(failures[0].error(), ErasureErrorV1::TrustSnapshotInvalid);
    Ok(())
}

#[test]
fn public_state_chain_query_requires_the_complete_predecessor_chain() -> Result<(), ErasureErrorV1>
{
    let request = request()?;
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(port(Vec::new(), None), COORDINATOR);
    let root = coordinator.submit(request.clone(), request.provenance())?;
    let successor = coordinator.authorize(request.reference(), reference(21))?;

    assert!(successor
        .verify_predecessor_chain(&StateMapResolver(BTreeMap::new()))
        .is_err());
    let mut states = BTreeMap::new();
    states.insert(root.state_digest(), root);
    assert!(successor
        .verify_predecessor_chain(&StateMapResolver(states))
        .is_ok());
    Ok(())
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
