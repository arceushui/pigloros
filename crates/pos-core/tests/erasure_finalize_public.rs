//! Public lifecycle coverage over the raw ERCRP1 persistence seam.

#[path = "support/coordinator.rs"]
pub mod coordinator_support;
#[path = "support/erasure.rs"]
pub mod erasure_support;

use coordinator_support::{PublicCoordinatorPort as PublicPort, PublicCoordinatorPortConfig};
use erasure_support::{
    obligation as fixture_obligation, reference, replay_target, request as fixture_request,
    retry_admission as fixture_retry_admission, RequestFixtureInput, RetryAdmissionFixture,
};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactTransitionV1,
    ErasureCoordinatorStateMachineV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureLifecycleV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionV1, ErasureScopeV1, ErasureStateTransitionV1,
};

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    fixture_request(RequestFixtureInput {
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

fn admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = fixture_obligation(request, target)?;
    fixture_retry_admission(RetryAdmissionFixture {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        obligations: std::slice::from_ref(&obligation),
        policy: reference(5),
        trust: reference(3),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: reference(9),
    })
}

const fn inventory(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner: target.replica_id,
            acknowledgements: reference(22),
            provenance: reference(23),
        },
        retained_disclosure: reference(24),
    }
}

#[test]
fn public_lifecycle_persists_raw_manifest_objects_and_attempt_index() -> Result<(), ErasureErrorV1>
{
    let target = replay_target(10);
    let request = request()?;
    let port = PublicPort::new(PublicCoordinatorPortConfig {
        targets: vec![target],
        fail_commits: false,
        policy: reference(5),
        trust: reference(3),
        scope_member: reference(7),
        freeze_evidence: reference(9),
        lineage_rule: None,
        freeze_rejection: None,
        operation_fault: None,
        attempt_reservation_admission: None,
    });
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));

    let submitted = coordinator.submit(request.clone(), request.provenance())?;
    assert_eq!(submitted.lifecycle(), ErasureLifecycleV1::Submitted);
    assert!(adapter.current_manifest(request.reference()).is_some());

    let authorized = coordinator.authorize(request.reference(), reference(9))?;
    assert_eq!(authorized.lifecycle(), ErasureLifecycleV1::Authorized);
    let frozen = coordinator.freeze_inventory(
        request.reference(),
        &ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            provenance: reference(9),
        },
    )?;
    assert_eq!(frozen.lifecycle(), ErasureLifecycleV1::AccessFrozen);

    let retry = admission(request.reference(), target)?;
    let awaiting = coordinator.dispatch_destruction(request.reference(), &retry)?;
    assert_eq!(
        awaiting.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(
        coordinator.dispatch_destruction(request.reference(), &retry)?,
        awaiting
    );

    let obligation = fixture_obligation(request.reference(), target)?;
    coordinator.acknowledge(
        request.reference(),
        ErasureAcknowledgementV1 {
            obligation: obligation.reference(),
            target,
            owner: target.replica_id,
            evidence: reference(21),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        },
    )?;

    let receipt = coordinator.finalize(
        request.reference(),
        ErasureReceiptInputV1 {
            request: reference(0),
            terminal_state: reference(0),
            coordinator: reference(0),
            lifecycle: ErasureLifecycleV1::Complete,
            freeze_position: 10,
            acknowledgements: Vec::new(),
            frozen_targets: vec![target],
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: vec![inventory(target)],
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::StructuralOnly,
            policy: reference(0),
            trust: reference(0),
            provenance: reference(0),
            issue_position: 21,
            signature: reference(25),
            receipt_digest: reference(0),
        },
    )?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(receipt.request(), request.reference());
    assert_eq!(adapter.attempt_index_count(request.reference())?, 1);
    assert!(adapter.attempt_page_ref(request.reference(), 0)?.is_some());
    assert!(adapter.current_manifest(request.reference()).is_some());
    Ok(())
}
