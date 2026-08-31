#[path = "support/coordinator.rs"]
mod coordinator_support;
#[path = "support/erasure.rs"]
mod erasure_support;

use coordinator_support::{PublicCoordinatorPort as PublicPort, PublicCoordinatorPortConfig};
use pos_core::{
    ErasureArtifactClassV1, ErasureArtifactTransitionV1, ErasureCoordinatorStateMachineV1,
    ErasureErrorV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1,
    ErasureLifecycleV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1,
    ErasureScopeV1, ErasureStateTransitionV1,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(10),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(11),
        replica_set: reference(12),
        replica_id: reference(13),
    }
}

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
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

const fn transition(lifecycle: ErasureLifecycleV1) -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(9),
    }
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
fn public_finalize_covers_successful_awaiting_and_terminal_commits() -> Result<(), ErasureErrorV1> {
    let target = target();
    let request = request()?;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        PublicPort::new(PublicCoordinatorPortConfig {
            targets: vec![target],
            fail_commits: false,
            policy: reference(5),
            trust: reference(3),
            scope_member: reference(7),
            freeze_evidence: reference(9),
        }),
        reference(2),
    );
    coordinator.submit(request, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(reference(1), transition(ErasureLifecycleV1::AccessFrozen))?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;

    let receipt = coordinator.finalize(
        reference(1),
        ErasureReceiptInputV1 {
            request: reference(1),
            terminal_state: reference(99),
            coordinator: reference(2),
            lifecycle: ErasureLifecycleV1::PartialFailure,
            freeze_position: 10,
            acknowledgements: Vec::new(),
            frozen_targets: vec![target],
            pending_owners: vec![target.replica_id],
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: vec![inventory(target)],
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::Exact,
            policy: reference(2),
            trust: reference(3),
            provenance: reference(4),
            issue_position: 11,
            signature: reference(5),
            receipt_digest: reference(99),
        },
    )?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
    Ok(())
}
