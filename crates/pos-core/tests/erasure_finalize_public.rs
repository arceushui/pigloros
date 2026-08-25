use pos_core::{
    target_closure_digest, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureCoordinatorPortV1, ErasureCoordinatorRecordV1,
    ErasureCoordinatorStateMachineV1, ErasureErrorV1, ErasureFreezeAdmissionV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeV1,
    ErasureStateResolverV1, ErasureStateTransitionV1,
};

fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn target() -> ErasureRequiredTargetV1 {
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

fn transition(lifecycle: ErasureLifecycleV1) -> ErasureStateTransitionV1 {
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

fn inventory(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner: reference(21),
            acknowledgements: reference(22),
            provenance: reference(23),
        },
        retained_disclosure: reference(24),
    }
}

struct PublicPort {
    records: Vec<ErasureCoordinatorRecordV1>,
    states: Vec<pos_core::ErasureStateV1>,
    target: ErasureRequiredTargetV1,
}

impl ErasureStateResolverV1 for PublicPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<pos_core::ErasureStateV1>, ErasureErrorV1> {
        Ok(self
            .states
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}

impl ErasureCoordinatorPortV1 for PublicPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: pos_core::ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn required_targets(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
        Ok(vec![self.target])
    }

    fn admit_freeze(
        &self,
        _request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
        targets: &[ErasureRequiredTargetV1],
    ) -> Result<ErasureFreezeAdmissionV1, ErasureErrorV1> {
        Ok(ErasureFreezeAdmissionV1 {
            freeze_position: 10,
            provenance: reference(9),
            target_closure: target_closure_digest(targets),
        })
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _targets: &[ErasureRequiredTargetV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_acknowledgement(
        &self,
        _request: ErasureReferenceV1,
        _acknowledgement: &ErasureAcknowledgementV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        Ok(self
            .records
            .iter()
            .find(|record| record.request().reference() == request)
            .cloned())
    }

    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|existing| existing.request() == record.request())
        {
            *existing = record.clone();
        } else {
            self.records.push(record.clone());
        }
        self.states.push(record.state().clone());
        Ok(())
    }
}

#[test]
fn public_finalize_covers_successful_awaiting_and_terminal_commits() -> Result<(), ErasureErrorV1> {
    let target = target();
    let request = request()?;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        PublicPort {
            records: Vec::new(),
            states: Vec::new(),
            target,
        },
        reference(2),
    );
    coordinator.submit(request.clone(), reference(3))?;
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
            required_targets: vec![target],
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
