use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    destruction_command_reference, ErasureAcknowledgementProvenanceV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureCoordinatorPortV1,
    ErasureCoordinatorRecordV1, ErasureCoordinatorStateMachineV1, ErasureErrorV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationSetInputV1, ErasureObligationSetV1,
    ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeCommitmentInputV1, ErasureScopeV1,
    ErasureStateResolverV1, ErasureStateTransitionV1,
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
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target: self.target,
            owner: self.target.replica_id,
            command_identity: destruction_command_reference(request, self.target),
        })?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: vec![obligation.reference()],
            policy: reference(5),
            trust: reference(3),
        })?;
        Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(
            ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
                targets: vec![self.target],
                scope: ErasureScopeCommitmentInputV1 {
                    request,
                    scope_members: vec![reference(7)],
                    target_closure: target_closure_digest(&[self.target]),
                    lineage_rule: None,
                },
                obligations: vec![obligation],
                obligation_set,
                freeze_position: 10,
                host_evidence: reference(9),
            })?,
        )))
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[pos_core::ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
    fn admit_attempt(
        &self,
        _admission: &pos_core::ErasureRetryAdmissionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
    fn admit_scope_extension(
        &self,
        _extension: &pos_core::ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
    fn admit_administrative_resolution(
        &self,
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl ErasurePersistencePortV1 for PublicPort {
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
        self.commit_records(std::slice::from_ref(&record))
    }

    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        let mut staged_records = self.records.clone();
        let mut staged_states = self.states.clone();
        for record in records {
            if let Some(existing) = staged_records
                .iter()
                .find(|existing| existing.request() == record.request())
            {
                if existing != record {
                    existing.validate_replacement(record)?;
                }
            } else if record.state().previous_state().is_some() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if let Some(existing) = staged_records
                .iter_mut()
                .find(|existing| existing.request() == record.request())
            {
                *existing = record.clone();
            } else {
                staged_records.push(record.clone());
            }
            staged_states.push(record.state().clone());
        }
        self.records = staged_records;
        self.states = staged_states;
        Ok(())
    }

    fn compare_and_swap_scope_extension(
        &mut self,
        _request: ErasureReferenceV1,
        _expected_ledger: ErasureReferenceV1,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.commit_record(record)
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        _request: ErasureReferenceV1,
        _expected_head: Option<ErasureReferenceV1>,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.commit_record(record)
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
