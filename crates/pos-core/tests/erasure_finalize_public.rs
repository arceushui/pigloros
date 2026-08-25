use std::{cell::RefCell, rc::Rc};

use pos_core::erasure::{
    target_closure_digest, ErasureAuthorizationDecisionV1, ErasureCoordinator,
    ErasureCoordinatorRecordPartsV1, ErasureFreezeAdmissionV1,
};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureCoordinatorPortV1, ErasureCoordinatorRecordV1,
    ErasureCoordinatorStateMachineV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeV1,
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
    request_with_subject(reference(2))
}

fn request_with_subject(subject: ErasureReferenceV1) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject,
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
    last_record: Rc<RefCell<Option<ErasureCoordinatorRecordV1>>>,
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
        *self.last_record.borrow_mut() = Some(record.clone());
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

fn partial_receipt_input(target: ErasureRequiredTargetV1) -> ErasureReceiptInputV1 {
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
    }
}

fn record_parts(record: &ErasureCoordinatorRecordV1) -> ErasureCoordinatorRecordPartsV1 {
    ErasureCoordinatorRecordPartsV1 {
        request: record.request().clone(),
        state: record.state().clone(),
        reserved_targets: record.reserved_targets().to_vec(),
        targets: record.targets().to_vec(),
        acknowledgements: record.acknowledgements().to_vec(),
        receipt: record.receipt().cloned(),
        receipt_input: record.receipt_input().cloned(),
        authorize_provenance: record.authorize_provenance(),
        freeze_provenance: record.freeze_provenance(),
        freeze_admission: record.freeze_admission(),
        dispatch_provenance: record.dispatch_provenance(),
    }
}

fn expect_terminal_binding_conflict(
    record: &ErasureCoordinatorRecordV1,
    mutate: impl FnOnce(&mut ErasureReceiptInputV1),
) -> Result<(), ErasureErrorV1> {
    let mut input = record
        .receipt_input()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    mutate(&mut input);
    let receipt = ErasureReceiptV1::new(input.clone())?;
    let mut parts = record_parts(record);
    parts.receipt = Some(receipt);
    parts.receipt_input = Some(input);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn committed_partial_record(
    history: Rc<RefCell<Option<ErasureCoordinatorRecordV1>>>,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let target = target();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        PublicPort {
            records: Vec::new(),
            states: Vec::new(),
            target,
            last_record: history.clone(),
        },
        reference(2),
    );
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(reference(1), transition(ErasureLifecycleV1::AccessFrozen))?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.finalize(reference(1), partial_receipt_input(target))?;
    history
        .borrow()
        .clone()
        .ok_or(ErasureErrorV1::ProvenanceMissing)
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
            last_record: Rc::new(RefCell::new(None)),
        },
        reference(2),
    );
    coordinator.submit(request, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(reference(1), transition(ErasureLifecycleV1::AccessFrozen))?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;

    let receipt = coordinator.finalize(reference(1), partial_receipt_input(target))?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
    Ok(())
}

#[test]
fn public_receipt_rejects_acknowledgement_outside_required_closure() {
    let required = target();
    let mut outside = required;
    outside.replica_id = reference(99);
    assert_eq!(
        ErasureReceiptV1::new(ErasureReceiptInputV1 {
            request: reference(1),
            terminal_state: reference(2),
            coordinator: reference(3),
            lifecycle: ErasureLifecycleV1::PartialFailure,
            freeze_position: 10,
            acknowledgements: vec![ErasureAcknowledgementV1 {
                target: outside,
                owner: outside.replica_id,
                evidence: reference(30),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            }],
            required_targets: vec![required],
            pending_owners: vec![required.replica_id],
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: Vec::new(),
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::Exact,
            policy: reference(4),
            trust: reference(5),
            provenance: reference(6),
            issue_position: 11,
            signature: reference(7),
            receipt_digest: reference(8),
        }),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn public_record_validation_rejects_wrong_acknowledgement_owner() -> Result<(), ErasureErrorV1> {
    let required = target();
    let state = pos_core::ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let parts = ErasureCoordinatorRecordPartsV1 {
        request: request()?,
        state,
        reserved_targets: Vec::new(),
        targets: vec![required],
        acknowledgements: vec![ErasureAcknowledgementV1 {
            target: required,
            owner: reference(99),
            evidence: reference(30),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        }],
        receipt: None,
        receipt_input: None,
        authorize_provenance: None,
        freeze_provenance: None,
        freeze_admission: None,
        dispatch_provenance: None,
    };
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn public_record_validation_rejects_each_terminal_receipt_binding_mismatch(
) -> Result<(), ErasureErrorV1> {
    let record = committed_partial_record(Rc::new(RefCell::new(None)))?;
    expect_terminal_binding_conflict(&record, |input| input.terminal_state = reference(98))?;
    expect_terminal_binding_conflict(&record, |input| input.coordinator = reference(97))?;
    expect_terminal_binding_conflict(&record, |input| input.request = reference(96))?;
    expect_terminal_binding_conflict(&record, |input| {
        let mut outside = target();
        outside.replica_id = reference(95);
        input.required_targets = vec![outside];
        input.pending_owners = vec![outside.replica_id];
        input.inventories.artifacts[0].target = outside;
    })?;
    expect_terminal_binding_conflict(&record, |input| {
        let acknowledgement = ErasureAcknowledgementV1 {
            target: target(),
            owner: target().replica_id,
            evidence: reference(94),
            outcome: ErasureAcknowledgementOutcomeV1::Negative,
        };
        input.acknowledgements = vec![acknowledgement];
        input.pending_owners = Vec::new();
        input.failed_owners = vec![acknowledgement.owner];
    })?;
    expect_terminal_binding_conflict(&record, |input| {
        input.lifecycle = ErasureLifecycleV1::Complete;
        let acknowledgement = ErasureAcknowledgementV1 {
            target: target(),
            owner: target().replica_id,
            evidence: reference(93),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        };
        input.acknowledgements = vec![acknowledgement];
        input.pending_owners = Vec::new();
        input.failed_owners = Vec::new();
    })?;
    Ok(())
}

#[test]
fn public_submit_rejects_same_reference_with_conflicting_request_fields(
) -> Result<(), ErasureErrorV1> {
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        PublicPort {
            records: Vec::new(),
            states: Vec::new(),
            target: target(),
            last_record: Rc::new(RefCell::new(None)),
        },
        reference(2),
    );
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator.submit(request_with_subject(reference(77))?, reference(3)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn public_coordinator_trait_rejects_a_submitted_request() -> Result<(), ErasureErrorV1> {
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        PublicPort {
            records: Vec::new(),
            states: Vec::new(),
            target: target(),
            last_record: Rc::new(RefCell::new(None)),
        },
        reference(2),
    );
    coordinator.submit(request()?, reference(3))?;
    let rejected = ErasureCoordinator::reject(&mut coordinator, reference(1), reference(8))?;
    assert_eq!(rejected.lifecycle(), ErasureLifecycleV1::Rejected);
    Ok(())
}

#[test]
fn public_request_decoder_rejects_trailing_and_noncanonical_cbor() -> Result<(), ErasureErrorV1> {
    let encoded = request()?.to_canonical_cbor()?;
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let position = encoded
        .windows(2)
        .rposition(|pair| pair == [9, 10])
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let mut noncanonical = encoded;
    noncanonical.splice(position..position + 2, [0x18, 9, 10]);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
