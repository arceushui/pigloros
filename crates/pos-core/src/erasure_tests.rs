fn test_uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn test_digest(reference: ErasureReferenceV1) -> Value {
    Value::Bytes(reference.digest().to_vec())
}
fn test_text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
use super::*;
use crate::erasure::codec::{
    array, cbor_argument, cbor_argument_bytes, cbor_item_end, cbor_shape_is_bounded,
    has_duplicate_by_inventory_target,
};
use ciborium::value::Value;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct TestCoordinatorPort {
    accepted: bool,
    authorization_admitted: bool,
    authorization_decisions: Rc<
        RefCell<
            Vec<(
                ErasureReferenceV1,
                ErasureReferenceV1,
                ErasureAuthorizationDecisionV1,
            )>,
        >,
    >,
    acknowledgement_admitted: bool,
    freeze_error: Option<ErasureErrorV1>,
    required_targets_error: Option<ErasureErrorV1>,
    admitted_freeze_provenance: Option<ErasureReferenceV1>,
    admitted_freeze_position: Option<u64>,
    admitted_freeze_closure: Option<ErasureReferenceV1>,
    freeze_reservation: Rc<RefCell<Option<ErasureFreezeAdmissionV1>>>,
    dispatch_error: Option<ErasureErrorV1>,
    receipt_error: Option<ErasureErrorV1>,
    receipt_inputs: Rc<RefCell<Vec<ErasureReceiptInputV1>>>,
    load_error: Option<ErasureErrorV1>,
    commit_error: Option<ErasureErrorV1>,
    commit_error_on_call: Option<usize>,
    commit_calls: Rc<RefCell<usize>>,
    targets: Vec<ErasureRequiredTargetV1>,
    records: Rc<RefCell<Vec<ErasureCoordinatorRecordV1>>>,
    state_history: Rc<RefCell<Vec<ErasureStateV1>>>,
}
struct TestResolver {
    states: Vec<ErasureStateV1>,
    unavailable: bool,
}
struct ReplyResolver {
    terminal: ErasureStateV1,
    previous: ErasureStateV1,
}
struct FailingPredecessorResolver {
    terminal: ErasureStateV1,
}
impl ErasureStateResolverV1 for TestResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if self.unavailable {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(self
            .states
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}
impl ErasureStateResolverV1 for ReplyResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if digest == self.terminal.state_digest() {
            Ok(Some(self.terminal.clone()))
        } else {
            Ok(Some(self.previous.clone()))
        }
    }
}
impl ErasureStateResolverV1 for FailingPredecessorResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if digest == self.terminal.state_digest() {
            Ok(Some(self.terminal.clone()))
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }
}
impl ErasureCoordinatorPortV1 for TestCoordinatorPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        if self.accepted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn admit_authorization(
        &self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.authorization_decisions
            .borrow_mut()
            .push((request, provenance, decision));
        if self.authorization_admitted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn required_targets(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
        if let Some(error) = self.required_targets_error {
            return Err(error);
        }
        Ok(self.targets.clone())
    }
    fn admit_freeze(
        &self,
        _request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
        targets: &[ErasureRequiredTargetV1],
    ) -> Result<ErasureFreezeAdmissionV1, ErasureErrorV1> {
        if let Some(error) = self.freeze_error {
            return Err(error);
        }
        if let Some(admission) = *self.freeze_reservation.borrow() {
            return Ok(admission);
        }
        let admission = ErasureFreezeAdmissionV1 {
            freeze_position: self
                .admitted_freeze_position
                .unwrap_or_else(|| requested.freeze_position.unwrap_or(10)),
            provenance: self
                .admitted_freeze_provenance
                .unwrap_or(requested.provenance),
            target_closure: self
                .admitted_freeze_closure
                .unwrap_or_else(|| target_closure_digest(targets)),
        };
        self.freeze_reservation.borrow_mut().replace(admission);
        Ok(admission)
    }
    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        if let Some(error) = self.dispatch_error {
            return Err(error);
        }
        Ok(())
    }
    fn admit_acknowledgement(
        &self,
        _request: ErasureReferenceV1,
        _acknowledgement: &ErasureAcknowledgementV1,
    ) -> Result<(), ErasureErrorV1> {
        if self.acknowledgement_admitted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn admit_receipt(&self, input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        self.receipt_inputs.borrow_mut().push(input.clone());
        if let Some(error) = self.receipt_error {
            return Err(error);
        }
        Ok(())
    }
}

impl ErasurePersistencePortV1 for TestCoordinatorPort {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        if let Some(error) = self.load_error {
            return Err(error);
        }
        Ok(self
            .records
            .borrow()
            .iter()
            .find(|record| record.request.reference() == request)
            .cloned())
    }

    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        self.commit_records(std::slice::from_ref(&record))
    }

    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        let mut staged_records = self.records.borrow().clone();
        let mut staged_states = self.state_history.borrow().clone();
        for record in records {
            *self.commit_calls.borrow_mut() += 1;
            if self
                .commit_error_on_call
                .is_some_and(|call| call == *self.commit_calls.borrow())
            {
                return Err(ErasureErrorV1::ReceiptCommitFailed);
            }
            if let Some(error) = self.commit_error {
                return Err(error);
            }
            if let Some(existing) = staged_records
                .iter()
                .find(|existing| existing.request.reference() == record.request.reference())
            {
                if existing != record {
                    existing.validate_replacement(record)?;
                }
            } else if record.state().previous_state().is_some() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if let Some(existing) = staged_records
                .iter_mut()
                .find(|existing| existing.request.reference() == record.request.reference())
            {
                *existing = record.clone();
            } else {
                staged_records.push(record.clone());
            }
            staged_states.push(record.state().clone());
        }
        self.records.replace(staged_records);
        self.state_history.replace(staged_states);
        Ok(())
    }
}

impl ErasureStateResolverV1 for TestCoordinatorPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        Ok(self
            .state_history
            .borrow()
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}

fn test_port(accepted: bool, targets: Vec<ErasureRequiredTargetV1>) -> TestCoordinatorPort {
    TestCoordinatorPort {
        accepted,
        authorization_admitted: true,
        authorization_decisions: Rc::new(RefCell::new(Vec::new())),
        acknowledgement_admitted: true,
        freeze_error: None,
        required_targets_error: None,
        admitted_freeze_provenance: None,
        admitted_freeze_position: None,
        admitted_freeze_closure: None,
        freeze_reservation: Rc::new(RefCell::new(None)),
        dispatch_error: None,
        receipt_error: None,
        receipt_inputs: Rc::new(RefCell::new(Vec::new())),
        load_error: None,
        commit_error: None,
        commit_error_on_call: None,
        commit_calls: Rc::new(RefCell::new(0)),
        targets,
        records: Rc::new(RefCell::new(Vec::new())),
        state_history: Rc::new(RefCell::new(Vec::new())),
    }
}
fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}
fn indexed_reference(index: usize) -> ErasureReferenceV1 {
    let mut digest = [0; 32];
    let index = index.to_be_bytes();
    digest[32 - index.len()..].copy_from_slice(&index);
    ErasureReferenceV1::from_digest(digest)
}
fn indexed_target(index: usize) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: indexed_reference(index),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: indexed_reference(index + 1),
        replica_set: reference(30),
        replica_id: indexed_reference(index + 2),
    }
}
fn references(count: usize) -> Vec<ErasureReferenceV1> {
    (0..count).map(indexed_reference).collect()
}
pub(super) fn request_input(selectors: Vec<ErasureReferenceV1>) -> ErasureRequestInputV1 {
    ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors,
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(6),
    }
}
fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(request_input(vec![reference(8), reference(7)]))
}
fn change(
    lifecycle: ErasureLifecycleV1,
    freeze_position: Option<u64>,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
) -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle,
        freeze_position,
        pending_owners,
        failed_owners,
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    }
}
fn acknowledgement(
    owner: u8,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        target: ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: reference(owner),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: reference(owner + 10),
            replica_set: reference(owner + 30),
            replica_id: reference(owner + 40),
        },
        owner: reference(owner + 40),
        evidence: reference(owner + 20),
        outcome,
    }
}
fn inventory_result(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(50),
            owner: reference(51),
            acknowledgements: reference(52),
            provenance: reference(53),
        },
        retained_disclosure: reference(54),
    }
}
fn receipt_input(
    lifecycle: ErasureLifecycleV1,
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
) -> ErasureReceiptInputV1 {
    let required_targets = acknowledgements
        .iter()
        .map(|acknowledgement| acknowledgement.target)
        .collect();
    let artifacts = acknowledgements
        .iter()
        .map(|acknowledgement| inventory_result(acknowledgement.target))
        .collect();
    ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(6),
        coordinator: reference(2),
        lifecycle,
        freeze_position: 10,
        required_targets,
        acknowledgements,
        pending_owners,
        failed_owners,
        inventories: ErasureReceiptInventoriesV1 {
            artifacts,
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(2),
        trust: reference(3),
        provenance: reference(4),
        issue_position: 11,
        signature: reference(5),
        receipt_digest: reference(0),
    }
}
fn receipt() -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
        ],
        Vec::new(),
        Vec::new(),
    ))
}
fn dispatched() -> Result<ErasureStateV1, ErasureErrorV1> {
    ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
        .transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?
        .transition(change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?
        .transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))
}
fn decode_request(value: &Value) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn decode_state(value: &Value) -> Result<ErasureStateV1, ErasureErrorV1> {
    ErasureStateV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn decode_receipt(value: &Value) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn public_value_bytes(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(bytes)
}
fn public_request_value(request: &ErasureRequestV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(request.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn public_state_value(state: &ErasureStateV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(state.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn public_receipt_value(receipt: &ErasureReceiptV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(receipt.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
pub(super) fn record_parts(record: &ErasureCoordinatorRecordV1) -> ErasureCoordinatorRecordPartsV1 {
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

pub(super) fn record_after_freeze(
    targets: Vec<ErasureRequiredTargetV1>,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let port = test_port(true, targets);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

pub(super) fn record_after_submit() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

fn record_after_acknowledgement() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

pub(super) fn complete_record() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let terminal = awaiting.transition({
        let mut transition = change(
            ErasureLifecycleV1::Complete,
            awaiting.freeze_position(),
            Vec::new(),
            Vec::new(),
        );
        transition.acknowledged_targets = vec![ack.target];
        transition.provenance = reference(4);
        transition
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    coordinator.finalize(reference(1), input)?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

fn completed_coordinator(
) -> Result<ErasureCoordinatorStateMachineV1<TestCoordinatorPort>, ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = change(
        ErasureLifecycleV1::Complete,
        awaiting.freeze_position(),
        Vec::new(),
        Vec::new(),
    );
    terminal_change.acknowledged_targets = vec![ack.target];
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    coordinator.finalize(reference(1), input)?;
    Ok(coordinator)
}

fn assert_conflicting_receipt_retry(
    mutate: impl FnOnce(&mut ErasureReceiptInputV1),
) -> Result<(), ErasureErrorV1> {
    let mut coordinator = completed_coordinator()?;
    let mut input = coordinator
        .port
        .records
        .borrow()
        .first()
        .and_then(ErasureCoordinatorRecordV1::receipt_input)
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    mutate(&mut input);
    assert_eq!(
        coordinator.finalize(reference(1), input),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn reject_terminal_receipt_mutation(
    record: &ErasureCoordinatorRecordV1,
    mutate: impl FnOnce(&mut ErasureReceiptV1),
) -> Result<(), ErasureErrorV1> {
    let mut parts = record_parts(record);
    mutate(
        parts
            .receipt
            .as_mut()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?,
    );
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn reject_terminal_input_mutation(
    record: &ErasureCoordinatorRecordV1,
    mutate: impl FnOnce(&mut ErasureReceiptInputV1),
) -> Result<(), ErasureErrorV1> {
    let mut parts = record_parts(record);
    let rebuilt = {
        let input = parts
            .receipt_input
            .as_mut()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        mutate(input);
        ErasureReceiptV1::new(input.clone())?
    };
    parts.receipt = Some(rebuilt);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn exercise_lifecycle_edge_cases() {
    for (current, next, permitted) in [
        (
            ErasureLifecycleV1::Submitted,
            ErasureLifecycleV1::Authorized,
            true,
        ),
        (
            ErasureLifecycleV1::Submitted,
            ErasureLifecycleV1::Rejected,
            true,
        ),
        (
            ErasureLifecycleV1::Authorized,
            ErasureLifecycleV1::AccessFrozen,
            true,
        ),
        (
            ErasureLifecycleV1::AccessFrozen,
            ErasureLifecycleV1::DestructionDispatched,
            true,
        ),
        (
            ErasureLifecycleV1::DestructionDispatched,
            ErasureLifecycleV1::AwaitingAcknowledgements,
            true,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::Complete,
            true,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::PartialFailure,
            true,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::Submitted,
            false,
        ),
        (
            ErasureLifecycleV1::Complete,
            ErasureLifecycleV1::Authorized,
            false,
        ),
    ] {
        assert_eq!(
            std::hint::black_box(current).permits(std::hint::black_box(next)),
            permitted
        );
    }
}

fn exercise_receipt_record_edges() -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let second = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut outside_closure = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![first],
        Vec::new(),
        Vec::new(),
    );
    outside_closure.required_targets = vec![second.target];
    assert_eq!(
        ErasureReceiptV1::new(outside_closure),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let awaiting = record_after_acknowledgement()?;
    let mut invalid_owner = record_parts(&awaiting);
    invalid_owner.acknowledgements[0].owner = reference(99);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_owner, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let complete = complete_record()?;
    reject_terminal_input_mutation(&complete, |input| input.terminal_state = reference(99))?;
    reject_terminal_input_mutation(&complete, |input| {
        input.lifecycle = ErasureLifecycleV1::PartialFailure;
        input.acknowledgements[0].outcome = ErasureAcknowledgementOutcomeV1::Negative;
        input.failed_owners = vec![first.target.replica_id];
    })?;
    reject_terminal_input_mutation(&complete, |input| input.coordinator = reference(99))?;
    reject_terminal_input_mutation(&complete, |input| input.request = reference(99))?;
    reject_terminal_input_mutation(&complete, |input| {
        input.required_targets = vec![second.target];
        input.acknowledgements = vec![second];
        input.inventories.artifacts = vec![inventory_result(second.target)];
    })?;
    reject_terminal_input_mutation(&complete, |input| {
        input.acknowledgements[0].evidence = reference(99);
    })?;

    let mut invalid_receipt_input = record_parts(&complete);
    invalid_receipt_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Submitted,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_receipt_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn exercise_state_machine_edges() -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let persisted = record_after_submit()?;
    let mut mismatched_request_input = request_input(vec![reference(8), reference(7)]);
    mismatched_request_input.subject = reference(99);
    let mismatched_request = ErasureRequestV1::new(mismatched_request_input)?;
    let mismatch_port = test_port(true, Vec::new());
    mismatch_port.records.replace(vec![persisted]);
    let mut mismatch = ErasureCoordinatorStateMachineV1::new(mismatch_port, reference(2));
    assert_eq!(
        mismatch.submit(mismatched_request, reference(3)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut rejected_port = test_port(true, Vec::new());
    rejected_port.authorization_admitted = false;
    let mut rejected = ErasureCoordinatorStateMachineV1::new(rejected_port, reference(2));
    rejected.submit(request()?, reference(3))?;
    assert_eq!(
        rejected.reject(reference(1), reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut missing_targets_port = test_port(true, vec![first.target]);
    missing_targets_port.required_targets_error = Some(ErasureErrorV1::AccessFreezeFailed);
    let mut missing_targets =
        ErasureCoordinatorStateMachineV1::new(missing_targets_port, reference(2));
    missing_targets.submit(request()?, reference(3))?;
    missing_targets.authorize(reference(1), reference(9))?;
    assert_eq!(
        missing_targets.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::AccessFreezeFailed)
    );

    let mut reservation_commit_port = test_port(true, vec![first.target]);
    reservation_commit_port.commit_error_on_call = Some(3);
    let mut reservation_commit =
        ErasureCoordinatorStateMachineV1::new(reservation_commit_port, reference(2));
    reservation_commit.submit(request()?, reference(3))?;
    reservation_commit.authorize(reference(1), reference(9))?;
    assert_eq!(
        reservation_commit.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    Ok(())
}

fn exercise_normalization_and_trait_edges() -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let submitted = record_after_submit()?;
    assert_eq!(
        ErasureCoordinatorStateMachineV1::<TestCoordinatorPort>::normalize_receipt_input(
            reference(1),
            reference(2),
            &submitted,
            receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = record_after_freeze(vec![first.target])?;
    assert_eq!(
        ErasureCoordinatorStateMachineV1::<TestCoordinatorPort>::normalize_receipt_input(
            reference(1),
            reference(2),
            &frozen,
            receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut trait_coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    let api: &mut dyn ErasureCoordinator = &mut trait_coordinator;
    api.submit(request()?)?;
    assert_eq!(
        api.reject(reference(1), reference(9))?.lifecycle(),
        ErasureLifecycleV1::Rejected
    );

    let mut malformed = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    malformed.lifecycle = ErasureLifecycleV1::Authorized;
    malformed.previous_state = None;
    assert_eq!(
        verify_predecessor_chain(malformed, &test_port(true, Vec::new())),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn lifecycle_edges_are_exercised() {
    exercise_lifecycle_edge_cases();
}

#[test]
fn receipt_record_edges_are_exercised() -> Result<(), ErasureErrorV1> {
    exercise_receipt_record_edges()
}

#[test]
fn state_machine_edges_are_exercised() -> Result<(), ErasureErrorV1> {
    exercise_state_machine_edges()
}

#[test]
fn normalization_and_trait_edges_are_exercised() -> Result<(), ErasureErrorV1> {
    exercise_normalization_and_trait_edges()
}

#[test]
fn coordinator_public_retries_reject_injection_and_query_existing() -> Result<(), ErasureErrorV1> {
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = coordinator.submit(request()?, reference(3))?;
    assert_eq!(coordinator.submit(request()?, reference(3))?, submitted);
    assert_eq!(coordinator.existing(reference(1)), Some(&submitted));
    Ok(())
}

#[test]
fn coordinator_authorization_and_rejection_use_public_host_seams() -> Result<(), ErasureErrorV1> {
    let mut unauthorized =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    unauthorized.port.authorization_admitted = false;
    unauthorized.submit(request()?, reference(3))?;
    assert_eq!(
        unauthorized.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    coordinator.submit(request()?, reference(3))?;
    let rejected = coordinator.reject(reference(1), reference(9))?;
    assert_eq!(rejected.lifecycle(), ErasureLifecycleV1::Rejected);
    assert_eq!(
        coordinator.reject(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(coordinator.reject(reference(1), reference(9))?, rejected);
    assert_eq!(
        coordinator.port.authorization_decisions.borrow().as_slice(),
        &[(
            reference(1),
            reference(9),
            ErasureAuthorizationDecisionV1::Rejected,
        ),]
    );
    Ok(())
}

#[test]
fn coordinator_reloads_durable_identity_after_restart() -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let request = request()?;
    let mut first = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = first.submit(request.clone(), reference(3))?;
    drop(first);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(restarted.submit(request, reference(99))?, submitted);
    Ok(())
}

#[test]
fn durable_record_reconstructs_through_public_parts_api() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request.clone(), reference(3))?;
    let persisted = restart_port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let reconstructed =
        ErasureCoordinatorRecordV1::from_parts(record_parts(&persisted), reference(2))?;
    restart_port.records.replace(vec![reconstructed]);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(
        restarted.submit(request, reference(99))?.lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    Ok(())
}

#[test]
fn submit_rehydration_verifies_the_persisted_predecessor_chain() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request.clone(), reference(3))?;
    let persisted = restart_port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let authorized = persisted.state().transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut parts = record_parts(&persisted);
    parts.state = authorized;
    parts.authorize_provenance = Some(reference(9));
    let reconstructed = ErasureCoordinatorRecordV1::from_parts(parts, reference(2))?;
    restart_port.records.replace(vec![reconstructed]);
    restart_port.state_history.borrow_mut().clear();

    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(
        restarted.submit(request, reference(99)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_record_parts_reject_inconsistent_public_inputs() -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    let persisted = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;

    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(record_parts(&persisted), reference(99)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut invalid_scope = record_parts(&persisted);
    invalid_scope.targets = vec![target, target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_scope, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut invalid_policy = record_parts(&persisted);
    invalid_policy.targets = vec![target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_policy, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let authorized = persisted.state().transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut missing_authorization = record_parts(&persisted);
    missing_authorization.state = authorized.clone();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(missing_authorization, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let mut invalid_frozen = record_parts(&persisted);
    invalid_frozen.state = frozen;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_frozen, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let dispatched = persisted
        .state()
        .transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?
        .transition(change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?
        .transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
    let mut invalid_dispatched = record_parts(&persisted);
    invalid_dispatched.state = dispatched;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_dispatched, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn durable_record_scope_checks_reject_independent_closure_conflicts() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let valid_frozen = record_after_freeze(vec![
        target,
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
    ])?;
    let mut frozen_parts = record_parts(&valid_frozen);
    frozen_parts.targets = vec![target, target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut unsorted_parts = record_parts(&valid_frozen);
    unsorted_parts.targets.reverse();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(unsorted_parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let awaiting = record_after_acknowledgement()?;
    let mut duplicate_acknowledgements = record_parts(&awaiting);
    duplicate_acknowledgements.acknowledgements.push(
        duplicate_acknowledgements
            .acknowledgements
            .first()
            .copied()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?,
    );
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(duplicate_acknowledgements, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let foreign = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut outside_closure = record_parts(&awaiting);
    outside_closure.acknowledgements = vec![foreign];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(outside_closure, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn durable_authorized_record_bounds_reserved_targets() -> Result<(), ErasureErrorV1> {
    let submitted = record_after_submit()?;
    let authorized_state = submitted.state().transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut parts = record_parts(&submitted);
    parts.state = authorized_state;
    parts.authorize_provenance = Some(reference(9));
    parts.reserved_targets = (0..ERASURE_MAX_INVENTORY_RESULTS)
        .map(indexed_target)
        .collect();
    assert!(ErasureCoordinatorRecordV1::from_parts(parts.clone(), reference(2)).is_ok());
    parts
        .reserved_targets
        .push(indexed_target(ERASURE_MAX_INVENTORY_RESULTS));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn durable_frozen_record_bounds_required_targets() -> Result<(), ErasureErrorV1> {
    let targets = (0..ERASURE_MAX_INVENTORY_RESULTS)
        .map(indexed_target)
        .collect::<Vec<_>>();
    let frozen = record_after_freeze(targets)?;
    assert_eq!(frozen.targets().len(), ERASURE_MAX_INVENTORY_RESULTS);
    let mut parts = record_parts(&frozen);
    parts
        .targets
        .push(indexed_target(ERASURE_MAX_INVENTORY_RESULTS));
    parts.freeze_admission = Some(ErasureFreezeAdmissionV1 {
        freeze_position: 10,
        provenance: reference(9),
        target_closure: target_closure_digest(&parts.targets),
    });
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn durable_record_freeze_reservation_and_admission_bindings_are_checked(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let submitted = record_after_submit()?;
    let authorized_state = submitted.state().transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut authorized = record_parts(&submitted);
    authorized.state = authorized_state;
    authorized.authorize_provenance = Some(reference(9));
    authorized.reserved_targets = vec![target];
    assert!(ErasureCoordinatorRecordV1::from_parts(authorized.clone(), reference(2)).is_ok());

    let mut duplicate_reservation = authorized.clone();
    duplicate_reservation.reserved_targets = vec![target, target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(duplicate_reservation, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut authorized_with_admission = authorized;
    authorized_with_admission.freeze_admission = Some(ErasureFreezeAdmissionV1 {
        freeze_position: 10,
        provenance: reference(9),
        target_closure: target_closure_digest(&[target]),
    });
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(authorized_with_admission, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let frozen = record_after_freeze(vec![target])?;
    let mut frozen_without_admission = record_parts(&frozen);
    frozen_without_admission.freeze_admission = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_without_admission, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut frozen_with_bad_admission = record_parts(&frozen);
    frozen_with_bad_admission.freeze_admission = Some(ErasureFreezeAdmissionV1 {
        freeze_position: 10,
        provenance: reference(9),
        target_closure: reference(99),
    });
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_with_bad_admission, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut frozen_with_bad_provenance = record_parts(&frozen);
    frozen_with_bad_provenance
        .freeze_admission
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .provenance = reference(99);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_with_bad_provenance, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut frozen_with_bad_position = record_parts(&frozen);
    frozen_with_bad_position
        .freeze_admission
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .freeze_position = 99;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_with_bad_position, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut frozen_with_reservation = record_parts(&frozen);
    frozen_with_reservation.reserved_targets = vec![target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_with_reservation, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let complete = complete_record()?;
    let mut terminal_without_receipt = record_parts(&complete);
    terminal_without_receipt.receipt = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(terminal_without_receipt, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut terminal_without_input = record_parts(&complete);
    terminal_without_input.receipt_input = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(terminal_without_input, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_authorized_shape_checks_each_persisted_field() -> Result<(), ErasureErrorV1> {
    let submitted = record_after_submit()?;
    let authorized_state = submitted.state().transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut authorized = record_parts(&submitted);
    authorized.state = authorized_state;
    authorized.authorize_provenance = Some(reference(9));

    let mut with_targets = authorized.clone();
    with_targets.targets = vec![target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_targets, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut with_acknowledgements = authorized.clone();
    with_acknowledgements.acknowledgements = vec![acknowledgement];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_acknowledgements, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut with_receipt = authorized.clone();
    with_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut with_receipt_input = authorized;
    with_receipt_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_receipt_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn durable_record_lifecycle_checks_reject_independent_receipt_fields() -> Result<(), ErasureErrorV1>
{
    let submitted = record_after_submit()?;
    let mut submitted_receipt = record_parts(&submitted);
    submitted_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(submitted_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut submitted_input = record_parts(&submitted);
    submitted_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(submitted_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let frozen = record_after_freeze(vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
    ])?;
    let mut frozen_receipt = record_parts(&frozen);
    frozen_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut frozen_input = record_parts(&frozen);
    frozen_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let dispatched = record_after_acknowledgement()?;
    let mut dispatched_receipt = record_parts(&dispatched);
    dispatched_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(dispatched_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut dispatched_input = record_parts(&dispatched);
    dispatched_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(dispatched_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn durable_terminal_record_checks_reject_independent_receipt_mismatches(
) -> Result<(), ErasureErrorV1> {
    let record = complete_record()?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.terminal_state = reference(99);
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.lifecycle = ErasureLifecycleV1::PartialFailure;
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.coordinator = reference(99);
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.request = reference(99);
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.required_targets.clear();
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.acknowledgements.clear();
    })?;

    let mut altered_state = record_parts(&record);
    altered_state.state.pending_owners = vec![reference(99)];
    altered_state
        .receipt
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .0
        .terminal_state = altered_state.state.state_digest();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(altered_state, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn coordinator_trait_interface_covers_each_lifecycle_operation() -> Result<(), ErasureErrorV1> {
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted_request = request()?;
    let submitted = {
        let api: &mut dyn ErasureCoordinator = &mut coordinator;
        let submitted = api.submit(submitted_request.clone())?;
        assert_eq!(
            api.authorize(reference(1), reference(9))?.lifecycle(),
            ErasureLifecycleV1::Authorized
        );
        assert_eq!(
            api.freeze_access(
                reference(1),
                change(
                    ErasureLifecycleV1::AccessFrozen,
                    Some(10),
                    Vec::new(),
                    Vec::new(),
                ),
            )?
            .lifecycle(),
            ErasureLifecycleV1::AccessFrozen
        );
        assert_eq!(
            api.dispatch_destruction(reference(1), reference(9))?
                .lifecycle(),
            ErasureLifecycleV1::DestructionDispatched
        );
        assert_eq!(
            api.acknowledge(reference(1), acknowledgement)?.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
        submitted
    };
    assert_eq!(submitted.lifecycle(), ErasureLifecycleV1::Submitted);
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let terminal = awaiting.transition({
        let mut transition = change(
            ErasureLifecycleV1::Complete,
            awaiting.freeze_position(),
            Vec::new(),
            Vec::new(),
        );
        transition.acknowledged_targets = vec![acknowledgement.target];
        transition.provenance = reference(4);
        transition
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.inventories.artifacts = vec![inventory_result(acknowledgement.target)];
    let api: &mut dyn ErasureCoordinator = &mut coordinator;
    assert_eq!(
        api.finalize(reference(1), input)?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    let persisted = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(persisted.request(), &submitted_request);
    assert_eq!(persisted.state().lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(persisted.targets(), &[acknowledgement.target]);
    assert_eq!(persisted.acknowledgements(), &[acknowledgement]);
    assert!(persisted.receipt().is_some());
    assert!(persisted.receipt_input().is_some());
    assert_eq!(persisted.authorize_provenance(), Some(reference(9)));
    assert_eq!(persisted.freeze_provenance(), Some(reference(9)));
    assert_eq!(persisted.dispatch_provenance(), Some(reference(9)));
    Ok(())
}

#[test]
fn coordinator_finalize_from_dispatched_state_rechecks_authority() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let dispatched = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let awaiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        dispatched.freeze_position(),
        Vec::new(),
        Vec::new(),
    ))?;
    let terminal = awaiting.transition(change(
        ErasureLifecycleV1::PartialFailure,
        awaiting.freeze_position(),
        vec![target.replica_id],
        Vec::new(),
    ))?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![target.replica_id],
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.required_targets = vec![target];
    input.provenance = reference(9);
    input.inventories.artifacts = vec![inventory_result(target)];
    coordinator.port.receipt_error = Some(ErasureErrorV1::PolicyConflict);
    assert_eq!(
        coordinator.finalize(reference(1), input),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator
            .existing(reference(1))
            .map(ErasureStateV1::lifecycle),
        Some(ErasureLifecycleV1::DestructionDispatched)
    );
    Ok(())
}

#[test]
fn coordinator_persists_host_freeze_provenance() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.admitted_freeze_provenance = Some(reference(42));
    port.admitted_freeze_position = Some(42);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    let frozen = coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    {
        let records = coordinator.port.records.borrow();
        let persisted = records.first().ok_or(ErasureErrorV1::ProvenanceMissing)?;
        assert_eq!(persisted.freeze_provenance(), Some(reference(42)));
        assert_eq!(persisted.state().provenance(), reference(42));
        assert_eq!(persisted.state().freeze_position(), Some(42));
    }
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    Ok(())
}

#[test]
fn coordinator_exposes_unknown_and_port_failure_contracts() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut unknown =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    assert_eq!(
        unknown.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new()
            )
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.acknowledge(
            reference(1),
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged)
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new()
            )
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut load_failed = test_port(true, Vec::new());
    load_failed.load_error = Some(ErasureErrorV1::KeyRegistryUnavailable);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(load_failed, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::KeyRegistryUnavailable)
    );

    let mut commit_failed = test_port(true, Vec::new());
    commit_failed.commit_error = Some(ErasureErrorV1::ReceiptCommitFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(commit_failed, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );

    let mut freeze_failed = test_port(true, vec![target]);
    freeze_failed.freeze_error = Some(ErasureErrorV1::AccessFreezeFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(freeze_failed, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::AccessFreezeFailed)
    );

    let mut dispatch_failed = test_port(true, vec![target]);
    dispatch_failed.dispatch_error = Some(ErasureErrorV1::KeyDestructionFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(dispatch_failed, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );

    Ok(())
}

#[test]
fn dispatch_intent_is_persisted_before_host_dispatch() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.dispatch_error = Some(ErasureErrorV1::KeyDestructionFailed);
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    let persisted = restart_port
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        persisted.state().lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    assert_eq!(persisted.dispatch_provenance(), Some(reference(9)));

    let mut retry_port = restart_port;
    retry_port.dispatch_error = None;
    let mut restarted = ErasureCoordinatorStateMachineV1::new(retry_port, reference(2));
    assert_eq!(
        restarted
            .dispatch_destruction(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::DestructionDispatched
    );
    Ok(())
}

#[test]
fn durable_record_envelope_round_trips_every_persisted_shape() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let submitted = record_after_submit()?;
    let authorized_state = submitted.state().transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut authorized_parts = record_parts(&submitted);
    authorized_parts.state = authorized_state;
    authorized_parts.reserved_targets = vec![target];
    authorized_parts.authorize_provenance = Some(reference(9));
    let authorized = ErasureCoordinatorRecordV1::from_parts(authorized_parts, reference(2))?;
    let records = [
        submitted,
        authorized,
        record_after_freeze(vec![target])?,
        record_after_acknowledgement()?,
        complete_record()?,
    ];
    for record in records {
        let bytes = record.to_canonical_cbor()?;
        let decoded = ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes)?;
        assert_eq!(decoded, record);
        assert_eq!(decoded.to_canonical_cbor()?, bytes);
    }
    Ok(())
}

#[test]
fn coordinator_rehydration_surfaces_port_load_failure() -> Result<(), ErasureErrorV1> {
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.port.load_error = Some(ErasureErrorV1::KeyRegistryUnavailable);
    assert_eq!(
        coordinator.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyRegistryUnavailable)
    );
    Ok(())
}

#[test]
fn coordinator_rejects_a_host_freeze_closure_mismatch() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.admitted_freeze_closure = Some(reference(99));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;

    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn freeze_retry_reuses_the_durable_target_reservation_after_restart() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.commit_error_on_call = Some(4);
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;

    let requested = change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        coordinator.freeze_inventory(reference(1), requested.clone()),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        coordinator
            .port
            .records
            .borrow()
            .first()
            .map(ErasureCoordinatorRecordV1::reserved_targets),
        Some([target].as_slice())
    );

    let later_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    drop(coordinator);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    restarted.port.targets = vec![later_target];
    restarted.port.admitted_freeze_position = Some(99);
    restarted.port.admitted_freeze_provenance = Some(reference(99));
    let retry = restarted.freeze_inventory(reference(1), requested)?;
    assert_eq!(retry.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(retry.freeze_position(), Some(10));
    assert_eq!(retry.provenance(), reference(9));
    let records = restarted.port.records.borrow();
    assert_eq!(records[0].targets, vec![target]);
    assert_eq!(records[0].reserved_targets, Vec::new());
    Ok(())
}

#[test]
fn coordinator_rejects_receipt_admission_after_terminal_derivation() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.receipt_error = Some(ErasureErrorV1::TrustSnapshotInvalid);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let mut negative = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative);
    negative.target = target;
    coordinator.acknowledge(reference(1), negative)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = change(
        ErasureLifecycleV1::PartialFailure,
        awaiting.freeze_position(),
        Vec::new(),
        vec![negative.owner],
    );
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![negative],
        Vec::new(),
        vec![negative.owner],
    );
    input.terminal_state = terminal.state_digest();
    input.required_targets = vec![target];
    input.inventories.artifacts = vec![inventory_result(target)];
    input.receipt_digest = reference(99);
    assert_eq!(
        coordinator.finalize(reference(1), input),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    assert_eq!(
        coordinator
            .port
            .receipt_inputs
            .borrow()
            .last()
            .map(|input| input.receipt_digest),
        Some(reference(0))
    );
    Ok(())
}

#[test]
fn coordinator_freezes_closure_and_commits_only_derived_terminal_outcomes(
) -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    assert_eq!(
        coordinator.authorize(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    let mut conflicting_freeze = change(
        ErasureLifecycleV1::Authorized,
        Some(11),
        Vec::new(),
        Vec::new(),
    );
    conflicting_freeze.provenance = reference(8);
    assert_eq!(
        coordinator.freeze_inventory(reference(1), conflicting_freeze),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::DestructionDispatched
    );
    assert_eq!(
        coordinator
            .dispatch_destruction(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::DestructionDispatched
    );
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.acknowledge(reference(1), ack)?,
        coordinator.acknowledge(reference(1), ack)?
    );
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    let injected = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    assert_eq!(
        coordinator.acknowledge(reference(1), injected),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut conflicting = ack;
    conflicting.outcome = ErasureAcknowledgementOutcomeV1::Negative;
    assert_eq!(
        coordinator.acknowledge(reference(1), conflicting),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn coordinator_normalizes_core_derived_finalize_fields_and_retries() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![ack.target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = change(
        ErasureLifecycleV1::Complete,
        awaiting.freeze_position(),
        Vec::new(),
        Vec::new(),
    );
    terminal_change.acknowledged_targets = vec![ack.target];
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut complete_input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    complete_input.terminal_state = terminal.state_digest();
    complete_input.inventories.artifacts = vec![inventory_result(ack.target)];
    complete_input.replay_claim = ErasureReplayClaimV1::Exact;
    let mut conflicting_first_finalize = complete_input.clone();
    conflicting_first_finalize.required_targets.clear();
    let committed = coordinator.finalize(reference(1), conflicting_first_finalize)?;
    assert_eq!(committed.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(
        committed.replay_claim(),
        ErasureReplayClaimV1::StructuralOnly
    );
    let mut conflicting_identity = complete_input.clone();
    conflicting_identity.terminal_state = reference(99);
    assert_eq!(
        coordinator.finalize(reference(1), complete_input)?,
        committed
    );
    let terminal_state = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(coordinator.acknowledge(reference(1), ack)?, terminal_state);
    assert_eq!(
        coordinator.finalize(reference(1), conflicting_identity),
        Ok(committed)
    );
    assert_eq!(
        coordinator
            .existing(reference(1))
            .map(ErasureStateV1::lifecycle),
        Some(ErasureLifecycleV1::Complete)
    );
    Ok(())
}

#[test]
fn coordinator_rejects_each_conflicting_receipt_evidence_retry() -> Result<(), ErasureErrorV1> {
    assert_conflicting_receipt_retry(|input| {
        input.inventories.artifacts[0].transition.reason = reference(99);
    })?;
    assert_conflicting_receipt_retry(|input| input.policy = reference(99))?;
    assert_conflicting_receipt_retry(|input| input.trust = reference(99))?;
    assert_conflicting_receipt_retry(|input| input.provenance = reference(99))?;
    assert_conflicting_receipt_retry(|input| input.issue_position = 99)?;
    assert_conflicting_receipt_retry(|input| input.signature = reference(99))?;
    Ok(())
}

#[test]
fn coordinator_derives_partial_failure_for_a_missing_frozen_target() -> Result<(), ErasureErrorV1> {
    let missing = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut negative = missing;
    negative.outcome = ErasureAcknowledgementOutcomeV1::Negative;
    let port = test_port(true, vec![missing.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), negative)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = change(
        ErasureLifecycleV1::PartialFailure,
        awaiting.freeze_position(),
        Vec::new(),
        vec![negative.owner],
    );
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![negative],
        Vec::new(),
        vec![negative.owner],
    );
    input.terminal_state = terminal.state_digest();
    input.required_targets = vec![missing.target];
    input.inventories.artifacts = vec![inventory_result(missing.target)];
    assert_eq!(
        coordinator.finalize(reference(1), input)?.lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}
#[test]
fn coordinator_rejects_premature_finalize_and_preserves_awaiting_acknowledgements(
) -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut second = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    second.owner = second.target.replica_id;
    let port = test_port(true, vec![first.target, second.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                vec![first],
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), first)?;
    assert_eq!(
        coordinator.acknowledge(reference(1), second)?.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}
#[test]
fn coordinator_rejects_unauthenticated_submission_and_unsupported_version(
) -> Result<(), ErasureErrorV1> {
    let port = test_port(false, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut value = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[1] = test_uint(2);
    assert_eq!(
        decode_receipt(&value),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    Ok(())
}
#[test]
fn receipt_history_requires_a_resolved_monotonic_terminal_chain() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let terminal = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
        ],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement(
            1,
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    let receipt = ErasureReceiptV1::new(input)?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: vec![terminal.clone()],
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let resolver = TestResolver {
        states: vec![submitted, authorized, frozen, dispatched, waiting, terminal],
        unavailable: false,
    };
    receipt.verify_history(&resolver)?;
    assert_eq!(
        receipt.verify_history(&FailingPredecessorResolver {
            terminal: resolver
                .states
                .last()
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: true,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
#[test]
fn receipt_inventory_codes_and_strict_decoder_paths_are_publicly_exercised(
) -> Result<(), ErasureErrorV1> {
    let encoded = receipt_inventory_encoding()?;
    receipt_inventory_decoder_rejections(&encoded)
}

fn receipt_inventory_encoding() -> Result<Vec<u8>, ErasureErrorV1> {
    let mut acknowledgements = vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(3, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(4, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(5, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(6, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(7, ErasureAcknowledgementOutcomeV1::Acknowledged),
    ];
    acknowledgements[1].target.artifact_class = ErasureArtifactClassV1::ReproManifest;
    acknowledgements[1].target.key_role = ErasureKeyRoleV1::Signing;
    acknowledgements[2].target.artifact_class = ErasureArtifactClassV1::CausalTrace;
    acknowledgements[2].target.key_role = ErasureKeyRoleV1::BackupEnvelope;
    acknowledgements[3].target.artifact_class = ErasureArtifactClassV1::ConformanceReport;
    acknowledgements[3].target.key_role = ErasureKeyRoleV1::ReplicaTransport;
    acknowledgements[4].target.artifact_class = ErasureArtifactClassV1::CalibrationReport;
    acknowledgements[5].target.artifact_class = ErasureArtifactClassV1::Export;
    acknowledgements[6].target.artifact_class = ErasureArtifactClassV1::ForkOrSnapshot;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        acknowledgements.clone(),
        Vec::new(),
        Vec::new(),
    );
    input.inventories.artifacts = vec![
        inventory_result(acknowledgements[0].target),
        inventory_result(acknowledgements[4].target),
        inventory_result(acknowledgements[5].target),
        inventory_result(acknowledgements[6].target),
    ];
    input.inventories.keys = vec![inventory_result(acknowledgements[1].target)];
    input.inventories.keys[0].category = ErasureInventoryCategoryV1::Key;
    input.inventories.replicas = vec![inventory_result(acknowledgements[2].target)];
    input.inventories.replicas[0].category = ErasureInventoryCategoryV1::Replica;
    input.inventories.backups = vec![inventory_result(acknowledgements[3].target)];
    input.inventories.backups[0].category = ErasureInventoryCategoryV1::Backup;
    let expected = ErasureReceiptV1::new(input)?;
    let encoded = expected.to_canonical_cbor()?;
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&encoded)?, expected);
    Ok(encoded)
}

fn receipt_inventory_decoder_rejections(encoded: &[u8]) -> Result<(), ErasureErrorV1> {
    let mut unknown_codes = public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(encoded)?)?;
    let mut tampered_digest = unknown_codes.clone();
    let Value::Array(fields) = &mut tampered_digest else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[16] = test_digest(reference(99));
    assert_eq!(
        decode_receipt(&tampered_digest),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let Value::Array(fields) = &mut unknown_codes else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(target) = &mut targets[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    target[0] = test_uint(7);
    assert_eq!(
        decode_receipt(&unknown_codes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unknown_role = public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(encoded)?)?;
    let Value::Array(fields) = &mut unknown_role else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(target) = &mut targets[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    target[2] = test_uint(4);
    assert_eq!(
        decode_receipt(&unknown_role),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unordered_targets =
        public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(encoded)?)?;
    let Value::Array(fields) = &mut unordered_targets else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    targets.swap(0, 1);
    assert_eq!(
        decode_receipt(&unordered_targets),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let noncanonical = [&[0x98, 18][..], &encoded[1..]].concat();
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    for invalid in [
        &[0x9f, 0xff][..],
        &[0xbf, 0xff][..],
        &[0x19, 0, 1][..],
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x9a, 0xff, 0xff, 0xff, 0xff][..],
        &[
            0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
            0x81, 0x81, 0x81, 0x00,
        ][..],
    ] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(invalid),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}
#[test]
fn coordinator_and_receipt_reject_each_public_injected_or_stale_seam() -> Result<(), ErasureErrorV1>
{
    coordinator_public_seam_rejections()?;
    receipt_public_seam_rejections();
    Ok(())
}

fn coordinator_public_seam_rejections() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    let frozen = coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(frozen.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                vec![ack],
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn receipt_public_seam_rejections() {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut stale_issue = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    stale_issue.issue_position = 9;
    assert_eq!(
        ErasureReceiptV1::new(stale_issue),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut invented_ack = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    invented_ack.acknowledgements[0].target =
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    assert_eq!(
        ErasureReceiptV1::new(invented_ack),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut mismatched_owner = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    mismatched_owner.acknowledgements[0].owner = reference(99);
    assert_eq!(
        ErasureReceiptV1::new(mismatched_owner),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut missing_inventory = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    missing_inventory.inventories.artifacts.clear();
    assert_eq!(
        ErasureReceiptV1::new(missing_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut oversized = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![reference(8)],
        Vec::new(),
    );
    oversized.acknowledgements = vec![ack; ERASURE_MAX_INVENTORY_RESULTS + 1];
    assert_eq!(
        ErasureReceiptV1::new(oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut strengthened = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    strengthened.inventories.artifacts[0].transition.from = ErasureReplayClaimV1::StructuralOnly;
    strengthened.inventories.artifacts[0].transition.to = ErasureReplayClaimV1::Exact;
    assert_eq!(
        ErasureReceiptV1::new(strengthened),
        Err(ErasureErrorV1::PolicyConflict)
    );
    for invalid in [&[0x18, 0][..], &[0x1a, 0, 0, 0, 1][..], &[0x60, 0][..]] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(invalid),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
}

#[test]
fn receipt_public_inventory_and_closure_boundaries() {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut oversized_inventory = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![reference(8)],
        Vec::new(),
    );
    oversized_inventory.inventories.artifacts =
        vec![inventory_result(ack.target); ERASURE_MAX_INVENTORY_RESULTS + 1];
    assert_eq!(
        ErasureReceiptV1::new(oversized_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let second_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut incomplete_closure = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        vec![second_target.owner],
        Vec::new(),
    );
    incomplete_closure
        .required_targets
        .push(second_target.target);
    incomplete_closure
        .inventories
        .artifacts
        .push(inventory_result(second_target.target));
    assert_eq!(
        ErasureReceiptV1::new(incomplete_closure),
        Err(ErasureErrorV1::PolicyConflict)
    );
}

#[test]
fn codec_predicates_and_cbor_argument_widths_are_closed_at_the_public_boundary() {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let inventory = inventory_result(target);
    let mut inventories = ErasureReceiptInventoriesV1 {
        artifacts: Vec::new(),
        keys: Vec::new(),
        replicas: Vec::new(),
        backups: Vec::new(),
    };
    inventories.artifacts.push(inventory);
    inventories.keys.push(ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Key,
        ..inventory
    });
    inventories.replicas.push(ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Replica,
        ..inventory
    });
    inventories.backups.push(ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Backup,
        ..inventory
    });
    assert!(!inventories_exceed_bound(&inventories));

    inventories.artifacts =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.artifacts.clear();
    inventories.keys =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.keys.clear();
    inventories.replicas =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.replicas.clear();
    inventories.backups =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.backups.clear();
    inventories.artifacts.push(inventory);
    inventories.keys.push(inventory);
    inventories.replicas.push(inventory);
    inventories.backups.push(inventory);

    for inventory in [
        &mut inventories.artifacts,
        &mut inventories.keys,
        &mut inventories.replicas,
        &mut inventories.backups,
    ] {
        let first = inventory[0];
        inventory.push(first);
        assert!(has_duplicate_by_inventory_target(inventory));
        inventory.clear();
    }
    inventories.artifacts =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.artifacts.clear();
    inventories.keys =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.keys.clear();
    inventories.replicas =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.replicas.clear();
    inventories.backups =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.backups.clear();
}

#[test]
fn inventory_category_duplicates_are_rejected() {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory_result(target), inventory_result(target)],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        }
    ));
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: vec![inventory_result(target), inventory_result(target)],
            replicas: Vec::new(),
            backups: Vec::new(),
        }
    ));
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: vec![inventory_result(target), inventory_result(target)],
            backups: Vec::new(),
        }
    ));
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: vec![inventory_result(target), inventory_result(target)],
        }
    ));
}

#[test]
fn owner_sets_are_closed_at_the_public_boundary() {
    let owner = reference(70);
    assert!(invalid_owner_sets(&[owner], &[owner]));
    assert!(!invalid_owner_sets(&[reference(70)], &[reference(71)]));
}

#[test]
fn cbor_argument_widths_are_closed_at_the_public_boundary() {
    assert_eq!(cbor_argument(&[0x01, 0x00], 0, 25), Ok((256, 2)));
    assert_eq!(
        cbor_argument(&[0x00, 0x01, 0x00, 0x00], 0, 26),
        Ok((65_536, 4))
    );
    assert_eq!(
        cbor_argument(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], 0, 27),
        Ok((4_294_967_296, 8))
    );
    assert_eq!(
        cbor_argument(&[0x00, 0x00], 0, 25),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_argument_bytes(&[0x00, 0x00, 0x00, 0x00], 0, 4, 65_536),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_item_end(&[0x01], 0, 16, ERASURE_MAX_INVENTORY_RESULTS),
        Ok(1)
    );
    assert_eq!(
        cbor_item_end(&[0x42, 0xaa], 0, 0, ERASURE_MAX_INVENTORY_RESULTS),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_shape_is_bounded(&[0x83, 0x01, 0x01, 0x01], 2,),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_item_end(&[0xf8, 0x17], 0, 0, ERASURE_MAX_INVENTORY_RESULTS),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_item_end(&[0xf7], 0, 0, ERASURE_MAX_INVENTORY_RESULTS),
        Err(ErasureErrorV1::InvalidEncoding)
    );
}

#[test]
fn coordinator_requires_host_admission_for_acknowledgements() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut port = test_port(true, vec![ack.target]);
    port.acknowledgement_admitted = false;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}
#[test]
fn public_erasure_failure_seams_cover_history_ordering_and_cbor_tails() -> Result<(), ErasureErrorV1>
{
    let receipt = receipt()?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: true,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut unordered = public_receipt_value(&receipt)?;
    let Value::Array(fields) = &mut unordered else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    artifacts.push(artifacts[0].clone());
    assert_eq!(
        decode_receipt(&unordered),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    for malformed in [
        &[0x58, 1][..],
        &[0x81, 0x58, 2, 0][..],
        &[0x81, 0x1a, 0, 0, 0][..],
        &[0x81, 0x58, 2, 0, 0][..],
        &[0x81, 0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x81, 0x78, 2, 0][..],
        &[0x81, 0x98, 24][..],
        &[0x81, 0x7f, 0xff][..],
    ] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn codec_size_and_shape_limits_return_closed_errors() {
    assert_eq!(
        encode_limited(&Value::Text("oversized".to_owned()), 0),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        array(&Value::Array(vec![Value::Null, Value::Null]), 1),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(array(&Value::Null, 1), Err(ErasureErrorV1::InvalidEncoding));
    assert_eq!(
        decode_limited(
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            32,
            4,
        ),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_limited(&[0xf7], 32, 4),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_limited(&[0xe0], 32, 4),
        Err(ErasureErrorV1::InvalidEncoding)
    );
}

#[test]
fn request_is_canonical_and_bounded() -> Result<(), ErasureErrorV1> {
    let first = request()?;
    let second = ErasureRequestV1::new(request_input(vec![reference(7), reference(8)]))?;
    let bytes = first.to_canonical_cbor()?;
    assert_eq!(bytes, second.to_canonical_cbor()?);
    assert_eq!(ErasureRequestV1::from_canonical_cbor(&bytes)?, first);
    assert_eq!(first.reference(), reference(1));
    assert_eq!(
        ErasureRequestV1::new(request_input(Vec::new())),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(request_input(vec![reference(7), reference(7)])),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut impossible = request_input(vec![reference(7)]);
    impossible.request_position = 11;
    assert_eq!(
        ErasureRequestV1::new(impossible),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn public_constants_display_and_state_digests_are_observable() -> Result<(), ErasureErrorV1> {
    assert_eq!(ERASURE_REQUEST_OR_STATE_MAX_BYTES, 1_048_576);
    assert_eq!(ERASURE_RECEIPT_MAX_BYTES, 16_777_216);
    assert_eq!(
        ErasureErrorV1::PolicyConflict.to_string(),
        "erasure contract error 4"
    );
    let first = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let second = ErasureStateV1::submitted(reference(4), reference(2), reference(3))?;
    assert_ne!(first.state_digest(), second.state_digest());
    Ok(())
}
#[test]
fn codecs_refuse_trailing_unknown_and_maps() -> Result<(), ErasureErrorV1> {
    let mut trailing = request()?.to_canonical_cbor()?;
    trailing.push(0);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unsupported = public_request_value(&request()?)?;
    let Value::Array(fields) = &mut unsupported else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[1] = test_uint(2);
    let mut bytes = Vec::new();
    ciborium::into_writer(&unsupported, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&bytes),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    let map = Value::Map(vec![(test_text("request"), test_digest(reference(1)))]);
    let mut map_bytes = Vec::new();
    ciborium::into_writer(&map, &mut map_bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&map_bytes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn decoders_refuse_unknown_closed_codes() -> Result<(), ErasureErrorV1> {
    let mut invalid_scope = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut invalid_scope else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[4] = test_uint(5);
    }
    assert_eq!(
        decode_request(&invalid_scope),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let mut invalid_lifecycle = public_state_value(&submitted)?;
    {
        let Value::Array(fields) = &mut invalid_lifecycle else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[3] = test_uint(8);
    }
    assert_eq!(
        decode_state(&invalid_lifecycle),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut invalid_claim = public_state_value(&submitted)?;
    {
        let Value::Array(fields) = &mut invalid_claim else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[8] = test_uint(5);
    }
    assert_eq!(
        decode_state(&invalid_claim),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let canonical = receipt()?;
    let mut invalid_outcome = public_receipt_value(&canonical)?;
    {
        let Value::Array(fields) = &mut invalid_outcome else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgements) = &mut fields[7] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgement) = &mut acknowledgements[0] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        acknowledgement[3] = test_uint(3);
    }
    assert_eq!(
        decode_receipt(&invalid_outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn public_decoders_reject_terminal_and_inventory_conflicts() -> Result<(), ErasureErrorV1> {
    let mut invalid_category = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut invalid_category else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventory) = &mut artifacts[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    inventory[0] = test_uint(99);
    assert_eq!(
        decode_receipt(&invalid_category),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut mismatched_category = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut mismatched_category else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventory) = &mut artifacts[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    inventory[0] = test_uint(1);
    assert_eq!(
        decode_receipt(&mismatched_category),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let waiting = dispatched()?.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let mut complete_change = change(
        ErasureLifecycleV1::Complete,
        Some(10),
        Vec::new(),
        Vec::new(),
    );
    complete_change.acknowledged_targets =
        vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target];
    let complete = waiting.transition(complete_change)?;
    let mut invalid_complete = public_state_value(&complete)?;
    let Value::Array(fields) = &mut invalid_complete else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[6] = Value::Array(vec![test_digest(reference(7))]);
    assert_eq!(
        decode_state(&invalid_complete),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let partial = waiting.transition(change(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        vec![reference(7)],
        Vec::new(),
    ))?;
    let mut invalid_partial = public_state_value(&partial)?;
    let Value::Array(fields) = &mut invalid_partial else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[6] = Value::Array(Vec::new());
    fields[7] = Value::Array(Vec::new());
    assert_eq!(
        decode_state(&invalid_partial),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}
#[test]
fn request_decoder_refuses_noncanonical_and_wrong_shapes() -> Result<(), ErasureErrorV1> {
    let mut wrong_tag_type = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut wrong_tag_type else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = Value::Bool(false);
    }
    assert_eq!(
        decode_request(&wrong_tag_type),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut wrong_scope_type = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut wrong_scope_type else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[4] = Value::Bool(false);
    }
    assert_eq!(
        decode_request(&wrong_scope_type),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut empty_selectors = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut empty_selectors else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[5] = Value::Array(Vec::new());
    }
    assert_eq!(
        decode_request(&empty_selectors),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    assert_eq!(
        decode_request(&Value::Array(vec![Value::Null; 13])),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_request(&Value::Null),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_request(&Value::Array(Vec::new())),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let canonical = request()?.to_canonical_cbor()?;
    let noncanonical = [&[0x98, 12][..], &canonical[1..]].concat();
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn receipt_decoder_refuses_unsorted_acknowledgements() -> Result<(), ErasureErrorV1> {
    let canonical = receipt()?;
    let mut unsorted = public_receipt_value(&canonical)?;
    {
        let Value::Array(fields) = &mut unsorted else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgements) = &mut fields[7] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        acknowledgements.swap(0, 1);
    }
    assert_eq!(decode_receipt(&unsorted), Err(ErasureErrorV1::ScopeInvalid));
    Ok(())
}
#[test]
fn receipt_decoder_exercises_each_public_field_boundary() -> Result<(), ErasureErrorV1> {
    for index in [2_usize, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 18] {
        let mut malformed = public_receipt_value(&receipt()?)?;
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[index] = Value::Null;
        assert!(matches!(
            decode_receipt(&malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        ));
    }
    for (index, value) in [(4_usize, test_uint(99)), (11, test_uint(99))] {
        let mut malformed = public_receipt_value(&receipt()?)?;
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[index] = value;
        assert_eq!(
            decode_receipt(&malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }

    let canonical = receipt()?.to_canonical_cbor()?;
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let noncanonical = [&[0x99, 0, 19][..], &canonical[1..]].concat();
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn receipt_constructor_bounds_acknowledgements() {
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![
                acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative);
                ERASURE_MAX_REFERENCES + 1
            ],
            Vec::new(),
            Vec::new(),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}
#[test]
fn lifecycle_public_edges_and_terminality_are_closed() {
    assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::Authorized.permits(ErasureLifecycleV1::AccessFrozen));
    assert!(ErasureLifecycleV1::AccessFrozen.permits(ErasureLifecycleV1::DestructionDispatched));
    assert!(ErasureLifecycleV1::DestructionDispatched
        .permits(ErasureLifecycleV1::AwaitingAcknowledgements));
    assert!(ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::Complete));
    assert!(
        ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::PartialFailure)
    );
    assert!(!ErasureLifecycleV1::Rejected.permits(ErasureLifecycleV1::Submitted));
    assert!(ErasureLifecycleV1::Complete.is_terminal());
    assert!(ErasureLifecycleV1::PartialFailure.is_terminal());
    assert!(ErasureLifecycleV1::Rejected.is_terminal());
    assert!(!ErasureLifecycleV1::Authorized.is_terminal());
}
#[test]
fn lifecycle_is_monotonic_and_digest_linked() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert!(submitted
        .lifecycle()
        .permits(ErasureLifecycleV1::Authorized));
    assert!(submitted.lifecycle().permits(ErasureLifecycleV1::Rejected));
    assert!(!ErasureLifecycleV1::Complete.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::PartialFailure.is_terminal());
    assert_eq!(
        submitted.transition(change(
            ErasureLifecycleV1::Submitted,
            None,
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        submitted.transition(change(
            ErasureLifecycleV1::Rejected,
            None,
            vec![reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(
        authorized.transition(change(
            ErasureLifecycleV1::AccessFrozen,
            None,
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(
        frozen.transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(11),
            Vec::new(),
            Vec::new(),
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        vec![reference(7)],
        Vec::new(),
    ))?;
    assert_eq!(
        waiting.transition(change(
            ErasureLifecycleV1::Complete,
            Some(10),
            vec![reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let partial = waiting.transition(change(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        Vec::new(),
        vec![reference(7)],
    ))?;
    let partial_bytes = partial.to_canonical_cbor()?;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&partial_bytes)?,
        partial
    );
    let authorized_bytes = authorized.to_canonical_cbor()?;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&authorized_bytes)?,
        authorized
    );
    let mut tampered = authorized_bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&tampered),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
#[test]
fn owner_evidence_bounds_are_enforced_at_the_public_transition() -> Result<(), ErasureErrorV1> {
    let dispatched = dispatched()?;
    assert!(dispatched
        .transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            references(ERASURE_MAX_REFERENCES),
            Vec::new(),
        ))
        .is_ok());
    assert!(dispatched
        .transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            references(ERASURE_MAX_REFERENCES),
        ))
        .is_ok());
    assert_eq!(
        dispatched.transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            references(ERASURE_MAX_REFERENCES + 1),
            Vec::new(),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        dispatched.transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            references(ERASURE_MAX_REFERENCES + 1),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn receipt_order_is_arrival_independent_and_completion_is_strict() -> Result<(), ErasureErrorV1> {
    let low = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let high = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let first = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![high, low],
        Vec::new(),
        Vec::new(),
    ))?;
    let second = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![low, high],
        Vec::new(),
        Vec::new(),
    ))?;
    let bytes = first.to_canonical_cbor()?;
    assert_eq!(bytes, second.to_canonical_cbor()?);
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&bytes)?, first);
    let negative = acknowledgement(3, ErasureAcknowledgementOutcomeV1::Negative);
    let negative_owner = negative.owner;
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            vec![negative],
            Vec::new(),
            vec![negative_owner]
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![low],
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![low],
            vec![reference(9)],
            Vec::new()
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn safe_errors_are_closed_and_payload_free() {
    for code in 0..16 {
        assert_eq!(
            ErasureErrorV1::from_code(code).map(ErasureErrorV1::code),
            Ok(code)
        );
    }
    assert_eq!(
        ErasureErrorV1::from_code(16),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert!(!ErasureErrorV1::ArtifactDeletionFailed
        .to_string()
        .contains("payload"));
}

#[test]
fn every_closed_wire_enum_round_trips_at_its_public_seam() -> Result<(), ErasureErrorV1> {
    request_wire_enum_roundtrip()?;
    state_wire_enum_roundtrip()?;
    receipt_wire_enum_roundtrip()
}

fn request_wire_enum_roundtrip() -> Result<(), ErasureErrorV1> {
    for scope in [
        ErasureScopeV1::PrivateSubjectData,
        ErasureScopeV1::ConsentedSharedData,
        ErasureScopeV1::PublicRecord,
        ErasureScopeV1::Aggregate,
        ErasureScopeV1::StructuralAuditMetadata,
    ] {
        let mut input = request_input(vec![reference(7)]);
        input.scope = scope;
        let request = ErasureRequestV1::new(input)?;
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&request.to_canonical_cbor()?)?,
            request
        );
    }
    Ok(())
}

fn state_wire_enum_roundtrip() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let complete = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
        ],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let partial = waiting.transition(change(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        vec![reference(44)],
        Vec::new(),
    ))?;
    let rejected = submitted.transition(change(
        ErasureLifecycleV1::Rejected,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    for state in [
        submitted, authorized, frozen, dispatched, waiting, complete, partial, rejected,
    ] {
        let encoded = state.to_canonical_cbor()?;
        assert_eq!(ErasureStateV1::from_canonical_cbor(&encoded)?, state);
        assert_ne!(state.state_digest(), reference(0));
    }

    for claim in [
        ErasureReplayClaimV1::Exact,
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ErasureReplayClaimV1::StructuralOnly,
        ErasureReplayClaimV1::UnverifiableArtifactsMissing,
        ErasureReplayClaimV1::IncompatibleProfile,
    ] {
        let mut transition = change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new());
        transition.replay_claim = claim;
        let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
            .transition(transition)?;
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&state.to_canonical_cbor()?)?,
            state
        );
    }
    Ok(())
}

fn receipt_wire_enum_roundtrip() -> Result<(), ErasureErrorV1> {
    let receipt = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative),
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Stale),
        ],
        Vec::new(),
        vec![reference(41), reference(42)],
    ))?;
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&receipt.to_canonical_cbor()?)?,
        receipt
    );
    Ok(())
}

#[test]
fn request_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let mut malformed = public_request_value(&request)?;
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = test_text("other-contract");
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = test_text("ERQ1");
        fields[2] = Value::Bool(false);
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[2] = test_digest(reference(1));
        fields[5] = Value::Array(vec![test_digest(reference(9)), test_digest(reference(8))]);
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(request_input(vec![
            reference(7);
            ERASURE_MAX_REFERENCES + 1
        ])),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES + 1]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES]),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn state_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(
        submitted.transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            vec![reference(7), reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut invalid_state = public_state_value(&submitted)?;
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[6] = Value::Array(vec![test_digest(reference(7)), test_digest(reference(7))]);
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[6] = Value::Array(Vec::new());
        state_fields[9] = test_digest(reference(8));
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[3] = test_uint(ErasureLifecycleV1::PartialFailure.code());
        state_fields[4] = test_uint(10);
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn receipt_constructor_rejects_retained_wire_boundaries() {
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Authorized,
            Vec::new(),
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            Vec::new(),
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Stale)],
            vec![reference(8)],
            vec![reference(8)]
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn public_state_owner_accessors_and_freeze_rejection_remain_exact() -> Result<(), ErasureErrorV1> {
    let dispatched = dispatched()?;
    let pending = vec![reference(7)];
    let failed = vec![reference(8)];
    let awaiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        pending.clone(),
        failed.clone(),
    ))?;
    assert_eq!(awaiting.pending_owners(), pending);
    assert_eq!(awaiting.failed_owners(), failed);

    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target, acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new(),),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let targets = (0..ERASURE_MAX_INVENTORY_RESULTS)
        .map(|index| ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: indexed_reference(index),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: indexed_reference(index + 1),
            replica_set: reference(30),
            replica_id: indexed_reference(index + 2),
        })
        .collect();
    let port = test_port(true, targets);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator
            .freeze_inventory(
                reference(1),
                change(
                    ErasureLifecycleV1::AccessFrozen,
                    Some(10),
                    Vec::new(),
                    Vec::new(),
                ),
            )?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    Ok(())
}

#[test]
fn public_freeze_rejects_a_required_target_closure_over_the_bound() -> Result<(), ErasureErrorV1> {
    let targets = (0..=ERASURE_MAX_INVENTORY_RESULTS)
        .map(|index| ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: indexed_reference(index),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: indexed_reference(index + 1),
            replica_set: reference(30),
            replica_id: indexed_reference(index + 2),
        })
        .collect();
    let port = test_port(true, targets);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn public_receipt_history_rejects_each_terminal_and_predecessor_mismatch(
) -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let terminal = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![acknowledgement.target],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    let receipt = ErasureReceiptV1::new(input.clone())?;
    let resolver = TestResolver {
        states: vec![
            submitted.clone(),
            authorized.clone(),
            frozen.clone(),
            dispatched.clone(),
            waiting.clone(),
            terminal.clone(),
        ],
        unavailable: false,
    };
    receipt.verify_history(&resolver)?;

    history_terminal_mismatches(&input, &resolver, waiting.state_digest())?;
    history_predecessor_mismatches(
        &input,
        &submitted,
        &authorized,
        &frozen,
        &dispatched,
        &terminal,
    )?;
    Ok(())
}

fn history_terminal_mismatches(
    input: &ErasureReceiptInputV1,
    resolver: &TestResolver,
    waiting: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    for mismatch in 0..4 {
        let mut altered = input.clone();
        match mismatch {
            0 => altered.request = reference(99),
            1 => {
                altered.lifecycle = ErasureLifecycleV1::PartialFailure;
                altered.acknowledgements[0].outcome = ErasureAcknowledgementOutcomeV1::Negative;
                altered.failed_owners = vec![reference(41)];
            }
            2 => {
                altered.freeze_position = 11;
                altered.issue_position = 11;
            }
            _ => altered.terminal_state = waiting,
        }
        assert_eq!(
            ErasureReceiptV1::new(altered)?.verify_history(resolver),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }
    Ok(())
}

fn history_predecessor_mismatches(
    input: &ErasureReceiptInputV1,
    submitted: &ErasureStateV1,
    authorized: &ErasureStateV1,
    frozen: &ErasureStateV1,
    dispatched: &ErasureStateV1,
    terminal: &ErasureStateV1,
) -> Result<(), ErasureErrorV1> {
    for previous in [submitted, authorized, frozen, dispatched] {
        assert_eq!(
            ErasureReceiptV1::new(input.clone())?.verify_history(&ReplyResolver {
                terminal: terminal.clone(),
                previous: previous.clone(),
            }),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}

#[test]
fn finalization_persists_the_atomic_batch_across_restart() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let terminal_state = awaiting.transition({
        let mut transition = change(
            ErasureLifecycleV1::Complete,
            awaiting.freeze_position(),
            Vec::new(),
            Vec::new(),
        );
        transition.acknowledged_targets = vec![ack.target];
        transition.provenance = reference(10);
        transition
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal_state.state_digest();
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    coordinator.finalize(reference(1), input)?;
    drop(coordinator);

    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(
        restarted.submit(request()?, reference(99))?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    Ok(())
}

#[test]
fn coordinator_rejects_storage_and_lifecycle_seams() -> Result<(), ErasureErrorV1> {
    let mut load_failed =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    load_failed.submit(request()?, reference(3))?;
    load_failed.port.load_error = Some(ErasureErrorV1::KeyRegistryUnavailable);
    assert_eq!(
        load_failed.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyRegistryUnavailable)
    );

    let mut invalid_dispatch =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    invalid_dispatch.submit(request()?, reference(3))?;
    assert_eq!(
        invalid_dispatch.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}
