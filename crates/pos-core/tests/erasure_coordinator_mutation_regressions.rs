//! Public-interface regressions for coordinator mutation survivors.

use std::cell::RefCell;
use std::rc::Rc;

use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    destruction_command_reference, inventory_obligation_reference, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAcknowledgementV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureCoordinatorPortV1, ErasureCoordinatorRecordPartsV1, ErasureCoordinatorRecordV1,
    ErasureCoordinatorStateMachineV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureErrorV1, ErasureFreezeAdmissionV1,
    ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasurePersistencePortV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1, ErasureStateV1,
    ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1,
};

const COORDINATOR: ErasureReferenceV1 = reference(200);

type SharedState = Rc<RefCell<PortState>>;
type Machine = ErasureCoordinatorStateMachineV1<SharedPort>;

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target(value: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(value),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(value + 1),
        replica_set: reference(value + 2),
        replica_id: reference(value + 3),
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
        horizon_position: 10,
        provenance,
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
        provenance: reference(90),
    }
}

const fn inventory_for(
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner,
            acknowledgements: reference(21),
            provenance: reference(22),
        },
        retained_disclosure: reference(23),
    }
}

fn acknowledgement_for(
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
    evidence: ErasureReferenceV1,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        obligation: inventory_obligation_reference(
            ErasureInventoryCategoryV1::Artifact,
            target,
            owner,
        ),
        target,
        owner,
        evidence,
        outcome,
    }
}

fn acknowledgement_provenance(
    request: ErasureReferenceV1,
    admission: &ErasureRetryAdmissionV1,
    acknowledgement: ErasureAcknowledgementV1,
    scope: &ErasureScopeCommitmentV1,
) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
    ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
        request,
        command: destruction_command_reference(request, acknowledgement.target),
        attempt: admission.reference(),
        obligation: acknowledgement.obligation,
        owner: acknowledgement.owner,
        scope: scope.reference(),
        outcome: acknowledgement.outcome,
        evidence: acknowledgement.evidence,
        policy: admission.policy(),
        trust: admission.trust(),
    })
}

fn retry_admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    attempt_ordinal: u64,
    source_receipt: Option<ErasureReferenceV1>,
    deadline_position: u64,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let owner = target.replica_id;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal,
        source_receipt,
        unresolved_obligations: vec![inventory_for(target, owner).obligation_reference()],
        command_identities: vec![destruction_command_reference(request, target)],
        policy: reference(6),
        trust: reference(94),
        admitted_position: if attempt_ordinal == 0 { 9 } else { 12 },
        deadline_position,
        authorization_provenance: reference(94),
    })
}

fn receipt_input(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    acknowledgement: ErasureAcknowledgementV1,
    lifecycle: ErasureLifecycleV1,
    issue_position: u64,
) -> ErasureReceiptInputV1 {
    let failed_owners = if acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
    {
        Vec::new()
    } else {
        vec![acknowledgement.owner]
    };
    ErasureReceiptInputV1 {
        request,
        terminal_state: reference(100),
        coordinator: COORDINATOR,
        lifecycle,
        freeze_position: 10,
        acknowledgements: vec![acknowledgement],
        required_targets: vec![target],
        pending_owners: Vec::new(),
        failed_owners,
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory_for(target, acknowledgement.owner)],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(6),
        trust: reference(94),
        provenance: reference(101),
        issue_position,
        signature: reference(102),
        receipt_digest: reference(0),
    }
}

const fn deadline_receipt_input(issue_position: u64) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(0),
        coordinator: COORDINATOR,
        lifecycle: ErasureLifecycleV1::PartialFailure,
        freeze_position: 10,
        acknowledgements: Vec::new(),
        required_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(6),
        trust: reference(94),
        provenance: reference(101),
        issue_position,
        signature: reference(102),
        receipt_digest: reference(0),
    }
}

struct PortState {
    records: Vec<ErasureCoordinatorRecordV1>,
    states: Vec<ErasureStateV1>,
    targets: Vec<ErasureRequiredTargetV1>,
}

struct SharedPort {
    state: SharedState,
}

impl ErasureStateResolverV1 for SharedPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        Ok(self
            .state
            .borrow()
            .states
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}

impl ErasurePersistencePortV1 for SharedPort {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        Ok(self
            .state
            .borrow()
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
        let mut state = self.state.borrow_mut();
        let mut staged_records = state.records.clone();
        let mut staged_states = state.states.clone();
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
        state.records = staged_records;
        state.states = staged_states;
        Ok(())
    }
}

impl ErasureCoordinatorPortV1 for SharedPort {
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
        Ok(self.state.borrow().targets.clone())
    }

    fn affected_scope(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
        Ok(vec![reference(3)])
    }

    fn admit_freeze(
        &self,
        _request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
        targets: &[ErasureRequiredTargetV1],
    ) -> Result<ErasureFreezeAdmissionV1, ErasureErrorV1> {
        Ok(ErasureFreezeAdmissionV1 {
            freeze_position: 10,
            provenance: reference(90),
            target_closure: target_closure_digest(targets),
        })
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[pos_core::ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(&self, _admission: &ErasureRetryAdmissionV1) -> Result<(), ErasureErrorV1> {
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
}

struct Fixture {
    machine: Machine,
    state: SharedState,
    request: ErasureReferenceV1,
}

fn submitted_fixture(targets: Vec<ErasureRequiredTargetV1>) -> Result<Fixture, ErasureErrorV1> {
    let state = Rc::new(RefCell::new(PortState {
        records: Vec::new(),
        states: Vec::new(),
        targets,
    }));
    let mut machine = Machine::new(
        SharedPort {
            state: state.clone(),
        },
        COORDINATOR,
    );
    let request = request_with(reference(1), reference(7))?;
    let request_reference = request.reference();
    machine.submit(request, reference(8))?;
    Ok(Fixture {
        machine,
        state,
        request: request_reference,
    })
}

fn authorized_fixture(targets: Vec<ErasureRequiredTargetV1>) -> Result<Fixture, ErasureErrorV1> {
    let mut fixture = submitted_fixture(targets)?;
    fixture.machine.authorize(fixture.request, reference(9))?;
    Ok(fixture)
}

fn frozen_fixture(targets: Vec<ErasureRequiredTargetV1>) -> Result<Fixture, ErasureErrorV1> {
    let mut fixture = authorized_fixture(targets)?;
    fixture
        .machine
        .freeze_inventory(fixture.request, freeze_transition())?;
    Ok(fixture)
}

fn awaiting_fixture(targets: Vec<ErasureRequiredTargetV1>) -> Result<Fixture, ErasureErrorV1> {
    let mut fixture = frozen_fixture(targets)?;
    fixture
        .machine
        .dispatch_destruction(fixture.request, reference(94))?;
    Ok(fixture)
}

fn complete_fixture() -> Result<Fixture, ErasureErrorV1> {
    let target = target(10);
    let mut fixture = awaiting_fixture(vec![target])?;
    let acknowledgement = acknowledgement_for(
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    );
    fixture
        .machine
        .acknowledge(fixture.request, acknowledgement)?;
    fixture.machine.finalize(
        fixture.request,
        receipt_input(
            fixture.request,
            target,
            acknowledgement,
            ErasureLifecycleV1::Complete,
            11,
        ),
    )?;
    Ok(fixture)
}

fn partial_failure_fixture() -> Result<Fixture, ErasureErrorV1> {
    let target = target(10);
    let mut fixture = awaiting_fixture(vec![target])?;
    let acknowledgement = acknowledgement_for(
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Negative,
        reference(96),
    );
    fixture
        .machine
        .acknowledge(fixture.request, acknowledgement)?;
    fixture.machine.finalize(
        fixture.request,
        receipt_input(
            fixture.request,
            target,
            acknowledgement,
            ErasureLifecycleV1::PartialFailure,
            11,
        ),
    )?;
    Ok(fixture)
}

fn latest_record(
    state: &SharedState,
    request: ErasureReferenceV1,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    state
        .borrow()
        .records
        .iter()
        .find(|record| record.request().reference() == request)
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

fn supporting_input(supporting: &ErasureSupportingRecordsV1) -> ErasureSupportingRecordsInputV1 {
    ErasureSupportingRecordsInputV1 {
        correction_provenance: supporting.correction_provenance().cloned(),
        scope_commitment: supporting.scope_commitment().cloned(),
        freeze_provenance: supporting.freeze_provenance(),
        freeze_failure: supporting.freeze_failure(),
        retry_admissions: supporting.retry_admissions().to_vec(),
        acknowledgement_provenance: supporting.acknowledgement_provenance().to_vec(),
        attempt_outcomes: supporting.attempt_outcomes().to_vec(),
        receipts: supporting.receipts().to_vec(),
        receipt_provenance: supporting.receipt_provenance().to_vec(),
        administrative_resolutions: supporting.administrative_resolutions().to_vec(),
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
        supporting_records: record.supporting_records().clone(),
    }
}

#[test]
fn partial_failure_retry_allows_same_state_acknowledgement_reset() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut fixture = partial_failure_fixture()?;
    let current = latest_record(&fixture.state, fixture.request)?;
    let receipt = current.receipt().ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let retry = retry_admission(
        fixture.request,
        target,
        1,
        Some(receipt.receipt_digest()),
        20,
    )?;

    let state = fixture.machine.dispatch_attempt(fixture.request, &retry)?;
    assert_eq!(state.lifecycle(), ErasureLifecycleV1::PartialFailure);
    let next = latest_record(&fixture.state, fixture.request)?;
    assert_eq!(current.acknowledgements().len(), 1);
    assert!(next.acknowledgements().is_empty());
    assert_eq!(next.supporting_records().retry_admissions().len(), 2);
    assert_eq!(current.validate_replacement(&next), Ok(()));
    Ok(())
}

#[test]
fn correction_predecessor_requires_the_exact_rejected_record() -> Result<(), ErasureErrorV1> {
    let mut predecessor_fixture = submitted_fixture(vec![target(10)])?;
    let predecessor_request = predecessor_fixture.request;
    predecessor_fixture
        .machine
        .reject(predecessor_request, reference(55))?;
    let predecessor = latest_record(&predecessor_fixture.state, predecessor_request)?;

    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: predecessor.request().reference(),
        rejected_terminal_state: predecessor.state().state_digest(),
        correction_reason: reference(56),
        authorization_provenance: reference(57),
    })?;
    let corrected_request = request_with(reference(2), correction.reference())?;
    let corrected_state =
        ErasureStateV1::submitted(corrected_request.reference(), COORDINATOR, reference(58))?;
    let supporting = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        correction_provenance: Some(correction),
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    let corrected = ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request: corrected_request,
            state: corrected_state,
            reserved_targets: Vec::new(),
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            freeze_admission: None,
            dispatch_provenance: None,
            supporting_records: supporting,
        },
        COORDINATOR,
    )?;

    assert_eq!(
        corrected.validate_correction_predecessor(&predecessor),
        Ok(())
    );
    assert_eq!(
        corrected.validate_correction_predecessor(&corrected),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn freeze_admission_binds_closure_scope_evidence_and_position() -> Result<(), ErasureErrorV1> {
    let fixture = frozen_fixture(vec![target(10)])?;
    let frozen = latest_record(&fixture.state, fixture.request)?;
    assert!(frozen.to_canonical_cbor().is_ok());

    let mut admission_mismatch = record_parts(&frozen);
    admission_mismatch
        .freeze_admission
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .target_closure = reference(91);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(admission_mismatch, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let original_scope = frozen
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let original_freeze = frozen
        .supporting_records()
        .freeze_provenance()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;

    let changed_scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: original_scope.request(),
        affected_scope: original_scope.affected_scope().to_vec(),
        target_closure: reference(92),
        extension_head: original_scope.extension_head(),
    })?;
    let changed_scope_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: original_freeze.request(),
        scope_commitment: changed_scope.reference(),
        freeze_position: original_freeze.freeze_position(),
        evidence: original_freeze.evidence(),
        extension_head: original_freeze.extension_head(),
    })?;
    let mut scope_mismatch = record_parts(&frozen);
    let mut scope_supporting = supporting_input(frozen.supporting_records());
    scope_supporting.scope_commitment = Some(changed_scope);
    scope_supporting.freeze_provenance = Some(changed_scope_freeze);
    scope_mismatch.supporting_records = ErasureSupportingRecordsV1::new(scope_supporting)?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(scope_mismatch, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let changed_evidence_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: original_freeze.request(),
        scope_commitment: original_freeze.scope_commitment(),
        freeze_position: original_freeze.freeze_position(),
        evidence: reference(93),
        extension_head: original_freeze.extension_head(),
    })?;
    let mut evidence_mismatch = record_parts(&frozen);
    let mut evidence_supporting = supporting_input(frozen.supporting_records());
    evidence_supporting.freeze_provenance = Some(changed_evidence_freeze);
    evidence_mismatch.supporting_records = ErasureSupportingRecordsV1::new(evidence_supporting)?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(evidence_mismatch, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut provenance_mismatch = record_parts(&frozen);
    provenance_mismatch.freeze_provenance = Some(reference(94));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(provenance_mismatch, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let changed_position_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: original_freeze.request(),
        scope_commitment: original_freeze.scope_commitment(),
        freeze_position: 11,
        evidence: original_freeze.evidence(),
        extension_head: original_freeze.extension_head(),
    })?;
    let mut position_mismatch = record_parts(&frozen);
    let mut position_supporting = supporting_input(frozen.supporting_records());
    position_supporting.freeze_provenance = Some(changed_position_freeze);
    position_mismatch.supporting_records = ErasureSupportingRecordsV1::new(position_supporting)?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(position_mismatch, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn terminal_validation_distinguishes_active_retry_from_stale_receipt() -> Result<(), ErasureErrorV1>
{
    let complete = complete_fixture()?;
    let complete_record = latest_record(&complete.state, complete.request)?;
    assert!(
        ErasureCoordinatorRecordV1::from_parts(record_parts(&complete_record), COORDINATOR,)
            .is_ok()
    );

    let mut missing_acknowledgements = record_parts(&complete_record);
    missing_acknowledgements.acknowledgements.clear();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(missing_acknowledgements, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut partial = partial_failure_fixture()?;
    let current = latest_record(&partial.state, partial.request)?;
    let receipt = current.receipt().ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let retry = retry_admission(
        partial.request,
        target(10),
        1,
        Some(receipt.receipt_digest()),
        20,
    )?;
    partial.machine.dispatch_attempt(partial.request, &retry)?;
    let active_retry = latest_record(&partial.state, partial.request)?;
    assert!(
        ErasureCoordinatorRecordV1::from_parts(record_parts(&active_retry), COORDINATOR,).is_ok()
    );
    Ok(())
}

#[test]
fn supporting_lifecycle_rejects_evidence_at_the_wrong_boundary() -> Result<(), ErasureErrorV1> {
    let authorized = authorized_fixture(vec![target(10)])?;
    let authorized_record = latest_record(&authorized.state, authorized.request)?;
    let empty_targets = Vec::new();
    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: authorized.request,
        affected_scope: vec![reference(3)],
        target_closure: target_closure_digest(&empty_targets),
        extension_head: None,
    })?;
    let mut authorized_parts = record_parts(&authorized_record);
    let mut authorized_supporting = supporting_input(authorized_record.supporting_records());
    authorized_supporting.scope_commitment = Some(scope);
    authorized_parts.supporting_records = ErasureSupportingRecordsV1::new(authorized_supporting)?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(authorized_parts, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let evidence_authorized = authorized_fixture(vec![target(10)])?;
    let evidence_admission =
        retry_admission(evidence_authorized.request, target(10), 0, None, u64::MAX)?;
    let evidence_record = latest_record(&evidence_authorized.state, evidence_authorized.request)?;
    let mut evidence_parts = record_parts(&evidence_record);
    let mut evidence_supporting = supporting_input(evidence_record.supporting_records());
    evidence_supporting.retry_admissions = vec![evidence_admission];
    evidence_parts.supporting_records = ErasureSupportingRecordsV1::new(evidence_supporting)?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(evidence_parts, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let rejected = empty_target_rejection_fixture()?;
    let rejected_record = latest_record(&rejected.state, rejected.request)?;
    assert!(
        ErasureCoordinatorRecordV1::from_parts(record_parts(&rejected_record), COORDINATOR,)
            .is_ok()
    );

    let frozen = frozen_fixture(vec![target(10)])?;
    let frozen_record = latest_record(&frozen.state, frozen.request)?;
    assert!(
        ErasureCoordinatorRecordV1::from_parts(record_parts(&frozen_record), COORDINATOR,).is_ok()
    );

    let frozen_scope = frozen_record
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut access_frozen_parts = record_parts(&frozen_record);
    let access_admission = retry_admission(frozen.request, target(10), 0, None, u64::MAX)?;
    let access_acknowledgement = acknowledgement_for(
        target(10),
        target(10).replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(97),
    );
    let access_provenance = acknowledgement_provenance(
        frozen.request,
        &access_admission,
        access_acknowledgement,
        frozen_scope,
    )?;
    let mut access_supporting = supporting_input(frozen_record.supporting_records());
    access_supporting.retry_admissions = vec![access_admission.clone()];
    access_supporting.acknowledgement_provenance = vec![access_provenance];
    access_frozen_parts.supporting_records = ErasureSupportingRecordsV1::new(access_supporting)?;
    access_frozen_parts.dispatch_provenance = Some(access_admission.reference());
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(access_frozen_parts, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn empty_target_rejection_fixture() -> Result<Fixture, ErasureErrorV1> {
    let mut fixture = authorized_fixture(Vec::new())?;
    assert_eq!(
        fixture
            .machine
            .freeze_inventory(fixture.request, freeze_transition()),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(fixture)
}

#[test]
fn freeze_rejects_an_empty_required_target_closure() -> Result<(), ErasureErrorV1> {
    let fixture = empty_target_rejection_fixture()?;
    let record = latest_record(&fixture.state, fixture.request)?;
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Rejected);
    assert!(record.supporting_records().freeze_failure().is_some());
    Ok(())
}

#[test]
fn dispatch_attempt_requires_the_current_request_ordinal_and_receipt() -> Result<(), ErasureErrorV1>
{
    let target = target(10);
    let mut fixture = frozen_fixture(vec![target])?;

    let wrong_request = retry_admission(reference(99), target, 0, None, u64::MAX)?;
    assert_eq!(
        fixture
            .machine
            .dispatch_attempt(fixture.request, &wrong_request),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut partial = partial_failure_fixture()?;
    let current = latest_record(&partial.state, partial.request)?;
    let source_receipt = current
        .receipt()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .receipt_digest();
    let wrong_ordinal =
        retry_admission(partial.request, target, 2, Some(source_receipt), u64::MAX)?;
    assert_eq!(
        partial
            .machine
            .dispatch_attempt(partial.request, &wrong_ordinal),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let wrong_source = retry_admission(partial.request, target, 1, Some(reference(98)), u64::MAX)?;
    assert_eq!(
        partial
            .machine
            .dispatch_attempt(partial.request, &wrong_source),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn destruction_dispatch_requires_a_frozen_nonempty_closure() -> Result<(), ErasureErrorV1> {
    let mut authorized = authorized_fixture(vec![target(10)])?;
    assert_eq!(
        authorized
            .machine
            .dispatch_destruction(authorized.request, reference(94)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut awaiting = awaiting_fixture(vec![target(10)])?;
    let state = awaiting
        .machine
        .dispatch_destruction(awaiting.request, reference(94))?;
    assert_eq!(
        state.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}

#[test]
fn acknowledgement_requires_a_unique_admitted_obligation_owner_pair() -> Result<(), ErasureErrorV1>
{
    let target = target(10);
    let mut accepted = awaiting_fixture(vec![target])?;
    let acknowledgement = acknowledgement_for(
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    );
    accepted
        .machine
        .acknowledge(accepted.request, acknowledgement)?;
    let conflicting = acknowledgement_for(
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(96),
    );
    assert_eq!(
        accepted.machine.acknowledge(accepted.request, conflicting),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut unadmitted = awaiting_fixture(vec![target])?;
    let mut wrong_pair = acknowledgement;
    wrong_pair.obligation = reference(97);
    assert_eq!(
        unadmitted
            .machine
            .acknowledge(unadmitted.request, wrong_pair),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn finalization_rejects_an_issue_after_the_attempt_deadline() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut fixture = frozen_fixture(vec![target])?;
    let admission = retry_admission(fixture.request, target, 0, None, 10)?;
    fixture
        .machine
        .dispatch_attempt(fixture.request, &admission)?;
    assert_eq!(
        fixture
            .machine
            .finalize(fixture.request, deadline_receipt_input(11)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn coordinator_rejects_duplicate_acknowledgement_identity_by_owner() -> Result<(), ErasureErrorV1> {
    let first_target = target(10);
    let second_target = target(20);
    let fixture = frozen_fixture(vec![first_target, second_target])?;
    let frozen = latest_record(&fixture.state, fixture.request)?;
    let first = acknowledgement_for(
        first_target,
        first_target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    );
    let mut second = acknowledgement_for(
        second_target,
        first_target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(96),
    );
    second.obligation = first.obligation;
    let mut parts = record_parts(&frozen);
    parts.acknowledgements = vec![first, second];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, COORDINATOR),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
