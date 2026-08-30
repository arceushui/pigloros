//! Public-interface regressions for coordinator mutation survivors.

use std::cell::RefCell;
use std::rc::Rc;

use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    destruction_command_reference, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAcknowledgementV1, ErasureAdministrativeResolutionActionV1,
    ErasureAdministrativeResolutionInputV1, ErasureAdministrativeResolutionV1,
    ErasureArtifactClassV1, ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureCoordinator,
    ErasureCoordinatorPortV1, ErasureCoordinatorRecordPartsV1, ErasureCoordinatorRecordV1,
    ErasureCoordinatorStateMachineV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureErrorV1, ErasureFreezeFailureInputV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationSetInputV1, ErasureObligationSetV1,
    ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1,
    ErasureStateTransitionV1, ErasureStateV1, ErasureSupportingRecordsInputV1,
    ErasureSupportingRecordsV1, ERASURE_MAX_TARGETS,
};

const COORDINATOR: ErasureReferenceV1 = reference(200);

type SharedState = Rc<RefCell<PortState>>;
type Machine = ErasureCoordinatorStateMachineV1<SharedPort>;

enum ReceiptMismatch {
    TerminalState,
    Coordinator,
    Request,
}

enum FreezePortFailure {
    RequiredTargets,
    AffectedScope,
    Admission,
}

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
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
    evidence: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner,
        command_identity: destruction_command_reference(request, target),
    })?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target,
        owner,
        evidence,
        outcome,
    })
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
        unresolved_obligations: vec![ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target,
            owner,
            command_identity: destruction_command_reference(request, target),
        })?
        .reference()],
        command_identities: vec![destruction_command_reference(request, target)],
        policy: reference(6),
        trust: reference(94),
        admitted_position: if attempt_ordinal == 0 { 9 } else { 12 },
        deadline_position,
        authorization_provenance: reference(94),
    })
}

fn administrative_resolution(
    record: &ErasureCoordinatorRecordV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    let scope = record
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let obligation_set = record
        .supporting_records()
        .obligation_set()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request: record.request().reference(),
        affected_digests: vec![record.state().state_digest()],
        action: ErasureAdministrativeResolutionActionV1::CloseContainment,
        scope_commitment: scope.reference(),
        policy: record.request().policy(),
        trust: obligation_set.trust(),
        principal: reference(72),
        authorization_provenance: reference(73),
        reason: reference(74),
        issue_position: 21,
        predecessor_resolution: None,
    })
}

fn atomic_admission(
    request: ErasureReferenceV1,
    targets: Vec<ErasureRequiredTargetV1>,
    mismatched_closure: bool,
    lineage_rule: Option<ErasureReferenceV1>,
) -> Result<ErasureAtomicFreezeAdmissionV1, ErasureErrorV1> {
    ErasureAtomicFreezeAdmissionV1::new(atomic_admission_input(
        request,
        targets,
        mismatched_closure,
        lineage_rule,
    )?)
}

fn atomic_admission_input(
    request: ErasureReferenceV1,
    mut targets: Vec<ErasureRequiredTargetV1>,
    mismatched_closure: bool,
    lineage_rule: Option<ErasureReferenceV1>,
) -> Result<ErasureAtomicFreezeAdmissionInputV1, ErasureErrorV1> {
    targets.sort_unstable();
    let mut obligations = targets
        .iter()
        .map(|target| {
            ErasureObligationV1::new(ErasureObligationInputV1 {
                category: ErasureInventoryCategoryV1::Artifact,
                target: *target,
                owner: target.replica_id,
                command_identity: destruction_command_reference(request, *target),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(6),
        trust: reference(94),
    })?;
    Ok(ErasureAtomicFreezeAdmissionInputV1 {
        targets: targets.clone(),
        scope: ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(3)],
            target_closure: if mismatched_closure {
                reference(91)
            } else {
                target_closure_digest(&targets)
            },
            lineage_rule,
        },
        obligations,
        obligation_set,
        freeze_position: 10,
        host_evidence: reference(90),
    })
}

fn bind_atomic_obligations(
    mut input: ErasureAtomicFreezeAdmissionInputV1,
) -> Result<ErasureAtomicFreezeAdmissionInputV1, ErasureErrorV1> {
    input
        .obligations
        .sort_unstable_by_key(ErasureObligationV1::reference);
    input.obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: input.scope.request,
        obligations: input
            .obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(6),
        trust: reference(94),
    })?;
    Ok(input)
}

fn corrected_record_for(
    rejected_request: ErasureReferenceV1,
    rejected_terminal_state: ErasureReferenceV1,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request,
        rejected_terminal_state,
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
    ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request: corrected_request,
            state: corrected_state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records: supporting,
        },
        COORDINATOR,
    )
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
        frozen_targets: vec![target],
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

struct PortState {
    records: Vec<ErasureCoordinatorRecordV1>,
    record_history: Vec<ErasureCoordinatorRecordV1>,
    states: Vec<ErasureStateV1>,
    targets: Vec<ErasureRequiredTargetV1>,
    frozen_targets_error: Option<ErasureErrorV1>,
    scope_members_error: Option<ErasureErrorV1>,
    freeze_error: Option<ErasureErrorV1>,
    freeze_rejection: Option<ErasureErrorV1>,
    mismatched_freeze_closure: bool,
    lineage_rule: Option<ErasureReferenceV1>,
    attempt_error: Option<ErasureErrorV1>,
    dispatch_error: Option<ErasureErrorV1>,
    acknowledgement_error: Option<ErasureErrorV1>,
    receipt_error: Option<ErasureErrorV1>,
    load_error: Option<ErasureErrorV1>,
    commit_error: Option<ErasureErrorV1>,
    scope_extension_error: Option<ErasureErrorV1>,
    scope_cas_error: Option<ErasureErrorV1>,
    administrative_resolution_error: Option<ErasureErrorV1>,
    administrative_cas_error: Option<ErasureErrorV1>,
    freeze_admission_request: Option<ErasureReferenceV1>,
    freeze_rejection_authorization: Option<ErasureReferenceV1>,
    resolver_error: Option<ErasureErrorV1>,
    authenticate_error: Option<ErasureErrorV1>,
    authorization_error: Option<ErasureErrorV1>,
    correction_error: Option<ErasureErrorV1>,
}

struct SharedPort {
    state: SharedState,
}

impl ErasureStateResolverV1 for SharedPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if let Some(error) = self.state.borrow().resolver_error {
            return Err(error);
        }
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
        if let Some(error) = self.state.borrow().load_error {
            return Err(error);
        }
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
        if let Some(error) = self.state.borrow().commit_error {
            return Err(error);
        }
        let mut state = self.state.borrow_mut();
        let mut staged_records = state.records.clone();
        let mut staged_states = state.states.clone();
        let mut staged_history = state.record_history.clone();
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
            staged_history.push(record.clone());
        }
        state.records = staged_records;
        state.states = staged_states;
        state.record_history = staged_history;
        Ok(())
    }

    fn compare_and_swap_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        expected_ledger: ErasureReferenceV1,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        if let Some(error) = self.state.borrow().scope_cas_error {
            return Err(error);
        }
        if self
            .load_record(request)?
            .and_then(|current| current.scope_extension_ledger())
            != Some(expected_ledger)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.commit_record(record)
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        request: ErasureReferenceV1,
        expected_head: Option<ErasureReferenceV1>,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        if let Some(error) = self.state.borrow().administrative_cas_error {
            return Err(error);
        }
        if self
            .load_record(request)?
            .and_then(|current| current.administrative_resolution_head())
            != expected_head
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.commit_record(record)
    }
}

impl ErasureCoordinatorPortV1 for SharedPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        self.state.borrow().authenticate_error.map_or(Ok(()), Err)
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.state.borrow().authorization_error.map_or(Ok(()), Err)
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.state.borrow().correction_error.map_or(Ok(()), Err)
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let state = self.state.borrow();
        if let Some(error) = state.freeze_rejection {
            return ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
                request,
                authorization_provenance: state
                    .freeze_rejection_authorization
                    .unwrap_or(reference(9)),
                evidence: reference(90),
                error,
            })
            .map(ErasureAtomicFreezeResultV1::Rejected);
        }
        if let Some(error) = state
            .frozen_targets_error
            .or(state.scope_members_error)
            .or(state.freeze_error)
        {
            return Err(error);
        }
        atomic_admission(
            state.freeze_admission_request.unwrap_or(request),
            state.targets.clone(),
            state.mismatched_freeze_closure,
            state.lineage_rule,
        )
        .map(Box::new)
        .map(ErasureAtomicFreezeResultV1::Admitted)
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[pos_core::ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        self.state.borrow().dispatch_error.map_or(Ok(()), Err)
    }

    fn admit_attempt(&self, _admission: &ErasureRetryAdmissionV1) -> Result<(), ErasureErrorV1> {
        self.state.borrow().attempt_error.map_or(Ok(()), Err)
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.state
            .borrow()
            .acknowledgement_error
            .map_or(Ok(()), Err)
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        self.state.borrow().receipt_error.map_or(Ok(()), Err)
    }
    fn admit_scope_extension(
        &self,
        _extension: &pos_core::ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.state
            .borrow()
            .scope_extension_error
            .map_or(Ok(()), Err)
    }
    fn admit_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.state
            .borrow()
            .administrative_resolution_error
            .map_or(Ok(()), Err)
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
        record_history: Vec::new(),
        states: Vec::new(),
        targets,
        frozen_targets_error: None,
        scope_members_error: None,
        freeze_error: None,
        freeze_rejection: None,
        mismatched_freeze_closure: false,
        lineage_rule: None,
        attempt_error: None,
        dispatch_error: None,
        acknowledgement_error: None,
        receipt_error: None,
        load_error: None,
        commit_error: None,
        scope_extension_error: None,
        scope_cas_error: None,
        administrative_resolution_error: None,
        administrative_cas_error: None,
        freeze_admission_request: None,
        freeze_rejection_authorization: None,
        resolver_error: None,
        authenticate_error: None,
        authorization_error: None,
        correction_error: None,
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
        fixture.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
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
        fixture.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Negative,
        reference(96),
    )?;
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

fn historical_record(
    state: &SharedState,
    lifecycle: ErasureLifecycleV1,
    predicate: impl Fn(&ErasureCoordinatorRecordV1) -> bool,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    state
        .borrow()
        .record_history
        .iter()
        .find(|record| record.state().lifecycle() == lifecycle && predicate(record))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

fn supporting_input(supporting: &ErasureSupportingRecordsV1) -> ErasureSupportingRecordsInputV1 {
    ErasureSupportingRecordsInputV1 {
        correction_provenance: supporting.correction_provenance().cloned(),
        authorization_rejection: supporting.authorization_rejection(),
        scope_commitment: supporting.scope_commitment().cloned(),
        freeze_provenance: supporting.freeze_provenance(),
        freeze_failure: supporting.freeze_failure(),
        obligations: supporting.obligations().to_vec(),
        obligation_set: supporting.obligation_set().cloned(),
        scope_extensions: supporting.scope_extensions().to_vec(),
        scope_extension_ledgers: supporting.scope_extension_ledgers().to_vec(),
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
        targets: record.targets().to_vec(),
        acknowledgements: record.acknowledgements().to_vec(),
        receipt: record.receipt().cloned(),
        receipt_input: record.receipt_input().cloned(),
        authorize_provenance: record.authorize_provenance(),
        freeze_provenance: record.freeze_provenance(),
        dispatch_provenance: record.dispatch_provenance(),
        scope_extension_ledger: record.scope_extension_ledger(),
        administrative_resolution_head: record.administrative_resolution_head(),
        supporting_records: record.supporting_records().clone(),
    }
}

fn assert_invalid_parts(parts: ErasureCoordinatorRecordPartsV1) {
    assert!(ErasureCoordinatorRecordV1::from_parts(parts, COORDINATOR).is_err());
}

#[test]
fn partial_failure_retry_starts_with_a_fresh_attempt_view() -> Result<(), ErasureErrorV1> {
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

    let mut retained_parts = record_parts(&next);
    retained_parts.acknowledgements = current.acknowledgements().to_vec();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(retained_parts, COORDINATOR),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_record_scope_and_lifecycle_shapes_reject_each_public_near_miss(
) -> Result<(), ErasureErrorV1> {
    let submitted = submitted_fixture(vec![target(10)])?;
    let submitted_record = latest_record(&submitted.state, submitted.request)?;
    let mut submitted_with_target = record_parts(&submitted_record);
    submitted_with_target.targets = vec![target(10)];
    assert_invalid_parts(submitted_with_target);

    let authorized = authorized_fixture(vec![target(10)])?;
    let authorized_record = latest_record(&authorized.state, authorized.request)?;
    let mut authorized_with_target = record_parts(&authorized_record);
    authorized_with_target.targets = vec![target(10)];
    assert_invalid_parts(authorized_with_target);

    let frozen = frozen_fixture(vec![target(10), target(20)])?;
    let frozen_record = latest_record(&frozen.state, frozen.request)?;

    let mut empty_frozen = record_parts(&frozen_record);
    empty_frozen.targets.clear();
    assert_invalid_parts(empty_frozen);

    let mut unsorted_targets = record_parts(&frozen_record);
    unsorted_targets.targets.reverse();
    assert_invalid_parts(unsorted_targets);

    let mut duplicate_targets = record_parts(&frozen_record);
    duplicate_targets.targets = vec![target(10), target(10)];
    assert_invalid_parts(duplicate_targets);

    let mut oversized_targets = record_parts(&frozen_record);
    oversized_targets.targets = vec![target(10); ERASURE_MAX_TARGETS + 1];
    assert_invalid_parts(oversized_targets);

    let first = acknowledgement_for(
        frozen.request,
        target(10),
        target(10).replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    let second = acknowledgement_for(
        frozen.request,
        target(20),
        target(20).replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(96),
    )?;
    let mut acknowledgements = vec![first, second];
    acknowledgements.sort_unstable();
    acknowledgements.reverse();
    let mut unsorted_acknowledgements = record_parts(&frozen_record);
    unsorted_acknowledgements.acknowledgements = acknowledgements;
    assert_invalid_parts(unsorted_acknowledgements);

    let mut injected_acknowledgement = record_parts(&frozen_record);
    injected_acknowledgement.acknowledgements = vec![acknowledgement_for(
        frozen.request,
        target(30),
        target(30).replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(97),
    )?];
    assert_invalid_parts(injected_acknowledgement);

    let awaiting = awaiting_fixture(vec![target(10)])?;
    let awaiting_record = latest_record(&awaiting.state, awaiting.request)?;
    let mut empty_awaiting = record_parts(&awaiting_record);
    empty_awaiting.targets.clear();
    assert_invalid_parts(empty_awaiting);
    Ok(())
}

#[test]
fn terminal_record_rejects_missing_and_mismatched_receipt_fields() -> Result<(), ErasureErrorV1> {
    let fixture = complete_fixture()?;
    let record = latest_record(&fixture.state, fixture.request)?;

    let mut missing_receipt = record_parts(&record);
    missing_receipt.receipt = None;
    assert_invalid_parts(missing_receipt);

    let mut missing_input = record_parts(&record);
    missing_input.receipt_input = None;
    assert_invalid_parts(missing_input);

    let mut mismatched_pair = record_parts(&record);
    mismatched_pair
        .receipt_input
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .signature = reference(103);
    assert_invalid_parts(mismatched_pair);

    for field in [
        ReceiptMismatch::TerminalState,
        ReceiptMismatch::Coordinator,
        ReceiptMismatch::Request,
    ] {
        let mut parts = record_parts(&record);
        let mut input = parts
            .receipt_input
            .clone()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        match field {
            ReceiptMismatch::TerminalState => input.terminal_state = reference(104),
            ReceiptMismatch::Coordinator => input.coordinator = reference(105),
            ReceiptMismatch::Request => input.request = reference(106),
        }
        parts.receipt = Some(pos_core::ErasureReceiptV1::new(input.clone())?);
        parts.receipt_input = Some(input);
        assert_invalid_parts(parts);
    }
    Ok(())
}

#[test]
fn correction_validation_requires_correction_evidence() -> Result<(), ErasureErrorV1> {
    let fixture = submitted_fixture(vec![target(10)])?;
    let record = latest_record(&fixture.state, fixture.request)?;
    assert_eq!(
        record.validate_correction_predecessor(&record),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn replacement_validation_rejects_identity_and_evidence_regressions() -> Result<(), ErasureErrorV1>
{
    let submitted = submitted_fixture(vec![target(10)])?;
    let submitted_record = latest_record(&submitted.state, submitted.request)?;
    assert_eq!(
        submitted_record.validate_replacement(&submitted_record),
        Ok(())
    );

    let other_request = request_with(reference(2), reference(7))?;
    let other_state =
        ErasureStateV1::submitted(other_request.reference(), COORDINATOR, reference(8))?;
    let other_record = ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request: other_request,
            state: other_state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records: ErasureSupportingRecordsV1::default(),
        },
        COORDINATOR,
    )?;
    assert_eq!(
        submitted_record.validate_replacement(&other_record),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let frozen = frozen_fixture(vec![target(10)])?;
    let frozen_record = latest_record(&frozen.state, frozen.request)?;
    let authorized = authorized_fixture(vec![target(10)])?;
    let authorized_record = latest_record(&authorized.state, authorized.request)?;
    assert_eq!(
        frozen_record.validate_replacement(&authorized_record),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let history = awaiting_fixture(vec![target(10)])?;
    let authorized = historical_record(&history.state, ErasureLifecycleV1::Authorized, |_| true)?;
    let dispatched = historical_record(
        &history.state,
        ErasureLifecycleV1::DestructionDispatched,
        |_| true,
    )?;
    assert_eq!(
        authorized.validate_replacement(&dispatched),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_records_bind_minimal_acknowledgement_trust_and_record_request(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let target = target(10);
    let admission = retry_admission(request, target, 0, None, u64::MAX)?;
    let acknowledgement = acknowledgement_for(
        request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    let wrong_trust =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request,
            command: destruction_command_reference(request, target),
            attempt: admission.reference(),
            obligation: acknowledgement.obligation,
            owner: acknowledgement.owner,
            scope: reference(96),
            outcome: acknowledgement.outcome,
            evidence: acknowledgement.evidence,
            policy: admission.policy(),
            trust: reference(97),
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            retry_admissions: vec![admission],
            acknowledgement_provenance: vec![wrong_trust],
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let target = target(10);
    let mut scoped = awaiting_fixture(vec![target])?;
    let acknowledgement = acknowledgement_for(
        scoped.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    scoped
        .machine
        .acknowledge(scoped.request, acknowledgement)?;
    let scoped_record = latest_record(&scoped.state, scoped.request)?;
    let mut scoped_supporting = supporting_input(scoped_record.supporting_records());
    let admitted = scoped_supporting
        .acknowledgement_provenance
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    scoped_supporting.acknowledgement_provenance = vec![ErasureAcknowledgementProvenanceV1::new(
        ErasureAcknowledgementProvenanceInputV1 {
            request: admitted.request(),
            command: admitted.command(),
            attempt: admitted.attempt(),
            obligation: admitted.obligation(),
            owner: admitted.owner(),
            scope: reference(99),
            outcome: admitted.outcome(),
            evidence: admitted.evidence(),
            policy: admitted.policy(),
            trust: admitted.trust(),
        },
    )?];
    assert_eq!(
        ErasureSupportingRecordsV1::new(scoped_supporting),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let fixture = submitted_fixture(vec![target])?;
    let submitted = latest_record(&fixture.state, fixture.request)?;
    let frozen = frozen_fixture(vec![target])?;
    let frozen_record = latest_record(&frozen.state, frozen.request)?;
    let mut parts = record_parts(&submitted);
    parts.supporting_records = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        administrative_resolutions: vec![administrative_resolution(&frozen_record)?],
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, COORDINATOR),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn replacement_validation_accepts_each_same_state_persistence_extension(
) -> Result<(), ErasureErrorV1> {
    let frozen = frozen_fixture(vec![target(10)])?;
    let frozen_record = latest_record(&frozen.state, frozen.request)?;
    let resolution = administrative_resolution(&frozen_record)?;
    let mut resolution_parts = record_parts(&frozen_record);
    let mut resolution_supporting = supporting_input(frozen_record.supporting_records());
    resolution_supporting.administrative_resolutions = vec![resolution.clone()];
    resolution_parts.supporting_records = ErasureSupportingRecordsV1::new(resolution_supporting)?;
    resolution_parts.administrative_resolution_head = Some(resolution.reference());
    let with_resolution = ErasureCoordinatorRecordV1::from_parts(resolution_parts, COORDINATOR)?;
    assert_eq!(frozen_record.validate_replacement(&with_resolution), Ok(()));

    let awaiting = awaiting_fixture(vec![target(10)])?;
    let frozen_without_intent = historical_record(
        &awaiting.state,
        ErasureLifecycleV1::AccessFrozen,
        |record| record.dispatch_provenance().is_none(),
    )?;
    let frozen_with_intent = historical_record(
        &awaiting.state,
        ErasureLifecycleV1::AccessFrozen,
        |record| record.dispatch_provenance().is_some(),
    )?;
    assert_eq!(
        frozen_without_intent.validate_replacement(&frozen_with_intent),
        Ok(())
    );

    let mut complete = awaiting_fixture(vec![target(10)])?;
    let before_acknowledgement = latest_record(&complete.state, complete.request)?;
    let acknowledgement = acknowledgement_for(
        complete.request,
        target(10),
        target(10).replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    complete
        .machine
        .acknowledge(complete.request, acknowledgement)?;
    let after_acknowledgement = latest_record(&complete.state, complete.request)?;
    assert_eq!(
        before_acknowledgement.validate_replacement(&after_acknowledgement),
        Ok(())
    );
    Ok(())
}

#[test]
fn coordinator_propagates_attempt_dispatch_acknowledgement_and_receipt_failures(
) -> Result<(), ErasureErrorV1> {
    let target = target(10);

    let mut attempt = frozen_fixture(vec![target])?;
    attempt.state.borrow_mut().attempt_error = Some(ErasureErrorV1::Unauthorized);
    let admission = retry_admission(attempt.request, target, 0, None, u64::MAX)?;
    assert_eq!(
        attempt
            .machine
            .dispatch_attempt(attempt.request, &admission),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut dispatch = frozen_fixture(vec![target])?;
    dispatch.state.borrow_mut().dispatch_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        dispatch
            .machine
            .dispatch_destruction(dispatch.request, reference(94)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut acknowledge = awaiting_fixture(vec![target])?;
    let acknowledgement = acknowledgement_for(
        acknowledge.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    acknowledge.state.borrow_mut().acknowledgement_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        acknowledge
            .machine
            .acknowledge(acknowledge.request, acknowledgement),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut finalize = awaiting_fixture(vec![target])?;
    finalize
        .machine
        .acknowledge(finalize.request, acknowledgement)?;
    finalize.state.borrow_mut().receipt_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        finalize.machine.finalize(
            finalize.request,
            receipt_input(
                finalize.request,
                target,
                acknowledgement,
                ErasureLifecycleV1::Complete,
                11,
            ),
        ),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn coordinator_propagates_authentication_authorization_and_resolution_failures(
) -> Result<(), ErasureErrorV1> {
    let mut authenticate = submitted_fixture(Vec::new())?;
    authenticate.state.borrow_mut().authenticate_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        authenticate
            .machine
            .submit(request_with(reference(40), reference(41))?, reference(42)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut authorize = submitted_fixture(Vec::new())?;
    authorize.state.borrow_mut().authorization_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        authorize.machine.authorize(authorize.request, reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut reject = submitted_fixture(Vec::new())?;
    reject.state.borrow_mut().authorization_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        reject.machine.reject(reject.request, reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut resolve = authorized_fixture(Vec::new())?;
    let record = latest_record(&resolve.state, resolve.request)?;
    resolve.state.borrow_mut().resolver_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        resolve
            .machine
            .submit(record.request().clone(), record.state().provenance()),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn corrected_submission_propagates_host_admission_failures() -> Result<(), ErasureErrorV1> {
    for authenticate_fails in [true, false] {
        let mut fixture = submitted_fixture(Vec::new())?;
        fixture.machine.reject(fixture.request, reference(9))?;
        let rejected = latest_record(&fixture.state, fixture.request)?;
        let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: fixture.request,
            rejected_terminal_state: rejected.state().state_digest(),
            correction_reason: reference(31),
            authorization_provenance: reference(32),
        })?;
        let request = request_with(reference(40), correction.reference())?;
        if authenticate_fails {
            fixture.state.borrow_mut().authenticate_error = Some(ErasureErrorV1::Unauthorized);
        } else {
            fixture.state.borrow_mut().correction_error = Some(ErasureErrorV1::Unauthorized);
        }
        assert_eq!(
            fixture.machine.submit_corrected(request, correction),
            Err(ErasureErrorV1::Unauthorized)
        );
    }
    Ok(())
}

#[test]
fn dispatch_rejects_a_command_outside_the_frozen_closure() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut fixture = frozen_fixture(vec![target])?;
    let invalid = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: fixture.request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target,
            owner: target.replica_id,
            command_identity: destruction_command_reference(fixture.request, target),
        })?
        .reference()],
        command_identities: vec![reference(99)],
        policy: reference(6),
        trust: reference(94),
        admitted_position: 9,
        deadline_position: u64::MAX,
        authorization_provenance: reference(94),
    })?;
    assert_eq!(
        fixture.machine.dispatch_attempt(fixture.request, &invalid),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn active_retry_can_commit_a_new_partial_failure_receipt() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut fixture = partial_failure_fixture()?;
    let record = latest_record(&fixture.state, fixture.request)?;
    let source_receipt = record
        .receipt()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .receipt_digest();
    let retry = retry_admission(fixture.request, target, 1, Some(source_receipt), 20)?;
    fixture.machine.dispatch_attempt(fixture.request, &retry)?;
    let retry_acknowledgement = acknowledgement_for(
        fixture.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Negative,
        reference(97),
    )?;
    fixture
        .machine
        .acknowledge(fixture.request, retry_acknowledgement)?;
    let receipt = fixture.machine.finalize(
        fixture.request,
        receipt_input(
            fixture.request,
            target,
            retry_acknowledgement,
            ErasureLifecycleV1::PartialFailure,
            20,
        ),
    )?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
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
    let corrected = corrected_record_for(
        predecessor.request().reference(),
        predecessor.state().state_digest(),
    )?;

    assert_eq!(
        corrected.validate_correction_predecessor(&predecessor),
        Ok(())
    );
    assert_eq!(
        corrected.validate_correction_predecessor(&corrected),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let submitted = historical_record(
        &predecessor_fixture.state,
        ErasureLifecycleV1::Submitted,
        |_| true,
    )?;
    let lifecycle_bound = corrected_record_for(
        submitted.request().reference(),
        submitted.state().state_digest(),
    )?;
    assert_eq!(
        lifecycle_bound.validate_correction_predecessor(&submitted),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut other_rejection = submitted_fixture(vec![target(10)])?;
    other_rejection
        .machine
        .reject(other_rejection.request, reference(59))?;
    let different_terminal = latest_record(&other_rejection.state, other_rejection.request)?;
    assert_eq!(
        corrected.validate_correction_predecessor(&different_terminal),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn atomic_freeze_binds_closure_scope_evidence_and_position() -> Result<(), ErasureErrorV1> {
    let fixture = frozen_fixture(vec![target(10)])?;
    let frozen = latest_record(&fixture.state, fixture.request)?;
    assert!(frozen.to_canonical_cbor().is_ok());

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
        scope_members: original_scope.scope_members().to_vec(),
        target_closure: reference(92),
        lineage_rule: original_scope.lineage_rule(),
    })?;
    let changed_scope_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request: original_freeze.request(),
        scope_commitment: changed_scope.reference(),
        obligation_set: original_freeze.obligation_set(),
        freeze_position: original_freeze.freeze_position(),
        host_evidence: original_freeze.host_evidence(),
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
        obligation_set: original_freeze.obligation_set(),
        freeze_position: original_freeze.freeze_position(),
        host_evidence: reference(93),
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
        obligation_set: original_freeze.obligation_set(),
        freeze_position: 11,
        host_evidence: original_freeze.host_evidence(),
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

fn assert_atomic_scope_invalid(input: ErasureAtomicFreezeAdmissionInputV1) {
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(input),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn atomic_freeze_rejects_inconsistent_closure_identity() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let first_target = target(10);
    let second_target = target(20);
    let base = atomic_admission_input(request, vec![first_target, second_target], false, None)?;
    assert!(ErasureAtomicFreezeAdmissionV1::new(base.clone()).is_ok());

    let mut empty_targets = base.clone();
    empty_targets.targets.clear();
    assert_atomic_scope_invalid(empty_targets);

    let mut unsorted_targets = base.clone();
    unsorted_targets.targets.reverse();
    assert_atomic_scope_invalid(unsorted_targets);

    let mut mismatched_request = base.clone();
    mismatched_request.scope.request = reference(99);
    assert_atomic_scope_invalid(mismatched_request);

    let mut zero_closure = base.clone();
    zero_closure.scope.target_closure = reference(0);
    assert_atomic_scope_invalid(zero_closure);

    let mut wrong_obligation_order = base;
    wrong_obligation_order.obligations.reverse();
    assert_atomic_scope_invalid(wrong_obligation_order);
    Ok(())
}

#[test]
fn atomic_freeze_rejects_unbound_obligations() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let first_target = target(10);
    let base = atomic_admission_input(request, vec![first_target, target(20)], false, None)?;
    let outside_obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: target(30),
        owner: reference(33),
        command_identity: destruction_command_reference(request, target(30)),
    })?;
    let mut outside_target = base.clone();
    outside_target.obligations = vec![outside_obligation];
    let outside_target = bind_atomic_obligations(outside_target)?;
    assert_atomic_scope_invalid(outside_target);

    let wrong_command = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: first_target,
        owner: first_target.replica_id,
        command_identity: reference(99),
    })?;
    let mut wrong_command_input = base;
    wrong_command_input.obligations = vec![wrong_command];
    let wrong_command_input = bind_atomic_obligations(wrong_command_input)?;
    assert_atomic_scope_invalid(wrong_command_input);
    Ok(())
}

#[test]
fn atomic_freeze_rejects_duplicate_obligation_coordinates() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let first_target = target(10);
    let base = atomic_admission_input(request, vec![first_target, target(20)], false, None)?;
    let duplicate_target_obligations = [first_target.replica_id, reference(99)]
        .into_iter()
        .map(|owner| {
            ErasureObligationV1::new(ErasureObligationInputV1 {
                category: ErasureInventoryCategoryV1::Artifact,
                target: first_target,
                owner,
                command_identity: destruction_command_reference(request, first_target),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut duplicate_target = base.clone();
    duplicate_target.obligations = duplicate_target_obligations;
    let duplicate_target = bind_atomic_obligations(duplicate_target)?;
    assert_atomic_scope_invalid(duplicate_target);

    let duplicate_command_owner = [
        ErasureInventoryCategoryV1::Artifact,
        ErasureInventoryCategoryV1::Key,
    ]
    .into_iter()
    .map(|category| {
        ErasureObligationV1::new(ErasureObligationInputV1 {
            category,
            target: first_target,
            owner: first_target.replica_id,
            command_identity: destruction_command_reference(request, first_target),
        })
    })
    .collect::<Result<Vec<_>, _>>()?;
    let mut duplicate_command = base;
    duplicate_command.obligations = duplicate_command_owner;
    let duplicate_command = bind_atomic_obligations(duplicate_command)?;
    assert_atomic_scope_invalid(duplicate_command);
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
        Err(ErasureErrorV1::ProvenanceMissing)
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
        scope_members: vec![reference(3)],
        target_closure: target_closure_digest(&empty_targets),
        lineage_rule: None,
    })?;
    let mut authorized_parts = record_parts(&authorized_record);
    let mut authorized_supporting = supporting_input(authorized_record.supporting_records());
    authorized_supporting.scope_commitment = Some(scope);
    authorized_parts.supporting_records = ErasureSupportingRecordsV1::new(authorized_supporting)?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(authorized_parts, COORDINATOR),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let rejected = empty_target_rejection_fixture()?;
    let rejected_record = latest_record(&rejected.state, rejected.request)?;
    let rejected_scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request: rejected.request,
        scope_members: vec![reference(3)],
        target_closure: target_closure_digest(&[]),
        lineage_rule: None,
    })?;
    let mut rejected_with_scope = record_parts(&rejected_record);
    rejected_with_scope.supporting_records =
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(rejected_scope),
            ..ErasureSupportingRecordsInputV1::default()
        })?;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(rejected_with_scope, COORDINATOR),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut authorized_with_failure = record_parts(&authorized_record);
    authorized_with_failure.supporting_records = rejected_record.supporting_records().clone();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(authorized_with_failure, COORDINATOR),
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
        frozen.request,
        target(10),
        target(10).replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(97),
    )?;
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
    fixture.state.borrow_mut().freeze_rejection = Some(ErasureErrorV1::ScopeInvalid);
    assert_eq!(
        fixture
            .machine
            .freeze_inventory(fixture.request, freeze_transition())?
            .lifecycle(),
        ErasureLifecycleV1::Rejected
    );
    Ok(fixture)
}

#[test]
fn freeze_rejects_an_empty_required_target_closure() -> Result<(), ErasureErrorV1> {
    let mut fixture = empty_target_rejection_fixture()?;
    let record = latest_record(&fixture.state, fixture.request)?;
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Rejected);
    assert!(record.supporting_records().freeze_failure().is_some());
    assert_eq!(
        fixture
            .machine
            .freeze_inventory(fixture.request, freeze_transition())?
            .lifecycle(),
        ErasureLifecycleV1::Rejected
    );
    Ok(())
}

#[test]
fn freeze_rejects_duplicate_and_oversized_target_closures() -> Result<(), ErasureErrorV1> {
    for targets in [vec![target(10), target(10)], vec![target(10); 257]] {
        let mut fixture = authorized_fixture(targets)?;
        fixture.state.borrow_mut().freeze_rejection = Some(ErasureErrorV1::ScopeInvalid);
        assert_eq!(
            fixture
                .machine
                .freeze_inventory(fixture.request, freeze_transition())?
                .lifecycle(),
            ErasureLifecycleV1::Rejected
        );
        assert_eq!(
            latest_record(&fixture.state, fixture.request)?
                .state()
                .lifecycle(),
            ErasureLifecycleV1::Rejected
        );
    }
    Ok(())
}

#[test]
fn freeze_preserves_closed_port_errors_without_persisting_a_rejection() -> Result<(), ErasureErrorV1>
{
    for (field, error) in [
        (
            FreezePortFailure::RequiredTargets,
            ErasureErrorV1::ScopeInvalid,
        ),
        (
            FreezePortFailure::RequiredTargets,
            ErasureErrorV1::Unauthorized,
        ),
        (
            FreezePortFailure::AffectedScope,
            ErasureErrorV1::ScopeInvalid,
        ),
        (
            FreezePortFailure::AffectedScope,
            ErasureErrorV1::Unauthorized,
        ),
        (FreezePortFailure::Admission, ErasureErrorV1::ScopeInvalid),
        (
            FreezePortFailure::Admission,
            ErasureErrorV1::AccessFreezeFailed,
        ),
        (FreezePortFailure::Admission, ErasureErrorV1::Unauthorized),
    ] {
        let mut fixture = authorized_fixture(vec![target(10)])?;
        match field {
            FreezePortFailure::RequiredTargets => {
                fixture.state.borrow_mut().frozen_targets_error = Some(error);
            }
            FreezePortFailure::AffectedScope => {
                fixture.state.borrow_mut().scope_members_error = Some(error);
            }
            FreezePortFailure::Admission => {
                fixture.state.borrow_mut().freeze_error = Some(error);
            }
        }
        assert_eq!(
            fixture
                .machine
                .freeze_inventory(fixture.request, freeze_transition()),
            Err(error)
        );
        let record = latest_record(&fixture.state, fixture.request)?;
        assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Authorized);
        assert!(record.supporting_records().freeze_failure().is_none());
    }

    let mut mismatch = authorized_fixture(vec![target(10)])?;
    mismatch.state.borrow_mut().mismatched_freeze_closure = true;
    assert_eq!(
        mismatch
            .machine
            .freeze_inventory(mismatch.request, freeze_transition()),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        latest_record(&mismatch.state, mismatch.request)?
            .state()
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    Ok(())
}

#[test]
fn freeze_rejects_host_evidence_bound_to_another_request_or_authorization(
) -> Result<(), ErasureErrorV1> {
    let mut wrong_request = authorized_fixture(vec![target(10)])?;
    wrong_request.state.borrow_mut().freeze_admission_request = Some(reference(99));
    assert_eq!(
        wrong_request
            .machine
            .freeze_inventory(wrong_request.request, freeze_transition()),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut wrong_authorization = authorized_fixture(vec![target(10)])?;
    {
        let mut state = wrong_authorization.state.borrow_mut();
        state.freeze_rejection = Some(ErasureErrorV1::ScopeInvalid);
        state.freeze_rejection_authorization = Some(reference(99));
    }
    assert_eq!(
        wrong_authorization
            .machine
            .freeze_inventory(wrong_authorization.request, freeze_transition()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn freeze_retry_is_idempotent_only_for_the_freeze_transition() -> Result<(), ErasureErrorV1> {
    let mut fixture = frozen_fixture(vec![target(10)])?;
    assert_eq!(
        fixture
            .machine
            .freeze_inventory(fixture.request, freeze_transition())?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    let mut wrong = freeze_transition();
    wrong.lifecycle = ErasureLifecycleV1::Complete;
    assert_eq!(
        fixture.machine.freeze_inventory(fixture.request, wrong),
        Err(ErasureErrorV1::PolicyConflict)
    );
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
fn dispatch_attempt_retries_exact_admission_and_rejects_another_closure(
) -> Result<(), ErasureErrorV1> {
    let frozen_target = target(10);
    let mut fixture = frozen_fixture(vec![frozen_target])?;
    let admission = retry_admission(fixture.request, frozen_target, 0, None, 20)?;
    fixture
        .machine
        .dispatch_attempt(fixture.request, &admission)?;
    assert_eq!(
        fixture
            .machine
            .dispatch_attempt(fixture.request, &admission)?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );

    let mut another = frozen_fixture(vec![frozen_target])?;
    let outside = retry_admission(another.request, target(20), 0, None, 20)?;
    assert_eq!(
        another.machine.dispatch_attempt(another.request, &outside),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn dispatch_attempt_rejects_a_valid_admission_from_the_wrong_lifecycle(
) -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut fixture = authorized_fixture(vec![target])?;
    let admission = retry_admission(fixture.request, target, 0, None, 20)?;
    assert_eq!(
        fixture
            .machine
            .dispatch_attempt(fixture.request, &admission),
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
        accepted.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    accepted
        .machine
        .acknowledge(accepted.request, acknowledgement)?;
    let conflicting = acknowledgement_for(
        accepted.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(96),
    )?;
    assert_eq!(
        accepted.machine.acknowledge(accepted.request, conflicting),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut different_owner = acknowledgement;
    different_owner.owner = reference(97);
    different_owner.evidence = reference(98);
    assert_eq!(
        accepted
            .machine
            .acknowledge(accepted.request, different_owner),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut different_obligation = acknowledgement;
    different_obligation.obligation = reference(99);
    different_obligation.evidence = reference(100);
    assert_eq!(
        accepted
            .machine
            .acknowledge(accepted.request, different_obligation),
        Err(ErasureErrorV1::Unauthorized)
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
fn retry_acknowledgement_must_belong_to_the_active_attempt() -> Result<(), ErasureErrorV1> {
    let first = target(10);
    let second = target(20);
    let mut fixture = frozen_fixture(vec![first, second])?;
    let initial = latest_record(&fixture.state, fixture.request)?;
    let obligations = initial.supporting_records().obligations();
    let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: fixture.request,
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
        policy: reference(6),
        trust: reference(94),
        admitted_position: 9,
        deadline_position: 10,
        authorization_provenance: reference(94),
    })?;
    fixture
        .machine
        .dispatch_attempt(fixture.request, &admission)?;
    let acknowledged = acknowledgement_for(
        fixture.request,
        first,
        first.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    let negative = acknowledgement_for(
        fixture.request,
        second,
        second.replica_id,
        ErasureAcknowledgementOutcomeV1::Negative,
        reference(96),
    )?;
    fixture.machine.acknowledge(fixture.request, acknowledged)?;
    fixture.machine.acknowledge(fixture.request, negative)?;
    let mut input = receipt_input(
        fixture.request,
        first,
        acknowledged,
        ErasureLifecycleV1::PartialFailure,
        11,
    );
    input
        .inventories
        .artifacts
        .push(inventory_for(second, second.replica_id));
    fixture.machine.finalize(fixture.request, input)?;
    let partial = latest_record(&fixture.state, fixture.request)?;
    let receipt = partial.receipt().ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let retry = retry_admission(
        fixture.request,
        second,
        1,
        Some(receipt.receipt_digest()),
        20,
    )?;
    fixture.machine.dispatch_attempt(fixture.request, &retry)?;
    let conflicting = acknowledgement_for(
        fixture.request,
        first,
        first.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(97),
    )?;
    assert_eq!(
        fixture.machine.acknowledge(fixture.request, conflicting),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn finalization_allows_partial_failure_after_the_attempt_deadline() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut fixture = frozen_fixture(vec![target])?;
    let admission = retry_admission(fixture.request, target, 0, None, 10)?;
    fixture
        .machine
        .dispatch_attempt(fixture.request, &admission)?;
    let acknowledgement = acknowledgement_for(
        fixture.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Negative,
        reference(96),
    )?;
    fixture
        .machine
        .acknowledge(fixture.request, acknowledgement)?;
    assert_eq!(
        fixture
            .machine
            .finalize(
                fixture.request,
                receipt_input(
                    fixture.request,
                    target,
                    acknowledgement,
                    ErasureLifecycleV1::PartialFailure,
                    11,
                ),
            )?
            .lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}

#[test]
fn finalization_requires_deadline_or_administrative_closure() -> Result<(), ErasureErrorV1> {
    let target = target(10);
    let mut early = frozen_fixture(vec![target])?;
    let admission = retry_admission(early.request, target, 0, None, 20)?;
    early.machine.dispatch_attempt(early.request, &admission)?;
    let negative = acknowledgement_for(
        early.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Negative,
        reference(96),
    )?;
    early.machine.acknowledge(early.request, negative)?;
    assert_eq!(
        early.machine.finalize(
            early.request,
            receipt_input(
                early.request,
                target,
                negative,
                ErasureLifecycleV1::PartialFailure,
                10,
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let record = latest_record(&early.state, early.request)?;
    let resolution = administrative_resolution(&record)?;
    early
        .machine
        .resolve_administratively(early.request, resolution)?;
    assert_eq!(
        early
            .machine
            .finalize(
                early.request,
                receipt_input(
                    early.request,
                    target,
                    negative,
                    ErasureLifecycleV1::PartialFailure,
                    10,
                ),
            )?
            .lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}

#[test]
fn finalization_rejects_inventory_outside_the_frozen_obligations() -> Result<(), ErasureErrorV1> {
    let frozen_target = target(10);
    let mut fixture = awaiting_fixture(vec![frozen_target])?;
    let acknowledgement = acknowledgement_for(
        fixture.request,
        frozen_target,
        frozen_target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    fixture
        .machine
        .acknowledge(fixture.request, acknowledgement)?;
    let mut input = receipt_input(
        fixture.request,
        frozen_target,
        acknowledgement,
        ErasureLifecycleV1::Complete,
        11,
    );
    input.inventories.artifacts[0].target = target(20);
    assert_eq!(
        fixture.machine.finalize(fixture.request, input),
        Err(ErasureErrorV1::ScopeInvalid)
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
        fixture.request,
        first_target,
        first_target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    let mut second = acknowledgement_for(
        fixture.request,
        second_target,
        first_target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(96),
    )?;
    second.obligation = first.obligation;
    let mut parts = record_parts(&frozen);
    parts.acknowledgements = vec![first, second];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, COORDINATOR),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn coordinator_cas_methods_advance_and_retry_exact_evidence() -> Result<(), ErasureErrorV1> {
    let mut fixture = authorized_fixture(vec![target(10)])?;
    fixture.state.borrow_mut().lineage_rule = Some(reference(55));
    fixture
        .machine
        .freeze_inventory(fixture.request, freeze_transition())?;

    let frozen = latest_record(&fixture.state, fixture.request)?;
    let scope = frozen
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: fixture.request,
        scope_commitment: scope.reference(),
        fork: reference(56),
        lineage_rule: reference(55),
        predecessor_extension: None,
        admission_provenance: reference(57),
    })?;
    ErasureCoordinator::append_scope_extension(&mut fixture.machine, fixture.request, extension)?;
    ErasureCoordinator::append_scope_extension(&mut fixture.machine, fixture.request, extension)?;
    let extended = latest_record(&fixture.state, fixture.request)?;
    assert_eq!(
        extended.supporting_records().scope_extensions().last(),
        Some(&extension)
    );

    let wrong_predecessor = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: fixture.request,
        scope_commitment: scope.reference(),
        fork: reference(58),
        lineage_rule: reference(55),
        predecessor_extension: None,
        admission_provenance: reference(59),
    })?;
    assert_eq!(
        fixture
            .machine
            .append_scope_extension(fixture.request, wrong_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let resolution = administrative_resolution(&extended)?;
    ErasureCoordinator::resolve_administratively(
        &mut fixture.machine,
        fixture.request,
        resolution.clone(),
    )?;
    ErasureCoordinator::resolve_administratively(
        &mut fixture.machine,
        fixture.request,
        resolution.clone(),
    )?;
    let resolved = latest_record(&fixture.state, fixture.request)?;
    assert_eq!(
        resolved.administrative_resolution_head(),
        Some(resolution.reference())
    );

    let wrong_predecessor =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: fixture.request,
            affected_digests: vec![resolved.state().state_digest()],
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: scope.reference(),
            policy: resolved.request().policy(),
            trust: resolved
                .supporting_records()
                .obligation_set()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?
                .trust(),
            principal: reference(72),
            authorization_provenance: reference(73),
            reason: reference(75),
            issue_position: 22,
            predecessor_resolution: None,
        })?;
    assert_eq!(
        fixture
            .machine
            .resolve_administratively(fixture.request, wrong_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn coordinator_propagates_durable_and_cas_port_failures() -> Result<(), ErasureErrorV1> {
    let mut unavailable = submitted_fixture(vec![target(10)])?;
    unavailable.state.borrow_mut().load_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        unavailable
            .machine
            .authorize(unavailable.request, reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut uncommitted = submitted_fixture(vec![target(10)])?;
    uncommitted.state.borrow_mut().commit_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        uncommitted
            .machine
            .authorize(uncommitted.request, reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut extension_fixture = authorized_fixture(vec![target(10)])?;
    extension_fixture.state.borrow_mut().lineage_rule = Some(reference(55));
    extension_fixture
        .machine
        .freeze_inventory(extension_fixture.request, freeze_transition())?;
    let record = latest_record(&extension_fixture.state, extension_fixture.request)?;
    let scope = record
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: extension_fixture.request,
        scope_commitment: scope.reference(),
        fork: reference(56),
        lineage_rule: reference(55),
        predecessor_extension: None,
        admission_provenance: reference(57),
    })?;
    extension_fixture.state.borrow_mut().scope_extension_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        extension_fixture
            .machine
            .append_scope_extension(extension_fixture.request, extension),
        Err(ErasureErrorV1::Unauthorized)
    );
    extension_fixture.state.borrow_mut().scope_extension_error = None;
    extension_fixture.state.borrow_mut().scope_cas_error = Some(ErasureErrorV1::PolicyConflict);
    assert_eq!(
        extension_fixture
            .machine
            .append_scope_extension(extension_fixture.request, extension),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut resolution_fixture = frozen_fixture(vec![target(10)])?;
    let record = latest_record(&resolution_fixture.state, resolution_fixture.request)?;
    let resolution = administrative_resolution(&record)?;
    resolution_fixture
        .state
        .borrow_mut()
        .administrative_resolution_error = Some(ErasureErrorV1::Unauthorized);
    assert_eq!(
        resolution_fixture
            .machine
            .resolve_administratively(resolution_fixture.request, resolution.clone()),
        Err(ErasureErrorV1::Unauthorized)
    );
    resolution_fixture
        .state
        .borrow_mut()
        .administrative_resolution_error = None;
    resolution_fixture
        .state
        .borrow_mut()
        .administrative_cas_error = Some(ErasureErrorV1::PolicyConflict);
    assert_eq!(
        resolution_fixture
            .machine
            .resolve_administratively(resolution_fixture.request, resolution),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn coordinator_cas_methods_require_frozen_scope_evidence() -> Result<(), ErasureErrorV1> {
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: reference(2),
        fork: reference(3),
        lineage_rule: reference(4),
        predecessor_extension: None,
        admission_provenance: reference(5),
    })?;
    let mut submitted = submitted_fixture(Vec::new())?;
    assert_eq!(
        submitted
            .machine
            .append_scope_extension(submitted.request, extension),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut frozen = frozen_fixture(vec![target(10)])?;
    assert_eq!(
        frozen
            .machine
            .append_scope_extension(frozen.request, extension),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: submitted.request,
            affected_digests: vec![reference(6)],
            action: ErasureAdministrativeResolutionActionV1::CloseContainment,
            scope_commitment: reference(2),
            policy: reference(6),
            trust: reference(7),
            principal: reference(8),
            authorization_provenance: reference(9),
            reason: reference(10),
            issue_position: 11,
            predecessor_resolution: None,
        })?;
    assert_eq!(
        submitted
            .machine
            .resolve_administratively(submitted.request, resolution),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn coordinator_trait_forwards_public_lifecycle_operations() -> Result<(), ErasureErrorV1> {
    let mut submitted = submitted_fixture(vec![target(10)])?;
    let second_request = request_with(reference(40), reference(41))?;
    let second_reference = second_request.reference();
    ErasureCoordinator::submit(&mut submitted.machine, second_request)?;
    ErasureCoordinator::authorize(&mut submitted.machine, second_reference, reference(42))?;

    let target = target(10);
    let mut awaiting = awaiting_fixture(vec![target])?;
    let acknowledgement = acknowledgement_for(
        awaiting.request,
        target,
        target.replica_id,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        reference(95),
    )?;
    ErasureCoordinator::acknowledge(&mut awaiting.machine, awaiting.request, acknowledgement)?;
    ErasureCoordinator::acknowledge(&mut awaiting.machine, awaiting.request, acknowledgement)?;
    let receipt = ErasureCoordinator::finalize(
        &mut awaiting.machine,
        awaiting.request,
        receipt_input(
            awaiting.request,
            target,
            acknowledgement,
            ErasureLifecycleV1::Complete,
            11,
        ),
    )?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[test]
fn coordinator_trait_submits_and_retries_a_corrected_request() -> Result<(), ErasureErrorV1> {
    let mut fixture = submitted_fixture(Vec::new())?;
    fixture.machine.reject(fixture.request, reference(9))?;
    let rejected = latest_record(&fixture.state, fixture.request)?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: fixture.request,
        rejected_terminal_state: rejected.state().state_digest(),
        correction_reason: reference(31),
        authorization_provenance: reference(32),
    })?;
    let corrected = request_with(reference(40), correction.reference())?;
    let corrected_reference = corrected.reference();
    ErasureCoordinator::submit_corrected(
        &mut fixture.machine,
        corrected.clone(),
        correction.clone(),
    )?;
    let retry =
        ErasureCoordinator::submit_corrected(&mut fixture.machine, corrected, correction.clone())?;
    assert_eq!(retry.request(), corrected_reference);
    assert_eq!(retry.lifecycle(), ErasureLifecycleV1::Submitted);

    let conflicting = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: corrected_reference,
        subject: reference(99),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 9,
        horizon_position: 10,
        provenance: correction.reference(),
    })?;
    assert_eq!(
        fixture
            .machine
            .submit_corrected(conflicting, correction.clone()),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let wrong_provenance = request_with(reference(41), reference(42))?;
    assert_eq!(
        fixture
            .machine
            .submit_corrected(wrong_provenance, correction.clone()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    fixture.state.borrow_mut().load_error = Some(ErasureErrorV1::Unauthorized);
    let unavailable = request_with(reference(42), correction.reference())?;
    assert_eq!(
        fixture.machine.submit_corrected(unavailable, correction),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}
