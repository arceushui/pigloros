//! Public coordinator operations over bounded recovered state.

use super::RecoveredErasureV1;
use super::{
    acknowledgement_inventory_reference, acknowledgements_close_frozen_obligations,
    derived_outcome_owners_for_obligations, erasure_evidence_set_reference,
    inventories_match_frozen_obligations, reference_zero, selected_obligations_reference,
    sort_inventories, weakest_inventory_claim, BTreeMap, BTreeSet, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureAuthorizationDecisionV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCasEffectV1,
    ErasureCoordinator, ErasureCoordinatorPortV1, ErasureCoordinatorStateMachineV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureIndexInsertV1, ErasureLifecycleV1, ErasurePersistedStateV1, ErasurePersistenceObjectV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1, ErasureStateTransitionV1,
    ErasureStateV1, PreparedErasureCasV1,
};
use super::{
    ErasureAcknowledgementV1, ErasureReceiptInputV1, ErasureReceiptV1, ErasureRetryAdmissionV1,
};

struct TerminalAttemptV1 {
    admission: ErasureRetryAdmissionV1,
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    lifecycle: ErasureLifecycleV1,
    outcome: ErasureAttemptOutcomeV1,
    state: ErasureStateV1,
    receipt_provenance: ErasureReceiptProvenanceV1,
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinatorStateMachineV1<P> {
    /// Construct a coordinator. The cache is a bounded working projection;
    /// durable ERCRP1 remains authoritative.
    #[must_use]
    pub const fn new(port: P, coordinator: ErasureReferenceV1) -> Self {
        Self {
            port,
            coordinator,
            records: Vec::new(),
        }
    }

    fn cache(&mut self, recovered: RecoveredErasureV1) {
        if let Some(slot) = self
            .records
            .iter_mut()
            .find(|value| value.request.reference() == recovered.request.reference())
        {
            *slot = recovered;
        } else {
            self.records.push(recovered);
        }
    }

    fn recover(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<RecoveredErasureV1>, ErasureErrorV1> {
        self.port
            .read_manifest(request)?
            .map(|stored| RecoveredErasureV1::recover(&self.port, &self.port, request, &stored))
            .transpose()
    }

    fn record(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<RecoveredErasureV1, ErasureErrorV1> {
        if let Some(record) = self
            .records
            .iter()
            .find(|record| record.request.reference() == request)
        {
            return Ok(record.clone());
        }
        self.recover(request)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .inspect(|record| {
                self.cache(record.clone());
            })
    }

    fn commit(
        &mut self,
        next: RecoveredErasureV1,
        expected: Option<ErasureReferenceV1>,
        include_request: bool,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::commit_objects(&next, include_request).and_then(|objects| {
            self.commit_delta(
                next,
                expected,
                objects,
                Vec::new(),
                ErasureCasEffectV1::None,
            )
        })
    }

    fn commit_objects(
        next: &RecoveredErasureV1,
        include_request: bool,
    ) -> Result<Vec<ErasurePersistenceObjectV1>, ErasureErrorV1> {
        let mut objects = Vec::new();
        if include_request {
            objects.push(next.request_object()?);
        }
        Ok(objects)
    }

    fn commit_delta(
        &mut self,
        mut next: RecoveredErasureV1,
        expected: Option<ErasureReferenceV1>,
        objects: Vec<ErasurePersistenceObjectV1>,
        indexes: Vec<ErasureIndexInsertV1>,
        effect: ErasureCasEffectV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let states = vec![next.state_object()?];
        let prepared: PreparedErasureCasV1 =
            next.prepare(expected, objects, states, indexes, effect)?;
        let next_digest = prepared.next_manifest().digest();
        if let Err(error) = self.port.compare_and_swap(prepared) {
            if error == ErasureErrorV1::PolicyConflict {
                self.records
                    .retain(|record| record.request.reference() != next.request.reference());
            }
            return Err(error);
        }
        next.manifest_digest = next_digest;
        let state = next.state.clone();
        self.cache(next);
        Ok(state)
    }

    /// Query a warm recovered state without consulting an adapter.
    #[must_use]
    pub fn existing(&self, request: ErasureReferenceV1) -> Option<&ErasureStateV1> {
        self.records
            .iter()
            .find(|record| record.request.reference() == request)
            .map(RecoveredErasureV1::state)
    }

    /// Authenticate and submit ERQ1 through an initial manifest CAS.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication, persistence, or conflicting-identity error.
    pub fn submit(
        &mut self,
        request: ErasureRequestV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        match self.recover(request.reference())? {
            Some(record) if record.request == request => {
                let state = record.state.clone();
                self.cache(record);
                Ok(state)
            }
            Some(_) => Err(ErasureErrorV1::PolicyConflict),
            None => self
                .port
                .authenticate(&request)
                .and_then(|()| {
                    ErasureStateV1::submitted(request.reference(), self.coordinator, provenance)
                })
                .and_then(|state| {
                    self.commit(RecoveredErasureV1::initial(request, state), None, true)
                }),
        }
    }

    /// Corrected submission retains its provenance as a new immutable object;
    /// its predecessor validation is deliberately recovered through the raw
    /// persistence seam before the initial CAS is prepared.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance, authentication, or persistence error.
    pub fn submit_corrected(
        &mut self,
        request: ErasureRequestV1,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if request.provenance() != correction.reference() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        match self.recover(request.reference())? {
            Some(record)
                if record.request == request && record.correction.as_ref() == Some(&correction) =>
            {
                let state = record.state.clone();
                self.cache(record);
                return Ok(state);
            }
            Some(_) => return Err(ErasureErrorV1::PolicyConflict),
            None => {}
        }
        let predecessor = self
            .recover(correction.rejected_request())?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if predecessor.state.lifecycle() != ErasureLifecycleV1::Rejected
            || predecessor.state.state_digest() != correction.rejected_terminal_state()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.port.authenticate(&request)?;
        self.port
            .admit_corrected_submission(&request, &correction)?;
        let state =
            ErasureStateV1::submitted(request.reference(), self.coordinator, request.provenance())?;
        let mut record = RecoveredErasureV1::initial(request, state);
        let objects = vec![record.request_object()?, record.set_correction(correction)?];
        self.commit_delta(record, None, objects, Vec::new(), ErasureCasEffectV1::None)
    }

    /// Authorize a submitted request and persist the successor ERS1.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, authorization, or CAS error.
    pub fn authorize(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if record.state.lifecycle() != ErasureLifecycleV1::Submitted {
            return (record.authorize_provenance == Some(provenance))
                .then_some(record.state)
                .ok_or(ErasureErrorV1::PolicyConflict);
        }
        self.port.admit_authorization(
            request,
            provenance,
            ErasureAuthorizationDecisionV1::Authorized,
        )?;
        let state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Authorized,
            freeze_position: None,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: record.state.replay_claim(),
            provenance,
        })?;
        record.replace_state(state);
        record.set_authorize_provenance(provenance);
        self.commit(record.clone(), Some(record.manifest_digest), false)
    }

    /// Reject a submitted request with immutable authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, authorization, or CAS error.
    pub fn reject(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if record.state.lifecycle() == ErasureLifecycleV1::Rejected {
            return record
                .rejection
                .as_ref()
                .filter(|value| value.authorization_provenance() == provenance)
                .map_or(Err(ErasureErrorV1::PolicyConflict), |_| Ok(record.state));
        }
        if record.state.lifecycle() != ErasureLifecycleV1::Submitted {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port.admit_authorization(
            request,
            provenance,
            ErasureAuthorizationDecisionV1::Rejected,
        )?;
        let rejection =
            ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
                request,
                authorization_provenance: provenance,
            })?;
        let state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Rejected,
            freeze_position: None,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: record.state.replay_claim(),
            provenance: rejection.reference(),
        })?;
        record.replace_state(state);
        let object = record.set_authorization_rejection(rejection)?;
        self.commit_delta(
            record.clone(),
            Some(record.manifest_digest),
            vec![object],
            Vec::new(),
            ErasureCasEffectV1::None,
        )
    }

    /// Persist the host's atomic access-freeze result.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, admission, or CAS error.
    pub fn freeze_inventory(
        &mut self,
        request: ErasureReferenceV1,
        transition: &ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let record = self.record(request)?;
        self.freeze_record(record, request, transition)
    }

    fn freeze_record(
        &mut self,
        mut record: RecoveredErasureV1,
        request: ErasureReferenceV1,
        transition: &ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if record.state.lifecycle() == ErasureLifecycleV1::Rejected
            && record.freeze_failure.is_some()
        {
            return Ok(record.state);
        }
        if record.freeze_provenance.is_some() {
            return (transition.lifecycle == ErasureLifecycleV1::AccessFrozen)
                .then_some(record.state)
                .ok_or(ErasureErrorV1::PolicyConflict);
        }
        if record.state.lifecycle() != ErasureLifecycleV1::Authorized {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        match self.port.admit_atomic_freeze(request, transition)? {
            ErasureAtomicFreezeResultV1::Admitted(admission) => {
                self.persist_atomic_freeze(&mut record, &admission)
            }
            ErasureAtomicFreezeResultV1::Rejected(failure) => {
                self.persist_freeze_rejection(&mut record, failure)
            }
        }
    }

    fn persist_atomic_freeze(
        &mut self,
        record: &mut RecoveredErasureV1,
        admission: &ErasureAtomicFreezeAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let request = record.request.reference();
        if admission.scope().request != request
            || admission.obligation_set().request() != request
            || admission.obligation_set().policy() != record.request.policy()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port.validate_freeze_authorization(
            admission.freeze_admission_evidence(),
            admission.freeze_authorization_evidence(),
        )?;
        let scope = ErasureScopeCommitmentV1::new(admission.scope().clone())?;
        let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
            request,
            scope_commitment: scope.reference(),
            obligation_set: admission.obligation_set().reference(),
            freeze_position: admission.freeze_position(),
            host_evidence: admission.freeze_admission_evidence().reference(),
        })?;
        let state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(admission.freeze_position()),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: record.state.replay_claim(),
            provenance: freeze.reference(),
        })?;
        record.replace_state(state);
        let objects = record.retain_atomic_freeze(admission, scope, freeze)?;
        self.commit_delta(
            record.clone(),
            Some(record.manifest_digest),
            objects,
            Vec::new(),
            ErasureCasEffectV1::None,
        )
    }

    fn persist_freeze_rejection(
        &mut self,
        record: &mut RecoveredErasureV1,
        failure: ErasureFreezeFailureV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if failure.request() != record.request.reference()
            || record.authorize_provenance != Some(failure.authorization_provenance())
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Rejected,
            freeze_position: None,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: record.state.replay_claim(),
            provenance: failure.reference(),
        })?;
        record.replace_state(state);
        let object = record.set_freeze_failure(failure)?;
        self.commit_delta(
            record.clone(),
            Some(record.manifest_digest),
            vec![object],
            Vec::new(),
            ErasureCasEffectV1::None,
        )
    }

    fn persisted_state(state: ErasureStateV1) -> Result<ErasurePersistedStateV1, ErasureErrorV1> {
        state
            .to_canonical_cbor()
            .map(|bytes| ErasurePersistedStateV1::new(state, bytes))
    }

    fn unresolved_obligations(record: &RecoveredErasureV1) -> Vec<ErasureReferenceV1> {
        let acknowledged = record
            .effective
            .values()
            .filter(|value| value.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged)
            .map(ErasureAcknowledgementProvenanceV1::obligation)
            .collect::<BTreeSet<_>>();
        record
            .obligations
            .iter()
            .filter(|value| !acknowledged.contains(&value.reference()))
            .map(super::ErasureObligationV1::reference)
            .collect()
    }

    fn commands_for_admission(
        record: &RecoveredErasureV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<Vec<ErasureDestructionCommandV1>, ErasureErrorV1> {
        let obligations = record
            .obligations
            .iter()
            .map(|value| (value.reference(), value))
            .collect::<BTreeMap<_, _>>();
        admission
            .unresolved_obligations()
            .iter()
            .zip(admission.command_identities())
            .map(|(reference, command)| {
                let obligation = obligations
                    .get(reference)
                    .copied()
                    .ok_or(ErasureErrorV1::ScopeInvalid)?;
                if obligation.command_identity() != *command {
                    return Err(ErasureErrorV1::ScopeInvalid);
                }
                Ok(ErasureDestructionCommandV1::from_obligation(
                    obligation,
                    admission.reference(),
                ))
            })
            .collect()
    }

    fn effective_acknowledgements(
        record: &RecoveredErasureV1,
    ) -> Result<Vec<ErasureAcknowledgementV1>, ErasureErrorV1> {
        record
            .effective
            .values()
            .map(|value| {
                let target = record
                    .obligations
                    .iter()
                    .find(|obligation| obligation.reference() == value.obligation())
                    .map(super::ErasureObligationV1::target)
                    .ok_or(ErasureErrorV1::ProvenanceMissing)?;
                Ok(ErasureAcknowledgementV1 {
                    target,
                    obligation: value.obligation(),
                    owner: value.owner(),
                    evidence: value.evidence(),
                    outcome: value.outcome(),
                })
            })
            .collect()
    }

    fn normalize_terminal_input(
        &self,
        record: &RecoveredErasureV1,
        mut input: ErasureReceiptInputV1,
        policy: ErasureReferenceV1,
        trust: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureReceiptInputV1, ErasureErrorV1> {
        input.request = record.request.reference();
        input.coordinator = self.coordinator;
        input.terminal_state = record.state.state_digest();
        input.lifecycle = record.state.lifecycle();
        input.freeze_position = record
            .state
            .freeze_position()
            .ok_or(ErasureErrorV1::PolicyConflict)?;
        input.frozen_targets.clone_from(&record.targets);
        input.acknowledgements = Self::effective_acknowledgements(record)?;
        input.pending_owners = record.state.pending_owners().to_vec();
        input.failed_owners = record.state.failed_owners().to_vec();
        sort_inventories(&mut input.inventories);
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        input.policy = policy;
        input.trust = trust;
        input.provenance = provenance;
        input.receipt_digest = reference_zero();
        Ok(input)
    }

    /// Admit and atomically persist one destruction attempt.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, quota, dispatch, or CAS error.
    pub fn dispatch_attempt(
        &mut self,
        request: ErasureReferenceV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if record
            .active
            .as_ref()
            .is_some_and(|active| active.admission == *admission)
        {
            return Ok(record.state);
        }
        if record.active.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !matches!(
            record.state.lifecycle(),
            ErasureLifecycleV1::AccessFrozen | ErasureLifecycleV1::PartialFailure
        ) || admission.request() != request
            || admission.attempt_ordinal() != record.completed_attempt_count
            || admission.source_receipt() != record.latest_receipt
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if admission.unresolved_obligations() != Self::unresolved_obligations(&record) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let commands = Self::commands_for_admission(&record, admission)?;
        let reservation = self.port.admit_attempt(admission)?;
        if reservation.admission() != admission.reference() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let object = record.begin_attempt(admission.clone())?;
        let mut states = Vec::new();
        if admission.attempt_ordinal() == 0 {
            let freeze_position = record.state.freeze_position();
            let replay_claim = record.state.replay_claim();
            let dispatched = record.state.transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::DestructionDispatched,
                freeze_position,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim,
                provenance: admission.reference(),
            })?;
            states.push(Self::persisted_state(dispatched.clone())?);
            record.replace_state(dispatched.transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
                freeze_position,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim,
                provenance: admission.reference(),
            })?);
        }
        states.push(record.state_object()?);
        let prepared = record.prepare(
            Some(record.manifest_digest),
            vec![object],
            states,
            Vec::new(),
            ErasureCasEffectV1::AttemptAdmission {
                reservation,
                commands,
            },
        )?;
        let next_digest = prepared.next_manifest().digest();
        self.port.compare_and_swap(prepared)?;
        record.manifest_digest = next_digest;
        let state = record.state.clone();
        self.cache(record);
        Ok(state)
    }
    /// Dispatch destruction through the stable coordinator operation.
    ///
    /// # Errors
    ///
    /// Returns a closed attempt-admission or CAS error.
    pub fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.dispatch_attempt(request, admission)
    }
    /// Persist one authenticated acknowledgement for the active attempt.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, lifecycle, or CAS error.
    pub fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if !matches!(
            record.state.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if record
            .targets
            .binary_search(&acknowledgement.target)
            .is_err()
        {
            return Err(ErasureErrorV1::Unauthorized);
        }
        let obligation = record
            .obligations
            .iter()
            .find(|value| value.reference() == acknowledgement.obligation)
            .ok_or(ErasureErrorV1::Unauthorized)?;
        if (obligation.target(), obligation.owner())
            != (acknowledgement.target, acknowledgement.owner)
        {
            return Err(ErasureErrorV1::Unauthorized);
        }
        let active = record
            .active
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let admitted = active
            .admission
            .unresolved_obligations()
            .binary_search(&acknowledgement.obligation)
            .is_ok_and(|index| {
                active.admission.command_identities()[index] == obligation.command_identity()
            });
        if !admitted {
            return Err(ErasureErrorV1::Unauthorized);
        }
        let scope = record
            .scope
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?
            .reference();
        let provenance =
            ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
                request,
                command: obligation.command_identity(),
                attempt: active.admission.reference(),
                obligation: acknowledgement.obligation,
                owner: acknowledgement.owner,
                scope,
                outcome: acknowledgement.outcome,
                evidence: acknowledgement.evidence,
                policy: active.admission.policy(),
                trust: active.admission.trust(),
            })?;
        if active
            .admitted
            .values()
            .any(|existing| existing == &provenance)
        {
            return Ok(record.state);
        }
        if active
            .admitted
            .contains_key(&(provenance.obligation(), provenance.owner()))
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port.admit_acknowledgement(&provenance)?;
        let object = record.retain_acknowledgement(&provenance)?;
        self.commit_delta(
            record.clone(),
            Some(record.manifest_digest),
            vec![object],
            Vec::new(),
            ErasureCasEffectV1::AcknowledgementAdmission {
                acknowledgement: provenance.reference(),
            },
        )
    }

    fn finalize_exact_retry(
        &self,
        record: &RecoveredErasureV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        let reference = record
            .latest_receipt
            .ok_or(ErasureErrorV1::PolicyConflict)?;
        let stored = ErasureReceiptV1::from_canonical_cbor(&self.port.read_object(reference)?)?;
        if stored.receipt_digest() != reference {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let normalized = self.normalize_terminal_input(
            record,
            input,
            stored.policy(),
            stored.trust(),
            stored.provenance(),
        )?;
        let candidate = ErasureReceiptV1::new(normalized)?;
        candidate.validate_frozen_obligations(&record.obligations)?;
        (candidate == stored)
            .then_some(stored)
            .ok_or(ErasureErrorV1::PolicyConflict)
    }

    fn terminal_attempt(
        request: ErasureReferenceV1,
        record: &RecoveredErasureV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<TerminalAttemptV1, ErasureErrorV1> {
        if !matches!(
            record.state.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let admission = record
            .active
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?
            .admission
            .clone();
        if !inventories_match_frozen_obligations(&input.inventories, &record.obligations) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let acknowledgements = Self::effective_acknowledgements(record)?;
        let complete =
            acknowledgements_close_frozen_obligations(&acknowledgements, &record.obligations);
        if !complete && input.issue_position < admission.deadline_position() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let lifecycle = if complete {
            ErasureLifecycleV1::Complete
        } else {
            ErasureLifecycleV1::PartialFailure
        };
        let acknowledgement_references = record
            .effective
            .values()
            .map(ErasureAcknowledgementProvenanceV1::reference)
            .collect::<Vec<_>>();
        let outcome = ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
            request,
            attempt: admission.reference(),
            source_receipt: admission.source_receipt(),
            lifecycle,
            selected_obligations: selected_obligations_reference(
                admission.unresolved_obligations(),
            ),
            acknowledgement_inventory: acknowledgement_inventory_reference(
                &acknowledgement_references,
            ),
            terminal_position: input.issue_position,
            policy: admission.policy(),
            trust: admission.trust(),
        })?;
        let (pending_owners, failed_owners) =
            derived_outcome_owners_for_obligations(&record.obligations, &acknowledgements);
        let state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle,
            freeze_position: record.state.freeze_position(),
            pending_owners,
            failed_owners,
            acknowledged_targets: if complete {
                record.targets.clone()
            } else {
                Vec::new()
            },
            replay_claim: weakest_inventory_claim(&input.inventories),
            provenance: outcome.reference(),
        })?;
        let receipt_provenance =
            ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
                request,
                attempt: admission.reference(),
                attempt_ordinal: admission.attempt_ordinal(),
                predecessor_receipt: admission.source_receipt(),
                terminal_state: state.state_digest(),
                evidence_set: erasure_evidence_set_reference(&acknowledgement_references),
                policy: admission.policy(),
                trust: admission.trust(),
                issue_position: input.issue_position,
            })?;
        Ok(TerminalAttemptV1 {
            admission,
            acknowledgements,
            lifecycle,
            outcome,
            state,
            receipt_provenance,
        })
    }

    /// Finalize the active attempt and persist its terminal receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, receipt-admission, or CAS error.
    pub fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        mut input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if record.active.is_none() {
            return self.finalize_exact_retry(&record, input);
        }
        let terminal = Self::terminal_attempt(request, &record, &input)?;
        record.replace_state(terminal.state);
        input.request = request;
        input.coordinator = self.coordinator;
        input.terminal_state = record.state.state_digest();
        input.lifecycle = terminal.lifecycle;
        input.freeze_position = record
            .state
            .freeze_position()
            .ok_or(ErasureErrorV1::PolicyConflict)?;
        input.frozen_targets.clone_from(&record.targets);
        input.acknowledgements = terminal.acknowledgements;
        input.pending_owners = record.state.pending_owners().to_vec();
        input.failed_owners = record.state.failed_owners().to_vec();
        sort_inventories(&mut input.inventories);
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        input.policy = terminal.admission.policy();
        input.trust = terminal.admission.trust();
        input.provenance = terminal.receipt_provenance.reference();
        input.receipt_digest = reference_zero();
        self.port.admit_receipt(&input)?;
        let receipt = ErasureReceiptV1::new(input)?;
        receipt.validate_frozen_obligations(&record.obligations)?;
        let (objects, index) =
            record.finish_attempt(&terminal.outcome, &terminal.receipt_provenance, &receipt)?;
        let prepared = record.prepare(
            Some(record.manifest_digest),
            objects,
            vec![record.state_object()?],
            vec![index],
            ErasureCasEffectV1::ReceiptAdmission {
                receipt: receipt.receipt_digest(),
            },
        )?;
        let next_digest = prepared.next_manifest().digest();
        self.port.compare_and_swap(prepared)?;
        record.manifest_digest = next_digest;
        self.cache(record);
        Ok(receipt)
    }
    /// Append one authorized future-Fork scope extension.
    ///
    /// # Errors
    ///
    /// Returns a closed scope, authorization, or CAS error.
    pub fn append_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        extension: ErasureScopeExtensionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if record
            .scope_head
            .is_some_and(|head| head.extension == extension.reference())
        {
            return Ok(record.state);
        }
        let scope = record
            .scope
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let lineage_rule = scope.lineage_rule().ok_or(ErasureErrorV1::PolicyConflict)?;
        if (
            extension.request(),
            extension.scope_commitment(),
            extension.lineage_rule(),
            extension.predecessor_extension(),
        ) != (
            request,
            scope.reference(),
            lineage_rule,
            record.scope_head.map(|head| head.extension),
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port.admit_scope_extension(&extension)?;
        let (extension_object, node_object, index) = record.append_scope_extension(extension)?;
        self.commit_delta(
            record.clone(),
            Some(record.manifest_digest),
            vec![extension_object, node_object],
            vec![index],
            ErasureCasEffectV1::None,
        )
    }
    /// Append one authorized administrative recovery resolution.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, provenance, or CAS error.
    pub fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
        if record.administrative_resolution_head == Some(resolution.reference()) {
            return Ok(record.state);
        }
        let scope = record
            .scope
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let obligations = record
            .obligation_set
            .as_ref()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if (
            resolution.request(),
            resolution.scope_commitment(),
            resolution.policy(),
            resolution.trust(),
            resolution.predecessor_resolution(),
        ) != (
            request,
            scope.reference(),
            record.request.policy(),
            obligations.trust(),
            record.administrative_resolution_head,
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port.admit_administrative_resolution(resolution)?;
        let (object, index) = record.append_administrative_resolution(resolution)?;
        self.commit_delta(
            record.clone(),
            Some(record.manifest_digest),
            vec![object],
            vec![index],
            ErasureCasEffectV1::None,
        )
    }
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinator for ErasureCoordinatorStateMachineV1<P> {
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::submit(self, request.clone(), request.provenance())
    }
    fn submit_corrected(
        &mut self,
        request: ErasureRequestV1,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::submit_corrected(self, request, correction)
    }
    fn authorize(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::authorize(self, request, provenance)
    }
    fn reject(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::reject(self, request, provenance)
    }
    fn freeze_access(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::freeze_inventory(self, request, &transition)
    }
    fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        admission: ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::dispatch_destruction(self, request, &admission)
    }
    fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::acknowledge(self, request, acknowledgement)
    }
    fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        Self::finalize(self, request, input)
    }
    fn append_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        extension: ErasureScopeExtensionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::append_scope_extension(self, request, extension)
    }
    fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::resolve_administratively(self, request, &resolution)
    }
}
