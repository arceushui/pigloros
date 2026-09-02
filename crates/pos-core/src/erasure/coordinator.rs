//! Public coordinator operations over bounded recovered state.

use super::RecoveredErasureV1;
use super::{
    BTreeMap, BTreeSet, ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAuthorizationDecisionV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCasEffectV1,
    ErasureCoordinator, ErasureCoordinatorPortV1, ErasureCoordinatorStateMachineV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureIndexInsertV1, ErasureLifecycleV1, ErasurePersistedStateV1, ErasurePersistenceObjectV1,
    ErasureReferenceV1, ErasureRequestV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1,
    ErasureStateTransitionV1, ErasureStateV1, PreparedErasureCasV1,
};
use super::{
    ErasureAcknowledgementV1, ErasureReceiptInputV1, ErasureReceiptV1, ErasureRetryAdmissionV1,
};

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
            .map(|stored| RecoveredErasureV1::recover(&self.port, &self.port, request, stored))
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
            .map(|record| {
                self.cache(record.clone());
                record
            })
    }

    fn commit(
        &mut self,
        mut next: RecoveredErasureV1,
        expected: Option<ErasureReferenceV1>,
        include_request: bool,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut objects = Vec::new();
        if include_request {
            objects.push(next.request_object()?);
        }
        self.commit_delta(
            next,
            expected,
            objects,
            Vec::new(),
            ErasureCasEffectV1::None,
        )
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
        if self.recover(request.reference())?.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
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
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut record = self.record(request)?;
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
        match self.port.admit_atomic_freeze(request, &transition)? {
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
        admission: ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.dispatch_attempt(request, &admission)
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
        self.port.admit_acknowledgement(&provenance)?;
        let object = record.retain_acknowledgement(provenance.clone())?;
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
    /// Finalize the active attempt and persist its terminal receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, receipt-admission, or CAS error.
    pub fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        let _ = (self.record(request)?, input);
        Err(ErasureErrorV1::PolicyConflict)
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
        let _ = (self.record(request)?, extension);
        Err(ErasureErrorV1::PolicyConflict)
    }
    /// Append one authorized administrative recovery resolution.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, provenance, or CAS error.
    pub fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let _ = (self.record(request)?, resolution);
        Err(ErasureErrorV1::PolicyConflict)
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
        Self::freeze_inventory(self, request, transition)
    }
    fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        admission: ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::dispatch_destruction(self, request, admission)
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
        Self::resolve_administratively(self, request, resolution)
    }
}
