//! Public coordinator operations over bounded recovered state.

use super::RecoveredErasureV1;
use super::{
    acknowledgement_inventory_reference, acknowledgements_close_frozen_obligations,
    derived_outcome_owners_for_obligations, erasure_evidence_set_reference,
    inventories_match_frozen_obligations, reference_zero, selected_obligations_reference,
    sort_inventories, BTreeMap, BTreeSet, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureAuthorizationDecisionV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCasEffectV1,
    ErasureCoordinator, ErasureCoordinatorPortV1, ErasureCoordinatorStateMachineV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureIndexInsertV1, ErasureLifecycleV1, ErasurePersistedStateV1, ErasurePersistenceObjectV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureRecoveryErrorQueryV1,
    ErasureRecoveryErrorV1, ErasureReferenceV1, ErasureRequestV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionV1, ErasureStateTransitionV1, ErasureStateV1, ErasureVerifiedStateQueryV1,
    PreparedErasureCasV1, PreparedErasureRecoveryErrorV1, StoredErasureManifestV1,
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
            obligations.get(reference).copied().map_or_else(
                || Err(ErasureErrorV1::ScopeInvalid),
                |obligation| {
                    if obligation.command_identity() != *command {
                        return Err(ErasureErrorV1::ScopeInvalid);
                    }
                    Ok(ErasureDestructionCommandV1::from_obligation(
                        obligation,
                        admission.reference(),
                    ))
                },
            )
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
            record
                .obligations
                .iter()
                .find(|obligation| obligation.reference() == value.obligation())
                .map(super::ErasureObligationV1::target)
                .map_or_else(
                    || Err(ErasureErrorV1::ProvenanceMissing),
                    |target| {
                        Ok(ErasureAcknowledgementV1 {
                            target,
                            obligation: value.obligation(),
                            owner: value.owner(),
                            evidence: value.evidence(),
                            outcome: value.outcome(),
                        })
                    },
                )
        })
        .collect()
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

    fn retain_recovery_error(
        &mut self,
        recovery_error: ErasureRecoveryErrorV1,
    ) -> Result<(), ErasureErrorV1> {
        PreparedErasureRecoveryErrorV1::new(recovery_error)
            .and_then(|prepared| self.port.append_recovery_error(prepared))
    }

    fn recovery_failure_error(
        &mut self,
        recovery_error: Result<ErasureRecoveryErrorV1, ErasureErrorV1>,
    ) -> ErasureErrorV1 {
        recovery_error
            .and_then(|recovery_error| {
                let error = recovery_error.error();
                self.retain_recovery_error(recovery_error).map(|()| error)
            })
            .unwrap_or_else(std::convert::identity)
    }

    fn recover_stored(
        &mut self,
        request: ErasureReferenceV1,
        stored: &StoredErasureManifestV1,
    ) -> Result<RecoveredErasureV1, ErasureErrorV1> {
        RecoveredErasureV1::recover(&self.port, &self.port, &self.port, request, stored).map_err(
            |failure| {
                self.recovery_failure_error(ErasureRecoveryErrorV1::new(
                    request,
                    Some(stored.digest()),
                    failure.subject(),
                    failure.error(),
                ))
            },
        )
    }

    fn recover(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<Option<RecoveredErasureV1>, ErasureErrorV1> {
        let stored = self.port.read_manifest(request).map_err(|error| {
            self.recovery_failure_error(ErasureRecoveryErrorV1::new(request, None, request, error))
        })?;
        stored
            .as_ref()
            .map(|stored| self.recover_stored(request, stored))
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
        include_request
            .then(|| next.request_object())
            .transpose()
            .map(|object| object.into_iter().collect())
    }

    fn commit_delta(
        &mut self,
        mut next: RecoveredErasureV1,
        expected: Option<ErasureReferenceV1>,
        objects: Vec<ErasurePersistenceObjectV1>,
        indexes: Vec<ErasureIndexInsertV1>,
        effect: ErasureCasEffectV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        next.state_object()
            .map(|state| vec![state])
            .and_then(|states| next.prepare(expected, objects, states, indexes, effect))
            .and_then(|prepared: PreparedErasureCasV1| {
                let next_digest = prepared.next_manifest().digest();
                self.port
                    .compare_and_swap(prepared)
                    .map(|_| next_digest)
                    .inspect_err(|error| {
                        if *error == ErasureErrorV1::PolicyConflict {
                            self.records.retain(|record| {
                                record.request.reference() != next.request.reference()
                            });
                        }
                    })
            })
            .map(|next_digest| {
                next.manifest_digest = next_digest;
                let state = next.state.clone();
                self.cache(next);
                state
            })
    }

    /// Query a warm recovered state without consulting an adapter.
    #[must_use]
    pub fn existing(&self, request: ErasureReferenceV1) -> Option<&ErasureStateV1> {
        self.records
            .iter()
            .find(|record| record.request.reference() == request)
            .map(RecoveredErasureV1::state)
    }

    /// Recover one request from durable storage and expose its verified scope
    /// and fence state to containment consumers such as #186.
    ///
    /// Unlike [`Self::existing`], this method always consults the adapter and
    /// revalidates the complete ERCRP1 graph. A missing request returns
    /// `Ok(None)`; malformed or unauthoritative persisted evidence fails
    /// closed.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence, provenance, authorization, or validation
    /// error when the durable graph cannot be verified.
    pub fn verified_state(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<Option<super::ErasureVerifiedStateV1>, ErasureErrorV1> {
        let Some(record) = self.recover(request)? else {
            return Ok(None);
        };
        let verified = record.verified_state();
        self.cache(record);
        Ok(Some(verified))
    }

    /// Return the durable recovery failures retained for one request.
    ///
    /// Recovery failures are intentionally queryable even while the primary
    /// ERCRP1 graph remains unrecoverable. These are bounded, payload-free
    /// diagnostics only: they never authorize containment or prove that the
    /// graph is invalid. Containment and administrative consumers must use a
    /// successfully verified state and fail closed when recovery fails.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence, decoding, or provenance error when an
    /// indexed recovery-error object cannot be verified.
    pub fn recovery_errors(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRecoveryErrorV1>, ErasureErrorV1> {
        let references = self.port.recovery_error_refs(request)?;
        if references.len() > super::ERASURE_MAX_RECOVERY_ERRORS {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        references
            .into_iter()
            .map(|reference| {
                let bytes = self.port.read_object(reference)?;
                let record = ErasureRecoveryErrorV1::from_canonical_cbor(&bytes)?;
                (record.request() == request && record.reference() == reference)
                    .then_some(record)
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
            .collect()
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
        ErasureStateV1::submitted(request.reference(), self.coordinator, request.provenance())
            .and_then(|state| {
                let mut record = RecoveredErasureV1::initial(request, state);
                record
                    .request_object()
                    .and_then(|request_object| {
                        record
                            .set_correction(correction)
                            .map(|correction_object| vec![request_object, correction_object])
                    })
                    .and_then(|objects| {
                        self.commit_delta(
                            record,
                            None,
                            objects,
                            Vec::new(),
                            ErasureCasEffectV1::None,
                        )
                    })
            })
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
        record
            .state
            .transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::Authorized,
                freeze_position: None,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim: record.state.replay_claim(),
                provenance,
            })
            .map(|state| {
                record.replace_state(state);
                record.set_authorize_provenance(provenance);
            })
            .and_then(|()| self.commit(record.clone(), Some(record.manifest_digest), false))
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
        ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
            request,
            authorization_provenance: provenance,
        })
        .and_then(|rejection| {
            record
                .state
                .transition(ErasureStateTransitionV1 {
                    lifecycle: ErasureLifecycleV1::Rejected,
                    freeze_position: None,
                    pending_owners: Vec::new(),
                    failed_owners: Vec::new(),
                    acknowledged_targets: Vec::new(),
                    replay_claim: record.state.replay_claim(),
                    provenance: rejection.reference(),
                })
                .map(|state| {
                    record.replace_state(state);
                })
                .and_then(|()| {
                    record
                        .set_authorization_rejection(rejection)
                        .map(|object| (object, record.clone()))
                })
                .and_then(|(object, record)| {
                    let expected = record.manifest_digest;
                    self.commit_delta(
                        record,
                        Some(expected),
                        vec![object],
                        Vec::new(),
                        ErasureCasEffectV1::None,
                    )
                })
        })
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
        self.record(request)
            .and_then(|record| self.freeze_record(record, request, transition))
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
        ErasureScopeCommitmentV1::new(admission.scope().clone())
            .and_then(|scope| {
                ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
                    request,
                    scope_commitment: scope.reference(),
                    obligation_set: admission.obligation_set().reference(),
                    freeze_position: admission.freeze_position(),
                    host_evidence: admission.freeze_admission_evidence().reference(),
                })
                .map(|freeze| (scope, freeze))
            })
            .and_then(|(scope, freeze)| {
                record
                    .state
                    .transition(ErasureStateTransitionV1 {
                        lifecycle: ErasureLifecycleV1::AccessFrozen,
                        freeze_position: Some(admission.freeze_position()),
                        pending_owners: Vec::new(),
                        failed_owners: Vec::new(),
                        acknowledged_targets: Vec::new(),
                        replay_claim: record.state.replay_claim(),
                        provenance: freeze.reference(),
                    })
                    .map(|state| (scope, freeze, state))
            })
            .and_then(|(scope, freeze, state)| {
                record.replace_state(state);
                record
                    .retain_atomic_freeze(admission, &scope, freeze)
                    .map(|objects| (objects, record.clone()))
            })
            .and_then(|(objects, record)| {
                let expected = record.manifest_digest;
                self.commit_delta(
                    record,
                    Some(expected),
                    objects,
                    Vec::new(),
                    ErasureCasEffectV1::None,
                )
            })
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
        record
            .state
            .transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::Rejected,
                freeze_position: None,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim: record.state.replay_claim(),
                provenance: failure.reference(),
            })
            .map(|state| record.replace_state(state))
            .and_then(|()| {
                record
                    .set_freeze_failure(failure)
                    .map(|object| (object, record.clone()))
            })
            .and_then(|(object, record)| {
                let expected = record.manifest_digest;
                self.commit_delta(
                    record,
                    Some(expected),
                    vec![object],
                    Vec::new(),
                    ErasureCasEffectV1::None,
                )
            })
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
        record.state.freeze_position().map_or_else(
            || Err(ErasureErrorV1::PolicyConflict),
            |freeze_position| {
                input.freeze_position = freeze_position;
                input.frozen_targets.clone_from(&record.targets);
                effective_acknowledgements(record).map(|acknowledgements| {
                    input.acknowledgements = acknowledgements;
                    input.pending_owners = record.state.pending_owners().to_vec();
                    input.failed_owners = record.state.failed_owners().to_vec();
                    sort_inventories(&mut input.inventories);
                    input.policy = policy;
                    input.trust = trust;
                    input.provenance = provenance;
                    input.receipt_digest = reference_zero();
                    input
                })
            },
        )
    }

    /// Admit and atomically persist one destruction attempt.
    ///
    /// The durable outbox is committed before host delivery. If delivery is
    /// rejected, the committed active attempt remains available for an exact
    /// retry.
    ///
    /// # Errors
    ///
    /// Returns a closed admission, persistence, or host-delivery error.
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
            return commands_for_admission(&record, admission).and_then(|commands| {
                self.port
                    .dispatch_destruction(request, &commands)
                    .map(|()| record.state)
            });
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
        commands_for_admission(&record, admission)
            .and_then(|commands| {
                self.port.admit_attempt(admission).and_then(|reservation| {
                    if reservation.admission() != admission.reference() {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    record.begin_attempt(admission.clone()).and_then(|object| {
                        Self::attempt_states(&mut record, admission).and_then(|states| {
                            record
                                .prepare(
                                    Some(record.manifest_digest),
                                    vec![object],
                                    states,
                                    Vec::new(),
                                    ErasureCasEffectV1::AttemptAdmission {
                                        reservation,
                                        commands: commands.clone(),
                                    },
                                )
                                .map(|prepared| (prepared, commands))
                        })
                    })
                })
            })
            .and_then(|(prepared, commands)| {
                let next_digest = prepared.next_manifest().digest();
                self.port
                    .compare_and_swap(prepared)
                    .map(|_| (next_digest, commands))
            })
            .map(|(next_digest, commands)| {
                record.manifest_digest = next_digest;
                let state = record.state.clone();
                self.cache(record);
                (state, commands)
            })
            .and_then(|(state, commands)| {
                self.port
                    .dispatch_destruction(request, &commands)
                    .map(|()| state)
            })
    }

    fn attempt_states(
        record: &mut RecoveredErasureV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<Vec<ErasurePersistedStateV1>, ErasureErrorV1> {
        if admission.attempt_ordinal() != 0 {
            return record.state_object().map(|state| vec![state]);
        }
        let freeze_position = record.state.freeze_position();
        let replay_claim = record.state.replay_claim();
        record
            .state
            .transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::DestructionDispatched,
                freeze_position,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim,
                provenance: admission.reference(),
            })
            .and_then(|dispatched| {
                Self::persisted_state(dispatched.clone()).and_then(|persisted| {
                    dispatched
                        .transition(ErasureStateTransitionV1 {
                            lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
                            freeze_position,
                            pending_owners: Vec::new(),
                            failed_owners: Vec::new(),
                            acknowledged_targets: Vec::new(),
                            replay_claim,
                            provenance: admission.reference(),
                        })
                        .map(|awaiting| {
                            record.replace_state(awaiting);
                            persisted
                        })
                })
            })
            .and_then(|persisted| record.state_object().map(|state| vec![persisted, state]))
    }
    /// Dispatch destruction through the stable coordinator operation.
    ///
    /// # Errors
    ///
    /// Returns a closed admission, persistence, or host-delivery error.
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
        let obligation = *record
            .obligations
            .iter()
            .find(|value| value.reference() == acknowledgement.obligation)
            .ok_or(ErasureErrorV1::Unauthorized)?;
        if (obligation.target(), obligation.owner())
            != (acknowledgement.target, acknowledgement.owner)
        {
            return Err(ErasureErrorV1::Unauthorized);
        }
        let Some((active, scope)) = record.active.clone().zip(record.scope.clone()) else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        if !active
            .admission
            .unresolved_obligations()
            .binary_search(&acknowledgement.obligation)
            .is_ok_and(|index| {
                active.admission.command_identities()[index] == obligation.command_identity()
            })
        {
            return Err(ErasureErrorV1::Unauthorized);
        }
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request,
            command: obligation.command_identity(),
            attempt: active.admission.reference(),
            obligation: acknowledgement.obligation,
            owner: acknowledgement.owner,
            scope: scope.reference(),
            outcome: acknowledgement.outcome,
            evidence: acknowledgement.evidence,
            policy: active.admission.policy(),
            trust: active.admission.trust(),
        })
        .and_then(|provenance| {
            if active
                .admitted
                .values()
                .any(|existing| existing == &provenance)
            {
                return Ok(record.state.clone());
            }
            if active
                .admitted
                .contains_key(&(provenance.obligation(), provenance.owner()))
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            self.port
                .admit_acknowledgement(&provenance)
                .and_then(|()| record.retain_acknowledgement(&provenance))
                .and_then(|object| {
                    let expected = record.manifest_digest;
                    self.commit_delta(
                        record.clone(),
                        Some(expected),
                        vec![object],
                        Vec::new(),
                        ErasureCasEffectV1::AcknowledgementAdmission {
                            acknowledgement: provenance.reference(),
                        },
                    )
                })
        })
    }

    fn finalize_exact_retry(
        &self,
        record: &RecoveredErasureV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        record.latest_receipt.map_or_else(
            || Err(ErasureErrorV1::PolicyConflict),
            |reference| {
                self.port
                    .read_object(reference)
                    .and_then(|bytes| ErasureReceiptV1::from_canonical_cbor(&bytes))
                    .and_then(|stored| {
                        if stored.receipt_digest() != reference {
                            return Err(ErasureErrorV1::ProvenanceMissing);
                        }
                        self.normalize_terminal_input(
                            record,
                            input,
                            stored.policy(),
                            stored.trust(),
                            stored.provenance(),
                        )
                        .and_then(ErasureReceiptV1::new)
                        .and_then(|candidate| {
                            candidate
                                .validate_frozen_obligations(&record.obligations)
                                .map(|()| (candidate, stored))
                        })
                    })
                    .and_then(|(candidate, stored)| {
                        (candidate == stored)
                            .then_some(stored)
                            .ok_or(ErasureErrorV1::PolicyConflict)
                    })
            },
        )
    }
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
    record.active.as_ref().map_or_else(
        || Err(ErasureErrorV1::ProvenanceMissing),
        |active| {
            let admission = active.admission.clone();
            if !inventories_match_frozen_obligations(&input.inventories, &record.obligations) {
                return Err(ErasureErrorV1::ScopeInvalid);
            }
            effective_acknowledgements(record).and_then(|acknowledgements| {
                let complete = acknowledgements_close_frozen_obligations(
                    &acknowledgements,
                    &record.obligations,
                );
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
                ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
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
                })
                .and_then(|outcome| {
                    let (pending_owners, failed_owners) = derived_outcome_owners_for_obligations(
                        &record.obligations,
                        &acknowledgements,
                    );
                    record
                        .state
                        .transition(ErasureStateTransitionV1 {
                            lifecycle,
                            freeze_position: record.state.freeze_position(),
                            pending_owners,
                            failed_owners,
                            acknowledged_targets: if complete {
                                record.targets.clone()
                            } else {
                                Vec::new()
                            },
                            replay_claim: input.replay_claim,
                            provenance: outcome.reference(),
                        })
                        .and_then(|state| {
                            ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
                                request,
                                attempt: admission.reference(),
                                attempt_ordinal: admission.attempt_ordinal(),
                                predecessor_receipt: admission.source_receipt(),
                                terminal_state: state.state_digest(),
                                evidence_set: erasure_evidence_set_reference(
                                    &acknowledgement_references,
                                ),
                                policy: admission.policy(),
                                trust: admission.trust(),
                                issue_position: input.issue_position,
                            })
                            .map(|receipt_provenance| {
                                TerminalAttemptV1 {
                                    admission,
                                    acknowledgements,
                                    lifecycle,
                                    outcome,
                                    state,
                                    receipt_provenance,
                                }
                            })
                        })
                })
            })
        },
    )
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinatorStateMachineV1<P> {
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
        let terminal = terminal_attempt(request, &record, &input)?;
        let TerminalAttemptV1 {
            admission,
            acknowledgements,
            lifecycle,
            outcome,
            state,
            receipt_provenance,
        } = terminal;
        record.replace_state(state);
        input.request = request;
        input.coordinator = self.coordinator;
        input.terminal_state = record.state.state_digest();
        input.lifecycle = lifecycle;
        record.state.freeze_position().map_or_else(
            || Err(ErasureErrorV1::PolicyConflict),
            |freeze_position| {
                input.freeze_position = freeze_position;
                input.frozen_targets.clone_from(&record.targets);
                input.acknowledgements = acknowledgements;
                input.pending_owners = record.state.pending_owners().to_vec();
                input.failed_owners = record.state.failed_owners().to_vec();
                sort_inventories(&mut input.inventories);
                input.policy = admission.policy();
                input.trust = admission.trust();
                input.provenance = receipt_provenance.reference();
                input.receipt_digest = reference_zero();
                self.port
                    .admit_receipt(&input)
                    .and_then(|()| {
                        ErasureReceiptV1::new(input).and_then(|receipt| {
                            receipt
                                .validate_frozen_obligations(&record.obligations)
                                .map(|()| receipt)
                        })
                    })
                    .and_then(|receipt| {
                        record
                            .finish_attempt(&outcome, &receipt_provenance, &receipt)
                            .map(|(objects, index)| (receipt, objects, index))
                    })
                    .and_then(|(receipt, objects, index)| {
                        record
                            .state_object()
                            .map(|state| (receipt, objects, index, state))
                    })
                    .and_then(|(receipt, objects, index, state)| {
                        record
                            .prepare(
                                Some(record.manifest_digest),
                                objects,
                                vec![state],
                                vec![index],
                                ErasureCasEffectV1::ReceiptAdmission {
                                    receipt: receipt.receipt_digest(),
                                },
                            )
                            .map(|prepared| (receipt, prepared))
                    })
                    .and_then(|(receipt, prepared)| {
                        let next_digest = prepared.next_manifest().digest();
                        self.port
                            .compare_and_swap(prepared)
                            .map(|_| (receipt, next_digest))
                    })
                    .map(|(receipt, next_digest)| {
                        record.manifest_digest = next_digest;
                        self.cache(record);
                        receipt
                    })
            },
        )
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
        record
            .append_scope_extension(extension)
            .and_then(|(extension_object, node_object, index)| {
                self.port
                    .admit_scope_extension(&extension)
                    .map(|()| (extension_object, node_object, index))
            })
            .and_then(|(extension_object, node_object, index)| {
                record.scope_extensions.push(extension);
                self.commit_delta(
                    record.clone(),
                    Some(record.manifest_digest),
                    vec![extension_object, node_object],
                    vec![index],
                    ErasureCasEffectV1::None,
                )
            })
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
            .map(super::ErasureScopeCommitmentV1::reference)
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let Some(obligations) = record.obligation_set.clone() else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let policy = record.request.policy();
        let predecessor = record.administrative_resolution_head;
        let expected = record.manifest_digest;
        {
            if (
                resolution.request(),
                resolution.scope_commitment(),
                resolution.policy(),
                resolution.trust(),
                resolution.predecessor_resolution(),
            ) != (request, scope, policy, obligations.trust(), predecessor)
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            record
                .append_administrative_resolution(resolution)
                .and_then(|(object, index)| {
                    self.port
                        .admit_administrative_resolution(resolution)
                        .map(|()| (object, index))
                })
                .and_then(|(object, index)| {
                    self.commit_delta(
                        record.clone(),
                        Some(expected),
                        vec![object],
                        vec![index],
                        ErasureCasEffectV1::None,
                    )
                })
        }
    }
}

impl<P: ErasureCoordinatorPortV1> ErasureVerifiedStateQueryV1
    for ErasureCoordinatorStateMachineV1<P>
{
    fn verified_state(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<Option<super::ErasureVerifiedStateV1>, ErasureErrorV1> {
        Self::verified_state(self, request)
    }
}

impl<P: ErasureCoordinatorPortV1> ErasureRecoveryErrorQueryV1
    for ErasureCoordinatorStateMachineV1<P>
{
    fn recovery_errors(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRecoveryErrorV1>, ErasureErrorV1> {
        Self::recovery_errors(self, request)
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        ErasureReceiptInventoriesV1, ErasureReplayClaimV1, ErasureRequestInputV1,
        ErasureRetryAdmissionInputV1,
    };

    const fn reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
        ErasureRequestV1::new(ErasureRequestInputV1 {
            request: reference(1),
            subject: reference(2),
            scope: crate::ErasureScopeV1::PrivateSubjectData,
            selectors: vec![reference(3)],
            requester: reference(4),
            authorization: reference(5),
            policy: reference(6),
            request_position: 7,
            horizon_position: 8,
            provenance: reference(9),
        })
    }

    fn terminal_input() -> ErasureReceiptInputV1 {
        ErasureReceiptInputV1 {
            request: reference(1),
            terminal_state: reference(2),
            coordinator: reference(3),
            lifecycle: ErasureLifecycleV1::Complete,
            freeze_position: 10,
            acknowledgements: Vec::new(),
            frozen_targets: Vec::new(),
            pending_owners: Vec::new(),
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
            issue_position: 20,
            signature: reference(7),
            receipt_digest: reference(8),
        }
    }

    #[test]
    fn recovery_helpers_reject_unbound_references() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let record = RecoveredErasureV1::initial(
            request.clone(),
            ErasureStateV1::submitted(request.reference(), reference(10), request.provenance())?,
        );
        let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            request: request.reference(),
            attempt_ordinal: 0,
            source_receipt: None,
            unresolved_obligations: vec![reference(11)],
            command_identities: vec![reference(12)],
            policy: reference(6),
            trust: reference(7),
            admitted_position: 13,
            deadline_position: 14,
            authorization_provenance: reference(15),
        })?;
        assert_eq!(
            commands_for_admission(&record, &admission),
            Err(ErasureErrorV1::ScopeInvalid)
        );

        let mut record = record;
        let acknowledgement =
            ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
                request: request.reference(),
                command: reference(16),
                attempt: reference(17),
                obligation: reference(18),
                owner: reference(19),
                scope: reference(20),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
                evidence: reference(21),
                policy: reference(6),
                trust: reference(7),
            })?;
        record
            .effective
            .insert((reference(18), reference(19)), acknowledgement);
        assert_eq!(
            effective_acknowledgements(&record),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn terminal_attempt_rejects_invalid_lifecycle_and_missing_active() -> Result<(), ErasureErrorV1>
    {
        let request = request()?;
        let submitted = RecoveredErasureV1::initial(
            request.clone(),
            ErasureStateV1::submitted(request.reference(), reference(10), request.provenance())?,
        );
        assert_eq!(
            terminal_attempt(request.reference(), &submitted, &terminal_input()).err(),
            Some(ErasureErrorV1::PolicyConflict)
        );

        let awaiting = ErasureStateV1 {
            request: request.reference(),
            lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
            freeze_position: Some(10),
            coordinator: reference(10),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            previous_state: None,
            provenance: reference(11),
            state_digest: reference(12),
        };
        let no_active = RecoveredErasureV1::initial(request.clone(), awaiting);
        assert_eq!(
            terminal_attempt(request.reference(), &no_active, &terminal_input()).err(),
            Some(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }
}
