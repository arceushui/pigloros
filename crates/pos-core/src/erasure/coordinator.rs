use super::{
    acknowledgement_inventory_reference, acknowledgements_close_frozen_obligations,
    derived_outcome_owners_for_obligations, erasure_evidence_set_reference,
    inventories_match_frozen_obligations, reference_zero, selected_obligations_reference,
    sort_inventories, verify_predecessor_chain, weakest_inventory_claim, BTreeMap, BTreeSet,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionV1, ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1,
    ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1, ErasureAuthorizationDecisionV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCoordinator,
    ErasureCoordinatorPortV1, ErasureCoordinatorRecordV1, ErasureCoordinatorStateMachineV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1, ErasureFreezeProvenanceV1,
    ErasureLifecycleV1, ErasureObligationV1, ErasureReceiptInputV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureRequestV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionLedgerInputV1, ErasureScopeExtensionLedgerV1,
    ErasureScopeExtensionV1, ErasureStateTransitionV1, ErasureStateV1, ErasureSupportingRecordsV1,
    VerifiedErasureCoordinatorRecordV1,
};

impl<P: ErasureCoordinatorPortV1> ErasureCoordinatorStateMachineV1<P> {
    /// Construct a host-owned state machine.
    #[must_use]
    pub const fn new(port: P, coordinator: ErasureReferenceV1) -> Self {
        Self {
            port,
            coordinator,
            records: Vec::new(),
        }
    }
    fn cache(&mut self, record: ErasureCoordinatorRecordV1) {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|existing| existing.request.reference() == record.request.reference())
        {
            *existing = record;
        } else {
            self.records.push(record);
        }
    }
    pub(super) fn record(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
        match self.port.load_record(request, &self.port) {
            Ok(Some(record)) => self.validate_recovered_record(&record).map(|()| {
                self.cache(record.clone());
                record
            }),
            Ok(None) => Err(ErasureErrorV1::ProvenanceMissing),
            Err(error) => Err(error),
        }
    }

    fn validate_recovered_record(
        &self,
        record: &ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        record
            .validate(self.coordinator)
            .and_then(|()| verify_predecessor_chain(record.state.clone(), &self.port))
    }
    fn commit(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        record.validate(self.coordinator).and_then(|()| {
            VerifiedErasureCoordinatorRecordV1::new(record.clone(), &self.port)
                .and_then(|verified| self.port.commit_record(verified))
                .map(|()| self.cache(record))
        })
    }
    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        records
            .iter()
            .try_for_each(|record| record.validate(self.coordinator))
            .and_then(|()| {
                records
                    .iter()
                    .cloned()
                    .map(|record| VerifiedErasureCoordinatorRecordV1::new(record, &self.port))
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|verified| self.port.commit_records(&verified))
            .map(|()| {
                records
                    .iter()
                    .cloned()
                    .for_each(|record| self.cache(record));
            })
    }
    /// Query an existing outcome without creating or advancing it.
    #[must_use]
    pub fn existing(&self, request: ErasureReferenceV1) -> Option<&ErasureStateV1> {
        self.records
            .iter()
            .find(|record| record.request.reference() == request)
            .map(|record| &record.state)
    }
    /// Authenticate and idempotently submit ERQ1.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication or conflicting-identity error.
    pub fn submit(
        &mut self,
        request: ErasureRequestV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        match self.port.load_record(request.reference(), &self.port) {
            Ok(Some(record)) => self.validate_recovered_record(&record).and_then(|()| {
                if record.request.eq(&request) {
                    let state = record.state.clone();
                    self.cache(record);
                    Ok(state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                }
            }),
            Ok(None) => self.port.authenticate(&request).and_then(|()| {
                ErasureStateV1::submitted(request.reference(), self.coordinator, provenance)
                    .and_then(|state| {
                        let record = ErasureCoordinatorRecordV1 {
                            request,
                            state: state.clone(),
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
                        };
                        self.commit(record).map(|()| state)
                    })
            }),
            Err(error) => Err(error),
        }
    }

    /// Submit a replacement request after host-authenticating its rejected
    /// predecessor and correction provenance.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication, predecessor, or durable-record error.
    pub fn submit_corrected(
        &mut self,
        request: ErasureRequestV1,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if request.provenance() != correction.reference() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        match self.port.load_record(request.reference(), &self.port) {
            Ok(Some(record)) => self
                .validate_recovered_record(&record)
                .and_then(|()| {
                    if record.request != request
                        || record.supporting_records.correction_provenance() != Some(&correction)
                    {
                        Err(ErasureErrorV1::PolicyConflict)
                    } else {
                        Ok(())
                    }
                })
                .map(|()| {
                    let state = record.state.clone();
                    self.cache(record);
                    state
                }),
            Ok(None) => self
                .port
                .load_record(correction.rejected_request(), &self.port)
                .and_then(|predecessor| predecessor.ok_or(ErasureErrorV1::ProvenanceMissing))
                .and_then(|predecessor| {
                    predecessor
                        .validate(self.coordinator)
                        .and_then(|()| {
                            verify_predecessor_chain(predecessor.state.clone(), &self.port)
                        })
                        .and_then(|()| self.port.authenticate(&request))
                        .and_then(|()| self.port.admit_corrected_submission(&request, &correction))
                        .and_then(|()| {
                            ErasureStateV1::submitted(
                                request.reference(),
                                self.coordinator,
                                request.provenance(),
                            )
                        })
                        .and_then(|state| {
                            let record = ErasureCoordinatorRecordV1 {
                                request,
                                state: state.clone(),
                                targets: Vec::new(),
                                acknowledgements: Vec::new(),
                                receipt: None,
                                receipt_input: None,
                                authorize_provenance: None,
                                freeze_provenance: None,
                                dispatch_provenance: None,
                                scope_extension_ledger: None,
                                administrative_resolution_head: None,
                                supporting_records: ErasureSupportingRecordsV1 {
                                    correction_provenance: Some(correction),
                                    ..ErasureSupportingRecordsV1::default()
                                },
                            };
                            record
                                .validate_correction_predecessor(&predecessor)
                                .and_then(|()| self.commit(record))
                                .map(|()| state)
                        })
                }),
            Err(error) => Err(error),
        }
    }

    /// Authorize a submitted ERQ1; an exact lifecycle retry is a query.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown request, an injected freeze, or a
    /// non-monotonic state transition.
    pub fn authorize(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() != ErasureLifecycleV1::Submitted {
                return if record.authorize_provenance == Some(provenance)
                    && (record.state.lifecycle() == ErasureLifecycleV1::Authorized
                        || record.state.lifecycle().is_attempt_terminal()
                        || record.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
                        || record.state.lifecycle() == ErasureLifecycleV1::DestructionDispatched
                        || record.state.lifecycle() == ErasureLifecycleV1::AwaitingAcknowledgements)
                {
                    Ok(record.state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            let replay_claim = record.state.replay_claim();
            self.port
                .admit_authorization(
                    request,
                    provenance,
                    ErasureAuthorizationDecisionV1::Authorized,
                )
                .and_then(|()| {
                    record.state.transition(ErasureStateTransitionV1 {
                        lifecycle: ErasureLifecycleV1::Authorized,
                        freeze_position: None,
                        pending_owners: Vec::new(),
                        failed_owners: Vec::new(),
                        acknowledged_targets: Vec::new(),
                        replay_claim,
                        provenance,
                    })
                })
                .and_then(|state| {
                    record.state = state;
                    record.authorize_provenance = Some(provenance);
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }
    /// Reject a submitted ERQ1 after host policy admission; an exact retry is
    /// a query of the already committed terminal state.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown request, failed host admission,
    /// or a non-monotonic state transition.
    pub fn reject(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() != ErasureLifecycleV1::Submitted {
                return record
                    .supporting_records
                    .authorization_rejection()
                    .filter(|rejection| rejection.authorization_provenance() == provenance)
                    .map_or(Err(ErasureErrorV1::PolicyConflict), |_| Ok(record.state));
            }
            let replay_claim = record.state.replay_claim();
            self.port
                .admit_authorization(
                    request,
                    provenance,
                    ErasureAuthorizationDecisionV1::Rejected,
                )
                .and_then(|()| {
                    ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
                        request,
                        authorization_provenance: provenance,
                    })
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
                            replay_claim,
                            provenance: rejection.reference(),
                        })
                        .map(|state| (rejection, state))
                })
                .and_then(|(rejection, state)| {
                    record.retain_authorization_rejection(state, rejection);
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }
    /// Persist the one host-produced atomic access-freeze decision.
    ///
    /// Exact retries return the durable state, including a canonical rejected
    /// state when the host rejected scope or freeze work.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, host, or durable-record error.
    pub fn freeze_inventory(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let ErasureStateTransitionV1 {
            lifecycle,
            freeze_position,
            pending_owners,
            failed_owners,
            acknowledged_targets,
            replay_claim,
            provenance,
        } = transition;
        let transition = ErasureStateTransitionV1 {
            lifecycle,
            freeze_position,
            pending_owners,
            failed_owners,
            acknowledged_targets,
            replay_claim,
            provenance,
        };
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() == ErasureLifecycleV1::Rejected
                && record.supporting_records.freeze_failure().is_some()
            {
                return Ok(record.state);
            }
            if record.freeze_provenance.is_some() {
                return (transition.lifecycle == ErasureLifecycleV1::AccessFrozen)
                    .then_some(record.state)
                    .ok_or(ErasureErrorV1::PolicyConflict);
            }
            if !matches!(
                (record.state.lifecycle(), transition.lifecycle),
                (
                    ErasureLifecycleV1::Authorized,
                    ErasureLifecycleV1::AccessFrozen
                )
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            self.port
                .admit_atomic_freeze(request, &transition)
                .and_then(|result| match result {
                    ErasureAtomicFreezeResultV1::Rejected(failure) => {
                        self.persist_freeze_rejection(&mut record, failure)
                    }
                    ErasureAtomicFreezeResultV1::Admitted(admission) => {
                        self.persist_atomic_freeze(&mut record, &admission)
                    }
                })
        })
    }

    pub(super) fn persist_atomic_freeze(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        admission: &ErasureAtomicFreezeAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let request = record.request.reference();
        if admission.scope().request != request
            || admission.obligation_set().request() != request
            || admission.obligation_set().policy() != record.request.policy()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port
            .validate_freeze_authorization(
                admission.freeze_admission_evidence(),
                admission.freeze_authorization_evidence(),
            )
            .and_then(|()| ErasureScopeCommitmentV1::new(admission.scope().clone()))
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
                scope
                    .lineage_rule()
                    .map(|_| {
                        ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
                            scope_commitment: scope.reference(),
                            extensions: Vec::new(),
                            head: None,
                        })
                    })
                    .transpose()
                    .map(|ledger| (scope, freeze, ledger))
            })
            .and_then(|(scope, freeze, ledger)| {
                let replay_claim = record.state.replay_claim();
                record
                    .state
                    .transition(ErasureStateTransitionV1 {
                        lifecycle: ErasureLifecycleV1::AccessFrozen,
                        freeze_position: Some(admission.freeze_position()),
                        pending_owners: Vec::new(),
                        failed_owners: Vec::new(),
                        acknowledged_targets: Vec::new(),
                        replay_claim,
                        provenance: freeze.reference(),
                    })
                    .map(|state| (scope, freeze, ledger, state))
            })
            .and_then(|(scope, freeze, ledger, state)| {
                record.retain_atomic_freeze(state.clone(), admission, scope, freeze, ledger);
                self.commit(record.clone()).map(|()| state)
            })
    }

    pub(super) fn persist_freeze_rejection(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        failure: ErasureFreezeFailureV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if failure.request() != record.request.reference()
            || record.authorize_provenance != Some(failure.authorization_provenance())
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let replay_claim = record.state.replay_claim();
        record
            .state
            .transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::Rejected,
                freeze_position: None,
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                acknowledged_targets: Vec::new(),
                replay_claim,
                provenance: failure.reference(),
            })
            .and_then(|state| {
                record.retain_freeze_failure(state.clone(), failure);
                self.commit(record.clone()).map(|()| state)
            })
    }
    /// Dispatch the frozen closure through the host-owned idempotent port.
    ///
    /// A caller cannot claim this lifecycle edge by supplying an ERS1
    /// transition. The dispatch intent is committed before the host call, so
    /// a restart can retry the same target closure without losing its command
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the request is unknown, the lifecycle is
    /// invalid, host dispatch is rejected, or the durable commit fails.
    pub fn dispatch_attempt(
        &mut self,
        request: ErasureReferenceV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
            ) && record.supporting_records.retry_admissions.last() == Some(admission)
            {
                return Ok(record.state);
            }
            let ordinal_index = record.supporting_records.attempt_outcomes.len();
            let source_receipt = record
                .supporting_records
                .receipts
                .last()
                .map(ErasureReceiptV1::receipt_digest);
            u64::try_from(ordinal_index)
                .map_err(|_| ErasureErrorV1::PolicyConflict)
                .and_then(|ordinal| {
                    if admission.request() != request
                        || admission.attempt_ordinal() != ordinal
                        || admission.source_receipt() != source_receipt
                        || !matches!(
                            record.state.lifecycle(),
                            ErasureLifecycleV1::AccessFrozen | ErasureLifecycleV1::PartialFailure
                        )
                    {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    let expected_obligations = Self::unresolved_obligation_references(&record);
                    if admission.unresolved_obligations() != expected_obligations.as_slice() {
                        return Err(ErasureErrorV1::ScopeInvalid);
                    }
                    Self::commands_for_admission(&record, admission).and_then(|commands| {
                        let already_admitted = record
                            .supporting_records
                            .retry_admissions
                            .get(ordinal_index)
                            == Some(admission);
                        let persist_admission = if already_admitted {
                            Ok(())
                        } else {
                            self.port.admit_attempt(admission).and_then(|()| {
                                record
                                    .supporting_records
                                    .retry_admissions
                                    .push(admission.clone());
                                record.acknowledgements = record
                                    .supporting_records
                                    .effective_acknowledgements(admission);
                                if ordinal == 0 {
                                    record.dispatch_provenance = Some(admission.reference());
                                }
                                self.commit(record.clone())
                            })
                        };
                        persist_admission
                            .and_then(|()| self.port.dispatch_destruction(request, &commands))
                            .and_then(|()| {
                                if ordinal != 0 {
                                    return Ok(record.state);
                                }
                                self.persist_initial_dispatch(&mut record, admission)
                            })
                    })
                })
        })
    }

    fn persist_initial_dispatch(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let freeze_position = record.state.freeze_position();
        let replay_claim = record.state.replay_claim();
        record.state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::DestructionDispatched,
            freeze_position,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim,
            provenance: admission.reference(),
        })?;
        let dispatched_record = record.clone();
        record.state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
            freeze_position,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim,
            provenance: admission.reference(),
        })?;
        self.commit_records(&[dispatched_record, record.clone()])
            .map(|()| record.state.clone())
    }

    fn unresolved_obligation_references(
        record: &ErasureCoordinatorRecordV1,
    ) -> Vec<ErasureReferenceV1> {
        let acknowledged = record
            .acknowledgements
            .iter()
            .filter(|acknowledgement| {
                acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
            })
            .map(|acknowledgement| acknowledgement.obligation)
            .collect::<BTreeSet<_>>();
        record
            .supporting_records
            .obligations()
            .iter()
            .filter(|obligation| !acknowledged.contains(&obligation.reference()))
            .map(ErasureObligationV1::reference)
            .collect()
    }

    fn has_acknowledgement_identity(
        record: &ErasureCoordinatorRecordV1,
        candidate: &ErasureAcknowledgementProvenanceV1,
    ) -> bool {
        record
            .supporting_records
            .acknowledgement_provenance
            .iter()
            .any(|existing| {
                (existing.command(), existing.attempt(), existing.owner())
                    == (candidate.command(), candidate.attempt(), candidate.owner())
            })
    }

    pub(super) fn commands_for_admission(
        record: &ErasureCoordinatorRecordV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<Vec<ErasureDestructionCommandV1>, ErasureErrorV1> {
        let obligations = record
            .supporting_records
            .obligations()
            .iter()
            .map(|obligation| (obligation.reference(), obligation))
            .collect::<BTreeMap<_, _>>();
        admission
            .unresolved_obligations()
            .iter()
            .zip(admission.command_identities())
            .try_fold(
                Vec::new(),
                |mut commands, (obligation_reference, command)| {
                    obligations
                        .get(obligation_reference)
                        .copied()
                        .ok_or(ErasureErrorV1::ScopeInvalid)
                        .and_then(|obligation| {
                            if obligation.command_identity() != *command {
                                return Err(ErasureErrorV1::ScopeInvalid);
                            }
                            commands.push(ErasureDestructionCommandV1::from_obligation(
                                obligation,
                                admission.reference(),
                            ));
                            Ok(commands)
                        })
                },
            )
    }

    /// Dispatch the initial attempt using request-pinned policy and host provenance.
    ///
    /// Retry callers use [`Self::dispatch_attempt`] with an explicit admission.
    ///
    /// # Errors
    ///
    /// Returns a closed scope, policy, trust, dispatch, or persistence error.
    pub fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|record| {
            if matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
            ) {
                return record
                    .supporting_records
                    .retry_admissions()
                    .last()
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
                    .and_then(|admission| {
                        if admission.authorization_provenance() == provenance {
                            Ok(record.state)
                        } else {
                            Err(ErasureErrorV1::PolicyConflict)
                        }
                    });
            }
            if record.state.lifecycle() != ErasureLifecycleV1::AccessFrozen {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            let obligations = Self::unresolved_obligation_references(&record);
            let command_identities = record
                .supporting_records
                .obligations()
                .iter()
                .map(|obligation| (obligation.reference(), obligation.command_identity()))
                .collect::<BTreeMap<_, _>>();
            obligations
                .iter()
                .map(|reference| {
                    command_identities
                        .get(reference)
                        .copied()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                })
                .collect::<Result<Vec<_>, _>>()
                .and_then(|command_identities| {
                    record
                        .supporting_records
                        .obligation_set()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|obligation_set| (command_identities, obligation_set.trust()))
                })
                .and_then(|(command_identities, trust)| {
                    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
                        request,
                        attempt_ordinal: 0,
                        source_receipt: None,
                        unresolved_obligations: obligations,
                        command_identities,
                        policy: record.request.policy(),
                        trust,
                        admitted_position: record.request.request_position(),
                        deadline_position: record.request.horizon_position(),
                        authorization_provenance: provenance,
                    })
                })
                .and_then(|admission| self.dispatch_attempt(request, &admission))
        })
    }
    /// Persist one frozen-closure acknowledgement; an exact retry is idempotent.
    ///
    /// # Errors
    ///
    /// Returns unauthorized for an injected target and policy conflict for a conflicting retry.
    pub fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record
                .acknowledgements
                .binary_search(&acknowledgement)
                .is_ok()
            {
                return Ok(record.state);
            }
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
            record
                .supporting_records
                .obligations()
                .binary_search_by_key(&acknowledgement.obligation, ErasureObligationV1::reference)
                .ok()
                .map(|index| &record.supporting_records.obligations()[index])
                .ok_or(ErasureErrorV1::Unauthorized)
                .and_then(|obligation| {
                    if (obligation.target(), obligation.owner())
                        == (acknowledgement.target, acknowledgement.owner)
                    {
                        Ok(obligation.command_identity())
                    } else {
                        Err(ErasureErrorV1::Unauthorized)
                    }
                })
                .and_then(|command| {
                    record
                        .supporting_records
                        .retry_admissions
                        .last()
                        .cloned()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|admission| (command, admission))
                })
                .and_then(|(command, admission)| {
                    let pair_is_admitted = admission
                        .unresolved_obligations()
                        .binary_search(&acknowledgement.obligation)
                        .is_ok_and(|index| admission.command_identities()[index] == command);
                    if !pair_is_admitted {
                        return Err(ErasureErrorV1::Unauthorized);
                    }
                    record
                        .supporting_records
                        .scope_commitment()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|scope| (command, admission, scope.reference()))
                })
                .and_then(|(command, admission, scope)| {
                    ErasureAcknowledgementProvenanceV1::new(
                        ErasureAcknowledgementProvenanceInputV1 {
                            request,
                            command,
                            attempt: admission.reference(),
                            obligation: acknowledgement.obligation,
                            owner: acknowledgement.owner,
                            scope,
                            outcome: acknowledgement.outcome,
                            evidence: acknowledgement.evidence,
                            policy: admission.policy(),
                            trust: admission.trust(),
                        },
                    )
                    .map(|provenance| (admission, provenance))
                })
                .and_then(|(admission, acknowledgement_provenance)| {
                    if Self::has_acknowledgement_identity(&record, &acknowledgement_provenance) {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    self.port
                        .admit_acknowledgement(&acknowledgement_provenance)
                        .and_then(|()| {
                            record.retain_acknowledgement(&admission, &acknowledgement_provenance);
                            let state = record.state.clone();
                            self.commit(record).map(|()| state)
                        })
                })
        })
    }
    /// Commit a receipt after normalizing core-derived fields against this record.
    ///
    /// A terminal retry must reproduce the exact caller-owned evidence admitted
    /// for that receipt. Request identity, terminal state, lifecycle, freeze
    /// position, closure, acknowledgements, owner sets, replay claim, and the
    /// derived receipt digest are normalized from durable coordinator state.
    ///
    /// # Errors
    ///
    /// Returns a closed error for injected evidence or a conflicting terminal retry.
    pub fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if let Some(stored) = record.receipt.clone() {
                let has_active_attempt = record.supporting_records.retry_admissions.len()
                    == record
                        .supporting_records
                        .attempt_outcomes
                        .len()
                        .saturating_add(1);
                if !has_active_attempt {
                    return Self::normalize_receipt_input(
                        request,
                        self.coordinator,
                        &record,
                        input,
                    )
                    .and_then(|normalized| {
                        if record.receipt_input.as_ref() == Some(&normalized) {
                            Ok(stored)
                        } else {
                            Err(ErasureErrorV1::PolicyConflict)
                        }
                    });
                }
            }
            Self::finalize_record(self, request, &mut record, &input)
        })
    }

    pub(super) fn normalize_receipt_input(
        request: ErasureReferenceV1,
        coordinator: ErasureReferenceV1,
        record: &ErasureCoordinatorRecordV1,
        mut input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptInputV1, ErasureErrorV1> {
        let Some(freeze_position) = record.state.freeze_position() else {
            return Err(ErasureErrorV1::PolicyConflict);
        };
        if !record.state.lifecycle().is_attempt_terminal() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        input.request = request;
        input.coordinator = coordinator;
        input.terminal_state = record.state.state_digest();
        input.lifecycle = record.state.lifecycle();
        input.freeze_position = freeze_position;
        input.frozen_targets.clone_from(&record.targets);
        input.acknowledgements.clone_from(&record.acknowledgements);
        input.pending_owners = record.state.pending_owners().to_vec();
        input.failed_owners = record.state.failed_owners().to_vec();
        sort_inventories(&mut input.inventories);
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        if let Some(receipt) = record.receipt.as_ref() {
            input.policy = receipt.0.policy;
            input.trust = receipt.0.trust;
            input.provenance = receipt.provenance();
        }
        input.receipt_digest = reference_zero();
        Ok(input)
    }

    fn finalize_record(
        &mut self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        Self::prepare_finalization(self, request, record, input)
            .and_then(|(terminal_record, receipt)| self.commit(terminal_record).map(|()| receipt))
    }

    fn attempt_outcome(
        record: &ErasureCoordinatorRecordV1,
        admission: &ErasureRetryAdmissionV1,
        lifecycle: ErasureLifecycleV1,
        terminal_position: u64,
    ) -> Result<(ErasureAttemptOutcomeV1, Vec<ErasureReferenceV1>), ErasureErrorV1> {
        let acknowledgements = record
            .supporting_records
            .effective_acknowledgement_provenance(admission)
            .into_iter()
            .map(|(_, provenance)| provenance.reference())
            .collect::<Vec<_>>();
        ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
            request: record.request.reference(),
            attempt: admission.reference(),
            source_receipt: admission.source_receipt(),
            lifecycle,
            selected_obligations: selected_obligations_reference(
                admission.unresolved_obligations(),
            ),
            acknowledgement_inventory: acknowledgement_inventory_reference(&acknowledgements),
            terminal_position,
            policy: admission.policy(),
            trust: admission.trust(),
        })
        .map(|outcome| (outcome, acknowledgements))
    }

    fn receipt_provenance_for_attempt(
        admission: &ErasureRetryAdmissionV1,
        terminal_state: ErasureReferenceV1,
        acknowledgements: &[ErasureReferenceV1],
        issue_position: u64,
    ) -> Result<ErasureReceiptProvenanceV1, ErasureErrorV1> {
        ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
            request: admission.request(),
            attempt: admission.reference(),
            attempt_ordinal: admission.attempt_ordinal(),
            predecessor_receipt: admission.source_receipt(),
            terminal_state,
            evidence_set: erasure_evidence_set_reference(acknowledgements),
            policy: admission.policy(),
            trust: admission.trust(),
            issue_position,
        })
    }

    pub(super) fn prepare_finalization(
        &self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<(ErasureCoordinatorRecordV1, ErasureReceiptV1), ErasureErrorV1> {
        if !matches!(
            record.state.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let Some(admission) = record.supporting_records.retry_admissions.last().cloned() else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        if record.supporting_records.retry_admissions.len()
            != record
                .supporting_records
                .attempt_outcomes
                .len()
                .saturating_add(1)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let obligations = record.supporting_records.obligations();
        if !inventories_match_frozen_obligations(&input.inventories, obligations) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        record.acknowledgements = record
            .supporting_records
            .effective_acknowledgements(&admission);
        let complete =
            acknowledgements_close_frozen_obligations(&record.acknowledgements, obligations);
        if !complete && input.issue_position < admission.deadline_position() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let lifecycle = if complete {
            ErasureLifecycleV1::Complete
        } else {
            ErasureLifecycleV1::PartialFailure
        };
        self.persist_finalization(request, record, input, &admission, lifecycle)
    }

    fn persist_finalization(
        &self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: &ErasureReceiptInputV1,
        admission: &ErasureRetryAdmissionV1,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(ErasureCoordinatorRecordV1, ErasureReceiptV1), ErasureErrorV1> {
        let obligations = record.supporting_records.obligations().to_vec();
        let (pending_owners, failed_owners) =
            derived_outcome_owners_for_obligations(&obligations, &record.acknowledgements);
        let replay_claim = weakest_inventory_claim(&input.inventories);
        let freeze_position = record.state.freeze_position();
        Self::attempt_outcome(record, admission, lifecycle, input.issue_position).and_then(
            |(outcome, acknowledgement_references)| {
                record
                    .state
                    .transition(ErasureStateTransitionV1 {
                        lifecycle,
                        freeze_position,
                        pending_owners,
                        failed_owners,
                        acknowledged_targets: if lifecycle == ErasureLifecycleV1::Complete {
                            record.targets.clone()
                        } else {
                            Vec::new()
                        },
                        replay_claim,
                        provenance: outcome.reference(),
                    })
                    .and_then(|terminal| {
                        Self::receipt_provenance_for_attempt(
                            admission,
                            terminal.state_digest(),
                            &acknowledgement_references,
                            input.issue_position,
                        )
                        .map(|provenance| (terminal, provenance))
                    })
                    .and_then(|(terminal, receipt_provenance)| {
                        record.state = terminal;
                        Self::normalize_receipt_input(
                            request,
                            self.coordinator,
                            record,
                            input.clone(),
                        )
                        .map(|mut normalized| {
                            normalized.policy = admission.policy();
                            normalized.trust = admission.trust();
                            normalized.provenance = receipt_provenance.reference();
                            (normalized, receipt_provenance)
                        })
                    })
                    .and_then(|(normalized, receipt_provenance)| {
                        self.port
                            .admit_receipt(&normalized)
                            .and_then(|()| ErasureReceiptV1::new(normalized.clone()))
                            .and_then(|receipt| {
                                receipt
                                    .validate_frozen_obligations(&obligations)
                                    .map(|()| receipt)
                            })
                            .map(|receipt| (normalized, receipt_provenance, receipt))
                    })
                    .map(|(normalized, receipt_provenance, receipt)| {
                        record.retain_terminal_receipt(
                            normalized,
                            &outcome,
                            receipt.clone(),
                            &receipt_provenance,
                        );
                        (record.clone(), receipt)
                    })
            },
        )
    }

    /// Append one host-admitted scope extension through the persistence CAS seam.
    ///
    /// # Errors
    ///
    /// Returns a closed scope, authorization, or CAS conflict error.
    pub fn append_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        extension: ErasureScopeExtensionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|record| {
            record
                .supporting_records
                .scope_commitment()
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)
                .and_then(|scope| {
                    scope
                        .lineage_rule()
                        .ok_or(ErasureErrorV1::PolicyConflict)
                        .map(|lineage_rule| (scope, lineage_rule))
                })
                .and_then(|(scope, lineage_rule)| {
                    record
                        .scope_extension_ledger
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|current_reference| (scope, lineage_rule, current_reference))
                })
                .and_then(|(scope, lineage_rule, current_reference)| {
                    record
                        .supporting_records
                        .scope_extension_ledgers()
                        .iter()
                        .find(|ledger| ledger.reference() == current_reference)
                        .cloned()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|current| (scope, lineage_rule, current_reference, current))
                })
                .and_then(|(scope, lineage_rule, current_reference, current)| {
                    if current.head() == Some(extension.reference()) {
                        return Ok(record.state);
                    }
                    if (
                        extension.request(),
                        extension.scope_commitment(),
                        extension.lineage_rule(),
                        extension.predecessor_extension(),
                    ) != (request, scope.reference(), lineage_rule, current.head())
                    {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    self.port.admit_scope_extension(&extension).and_then(|()| {
                        let mut extensions = current.extensions().to_vec();
                        extensions.push(extension.reference());
                        ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
                            scope_commitment: scope.reference(),
                            extensions,
                            head: Some(extension.reference()),
                        })
                        .and_then(|successor| {
                            let mut next = record;
                            next.retain_scope_extension(extension, successor);
                            let state = next.state.clone();
                            VerifiedErasureCoordinatorRecordV1::new(next.clone(), &self.port)
                                .and_then(|verified| {
                                    self.port.compare_and_swap_scope_extension(
                                        request,
                                        current_reference,
                                        verified,
                                    )
                                })
                                .map(|()| {
                                    self.cache(next);
                                    state
                                })
                        })
                    })
                })
        })
    }

    /// Append one host-admitted administrative resolution through the CAS seam.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, commitment, or CAS conflict error.
    pub fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|record| {
            record
                .supporting_records
                .scope_commitment()
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)
                .and_then(|scope| {
                    record
                        .supporting_records
                        .obligation_set()
                        .cloned()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|obligation_set| (scope, obligation_set))
                })
                .and_then(|(scope, obligation_set)| {
                    let expected_head = record.administrative_resolution_head;
                    if expected_head == Some(resolution.reference()) {
                        return Ok(record.state);
                    }
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
                        obligation_set.trust(),
                        expected_head,
                    ) {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    self.port
                        .admit_administrative_resolution(&resolution)
                        .and_then(|()| {
                            let mut next = record;
                            next.retain_administrative_resolution(resolution);
                            let state = next.state.clone();
                            VerifiedErasureCoordinatorRecordV1::new(next.clone(), &self.port)
                                .and_then(|verified| {
                                    self.port.compare_and_swap_administrative_resolution(
                                        request,
                                        expected_head,
                                        verified,
                                    )
                                })
                                .map(|()| {
                                    self.cache(next);
                                    state
                                })
                        })
                })
        })
    }
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinator for ErasureCoordinatorStateMachineV1<P> {
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        let provenance = request.provenance();
        Self::submit(self, request, provenance)
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
        Self::dispatch_attempt(self, request, &admission)
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
