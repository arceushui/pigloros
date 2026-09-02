use super::{
    acknowledgement_inventory_reference, administrative_resolution_from_fields,
    administrative_resolution_value, category_obligation_count_is_bounded, decode_limited,
    destruction_command_reference, domain_digest, encode_limited, erasure_evidence_set_reference,
    exact_array, has_duplicate, obligation_count_is_bounded, reference_zero,
    scope_extension_count_is_bounded, selected_obligations_reference,
    supporting_records_from_value, supporting_records_value, BTreeMap, BTreeSet,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureAttemptOutcomeV1, ErasureAuthorizationRejectionV1,
    ErasureCoordinator, ErasureCoordinatorPortV1, ErasureCorrectionProvenanceV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1,
    ErasurePositiveProvenanceIndexV1, ErasureReceiptProvenanceV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionLedgerV1, ErasureScopeExtensionV1,
    ErasureStateResolverV1, ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1,
    ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1, ERASURE_COORDINATOR_RECORD_MAX_BYTES,
    ERASURE_INVENTORY_CATEGORY_COUNT, ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS,
    ERASURE_MAX_ATTEMPT_OUTCOMES, ERASURE_MAX_OBLIGATIONS, ERASURE_MAX_REFERENCES,
    ERASURE_PORTABLE_RECORD_MAX_BYTES,
};

struct ErasureEvidenceIndex<'a> {
    obligations: BTreeMap<ErasureReferenceV1, &'a ErasureObligationV1>,
    admissions: BTreeMap<ErasureReferenceV1, &'a ErasureRetryAdmissionV1>,
    admitted_commands: BTreeSet<(ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1)>,
    provenance_by_attempt:
        BTreeMap<ErasureReferenceV1, Vec<&'a ErasureAcknowledgementProvenanceV1>>,
    earliest_positive: ErasurePositiveProvenanceIndexV1<'a>,
    current_provenance: BTreeMap<
        (ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1),
        &'a ErasureAcknowledgementProvenanceV1,
    >,
}

impl<'a> ErasureEvidenceIndex<'a> {
    fn new(records: &'a ErasureSupportingRecordsV1) -> Self {
        let obligations = records
            .obligations
            .iter()
            .map(|obligation| (obligation.reference(), obligation))
            .collect::<BTreeMap<_, _>>();
        let admissions = records
            .retry_admissions
            .iter()
            .map(|admission| (admission.reference(), admission))
            .collect::<BTreeMap<_, _>>();
        let admitted_commands = records
            .retry_admissions
            .iter()
            .flat_map(|admission| {
                admission
                    .unresolved_obligations()
                    .iter()
                    .copied()
                    .zip(admission.command_identities().iter().copied())
                    .map(|(obligation, command)| (admission.reference(), obligation, command))
            })
            .collect();
        let mut provenance_by_attempt = BTreeMap::<_, Vec<_>>::new();
        let mut earliest_positive = BTreeMap::new();
        let mut current_provenance = BTreeMap::new();
        for provenance in &records.acknowledgement_provenance {
            provenance_by_attempt
                .entry(provenance.attempt())
                .or_default()
                .push(provenance);
            current_provenance
                .entry((
                    provenance.attempt(),
                    provenance.obligation(),
                    provenance.owner(),
                ))
                .or_insert(provenance);
            if provenance.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged {
                let Some(admission) = admissions.get(&provenance.attempt()) else {
                    continue;
                };
                let candidate = (admission.attempt_ordinal(), provenance.reference());
                let entry = earliest_positive
                    .entry((provenance.obligation(), provenance.owner()))
                    .or_insert((candidate, provenance));
                if candidate < entry.0 {
                    *entry = (candidate, provenance);
                }
            }
        }
        Self {
            obligations,
            admissions,
            admitted_commands,
            provenance_by_attempt,
            earliest_positive,
            current_provenance,
        }
    }

    fn effective_provenance(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Vec<(
        &'a ErasureObligationV1,
        &'a ErasureAcknowledgementProvenanceV1,
    )> {
        self.obligations
            .values()
            .filter_map(|obligation| {
                let identity = (obligation.reference(), obligation.owner());
                self.earliest_positive
                    .get(&identity)
                    .filter(|((ordinal, _), _)| *ordinal <= admission.attempt_ordinal())
                    .map(|(_, provenance)| (*obligation, *provenance))
                    .or_else(|| {
                        self.current_provenance
                            .get(&(
                                admission.reference(),
                                obligation.reference(),
                                obligation.owner(),
                            ))
                            .map(|provenance| (*obligation, *provenance))
                    })
            })
            .collect()
    }

    fn advance_effective_references(
        &self,
        admission: &ErasureRetryAdmissionV1,
        carried: &mut ErasurePositiveProvenanceIndexV1<'a>,
    ) -> Vec<ErasureReferenceV1> {
        let mut current = BTreeMap::new();
        for provenance in self
            .provenance_by_attempt
            .get(&admission.reference())
            .into_iter()
            .flatten()
        {
            let provenance = *provenance;
            let Some(obligation) = self.obligations.get(&provenance.obligation()) else {
                continue;
            };
            if obligation.owner() != provenance.owner() {
                continue;
            }
            let identity = (obligation.reference(), obligation.owner());
            if provenance.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged {
                let candidate = (admission.attempt_ordinal(), provenance.reference());
                let entry = carried.entry(identity).or_insert((candidate, provenance));
                if candidate < entry.0 {
                    *entry = (candidate, provenance);
                }
            } else if !carried.contains_key(&identity) {
                current.entry(identity).or_insert(provenance);
            }
        }
        carried
            .values()
            .map(|(_, provenance)| provenance.reference())
            .chain(current.values().map(|provenance| provenance.reference()))
            .collect()
    }
}

impl ErasureSupportingRecordsV1 {
    /// Encode the canonical portable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed error when this optional aggregate envelope exceeds
    /// the coordinator bound. Durable adapters use normalized evidence.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &supporting_records_value(self),
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical portable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or conflicting evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
        .and_then(|value| supporting_records_from_value(&value))
    }

    /// Validate one complete immutable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed policy or provenance error for a fork, gap, mismatched
    /// request, attempt, receipt, or bounded collection.
    pub fn new(input: ErasureSupportingRecordsInputV1) -> Result<Self, ErasureErrorV1> {
        Self::from_canonical_input(input)
    }

    pub(super) fn from_canonical_input(
        input: ErasureSupportingRecordsInputV1,
    ) -> Result<Self, ErasureErrorV1> {
        let records = Self {
            correction_provenance: input.correction_provenance,
            authorization_rejection: input.authorization_rejection,
            scope_commitment: input.scope_commitment,
            freeze_admission_evidence: input.freeze_admission_evidence,
            freeze_authorization_evidence: input.freeze_authorization_evidence,
            freeze_provenance: input.freeze_provenance,
            freeze_failure: input.freeze_failure,
            obligations: input.obligations,
            obligation_set: input.obligation_set,
            scope_extensions: input.scope_extensions,
            scope_extension_ledgers: input.scope_extension_ledgers,
            retry_admissions: input.retry_admissions,
            acknowledgement_provenance: input.acknowledgement_provenance,
            attempt_outcomes: input.attempt_outcomes,
            receipts: input.receipts,
            receipt_provenance: input.receipt_provenance,
            administrative_resolutions: input.administrative_resolutions,
        };
        records.validate().map(|()| records)
    }

    /// Return correction provenance, when this ERQ1 replaces a rejection.
    #[must_use]
    pub const fn correction_provenance(&self) -> Option<&ErasureCorrectionProvenanceV1> {
        self.correction_provenance.as_ref()
    }

    /// Return canonical pre-authorization rejection evidence, when present.
    #[must_use]
    pub const fn authorization_rejection(&self) -> Option<ErasureAuthorizationRejectionV1> {
        self.authorization_rejection
    }

    /// Return the immutable resolved scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> Option<&ErasureScopeCommitmentV1> {
        self.scope_commitment.as_ref()
    }

    /// Return complete freeze-admission applicability evidence.
    #[must_use]
    pub const fn freeze_admission_evidence(&self) -> Option<&ErasureFreezeAdmissionEvidenceV1> {
        self.freeze_admission_evidence.as_ref()
    }

    /// Return retained host authorization evidence for the freeze admission.
    #[must_use]
    pub const fn freeze_authorization_evidence(
        &self,
    ) -> Option<&ErasureFreezeAuthorizationEvidenceV1> {
        self.freeze_authorization_evidence.as_ref()
    }

    /// Return immutable successful freeze evidence.
    #[must_use]
    pub const fn freeze_provenance(&self) -> Option<ErasureFreezeProvenanceV1> {
        self.freeze_provenance
    }

    /// Return immutable freeze-failure evidence.
    #[must_use]
    pub const fn freeze_failure(&self) -> Option<ErasureFreezeFailureV1> {
        self.freeze_failure
    }

    /// Return immutable category/target/owner obligations.
    #[must_use]
    pub fn obligations(&self) -> &[ErasureObligationV1] {
        &self.obligations
    }

    /// Return the frozen obligation-reference set, when access froze.
    #[must_use]
    pub const fn obligation_set(&self) -> Option<&ErasureObligationSetV1> {
        self.obligation_set.as_ref()
    }

    /// Return immutable future-Fork scope extensions.
    #[must_use]
    pub fn scope_extensions(&self) -> &[ErasureScopeExtensionV1] {
        &self.scope_extensions
    }

    /// Return immutable extension-ledger snapshots.
    #[must_use]
    pub fn scope_extension_ledgers(&self) -> &[ErasureScopeExtensionLedgerV1] {
        &self.scope_extension_ledgers
    }

    /// Return attempt admissions in ordinal order.
    #[must_use]
    pub fn retry_admissions(&self) -> &[ErasureRetryAdmissionV1] {
        &self.retry_admissions
    }

    /// Return acknowledgement-result evidence.
    #[must_use]
    pub fn acknowledgement_provenance(&self) -> &[ErasureAcknowledgementProvenanceV1] {
        &self.acknowledgement_provenance
    }

    /// Return attempt outcomes in ordinal order.
    #[must_use]
    pub fn attempt_outcomes(&self) -> &[ErasureAttemptOutcomeV1] {
        &self.attempt_outcomes
    }

    /// Return immutable ERC1 receipts in ordinal order.
    #[must_use]
    pub fn receipts(&self) -> &[ErasureReceiptV1] {
        &self.receipts
    }

    /// Return receipt provenance in ordinal order.
    #[must_use]
    pub fn receipt_provenance(&self) -> &[ErasureReceiptProvenanceV1] {
        &self.receipt_provenance
    }

    /// Return the administrative-resolution chain.
    #[must_use]
    pub fn administrative_resolutions(&self) -> &[ErasureAdministrativeResolutionV1] {
        &self.administrative_resolutions
    }

    pub(super) fn persistence_evidence(
        &self,
    ) -> Result<Vec<(ErasureReferenceV1, Vec<u8>)>, ErasureErrorV1> {
        let mut evidence = Vec::new();
        macro_rules! push_optional {
            ($value:expr_2021) => {
                if let Some(value) = $value {
                    evidence.push((value.reference(), value.to_canonical_cbor()?));
                }
            };
        }
        macro_rules! push_records {
            ($values:expr_2021) => {
                for value in $values {
                    evidence.push((value.reference(), value.to_canonical_cbor()?));
                }
            };
        }

        push_optional!(self.correction_provenance.as_ref());
        push_optional!(self.authorization_rejection.as_ref());
        push_optional!(self.scope_commitment.as_ref());
        push_optional!(self.freeze_admission_evidence.as_ref());
        push_optional!(self.freeze_authorization_evidence.as_ref());
        push_optional!(self.freeze_provenance.as_ref());
        push_optional!(self.freeze_failure.as_ref());
        push_records!(&self.obligations);
        push_optional!(self.obligation_set.as_ref());
        push_records!(&self.scope_extensions);
        push_records!(&self.scope_extension_ledgers);
        push_records!(&self.retry_admissions);
        push_records!(&self.acknowledgement_provenance);
        push_records!(&self.attempt_outcomes);
        for receipt in &self.receipts {
            evidence.push((receipt.receipt_digest(), receipt.to_canonical_cbor()?));
        }
        push_records!(&self.receipt_provenance);
        push_records!(&self.administrative_resolutions);
        Ok(evidence)
    }

    pub(super) fn validate(&self) -> Result<(), ErasureErrorV1> {
        if self.authorization_rejection.is_some() && self.freeze_failure.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.authorization_rejection.is_some()
            && (self.scope_commitment.is_some()
                || self.freeze_admission_evidence.is_some()
                || self.freeze_authorization_evidence.is_some()
                || self.freeze_provenance.is_some()
                || self.obligation_set.is_some()
                || !self.obligations.is_empty()
                || !self.scope_extensions.is_empty()
                || !self.scope_extension_ledgers.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.freeze_failure.is_some()
            && (self.scope_commitment.is_some()
                || self.freeze_admission_evidence.is_some()
                || self.freeze_authorization_evidence.is_some()
                || self.freeze_provenance.is_some()
                || self.obligation_set.is_some()
                || !self.obligations.is_empty()
                || !self.scope_extensions.is_empty()
                || !self.scope_extension_ledgers.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if let Some(freeze) = self.freeze_provenance {
            let Some(scope) = self.scope_commitment.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(obligation_set) = self.obligation_set.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(admission) = self.freeze_admission_evidence.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(authorization) = self.freeze_authorization_evidence.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let freeze_matches_scope = freeze.scope_commitment() == scope.reference()
                && freeze.obligation_set() == obligation_set.reference()
                && freeze.host_evidence() == admission.reference();
            if !freeze_matches_scope {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            self.validate_freeze_admission_bindings(
                scope,
                obligation_set,
                admission,
                authorization,
            )?;
        } else if self.freeze_admission_evidence.is_some()
            || self.freeze_authorization_evidence.is_some()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if self.scope_commitment.is_none()
            && (self.obligation_set.is_some()
                || !self.scope_extensions.is_empty()
                || !self.scope_extension_ledgers.is_empty())
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.validate_obligation_evidence()?;
        self.validate_scope_extension_evidence()?;
        // Attempt-scoped collection lengths are bounded by admission ordinals
        // and their per-attempt cardinality checks. Acknowledgement provenance
        // is append-only across attempts, so its lifetime bound is the encoded
        // coordinator-record limit rather than one attempt's obligation count.
        if self
            .administrative_resolutions
            .get(ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS)
            .is_some()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.attempt_outcomes.len() != self.receipts.len() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.receipts.len() != self.receipt_provenance.len() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.retry_admissions.len() < self.attempt_outcomes.len() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.retry_admissions.len() > self.attempt_outcomes.len().saturating_add(1) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.validate_acknowledgements()?;
        self.validate_attempt_chain()?;
        self.validate_resolution_chain()
    }

    pub(super) fn validate_freeze_admission_bindings(
        &self,
        scope: &ErasureScopeCommitmentV1,
        obligation_set: &ErasureObligationSetV1,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        let freeze = self
            .freeze_provenance
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if (
            admission.request(),
            admission.scope_commitment(),
            admission.obligation_set(),
            admission.freeze_position(),
            admission.policy(),
            admission.trust(),
            admission.authorization_provenance(),
            authorization.admission_body_digest(),
            authorization.policy(),
            authorization.trust(),
        ) != (
            scope.request(),
            scope.reference(),
            obligation_set.reference(),
            freeze.freeze_position(),
            obligation_set.policy(),
            obligation_set.trust(),
            authorization.reference(),
            admission.authorization_body_digest()?,
            obligation_set.policy(),
            obligation_set.trust(),
        ) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    pub(super) fn validate_obligation_evidence(&self) -> Result<(), ErasureErrorV1> {
        let Some(set) = self.obligation_set.as_ref() else {
            return if self.obligations.is_empty() {
                Ok(())
            } else {
                Err(ErasureErrorV1::ProvenanceMissing)
            };
        };
        if !obligation_count_is_bounded(self.obligations.len()) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let references = self
            .obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect::<Vec<_>>();
        if set.obligations() != references.as_slice() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut category_counts = [0_usize; ERASURE_INVENTORY_CATEGORY_COUNT];
        let mut command_owner_pairs = Vec::with_capacity(self.obligations.len());
        let mut category_target_pairs = Vec::with_capacity(self.obligations.len());
        for obligation in &self.obligations {
            if obligation.command_identity()
                != destruction_command_reference(set.request(), obligation.target())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            let category = obligation.category().index();
            category_counts[category] = category_counts[category].saturating_add(1);
            command_owner_pairs.push((obligation.command_identity(), obligation.owner()));
            category_target_pairs.push((obligation.category(), obligation.target()));
        }
        command_owner_pairs.sort_unstable();
        category_target_pairs.sort_unstable();
        if category_counts
            .iter()
            .any(|count| !category_obligation_count_is_bounded(*count))
            || has_duplicate(&command_owner_pairs)
            || has_duplicate(&category_target_pairs)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(())
    }

    pub(super) fn validate_scope_extension_evidence(&self) -> Result<(), ErasureErrorV1> {
        let Some(scope) = self.scope_commitment.as_ref() else {
            return Ok(());
        };
        let Some(lineage_rule) = scope.lineage_rule() else {
            return if self.scope_extensions.is_empty() && self.scope_extension_ledgers.is_empty() {
                Ok(())
            } else {
                Err(ErasureErrorV1::PolicyConflict)
            };
        };
        if !scope_extension_count_is_bounded(self.scope_extensions.len())
            || self.scope_extension_ledgers.len() != self.scope_extensions.len().saturating_add(1)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let mut forks = Vec::with_capacity(self.scope_extensions.len());
        let mut expected_predecessor = None;
        for extension in &self.scope_extensions {
            if (
                extension.request(),
                extension.scope_commitment(),
                extension.lineage_rule(),
                extension.predecessor_extension(),
            ) != (
                scope.request(),
                scope.reference(),
                lineage_rule,
                expected_predecessor,
            ) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            expected_predecessor = Some(extension.reference());
            forks.push(extension.fork());
        }
        forks.sort_unstable();
        if has_duplicate(&forks) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let extension_references = self
            .scope_extensions
            .iter()
            .map(ErasureScopeExtensionV1::reference)
            .collect::<Vec<_>>();
        for (index, ledger) in self.scope_extension_ledgers.iter().enumerate() {
            let expected_extensions = &extension_references[..index];
            let expected_head = expected_extensions.last().copied();
            if ledger.scope_commitment() != scope.reference()
                || ledger.extensions() != expected_extensions
                || ledger.head() != expected_head
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }

    pub(super) fn effective_acknowledgement_provenance(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Vec<(&ErasureObligationV1, &ErasureAcknowledgementProvenanceV1)> {
        ErasureEvidenceIndex::new(self).effective_provenance(admission)
    }

    pub(super) fn effective_acknowledgements(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Vec<ErasureAcknowledgementV1> {
        let mut acknowledgements = self
            .effective_acknowledgement_provenance(admission)
            .into_iter()
            .map(|(obligation, provenance)| ErasureAcknowledgementV1 {
                obligation: obligation.reference(),
                target: obligation.target(),
                owner: obligation.owner(),
                evidence: provenance.evidence(),
                outcome: provenance.outcome(),
            })
            .collect::<Vec<_>>();
        acknowledgements.sort_unstable();
        acknowledgements
    }

    pub(super) fn validate_attempt_chain(&self) -> Result<(), ErasureErrorV1> {
        let evidence = ErasureEvidenceIndex::new(self);
        let mut carried = BTreeMap::new();
        let mut expected_predecessor = None;
        let mut receipt_digests = self.receipts.iter().map(ErasureReceiptV1::receipt_digest);
        for (ordinal, admission) in self.retry_admissions.iter().enumerate() {
            let ordinal = ordinal as u64;
            if admission.attempt_ordinal() != ordinal
                || admission.source_receipt() != expected_predecessor
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            expected_predecessor = receipt_digests.next();
        }
        for (ordinal, (((outcome, receipt), provenance), admission)) in self
            .attempt_outcomes
            .iter()
            .zip(&self.receipts)
            .zip(&self.receipt_provenance)
            .zip(&self.retry_admissions)
            .enumerate()
        {
            let ordinal = ordinal as u64;
            let outcome_matches = (
                outcome.request(),
                outcome.attempt(),
                outcome.source_receipt(),
                outcome.lifecycle(),
                outcome.policy(),
                outcome.trust(),
            ) == (
                admission.request(),
                admission.reference(),
                admission.source_receipt(),
                receipt.lifecycle(),
                admission.policy(),
                admission.trust(),
            );
            let provenance_matches = (
                provenance.request(),
                provenance.attempt(),
                provenance.attempt_ordinal(),
                provenance.predecessor_receipt(),
                provenance.terminal_state(),
                provenance.policy(),
                provenance.trust(),
            ) == (
                admission.request(),
                admission.reference(),
                ordinal,
                admission.source_receipt(),
                receipt.terminal_state(),
                admission.policy(),
                admission.trust(),
            );
            let acknowledgement_references =
                evidence.advance_effective_references(admission, &mut carried);
            let selected_obligations =
                selected_obligations_reference(admission.unresolved_obligations());
            let acknowledgement_inventory =
                acknowledgement_inventory_reference(&acknowledgement_references);
            let evidence_set = erasure_evidence_set_reference(&acknowledgement_references);
            if !outcome_matches
                || !provenance_matches
                || outcome.selected_obligations() != selected_obligations
                || outcome.acknowledgement_inventory() != acknowledgement_inventory
                || outcome.terminal_position() != provenance.issue_position()
                || provenance.evidence_set() != evidence_set
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if receipt.provenance() != provenance.reference() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }

    pub(super) fn validate_acknowledgements(&self) -> Result<(), ErasureErrorV1> {
        let evidence = ErasureEvidenceIndex::new(self);
        let mut identities = Vec::with_capacity(self.acknowledgement_provenance.len());
        let scope = self
            .scope_commitment
            .as_ref()
            .map(ErasureScopeCommitmentV1::reference);
        for acknowledgement in &self.acknowledgement_provenance {
            let obligation = evidence
                .obligations
                .get(&acknowledgement.obligation())
                .copied()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let admission = evidence
                .admissions
                .get(&acknowledgement.attempt())
                .copied()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let command_matches_obligation = evidence.admitted_commands.contains(&(
                acknowledgement.attempt(),
                acknowledgement.obligation(),
                acknowledgement.command(),
            ));
            let command_differs = obligation.command_identity() != acknowledgement.command();
            if admission.request() != acknowledgement.request()
                || !command_matches_obligation
                || command_differs
                || obligation.owner() != acknowledgement.owner()
                || Some(acknowledgement.scope()) != scope
                || admission.policy() != acknowledgement.policy()
                || admission.trust() != acknowledgement.trust()
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            identities.push((
                acknowledgement.command(),
                acknowledgement.attempt(),
                acknowledgement.owner(),
            ));
        }
        if !self
            .acknowledgement_provenance
            .iter()
            .map(acknowledgement_provenance_ordering_key)
            .is_sorted()
            || has_duplicate(&identities)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    pub(super) fn validate_resolution_chain(&self) -> Result<(), ErasureErrorV1> {
        let mut predecessor = None;
        for resolution in &self.administrative_resolutions {
            if resolution.predecessor_resolution() != predecessor {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            predecessor = Some(resolution.reference());
        }
        Ok(())
    }

    pub(super) fn validates_request(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        let attempts_match = self
            .authorization_rejection
            .is_none_or(|record| record.request() == request)
            && self
                .scope_commitment
                .as_ref()
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_admission_evidence
                .as_ref()
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_provenance
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_failure
                .is_none_or(|record| record.request() == request)
            && self
                .obligation_set
                .as_ref()
                .is_none_or(|record| record.request() == request)
            && self
                .scope_extensions
                .iter()
                .all(|record| record.request() == request)
            && self
                .retry_admissions
                .iter()
                .all(|record| record.request() == request)
            && self
                .acknowledgement_provenance
                .iter()
                .all(|record| record.request() == request)
            && self
                .attempt_outcomes
                .iter()
                .all(|record| record.request() == request)
            && self
                .receipt_provenance
                .iter()
                .all(|record| record.request() == request)
            && self
                .administrative_resolutions
                .iter()
                .all(|record| record.request() == request)
            && self
                .receipts
                .iter()
                .all(|record| record.0.request == request);
        if attempts_match {
            Ok(())
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }

    pub(super) fn is_prefix_of(&self, next: &Self) -> bool {
        [
            option_is_unchanged(
                self.correction_provenance.as_ref(),
                next.correction_provenance.as_ref(),
            ),
            option_is_unchanged(
                self.authorization_rejection.as_ref(),
                next.authorization_rejection.as_ref(),
            ),
            option_is_unchanged(
                self.scope_commitment.as_ref(),
                next.scope_commitment.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_admission_evidence.as_ref(),
                next.freeze_admission_evidence.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_authorization_evidence.as_ref(),
                next.freeze_authorization_evidence.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_provenance.as_ref(),
                next.freeze_provenance.as_ref(),
            ),
            option_is_unchanged(self.freeze_failure.as_ref(), next.freeze_failure.as_ref()),
            next.obligations.starts_with(&self.obligations),
            option_is_unchanged(self.obligation_set.as_ref(), next.obligation_set.as_ref()),
            next.scope_extensions.starts_with(&self.scope_extensions),
            next.scope_extension_ledgers
                .starts_with(&self.scope_extension_ledgers),
            next.retry_admissions.starts_with(&self.retry_admissions),
            self.acknowledgement_provenance.iter().all(|record| {
                next.acknowledgement_provenance
                    .binary_search_by_key(
                        &acknowledgement_provenance_ordering_key(record),
                        acknowledgement_provenance_ordering_key,
                    )
                    .is_ok()
            }),
            next.attempt_outcomes.starts_with(&self.attempt_outcomes),
            next.receipts.starts_with(&self.receipts),
            next.receipt_provenance
                .starts_with(&self.receipt_provenance),
            next.administrative_resolutions
                .starts_with(&self.administrative_resolutions),
        ]
        .into_iter()
        .all(std::convert::identity)
    }
}
pub(super) const fn acknowledgement_provenance_ordering_key(
    acknowledgement: &ErasureAcknowledgementProvenanceV1,
) -> (
    ErasureReferenceV1,
    ErasureReferenceV1,
    ErasureReferenceV1,
    ErasureReferenceV1,
) {
    (
        acknowledgement.command(),
        acknowledgement.attempt(),
        acknowledgement.owner(),
        acknowledgement.reference(),
    )
}

pub(super) fn option_is_unchanged<T: PartialEq>(current: Option<&T>, next: Option<&T>) -> bool {
    current.is_none_or(|value| next == Some(value))
}

impl ErasureAdministrativeResolutionV1 {
    /// Construct, normalize, and content-address an administrative resolution.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an empty, duplicate, or oversized set.
    pub fn new(mut input: ErasureAdministrativeResolutionInputV1) -> Result<Self, ErasureErrorV1> {
        if input.affected_digests.is_empty()
            || input.affected_digests.len() > ERASURE_MAX_REFERENCES
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.affected_digests.sort_unstable();
        if has_duplicate(&input.affected_digests) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return affected state/evidence digests in bytewise order.
    #[must_use]
    pub fn affected_digests(&self) -> &[ErasureReferenceV1] {
        &self.input.affected_digests
    }
    /// Return the closed recovery action.
    #[must_use]
    pub const fn action(&self) -> ErasureAdministrativeResolutionActionV1 {
        self.input.action
    }
    /// Return the affected scope-commitment digest.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return the authorizing Principal digest.
    #[must_use]
    pub const fn principal(&self) -> ErasureReferenceV1 {
        self.input.principal
    }
    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }
    /// Return the resolution-reason digest.
    #[must_use]
    pub const fn reason(&self) -> ErasureReferenceV1 {
        self.input.reason
    }
    /// Return the issue logical position.
    #[must_use]
    pub const fn issue_position(&self) -> u64 {
        self.input.issue_position
    }
    /// Return the preceding resolution digest, if any.
    #[must_use]
    pub const fn predecessor_resolution(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_resolution
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &administrative_resolution_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical administrative-resolution record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 13).and_then(administrative_resolution_from_fields))
    }

    pub(super) fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &administrative_resolution_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

pub(super) fn normalize_retry_admission(
    input: &mut ErasureRetryAdmissionInputV1,
) -> Result<(), ErasureErrorV1> {
    if !(0..ERASURE_MAX_ATTEMPT_OUTCOMES as u64).contains(&input.attempt_ordinal) {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if (input.attempt_ordinal == 0) != input.source_receipt.is_none() {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if input
        .deadline_position
        .checked_sub(input.admitted_position)
        .is_none()
    {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if input.unresolved_obligations.len() != input.command_identities.len() {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    if input
        .unresolved_obligations
        .get(ERASURE_MAX_OBLIGATIONS)
        .is_some()
    {
        return Err(ErasureErrorV1::ScopeInvalid);
    }

    let mut pairs = input
        .unresolved_obligations
        .iter()
        .copied()
        .zip(input.command_identities.iter().copied())
        .collect::<Vec<_>>();
    pairs.sort_unstable_by_key(|(obligation, _)| *obligation);
    let duplicate_obligation = has_duplicate(
        &pairs
            .iter()
            .map(|(obligation, _)| *obligation)
            .collect::<Vec<_>>(),
    );
    if duplicate_obligation {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    input.unresolved_obligations = pairs.iter().map(|(obligation, _)| *obligation).collect();
    input.command_identities = pairs.iter().map(|(_, command)| *command).collect();
    Ok(())
}
