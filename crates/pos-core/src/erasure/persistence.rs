use super::*;

impl ErasurePersistenceEvidenceV1 {
    /// Return the content address used by persistence adapters.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.reference
    }

    /// Return the canonical bytes for this independently bounded object.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
}

/// Normalized durable coordinator representation.
///
/// The bounded manifest contains ERQ1/ERS1 and references to supporting
/// evidence. Each evidence object is stored independently so the permitted
/// receipt history cannot be rejected by an unrelated aggregate byte limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasurePersistenceBundleV1 {
    manifest_cbor: Vec<u8>,
    evidence: Vec<ErasurePersistenceEvidenceV1>,
}

impl ErasurePersistenceBundleV1 {
    /// Return the bounded canonical coordinator manifest.
    #[must_use]
    pub fn manifest_cbor(&self) -> &[u8] {
        &self.manifest_cbor
    }

    /// Return independently bounded content-addressed evidence objects.
    #[must_use]
    pub fn evidence(&self) -> &[ErasurePersistenceEvidenceV1] {
        &self.evidence
    }
}

impl ErasureCoordinatorRecordV1 {
    /// Reconstruct a durable coordinator record from host storage.
    ///
    /// Hosts may persist the returned public fields in any representation and
    /// must validate the complete record again when rehydrating it.  This
    /// constructor is the only supported boundary for records loaded by an
    /// [`ErasurePersistencePortV1`].
    ///
    /// # Errors
    ///
    /// Returns a closed error when the persisted record is inconsistent with
    /// the coordinator, lifecycle, closure, provenance, or terminal receipt.
    pub fn from_parts(
        parts: ErasureCoordinatorRecordPartsV1,
        coordinator: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        let record = Self {
            request: parts.request,
            state: parts.state,
            targets: parts.targets,
            acknowledgements: parts.acknowledgements,
            receipt: parts.receipt,
            receipt_input: parts.receipt_input,
            authorize_provenance: parts.authorize_provenance,
            freeze_provenance: parts.freeze_provenance,
            dispatch_provenance: parts.dispatch_provenance,
            scope_extension_ledger: parts.scope_extension_ledger,
            administrative_resolution_head: parts.administrative_resolution_head,
            supporting_records: parts.supporting_records,
        };
        record.validate(coordinator).map(|()| record)
    }

    /// Encode the complete durable coordinator record as canonical CBOR.
    ///
    /// The record embeds the canonical ERQ1, ERS1, and (when terminal) ERC1
    /// values. The terminal receipt is also the normalized receipt input, so
    /// it is stored once and reconstructed on load.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the record is invalid or exceeds the V1
    /// durable-record bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.validate(self.state.coordinator()).and_then(|()| {
            encode_limited(&record_value(self), ERASURE_COORDINATOR_RECORD_MAX_BYTES)
        })
    }

    /// Decode and validate one complete durable coordinator record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, oversized, or
    /// internally inconsistent persisted bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
        .and_then(|value| exact_array(&value, 13).and_then(record_from_fields))
    }

    /// Split this record into a bounded manifest and independently bounded
    /// content-addressed supporting objects for durable adapters.
    ///
    /// # Errors
    ///
    /// Returns a closed validation or encoding error for invalid evidence.
    pub fn to_persistence_bundle(&self) -> Result<ErasurePersistenceBundleV1, ErasureErrorV1> {
        self.validate(self.state.coordinator()).and_then(|()| {
            let manifest_cbor = encode_limited(
                &persistence_manifest_value(self),
                ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            )?;
            let mut evidence = BTreeMap::new();
            self.supporting_records
                .persistence_evidence()?
                .into_iter()
                .try_for_each(|(reference, canonical_cbor)| {
                    match evidence.entry(reference) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(canonical_cbor);
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => {
                            if entry.get() != &canonical_cbor {
                                return Err(ErasureErrorV1::ProvenanceMissing);
                            }
                        }
                    }
                    Ok(())
                })?;
            Ok(ErasurePersistenceBundleV1 {
                manifest_cbor,
                evidence: evidence
                    .into_iter()
                    .map(|(reference, canonical_cbor)| ErasurePersistenceEvidenceV1 {
                        reference,
                        canonical_cbor,
                    })
                    .collect(),
            })
        })
    }

    /// Rehydrate a normalized durable record through a content-addressed
    /// evidence resolver.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding or provenance error when the manifest is
    /// malformed, an object is unavailable, or bytes do not match their
    /// expected content address.
    pub fn from_persistence_manifest(
        manifest_cbor: &[u8],
        evidence: &mut dyn FnMut(ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1>,
    ) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            manifest_cbor,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
        .and_then(|value| {
            exact_array(&value, 13)
                .and_then(|fields| record_from_persistence_manifest(fields, evidence))
        })
    }

    /// Verify retained host authorization before a recovered record is returned.
    ///
    /// Pre-freeze records carry neither ERFA1 nor ERFAA1 evidence. Every
    /// frozen-or-later record carries both and must pass the supplied host
    /// verifier; a partial pair fails closed.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance or host-verification error.
    pub fn verify_recovered_freeze_authorization(
        &self,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<(), ErasureErrorV1> {
        match (
            self.supporting_records.freeze_admission_evidence(),
            self.supporting_records.freeze_authorization_evidence(),
        ) {
            (Some(admission), Some(authorization)) => {
                verifier.validate_freeze_authorization(admission, authorization)
            }
            (None, None) => Ok(()),
            _ => Err(ErasureErrorV1::ProvenanceMissing),
        }
    }

    pub(super) fn retain_authorization_rejection(
        &mut self,
        state: ErasureStateV1,
        rejection: ErasureAuthorizationRejectionV1,
    ) {
        self.state = state;
        self.supporting_records.authorization_rejection = Some(rejection);
    }

    pub(super) fn retain_atomic_freeze(
        &mut self,
        state: ErasureStateV1,
        admission: &ErasureAtomicFreezeAdmissionV1,
        scope: ErasureScopeCommitmentV1,
        freeze: ErasureFreezeProvenanceV1,
        ledger: Option<ErasureScopeExtensionLedgerV1>,
    ) {
        self.state = state;
        self.targets = admission.targets().to_vec();
        self.freeze_provenance = Some(freeze.reference());
        self.scope_extension_ledger = ledger
            .as_ref()
            .map(ErasureScopeExtensionLedgerV1::reference);
        self.supporting_records.scope_commitment = Some(scope);
        self.supporting_records.freeze_admission_evidence =
            Some(admission.freeze_admission_evidence().clone());
        self.supporting_records.freeze_authorization_evidence =
            Some(admission.freeze_authorization_evidence().clone());
        self.supporting_records.freeze_provenance = Some(freeze);
        self.supporting_records.obligations = admission.obligations().to_vec();
        self.supporting_records.obligation_set = Some(admission.obligation_set().clone());
        self.supporting_records.scope_extension_ledgers = ledger.into_iter().collect();
    }

    pub(super) fn retain_freeze_failure(
        &mut self,
        state: ErasureStateV1,
        failure: ErasureFreezeFailureV1,
    ) {
        self.state = state;
        self.supporting_records.freeze_failure = Some(failure);
    }

    pub(super) fn retain_acknowledgement(
        &mut self,
        admission: &ErasureRetryAdmissionV1,
        provenance: &ErasureAcknowledgementProvenanceV1,
    ) {
        self.supporting_records
            .acknowledgement_provenance
            .push(*provenance);
        self.supporting_records
            .acknowledgement_provenance
            .sort_unstable_by_key(acknowledgement_provenance_ordering_key);
        self.acknowledgements = self
            .supporting_records
            .effective_acknowledgements(admission);
    }

    pub(super) fn retain_terminal_receipt(
        &mut self,
        input: ErasureReceiptInputV1,
        outcome: &ErasureAttemptOutcomeV1,
        receipt: ErasureReceiptV1,
        provenance: &ErasureReceiptProvenanceV1,
    ) {
        self.receipt_input = Some(input);
        self.receipt = Some(receipt.clone());
        self.supporting_records.attempt_outcomes.push(*outcome);
        self.supporting_records.receipts.push(receipt);
        self.supporting_records.receipt_provenance.push(*provenance);
    }

    pub(super) fn retain_scope_extension(
        &mut self,
        extension: ErasureScopeExtensionV1,
        successor: ErasureScopeExtensionLedgerV1,
    ) {
        self.scope_extension_ledger = Some(successor.reference());
        self.supporting_records.scope_extensions.push(extension);
        self.supporting_records
            .scope_extension_ledgers
            .push(successor);
    }

    pub(super) fn retain_administrative_resolution(
        &mut self,
        resolution: ErasureAdministrativeResolutionV1,
    ) {
        self.administrative_resolution_head = Some(resolution.reference());
        self.supporting_records
            .administrative_resolutions
            .push(resolution);
    }

    /// Validate a replacement against the currently persisted record.
    ///
    /// Same-byte retries are idempotent. The only same-state extensions are
    /// admitted acknowledgement evidence, scope-ledger successors, and
    /// administrative-resolution successors; all lifecycle changes require a
    /// new ERS1 predecessor link.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::PolicyConflict`] when the replacement is not
    /// a permitted monotonic update.
    pub fn validate_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        let coordinator = self.state.coordinator();
        self.validate(coordinator)
            .and_then(|()| next.validate(coordinator))
            .and_then(|()| self.validate_replacement_fields(next))
    }

    fn validate_replacement_fields(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        if self.request != next.request {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !self
            .supporting_records
            .is_prefix_of(&next.supporting_records)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self == next {
            return Ok(());
        }
        if self.state.state_digest() == next.state.state_digest() {
            return self.validate_same_state_replacement(next);
        }
        self.validate_advanced_replacement(next)
    }

    pub(super) fn validate_same_state_replacement(
        &self,
        next: &Self,
    ) -> Result<(), ErasureErrorV1> {
        if (
            &self.request,
            &self.targets,
            &self.receipt,
            &self.receipt_input,
            self.authorize_provenance,
            self.freeze_provenance,
        ) != (
            &next.request,
            &next.targets,
            &next.receipt,
            &next.receipt_input,
            next.authorize_provenance,
            next.freeze_provenance,
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let lifecycle = self.state.lifecycle();
        let frozen = matches!(
            lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        );
        if self.dispatch_provenance != next.dispatch_provenance
            && !matches!(
                (
                    lifecycle,
                    self.dispatch_provenance,
                    next.dispatch_provenance
                ),
                (ErasureLifecycleV1::AccessFrozen, None, Some(_))
            )
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if (self.scope_extension_ledger != next.scope_extension_ledger
            || self.administrative_resolution_head != next.administrative_resolution_head)
            && !frozen
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.acknowledgements != next.acknowledgements
            && !matches!(
                lifecycle,
                ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
            )
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    pub(super) fn validate_advanced_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        if next.state.validate_predecessor(&self.state).is_err() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let targets_continue = next.targets == self.targets
            || (self.state.lifecycle() == ErasureLifecycleV1::Authorized
                && next.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
                && !next.targets.is_empty());
        if !targets_continue {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let initializes_scope_extension_ledger = self.state.lifecycle()
            == ErasureLifecycleV1::Authorized
            && next.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
            && self.scope_extension_ledger.is_none()
            && next.scope_extension_ledger.is_some();
        if (next.scope_extension_ledger != self.scope_extension_ledger
            && !initializes_scope_extension_ledger)
            || next.administrative_resolution_head != self.administrative_resolution_head
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if ![
            (self.authorize_provenance, next.authorize_provenance),
            (self.freeze_provenance, next.freeze_provenance),
            (self.dispatch_provenance, next.dispatch_provenance),
        ]
        .into_iter()
        .all(|(current, replacement)| current.is_none() || current == replacement)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    /// Return the authenticated ERQ1 request.
    #[must_use]
    pub const fn request(&self) -> &ErasureRequestV1 {
        &self.request
    }

    /// Return the latest digest-linked ERS1 state.
    #[must_use]
    pub const fn state(&self) -> &ErasureStateV1 {
        &self.state
    }

    /// Return the frozen required-target closure.
    #[must_use]
    pub fn targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.targets
    }

    /// Return acknowledgements accepted for the frozen closure.
    #[must_use]
    pub fn acknowledgements(&self) -> &[ErasureAcknowledgementV1] {
        &self.acknowledgements
    }

    /// Return the committed terminal receipt, if any.
    #[must_use]
    pub const fn receipt(&self) -> Option<&ErasureReceiptV1> {
        self.receipt.as_ref()
    }

    /// Return the exact terminal input admitted for idempotent retries.
    #[must_use]
    pub const fn receipt_input(&self) -> Option<&ErasureReceiptInputV1> {
        self.receipt_input.as_ref()
    }

    /// Return the authenticated authorization provenance, if present.
    #[must_use]
    pub const fn authorize_provenance(&self) -> Option<ErasureReferenceV1> {
        self.authorize_provenance
    }

    /// Return the host-authenticated freeze provenance, if present.
    #[must_use]
    pub const fn freeze_provenance(&self) -> Option<ErasureReferenceV1> {
        self.freeze_provenance
    }

    /// Return the host-authenticated dispatch provenance, if present.
    #[must_use]
    pub const fn dispatch_provenance(&self) -> Option<ErasureReferenceV1> {
        self.dispatch_provenance
    }

    /// Return the immutable scope-extension ledger reference, when future-Fork
    /// semantics were admitted at freeze.
    #[must_use]
    pub const fn scope_extension_ledger(&self) -> Option<ErasureReferenceV1> {
        self.scope_extension_ledger
    }

    /// Return the durable administrative-resolution chain head, if present.
    #[must_use]
    pub const fn administrative_resolution_head(&self) -> Option<ErasureReferenceV1> {
        self.administrative_resolution_head
    }

    /// Return immutable supporting records recovered with this coordinator state.
    #[must_use]
    pub const fn supporting_records(&self) -> &ErasureSupportingRecordsV1 {
        &self.supporting_records
    }

    /// Validate the rejected predecessor named by correction provenance.
    ///
    /// # Errors
    ///
    /// Returns provenance missing unless the predecessor is the exact rejected
    /// ERQ1/terminal ERS1 pair named by this record.
    pub fn validate_correction_predecessor(
        &self,
        predecessor: &Self,
    ) -> Result<(), ErasureErrorV1> {
        self.supporting_records
            .correction_provenance()
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|correction| {
                let predecessor_matches = (
                    predecessor.request.reference(),
                    predecessor.state.lifecycle(),
                    predecessor.state.state_digest(),
                ) == (
                    correction.rejected_request(),
                    ErasureLifecycleV1::Rejected,
                    correction.rejected_terminal_state(),
                );
                predecessor_matches
                    .then_some(())
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
            .and_then(|()| predecessor.validate(predecessor.state.coordinator()))
            .and_then(|()| {
                let rejection_matches = predecessor
                    .supporting_records
                    .freeze_failure()
                    .is_some_and(|failure| failure.reference() == predecessor.state.provenance())
                    || predecessor
                        .supporting_records
                        .authorization_rejection()
                        .is_some_and(|rejection| {
                            rejection.reference() == predecessor.state.provenance()
                        });
                rejection_matches
                    .then_some(())
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
    }

    fn validate_scope(&self) -> Result<(), ErasureErrorV1> {
        if !target_count_is_bounded(self.targets.len()) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !strictly_increasing(&self.targets) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if has_duplicate_acknowledgement_identity(&self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !strictly_increasing(&self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&self.targets, &self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let obligation_identities = self
            .supporting_records
            .obligations()
            .iter()
            .map(|obligation| {
                (
                    obligation.reference(),
                    obligation.target(),
                    obligation.owner(),
                )
            })
            .collect::<BTreeSet<_>>();
        if !self.acknowledgements.iter().all(|acknowledgement| {
            obligation_identities.contains(&(
                acknowledgement.obligation,
                acknowledgement.target,
                acknowledgement.owner,
            ))
        }) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if let Some(admission) = self.supporting_records.retry_admissions().last() {
            let expected = self
                .supporting_records
                .effective_acknowledgements(admission);
            if expected.as_slice() != self.acknowledgements.as_slice() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        } else if !self.acknowledgements.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    pub(super) fn validate_lifecycle_shape(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Rejected
        ) && (!self.targets.is_empty()
            || !self.acknowledgements.is_empty()
            || self.receipt.is_some()
            || self.receipt_input.is_some()
            || self.scope_extension_ledger.is_some()
            || self.administrative_resolution_head.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::Authorized
            && (!self.targets.is_empty()
                || !self.acknowledgements.is_empty()
                || self.receipt.is_some()
                || self.receipt_input.is_some()
                || self.scope_extension_ledger.is_some()
                || self.administrative_resolution_head.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::AccessFrozen
            && (self.targets.is_empty()
                || !self.acknowledgements.is_empty()
                || self.receipt.is_some()
                || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
        ) && (self.targets.is_empty() || self.receipt.is_some() || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    pub(super) fn validate_frozen_evidence(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        if matches!(
            lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        ) {
            let (Some(scope), Some(freeze), Some(obligation_set), Some(admission)) = (
                self.supporting_records.scope_commitment(),
                self.supporting_records.freeze_provenance(),
                self.supporting_records.obligation_set(),
                self.supporting_records.freeze_admission_evidence(),
            ) else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let expected_state_provenance =
                (lifecycle == ErasureLifecycleV1::AccessFrozen).then_some(freeze.reference());
            let actual_state_provenance =
                (lifecycle == ErasureLifecycleV1::AccessFrozen).then_some(self.state.provenance());
            if (
                scope.target_closure(),
                obligation_set.request(),
                obligation_set.policy(),
                freeze.request(),
                freeze.scope_commitment(),
                freeze.obligation_set(),
                freeze.host_evidence(),
                self.freeze_provenance,
                self.state.freeze_position(),
                freeze.freeze_position(),
                actual_state_provenance,
            ) != (
                target_closure_digest(&self.targets),
                self.request.reference(),
                self.request.policy(),
                self.request.reference(),
                scope.reference(),
                obligation_set.reference(),
                admission.reference(),
                Some(freeze.reference()),
                Some(freeze.freeze_position()),
                freeze.freeze_position(),
                expected_state_provenance,
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            for obligation in self.supporting_records.obligations() {
                if self.targets.binary_search(&obligation.target()).is_err()
                    || obligation.command_identity()
                        != destruction_command_reference(
                            self.request.reference(),
                            obligation.target(),
                        )
                {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            return validate_applicability_obligations(
                admission.applicability_matrix(),
                &self.targets,
                self.supporting_records.obligations(),
            )
            .and_then(|()| {
                let expected_ledger = scope.lineage_rule().and_then(|_| {
                    self.supporting_records
                        .scope_extension_ledgers()
                        .last()
                        .map(ErasureScopeExtensionLedgerV1::reference)
                });
                if self.scope_extension_ledger == expected_ledger {
                    Ok(())
                } else {
                    Err(ErasureErrorV1::ProvenanceMissing)
                }
            });
        }
        Ok(())
    }

    pub(super) fn validate_provenance(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        // Validate the exact provenance shape, not only its cardinality. A
        // malformed record must not substitute dispatch evidence for the
        // authorization or freeze evidence which precedes it.
        let expected = match lifecycle {
            ErasureLifecycleV1::Submitted => (false, false, false),
            ErasureLifecycleV1::Rejected => (
                self.supporting_records.freeze_failure().is_some(),
                false,
                false,
            ),
            ErasureLifecycleV1::Authorized => (true, false, false),
            // An AccessFrozen record may carry a durable dispatch intent while
            // the host operation is being retried. It is not yet a lifecycle
            // transition, but its identity must survive restart.
            ErasureLifecycleV1::AccessFrozen => (true, true, self.dispatch_provenance.is_some()),
            ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements
            | ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure => (true, true, true),
        };
        let actual = (
            self.authorize_provenance.is_some(),
            self.freeze_provenance.is_some(),
            self.dispatch_provenance.is_some(),
        );
        let rejected_before_authorization = lifecycle == ErasureLifecycleV1::Rejected
            && self.supporting_records.authorization_rejection().is_some();
        if (!rejected_before_authorization && actual != expected)
            || (rejected_before_authorization && actual != (false, false, false))
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    pub(super) fn validate_administrative_resolution_head(&self) -> Result<(), ErasureErrorV1> {
        let resolutions = self.supporting_records.administrative_resolutions();
        let expected_head = resolutions
            .last()
            .map(ErasureAdministrativeResolutionV1::reference);
        if self.administrative_resolution_head != expected_head {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if resolutions.is_empty() {
            return Ok(());
        }
        let (Some(scope), Some(obligation_set)) = (
            self.supporting_records.scope_commitment(),
            self.supporting_records.obligation_set(),
        ) else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        if resolutions.iter().any(|resolution| {
            (
                resolution.request(),
                resolution.scope_commitment(),
                resolution.policy(),
                resolution.trust(),
            ) != (
                self.request.reference(),
                scope.reference(),
                self.request.policy(),
                obligation_set.trust(),
            )
        }) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    pub(super) fn validate_terminal(
        &self,
        lifecycle: ErasureLifecycleV1,
        coordinator: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        if !matches!(
            lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            return Ok(());
        }
        let (Some(receipt), Some(receipt_input)) =
            (self.receipt.as_ref(), self.receipt_input.as_ref())
        else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let mut acknowledgements = self.acknowledgements.clone();
        acknowledgements.sort_unstable();
        ErasureReceiptV1::new(receipt_input.clone())
            .and_then(|reconstructed| {
                if (
                    receipt,
                    receipt.terminal_state(),
                    receipt.lifecycle(),
                    receipt.coordinator(),
                    receipt.replay_claim(),
                    receipt.0.request,
                    receipt.frozen_targets(),
                ) != (
                    &reconstructed,
                    self.state.state_digest(),
                    lifecycle,
                    coordinator,
                    self.state.replay_claim(),
                    self.request.reference(),
                    self.targets.as_slice(),
                ) {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                if receipt.acknowledgements().ne(acknowledgements.as_slice()) {
                    let active_retry = self.supporting_records.retry_admissions.len()
                        == self
                            .supporting_records
                            .attempt_outcomes
                            .len()
                            .saturating_add(1);
                    if !active_retry {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                }
                receipt.validate_frozen_obligations(self.supporting_records.obligations())
            })
            .and_then(|()| {
                let (pending, failed) = derived_outcome_owners_for_obligations(
                    self.supporting_records.obligations(),
                    receipt.acknowledgements(),
                );
                if (self.state.pending_owners(), self.state.failed_owners())
                    != (pending.as_slice(), failed.as_slice())
                {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                let (Some(outcome), Some(provenance)) = (
                    self.supporting_records.attempt_outcomes().last(),
                    self.supporting_records.receipt_provenance().last(),
                ) else {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                };
                if (
                    self.state.provenance(),
                    receipt.provenance(),
                    provenance.terminal_state(),
                ) != (
                    outcome.reference(),
                    provenance.reference(),
                    self.state.state_digest(),
                ) {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
                Ok(())
            })
    }

    pub(super) fn validate(&self, coordinator: ErasureReferenceV1) -> Result<(), ErasureErrorV1> {
        if (self.request.reference(), self.state.coordinator())
            != (self.state.request(), coordinator)
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let lifecycle = self.state.lifecycle();
        self.supporting_records
            .validate()
            .and_then(|()| {
                self.supporting_records
                    .validates_request(self.request.reference())
            })
            .and_then(|()| {
                if self
                    .supporting_records
                    .correction_provenance()
                    .is_some_and(|correction| self.request.provenance() != correction.reference())
                {
                    Err(ErasureErrorV1::ProvenanceMissing)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| self.validate_supporting_lifecycle(lifecycle))
            .and_then(|()| self.validate_scope())
            .and_then(|()| self.validate_lifecycle_shape(lifecycle))
            .and_then(|()| self.validate_frozen_evidence(lifecycle))
            .and_then(|()| self.validate_provenance(lifecycle))
            .and_then(|()| self.validate_administrative_resolution_head())
            .and_then(|()| self.validate_terminal(lifecycle, coordinator))
    }

    fn validate_supporting_lifecycle(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        self.validate_supporting_evidence_shape(lifecycle)
            .and_then(|()| self.validate_attempt_evidence_shape(lifecycle))
            .and_then(|()| {
                if matches!(
                    lifecycle,
                    ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
                ) && self.supporting_records.receipts().last() != self.receipt.as_ref()
                {
                    Err(ErasureErrorV1::ProvenanceMissing)
                } else {
                    Ok(())
                }
            })
    }

    pub(super) fn validate_supporting_evidence_shape(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        let scope = self.supporting_records.scope_commitment();
        let admission = self.supporting_records.freeze_admission_evidence();
        let freeze_authorization = self.supporting_records.freeze_authorization_evidence();
        let freeze = self.supporting_records.freeze_provenance();
        let failure = self.supporting_records.freeze_failure();
        let authorization_rejection = self.supporting_records.authorization_rejection();
        let obligation_set = self.supporting_records.obligation_set();
        match lifecycle {
            ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Authorized => {
                if (
                    scope.is_some(),
                    admission.is_some(),
                    freeze_authorization.is_some(),
                    freeze.is_some(),
                    failure.is_some(),
                    authorization_rejection.is_some(),
                    obligation_set.is_some(),
                ) != (false, false, false, false, false, false, false)
                {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
            }
            ErasureLifecycleV1::Rejected => {
                if let Some(failure) = failure {
                    let Some(authorization) = self.authorize_provenance else {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    };
                    if (
                        scope.is_some(),
                        admission.is_some(),
                        freeze_authorization.is_some(),
                        freeze.is_some(),
                        failure.authorization_provenance(),
                        self.state.provenance(),
                    ) != (
                        false,
                        false,
                        false,
                        false,
                        authorization,
                        failure.reference(),
                    ) || authorization_rejection.is_some()
                        || obligation_set.is_some()
                    {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                } else if let Some(rejection) = authorization_rejection {
                    if (
                        scope.is_some(),
                        admission.is_some(),
                        freeze_authorization.is_some(),
                        freeze.is_some(),
                        obligation_set.is_some(),
                        self.authorize_provenance,
                        rejection.request(),
                        self.state.provenance(),
                    ) != (
                        false,
                        false,
                        false,
                        false,
                        false,
                        None,
                        self.request.reference(),
                        rejection.reference(),
                    ) {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                } else {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            ErasureLifecycleV1::AccessFrozen
            | ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements
            | ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure => {
                if (
                    scope.is_some(),
                    admission.is_some(),
                    freeze_authorization.is_some(),
                    freeze.is_some(),
                    failure.is_some(),
                    authorization_rejection.is_some(),
                    obligation_set.is_some(),
                ) != (true, true, true, true, false, false, true)
                {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_attempt_evidence_shape(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        let has_attempt_evidence = !self.supporting_records.retry_admissions().is_empty();
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Submitted
                | ErasureLifecycleV1::Authorized
                | ErasureLifecycleV1::Rejected
        ) && has_attempt_evidence
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::AccessFrozen {
            let admissions = self.supporting_records.retry_admissions();
            let dispatch_intent_matches = match (self.dispatch_provenance, admissions) {
                (None, []) => true,
                (Some(provenance), [admission]) => provenance == admission.reference(),
                _ => false,
            };
            if !dispatch_intent_matches
                || !self
                    .supporting_records
                    .acknowledgement_provenance()
                    .is_empty()
                || !self.supporting_records.attempt_outcomes().is_empty()
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
        ) {
            let Some(admission) = self.supporting_records.retry_admissions().last() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            if self.state.provenance() != admission.reference()
                || self.dispatch_provenance != Some(admission.reference())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }
}
