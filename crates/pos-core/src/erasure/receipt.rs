use super::{
    acknowledgements_are_closure_subset, decode_limited, domain_digest, encode_canonical,
    encode_limited, exact_array, freeze_is_monotonic, has_duplicate,
    has_duplicate_acknowledgement_identity, invalid_owner_sets, inventories_are_within_closure,
    inventories_exceed_bound, inventories_have_duplicate_targets, inventory_categories_match,
    inventory_transitions_preserve_or_weaken, receipt_core_value, receipt_from_fields,
    receipt_value, reference_zero, sort_inventories, state_core_value, state_from_fields,
    state_value, verify_predecessor_chain, weakest_inventory_claim, BTreeMap, BTreeSet,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureErrorV1, ErasureLifecycleV1,
    ErasureObligationV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequiredTargetV1, ErasureStateResolverV1,
    ErasureStateTransitionV1, ErasureStateV1, Ordering, ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
    ERASURE_MAX_INVENTORY_RESULTS, ERASURE_MAX_OUTCOME_OWNERS, ERASURE_RECEIPT_MAX_BYTES,
    ERASURE_RECEIPT_TAG_V1, ERASURE_REQUEST_OR_STATE_MAX_BYTES, ERS1,
};

impl ErasureStateV1 {
    /// Create the initial submitted ERS1 state.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if its digest cannot be derived.
    pub fn submitted(
        request: ErasureReferenceV1,
        coordinator: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        Self {
            request,
            lifecycle: ErasureLifecycleV1::Submitted,
            freeze_position: None,
            coordinator,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            previous_state: None,
            provenance,
            state_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Return the current lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.lifecycle
    }
    /// Return the predecessor-link digest for the next state.
    #[must_use]
    pub const fn state_digest(&self) -> ErasureReferenceV1 {
        self.state_digest
    }
    /// Return the ERQ1 request digest bound to this state.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.request
    }
    /// Return the coordinator identity which authored this state.
    #[must_use]
    pub const fn coordinator(&self) -> ErasureReferenceV1 {
        self.coordinator
    }
    /// Return the provenance committed for this state transition.
    #[must_use]
    pub const fn provenance(&self) -> ErasureReferenceV1 {
        self.provenance
    }
    /// Return the frozen Tick Boundary, if access has been frozen.
    #[must_use]
    pub const fn freeze_position(&self) -> Option<u64> {
        self.freeze_position
    }
    /// Return the evidence-derived replay claim.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.replay_claim
    }
    /// Return the preceding ERS1 digest, if this is not the root state.
    #[must_use]
    pub const fn previous_state(&self) -> Option<ErasureReferenceV1> {
        self.previous_state
    }
    /// Verify that `previous` is the exact monotonic predecessor of this state.
    ///
    /// The check binds the request and coordinator identities, the lifecycle
    /// edge, the access-freeze position, the replay-claim weakening, and the
    /// content-addressed predecessor digest. Storage adapters use this same
    /// rule before accepting a durable state transition.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] when the predecessor is
    /// absent, mismatched, or violates the forward-only state contract.
    pub fn validate_predecessor(&self, previous: &Self) -> Result<(), ErasureErrorV1> {
        let Some(previous_digest) = self.previous_state else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let predecessor_is_valid = [
            previous.state_digest() == previous_digest,
            previous.request() == self.request(),
            previous.coordinator() == self.coordinator(),
            previous.lifecycle().permits(self.lifecycle()),
            freeze_is_monotonic(previous.freeze_position(), self.freeze_position()),
            previous
                .replay_claim()
                .preserves_or_weakens(self.replay_claim()),
        ]
        .into_iter()
        .all(|valid| valid);
        if predecessor_is_valid {
            Ok(())
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }
    /// Verify the complete bounded predecessor chain for this state.
    ///
    /// A decoded ERS1 state proves only its own digest and shape. Callers that
    /// load a state from durable storage must also resolve every predecessor
    /// back to the submitted root before treating the state as authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] when a predecessor is
    /// absent, malformed, mismatched, or deeper than the V1 history bound.
    pub fn verify_predecessor_chain<R: ErasureStateResolverV1>(
        &self,
        resolver: &R,
    ) -> Result<(), ErasureErrorV1> {
        verify_predecessor_chain(self.clone(), resolver)
    }
    /// Return owners whose required target has not positively acknowledged.
    #[must_use]
    pub fn pending_owners(&self) -> &[ErasureReferenceV1] {
        &self.pending_owners
    }
    /// Return owners whose acknowledgement is stale or negative.
    #[must_use]
    pub fn failed_owners(&self) -> &[ErasureReferenceV1] {
        &self.failed_owners
    }
    /// Advance exactly one permitted edge while preserving the freeze position.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a backward edge, changed freeze position,
    /// invalid owner evidence, or invalid terminal evidence.
    pub(crate) fn transition(
        &self,
        mut change: ErasureStateTransitionV1,
    ) -> Result<Self, ErasureErrorV1> {
        if !self.lifecycle.permits(change.lifecycle)
            || !freeze_is_monotonic(self.freeze_position, change.freeze_position)
            || !self.replay_claim.preserves_or_weakens(change.replay_claim)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if change.lifecycle == ErasureLifecycleV1::Complete
            && change.acknowledged_targets.is_empty()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        change.pending_owners.sort_unstable();
        change.failed_owners.sort_unstable();
        if invalid_owner_sets(&change.pending_owners, &change.failed_owners) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            request: self.request,
            lifecycle: change.lifecycle,
            freeze_position: change.freeze_position,
            coordinator: self.coordinator,
            pending_owners: change.pending_owners,
            failed_owners: change.failed_owners,
            replay_claim: change.replay_claim,
            previous_state: Some(self.state_digest),
            provenance: change.provenance,
            state_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Encode exact-length deterministic ERS1.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid evidence or a mismatched state digest.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.validate()
            .and_then(|()| self.clone().with_digest())
            .and_then(|expected| encode_canonical(&state_value(&expected)))
    }
    /// Decode ERS1 without accepting invented history.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed state, invalid evidence, or digest mismatch.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_REQUEST_OR_STATE_MAX_BYTES,
            ERASURE_MAX_OUTCOME_OWNERS,
        )
        .and_then(|value| exact_array(&value, 12).and_then(state_from_fields))
    }
    pub(super) fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        self.validate()
            .and_then(|()| encode_canonical(&state_core_value(&self)))
            .map(|bytes| {
                self.state_digest = ErasureReferenceV1::from_digest(domain_digest(ERS1, &bytes));
                self
            })
    }
    pub(super) fn validate(&self) -> Result<(), ErasureErrorV1> {
        if matches!(
            self.lifecycle,
            ErasureLifecycleV1::Submitted
                | ErasureLifecycleV1::Authorized
                | ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::Rejected
        ) && (!self.pending_owners.is_empty() || !self.failed_owners.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let needs_freeze = matches!(
            self.lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        );
        if needs_freeze != self.freeze_position.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if (self.lifecycle != ErasureLifecycleV1::Submitted) != self.previous_state.is_some() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if self.lifecycle == ErasureLifecycleV1::Complete
            && (!self.pending_owners.is_empty() || !self.failed_owners.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.lifecycle == ErasureLifecycleV1::PartialFailure
            && self.pending_owners.is_empty()
            && self.failed_owners.is_empty()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }
}

impl Ord for ErasureAcknowledgementV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.target,
            self.obligation,
            self.owner,
            self.evidence,
            self.outcome.code(),
        )
            .cmp(&(
                other.target,
                other.obligation,
                other.owner,
                other.evidence,
                other.outcome.code(),
            ))
    }
}
impl PartialOrd for ErasureAcknowledgementV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ErasureAcknowledgementOutcomeV1 {
    pub(super) const fn code(self) -> u64 {
        match self {
            Self::Acknowledged => 0,
            Self::Negative => 1,
            Self::Stale => 2,
        }
    }
    pub(super) const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Acknowledged),
            1 => Ok(Self::Negative),
            2 => Ok(Self::Stale),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

impl ErasureReceiptV1 {
    /// Return the ERQ1 digest bound into this receipt.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.0.request
    }

    /// Return the terminal outcome derived from the frozen closure.
    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.0.lifecycle
    }
    /// Return the weakest claim derived from the recorded inventory evidence.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.0.replay_claim
    }

    /// Return the frozen Tick Boundary position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.0.freeze_position
    }

    /// Return the policy revision admitted for this receipt.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.0.policy
    }

    /// Return the trust snapshot admitted for this receipt.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.0.trust
    }

    /// Return the logical position at which this receipt was issued.
    #[must_use]
    pub const fn issue_position(&self) -> u64 {
        self.0.issue_position
    }

    /// Return the signature or commitment digest admitted for this receipt.
    #[must_use]
    pub const fn signature(&self) -> ErasureReferenceV1 {
        self.0.signature
    }
    /// Validate ERC1 and normalize acknowledgement arrival order.
    ///
    /// # Errors
    ///
    /// Returns a closed error for incomplete or conflicting terminal evidence.
    pub fn new(mut input: ErasureReceiptInputV1) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            input.lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if input.acknowledgements.len() > ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT
            || input.frozen_targets.len() > ERASURE_MAX_INVENTORY_RESULTS
            || inventories_exceed_bound(&input.inventories)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if input.issue_position < input.freeze_position {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !inventory_transitions_preserve_or_weaken(&input.inventories) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        sort_inventories(&mut input.inventories);
        if !inventory_categories_match(&input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if inventories_have_duplicate_targets(&input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.acknowledgements.sort_unstable();
        input.frozen_targets.sort_unstable();
        input.pending_owners.sort_unstable();
        input.failed_owners.sort_unstable();
        if has_duplicate(&input.frozen_targets)
            || has_duplicate_acknowledgement_identity(&input.acknowledgements)
            || invalid_owner_sets(&input.pending_owners, &input.failed_owners)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&input.frozen_targets, &input.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_reference_inventory_entries(
            &input.inventories,
            &input.acknowledgements,
        ) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let (derived_pending, derived_failed) =
            derived_inventory_outcome_owners(&input.inventories, &input.acknowledgements);
        if input.pending_owners != derived_pending || input.failed_owners != derived_failed {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !inventories_are_within_closure(&input.frozen_targets, &input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        // The caller's claim is descriptive input only.  ERC1 records the
        // weakest claim disclosed by the per-artifact transitions.
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        let complete =
            acknowledgements_cover_inventory_entries(&input.inventories, &input.acknowledgements)
                && input
                    .acknowledgements
                    .iter()
                    .all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let unresolved =
            !complete || !input.pending_owners.is_empty() || !input.failed_owners.is_empty();
        if input.lifecycle == ErasureLifecycleV1::Complete && !complete {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if input.lifecycle == ErasureLifecycleV1::PartialFailure && !unresolved {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        input.receipt_digest = reference_zero();
        Self(input).with_digest()
    }
    /// Encode exact-length deterministic ERC1.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if canonical serialization fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.clone().with_digest().and_then(|expected| {
            encode_limited(&receipt_value(&expected.0), ERASURE_RECEIPT_MAX_BYTES)
        })
    }
    /// Decode ERC1 structural evidence; call [`Self::verify_history`] to verify ERS1 ancestry.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or conflicting evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_RECEIPT_MAX_BYTES,
            ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
        )
        .and_then(|value| exact_array(&value, 19).and_then(receipt_from_fields))
    }
    /// Return the terminal ERS1 digest bound into this receipt.
    #[must_use]
    pub const fn terminal_state(&self) -> ErasureReferenceV1 {
        self.0.terminal_state
    }
    /// Return the coordinator identity bound into this receipt.
    #[must_use]
    pub const fn coordinator(&self) -> ErasureReferenceV1 {
        self.0.coordinator
    }
    /// Return the derived receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> ErasureReferenceV1 {
        self.0.receipt_digest
    }
    /// Return the canonical receipt-provenance address.
    #[must_use]
    pub const fn provenance(&self) -> ErasureReferenceV1 {
        self.0.provenance
    }
    /// Return the frozen target closure.
    #[must_use]
    pub fn frozen_targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.0.frozen_targets
    }
    /// Return the canonical acknowledgement closure.
    #[must_use]
    pub fn acknowledgements(&self) -> &[ErasureAcknowledgementV1] {
        &self.0.acknowledgements
    }
    /// Return the four canonical independently owned evidence inventories.
    #[must_use]
    pub const fn inventories(&self) -> &ErasureReceiptInventoriesV1 {
        &self.0.inventories
    }

    /// Validate that this receipt closes the exact frozen obligation set.
    ///
    /// A standalone ERC1 decoder cannot know the policy-selected applicability
    /// matrix; the durable coordinator invokes this public check once it has
    /// recovered the frozen `ERO1` objects and `EROS1` set.
    ///
    /// # Errors
    ///
    /// Returns a closed error for missing, extraneous, or wrong-owner category
    /// evidence, or for a lifecycle inconsistent with the exact closure.
    pub fn validate_frozen_obligations(
        &self,
        obligations: &[ErasureObligationV1],
    ) -> Result<(), ErasureErrorV1> {
        if !inventories_match_frozen_obligations(&self.0.inventories, obligations) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let (pending, failed) =
            derived_outcome_owners_for_obligations(obligations, &self.0.acknowledgements);
        if self.0.pending_owners != pending || self.0.failed_owners != failed {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }
    /// Verify terminal binding and the bounded ERS1 predecessor chain via a host resolver.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance or policy error when the resolver cannot prove the chain.
    pub fn verify_history<R: ErasureStateResolverV1>(
        &self,
        resolver: &R,
    ) -> Result<(), ErasureErrorV1> {
        match resolver.resolve_state(self.terminal_state()) {
            Ok(Some(terminal)) => {
                let matches_receipt = terminal.request() == self.0.request
                    && terminal.state_digest() == self.terminal_state()
                    && terminal.coordinator() == self.0.coordinator
                    && terminal.lifecycle() == self.0.lifecycle
                    && terminal.freeze_position() == Some(self.0.freeze_position)
                    && terminal.replay_claim() == self.0.replay_claim;
                if !matches_receipt {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                verify_predecessor_chain(terminal, resolver)
            }
            Ok(None) => Err(ErasureErrorV1::ProvenanceMissing),
            Err(error) => Err(error),
        }
    }
    pub(super) fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        encode_limited(&receipt_core_value(&self.0), ERASURE_RECEIPT_MAX_BYTES).map(|bytes| {
            self.0.receipt_digest =
                ErasureReferenceV1::from_digest(domain_digest(ERASURE_RECEIPT_TAG_V1, &bytes));
            self
        })
    }
}

pub(super) fn derived_inventory_outcome_owners(
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> (Vec<ErasureReferenceV1>, Vec<ErasureReferenceV1>) {
    let mut outcomes = BTreeMap::new();
    for acknowledgement in acknowledgements {
        let flags = outcomes
            .entry((acknowledgement.target, acknowledgement.owner))
            .or_insert((false, false));
        flags.0 = true;
        flags.1 |= acknowledgement.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged;
    }
    let mut pending = Vec::new();
    let mut failed = Vec::new();
    for entry in [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    {
        let (saw_acknowledgement, saw_non_positive) = outcomes
            .get(&(entry.target, entry.transition.owner))
            .copied()
            .unwrap_or((false, false));
        if !saw_acknowledgement {
            pending.push(entry.transition.owner);
        } else if saw_non_positive {
            failed.push(entry.transition.owner);
        }
    }
    pending.sort_unstable();
    pending.dedup();
    failed.sort_unstable();
    failed.dedup();
    pending.retain(|owner| failed.binary_search(owner).is_err());
    (pending, failed)
}

pub(super) fn acknowledgements_cover_inventory_entries(
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    let mut inventory_pairs = [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| (entry.target, entry.transition.owner))
    .collect::<Vec<_>>();
    let mut acknowledgement_pairs = acknowledgements
        .iter()
        .map(|acknowledgement| (acknowledgement.target, acknowledgement.owner))
        .collect::<Vec<_>>();
    inventory_pairs.sort_unstable();
    acknowledgement_pairs.sort_unstable();
    inventory_pairs == acknowledgement_pairs
}

pub(super) fn acknowledgements_reference_inventory_entries(
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    let inventory_pairs = [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| (entry.target, entry.transition.owner))
    .collect::<BTreeSet<_>>();
    acknowledgements.iter().all(|acknowledgement| {
        inventory_pairs.contains(&(acknowledgement.target, acknowledgement.owner))
    })
}

pub(super) fn inventories_match_frozen_obligations(
    inventories: &ErasureReceiptInventoriesV1,
    obligations: &[ErasureObligationV1],
) -> bool {
    let mut inventory_pairs = [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| (entry.category, entry.target, entry.transition.owner))
    .collect::<Vec<_>>();
    let mut obligation_pairs = obligations
        .iter()
        .map(|obligation| {
            (
                obligation.category(),
                obligation.target(),
                obligation.owner(),
            )
        })
        .collect::<Vec<_>>();
    inventory_pairs.sort_unstable();
    obligation_pairs.sort_unstable();
    inventory_pairs == obligation_pairs
}

pub(super) fn acknowledgements_close_frozen_obligations(
    acknowledgements: &[ErasureAcknowledgementV1],
    obligations: &[ErasureObligationV1],
) -> bool {
    let mut acknowledgement_closure = acknowledgements
        .iter()
        .map(|acknowledgement| {
            (
                acknowledgement.obligation,
                acknowledgement.target,
                acknowledgement.owner,
                acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged,
            )
        })
        .collect::<Vec<_>>();
    let mut obligation_closure = obligations
        .iter()
        .map(|obligation| {
            (
                obligation.reference(),
                obligation.target(),
                obligation.owner(),
                true,
            )
        })
        .collect::<Vec<_>>();
    acknowledgement_closure.sort_unstable();
    obligation_closure.sort_unstable();
    acknowledgement_closure == obligation_closure
}

pub(super) fn derived_outcome_owners_for_obligations(
    obligations: &[ErasureObligationV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> (Vec<ErasureReferenceV1>, Vec<ErasureReferenceV1>) {
    let acknowledged = acknowledgements
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
        })
        .map(|acknowledgement| (acknowledgement.obligation, acknowledgement.owner))
        .collect::<BTreeSet<_>>();
    let mut pending = obligations
        .iter()
        .filter(|obligation| !acknowledged.contains(&(obligation.reference(), obligation.owner())))
        .map(ErasureObligationV1::owner)
        .collect::<Vec<_>>();
    let mut failed = acknowledgements
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged
        })
        .map(|acknowledgement| acknowledgement.owner)
        .collect::<Vec<_>>();
    pending.sort_unstable();
    pending.dedup();
    failed.sort_unstable();
    failed.dedup();
    pending.retain(|owner| failed.binary_search(owner).is_err());
    (pending, failed)
}

/// Compute the canonical digest for an exact sorted freeze target closure.
///
/// The caller must provide the closure in the canonical order returned by the
/// coordinator after sorting and duplicate rejection.  The digest binds every
/// target coordinate used by ERQ1/ERS1 freeze admission.
#[must_use]
pub fn target_closure_digest(targets: &[ErasureRequiredTargetV1]) -> ErasureReferenceV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/erasure-freeze-closure/v1");
    for target in targets {
        hasher.update(&target.artifact_class.code().to_be_bytes());
        hasher.update(&target.artifact_digest.digest());
        hasher.update(&target.key_role.code().to_be_bytes());
        hasher.update(&target.key_digest.digest());
        hasher.update(&target.replica_set.digest());
        hasher.update(&target.replica_id.digest());
    }
    ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
}
