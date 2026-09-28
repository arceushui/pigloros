#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-state` — projection layer over the `pos-core` primitives.
//!
//! Provides:
//! - [`ProjectionRegistry`]: a named registry of [`Reducer`] implementations.
//! - [`EntityStateProjection`]: a built-in `Reducer` that folds event metadata per entity.
//! - [`RelationshipIndex`]: an adjacency index for directed [`Relationship`] values.
//!
//! No I/O, no async.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use std::{collections::HashMap, sync::Arc};

use pos_core::{
    AuthorityErrorV1, AuthorityEvaluatorV1, AuthorityRegistrySnapshotV1, AuthorizationDecisionV1,
    AuthorizationRequestV1, CanonicalBytes, ConsentEvidenceV1, ConsentRevocationFoldListener,
    ConsentRevokedV1, EntityId, ErasureContainmentGateV1, ErasureGate, ErasureProtectedOperationV1,
    ErasureReferenceV1, Event, Hash, ObservationArtifactV1, ObservationRecordDraftV1,
    ObservationRecordV1, ObservationSnapshotDraftV1, ObservationSnapshotV1, ObservationStatusV1,
    PersistedAuthorityV1, PluginId, Reducer, Relationship, Seq, State, StateRegistry, TimelineId,
    WallTime, EVENT_TYPE_CONSENT_REVOKED_V1, MAX_OBSERVATION_SNAPSHOT_RECORDS,
};

// ---------------------------------------------------------------------------
// EntityStateProjection
// ---------------------------------------------------------------------------

/// A [`Reducer`] that folds each event into minimal per-entity state.
///
/// After each event the state contains:
/// - `"last_event_type"`: the event-type string of the most-recent event.
/// - `"event_count"`: the running count of events applied to this entity.
#[derive(Clone, Debug, Default)]
pub struct EntityStateProjection;

impl Reducer for EntityStateProjection {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        // Increment event counter.
        let count = state
            .get("event_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("event_count", serde_json::Value::Number((count + 1).into()));
        // Record the event type.
        state.set(
            "last_event_type",
            serde_json::Value::String(event.event_type.as_str().to_owned()),
        );
    }
}

// ---------------------------------------------------------------------------
// ProjectionRegistry
// ---------------------------------------------------------------------------

/// Rejection before an installed reducer slot is mutated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionSlotErrorV1 {
    /// A display name is empty or exceeds the canonical text bound.
    InvalidName,
    /// The stable Plugin identity already owns a slot.
    DuplicatePluginId { plugin_id: PluginId },
}

/// One named slot inside the registry.
struct Slot {
    plugin_id: Option<PluginId>,
    reducer: Box<dyn Reducer>,
    registry: StateRegistry,
    observation_policy: Option<ProjectionObservationPolicyV1>,
}

/// A named registry of [`Reducer`] implementations backed by per-name [`StateRegistry`]s.
///
/// Plugins register reducers during Wave 3 initialisation; the registry then
/// applies every incoming event to every registered reducer in insertion order.
pub struct ProjectionRegistry {
    /// Ordered list so iteration is deterministic.
    slots: Vec<(String, Slot)>,
    /// Host-owned erasure gate for protected projection materialization.
    erasure_gate: Option<Arc<dyn ErasureGate>>,
    /// Whether the current gate was supplied by the host composition root.
    /// The constructor's fail-closed gate can be replaced exactly once.
    erasure_gate_bound: bool,
    source_timeline: Option<TimelineId>,
    source_generation: Option<ErasureReferenceV1>,
    mixed_sources: bool,
    /// Nesting depth for state transactions, used to retain privacy effects
    /// when a later protected-use check rolls ordinary state back.
    state_transaction_depth: usize,
    /// Consent revocations observed by active state transactions.
    transaction_revocations: Vec<EntityId>,
}

impl Default for ProjectionRegistry {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            erasure_gate: Some(Arc::new(ErasureContainmentGateV1::new_fail_closed())),
            erasure_gate_bound: false,
            source_timeline: None,
            source_generation: None,
            mixed_sources: false,
            state_transaction_depth: 0,
            transaction_revocations: Vec::new(),
        }
    }
}

impl std::fmt::Debug for ProjectionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = Vec::with_capacity(self.slots.len());
        for (name, _) in &self.slots {
            names.push(name.as_str());
        }
        f.debug_struct("ProjectionRegistry")
            .field("reducers", &names)
            .finish_non_exhaustive()
    }
}

impl ProjectionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the host-owned erasure gate used by protected observations.
    #[must_use]
    pub fn with_erasure_gate(mut self, gate: Arc<dyn ErasureGate>) -> Self {
        self.bind_erasure_gate(gate);
        self
    }

    /// Bind the host-owned erasure gate in place.
    pub fn bind_erasure_gate(&mut self, gate: Arc<dyn ErasureGate>) {
        if self.erasure_gate_bound {
            return;
        }
        self.erasure_gate = Some(gate);
        self.erasure_gate_bound = true;
    }

    /// Return the host-bound erasure gate, when this registry has one.
    #[must_use]
    pub fn clone_erasure_gate(&self) -> Option<Arc<dyn ErasureGate>> {
        self.erasure_gate_bound
            .then_some(self.erasure_gate.clone())
            .flatten()
    }

    /// Remove the erasure gate so protected observations fail closed.
    #[must_use]
    pub fn without_erasure_gate(mut self) -> Self {
        self.erasure_gate = None;
        self
    }

    fn with_erasure_fence<T>(
        &self,
        timeline: TimelineId,
        mut effect: impl FnMut(&Self) -> Result<T, AuthorityErrorV1>,
    ) -> Result<T, AuthorityErrorV1> {
        let gate = self
            .erasure_gate
            .as_ref()
            .filter(|_| self.source_matches_timeline(timeline))
            .ok_or(AuthorityErrorV1::SourceUnavailable)?;
        let mut result = Err(AuthorityErrorV1::SourceUnavailable);
        let mut run = || {
            result = self.apply_if_current_generation(gate.as_ref(), &mut effect);
        };
        gate.with_fence(timeline, ErasureProtectedOperationV1::Snapshot, &mut run)
            .map_err(|_| AuthorityErrorV1::SourceUnavailable)?;
        result
    }

    fn source_matches_timeline(&self, timeline: TimelineId) -> bool {
        !self.mixed_sources && self.source_timeline.is_none_or(|source| source == timeline)
    }

    fn source_generation_is_current(&self, gate: &dyn ErasureGate) -> bool {
        self.source_timeline.is_none() || self.source_generation == gate.inventory_generation().ok()
    }

    fn apply_if_current_generation<T>(
        &self,
        gate: &dyn ErasureGate,
        effect: &mut impl FnMut(&Self) -> Result<T, AuthorityErrorV1>,
    ) -> Result<T, AuthorityErrorV1> {
        if self.source_generation_is_current(gate) {
            effect(self)
        } else {
            Err(AuthorityErrorV1::SourceUnavailable)
        }
    }

    /// Verify that accumulated state still belongs to this Timeline and the
    /// currently installed inventory generation before a Fork can inherit it.
    ///
    /// # Errors
    /// Returns a closed source error for a stale, mixed, or unavailable source.
    pub fn validate_fork_source(&self, timeline: TimelineId) -> Result<(), AuthorityErrorV1> {
        self.with_erasure_fence(timeline, |_| Ok(()))
    }

    /// Register a named reducer.
    ///
    /// If a reducer with the same name was already registered it is replaced and
    /// its accumulated state is cleared.
    pub fn register(&mut self, name: &str, reducer: Box<dyn Reducer>) {
        self.register_with_policy(name, reducer, None);
    }

    /// Register a named reducer with immutable host observation policy.
    ///
    /// # Errors
    /// Returns a closed validation error when the policy is incomplete or
    /// noncanonical.
    pub fn register_observable(
        &mut self,
        name: &str,
        reducer: Box<dyn Reducer>,
        policy: ProjectionObservationPolicyV1,
    ) -> Result<(), AuthorityErrorV1> {
        if name.is_empty() || name.len() > pos_core::MAX_AUTHORITY_TEXT_BYTES {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        self.register_with_policy(name, reducer, Some(policy));
        Ok(())
    }

    fn register_with_policy(
        &mut self,
        name: &str,
        reducer: Box<dyn Reducer>,
        observation_policy: Option<ProjectionObservationPolicyV1>,
    ) {
        self.slots
            .retain(|(registered, slot)| registered != name || slot.plugin_id.is_some());
        self.slots.push((
            name.to_owned(),
            Slot {
                plugin_id: None,
                reducer,
                registry: StateRegistry::new(),
                observation_policy,
            },
        ));
    }

    /// Register an installed reducer under its stable Plugin identity.
    /// Display names may coincide; they are never used as installed slot keys.
    ///
    /// # Errors
    /// Rejects an invalid name or duplicate Plugin identity before mutation.
    pub fn register_installed_reducer(
        &mut self,
        plugin_id: PluginId,
        name: &str,
        reducer: Box<dyn Reducer>,
    ) -> Result<(), ProjectionSlotErrorV1> {
        if name.is_empty() || name.len() > pos_core::MAX_AUTHORITY_TEXT_BYTES {
            return Err(ProjectionSlotErrorV1::InvalidName);
        }
        if self
            .slots
            .iter()
            .any(|(_, slot)| slot.plugin_id == Some(plugin_id))
        {
            return Err(ProjectionSlotErrorV1::DuplicatePluginId { plugin_id });
        }
        self.slots.push((
            name.to_owned(),
            Slot {
                plugin_id: Some(plugin_id),
                reducer,
                registry: StateRegistry::new(),
                observation_policy: None,
            },
        ));
        Ok(())
    }

    /// Apply one Event from its host-identified Timeline to every registered
    /// reducer. Mixing Timelines invalidates accumulated state until reset.
    pub fn apply_event(&mut self, timeline: TimelineId, event: &Event) {
        if !self.bind_event_source(timeline) {
            return;
        }
        self.apply_bound_event(event);
    }

    fn apply_bound_event(&mut self, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_CONSENT_REVOKED_V1 {
            if let Ok(revocation) = ConsentRevokedV1::decode(&event.payload) {
                self.on_consent_revoked(revocation.subject_id, revocation.fence_seq);
            }
            return;
        }
        // Consent is host control-plane state.  It is never reducer input and
        // therefore cannot become a Plugin-visible projection or snapshot.
        if pos_core::is_consent_event_type(&event.event_type) {
            return;
        }
        if pos_core::is_geographic_event_type(&event.event_type) {
            return;
        }
        for (_, slot) in &mut self.slots {
            slot.registry.apply(slot.reducer.as_ref(), event);
        }
    }

    fn bind_event_source(&mut self, timeline: TimelineId) -> bool {
        if self.mixed_sources {
            return false;
        }
        let generation = self
            .erasure_gate
            .as_ref()
            .and_then(|gate| gate.inventory_generation().ok());
        if self.source_timeline.is_some() && self.source_generation != generation {
            self.clear_state();
            self.mixed_sources = true;
            return false;
        }
        match self.source_timeline {
            Some(source) if source != timeline => {
                self.clear_state();
                self.mixed_sources = true;
                return false;
            }
            None => {
                self.source_timeline = Some(timeline);
                self.source_generation = generation;
            }
            Some(_) => {}
        }
        true
    }

    /// Batch-fold Events from one host-identified Timeline into every reducer.
    pub fn fold_events(&mut self, timeline: TimelineId, events: &[Event]) {
        for event in events {
            self.apply_event(timeline, event);
        }
    }

    /// Rebuild state from one host-captured Timeline prefix under its current
    /// containment fence after the inventory generation changes.
    ///
    /// # Errors
    /// Returns a closed source error when the Timeline cannot be authorized.
    pub fn refold_events(
        &mut self,
        timeline: TimelineId,
        events: &[Event],
        expected_generation: Option<ErasureReferenceV1>,
    ) -> Result<(), AuthorityErrorV1> {
        let gate = self
            .erasure_gate
            .as_ref()
            .map(Arc::clone)
            .ok_or(AuthorityErrorV1::SourceUnavailable)?;
        let mut refolded = false;
        let mut refold = || {
            if gate.inventory_generation().ok() == expected_generation {
                self.clear_state();
                self.fold_events(timeline, events);
                refolded = !self.mixed_sources;
            }
        };
        gate.with_fence(timeline, ErasureProtectedOperationV1::Snapshot, &mut refold)
            .map_err(|_| AuthorityErrorV1::SourceUnavailable)?;
        refolded
            .then_some(())
            .ok_or(AuthorityErrorV1::SourceUnavailable)
    }

    /// Rebind a restored parent projection only after its child Fork has been
    /// committed and installed by the host. The child containment proof is
    /// checked before the inherited state can be exposed under that identity.
    ///
    /// # Errors
    /// Returns a closed source error for mixed or mismatched input or when the
    /// committed child is not available in the current host gate.
    pub fn adopt_committed_fork(
        &mut self,
        parent: TimelineId,
        child: TimelineId,
    ) -> Result<(), AuthorityErrorV1> {
        if self.mixed_sources || self.source_timeline.is_some_and(|source| source != parent) {
            return Err(AuthorityErrorV1::SourceUnavailable);
        }
        self.erasure_gate
            .as_ref()
            .map(Arc::clone)
            .ok_or(AuthorityErrorV1::SourceUnavailable)
            .and_then(|gate| {
                let mut bind = || {
                    self.source_timeline = Some(child);
                    self.source_generation = gate.inventory_generation().ok();
                };
                gate.with_fence(child, ErasureProtectedOperationV1::Fork, &mut bind)
                    .map_err(|_| AuthorityErrorV1::SourceUnavailable)
            })
    }

    /// Return owned state for an entity from the **first** registered reducer
    /// while the current Timeline fence is held.
    ///
    /// Returns `None` if no reducers have been registered or the entity is unknown.
    /// To query a specific reducer use [`Self::state_for_reducer`].
    /// # Errors
    /// Returns a closed source error when the Timeline has no verified access.
    pub fn state_for(
        &self,
        timeline: TimelineId,
        entity: &EntityId,
    ) -> Result<Option<State>, AuthorityErrorV1> {
        self.with_erasure_fence(timeline, |registry| {
            Ok(registry
                .slots
                .first()
                .and_then(|(_, slot)| slot.registry.get(entity))
                .cloned())
        })
    }

    /// Return owned state for an entity from the named reducer while the
    /// current Timeline fence is held.
    ///
    /// # Errors
    /// Returns a closed source error when the Timeline has no verified access.
    pub fn state_for_reducer(
        &self,
        timeline: TimelineId,
        name: &str,
        entity: &EntityId,
    ) -> Result<Option<State>, AuthorityErrorV1> {
        self.with_erasure_fence(timeline, |registry| {
            let mut matches = registry.slots.iter().filter(|(n, _)| n == name);
            Ok(matches
                .next()
                .filter(|_| matches.next().is_none())
                .and_then(|(_, slot)| slot.registry.get(entity))
                .cloned())
        })
    }

    /// Return state from one installed Plugin's reducer slot.
    #[must_use]
    pub fn state_for_plugin(&self, plugin_id: PluginId, entity: &EntityId) -> Option<&State> {
        self.slots
            .iter()
            .find(|(_, slot)| slot.plugin_id == Some(plugin_id))
            .and_then(|(_, slot)| slot.registry.get(entity))
    }

    /// Materialize exactly one host-authorized participant observation.
    ///
    /// Authorization is validated before projection lookup. The returned OBS1
    /// owns only canonical value bytes and provenance; it exposes neither this
    /// registry nor a `State`/`Event` handle. State for every other subject and
    /// reducer is therefore outside the derivation's data dependencies.
    ///
    /// # Errors
    /// Returns a closed authority error when the decision is denied, does not
    /// exactly bind the request, lacks participant/Plugin installation identity,
    /// or the requested materialization cannot form a valid bounded OBS1.
    pub fn materialize_authorized_observation(
        &self,
        request: &AuthorizationRequestV1,
        decision: &AuthorizationDecisionV1,
        authority: &PersistedAuthorityV1,
        authority_registry: &AuthorityRegistrySnapshotV1,
        authority_position: Seq,
        context: &ProjectionObservationContextV1,
    ) -> Result<AuthorizedObservationV1, AuthorityErrorV1> {
        self.with_erasure_fence(context.timeline_id, |registry| {
            authority
                .validate_observation_authorization(
                    request,
                    decision,
                    authority_registry,
                    authority_position,
                )
                .and_then(|()| {
                    registry.materialize_authorized_projection(request, decision, context)
                })
                .map(|snapshot| {
                    let artifact_digest = snapshot.provenance_digest();
                    AuthorizedObservationV1 {
                        snapshot,
                        artifact_digest,
                        request: request.clone(),
                        decision: decision.clone(),
                    }
                })
        })
    }

    fn unique_observation_slot_for_plugin(&self, name: &str, plugin_id: PluginId) -> Option<&Slot> {
        let mut matches = self.slots.iter().filter(|(registered, slot)| {
            registered == name && slot.plugin_id.is_none_or(|id| id == plugin_id)
        });
        matches
            .next()
            .filter(|_| matches.next().is_none())
            .map(|(_, slot)| slot)
    }

    fn materialize_authorized_projection(
        &self,
        request: &AuthorizationRequestV1,
        decision: &AuthorizationDecisionV1,
        context: &ProjectionObservationContextV1,
    ) -> Result<ObservationSnapshotV1, AuthorityErrorV1> {
        if context.reducer.is_empty() || context.reducer.len() > pos_core::MAX_AUTHORITY_TEXT_BYTES
        {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        if request.resource().strip_prefix("projection.") != Some(context.reducer.as_str()) {
            return Err(AuthorityErrorV1::UnauthorizedSource);
        }
        let Some(subject_id) = request.subject_id() else {
            return Err(AuthorityErrorV1::ConsentMissing);
        };
        let Some(participant_id) = request.participant_id() else {
            return Err(AuthorityErrorV1::UnauthorizedSource);
        };
        let Some((plugin_id, installation_id)) = request.plugin_id().zip(request.installation_id())
        else {
            return Err(AuthorityErrorV1::UnauthorizedSource);
        };
        let Some(slot) = self.unique_observation_slot_for_plugin(&context.reducer, plugin_id)
        else {
            return Err(AuthorityErrorV1::SourceUnavailable);
        };
        let Some(policy) = slot.observation_policy.as_ref() else {
            return Err(AuthorityErrorV1::UnauthorizedSource);
        };
        slot.registry
            .get(&subject_id)
            .map(|state| canonical_state_artifact(state, policy.permitted_fields()))
            .transpose()
            .and_then(|artifact| {
                let (status, artifact_digest, projection_digest, source_digest, artifacts) =
                    artifact.map_or_else(
                        || {
                            (
                                ObservationStatusV1::NotObserved,
                                None,
                                None,
                                absence_source_digest(context, subject_id),
                                Vec::new(),
                            )
                        },
                        |artifact| {
                            let digest = artifact.digest();
                            (
                                ObservationStatusV1::Present,
                                Some(digest),
                                Some(digest),
                                digest,
                                vec![artifact],
                            )
                        },
                    );
                ObservationRecordV1::try_from_draft(ObservationRecordDraftV1 {
                    participant_id,
                    resource: request.resource().to_owned(),
                    data_category: request.data_category().to_owned(),
                    status,
                    artifact_digest,
                    source_timeline: context.timeline_id,
                    source_position: context.observed_through,
                    schema: policy.schema().to_owned(),
                    source_digest,
                    projection_digest,
                    provenance_digest: policy.digest(),
                    minimization_revision: policy.minimization_revision(),
                })
                .and_then(|record| {
                    ObservationSnapshotV1::try_from_draft(ObservationSnapshotDraftV1 {
                        principal: decision.principal().clone(),
                        participant_id,
                        plugin_id,
                        installation_id,
                        timeline_id: context.timeline_id,
                        observed_through: context.observed_through,
                        authority_timeline: decision.authority_timeline(),
                        authority_position: decision.at_position(),
                        authorization_request_digest: request.binding_digest(),
                        authorization_decision_digest: decision.decision_digest(),
                        grant_chain_bindings: decision.grant_chain_bindings().to_vec(),
                        consent_policy_revision: decision.consent_policy_revision(),
                        capability_policy_revision: decision.capability_policy_revision(),
                        revocation_epoch: request.revocation_epoch(),
                        visibility_policy_revision: policy.visibility_policy_revision(),
                        schema_revision: policy.schema_revision(),
                        minimization_revision: policy.minimization_revision(),
                        records: vec![record],
                        artifacts,
                        prior_snapshot_digest: context.prior_snapshot_digest,
                        provenance_digest: policy.digest(),
                    })
                })
            })
    }

    /// Return the names of all registered reducers in insertion order.
    #[must_use]
    pub fn reducer_names(&self) -> Vec<&str> {
        let mut names = Vec::with_capacity(self.slots.len());
        for (name, _) in &self.slots {
            names.push(name.as_str());
        }
        names
    }

    /// Reset all accumulated state back to empty.
    ///
    /// Registered reducers are kept; only the per-entity state accumulation is
    /// cleared. This is equivalent to calling [`Self::register`] for every
    /// reducer again but preserving insertion order.
    pub fn clear_state(&mut self) {
        for (_, slot) in &mut self.slots {
            slot.registry = StateRegistry::new();
        }
        self.source_timeline = None;
        self.source_generation = None;
        self.mixed_sources = false;
    }

    /// Run an operation, restoring accumulated state maps when it fails.
    ///
    /// This does not isolate protected Replay or Snapshot candidates. Reducer
    /// registrations, reducer internals, policies, and external effects are not
    /// rolled back; an owner-controlled private candidate is still required
    /// before releasing protected results.
    ///
    /// # Errors
    ///
    /// Returns the error produced by `operation` after restoring the original
    /// accumulated state.
    pub fn try_with_state_transaction<T, E>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut before: HashMap<(String, Option<PluginId>), StateRegistry> = self
            .slots
            .iter()
            .map(|(name, slot)| ((name.clone(), slot.plugin_id), slot.registry.clone()))
            .collect();
        let before_source = (
            self.source_timeline,
            self.source_generation,
            self.mixed_sources,
        );
        let revocation_checkpoint = self.transaction_revocations.len();
        let outermost = self.state_transaction_depth == 0;
        self.state_transaction_depth += 1;
        let outcome = operation(self);
        self.state_transaction_depth -= 1;
        match outcome {
            Ok(value) => {
                if outermost {
                    self.transaction_revocations.clear();
                }
                Ok(value)
            }
            Err(error) => {
                let revoked_subjects =
                    self.transaction_revocations[revocation_checkpoint..].to_vec();
                for (name, slot) in &mut self.slots {
                    slot.registry = before
                        .remove(&(name.clone(), slot.plugin_id))
                        .unwrap_or_default();
                }
                (
                    self.source_timeline,
                    self.source_generation,
                    self.mixed_sources,
                ) = before_source;
                for subject in revoked_subjects {
                    self.forget_subject(&subject);
                }
                if outermost {
                    self.transaction_revocations.clear();
                }
                Err(error)
            }
        }
    }

    /// Retain only one subject's accumulated state in every reducer.
    pub fn retain_subject(&mut self, subject: &EntityId) {
        for (_, slot) in &mut self.slots {
            slot.registry.retain_only(subject);
        }
    }

    fn forget_subject(&mut self, subject: &EntityId) {
        for (_, slot) in &mut self.slots {
            slot.registry.remove(subject);
        }
    }

    /// Restore accumulated state from a previously captured snapshot map.
    ///
    /// Replaces each registered reducer's accumulated state with its matching
    /// [`StateRegistry`] from `snapshot`, or an empty registry when absent.
    /// Snapshot entries for unregistered reducers are ignored.
    ///
    /// This is the counterpart of [`Self::state_snapshot`] and is used by
    /// `pos-time` snapshot consistency verification to seed the incremental path.
    /// The caller must preserve the source Timeline and captured generation
    /// from the host-held snapshot. State is installed only while that exact
    /// generation is current and the Timeline snapshot fence is held.
    ///
    /// # Errors
    /// Returns a closed source error when the generation is stale or the
    /// Timeline snapshot fence is unavailable or reducer names are ambiguous.
    pub fn restore_from_snapshot(
        &mut self,
        timeline: TimelineId,
        snapshot: &std::collections::HashMap<String, StateRegistry>,
        expected_generation: Option<ErasureReferenceV1>,
    ) -> Result<(), AuthorityErrorV1> {
        if self.has_duplicate_names() {
            return Err(AuthorityErrorV1::SourceUnavailable);
        }
        let gate = self
            .erasure_gate
            .as_ref()
            .map(Arc::clone)
            .ok_or(AuthorityErrorV1::SourceUnavailable)?;
        let mut restored = false;
        let mut install = || {
            let current_generation = gate.inventory_generation().ok();
            if current_generation == expected_generation {
                self.clear_state();
                self.source_timeline = Some(timeline);
                self.source_generation = current_generation;
                for (name, slot) in &mut self.slots {
                    // Missing snapshot entries stay empty after `clear_state`.
                    if let Some(state) = snapshot.get(name) {
                        slot.registry = state.clone();
                    }
                }
                restored = true;
            }
        };
        gate.with_fence(
            timeline,
            ErasureProtectedOperationV1::Snapshot,
            &mut install,
        )
        .map_err(|_| AuthorityErrorV1::SourceUnavailable)?;
        restored
            .then_some(())
            .ok_or(AuthorityErrorV1::SourceUnavailable)
    }

    /// Materialize a snapshot of all per-reducer state inside the current
    /// Timeline containment fence.
    ///
    /// The returned map is keyed by reducer name and contains each reducer's
    /// accumulated [`StateRegistry`]. This is used by `pos-time` snapshot
    /// capture and consistency verification.
    ///
    /// # Errors
    /// Returns a closed source error when the host-owned gate is absent,
    /// poisoned, stale, or denies snapshot materialization for `timeline`.
    pub fn state_snapshot(
        &self,
        timeline: TimelineId,
    ) -> Result<std::collections::HashMap<String, StateRegistry>, AuthorityErrorV1> {
        self.with_erasure_fence(timeline, |registry| {
            if registry.has_duplicate_names() {
                return Err(AuthorityErrorV1::SourceUnavailable);
            }
            Ok(registry.snapshot_unfenced())
        })
    }

    fn has_duplicate_names(&self) -> bool {
        let mut names = std::collections::HashSet::new();
        self.slots.iter().any(|(name, _)| !names.insert(name))
    }

    fn snapshot_unfenced(&self) -> std::collections::HashMap<String, StateRegistry> {
        let mut snapshot = std::collections::HashMap::new();
        for (name, slot) in &self.slots {
            snapshot.insert(name.clone(), slot.registry.clone());
        }
        snapshot
    }

    /// Compare this registry's accumulated state against a previously captured
    /// snapshot map (as returned by [`Self::state_snapshot`]).
    ///
    /// Returns the first differing `(reducer_name, entity_id)` pair, or `None`
    /// when the states are identical.
    ///
    /// # Errors
    /// Returns a closed source error when Timeline access is unverified or
    /// reducer names are ambiguous.
    pub fn diff_against_snapshot(
        &self,
        timeline: TimelineId,
        snapshot: &std::collections::HashMap<String, StateRegistry>,
        all_entities: &[EntityId],
    ) -> Result<Option<(String, EntityId)>, AuthorityErrorV1> {
        self.with_erasure_fence(timeline, |registry| {
            if registry.has_duplicate_names() {
                return Err(AuthorityErrorV1::SourceUnavailable);
            }
            for (name, slot) in &registry.slots {
                let snap_reg = snapshot.get(name).cloned().unwrap_or_default();
                for entity in all_entities {
                    if slot.registry.get_or_default(entity) != snap_reg.get_or_default(entity) {
                        return Ok(Some((name.clone(), *entity)));
                    }
                }
            }
            Ok(None)
        })
    }
}

/// Host-materialized observation carrying the authority evidence used to derive it.
///
/// The private fields make this the admission token for participant execution:
/// callers may inspect or clone a materialized observation, but only this crate
/// can create one from protected `Projection` state.
///
/// ```compile_fail
/// use pos_core::{AuthorizationDecisionV1, AuthorizationRequestV1, ObservationSnapshotV1};
/// use pos_state::AuthorizedObservationV1;
///
/// fn forge(
///     snapshot: ObservationSnapshotV1,
///     request: AuthorizationRequestV1,
///     decision: AuthorizationDecisionV1,
/// ) -> AuthorizedObservationV1 {
///     AuthorizedObservationV1 { snapshot, request, decision }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedObservationV1 {
    snapshot: ObservationSnapshotV1,
    artifact_digest: Hash,
    request: AuthorizationRequestV1,
    decision: AuthorizationDecisionV1,
}

impl AuthorizedObservationV1 {
    /// Return the safe content identity used to register this OBS1 artifact.
    #[must_use]
    pub const fn artifact_digest(&self) -> Hash {
        self.artifact_digest
    }

    /// Release the minimized immutable OBS1 snapshot only while its registered
    /// artifact remains authoritative.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::SourceUnavailable`] after structural
    /// degradation, erasure, invalidation, or a mismatched registration.
    pub fn authoritative_snapshot(
        &self,
        evaluation: &pos_core::ReplayClaimEvaluationV1,
    ) -> Result<&ObservationSnapshotV1, AuthorityErrorV1> {
        evaluation
            .require_authoritative_use(
                pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
                pos_core::ErasureReferenceV1::from_digest(*self.artifact_digest.as_bytes()),
            )
            .map_err(|_| AuthorityErrorV1::SourceUnavailable)
            .map(|()| &self.snapshot)
    }

    /// Release one snapshot artifact only when ADR-060 still permits authoritative use.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::SourceUnavailable`] when the artifact is
    /// erased, invalidated, structurally retained, absent from the evaluation,
    /// or absent from this observation snapshot.
    pub fn authoritative_artifact(
        &self,
        digest: Hash,
        evaluation: &pos_core::ReplayClaimEvaluationV1,
    ) -> Result<&ObservationArtifactV1, AuthorityErrorV1> {
        evaluation
            .require_authoritative_use(
                pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
                pos_core::ErasureReferenceV1::from_digest(*digest.as_bytes()),
            )
            .map_err(|_| AuthorityErrorV1::SourceUnavailable)
            .and_then(|()| {
                self.snapshot
                    .artifact(digest)
                    .ok_or(AuthorityErrorV1::SourceUnavailable)
            })
    }

    /// Re-evaluate consent, capability, delegation, and revocation evidence at
    /// the current authority boundary.
    ///
    /// # Errors
    /// Returns a closed authority error when any current evidence differs from
    /// the evidence that authorized materialization.
    pub fn revalidate(
        &self,
        authority: &PersistedAuthorityV1,
        registry: &AuthorityRegistrySnapshotV1,
        at_position: Seq,
    ) -> Result<(), AuthorityErrorV1> {
        authority.validate_observation_authorization(
            &self.request,
            &self.decision,
            registry,
            at_position,
        )
    }
}

/// Host-owned inputs required to materialize one Projection observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionObservationContextV1 {
    pub timeline_id: TimelineId,
    pub observed_through: Seq,
    pub reducer: String,
    pub prior_snapshot_digest: Option<Hash>,
}

fn absence_source_digest(context: &ProjectionObservationContextV1, subject_id: EntityId) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ProjectionObservationAbsence.v1\0");
    hasher.update(&context.timeline_id.inner().to_bytes());
    hasher.update(&subject_id.inner().to_bytes());
    hasher.update(&context.observed_through.as_u64().to_be_bytes());
    hasher.update(blake3::hash(context.reducer.as_bytes()).as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Immutable host policy installed at the same composition seam as a Reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionObservationPolicyV1 {
    permitted_fields: Vec<String>,
    schema: String,
    visibility_policy_revision: Hash,
    schema_revision: Hash,
    minimization_revision: Hash,
    digest: Hash,
}

impl ProjectionObservationPolicyV1 {
    /// Validate and bind the complete policy used for observation materialization.
    ///
    /// # Errors
    /// Returns a closed validation error for empty, oversized, duplicate, or
    /// noncanonical policy fields.
    pub fn try_new(
        permitted_fields: Vec<String>,
        schema: String,
        visibility_policy_revision: Hash,
        schema_revision: Hash,
        minimization_revision: Hash,
    ) -> Result<Self, AuthorityErrorV1> {
        validate_observation_policy_fields(&permitted_fields, &schema).and_then(|()| {
            if [
                visibility_policy_revision,
                schema_revision,
                minimization_revision,
            ]
            .contains(&Hash::zero())
            {
                return Err(AuthorityErrorV1::ProvenanceMissing);
            }
            let digest = observation_policy_digest(
                &permitted_fields,
                &schema,
                visibility_policy_revision,
                schema_revision,
                minimization_revision,
            );
            Ok(Self {
                permitted_fields,
                schema,
                visibility_policy_revision,
                schema_revision,
                minimization_revision,
                digest,
            })
        })
    }

    fn permitted_fields(&self) -> &[String] {
        &self.permitted_fields
    }

    fn schema(&self) -> &str {
        &self.schema
    }

    const fn visibility_policy_revision(&self) -> Hash {
        self.visibility_policy_revision
    }

    const fn schema_revision(&self) -> Hash {
        self.schema_revision
    }

    const fn minimization_revision(&self) -> Hash {
        self.minimization_revision
    }

    const fn digest(&self) -> Hash {
        self.digest
    }
}

fn validate_observation_policy_fields(
    permitted_fields: &[String],
    schema: &str,
) -> Result<(), AuthorityErrorV1> {
    if schema.is_empty()
        || schema.len() > pos_core::MAX_AUTHORITY_TEXT_BYTES
        || permitted_fields.is_empty()
        || permitted_fields.len() > MAX_OBSERVATION_SNAPSHOT_RECORDS
        || permitted_fields
            .iter()
            .any(|field| field.is_empty() || field.len() > pos_core::MAX_AUTHORITY_TEXT_BYTES)
    {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
    }
    if permitted_fields.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(AuthorityErrorV1::NonCanonicalOrder)
    } else {
        Ok(())
    }
}

fn observation_policy_digest(
    permitted_fields: &[String],
    schema: &str,
    visibility_policy_revision: Hash,
    schema_revision: Hash,
    minimization_revision: Hash,
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ProjectionObservationPolicy.v1\0");
    digest_text(&mut hasher, schema);
    for field in permitted_fields {
        digest_text(&mut hasher, field);
    }
    hasher.update(visibility_policy_revision.as_bytes());
    hasher.update(schema_revision.as_bytes());
    hasher.update(minimization_revision.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn digest_text(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(blake3::hash(value.as_bytes()).as_bytes());
}

fn canonical_state_artifact(
    state: &State,
    permitted_fields: &[String],
) -> Result<ObservationArtifactV1, AuthorityErrorV1> {
    let value = serde_json::Value::Object(
        permitted_fields
            .iter()
            .filter_map(|key| {
                state
                    .fields
                    .get(key)
                    .map(|value| (key.clone(), canonical_json(value)))
            })
            .collect(),
    );
    serde_json::to_vec(&value)
        .map(CanonicalBytes::from_vec)
        .map_err(|_| AuthorityErrorV1::InvalidEncoding)
        .and_then(ObservationArtifactV1::try_new)
}

fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

impl ConsentRevocationFoldListener for ProjectionRegistry {
    fn on_consent_revoked(&mut self, subject_id: EntityId, _fence_seq: u64) {
        if self.state_transaction_depth > 0 {
            self.transaction_revocations.push(subject_id);
        }
        self.forget_subject(&subject_id);
    }
}

// ---------------------------------------------------------------------------
// RelationshipIndex
// ---------------------------------------------------------------------------

/// Adjacency index for directed [`Relationship`] values.
///
/// NOT a [`Reducer`] — relationships are not per-entity event state; they are
/// recorded explicitly by callers that know when a relationship is established.
#[derive(Clone, Debug, Default)]
pub struct RelationshipIndex {
    outgoing: HashMap<EntityId, Vec<Relationship>>,
    incoming: HashMap<EntityId, Vec<Relationship>>,
}

impl RelationshipIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a relationship in both the outgoing and incoming indices.
    pub fn record(&mut self, rel: Relationship) {
        self.outgoing
            .entry(rel.source)
            .or_default()
            .push(rel.clone());
        self.incoming.entry(rel.target).or_default().push(rel);
    }

    /// All relationships whose source is `id`.
    #[must_use]
    pub fn outgoing_from(&self, id: &EntityId) -> &[Relationship] {
        self.outgoing.get(id).map_or(&[], Vec::as_slice)
    }

    /// All relationships whose target is `id`.
    #[must_use]
    pub fn incoming_to(&self, id: &EntityId) -> &[Relationship] {
        self.incoming.get(id).map_or(&[], Vec::as_slice)
    }

    /// Union of outgoing targets and incoming sources — the direct neighbours of `id`.
    ///
    /// Each neighbour appears at most once even if it is both a source and a target.
    #[must_use]
    pub fn neighbours(&self, id: &EntityId) -> Vec<EntityId> {
        let mut seen: std::collections::HashSet<EntityId> = std::collections::HashSet::new();
        let mut result = Vec::new();

        for rel in self.outgoing_from(id) {
            if seen.contains(&rel.target) {
                continue;
            }
            seen.insert(rel.target);
            result.push(rel.target);
        }
        for rel in self.incoming_to(id) {
            if seen.contains(&rel.source) {
                continue;
            }
            seen.insert(rel.source);
            result.push(rel.source);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::PluginId;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        entity::RelationshipKind,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::EventId,
        AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
        AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
        AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1,
        AuthorizationRequestDraftV1, AuthorizationRequestV1, CapabilityGrantDraftV1,
        CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1, ConsentEvidenceV1,
        DelegateClassV1, DelegationChainV1, PrincipalRefV1, DELEGATE_ACTION_V1,
    };
    use proptest::prelude::*;

    fn open_projection_registry() -> ProjectionRegistry {
        ProjectionRegistry::new()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
    }

    fn test_timeline() -> TimelineId {
        static TIMELINE: std::sync::OnceLock<TimelineId> = std::sync::OnceLock::new();
        *TIMELINE.get_or_init(TimelineId::new)
    }

    trait ProjectionTestReads {
        fn state_for_test(&self, entity: &EntityId) -> Option<State>;
        fn state_for_reducer_test(&self, name: &str, entity: &EntityId) -> Option<State>;
    }

    impl ProjectionTestReads for ProjectionRegistry {
        fn state_for_test(&self, entity: &EntityId) -> Option<State> {
            test_ok(self.state_for(test_timeline(), entity))
        }

        fn state_for_reducer_test(&self, name: &str, entity: &EntityId) -> Option<State> {
            test_ok(self.state_for_reducer(test_timeline(), name, entity))
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn make_event(entity: EntityId) -> Event {
        make_event_typed(entity, "test.tick")
    }

    fn make_event_typed(entity: EntityId, kind: &str) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(kind),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    const fn test_hash(value: u8) -> Hash {
        Hash::from_bytes([value; 32])
    }

    struct CacheFixture {
        decision: AuthorizationDecisionV1,
        request: AuthorizationRequestV1,
        authority: PersistedAuthorityV1,
    }

    fn active_decision(authority_timeline: TimelineId) -> CacheFixture {
        decision_with_capability_trust(authority_timeline, test_hash(5), true)
    }

    fn authority_registry(
        request: &AuthorizationRequestV1,
        grants: &[CapabilityGrantV1],
        registry_digest: Hash,
        trust_capability: bool,
    ) -> AuthorityRegistrySnapshotV1 {
        let mut capability_bindings = if trust_capability {
            grants
                .iter()
                .map(|grant| test_ok(grant.binding_digest()))
                .collect()
        } else {
            vec![]
        };
        capability_bindings.sort_unstable();
        test_ok(AuthorityRegistrySnapshotV1::try_new(
            registry_digest,
            vec![request.authenticated().registry_binding_digest()],
            capability_bindings,
            vec![],
        ))
    }

    fn delegation_scopes(actor: EntityId) -> (CapabilityScopeV1, CapabilityScopeV1) {
        let scope = |actions| {
            test_ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
                resources: vec!["profile".to_owned()],
                actions,
                purposes: vec!["planning".to_owned()],
                audiences: vec!["local-host".to_owned()],
                actor_entity_ids: vec![actor],
                subject_ids: vec![],
                participant_ids: vec![],
                plugin_id: None,
                principal_roles: vec![AuthorityRoleV1::Actor],
                max_uses: 2,
                budget: 10,
                environment_constraints: vec!["local-only".to_owned()],
            }))
        };
        (
            scope(vec![DELEGATE_ACTION_V1.to_owned(), "read".to_owned()]),
            scope(vec!["read".to_owned()]),
        )
    }

    fn cache_request(
        authenticated: AuthenticatedPrincipalResultV1,
        actor: EntityId,
        authority_timeline: TimelineId,
        policy: Hash,
        registry_digest: Hash,
    ) -> AuthorizationRequestV1 {
        test_ok(AuthorizationRequestV1::try_from_draft(
            AuthorizationRequestDraftV1 {
                authenticated,
                actor_entity_id: actor,
                subject_id: None,
                participant_id: None,
                plugin_id: None,
                installation_id: None,
                principal_role: AuthorityRoleV1::Actor,
                resource: "profile".to_owned(),
                data_category: "public".to_owned(),
                action: "read".to_owned(),
                purpose: "planning".to_owned(),
                audience: "local-host".to_owned(),
                at_time: WallTime::from_micros(10),
                authority_timeline,
                at_position: Seq::from_u64(10),
                consent_timeline: None,
                consent_at_position: None,
                use_count: 1,
                budget: 5,
                consent_policy_revision: policy,
                capability_policy_revision: policy,
                revocation_epoch: 0,
                revocation_state_current: true,
                authority_registry_digest: registry_digest,
                consent: ConsentEvidenceV1::NotRequired,
                environment_constraints: vec!["local-only".to_owned()],
            },
        ))
    }

    fn projection_request(
        base: &AuthorizationRequestV1,
        subject_id: Option<EntityId>,
        participant_id: Option<EntityId>,
        plugin_context: Option<(PluginId, [u8; 16])>,
        consent: ConsentEvidenceV1,
    ) -> AuthorizationRequestV1 {
        let (plugin_id, installation_id) = plugin_context.unzip();
        test_ok(AuthorizationRequestV1::try_from_draft(
            AuthorizationRequestDraftV1 {
                authenticated: base.authenticated().clone(),
                actor_entity_id: base.actor_entity_id(),
                subject_id,
                participant_id,
                plugin_id,
                installation_id,
                principal_role: base.principal_role(),
                resource: "projection.missing-reducer".to_owned(),
                data_category: base.data_category().to_owned(),
                action: base.action().to_owned(),
                purpose: base.purpose().to_owned(),
                audience: base.audience().to_owned(),
                at_time: base.at_time(),
                authority_timeline: base.authority_timeline(),
                at_position: base.at_position(),
                consent_timeline: subject_id.map(|_| base.authority_timeline()),
                consent_at_position: subject_id.map(|_| base.at_position()),
                use_count: base.use_count(),
                budget: base.budget(),
                consent_policy_revision: base.consent_policy_revision(),
                capability_policy_revision: base.capability_policy_revision(),
                revocation_epoch: base.revocation_epoch(),
                revocation_state_current: base.revocation_state_current(),
                authority_registry_digest: base.authority_registry_digest(),
                consent,
                environment_constraints: base.environment_constraints().to_vec(),
            },
        ))
    }

    fn decision_with_capability_trust(
        authority_timeline: TimelineId,
        grant_id: Hash,
        trust_capability: bool,
    ) -> CacheFixture {
        let root_principal = test_ok(PrincipalRefV1::try_new([1; 16], "local.test"));
        let delegate = test_ok(PrincipalRefV1::try_new([2; 16], "local.test"));
        let leaf_principal = test_ok(PrincipalRefV1::try_new([3; 16], "local.test"));
        let actor = EntityId::new();
        let authenticated = test_ok(AuthenticatedPrincipalResultV1::try_from_draft(
            AuthenticatedPrincipalDraftV1 {
                principal: leaf_principal.clone(),
                adapter_id: "test-adapter".to_owned(),
                assurance: test_ok(AssuranceLevelV1::try_new(1)),
                issued_at: WallTime::from_micros(1),
                expires_at: WallTime::from_micros(100),
                binding_digest: test_hash(3),
            },
        ));
        let policy = test_hash(4);
        let consent_reference = test_hash(6);
        let registry_digest = test_hash(7);
        let (root_scope, child_scope) = delegation_scopes(actor);
        let parent_grant_id = test_hash(16);
        let parent = test_ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id: parent_grant_id,
            grantor: root_principal,
            grantee: AuthorityGranteeV1::Principal(delegate.clone()),
            trust_domain: "local.test".to_owned(),
            scope: root_scope,
            valid_from_position: Seq::from_u64(1),
            valid_until_position: Seq::from_u64(80),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 1,
            permitted_delegate_classes: vec![DelegateClassV1::Principal],
            consent_references: vec![consent_reference],
            policy_revision: policy,
            issuance_timeline: authority_timeline,
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: registry_digest,
        }));
        let child = test_ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id,
            grantor: delegate,
            grantee: AuthorityGranteeV1::Principal(leaf_principal),
            trust_domain: "local.test".to_owned(),
            scope: child_scope,
            valid_from_position: Seq::from_u64(2),
            valid_until_position: Seq::from_u64(80),
            parent_grant_id: Some(parent_grant_id),
            delegation_depth: 1,
            max_delegation_depth: 1,
            permitted_delegate_classes: vec![],
            consent_references: vec![consent_reference],
            policy_revision: policy,
            issuance_timeline: authority_timeline,
            issuance_seq: Seq::from_u64(2),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: registry_digest,
        }));
        let request = cache_request(
            authenticated,
            actor,
            authority_timeline,
            policy,
            registry_digest,
        );
        let grants = vec![parent.clone(), child.clone()];
        let registry = authority_registry(&request, &grants, registry_digest, trust_capability);
        let chain = test_ok(DelegationChainV1::try_from_grants(grants));
        let decision = AuthorityEvaluatorV1::authorize(&request, &chain, &registry);
        let persistence_registry = authority_registry(
            &request,
            &[parent.clone(), child.clone()],
            registry_digest,
            true,
        );
        let host = AuthorityPersistenceHostV1::new(&persistence_registry);
        let mut state = AuthorityPersistenceStateV1::new();
        test_ok(state.issue_grant(test_ok(host.authorize_grant(&parent)), parent));
        test_ok(state.issue_grant(test_ok(host.authorize_grant(&child)), child));
        CacheFixture {
            decision,
            request,
            authority: test_ok(state.resolve(grant_id)),
        }
    }

    // ------------------------------------------------------------------
    // ProjectionRegistry tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_applies_to_all_reducers() {
        let mut registry = open_projection_registry();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(entity));

        let count_a = registry
            .state_for_reducer_test("a", &entity)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        let count_b = registry
            .state_for_reducer_test("b", &entity)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        assert_eq!(count_a, 1, "reducer 'a' should have seen 1 event");
        assert_eq!(count_b, 1, "reducer 'b' should have seen 1 event");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_retain_subject_filters_every_reducer() {
        let mut registry = open_projection_registry();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        let unrelated = EntityId::new();
        registry.fold_events(
            test_timeline(),
            &[make_event(subject), make_event(unrelated)],
        );

        registry.retain_subject(&subject);

        for name in ["a", "b"] {
            assert!(registry.state_for_reducer_test(name, &subject).is_some());
            assert!(registry.state_for_reducer_test(name, &unrelated).is_none());
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_fold_events() {
        let mut registry = open_projection_registry();
        registry.register("main", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        let events: Vec<Event> = (0..5).map(|_| make_event(entity)).collect();
        registry.fold_events(test_timeline(), &events);

        let count = registry
            .state_for_reducer_test("main", &entity)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("event_count should be present"))
            });
        assert_eq!(count, 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn valid_consent_revocation_evicts_each_subject_projection_cache() {
        let mut registry = open_projection_registry();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        let other = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(subject));
        registry.apply_event(test_timeline(), &make_event(other));

        let revocation = ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 2,
        };
        let mut event = make_event_typed(subject, EVENT_TYPE_CONSENT_REVOKED_V1);
        event.payload = revocation.encode().unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("invalid revocation fixture: {error:?}")))
        });
        registry.apply_event(test_timeline(), &event);

        assert!(registry.state_for_test(&subject).is_none());
        assert!(registry.state_for_reducer_test("b", &subject).is_none());
        assert!(registry.state_for_test(&other).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn failed_state_transaction_does_not_restore_revoked_subject_projection() {
        let mut registry = open_projection_registry();
        registry.register("events", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        let other = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(subject));
        registry.apply_event(test_timeline(), &make_event(other));

        let revocation = ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 2,
        };
        let mut event = make_event_typed(subject, EVENT_TYPE_CONSENT_REVOKED_V1);
        event.payload = revocation.encode().unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("invalid revocation fixture: {error:?}")))
        });

        let result = registry.try_with_state_transaction(|candidate| {
            candidate.apply_event(test_timeline(), &event);
            Err::<(), _>(())
        });

        assert_eq!(result, Err(()));
        assert!(registry.state_for_test(&subject).is_none());
        assert!(registry.state_for_test(&other).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn outer_state_transaction_retains_nested_revocation_after_failure() {
        let mut registry = open_projection_registry();
        registry.register("events", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(subject));
        let revocation = ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 2,
        };
        let mut event = make_event_typed(subject, EVENT_TYPE_CONSENT_REVOKED_V1);
        event.payload = revocation.encode().unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("invalid revocation fixture: {error:?}")))
        });

        let result = registry.try_with_state_transaction(|candidate| {
            let nested = candidate.try_with_state_transaction(|inner| {
                inner.apply_event(test_timeline(), &event);
                Err::<(), _>(())
            });
            assert_eq!(nested, Err(()));
            Ok::<(), ()>(())
        });

        assert_eq!(result, Ok(()));
        assert!(registry.state_for_test(&subject).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn successful_nested_state_transaction_keeps_outer_transaction_open() {
        let mut registry = ProjectionRegistry::new();
        let result = registry.try_with_state_transaction(|outer| {
            outer.try_with_state_transaction(|_inner| Ok::<(), ()>(()))
        });
        assert_eq!(result, Ok(()));
        assert_eq!(registry.state_transaction_depth, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn malformed_consent_revocation_does_not_evict_projection_cache() {
        let mut registry = open_projection_registry();
        registry.register("events", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(subject));

        let malformed = make_event_typed(subject, EVENT_TYPE_CONSENT_REVOKED_V1);
        registry.apply_event(test_timeline(), &malformed);

        assert!(registry.state_for_test(&subject).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducers_never_observe_reserved_consent_namespace_events() {
        let mut registry = open_projection_registry();
        registry.register("events", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        let consent_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("consent.future.v2"),
            payload: CanonicalBytes::from_static(b"host-only"),
            seq: pos_core::clock::Seq::from_u64(1),
            wall_time: WallTime::now(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        registry.apply_event(test_timeline(), &consent_event);
        assert!(registry.state_for_test(&entity).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_state_for_returns_first_reducers_view() {
        let mut registry = open_projection_registry();
        registry.register("first", Box::new(EntityStateProjection));
        registry.register("second", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(entity));

        let state = registry
            .state_for_test(&entity)
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("state should exist")));
        let count = state
            .get("event_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_state_for_returns_none_when_empty() {
        let registry = open_projection_registry();
        let entity = EntityId::new();
        assert!(registry.state_for_test(&entity).is_none());
    }

    #[test]
    fn public_projection_reads_close_after_timeline_freeze() {
        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate.clone());
        registry.register("events", Box::new(EntityStateProjection));
        registry.apply_event(timeline, &make_event(entity));
        let snapshot = test_ok(registry.state_snapshot(timeline));
        assert!(test_ok(registry.state_for(timeline, &entity)).is_some());
        assert!(test_ok(registry.state_for_reducer(timeline, "events", &entity)).is_some());
        assert!(test_ok(registry.diff_against_snapshot(timeline, &snapshot, &[entity])).is_none());

        gate.freeze_timeline_for_test(timeline);
        assert_eq!(
            registry.state_for(timeline, &entity).map(|_| ()),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert_eq!(
            registry
                .state_for_reducer(timeline, "events", &entity)
                .map(|_| ()),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert_eq!(
            registry
                .diff_against_snapshot(timeline, &snapshot, &[entity])
                .map(|_| ()),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
    }

    #[test]
    fn projection_state_cannot_be_read_through_another_timeline_fence() {
        let source = TimelineId::new();
        let unrelated = TimelineId::new();
        let entity = EntityId::new();
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("events", Box::new(EntityStateProjection));
        registry.apply_event(source, &make_event(entity));
        assert!(test_ok(registry.state_for(source, &entity)).is_some());
        assert_eq!(
            registry.state_for(unrelated, &entity),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        registry.apply_event(unrelated, &make_event(entity));
        assert_eq!(
            registry.state_for(source, &entity),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        registry.apply_event(source, &make_event(entity));
        assert_eq!(
            registry.state_for(unrelated, &entity),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        registry.clear_state();
        registry.apply_event(unrelated, &make_event(entity));
        assert!(test_ok(registry.state_for(unrelated, &entity)).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_restore_from_snapshot_skips_unknown_reducers() {
        let mut registry = open_projection_registry();
        registry.register("registered", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(entity));

        let mut snapshot = std::collections::HashMap::new();
        snapshot.insert("other".to_owned(), StateRegistry::new());
        test_ok(registry.restore_from_snapshot(test_timeline(), &snapshot, None));

        let count = registry
            .state_for_reducer_test("registered", &entity)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_restore_from_snapshot_loads_matching_reducer() {
        let timeline = test_timeline();
        let mut registry = open_projection_registry();
        registry.register("registered", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        registry.apply_event(test_timeline(), &make_event(entity));
        let snapshot = test_ok(registry.state_snapshot(timeline));

        let mut restored = open_projection_registry();
        restored.register("registered", Box::new(EntityStateProjection));
        test_ok(restored.restore_from_snapshot(timeline, &snapshot, None));

        let count = restored
            .state_for_reducer_test("registered", &entity)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn projection_registry_restore_rejects_stale_generation_and_blocked_timeline() {
        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let mut source = ProjectionRegistry::new().with_erasure_gate(gate.clone());
        source.register("events", Box::new(EntityStateProjection));
        source.apply_event(timeline, &make_event(entity));
        let snapshot = test_ok(source.state_snapshot(timeline));

        let mut restored = ProjectionRegistry::new().with_erasure_gate(gate.clone());
        restored.register("events", Box::new(EntityStateProjection));
        assert_eq!(
            restored.restore_from_snapshot(
                timeline,
                &snapshot,
                Some(ErasureReferenceV1::from_digest([7; 32])),
            ),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert!(test_ok(restored.state_for(timeline, &entity)).is_none());

        gate.block_timeline(timeline);
        assert_eq!(
            restored.restore_from_snapshot(timeline, &snapshot, None),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert_eq!(
            ProjectionRegistry::new().restore_from_snapshot(timeline, &snapshot, None),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
    }

    #[test]
    fn projection_refold_replaces_state_only_at_the_captured_generation() {
        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate.clone());
        registry.register("events", Box::new(EntityStateProjection));
        let event = make_event(entity);
        registry.fold_events(timeline, &[event.clone(), event.clone()]);

        assert_eq!(
            registry.refold_events(
                timeline,
                std::slice::from_ref(&event),
                Some(ErasureReferenceV1::from_digest([3; 32])),
            ),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        let count = |registry: &ProjectionRegistry| {
            test_ok(registry.state_for_reducer(timeline, "events", &entity))
                .and_then(|state| state.get("event_count").and_then(serde_json::Value::as_u64))
        };
        assert_eq!(count(&registry), Some(2));

        test_ok(registry.refold_events(timeline, std::slice::from_ref(&event), None));
        assert_eq!(count(&registry), Some(1));

        gate.block_timeline(timeline);
        assert_eq!(
            registry.refold_events(timeline, std::slice::from_ref(&event), None),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert_eq!(
            ProjectionRegistry::new().refold_events(timeline, &[event], None),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
    }

    #[test]
    fn committed_fork_rejects_a_different_projection_parent() {
        let source = TimelineId::new();
        let unrelated = TimelineId::new();
        let child = TimelineId::new();
        let entity = EntityId::new();
        let mut registry = open_projection_registry();
        registry.register("events", Box::new(EntityStateProjection));
        registry.apply_event(source, &make_event(entity));
        assert_eq!(
            registry.adopt_committed_fork(unrelated, child),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert!(test_ok(registry.state_for(source, &entity)).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(on))]
    fn public_state_snapshot_fails_closed_without_timeline_access() {
        let timeline = TimelineId::new();
        let unbound = ProjectionRegistry::new();
        assert_eq!(
            unbound.state_snapshot(timeline).map(|_| ()),
            Err(AuthorityErrorV1::SourceUnavailable)
        );

        let blocked_gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        blocked_gate.block_timeline(timeline);
        let blocked = ProjectionRegistry::new().with_erasure_gate(blocked_gate);
        assert_eq!(
            blocked.state_snapshot(timeline).map(|_| ()),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours_dedupes_duplicate_outgoing_targets() {
        let mut index = RelationshipIndex::new();
        let hub = EntityId::new();
        let target = EntityId::new();
        index.record(Relationship::new(hub, target, RelationshipKind::new("a")));
        index.record(Relationship::new(hub, target, RelationshipKind::new("b")));
        let neighbours = index.neighbours(&hub);
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0], target);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours_dedupes_duplicate_incoming_sources() {
        let mut index = RelationshipIndex::new();
        let hub = EntityId::new();
        let source = EntityId::new();
        index.record(Relationship::new(source, hub, RelationshipKind::new("a")));
        index.record(Relationship::new(source, hub, RelationshipKind::new("b")));
        let neighbours = index.neighbours(&hub);
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0], source);
    }

    // ------------------------------------------------------------------
    // EntityStateProjection tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_state_projection_counts_events() {
        let proj = EntityStateProjection;
        let entity = EntityId::new();
        let mut state_reg = StateRegistry::new();

        for _ in 0..3 {
            state_reg.apply(&proj, &make_event(entity));
        }

        let count = state_reg
            .get(&entity)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("event_count should be present"))
            });
        assert_eq!(count, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_state_projection_different_entities_tracked_separately() {
        let proj = EntityStateProjection;
        let a = EntityId::new();
        let b = EntityId::new();
        let mut state_reg = StateRegistry::new();

        state_reg.apply(&proj, &make_event(a));
        state_reg.apply(&proj, &make_event(a));
        state_reg.apply(&proj, &make_event(b));

        let count_a = state_reg
            .get(&a)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        let count_b = state_reg
            .get(&b)
            .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        assert_eq!(count_a, 2);
        assert_eq!(count_b, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_state_projection_records_last_event_type() {
        let proj = EntityStateProjection;
        let entity = EntityId::new();
        let mut state_reg = StateRegistry::new();

        state_reg.apply(&proj, &make_event_typed(entity, "first.type"));
        state_reg.apply(&proj, &make_event_typed(entity, "second.type"));

        let last = state_reg
            .get(&entity)
            .and_then(|s| s.get("last_event_type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("last_event_type should be present"))
            });
        assert_eq!(last, "second.type");
    }

    // ------------------------------------------------------------------
    // RelationshipIndex tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_records_and_queries() {
        let mut index = RelationshipIndex::new();
        let a = EntityId::new();
        let b = EntityId::new();
        let c = EntityId::new();

        index.record(Relationship::new(a, b, RelationshipKind::new("trusts")));
        index.record(Relationship::new(a, c, RelationshipKind::new("employs")));
        index.record(Relationship::new(c, b, RelationshipKind::new("trusts")));

        assert_eq!(index.outgoing_from(&a).len(), 2);
        assert_eq!(index.incoming_to(&b).len(), 2);
        assert_eq!(index.outgoing_from(&c).len(), 1);
        assert_eq!(index.incoming_to(&c).len(), 1);

        let lone = EntityId::new();
        assert!(index.outgoing_from(&lone).is_empty());
        assert!(index.incoming_to(&lone).is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours() {
        let mut index = RelationshipIndex::new();
        let hub = EntityId::new();
        let x = EntityId::new();
        let y = EntityId::new();
        let z = EntityId::new();

        // hub → x  (outgoing target = x)
        index.record(Relationship::new(hub, x, RelationshipKind::new("link")));
        // y → hub  (incoming source = y)
        index.record(Relationship::new(y, hub, RelationshipKind::new("link")));
        // z → hub  (incoming source = z)
        index.record(Relationship::new(z, hub, RelationshipKind::new("link")));

        let mut neighbours = index.neighbours(&hub);
        neighbours.sort();
        let mut expected = vec![x, y, z];
        expected.sort();
        assert_eq!(neighbours, expected);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours_no_duplicates() {
        let mut index = RelationshipIndex::new();
        let a = EntityId::new();
        let b = EntityId::new();

        // a → b and b → a: from a's perspective b appears in both lists.
        index.record(Relationship::new(a, b, RelationshipKind::new("link")));
        index.record(Relationship::new(b, a, RelationshipKind::new("link")));

        let neighbours = index.neighbours(&a);
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0], b);
    }

    // ------------------------------------------------------------------
    // proptest: fold determinism
    // ------------------------------------------------------------------

    proptest! {
        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn fold_deterministic(n_events in 1usize..=20) {
            let entity = EntityId::new();
            let events: Vec<Event> = (0..n_events).map(|_| make_event(entity)).collect();

            let mut reg1 = open_projection_registry();
            reg1.register("p", Box::new(EntityStateProjection));
            reg1.fold_events(test_timeline(), &events);

            let mut reg2 = open_projection_registry();
            reg2.register("p", Box::new(EntityStateProjection));
            reg2.fold_events(test_timeline(), &events);

            let count1 = reg1
                .state_for_reducer_test("p", &entity)
                .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
                .unwrap_or(0);
            let count2 = reg2
                .state_for_reducer_test("p", &entity)
                .and_then(|s| s.get("event_count").and_then(serde_json::Value::as_u64))
                .unwrap_or(0);

            prop_assert_eq!(count1, count2);
            prop_assert_eq!(count1, n_events as u64);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(on))]
    fn public_observation_path_enters_the_erasure_fence() {
        let timeline = TimelineId::new();
        let fixture = active_decision(timeline);
        let authority_registry = test_ok(AuthorityRegistrySnapshotV1::try_new(
            test_hash(7),
            vec![fixture.request.authenticated().registry_binding_digest()],
            Vec::new(),
            Vec::new(),
        ));
        let context = ProjectionObservationContextV1 {
            timeline_id: timeline,
            observed_through: Seq::ZERO,
            reducer: "missing-reducer".to_owned(),
            prior_snapshot_digest: None,
        };
        let mut registry = ProjectionRegistry::new();
        assert_eq!(
            registry
                .materialize_authorized_observation(
                    &fixture.request,
                    &fixture.decision,
                    &fixture.authority,
                    &authority_registry,
                    Seq::ZERO,
                    &context,
                )
                .map(|_| ()),
            Err(AuthorityErrorV1::SourceUnavailable)
        );

        let blocked_gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        blocked_gate.block_timeline(timeline);
        registry.bind_erasure_gate(blocked_gate);
        // A second binding cannot replace the host gate with a permissive one.
        registry.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
        assert_eq!(
            registry.materialize_authorized_observation(
                &fixture.request,
                &fixture.decision,
                &fixture.authority,
                &authority_registry,
                Seq::ZERO,
                &context,
            ),
            Err(AuthorityErrorV1::SourceUnavailable)
        );

        let unbound = ProjectionRegistry::new().without_erasure_gate();
        assert_eq!(
            unbound.materialize_authorized_observation(
                &fixture.request,
                &fixture.decision,
                &fixture.authority,
                &authority_registry,
                Seq::ZERO,
                &context,
            ),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
    }

    #[test]
    fn projection_materialization_requires_every_subject_and_plugin_binding() {
        let fixture = active_decision(TimelineId::new());
        let context = ProjectionObservationContextV1 {
            timeline_id: fixture.request.authority_timeline(),
            observed_through: Seq::ZERO,
            reducer: "missing-reducer".to_owned(),
            prior_snapshot_digest: None,
        };
        let mut registry = ProjectionRegistry::new();
        let subject = EntityId::new();
        let participant = EntityId::new();
        let plugin = PluginId::new();

        let missing_subject = projection_request(
            &fixture.request,
            None,
            Some(participant),
            Some((plugin, [1; 16])),
            fixture.request.consent().clone(),
        );
        assert_eq!(
            registry.materialize_authorized_projection(
                &missing_subject,
                &fixture.decision,
                &context,
            ),
            Err(AuthorityErrorV1::ConsentMissing)
        );

        let missing_participant = projection_request(
            &fixture.request,
            Some(subject),
            None,
            Some((plugin, [1; 16])),
            fixture.request.consent().clone(),
        );
        assert_eq!(
            registry.materialize_authorized_projection(
                &missing_participant,
                &fixture.decision,
                &context,
            ),
            Err(AuthorityErrorV1::UnauthorizedSource)
        );

        let missing_plugin = projection_request(
            &fixture.request,
            Some(subject),
            Some(participant),
            None,
            fixture.request.consent().clone(),
        );
        assert_eq!(
            registry.materialize_authorized_projection(
                &missing_plugin,
                &fixture.decision,
                &context,
            ),
            Err(AuthorityErrorV1::UnauthorizedSource)
        );

        let bound = projection_request(
            &fixture.request,
            Some(subject),
            Some(participant),
            Some((plugin, [1; 16])),
            fixture.request.consent().clone(),
        );
        test_ok(registry.register_installed_reducer(
            PluginId::new(),
            "missing-reducer",
            Box::new(EntityStateProjection),
        ));
        assert_eq!(
            registry.materialize_authorized_projection(&bound, &fixture.decision, &context),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        test_ok(registry.register_installed_reducer(
            plugin,
            "missing-reducer",
            Box::new(EntityStateProjection),
        ));
        assert_eq!(
            registry.materialize_authorized_projection(&bound, &fixture.decision, &context),
            Err(AuthorityErrorV1::UnauthorizedSource)
        );
        registry.register("missing-reducer", Box::new(EntityStateProjection));
        assert_eq!(
            registry.materialize_authorized_projection(&bound, &fixture.decision, &context),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod extra_tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_debug_shows_reducer_names() {
        let mut reg = ProjectionRegistry::new();
        reg.register("alpha", Box::new(EntityStateProjection));
        reg.register("beta", Box::new(EntityStateProjection));
        let debug_str = format!("{reg:?}");
        assert!(debug_str.contains("alpha"));
        assert!(debug_str.contains("beta"));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod wave3_tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::{EntityId, EventId},
        Event, Reducer, State,
    };

    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    struct TR;

    fn open_projection_registry() -> ProjectionRegistry {
        ProjectionRegistry::new()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
    }

    fn test_timeline() -> TimelineId {
        static TIMELINE: std::sync::OnceLock<TimelineId> = std::sync::OnceLock::new();
        *TIMELINE.get_or_init(TimelineId::new)
    }

    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    impl Reducer for TR {
        fn initial(&self) -> State {
            State::new()
        }
        fn apply(&self, state: &mut State, _: &Event) {
            let n = state
                .get("n")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn ev(entity: EntityId) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_names_returns_registered_names() {
        let mut reg = ProjectionRegistry::new();
        reg.register("alpha", Box::new(TR));
        reg.register("beta", Box::new(TR));
        let names = reg.reducer_names();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn installed_same_name_reducers_keep_independent_state_and_rollback() {
        let first = PluginId::new();
        let second = PluginId::new();
        let entity = EntityId::new();
        let timeline = TimelineId::new();
        let mut registry = ProjectionRegistry::new()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
        assert!(registry
            .register_installed_reducer(first, "same", Box::new(EntityStateProjection))
            .is_ok());
        registry.apply_event(timeline, &ev(entity));
        let single_slot_snapshot = test_ok(registry.state_snapshot(timeline));
        assert!(registry
            .register_installed_reducer(second, "same", Box::new(EntityStateProjection))
            .is_ok());
        let count = |registry: &ProjectionRegistry, id| {
            registry
                .state_for_plugin(id, &entity)
                .and_then(|state| state.get("event_count"))
                .and_then(serde_json::Value::as_u64)
        };
        assert_eq!(count(&registry, first), Some(1));
        assert_eq!(count(&registry, second), None);
        assert!(test_ok(registry.state_for_reducer(timeline, "same", &entity)).is_none());
        assert!(test_ok(registry.state_for(timeline, &entity)).is_some());
        assert!(matches!(
            registry.state_snapshot(timeline),
            Err(AuthorityErrorV1::SourceUnavailable)
        ));
        assert_eq!(
            registry.restore_from_snapshot(timeline, &single_slot_snapshot, None),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert_eq!(count(&registry, first), Some(1));
        assert_eq!(count(&registry, second), None);
        assert_eq!(
            registry.diff_against_snapshot(timeline, &single_slot_snapshot, &[entity]),
            Err(AuthorityErrorV1::SourceUnavailable)
        );
        assert!(matches!(
            registry.register_installed_reducer(first, "other", Box::new(EntityStateProjection)),
            Err(ProjectionSlotErrorV1::DuplicatePluginId { .. })
        ));
        assert_eq!(
            registry.register_installed_reducer(
                PluginId::new(),
                "",
                Box::new(EntityStateProjection),
            ),
            Err(ProjectionSlotErrorV1::InvalidName)
        );
        assert_eq!(
            registry.register_installed_reducer(
                PluginId::new(),
                &"x".repeat(pos_core::MAX_AUTHORITY_TEXT_BYTES + 1),
                Box::new(EntityStateProjection),
            ),
            Err(ProjectionSlotErrorV1::InvalidName)
        );
        let denied: Result<(), &str> = registry.try_with_state_transaction(|candidate| {
            candidate.apply_event(timeline, &ev(entity));
            Err("denied")
        });
        assert_eq!(denied, Err("denied"));
        assert_eq!(count(&registry, first), Some(1));
        assert_eq!(count(&registry, second), None);
    }

    #[test]
    fn failed_state_transaction_restores_by_slot_after_registration_reorders_slots() {
        let entity = EntityId::new();
        let mut registry = ProjectionRegistry::new();
        registry.register("first", Box::new(EntityStateProjection));
        registry.apply_event(&ev(entity));
        registry.register("second", Box::new(EntityStateProjection));
        registry.apply_event(&ev(entity));
        let count = |registry: &ProjectionRegistry, name| {
            registry
                .state_for_reducer(name, &entity)
                .and_then(|state| state.get("event_count"))
                .and_then(serde_json::Value::as_u64)
        };
        assert_eq!(count(&registry, "first"), Some(2));
        assert_eq!(count(&registry, "second"), Some(1));

        let denied: Result<(), &str> = registry.try_with_state_transaction(|candidate| {
            candidate.register("first", Box::new(EntityStateProjection));
            candidate.register("third", Box::new(EntityStateProjection));
            candidate.apply_event(&ev(entity));
            Err("denied")
        });

        assert_eq!(denied, Err("denied"));
        assert_eq!(count(&registry, "first"), Some(2));
        assert_eq!(count(&registry, "second"), Some(1));
        assert_eq!(count(&registry, "third"), None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_snapshot_identical_returns_none() {
        let entity = EntityId::new();
        let mut reg = open_projection_registry();
        reg.register("r", Box::new(TR));
        reg.apply_event(test_timeline(), &ev(entity));

        let snap = reg.snapshot_unfenced();
        let diff = test_ok(reg.diff_against_snapshot(test_timeline(), &snap, &[entity]));
        assert!(diff.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_snapshot_diverged_returns_some() {
        let entity = EntityId::new();
        let mut reg = open_projection_registry();
        reg.register("r", Box::new(TR));
        reg.apply_event(test_timeline(), &ev(entity));

        let snap = reg.snapshot_unfenced();
        // Apply another event — now reg diverges from the snapshot
        reg.apply_event(test_timeline(), &ev(entity));
        let diff = test_ok(reg.diff_against_snapshot(test_timeline(), &snap, &[entity]));
        assert!(diff.is_some());
        let (name, eid) =
            diff.unwrap_or_else(|| std::panic::resume_unwind(Box::new("diff should be present")));
        assert_eq!(name, "r");
        assert_eq!(eid, entity);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_empty_snapshot_returns_some_when_reg_has_state() {
        let entity = EntityId::new();
        let mut reg = open_projection_registry();
        reg.register("r", Box::new(TR));
        reg.apply_event(test_timeline(), &ev(entity));

        let empty_snap = std::collections::HashMap::new();
        let diff = test_ok(reg.diff_against_snapshot(test_timeline(), &empty_snap, &[entity]));
        assert!(diff.is_some());
    }

    #[test]
    fn cloned_erasure_gate_exists_only_after_an_explicit_host_binding() {
        let mut registry = ProjectionRegistry::new();
        assert!(registry.clone_erasure_gate().is_none());

        let gate: Arc<dyn ErasureGate> = Arc::new(ErasureContainmentGateV1::new_test_open());
        registry.bind_erasure_gate(Arc::clone(&gate));
        let cloned = registry.clone_erasure_gate();
        assert!(cloned
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &gate)));

        let registry = registry.without_erasure_gate();
        assert!(registry.clone_erasure_gate().is_none());
    }
}
