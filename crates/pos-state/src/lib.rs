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

use std::collections::{BTreeSet, HashMap};

use pos_core::{
    AuthorityErrorV1, AuthorityRegistrySnapshotV1, AuthorizationDecisionV1, AuthorizationRequestV1,
    CanonicalBytes, ConsentEvidenceV1, ConsentRevocationFoldListener, ConsentRevokedV1, EntityId,
    Event, Hash, ObservationArtifactV1, ObservationRecordDraftV1, ObservationRecordV1,
    ObservationSnapshotDraftV1, ObservationSnapshotV1, ObservationStatusV1, PersistedAuthorityV1,
    Reducer, Relationship, Seq, State, StateRegistry, TimelineId, WallTime,
    EVENT_TYPE_CONSENT_REVOKED_V1, MAX_OBSERVATION_SNAPSHOT_RECORDS,
};

// ---------------------------------------------------------------------------
// AuthorizationCacheV1
// ---------------------------------------------------------------------------

/// Exact invalidation identity for one cached active authorization decision.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorizationCacheKeyV1 {
    request_digest: Hash,
    authority_timeline: TimelineId,
    grant_chain_bindings: Vec<Hash>,
    consent_policy_revision: Hash,
    capability_policy_revision: Hash,
    revocation_epoch: u64,
}

impl AuthorizationCacheKeyV1 {
    #[must_use]
    pub fn from_decision(decision: &AuthorizationDecisionV1, revocation_epoch: u64) -> Self {
        Self {
            request_digest: decision.request_digest(),
            authority_timeline: decision.authority_timeline(),
            grant_chain_bindings: decision.grant_chain_bindings().to_vec(),
            consent_policy_revision: decision.consent_policy_revision(),
            capability_policy_revision: decision.capability_policy_revision(),
            revocation_epoch,
        }
    }

    #[must_use]
    pub const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }

    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
}

#[derive(Clone, Debug)]
struct AuthorizationCacheEntryV1 {
    decision: AuthorizationDecisionV1,
    expires_at: WallTime,
    valid_until_position: Seq,
    grant_ids: BTreeSet<Hash>,
    consent_references: BTreeSet<Hash>,
}

/// Current authorized-decision projection with explicit expiry and revocation indexes.
///
/// Only active decisions are admitted. Every lookup supplies the current wall-time and
/// Timeline position, so an entry cannot outlive the shorter of its consent/grant wall
/// expiry and logical-position expiry. Parent and consent indexes make revocation
/// invalidation independent of which chain member was the leaf.
#[derive(Clone, Debug, Default)]
pub struct AuthorizationCacheV1 {
    entries: HashMap<AuthorizationCacheKeyV1, AuthorizationCacheEntryV1>,
}

impl AuthorizationCacheV1 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache an active decision until its derived shortest expiry.
    ///
    /// Returns the exact cache key, or `None` when the decision is denied, the
    /// request does not match the persisted authority state, an expiry is not in
    /// the request's future, or no capability chain is identified.
    pub fn insert_active(
        &mut self,
        decision: AuthorizationDecisionV1,
        request: &AuthorizationRequestV1,
        authority: &PersistedAuthorityV1,
    ) -> Option<AuthorizationCacheKeyV1> {
        let grants = authority.chain().grants();
        let grant_ids = grants
            .iter()
            .map(pos_core::CapabilityGrantV1::grant_id)
            .collect::<BTreeSet<_>>();
        let consent_references = grants
            .iter()
            .flat_map(|grant| grant.consent_references().iter().copied())
            .collect::<BTreeSet<_>>();
        let first_grant = &grants[0];
        let valid_until_position = grants
            .iter()
            .skip(1)
            .fold(first_grant.valid_until_position(), |shortest, grant| {
                shortest.min(grant.valid_until_position())
            });
        let chain_bindings_result = grants
            .iter()
            .map(pos_core::CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>();
        let Ok(chain_bindings) = chain_bindings_result else {
            return None;
        };
        let authentication_expiry = request.authenticated().expires_at();
        let expires_at = match request.consent() {
            ConsentEvidenceV1::Resolved { grants } => grants
                .iter()
                .map(pos_core::ConsentGrantRefV1::valid_until)
                .min()
                .map_or(authentication_expiry, |consent_expiry| {
                    consent_expiry.min(authentication_expiry)
                }),
            _ => authentication_expiry,
        };
        let digest_matches = decision.request_digest() == request.binding_digest();
        let request_matches = digest_matches
            && decision.grant_chain_bindings() == chain_bindings.as_slice()
            && decision.authority_timeline() == request.authority_timeline()
            && decision.at_position() == request.at_position()
            && decision.capability_policy_revision() == request.capability_policy_revision()
            && decision.consent_policy_revision() == request.consent_policy_revision()
            && authority.revocation_epoch() == request.revocation_epoch();
        if !decision.is_allowed()
            || !request_matches
            || request.at_time() >= expires_at
            || valid_until_position <= decision.at_position()
            || grant_ids.is_empty()
        {
            return None;
        }
        let key = AuthorizationCacheKeyV1::from_decision(&decision, authority.revocation_epoch());
        self.entries.insert(
            key.clone(),
            AuthorizationCacheEntryV1 {
                decision,
                expires_at,
                valid_until_position,
                grant_ids,
                consent_references,
            },
        );
        Some(key)
    }

    /// Read an unexpired decision through its complete invalidation identity.
    pub fn get(
        &mut self,
        key: &AuthorizationCacheKeyV1,
        at_time: WallTime,
        at_position: Seq,
    ) -> Option<&AuthorizationDecisionV1> {
        let expired = self.entries.get(key).is_some_and(|entry| {
            at_time >= entry.expires_at || at_position >= entry.valid_until_position
        });
        if expired {
            self.entries.remove(key);
            None
        } else {
            self.entries.get(key).map(|entry| &entry.decision)
        }
    }

    /// Invalidate every leaf decision derived from this grant or any parent grant.
    pub fn invalidate_grant(&mut self, grant_id: Hash) -> usize {
        self.retain_counted(|entry| !entry.grant_ids.contains(&grant_id))
    }

    /// Invalidate every decision derived from one revoked consent reference.
    pub fn invalidate_consent(&mut self, consent_reference: Hash) -> usize {
        self.retain_counted(|entry| !entry.consent_references.contains(&consent_reference))
    }

    /// Drop stale epochs for one authority Timeline while leaving unrelated Timelines intact.
    pub fn retain_revocation_epoch(
        &mut self,
        authority_timeline: TimelineId,
        current_epoch: u64,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|key, _| {
            key.authority_timeline() != authority_timeline
                || key.revocation_epoch() == current_epoch
        });
        before.saturating_sub(self.entries.len())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn retain_counted(
        &mut self,
        mut keep: impl FnMut(&AuthorizationCacheEntryV1) -> bool,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| keep(entry));
        before.saturating_sub(self.entries.len())
    }
}

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

/// One named slot inside the registry.
struct Slot {
    reducer: Box<dyn Reducer>,
    registry: StateRegistry,
    observation_policy: Option<ProjectionObservationPolicyV1>,
}

/// A named registry of [`Reducer`] implementations backed by per-name [`StateRegistry`]s.
///
/// Plugins register reducers during Wave 3 initialisation; the registry then
/// applies every incoming event to every registered reducer in insertion order.
#[derive(Default)]
pub struct ProjectionRegistry {
    /// Ordered list so iteration is deterministic.
    slots: Vec<(String, Slot)>,
}

impl std::fmt::Debug for ProjectionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = Vec::with_capacity(self.slots.len());
        for (name, _) in &self.slots {
            names.push(name.as_str());
        }
        f.debug_struct("ProjectionRegistry")
            .field("reducers", &names)
            .finish()
    }
}

impl ProjectionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        self.slots.retain(|(registered, _)| registered != name);
        self.slots.push((
            name.to_owned(),
            Slot {
                reducer,
                registry: StateRegistry::new(),
                observation_policy,
            },
        ));
    }

    /// Apply a single event to every registered reducer.
    pub fn apply_event(&mut self, event: &Event) {
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

    /// Batch-fold a slice of events into every registered reducer.
    pub fn fold_events(&mut self, events: &[Event]) {
        for event in events {
            self.apply_event(event);
        }
    }

    /// Return the state for a given entity from the **first** registered reducer.
    ///
    /// Returns `None` if no reducers have been registered or the entity is unknown.
    /// To query a specific reducer use [`Self::state_for_reducer`].
    #[must_use]
    pub fn state_for(&self, entity: &EntityId) -> Option<&State> {
        self.slots
            .first()
            .and_then(|(_, slot)| slot.registry.get(entity))
    }

    /// Return the state for a given entity from the reducer identified by `name`.
    #[must_use]
    pub fn state_for_reducer(&self, name: &str, entity: &EntityId) -> Option<&State> {
        self.slots
            .iter()
            .find(|(n, _)| n == name)
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
        authority
            .validate_observation_authorization(
                request,
                decision,
                authority_registry,
                authority_position,
            )
            .and_then(|()| self.materialize_authorized_projection(request, decision, context))
            .map(|snapshot| AuthorizedObservationV1 {
                snapshot,
                request: request.clone(),
                decision: decision.clone(),
            })
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
        let Some(plugin_id) = request.plugin_id() else {
            return Err(AuthorityErrorV1::UnauthorizedSource);
        };
        let Some(installation_id) = request.installation_id() else {
            return Err(AuthorityErrorV1::UnauthorizedSource);
        };
        let Some(slot) = self
            .slots
            .iter()
            .find_map(|(name, slot)| (name == &context.reducer).then_some(slot))
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
                    artifact.map_or(
                        (
                            ObservationStatusV1::NotObserved,
                            None,
                            None,
                            absence_source_digest(context, subject_id),
                            Vec::new(),
                        ),
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
    }

    /// Retain only one subject's accumulated state in every reducer.
    pub fn retain_subject(&mut self, subject: &EntityId) {
        for (_, slot) in &mut self.slots {
            slot.registry.retain_only(subject);
        }
    }

    /// Restore accumulated state from a previously captured snapshot map.
    ///
    /// Resets all accumulated state first (via [`Self::clear_state`]), then
    /// loads the corresponding [`StateRegistry`] for each reducer name found in
    /// `snapshot`. Reducer names present in `snapshot` but not registered are
    /// ignored; registered reducers with no entry in `snapshot` remain empty.
    ///
    /// This is the counterpart of [`Self::state_snapshot`] and is used by
    /// `pos-time` snapshot consistency verification to seed the incremental path.
    pub fn restore_from_snapshot(
        &mut self,
        snapshot: &std::collections::HashMap<String, StateRegistry>,
    ) {
        self.clear_state();
        for (name, slot) in &mut self.slots {
            // Missing snapshot entries stay empty after `clear_state`.
            if let Some(restored) = snapshot.get(name) {
                slot.registry = restored.clone();
            }
        }
    }

    /// Extract a snapshot of all per-reducer state as a serialisable map.
    ///
    /// The returned map is keyed by reducer name and contains each reducer's
    /// accumulated [`StateRegistry`]. This is used by `pos-time` snapshot
    /// capture and consistency verification.
    #[must_use]
    pub fn state_snapshot(&self) -> std::collections::HashMap<String, StateRegistry> {
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
    #[must_use]
    pub fn diff_against_snapshot(
        &self,
        snapshot: &std::collections::HashMap<String, StateRegistry>,
        all_entities: &[EntityId],
    ) -> Option<(String, EntityId)> {
        for (name, slot) in &self.slots {
            let snap_reg = snapshot.get(name).cloned().unwrap_or_default();
            for entity in all_entities {
                if slot.registry.get_or_default(entity) != snap_reg.get_or_default(entity) {
                    return Some((name.clone(), *entity));
                }
            }
        }
        None
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
    request: AuthorizationRequestV1,
    decision: AuthorizationDecisionV1,
}

impl AuthorizedObservationV1 {
    /// Return the minimized immutable OBS1 snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ObservationSnapshotV1 {
        &self.snapshot
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

impl std::ops::Deref for AuthorizedObservationV1 {
    type Target = ObservationSnapshotV1;

    fn deref(&self) -> &Self::Target {
        self.snapshot()
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
        for (_, slot) in &mut self.slots {
            slot.registry.remove(&subject_id);
        }
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
        parent_grant_id: Hash,
        consent_reference: Hash,
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
            parent_grant_id,
            consent_reference,
        }
    }

    // ------------------------------------------------------------------
    // ProjectionRegistry tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_applies_to_all_reducers() {
        let mut registry = ProjectionRegistry::new();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));

        let count_a = registry
            .state_for_reducer("a", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let count_b = registry
            .state_for_reducer("b", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count_a, 1, "reducer 'a' should have seen 1 event");
        assert_eq!(count_b, 1, "reducer 'b' should have seen 1 event");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_retain_subject_filters_every_reducer() {
        let mut registry = ProjectionRegistry::new();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        let unrelated = EntityId::new();
        registry.fold_events(&[make_event(subject), make_event(unrelated)]);

        registry.retain_subject(&subject);

        for name in ["a", "b"] {
            assert!(registry.state_for_reducer(name, &subject).is_some());
            assert!(registry.state_for_reducer(name, &unrelated).is_none());
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_fold_events() {
        let mut registry = ProjectionRegistry::new();
        registry.register("main", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        let events: Vec<Event> = (0..5).map(|_| make_event(entity)).collect();
        registry.fold_events(&events);

        let count = registry
            .state_for_reducer("main", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("event_count should be present"))
            });
        assert_eq!(count, 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn valid_consent_revocation_evicts_each_subject_projection_cache() {
        let mut registry = ProjectionRegistry::new();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        let other = EntityId::new();
        registry.apply_event(&make_event(subject));
        registry.apply_event(&make_event(other));

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
        registry.apply_event(&event);

        assert!(registry.state_for(&subject).is_none());
        assert!(registry.state_for_reducer("b", &subject).is_none());
        assert!(registry.state_for(&other).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn malformed_consent_revocation_does_not_evict_projection_cache() {
        let mut registry = ProjectionRegistry::new();
        registry.register("events", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        registry.apply_event(&make_event(subject));

        let malformed = make_event_typed(subject, EVENT_TYPE_CONSENT_REVOKED_V1);
        registry.apply_event(&malformed);

        assert!(registry.state_for(&subject).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducers_never_observe_reserved_consent_namespace_events() {
        let mut registry = ProjectionRegistry::new();
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
            payload_hash: Hash::from_bytes([0; 32]),
        };
        registry.apply_event(&consent_event);
        assert!(registry.state_for(&entity).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_state_for_returns_first_reducers_view() {
        let mut registry = ProjectionRegistry::new();
        registry.register("first", Box::new(EntityStateProjection));
        registry.register("second", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));

        let state = registry
            .state_for(&entity)
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
        let registry = ProjectionRegistry::new();
        let entity = EntityId::new();
        assert!(registry.state_for(&entity).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authorization_cache_expires_at_the_shortest_time_or_position() {
        let fixture = active_decision(TimelineId::new());
        let mut by_time = AuthorizationCacheV1::new();
        let key = by_time
            .insert_active(
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
            )
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        assert!(by_time
            .get(&key, WallTime::from_micros(99), Seq::from_u64(79))
            .is_some());
        assert!(by_time
            .get(&key, WallTime::from_micros(100), Seq::from_u64(79))
            .is_none());
        assert!(by_time.is_empty());

        let mut by_position = AuthorizationCacheV1::new();
        let key = by_position
            .insert_active(fixture.decision, &fixture.request, &fixture.authority)
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        assert!(by_position
            .get(&key, WallTime::from_micros(99), Seq::from_u64(80))
            .is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authorization_cache_invalidates_parent_consent_and_stale_epoch() {
        let timeline = TimelineId::new();
        let other_timeline = TimelineId::new();
        let fixture = active_decision(timeline);
        let other = active_decision(other_timeline);

        let mut grant_cache = AuthorizationCacheV1::new();
        assert!(grant_cache
            .insert_active(
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
            )
            .is_some());
        assert_eq!(grant_cache.invalidate_grant(fixture.parent_grant_id), 1);
        assert!(grant_cache.is_empty());

        let mut consent_cache = AuthorizationCacheV1::new();
        assert!(consent_cache
            .insert_active(
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
            )
            .is_some());
        assert_eq!(
            consent_cache.invalidate_consent(fixture.consent_reference),
            1
        );

        let mut epoch_cache = AuthorizationCacheV1::new();
        assert!(epoch_cache
            .insert_active(fixture.decision, &fixture.request, &fixture.authority,)
            .is_some());
        assert!(epoch_cache
            .insert_active(other.decision, &other.request, &other.authority,)
            .is_some());
        assert_eq!(epoch_cache.len(), 2);
        assert_eq!(epoch_cache.retain_revocation_epoch(timeline, 1), 1);
        assert_eq!(epoch_cache.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authorization_cache_rejects_mismatched_or_denied_entries() {
        let timeline = TimelineId::new();
        let fixture = active_decision(timeline);
        let mismatched = active_decision(TimelineId::new());
        let mismatched_chain = decision_with_capability_trust(timeline, test_hash(15), true);
        let mut cache = AuthorizationCacheV1::new();
        assert!(cache
            .insert_active(
                fixture.decision.clone(),
                &mismatched.request,
                &fixture.authority,
            )
            .is_none());
        assert!(cache
            .insert_active(
                fixture.decision.clone(),
                &fixture.request,
                &mismatched_chain.authority,
            )
            .is_none());

        let denied = decision_with_capability_trust(timeline, test_hash(5), false);
        assert!(!denied.decision.is_allowed());
        assert!(cache
            .insert_active(denied.decision, &denied.request, &denied.authority,)
            .is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_restore_from_snapshot_skips_unknown_reducers() {
        let mut registry = ProjectionRegistry::new();
        registry.register("registered", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));

        let mut snapshot = std::collections::HashMap::new();
        snapshot.insert("other".to_owned(), StateRegistry::new());
        registry.restore_from_snapshot(&snapshot);

        let count = registry
            .state_for_reducer("registered", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_restore_from_snapshot_loads_matching_reducer() {
        let mut registry = ProjectionRegistry::new();
        registry.register("registered", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));
        let snapshot = registry.state_snapshot();

        let mut restored = ProjectionRegistry::new();
        restored.register("registered", Box::new(EntityStateProjection));
        restored.restore_from_snapshot(&snapshot);

        let count = restored
            .state_for_reducer("registered", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count, 1);
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
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
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
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let count_b = state_reg
            .get(&b)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
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

            let mut reg1 = ProjectionRegistry::new();
            reg1.register("p", Box::new(EntityStateProjection));
            reg1.fold_events(&events);

            let mut reg2 = ProjectionRegistry::new();
            reg2.register("p", Box::new(EntityStateProjection));
            reg2.fold_events(&events);

            let count1 = reg1
                .state_for_reducer("p", &entity)
                .and_then(|s| s.get("event_count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let count2 = reg2
                .state_for_reducer("p", &entity)
                .and_then(|s| s.get("event_count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);

            prop_assert_eq!(count1, count2);
            prop_assert_eq!(count1, n_events as u64);
        }
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

    struct TR;
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_snapshot_identical_returns_none() {
        let entity = EntityId::new();
        let mut reg = ProjectionRegistry::new();
        reg.register("r", Box::new(TR));
        reg.apply_event(&ev(entity));

        let snap = reg.state_snapshot();
        let diff = reg.diff_against_snapshot(&snap, &[entity]);
        assert!(diff.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_snapshot_diverged_returns_some() {
        let entity = EntityId::new();
        let mut reg = ProjectionRegistry::new();
        reg.register("r", Box::new(TR));
        reg.apply_event(&ev(entity));

        let snap = reg.state_snapshot();
        // Apply another event — now reg diverges from the snapshot
        reg.apply_event(&ev(entity));
        let diff = reg.diff_against_snapshot(&snap, &[entity]);
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
        let mut reg = ProjectionRegistry::new();
        reg.register("r", Box::new(TR));
        reg.apply_event(&ev(entity));

        let empty_snap = std::collections::HashMap::new();
        let diff = reg.diff_against_snapshot(&empty_snap, &[entity]);
        assert!(diff.is_some());
    }
}
