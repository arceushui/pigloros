#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{
    pipeline_authority_revision_v1, pipeline_erasure_revision_v1, AppendDedupKey, AppendDedupScope,
    AppendIdentity, ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, AssuranceLevelV1, AuthenticatedPrincipalDraftV1,
    AuthenticatedPrincipalResultV1, AuthorityErrorV1, AuthorityEvaluatorV1, AuthorityGranteeV1,
    AuthorityPersistenceHostV1, AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, AuthorizationRequestDraftV1, AuthorizationRequestV1, CanonicalBytes,
    Capability, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, ConsentEvidenceV1,
    ConsentGrantRefDraftV1, ConsentGrantRefV1, ConsentGrantStatusV1, EntityId,
    ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1,
    Event, EventDraft, Hash, Kind, KnowledgeSnapshotDraftV1, KnowledgeSnapshotV1,
    MemoryPolicyRevisionV1, ObservationSnapshotV1, PersistedAuthorityV1, PipelineAdmissionBasisV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineAttemptIdV1,
    PipelineCommitReceiptV1, PipelineEvidenceRefV1, PipelineOutcomeV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, Plugin, PluginId,
    PrincipalRefV1, Reducer, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
    Seq, SeqRange, State, TimelineId, WallTime,
};
use pos_runtime::{
    AuthorizedDriverTargetV1, AuthorizedDriverViewV1, AuthorizedViewAuthorityV1, Driver,
    ObservationView, PluginRegistry, RuntimeError, ScheduledAdmissionStoreV1,
    ScheduledPassAdmissionV1, StepOutput,
};
use pos_state::{
    AuthorizedObservationV1, ProjectionObservationContextV1, ProjectionObservationPolicyV1,
    ProjectionRegistry,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

fn error_text<T>(result: Result<T, RuntimeError>) -> String {
    match result {
        Ok(_) => std::panic::resume_unwind(Box::new("expected runtime error")),
        Err(error) => error.to_string(),
    }
}

fn authority_error<T>(result: Result<T, RuntimeError>) -> AuthorityErrorV1 {
    match result {
        Err(RuntimeError::Authority(error)) => error,
        Ok(_) => std::panic::resume_unwind(Box::new("expected authority error")),
        Err(error) => {
            std::panic::resume_unwind(Box::new(format!("expected authority error, got: {error}")))
        }
    }
}

const fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn observation_evaluation(observation: &AuthorizedObservationV1) -> ReplayClaimEvaluationV1 {
    observation_evaluation_for(
        observation,
        ArtifactStateV1::Retained,
        ArtifactTransitionRuleV1::PreserveExact,
    )
}

fn observation_evaluation_for(
    observation: &AuthorizedObservationV1,
    state: ArtifactStateV1,
    transition_rule: ArtifactTransitionRuleV1,
) -> ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::ForkOrSnapshot,
                ErasureReferenceV1::from_digest(*observation.artifact_digest().as_bytes()),
                ArtifactDataClassV1::PrivateSubjectData,
                None,
                ErasureReferenceV1::from_digest([242; 32]),
                ArtifactOptionalityV1::Required,
                transition_rule,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state,
        }],
    )
    .test_ok()
}

struct Fixture {
    observation: AuthorizedObservationV1,
    knowledge: KnowledgeSnapshotV1,
    state: AuthorityPersistenceStateV1,
    host: AuthorityPersistenceHostV1,
    authority_registry: AuthorityRegistrySnapshotV1,
    authentication_binding: Hash,
    consent_binding: Hash,
    grant: CapabilityGrantV1,
    plugin_id: PluginId,
    timeline_id: TimelineId,
}

struct FixtureIds {
    principal: PrincipalRefV1,
    participant_id: EntityId,
    plugin_id: PluginId,
    timeline_id: TimelineId,
    authority_timeline: TimelineId,
}

fn capability_grant(
    ids: &FixtureIds,
    actor_id: EntityId,
    subject_id: EntityId,
    consent_id: Hash,
    registry_digest: Hash,
    policy_revision: Hash,
) -> CapabilityGrantV1 {
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["projection.profile".to_owned()],
        actions: vec!["observe".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![actor_id],
        subject_ids: vec![subject_id],
        participant_ids: vec![ids.participant_id],
        plugin_id: Some(ids.plugin_id),
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 2,
        budget: 10,
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok();
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash_from_repeated_byte(10),
        grantor: ids.principal.clone(),
        grantee: AuthorityGranteeV1::PluginInstallation {
            controller: ids.principal.clone(),
            plugin_id: ids.plugin_id,
            installation_id: [11; 16],
        },
        trust_domain: "host.test".to_owned(),
        scope,
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(80),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: Vec::new(),
        consent_references: vec![consent_id],
        policy_revision,
        issuance_timeline: ids.authority_timeline,
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .test_ok()
}

fn consent_grant(
    ids: &FixtureIds,
    actor_id: EntityId,
    subject_id: EntityId,
    consent_id: Hash,
    registry_digest: Hash,
    policy_revision: Hash,
) -> ConsentGrantRefV1 {
    ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
        consent_id,
        subject_id,
        grantee_id: actor_id,
        data_categories: vec!["profile.preferences".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        action_classes: vec!["observe".to_owned()],
        valid_from: WallTime::from_micros(1),
        valid_until: WallTime::from_micros(100),
        withdrawal_retention_policy: "erase-derived-data".to_owned(),
        policy_revision,
        issuer: ids.principal.clone(),
        issuer_evidence: hash_from_repeated_byte(9),
        consent_timeline: ids.authority_timeline,
        grant_position: Seq::from_u64(5),
        status: ConsentGrantStatusV1::Active,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .test_ok()
}

fn authorization_request(
    ids: &FixtureIds,
    actor_id: EntityId,
    subject_id: EntityId,
    registry_digest: Hash,
    policy_revision: Hash,
    consent: ConsentGrantRefV1,
) -> AuthorizationRequestV1 {
    let authenticated =
        AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: ids.principal.clone(),
            adapter_id: "test-adapter".to_owned(),
            assurance: AssuranceLevelV1::try_new(1).test_ok(),
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(100),
            binding_digest: hash_from_repeated_byte(5),
        })
        .test_ok();
    AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
        authenticated,
        actor_entity_id: actor_id,
        subject_id: Some(subject_id),
        participant_id: Some(ids.participant_id),
        plugin_id: Some(ids.plugin_id),
        installation_id: Some([11; 16]),
        principal_role: AuthorityRoleV1::Actor,
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        action: "observe".to_owned(),
        purpose: "planning".to_owned(),
        audience: "local-host".to_owned(),
        at_time: WallTime::from_micros(10),
        authority_timeline: ids.authority_timeline,
        at_position: Seq::from_u64(10),
        consent_timeline: Some(ids.authority_timeline),
        consent_at_position: Some(Seq::from_u64(10)),
        use_count: 1,
        budget: 5,
        consent_policy_revision: policy_revision,
        capability_policy_revision: policy_revision,
        revocation_epoch: 0,
        revocation_state_current: true,
        authority_registry_digest: registry_digest,
        consent: ConsentEvidenceV1::Resolved {
            grants: vec![consent],
        },
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok()
}

fn knowledge_snapshot(snapshot: &pos_core::ObservationSnapshotV1) -> KnowledgeSnapshotV1 {
    KnowledgeSnapshotV1::try_from_observation_snapshot(
        KnowledgeSnapshotDraftV1 {
            principal: snapshot.principal().clone(),
            participant_id: snapshot.participant_id(),
            timeline_id: snapshot.timeline_id(),
            observed_through: snapshot.observed_through(),
            observation_snapshot_digest: snapshot.digest(),
            observations: snapshot.records().to_vec(),
            beliefs: Vec::new(),
            preference_value_revision: None,
            ai_goal_policy_revision: None,
            memory_policy_revision: MemoryPolicyRevisionV1::try_new(hash_from_repeated_byte(21))
                .test_ok(),
            prior_snapshot_digest: None,
            external_provenance: Vec::new(),
            provenance_digest: hash_from_repeated_byte(22),
        },
        snapshot,
    )
    .test_ok()
}

fn fixture() -> Fixture {
    fixture_with_timeline(TimelineId::new())
}

fn empty_profile_projections() -> ProjectionRegistry {
    let mut projections = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    projections
        .register_observable(
            "profile",
            Box::new(EmptyReducer),
            ProjectionObservationPolicyV1::try_new(
                vec!["count".to_owned()],
                "profile.v1".to_owned(),
                hash_from_repeated_byte(18),
                hash_from_repeated_byte(19),
                hash_from_repeated_byte(15),
            )
            .test_ok(),
        )
        .test_ok();
    projections
}

fn fixture_with_timeline(timeline_id: TimelineId) -> Fixture {
    let ids = FixtureIds {
        principal: PrincipalRefV1::try_new([1; 16], "host.test").test_ok(),
        participant_id: EntityId::new(),
        plugin_id: PluginId::new(),
        timeline_id,
        authority_timeline: TimelineId::new(),
    };
    let registry_digest = hash_from_repeated_byte(6);
    let policy_revision = hash_from_repeated_byte(7);
    let actor_id = EntityId::new();
    let subject_id = EntityId::new();
    let consent_id = hash_from_repeated_byte(8);
    let consent = consent_grant(
        &ids,
        actor_id,
        subject_id,
        consent_id,
        registry_digest,
        policy_revision,
    );
    let grant = capability_grant(
        &ids,
        actor_id,
        subject_id,
        consent_id,
        registry_digest,
        policy_revision,
    );
    let grant_binding = grant.binding_digest().test_ok();
    let request = authorization_request(
        &ids,
        actor_id,
        subject_id,
        registry_digest,
        policy_revision,
        consent.clone(),
    );
    let authentication_binding = request.authenticated().registry_binding_digest();
    let authority_registry = AuthorityRegistrySnapshotV1::try_new(
        registry_digest,
        vec![authentication_binding],
        vec![grant_binding],
        vec![consent.binding_digest()],
    )
    .test_ok();
    let host = AuthorityPersistenceHostV1::new(&authority_registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(host.authorize_grant(&grant).test_ok(), grant.clone())
        .test_ok();
    let authority = state.resolve(grant.grant_id()).test_ok();
    let chain = pos_core::DelegationChainV1::try_from_grants(vec![grant.clone()]).test_ok();
    let decision = AuthorityEvaluatorV1::authorize(&request, &chain, &authority_registry);
    assert!(decision.is_allowed());
    let projections = empty_profile_projections();
    let observation = projections
        .materialize_authorized_observation(
            &request,
            &decision,
            &authority,
            &authority_registry,
            Seq::from_u64(10),
            &ProjectionObservationContextV1 {
                timeline_id,
                observed_through: Seq::from_u64(12),
                reducer: "profile".to_owned(),
                prior_snapshot_digest: None,
            },
        )
        .test_ok();
    let knowledge = knowledge_snapshot(
        observation
            .authoritative_snapshot(&observation_evaluation(&observation))
            .test_ok(),
    );
    Fixture {
        observation,
        knowledge,
        state,
        host,
        authority_registry,
        authentication_binding,
        consent_binding: consent.binding_digest(),
        grant,
        plugin_id: ids.plugin_id,
        timeline_id: ids.timeline_id,
    }
}

fn gated_registry() -> PluginRegistry {
    PluginRegistry::new().with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

struct EmptyReducer;

impl Reducer for EmptyReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &Event) {}
}

struct TestPlugin {
    id: PluginId,
}

impl Plugin for TestPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "participant-driver"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("participant.planned")],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

struct DriverlessPlugin {
    id: PluginId,
}

impl Plugin for DriverlessPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "participant-data"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: Vec::new(),
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct DriverState {
    observed_digest: Option<Hash>,
    knowledge_digest: Option<Hash>,
    participant: Option<EntityId>,
    anchor: Option<Seq>,
    visible: usize,
    emitted: Option<EntityId>,
    saw_raw_state: bool,
    saw_raw_events: bool,
    commits: u32,
    aborts: u32,
}

struct ParticipantDriver {
    state: Arc<Mutex<DriverState>>,
    entity: EntityId,
    event_type: Kind,
    ambient_subscription: Option<pos_runtime::ProjectionKey>,
}

struct ForeignEventOwner {
    id: PluginId,
}

impl Plugin for ForeignEventOwner {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "foreign-event-owner"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("foreign.owned")],
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: false,
        }
    }
}

struct RejectedDriver {
    state: Arc<Mutex<DriverState>>,
    entity: EntityId,
    fail_step: bool,
}

impl Driver for RejectedDriver {
    fn name(&self) -> &'static str {
        "rejected-participant-driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        if self.fail_step {
            return Err(RuntimeError::NoDriver {
                name: self.name().to_owned(),
            });
        }
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new(pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE),
            CanonicalBytes::from_static(b"host-owned"),
        )]))
    }

    fn abort_step(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts += 1;
    }
}

impl Driver for ParticipantDriver {
    fn name(&self) -> &'static str {
        "participant-driver"
    }

    fn subscriptions(&self) -> &[pos_runtime::ProjectionKey] {
        self.ambient_subscription.as_slice()
    }

    fn step(
        &mut self,
        _: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.observed_digest = observations
                .authorized_snapshot()
                .map(ObservationSnapshotV1::digest);
            state.knowledge_digest = observations
                .authorized_knowledge()
                .map(KnowledgeSnapshotV1::digest);
            state.saw_raw_state = self
                .ambient_subscription
                .as_ref()
                .is_some_and(|key| observations.state_for(key).is_some());
            state.saw_raw_events = !observations.events().is_empty();
            state.participant = observations
                .authorized_snapshot()
                .map(ObservationSnapshotV1::participant_id);
            state.anchor = observations
                .anchor()
                .map(pos_runtime::SnapshotAnchor::observed_through);
            state.visible = observations.len();
            state.emitted = Some(self.entity);
        }
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            self.event_type.clone(),
            CanonicalBytes::from_static(b"planned"),
        )]))
    }

    fn commit_step(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commits += 1;
    }

    fn abort_step(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts += 1;
    }
}

fn registry_with_mode(
    fixture: &Fixture,
    ambient: bool,
    mut registry: PluginRegistry,
) -> (PluginRegistry, Arc<Mutex<DriverState>>) {
    let state = Arc::new(Mutex::new(DriverState::default()));
    let driver = ParticipantDriver {
        state: Arc::clone(&state),
        entity: EntityId::new(),
        event_type: Kind::new("participant.planned"),
        ambient_subscription: ambient.then(|| pos_runtime::ProjectionKey::new(EntityId::new())),
    };
    registry
        .register_generated(
            &TestPlugin {
                id: fixture.plugin_id,
            },
            None,
            Some(Box::new(driver)),
        )
        .test_ok();
    (registry, state)
}

fn registry(fixture: &Fixture, ambient: bool) -> (PluginRegistry, Arc<Mutex<DriverState>>) {
    registry_with_mode(fixture, ambient, gated_registry())
}

fn current_authority(fixture: &Fixture) -> PersistedAuthorityV1 {
    fixture.state.resolve(fixture.grant.grant_id()).test_ok()
}

fn registry_without_consent(fixture: &Fixture) -> AuthorityRegistrySnapshotV1 {
    AuthorityRegistrySnapshotV1::try_new(
        fixture.authority_registry.registry_digest(),
        vec![fixture.authentication_binding],
        vec![fixture.grant.binding_digest().test_ok()],
        Vec::new(),
    )
    .test_ok()
}

fn registry_without_capability(fixture: &Fixture) -> AuthorityRegistrySnapshotV1 {
    AuthorityRegistrySnapshotV1::try_new(
        fixture.authority_registry.registry_digest(),
        vec![fixture.authentication_binding],
        Vec::new(),
        vec![fixture.consent_binding],
    )
    .test_ok()
}

fn stage_current(
    registry: &mut PluginRegistry,
    fixture: &Fixture,
) -> Result<Vec<EventDraft>, RuntimeError> {
    stage_view(
        registry,
        fixture.timeline_id,
        driver_view(fixture),
        view_authority(
            fixture,
            &observation_evaluation(&fixture.observation),
            &current_authority(fixture),
        ),
    )
}

const fn view_authority<'a>(
    fixture: &'a Fixture,
    evaluation: &'a ReplayClaimEvaluationV1,
    authority: &'a PersistedAuthorityV1,
) -> AuthorizedViewAuthorityV1<'a> {
    AuthorizedViewAuthorityV1 {
        artifact_evaluation: evaluation,
        authority,
        authority_registry: &fixture.authority_registry,
        authority_position: Seq::from_u64(10),
    }
}

fn driver_view(fixture: &Fixture) -> AuthorizedDriverViewV1 {
    AuthorizedDriverViewV1 {
        target: AuthorizedDriverTargetV1::new(fixture.plugin_id, fixture.timeline_id),
        observation: fixture.observation.clone(),
        knowledge: fixture.knowledge.clone(),
    }
}

/// Stage a one-Driver authorized pass at the fixture's base cut.
fn stage_view(
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    view: AuthorizedDriverViewV1,
    authority: AuthorizedViewAuthorityV1<'_>,
) -> Result<Vec<EventDraft>, RuntimeError> {
    registry.stage_authorized_scheduled_pass(timeline, Seq::from_u64(12), &[view], &[authority])
}

/// Host admission inputs for a port that has no published fence.
fn unfenced_admission() -> ScheduledPassAdmissionV1 {
    ScheduledPassAdmissionV1 {
        attempt_id: PipelineAttemptIdV1::try_new([1; 16]).test_ok(),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([2; 32]),
            AppendDedupScope::from_keyed_hash([3; 32]),
        ),
        provider_validation: PipelineEvidenceRefV1::try_new(hash_from_repeated_byte(4)).test_ok(),
        security_revisions: PipelineSecurityRevisionsV1::try_from_draft(
            PipelineSecurityRevisionsDraftV1 {
                authority: hash_from_repeated_byte(5),
                consent: hash_from_repeated_byte(6),
                capability: hash_from_repeated_byte(7),
                delegation: hash_from_repeated_byte(8),
                policy: hash_from_repeated_byte(9),
                execution_profile: hash_from_repeated_byte(10),
                erasure: hash_from_repeated_byte(11),
            },
        )
        .test_ok(),
        commit_head: Seq::from_u64(12),
        commit_now_secs: 1,
    }
}

/// Admit a one-Driver authorized pass through a port without a fence.
fn admit_unfenced(
    registry: &mut PluginRegistry,
    authority: AuthorizedViewAuthorityV1<'_>,
) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
    registry.admit_authorized_scheduled_pass(
        &mut MemoryStore::new(),
        &unfenced_admission(),
        &[authority],
    )
}

/// Root authority grant named by a prepared store's admission fence.
fn admission_root_grant() -> CapabilityGrantV1 {
    let principal = PrincipalRefV1::try_new([40; 16], "local.test").test_ok();
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash_from_repeated_byte(41),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::Principal(principal),
        trust_domain: "local.test".to_owned(),
        scope: CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["timeline".to_owned()],
            actions: vec!["scheduled.admit".to_owned()],
            purposes: vec!["simulation".to_owned()],
            audiences: vec!["local-host".to_owned()],
            actor_entity_ids: vec![EntityId::from_ulid(ulid::Ulid(42))],
            subject_ids: Vec::new(),
            participant_ids: Vec::new(),
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 10,
            budget: 100,
            environment_constraints: vec!["local-only".to_owned()],
        })
        .test_ok(),
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: Vec::new(),
        consent_references: Vec::new(),
        policy_revision: hash_from_repeated_byte(43),
        issuance_timeline: TimelineId::from_ulid(ulid::Ulid(44)),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: hash_from_repeated_byte(45),
    })
    .test_ok()
}

/// One store whose Timeline holds the 12-Event base cut and a published
/// admission fence.
struct AdmissionStore {
    store: Box<dyn ScheduledAdmissionStoreV1>,
    timeline: TimelineId,
    revisions: PipelineSecurityRevisionsV1,
}

impl AdmissionStore {
    fn prepare(mut store: Box<dyn ScheduledAdmissionStoreV1>) -> Self {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        store
            .bind_erasure_gate(Arc::<ErasureContainmentGateV1>::clone(&gate))
            .test_ok();
        let timeline = store
            .create_timeline("authorized-scheduled-pass")
            .test_ok()
            .id();
        let prior: Vec<EventDraft> = (0..12)
            .map(|_| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new("world.prior"),
                    CanonicalBytes::from_static(b"prior"),
                )
            })
            .collect();
        store.append(timeline, &prior).test_ok();
        let root = admission_root_grant();
        let host = AuthorityPersistenceHostV1::new(
            &AuthorityRegistrySnapshotV1::try_new(
                hash_from_repeated_byte(45),
                vec![hash_from_repeated_byte(46)],
                vec![root.binding_digest().test_ok()],
                Vec::new(),
            )
            .test_ok(),
        );
        store
            .bind_authority_persistence(host.persistence_binding())
            .test_ok();
        store
            .issue_capability_grant(host.authorize_grant(&root).test_ok(), &root)
            .test_ok();
        let revisions =
            PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
                authority: pipeline_authority_revision_v1(
                    &store.load_authority(root.grant_id()).test_ok(),
                ),
                consent: hash_from_repeated_byte(51),
                capability: hash_from_repeated_byte(52),
                delegation: hash_from_repeated_byte(53),
                policy: hash_from_repeated_byte(54),
                execution_profile: hash_from_repeated_byte(55),
                erasure: pipeline_erasure_revision_v1(gate.inventory_generation().ok()),
            })
            .test_ok();
        store
            .set_pipeline_admission_fence(
                timeline,
                PipelineAdmissionFenceV1::try_new(root.grant_id(), revisions, None, 100).test_ok(),
            )
            .test_ok();
        Self {
            store,
            timeline,
            revisions,
        }
    }

    /// Host admission inputs read after the pass finished.
    fn admission(&self, key: u8) -> ScheduledPassAdmissionV1 {
        ScheduledPassAdmissionV1 {
            attempt_id: PipelineAttemptIdV1::try_new([key; 16]).test_ok(),
            idempotency: AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([key; 32]),
                AppendDedupScope::from_keyed_hash([62; 32]),
            ),
            provider_validation: PipelineEvidenceRefV1::try_new(hash_from_repeated_byte(60))
                .test_ok(),
            security_revisions: self.revisions,
            commit_head: self.store.logical_head(self.timeline).test_ok(),
            commit_now_secs: 1,
        }
    }

    /// Events committed after the 12-Event base cut.
    fn committed(&self) -> Vec<Event> {
        self.store
            .read(self.timeline, SeqRange::all())
            .test_ok()
            .split_off(12)
    }
}

/// A `MemoryStore` and a `SQLite` store, each prepared at the base cut.
fn admission_stores() -> Vec<(&'static str, AdmissionStore)> {
    vec![
        (
            "memory",
            AdmissionStore::prepare(Box::new(MemoryStore::new())),
        ),
        (
            "sqlite",
            AdmissionStore::prepare(Box::new(SqliteStore::open(":memory:").test_ok())),
        ),
    ]
}

/// Records the observation anchor of every submitted basis.
struct RecordingPort<'a> {
    inner: &'a mut dyn ScheduledAdmissionStoreV1,
    anchors: Vec<(Seq, Hash)>,
}

impl PipelineAdmissionPortV1 for RecordingPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, pos_core::CoreError> {
        let observation = basis.attempt().observation();
        self.anchors.push((
            observation.observed_through(),
            observation.snapshot_digest(),
        ));
        self.inner.admit_pipeline_batch(basis)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<pos_core::PurgeOutcome, pos_core::CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }
}

/// Copy what a Driver recorded, releasing its lock at once.
fn observed(state: &Arc<Mutex<DriverState>>) -> DriverState {
    *state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn authorized_driver_receives_only_the_bound_snapshot_and_requires_its_commit_fence() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    let drafts = stage_current(&mut registry, &fixture).test_ok();
    let observed = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        observed.observed_digest,
        Some(
            fixture
                .observation
                .authoritative_snapshot(&observation_evaluation(&fixture.observation))
                .test_ok()
                .digest()
        )
    );
    assert_eq!(observed.knowledge_digest, Some(fixture.knowledge.digest()));
    assert!(!observed.saw_raw_state);
    assert!(!observed.saw_raw_events);
    drop(observed);

    assert!(error_text(registry.commit_step_at(Seq::from_u64(12), 0))
        .contains("requires a fresh authority fence"));
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1
    );
}

#[test]
fn replay_rejects_authorized_driver_before_invocation() {
    let fixture = fixture();
    let (mut replay, state) = registry_with_mode(&fixture, false, PluginRegistry::new_replay());

    assert_eq!(
        error_text(stage_current(&mut replay, &fixture)),
        "recorder mode mismatch: expected Live, got Replay"
    );
    let (observed_digest, knowledge_digest, commits, aborts) = {
        let observed = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            observed.observed_digest,
            observed.knowledge_digest,
            observed.commits,
            observed.aborts,
        )
    };
    assert_eq!(observed_digest, None);
    assert_eq!(knowledge_digest, None);
    assert_eq!(commits, 0);
    assert_eq!(aborts, 0);
}

#[test]
fn authorized_driver_rejects_mismatched_or_ambient_inputs_before_invocation() {
    let fixture = fixture();
    let (mut mismatched, mismatch_state) = registry(&fixture, false);
    let authority = current_authority(&fixture);
    assert!(error_text(stage_view(
        &mut mismatched,
        fixture.timeline_id,
        AuthorizedDriverViewV1 {
            target: AuthorizedDriverTargetV1::new(fixture.plugin_id, TimelineId::new()),
            observation: fixture.observation.clone(),
            knowledge: fixture.knowledge.clone()
        },
        AuthorizedViewAuthorityV1 {
            artifact_evaluation: &observation_evaluation(&fixture.observation),
            authority: &authority,
            authority_registry: &fixture.authority_registry,
            authority_position: Seq::from_u64(10)
        }
    ))
    .contains("authority source is unauthorized"));
    assert_eq!(
        mismatch_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_digest,
        None
    );

    let (mut wrong_knowledge, knowledge_state) = registry(&fixture, false);
    assert!(error_text(stage_view(
        &mut wrong_knowledge,
        fixture.timeline_id,
        AuthorizedDriverViewV1 {
            target: AuthorizedDriverTargetV1::new(fixture.plugin_id, fixture.timeline_id),
            observation: fixture.observation.clone(),
            knowledge: fixture_with_timeline(fixture.timeline_id).knowledge
        },
        AuthorizedViewAuthorityV1 {
            artifact_evaluation: &observation_evaluation(&fixture.observation),
            authority: &authority,
            authority_registry: &fixture.authority_registry,
            authority_position: Seq::from_u64(10)
        }
    ))
    .contains("provenance is missing"));
    assert_eq!(
        knowledge_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_digest,
        None
    );

    let (mut ambient, ambient_state) = registry(&fixture, true);
    assert!(error_text(stage_view(
        &mut ambient,
        fixture.timeline_id,
        driver_view(&fixture),
        view_authority(
            &fixture,
            &observation_evaluation(&fixture.observation),
            &authority
        )
    ))
    .contains("authority source is unauthorized"));
    assert_eq!(
        ambient_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_digest,
        None
    );
}

#[test]
fn authority_is_revalidated_before_any_staged_draft_is_appended() {
    let mut fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: fixture.grant.grant_id(),
        authority_timeline: fixture.grant.issuance_timeline(),
        fence_position: Seq::from_u64(11),
        revocation_epoch: 1,
        policy_revision: fixture.grant.policy_revision(),
        authority_registry_digest: fixture.grant.authority_registry_digest(),
    })
    .test_ok();
    fixture
        .state
        .revoke_grant(
            fixture
                .host
                .authorize_revocation(&fixture.grant, &revocation)
                .test_ok(),
            revocation,
        )
        .test_ok();
    let authority = fixture.state.resolve(fixture.grant.grant_id()).test_ok();
    let evaluation = observation_evaluation(&fixture.observation);

    assert_eq!(
        authority_error(admit_unfenced(
            &mut registry,
            AuthorizedViewAuthorityV1 {
                authority_position: Seq::from_u64(11),
                ..view_authority(&fixture, &evaluation, &authority)
            },
        )),
        AuthorityErrorV1::CapabilityMissing
    );
    let state = observed(&state);
    assert_eq!((state.aborts, state.commits), (1, 0));
}

#[test]
fn current_consent_is_required_before_driver_invocation() {
    let fixture = fixture();
    let authority = current_authority(&fixture);
    let (mut registry, state) = registry(&fixture, false);

    assert_eq!(
        authority_error(stage_view(
            &mut registry,
            fixture.timeline_id,
            AuthorizedDriverViewV1 {
                target: AuthorizedDriverTargetV1::new(fixture.plugin_id, fixture.timeline_id),
                observation: fixture.observation.clone(),
                knowledge: fixture.knowledge.clone()
            },
            AuthorizedViewAuthorityV1 {
                artifact_evaluation: &observation_evaluation(&fixture.observation),
                authority: &authority,
                authority_registry: &registry_without_consent(&fixture),
                authority_position: Seq::from_u64(10)
            }
        )),
        AuthorityErrorV1::ConsentMissing
    );
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_digest,
        None
    );
}

#[test]
fn consent_revocation_after_staging_aborts_before_append() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
    let evaluation = observation_evaluation(&fixture.observation);
    let authority = current_authority(&fixture);
    let without_consent = registry_without_consent(&fixture);

    assert_eq!(
        authority_error(admit_unfenced(
            &mut registry,
            AuthorizedViewAuthorityV1 {
                authority_registry: &without_consent,
                authority_position: Seq::from_u64(11),
                ..view_authority(&fixture, &evaluation, &authority)
            },
        )),
        AuthorityErrorV1::ConsentMissing
    );
    let state = observed(&state);
    assert_eq!((state.aborts, state.commits), (1, 0));
}

#[test]
fn capability_removal_after_staging_aborts_without_append() {
    for (name, mut prepared) in admission_stores() {
        let fixture = fixture_with_timeline(prepared.timeline);
        let (mut registry, state) = registry(&fixture, false);
        assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
        let evaluation = observation_evaluation(&fixture.observation);
        let authority = current_authority(&fixture);
        let without_capability = registry_without_capability(&fixture);
        let admission = prepared.admission(1);

        assert_eq!(
            authority_error(registry.admit_authorized_scheduled_pass(
                prepared.store.as_mut(),
                &admission,
                &[AuthorizedViewAuthorityV1 {
                    authority_registry: &without_capability,
                    ..view_authority(&fixture, &evaluation, &authority)
                }],
            )),
            AuthorityErrorV1::CapabilityMissing,
            "{name}"
        );
        assert!(prepared.committed().is_empty(), "{name}");
        let state = observed(&state);
        assert_eq!((state.aborts, state.commits), (1, 0), "{name}");
    }
}

#[test]
fn revoked_authority_is_rejected_before_driver_invocation() {
    let mut fixture = fixture();
    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: fixture.grant.grant_id(),
        authority_timeline: fixture.grant.issuance_timeline(),
        fence_position: Seq::from_u64(11),
        revocation_epoch: 1,
        policy_revision: fixture.grant.policy_revision(),
        authority_registry_digest: fixture.grant.authority_registry_digest(),
    })
    .test_ok();
    fixture
        .state
        .revoke_grant(
            fixture
                .host
                .authorize_revocation(&fixture.grant, &revocation)
                .test_ok(),
            revocation,
        )
        .test_ok();
    let authority = current_authority(&fixture);
    let (mut registry, state) = registry(&fixture, false);

    assert_eq!(
        authority_error(stage_view(
            &mut registry,
            fixture.timeline_id,
            AuthorizedDriverViewV1 {
                target: AuthorizedDriverTargetV1::new(fixture.plugin_id, fixture.timeline_id),
                observation: fixture.observation.clone(),
                knowledge: fixture.knowledge.clone()
            },
            AuthorizedViewAuthorityV1 {
                artifact_evaluation: &observation_evaluation(&fixture.observation),
                authority: &authority,
                authority_registry: &fixture.authority_registry,
                authority_position: Seq::from_u64(11)
            }
        )),
        AuthorityErrorV1::CapabilityMissing
    );
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_digest,
        None
    );
}

#[test]
fn authorized_work_commits_only_the_retained_staged_drafts() {
    for (name, mut prepared) in admission_stores() {
        let fixture = fixture_with_timeline(prepared.timeline);
        let (mut registry, _) = registry(&fixture, false);
        let mut returned = stage_current(&mut registry, &fixture).test_ok();
        returned[0].payload = CanonicalBytes::from_static(b"substituted");
        let evaluation = observation_evaluation(&fixture.observation);
        let authority = current_authority(&fixture);
        let admission = prepared.admission(2);

        assert!(registry
            .admit_authorized_scheduled_pass(
                prepared.store.as_mut(),
                &admission,
                &[view_authority(&fixture, &evaluation, &authority)],
            )
            .test_ok()
            .is_some());
        let committed = prepared.committed();
        assert_eq!(committed.len(), 1, "{name}");
        assert_eq!(committed[0].payload.as_slice(), b"planned", "{name}");
    }
}

#[test]
fn current_authority_fence_admits_then_commits_the_driver() {
    for (name, mut prepared) in admission_stores() {
        let fixture = fixture_with_timeline(prepared.timeline);
        let (mut registry, state) = registry(&fixture, false);
        assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
        let evaluation = observation_evaluation(&fixture.observation);
        let authority = current_authority(&fixture);
        let admission = prepared.admission(3);

        let receipt = registry
            .admit_authorized_scheduled_pass(
                prepared.store.as_mut(),
                &admission,
                &[view_authority(&fixture, &evaluation, &authority)],
            )
            .test_ok();
        assert_eq!(
            receipt.map(|receipt| receipt.committed_events().len()),
            Some(1),
            "{name}"
        );
        assert_eq!(prepared.committed().len(), 1, "{name}");
        let state = observed(&state);
        assert_eq!((state.aborts, state.commits), (0, 1), "{name}");
    }
}

#[test]
fn erased_observation_between_stage_and_commit_aborts_without_appending() {
    for (name, mut prepared) in admission_stores() {
        let fixture = fixture_with_timeline(prepared.timeline);
        let (mut registry, state) = registry(&fixture, false);
        assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
        let erased = observation_evaluation_for(
            &fixture.observation,
            ArtifactStateV1::Erased,
            ArtifactTransitionRuleV1::Remove,
        );
        let authority = current_authority(&fixture);
        let admission = prepared.admission(4);

        assert_eq!(
            authority_error(registry.admit_authorized_scheduled_pass(
                prepared.store.as_mut(),
                &admission,
                &[view_authority(&fixture, &erased, &authority)],
            )),
            AuthorityErrorV1::SourceUnavailable,
            "{name}"
        );
        assert!(prepared.committed().is_empty(), "{name}");
        let state = observed(&state);
        assert_eq!((state.aborts, state.commits), (1, 0), "{name}");
    }
}

#[test]
fn authorized_staging_and_commit_failures_are_closed_and_abortable() {
    let fixture = fixture();
    let authority = current_authority(&fixture);
    let mut missing = gated_registry();
    assert!(error_text(stage_view(
        &mut missing,
        fixture.timeline_id,
        driver_view(&fixture),
        view_authority(
            &fixture,
            &observation_evaluation(&fixture.observation),
            &authority
        )
    ))
    .contains("has no driver"));

    let mut driverless = gated_registry();
    driverless
        .register_generated(
            &DriverlessPlugin {
                id: fixture.plugin_id,
            },
            None,
            None,
        )
        .test_ok();
    assert!(error_text(stage_view(
        &mut driverless,
        fixture.timeline_id,
        driver_view(&fixture),
        view_authority(
            &fixture,
            &observation_evaluation(&fixture.observation),
            &authority
        )
    ))
    .contains("has no driver"));

    let (limited, limited_state) = registry(&fixture, false);
    let mut limited = limited.with_resource_limit(0);
    let exhausted = error_text(stage_view(
        &mut limited,
        fixture.timeline_id,
        driver_view(&fixture),
        view_authority(
            &fixture,
            &observation_evaluation(&fixture.observation),
            &authority,
        ),
    ));
    assert!(exhausted.contains("requested=1"));
    assert!(exhausted.contains("limit=0"));
    assert_eq!(
        limited_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1
    );

    let (mut registry, state) = registry(&fixture, false);
    assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
    let evaluation = observation_evaluation(&fixture.observation);
    assert!(error_text(admit_unfenced(
        &mut registry,
        view_authority(&fixture, &evaluation, &authority),
    ))
    .contains("store error"));
    assert_eq!(observed(&state).aborts, 1);
    assert!(error_text(admit_unfenced(
        &mut registry,
        view_authority(&fixture, &evaluation, &authority),
    ))
    .contains("already pending"));
}

#[test]
fn authorized_staging_aborts_driver_and_host_owned_draft_failures() {
    let fixture = fixture();
    let authority = current_authority(&fixture);
    for (fail_step, expected) in [
        (true, "has no driver"),
        (false, "Gateway-owned consent event type"),
    ] {
        let state = Arc::new(Mutex::new(DriverState::default()));
        let driver = RejectedDriver {
            state: Arc::clone(&state),
            entity: EntityId::new(),
            fail_step,
        };
        let mut registry = gated_registry();
        registry
            .register_generated(
                &TestPlugin {
                    id: fixture.plugin_id,
                },
                None,
                Some(Box::new(driver)),
            )
            .test_ok();

        let error = error_text(stage_view(
            &mut registry,
            fixture.timeline_id,
            driver_view(&fixture),
            view_authority(
                &fixture,
                &observation_evaluation(&fixture.observation),
                &authority,
            ),
        ));
        assert!(error.contains(expected));
        assert_eq!(
            state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .aborts,
            1
        );
    }
}

#[test]
fn authorized_driver_cannot_emit_another_plugins_registered_event_type() {
    let fixture = fixture();
    let state = Arc::new(Mutex::new(DriverState::default()));
    let driver = ParticipantDriver {
        state: Arc::clone(&state),
        entity: EntityId::new(),
        event_type: Kind::new("foreign.owned"),
        ambient_subscription: None,
    };
    let mut registry = gated_registry();
    registry
        .register_generated(
            &TestPlugin {
                id: fixture.plugin_id,
            },
            None,
            Some(Box::new(driver)),
        )
        .test_ok();
    registry
        .register_generated(
            &ForeignEventOwner {
                id: PluginId::new(),
            },
            None,
            None,
        )
        .test_ok();

    assert_eq!(
        authority_error(stage_view(
            &mut registry,
            fixture.timeline_id,
            driver_view(&fixture),
            view_authority(
                &fixture,
                &observation_evaluation(&fixture.observation),
                &current_authority(&fixture)
            )
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    let (aborts, commits) = {
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.aborts, state.commits)
    };
    assert_eq!(aborts, 1);
    assert_eq!(commits, 0);
}

#[test]
fn authorized_driver_accepts_its_exact_resource_limit() {
    let fixture = fixture();
    let (registry, state) = registry(&fixture, false);
    let mut registry = registry.with_resource_limit(1);

    let drafts = stage_current(&mut registry, &fixture).test_ok();

    assert_eq!(drafts.len(), 1);
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        0
    );
}

#[test]
fn authorized_commit_rejects_a_legacy_pending_step() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    registry
        .step_all_anchored(fixture.timeline_id, Seq::from_u64(12))
        .test_ok();
    let evaluation = observation_evaluation(&fixture.observation);
    let authority = current_authority(&fixture);

    assert_eq!(
        authority_error(admit_unfenced(
            &mut registry,
            view_authority(&fixture, &evaluation, &authority),
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    assert_eq!(observed(&state).aborts, 1);
}

#[test]
fn scheduled_admission_refuses_participant_authorized_work() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
    let mut port = MemoryStore::new();
    let admission = unfenced_admission();

    let refused = registry.admit_scheduled_pass(&mut port, &admission);
    match refused {
        Err(RuntimeError::AuthorityFenceRequired) => {}
        Ok(_) => std::panic::resume_unwind(Box::new("expected authority fence error")),
        Err(other) => std::panic::resume_unwind(Box::new(format!(
            "expected authority fence error, got: {other}"
        ))),
    }
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1,
        "every staged Driver is aborted"
    );
    assert!(
        error_text(registry.admit_scheduled_pass(&mut port, &admission))
            .contains("Driver step is already pending")
    );
}

#[test]
fn authorized_staging_requires_the_registry_erasure_gate() {
    let fixture = fixture();
    let (registry, state) = registry(&fixture, false);
    let mut registry = registry.without_erasure_gate();

    assert!(error_text(stage_current(&mut registry, &fixture)).contains("erasure containment gate"));
    assert_eq!(observed(&state).observed_digest, None);
}

/// Two participant Drivers registered in host schedule order.
fn two_participants(
    first: &Fixture,
    second: &Fixture,
    second_ambient: bool,
) -> (PluginRegistry, [Arc<Mutex<DriverState>>; 2]) {
    let (registry, first_state) = registry_with_mode(first, false, gated_registry());
    let (registry, second_state) = registry_with_mode(second, second_ambient, registry);
    (registry, [first_state, second_state])
}

fn revoke(fixture: &mut Fixture) {
    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: fixture.grant.grant_id(),
        authority_timeline: fixture.grant.issuance_timeline(),
        fence_position: Seq::from_u64(11),
        revocation_epoch: 1,
        policy_revision: fixture.grant.policy_revision(),
        authority_registry_digest: fixture.grant.authority_registry_digest(),
    })
    .test_ok();
    fixture
        .state
        .revoke_grant(
            fixture
                .host
                .authorize_revocation(&fixture.grant, &revocation)
                .test_ok(),
            revocation,
        )
        .test_ok();
}

/// Stage and admit one authorized pass, returning the bound observation anchor.
fn admit_recorded(
    registry: &mut PluginRegistry,
    prepared: &mut AdmissionStore,
    key: u8,
    views: &[AuthorizedDriverViewV1],
    authorities: &[AuthorizedViewAuthorityV1<'_>],
) -> (Seq, Hash) {
    registry
        .stage_authorized_scheduled_pass(prepared.timeline, Seq::from_u64(12), views, authorities)
        .test_ok();
    let admission = prepared.admission(key);
    let mut port = RecordingPort {
        inner: prepared.store.as_mut(),
        anchors: Vec::new(),
    };
    let receipt = registry
        .admit_authorized_scheduled_pass(&mut port, &admission, authorities)
        .test_ok();
    assert_eq!(
        receipt.map(|receipt| receipt.committed_events().len()),
        Some(views.len())
    );
    assert_eq!(port.anchors.len(), 1);
    port.anchors[0]
}

#[test]
fn each_scheduled_driver_observes_only_its_own_authorized_view() {
    for (name, mut prepared) in admission_stores() {
        let first = fixture_with_timeline(prepared.timeline);
        let second = fixture_with_timeline(prepared.timeline);
        let (mut registry, [first_state, second_state]) = two_participants(&first, &second, false);
        let first_evaluation = observation_evaluation(&first.observation);
        let second_evaluation = observation_evaluation(&second.observation);
        let first_authority = current_authority(&first);
        let second_authority = current_authority(&second);
        let authorities = [
            view_authority(&first, &first_evaluation, &first_authority),
            view_authority(&second, &second_evaluation, &second_authority),
        ];
        let views = [driver_view(&first), driver_view(&second)];

        let (observed_through, both) =
            admit_recorded(&mut registry, &mut prepared, 5, &views, &authorities);

        assert_eq!(observed_through, Seq::from_u64(12), "{name}");
        for (state, own, other) in [
            (&first_state, &first, &second),
            (&second_state, &second, &first),
        ] {
            let own_evaluation = observation_evaluation(&own.observation);
            let other_evaluation = observation_evaluation(&other.observation);
            let own_snapshot = own
                .observation
                .authoritative_snapshot(&own_evaluation)
                .test_ok();
            let other_snapshot = other
                .observation
                .authoritative_snapshot(&other_evaluation)
                .test_ok();
            let state = observed(state);
            assert_eq!(state.observed_digest, Some(own_snapshot.digest()), "{name}");
            assert_ne!(
                state.observed_digest,
                Some(other_snapshot.digest()),
                "{name}"
            );
            assert_eq!(
                state.knowledge_digest,
                Some(own.knowledge.digest()),
                "{name}"
            );
            assert_eq!(
                state.participant,
                Some(own_snapshot.participant_id()),
                "{name}"
            );
            assert_ne!(
                state.participant,
                Some(other_snapshot.participant_id()),
                "{name}"
            );
            assert_eq!(state.visible, own_snapshot.records().len(), "{name}");
            assert_eq!(state.anchor, Some(Seq::from_u64(12)), "{name}");
            assert!(!state.saw_raw_state, "{name}");
            assert!(!state.saw_raw_events, "{name}");
            assert_eq!((state.aborts, state.commits), (0, 1), "{name}");
        }
        let committed: Vec<Option<EntityId>> = prepared
            .committed()
            .iter()
            .map(|event| Some(event.entity))
            .collect();
        assert_eq!(
            committed,
            vec![
                observed(&first_state).emitted,
                observed(&second_state).emitted
            ],
            "{name}: one batch in host schedule order"
        );

        let alone = admit_recorded(
            &mut registry,
            &mut prepared,
            6,
            &views[..1],
            &authorities[..1],
        );
        let again = admit_recorded(&mut registry, &mut prepared, 7, &views, &authorities);
        assert_ne!(alone.1, both, "{name}: the basis binds every view");
        assert_eq!(again.1, both, "{name}: the binding is deterministic");
    }
}

#[test]
fn late_revocation_of_one_view_aborts_the_whole_scheduled_pass() {
    for (name, mut prepared) in admission_stores() {
        let first = fixture_with_timeline(prepared.timeline);
        let mut second = fixture_with_timeline(prepared.timeline);
        let (mut registry, states) = two_participants(&first, &second, false);
        let first_evaluation = observation_evaluation(&first.observation);
        let second_evaluation = observation_evaluation(&second.observation);
        let first_authority = current_authority(&first);
        let staged_authority = current_authority(&second);
        registry
            .stage_authorized_scheduled_pass(
                prepared.timeline,
                Seq::from_u64(12),
                &[driver_view(&first), driver_view(&second)],
                &[
                    view_authority(&first, &first_evaluation, &first_authority),
                    view_authority(&second, &second_evaluation, &staged_authority),
                ],
            )
            .test_ok();
        revoke(&mut second);
        let revoked = current_authority(&second);
        let admission = prepared.admission(8);

        assert_eq!(
            authority_error(registry.admit_authorized_scheduled_pass(
                prepared.store.as_mut(),
                &admission,
                &[
                    view_authority(&first, &first_evaluation, &first_authority),
                    AuthorizedViewAuthorityV1 {
                        authority_position: Seq::from_u64(11),
                        ..view_authority(&second, &second_evaluation, &revoked)
                    },
                ],
            )),
            AuthorityErrorV1::CapabilityMissing,
            "{name}"
        );
        assert!(prepared.committed().is_empty(), "{name}");
        for state in &states {
            let state = observed(state);
            assert_eq!((state.aborts, state.commits), (1, 0), "{name}");
        }
    }
}

#[test]
fn a_failing_driver_aborts_every_driver_staged_by_the_pass() {
    let timeline = TimelineId::new();
    let first = fixture_with_timeline(timeline);
    let second = fixture_with_timeline(timeline);
    let (mut registry, [first_state, second_state]) = two_participants(&first, &second, true);
    let first_evaluation = observation_evaluation(&first.observation);
    let second_evaluation = observation_evaluation(&second.observation);
    let first_authority = current_authority(&first);
    let second_authority = current_authority(&second);

    assert_eq!(
        authority_error(registry.stage_authorized_scheduled_pass(
            timeline,
            Seq::from_u64(12),
            &[driver_view(&first), driver_view(&second)],
            &[
                view_authority(&first, &first_evaluation, &first_authority),
                view_authority(&second, &second_evaluation, &second_authority),
            ],
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    assert!(observed(&first_state).observed_digest.is_some());
    assert_eq!(observed(&first_state).aborts, 1);
    assert_eq!(observed(&second_state).observed_digest, None);
    assert!(error_text(admit_unfenced(
        &mut registry,
        view_authority(&first, &first_evaluation, &first_authority),
    ))
    .contains("already pending"));
}

#[test]
fn views_must_follow_host_schedule_order_and_share_the_base_cut() {
    let timeline = TimelineId::new();
    let first = fixture_with_timeline(timeline);
    let second = fixture_with_timeline(timeline);
    let (mut registry, states) = two_participants(&first, &second, false);
    let first_evaluation = observation_evaluation(&first.observation);
    let second_evaluation = observation_evaluation(&second.observation);
    let first_authority = current_authority(&first);
    let second_authority = current_authority(&second);

    assert_eq!(
        authority_error(registry.stage_authorized_scheduled_pass(
            timeline,
            Seq::from_u64(12),
            &[driver_view(&second), driver_view(&first)],
            &[
                view_authority(&second, &second_evaluation, &second_authority),
                view_authority(&first, &first_evaluation, &first_authority),
            ],
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    assert_eq!(
        authority_error(registry.stage_authorized_scheduled_pass(
            timeline,
            Seq::from_u64(11),
            &[driver_view(&first)],
            &[view_authority(&first, &first_evaluation, &first_authority)],
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    assert_eq!(
        authority_error(registry.stage_authorized_scheduled_pass(
            timeline,
            Seq::from_u64(12),
            &[driver_view(&first), driver_view(&second)],
            &[view_authority(&first, &first_evaluation, &first_authority)],
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    for state in &states {
        assert_eq!(observed(state).observed_digest, None);
    }
}

#[test]
fn authorized_admission_requires_one_current_authority_per_view() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    assert_eq!(stage_current(&mut registry, &fixture).test_ok().len(), 1);
    assert!(error_text(stage_current(&mut registry, &fixture)).contains("already pending"));

    assert_eq!(
        authority_error(registry.admit_authorized_scheduled_pass(
            &mut MemoryStore::new(),
            &unfenced_admission(),
            &[],
        )),
        AuthorityErrorV1::UnauthorizedSource
    );
    let state = observed(&state);
    assert_eq!((state.aborts, state.commits), (1, 0));
}

#[test]
fn an_empty_authorized_pass_commits_without_admission() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    assert!(registry
        .stage_authorized_scheduled_pass(fixture.timeline_id, Seq::from_u64(12), &[], &[])
        .test_ok()
        .is_empty());

    assert!(registry
        .admit_authorized_scheduled_pass(&mut MemoryStore::new(), &unfenced_admission(), &[])
        .test_ok()
        .is_none());
    assert_eq!(observed(&state).observed_digest, None);
    assert!(stage_current(&mut registry, &fixture).is_ok());
}
