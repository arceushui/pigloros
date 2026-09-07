use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityErrorV1, AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1,
    AuthorizationRequestDraftV1, AuthorizationRequestV1, CanonicalBytes, Capability,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, ConsentEvidenceV1, ConsentGrantRefDraftV1,
    ConsentGrantRefV1, ConsentGrantStatusV1, EntityId, Event, EventDraft, Hash, Kind,
    KnowledgeSnapshotDraftV1, KnowledgeSnapshotV1, MemoryPolicyRevisionV1, ObservationSnapshotV1,
    PersistedAuthorityV1, Plugin, PluginId, PrincipalRefV1, Reducer, Seq, SeqRange, State,
    TimelineId, WallTime,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use pos_state::{
    AuthorizedObservationV1, ProjectionObservationContextV1, ProjectionObservationPolicyV1,
    ProjectionRegistry,
};
use pos_store::{open_store, StoreConfig};
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
    let mut projections = ProjectionRegistry::new();
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
    let knowledge = knowledge_snapshot(observation.snapshot());
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

#[derive(Default)]
struct DriverState {
    observed_digest: Option<Hash>,
    knowledge_digest: Option<Hash>,
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

fn registry(fixture: &Fixture, ambient: bool) -> (PluginRegistry, Arc<Mutex<DriverState>>) {
    let state = Arc::new(Mutex::new(DriverState::default()));
    let driver = ParticipantDriver {
        state: Arc::clone(&state),
        entity: EntityId::new(),
        event_type: Kind::new("participant.planned"),
        ambient_subscription: ambient.then(|| pos_runtime::ProjectionKey::new(EntityId::new())),
    };
    let mut registry = PluginRegistry::new();
    registry
        .register(
            &TestPlugin {
                id: fixture.plugin_id,
            },
            None,
            Some(Box::new(driver)),
        )
        .test_ok();
    (registry, state)
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
    registry.stage_authorized_driver(
        fixture.plugin_id,
        fixture.timeline_id,
        fixture.observation.clone(),
        &fixture.knowledge,
        &current_authority(fixture),
        &fixture.authority_registry,
        Seq::from_u64(10),
    )
}

#[test]
fn authorized_driver_receives_only_the_bound_snapshot_and_requires_its_commit_fence() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    let drafts = stage_current(&mut registry, &fixture).test_ok();
    let observed = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(observed.observed_digest, Some(fixture.observation.digest()));
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
fn authorized_driver_rejects_mismatched_or_ambient_inputs_before_invocation() {
    let fixture = fixture();
    let (mut mismatched, mismatch_state) = registry(&fixture, false);
    let authority = current_authority(&fixture);
    assert!(error_text(mismatched.stage_authorized_driver(
        fixture.plugin_id,
        TimelineId::new(),
        fixture.observation.clone(),
        &fixture.knowledge,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
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
    assert!(error_text(wrong_knowledge.stage_authorized_driver(
        fixture.plugin_id,
        fixture.timeline_id,
        fixture.observation.clone(),
        &fixture_with_timeline(fixture.timeline_id).knowledge,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
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
    assert!(error_text(ambient.stage_authorized_driver(
        fixture.plugin_id,
        fixture.timeline_id,
        fixture.observation.clone(),
        &fixture.knowledge,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
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
    let drafts = stage_current(&mut registry, &fixture).test_ok();
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
    let mut store = open_store(StoreConfig::Memory).test_ok();

    assert_eq!(
        authority_error(registry.append_and_commit_authorized_step_at(
            store.as_mut(),
            &drafts,
            &authority,
            &fixture.authority_registry,
            Seq::from_u64(11),
        )),
        AuthorityErrorV1::CapabilityMissing
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
fn current_consent_is_required_before_driver_invocation() {
    let fixture = fixture();
    let authority = current_authority(&fixture);
    let (mut registry, state) = registry(&fixture, false);

    assert_eq!(
        authority_error(registry.stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.observation.clone(),
            &fixture.knowledge,
            &authority,
            &registry_without_consent(&fixture),
            Seq::from_u64(10),
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
    let drafts = stage_current(&mut registry, &fixture).test_ok();
    let mut store = open_store(StoreConfig::Memory).test_ok();

    assert_eq!(
        authority_error(registry.append_and_commit_authorized_step_at(
            store.as_mut(),
            &drafts,
            &current_authority(&fixture),
            &registry_without_consent(&fixture),
            Seq::from_u64(11),
        )),
        AuthorityErrorV1::ConsentMissing
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
fn capability_removal_after_staging_aborts_without_append() {
    let mut store = open_store(StoreConfig::Memory).test_ok();
    let timeline = store
        .create_timeline("authorized-capability-loss")
        .test_ok();
    let fixture = fixture_with_timeline(timeline.id());
    let (mut registry, state) = registry(&fixture, false);
    let drafts = stage_current(&mut registry, &fixture).test_ok();

    assert_eq!(
        authority_error(registry.append_and_commit_authorized_step_at(
            store.as_mut(),
            &drafts,
            &current_authority(&fixture),
            &registry_without_capability(&fixture),
            Seq::from_u64(10),
        )),
        AuthorityErrorV1::CapabilityMissing
    );
    assert!(store
        .read(timeline.id(), SeqRange::all())
        .test_ok()
        .is_empty());
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
        authority_error(registry.stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.observation.clone(),
            &fixture.knowledge,
            &authority,
            &fixture.authority_registry,
            Seq::from_u64(11),
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
fn authorized_work_rejects_legacy_append_and_substituted_drafts() {
    let fixture = fixture();
    let (mut legacy, legacy_state) = registry(&fixture, false);
    let legacy_drafts = stage_current(&mut legacy, &fixture).test_ok();
    let mut legacy_store = open_store(StoreConfig::Memory).test_ok();
    assert!(error_text(legacy.append_and_commit_step_at(
        legacy_store.as_mut(),
        Seq::from_u64(12),
        0,
        &legacy_drafts,
    ))
    .contains("requires a fresh authority fence"));
    assert_eq!(
        legacy_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1
    );

    let (mut substituted, substituted_state) = registry(&fixture, false);
    let mut changed_drafts = stage_current(&mut substituted, &fixture).test_ok();
    changed_drafts[0].payload = CanonicalBytes::from_static(b"substituted");
    let authority = fixture.state.resolve(fixture.grant.grant_id()).test_ok();
    let mut substituted_store = open_store(StoreConfig::Memory).test_ok();
    assert!(error_text(substituted.append_and_commit_authorized_step_at(
        substituted_store.as_mut(),
        &changed_drafts,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
    ))
    .contains("authority source is unauthorized"));
    assert_eq!(
        substituted_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1
    );
}

#[test]
fn current_authority_fence_appends_then_commits_the_driver() {
    let mut store = open_store(StoreConfig::Memory).test_ok();
    let timeline = store.create_timeline("authorized-participant").test_ok();
    let fixture = fixture_with_timeline(timeline.id());
    let (mut registry, state) = registry(&fixture, false);
    let drafts = stage_current(&mut registry, &fixture).test_ok();
    let authority = fixture.state.resolve(fixture.grant.grant_id()).test_ok();
    let events = registry
        .append_and_commit_authorized_step_at(
            store.as_mut(),
            &drafts,
            &authority,
            &fixture.authority_registry,
            Seq::from_u64(10),
        )
        .test_ok();

    assert_eq!(events.len(), 1);
    let (aborts, commits) = {
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.aborts, state.commits)
    };
    assert_eq!(aborts, 0);
    assert_eq!(commits, 1);
}

#[test]
fn authorized_staging_and_commit_failures_are_closed_and_abortable() {
    let fixture = fixture();
    let authority = current_authority(&fixture);
    let mut missing = PluginRegistry::new();
    assert!(error_text(missing.stage_authorized_driver(
        fixture.plugin_id,
        fixture.timeline_id,
        fixture.observation.clone(),
        &fixture.knowledge,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
    ))
    .contains("has no driver"));

    let mut driverless = PluginRegistry::new();
    driverless
        .register(
            &DriverlessPlugin {
                id: fixture.plugin_id,
            },
            None,
            None,
        )
        .test_ok();
    assert!(error_text(driverless.stage_authorized_driver(
        fixture.plugin_id,
        fixture.timeline_id,
        fixture.observation.clone(),
        &fixture.knowledge,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
    ))
    .contains("has no driver"));

    let (limited, limited_state) = registry(&fixture, false);
    let mut limited = limited.with_resource_limit(0);
    let exhausted = error_text(limited.stage_authorized_driver(
        fixture.plugin_id,
        fixture.timeline_id,
        fixture.observation.clone(),
        &fixture.knowledge,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
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
    let drafts = stage_current(&mut registry, &fixture).test_ok();
    let mut store = open_store(StoreConfig::Memory).test_ok();
    assert!(error_text(registry.append_and_commit_authorized_step_at(
        store.as_mut(),
        &drafts,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
    ))
    .contains("store error"));
    assert_eq!(
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1
    );
    assert!(error_text(registry.append_and_commit_authorized_step_at(
        store.as_mut(),
        &drafts,
        &authority,
        &fixture.authority_registry,
        Seq::from_u64(10),
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
        let mut registry = PluginRegistry::new();
        registry
            .register(
                &TestPlugin {
                    id: fixture.plugin_id,
                },
                None,
                Some(Box::new(driver)),
            )
            .test_ok();

        let error = error_text(registry.stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.observation.clone(),
            &fixture.knowledge,
            &authority,
            &fixture.authority_registry,
            Seq::from_u64(10),
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
    let mut registry = PluginRegistry::new();
    registry
        .register(
            &TestPlugin {
                id: fixture.plugin_id,
            },
            None,
            Some(Box::new(driver)),
        )
        .test_ok();
    registry
        .register(
            &ForeignEventOwner {
                id: PluginId::new(),
            },
            None,
            None,
        )
        .test_ok();

    assert_eq!(
        authority_error(registry.stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.observation.clone(),
            &fixture.knowledge,
            &current_authority(&fixture),
            &fixture.authority_registry,
            Seq::from_u64(10),
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
    let drafts = registry
        .step_all_anchored(fixture.timeline_id, Seq::from_u64(12))
        .test_ok();
    let mut store = open_store(StoreConfig::Memory).test_ok();

    let error = registry.append_and_commit_authorized_step_at(
        store.as_mut(),
        &drafts,
        &current_authority(&fixture),
        &fixture.authority_registry,
        Seq::from_u64(10),
    );
    match error {
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
        1
    );
}
