use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1,
    AuthorizationDecisionV1, AuthorizationRequestDraftV1, AuthorizationRequestV1, CanonicalBytes,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConsentEvidenceV1, ConsentGrantRefDraftV1, ConsentGrantRefV1, ConsentGrantStatusV1,
    DelegationChainV1, EntityId, Event, EventId, Hash, Kind, ObservationStatusV1,
    PersistedAuthorityV1, PluginId, PrincipalRefV1, Reducer, SchemaVersion, Seq, State, TimelineId,
    WallTime,
};
use pos_state::{ProjectionObservationContextV1, ProjectionRegistry};
use std::fmt::Debug;

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

impl<T> TestOk<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
    }
}

const fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn authenticated_principal(principal: PrincipalRefV1) -> AuthenticatedPrincipalResultV1 {
    AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
        principal,
        adapter_id: "test-adapter".to_owned(),
        assurance: AssuranceLevelV1::try_new(1).test_ok(),
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(100),
        binding_digest: hash_from_repeated_byte(5),
    })
    .test_ok()
}

struct CountReducer;

impl Reducer for CountReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _: &Event) {
        let count = state
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

struct NestedReducer;

impl Reducer for NestedReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _: &Event) {
        state.set(
            "nested",
            serde_json::json!({"z": [{"b": 2, "a": 1}], "a": true}),
        );
    }
}

fn event(entity: EntityId, sequence: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new("profile.changed"),
        payload: CanonicalBytes::from_static(b"{}"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(sequence),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        payload_hash: hash_from_repeated_byte(1),
    }
}

struct AuthorityFixture {
    request: AuthorizationRequestV1,
    decision: AuthorizationDecisionV1,
    chain: DelegationChainV1,
    authority: PersistedAuthorityV1,
    participant_id: EntityId,
    plugin_id: PluginId,
}

fn consent_grant(
    consent_id: Hash,
    subject_id: EntityId,
    actor_entity_id: EntityId,
    authority_timeline: TimelineId,
    policy_revision: Hash,
    registry_digest: Hash,
    issuer: PrincipalRefV1,
) -> ConsentGrantRefV1 {
    ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
        consent_id,
        subject_id,
        grantee_id: actor_entity_id,
        data_categories: vec!["profile.preferences".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        action_classes: vec!["observe".to_owned()],
        valid_from: WallTime::from_micros(1),
        valid_until: WallTime::from_micros(100),
        withdrawal_retention_policy: "erase-derived-data".to_owned(),
        policy_revision,
        issuer,
        issuer_evidence: hash_from_repeated_byte(12),
        consent_timeline: authority_timeline,
        grant_position: Seq::from_u64(5),
        status: ConsentGrantStatusV1::Active,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .test_ok()
}

fn observation_scope(
    actor: EntityId,
    subject: EntityId,
    participant_id: EntityId,
    plugin_id: PluginId,
) -> CapabilityScopeV1 {
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["projection.profile".to_owned()],
        actions: vec!["observe".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![actor],
        subject_ids: vec![subject],
        participant_ids: vec![participant_id],
        plugin_id: Some(plugin_id),
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 2,
        budget: 10,
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok()
}

fn persisted_authority(
    registry: &AuthorityRegistrySnapshotV1,
    grant: &CapabilityGrantV1,
) -> PersistedAuthorityV1 {
    let host = AuthorityPersistenceHostV1::new(registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(host.authorize_grant(grant).test_ok(), grant.clone())
        .test_ok();
    state.resolve(grant.grant_id()).test_ok()
}

fn authority_fixture() -> AuthorityFixture {
    let principal = PrincipalRefV1::try_new([1; 16], "host.test").test_ok();
    let actor = EntityId::new();
    let subject = EntityId::new();
    let participant_id = EntityId::new();
    let plugin_id = PluginId::new();
    let installation_id = [2; 16];
    let authority_timeline = TimelineId::new();
    let policy_revision = hash_from_repeated_byte(3);
    let registry_digest = hash_from_repeated_byte(4);
    let consent_id = hash_from_repeated_byte(5);
    let authenticated = authenticated_principal(principal.clone());
    let consent = consent_grant(
        consent_id,
        subject,
        actor,
        authority_timeline,
        policy_revision,
        registry_digest,
        principal.clone(),
    );
    let scope = observation_scope(actor, subject, participant_id, plugin_id);
    let grant = CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash_from_repeated_byte(6),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::PluginInstallation {
            controller: principal,
            plugin_id,
            installation_id,
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
        issuance_timeline: authority_timeline,
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .test_ok();
    let request = AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
        authenticated,
        actor_entity_id: actor,
        subject_id: Some(subject),
        participant_id: Some(participant_id),
        plugin_id: Some(plugin_id),
        installation_id: Some(installation_id),
        principal_role: AuthorityRoleV1::Actor,
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        action: "observe".to_owned(),
        purpose: "planning".to_owned(),
        audience: "local-host".to_owned(),
        at_time: WallTime::from_micros(10),
        authority_timeline,
        at_position: Seq::from_u64(10),
        consent_timeline: Some(authority_timeline),
        consent_at_position: Some(Seq::from_u64(10)),
        use_count: 1,
        budget: 5,
        consent_policy_revision: policy_revision,
        capability_policy_revision: policy_revision,
        revocation_epoch: 0,
        revocation_state_current: true,
        authority_registry_digest: registry_digest,
        consent: ConsentEvidenceV1::Resolved {
            grants: vec![consent.clone()],
        },
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok();
    let registry = AuthorityRegistrySnapshotV1::try_new(
        registry_digest,
        vec![request.authenticated().registry_binding_digest()],
        vec![grant.binding_digest().test_ok()],
        vec![consent.binding_digest()],
    )
    .test_ok();
    let chain = DelegationChainV1::try_from_grants(vec![grant.clone()]).test_ok();
    let decision = AuthorityEvaluatorV1::authorize(&request, &chain, &registry);
    assert!(decision.is_allowed());
    let authority = persisted_authority(&registry, &grant);
    AuthorityFixture {
        request,
        decision,
        chain,
        authority,
        participant_id,
        plugin_id,
    }
}

fn context(timeline_id: TimelineId) -> ProjectionObservationContextV1 {
    ProjectionObservationContextV1 {
        timeline_id,
        observed_through: Seq::from_u64(7),
        reducer: "profile".to_owned(),
        schema: "profile.v1".to_owned(),
        visibility_policy_revision: hash_from_repeated_byte(7),
        schema_revision: hash_from_repeated_byte(8),
        minimization_revision: hash_from_repeated_byte(9),
        source_digest: hash_from_repeated_byte(10),
        provenance_digest: hash_from_repeated_byte(11),
        prior_snapshot_digest: None,
    }
}

#[test]
fn authorized_materialization_ignores_every_other_subject() {
    let fixture = authority_fixture();
    let subject = fixture.request.subject_id().test_ok();
    let other = EntityId::new();
    let timeline_id = TimelineId::new();
    let mut first = ProjectionRegistry::new();
    first.register("profile", Box::new(CountReducer));
    first.fold_events(&[event(subject, 1), event(other, 2)]);
    let mut second = ProjectionRegistry::new();
    second.register("profile", Box::new(CountReducer));
    second.fold_events(&[event(subject, 1), event(other, 2), event(other, 3)]);

    let first_snapshot = first
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &context(timeline_id),
        )
        .test_ok();
    let second_snapshot = second
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &context(timeline_id),
        )
        .test_ok();

    assert_eq!(first_snapshot.participant_id(), fixture.participant_id);
    assert_eq!(first_snapshot.plugin_id(), fixture.plugin_id);
    assert_eq!(first_snapshot.encode(), second_snapshot.encode());
    let record = &first_snapshot.records()[0];
    let artifact = first_snapshot
        .artifact(record.artifact_digest().test_ok())
        .test_ok();
    assert_eq!(artifact.bytes().as_slice(), br#"{"count":1}"#);
}

#[test]
fn materialization_fails_closed_before_reading_without_active_exact_authorization() {
    let fixture = authority_fixture();
    let unrelated = authority_fixture();
    let mut registry = ProjectionRegistry::new();
    registry.register("profile", Box::new(CountReducer));
    registry.fold_events(&[event(fixture.request.subject_id().test_ok(), 1)]);
    assert_eq!(
        registry.materialize_authorized_observation(
            &unrelated.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::UnauthorizedSource)
    );
}

#[test]
fn materialization_represents_absence_without_inventing_an_artifact() {
    let fixture = authority_fixture();
    let mut registry = ProjectionRegistry::new();
    registry.register("profile", Box::new(CountReducer));

    let snapshot = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        )
        .test_ok();
    let record = &snapshot.records()[0];
    assert_eq!(record.status(), ObservationStatusV1::NotObserved);
    assert_eq!(record.artifact_digest(), None);
}

#[test]
fn materialization_canonicalizes_nested_projection_values() {
    let fixture = authority_fixture();
    let subject = fixture.request.subject_id().test_ok();
    let mut registry = ProjectionRegistry::new();
    registry.register("profile", Box::new(NestedReducer));
    registry.fold_events(&[event(subject, 1)]);

    let snapshot = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        )
        .test_ok();
    let digest = snapshot.records()[0].artifact_digest().test_ok();
    assert_eq!(
        snapshot.artifact(digest).test_ok().bytes().as_slice(),
        br#"{"nested":{"a":true,"z":[{"a":1,"b":2}]}}"#
    );
}

#[test]
fn materialization_rejects_denied_authority_and_empty_reducer_names() {
    let fixture = authority_fixture();
    let untrusted_registry = AuthorityRegistrySnapshotV1::try_new(
        fixture.request.authority_registry_digest(),
        vec![fixture.request.authenticated().registry_binding_digest()],
        Vec::new(),
        Vec::new(),
    )
    .test_ok();
    let denied =
        AuthorityEvaluatorV1::authorize(&fixture.request, &fixture.chain, &untrusted_registry);
    assert!(!denied.is_allowed());
    let registry = ProjectionRegistry::new();
    assert_eq!(
        registry.materialize_authorized_observation(
            &fixture.request,
            &denied,
            &fixture.authority,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(denied.error().test_ok())
    );

    let mut observation_context = context(TimelineId::new());
    observation_context.reducer.clear();
    assert_eq!(
        registry.materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &observation_context,
        ),
        Err(pos_core::AuthorityErrorV1::FieldOutOfBounds)
    );

    let mut unrelated_reducer = context(TimelineId::new());
    unrelated_reducer.reducer = "private-profile".to_owned();
    assert_eq!(
        registry.materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(10),
            &unrelated_reducer,
        ),
        Err(pos_core::AuthorityErrorV1::UnauthorizedSource)
    );
    assert_eq!(
        registry.materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            Seq::from_u64(9),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::RevocationStateStale)
    );
}
