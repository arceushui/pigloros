use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1,
    AuthorizationDecisionV1, AuthorizationRequestDraftV1, AuthorizationRequestV1, CanonicalBytes,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConsentEvidenceV1, ConsentGrantRefDraftV1, ConsentGrantRefV1, ConsentGrantStatusV1,
    DelegationChainV1, EntityId, Event, EventId, Hash, Kind, ObservationStatusV1,
    PersistedAuthorityV1, PluginId, PrincipalRefV1, Reducer, SchemaVersion, Seq, State, TimelineId,
    WallTime, MAX_OBSERVATION_SNAPSHOT_RECORDS,
};
use pos_state::{
    ProjectionObservationContextV1, ProjectionObservationPolicyV1, ProjectionRegistry,
};
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
        state.set("secret", serde_json::json!("must-not-cross-boundary"));
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
    registry: AuthorityRegistrySnapshotV1,
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

fn consent_evidence(present: bool, consent: &ConsentGrantRefV1) -> ConsentEvidenceV1 {
    if present {
        ConsentEvidenceV1::Resolved {
            grants: vec![consent.clone()],
        }
    } else {
        ConsentEvidenceV1::NotRequired
    }
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
    authority_fixture_with_identity_presence([true; 3])
}

fn authority_fixture_with_identity_presence(present: [bool; 3]) -> AuthorityFixture {
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
        subject_id: present[0].then_some(subject),
        participant_id: present[1].then_some(participant_id),
        plugin_id: present[2].then_some(plugin_id),
        installation_id: present[2].then_some(installation_id),
        principal_role: AuthorityRoleV1::Actor,
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        action: "observe".to_owned(),
        purpose: "planning".to_owned(),
        audience: "local-host".to_owned(),
        at_time: WallTime::from_micros(10),
        authority_timeline,
        at_position: Seq::from_u64(10),
        consent_timeline: present[0].then_some(authority_timeline),
        consent_at_position: present[0].then_some(Seq::from_u64(10)),
        use_count: 1,
        budget: 5,
        consent_policy_revision: policy_revision,
        capability_policy_revision: policy_revision,
        revocation_epoch: 0,
        revocation_state_current: true,
        authority_registry_digest: registry_digest,
        consent: consent_evidence(present[0], &consent),
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
    assert_eq!(decision.is_allowed(), present == [true; 3]);
    let authority = persisted_authority(&registry, &grant);
    AuthorityFixture {
        request,
        decision,
        chain,
        authority,
        registry,
        participant_id,
        plugin_id,
    }
}

#[test]
fn materialization_requires_each_observation_identity_before_projection_access() {
    for (present, expected) in [
        (
            [false, true, true],
            pos_core::AuthorityErrorV1::CapabilityMissing,
        ),
        (
            [true, false, true],
            pos_core::AuthorityErrorV1::CapabilityMissing,
        ),
        (
            [true, true, false],
            pos_core::AuthorityErrorV1::CapabilityMissing,
        ),
    ] {
        let fixture = authority_fixture_with_identity_presence(present);
        assert_eq!(
            fixture.authority.validate_observation_authorization(
                &fixture.request,
                &fixture.decision,
                &fixture.registry,
                Seq::from_u64(10),
            ),
            Err(expected)
        );

        let mut projections = ProjectionRegistry::new();
        register_profile(&mut projections, Box::new(CountReducer));
        assert_eq!(
            projections.materialize_authorized_observation(
                &fixture.request,
                &fixture.decision,
                &fixture.authority,
                &fixture.registry,
                Seq::from_u64(10),
                &context(TimelineId::new()),
            ),
            Err(expected)
        );
    }
}

#[test]
fn unresolved_principal_precedes_missing_observation_identity() {
    let fixture = authority_fixture_with_identity_presence([true, false, true]);
    let untrusted_registry = AuthorityRegistrySnapshotV1::try_new(
        fixture.request.authority_registry_digest(),
        vec![hash_from_repeated_byte(99)],
        Vec::new(),
        Vec::new(),
    )
    .test_ok();
    let decision =
        AuthorityEvaluatorV1::authorize(&fixture.request, &fixture.chain, &untrusted_registry);
    assert_eq!(
        decision.error(),
        Some(pos_core::AuthorityErrorV1::PrincipalUnresolved)
    );
    assert_eq!(
        fixture.authority.validate_observation_authorization(
            &fixture.request,
            &decision,
            &untrusted_registry,
            Seq::from_u64(10),
        ),
        Err(pos_core::AuthorityErrorV1::PrincipalUnresolved)
    );

    let mut projections = ProjectionRegistry::new();
    register_profile(&mut projections, Box::new(CountReducer));
    assert_eq!(
        projections.materialize_authorized_observation(
            &fixture.request,
            &decision,
            &fixture.authority,
            &untrusted_registry,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::PrincipalUnresolved)
    );
}

fn context(timeline_id: TimelineId) -> ProjectionObservationContextV1 {
    ProjectionObservationContextV1 {
        timeline_id,
        observed_through: Seq::from_u64(7),
        reducer: "profile".to_owned(),
        prior_snapshot_digest: None,
    }
}

fn policy(permitted_fields: Vec<String>) -> ProjectionObservationPolicyV1 {
    ProjectionObservationPolicyV1::try_new(
        permitted_fields,
        "profile.v1".to_owned(),
        hash_from_repeated_byte(7),
        hash_from_repeated_byte(8),
        hash_from_repeated_byte(9),
    )
    .test_ok()
}

fn register_profile(registry: &mut ProjectionRegistry, reducer: Box<dyn Reducer>) {
    registry
        .register_observable("profile", reducer, policy(vec!["count".to_owned()]))
        .test_ok();
}

#[test]
fn authorized_materialization_ignores_every_other_subject() {
    let fixture = authority_fixture();
    let subject = fixture.request.subject_id().test_ok();
    let other = EntityId::new();
    let timeline_id = TimelineId::new();
    let mut first = ProjectionRegistry::new();
    register_profile(&mut first, Box::new(CountReducer));
    first.fold_events(&[event(subject, 1), event(other, 2)]);
    let mut second = ProjectionRegistry::new();
    register_profile(&mut second, Box::new(CountReducer));
    second.fold_events(&[event(subject, 1), event(other, 2), event(other, 3)]);

    let first_snapshot = first
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(timeline_id),
        )
        .test_ok();
    let second_snapshot = second
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
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
    assert_eq!(record.source_digest(), artifact.digest());
    assert_eq!(
        record.provenance_digest(),
        first_snapshot.provenance_digest()
    );
}

#[test]
fn observation_artifact_release_rejects_erased_or_invalidated_evidence() {
    use pos_core::{
        ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
        ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureKeyRoleV1, ErasureReferenceV1,
        ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluatorV1,
    };

    let fixture = authority_fixture();
    let subject = fixture.request.subject_id().test_ok();
    let mut registry = ProjectionRegistry::new();
    register_profile(&mut registry, Box::new(CountReducer));
    registry.fold_events(&[event(subject, 1)]);
    let observation = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        )
        .test_ok();
    let digest = observation.records()[0].artifact_digest().test_ok();
    let evaluate = |state| {
        ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[ArtifactClaimInputV1 {
                registration: RegisteredArtifactV1 {
                    artifact_class: ErasureArtifactClassV1::ForkOrSnapshot,
                    artifact_digest: ErasureReferenceV1::from_digest(*digest.as_bytes()),
                    data_class: ArtifactDataClassV1::PrivateSubjectData,
                    key_role: Some(ErasureKeyRoleV1::DataEncryption),
                    owner: ErasureReferenceV1::from_digest([71; 32]),
                    optionality: ArtifactOptionalityV1::Required,
                    transition_rule: ArtifactTransitionRuleV1::Remove,
                },
                current_claim: ErasureReplayClaimV1::Exact,
                state,
            }],
        )
        .test_ok()
    };

    let retained = evaluate(ArtifactStateV1::Retained);
    assert_eq!(
        observation
            .authoritative_artifact(digest, &retained)
            .test_ok()
            .bytes()
            .as_slice(),
        br#"{"count":1}"#
    );
    for state in [ArtifactStateV1::Erased, ArtifactStateV1::Invalidated] {
        assert!(matches!(
            observation.authoritative_artifact(digest, &evaluate(state)),
            Err(pos_core::AuthorityErrorV1::SourceUnavailable)
        ));
    }

    let unknown = hash_from_repeated_byte(99);
    assert!(matches!(
        observation.authoritative_artifact(unknown, &retained),
        Err(pos_core::AuthorityErrorV1::SourceUnavailable)
    ));
}

#[test]
fn materialization_fails_closed_before_reading_without_active_exact_authorization() {
    let fixture = authority_fixture();
    let unrelated = authority_fixture();
    let mut registry = ProjectionRegistry::new();
    register_profile(&mut registry, Box::new(CountReducer));
    registry.fold_events(&[event(fixture.request.subject_id().test_ok(), 1)]);
    assert_eq!(
        registry.materialize_authorized_observation(
            &unrelated.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::UnauthorizedSource)
    );

    let stripped_registry = AuthorityRegistrySnapshotV1::try_new(
        fixture.request.authority_registry_digest(),
        vec![fixture.request.authenticated().registry_binding_digest()],
        Vec::new(),
        Vec::new(),
    )
    .test_ok();
    let current =
        AuthorityEvaluatorV1::authorize(&fixture.request, &fixture.chain, &stripped_registry);
    assert!(!current.is_allowed());
    assert_eq!(
        registry.materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &stripped_registry,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(current.error().test_ok())
    );
}

#[test]
fn materialization_represents_absence_without_inventing_an_artifact() {
    let fixture = authority_fixture();
    let mut registry = ProjectionRegistry::new();
    register_profile(&mut registry, Box::new(CountReducer));
    let timeline_id = TimelineId::new();

    let snapshot = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(timeline_id),
        )
        .test_ok();
    let record = &snapshot.records()[0];
    assert_eq!(record.status(), ObservationStatusV1::NotObserved);
    assert_eq!(record.artifact_digest(), None);
    assert_ne!(record.source_digest(), record.provenance_digest());

    let later = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &ProjectionObservationContextV1 {
                observed_through: Seq::from_u64(8),
                ..context(timeline_id)
            },
        )
        .test_ok();
    assert_ne!(record.source_digest(), later.records()[0].source_digest());
}

#[test]
fn materialization_canonicalizes_nested_projection_values() {
    let fixture = authority_fixture();
    let subject = fixture.request.subject_id().test_ok();
    let mut registry = ProjectionRegistry::new();
    registry
        .register_observable(
            "profile",
            Box::new(NestedReducer),
            policy(vec!["nested".to_owned()]),
        )
        .test_ok();
    registry.fold_events(&[event(subject, 1)]);

    let snapshot = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
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
            &untrusted_registry,
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
            &fixture.registry,
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
            &fixture.registry,
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
            &fixture.registry,
            Seq::from_u64(9),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::RevocationStateStale)
    );
}

#[test]
fn observation_policy_rejects_incomplete_or_noncanonical_configuration() {
    let revisions = (
        hash_from_repeated_byte(7),
        hash_from_repeated_byte(8),
        hash_from_repeated_byte(9),
    );
    assert_eq!(
        ProjectionObservationPolicyV1::try_new(
            Vec::new(),
            "profile.v1".to_owned(),
            revisions.0,
            revisions.1,
            revisions.2,
        ),
        Err(pos_core::AuthorityErrorV1::FieldOutOfBounds)
    );
    for (fields, schema) in [
        (vec!["count".to_owned()], String::new()),
        (
            vec!["count".to_owned()],
            "s".repeat(pos_core::MAX_AUTHORITY_TEXT_BYTES + 1),
        ),
        (
            vec!["count".to_owned(); MAX_OBSERVATION_SNAPSHOT_RECORDS + 1],
            "profile.v1".to_owned(),
        ),
        (vec![String::new()], "profile.v1".to_owned()),
        (
            vec!["f".repeat(pos_core::MAX_AUTHORITY_TEXT_BYTES + 1)],
            "profile.v1".to_owned(),
        ),
    ] {
        assert_eq!(
            ProjectionObservationPolicyV1::try_new(
                fields,
                schema,
                revisions.0,
                revisions.1,
                revisions.2,
            ),
            Err(pos_core::AuthorityErrorV1::FieldOutOfBounds)
        );
    }
    assert_eq!(
        ProjectionObservationPolicyV1::try_new(
            vec!["secret".to_owned(), "count".to_owned()],
            "profile.v1".to_owned(),
            revisions.0,
            revisions.1,
            revisions.2,
        ),
        Err(pos_core::AuthorityErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        ProjectionObservationPolicyV1::try_new(
            vec!["count".to_owned()],
            "profile.v1".to_owned(),
            Hash::zero(),
            revisions.1,
            revisions.2,
        ),
        Err(pos_core::AuthorityErrorV1::ProvenanceMissing)
    );
}

#[test]
fn observation_policy_is_required_for_materialization() {
    let fixture = authority_fixture();
    let observable_policy = policy(vec!["count".to_owned()]);
    let mut invalid_registration = ProjectionRegistry::new();
    assert_eq!(
        invalid_registration.register_observable(
            "",
            Box::new(CountReducer),
            observable_policy.clone(),
        ),
        Err(pos_core::AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        invalid_registration.register_observable(
            &"r".repeat(pos_core::MAX_AUTHORITY_TEXT_BYTES + 1),
            Box::new(CountReducer),
            observable_policy,
        ),
        Err(pos_core::AuthorityErrorV1::FieldOutOfBounds)
    );

    assert_eq!(
        ProjectionRegistry::new().materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::SourceUnavailable)
    );
    let mut registry = ProjectionRegistry::new();
    registry.register("profile", Box::new(CountReducer));
    assert_eq!(
        registry.materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(TimelineId::new()),
        ),
        Err(pos_core::AuthorityErrorV1::UnauthorizedSource)
    );
}

#[test]
fn observation_policy_rejects_each_zero_revision() {
    let valid = (
        hash_from_repeated_byte(7),
        hash_from_repeated_byte(8),
        hash_from_repeated_byte(9),
    );
    for revisions in [
        (Hash::zero(), valid.1, valid.2),
        (valid.0, Hash::zero(), valid.2),
        (valid.0, valid.1, Hash::zero()),
    ] {
        assert_eq!(
            ProjectionObservationPolicyV1::try_new(
                vec!["count".to_owned()],
                "profile.v1".to_owned(),
                revisions.0,
                revisions.1,
                revisions.2,
            ),
            Err(pos_core::AuthorityErrorV1::ProvenanceMissing)
        );
    }
}

#[test]
fn observation_policy_rejects_duplicate_permitted_fields() {
    assert_eq!(
        ProjectionObservationPolicyV1::try_new(
            vec!["count".to_owned(), "count".to_owned()],
            "profile.v1".to_owned(),
            hash_from_repeated_byte(7),
            hash_from_repeated_byte(8),
            hash_from_repeated_byte(9),
        ),
        Err(pos_core::AuthorityErrorV1::NonCanonicalOrder)
    );
}

#[test]
fn prior_observation_snapshot_changes_snapshot_digest_not_policy_provenance() {
    let fixture = authority_fixture();
    let mut registry = ProjectionRegistry::new();
    register_profile(&mut registry, Box::new(CountReducer));
    let timeline_id = TimelineId::new();
    let without_prior = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &context(timeline_id),
        )
        .test_ok();
    let prior_digest = hash_from_repeated_byte(42);
    let with_prior = registry
        .materialize_authorized_observation(
            &fixture.request,
            &fixture.decision,
            &fixture.authority,
            &fixture.registry,
            Seq::from_u64(10),
            &ProjectionObservationContextV1 {
                prior_snapshot_digest: Some(prior_digest),
                ..context(timeline_id)
            },
        )
        .test_ok();

    assert_eq!(with_prior.prior_snapshot_digest(), Some(prior_digest));
    assert_ne!(with_prior.digest(), without_prior.digest());
    assert_eq!(
        with_prior.provenance_digest(),
        without_prior.provenance_digest()
    );
}
