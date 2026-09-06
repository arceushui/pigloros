use pos_core::{
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, Capability,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, EntityId, EventDraft, Hash, Kind,
    ObservationRecordDraftV1, ObservationRecordV1, ObservationSnapshotDraftV1,
    ObservationSnapshotV1, ObservationStatusV1, Plugin, PluginId, PrincipalRefV1, Seq, TimelineId,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use pos_store::{open_store, StoreConfig};
use std::sync::{Arc, Mutex};
use ulid::Ulid;

fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

struct Fixture {
    snapshot: ObservationSnapshotV1,
    state: AuthorityPersistenceStateV1,
    host: AuthorityPersistenceHostV1,
    grant: CapabilityGrantV1,
    plugin_id: PluginId,
    timeline_id: TimelineId,
}

fn fixture() -> Fixture {
    let principal = PrincipalRefV1::try_new([1; 16], "host.test").expect("principal");
    let participant_id = EntityId::from_ulid(Ulid::from(2_u128));
    let plugin_id = PluginId::from_ulid(Ulid::from(3_u128));
    let timeline_id = TimelineId::from_ulid(Ulid::from(4_u128));
    let authority_timeline = TimelineId::from_ulid(Ulid::from(5_u128));
    let registry_digest = hash_from_repeated_byte(6);
    let policy_revision = hash_from_repeated_byte(7);
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["projection.profile".to_owned()],
        actions: vec!["observe".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![EntityId::from_ulid(Ulid::from(8_u128))],
        subject_ids: vec![EntityId::from_ulid(Ulid::from(9_u128))],
        participant_ids: vec![participant_id],
        plugin_id: Some(plugin_id),
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 2,
        budget: 10,
        environment_constraints: vec!["local-only".to_owned()],
    })
    .expect("scope");
    let grant = CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash_from_repeated_byte(10),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::PluginInstallation {
            controller: principal.clone(),
            plugin_id,
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
        consent_references: Vec::new(),
        policy_revision,
        issuance_timeline: authority_timeline,
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .expect("grant");
    let grant_binding = grant.binding_digest().expect("grant binding");
    let registry = AuthorityRegistrySnapshotV1::try_new(
        registry_digest,
        Vec::new(),
        vec![grant_binding],
        Vec::new(),
    )
    .expect("registry");
    let host = AuthorityPersistenceHostV1::new(&registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(
            host.authorize_grant(&grant).expect("issue permit"),
            grant.clone(),
        )
        .expect("persist grant");
    let record = ObservationRecordV1::try_from_draft(ObservationRecordDraftV1 {
        participant_id,
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        status: ObservationStatusV1::NotObserved,
        artifact_digest: None,
        source_timeline: timeline_id,
        source_position: Seq::from_u64(12),
        schema: "profile.v1".to_owned(),
        source_digest: hash_from_repeated_byte(13),
        projection_digest: None,
        provenance_digest: hash_from_repeated_byte(14),
        minimization_revision: hash_from_repeated_byte(15),
    })
    .expect("record");
    let snapshot = ObservationSnapshotV1::try_from_draft(ObservationSnapshotDraftV1 {
        principal,
        participant_id,
        plugin_id,
        installation_id: [11; 16],
        timeline_id,
        observed_through: Seq::from_u64(12),
        authority_timeline,
        authority_position: Seq::from_u64(10),
        authorization_request_digest: hash_from_repeated_byte(16),
        authorization_decision_digest: hash_from_repeated_byte(17),
        grant_chain_bindings: vec![grant_binding],
        consent_policy_revision: policy_revision,
        capability_policy_revision: policy_revision,
        revocation_epoch: 0,
        visibility_policy_revision: hash_from_repeated_byte(18),
        schema_revision: hash_from_repeated_byte(19),
        minimization_revision: hash_from_repeated_byte(15),
        records: vec![record],
        artifacts: Vec::new(),
        prior_snapshot_digest: None,
        provenance_digest: hash_from_repeated_byte(20),
    })
    .expect("snapshot");
    Fixture {
        snapshot,
        state,
        host,
        grant,
        plugin_id,
        timeline_id,
    }
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

#[derive(Default)]
struct DriverState {
    observed_digest: Option<Hash>,
    saw_raw_state: bool,
    saw_raw_events: bool,
    commits: u32,
    aborts: u32,
}

struct ParticipantDriver {
    state: Arc<Mutex<DriverState>>,
    entity: EntityId,
    ambient_subscription: Option<pos_runtime::ProjectionKey>,
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
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.observed_digest = observations
            .authorized_snapshot()
            .map(ObservationSnapshotV1::digest);
        state.saw_raw_state = self
            .ambient_subscription
            .as_ref()
            .is_some_and(|key| observations.state_for(key).is_some());
        state.saw_raw_events = !observations.events().is_empty();
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new("participant.planned"),
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
        entity: EntityId::from_ulid(Ulid::from(30_u128)),
        ambient_subscription: ambient
            .then(|| pos_runtime::ProjectionKey::new(EntityId::from_ulid(Ulid::from(31_u128)))),
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
        .expect("register driver");
    (registry, state)
}

#[test]
fn authorized_driver_receives_only_the_bound_snapshot_and_requires_its_commit_fence() {
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    let drafts = registry
        .stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.snapshot.clone(),
        )
        .expect("stage authorized driver");
    let observed = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(observed.observed_digest, Some(fixture.snapshot.digest()));
    assert!(!observed.saw_raw_state);
    assert!(!observed.saw_raw_events);
    drop(observed);

    assert!(matches!(
        registry.commit_step_at(Seq::from_u64(12), 0),
        Err(RuntimeError::AuthorityFenceRequired)
    ));
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
    assert!(matches!(
        mismatched.stage_authorized_driver(
            fixture.plugin_id,
            TimelineId::from_ulid(Ulid::from(99_u128)),
            fixture.snapshot.clone(),
        ),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
    assert_eq!(
        mismatch_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_digest,
        None
    );

    let (mut ambient, ambient_state) = registry(&fixture, true);
    assert!(matches!(
        ambient.stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.snapshot.clone(),
        ),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
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
    let drafts = registry
        .stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.snapshot.clone(),
        )
        .expect("stage authorized driver");
    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: fixture.grant.grant_id(),
        authority_timeline: fixture.grant.issuance_timeline(),
        fence_position: Seq::from_u64(11),
        revocation_epoch: 1,
        policy_revision: fixture.grant.policy_revision(),
        authority_registry_digest: fixture.grant.authority_registry_digest(),
    })
    .expect("revocation");
    fixture
        .state
        .revoke_grant(
            fixture
                .host
                .authorize_revocation(&fixture.grant, &revocation)
                .expect("revocation permit"),
            revocation,
        )
        .expect("persist revocation");
    let authority = fixture
        .state
        .resolve(fixture.grant.grant_id())
        .expect("resolved authority");
    let mut store = open_store(StoreConfig::Memory).expect("memory store");

    assert!(matches!(
        registry.append_and_commit_authorized_step_at(
            store.as_mut(),
            &drafts,
            &authority,
            Seq::from_u64(11),
        ),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::RevokedAtFence
        ))
    ));
    let state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(state.aborts, 1);
    assert_eq!(state.commits, 0);
}

#[test]
fn authorized_work_rejects_legacy_append_and_substituted_drafts() {
    let fixture = fixture();
    let (mut legacy, legacy_state) = registry(&fixture, false);
    let legacy_drafts = legacy
        .stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.snapshot.clone(),
        )
        .expect("stage legacy-bypass attempt");
    let mut legacy_store = open_store(StoreConfig::Memory).expect("memory store");
    assert!(matches!(
        legacy.append_and_commit_step_at(
            legacy_store.as_mut(),
            Seq::from_u64(12),
            0,
            &legacy_drafts,
        ),
        Err(RuntimeError::AuthorityFenceRequired)
    ));
    assert_eq!(
        legacy_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .aborts,
        1
    );

    let (mut substituted, substituted_state) = registry(&fixture, false);
    let mut changed_drafts = substituted
        .stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.snapshot.clone(),
        )
        .expect("stage substitution attempt");
    changed_drafts[0].payload = CanonicalBytes::from_static(b"substituted");
    let authority = fixture
        .state
        .resolve(fixture.grant.grant_id())
        .expect("resolved authority");
    let mut substituted_store = open_store(StoreConfig::Memory).expect("memory store");
    assert!(matches!(
        substituted.append_and_commit_authorized_step_at(
            substituted_store.as_mut(),
            &changed_drafts,
            &authority,
            Seq::from_u64(10),
        ),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
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
    let fixture = fixture();
    let (mut registry, state) = registry(&fixture, false);
    let drafts = registry
        .stage_authorized_driver(
            fixture.plugin_id,
            fixture.timeline_id,
            fixture.snapshot.clone(),
        )
        .expect("stage authorized driver");
    let authority = fixture
        .state
        .resolve(fixture.grant.grant_id())
        .expect("resolved authority");
    let mut store = open_store(StoreConfig::Memory).expect("memory store");
    let events = registry
        .append_and_commit_authorized_step_at(
            store.as_mut(),
            &drafts,
            &authority,
            Seq::from_u64(10),
        )
        .expect("append authorized step");

    assert_eq!(events.len(), 1);
    let state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(state.aborts, 0);
    assert_eq!(state.commits, 1);
}
