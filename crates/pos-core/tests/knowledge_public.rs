use pos_core::{
    AiGoalPolicyRevisionV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1, BeliefRecordDraftV1,
    BeliefRecordV1, CanonicalBytes, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConfidenceV1, EntityId, Hash, KnowledgeSnapshotDraftV1, KnowledgeSnapshotV1,
    MemoryPolicyRevisionV1, ObservationArtifactV1, ObservationRecordDraftV1, ObservationRecordV1,
    ObservationSnapshotDraftV1, ObservationSnapshotV1, ObservationStatusV1, PluginId,
    PreferenceValueRevisionV1, PrincipalRefV1, Seq, TimelineId,
};
use ulid::Ulid;

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

const fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn belief_draft(
    entity_id: EntityId,
    predicate: &str,
    observation_digest: Hash,
) -> BeliefRecordDraftV1 {
    BeliefRecordDraftV1 {
        entity_id,
        predicate: predicate.to_owned(),
        confidence: ConfidenceV1::try_new(750_000).test_ok(),
        provenance_digest: hash_from_repeated_byte(23),
        observation_record_digests: vec![observation_digest],
    }
}

#[test]
fn knowledge_snapshot_preserves_epistemic_and_revision_meanings() {
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let observation =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .test_ok();
    let belief = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "prefers.tea",
        observation.digest(),
    ))
    .test_ok();
    let snapshot = KnowledgeSnapshotV1::try_from_draft(KnowledgeSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").test_ok(),
        participant_id,
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        observation_snapshot_digest: hash_from_repeated_byte(25),
        observations: vec![observation],
        beliefs: vec![belief.clone()],
        preference_value_revision: Some(
            PreferenceValueRevisionV1::try_new(hash_from_repeated_byte(26)).test_ok(),
        ),
        ai_goal_policy_revision: Some(
            AiGoalPolicyRevisionV1::try_new(hash_from_repeated_byte(27)).test_ok(),
        ),
        memory_policy_revision: MemoryPolicyRevisionV1::try_new(hash_from_repeated_byte(28))
            .test_ok(),
        prior_snapshot_digest: Some(hash_from_repeated_byte(29)),
        external_provenance: vec![hash_from_repeated_byte(30)],
        provenance_digest: hash_from_repeated_byte(31),
    })
    .test_ok();

    assert_eq!(snapshot.beliefs(), &[belief]);
    assert_eq!(
        snapshot
            .preference_value_revision()
            .map(PreferenceValueRevisionV1::digest),
        Some(hash_from_repeated_byte(26))
    );
    assert_eq!(
        snapshot
            .ai_goal_policy_revision()
            .map(AiGoalPolicyRevisionV1::digest),
        Some(hash_from_repeated_byte(27))
    );
    assert_eq!(
        snapshot.memory_policy_revision().digest(),
        hash_from_repeated_byte(28)
    );
    assert_eq!(
        KnowledgeSnapshotV1::decode(&snapshot.encode().test_ok()),
        Ok(snapshot)
    );
}

#[test]
fn knowledge_snapshot_rejects_noncanonical_belief_order() {
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let observation =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .test_ok();
    let later = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "z.last",
        observation.digest(),
    ))
    .test_ok();
    let earlier = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "a.first",
        observation.digest(),
    ))
    .test_ok();
    let mut draft = KnowledgeSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").test_ok(),
        participant_id,
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        observation_snapshot_digest: hash_from_repeated_byte(25),
        observations: vec![observation],
        beliefs: vec![later, earlier],
        preference_value_revision: None,
        ai_goal_policy_revision: None,
        memory_policy_revision: MemoryPolicyRevisionV1::try_new(hash_from_repeated_byte(28))
            .test_ok(),
        prior_snapshot_digest: None,
        external_provenance: Vec::new(),
        provenance_digest: hash_from_repeated_byte(31),
    };

    assert_eq!(
        KnowledgeSnapshotV1::try_from_draft(draft.clone()),
        Err(pos_core::AuthorityErrorV1::NonCanonicalOrder)
    );
    draft.beliefs.reverse();
    assert!(KnowledgeSnapshotV1::try_from_draft(draft).is_ok());
}

fn observation_snapshot_draft(
    records: Vec<ObservationRecordV1>,
    artifacts: Vec<ObservationArtifactV1>,
) -> ObservationSnapshotDraftV1 {
    ObservationSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").test_ok(),
        participant_id: EntityId::from_ulid(Ulid::from(1_u128)),
        plugin_id: PluginId::from_ulid(Ulid::from(11_u128)),
        installation_id: [12; 16],
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        authority_timeline: TimelineId::from_ulid(Ulid::from(13_u128)),
        authority_position: Seq::from_u64(6),
        authorization_request_digest: hash_from_repeated_byte(14),
        authorization_decision_digest: hash_from_repeated_byte(15),
        grant_chain_bindings: vec![hash_from_repeated_byte(16)],
        consent_policy_revision: hash_from_repeated_byte(17),
        capability_policy_revision: hash_from_repeated_byte(18),
        revocation_epoch: 3,
        visibility_policy_revision: hash_from_repeated_byte(19),
        schema_revision: hash_from_repeated_byte(20),
        minimization_revision: hash_from_repeated_byte(6),
        records,
        artifacts,
        prior_snapshot_digest: Some(hash_from_repeated_byte(21)),
        provenance_digest: hash_from_repeated_byte(22),
    }
}

fn record_draft(
    status: ObservationStatusV1,
    artifact_digest: Option<Hash>,
) -> ObservationRecordDraftV1 {
    ObservationRecordDraftV1 {
        participant_id: EntityId::from_ulid(Ulid::from(1_u128)),
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        status,
        artifact_digest,
        source_timeline: TimelineId::from_ulid(Ulid::from(2_u128)),
        source_position: Seq::from_u64(7),
        schema: "profile.v1".to_owned(),
        source_digest: hash_from_repeated_byte(3),
        projection_digest: Some(hash_from_repeated_byte(4)),
        provenance_digest: hash_from_repeated_byte(5),
        minimization_revision: hash_from_repeated_byte(6),
    }
}

struct AuthorityFenceFixture {
    snapshot: ObservationSnapshotV1,
    state: AuthorityPersistenceStateV1,
    host: AuthorityPersistenceHostV1,
    grant: CapabilityGrantV1,
}

fn authority_fence_fixture(snapshot_epoch: u64) -> AuthorityFenceFixture {
    let principal = PrincipalRefV1::try_new([7; 16], "host.test").test_ok();
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let plugin_id = PluginId::from_ulid(Ulid::from(11_u128));
    let authority_timeline = TimelineId::from_ulid(Ulid::from(13_u128));
    let registry_digest = hash_from_repeated_byte(40);
    let policy_revision = hash_from_repeated_byte(41);
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["projection.profile".to_owned()],
        actions: vec!["observe".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![EntityId::from_ulid(Ulid::from(42_u128))],
        subject_ids: vec![EntityId::from_ulid(Ulid::from(43_u128))],
        participant_ids: vec![participant_id],
        plugin_id: Some(plugin_id),
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 2,
        budget: 10,
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok();
    let grant = CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash_from_repeated_byte(44),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::PluginInstallation {
            controller: principal.clone(),
            plugin_id,
            installation_id: [12; 16],
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
    .test_ok();
    let grant_binding = grant.binding_digest().test_ok();
    let registry = AuthorityRegistrySnapshotV1::try_new(
        registry_digest,
        Vec::new(),
        vec![grant_binding],
        Vec::new(),
    )
    .test_ok();
    let host = AuthorityPersistenceHostV1::new(&registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(host.authorize_grant(&grant).test_ok(), grant.clone())
        .test_ok();
    let mut snapshot_draft = observation_snapshot_draft(
        vec![ObservationRecordV1::try_from_draft(record_draft(
            ObservationStatusV1::NotObserved,
            None,
        ))
        .test_ok()],
        Vec::new(),
    );
    snapshot_draft.principal = principal;
    snapshot_draft.participant_id = participant_id;
    snapshot_draft.plugin_id = plugin_id;
    snapshot_draft.authority_timeline = authority_timeline;
    snapshot_draft.authority_position = Seq::from_u64(10);
    snapshot_draft.grant_chain_bindings = vec![grant_binding];
    snapshot_draft.capability_policy_revision = policy_revision;
    snapshot_draft.revocation_epoch = snapshot_epoch;
    AuthorityFenceFixture {
        snapshot: ObservationSnapshotV1::try_from_draft(snapshot_draft).test_ok(),
        state,
        host,
        grant,
    }
}

#[test]
fn observation_snapshot_revalidates_current_authority_at_commit_fence() {
    let fixture = authority_fence_fixture(0);
    let authority = fixture.state.resolve(fixture.grant.grant_id()).test_ok();

    assert_eq!(
        fixture
            .snapshot
            .validate_authority_fence(&authority, Seq::from_u64(10)),
        Ok(())
    );
    assert_eq!(
        fixture
            .snapshot
            .validate_authority_fence(&authority, Seq::from_u64(9)),
        Err(pos_core::AuthorityErrorV1::RevocationStateStale)
    );
    assert_eq!(
        fixture
            .snapshot
            .validate_authority_fence(&authority, Seq::from_u64(80)),
        Err(pos_core::AuthorityErrorV1::CapabilityMissing)
    );
}

#[test]
fn observation_snapshot_rejects_stale_or_newly_revoked_authority() {
    let stale = authority_fence_fixture(1);
    let stale_authority = stale.state.resolve(stale.grant.grant_id()).test_ok();
    assert_eq!(
        stale
            .snapshot
            .validate_authority_fence(&stale_authority, Seq::from_u64(10)),
        Err(pos_core::AuthorityErrorV1::RevocationStateStale)
    );

    let mut revoked = authority_fence_fixture(0);
    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: revoked.grant.grant_id(),
        authority_timeline: revoked.grant.issuance_timeline(),
        fence_position: Seq::from_u64(11),
        revocation_epoch: 1,
        policy_revision: revoked.grant.policy_revision(),
        authority_registry_digest: revoked.grant.authority_registry_digest(),
    })
    .test_ok();
    revoked
        .state
        .revoke_grant(
            revoked
                .host
                .authorize_revocation(&revoked.grant, &revocation)
                .test_ok(),
            revocation,
        )
        .test_ok();
    let revoked_authority = revoked.state.resolve(revoked.grant.grant_id()).test_ok();
    assert_eq!(
        revoked
            .snapshot
            .validate_authority_fence(&revoked_authority, Seq::from_u64(11)),
        Err(pos_core::AuthorityErrorV1::RevokedAtFence)
    );
}

#[test]
fn observation_record_round_trip_binds_participant_source_and_minimization() {
    let artifact =
        ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed")).test_ok();
    let draft = record_draft(ObservationStatusV1::Present, Some(artifact.digest()));
    let participant_id = draft.participant_id;
    let record = ObservationRecordV1::try_from_draft(draft.clone()).test_ok();

    assert_eq!(record.participant_id(), participant_id);
    assert_eq!(record.status(), ObservationStatusV1::Present);
    assert_eq!(record.artifact_digest(), Some(artifact.digest()));
    assert_ne!(record.digest(), Hash::zero());
    assert_eq!(
        ObservationRecordV1::decode(&record.encode().test_ok()),
        Ok(record.clone())
    );

    let mut changed_timeline = draft.clone();
    changed_timeline.source_timeline = TimelineId::from_ulid(Ulid::from(9_u128));
    let mut changed_participant = draft.clone();
    changed_participant.participant_id = EntityId::from_ulid(Ulid::from(10_u128));
    let mut changed_position = draft.clone();
    changed_position.source_position = Seq::from_u64(8);
    let mut changed_minimization = draft;
    changed_minimization.minimization_revision = hash_from_repeated_byte(9);
    for changed in [
        changed_participant,
        changed_timeline,
        changed_position,
        changed_minimization,
    ] {
        assert_ne!(
            ObservationRecordV1::try_from_draft(changed)
                .test_ok()
                .digest(),
            record.digest()
        );
    }
}

#[test]
fn typed_absence_cannot_carry_observation_value_bytes() {
    let result = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Unauthorized,
        Some(hash_from_repeated_byte(1)),
    ));

    assert_eq!(result, Err(pos_core::AuthorityErrorV1::UnauthorizedSource));
}

#[test]
fn observation_snapshot_is_authorization_bound_and_content_addressed() {
    let artifact =
        ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed")).test_ok();
    let record = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Present,
        Some(artifact.digest()),
    ))
    .test_ok();
    let snapshot = ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
        vec![record.clone()],
        vec![artifact.clone()],
    ))
    .test_ok();

    assert_eq!(snapshot.records(), &[record]);
    assert_eq!(snapshot.artifact(artifact.digest()), Some(&artifact));
    assert_eq!(snapshot.revocation_epoch(), 3);
    assert_ne!(snapshot.digest(), Hash::zero());
    assert_eq!(
        ObservationSnapshotV1::decode(&snapshot.encode().test_ok()),
        Ok(snapshot)
    );
}

#[test]
fn observation_snapshot_rejects_noncanonical_records_and_unbound_artifacts() {
    let artifact =
        ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed")).test_ok();
    let mut later = record_draft(ObservationStatusV1::Present, Some(artifact.digest()));
    later.source_position = Seq::from_u64(8);
    let later = ObservationRecordV1::try_from_draft(later).test_ok();
    let earlier = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Present,
        Some(artifact.digest()),
    ))
    .test_ok();

    assert_eq!(
        ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
            vec![later, earlier],
            vec![artifact.clone()],
        )),
        Err(pos_core::AuthorityErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
            Vec::new(),
            vec![artifact,]
        )),
        Err(pos_core::AuthorityErrorV1::ProvenanceMissing)
    );
}
