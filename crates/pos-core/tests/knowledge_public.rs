use ciborium::Value;
use pos_core::{
    AiGoalPolicyRevisionV1, AuthorityErrorV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1, BeliefRecordDraftV1,
    BeliefRecordV1, CanonicalBytes, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConfidenceV1, EntityId, Hash, KnowledgeSnapshotDraftV1, KnowledgeSnapshotV1,
    MemoryPolicyRevisionV1, ObservationArtifactV1, ObservationRecordDraftV1, ObservationRecordV1,
    ObservationSnapshotDraftV1, ObservationSnapshotV1, ObservationStatusV1, PluginId,
    PreferenceValueRevisionV1, PrincipalRefV1, Seq, TimelineId, MAX_KNOWLEDGE_SNAPSHOT_RECORDS,
    MAX_OBSERVATION_ARTIFACT_BYTES,
};
use ulid::Ulid;

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        assert!(self.is_ok(), "unexpected fixture error: {self:?}");
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

const fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn encode_value(value: &Value) -> CanonicalBytes {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).test_ok();
    CanonicalBytes::from_vec(bytes)
}

fn changed_array(encoded: &CanonicalBytes, change: impl FnOnce(&mut Vec<Value>)) -> CanonicalBytes {
    let value: Value = ciborium::from_reader(encoded.as_slice()).test_ok();
    let Value::Array(mut fields) = value else {
        std::panic::resume_unwind(Box::new("expected canonical array"));
    };
    change(&mut fields);
    encode_value(&Value::Array(fields))
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

fn knowledge_draft(
    participant_id: EntityId,
    observations: Vec<ObservationRecordV1>,
    beliefs: Vec<BeliefRecordV1>,
) -> KnowledgeSnapshotDraftV1 {
    KnowledgeSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").test_ok(),
        participant_id,
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        observation_snapshot_digest: hash_from_repeated_byte(25),
        observations,
        beliefs,
        preference_value_revision: None,
        ai_goal_policy_revision: None,
        memory_policy_revision: MemoryPolicyRevisionV1::try_new(hash_from_repeated_byte(28))
            .test_ok(),
        prior_snapshot_digest: None,
        external_provenance: Vec::new(),
        provenance_digest: hash_from_repeated_byte(31),
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
        observations: vec![observation.clone()],
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

    assert_eq!(snapshot.principal().principal_id(), &[7; 16]);
    assert_eq!(snapshot.participant_id(), participant_id);
    assert_eq!(
        snapshot.timeline_id(),
        TimelineId::from_ulid(Ulid::from(2_u128))
    );
    assert_eq!(snapshot.observed_through(), Seq::from_u64(7));
    assert_eq!(
        snapshot.observation_snapshot_digest(),
        hash_from_repeated_byte(25)
    );
    assert_eq!(snapshot.observations(), &[observation]);
    assert_eq!(snapshot.beliefs(), &[belief]);
    assert_eq!(belief.entity_id(), participant_id);
    assert_eq!(belief.predicate(), "prefers.tea");
    assert_eq!(belief.confidence().millionths(), 750_000);
    assert_eq!(belief.provenance_digest(), hash_from_repeated_byte(23));
    assert_eq!(belief.observation_record_digests(), &[observation.digest()]);
    assert_ne!(belief.digest(), Hash::zero());
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
        snapshot.prior_snapshot_digest(),
        Some(hash_from_repeated_byte(29))
    );
    assert_eq!(
        snapshot.external_provenance(),
        &[hash_from_repeated_byte(30)]
    );
    assert_eq!(snapshot.provenance_digest(), hash_from_repeated_byte(31));
    assert_ne!(snapshot.digest(), Hash::zero());
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
        vec![hash_from_repeated_byte(45)],
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
    assert_eq!(record.resource(), "projection.profile");
    assert_eq!(record.data_category(), "profile.preferences");
    assert_eq!(record.status(), ObservationStatusV1::Present);
    assert_eq!(record.artifact_digest(), Some(artifact.digest()));
    assert_eq!(
        record.source_timeline(),
        TimelineId::from_ulid(Ulid::from(2_u128))
    );
    assert_eq!(record.source_position(), Seq::from_u64(7));
    assert_eq!(record.schema(), "profile.v1");
    assert_eq!(record.source_digest(), hash_from_repeated_byte(3));
    assert_eq!(record.projection_digest(), Some(hash_from_repeated_byte(4)));
    assert_eq!(record.provenance_digest(), hash_from_repeated_byte(5));
    assert_eq!(record.minimization_revision(), hash_from_repeated_byte(6));
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

    assert_eq!(artifact.bytes().as_slice(), b"allowed");
    assert_eq!(snapshot.principal().principal_id(), &[7; 16]);
    assert_eq!(
        snapshot.participant_id(),
        EntityId::from_ulid(Ulid::from(1_u128))
    );
    assert_eq!(
        snapshot.plugin_id(),
        PluginId::from_ulid(Ulid::from(11_u128))
    );
    assert_eq!(snapshot.installation_id(), [12; 16]);
    assert_eq!(
        snapshot.timeline_id(),
        TimelineId::from_ulid(Ulid::from(2_u128))
    );
    assert_eq!(snapshot.observed_through(), Seq::from_u64(7));
    assert_eq!(
        snapshot.authority_timeline(),
        TimelineId::from_ulid(Ulid::from(13_u128))
    );
    assert_eq!(snapshot.authority_position(), Seq::from_u64(6));
    assert_eq!(
        snapshot.authorization_request_digest(),
        hash_from_repeated_byte(14)
    );
    assert_eq!(
        snapshot.authorization_decision_digest(),
        hash_from_repeated_byte(15)
    );
    assert_eq!(
        snapshot.grant_chain_bindings(),
        &[hash_from_repeated_byte(16)]
    );
    assert_eq!(
        snapshot.consent_policy_revision(),
        hash_from_repeated_byte(17)
    );
    assert_eq!(
        snapshot.capability_policy_revision(),
        hash_from_repeated_byte(18)
    );
    assert_eq!(snapshot.records(), &[record]);
    assert_eq!(snapshot.artifact(artifact.digest()), Some(&artifact));
    assert_eq!(snapshot.artifact(hash_from_repeated_byte(99)), None);
    assert_eq!(snapshot.revocation_epoch(), 3);
    assert_eq!(
        snapshot.visibility_policy_revision(),
        hash_from_repeated_byte(19)
    );
    assert_eq!(snapshot.schema_revision(), hash_from_repeated_byte(20));
    assert_eq!(snapshot.minimization_revision(), hash_from_repeated_byte(6));
    assert_eq!(
        snapshot.prior_snapshot_digest(),
        Some(hash_from_repeated_byte(21))
    );
    assert_eq!(snapshot.provenance_digest(), hash_from_repeated_byte(22));
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

#[test]
fn observation_value_and_presence_boundaries_are_closed() {
    assert_eq!(
        ObservationArtifactV1::try_new(CanonicalBytes::from_vec(Vec::new())),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ObservationArtifactV1::try_new(CanonicalBytes::from_vec(vec![
            1;
            MAX_OBSERVATION_ARTIFACT_BYTES
                + 1
        ])),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(ConfidenceV1::try_new(0).test_ok().millionths(), 0);
    assert_eq!(
        ConfidenceV1::try_new(1_000_000).test_ok().millionths(),
        1_000_000
    );
    assert_eq!(
        ConfidenceV1::try_new(1_000_001),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PreferenceValueRevisionV1::try_new(Hash::zero()),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        AiGoalPolicyRevisionV1::try_new(Hash::zero()),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        MemoryPolicyRevisionV1::try_new(Hash::zero()),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    for status in [
        ObservationStatusV1::Unknown,
        ObservationStatusV1::Unauthorized,
        ObservationStatusV1::Deleted,
        ObservationStatusV1::Unavailable,
        ObservationStatusV1::NotObserved,
    ] {
        let record = ObservationRecordV1::try_from_draft(record_draft(status, None)).test_ok();
        assert_eq!(record.status(), status);
        assert_eq!(
            ObservationRecordV1::decode(&record.encode().test_ok()),
            Ok(record)
        );
    }
    assert_eq!(
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::Present, None)),
        Err(AuthorityErrorV1::SourceUnavailable)
    );
    assert_eq!(
        ObservationRecordV1::try_from_draft(record_draft(
            ObservationStatusV1::Unknown,
            Some(hash_from_repeated_byte(1)),
        )),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn observation_record_validation_and_codec_reject_each_closed_shape() {
    let valid =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .test_ok();
    let encoded = valid.encode().test_ok();

    let mut invalid = record_draft(ObservationStatusV1::NotObserved, None);
    invalid.resource.clear();
    assert_eq!(
        ObservationRecordV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = record_draft(ObservationStatusV1::NotObserved, None);
    invalid.source_digest = Hash::zero();
    assert_eq!(
        ObservationRecordV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = record_draft(ObservationStatusV1::NotObserved, None);
    invalid.projection_digest = Some(Hash::zero());
    assert_eq!(
        ObservationRecordV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    assert_eq!(
        ObservationRecordV1::decode(&changed_array(&encoded, |fields| {
            fields[1] = Value::Integer(2.into());
        })),
        Err(AuthorityErrorV1::UnsupportedVersion)
    );
    assert_eq!(
        ObservationRecordV1::decode(&changed_array(&encoded, |fields| {
            fields[5] = Value::Integer(9.into());
        })),
        Err(AuthorityErrorV1::UnknownEnum)
    );
    assert_eq!(
        ObservationRecordV1::decode(&changed_array(&encoded, |fields| {
            fields[14] = Value::Bytes(vec![99; 32]);
        })),
        Err(AuthorityErrorV1::DigestMismatch)
    );
    let mut trailing = encoded.as_slice().to_vec();
    trailing.push(0);
    assert_eq!(
        ObservationRecordV1::decode(&CanonicalBytes::from_vec(trailing)),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
}

#[test]
fn observation_snapshot_validation_rejects_identity_provenance_and_size_drift() {
    let record =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .test_ok();

    let mut invalid = observation_snapshot_draft(vec![record.clone()], Vec::new());
    invalid.installation_id = [0; 16];
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = observation_snapshot_draft(vec![record.clone()], Vec::new());
    invalid.grant_chain_bindings.clear();
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ProvenanceMissing)
    );
    let mut invalid = observation_snapshot_draft(vec![record.clone()], Vec::new());
    invalid.grant_chain_bindings = vec![hash_from_repeated_byte(16); 2];
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ProvenanceMissing)
    );
    let mut invalid = observation_snapshot_draft(vec![record.clone()], Vec::new());
    invalid.participant_id = EntityId::from_ulid(Ulid::from(99_u128));
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::UnauthorizedSource)
    );
    let invalid = observation_snapshot_draft(
        vec![record.clone(); pos_core::MAX_OBSERVATION_SNAPSHOT_RECORDS + 1],
        Vec::new(),
    );
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    let artifact = ObservationArtifactV1::try_new(CanonicalBytes::from_vec(vec![
        7;
        MAX_OBSERVATION_ARTIFACT_BYTES
    ]))
    .test_ok();
    let record = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Present,
        Some(artifact.digest()),
    ))
    .test_ok();
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
            vec![record],
            vec![artifact]
        )),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn observation_snapshot_codec_rejects_nested_and_digest_tampering() {
    let artifact =
        ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed")).test_ok();
    let record = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Present,
        Some(artifact.digest()),
    ))
    .test_ok();
    let snapshot = ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
        vec![record],
        vec![artifact],
    ))
    .test_ok();
    let encoded = snapshot.encode().test_ok();

    for changed in [
        changed_array(&encoded, |fields| {
            fields[19] = Value::Text("records".to_owned())
        }),
        changed_array(&encoded, |fields| {
            fields[20] = Value::Text("artifacts".to_owned())
        }),
        changed_array(&encoded, |fields| fields[5] = Value::Bytes(vec![1; 15])),
    ] {
        assert_eq!(
            ObservationSnapshotV1::decode(&changed),
            Err(AuthorityErrorV1::InvalidEncoding)
        );
    }
    assert_eq!(
        ObservationSnapshotV1::decode(&changed_array(&encoded, |fields| {
            fields[23] = Value::Bytes(vec![88; 32]);
        })),
        Err(AuthorityErrorV1::DigestMismatch)
    );
    let changed_artifact = changed_array(&encoded, |fields| {
        let Value::Array(artifacts) = &mut fields[20] else {
            std::panic::resume_unwind(Box::new("expected artifact array"));
        };
        let Value::Array(artifact_fields) = &mut artifacts[0] else {
            std::panic::resume_unwind(Box::new("expected artifact record"));
        };
        artifact_fields[0] = Value::Bytes(vec![77; 32]);
    });
    assert_eq!(
        ObservationSnapshotV1::decode(&changed_artifact),
        Err(AuthorityErrorV1::DigestMismatch)
    );
}

#[test]
fn belief_and_knowledge_validation_reject_unbound_or_noncanonical_evidence() {
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let observation =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .test_ok();

    let mut invalid_belief = belief_draft(participant_id, "prefers.tea", observation.digest());
    invalid_belief.entity_id = EntityId::from_ulid(Ulid::nil());
    assert_eq!(
        BeliefRecordV1::try_from_draft(invalid_belief),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid_belief = belief_draft(participant_id, "prefers.tea", observation.digest());
    invalid_belief.predicate.clear();
    assert_eq!(
        BeliefRecordV1::try_from_draft(invalid_belief),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid_belief = belief_draft(participant_id, "prefers.tea", observation.digest());
    invalid_belief.observation_record_digests = vec![observation.digest(); 2];
    assert_eq!(
        BeliefRecordV1::try_from_draft(invalid_belief),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    let mut invalid_belief = belief_draft(participant_id, "prefers.tea", observation.digest());
    invalid_belief.provenance_digest = Hash::zero();
    assert_eq!(
        BeliefRecordV1::try_from_draft(invalid_belief),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    let belief = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "prefers.tea",
        observation.digest(),
    ))
    .test_ok();
    let mut invalid = knowledge_draft(
        participant_id,
        vec![observation.clone()],
        vec![belief.clone()],
    );
    invalid.beliefs[0] = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "prefers.tea",
        hash_from_repeated_byte(90),
    ))
    .test_ok();
    assert_eq!(
        KnowledgeSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ProvenanceMissing)
    );
    let mut invalid = knowledge_draft(participant_id, vec![observation.clone()], vec![belief]);
    invalid.external_provenance = vec![hash_from_repeated_byte(33); 2];
    assert_eq!(
        KnowledgeSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    let mut invalid = knowledge_draft(participant_id, vec![observation.clone()], Vec::new());
    invalid.external_provenance = vec![Hash::zero()];
    assert_eq!(
        KnowledgeSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let invalid = knowledge_draft(
        participant_id,
        vec![observation; MAX_KNOWLEDGE_SNAPSHOT_RECORDS + 1],
        Vec::new(),
    );
    assert_eq!(
        KnowledgeSnapshotV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn knowledge_snapshot_codec_rejects_nested_confidence_and_digest_tampering() {
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
    let snapshot = KnowledgeSnapshotV1::try_from_draft(knowledge_draft(
        participant_id,
        vec![observation],
        vec![belief],
    ))
    .test_ok();
    let encoded = snapshot.encode().test_ok();

    for changed in [
        changed_array(&encoded, |fields| {
            fields[7] = Value::Text("observations".to_owned())
        }),
        changed_array(&encoded, |fields| {
            fields[8] = Value::Text("beliefs".to_owned())
        }),
    ] {
        assert_eq!(
            KnowledgeSnapshotV1::decode(&changed),
            Err(AuthorityErrorV1::InvalidEncoding)
        );
    }
    let invalid_confidence = changed_array(&encoded, |fields| {
        let Value::Array(beliefs) = &mut fields[8] else {
            std::panic::resume_unwind(Box::new("expected belief array"));
        };
        let Value::Array(belief_fields) = &mut beliefs[0] else {
            std::panic::resume_unwind(Box::new("expected belief record"));
        };
        belief_fields[2] = Value::Integer(1_000_001_u64.into());
    });
    assert_eq!(
        KnowledgeSnapshotV1::decode(&invalid_confidence),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        KnowledgeSnapshotV1::decode(&changed_array(&encoded, |fields| {
            fields[15] = Value::Bytes(vec![66; 32]);
        })),
        Err(AuthorityErrorV1::DigestMismatch)
    );
}
