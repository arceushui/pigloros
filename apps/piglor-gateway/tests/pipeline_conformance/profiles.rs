//! ADR-021 Revision 3 scheduled observation profiles at the runtime seam.
//!
//! No production host composes a participant-bound Driver yet (the Scenario
//! Room host is planned for Wave 9). These runners act as the test host the
//! amendment names: they stage a participant-authorized pass through the
//! #481 seam and an anchored non-participant pass through the #480 seam,
//! and offer both to a recording admission port.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    AppendDedupKey, AppendDedupScope, AppendIdentity, ArtifactClaimInputV1, ArtifactDataClassV1,
    ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1, AssuranceLevelV1,
    AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1, AuthorityEvaluatorV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorizationRequestDraftV1,
    AuthorizationRequestV1, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, ConsentEvidenceV1, ConsentGrantRefDraftV1, ConsentGrantRefV1,
    ConsentGrantStatusV1, DelegationChainV1, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, Hash,
    KnowledgeSnapshotDraftV1, KnowledgeSnapshotV1, MemoryPolicyRevisionV1, ObservationSnapshotV1,
    PersistedAuthorityV1, PipelineAttemptIdV1, PipelineEvidenceRefV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, PluginId, PrincipalRefV1,
    Reducer, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, Seq, State,
    TimelineId, WallTime,
};
use pos_runtime::{
    AuthorizedDriverViewV1, AuthorizedViewAuthorityV1, Driver, ObservationView, PluginRegistry,
    ProjectionKey, RuntimeError, ScheduledPassAdmissionV1, StepOutput,
};
use pos_state::{
    AuthorizedObservationV1, ProjectionObservationContextV1, ProjectionObservationPolicyV1,
    ProjectionRegistry,
};

use super::{
    harness::Capture,
    support::{draft, expect_err, gated_registry, FixturePlugin, RecordingPort, TestOk},
};

/// The two observation digest domains ADR-021 Revision 3 Decision 5 names.
const ANCHORED_DOMAIN: &[u8] = b"PiglorOS.ScheduledObservationSnapshot.v1\0";
const AUTHORIZED_DOMAIN: &[u8] = b"PiglorOS.AuthorizedScheduledPass.v1\0";
/// The shared base cut of every pass in these runners.
const CUT: u64 = 12;
const PLANNED: &str = "participant.planned";

const fn digest(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

/// A participant-authorized view and the authority behind it.
struct Participant {
    observation: AuthorizedObservationV1,
    knowledge: KnowledgeSnapshotV1,
    state: AuthorityPersistenceStateV1,
    authority_registry: AuthorityRegistrySnapshotV1,
    grant: CapabilityGrantV1,
    plugin_id: PluginId,
    timeline_id: TimelineId,
}

struct Ids {
    principal: PrincipalRefV1,
    participant_id: EntityId,
    plugin_id: PluginId,
    authority_timeline: TimelineId,
    actor_id: EntityId,
    subject_id: EntityId,
}

struct EmptyReducer;

impl Reducer for EmptyReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &Event) {}
}

fn capability_grant(ids: &Ids) -> CapabilityGrantV1 {
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["projection.profile".to_owned()],
        actions: vec!["observe".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![ids.actor_id],
        subject_ids: vec![ids.subject_id],
        participant_ids: vec![ids.participant_id],
        plugin_id: Some(ids.plugin_id),
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 2,
        budget: 10,
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok();
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: digest(10),
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
        consent_references: vec![digest(8)],
        policy_revision: digest(7),
        issuance_timeline: ids.authority_timeline,
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: digest(6),
    })
    .test_ok()
}

fn consent_grant(ids: &Ids) -> ConsentGrantRefV1 {
    ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
        consent_id: digest(8),
        subject_id: ids.subject_id,
        grantee_id: ids.actor_id,
        data_categories: vec!["profile.preferences".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        action_classes: vec!["observe".to_owned()],
        valid_from: WallTime::from_micros(1),
        valid_until: WallTime::from_micros(100),
        withdrawal_retention_policy: "erase-derived-data".to_owned(),
        policy_revision: digest(7),
        issuer: ids.principal.clone(),
        issuer_evidence: digest(9),
        consent_timeline: ids.authority_timeline,
        grant_position: Seq::from_u64(5),
        status: ConsentGrantStatusV1::Active,
        revocation_fence: None,
        authority_registry_digest: digest(6),
    })
    .test_ok()
}

fn authorization_request(ids: &Ids, consent: ConsentGrantRefV1) -> AuthorizationRequestV1 {
    let authenticated =
        AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: ids.principal.clone(),
            adapter_id: "test-adapter".to_owned(),
            assurance: AssuranceLevelV1::try_new(1).test_ok(),
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(100),
            binding_digest: digest(5),
        })
        .test_ok();
    AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
        authenticated,
        actor_entity_id: ids.actor_id,
        subject_id: Some(ids.subject_id),
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
        consent_policy_revision: digest(7),
        capability_policy_revision: digest(7),
        revocation_epoch: 0,
        revocation_state_current: true,
        authority_registry_digest: digest(6),
        consent: ConsentEvidenceV1::Resolved {
            grants: vec![consent],
        },
        environment_constraints: vec!["local-only".to_owned()],
    })
    .test_ok()
}

fn knowledge_snapshot(snapshot: &ObservationSnapshotV1) -> KnowledgeSnapshotV1 {
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
            memory_policy_revision: MemoryPolicyRevisionV1::try_new(digest(21)).test_ok(),
            prior_snapshot_digest: None,
            external_provenance: Vec::new(),
            provenance_digest: digest(22),
        },
        snapshot,
    )
    .test_ok()
}

fn observation_evaluation(observation: &AuthorizedObservationV1) -> ReplayClaimEvaluationV1 {
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
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .test_ok()
}

fn participant() -> Participant {
    let ids = Ids {
        principal: PrincipalRefV1::try_new([1; 16], "host.test").test_ok(),
        participant_id: EntityId::new(),
        plugin_id: PluginId::new(),
        authority_timeline: TimelineId::new(),
        actor_id: EntityId::new(),
        subject_id: EntityId::new(),
    };
    let timeline_id = TimelineId::new();
    let consent = consent_grant(&ids);
    let grant = capability_grant(&ids);
    let request = authorization_request(&ids, consent.clone());
    let authority_registry = AuthorityRegistrySnapshotV1::try_new(
        digest(6),
        vec![request.authenticated().registry_binding_digest()],
        vec![grant.binding_digest().test_ok()],
        vec![consent.binding_digest()],
    )
    .test_ok();
    let host = AuthorityPersistenceHostV1::new(&authority_registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(host.authorize_grant(&grant).test_ok(), grant.clone())
        .test_ok();
    let authority = state.resolve(grant.grant_id()).test_ok();
    let chain = DelegationChainV1::try_from_grants(vec![grant.clone()]).test_ok();
    let decision = AuthorityEvaluatorV1::authorize(&request, &chain, &authority_registry);
    let mut projections = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    projections
        .register_observable(
            "profile",
            Box::new(EmptyReducer),
            ProjectionObservationPolicyV1::try_new(
                vec!["count".to_owned()],
                "profile.v1".to_owned(),
                digest(18),
                digest(19),
                digest(15),
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
                observed_through: Seq::from_u64(CUT),
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
    Participant {
        observation,
        knowledge,
        state,
        authority_registry,
        grant,
        plugin_id: ids.plugin_id,
        timeline_id,
    }
}

impl Participant {
    fn current_authority(&self) -> PersistedAuthorityV1 {
        self.state.resolve(self.grant.grant_id()).test_ok()
    }

    fn view(&self) -> AuthorizedDriverViewV1 {
        AuthorizedDriverViewV1 {
            plugin_id: self.plugin_id,
            observation: self.observation.clone(),
            knowledge: self.knowledge.clone(),
        }
    }

    const fn authority<'a>(
        &'a self,
        evaluation: &'a ReplayClaimEvaluationV1,
        authority: &'a PersistedAuthorityV1,
    ) -> AuthorizedViewAuthorityV1<'a> {
        AuthorizedViewAuthorityV1 {
            artifact_evaluation: evaluation,
            authority,
            authority_registry: &self.authority_registry,
            authority_position: Seq::from_u64(10),
        }
    }
}

/// A participant Driver that emits one planned draft and counts aborts.
struct PlannedDriver {
    entity: EntityId,
    aborts: Arc<AtomicUsize>,
    ambient: Option<ProjectionKey>,
}

impl Driver for PlannedDriver {
    fn name(&self) -> &'static str {
        "participant-driver"
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        self.ambient.as_slice()
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![draft(
            self.entity,
            PLANNED,
            b"planned",
        )]))
    }

    fn abort_step(&mut self) {
        self.aborts.fetch_add(1, Ordering::SeqCst);
    }
}

fn participant_registry(
    participant: &Participant,
    ambient: bool,
) -> (PluginRegistry, Arc<AtomicUsize>) {
    let aborts = Arc::new(AtomicUsize::new(0));
    let mut registry = gated_registry(None);
    registry
        .register_generated(
            &FixturePlugin {
                id: participant.plugin_id,
                name: "participant-driver",
                owned: vec![PLANNED],
                has_driver: true,
            },
            None,
            Some(Box::new(PlannedDriver {
                entity: EntityId::new(),
                aborts: Arc::clone(&aborts),
                ambient: ambient.then(|| ProjectionKey::new(EntityId::new())),
            })),
        )
        .test_ok();
    (registry, aborts)
}

/// Host admission inputs for a port that never commits.
fn admission() -> ScheduledPassAdmissionV1 {
    ScheduledPassAdmissionV1 {
        attempt_id: PipelineAttemptIdV1::try_new([1; 16]).test_ok(),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([2; 32]),
            AppendDedupScope::from_keyed_hash([3; 32]),
        ),
        provider_validation: PipelineEvidenceRefV1::try_new(digest(4)).test_ok(),
        security_revisions: PipelineSecurityRevisionsV1::try_from_draft(
            PipelineSecurityRevisionsDraftV1 {
                authority: digest(5),
                consent: digest(6),
                capability: digest(7),
                delegation: digest(8),
                policy: digest(9),
                execution_profile: digest(10),
                erasure: digest(11),
            },
        )
        .test_ok(),
        commit_head: Seq::from_u64(CUT),
        commit_now_secs: 1,
    }
}

fn stage_authorized(
    registry: &mut PluginRegistry,
    participant: &Participant,
) -> Result<usize, RuntimeError> {
    let evaluation = observation_evaluation(&participant.observation);
    let current = participant.current_authority();
    registry
        .stage_authorized_scheduled_pass(
            participant.timeline_id,
            Seq::from_u64(CUT),
            &[participant.view()],
            &[participant.authority(&evaluation, &current)],
        )
        .map(|drafts| drafts.len())
}

fn admit_authorized(
    registry: &mut PluginRegistry,
    participant: &Participant,
    port: &mut RecordingPort,
) -> RuntimeError {
    let evaluation = observation_evaluation(&participant.observation);
    let current = participant.current_authority();
    expect_err(registry.admit_authorized_scheduled_pass(
        port,
        &admission(),
        &[participant.authority(&evaluation, &current)],
    ))
}

/// PCF-R3-001: a participant-authorized pass offered to the anchored
/// admission path fails with `AuthorityFenceRequired`; nothing reaches the
/// store and the staged Driver is aborted.
#[must_use]
pub fn participant_pass_needs_its_fence() -> Capture {
    let mut capture = Capture::default();
    let participant = participant();
    let (mut registry, aborts) = participant_registry(&participant, false);
    let staged = stage_authorized(&mut registry, &participant).test_ok();
    let mut port = RecordingPort::default();
    let refused = expect_err(registry.admit_scheduled_pass(&mut port, &admission()));
    capture.record("none", "staged", staged);
    capture.record("none", "anchored-admission", refused);
    capture.record("none", "offered-to-store", port.offered.len());
    capture.record("none", "driver-aborted", aborts.load(Ordering::SeqCst));
    capture
}

/// PCF-R3-002: one scheduled pass is never both observation profiles.
///
/// An authorized stage while an anchored pass is pending, the authorized
/// admission of an anchored pass, and a subscription-scoped Driver offered to
/// the authorized
/// path all fail closed before anything reaches the store.
#[must_use]
pub fn one_pass_one_profile() -> Capture {
    let mut capture = Capture::default();
    let participant = participant();
    let (mut registry, aborts) = participant_registry(&participant, false);
    let mut port = RecordingPort::default();
    let anchored = registry
        .step_all_anchored(participant.timeline_id, Seq::from_u64(CUT))
        .test_ok();
    let mixed = expect_err(stage_authorized(&mut registry, &participant));
    let crossed = admit_authorized(&mut registry, &participant, &mut port);
    capture.record("none", "anchored.staged", anchored.len());
    capture.record("none", "authorized-stage-while-anchored-pending", mixed);
    capture.record("none", "authorized-admission-of-anchored-pass", crossed);
    capture.record("none", "anchored.aborted", aborts.load(Ordering::SeqCst));

    let (mut ambient, _) = participant_registry(&participant, true);
    let scoped = expect_err(stage_authorized(&mut ambient, &participant));
    capture.record(
        "none",
        "subscription-scoped-driver-on-authorized-path",
        scoped,
    );
    capture.record("none", "offered-to-store", port.offered.len());
    capture
}

fn anchored_digest(timeline: TimelineId, cut: u64) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ANCHORED_DOMAIN);
    hasher.update(&timeline.inner().to_bytes());
    hasher.update(&cut.to_be_bytes());
    hasher.update(&0_u64.to_be_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// PCF-R3-003: for the same cut and state, the anchored and the authorized
/// observation digests bound into the admission basis come from disjoint
/// domains.
#[must_use]
pub fn digest_domain_separation() -> Capture {
    let mut capture = Capture::default();
    let participant = participant();
    let (mut registry, _) = participant_registry(&participant, false);
    let mut port = RecordingPort::default();
    registry
        .step_all_anchored(participant.timeline_id, Seq::from_u64(CUT))
        .test_ok();
    let anchored_refusal = expect_err(registry.admit_scheduled_pass(&mut port, &admission()));
    stage_authorized(&mut registry, &participant).test_ok();
    let authorized_refusal = admit_authorized(&mut registry, &participant, &mut port);
    let digests: Vec<Hash> = port
        .offered
        .iter()
        .map(|basis| basis.attempt().observation().snapshot_digest())
        .collect();
    let cuts: Vec<u64> = port
        .offered
        .iter()
        .map(|basis| basis.attempt().observation().observed_through().as_u64())
        .collect();
    let independent = anchored_digest(participant.timeline_id, CUT);
    capture.record("none", "anchored.refusal", anchored_refusal);
    capture.record("none", "authorized.refusal", authorized_refusal);
    capture.record("none", "offered", digests.len());
    capture.record("none", "cuts", format!("{cuts:?}"));
    capture.record(
        "none",
        "anchored.in-declared-domain",
        digests.first() == Some(&independent),
    );
    capture.record(
        "none",
        "authorized.outside-anchored-domain",
        digests.get(1).is_some_and(|second| *second != independent),
    );
    capture.record("none", "profiles-differ", digests.first() != digests.get(1));
    capture.record(
        "none",
        "domains-prefix-free",
        !ANCHORED_DOMAIN.starts_with(AUTHORIZED_DOMAIN)
            && !AUTHORIZED_DOMAIN.starts_with(ANCHORED_DOMAIN),
    );
    capture
}
