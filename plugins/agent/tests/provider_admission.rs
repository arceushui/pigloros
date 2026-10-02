//! ADR-046 provider output reaches the Timeline only through ADR-021 host admission.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::sync::Arc;

use pos_core::{
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AuthorityGranteeV1,
    AuthorityPersistenceHostV1, AuthorityPersistencePortV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, Capability, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, DelegateClassV1, EntityId, ErasureContainmentGateV1, EventStore, Hash, Kind,
    PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1, PipelineAttemptIdV1,
    PipelineEvidenceRefV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, Plugin,
    PluginId, PrincipalRefV1, Seq, SeqRange, TimelineId, DELEGATE_ACTION_V1,
};
use pos_plugin_agent::{
    protocol::{
        ActionCatalogueV1, AgentProviderProvenanceV1, BoundedProviderBytes, ProviderAttempt,
    },
    AgentDecisionReplayVerifier, FixtureAgentDecisionProvider, ProviderBackedAgentDriver,
    EVENT_TYPE_ACTION,
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, schema::EventTypeSchema, InstalledOutputPolicySourceV1,
    OutputPolicyBindingV1, PluginRegistry, RuntimeError, ScheduledPassAdmissionV1,
    TimelineHistorySegment,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;

#[cfg_attr(coverage_nightly, coverage(off))]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn principal(value: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([value; 16], "local.test"))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn root_grant() -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash(1),
        grantor: principal(1),
        grantee: AuthorityGranteeV1::Principal(principal(2)),
        trust_domain: "local.test".to_owned(),
        scope: ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["world".to_owned()],
            actions: vec!["act".to_owned(), DELEGATE_ACTION_V1.to_owned()],
            purposes: vec!["simulation".to_owned()],
            audiences: vec!["local-host".to_owned()],
            actor_entity_ids: vec![entity(10)],
            subject_ids: vec![entity(50)],
            participant_ids: vec![entity(20)],
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 10,
            budget: 100,
            environment_constraints: vec!["local-only".to_owned()],
        })),
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 2,
        permitted_delegate_classes: vec![DelegateClassV1::Principal],
        consent_references: vec![hash(8)],
        policy_revision: hash(9),
        issuance_timeline: TimelineId::from_ulid(Ulid::from(30_u128)),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn revisions(
    authority: Hash,
    delegation: Hash,
    erasure: Hash,
    consent: u8,
) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority,
            consent: hash(consent),
            capability: hash(12),
            delegation,
            policy: hash(14),
            execution_profile: hash(15),
            erasure,
        },
    ))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn publish(store: &mut MemoryStore, timeline: TimelineId, revisions: PipelineSecurityRevisionsV1) {
    ok(store.set_pipeline_admission_fence(
        timeline,
        ok(PipelineAdmissionFenceV1::try_new(
            hash(1),
            revisions,
            None,
            10,
        )),
    ));
}

/// Bind the erasure gate and persisted authority, then publish the fence.
#[cfg_attr(coverage_nightly, coverage(off))]
fn admission_store(
    gate: &Arc<ErasureContainmentGateV1>,
) -> (MemoryStore, TimelineId, PipelineSecurityRevisionsV1) {
    let mut store = MemoryStore::new();
    let timeline = ok(store.create_timeline("provider-admission")).id();
    ok(store.bind_erasure_gate(Arc::clone(gate)));
    let host = AuthorityPersistenceHostV1::new(&ok(AuthorityRegistrySnapshotV1::try_new(
        hash(7),
        vec![hash(200)],
        vec![ok(root_grant().binding_digest())],
        vec![],
    )));
    ok(store.bind_authority_persistence(host.persistence_binding()));
    let root = root_grant();
    ok(store.issue_capability_grant(ok(host.authorize_grant(&root)), &root));
    let authority = ok(store.load_authority(hash(1)));
    let current = revisions(
        pipeline_authority_revision_v1(&authority),
        pipeline_delegation_revision_v1(&authority),
        pipeline_erasure_revision_v1(gate.inventory_generation().ok()),
        11,
    );
    publish(&mut store, timeline, current);
    (store, timeline, current)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn admission(
    store: &MemoryStore,
    timeline: TimelineId,
    revisions: PipelineSecurityRevisionsV1,
    key: u8,
) -> ScheduledPassAdmissionV1 {
    ScheduledPassAdmissionV1 {
        attempt_id: ok(PipelineAttemptIdV1::try_new([key; 16])),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([62; 32]),
        ),
        provider_validation: ok(PipelineEvidenceRefV1::try_new(hash(60))),
        security_revisions: revisions,
        commit_head: ok(store.logical_head(timeline)),
        commit_now_secs: 1,
    }
}

struct AgentBindingPlugin {
    id: PluginId,
}

impl Plugin for AgentBindingPlugin {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id(&self) -> PluginId {
        self.id
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        "agent"
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn version(&self) -> &'static str {
        "1.0.0"
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_ACTION), Kind::new(RECORDER_EVENT_TYPE)],
            ..Capability::default()
        }
    }
}

/// Minimal `PDP1` acceptance of catalogue index 0, encoded independently.
#[cfg_attr(coverage_nightly, coverage(off))]
fn accepted_proposal() -> ProviderAttempt {
    // [ "PDP1", 1, 0, index 0, confidence 900000 ]
    let bytes = vec![
        0x85, 0x44, b'P', b'D', b'P', b'1', 0x01, 0x00, 0x00, 0x1a, 0x00, 0x0d, 0xbb, 0xa0,
    ];
    ProviderAttempt::Response(ok(BoundedProviderBytes::try_from(bytes)))
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn provider_proposal_commits_only_through_host_admission() {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let (mut store, timeline, current) = admission_store(&gate);
    let agent = entity(10);
    let plugin = AgentBindingPlugin {
        id: PluginId::from_ulid(Ulid::from(40_u128)),
    };
    let catalogue = ok(ActionCatalogueV1::try_new(vec![
        "move".to_owned(),
        "wait".to_owned(),
    ]));
    let provenance = ok(AgentProviderProvenanceV1::try_new(
        plugin.id,
        "1.0.0".to_owned(),
        [0x31; 32],
        "fixture-local".to_owned(),
        "fixture-v1".to_owned(),
        [0x32; 32],
    ));
    let provider =
        FixtureAgentDecisionProvider::new(vec![accepted_proposal(), accepted_proposal()]);
    let calls = provider.call_count_handle();
    let mut registry = PluginRegistry::new().with_erasure_gate(gate);
    let binding = ok(OutputPolicyBindingV1::from_installed_source(
        &plugin,
        InstalledOutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    ));
    ok(registry.register_test_driver_with_verified_output_policy(
        plugin.id,
        binding,
        Box::new(ProviderBackedAgentDriver::new(
            agent,
            catalogue.clone(),
            provenance.clone(),
            Box::new(provider),
        )),
    ));
    ok(registry.schemas.register(EventTypeSchema {
        event_type: Kind::new(EVENT_TYPE_ACTION),
        description: "host-constructed Agent action".to_owned(),
        json_schema: None,
    }));

    // A validated provider proposal is still tentative: a stale basis
    // discards it and commits nothing.
    ok(registry.step_all_anchored(timeline, Seq::ZERO));
    publish(
        &mut store,
        timeline,
        revisions(
            hash(70),
            current.as_draft().delegation,
            current.as_draft().erasure,
            71,
        ),
    );
    let stale = admission(&store, timeline, current, 1);
    let rejected = registry.admit_scheduled_pass(&mut store, &stale);
    assert!(matches!(
        rejected,
        Err(RuntimeError::ScheduledPassNotAdmitted(_))
    ));
    assert!(ok(store.read(timeline, SeqRange::all())).is_empty());
    publish(&mut store, timeline, current);

    let drafts = ok(registry.step_all_anchored(timeline, Seq::ZERO));
    assert_eq!(calls.get(), 2);
    let admitted = admission(&store, timeline, current, 2);
    let receipt = ok(registry.admit_scheduled_pass(&mut store, &admitted))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected a committed batch")));

    // Event identity and Timeline Order come only from the store transaction.
    let events = ok(store.read(timeline, SeqRange::all()));
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| event.event_type.as_str())
        .collect();
    assert_eq!(kinds, [RECORDER_EVENT_TYPE, EVENT_TYPE_ACTION]);
    assert_eq!(drafts.len(), events.len());
    let identities: Vec<_> = receipt
        .committed_events()
        .iter()
        .map(|committed| (committed.event_id(), committed.seq()))
        .collect();
    let stored: Vec<_> = events.iter().map(|event| (event.id, event.seq)).collect();
    assert_eq!(identities, stored);

    // Replay reads committed evidence and never calls the provider again.
    let verifier = ok(AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
        vec![TimelineHistorySegment::new(timeline, Seq::from_u64(32))],
        agent,
        provenance,
        catalogue,
    ));
    assert_eq!(
        ok(verifier.verify(&events, None)).last_verified(),
        Seq::from_u64(2)
    );
    assert_eq!(calls.get(), 2);
}
