//! ADR-021 scheduled AI Driver passes through atomic host admission (#318).
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pos_core::{
    factual_artifact_digest, factual_event_schema_id, factual_fold_checkpoint_content_digest,
    factual_fold_history_content_digest, factual_history_content_digest,
    factual_ingress_content_digest, factual_verified_prefix_content_digest,
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AuthorityErrorV1, AuthorityGranteeV1,
    AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, Capability,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, ConsentAuthority, ConsentGrantedV1,
    ConsentRevokedV1, CoreError, CounterfactualDependencyErrorV1, DelegateClassV1,
    DependencyNodeCoordinateV1, DependencyNodeRecordV1, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, EventStore, FactualDependencyErrorV1, FactualEventRefV1, FactualFoldCursorV1,
    FactualFoldWindowV1, FactualHostOwnerV1, FactualNodeKeyV1, FactualPrefixReadPortV1,
    FactualTickDependenciesV1, Hash, Kind, PersistedAuthorityV1, PipelineAdmissionBasisDraftV1,
    PipelineAdmissionBasisV1, PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1,
    PipelineAdmissionPortV1, PipelineAttemptIdV1, PipelineCommitReceiptV1, PipelineContractErrorV1,
    PipelineEvidenceRefV1, PipelineOutcomeV1, PipelineSecurityRevisionsDraftV1,
    PipelineSecurityRevisionsV1, Plugin, PluginId, PrincipalRefV1, RecordedDependencyClassV1,
    RecordedNodeOriginV1, RecordedSetCountsV1, Reducer, Seq, SeqRange, State,
    TickDependencyRecordV1, TimelineId, DELEGATE_ACTION_V1, EVENT_TYPE_CONSENT_GRANTED_V1,
    EVENT_TYPE_CONSENT_REVOKED_V1, FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1, FACTUAL_FOLD_SCHEMA_ID_V1,
    FACTUAL_HISTORY_SCHEMA_ID_V1, FACTUAL_PREFIX_SCHEMA_ID_V1, FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
    FACTUAL_STEP_SCHEMA_ID_V1, GEOGRAPHIC_EVENT_TYPE, HOST_CONSENT_CLOSED_EVENT_TYPE,
    MAX_FACTUAL_FOLD_INPUT_EDGES_PER_TICK_V1, MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1,
    MAX_FORWARDED_EVENTS_PER_DRIVER_V1, MAX_OUTPUT_DIRECT_INPUTS_V1, MAX_STEP_INPUTS_PER_DRIVER_V1,
    PIPELINE_CONTRACT_VERSION_V1,
};
use pos_runtime::{
    DeclaredOutputV1, DirectInputRefV1, Driver, LocalScheduledAdmissionHostV1, ObservationView,
    PluginRegistry, ProjectionKey, RuntimeError, ScheduledAdmissionStoreV1,
    ScheduledDriverBindingV1, ScheduledPassAdmissionV1, StepOutput, TimelineHistorySegment,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use ulid::Ulid;

/// The one-member Fork ancestry of a fixture Timeline with no parent.
fn root_ancestry(timeline: pos_core::TimelineId) -> Vec<pos_core::TimelineMeta> {
    vec![pos_core::TimelineMeta {
        id: timeline,
        ..pos_core::TimelineMeta::root("root")
    }]
}

const PROJECTION: &str = "agent.scheduled.projection";

type Admitted = Result<Option<PipelineCommitReceiptV1>, RuntimeError>;

/// A committed factual Tick a store seeds without a pipeline commit.
type SeededTick = pos_core::counterfactual_store::test_fixtures::SeededFactualTickV1;

/// The seeding seam both adapters expose until slices 8 and 9 write rows.
trait Seed {
    fn seed(&mut self, timeline: TimelineId, ticks: &[SeededTick]);
}

impl Seed for MemoryStore {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seed(&mut self, timeline: TimelineId, ticks: &[SeededTick]) {
        ok(self.seed_factual_prefix(timeline, ticks));
    }
}

impl Seed for SqliteStore {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seed(&mut self, timeline: TimelineId, ticks: &[SeededTick]) {
        ok(self.seed_factual_prefix(timeline, ticks));
    }
}

trait Harness:
    ScheduledAdmissionStoreV1
    + EventStore
    + PipelineAdmissionPortV1
    + FactualPrefixReadPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
    + Seed
{
}

impl<T: ScheduledAdmissionStoreV1 + Seed> Harness for T {}

#[cfg_attr(coverage_nightly, coverage(off))]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// The one authority grant every admission in this file runs under.
const GRANT: Hash = hash(1);

#[cfg_attr(coverage_nightly, coverage(off))]
fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn stores() -> Vec<(&'static str, Box<dyn Harness>)> {
    vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(ok(SqliteStore::open(":memory:")))),
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn principal(value: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([value; 16], "local.test"))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(30_u128))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn root_grant() -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: GRANT,
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
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn authority_host() -> AuthorityPersistenceHostV1 {
    AuthorityPersistenceHostV1::new(&ok(AuthorityRegistrySnapshotV1::try_new(
        hash(7),
        vec![hash(200)],
        vec![ok(root_grant().binding_digest())],
        vec![],
    )))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn revisions(authority: &PersistedAuthorityV1, erasure: Hash) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority: pipeline_authority_revision_v1(authority),
            consent: hash(11),
            capability: hash(12),
            delegation: pipeline_delegation_revision_v1(authority),
            policy: hash(14),
            execution_profile: hash(15),
            erasure,
        },
    ))
}

/// The same revisions after the consent owner republished a new revision.
#[cfg_attr(coverage_nightly, coverage(off))]
fn stale_consent(current: PipelineSecurityRevisionsV1) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            consent: hash(71),
            ..current.as_draft()
        },
    ))
}

/// Publish the host-owned admission fence for one Timeline.
#[cfg_attr(coverage_nightly, coverage(off))]
fn publish(
    store: &mut dyn Harness,
    timeline: TimelineId,
    revisions: PipelineSecurityRevisionsV1,
    budget: u64,
) {
    ok(store.set_pipeline_admission_fence(
        timeline,
        ok(PipelineAdmissionFenceV1::try_new(
            GRANT, revisions, None, budget,
        )),
    ));
}

/// Host-owned admission state for one Timeline in one store.
struct Host {
    timeline: TimelineId,
    gate: Arc<ErasureContainmentGateV1>,
    authority: AuthorityPersistenceHostV1,
    revisions: PipelineSecurityRevisionsV1,
}

impl Host {
    /// Persist the root authority grant and publish a fence with `budget`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prepare(store: &mut dyn Harness, budget: u64) -> Self {
        let timeline = ok(store.create_timeline("scheduled-admission")).id();
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        ok(store.bind_erasure_gate(Arc::clone(&gate)));
        let authority = authority_host();
        ok(store.bind_authority_persistence(authority.persistence_binding()));
        let root = root_grant();
        ok(store.issue_capability_grant(ok(authority.authorize_grant(&root)), &root));
        let current = revisions(
            &ok(store.load_authority(GRANT)),
            pipeline_erasure_revision_v1(gate.inventory_generation().ok()),
        );
        publish(store, timeline, current, budget);
        Self {
            timeline,
            gate,
            authority,
            revisions: current,
        }
    }

    /// The same host state bound to another Timeline in the same store.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn on(&self, timeline: TimelineId) -> Self {
        Self {
            timeline,
            gate: Arc::clone(&self.gate),
            authority: authority_host(),
            revisions: self.revisions,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revoke_root(&self, store: &mut dyn Harness) {
        let revocation = ok(CapabilityRevocationV1::try_from_draft(
            CapabilityRevocationDraftV1 {
                grant_id: GRANT,
                authority_timeline: authority_timeline(),
                fence_position: Seq::from_u64(2),
                revocation_epoch: 1,
                policy_revision: hash(9),
                authority_registry_digest: hash(7),
            },
        ));
        ok(store.revoke_capability_grant(
            ok(self
                .authority
                .authorize_revocation(&root_grant(), &revocation)),
            &revocation,
        ));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn registry(&self) -> PluginRegistry {
        PluginRegistry::new().with_erasure_gate(self.gate.clone())
    }

    /// Host-issued admission inputs read after the pass finished.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admission(&self, store: &dyn Harness, key: u8) -> ScheduledPassAdmissionV1 {
        ScheduledPassAdmissionV1 {
            attempt_id: ok(PipelineAttemptIdV1::try_new([key; 16])),
            idempotency: AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([key; 32]),
                AppendDedupScope::from_keyed_hash([62; 32]),
            ),
            provider_validation: ok(PipelineEvidenceRefV1::try_new(hash(60))),
            security_revisions: self.revisions,
            // The grant `publish` names in the Timeline's fence.
            authority_grant: GRANT,
            commit_head: ok(store.logical_head(self.timeline)),
            commit_now_secs: 1,
        }
    }

    /// Admit the staged pass with host inputs read after it finished.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit(&self, registry: &mut PluginRegistry, store: &mut dyn Harness, key: u8) -> Admitted {
        let admission = self.admission(store, key);
        registry.admit_scheduled_pass(store, &admission)
    }
}

type Log = Arc<Mutex<Vec<String>>>;

#[cfg_attr(coverage_nightly, coverage(off))]
fn entries(log: &Log) -> Vec<String> {
    log.lock()
        .map(|entries| entries.to_vec())
        .unwrap_or_default()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn record(log: &Log, entry: String) {
    log.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(entry);
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn count(log: &Log, suffix: &str) -> usize {
    entries(log)
        .iter()
        .filter(|entry| entry.ends_with(suffix))
        .count()
}

/// Deterministic Driver that emits its payload vector and logs its lifecycle.
struct ScriptedDriver {
    name: &'static str,
    event_type: &'static str,
    entity: EntityId,
    payloads: Vec<&'static [u8]>,
    subscriptions: Vec<ProjectionKey>,
    fail: Option<bool>,
    log: Log,
}

impl Driver for ScriptedDriver {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        self.name
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_interval(&self) -> Duration {
        Duration::from_nanos(10)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step(
        &mut self,
        _: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let anchor = observations
            .anchor()
            .map_or(u64::MAX, |anchor| anchor.observed_through().as_u64());
        record(&self.log, format!("{}:step@{anchor}", self.name));
        match self.fail {
            Some(true) => std::panic::resume_unwind(Box::new("scripted Driver trap")),
            Some(false) => Err(RuntimeError::NoDriver {
                name: self.name.to_owned(),
            }),
            None => Ok(StepOutput::new(
                self.payloads
                    .iter()
                    .map(|payload| {
                        EventDraft::new(
                            self.entity,
                            Kind::new(self.event_type),
                            CanonicalBytes::from_static(payload),
                        )
                    })
                    .collect(),
            )),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn commit_step(&mut self) {
        record(&self.log, format!("{}:commit", self.name));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn abort_step(&mut self) {
        record(&self.log, format!("{}:abort", self.name));
    }
}

struct TestPlugin {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
    reducer: bool,
}

impl Plugin for TestPlugin {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id(&self) -> PluginId {
        self.id
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        self.name
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            owned_entity_kinds: Vec::new(),
            has_driver: !self.reducer,
            has_reducer: self.reducer,
        }
    }
}

struct CountingReducer;

impl Reducer for CountingReducer {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn initial(&self) -> State {
        State::new()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn apply(&self, state: &mut State, _: &Event) {
        let count = state
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::Value::Number((count + 1).into()));
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn register(registry: &mut PluginRegistry, driver: ScriptedDriver) {
    let plugin = TestPlugin {
        id: PluginId::new(),
        name: driver.name,
        event_type: driver.event_type,
        reducer: false,
    };
    // Registration records the owned type's schema; it is never re-registered.
    ok(registry.register_generated(&plugin, None, Some(Box::new(driver))));
    ok(registry.compose_non_participant_drivers());
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn driver(name: &'static str, payloads: Vec<&'static [u8]>, log: &Log) -> ScriptedDriver {
    let event_type = match name {
        "first" => "agent.scheduled.first",
        "second" => "agent.scheduled.second",
        _ => "agent.scheduled.observer",
    };
    ScriptedDriver {
        name,
        event_type,
        entity: entity(10),
        payloads,
        subscriptions: Vec::new(),
        fail: None,
        log: Arc::clone(log),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn committed_events(store: &dyn Harness, timeline: TimelineId) -> Vec<Event> {
    ok(store.read(timeline, SeqRange::all()))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn budget(store: &dyn Harness, timeline: TimelineId) -> Option<u64> {
    ok(store.pipeline_admission_fence(timeline))
        .as_ref()
        .map(PipelineAdmissionFenceV1::remaining_event_budget)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn receipt(result: Admitted) -> PipelineCommitReceiptV1 {
    ok(result).unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected a committed batch")))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn rejection(result: Admitted) -> String {
    let error = err(result);
    assert!(error
        .to_string()
        .starts_with("scheduled pass was not admitted"));
    match error {
        RuntimeError::ScheduledPassNotAdmitted(outcome) => format!("{outcome:?}"),
        other => std::panic::resume_unwind(Box::new(format!("expected a rejection: {other}"))),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn human_event(store: &mut dyn Harness, timeline: TimelineId) {
    ok(store.append(
        timeline,
        &[EventDraft::new(
            entity(20),
            Kind::new("human.action"),
            CanonicalBytes::from_static(b"human"),
        )],
    ));
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn scheduled_pass_commits_every_due_batch_in_schedule_and_vector_order() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));
        register(&mut registry, driver("second", vec![b"b1"], &log));

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        // A human Event committed while the pass ran does not invalidate its
        // shared base snapshot; the host binds the head it reads afterwards.
        human_event(store.as_mut(), host.timeline);
        let committed = receipt(host.admit(&mut registry, store.as_mut(), 1));

        let events = committed_events(store.as_ref(), host.timeline);
        let payloads: Vec<&[u8]> = events[1..]
            .iter()
            .map(|event| event.payload.as_slice())
            .collect();
        assert_eq!(payloads, [&b"a1"[..], &b"a2"[..], &b"b1"[..]], "{name}");
        let positions: Vec<_> = committed
            .committed_events()
            .iter()
            .map(|event| (event.seq().as_u64(), event.event_id()))
            .collect();
        let stored: Vec<_> = events[1..]
            .iter()
            .map(|event| (event.seq.as_u64(), event.id))
            .collect();
        assert_eq!(positions, stored, "{name}");
        assert_eq!(committed.timeline_id(), host.timeline, "{name}");
        assert_eq!(
            entries(&log),
            [
                "first:step@0",
                "second:step@0",
                "first:commit",
                "second:commit"
            ],
            "{name}"
        );
        assert_eq!(budget(store.as_ref(), host.timeline), Some(7), "{name}");

        ok(registry.step_all_anchored(
            host.timeline,
            &root_ancestry(host.timeline),
            Seq::from_u64(4),
        ));
        registry.abort_step();
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn stale_basis_and_late_revocation_abort_the_whole_pass() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        register(&mut registry, driver("second", vec![b"b1"], &log));

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        publish(
            store.as_mut(),
            host.timeline,
            stale_consent(host.revisions),
            10,
        );
        let stale = host.admit(&mut registry, store.as_mut(), 1);
        assert_eq!(rejection(stale), "AdmissionConflict", "{name}");
        publish(store.as_mut(), host.timeline, host.revisions, 10);

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        let admission = host.admission(store.as_ref(), 2);
        human_event(store.as_mut(), host.timeline);
        let moved = registry.admit_scheduled_pass(store.as_mut(), &admission);
        assert_eq!(rejection(moved), "AdmissionConflict", "{name}");

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        host.revoke_root(store.as_mut());
        let revoked = host.admit(&mut registry, store.as_mut(), 3);
        assert_eq!(rejection(revoked), "AuthorityRevoked", "{name}");

        assert_eq!(committed_events(store.as_ref(), host.timeline).len(), 1);
        assert_eq!(budget(store.as_ref(), host.timeline), Some(10), "{name}");
        assert_eq!(count(&log, ":abort"), 6, "{name}");
        assert_eq!(count(&log, ":commit"), 0, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn store_budget_fence_and_erasure_failures_commit_nothing() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        let exhausted = host.admit(&mut registry, store.as_mut(), 1);
        assert_eq!(rejection(exhausted), "ResourceExhausted", "{name}");

        let unfenced = host.on(ok(store.create_timeline("unfenced")).id());
        ok(registry.step_all_anchored(
            unfenced.timeline,
            &root_ancestry(unfenced.timeline),
            Seq::ZERO,
        ));
        let missing = unfenced.admit(&mut registry, store.as_mut(), 2);
        assert_eq!(rejection(missing), "PolicyIndeterminate", "{name}");

        assert!(committed_events(store.as_ref(), host.timeline).is_empty());
        publish(store.as_mut(), host.timeline, host.revisions, 10);
        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        let admission = host.admission(store.as_ref(), 3);
        host.gate.freeze_timeline_for_test(host.timeline);
        let frozen = err(registry.admit_scheduled_pass(store.as_mut(), &admission));
        assert!(
            matches!(frozen, RuntimeError::Store(CoreError::ErasureAccessFrozen)),
            "{name}: {frozen}"
        );

        assert_eq!(count(&log, ":step@0"), 3, "{name}");
        assert_eq!(count(&log, ":abort"), 3, "{name}");
        assert_eq!(count(&log, ":commit"), 0, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn driver_failure_trap_and_invalid_basis_discard_the_pass() {
    let mut store = MemoryStore::new();
    let host = Host::prepare(&mut store, 10);
    for fail in [false, true] {
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        register(
            &mut registry,
            ScriptedDriver {
                fail: Some(fail),
                ..driver("second", Vec::new(), &log)
            },
        );
        assert!(registry
            .step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO)
            .is_err());
        let nothing = err(host.admit(&mut registry, &mut store, 1));
        assert!(matches!(nothing, RuntimeError::PendingDriverStep));
        assert_eq!(
            entries(&log),
            [
                "first:step@0",
                "second:step@0",
                "first:abort",
                "second:abort"
            ]
        );
    }

    let log = Log::default();
    let mut registry = host.registry();
    register(&mut registry, driver("first", vec![b"a1"], &log));
    ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
    let admission = ScheduledPassAdmissionV1 {
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([0; 32]),
            AppendDedupScope::from_keyed_hash([62; 32]),
        ),
        ..host.admission(&store, 1)
    };
    let invalid = err(registry.admit_scheduled_pass(&mut store, &admission));
    assert!(matches!(
        invalid,
        RuntimeError::PipelineContract(PipelineContractErrorV1::FieldOutOfBounds)
    ));
    assert!(invalid.to_string().contains("admission basis is invalid"));
    assert_eq!(entries(&log), ["first:step@0", "first:abort"]);
    assert!(committed_events(&store, host.timeline).is_empty());
}

/// Port that commits through the real store and then loses the outcome. It
/// keeps the basis it was offered.
struct LostOutcomePort<'a> {
    inner: &'a mut dyn Harness,
    bases: Vec<PipelineAdmissionBasisV1>,
}

impl PipelineAdmissionPortV1 for LostOutcomePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.bases.push(basis.clone());
        self.inner.admit_pipeline_batch(basis).and_then(|_| {
            Err(CoreError::StorageOutcomeUnknown(
                "injected lost commit acknowledgement".to_owned(),
            ))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: pos_core::TimelineId,
        key: pos_core::AppendDedupKey,
        attempt_id: pos_core::PipelineAttemptIdV1,
    ) -> Result<pos_core::PipelineReceiptLookupV1, pos_core::CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl FactualPrefixReadPortV1 for LostOutcomePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.inner.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.inner.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.inner.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.inner.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.inner.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.inner.factual_set_counts(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        self.inner.fold_cursor(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        self.inner.fold_window(timeline, after, through)
    }
}

/// Admit the staged pass through a port that loses the outcome, and return the
/// basis the store was offered.
#[cfg_attr(coverage_nightly, coverage(off))]
fn lose_outcome_basis(
    host: &Host,
    registry: &mut PluginRegistry,
    store: &mut dyn Harness,
    key: u8,
) -> PipelineAdmissionBasisV1 {
    let admission = host.admission(store, key);
    let mut port = LostOutcomePort {
        inner: store,
        bases: Vec::new(),
    };
    let lost = err(registry.admit_scheduled_pass(&mut port, &admission));
    assert!(matches!(
        lost,
        RuntimeError::Store(CoreError::StorageOutcomeUnknown(_))
    ));
    assert_eq!(port.bases.len(), 1);
    port.bases.remove(0)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn in_doubt_pass_recovers_its_receipt_without_rerunning_drivers() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        lose_outcome_basis(&host, &mut registry, store.as_mut(), 1);
        assert!(matches!(
            registry.step_all_anchored(
                host.timeline,
                &root_ancestry(host.timeline),
                Seq::from_u64(2),
            ),
            Err(RuntimeError::PendingDriverStep)
        ));

        let recovered = receipt(registry.recover_scheduled_pass(store.as_mut()));
        let events = committed_events(store.as_ref(), host.timeline);
        assert_eq!(events.len(), 2, "{name}");
        assert_eq!(recovered.committed_events().len(), 2, "{name}");
        assert_eq!(recovered.committed_events()[0].event_id(), events[0].id);
        assert_eq!(entries(&log), ["first:step@0", "first:commit"], "{name}");
        let none = err(registry.recover_scheduled_pass(store.as_mut()));
        assert!(none.to_string().contains("no scheduled pass admission"));

        ok(registry.step_all_anchored(
            host.timeline,
            &root_ancestry(host.timeline),
            Seq::from_u64(2),
        ));
        lose_outcome_basis(&host, &mut registry, store.as_mut(), 2);
        registry.abort_step();
        ok(registry.step_all_anchored(
            host.timeline,
            &root_ancestry(host.timeline),
            Seq::from_u64(4),
        ));
        registry.abort_step();
        assert_eq!(
            entries(&log)[2..],
            ["first:step@2", "first:abort", "first:step@4", "first:abort"],
            "{name}"
        );
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn not_admitted_error_displays_only_the_outcome_discriminant() {
    let mut store = MemoryStore::new();
    let host = Host::prepare(&mut store, 10);
    let log = Log::default();
    let mut registry = host.registry();
    register(&mut registry, driver("first", vec![b"a1"], &log));
    ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
    let committed = receipt(host.admit(&mut registry, &mut store, 1));
    let event_id = committed.committed_events()[0].event_id().to_string();

    let outcomes = [
        (PipelineOutcomeV1::Rejected, "Rejected"),
        (PipelineOutcomeV1::InvalidObservation, "InvalidObservation"),
        (PipelineOutcomeV1::AuthorityRevoked, "AuthorityRevoked"),
        (PipelineOutcomeV1::AuthorityExpired, "AuthorityExpired"),
        (
            PipelineOutcomeV1::PolicyIndeterminate,
            "PolicyIndeterminate",
        ),
        (PipelineOutcomeV1::ResourceExhausted, "ResourceExhausted"),
        (
            PipelineOutcomeV1::InvalidPluginResult,
            "InvalidPluginResult",
        ),
        (
            PipelineOutcomeV1::InvalidProviderResult,
            "InvalidProviderResult",
        ),
        (PipelineOutcomeV1::DomainConflict, "DomainConflict"),
        (PipelineOutcomeV1::AdmissionConflict, "AdmissionConflict"),
        (PipelineOutcomeV1::Committed(committed.clone()), "Committed"),
        (
            PipelineOutcomeV1::RecoveredDuplicate(committed),
            "RecoveredDuplicate",
        ),
    ];
    for (outcome, discriminant) in outcomes {
        let rendered = RuntimeError::ScheduledPassNotAdmitted(Box::new(outcome)).to_string();
        assert_eq!(
            rendered,
            format!("scheduled pass was not admitted: {discriminant}")
        );
        assert!(!rendered.contains(&event_id), "{rendered}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn cadence_commits_only_after_admission_and_empty_passes_admit_no_event() {
    let mut store = MemoryStore::new();
    let host = Host::prepare(&mut store, 10);
    let log = Log::default();
    let mut registry = host.registry();
    register(&mut registry, driver("first", vec![b"a1"], &log));

    ok(registry.tick_cadenced_anchored(
        host.timeline,
        &root_ancestry(host.timeline),
        100,
        Seq::ZERO,
    ));
    publish(&mut store, host.timeline, stale_consent(host.revisions), 10);
    let stale = err(host.admit(&mut registry, &mut store, 1));
    assert!(stale.to_string().ends_with("AdmissionConflict"), "{stale}");
    publish(&mut store, host.timeline, host.revisions, 10);

    let due = ok(registry.tick_cadenced_anchored(
        host.timeline,
        &root_ancestry(host.timeline),
        100,
        Seq::ZERO,
    ));
    assert_eq!(due.len(), 1, "an aborted pass must not advance cadence");
    assert_eq!(
        receipt(host.admit(&mut registry, &mut store, 2))
            .committed_events()
            .len(),
        1
    );

    let idle = ok(registry.tick_cadenced_anchored(
        host.timeline,
        &root_ancestry(host.timeline),
        105,
        Seq::from_u64(1),
    ));
    assert!(idle.is_empty());
    assert!(ok(host.admit(&mut registry, &mut store, 3)).is_none());
    assert_eq!(committed_events(&store, host.timeline).len(), 1);
    assert_eq!(budget(&store, host.timeline), Some(9));
    assert_eq!(
        entries(&log),
        [
            "first:step@0",
            "first:abort",
            "first:step@0",
            "first:commit"
        ]
    );
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn nested_fork_pass_commits_in_stitched_timeline_order() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));
        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        assert_eq!(
            receipt(host.admit(&mut registry, store.as_mut(), 1))
                .committed_events()
                .len(),
            2,
            "{name}"
        );

        let child = ok(store.fork(host.timeline, Seq::from_u64(2), "child")).id();
        human_event(store.as_mut(), child);
        let nested = host.on(ok(store.fork(child, Seq::from_u64(3), "grandchild")).id());
        publish(store.as_mut(), nested.timeline, host.revisions, 10);
        ok(registry.step_all_anchored(
            nested.timeline,
            &root_ancestry(nested.timeline),
            Seq::from_u64(3),
        ));
        let committed = receipt(nested.admit(&mut registry, store.as_mut(), 2));

        let positions: Vec<u64> = committed
            .committed_events()
            .iter()
            .map(|event| event.seq().as_u64())
            .collect();
        assert_eq!(positions, [4, 5], "{name}");
        let order: Vec<u64> = committed_events(store.as_ref(), nested.timeline)
            .iter()
            .map(|event| event.seq.as_u64())
            .collect();
        assert_eq!(order, [1, 2, 3, 4, 5], "{name}");
        assert_eq!(
            entries(&log)[2..],
            ["first:step@3", "first:commit"],
            "{name}"
        );
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn consent_grant(subject_id: EntityId) -> ConsentGrantedV1 {
    ConsentGrantedV1 {
        subject_id,
        grantee_id: entity(77),
        purpose: "scheduled-admission".to_owned(),
        modalities: pos_core::MODALITY_LOCATION,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: 1,
    }
}

/// Commit one subject projection Event and fold it into live projections.
#[cfg_attr(coverage_nightly, coverage(off))]
fn fold_projection(
    store: &mut MemoryStore,
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    subject: EntityId,
) -> Seq {
    let events = ok(store.append(
        timeline,
        &[EventDraft::new(
            subject,
            Kind::new(PROJECTION),
            CanonicalBytes::from_static(b"projection"),
        )],
    ));
    registry.fold_events(timeline, &events);
    ok(store.logical_head(timeline))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn observer_registry(host: &Host, authority: &ConsentAuthority, log: &Log) -> PluginRegistry {
    let subject = entity(50);
    let mut registry = host.registry().with_consent_authority(authority.clone());
    ok(registry.register_generated(
        &TestPlugin {
            id: PluginId::new(),
            name: "projection",
            event_type: PROJECTION,
            reducer: true,
        },
        Some(Box::new(CountingReducer)),
        None,
    ));
    register(
        &mut registry,
        ScriptedDriver {
            entity: subject,
            subscriptions: vec![ProjectionKey::new(subject)],
            ..driver("observer", vec![b"seen"], log)
        },
    );
    registry
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn protected_pass_binds_its_authorized_snapshot_and_rechecks_consent() {
    let mut store = MemoryStore::new();
    let host = Host::prepare(&mut store, 10);
    let subject = entity(50);
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(host.timeline, &consent_grant(subject));
    let log = Log::default();
    let mut registry = observer_registry(&host, &authority, &log);
    let observed = fold_projection(&mut store, &mut registry, host.timeline, subject);
    let stage = |registry: &mut PluginRegistry| {
        ok(registry.step_all_anchored_protected(
            host.timeline,
            &root_ancestry(host.timeline),
            observed,
            token.clone(),
            1,
            &[],
        ))
    };

    assert_eq!(stage(&mut registry).len(), 1);
    let admission = host.admission(&store, 1);
    let _first = receipt(registry.admit_scheduled_pass(&mut store, &admission));

    // A pass rebuilt after the commit declares a different Tick and chain
    // edge, so under the committed key it conflicts (ADR-064 R3.8). The exact
    // retry of the retained basis is covered by the recovery fixtures.
    stage(&mut registry);
    let rebuilt = registry.admit_scheduled_pass(&mut store, &admission);
    assert_eq!(rejection(rebuilt), "AdmissionConflict");

    // The same attempt identity over a changed authorized snapshot conflicts.
    fold_projection(&mut store, &mut registry, host.timeline, subject);
    stage(&mut registry);
    let changed = registry.admit_scheduled_pass(&mut store, &admission);
    assert_eq!(rejection(changed), "AdmissionConflict");

    stage(&mut registry);
    ok(authority.record_revocation_on_timeline(
        host.timeline,
        &ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: entity(77),
            grant_seq: 1,
            fence_seq: 1,
        },
    ));
    let revoked = err(host.admit(&mut registry, &mut store, 2));
    assert!(matches!(revoked, RuntimeError::Consent(_)), "{revoked}");
    assert_eq!(committed_events(&store, host.timeline).len(), 3);
    // One commit (the first pass); the rebuilt pass, the changed snapshot and
    // the revoked consent each abort their staged Driver.
    assert_eq!(count(&log, ":commit"), 1);
    assert_eq!(count(&log, ":abort"), 3);
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_host_publishes_admits_and_refreshes_the_session_fence() {
    for (name, mut store) in stores() {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        ok(store.bind_erasure_gate(Arc::clone(&gate)));
        let timeline = ok(store.create_timeline("local-admission")).id();
        let host = ok(LocalScheduledAdmissionHostV1::shared());
        let log = Log::default();
        let mut registry = PluginRegistry::new().with_erasure_gate(gate);
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));

        let revisions = ok(host.observe(&registry, store.as_mut(), timeline));
        let fence = ok(store.pipeline_admission_fence(timeline));
        assert_eq!(
            fence.map(|fence| (fence.authority_grant(), fence.security_revisions())),
            Some((host.authority_grant(), revisions)),
            "{name}"
        );
        assert_eq!(budget(store.as_ref(), timeline), Some(u64::MAX), "{name}");
        // The delegation revision is the persisted chain's, so a revocation
        // persisted in the session store moves the fence (#483).
        let persisted = ok(store.load_authority(host.authority_grant()));
        assert_eq!(
            revisions.as_draft().delegation,
            pipeline_delegation_revision_v1(&persisted),
            "{name}"
        );
        assert_eq!(
            ok(host.observe(&registry, store.as_mut(), timeline)),
            revisions,
            "{name}"
        );

        let drafts = ok(registry.step_all_anchored(timeline, &root_ancestry(timeline), Seq::ZERO));
        assert_eq!(drafts.len(), 2, "{name}");
        let head = ok(store.logical_head(timeline));
        let committed = receipt(host.admit(&mut registry, store.as_mut(), revisions, head, 1));
        assert_eq!(committed.committed_events().len(), 2, "{name}");
        assert_eq!(
            budget(store.as_ref(), timeline),
            Some(u64::MAX - 2),
            "{name}"
        );
        assert_eq!(entries(&log), ["first:step@0", "first:commit"], "{name}");

        // A fence published under other revisions is replaced from the
        // current persisted state, keeping its remaining Event budget.
        publish(store.as_mut(), timeline, stale_consent(revisions), 5);
        assert_eq!(
            ok(host.observe(&registry, store.as_mut(), timeline)),
            revisions,
            "{name}"
        );
        let fence = ok(store.pipeline_admission_fence(timeline));
        assert_eq!(
            fence.map(|fence| (fence.authority_grant(), fence.security_revisions())),
            Some((host.authority_grant(), revisions)),
            "{name}"
        );
        assert_eq!(budget(store.as_ref(), timeline), Some(5), "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_host_fails_closed_for_a_store_bound_to_another_authority_host() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let unfenced = ok(store.create_timeline("unfenced")).id();
        let local = ok(LocalScheduledAdmissionHostV1::shared());
        let error = err(local.observe(&host.registry(), store.as_mut(), unfenced));
        assert!(
            matches!(
                error,
                RuntimeError::AuthorityPersistence(AuthorityPersistenceErrorV1::Unavailable)
            ),
            "{name}: {error}"
        );
        assert_eq!(
            error.to_string(),
            "scheduled admission authority persistence failed closed: \
             authority persistence is unavailable",
            "{name}"
        );
        assert_eq!(budget(store.as_ref(), unfenced), None, "{name}");
    }
}

/// Admission ports whose fence publication fails after authority binds.
struct FenceRejectingPorts<'a> {
    inner: &'a mut MemoryStore,
}

impl PipelineAdmissionPortV1 for FenceRejectingPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.inner.admit_pipeline_batch(basis)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: pos_core::TimelineId,
        key: pos_core::AppendDedupKey,
        attempt_id: pos_core::PipelineAttemptIdV1,
    ) -> Result<pos_core::PipelineReceiptLookupV1, pos_core::CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl FactualPrefixReadPortV1 for FenceRejectingPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        FactualPrefixReadPortV1::last_committed_factual_tick(&*self.inner, timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        FactualPrefixReadPortV1::cut_tick_at(&*self.inner, timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        FactualPrefixReadPortV1::nodes_for_committed_events(&*self.inner, timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        FactualPrefixReadPortV1::nodes_by_digest(&*self.inner, timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        FactualPrefixReadPortV1::last_step_node(&*self.inner, timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        FactualPrefixReadPortV1::factual_set_counts(&*self.inner, timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        FactualPrefixReadPortV1::fold_cursor(&*self.inner, timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        FactualPrefixReadPortV1::fold_window(&*self.inner, timeline, after, through)
    }
}

impl PipelineAdmissionFencePublisherV1 for FenceRejectingPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn set_pipeline_admission_fence(
        &mut self,
        _: TimelineId,
        _: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        Err(CoreError::Storage(
            "injected fence publication failure".to_owned(),
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        self.inner.pipeline_admission_fence(timeline)
    }
}

impl AuthorityPersistencePortV1 for FenceRejectingPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bind_authority_persistence(
        &mut self,
        binding: pos_core::AuthorityPersistenceBindingV1,
    ) -> Result<(), AuthorityPersistenceErrorV1> {
        self.inner.bind_authority_persistence(binding)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn issue_capability_grant(
        &mut self,
        permit: pos_core::AuthorityMutationPermitV1,
        grant: &CapabilityGrantV1,
    ) -> Result<pos_core::AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        self.inner.issue_capability_grant(permit, grant)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revoke_capability_grant(
        &mut self,
        permit: pos_core::AuthorityMutationPermitV1,
        revocation: &CapabilityRevocationV1,
    ) -> Result<pos_core::AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        self.inner.revoke_capability_grant(permit, revocation)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn load_authority(
        &self,
        leaf_grant_id: Hash,
    ) -> Result<pos_core::PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
        self.inner.load_authority(leaf_grant_id)
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_host_reports_a_fence_publication_failure_as_a_store_error() {
    let mut store = MemoryStore::new();
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    ok(store.bind_erasure_gate(Arc::clone(&gate)));
    let timeline = ok(store.create_timeline("fence-publication-failure")).id();
    let host = ok(LocalScheduledAdmissionHostV1::shared());
    let registry = PluginRegistry::new().with_erasure_gate(gate);

    let error = err(host.observe(
        &registry,
        &mut FenceRejectingPorts { inner: &mut store },
        timeline,
    ));
    assert!(
        matches!(&error, RuntimeError::Store(CoreError::Storage(message))
            if message == "injected fence publication failure"),
        "{error}"
    );
    assert!(ok(store.pipeline_admission_fence(timeline)).is_none());
    assert!(store.load_authority(host.authority_grant()).is_ok());
}

// ── Plugin draft ownership on the non-participant path (#484) ──────────────

/// The Event type the "first" Driver's Plugin owns.
const FIRST_OWNED: &str = "agent.scheduled.first";

/// A Driver whose Plugin owns only `agent.scheduled.intruder` but which
/// emits the Event type that the "first" Driver's Plugin owns.
#[cfg_attr(coverage_nightly, coverage(off))]
fn register_intruder(registry: &mut PluginRegistry, log: &Log) {
    let plugin = TestPlugin {
        id: PluginId::new(),
        name: "intruder",
        event_type: "agent.scheduled.intruder",
        reducer: false,
    };
    let intruder = ScriptedDriver {
        event_type: FIRST_OWNED,
        ..driver("intruder", vec![b"forged"], log)
    };
    ok(registry.register_generated(&plugin, None, Some(Box::new(intruder))));
    ok(registry.compose_non_participant_drivers());
}

/// Assert the pass was rejected as an unauthorized source and that every
/// Driver it staged was aborted without a commit.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_ownership_rejected(error: &RuntimeError, log: &Log, name: &str) {
    assert!(
        matches!(
            error,
            RuntimeError::Authority(AuthorityErrorV1::UnauthorizedSource)
        ),
        "{name}: {error}"
    );
    assert_eq!(
        entries(log),
        [
            "first:step@0",
            "intruder:step@0",
            "first:abort",
            "intruder:abort"
        ],
        "{name}"
    );
}

/// ADR-021 Revision 3 Decision 4: a scheduled Driver that emits another
/// Plugin's Event type is rejected on the anchored non-participant path with
/// the same error as on the participant-authorized path, and nothing commits.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn anchored_pass_rejects_another_plugins_event_type_and_commits_nothing() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        register_intruder(&mut registry, &log);

        let error = err(registry.step_all_anchored(
            host.timeline,
            &root_ancestry(host.timeline),
            Seq::ZERO,
        ));
        assert_ownership_rejected(&error, &log, name);
        assert!(
            matches!(
                err(host.admit(&mut registry, store.as_mut(), 1)),
                RuntimeError::PendingDriverStep
            ),
            "{name}"
        );
        assert!(
            committed_events(store.as_ref(), host.timeline).is_empty(),
            "{name}"
        );
        assert_eq!(budget(store.as_ref(), host.timeline), Some(10), "{name}");
    }
}

/// The local scheduled admission host (`ExperimentSession`'s host) applies
/// the same ownership rule before it publishes or admits anything.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_host_rejects_another_plugins_event_type_and_commits_nothing() {
    for (name, mut store) in stores() {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        ok(store.bind_erasure_gate(Arc::clone(&gate)));
        let timeline = ok(store.create_timeline("local-foreign-draft")).id();
        let host = ok(LocalScheduledAdmissionHostV1::shared());
        let log = Log::default();
        let mut registry = PluginRegistry::new().with_erasure_gate(gate);
        register(&mut registry, driver("first", vec![b"a1"], &log));
        register_intruder(&mut registry, &log);
        let revisions = ok(host.observe(&registry, store.as_mut(), timeline));

        let error = err(registry.step_all_anchored(timeline, &root_ancestry(timeline), Seq::ZERO));
        assert_ownership_rejected(&error, &log, name);
        let head = ok(store.logical_head(timeline));
        assert!(
            matches!(
                err(host.admit(&mut registry, store.as_mut(), revisions, head, 1)),
                RuntimeError::PendingDriverStep
            ),
            "{name}"
        );
        assert!(
            committed_events(store.as_ref(), timeline).is_empty(),
            "{name}"
        );
        assert_eq!(budget(store.as_ref(), timeline), Some(u64::MAX), "{name}");
    }
}

/// Driver that records which probed Projections its view exposes (#513).
struct ProbingDriver {
    name: &'static str,
    event_type: &'static str,
    entity: EntityId,
    subscriptions: Vec<ProjectionKey>,
    verified_prefix: bool,
    log: Log,
}

impl Driver for ProbingDriver {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        self.name
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn requires_verified_event_prefix(&self) -> bool {
        self.verified_prefix
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step(
        &mut self,
        _: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let seen: Vec<String> = PROBED
            .iter()
            .map(|subject| {
                observations
                    .state_for(&ProjectionKey::new(entity(*subject)))
                    .and_then(|state| state.get("count"))
                    .map_or_else(|| "none".to_owned(), ToString::to_string)
            })
            .collect();
        record(&self.log, format!("{}:{}", self.name, seen.join(",")));
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new(self.event_type),
            CanonicalBytes::from_static(b"probed"),
        )]))
    }
}

/// The subjects every probing Driver reads, subscribed or not: A, then B.
const PROBED: [u128; 2] = [50, 51];

/// A probing Driver named `name` that owns `event_type`, subscribes to
/// `subscriptions`, and emits one draft on `draft_entity`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe(
    name: &'static str,
    event_type: &'static str,
    subscriptions: &[EntityId],
    draft_entity: EntityId,
    log: &Log,
) -> ProbingDriver {
    ProbingDriver {
        name,
        event_type,
        entity: draft_entity,
        subscriptions: subscriptions
            .iter()
            .copied()
            .map(ProjectionKey::new)
            .collect(),
        verified_prefix: false,
        log: Arc::clone(log),
    }
}

/// Register a probing Driver under a Plugin that owns its Event type.
#[cfg_attr(coverage_nightly, coverage(off))]
fn register_probe(registry: &mut PluginRegistry, driver: ProbingDriver) {
    let plugin = TestPlugin {
        id: PluginId::new(),
        name: driver.name,
        event_type: driver.event_type,
        reducer: false,
    };
    ok(registry.register_generated(&plugin, None, Some(Box::new(driver))));
    ok(registry.compose_non_participant_drivers());
}

/// Register the counting Projection reducer every probe reads from.
#[cfg_attr(coverage_nightly, coverage(off))]
fn register_projection(registry: &mut PluginRegistry) {
    ok(registry.register_generated(
        &TestPlugin {
            id: PluginId::new(),
            name: "projection",
            event_type: PROJECTION,
            reducer: true,
        },
        Some(Box::new(CountingReducer)),
        None,
    ));
}

/// Commit one Projection Event per subject in any store and fold them.
#[cfg_attr(coverage_nightly, coverage(off))]
fn fold_subjects(
    store: &mut dyn Harness,
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    subjects: &[EntityId],
) -> Seq {
    let drafts: Vec<EventDraft> = subjects
        .iter()
        .map(|subject| {
            EventDraft::new(
                *subject,
                Kind::new(PROJECTION),
                CanonicalBytes::from_static(b"projection"),
            )
        })
        .collect();
    let events = ok(store.append(timeline, &drafts));
    registry.fold_events(timeline, &events);
    ok(store.logical_head(timeline))
}

/// What a [`DigestRecordingPort`] answers to each basis it is offered.
enum Reply {
    /// Commit through the real store.
    Commit,
    /// Answer this outcome without committing anything.
    Refuse(PipelineOutcomeV1),
    /// Commit through the real store a basis whose asserted Tick is this many
    /// Ticks later than the registry declared.
    Skew(u64),
}

/// Port that records each offered basis and either commits through the real
/// store, with its Tick moved or not, or answers a fixed refusal.
struct DigestRecordingPort<'a> {
    inner: &'a mut dyn Harness,
    bases: Vec<PipelineAdmissionBasisV1>,
    reply: Reply,
}

impl<'a> DigestRecordingPort<'a> {
    /// A port that commits through `inner`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn over(inner: &'a mut dyn Harness) -> Self {
        Self {
            inner,
            bases: Vec::new(),
            reply: Reply::Commit,
        }
    }

    /// A port that commits through `inner` a basis whose asserted Tick is
    /// `skew` Ticks later than the registry declared, as a host that lost a
    /// race with another commit would offer it.
    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn skewing(inner: &'a mut dyn Harness, skew: u64) -> Self {
        Self {
            inner,
            bases: Vec::new(),
            reply: Reply::Skew(skew),
        }
    }

    /// A port that reads through `inner` and answers `outcome` to every basis.
    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn refusing(inner: &'a mut dyn Harness, outcome: PipelineOutcomeV1) -> Self {
        Self {
            inner,
            bases: Vec::new(),
            reply: Reply::Refuse(outcome),
        }
    }
}

/// The basis with its asserted Tick `skew` Ticks later, every other field
/// unchanged.
#[cfg_attr(coverage_nightly, coverage(off))]
fn skewed(basis: &PipelineAdmissionBasisV1, skew: u64) -> PipelineAdmissionBasisV1 {
    let declared = basis.dependencies();
    let moved = FactualTickDependenciesV1::new(
        declared.tick().saturating_add(skew),
        declared.record().clone(),
        declared.output_bindings().to_vec(),
        declared.event_nodes().to_vec(),
        declared.fold().clone(),
    );
    ok(PipelineAdmissionBasisV1::try_from_draft(
        PipelineAdmissionBasisDraftV1 {
            contract_version: PIPELINE_CONTRACT_VERSION_V1,
            attempt: Some(*basis.attempt()),
            tentative_result: Some(basis.tentative_result()),
            precondition: Some(basis.precondition()),
            security_revisions: Some(basis.security_revisions()),
            batch: Some(basis.batch().clone()),
            dependencies: moved,
        },
    ))
}

impl PipelineAdmissionPortV1 for DigestRecordingPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.bases.push(basis.clone());
        match &self.reply {
            Reply::Commit => self.inner.admit_pipeline_batch(basis),
            Reply::Refuse(outcome) => Ok(outcome.clone()),
            Reply::Skew(skew) => self.inner.admit_pipeline_batch(&skewed(basis, *skew)),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<pos_core::PipelineReceiptLookupV1, CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl FactualPrefixReadPortV1 for DigestRecordingPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.inner.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.inner.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.inner.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.inner.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.inner.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.inner.factual_set_counts(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        self.inner.fold_cursor(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        self.inner.fold_window(timeline, after, through)
    }
}

/// The ADR-021 scheduled snapshot digest recomputed independently of the
/// runtime from its documented layout. `states` holds each captured entity
/// with its canonical State JSON, in ascending entity byte order.
#[cfg_attr(coverage_nightly, coverage(off))]
fn expected_digest(
    timeline: TimelineId,
    observed_through: Seq,
    states: &[(EntityId, &str)],
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ScheduledObservationSnapshot.v1\0");
    hasher.update(&timeline.inner().to_bytes());
    hasher.update(&observed_through.as_u64().to_be_bytes());
    hasher.update(&(states.len() as u64).to_be_bytes());
    for (entity, state) in states {
        hasher.update(&entity.inner().to_bytes());
        hasher.update(&(state.len() as u64).to_be_bytes());
        hasher.update(state.as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// The canonical State JSON of a subject folded from exactly one Projection
/// Event: `CountingReducer` starts from an empty State and sets `count` to 1.
const ONE_FOLDED_EVENT: &str = r#"{"count":1}"#;

/// #513, ADR-021 Revision 3 Decision 1: in a protected multi-Driver pass the
/// shared snapshot holds the union of every due Driver's subscriptions, but
/// each Driver reads only its own. The Drivers with no subscription, on
/// either the plain or the verified-prefix path, read nothing; the subscriber
/// reads only subject A; and the bound digest still covers the whole union.
///
/// A protected pass authorizes exactly one consent subject, so a second
/// subscriber on a disjoint subject B cannot share the pass: the pass fails
/// closed before any Driver steps.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn protected_pass_scopes_each_drivers_view_to_its_own_subscriptions() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let (subject, other) = (entity(PROBED[0]), entity(PROBED[1]));
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(host.timeline, &consent_grant(subject));
        let log = Log::default();
        let mut registry = host.registry().with_consent_authority(authority);
        register_projection(&mut registry);
        register_probe(
            &mut registry,
            probe("blind", "agent.scheduled.blind", &[], subject, &log),
        );
        register_probe(
            &mut registry,
            ProbingDriver {
                verified_prefix: true,
                ..probe("prefix", "agent.scheduled.prefix", &[], subject, &log)
            },
        );
        register_probe(
            &mut registry,
            probe(
                "subscriber",
                "agent.scheduled.subscriber",
                &[subject],
                subject,
                &log,
            ),
        );
        let observed = fold_subjects(
            store.as_mut(),
            &mut registry,
            host.timeline,
            &[subject, other],
        );
        let prefix = committed_events(store.as_ref(), host.timeline);

        let staged = ok(registry.step_all_anchored_protected(
            host.timeline,
            &root_ancestry(host.timeline),
            observed,
            token.clone(),
            1,
            &prefix,
        ));
        assert_eq!(staged.len(), 3, "{name}");
        assert_eq!(
            entries(&log),
            ["blind:none,none", "prefix:none,none", "subscriber:1,none"],
            "{name}"
        );
        let basis = admit_basis(&host, &mut registry, store.as_mut(), 1);
        let digest = basis.attempt().observation().snapshot_digest();
        assert_eq!(
            digest,
            expected_digest(host.timeline, observed, &[(subject, ONE_FOLDED_EVENT)]),
            "{name}"
        );
        assert_eq!(
            committed_events(store.as_ref(), host.timeline).len(),
            5,
            "{name}"
        );

        register_probe(
            &mut registry,
            probe("other", "agent.scheduled.other", &[other], subject, &log),
        );
        let head = ok(store.logical_head(host.timeline));
        let refused = err(registry.step_all_anchored_protected(
            host.timeline,
            &root_ancestry(host.timeline),
            head,
            token,
            1,
            &[],
        ));
        assert!(
            matches!(
                refused,
                RuntimeError::Consent(pos_core::ConsentError::NoConsent)
            ),
            "{name}: {refused}"
        );
        assert_eq!(entries(&log).len(), 3, "{name}");
    }
}

/// #513: a public pass refuses any Projection subscriber before a Driver
/// steps, and a Driver with no subscription reads nothing even though
/// Projection state exists.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn public_pass_refuses_subscribers_and_hides_projections_from_the_rest() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let (subject, other) = (entity(PROBED[0]), entity(PROBED[1]));
        let log = Log::default();
        let mut registry = host.registry();
        register_projection(&mut registry);
        register_probe(
            &mut registry,
            probe("blind", "agent.scheduled.blind", &[], entity(10), &log),
        );
        let observed = fold_subjects(
            store.as_mut(),
            &mut registry,
            host.timeline,
            &[subject, other],
        );

        assert_eq!(
            ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), observed,))
                .len(),
            1,
            "{name}"
        );
        assert_eq!(entries(&log), ["blind:none,none"], "{name}");
        let basis = admit_basis(&host, &mut registry, store.as_mut(), 1);
        let digest = basis.attempt().observation().snapshot_digest();
        assert_eq!(
            digest,
            expected_digest(host.timeline, observed, &[]),
            "{name}"
        );

        register_probe(
            &mut registry,
            probe(
                "subscriber",
                "agent.scheduled.subscriber",
                &[subject],
                entity(10),
                &log,
            ),
        );
        let head = ok(store.logical_head(host.timeline));
        let refused =
            err(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), head));
        assert!(
            matches!(
                refused,
                RuntimeError::Consent(pos_core::ConsentError::NoConsent)
            ),
            "{name}: {refused}"
        );
        assert_eq!(entries(&log), ["blind:none,none"], "{name}");
    }
}

// ── ADR-021 Revision 3 composition-time profiles (#504) ─────────────────────

/// Register `driver` without composing its scheduled observation profile.
#[cfg_attr(coverage_nightly, coverage(off))]
fn register_unbound(registry: &mut PluginRegistry, driver: ScriptedDriver) -> PluginId {
    let plugin = TestPlugin {
        id: PluginId::new(),
        name: driver.name,
        event_type: driver.event_type,
        reducer: false,
    };
    ok(registry.register_generated(&plugin, None, Some(Box::new(driver))));
    plugin.id
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn composition_error(
    registry: &mut PluginRegistry,
    bindings: &[(PluginId, ScheduledDriverBindingV1)],
) -> String {
    err(registry.compose_scheduled_profiles(bindings)).to_string()
}

/// The host fixes exactly one profile per registered Driver, only from its
/// binding: a binding of anything but a registered Driver, a second binding,
/// an incomplete composition and a mixed one all assign nothing. A complete
/// non-participant composition then commits its pass on both stores.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn composition_fixes_one_profile_per_driver_before_any_pass() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        let first = register_unbound(&mut registry, driver("first", vec![b"a1"], &log));
        let second = register_unbound(&mut registry, driver("second", vec![b"b1"], &log));
        let projection = PluginId::new();
        ok(registry.register_generated(
            &TestPlugin {
                id: projection,
                name: "projection",
                event_type: PROJECTION,
                reducer: true,
            },
            Some(Box::new(CountingReducer)),
            None,
        ));
        let non_participant = ScheduledDriverBindingV1::NonParticipant;
        let participant = ScheduledDriverBindingV1::Participant(entity(30));
        let unknown = PluginId::new();
        let duplicate = [(first, non_participant), (first, participant)];
        let mixed = [(first, participant), (second, non_participant)];
        let complete = [(first, non_participant), (second, non_participant)];

        assert_eq!(
            composition_error(&mut registry, &[(unknown, non_participant)]),
            format!("plugin {unknown} is not a registered scheduled Driver"),
            "{name}"
        );
        assert_eq!(
            composition_error(&mut registry, &[(projection, non_participant)]),
            format!("plugin {projection} is not a registered scheduled Driver"),
            "{name}"
        );
        assert_eq!(
            composition_error(&mut registry, &duplicate),
            "scheduled Driver 'first' already has an observation profile",
            "{name}"
        );
        assert_eq!(
            composition_error(&mut registry, &[(first, non_participant)]),
            "scheduled Driver 'second' has no observation profile assignment",
            "{name}"
        );
        assert_eq!(
            composition_error(&mut registry, &mixed),
            "one composition cannot mix participant-bound and non-participant Drivers",
            "{name}"
        );
        assert_eq!(registry.scheduled_binding(first), None, "{name}");
        assert_eq!(
            err(registry.step_all_anchored(
                host.timeline,
                &root_ancestry(host.timeline),
                Seq::ZERO,
            ))
            .to_string(),
            "scheduled Driver 'first' has no observation profile assignment",
            "{name}"
        );
        assert!(entries(&log).is_empty(), "{name}");

        ok(registry.compose_scheduled_profiles(&complete));
        assert_eq!(
            registry.scheduled_binding(second),
            Some(non_participant),
            "{name}"
        );
        assert_eq!(
            composition_error(&mut registry, &[(second, non_participant)]),
            "scheduled Driver 'second' already has an observation profile",
            "{name}"
        );
        ok(registry.compose_non_participant_drivers());
        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
        receipt(host.admit(&mut registry, store.as_mut(), 1));
        assert_eq!(
            committed_events(store.as_ref(), host.timeline).len(),
            2,
            "{name}"
        );
    }
}

/// A participant-bound Driver is refused before it runs on every anchored and
/// unanchored path, a host without Participants cannot compose it, and a
/// Driver registered beside it cannot be composed non-participant. Nothing
/// is staged or committed on either store.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn participant_bound_drivers_never_stage_outside_their_authorized_views() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        let first = register_unbound(&mut registry, driver("first", vec![b"a1"], &log));
        let bound = ScheduledDriverBindingV1::Participant(entity(30));
        ok(registry.compose_scheduled_profiles(&[(first, bound)]));
        assert_eq!(registry.scheduled_binding(first), Some(bound), "{name}");
        assert_eq!(
            bound.profile(),
            pos_core::ScheduledObservationProfileV1::ParticipantBound
        );
        let refusal = "scheduled Driver 'first' is not composed for the NonParticipant profile";
        let head = ok(store.logical_head(host.timeline));
        let refusals = [
            err(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), head)),
            err(registry.tick_cadenced_anchored(
                host.timeline,
                &root_ancestry(host.timeline),
                0,
                head,
            )),
            err(registry.step_all(host.timeline, &root_ancestry(host.timeline))),
            err(registry.tick_cadenced(host.timeline, &root_ancestry(host.timeline), 0)),
            err(registry.compose_non_participant_drivers()),
        ];
        for refused in refusals {
            assert_eq!(refused.to_string(), refusal, "{name}");
        }

        let second = register_unbound(&mut registry, driver("second", vec![b"b1"], &log));
        assert_eq!(
            err(registry.compose_non_participant_drivers()).to_string(),
            "one composition cannot mix participant-bound and non-participant Drivers",
            "{name}"
        );
        assert_eq!(registry.scheduled_binding(second), None, "{name}");
        assert!(entries(&log).is_empty(), "{name}");
        assert!(
            committed_events(store.as_ref(), host.timeline).is_empty(),
            "{name}"
        );
    }
}

// ── Set-capacity preflight (ADR-064 Revision 3, R3.10) ─────────────────────

/// The recorded-set counts one node, edge or declared input past the preflight
/// threshold: one worst-case Tick no longer fits.
///
/// The thresholds are the caps less one worst-case Tick: 934,464 nodes is
/// 1,000,000 - 65,536, and 3,737,856 edges or inputs is 4,000,000 - 262,144.
const fn exhausted_counts() -> [RecordedSetCountsV1; 3] {
    [
        RecordedSetCountsV1 {
            nodes: 934_465,
            edges: 0,
            inputs: 0,
        },
        RecordedSetCountsV1 {
            nodes: 0,
            edges: 3_737_857,
            inputs: 0,
        },
        RecordedSetCountsV1 {
            nodes: 0,
            edges: 0,
            inputs: 3_737_857,
        },
    ]
}

/// The counts exactly at the threshold: one worst-case Tick still fits.
///
/// 934,464 is 1,000,000 - 65,536 and 3,737,856 is 4,000,000 - 262,144.
const AT_THRESHOLD: RecordedSetCountsV1 = RecordedSetCountsV1 {
    nodes: 934_464,
    edges: 3_737_856,
    inputs: 3_737_856,
};

/// Ports over a real store that report fixed recorded-set counts and count the
/// batches offered to the store.
struct CountsPorts<'a> {
    inner: &'a mut dyn Harness,
    counts: RecordedSetCountsV1,
    offered: usize,
    reads: Cell<usize>,
}

impl<'a> CountsPorts<'a> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn new(inner: &'a mut dyn Harness, counts: RecordedSetCountsV1) -> Self {
        Self {
            inner,
            counts,
            offered: 0,
            reads: Cell::new(0),
        }
    }
}

impl PipelineAdmissionPortV1 for CountsPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.offered += 1;
        self.inner.admit_pipeline_batch(basis)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<pos_core::PipelineReceiptLookupV1, CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl FactualPrefixReadPortV1 for CountsPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<pos_core::FactualHeadV1, CoreError> {
        self.inner.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: TimelineId,
        seq: Seq,
    ) -> Result<pos_core::FactualCutV1, CoreError> {
        self.inner.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, CoreError> {
        self.inner.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        self.inner.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, CoreError> {
        self.inner.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(&self, _: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.counts)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_cursor(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, CoreError> {
        self.inner.fold_cursor(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_window(
        &self,
        timeline: TimelineId,
        after: Seq,
        through: Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, CoreError> {
        self.inner.fold_window(timeline, after, through)
    }
}

impl PipelineAdmissionFencePublisherV1 for CountsPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.inner.set_pipeline_admission_fence(timeline, fence)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        self.inner.pipeline_admission_fence(timeline)
    }
}

impl AuthorityPersistencePortV1 for CountsPorts<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bind_authority_persistence(
        &mut self,
        binding: pos_core::AuthorityPersistenceBindingV1,
    ) -> Result<(), AuthorityPersistenceErrorV1> {
        self.inner.bind_authority_persistence(binding)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn issue_capability_grant(
        &mut self,
        permit: pos_core::AuthorityMutationPermitV1,
        grant: &CapabilityGrantV1,
    ) -> Result<pos_core::AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        self.inner.issue_capability_grant(permit, grant)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revoke_capability_grant(
        &mut self,
        permit: pos_core::AuthorityMutationPermitV1,
        revocation: &CapabilityRevocationV1,
    ) -> Result<pos_core::AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        self.inner.revoke_capability_grant(permit, revocation)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn load_authority(
        &self,
        leaf_grant_id: Hash,
    ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
        self.inner.load_authority(leaf_grant_id)
    }
}

/// Whether `error` is the set-exhaustion refusal of the preflight.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn is_set_exhausted(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::DependencyDeclaration(FactualDependencyErrorV1::SetExhausted)
    )
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_preflight_aborts_the_staged_drivers_before_any_store_call() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        let ancestry = root_ancestry(host.timeline);

        for counts in exhausted_counts() {
            ok(registry.step_all_anchored(host.timeline, &ancestry, Seq::ZERO));
            let admission = host.admission(store.as_ref(), 1);
            let mut port = CountsPorts::new(store.as_mut(), counts);
            let error = err(registry.admit_scheduled_pass(&mut port, &admission));
            assert!(is_set_exhausted(&error), "{name}: {error}");
            assert_eq!((port.offered, port.reads.get()), (0, 1), "{name}");
        }
        assert_eq!(count(&log, ":abort"), 3, "{name}");
        assert_eq!(count(&log, ":commit"), 0, "{name}");
        assert!(committed_events(store.as_ref(), host.timeline).is_empty());

        // Exactly at the threshold one more worst-case Tick fits.
        ok(registry.step_all_anchored(host.timeline, &ancestry, Seq::ZERO));
        let admission = host.admission(store.as_ref(), 2);
        let mut port = CountsPorts::new(store.as_mut(), AT_THRESHOLD);
        receipt(registry.admit_scheduled_pass(&mut port, &admission));
        assert_eq!((port.offered, port.reads.get()), (1, 1), "{name}");
        assert_eq!(count(&log, ":commit"), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_empty_pass_at_the_threshold_commits_its_cursor_advance_without_a_preflight() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", Vec::new(), &log));

        let ancestry = root_ancestry(host.timeline);
        ok(registry.step_all_anchored(host.timeline, &ancestry, Seq::ZERO));
        let admission = host.admission(store.as_ref(), 1);
        let mut port = CountsPorts::new(store.as_mut(), exhausted_counts()[0]);
        assert!(ok(registry.admit_scheduled_pass(&mut port, &admission)).is_none());
        assert_eq!((port.offered, port.reads.get()), (0, 0), "{name}");
        assert_eq!(entries(&log), ["first:step@0", "first:commit"], "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn observe_refuses_an_exhausted_timeline_before_any_driver_steps() {
    let payload_sets: [Vec<&'static [u8]>; 2] = [Vec::new(), vec![b"a1"]];
    for (name, mut store) in stores() {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        ok(store.bind_erasure_gate(Arc::clone(&gate)));
        let timeline = ok(store.create_timeline("observe-exhausted")).id();
        let host = ok(LocalScheduledAdmissionHostV1::shared());
        for payloads in &payload_sets {
            let log = Log::default();
            let mut registry = PluginRegistry::new().with_erasure_gate(gate.clone());
            register(&mut registry, driver("first", payloads.clone(), &log));

            // A pass that stages nothing is refused as well: `observe` cannot
            // know that before the Drivers step.
            for counts in exhausted_counts() {
                let mut port = CountsPorts::new(store.as_mut(), counts);
                let error = err(host.observe(&registry, &mut port, timeline));
                assert!(is_set_exhausted(&error), "{name}: {error}");
            }
            assert!(ok(store.pipeline_admission_fence(timeline)).is_none());
            assert!(entries(&log).is_empty(), "{name}");

            // Nothing was staged: the registry has no pending step.
            let ancestry = root_ancestry(timeline);
            ok(registry.step_all_anchored(timeline, &ancestry, Seq::ZERO));
            registry.abort_step();
        }

        let log = Log::default();
        let mut registry = PluginRegistry::new().with_erasure_gate(gate);
        register(&mut registry, driver("first", vec![b"a1"], &log));
        let mut port = CountsPorts::new(store.as_mut(), AT_THRESHOLD);
        ok(host.observe(&registry, &mut port, timeline));
        assert!(ok(store.pipeline_admission_fence(timeline)).is_some());
    }
}

/// ADR-064 R3.4: the basis a scheduled pass submits declares its factual
/// Tick: the snapshot node, a step node per Driver and an output node per
/// draft, bound to the drafts in vector order.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_submitted_basis_declares_the_factual_tick_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));
        register(&mut registry, driver("second", Vec::new(), &log));
        let ancestry = root_ancestry(host.timeline);
        ok(registry.step_all_anchored(host.timeline, &ancestry, Seq::ZERO));
        let admission = host.admission(store.as_ref(), 1);
        let mut port = DigestRecordingPort::over(store.as_mut());
        receipt(registry.admit_scheduled_pass(&mut port, &admission));
        let basis = &port.bases[0];
        let dependencies = basis.dependencies();

        assert_eq!(dependencies.tick(), 1, "{name}");
        let nodes = dependencies.record().nodes();
        let positions: Vec<(u32, u32)> = nodes
            .iter()
            .map(|node| {
                let coordinate = node.coordinate();
                (coordinate.scheduler_position(), coordinate.output_ordinal())
            })
            .collect();
        assert_eq!(
            positions,
            [(0, 0), (1, 0), (1, 1), (1, 2), (2, 0)],
            "{name}"
        );
        let bound: Vec<(u32, u32)> = dependencies
            .output_bindings()
            .iter()
            .map(|binding| (binding.draft_index, binding.node_index))
            .collect();
        assert_eq!(bound, [(0, 2), (1, 3)], "{name}");
        assert!(dependencies.event_nodes().is_empty(), "{name}");

        // The snapshot node binds the digest the basis anchor carries.
        let key = FactualNodeKeyV1 {
            tick: 1,
            scheduler_position: 0,
            owner: OBSERVATION,
            output_ordinal: 0,
            schema_id: FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
        };
        let anchored = basis.attempt().observation().snapshot_digest();
        let snapshot = factual_artifact_digest(host.timeline, key, anchored);
        assert_eq!(nodes[0].coordinate().artifact_digest(), snapshot, "{name}");
    }
}

/// Step and admit one pass over the Timeline through `cut.0` under the
/// idempotency key `cut.1`, and return the basis it submitted.
///
/// This and `first_step_node` are the slice 7b helpers: they step every Driver
/// and know no Event slice. The `stage` and `pass_basis` helpers of the #628
/// section below add cadence and a committed prefix.
#[cfg_attr(coverage_nightly, coverage(off))]
fn admit_pass_basis(
    host: &Host,
    registry: &mut PluginRegistry,
    store: &mut dyn Harness,
    cut: (u64, u8),
) -> PipelineAdmissionBasisV1 {
    let (observed, key) = cut;
    let ancestry = root_ancestry(host.timeline);
    ok(registry.step_all_anchored(host.timeline, &ancestry, Seq::from_u64(observed)));
    admit_basis(host, registry, store, key)
}

/// The step node of the first Driver in a submitted basis.
#[cfg_attr(coverage_nightly, coverage(off))]
fn first_step_node(basis: &PipelineAdmissionBasisV1) -> DependencyNodeRecordV1 {
    let nodes = basis.dependencies().record().nodes();
    let found = nodes.iter().find(|node| {
        node.coordinate().scheduler_position() == 1 && node.coordinate().output_ordinal() == 0
    });
    found
        .cloned()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("no first step node")))
}

/// ADR-064 R3.4.1: until the stores hold factual rows the head stays zero, yet
/// a second pass declares a Tick later than the first and chains to the first
/// pass's step node.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_second_pass_declares_a_later_tick_chained_to_the_first_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));

        let first = admit_pass_basis(&host, &mut registry, store.as_mut(), (0, 1));
        let second = admit_pass_basis(&host, &mut registry, store.as_mut(), (2, 2));

        assert_eq!(first.dependencies().tick(), 1, "{name}");
        assert_eq!(second.dependencies().tick(), 2, "{name}");
        let recorded = first_step_node(&first).coordinate().artifact_digest();
        let step = first_step_node(&second);
        assert!(step.input_digests().contains(&recorded), "{name}");
    }
}

/// A restore resets the chain to a lookup against the store, which holds no
/// row yet, and the Tick after the restored pass still follows it with a chain
/// edge. The Tick the restored registry itself declares is deliberately not
/// pinned: it is transitional until slices 8-9 write rows, after which a
/// restarted registry declares the head plus one.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_restored_registry_keeps_declaring_later_ticks_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 10);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1", b"a2"], &log));

        let first = admit_pass_basis(&host, &mut registry, store.as_mut(), (0, 1));
        assert_eq!(first.dependencies().tick(), 1, "{name}");
        let events = committed_events(store.as_ref(), host.timeline);
        let segment = TimelineHistorySegment::new(host.timeline, Seq::from_u64(2));
        ok(registry.restore_driver_state(&[segment], &events));

        let restored = admit_pass_basis(&host, &mut registry, store.as_mut(), (2, 2));
        let later = admit_pass_basis(&host, &mut registry, store.as_mut(), (4, 3));
        let restored_tick = restored.dependencies().tick();
        assert!(later.dependencies().tick() > restored_tick, "{name}");
        let recorded = first_step_node(&restored).coordinate().artifact_digest();
        let step = first_step_node(&later);
        assert!(step.input_digests().contains(&recorded), "{name}");
    }
}

// ── Registry-driven basis content (ADR-064 Revision 3, Redmine #628) ───────
//
// These tests drive the registry over both real adapters and assert the
// factual Tick declaration each submitted basis carries. The expected digests
// come from the pos-core helper functions that the pos-core vectors pin, so
// they are independent of the registry but not of pos-core.
//
// The adapters write no factual rows until slices 8 and 9, so a Tick the
// registry declares never reaches the prefix a later pass reads, and a real
// adapter's head stays at the last seeded Tick. Two things follow:
//
// - A scenario that needs the store to answer from an earlier Tick seeds the
//   prefix with `seed_factual_prefix` (D16) instead.
// - A scenario that spans several Ticks of one registry asserts the retained
//   state (the `Recorded` chain and history nodes) and the declared digests,
//   which is what the registry knows before slice 8. Slice 8 changes no
//   assertion of this section: the head then follows the rows, and every
//   later Tick is still the head plus one, as the retained nodes give it.

type Staged = Result<Vec<EventDraft>, RuntimeError>;

/// The Event type the basis Drivers subscribe to.
const INPUT: &str = "agent.basis.input";
/// An Event type none of them subscribes to.
const OTHER_INPUT: &str = "agent.basis.other_input";
const ENDOGENOUS: RecordedDependencyClassV1 = RecordedDependencyClassV1::EndogenousRecomputed;
const PRESENTATION: RecordedDependencyClassV1 = RecordedDependencyClassV1::PresentationOnly;
const OBSERVATION: &str = FactualHostOwnerV1::Observation.as_str();
const HISTORY: &str = FactualHostOwnerV1::History.as_str();
const INGRESS: &str = FactualHostOwnerV1::Ingress.as_str();
const PREFIX: &str = FactualHostOwnerV1::Prefix.as_str();
const HISTORY_SCHEMA: u32 = FACTUAL_HISTORY_SCHEMA_ID_V1;
const PREFIX_SCHEMA: u32 = FACTUAL_PREFIX_SCHEMA_ID_V1;
/// The payload of the one draft most basis Drivers emit.
const ONE_DRAFT: &[u8] = b"a";
/// The owner ID of the Plugin whose nodes the seeded Ticks hold.
const OLD_OWNER: &str = "plugin:old";
/// The provenance digest of every seeded node.
const PROVENANCE: Hash = hash(9);
/// The nodes of the bulk Tick: the 4,096 inputs of a full output node.
const BULK: u32 = 4_096;
/// The schema ID of a bulk node: no host schema and no Event type has it.
const BULK_SCHEMA: u32 = 7;
/// How many Events one append writes.
const APPEND_BATCH: usize = 500;
/// The first Driver steps every ten nanoseconds, the second every millisecond.
const FAST: Duration = Duration::from_nanos(10);
const SLOW: Duration = Duration::from_millis(1);
const FAST_NS: u128 = FAST.as_nanos();
const SLOW_NS: u128 = SLOW.as_nanos();
/// The time of the one pass that starts the cadence of both Drivers.
const STEP_AT: u128 = 100;
/// After that pass only the first Driver is due: one nanosecond past its interval.
const FIRST_DUE_NS: u128 = STEP_AT + FAST_NS + 1;
/// Both Drivers are due again: a hundred nanoseconds past the second interval.
const BOTH_DUE_NS: u128 = STEP_AT + SLOW_NS + 100;

/// What a basis Driver emits and declares on its next step.
#[derive(Default)]
struct Plan {
    payloads: Vec<&'static [u8]>,
    step_inputs: Vec<DirectInputRefV1>,
    direct_inputs: Vec<DirectInputRefV1>,
}

impl Plan {
    /// A plan of one draft that declares these inputs.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn declaring(step_inputs: Vec<DirectInputRefV1>, direct_inputs: Vec<DirectInputRefV1>) -> Self {
        Self {
            payloads: vec![ONE_DRAFT],
            step_inputs,
            direct_inputs,
        }
    }

    /// The step output this plan describes for a Driver owning `event_type`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn output(&self, event_type: &str) -> StepOutput {
        let outputs = self
            .payloads
            .iter()
            .copied()
            .map(|payload| DeclaredOutputV1 {
                draft: EventDraft::new(
                    entity(10),
                    Kind::new(event_type),
                    CanonicalBytes::from_static(payload),
                ),
                direct_inputs: self.direct_inputs.clone(),
            })
            .collect();
        StepOutput::declared(self.step_inputs.clone(), outputs)
    }
}

type SharedPlan = Arc<Mutex<Plan>>;

/// The name of a basis Driver and the Event type its Plugin owns.
type Named = (&'static str, &'static str);

const FIRST: Named = ("first", "agent.basis.first");
const SECOND: Named = ("second", "agent.basis.second");
const THIRD: Named = ("third", "agent.basis.third");
const FOURTH: Named = ("fourth", "agent.basis.fourth");

/// Driver whose output and declared inputs a test sets between passes.
struct BasisDriver {
    name: &'static str,
    event_type: &'static str,
    interval: Duration,
    subscriptions: Vec<Kind>,
    verified_prefix: bool,
    plan: SharedPlan,
    log: Log,
}

impl BasisDriver {
    /// A Driver with no subscription that emits nothing, and its plan.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new(named: Named, log: &Log) -> (Self, SharedPlan) {
        let (name, event_type) = named;
        let plan = SharedPlan::default();
        let driver = Self {
            name,
            event_type,
            interval: Duration::from_nanos(10),
            subscriptions: Vec::new(),
            verified_prefix: false,
            plan: Arc::clone(&plan),
            log: Arc::clone(log),
        };
        (driver, plan)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn subscribed(mut self, event_type: &str) -> Self {
        self.subscriptions.push(Kind::new(event_type));
        self
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn verified(mut self) -> Self {
        self.verified_prefix = true;
        self
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn every(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

impl Driver for BasisDriver {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        self.name
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_interval(&self) -> Duration {
        self.interval
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_subscriptions(&self) -> &[Kind] {
        &self.subscriptions
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn requires_verified_event_prefix(&self) -> bool {
        self.verified_prefix
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        record(&self.log, format!("{}:step", self.name));
        let plan = self
            .plan
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(plan.output(self.event_type))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn commit_step(&mut self) {
        record(&self.log, format!("{}:commit", self.name));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn abort_step(&mut self) {
        record(&self.log, format!("{}:abort", self.name));
    }
}

/// Change what a Driver emits and declares from its next step on.
#[cfg_attr(coverage_nightly, coverage(off))]
fn plan_of(shared: &SharedPlan, change: impl FnOnce(&mut Plan)) {
    let mut guard = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    change(&mut guard);
}

/// The Driver emits `payloads` and declares nothing.
#[cfg_attr(coverage_nightly, coverage(off))]
fn emit(shared: &SharedPlan, payloads: &[&'static [u8]]) {
    plan_of(shared, |plan| {
        plan.payloads = payloads.to_vec();
        plan.step_inputs.clear();
        plan.direct_inputs.clear();
    });
}

/// The Driver follows `declared` from its next step on.
#[cfg_attr(coverage_nightly, coverage(off))]
fn declare(shared: &SharedPlan, declared: Plan) {
    plan_of(shared, |plan| *plan = declared);
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn register_basis(registry: &mut PluginRegistry, driver: BasisDriver) {
    let plugin = TestPlugin {
        id: PluginId::new(),
        name: driver.name,
        event_type: driver.event_type,
        reducer: false,
    };
    ok(registry.register_generated(&plugin, None, Some(Box::new(driver))));
    ok(registry.compose_non_participant_drivers());
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn committed(seq: u64) -> DirectInputRefV1 {
    DirectInputRefV1::CommittedEvent {
        seq: Seq::from_u64(seq),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn named(digest: Hash) -> DirectInputRefV1 {
    DirectInputRefV1::NodeDigest { digest }
}

/// The first `count` of `digests`, each declared by digest.
#[cfg_attr(coverage_nightly, coverage(off))]
fn named_inputs(digests: &[Hash], count: usize) -> Vec<DirectInputRefV1> {
    digests[..count].iter().copied().map(named).collect()
}

/// A digest that no `hash(n)` constant of these tests equals.
#[cfg_attr(coverage_nightly, coverage(off))]
fn indexed_hash(index: u32) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[0] = 0xA5;
    bytes[28..].copy_from_slice(&index.to_be_bytes());
    Hash::from_bytes(bytes)
}

/// Append `count` Events of `kind` to the Timeline, in batches.
#[cfg_attr(coverage_nightly, coverage(off))]
fn append_events(store: &mut dyn Harness, host: &Host, kind: &str, count: usize) {
    let mut left = count;
    while left > 0 {
        let batch = left.min(APPEND_BATCH);
        let drafts: Vec<EventDraft> = (0..batch)
            .map(|_| {
                let payload = CanonicalBytes::from_static(b"basis");
                EventDraft::new(entity(20), Kind::new(kind), payload)
            })
            .collect();
        ok(store.append(host.timeline, &drafts));
        left -= batch;
    }
}

/// The covered Events of a digest over `events`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn event_refs(events: &[Event]) -> Vec<FactualEventRefV1> {
    events
        .iter()
        .map(|event| FactualEventRefV1 {
            seq: event.seq,
            payload_hash: event.payload_hash,
        })
        .collect()
}

// ── Seeded prefix ─────────────────────────────────────────────────────────

/// A node of a seeded Tick, without the fields every seeded node shares.
struct NodeSpec<'a> {
    owner: &'a str,
    ordinal: u32,
    schema_id: u32,
    digest: Hash,
    class: RecordedDependencyClassV1,
}

/// The step node of `owner`: ordinal zero.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn step_spec(owner: &str, digest: Hash) -> NodeSpec<'_> {
    NodeSpec {
        owner,
        ordinal: 0,
        schema_id: FACTUAL_STEP_SCHEMA_ID_V1,
        digest,
        class: ENDOGENOUS,
    }
}

/// A node of `owner` that stands for an Event of the subscribed type.
#[cfg_attr(coverage_nightly, coverage(off))]
fn event_spec(
    owner: &str,
    ordinal: u32,
    digest: Hash,
    class: RecordedDependencyClassV1,
) -> NodeSpec<'_> {
    NodeSpec {
        owner,
        ordinal,
        schema_id: factual_event_schema_id(INPUT),
        digest,
        class,
    }
}

/// The committed node `spec` describes, at scheduler position one.
#[cfg_attr(coverage_nightly, coverage(off))]
fn seeded_node(tick: u64, spec: &NodeSpec<'_>) -> DependencyNodeRecordV1 {
    let coordinate = ok(DependencyNodeCoordinateV1::try_new(
        tick,
        1,
        spec.owner.to_owned(),
        spec.ordinal,
        spec.schema_id,
        spec.digest,
    ));
    ok(DependencyNodeRecordV1::try_new(
        coordinate,
        spec.class,
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        PROVENANCE,
    ))
}

/// A committed Tick that owns the `seq` range `range` and binds the Events
/// of `bound` to their nodes.
#[cfg_attr(coverage_nightly, coverage(off))]
fn seeded_tick(
    tick: u64,
    nodes: Vec<DependencyNodeRecordV1>,
    range: (u64, u64),
    bound: Vec<(Seq, Hash)>,
) -> SeededTick {
    let record = ok(TickDependencyRecordV1::try_new(
        tick,
        RecordedNodeOriginV1::Committed,
        nodes,
        Vec::new(),
    ));
    SeededTick {
        record,
        first_seq: Seq::from_u64(range.0),
        last_seq: Seq::from_u64(range.1),
        event_nodes: bound,
    }
}

/// A Tick of `BULK` nodes of one owner, each with its own digest. It owns Event 1.
#[cfg_attr(coverage_nightly, coverage(off))]
fn bulk_tick() -> SeededTick {
    let owner = "plugin:bulk";
    let nodes: Vec<DependencyNodeRecordV1> = (0..BULK)
        .map(|ordinal| {
            let spec = NodeSpec {
                owner,
                ordinal,
                schema_id: BULK_SCHEMA,
                digest: indexed_hash(ordinal),
                class: ENDOGENOUS,
            };
            seeded_node(1, &spec)
        })
        .collect();
    seeded_tick(1, nodes, (1, 1), Vec::new())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn bulk_digests() -> Vec<Hash> {
    (0..BULK).map(indexed_hash).collect()
}

// ── Passes and bases ───────────────────────────────────────────────────────

/// Which Drivers a pass steps.
#[derive(Clone, Copy)]
enum Selection {
    All,
    /// The Drivers due at this time in nanoseconds.
    Cadenced(u128),
}

/// A cut of the Timeline and the committed prefix the host hands a pass.
struct Cut<'a> {
    observed: u64,
    events: &'a [Event],
    selection: Selection,
}

/// The pass over every Driver observed through `observed`.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn all_at(observed: u64, events: &[Event]) -> Cut<'_> {
    Cut {
        observed,
        events,
        selection: Selection::All,
    }
}

/// The pass over the Drivers due at `now_ns`.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn due_at(observed: u64, events: &[Event], now_ns: u128) -> Cut<'_> {
    Cut {
        observed,
        events,
        selection: Selection::Cadenced(now_ns),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn step_all_pass(host: &Host, registry: &mut PluginRegistry, cut: &Cut<'_>) -> Staged {
    let ancestry = root_ancestry(host.timeline);
    let (timeline, events) = (host.timeline, cut.events);
    let through = Seq::from_u64(cut.observed);
    registry.step_all_anchored_with_events(timeline, &ancestry, through, events)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn step_due_pass(
    host: &Host,
    registry: &mut PluginRegistry,
    cut: &Cut<'_>,
    now_ns: u128,
) -> Staged {
    let ancestry = root_ancestry(host.timeline);
    let (timeline, events) = (host.timeline, cut.events);
    let through = Seq::from_u64(cut.observed);
    registry.tick_cadenced_anchored_with_events(timeline, &ancestry, now_ns, through, events)
}

/// Step the pass `cut` describes and stage its drafts.
#[cfg_attr(coverage_nightly, coverage(off))]
fn stage(host: &Host, registry: &mut PluginRegistry, cut: &Cut<'_>) -> Staged {
    match cut.selection {
        Selection::All => step_all_pass(host, registry, cut),
        Selection::Cadenced(now_ns) => step_due_pass(host, registry, cut, now_ns),
    }
}

/// Settle a staged pass that has no draft: nothing is admitted.
#[cfg_attr(coverage_nightly, coverage(off))]
fn settle_empty(host: &Host, registry: &mut PluginRegistry, store: &mut dyn Harness, key: u8) {
    let admitted = ok(host.admit(registry, store, key));
    assert!(admitted.is_none());
}

/// Admit the staged pass and return the basis the store was offered.
#[cfg_attr(coverage_nightly, coverage(off))]
fn admit_basis(
    host: &Host,
    registry: &mut PluginRegistry,
    store: &mut dyn Harness,
    key: u8,
) -> PipelineAdmissionBasisV1 {
    let admission = host.admission(store, key);
    let mut port = DigestRecordingPort::over(store);
    receipt(registry.admit_scheduled_pass(&mut port, &admission));
    assert_eq!(port.bases.len(), 1);
    port.bases.remove(0)
}

/// Admit the staged pass, which must fail, and return its error with the
/// number of bases the store was offered.
#[cfg_attr(coverage_nightly, coverage(off))]
fn admit_failure(
    host: &Host,
    registry: &mut PluginRegistry,
    store: &mut dyn Harness,
    key: u8,
) -> (RuntimeError, usize) {
    let admission = host.admission(store, key);
    let mut port = DigestRecordingPort::over(store);
    let error = err(registry.admit_scheduled_pass(&mut port, &admission));
    (error, port.bases.len())
}

/// Step the pass `cut` describes and admit it, returning its basis.
#[cfg_attr(coverage_nightly, coverage(off))]
fn pass_basis(
    host: &Host,
    registry: &mut PluginRegistry,
    store: &mut dyn Harness,
    cut: &Cut<'_>,
    key: u8,
) -> PipelineAdmissionBasisV1 {
    ok(stage(host, registry, cut));
    admit_basis(host, registry, store, key)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn declaration_error(error: RuntimeError) -> FactualDependencyErrorV1 {
    match error {
        RuntimeError::DependencyDeclaration(declaration) => declaration,
        other => std::panic::resume_unwind(Box::new(format!("unexpected error: {other}"))),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn declared_nodes(basis: &PipelineAdmissionBasisV1) -> &[DependencyNodeRecordV1] {
    basis.dependencies().record().nodes()
}

/// The `seq`s the ingress nodes of a basis are bound to, in the order declared.
#[cfg_attr(coverage_nightly, coverage(off))]
fn bound_seqs(basis: &PipelineAdmissionBasisV1) -> Vec<u64> {
    let bindings = basis.dependencies().event_nodes();
    bindings.iter().map(|b| b.seq.as_u64()).collect()
}

/// How many nodes of `owner` a basis declares.
#[cfg_attr(coverage_nightly, coverage(off))]
fn count_owned_by(basis: &PipelineAdmissionBasisV1, owner: &str) -> usize {
    let nodes = declared_nodes(basis);
    nodes
        .iter()
        .filter(|node| node.coordinate().owner_id() == owner)
        .count()
}

/// The node of `owner` at output ordinal `ordinal`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn node_of(basis: &PipelineAdmissionBasisV1, owner: &str, ordinal: u32) -> DependencyNodeRecordV1 {
    let nodes = declared_nodes(basis);
    let found = nodes.iter().find(|node| {
        node.coordinate().owner_id() == owner && node.coordinate().output_ordinal() == ordinal
    });
    found
        .cloned()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("no such node")))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn digest_of(basis: &PipelineAdmissionBasisV1, owner: &str, ordinal: u32) -> Hash {
    let node = node_of(basis, owner, ordinal);
    node.coordinate().artifact_digest()
}

/// The inputs the step node of `owner` declares.
#[cfg_attr(coverage_nightly, coverage(off))]
fn step_inputs_of(basis: &PipelineAdmissionBasisV1, owner: &str) -> Vec<Hash> {
    let step = node_of(basis, owner, 0);
    step.input_digests().to_vec()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn declares(basis: &PipelineAdmissionBasisV1, owner: &str, digest: Hash) -> bool {
    step_inputs_of(basis, owner).contains(&digest)
}

/// The owner ID of the `index`-th registered Driver.
///
/// The tests depend on `factual_owner_ids()` listing the Plugins in
/// registration order, which the registry's insertion-ordered map guarantees.
#[cfg_attr(coverage_nightly, coverage(off))]
fn owner_at(registry: &PluginRegistry, index: usize) -> String {
    let owners = registry.factual_owner_ids();
    owners[index].1.as_str().to_owned()
}

/// The key of a host node, which sits at scheduler position zero.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn host_key(tick: u64, owner: &str, ordinal: u32, schema_id: u32) -> FactualNodeKeyV1<'_> {
    FactualNodeKeyV1 {
        tick,
        scheduler_position: 0,
        owner,
        output_ordinal: ordinal,
        schema_id,
    }
}

// ── Chain edge across a fresh registry, class rule on a seeded node ───────

/// ADR-064 R3.4.2(c) and D16: a fresh registry over a prefix that already
/// holds Ticks looks up each Driver's latest step node, declares it as the
/// chain edge, and declares a Tick after the prefix head. The next pass of the
/// same registry declares the step node it recorded itself instead.
///
/// Until slices 8 and 9 the head stays at the seeded Tick, so the second pass
/// gets its Tick from the retained node.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_fresh_registry_chains_to_the_seeded_step_node_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        register(&mut registry, driver("second", Vec::new(), &log));
        let (first, second) = (owner_at(&registry, 0), owner_at(&registry, 1));
        append_events(store.as_mut(), &host, INPUT, 2);
        let seeded = hash(0x41);
        let step_node = step_spec(&first, seeded);
        let nodes = vec![seeded_node(3, &step_node)];
        let tick = seeded_tick(3, nodes, (1, 2), Vec::new());
        store.seed(host.timeline, &[tick]);
        let head = ok(store.last_committed_factual_tick(host.timeline));
        assert_eq!(head.tick, 3, "{name}");

        let one = admit_pass_basis(&host, &mut registry, store.as_mut(), (2, 1));
        assert_eq!(one.dependencies().tick(), 4, "{name}");
        let snapshot = digest_of(&one, OBSERVATION, 0);
        let inputs = step_inputs_of(&one, &first);
        assert_eq!(inputs.len(), 2, "{name}");
        assert!(inputs.contains(&seeded), "{name}");
        assert!(inputs.contains(&snapshot), "{name}");
        // The prefix holds no node of the second Driver: the snapshot is its only input.
        assert_eq!(step_inputs_of(&one, &second), [snapshot], "{name}");

        let two = admit_pass_basis(&host, &mut registry, store.as_mut(), (3, 2));
        assert_eq!(two.dependencies().tick(), 5, "{name}");
        let recorded = digest_of(&one, &first, 0);
        let chained = step_inputs_of(&two, &first);
        assert!(chained.contains(&recorded), "{name}");
        assert!(!chained.contains(&seeded), "{name}");
    }
}

/// ADR-064 R3.4.4 and R3.5: an Event forwarded to a Driver whose recorded
/// node is `PresentationOnly` breaks the class rule. The registry refuses the
/// pass before it offers the store anything, and the staged Driver aborts. A
/// second pass without a restore fails the same way; a restored Driver, which
/// is forwarded no Event and declares a history node instead, does not
/// violate the rule (R3.4.10).
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_seeded_presentation_only_event_node_is_refused_before_any_store_call() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut registry = host.registry();
        register_basis(&mut registry, driver.subscribed(INPUT));
        emit(&plan, &[b"a"]);
        append_events(store.as_mut(), &host, INPUT, 2);
        // Tick 1 owns both Events; the node of Event 1 is presentation only.
        let step_node = step_spec(OLD_OWNER, hash(0x51));
        let shown = event_spec(OLD_OWNER, 1, hash(0x52), PRESENTATION);
        let nodes = vec![seeded_node(1, &step_node), seeded_node(1, &shown)];
        let bound = vec![(Seq::from_u64(1), hash(0x52))];
        let tick = seeded_tick(1, nodes, (1, 2), bound);
        store.seed(host.timeline, &[tick]);

        let events = committed_events(store.as_ref(), host.timeline);
        ok(stage(&host, &mut registry, &all_at(2, &events)));
        let (error, offered) = admit_failure(&host, &mut registry, store.as_mut(), 1);
        assert_eq!(
            declaration_error(error),
            FactualDependencyErrorV1::ClassRuleViolation,
            "{name}"
        );
        assert_eq!(offered, 0, "{name}");
        let trail = entries(&log);
        assert_eq!(trail, ["first:step", "first:abort"], "{name}");
        let stored = committed_events(store.as_ref(), host.timeline);
        assert_eq!(stored.len(), 2, "{name}");

        // A second pass without a restore forwards the same Events and fails the same way.
        let violated = FactualDependencyErrorV1::ClassRuleViolation;
        ok(stage(&host, &mut registry, &all_at(2, &events)));
        let (again, offered) = admit_failure(&host, &mut registry, store.as_mut(), 2);
        assert_eq!(declaration_error(again), violated, "{name}");
        assert_eq!(offered, 0, "{name}");

        // A restored Driver is forwarded no Event: a history node covers them
        // (R3.4.10), the presentation-only node is no input, and the pass commits.
        let segment = TimelineHistorySegment::new(host.timeline, Seq::from_u64(2));
        ok(registry.restore_driver_state(&[segment], &events));
        let cut = all_at(2, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 3);
        assert_eq!(basis.dependencies().tick(), 2, "{name}");
        assert_eq!(count_owned_by(&basis, HISTORY), 1, "{name}");
        // Only the fold part records an ingress node (ADR-064 R4.1): Event 2,
        // since Event 1's presentation-only node makes it no fold input.
        assert_eq!(bound_seqs(&basis), [2], "{name}");
    }
}

// ── History nodes: collapse and restore ────────────────────────────────────

/// ADR-064 R3.4.8 and R3.4.10: a Driver whose carried set is full and that
/// has a new Event collapses the set into one history node. The next recorded
/// step declares that node, records it once, and consumes it.
///
/// The collapsed Events are not declared one by one: only the new Event gets
/// an ingress node.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_full_carried_set_collapses_into_one_history_node_on_both_adapters() {
    let full = MAX_FORWARDED_EVENTS_PER_DRIVER_V1;
    let carried = ok(u64::try_from(full));
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut registry = host.registry();
        register_basis(&mut registry, driver.subscribed(INPUT));
        append_events(store.as_mut(), &host, INPUT, full + 1);
        let events = committed_events(store.as_ref(), host.timeline);

        // A pass that stages nothing consumes the first Events into the carried set.
        ok(stage(&host, &mut registry, &all_at(carried, &events)));
        settle_empty(&host, &mut registry, store.as_mut(), 1);

        // One new Event finds the set full: the set collapses into a history node.
        emit(&plan, &[b"a"]);
        let cut = all_at(carried + 1, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 2);
        assert_eq!(basis.dependencies().tick(), 1, "{name}");
        assert_eq!(count_owned_by(&basis, HISTORY), 1, "{name}");
        // The new Event's ingress node, which the fold part shares, and one
        // per collapsed Event, which only the fold part inputs (ADR-064 R4.2).
        assert_eq!(count_owned_by(&basis, INGRESS), full + 1, "{name}");
        let node = node_of(&basis, HISTORY, 0);
        let schema = node.coordinate().schema_id();
        assert_eq!(schema, HISTORY_SCHEMA, "{name}");
        let covered = event_refs(&events[..full]);
        let content = factual_history_content_digest(
            Hash::zero(),
            Seq::from_u64(1),
            Seq::from_u64(carried),
            &covered,
        );
        let key = host_key(1, HISTORY, 0, HISTORY_SCHEMA);
        let expected = factual_artifact_digest(host.timeline, key, content);
        let history = node.coordinate().artifact_digest();
        assert_eq!(history, expected, "{name}");
        let owner = owner_at(&registry, 0);
        // The snapshot, the history node and the new Event's ingress node.
        let inputs = step_inputs_of(&basis, &owner);
        assert_eq!(inputs.len(), 3, "{name}");
        assert!(inputs.contains(&history), "{name}");

        // The next Tick neither records nor declares the consumed history.
        emit(&plan, &[b"b"]);
        let latest = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(carried + 2, &latest);
        let next = pass_basis(&host, &mut registry, store.as_mut(), &cut, 3);
        assert_eq!(next.dependencies().tick(), 2, "{name}");
        assert_eq!(count_owned_by(&next, HISTORY), 0, "{name}");
        let chain = step_inputs_of(&next, &owner);
        assert_eq!(chain.len(), 2, "{name}");
        assert!(!chain.contains(&history), "{name}");
    }
}

type Pair = (PluginRegistry, [SharedPlan; 2]);

/// Two Drivers restored over three Events, both stepped once at `STEP_AT`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn restored_pair(host: &Host, store: &mut dyn Harness, log: &Log) -> Pair {
    let (first, first_plan) = BasisDriver::new(FIRST, log);
    let (second, second_plan) = BasisDriver::new(SECOND, log);
    let mut registry = host.registry();
    register_basis(&mut registry, first.every(FAST));
    register_basis(&mut registry, second.every(SLOW));
    append_events(store, host, INPUT, 3);
    // The one step at `STEP_AT` leaves the second Driver not due for `SLOW_NS`.
    ok(stage(host, &mut registry, &due_at(0, &[], STEP_AT)));
    settle_empty(host, &mut registry, store, 1);
    let events = committed_events(store, host.timeline);
    let segment = TimelineHistorySegment::new(host.timeline, Seq::from_u64(3));
    ok(registry.restore_driver_state(&[segment], &events));
    (registry, [first_plan, second_plan])
}

/// ADR-064 R3.4.10: a restore gives every Driver the one history node that
/// covers the visible history. The first Driver to step records it; the
/// Driver stepped later declares it by artifact digest and records no second
/// node.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_restored_history_node_is_declared_by_the_driver_stepped_later_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (mut registry, plans) = restored_pair(&host, store.as_mut(), &log);
        let events = committed_events(store.as_ref(), host.timeline);
        let (first, second) = (owner_at(&registry, 0), owner_at(&registry, 1));

        // Only the first Driver is due: it records the restored history node.
        emit(&plans[0], &[b"a"]);
        let cut = due_at(3, &events, FIRST_DUE_NS);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 2);
        assert_eq!(basis.dependencies().tick(), 1, "{name}");
        assert_eq!(count_owned_by(&basis, HISTORY), 1, "{name}");
        assert_eq!(count_owned_by(&basis, &second), 0, "{name}");
        let covered = event_refs(&events);
        let content = factual_history_content_digest(
            Hash::zero(),
            Seq::from_u64(1),
            Seq::from_u64(3),
            &covered,
        );
        let key = host_key(1, HISTORY, 0, HISTORY_SCHEMA);
        let expected = factual_artifact_digest(host.timeline, key, content);
        let history = digest_of(&basis, HISTORY, 0);
        assert_eq!(history, expected, "{name}");
        assert!(declares(&basis, &first, history), "{name}");

        // The second Driver steps later and declares the node without recording another.
        emit(&plans[0], &[]);
        emit(&plans[1], &[b"b"]);
        let latest = committed_events(store.as_ref(), host.timeline);
        let cut = due_at(4, &latest, BOTH_DUE_NS);
        let later = pass_basis(&host, &mut registry, store.as_mut(), &cut, 3);
        assert_eq!(later.dependencies().tick(), 2, "{name}");
        assert_eq!(count_owned_by(&later, HISTORY), 0, "{name}");
        assert!(declares(&later, &second, history), "{name}");
        assert!(!declares(&later, &first, history), "{name}");
        let step_digest = digest_of(&basis, &first, 0);
        assert!(declares(&later, &first, step_digest), "{name}");
    }
}

/// ADR-064 R3.4.10: Drivers stepped in the same pass after a restore share
/// the one history node.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn drivers_stepped_together_after_a_restore_share_one_history_node() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (mut registry, plans) = restored_pair(&host, store.as_mut(), &log);
        let events = committed_events(store.as_ref(), host.timeline);
        emit(&plans[0], &[b"a"]);
        emit(&plans[1], &[b"b"]);
        let cut = all_at(3, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 2);
        assert_eq!(count_owned_by(&basis, HISTORY), 1, "{name}");
        let history = digest_of(&basis, HISTORY, 0);
        for index in 0..2 {
            let owner = owner_at(&registry, index);
            assert!(declares(&basis, &owner, history), "{name}");
        }
    }
}

// ── The verified prefix ───────────────────────────────────────────────────

/// ADR-064 R3.3.1 and R3.4.9: Drivers that read the verified prefix declare a
/// prefix node, shared by every Driver whose prefix digest is equal. A Driver
/// without the prefix declares none.
///
/// The prefix ordinal is the rank of first use in schedule order (R3.4.9: `k`
/// in the schedule order of the first Driver that needs the digest), as the
/// registry's `Interned` list assigns it.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn verified_prefix_drivers_declare_one_prefix_node_per_digest_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let mut registry = host.registry();
        let (first, plan) = BasisDriver::new(FIRST, &log);
        register_basis(&mut registry, first.verified());
        let (second, _) = BasisDriver::new(SECOND, &log);
        register_basis(&mut registry, second.verified());
        let (third, _) = BasisDriver::new(THIRD, &log);
        register_basis(&mut registry, third);
        let (fourth, _) = BasisDriver::new(FOURTH, &log);
        register_basis(&mut registry, fourth.verified().subscribed(INPUT));
        emit(&plan, &[b"a"]);
        append_events(store.as_mut(), &host, INPUT, 2);
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(2, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 1);
        let tick = basis.dependencies().tick();
        assert_eq!(count_owned_by(&basis, PREFIX), 2, "{name}");

        // The first two Drivers hand an empty prefix; the fourth hands both Events.
        let through = Seq::from_u64(2);
        let empty = factual_verified_prefix_content_digest(through, &[]);
        let handed = event_refs(&events);
        let full = factual_verified_prefix_content_digest(through, &handed);
        let zero_key = host_key(tick, PREFIX, 0, PREFIX_SCHEMA);
        let shared = factual_artifact_digest(host.timeline, zero_key, empty);
        let one_key = host_key(tick, PREFIX, 1, PREFIX_SCHEMA);
        let apart = factual_artifact_digest(host.timeline, one_key, full);
        assert_eq!(digest_of(&basis, PREFIX, 0), shared, "{name}");
        assert_eq!(digest_of(&basis, PREFIX, 1), apart, "{name}");

        let owners: Vec<String> = (0..4).map(|i| owner_at(&registry, i)).collect();
        assert!(declares(&basis, &owners[0], shared), "{name}");
        assert!(declares(&basis, &owners[1], shared), "{name}");
        assert!(!declares(&basis, &owners[2], shared), "{name}");
        assert!(!declares(&basis, &owners[2], apart), "{name}");
        assert!(declares(&basis, &owners[3], apart), "{name}");
        assert!(!declares(&basis, &owners[3], shared), "{name}");

        // The prefix nodes are recomputed, input-free and of the prefix schema.
        for ordinal in 0..2 {
            let node = node_of(&basis, PREFIX, ordinal);
            assert_eq!(node.class(), ENDOGENOUS, "{name}");
            assert_eq!(node.coordinate().schema_id(), PREFIX_SCHEMA, "{name}");
            assert!(node.input_digests().is_empty(), "{name}");
        }
        // The fourth Driver subscribed to the Event type, so its step node
        // declares exactly the snapshot, its prefix node and the two ingress nodes.
        let snapshot = digest_of(&basis, OBSERVATION, 0);
        let first_ingress = digest_of(&basis, INGRESS, 0);
        let second_ingress = digest_of(&basis, INGRESS, 1);
        let mut expected = [snapshot, apart, first_ingress, second_ingress];
        expected.sort();
        let mut inputs = step_inputs_of(&basis, &owners[3]);
        inputs.sort();
        assert_eq!(inputs, expected, "{name}");
    }
}

// ── An in-doubt pass ──────────────────────────────────────────────────────

/// ADR-064 R3.8.1: a pass whose outcome is unknown and that the store
/// admitted settles the registry's chain and history state when it is
/// recovered, exactly as a first commit does. The Driver that stepped has its
/// step node recorded; the restored Driver that did not step still holds the
/// history node the pass recorded, and declares it by digest in the next Tick
/// without recording a second one.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_recovered_pass_settles_chain_and_history_like_a_first_commit() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (mut registry, plans) = restored_pair(&host, store.as_mut(), &log);
        let events = committed_events(store.as_ref(), host.timeline);
        let (first, second) = (owner_at(&registry, 0), owner_at(&registry, 1));

        emit(&plans[0], &[b"a"]);
        ok(stage(
            &host,
            &mut registry,
            &due_at(3, &events, FIRST_DUE_NS),
        ));
        let lost = lose_outcome_basis(&host, &mut registry, store.as_mut(), 2);
        let before = count(&log, "first:commit");
        let appended = committed_events(store.as_ref(), host.timeline).len();

        // The store admitted the batch: recovery resubmits the retained exact basis.
        let mut port = DigestRecordingPort::over(store.as_mut());
        let recovered = receipt(registry.recover_scheduled_pass(&mut port));
        assert_eq!(port.bases.len(), 1, "{name}");
        let resubmitted = port.bases.remove(0);
        assert_eq!(resubmitted, lost, "{name}");
        assert_eq!(recovered.committed_events().len(), 1, "{name}");
        // The resubmission replayed the receipt: no Event was appended twice.
        let after = committed_events(store.as_ref(), host.timeline).len();
        assert_eq!(after, appended, "{name}");
        assert_eq!(count(&log, "first:commit"), before + 1, "{name}");
        assert_eq!(count_owned_by(&resubmitted, HISTORY), 1, "{name}");
        let history = digest_of(&resubmitted, HISTORY, 0);
        let step_digest = digest_of(&resubmitted, &first, 0);

        // The next Tick wakes the second Driver as well.
        emit(&plans[0], &[]);
        emit(&plans[1], &[b"b"]);
        let latest = committed_events(store.as_ref(), host.timeline);
        let cut = due_at(4, &latest, BOTH_DUE_NS);
        let later = pass_basis(&host, &mut registry, store.as_mut(), &cut, 3);
        assert_eq!(later.dependencies().tick(), 2, "{name}");
        assert_eq!(count_owned_by(&later, HISTORY), 0, "{name}");
        assert!(declares(&later, &second, history), "{name}");
        assert!(declares(&later, &first, step_digest), "{name}");
        assert!(!declares(&later, &first, history), "{name}");
    }
}

// ── Refusals by the store ─────────────────────────────────────────────────

/// ADR-064 R3.8.2: the two dependency outcomes the store may return are
/// wrapped as a not-admitted error, the staged Drivers abort, and nothing
/// commits. A refused attempt advances nothing: the next pass declares the
/// same Tick again.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_stores_dependency_refusals_abort_the_staged_drivers_on_both_adapters() {
    let refusals = [
        PipelineOutcomeV1::InvalidDependencyDeclaration,
        PipelineOutcomeV1::DependencySetExhausted,
    ];
    for outcome in refusals {
        // The port answers the refusal itself, so the adapter loop only keeps
        // the harness uniform with the other tests.
        for (name, mut store) in stores() {
            let host = Host::prepare(store.as_mut(), 1_000);
            let log = Log::default();
            let mut registry = host.registry();
            register(&mut registry, driver("first", vec![b"a1"], &log));
            ok(stage(&host, &mut registry, &all_at(0, &[])));
            let admission = host.admission(store.as_ref(), 1);
            let mut port = DigestRecordingPort::refusing(store.as_mut(), outcome.clone());
            let refused = rejection(registry.admit_scheduled_pass(&mut port, &admission));
            assert_eq!(refused, format!("{outcome:?}"), "{name}");
            assert_eq!(port.bases.len(), 1, "{name}");
            let trail = entries(&log);
            assert_eq!(trail, ["first:step@0", "first:abort"], "{name}");
            let stored = committed_events(store.as_ref(), host.timeline);
            assert!(stored.is_empty(), "{name}");

            let retry = admit_pass_basis(&host, &mut registry, store.as_mut(), (0, 2));
            assert_eq!(retry.dependencies().tick(), 1, "{name}");
        }
    }
}

// ── Ingress nodes, the carried set and declared inputs ────────────────────

/// ADR-064 R3.4.4 and R3.7.4: the Events forwarded to the Drivers of a pass,
/// which have no node in the prefix, get one ingress node each, recorded once
/// and bound to their `seq` in ascending order (R3.7.4 persists the per-Event
/// binding). Every Driver that received them declares the same nodes.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn ingress_nodes_bind_the_forwarded_events_in_ascending_order_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let mut registry = host.registry();
        let (first, plan) = BasisDriver::new(FIRST, &log);
        register_basis(&mut registry, first.subscribed(INPUT));
        let (second, _) = BasisDriver::new(SECOND, &log);
        register_basis(&mut registry, second.subscribed(INPUT));
        emit(&plan, &[b"a"]);
        append_events(store.as_mut(), &host, INPUT, 3);
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(3, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 1);

        assert_eq!(bound_seqs(&basis), [1, 2, 3], "{name}");
        let bindings = basis.dependencies().event_nodes();
        let nodes = declared_nodes(&basis);
        let schema = factual_event_schema_id(INPUT);
        for (ordinal, (binding, event)) in (0_u32..).zip(bindings.iter().zip(&events)) {
            let node = &nodes[ok(usize::try_from(binding.node_index))];
            let coordinate = node.coordinate();
            assert_eq!(coordinate.owner_id(), INGRESS, "{name}");
            assert_eq!(coordinate.output_ordinal(), ordinal, "{name}");
            let exogenous = RecordedDependencyClassV1::ExogenousFrozen;
            assert_eq!(node.class(), exogenous, "{name}");
            let content = factual_ingress_content_digest(event.payload_hash, event.seq);
            let key = host_key(1, INGRESS, ordinal, schema);
            let expected = factual_artifact_digest(host.timeline, key, content);
            assert_eq!(coordinate.artifact_digest(), expected, "{name}");
        }
        assert_eq!(count_owned_by(&basis, INGRESS), 3, "{name}");
        // Both Drivers declare the snapshot and the three ingress nodes, once each.
        for index in 0..2 {
            let owner = owner_at(&registry, index);
            assert_eq!(step_inputs_of(&basis, &owner).len(), 4, "{name}");
        }
    }
}

/// ADR-064 R3.4.7 and R3.4.8: the Events a pass consumed without recording a
/// step node stay in the Driver's carried set with their own Event type. The
/// next recorded step declares them besides its new Events, and a recorded step
/// consumes the set.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn events_consumed_by_an_empty_pass_are_declared_by_the_next_recorded_step() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut registry = host.registry();
        let both = driver.subscribed(INPUT).subscribed(OTHER_INPUT);
        register_basis(&mut registry, both);
        // Event 1 is of one subscribed type and Event 2 of the other.
        append_events(store.as_mut(), &host, INPUT, 1);
        append_events(store.as_mut(), &host, OTHER_INPUT, 1);
        let events = committed_events(store.as_ref(), host.timeline);
        ok(stage(&host, &mut registry, &all_at(2, &events)));
        settle_empty(&host, &mut registry, store.as_mut(), 1);

        append_events(store.as_mut(), &host, INPUT, 1);
        let events = committed_events(store.as_ref(), host.timeline);
        emit(&plan, &[b"a"]);
        let cut = all_at(3, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 2);
        assert_eq!(bound_seqs(&basis), [1, 2, 3], "{name}");
        // Each carried Event keeps the schema ID of its own Event type.
        let input_schema = factual_event_schema_id(INPUT);
        let other_schema = factual_event_schema_id(OTHER_INPUT);
        let expected = [input_schema, other_schema, input_schema];
        let nodes = declared_nodes(&basis);
        let bindings = basis.dependencies().event_nodes();
        for (binding, schema) in bindings.iter().zip(expected) {
            let node = &nodes[ok(usize::try_from(binding.node_index))];
            assert_eq!(node.coordinate().schema_id(), schema, "{name}");
        }

        // The recorded step consumed the set: the next Tick declares only what is new.
        append_events(store.as_mut(), &host, INPUT, 1);
        let latest = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(5, &latest);
        let next = pass_basis(&host, &mut registry, store.as_mut(), &cut, 3);
        assert_eq!(bound_seqs(&next), [5], "{name}");
    }
}

/// ADR-064 R3.6.1 and R3.4.2: equal inputs, however they are declared, are
/// declared once (the host deduplicates each node's inputs). A forwarded Event
/// that the prefix holds a node for is declared by that node (R3.4.4), not by
/// an ingress node.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn equal_inputs_declared_in_several_ways_are_declared_once_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut registry = host.registry();
        register_basis(&mut registry, driver.subscribed(INPUT));
        append_events(store.as_mut(), &host, INPUT, 3);
        // Tick 1 owns Event 1: a step node and the node of Event 1.
        let (step_digest, event_digest) = (hash(0x61), hash(0x62));
        let step_node = step_spec(OLD_OWNER, step_digest);
        let event_node = event_spec(OLD_OWNER, 1, event_digest, ENDOGENOUS);
        let nodes = vec![seeded_node(1, &step_node), seeded_node(1, &event_node)];
        let bound = vec![(Seq::from_u64(1), event_digest)];
        let tick = seeded_tick(1, nodes, (1, 1), bound);
        store.seed(host.timeline, &[tick]);

        // Event 2 is forwarded and declared; the step node is named twice at
        // step level and once at draft level; Event 3 is forwarded and declared
        // by the draft.
        let at_step = vec![committed(2), named(step_digest), named(step_digest)];
        let at_draft = vec![named(step_digest), committed(3)];
        declare(&plan, Plan::declaring(at_step, at_draft));
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(3, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 1);

        let owner = owner_at(&registry, 0);
        // The snapshot, the node of Event 1, the ingress nodes of Events 2 and 3, the named node.
        let inputs = step_inputs_of(&basis, &owner);
        assert_eq!(inputs.len(), 5, "{name}");
        assert!(inputs.contains(&event_digest), "{name}");
        assert!(inputs.contains(&step_digest), "{name}");
        assert_eq!(count_owned_by(&basis, INGRESS), 2, "{name}");
        // The output node declares its step node, the named node and Event 3's ingress node.
        let output = node_of(&basis, &owner, 1);
        assert_eq!(output.input_digests().len(), 3, "{name}");
    }
}

// ── Declared inputs the registry refuses ──────────────────────────────────

/// The inputs a one-Driver pass declares, and whether the Driver subscribes to
/// the Event type of the Events the pass handles.
struct Declares {
    subscribed: bool,
    plan: Plan,
}

impl Declares {
    /// Declare `inputs` on the step node.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn steps(subscribed: bool, inputs: Vec<DirectInputRefV1>) -> Self {
        Self {
            subscribed,
            plan: Plan::declaring(inputs, Vec::new()),
        }
    }

    /// Declare `inputs` on the one draft.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn drafts(subscribed: bool, inputs: Vec<DirectInputRefV1>) -> Self {
        Self {
            subscribed,
            plan: Plan::declaring(Vec::new(), inputs),
        }
    }
}

/// A registry of the one Driver `first`, set to declare `wanted`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn declaring_registry(host: &Host, log: &Log, wanted: Declares) -> PluginRegistry {
    let (driver, plan) = BasisDriver::new(FIRST, log);
    let driver = if wanted.subscribed {
        driver.subscribed(INPUT)
    } else {
        driver
    };
    let mut registry = host.registry();
    register_basis(&mut registry, driver);
    declare(&plan, wanted.plan);
    registry
}

/// Run the pass of a Driver that declares `wanted` and return its basis with
/// the owner ID of the Driver.
#[cfg_attr(coverage_nightly, coverage(off))]
fn declared_basis(
    name: &str,
    host: &Host,
    store: &mut dyn Harness,
    wanted: Declares,
    cut: &Cut<'_>,
) -> (PipelineAdmissionBasisV1, String) {
    let log = Log::default();
    let mut registry = declaring_registry(host, &log, wanted);
    let basis = pass_basis(host, &mut registry, store, cut, 1);
    assert_eq!(count(&log, "first:commit"), 1, "{name}");
    (basis, owner_at(&registry, 0))
}

/// Run the pass of a Driver that declares `wanted`, which the registry must
/// refuse before the store is offered anything, and return the error.
#[cfg_attr(coverage_nightly, coverage(off))]
fn refused_declaration(
    name: &str,
    host: &Host,
    store: &mut dyn Harness,
    wanted: Declares,
    cut: &Cut<'_>,
) -> FactualDependencyErrorV1 {
    let log = Log::default();
    let mut registry = declaring_registry(host, &log, wanted);
    ok(stage(host, &mut registry, cut));
    let (error, offered) = admit_failure(host, &mut registry, store, 1);
    assert_eq!(offered, 0, "{name}");
    let trail = entries(&log);
    assert_eq!(trail, ["first:step", "first:abort"], "{name}");
    declaration_error(error)
}

/// Run the pass of a Driver that declares `inputs` at the step level and again
/// at the draft level, and assert the registry refuses both with `expected`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_refused_at_both_levels(
    name: &str,
    host: &Host,
    store: &mut dyn Harness,
    subscribed: bool,
    inputs: &[DirectInputRefV1],
    cut: &Cut<'_>,
    expected: FactualDependencyErrorV1,
) {
    let wanted = Declares::steps(subscribed, inputs.to_vec());
    let refused = refused_declaration(name, host, store, wanted, cut);
    assert_eq!(refused, expected, "{name}: step level");
    let wanted = Declares::drafts(subscribed, inputs.to_vec());
    let refused = refused_declaration(name, host, store, wanted, cut);
    assert_eq!(refused, expected, "{name}: draft level");
}

/// ADR-064 R3.6.2: a Driver may declare only an Event it could have read: one
/// at or below the cut, of a type it subscribed to, and only if it subscribed
/// to some type. A node digest that names the node of such an Event is
/// undeclarable too.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn undeclarable_inputs_abort_the_pass_before_any_store_call_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        append_events(store.as_mut(), &host, INPUT, 2);
        append_events(store.as_mut(), &host, OTHER_INPUT, 1);
        let events = committed_events(store.as_ref(), host.timeline);
        let undeclarable = FactualDependencyErrorV1::UndeclarableInput;
        let store = store.as_mut();

        // Event 2 lies above a cut at 1.
        let cut = all_at(1, &events);
        let inputs = [committed(2)];
        assert_refused_at_both_levels(name, &host, store, true, &inputs, &cut, undeclarable);

        // A Driver that subscribed to no Event type observes none.
        let cut = all_at(2, &events);
        let inputs = [committed(1)];
        assert_refused_at_both_levels(name, &host, store, false, &inputs, &cut, undeclarable);

        // Event 3 is of a type the Driver did not subscribe to.
        let cut = all_at(3, &events);
        let inputs = [committed(3)];
        assert_refused_at_both_levels(name, &host, store, true, &inputs, &cut, undeclarable);

        // The recorded node of Event 3, named by its digest, is undeclarable as well.
        let step_node = step_spec(OLD_OWNER, hash(0x91));
        let other = NodeSpec {
            owner: OLD_OWNER,
            ordinal: 1,
            schema_id: factual_event_schema_id(OTHER_INPUT),
            digest: hash(0x92),
            class: ENDOGENOUS,
        };
        let nodes = vec![seeded_node(1, &step_node), seeded_node(1, &other)];
        let bound = vec![(Seq::from_u64(3), hash(0x92))];
        store.seed(host.timeline, &[seeded_tick(1, nodes, (1, 3), bound)]);
        let inputs = [named(hash(0x92))];
        assert_refused_at_both_levels(name, &host, store, true, &inputs, &cut, undeclarable);
    }
}

/// ADR-064 R3.6.2: a declared input that resolves to no Event the pass saw
/// and no recorded node is unresolved, at both levels. An Event "seen by the
/// pass" is one the host handed to the pass.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn unresolved_inputs_abort_the_pass_before_any_store_call_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        append_events(store.as_mut(), &host, INPUT, 3);
        let events = committed_events(store.as_ref(), host.timeline);
        let unresolved = FactualDependencyErrorV1::UnresolvedInput;
        let store = store.as_mut();

        // The host hands the pass Events 1 and 2 only, and the prefix holds no node for Event 3.
        let seen = &events[..2];
        let cut = all_at(3, seen);
        let inputs = [committed(3)];
        assert_refused_at_both_levels(name, &host, store, true, &inputs, &cut, unresolved);

        // No recorded node has this digest.
        let cut = all_at(3, &events);
        let inputs = [named(hash(0xEE))];
        assert_refused_at_both_levels(name, &host, store, false, &inputs, &cut, unresolved);
    }
}

/// ADR-064 R3.5: a declared input that resolves to a `PresentationOnly` node
/// breaks the class rule, at step level and at draft level.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_declared_presentation_only_node_breaks_the_class_rule_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        append_events(store.as_mut(), &host, INPUT, 1);
        let step_node = step_spec(OLD_OWNER, hash(0x71));
        let shown = event_spec(OLD_OWNER, 1, hash(0x72), PRESENTATION);
        let nodes = vec![seeded_node(1, &step_node), seeded_node(1, &shown)];
        // The node is deliberately unbound: no `event_nodes` binding names it,
        // so a Driver reaches it only by its digest.
        let tick = seeded_tick(1, nodes, (1, 1), Vec::new());
        store.seed(host.timeline, &[tick]);
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(1, &events);
        let violated = FactualDependencyErrorV1::ClassRuleViolation;

        let wanted = Declares::steps(false, vec![named(hash(0x72))]);
        let refused = refused_declaration(name, &host, store.as_mut(), wanted, &cut);
        assert_eq!(refused, violated, "{name}");
        let wanted = Declares::drafts(false, vec![named(hash(0x72))]);
        let refused = refused_declaration(name, &host, store.as_mut(), wanted, &cut);
        assert_eq!(refused, violated, "{name}");
    }
}

/// The error of a declaration that overfills a node's inputs.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn bounds_error() -> FactualDependencyErrorV1 {
    FactualDependencyErrorV1::Record(CounterfactualDependencyErrorV1::FieldOutOfBounds)
}

/// ADR-064 R3.6.1: a Driver may declare 255 step-level inputs, which with the
/// snapshot node fill a step node. One more is refused before the store is
/// offered anything.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_step_level_declaration_cap_holds_on_both_adapters() {
    let cap = MAX_STEP_INPUTS_PER_DRIVER_V1;
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        append_events(store.as_mut(), &host, INPUT, 1);
        store.seed(host.timeline, &[bulk_tick()]);
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(1, &events);
        let digests = bulk_digests();

        let at_cap = Declares::steps(false, named_inputs(&digests, cap));
        let (basis, owner) = declared_basis(name, &host, store.as_mut(), at_cap, &cut);
        assert_eq!(basis.dependencies().tick(), 2, "{name}");
        let inputs = step_inputs_of(&basis, &owner);
        assert_eq!(inputs.len(), cap + 1, "{name}");

        let over = Declares::steps(false, named_inputs(&digests, cap + 1));
        let refused = refused_declaration(name, &host, store.as_mut(), over, &cut);
        assert_eq!(refused, bounds_error(), "{name}");
    }
}

/// ADR-064 R3.6.1: a draft may declare 4,095 inputs, which with its step node
/// fill an output node. One more is refused before the store is offered
/// anything.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_draft_level_declaration_cap_holds_on_both_adapters() {
    let cap = MAX_OUTPUT_DIRECT_INPUTS_V1;
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        append_events(store.as_mut(), &host, INPUT, 1);
        store.seed(host.timeline, &[bulk_tick()]);
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(1, &events);
        let digests = bulk_digests();

        let at_cap = Declares::drafts(false, named_inputs(&digests, cap));
        let (basis, owner) = declared_basis(name, &host, store.as_mut(), at_cap, &cut);
        assert_eq!(basis.dependencies().tick(), 2, "{name}");
        let output = node_of(&basis, &owner, 1);
        assert_eq!(output.input_digests().len(), cap + 1, "{name}");

        let over = Declares::drafts(false, named_inputs(&digests, cap + 1));
        let refused = refused_declaration(name, &host, store.as_mut(), over, &cut);
        assert_eq!(refused, bounds_error(), "{name}");
    }
}

// ── The 4 + 3,837 + 255 partition of a step node ──────────────────────────

/// The Events a saturated Driver is forwarded: the most one step node declares.
const BACKLOG: usize = MAX_FORWARDED_EVENTS_PER_DRIVER_V1;
/// The Events of the history a restore covers.
const RESTORED: usize = 2;
/// The artifact digest of the seeded step node a restored Driver chains to.
const CHAIN_DIGEST: Hash = hash(0x81);

/// A verified-prefix Driver that a restore left with a history node and a
/// chain lookup to a seeded step node, and the `BACKLOG` Events it is
/// forwarded next. Return its registry, its plan and the committed prefix.
///
/// The seeded Ticks are the bulk Tick of 4,096 declarable nodes and a Tick
/// with the step node of the Driver.
#[cfg_attr(coverage_nightly, coverage(off))]
fn saturated_driver(
    host: &Host,
    store: &mut dyn Harness,
    log: &Log,
) -> (PluginRegistry, SharedPlan, Vec<Event>) {
    let (driver, plan) = BasisDriver::new(FIRST, log);
    let mut registry = host.registry();
    register_basis(&mut registry, driver.verified().subscribed(INPUT));
    append_events(store, host, OTHER_INPUT, RESTORED);
    let owner = owner_at(&registry, 0);
    let step_node = step_spec(&owner, CHAIN_DIGEST);
    let chain = seeded_tick(2, vec![seeded_node(2, &step_node)], (2, 2), Vec::new());
    store.seed(host.timeline, &[bulk_tick(), chain]);
    let history = committed_events(store, host.timeline);
    let segment = TimelineHistorySegment::new(host.timeline, Seq::from_u64(2));
    ok(registry.restore_driver_state(&[segment], &history));
    append_events(store, host, INPUT, BACKLOG);
    let events = committed_events(store, host.timeline);
    (registry, plan, events)
}

/// ADR-064 R3.4.2 and R3.6.1 (4 + 3,837 + 255 = 4,096): a verified-prefix
/// Driver at a saturated backlog, with a history node and a chain edge, that
/// declares 255 step inputs gets a step node of exactly 4,096 inputs: the
/// snapshot, the chain, the history and the prefix node, 3,837 ingress nodes
/// and the 255 declared nodes.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_saturated_driver_declares_a_step_node_of_exactly_4096_inputs_on_both_adapters() {
    let cap = MAX_STEP_INPUTS_PER_DRIVER_V1;
    let digests = bulk_digests();
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (mut registry, plan, events) = saturated_driver(&host, store.as_mut(), &log);
        let wanted = Plan::declaring(named_inputs(&digests, cap), Vec::new());
        declare(&plan, wanted);
        let through = ok(u64::try_from(events.len()));
        let cut = all_at(through, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 1);

        assert_eq!(basis.dependencies().tick(), 3, "{name}");
        // The backlog's ingress nodes, which the fold part shares, and those of
        // the restored Events, which only the fold part inputs (ADR-064 R4.2).
        assert_eq!(
            count_owned_by(&basis, INGRESS),
            BACKLOG + RESTORED,
            "{name}"
        );
        assert_eq!(count_owned_by(&basis, HISTORY), 1, "{name}");
        assert_eq!(count_owned_by(&basis, PREFIX), 1, "{name}");
        let owner = owner_at(&registry, 0);
        let inputs = step_inputs_of(&basis, &owner);
        let full = ok(usize::try_from(BULK));
        assert_eq!(inputs.len(), full, "{name}");
        assert!(inputs.contains(&CHAIN_DIGEST), "{name}");
    }
}

/// ADR-064 R3.6.1: at a saturated backlog one more declared input is refused
/// before the store is offered anything, and the staged Driver aborts.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn one_more_declared_input_is_refused_at_a_saturated_backlog_on_both_adapters() {
    let cap = MAX_STEP_INPUTS_PER_DRIVER_V1;
    let digests = bulk_digests();
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (mut registry, plan, events) = saturated_driver(&host, store.as_mut(), &log);
        let wanted = Plan::declaring(named_inputs(&digests, cap + 1), Vec::new());
        declare(&plan, wanted);
        let through = ok(u64::try_from(events.len()));
        ok(stage(&host, &mut registry, &all_at(through, &events)));
        let (error, offered) = admit_failure(&host, &mut registry, store.as_mut(), 1);
        assert_eq!(declaration_error(error), bounds_error(), "{name}");
        assert_eq!(offered, 0, "{name}");
        assert_eq!(count(&log, "first:abort"), 1, "{name}");
    }
}

// ── Recorded rows through the registry (ADR-064 Revision 3, Redmine #604) ──
//
// Both adapters record the Tick rows with the Events.

/// ADR-064 R3.4.4 and R3.7.4: the Events forwarded to a Driver that have no
/// node get one ingress node each, recorded once with the Tick and bound to
/// their `seq`. A later pass that forwards a new Event records one more node
/// and no second node for the earlier Events.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn forwarded_events_are_recorded_once_as_ingress_nodes_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let mut registry = host.registry();
        let (first, plan) = BasisDriver::new(FIRST, &log);
        register_basis(&mut registry, first.subscribed(INPUT));
        emit(&plan, &[b"a"]);
        append_events(store.as_mut(), &host, INPUT, 3);
        let events = committed_events(store.as_ref(), host.timeline);
        let cut = all_at(3, &events);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 1);

        // The snapshot, three ingress nodes, the step node, the one output, and
        // the fold checkpoint node over the three Events (ADR-064 R4.2).
        let counts = ok(store.factual_set_counts(host.timeline));
        assert_eq!(counts.nodes, declared_nodes(&basis).len(), "{name}");
        assert_eq!(counts.nodes, 7, "{name}");
        let seqs = [1, 2, 3, 4].map(Seq::from_u64);
        let bound = ok(store.nodes_for_committed_events(host.timeline, &seqs));
        let owners: Vec<Option<&str>> = bound
            .iter()
            .map(|node| node.as_ref().map(|found| found.coordinate().owner_id()))
            .collect();
        let driver = owner_at(&registry, 0);
        assert_eq!(owners[..3], [Some(INGRESS); 3], "{name}");
        assert_eq!(owners[3], Some(driver.as_str()), "{name}");

        // A fourth raw Event is the only one the next pass records a node for.
        append_events(store.as_mut(), &host, INPUT, 1);
        let latest = committed_events(store.as_ref(), host.timeline);
        emit(&plan, &[b"b"]);
        let cut = all_at(5, &latest);
        let next = pass_basis(&host, &mut registry, store.as_mut(), &cut, 2);
        assert_eq!(bound_seqs(&next), [5], "{name}");
        let after = ok(store.factual_set_counts(host.timeline));
        assert_eq!(
            after.nodes,
            counts.nodes + declared_nodes(&next).len(),
            "{name}"
        );
    }
}

/// ADR-064 R3.4.10 and R3.7.4: the history node a restore leaves is recorded
/// once, by the first Driver that steps; the Driver stepped later declares it
/// by digest and the store resolves it without a second row.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_restored_history_node_is_recorded_once_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (mut registry, plans) = restored_pair(&host, store.as_mut(), &log);
        let events = committed_events(store.as_ref(), host.timeline);

        emit(&plans[0], &[b"a"]);
        let cut = due_at(3, &events, FIRST_DUE_NS);
        let basis = pass_basis(&host, &mut registry, store.as_mut(), &cut, 2);
        let history = digest_of(&basis, HISTORY, 0);
        let found = ok(store.nodes_by_digest(host.timeline, &[history]));
        assert!(matches!(found.as_slice(), [Some((_, None))]), "{name}");

        emit(&plans[0], &[]);
        emit(&plans[1], &[b"b"]);
        let latest = committed_events(store.as_ref(), host.timeline);
        let cut = due_at(4, &latest, BOTH_DUE_NS);
        let later = pass_basis(&host, &mut registry, store.as_mut(), &cut, 3);
        assert_eq!(count_owned_by(&later, HISTORY), 0, "{name}");
        let recorded = ok(store.factual_set_counts(host.timeline));
        let declared = declared_nodes(&basis).len() + declared_nodes(&later).len();
        assert_eq!(recorded.nodes, declared, "{name}");
    }
}

/// What a real-store refusal case offers: the authority grant of the pass and
/// the Ticks later than the registry declared that the store is offered it.
#[derive(Clone, Copy)]
struct Offer {
    grant: Hash,
    skew: u64,
}

/// Stage one Driver over an empty Timeline, offer its pass to the real store
/// with the authority grant and the Tick skew `offer` names, and require the
/// refusal `expected`: the staged Driver aborts and nothing commits.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_real_refusal(
    name: &str,
    store: &mut dyn Harness,
    host: &Host,
    offer: Offer,
    expected: &PipelineOutcomeV1,
) {
    let Offer { grant, skew } = offer;
    let log = Log::default();
    let mut registry = host.registry();
    register(&mut registry, driver("first", vec![b"a1"], &log));
    ok(stage(host, &mut registry, &all_at(0, &[])));
    let admission = ScheduledPassAdmissionV1 {
        authority_grant: grant,
        ..host.admission(store, 1)
    };
    let mut port = DigestRecordingPort::skewing(store, skew);
    let refused = rejection(registry.admit_scheduled_pass(&mut port, &admission));
    assert_eq!(refused, format!("{expected:?}"), "{name}");
    assert_eq!(port.bases.len(), 1, "{name}");
    assert_eq!(entries(&log), ["first:step@0", "first:abort"], "{name}");
    assert!(committed_events(store, host.timeline).is_empty(), "{name}");
}

/// ADR-064 R3.8.2 and R3.7.2: a refusal the real store gives is wrapped as a
/// not-admitted error; the staged Drivers abort, nothing commits, and the retry
/// that declares the right Tick under the fence's grant commits.
///
/// Two refusals are reachable through the real adapter here: an asserted Tick
/// that is not the next one (`InvalidDependencyDeclaration`) and edges that
/// name another authority grant than the persisted fence's
/// (`AdmissionConflict`). `DependencySetExhausted` needs a recorded set filled
/// to its bound of a million nodes; no public seam fills one, so that outcome
/// is covered in `pos-store` for each adapter
/// (`an_exhausted_dependency_set_refuses_both_ingresses_and_commits_nothing`
/// for `MemoryStore` and
/// `sqlite_an_exhausted_dependency_set_refuses_both_ingresses_and_commits_nothing`
/// for `SqliteStore`).
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_stores_own_refusal_aborts_the_staged_drivers() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let invalid = PipelineOutcomeV1::InvalidDependencyDeclaration;
        let late = Offer {
            grant: GRANT,
            skew: 4,
        };
        assert_real_refusal(name, store.as_mut(), &host, late, &invalid);
        let conflict = PipelineOutcomeV1::AdmissionConflict;
        let stale = Offer {
            grant: hash(2),
            skew: 0,
        };
        assert_real_refusal(name, store.as_mut(), &host, stale, &conflict);

        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        let retry = admit_pass_basis(&host, &mut registry, store.as_mut(), (0, 2));
        assert_eq!(retry.dependencies().tick(), 1, "{name}");
        assert_eq!(
            committed_events(store.as_ref(), host.timeline).len(),
            1,
            "{name}"
        );
    }
}

// ── Fold checkpoint nodes (ADR-064 Revision 4, Redmine #751) ──────────────
//
// The builder reads the fold cursor and window through the port, and the
// assembly records the fold part behind the snapshot node; the adapters write
// one fold-head row per scheduled Tick. The generic append refuses consent and
// geographic drafts (their own host seams check the payload and the subject),
// so the exclusion case reports plain Events under those types through
// `FoldProbePort`: the builder sees only the type, the payload hash and the
// node of a window Event, never its payload or entity.

const FOLD: &str = FactualHostOwnerV1::Fold.as_str();
const FOLD_HISTORY: &str = FactualHostOwnerV1::FoldHistory.as_str();
/// An Event type of an Ephemeral-declared output, appended outside the Tick
/// path: such an Event has no node.
const EPHEMERAL_TYPE: &str = "agent.basis.ephemeral";

/// One fold window read: its range and the `seq`s it returned.
type WindowRead = (u64, u64, Vec<u64>);

/// Port that commits through a real store, keeps every basis it is offered,
/// logs every fold window read, and reports the Events of `retype` under
/// another Event type.
struct FoldProbePort<'a> {
    inner: &'a mut dyn Harness,
    retype: BTreeMap<u64, &'static str>,
    reads: RefCell<Vec<WindowRead>>,
    bases: Vec<PipelineAdmissionBasisV1>,
}

impl<'a> FoldProbePort<'a> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn over(inner: &'a mut dyn Harness, retype: BTreeMap<u64, &'static str>) -> Self {
        Self {
            inner,
            retype,
            reads: RefCell::default(),
            bases: Vec::new(),
        }
    }
}

impl PipelineAdmissionPortV1 for FoldProbePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.bases.push(basis.clone());
        self.inner.admit_pipeline_batch(basis)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<pos_core::PipelineReceiptLookupV1, CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl FactualPrefixReadPortV1 for FoldProbePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<pos_core::FactualHeadV1, CoreError> {
        self.inner.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: TimelineId,
        seq: Seq,
    ) -> Result<pos_core::FactualCutV1, CoreError> {
        self.inner.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        self.inner.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        self.inner.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        self.inner.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(&self, timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        self.inner.factual_set_counts(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_cursor(&self, timeline: TimelineId) -> Result<Option<FactualFoldCursorV1>, CoreError> {
        self.inner.fold_cursor(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fold_window(
        &self,
        timeline: TimelineId,
        after: Seq,
        through: Seq,
    ) -> Result<FactualFoldWindowV1, CoreError> {
        let mut window = self.inner.fold_window(timeline, after, through)?;
        for event in &mut window.events {
            if let Some(kind) = self.retype.get(&event.seq.as_u64()) {
                event.event_type = Kind::new(*kind);
            }
        }
        let seqs = window.events.iter().map(|event| event.seq.as_u64());
        let read = (after.as_u64(), through.as_u64(), seqs.collect());
        self.reads.borrow_mut().push(read);
        Ok(window)
    }
}

/// Admit the staged pass through `port`, which must commit it, and return the
/// basis it was offered.
#[cfg_attr(coverage_nightly, coverage(off))]
fn admit_through(
    host: &Host,
    registry: &mut PluginRegistry,
    port: &mut FoldProbePort<'_>,
    key: u8,
) -> PipelineAdmissionBasisV1 {
    let admission = host.admission(&*port.inner, key);
    receipt(registry.admit_scheduled_pass(port, &admission));
    assert_eq!(port.bases.len(), 1);
    port.bases.remove(0)
}

/// The fold checkpoint nodes of a basis, in chain order.
#[cfg_attr(coverage_nightly, coverage(off))]
fn fold_nodes(basis: &PipelineAdmissionBasisV1) -> Vec<DependencyNodeRecordV1> {
    let nodes = declared_nodes(basis);
    let node = |index: &u32| nodes[ok(usize::try_from(*index))].clone();
    let checkpoints = &basis.dependencies().fold().checkpoints;
    checkpoints.iter().map(node).collect()
}

/// The artifact digests of the nodes the Event bindings of a basis name, in
/// ascending `seq`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn bound_digests(basis: &PipelineAdmissionBasisV1) -> Vec<Hash> {
    let nodes = declared_nodes(basis);
    let digest = |index: u32| {
        let at = ok(usize::try_from(index));
        nodes[at].coordinate().artifact_digest()
    };
    let bindings = basis.dependencies().event_nodes();
    bindings
        .iter()
        .map(|binding| digest(binding.node_index))
        .collect()
}

/// The sorted input digests of a node.
#[cfg_attr(coverage_nightly, coverage(off))]
fn sorted_inputs(node: &DependencyNodeRecordV1) -> Vec<Hash> {
    let mut inputs = node.input_digests().to_vec();
    inputs.sort();
    inputs
}

/// The Event types the exclusion case reports: Events 1 and 2 as revocations,
/// one for another subject than its entity and one malformed (the window
/// shows neither payload nor entity, so they differ only in the store), 3 as
/// a consent grant, 4 as a geographic Event, 5 as the consent-closed marker
/// and 7 as an Event of an Ephemeral-declared type appended outside the Tick
/// path. Event 6 keeps its type: its node is presentation only.
#[cfg_attr(coverage_nightly, coverage(off))]
fn exclusion_types() -> BTreeMap<u64, &'static str> {
    BTreeMap::from([
        (1, EVENT_TYPE_CONSENT_REVOKED_V1),
        (2, EVENT_TYPE_CONSENT_REVOKED_V1),
        (3, EVENT_TYPE_CONSENT_GRANTED_V1),
        (4, GEOGRAPHIC_EVENT_TYPE),
        (5, HOST_CONSENT_CLOSED_EVENT_TYPE),
        (7, EPHEMERAL_TYPE),
    ])
}

/// ADR-064 R4.1 (conformance test 3): every `consent.revoked.v1` Event is a
/// fold input, matched by its type alone, and so is an Event of an Ephemeral
/// type without a node, through an ingress node. A consent grant, a
/// geographic Event, the consent-closed marker and an Event bound to a
/// presentation-only node are not.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn fold_inputs_skip_consent_geographic_and_presentation_only_events_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut registry = host.registry();
        register_basis(&mut registry, driver);
        emit(&plan, &[b"a"]);
        append_events(store.as_mut(), &host, INPUT, 7);
        // Tick 1 owns the seven Events and binds Event 6 to a presentation-only node.
        let step_node = step_spec(OLD_OWNER, hash(0x51));
        let shown = event_spec(OLD_OWNER, 1, hash(0x52), PRESENTATION);
        let nodes = vec![seeded_node(1, &step_node), seeded_node(1, &shown)];
        let bound = vec![(Seq::from_u64(6), hash(0x52))];
        store.seed(host.timeline, &[seeded_tick(1, nodes, (1, 7), bound)]);

        ok(stage(&host, &mut registry, &all_at(7, &[])));
        let mut port = FoldProbePort::over(store.as_mut(), exclusion_types());
        let basis = admit_through(&host, &mut registry, &mut port, 1);
        let reads: Vec<WindowRead> = vec![(0, 7, (1..=7).collect())];
        assert_eq!(port.reads.take(), reads, "{name}");
        assert_eq!(bound_seqs(&basis), [1, 2, 7], "{name}");
        let folded = fold_nodes(&basis);
        assert_eq!(folded.len(), 1, "{name}");
        assert_eq!(count_owned_by(&basis, FOLD_HISTORY), 0, "{name}");
        let mut expected = bound_digests(&basis);
        expected.sort();
        assert_eq!(sorted_inputs(&folded[0]), expected, "{name}");
        let last = folded[0].coordinate().artifact_digest();
        let snapshot = node_of(&basis, OBSERVATION, 0);
        assert_eq!(snapshot.input_digests(), [last], "{name}");
    }
}

/// ADR-064 R4.3 (conformance test 5): an in-doubt attempt resubmits the same
/// basis, digest included, and gets the retained outcome; the fold-head row
/// its first submission wrote stays the only one.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_retried_fold_tick_resubmits_its_basis_and_writes_no_second_row() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        append_events(store.as_mut(), &host, INPUT, 2);
        let ancestry = root_ancestry(host.timeline);
        ok(registry.step_all_anchored(host.timeline, &ancestry, Seq::from_u64(2)));
        let lost = lose_outcome_basis(&host, &mut registry, store.as_mut(), 1);
        let written = ok(store.fold_cursor(host.timeline));
        let expected = FactualFoldCursorV1 {
            scanned_through: Seq::from_u64(2),
            head: Some(fold_nodes(&lost)[0].clone()),
        };
        assert_eq!(written, Some(expected), "{name}");

        let mut port = DigestRecordingPort::over(store.as_mut());
        let recovered = receipt(registry.recover_scheduled_pass(&mut port));
        let resubmitted = port.bases.remove(0);
        let digest = lost.dependencies().digest();
        assert_eq!(resubmitted.dependencies().digest(), digest, "{name}");
        assert_eq!(resubmitted, lost, "{name}");
        assert_eq!(recovered.committed_events().len(), 1, "{name}");
        assert_eq!(ok(store.fold_cursor(host.timeline)), written, "{name}");
        let events = committed_events(store.as_ref(), host.timeline);
        assert_eq!(events.len(), 3, "{name}");
    }
}

/// Tick 1 of the recovery case: a fresh registry whose one Driver emits one
/// draft, over two raw Events. The registry is dropped on return.
#[cfg_attr(coverage_nightly, coverage(off))]
fn first_recovery_tick(host: &Host, store: &mut dyn Harness) -> PipelineAdmissionBasisV1 {
    let log = Log::default();
    let (driver, plan) = BasisDriver::new(FIRST, &log);
    let mut registry = host.registry();
    register_basis(&mut registry, driver);
    emit(&plan, &[b"a"]);
    append_events(store, host, INPUT, 2);
    pass_basis(host, &mut registry, store, &all_at(2, &[]), 1)
}

/// Tick 2 of the recovery case: another fresh registry, over one more raw
/// Event. Tick 1's output is Event 3 and the raw Event is Event 4.
#[cfg_attr(coverage_nightly, coverage(off))]
fn second_recovery_tick(host: &Host, store: &mut dyn Harness) -> PipelineAdmissionBasisV1 {
    let log = Log::default();
    let (driver, plan) = BasisDriver::new(FIRST, &log);
    let mut registry = host.registry();
    register_basis(&mut registry, driver);
    emit(&plan, &[b"b"]);
    append_events(store, host, INPUT, 1);
    pass_basis(host, &mut registry, store, &all_at(4, &[]), 2)
}

/// The second Tick's fold node chains to the head the first Tick persisted
/// and starts at the persisted cursor: it covers Events 3 and 4 from `seq` 3.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_chained_to_the_persisted_head(
    name: &str,
    host: &Host,
    store: &dyn Harness,
    ticks: [&PipelineAdmissionBasisV1; 2],
) {
    let [first, second] = ticks;
    assert_eq!(second.dependencies().tick(), 2, "{name}");
    let head = fold_nodes(first)[0].coordinate().artifact_digest();
    let node = fold_nodes(second)[0].clone();
    assert!(node.input_digests().contains(&head), "{name}");
    let events = committed_events(store, host.timeline);
    let covered = event_refs(&events[2..4]);
    let (from, through) = (Seq::from_u64(3), Seq::from_u64(4));
    let content = factual_fold_checkpoint_content_digest(head, from, through, &covered);
    let key = host_key(2, FOLD, 0, FACTUAL_FOLD_SCHEMA_ID_V1);
    let expected = factual_artifact_digest(host.timeline, key, content);
    assert_eq!(node.coordinate().artifact_digest(), expected, "{name}");
}

/// ADR-064 R4.2 (conformance test 6): after the store and the registry are
/// dropped and reopened between two Ticks, the next fold node chains to the
/// persisted head and starts at the persisted cursor. The memory adapter
/// cannot be reopened, so there only the registry is dropped.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_reopened_store_and_registry_chain_the_next_fold_node_to_the_persisted_head() {
    let directory = ok(tempfile::tempdir());
    let path = directory.path().join("fold-recovery.db");
    let file = path.to_string_lossy().into_owned();
    let mut sqlite = ok(SqliteStore::open(&file));
    let host = Host::prepare(&mut sqlite, 1_000);
    let first = first_recovery_tick(&host, &mut sqlite);
    drop(sqlite);
    let mut reopened = ok(SqliteStore::open(&file));
    ok(reopened.bind_erasure_gate(Arc::clone(&host.gate)));
    ok(reopened.bind_authority_persistence(host.authority.persistence_binding()));
    let second = second_recovery_tick(&host, &mut reopened);
    assert_chained_to_the_persisted_head("sqlite", &host, &reopened, [&first, &second]);

    let mut memory = MemoryStore::new();
    let host = Host::prepare(&mut memory, 1_000);
    let first = first_recovery_tick(&host, &mut memory);
    let second = second_recovery_tick(&host, &mut memory);
    assert_chained_to_the_persisted_head("memory", &host, &memory, [&first, &second]);
}

/// ADR-064 R4.2 (conformance test 8): the parent's cut Tick committed two
/// outputs after its own anchor, which no parent Tick scanned, and the Fork
/// point leaves three unbound parent-tail Events after them. The child's
/// first fold node inputs the parent's head, the two output nodes through the
/// inherited bindings, and three new ingress nodes.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_forks_first_fold_node_chains_to_the_parents_head_below_its_cut_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        let log = Log::default();
        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut registry = host.registry();
        register_basis(&mut registry, driver);
        emit(&plan, &[b"a", b"b"]);
        append_events(store.as_mut(), &host, INPUT, 1);
        // Tick 1 scans Event 1; its outputs are Events 2 and 3.
        let parent = pass_basis(&host, &mut registry, store.as_mut(), &all_at(1, &[]), 1);
        append_events(store.as_mut(), &host, INPUT, 3);
        let fork = ok(store.fork(host.timeline, Seq::from_u64(6), "fold-child")).id();
        let child = host.on(fork);
        publish(store.as_mut(), fork, host.revisions, 1_000);

        let (driver, plan) = BasisDriver::new(FIRST, &log);
        let mut forked = child.registry();
        register_basis(&mut forked, driver);
        emit(&plan, &[b"c"]);
        let first = pass_basis(&child, &mut forked, store.as_mut(), &all_at(6, &[]), 2);
        assert_eq!(first.dependencies().tick(), 2, "{name}");
        assert_eq!(bound_seqs(&first), [4, 5, 6], "{name}");
        let owner = owner_at(&registry, 0);
        let mut expected = vec![
            digest_of(&parent, FOLD, 0),
            digest_of(&parent, &owner, 1),
            digest_of(&parent, &owner, 2),
        ];
        expected.extend(bound_digests(&first));
        expected.sort();
        assert_eq!(sorted_inputs(&fold_nodes(&first)[0]), expected, "{name}");
    }
}

/// The Events of the rollout case.
const ROLLOUT_EVENTS: usize = 70_000;

/// Three committed Ticks recorded before the builder read a fold window: one
/// step node each, and no fold-head row.
#[cfg_attr(coverage_nightly, coverage(off))]
fn pre_rollout_ticks() -> Vec<SeededTick> {
    let digests = [hash(0x61), hash(0x62), hash(0x63)];
    (1_u64..)
        .zip(digests)
        .map(|(tick, digest)| {
            let nodes = vec![seeded_node(tick, &step_spec(OLD_OWNER, digest))];
            seeded_tick(tick, nodes, (tick, tick), Vec::new())
        })
        .collect()
}

/// ADR-064 R4.4 (conformance test 9): the first Tick with a fold window on a
/// Timeline of three earlier Ticks without a fold-head row and 70,000 Events
/// starts at `Seq::ZERO`, reads only the newest 65,536 Events, keeps the
/// newest 16,384 fold inputs in five fold nodes, and collapses the older ones
/// into one fold-history node over their range.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_first_fold_tick_after_the_rollout_starts_at_zero_on_both_adapters() {
    for (name, mut store) in stores() {
        let host = Host::prepare(store.as_mut(), 1_000);
        append_events(store.as_mut(), &host, INPUT, ROLLOUT_EVENTS);
        store.seed(host.timeline, &pre_rollout_ticks());
        assert_eq!(ok(store.fold_cursor(host.timeline)), None, "{name}");
        let log = Log::default();
        let mut registry = host.registry();
        register(&mut registry, driver("first", vec![b"a1"], &log));
        let through = ok(u64::try_from(ROLLOUT_EVENTS));
        let ancestry = root_ancestry(host.timeline);
        let observed = Seq::from_u64(through);
        ok(registry.step_all_anchored(host.timeline, &ancestry, observed));
        let mut port = FoldProbePort::over(store.as_mut(), BTreeMap::new());
        let basis = admit_through(&host, &mut registry, &mut port, 1);

        let reads = port.reads.take();
        assert_eq!(reads.len(), 1, "{name}");
        assert_eq!((reads[0].0, reads[0].1), (0, through), "{name}");
        let scanned = reads[0].2.len();
        assert_eq!(scanned, MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1, "{name}");
        assert_eq!(basis.dependencies().tick(), 4, "{name}");
        assert_eq!(fold_nodes(&basis).len(), 5, "{name}");
        let kept = MAX_FACTUAL_FOLD_INPUT_EDGES_PER_TICK_V1;
        let collapsed = through - ok(u64::try_from(kept));
        let (from, to) = (Seq::from_u64(1), Seq::from_u64(collapsed));
        let content = factual_fold_history_content_digest(from, to);
        let key = host_key(4, FOLD_HISTORY, 0, FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1);
        let expected = factual_artifact_digest(host.timeline, key, content);
        assert_eq!(digest_of(&basis, FOLD_HISTORY, 0), expected, "{name}");
        let bound = bound_seqs(&basis);
        assert_eq!(bound.len(), kept, "{name}");
        assert_eq!(bound.first(), Some(&(collapsed + 1)), "{name}");
    }
}
