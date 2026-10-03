//! ADR-021 scheduled AI Driver passes through atomic host admission (#318).
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pos_core::{
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AuthorityErrorV1, AuthorityGranteeV1,
    AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, Capability,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, ConsentAuthority, ConsentGrantedV1,
    ConsentRevokedV1, CoreError, DelegateClassV1, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, EventStore, Hash, Kind, PersistedAuthorityV1, PipelineAdmissionBasisV1,
    PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineCommitReceiptV1, PipelineContractErrorV1, PipelineEvidenceRefV1,
    PipelineOutcomeV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, Plugin,
    PluginId, PrincipalRefV1, Reducer, Seq, SeqRange, State, TimelineId, DELEGATE_ACTION_V1,
};
use pos_runtime::{
    Driver, LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, ProjectionKey,
    RuntimeError, ScheduledAdmissionStoreV1, ScheduledDriverBindingV1, ScheduledPassAdmissionV1,
    StepOutput,
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

trait Harness:
    ScheduledAdmissionStoreV1
    + EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
{
}

impl<T: ScheduledAdmissionStoreV1> Harness for T {}

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
            hash(1),
            revisions,
            None,
            budget,
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
            &ok(store.load_authority(hash(1))),
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
                grant_id: hash(1),
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

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::from_u64(4)));
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
        ok(registry.step_all_anchored(unfenced.timeline, &root_ancestry(unfenced.timeline), Seq::ZERO));
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

/// Port that commits through the real store and then loses the outcome.
struct LostOutcomePort<'a> {
    inner: &'a mut dyn Harness,
}

impl PipelineAdmissionPortV1 for LostOutcomePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
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

#[cfg_attr(coverage_nightly, coverage(off))]
fn lose_outcome(host: &Host, registry: &mut PluginRegistry, store: &mut dyn Harness, key: u8) {
    let admission = host.admission(store, key);
    let lost =
        err(registry.admit_scheduled_pass(&mut LostOutcomePort { inner: store }, &admission));
    assert!(matches!(
        lost,
        RuntimeError::Store(CoreError::StorageOutcomeUnknown(_))
    ));
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
        lose_outcome(&host, &mut registry, store.as_mut(), 1);
        assert!(matches!(
            registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::from_u64(2)),
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

        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::from_u64(2)));
        lose_outcome(&host, &mut registry, store.as_mut(), 2);
        registry.abort_step();
        ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::from_u64(4)));
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

    ok(registry.tick_cadenced_anchored(host.timeline, &root_ancestry(host.timeline), 100, Seq::ZERO));
    publish(&mut store, host.timeline, stale_consent(host.revisions), 10);
    let stale = err(host.admit(&mut registry, &mut store, 1));
    assert!(stale.to_string().ends_with("AdmissionConflict"), "{stale}");
    publish(&mut store, host.timeline, host.revisions, 10);

    let due = ok(registry.tick_cadenced_anchored(host.timeline, &root_ancestry(host.timeline), 100, Seq::ZERO));
    assert_eq!(due.len(), 1, "an aborted pass must not advance cadence");
    assert_eq!(
        receipt(host.admit(&mut registry, &mut store, 2))
            .committed_events()
            .len(),
        1
    );

    let idle = ok(registry.tick_cadenced_anchored(host.timeline, &root_ancestry(host.timeline), 105, Seq::from_u64(1)));
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
        ok(registry.step_all_anchored(nested.timeline, &root_ancestry(nested.timeline), Seq::from_u64(3)));
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
        ok(registry.step_all_anchored_protected(host.timeline, &root_ancestry(host.timeline), observed, token.clone(), 1, &[]))
    };

    assert_eq!(stage(&mut registry).len(), 1);
    let admission = host.admission(&store, 1);
    let first = receipt(registry.admit_scheduled_pass(&mut store, &admission));
    stage(&mut registry);
    let retried = receipt(registry.admit_scheduled_pass(&mut store, &admission));
    assert_eq!(
        retried, first,
        "an exact retry recovers the original receipt"
    );

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
    assert_eq!(count(&log, ":commit"), 2);
    assert_eq!(count(&log, ":abort"), 2);
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

        let error = err(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO));
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

/// Port that records each offered snapshot digest and commits through the
/// real store.
struct DigestRecordingPort<'a> {
    inner: &'a mut dyn Harness,
    digests: Vec<Hash>,
}

impl PipelineAdmissionPortV1 for DigestRecordingPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.digests
            .push(basis.attempt().observation().snapshot_digest());
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

/// Admit the staged pass and return the snapshot digest it bound.
#[cfg_attr(coverage_nightly, coverage(off))]
fn admit_recording_digest(
    host: &Host,
    registry: &mut PluginRegistry,
    store: &mut dyn Harness,
    key: u8,
) -> Hash {
    let admission = host.admission(store, key);
    let mut port = DigestRecordingPort {
        inner: store,
        digests: Vec::new(),
    };
    receipt(registry.admit_scheduled_pass(&mut port, &admission));
    assert_eq!(port.digests.len(), 1);
    port.digests[0]
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
        let digest = admit_recording_digest(&host, &mut registry, store.as_mut(), 1);
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
        let refused = err(registry.step_all_anchored_protected(host.timeline, &root_ancestry(host.timeline), head, token, 1, &[]));
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
            ok(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), observed)).len(),
            1,
            "{name}"
        );
        assert_eq!(entries(&log), ["blind:none,none"], "{name}");
        let digest = admit_recording_digest(&host, &mut registry, store.as_mut(), 1);
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
        let refused = err(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), head));
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
            err(registry.step_all_anchored(host.timeline, &root_ancestry(host.timeline), Seq::ZERO)).to_string(),
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
            err(registry.tick_cadenced_anchored(host.timeline, &root_ancestry(host.timeline), 0, head)),
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
