//! ADR-021 scheduled AI Driver passes through atomic host admission (#318).
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pos_core::{
    pipeline_authority_revision_v1, pipeline_erasure_revision_v1, AppendDedupKey, AppendDedupScope,
    AppendIdentity, AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, Capability,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, ConsentAuthority, ConsentGrantedV1,
    ConsentRevokedV1, CoreError, DelegateClassV1, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, EventStore, Hash, Kind, PipelineAdmissionBasisV1,
    PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineCommitReceiptV1, PipelineContractErrorV1, PipelineEvidenceRefV1,
    PipelineOutcomeV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, Plugin,
    PluginId, PrincipalRefV1, Reducer, Seq, SeqRange, State, TimelineId, DELEGATE_ACTION_V1,
};
use pos_runtime::{
    schema::EventTypeSchema, Driver, ObservationView, PluginRegistry, ProjectionKey, RuntimeError,
    ScheduledPassAdmissionV1, StepOutput,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use ulid::Ulid;

const PROJECTION: &str = "agent.scheduled.projection";

type Admitted = Result<Option<PipelineCommitReceiptV1>, RuntimeError>;

trait Harness:
    EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
{
}

impl<T> Harness for T where
    T: EventStore
        + PipelineAdmissionPortV1
        + PipelineAdmissionFencePublisherV1
        + AuthorityPersistencePortV1
{
}

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
            actions: vec![DELEGATE_ACTION_V1.to_owned(), "act".to_owned()],
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
fn revisions(authority: Hash, erasure: Hash) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority,
            consent: hash(11),
            capability: hash(12),
            delegation: hash(13),
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
            pipeline_authority_revision_v1(&ok(store.load_authority(hash(1)))),
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
    ok(registry.register_generated(&plugin, None, Some(Box::new(driver))));
    registry.schemas.register(EventTypeSchema {
        event_type: Kind::new(plugin.event_type),
        description: "scheduled AI Driver output".to_owned(),
        json_schema: None,
    });
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

        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
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

        ok(registry.step_all_anchored(host.timeline, Seq::from_u64(4)));
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

        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
        publish(
            store.as_mut(),
            host.timeline,
            stale_consent(host.revisions),
            10,
        );
        let stale = host.admit(&mut registry, store.as_mut(), 1);
        assert_eq!(rejection(stale), "AdmissionConflict", "{name}");
        publish(store.as_mut(), host.timeline, host.revisions, 10);

        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
        let admission = host.admission(store.as_ref(), 2);
        human_event(store.as_mut(), host.timeline);
        let moved = registry.admit_scheduled_pass(store.as_mut(), &admission);
        assert_eq!(rejection(moved), "AdmissionConflict", "{name}");

        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
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

        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
        let exhausted = host.admit(&mut registry, store.as_mut(), 1);
        assert_eq!(rejection(exhausted), "ResourceExhausted", "{name}");

        let unfenced = host.on(ok(store.create_timeline("unfenced")).id());
        ok(registry.step_all_anchored(unfenced.timeline, Seq::ZERO));
        let missing = unfenced.admit(&mut registry, store.as_mut(), 2);
        assert_eq!(rejection(missing), "PolicyIndeterminate", "{name}");

        assert!(committed_events(store.as_ref(), host.timeline).is_empty());
        publish(store.as_mut(), host.timeline, host.revisions, 10);
        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
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
            .step_all_anchored(host.timeline, Seq::ZERO)
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
    ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
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

        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
        lose_outcome(&host, &mut registry, store.as_mut(), 1);
        assert!(matches!(
            registry.step_all_anchored(host.timeline, Seq::from_u64(2)),
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

        ok(registry.step_all_anchored(host.timeline, Seq::from_u64(2)));
        lose_outcome(&host, &mut registry, store.as_mut(), 2);
        registry.abort_step();
        ok(registry.step_all_anchored(host.timeline, Seq::from_u64(4)));
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
    ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
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

    ok(registry.tick_cadenced_anchored(host.timeline, 100, Seq::ZERO));
    publish(&mut store, host.timeline, stale_consent(host.revisions), 10);
    let stale = err(host.admit(&mut registry, &mut store, 1));
    assert!(stale.to_string().ends_with("AdmissionConflict"), "{stale}");
    publish(&mut store, host.timeline, host.revisions, 10);

    let due = ok(registry.tick_cadenced_anchored(host.timeline, 100, Seq::ZERO));
    assert_eq!(due.len(), 1, "an aborted pass must not advance cadence");
    assert_eq!(
        receipt(host.admit(&mut registry, &mut store, 2))
            .committed_events()
            .len(),
        1
    );

    let idle = ok(registry.tick_cadenced_anchored(host.timeline, 105, Seq::from_u64(1)));
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
        ok(registry.step_all_anchored(host.timeline, Seq::ZERO));
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
        ok(registry.step_all_anchored(nested.timeline, Seq::from_u64(3)));
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
        ok(registry.step_all_anchored_protected(host.timeline, observed, token.clone(), 1, &[]))
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
