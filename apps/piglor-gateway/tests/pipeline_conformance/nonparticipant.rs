//! ADR-021 Revision 3 non-participant profile at the runtime seam (#480).

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, PoisonError,
};

use pos_core::{
    AppendDedupKey, AppendDedupScope, AppendIdentity, Capability, ConsentAuthority,
    ConsentCapabilityToken, ConsentRevokedV1, EntityId, ErasureContainmentGateV1, Event, Hash,
    Kind, PipelineAttemptIdV1, PipelineEvidenceRefV1, PipelineSecurityRevisionsDraftV1,
    PipelineSecurityRevisionsV1, Plugin, PluginId, Reducer, Seq, State, TimelineId,
};
use pos_runtime::{
    Driver, LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, ProjectionKey,
    RuntimeError, ScheduledAdmissionStoreV1, ScheduledPassAdmissionV1, StepOutput,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

use super::{
    harness::Capture,
    support::{
        draft, events, gated_registry, persona_token, stage, stores, FixturePlugin, RecordingPort,
        ScriptedDriver, TestOk,
    },
};

const PROJECTION: &str = "conformance.projection";

/// Counts the Events folded for each entity.
struct CountingReducer;

impl Reducer for CountingReducer {
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

/// A reducer-only Plugin that owns the observed Projection type.
struct ProjectionPlugin {
    id: PluginId,
}

impl Plugin for ProjectionPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "projection"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(PROJECTION)],
            has_reducer: true,
            ..Capability::default()
        }
    }
}

/// A Driver that records its anchor and which probed Projections it sees.
struct ObserverDriver {
    label: &'static str,
    event_type: &'static str,
    subscriptions: Vec<ProjectionKey>,
    probes: [ProjectionKey; 2],
    seen: Arc<Mutex<Vec<String>>>,
}

impl Driver for ObserverDriver {
    fn name(&self) -> &'static str {
        self.label
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    fn step(
        &mut self,
        _: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let anchor = observations
            .anchor()
            .map_or(u64::MAX, |anchor| anchor.observed_through().as_u64());
        let [first, second] = &self.probes;
        let line = format!(
            "{}@{anchor}:a={},b={}",
            self.label,
            observations.state_for(first).is_some(),
            observations.state_for(second).is_some()
        );
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
        Ok(StepOutput::new(vec![draft(
            EntityId::new(),
            self.event_type,
            b"observed",
        )]))
    }
}

/// Host admission inputs for a port that never commits.
fn admission(commit_head: Seq) -> ScheduledPassAdmissionV1 {
    let digest = |byte: u8| Hash::from_bytes([byte; 32]);
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
        commit_head,
        commit_now_secs: 0,
    }
}

fn fold(
    registry: &mut PluginRegistry,
    backend: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    subjects: &[EntityId],
) {
    let drafts: Vec<_> = subjects
        .iter()
        .map(|subject| draft(*subject, PROJECTION, b"projection"))
        .collect();
    let committed = backend.append(timeline, &drafts).test_ok();
    registry.fold_events(timeline, &committed);
}

/// Stage one public anchored pass and offer it to `port`.
fn offer(
    registry: &mut PluginRegistry,
    backend: &dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: &ConsentCapabilityToken,
    port: &mut RecordingPort,
) -> usize {
    let (head, drafts) = stage(registry, backend, timeline, Some(token)).test_ok();
    let _refused = registry.admit_scheduled_pass(port, &admission(head));
    drafts.len()
}

/// PCF-R3-007: every due Driver of a non-participant pass shares one base
/// cut and sees only its subscribed Projections, and the bound snapshot
/// digest changes exactly when the observed state changes.
#[must_use]
pub fn non_participant_pass_is_subscription_scoped() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("non-participant").test_ok().id();
        let (first, second) = (EntityId::new(), EntityId::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, timeline, first);
        let mut registry = gated_registry(Some(&authority));
        registry
            .register_generated(
                &ProjectionPlugin {
                    id: PluginId::new(),
                },
                Some(Box::new(CountingReducer)),
                None,
            )
            .test_ok();
        // Projection subscriptions are consent-gated: the token names the
        // first subject only, so only observer-a subscribes, and observer-b
        // probes the same Projections without a subscription.
        for (label, event_type, subscriptions) in [
            ("observer-a", "observer.a", vec![ProjectionKey::new(first)]),
            ("observer-b", "observer.b", Vec::new()),
        ] {
            registry
                .register_generated(
                    &FixturePlugin::new(label, &[event_type], true),
                    None,
                    Some(Box::new(ObserverDriver {
                        label,
                        event_type,
                        subscriptions,
                        probes: [ProjectionKey::new(first), ProjectionKey::new(second)],
                        seen: Arc::clone(&seen),
                    })),
                )
                .test_ok();
        }
        fold(&mut registry, backend.as_mut(), timeline, &[first, second]);
        let mut port = RecordingPort::default();
        let staged = offer(&mut registry, backend.as_ref(), timeline, &token, &mut port);
        let observers = seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .join("|");
        fold(&mut registry, backend.as_mut(), timeline, &[first]);
        offer(&mut registry, backend.as_ref(), timeline, &token, &mut port);
        offer(&mut registry, backend.as_ref(), timeline, &token, &mut port);
        let digests: Vec<Hash> = port
            .offered
            .iter()
            .map(|basis| basis.attempt().observation().snapshot_digest())
            .collect();
        capture.record(store, "staged", staged);
        capture.record(store, "observers", observers);
        capture.record(store, "offered", digests.len());
        capture.record(
            store,
            "digest.changes-with-state",
            digests.first() != digests.get(1),
        );
        capture.record(
            store,
            "digest.stable-without-change",
            digests.get(1) == digests.get(2),
        );
    }
    capture
}

/// Two scheduled Drivers for one subject, with their abort counters.
fn late_registry(
    mut registry: PluginRegistry,
    subject: EntityId,
) -> (PluginRegistry, [Arc<AtomicUsize>; 2]) {
    let mut aborts = Vec::new();
    for (label, event_type) in [("late-a", "late.a"), ("late-b", "late.b")] {
        let driver = ScriptedDriver::new(label, vec![draft(subject, event_type, b"late")]);
        aborts.push(Arc::clone(&driver.aborts));
        registry
            .register_generated(
                &FixturePlugin::new(label, &[event_type], true),
                None,
                Some(Box::new(driver)),
            )
            .test_ok();
    }
    let second = aborts.pop().test_ok();
    let first = aborts.pop().test_ok();
    (registry, [first, second])
}

fn aborted(aborts: &[Arc<AtomicUsize>; 2]) -> String {
    format!(
        "{},{}",
        aborts[0].load(Ordering::SeqCst),
        aborts[1].load(Ordering::SeqCst)
    )
}

/// PCF-R3-008: a consent revocation or an erasure freeze that lands after a
/// non-participant pass was staged aborts every Driver of the pass and
/// commits nothing.
#[must_use]
pub fn late_revocation_or_freeze_aborts_the_pass() -> Capture {
    let mut capture = Capture::default();
    let host = LocalScheduledAdmissionHostV1::shared().test_ok();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("late-revocation").test_ok().id();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = persona_token(&authority, timeline, subject);
        let (mut registry, aborts) = late_registry(gated_registry(Some(&authority)), subject);
        // A committed Event puts the Logical Head at 1, so a revocation
        // fenced at that head invalidates the token at the commit head.
        backend
            .append(timeline, &[draft(subject, "late.seed", b"seed")])
            .test_ok();
        let revisions = host
            .observe(&registry, backend.as_mut(), timeline)
            .test_ok();
        let (head, staged) =
            stage(&mut registry, backend.as_ref(), timeline, Some(&token)).test_ok();
        authority
            .record_revocation_on_timeline(
                timeline,
                &ConsentRevokedV1 {
                    subject_id: subject,
                    grantee_id: token.grantee_id(),
                    grant_seq: token.grant_seq(),
                    fence_seq: head.as_u64(),
                },
            )
            .test_ok();
        let revoked = host.admit(&mut registry, backend.as_mut(), revisions, head, 0);
        capture.record(store, "consent.staged", staged.len());
        capture.record(
            store,
            "consent.refused",
            matches!(revoked, Err(RuntimeError::Consent(_))),
        );
        capture.record(store, "consent.aborted", aborted(&aborts));
        capture.record(
            store,
            "consent.committed",
            events(backend.as_ref(), timeline).len(),
        );
    }
    let fenced: Vec<(&str, Box<dyn ScheduledAdmissionStoreV1>)> = vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ];
    for (store, mut backend) in fenced {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        backend.bind_erasure_gate(Arc::clone(&gate)).test_ok();
        let timeline = backend.create_timeline("late-freeze").test_ok().id();
        let (mut registry, aborts) = late_registry(
            PluginRegistry::new().with_erasure_gate(gate.clone()),
            EntityId::new(),
        );
        let revisions = host
            .observe(&registry, backend.as_mut(), timeline)
            .test_ok();
        let (head, staged) = stage(&mut registry, backend.as_ref(), timeline, None).test_ok();
        gate.freeze_timeline_for_test(timeline);
        let frozen = host.admit(&mut registry, backend.as_mut(), revisions, head, 0);
        capture.record(store, "erasure.staged", staged.len());
        capture.record(store, "erasure.refused", frozen.is_err());
        capture.record(store, "erasure.aborted", aborted(&aborts));
    }
    capture
}
