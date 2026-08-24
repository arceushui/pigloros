#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
    Capability, ConsentAuthority, ConsentCapabilityToken, ConsentError, ConsentGate,
    ConsentGranted, Plugin, PluginId, Reducer, State,
};
use pos_runtime::{
    Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput, TimelineHistorySegment,
};
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    time::Duration,
};

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected success-path error: {error:?}"
        )))
    })
}

fn test_err<T: Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => {
            std::panic::resume_unwind(Box::new(format!("unexpected error-path value: {value:?}")))
        }
        Err(error) => error,
    }
}

struct ProtectedEventDriver {
    entity: EntityId,
}

impl Driver for ProtectedEventDriver {
    fn name(&self) -> &'static str {
        "protected-event"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new("protected.event"),
            CanonicalBytes::from_static(b"protected"),
        )]))
    }
}

struct MismatchedSubjectDriver {
    entity: EntityId,
}

struct MismatchedRetentionDriver {
    entity: EntityId,
}

impl Driver for MismatchedRetentionDriver {
    fn name(&self) -> &'static str {
        "mismatched-retention-subject"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new("retention.extend.v1"),
            CanonicalBytes::from_static(b"protected"),
        )]))
    }
}

impl Driver for MismatchedSubjectDriver {
    fn name(&self) -> &'static str {
        "mismatched-subject"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new("geo.position.v1"),
            CanonicalBytes::from_static(b"protected"),
        )]))
    }
}

struct SubscribedDriver {
    key: pos_runtime::ProjectionKey,
}

struct EmptyDriver;

impl Driver for EmptyDriver {
    fn name(&self) -> &'static str {
        "empty-public-seam"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}

struct ProjectionPlugin {
    id: PluginId,
}

impl Plugin for ProjectionPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "projection-public-seam"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("projection.public")],
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: true,
        }
    }
}

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
        state.set("count", serde_json::Value::Number((count + 1).into()));
    }
}

fn projection_event(entity: EntityId, event_type: &str, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(b"projection"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

struct RestoreTrackingDriver {
    aborts: Arc<Mutex<u32>>,
    commits: Arc<Mutex<u32>>,
}

impl Driver for RestoreTrackingDriver {
    fn name(&self) -> &'static str {
        "restore-tracking"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn commit_restore_from_history(&mut self) {
        *self
            .commits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
    }

    fn abort_restore_from_history(&mut self) {
        *self
            .aborts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
    }
}

struct RestoreFailureDriver {
    aborts: Arc<Mutex<u32>>,
}

impl Driver for RestoreFailureDriver {
    fn name(&self) -> &'static str {
        "restore-failure"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn stage_restore_from_history(
        &mut self,
        _: &pos_runtime::DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::InvalidRecoveryEvidence {
            reason: "public restore failure",
        })
    }

    fn abort_restore_from_history(&mut self) {
        *self
            .aborts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
    }
}

struct PanickingRestoreDriver;

impl Driver for PanickingRestoreDriver {
    fn name(&self) -> &'static str {
        "restore-panic"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn commit_restore_from_history(&mut self) {
        std::panic::resume_unwind(Box::new("public restore commit panic"));
    }
}

struct OverflowCadencedDriver;

impl Driver for OverflowCadencedDriver {
    fn name(&self) -> &'static str {
        "overflow-cadence"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_nanos(1)
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}

struct CadencedDraftDriver {
    entity: EntityId,
}

impl Driver for CadencedDraftDriver {
    fn name(&self) -> &'static str {
        "cadenced-draft"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            self.entity,
            Kind::new("runtime.public.cadence"),
            CanonicalBytes::from_static(b"cadence"),
        )]))
    }
}

impl Driver for SubscribedDriver {
    fn name(&self) -> &'static str {
        "subscribed"
    }

    fn subscriptions(&self) -> &[pos_runtime::ProjectionKey] {
        std::slice::from_ref(&self.key)
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}

fn grant(subject_id: EntityId) -> ConsentGranted {
    ConsentGranted {
        subject_id,
        grantee_id: EntityId::new(),
        purpose: "runtime-public-seam".to_owned(),
        modalities: pos_core::MODALITY_LOCATION,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: 1,
    }
}

#[test]
fn protected_public_seam_checks_timeline_and_rechecks_at_commit_head() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let grant = grant(subject);
    let token = authority.record_grant_on_timeline(timeline, &grant);
    let mut registry = PluginRegistry::new().with_consent_authority(authority.clone());
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));

    let drafts =
        test_ok(registry.step_all_anchored_protected(timeline, Seq::ZERO, token.clone(), 1, &[]));
    assert_eq!(drafts.len(), 1);

    test_ok(authority.record_revocation_on_timeline(
        timeline,
        &pos_core::ConsentRevoked {
            subject_id: subject,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 1,
        },
    ));
    let error = test_err(registry.commit_step_at(Seq::from_u64(1), 2));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::Revoked)
    ));

    let wrong_timeline = TimelineId::new();
    let error =
        test_err(registry.step_all_anchored_protected(wrong_timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

#[test]
fn protected_public_seam_fails_closed_without_a_bound_gate() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));

    let error = test_err(registry.step_all_anchored_protected(timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

struct MismatchedDraftGate {
    returned: ConsentCapabilityToken,
}

impl ConsentGate for MismatchedDraftGate {
    fn check_consent(
        &self,
        _: TimelineId,
        _: EntityId,
        _: &Kind,
        _: u64,
        _: u64,
    ) -> Result<ConsentCapabilityToken, ConsentError> {
        Ok(self.returned.clone())
    }

    fn validate_token(
        &self,
        _: TimelineId,
        token: &ConsentCapabilityToken,
        _: u64,
        _: u64,
    ) -> Result<(), ConsentError> {
        if token == &self.returned {
            Ok(())
        } else {
            Err(ConsentError::NoConsent)
        }
    }
}

#[test]
fn protected_public_seam_rejects_a_gate_that_returns_a_different_token() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let issuing_authority = ConsentAuthority::new();
    let token = issuing_authority.record_grant_on_timeline(timeline, &grant(subject));
    let other_authority = ConsentAuthority::new();
    let returned = other_authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry =
        PluginRegistry::new().with_consent_gate(Arc::new(MismatchedDraftGate { returned }));
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));

    let error = test_err(registry.step_all_anchored_protected(timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

#[test]
fn protected_public_seam_rejects_a_draft_for_a_different_subject() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let other_subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry = PluginRegistry::new().with_consent_authority(authority);
    registry.register_driver(Box::new(MismatchedSubjectDriver {
        entity: other_subject,
    }));

    let error = test_err(registry.step_all_anchored_protected(timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

#[test]
fn protected_public_seam_rejects_a_retention_draft_for_a_different_subject() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry = PluginRegistry::new().with_consent_authority(authority);
    registry.register_driver(Box::new(MismatchedRetentionDriver {
        entity: EntityId::new(),
    }));

    let error = test_err(registry.step_all_anchored_protected(timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

struct RejectingDraftGate;

impl ConsentGate for RejectingDraftGate {
    fn check_consent(
        &self,
        _: TimelineId,
        _: EntityId,
        _: &Kind,
        _: u64,
        _: u64,
    ) -> Result<ConsentCapabilityToken, ConsentError> {
        Err(ConsentError::NoConsent)
    }

    fn validate_token(
        &self,
        _: TimelineId,
        _: &ConsentCapabilityToken,
        _: u64,
        _: u64,
    ) -> Result<(), ConsentError> {
        Err(ConsentError::NoConsent)
    }
}

#[test]
fn ordinary_public_seam_routes_every_draft_through_the_bound_gate() {
    let timeline = TimelineId::new();
    let mut registry = PluginRegistry::new().with_consent_gate(Arc::new(RejectingDraftGate));
    registry.register_driver(Box::new(ProtectedEventDriver {
        entity: EntityId::new(),
    }));

    let error = test_err(registry.step_all_anchored(timeline, Seq::ZERO));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

struct CommitFenceGate {
    token: ConsentCapabilityToken,
    observed_now_secs: Arc<Mutex<Vec<u64>>>,
}

impl ConsentGate for CommitFenceGate {
    fn check_consent(
        &self,
        _: TimelineId,
        _: EntityId,
        _: &Kind,
        _: u64,
        _: u64,
    ) -> Result<ConsentCapabilityToken, ConsentError> {
        Ok(self.token.clone())
    }

    fn validate_token(
        &self,
        _: TimelineId,
        _: &ConsentCapabilityToken,
        _: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        self.observed_now_secs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(now_secs);
        if now_secs >= 2 {
            Err(ConsentError::Expired)
        } else {
            Ok(())
        }
    }
}

#[test]
fn protected_public_seam_revalidates_at_the_fresh_commit_fence_time() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let observed_now_secs = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(CommitFenceGate {
        token: token.clone(),
        observed_now_secs: observed_now_secs.clone(),
    });
    let mut registry = PluginRegistry::new().with_consent_gate(gate);
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));

    let drafts = test_ok(registry.step_all_anchored_protected(timeline, Seq::ZERO, token, 1, &[]));
    assert_eq!(drafts.len(), 1);
    let error = test_err(registry.commit_step_at(Seq::ZERO, 2));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::Expired)
    ));

    assert_eq!(
        *observed_now_secs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![1, 2]
    );
}

#[test]
fn protected_append_fence_rejects_before_store_append() {
    use pos_store::{open_store, StoreConfig};

    let mut store = test_ok(open_store(StoreConfig::Memory));
    let timeline = test_ok(store.create_timeline("protected-fence"));
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline.id(), &grant(subject));
    let observed_now_secs = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(CommitFenceGate {
        token: token.clone(),
        observed_now_secs,
    });
    let mut registry = PluginRegistry::new().with_consent_gate(gate);
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));
    let drafts =
        test_ok(registry.step_all_anchored_protected(timeline.id(), Seq::ZERO, token, 1, &[]));

    let error = test_err(registry.append_and_commit_step_at(store.as_mut(), Seq::ZERO, 2, &drafts));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::Expired)
    ));
    assert_eq!(
        test_ok(store.logical_head(timeline.id())),
        Seq::ZERO,
        "a rejected consent fence must not append drafts"
    );
}

#[test]
fn append_fence_revalidates_caller_supplied_drafts() {
    use pos_store::{open_store, StoreConfig};

    let mut store = test_ok(open_store(StoreConfig::Memory));
    let timeline = test_ok(store.create_timeline("protected-draft-replacement"));
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline.id(), &grant(subject));
    let mut registry = PluginRegistry::new().with_consent_authority(authority);
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));
    let _staged =
        test_ok(registry.step_all_anchored_protected(timeline.id(), Seq::ZERO, token, 1, &[]));
    let replacement = vec![EventDraft::new(
        subject,
        Kind::new("consent.granted.v1"),
        CanonicalBytes::from_static(b"forged"),
    )];

    let error =
        test_err(registry.append_and_commit_step_at(store.as_mut(), Seq::ZERO, 1, &replacement));
    assert!(matches!(
        error,
        RuntimeError::ConsentDraft { ref event_type } if event_type == "consent.granted.v1"
    ));
    assert_eq!(test_ok(store.logical_head(timeline.id())), Seq::ZERO);
}

#[test]
fn public_append_fence_revalidates_caller_supplied_drafts() {
    use pos_store::{open_store, StoreConfig};

    let mut store = test_ok(open_store(StoreConfig::Memory));
    let timeline = test_ok(store.create_timeline("public-draft-replacement"));
    let subject = EntityId::new();
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(EmptyDriver));
    let _staged = test_ok(registry.step_all_anchored(timeline.id(), Seq::ZERO));
    let replacement = vec![EventDraft::new(
        subject,
        Kind::new("consent.granted.v1"),
        CanonicalBytes::from_static(b"forged"),
    )];

    let error =
        test_err(registry.append_and_commit_step_at(store.as_mut(), Seq::ZERO, 1, &replacement));
    assert!(matches!(
        error,
        RuntimeError::ConsentDraft { ref event_type } if event_type == "consent.granted.v1"
    ));
    assert_eq!(test_ok(store.logical_head(timeline.id())), Seq::ZERO);
}

#[test]
fn protected_public_seam_aborts_when_the_gate_rejects_a_draft() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry = PluginRegistry::new().with_consent_gate(Arc::new(RejectingDraftGate));
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));

    let error = test_err(registry.step_all_anchored_protected(timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn ordinary_step_and_tick_enforce_projection_and_draft_boundaries() {
    use pos_store::{open_store, StoreConfig};

    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));

    let mut step_with_projection = PluginRegistry::new().with_consent_authority(authority.clone());
    step_with_projection.register_driver(Box::new(SubscribedDriver {
        key: pos_runtime::ProjectionKey::new(subject),
    }));
    assert!(matches!(
        test_err(step_with_projection.step_all(timeline)),
        RuntimeError::Consent(ConsentError::NoConsent)
    ));

    let mut tick_with_projection = PluginRegistry::new().with_consent_authority(authority.clone());
    tick_with_projection.register_driver(Box::new(SubscribedDriver {
        key: pos_runtime::ProjectionKey::new(subject),
    }));
    assert!(matches!(
        test_err(tick_with_projection.tick_cadenced(timeline, 0)),
        RuntimeError::Consent(ConsentError::NoConsent)
    ));

    let mut protected_with_projection =
        PluginRegistry::new().with_consent_authority(authority.clone());
    protected_with_projection.register_driver(Box::new(SubscribedDriver {
        key: pos_runtime::ProjectionKey::new(subject),
    }));
    assert!(protected_with_projection
        .step_all_anchored_protected(timeline, Seq::ZERO, token, 0, &[])
        .is_ok());

    let mut ordinary_step = PluginRegistry::new().with_consent_authority(authority.clone());
    ordinary_step.register_driver(Box::new(MismatchedSubjectDriver { entity: subject }));
    assert!(matches!(
        test_err(ordinary_step.step_all(timeline)),
        RuntimeError::Consent(ConsentError::NoConsent)
    ));

    let mut ordinary_tick = PluginRegistry::new().with_consent_authority(authority);
    ordinary_tick.register_driver(Box::new(MismatchedSubjectDriver { entity: subject }));
    assert!(matches!(
        test_err(ordinary_tick.tick_cadenced(timeline, 0)),
        RuntimeError::Consent(ConsentError::NoConsent)
    ));

    let mut store = test_ok(open_store(StoreConfig::Memory));
    let mut empty = PluginRegistry::new();
    assert!(matches!(
        test_err(empty.append_and_commit_step_at(store.as_mut(), Seq::ZERO, 0, &[],)),
        RuntimeError::PendingDriverStep
    ));
}

#[test]
fn protected_cadenced_public_seam_stages_and_commits() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry = PluginRegistry::new().with_consent_authority(authority);
    registry.register_driver(Box::new(ProtectedEventDriver { entity: subject }));

    let drafts =
        test_ok(registry.tick_cadenced_anchored_protected(timeline, 0, Seq::ZERO, token, 1, &[]));
    assert_eq!(drafts.len(), 1);
    test_ok(registry.commit_step_at(Seq::ZERO, 1));
}

#[test]
fn public_registry_recovery_and_unprotected_transactions_run() {
    let timeline = TimelineId::new();
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(EmptyDriver));

    let event = Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new("public.recovery.v1"),
        payload: CanonicalBytes::from_static(b"recovery"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(1),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: Hash::from_bytes([0; 32]),
    };
    test_ok(registry.restore_driver_state(
        &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
        &[event],
    ));
    assert!(test_ok(registry.step_all_anchored(timeline, Seq::ZERO)).is_empty());
    test_ok(registry.commit_step_at(Seq::ZERO, 0));
    assert!(test_ok(registry.tick_cadenced(timeline, 0)).is_empty());

    let mut projection_registry = PluginRegistry::new();
    projection_registry.register_driver(Box::new(SubscribedDriver {
        key: pos_runtime::ProjectionKey::new(EntityId::new()),
    }));
    assert!(matches!(
        test_err(projection_registry.step_all_anchored(timeline, Seq::ZERO)),
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}

#[test]
fn public_cadence_executes_driver_output_through_the_consent_boundary() {
    let timeline = TimelineId::new();
    let entity = EntityId::new();
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(CadencedDraftDriver { entity }));

    let drafts = test_ok(registry.tick_cadenced(timeline, 0));
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].entity, entity);
    assert_eq!(drafts[0].event_type.as_str(), "runtime.public.cadence");

    let drafts = test_ok(registry.tick_cadenced(timeline, 1));
    assert!(drafts.is_empty());
}

#[test]
fn public_registry_gate_projection_and_control_marker_seams_are_distinguishable() {
    let unbound = PluginRegistry::new().without_consent_gate();
    assert!(unbound.clone_consent_gate().is_none());
    let authority = ConsentAuthority::new();
    let protected_token =
        authority.record_grant_on_timeline(TimelineId::new(), &grant(EntityId::new()));
    assert!(matches!(
        test_err(unbound.step_all_anchored_protected(
            TimelineId::new(),
            Seq::ZERO,
            protected_token,
            1,
            &[],
        )),
        RuntimeError::ConsentOperationUnavailable
    ));

    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let unrelated = EntityId::new();
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut registry = PluginRegistry::new().with_consent_authority(authority);
    test_ok(registry.register(
        &ProjectionPlugin {
            id: PluginId::new(),
        },
        Some(Box::new(CountingReducer)),
        None,
    ));

    registry.fold_events(&[
        projection_event(subject, "projection.public", 1),
        projection_event(subject, "projection.public", 2),
        projection_event(unrelated, "projection.public", 3),
        projection_event(subject, pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE, 4),
    ]);
    let projections = test_ok(registry.into_authorized_projections(
        timeline,
        Seq::from_u64(4),
        1,
        Some(&token),
        None,
    ));
    assert_eq!(
        projections
            .state_for_reducer("projection-public-seam", &subject)
            .and_then(|state| state.get("count"))
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert!(projections
        .state_for_reducer("projection-public-seam", &unrelated)
        .is_none());
}

#[test]
fn public_restore_failure_aborts_prior_driver_and_reports_commit_panic() {
    let timeline = TimelineId::new();
    let tracking_aborts = Arc::new(Mutex::new(0));
    let tracking_commits = Arc::new(Mutex::new(0));
    let failing_aborts = Arc::new(Mutex::new(0));
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(RestoreTrackingDriver {
        aborts: Arc::clone(&tracking_aborts),
        commits: Arc::clone(&tracking_commits),
    }));
    registry.register_driver(Box::new(RestoreFailureDriver {
        aborts: Arc::clone(&failing_aborts),
    }));
    test_ok(registry.step_all(timeline));

    assert!(matches!(
        registry.restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[]),
        Err(RuntimeError::InvalidRecoveryEvidence { .. })
    ));
    assert_eq!(
        *tracking_aborts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        1
    );
    assert_eq!(
        *failing_aborts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        1
    );
    assert_eq!(
        *tracking_commits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        0
    );

    let mut panicking = PluginRegistry::new();
    panicking.register_driver(Box::new(PanickingRestoreDriver));
    test_ok(panicking.step_all(timeline));
    assert!(matches!(
        panicking.restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[]),
        Err(RuntimeError::DriverRestorePanicked { .. })
    ));
}

#[test]
fn public_cadence_and_empty_registry_cover_ready_and_overflow_boundaries() {
    let timeline = TimelineId::new();
    assert!(test_ok(PluginRegistry::new().step_all(timeline)).is_empty());

    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(OverflowCadencedDriver));
    assert!(test_ok(registry.tick_cadenced(timeline, u128::MAX)).is_empty());
    assert!(matches!(
        test_err(registry.tick_cadenced(timeline, u128::MAX)),
        RuntimeError::CadenceOverflow { .. }
    ));
}
