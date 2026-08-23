use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, TimelineId},
    ConsentAuthority, ConsentCapabilityToken, ConsentError, ConsentGate, ConsentGranted,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
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
        _: &ConsentCapabilityToken,
        _: u64,
        _: u64,
    ) -> Result<(), ConsentError> {
        Ok(())
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
        Ok(())
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
