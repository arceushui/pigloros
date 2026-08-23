use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, TimelineId},
    ConsentAuthority, ConsentError, ConsentGranted,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use std::fmt::Debug;

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
    registry.commit_step_at(Seq::from_u64(1));

    let wrong_timeline = TimelineId::new();
    let error =
        test_err(registry.step_all_anchored_protected(wrong_timeline, Seq::ZERO, token, 1, &[]));
    assert!(matches!(
        error,
        RuntimeError::Consent(ConsentError::NoConsent)
    ));
}
