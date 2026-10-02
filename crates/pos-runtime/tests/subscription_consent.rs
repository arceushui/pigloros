//! Subscribed committed Events are consent-gated like every other
//! non-participant observation (ADR-039; ADR-021 Revision 3 Decision 1).
//! ADR-024 Revision 1 Decision 5 relies on this for Eval's subscriptions to
//! Persona's prediction sources.

use std::sync::{Arc, Mutex, PoisonError};

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
    ConsentAuthority, ConsentCapabilityToken, ConsentGrantedV1, ErasureContainmentGateV1,
    MODALITY_PERSONA,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected subscription fixture error: {error:?}"
            )))
        })
    }
}

const PERSONA: &str = "persona.prediction";
const FORK: &str = "timeline.fork.requested";
const RETENTION: &str = "retention.extended";
const ORDINARY: &str = "ordinary.event";

struct RecordingDriver {
    subscriptions: Vec<Kind>,
    seen: Arc<Mutex<Vec<(String, EntityId)>>>,
}

impl Driver for RecordingDriver {
    fn name(&self) -> &'static str {
        "subscription-recorder"
    }

    fn event_subscriptions(&self) -> &[Kind] {
        &self.subscriptions
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = observations
            .events()
            .iter()
            .map(|event| (event.event_type.as_str().to_owned(), event.entity))
            .collect();
        Ok(StepOutput::empty())
    }
}

fn event(seq: u64, event_type: &str, entity: EntityId) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(b"x"),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

fn grant(subject: EntityId, modalities: u8) -> ConsentGrantedV1 {
    ConsentGrantedV1 {
        subject_id: subject,
        grantee_id: EntityId::new(),
        purpose: "subscription-consent".to_owned(),
        modalities,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 0,
        expiry_secs: 0,
        grant_seq: 1,
    }
}

struct Fixture {
    registry: PluginRegistry,
    seen: Arc<Mutex<Vec<(String, EntityId)>>>,
    timeline: TimelineId,
    events: Vec<Event>,
}

fn fixture(authority: ConsentAuthority, subject: EntityId, other: EntityId) -> Fixture {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut registry = PluginRegistry::new()
        .with_consent_authority(authority)
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    registry.register_test_driver(Box::new(RecordingDriver {
        subscriptions: [PERSONA, FORK, RETENTION, ORDINARY]
            .into_iter()
            .map(Kind::new)
            .collect(),
        seen: Arc::clone(&seen),
    }));
    Fixture {
        registry,
        seen,
        timeline: TimelineId::new(),
        events: vec![
            event(1, PERSONA, subject),
            event(2, PERSONA, other),
            event(3, FORK, subject),
            event(4, RETENTION, subject),
            event(5, ORDINARY, other),
        ],
    }
}

fn seen_after(
    fixture: &mut Fixture,
    token: Option<ConsentCapabilityToken>,
) -> Vec<(String, EntityId)> {
    let staged = match token {
        Some(token) => fixture.registry.step_all_anchored_protected(
            fixture.timeline,
            Seq::ZERO,
            token,
            0,
            &fixture.events,
        ),
        None => fixture.registry.step_all_anchored_with_events(
            fixture.timeline,
            Seq::ZERO,
            &fixture.events,
        ),
    };
    assert!(staged.test_ok().is_empty());
    fixture.registry.abort_step();
    fixture
        .seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[test]
fn a_public_pass_sees_no_consent_sensitive_event() {
    let subject = EntityId::new();
    let other = EntityId::new();
    let mut fixture = fixture(ConsentAuthority::new(), subject, other);

    assert_eq!(
        seen_after(&mut fixture, None),
        vec![(ORDINARY.to_owned(), other)]
    );
}

#[test]
fn a_protected_pass_sees_only_its_subject_within_the_granted_modalities() {
    let subject = EntityId::new();
    let other = EntityId::new();
    let authority = ConsentAuthority::new();
    let mut fixture = fixture(authority.clone(), subject, other);
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));

    // The other entity's source, the unpermitted Fork request and the
    // retention record stay hidden.
    assert_eq!(
        seen_after(&mut fixture, Some(persona)),
        vec![(PERSONA.to_owned(), subject), (ORDINARY.to_owned(), other)]
    );

    // A token without the Persona modality sees no Persona source.
    let bare = authority.record_grant_on_timeline(fixture.timeline, &grant(subject, 0));
    assert_eq!(
        seen_after(&mut fixture, Some(bare)),
        vec![(ORDINARY.to_owned(), other)]
    );
}
