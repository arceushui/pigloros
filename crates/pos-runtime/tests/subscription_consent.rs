//! Subscribed committed Events reach a Driver only under consent (ADR-039;
//! ADR-021 Revision 3 Decision 1; ADR-024 Revision 1 Decision 5).
//!
//! ADR-021 Revision 4 Decision 1 (#494): a Driver that does not read the
//! full verified prefix may not subscribe to a consent-sensitive type, so
//! registration rejects it before any registry change. A verified-prefix
//! Driver is filtered again on every pass, so nothing hidden by one pass is
//! lost after a later grant. The host captures both declarations once, at
//! registration, and a later change in the Driver's answers has no effect.

use std::{
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    ids::{EntityId, EventId, PluginId, TimelineId},
    is_subject_controlled_event_type, Capability, ConsentAuthority, ConsentCapabilityToken,
    ConsentGrantedV1, ErasureContainmentGateV1, Plugin, EVENT_TYPE_CONSENT_GRANTED_V1,
    HOST_CONSENT_CLOSED_EVENT_TYPE, MODALITY_EXPORT, MODALITY_LOCATION, MODALITY_MODEL_FIT,
    MODALITY_PERSONA,
};
use pos_runtime::{
    Driver, ObservationView, OutputPolicyBindingV1, OutputPolicySourceV1, PluginCompositionErrorV1,
    PluginRegistry, RuntimeError, StepOutput,
};

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
const LATER: &str = "later.event";

/// What the last pass showed a Driver: `(event type, entity)` in Timeline
/// Order.
type Seen = Arc<Mutex<Vec<(String, EntityId)>>>;

/// A Driver whose declarations switch to a second set once `changed` is set.
struct RecordingDriver {
    subscriptions: Vec<Kind>,
    verified_prefix: bool,
    changed_subscriptions: Vec<Kind>,
    changed_verified_prefix: bool,
    changed: Arc<AtomicBool>,
    seen: Seen,
}

impl RecordingDriver {
    fn new(subscriptions: &[&str], verified_prefix: bool, seen: &Seen) -> Self {
        Self {
            subscriptions: kinds(subscriptions),
            verified_prefix,
            changed_subscriptions: kinds(subscriptions),
            changed_verified_prefix: verified_prefix,
            changed: Arc::new(AtomicBool::new(false)),
            seen: Arc::clone(seen),
        }
    }
}

impl Driver for RecordingDriver {
    fn name(&self) -> &'static str {
        "subscription-recorder"
    }

    fn event_subscriptions(&self) -> &[Kind] {
        if self.changed.load(Ordering::SeqCst) {
            &self.changed_subscriptions
        } else {
            &self.subscriptions
        }
    }

    fn requires_verified_event_prefix(&self) -> bool {
        if self.changed.load(Ordering::SeqCst) {
            self.changed_verified_prefix
        } else {
            self.verified_prefix
        }
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = observations
            .verified_prefix_events()
            .unwrap_or_else(|| observations.events())
            .iter()
            .map(|event| (event.event_type.as_str().to_owned(), event.entity))
            .collect();
        Ok(StepOutput::empty())
    }
}

/// A Plugin with a Driver and one owned type, for the generated path.
struct DriverPlugin {
    id: PluginId,
}

impl Plugin for DriverPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "subscription-plugin"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("subscription.owned")],
            has_driver: true,
            ..Capability::default()
        }
    }
}

fn kinds(event_types: &[&str]) -> Vec<Kind> {
    event_types.iter().copied().map(Kind::new).collect()
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

fn consent_registry(authority: ConsentAuthority) -> PluginRegistry {
    PluginRegistry::new()
        .with_consent_authority(authority)
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

struct Fixture {
    registry: PluginRegistry,
    seen: Seen,
    timeline: TimelineId,
    events: Vec<Event>,
}

impl Fixture {
    /// Register `driver` through the test-support path and compose it.
    fn new(authority: ConsentAuthority, driver: RecordingDriver, events: Vec<Event>) -> Self {
        let seen = Arc::clone(&driver.seen);
        let mut registry = consent_registry(authority);
        registry.register_test_driver(Box::new(driver));
        registry.compose_non_participant_drivers().test_ok();
        Self {
            registry,
            seen,
            timeline: TimelineId::new(),
            events,
        }
    }

    fn head(&self) -> Seq {
        self.events.last().map_or(Seq::ZERO, |event| event.seq)
    }

    fn finish(&mut self, staged: Result<Vec<EventDraft>, RuntimeError>) -> Vec<(String, EntityId)> {
        assert!(staged.test_ok().is_empty());
        self.registry.abort_step();
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn public_view(&mut self) -> Vec<(String, EntityId)> {
        let (timeline, head) = (self.timeline, self.head());
        let registry = &mut self.registry;
        let staged = registry.step_all_anchored_with_events(timeline, head, &self.events);
        self.finish(staged)
    }

    fn protected_view(&mut self, token: ConsentCapabilityToken) -> Vec<(String, EntityId)> {
        let (timeline, head) = (self.timeline, self.head());
        let registry = &mut self.registry;
        let staged = registry.step_all_anchored_protected(timeline, head, token, 0, &self.events);
        self.finish(staged)
    }
}

/// The five-Event prefix: two Persona sources, a Fork request, a retention
/// record and one ordinary Event.
fn sensitive_prefix(subject: EntityId, other: EntityId) -> Vec<Event> {
    vec![
        event(1, PERSONA, subject),
        event(2, PERSONA, other),
        event(3, FORK, subject),
        event(4, RETENTION, subject),
        event(5, ORDINARY, other),
    ]
}

fn verified_fixture(authority: &ConsentAuthority, subject: EntityId, other: EntityId) -> Fixture {
    let seen = Seen::default();
    Fixture::new(
        authority.clone(),
        RecordingDriver::new(&[PERSONA, FORK, RETENTION, ORDINARY], true, &seen),
        sensitive_prefix(subject, other),
    )
}

#[test]
fn a_public_pass_sees_no_consent_sensitive_event() {
    let subject = EntityId::new();
    let other = EntityId::new();
    let mut fixture = verified_fixture(&ConsentAuthority::new(), subject, other);

    assert_eq!(fixture.public_view(), vec![(ORDINARY.to_owned(), other)]);
}

#[test]
fn a_protected_pass_sees_only_its_subject_within_the_granted_modalities() {
    let subject = EntityId::new();
    let other = EntityId::new();
    let authority = ConsentAuthority::new();
    let mut fixture = verified_fixture(&authority, subject, other);
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));

    // The other entity's source, the unpermitted Fork request and the
    // retention record stay hidden.
    assert_eq!(
        fixture.protected_view(persona),
        vec![(PERSONA.to_owned(), subject), (ORDINARY.to_owned(), other)]
    );

    // A token without the Persona modality sees no Persona source.
    let bare = authority.record_grant_on_timeline(fixture.timeline, &grant(subject, 0));
    assert_eq!(
        fixture.protected_view(bare),
        vec![(ORDINARY.to_owned(), other)]
    );
}

#[test]
fn a_later_grant_delivers_every_earlier_hidden_event() {
    let subject = EntityId::new();
    let other = EntityId::new();
    let authority = ConsentAuthority::new();
    let mut fixture = verified_fixture(&authority, subject, other);
    let ordinary_only = vec![(ORDINARY.to_owned(), other)];

    // A public pass, then a protected pass without the Persona modality.
    assert_eq!(fixture.public_view(), ordinary_only);
    let bare = authority.record_grant_on_timeline(fixture.timeline, &grant(subject, 0));
    assert_eq!(fixture.protected_view(bare), ordinary_only);

    // The later grant shows the earlier source: nothing was lost.
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));
    assert_eq!(
        fixture.protected_view(persona),
        vec![(PERSONA.to_owned(), subject), (ORDINARY.to_owned(), other)]
    );
}

#[test]
fn a_consent_event_never_reaches_a_driver_even_for_its_own_subject() {
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let seen = Seen::default();
    let mut fixture = Fixture::new(
        authority.clone(),
        RecordingDriver::new(&[EVENT_TYPE_CONSENT_GRANTED_V1, ORDINARY], true, &seen),
        vec![
            event(1, EVENT_TYPE_CONSENT_GRANTED_V1, subject),
            event(2, ORDINARY, subject),
        ],
    );
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));

    assert_eq!(
        fixture.protected_view(persona),
        vec![(ORDINARY.to_owned(), subject)]
    );
}

#[test]
fn driver_visibility_agrees_with_the_shared_subject_controlled_predicate() {
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let table = [
        PERSONA,
        "geo.location.v1",
        "model.fit.v1",
        "export.bundle.v1",
        FORK,
        RETENTION,
        EVENT_TYPE_CONSENT_GRANTED_V1,
        "eval.prediction",
        "timeline.forked",
        "world.observation.v1",
        ORDINARY,
    ];
    let seen = Seen::default();
    let events = table
        .iter()
        .zip(1..)
        .map(|(event_type, seq)| event(seq, event_type, subject))
        .collect();
    let mut fixture = Fixture::new(
        authority.clone(),
        RecordingDriver::new(&table, true, &seen),
        events,
    );
    let public: Vec<String> = fixture
        .public_view()
        .into_iter()
        .map(|(event_type, _)| event_type)
        .collect();
    let expected: Vec<String> = table
        .iter()
        .filter(|event_type| !is_subject_controlled_event_type(&Kind::new(**event_type)))
        .map(|event_type| (*event_type).to_owned())
        .collect();
    assert_eq!(public, expected);

    // A token with every modality, Fork and retention shows every
    // consent-sensitive type of its subject, and still no `consent.*` type.
    let mut everything = grant(
        subject,
        MODALITY_PERSONA | MODALITY_LOCATION | MODALITY_MODEL_FIT | MODALITY_EXPORT,
    );
    everything.fork_permitted = true;
    everything.export_permitted = true;
    everything.retention_days = 1;
    let token = authority.record_grant_on_timeline(fixture.timeline, &everything);
    let protected: Vec<String> = fixture
        .protected_view(token)
        .into_iter()
        .map(|(event_type, _)| event_type)
        .collect();
    let without_consent: Vec<String> = table
        .iter()
        .filter(|event_type| **event_type != EVENT_TYPE_CONSENT_GRANTED_V1)
        .map(|event_type| (*event_type).to_owned())
        .collect();
    assert_eq!(protected, without_consent);
}

fn rejection(event_type: &str) -> String {
    let error = PluginCompositionErrorV1::CursorSubscriptionToConsentSensitiveType {
        event_type: event_type.to_owned(),
    };
    RuntimeError::Composition(error).to_string()
}

fn generated_binding(plugin: &DriverPlugin) -> OutputPolicyBindingV1 {
    OutputPolicyBindingV1::from_source(
        plugin,
        OutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )
    .test_ok()
}

/// Register a cursor-based Driver subscribed to `event_type` through the
/// generated, test-support verified and undeclared paths. Each path must
/// reject it and leave the registry unchanged.
fn assert_rejected_everywhere(event_type: &str) {
    let seen = Seen::default();
    let cursor = || -> Box<dyn Driver> {
        Box::new(RecordingDriver::new(&[ORDINARY, event_type], false, &seen))
    };
    let plugin = DriverPlugin {
        id: PluginId::new(),
    };
    let mut registry = consent_registry(ConsentAuthority::new());

    let generated = registry.register_generated(&plugin, None, Some(cursor()));
    let verified = registry.register_test_driver_with_verified_output_policy(
        plugin.id,
        generated_binding(&plugin),
        cursor(),
    );
    let undeclared = registry.register_driver(cursor());
    for result in [generated, verified, undeclared] {
        assert_eq!(
            result.err().map(|error| error.to_string()),
            Some(rejection(event_type))
        );
    }
    assert_eq!((registry.len(), registry.driver_count()), (0, 0));

    // Nothing was claimed: the same Plugin registers once its Driver reads
    // the verified prefix.
    let verified_prefix = RecordingDriver::new(&[ORDINARY, event_type], true, &seen);
    registry
        .register_generated(&plugin, None, Some(Box::new(verified_prefix)))
        .test_ok();
    assert_eq!((registry.len(), registry.driver_count()), (1, 1));
}

#[test]
fn a_cursor_subscription_to_a_modality_type_is_rejected_at_registration() {
    for event_type in [
        PERSONA,
        "geo.location.v1",
        "model.fit.v1",
        "export.bundle.v1",
    ] {
        assert_rejected_everywhere(event_type);
    }
}

#[test]
fn a_cursor_subscription_to_a_fork_or_retention_type_is_rejected_at_registration() {
    assert_rejected_everywhere(FORK);
    assert_rejected_everywhere(RETENTION);
}

#[test]
fn the_panicking_test_support_path_rejects_a_cursor_subscription_too() {
    let seen = Seen::default();
    let mut registry = consent_registry(ConsentAuthority::new());
    let driver = RecordingDriver::new(&[PERSONA], false, &seen);
    let register = AssertUnwindSafe(|| registry.register_test_driver(Box::new(driver)));

    assert!(std::panic::catch_unwind(register).is_err());
    assert_eq!((registry.len(), registry.driver_count()), (0, 0));
}

#[test]
fn a_cursor_based_subscriber_to_ordinary_types_keeps_its_view() {
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let seen = Seen::default();
    let subscriptions = [
        ORDINARY,
        EVENT_TYPE_CONSENT_GRANTED_V1,
        HOST_CONSENT_CLOSED_EVENT_TYPE,
    ];
    let mut fixture = Fixture::new(
        authority.clone(),
        RecordingDriver::new(&subscriptions, false, &seen),
        vec![
            event(1, ORDINARY, subject),
            event(2, EVENT_TYPE_CONSENT_GRANTED_V1, subject),
            event(3, HOST_CONSENT_CLOSED_EVENT_TYPE, subject),
            event(4, ORDINARY, subject),
        ],
    );
    let ordinary = vec![
        (ORDINARY.to_owned(), subject),
        (ORDINARY.to_owned(), subject),
    ];

    // Host-owned consent Events never reach it, in a public or a protected
    // pass; ordinary Events are unchanged.
    assert_eq!(fixture.public_view(), ordinary);
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));
    assert_eq!(fixture.protected_view(persona), ordinary);
}

#[test]
fn a_later_change_of_a_cursor_drivers_declarations_has_no_effect() {
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let seen = Seen::default();
    let mut driver = RecordingDriver::new(&[ORDINARY], false, &seen);
    driver.changed_subscriptions = kinds(&[ORDINARY, LATER, PERSONA]);
    driver.changed_verified_prefix = true;
    let changed = Arc::clone(&driver.changed);
    let mut fixture = Fixture::new(
        authority.clone(),
        driver,
        vec![
            event(1, ORDINARY, subject),
            event(2, LATER, subject),
            event(3, PERSONA, subject),
        ],
    );
    changed.store(true, Ordering::SeqCst);
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));

    // No newly added type is delivered, the Driver keeps cursor delivery,
    // and the pass is not failed for the change.
    assert_eq!(
        fixture.protected_view(persona),
        vec![(ORDINARY.to_owned(), subject)]
    );
    assert_eq!(fixture.public_view(), vec![(ORDINARY.to_owned(), subject)]);
}

#[test]
fn a_later_change_of_a_verified_drivers_declarations_has_no_effect() {
    let subject = EntityId::new();
    let authority = ConsentAuthority::new();
    let seen = Seen::default();
    let mut driver = RecordingDriver::new(&[PERSONA, ORDINARY], true, &seen);
    driver.changed_subscriptions = Vec::new();
    driver.changed_verified_prefix = false;
    let changed = Arc::clone(&driver.changed);
    let mut fixture = Fixture::new(
        authority.clone(),
        driver,
        vec![event(1, PERSONA, subject), event(2, ORDINARY, subject)],
    );
    changed.store(true, Ordering::SeqCst);

    // The registered verified prefix is still consent-filtered: a public
    // pass hides the source, and a later grant shows it.
    assert_eq!(fixture.public_view(), vec![(ORDINARY.to_owned(), subject)]);
    let persona =
        authority.record_grant_on_timeline(fixture.timeline, &grant(subject, MODALITY_PERSONA));
    assert_eq!(
        fixture.protected_view(persona),
        vec![
            (PERSONA.to_owned(), subject),
            (ORDINARY.to_owned(), subject),
        ]
    );
}
