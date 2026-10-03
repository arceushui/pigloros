//! ADR-021 Revision 4 Decision 1: consent-sensitive Driver subscriptions
//! (#494).
//!
//! A scheduled Driver that does not read the full verified prefix may not
//! subscribe to a consent-sensitive type. Every public registration path
//! that accepts a Driver rejects it with the closed composition error before
//! any registry change; the installed and manifest-slot seams accept no
//! Driver and fail closed in Wave 8, and a host catalogue bundle carries no
//! Driver. A verified-prefix Driver is consent-filtered on every pass, so a
//! later grant delivers every earlier hidden Event. The host captures both
//! declarations once, at registration, and only that snapshot governs.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, PoisonError,
};

use pos_core::{
    ActionApprover, ConsentAuthority, ConsentCapabilityToken, ConsentGrantedV1, EntityId, Hash,
    Kind, TimelineId,
};
use pos_runtime::{
    DomainImplementationKindV1, Driver, ObservationView, OutputAdmissionErrorV1,
    OutputPolicyBindingV1, OutputPolicySourceV1, PluginAvailabilityV1, PluginComposition,
    PluginIsolationV1, PluginPinV1, PluginRegistrationV1, PluginRegistry, RuntimeError,
    ScheduledAdmissionStoreV1, StepOutput,
};

use super::{
    harness::Capture,
    support::{
        draft, events, gated_registry, pass, persona_token, stores, CountingApprover, FixturePlugin,
        TestOk,
    },
};

const PERSONA: &str = "persona.prediction";
const ORDINARY: &str = "ordinary.event";
const LATER: &str = "later.event";

/// Every public registration path, in capture order.
const PATHS: [&str; 11] = [
    "generated",
    "generated-with-approver",
    "local",
    "pinned",
    "pinned-with-approver",
    "verified",
    "verified-with-approver",
    "test-driver",
    "undeclared-driver",
    "installed",
    "manifest-slot",
];

/// A Driver that records what its last pass showed it and whose
/// declarations switch to a second set once `changed` is set.
struct SubscriptionDriver {
    subject: EntityId,
    subscriptions: Vec<Kind>,
    verified_prefix: bool,
    changed_subscriptions: Vec<Kind>,
    changed_verified_prefix: bool,
    changed: Arc<AtomicBool>,
    seen: Arc<Mutex<String>>,
}

impl SubscriptionDriver {
    fn new(subject: EntityId, subscriptions: &[&str], verified_prefix: bool) -> Self {
        Self {
            subject,
            subscriptions: kinds(subscriptions),
            verified_prefix,
            changed_subscriptions: kinds(subscriptions),
            changed_verified_prefix: verified_prefix,
            changed: Arc::new(AtomicBool::new(false)),
            seen: Arc::new(Mutex::new(String::new())),
        }
    }
}

impl Driver for SubscriptionDriver {
    fn name(&self) -> &'static str {
        "r4-subscriber"
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
        _: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let seen: Vec<String> = observations
            .verified_prefix_events()
            .unwrap_or_else(|| observations.events())
            .iter()
            .map(|event| {
                let owner = if event.entity == self.subject {
                    "subject"
                } else {
                    "other"
                };
                format!("{}@{owner}", event.event_type.as_str())
            })
            .collect();
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = if seen.is_empty() {
            "none".to_owned()
        } else {
            seen.join(",")
        };
        Ok(StepOutput::empty())
    }
}

fn kinds(event_types: &[&str]) -> Vec<Kind> {
    event_types.iter().copied().map(Kind::new).collect()
}

/// What the last pass showed one Driver.
fn read(seen: &Mutex<String>) -> String {
    seen.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn binding(plugin: &FixturePlugin) -> OutputPolicyBindingV1 {
    OutputPolicyBindingV1::from_source(
        plugin,
        OutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )
    .test_ok()
}

fn registration(byte: u8) -> PluginRegistrationV1 {
    PluginRegistrationV1::new(
        PluginPinV1::try_new(
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::OperatorTrustedNative,
            Hash::from_bytes([byte; 32]),
            vec!["r4-conformance".to_owned()],
        )
        .test_ok(),
        PluginAvailabilityV1::Available,
    )
}

fn approver() -> Option<Box<dyn ActionApprover>> {
    Some(Box::new(CountingApprover(Arc::default())))
}

/// Register `plugin` with `driver` through one named public path. The
/// installed and manifest-slot seams accept no Driver.
fn register(
    registry: &mut PluginRegistry,
    path: &str,
    plugin: &FixturePlugin,
    driver: Box<dyn Driver>,
) -> Result<(), RuntimeError> {
    let owned = kinds(&plugin.owned);
    match path {
        "generated" => registry.register_generated(plugin, None, Some(driver)),
        "generated-with-approver" => {
            registry.register_generated_with_approver(plugin, None, Some(driver), approver(), owned)
        }
        "local" => {
            registry.register_local(plugin, vec!["r4-local".to_owned()], None, Some(driver))
        }
        "pinned" => registry.register_pinned_generated(plugin, registration(1), None, Some(driver)),
        "pinned-with-approver" => registry.register_pinned_generated_with_approver(
            plugin,
            registration(2),
            None,
            Some(driver),
            approver(),
            owned,
        ),
        "verified" => registry.register_with_verified_output_policy(
            plugin,
            binding(plugin),
            None,
            Some(driver),
        ),
        "verified-with-approver" => registry.register_with_verified_output_policy_and_approver(
            plugin,
            binding(plugin),
            None,
            Some(driver),
            approver(),
            owned,
        ),
        "test-driver" => registry.register_test_driver_with_verified_output_policy(
            plugin.id,
            binding(plugin),
            driver,
        ),
        "undeclared-driver" => registry.register_driver(driver),
        "installed" => {
            registry.register_installed_output(plugin, binding(plugin), registration(3), None)
        }
        _ => registry.register_installed_output_in_manifest_slot(
            plugin,
            binding(plugin),
            registration(4),
            None,
            "r4-slot",
        ),
    }
}

/// A stable name for one registration result.
fn outcome(result: Result<(), RuntimeError>) -> String {
    match result {
        Ok(()) => "registered".to_owned(),
        Err(RuntimeError::OutputAdmission(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "EPF1",
        })) => "fails-closed:EPF1".to_owned(),
        Err(error) => error.to_string(),
    }
}

/// Everything a rejected registration must leave untouched.
#[derive(Debug, PartialEq, Eq)]
struct RegistryState {
    composition: PluginComposition,
    event_types: Vec<String>,
    plugins: usize,
    drivers: usize,
}

impl RegistryState {
    fn of(registry: &PluginRegistry) -> Self {
        let mut event_types: Vec<String> = registry
            .schemas
            .iter()
            .map(|schema| schema.event_type.as_str().to_owned())
            .collect();
        event_types.sort();
        Self {
            composition: registry.composition(),
            event_types,
            plugins: registry.len(),
            drivers: registry.driver_count(),
        }
    }
}

/// Offer a cursor-based Driver subscribed to each labelled type on every
/// public path, then the same Driver declaring the verified prefix.
fn rejected_on_every_path(types: &[(&str, &str)]) -> Capture {
    let mut capture = Capture::default();
    for &(label, event_type) in types {
        for path in PATHS {
            let mut registry = gated_registry(None);
            let before = RegistryState::of(&registry);
            let plugin = FixturePlugin::new("r4-cursor", &["r4.cursor.owned"], true);
            let subject = EntityId::new();
            let cursor = SubscriptionDriver::new(subject, &[ORDINARY, event_type], false);
            let result = register(&mut registry, path, &plugin, Box::new(cursor));
            capture.record("none", &format!("{label}.{path}"), outcome(result));
            capture.record(
                "none",
                &format!("{label}.{path}.unchanged"),
                RegistryState::of(&registry) == before,
            );
            let verified = SubscriptionDriver::new(subject, &[ORDINARY, event_type], true);
            let result = register(&mut registry, path, &plugin, Box::new(verified));
            capture.record(
                "none",
                &format!("{label}.{path}.verified-prefix"),
                outcome(result),
            );
        }
    }
    capture
}

/// PCF-R4-001: a cursor-based Driver subscribing to a type with an ADR-039
/// modality is rejected at registration on every path, and the registry is
/// unchanged; the same Driver declaring the verified prefix registers.
#[must_use]
pub fn cursor_modality_subscription_is_rejected() -> Capture {
    rejected_on_every_path(&[("persona", PERSONA), ("geo", "geo.location.v1")])
}

/// PCF-R4-002: the same rejection applies to `timeline.fork.*` and
/// `retention.*` subscriptions.
#[must_use]
pub fn cursor_fork_and_retention_subscriptions_are_rejected() -> Capture {
    rejected_on_every_path(&[
        ("fork", "timeline.fork.requested"),
        ("retention", "retention.extended"),
    ])
}

/// One registered subscriber and what its passes showed it.
struct Subscriber {
    changed: Arc<AtomicBool>,
    seen: Arc<Mutex<String>>,
}

impl Subscriber {
    /// Register `driver` on the generated path for a Plugin that owns
    /// `owned`.
    fn register(
        registry: &mut PluginRegistry,
        owned: &'static str,
        driver: SubscriptionDriver,
    ) -> Self {
        let subscriber = Self {
            changed: Arc::clone(&driver.changed),
            seen: Arc::clone(&driver.seen),
        };
        let plugin = FixturePlugin::new(owned, &[owned], true);
        registry
            .register_generated(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        subscriber
    }

    /// Run one committed pass and report what it showed the Driver.
    fn pass(
        &self,
        registry: &mut PluginRegistry,
        backend: &mut dyn ScheduledAdmissionStoreV1,
        timeline: TimelineId,
        token: Option<&ConsentCapabilityToken>,
    ) -> String {
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = "not-run".to_owned();
        pass(registry, backend, timeline, token)
            .map_or_else(|error| error.to_string(), |_| read(&self.seen))
    }
}

/// A consent capability for `subject` without any modality.
fn bare_token(
    authority: &ConsentAuthority,
    timeline: TimelineId,
    subject: EntityId,
) -> ConsentCapabilityToken {
    authority.record_grant_on_timeline(
        timeline,
        &ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "pipeline-conformance".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    )
}

/// PCF-R4-003: a verified-prefix Driver subscribed to a consent-sensitive
/// type registers. Across a public pass, a protected pass without the
/// modality and a later grant, it never observes a sensitive Event without
/// consent and observes every earlier one after the grant.
#[must_use]
pub fn verified_prefix_delivery_loses_nothing() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("r4-verified").test_ok().id();
        let subject = EntityId::new();
        let other = EntityId::new();
        let authority = ConsentAuthority::new();
        let mut registry = gated_registry(Some(&authority));
        let driver = SubscriptionDriver::new(subject, &[PERSONA, ORDINARY], true);
        let subscriber = Subscriber::register(&mut registry, "r4.verified", driver);
        let first = [
            draft(subject, PERSONA, b"first"),
            draft(other, PERSONA, b"other"),
            draft(other, ORDINARY, b"ordinary"),
        ];
        backend.append(timeline, &first).test_ok();
        let backend = backend.as_mut();
        capture.record(
            store,
            "public",
            subscriber.pass(&mut registry, backend, timeline, None),
        );
        let bare = bare_token(&authority, timeline, subject);
        capture.record(
            store,
            "protected-without-modality",
            subscriber.pass(&mut registry, backend, timeline, Some(&bare)),
        );
        backend
            .append(timeline, &[draft(subject, PERSONA, b"second")])
            .test_ok();
        let granted = persona_token(&authority, timeline, subject);
        capture.record(
            store,
            "after-grant",
            subscriber.pass(&mut registry, backend, timeline, Some(&granted)),
        );
        capture.record(store, "committed", events(backend, timeline).len());
    }
    capture
}

/// PCF-R4-004: a cursor-based Driver subscribing only to non-sensitive
/// types registers and keeps cursor delivery: each pass shows only the
/// subscribed Events after its cursor, in a public or a protected pass.
#[must_use]
pub fn cursor_subscription_to_ordinary_types_is_unchanged() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("r4-cursor").test_ok().id();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let mut registry = gated_registry(Some(&authority));
        let driver = SubscriptionDriver::new(subject, &[ORDINARY, LATER], false);
        let subscriber = Subscriber::register(&mut registry, "r4.cursor", driver);
        let first = [
            draft(subject, ORDINARY, b"first"),
            draft(subject, PERSONA, b"unsubscribed"),
            draft(subject, LATER, b"later"),
        ];
        backend.append(timeline, &first).test_ok();
        let backend = backend.as_mut();
        capture.record(
            store,
            "first-pass",
            subscriber.pass(&mut registry, backend, timeline, None),
        );
        backend
            .append(timeline, &[draft(subject, ORDINARY, b"second")])
            .test_ok();
        let token = persona_token(&authority, timeline, subject);
        capture.record(
            store,
            "protected-pass",
            subscriber.pass(&mut registry, backend, timeline, Some(&token)),
        );
        capture.record(
            store,
            "idle-pass",
            subscriber.pass(&mut registry, backend, timeline, None),
        );
    }
    capture
}

/// PCF-R4-005: the registration snapshot governs. A Driver whose
/// declarations change after registration keeps its registered behaviour:
/// no newly added type is delivered, the cursor rule is unchanged, and the
/// pass is not failed for the change.
#[must_use]
pub fn registration_snapshot_governs() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("r4-snapshot").test_ok().id();
        let subject = EntityId::new();
        let other = EntityId::new();
        let authority = ConsentAuthority::new();
        let mut registry = gated_registry(Some(&authority));
        let mut cursor = SubscriptionDriver::new(subject, &[ORDINARY], false);
        cursor.changed_subscriptions = kinds(&[ORDINARY, LATER, PERSONA]);
        cursor.changed_verified_prefix = true;
        let cursor = Subscriber::register(&mut registry, "r4.cursor", cursor);
        let mut verified = SubscriptionDriver::new(subject, &[PERSONA, ORDINARY], true);
        verified.changed_subscriptions = Vec::new();
        verified.changed_verified_prefix = false;
        let verified = Subscriber::register(&mut registry, "r4.verified", verified);
        let prefix = [
            draft(subject, PERSONA, b"source"),
            draft(subject, LATER, b"later"),
            draft(other, ORDINARY, b"ordinary"),
        ];
        backend.append(timeline, &prefix).test_ok();
        cursor.changed.store(true, Ordering::SeqCst);
        verified.changed.store(true, Ordering::SeqCst);
        let backend = backend.as_mut();
        capture.record(
            store,
            "public.cursor",
            cursor.pass(&mut registry, backend, timeline, None),
        );
        capture.record(store, "public.verified", read(&verified.seen));
        let granted = persona_token(&authority, timeline, subject);
        capture.record(
            store,
            "granted.verified",
            verified.pass(&mut registry, backend, timeline, Some(&granted)),
        );
        capture.record(store, "granted.cursor", read(&cursor.seen));
    }
    capture
}
