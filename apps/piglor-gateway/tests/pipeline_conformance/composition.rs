//! ADR-021 Revision 3 Decisions 2 and 3: composition-time scheduled
//! observation profiles (#504).
//!
//! The host fixes each scheduled Driver's profile from its ADR-059
//! Participant binding when it composes the registry. These runners act as
//! the test host the amendment names, on `MemoryStore` and `SQLite`: an
//! unassigned Driver, a participant-bound Driver offered to an anchored
//! path, and a composition that mixes both profiles are each rejected before
//! any Driver runs, so nothing reaches the store.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{EntityId, PluginId, TimelineId};
use pos_runtime::{
    PluginRegistry, RuntimeError, ScheduledAdmissionStoreV1, ScheduledDriverBindingV1,
};

use super::{
    harness::Capture,
    support::{
        draft, events, expect_err, gated_registry, pass, stores, FixturePlugin, ScriptedDriver,
        TestOk,
    },
};

/// One registered Driver and the counters of its invocations.
struct Registered {
    id: PluginId,
    steps: Arc<AtomicUsize>,
    aborts: Arc<AtomicUsize>,
}

/// Register a Driver named `name` that emits one draft of its own type.
fn register(
    registry: &mut PluginRegistry,
    name: &'static str,
    event_type: &'static str,
) -> Registered {
    let plugin = FixturePlugin::new(name, &[event_type], true);
    let driver = ScriptedDriver::new(name, vec![draft(EntityId::new(), event_type, b"pass")]);
    let registered = Registered {
        id: plugin.id,
        steps: Arc::clone(&driver.steps),
        aborts: Arc::clone(&driver.aborts),
    };
    registry
        .register_generated(&plugin, None, Some(Box::new(driver)))
        .test_ok();
    registered
}

/// The total invocations and aborts of `drivers`, as `steps/aborts`.
fn invocations(drivers: &[&Registered]) -> String {
    let steps: usize = drivers
        .iter()
        .map(|driver| driver.steps.load(Ordering::SeqCst))
        .sum();
    let aborts: usize = drivers
        .iter()
        .map(|driver| driver.aborts.load(Ordering::SeqCst))
        .sum();
    format!("{steps}/{aborts}")
}

/// The profile fixed for `driver`, or `unassigned`.
fn binding(registry: &PluginRegistry, driver: &Registered) -> String {
    registry
        .scheduled_binding(driver.id)
        .map_or_else(|| "unassigned".to_owned(), |binding| format!("{:?}", binding.profile()))
}

fn create_timeline(backend: &mut dyn ScheduledAdmissionStoreV1, name: &str) -> TimelineId {
    backend.create_timeline(name).test_ok().id()
}

/// Stage an anchored pass at the store's Logical Head.
fn anchored(
    registry: &mut PluginRegistry,
    backend: &dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
) -> RuntimeError {
    let head = backend.logical_head(timeline).test_ok();
    expect_err(registry.step_all_anchored_with_events(timeline, head, &[]))
}

/// Stage an empty participant-authorized pass at the store's Logical Head.
fn authorized(
    registry: &mut PluginRegistry,
    backend: &dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
) -> RuntimeError {
    let head = backend.logical_head(timeline).test_ok();
    expect_err(registry.stage_authorized_scheduled_pass(timeline, head, &[], &[]))
}

/// PCF-R3-009: a scheduled Driver with no profile assignment is rejected at
/// composition, and every scheduled path refuses it before staging.
///
/// A composition that leaves one Driver unassigned assigns nothing, and
/// neither the anchored nor the participant-authorized path runs a Driver.
#[must_use]
pub fn unassigned_driver_is_rejected() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = create_timeline(backend.as_mut(), "r3-unassigned");
        let mut registry = gated_registry(None);
        let first = register(&mut registry, "first", "r3.first");
        let second = register(&mut registry, "second", "r3.second");
        let bindings = [(first.id, ScheduledDriverBindingV1::NonParticipant)];
        let composition = expect_err(registry.compose_scheduled_profiles(&bindings));
        capture.record(store, "composition", composition);
        capture.record(store, "first.binding", binding(&registry, &first));
        capture.record(
            store,
            "anchored",
            anchored(&mut registry, backend.as_ref(), timeline),
        );
        capture.record(
            store,
            "authorized",
            authorized(&mut registry, backend.as_ref(), timeline),
        );
        capture.record(store, "driver.steps/aborts", invocations(&[&first, &second]));
        capture.record(store, "committed", events(backend.as_ref(), timeline).len());
    }
    capture
}

/// PCF-R3-010: a participant-bound Driver offered to any anchored path is
/// rejected before staging, not only by the `AuthorityFenceRequired`
/// backstop.
///
/// The anchored all-Driver and cadenced paths, the local scheduled-admission
/// host and the unanchored step all refuse the Driver before it runs.
#[must_use]
pub fn participant_bound_driver_never_stages_anchored() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = create_timeline(backend.as_mut(), "r3-anchored");
        let mut registry = gated_registry(None);
        let participant = register(&mut registry, "participant", "r3.participant");
        let bound = ScheduledDriverBindingV1::Participant(EntityId::new());
        registry
            .compose_scheduled_profiles(&[(participant.id, bound)])
            .test_ok();
        let head = backend.logical_head(timeline).test_ok();
        capture.record(store, "binding", binding(&registry, &participant));
        capture.record(
            store,
            "anchored",
            anchored(&mut registry, backend.as_ref(), timeline),
        );
        capture.record(
            store,
            "cadenced",
            expect_err(registry.tick_cadenced_anchored_with_events(timeline, 0, head, &[])),
        );
        capture.record(
            store,
            "local-host",
            expect_err(pass(&mut registry, backend.as_mut(), timeline, None)),
        );
        capture.record(store, "unanchored", expect_err(registry.step_all(timeline)));
        capture.record(store, "driver.steps/aborts", invocations(&[&participant]));
        capture.record(store, "committed", events(backend.as_ref(), timeline).len());
    }
    capture
}

/// PCF-R3-011: one composition never mixes participant-bound and
/// non-participant Drivers.
///
/// A mixed composition assigns nothing. A host that composed a
/// participant-bound Driver cannot later compose a world Driver as
/// non-participant, and neither scheduled path stages the mixed registry.
#[must_use]
pub fn mixed_composition_is_rejected() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = create_timeline(backend.as_mut(), "r3-mixed");
        let mut registry = gated_registry(None);
        let participant = register(&mut registry, "participant", "r3.participant");
        let world = register(&mut registry, "world", "r3.world");
        let bound = ScheduledDriverBindingV1::Participant(EntityId::new());
        let bindings = [
            (participant.id, bound),
            (world.id, ScheduledDriverBindingV1::NonParticipant),
        ];
        let mixed = expect_err(registry.compose_scheduled_profiles(&bindings));
        capture.record(store, "mixed", mixed);
        capture.record(
            store,
            "bindings-after-refusal",
            format!(
                "{},{}",
                binding(&registry, &participant),
                binding(&registry, &world)
            ),
        );

        let mut late_registry = gated_registry(None);
        let late_participant = register(&mut late_registry, "participant", "r3.participant");
        late_registry
            .compose_scheduled_profiles(&[(late_participant.id, bound)])
            .test_ok();
        let late_world = register(&mut late_registry, "world", "r3.world");
        capture.record(
            store,
            "late-non-participant",
            expect_err(late_registry.compose_non_participant_drivers()),
        );
        capture.record(
            store,
            "late.anchored",
            anchored(&mut late_registry, backend.as_ref(), timeline),
        );
        capture.record(
            store,
            "late.authorized",
            authorized(&mut late_registry, backend.as_ref(), timeline),
        );
        capture.record(
            store,
            "driver.steps/aborts",
            invocations(&[&participant, &world, &late_participant, &late_world]),
        );
        capture.record(store, "committed", events(backend.as_ref(), timeline).len());
    }
    capture
}
