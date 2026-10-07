//! Host-observed Plugin availability at pass time (ADR-061, #543).

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    Capability, ErasureContainmentGateV1, Hash, Kind, Plugin, PluginId, Seq, TimelineId,
};
use pos_runtime::{
    DomainImplementationKindV1, Driver, ObservationView, PluginAvailabilityV1,
    PluginCompositionErrorV1, PluginExecutionModeV1, PluginIsolationV1, PluginPinV1,
    PluginRegistrationV1, PluginRegistry, RequiredPluginCompositionV1, RequiredPluginV1,
    RuntimeError, StepOutput,
};

/// The one-member Fork ancestry of a fixture Timeline with no parent.
fn root_ancestry(timeline: TimelineId) -> Vec<pos_core::TimelineMeta> {
    vec![pos_core::TimelineMeta {
        id: timeline,
        ..pos_core::TimelineMeta::root("root")
    }]
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

struct DriverPlugin {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
}

impl Plugin for DriverPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            has_driver: true,
            ..Capability::default()
        }
    }
}

struct CountingDriver(Arc<AtomicUsize>);

impl Driver for CountingDriver {
    fn name(&self) -> &'static str {
        "counting-driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(StepOutput::empty())
    }
}

fn pin(byte: u8, role: &str) -> PluginPinV1 {
    ok(PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::GovernedCommunity,
        Hash::from_bytes([byte; 32]),
        vec![role.to_owned()],
    ))
}

fn plugin(name: &'static str, event_type: &'static str) -> DriverPlugin {
    DriverPlugin {
        id: PluginId::new(),
        name,
        event_type,
    }
}

fn new_registry() -> PluginRegistry {
    PluginRegistry::new().with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

/// Register `plugin` pinned and available with a counting Driver.
fn register_pinned(
    registry: &mut PluginRegistry,
    plugin: &DriverPlugin,
    pin: PluginPinV1,
) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    ok(registry.register_pinned_generated(
        plugin,
        PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available),
        None,
        Some(Box::new(CountingDriver(Arc::clone(&calls)))),
    ));
    calls
}

fn pass(registry: &mut PluginRegistry, timeline: TimelineId) -> Result<(), RuntimeError> {
    registry
        .step_all_anchored(timeline, &root_ancestry(timeline), Seq::ZERO)
        .map(|_| ())
}

#[test]
fn the_setter_reports_an_unregistered_and_an_unpinned_plugin() {
    let mut registry = new_registry();
    let unknown = PluginId::new();
    assert_eq!(registry.availability(unknown), None);
    let error = err(registry.set_availability(unknown, PluginAvailabilityV1::Trapped));
    assert!(matches!(
        error,
        RuntimeError::Composition(PluginCompositionErrorV1::MissingImplementation { plugin_id })
            if plugin_id == unknown
    ));

    let unpinned = plugin("unpinned", "availability.unpinned");
    ok(registry.register_generated(
        &unpinned,
        None,
        Some(Box::new(CountingDriver(Arc::default()))),
    ));
    assert_eq!(registry.availability(unpinned.id), None);
    let error = err(registry.set_availability(unpinned.id, PluginAvailabilityV1::Trapped));
    assert!(matches!(
        error,
        RuntimeError::Composition(PluginCompositionErrorV1::UnpinnedImplementation { plugin_id })
            if plugin_id == unpinned.id
    ));
}

#[test]
fn a_pass_refuses_every_non_available_driver_before_it_runs() {
    for availability in [
        PluginAvailabilityV1::Disabled,
        PluginAvailabilityV1::Unavailable,
        PluginAvailabilityV1::Revoked,
        PluginAvailabilityV1::Trapped,
        PluginAvailabilityV1::ResourceExhausted,
    ] {
        let mut registry = new_registry();
        let quarantined = plugin("quarantined", "availability.quarantined");
        let healthy = plugin("healthy", "availability.healthy");
        let quarantined_calls = register_pinned(&mut registry, &quarantined, pin(1, "first"));
        let healthy_calls = register_pinned(&mut registry, &healthy, pin(2, "second"));
        ok(registry.compose_non_participant_drivers());
        assert_eq!(
            registry.availability(quarantined.id),
            Some(PluginAvailabilityV1::Available)
        );
        ok(registry.set_availability(quarantined.id, availability));
        assert_eq!(registry.availability(quarantined.id), Some(availability));

        let timeline = TimelineId::new();
        for _ in 0..2 {
            let error = err(pass(&mut registry, timeline));
            assert!(
                matches!(
                    error,
                    RuntimeError::Composition(
                        PluginCompositionErrorV1::ImplementationUnavailable {
                            plugin_id,
                            availability: refused,
                        }
                    ) if plugin_id == quarantined.id && refused == availability
                ),
                "{availability:?}: {error}"
            );
        }
        // The refusal precedes every Driver and stages nothing, so a repeated
        // pass reports the same refusal and never `PendingDriverStep`.
        assert_eq!(quarantined_calls.load(Ordering::SeqCst), 0);
        assert_eq!(healthy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            registry.availability(healthy.id),
            Some(PluginAvailabilityV1::Available)
        );

        ok(registry.set_availability(quarantined.id, PluginAvailabilityV1::Available));
        ok(pass(&mut registry, timeline));
        registry.abort_step();
        assert_eq!(quarantined_calls.load(Ordering::SeqCst), 1);
        assert_eq!(healthy_calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn an_unpinned_driver_is_never_refused_and_the_pin_survives_a_change() {
    let mut registry = new_registry();
    let unpinned = plugin("unpinned", "availability.unpinned");
    let calls = Arc::new(AtomicUsize::new(0));
    ok(registry.register_generated(
        &unpinned,
        None,
        Some(Box::new(CountingDriver(Arc::clone(&calls)))),
    ));
    ok(registry.compose_non_participant_drivers());
    let timeline = TimelineId::new();
    ok(pass(&mut registry, timeline));
    registry.abort_step();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut pinned = new_registry();
    let community = plugin("community", "availability.community");
    let community_pin = pin(3, "world");
    register_pinned(&mut pinned, &community, community_pin.clone());
    ok(pinned.set_availability(community.id, PluginAvailabilityV1::Trapped));
    ok(pinned.set_availability(community.id, PluginAvailabilityV1::Available));
    let required = ok(RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![ok(RequiredPluginV1::try_new(
            community.id,
            community.version(),
            community_pin,
        ))],
    ));
    assert_eq!(
        ok(pinned.resolve_required_composition(&required))
            .plugins()
            .len(),
        1
    );
}
