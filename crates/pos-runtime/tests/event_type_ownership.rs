//! ADR-024 Revision 1: exclusive Plugin Event-type ownership (#486).
//!
//! Every registration path that installs owned Event types runs one shared
//! ownership check before any registry mutation. These tests exercise it
//! through the public registration seams only.

use pos_core::{
    state::{Reducer, State},
    Capability, Event, Hash, Kind, Plugin, PluginId,
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, DomainImplementationKindV1, Driver, ManifestSlotV1,
    ObservationView, OutputAdmissionErrorV1, OutputPolicyBindingV1, OutputPolicySourceV1,
    PluginAvailabilityV1, PluginComposition, PluginCompositionErrorV1, PluginIsolationV1,
    PluginPinV1, PluginRegistrationV1, PluginRegistry, RuntimeError, StepOutput,
};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected ownership fixture error: {error:?}"
            )))
        })
    }
}

struct OwnerPlugin {
    id: PluginId,
    name: &'static str,
    owned: Vec<&'static str>,
    has_reducer: bool,
}

impl OwnerPlugin {
    fn new(name: &'static str, owned: &[&'static str]) -> Self {
        Self {
            id: PluginId::new(),
            name,
            owned: owned.to_vec(),
            has_reducer: false,
        }
    }

    const fn with_reducer(mut self) -> Self {
        self.has_reducer = true;
        self
    }
}

impl Plugin for OwnerPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: self.owned.iter().copied().map(Kind::new).collect(),
            has_reducer: self.has_reducer,
            ..Capability::default()
        }
    }
}

struct CountReducer;

impl Reducer for CountReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _state: &mut State, _event: &Event) {}
}

struct IdleDriver;

impl Driver for IdleDriver {
    fn name(&self) -> &'static str {
        "idle-test-driver"
    }

    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}

/// Everything a rejected registration must leave untouched.
#[derive(Debug, PartialEq, Eq)]
struct RegistrySnapshot {
    composition: PluginComposition,
    descriptions: Vec<(String, String)>,
    plugin_count: usize,
    driver_count: usize,
    /// Owned Event types and exact retained closure bytes, one row per Plugin.
    ownership: Vec<(Vec<String>, Option<Vec<u8>>)>,
}

fn snapshot(registry: &PluginRegistry) -> RegistrySnapshot {
    let mut descriptions: Vec<(String, String)> = registry
        .schemas
        .iter()
        .map(|schema| {
            (
                schema.event_type.as_str().to_owned(),
                schema.description.clone(),
            )
        })
        .collect();
    descriptions.sort();
    RegistrySnapshot {
        composition: registry.composition(),
        descriptions,
        plugin_count: registry.len(),
        driver_count: registry.driver_count(),
        ownership: registry.plugin_ownership_rows(),
    }
}

fn owner_error(event_type: &str) -> String {
    RuntimeError::Composition(PluginCompositionErrorV1::DuplicateEventTypeOwner {
        event_type: event_type.to_owned(),
    })
    .to_string()
}

fn generated_binding<P: Plugin>(plugin: &P) -> OutputPolicyBindingV1 {
    OutputPolicyBindingV1::from_source(
        plugin,
        OutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )
    .test_ok()
}

fn register(registry: &mut PluginRegistry, plugin: &OwnerPlugin) -> Result<(), RuntimeError> {
    let reducer: Option<Box<dyn Reducer>> = if plugin.has_reducer {
        Some(Box::new(CountReducer))
    } else {
        None
    };
    registry.register_generated(plugin, reducer, None)
}

#[test]
fn a_second_claimant_is_rejected_in_either_order_and_leaves_the_registry_unchanged() {
    for first_is_alpha in [true, false] {
        let alpha = OwnerPlugin::new("alpha", &["alpha.only", "shared.type"]).with_reducer();
        let beta = OwnerPlugin::new("beta", &["beta.only", "shared.type"]).with_reducer();
        let (first, second) = if first_is_alpha {
            (&alpha, &beta)
        } else {
            (&beta, &alpha)
        };
        let mut registry = PluginRegistry::new();
        register(&mut registry, first).test_ok();
        let before = snapshot(&registry);

        let error = register(&mut registry, second)
            .err()
            .map(|error| error.to_string());

        assert_eq!(error, Some(owner_error("shared.type")));
        assert_eq!(snapshot(&registry), before);
        // A corrected declaration is a new registration and succeeds.
        let corrected = OwnerPlugin::new("corrected", &["corrected.only"]);
        register(&mut registry, &corrected).test_ok();
        assert_eq!(registry.len(), 2);
    }
}

#[test]
fn a_declaration_listing_a_type_twice_is_rejected_before_any_other_check() {
    let duplicate = OwnerPlugin::new("duplicate", &["dup.type", "dup.type"]);
    // The binding belongs to another Plugin, so every later registration
    // check would also fail; the ownership check runs first.
    let other = OwnerPlugin::new("other", &["dup.type"]);
    let mut registry = PluginRegistry::new();
    let before = snapshot(&registry);

    let error = registry
        .register_with_verified_output_policy(&duplicate, generated_binding(&other), None, None)
        .err()
        .map(|error| error.to_string());

    assert_eq!(error, Some(owner_error("dup.type")));
    assert_eq!(snapshot(&registry), before);
}

fn pinned_registration(byte: u8) -> PluginRegistrationV1 {
    PluginRegistrationV1::new(
        PluginPinV1::try_new(
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::OperatorTrustedNative,
            Hash::from_bytes([byte; 32]),
            vec![format!("duplicate-role-{byte}")],
        )
        .test_ok(),
        PluginAvailabilityV1::Available,
    )
}

/// The test-support Driver path takes a binding built from the Plugin.
fn register_test_driver(
    registry: &mut PluginRegistry,
    plugin: &OwnerPlugin,
) -> Result<(), RuntimeError> {
    OutputPolicyBindingV1::from_source(
        plugin,
        OutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )
    .map_err(RuntimeError::from)
    .and_then(|binding| {
        registry.register_test_driver_with_verified_output_policy(
            plugin.id,
            binding,
            Box::new(IdleDriver),
        )
    })
}

/// Register `plugin` through one named public registration path.
fn register_on_path(
    registry: &mut PluginRegistry,
    path: &str,
    plugin: &OwnerPlugin,
) -> Result<(), RuntimeError> {
    let slot = ManifestSlotV1::try_new("duplicate-local")?;
    match path {
        "generated" => registry.register_generated(plugin, None, None),
        "generated-with-approver" => {
            registry.register_generated_with_approver(plugin, None, None, None, std::iter::empty())
        }
        "pinned" => registry.register_pinned_generated(plugin, pinned_registration(1), None, None),
        "pinned-with-approver" => registry.register_pinned_generated_with_approver(
            plugin,
            pinned_registration(2),
            None,
            None,
            None,
            std::iter::empty(),
        ),
        "local" => {
            registry.register_local(plugin, slot, vec!["duplicate-local".to_owned()], None, None)
        }
        _ => register_test_driver(registry, plugin),
    }
}

/// ADR-024 Revision 1 (#505): a declaration that lists one type twice fails
/// with the closed ownership error on every registration path that builds
/// its own binding, before any policy is constructed, and leaves the
/// registry unchanged.
#[test]
fn a_declaration_listing_a_type_twice_fails_with_the_ownership_error_on_every_path() {
    for path in [
        "generated",
        "generated-with-approver",
        "pinned",
        "pinned-with-approver",
        "local",
        "test-driver",
    ] {
        let duplicate = OwnerPlugin::new("duplicate", &["dup.other", "dup.type", "dup.type"]);
        let mut registry = PluginRegistry::new();
        let before = snapshot(&registry);

        let error = register_on_path(&mut registry, path, &duplicate);

        assert!(
            matches!(
                error,
                Err(RuntimeError::Composition(
                    PluginCompositionErrorV1::DuplicateEventTypeOwner { ref event_type }
                )) if event_type == "dup.type"
            ),
            "{path}: {error:?}"
        );
        assert_eq!(snapshot(&registry), before, "{path}");
    }
}

/// The binding constructor itself reports the duplicate declaration as the
/// closed ownership error, which the runtime error keeps as a composition
/// error rather than an output-admission error.
#[test]
fn binding_construction_reports_a_duplicate_declaration_as_the_ownership_error() {
    let duplicate = OwnerPlugin::new("duplicate", &["dup.type", "dup.type"]);
    let error = OutputPolicyBindingV1::from_source(
        &duplicate,
        OutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )
    .err();
    let closed = PluginCompositionErrorV1::DuplicateEventTypeOwner {
        event_type: "dup.type".to_owned(),
    };
    assert_eq!(
        error,
        Some(OutputAdmissionErrorV1::Composition(closed.clone()))
    );
    assert!(matches!(
        error.map(RuntimeError::from),
        Some(RuntimeError::Composition(ref inner)) if *inner == closed
    ));
    assert!(matches!(
        RuntimeError::from(OutputAdmissionErrorV1::PluginMismatch),
        RuntimeError::OutputAdmission(OutputAdmissionErrorV1::PluginMismatch)
    ));
    // A declaration without a duplicate still builds its binding.
    let distinct = OwnerPlugin::new("distinct", &["dup.other", "dup.type"]);
    let built = OutputPolicyBindingV1::from_source(
        &distinct,
        OutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    );
    assert!(built.is_ok());
}

#[test]
fn the_recorder_type_has_one_claimant_and_keeps_the_host_schema() {
    let mut registry = PluginRegistry::new();
    let host_description = |registry: &PluginRegistry| {
        registry
            .schemas
            .iter()
            .find(|schema| schema.event_type.as_str() == RECORDER_EVENT_TYPE)
            .map(|schema| schema.description.clone())
    };
    let before = host_description(&registry);
    assert!(before.is_some());

    let agent = OwnerPlugin::new("recording-agent", &[RECORDER_EVENT_TYPE, "agent.recorded"]);
    register(&mut registry, &agent).test_ok();
    assert_eq!(host_description(&registry), before);

    let rival = OwnerPlugin::new("rival-recorder", &[RECORDER_EVENT_TYPE]);
    let state = snapshot(&registry);
    let error = register(&mut registry, &rival)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, Some(owner_error(RECORDER_EVENT_TYPE)));
    assert_eq!(snapshot(&registry), state);
}

#[test]
fn a_non_claimable_host_type_is_rejected_on_every_path() {
    let consent = OwnerPlugin::new(
        "consent-claimant",
        &[pos_core::EVENT_TYPE_CONSENT_REVOKED_V1],
    );
    let mut registry = PluginRegistry::new();
    let before = snapshot(&registry);

    // The Plugin path keeps its reserved consent error, which runs first.
    assert!(matches!(
        register(&mut registry, &consent),
        Err(RuntimeError::ReservedConsentEventType { .. })
    ));
    assert_eq!(snapshot(&registry), before);

    // The test-support Driver path derives its types from the binding and
    // reaches the shared ownership check.
    let error = registry
        .register_test_driver_with_verified_output_policy(
            consent.id,
            generated_binding(&consent),
            Box::new(IdleDriver),
        )
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        error,
        Some(owner_error(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1))
    );
    assert_eq!(snapshot(&registry), before);
}

#[test]
fn test_support_driver_registrations_share_the_ownership_check() {
    let plugin = OwnerPlugin::new("plugin-owner", &["shared.type"]);
    let driver_owner = OwnerPlugin::new("driver-owner", &["shared.type"]);

    // A Plugin first, then a Driver claiming the same type.
    let mut registry = PluginRegistry::new();
    register(&mut registry, &plugin).test_ok();
    let before = snapshot(&registry);
    let error = registry
        .register_test_driver_with_verified_output_policy(
            driver_owner.id,
            generated_binding(&driver_owner),
            Box::new(IdleDriver),
        )
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, Some(owner_error("shared.type")));
    assert_eq!(snapshot(&registry), before);

    // A Driver first, then a Plugin claiming the same type.
    let mut registry = PluginRegistry::new();
    registry
        .register_test_driver_with_verified_output_policy(
            driver_owner.id,
            generated_binding(&driver_owner),
            Box::new(IdleDriver),
        )
        .test_ok();
    let before = snapshot(&registry);
    let error = register(&mut registry, &plugin)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, Some(owner_error("shared.type")));
    assert_eq!(snapshot(&registry), before);

    // The same registration identity is a duplicate Plugin, not a new claimant.
    assert!(matches!(
        registry.register_test_driver_with_verified_output_policy(
            driver_owner.id,
            generated_binding(&driver_owner),
            Box::new(IdleDriver),
        ),
        Err(RuntimeError::DuplicatePlugin { .. })
    ));
    assert_eq!(snapshot(&registry), before);

    // Distinct types coexist.
    let distinct = OwnerPlugin::new("distinct-owner", &["distinct.type"]);
    registry
        .register_test_driver_with_verified_output_policy(
            distinct.id,
            generated_binding(&distinct),
            Box::new(IdleDriver),
        )
        .test_ok();
    assert_eq!(registry.driver_count(), 2);
}
