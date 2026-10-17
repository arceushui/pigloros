use std::collections::BTreeSet;
use std::error::Error;
use std::time::Duration;

use pos_core::output_policy::{OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1};
use pos_core::{Capability, EntityId, ImplementationKeyV1};
use pos_crypto::plugin_execution::{PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1};

use super::*;
use crate::{PluginExecutionModeV1, RequiredPluginCompositionV1};

type TestResult = Result<(), Box<dyn Error>>;
type Facts = FallbackCandidateFactsV1;
type Field = FallbackValidationFieldV1;

const ENTRY: &str = "weather";
const OWNED: &str = "acme.weather.v1";
const LOCAL: PluginExecutionModeV1 = PluginExecutionModeV1::Local;

struct FactsPlugin {
    id: PluginId,
    name: &'static str,
    version: &'static str,
    owned: &'static [&'static str],
    has_driver: bool,
}

impl Plugin for FactsPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: self.owned.iter().copied().map(Kind::new).collect(),
            owned_entity_kinds: Vec::new(),
            has_driver: self.has_driver,
            has_reducer: false,
        }
    }

    fn version(&self) -> &'static str {
        self.version
    }
}

fn plugin(name: &'static str, version: &'static str) -> FactsPlugin {
    FactsPlugin {
        id: PluginId::new(),
        name,
        version,
        owned: &[OWNED],
        has_driver: true,
    }
}

fn pin(plugin_id: &str, version: &str, digest: u8) -> Result<CompositionPinV1, Box<dyn Error>> {
    let key = ImplementationKeyV1::new(
        plugin_id.to_owned(),
        version.to_owned(),
        Hash::from_bytes([digest; 32]),
    )?;
    Ok(CompositionPinV1::new(key, vec![ENTRY.to_owned()])?)
}

fn descriptor(capability_id: &str) -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: capability_id.to_owned(),
        operation: "read".to_owned(),
        resource_pattern: "weather/*".to_owned(),
        purpose: "forecast".to_owned(),
        audience: "local".to_owned(),
        required: false,
        max_calls: 4,
        max_request_bytes: 64,
        max_response_bytes: 64,
    }
}

fn execution(pin: &CompositionPinV1) -> FallbackExecutionFactsV1 {
    let key = pin.implementation();
    FallbackExecutionFactsV1 {
        plugin_id: key.plugin_id().to_owned(),
        release_digest: key.release_digest(),
        capabilities: vec![descriptor("weather.read")],
        budget: DeterministicBudgetV1::MAXIMA,
    }
}

fn host(pin: &CompositionPinV1) -> FallbackHostFactsV1 {
    FallbackHostFactsV1 {
        active_release_digest: Some(pin.implementation().release_digest()),
        publisher: Some("acme-publisher".to_owned()),
        namespace_grants: vec!["acme".to_owned()],
        conformance_profiles: BTreeSet::from([Hash::from_bytes([9; 32])]),
    }
}

fn settings(key: &ProjectionKey) -> FallbackDriverSettingsV1 {
    FallbackDriverSettingsV1 {
        tick_interval: Duration::from_millis(100),
        subscriptions: vec![key.clone()],
    }
}

fn facts(
    plugin: &FactsPlugin,
    pin: CompositionPinV1,
    key: &ProjectionKey,
) -> Result<Facts, RuntimeError> {
    let execution = execution(&pin);
    let host = host(&pin);
    Facts::collect(plugin, pin, settings(key), execution, host)
}

struct Fixture {
    primary: Facts,
    candidate: Facts,
    composition: RequiredPluginCompositionV1,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let key = ProjectionKey::new(EntityId::new());
    let primary_pin = pin("acme.primary", "1.0.0", 1)?;
    let primary = facts(&plugin("primary", "1.0.0"), primary_pin, &key)?;
    let candidate_pin = pin("acme.candidate", "2.0.0", 2)?;
    let candidate = facts(&plugin("candidate", "2.0.0"), candidate_pin, &key)?;
    let other_pin = community_pin_v1(Hash::from_bytes([3; 32]), vec!["other".to_owned()])?;
    let other = RequiredPluginV1::try_new(PluginId::new(), "1.0.0", other_pin)?;
    let primary_required = required_plugin_v1(primary.registry.plugin_id, &primary.pin)?;
    let composition = RequiredPluginCompositionV1::try_new(LOCAL, vec![primary_required, other])?;
    Ok(Fixture {
        primary,
        candidate,
        composition,
    })
}

impl Fixture {
    fn refusal(&self) -> Option<Field> {
        validate_fallback_candidate_v1(ENTRY, &self.composition, &self.primary, &self.candidate)
            .err()
            .map(|error| error.field)
    }

    /// The refusal after `edit` changes the candidate.
    fn refusal_after(mut self, edit: impl FnOnce(&mut Facts)) -> Option<Field> {
        edit(&mut self.candidate);
        self.refusal()
    }

    /// The refusal after `edit` changes the primary.
    fn primary_refusal_after(mut self, edit: impl FnOnce(&mut Facts)) -> Option<Field> {
        edit(&mut self.primary);
        self.refusal()
    }
}

fn declaration(
    authority: OutputAuthorityV1,
    fidelity: OutputFidelityV1,
    max_bytes: u32,
    stride: Option<u32>,
    group: Option<u32>,
) -> Result<OutputDeclarationV1, Box<dyn Error>> {
    Ok(OutputDeclarationV1::new(
        OWNED.to_owned(),
        authority,
        fidelity,
        max_bytes,
        stride,
        group,
    )?)
}

#[test]
fn shell_answers_from_settings_and_is_never_stepped() {
    let key = ProjectionKey::new(EntityId::new());
    let mut shell = FallbackDriverShellV1::new("shell", settings(&key));
    assert_eq!(shell.name(), "shell");
    assert_eq!(shell.tick_interval(), Duration::from_millis(100));
    assert_eq!(shell.subscriptions(), [key].as_slice());
    let step = shell.step(TimelineId::new(), ObservationView::empty());
    let refused = matches!(step, Err(RuntimeError::CapabilityMismatch { .. }));
    assert!(refused, "{step:?}");
    assert!(format!("{shell:?}").contains("shell"));
}

#[test]
fn scratch_facts_come_from_the_registered_entry() -> TestResult {
    let key = ProjectionKey::new(EntityId::new());
    let pin = pin("acme.primary", "1.0.0", 1)?;
    let plugin = plugin("primary", "1.0.0");
    let registry = PluginRegistry::fallback_scratch_facts_v1(&plugin, &pin, settings(&key))?;
    let community = community_pin_v1(Hash::from_bytes([1; 32]), vec![ENTRY.to_owned()])?;
    let non_participant = Some(ScheduledDriverBindingV1::NonParticipant);
    assert_eq!(registry.plugin_id(), plugin.id);
    assert_eq!(registry.version, "1.0.0");
    assert_eq!(registry.pin, Some(community));
    assert_eq!(registry.owned_event_types, vec![OWNED.to_owned()]);
    assert_eq!(registry.schemas, vec![None::<String>]);
    assert_eq!(registry.outputs.len(), 1);
    assert_eq!(registry.cpu_reservations_us, Some([10; 3]));
    assert_eq!(registry.subscriptions, vec![key]);
    assert!(registry.event_subscriptions.is_empty());
    assert_eq!(registry.driver_interval, Some(Duration::from_millis(100)));
    assert_eq!(registry.binding, non_participant);
    let copy = registry.clone();
    assert_eq!(copy, registry);
    assert!(format!("{copy:?}").contains(OWNED));
    Ok(())
}

#[test]
fn scratch_registration_refuses_a_bad_pin_or_a_bad_plugin() -> TestResult {
    let key = ProjectionKey::new(EntityId::new());
    let zero = pin("acme.primary", "1.0.0", 0)?;
    let primary = plugin("primary", "1.0.0");
    let result = PluginRegistry::fallback_scratch_facts_v1(&primary, &zero, settings(&key));
    let refused = matches!(result, Err(RuntimeError::Composition(_)));
    assert!(refused, "{result:?}");
    let mut driverless = plugin("driverless", "1.0.0");
    driverless.has_driver = false;
    let collected = facts(&driverless, pin("acme.primary", "1.0.0", 1)?, &key);
    let refused = matches!(collected, Err(RuntimeError::CapabilityMismatch { .. }));
    assert!(refused, "{collected:?}");
    Ok(())
}

#[test]
fn derived_facts_and_errors_are_comparable_and_printable() -> TestResult {
    let fixture = fixture()?;
    let copy = fixture.candidate.clone();
    assert_eq!(copy, fixture.candidate);
    assert!(format!("{copy:?}").contains("acme.candidate"));
    let settings = settings(&ProjectionKey::new(EntityId::new()));
    assert_eq!(settings.clone(), settings);
    assert!(format!("{settings:?}").contains("100ms"));
    assert_eq!(FallbackHostFactsV1::default().active_release_digest, None);
    let error = InvalidFallbackPolicyV1 {
        entry_key: ENTRY.to_owned(),
        field: Field::Admission,
    };
    assert_eq!(error.clone(), error);
    assert!(error.to_string().contains("'weather': Admission"));
    assert!(format!("{error:?}").contains("Admission"));
    assert_ne!(Field::Identity, Field::Roles);
    Ok(())
}

#[test]
fn execution_facts_come_from_the_projection() {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: "acme.primary".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 1,
            required_features: Vec::new(),
        },
        capabilities: vec![descriptor("weather.read")],
        budget: DeterministicBudgetV1::MINIMA,
    };
    let projection = PluginExecutionProjectionV1::from(fixture);
    let facts = FallbackExecutionFactsV1::from_projection(&projection);
    assert_eq!(facts.plugin_id, "acme.primary");
    assert_eq!(facts.release_digest, Hash::from_bytes([0x22; 32]));
    assert_eq!(facts.capabilities, vec![descriptor("weather.read")]);
    assert_eq!(facts.budget, DeterministicBudgetV1::MINIMA);
}

#[test]
fn required_plugin_is_derived_from_imk1() -> TestResult {
    let id = PluginId::new();
    let required = required_plugin_v1(id, &pin("acme.primary", "1.0.0", 1)?)?;
    let community = community_pin_v1(Hash::from_bytes([1; 32]), vec![ENTRY.to_owned()])?;
    assert_eq!(required.plugin_id(), id);
    assert_eq!(required.version(), "1.0.0");
    assert_eq!(required.pin(), &community);
    let zero = pin("acme.primary", "1.0.0", 0)?;
    assert!(required_plugin_v1(id, &zero).is_err());
    Ok(())
}

#[test]
fn required_plugin_enforcement_binds_version_and_digest() -> TestResult {
    let pin = pin("acme.primary", "1.0.0", 1)?;
    let roles = vec![ENTRY.to_owned()];
    let registered = community_pin_v1(Hash::from_bytes([1; 32]), roles.clone())?;
    let other = community_pin_v1(Hash::from_bytes([2; 32]), roles)?;
    let enforce = |version: &str, registered: Option<&PluginPinV1>| {
        enforce_required_plugin_v1(version, registered, &pin)
    };
    assert_eq!(enforce("1.0.0", Some(&registered)), Ok(()));
    assert_eq!(enforce("1.0.1", Some(&registered)), Err(Field::Version));
    let digest = Err(Field::ConfigurationDigest);
    assert_eq!(enforce("1.0.0", Some(&other)), digest);
    assert_eq!(enforce("1.0.0", None), digest);
    Ok(())
}

#[test]
fn a_matching_candidate_validates() -> TestResult {
    assert_eq!(fixture()?.refusal(), None);
    let superset = fixture()?.refusal_after(|candidate| {
        let profile = Hash::from_bytes([8; 32]);
        candidate.host.conformance_profiles.insert(profile);
        candidate.execution.budget = DeterministicBudgetV1::MINIMA;
    });
    assert_eq!(superset, None);
    Ok(())
}

#[test]
fn rule_one_identity() -> TestResult {
    let foreign = fixture()?.refusal_after(|candidate| {
        candidate.execution.plugin_id = "acme.other".to_owned();
    });
    assert_eq!(foreign, Some(Field::Identity));
    let digest = fixture()?.primary_refusal_after(|primary| {
        primary.execution.release_digest = Hash::from_bytes([7; 32]);
    });
    assert_eq!(digest, Some(Field::Identity));
    Ok(())
}

#[test]
fn rule_one_roles_and_distinctness() -> TestResult {
    let fixture_roles = fixture()?;
    let key = fixture_roles.candidate.pin.implementation().clone();
    let extra = vec![ENTRY.to_owned(), "extra".to_owned()];
    let roles = CompositionPinV1::new(key.clone(), extra)?;
    let refused = fixture_roles.refusal_after(|candidate| {
        candidate.pin = roles;
    });
    assert_eq!(refused, Some(Field::Roles));
    let other = CompositionPinV1::new(key, vec!["other".to_owned()])?;
    let refused = fixture()?.refusal_after(|candidate| {
        candidate.pin = other;
    });
    assert_eq!(refused, Some(Field::Roles));
    let fixture_same = fixture()?;
    let same = fixture_same.primary.pin.clone();
    let shared_text = fixture_same.refusal_after(|candidate| {
        candidate.execution = execution(&same);
        candidate.pin = same;
    });
    assert_eq!(shared_text, Some(Field::Distinctness));
    let fixture_id = fixture()?;
    let primary_id = fixture_id.primary.registry.plugin_id;
    let shared_id = fixture_id.refusal_after(|candidate| {
        candidate.registry.plugin_id = primary_id;
    });
    assert_eq!(shared_id, Some(Field::Distinctness));
    Ok(())
}

#[test]
fn required_plugin_binding_is_enforced_for_both() -> TestResult {
    let version = fixture()?.refusal_after(|candidate| {
        candidate.registry.version = "9.0.0".to_owned();
    });
    assert_eq!(version, Some(Field::Version));
    let digest = fixture()?.primary_refusal_after(|primary| {
        primary.registry.pin = None;
    });
    assert_eq!(digest, Some(Field::ConfigurationDigest));
    Ok(())
}

#[test]
fn rule_one_effective_composition() -> TestResult {
    let mut missing = fixture()?;
    let other = missing.composition.plugins()[1].clone();
    missing.composition = RequiredPluginCompositionV1::try_new(LOCAL, vec![other])?;
    assert_eq!(missing.refusal(), Some(Field::Composition));
    let duplicate = fixture()?;
    let other_id = duplicate.composition.plugins()[1].plugin_id();
    let refused = duplicate.refusal_after(|candidate| {
        candidate.registry.plugin_id = other_id;
    });
    assert_eq!(refused, Some(Field::Composition));
    let nil = PluginId::from_ulid(ulid::Ulid::nil());
    let invalid = fixture()?.refusal_after(|candidate| {
        candidate.registry.plugin_id = nil;
    });
    assert_eq!(invalid, Some(Field::Composition));
    Ok(())
}

#[test]
fn rule_two_event_types_and_schemas() -> TestResult {
    let types = fixture()?.refusal_after(|candidate| {
        candidate.registry.owned_event_types = vec!["acme.other.v1".to_owned()];
    });
    assert_eq!(types, Some(Field::EventTypes));
    let schemas = fixture()?.refusal_after(|candidate| {
        candidate.registry.schemas = vec![Some("{}".to_owned())];
    });
    assert_eq!(schemas, Some(Field::Schemas));
    Ok(())
}

#[test]
fn rule_two_output_policy() -> TestResult {
    let authoritative = OutputAuthorityV1::Authoritative;
    let derived = OutputAuthorityV1::ReproducibleDerived;
    let l0 = OutputFidelityV1::L0;
    let lowered = declaration(authoritative, l0, 1_024, None, None)?;
    let accepted = fixture()?.refusal_after(|candidate| {
        candidate.registry.outputs = vec![lowered];
    });
    assert_eq!(accepted, None);
    for outputs in [
        vec![declaration(authoritative, l0, 8_192, None, None)?],
        vec![declaration(derived, l0, 1_024, None, None)?],
        Vec::new(),
    ] {
        let refused = fixture()?.refusal_after(|candidate| {
            candidate.registry.outputs = outputs;
        });
        assert_eq!(refused, Some(Field::OutputPolicy));
    }
    Ok(())
}

#[test]
fn rule_two_output_fidelity_metadata() -> TestResult {
    let derived = OutputAuthorityV1::ReproducibleDerived;
    let (l1, l2) = (OutputFidelityV1::L1, OutputFidelityV1::L2);
    let pairs = [
        (
            declaration(derived, l1, 1_024, Some(2), None)?,
            declaration(derived, l1, 1_024, Some(3), None)?,
        ),
        (
            declaration(derived, l2, 1_024, None, Some(10))?,
            declaration(derived, l2, 1_024, None, Some(11))?,
        ),
        (
            declaration(derived, l1, 1_024, Some(2), None)?,
            declaration(derived, l2, 1_024, None, Some(10))?,
        ),
    ];
    for (primary, candidate) in pairs {
        let mut fixture = fixture()?;
        fixture.primary.registry.outputs = vec![primary];
        let refused = fixture.refusal_after(|facts| {
            facts.registry.outputs = vec![candidate];
        });
        assert_eq!(refused, Some(Field::OutputPolicy));
    }
    Ok(())
}

#[test]
fn rule_two_same_publisher_needs_no_grant() -> TestResult {
    let accepted = fixture()?.refusal_after(|candidate| {
        candidate.host.namespace_grants.clear();
    });
    assert_eq!(accepted, None);
    Ok(())
}

#[test]
fn rule_two_cross_publisher_needs_a_grant_for_every_type() -> TestResult {
    let granted = fixture()?.refusal_after(|candidate| {
        candidate.host.publisher = Some("other-publisher".to_owned());
    });
    assert_eq!(granted, None);
    let ungranted = fixture()?.refusal_after(|candidate| {
        candidate.host.publisher = Some("other-publisher".to_owned());
        candidate.host.namespace_grants.clear();
    });
    assert_eq!(ungranted, Some(Field::Namespace));
    let unprefixed = fixture()?.refusal_after(|candidate| {
        candidate.host.publisher = Some("other-publisher".to_owned());
        candidate.host.namespace_grants = vec!["acm".to_owned(), "other".to_owned()];
    });
    assert_eq!(unprefixed, Some(Field::Namespace));
    Ok(())
}

#[test]
fn rule_two_an_unattributed_publisher_is_cross_publisher() -> TestResult {
    let mut unattributed = fixture()?;
    unattributed.primary.host.publisher = None;
    let refused = unattributed.refusal_after(|candidate| {
        candidate.host.publisher = None;
        candidate.host.namespace_grants.clear();
    });
    assert_eq!(refused, Some(Field::Namespace));
    let mut granted = fixture()?;
    granted.primary.host.publisher = None;
    assert_eq!(granted.refusal(), None);
    Ok(())
}

#[test]
fn rule_three_capabilities_and_subscriptions() -> TestResult {
    let capability = fixture()?.refusal_after(|candidate| {
        let write = descriptor("weather.write");
        candidate.execution.capabilities.push(write);
    });
    assert_eq!(capability, Some(Field::Capabilities));
    let projection = fixture()?.refusal_after(|candidate| {
        let key = ProjectionKey::new(EntityId::new());
        candidate.registry.subscriptions.push(key);
    });
    assert_eq!(projection, Some(Field::Subscriptions));
    let event = fixture()?.refusal_after(|candidate| {
        candidate
            .registry
            .event_subscriptions
            .push(Kind::new(OWNED));
    });
    assert_eq!(event, Some(Field::Subscriptions));
    let fewer = fixture()?.refusal_after(|candidate| {
        candidate.execution.capabilities.clear();
        candidate.registry.subscriptions.clear();
    });
    assert_eq!(fewer, None);
    Ok(())
}

#[test]
fn rule_four_budgets() -> TestResult {
    let mut lowered = fixture()?;
    lowered.primary.execution.budget = DeterministicBudgetV1::MINIMA;
    assert_eq!(lowered.refusal(), Some(Field::Budgets));
    let cpu = fixture()?.refusal_after(|candidate| {
        candidate.registry.cpu_reservations_us = Some([11; 3]);
    });
    assert_eq!(cpu, Some(Field::Budgets));
    let missing = fixture()?.refusal_after(|candidate| {
        candidate.registry.cpu_reservations_us = None;
    });
    assert_eq!(missing, Some(Field::Budgets));
    let unreserved = fixture()?.primary_refusal_after(|primary| {
        primary.registry.cpu_reservations_us = None;
    });
    assert_eq!(unreserved, Some(Field::Budgets));
    Ok(())
}

#[test]
fn rule_five_profile_and_interval() -> TestResult {
    let participant = ScheduledDriverBindingV1::Participant(EntityId::new());
    let bound = fixture()?.refusal_after(|candidate| {
        candidate.registry.binding = Some(participant);
    });
    assert_eq!(bound, Some(Field::Profile));
    let unbound = fixture()?.primary_refusal_after(|primary| {
        primary.registry.binding = None;
    });
    assert_eq!(unbound, Some(Field::Profile));
    let interval = fixture()?.refusal_after(|candidate| {
        candidate.registry.driver_interval = Some(Duration::from_millis(50));
    });
    assert_eq!(interval, Some(Field::DriverInterval));
    Ok(())
}

#[test]
fn rule_six_admission() -> TestResult {
    let inactive = fixture()?.refusal_after(|candidate| {
        candidate.host.active_release_digest = None;
    });
    assert_eq!(inactive, Some(Field::Admission));
    let other = fixture()?.refusal_after(|candidate| {
        candidate.host.active_release_digest = Some(Hash::from_bytes([5; 32]));
    });
    assert_eq!(other, Some(Field::Admission));
    Ok(())
}

#[test]
fn rule_seven_conformance_parity() -> TestResult {
    let missing = fixture()?.refusal_after(|candidate| {
        candidate.host.conformance_profiles.clear();
    });
    assert_eq!(missing, Some(Field::Conformance));
    let mut newer = fixture()?;
    newer.primary.host.conformance_profiles = BTreeSet::from([Hash::from_bytes([4; 32])]);
    assert_eq!(newer.refusal(), Some(Field::Conformance));
    let mut empty = fixture()?;
    empty.primary.host.conformance_profiles.clear();
    let accepted = empty.refusal_after(|candidate| {
        candidate.host.conformance_profiles.clear();
    });
    assert_eq!(accepted, None);
    Ok(())
}

#[test]
fn a_refusal_names_the_entry() -> TestResult {
    let fixture = fixture()?;
    let mut candidate = fixture.candidate.clone();
    candidate.host.active_release_digest = None;
    let (composition, primary) = (&fixture.composition, &fixture.primary);
    let error = validate_fallback_candidate_v1("slot-a", composition, primary, &candidate);
    let expected = InvalidFallbackPolicyV1 {
        entry_key: "slot-a".to_owned(),
        field: Field::Admission,
    };
    assert_eq!(error, Err(expected));
    Ok(())
}

#[test]
fn a_driverless_unpinned_entry_has_no_driver_facts() -> TestResult {
    let plugin = FactsPlugin {
        owned: &["acme.zeta.v1", "acme.alpha.v1"],
        has_driver: false,
        ..plugin("driverless", "1.0.0")
    };
    let mut registry = PluginRegistry::new();
    registry.register_generated(&plugin, None, None)?;
    let facts = registry.fallback_registry_facts_v1(plugin.id)?;
    assert_eq!(facts.owned_event_types, ["acme.alpha.v1", "acme.zeta.v1"]);
    assert_eq!(facts.schemas, vec![None::<String>, None]);
    assert_eq!(facts.outputs.len(), 2);
    assert_eq!(facts.cpu_reservations_us, Some([10; 3]));
    assert_eq!(facts.pin, None);
    assert!(facts.subscriptions.is_empty());
    assert_eq!(facts.driver_interval, None);
    assert_eq!(facts.binding, None);
    Ok(())
}

#[test]
fn an_entry_without_an_output_admission_has_no_reservation() -> TestResult {
    let mut registry = PluginRegistry::new();
    let key = ProjectionKey::new(EntityId::new());
    let shell = FallbackDriverShellV1::new("undeclared", settings(&key));
    registry.register_driver(Box::new(shell))?;
    let composition = registry.composition();
    let id = composition.plugins[0].id;
    let facts = registry.fallback_registry_facts_v1(id)?;
    assert_eq!(facts.cpu_reservations_us, None);
    assert!(facts.outputs.is_empty());
    assert_eq!(facts.driver_interval, Some(Duration::from_millis(100)));
    assert_eq!(facts.subscriptions, vec![key]);
    Ok(())
}

#[test]
fn an_unregistered_plugin_has_no_facts() {
    let registry = PluginRegistry::new();
    let facts = registry.fallback_registry_facts_v1(PluginId::new());
    let refused = matches!(facts, Err(RuntimeError::NoDriver { .. }));
    assert!(refused, "{facts:?}");
}

#[test]
fn a_reserved_type_is_refused_on_the_facts_only_path() -> TestResult {
    let reserved = FactsPlugin {
        owned: &[pos_core::COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1],
        ..plugin("reserved", "1.0.0")
    };
    let key = ProjectionKey::new(EntityId::new());
    let pin = pin("acme.reserved", "1.0.0", 1)?;
    let facts = PluginRegistry::fallback_scratch_facts_v1(&reserved, &pin, settings(&key));
    let refused = matches!(facts, Err(RuntimeError::ReservedHostEventType { .. }));
    assert!(refused, "{facts:?}");
    Ok(())
}
