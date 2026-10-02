//! ADR-024 Revision 1 exclusive Event-type ownership through every public
//! registration path (#486).

use std::sync::{atomic::AtomicUsize, Arc};

use pos_core::{
    ActionApprover, CanonicalBytes, EntityId, Hash, Kind, Plugin, ProposedAction, TimelineId,
    EVENT_TYPE_CONSENT_REVOKED_V1,
};
use pos_plugin_agent::AgentPlugin;
use pos_plugin_persona::PersonaPlugin;
use pos_plugin_society::{SocietyPlugin, EVENT_TYPE_SIGNAL};
use pos_plugin_world::{WorldPlugin, EVENT_TYPE_ACTION_V1};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, DomainImplementationKindV1, InstalledOutputPolicySourceV1,
    OutputAdmissionErrorV1, OutputPolicyBindingV1, PluginAvailabilityV1, PluginComposition,
    PluginIsolationV1, PluginPinV1, PluginRegistrationV1, PluginRegistry, RuntimeError,
};

use super::{
    harness::Capture,
    support::{gated_registry, CountingApprover, FixturePlugin, ScriptedDriver, TestOk},
};

/// Every public registration path that installs owned Event types.
const PATHS: [&str; 9] = [
    "generated",
    "generated-with-approver",
    "pinned",
    "pinned-with-approver",
    "verified",
    "verified-with-approver",
    "test-driver",
    "installed",
    "manifest-slot",
];

/// Everything a rejected registration must leave untouched.
#[derive(Debug, PartialEq, Eq)]
struct RegistrySnapshot {
    composition: PluginComposition,
    descriptions: Vec<(String, String)>,
    plugins: usize,
    drivers: usize,
    policies: Vec<(String, Hash)>,
    routes: Vec<String>,
}

/// Probe the approver route for each of `event_types`.
fn routes(registry: &PluginRegistry, event_types: &[&str]) -> Vec<String> {
    let timeline = TimelineId::new();
    event_types
        .iter()
        .map(|event_type| {
            let proposal = ProposedAction::new(
                Kind::new(*event_type),
                EntityId::new(),
                CanonicalBytes::from_static(b"probe"),
                Kind::new(format!("{event_type}.submit")),
            );
            registry
                .submit_action(timeline, &proposal)
                .map_or_else(|error| error.to_string(), |_| "routed".to_owned())
        })
        .collect()
}

fn snapshot(registry: &PluginRegistry, probes: &[&str]) -> RegistrySnapshot {
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
        plugins: registry.len(),
        drivers: registry.driver_count(),
        policies: registry
            .replay_policy_identities()
            .map(|(name, digest)| (name.to_owned(), digest))
            .collect(),
        routes: routes(registry, probes),
    }
}

fn generated_binding<P: Plugin>(plugin: &P) -> Result<OutputPolicyBindingV1, RuntimeError> {
    OutputPolicyBindingV1::from_installed_source(
        plugin,
        InstalledOutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )
    .map_err(RuntimeError::from)
}

fn registration(byte: u8) -> PluginRegistrationV1 {
    PluginRegistrationV1::new(
        PluginPinV1::try_new(
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::OperatorTrustedNative,
            Hash::from_bytes([byte; 32]),
            vec!["conformance".to_owned()],
        )
        .test_ok(),
        PluginAvailabilityV1::Available,
    )
}

fn approver() -> Box<dyn ActionApprover> {
    Box::new(CountingApprover(Arc::new(AtomicUsize::new(0))))
}

fn kinds(plugin: &FixturePlugin) -> Vec<Kind> {
    plugin.owned.iter().copied().map(Kind::new).collect()
}

/// Register `plugin` through one named public path.
fn register(
    registry: &mut PluginRegistry,
    path: &str,
    plugin: &FixturePlugin,
) -> Result<(), RuntimeError> {
    match path {
        "generated" => registry.register_generated(plugin, None, None),
        "generated-with-approver" => registry.register_generated_with_approver(
            plugin,
            None,
            None,
            Some(approver()),
            kinds(plugin),
        ),
        "pinned" => registry.register_pinned_generated(plugin, registration(1), None, None),
        "pinned-with-approver" => registry.register_pinned_generated_with_approver(
            plugin,
            registration(2),
            None,
            None,
            Some(approver()),
            kinds(plugin),
        ),
        "verified" => generated_binding(plugin).and_then(|binding| {
            registry.register_with_verified_output_policy(plugin, binding, None, None)
        }),
        "verified-with-approver" => generated_binding(plugin).and_then(|binding| {
            registry.register_with_verified_output_policy_and_approver(
                plugin,
                binding,
                None,
                None,
                Some(approver()),
                kinds(plugin),
            )
        }),
        "test-driver" => generated_binding(plugin).and_then(|binding| {
            registry.register_test_driver_with_verified_output_policy(
                plugin.id,
                binding,
                Box::new(ScriptedDriver::new("conformance-claimant", Vec::new())),
            )
        }),
        "installed" => generated_binding(plugin).and_then(|binding| {
            registry.register_installed_output(plugin, binding, registration(3), None)
        }),
        _ => generated_binding(plugin).and_then(|binding| {
            registry.register_installed_output_in_manifest_slot(
                plugin,
                binding,
                registration(4),
                None,
                "conformance-slot",
            )
        }),
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

/// An incumbent that owns `shared.type`, with an approver route for it.
fn incumbent_registry() -> PluginRegistry {
    let mut registry = gated_registry(None);
    let alpha = FixturePlugin::new("alpha", &["alpha.only", "shared.type"], false);
    registry
        .register_generated_with_approver(&alpha, None, None, Some(approver()), kinds(&alpha))
        .test_ok();
    registry
}

/// PCF-REG-001: a second claimant of an owned type is rejected on every
/// public registration path and leaves the registry unchanged.
#[must_use]
pub fn second_claimant_rejected() -> Capture {
    let mut capture = Capture::default();
    let probes = ["alpha.only", "shared.type", "beta.only"];
    for path in PATHS {
        let mut registry = incumbent_registry();
        let before = snapshot(&registry, &probes);
        let beta = FixturePlugin::new("beta", &["beta.only", "shared.type"], true);
        let result = register(&mut registry, path, &beta);
        capture.record("none", path, outcome(result));
        capture.record(
            "none",
            &format!("{path}.unchanged"),
            snapshot(&registry, &probes) == before,
        );
    }
    capture
}

/// PCF-REG-002: a declaration that lists one type twice is rejected on every
/// public registration path and leaves the registry unchanged.
#[must_use]
pub fn duplicate_declaration_rejected() -> Capture {
    let mut capture = Capture::default();
    let probes = ["dup.type"];
    for path in PATHS {
        let mut registry = gated_registry(None);
        let before = snapshot(&registry, &probes);
        let duplicate = FixturePlugin::new("duplicate", &["dup.type", "dup.type"], true);
        let result = register(&mut registry, path, &duplicate);
        capture.record("none", path, outcome(result));
        capture.record(
            "none",
            &format!("{path}.unchanged"),
            snapshot(&registry, &probes) == before,
        );
    }
    capture
}

/// PCF-REG-003: a claim on a non-claimable host type is rejected on every
/// public registration path and leaves the registry unchanged.
#[must_use]
pub fn host_type_not_claimable() -> Capture {
    let mut capture = Capture::default();
    let probes = [EVENT_TYPE_CONSENT_REVOKED_V1];
    for path in PATHS {
        let mut registry = gated_registry(None);
        let before = snapshot(&registry, &probes);
        let claimant =
            FixturePlugin::new("consent-claimant", &[EVENT_TYPE_CONSENT_REVOKED_V1], true);
        let result = register(&mut registry, path, &claimant);
        capture.record("none", path, outcome(result));
        capture.record(
            "none",
            &format!("{path}.unchanged"),
            snapshot(&registry, &probes) == before,
        );
    }
    capture
}

/// Register `first`, then `second`; report the second outcome and which
/// registration owns the contested type.
fn race(first: &dyn Plugin, second: &dyn Plugin) -> (String, Vec<String>) {
    let mut registry = gated_registry(None);
    registry.register_generated(first, None, None).test_ok();
    let rejected = outcome(registry.register_generated(second, None, None));
    (
        rejected,
        registry.plugin_names().map(str::to_owned).collect(),
    )
}

/// PCF-REG-004: overlapping Plugins fail closed whatever their registration
/// order.
#[must_use]
pub fn order_independent() -> Capture {
    let mut capture = Capture::default();
    let alpha = FixturePlugin::new("alpha", &["alpha.only", "shared.type"], false);
    let beta = FixturePlugin::new("beta", &["beta.only", "shared.type"], false);
    let (alpha_first, alpha_owner) = race(&alpha, &beta);
    let (beta_first, beta_owner) = race(&beta, &alpha);
    capture.record("none", "alpha-first.second", alpha_first);
    capture.record("none", "alpha-first.registered", alpha_owner.join(","));
    capture.record("none", "beta-first.second", beta_first);
    capture.record("none", "beta-first.registered", beta_owner.join(","));
    capture
}

/// PCF-REG-005: the latent first-party overlaps fail closed in either order:
/// two `AgentPlugin` registrations, two declarers of `world.action.v1`, and
/// two declarers of `society.signal`.
#[must_use]
pub fn latent_overlaps_fail_closed() -> Capture {
    let mut capture = Capture::default();
    let (agent, agent_owner) = race(&AgentPlugin::new(), &AgentPlugin::new());
    capture.record("none", "agent.second", agent);
    capture.record("none", "agent.registered", agent_owner.len());
    let world_fixture = FixturePlugin::new("world-action-fixture", &[EVENT_TYPE_ACTION_V1], false);
    capture.record(
        "none",
        "world.fixture-second",
        race(&WorldPlugin::new(), &world_fixture).0,
    );
    capture.record(
        "none",
        "world.world-second",
        race(&world_fixture, &WorldPlugin::new()).0,
    );
    let signal_fixture = FixturePlugin::new("signal-fixture", &[EVENT_TYPE_SIGNAL], false);
    capture.record(
        "none",
        "society.fixture-second",
        race(&SocietyPlugin::new(), &signal_fixture).0,
    );
    capture.record(
        "none",
        "society.society-second",
        race(&signal_fixture, &SocietyPlugin::new()).0,
    );
    capture
}

fn recorder_description(registry: &PluginRegistry) -> Option<String> {
    registry
        .schemas
        .iter()
        .find(|schema| schema.event_type.as_str() == RECORDER_EVENT_TYPE)
        .map(|schema| schema.description.clone())
}

/// PCF-REG-006: one `AgentPlugin` claims the Recorder type and keeps the
/// host schema; a second claimant is rejected.
#[must_use]
pub fn recorder_single_claimant() -> Capture {
    let mut capture = Capture::default();
    let mut registry = gated_registry(None);
    let host_schema = recorder_description(&registry);
    capture.record("none", "host-schema-present", host_schema.is_some());
    let agent = outcome(registry.register_generated(&AgentPlugin::new(), None, None));
    capture.record("none", "agent", agent);
    capture.record(
        "none",
        "host-schema-kept",
        recorder_description(&registry) == host_schema,
    );
    let rival = FixturePlugin::new("rival-recorder", &[RECORDER_EVENT_TYPE], false);
    let before = snapshot(&registry, &[RECORDER_EVENT_TYPE]);
    capture.record(
        "none",
        "rival",
        outcome(registry.register_generated(&rival, None, None)),
    );
    capture.record(
        "none",
        "rival.unchanged",
        snapshot(&registry, &[RECORDER_EVENT_TYPE]) == before,
    );
    capture
}

/// PCF-EVAL-001: Persona owns no `eval.*` type.
#[must_use]
pub fn persona_owns_no_eval_type() -> Capture {
    let mut capture = Capture::default();
    let mut owned: Vec<String> = PersonaPlugin::new()
        .capability()
        .owned_event_types
        .iter()
        .map(|kind| kind.as_str().to_owned())
        .collect();
    owned.sort();
    capture.record(
        "none",
        "owns-eval",
        owned.iter().any(|kind| kind.starts_with("eval.")),
    );
    capture.record("none", "owned", owned.join(","));
    let mut registry = gated_registry(None);
    capture.record(
        "none",
        "registers",
        outcome(registry.register_generated(&PersonaPlugin::new(), None, None)),
    );
    capture
}
