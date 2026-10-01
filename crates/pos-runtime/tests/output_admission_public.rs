#![cfg(target_os = "linux")]

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    store::EventStore,
    Capability, Plugin, PluginId,
};
use pos_runtime::{
    installed_plugin_role_v1, validate_output_policy_artifacts_v1, DomainImplementationKindV1,
    Driver, LocalScheduledAdmissionHostV1, ObservationView, OutputAdmissionErrorV1,
    OutputPolicySourceV1, PluginAvailabilityV1, PluginIsolationV1, PluginPinV1,
    PluginRegistrationV1, PluginRegistry, RuntimeError, StepOutput, TickScheduler,
};
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

struct FixtureBinding {
    binding: pos_runtime::OutputPolicyBindingV1,
    output_policy_bytes: Vec<u8>,
    executable_budget_bytes: Vec<u8>,
    implementation_artifact: Vec<u8>,
    configuration_artifact: Vec<u8>,
    profile_artifact: Vec<u8>,
    retention_artifact: Vec<u8>,
}

fn verified_binding<P: Plugin>(plugin: &P) -> Result<FixtureBinding, Box<dyn Error>> {
    let configuration_details = b"fixture-configuration";
    let binding = pos_runtime::OutputPolicyBindingV1::from_source(
        plugin,
        pos_runtime::OutputPolicySourceV1::Generated,
        configuration_details,
        "deterministic-local-v1",
    )?;
    let policy = binding.policy().clone();
    let budget = binding.budget().clone();
    Ok(FixtureBinding {
        output_policy_bytes: policy.to_canonical_cbor(),
        executable_budget_bytes: budget.to_canonical_cbor(),
        implementation_artifact: binding.implementation_artifact().to_vec(),
        configuration_artifact: binding.configuration_artifact().to_vec(),
        profile_artifact: binding.execution_profile_artifact().to_vec(),
        retention_artifact: binding.retention_policy_artifact().to_vec(),
        binding,
    })
}

fn register_verified_fixture_driver<P: Plugin, D: Driver + 'static>(
    registry: &mut PluginRegistry,
    plugin: &P,
    driver: D,
) -> TestResult {
    registry.register_with_verified_output_policy(
        plugin,
        verified_binding(plugin)?.binding,
        None,
        Some(Box::new(driver)),
    )?;
    Ok(())
}

fn canonical_fixture_closure_bytes(source: &FixtureBinding) -> Vec<u8> {
    let members = [
        source.output_policy_bytes.as_slice(),
        source.executable_budget_bytes.as_slice(),
        source.implementation_artifact.as_slice(),
        source.configuration_artifact.as_slice(),
        source.profile_artifact.as_slice(),
        source.retention_artifact.as_slice(),
    ];
    let mut bytes = Vec::from(&b"OPC1"[..]);
    for member in members {
        bytes.extend_from_slice(&(member.len() as u64).to_be_bytes());
        bytes.extend_from_slice(member);
    }
    bytes
}

fn assert_artifact_shape_rejections(source: &FixtureBinding) {
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &[0],
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EOP1" })
    ));
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &[],
            &source.configuration_artifact,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "implementation"
        })
    ));
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            b"invalid",
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration"
        })
    ));
    assert_malformed_configuration_rejections(source);
    assert_profile_and_retention_shape_rejections(source);
}

fn assert_malformed_configuration_rejections(source: &FixtureBinding) {
    let mut truncated_length = b"CFG1".to_vec();
    truncated_length.extend_from_slice(&[0; 7]);
    let mut truncated_field = b"CFG1".to_vec();
    truncated_field.extend_from_slice(&1_u64.to_le_bytes());
    let mut overflowing_field = b"CFG1".to_vec();
    overflowing_field.extend_from_slice(&u64::MAX.to_le_bytes());
    for malformed in [
        b"CFG1".to_vec(),
        truncated_length,
        truncated_field,
        overflowing_field,
        framed_configuration(&[&[0xff], b"1.0.0", b""]),
        framed_configuration(&[b"rule-agent", &[0xff], b""]),
        framed_configuration(&[b"rule-agent", b"1.0.0", &[0xff], b""]),
    ] {
        assert!(matches!(
            validate_output_policy_artifacts_v1(
                &source.output_policy_bytes,
                &source.executable_budget_bytes,
                &source.implementation_artifact,
                &malformed,
                &source.profile_artifact,
                &source.retention_artifact,
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration"
            })
        ));
    }
    let unordered_configuration =
        framed_configuration(&[b"rule-agent", b"1.0.0", b"z.event", b"a.event", b"details"]);
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &unordered_configuration,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration"
        })
    ));
}

fn assert_profile_and_retention_shape_rejections(source: &FixtureBinding) {
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            b"invalid",
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    ));
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &source.profile_artifact,
            b"invalid",
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "RTP1" })
    ));
}

fn framed_configuration(fields: &[&[u8]]) -> Vec<u8> {
    let mut artifact = b"CFG1".to_vec();
    for field in fields {
        let Ok(length) = u64::try_from(field.len()) else {
            return Vec::new();
        };
        artifact.extend_from_slice(&length.to_le_bytes());
        artifact.extend_from_slice(field);
    }
    artifact
}

fn assert_artifact_size_rejections(source: &FixtureBinding) {
    let oversized_policy = vec![0; pos_core::output_policy::MAX_OUTPUT_POLICY_BYTES_V1 + 1];
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &oversized_policy,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EOP1" })
    ));
    let oversized_budget = vec![0; pos_core::MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1 + 1];
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &oversized_budget,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EBP1" })
    ));
    let oversized_implementation =
        vec![0; pos_runtime::MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1 + 1];
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &oversized_implementation,
            &source.configuration_artifact,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "implementation"
        })
    ));
    let oversized_configuration =
        vec![0; pos_runtime::MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1 + 1];
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &oversized_configuration,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration"
        })
    ));
    let oversized_profile = vec![0; pos_conformance::MAX_EXECUTION_PROFILE_BYTES_V1 + 1];
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &oversized_profile,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    ));
    let oversized_retention = vec![0; pos_core::retention::MAX_WORLD_RETENTION_RECORD_BYTES_V1 + 1];
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &source.profile_artifact,
            &oversized_retention,
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "RTP1" })
    ));
}

fn assert_artifact_identity_rejections(source: &FixtureBinding) -> TestResult {
    let mut implementation = source.implementation_artifact.clone();
    implementation.push(0);
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &implementation,
            &source.configuration_artifact,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch {
            kind: "implementation"
        })
    ));
    let configuration = framed_configuration(&[
        b"rule-agent",
        b"1.0.0",
        b"plugin.l0",
        b"plugin.l1",
        b"plugin.l2",
        b"plugin.output",
        b"different-configuration-details",
    ]);
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &configuration,
            &source.profile_artifact,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch {
            kind: "configuration"
        })
    ));
    let alternate_profile =
        pos_conformance::draft_execution_profile_bytes_v1("deterministic-air-gapped-v1")?;
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &alternate_profile,
            &source.retention_artifact,
        ),
        Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "EPF1" })
    ));
    let mut retention = source.retention_artifact.clone();
    let hash_start = retention
        .windows(2)
        .position(|window| window == [0x58, 0x20])
        .ok_or_else(|| std::io::Error::other("RTP1 hash field missing"))?
        + 2;
    retention[hash_start] ^= 1;
    assert!(matches!(
        validate_output_policy_artifacts_v1(
            &source.output_policy_bytes,
            &source.executable_budget_bytes,
            &source.implementation_artifact,
            &source.configuration_artifact,
            &source.profile_artifact,
            &retention,
        ),
        Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "RTP1" })
    ));
    Ok(())
}

#[test]
fn verified_output_policy_closure_is_retrievable_and_fail_closed() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let source = verified_binding(&plugin)?;
    assert!(!source.output_policy_bytes.is_empty());
    assert!(!source.executable_budget_bytes.is_empty());
    assert!(!source.implementation_artifact.is_empty());
    assert!(source.configuration_artifact.starts_with(b"CFG1"));
    assert!(source.profile_artifact.is_empty());
    assert!(!source.retention_artifact.is_empty());
    assert_artifact_shape_rejections(&source);
    assert_artifact_size_rejections(&source);
    assert_artifact_identity_rejections(&source)?;
    let expected_bytes = canonical_fixture_closure_bytes(&source);
    assert!(expected_bytes.starts_with(b"OPC1"));
    let fresh_plugin = FixturePlugin {
        id: PluginId::new(),
    };

    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_with_verified_output_policy(
        &plugin,
        source.binding,
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    let (_, retained) = registry
        .replay_policy_closures()
        .next()
        .ok_or_else(|| std::io::Error::other("verified closure was not retained"))?;
    assert_eq!(retained, expected_bytes);

    let fresh_source = verified_binding(&fresh_plugin)?;
    let mut fresh_registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    fresh_registry.register_with_verified_output_policy(
        &fresh_plugin,
        fresh_source.binding,
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    let (_, fresh_retained) = fresh_registry
        .replay_policy_closures()
        .next()
        .ok_or_else(|| std::io::Error::other("fresh closure was not retained"))?;
    assert_ne!(retained, fresh_retained);
    assert_eq!(
        registry.replay_policy_closure_identities().next(),
        fresh_registry.replay_policy_closure_identities().next()
    );

    Ok(())
}

#[test]
fn verified_binding_rejects_a_foreign_plugin_instance() -> TestResult {
    let plugin_id = PluginId::new();
    let bound_plugin = FixturePlugin { id: plugin_id };
    let foreign_plugin = FixturePlugin { id: plugin_id };
    let source = verified_binding(&bound_plugin)?;
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));

    assert!(matches!(
        registry.register_with_verified_output_policy(
            &foreign_plugin,
            source.binding,
            None,
            Some(Box::new(FixtureDriver)),
        ),
        Err(RuntimeError::OutputAdmission(
            OutputAdmissionErrorV1::PluginMismatch
        ))
    ));
    Ok(())
}

#[test]
fn local_execution_profile_absence_does_not_create_installed_authority() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));

    // Generated local admission has no EPF1 profile member.
    let local = verified_binding(&plugin)?;
    let changed = pos_runtime::OutputPolicyBindingV1::from_source(
        &plugin,
        OutputPolicySourceV1::Generated,
        b"fixture-configuration",
        "deterministic-air-gapped-v1",
    )?;
    assert!(changed.execution_profile_artifact().is_empty());
    assert!(local.profile_artifact.is_empty());
    let pin = PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        changed.policy().digest(),
        vec![installed_plugin_role_v1(&plugin)],
    )?;
    assert!(matches!(
        registry.register_installed_output(
            &plugin,
            changed,
            PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available),
            None,
        ),
        Err(RuntimeError::OutputAdmission(
            OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" }
        ))
    ));
    assert!(registry.is_empty());

    // The rejected attempts left no residue: the same Plugin still registers.
    registry.register_with_verified_output_policy(
        &plugin,
        local.binding,
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    assert_eq!(registry.len(), 1);
    Ok(())
}

fn draft(event_type: &str, bytes: &[u8]) -> EventDraft {
    EventDraft::new(
        pos_core::EntityId::new(),
        Kind::new(event_type),
        CanonicalBytes::from_vec(bytes.to_vec()),
    )
}

struct FixturePlugin {
    id: PluginId,
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "rule-agent"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new("plugin.output"),
                Kind::new("plugin.l0"),
                Kind::new("plugin.l1"),
                Kind::new("plugin.l2"),
            ],
            has_driver: true,
            ..Capability::default()
        }
    }
}

/// A second Plugin owning its own Event type: under exclusive ownership two
/// registrations in one registry never share an owned type (ADR-024 R1).
struct SecondFixturePlugin {
    id: PluginId,
}

impl Plugin for SecondFixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "second-fixture"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("second.output")],
            has_driver: true,
            ..Capability::default()
        }
    }
}

struct ForeignCapabilityPlugin {
    id: PluginId,
}

impl Plugin for ForeignCapabilityPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "rule-agent"
    }

    fn capability(&self) -> Capability {
        Capability::default()
    }
}

struct FixtureDriver;

impl Driver for FixtureDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![draft("plugin.output", b"accepted")]))
    }

    fn name(&self) -> &'static str {
        "output-admission-fixture-driver"
    }
}

struct FullBudgetDriver;

impl Driver for FullBudgetDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let drafts = (0..1_000)
            .map(|_| draft("plugin.output", b"accepted"))
            .collect();
        Ok(StepOutput::new(drafts))
    }

    fn name(&self) -> &'static str {
        "output-admission-full-budget-fixture-driver"
    }

    fn tick_interval(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(1)
    }
}

struct RejectingDriver;

impl Driver for RejectingDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![draft(
            "plugin.undeclared",
            b"rejected",
        )]))
    }

    fn name(&self) -> &'static str {
        "output-admission-rejecting-driver"
    }
}

struct CadencedFixtureDriver;

impl Driver for CadencedFixtureDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![draft("plugin.output", b"accepted")]))
    }

    fn name(&self) -> &'static str {
        "output-admission-cadenced-fixture-driver"
    }

    fn tick_interval(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(100)
    }
}

struct RejectOnceDriver {
    reject_next: bool,
}

impl Driver for RejectOnceDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let event_type = if self.reject_next {
            self.reject_next = false;
            "plugin.undeclared"
        } else {
            "second.output"
        };
        Ok(StepOutput::new(vec![draft(event_type, b"accepted")]))
    }

    fn name(&self) -> &'static str {
        "output-admission-reject-once-driver"
    }
}

#[test]
fn failed_scheduler_pass_does_not_advance_earlier_driver_cadence() -> TestResult {
    let first = FixturePlugin {
        id: PluginId::new(),
    };
    let second = SecondFixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    register_verified_fixture_driver(&mut registry, &first, CadencedFixtureDriver)?;
    register_verified_fixture_driver(
        &mut registry,
        &second,
        RejectOnceDriver { reject_next: true },
    )?;
    let timeline = pos_core::TimelineId::new();
    let mut scheduler = TickScheduler::new(registry);
    assert!(matches!(
        scheduler.tick(timeline, 0),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
    assert_eq!(scheduler.tick(timeline, 0)?.len(), 2);
    Ok(())
}

/// The undeclared type is outside the Plugin's owned types, so public cadence
/// and live stepping reject it through the shared Driver output vetting (#484).
#[test]
fn public_tick_and_step_reject_unowned_driver_output() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_generated(&plugin, None, Some(Box::new(RejectingDriver)))?;
    let timeline = pos_core::TimelineId::new();
    assert!(matches!(
        registry.tick_cadenced(timeline, 0),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
    assert!(matches!(
        registry.step_all(timeline),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
    Ok(())
}

#[test]
fn registry_requires_the_policy_before_a_driver_output_can_stage() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let source = verified_binding(&plugin)?;
    let timeline = pos_core::TimelineId::new();

    let mut admitted = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    admitted.register_with_verified_output_policy(
        &plugin,
        source.binding,
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    assert!(matches!(
        admitted.step_all_anchored(timeline, pos_core::Seq::ZERO),
        Ok(drafts) if drafts.len() == 1
    ));

    let mut generated = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    generated.register_generated(
        &FixturePlugin {
            id: PluginId::new(),
        },
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    assert!(matches!(
        generated.step_all_anchored(timeline, pos_core::Seq::ZERO),
        Ok(drafts) if drafts.len() == 1
    ));
    Ok(())
}

#[test]
fn public_binding_rejects_foreign_capability_name() {
    let plugin = ForeignCapabilityPlugin {
        id: PluginId::new(),
    };
    assert!(matches!(
        pos_runtime::OutputPolicyBindingV1::from_source(
            &plugin,
            OutputPolicySourceV1::RuleAgent,
            &[],
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::PluginMismatch)
    ));
}

#[test]
fn public_binding_rejects_name_only_installed_source_claims() {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    assert!(matches!(
        pos_runtime::OutputPolicyBindingV1::from_source(
            &plugin,
            OutputPolicySourceV1::RuleAgent,
            &[],
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::PluginMismatch)
    ));
}

#[test]
fn generated_registration_binds_owned_output_policy() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_generated(&plugin, None, Some(Box::new(FixtureDriver)))?;
    assert_eq!(registry.len(), 1);
    assert!(matches!(
        registry.register_generated(&plugin, None, Some(Box::new(FixtureDriver))),
        Err(RuntimeError::DuplicatePlugin { .. })
    ));
    Ok(())
}

#[test]
fn generated_registration_with_approver_binds_owned_output_policy() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_generated_with_approver(
        &plugin,
        None,
        Some(Box::new(FixtureDriver)),
        None,
        std::iter::empty(),
    )?;
    assert_eq!(registry.len(), 1);
    Ok(())
}

#[test]
fn public_tick_and_step_validate_generated_driver_output() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_generated(&plugin, None, Some(Box::new(FixtureDriver)))?;
    let timeline = pos_core::TimelineId::new();
    registry.tick_cadenced(timeline, 0)?;
    registry.step_all(timeline)?;
    Ok(())
}

#[test]
fn successful_unanchored_steps_reset_admission_usage_at_each_call_boundary() -> TestResult {
    let timeline = pos_core::TimelineId::new();
    let scheduled_plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut scheduled_registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    scheduled_registry.register_generated(
        &scheduled_plugin,
        None,
        Some(Box::new(FullBudgetDriver)),
    )?;
    let mut scheduler = TickScheduler::new(scheduled_registry);
    assert_eq!(scheduler.tick(timeline, 0)?.len(), 1_000);
    assert_eq!(scheduler.tick(timeline, 1)?.len(), 1_000);

    let stepped_plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let mut stepped_registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    stepped_registry.register_generated(&stepped_plugin, None, Some(Box::new(FullBudgetDriver)))?;
    assert_eq!(stepped_registry.step_all(timeline)?.len(), 1_000);
    assert_eq!(stepped_registry.step_all(timeline)?.len(), 1_000);
    Ok(())
}

struct DuplicateFixturePlugin {
    id: PluginId,
}

struct InvalidDeclarationPlugin;

impl Plugin for InvalidDeclarationPlugin {
    fn id(&self) -> PluginId {
        PluginId::new()
    }

    fn name(&self) -> &'static str {
        "invalid-declaration-output-admission-fixture"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("")],
            ..Capability::default()
        }
    }
}

#[test]
fn generated_approver_registration_rejects_invalid_owned_event_declaration() {
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_generated_with_approver(
            &InvalidDeclarationPlugin,
            None,
            None,
            None,
            std::iter::empty(),
        ),
        Err(RuntimeError::CapabilityMismatch { .. })
    ));
}

struct FlippingVersionPlugin {
    id: PluginId,
    calls: AtomicUsize,
}

impl Plugin for FlippingVersionPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "flipping-version-output-admission-fixture"
    }

    fn version(&self) -> &'static str {
        if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            "1.0.0"
        } else {
            "2.0.0"
        }
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("plugin.output")],
            ..Capability::default()
        }
    }
}

#[test]
fn generated_approver_registration_rejects_changed_plugin_version() {
    let plugin = FlippingVersionPlugin {
        id: PluginId::new(),
        calls: AtomicUsize::new(0),
    };
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_generated_with_approver(&plugin, None, None, None, std::iter::empty(),),
        Err(RuntimeError::OutputAdmission(_))
    ));
}

#[test]
fn generated_registration_rejects_invalid_owned_event_declaration() {
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_generated(&InvalidDeclarationPlugin, None, None),
        Err(RuntimeError::CapabilityMismatch { .. })
    ));
}

#[test]
fn explicit_registration_rejects_unowned_installed_source() {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    assert!(matches!(
        pos_runtime::OutputPolicyBindingV1::from_source(
            &plugin,
            OutputPolicySourceV1::RuleAgent,
            b"fixture-configuration",
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::PluginMismatch)
    ));
}

#[test]
fn explicit_registration_rejects_name_only_source_even_with_configuration() {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    assert!(matches!(
        pos_runtime::OutputPolicyBindingV1::from_source(
            &plugin,
            OutputPolicySourceV1::Agent,
            b"fixture-configuration",
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::PluginMismatch)
    ));
}

impl Plugin for DuplicateFixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "duplicate-output-admission-fixture"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("plugin.output"), Kind::new("plugin.output")],
            ..Capability::default()
        }
    }
}

#[test]
fn generated_registration_rejects_duplicate_owned_event_types() {
    let plugin = DuplicateFixturePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_generated(&plugin, None, None),
        Err(RuntimeError::CapabilityMismatch { .. })
    ));
}

fn sized_draft(event_type: &str, payload_bytes: usize) -> EventDraft {
    EventDraft::new(
        pos_core::EntityId::new(),
        Kind::new(event_type),
        CanonicalBytes::from_vec(vec![0x5a; payload_bytes]),
    )
}

struct SizedPayloadDriver {
    event_type: &'static str,
    payload_bytes: usize,
}

impl Driver for SizedPayloadDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![sized_draft(
            self.event_type,
            self.payload_bytes,
        )]))
    }

    fn name(&self) -> &'static str {
        "output-admission-sized-payload-driver"
    }
}

fn declared_event_limit(source: &FixtureBinding, event_type: &str) -> Result<u32, Box<dyn Error>> {
    let declared = source
        .binding
        .policy()
        .fields()
        .output_declarations
        .iter()
        .find(|declaration| declaration.event_type() == event_type)
        .map(pos_core::output_policy::OutputDeclarationV1::max_bytes)
        .ok_or_else(|| std::io::Error::other("fixture output declaration missing"))?;
    Ok(declared.min(source.binding.budget().fields().max_event_bytes))
}

/// Register the fixture through the installed-source seam with a Driver that
/// emits one draft of `event_type` sized at the recorded limit plus `extra`.
fn registered_with_sized_output(
    plugin: &FixturePlugin,
    event_type: &'static str,
    extra: usize,
) -> Result<(PluginRegistry, u32), Box<dyn Error>> {
    let source = verified_binding(plugin)?;
    let limit = declared_event_limit(&source, "plugin.output")?;
    let payload_bytes = usize::try_from(limit)? + extra;
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_with_verified_output_policy(
        plugin,
        source.binding,
        None,
        Some(Box::new(SizedPayloadDriver {
            event_type,
            payload_bytes,
        })),
    )?;
    Ok((registry, limit))
}

fn gated_store() -> Result<pos_store::memory::MemoryStore, Box<dyn Error>> {
    let mut store = pos_store::memory::MemoryStore::new();
    store.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    Ok(store)
}

/// Admit the staged pass through the local host and return its committed
/// Event count.
fn admit_staged(
    registry: &mut PluginRegistry,
    store: &mut pos_store::memory::MemoryStore,
    timeline: pos_core::TimelineId,
) -> Result<usize, Box<dyn Error>> {
    let host = LocalScheduledAdmissionHostV1::shared()?;
    let revisions = host.observe(registry, store, timeline)?;
    let head = store.logical_head(timeline)?;
    let receipt = host
        .admit(registry, store, revisions, head, 0)?
        .ok_or("expected a committed batch")?;
    Ok(receipt.committed_events().len())
}

/// A rejected step leaves nothing staged: admission fails because no pass is
/// pending, and the Timeline stays empty.
fn assert_rejected_output_is_not_persisted(
    registry: &mut PluginRegistry,
    store: &mut pos_store::memory::MemoryStore,
    timeline: pos_core::TimelineId,
) -> TestResult {
    let error = admit_staged(registry, store, timeline)
        .err()
        .ok_or("expected the rejected draft to be refused")?;
    assert!(error.to_string().contains("Driver step is already pending"));
    assert_eq!(store.logical_head(timeline)?, pos_core::Seq::ZERO);
    Ok(())
}

#[test]
fn verified_step_appends_output_at_the_exact_event_byte_limit() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let (mut registry, limit) = registered_with_sized_output(&plugin, "plugin.output", 0)?;
    let mut store = gated_store()?;
    let timeline = store.create_timeline("output-admission-exact-limit")?.id();

    let drafts = registry.step_all_anchored(timeline, pos_core::Seq::ZERO)?;
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].payload.len(), usize::try_from(limit)?);
    assert_eq!(admit_staged(&mut registry, &mut store, timeline)?, 1);
    assert_eq!(store.logical_head(timeline)?, pos_core::Seq::from_u64(1));
    Ok(())
}

#[test]
fn verified_step_rejects_output_one_byte_over_the_event_limit_before_append() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let (mut registry, limit) = registered_with_sized_output(&plugin, "plugin.output", 1)?;
    let requested_bytes = usize::try_from(limit)? + 1;
    let mut store = gated_store()?;
    let timeline = store.create_timeline("output-admission-overflow")?.id();

    assert!(matches!(
        registry.step_all_anchored(timeline, pos_core::Seq::ZERO),
        Err(RuntimeError::OutputAdmission(OutputAdmissionErrorV1::EventBytesExceeded {
            ref event_type,
            requested,
            limit: recorded,
        })) if event_type == "plugin.output" && requested == requested_bytes && recorded == limit
    ));
    assert_rejected_output_is_not_persisted(&mut registry, &mut store, timeline)
}

/// Emits one valid draft followed by one draft over the event byte limit on
/// its first step, then only the valid draft on every later step.
struct MixedBatchDriver {
    over_limit_bytes: usize,
    stepped: bool,
}

impl Driver for MixedBatchDriver {
    fn step(
        &mut self,
        _timeline: pos_core::TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let mut drafts = vec![sized_draft("plugin.output", 1)];
        if !std::mem::replace(&mut self.stepped, true) {
            drafts.push(sized_draft("plugin.output", self.over_limit_bytes));
        }
        Ok(StepOutput::new(drafts))
    }

    fn name(&self) -> &'static str {
        "output-admission-mixed-batch-driver"
    }
}

#[test]
fn verified_step_rejects_a_batch_with_one_overflowing_draft_atomically() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let source = verified_binding(&plugin)?;
    let limit = declared_event_limit(&source, "plugin.output")?;
    let over_limit_bytes = usize::try_from(limit)? + 1;
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    registry.register_with_verified_output_policy(
        &plugin,
        source.binding,
        None,
        Some(Box::new(MixedBatchDriver {
            over_limit_bytes,
            stepped: false,
        })),
    )?;
    let mut store = gated_store()?;
    let timeline = store.create_timeline("output-admission-mixed-batch")?.id();

    let rejected = registry.step_all_anchored(timeline, pos_core::Seq::ZERO);
    assert!(matches!(
        rejected,
        Err(RuntimeError::OutputAdmission(OutputAdmissionErrorV1::EventBytesExceeded {
            ref event_type,
            requested,
            limit: recorded,
        })) if event_type == "plugin.output" && requested == over_limit_bytes && recorded == limit
    ));
    assert_eq!(store.logical_head(timeline)?, pos_core::Seq::ZERO);

    let drafts = registry.step_all_anchored(timeline, pos_core::Seq::ZERO)?;
    assert_eq!(drafts.len(), 1);
    assert_eq!(admit_staged(&mut registry, &mut store, timeline)?, 1);
    assert_eq!(store.logical_head(timeline)?, pos_core::Seq::from_u64(1));
    Ok(())
}

/// A verified declaration names exactly the Plugin's owned Event types, so an
/// undeclared type is also unowned. The Driver output vetting shared by every
/// path rejects it as an unauthorized source before the budget check (#484).
#[test]
fn verified_step_rejects_an_undeclared_event_type_before_append() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let (mut registry, _) = registered_with_sized_output(&plugin, "plugin.undeclared", 0)?;
    let mut store = gated_store()?;
    let timeline = store.create_timeline("output-admission-undeclared")?.id();

    assert!(matches!(
        registry.step_all_anchored(timeline, pos_core::Seq::ZERO),
        Err(RuntimeError::Authority(
            pos_core::AuthorityErrorV1::UnauthorizedSource
        ))
    ));
    assert_rejected_output_is_not_persisted(&mut registry, &mut store, timeline)
}

#[test]
fn generated_binding_keeps_an_undeclared_profile_metadata_only() -> TestResult {
    let plugin = FixturePlugin {
        id: PluginId::new(),
    };
    let binding = pos_runtime::OutputPolicyBindingV1::from_source(
        &plugin,
        OutputPolicySourceV1::Generated,
        b"fixture-configuration",
        "undeclared-profile-v1",
    )?;
    assert!(binding.execution_profile_artifact().is_empty());
    Ok(())
}

struct UpgradingPlugin {
    id: PluginId,
    upgraded: AtomicBool,
}

impl Plugin for UpgradingPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "upgrading-output-admission-fixture"
    }

    fn version(&self) -> &'static str {
        if self.upgraded.load(Ordering::Relaxed) {
            "2.0.0"
        } else {
            "1.0.0"
        }
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("plugin.output")],
            has_driver: true,
            ..Capability::default()
        }
    }
}

#[test]
fn verified_registration_rejects_a_policy_recorded_for_another_plugin_identity() -> TestResult {
    let plugin = UpgradingPlugin {
        id: PluginId::new(),
        upgraded: AtomicBool::new(false),
    };
    let binding = pos_runtime::OutputPolicyBindingV1::from_source(
        &plugin,
        OutputPolicySourceV1::Generated,
        b"fixture-configuration",
        "deterministic-local-v1",
    )?;
    assert_eq!(binding.policy().fields().plugin_version, "1.0.0");
    plugin.upgraded.store(true, Ordering::Relaxed);
    let mut registry = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));

    assert!(matches!(
        registry.register_with_verified_output_policy(
            &plugin,
            binding,
            None,
            Some(Box::new(FixtureDriver)),
        ),
        Err(RuntimeError::OutputAdmission(
            OutputAdmissionErrorV1::PluginVersionMismatch
        ))
    ));
    assert!(registry.is_empty());
    assert!(registry.output_policy_digests().next().is_none());
    assert!(registry.replay_policy_closures().next().is_none());
    Ok(())
}
