use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    Capability, Plugin, PluginId,
};
use pos_runtime::{
    validate_output_policy_artifacts_v1, Driver, InstalledOutputPolicySourceV1, ObservationView,
    OutputAdmissionErrorV1, PluginRegistry, RuntimeError, StepOutput,
};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn verified_binding(plugin: &FixturePlugin) -> Result<FixtureBinding, Box<dyn Error>> {
    let configuration_details = b"fixture-configuration";
    let binding = pos_runtime::OutputPolicyBindingV1::from_installed_source(
        plugin,
        pos_runtime::InstalledOutputPolicySourceV1::Generated,
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
    let mut configuration = source.configuration_artifact.clone();
    configuration.push(0);
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
        pos_conformance::host_verified_execution_profile_bytes_v1("deterministic-air-gapped-v1")?;
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
    assert!(!source.profile_artifact.is_empty());
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

#[test]
fn public_tick_and_step_report_output_admission_failures() -> TestResult {
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
        Err(RuntimeError::OutputAdmission(_))
    ));
    assert!(matches!(
        registry.step_all(timeline),
        Err(RuntimeError::OutputAdmission(_))
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
        pos_runtime::OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::RuleAgent,
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
        pos_runtime::OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::RuleAgent,
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
        pos_runtime::OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::Agent,
            b"fixture-configuration",
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::PluginMismatch)
    ));
    assert!(matches!(
        pos_runtime::OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::RuleAgent,
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
        pos_runtime::OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::Agent,
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
