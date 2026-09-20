use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    output_policy::{
        OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1, OutputPolicyInputV1,
        OutputPolicyV1,
    },
    Capability, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1, Hash,
    Plugin, PluginCpuReservationV1, PluginId, WorkloadProfileV1,
};
use pos_runtime::{
    Driver, ObservationView, OutputAdmissionErrorV1, OutputAdmissionV1, PluginRegistry,
    RuntimeError, StepOutput,
};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

fn budget(plugin_id: PluginId) -> Result<ExecutableBudgetPolicyV1, Box<dyn Error>> {
    budget_with(plugin_id, 16, 2, 32, 100, [10, 10, 10])
}

fn budget_with(
    plugin_id: PluginId,
    max_event_bytes: u32,
    max_events: u32,
    max_bytes: u64,
    max_cpu_us: u32,
    cpu_reservations_us: [u32; 3],
) -> Result<ExecutableBudgetPolicyV1, Box<dyn Error>> {
    ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
        revision: 1,
        workload_profile: WorkloadProfileV1::Interactive,
        cut_budget_family: 0,
        max_event_bytes,
        fidelity_budgets: [
            FidelityBudgetV1 {
                level: 0,
                max_events,
                max_bytes,
                max_cpu_us,
                shared_host_cpu_reservation_us: 0,
            },
            FidelityBudgetV1 {
                level: 1,
                max_events,
                max_bytes,
                max_cpu_us,
                shared_host_cpu_reservation_us: 0,
            },
            FidelityBudgetV1 {
                level: 2,
                max_events,
                max_bytes,
                max_cpu_us,
                shared_host_cpu_reservation_us: 0,
            },
        ],
        plugin_cpu_reservations: vec![PluginCpuReservationV1 {
            plugin_id,
            cpu_reservations_us,
        }],
        accounting_semantics: 0,
        execution_profile_hash: Hash::from_bytes([7; 32]),
        max_pass_wall_duration_us: 1_000,
    })
    .map_err(|error| error.to_string().into())
}

fn policy(
    plugin_id: PluginId,
    budget: &ExecutableBudgetPolicyV1,
) -> Result<OutputPolicyV1, Box<dyn Error>> {
    let declaration = OutputDeclarationV1::new(
        "plugin.output".to_owned(),
        OutputAuthorityV1::Authoritative,
        OutputFidelityV1::L0,
        16,
        None,
        None,
    )
    .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: Hash::from_bytes([1; 32]),
        base_configuration_digest: Hash::from_bytes([2; 32]),
        executable_profile_hash: budget.digest(),
        retention_policy_hash: Hash::from_bytes([3; 32]),
        policy_revision: 1,
        output_declarations: vec![declaration],
    })
    .map_err(|error| error.to_string().into())
}

fn multi_fidelity_policy(
    plugin_id: PluginId,
    budget: &ExecutableBudgetPolicyV1,
) -> Result<OutputPolicyV1, Box<dyn Error>> {
    let declarations = [
        (
            "plugin.l0",
            OutputAuthorityV1::Authoritative,
            OutputFidelityV1::L0,
        ),
        (
            "plugin.l1",
            OutputAuthorityV1::ReproducibleDerived,
            OutputFidelityV1::L1,
        ),
        (
            "plugin.l2",
            OutputAuthorityV1::Ephemeral,
            OutputFidelityV1::L2,
        ),
    ]
    .into_iter()
    .map(|(event_type, authority, fidelity)| {
        let (stride_ticks, aggregate_min_group) = match fidelity {
            OutputFidelityV1::L0 => (None, None),
            OutputFidelityV1::L1 => (Some(1), None),
            OutputFidelityV1::L2 => (None, Some(10)),
        };
        OutputDeclarationV1::new(
            event_type.to_owned(),
            authority,
            fidelity,
            16,
            stride_ticks,
            aggregate_min_group,
        )
    })
    .collect::<Result<Vec<_>, _>>()?;
    Ok(OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: Hash::from_bytes([1; 32]),
        base_configuration_digest: Hash::from_bytes([2; 32]),
        executable_profile_hash: budget.digest(),
        retention_policy_hash: Hash::from_bytes([3; 32]),
        policy_revision: 1,
        output_declarations: declarations,
    })?)
}

fn draft(event_type: &str, bytes: &[u8]) -> EventDraft {
    EventDraft::new(
        pos_core::EntityId::new(),
        Kind::new(event_type),
        CanonicalBytes::from_vec(bytes.to_vec()),
    )
}

#[test]
fn output_admission_accepts_declared_output_and_exposes_policy_identity() -> TestResult {
    let plugin_id = PluginId::new();
    let budget = budget(plugin_id)?;
    let admission =
        OutputAdmissionV1::try_new(plugin_id, "1.0.0", policy(plugin_id, &budget)?, budget)?;

    admission.validate_batch(&[draft("plugin.output", b"accepted")])?;
    assert_ne!(admission.policy_digest(), Hash::zero());
    Ok(())
}

#[test]
fn output_admission_rejects_missing_declaration_and_overflow() -> TestResult {
    let plugin_id = PluginId::new();
    let budget = budget(plugin_id)?;
    let admission =
        OutputAdmissionV1::try_new(plugin_id, "1.0.0", policy(plugin_id, &budget)?, budget)?;

    assert!(matches!(
        admission.validate_batch(&[draft("plugin.unknown", b"x")]),
        Err(OutputAdmissionErrorV1::MissingDeclaration { .. })
    ));
    let drafts = vec![
        draft("plugin.output", b"a"),
        draft("plugin.output", b"b"),
        draft("plugin.output", b"c"),
    ];
    assert!(matches!(
        admission.validate_batch(&drafts),
        Err(OutputAdmissionErrorV1::EventCountExceeded { level: 0, .. })
    ));
    Ok(())
}

#[test]
fn output_admission_rejects_policy_plugin_mismatch() -> TestResult {
    let plugin_id = PluginId::new();
    let other_plugin = PluginId::new();
    let budget = budget(plugin_id)?;
    assert!(matches!(
        OutputAdmissionV1::try_new(other_plugin, "1.0.0", policy(plugin_id, &budget)?, budget),
        Err(OutputAdmissionErrorV1::PluginMismatch)
    ));
    Ok(())
}

#[test]
fn output_admission_accounts_for_each_fidelity_level() -> TestResult {
    let plugin_id = PluginId::new();
    let budget = budget(plugin_id)?;
    let admission = OutputAdmissionV1::try_new(
        plugin_id,
        "1.0.0",
        multi_fidelity_policy(plugin_id, &budget)?,
        budget,
    )?;
    admission.validate_batch(&[
        draft("plugin.l0", b"a"),
        draft("plugin.l1", b"b"),
        draft("plugin.l2", b"c"),
    ])?;
    assert_eq!(admission.plugin_id(), plugin_id);
    Ok(())
}

#[test]
fn output_admission_rejects_plugin_version_mismatch() -> TestResult {
    let plugin_id = PluginId::new();
    let budget = budget(plugin_id)?;
    assert!(matches!(
        OutputAdmissionV1::try_new(plugin_id, "2.0.0", policy(plugin_id, &budget)?, budget),
        Err(OutputAdmissionErrorV1::PluginVersionMismatch)
    ));
    Ok(())
}

#[test]
fn output_admission_rejects_identity_and_resource_limits() -> TestResult {
    let plugin_id = PluginId::new();
    let mismatched = budget(plugin_id)?;
    let mismatched_policy = policy(plugin_id, &mismatched)?;
    let mismatched_budget = budget_with(PluginId::new(), 16, 2, 32, 100, [10, 10, 10])?;
    assert!(matches!(
        OutputAdmissionV1::try_new(plugin_id, "1.0.0", mismatched_policy, mismatched_budget),
        Err(OutputAdmissionErrorV1::PolicyIdentityMismatch)
    ));

    let no_cpu_plugin = PluginId::new();
    let no_cpu_budget = budget_with(no_cpu_plugin, 16, 2, 32, 100, [10, 10, 10])?;
    let no_cpu_policy = policy(plugin_id, &no_cpu_budget)?;
    assert!(matches!(
        OutputAdmissionV1::try_new(plugin_id, "1.0.0", no_cpu_policy, no_cpu_budget),
        Err(OutputAdmissionErrorV1::MissingCpuReservation)
    ));

    let bytes_budget = budget_with(plugin_id, 4, 2, 32, 100, [10, 10, 10])?;
    let bytes_admission = OutputAdmissionV1::try_new(
        plugin_id,
        "1.0.0",
        policy(plugin_id, &bytes_budget)?,
        bytes_budget,
    )?;
    assert!(matches!(
        bytes_admission.validate_batch(&[draft("plugin.output", b"12345")]),
        Err(OutputAdmissionErrorV1::EventBytesExceeded { .. })
    ));

    let batch_budget = budget_with(plugin_id, 16, 2, 3, 100, [10, 10, 10])?;
    let batch_admission = OutputAdmissionV1::try_new(
        plugin_id,
        "1.0.0",
        policy(plugin_id, &batch_budget)?,
        batch_budget,
    )?;
    assert!(matches!(
        batch_admission
            .validate_batch(&[draft("plugin.output", b"ab"), draft("plugin.output", b"cd")]),
        Err(OutputAdmissionErrorV1::BatchBytesExceeded { .. })
    ));

    let cpu_budget = budget_with(plugin_id, 16, 2, 32, 10, [10, 10, 10])?;
    let cpu_admission = OutputAdmissionV1::try_new(
        plugin_id,
        "1.0.0",
        policy(plugin_id, &cpu_budget)?,
        cpu_budget,
    )?;
    assert!(matches!(
        cpu_admission.validate_batch(&[draft("plugin.output", b"a"), draft("plugin.output", b"b")]),
        Err(OutputAdmissionErrorV1::CpuExceeded { .. })
    ));
    Ok(())
}

struct FixturePlugin {
    id: PluginId,
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "output-admission-fixture"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("plugin.output")],
            has_driver: true,
            ..Capability::default()
        }
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
    let plugin_id = PluginId::new();
    let budget = budget(plugin_id)?;
    let policy = policy(plugin_id, &budget)?;
    let timeline = pos_core::TimelineId::new();

    let mut admitted = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    admitted.register_with_output_policy(
        &FixturePlugin { id: plugin_id },
        policy,
        budget,
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    assert!(matches!(
        admitted.step_all_anchored(timeline, pos_core::Seq::ZERO),
        Ok(drafts) if drafts.len() == 1
    ));

    let mut missing = PluginRegistry::new().with_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ));
    missing.register_generated(
        &FixturePlugin {
            id: PluginId::new(),
        },
        None,
        Some(Box::new(FixtureDriver)),
    )?;
    assert!(matches!(
        missing.step_all_anchored(timeline, pos_core::Seq::ZERO),
        Err(RuntimeError::OutputAdmission(_))
    ));
    Ok(())
}

#[test]
fn registry_rejects_policy_declarations_outside_plugin_capability() -> TestResult {
    let plugin_id = PluginId::new();
    let budget = budget(plugin_id)?;
    let declaration = OutputDeclarationV1::new(
        "plugin.foreign".to_owned(),
        OutputAuthorityV1::Authoritative,
        OutputFidelityV1::L0,
        16,
        None,
        None,
    )?;
    let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: Hash::from_bytes([1; 32]),
        base_configuration_digest: Hash::from_bytes([2; 32]),
        executable_profile_hash: budget.digest(),
        retention_policy_hash: Hash::from_bytes([3; 32]),
        policy_revision: 1,
        output_declarations: vec![declaration],
    })?;
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_with_output_policy(
            &FixturePlugin { id: plugin_id },
            policy,
            budget,
            None,
            None,
        ),
        Err(RuntimeError::CapabilityMismatch { .. })
    ));
    Ok(())
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
fn explicit_registration_rejects_policy_budget_identity_mismatch() -> TestResult {
    let plugin_id = PluginId::new();
    let executable_budget = budget(plugin_id)?;
    let policy = policy(plugin_id, &executable_budget)?;
    let other_budget = budget(PluginId::new())?;
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_with_output_policy(
            &FixturePlugin { id: plugin_id },
            policy,
            other_budget,
            None,
            None,
        ),
        Err(RuntimeError::OutputAdmission(_))
    ));
    Ok(())
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
