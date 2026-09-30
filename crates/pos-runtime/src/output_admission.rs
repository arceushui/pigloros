//! Host-owned admission of Plugin output against one recorded policy identity.

use pos_core::{
    event::{EventDraft, Kind},
    output_policy::{
        OutputFidelityV1, OutputPolicyV1, MAX_OUTPUT_DECLARATIONS_V1, MAX_OUTPUT_POLICY_BYTES_V1,
    },
    plugin::{PluginInstanceIdentity, PluginOwnerTokenV1},
    retention::{WorldRetentionPolicyV1, MAX_WORLD_RETENTION_RECORD_BYTES_V1},
    ActionApprover, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1,
    Hash, Plugin, PluginCpuReservationV1, PluginId, WorkloadProfileV1,
    MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1,
};
use std::{any::type_name, sync::Mutex};

use crate::driver::Driver;

pub(crate) const WORLD_ACTION_EVENT_TYPE_V1: &str = "world.action.v1";

const MAX_EXECUTION_PROFILE_BYTES_V1: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const _: () =
    assert!(MAX_EXECUTION_PROFILE_BYTES_V1 == pos_conformance::MAX_EXECUTION_PROFILE_BYTES_V1);

/// Maximum aggregate bytes retained by one output-policy closure envelope.
pub const MAX_OUTPUT_POLICY_CLOSURE_BYTES_V1: usize = 2 * 65_536
    + 2 * crate::reviewed_policy::MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1
    + MAX_EXECUTION_PROFILE_BYTES_V1
    + MAX_WORLD_RETENTION_RECORD_BYTES_V1
    + 4
    + 6 * 8;

/// Closed failures returned by the production output gate.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutputAdmissionErrorV1 {
    #[error("output policy Plugin identity does not match the registered Plugin")]
    PluginMismatch,
    #[error("output policy Plugin version does not match the registered Plugin")]
    PluginVersionMismatch,
    #[error("output policy executable profile identity does not match the supplied budget")]
    PolicyIdentityMismatch,
    #[error("Plugin output has no declared policy entry for event type '{event_type}'")]
    MissingDeclaration { event_type: String },
    #[error("Plugin output '{event_type}' exceeds its declared byte limit")]
    EventBytesExceeded {
        event_type: String,
        requested: usize,
        limit: u32,
    },
    #[error("Plugin output exceeds the executable event-count budget")]
    EventCountExceeded {
        level: u8,
        requested: u64,
        limit: u32,
    },
    #[error("Plugin output exceeds the executable byte budget")]
    BatchBytesExceeded {
        level: u8,
        requested: u64,
        limit: u64,
    },
    #[error("executable budget has no CPU reservation for the registered Plugin")]
    MissingCpuReservation,
    #[error("{kind} artifact is missing or malformed")]
    ArtifactInvalid { kind: &'static str },
    #[error("{kind} artifact identity does not match the recorded policy")]
    ArtifactIdentityMismatch { kind: &'static str },
    #[error("{kind} callback is not the installed implementation")]
    CallbackMismatch { kind: &'static str },
}

/// Installed implementation source selected by a trusted composition root.
///
/// These variants are the only artifact roots accepted by production output
/// admission. The runtime observes the concrete Plugin type at this boundary,
/// resolves its complete native source bundle from the repository, and rejects
/// same-name or caller-authored fixture types before policy construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledOutputPolicySourceV1 {
    /// The bounded generated source available only to explicit test-support fixtures.
    #[cfg(any(test, feature = "test-support"))]
    Generated,
    /// The Gateway composition root.
    Gateway,
    /// The World plugin composition root.
    World,
    /// The Rule Agent plugin composition root.
    RuleAgent,
    /// The general Agent plugin composition root.
    Agent,
    /// The Synthetic Observation plugin composition root.
    SyntheticObservation,
    /// The Society plugin composition root.
    Society,
    /// The experiment proof composition root.
    Experiment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputPolicyArtifactInputV1 {
    implementation: Vec<u8>,
    configuration: Vec<u8>,
    execution_profile: Vec<u8>,
    retention_policy: Vec<u8>,
}

impl OutputPolicyArtifactInputV1 {
    fn from_slices(
        implementation_artifact: &[u8],
        configuration_artifact: &[u8],
        execution_profile_artifact: &[u8],
        retention_policy_artifact: &[u8],
    ) -> Result<Self, OutputAdmissionErrorV1> {
        validate_leaf_lengths(
            implementation_artifact,
            configuration_artifact,
            execution_profile_artifact,
            retention_policy_artifact,
        )?;
        Ok(Self {
            implementation: implementation_artifact.to_vec(),
            configuration: configuration_artifact.to_vec(),
            execution_profile: execution_profile_artifact.to_vec(),
            retention_policy: retention_policy_artifact.to_vec(),
        })
    }

    pub(crate) fn implementation_artifact(&self) -> &[u8] {
        &self.implementation
    }

    pub(crate) fn configuration_artifact(&self) -> &[u8] {
        &self.configuration
    }

    pub(crate) fn execution_profile_artifact(&self) -> &[u8] {
        &self.execution_profile
    }

    pub(crate) fn retention_policy_artifact(&self) -> &[u8] {
        &self.retention_policy
    }
}

/// One native Plugin type compiled into an installed source.
///
/// Callback and Plugin ownership compare `std::any::type_name` strings rather
/// than `TypeId`: the runtime cannot depend on the Plugin crates that own
/// these types, so it cannot name them. `type_name` output is not guaranteed
/// to be unique or stable across compiler versions, so this check is a
/// same-build composition guard, not an authenticated identity; authenticated
/// owner proof is deferred to Redmine #396 and #395.
struct InstalledPluginV1 {
    /// Name reported by the installed Plugin type.
    name: &'static str,
    /// Concrete Plugin type observed at the composition boundary.
    type_name: &'static str,
    /// Output Event types declared for this Plugin.
    event_types: &'static [&'static str],
    /// Concrete Driver type compiled for this Plugin, if any.
    driver_type: Option<&'static str>,
}

/// Complete native data for one installed source, so adding a source is one
/// descriptor plus its enum variant.
struct InstalledSourceDescriptorV1 {
    plugins: &'static [InstalledPluginV1],
    /// Concrete `ActionApprover` type accepted from this source, if any.
    approver_type: Option<&'static str>,
    workload_profile: WorkloadProfileV1,
    /// Source files bundled into the implementation artifact.
    source_files: &'static [(&'static str, &'static [u8])],
}

#[cfg(any(test, feature = "test-support"))]
static GENERATED_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[],
    approver_type: None,
    workload_profile: WorkloadProfileV1::Interactive,
    source_files: &[],
};

static GATEWAY_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[InstalledPluginV1 {
        name: "gateway-world-actions",
        type_name: "piglor_gateway::GatewayActionPlugin",
        event_types: &[WORLD_ACTION_EVENT_TYPE_V1],
        driver_type: None,
    }],
    approver_type: Some("piglor_gateway::GatewayWorldActionApprover"),
    workload_profile: WorkloadProfileV1::Interactive,
    source_files: &[
        (
            "src/lib.rs",
            include_bytes!("../../../apps/piglor-gateway/src/lib.rs"),
        ),
        (
            "src/authorization.rs",
            include_bytes!("../../../apps/piglor-gateway/src/authorization.rs"),
        ),
        (
            "src/executor.rs",
            include_bytes!("../../../apps/piglor-gateway/src/executor.rs"),
        ),
        (
            "src/http.rs",
            include_bytes!("../../../apps/piglor-gateway/src/http.rs"),
        ),
        (
            "src/ledger_config.rs",
            include_bytes!("../../../apps/piglor-gateway/src/ledger_config.rs"),
        ),
        (
            "src/owntracks.rs",
            include_bytes!("../../../apps/piglor-gateway/src/owntracks.rs"),
        ),
        (
            "src/owntracks_http.rs",
            include_bytes!("../../../apps/piglor-gateway/src/owntracks_http.rs"),
        ),
        (
            "src/main.rs",
            include_bytes!("../../../apps/piglor-gateway/src/main.rs"),
        ),
        (
            "plugins/world/src/lib.rs",
            include_bytes!("../../../plugins/world/src/lib.rs"),
        ),
    ],
};

static WORLD_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[InstalledPluginV1 {
        name: "world",
        type_name: "pos_plugin_world::WorldPlugin",
        event_types: &[
            WORLD_ACTION_EVENT_TYPE_V1,
            "world.observation.v1",
            "world.config.v1",
        ],
        driver_type: Some("pos_plugin_world::WorldDriver"),
    }],
    approver_type: Some("pos_plugin_world::WorldPlugin"),
    workload_profile: WorkloadProfileV1::Fork,
    source_files: &[(
        "src/lib.rs",
        include_bytes!("../../../plugins/world/src/lib.rs"),
    )],
};

static RULE_AGENT_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[InstalledPluginV1 {
        name: "rule-agent",
        type_name: "pos_plugin_rule_agent::RuleAgentPlugin",
        event_types: &["agent.decision"],
        driver_type: Some("pos_plugin_rule_agent::RuleAgentDriver"),
    }],
    approver_type: None,
    workload_profile: WorkloadProfileV1::Research,
    source_files: &[(
        "src/lib.rs",
        include_bytes!("../../../plugins/entities/rule-agent/src/lib.rs"),
    )],
};

static AGENT_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[InstalledPluginV1 {
        name: "agent",
        type_name: "pos_plugin_agent::AgentPlugin",
        event_types: &["agent.action", "runtime.recorded_output"],
        driver_type: None,
    }],
    approver_type: None,
    workload_profile: WorkloadProfileV1::Interactive,
    source_files: &[
        (
            "src/lib.rs",
            include_bytes!("../../../plugins/agent/src/lib.rs"),
        ),
        (
            "src/protocol.rs",
            include_bytes!("../../../plugins/agent/src/protocol.rs"),
        ),
        (
            "src/provider.rs",
            include_bytes!("../../../plugins/agent/src/provider.rs"),
        ),
        (
            "src/provider_driver.rs",
            include_bytes!("../../../plugins/agent/src/provider_driver.rs"),
        ),
        (
            "src/replay.rs",
            include_bytes!("../../../plugins/agent/src/replay.rs"),
        ),
    ],
};

static SYNTHETIC_OBSERVATION_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[InstalledPluginV1 {
        name: "synthetic-obs",
        type_name: "pos_plugin_synthetic_obs::SyntheticObsPlugin",
        event_types: &["obs.synthetic"],
        driver_type: Some("pos_plugin_synthetic_obs::SyntheticDriver"),
    }],
    approver_type: None,
    workload_profile: WorkloadProfileV1::Research,
    source_files: &[(
        "src/lib.rs",
        include_bytes!("../../../plugins/observations/synthetic/src/lib.rs"),
    )],
};

static SOCIETY_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[
        InstalledPluginV1 {
            name: "society",
            type_name: "pos_plugin_society::SocietyPlugin",
            event_types: &["society.signal"],
            driver_type: None,
        },
        InstalledPluginV1 {
            name: "society-signal-projection",
            type_name: "pos_plugin_society::SocietySignalProjectionPlugin",
            event_types: &[],
            driver_type: None,
        },
    ],
    approver_type: None,
    workload_profile: WorkloadProfileV1::Fork,
    source_files: &[(
        "src/lib.rs",
        include_bytes!("../../../plugins/society/src/lib.rs"),
    )],
};

static EXPERIMENT_SOURCE: InstalledSourceDescriptorV1 = InstalledSourceDescriptorV1 {
    plugins: &[
        InstalledPluginV1 {
            name: "successful-sibling",
            type_name: "pos_experiment::moat_proof::SiblingProbePlugin",
            event_types: &["proof.failure.sibling"],
            driver_type: Some("pos_experiment::moat_proof::SiblingProbeDriver"),
        },
        InstalledPluginV1 {
            name: "failure-probe",
            type_name: "pos_experiment::moat_proof::FailureProbePlugin",
            event_types: &["proof.failure.probe"],
            driver_type: Some("pos_experiment::moat_proof::FailureProbeDriver"),
        },
        InstalledPluginV1 {
            name: "proof-agent",
            type_name: "pos_experiment::moat_proof::ProofAgentPlugin",
            event_types: &["proof.agent.reaction.v1"],
            driver_type: Some("pos_experiment::moat_proof::ProofAgentDriver"),
        },
        InstalledPluginV1 {
            name: "society",
            type_name: "pos_experiment::moat_proof::ProofSocietyPlugin",
            event_types: &["society.signal"],
            driver_type: Some("pos_experiment::moat_proof::ProofSocietyDriver"),
        },
    ],
    approver_type: None,
    workload_profile: WorkloadProfileV1::Fork,
    source_files: &[
        (
            "src/lib.rs",
            include_bytes!("../../../apps/pos-experiment/src/lib.rs"),
        ),
        (
            "src/moat_proof.rs",
            include_bytes!("../../../apps/pos-experiment/src/moat_proof.rs"),
        ),
        (
            "plugins/world/src/lib.rs",
            include_bytes!("../../../plugins/world/src/lib.rs"),
        ),
        (
            "plugins/society/src/lib.rs",
            include_bytes!("../../../plugins/society/src/lib.rs"),
        ),
    ],
};

impl InstalledOutputPolicySourceV1 {
    /// Return the complete native data compiled into this source.
    fn descriptor(self) -> &'static InstalledSourceDescriptorV1 {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Generated => &GENERATED_SOURCE,
            Self::Gateway => &GATEWAY_SOURCE,
            Self::World => &WORLD_SOURCE,
            Self::RuleAgent => &RULE_AGENT_SOURCE,
            Self::Agent => &AGENT_SOURCE,
            Self::SyntheticObservation => &SYNTHETIC_OBSERVATION_SOURCE,
            Self::Society => &SOCIETY_SOURCE,
            Self::Experiment => &EXPERIMENT_SOURCE,
        }
    }

    fn installed_plugin(self, plugin_name: &str) -> Option<&'static InstalledPluginV1> {
        self.descriptor()
            .plugins
            .iter()
            .find(|installed| installed.name == plugin_name)
    }

    pub(crate) fn accepts_plugin<P: Plugin + ?Sized>(self, plugin: &P) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if matches!(self, Self::Generated) {
            return true;
        }
        let owner = PluginInstanceIdentity::installed_owner_token(plugin);
        self.installed_plugin(plugin.name())
            .is_some_and(|installed| owner.verifies_instance(plugin, installed.type_name))
    }

    fn accepts_driver<D: Driver + 'static>(self, plugin_name: &str) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if matches!(self, Self::Generated) {
            return true;
        }
        self.installed_plugin(plugin_name)
            .is_some_and(|installed| installed.driver_type == Some(type_name::<D>()))
    }

    pub(crate) fn accepts_approver<A: ActionApprover + 'static>(self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if matches!(self, Self::Generated) {
            return true;
        }
        self.descriptor().approver_type == Some(type_name::<A>())
    }

    fn implementation_artifact<P: Plugin + ?Sized>(self, plugin: &P) -> Vec<u8> {
        #[cfg(any(test, feature = "test-support"))]
        if matches!(self, Self::Generated) {
            return generated_implementation_artifact_v1(plugin);
        }
        #[cfg(not(any(test, feature = "test-support")))]
        let _ = plugin;
        source_artifact_bundle(self.descriptor().source_files)
    }

    fn event_types<P: Plugin + ?Sized>(self, plugin: &P) -> Vec<String> {
        #[cfg(any(test, feature = "test-support"))]
        if matches!(self, Self::Generated) {
            let mut event_types = plugin
                .capability()
                .owned_event_types
                .into_iter()
                .map(|kind| kind.as_str().to_owned())
                .collect::<Vec<_>>();
            event_types.sort_unstable();
            return event_types;
        }
        let mut event_types =
            self.installed_plugin(plugin.name())
                .map_or_else(Vec::new, |installed| {
                    installed
                        .event_types
                        .iter()
                        .map(|event_type| (*event_type).to_owned())
                        .collect()
                });
        event_types.sort_unstable();
        event_types
    }

    fn workload_profile(self) -> WorkloadProfileV1 {
        self.descriptor().workload_profile
    }

    fn build_budget(
        self,
        plugin_id: PluginId,
        execution_profile_hash: Hash,
    ) -> Result<ExecutableBudgetPolicyV1, OutputAdmissionErrorV1> {
        let workload_profile = self.workload_profile();
        let max_event_bytes = match workload_profile {
            WorkloadProfileV1::Research => 16_384,
            WorkloadProfileV1::Interactive | WorkloadProfileV1::Fork => 4_096,
        };
        ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
            revision: 1,
            workload_profile,
            cut_budget_family: 0,
            max_event_bytes,
            fidelity_budgets: [
                FidelityBudgetV1 {
                    level: 0,
                    max_events: 1_000,
                    max_bytes: 64 * 1024 * 1024,
                    max_cpu_us: 500_000,
                    shared_host_cpu_reservation_us: 0,
                },
                FidelityBudgetV1 {
                    level: 1,
                    max_events: 1_000,
                    max_bytes: 64 * 1024 * 1024,
                    max_cpu_us: 250_000,
                    shared_host_cpu_reservation_us: 0,
                },
                FidelityBudgetV1 {
                    level: 2,
                    max_events: 1_000,
                    max_bytes: 16 * 1024 * 1024,
                    max_cpu_us: 50_000,
                    shared_host_cpu_reservation_us: 0,
                },
            ],
            plugin_cpu_reservations: vec![PluginCpuReservationV1 {
                plugin_id,
                cpu_reservations_us: [250_000, 125_000, 25_000],
            }],
            accounting_semantics: 0,
            execution_profile_hash,
            max_pass_wall_duration_us: 1_000,
        })
        .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EBP1" })
    }

    fn build_policy<P: Plugin + ?Sized>(
        self,
        plugin: &P,
        implementation_hash: Hash,
        configuration_hash: Hash,
        budget: &ExecutableBudgetPolicyV1,
    ) -> Result<OutputPolicyV1, OutputAdmissionErrorV1> {
        let declarations = self
            .event_types(plugin)
            .into_iter()
            .map(|event_type| {
                pos_core::output_policy::OutputDeclarationV1::new(
                    event_type,
                    pos_core::output_policy::OutputAuthorityV1::Authoritative,
                    OutputFidelityV1::L0,
                    4_096,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EOP1" })?;
        OutputPolicyV1::new(pos_core::output_policy::OutputPolicyInputV1 {
            plugin_id: plugin.id(),
            plugin_version: plugin.version().to_owned(),
            implementation_hash,
            base_configuration_digest: configuration_hash,
            executable_profile_hash: budget.digest(),
            retention_policy_hash: crate::reviewed_policy::reviewed_retention_policy_hash_v1(),
            policy_revision: 1,
            output_declarations: declarations,
        })
        .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EOP1" })
    }

    /// Hash the exact implementation source owned by this installed root.
    #[must_use]
    pub fn implementation_artifact_hash<P: Plugin + ?Sized>(self, plugin: &P) -> Hash {
        crate::reviewed_policy::implementation_artifact_hash_v1(
            &self.implementation_artifact(plugin),
        )
    }

    fn resolve_artifacts<P: Plugin + ?Sized>(
        self,
        plugin: &P,
        configuration_details: &[u8],
        profile_id: &str,
    ) -> Result<OutputPolicyArtifactInputV1, OutputAdmissionErrorV1> {
        let configuration_artifact = crate::reviewed_policy::canonical_plugin_configuration_v1(
            plugin,
            configuration_details,
        )
        .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration",
        })?;
        let execution_profile_artifact = execution_profile_artifact_v1(profile_id, self)
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })?;
        let implementation_artifact = self.implementation_artifact(plugin);
        let retention_policy_artifact =
            crate::reviewed_policy::reviewed_retention_policy_bytes_v1();
        OutputPolicyArtifactInputV1::from_slices(
            &implementation_artifact,
            &configuration_artifact,
            &execution_profile_artifact,
            retention_policy_artifact,
        )
    }
}

/// Deterministic implementation bytes for the test-support generated source.
///
/// This remains a bounded fixture source; ordinary registration has no
/// generated fallback and must select an installed composition root above.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn generated_implementation_artifact_v1<P: Plugin + ?Sized>(plugin: &P) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"pigloros.generated-implementation.v1\0");
    append_framed_bytes(&mut bytes, plugin.name().as_bytes());
    append_framed_bytes(&mut bytes, plugin.version().as_bytes());
    let mut event_types = plugin
        .capability()
        .owned_event_types
        .into_iter()
        .map(|kind| kind.as_str().to_owned())
        .collect::<Vec<_>>();
    event_types.sort_unstable();
    for event_type in event_types {
        append_framed_bytes(&mut bytes, event_type.as_bytes());
    }
    bytes
}

fn source_artifact_bundle(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PSB1");
    for (path, source) in parts {
        let path_len = u64::try_from(path.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&path_len.to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
        let source_len = u64::try_from(source.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&source_len.to_be_bytes());
        bytes.extend_from_slice(source);
    }
    bytes
}

#[cfg(any(test, feature = "test-support"))]
fn append_framed_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    output.extend_from_slice(&bytes_len.to_le_bytes());
    output.extend_from_slice(bytes);
}

/// A host-owned output policy binding with no caller-supplied artifact leaves.
pub struct OutputPolicyBindingV1 {
    policy: OutputPolicyV1,
    budget: ExecutableBudgetPolicyV1,
    artifacts: OutputPolicyArtifactInputV1,
    source: InstalledOutputPolicySourceV1,
    plugin_name: &'static str,
    owner_token: PluginOwnerTokenV1,
    /// Validated installed callbacks. They stay inert until installed
    /// registration returns with Wave 9 (#467/#462); see
    /// [`Self::with_installed_driver`].
    driver: Option<Box<dyn Driver>>,
    approver: Option<(Box<dyn ActionApprover>, Vec<Kind>)>,
}

impl OutputPolicyBindingV1 {
    /// Resolve the exact installed source leaves and bind them to one policy.
    ///
    /// # Errors
    /// Returns a closed artifact or profile error before registration can
    /// mutate the registry.
    pub fn from_installed_source<P: Plugin>(
        plugin: &P,
        source: InstalledOutputPolicySourceV1,
        configuration_details: &[u8],
        profile_id: &str,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if !source.accepts_plugin(plugin) {
            return Err(OutputAdmissionErrorV1::PluginMismatch);
        }
        let artifacts = source.resolve_artifacts(plugin, configuration_details, profile_id)?;
        let configuration_hash = crate::reviewed_policy::host_artifact_hash_v1(
            b"pigloros.base-configuration.v1",
            artifacts.configuration_artifact(),
        );
        let budget = source.build_budget(
            plugin.id(),
            crate::reviewed_policy::execution_profile_artifact_hash_v1(
                artifacts.execution_profile_artifact(),
            ),
        )?;
        let implementation_hash = crate::reviewed_policy::implementation_artifact_hash_v1(
            artifacts.implementation_artifact(),
        );
        let policy =
            source.build_policy(plugin, implementation_hash, configuration_hash, &budget)?;
        Ok(Self {
            policy,
            budget,
            artifacts,
            source,
            plugin_name: plugin.name(),
            owner_token: PluginInstanceIdentity::installed_owner_token(plugin),
            driver: None,
            approver: None,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_installed_source_with_policy<P: Plugin + ?Sized>(
        plugin: &P,
        source: InstalledOutputPolicySourceV1,
        policy: OutputPolicyV1,
        budget: ExecutableBudgetPolicyV1,
        configuration_details: &[u8],
        profile_id: &str,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if !source.accepts_plugin(plugin) {
            return Err(OutputAdmissionErrorV1::PluginMismatch);
        }
        let artifacts = source.resolve_artifacts(plugin, configuration_details, profile_id)?;
        Ok(Self {
            policy,
            budget,
            artifacts,
            source,
            plugin_name: plugin.name(),
            owner_token: PluginInstanceIdentity::installed_owner_token(plugin),
            driver: None,
            approver: None,
        })
    }

    /// Attach only the concrete Driver compiled into this installed source.
    ///
    /// The attached Driver stays inert until installed registration returns
    /// with Wave 9 (#467/#462): no Wave 8 path consumes a binding's callbacks,
    /// because installed registration fails closed. The method still checks
    /// the Driver against the reviewed source descriptor now, so a foreign
    /// or duplicate callback can never be bound to an installed source and
    /// the Wave 9 consumer inherits an already-validated binding.
    ///
    /// # Errors
    /// Rejects a foreign or duplicate Driver before registration can mutate state.
    pub fn with_installed_driver<D: Driver + 'static>(
        mut self,
        driver: D,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if self.driver.is_some() || !self.source.accepts_driver::<D>(self.plugin_name) {
            return Err(OutputAdmissionErrorV1::CallbackMismatch { kind: "driver" });
        }
        self.driver = Some(Box::new(driver));
        Ok(self)
    }

    /// Attach only the concrete `ActionApprover` compiled into this installed source.
    ///
    /// Like [`Self::with_installed_driver`], the approver and its routes stay
    /// inert until installed registration returns with Wave 9 (#467/#462).
    /// The reviewed approver type and the route bound are validated now so
    /// that a foreign, duplicate, or unbounded approver is rejected at the
    /// binding boundary rather than at a later consumer.
    ///
    /// # Errors
    /// Rejects a foreign or duplicate approver before registration can mutate state.
    pub fn with_installed_action_approver<A: ActionApprover + 'static>(
        mut self,
        approver: A,
        event_types: impl IntoIterator<Item = Kind>,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if self.approver.is_some()
            || self.source == InstalledOutputPolicySourceV1::World
            || !self.source.accepts_approver::<A>()
        {
            return Err(OutputAdmissionErrorV1::CallbackMismatch { kind: "approver" });
        }
        let routes: Vec<_> = event_types
            .into_iter()
            .take(MAX_OUTPUT_DECLARATIONS_V1 + 1)
            .collect();
        if routes.len() > MAX_OUTPUT_DECLARATIONS_V1 {
            return Err(OutputAdmissionErrorV1::CallbackMismatch { kind: "approver" });
        }
        self.approver = Some((Box::new(approver), routes));
        Ok(self)
    }

    pub(crate) fn verifies_erased_owner_instance(&self, plugin: &dyn Plugin) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if self.source == InstalledOutputPolicySourceV1::Generated {
            return self.owner_token == PluginInstanceIdentity::installed_owner_token(plugin);
        }
        self.source.descriptor().plugins.iter().any(|installed| {
            self.owner_token
                .verifies_erased_instance(plugin, installed.type_name)
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        OutputPolicyV1,
        ExecutableBudgetPolicyV1,
        OutputPolicyArtifactInputV1,
        InstalledOutputPolicySourceV1,
        PluginOwnerTokenV1,
    ) {
        (
            self.policy,
            self.budget,
            self.artifacts,
            self.source,
            self.owner_token,
        )
    }

    /// The host-owned structural EOP1 policy selected for this binding.
    #[must_use]
    pub const fn policy(&self) -> &OutputPolicyV1 {
        &self.policy
    }

    /// The host-owned structural EBP1 budget selected for this binding.
    #[must_use]
    pub const fn budget(&self) -> &ExecutableBudgetPolicyV1 {
        &self.budget
    }

    /// Exact implementation bytes retained by this binding.
    #[must_use]
    pub fn implementation_artifact(&self) -> &[u8] {
        self.artifacts.implementation_artifact()
    }

    /// Exact canonical configuration bytes retained by this binding.
    #[must_use]
    pub fn configuration_artifact(&self) -> &[u8] {
        self.artifacts.configuration_artifact()
    }

    /// Exact installed EPF1 bytes retained by this binding.
    #[must_use]
    pub fn execution_profile_artifact(&self) -> &[u8] {
        self.artifacts.execution_profile_artifact()
    }

    /// Exact reviewed RTP1 bytes retained by this binding.
    #[must_use]
    pub fn retention_policy_artifact(&self) -> &[u8] {
        self.artifacts.retention_policy_artifact()
    }

    /// ADR-088 OPC1 identity of this exact installed source binding.
    ///
    /// This is a structural hash, not owner authentication or permission to
    /// release retained bytes.
    ///
    /// # Errors
    /// Rejects an incomplete or noncanonical installed closure.
    pub fn manifest_closure_hash(&self) -> Result<Hash, OutputAdmissionErrorV1> {
        let closure = OutputPolicyClosureV1::from_artifacts(
            &self.policy.to_canonical_cbor(),
            &self.budget.to_canonical_cbor(),
            self.implementation_artifact(),
            self.configuration_artifact(),
            self.execution_profile_artifact(),
            self.retention_policy_artifact(),
        )?;
        Ok(closure.manifest_closure_hash())
    }
}

/// The immutable artifact closure required to activate one output policy.
///
/// EOP1/EBP1 identify the declarations and executable bounds.  The remaining
/// bytes are the exact implementation, configuration, EPF1, and RTP1 inputs
/// that those records reference.  Keeping the bytes with the admission owner
/// makes the Replay identity retrievable instead of reducing it to opaque
/// digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputPolicyClosureV1 {
    output_policy: OutputPolicyV1,
    executable_budget: ExecutableBudgetPolicyV1,
    output_policy_bytes: Vec<u8>,
    executable_budget_bytes: Vec<u8>,
    implementation_artifact: Vec<u8>,
    configuration_artifact: Vec<u8>,
    execution_profile_artifact: Vec<u8>,
    retention_policy_artifact: Vec<u8>,
}

impl OutputPolicyClosureV1 {
    /// Verify and retain a complete canonical policy closure.
    ///
    /// # Errors
    /// Returns a closed artifact or canonicality error when one referenced
    /// object is absent, malformed, or does not match its recorded identity.
    pub(crate) fn from_artifacts(
        output_policy_bytes: &[u8],
        executable_budget_bytes: &[u8],
        implementation_artifact: &[u8],
        configuration_artifact: &[u8],
        execution_profile_artifact: &[u8],
        retention_policy_artifact: &[u8],
    ) -> Result<Self, OutputAdmissionErrorV1> {
        Self::from_artifacts_inner(
            output_policy_bytes,
            executable_budget_bytes,
            implementation_artifact,
            configuration_artifact,
            execution_profile_artifact,
            retention_policy_artifact,
        )
    }

    fn from_artifacts_inner(
        output_policy_bytes: &[u8],
        executable_budget_bytes: &[u8],
        implementation_artifact: &[u8],
        configuration_artifact: &[u8],
        execution_profile_artifact: &[u8],
        retention_policy_artifact: &[u8],
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if output_policy_bytes.len() > MAX_OUTPUT_POLICY_BYTES_V1 {
            return Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EOP1" });
        }
        if executable_budget_bytes.len() > MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1 {
            return Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EBP1" });
        }
        validate_leaf_lengths(
            implementation_artifact,
            configuration_artifact,
            execution_profile_artifact,
            retention_policy_artifact,
        )?;
        let output_policy = OutputPolicyV1::from_canonical_cbor(output_policy_bytes)
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EOP1" })?;
        let executable_budget =
            ExecutableBudgetPolicyV1::from_canonical_cbor(executable_budget_bytes)
                .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EBP1" })?;
        if !crate::reviewed_policy::is_canonical_plugin_configuration_v1(configuration_artifact) {
            return Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration",
            });
        }
        validate_execution_profile_artifact_v1(execution_profile_artifact)?;
        let retention_policy =
            WorldRetentionPolicyV1::from_canonical_cbor(retention_policy_artifact)
                .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "RTP1" })?;

        let expected_implementation =
            crate::reviewed_policy::implementation_artifact_hash_v1(implementation_artifact);
        if output_policy.fields().implementation_hash != expected_implementation {
            return Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch {
                kind: "implementation",
            });
        }
        let expected_configuration = crate::reviewed_policy::host_artifact_hash_v1(
            b"pigloros.base-configuration.v1",
            configuration_artifact,
        );
        if output_policy.fields().base_configuration_digest != expected_configuration {
            return Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch {
                kind: "configuration",
            });
        }
        let expected_profile =
            crate::reviewed_policy::execution_profile_artifact_hash_v1(execution_profile_artifact);
        if executable_budget.fields().execution_profile_hash != expected_profile
            || output_policy.fields().executable_profile_hash != executable_budget.digest()
        {
            return Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "EPF1" });
        }
        if output_policy.fields().retention_policy_hash != retention_policy.digest() {
            return Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "RTP1" });
        }

        Ok(Self {
            output_policy,
            executable_budget,
            output_policy_bytes: output_policy_bytes.to_vec(),
            executable_budget_bytes: executable_budget_bytes.to_vec(),
            implementation_artifact: implementation_artifact.to_vec(),
            configuration_artifact: configuration_artifact.to_vec(),
            execution_profile_artifact: execution_profile_artifact.to_vec(),
            retention_policy_artifact: retention_policy_artifact.to_vec(),
        })
    }

    /// The decoded EOP1 policy.
    #[must_use]
    pub const fn output_policy(&self) -> &OutputPolicyV1 {
        &self.output_policy
    }

    /// The decoded EBP1 executable budget.
    #[must_use]
    pub const fn executable_budget(&self) -> &ExecutableBudgetPolicyV1 {
        &self.executable_budget
    }

    /// Exact EOP1 bytes retained for Replay closure retrieval.
    #[must_use]
    pub fn output_policy_bytes(&self) -> &[u8] {
        &self.output_policy_bytes
    }

    /// Exact EBP1 bytes retained for Replay closure retrieval.
    #[must_use]
    pub fn executable_budget_bytes(&self) -> &[u8] {
        &self.executable_budget_bytes
    }

    /// Exact implementation artifact bytes retained for Replay closure retrieval.
    #[must_use]
    pub fn implementation_artifact(&self) -> &[u8] {
        &self.implementation_artifact
    }

    /// Exact configuration artifact bytes retained for Replay closure retrieval.
    #[must_use]
    pub fn configuration_artifact(&self) -> &[u8] {
        &self.configuration_artifact
    }

    /// Exact EPF1 bytes retained for Replay closure retrieval.
    #[must_use]
    pub fn execution_profile_artifact(&self) -> &[u8] {
        &self.execution_profile_artifact
    }

    /// Exact RTP1 bytes retained for Replay closure retrieval.
    #[must_use]
    pub fn retention_policy_artifact(&self) -> &[u8] {
        &self.retention_policy_artifact
    }

    /// Stable identity over every retained closure member.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.output-policy-closure.v1\0");
        for bytes in [
            self.output_policy_bytes(),
            self.executable_budget_bytes(),
            self.implementation_artifact(),
            self.configuration_artifact(),
            self.execution_profile_artifact(),
            self.retention_policy_artifact(),
        ] {
            let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            hasher.update(&bytes_len.to_le_bytes());
            hasher.update(bytes);
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// ADR-088's exact OPC1 identity for the later scoped native closure leaf.
    ///
    /// This hash identifies retained bytes; it does not prove owner admission,
    /// native retention, or permission to release protected material.
    #[must_use]
    pub fn manifest_closure_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
        hasher.update(&self.to_canonical_bytes());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Stable identity for comparing this closure across fresh Plugin IDs.
    ///
    /// The exact EOP1/EBP1 bytes remain available through the retrieval
    /// accessors and [`Self::to_canonical_bytes`], but their allocated Plugin
    /// IDs are intentionally excluded from this comparison identity.  The
    /// typed policy and budget fields, together with every non-address
    /// artifact, still participate in the digest.
    #[must_use]
    pub fn replay_identity_digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.output-policy-replay-identity.v1\0");
        let policy = self.output_policy.fields();
        hash_framed(&mut hasher, policy.plugin_version.as_bytes());
        for hash in [
            policy.implementation_hash,
            policy.base_configuration_digest,
            policy.retention_policy_hash,
        ] {
            hasher.update(hash.as_bytes());
        }
        hasher.update(&policy.policy_revision.to_le_bytes());
        let mut declarations = policy.output_declarations.iter().collect::<Vec<_>>();
        declarations.sort_by(|left, right| left.event_type().cmp(right.event_type()));
        for declaration in declarations {
            hash_framed(&mut hasher, declaration.event_type().as_bytes());
            hasher.update(&[match declaration.authority() {
                pos_core::output_policy::OutputAuthorityV1::Authoritative => 0,
                pos_core::output_policy::OutputAuthorityV1::ReproducibleDerived => 1,
                pos_core::output_policy::OutputAuthorityV1::Ephemeral => 2,
            }]);
            hasher.update(&[match declaration.fidelity() {
                OutputFidelityV1::L0 => 0,
                OutputFidelityV1::L1 => 1,
                OutputFidelityV1::L2 => 2,
            }]);
            hasher.update(&declaration.max_bytes().to_le_bytes());
            hasher.update(&declaration.stride_ticks().unwrap_or_default().to_le_bytes());
            hasher.update(
                &declaration
                    .aggregate_min_group()
                    .unwrap_or_default()
                    .to_le_bytes(),
            );
        }
        let budget = self.executable_budget.fields();
        hasher.update(&budget.revision.to_le_bytes());
        hasher.update(&[match budget.workload_profile {
            pos_core::WorkloadProfileV1::Interactive => 0,
            pos_core::WorkloadProfileV1::Fork => 1,
            pos_core::WorkloadProfileV1::Research => 2,
        }]);
        hasher.update(&[budget.cut_budget_family]);
        hasher.update(&budget.max_event_bytes.to_le_bytes());
        for fidelity in budget.fidelity_budgets {
            hasher.update(&[fidelity.level]);
            hasher.update(&fidelity.max_events.to_le_bytes());
            hasher.update(&fidelity.max_bytes.to_le_bytes());
            hasher.update(&fidelity.max_cpu_us.to_le_bytes());
            hasher.update(&fidelity.shared_host_cpu_reservation_us.to_le_bytes());
        }
        let mut reservations = budget
            .plugin_cpu_reservations
            .iter()
            .map(|reservation| reservation.cpu_reservations_us)
            .collect::<Vec<_>>();
        reservations.sort_unstable();
        for reservation in reservations {
            for value in reservation {
                hasher.update(&value.to_le_bytes());
            }
        }
        hasher.update(&[budget.accounting_semantics]);
        hasher.update(budget.execution_profile_hash.as_bytes());
        hasher.update(&budget.max_pass_wall_duration_us.to_le_bytes());
        for bytes in [
            self.implementation_artifact(),
            self.configuration_artifact(),
            self.execution_profile_artifact(),
            self.retention_policy_artifact(),
        ] {
            hash_framed(&mut hasher, bytes);
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Encode the retained closure as one deterministic, length-framed record.
    ///
    /// This is a retrieval envelope for a Replay manifest; each member keeps
    /// its own native EOP1/EBP1/EPF1/RTP1 encoding and is independently
    /// revalidated before use.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let members = [
            self.output_policy_bytes(),
            self.executable_budget_bytes(),
            self.implementation_artifact(),
            self.configuration_artifact(),
            self.execution_profile_artifact(),
            self.retention_policy_artifact(),
        ];
        let total_len = members.iter().fold(4usize, |length, bytes| {
            length.saturating_add(8).saturating_add(bytes.len())
        });
        debug_assert!(total_len <= MAX_OUTPUT_POLICY_CLOSURE_BYTES_V1);
        let mut output = Vec::with_capacity(total_len.min(MAX_OUTPUT_POLICY_CLOSURE_BYTES_V1));
        output.extend_from_slice(b"OPC1");
        for bytes in members {
            let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            output.extend_from_slice(&bytes_len.to_be_bytes());
            output.extend_from_slice(bytes);
        }
        output
    }
}

/// Validate a complete host artifact set without minting an admission closure.
///
/// Closure construction remains private to registry registration; this
/// read-only seam is useful to independent host preflight tooling.
///
/// # Errors
/// Returns the closed artifact or identity error reported by the native
/// policy, budget, profile, and retention decoders.
pub fn validate_output_policy_artifacts_v1(
    output_policy_bytes: &[u8],
    executable_budget_bytes: &[u8],
    implementation_artifact: &[u8],
    configuration_artifact: &[u8],
    execution_profile_artifact: &[u8],
    retention_policy_artifact: &[u8],
) -> Result<(), OutputAdmissionErrorV1> {
    OutputPolicyClosureV1::from_artifacts_inner(
        output_policy_bytes,
        executable_budget_bytes,
        implementation_artifact,
        configuration_artifact,
        execution_profile_artifact,
        retention_policy_artifact,
    )
    .map(|_| ())
}

fn hash_framed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(&bytes_len.to_le_bytes());
    hasher.update(bytes);
}

const fn validate_leaf_lengths(
    implementation_artifact: &[u8],
    configuration_artifact: &[u8],
    execution_profile_artifact: &[u8],
    retention_policy_artifact: &[u8],
) -> Result<(), OutputAdmissionErrorV1> {
    if implementation_artifact.is_empty()
        || implementation_artifact.len()
            > crate::reviewed_policy::MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1
    {
        return Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "implementation",
        });
    }
    if configuration_artifact.len()
        > crate::reviewed_policy::MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1
    {
        return Err(OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration",
        });
    }
    if execution_profile_artifact.len() > MAX_EXECUTION_PROFILE_BYTES_V1 {
        return Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" });
    }
    if retention_policy_artifact.len() > MAX_WORLD_RETENTION_RECORD_BYTES_V1 {
        return Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "RTP1" });
    }
    Ok(())
}

fn validate_execution_profile_artifact_v1(bytes: &[u8]) -> Result<(), OutputAdmissionErrorV1> {
    #[cfg(target_os = "linux")]
    {
        pos_conformance::ExecutionProfileV1::from_canonical_cbor(bytes)
            .map(|_| ())
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = bytes;
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn draft_execution_profile_artifact_v1(
    profile_id: &str,
) -> Result<Vec<u8>, OutputAdmissionErrorV1> {
    #[cfg(target_os = "linux")]
    {
        pos_conformance::draft_execution_profile_bytes_v1(profile_id)
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile_id;
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    }
}

fn execution_profile_artifact_v1(
    profile_id: &str,
    source: InstalledOutputPolicySourceV1,
) -> Result<Vec<u8>, OutputAdmissionErrorV1> {
    #[cfg(any(test, feature = "test-support"))]
    if source == InstalledOutputPolicySourceV1::Generated {
        return draft_execution_profile_artifact_v1(profile_id);
    }
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = source;
    #[cfg(target_os = "linux")]
    {
        pos_conformance::host_verified_execution_profile_bytes_v1(profile_id)
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile_id;
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    }
}

/// Deterministic, host-side validation of one Plugin's complete output batch.
///
/// The validator is intentionally immutable: a rejected staged step cannot
/// consume budget. The host invokes it before append and exposes the policy
/// digest to the surrounding evidence pipeline.
#[derive(Debug)]
pub struct OutputAdmissionV1 {
    plugin_id: PluginId,
    policy_digest: Hash,
    policy: OutputPolicyV1,
    budget: ExecutableBudgetPolicyV1,
    usage: Mutex<AdmissionUsage>,
    closure: Option<OutputPolicyClosureV1>,
    owner_token: Option<PluginOwnerTokenV1>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AdmissionUsage {
    events: [u64; 3],
    bytes: [u64; 3],
}

impl OutputAdmissionV1 {
    /// Bind a structural output policy to its exact executable budget identity.
    ///
    /// # Errors
    /// Returns an identity or budget error when the policy does not describe
    /// the registered Plugin and its executable reservation.
    #[cfg(test)]
    pub(crate) fn try_new(
        plugin_id: PluginId,
        plugin_version: &str,
        policy: OutputPolicyV1,
        budget: ExecutableBudgetPolicyV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        Self::try_new_core(plugin_id, plugin_version, policy, budget)
    }

    /// Bind a Plugin to a complete, host-verified artifact closure.
    ///
    /// # Errors
    /// Returns an identity, artifact, or budget error when the closure does
    /// not describe the registered Plugin and its executable reservation.
    pub(crate) fn try_new_verified(
        plugin_id: PluginId,
        plugin_version: &str,
        closure: OutputPolicyClosureV1,
        owner_token: PluginOwnerTokenV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        Self::try_new_verified_inner(plugin_id, plugin_version, closure).map(|mut admission| {
            admission.owner_token = Some(owner_token);
            admission
        })
    }

    fn try_new_verified_inner(
        plugin_id: PluginId,
        plugin_version: &str,
        closure: OutputPolicyClosureV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        let policy = closure.output_policy().clone();
        let budget = closure.executable_budget().clone();
        let admission = Self::try_new_core(plugin_id, plugin_version, policy, budget)?;
        Ok(Self {
            closure: Some(closure),
            ..admission
        })
    }

    fn try_new_core(
        plugin_id: PluginId,
        plugin_version: &str,
        policy: OutputPolicyV1,
        budget: ExecutableBudgetPolicyV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if policy.fields().plugin_id != plugin_id {
            return Err(OutputAdmissionErrorV1::PluginMismatch);
        }
        if policy.fields().plugin_version != plugin_version {
            return Err(OutputAdmissionErrorV1::PluginVersionMismatch);
        }
        if policy.fields().executable_profile_hash != budget.digest() {
            return Err(OutputAdmissionErrorV1::PolicyIdentityMismatch);
        }
        let has_cpu_reservation = budget
            .fields()
            .plugin_cpu_reservations
            .iter()
            .any(|row| row.plugin_id == plugin_id);
        if !has_cpu_reservation {
            return Err(OutputAdmissionErrorV1::MissingCpuReservation);
        }
        Ok(Self {
            plugin_id,
            policy_digest: policy.digest(),
            policy,
            budget,
            usage: Mutex::new(AdmissionUsage::default()),
            closure: None,
            owner_token: None,
        })
    }

    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    #[must_use]
    pub const fn policy_digest(&self) -> Hash {
        self.policy_digest
    }

    #[must_use]
    pub const fn policy(&self) -> &OutputPolicyV1 {
        &self.policy
    }

    #[must_use]
    pub const fn budget(&self) -> &ExecutableBudgetPolicyV1 {
        &self.budget
    }

    /// Return the retained closure when this admission was host-verified.
    #[must_use]
    pub const fn closure(&self) -> Option<&OutputPolicyClosureV1> {
        self.closure.as_ref()
    }

    pub(crate) const fn owner_token(&self) -> Option<PluginOwnerTokenV1> {
        self.owner_token
    }

    pub(crate) fn reset_usage(&self) {
        *self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = AdmissionUsage::default();
    }

    /// Validate every draft against declarations and the complete step budget.
    ///
    /// # Errors
    /// Returns a declaration or resource-limit error when any draft exceeds
    /// the bound policy.
    pub fn validate_batch(&self, drafts: &[EventDraft]) -> Result<(), OutputAdmissionErrorV1> {
        self.validate_batch_with_usage(drafts, true)
    }

    /// Validate one host-approved action without consuming the Driver cut budget.
    ///
    /// Actions are individually fenced append operations rather than staged
    /// Driver output. They still require the registered policy, declaration,
    /// byte, count, and CPU checks, but their admission must not exhaust the
    /// next independent action by retaining the previous action's usage.
    ///
    /// # Errors
    /// Returns the same declaration or resource-limit error as [`Self::validate_batch`].
    pub fn validate_action(&self, draft: &EventDraft) -> Result<(), OutputAdmissionErrorV1> {
        self.validate_batch_with_usage(std::slice::from_ref(draft), false)
    }

    fn validate_batch_with_usage(
        &self,
        drafts: &[EventDraft],
        retain_usage: bool,
    ) -> Result<(), OutputAdmissionErrorV1> {
        // Hold the usage lock across validation and commit so concurrent host
        // invocations cannot validate against the same stale cumulative total.
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut counts = usage.events;
        let mut bytes = usage.bytes;
        for draft in drafts {
            let Some(declaration) = self
                .policy
                .fields()
                .output_declarations
                .iter()
                .find(|declaration| declaration.event_type() == draft.event_type.as_str())
            else {
                return Err(OutputAdmissionErrorV1::MissingDeclaration {
                    event_type: draft.event_type.as_str().to_owned(),
                });
            };
            let payload_bytes = draft.payload.len();
            // Compare in u64 without lossy casts; a length beyond u64 saturates
            // and is rejected by every u32 event limit.
            let payload_len = u64::try_from(payload_bytes).unwrap_or(u64::MAX);
            let event_limit = declaration
                .max_bytes()
                .min(self.budget.fields().max_event_bytes);
            if payload_len > u64::from(event_limit) {
                return Err(OutputAdmissionErrorV1::EventBytesExceeded {
                    event_type: draft.event_type.as_str().to_owned(),
                    requested: payload_bytes,
                    limit: event_limit,
                });
            }
            let level = match declaration.fidelity() {
                OutputFidelityV1::L0 => 0,
                OutputFidelityV1::L1 => 1,
                OutputFidelityV1::L2 => 2,
            };
            counts[level] = counts[level].saturating_add(1);
            bytes[level] = bytes[level].saturating_add(payload_len);
        }

        for (level_index, budget) in self.budget.fields().fidelity_budgets.iter().enumerate() {
            let level: u8 = match level_index {
                0 => 0,
                1 => 1,
                _ => 2,
            };
            if counts[level_index] > u64::from(budget.max_events) {
                return Err(OutputAdmissionErrorV1::EventCountExceeded {
                    level,
                    requested: counts[level_index],
                    limit: budget.max_events,
                });
            }
            if bytes[level_index] > budget.max_bytes {
                return Err(OutputAdmissionErrorV1::BatchBytesExceeded {
                    level,
                    requested: bytes[level_index],
                    limit: budget.max_bytes,
                });
            }
        }
        if retain_usage {
            *usage = AdmissionUsage {
                events: counts,
                bytes,
            };
        }
        drop(usage);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(debug_assertions)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        output_policy::{
            OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1, OutputPolicyInputV1,
        },
        ExecutableBudgetPolicyInputV1, FidelityBudgetV1, PluginCpuReservationV1, WorkloadProfileV1,
    };

    /// Unwrap a fixture result, resuming the unwind with the error's debug text.
    trait OrResume<T> {
        fn or_resume(self) -> T;
    }

    impl<T, E: std::fmt::Debug> OrResume<T> for Result<T, E> {
        #[track_caller]
        fn or_resume(self) -> T {
            self.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
        }
    }

    struct SourceProbeDriver;

    impl Driver for SourceProbeDriver {
        fn step(
            &mut self,
            _timeline: pos_core::TimelineId,
            _observations: crate::driver::ObservationView<'_>,
        ) -> Result<crate::driver::StepOutput, crate::RuntimeError> {
            Err(crate::RuntimeError::ErasureOperationUnavailable)
        }

        fn name(&self) -> &'static str {
            "source-probe"
        }
    }

    #[test]
    fn draft_epf1_requires_generated_source() -> Result<(), Box<dyn std::error::Error>> {
        let profile_id = "deterministic-local-v1";
        let generated =
            execution_profile_artifact_v1(profile_id, InstalledOutputPolicySourceV1::Generated)?;
        assert_eq!(
            generated,
            pos_conformance::draft_execution_profile_bytes_v1(profile_id)?
        );
        for source in [
            InstalledOutputPolicySourceV1::Gateway,
            InstalledOutputPolicySourceV1::World,
            InstalledOutputPolicySourceV1::RuleAgent,
            InstalledOutputPolicySourceV1::Agent,
            InstalledOutputPolicySourceV1::SyntheticObservation,
            InstalledOutputPolicySourceV1::Society,
            InstalledOutputPolicySourceV1::Experiment,
        ] {
            assert_eq!(
                execution_profile_artifact_v1(profile_id, source),
                Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
            );
        }
        Ok(())
    }

    #[test]
    fn installed_sources_reject_unrelated_driver_types() {
        for source in [
            InstalledOutputPolicySourceV1::Gateway,
            InstalledOutputPolicySourceV1::Agent,
            InstalledOutputPolicySourceV1::Society,
            InstalledOutputPolicySourceV1::World,
            InstalledOutputPolicySourceV1::RuleAgent,
            InstalledOutputPolicySourceV1::SyntheticObservation,
        ] {
            assert!(!source.accepts_driver::<SourceProbeDriver>("unrelated"));
        }
        for plugin_name in [
            "successful-sibling",
            "failure-probe",
            "proof-agent",
            "society",
            "unrelated",
        ] {
            assert!(!InstalledOutputPolicySourceV1::Experiment
                .accepts_driver::<SourceProbeDriver>(plugin_name));
        }
    }

    #[test]
    fn installed_sources_reject_unrelated_approver_types() {
        assert!(InstalledOutputPolicySourceV1::Generated.accepts_approver::<BindingTestApprover>());
        for source in [
            InstalledOutputPolicySourceV1::RuleAgent,
            InstalledOutputPolicySourceV1::Agent,
            InstalledOutputPolicySourceV1::SyntheticObservation,
            InstalledOutputPolicySourceV1::Society,
            InstalledOutputPolicySourceV1::Experiment,
        ] {
            assert!(!source.accepts_approver::<BindingTestApprover>());
        }
    }

    #[test]
    fn binding_attaches_one_driver_and_checks_the_owner_instance() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "fixture",
            events: vec![Kind::new("plugin.output")],
        };
        let generated = || {
            OutputPolicyBindingV1::from_installed_source(
                &plugin,
                InstalledOutputPolicySourceV1::Generated,
                &[],
                "deterministic-local-v1",
            )
            .or_resume()
        };
        let driven = generated()
            .with_installed_driver(SourceProbeDriver)
            .or_resume();
        assert!(matches!(
            driven.with_installed_driver(SourceProbeDriver),
            Err(OutputAdmissionErrorV1::CallbackMismatch { kind: "driver" })
        ));

        let cloned_plugin = plugin.clone();
        let mut owned = generated();
        assert!(owned.verifies_erased_owner_instance(&plugin));
        assert!(!owned.verifies_erased_owner_instance(&cloned_plugin));
        // An installed source checks the owner against its descriptor types,
        // which a fixture Plugin never matches.
        owned.source = InstalledOutputPolicySourceV1::Gateway;
        assert!(!owned.verifies_erased_owner_instance(&plugin));
    }

    fn budget(
        plugin_id: PluginId,
        max_event_bytes: u32,
        max_events: u32,
        max_bytes: u64,
        max_cpu_us: u32,
        cpu_reservations_us: [u32; 3],
    ) -> ExecutableBudgetPolicyV1 {
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
        .or_resume()
    }

    fn policy(plugin_id: PluginId, budget: &ExecutableBudgetPolicyV1) -> OutputPolicyV1 {
        let declaration = OutputDeclarationV1::new(
            "plugin.output".to_owned(),
            OutputAuthorityV1::Authoritative,
            OutputFidelityV1::L0,
            16,
            None,
            None,
        )
        .or_resume();
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
        .or_resume()
    }

    fn draft(event_type: &str, bytes: &[u8]) -> EventDraft {
        EventDraft::new(
            pos_core::EntityId::new(),
            Kind::new(event_type),
            CanonicalBytes::from_vec(bytes.to_vec()),
        )
    }

    #[derive(Clone)]
    struct FixturePlugin {
        id: PluginId,
        name: &'static str,
        events: Vec<Kind>,
    }

    impl Plugin for FixturePlugin {
        fn id(&self) -> PluginId {
            self.id
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn capability(&self) -> pos_core::Capability {
            pos_core::Capability {
                owned_event_types: self.events.clone(),
                has_driver: true,
                ..pos_core::Capability::default()
            }
        }
    }

    struct BindingTestApprover;

    impl ActionApprover for BindingTestApprover {
        fn approve(
            &self,
            proposal: &pos_core::ProposedAction,
        ) -> Result<EventDraft, pos_core::ActionRejected> {
            Ok(EventDraft::new(
                proposal.actor_entity_id,
                proposal.event_type.clone(),
                proposal.payload.clone(),
            ))
        }
    }

    #[test]
    fn gateway_source_closure_retains_the_delegated_world_approver_source() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "gateway-world-actions",
            events: Vec::new(),
        };
        let artifact = InstalledOutputPolicySourceV1::Gateway.implementation_artifact(&plugin);
        let delegated: &[u8] = include_bytes!("../../../plugins/world/src/lib.rs");
        assert!(artifact
            .windows(delegated.len())
            .any(|window| window == delegated));
        assert!(!InstalledOutputPolicySourceV1::Gateway.accepts_approver::<BindingTestApprover>());
    }

    #[test]
    fn manifest_binding_hash_rejects_a_changed_artifact() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "fixture",
            events: Vec::new(),
        };
        let mut binding = OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::Generated,
            &[],
            "deterministic-local-v1",
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(binding.manifest_closure_hash().is_ok());
        binding.artifacts.configuration.push(0xff);
        assert!(binding.manifest_closure_hash().is_err());
    }

    struct LongVersionPlugin {
        version: &'static str,
    }

    impl Plugin for LongVersionPlugin {
        fn id(&self) -> PluginId {
            PluginId::new()
        }

        fn name(&self) -> &'static str {
            "long-version"
        }

        fn capability(&self) -> pos_core::Capability {
            pos_core::Capability {
                owned_event_types: vec![Kind::new("version.output")],
                ..pos_core::Capability::default()
            }
        }

        fn version(&self) -> &'static str {
            self.version
        }
    }

    fn closure_for(
        plugin_id: PluginId,
        workload_profile: WorkloadProfileV1,
    ) -> OutputPolicyClosureV1 {
        let profile = draft_execution_profile_artifact_v1("deterministic-local-v1").or_resume();
        let profile_hash = crate::reviewed_policy::execution_profile_artifact_hash_v1(&profile);
        let budget = ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
            revision: 1,
            workload_profile,
            cut_budget_family: 0,
            max_event_bytes: match workload_profile {
                WorkloadProfileV1::Research => 16_384,
                WorkloadProfileV1::Interactive | WorkloadProfileV1::Fork => 4_096,
            },
            fidelity_budgets: [
                FidelityBudgetV1 {
                    level: 0,
                    max_events: 100,
                    max_bytes: 100_000,
                    max_cpu_us: 100_000,
                    shared_host_cpu_reservation_us: 0,
                },
                FidelityBudgetV1 {
                    level: 1,
                    max_events: 100,
                    max_bytes: 100_000,
                    max_cpu_us: 100_000,
                    shared_host_cpu_reservation_us: 0,
                },
                FidelityBudgetV1 {
                    level: 2,
                    max_events: 100,
                    max_bytes: 100_000,
                    max_cpu_us: 50_000,
                    shared_host_cpu_reservation_us: 0,
                },
            ],
            plugin_cpu_reservations: vec![PluginCpuReservationV1 {
                plugin_id,
                cpu_reservations_us: [10, 20, 30],
            }],
            accounting_semantics: 0,
            execution_profile_hash: profile_hash,
            max_pass_wall_duration_us: 1_000,
        })
        .or_resume();
        let implementation = b"fixture-implementation";
        let configuration = fixture_configuration_artifact();
        let declarations = vec![
            OutputDeclarationV1::new(
                "a.authoritative".to_owned(),
                OutputAuthorityV1::Authoritative,
                OutputFidelityV1::L0,
                64,
                None,
                None,
            )
            .or_resume(),
            OutputDeclarationV1::new(
                "b.derived".to_owned(),
                OutputAuthorityV1::ReproducibleDerived,
                OutputFidelityV1::L1,
                64,
                Some(2),
                None,
            )
            .or_resume(),
            OutputDeclarationV1::new(
                "c.ephemeral".to_owned(),
                OutputAuthorityV1::Ephemeral,
                OutputFidelityV1::L2,
                64,
                None,
                Some(10),
            )
            .or_resume(),
        ];
        let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
            plugin_id,
            plugin_version: "1.0.0".to_owned(),
            implementation_hash: crate::reviewed_policy::implementation_artifact_hash_v1(
                implementation,
            ),
            base_configuration_digest: crate::reviewed_policy::host_artifact_hash_v1(
                b"pigloros.base-configuration.v1",
                &configuration,
            ),
            executable_profile_hash: budget.digest(),
            retention_policy_hash: crate::reviewed_policy::reviewed_retention_policy_hash_v1(),
            policy_revision: 1,
            output_declarations: declarations,
        })
        .or_resume();
        OutputPolicyClosureV1::from_artifacts(
            &policy.to_canonical_cbor(),
            &budget.to_canonical_cbor(),
            implementation,
            &configuration,
            &profile,
            crate::reviewed_policy::reviewed_retention_policy_bytes_v1(),
        )
        .or_resume()
    }

    fn fixture_configuration_artifact() -> Vec<u8> {
        let mut artifact = b"CFG1".to_vec();
        for field in [
            b"fixture".as_slice(),
            b"1.0.0".as_slice(),
            b"fixture.output".as_slice(),
            b"fixture".as_slice(),
        ] {
            append_framed_bytes(&mut artifact, field);
        }
        artifact
    }

    const fn installed_sources() -> [InstalledOutputPolicySourceV1; 8] {
        [
            InstalledOutputPolicySourceV1::Generated,
            InstalledOutputPolicySourceV1::Gateway,
            InstalledOutputPolicySourceV1::World,
            InstalledOutputPolicySourceV1::RuleAgent,
            InstalledOutputPolicySourceV1::Agent,
            InstalledOutputPolicySourceV1::SyntheticObservation,
            InstalledOutputPolicySourceV1::Society,
            InstalledOutputPolicySourceV1::Experiment,
        ]
    }

    #[test]
    fn installed_source_descriptors_bind_native_types_and_event_types() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "fixture",
            events: vec![Kind::new("fixture.output")],
        };
        for source in installed_sources() {
            let expected_native_types: &[&str] = match source {
                InstalledOutputPolicySourceV1::Generated => &[],
                InstalledOutputPolicySourceV1::Gateway => &["piglor_gateway::GatewayActionPlugin"],
                InstalledOutputPolicySourceV1::World => &["pos_plugin_world::WorldPlugin"],
                InstalledOutputPolicySourceV1::RuleAgent => {
                    &["pos_plugin_rule_agent::RuleAgentPlugin"]
                }
                InstalledOutputPolicySourceV1::Agent => &["pos_plugin_agent::AgentPlugin"],
                InstalledOutputPolicySourceV1::SyntheticObservation => {
                    &["pos_plugin_synthetic_obs::SyntheticObsPlugin"]
                }
                InstalledOutputPolicySourceV1::Society => &[
                    "pos_plugin_society::SocietyPlugin",
                    "pos_plugin_society::SocietySignalProjectionPlugin",
                ],
                InstalledOutputPolicySourceV1::Experiment => &[
                    "pos_experiment::moat_proof::SiblingProbePlugin",
                    "pos_experiment::moat_proof::FailureProbePlugin",
                    "pos_experiment::moat_proof::ProofAgentPlugin",
                    "pos_experiment::moat_proof::ProofSocietyPlugin",
                ],
            };
            let native_types = source
                .descriptor()
                .plugins
                .iter()
                .map(|installed| installed.type_name)
                .collect::<Vec<_>>();
            assert_eq!(native_types, expected_native_types);
            assert!(!source.implementation_artifact(&plugin).is_empty());
            let expected_event_types: &[&str] = match source {
                InstalledOutputPolicySourceV1::Generated => &["fixture.output"],
                InstalledOutputPolicySourceV1::Gateway => &["world.action.v1"],
                InstalledOutputPolicySourceV1::World => {
                    &["world.action.v1", "world.observation.v1", "world.config.v1"]
                }
                InstalledOutputPolicySourceV1::RuleAgent => &["agent.decision"],
                InstalledOutputPolicySourceV1::Agent => {
                    &["agent.action", "runtime.recorded_output"]
                }
                InstalledOutputPolicySourceV1::SyntheticObservation => &["obs.synthetic"],
                InstalledOutputPolicySourceV1::Society => &["society.signal"],
                InstalledOutputPolicySourceV1::Experiment => &["proof.failure.sibling"],
            };
            let mut expected_event_types = expected_event_types
                .iter()
                .map(|event_type| (*event_type).to_owned())
                .collect::<Vec<_>>();
            expected_event_types.sort_unstable();
            let installed_name = source
                .descriptor()
                .plugins
                .first()
                .map_or(plugin.name, |installed| installed.name);
            let named = FixturePlugin {
                id: plugin.id,
                name: installed_name,
                events: vec![Kind::new("fixture.output")],
            };
            assert_eq!(source.event_types(&named), expected_event_types);
        }
    }

    #[test]
    fn installed_sources_exercise_names_artifacts_and_policy_builders() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "fixture",
            events: vec![Kind::new("fixture.output")],
        };
        for source in installed_sources() {
            let expected_profile = match source {
                InstalledOutputPolicySourceV1::Generated
                | InstalledOutputPolicySourceV1::Gateway
                | InstalledOutputPolicySourceV1::Agent => WorkloadProfileV1::Interactive,
                InstalledOutputPolicySourceV1::RuleAgent
                | InstalledOutputPolicySourceV1::SyntheticObservation => {
                    WorkloadProfileV1::Research
                }
                InstalledOutputPolicySourceV1::World
                | InstalledOutputPolicySourceV1::Society
                | InstalledOutputPolicySourceV1::Experiment => WorkloadProfileV1::Fork,
            };
            assert_eq!(source.workload_profile(), expected_profile);
            let accepts_plugin = source.accepts_plugin(&plugin);
            assert_eq!(
                accepts_plugin,
                matches!(source, InstalledOutputPolicySourceV1::Generated)
            );
            let budget = source
                .build_budget(plugin.id, Hash::from_bytes([9; 32]))
                .or_resume();
            if matches!(source, InstalledOutputPolicySourceV1::Generated) {
                assert!(accepts_plugin);
                source
                    .build_policy(
                        &plugin,
                        source.implementation_artifact_hash(&plugin),
                        Hash::from_bytes([8; 32]),
                        &budget,
                    )
                    .or_resume();
            } else {
                assert!(!accepts_plugin);
            }
        }
    }

    #[test]
    fn experiment_source_event_types_are_name_bound() {
        for name in [
            "proof-agent",
            "proof-society",
            "society",
            "successful-sibling",
            "failure-probe",
            "unknown-experiment",
        ] {
            let named = FixturePlugin {
                id: PluginId::new(),
                name,
                events: vec![Kind::new("fixture.output")],
            };
            let expected_event_types = match name {
                "proof-agent" => vec!["proof.agent.reaction.v1".to_owned()],
                "society" => vec!["society.signal".to_owned()],
                "successful-sibling" => vec!["proof.failure.sibling".to_owned()],
                "failure-probe" => vec!["proof.failure.probe".to_owned()],
                _ => Vec::new(),
            };
            assert_eq!(
                InstalledOutputPolicySourceV1::Experiment.event_types(&named),
                expected_event_types
            );
            assert!(!InstalledOutputPolicySourceV1::Experiment.accepts_plugin(&named));
        }
    }

    #[test]
    fn generated_policy_rejects_invalid_event_type_and_long_version() {
        let empty = FixturePlugin {
            id: PluginId::new(),
            name: "empty",
            events: vec![Kind::new("")],
        };
        let budget = InstalledOutputPolicySourceV1::Generated
            .build_budget(empty.id, Hash::from_bytes([9; 32]))
            .or_resume();
        assert!(InstalledOutputPolicySourceV1::Generated
            .build_policy(
                &empty,
                InstalledOutputPolicySourceV1::Generated.implementation_artifact_hash(&empty),
                Hash::from_bytes([8; 32]),
                &budget,
            )
            .is_err());
        let long_version = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";
        let long_version_plugin = LongVersionPlugin {
            version: long_version,
        };
        let budget = InstalledOutputPolicySourceV1::Generated
            .build_budget(long_version_plugin.id(), Hash::from_bytes([9; 32]))
            .or_resume();
        assert!(InstalledOutputPolicySourceV1::Generated
            .build_policy(
                &long_version_plugin,
                InstalledOutputPolicySourceV1::Generated
                    .implementation_artifact_hash(&long_version_plugin),
                Hash::from_bytes([8; 32]),
                &budget,
            )
            .is_err());
        assert!(OutputPolicyBindingV1::from_installed_source(
            &long_version_plugin,
            InstalledOutputPolicySourceV1::Generated,
            &[],
            "deterministic-local-v1",
        )
        .is_err());
    }

    #[test]
    fn binding_leaf_and_profile_errors_are_closed() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "fixture",
            events: vec![Kind::new("fixture.output")],
        };
        let too_large =
            vec![0_u8; crate::reviewed_policy::MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1 + 1];
        assert!(matches!(
            OutputPolicyArtifactInputV1::from_slices(&too_large, b"CFG1", b"profile", b"retention",),
            Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "implementation"
            })
        ));
        let too_large =
            vec![0_u8; crate::reviewed_policy::MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1 + 1];
        assert!(matches!(
            OutputPolicyArtifactInputV1::from_slices(
                b"implementation",
                &too_large,
                b"profile",
                b"retention",
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration"
            })
        ));
        let too_large = vec![0_u8; MAX_EXECUTION_PROFILE_BYTES_V1 + 1];
        assert!(matches!(
            OutputPolicyArtifactInputV1::from_slices(
                b"implementation",
                b"CFG1",
                &too_large,
                b"retention",
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
        ));
        let too_large = vec![0_u8; MAX_WORLD_RETENTION_RECORD_BYTES_V1 + 1];
        assert!(matches!(
            OutputPolicyArtifactInputV1::from_slices(
                b"implementation",
                b"CFG1",
                b"profile",
                &too_large,
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "RTP1" })
        ));
        let details =
            vec![0_u8; crate::reviewed_policy::MAX_PLUGIN_CONFIGURATION_DETAILS_BYTES_V1 + 1];
        assert!(matches!(
            OutputPolicyBindingV1::from_installed_source(
                &plugin,
                InstalledOutputPolicySourceV1::Generated,
                &details,
                "deterministic-local-v1",
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration"
            })
        ));
        assert!(matches!(
            OutputPolicyBindingV1::from_installed_source(
                &plugin,
                InstalledOutputPolicySourceV1::Generated,
                &[],
                "missing-profile",
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
        ));
        let budget = budget(plugin.id, 16, 2, 32, 100, [10, 10, 10]);
        let policy = policy(plugin.id, &budget);
        assert!(matches!(
            OutputPolicyBindingV1::from_installed_source_with_policy(
                &plugin,
                InstalledOutputPolicySourceV1::Generated,
                policy.clone(),
                budget.clone(),
                &details,
                "deterministic-local-v1",
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration"
            })
        ));
        assert!(matches!(
            OutputPolicyBindingV1::from_installed_source_with_policy(
                &plugin,
                InstalledOutputPolicySourceV1::Generated,
                policy,
                budget,
                &[],
                "missing-profile",
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
        ));
    }

    #[test]
    fn binding_rejects_an_unrelated_installed_source() {
        let plugin = FixturePlugin {
            id: PluginId::new(),
            name: "fixture",
            events: vec![Kind::new("fixture.output")],
        };
        let budget = budget(plugin.id, 16, 2, 32, 100, [10, 10, 10]);
        let policy = policy(plugin.id, &budget);
        assert!(matches!(
            OutputPolicyBindingV1::from_installed_source_with_policy(
                &plugin,
                InstalledOutputPolicySourceV1::World,
                policy,
                budget,
                &[],
                "deterministic-local-v1",
            ),
            Err(OutputAdmissionErrorV1::PluginMismatch)
        ));
    }

    #[test]
    fn malformed_budget_bytes_fail_before_configuration_admission() {
        let closure = closure_for(PluginId::new(), WorkloadProfileV1::Interactive);
        assert!(matches!(
            OutputPolicyClosureV1::from_artifacts(
                closure.output_policy_bytes(),
                b"invalid-budget",
                closure.implementation_artifact(),
                closure.configuration_artifact(),
                closure.execution_profile_artifact(),
                closure.retention_policy_artifact(),
            ),
            Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EBP1" })
        ));
    }

    #[test]
    fn closure_digests_cover_all_declared_identity_variants() {
        let plugin_id = PluginId::new();
        let mut replay_identities = Vec::new();
        for workload in [
            WorkloadProfileV1::Interactive,
            WorkloadProfileV1::Fork,
            WorkloadProfileV1::Research,
        ] {
            let closure = closure_for(plugin_id, workload);
            assert_ne!(closure.digest(), Hash::zero());
            replay_identities.push(closure.replay_identity_digest());
            assert!(!closure.output_policy_bytes().is_empty());
            assert!(!closure.executable_budget_bytes().is_empty());
            assert_eq!(closure.implementation_artifact(), b"fixture-implementation");
            assert_eq!(
                closure.configuration_artifact(),
                fixture_configuration_artifact()
            );
            assert!(!closure.execution_profile_artifact().is_empty());
            assert!(!closure.retention_policy_artifact().is_empty());
            assert!(!closure.to_canonical_bytes().is_empty());
        }
        assert_ne!(replay_identities[0], replay_identities[1]);
        assert_ne!(replay_identities[0], replay_identities[2]);
        assert_ne!(replay_identities[1], replay_identities[2]);
    }

    #[test]
    fn admission_core_identity_and_accessors_are_exercised() {
        let plugin_id = PluginId::new();
        let budget_a = budget(plugin_id, 16, 2, 32, 100, [10, 10, 10]);
        let policy_a = policy(plugin_id, &budget_a);
        let admission =
            OutputAdmissionV1::try_new(plugin_id, "1.0.0", policy_a.clone(), budget_a.clone())
                .or_resume();
        assert_eq!(admission.plugin_id(), plugin_id);
        assert_eq!(admission.policy(), &policy_a);
        assert_eq!(admission.budget(), &budget_a);
        assert!(admission.closure().is_none());
        assert!(admission.owner_token().is_none());
        let budget_b = budget(plugin_id, 15, 2, 32, 100, [10, 10, 10]);
        assert!(matches!(
            OutputAdmissionV1::try_new(plugin_id, "1.0.0", policy_a.clone(), budget_b.clone()),
            Err(OutputAdmissionErrorV1::PolicyIdentityMismatch)
        ));
        assert!(matches!(
            OutputAdmissionV1::try_new_core(
                PluginId::new(),
                "1.0.0",
                policy_a.clone(),
                budget_a.clone(),
            ),
            Err(OutputAdmissionErrorV1::PluginMismatch)
        ));
        assert!(matches!(
            OutputAdmissionV1::try_new_core(plugin_id, "2.0.0", policy_a.clone(), budget_a),
            Err(OutputAdmissionErrorV1::PluginVersionMismatch)
        ));
        assert!(matches!(
            OutputAdmissionV1::try_new_core(plugin_id, "1.0.0", policy_a, budget_b),
            Err(OutputAdmissionErrorV1::PolicyIdentityMismatch)
        ));
        let other_id = PluginId::new();
        let other_budget = budget(other_id, 16, 2, 32, 100, [10, 10, 10]);
        assert!(matches!(
            OutputAdmissionV1::try_new_core(
                plugin_id,
                "1.0.0",
                policy(plugin_id, &other_budget),
                other_budget,
            ),
            Err(OutputAdmissionErrorV1::MissingCpuReservation)
        ));
        let closure = closure_for(plugin_id, WorkloadProfileV1::Interactive);
        let verified = OutputAdmissionV1::try_new_verified(
            plugin_id,
            "1.0.0",
            closure,
            FixturePlugin {
                id: plugin_id,
                name: "fixture",
                events: vec![Kind::new("fixture.output")],
            }
            .installed_owner_token(),
        )
        .or_resume();
        assert!(verified.closure().is_some());
        assert!(verified.owner_token().is_some());
    }

    #[test]
    fn accepts_declared_output_and_tracks_identity() {
        let plugin_id = PluginId::new();
        let budget = budget(plugin_id, 16, 2, 32, 100, [10, 10, 10]);
        let admission =
            OutputAdmissionV1::try_new(plugin_id, "1.0.0", policy(plugin_id, &budget), budget)
                .or_resume();
        admission
            .validate_batch(&[draft("plugin.output", b"accepted")])
            .or_resume();
        assert!(matches!(
            admission.validate_batch(&[
                draft("plugin.output", b"second"),
                draft("plugin.output", b"third")
            ]),
            Err(OutputAdmissionErrorV1::EventCountExceeded { level: 0, .. })
        ));
        assert_ne!(admission.policy_digest(), Hash::zero());
    }

    #[test]
    fn fixture_verified_admission_accepts_each_declared_fidelity() {
        let plugin_id = PluginId::new();
        let closure = closure_for(plugin_id, WorkloadProfileV1::Interactive);
        let owner = FixturePlugin {
            id: plugin_id,
            name: "fixture",
            events: vec![
                Kind::new("a.authoritative"),
                Kind::new("b.derived"),
                Kind::new("c.ephemeral"),
            ],
        }
        .installed_owner_token();
        let admission =
            OutputAdmissionV1::try_new_verified(plugin_id, "1.0.0", closure, owner).or_resume();
        admission
            .validate_batch(&[
                draft("a.authoritative", b"a"),
                draft("b.derived", b"b"),
                draft("c.ephemeral", b"c"),
            ])
            .or_resume();
    }

    #[test]
    fn rejects_missing_declarations_and_identity_mismatches() {
        let plugin_id = PluginId::new();
        let budget = budget(plugin_id, 16, 2, 32, 100, [10, 10, 10]);
        let admission = OutputAdmissionV1::try_new(
            plugin_id,
            "1.0.0",
            policy(plugin_id, &budget),
            budget.clone(),
        )
        .or_resume();
        assert!(matches!(
            admission.validate_batch(&[draft("plugin.unknown", b"x")]),
            Err(OutputAdmissionErrorV1::MissingDeclaration { .. })
        ));
        assert!(matches!(
            OutputAdmissionV1::try_new(
                PluginId::new(),
                "1.0.0",
                policy(plugin_id, &budget),
                budget.clone(),
            ),
            Err(OutputAdmissionErrorV1::PluginMismatch)
        ));
        assert!(matches!(
            OutputAdmissionV1::try_new(plugin_id, "2.0.0", policy(plugin_id, &budget), budget),
            Err(OutputAdmissionErrorV1::PluginVersionMismatch)
        ));
    }

    #[test]
    fn accounts_for_fidelity_and_resource_limits() {
        let plugin_id = PluginId::new();
        let bytes_budget = budget(plugin_id, 4, 2, 32, 100, [10, 10, 10]);
        let bytes_admission = OutputAdmissionV1::try_new(
            plugin_id,
            "1.0.0",
            policy(plugin_id, &bytes_budget),
            bytes_budget,
        )
        .or_resume();
        assert!(matches!(
            bytes_admission.validate_batch(&[draft("plugin.output", b"12345")]),
            Err(OutputAdmissionErrorV1::EventBytesExceeded { .. })
        ));

        let batch_budget = budget(plugin_id, 16, 2, 3, 100, [10, 10, 10]);
        let batch_admission = OutputAdmissionV1::try_new(
            plugin_id,
            "1.0.0",
            policy(plugin_id, &batch_budget),
            batch_budget,
        )
        .or_resume();
        assert!(matches!(
            batch_admission
                .validate_batch(&[draft("plugin.output", b"ab"), draft("plugin.output", b"cd")]),
            Err(OutputAdmissionErrorV1::BatchBytesExceeded { .. })
        ));

        let cpu_budget = budget(plugin_id, 16, 3, 32, 10, [10, 10, 10]);
        let cpu_admission = OutputAdmissionV1::try_new(
            plugin_id,
            "1.0.0",
            policy(plugin_id, &cpu_budget),
            cpu_budget,
        )
        .or_resume();
        assert!(cpu_admission
            .validate_batch(&[draft("plugin.output", b"a"), draft("plugin.output", b"b")])
            .is_ok());
        assert!(cpu_admission
            .validate_batch(&[draft("plugin.output", b"c")])
            .is_ok());

        let no_cpu_plugin = PluginId::new();
        let no_cpu_budget = budget(no_cpu_plugin, 16, 2, 32, 100, [10, 10, 10]);
        assert!(matches!(
            OutputAdmissionV1::try_new(
                plugin_id,
                "1.0.0",
                policy(plugin_id, &no_cpu_budget),
                no_cpu_budget,
            ),
            Err(OutputAdmissionErrorV1::MissingCpuReservation)
        ));
    }
}
