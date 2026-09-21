//! Host-owned admission of Plugin output against one recorded policy identity.

use pos_conformance::ExecutionProfileV1;
use pos_core::{
    event::EventDraft,
    output_policy::{OutputFidelityV1, OutputPolicyV1, MAX_OUTPUT_POLICY_BYTES_V1},
    retention::{WorldRetentionPolicyV1, MAX_WORLD_RETENTION_RECORD_BYTES_V1},
    ExecutableBudgetPolicyV1, Hash, Plugin, PluginId, MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1,
};
use std::sync::Mutex;

/// Maximum aggregate bytes retained by one output-policy closure envelope.
pub const MAX_OUTPUT_POLICY_CLOSURE_BYTES_V1: usize = 2 * 65_536
    + 2 * crate::reviewed_policy::MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1
    + pos_conformance::MAX_EXECUTION_PROFILE_BYTES_V1
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
    #[error("Plugin output exceeds the executable CPU budget")]
    CpuExceeded {
        level: u8,
        requested: u64,
        limit: u32,
    },
    #[error("executable budget has no CPU reservation for the registered Plugin")]
    MissingCpuReservation,
    #[error("{kind} artifact is missing or malformed")]
    ArtifactInvalid { kind: &'static str },
    #[error("{kind} artifact identity does not match the recorded policy")]
    ArtifactIdentityMismatch { kind: &'static str },
}

/// Exact artifacts returned by an installed host owner for one policy.
///
/// The fields are private so callers can only hand them to the runtime
/// verifier through an [`OutputPolicyAuthorityV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputPolicyArtifactInputV1 {
    implementation_artifact: Vec<u8>,
    configuration_artifact: Vec<u8>,
    execution_profile_artifact: Vec<u8>,
    retention_policy_artifact: Vec<u8>,
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
            implementation_artifact: implementation_artifact.to_vec(),
            configuration_artifact: configuration_artifact.to_vec(),
            execution_profile_artifact: execution_profile_artifact.to_vec(),
            retention_policy_artifact: retention_policy_artifact.to_vec(),
        })
    }

    #[must_use]
    pub fn implementation_artifact(&self) -> &[u8] {
        &self.implementation_artifact
    }

    #[must_use]
    pub fn configuration_artifact(&self) -> &[u8] {
        &self.configuration_artifact
    }

    #[must_use]
    pub fn execution_profile_artifact(&self) -> &[u8] {
        &self.execution_profile_artifact
    }

    #[must_use]
    pub fn retention_policy_artifact(&self) -> &[u8] {
        &self.retention_policy_artifact
    }
}

/// Installed host authority that resolves one Plugin's exact artifacts.
///
/// Composition roots construct this authority from their installed module,
/// configuration, execution-profile, and retention sources.  The runtime
/// invokes it during registration and performs the final native validation and
/// identity checks before minting an admission closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledOutputPolicyAuthorityV1 {
    plugin_name: String,
    plugin_version: String,
    artifacts: OutputPolicyArtifactInputV1,
}

impl InstalledOutputPolicyAuthorityV1 {
    /// Build an installed authority from host-owned source artifacts.
    ///
    /// # Errors
    /// Returns an artifact error before copying an oversized source.
    pub fn try_new(
        plugin: &dyn Plugin,
        implementation_artifact: &[u8],
        configuration_details: &[u8],
        execution_profile_artifact: &[u8],
        retention_policy_artifact: &[u8],
    ) -> Result<Self, OutputAdmissionErrorV1> {
        let configuration_artifact = crate::reviewed_policy::canonical_plugin_configuration_v1(
            plugin,
            configuration_details,
        )
        .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration",
        })?;
        let artifacts = OutputPolicyArtifactInputV1::from_slices(
            implementation_artifact,
            &configuration_artifact,
            execution_profile_artifact,
            retention_policy_artifact,
        )?;
        Ok(Self {
            plugin_name: plugin.name().to_owned(),
            plugin_version: plugin.version().to_owned(),
            artifacts,
        })
    }

    fn resolve(
        &self,
        plugin: &dyn Plugin,
    ) -> Result<OutputPolicyArtifactInputV1, OutputAdmissionErrorV1> {
        if plugin.name() != self.plugin_name {
            return Err(OutputAdmissionErrorV1::ArtifactIdentityMismatch {
                kind: "configuration",
            });
        }
        if plugin.version() != self.plugin_version {
            return Err(OutputAdmissionErrorV1::PluginVersionMismatch);
        }
        Ok(self.artifacts.clone())
    }
}

/// Host capability used by the runtime to resolve exact policy artifacts.
pub trait OutputPolicyAuthorityV1: Send + Sync {
    /// Resolve artifacts for the requested policy and executable budget.
    fn resolve(
        &self,
        plugin: &dyn Plugin,
        policy: &OutputPolicyV1,
        budget: &ExecutableBudgetPolicyV1,
    ) -> Result<OutputPolicyArtifactInputV1, OutputAdmissionErrorV1>;
}

impl OutputPolicyAuthorityV1 for InstalledOutputPolicyAuthorityV1 {
    fn resolve(
        &self,
        plugin: &dyn Plugin,
        _policy: &OutputPolicyV1,
        _budget: &ExecutableBudgetPolicyV1,
    ) -> Result<OutputPolicyArtifactInputV1, OutputAdmissionErrorV1> {
        self.resolve(plugin)
    }
}

/// A policy and budget bound to an installed host authority.
pub struct OutputPolicyBindingV1 {
    policy: OutputPolicyV1,
    budget: ExecutableBudgetPolicyV1,
    authority: Box<dyn OutputPolicyAuthorityV1>,
}

impl OutputPolicyBindingV1 {
    /// Bind structural policy values to the authority that owns their source
    /// artifacts.
    #[must_use]
    pub fn new(
        policy: OutputPolicyV1,
        budget: ExecutableBudgetPolicyV1,
        authority: Box<dyn OutputPolicyAuthorityV1>,
    ) -> Self {
        Self {
            policy,
            budget,
            authority,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        OutputPolicyV1,
        ExecutableBudgetPolicyV1,
        Box<dyn OutputPolicyAuthorityV1>,
    ) {
        (self.policy, self.budget, self.authority)
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
    /// Build a closure from the host's typed policy values and exact source
    /// artifacts.  The configuration bytes are framed with the registered
    /// Plugin's immutable name/version/capability descriptor before identity
    /// verification.
    ///
    /// # Errors
    /// Returns the same closed artifact or canonicality errors as
    /// [`Self::from_artifacts`].
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn from_plugin_artifacts(
        plugin: &dyn Plugin,
        output_policy: &OutputPolicyV1,
        executable_budget: &ExecutableBudgetPolicyV1,
        implementation_artifact: &[u8],
        configuration_details: &[u8],
        execution_profile_artifact: &[u8],
        retention_policy_artifact: &[u8],
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if implementation_artifact.len()
            > crate::reviewed_policy::MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1
        {
            return Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "implementation",
            });
        }
        let configuration_artifact = crate::reviewed_policy::canonical_plugin_configuration_v1(
            plugin,
            configuration_details,
        )
        .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid {
            kind: "configuration",
        })?;
        Self::from_artifacts(
            &output_policy.to_canonical_cbor(),
            &executable_budget.to_canonical_cbor(),
            implementation_artifact,
            &configuration_artifact,
            execution_profile_artifact,
            retention_policy_artifact,
        )
    }

    /// Verify and retain a complete canonical policy closure.
    ///
    /// # Errors
    /// Returns a closed artifact or canonicality error when one referenced
    /// object is absent, malformed, or does not match its recorded identity.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn from_artifacts(
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

    #[cfg(not(debug_assertions))]
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
        if !configuration_artifact.starts_with(b"CFG1") {
            return Err(OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration",
            });
        }
        ExecutionProfileV1::from_canonical_cbor(execution_profile_artifact)
            .map_err(|_| OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })?;
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
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
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
            output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            output.extend_from_slice(bytes);
        }
        output
    }
}

fn hash_framed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn validate_leaf_lengths(
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
    if execution_profile_artifact.len() > pos_conformance::MAX_EXECUTION_PROFILE_BYTES_V1 {
        return Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" });
    }
    if retention_policy_artifact.len() > MAX_WORLD_RETENTION_RECORD_BYTES_V1 {
        return Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "RTP1" });
    }
    Ok(())
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
    cpu_reservations_us: [u32; 3],
    usage: Mutex<AdmissionUsage>,
    closure: Option<OutputPolicyClosureV1>,
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
    #[cfg(debug_assertions)]
    pub fn try_new(
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
        let Some(cpu_reservations_us) = budget
            .fields()
            .plugin_cpu_reservations
            .iter()
            .find(|row| row.plugin_id == plugin_id)
            .map(|row| row.cpu_reservations_us)
        else {
            return Err(OutputAdmissionErrorV1::MissingCpuReservation);
        };
        Ok(Self {
            plugin_id,
            policy_digest: policy.digest(),
            policy,
            budget,
            cpu_reservations_us,
            usage: Mutex::new(AdmissionUsage::default()),
            closure: None,
        })
    }

    /// Bind a Plugin to a complete, host-verified artifact closure.
    ///
    /// # Errors
    /// Returns an identity, artifact, or budget error when the closure does
    /// not describe the registered Plugin and its executable reservation.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn try_new_verified(
        plugin_id: PluginId,
        plugin_version: &str,
        closure: OutputPolicyClosureV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        Self::try_new_verified_inner(plugin_id, plugin_version, closure)
    }

    #[cfg(not(debug_assertions))]
    pub(crate) fn try_new_verified(
        plugin_id: PluginId,
        plugin_version: &str,
        closure: OutputPolicyClosureV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        Self::try_new_verified_inner(plugin_id, plugin_version, closure)
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
        let Some(cpu_reservations_us) = budget
            .fields()
            .plugin_cpu_reservations
            .iter()
            .find(|row| row.plugin_id == plugin_id)
            .map(|row| row.cpu_reservations_us)
        else {
            return Err(OutputAdmissionErrorV1::MissingCpuReservation);
        };
        Ok(Self {
            plugin_id,
            policy_digest: policy.digest(),
            policy,
            budget,
            cpu_reservations_us,
            usage: Mutex::new(AdmissionUsage::default()),
            closure: None,
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
            let event_limit = declaration
                .max_bytes()
                .min(self.budget.fields().max_event_bytes);
            if payload_bytes > event_limit as usize {
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
            bytes[level] = bytes[level].saturating_add(payload_bytes as u64);
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
            let cpu = counts[level_index]
                .saturating_mul(u64::from(self.cpu_reservations_us[level_index]));
            if cpu > u64::from(budget.max_cpu_us) {
                return Err(OutputAdmissionErrorV1::CpuExceeded {
                    level,
                    requested: cpu,
                    limit: budget.max_cpu_us,
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
