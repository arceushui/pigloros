//! Root-owned identities sealed into one fresh installation transaction.

use ciborium::value::Value;

use super::{fresh_distinct_selector_id, AdmittedSelectorProvider};
use crate::evaluator_protocol::encode;
use crate::sandbox_provider_protocol::{SandboxTrustKey, SandboxTrustRole};
use crate::selector::SelectorBoundaryError;

const PREVIOUS_PROVIDER_BINDING_DOMAIN: &[u8] = b"PiglorOS.PreviousProviderBinding.v1\0";
const MAX_ATTEMPTS: usize = 256;

/// Root-selector allocated identity for one admitted provider runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRuntimeSlot {
    provider_manifest_digest: [u8; 32],
    runtime_instance_id: [u8; 16],
    lifecycle_scope_id: [u8; 16],
}

impl ProviderRuntimeSlot {
    /// Allocate distinct, nonzero runtime and lifecycle identities.
    ///
    /// # Errors
    /// Returns a closed failure when selector entropy is unavailable.
    pub(crate) fn allocate(
        admitted: &AdmittedSelectorProvider,
    ) -> Result<Self, SelectorBoundaryError> {
        let provider_manifest_digest = admitted.provider().manifest().manifest_digest;
        let runtime_instance_id = fresh_distinct_selector_id(&[])?;
        let lifecycle_scope_id = fresh_distinct_selector_id(&[runtime_instance_id])?;
        Ok(Self {
            provider_manifest_digest,
            runtime_instance_id,
            lifecycle_scope_id,
        })
    }

    /// Runtime identity used by the concrete lifecycle adapter.
    #[must_use]
    pub const fn runtime_instance_id(&self) -> [u8; 16] {
        self.runtime_instance_id
    }

    /// Lifecycle-scope identity used by the concrete lifecycle adapter.
    #[must_use]
    pub const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.lifecycle_scope_id
    }

    /// Bind this slot to the exact observed provider main process.
    ///
    /// # Errors
    /// Rejects a zero PID. Start-time zero is valid at the kernel boot-clock origin.
    pub(crate) const fn bind_observed_process(
        self,
        main_pid: u64,
        main_start_time_ticks: u64,
    ) -> Result<AdmittedProviderRuntime, SelectorBoundaryError> {
        if main_pid == 0 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(AdmittedProviderRuntime {
            slot: self,
            main_pid,
            main_start_time_ticks,
        })
    }
}

/// Exact process identity for one root-selector allocated admitted runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedProviderRuntime {
    slot: ProviderRuntimeSlot,
    main_pid: u64,
    main_start_time_ticks: u64,
}

impl AdmittedProviderRuntime {
    /// Root-selector runtime identity.
    #[must_use]
    pub const fn runtime_instance_id(&self) -> [u8; 16] {
        self.slot.runtime_instance_id
    }

    /// Root-selector lifecycle-scope identity.
    #[must_use]
    pub const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.slot.lifecycle_scope_id
    }

    /// Observed provider main PID.
    #[must_use]
    pub const fn main_pid(&self) -> u64 {
        self.main_pid
    }

    /// Observed `/proc/<pid>/stat` start-time ticks.
    #[must_use]
    pub const fn main_start_time_ticks(&self) -> u64 {
        self.main_start_time_ticks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreviousProviderBinding {
    provider_id: String,
    provider_manifest_digest: [u8; 32],
    provider_binary_digest: [u8; 32],
    public_contract_digest: [u8; 32],
    runtime_key_id: String,
    runtime_public_key: [u8; 32],
    runtime_key_epoch: u64,
    runtime_instance_id: [u8; 16],
    lifecycle_scope_id: [u8; 16],
    main_pid: u64,
    main_start_time_ticks: u64,
}

impl PreviousProviderBinding {
    fn value(&self) -> Value {
        Value::Array(vec![
            Value::Text(self.provider_id.clone()),
            Value::Bytes(self.provider_manifest_digest.to_vec()),
            Value::Bytes(self.provider_binary_digest.to_vec()),
            Value::Bytes(self.public_contract_digest.to_vec()),
            Value::Array(vec![
                Value::Text(self.runtime_key_id.clone()),
                Value::Integer(3_u64.into()),
                Value::Bytes(self.runtime_public_key.to_vec()),
                Value::Integer(self.runtime_key_epoch.into()),
            ]),
            Value::Bytes(self.runtime_instance_id.to_vec()),
            Value::Bytes(self.lifecycle_scope_id.to_vec()),
            Value::Integer(self.main_pid.into()),
            Value::Integer(self.main_start_time_ticks.into()),
        ])
    }

    fn digest(&self) -> Result<[u8; 32], SelectorBoundaryError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREVIOUS_PROVIDER_BINDING_DOMAIN);
        hasher.update(&encode(&self.value()).map_err(invalid)?);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryPeerSlot {
    runtime: [u8; 16],
    lifecycle_scope: [u8; 16],
    endpoint: [u8; 16],
}

impl RecoveryPeerSlot {
    fn allocate(previous: &PreviousProviderBinding) -> Result<Self, SelectorBoundaryError> {
        let excluded = [previous.runtime_instance_id, previous.lifecycle_scope_id];
        let runtime = fresh_distinct_selector_id(&excluded)?;
        let lifecycle_scope = fresh_distinct_selector_id(&[excluded[0], excluded[1], runtime])?;
        let endpoint =
            fresh_distinct_selector_id(&[excluded[0], excluded[1], runtime, lifecycle_scope])?;
        Ok(Self {
            runtime,
            lifecycle_scope,
            endpoint,
        })
    }

    fn value(&self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.runtime.to_vec()),
            Value::Bytes(self.lifecycle_scope.to_vec()),
            Value::Bytes(self.endpoint.to_vec()),
        ])
    }
}

/// Opaque root-selector snapshot used to commit one exact SIR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationRecoverySnapshot {
    previous_provider: PreviousProviderBinding,
    recovery_slot: RecoveryPeerSlot,
    previous_live_attempt_ids: Vec<[u8; 16]>,
    required_cancelled_attempt_ids: Vec<[u8; 16]>,
}

impl InstallationRecoverySnapshot {
    /// Seal the exact admitted runtime and complete fenced attempt snapshot.
    ///
    /// # Errors
    /// Rejects a foreign runtime, invalid runtime authority, malformed attempt
    /// sets, or an affected set that is not a subset of the live set.
    pub(crate) fn seal(
        admitted: &AdmittedSelectorProvider,
        runtime: &AdmittedProviderRuntime,
        previous_live_attempt_ids: Vec<[u8; 16]>,
        required_cancelled_attempt_ids: Vec<[u8; 16]>,
    ) -> Result<Self, SelectorBoundaryError> {
        let provider = admitted.provider().manifest();
        if runtime.slot.provider_manifest_digest != provider.manifest_digest {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        validate_attempts(&previous_live_attempt_ids)?;
        validate_attempts(&required_cancelled_attempt_ids)?;
        if required_cancelled_attempt_ids
            .iter()
            .any(|id| previous_live_attempt_ids.binary_search(id).is_err())
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let runtime_key = runtime_key(admitted, &provider.runtime_attestation_key_id)?;
        let previous_provider = PreviousProviderBinding {
            provider_id: provider.provider_id.clone(),
            provider_manifest_digest: provider.manifest_digest,
            provider_binary_digest: provider.binary_digest,
            public_contract_digest: provider.public_contract_digest,
            runtime_key_id: runtime_key.key_id.clone(),
            runtime_public_key: runtime_key.public_key,
            runtime_key_epoch: runtime_key.epoch,
            runtime_instance_id: runtime.runtime_instance_id(),
            lifecycle_scope_id: runtime.lifecycle_scope_id(),
            main_pid: runtime.main_pid(),
            main_start_time_ticks: runtime.main_start_time_ticks(),
        };
        let recovery_slot = RecoveryPeerSlot::allocate(&previous_provider)?;
        Ok(Self {
            previous_provider,
            recovery_slot,
            previous_live_attempt_ids,
            required_cancelled_attempt_ids,
        })
    }

    pub(super) fn previous_provider_value(&self) -> Value {
        self.previous_provider.value()
    }

    pub(super) fn previous_provider_digest(&self) -> Result<[u8; 32], SelectorBoundaryError> {
        self.previous_provider.digest()
    }

    pub(super) fn recovery_slot_value(&self) -> Value {
        self.recovery_slot.value()
    }

    pub(super) fn previous_live_attempt_ids(&self) -> &[[u8; 16]] {
        &self.previous_live_attempt_ids
    }

    pub(super) fn required_cancelled_attempt_ids(&self) -> &[[u8; 16]] {
        &self.required_cancelled_attempt_ids
    }

    pub(super) fn runtime_key(&self) -> (&str, [u8; 32]) {
        (
            &self.previous_provider.runtime_key_id,
            self.previous_provider.runtime_public_key,
        )
    }
}

fn runtime_key<'a>(
    admitted: &'a AdmittedSelectorProvider,
    key_id: &str,
) -> Result<&'a SandboxTrustKey, SelectorBoundaryError> {
    admitted
        .bootstrap()
        .trust()
        .keys()
        .iter()
        .find(|key| {
            key.key_id == key_id && key.role == SandboxTrustRole::ProviderRuntimeAttestation
        })
        .ok_or(SelectorBoundaryError::ArtifactInvalid)
}

fn validate_attempts(ids: &[[u8; 16]]) -> Result<(), SelectorBoundaryError> {
    if ids.len() > MAX_ATTEMPTS
        || ids.contains(&[0; 16])
        || !ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}

const fn invalid(_: crate::evaluator_protocol::ProtocolError) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}
