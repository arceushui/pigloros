//! Sealed root-selector identities retained by one installation recovery transaction.

use ciborium::value::Value;

use crate::evaluator_protocol::{array, array_values, encode, fixed_bytes, text, uint};
use crate::sandbox_provider_protocol::{
    SandboxProviderManifest, SandboxTrustKey, SandboxTrustRole,
};
use crate::selector::SelectorBoundaryError;

use super::super::InstalledSelectorAuthority;

const PREVIOUS_PROVIDER_BINDING_DOMAIN: &[u8] = b"PiglorOS.PreviousProviderBinding.v1\0";
const MAX_ATTEMPTS: usize = 256;

/// Root-selector allocated identity for one admitted provider runtime slot.
///
/// The fields are opaque so arbitrary identifiers cannot be substituted after
/// the slot is bound to one admitted provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRuntimeSlot {
    provider_manifest_digest: [u8; 32],
    runtime_instance_id: [u8; 16],
    lifecycle_scope_id: [u8; 16],
}

impl ProviderRuntimeSlot {
    pub(crate) fn allocate(provider_manifest_digest: [u8; 32]) -> Self {
        let runtime_instance_id = random_id(&[]);
        let lifecycle_scope_id = random_id(&[runtime_instance_id]);
        Self {
            provider_manifest_digest,
            runtime_instance_id,
            lifecycle_scope_id,
        }
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

    /// Bind the allocated slot to the exact observed provider main process.
    ///
    /// # Errors
    /// Rejects an invalid PID. Start-time zero is valid on kernels whose boot
    /// clock observation is zero at process creation.
    pub const fn bind_observed_process(
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

    /// Observed main PID; process identity also requires its start-time ticks.
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
pub(super) struct PreviousProviderBinding {
    pub(super) provider_id: String,
    pub(super) provider_manifest_digest: [u8; 32],
    pub(super) provider_binary_digest: [u8; 32],
    pub(super) public_contract_digest: [u8; 32],
    pub(super) runtime_key_id: String,
    pub(super) runtime_public_key: [u8; 32],
    pub(super) runtime_key_epoch: u64,
    pub(super) runtime_instance_id: [u8; 16],
    pub(super) lifecycle_scope_id: [u8; 16],
    pub(super) main_pid: u64,
    pub(super) main_start_time_ticks: u64,
}

impl PreviousProviderBinding {
    pub(super) fn from_value(value: &Value) -> Result<Self, SelectorBoundaryError> {
        let fields = array(value, 9).map_err(invalid)?;
        let runtime_key = array(&fields[4], 4).map_err(invalid)?;
        if uint(&runtime_key[1]).map_err(invalid)? != 3 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let binding = Self {
            provider_id: text(&fields[0]).map_err(invalid)?.to_owned(),
            provider_manifest_digest: nonzero_digest(&fields[1])?,
            provider_binary_digest: nonzero_digest(&fields[2])?,
            public_contract_digest: nonzero_digest(&fields[3])?,
            runtime_key_id: text(&runtime_key[0]).map_err(invalid)?.to_owned(),
            runtime_public_key: fixed_bytes(&runtime_key[2]).map_err(invalid)?,
            runtime_key_epoch: uint(&runtime_key[3]).map_err(invalid)?,
            runtime_instance_id: nonzero_id(&fields[5])?,
            lifecycle_scope_id: nonzero_id(&fields[6])?,
            main_pid: uint(&fields[7]).map_err(invalid)?,
            main_start_time_ticks: uint(&fields[8]).map_err(invalid)?,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(super) fn value(&self) -> Value {
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

    pub(super) fn digest(&self) -> Result<[u8; 32], SelectorBoundaryError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREVIOUS_PROVIDER_BINDING_DOMAIN);
        hasher.update(&encode(&self.value()).map_err(invalid)?);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate(&self) -> Result<(), SelectorBoundaryError> {
        if self.provider_id.is_empty()
            || self.runtime_key_id.is_empty()
            || self.provider_manifest_digest == [0; 32]
            || self.provider_binary_digest == [0; 32]
            || self.public_contract_digest == [0; 32]
            || self.runtime_public_key == [0; 32]
            || self.runtime_instance_id == [0; 16]
            || self.lifecycle_scope_id == [0; 16]
            || self.runtime_instance_id == self.lifecycle_scope_id
            || self.main_pid == 0
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        ed25519_dalek::VerifyingKey::from_bytes(&self.runtime_public_key)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveryPeerSlot {
    pub(super) runtime: [u8; 16],
    pub(super) lifecycle_scope: [u8; 16],
    pub(super) endpoint: [u8; 16],
}

impl RecoveryPeerSlot {
    fn allocate(previous: &PreviousProviderBinding) -> Self {
        let runtime_id = random_id(&[previous.runtime_instance_id, previous.lifecycle_scope_id]);
        let lifecycle_scope_id = random_id(&[
            previous.runtime_instance_id,
            previous.lifecycle_scope_id,
            runtime_id,
        ]);
        let endpoint_id = random_id(&[
            previous.runtime_instance_id,
            previous.lifecycle_scope_id,
            runtime_id,
            lifecycle_scope_id,
        ]);
        Self {
            runtime: runtime_id,
            lifecycle_scope: lifecycle_scope_id,
            endpoint: endpoint_id,
        }
    }

    pub(super) fn from_value(value: &Value) -> Result<Self, SelectorBoundaryError> {
        let fields = array(value, 3).map_err(invalid)?;
        let slot = Self {
            runtime: nonzero_id(&fields[0])?,
            lifecycle_scope: nonzero_id(&fields[1])?,
            endpoint: nonzero_id(&fields[2])?,
        };
        if slot.runtime == slot.lifecycle_scope
            || slot.runtime == slot.endpoint
            || slot.lifecycle_scope == slot.endpoint
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(slot)
    }

    pub(super) fn value(&self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.runtime.to_vec()),
            Value::Bytes(self.lifecycle_scope.to_vec()),
            Value::Bytes(self.endpoint.to_vec()),
        ])
    }
}

/// Opaque, root-selector sealed snapshot used to commit one exact SIR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationRecoverySnapshot {
    pub(super) previous_provider: PreviousProviderBinding,
    pub(super) recovery_slot: RecoveryPeerSlot,
    pub(super) previous_live_attempt_ids: Vec<[u8; 16]>,
    pub(super) required_cancelled_attempt_ids: Vec<[u8; 16]>,
}

impl InstallationRecoverySnapshot {
    pub(crate) fn seal(
        provider_id: String,
        provider_manifest_digest: [u8; 32],
        provider_binary_digest: [u8; 32],
        public_contract_digest: [u8; 32],
        runtime_key: &SandboxTrustKey,
        runtime: &AdmittedProviderRuntime,
        previous_live_attempt_ids: Vec<[u8; 16]>,
        required_cancelled_attempt_ids: Vec<[u8; 16]>,
    ) -> Result<Self, SelectorBoundaryError> {
        if runtime.slot.provider_manifest_digest != provider_manifest_digest
            || runtime_key.role != SandboxTrustRole::ProviderRuntimeAttestation
        {
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
        let previous_provider = PreviousProviderBinding {
            provider_id,
            provider_manifest_digest,
            provider_binary_digest,
            public_contract_digest,
            runtime_key_id: runtime_key.key_id.clone(),
            runtime_public_key: runtime_key.public_key,
            runtime_key_epoch: runtime_key.epoch,
            runtime_instance_id: runtime.runtime_instance_id(),
            lifecycle_scope_id: runtime.lifecycle_scope_id(),
            main_pid: runtime.main_pid,
            main_start_time_ticks: runtime.main_start_time_ticks,
        };
        previous_provider.validate()?;
        let recovery_slot = RecoveryPeerSlot::allocate(&previous_provider);
        Ok(Self {
            previous_provider,
            recovery_slot,
            previous_live_attempt_ids,
            required_cancelled_attempt_ids,
        })
    }

    pub(super) fn from_values(
        provider: &Value,
        slot: &Value,
        live: &Value,
        cancelled: &Value,
    ) -> Result<Self, SelectorBoundaryError> {
        let previous_provider = PreviousProviderBinding::from_value(provider)?;
        let recovery_slot = RecoveryPeerSlot::from_value(slot)?;
        if [
            recovery_slot.runtime,
            recovery_slot.lifecycle_scope,
            recovery_slot.endpoint,
        ]
        .iter()
        .any(|id| {
            *id == previous_provider.runtime_instance_id
                || *id == previous_provider.lifecycle_scope_id
        }) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let previous_live_attempt_ids = attempt_ids(live)?;
        let required_cancelled_attempt_ids = attempt_ids(cancelled)?;
        if required_cancelled_attempt_ids
            .iter()
            .any(|id| previous_live_attempt_ids.binary_search(id).is_err())
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(Self {
            previous_provider,
            recovery_slot,
            previous_live_attempt_ids,
            required_cancelled_attempt_ids,
        })
    }

    pub(crate) fn validate_against(
        &self,
        authority: &InstalledSelectorAuthority,
    ) -> Result<(), SelectorBoundaryError> {
        let selection = authority.policy().selection();
        if selection.provider_manifest != self.previous_provider.provider_manifest_digest
            || selection.provider_binary != self.previous_provider.provider_binary_digest
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let manifest_bytes = authority
            .installed
            .control_bytes(3, selection.provider_manifest)?;
        let manifest = SandboxProviderManifest::from_canonical_cbor(&manifest_bytes)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        if manifest.provider_id != self.previous_provider.provider_id
            || manifest.manifest_digest != self.previous_provider.provider_manifest_digest
            || manifest.binary_digest != self.previous_provider.provider_binary_digest
            || manifest.public_contract_digest != self.previous_provider.public_contract_digest
            || manifest.runtime_attestation_key_id != self.previous_provider.runtime_key_id
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let runtime_key = authority
            .trust()
            .keys()
            .iter()
            .find(|key| key.key_id == self.previous_provider.runtime_key_id)
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        if runtime_key.role != SandboxTrustRole::ProviderRuntimeAttestation
            || runtime_key.public_key != self.previous_provider.runtime_public_key
            || runtime_key.epoch != self.previous_provider.runtime_key_epoch
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let active = authority
            .revocation()
            .active_key(
                authority.trust(),
                &runtime_key.key_id,
                SandboxTrustRole::ProviderRuntimeAttestation,
            )
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        if active.to_bytes() != runtime_key.public_key {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let release_key = authority
            .revocation()
            .active_key(
                authority.trust(),
                &manifest.provider_release_key_id,
                SandboxTrustRole::ProviderRelease,
            )
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        manifest
            .verify_signature(&release_key)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))
    }

    pub(crate) fn previous_provider_value(&self) -> Value {
        self.previous_provider.value()
    }

    pub(crate) fn previous_provider_digest(&self) -> Result<[u8; 32], SelectorBoundaryError> {
        self.previous_provider.digest()
    }

    pub(crate) fn recovery_slot_value(&self) -> Value {
        self.recovery_slot.value()
    }

    pub(crate) fn previous_live_attempt_ids(&self) -> &[[u8; 16]] {
        &self.previous_live_attempt_ids
    }

    pub(crate) fn required_cancelled_attempt_ids(&self) -> &[[u8; 16]] {
        &self.required_cancelled_attempt_ids
    }

    pub(crate) const fn previous_runtime_ids(&self) -> ([u8; 16], [u8; 16]) {
        (
            self.previous_provider.runtime_instance_id,
            self.previous_provider.lifecycle_scope_id,
        )
    }

    pub(crate) const fn recovery_slot_ids(&self) -> [[u8; 16]; 3] {
        [
            self.recovery_slot.runtime,
            self.recovery_slot.lifecycle_scope,
            self.recovery_slot.endpoint,
        ]
    }

    #[cfg(test)]
    pub(crate) fn runtime_key_id(&self) -> &str {
        &self.previous_provider.runtime_key_id
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        provider_id: &str,
        provider_manifest_digest: [u8; 32],
        provider_binary_digest: [u8; 32],
        public_contract_digest: [u8; 32],
        runtime_key: &SandboxTrustKey,
        previous_live_attempt_ids: Vec<[u8; 16]>,
        required_cancelled_attempt_ids: Vec<[u8; 16]>,
    ) -> Result<Self, SelectorBoundaryError> {
        let runtime = ProviderRuntimeSlot::allocate(provider_manifest_digest)
            .bind_observed_process(100, 200)?;
        Self::seal(
            provider_id.to_owned(),
            provider_manifest_digest,
            provider_binary_digest,
            public_contract_digest,
            runtime_key,
            &runtime,
            previous_live_attempt_ids,
            required_cancelled_attempt_ids,
        )
    }
}

fn attempt_ids(value: &Value) -> Result<Vec<[u8; 16]>, SelectorBoundaryError> {
    let values = array_values(value).map_err(invalid)?;
    if values.len() > MAX_ATTEMPTS {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let ids = values
        .iter()
        .map(nonzero_id)
        .collect::<Result<Vec<_>, _>>()?;
    validate_attempts(&ids)?;
    Ok(ids)
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

fn nonzero_digest(value: &Value) -> Result<[u8; 32], SelectorBoundaryError> {
    let digest = fixed_bytes(value).map_err(invalid)?;
    if digest == [0; 32] {
        Err(SelectorBoundaryError::ArtifactInvalid)
    } else {
        Ok(digest)
    }
}

fn nonzero_id(value: &Value) -> Result<[u8; 16], SelectorBoundaryError> {
    let id = fixed_bytes(value).map_err(invalid)?;
    if id == [0; 16] {
        Err(SelectorBoundaryError::ArtifactInvalid)
    } else {
        Ok(id)
    }
}

fn random_id(excluded: &[[u8; 16]]) -> [u8; 16] {
    loop {
        let candidate = rand::random();
        if candidate != [0; 16] && !excluded.contains(&candidate) {
            return candidate;
        }
    }
}

const fn invalid(_: crate::evaluator_protocol::ProtocolError) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn runtime_key() -> SandboxTrustKey {
        SandboxTrustKey {
            key_id: "runtime".to_owned(),
            role: SandboxTrustRole::ProviderRuntimeAttestation,
            public_key: SigningKey::from_bytes(&[45; 32]).verifying_key().to_bytes(),
            epoch: 7,
        }
    }

    fn binding() -> PreviousProviderBinding {
        PreviousProviderBinding {
            provider_id: "provider".to_owned(),
            provider_manifest_digest: [1; 32],
            provider_binary_digest: [2; 32],
            public_contract_digest: [3; 32],
            runtime_key_id: "runtime".to_owned(),
            runtime_public_key: runtime_key().public_key,
            runtime_key_epoch: 7,
            runtime_instance_id: [4; 16],
            lifecycle_scope_id: [5; 16],
            main_pid: 101,
            main_start_time_ticks: 202,
        }
    }

    #[test]
    fn previous_binding_round_trips_and_rejects_identity_substitution() -> TestResult {
        let binding = binding();
        let encoded = binding.value();
        let decoded = PreviousProviderBinding::from_value(&encoded)?;
        assert_eq!(decoded, binding);
        assert_eq!(decoded.digest()?, binding.digest()?);

        for (index, replacement) in [
            (0, Value::Text(String::new())),
            (1, Value::Bytes(vec![0; 32])),
            (5, Value::Bytes(vec![0; 16])),
            (6, Value::Bytes(vec![4; 16])),
            (7, Value::Integer(0_u64.into())),
        ] {
            let Value::Array(mut fields) = binding.value() else {
                return Err("binding fixture must be an array".into());
            };
            fields[index] = replacement;
            assert_eq!(
                PreviousProviderBinding::from_value(&Value::Array(fields)),
                Err(SelectorBoundaryError::ArtifactInvalid)
            );
        }

        let Value::Array(mut fields) = binding.value() else {
            return Err("binding fixture must be an array".into());
        };
        let Value::Array(runtime) = &mut fields[4] else {
            return Err("runtime key fixture must be an array".into());
        };
        runtime[1] = Value::Integer(2_u64.into());
        assert_eq!(
            PreviousProviderBinding::from_value(&Value::Array(fields)),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    #[test]
    fn recovery_slots_and_attempt_sets_preserve_distinct_bound_identities() -> TestResult {
        let key = runtime_key();
        let runtime = ProviderRuntimeSlot::allocate([1; 32]).bind_observed_process(101, 0)?;
        let snapshot = InstallationRecoverySnapshot::seal(
            "provider".to_owned(),
            [1; 32],
            [2; 32],
            [3; 32],
            &key,
            &runtime,
            vec![[6; 16], [7; 16]],
            vec![[6; 16]],
        )?;
        let [recovery_runtime, recovery_scope, recovery_endpoint] = snapshot.recovery_slot_ids();
        let (previous_runtime, previous_scope) = snapshot.previous_runtime_ids();
        for id in [
            recovery_runtime,
            recovery_scope,
            recovery_endpoint,
            previous_runtime,
            previous_scope,
        ] {
            assert_ne!(id, [0; 16]);
        }
        assert_ne!(recovery_runtime, recovery_scope);
        assert_ne!(recovery_runtime, recovery_endpoint);
        assert_ne!(recovery_scope, recovery_endpoint);

        let decoded = InstallationRecoverySnapshot::from_values(
            &snapshot.previous_provider_value(),
            &snapshot.recovery_slot_value(),
            &Value::Array(vec![Value::Bytes(vec![6; 16]), Value::Bytes(vec![7; 16])]),
            &Value::Array(vec![Value::Bytes(vec![6; 16])]),
        )?;
        assert_eq!(decoded.previous_live_attempt_ids(), &[[6; 16], [7; 16]]);
        assert_eq!(decoded.required_cancelled_attempt_ids(), &[[6; 16]]);

        let Value::Array(mut colliding_slot) = snapshot.recovery_slot_value() else {
            return Err("recovery slot fixture must be an array".into());
        };
        colliding_slot[0] = Value::Bytes(previous_runtime.to_vec());
        assert_eq!(
            InstallationRecoverySnapshot::from_values(
                &snapshot.previous_provider_value(),
                &Value::Array(colliding_slot),
                &Value::Array(vec![Value::Bytes(vec![6; 16]), Value::Bytes(vec![7; 16])]),
                &Value::Array(vec![Value::Bytes(vec![6; 16])]),
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            InstallationRecoverySnapshot::seal(
                "provider".to_owned(),
                [1; 32],
                [2; 32],
                [3; 32],
                &key,
                &runtime,
                vec![[7; 16], [6; 16]],
                vec![],
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    #[test]
    fn identifier_decoders_reject_zero_duplicate_and_unsorted_input() {
        assert_eq!(
            nonzero_digest(&Value::Bytes(vec![0; 32])),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            nonzero_id(&Value::Bytes(vec![0; 16])),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        for values in [
            vec![Value::Bytes(vec![0; 16])],
            vec![Value::Bytes(vec![2; 16]), Value::Bytes(vec![2; 16])],
            vec![Value::Bytes(vec![3; 16]), Value::Bytes(vec![2; 16])],
        ] {
            assert_eq!(
                attempt_ids(&Value::Array(values)),
                Err(SelectorBoundaryError::ArtifactInvalid)
            );
        }
        let fresh = random_id(&[[9; 16]]);
        assert_ne!(fresh, [0; 16]);
        assert_ne!(fresh, [9; 16]);
    }
}
