use ciborium::value::Value;
use sha2::{Digest, Sha256};

use crate::{identifier, ExecutionModeV1};

use super::codec::{
    array, bytes, canonically_ordered, decode, digest, encode, fixed, sign, text, uint,
    validate_magic, value_bytes, value_text, value_uint, verify,
};
use super::{
    NetworkCapabilityV1, ProviderCapabilityV1, SandboxArchitectureV1, SandboxContractErrorV1,
    SandboxLimitV1, MAX_SANDBOX_PROVIDER_ENTRIES_V1,
};

const SPM1: &str = "SPM1";
const LPS1: &str = "LPS1";
const SIM1: &str = "SIM1";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SIGNATURE_DER_BYTES: usize = 1024 * 1024;
const MAX_EXECUTABLE_PATH_BYTES: usize = 512;
const MAX_ARGUMENT_BYTES: usize = 256;

/// Exact signed SPM1 provider-release manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderManifestV1 {
    /// Provider-neutral identifier.
    pub provider_id: String,
    /// Source-tree digest.
    pub source_digest: [u8; 32],
    /// Build-recipe digest.
    pub build_digest: [u8; 32],
    /// Provider binary digest.
    pub binary_digest: [u8; 32],
    /// Public provider-contract package digest.
    pub public_contract_digest: [u8; 32],
    /// Runtime-attestation key identifier.
    pub runtime_attestation_key_id: String,
    /// Strictly canonically ordered capability descriptors.
    pub capabilities: Vec<ProviderCapabilityV1>,
    /// Strictly ordered supported architectures.
    pub architectures: Vec<SandboxArchitectureV1>,
    /// Dependency inventory digest.
    pub dependency_digest: [u8; 32],
    /// SBOM digest.
    pub sbom_digest: [u8; 32],
    /// Licence inventory digest.
    pub licence_digest: [u8; 32],
    /// Build and publication provenance digest.
    pub provenance_digest: [u8; 32],
    /// Trust epoch under which the release is admitted.
    pub trust_epoch: u64,
    /// Public provider-conformance profile digest.
    pub pcf1_digest: [u8; 32],
    /// Required provider-neutral host-feature-set digest.
    pub required_hcp1_feature_set_digest: [u8; 32],
    /// Provider-release signing-key identifier.
    pub provider_release_key_id: String,
    /// Self-digest of the exact SPM1-U array.
    pub manifest_digest: [u8; 32],
    /// Ed25519 signature over the manifest digest.
    pub signature: [u8; 64],
}

impl SandboxProviderManifestV1 {
    /// Seal this manifest with the supplied provider-release key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.manifest_digest = digest(SPM1, &self.unsigned_value())?;
        self.signature = sign(SPM1, &self.manifest_digest, key);
        Ok(self)
    }

    /// Validate shape, canonical ordering, and self-digest.
    ///
    /// # Errors
    /// Returns a closed error for malformed fields, order, digest, or signature bytes.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        if self.signature == [0; 64] {
            return Err(SandboxContractErrorV1::SignatureInvalid);
        }
        (self.manifest_digest == digest(SPM1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify the signature with a caller-authorized provider-release key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(SPM1, &self.manifest_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR SPM1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.manifest_digest),
            value_bytes(&self.signature),
        ]))
    }

    /// Decode exact deterministic-CBOR SPM1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(encoded)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<18>(&fields[0])?;
        validate_magic(unsigned, SPM1)?;
        let manifest = Self {
            provider_id: text(&unsigned[2])?.to_owned(),
            source_digest: fixed(&unsigned[3])?,
            build_digest: fixed(&unsigned[4])?,
            binary_digest: fixed(&unsigned[5])?,
            public_contract_digest: fixed(&unsigned[6])?,
            runtime_attestation_key_id: text(&unsigned[7])?.to_owned(),
            capabilities: decode_capabilities(&unsigned[8])?,
            architectures: decode_architectures(&unsigned[9])?,
            dependency_digest: fixed(&unsigned[10])?,
            sbom_digest: fixed(&unsigned[11])?,
            licence_digest: fixed(&unsigned[12])?,
            provenance_digest: fixed(&unsigned[13])?,
            trust_epoch: uint(&unsigned[14])?,
            pcf1_digest: fixed(&unsigned[15])?,
            required_hcp1_feature_set_digest: fixed(&unsigned[16])?,
            provider_release_key_id: text(&unsigned[17])?.to_owned(),
            manifest_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        manifest.validate().map(|()| manifest)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let digests = [
            self.source_digest,
            self.build_digest,
            self.binary_digest,
            self.public_contract_digest,
            self.dependency_digest,
            self.sbom_digest,
            self.licence_digest,
            self.provenance_digest,
            self.pcf1_digest,
            self.required_hcp1_feature_set_digest,
        ];
        if !identifier(&self.provider_id, MAX_IDENTIFIER_BYTES)
            || !bounded_text(&self.runtime_attestation_key_id, MAX_IDENTIFIER_BYTES)
            || !bounded_text(&self.provider_release_key_id, MAX_IDENTIFIER_BYTES)
            || digests.contains(&[0; 32])
            || self.capabilities.is_empty()
            || self.capabilities.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.architectures.is_empty()
            || self.architectures.len() > 2
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        let capability_values = self
            .capabilities
            .iter()
            .map(capability_value)
            .collect::<Vec<_>>();
        if self
            .capabilities
            .iter()
            .any(|capability| !identifier(&capability.capability_id, MAX_IDENTIFIER_BYTES))
            || !canonically_ordered(&capability_values)?
            || !self.architectures.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SandboxContractErrorV1::NonCanonicalOrder);
        }
        Ok(())
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SPM1),
            value_uint(1),
            value_text(&self.provider_id),
            value_bytes(&self.source_digest),
            value_bytes(&self.build_digest),
            value_bytes(&self.binary_digest),
            value_bytes(&self.public_contract_digest),
            value_text(&self.runtime_attestation_key_id),
            Value::Array(self.capabilities.iter().map(capability_value).collect()),
            Value::Array(
                self.architectures
                    .iter()
                    .map(|value| value_uint(value.code()))
                    .collect(),
            ),
            value_bytes(&self.dependency_digest),
            value_bytes(&self.sbom_digest),
            value_bytes(&self.licence_digest),
            value_bytes(&self.provenance_digest),
            value_uint(self.trust_epoch),
            value_bytes(&self.pcf1_digest),
            value_bytes(&self.required_hcp1_feature_set_digest),
            value_text(&self.provider_release_key_id),
        ])
    }
}

/// Exact self-digested LPS1 launch policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPolicyV1 {
    /// Stable policy identifier.
    pub policy_id: String,
    /// Closed Local, Air-Gapped, Replay, or Fork mode.
    pub execution_mode: ExecutionModeV1,
    /// Exact signed image manifest digest.
    pub sim1_digest: [u8; 32],
    /// Strictly ordered resource limits.
    pub effective_limits: Vec<SandboxLimitV1>,
    /// Strictly canonically ordered exact-endpoint network capabilities.
    pub network_capabilities: Vec<NetworkCapabilityV1>,
    /// Self-digest of the exact LPS1-U array.
    pub policy_digest: [u8; 32],
}

impl LaunchPolicyV1 {
    /// Compute and install the exact LPS1 self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.policy_digest = digest(LPS1, &self.unsigned_value())?;
        Ok(self)
    }

    /// Validate shape, ordering, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid policy data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        (self.policy_digest == digest(LPS1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Encode exact deterministic-CBOR LPS1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.policy_digest),
        ]))
    }

    /// Decode exact deterministic-CBOR LPS1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<2>(&value)?;
        let unsigned = array::<7>(&fields[0])?;
        validate_magic(unsigned, LPS1)?;
        let policy = Self {
            policy_id: text(&unsigned[2])?.to_owned(),
            execution_mode: decode_mode(&unsigned[3])?,
            sim1_digest: fixed(&unsigned[4])?,
            effective_limits: decode_limits(&unsigned[5])?,
            network_capabilities: decode_network_capabilities(&unsigned[6])?,
            policy_digest: fixed(&fields[1])?,
        };
        policy.validate().map(|()| policy)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        if !identifier(&self.policy_id, MAX_IDENTIFIER_BYTES)
            || self.sim1_digest == [0; 32]
            || self.effective_limits.is_empty()
            || self.effective_limits.len() > 16
            || self.network_capabilities.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if self
            .effective_limits
            .iter()
            .any(|limit| limit.limit_id > 15 || limit.value == 0)
            || self
                .network_capabilities
                .iter()
                .any(|capability| !valid_network_capability(capability))
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if !self
            .effective_limits
            .windows(2)
            .all(|pair| pair[0].limit_id < pair[1].limit_id)
        {
            return Err(SandboxContractErrorV1::NonCanonicalOrder);
        }
        let network_values = self
            .network_capabilities
            .iter()
            .map(network_capability_value)
            .collect::<Vec<_>>();
        if !canonically_ordered(&network_values)? {
            return Err(SandboxContractErrorV1::NonCanonicalOrder);
        }
        if self.execution_mode != ExecutionModeV1::Local && !self.network_capabilities.is_empty() {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        Ok(())
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(LPS1),
            value_uint(1),
            value_text(&self.policy_id),
            value_uint(mode_code(self.execution_mode)),
            value_bytes(&self.sim1_digest),
            Value::Array(
                self.effective_limits
                    .iter()
                    .map(|limit| {
                        Value::Array(vec![
                            value_uint(u64::from(limit.limit_id)),
                            value_uint(limit.value),
                        ])
                    })
                    .collect(),
            ),
            Value::Array(
                self.network_capabilities
                    .iter()
                    .map(network_capability_value)
                    .collect(),
            ),
        ])
    }
}

/// Closed role of one SIM1 GPT partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionRoleV1 {
    /// Root filesystem data.
    RootData,
    /// Root dm-verity hash tree.
    RootVerity,
    /// Root dm-verity signature data.
    RootVeritySignature,
}

impl PartitionRoleV1 {
    const fn code(self) -> u64 {
        match self {
            Self::RootData => 0,
            Self::RootVerity => 1,
            Self::RootVeritySignature => 2,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::RootData),
            1 => Ok(Self::RootVerity),
            2 => Ok(Self::RootVeritySignature),
            _ => Err(SandboxContractErrorV1::InvalidEncoding),
        }
    }
}

/// Exact SIM1 partition descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionDescriptorV1 {
    /// Closed root-data, root-verity, or root-verity-signature role.
    pub role: PartitionRoleV1,
    /// Architecture/role-specific DPS type UUID in RFC byte order.
    pub partition_type_uuid: [u8; 16],
    /// Nonzero per-image partition instance UUID.
    pub partition_instance_uuid: [u8; 16],
    /// Byte offset from the image start.
    pub start_bytes: u64,
    /// Nonzero partition extent length.
    pub length_bytes: u64,
    /// BLAKE3 digest of exact partition bytes.
    pub content_blake3_digest: [u8; 32],
}

/// Exact bounded DER PKCS#7 proof embedded in SIM1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs7ProofV1 {
    /// Exact DER byte length.
    pub der_length: u64,
    /// SHA-256 digest of the DER bytes.
    pub der_sha256: [u8; 32],
    /// Exact DER PKCS#7 bytes.
    pub der_bytes: Vec<u8>,
}

/// Exact signed SIM1 image-project manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedImageManifestV1 {
    /// Stable image identifier.
    pub image_id: String,
    /// Target architecture.
    pub architecture: SandboxArchitectureV1,
    /// Exact root-image byte length.
    pub root_image_length: u64,
    /// BLAKE3 digest of exact root-image bytes.
    pub root_image_blake3_digest: [u8; 32],
    /// Exactly root-data, root-verity, and root-verity-signature descriptors.
    pub partitions: [PartitionDescriptorV1; 3],
    /// Exact dm-verity root hash.
    pub root_hash_sha256: [u8; 32],
    /// Exact DER PKCS#7 proof.
    pub root_hash_signature: Pkcs7ProofV1,
    /// SHA-256 fingerprint of the signing certificate.
    pub signing_certificate_sha256: [u8; 32],
    /// Administrator-selected kernel-keyring serial.
    pub kernel_keyring_serial: u64,
    /// Normalized absolute executable path within the image.
    pub executable_path: String,
    /// BLAKE3 digest of exact executable bytes.
    pub executable_blake3_digest: [u8; 32],
    /// Fixed executable argument vector.
    pub arguments: Vec<String>,
    /// Image trust epoch.
    pub image_trust_epoch: u64,
    /// Image-project signing-key identifier.
    pub image_project_key_id: String,
    /// Self-digest of the exact SIM1-U array.
    pub manifest_digest: [u8; 32],
    /// Image-project Ed25519 signature.
    pub signature: [u8; 64],
}

impl SignedImageManifestV1 {
    /// Seal this image manifest with the supplied image-project key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.manifest_digest = digest(SIM1, &self.unsigned_value())?;
        self.signature = sign(SIM1, &self.manifest_digest, key);
        Ok(self)
    }

    /// Validate shape, image identities, and self-digest.
    ///
    /// # Errors
    /// Returns a closed error for malformed fields, digest, or signature bytes.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        if self.signature == [0; 64] {
            return Err(SandboxContractErrorV1::SignatureInvalid);
        }
        (self.manifest_digest == digest(SIM1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify the signature with a caller-authorized image-project key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(SIM1, &self.manifest_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR SIM1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.manifest_digest),
            value_bytes(&self.signature),
        ]))
    }

    /// Decode exact deterministic-CBOR SIM1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(encoded)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<20>(&fields[0])?;
        validate_magic(unsigned, SIM1)?;
        if uint(&unsigned[8])? != 4096
            || uint(&unsigned[9])? != 4096
            || uint(&unsigned[10])? != 1
            || !bytes(&unsigned[11])?.is_empty()
        {
            return Err(SandboxContractErrorV1::InvalidEncoding);
        }
        let manifest = Self {
            image_id: text(&unsigned[2])?.to_owned(),
            architecture: SandboxArchitectureV1::from_code(uint(&unsigned[3])?)?,
            root_image_length: uint(&unsigned[4])?,
            root_image_blake3_digest: fixed(&unsigned[5])?,
            partitions: decode_partitions(&unsigned[6])?,
            root_hash_sha256: fixed(&unsigned[7])?,
            root_hash_signature: decode_pkcs7(&unsigned[12])?,
            signing_certificate_sha256: fixed(&unsigned[13])?,
            kernel_keyring_serial: uint(&unsigned[14])?,
            executable_path: text(&unsigned[15])?.to_owned(),
            executable_blake3_digest: fixed(&unsigned[16])?,
            arguments: decode_texts(&unsigned[17])?,
            image_trust_epoch: uint(&unsigned[18])?,
            image_project_key_id: text(&unsigned[19])?.to_owned(),
            manifest_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        manifest.validate().map(|()| manifest)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        if !identifier(&self.image_id, MAX_IDENTIFIER_BYTES)
            || self.root_image_length == 0
            || self.root_image_length > MAX_IMAGE_BYTES
            || self.root_image_blake3_digest == [0; 32]
            || self.root_hash_sha256 == [0; 32]
            || self.signing_certificate_sha256 == [0; 32]
            || self.kernel_keyring_serial == 0
            || self.executable_blake3_digest == [0; 32]
            || !normalized_absolute_path(&self.executable_path)
            || self.arguments.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self
                .arguments
                .iter()
                .any(|argument| argument.is_empty() || argument.len() > MAX_ARGUMENT_BYTES)
            || !bounded_text(&self.image_project_key_id, MAX_IDENTIFIER_BYTES)
            || !valid_pkcs7(&self.root_hash_signature)
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        validate_partitions(self.architecture, self.root_image_length, &self.partitions)
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SIM1),
            value_uint(1),
            value_text(&self.image_id),
            value_uint(self.architecture.code()),
            value_uint(self.root_image_length),
            value_bytes(&self.root_image_blake3_digest),
            Value::Array(self.partitions.iter().map(partition_value).collect()),
            value_bytes(&self.root_hash_sha256),
            value_uint(4096),
            value_uint(4096),
            value_uint(1),
            value_bytes(&[]),
            pkcs7_value(&self.root_hash_signature),
            value_bytes(&self.signing_certificate_sha256),
            value_uint(self.kernel_keyring_serial),
            value_text(&self.executable_path),
            value_bytes(&self.executable_blake3_digest),
            Value::Array(
                self.arguments
                    .iter()
                    .map(|value| value_text(value))
                    .collect(),
            ),
            value_uint(self.image_trust_epoch),
            value_text(&self.image_project_key_id),
        ])
    }
}

fn capability_value(value: &ProviderCapabilityV1) -> Value {
    Value::Array(vec![
        value_text(&value.capability_id),
        value_uint(value.capability_version),
        value_uint(value.minimum_strength),
    ])
}

fn decode_capabilities(value: &Value) -> Result<Vec<ProviderCapabilityV1>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| {
            let fields = array::<3>(value)?;
            Ok(ProviderCapabilityV1 {
                capability_id: text(&fields[0])?.to_owned(),
                capability_version: uint(&fields[1])?,
                minimum_strength: uint(&fields[2])?,
            })
        })
        .collect()
}

fn decode_architectures(
    value: &Value,
) -> Result<Vec<SandboxArchitectureV1>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| SandboxArchitectureV1::from_code(uint(value)?))
        .collect()
}

fn network_capability_value(value: &NetworkCapabilityV1) -> Value {
    Value::Array(vec![
        value_text(&value.capability_id),
        value_uint(0),
        value_uint(u64::from(value.address.len() != 4)),
        value_bytes(&value.address),
        value_uint(u64::from(value.destination_port)),
        value_uint(value.request_maximum),
        value_uint(value.response_maximum),
    ])
}

fn valid_network_capability(value: &NetworkCapabilityV1) -> bool {
    identifier(&value.capability_id, MAX_IDENTIFIER_BYTES)
        && matches!(value.address.len(), 4 | 16)
        && value.destination_port != 0
        && (1..=128 * 1024 * 1024).contains(&value.request_maximum)
        && (1..=128 * 1024 * 1024).contains(&value.response_maximum)
}

fn decode_network_capabilities(
    value: &Value,
) -> Result<Vec<NetworkCapabilityV1>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| {
            let fields = array::<7>(value)?;
            let address = bytes(&fields[3])?.to_vec();
            let family = uint(&fields[2])?;
            if uint(&fields[1])? != 0 || !matches!((family, address.len()), (0, 4) | (1, 16)) {
                return Err(SandboxContractErrorV1::InvalidEncoding);
            }
            Ok(NetworkCapabilityV1 {
                capability_id: text(&fields[0])?.to_owned(),
                address,
                destination_port: u16::try_from(uint(&fields[4])?)
                    .map_err(|_| SandboxContractErrorV1::FieldOutOfBounds)?,
                request_maximum: uint(&fields[5])?,
                response_maximum: uint(&fields[6])?,
            })
        })
        .collect()
}

fn decode_limits(value: &Value) -> Result<Vec<SandboxLimitV1>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| {
            let fields = array::<2>(value)?;
            Ok(SandboxLimitV1 {
                limit_id: u8::try_from(uint(&fields[0])?)
                    .map_err(|_| SandboxContractErrorV1::FieldOutOfBounds)?,
                value: uint(&fields[1])?,
            })
        })
        .collect()
}

const fn mode_code(value: ExecutionModeV1) -> u64 {
    match value {
        ExecutionModeV1::Local => 0,
        ExecutionModeV1::AirGapped => 1,
        ExecutionModeV1::Replay => 2,
        ExecutionModeV1::Fork => 3,
    }
}

fn decode_mode(value: &Value) -> Result<ExecutionModeV1, SandboxContractErrorV1> {
    match uint(value)? {
        0 => Ok(ExecutionModeV1::Local),
        1 => Ok(ExecutionModeV1::AirGapped),
        2 => Ok(ExecutionModeV1::Replay),
        3 => Ok(ExecutionModeV1::Fork),
        _ => Err(SandboxContractErrorV1::InvalidEncoding),
    }
}

fn partition_value(value: &PartitionDescriptorV1) -> Value {
    Value::Array(vec![
        value_uint(value.role.code()),
        value_bytes(&value.partition_type_uuid),
        value_bytes(&value.partition_instance_uuid),
        value_uint(value.start_bytes),
        value_uint(value.length_bytes),
        value_bytes(&value.content_blake3_digest),
    ])
}

fn decode_partitions(value: &Value) -> Result<[PartitionDescriptorV1; 3], SandboxContractErrorV1> {
    let values = array::<3>(value)?;
    values
        .iter()
        .map(|value| {
            let fields = array::<6>(value)?;
            Ok(PartitionDescriptorV1 {
                role: PartitionRoleV1::from_code(uint(&fields[0])?)?,
                partition_type_uuid: fixed(&fields[1])?,
                partition_instance_uuid: fixed(&fields[2])?,
                start_bytes: uint(&fields[3])?,
                length_bytes: uint(&fields[4])?,
                content_blake3_digest: fixed(&fields[5])?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| SandboxContractErrorV1::InvalidEncoding)
}

fn validate_partitions(
    architecture: SandboxArchitectureV1,
    image_length: u64,
    partitions: &[PartitionDescriptorV1; 3],
) -> Result<(), SandboxContractErrorV1> {
    for (index, partition) in partitions.iter().enumerate() {
        if partition.role.code() != index as u64
            || partition.partition_type_uuid != dps_type_uuid(architecture, partition.role)
            || partition.partition_instance_uuid == [0; 16]
            || partition.length_bytes == 0
            || partition.length_bytes > MAX_IMAGE_BYTES
            || partition.content_blake3_digest == [0; 32]
            || partition
                .start_bytes
                .checked_add(partition.length_bytes)
                .is_none_or(|end| end > image_length)
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
    }
    if partitions.iter().enumerate().any(|(index, left)| {
        partitions.iter().skip(index + 1).any(|right| {
            left.partition_instance_uuid == right.partition_instance_uuid
                || ranges_overlap(left, right)
        })
    }) {
        return Err(SandboxContractErrorV1::InconsistentFields);
    }
    Ok(())
}

const fn ranges_overlap(left: &PartitionDescriptorV1, right: &PartitionDescriptorV1) -> bool {
    // `validate_partitions` proves both additions fit before checking pairs.
    let left_end = left.start_bytes + left.length_bytes;
    let right_end = right.start_bytes + right.length_bytes;
    left.start_bytes < right_end && right.start_bytes < left_end
}

const fn dps_type_uuid(architecture: SandboxArchitectureV1, role: PartitionRoleV1) -> [u8; 16] {
    match (architecture, role) {
        (SandboxArchitectureV1::X86_64, PartitionRoleV1::RootData) => [
            0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84,
            0xb7, 0x09,
        ],
        (SandboxArchitectureV1::X86_64, PartitionRoleV1::RootVerity) => [
            0x2c, 0x73, 0x57, 0xed, 0xeb, 0xd2, 0x46, 0xd9, 0xae, 0xc1, 0x23, 0xd4, 0x37, 0xec,
            0x2b, 0xf5,
        ],
        (SandboxArchitectureV1::X86_64, PartitionRoleV1::RootVeritySignature) => [
            0x41, 0x09, 0x2b, 0x05, 0x9f, 0xc8, 0x45, 0x23, 0x99, 0x4f, 0x2d, 0xef, 0x04, 0x08,
            0xb1, 0x76,
        ],
        (SandboxArchitectureV1::Aarch64, PartitionRoleV1::RootData) => [
            0xb9, 0x21, 0xb0, 0x45, 0x1d, 0xf0, 0x41, 0xc3, 0xaf, 0x44, 0x4c, 0x6f, 0x28, 0x0d,
            0x3f, 0xae,
        ],
        (SandboxArchitectureV1::Aarch64, PartitionRoleV1::RootVerity) => [
            0xdf, 0x33, 0x00, 0xce, 0xd6, 0x9f, 0x4c, 0x92, 0x97, 0x8c, 0x9b, 0xfb, 0x0f, 0x38,
            0xd8, 0x20,
        ],
        (SandboxArchitectureV1::Aarch64, PartitionRoleV1::RootVeritySignature) => [
            0x6d, 0xb6, 0x9d, 0xe6, 0x29, 0xf4, 0x47, 0x58, 0xa7, 0xa5, 0x96, 0x21, 0x90, 0xf0,
            0x0c, 0xe3,
        ],
    }
}

fn pkcs7_value(value: &Pkcs7ProofV1) -> Value {
    Value::Array(vec![
        value_uint(value.der_length),
        value_bytes(&value.der_sha256),
        value_bytes(&value.der_bytes),
    ])
}

fn decode_pkcs7(value: &Value) -> Result<Pkcs7ProofV1, SandboxContractErrorV1> {
    let fields = array::<3>(value)?;
    Ok(Pkcs7ProofV1 {
        der_length: uint(&fields[0])?,
        der_sha256: fixed(&fields[1])?,
        der_bytes: bytes(&fields[2])?.to_vec(),
    })
}

fn valid_pkcs7(value: &Pkcs7ProofV1) -> bool {
    let actual_digest: [u8; 32] = Sha256::digest(&value.der_bytes).into();
    !value.der_bytes.is_empty()
        && value.der_bytes.len() <= MAX_SIGNATURE_DER_BYTES
        && value.der_length == value.der_bytes.len() as u64
        && value.der_sha256 == actual_digest
}

fn decode_texts(value: &Value) -> Result<Vec<String>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| text(value).map(ToOwned::to_owned))
        .collect()
}

const fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

fn normalized_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_EXECUTABLE_PATH_BYTES
        && !value.contains('\0')
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}
