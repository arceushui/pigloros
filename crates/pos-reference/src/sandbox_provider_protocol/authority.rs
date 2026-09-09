use ciborium::value::Value;
use sha2::{Digest, Sha256};

use super::codec::{
    array, bounded_array, byte_string, bytes_value, decode_document, decode_text_list, digest32,
    fixed_bytes, id16, identifier, key_id, normalized_absolute_path, require_canonical_order,
    require_signature, self_digested, signed, text, text_value, uint, uint_value, usize_u64,
    valid_identifier, valid_key_id, verify_digest, verify_signature, MAX_INPUT_BYTES_U64,
    MAX_LIST_ENTRIES,
};
use super::SandboxProviderProtocolError;

const MAX_ARGUMENT_BYTES: usize = 256;
const MAX_SYSCALL_NAMES: usize = 512;
const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PKCS7_BYTES: usize = 1024 * 1024;

/// Provider-neutral architecture discriminant.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SandboxArchitecture {
    /// AMD64/x86-64.
    X86_64,
    /// AArch64/ARM64.
    Aarch64,
}

impl SandboxArchitecture {
    pub(super) const fn code(self) -> u64 {
        match self {
            Self::X86_64 => 0,
            Self::Aarch64 => 1,
        }
    }

    pub(super) const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        match code {
            0 => Ok(Self::X86_64),
            1 => Ok(Self::Aarch64),
            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
        }
    }
}

/// Independently decoded architecture-qualified SCS1 syscall policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSyscallSet {
    pub architecture: SandboxArchitecture,
    pub requested_names: Vec<String>,
    pub expected_effective_names: Vec<String>,
    pub syscall_set_digest: [u8; 32],
}

impl SandboxSyscallSet {
    /// Decode and fully validate exact canonical SCS1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed, legacy, or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, syscall_set_digest) = self_digested::<5>(&value, "SCS1")?;
        let syscall_set = Self {
            architecture: SandboxArchitecture::decode(uint(&fields[2])?)?,
            requested_names: decode_syscall_names(&fields[3])?,
            expected_effective_names: decode_syscall_names(&fields[4])?,
            syscall_set_digest,
        };
        syscall_set.validate(fields).map(|()| syscall_set)
    }

    fn validate(&self, unsigned: &[Value; 5]) -> Result<(), SandboxProviderProtocolError> {
        validate_syscall_names(&self.requested_names)?;
        validate_syscall_names(&self.expected_effective_names)?;
        if self
            .requested_names
            .iter()
            .any(|name| self.expected_effective_names.binary_search(name).is_err())
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        verify_digest("SCS1", unsigned, self.syscall_set_digest)
    }
}

/// Closed evaluator execution mode used by LPS1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxExecutionMode {
    /// Bounded Local network exchanges.
    Local,
    /// No network authority.
    AirGapped,
    /// Deterministic replay.
    Replay,
    /// Deterministic fork.
    Fork,
}

impl SandboxExecutionMode {
    const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        match code {
            0 => Ok(Self::Local),
            1 => Ok(Self::AirGapped),
            2 => Ok(Self::Replay),
            3 => Ok(Self::Fork),
            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
        }
    }
}

/// One provider-neutral capability descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCapability {
    pub capability_id: String,
    pub capability_version: u64,
    pub minimum_strength: u64,
}

/// One exact LPS1 resource limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxLimit {
    pub limit_id: u8,
    pub value: u64,
}

/// One exact TCP endpoint capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkCapability {
    pub capability_id: String,
    pub address: Vec<u8>,
    pub destination_port: u16,
    pub request_maximum: u64,
    pub response_maximum: u64,
}

/// Independently decoded signed provider manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderManifest {
    pub provider_id: String,
    pub source_digest: [u8; 32],
    pub build_digest: [u8; 32],
    pub binary_digest: [u8; 32],
    pub public_contract_digest: [u8; 32],
    pub runtime_attestation_key_id: String,
    pub capabilities: Vec<ProviderCapability>,
    pub architectures: Vec<SandboxArchitecture>,
    pub dependency_digest: [u8; 32],
    pub sbom_digest: [u8; 32],
    pub licence_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
    pub trust_epoch: u64,
    pub pcf1_digest: [u8; 32],
    pub required_hcp1_feature_set_digest: [u8; 32],
    pub provider_release_key_id: String,
    pub manifest_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl SandboxProviderManifest {
    /// Decode, bound-check, reorder-check, and verify the SPM1 self-digest.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, manifest_digest, signature) = signed::<18>(&value, "SPM1")?;
        let manifest = Self {
            provider_id: identifier(&fields[2])?,
            source_digest: digest32(&fields[3])?,
            build_digest: digest32(&fields[4])?,
            binary_digest: digest32(&fields[5])?,
            public_contract_digest: digest32(&fields[6])?,
            runtime_attestation_key_id: key_id(&fields[7])?,
            capabilities: decode_capabilities(&fields[8])?,
            architectures: decode_architectures(&fields[9])?,
            dependency_digest: digest32(&fields[10])?,
            sbom_digest: digest32(&fields[11])?,
            licence_digest: digest32(&fields[12])?,
            provenance_digest: digest32(&fields[13])?,
            trust_epoch: uint(&fields[14])?,
            pcf1_digest: digest32(&fields[15])?,
            required_hcp1_feature_set_digest: digest32(&fields[16])?,
            provider_release_key_id: key_id(&fields[17])?,
            manifest_digest,
            signature,
        };
        manifest.validate(fields).map(|()| manifest)
    }

    /// Verify SPM1 using a caller-authorized provider-release key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("SPM1", &self.manifest_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 18]) -> Result<(), SandboxProviderProtocolError> {
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
        if digests.contains(&[0; 32])
            || !valid_identifier(&self.provider_id)
            || !valid_key_id(&self.runtime_attestation_key_id)
            || !valid_key_id(&self.provider_release_key_id)
            || self.capabilities.is_empty()
            || self.capabilities.len() > MAX_LIST_ENTRIES
            || self.architectures.is_empty()
            || self.architectures.len() > 2
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        if self
            .capabilities
            .iter()
            .any(|capability| !valid_identifier(&capability.capability_id))
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        let capability_values = self
            .capabilities
            .iter()
            .map(capability_value)
            .collect::<Vec<_>>();
        require_canonical_order(&capability_values)?;
        if !self.architectures.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(SandboxProviderProtocolError::NonCanonicalOrder);
        }
        verify_digest("SPM1", unsigned, self.manifest_digest)
    }

    fn unsigned_value(&self) -> [Value; 18] {
        [
            text_value("SPM1"),
            uint_value(1),
            text_value(&self.provider_id),
            bytes_value(&self.source_digest),
            bytes_value(&self.build_digest),
            bytes_value(&self.binary_digest),
            bytes_value(&self.public_contract_digest),
            text_value(&self.runtime_attestation_key_id),
            Value::Array(self.capabilities.iter().map(capability_value).collect()),
            Value::Array(
                self.architectures
                    .iter()
                    .map(|architecture| uint_value(architecture.code()))
                    .collect(),
            ),
            bytes_value(&self.dependency_digest),
            bytes_value(&self.sbom_digest),
            bytes_value(&self.licence_digest),
            bytes_value(&self.provenance_digest),
            uint_value(self.trust_epoch),
            bytes_value(&self.pcf1_digest),
            bytes_value(&self.required_hcp1_feature_set_digest),
            text_value(&self.provider_release_key_id),
        ]
    }
}

/// Independently decoded self-digested launch policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPolicy {
    pub policy_id: String,
    pub execution_mode: SandboxExecutionMode,
    pub sim1_digest: [u8; 32],
    pub effective_limits: Vec<SandboxLimit>,
    pub network_capabilities: Vec<NetworkCapability>,
    pub policy_digest: [u8; 32],
}

impl LaunchPolicy {
    /// Decode and fully validate exact canonical LPS1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, policy_digest) = self_digested::<7>(&value, "LPS1")?;
        let policy = Self {
            policy_id: identifier(&fields[2])?,
            execution_mode: SandboxExecutionMode::decode(uint(&fields[3])?)?,
            sim1_digest: digest32(&fields[4])?,
            effective_limits: decode_limits(&fields[5])?,
            network_capabilities: decode_network_capabilities(&fields[6])?,
            policy_digest,
        };
        policy.validate(fields).map(|()| policy)
    }

    fn validate(&self, unsigned: &[Value; 7]) -> Result<(), SandboxProviderProtocolError> {
        if !valid_identifier(&self.policy_id)
            || self.sim1_digest == [0; 32]
            || self.effective_limits.len() != 17
            || self.network_capabilities.len() > MAX_LIST_ENTRIES
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        if self
            .effective_limits
            .iter()
            .any(|limit| limit.limit_id > 16)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        if !self
            .effective_limits
            .windows(2)
            .all(|pair| pair[0].limit_id < pair[1].limit_id)
        {
            return Err(SandboxProviderProtocolError::NonCanonicalOrder);
        }
        require_canonical_order(
            &self
                .network_capabilities
                .iter()
                .map(network_capability_value)
                .collect::<Vec<_>>(),
        )?;
        if self.execution_mode != SandboxExecutionMode::Local
            && !self.network_capabilities.is_empty()
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        verify_digest("LPS1", unsigned, self.policy_digest)
    }
}

/// Closed role of one SIM1 GPT partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionRole {
    RootData,
    RootVerity,
    RootVeritySignature,
}

impl PartitionRole {
    const fn code(self) -> u64 {
        match self {
            Self::RootData => 0,
            Self::RootVerity => 1,
            Self::RootVeritySignature => 2,
        }
    }

    const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        match code {
            0 => Ok(Self::RootData),
            1 => Ok(Self::RootVerity),
            2 => Ok(Self::RootVeritySignature),
            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
        }
    }
}

/// Named SIM1 partition descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionDescriptor {
    pub role: PartitionRole,
    pub partition_type_uuid: [u8; 16],
    pub partition_instance_uuid: [u8; 16],
    pub start_bytes: u64,
    pub length_bytes: u64,
    pub content_blake3_digest: [u8; 32],
}

/// Named bounded PKCS#7 proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs7Proof {
    pub der_length: u64,
    pub der_sha256: [u8; 32],
    pub der_bytes: Vec<u8>,
}

/// Independently decoded signed image manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedImageManifest {
    pub image_id: String,
    pub architecture: SandboxArchitecture,
    pub root_image_length: u64,
    pub root_image_blake3_digest: [u8; 32],
    pub partitions: [PartitionDescriptor; 3],
    pub root_hash_sha256: [u8; 32],
    pub root_hash_signature: Pkcs7Proof,
    pub signing_certificate_sha256: [u8; 32],
    pub kernel_keyring_serial: u64,
    pub executable_path: String,
    pub executable_blake3_digest: [u8; 32],
    pub arguments: Vec<String>,
    pub image_trust_epoch: u64,
    pub image_project_key_id: String,
    pub manifest_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedImageManifest {
    /// Decode and fully validate exact canonical SIM1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, manifest_digest, signature) = signed::<20>(&value, "SIM1")?;
        if uint(&fields[8])? != 4096
            || uint(&fields[9])? != 4096
            || uint(&fields[10])? != 1
            || !byte_string(&fields[11])?.is_empty()
        {
            return Err(SandboxProviderProtocolError::InvalidEncoding);
        }
        let manifest = Self {
            image_id: identifier(&fields[2])?,
            architecture: SandboxArchitecture::decode(uint(&fields[3])?)?,
            root_image_length: uint(&fields[4])?,
            root_image_blake3_digest: digest32(&fields[5])?,
            partitions: decode_partitions(&fields[6])?,
            root_hash_sha256: digest32(&fields[7])?,
            root_hash_signature: decode_pkcs7(&fields[12])?,
            signing_certificate_sha256: digest32(&fields[13])?,
            kernel_keyring_serial: uint(&fields[14])?,
            executable_path: text(&fields[15])?.to_owned(),
            executable_blake3_digest: digest32(&fields[16])?,
            arguments: decode_text_list(&fields[17])?,
            image_trust_epoch: uint(&fields[18])?,
            image_project_key_id: key_id(&fields[19])?,
            manifest_digest,
            signature,
        };
        manifest.validate(fields).map(|()| manifest)
    }

    /// Verify SIM1 using a caller-authorized image-project key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("SIM1", &self.manifest_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 20]) -> Result<(), SandboxProviderProtocolError> {
        if !valid_identifier(&self.image_id)
            || !valid_key_id(&self.image_project_key_id)
            || self.root_image_length == 0
            || self.root_image_length > MAX_IMAGE_BYTES
            || self.root_image_blake3_digest == [0; 32]
            || self.root_hash_sha256 == [0; 32]
            || self.signing_certificate_sha256 == [0; 32]
            || self.kernel_keyring_serial == 0
            || self.executable_blake3_digest == [0; 32]
            || !normalized_absolute_path(&self.executable_path)
            || self.arguments.len() > MAX_LIST_ENTRIES
            || self.arguments.iter().any(|argument| {
                argument.is_empty()
                    || argument.len() > MAX_ARGUMENT_BYTES
                    || argument.contains('\0')
            })
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        validate_pkcs7(&self.root_hash_signature)?;
        validate_partitions(self.architecture, self.root_image_length, &self.partitions)?;
        verify_digest("SIM1", unsigned, self.manifest_digest)
    }

    fn unsigned_value(&self) -> [Value; 20] {
        [
            text_value("SIM1"),
            uint_value(1),
            text_value(&self.image_id),
            uint_value(self.architecture.code()),
            uint_value(self.root_image_length),
            bytes_value(&self.root_image_blake3_digest),
            Value::Array(self.partitions.iter().map(partition_value).collect()),
            bytes_value(&self.root_hash_sha256),
            uint_value(4096),
            uint_value(4096),
            uint_value(1),
            bytes_value(&[]),
            pkcs7_value(&self.root_hash_signature),
            bytes_value(&self.signing_certificate_sha256),
            uint_value(self.kernel_keyring_serial),
            text_value(&self.executable_path),
            bytes_value(&self.executable_blake3_digest),
            Value::Array(
                self.arguments
                    .iter()
                    .map(|value| text_value(value))
                    .collect(),
            ),
            uint_value(self.image_trust_epoch),
            text_value(&self.image_project_key_id),
        ]
    }
}

fn decode_capabilities(
    value: &Value,
) -> Result<Vec<ProviderCapability>, SandboxProviderProtocolError> {
    bounded_array(value, 1)?
        .iter()
        .map(|value| {
            let fields = array::<3>(value)?;
            Ok(ProviderCapability {
                capability_id: identifier(&fields[0])?,
                capability_version: uint(&fields[1])?,
                minimum_strength: uint(&fields[2])?,
            })
        })
        .collect()
}

fn capability_value(value: &ProviderCapability) -> Value {
    Value::Array(vec![
        text_value(&value.capability_id),
        uint_value(value.capability_version),
        uint_value(value.minimum_strength),
    ])
}

fn decode_architectures(
    value: &Value,
) -> Result<Vec<SandboxArchitecture>, SandboxProviderProtocolError> {
    bounded_array(value, 1)?
        .iter()
        .map(|value| SandboxArchitecture::decode(uint(value)?))
        .collect()
}

fn decode_syscall_names(value: &Value) -> Result<Vec<String>, SandboxProviderProtocolError> {
    let Value::Array(values) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| text(value).map(ToOwned::to_owned))
        .collect()
}

fn validate_syscall_names(names: &[String]) -> Result<(), SandboxProviderProtocolError> {
    if names.is_empty()
        || names.len() > MAX_SYSCALL_NAMES
        || names.iter().any(|name| !valid_syscall_name(name))
    {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    if !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SandboxProviderProtocolError::NonCanonicalOrder);
    }
    Ok(())
}

fn valid_syscall_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'_'))
        && name.len() <= 128
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn decode_limits(value: &Value) -> Result<Vec<SandboxLimit>, SandboxProviderProtocolError> {
    bounded_array(value, 1)?
        .iter()
        .map(|value| {
            let fields = array::<2>(value)?;
            Ok(SandboxLimit {
                limit_id: u8::try_from(uint(&fields[0])?)
                    .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?,
                value: uint(&fields[1])?,
            })
        })
        .collect()
}

fn decode_network_capabilities(
    value: &Value,
) -> Result<Vec<NetworkCapability>, SandboxProviderProtocolError> {
    bounded_array(value, 0)?
        .iter()
        .map(|value| {
            let fields = array::<7>(value)?;
            if uint(&fields[1])? != 0 {
                return Err(SandboxProviderProtocolError::InvalidEncoding);
            }
            let family = uint(&fields[2])?;
            let address = byte_string(&fields[3])?.to_vec();
            if !matches!((family, address.len()), (0, 4) | (1, 16)) {
                return Err(SandboxProviderProtocolError::InvalidEncoding);
            }
            let destination_port = u16::try_from(uint(&fields[4])?)
                .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?;
            let request_maximum = uint(&fields[5])?;
            let response_maximum = uint(&fields[6])?;
            if destination_port == 0
                || !(1..=MAX_INPUT_BYTES_U64).contains(&request_maximum)
                || !(1..=MAX_INPUT_BYTES_U64).contains(&response_maximum)
            {
                return Err(SandboxProviderProtocolError::FieldOutOfBounds);
            }
            Ok(NetworkCapability {
                capability_id: identifier(&fields[0])?,
                address,
                destination_port,
                request_maximum,
                response_maximum,
            })
        })
        .collect()
}

fn network_capability_value(value: &NetworkCapability) -> Value {
    Value::Array(vec![
        text_value(&value.capability_id),
        uint_value(0),
        uint_value(u64::from(value.address.len() != 4)),
        bytes_value(&value.address),
        uint_value(u64::from(value.destination_port)),
        uint_value(value.request_maximum),
        uint_value(value.response_maximum),
    ])
}

fn decode_partitions(
    value: &Value,
) -> Result<[PartitionDescriptor; 3], SandboxProviderProtocolError> {
    array::<3>(value)?
        .iter()
        .map(|value| {
            let fields = array::<6>(value)?;
            Ok(PartitionDescriptor {
                role: PartitionRole::decode(uint(&fields[0])?)?,
                partition_type_uuid: fixed_bytes(&fields[1])?,
                partition_instance_uuid: id16(&fields[2])?,
                start_bytes: uint(&fields[3])?,
                length_bytes: uint(&fields[4])?,
                content_blake3_digest: digest32(&fields[5])?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)
}

fn partition_value(value: &PartitionDescriptor) -> Value {
    Value::Array(vec![
        uint_value(value.role.code()),
        bytes_value(&value.partition_type_uuid),
        bytes_value(&value.partition_instance_uuid),
        uint_value(value.start_bytes),
        uint_value(value.length_bytes),
        bytes_value(&value.content_blake3_digest),
    ])
}

fn validate_partitions(
    architecture: SandboxArchitecture,
    image_length: u64,
    partitions: &[PartitionDescriptor; 3],
) -> Result<(), SandboxProviderProtocolError> {
    let mut ends = [0_u64; 3];
    for (index, (expected_role, partition)) in [0_u64, 1, 2].into_iter().zip(partitions).enumerate()
    {
        let end = partition
            .start_bytes
            .checked_add(partition.length_bytes)
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)?;
        if partition.role.code() != expected_role
            || partition.partition_type_uuid != dps_uuid(architecture, partition.role)
            || partition.partition_instance_uuid == [0; 16]
            || partition.length_bytes == 0
            || partition.length_bytes > MAX_IMAGE_BYTES
            || partition.content_blake3_digest == [0; 32]
            || end > image_length
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        ends[index] = end;
    }
    for left in 0..partitions.len() {
        for right in left + 1..partitions.len() {
            if partitions[left].partition_instance_uuid == partitions[right].partition_instance_uuid
                || (partitions[left].start_bytes < ends[right]
                    && partitions[right].start_bytes < ends[left])
            {
                return Err(SandboxProviderProtocolError::InconsistentFields);
            }
        }
    }
    Ok(())
}

const fn dps_uuid(architecture: SandboxArchitecture, role: PartitionRole) -> [u8; 16] {
    match (architecture, role) {
        (SandboxArchitecture::X86_64, PartitionRole::RootData) => [
            0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84,
            0xb7, 0x09,
        ],
        (SandboxArchitecture::X86_64, PartitionRole::RootVerity) => [
            0x2c, 0x73, 0x57, 0xed, 0xeb, 0xd2, 0x46, 0xd9, 0xae, 0xc1, 0x23, 0xd4, 0x37, 0xec,
            0x2b, 0xf5,
        ],
        (SandboxArchitecture::X86_64, PartitionRole::RootVeritySignature) => [
            0x41, 0x09, 0x2b, 0x05, 0x9f, 0xc8, 0x45, 0x23, 0x99, 0x4f, 0x2d, 0xef, 0x04, 0x08,
            0xb1, 0x76,
        ],
        (SandboxArchitecture::Aarch64, PartitionRole::RootData) => [
            0xb9, 0x21, 0xb0, 0x45, 0x1d, 0xf0, 0x41, 0xc3, 0xaf, 0x44, 0x4c, 0x6f, 0x28, 0x0d,
            0x3f, 0xae,
        ],
        (SandboxArchitecture::Aarch64, PartitionRole::RootVerity) => [
            0xdf, 0x33, 0x00, 0xce, 0xd6, 0x9f, 0x4c, 0x92, 0x97, 0x8c, 0x9b, 0xfb, 0x0f, 0x38,
            0xd8, 0x20,
        ],
        (SandboxArchitecture::Aarch64, PartitionRole::RootVeritySignature) => [
            0x6d, 0xb6, 0x9d, 0xe6, 0x29, 0xf4, 0x47, 0x58, 0xa7, 0xa5, 0x96, 0x21, 0x90, 0xf0,
            0x0c, 0xe3,
        ],
    }
}

fn decode_pkcs7(value: &Value) -> Result<Pkcs7Proof, SandboxProviderProtocolError> {
    let fields = array::<3>(value)?;
    Ok(Pkcs7Proof {
        der_length: uint(&fields[0])?,
        der_sha256: digest32(&fields[1])?,
        der_bytes: byte_string(&fields[2])?.to_vec(),
    })
}

fn pkcs7_value(value: &Pkcs7Proof) -> Value {
    Value::Array(vec![
        uint_value(value.der_length),
        bytes_value(&value.der_sha256),
        bytes_value(&value.der_bytes),
    ])
}

fn validate_pkcs7(value: &Pkcs7Proof) -> Result<(), SandboxProviderProtocolError> {
    let actual_sha256: [u8; 32] = Sha256::digest(&value.der_bytes).into();
    if value.der_bytes.is_empty()
        || value.der_bytes.len() > MAX_PKCS7_BYTES
        || value.der_length != usize_u64(value.der_bytes.len())?
        || value.der_sha256 != actual_sha256
    {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}
