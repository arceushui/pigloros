//! Bounded, data-only provider records for the CPF1 conformance contract.
//!
//! FPR1 binds the providers a profile may require. FPP1 is the immutable,
//! data-only package manifest supplied by one provider. Neither format names
//! an executable, loader, runtime, or transport: execution belongs to the
//! public subject adapters selected by a fixture.

use ciborium::value::Value;
use std::io::Cursor;
use thiserror::Error;

use crate::{ClaimLayerV1, SubjectAdapterKindV1};

/// Magic for the fixture-provider registry record.
pub const FIXTURE_PROVIDER_REGISTRY_MAGIC_V1: &str = "FPR1";
/// Magic for the data-only fixture-provider package record.
pub const FIXTURE_PROVIDER_PACKAGE_MAGIC_V1: &str = "FPP1";
/// Canonical archive member path for the FPR1 registry artifact.
pub const FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1: &str =
    "authority/fixture-provider-registry.cbor";
/// Largest raw artifact that a provider descriptor may name.
pub const MAX_PROVIDER_ARTIFACT_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_PROVIDER_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROVIDER_ENTRIES: usize = 4096;
const MAX_PROVIDER_ENTRIES_CBOR: u64 = 4096;
const MAX_MEMBER_PATH_BYTES: usize = 512;
const MAX_MEMBER_PATH_COMPONENTS: usize = 16;
const MAX_MEMBER_PATH_COMPONENT_BYTES: usize = 128;
const MAX_MEDIA_TYPE_BYTES: usize = 127;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CONTRACT_VERSION_BYTES: usize = 64;
const MAX_STRUCTURAL_NESTING: u8 = 32;

/// Closed failures for FPR1 and FPP1 public records.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderContractErrorV1 {
    /// The CBOR input is malformed, noncanonical, or not an array-only record.
    #[error("provider contract encoding is invalid")]
    InvalidEncoding,
    /// The magic or version does not name the current provider contract.
    #[error("provider contract version is unsupported")]
    UnsupportedVersion,
    /// A bounded field or collection is empty, too large, or otherwise invalid.
    #[error("provider contract field is out of bounds")]
    FieldOutOfBounds,
    /// A provider or artifact identifier does not use the closed identifier grammar.
    #[error("provider contract identifier is invalid")]
    InvalidIdentifier,
    /// A contract version is not an exact bounded Semantic Version.
    #[error("provider contract version text is invalid")]
    InvalidContractVersion,
    /// A descriptor member path is not a safe relative archive path.
    #[error("provider contract member path is invalid")]
    InvalidMemberPath,
    /// A descriptor media type is not a lowercase RFC6838-like media type.
    #[error("provider contract media type is invalid")]
    InvalidMediaType,
    /// A sequence is duplicated or not in its required canonical order.
    #[error("provider contract records are not canonically ordered")]
    NonCanonicalOrder,
    /// A self-digest or raw package descriptor digest does not match its bytes.
    #[error("provider contract digest does not match")]
    DigestMismatch,
    /// A registry provider entry and FPP1 package do not describe the same provider.
    #[error("provider package does not match its registry entry")]
    PackageBindingMismatch,
    /// The seven-family provider schema inventory is incomplete or out of order.
    #[error("provider package family inventory is invalid")]
    FamilyInventoryInvalid,
}

/// The stable identity of one provider contract implementation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FixtureProviderKeyV1 {
    /// Closed provider identifier.
    pub provider_id: String,
    /// Exact provider contract Semantic Version.
    pub contract_version: String,
    /// Provider ABI major version.
    pub abi_major: u16,
    /// Provider ABI minor version.
    pub abi_minor: u16,
}

/// An immutable reference to public artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDescriptorV1 {
    /// Relative archive member path.
    pub member_path: String,
    /// Lowercase RFC6838-like media type.
    pub media_type: String,
    /// Exact raw member byte length.
    pub byte_length: u64,
    /// BLAKE3 digest of the exact raw member bytes.
    pub blake3_digest: [u8; 32],
}

/// One FPR1 registry provider entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureProviderEntryV1 {
    /// Provider identity used as the registry sort key.
    pub provider_key: FixtureProviderKeyV1,
    /// The only conformance claim layer this provider supplies.
    pub claim_layer: ClaimLayerV1,
    /// Public subject boundary selected by fixtures using this provider.
    pub subject_adapter: SubjectAdapterKindV1,
    /// Descriptor of exact FPP1 package bytes.
    pub provider_package_descriptor: ArtifactDescriptorV1,
}

/// The ordered FPR1 provider registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureProviderRegistryV1 {
    /// Strictly ordered provider entries.
    pub providers: Vec<FixtureProviderEntryV1>,
    /// Domain-separated digest of FPR1 fields 0 through 2.
    pub registry_digest: [u8; 32],
}

/// CPF1's binding to one exact FPR1 registry artifact and its required providers.
///
/// This is an embedded CPF1 field, so its two-field CBOR representation has no
/// standalone magic or self-digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureProviderRegistryBindingV1 {
    /// Descriptor for exact FPR1 bytes at the canonical registry member path.
    pub registry_artifact: ArtifactDescriptorV1,
    /// Strictly ordered, duplicate-free subset of FPR1 provider keys.
    pub required_provider_keys: Vec<FixtureProviderKeyV1>,
}

/// One of the seven fixed fixture families.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FixtureFamilyV1 {
    /// Exact successful public result.
    Positive,
    /// Denied input leaves no state change.
    Denied,
    /// A valid envelope contains malformed payload data.
    Malformed,
    /// A deterministic resource limit is exercised.
    ResourceExhaustion,
    /// Synthetic deletion or redaction behavior.
    DeletionRedaction,
    /// Trust/release-governed downgrade behavior.
    Downgrade,
    /// Independent algorithm, schema, or oracle evaluation.
    IndependentEvaluation,
}

impl FixtureFamilyV1 {
    pub(crate) const fn wire_code(self) -> u64 {
        match self {
            Self::Positive => 0,
            Self::Denied => 1,
            Self::Malformed => 2,
            Self::ResourceExhaustion => 3,
            Self::DeletionRedaction => 4,
            Self::Downgrade => 5,
            Self::IndependentEvaluation => 6,
        }
    }

    pub(crate) const fn from_wire_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Positive),
            1 => Some(Self::Denied),
            2 => Some(Self::Malformed),
            3 => Some(Self::ResourceExhaustion),
            4 => Some(Self::DeletionRedaction),
            5 => Some(Self::Downgrade),
            6 => Some(Self::IndependentEvaluation),
            _ => None,
        }
    }
}

const FIXTURE_FAMILIES: [FixtureFamilyV1; 7] = [
    FixtureFamilyV1::Positive,
    FixtureFamilyV1::Denied,
    FixtureFamilyV1::Malformed,
    FixtureFamilyV1::ResourceExhaustion,
    FixtureFamilyV1::DeletionRedaction,
    FixtureFamilyV1::Downgrade,
    FixtureFamilyV1::IndependentEvaluation,
];

/// The schema descriptor for one fixed fixture family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFamilySchemaV1 {
    /// One of the closed family codes zero through six.
    pub family: FixtureFamilyV1,
    /// Exact bytes of the public schema for this family.
    pub schema_descriptor: ArtifactDescriptorV1,
}

/// The FPP1 data-only provider package manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureProviderPackageV1 {
    /// Must match the FPR1 provider key.
    pub provider_key: FixtureProviderKeyV1,
    /// Must match the FPR1 claim layer.
    pub claim_layer: ClaimLayerV1,
    /// Must match the FPR1 subject adapter.
    pub subject_adapter: SubjectAdapterKindV1,
    /// Exactly the seven ordered family schemas.
    pub family_schemas: Vec<ProviderFamilySchemaV1>,
    /// Provider package license bytes.
    pub licence_descriptor: ArtifactDescriptorV1,
    /// Provider package notices bytes.
    pub notices_descriptor: ArtifactDescriptorV1,
    /// Provider package SBOM bytes.
    pub sbom_descriptor: ArtifactDescriptorV1,
    /// Provider package source-provenance bytes.
    pub source_provenance_descriptor: ArtifactDescriptorV1,
    /// Provider package limitations bytes.
    pub limitations_descriptor: ArtifactDescriptorV1,
    /// Domain-separated digest of FPP1 fields 0 through 10.
    pub package_digest: [u8; 32],
}

impl FixtureProviderRegistryV1 {
    /// Validate the typed FPR1 value, including its exact self-digest.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error for invalid fields, order, or digest.
    pub fn validate(&self) -> Result<(), ProviderContractErrorV1> {
        validate_registry_fields(self).and_then(|()| {
            self.digest().and_then(|digest| {
                if digest == self.registry_digest {
                    Ok(())
                } else {
                    Err(ProviderContractErrorV1::DigestMismatch)
                }
            })
        })
    }

    /// Encode the exact canonical FPR1 CBOR record.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProviderContractErrorV1> {
        self.validate()
            .and_then(|()| encode_bounded(&encode_registry(self)))
    }

    /// Decode and validate exact canonical FPR1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProviderContractErrorV1> {
        decode_bounded(bytes)
            .and_then(|value| decode_registry(&value))
            .and_then(|registry| registry.validate().map(|()| registry))
    }

    /// Compute the FPR1 registry digest over canonical fields zero through two.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error when canonical encoding fails.
    pub fn digest(&self) -> Result<[u8; 32], ProviderContractErrorV1> {
        digest_fields(
            b"PiglorOS.Conformance.ProviderRegistry.v1\0",
            &encode_registry_fields(self),
        )
    }
}

impl FixtureProviderRegistryBindingV1 {
    /// Validate the embedded CPF1 registry binding.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error for an invalid descriptor, key, or key order.
    pub fn validate(&self) -> Result<(), ProviderContractErrorV1> {
        validate_descriptor(&self.registry_artifact).and_then(|()| {
            if self.registry_artifact.member_path != FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1 {
                Err(ProviderContractErrorV1::InvalidMemberPath)
            } else if self.required_provider_keys.is_empty() {
                Err(ProviderContractErrorV1::FieldOutOfBounds)
            } else if self
                .required_provider_keys
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                Err(ProviderContractErrorV1::NonCanonicalOrder)
            } else {
                self.required_provider_keys
                    .iter()
                    .try_for_each(validate_provider_key)
            }
        })
    }

    /// Encode the exact canonical two-field CPF1 registry-binding value.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProviderContractErrorV1> {
        self.validate()
            .and_then(|()| encode_bounded(&encode_registry_binding(self)))
    }

    /// Decode and validate exact canonical two-field CPF1 registry-binding bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProviderContractErrorV1> {
        decode_bounded(bytes)
            .and_then(|value| decode_registry_binding(&value))
            .and_then(|binding| binding.validate().map(|()| binding))
    }
}

impl FixtureProviderPackageV1 {
    /// Validate the typed FPP1 value, including its exact self-digest.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error for invalid fields, inventory, or digest.
    pub fn validate(&self) -> Result<(), ProviderContractErrorV1> {
        validate_package_fields(self).and_then(|()| {
            self.digest().and_then(|digest| {
                if digest == self.package_digest {
                    Ok(())
                } else {
                    Err(ProviderContractErrorV1::DigestMismatch)
                }
            })
        })
    }

    /// Encode the exact canonical FPP1 CBOR record.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProviderContractErrorV1> {
        self.validate()
            .and_then(|()| encode_bounded(&encode_package(self)))
    }

    /// Decode and validate exact canonical FPP1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProviderContractErrorV1> {
        decode_bounded(bytes)
            .and_then(|value| decode_package(&value))
            .and_then(|package| package.validate().map(|()| package))
    }

    /// Compute the FPP1 package digest over canonical fields zero through ten.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error when canonical encoding fails.
    pub fn digest(&self) -> Result<[u8; 32], ProviderContractErrorV1> {
        digest_fields(
            b"PiglorOS.Conformance.ProviderPackage.v1\0",
            &encode_package_fields(self),
        )
    }

    /// Verify this FPP1 against the exact FPR1 entry and raw package bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed provider-contract error if typed fields, raw size, or raw digest differ.
    pub fn validate_registry_binding(
        &self,
        entry: &FixtureProviderEntryV1,
        package_bytes: &[u8],
    ) -> Result<(), ProviderContractErrorV1> {
        self.validate()
            .and_then(|()| validate_provider_entry(entry))
            .and_then(|()| {
                let descriptor = &entry.provider_package_descriptor;
                let length = u64::try_from(package_bytes.len())
                    .map_err(|_| ProviderContractErrorV1::FieldOutOfBounds)?;
                let canonical_bytes = self.to_canonical_cbor()?;
                if self.provider_key != entry.provider_key
                    || self.claim_layer != entry.claim_layer
                    || self.subject_adapter != entry.subject_adapter
                    || canonical_bytes != package_bytes
                    || descriptor.byte_length != length
                    || descriptor.blake3_digest != *blake3::hash(package_bytes).as_bytes()
                {
                    Err(ProviderContractErrorV1::PackageBindingMismatch)
                } else {
                    Ok(())
                }
            })
    }
}

fn validate_registry_fields(
    registry: &FixtureProviderRegistryV1,
) -> Result<(), ProviderContractErrorV1> {
    if registry.providers.is_empty() || registry.providers.len() > MAX_PROVIDER_ENTRIES {
        return Err(ProviderContractErrorV1::FieldOutOfBounds);
    }
    if registry
        .providers
        .windows(2)
        .any(|pair| pair[0].provider_key >= pair[1].provider_key)
    {
        return Err(ProviderContractErrorV1::NonCanonicalOrder);
    }
    registry
        .providers
        .iter()
        .try_for_each(validate_provider_entry)
}

fn validate_package_fields(
    package: &FixtureProviderPackageV1,
) -> Result<(), ProviderContractErrorV1> {
    validate_provider_key(&package.provider_key)
        .and_then(|()| validate_family_schemas(&package.family_schemas))
        .and_then(|()| validate_descriptor(&package.licence_descriptor))
        .and_then(|()| validate_descriptor(&package.notices_descriptor))
        .and_then(|()| validate_descriptor(&package.sbom_descriptor))
        .and_then(|()| validate_descriptor(&package.source_provenance_descriptor))
        .and_then(|()| validate_descriptor(&package.limitations_descriptor))
        .and_then(|()| {
            let paths = [
                &package.licence_descriptor.member_path,
                &package.notices_descriptor.member_path,
                &package.sbom_descriptor.member_path,
                &package.source_provenance_descriptor.member_path,
                &package.limitations_descriptor.member_path,
            ];
            if paths.windows(2).any(|pair| pair[0] == pair[1])
                || paths
                    .iter()
                    .enumerate()
                    .any(|(index, path)| paths[..index].contains(path))
            {
                Err(ProviderContractErrorV1::NonCanonicalOrder)
            } else {
                Ok(())
            }
        })
}

fn validate_provider_entry(entry: &FixtureProviderEntryV1) -> Result<(), ProviderContractErrorV1> {
    validate_provider_key(&entry.provider_key)
        .and_then(|()| validate_descriptor(&entry.provider_package_descriptor))
}

fn validate_provider_key(key: &FixtureProviderKeyV1) -> Result<(), ProviderContractErrorV1> {
    if !provider_identifier(&key.provider_id) {
        Err(ProviderContractErrorV1::InvalidIdentifier)
    } else if !semantic_version(&key.contract_version) {
        Err(ProviderContractErrorV1::InvalidContractVersion)
    } else {
        Ok(())
    }
}

fn validate_family_schemas(
    schemas: &[ProviderFamilySchemaV1],
) -> Result<(), ProviderContractErrorV1> {
    let ordered = schemas.len() == 7
        && schemas
            .iter()
            .zip(FIXTURE_FAMILIES)
            .all(|(schema, family)| schema.family == family);
    if !ordered {
        return Err(ProviderContractErrorV1::FamilyInventoryInvalid);
    }
    schemas
        .iter()
        .try_for_each(|schema| validate_descriptor(&schema.schema_descriptor))
}

fn validate_descriptor(descriptor: &ArtifactDescriptorV1) -> Result<(), ProviderContractErrorV1> {
    if !member_path(&descriptor.member_path) {
        Err(ProviderContractErrorV1::InvalidMemberPath)
    } else if !media_type(&descriptor.media_type) {
        Err(ProviderContractErrorV1::InvalidMediaType)
    } else if descriptor.byte_length == 0 || descriptor.byte_length > MAX_PROVIDER_ARTIFACT_BYTES_V1
    {
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    } else if descriptor.blake3_digest == [0; 32] {
        Err(ProviderContractErrorV1::DigestMismatch)
    } else {
        Ok(())
    }
}

fn provider_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b'/' | b'-')
        })
}

fn semantic_version(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CONTRACT_VERSION_BYTES || !value.is_ascii() {
        return false;
    }
    let (core_and_pre, build) = match value.split_once('+') {
        Some((core, suffix)) if !suffix.is_empty() && !suffix.contains('+') => (core, suffix),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, pre) = match core_and_pre.split_once('-') {
        Some((core, suffix)) if !suffix.is_empty() => (core, suffix),
        Some(_) => return false,
        None => (core_and_pre, ""),
    };
    let core_valid = core.split('.').count() == 3 && core.split('.').all(numeric_semver_identifier);
    core_valid && semver_identifiers(pre, true) && semver_identifiers(build, false)
}

fn numeric_semver_identifier(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn semver_identifiers(value: &str, numeric_zero_forbidden: bool) -> bool {
    value.is_empty()
        || value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!numeric_zero_forbidden
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || numeric_semver_identifier(identifier))
        })
}

fn member_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MEMBER_PATH_BYTES
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value.split('/').count() <= MAX_MEMBER_PATH_COMPONENTS
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.len() <= MAX_MEMBER_PATH_COMPONENT_BYTES
        })
}

fn media_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() >= 3
        && value.len() <= MAX_MEDIA_TYPE_BYTES
        && value.is_ascii()
        && bytes.iter().all(|byte| !byte.is_ascii_uppercase())
        && bytes.iter().filter(|byte| **byte == b'/').count() == 1
        && !value.starts_with('/')
        && !value.ends_with('/')
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    *byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        })
}

fn digest_fields(domain: &[u8], fields: &Value) -> Result<[u8; 32], ProviderContractErrorV1> {
    encode_bounded(fields).and_then(|bytes| {
        let encoded_length =
            u64::try_from(bytes.len()).map_err(|_| ProviderContractErrorV1::FieldOutOfBounds)?;
        let mut preimage = Vec::with_capacity(domain.len() + 8 + bytes.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(&encoded_length.to_be_bytes());
        preimage.extend_from_slice(&bytes);
        Ok(*blake3::hash(&preimage).as_bytes())
    })
}

fn encode_registry(registry: &FixtureProviderRegistryV1) -> Value {
    let mut fields = registry_fields(registry);
    fields.push(digest(&registry.registry_digest));
    Value::Array(fields)
}

fn encode_registry_fields(registry: &FixtureProviderRegistryV1) -> Value {
    Value::Array(registry_fields(registry))
}

pub(crate) fn encode_registry_binding(value: &FixtureProviderRegistryBindingV1) -> Value {
    Value::Array(vec![
        encode_artifact_descriptor(&value.registry_artifact),
        Value::Array(
            value
                .required_provider_keys
                .iter()
                .map(encode_provider_key)
                .collect(),
        ),
    ])
}

fn registry_fields(registry: &FixtureProviderRegistryV1) -> Vec<Value> {
    vec![
        text(FIXTURE_PROVIDER_REGISTRY_MAGIC_V1),
        uint(1),
        Value::Array(
            registry
                .providers
                .iter()
                .map(encode_provider_entry)
                .collect(),
        ),
    ]
}

fn encode_package(package: &FixtureProviderPackageV1) -> Value {
    let mut fields = package_fields(package);
    fields.push(digest(&package.package_digest));
    Value::Array(fields)
}

fn encode_package_fields(package: &FixtureProviderPackageV1) -> Value {
    Value::Array(package_fields(package))
}

fn package_fields(package: &FixtureProviderPackageV1) -> Vec<Value> {
    vec![
        text(FIXTURE_PROVIDER_PACKAGE_MAGIC_V1),
        uint(1),
        encode_provider_key(&package.provider_key),
        claim_layer(package.claim_layer),
        subject_adapter(package.subject_adapter),
        Value::Array(
            package
                .family_schemas
                .iter()
                .map(encode_family_schema)
                .collect(),
        ),
        encode_artifact_descriptor(&package.licence_descriptor),
        encode_artifact_descriptor(&package.notices_descriptor),
        encode_artifact_descriptor(&package.sbom_descriptor),
        encode_artifact_descriptor(&package.source_provenance_descriptor),
        encode_artifact_descriptor(&package.limitations_descriptor),
    ]
}

fn encode_provider_entry(value: &FixtureProviderEntryV1) -> Value {
    Value::Array(vec![
        text(&value.provider_key.provider_id),
        text(&value.provider_key.contract_version),
        uint(u64::from(value.provider_key.abi_major)),
        uint(u64::from(value.provider_key.abi_minor)),
        claim_layer(value.claim_layer),
        subject_adapter(value.subject_adapter),
        encode_artifact_descriptor(&value.provider_package_descriptor),
    ])
}

pub(crate) fn encode_provider_key(value: &FixtureProviderKeyV1) -> Value {
    Value::Array(vec![
        text(&value.provider_id),
        text(&value.contract_version),
        uint(u64::from(value.abi_major)),
        uint(u64::from(value.abi_minor)),
    ])
}

fn encode_family_schema(value: &ProviderFamilySchemaV1) -> Value {
    Value::Array(vec![
        uint(value.family.wire_code()),
        encode_artifact_descriptor(&value.schema_descriptor),
    ])
}

pub(crate) fn encode_artifact_descriptor(value: &ArtifactDescriptorV1) -> Value {
    Value::Array(vec![
        text(&value.member_path),
        text(&value.media_type),
        uint(value.byte_length),
        digest(&value.blake3_digest),
    ])
}

fn decode_registry(value: &Value) -> Result<FixtureProviderRegistryV1, ProviderContractErrorV1> {
    let fields = array(value, 4)?;
    if text_value(&fields[0])? != FIXTURE_PROVIDER_REGISTRY_MAGIC_V1 || uint_value(&fields[1])? != 1
    {
        return Err(ProviderContractErrorV1::UnsupportedVersion);
    }
    array_values(&fields[2]).and_then(|providers| {
        if providers.len() > MAX_PROVIDER_ENTRIES {
            return Err(ProviderContractErrorV1::FieldOutOfBounds);
        }
        providers
            .iter()
            .map(decode_provider_entry)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|providers| {
                digest_value(&fields[3]).map(|registry_digest| FixtureProviderRegistryV1 {
                    providers,
                    registry_digest,
                })
            })
    })
}

pub(crate) fn decode_registry_binding(
    value: &Value,
) -> Result<FixtureProviderRegistryBindingV1, ProviderContractErrorV1> {
    let fields = array(value, 2)?;
    decode_artifact_descriptor(&fields[0]).and_then(|registry_artifact| {
        array_values(&fields[1]).and_then(|required_provider_keys| {
            if required_provider_keys.len() > MAX_PROVIDER_ENTRIES {
                return Err(ProviderContractErrorV1::FieldOutOfBounds);
            }
            required_provider_keys
                .iter()
                .map(decode_provider_key)
                .collect::<Result<Vec<_>, _>>()
                .map(|required_provider_keys| FixtureProviderRegistryBindingV1 {
                    registry_artifact,
                    required_provider_keys,
                })
        })
    })
}

fn decode_package(value: &Value) -> Result<FixtureProviderPackageV1, ProviderContractErrorV1> {
    let fields = array(value, 12)?;
    if text_value(&fields[0])? != FIXTURE_PROVIDER_PACKAGE_MAGIC_V1 || uint_value(&fields[1])? != 1
    {
        return Err(ProviderContractErrorV1::UnsupportedVersion);
    }
    let provider_key = decode_provider_key(&fields[2])?;
    let claim_layer = decode_claim_layer(&fields[3])?;
    let subject_adapter = decode_subject_adapter(&fields[4])?;
    let family_schemas = array(&fields[5], 7)?
        .iter()
        .map(decode_family_schema)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FixtureProviderPackageV1 {
        provider_key,
        claim_layer,
        subject_adapter,
        family_schemas,
        licence_descriptor: decode_artifact_descriptor(&fields[6])?,
        notices_descriptor: decode_artifact_descriptor(&fields[7])?,
        sbom_descriptor: decode_artifact_descriptor(&fields[8])?,
        source_provenance_descriptor: decode_artifact_descriptor(&fields[9])?,
        limitations_descriptor: decode_artifact_descriptor(&fields[10])?,
        package_digest: digest_value(&fields[11])?,
    })
}

fn decode_provider_entry(value: &Value) -> Result<FixtureProviderEntryV1, ProviderContractErrorV1> {
    let fields = array(value, 7)?;
    decode_provider_key(&Value::Array(fields[..4].to_vec())).and_then(|provider_key| {
        decode_claim_layer(&fields[4]).and_then(|claim_layer| {
            decode_subject_adapter(&fields[5]).and_then(|subject_adapter| {
                decode_artifact_descriptor(&fields[6]).map(|provider_package_descriptor| {
                    FixtureProviderEntryV1 {
                        provider_key,
                        claim_layer,
                        subject_adapter,
                        provider_package_descriptor,
                    }
                })
            })
        })
    })
}

pub(crate) fn decode_provider_key(
    value: &Value,
) -> Result<FixtureProviderKeyV1, ProviderContractErrorV1> {
    let fields = array(value, 4)?;
    text_value(&fields[0]).and_then(|provider_id| {
        text_value(&fields[1]).and_then(|contract_version| {
            u16_value(&fields[2]).and_then(|abi_major| {
                u16_value(&fields[3]).map(|abi_minor| FixtureProviderKeyV1 {
                    provider_id,
                    contract_version,
                    abi_major,
                    abi_minor,
                })
            })
        })
    })
}

fn decode_family_schema(value: &Value) -> Result<ProviderFamilySchemaV1, ProviderContractErrorV1> {
    let fields = array(value, 2)?;
    uint_value(&fields[0]).and_then(|code| {
        FixtureFamilyV1::from_wire_code(code)
            .ok_or(ProviderContractErrorV1::FamilyInventoryInvalid)
            .and_then(|family| {
                decode_artifact_descriptor(&fields[1]).map(|schema_descriptor| {
                    ProviderFamilySchemaV1 {
                        family,
                        schema_descriptor,
                    }
                })
            })
    })
}

pub(crate) fn decode_artifact_descriptor(
    value: &Value,
) -> Result<ArtifactDescriptorV1, ProviderContractErrorV1> {
    let fields = array(value, 4)?;
    text_value(&fields[0]).and_then(|member_path| {
        text_value(&fields[1]).and_then(|media_type| {
            uint_value(&fields[2]).and_then(|byte_length| {
                digest_value(&fields[3]).map(|blake3_digest| ArtifactDescriptorV1 {
                    member_path,
                    media_type,
                    byte_length,
                    blake3_digest,
                })
            })
        })
    })
}

fn encode_bounded(value: &Value) -> Result<Vec<u8>, ProviderContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| ProviderContractErrorV1::InvalidEncoding)?;
    if bytes.len() > MAX_PROVIDER_RECORD_BYTES {
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    } else {
        Ok(bytes)
    }
}

fn decode_bounded(bytes: &[u8]) -> Result<Value, ProviderContractErrorV1> {
    if bytes.len() > MAX_PROVIDER_RECORD_BYTES {
        return Err(ProviderContractErrorV1::FieldOutOfBounds);
    }
    preflight_cbor(bytes).and_then(|()| {
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| ProviderContractErrorV1::InvalidEncoding)
            .and_then(|value| {
                encode_bounded(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(ProviderContractErrorV1::InvalidEncoding)
                    }
                })
            })
    })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), ProviderContractErrorV1> {
    fn read_length(
        bytes: &[u8],
        index: &mut usize,
        additional: u8,
    ) -> Result<u64, ProviderContractErrorV1> {
        let width = match additional {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(ProviderContractErrorV1::InvalidEncoding),
        };
        let end = index.saturating_add(width);
        let encoded = bytes
            .get(*index..end)
            .ok_or(ProviderContractErrorV1::InvalidEncoding)?;
        *index = end;
        let mut value = [0_u8; 8];
        value[8 - width..].copy_from_slice(encoded);
        Ok(u64::from_be_bytes(value))
    }

    fn item(bytes: &[u8], index: &mut usize, depth: u8) -> Result<(), ProviderContractErrorV1> {
        if depth > MAX_STRUCTURAL_NESTING {
            return Err(ProviderContractErrorV1::FieldOutOfBounds);
        }
        let initial = *bytes
            .get(*index)
            .ok_or(ProviderContractErrorV1::InvalidEncoding)?;
        *index = index.saturating_add(1);
        let length = read_length(bytes, index, initial & 0x1f)?;
        match initial >> 5 {
            0 | 1 => Ok(()),
            2 | 3 => {
                let count = usize::try_from(length)
                    .map_err(|_| ProviderContractErrorV1::FieldOutOfBounds)?;
                let end = index
                    .checked_add(count)
                    .ok_or(ProviderContractErrorV1::FieldOutOfBounds)?;
                bytes
                    .get(*index..end)
                    .ok_or(ProviderContractErrorV1::InvalidEncoding)?;
                *index = end;
                Ok(())
            }
            4 => {
                if length > MAX_PROVIDER_ENTRIES_CBOR {
                    return Err(ProviderContractErrorV1::FieldOutOfBounds);
                }
                for _ in 0..length {
                    item(bytes, index, depth.saturating_add(1))?;
                }
                Ok(())
            }
            _ => Err(ProviderContractErrorV1::InvalidEncoding),
        }
    }

    let mut index = 0;
    item(bytes, &mut index, 0).and_then(|()| {
        if index == bytes.len() {
            Ok(())
        } else {
            Err(ProviderContractErrorV1::InvalidEncoding)
        }
    })
}

fn array(value: &Value, length: usize) -> Result<&[Value], ProviderContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(ProviderContractErrorV1::InvalidEncoding),
    }
}

fn array_values(value: &Value) -> Result<&[Value], ProviderContractErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(ProviderContractErrorV1::InvalidEncoding),
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn text_value(value: &Value) -> Result<String, ProviderContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(ProviderContractErrorV1::InvalidEncoding),
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn uint_value(value: &Value) -> Result<u64, ProviderContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| ProviderContractErrorV1::InvalidEncoding)
        }
        _ => Err(ProviderContractErrorV1::InvalidEncoding),
    }
}

fn u8_value(value: &Value) -> Result<u8, ProviderContractErrorV1> {
    u8::try_from(uint_value(value)?).map_err(|_| ProviderContractErrorV1::FieldOutOfBounds)
}

fn u16_value(value: &Value) -> Result<u16, ProviderContractErrorV1> {
    u16::try_from(uint_value(value)?).map_err(|_| ProviderContractErrorV1::FieldOutOfBounds)
}

fn digest(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn digest_value(value: &Value) -> Result<[u8; 32], ProviderContractErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProviderContractErrorV1::InvalidEncoding),
        _ => Err(ProviderContractErrorV1::InvalidEncoding),
    }
}

fn claim_layer(value: ClaimLayerV1) -> Value {
    uint(u64::from(value.wire_code()))
}

fn decode_claim_layer(value: &Value) -> Result<ClaimLayerV1, ProviderContractErrorV1> {
    u8_value(value).and_then(|code| {
        ClaimLayerV1::from_wire_code(code).ok_or(ProviderContractErrorV1::FieldOutOfBounds)
    })
}

fn subject_adapter(value: SubjectAdapterKindV1) -> Value {
    uint(match value {
        SubjectAdapterKindV1::ExportedArtifact => 0,
        SubjectAdapterKindV1::PublicGatewayProtocol => 1,
        SubjectAdapterKindV1::PublicPluginProtocol => 2,
    })
}

fn decode_subject_adapter(value: &Value) -> Result<SubjectAdapterKindV1, ProviderContractErrorV1> {
    match uint_value(value)? {
        0 => Ok(SubjectAdapterKindV1::ExportedArtifact),
        1 => Ok(SubjectAdapterKindV1::PublicGatewayProtocol),
        2 => Ok(SubjectAdapterKindV1::PublicPluginProtocol),
        _ => Err(ProviderContractErrorV1::FieldOutOfBounds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn descriptor(path: &str, seed: u8) -> ArtifactDescriptorV1 {
        ArtifactDescriptorV1 {
            member_path: path.to_owned(),
            media_type: "application/cbor".to_owned(),
            byte_length: 1,
            blake3_digest: digest(seed),
        }
    }

    fn provider_key() -> FixtureProviderKeyV1 {
        FixtureProviderKeyV1 {
            provider_id: "pigloros.conformance.example".to_owned(),
            contract_version: "1.2.3-rc.1+build.9".to_owned(),
            abi_major: 1,
            abi_minor: 0,
        }
    }

    fn package() -> FixtureProviderPackageV1 {
        let family_schemas = [
            FixtureFamilyV1::Positive,
            FixtureFamilyV1::Denied,
            FixtureFamilyV1::Malformed,
            FixtureFamilyV1::ResourceExhaustion,
            FixtureFamilyV1::DeletionRedaction,
            FixtureFamilyV1::Downgrade,
            FixtureFamilyV1::IndependentEvaluation,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, family)| ProviderFamilySchemaV1 {
            family,
            schema_descriptor: descriptor(
                &format!("schemas/{index}.cddl"),
                u8::try_from(index + 1).expect("seven fixed schema seeds"),
            ),
        })
        .collect();
        let mut package = FixtureProviderPackageV1 {
            provider_key: provider_key(),
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
            family_schemas,
            licence_descriptor: descriptor("meta/license.txt", 8),
            notices_descriptor: descriptor("meta/notices.txt", 9),
            sbom_descriptor: descriptor("meta/sbom.cdx.json", 10),
            source_provenance_descriptor: descriptor("meta/source.json", 11),
            limitations_descriptor: descriptor("meta/limitations.md", 12),
            package_digest: [0; 32],
        };
        package.package_digest = package.digest().expect("package digest");
        package
    }

    fn registry(package_bytes: &[u8]) -> FixtureProviderRegistryV1 {
        let mut registry = FixtureProviderRegistryV1 {
            providers: vec![FixtureProviderEntryV1 {
                provider_key: provider_key(),
                claim_layer: ClaimLayerV1::ArtifactIntegrity,
                subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
                provider_package_descriptor: ArtifactDescriptorV1 {
                    member_path: "providers/example.fpp1".to_owned(),
                    media_type: "application/cbor".to_owned(),
                    byte_length: u64::try_from(package_bytes.len()).expect("length"),
                    blake3_digest: *blake3::hash(package_bytes).as_bytes(),
                },
            }],
            registry_digest: [0; 32],
        };
        registry.registry_digest = registry.digest().expect("registry digest");
        registry
    }

    #[test]
    fn fpr1_and_fpp1_round_trip_and_bind_exact_package_bytes() {
        let package = package();
        let package_bytes = package.to_canonical_cbor().expect("valid FPP1");
        let registry = registry(&package_bytes);
        let registry_bytes = registry.to_canonical_cbor().expect("valid FPR1");

        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&package_bytes),
            Ok(package.clone())
        );
        assert_eq!(
            FixtureProviderRegistryV1::from_canonical_cbor(&registry_bytes),
            Ok(registry.clone())
        );
        assert_eq!(
            package.validate_registry_binding(&registry.providers[0], &package_bytes),
            Ok(())
        );
    }

    #[test]
    fn registry_rejects_unsorted_keys_and_tampered_digest() {
        let package = package();
        let package_bytes = package.to_canonical_cbor().expect("valid FPP1");
        let mut registry = registry(&package_bytes);
        let mut later = registry.providers[0].clone();
        later.provider_key.provider_id = "z-provider".to_owned();
        registry.providers.insert(0, later);
        assert_eq!(
            registry.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );

        let mut digest_mismatch = registry(&package_bytes);
        digest_mismatch.registry_digest = digest(99);
        assert_eq!(
            digest_mismatch.validate(),
            Err(ProviderContractErrorV1::DigestMismatch)
        );
    }

    #[test]
    fn package_rejects_incomplete_family_inventory_and_duplicate_metadata_paths() {
        let mut missing_family = package();
        missing_family.family_schemas.pop();
        assert_eq!(
            missing_family.validate(),
            Err(ProviderContractErrorV1::FamilyInventoryInvalid)
        );

        let mut duplicate_metadata = package();
        duplicate_metadata.notices_descriptor.member_path = "meta/license.txt".to_owned();
        assert_eq!(
            duplicate_metadata.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );
    }

    #[test]
    fn descriptor_and_identifier_boundaries_are_closed() {
        let mut invalid_identifier = package();
        invalid_identifier.provider_key.provider_id = "Provider".to_owned();
        assert_eq!(
            invalid_identifier.validate(),
            Err(ProviderContractErrorV1::InvalidIdentifier)
        );

        let mut invalid_version = package();
        invalid_version.provider_key.contract_version = "01.0.0".to_owned();
        assert_eq!(
            invalid_version.validate(),
            Err(ProviderContractErrorV1::InvalidContractVersion)
        );

        let mut invalid = package();
        invalid.licence_descriptor.member_path = "/absolute.cbor".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMemberPath)
        );
        invalid.licence_descriptor.member_path = "relative.cbor".to_owned();
        invalid.licence_descriptor.media_type = "Application/cbor".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMediaType)
        );
    }

    #[test]
    fn self_digests_use_exact_field_arrays_and_length_prefixes() {
        let package = package();
        let package_fields = encode_bounded(&encode_package_fields(&package)).expect("fields");
        let mut package_preimage = b"PiglorOS.Conformance.ProviderPackage.v1\0".to_vec();
        package_preimage.extend_from_slice(
            &u64::try_from(package_fields.len())
                .expect("length")
                .to_be_bytes(),
        );
        package_preimage.extend_from_slice(&package_fields);
        assert_eq!(
            package.digest().expect("package digest"),
            *blake3::hash(&package_preimage).as_bytes()
        );

        let package_bytes = package.to_canonical_cbor().expect("valid package");
        let registry = registry(&package_bytes);
        let registry_fields = encode_bounded(&encode_registry_fields(&registry)).expect("fields");
        let mut registry_preimage = b"PiglorOS.Conformance.ProviderRegistry.v1\0".to_vec();
        registry_preimage.extend_from_slice(
            &u64::try_from(registry_fields.len())
                .expect("length")
                .to_be_bytes(),
        );
        registry_preimage.extend_from_slice(&registry_fields);
        assert_eq!(
            registry.digest().expect("registry digest"),
            *blake3::hash(&registry_preimage).as_bytes()
        );
    }

    #[test]
    fn cpf1_registry_binding_is_an_exact_two_field_value() {
        let binding = FixtureProviderRegistryBindingV1 {
            registry_artifact: descriptor(FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, 41),
            required_provider_keys: vec![provider_key()],
        };
        let bytes = binding.to_canonical_cbor().expect("valid binding");
        assert_eq!(
            FixtureProviderRegistryBindingV1::from_canonical_cbor(&bytes),
            Ok(binding.clone())
        );

        let mut duplicate_keys = binding.clone();
        duplicate_keys.required_provider_keys.push(provider_key());
        assert_eq!(
            duplicate_keys.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );

        let mut wrong_path = binding;
        wrong_path.registry_artifact.member_path = "authority/registry.cbor".to_owned();
        assert_eq!(
            wrong_path.validate(),
            Err(ProviderContractErrorV1::InvalidMemberPath)
        );
    }

    #[test]
    fn decoders_reject_wrong_magic_noncanonical_bytes_and_binding_mismatch() {
        let package = package();
        let package_bytes = package.to_canonical_cbor().expect("valid FPP1");
        let mut wrong_magic = encode_package(&package);
        if let Value::Array(fields) = &mut wrong_magic {
            fields[0] = text("FPP0");
        }
        let wrong_magic_bytes = encode_bounded(&wrong_magic).expect("encode wrong magic");
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&wrong_magic_bytes),
            Err(ProviderContractErrorV1::UnsupportedVersion)
        );

        let mut trailing = package_bytes.clone();
        trailing.push(0);
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&trailing),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );

        let registry = registry(&package_bytes);
        let mut changed = package_bytes;
        changed[0] ^= 1;
        assert_eq!(
            package.validate_registry_binding(&registry.providers[0], &changed),
            Err(ProviderContractErrorV1::PackageBindingMismatch)
        );
    }
}
