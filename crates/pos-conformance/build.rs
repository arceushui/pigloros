#[cfg(target_os = "linux")]
use rustix::fs::{self as rustix_fs, Dir, FileType, Mode, OFlags, ResolveFlags, CWD};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(not(target_os = "linux"))]
use std::io;
#[cfg(target_os = "linux")]
use std::io::{self, Read as _};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

const PROFILE_COUNT: usize = 7;
const FIXTURES_PER_PROFILE: usize = 7;
const STATIC_SOURCE_PATHS: [&str; 14] = [
    "BLAKE3SUMS",
    "expected-authority/inventory.json",
    "matrix/execution-matrix.json",
    "support/LICENSE",
    "support/NOTICE",
    "support/build-provenance.json",
    "support/draft-execution-authority.json",
    "support/fixture-family-contract.json",
    "support/limitations.md",
    "support/normative-requirements.md",
    "support/publication-review.json",
    "support/sbom.json",
    "support/schema-cpf1-v1.cddl",
    "support/source-provenance.json",
];

struct CatalogRoot {
    source: PathBuf,
    #[cfg(target_os = "linux")]
    directory: OwnedFd,
}

struct SourceSnapshots {
    sha256_inventory: Vec<u8>,
    sha256_entries: BTreeMap<String, [u8; 32]>,
    blake3_entries: BTreeMap<String, [u8; 32]>,
    sources: BTreeMap<String, Vec<u8>>,
}

impl SourceSnapshots {
    fn bytes(&self, relative: &str, description: &str) -> Result<&[u8], io::Error> {
        self.sources
            .get(relative)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                invalid_data(format!("{description} is absent from the source snapshot"))
            })
    }
}

struct FixturePaths {
    case_id: String,
    family: CatalogFixtureFamily,
    schema_path: String,
    contract: CatalogFixtureContract,
    strict_oracle: CatalogStrictOracle,
    schema: FixtureAsset,
    input: FixtureAsset,
    expected: FixtureAsset,
    oracle: FixtureAsset,
}

struct FixtureAsset {
    relative: String,
    bytes: Vec<u8>,
}

struct ProfilePaths {
    wire_code: u64,
    profile: String,
    profile_id: String,
    claim_layer: CatalogClaimLayer,
    subject_adapter: CatalogSubjectAdapter,
    profile_record: Vec<u8>,
    fixture_provider: FixtureProvider,
    provider_manifest: FixtureAsset,
    fixtures: Vec<FixturePaths>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CatalogFixtureFamily {
    Positive,
    Denied,
    Malformed,
    ResourceExhaustion,
    DeletionRedaction,
    Downgrade,
    IndependentEvaluation,
}

impl CatalogFixtureFamily {
    const ALL: [Self; FIXTURES_PER_PROFILE] = [
        Self::Positive,
        Self::Denied,
        Self::Malformed,
        Self::ResourceExhaustion,
        Self::DeletionRedaction,
        Self::Downgrade,
        Self::IndependentEvaluation,
    ];

    const fn catalog_name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Denied => "denied",
            Self::Malformed => "malformed",
            Self::ResourceExhaustion => "resource-exhaustion",
            Self::DeletionRedaction => "deletion-redaction",
            Self::Downgrade => "downgrade",
            Self::IndependentEvaluation => "independent-evaluation",
        }
    }

    const fn rust_variant(self) -> &'static str {
        match self {
            Self::Positive => "FixtureFamilyV1::Positive",
            Self::Denied => "FixtureFamilyV1::Denied",
            Self::Malformed => "FixtureFamilyV1::Malformed",
            Self::ResourceExhaustion => "FixtureFamilyV1::ResourceExhaustion",
            Self::DeletionRedaction => "FixtureFamilyV1::DeletionRedaction",
            Self::Downgrade => "FixtureFamilyV1::Downgrade",
            Self::IndependentEvaluation => "FixtureFamilyV1::IndependentEvaluation",
        }
    }
}

#[derive(Clone, Copy)]
enum CatalogClaimLayer {
    ArtifactIntegrity,
    ReplayConformance,
    KnowledgeNonInterference,
    GatewayClientConformance,
    PluginConformance,
    MetricConformance,
    EmpiricalEvaluation,
}

impl CatalogClaimLayer {
    fn from_catalog_name(name: &str) -> Result<Self, io::Error> {
        match name {
            "artifact-integrity" => Ok(Self::ArtifactIntegrity),
            "replay-conformance" => Ok(Self::ReplayConformance),
            "knowledge-non-interference" => Ok(Self::KnowledgeNonInterference),
            "gateway-client-conformance" => Ok(Self::GatewayClientConformance),
            "plugin-conformance" => Ok(Self::PluginConformance),
            "metric-conformance" => Ok(Self::MetricConformance),
            "empirical-evaluation" => Ok(Self::EmpiricalEvaluation),
            _ => Err(invalid_data("profile catalog claim_layer is invalid")),
        }
    }

    const fn wire_code(self) -> u64 {
        match self {
            Self::ArtifactIntegrity => 0,
            Self::ReplayConformance => 1,
            Self::KnowledgeNonInterference => 2,
            Self::GatewayClientConformance => 3,
            Self::PluginConformance => 4,
            Self::MetricConformance => 5,
            Self::EmpiricalEvaluation => 6,
        }
    }

    const fn rust_variant(self) -> &'static str {
        match self {
            Self::ArtifactIntegrity => "ClaimLayerV1::ArtifactIntegrity",
            Self::ReplayConformance => "ClaimLayerV1::ReplayConformance",
            Self::KnowledgeNonInterference => "ClaimLayerV1::KnowledgeNonInterference",
            Self::GatewayClientConformance => "ClaimLayerV1::GatewayClientConformance",
            Self::PluginConformance => "ClaimLayerV1::PluginConformance",
            Self::MetricConformance => "ClaimLayerV1::MetricConformance",
            Self::EmpiricalEvaluation => "ClaimLayerV1::EmpiricalEvaluation",
        }
    }
}

#[derive(Clone, Copy)]
enum CatalogSubjectAdapter {
    ExportedArtifact,
    PublicGatewayProtocol,
    PublicPluginProtocol,
}

impl CatalogSubjectAdapter {
    fn from_catalog_name(name: &str) -> Result<Self, io::Error> {
        match name {
            "exported-artifact" => Ok(Self::ExportedArtifact),
            "public-gateway-protocol" => Ok(Self::PublicGatewayProtocol),
            "public-plugin-protocol" => Ok(Self::PublicPluginProtocol),
            _ => Err(invalid_data("profile catalog subject_adapter is invalid")),
        }
    }

    const fn rust_variant(self) -> &'static str {
        match self {
            Self::ExportedArtifact => "SubjectAdapterKindV1::ExportedArtifact",
            Self::PublicGatewayProtocol => "SubjectAdapterKindV1::PublicGatewayProtocol",
            Self::PublicPluginProtocol => "SubjectAdapterKindV1::PublicPluginProtocol",
        }
    }
}

struct FixtureProvider {
    provider_id: String,
    contract_version: String,
    abi_major: u16,
    abi_minor: u16,
    package_path: String,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFixtureContract {
    deterministic_budget: CatalogDeterministicBudget,
    watchdog_ms: u64,
    network_allowed: bool,
    minimum_capability_ids: Vec<String>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDeterministicBudget {
    memory_bytes: u64,
    cpu_fuel: u64,
    host_calls: u64,
    event_count: u64,
    output_bytes: u64,
    storage_bytes: u64,
    execution_steps: u64,
    simulation_time_ns: u64,
}

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum CatalogStrictOracle {
    CanonicalOutput,
    NamespacedFailure {
        owner_id: String,
        contract_version: String,
        code_id: String,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureOracleRecord {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    oracle: CatalogStrictOracle,
    output: Option<Value>,
}

#[derive(serde::Deserialize)]
struct FixtureInputIdentity {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    provider_contract: String,
    subject_adapter: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceStatusRecord {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    input_blake3_digest: String,
    status: String,
    execution_result: serde_json::Value,
    executed_at: serde_json::Value,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftAuthorityDeclaration {
    magic: String,
    version: u64,
    lifecycle: String,
    authority_kind: String,
    trust_policy_id: String,
    trust_policy_epoch: u64,
    effective_timeline_position: u64,
    offline_valid_through: String,
    fixture_authority_key_id: String,
    fixture_authority_public_key_hex: String,
    execution_profiles: Vec<DraftExecutionProfile>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftExecutionProfile {
    profile_id: String,
    semantic_version: String,
    network_allowed: bool,
    capability_ids: Vec<String>,
    reproducibility_classes: Vec<DraftReproducibilityClass>,
}

#[derive(serde::Deserialize)]
enum DraftReproducibilityClass {
    ProfileRecomputation,
    CrossProfileConformance,
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(target_os = "linux")]
fn catalog_root(manifest_dir: &Path) -> Result<CatalogRoot, io::Error> {
    let source = manifest_dir.join("../../fixtures/conformance");
    let source_name = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        invalid_data(format!(
            "conformance fixture root contains a NUL byte: {}",
            source.display()
        ))
    })?;
    let directory = rustix_fs::openat2(
        CWD,
        source_name.as_c_str(),
        OFlags::RDONLY
            .union(OFlags::DIRECTORY)
            .union(OFlags::CLOEXEC)
            .union(OFlags::NOFOLLOW),
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        invalid_data(format!(
            "conformance fixture root cannot be opened at {}: {error}",
            source.display()
        ))
    })?;
    let metadata = rustix_fs::fstat(&directory).map_err(|error| {
        invalid_data(format!(
            "conformance fixture root cannot be inspected at {}: {error}",
            source.display()
        ))
    })?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
        return Err(invalid_data(format!(
            "conformance fixture root must be a directory: {}",
            source.display()
        )));
    }
    Ok(CatalogRoot { source, directory })
}

#[cfg(not(target_os = "linux"))]
fn catalog_root(_manifest_dir: &Path) -> Result<CatalogRoot, io::Error> {
    Err(invalid_data(
        "secure conformance fixture snapshot generation requires Linux openat2",
    ))
}

fn relative_components<'a>(
    relative: &'a str,
    description: &str,
) -> Result<Vec<&'a std::ffi::OsStr>, io::Error> {
    if relative.is_empty() {
        return Err(invalid_data(format!("{description} must not be empty")));
    }
    Path::new(relative)
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(invalid_data(format!(
                "{description} must be a relative path without traversal: {relative}"
            ))),
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn open_fixture_relative(
    root: &CatalogRoot,
    relative: &str,
    description: &str,
    final_is_directory: bool,
) -> Result<OwnedFd, io::Error> {
    let _ = relative_components(relative, description)?;
    let relative_name = CString::new(relative)
        .map_err(|_| invalid_data(format!("{description} contains a NUL byte: {relative}")))?;
    let mut flags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);
    if final_is_directory {
        flags = flags.union(OFlags::DIRECTORY);
    }
    let opened = rustix_fs::openat2(
        &root.directory,
        relative_name.as_c_str(),
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
    )
    .map_err(|error| {
        invalid_data(format!(
            "{description} cannot be opened beneath the conformance fixture root at {relative}: {error}"
        ))
    })?;
    let metadata = rustix_fs::fstat(&opened).map_err(|error| {
        invalid_data(format!(
            "{description} cannot be inspected at {relative}: {error}"
        ))
    })?;
    let expected_type = if final_is_directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    if FileType::from_raw_mode(metadata.st_mode) != expected_type {
        return Err(invalid_data(format!(
            "{description} must be a {}: {relative}",
            if final_is_directory {
                "directory"
            } else {
                "regular file"
            }
        )));
    }
    Ok(opened)
}

#[cfg(target_os = "linux")]
fn read_fixture_relative(
    root: &CatalogRoot,
    relative: &str,
    description: &str,
) -> Result<Vec<u8>, io::Error> {
    let mut file: File = open_fixture_relative(root, relative, description, false)?.into();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        invalid_data(format!(
            "{description} cannot be read at {relative}: {error}"
        ))
    })?;
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_fixture_relative(
    _root: &CatalogRoot,
    _relative: &str,
    _description: &str,
) -> Result<Vec<u8>, io::Error> {
    Err(invalid_data(
        "secure conformance fixture snapshot generation requires Linux openat2",
    ))
}

fn checksum_digest(hex: &str, description: &str) -> Result<[u8; 32], io::Error> {
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(invalid_data(format!(
            "{description} must contain 64 ASCII hex digits"
        )));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| invalid_data(format!("{description} is not UTF-8")))?;
        digest[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| invalid_data(format!("{description} contains a non-hex digit")))?;
    }
    Ok(digest)
}

fn checksum_manifest(
    bytes: &[u8],
    description: &str,
) -> Result<std::collections::BTreeMap<String, [u8; 32]>, io::Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid_data(format!("{description} must be UTF-8")))?;
    if text.is_empty() || !text.ends_with('\n') {
        return Err(invalid_data(format!(
            "{description} must be non-empty and newline-terminated"
        )));
    }
    text.lines()
        .try_fold(std::collections::BTreeMap::new(), |mut entries, line| {
            let (hex, relative) = line.split_once("  ").ok_or_else(|| {
                invalid_data(format!("{description} contains a malformed record"))
            })?;
            let _ = relative_components(relative, description)?;
            let digest = checksum_digest(hex, description)?;
            if entries.insert(relative.to_owned(), digest).is_some() {
                return Err(invalid_data(format!(
                    "{description} contains duplicate path {relative}"
                )));
            }
            Ok(entries)
        })
}

fn expected_source_paths(profiles: &[ProfilePaths]) -> BTreeSet<String> {
    let mut paths: BTreeSet<String> = STATIC_SOURCE_PATHS.map(str::to_owned).into_iter().collect();
    for profile in profiles {
        paths.insert(profile.profile.clone());
        paths.insert(profile.provider_manifest.relative.clone());
        for fixture in &profile.fixtures {
            paths.insert(fixture.schema.relative.clone());
            paths.insert(fixture.input.relative.clone());
            paths.insert(fixture.expected.relative.clone());
            paths.insert(fixture.oracle.relative.clone());
        }
    }
    paths
}

fn source_snapshots(root: &CatalogRoot) -> Result<SourceSnapshots, io::Error> {
    let sha256_bytes = read_fixture_relative(root, "SHA256SUMS", "SHA-256 source inventory")?;
    let sha256_entries = checksum_manifest(&sha256_bytes, "SHA-256 source inventory")?;
    if sha256_entries.contains_key("SHA256SUMS") {
        return Err(invalid_data(
            "SHA-256 source inventory must not declare itself",
        ));
    }
    let sources = sha256_entries
        .keys()
        .map(|relative| {
            read_fixture_relative(root, relative, "SHA-256 inventoried source")
                .map(|bytes| (relative.clone(), bytes))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let blake3_bytes = sources
        .get("BLAKE3SUMS")
        .ok_or_else(|| invalid_data("SHA-256 source inventory omits BLAKE3SUMS"))?;
    let blake3_entries = checksum_manifest(blake3_bytes, "BLAKE3 source inventory")?;
    Ok(SourceSnapshots {
        sha256_inventory: sha256_bytes,
        sha256_entries,
        blake3_entries,
        sources,
    })
}

fn verify_source_inventory(
    snapshots: &SourceSnapshots,
    profiles: &[ProfilePaths],
) -> Result<[u8; 32], io::Error> {
    let expected_paths = expected_source_paths(profiles);
    let declared_paths = snapshots
        .sha256_entries
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared_paths != expected_paths {
        return Err(invalid_data(
            "SHA-256 source inventory does not declare the complete materialization closure",
        ));
    }
    for (relative, expected) in &snapshots.sha256_entries {
        let bytes = snapshots.bytes(relative, "SHA-256 inventoried source")?;
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if &actual != expected {
            return Err(invalid_data(format!(
                "SHA-256 source inventory digest mismatch for {relative}"
            )));
        }
    }

    let mut blake3_paths = expected_paths;
    blake3_paths.remove("BLAKE3SUMS");
    if snapshots
        .blake3_entries
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != blake3_paths
    {
        return Err(invalid_data(
            "BLAKE3 source inventory does not declare the complete materialization closure",
        ));
    }
    for (relative, expected) in &snapshots.blake3_entries {
        let bytes = snapshots.bytes(relative, "BLAKE3 inventoried source")?;
        if blake3::hash(bytes).as_bytes() != expected {
            return Err(invalid_data(format!(
                "BLAKE3 source inventory digest mismatch for {relative}"
            )));
        }
    }
    Ok(Sha256::digest(&snapshots.sha256_inventory).into())
}

fn json_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, io::Error> {
    value
        .get(field)
        .ok_or_else(|| invalid_data(format!("profile catalog is missing {field}")))
}

fn json_text(value: &Value, field: &str) -> Result<String, io::Error> {
    json_field(value, field)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_data(format!("profile catalog {field} must be text")))
}

fn json_u64(value: &Value, field: &str) -> Result<u64, io::Error> {
    json_field(value, field)?
        .as_u64()
        .ok_or_else(|| invalid_data(format!("profile catalog {field} must be unsigned")))
}

fn validate_fixture_provider(
    provider: &Value,
    claim_layer: &str,
    subject_adapter: &str,
) -> Result<(), io::Error> {
    let schemas = json_field(provider, "schemas")?.as_object();
    let operations = json_field(provider, "fixture_operations")?.as_object();
    let payloads = json_field(provider, "fixture_payloads")?.as_object();
    let contracts = json_field(provider, "fixture_contracts")?.as_object();
    let contracts_match_families = schemas
        .zip(operations)
        .zip(payloads)
        .zip(contracts)
        .is_some_and(|(((schemas, operations), payloads), contracts)| {
            let schema_families = schemas.keys().collect::<BTreeSet<_>>();
            let operation_families = operations.keys().collect::<BTreeSet<_>>();
            let payload_families = payloads.keys().collect::<BTreeSet<_>>();
            let contract_families = contracts.keys().collect::<BTreeSet<_>>();
            schemas.len() == FIXTURES_PER_PROFILE
                && operations.len() == FIXTURES_PER_PROFILE
                && payloads.len() == FIXTURES_PER_PROFILE
                && contracts.len() == FIXTURES_PER_PROFILE
                && schema_families == operation_families
                && schema_families == payload_families
                && schema_families == contract_families
        });
    let valid = !json_text(provider, "provider_id")?.is_empty()
        && !json_text(provider, "contract_version")?.is_empty()
        && u16::try_from(json_u64(provider, "abi_major")?).is_ok()
        && u16::try_from(json_u64(provider, "abi_minor")?).is_ok()
        && !json_text(provider, "package_path")?.is_empty()
        && json_text(provider, "claim_layer")? == claim_layer
        && json_text(provider, "subject_adapter")? == subject_adapter
        && contracts_match_families;
    if valid {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "provider manifest does not match profile claim layer {claim_layer}"
        )))
    }
}

fn validate_fixture_records(
    fixture: &Value,
    provider: &Value,
    schema_bytes: &[u8],
    input_bytes: &[u8],
    expected_bytes: &[u8],
    oracle_bytes: &[u8],
    claim_layer: &str,
    subject_adapter: &str,
) -> Result<CatalogStrictOracle, io::Error> {
    let case_id = json_text(fixture, "case_id")?;
    let family: CatalogFixtureFamily =
        serde_json::from_value(json_field(fixture, "family")?.clone()).map_err(|error| {
            invalid_data(format!("fixture {case_id} family is invalid: {error}"))
        })?;
    if json_text(fixture, "claim_layer")? != claim_layer {
        return Err(invalid_data(format!(
            "fixture {case_id} claim layer does not match its profile"
        )));
    }
    let input: Value = serde_json::from_slice(input_bytes)
        .map_err(|error| invalid_data(format!("fixture {case_id} input is invalid: {error}")))?;
    let input_identity: FixtureInputIdentity =
        serde_json::from_slice(input_bytes).map_err(|error| {
            invalid_data(format!(
                "fixture {case_id} input identity is invalid: {error}"
            ))
        })?;
    let evidence: EvidenceStatusRecord =
        serde_json::from_slice(expected_bytes).map_err(|error| {
            invalid_data(format!(
                "fixture {case_id} evidence status is invalid: {error}"
            ))
        })?;
    let oracle: FixtureOracleRecord = serde_json::from_slice(oracle_bytes)
        .map_err(|error| invalid_data(format!("fixture {case_id} oracle is invalid: {error}")))?;
    let provider_contract = format!(
        "{}@{}",
        json_text(provider, "provider_id")?,
        json_text(provider, "contract_version")?
    );
    let operation = json_field(provider, "fixture_operations")?
        .get(family.catalog_name())
        .ok_or_else(|| {
            invalid_data(format!(
                "provider omits operation for {}",
                family.catalog_name()
            ))
        })?;
    let actual_operation = input.pointer("/stimulus/operation");
    let operation_matches = match operation {
        Value::Null => actual_operation.is_none(),
        Value::String(expected) => actual_operation.and_then(Value::as_str) == Some(expected),
        _ => false,
    };
    let input_digest = blake3::hash(input_bytes).to_hex().to_string();
    let schema_accepts_input = json_schema_accepts(schema_bytes, &input)?;
    let schema_result_matches = schema_accepts_input == (family != CatalogFixtureFamily::Malformed);
    let expected_shape_matches = if family == CatalogFixtureFamily::IndependentEvaluation {
        input.get("expected").is_none()
            && input
                .get("expected_digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.len() == 64)
    } else {
        input.get("expected").is_some_and(Value::is_object)
    };
    let oracle_shape_matches = match &oracle.oracle {
        CatalogStrictOracle::CanonicalOutput => oracle.output.is_some(),
        CatalogStrictOracle::NamespacedFailure { .. } => oracle.output.is_none(),
    };
    let identity_matches = input_identity.case_id == case_id
        && input_identity.claim_layer == claim_layer
        && input_identity.family == family
        && input_identity.provider_contract == provider_contract
        && input_identity.subject_adapter == subject_adapter
        && expected_shape_matches
        && evidence.case_id == case_id
        && evidence.claim_layer == claim_layer
        && evidence.family == family
        && evidence.input_blake3_digest == input_digest
        && evidence.status == "pending"
        && evidence.execution_result == Value::Null
        && evidence.executed_at == Value::Null
        && oracle.case_id == case_id
        && oracle.claim_layer == claim_layer
        && oracle.family == family
        && oracle_shape_matches
        && schema_result_matches;
    if operation_matches && identity_matches {
        Ok(oracle.oracle)
    } else {
        Err(invalid_data(format!(
            "fixture {case_id} does not match its profile/provider identity"
        )))
    }
}

fn json_schema_accepts(schema_bytes: &[u8], instance: &Value) -> Result<bool, io::Error> {
    let schema: Value = serde_json::from_slice(schema_bytes)
        .map_err(|error| invalid_data(format!("fixture schema is invalid: {error}")))?;
    validate_supported_schema(&schema).and_then(|()| value_matches_schema(instance, &schema))
}

fn validate_supported_schema(schema: &Value) -> Result<(), io::Error> {
    let object = schema
        .as_object()
        .ok_or_else(|| invalid_data("fixture schema node must be an object"))?;
    let supported = [
        "$schema",
        "additionalProperties",
        "const",
        "maximum",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "required",
        "type",
    ];
    if object.keys().any(|key| !supported.contains(&key.as_str())) {
        return Err(invalid_data("fixture schema uses an unsupported keyword"));
    }
    let metadata_valid = object
        .get("$schema")
        .is_none_or(|value| value.as_str() == Some("https://json-schema.org/draft/2020-12/schema"))
        && object
            .get("additionalProperties")
            .is_none_or(Value::is_boolean)
        && object
            .get("minLength")
            .is_none_or(|value| value.as_u64().is_some())
        && object
            .get("minimum")
            .is_none_or(|value| value.as_i64().is_some())
        && object
            .get("maximum")
            .is_none_or(|value| value.as_i64().is_some())
        && object
            .get("pattern")
            .is_none_or(|value| value.as_str() == Some("^[0-9a-f]{64}$"))
        && object.get("required").is_none_or(|value| {
            value
                .as_array()
                .is_some_and(|names| names.iter().all(Value::is_string))
        });
    if !metadata_valid {
        return Err(invalid_data("fixture schema keyword value is unsupported"));
    }
    schema_type_matches(&Value::Null, object.get("type"))?;
    object.get("properties").map_or(Ok(()), |properties| {
        properties
            .as_object()
            .ok_or_else(|| invalid_data("fixture schema properties must be an object"))?
            .values()
            .try_for_each(validate_supported_schema)
    })
}

fn value_matches_schema(instance: &Value, schema: &Value) -> Result<bool, io::Error> {
    let object = schema
        .as_object()
        .ok_or_else(|| invalid_data("fixture schema node must be an object"))?;
    if !schema_type_matches(instance, object.get("type"))?
        || object
            .get("const")
            .is_some_and(|constant| constant != instance)
        || !schema_scalar_constraints_match(instance, object)?
    {
        return Ok(false);
    }
    schema_object_constraints_match(instance, object)
}

fn schema_type_matches(instance: &Value, declared: Option<&Value>) -> Result<bool, io::Error> {
    declared.map_or(Ok(true), |value| {
        value
            .as_str()
            .ok_or_else(|| invalid_data("fixture schema type must be a string"))
            .and_then(|kind| match kind {
                "array" => Ok(instance.is_array()),
                "integer" => Ok(instance.as_i64().is_some() || instance.as_u64().is_some()),
                "object" => Ok(instance.is_object()),
                "string" => Ok(instance.is_string()),
                _ => Err(invalid_data("fixture schema type is unsupported")),
            })
    })
}

fn schema_scalar_constraints_match(
    instance: &Value,
    schema: &serde_json::Map<String, Value>,
) -> Result<bool, io::Error> {
    let minimum_length = schema.get("minLength").map_or(Ok(None), |value| {
        value
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid_data("fixture schema minLength must be unsigned"))
    })?;
    let length_matches = minimum_length.is_none_or(|minimum| {
        instance.as_str().is_some_and(|value| {
            u64::try_from(value.chars().count()).is_ok_and(|length| length >= minimum)
        })
    });
    let pattern_matches = schema.get("pattern").map_or(Ok(true), |pattern| {
        pattern
            .as_str()
            .ok_or_else(|| invalid_data("fixture schema pattern must be a string"))
            .and_then(|pattern| {
                if pattern == "^[0-9a-f]{64}$" {
                    Ok(instance.as_str().is_some_and(|value| {
                        value.len() == 64
                            && value
                                .bytes()
                                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                    }))
                } else {
                    Err(invalid_data("fixture schema pattern is unsupported"))
                }
            })
    })?;
    let minimum_matches = integer_bound_matches(instance, schema.get("minimum"), false)?;
    let maximum_matches = integer_bound_matches(instance, schema.get("maximum"), true)?;
    Ok(length_matches && pattern_matches && minimum_matches && maximum_matches)
}

fn integer_bound_matches(
    instance: &Value,
    bound: Option<&Value>,
    maximum: bool,
) -> Result<bool, io::Error> {
    bound.map_or(Ok(true), |bound| {
        let bound = bound
            .as_i64()
            .ok_or_else(|| invalid_data("fixture schema bound must be an integer"))?;
        let value = instance
            .as_i64()
            .ok_or_else(|| invalid_data("fixture integer does not fit the supported range"))?;
        Ok(if maximum {
            value <= bound
        } else {
            value >= bound
        })
    })
}

fn schema_object_constraints_match(
    instance: &Value,
    schema: &serde_json::Map<String, Value>,
) -> Result<bool, io::Error> {
    let Some(instance) = instance.as_object() else {
        return Ok(true);
    };
    let properties = schema.get("properties").map_or(Ok(None), |value| {
        value
            .as_object()
            .map(Some)
            .ok_or_else(|| invalid_data("fixture schema properties must be an object"))
    })?;
    let required = schema.get("required").map_or(Ok(Vec::new()), |value| {
        value
            .as_array()
            .ok_or_else(|| invalid_data("fixture schema required must be an array"))?
            .iter()
            .map(|name| {
                name.as_str()
                    .ok_or_else(|| invalid_data("fixture schema required entry must be a string"))
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    if required.iter().any(|name| !instance.contains_key(*name)) {
        return Ok(false);
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false))
        && instance
            .keys()
            .any(|name| properties.is_none_or(|known| !known.contains_key(name)))
    {
        return Ok(false);
    }
    properties.map_or(Ok(true), |properties| {
        properties
            .iter()
            .try_fold(true, |matches, (name, child_schema)| {
                instance.get(name).map_or(Ok(matches), |child| {
                    value_matches_schema(child, child_schema)
                        .map(|child_matches| matches && child_matches)
                })
            })
    })
}

fn fixture_contract(
    provider: &Value,
    family: CatalogFixtureFamily,
) -> Result<CatalogFixtureContract, io::Error> {
    let contract = json_field(provider, "fixture_contracts")?
        .get(family.catalog_name())
        .ok_or_else(|| {
            invalid_data(format!(
                "provider omits contract for {}",
                family.catalog_name()
            ))
        })?;
    serde_json::from_value(contract.clone()).map_err(|error| {
        invalid_data(format!(
            "provider contract for {} is invalid: {error}",
            family.catalog_name()
        ))
    })
}

fn fixture_provider(provider: &Value) -> Result<FixtureProvider, io::Error> {
    let abi_major = u16::try_from(json_u64(provider, "abi_major")?)
        .map_err(|_| invalid_data("provider abi_major must fit u16"))?;
    let abi_minor = u16::try_from(json_u64(provider, "abi_minor")?)
        .map_err(|_| invalid_data("provider abi_minor must fit u16"))?;
    Ok(FixtureProvider {
        provider_id: json_text(provider, "provider_id")?,
        contract_version: json_text(provider, "contract_version")?,
        abi_major,
        abi_minor,
        package_path: json_text(provider, "package_path")?,
    })
}

fn relative_asset(
    snapshots: &SourceSnapshots,
    value: &Value,
    field: &str,
) -> Result<FixtureAsset, io::Error> {
    let relative = json_text(value, field)?;
    let description = format!("profile catalog {field}");
    let bytes = snapshots.bytes(&relative, &description)?.to_vec();
    Ok(FixtureAsset { relative, bytes })
}

fn profile_fixtures(
    snapshots: &SourceSnapshots,
    profile_value: &Value,
    provider_value: &Value,
    provider_schemas: &serde_json::Map<String, Value>,
    claim_layer: &str,
    subject_adapter: &str,
) -> Result<Vec<FixturePaths>, io::Error> {
    let fixtures = json_field(profile_value, "fixtures")?
        .as_array()
        .ok_or_else(|| invalid_data("profile catalog fixtures must be an array"))?;
    fixtures
        .iter()
        .zip(CatalogFixtureFamily::ALL)
        .map(|(fixture, expected_family)| {
            let case_id = json_text(fixture, "case_id")?;
            let family: CatalogFixtureFamily =
                serde_json::from_value(json_field(fixture, "family")?.clone()).map_err(
                    |error| invalid_data(format!("fixture {case_id} family is invalid: {error}")),
                )?;
            if family != expected_family {
                return Err(invalid_data(format!(
                    "profile fixture {case_id} is not in canonical family order"
                )));
            }
            let schema_path = json_text(fixture, "schema")?;
            let schema = relative_asset(snapshots, fixture, "schema")?;
            let expected_schema = provider_schemas
                .get(family.catalog_name())
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid_data(format!(
                        "provider manifest is missing schema {}",
                        family.catalog_name()
                    ))
                })?;
            if schema.relative != expected_schema {
                return Err(invalid_data(format!(
                    "profile fixture schema does not match family {}",
                    family.catalog_name()
                )));
            }
            let input = relative_asset(snapshots, fixture, "input")?;
            let expected = relative_asset(snapshots, fixture, "expected")?;
            let oracle = relative_asset(snapshots, fixture, "oracle")?;
            let strict_oracle = validate_fixture_records(
                fixture,
                provider_value,
                &schema.bytes,
                &input.bytes,
                &expected.bytes,
                &oracle.bytes,
                claim_layer,
                subject_adapter,
            )?;
            Ok(FixturePaths {
                case_id,
                family,
                schema_path,
                contract: fixture_contract(provider_value, family)?,
                strict_oracle,
                schema,
                input,
                expected,
                oracle,
            })
        })
        .collect()
}

fn profile_paths(
    snapshots: &SourceSnapshots,
    profile: String,
) -> Result<ProfilePaths, Box<dyn Error>> {
    let profile_record = snapshots.bytes(&profile, "profile manifest")?.to_vec();
    let profile_value: Value = serde_json::from_slice(&profile_record)?;
    let profile_id = json_text(&profile_value, "profile_id")?;
    let claim_layer = json_text(&profile_value, "claim_layer")?;
    let catalog_claim_layer = CatalogClaimLayer::from_catalog_name(&claim_layer)?;
    let subject_adapter = json_text(&profile_value, "subject_adapter")?;
    let catalog_subject_adapter = CatalogSubjectAdapter::from_catalog_name(&subject_adapter)?;
    let fixture_root = json_text(&profile_value, "fixture_root")?;
    let provider_manifest = relative_asset(snapshots, &profile_value, "fixture_provider_manifest")?;
    let provider_value: Value = serde_json::from_slice(&provider_manifest.bytes)?;
    validate_fixture_provider(&provider_value, &claim_layer, &subject_adapter)?;
    let fixture_provider = fixture_provider(&provider_value)?;
    let provider_schemas = json_field(&provider_value, "schemas")?
        .as_object()
        .ok_or_else(|| invalid_data("provider manifest schemas must be an object"))?;
    let wire_code = json_field(&profile_value, "wire_code")?
        .as_u64()
        .ok_or_else(|| invalid_data("profile catalog wire_code must be unsigned"))?;
    let fixture_records = json_field(&profile_value, "fixtures")?
        .as_array()
        .ok_or_else(|| invalid_data("profile catalog fixtures must be an array"))?;
    if fixture_records.len() != FIXTURES_PER_PROFILE {
        return Err(invalid_data(format!(
            "profile manifest {profile} must declare exactly {FIXTURES_PER_PROFILE} fixtures, found {}",
            fixture_records.len()
        ))
        .into());
    }
    let fixtures = profile_fixtures(
        snapshots,
        &profile_value,
        &provider_value,
        provider_schemas,
        &claim_layer,
        &subject_adapter,
    )?;
    let bundle_modes = json_field(&profile_value, "bundle_modes")?;
    let execution_profiles = json_field(&profile_value, "execution_profiles")?;
    if fixture_root != claim_layer
        || wire_code != catalog_claim_layer.wire_code()
        || bundle_modes != &serde_json::json!(["local", "air-gapped"])
        || execution_profiles
            != &serde_json::json!(["deterministic-local-v1", "deterministic-air-gapped-v1"])
    {
        return Err(invalid_data(format!(
            "profile manifest {profile} must declare exactly {FIXTURES_PER_PROFILE} fixtures, found {}",
            fixtures.len()
        ))
        .into());
    }
    Ok(ProfilePaths {
        wire_code,
        profile,
        profile_id,
        claim_layer: catalog_claim_layer,
        subject_adapter: catalog_subject_adapter,
        profile_record,
        fixture_provider,
        provider_manifest,
        fixtures,
    })
}

#[cfg(target_os = "linux")]
fn profile_manifests(root: &CatalogRoot) -> Result<Vec<String>, Box<dyn Error>> {
    let profiles_directory = open_fixture_relative(root, "profiles", "profile root", true)?;
    let mut profile_manifests = Vec::new();
    for entry in Dir::read_from(&profiles_directory)
        .map_err(|error| invalid_data(format!("profile root cannot be read: {error}")))?
    {
        let entry =
            entry.map_err(|error| invalid_data(format!("profile root cannot be read: {error}")))?;
        let entry_name = std::str::from_utf8(entry.file_name().to_bytes())
            .map_err(|_| invalid_data("profile directory name must be UTF-8"))?;
        if entry_name == "." || entry_name == ".." {
            continue;
        }
        let directory = format!("profiles/{entry_name}");
        let _opened_directory = open_fixture_relative(root, &directory, "profile directory", true)?;
        profile_manifests.push(format!("{directory}/profile.json"));
    }
    Ok(profile_manifests)
}

#[cfg(not(target_os = "linux"))]
fn profile_manifests(_root: &CatalogRoot) -> Result<Vec<String>, Box<dyn Error>> {
    Err(
        invalid_data("secure conformance fixture snapshot generation requires Linux openat2")
            .into(),
    )
}

fn discover_profiles(
    root: &CatalogRoot,
    snapshots: &SourceSnapshots,
) -> Result<Vec<ProfilePaths>, Box<dyn Error>> {
    let profile_manifests = profile_manifests(root)?;
    if profile_manifests.len() != PROFILE_COUNT {
        return Err(invalid_data(format!(
            "profile root must contain exactly {PROFILE_COUNT} profile directories, found {}",
            profile_manifests.len()
        ))
        .into());
    }
    let mut profiles = profile_manifests
        .into_iter()
        .map(|profile| profile_paths(snapshots, profile))
        .collect::<Result<Vec<_>, _>>()?;
    profiles.sort_unstable_by_key(|profile| profile.wire_code);
    if profiles
        .windows(2)
        .any(|pair| pair[0].wire_code >= pair[1].wire_code)
    {
        return Err(invalid_data(
            "profile catalog wire codes must be unique and strictly increasing",
        )
        .into());
    }
    Ok(profiles)
}

fn emit_fixture_contract(
    generated: &mut String,
    fixture: &FixturePaths,
) -> Result<(), std::fmt::Error> {
    writeln!(
        generated,
        "                        contract: CatalogFixtureContract {{"
    )?;
    writeln!(
        generated,
        "                            deterministic_budget: DeterministicBudgetV1 {{"
    )?;
    let budget = &fixture.contract.deterministic_budget;
    writeln!(
        generated,
        "                                memory_bytes: {},",
        budget.memory_bytes
    )?;
    writeln!(
        generated,
        "                                cpu_fuel: {},",
        budget.cpu_fuel
    )?;
    writeln!(
        generated,
        "                                host_calls: {},",
        budget.host_calls
    )?;
    writeln!(
        generated,
        "                                event_count: {},",
        budget.event_count
    )?;
    writeln!(
        generated,
        "                                output_bytes: {},",
        budget.output_bytes
    )?;
    writeln!(
        generated,
        "                                storage_bytes: {},",
        budget.storage_bytes
    )?;
    writeln!(
        generated,
        "                                execution_steps: {},",
        budget.execution_steps
    )?;
    writeln!(
        generated,
        "                                simulation_time_ns: {},",
        budget.simulation_time_ns
    )?;
    writeln!(generated, "                            }},")?;
    writeln!(
        generated,
        "                            watchdog_ms: {},",
        fixture.contract.watchdog_ms
    )?;
    writeln!(
        generated,
        "                            network_allowed: {},",
        fixture.contract.network_allowed
    )?;
    write!(
        generated,
        "                            minimum_capability_ids: &["
    )?;
    for capability in &fixture.contract.minimum_capability_ids {
        write!(generated, "{capability:?}, ")?;
    }
    writeln!(generated, "],")?;
    writeln!(generated, "                        }},")
}

fn emit_strict_oracle(
    generated: &mut String,
    oracle: &CatalogStrictOracle,
) -> Result<(), std::fmt::Error> {
    match oracle {
        CatalogStrictOracle::CanonicalOutput => writeln!(
            generated,
            "                        strict_oracle: CatalogStrictOracle::CanonicalOutput,"
        ),
        CatalogStrictOracle::NamespacedFailure {
            owner_id,
            contract_version,
            code_id,
        } => {
            writeln!(
                generated,
                "                        strict_oracle: CatalogStrictOracle::NamespacedFailure {{"
            )?;
            writeln!(
                generated,
                "                            owner_id: {owner_id:?},"
            )?;
            writeln!(
                generated,
                "                            contract_version: {contract_version:?},"
            )?;
            writeln!(
                generated,
                "                            code_id: {code_id:?},"
            )?;
            writeln!(generated, "                        }},")
        }
    }
}

fn emit_fixture(generated: &mut String, fixture: &FixturePaths) -> Result<(), std::fmt::Error> {
    writeln!(generated, "                    CatalogFixture {{")?;
    writeln!(
        generated,
        "                        case_id: {:?},",
        fixture.case_id
    )?;
    writeln!(
        generated,
        "                        family: {},",
        fixture.family.rust_variant()
    )?;
    writeln!(
        generated,
        "                        schema_path: {:?},",
        fixture.schema_path
    )?;
    emit_fixture_contract(generated, fixture)?;
    writeln!(
        generated,
        "                        schema: &{:?},",
        fixture.schema.bytes
    )?;
    writeln!(
        generated,
        "                        input: &{:?},",
        fixture.input.bytes
    )?;
    writeln!(
        generated,
        "                        expected: &{:?},",
        fixture.expected.bytes
    )?;
    writeln!(
        generated,
        "                        oracle: &{:?},",
        fixture.oracle.bytes
    )?;
    emit_strict_oracle(generated, &fixture.strict_oracle)?;
    writeln!(generated, "                    }},")
}

fn emit_profile(generated: &mut String, profile: &ProfilePaths) -> Result<(), std::fmt::Error> {
    writeln!(generated, "            LayerCatalogEntry {{")?;
    writeln!(
        generated,
        "                claim_layer: {},",
        profile.claim_layer.rust_variant()
    )?;
    writeln!(
        generated,
        "                profile_id: {:?},",
        profile.profile_id
    )?;
    writeln!(
        generated,
        "                subject_adapter: {},",
        profile.subject_adapter.rust_variant()
    )?;
    writeln!(
        generated,
        "                fixture_provider: FixtureProvider {{"
    )?;
    writeln!(
        generated,
        "                    provider_id: {:?},",
        profile.fixture_provider.provider_id
    )?;
    writeln!(
        generated,
        "                    contract_version: {:?},",
        profile.fixture_provider.contract_version
    )?;
    writeln!(
        generated,
        "                    abi_major: {},",
        profile.fixture_provider.abi_major
    )?;
    writeln!(
        generated,
        "                    abi_minor: {},",
        profile.fixture_provider.abi_minor
    )?;
    writeln!(
        generated,
        "                    package_path: {:?},",
        profile.fixture_provider.package_path
    )?;
    writeln!(generated, "                }},")?;
    writeln!(
        generated,
        "                profile_record: &{:?},",
        profile.profile_record
    )?;
    writeln!(generated, "                fixtures: vec![")?;
    for fixture in &profile.fixtures {
        emit_fixture(generated, fixture)?;
    }
    writeln!(generated, "                ],")?;
    writeln!(generated, "            }},")
}

fn emit_catalog(profiles: &[ProfilePaths]) -> Result<String, std::fmt::Error> {
    let mut generated = String::from(
        "fn layer_catalog() -> LayerCatalog {\n    LayerCatalog {\n        entries: vec![\n",
    );
    for profile in profiles {
        emit_profile(&mut generated, profile)?;
    }
    generated.push_str("        ],\n    }\n}\n");
    Ok(generated)
}

fn draft_authority_public_key(snapshots: &SourceSnapshots) -> Result<[u8; 32], io::Error> {
    let relative = "support/draft-execution-authority.json";
    let bytes = snapshots.bytes(relative, "Draft authority declaration")?;
    let declaration: DraftAuthorityDeclaration =
        serde_json::from_slice(bytes).map_err(|error| {
            invalid_data(format!(
                "Draft authority declaration is invalid at {relative}: {error}"
            ))
        })?;
    let profiles_are_valid = declaration.execution_profiles.len() == 2
        && declaration.execution_profiles.iter().all(|profile| {
            !profile.profile_id.is_empty()
                && !profile.semantic_version.is_empty()
                && !profile.network_allowed
                && profile.capability_ids.is_empty()
                && !profile.reproducibility_classes.is_empty()
        });
    if declaration.magic != "DFA1"
        || declaration.version != 1
        || declaration.lifecycle != "Draft"
        || declaration.authority_kind != "repository-test-fixture-only"
        || declaration.trust_policy_id.is_empty()
        || declaration.trust_policy_epoch == 0
        || declaration.effective_timeline_position != 0
        || declaration.offline_valid_through.is_empty()
        || declaration.fixture_authority_key_id.is_empty()
        || !profiles_are_valid
    {
        return Err(invalid_data("Draft authority declaration is inconsistent"));
    }
    let hex = declaration.fixture_authority_public_key_hex;
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(invalid_data(
            "Draft authority public key must contain 64 ASCII hex digits",
        ));
    }
    let mut key = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| invalid_data("Draft authority public key is not UTF-8"))?;
        key[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| invalid_data("Draft authority public key contains a non-hex digit"))?;
    }
    Ok(key)
}

fn emit_draft_authority(key: [u8; 32]) -> String {
    format!("const DRAFT_AUTHORITY_PUBLIC_KEY_BYTES: [u8; 32] = {key:?};\n")
}

fn emit_byte_constant(
    generated: &mut String,
    name: &str,
    bytes: &[u8],
) -> Result<(), std::fmt::Error> {
    writeln!(generated, "const {name}: &[u8] = &{bytes:?};")
}

fn emit_bundle_contract_assets(snapshots: &SourceSnapshots) -> Result<String, Box<dyn Error>> {
    let mut generated = String::new();
    for (name, relative) in [
        ("EXECUTION_MATRIX_BYTES_V1", "matrix/execution-matrix.json"),
        (
            "AUTHORITY_INVENTORY_BYTES_V1",
            "expected-authority/inventory.json",
        ),
        (
            "DRAFT_AUTHORITY_DECLARATION_BYTES_V1",
            "support/draft-execution-authority.json",
        ),
    ] {
        emit_byte_constant(
            &mut generated,
            name,
            snapshots.bytes(relative, "bundle-contract source")?,
        )?;
    }
    Ok(generated)
}

fn emit_materialization_assets(
    snapshots: &SourceSnapshots,
    key: [u8; 32],
    source_inventory_digest: [u8; 32],
) -> Result<String, Box<dyn Error>> {
    let mut generated = format!(
        "const DRAFT_AUTHORITY_PUBLIC_KEY_BYTES: [u8; 32] = {key:?};\n\
         const SOURCE_INVENTORY_DIGEST: [u8; 32] = {source_inventory_digest:?};\n"
    );
    for (name, relative) in [
        (
            "MATERIALIZATION_AUTHORITY_INVENTORY_BYTES",
            "expected-authority/inventory.json",
        ),
        (
            "MATERIALIZATION_EXECUTION_MATRIX_BYTES",
            "matrix/execution-matrix.json",
        ),
        ("MATERIALIZATION_LICENSE_BYTES", "support/LICENSE"),
        ("MATERIALIZATION_NOTICE_BYTES", "support/NOTICE"),
        (
            "MATERIALIZATION_BUILD_PROVENANCE_BYTES",
            "support/build-provenance.json",
        ),
        (
            "MATERIALIZATION_DRAFT_AUTHORITY_DECLARATION_BYTES",
            "support/draft-execution-authority.json",
        ),
        (
            "MATERIALIZATION_FIXTURE_CONTRACT_POLICY_BYTES",
            "support/fixture-family-contract.json",
        ),
        (
            "MATERIALIZATION_LIMITATIONS_BYTES",
            "support/limitations.md",
        ),
        (
            "MATERIALIZATION_NORMATIVE_REQUIREMENTS_BYTES",
            "support/normative-requirements.md",
        ),
        (
            "MATERIALIZATION_PUBLICATION_REVIEW_BYTES",
            "support/publication-review.json",
        ),
        ("MATERIALIZATION_SBOM_BYTES", "support/sbom.json"),
        (
            "MATERIALIZATION_PROFILE_SCHEMA_BYTES",
            "support/schema-cpf1-v1.cddl",
        ),
        (
            "MATERIALIZATION_SOURCE_PROVENANCE_BYTES",
            "support/source-provenance.json",
        ),
    ] {
        emit_byte_constant(
            &mut generated,
            name,
            snapshots.bytes(relative, "materialization source")?,
        )?;
    }
    Ok(generated)
}

fn emit_rerun_directives(root: &CatalogRoot, snapshots: &SourceSnapshots) {
    let mut paths = BTreeSet::from([root.source.join("profiles"), root.source.join("SHA256SUMS")]);
    paths.extend(
        snapshots
            .sources
            .keys()
            .map(|relative| root.source.join(relative)),
    );
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| invalid_data("CARGO_MANIFEST_DIR is unavailable"))?,
    );
    let root = catalog_root(&manifest_dir)?;
    let snapshots = source_snapshots(&root)?;
    let profiles = discover_profiles(&root, &snapshots)?;
    let source_inventory_digest = verify_source_inventory(&snapshots, &profiles)?;
    let draft_authority_key = draft_authority_public_key(&snapshots)?;
    emit_rerun_directives(&root, &snapshots);
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| invalid_data("OUT_DIR is unavailable"))?,
    );
    std::fs::write(
        out_dir.join("conformance_fixture_catalog.rs"),
        emit_catalog(&profiles)?,
    )?;
    std::fs::write(
        out_dir.join("draft_authority.rs"),
        emit_draft_authority(draft_authority_key),
    )?;
    std::fs::write(
        out_dir.join("bundle_contract_assets.rs"),
        emit_bundle_contract_assets(&snapshots)?,
    )?;
    std::fs::write(
        out_dir.join("materialization_assets.rs"),
        emit_materialization_assets(&snapshots, draft_authority_key, source_inventory_digest)?,
    )?;
    Ok(())
}
