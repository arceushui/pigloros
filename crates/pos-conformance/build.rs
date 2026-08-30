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
#[cfg(target_os = "linux")]
const MAX_SOURCE_FILE_COUNT: usize = 4_096;
#[cfg(target_os = "linux")]
const MAX_SOURCE_FILE_SIZE: u64 = 64 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_SOURCE_TOTAL_SIZE: u64 = 1024 * 1024 * 1024;
const CORE_SOURCE_PATHS: [&str; 3] = [
    "BLAKE3SUMS",
    "expected-authority/inventory.json",
    "matrix/execution-matrix.json",
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
    family_variant: String,
    schema_path: String,
    contract: CatalogFixtureContract,
    strict_oracle: CatalogStrictOracle,
    failure_outcome: CatalogVerificationOutcome,
    replay_claim: CatalogReplayClaim,
    redaction_state: CatalogRedactionState,
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
    claim_layer: String,
    claim_layer_variant: String,
    subject_adapter: CatalogSubjectAdapter,
    profile_record: Vec<u8>,
    fixture_providers: Vec<ProfileFixtureProvider>,
}

struct ProfileFixtureProvider {
    provider: FixtureProvider,
    manifest: FixtureAsset,
    fixtures: Vec<FixturePaths>,
}

struct FixtureFamilyCatalog {
    canonical_order: Vec<String>,
    declarations: BTreeMap<String, FixtureFamilyDeclaration>,
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
    schema_media_type: String,
    payload_media_type: String,
    oracle_media_type: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderArtifactMediaTypes {
    schema: String,
    payload: String,
    oracle: String,
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
struct FixtureFamilyContract {
    magic: String,
    version: u64,
    families: Vec<FixtureFamilyDeclaration>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFamilyDeclaration {
    name: String,
    operation: String,
    oracle: FixtureFamilyOracle,
    failure_outcome: CatalogVerificationOutcome,
    replay_claim: CatalogReplayClaim,
    redaction_state: CatalogRedactionState,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CatalogVerificationOutcome {
    InvalidManifest,
    IncompatibleProfile,
    ResourceLimitExceeded,
}

impl CatalogVerificationOutcome {
    const fn rust_variant(self) -> &'static str {
        match self {
            Self::InvalidManifest => "VerificationOutcomeV1::InvalidManifest",
            Self::IncompatibleProfile => "VerificationOutcomeV1::IncompatibleProfile",
            Self::ResourceLimitExceeded => "VerificationOutcomeV1::ResourceLimitExceeded",
        }
    }
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CatalogReplayClaim {
    Exact,
    ExactAuthoritativeWithRedactedViews,
    IncompatibleProfile,
}

impl CatalogReplayClaim {
    const fn rust_variant(self) -> &'static str {
        match self {
            Self::Exact => "ReplayClaimV1::Exact",
            Self::ExactAuthoritativeWithRedactedViews => {
                "ReplayClaimV1::ExactAuthoritativeWithRedactedViews"
            }
            Self::IncompatibleProfile => "ReplayClaimV1::IncompatibleProfile",
        }
    }
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CatalogRedactionState {
    None,
    RedactedViews,
}

impl CatalogRedactionState {
    const fn rust_variant(self) -> &'static str {
        match self {
            Self::None => "RedactionStateV1::None",
            Self::RedactedViews => "RedactionStateV1::RedactedViews",
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum FixtureFamilyOracle {
    CanonicalOutput,
    NamespacedFailure { code_id: String },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceStatusRecord {
    case_id: String,
    claim_layer: String,
    family: String,
    input_blake3_digest: String,
    status: String,
    execution_result: serde_json::Value,
    executed_at: serde_json::Value,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportPackageManifest {
    magic: String,
    version: u64,
    artifacts: Vec<SupportArtifactDeclaration>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportArtifactDeclaration {
    path: String,
    media_type: String,
    role: SupportArtifactRole,
    provider_package: bool,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SupportArtifactRole {
    NormativeSpecification,
    Schema,
    Licence,
    Notice,
    Sbom,
    Provenance,
    Limitations,
    FixtureContractPolicy,
    AuthorityDeclaration,
}

impl SupportArtifactRole {
    const fn rust_variant(self) -> &'static str {
        match self {
            Self::NormativeSpecification => "BundleMemberRoleV1::NormativeSpecification",
            Self::Schema => "BundleMemberRoleV1::Schema",
            Self::Licence => "BundleMemberRoleV1::Licence",
            Self::Notice => "BundleMemberRoleV1::Notice",
            Self::Sbom => "BundleMemberRoleV1::Sbom",
            Self::Provenance => "BundleMemberRoleV1::Provenance",
            Self::Limitations => "BundleMemberRoleV1::Limitations",
            Self::FixtureContractPolicy => "BundleMemberRoleV1::FixtureContractPolicy",
            Self::AuthorityDeclaration => "BundleMemberRoleV1::AuthorityDeclaration",
        }
    }
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

#[derive(Clone, Copy, Eq, PartialEq, serde::Deserialize)]
enum DraftReproducibilityClass {
    ProfileRecomputation,
    CrossProfileConformance,
}

impl DraftReproducibilityClass {
    const fn wire_code(self) -> u64 {
        match self {
            Self::ProfileRecomputation => 1,
            Self::CrossProfileConformance => 2,
        }
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn rust_enum_variant(
    enum_name: &str,
    catalog_name: &str,
    description: &str,
) -> Result<String, io::Error> {
    let mut variant = String::new();
    for segment in catalog_name.split('-') {
        let Some(first) = segment.chars().next() else {
            return Err(invalid_data(format!(
                "{description} must be lowercase kebab-case: {catalog_name}"
            )));
        };
        if !first.is_ascii_lowercase()
            || !segment
                .chars()
                .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        {
            return Err(invalid_data(format!(
                "{description} must be lowercase kebab-case: {catalog_name}"
            )));
        }
        variant.push(first.to_ascii_uppercase());
        variant.extend(segment.chars().skip(1));
    }
    if variant.is_empty() {
        return Err(invalid_data(format!(
            "{description} must be lowercase kebab-case: {catalog_name}"
        )));
    }
    Ok(format!("{enum_name}::{variant}"))
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
fn fixture_file_size(file: &OwnedFd, relative: &str, description: &str) -> Result<u64, io::Error> {
    let metadata = rustix_fs::fstat(file).map_err(|error| {
        invalid_data(format!(
            "{description} cannot be inspected at {relative}: {error}"
        ))
    })?;
    let size = u64::try_from(metadata.st_size).map_err(|_| {
        invalid_data(format!(
            "{description} has an invalid negative size at {relative}"
        ))
    })?;
    if size > MAX_SOURCE_FILE_SIZE {
        return Err(invalid_data(format!(
            "{description} exceeds the {MAX_SOURCE_FILE_SIZE}-byte source-file limit at {relative}: {size} bytes"
        )));
    }
    Ok(size)
}

#[cfg(target_os = "linux")]
fn read_opened_fixture(
    opened: OwnedFd,
    declared_size: u64,
    relative: &str,
    description: &str,
) -> Result<Vec<u8>, io::Error> {
    let capacity = usize::try_from(declared_size).map_err(|_| {
        invalid_data(format!(
            "{description} size cannot be represented on this platform at {relative}"
        ))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        invalid_data(format!(
            "{description} cannot reserve {capacity} bytes at {relative}: {error}"
        ))
    })?;
    let file: File = opened.into();
    file.take(MAX_SOURCE_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            invalid_data(format!(
                "{description} cannot be read at {relative}: {error}"
            ))
        })?;
    let actual_size = u64::try_from(bytes.len())
        .map_err(|_| invalid_data(format!("{description} is too large at {relative}")))?;
    if actual_size > MAX_SOURCE_FILE_SIZE {
        return Err(invalid_data(format!(
            "{description} grew beyond the {MAX_SOURCE_FILE_SIZE}-byte source-file limit while reading {relative}"
        )));
    }
    if actual_size != declared_size {
        return Err(invalid_data(format!(
            "{description} changed size while reading {relative}: declared {declared_size} bytes, read {actual_size} bytes"
        )));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_fixture_relative(
    root: &CatalogRoot,
    relative: &str,
    description: &str,
) -> Result<Vec<u8>, io::Error> {
    let opened = open_fixture_relative(root, relative, description, false)?;
    let declared_size = fixture_file_size(&opened, relative, description)?;
    read_opened_fixture(opened, declared_size, relative, description)
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

fn expected_source_paths(
    profiles: &[ProfilePaths],
    support: &SupportPackageManifest,
) -> BTreeSet<String> {
    let mut paths: BTreeSet<String> = CORE_SOURCE_PATHS.map(str::to_owned).into_iter().collect();
    paths.extend(
        support
            .artifacts
            .iter()
            .map(|artifact| artifact.path.clone()),
    );
    for profile in profiles {
        paths.insert(profile.profile.clone());
        for provider in &profile.fixture_providers {
            paths.insert(provider.manifest.relative.clone());
            for fixture in &provider.fixtures {
                paths.insert(fixture.schema.relative.clone());
                paths.insert(fixture.input.relative.clone());
                paths.insert(fixture.expected.relative.clone());
                paths.insert(fixture.oracle.relative.clone());
            }
        }
    }
    paths
}

#[cfg(target_os = "linux")]
fn inventoried_sources(
    root: &CatalogRoot,
    entries: &BTreeMap<String, [u8; 32]>,
) -> Result<BTreeMap<String, Vec<u8>>, io::Error> {
    if entries.len() > MAX_SOURCE_FILE_COUNT {
        return Err(invalid_data(format!(
            "SHA-256 source inventory exceeds the {MAX_SOURCE_FILE_COUNT}-file limit: {} files",
            entries.len()
        )));
    }
    let mut declared_total_size = 0_u64;
    for relative in entries.keys() {
        let opened = open_fixture_relative(root, relative, "SHA-256 inventoried source", false)?;
        let declared_size = fixture_file_size(&opened, relative, "SHA-256 inventoried source")?;
        declared_total_size = declared_total_size
            .checked_add(declared_size)
            .ok_or_else(|| invalid_data("SHA-256 inventoried source size total overflowed"))?;
        if declared_total_size > MAX_SOURCE_TOTAL_SIZE {
            return Err(invalid_data(format!(
                "SHA-256 inventoried sources exceed the {MAX_SOURCE_TOTAL_SIZE}-byte cumulative limit"
            )));
        }
    }
    let mut retained_total_size = 0_u64;
    let mut sources = BTreeMap::new();
    for relative in entries.keys() {
        let opened = open_fixture_relative(root, relative, "SHA-256 inventoried source", false)?;
        let declared_size = fixture_file_size(&opened, relative, "SHA-256 inventoried source")?;
        let next_total_size = retained_total_size
            .checked_add(declared_size)
            .ok_or_else(|| invalid_data("SHA-256 inventoried source size total overflowed"))?;
        if next_total_size > MAX_SOURCE_TOTAL_SIZE {
            return Err(invalid_data(format!(
                "SHA-256 inventoried sources exceed the {MAX_SOURCE_TOTAL_SIZE}-byte cumulative limit"
            )));
        }
        let bytes = read_opened_fixture(
            opened,
            declared_size,
            relative,
            "SHA-256 inventoried source",
        )?;
        retained_total_size = next_total_size;
        sources.insert(relative.clone(), bytes);
    }
    Ok(sources)
}

#[cfg(not(target_os = "linux"))]
fn inventoried_sources(
    root: &CatalogRoot,
    entries: &BTreeMap<String, [u8; 32]>,
) -> Result<BTreeMap<String, Vec<u8>>, io::Error> {
    entries
        .keys()
        .map(|relative| {
            read_fixture_relative(root, relative, "SHA-256 inventoried source")
                .map(|bytes| (relative.clone(), bytes))
        })
        .collect()
}

fn source_snapshots(root: &CatalogRoot) -> Result<SourceSnapshots, io::Error> {
    let sha256_bytes = read_fixture_relative(root, "SHA256SUMS", "SHA-256 source inventory")?;
    let sha256_entries = checksum_manifest(&sha256_bytes, "SHA-256 source inventory")?;
    if sha256_entries.contains_key("SHA256SUMS") {
        return Err(invalid_data(
            "SHA-256 source inventory must not declare itself",
        ));
    }
    let sources = inventoried_sources(root, &sha256_entries)?;
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
    let support = support_package_manifest(snapshots)?;
    let expected_paths = expected_source_paths(profiles, &support);
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
    let contracts = json_field(provider, "fixture_contracts")?.as_object();
    let contracts_match_families = schemas.zip(contracts).is_some_and(|(schemas, contracts)| {
        let schema_families = schemas.keys().collect::<BTreeSet<_>>();
        let contract_families = contracts.keys().collect::<BTreeSet<_>>();
        schemas.len() == FIXTURES_PER_PROFILE
            && contracts.len() == FIXTURES_PER_PROFILE
            && schema_families == contract_families
    });
    let media_types: ProviderArtifactMediaTypes = serde_json::from_value(
        json_field(provider, "artifact_media_types")?.clone(),
    )
    .map_err(|error| {
        invalid_data(format!(
            "provider artifact media types are invalid: {error}"
        ))
    })?;
    let valid = !json_text(provider, "provider_id")?.is_empty()
        && !json_text(provider, "contract_version")?.is_empty()
        && u16::try_from(json_u64(provider, "abi_major")?).is_ok()
        && u16::try_from(json_u64(provider, "abi_minor")?).is_ok()
        && !json_text(provider, "package_path")?.is_empty()
        && valid_media_type(&media_types.schema)
        && valid_media_type(&media_types.payload)
        && valid_media_type(&media_types.oracle)
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

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$&^_.+-/".contains(&byte)
        })
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty() && !subtype.is_empty() && !subtype.contains('/')
        })
}

fn validate_evidence_status(
    fixture: &Value,
    input_bytes: &[u8],
    expected_bytes: &[u8],
    claim_layer: &str,
) -> Result<(), io::Error> {
    let case_id = json_text(fixture, "case_id")?;
    let family = json_text(fixture, "family")?;
    if json_text(fixture, "claim_layer")? != claim_layer {
        return Err(invalid_data(format!(
            "fixture {case_id} claim layer does not match its profile"
        )));
    }
    let evidence: EvidenceStatusRecord =
        serde_json::from_slice(expected_bytes).map_err(|error| {
            invalid_data(format!(
                "fixture {case_id} evidence status is invalid: {error}"
            ))
        })?;
    let input_digest = blake3::hash(input_bytes).to_hex().to_string();
    let identity_matches = evidence.case_id == case_id
        && evidence.claim_layer == claim_layer
        && evidence.family == family
        && evidence.input_blake3_digest == input_digest
        && evidence.status == "pending"
        && evidence.execution_result == Value::Null
        && evidence.executed_at == Value::Null;
    if identity_matches {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "fixture {case_id} evidence status does not match its profile identity"
        )))
    }
}

fn fixture_family_contract(snapshots: &SourceSnapshots) -> Result<FixtureFamilyCatalog, io::Error> {
    let bytes = snapshots.bytes(
        "support/fixture-family-contract.json",
        "fixture-family contract",
    )?;
    let contract: FixtureFamilyContract = serde_json::from_slice(bytes)
        .map_err(|error| invalid_data(format!("fixture-family contract is invalid: {error}")))?;
    if contract.magic != "FFM1" || contract.version != 1 {
        return Err(invalid_data(
            "fixture-family contract version is unsupported",
        ));
    }
    if contract.families.len() == FIXTURES_PER_PROFILE {
        let mut canonical_order = Vec::with_capacity(FIXTURES_PER_PROFILE);
        let mut declarations = BTreeMap::new();
        for family in contract.families {
            let family_name = family.name.clone();
            if declarations.insert(family_name.clone(), family).is_some() {
                return Err(invalid_data(
                    "fixture-family contract contains duplicate family names",
                ));
            }
            canonical_order.push(family_name);
        }
        Ok(FixtureFamilyCatalog {
            canonical_order,
            declarations,
        })
    } else {
        Err(invalid_data(
            "fixture-family contract must declare exactly seven families",
        ))
    }
}

fn strict_oracle(
    family: &FixtureFamilyDeclaration,
    provider: &FixtureProvider,
) -> Result<CatalogStrictOracle, io::Error> {
    let operation_valid = matches!(family.operation.as_str(), "required" | "optional");
    if !operation_valid {
        return Err(invalid_data("fixture-family operation policy is invalid"));
    }
    Ok(match &family.oracle {
        FixtureFamilyOracle::CanonicalOutput => CatalogStrictOracle::CanonicalOutput,
        FixtureFamilyOracle::NamespacedFailure { code_id } => {
            CatalogStrictOracle::NamespacedFailure {
                owner_id: provider.provider_id.clone(),
                contract_version: provider.contract_version.clone(),
                code_id: code_id.clone(),
            }
        }
    })
}

fn fixture_contract(provider: &Value, family: &str) -> Result<CatalogFixtureContract, io::Error> {
    let contract = json_field(provider, "fixture_contracts")?
        .get(family)
        .ok_or_else(|| invalid_data(format!("provider omits contract for {family}")))?;
    serde_json::from_value(contract.clone()).map_err(|error| {
        invalid_data(format!(
            "provider contract for {family} is invalid: {error}"
        ))
    })
}

fn fixture_provider(provider: &Value) -> Result<FixtureProvider, io::Error> {
    let abi_major = u16::try_from(json_u64(provider, "abi_major")?)
        .map_err(|_| invalid_data("provider abi_major must fit u16"))?;
    let abi_minor = u16::try_from(json_u64(provider, "abi_minor")?)
        .map_err(|_| invalid_data("provider abi_minor must fit u16"))?;
    let media_types: ProviderArtifactMediaTypes = serde_json::from_value(
        json_field(provider, "artifact_media_types")?.clone(),
    )
    .map_err(|error| {
        invalid_data(format!(
            "provider artifact media types are invalid: {error}"
        ))
    })?;
    Ok(FixtureProvider {
        provider_id: json_text(provider, "provider_id")?,
        contract_version: json_text(provider, "contract_version")?,
        abi_major,
        abi_minor,
        package_path: json_text(provider, "package_path")?,
        schema_media_type: media_types.schema,
        payload_media_type: media_types.payload,
        oracle_media_type: media_types.oracle,
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
    fixtures: &[&Value],
    provider_value: &Value,
    provider: &FixtureProvider,
    provider_schemas: &serde_json::Map<String, Value>,
    family_contract: &FixtureFamilyCatalog,
    claim_layer: &str,
) -> Result<Vec<FixturePaths>, io::Error> {
    fixtures
        .iter()
        .zip(&family_contract.canonical_order)
        .map(|(fixture, expected_family)| {
            let case_id = json_text(fixture, "case_id")?;
            let family = json_text(fixture, "family")?;
            if family != expected_family.as_str() {
                return Err(invalid_data(format!(
                    "profile fixture {case_id} is not in canonical family order"
                )));
            }
            let family_variant =
                rust_enum_variant("FixtureFamilyV1", &family, "profile fixture family")?;
            let schema_path = json_text(fixture, "schema")?;
            let schema = relative_asset(snapshots, fixture, "schema")?;
            let expected_schema = provider_schemas
                .get(&family)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid_data(format!("provider manifest is missing schema {family}"))
                })?;
            if schema.relative != expected_schema {
                return Err(invalid_data(format!(
                    "profile fixture schema does not match family {family}"
                )));
            }
            let input = relative_asset(snapshots, fixture, "input")?;
            let expected = relative_asset(snapshots, fixture, "expected")?;
            let oracle = relative_asset(snapshots, fixture, "oracle")?;
            validate_evidence_status(fixture, &input.bytes, &expected.bytes, claim_layer)?;
            let family_declaration = family_contract
                .declarations
                .get(&family)
                .ok_or_else(|| invalid_data(format!("fixture-family contract omits {family}")))?;
            Ok(FixturePaths {
                case_id,
                family_variant,
                schema_path,
                contract: fixture_contract(provider_value, &family)?,
                strict_oracle: strict_oracle(family_declaration, provider)?,
                failure_outcome: family_declaration.failure_outcome,
                replay_claim: family_declaration.replay_claim,
                redaction_state: family_declaration.redaction_state,
                schema,
                input,
                expected,
                oracle,
            })
        })
        .collect()
}

struct ProfileFixtureContext<'a> {
    snapshots: &'a SourceSnapshots,
    family_contract: &'a FixtureFamilyCatalog,
    profile: &'a str,
    claim_layer: &'a str,
    subject_adapter: &'a str,
    fixtures_by_case_id: &'a BTreeMap<String, &'a Value>,
}

fn profile_fixture_provider(
    context: &ProfileFixtureContext<'_>,
    declaration: &Value,
    assigned_case_ids: &mut BTreeSet<String>,
) -> Result<ProfileFixtureProvider, io::Error> {
    let manifest = relative_asset(context.snapshots, declaration, "manifest")?;
    let provider_value: Value = serde_json::from_slice(&manifest.bytes).map_err(|error| {
        invalid_data(format!(
            "fixture provider manifest {} is invalid: {error}",
            manifest.relative
        ))
    })?;
    validate_fixture_provider(
        &provider_value,
        context.claim_layer,
        context.subject_adapter,
    )?;
    let provider = fixture_provider(&provider_value)?;
    let provider_schemas = json_field(&provider_value, "schemas")?
        .as_object()
        .ok_or_else(|| invalid_data("provider manifest schemas must be an object"))?;
    let fixture_case_ids = json_field(declaration, "fixture_case_ids")?
        .as_array()
        .ok_or_else(|| invalid_data("fixture provider fixture_case_ids must be an array"))?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                invalid_data("fixture provider fixture_case_ids must contain strings")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fixture_case_ids.len() != FIXTURES_PER_PROFILE {
        return Err(invalid_data(format!(
            "profile manifest {} provider {} must declare exactly {FIXTURES_PER_PROFILE} fixtures, found {}",
            context.profile,
            provider.provider_id,
            fixture_case_ids.len()
        )));
    }
    let fixtures = fixture_case_ids
        .iter()
        .map(|case_id| {
            if !assigned_case_ids.insert(case_id.clone()) {
                return Err(invalid_data(format!(
                    "profile manifest {} assigns fixture {case_id} to multiple providers",
                    context.profile
                )));
            }
            context
                .fixtures_by_case_id
                .get(case_id)
                .copied()
                .ok_or_else(|| {
                    invalid_data(format!(
                        "profile manifest {} provider {} references undeclared fixture {case_id}",
                        context.profile, provider.provider_id
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    profile_fixtures(
        context.snapshots,
        &fixtures,
        &provider_value,
        &provider,
        provider_schemas,
        context.family_contract,
        context.claim_layer,
    )
    .map(|fixtures| ProfileFixtureProvider {
        provider,
        manifest,
        fixtures,
    })
}

fn profile_fixture_providers(
    snapshots: &SourceSnapshots,
    family_contract: &FixtureFamilyCatalog,
    profile: &str,
    claim_layer: &str,
    subject_adapter: &str,
    provider_declarations: &[Value],
    fixture_records: &[Value],
) -> Result<Vec<ProfileFixtureProvider>, io::Error> {
    if provider_declarations.is_empty() {
        return Err(invalid_data(
            "profile catalog fixture_providers must not be empty",
        ));
    }
    let fixtures_by_case_id = fixture_records
        .iter()
        .map(|fixture| json_text(fixture, "case_id").map(|case_id| (case_id, fixture)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if fixtures_by_case_id.len() != fixture_records.len() {
        return Err(invalid_data(format!(
            "profile manifest {profile} contains duplicate fixture case IDs"
        )));
    }
    let mut assigned_case_ids = BTreeSet::new();
    let context = ProfileFixtureContext {
        snapshots,
        family_contract,
        profile,
        claim_layer,
        subject_adapter,
        fixtures_by_case_id: &fixtures_by_case_id,
    };
    let fixture_providers = provider_declarations
        .iter()
        .map(|declaration| profile_fixture_provider(&context, declaration, &mut assigned_case_ids))
        .collect::<Result<Vec<_>, _>>()?;
    if assigned_case_ids.len() != fixture_records.len() {
        return Err(invalid_data(format!(
            "profile manifest {profile} has fixtures that are not owned by a declared provider"
        )));
    }
    let mut provider_keys = fixture_providers
        .iter()
        .map(|entry| {
            (
                entry.provider.provider_id.as_str(),
                entry.provider.contract_version.as_str(),
                entry.provider.abi_major,
                entry.provider.abi_minor,
            )
        })
        .collect::<Vec<_>>();
    let declared_provider_keys = provider_keys.clone();
    provider_keys.sort_unstable();
    provider_keys.dedup();
    if provider_keys.len() != fixture_providers.len() {
        return Err(invalid_data(format!(
            "profile manifest {profile} contains duplicate fixture provider keys"
        )));
    }
    if provider_keys != declared_provider_keys {
        return Err(invalid_data(format!(
            "profile manifest {profile} fixture providers are not in canonical provider-key order"
        )));
    }
    Ok(fixture_providers)
}

fn profile_paths(
    snapshots: &SourceSnapshots,
    family_contract: &FixtureFamilyCatalog,
    profile: String,
) -> Result<ProfilePaths, Box<dyn Error>> {
    let profile_record = snapshots.bytes(&profile, "profile manifest")?.to_vec();
    let profile_value: Value = serde_json::from_slice(&profile_record)?;
    let profile_id = json_text(&profile_value, "profile_id")?;
    let claim_layer = json_text(&profile_value, "claim_layer")?;
    let claim_layer_variant =
        rust_enum_variant("ClaimLayerV1", &claim_layer, "profile claim layer")?;
    let subject_adapter = json_text(&profile_value, "subject_adapter")?;
    let catalog_subject_adapter = CatalogSubjectAdapter::from_catalog_name(&subject_adapter)?;
    let fixture_root = json_text(&profile_value, "fixture_root")?;
    let provider_declarations = json_field(&profile_value, "fixture_providers")?
        .as_array()
        .ok_or_else(|| invalid_data("profile catalog fixture_providers must be an array"))?;
    let wire_code = json_field(&profile_value, "wire_code")?
        .as_u64()
        .ok_or_else(|| invalid_data("profile catalog wire_code must be unsigned"))?;
    let fixture_records = json_field(&profile_value, "fixtures")?
        .as_array()
        .ok_or_else(|| invalid_data("profile catalog fixtures must be an array"))?;
    let fixture_providers = profile_fixture_providers(
        snapshots,
        family_contract,
        &profile,
        &claim_layer,
        &subject_adapter,
        provider_declarations,
        fixture_records,
    )?;
    let bundle_modes = json_field(&profile_value, "bundle_modes")?;
    let execution_profiles = json_field(&profile_value, "execution_profiles")?;
    if fixture_root != claim_layer {
        return Err(invalid_data(format!(
            "profile manifest {profile} fixture_root must match claim_layer {claim_layer}, found {fixture_root}"
        ))
        .into());
    }
    let expected_bundle_modes = serde_json::json!(["local", "air-gapped"]);
    if bundle_modes != &expected_bundle_modes {
        return Err(invalid_data(format!(
            "profile manifest {profile} bundle_modes must be {expected_bundle_modes}, found {bundle_modes}"
        ))
        .into());
    }
    let expected_execution_profiles =
        serde_json::json!(["deterministic-local-v1", "deterministic-air-gapped-v1"]);
    if execution_profiles != &expected_execution_profiles {
        return Err(invalid_data(format!(
            "profile manifest {profile} execution_profiles must be {expected_execution_profiles}, found {execution_profiles}"
        ))
        .into());
    }
    Ok(ProfilePaths {
        wire_code,
        profile,
        profile_id,
        claim_layer,
        claim_layer_variant,
        subject_adapter: catalog_subject_adapter,
        profile_record,
        fixture_providers,
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
    let family_contract = fixture_family_contract(snapshots)?;
    if profile_manifests.len() != PROFILE_COUNT {
        return Err(invalid_data(format!(
            "profile root must contain exactly {PROFILE_COUNT} profile directories, found {}",
            profile_manifests.len()
        ))
        .into());
    }
    let mut profiles = profile_manifests
        .into_iter()
        .map(|profile| profile_paths(snapshots, &family_contract, profile))
        .collect::<Result<Vec<_>, _>>()?;
    profiles.sort_unstable_by_key(|profile| profile.wire_code);
    if profiles
        .iter()
        .enumerate()
        .any(|(index, profile)| profile.wire_code != index as u64)
    {
        return Err(invalid_data(
            "profile catalog wire codes must cover the canonical range zero through six",
        )
        .into());
    }
    let claim_layers = profiles
        .iter()
        .map(|profile| profile.claim_layer.as_str())
        .collect::<BTreeSet<_>>();
    if claim_layers.len() != profiles.len() {
        return Err(invalid_data("profile catalog claim layers must be unique").into());
    }
    let profile_ids = profiles
        .iter()
        .map(|profile| profile.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    if profile_ids.len() != profiles.len() {
        return Err(invalid_data("profile catalog profile IDs must be unique").into());
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
        rust_u64_literal(budget.memory_bytes)
    )?;
    writeln!(
        generated,
        "                                cpu_fuel: {},",
        rust_u64_literal(budget.cpu_fuel)
    )?;
    writeln!(
        generated,
        "                                host_calls: {},",
        rust_u64_literal(budget.host_calls)
    )?;
    writeln!(
        generated,
        "                                event_count: {},",
        rust_u64_literal(budget.event_count)
    )?;
    writeln!(
        generated,
        "                                output_bytes: {},",
        rust_u64_literal(budget.output_bytes)
    )?;
    writeln!(
        generated,
        "                                storage_bytes: {},",
        rust_u64_literal(budget.storage_bytes)
    )?;
    writeln!(
        generated,
        "                                execution_steps: {},",
        rust_u64_literal(budget.execution_steps)
    )?;
    writeln!(
        generated,
        "                                simulation_time_ns: {},",
        rust_u64_literal(budget.simulation_time_ns)
    )?;
    writeln!(generated, "                            }},")?;
    writeln!(
        generated,
        "                            watchdog_ms: {},",
        rust_u64_literal(fixture.contract.watchdog_ms)
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

fn rust_u64_literal(value: u64) -> String {
    let digits = value.to_string();
    let mut literal = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            literal.push('_');
        }
        literal.push(digit);
    }
    literal
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

fn emit_fixture(
    generated: &mut String,
    fixture: &FixturePaths,
    fixture_index: usize,
) -> Result<(), std::fmt::Error> {
    writeln!(
        generated,
        "const fn catalog_fixture_{fixture_index}() -> CatalogFixture {{"
    )?;
    writeln!(generated, "                    CatalogFixture {{")?;
    writeln!(
        generated,
        "                        case_id: {:?},",
        fixture.case_id
    )?;
    writeln!(
        generated,
        "                        family: {},",
        fixture.family_variant
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
    writeln!(
        generated,
        "                        failure_outcome: {},",
        fixture.failure_outcome.rust_variant()
    )?;
    writeln!(
        generated,
        "                        replay_claim: {},",
        fixture.replay_claim.rust_variant()
    )?;
    writeln!(
        generated,
        "                        redaction_state: {},",
        fixture.redaction_state.rust_variant()
    )?;
    writeln!(generated, "                    }}\n}}")
}

fn emit_profile(
    generated: &mut String,
    profile: &ProfilePaths,
    profile_index: usize,
    first_fixture_index: usize,
) -> Result<(), std::fmt::Error> {
    writeln!(
        generated,
        "fn catalog_profile_{profile_index}() -> LayerCatalogEntry {{"
    )?;
    writeln!(generated, "            LayerCatalogEntry {{")?;
    writeln!(
        generated,
        "                claim_layer: {},",
        profile.claim_layer_variant
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
        "                profile_record: &{:?},",
        profile.profile_record
    )?;
    writeln!(generated, "                fixture_providers: vec![")?;
    let mut fixture_index = first_fixture_index;
    for entry in &profile.fixture_providers {
        writeln!(generated, "                    CatalogFixtureProvider {{")?;
        writeln!(
            generated,
            "                        provider: FixtureProvider {{"
        )?;
        writeln!(
            generated,
            "                            provider_id: {:?},",
            entry.provider.provider_id
        )?;
        writeln!(
            generated,
            "                            contract_version: {:?},",
            entry.provider.contract_version
        )?;
        writeln!(
            generated,
            "                            abi_major: {},",
            entry.provider.abi_major
        )?;
        writeln!(
            generated,
            "                            abi_minor: {},",
            entry.provider.abi_minor
        )?;
        writeln!(
            generated,
            "                            package_path: {:?},",
            entry.provider.package_path
        )?;
        writeln!(
            generated,
            "                            schema_media_type: {:?},",
            entry.provider.schema_media_type
        )?;
        writeln!(
            generated,
            "                            payload_media_type: {:?},",
            entry.provider.payload_media_type
        )?;
        writeln!(
            generated,
            "                            oracle_media_type: {:?},",
            entry.provider.oracle_media_type
        )?;
        writeln!(generated, "                        }},")?;
        writeln!(generated, "                        fixtures: vec![")?;
        for current_index in fixture_index..fixture_index + entry.fixtures.len() {
            writeln!(
                generated,
                "                            catalog_fixture_{current_index}(),"
            )?;
        }
        fixture_index += entry.fixtures.len();
        writeln!(generated, "                        ],")?;
        writeln!(generated, "                    }},")?;
    }
    writeln!(generated, "                ],")?;
    writeln!(generated, "            }}\n}}")
}

fn emit_catalog(profiles: &[ProfilePaths]) -> Result<String, std::fmt::Error> {
    let mut generated = String::new();
    let mut fixture_index = 0;
    for profile in profiles {
        for provider in &profile.fixture_providers {
            for fixture in &provider.fixtures {
                emit_fixture(&mut generated, fixture, fixture_index)?;
                fixture_index += 1;
            }
        }
    }
    let mut first_fixture_index = 0;
    for (profile_index, profile) in profiles.iter().enumerate() {
        emit_profile(&mut generated, profile, profile_index, first_fixture_index)?;
        first_fixture_index += profile
            .fixture_providers
            .iter()
            .map(|provider| provider.fixtures.len())
            .sum::<usize>();
    }
    generated.push_str(
        "fn layer_catalog() -> LayerCatalog {\n    LayerCatalog {\n        entries: vec![\n",
    );
    for profile_index in 0..profiles.len() {
        writeln!(generated, "            catalog_profile_{profile_index}(),")?;
    }
    generated.push_str("        ],\n    }\n}\n");
    Ok(generated)
}

fn draft_authority(
    snapshots: &SourceSnapshots,
) -> Result<(DraftAuthorityDeclaration, [u8; 32]), io::Error> {
    let relative = "support/draft-execution-authority.json";
    let bytes = snapshots.bytes(relative, "Draft authority declaration")?;
    let declaration: DraftAuthorityDeclaration =
        serde_json::from_slice(bytes).map_err(|error| {
            invalid_data(format!(
                "Draft authority declaration is invalid at {relative}: {error}"
            ))
        })?;
    let declared_profile_ids = declaration
        .execution_profiles
        .iter()
        .map(|profile| profile.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    let profiles_are_valid = declared_profile_ids
        == BTreeSet::from(["deterministic-air-gapped-v1", "deterministic-local-v1"])
        && declaration.execution_profiles.iter().all(|profile| {
            !profile.profile_id.is_empty()
                && !profile.semantic_version.is_empty()
                && !profile.network_allowed
                && profile.capability_ids.is_empty()
                && profile.reproducibility_classes
                    == [
                        DraftReproducibilityClass::ProfileRecomputation,
                        DraftReproducibilityClass::CrossProfileConformance,
                    ]
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
    let hex = &declaration.fixture_authority_public_key_hex;
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
    Ok((declaration, key))
}

fn emit_draft_authority(
    declaration: &DraftAuthorityDeclaration,
    key: [u8; 32],
) -> Result<String, std::fmt::Error> {
    let mut generated = format!(
        "const DRAFT_AUTHORITY_PUBLIC_KEY_BYTES: [u8; 32] = {key:?};\n\
         const DRAFT_AUTHORITY_TRUST_POLICY_ID: &str = {:?};\n\
         const DRAFT_AUTHORITY_TRUST_POLICY_EPOCH: u64 = {};\n\
         const DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION: u64 = {};\n\
         const DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH: &str = {:?};\n\
         const DRAFT_AUTHORITY_KEY_ID: &str = {:?};\n",
        declaration.trust_policy_id,
        declaration.trust_policy_epoch,
        declaration.effective_timeline_position,
        declaration.offline_valid_through,
        declaration.fixture_authority_key_id,
    );
    writeln!(
        generated,
        "struct DraftExecutionProfileSource {{\n\
             profile_id: &'static str,\n\
             semantic_version: &'static str,\n\
             network_allowed: bool,\n\
             capability_ids: &'static [&'static str],\n\
             reproducibility_classes: &'static [u64],\n\
         }}\n\
         const DRAFT_EXECUTION_PROFILES: [DraftExecutionProfileSource; {}] = [",
        declaration.execution_profiles.len()
    )?;
    for profile in &declaration.execution_profiles {
        let capabilities = profile
            .capability_ids
            .iter()
            .map(|capability| format!("{capability:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let classes = profile
            .reproducibility_classes
            .iter()
            .copied()
            .map(DraftReproducibilityClass::wire_code)
            .map(|code| code.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            generated,
            "    DraftExecutionProfileSource {{ profile_id: {:?}, semantic_version: {:?}, network_allowed: {}, capability_ids: &[{}], reproducibility_classes: &[{}] }},",
            profile.profile_id,
            profile.semantic_version,
            profile.network_allowed,
            capabilities,
            classes,
        )?;
    }
    generated.push_str("];\n");
    Ok(generated)
}

fn emit_byte_constant(
    generated: &mut String,
    name: &str,
    bytes: &[u8],
) -> Result<(), std::fmt::Error> {
    writeln!(generated, "const {name}: &[u8] = &{bytes:?};")
}

fn support_constant_name(path: &str) -> String {
    let mut name = String::from("MATERIALIZATION_");
    for character in path.chars() {
        if character.is_ascii_alphanumeric() {
            name.push(character.to_ascii_uppercase());
        } else {
            name.push('_');
        }
    }
    name.push_str("_BYTES");
    name
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
        (
            "SUPPORT_PACKAGE_MANIFEST_BYTES_V1",
            "support/package-manifest.json",
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

fn support_package_manifest(
    snapshots: &SourceSnapshots,
) -> Result<SupportPackageManifest, io::Error> {
    let manifest: SupportPackageManifest = serde_json::from_slice(
        snapshots.bytes("support/package-manifest.json", "support package manifest")?,
    )
    .map_err(|error| invalid_data(format!("support package manifest is invalid: {error}")))?;
    let declared = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    let inventoried_support = snapshots
        .sha256_entries
        .keys()
        .filter(|path| path.starts_with("support/"))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let records_are_valid = manifest.artifacts.iter().all(|artifact| {
        valid_media_type(&artifact.media_type)
            && artifact.path.starts_with("support/")
            && !artifact.path.contains("..")
    });
    let records_are_ordered = manifest
        .artifacts
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path);
    if manifest.magic == "SPM1"
        && manifest.version == 1
        && declared.len() == manifest.artifacts.len()
        && declared == inventoried_support
        && records_are_valid
        && records_are_ordered
    {
        Ok(manifest)
    } else {
        Err(invalid_data("support package manifest is inconsistent"))
    }
}

fn emit_materialization_assets(
    snapshots: &SourceSnapshots,
    draft_authority: &DraftAuthorityDeclaration,
    key: [u8; 32],
    source_inventory_digest: [u8; 32],
) -> Result<String, Box<dyn Error>> {
    let mut generated = emit_draft_authority(draft_authority, key)?;
    writeln!(
        generated,
        "const SOURCE_INVENTORY_DIGEST: [u8; 32] = {source_inventory_digest:?};"
    )?;
    for (name, relative) in [
        (
            "MATERIALIZATION_AUTHORITY_INVENTORY_BYTES",
            "expected-authority/inventory.json",
        ),
        (
            "MATERIALIZATION_EXECUTION_MATRIX_BYTES",
            "matrix/execution-matrix.json",
        ),
    ] {
        emit_byte_constant(
            &mut generated,
            name,
            snapshots.bytes(relative, "materialization source")?,
        )?;
    }
    generated.push_str(
        "struct MaterializationSupportArtifact {\n\
             path: &'static str,\n\
             media_type: &'static str,\n\
             bytes: &'static [u8],\n\
             role: BundleMemberRoleV1,\n\
             provider_package: bool,\n\
         }\n",
    );
    let support = support_package_manifest(snapshots)?;
    for artifact in &support.artifacts {
        emit_byte_constant(
            &mut generated,
            &support_constant_name(&artifact.path),
            snapshots.bytes(&artifact.path, "support package artifact")?,
        )?;
    }
    writeln!(
        generated,
        "const MATERIALIZATION_SUPPORT_ARTIFACTS: [MaterializationSupportArtifact; {}] = [",
        support.artifacts.len()
    )?;
    for artifact in support.artifacts {
        let bytes_constant = support_constant_name(&artifact.path);
        writeln!(
            generated,
            "    MaterializationSupportArtifact {{ path: {:?}, media_type: {:?}, bytes: {bytes_constant}, role: {}, provider_package: {} }},",
            artifact.path,
            artifact.media_type,
            artifact.role.rust_variant(),
            artifact.provider_package,
        )?;
    }
    generated.push_str("];\n");
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
    let (draft_authority, draft_authority_key) = draft_authority(&snapshots)?;
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
        emit_draft_authority(&draft_authority, draft_authority_key)?,
    )?;
    std::fs::write(
        out_dir.join("bundle_contract_assets.rs"),
        emit_bundle_contract_assets(&snapshots)?,
    )?;
    std::fs::write(
        out_dir.join("materialization_assets.rs"),
        emit_materialization_assets(
            &snapshots,
            &draft_authority,
            draft_authority_key,
            source_inventory_digest,
        )?,
    )?;
    Ok(())
}
