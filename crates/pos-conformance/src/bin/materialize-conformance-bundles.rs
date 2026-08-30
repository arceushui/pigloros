#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    expected_result_member_path, verify_archive_release_filename,
    verify_release_tree_independently, ArtifactDescriptorV1, BundleExpectedResultV1,
    BundleMemberRoleV1, BundleMemberV1, BundleModeV1, CapabilityPolicyV1, ClaimLayerV1,
    ConformanceBundlePairV1, ConformanceBundleV1, ConformanceProfileV1, DeterministicBudgetV1,
    EvaluatorHardCapsV1, EvaluatorProtocolV1, FixtureContractTransitionV1, FixtureDescriptorV1,
    FixtureFamilyV1, FixtureProvenanceV1, FixtureProviderEntryV1, FixtureProviderKeyV1,
    FixtureProviderPackageV1, FixtureProviderRegistryBindingV1, FixtureProviderRegistryV1,
    IndependenceRequirementsV1, NamespacedFailureV1, OperationalSafetyV1, ProfileLifecycleV1,
    ProviderFamilySchemaV1, RedactionStateV1, ReplayClaimV1, StrictOracleKindV1, StrictOracleV1,
    SubjectAdapterKindV1, VerificationOutcomeV1, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
};
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error as ThisError;

include!("materialize-conformance-bundles/atomic_publication.rs");

const MATERIALIZATION_METADATA_PATH: &str = "MATERIALIZATION-METADATA.json";
const OUTPUT_CHECKSUM_INVENTORY_PATH: &str = "SHA256SUMS";
#[derive(Clone, Copy)]
struct FixtureContext {
    claim_layer: ClaimLayerV1,
    profile_record_digest: [u8; 32],
    source_provenance_digest: [u8; 32],
    build_provenance_digest: [u8; 32],
    publication_review_digest: [u8; 32],
    notice_digest: [u8; 32],
    sbom_digest: [u8; 32],
    limitations_digest: [u8; 32],
    normative_spec_digest: [u8; 32],
}

struct MaterializationContext<'a> {
    signing_key: &'a SigningKey,
    inventory_bytes: &'a [u8],
    providers: &'a ProviderCatalog,
}

#[derive(Clone)]
struct MaterializedFile {
    relative_path: String,
    bytes: Vec<u8>,
    archive_release_filename: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
enum MaterializationCommand {
    Publish(PathBuf),
    Fingerprint,
}

enum PreparedMaterializationCommand {
    Publish(AtomicPublication),
    Fingerprint,
}

#[derive(Debug, ThisError)]
enum MaterializationError {
    #[error("destination already exists")]
    DestinationExists,
    #[error("untrusted output directory")]
    UntrustedOutputDirectory,
    #[error("symbolic link detected in output path")]
    SymlinkDetected,
    #[error("atomic publication is unsupported")]
    AtomicPublicationUnsupported,
    #[error("durability synchronization failed")]
    DurabilitySyncFailed,
    #[error("staged archive digest mismatch")]
    ArchiveDigestMismatch,
    #[error("destination is not addressed by the source inventory digest")]
    SourceInventoryAddressMismatch,
}

#[derive(Clone, Copy)]
struct FixtureSource {
    schema: &'static [u8],
    input: &'static [u8],
    expected: &'static [u8],
    oracle: &'static [u8],
}

struct LayerSource {
    profile_record: &'static [u8],
    provider_record: &'static [u8],
    fixtures: &'static [FixtureSource],
}

include!(concat!(env!("OUT_DIR"), "/conformance_fixture_catalog.rs"));
include!(concat!(env!("OUT_DIR"), "/draft_authority.rs"));

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum CatalogExecutionProfile {
    DeterministicLocalV1,
    DeterministicAirGappedV1,
}

impl CatalogExecutionProfile {
    const ALL: [Self; 2] = [Self::DeterministicLocalV1, Self::DeterministicAirGappedV1];

    const fn name(self) -> &'static str {
        match self {
            Self::DeterministicLocalV1 => "deterministic-local-v1",
            Self::DeterministicAirGappedV1 => "deterministic-air-gapped-v1",
        }
    }

    fn digest(self) -> Result<[u8; 32], Box<dyn Error>> {
        execution_profile_bytes(self).map(|bytes| *blake3::hash(&bytes).as_bytes())
    }

    const fn execution_mode(self) -> pos_conformance::ExecutionModeV1 {
        match self {
            Self::DeterministicLocalV1 => pos_conformance::ExecutionModeV1::Local,
            Self::DeterministicAirGappedV1 => pos_conformance::ExecutionModeV1::AirGapped,
        }
    }
}

// This seed is repository test-fixture authority only.  It is never a
// deployment trust root and is used solely to make Draft evidence reproducible.
const DRAFT_FIXTURE_AUTHORITY_SIGNING_BYTES: [u8; 32] = [7; 32];

#[derive(Deserialize)]
struct DraftAuthorityDeclaration {
    trust_policy_id: String,
    trust_policy_epoch: u64,
    effective_timeline_position: u64,
    offline_valid_through: String,
    fixture_authority_key_id: String,
    execution_profiles: Vec<DraftExecutionProfileDeclaration>,
}

#[derive(Deserialize)]
struct DraftExecutionProfileDeclaration {
    profile_id: String,
    semantic_version: String,
    network_allowed: bool,
    capability_ids: Vec<String>,
    reproducibility_classes: Vec<DraftReproducibilityClass>,
}

#[derive(Clone, Copy, Deserialize)]
enum DraftReproducibilityClass {
    ProfileRecomputation,
    CrossProfileConformance,
}

impl DraftReproducibilityClass {
    fn value(self) -> Value {
        match self {
            Self::ProfileRecomputation => Value::Integer(1_u64.into()),
            Self::CrossProfileConformance => Value::Integer(2_u64.into()),
        }
    }
}

fn draft_authority() -> Result<DraftAuthorityDeclaration, Box<dyn Error>> {
    serde_json::from_slice(include_bytes!(
        "../../../../fixtures/conformance/support/draft-execution-authority.json"
    ))
    .map_err(Into::into)
}

fn authority_signing_key(expected_public_key: [u8; 32]) -> Result<SigningKey, Box<dyn Error>> {
    let key = SigningKey::from_bytes(&DRAFT_FIXTURE_AUTHORITY_SIGNING_BYTES);
    if key.verifying_key().to_bytes() == expected_public_key {
        Ok(key)
    } else {
        Err("Draft fixture signing key does not match its public declaration".into())
    }
}

fn cbor_bytes(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(Box::<dyn Error>::from)
        .map(|()| bytes)
}

fn execution_profile_bytes(profile: CatalogExecutionProfile) -> Result<Vec<u8>, Box<dyn Error>> {
    let authority = draft_authority()?;
    let declaration = authority
        .execution_profiles
        .iter()
        .find(|candidate| candidate.profile_id == profile.name())
        .ok_or("Draft authority omits an execution profile")?;
    let reproducibility_classes = declaration
        .reproducibility_classes
        .iter()
        .copied()
        .map(DraftReproducibilityClass::value)
        .collect::<Vec<_>>();
    let fields = vec![
        Value::Text("EPF1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(declaration.profile_id.clone()),
        Value::Text(declaration.semantic_version.clone()),
        Value::Array(reproducibility_classes),
        Value::Bool(declaration.network_allowed),
        Value::Array(
            declaration
                .capability_ids
                .iter()
                .cloned()
                .map(Value::Text)
                .collect(),
        ),
        Value::Text("fixture-scheduler-v1".to_owned()),
        Value::Text("fixture-numeric-v1".to_owned()),
        Value::Text("fixture-schema-v1".to_owned()),
        Value::Text("fixture-artifact-v1".to_owned()),
        Value::Text("fixture-budget-v1".to_owned()),
        Value::Array(Vec::new()),
        Value::Null,
    ];
    cbor_bytes(&Value::Array(fields.clone())).and_then(|unsigned| {
        let digest = labeled_digest("PiglorOS.ExecutionProfile.v1", &unsigned);
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(digest.to_vec()));
        cbor_bytes(&Value::Array(signed_fields))
    })
}

fn trust_policy_snapshot_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    let authority = draft_authority()?;
    let key = authority_signing_key(DRAFT_AUTHORITY_PUBLIC_KEY_BYTES)?;
    let fields = vec![
        Value::Text("TPS1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(authority.trust_policy_id),
        Value::Integer(authority.trust_policy_epoch.into()),
        Value::Integer(authority.effective_timeline_position.into()),
        Value::Text(authority.fixture_authority_key_id),
        Value::Bytes(DRAFT_AUTHORITY_PUBLIC_KEY_BYTES.to_vec()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Text(authority.offline_valid_through),
        Value::Null,
    ];
    cbor_bytes(&Value::Array(fields.clone())).and_then(|unsigned| {
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(key.sign(&unsigned).to_bytes().to_vec()));
        cbor_bytes(&Value::Array(signed_fields))
    })
}

fn trust_policy_snapshot_digest() -> Result<[u8; 32], Box<dyn Error>> {
    trust_policy_snapshot_bytes().map(|bytes| *blake3::hash(&bytes).as_bytes())
}

fn provider_key_value(key: &FixtureProviderKeyV1) -> Value {
    Value::Array(vec![
        Value::Text(key.provider_id.clone()),
        Value::Text(key.contract_version.clone()),
        Value::Integer(u64::from(key.abi_major).into()),
        Value::Integer(u64::from(key.abi_minor).into()),
    ])
}

fn release_admission_bytes(
    case_id: &str,
    execution_profile_digest: [u8; 32],
    trust_policy_snapshot_digest: [u8; 32],
    from: &FixtureProviderKeyV1,
    to: &FixtureProviderKeyV1,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let authority = draft_authority()?;
    let key = authority_signing_key(DRAFT_AUTHORITY_PUBLIC_KEY_BYTES)?;
    let fields = vec![
        Value::Text("RAD1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Text(case_id.to_owned()),
        Value::Bytes(execution_profile_digest.to_vec()),
        Value::Bytes(trust_policy_snapshot_digest.to_vec()),
        provider_key_value(from),
        provider_key_value(to),
        Value::Bool(false),
        Value::Text(authority.fixture_authority_key_id),
    ];
    cbor_bytes(&Value::Array(fields.clone())).and_then(|unsigned| {
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(key.sign(&unsigned).to_bytes().to_vec()));
        cbor_bytes(&Value::Array(signed_fields))
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum CatalogBundleMode {
    Local,
    AirGapped,
}

impl CatalogBundleMode {
    const ALL: [Self; 2] = [Self::Local, Self::AirGapped];

    const fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::AirGapped => "air-gapped",
        }
    }

    const fn bundle_mode(self) -> BundleModeV1 {
        match self {
            Self::Local => BundleModeV1::Local,
            Self::AirGapped => BundleModeV1::AirGapped,
        }
    }
}

impl CatalogFixtureFamily {
    const ALL: [Self; 7] = [
        Self::Positive,
        Self::Denied,
        Self::Malformed,
        Self::ResourceExhaustion,
        Self::DeletionRedaction,
        Self::Downgrade,
        Self::IndependentEvaluation,
    ];

    const fn provider_family(self) -> FixtureFamilyV1 {
        match self {
            Self::Positive => FixtureFamilyV1::Positive,
            Self::Denied => FixtureFamilyV1::Denied,
            Self::Malformed => FixtureFamilyV1::Malformed,
            Self::ResourceExhaustion => FixtureFamilyV1::ResourceExhaustion,
            Self::DeletionRedaction => FixtureFamilyV1::DeletionRedaction,
            Self::Downgrade => FixtureFamilyV1::Downgrade,
            Self::IndependentEvaluation => FixtureFamilyV1::IndependentEvaluation,
        }
    }
}

#[derive(Deserialize)]
struct ProfileCatalogRecord {
    profile_id: String,
    claim_layer: String,
    wire_code: u8,
    subject_adapter: String,
    fixture_root: String,
    fixtures: Vec<ProfileFixtureRecord>,
    execution_profiles: [CatalogExecutionProfile; 2],
    bundle_modes: [CatalogBundleMode; 2],
}

#[derive(Deserialize)]
struct ProfileFixtureRecord {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    schema: String,
    input: String,
    expected: String,
    oracle: String,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CatalogStrictOracle {
    CanonicalOutput,
    NamespacedFailure {
        owner_id: String,
        contract_version: String,
        code_id: String,
    },
}

#[derive(Deserialize)]
struct FixtureOracleRecord {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    oracle: CatalogStrictOracle,
}

#[derive(Deserialize)]
struct FixtureInputIdentity {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    provider_contract: String,
    subject_adapter: String,
}

#[derive(Deserialize)]
struct EvidenceStatusRecord {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    input_blake3_digest: String,
    status: String,
    execution_result: Option<serde_json::Value>,
    executed_at: Option<String>,
}

#[derive(Clone, Deserialize)]
struct FixtureProviderRecord {
    provider_id: String,
    contract_version: String,
    abi_major: u16,
    abi_minor: u16,
    claim_layer: String,
    subject_adapter: String,
    package_path: String,
    fixture_operations: BTreeMap<CatalogFixtureFamily, Option<String>>,
    schemas: BTreeMap<CatalogFixtureFamily, String>,
    fixture_contracts: BTreeMap<CatalogFixtureFamily, CatalogFixtureContract>,
}

#[derive(Clone, Deserialize)]
struct CatalogFixtureContract {
    deterministic_budget: CatalogDeterministicBudget,
    watchdog_ms: u64,
    network_allowed: bool,
    minimum_capability_ids: Vec<String>,
}

#[derive(Clone, Deserialize)]
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

impl CatalogDeterministicBudget {
    const fn resolved(&self) -> DeterministicBudgetV1 {
        DeterministicBudgetV1 {
            memory_bytes: self.memory_bytes,
            cpu_fuel: self.cpu_fuel,
            host_calls: self.host_calls,
            event_count: self.event_count,
            output_bytes: self.output_bytes,
            storage_bytes: self.storage_bytes,
            execution_steps: self.execution_steps,
            simulation_time_ns: self.simulation_time_ns,
        }
    }
}

struct CatalogFixture {
    record: ProfileFixtureRecord,
    contract: CatalogFixtureContract,
    schema: &'static [u8],
    input: &'static [u8],
    expected: &'static [u8],
    oracle: &'static [u8],
    strict_oracle: CatalogStrictOracle,
}

struct FixtureExpectation {
    strict_oracle: StrictOracleV1,
    verification_outcome: VerificationOutcomeV1,
    verification_error: Option<NamespacedFailureV1>,
    replay_claim: ReplayClaimV1,
    redaction_state: RedactionStateV1,
}

struct LayerCatalogEntry {
    claim_layer: ClaimLayerV1,
    name: &'static str,
    profile_id: String,
    subject_adapter: SubjectAdapterKindV1,
    fixture_provider: FixtureProviderRecord,
    profile_record: &'static [u8],
    fixtures: Vec<CatalogFixture>,
    execution_profiles: [CatalogExecutionProfile; 2],
    bundle_modes: [CatalogBundleMode; 2],
}

struct LayerCatalog {
    entries: Vec<LayerCatalogEntry>,
    bundle_modes: [CatalogBundleMode; 2],
}

struct CatalogEntryInput {
    record: ProfileCatalogRecord,
    fixture_provider: FixtureProviderRecord,
}

#[derive(Clone)]
struct PublicArtifact {
    path: String,
    media_type: &'static str,
    bytes: Vec<u8>,
}

impl PublicArtifact {
    fn descriptor(&self) -> ArtifactDescriptorV1 {
        artifact_descriptor(&self.path, self.media_type, &self.bytes)
    }

    fn materialized_file(&self) -> MaterializedFile {
        MaterializedFile {
            relative_path: self.path.clone(),
            bytes: self.bytes.clone(),
            archive_release_filename: None,
        }
    }
}

fn artifact_descriptor(path: &str, media_type: &str, bytes: &[u8]) -> ArtifactDescriptorV1 {
    ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: media_type.to_owned(),
        byte_length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        blake3_digest: *blake3::hash(bytes).as_bytes(),
    }
}

struct ProviderPackage {
    provider_key: FixtureProviderKeyV1,
    claim_layer: ClaimLayerV1,
    subject_adapter: SubjectAdapterKindV1,
    schemas: Vec<PublicArtifact>,
    artifact: PublicArtifact,
}

struct ProviderCatalog {
    registry: PublicArtifact,
    packages: Vec<ProviderPackage>,
    package_support: [PublicArtifact; 7],
}

impl ProviderCatalog {
    fn binding_for(&self, provider_key: FixtureProviderKeyV1) -> FixtureProviderRegistryBindingV1 {
        FixtureProviderRegistryBindingV1 {
            registry_artifact: self.registry.descriptor(),
            required_provider_keys: vec![provider_key],
        }
    }

    fn materialized_files(&self) -> Vec<MaterializedFile> {
        self.packages
            .iter()
            .flat_map(|package| &package.schemas)
            .chain(&self.package_support)
            .chain(self.packages.iter().map(|package| &package.artifact))
            .chain(std::iter::once(&self.registry))
            .map(PublicArtifact::materialized_file)
            .collect()
    }
}

fn public_artifact(path: &str, media_type: &'static str, bytes: &[u8]) -> PublicArtifact {
    PublicArtifact {
        path: path.to_owned(),
        media_type,
        bytes: bytes.to_vec(),
    }
}

fn embedded_catalog_result<T, E>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|_| std::process::abort())
}

fn embedded_catalog_option<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| std::process::abort())
}

fn package_support_artifacts() -> [PublicArtifact; 7] {
    [
        public_artifact(
            "support/LICENSE",
            "text/plain",
            include_bytes!("../../../../fixtures/conformance/support/LICENSE"),
        ),
        public_artifact(
            "support/NOTICE",
            "text/plain",
            include_bytes!("../../../../fixtures/conformance/support/NOTICE"),
        ),
        public_artifact(
            "support/sbom.json",
            "application/json",
            include_bytes!("../../../../fixtures/conformance/support/sbom.json"),
        ),
        public_artifact(
            "support/source-provenance.json",
            "application/json",
            include_bytes!("../../../../fixtures/conformance/support/source-provenance.json"),
        ),
        public_artifact(
            "support/build-provenance.json",
            "application/json",
            include_bytes!("../../../../fixtures/conformance/support/build-provenance.json"),
        ),
        public_artifact(
            "support/publication-review.json",
            "application/json",
            include_bytes!("../../../../fixtures/conformance/support/publication-review.json"),
        ),
        public_artifact(
            "support/limitations.md",
            "text/markdown",
            include_bytes!("../../../../fixtures/conformance/support/limitations.md"),
        ),
    ]
}

fn provider_catalog(catalog: &LayerCatalog) -> ProviderCatalog {
    let package_support = package_support_artifacts();
    let mut packages = catalog
        .entries
        .iter()
        .map(|layer| provider_package(layer, &package_support))
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.provider_key.cmp(&right.provider_key));
    let providers = packages
        .iter()
        .map(|package| FixtureProviderEntryV1 {
            provider_key: package.provider_key.clone(),
            claim_layer: package.claim_layer,
            subject_adapter: package.subject_adapter,
            provider_package_descriptor: package.artifact.descriptor(),
        })
        .collect::<Vec<_>>();
    let mut registry = FixtureProviderRegistryV1 {
        providers,
        registry_digest: [0; 32],
    };
    registry.registry_digest = embedded_catalog_result(registry.digest());
    registry
        .providers
        .iter()
        .zip(&packages)
        .for_each(|(entry, catalog_package)| {
            embedded_catalog_result(
                FixtureProviderPackageV1::from_canonical_cbor(&catalog_package.artifact.bytes)
                    .and_then(|decoded| {
                        decoded.validate_registry_binding(entry, &catalog_package.artifact.bytes)
                    }),
            );
        });
    let registry = public_artifact(
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
        "application/cbor",
        &embedded_catalog_result(registry.to_canonical_cbor()),
    );
    ProviderCatalog {
        registry,
        packages,
        package_support,
    }
}

fn provider_package(
    layer: &LayerCatalogEntry,
    package_support: &[PublicArtifact; 7],
) -> ProviderPackage {
    let provider_key = FixtureProviderKeyV1 {
        provider_id: layer.fixture_provider.provider_id.clone(),
        contract_version: layer.fixture_provider.contract_version.clone(),
        abi_major: layer.fixture_provider.abi_major,
        abi_minor: layer.fixture_provider.abi_minor,
    };
    let schemas = provider_schema_artifacts(layer);
    let [licence, notices, sbom, source_provenance, _, _, limitations] = package_support;
    let mut package = FixtureProviderPackageV1 {
        provider_key: provider_key.clone(),
        claim_layer: layer.claim_layer,
        subject_adapter: layer.subject_adapter,
        family_schemas: schemas
            .iter()
            .zip(CatalogFixtureFamily::ALL)
            .map(|(schema, family)| ProviderFamilySchemaV1 {
                family: family.provider_family(),
                schema_descriptor: schema.descriptor(),
            })
            .collect(),
        licence_descriptor: licence.descriptor(),
        notices_descriptor: notices.descriptor(),
        sbom_descriptor: sbom.descriptor(),
        source_provenance_descriptor: source_provenance.descriptor(),
        limitations_descriptor: limitations.descriptor(),
        package_digest: [0; 32],
    };
    package.package_digest = embedded_catalog_result(package.digest());
    let artifact = public_artifact(
        &layer.fixture_provider.package_path,
        "application/cbor",
        &embedded_catalog_result(package.to_canonical_cbor()),
    );
    ProviderPackage {
        provider_key,
        claim_layer: layer.claim_layer,
        subject_adapter: layer.subject_adapter,
        schemas,
        artifact,
    }
}

fn provider_schema_artifacts(layer: &LayerCatalogEntry) -> Vec<PublicArtifact> {
    let mut schemas = layer
        .fixtures
        .iter()
        .map(|fixture| {
            (
                fixture.record.family,
                public_artifact(
                    &fixture.record.schema,
                    "application/schema+json",
                    fixture.schema,
                ),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    CatalogFixtureFamily::ALL
        .into_iter()
        .filter_map(|family| schemas.remove(&family))
        .collect()
}

fn invalid_catalog(message: &str) -> Box<dyn Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

fn layer_catalog() -> Result<LayerCatalog, Box<dyn Error>> {
    let entries = LAYER_SOURCES
        .iter()
        .map(catalog_entry)
        .collect::<Result<Vec<_>, _>>()?;
    finish_layer_catalog(entries)
}

fn finish_layer_catalog(entries: Vec<LayerCatalogEntry>) -> Result<LayerCatalog, Box<dyn Error>> {
    let bundle_modes = entries
        .first()
        .map_or(CatalogBundleMode::ALL, |entry| entry.bundle_modes);
    if entries
        .iter()
        .any(|entry| entry.bundle_modes != bundle_modes)
    {
        return Err(invalid_catalog("profile bundle modes disagree"));
    }
    Ok(LayerCatalog {
        entries,
        bundle_modes,
    })
}

fn catalog_entry(source: &LayerSource) -> Result<LayerCatalogEntry, Box<dyn Error>> {
    let input = catalog_entry_input(source)?;
    let (claim_layer, subject_adapter) = catalog_identity(&input.record)?;
    let fixtures_match_profile = input.record.fixtures.len() == CatalogFixtureFamily::ALL.len()
        && input
            .record
            .fixtures
            .iter()
            .zip(CatalogFixtureFamily::ALL)
            .all(|(fixture, family)| {
                fixture.family == family && fixture.claim_layer == input.record.claim_layer
            });
    if !fixtures_match_profile
        || input.record.execution_profiles != CatalogExecutionProfile::ALL
        || input.record.bundle_modes != CatalogBundleMode::ALL
    {
        return Err(invalid_catalog("profile catalog shape is invalid"));
    }
    let fixtures = catalog_fixtures(source, &input.record, &input.fixture_provider)?;
    Ok(LayerCatalogEntry {
        claim_layer,
        name: claim_layer.catalog_name(),
        profile_id: input.record.profile_id,
        subject_adapter,
        fixture_provider: input.fixture_provider,
        profile_record: source.profile_record,
        fixtures,
        execution_profiles: input.record.execution_profiles,
        bundle_modes: input.record.bundle_modes,
    })
}

fn catalog_entry_input(source: &LayerSource) -> Result<CatalogEntryInput, Box<dyn Error>> {
    let record = serde_json::from_slice(source.profile_record)?;
    let fixture_provider = serde_json::from_slice(source.provider_record)?;
    Ok(CatalogEntryInput {
        record,
        fixture_provider,
    })
}

fn catalog_identity(
    record: &ProfileCatalogRecord,
) -> Result<(ClaimLayerV1, SubjectAdapterKindV1), Box<dyn Error>> {
    let claim_layer = ClaimLayerV1::from_wire_code(record.wire_code)
        .ok_or_else(|| invalid_catalog("profile wire code is invalid"))?;
    let subject_adapter = SubjectAdapterKindV1::from_catalog_name(&record.subject_adapter)
        .ok_or_else(|| invalid_catalog("profile subject adapter is invalid"))?;
    if record.claim_layer != claim_layer.catalog_name() || record.fixture_root != record.claim_layer
    {
        return Err(invalid_catalog("profile identity is inconsistent"));
    }
    Ok((claim_layer, subject_adapter))
}

fn catalog_fixtures(
    source: &LayerSource,
    record: &ProfileCatalogRecord,
    fixture_provider: &FixtureProviderRecord,
) -> Result<Vec<CatalogFixture>, Box<dyn Error>> {
    let provider_contract = format!(
        "{}@{}",
        fixture_provider.provider_id, fixture_provider.contract_version
    );
    if fixture_provider.claim_layer != record.claim_layer
        || fixture_provider.subject_adapter != record.subject_adapter
        || source.fixtures.len() != record.fixtures.len()
    {
        return Err(invalid_catalog("provider identity is inconsistent"));
    }
    source
        .fixtures
        .iter()
        .zip(record.fixtures.iter())
        .map(|(fixture_source, fixture_record)| {
            let contract = fixture_provider
                .fixture_contracts
                .get(&fixture_record.family)
                .ok_or_else(|| invalid_catalog("provider contract is missing"))?;
            let operation = fixture_provider
                .fixture_operations
                .get(&fixture_record.family)
                .ok_or_else(|| invalid_catalog("provider operation is missing"))?;
            let schema = fixture_provider
                .schemas
                .get(&fixture_record.family)
                .ok_or_else(|| invalid_catalog("provider schema is missing"))?;
            if schema != &fixture_record.schema {
                return Err(invalid_catalog("provider schema binding is inconsistent"));
            }
            catalog_fixture(
                fixture_record,
                fixture_source,
                contract,
                &provider_contract,
                &record.subject_adapter,
                operation.as_deref(),
            )
        })
        .collect()
}

fn catalog_fixture(
    record: &ProfileFixtureRecord,
    source: &FixtureSource,
    contract: &CatalogFixtureContract,
    provider_contract: &str,
    subject_adapter: &str,
    operation: Option<&str>,
) -> Result<CatalogFixture, Box<dyn Error>> {
    let oracle: FixtureOracleRecord = serde_json::from_slice(source.oracle)?;
    let input: FixtureInputIdentity = serde_json::from_slice(source.input)?;
    let evidence: EvidenceStatusRecord = serde_json::from_slice(source.expected)?;
    let input_digest = blake3::hash(source.input).to_hex().to_string();
    let identity_matches = input.case_id == record.case_id
        && input.claim_layer == record.claim_layer
        && input.family == record.family
        && input.provider_contract == provider_contract
        && input.subject_adapter == subject_adapter
        && evidence.case_id == record.case_id
        && evidence.claim_layer == record.claim_layer
        && evidence.family == record.family
        && evidence.input_blake3_digest == input_digest
        && evidence.status == "pending"
        && evidence.execution_result.is_none()
        && evidence.executed_at.is_none()
        && oracle.case_id == record.case_id
        && oracle.claim_layer == record.claim_layer
        && oracle.family == record.family;
    let operation_matches = operation.is_none_or(|expected| {
        serde_json::from_slice::<serde_json::Value>(source.input)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/stimulus/operation")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some(expected)
    });
    if !identity_matches || !operation_matches {
        return Err(invalid_catalog("fixture identity is inconsistent"));
    }
    Ok(CatalogFixture {
        record: ProfileFixtureRecord {
            case_id: record.case_id.clone(),
            claim_layer: record.claim_layer.clone(),
            family: record.family,
            schema: record.schema.clone(),
            input: record.input.clone(),
            expected: record.expected.clone(),
            oracle: record.oracle.clone(),
        },
        contract: contract.clone(),
        schema: source.schema,
        input: source.input,
        expected: source.expected,
        oracle: source.oracle,
        strict_oracle: oracle.oracle,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    run(
        std::env::args_os(),
        std::env::var("PIGLOROS_CONFORMANCE_SIGNING_KEY"),
    )
}

fn run(
    arguments: impl Iterator<Item = OsString>,
    encoded_signing_key: Result<String, std::env::VarError>,
) -> Result<(), Box<dyn Error>> {
    command_from_arguments(arguments)
        .and_then(|command| {
            signing_key_from_encoded(encoded_signing_key).map(|signing_key| (command, signing_key))
        })
        .and_then(|(command, signing_key)| {
            prepare_command(command).map(|command| (command, signing_key))
        })
        .and_then(|(command, signing_key)| {
            materialized_files(&signing_key).and_then(|outputs| execute_command(command, &outputs))
        })
}

fn prepare_command(
    command: MaterializationCommand,
) -> Result<PreparedMaterializationCommand, Box<dyn Error>> {
    match command {
        MaterializationCommand::Publish(output_root) => {
            validate_source_inventory_address(&output_root)
                .and_then(|()| AtomicPublication::prepare(&output_root))
                .map(PreparedMaterializationCommand::Publish)
                .map_err(Into::into)
        }
        MaterializationCommand::Fingerprint => Ok(PreparedMaterializationCommand::Fingerprint),
    }
}

fn validate_source_inventory_address(destination: &Path) -> Result<(), MaterializationError> {
    let digest: [u8; 32] = Sha256::digest(include_bytes!(
        "../../../../fixtures/conformance/SHA256SUMS"
    ))
    .into();
    let expected = pos_conformance::hex_digest(&digest);
    if destination
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected)
    {
        Ok(())
    } else {
        Err(MaterializationError::SourceInventoryAddressMismatch)
    }
}

fn execute_command(
    command: PreparedMaterializationCommand,
    outputs: &[MaterializedFile],
) -> Result<(), Box<dyn Error>> {
    match command {
        PreparedMaterializationCommand::Publish(publication) => {
            publish_materialized_tree(publication, outputs).map_err(Into::into)
        }
        PreparedMaterializationCommand::Fingerprint => {
            let fingerprint = format!(
                "{}\n",
                pos_conformance::hex_digest(&materialized_tree_digest(outputs))
            );
            let mut output = std::io::stdout().lock();
            output.write_all(fingerprint.as_bytes()).map_err(Into::into)
        }
    }
}

fn materialized_files(signing_key: &SigningKey) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    let inventory_bytes =
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json");
    let catalog = layer_catalog()?;
    let providers = provider_catalog(&catalog);
    let context = MaterializationContext {
        signing_key,
        inventory_bytes,
        providers: &providers,
    };
    catalog
        .entries
        .iter()
        .try_fold(providers.materialized_files(), |mut outputs, spec| {
            materialize_profile(&context, spec, catalog.bundle_modes).map(|files| {
                outputs.extend(files);
                outputs
            })
        })
        .map(|mut outputs| {
            let archives = outputs
                .iter()
                .filter(|output| output.archive_release_filename.is_some())
                .map(|output| output.bytes.as_slice())
                .collect::<Vec<_>>();
            embedded_catalog_result(verify_release_tree_independently(&archives));
            let published_file_count = outputs.len().saturating_add(2);
            outputs.push(materialization_metadata(&catalog, published_file_count));
            outputs.push(output_checksum_inventory(&outputs));
            outputs
        })
}

fn command_from_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<MaterializationCommand, Box<dyn Error>> {
    let _program = arguments.next();
    let argument = arguments
        .next()
        .ok_or("materialization output directory is required")?;
    if arguments.next().is_some() {
        return Err("materialization accepts exactly one output directory".into());
    }
    if argument == "--fingerprint" {
        Ok(MaterializationCommand::Fingerprint)
    } else {
        Ok(MaterializationCommand::Publish(PathBuf::from(argument)))
    }
}

fn materialized_tree_digest(files: &[MaterializedFile]) -> [u8; 32] {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ConformanceMaterializedTree.v1\0");
    hasher.update(&(ordered.len() as u64).to_be_bytes());
    for file in ordered {
        hasher.update(&(file.relative_path.len() as u64).to_be_bytes());
        hasher.update(file.relative_path.as_bytes());
        hasher.update(&(file.bytes.len() as u64).to_be_bytes());
        hasher.update(&file.bytes);
    }
    *hasher.finalize().as_bytes()
}

fn signing_key_from_encoded(
    encoded: Result<String, std::env::VarError>,
) -> Result<SigningKey, Box<dyn Error>> {
    encoded
        .map_err(Into::into)
        .and_then(|encoded| {
            pos_conformance::decode_hex_digest(&encoded)
                .ok_or_else(|| "invalid conformance signing key".into())
        })
        .map(|bytes| SigningKey::from_bytes(&bytes))
}

fn materialize_profile(
    context: &MaterializationContext<'_>,
    layer: &LayerCatalogEntry,
    bundle_modes: [CatalogBundleMode; 2],
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    profile_from_catalog(layer, context.providers).and_then(|mut profile| {
        profile.lifecycle = ProfileLifecycleV1::Draft;
        profile.profile_digest = profile.digest();
        let prefix = format!("{}/draft", layer.name);
        profile
            .to_canonical_cbor()
            .map_err(Into::into)
            .and_then(|profile_bytes| {
                let [local, air_gapped] = bundle_modes
                    .map(|mode| signed_bundle(context, layer, &profile, mode.bundle_mode()));
                local.and_then(|local| {
                    air_gapped.and_then(|air_gapped| {
                        let pair = ConformanceBundlePairV1 { local, air_gapped };
                        pair.validate().map_err(Into::into).and_then(|()| {
                            materialized_profile_outputs(
                                &profile,
                                &prefix,
                                profile_bytes,
                                &pair,
                                bundle_modes,
                            )
                        })
                    })
                })
            })
    })
}

fn signed_bundle(
    context: &MaterializationContext<'_>,
    layer: &LayerCatalogEntry,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<ConformanceBundleV1, Box<dyn Error>> {
    bundle_inputs_from_profile(
        layer,
        profile,
        mode,
        context.inventory_bytes,
        context.providers,
    )
    .and_then(|(members, expected_results)| {
        ConformanceBundleV1::materialize(profile, mode, members, expected_results)
            .and_then(|bundle| bundle.sign(context.signing_key))
            .map_err(Into::into)
    })
}

fn materialized_profile_outputs(
    profile: &ConformanceProfileV1,
    prefix: &str,
    profile_bytes: Vec<u8>,
    pair: &ConformanceBundlePairV1,
    modes: [CatalogBundleMode; 2],
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    let outputs = vec![MaterializedFile {
        relative_path: format!(
            "{prefix}/CPF1-{}.cbor",
            pos_conformance::hex_digest(&profile.profile_digest)
        ),
        bytes: profile_bytes,
        archive_release_filename: None,
    }];
    modes
        .into_iter()
        .map(CatalogBundleMode::name)
        .zip([&pair.local, &pair.air_gapped])
        .try_fold(outputs, |mut outputs, (mode_name, bundle)| {
            materialized_bundle_files(prefix, mode_name, bundle).map(|files| {
                outputs.extend(files);
                outputs
            })
        })
}

fn materialized_bundle_files(
    prefix: &str,
    mode_name: &str,
    bundle: &ConformanceBundleV1,
) -> Result<[MaterializedFile; 2], Box<dyn Error>> {
    bundle
        .manifest_digest()
        .and_then(|manifest_digest| {
            bundle
                .release_filename()
                .map(|release_filename| (manifest_digest, release_filename))
        })
        .and_then(|(manifest_digest, release_filename)| {
            bundle
                .manifest_bytes()
                .map(|manifest_bytes| (manifest_digest, release_filename, manifest_bytes))
        })
        .and_then(|(manifest_digest, release_filename, manifest_bytes)| {
            bundle.to_canonical_cbor().map(|bundle_bytes| {
                (
                    manifest_digest,
                    release_filename,
                    manifest_bytes,
                    bundle_bytes,
                )
            })
        })
        .map_err(Into::into)
        .and_then(
            |(manifest_digest, release_filename, manifest_bytes, bundle_bytes)| {
                verify_public_archive(&bundle_bytes, &release_filename).map(|()| {
                    [
                        MaterializedFile {
                            relative_path: format!(
                                "{prefix}/manifest-{mode_name}-{}.cbor",
                                pos_conformance::hex_digest(&manifest_digest)
                            ),
                            bytes: manifest_bytes,
                            archive_release_filename: None,
                        },
                        MaterializedFile {
                            relative_path: format!("{prefix}/{release_filename}"),
                            bytes: bundle_bytes,
                            archive_release_filename: Some(release_filename),
                        },
                    ]
                })
            },
        )
}

fn materialization_metadata(
    catalog: &LayerCatalog,
    published_file_count: usize,
) -> MaterializedFile {
    let layer_names = catalog
        .entries
        .iter()
        .map(|layer| layer.name)
        .collect::<Vec<_>>();
    let mode_names = catalog
        .bundle_modes
        .into_iter()
        .map(CatalogBundleMode::name)
        .collect::<Vec<_>>();
    MaterializedFile {
        relative_path: MATERIALIZATION_METADATA_PATH.to_owned(),
        bytes: serde_json::json!({
            "format": 1,
            "lifecycles": ["draft"],
            "layers": layer_names,
            "modes": mode_names,
            "published_file_count": published_file_count,
        })
        .to_string()
        .into_bytes(),
        archive_release_filename: None,
    }
}

fn output_checksum_inventory(files: &[MaterializedFile]) -> MaterializedFile {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut inventory = String::new();
    for file in ordered {
        let digest: [u8; 32] = Sha256::digest(&file.bytes).into();
        inventory.push_str(&pos_conformance::hex_digest(&digest));
        inventory.push_str("  ");
        inventory.push_str(&file.relative_path);
        inventory.push('\n');
    }
    MaterializedFile {
        relative_path: OUTPUT_CHECKSUM_INVENTORY_PATH.to_owned(),
        bytes: inventory.into_bytes(),
        archive_release_filename: None,
    }
}

fn fixture_context(profile_record_bytes: &[u8], claim_layer: ClaimLayerV1) -> FixtureContext {
    let profile_record_digest =
        labeled_digest("PiglorOS.CPF1ProfileRecord.v1", profile_record_bytes);
    let normative =
        include_bytes!("../../../../fixtures/conformance/support/normative-requirements.md");
    let notice = include_bytes!("../../../../fixtures/conformance/support/NOTICE");
    let sbom = include_bytes!("../../../../fixtures/conformance/support/sbom.json");
    let source_provenance =
        include_bytes!("../../../../fixtures/conformance/support/source-provenance.json");
    let build_provenance =
        include_bytes!("../../../../fixtures/conformance/support/build-provenance.json");
    let publication_review =
        include_bytes!("../../../../fixtures/conformance/support/publication-review.json");
    let limitations = include_bytes!("../../../../fixtures/conformance/support/limitations.md");
    let notice_digest = *blake3::hash(notice).as_bytes();
    let sbom_digest = *blake3::hash(sbom).as_bytes();
    let limitations_digest = *blake3::hash(limitations).as_bytes();
    FixtureContext {
        claim_layer,
        profile_record_digest,
        source_provenance_digest: *blake3::hash(source_provenance).as_bytes(),
        build_provenance_digest: *blake3::hash(build_provenance).as_bytes(),
        publication_review_digest: *blake3::hash(publication_review).as_bytes(),
        notice_digest,
        sbom_digest,
        limitations_digest,
        normative_spec_digest: *blake3::hash(normative).as_bytes(),
    }
}

fn fixtures_for_layer(
    layer: &LayerCatalogEntry,
    context: &FixtureContext,
    provider_key: &FixtureProviderKeyV1,
) -> Result<Vec<FixtureDescriptorV1>, Box<dyn Error>> {
    layer
        .fixtures
        .iter()
        .try_fold(
            Vec::with_capacity(layer.fixtures.len() * layer.execution_profiles.len()),
            |mut fixtures, fixture| {
                layer
                    .execution_profiles
                    .into_iter()
                    .map(|execution_profile| {
                        execution_profile.digest().and_then(|digest| {
                            fixture_descriptor_from_record(
                                layer,
                                fixture,
                                context,
                                provider_key,
                                digest,
                                execution_profile.execution_mode(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(|descriptors| {
                        fixtures.extend(descriptors);
                        fixtures
                    })
            },
        )
        .map(|mut fixtures| {
            fixtures.sort_by_key(|fixture| {
                (
                    fixture.provider_key.clone(),
                    fixture.family,
                    fixture.case_id.clone(),
                    fixture.execution_profile_digest,
                    fixture.modes.clone(),
                )
            });
            fixtures
        })
}

fn profile_from_catalog(
    layer: &LayerCatalogEntry,
    providers: &ProviderCatalog,
) -> Result<ConformanceProfileV1, Box<dyn Error>> {
    let context = fixture_context(layer.profile_record, layer.claim_layer);
    let provider_key = FixtureProviderKeyV1 {
        provider_id: layer.fixture_provider.provider_id.clone(),
        contract_version: layer.fixture_provider.contract_version.clone(),
        abi_major: layer.fixture_provider.abi_major,
        abi_minor: layer.fixture_provider.abi_minor,
    };
    fixtures_for_layer(layer, &context, &provider_key).and_then(|fixtures| {
        layer
            .execution_profiles
            .into_iter()
            .map(CatalogExecutionProfile::digest)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|mut execution_profile_digests| {
                execution_profile_digests.sort_unstable();
                trust_policy_snapshot_digest().map(|snapshot_digest| {
                    let execution_matrix_digest = *blake3::hash(include_bytes!(
                        "../../../../fixtures/conformance/matrix/execution-matrix.json"
                    ))
                    .as_bytes();
                    let mut profile = ConformanceProfileV1 {
                        profile_id: layer.profile_id.clone(),
                        semantic_version: "1.0.0".to_owned(),
                        lifecycle: ProfileLifecycleV1::Draft,
                        normative_spec_digest: context.normative_spec_digest,
                        execution_matrix_digest,
                        execution_profile_digests,
                        fixture_provider_registry: providers.binding_for(provider_key),
                        fixtures,
                        allowed_divergences: Vec::new(),
                        evaluator_protocol: evaluator_protocol(context.profile_record_digest),
                        independence_requirements: IndependenceRequirementsV1 {
                            technical_independence_required: true,
                            authorship_independence_required: true,
                            organizational_independence_required: false,
                            trust_policy_snapshot_digest: snapshot_digest,
                            requirements_digest: labeled_digest(
                                "PiglorOS.IndependenceRequirements.v1",
                                layer.profile_record,
                            ),
                        },
                        fixture_contract_policy_digest: *blake3::hash(include_bytes!(
                            "../../../../fixtures/conformance/support/fixture-family-contract.json"
                        ))
                        .as_bytes(),
                        limitations_digest: context.limitations_digest,
                        provenance_digest: context.publication_review_digest,
                        previous_profile_digest: None,
                        profile_digest: [0; 32],
                    };
                    profile.profile_digest = profile.digest();
                    profile
                })
            })
    })
}

fn fixture_descriptor_from_record(
    layer: &LayerCatalogEntry,
    fixture: &CatalogFixture,
    context: &FixtureContext,
    provider_key: &FixtureProviderKeyV1,
    execution_profile_digest: [u8; 32],
    mode: pos_conformance::ExecutionModeV1,
) -> Result<FixtureDescriptorV1, Box<dyn Error>> {
    let payload_path =
        fixture_payload_member_path(&fixture.record.case_id, &execution_profile_digest);
    let evidence_path =
        evidence_status_member_path(&fixture.record.case_id, &execution_profile_digest);
    let oracle_output_path = expected_result_member_path(
        &fixture.record.case_id,
        context.claim_layer,
        &execution_profile_digest,
    );
    let evidence = artifact_descriptor(&evidence_path, "application/json", fixture.expected);
    let oracle_output =
        artifact_descriptor(&oracle_output_path, "application/json", fixture.oracle);
    let expectation = fixture_expectation(fixture, &oracle_output);
    let auxiliary = if expectation.strict_oracle.output.is_some() {
        vec![evidence]
    } else {
        vec![evidence, oracle_output]
    };
    let downgrade = fixture.record.family == CatalogFixtureFamily::Downgrade;
    let transition = downgrade.then(|| FixtureContractTransitionV1 {
        from: FixtureProviderKeyV1 {
            provider_id: provider_key.provider_id.clone(),
            contract_version: provider_key.contract_version.clone(),
            abi_major: provider_key.abi_major,
            abi_minor: 1,
        },
        to: provider_key.clone(),
    });
    trust_policy_snapshot_digest().and_then(|trust_policy_snapshot_digest| {
        let release_admission_digest = transition.as_ref().map_or_else(
            || Ok(None),
            |transition| {
                release_admission_bytes(
                    &fixture.record.case_id,
                    execution_profile_digest,
                    trust_policy_snapshot_digest,
                    &transition.from,
                    &transition.to,
                )
                .map(|bytes| Some(*blake3::hash(&bytes).as_bytes()))
            },
        );
        release_admission_digest.map(|release_admission_digest| {
            let mut descriptor = FixtureDescriptorV1 {
                case_id: fixture.record.case_id.clone(),
                mandatory: true,
                claim_layer: context.claim_layer,
                family: fixture.record.family.provider_family(),
                provider_key: provider_key.clone(),
                execution_profile_digest,
                modes: vec![mode],
                subject_adapter: layer.subject_adapter,
                schema: artifact_descriptor(
                    &fixture.record.schema,
                    "application/schema+json",
                    fixture.schema,
                ),
                payload: artifact_descriptor(&payload_path, "application/json", fixture.input),
                auxiliary,
                strict_oracle: expectation.strict_oracle,
                expected_verification_outcome: expectation.verification_outcome,
                expected_verification_error: expectation.verification_error,
                replay_claim: expectation.replay_claim,
                redaction_state: expectation.redaction_state,
                deterministic_budget: fixture.contract.deterministic_budget.resolved(),
                operational_safety: OperationalSafetyV1 {
                    watchdog_ms: fixture.contract.watchdog_ms,
                },
                capability_policy: CapabilityPolicyV1 {
                    network_allowed: fixture.contract.network_allowed,
                    capability_ids: fixture.contract.minimum_capability_ids.clone(),
                },
                provenance: fixture_provenance(context),
                trust_policy_snapshot_digest: downgrade.then_some(trust_policy_snapshot_digest),
                release_admission_digest,
                transition,
                fixture_digest: [0; 32],
            };
            descriptor.fixture_digest = descriptor.digest();
            descriptor
        })
    })
}

fn fixture_expectation(
    fixture: &CatalogFixture,
    auxiliary: &ArtifactDescriptorV1,
) -> FixtureExpectation {
    let (strict_oracle, verification_outcome, verification_error) = match &fixture.strict_oracle {
        CatalogStrictOracle::CanonicalOutput => (
            StrictOracleV1 {
                kind: StrictOracleKindV1::Output,
                output: Some(auxiliary.clone()),
                failure: None,
                divergence: None,
            },
            VerificationOutcomeV1::VerifiedExact,
            None,
        ),
        CatalogStrictOracle::NamespacedFailure {
            owner_id,
            contract_version,
            code_id,
        } => {
            let failure = NamespacedFailureV1 {
                owner_id: owner_id.clone(),
                contract_version: contract_version.clone(),
                code_id: code_id.clone(),
            };
            let outcome = match fixture.record.family {
                CatalogFixtureFamily::ResourceExhaustion => {
                    VerificationOutcomeV1::ResourceLimitExceeded
                }
                CatalogFixtureFamily::Downgrade => VerificationOutcomeV1::IncompatibleProfile,
                _ => VerificationOutcomeV1::InvalidManifest,
            };
            (
                StrictOracleV1 {
                    kind: StrictOracleKindV1::Failure,
                    output: None,
                    failure: Some(failure.clone()),
                    divergence: None,
                },
                outcome,
                Some(failure),
            )
        }
    };
    let (replay_claim, redaction_state) = match fixture.record.family {
        CatalogFixtureFamily::DeletionRedaction => (
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            RedactionStateV1::RedactedViews,
        ),
        CatalogFixtureFamily::Downgrade => {
            (ReplayClaimV1::IncompatibleProfile, RedactionStateV1::None)
        }
        _ => (ReplayClaimV1::Exact, RedactionStateV1::None),
    };
    FixtureExpectation {
        strict_oracle,
        verification_outcome,
        verification_error,
        replay_claim,
        redaction_state,
    }
}

fn fixture_provenance(context: &FixtureContext) -> FixtureProvenanceV1 {
    FixtureProvenanceV1 {
        licence_id: "MIT".to_owned(),
        notices_digest: context.notice_digest,
        sbom_digest: context.sbom_digest,
        source_digest: context.source_provenance_digest,
        build_digest: context.build_provenance_digest,
        publication_review_digest: context.publication_review_digest,
        limitations_digest: context.limitations_digest,
    }
}

fn labeled_digest(label: &str, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(label.len() + 1 + bytes.len());
    input.extend_from_slice(label.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

fn fixture_payload_member_path(case_id: &str, execution_profile_digest: &[u8; 32]) -> String {
    format!(
        "fixtures/{case_id}/{}.json",
        pos_conformance::hex_digest(execution_profile_digest)
    )
}

fn evidence_status_member_path(case_id: &str, execution_profile_digest: &[u8; 32]) -> String {
    format!(
        "evidence/{case_id}/{}.json",
        pos_conformance::hex_digest(execution_profile_digest)
    )
}

fn evaluator_protocol(profile_record_digest: [u8; 32]) -> EvaluatorProtocolV1 {
    EvaluatorProtocolV1 {
        protocol_id: "pigloros.evaluator.v1".to_owned(),
        protocol_digest: labeled_digest("PiglorOS.EvaluatorProtocol.v1", &profile_record_digest),
        request_schema_digest: labeled_digest(
            "PiglorOS.EvaluatorRequestSchema.v1",
            &profile_record_digest,
        ),
        report_schema_digest: labeled_digest(
            "PiglorOS.EvaluatorReportSchema.v1",
            &profile_record_digest,
        ),
        hard_caps: EvaluatorHardCapsV1 {
            max_profile_bytes: 16 * 1024 * 1024,
            max_cases: 65_536,
            max_bundle_members: 65_536,
            max_member_path_bytes: 256,
            max_member_bytes: 64 * 1024 * 1024,
            max_total_bundle_bytes: 1024 * 1024 * 1024,
            max_compression_expansion: 100,
            max_structural_nesting: 32,
            max_coordinate_bytes: 128,
            max_diagnostic_bytes: 1024 * 1024,
            max_deterministic_memory_bytes: 1024 * 1024 * 1024,
            max_deterministic_cpu_fuel: 1_000_000_000,
            max_deterministic_host_calls: 1_000_000,
            max_deterministic_event_count: 1_000_000,
            max_deterministic_output_bytes: 64 * 1024 * 1024,
            max_deterministic_storage_bytes: 1024 * 1024 * 1024,
            max_deterministic_execution_steps: 1_000_000_000,
            max_deterministic_simulation_time_ns: 86_400_000_000_000,
        },
    }
}

fn bundle_inputs_from_profile(
    layer: &LayerCatalogEntry,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
    inventory_bytes: &[u8],
    providers: &ProviderCatalog,
) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn Error>> {
    let execution_mode = match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
    };
    let mut members = Vec::new();
    let mut expected_results = Vec::new();
    for fixture in profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.modes.contains(&execution_mode))
    {
        let source = embedded_catalog_option(
            layer
                .fixtures
                .iter()
                .find(|source| source.record.case_id == fixture.case_id),
        );
        members.push(BundleMemberV1::fixture_input(
            fixture.payload.member_path.clone(),
            source.input.to_vec(),
        ));
        let path = expected_result_member_path(
            &fixture.case_id,
            fixture.claim_layer,
            &fixture.execution_profile_digest,
        );
        let evidence_path =
            evidence_status_member_path(&fixture.case_id, &fixture.execution_profile_digest);
        members.push(BundleMemberV1::evidence_status(
            evidence_path,
            source.expected.to_vec(),
        ));
        let member = BundleMemberV1::expected_result(path.clone(), source.oracle.to_vec());
        expected_results.push(BundleExpectedResultV1 {
            case_id: fixture.case_id.clone(),
            claim_layer: fixture.claim_layer,
            execution_profile_digest: fixture.execution_profile_digest,
            mode,
            member_path: path.clone(),
            digest: member.digest,
        });
        members.push(member);
    }
    expected_results.sort();
    append_supporting_members(&mut members, inventory_bytes, providers, profile, mode)
        .map(|()| (members, expected_results))
}

fn append_supporting_members(
    members: &mut Vec<BundleMemberV1>,
    inventory_bytes: &[u8],
    providers: &ProviderCatalog,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<(), Box<dyn Error>> {
    let support = [
        (
            "support/normative-requirements.md",
            include_bytes!("../../../../fixtures/conformance/support/normative-requirements.md")
                .as_slice(),
            BundleMemberRoleV1::NormativeSpecification,
        ),
        (
            "support/LICENSE",
            include_bytes!("../../../../fixtures/conformance/support/LICENSE").as_slice(),
            BundleMemberRoleV1::Licence,
        ),
        (
            "support/NOTICE",
            include_bytes!("../../../../fixtures/conformance/support/NOTICE").as_slice(),
            BundleMemberRoleV1::Notice,
        ),
        (
            "support/sbom.json",
            include_bytes!("../../../../fixtures/conformance/support/sbom.json").as_slice(),
            BundleMemberRoleV1::Sbom,
        ),
        (
            "support/source-provenance.json",
            include_bytes!("../../../../fixtures/conformance/support/source-provenance.json")
                .as_slice(),
            BundleMemberRoleV1::Provenance,
        ),
        (
            "support/build-provenance.json",
            include_bytes!("../../../../fixtures/conformance/support/build-provenance.json")
                .as_slice(),
            BundleMemberRoleV1::Provenance,
        ),
        (
            "support/publication-review.json",
            include_bytes!("../../../../fixtures/conformance/support/publication-review.json")
                .as_slice(),
            BundleMemberRoleV1::Provenance,
        ),
        (
            "support/limitations.md",
            include_bytes!("../../../../fixtures/conformance/support/limitations.md").as_slice(),
            BundleMemberRoleV1::Limitations,
        ),
    ];
    for (path, bytes, role) in support {
        members.push(BundleMemberV1::supporting(path, bytes.to_vec(), role));
    }
    members.push(BundleMemberV1::supporting(
        "support/schema-cpf1-v1.cddl",
        include_bytes!("../../../../fixtures/conformance/support/schema-cpf1-v1.cddl").to_vec(),
        BundleMemberRoleV1::Schema,
    ));
    members.push(BundleMemberV1::supporting(
        "support/fixture-family-contract.json",
        include_bytes!("../../../../fixtures/conformance/support/fixture-family-contract.json")
            .to_vec(),
        BundleMemberRoleV1::FixtureContractPolicy,
    ));
    members.push(BundleMemberV1::supporting(
        "support/draft-execution-authority.json",
        include_bytes!("../../../../fixtures/conformance/support/draft-execution-authority.json")
            .to_vec(),
        BundleMemberRoleV1::AuthorityDeclaration,
    ));
    for schema in providers
        .packages
        .iter()
        .flat_map(|package| &package.schemas)
    {
        members.push(BundleMemberV1::supporting(
            schema.path.clone(),
            schema.bytes.clone(),
            BundleMemberRoleV1::Schema,
        ));
    }
    let inventory = BundleMemberV1::authority_inventory(inventory_bytes.to_vec());
    members.push(inventory);
    let matrix = BundleMemberV1::execution_matrix(
        include_bytes!("../../../../fixtures/conformance/matrix/execution-matrix.json").to_vec(),
    );
    members.push(matrix);
    append_draft_authority_members(members, profile, mode).map(|()| {
        members.push(BundleMemberV1::fixture_provider_registry(
            providers.registry.bytes.clone(),
        ));
        for package in &providers.packages {
            members.push(BundleMemberV1::fixture_provider_package(
                package.artifact.path.clone(),
                package.artifact.bytes.clone(),
            ));
        }
    })
}

fn append_draft_authority_members(
    members: &mut Vec<BundleMemberV1>,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<(), Box<dyn Error>> {
    CatalogExecutionProfile::ALL
        .into_iter()
        .map(|execution_profile| {
            execution_profile_bytes(execution_profile).map(|bytes| {
                BundleMemberV1::supporting(
                    format!(
                        "authority/execution-profiles/{}.epf1",
                        execution_profile.name()
                    ),
                    bytes,
                    BundleMemberRoleV1::ExecutionProfile,
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|execution_profiles| {
            members.extend(execution_profiles);
            trust_policy_snapshot_bytes().and_then(|snapshot| {
                members.push(BundleMemberV1::supporting(
                    "authority/trust-policy-snapshot.tps1",
                    snapshot,
                    BundleMemberRoleV1::TrustPolicySnapshot,
                ));
                append_draft_release_admissions(members, profile, mode)
            })
        })
}

fn append_draft_release_admissions(
    members: &mut Vec<BundleMemberV1>,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<(), Box<dyn Error>> {
    let execution_mode = match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
    };
    profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.family == FixtureFamilyV1::Downgrade)
        .filter(|fixture| fixture.modes.contains(&execution_mode))
        .try_for_each(|fixture| {
            let transition = embedded_catalog_option(fixture.transition.as_ref());
            let trust_snapshot = embedded_catalog_option(fixture.trust_policy_snapshot_digest);
            release_admission_bytes(
                &fixture.case_id,
                fixture.execution_profile_digest,
                trust_snapshot,
                &transition.from,
                &transition.to,
            )
            .map(|bytes| {
                members.push(BundleMemberV1::supporting(
                    format!(
                        "authority/release-admissions/{}-{}.rad1",
                        fixture.case_id,
                        pos_conformance::hex_digest(&fixture.execution_profile_digest)
                    ),
                    bytes,
                    BundleMemberRoleV1::ReleaseAdmission,
                ));
            })
        })
}

#[cfg(test)]
fn tested<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("test setup failed: {error:?}"))
}

#[cfg(test)]
fn first_catalog_input() -> CatalogEntryInput {
    tested(catalog_entry_input(&LAYER_SOURCES[0]))
}

#[cfg(test)]
#[test]
#[should_panic(expected = "test setup failed")]
fn tested_reports_setup_failures() {
    tested::<(), _>(Err("intentional setup failure"));
}

#[cfg(test)]
#[test]
fn embedded_catalog_uses_manifest_owned_identity_modes_and_fixtures() {
    let catalog = tested(layer_catalog());
    assert_eq!(catalog.entries.len(), 7);
    assert_eq!(catalog.bundle_modes, CatalogBundleMode::ALL);
    assert!(catalog.entries.iter().all(|entry| {
        entry.name == entry.claim_layer.catalog_name()
            && entry.bundle_modes == CatalogBundleMode::ALL
            && entry.execution_profiles == CatalogExecutionProfile::ALL
            && entry.fixtures.len() == CatalogFixtureFamily::ALL.len()
    }));
}

#[cfg(test)]
#[test]
fn catalog_identity_rejects_each_conflicting_manifest_field() {
    let mut input = first_catalog_input();
    input.record.claim_layer = "replay-conformance".to_owned();
    assert!(catalog_identity(&input.record).is_err());

    let mut input = first_catalog_input();
    input.record.fixture_root = "other-root".to_owned();
    assert!(catalog_identity(&input.record).is_err());

    let mut input = first_catalog_input();
    input.record.wire_code = u8::MAX;
    assert!(catalog_identity(&input.record).is_err());

    let mut input = first_catalog_input();
    input.record.subject_adapter = "private-helper".to_owned();
    assert!(catalog_identity(&input.record).is_err());
}

#[cfg(test)]
#[test]
fn catalog_fixture_rejects_conflicting_public_records() {
    let input = first_catalog_input();
    let record = &input.record.fixtures[0];
    let contract = &input.fixture_provider.fixture_contracts[&record.family];
    let source = &LAYER_SOURCES[0].fixtures[0];
    let provider_contract = format!(
        "{}@{}",
        input.fixture_provider.provider_id, input.fixture_provider.contract_version
    );
    let operation = input.fixture_provider.fixture_operations[&record.family].as_deref();
    assert!(catalog_fixture(
        record,
        source,
        contract,
        &provider_contract,
        &input.record.subject_adapter,
        operation,
    )
    .is_ok());
    assert!(catalog_fixture(
        record,
        source,
        contract,
        "wrong-provider@1.0.0",
        &input.record.subject_adapter,
        operation,
    )
    .is_err());
    assert!(catalog_fixture(
        record,
        source,
        contract,
        &provider_contract,
        &input.record.subject_adapter,
        Some("wrong-operation"),
    )
    .is_err());
}

#[cfg(test)]
#[test]
fn catalog_entry_rejects_profile_and_provider_drift() {
    let source = &LAYER_SOURCES[0];
    let mut profile: serde_json::Value = tested(serde_json::from_slice(source.profile_record));
    profile["bundle_modes"] = serde_json::json!(["air-gapped", "local"]);
    let profile = Box::leak(tested(serde_json::to_vec(&profile)).into_boxed_slice());
    let changed = LayerSource {
        profile_record: profile,
        provider_record: source.provider_record,
        fixtures: source.fixtures,
    };
    assert!(catalog_entry(&changed).is_err());

    let mut profile: serde_json::Value = tested(serde_json::from_slice(source.profile_record));
    profile["execution_profiles"] = serde_json::json!(["deterministic-local-v1"]);
    let profile = Box::leak(tested(serde_json::to_vec(&profile)).into_boxed_slice());
    let changed = LayerSource {
        profile_record: profile,
        provider_record: source.provider_record,
        fixtures: source.fixtures,
    };
    assert!(catalog_entry(&changed).is_err());

    let mut provider: serde_json::Value = tested(serde_json::from_slice(source.provider_record));
    provider["claim_layer"] = serde_json::Value::String("replay-conformance".to_owned());
    let provider = Box::leak(tested(serde_json::to_vec(&provider)).into_boxed_slice());
    let changed = LayerSource {
        profile_record: source.profile_record,
        provider_record: provider,
        fixtures: source.fixtures,
    };
    assert!(catalog_entry(&changed).is_err());

    let mut input = first_catalog_input();
    input
        .fixture_provider
        .fixture_contracts
        .remove(&CatalogFixtureFamily::Positive);
    assert!(catalog_fixtures(source, &input.record, &input.fixture_provider).is_err());

    let mut input = first_catalog_input();
    input
        .fixture_provider
        .fixture_operations
        .remove(&CatalogFixtureFamily::Positive);
    assert!(catalog_fixtures(source, &input.record, &input.fixture_provider).is_err());

    let mut input = first_catalog_input();
    input
        .fixture_provider
        .schemas
        .remove(&CatalogFixtureFamily::Positive);
    assert!(catalog_fixtures(source, &input.record, &input.fixture_provider).is_err());

    let mut provider: serde_json::Value = tested(serde_json::from_slice(source.provider_record));
    provider["schemas"]["positive"] = serde_json::Value::String("wrong-schema.json".to_owned());
    let provider = Box::leak(tested(serde_json::to_vec(&provider)).into_boxed_slice());
    let changed = LayerSource {
        profile_record: source.profile_record,
        provider_record: provider,
        fixtures: source.fixtures,
    };
    assert!(catalog_entry(&changed).is_err());

    let entries = LAYER_SOURCES
        .iter()
        .map(catalog_entry)
        .collect::<Result<Vec<_>, _>>();
    let mut entries = tested(entries);
    entries[0].bundle_modes = [CatalogBundleMode::AirGapped, CatalogBundleMode::Local];
    assert!(finish_layer_catalog(entries).is_err());
}

#[cfg(test)]
#[test]
fn draft_authority_rejects_mismatched_signing_key_and_unknown_classes() {
    assert!(authority_signing_key([0; 32]).is_err());
    assert!(authority_signing_key(DRAFT_AUTHORITY_PUBLIC_KEY_BYTES).is_ok());

    let mut declaration: serde_json::Value = tested(serde_json::from_slice(include_bytes!(
        "../../../../fixtures/conformance/support/draft-execution-authority.json"
    )));
    declaration["execution_profiles"][0]["reproducibility_classes"][0] =
        serde_json::Value::String("UnknownClass".to_owned());
    assert!(serde_json::from_value::<DraftAuthorityDeclaration>(declaration).is_err());
}
fn verify_public_archive(
    archive_bytes: &[u8],
    release_filename: &str,
) -> Result<(), Box<dyn Error>> {
    ConformanceBundleV1::from_canonical_cbor(archive_bytes)
        .map_err(Into::into)
        .and_then(|_| {
            verify_archive_release_filename(archive_bytes, release_filename).map_err(Into::into)
        })
}
