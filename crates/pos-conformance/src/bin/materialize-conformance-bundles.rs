#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
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
#[cfg(target_os = "linux")]
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, ResolveFlags, CWD};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use std::error::Error;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use thiserror::Error as ThisError;

const MATERIALIZATION_METADATA_PATH: &str = "MATERIALIZATION-METADATA.json";
const OUTPUT_CHECKSUM_INVENTORY_PATH: &str = "SHA256SUMS";
const REQUIRED_FIXTURE_FAMILIES: usize = 7;
#[derive(Clone, Copy)]
struct FixtureContext {
    claim_layer: ClaimLayerV1,
    profile_record_digest: [u8; 32],
    provenance_digest: [u8; 32],
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
}

struct LayerSource {
    profile_record: &'static [u8],
    fixtures: &'static [FixtureSource],
}

include!(concat!(env!("OUT_DIR"), "/conformance_fixture_catalog.rs"));

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

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum CatalogExecutionProfile {
    DeterministicLocalV1,
    DeterministicAirGappedV1,
}

impl CatalogExecutionProfile {
    const fn name(self) -> &'static str {
        match self {
            Self::DeterministicLocalV1 => "deterministic-local-v1",
            Self::DeterministicAirGappedV1 => "deterministic-air-gapped-v1",
        }
    }

    fn digest(self) -> [u8; 32] {
        labeled_digest("PiglorOS.ExecutionProfile.v1", self.name().as_bytes())
    }

    const fn execution_mode(self) -> pos_conformance::ExecutionModeV1 {
        match self {
            Self::DeterministicLocalV1 => pos_conformance::ExecutionModeV1::Local,
            Self::DeterministicAirGappedV1 => pos_conformance::ExecutionModeV1::AirGapped,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
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
    const ALL: [Self; REQUIRED_FIXTURE_FAMILIES] = [
        Self::Positive,
        Self::Denied,
        Self::Malformed,
        Self::ResourceExhaustion,
        Self::DeletionRedaction,
        Self::Downgrade,
        Self::IndependentEvaluation,
    ];

    const fn name(self) -> &'static str {
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
    wire_code: u8,
    subject_adapter: String,
    fixture_provider: FixtureProviderRecord,
    fixtures: Vec<ProfileFixtureRecord>,
    execution_profiles: [CatalogExecutionProfile; 2],
}

#[derive(Deserialize)]
struct ProfileFixtureRecord {
    case_id: String,
    claim_layer: String,
    family: CatalogFixtureFamily,
    schema: String,
    input: String,
    expected: String,
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
struct FixtureExpectedRecord {
    draft_expected_result: CatalogStrictOracle,
}

#[derive(Clone, Deserialize)]
struct FixtureProviderRecord {
    provider_id: String,
    contract_version: String,
    abi_major: u16,
    abi_minor: u16,
    package_path: String,
}

struct CatalogFixture {
    record: ProfileFixtureRecord,
    schema: &'static [u8],
    input: &'static [u8],
    expected: &'static [u8],
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
}

struct LayerCatalog {
    entries: Vec<LayerCatalogEntry>,
    bundle_modes: [CatalogBundleMode; 2],
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
    artifact: PublicArtifact,
}

struct ProviderCatalog {
    registry: PublicArtifact,
    packages: Vec<ProviderPackage>,
    schemas: Vec<PublicArtifact>,
    package_support: [PublicArtifact; 5],
}

impl ProviderCatalog {
    fn binding_for(&self, provider_key: FixtureProviderKeyV1) -> FixtureProviderRegistryBindingV1 {
        FixtureProviderRegistryBindingV1 {
            registry_artifact: self.registry.descriptor(),
            required_provider_keys: vec![provider_key],
        }
    }

    fn materialized_files(&self) -> Vec<MaterializedFile> {
        self.schemas
            .iter()
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

fn package_support_artifacts() -> [PublicArtifact; 5] {
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
            "support/provenance.json",
            "application/json",
            include_bytes!("../../../../fixtures/conformance/support/provenance.json"),
        ),
        public_artifact(
            "support/limitations.md",
            "text/markdown",
            include_bytes!("../../../../fixtures/conformance/support/limitations.md"),
        ),
    ]
}

fn provider_catalog(catalog: &LayerCatalog) -> Result<ProviderCatalog, Box<dyn Error>> {
    let schemas = provider_schema_artifacts(catalog)?;
    let package_support = package_support_artifacts();
    let mut packages = catalog
        .entries
        .iter()
        .map(|layer| provider_package(layer, &schemas, &package_support))
        .collect::<Result<Vec<_>, _>>()?;
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
    registry.registry_digest = registry.digest()?;
    registry
        .providers
        .iter()
        .zip(&packages)
        .try_for_each(|(entry, catalog_package)| {
            FixtureProviderPackageV1::from_canonical_cbor(&catalog_package.artifact.bytes).and_then(
                |decoded| decoded.validate_registry_binding(entry, &catalog_package.artifact.bytes),
            )
        })?;
    let registry = public_artifact(
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
        "application/cbor",
        &registry.to_canonical_cbor()?,
    );
    Ok(ProviderCatalog {
        registry,
        packages,
        schemas,
        package_support,
    })
}

fn provider_package(
    layer: &LayerCatalogEntry,
    schemas: &[PublicArtifact],
    package_support: &[PublicArtifact; 5],
) -> Result<ProviderPackage, Box<dyn Error>> {
    let provider_key = FixtureProviderKeyV1 {
        provider_id: layer.fixture_provider.provider_id.clone(),
        contract_version: layer.fixture_provider.contract_version.clone(),
        abi_major: layer.fixture_provider.abi_major,
        abi_minor: layer.fixture_provider.abi_minor,
    };
    let [licence, notices, sbom, source_provenance, limitations] = package_support;
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
    package.package_digest = package.digest()?;
    let artifact = public_artifact(
        &layer.fixture_provider.package_path,
        "application/cbor",
        &package.to_canonical_cbor()?,
    );
    Ok(ProviderPackage {
        provider_key,
        claim_layer: layer.claim_layer,
        subject_adapter: layer.subject_adapter,
        artifact,
    })
}

fn provider_schema_artifacts(
    catalog: &LayerCatalog,
) -> Result<Vec<PublicArtifact>, Box<dyn Error>> {
    let mut schemas = std::collections::BTreeMap::new();
    for fixture in catalog.entries.iter().flat_map(|entry| &entry.fixtures) {
        let artifact = public_artifact(
            &fixture.record.schema,
            "application/schema+json",
            fixture.schema,
        );
        if schemas
            .insert(fixture.record.family, artifact.clone())
            .is_some_and(|existing: PublicArtifact| {
                existing.path != artifact.path || existing.bytes != artifact.bytes
            })
        {
            return Err("fixture family schemas differ between providers".into());
        }
    }
    if schemas.len() != REQUIRED_FIXTURE_FAMILIES {
        return Err("provider catalog must define exactly seven family schemas".into());
    }
    CatalogFixtureFamily::ALL
        .into_iter()
        .map(|family| {
            schemas.remove(&family).ok_or_else(|| {
                Box::<dyn Error>::from("provider catalog is missing a family schema")
            })
        })
        .collect()
}

fn layer_catalog() -> Result<LayerCatalog, Box<dyn Error>> {
    let entries = LAYER_SOURCES
        .iter()
        .map(catalog_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LayerCatalog {
        entries,
        bundle_modes: CatalogBundleMode::ALL,
    })
}

fn catalog_entry(source: &LayerSource) -> Result<LayerCatalogEntry, Box<dyn Error>> {
    let record: ProfileCatalogRecord = serde_json::from_slice(source.profile_record)?;
    let claim_layer = ClaimLayerV1::from_wire_code(record.wire_code)
        .ok_or("typed layer catalog wire code is invalid")?;
    let fixtures = source
        .fixtures
        .iter()
        .zip(record.fixtures.iter())
        .map(|(fixture_source, fixture_record)| catalog_fixture(fixture_record, fixture_source))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LayerCatalogEntry {
        claim_layer,
        name: claim_layer.catalog_name(),
        profile_id: record.profile_id,
        subject_adapter: SubjectAdapterKindV1::from_catalog_name(&record.subject_adapter)
            .ok_or("typed layer catalog subject adapter is invalid")?,
        fixture_provider: record.fixture_provider,
        profile_record: source.profile_record,
        fixtures,
        execution_profiles: record.execution_profiles,
    })
}

fn catalog_fixture(
    record: &ProfileFixtureRecord,
    source: &FixtureSource,
) -> Result<CatalogFixture, Box<dyn Error>> {
    let expected: FixtureExpectedRecord = serde_json::from_slice(source.expected)?;
    Ok(CatalogFixture {
        record: ProfileFixtureRecord {
            case_id: record.case_id.clone(),
            claim_layer: record.claim_layer.clone(),
            family: record.family,
            schema: record.schema.clone(),
            input: record.input.clone(),
            expected: record.expected.clone(),
        },
        schema: source.schema,
        input: source.input,
        expected: source.expected,
        strict_oracle: expected.draft_expected_result,
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
    let providers = provider_catalog(&catalog)
        .map_err(|error| contextual_error("provider catalog", error))?;
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
        .and_then(|mut outputs| {
            let archives = outputs
                .iter()
                .filter(|output| output.archive_release_filename.is_some())
                .map(|output| output.bytes.as_slice())
                .collect::<Vec<_>>();
            verify_release_tree_independently(&archives).map_err(Box::<dyn Error>::from)?;
            let published_file_count = outputs.len().saturating_add(2);
            outputs.push(materialization_metadata(&catalog, published_file_count));
            outputs.push(output_checksum_inventory(&outputs));
            Ok(outputs)
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
    let mut profile = profile_from_catalog(layer, context.providers);
    profile.lifecycle = ProfileLifecycleV1::Draft;
    profile.profile_digest = profile.digest();
    let prefix = format!("{}/draft", layer.name);
    profile
        .to_canonical_cbor()
        .map_err(|error| contextual_error("CPF1 profile encoding", error))
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
}

fn signed_bundle(
    context: &MaterializationContext<'_>,
    layer: &LayerCatalogEntry,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<ConformanceBundleV1, Box<dyn Error>> {
    let (members, expected_results) = bundle_inputs_from_profile(
        layer,
        profile,
        mode,
        context.inventory_bytes,
        context.providers,
    )?;
    ConformanceBundleV1::materialize(profile, mode, members, expected_results)
        .map_err(|error| contextual_error("CFB1 bundle materialization", error))
        .and_then(|bundle| {
            bundle
                .sign(context.signing_key)
                .map_err(|error| contextual_error("CFB1 bundle signing", error))
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
    let provenance = include_bytes!("../../../../fixtures/conformance/support/provenance.json");
    let limitations = include_bytes!("../../../../fixtures/conformance/support/limitations.md");
    let provenance_digest = *blake3::hash(provenance).as_bytes();
    let notice_digest = *blake3::hash(notice).as_bytes();
    let sbom_digest = *blake3::hash(sbom).as_bytes();
    let limitations_digest = *blake3::hash(limitations).as_bytes();
    FixtureContext {
        claim_layer,
        profile_record_digest,
        provenance_digest,
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
) -> Vec<FixtureDescriptorV1> {
    let mut fixtures = Vec::with_capacity(layer.fixtures.len() * layer.execution_profiles.len());
    for fixture in &layer.fixtures {
        fixtures.extend(layer.execution_profiles.map(|execution_profile| {
            fixture_descriptor_from_record(
                layer,
                fixture,
                context,
                provider_key,
                execution_profile.digest(),
                execution_profile.execution_mode(),
            )
        }));
    }
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
}

fn profile_from_catalog(
    layer: &LayerCatalogEntry,
    providers: &ProviderCatalog,
) -> ConformanceProfileV1 {
    let context = fixture_context(layer.profile_record, layer.claim_layer);
    let provider_key = FixtureProviderKeyV1 {
        provider_id: layer.fixture_provider.provider_id.clone(),
        contract_version: layer.fixture_provider.contract_version.clone(),
        abi_major: layer.fixture_provider.abi_major,
        abi_minor: layer.fixture_provider.abi_minor,
    };
    let fixtures = fixtures_for_layer(layer, &context, &provider_key);
    let mut execution_profile_digests = layer
        .execution_profiles
        .map(CatalogExecutionProfile::digest)
        .to_vec();
    execution_profile_digests.sort_unstable();
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
            trust_policy_snapshot_digest: labeled_digest(
                "PiglorOS.TrustPolicySnapshot.v1",
                layer.profile_record,
            ),
            requirements_digest: labeled_digest(
                "PiglorOS.IndependenceRequirements.v1",
                layer.profile_record,
            ),
        },
        fixture_contract_policy_digest: labeled_digest(
            "PiglorOS.FixtureContractPolicy.v1",
            layer.profile_record,
        ),
        limitations_digest: context.limitations_digest,
        provenance_digest: context.provenance_digest,
        previous_profile_digest: None,
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    profile
}

fn fixture_descriptor_from_record(
    layer: &LayerCatalogEntry,
    fixture: &CatalogFixture,
    context: &FixtureContext,
    provider_key: &FixtureProviderKeyV1,
    execution_profile_digest: [u8; 32],
    mode: pos_conformance::ExecutionModeV1,
) -> FixtureDescriptorV1 {
    let payload_path =
        fixture_payload_member_path(&fixture.record.case_id, &execution_profile_digest);
    let expected_path = expected_result_member_path(
        &fixture.record.case_id,
        context.claim_layer,
        &execution_profile_digest,
    );
    let fixture_record = serde_json::json!({
        "case_id": &fixture.record.case_id,
        "claim_layer": &fixture.record.claim_layer,
        "expected": &fixture.record.expected,
        "family": fixture.record.family.name(),
        "schema": &fixture.record.schema,
        "input": &fixture.record.input,
    })
    .to_string();
    let fixture_record_digest =
        labeled_digest("PiglorOS.CPF1FixtureRecord.v1", fixture_record.as_bytes());
    let auxiliary = artifact_descriptor(&expected_path, "application/json", fixture.expected);
    let expectation = fixture_expectation(fixture, &auxiliary);
    let downgrade = fixture.record.family == CatalogFixtureFamily::Downgrade;
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
        auxiliary: vec![auxiliary],
        strict_oracle: expectation.strict_oracle,
        expected_verification_outcome: expectation.verification_outcome,
        expected_verification_error: expectation.verification_error,
        replay_claim: expectation.replay_claim,
        redaction_state: expectation.redaction_state,
        deterministic_budget: fixture_budget(),
        operational_safety: fixture_operational_safety(),
        capability_policy: fixture_capability_policy(fixture.record.family),
        provenance: fixture_provenance(context),
        trust_policy_snapshot_digest: downgrade.then(|| {
            labeled_digest(
                "PiglorOS.DowngradeTrustPolicy.v1",
                &[
                    context.profile_record_digest.as_slice(),
                    fixture_record_digest.as_slice(),
                ]
                .concat(),
            )
        }),
        release_admission_digest: downgrade.then(|| {
            labeled_digest(
                "PiglorOS.DowngradeReleaseAdmission.v1",
                &[
                    context.profile_record_digest.as_slice(),
                    fixture_record_digest.as_slice(),
                ]
                .concat(),
            )
        }),
        transition: downgrade.then(|| FixtureContractTransitionV1 {
            from: FixtureProviderKeyV1 {
                provider_id: provider_key.provider_id.clone(),
                contract_version: provider_key.contract_version.clone(),
                abi_major: provider_key.abi_major,
                abi_minor: 1,
            },
            to: provider_key.clone(),
        }),
        fixture_digest: [0; 32],
    };
    descriptor.fixture_digest = descriptor.digest();
    descriptor
}

fn fixture_expectation(
    fixture: &CatalogFixture,
    auxiliary: &ArtifactDescriptorV1,
) -> FixtureExpectation {
    let (strict_oracle, verification_outcome, verification_error) =
        match &fixture.strict_oracle {
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

const fn fixture_budget() -> DeterministicBudgetV1 {
    DeterministicBudgetV1 {
        memory_bytes: 64 * 1024 * 1024,
        cpu_fuel: 10_000_000,
        host_calls: 10_000,
        event_count: 100_000,
        output_bytes: 16 * 1024 * 1024,
        storage_bytes: 64 * 1024 * 1024,
        execution_steps: 10_000_000,
        simulation_time_ns: 60_000_000_000,
    }
}

const fn fixture_operational_safety() -> OperationalSafetyV1 {
    OperationalSafetyV1 {
        watchdog_ms: 120_000,
    }
}

fn fixture_capability_policy(family: CatalogFixtureFamily) -> CapabilityPolicyV1 {
    let capability = match family {
        CatalogFixtureFamily::Denied => None,
        CatalogFixtureFamily::DeletionRedaction => Some("redact-synthetic-subject"),
        CatalogFixtureFamily::Downgrade => Some("verify-release-admission"),
        _ => Some("read-public-bundle"),
    };
    CapabilityPolicyV1 {
        network_allowed: false,
        capability_ids: capability.into_iter().map(str::to_owned).collect(),
    }
}

fn fixture_provenance(context: &FixtureContext) -> FixtureProvenanceV1 {
    FixtureProvenanceV1 {
        licence_id: "MIT".to_owned(),
        notices_digest: context.notice_digest,
        sbom_digest: context.sbom_digest,
        source_digest: context.provenance_digest,
        build_digest: context.provenance_digest,
        publication_review_digest: context.provenance_digest,
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
        let source = layer
            .fixtures
            .iter()
            .find(|source| source.record.case_id == fixture.case_id)
            .ok_or("profile fixture is absent from the typed layer catalog")?;
        let expected_payload_path =
            fixture_payload_member_path(&fixture.case_id, &fixture.execution_profile_digest);
        if fixture.schema
            != artifact_descriptor(
                &source.record.schema,
                "application/schema+json",
                source.schema,
            )
            || fixture.payload
                != artifact_descriptor(&expected_payload_path, "application/json", source.input)
        {
            return Err("profile fixture descriptors disagree with public catalog assets".into());
        }
        members.push(BundleMemberV1::fixture_input(
            fixture.payload.member_path.clone(),
            source.input.to_vec(),
        ));
        let path = expected_result_member_path(
            &fixture.case_id,
            fixture.claim_layer,
            &fixture.execution_profile_digest,
        );
        if fixture.auxiliary.as_slice()
            != [artifact_descriptor(
                &path,
                "application/json",
                source.expected,
            )]
        {
            return Err(
                "profile expected-result descriptor disagrees with public catalog asset".into(),
            );
        }
        let member = BundleMemberV1::expected_result(path.clone(), source.expected.to_vec());
        expected_results.push(BundleExpectedResultV1 {
            case_id: fixture.case_id.clone(),
            claim_layer: fixture.claim_layer,
            execution_profile_digest: fixture.execution_profile_digest,
            mode,
            member_path: path,
            digest: member.digest,
        });
        members.push(member);
    }
    expected_results.sort();
    append_supporting_members(&mut members, inventory_bytes, providers);
    Ok((members, expected_results))
}

fn append_supporting_members(
    members: &mut Vec<BundleMemberV1>,
    inventory_bytes: &[u8],
    providers: &ProviderCatalog,
) {
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
            "support/provenance.json",
            include_bytes!("../../../../fixtures/conformance/support/provenance.json").as_slice(),
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
    for schema in &providers.schemas {
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
    members.push(BundleMemberV1::fixture_provider_registry(
        providers.registry.bytes.clone(),
    ));
    for package in &providers.packages {
        members.push(BundleMemberV1::fixture_provider_package(
            package.artifact.path.clone(),
            package.artifact.bytes.clone(),
        ));
    }
}

fn verify_public_archive(
    archive_bytes: &[u8],
    release_filename: &str,
) -> Result<(), Box<dyn Error>> {
    ConformanceBundleV1::from_canonical_cbor(archive_bytes)
        .map_err(|error| contextual_error("typed CFB1 verification", error))
        .and_then(|_| {
            verify_archive_release_filename(archive_bytes, release_filename)
                .map_err(|error| contextual_error("independent CFB1 verification", error))
        })
}

fn contextual_error(context: &str, error: impl std::fmt::Display) -> Box<dyn Error> {
    format!("{context}: {error}").into()
}

#[cfg(target_os = "linux")]
struct AtomicPublication {
    parent: OwnedFd,
    staging: OwnedFd,
    staging_name: CString,
    destination_name: CString,
    parent_identity: DirectoryIdentity,
    staging_identity: DirectoryIdentity,
    staging_present: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
struct RelativeFilePath {
    directories: Vec<CString>,
    file_name: CString,
}

#[cfg(target_os = "linux")]
struct VerifiedPublication(AtomicPublication);

#[cfg(not(target_os = "linux"))]
struct AtomicPublication;

#[cfg(not(target_os = "linux"))]
impl AtomicPublication {
    const fn prepare(_destination: &Path) -> Result<Self, MaterializationError> {
        Err(MaterializationError::AtomicPublicationUnsupported)
    }
}

#[cfg(target_os = "linux")]
impl AtomicPublication {
    fn prepare(destination: &Path) -> Result<Self, MaterializationError> {
        output_parent_and_name(destination).and_then(|(parent_path, destination_name)| {
            let effective_uid = effective_uid();
            open_trusted_parent(parent_path, effective_uid).and_then(|(parent, parent_identity)| {
                create_private_staging(&parent, parent_identity, effective_uid).map(
                    |(staging_name, staging, staging_identity)| Self {
                        parent,
                        staging,
                        staging_name,
                        destination_name,
                        parent_identity,
                        staging_identity,
                        staging_present: true,
                    },
                )
            })
        })
    }

    fn write_file(&self, relative_path: &str, bytes: &[u8]) -> Result<(), MaterializationError> {
        relative_file_path(Path::new(relative_path)).and_then(|path| {
            self.write_parent(&path.directories).and_then(|directory| {
                let flags = OFlags::WRONLY
                    .union(OFlags::CREATE)
                    .union(OFlags::EXCL)
                    .union(OFlags::CLOEXEC)
                    .union(OFlags::NOFOLLOW);
                open_at2(
                    &directory,
                    &path.file_name,
                    flags,
                    Mode::from_raw_mode(0o600),
                    ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
                )
                .and_then(|fd| {
                    let mut file: File = fd.into();
                    file.write_all(bytes)
                        .map_err(|_| MaterializationError::DurabilitySyncFailed)
                        .and_then(|()| sync_fd(&file))
                        .and_then(|()| sync_fd(&directory))
                })
            })
        })
    }

    fn write_parent(&self, directories: &[CString]) -> Result<OwnedFd, MaterializationError> {
        duplicate_fd(&self.staging).and_then(|directory| {
            directories.iter().try_fold(directory, |directory, name| {
                open_or_create_directory(&directory, name)
            })
        })
    }

    fn verify_and_sync(
        self,
        files: &[MaterializedFile],
    ) -> Result<VerifiedPublication, MaterializationError> {
        files
            .iter()
            .try_for_each(|file| {
                self.read_file(&file.relative_path).and_then(|bytes| {
                    if bytes != file.bytes {
                        return Err(MaterializationError::ArchiveDigestMismatch);
                    }
                    file.archive_release_filename
                        .as_deref()
                        .map_or(Ok(()), |release_filename| {
                            verify_public_archive(&bytes, release_filename)
                                .map_err(|_| MaterializationError::ArchiveDigestMismatch)
                        })
                })
            })
            .and_then(|()| sync_fd(&self.staging))
            .map(|()| VerifiedPublication(self))
    }

    fn read_file(&self, relative_path: &str) -> Result<Vec<u8>, MaterializationError> {
        relative_file_path(Path::new(relative_path)).and_then(|path| {
            self.read_parent(&path.directories).and_then(|directory| {
                open_at2(
                    &directory,
                    &path.file_name,
                    OFlags::RDONLY
                        .union(OFlags::CLOEXEC)
                        .union(OFlags::NOFOLLOW),
                    Mode::empty(),
                    ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
                )
                .and_then(|fd| {
                    let mut file: File = fd.into();
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes)
                        .map_err(|_| MaterializationError::ArchiveDigestMismatch)
                        .map(|_| bytes)
                })
            })
        })
    }

    fn read_parent(&self, directories: &[CString]) -> Result<OwnedFd, MaterializationError> {
        duplicate_fd(&self.staging).and_then(|directory| {
            directories.iter().try_fold(directory, |directory, name| {
                open_directory(&directory, name)
            })
        })
    }
}

#[cfg(target_os = "linux")]
impl VerifiedPublication {
    fn publish(self) -> Result<(), MaterializationError> {
        let mut publication = self.0;
        publication.revalidate_for_publish().and_then(|()| {
            fs::renameat_with(
                &publication.parent,
                publication.staging_name.as_c_str(),
                &publication.parent,
                publication.destination_name.as_c_str(),
                RenameFlags::NOREPLACE,
            )
            .map_err(map_publish_error)
            .and_then(|()| {
                publication.staging_present = false;
                sync_fd(&publication.parent)
            })
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for AtomicPublication {
    fn drop(&mut self) {
        if self.staging_present {
            drop(remove_staging_tree(
                &self.parent,
                self.parent_identity,
                &self.staging_name,
                self.staging_identity,
                effective_uid(),
            ));
        }
    }
}

#[cfg(target_os = "linux")]
fn publish_materialized_tree(
    publication: AtomicPublication,
    files: &[MaterializedFile],
) -> Result<(), MaterializationError> {
    files
        .iter()
        .try_for_each(|file| publication.write_file(&file.relative_path, &file.bytes))
        .and_then(|()| publication.verify_and_sync(files))
        .and_then(VerifiedPublication::publish)
}

#[cfg(not(target_os = "linux"))]
fn publish_materialized_tree(
    _publication: AtomicPublication,
    _files: &[MaterializedFile],
) -> Result<(), MaterializationError> {
    Err(MaterializationError::AtomicPublicationUnsupported)
}

#[cfg(target_os = "linux")]
fn output_parent_and_name(destination: &Path) -> Result<(&Path, CString), MaterializationError> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(MaterializationError::UntrustedOutputDirectory)?;
    CString::new(file_name.as_bytes())
        .map_err(|_| MaterializationError::UntrustedOutputDirectory)
        .map(|name| (parent, name))
}

#[cfg(target_os = "linux")]
fn open_trusted_parent(
    parent: &Path,
    effective_uid: u32,
) -> Result<(OwnedFd, DirectoryIdentity), MaterializationError> {
    CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| MaterializationError::UntrustedOutputDirectory)
        .and_then(|parent| {
            open_at2(
                CWD,
                &parent,
                OFlags::RDONLY
                    .union(OFlags::DIRECTORY)
                    .union(OFlags::CLOEXEC),
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
        })
        .and_then(|parent| {
            trusted_parent_identity(&parent, effective_uid).map(|identity| (parent, identity))
        })
}

#[cfg(target_os = "linux")]
fn create_private_staging(
    parent: &OwnedFd,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(CString, OwnedFd, DirectoryIdentity), MaterializationError> {
    revalidate_parent(parent, parent_identity, effective_uid)?;
    for _ in 0..16 {
        let attempt = random_staging_name().and_then(|name| {
            match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) => configure_private_staging(parent, &name, parent_identity, effective_uid)
                    .map(Some),
                Err(Errno::EXIST) => Ok(None),
                Err(error) => Err(map_open_error(error)),
            }
        });
        match attempt {
            Ok(Some(staging)) => return Ok(staging),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    Err(MaterializationError::UntrustedOutputDirectory)
}

#[cfg(target_os = "linux")]
fn configure_private_staging(
    parent: &OwnedFd,
    staging_name: &CString,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(CString, OwnedFd, DirectoryIdentity), MaterializationError> {
    let staging = match open_directory(parent, staging_name) {
        Ok(staging) => staging,
        Err(error) => {
            remove_empty_staging(parent, staging_name)?;
            return Err(error);
        }
    };
    let configured = fs::fchmod(&staging, Mode::from_raw_mode(0o700))
        .map_err(map_sync_error)
        .and_then(|()| sync_fd(&staging))
        .and_then(|()| {
            staging_identity(
                parent,
                staging_name,
                &staging,
                parent_identity,
                effective_uid,
            )
        });
    match configured {
        Ok(staging_identity) => Ok((staging_name.clone(), staging, staging_identity)),
        Err(error) => {
            drop(staging);
            remove_empty_staging(parent, staging_name)?;
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_empty_staging(parent: &OwnedFd, staging_name: &CStr) -> Result<(), MaterializationError> {
    fs::unlinkat(parent, staging_name, AtFlags::REMOVEDIR)
        .map_err(map_cleanup_error)
        .and_then(|()| sync_fd(parent))
}

#[cfg(target_os = "linux")]
fn random_staging_name() -> Result<CString, MaterializationError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| MaterializationError::AtomicPublicationUnsupported)
        .and_then(|()| {
            let suffix = blake3::hash(&random).to_hex();
            CString::new(format!(".pigloros-conformance-staging-{suffix}"))
                .map_err(|_| MaterializationError::AtomicPublicationUnsupported)
        })
}

#[cfg(target_os = "linux")]
fn relative_file_path(path: &Path) -> Result<RelativeFilePath, MaterializationError> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => CString::new(name.as_bytes())
                .map_err(|_| MaterializationError::UntrustedOutputDirectory),
            _ => Err(MaterializationError::UntrustedOutputDirectory),
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|mut components| {
            components
                .pop()
                .map(|file_name| RelativeFilePath {
                    directories: components,
                    file_name,
                })
                .ok_or(MaterializationError::UntrustedOutputDirectory)
        })
}

#[cfg(target_os = "linux")]
fn open_or_create_directory(
    parent: &OwnedFd,
    name: &CString,
) -> Result<OwnedFd, MaterializationError> {
    match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(map_open_error(error)),
    }
    sync_fd(parent).and_then(|()| open_directory(parent, name))
}

#[cfg(target_os = "linux")]
fn open_directory(parent: &OwnedFd, name: &CStr) -> Result<OwnedFd, MaterializationError> {
    open_at2(
        parent,
        name,
        OFlags::RDONLY
            .union(OFlags::DIRECTORY)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
        ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
    )
}

#[cfg(target_os = "linux")]
fn duplicate_fd(fd: &OwnedFd) -> Result<OwnedFd, MaterializationError> {
    rustix::io::dup(fd).map_err(|_| MaterializationError::UntrustedOutputDirectory)
}

#[cfg(target_os = "linux")]
fn open_at2<Fd: std::os::fd::AsFd>(
    directory_fd: Fd,
    path: &CStr,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd, MaterializationError> {
    fs::openat2(directory_fd, path, flags, mode, resolve).map_err(map_open_error)
}

#[cfg(target_os = "linux")]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(target_os = "linux")]
fn trusted_parent_identity(
    parent: &OwnedFd,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    fs::fstat(parent)
        .map_err(map_open_error)
        .and_then(|metadata| validate_trusted_parent(metadata, effective_uid))
}

#[cfg(target_os = "linux")]
fn validate_trusted_parent(
    metadata: rustix::fs::Stat,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    let mode = Mode::from_raw_mode(metadata.st_mode);
    let writable_by_others = mode.intersects(Mode::WGRP.union(Mode::WOTH));
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != effective_uid
        || !mode.contains(Mode::WUSR.union(Mode::XUSR))
        || (writable_by_others && !mode.contains(Mode::SVTX))
    {
        return Err(MaterializationError::UntrustedOutputDirectory);
    }
    Ok(directory_identity(metadata))
}

#[cfg(target_os = "linux")]
const fn directory_identity(metadata: rustix::fs::Stat) -> DirectoryIdentity {
    DirectoryIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    }
}

#[cfg(target_os = "linux")]
fn revalidate_parent(
    parent: &OwnedFd,
    expected_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(), MaterializationError> {
    trusted_parent_identity(parent, effective_uid).and_then(|actual_identity| {
        if actual_identity == expected_identity {
            Ok(())
        } else {
            Err(MaterializationError::UntrustedOutputDirectory)
        }
    })
}

#[cfg(target_os = "linux")]
fn staging_identity(
    parent: &OwnedFd,
    staging_name: &CStr,
    staging: &OwnedFd,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    fs::statat(parent, staging_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_open_error)
        .and_then(|named_metadata| {
            fs::fstat(staging)
                .map_err(map_open_error)
                .and_then(|retained_metadata| {
                    let named_identity =
                        validate_private_staging(named_metadata, parent_identity, effective_uid)?;
                    let retained_identity = validate_private_staging(
                        retained_metadata,
                        parent_identity,
                        effective_uid,
                    )?;
                    if named_identity == retained_identity {
                        Ok(named_identity)
                    } else {
                        Err(MaterializationError::UntrustedOutputDirectory)
                    }
                })
        })
}

#[cfg(target_os = "linux")]
fn validate_private_staging(
    metadata: rustix::fs::Stat,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    let mode = Mode::from_raw_mode(metadata.st_mode);
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != effective_uid
        || metadata.st_dev != parent_identity.device
        || mode != Mode::RWXU
    {
        return Err(MaterializationError::UntrustedOutputDirectory);
    }
    Ok(directory_identity(metadata))
}

#[cfg(target_os = "linux")]
impl AtomicPublication {
    fn revalidate_for_publish(&self) -> Result<(), MaterializationError> {
        revalidate_parent(&self.parent, self.parent_identity, effective_uid()).and_then(|()| {
            staging_identity(
                &self.parent,
                self.staging_name.as_c_str(),
                &self.staging,
                self.parent_identity,
                effective_uid(),
            )
            .and_then(|actual_identity| {
                if actual_identity == self.staging_identity {
                    Ok(())
                } else {
                    Err(MaterializationError::UntrustedOutputDirectory)
                }
            })
        })
    }
}

#[cfg(target_os = "linux")]
fn remove_staging_tree(
    parent: &OwnedFd,
    parent_identity: DirectoryIdentity,
    staging_name: &CStr,
    staging_identity_expected: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(), MaterializationError> {
    revalidate_parent(parent, parent_identity, effective_uid).and_then(|()| {
        open_directory(parent, staging_name).and_then(|staging| {
            staging_identity(
                parent,
                staging_name,
                &staging,
                parent_identity,
                effective_uid,
            )
            .and_then(|actual_identity| {
                if actual_identity == staging_identity_expected {
                    remove_directory_contents(&staging)
                        .and_then(|()| {
                            fs::unlinkat(parent, staging_name, AtFlags::REMOVEDIR)
                                .map_err(map_cleanup_error)
                        })
                        .and_then(|()| sync_fd(parent))
                } else {
                    Err(MaterializationError::UntrustedOutputDirectory)
                }
            })
        })
    })
}

#[cfg(target_os = "linux")]
fn remove_directory_contents(directory: &OwnedFd) -> Result<(), MaterializationError> {
    Dir::read_from(directory)
        .map_err(map_cleanup_error)
        .and_then(|mut entries| {
            entries.try_for_each(|entry| {
                entry
                    .map_err(map_cleanup_error)
                    .and_then(|entry| remove_directory_entry(directory, entry.file_name()))
            })
        })
}

#[cfg(target_os = "linux")]
fn remove_directory_entry(directory: &OwnedFd, name: &CStr) -> Result<(), MaterializationError> {
    if name.to_bytes() == b"." || name.to_bytes() == b".." {
        return Ok(());
    }
    fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_cleanup_error)
        .and_then(|metadata| match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => open_directory(directory, name).and_then(|child| {
                remove_directory_contents(&child)
                    .and_then(|()| {
                        fs::unlinkat(directory, name, AtFlags::REMOVEDIR).map_err(map_cleanup_error)
                    })
                    .and_then(|()| sync_fd(directory))
            }),
            FileType::RegularFile => open_at2(
                directory,
                name,
                OFlags::RDONLY
                    .union(OFlags::CLOEXEC)
                    .union(OFlags::NOFOLLOW),
                Mode::empty(),
                ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
            )
            .and_then(|file| {
                fs::fstat(&file)
                    .map_err(map_cleanup_error)
                    .and_then(|file_metadata| {
                        if FileType::from_raw_mode(file_metadata.st_mode) == FileType::RegularFile {
                            fs::unlinkat(directory, name, AtFlags::empty())
                                .map_err(map_cleanup_error)
                                .and_then(|()| sync_fd(directory))
                        } else {
                            Err(MaterializationError::UntrustedOutputDirectory)
                        }
                    })
            }),
            FileType::Symlink => Err(MaterializationError::SymlinkDetected),
            _ => Err(MaterializationError::UntrustedOutputDirectory),
        })
}

#[cfg(target_os = "linux")]
fn sync_fd<Fd: std::os::fd::AsFd>(fd: Fd) -> Result<(), MaterializationError> {
    fs::fsync(fd).map_err(map_sync_error)
}

#[cfg(target_os = "linux")]
const fn map_open_error(error: Errno) -> MaterializationError {
    match error {
        Errno::LOOP => MaterializationError::SymlinkDetected,
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const fn map_publish_error(error: Errno) -> MaterializationError {
    match error {
        Errno::EXIST => MaterializationError::DestinationExists,
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const fn map_sync_error(error: Errno) -> MaterializationError {
    match error {
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::DurabilitySyncFailed,
    }
}

#[cfg(target_os = "linux")]
const fn map_cleanup_error(error: Errno) -> MaterializationError {
    match error {
        Errno::LOOP => MaterializationError::SymlinkDetected,
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const _: () = {
    assert!(matches!(
        map_open_error(Errno::LOOP),
        MaterializationError::SymlinkDetected
    ));
    assert!(matches!(
        map_open_error(Errno::NOSYS),
        MaterializationError::AtomicPublicationUnsupported
    ));
    assert!(matches!(
        map_open_error(Errno::INVAL),
        MaterializationError::AtomicPublicationUnsupported
    ));
    assert!(matches!(
        map_publish_error(Errno::EXIST),
        MaterializationError::DestinationExists
    ));
    assert!(matches!(
        map_publish_error(Errno::NOSYS),
        MaterializationError::AtomicPublicationUnsupported
    ));
    assert!(matches!(
        map_publish_error(Errno::INVAL),
        MaterializationError::AtomicPublicationUnsupported
    ));
};
