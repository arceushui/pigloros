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
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use std::error::Error;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error as ThisError;

include!("materialize-conformance-bundles/atomic_publication.rs");

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
    schemas: Vec<PublicArtifact>,
    artifact: PublicArtifact,
}

struct ProviderCatalog {
    registry: PublicArtifact,
    packages: Vec<ProviderPackage>,
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
    let package_support = package_support_artifacts();
    let mut packages = catalog
        .entries
        .iter()
        .map(|layer| provider_package(layer, &package_support))
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
        package_support,
    })
}

fn provider_package(
    layer: &LayerCatalogEntry,
    package_support: &[PublicArtifact; 5],
) -> Result<ProviderPackage, Box<dyn Error>> {
    let provider_key = FixtureProviderKeyV1 {
        provider_id: layer.fixture_provider.provider_id.clone(),
        contract_version: layer.fixture_provider.contract_version.clone(),
        abi_major: layer.fixture_provider.abi_major,
        abi_minor: layer.fixture_provider.abi_minor,
    };
    let schemas = provider_schema_artifacts(layer)?;
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
        schemas,
        artifact,
    })
}

fn provider_schema_artifacts(
    layer: &LayerCatalogEntry,
) -> Result<Vec<PublicArtifact>, Box<dyn Error>> {
    let mut schemas = std::collections::BTreeMap::new();
    for fixture in &layer.fixtures {
        let artifact = public_artifact(
            &fixture.record.schema,
            "application/schema+json",
            fixture.schema,
        );
        if schemas.insert(fixture.record.family, artifact).is_some() {
            return Err("provider defines a fixture family schema more than once".into());
        }
    }
    if schemas.len() != REQUIRED_FIXTURE_FAMILIES {
        return Err("provider must define exactly seven family schemas".into());
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
    let providers = provider_catalog(&catalog)?;
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
        .and_then(|bundle| bundle.sign(context.signing_key))
        .map_err(Into::into)
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
    let oracle_output_path =
        oracle_output_member_path(&fixture.record.case_id, &execution_profile_digest);
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
    let oracle_output =
        artifact_descriptor(&oracle_output_path, "application/json", fixture.expected);
    let expectation = fixture_expectation(fixture, &oracle_output);
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

fn oracle_output_member_path(case_id: &str, execution_profile_digest: &[u8; 32]) -> String {
    format!(
        "oracles/{case_id}/{}.json",
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
        if let Some(output) = fixture.strict_oracle.output.as_ref() {
            let output_path =
                oracle_output_member_path(&fixture.case_id, &fixture.execution_profile_digest);
            if output != &artifact_descriptor(&output_path, "application/json", source.expected) {
                return Err(
                    "profile strict-oracle descriptor disagrees with public catalog asset".into(),
                );
            }
            members.push(BundleMemberV1::expected_result(
                output_path,
                source.expected.to_vec(),
            ));
        }
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
        .map_err(Into::into)
        .and_then(|_| {
            verify_archive_release_filename(archive_bytes, release_filename).map_err(Into::into)
        })
}
