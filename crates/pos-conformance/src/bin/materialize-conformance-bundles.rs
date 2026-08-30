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
use sha2::{Digest as Sha2Digest, Sha256};
use std::error::Error;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error as ThisError;

#[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    #[error("destination already exists")]
    DestinationExists,
    #[cfg(target_os = "linux")]
    #[error("untrusted output directory")]
    UntrustedOutputDirectory,
    #[cfg(target_os = "linux")]
    #[error("symbolic link detected in output path")]
    SymlinkDetected,
    #[error("atomic publication is unsupported")]
    AtomicPublicationUnsupported,
    #[cfg(target_os = "linux")]
    #[error("durability synchronization failed")]
    DurabilitySyncFailed,
    #[cfg(target_os = "linux")]
    #[error("staged archive digest mismatch")]
    ArchiveDigestMismatch,
    #[error("destination is not addressed by the source inventory digest")]
    SourceInventoryAddressMismatch,
}

include!(concat!(env!("OUT_DIR"), "/materialization_assets.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

const EXECUTION_MODES: [pos_conformance::ExecutionModeV1; 2] = [
    pos_conformance::ExecutionModeV1::Local,
    pos_conformance::ExecutionModeV1::AirGapped,
];

// This seed is repository test-fixture authority only.  It is never a
// deployment trust root and is used solely to make Draft evidence reproducible.
const DRAFT_FIXTURE_AUTHORITY_SIGNING_BYTES: [u8; 32] = [7; 32];

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
    let declaration = DRAFT_EXECUTION_PROFILES
        .iter()
        .find(|candidate| candidate.profile_id == profile.name())
        .ok_or("Draft authority omits an execution profile")?;
    let reproducibility_classes = declaration
        .reproducibility_classes
        .iter()
        .copied()
        .map(|code| Value::Integer(code.into()))
        .collect::<Vec<_>>();
    let fields = vec![
        Value::Text("EPF1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(declaration.profile_id.to_owned()),
        Value::Text(declaration.semantic_version.to_owned()),
        Value::Array(reproducibility_classes),
        Value::Bool(declaration.network_allowed),
        Value::Array(
            declaration
                .capability_ids
                .iter()
                .map(|capability| Value::Text((*capability).to_owned()))
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
    let key = authority_signing_key(DRAFT_AUTHORITY_PUBLIC_KEY_BYTES)?;
    let fields = vec![
        Value::Text("TPS1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(DRAFT_AUTHORITY_TRUST_POLICY_ID.to_owned()),
        Value::Integer(DRAFT_AUTHORITY_TRUST_POLICY_EPOCH.into()),
        Value::Integer(DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION.into()),
        Value::Text(DRAFT_AUTHORITY_KEY_ID.to_owned()),
        Value::Bytes(DRAFT_AUTHORITY_PUBLIC_KEY_BYTES.to_vec()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Text(DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH.to_owned()),
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
        Value::Text(DRAFT_AUTHORITY_KEY_ID.to_owned()),
    ];
    cbor_bytes(&Value::Array(fields.clone())).and_then(|unsigned| {
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(key.sign(&unsigned).to_bytes().to_vec()));
        cbor_bytes(&Value::Array(signed_fields))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone)]
enum CatalogStrictOracle {
    CanonicalOutput,
    NamespacedFailure {
        owner_id: &'static str,
        contract_version: &'static str,
        code_id: &'static str,
    },
}

struct FixtureProvider {
    provider_id: &'static str,
    contract_version: &'static str,
    abi_major: u16,
    abi_minor: u16,
    package_path: &'static str,
    schema_media_type: &'static str,
    payload_media_type: &'static str,
    oracle_media_type: &'static str,
}

struct CatalogFixtureContract {
    deterministic_budget: DeterministicBudgetV1,
    watchdog_ms: u64,
    network_allowed: bool,
    minimum_capability_ids: &'static [&'static str],
}

struct CatalogFixture {
    case_id: &'static str,
    family: FixtureFamilyV1,
    schema_path: &'static str,
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
    profile_id: &'static str,
    subject_adapter: SubjectAdapterKindV1,
    fixture_provider: FixtureProvider,
    profile_record: &'static [u8],
    fixtures: Vec<CatalogFixture>,
}

struct LayerCatalog {
    entries: Vec<LayerCatalogEntry>,
}

include!(concat!(env!("OUT_DIR"), "/conformance_fixture_catalog.rs"));

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

fn package_support_artifacts() -> [PublicArtifact; 7] {
    [
        public_artifact(
            "support/LICENSE",
            "text/plain",
            MATERIALIZATION_LICENSE_BYTES,
        ),
        public_artifact("support/NOTICE", "text/plain", MATERIALIZATION_NOTICE_BYTES),
        public_artifact(
            "support/sbom.json",
            "application/json",
            MATERIALIZATION_SBOM_BYTES,
        ),
        public_artifact(
            "support/source-provenance.json",
            "application/json",
            MATERIALIZATION_SOURCE_PROVENANCE_BYTES,
        ),
        public_artifact(
            "support/build-provenance.json",
            "application/json",
            MATERIALIZATION_BUILD_PROVENANCE_BYTES,
        ),
        public_artifact(
            "support/publication-review.json",
            "application/json",
            MATERIALIZATION_PUBLICATION_REVIEW_BYTES,
        ),
        public_artifact(
            "support/limitations.md",
            "text/markdown",
            MATERIALIZATION_LIMITATIONS_BYTES,
        ),
    ]
}

fn provider_catalog(catalog: &LayerCatalog) -> Result<ProviderCatalog, Box<dyn Error>> {
    let package_support = package_support_artifacts();
    catalog
        .entries
        .iter()
        .map(|layer| provider_package(layer, &package_support))
        .collect::<Result<Vec<_>, _>>()
        .map(|mut packages| {
            packages.sort_by(|left, right| left.provider_key.cmp(&right.provider_key));
            packages
        })
        .and_then(|packages| {
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
            registry
                .digest()
                .map_err(Box::<dyn Error>::from)
                .map(|registry_digest| {
                    registry.registry_digest = registry_digest;
                    (packages, registry)
                })
        })
        .and_then(|(packages, registry)| {
            registry
                .providers
                .iter()
                .zip(&packages)
                .try_for_each(|(entry, catalog_package)| {
                    FixtureProviderPackageV1::from_canonical_cbor(&catalog_package.artifact.bytes)
                        .and_then(|decoded| {
                            decoded
                                .validate_registry_binding(entry, &catalog_package.artifact.bytes)
                        })
                        .map_err(Box::<dyn Error>::from)
                })
                .map(|()| (packages, registry))
        })
        .and_then(|(packages, registry)| {
            registry
                .to_canonical_cbor()
                .map_err(Box::<dyn Error>::from)
                .map(|registry_bytes| ProviderCatalog {
                    registry: public_artifact(
                        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
                        "application/cbor",
                        &registry_bytes,
                    ),
                    packages,
                    package_support,
                })
        })
}

fn provider_package(
    layer: &LayerCatalogEntry,
    package_support: &[PublicArtifact; 7],
) -> Result<ProviderPackage, Box<dyn Error>> {
    let provider_key = FixtureProviderKeyV1 {
        provider_id: layer.fixture_provider.provider_id.to_owned(),
        contract_version: layer.fixture_provider.contract_version.to_owned(),
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
            .zip(layer.fixtures.iter().map(|fixture| fixture.family))
            .map(|(schema, family)| ProviderFamilySchemaV1 {
                family,
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
    package
        .digest()
        .map_err(Box::<dyn Error>::from)
        .and_then(|package_digest| {
            package.package_digest = package_digest;
            package
                .to_canonical_cbor()
                .map_err(Box::<dyn Error>::from)
                .map(|package_bytes| ProviderPackage {
                    provider_key,
                    claim_layer: layer.claim_layer,
                    subject_adapter: layer.subject_adapter,
                    schemas,
                    artifact: public_artifact(
                        layer.fixture_provider.package_path,
                        "application/cbor",
                        &package_bytes,
                    ),
                })
        })
}

fn provider_schema_artifacts(layer: &LayerCatalogEntry) -> Vec<PublicArtifact> {
    layer
        .fixtures
        .iter()
        .map(|fixture| {
            public_artifact(
                fixture.schema_path,
                layer.fixture_provider.schema_media_type,
                fixture.schema,
            )
        })
        .collect()
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
    let expected = pos_conformance::hex_digest(&SOURCE_INVENTORY_DIGEST);
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
    let inventory_bytes = MATERIALIZATION_AUTHORITY_INVENTORY_BYTES;
    let catalog = layer_catalog();
    provider_catalog(&catalog).and_then(|providers| {
        let context = MaterializationContext {
            signing_key,
            inventory_bytes,
            providers: &providers,
        };
        catalog
            .entries
            .iter()
            .try_fold(providers.materialized_files(), |mut outputs, spec| {
                materialize_profile(&context, spec, CatalogBundleMode::ALL).map(|files| {
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
                verify_release_tree_independently(&archives)
                    .map_err(Box::<dyn Error>::from)
                    .map(|()| {
                        let published_file_count = outputs.len().saturating_add(2);
                        outputs.push(materialization_metadata(&catalog, published_file_count));
                        outputs.push(output_checksum_inventory(&outputs));
                        outputs
                    })
            })
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
        .and_then(|bytes| {
            let key = SigningKey::from_bytes(&bytes);
            if key.verifying_key().to_bytes() == DRAFT_AUTHORITY_PUBLIC_KEY_BYTES {
                Ok(key)
            } else {
                Err("conformance signing key is not declared by the Draft authority".into())
            }
        })
}

fn materialize_profile(
    context: &MaterializationContext<'_>,
    layer: &LayerCatalogEntry,
    bundle_modes: [CatalogBundleMode; 2],
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    profile_from_catalog(layer, context.providers).and_then(|mut profile| {
        profile.lifecycle = ProfileLifecycleV1::Draft;
        profile.profile_digest = profile.digest();
        let prefix = format!("{}/draft", layer.claim_layer.catalog_name());
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
        .map(|layer| layer.claim_layer.catalog_name())
        .collect::<Vec<_>>();
    let mode_names = CatalogBundleMode::ALL
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
    let normative = MATERIALIZATION_NORMATIVE_REQUIREMENTS_BYTES;
    let notice = MATERIALIZATION_NOTICE_BYTES;
    let sbom = MATERIALIZATION_SBOM_BYTES;
    let source_provenance = MATERIALIZATION_SOURCE_PROVENANCE_BYTES;
    let build_provenance = MATERIALIZATION_BUILD_PROVENANCE_BYTES;
    let publication_review = MATERIALIZATION_PUBLICATION_REVIEW_BYTES;
    let limitations = MATERIALIZATION_LIMITATIONS_BYTES;
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
    CatalogExecutionProfile::ALL
        .into_iter()
        .map(CatalogExecutionProfile::digest)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|execution_profiles| {
            layer
                .fixtures
                .iter()
                .flat_map(|fixture| {
                    execution_profiles.iter().copied().flat_map(move |digest| {
                        EXECUTION_MODES
                            .into_iter()
                            .map(move |mode| (fixture, digest, mode))
                    })
                })
                .map(|(fixture, digest, mode)| {
                    fixture_descriptor_from_record(
                        layer,
                        fixture,
                        context,
                        provider_key,
                        digest,
                        mode,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })
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
        provider_id: layer.fixture_provider.provider_id.to_owned(),
        contract_version: layer.fixture_provider.contract_version.to_owned(),
        abi_major: layer.fixture_provider.abi_major,
        abi_minor: layer.fixture_provider.abi_minor,
    };
    fixtures_for_layer(layer, &context, &provider_key).and_then(|fixtures| {
        CatalogExecutionProfile::ALL
            .into_iter()
            .map(CatalogExecutionProfile::digest)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|mut execution_profile_digests| {
                execution_profile_digests.sort_unstable();
                trust_policy_snapshot_digest().map(|snapshot_digest| {
                    let execution_matrix_digest =
                        *blake3::hash(MATERIALIZATION_EXECUTION_MATRIX_BYTES).as_bytes();
                    let mut profile = ConformanceProfileV1 {
                        profile_id: layer.profile_id.to_owned(),
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
                        fixture_contract_policy_digest: *blake3::hash(
                            MATERIALIZATION_FIXTURE_CONTRACT_POLICY_BYTES,
                        )
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
    let payload_path = fixture_payload_member_path(fixture.case_id, &execution_profile_digest);
    let evidence_path = evidence_status_member_path(fixture.case_id, &execution_profile_digest);
    let oracle_output_path = expected_result_member_path(
        fixture.case_id,
        context.claim_layer,
        &execution_profile_digest,
    );
    let evidence = artifact_descriptor(&evidence_path, "application/json", fixture.expected);
    let oracle_output = artifact_descriptor(
        &oracle_output_path,
        layer.fixture_provider.oracle_media_type,
        fixture.oracle,
    );
    let expectation = fixture_expectation(fixture, &oracle_output);
    let auxiliary = if expectation.strict_oracle.output.is_some() {
        vec![evidence]
    } else {
        vec![evidence, oracle_output]
    };
    let downgrade = fixture.family == FixtureFamilyV1::Downgrade;
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
                    fixture.case_id,
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
                case_id: fixture.case_id.to_owned(),
                mandatory: true,
                claim_layer: context.claim_layer,
                family: fixture.family,
                provider_key: provider_key.clone(),
                execution_profile_digest,
                modes: vec![mode],
                subject_adapter: layer.subject_adapter,
                schema: artifact_descriptor(
                    fixture.schema_path,
                    layer.fixture_provider.schema_media_type,
                    fixture.schema,
                ),
                payload: artifact_descriptor(
                    &payload_path,
                    layer.fixture_provider.payload_media_type,
                    fixture.input,
                ),
                auxiliary,
                strict_oracle: expectation.strict_oracle,
                expected_verification_outcome: expectation.verification_outcome,
                expected_verification_error: expectation.verification_error,
                replay_claim: expectation.replay_claim,
                redaction_state: expectation.redaction_state,
                deterministic_budget: fixture.contract.deterministic_budget.clone(),
                operational_safety: OperationalSafetyV1 {
                    watchdog_ms: fixture.contract.watchdog_ms,
                },
                capability_policy: CapabilityPolicyV1 {
                    network_allowed: fixture.contract.network_allowed,
                    capability_ids: fixture
                        .contract
                        .minimum_capability_ids
                        .iter()
                        .map(|capability| (*capability).to_owned())
                        .collect(),
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
                owner_id: (*owner_id).to_owned(),
                contract_version: (*contract_version).to_owned(),
                code_id: (*code_id).to_owned(),
            };
            let outcome = match fixture.family {
                FixtureFamilyV1::ResourceExhaustion => VerificationOutcomeV1::ResourceLimitExceeded,
                FixtureFamilyV1::Downgrade => VerificationOutcomeV1::IncompatibleProfile,
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
    let (replay_claim, redaction_state) = match fixture.family {
        FixtureFamilyV1::DeletionRedaction => (
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            RedactionStateV1::RedactedViews,
        ),
        FixtureFamilyV1::Downgrade => (ReplayClaimV1::IncompatibleProfile, RedactionStateV1::None),
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
        "fixtures/{case_id}/{}.payload",
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
    let execution_mode = execution_mode(mode);
    let mut members = Vec::new();
    let mut expected_results = Vec::new();
    for source in &layer.fixtures {
        for fixture in profile
            .fixtures
            .iter()
            .filter(|fixture| fixture.case_id == source.case_id)
            .filter(|fixture| fixture.modes.contains(&execution_mode))
        {
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
            MATERIALIZATION_NORMATIVE_REQUIREMENTS_BYTES,
            BundleMemberRoleV1::NormativeSpecification,
        ),
        (
            "support/LICENSE",
            MATERIALIZATION_LICENSE_BYTES,
            BundleMemberRoleV1::Licence,
        ),
        (
            "support/NOTICE",
            MATERIALIZATION_NOTICE_BYTES,
            BundleMemberRoleV1::Notice,
        ),
        (
            "support/sbom.json",
            MATERIALIZATION_SBOM_BYTES,
            BundleMemberRoleV1::Sbom,
        ),
        (
            "support/source-provenance.json",
            MATERIALIZATION_SOURCE_PROVENANCE_BYTES,
            BundleMemberRoleV1::Provenance,
        ),
        (
            "support/build-provenance.json",
            MATERIALIZATION_BUILD_PROVENANCE_BYTES,
            BundleMemberRoleV1::Provenance,
        ),
        (
            "support/publication-review.json",
            MATERIALIZATION_PUBLICATION_REVIEW_BYTES,
            BundleMemberRoleV1::Provenance,
        ),
        (
            "support/limitations.md",
            MATERIALIZATION_LIMITATIONS_BYTES,
            BundleMemberRoleV1::Limitations,
        ),
    ];
    for (path, bytes, role) in support {
        members.push(BundleMemberV1::supporting(path, bytes.to_vec(), role));
    }
    members.push(BundleMemberV1::supporting(
        "support/schema-cpf1-v1.cddl",
        MATERIALIZATION_PROFILE_SCHEMA_BYTES.to_vec(),
        BundleMemberRoleV1::Schema,
    ));
    members.push(BundleMemberV1::supporting(
        "support/fixture-family-contract.json",
        MATERIALIZATION_FIXTURE_CONTRACT_POLICY_BYTES.to_vec(),
        BundleMemberRoleV1::FixtureContractPolicy,
    ));
    members.push(BundleMemberV1::supporting(
        "support/draft-execution-authority.json",
        MATERIALIZATION_DRAFT_AUTHORITY_DECLARATION_BYTES.to_vec(),
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
    let matrix = BundleMemberV1::execution_matrix(MATERIALIZATION_EXECUTION_MATRIX_BYTES.to_vec());
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
    let execution_mode = execution_mode(mode);
    profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.family == FixtureFamilyV1::Downgrade)
        .filter(|fixture| fixture.modes.contains(&execution_mode))
        .try_for_each(|fixture| {
            let transition = FixtureContractTransitionV1 {
                from: FixtureProviderKeyV1 {
                    provider_id: fixture.provider_key.provider_id.clone(),
                    contract_version: fixture.provider_key.contract_version.clone(),
                    abi_major: fixture.provider_key.abi_major,
                    abi_minor: 1,
                },
                to: fixture.provider_key.clone(),
            };
            trust_policy_snapshot_digest().and_then(|trust_snapshot| {
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
        })
}

const fn execution_mode(mode: BundleModeV1) -> pos_conformance::ExecutionModeV1 {
    match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
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
