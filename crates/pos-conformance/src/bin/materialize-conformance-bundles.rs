#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, verify_archive_release_filename,
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, ClaimLayerV1,
    ConformanceBundlePairV1, ConformanceBundleV1, ConformanceProfileV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1,
    FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
#[cfg(target_os = "linux")]
use rustix::fs::{self, Mode, OFlags, RenameFlags, ResolveFlags, CWD};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
use std::error::Error;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::OsString;
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
#[derive(Clone, Copy)]
struct FixtureContext {
    claim_layer: ClaimLayerV1,
    local_execution_profile_digest: [u8; 32],
    air_gapped_execution_profile_digest: [u8; 32],
    profile_record_digest: [u8; 32],
    schema_digest: [u8; 32],
    provenance_digest: [u8; 32],
    notice_digest: [u8; 32],
    sbom_digest: [u8; 32],
    limitations_digest: [u8; 32],
    normative_spec_digest: [u8; 32],
}

struct MaterializationContext<'a> {
    signing_key: &'a SigningKey,
    inventory_bytes: &'a [u8],
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
}

type CanonicalFixtureBytes = (&'static [u8], &'static [u8]);

macro_rules! fixture_sources {
    ($layer:literal) => {
        &[
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/positive.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/positive.json"
                )),
            ),
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/negative.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/negative.json"
                )),
            ),
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/malformed.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/malformed.json"
                )),
            ),
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/resource.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/resource.json"
                )),
            ),
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/deletion.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/deletion.json"
                )),
            ),
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/downgrade.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/downgrade.json"
                )),
            ),
            (
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/inputs/",
                    $layer,
                    "/independent-evaluation.json"
                )),
                include_bytes!(concat!(
                    "../../../../fixtures/conformance/expected/",
                    $layer,
                    "/independent-evaluation.json"
                )),
            ),
        ]
    };
}

struct LayerSpec {
    claim_layer: ClaimLayerV1,
    name: &'static str,
    profile_id: &'static str,
    subject_adapter: SubjectAdapterKindV1,
    profile_record: &'static [u8],
    fixture_bytes: &'static [CanonicalFixtureBytes; 7],
}

const LAYER_SPECS: [LayerSpec; 7] = [
    LayerSpec {
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        name: "artifact-integrity",
        profile_id: "pigloros.w8.artifact-integrity.1.0.0",
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/artifact-integrity/profile.json"
        ),
        fixture_bytes: fixture_sources!("artifact-integrity"),
    },
    LayerSpec {
        claim_layer: ClaimLayerV1::ReplayConformance,
        name: "replay-conformance",
        profile_id: "pigloros.w8.replay-conformance.1.0.0",
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/replay-conformance/profile.json"
        ),
        fixture_bytes: fixture_sources!("replay-conformance"),
    },
    LayerSpec {
        claim_layer: ClaimLayerV1::KnowledgeNonInterference,
        name: "knowledge-non-interference",
        profile_id: "pigloros.w8.knowledge-non-interference.1.0.0",
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/knowledge-non-interference/profile.json"
        ),
        fixture_bytes: fixture_sources!("knowledge-non-interference"),
    },
    LayerSpec {
        claim_layer: ClaimLayerV1::GatewayClientConformance,
        name: "gateway-client-conformance",
        profile_id: "pigloros.w8.gateway-client-conformance.1.0.0",
        subject_adapter: SubjectAdapterKindV1::PublicGatewayProtocol,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/gateway-client-conformance/profile.json"
        ),
        fixture_bytes: fixture_sources!("gateway-client-conformance"),
    },
    LayerSpec {
        claim_layer: ClaimLayerV1::PluginConformance,
        name: "plugin-conformance",
        profile_id: "pigloros.w8.plugin-conformance.1.0.0",
        subject_adapter: SubjectAdapterKindV1::PublicPluginProtocol,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/plugin-conformance/profile.json"
        ),
        fixture_bytes: fixture_sources!("plugin-conformance"),
    },
    LayerSpec {
        claim_layer: ClaimLayerV1::MetricConformance,
        name: "metric-conformance",
        profile_id: "pigloros.w8.metric-conformance.1.0.0",
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/metric-conformance/profile.json"
        ),
        fixture_bytes: fixture_sources!("metric-conformance"),
    },
    LayerSpec {
        claim_layer: ClaimLayerV1::EmpiricalEvaluation,
        name: "empirical-evaluation",
        profile_id: "pigloros.w8.empirical-evaluation.1.0.0",
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        profile_record: include_bytes!(
            "../../../../fixtures/conformance/profiles/empirical-evaluation/profile.json"
        ),
        fixture_bytes: fixture_sources!("empirical-evaluation"),
    },
];

const fn layer_spec(claim_layer: ClaimLayerV1) -> &'static LayerSpec {
    match claim_layer {
        ClaimLayerV1::ArtifactIntegrity => &LAYER_SPECS[0],
        ClaimLayerV1::ReplayConformance => &LAYER_SPECS[1],
        ClaimLayerV1::KnowledgeNonInterference => &LAYER_SPECS[2],
        ClaimLayerV1::GatewayClientConformance => &LAYER_SPECS[3],
        ClaimLayerV1::PluginConformance => &LAYER_SPECS[4],
        ClaimLayerV1::MetricConformance => &LAYER_SPECS[5],
        ClaimLayerV1::EmpiricalEvaluation => &LAYER_SPECS[6],
    }
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
        MaterializationCommand::Publish(output_root) => AtomicPublication::prepare(&output_root)
            .map(PreparedMaterializationCommand::Publish)
            .map_err(Into::into),
        MaterializationCommand::Fingerprint => Ok(PreparedMaterializationCommand::Fingerprint),
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
    let context = MaterializationContext {
        signing_key,
        inventory_bytes,
    };
    LAYER_SPECS
        .iter()
        .try_fold(Vec::new(), |mut outputs, spec| {
            materialize_profile(&context, spec).map(|files| {
                outputs.extend(files);
                outputs
            })
        })
        .map(|mut outputs| {
            outputs.push(materialization_metadata());
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
    layer: &LayerSpec,
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    let mut profile = profile_for_claim_layer(layer.claim_layer);
    profile.lifecycle = ProfileLifecycleV1::Draft;
    profile.profile_digest = profile.digest();
    let prefix = format!("{}/draft", layer.name);
    profile
        .to_canonical_cbor()
        .map_err(Into::into)
        .and_then(|profile_bytes| {
            signed_bundle(context, &profile, BundleModeV1::Local).and_then(|local| {
                signed_bundle(context, &profile, BundleModeV1::AirGapped).and_then(|air_gapped| {
                    let pair = ConformanceBundlePairV1 { local, air_gapped };
                    pair.validate().map_err(Into::into).and_then(|()| {
                        materialized_profile_outputs(&profile, &prefix, profile_bytes, &pair)
                    })
                })
            })
        })
}

fn signed_bundle(
    context: &MaterializationContext<'_>,
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<ConformanceBundleV1, Box<dyn Error>> {
    let (members, expected_results) =
        bundle_inputs_from_profile(profile, mode, context.inventory_bytes);
    ConformanceBundleV1::materialize(profile, mode, members, expected_results)
        .and_then(|bundle| bundle.sign(context.signing_key))
        .map_err(Into::into)
}

fn materialized_profile_outputs(
    profile: &ConformanceProfileV1,
    prefix: &str,
    profile_bytes: Vec<u8>,
    pair: &ConformanceBundlePairV1,
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    let outputs = vec![MaterializedFile {
        relative_path: format!(
            "{prefix}/CPF1-{}.cbor",
            pos_conformance::hex_digest(&profile.profile_digest)
        ),
        bytes: profile_bytes,
        archive_release_filename: None,
    }];
    [("local", &pair.local), ("air-gapped", &pair.air_gapped)]
        .into_iter()
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
                verify_public_archive(&bundle_bytes, &release_filename).map(|_| {
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

fn materialization_metadata() -> MaterializedFile {
    let layer_names = LAYER_SPECS
        .iter()
        .map(|layer| layer.name)
        .collect::<Vec<_>>();
    MaterializedFile {
        relative_path: MATERIALIZATION_METADATA_PATH.to_owned(),
        bytes: serde_json::json!({
            "format": 1,
            "lifecycles": ["draft"],
            "layers": layer_names,
            "modes": ["local", "air-gapped"],
        })
        .to_string()
        .into_bytes(),
        archive_release_filename: None,
    }
}

const fn profile_record_bytes(claim_layer: ClaimLayerV1) -> &'static [u8] {
    layer_spec(claim_layer).profile_record
}

fn fixture_context(profile_record_bytes: &[u8], claim_layer: ClaimLayerV1) -> FixtureContext {
    let profile_record_digest =
        labeled_digest("PiglorOS.CPF1ProfileRecord.v1", profile_record_bytes);
    let normative =
        include_bytes!("../../../../fixtures/conformance/support/normative-requirements.md");
    let schema = include_bytes!("../../../../fixtures/conformance/support/schema-cpf1-v1.cddl");
    let notice = include_bytes!("../../../../fixtures/conformance/support/NOTICE");
    let sbom = include_bytes!("../../../../fixtures/conformance/support/sbom.json");
    let provenance = include_bytes!("../../../../fixtures/conformance/support/provenance.json");
    let limitations = include_bytes!("../../../../fixtures/conformance/support/limitations.md");
    let schema_digest = *blake3::hash(schema).as_bytes();
    let provenance_digest = *blake3::hash(provenance).as_bytes();
    let notice_digest = *blake3::hash(notice).as_bytes();
    let sbom_digest = *blake3::hash(sbom).as_bytes();
    let limitations_digest = *blake3::hash(limitations).as_bytes();
    let local_execution_profile_digest =
        labeled_digest("PiglorOS.ExecutionProfile.v1", b"deterministic-local-v1");
    let air_gapped_execution_profile_digest = labeled_digest(
        "PiglorOS.ExecutionProfile.v1",
        b"deterministic-air-gapped-v1",
    );
    FixtureContext {
        claim_layer,
        local_execution_profile_digest,
        air_gapped_execution_profile_digest,
        profile_record_digest,
        schema_digest,
        provenance_digest,
        notice_digest,
        sbom_digest,
        limitations_digest,
        normative_spec_digest: *blake3::hash(normative).as_bytes(),
    }
}

fn fixtures_for_layer(context: &FixtureContext) -> Vec<FixtureDescriptorV1> {
    let mut fixtures = Vec::with_capacity(FixtureFamily::ALL.len() * 2);
    for family in FixtureFamily::ALL {
        let local = fixture_descriptor_from_record(
            family,
            context,
            context.local_execution_profile_digest,
            pos_conformance::ExecutionModeV1::Local,
        );
        let mut air_gapped = local.clone();
        air_gapped.execution_profile_digest = context.air_gapped_execution_profile_digest;
        air_gapped.modes = vec![pos_conformance::ExecutionModeV1::AirGapped];
        fixtures.push(local);
        fixtures.push(air_gapped);
    }
    fixtures.sort_by_key(|fixture| {
        (
            fixture.case_id.clone(),
            fixture.claim_layer,
            fixture.execution_profile_digest,
        )
    });
    fixtures
}

fn profile_for_claim_layer(claim_layer: ClaimLayerV1) -> ConformanceProfileV1 {
    profile_from_record(claim_layer, profile_record_bytes(claim_layer))
}

fn profile_from_record(
    claim_layer: ClaimLayerV1,
    profile_record_bytes: &[u8],
) -> ConformanceProfileV1 {
    let context = fixture_context(profile_record_bytes, claim_layer);
    let fixtures = fixtures_for_layer(&context);
    let mut execution_profile_digests = vec![
        context.local_execution_profile_digest,
        context.air_gapped_execution_profile_digest,
    ];
    execution_profile_digests.sort_unstable();
    let execution_matrix_digest = *blake3::hash(include_bytes!(
        "../../../../fixtures/conformance/matrix/execution-matrix.json"
    ))
    .as_bytes();
    let mut profile = ConformanceProfileV1 {
        profile_id: profile_id(claim_layer).to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: context.normative_spec_digest,
        execution_matrix_digest,
        execution_profile_digests,
        public_schema_digests: vec![context.schema_digest],
        fixtures,
        allowed_divergences: Vec::new(),
        evaluator_protocol: evaluator_protocol(context.profile_record_digest),
        independence_requirements: IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: labeled_digest(
                "PiglorOS.TrustPolicySnapshot.v1",
                profile_record_bytes,
            ),
            requirements_digest: labeled_digest(
                "PiglorOS.IndependenceRequirements.v1",
                profile_record_bytes,
            ),
        },
        compatibility_digest: labeled_digest("PiglorOS.Compatibility.v1", profile_record_bytes),
        limitations_digest: context.limitations_digest,
        provenance_digest: context.provenance_digest,
        previous_profile_digest: None,
        stable_evidence: Vec::new(),
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    profile
}

const fn profile_id(claim_layer: ClaimLayerV1) -> &'static str {
    layer_spec(claim_layer).profile_id
}

const fn subject_adapter(claim_layer: ClaimLayerV1) -> SubjectAdapterKindV1 {
    layer_spec(claim_layer).subject_adapter
}

fn fixture_descriptor_from_record(
    family: FixtureFamily,
    context: &FixtureContext,
    execution_profile_digest: [u8; 32],
    mode: pos_conformance::ExecutionModeV1,
) -> FixtureDescriptorV1 {
    let layer_name = layer_spec(context.claim_layer).name;
    let family_name = family.name();
    let case_id = format!("{layer_name}-{family_name}");
    let input_path = format!("inputs/{layer_name}/{family_name}.json");
    let (input, expected) = layer_spec(context.claim_layer).fixture_bytes[family.index()];
    let fixture_record = format!(
        "{{\"case_id\":\"{case_id}\",\"claim_layer\":\"{layer_name}\",\"expected\":\"expected/{layer_name}/{family_name}.json\",\"family\":\"{family_name}\",\"input\":\"{input_path}\"}}"
    );
    let fixture_record_digest =
        labeled_digest("PiglorOS.CPF1FixtureRecord.v1", fixture_record.as_bytes());
    let draft_provenance_material = [
        context.profile_record_digest.as_slice(),
        fixture_record_digest.as_slice(),
    ]
    .concat();
    FixtureDescriptorV1 {
        case_id,
        mandatory: true,
        claim_layer: context.claim_layer,
        execution_profile_digest,
        public_schema_digest: context.schema_digest,
        modes: vec![mode],
        subject_adapter: subject_adapter(context.claim_layer),
        inputs: vec![FixtureInputMemberV1 {
            member_id: input_path,
            size_bytes: input.len() as u64,
            digest: *blake3::hash(input).as_bytes(),
            provenance_digest: context.provenance_digest,
        }],
        expected: ExpectedResultV1::CanonicalBytes {
            digest: *blake3::hash(expected).as_bytes(),
            bytes: expected.to_vec(),
        },
        expected_verification_outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
        expected_verification_error: Some(SafeErrorCodeV1::ProvenanceMissing),
        replay_claim: ReplayClaimV1::UnverifiableArtifactsMissing,
        redaction_state: RedactionStateV1::EvidenceMissing,
        bounds: FixtureBoundsV1 {
            cpu_fuel: 1,
            memory_bytes: 1,
            event_count: 1,
            output_bytes: 1024,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
            watchdog_ms: 1,
        },
        capability_policy: pos_conformance::CapabilityPolicyV1 {
            network_allowed: false,
            capability_ids: vec!["read-public-bundle".to_owned()],
        },
        provenance: FixtureProvenanceV1 {
            licence_id: "MIT".to_owned(),
            notices_digest: context.notice_digest,
            sbom_digest: context.sbom_digest,
            source_digest: labeled_digest(
                "PiglorOS.DraftSourceMetadata.v1",
                &draft_provenance_material,
            ),
            build_digest: labeled_digest(
                "PiglorOS.DraftBuildMetadata.v1",
                &draft_provenance_material,
            ),
            publication_review_digest: labeled_digest(
                "PiglorOS.DraftPublicationReviewMetadata.v1",
                &draft_provenance_material,
            ),
            limitations_digest: context.limitations_digest,
        },
        compatibility_digest: labeled_digest(
            "PiglorOS.FixtureCompatibility.v1",
            &[
                context.profile_record_digest.as_slice(),
                fixture_record_digest.as_slice(),
            ]
            .concat(),
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureFamily {
    Positive,
    Negative,
    Malformed,
    Resource,
    Deletion,
    Downgrade,
    IndependentEvaluation,
}

impl FixtureFamily {
    const ALL: [Self; 7] = [
        Self::Positive,
        Self::Negative,
        Self::Malformed,
        Self::Resource,
        Self::Deletion,
        Self::Downgrade,
        Self::IndependentEvaluation,
    ];

    const SORTED: [Self; 7] = [
        Self::Deletion,
        Self::Downgrade,
        Self::IndependentEvaluation,
        Self::Malformed,
        Self::Negative,
        Self::Positive,
        Self::Resource,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Malformed => "malformed",
            Self::Resource => "resource",
            Self::Deletion => "deletion",
            Self::Downgrade => "downgrade",
            Self::IndependentEvaluation => "independent-evaluation",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Positive => 0,
            Self::Negative => 1,
            Self::Malformed => 2,
            Self::Resource => 3,
            Self::Deletion => 4,
            Self::Downgrade => 5,
            Self::IndependentEvaluation => 6,
        }
    }
}

fn labeled_digest(label: &str, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(label.len() + 1 + bytes.len());
    input.extend_from_slice(label.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
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
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
    inventory_bytes: &[u8],
) -> (Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>) {
    let execution_mode = match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
    };
    let mut members = Vec::new();
    let mut expected_results = Vec::new();
    for (fixture_index, fixture) in profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.modes.contains(&execution_mode))
        .enumerate()
    {
        let (input, expected) = layer_spec(fixture.claim_layer).fixture_bytes
            [FixtureFamily::SORTED[fixture_index].index()];
        for member in &fixture.inputs {
            members.push(BundleMemberV1::fixture_input(
                fixture_input_member_path(
                    &fixture.case_id,
                    fixture.claim_layer,
                    &fixture.execution_profile_digest,
                    &member.member_id,
                ),
                input.to_vec(),
            ));
        }
        let path = expected_result_member_path(
            &fixture.case_id,
            fixture.claim_layer,
            &fixture.execution_profile_digest,
        );
        let member = BundleMemberV1::expected_result(path.clone(), expected.to_vec());
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
    append_supporting_members(&mut members, inventory_bytes);
    (members, expected_results)
}

fn append_supporting_members(members: &mut Vec<BundleMemberV1>, inventory_bytes: &[u8]) {
    let support = [
        (
            "support/normative-requirements.md",
            include_bytes!("../../../../fixtures/conformance/support/normative-requirements.md")
                .as_slice(),
            BundleMemberRoleV1::NormativeSpecification,
        ),
        (
            "support/schema-cpf1-v1.cddl",
            include_bytes!("../../../../fixtures/conformance/support/schema-cpf1-v1.cddl")
                .as_slice(),
            BundleMemberRoleV1::Schema,
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
    let inventory = BundleMemberV1::authority_inventory(inventory_bytes.to_vec());
    members.push(inventory);
    let matrix = BundleMemberV1::execution_matrix(
        include_bytes!("../../../../fixtures/conformance/matrix/execution-matrix.json").to_vec(),
    );
    members.push(matrix);
}

fn verify_public_archive(
    archive_bytes: &[u8],
    release_filename: &str,
) -> Result<VerifiedArchive, Box<dyn Error>> {
    ConformanceBundleV1::from_canonical_cbor(archive_bytes)
        .map_err(Into::into)
        .and_then(|_| {
            verify_archive_release_filename(archive_bytes, release_filename).map_err(Into::into)
        })
        .map(|()| VerifiedArchive)
}

struct VerifiedArchive;

#[cfg(target_os = "linux")]
struct AtomicPublication {
    parent: OwnedFd,
    staging: OwnedFd,
    staging_name: CString,
    destination_name: CString,
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
            open_trusted_parent(parent_path).and_then(|parent| {
                create_private_staging(&parent).map(|(staging_name, staging)| Self {
                    parent,
                    staging,
                    staging_name,
                    destination_name,
                })
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
                        .and_then(|()| {
                            file.sync_all()
                                .map_err(|_| MaterializationError::DurabilitySyncFailed)
                        })
                        .and_then(|()| {
                            fs::fsync(&directory)
                                .map_err(|_| MaterializationError::DurabilitySyncFailed)
                        })
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
                                .map(|_| ())
                                .map_err(|_| MaterializationError::ArchiveDigestMismatch)
                        })
                })
            })
            .and_then(|()| {
                fs::fsync(&self.staging).map_err(|_| MaterializationError::DurabilitySyncFailed)
            })
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
        let publication = self.0;
        fs::renameat_with(
            &publication.parent,
            publication.staging_name.as_c_str(),
            &publication.parent,
            publication.destination_name.as_c_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(map_publish_error)
        .and_then(|()| {
            fs::fsync(&publication.parent).map_err(|_| MaterializationError::DurabilitySyncFailed)
        })
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
fn open_trusted_parent(parent: &Path) -> Result<OwnedFd, MaterializationError> {
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
}

#[cfg(target_os = "linux")]
fn create_private_staging(parent: &OwnedFd) -> Result<(CString, OwnedFd), MaterializationError> {
    for _ in 0..16 {
        let attempt = random_staging_name().and_then(|name| {
            match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) => open_directory(parent, &name).map(|staging| Some((name, staging))),
                Err(Errno::EXIST) => Ok(None),
                Err(_) => Err(MaterializationError::UntrustedOutputDirectory),
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
        Err(_) => return Err(MaterializationError::UntrustedOutputDirectory),
    }
    fs::fsync(parent)
        .map_err(|_| MaterializationError::DurabilitySyncFailed)
        .and_then(|()| open_directory(parent, name))
}

#[cfg(target_os = "linux")]
fn open_directory(parent: &OwnedFd, name: &CString) -> Result<OwnedFd, MaterializationError> {
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
    path: &CString,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd, MaterializationError> {
    fs::openat2(directory_fd, path.as_c_str(), flags, mode, resolve).map_err(map_open_error)
}

#[cfg(target_os = "linux")]
const fn map_open_error(error: Errno) -> MaterializationError {
    match error {
        Errno::LOOP => MaterializationError::SymlinkDetected,
        Errno::NOSYS | Errno::INVAL => MaterializationError::AtomicPublicationUnsupported,
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const fn map_publish_error(error: Errno) -> MaterializationError {
    match error {
        Errno::EXIST => MaterializationError::DestinationExists,
        Errno::NOSYS | Errno::INVAL => MaterializationError::AtomicPublicationUnsupported,
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
