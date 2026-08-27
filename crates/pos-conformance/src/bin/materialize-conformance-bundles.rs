#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, verify_archive_release_filename,
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, ClaimLayerV1,
    ConformanceBundlePairV1, ConformanceBundleV1, ConformanceProfileV2, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1,
    FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
#[cfg(target_os = "linux")]
use rustix::fs::{self, Mode, OFlags, RenameFlags, ResolveFlags, CWD};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::error::Error;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use thiserror::Error as ThisError;

const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
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

struct MaterializedFile {
    relative_path: String,
    bytes: Vec<u8>,
    archive: Option<ArchiveExpectation>,
}

struct ArchiveExpectation {
    digest: [u8; 32],
    manifest: Vec<u8>,
    release_filename: String,
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
    fixture_root: &'static str,
    wire_code: u8,
    profile_id: &'static str,
    subject_adapter: SubjectAdapterKindV1,
    profile_record: &'static [u8],
    fixture_bytes: &'static [CanonicalFixtureBytes; 7],
}

const LAYER_SPECS: [LayerSpec; 7] = [
    LayerSpec {
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        name: "artifact-integrity",
        fixture_root: "artifact-integrity",
        wire_code: 0,
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
        fixture_root: "replay-conformance",
        wire_code: 1,
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
        fixture_root: "knowledge-non-interference",
        wire_code: 2,
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
        fixture_root: "gateway-client-conformance",
        wire_code: 3,
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
        fixture_root: "plugin-conformance",
        wire_code: 4,
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
        fixture_root: "metric-conformance",
        wire_code: 5,
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
        fixture_root: "empirical-evaluation",
        wire_code: 6,
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
    mut arguments: impl Iterator<Item = OsString>,
    encoded_signing_key: Result<String, std::env::VarError>,
) -> Result<(), Box<dyn Error>> {
    let _program = arguments.next();
    let output_root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("materialization output directory is required")?;
    if arguments.next().is_some() {
        return Err("materialization accepts exactly one output directory".into());
    }
    let signing_key = signing_key_from_encoded(encoded_signing_key)?;
    let inventory_bytes =
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json");
    let lifecycles = publication_lifecycles_from_bytes(inventory_bytes)?;
    let context = MaterializationContext {
        signing_key: &signing_key,
        inventory_bytes,
    };
    let mut outputs = Vec::new();
    for spec in &LAYER_SPECS {
        for (lifecycle, lifecycle_name) in &lifecycles {
            outputs.extend(materialize_profile_with_inventory(
                &context,
                spec,
                *lifecycle,
                lifecycle_name,
            )?);
        }
    }
    outputs.push(materialization_metadata(&lifecycles)?);
    publish_materialized_tree(&output_root, &outputs).map_err(Into::into)
}

fn signing_key_from_encoded(
    encoded: Result<String, std::env::VarError>,
) -> Result<SigningKey, Box<dyn Error>> {
    let encoded = encoded?;
    let bytes =
        pos_conformance::decode_hex_digest(&encoded).ok_or("invalid conformance signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn publication_lifecycles_from_bytes(
    bytes: &[u8],
) -> Result<Vec<(ProfileLifecycleV1, &'static str)>, Box<dyn Error>> {
    let inventory: JsonValue = serde_json::from_slice(bytes)?;
    let lifecycle = inventory
        .get("lifecycle")
        .and_then(JsonValue::as_str)
        .ok_or("authority inventory lifecycle is missing")?;
    if lifecycle != "Draft" {
        return Err("only Draft authority inventories can be materialized here".into());
    }
    Ok(vec![(ProfileLifecycleV1::Draft, "draft")])
}

fn materialize_profile_with_inventory(
    context: &MaterializationContext<'_>,
    layer: &LayerSpec,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    profile_for_claim_layer(layer.claim_layer).and_then(|profile| {
        materialize_profile_from_profile(context, profile, lifecycle, lifecycle_name, layer.name)
    })
}

fn materialize_profile_from_profile(
    context: &MaterializationContext<'_>,
    mut profile: ConformanceProfileV2,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    layer_name: &str,
) -> Result<Vec<MaterializedFile>, Box<dyn Error>> {
    if lifecycle != ProfileLifecycleV1::Draft {
        return Err("the #190 materializer emits Draft bundles only".into());
    }
    profile.lifecycle = lifecycle;
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    let prefix = format!("{layer_name}/{lifecycle_name}");
    let mut outputs = vec![MaterializedFile {
        relative_path: format!(
            "{prefix}/CPF2-{}.cbor",
            pos_conformance::hex_digest(&profile.profile_digest)
        ),
        bytes: profile_bytes,
        archive: None,
    }];
    let mut signed_bundles = Vec::with_capacity(2);
    for mode in [BundleModeV1::Local, BundleModeV1::AirGapped] {
        let mode_name = match mode {
            BundleModeV1::Local => "local",
            BundleModeV1::AirGapped => "air-gapped",
        };
        let (members, expected_results) =
            bundle_inputs_from_profile(&profile, mode, context.inventory_bytes).map_err(
                |error| {
                    format!("failed to assemble {layer_name}/{mode_name} bundle inputs: {error:?}")
                },
            )?;
        let bundle = ConformanceBundleV1::materialize(&profile, mode, members, expected_results)?;
        let bundle = bundle.sign(context.signing_key)?;
        signed_bundles.push(bundle);
    }
    let pair = ConformanceBundlePairV1 {
        local: signed_bundles.remove(0),
        air_gapped: signed_bundles.remove(0),
    };
    pair.validate()?;
    for (mode_name, bundle) in [("local", &pair.local), ("air-gapped", &pair.air_gapped)] {
        let manifest_digest = bundle.manifest_digest()?;
        let archive_digest = bundle.archive_digest()?;
        let release_filename = bundle.release_filename()?;
        let manifest_bytes = bundle.manifest_bytes()?;
        let bundle_bytes = bundle.to_canonical_cbor()?;
        verify_public_archive(
            &bundle_bytes,
            &archive_digest,
            &manifest_bytes,
            &release_filename,
        )?;
        outputs.push(MaterializedFile {
            relative_path: format!(
                "{prefix}/manifest-{mode_name}-{}.cbor",
                pos_conformance::hex_digest(&manifest_digest)
            ),
            bytes: manifest_bytes.clone(),
            archive: None,
        });
        outputs.push(MaterializedFile {
            relative_path: format!("{prefix}/{release_filename}"),
            bytes: bundle_bytes,
            archive: Some(ArchiveExpectation {
                digest: archive_digest,
                manifest: manifest_bytes,
                release_filename,
            }),
        });
    }
    Ok(outputs)
}

fn materialization_metadata(
    lifecycles: &[(ProfileLifecycleV1, &'static str)],
) -> Result<MaterializedFile, Box<dyn Error>> {
    let lifecycle_names: Vec<&str> = lifecycles.iter().map(|(_, name)| *name).collect();
    let layer_names: Vec<&str> = LAYER_SPECS.iter().map(|layer| layer.name).collect();
    Ok(MaterializedFile {
        relative_path: MATERIALIZATION_METADATA_PATH.to_owned(),
        bytes: serde_json::to_vec(&serde_json::json!({
            "format": 1,
            "lifecycles": lifecycle_names,
            "layers": layer_names,
            "modes": ["local", "air-gapped"],
        }))?,
        archive: None,
    })
}

const fn profile_record_bytes(claim_layer: ClaimLayerV1) -> &'static [u8] {
    layer_spec(claim_layer).profile_record
}

fn validated_profile_record(
    claim_layer: ClaimLayerV1,
) -> Result<(&'static [u8], JsonValue), Box<dyn Error>> {
    validated_profile_record_bytes(claim_layer, profile_record_bytes(claim_layer))
}

fn validated_profile_record_bytes(
    claim_layer: ClaimLayerV1,
    profile_record_bytes: &[u8],
) -> Result<(&[u8], JsonValue), Box<dyn Error>> {
    let profile_record: JsonValue = serde_json::from_slice(profile_record_bytes)?;
    validate_profile_record_bindings(claim_layer, &profile_record)?;
    Ok((profile_record_bytes, profile_record))
}

fn validate_profile_record_bindings(
    claim_layer: ClaimLayerV1,
    profile_record: &JsonValue,
) -> Result<(), Box<dyn Error>> {
    let matrix = include_bytes!("../../../../fixtures/conformance/matrix/execution-matrix.json");
    let matrix_json: JsonValue = serde_json::from_slice(matrix)?;
    let matrix_lifecycle = json_text(&matrix_json, "lifecycle")?;
    let spec = layer_spec(claim_layer);
    if json_text(profile_record, "profile_id")? != spec.profile_id
        || json_text(profile_record, "claim_layer")? != claim_layer_name(claim_layer)
        || json_text(profile_record, "fixture_root")? != spec.fixture_root
        || json_u64(profile_record, "wire_code")? != u64::from(spec.wire_code)
        || json_text(profile_record, "authority_inventory")? != "expected-authority/inventory.json"
        || json_string_array(profile_record, "execution_profiles")?
            != vec!["deterministic-local-v1", "deterministic-air-gapped-v1"]
        || json_string_array(profile_record, "bundle_modes")? != vec!["local", "air-gapped"]
    {
        return Err("canonical profile record has invalid binding metadata".into());
    }
    let inventory =
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json");
    if pos_conformance::decode_hex_digest(json_text(
        profile_record,
        "authority_inventory_sha256_digest",
    )?) != Some(Sha256::digest(inventory).into())
    {
        return Err("canonical profile record digest binding is invalid".into());
    }
    if claim_layer == ClaimLayerV1::KnowledgeNonInterference
        && (json_text(profile_record, "adr_059_execution_matrix")?
            != "matrix/execution-matrix.json"
            || json_text(profile_record, "adr_059_execution_matrix_status")? != matrix_lifecycle
            || pos_conformance::decode_hex_digest(json_text(
                profile_record,
                "adr_059_execution_matrix_blake3_digest",
            )?) != Some(*blake3::hash(matrix).as_bytes()))
    {
        return Err("knowledge profile matrix binding is invalid".into());
    }
    Ok(())
}

fn fixture_context(profile_record_bytes: &[u8], claim_layer: ClaimLayerV1) -> FixtureContext {
    let profile_record_digest =
        labeled_digest("PiglorOS.CPF2ProfileRecord.v2", profile_record_bytes);
    let normative =
        include_bytes!("../../../../fixtures/conformance/support/normative-requirements.md");
    let schema = include_bytes!("../../../../fixtures/conformance/support/schema-cpf2-v2.cddl");
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

fn fixtures_from_profile_record(
    profile_record: &JsonValue,
    context: &FixtureContext,
) -> Result<Vec<FixtureDescriptorV1>, Box<dyn Error>> {
    let fixture_records = profile_record
        .get("fixtures")
        .and_then(JsonValue::as_array)
        .ok_or("canonical profile fixtures are missing")?;
    if fixture_records.len() != 7 {
        return Err("canonical profile must declare all seven fixture families".into());
    }
    let mut fixtures = Vec::with_capacity(fixture_records.len() * 2);
    for fixture_record in fixture_records {
        if json_text(fixture_record, "claim_layer")? != claim_layer_name(context.claim_layer) {
            return Err("canonical profile fixture is bound to the wrong claim layer".into());
        }
        let local = fixture_descriptor_from_record(
            fixture_record,
            context,
            context.local_execution_profile_digest,
            pos_conformance::ExecutionModeV1::Local,
        )?;
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
    Ok(fixtures)
}

fn profile_for_claim_layer(
    claim_layer: ClaimLayerV1,
) -> Result<ConformanceProfileV2, Box<dyn Error>> {
    validated_profile_record(claim_layer).and_then(|(profile_record_bytes, profile_record)| {
        profile_from_record(claim_layer, profile_record_bytes, &profile_record)
    })
}

fn profile_from_record(
    claim_layer: ClaimLayerV1,
    profile_record_bytes: &[u8],
    profile_record: &JsonValue,
) -> Result<ConformanceProfileV2, Box<dyn Error>> {
    let context = fixture_context(profile_record_bytes, claim_layer);
    let fixtures = fixtures_from_profile_record(profile_record, &context)?;
    let mut execution_profile_digests = vec![
        context.local_execution_profile_digest,
        context.air_gapped_execution_profile_digest,
    ];
    execution_profile_digests.sort_unstable();
    let execution_matrix_digest = *blake3::hash(include_bytes!(
        "../../../../fixtures/conformance/matrix/execution-matrix.json"
    ))
    .as_bytes();
    let mut profile = ConformanceProfileV2 {
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
    Ok(profile)
}

const fn profile_id(claim_layer: ClaimLayerV1) -> &'static str {
    layer_spec(claim_layer).profile_id
}

const fn claim_layer_name(claim_layer: ClaimLayerV1) -> &'static str {
    layer_spec(claim_layer).name
}

const fn subject_adapter(claim_layer: ClaimLayerV1) -> SubjectAdapterKindV1 {
    layer_spec(claim_layer).subject_adapter
}

fn fixture_descriptor_from_record(
    record: &JsonValue,
    context: &FixtureContext,
    execution_profile_digest: [u8; 32],
    mode: pos_conformance::ExecutionModeV1,
) -> Result<FixtureDescriptorV1, Box<dyn Error>> {
    let case_id = json_text(record, "case_id")?;
    let family = json_text(record, "family")?;
    let input_path = json_text(record, "input")?;
    let expected_path = json_text(record, "expected")?;
    if family_for_path(input_path, expected_path) != Some(family) {
        return Err("canonical fixture family is not bound to its paths".into());
    }
    let (input, expected) =
        canonical_fixture_bytes(context.claim_layer, input_path, expected_path)?;
    let expected_result_bytes = validate_fixture_records(
        input,
        expected,
        case_id,
        family,
        claim_layer_name(context.claim_layer),
    )?;
    let fixture_record_digest = labeled_digest(
        "PiglorOS.CPF2FixtureRecord.v2",
        &serde_json::to_vec(record)?,
    );
    let draft_provenance_material = [
        context.profile_record_digest.as_slice(),
        fixture_record_digest.as_slice(),
    ]
    .concat();
    Ok(FixtureDescriptorV1 {
        case_id: case_id.to_owned(),
        mandatory: true,
        claim_layer: context.claim_layer,
        execution_profile_digest,
        public_schema_digest: context.schema_digest,
        modes: vec![mode],
        subject_adapter: subject_adapter(context.claim_layer),
        inputs: vec![FixtureInputMemberV1 {
            member_id: input_path.to_owned(),
            size_bytes: input.len() as u64,
            digest: *blake3::hash(input).as_bytes(),
            provenance_digest: context.provenance_digest,
        }],
        expected: ExpectedResultV1::CanonicalBytes {
            digest: *blake3::hash(&expected_result_bytes).as_bytes(),
            bytes: expected_result_bytes,
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
    })
}

fn validate_fixture_records(
    input: &[u8],
    expected: &[u8],
    case_id: &str,
    family: &str,
    claim_layer: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let input_record: JsonValue = serde_json::from_slice(input)?;
    let expected_record: JsonValue = serde_json::from_slice(expected)?;
    for record in [&input_record, &expected_record] {
        if json_text(record, "case_id")? != case_id
            || json_text(record, "claim_layer")? != claim_layer
            || json_text(record, "family")? != family
        {
            return Err("fixture record identity does not match its profile declaration".into());
        }
    }
    let declared_input_digest =
        pos_conformance::decode_hex_digest(json_text(&expected_record, "input_blake3_digest")?)
            .ok_or("expected fixture input digest is invalid")?;
    if declared_input_digest != *blake3::hash(input).as_bytes() {
        return Err("expected fixture input digest does not match its input bytes".into());
    }
    let draft_result = expected_record
        .get("draft_expected_result")
        .ok_or("Draft expected result is missing")?;
    if json_text(draft_result, "kind")? != "typed-failure"
        || json_text(draft_result, "error_code")? != "ProvenanceMissing"
    {
        return Err("Draft expected result is not the unavailable typed result".into());
    }
    if json_text(&input_record, "subject")?.is_empty()
        || json_text(&input_record, "assertion")?.is_empty()
        || json_text(&expected_record, "result")?.is_empty()
        || json_text(&expected_record, "status")? != "pending"
        || expected_record.get("verification").is_some()
        || expected_record.get("source").is_some()
    {
        return Err("Draft fixture records contain unsupported evidence claims".into());
    }
    Ok(expected.to_vec())
}

fn family_for_path(input_path: &str, expected_path: &str) -> Option<&'static str> {
    let input_family = input_path
        .strip_prefix("inputs/")?
        .rsplit('/')
        .next()?
        .strip_suffix(".json")?;
    let expected_family = expected_path
        .strip_prefix("expected/")?
        .rsplit('/')
        .next()?
        .strip_suffix(".json")?;
    if input_family != expected_family {
        return None;
    }
    match input_family {
        "positive" => Some("positive"),
        "negative" => Some("negative"),
        "malformed" => Some("malformed"),
        "resource" => Some("resource"),
        "deletion" => Some("deletion"),
        "downgrade" => Some("downgrade"),
        "independent-evaluation" => Some("independent-evaluation"),
        _ => None,
    }
}

fn canonical_fixture_bytes(
    claim_layer: ClaimLayerV1,
    input_path: &str,
    expected_path: &str,
) -> Result<CanonicalFixtureBytes, Box<dyn Error>> {
    let fixture_root = layer_spec(claim_layer).fixture_root;
    if !input_path.starts_with(&format!("inputs/{fixture_root}/")) {
        return Err("canonical fixture input path is bound to the wrong claim layer".into());
    }
    if !expected_path.starts_with(&format!("expected/{fixture_root}/")) {
        return Err("canonical fixture expected path is bound to the wrong claim layer".into());
    }
    let family =
        family_for_path(input_path, expected_path).ok_or("canonical fixture paths are unknown")?;
    let family_index = [
        "positive",
        "negative",
        "malformed",
        "resource",
        "deletion",
        "downgrade",
        "independent-evaluation",
    ]
    .iter()
    .position(|candidate| *candidate == family)
    .ok_or("canonical fixture family is unknown")?;
    Ok(layer_spec(claim_layer).fixture_bytes[family_index])
}

fn labeled_digest(label: &str, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(label.len() + 1 + bytes.len());
    input.extend_from_slice(label.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

fn json_text<'a>(value: &'a JsonValue, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("canonical profile field is missing: {field}").into())
}

fn json_u64(value: &JsonValue, field: &str) -> Result<u64, Box<dyn Error>> {
    value
        .get(field)
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| format!("canonical profile field is missing: {field}").into())
}

fn json_string_array<'a>(
    value: &'a JsonValue,
    field: &str,
) -> Result<Vec<&'a str>, Box<dyn Error>> {
    value
        .get(field)
        .and_then(JsonValue::as_array)
        .ok_or_else(|| -> Box<dyn Error> {
            format!("canonical profile array is missing: {field}").into()
        })?
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                format!("canonical profile array contains a non-string: {field}").into()
            })
        })
        .collect()
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

#[cfg(test)]
fn bundle_inputs(
    profile: &ConformanceProfileV2,
    mode: BundleModeV1,
) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn Error>> {
    bundle_inputs_from_profile(
        profile,
        mode,
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json"),
    )
}

fn bundle_inputs_from_profile(
    profile: &ConformanceProfileV2,
    mode: BundleModeV1,
    inventory_bytes: &[u8],
) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn Error>> {
    let execution_mode = match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
    };
    if !profile
        .fixtures
        .iter()
        .any(|fixture| fixture.modes.contains(&execution_mode))
    {
        return Err("profile has no fixtures for the requested bundle mode".into());
    }
    let mut members = Vec::new();
    let mut expected_results = Vec::new();
    for fixture in &profile.fixtures {
        if !fixture.modes.contains(&execution_mode) {
            continue;
        }
        for member in &fixture.inputs {
            let input = canonical_fixture_input(fixture.claim_layer, &member.member_id)?;
            members.push(BundleMemberV1::new(
                fixture_input_member_path(
                    &fixture.case_id,
                    fixture.claim_layer,
                    &fixture.execution_profile_digest,
                    &member.member_id,
                ),
                input.to_vec(),
                false,
            ));
        }
        let bytes = match &fixture.expected {
            ExpectedResultV1::CanonicalBytes { bytes, .. } => bytes.clone(),
            typed_or_divergent => typed_or_divergent.to_canonical_bytes()?,
        };
        let path = expected_result_member_path(
            &fixture.case_id,
            fixture.claim_layer,
            &fixture.execution_profile_digest,
        );
        let member = BundleMemberV1::new(path.clone(), bytes, true);
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
    append_supporting_members(&mut members, inventory_bytes)?;
    Ok((members, expected_results))
}

fn append_supporting_members(
    members: &mut Vec<BundleMemberV1>,
    inventory_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let support = [
        (
            "support/normative-requirements.md",
            include_bytes!("../../../../fixtures/conformance/support/normative-requirements.md")
                .as_slice(),
            BundleMemberRoleV1::NormativeSpecification,
        ),
        (
            "support/schema-cpf2-v2.cddl",
            include_bytes!("../../../../fixtures/conformance/support/schema-cpf2-v2.cddl")
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
    let mut inventory = BundleMemberV1::new(
        AUTHORITY_INVENTORY_MEMBER_PATH,
        inventory_bytes.to_vec(),
        false,
    );
    inventory.role = BundleMemberRoleV1::AuthorityInventory;
    members.push(inventory);
    let mut matrix = BundleMemberV1::new(
        "authority/execution-matrix.json",
        include_bytes!("../../../../fixtures/conformance/matrix/execution-matrix.json").to_vec(),
        false,
    );
    matrix.role = BundleMemberRoleV1::ExecutionMatrix;
    members.push(matrix);
    if json_text(
        &serde_json::from_slice::<JsonValue>(inventory_bytes)?,
        "lifecycle",
    )? != "Draft"
    {
        return Err("only Draft authority inventories can be materialized here".into());
    }
    Ok(())
}

fn canonical_fixture_input(
    claim_layer: ClaimLayerV1,
    member_id: &str,
) -> Result<&'static [u8], Box<dyn Error>> {
    let relative = member_id
        .strip_prefix("inputs/")
        .ok_or("fixture input member path is not canonical")?;
    let expected_path = format!("expected/{relative}");
    let (input, _) = canonical_fixture_bytes(claim_layer, member_id, &expected_path)?;
    Ok(input)
}

fn verify_public_archive(
    archive_bytes: &[u8],
    expected_archive_digest: &[u8; 32],
    expected_manifest: &[u8],
    release_filename: &str,
) -> Result<(), Box<dyn Error>> {
    ConformanceBundleV1::from_canonical_cbor(archive_bytes)
        .map_err(|error| Box::new(error) as Box<dyn Error>)
        .and_then(|decoded| {
            decoded
                .to_canonical_cbor()
                .map_err(|error| Box::new(error) as Box<dyn Error>)
                .and_then(|canonical_bytes| {
                    decoded
                        .manifest_bytes()
                        .map_err(|error| Box::new(error) as Box<dyn Error>)
                        .and_then(|manifest_bytes| {
                            decoded
                                .archive_digest()
                                .map_err(|error| Box::new(error) as Box<dyn Error>)
                                .and_then(|archive_digest| {
                                    if canonical_bytes != archive_bytes
                                        || manifest_bytes != expected_manifest
                                        || archive_digest != *expected_archive_digest
                                    {
                                        Err("public archive verification did not reproduce canonical bytes"
                                            .into())
                                    } else {
                                        verify_archive_release_filename(
                                            archive_bytes,
                                            release_filename,
                                        )
                                        .map_err(|error| Box::new(error) as Box<dyn Error>)
                                    }
                                })
                        })
                })
        })
}

#[cfg(target_os = "linux")]
struct AtomicPublication {
    parent: OwnedFd,
    staging: OwnedFd,
    staging_name: CString,
    destination_name: CString,
}

#[cfg(target_os = "linux")]
impl AtomicPublication {
    fn prepare(destination: &Path) -> Result<Self, MaterializationError> {
        let (parent_path, destination_name) = output_parent_and_name(destination)?;
        let parent = open_trusted_parent(parent_path)?;
        let (staging_name, staging) = create_private_staging(&parent)?;
        Ok(Self {
            parent,
            staging,
            staging_name,
            destination_name,
        })
    }

    fn write_file(&self, relative_path: &str, bytes: &[u8]) -> Result<(), MaterializationError> {
        let components = relative_components(Path::new(relative_path))?;
        let (file_name, directories) = components
            .split_last()
            .ok_or(MaterializationError::UntrustedOutputDirectory)?;
        let mut directory = duplicate_fd(&self.staging)?;
        for name in directories {
            directory = open_or_create_directory(&directory, name)?;
        }
        let fd = open_at2(
            &directory,
            file_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        let mut file: File = fd.into();
        file.write_all(bytes)
            .map_err(|_| MaterializationError::DurabilitySyncFailed)?;
        file.sync_all()
            .map_err(|_| MaterializationError::DurabilitySyncFailed)?;
        sync_fd(&directory)
    }

    fn verify_and_sync(&self, files: &[MaterializedFile]) -> Result<(), MaterializationError> {
        for file in files {
            let bytes = self.read_file(&file.relative_path)?;
            if bytes != file.bytes {
                return Err(MaterializationError::ArchiveDigestMismatch);
            }
            if let Some(archive) = &file.archive {
                verify_public_archive(
                    &bytes,
                    &archive.digest,
                    &archive.manifest,
                    &archive.release_filename,
                )
                .map_err(|_| MaterializationError::ArchiveDigestMismatch)?;
            }
        }
        sync_fd(&self.staging)
    }

    fn read_file(&self, relative_path: &str) -> Result<Vec<u8>, MaterializationError> {
        let components = relative_components(Path::new(relative_path))?;
        let (file_name, directories) = components
            .split_last()
            .ok_or(MaterializationError::UntrustedOutputDirectory)?;
        let mut directory = duplicate_fd(&self.staging)?;
        for name in directories {
            directory = open_directory(&directory, name)?;
        }
        let fd = open_at2(
            &directory,
            file_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        let mut file: File = fd.into();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| MaterializationError::ArchiveDigestMismatch)?;
        Ok(bytes)
    }

    fn publish(self) -> Result<(), MaterializationError> {
        fs::renameat_with(
            &self.parent,
            self.staging_name.as_c_str(),
            &self.parent,
            self.destination_name.as_c_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(map_publish_error)?;
        sync_fd(&self.parent)
    }
}

#[cfg(target_os = "linux")]
fn publish_materialized_tree(
    destination: &Path,
    files: &[MaterializedFile],
) -> Result<(), MaterializationError> {
    let publication = AtomicPublication::prepare(destination)?;
    for file in files {
        publication.write_file(&file.relative_path, &file.bytes)?;
    }
    publication.verify_and_sync(files)?;
    publication.publish()
}

#[cfg(not(target_os = "linux"))]
fn publish_materialized_tree(
    _destination: &Path,
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
    let parent = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| MaterializationError::UntrustedOutputDirectory)?;
    open_at2(
        CWD,
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
}

#[cfg(target_os = "linux")]
fn create_private_staging(parent: &OwnedFd) -> Result<(CString, OwnedFd), MaterializationError> {
    for _ in 0..16 {
        let name = random_staging_name()?;
        match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                let staging = open_directory(parent, &name)?;
                return Ok((name, staging));
            }
            Err(Errno::EXIST) => {}
            Err(Errno::LOOP) => return Err(MaterializationError::SymlinkDetected),
            Err(_) => return Err(MaterializationError::UntrustedOutputDirectory),
        }
    }
    Err(MaterializationError::UntrustedOutputDirectory)
}

#[cfg(target_os = "linux")]
fn random_staging_name() -> Result<CString, MaterializationError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| MaterializationError::AtomicPublicationUnsupported)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        suffix.push(char::from(HEX[usize::from(byte >> 4)]));
        suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    CString::new(format!(".pigloros-conformance-staging-{suffix}"))
        .map_err(|_| MaterializationError::AtomicPublicationUnsupported)
}

#[cfg(target_os = "linux")]
fn relative_components(path: &Path) -> Result<Vec<CString>, MaterializationError> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(MaterializationError::UntrustedOutputDirectory);
        };
        components.push(
            CString::new(name.as_bytes())
                .map_err(|_| MaterializationError::UntrustedOutputDirectory)?,
        );
    }
    if components.is_empty() {
        return Err(MaterializationError::UntrustedOutputDirectory);
    }
    Ok(components)
}

#[cfg(target_os = "linux")]
fn open_or_create_directory(
    parent: &OwnedFd,
    name: &CString,
) -> Result<OwnedFd, MaterializationError> {
    match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(Errno::LOOP) => return Err(MaterializationError::SymlinkDetected),
        Err(_) => return Err(MaterializationError::UntrustedOutputDirectory),
    }
    sync_fd(parent)?;
    open_directory(parent, name)
}

#[cfg(target_os = "linux")]
fn open_directory(parent: &OwnedFd, name: &CString) -> Result<OwnedFd, MaterializationError> {
    open_at2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
}

#[cfg(target_os = "linux")]
fn duplicate_fd(fd: &OwnedFd) -> Result<OwnedFd, MaterializationError> {
    rustix::io::dup(fd).map_err(|_| MaterializationError::UntrustedOutputDirectory)
}

#[cfg(target_os = "linux")]
fn sync_fd(fd: &OwnedFd) -> Result<(), MaterializationError> {
    fs::fsync(fd).map_err(|_| MaterializationError::DurabilitySyncFailed)
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
        Errno::LOOP => MaterializationError::SymlinkDetected,
        Errno::NOSYS | Errno::INVAL => MaterializationError::AtomicPublicationUnsupported,
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_conformance::{ExecutionModeV1, SafeErrorCodeV1};

    fn local_bundle_artifacts(
        profile: &ConformanceProfileV2,
        signing_key: &SigningKey,
    ) -> Result<LocalBundleArtifacts, Box<dyn Error>> {
        let (members, expected_results) = bundle_inputs(profile, BundleModeV1::Local)?;
        let bundle = ConformanceBundleV1::materialize(
            profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?
        .sign(signing_key)?;
        let digest = bundle.archive_digest()?;
        let manifest = bundle.manifest_bytes()?;
        let bytes = bundle.to_canonical_cbor()?;
        Ok((bytes, digest, manifest, bundle.release_filename()?))
    }

    type LocalBundleArtifacts = (Vec<u8>, [u8; 32], Vec<u8>, String);

    fn test_profile(claim_layer: ClaimLayerV1) -> Result<ConformanceProfileV2, Box<dyn Error>> {
        profile_for_claim_layer(claim_layer)
    }

    #[test]
    fn helper_validation_seams_cover_alternate_records() -> Result<(), Box<dyn Error>> {
        helper_validation_seams_cover_codecs();
        let canonical_bytes = profile_record_bytes(ClaimLayerV1::ArtifactIntegrity);
        let canonical_record: JsonValue = serde_json::from_slice(canonical_bytes)?;
        let context = fixture_context(canonical_bytes, ClaimLayerV1::ArtifactIntegrity);
        helper_validation_seams_reject_profile_binding_changes(&canonical_record);
        helper_validation_seams_cover_fixture_variants(&canonical_record, &context)?;
        helper_validation_seams_cover_protocol_caps();
        Ok(())
    }

    fn helper_validation_seams_cover_codecs() {
        assert_eq!(pos_conformance::decode_hex_digest("00"), None);
        assert_eq!(pos_conformance::decode_hex_digest(&"gg".repeat(32)), None);
        assert_eq!(pos_conformance::decode_hex_digest(&"0g".repeat(32)), None);
        assert_eq!(
            pos_conformance::decode_hex_digest(&"ab".repeat(32)),
            Some([0xab; 32])
        );
        assert_eq!(
            pos_conformance::decode_hex_digest(&"AB".repeat(32)),
            Some([0xab; 32])
        );
        assert_eq!(
            pos_conformance::decode_hex_digest(&"01".repeat(32)),
            Some([0x01; 32])
        );
        assert_eq!(
            pos_conformance::decode_hex_digest(&"a5".repeat(32)),
            Some([0xa5; 32])
        );
        assert_eq!(pos_conformance::hex_digest(&[0xabu8; 32]), "ab".repeat(32));
        assert!(json_text(&JsonValue::Null, "missing").is_err());
        assert!(json_u64(&JsonValue::Null, "missing").is_err());
        assert!(json_string_array(&JsonValue::Null, "missing").is_err());
        assert!(json_string_array(&serde_json::json!({"values": ["ok", 7]}), "values").is_err());
    }

    fn helper_validation_seams_reject_profile_binding_changes(canonical_record: &JsonValue) {
        assert!(validate_profile_record_bindings(
            ClaimLayerV1::ArtifactIntegrity,
            canonical_record
        )
        .is_ok());
        for field in [
            "profile_id",
            "claim_layer",
            "fixture_root",
            "wire_code",
            "authority_inventory",
            "adr_059_execution_matrix",
            "adr_059_execution_matrix_status",
        ] {
            let mut invalid_metadata = canonical_record.clone();
            invalid_metadata[field] = JsonValue::String("invalid".to_owned());
            assert!(validate_profile_record_bindings(
                ClaimLayerV1::ArtifactIntegrity,
                &invalid_metadata
            )
            .is_err());
        }
        for field in ["execution_profiles", "bundle_modes"] {
            let mut invalid_metadata = canonical_record.clone();
            invalid_metadata[field] = JsonValue::Array(vec![JsonValue::String("invalid".into())]);
            assert!(validate_profile_record_bindings(
                ClaimLayerV1::ArtifactIntegrity,
                &invalid_metadata
            )
            .is_err());
        }
        let mut invalid_digest = canonical_record.clone();
        invalid_digest["authority_inventory_sha256_digest"] = JsonValue::String("00".repeat(32));
        assert!(
            validate_profile_record_bindings(ClaimLayerV1::ArtifactIntegrity, &invalid_digest)
                .is_err()
        );
        let mut invalid_matrix_digest = canonical_record.clone();
        invalid_matrix_digest["adr_059_execution_matrix_blake3_digest"] =
            JsonValue::String("00".repeat(32));
        assert!(validate_profile_record_bindings(
            ClaimLayerV1::ArtifactIntegrity,
            &invalid_matrix_digest
        )
        .is_err());
    }

    fn helper_validation_seams_cover_fixture_variants(
        canonical_record: &JsonValue,
        context: &FixtureContext,
    ) -> Result<(), Box<dyn Error>> {
        let fixture_records = canonical_record["fixtures"]
            .as_array()
            .ok_or("canonical fixture records are missing")?;
        let deletion_record = fixture_records
            .iter()
            .find(|record| record.get("family").and_then(JsonValue::as_str) == Some("deletion"))
            .ok_or("canonical deletion fixture is missing")?;
        let deletion = fixture_descriptor_from_record(
            deletion_record,
            context,
            context.local_execution_profile_digest,
            ExecutionModeV1::Local,
        )?;
        assert_eq!(
            deletion.expected_verification_outcome,
            VerificationOutcomeV1::UnverifiableArtifactsMissing
        );
        assert_eq!(
            deletion.expected_verification_error,
            Some(SafeErrorCodeV1::ProvenanceMissing)
        );
        assert_eq!(
            deletion.replay_claim,
            pos_conformance::ReplayClaimV1::UnverifiableArtifactsMissing
        );
        assert_eq!(
            deletion.redaction_state,
            pos_conformance::RedactionStateV1::EvidenceMissing
        );

        let positive_record = fixture_records
            .iter()
            .find(|record| record.get("family").and_then(JsonValue::as_str) == Some("positive"))
            .ok_or("canonical positive fixture is missing")?;
        let positive = fixture_descriptor_from_record(
            positive_record,
            context,
            context.local_execution_profile_digest,
            ExecutionModeV1::Local,
        )?;
        assert_eq!(
            positive.expected_verification_outcome,
            VerificationOutcomeV1::UnverifiableArtifactsMissing
        );
        assert_eq!(
            positive.expected_verification_error,
            Some(SafeErrorCodeV1::ProvenanceMissing)
        );
        assert_eq!(
            positive.replay_claim,
            pos_conformance::ReplayClaimV1::UnverifiableArtifactsMissing
        );
        assert_eq!(
            positive.redaction_state,
            pos_conformance::RedactionStateV1::EvidenceMissing
        );
        Ok(())
    }

    fn helper_validation_seams_cover_protocol_caps() {
        let protocol = evaluator_protocol([42; 32]);
        assert_eq!(protocol.hard_caps.max_profile_bytes, 16_777_216);
        assert_eq!(protocol.hard_caps.max_member_path_bytes, 256);
        assert_eq!(protocol.hard_caps.max_member_bytes, 67_108_864);
        assert_eq!(protocol.hard_caps.max_total_bundle_bytes, 1_073_741_824);
        assert_eq!(protocol.hard_caps.max_diagnostic_bytes, 1_048_576);
    }

    #[test]
    fn helper_validation_seams_reject_invalid_fixture_records() -> Result<(), Box<dyn Error>> {
        let canonical_bytes = profile_record_bytes(ClaimLayerV1::ArtifactIntegrity);
        let canonical_record: JsonValue = serde_json::from_slice(canonical_bytes)?;
        let context = fixture_context(canonical_bytes, ClaimLayerV1::ArtifactIntegrity);
        let positive_record = &canonical_record["fixtures"][0];
        let positive_input_path = json_text(positive_record, "input")?;
        let positive_expected_path = json_text(positive_record, "expected")?;
        let (positive_input, positive_expected) = canonical_fixture_bytes(
            ClaimLayerV1::ArtifactIntegrity,
            positive_input_path,
            positive_expected_path,
        )?;
        assert!(validate_fixture_records(
            positive_input,
            positive_expected,
            "artifact-integrity-positive",
            "positive",
            "artifact-integrity",
        )
        .is_ok());
        let mut invalid_expected: JsonValue = serde_json::from_slice(positive_expected)?;
        invalid_expected["status"] = JsonValue::String("verified".to_owned());
        let invalid_expected_bytes = serde_json::to_vec(&invalid_expected)?;
        assert!(validate_fixture_records(
            positive_input,
            &invalid_expected_bytes,
            "artifact-integrity-positive",
            "positive",
            "artifact-integrity",
        )
        .is_err());
        let mut mismatched_input_digest: JsonValue = serde_json::from_slice(positive_expected)?;
        mismatched_input_digest["input_blake3_digest"] = JsonValue::String("00".repeat(32));
        let mismatched_input_digest_bytes = serde_json::to_vec(&mismatched_input_digest)?;
        assert!(validate_fixture_records(
            positive_input,
            &mismatched_input_digest_bytes,
            "artifact-integrity-positive",
            "positive",
            "artifact-integrity",
        )
        .is_err());
        let mut invalid_input: JsonValue = serde_json::from_slice(positive_input)?;
        invalid_input["case_id"] = JsonValue::String("wrong-case".to_owned());
        let invalid_input_bytes = serde_json::to_vec(&invalid_input)?;
        assert!(validate_fixture_records(
            &invalid_input_bytes,
            positive_expected,
            "artifact-integrity-positive",
            "positive",
            "artifact-integrity",
        )
        .is_err());
        let mut invalid_fixtures = canonical_record;
        invalid_fixtures["fixtures"] = JsonValue::Array(Vec::new());
        assert!(fixtures_from_profile_record(&invalid_fixtures, &context).is_err());
        invalid_fixtures["fixtures"] = JsonValue::Null;
        assert!(fixtures_from_profile_record(&invalid_fixtures, &context).is_err());
        let invalid_fixture = serde_json::json!({
            "case_id": "artifact-integrity-positive",
            "family": "positive",
            "input": "inputs/replay-conformance/negative.json",
            "expected": "expected/replay-conformance/negative.json"
        });
        let mut invalid_collection = serde_json::json!({"fixtures": [invalid_fixture]});
        assert!(fixtures_from_profile_record(&invalid_collection, &context).is_err());
        invalid_collection["fixtures"] = JsonValue::Array(vec![JsonValue::Null]);
        assert!(fixtures_from_profile_record(&invalid_collection, &context).is_err());
        invalid_collection["fixtures"] = JsonValue::Array(vec![invalid_fixture.clone(); 7]);
        assert!(fixtures_from_profile_record(&invalid_collection, &context).is_err());
        assert!(fixture_descriptor_from_record(
            &invalid_fixture,
            &context,
            context.local_execution_profile_digest,
            pos_conformance::ExecutionModeV1::Local,
        )
        .is_err());
        for invalid_fixture in [
            serde_json::json!({}),
            serde_json::json!({"case_id": "artifact-integrity-positive"}),
            serde_json::json!({"case_id": "artifact-integrity-positive", "family": "positive"}),
            serde_json::json!({
                "case_id": "artifact-integrity-positive",
                "family": "positive",
                "input": "inputs/artifact-integrity/positive.json"
            }),
        ] {
            assert!(fixture_descriptor_from_record(
                &invalid_fixture,
                &context,
                context.local_execution_profile_digest,
                pos_conformance::ExecutionModeV1::Local,
            )
            .is_err());
        }
        assert_eq!(family_for_path("unknown", "unknown"), None);
        assert!(
            canonical_fixture_bytes(ClaimLayerV1::ArtifactIntegrity, "unknown", "unknown").is_err()
        );
        assert!(canonical_fixture_input(ClaimLayerV1::ArtifactIntegrity, "unknown").is_err());
        Ok(())
    }

    #[test]
    fn fixture_record_predicates_fail_closed_independently() -> Result<(), Box<dyn Error>> {
        let canonical_bytes = profile_record_bytes(ClaimLayerV1::ArtifactIntegrity);
        let canonical_record: JsonValue = serde_json::from_slice(canonical_bytes)?;
        let fixture = &canonical_record["fixtures"][0];
        let (positive_input, positive_expected) = canonical_fixture_bytes(
            ClaimLayerV1::ArtifactIntegrity,
            json_text(fixture, "input")?,
            json_text(fixture, "expected")?,
        )?;
        let input_record: JsonValue = serde_json::from_slice(positive_input)?;
        let expected_record: JsonValue = serde_json::from_slice(positive_expected)?;
        for field in ["claim_layer", "family"] {
            let mut invalid_expected = expected_record.clone();
            invalid_expected[field] = JsonValue::String("wrong".to_owned());
            let invalid_expected = serde_json::to_vec(&invalid_expected)?;
            assert!(validate_fixture_records(
                positive_input,
                &invalid_expected,
                "artifact-integrity-positive",
                "positive",
                "artifact-integrity",
            )
            .is_err());
        }
        for field in ["kind", "error_code"] {
            let mut invalid_expected = expected_record.clone();
            invalid_expected["draft_expected_result"][field] =
                JsonValue::String("wrong".to_owned());
            let invalid_expected = serde_json::to_vec(&invalid_expected)?;
            assert!(validate_fixture_records(
                positive_input,
                &invalid_expected,
                "artifact-integrity-positive",
                "positive",
                "artifact-integrity",
            )
            .is_err());
        }
        for field in ["subject", "assertion"] {
            let mut invalid_input = input_record.clone();
            invalid_input[field] = JsonValue::String(String::new());
            let invalid_input = serde_json::to_vec(&invalid_input)?;
            let mut matching_expected = expected_record.clone();
            matching_expected["input_blake3_digest"] = JsonValue::String(
                pos_conformance::hex_digest(blake3::hash(&invalid_input).as_bytes()),
            );
            let matching_expected = serde_json::to_vec(&matching_expected)?;
            assert!(validate_fixture_records(
                &invalid_input,
                &matching_expected,
                "artifact-integrity-positive",
                "positive",
                "artifact-integrity",
            )
            .is_err());
        }
        for (field, replacement) in [
            ("result", JsonValue::String(String::new())),
            ("status", JsonValue::String("verified".to_owned())),
            ("verification", JsonValue::Bool(true)),
            ("source", JsonValue::Bool(true)),
        ] {
            let mut invalid_expected = expected_record.clone();
            invalid_expected[field] = replacement;
            let invalid_expected = serde_json::to_vec(&invalid_expected)?;
            assert!(validate_fixture_records(
                positive_input,
                &invalid_expected,
                "artifact-integrity-positive",
                "positive",
                "artifact-integrity",
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn knowledge_profile_matrix_binding_predicates_fail_closed() -> Result<(), Box<dyn Error>> {
        let record: JsonValue =
            serde_json::from_slice(profile_record_bytes(ClaimLayerV1::KnowledgeNonInterference))?;
        for (field, replacement) in [
            (
                "adr_059_execution_matrix",
                JsonValue::String("wrong".to_owned()),
            ),
            (
                "adr_059_execution_matrix_status",
                JsonValue::String("wrong".to_owned()),
            ),
            (
                "adr_059_execution_matrix_blake3_digest",
                JsonValue::String("00".repeat(32)),
            ),
        ] {
            let mut invalid_record = record.clone();
            invalid_record[field] = replacement;
            assert!(validate_profile_record_bindings(
                ClaimLayerV1::KnowledgeNonInterference,
                &invalid_record,
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn profile_and_fixture_construction_paths_are_exercised() -> Result<(), Box<dyn Error>> {
        let canonical_bytes = profile_record_bytes(ClaimLayerV1::ArtifactIntegrity);
        let canonical_record: JsonValue = serde_json::from_slice(canonical_bytes)?;
        let context = fixture_context(canonical_bytes, ClaimLayerV1::ArtifactIntegrity);
        assert!(fixtures_from_profile_record(&canonical_record, &context).is_ok());
        let fixture_record = &canonical_record["fixtures"][0];
        assert!(fixture_descriptor_from_record(
            fixture_record,
            &context,
            context.local_execution_profile_digest,
            ExecutionModeV1::Local,
        )
        .is_ok());

        let mut wrong_layer = canonical_record.clone();
        wrong_layer["fixtures"][0]["claim_layer"] = JsonValue::String("wrong".to_owned());
        assert!(fixtures_from_profile_record(&wrong_layer, &context).is_err());
        let mut unknown_fixture = canonical_record;
        unknown_fixture["fixtures"][0]["input"] =
            JsonValue::String("inputs/artifact-integrity/unknown.json".to_owned());
        assert!(fixtures_from_profile_record(&unknown_fixture, &context).is_err());

        let knowledge_bytes = profile_record_bytes(ClaimLayerV1::KnowledgeNonInterference);
        let knowledge_record: JsonValue = serde_json::from_slice(knowledge_bytes)?;
        assert!(profile_from_record(
            ClaimLayerV1::KnowledgeNonInterference,
            knowledge_bytes,
            &knowledge_record,
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn canonical_record_required_fields_reject_missing_values() -> Result<(), Box<dyn Error>> {
        let canonical_bytes = profile_record_bytes(ClaimLayerV1::ArtifactIntegrity);
        let canonical_record: JsonValue = serde_json::from_slice(canonical_bytes)?;
        assert!(validated_profile_record_bytes(ClaimLayerV1::ArtifactIntegrity, b"{").is_err());
        let mut invalid_record = canonical_record.clone();
        invalid_record["profile_id"] = JsonValue::Null;
        let invalid_record_bytes = serde_json::to_vec(&invalid_record)?;
        assert!(validated_profile_record_bytes(
            ClaimLayerV1::ArtifactIntegrity,
            &invalid_record_bytes,
        )
        .is_err());
        let mut invalid_fixtures = canonical_record.clone();
        invalid_fixtures["fixtures"] = JsonValue::Null;
        assert!(profile_from_record(
            ClaimLayerV1::ArtifactIntegrity,
            canonical_bytes,
            &invalid_fixtures,
        )
        .is_err());
        let context = fixture_context(canonical_bytes, ClaimLayerV1::ArtifactIntegrity);
        let invalid_collection = serde_json::json!({"fixtures": [JsonValue::Null]});
        assert!(fixtures_from_profile_record(&invalid_collection, &context).is_err());
        let invalid_fixture = serde_json::json!({
            "case_id": "artifact-integrity-positive",
            "family": "positive",
            "input": "inputs/artifact-integrity/positive.json"
        });
        let invalid_collection = serde_json::json!({"fixtures": [invalid_fixture]});
        assert!(fixtures_from_profile_record(&invalid_collection, &context).is_err());
        for field in [
            "profile_id",
            "claim_layer",
            "fixture_root",
            "wire_code",
            "authority_inventory",
            "execution_profiles",
            "bundle_modes",
            "authority_inventory_sha256_digest",
        ] {
            let mut missing = canonical_record.clone();
            missing
                .as_object_mut()
                .ok_or("canonical profile record is not an object")?
                .remove(field);
            assert!(
                validate_profile_record_bindings(ClaimLayerV1::ArtifactIntegrity, &missing)
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn archive_validation_seams() -> Result<(), Box<dyn Error>> {
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let (archive_bytes, archive_digest, manifest, release_filename) =
            local_bundle_artifacts(&profile, &signing_key)?;
        let mut wrong_digest = archive_digest;
        wrong_digest[0] ^= 1;
        assert!(
            verify_public_archive(&archive_bytes, &wrong_digest, &manifest, &release_filename)
                .is_err()
        );
        assert!(verify_public_archive(
            &archive_bytes,
            &archive_digest,
            b"invalid",
            &release_filename
        )
        .is_err());
        assert!(
            verify_public_archive(b"invalid", &archive_digest, &manifest, &release_filename)
                .is_err()
        );
        let mut invalid_signature_bytes = archive_bytes;
        let signature_byte = invalid_signature_bytes
            .last_mut()
            .ok_or("canonical bundle must contain a signature")?;
        *signature_byte ^= 1;
        assert!(verify_public_archive(
            &invalid_signature_bytes,
            &archive_digest,
            &manifest,
            &release_filename,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn helper_validation_seams_cover_materialization_errors() -> Result<(), Box<dyn Error>> {
        let candidate = br#"{"lifecycle":"Candidate"}"#;
        assert!(publication_lifecycles_from_bytes(candidate).is_err());
        let draft = br#"{"lifecycle":"Draft"}"#;
        assert_eq!(
            publication_lifecycles_from_bytes(draft).as_ref().ok(),
            Some(&vec![(ProfileLifecycleV1::Draft, "draft")])
        );
        assert!(publication_lifecycles_from_bytes(b"{}").is_err());
        assert!(publication_lifecycles_from_bytes(br#"{"lifecycle":"Retired"}"#).is_err());
        assert!(publication_lifecycles_from_bytes(b"{").is_err());
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        assert!(bundle_inputs_from_profile(&profile, BundleModeV1::Local, b"{").is_err());
        assert!(bundle_inputs_from_profile(&profile, BundleModeV1::Local, b"{}").is_err());
        let mut invalid_input_profile = profile;
        invalid_input_profile.fixtures[0].inputs[0].member_id =
            "inputs/artifact-integrity/unknown.json".to_owned();
        assert!(bundle_inputs(&invalid_input_profile, BundleModeV1::Local).is_err());

        let mut invalid_expected = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        invalid_expected.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding);
        assert!(bundle_inputs(&invalid_expected, BundleModeV1::Local).is_ok());

        let mut invalid_profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        invalid_profile.fixtures.clear();
        assert!(bundle_inputs(&invalid_profile, BundleModeV1::Local).is_err());

        let mut unsupported_mode = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        for fixture in &mut unsupported_mode.fixtures {
            fixture.modes = vec![ExecutionModeV1::AirGapped];
        }
        assert!(bundle_inputs(&unsupported_mode, BundleModeV1::Local).is_err());
        Ok(())
    }

    #[test]
    fn materializer_rejects_each_public_fixture_boundary() -> Result<(), Box<dyn Error>> {
        materializer_rejects_non_draft_lifecycle()?;
        materializer_rejects_matrix_binding_changes()?;
        materializer_rejects_invalid_fixture_records()?;
        materializer_recognizes_every_fixture_family();
        Ok(())
    }

    fn materializer_rejects_non_draft_lifecycle() -> Result<(), Box<dyn Error>> {
        let draft = br#"{"lifecycle":"Draft"}"#;
        let candidate = br#"{"lifecycle":"Candidate"}"#;
        assert!(publication_lifecycles_from_bytes(candidate).is_err());
        let mut members = Vec::new();
        assert!(append_supporting_members(&mut members, candidate).is_err());
        assert!(append_supporting_members(&mut members, draft).is_ok());
        Ok(())
    }

    fn materializer_rejects_matrix_binding_changes() -> Result<(), Box<dyn Error>> {
        let knowledge_bytes = profile_record_bytes(ClaimLayerV1::KnowledgeNonInterference);
        let knowledge: JsonValue = serde_json::from_slice(knowledge_bytes)?;
        assert!(validate_profile_record_bindings(
            ClaimLayerV1::KnowledgeNonInterference,
            &knowledge,
        )
        .is_ok());
        for field in [
            "adr_059_execution_matrix",
            "adr_059_execution_matrix_status",
            "adr_059_execution_matrix_blake3_digest",
        ] {
            let mut changed = knowledge.clone();
            changed[field] = JsonValue::String("invalid".to_owned());
            assert!(validate_profile_record_bindings(
                ClaimLayerV1::KnowledgeNonInterference,
                &changed,
            )
            .is_err());
        }
        Ok(())
    }

    fn materializer_rejects_invalid_fixture_records() -> Result<(), Box<dyn Error>> {
        let artifact_bytes = profile_record_bytes(ClaimLayerV1::ArtifactIntegrity);
        let artifact: JsonValue = serde_json::from_slice(artifact_bytes)?;
        let fixture_record = &artifact["fixtures"][0];
        let input_path = json_text(fixture_record, "input")?;
        let expected_path = json_text(fixture_record, "expected")?;
        let (input, expected) =
            canonical_fixture_bytes(ClaimLayerV1::ArtifactIntegrity, input_path, expected_path)?;
        for (changed_input, changed_expected) in [
            (b"{".as_slice(), expected),
            (input, b"{".as_slice()),
            (input, br#"{"case_id":"wrong"}"#.as_slice()),
        ] {
            assert!(validate_fixture_records(
                changed_input,
                changed_expected,
                "artifact-integrity-positive",
                "positive",
                "artifact-integrity",
            )
            .is_err());
        }
        assert!(canonical_fixture_bytes(
            ClaimLayerV1::ArtifactIntegrity,
            "inputs/replay-conformance/positive.json",
            "expected/replay-conformance/positive.json",
        )
        .is_err());
        assert!(canonical_fixture_bytes(
            ClaimLayerV1::ArtifactIntegrity,
            "inputs/replay-conformance/positive.json",
            "expected/artifact-integrity/positive.json",
        )
        .is_err());
        assert!(canonical_fixture_bytes(
            ClaimLayerV1::ArtifactIntegrity,
            "inputs/artifact-integrity/positive.json",
            "expected/replay-conformance/positive.json",
        )
        .is_err());
        Ok(())
    }

    fn materializer_recognizes_every_fixture_family() {
        for (input_path, expected_path, expected_family) in [
            (
                "inputs/artifact-integrity/positive.json",
                "expected/artifact-integrity/positive.json",
                Some("positive"),
            ),
            (
                "inputs/artifact-integrity/negative.json",
                "expected/artifact-integrity/negative.json",
                Some("negative"),
            ),
            (
                "inputs/artifact-integrity/malformed.json",
                "expected/artifact-integrity/malformed.json",
                Some("malformed"),
            ),
            (
                "inputs/artifact-integrity/resource.json",
                "expected/artifact-integrity/resource.json",
                Some("resource"),
            ),
            (
                "inputs/artifact-integrity/deletion.json",
                "expected/artifact-integrity/deletion.json",
                Some("deletion"),
            ),
            (
                "inputs/artifact-integrity/downgrade.json",
                "expected/artifact-integrity/downgrade.json",
                Some("downgrade"),
            ),
            (
                "inputs/artifact-integrity/independent-evaluation.json",
                "expected/artifact-integrity/independent-evaluation.json",
                Some("independent-evaluation"),
            ),
        ] {
            assert_eq!(family_for_path(input_path, expected_path), expected_family);
        }
        assert_eq!(
            family_for_path(
                "inputs/artifact-integrity/positive.json",
                "expected/artifact-integrity/negative.json",
            ),
            None,
        );
        assert_eq!(
            family_for_path(
                "wrong/artifact-integrity/positive.json",
                "expected/artifact-integrity/positive.json",
            ),
            None,
        );
        for (input_path, expected_path) in [
            ("inputs/", "expected/artifact-integrity/positive.json"),
            ("inputs/artifact-integrity/positive.json", "expected/"),
            (
                "inputs/artifact-integrity/.json",
                "expected/artifact-integrity/.json",
            ),
            (
                "inputs/artifact-integrity/positive.json",
                "wrong/artifact-integrity/positive.json",
            ),
        ] {
            assert_eq!(family_for_path(input_path, expected_path), None);
        }
    }
}
