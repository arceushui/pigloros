#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, verify_archive_independently,
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, ClaimLayerV1,
    ConformanceBundlePairV1, ConformanceBundleV1, ConformanceProfileV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1,
    FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::error::Error;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";

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
    output_root: &'a Path,
    signing_key: &'a SigningKey,
    inventory_bytes: &'a [u8],
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
    run_with_inventory(
        &mut arguments,
        encoded_signing_key,
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json"),
    )
}

fn run_with_inventory(
    arguments: &mut impl Iterator<Item = OsString>,
    encoded_signing_key: Result<String, std::env::VarError>,
    inventory_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let _program = arguments.next();
    let output_root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("materialization output directory is required")?;
    if arguments.next().is_some() {
        return Err("materialization accepts exactly one output directory".into());
    }
    if output_root.exists() {
        return Err("materialization output directory already exists".into());
    }
    let signing_key = signing_key_from_encoded(encoded_signing_key)?;
    let lifecycles = publication_lifecycles_from_bytes(inventory_bytes)?;
    std::fs::create_dir(&output_root)?;
    let context = MaterializationContext {
        output_root: &output_root,
        signing_key: &signing_key,
        inventory_bytes,
    };
    for spec in &LAYER_SPECS {
        for (lifecycle, lifecycle_name) in &lifecycles {
            materialize_profile_with_inventory(&context, spec, *lifecycle, lifecycle_name)?;
        }
    }
    Ok(())
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
    match inventory
        .get("lifecycle")
        .and_then(JsonValue::as_str)
        .ok_or("authority inventory lifecycle is missing")?
    {
        "Draft" => Ok(vec![(ProfileLifecycleV1::Draft, "draft")]),
        "Candidate" => {
            Err("Candidate materialization is owned by the #198 governance workflow".into())
        }
        _ => Err("unsupported authority inventory lifecycle".into()),
    }
}

fn materialize_profile_with_inventory(
    context: &MaterializationContext<'_>,
    layer: &LayerSpec,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
) -> Result<(), Box<dyn Error>> {
    profile_for_claim_layer(layer.claim_layer).and_then(|profile| {
        materialize_profile_from_profile(context, profile, lifecycle, lifecycle_name, layer.name)
    })
}

#[cfg(test)]
fn materialize_profile_for_test(
    output_root: &Path,
    signing_key: &SigningKey,
    profile: ConformanceProfileV1,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    layer_name: &str,
) -> Result<(), Box<dyn Error>> {
    let context = MaterializationContext {
        output_root,
        signing_key,
        inventory_bytes: include_bytes!(
            "../../../../fixtures/conformance/expected-authority/inventory.json"
        ),
    };
    materialize_profile_from_profile(&context, profile, lifecycle, lifecycle_name, layer_name)
}

fn materialize_profile_from_profile(
    context: &MaterializationContext<'_>,
    mut profile: ConformanceProfileV1,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    layer_name: &str,
) -> Result<(), Box<dyn Error>> {
    if lifecycle != ProfileLifecycleV1::Draft {
        return Err("the #190 materializer emits Draft bundles only".into());
    }
    profile.lifecycle = lifecycle;
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    let prefix = format!("{layer_name}/{lifecycle_name}");
    let mut outputs = vec![(
        format!(
            "{prefix}/CPF1-{}.cbor",
            pos_conformance::hex_digest(&profile.profile_digest)
        ),
        profile_bytes,
    )];
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
        let bundle = ConformanceBundleV1::materialize(&profile, mode, members, expected_results)
            .and_then(|bundle| bundle.sign(context.signing_key))
            .map_err(|error| {
                format!("failed to materialize {layer_name}/{mode_name} bundle: {error:?}")
            })?;
        signed_bundles.push(bundle);
    }
    let pair = ConformanceBundlePairV1 {
        local: signed_bundles.remove(0),
        air_gapped: signed_bundles.remove(0),
    };
    pair.validate()?;
    for (mode_name, bundle) in [("local", &pair.local), ("air-gapped", &pair.air_gapped)] {
        let bundle_digest = bundle.bundle_digest()?;
        let manifest_bytes = bundle.manifest_bytes()?;
        let bundle_bytes = bundle.to_canonical_cbor()?;
        verify_public_archive(&bundle_bytes, &bundle_digest, &manifest_bytes).map_err(|error| {
            format!("failed to verify {layer_name}/{mode_name} bundle: {error:?}")
        })?;
        outputs.push((
            format!(
                "{prefix}/manifest-{mode_name}-{}.cbor",
                pos_conformance::hex_digest(&bundle_digest)
            ),
            manifest_bytes,
        ));
        outputs.push((
            format!(
                "{prefix}/bundle-{mode_name}-{}.cfb1",
                pos_conformance::hex_digest(&bundle_digest)
            ),
            bundle_bytes,
        ));
    }
    for (relative_path, bytes) in outputs {
        write_materialized_file(context.output_root, relative_path, &bytes)?;
    }
    Ok(())
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
    if claim_layer != ClaimLayerV1::KnowledgeNonInterference
        && [
            "adr_059_execution_matrix",
            "adr_059_execution_matrix_blake3_digest",
            "adr_059_execution_matrix_status",
            "matrix",
            "matrix_size_bytes",
            "matrix_blake3_digest",
        ]
        .iter()
        .any(|field| profile_record.get(*field).is_some())
    {
        return Err("execution matrix binding is only valid for the knowledge profile".into());
    }
    Ok(())
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
        let local = fixture(
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
) -> Result<ConformanceProfileV1, Box<dyn Error>> {
    validated_profile_record(claim_layer).and_then(|(profile_record_bytes, profile_record)| {
        profile_from_record(claim_layer, profile_record_bytes, &profile_record)
    })
}

fn profile_from_record(
    claim_layer: ClaimLayerV1,
    profile_record_bytes: &[u8],
    profile_record: &JsonValue,
) -> Result<ConformanceProfileV1, Box<dyn Error>> {
    let context = fixture_context(profile_record_bytes, claim_layer);
    let fixtures = fixtures_from_profile_record(profile_record, &context)?;
    let mut execution_profile_digests = vec![
        context.local_execution_profile_digest,
        context.air_gapped_execution_profile_digest,
    ];
    execution_profile_digests.sort_unstable();
    let mut profile = ConformanceProfileV1 {
        profile_id: profile_id(claim_layer).to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: context.normative_spec_digest,
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
    if claim_layer == ClaimLayerV1::KnowledgeNonInterference {
        profile.bind_execution_matrix_digest(
            *blake3::hash(include_bytes!(
                "../../../../fixtures/conformance/matrix/execution-matrix.json"
            ))
            .as_bytes(),
        )?;
    } else {
        profile.profile_digest = profile.digest();
    }
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

fn fixture(
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
        "PiglorOS.CPF1FixtureRecord.v1",
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
    if !input_path.starts_with(&format!("inputs/{fixture_root}/"))
        || !expected_path.starts_with(&format!("expected/{fixture_root}/"))
    {
        return Err("canonical fixture paths are bound to the wrong claim layer".into());
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
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn Error>> {
    bundle_inputs_from_profile(
        profile,
        mode,
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json"),
    )
}

fn bundle_inputs_from_profile(
    profile: &ConformanceProfileV1,
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
    bundle_bytes: &[u8],
    expected_digest: &[u8; 32],
    expected_manifest: &[u8],
) -> Result<(), Box<dyn Error>> {
    ConformanceBundleV1::from_canonical_cbor(bundle_bytes)
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
                                .bundle_digest()
                                .map_err(|error| Box::new(error) as Box<dyn Error>)
                                .and_then(|bundle_digest| {
                                    if canonical_bytes != bundle_bytes
                                        || manifest_bytes != expected_manifest
                                        || bundle_digest != *expected_digest
                                    {
                                        Err("public archive verification did not reproduce canonical bytes"
                                            .into())
                                    } else {
                                        verify_archive_independently(bundle_bytes)
                                            .map_err(|error| Box::new(error) as Box<dyn Error>)
                                    }
                                })
                        })
                })
        })
}

fn write_materialized_file(
    root: &Path,
    relative: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let relative = relative.as_ref();
    let root_metadata = std::fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("materialized output root must be a directory".into());
    }
    let mut components = relative.components().peekable();
    let mut parent = root.to_owned();
    let file_name = loop {
        let component = components
            .next()
            .ok_or("materialized file path must not be empty")?;
        let Component::Normal(name) = component else {
            return Err("materialized file path must be relative and normalized".into());
        };
        if components.peek().is_none() {
            break name;
        }
        parent.push(name);
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("materialized output directory must not contain symlinks".into());
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err("materialized output path component is not a directory".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&parent)?;
            }
            Err(error) => return Err(error.into()),
        }
    };
    let path = parent.join(file_name);
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_conformance::{ExecutionModeV1, SafeErrorCodeV1};

    fn signing_key_hex() -> String {
        "07".repeat(32)
    }

    fn output_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pigloros-conformance-{name}-{}",
            std::process::id()
        ))
    }

    fn local_bundle_digest(profile: &ConformanceProfileV1, signing_key: &SigningKey) -> [u8; 32] {
        let digest = bundle_inputs(profile, BundleModeV1::Local)
            .ok()
            .and_then(|(members, expected_results)| {
                ConformanceBundleV1::materialize(
                    profile,
                    BundleModeV1::Local,
                    members,
                    expected_results,
                )
                .ok()
            })
            .and_then(|bundle| bundle.sign(signing_key).ok())
            .and_then(|bundle| bundle.bundle_digest().ok());
        assert!(digest.is_some(), "fixture bundle digest setup must succeed");
        digest.unwrap_or_default()
    }

    fn local_bundle_artifacts(
        profile: &ConformanceProfileV1,
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
        let digest = bundle.bundle_digest()?;
        let manifest = bundle.manifest_bytes()?;
        let bytes = bundle.to_canonical_cbor()?;
        Ok((bytes, digest, manifest))
    }

    type LocalBundleArtifacts = (Vec<u8>, [u8; 32], Vec<u8>);

    fn test_profile(claim_layer: ClaimLayerV1) -> Result<ConformanceProfileV1, Box<dyn Error>> {
        profile_for_claim_layer(claim_layer)
    }

    #[test]
    fn materializer_run_covers_all_profile_layers() {
        let output = output_root("run");
        let arguments = [
            OsString::from("materialize"),
            output.clone().into_os_string(),
        ];
        assert!(run(arguments.into_iter(), Ok(signing_key_hex())).is_ok());
        assert!(output.join("artifact-integrity/draft").is_dir());
        assert!(output.join("empirical-evaluation/draft").is_dir());
        assert!(std::fs::remove_dir_all(output).is_ok());
    }

    #[test]
    fn profile_binds_one_execution_profile_per_mode_and_preserves_pair_parity(
    ) -> Result<(), Box<dyn Error>> {
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        assert!(profile.execution_matrix_digest().is_err());
        let knowledge_profile = test_profile(ClaimLayerV1::KnowledgeNonInterference)?;
        assert_eq!(
            knowledge_profile.execution_matrix_digest()?,
            *blake3::hash(include_bytes!(
                "../../../../fixtures/conformance/matrix/execution-matrix.json"
            ))
            .as_bytes()
        );
        let inventory =
            include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let (local_members, local_expected) =
            bundle_inputs_from_profile(&profile, BundleModeV1::Local, inventory)?;
        let (air_gapped_members, air_gapped_expected) =
            bundle_inputs_from_profile(&profile, BundleModeV1::AirGapped, inventory)?;
        assert_eq!(local_expected.len(), 7);
        assert_eq!(air_gapped_expected.len(), 7);
        assert!(local_expected.iter().all(|expected| {
            expected.execution_profile_digest
                == labeled_digest("PiglorOS.ExecutionProfile.v1", b"deterministic-local-v1")
        }));
        assert!(air_gapped_expected.iter().all(|expected| {
            expected.execution_profile_digest
                == labeled_digest(
                    "PiglorOS.ExecutionProfile.v1",
                    b"deterministic-air-gapped-v1",
                )
        }));
        let local = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            local_members,
            local_expected,
        )?
        .sign(&signing_key)?;
        let air_gapped = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::AirGapped,
            air_gapped_members,
            air_gapped_expected,
        )?
        .sign(&signing_key)?;
        ConformanceBundlePairV1 { local, air_gapped }.validate()?;
        Ok(())
    }

    #[test]
    fn materializer_argument_and_key_errors_are_explicit() {
        let entry: fn() -> Result<(), Box<dyn Error>> = main;
        assert!(entry().is_err());
        assert!(run(
            [OsString::from("materialize")].into_iter(),
            Ok(signing_key_hex())
        )
        .is_err());
        let output = output_root("extra");
        let arguments = [
            OsString::from("materialize"),
            output.clone().into_os_string(),
            OsString::from("extra"),
        ];
        assert!(run(arguments.into_iter(), Ok(signing_key_hex())).is_err());
        assert!(std::fs::create_dir_all(&output).is_ok());
        let arguments = [
            OsString::from("materialize"),
            output.clone().into_os_string(),
        ];
        assert!(run(arguments.into_iter(), Ok(signing_key_hex())).is_err());
        assert!(std::fs::remove_dir_all(output).is_ok());
        let arguments = [OsString::from("materialize"), OsString::from("missing")];
        assert!(run(
            arguments.into_iter(),
            std::env::var("PIGLOROS_CONFORMANCE_MISSING_SIGNING_KEY")
        )
        .is_err());
        let blocker = output_root("blocker");
        assert!(std::fs::write(&blocker, b"not a directory").is_ok());
        let child = blocker.join("child");
        let arguments = [OsString::from("materialize"), child.into_os_string()];
        assert!(run(arguments.into_iter(), Ok(signing_key_hex())).is_err());
        assert!(std::fs::remove_file(blocker).is_ok());
        assert!(signing_key_from_encoded(std::env::var(
            "PIGLOROS_CONFORMANCE_MISSING_SIGNING_KEY"
        ))
        .is_err());
        assert!(signing_key_from_encoded(Ok("not-a-key".to_owned())).is_err());
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
        let deletion = fixture(
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
        let positive = fixture(
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
        assert!(fixture(
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
            assert!(fixture(
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
        let (bundle_bytes, bundle_digest, manifest) =
            local_bundle_artifacts(&profile, &signing_key)?;
        let mut wrong_digest = bundle_digest;
        wrong_digest[0] ^= 1;
        assert!(verify_public_archive(&bundle_bytes, &wrong_digest, &manifest).is_err());
        assert!(verify_public_archive(&bundle_bytes, &bundle_digest, b"invalid").is_err());
        assert!(verify_public_archive(b"invalid", &bundle_digest, &manifest).is_err());
        let mut invalid_signature_bytes = bundle_bytes;
        let signature_byte = invalid_signature_bytes
            .last_mut()
            .ok_or("canonical bundle must contain a signature")?;
        *signature_byte ^= 1;
        assert!(
            verify_public_archive(&invalid_signature_bytes, &bundle_digest, &manifest).is_err()
        );
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
        let mut invalid_inventory = [
            OsString::from("materialize"),
            OsString::from("invalid-inventory"),
        ]
        .into_iter();
        assert!(run_with_inventory(&mut invalid_inventory, Ok(signing_key_hex()), b"{}").is_err());
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
        let output = output_root("invalid-expected");
        assert!(materialize_profile_for_test(
            &output,
            &SigningKey::from_bytes(&[7; 32]),
            invalid_expected,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        drop(std::fs::remove_dir_all(output));

        let mut invalid_profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        invalid_profile.fixtures.clear();
        let output = output_root("invalid-profile");
        assert!(materialize_profile_for_test(
            &output,
            &SigningKey::from_bytes(&[7; 32]),
            invalid_profile,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        drop(std::fs::remove_dir_all(output));

        let mut unsupported_mode = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        for fixture in &mut unsupported_mode.fixtures {
            fixture.modes = vec![ExecutionModeV1::AirGapped];
        }
        let output = output_root("unsupported-mode");
        assert!(materialize_profile_for_test(
            &output,
            &SigningKey::from_bytes(&[7; 32]),
            unsupported_mode,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        drop(std::fs::remove_dir_all(output));

        let output = output_root("write-error");
        assert!(std::fs::create_dir_all(output.join("directory")).is_ok());
        assert!(write_materialized_file(&output, "directory", b"bytes").is_err());
        assert!(std::fs::remove_dir_all(output).is_ok());

        let blocker = output_root("create-dir-error");
        assert!(std::fs::write(&blocker, b"not a directory").is_ok());
        assert!(write_materialized_file(&blocker, "nested/file", b"bytes").is_err());
        assert!(std::fs::remove_file(blocker).is_ok());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn materialized_output_rejects_symlinked_parent_directories() -> Result<(), Box<dyn Error>> {
        let output = output_root("symlink-parent");
        std::fs::create_dir_all(output.join("real"))?;
        std::os::unix::fs::symlink(output.join("real"), output.join("link"))?;
        assert!(write_materialized_file(&output, "link/file", b"bytes").is_err());
        std::fs::remove_dir_all(output)?;

        let root_parent = output_root("symlink-root");
        let root_target = root_parent.join("target");
        let root_link = root_parent.join("link");
        std::fs::create_dir_all(&root_target)?;
        std::os::unix::fs::symlink(&root_target, &root_link)?;
        assert!(write_materialized_file(&root_link, "file", b"bytes").is_err());
        std::fs::remove_dir_all(root_parent)?;
        Ok(())
    }

    fn assert_canonical_profiles_bind_fixture_families() -> Result<(), Box<dyn Error>> {
        for spec in &LAYER_SPECS {
            let claim_layer = spec.claim_layer;
            let profile = test_profile(claim_layer)?;
            assert_eq!(profile.fixtures.len(), 14);
            assert_eq!(
                profile
                    .fixtures
                    .iter()
                    .filter(|fixture| fixture.modes == [pos_conformance::ExecutionModeV1::Local])
                    .count(),
                7
            );
            assert_eq!(
                profile
                    .fixtures
                    .iter()
                    .filter(|fixture| {
                        fixture.modes == [pos_conformance::ExecutionModeV1::AirGapped]
                    })
                    .count(),
                7
            );
            assert!(profile.fixtures.iter().all(|fixture| {
                fixture
                    .inputs
                    .first()
                    .is_some_and(|input| input.member_id.starts_with("inputs/"))
            }));
            assert!(profile
                .fixtures
                .iter()
                .all(|fixture| fixture.subject_adapter == subject_adapter(claim_layer)));
        }
        Ok(())
    }

    #[test]
    fn canonical_records_bind_fixture_families() -> Result<(), Box<dyn Error>> {
        assert_canonical_profiles_bind_fixture_families()?;
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        let (members, expected) = bundle_inputs(&profile, BundleModeV1::Local)?;
        assert_eq!(expected.len(), 7);
        assert!(members.iter().any(|member| {
            member.role == BundleMemberRoleV1::AuthorityInventory
                && member.path == AUTHORITY_INVENTORY_MEMBER_PATH
        }));
        Ok(())
    }

    #[test]
    fn materializer_manifest_and_bundle_write_errors_are_explicit() -> Result<(), Box<dyn Error>> {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        let digest = local_bundle_digest(&profile, &signing_key);
        let prefix = "artifact-integrity/draft";

        let manifest_root = output_root("manifest-error");
        assert!(std::fs::create_dir_all(manifest_root.join(prefix)).is_ok());
        assert!(std::fs::create_dir_all(manifest_root.join(format!(
            "{prefix}/manifest-local-{}.cbor",
            pos_conformance::hex_digest(&digest)
        )),)
        .is_ok());
        assert!(materialize_profile_for_test(
            &manifest_root,
            &signing_key,
            profile,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        assert!(std::fs::remove_dir_all(manifest_root).is_ok());

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        let digest = local_bundle_digest(&profile, &signing_key);
        let bundle_root = output_root("bundle-error");
        assert!(std::fs::create_dir_all(bundle_root.join(prefix)).is_ok());
        assert!(std::fs::write(
            bundle_root.join(format!(
                "{prefix}/manifest-local-{}.cbor",
                pos_conformance::hex_digest(&digest)
            )),
            b"existing",
        )
        .is_ok());
        assert!(std::fs::create_dir_all(bundle_root.join(format!(
            "{prefix}/bundle-local-{}.cfb1",
            pos_conformance::hex_digest(&digest)
        )),)
        .is_ok());
        assert!(materialize_profile_for_test(
            &bundle_root,
            &signing_key,
            profile,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        assert!(std::fs::remove_dir_all(bundle_root).is_ok());
        Ok(())
    }

    #[test]
    fn materializer_rejects_each_public_fixture_boundary() -> Result<(), Box<dyn Error>> {
        materializer_rejects_non_draft_lifecycle()?;
        materializer_rejects_matrix_binding_changes()?;
        materializer_rejects_invalid_fixture_records()?;
        materializer_recognizes_every_fixture_family();
        materialized_output_paths_are_fail_closed()?;
        Ok(())
    }

    fn materializer_rejects_non_draft_lifecycle() -> Result<(), Box<dyn Error>> {
        let draft = br#"{"lifecycle":"Draft"}"#;
        let candidate = br#"{"lifecycle":"Candidate"}"#;
        let mut candidate_arguments = [
            OsString::from("materialize"),
            OsString::from("candidate-inventory"),
        ]
        .into_iter();
        assert!(
            run_with_inventory(&mut candidate_arguments, Ok(signing_key_hex()), candidate,)
                .is_err()
        );

        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        let lifecycle_root = output_root("candidate-lifecycle");
        assert!(materialize_profile_for_test(
            &lifecycle_root,
            &SigningKey::from_bytes(&[7; 32]),
            profile,
            ProfileLifecycleV1::Candidate,
            "candidate",
            "artifact-integrity",
        )
        .is_err());
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
    }

    fn materialized_output_paths_are_fail_closed() -> Result<(), Box<dyn Error>> {
        let missing_root = output_root("missing-root");
        assert!(write_materialized_file(&missing_root, "file", b"bytes").is_err());

        let root = output_root("path-boundaries");
        std::fs::create_dir(&root)?;
        assert!(write_materialized_file(&root, "", b"bytes").is_err());
        assert!(write_materialized_file(&root, ".", b"bytes").is_err());
        assert!(write_materialized_file(&root, "../escape", b"bytes").is_err());

        std::fs::write(root.join("file-parent"), b"blocker")?;
        assert!(write_materialized_file(&root, "file-parent/child", b"bytes").is_err());
        assert!(write_materialized_file(&root, "created/nested/file", b"bytes").is_ok());
        assert_eq!(std::fs::read(root.join("created/nested/file"))?, b"bytes");
        assert!(write_materialized_file(&root, "created/nested/file", b"bytes").is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
