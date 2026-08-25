use ed25519_dalek::SigningKey;
use pos_conformance::{
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, ClaimLayerV1,
    ConformanceBundleV1, ConformanceProfileV1, EvaluatorHardCapsV1, EvaluatorProtocolV1,
    ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1, FixtureInputMemberV1,
    FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1, RedactionStateV1,
    ReplayClaimV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::error::Error;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

const AUTHORITY_ROOT_ENV: &str = "PIGLOROS_CONFORMANCE_AUTHORITY_ROOT";

const PROFILE_RECORDS: [(&[u8], ClaimLayerV1); 7] = [
    (
        include_bytes!("../../../../fixtures/conformance/profiles/artifact-integrity/profile.json"),
        ClaimLayerV1::ArtifactIntegrity,
    ),
    (
        include_bytes!("../../../../fixtures/conformance/profiles/replay-conformance/profile.json"),
        ClaimLayerV1::ReplayConformance,
    ),
    (
        include_bytes!(
            "../../../../fixtures/conformance/profiles/knowledge-non-interference/profile.json"
        ),
        ClaimLayerV1::KnowledgeNonInterference,
    ),
    (
        include_bytes!(
            "../../../../fixtures/conformance/profiles/gateway-client-conformance/profile.json"
        ),
        ClaimLayerV1::GatewayClientConformance,
    ),
    (
        include_bytes!("../../../../fixtures/conformance/profiles/plugin-conformance/profile.json"),
        ClaimLayerV1::PluginConformance,
    ),
    (
        include_bytes!("../../../../fixtures/conformance/profiles/metric-conformance/profile.json"),
        ClaimLayerV1::MetricConformance,
    ),
    (
        include_bytes!(
            "../../../../fixtures/conformance/profiles/empirical-evaluation/profile.json"
        ),
        ClaimLayerV1::EmpiricalEvaluation,
    ),
];

#[derive(Clone, Copy)]
struct FixtureContext {
    claim_layer: ClaimLayerV1,
    execution_profile_digest: [u8; 32],
    profile_record_digest: [u8; 32],
    schema_digest: [u8; 32],
    provenance_digest: [u8; 32],
    notice_digest: [u8; 32],
    sbom_digest: [u8; 32],
    limitations_digest: [u8; 32],
    normative_spec_digest: [u8; 32],
}

type CanonicalFixtureBytes = (&'static [u8], &'static [u8]);

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
    let authority_root = std::env::var_os(AUTHORITY_ROOT_ENV).map(PathBuf::from);
    run_with_inventory_and_authority(
        &mut arguments,
        encoded_signing_key,
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json"),
        authority_root,
    )
}

#[cfg(test)]
fn run_with_inventory(
    arguments: &mut impl Iterator<Item = OsString>,
    encoded_signing_key: Result<String, std::env::VarError>,
    inventory_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    run_with_inventory_and_authority(arguments, encoded_signing_key, inventory_bytes, None)
}

fn run_with_inventory_and_authority(
    arguments: &mut impl Iterator<Item = OsString>,
    encoded_signing_key: Result<String, std::env::VarError>,
    inventory_bytes: &[u8],
    authority_root: Option<&Path>,
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
    let layers = [
        (ClaimLayerV1::ArtifactIntegrity, "artifact-integrity"),
        (ClaimLayerV1::ReplayConformance, "replay-conformance"),
        (
            ClaimLayerV1::KnowledgeNonInterference,
            "knowledge-non-interference",
        ),
        (
            ClaimLayerV1::GatewayClientConformance,
            "gateway-client-conformance",
        ),
        (ClaimLayerV1::PluginConformance, "plugin-conformance"),
        (ClaimLayerV1::MetricConformance, "metric-conformance"),
        (ClaimLayerV1::EmpiricalEvaluation, "empirical-evaluation"),
    ];
    for (claim_layer, layer_name) in layers {
        for (lifecycle, lifecycle_name) in &lifecycles {
            materialize_profile_with_inventory(
                &output_root,
                &signing_key,
                claim_layer,
                layer_name,
                *lifecycle,
                lifecycle_name,
                inventory_bytes,
                authority_root,
            )?;
        }
    }
    Ok(())
}

fn signing_key_from_encoded(
    encoded: Result<String, std::env::VarError>,
) -> Result<SigningKey, Box<dyn Error>> {
    let encoded = encoded?;
    let bytes = decode_hex(&encoded).ok_or("invalid conformance signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(bytes)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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
        "Candidate" => Ok(vec![
            (ProfileLifecycleV1::Draft, "draft"),
            (ProfileLifecycleV1::Candidate, "candidate"),
        ]),
        _ => Err("unsupported authority inventory lifecycle".into()),
    }
}

fn materialize_profile_with_inventory(
    output_root: &Path,
    signing_key: &SigningKey,
    claim_layer: ClaimLayerV1,
    layer_name: &str,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    inventory_bytes: &[u8],
    authority_root: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let profile = profile_for_claim_layer(claim_layer)?;
    materialize_profile_from_profile_with_authority(
        output_root,
        signing_key,
        profile,
        lifecycle,
        lifecycle_name,
        layer_name,
        inventory_bytes,
        authority_root,
    )
}

#[cfg(test)]
fn materialize_profile_from_profile(
    output_root: &Path,
    signing_key: &SigningKey,
    profile: ConformanceProfileV1,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    layer_name: &str,
) -> Result<(), Box<dyn Error>> {
    materialize_profile_from_profile_with_authority(
        output_root,
        signing_key,
        profile,
        lifecycle,
        lifecycle_name,
        layer_name,
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json"),
        None,
    )
}

fn materialize_profile_from_profile_with_authority(
    output_root: &Path,
    signing_key: &SigningKey,
    mut profile: ConformanceProfileV1,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    layer_name: &str,
    inventory_bytes: &[u8],
    authority_root: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    profile.lifecycle = lifecycle;
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    let prefix = format!("{layer_name}/{lifecycle_name}");
    write_materialized_file(
        output_root,
        format!("{prefix}/CPF1-{}.cbor", hex(&profile.profile_digest)),
        &profile_bytes,
    )?;
    for (mode, mode_name) in [
        (BundleModeV1::Local, "local"),
        (BundleModeV1::AirGapped, "air-gapped"),
    ] {
        let (members, expected_results) =
            bundle_inputs_with_authority(&profile, mode, inventory_bytes, authority_root)?;
        let (bundle, bundle_digest) =
            ConformanceBundleV1::materialize(&profile, mode, members, expected_results)
                .and_then(|bundle| bundle.sign(signing_key))
                .and_then(|bundle| {
                    bundle
                        .bundle_digest()
                        .map(|bundle_digest| (bundle, bundle_digest))
                })?;
        let (manifest_bytes, bundle_bytes) =
            bundle.manifest_bytes().and_then(|manifest_bytes| {
                bundle
                    .to_canonical_cbor()
                    .map(|bundle_bytes| (manifest_bytes, bundle_bytes))
            })?;
        verify_public_archive(&bundle_bytes, &bundle_digest, &manifest_bytes)?;
        write_materialized_file(
            output_root,
            format!("{prefix}/manifest-{mode_name}-{}.cbor", hex(&bundle_digest)),
            &manifest_bytes,
        )?;
        write_materialized_file(
            output_root,
            format!("{prefix}/bundle-{mode_name}-{}.cfb1", hex(&bundle_digest)),
            &bundle_bytes,
        )?;
    }
    Ok(())
}

fn profile_record_bytes(claim_layer: ClaimLayerV1) -> Result<&'static [u8], Box<dyn Error>> {
    PROFILE_RECORDS
        .iter()
        .find(|(_, record_claim_layer)| *record_claim_layer == claim_layer)
        .map(|(bytes, _)| *bytes)
        .ok_or_else(|| "canonical profile record is missing".into())
}

fn validated_profile_record(
    claim_layer: ClaimLayerV1,
) -> Result<(&'static [u8], JsonValue), Box<dyn Error>> {
    let profile_record_bytes = profile_record_bytes(claim_layer)?;
    let profile_record: JsonValue = serde_json::from_slice(profile_record_bytes)?;
    if json_text(&profile_record, "profile_id")? != profile_id(claim_layer)
        || json_text(&profile_record, "claim_layer")? != claim_layer_name(claim_layer)
        || json_text(&profile_record, "authority_inventory")? != "expected-authority/inventory.json"
        || json_text(&profile_record, "adr_059_execution_matrix")? != "matrix/adr-059-complete.json"
        || json_text(&profile_record, "adr_059_execution_matrix_status")? != "Draft"
        || json_string_array(&profile_record, "execution_profiles")?
            != vec!["deterministic-local-v1", "deterministic-air-gapped-v1"]
        || json_string_array(&profile_record, "bundle_modes")? != vec!["local", "air-gapped"]
    {
        return Err("canonical profile record has invalid binding metadata".into());
    }
    let inventory =
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json");
    let matrix = include_bytes!("../../../../fixtures/conformance/matrix/adr-059-complete.json");
    if decode_hex(json_text(
        &profile_record,
        "authority_inventory_sha256_digest",
    )?) != Some(Sha256::digest(inventory).into())
        || decode_hex(json_text(
            &profile_record,
            "adr_059_execution_matrix_blake3_digest",
        )?) != Some(*blake3::hash(matrix).as_bytes())
    {
        return Err("canonical profile record digest binding is invalid".into());
    }
    Ok((profile_record_bytes, profile_record))
}

fn fixture_context(
    profile_record_bytes: &'static [u8],
    claim_layer: ClaimLayerV1,
) -> FixtureContext {
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
    let execution_profile_digest =
        labeled_digest("PiglorOS.ExecutionProfile.v1", b"deterministic-local-v1");
    FixtureContext {
        claim_layer,
        execution_profile_digest,
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
    let mut fixtures = fixture_records
        .iter()
        .map(|fixture_record| fixture(fixture_record, context))
        .collect::<Result<Vec<_>, _>>()?;
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
    let (profile_record_bytes, profile_record) = validated_profile_record(claim_layer)?;
    let context = fixture_context(profile_record_bytes, claim_layer);
    let fixtures = fixtures_from_profile_record(&profile_record, &context)?;
    let air_gapped_execution_profile_digest = labeled_digest(
        "PiglorOS.ExecutionProfile.v1",
        b"deterministic-air-gapped-v1",
    );
    let mut execution_profile_digests = vec![
        context.execution_profile_digest,
        air_gapped_execution_profile_digest,
    ];
    execution_profile_digests.sort_unstable();
    let mut profile = ConformanceProfileV1 {
        profile_id: json_text(&profile_record, "profile_id")?.to_owned(),
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
    profile.profile_digest = profile.digest();
    Ok(profile)
}

const fn profile_id(claim_layer: ClaimLayerV1) -> &'static str {
    match claim_layer {
        ClaimLayerV1::ArtifactIntegrity => "pigloros.w8.artifact-integrity.1.0.0",
        ClaimLayerV1::ReplayConformance => "pigloros.w8.replay-conformance.1.0.0",
        ClaimLayerV1::KnowledgeNonInterference => "pigloros.w8.knowledge-non-interference.1.0.0",
        ClaimLayerV1::GatewayClientConformance => "pigloros.w8.gateway-client-conformance.1.0.0",
        ClaimLayerV1::PluginConformance => "pigloros.w8.plugin-conformance.1.0.0",
        ClaimLayerV1::MetricConformance => "pigloros.w8.metric-conformance.1.0.0",
        ClaimLayerV1::EmpiricalEvaluation => "pigloros.w8.empirical-evaluation.1.0.0",
    }
}

const fn claim_layer_name(claim_layer: ClaimLayerV1) -> &'static str {
    match claim_layer {
        ClaimLayerV1::ArtifactIntegrity => "artifact-integrity",
        ClaimLayerV1::ReplayConformance => "replay-conformance",
        ClaimLayerV1::KnowledgeNonInterference => "knowledge-non-interference",
        ClaimLayerV1::GatewayClientConformance => "gateway-client-conformance",
        ClaimLayerV1::PluginConformance => "plugin-conformance",
        ClaimLayerV1::MetricConformance => "metric-conformance",
        ClaimLayerV1::EmpiricalEvaluation => "empirical-evaluation",
    }
}

fn fixture(
    record: &JsonValue,
    context: &FixtureContext,
) -> Result<FixtureDescriptorV1, Box<dyn Error>> {
    let case_id = json_text(record, "case_id")?;
    let family = json_text(record, "family")?;
    let input_path = json_text(record, "input")?;
    let expected_path = json_text(record, "expected")?;
    if family_for_path(input_path, expected_path) != Some(family) {
        return Err("canonical fixture family is not bound to its paths".into());
    }
    let (input, expected) = canonical_fixture_bytes(input_path, expected_path)?;
    let fixture_record_digest = labeled_digest(
        "PiglorOS.CPF1FixtureRecord.v1",
        &serde_json::to_vec(record)?,
    );
    Ok(FixtureDescriptorV1 {
        case_id: case_id.to_owned(),
        mandatory: true,
        claim_layer: context.claim_layer,
        execution_profile_digest: context.execution_profile_digest,
        public_schema_digest: context.schema_digest,
        modes: vec![
            pos_conformance::ExecutionModeV1::Local,
            pos_conformance::ExecutionModeV1::AirGapped,
        ],
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        inputs: vec![FixtureInputMemberV1 {
            member_id: input_path.to_owned(),
            size_bytes: input.len() as u64,
            digest: *blake3::hash(input).as_bytes(),
            provenance_digest: context.provenance_digest,
        }],
        expected: ExpectedResultV1::CanonicalBytes {
            bytes: expected.to_vec(),
            digest: *blake3::hash(expected).as_bytes(),
        },
        expected_verification_outcome: VerificationOutcomeV1::VerifiedExact,
        expected_verification_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
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
            source_digest: context.provenance_digest,
            build_digest: context.provenance_digest,
            publication_review_digest: context.provenance_digest,
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

fn family_for_path(input_path: &str, expected_path: &str) -> Option<&'static str> {
    match (input_path, expected_path) {
        ("inputs/artifact-positive.json", "expected/artifact-positive.json") => Some("positive"),
        ("inputs/replay-negative.json", "expected/replay-negative.json") => Some("negative"),
        ("inputs/knowledge-malformed.json", "expected/knowledge-malformed.json") => {
            Some("malformed")
        }
        ("inputs/gateway-resource-limit.json", "expected/gateway-resource-limit.json") => {
            Some("resource")
        }
        ("inputs/plugin-deletion.json", "expected/plugin-deletion.json") => Some("deletion"),
        ("inputs/metric-downgrade.json", "expected/metric-downgrade.json") => Some("downgrade"),
        ("inputs/empirical-independent.json", "expected/empirical-independent.json") => {
            Some("independent-evaluation")
        }
        _ => None,
    }
}

fn canonical_fixture_bytes(
    input_path: &str,
    expected_path: &str,
) -> Result<CanonicalFixtureBytes, Box<dyn Error>> {
    let bytes = match (input_path, expected_path) {
        ("inputs/artifact-positive.json", "expected/artifact-positive.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/artifact-positive.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/artifact-positive.json")
                .as_slice(),
        ),
        ("inputs/replay-negative.json", "expected/replay-negative.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/replay-negative.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/replay-negative.json")
                .as_slice(),
        ),
        ("inputs/knowledge-malformed.json", "expected/knowledge-malformed.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/knowledge-malformed.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/knowledge-malformed.json")
                .as_slice(),
        ),
        ("inputs/gateway-resource-limit.json", "expected/gateway-resource-limit.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/gateway-resource-limit.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/gateway-resource-limit.json")
                .as_slice(),
        ),
        ("inputs/plugin-deletion.json", "expected/plugin-deletion.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/plugin-deletion.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/plugin-deletion.json")
                .as_slice(),
        ),
        ("inputs/metric-downgrade.json", "expected/metric-downgrade.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/metric-downgrade.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/metric-downgrade.json")
                .as_slice(),
        ),
        ("inputs/empirical-independent.json", "expected/empirical-independent.json") => (
            include_bytes!("../../../../fixtures/conformance/inputs/empirical-independent.json")
                .as_slice(),
            include_bytes!("../../../../fixtures/conformance/expected/empirical-independent.json")
                .as_slice(),
        ),
        _ => return Err("canonical fixture paths are unknown".into()),
    };
    Ok(bytes)
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
    bundle_inputs_with_authority(
        profile,
        mode,
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json"),
        None,
    )
}

fn bundle_inputs_with_authority(
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
    inventory_bytes: &[u8],
    authority_root: Option<&Path>,
) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn Error>> {
    let execution_mode = match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
    };
    let mut members = Vec::new();
    let mut expected_results = Vec::new();
    for fixture in &profile.fixtures {
        for member in &fixture.inputs {
            let input = canonical_fixture_input(&fixture.case_id, &member.member_id)?;
            members.push(BundleMemberV1::new(
                fixture_input_path(
                    &fixture.case_id,
                    fixture.claim_layer,
                    &fixture.execution_profile_digest,
                    &member.member_id,
                ),
                input.to_vec(),
                false,
            ));
        }
        let ExpectedResultV1::CanonicalBytes { bytes, .. } = &fixture.expected else {
            return Err("materializer requires canonical public expected bytes".into());
        };
        let path = expected_member_path(
            &fixture.case_id,
            fixture.claim_layer,
            &fixture.execution_profile_digest,
        );
        let member = BundleMemberV1::new(path.clone(), bytes.clone(), true);
        expected_results.push(BundleExpectedResultV1 {
            case_id: fixture.case_id.clone(),
            claim_layer: fixture.claim_layer,
            execution_profile_digest: fixture.execution_profile_digest,
            mode,
            member_path: path,
            digest: member.digest,
        });
        if !fixture.modes.contains(&execution_mode) {
            return Err("fixture does not support selected materialization mode".into());
        }
        members.push(member);
    }
    append_supporting_members_with_authority(&mut members, inventory_bytes, authority_root)?;
    Ok((members, expected_results))
}

fn append_supporting_members_with_authority(
    members: &mut Vec<BundleMemberV1>,
    inventory_bytes: &[u8],
    authority_root: Option<&Path>,
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
        "authority/expected-authority-inventory.json",
        inventory_bytes.to_vec(),
        false,
    );
    inventory.role = BundleMemberRoleV1::AuthorityInventory;
    members.push(inventory);
    let mut matrix = BundleMemberV1::new(
        "authority/adr-059-execution-matrix.json",
        include_bytes!("../../../../fixtures/conformance/matrix/adr-059-complete.json").to_vec(),
        false,
    );
    matrix.role = BundleMemberRoleV1::ExecutionMatrix;
    members.push(matrix);
    let inventory_json: JsonValue = serde_json::from_slice(inventory_bytes)?;
    if json_text(&inventory_json, "lifecycle")? == "Candidate" {
        let authority_root = authority_root
            .ok_or("Candidate materialization requires PIGLOROS_CONFORMANCE_AUTHORITY_ROOT")?;
        append_authority_artifacts(members, &inventory_json, authority_root)?;
    }
    Ok(())
}

fn append_authority_artifacts(
    members: &mut Vec<BundleMemberV1>,
    inventory: &JsonValue,
    authority_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let entries = inventory
        .get("entries")
        .and_then(JsonValue::as_array)
        .ok_or("Candidate authority inventory entries are missing")?;
    for entry in entries {
        append_authority_artifact(
            members,
            entry,
            "fixture_bytes_path",
            "fixture_bytes_digest",
            BundleMemberRoleV1::AuthorityFixture,
            authority_root,
        )?;
        append_authority_artifact(
            members,
            entry,
            "expected_result_path",
            "expected_result_digest",
            BundleMemberRoleV1::AuthorityExpectedResult,
            authority_root,
        )?;
    }
    Ok(())
}

fn append_authority_artifact(
    members: &mut Vec<BundleMemberV1>,
    entry: &JsonValue,
    path_field: &str,
    digest_field: &str,
    role: BundleMemberRoleV1,
    authority_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let source_path = json_text(entry, path_field)?;
    let relative_path = safe_authority_relative_path(source_path)?;
    let bytes = std::fs::read(authority_root.join(relative_path))?;
    let artifact_fixture_id = serde_json::from_slice::<JsonValue>(&bytes)
        .ok()
        .and_then(|value| {
            value
                .get("fixture_id")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        });
    if bytes.is_empty()
        || decode_hex(json_text(entry, digest_field)?) != Some(*blake3::hash(&bytes).as_bytes())
        || artifact_fixture_id.as_deref() != entry.get("fixture_id").and_then(JsonValue::as_str)
    {
        return Err("Candidate authority artifact does not match inventory".into());
    }
    let mut member = BundleMemberV1::new(format!("authority/{source_path}"), bytes, false);
    member.role = role;
    members.push(member);
    Ok(())
}

fn safe_authority_relative_path(path: &str) -> Result<&Path, Box<dyn Error>> {
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err("authority inventory path escapes its configured root".into())
    } else {
        Ok(relative)
    }
}

fn fixture_input_path(
    case_id: &str,
    claim_layer: ClaimLayerV1,
    execution_profile_digest: &[u8; 32],
    member_id: &str,
) -> String {
    let mut input = b"PiglorOS.CPF1InputPath.v1\0".to_vec();
    append_path_component(&mut input, case_id);
    input.push(claim_layer_code(claim_layer));
    input.extend_from_slice(execution_profile_digest);
    append_path_component(&mut input, member_id);
    format!("inputs/{}.bin", blake3::hash(&input).to_hex())
}

fn expected_member_path(
    case_id: &str,
    claim_layer: ClaimLayerV1,
    execution_profile_digest: &[u8; 32],
) -> String {
    let mut input = b"PiglorOS.CPF1ExpectedPath.v1\0".to_vec();
    append_path_component(&mut input, case_id);
    input.push(claim_layer_code(claim_layer));
    input.extend_from_slice(execution_profile_digest);
    format!("expected/{}.bin", blake3::hash(&input).to_hex())
}

fn append_path_component(input: &mut Vec<u8>, value: &str) {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
}

const fn claim_layer_code(claim_layer: ClaimLayerV1) -> u8 {
    match claim_layer {
        ClaimLayerV1::ArtifactIntegrity => 0,
        ClaimLayerV1::ReplayConformance => 1,
        ClaimLayerV1::KnowledgeNonInterference => 2,
        ClaimLayerV1::GatewayClientConformance => 3,
        ClaimLayerV1::PluginConformance => 4,
        ClaimLayerV1::MetricConformance => 5,
        ClaimLayerV1::EmpiricalEvaluation => 6,
    }
}

fn canonical_fixture_input(
    case_id: &str,
    member_id: &str,
) -> Result<&'static [u8], Box<dyn Error>> {
    let expected_path = match case_id {
        "artifact-positive" => "expected/artifact-positive.json",
        "replay-negative" => "expected/replay-negative.json",
        "knowledge-malformed" => "expected/knowledge-malformed.json",
        "gateway-resource-limit" => "expected/gateway-resource-limit.json",
        "plugin-deletion" => "expected/plugin-deletion.json",
        "metric-downgrade" => "expected/metric-downgrade.json",
        "empirical-independent" => "expected/empirical-independent.json",
        _ => return Err("fixture case is not a canonical profile family".into()),
    };
    let (input, _) = canonical_fixture_bytes(member_id, expected_path)?;
    Ok(input)
}

fn verify_public_archive(
    bundle_bytes: &[u8],
    expected_digest: &[u8; 32],
    expected_manifest: &[u8],
) -> Result<(), Box<dyn Error>> {
    let decoded = ConformanceBundleV1::from_canonical_cbor(bundle_bytes)?;
    if decoded.to_canonical_cbor()? != bundle_bytes
        || decoded.manifest_bytes()? != expected_manifest
        || decoded.bundle_digest()? != *expected_digest
    {
        return Err("public archive verification did not reproduce canonical bytes".into());
    }
    decoded.validate()?;
    Ok(())
}

fn write_materialized_file(
    root: &Path,
    relative: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    value
}

#[cfg(test)]
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
        assert_eq!(decode_hex("00"), None);
        assert_eq!(decode_hex(&"gg".repeat(32)), None);
        assert_eq!(decode_hex(&"0g".repeat(32)), None);
        assert_eq!(decode_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(decode_hex(&"AB".repeat(32)), Some([0xab; 32]));
        assert_eq!(hex(&[0xabu8; 32]), "ab".repeat(32));

        let candidate = br#"{"lifecycle":"Candidate"}"#;
        let lifecycles = publication_lifecycles_from_bytes(candidate);
        assert_eq!(
            lifecycles.as_ref().ok(),
            Some(&vec![
                (ProfileLifecycleV1::Draft, "draft"),
                (ProfileLifecycleV1::Candidate, "candidate")
            ])
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

        let mut invalid_expected = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        invalid_expected.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding);
        assert!(bundle_inputs(&invalid_expected, BundleModeV1::Local).is_err());
        let output = output_root("invalid-expected");
        assert!(materialize_profile_from_profile(
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
        assert!(materialize_profile_from_profile(
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
        assert!(materialize_profile_from_profile(
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

    #[test]
    fn canonical_records_bind_fixture_families_and_candidate_authority(
    ) -> Result<(), Box<dyn Error>> {
        for (_, claim_layer) in PROFILE_RECORDS {
            let profile = test_profile(claim_layer)?;
            assert_eq!(profile.fixtures.len(), 7);
            assert!(profile.fixtures.iter().all(|fixture| {
                fixture
                    .inputs
                    .first()
                    .is_some_and(|input| input.member_id.starts_with("inputs/"))
            }));
        }

        let mut inventory: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        inventory["lifecycle"] = JsonValue::String("Candidate".to_owned());
        let entries = inventory
            .get_mut("entries")
            .and_then(JsonValue::as_array_mut)
            .ok_or("candidate inventory entries are missing")?;
        let root = output_root("candidate-authority");
        for entry in entries {
            let fixture_id = entry
                .get("fixture_id")
                .and_then(JsonValue::as_str)
                .ok_or("candidate fixture id is missing")?
                .to_owned();
            let fixture_path = format!("fixtures/{fixture_id}.json");
            let result_path = format!("results/{fixture_id}.json");
            let fixture_bytes = serde_json::to_vec(&serde_json::json!({
                "fixture_id": fixture_id,
                "kind": "fixture"
            }))?;
            let result_bytes = serde_json::to_vec(&serde_json::json!({
                "fixture_id": fixture_id,
                "kind": "result"
            }))?;
            for (path, bytes, path_field, digest_field) in [
                (
                    fixture_path.as_str(),
                    fixture_bytes.as_slice(),
                    "fixture_bytes_path",
                    "fixture_bytes_digest",
                ),
                (
                    result_path.as_str(),
                    result_bytes.as_slice(),
                    "expected_result_path",
                    "expected_result_digest",
                ),
            ] {
                let path = root.join(path);
                assert!(
                    std::fs::create_dir_all(path.parent().ok_or("authority parent missing")?)
                        .is_ok()
                );
                assert!(std::fs::write(&path, bytes).is_ok());
                entry[path_field] =
                    JsonValue::String(path.strip_prefix(&root)?.display().to_string());
                entry[digest_field] = JsonValue::String(hex(blake3::hash(bytes).as_bytes()));
            }
            entry["materialization_status"] = JsonValue::String("materialized".to_owned());
        }
        let inventory_bytes = serde_json::to_vec(&inventory)?;
        let profile = test_profile(ClaimLayerV1::ArtifactIntegrity)?;
        assert!(bundle_inputs_with_authority(
            &profile,
            BundleModeV1::Local,
            &inventory_bytes,
            None,
        )
        .is_err());
        let (members, _) = bundle_inputs_with_authority(
            &profile,
            BundleModeV1::Local,
            &inventory_bytes,
            Some(&root),
        )?;
        assert_eq!(
            members
                .iter()
                .filter(|member| member.role == BundleMemberRoleV1::AuthorityFixture)
                .count(),
            11
        );
        assert_eq!(
            members
                .iter()
                .filter(|member| member.role == BundleMemberRoleV1::AuthorityExpectedResult)
                .count(),
            11
        );
        assert!(safe_authority_relative_path("../escape.json").is_err());
        assert!(std::fs::remove_dir_all(root).is_ok());
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
        assert!(std::fs::create_dir_all(
            manifest_root.join(format!("{prefix}/manifest-local-{}.cbor", hex(&digest))),
        )
        .is_ok());
        assert!(materialize_profile_from_profile(
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
            bundle_root.join(format!("{prefix}/manifest-local-{}.cbor", hex(&digest))),
            b"existing",
        )
        .is_ok());
        assert!(std::fs::create_dir_all(
            bundle_root.join(format!("{prefix}/bundle-local-{}.cfb1", hex(&digest))),
        )
        .is_ok());
        assert!(materialize_profile_from_profile(
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
}
