use ed25519_dalek::SigningKey;
use pos_conformance::{
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, ClaimLayerV1,
    ConformanceBundleV1, ConformanceProfileV1, EvaluatorHardCapsV1, EvaluatorProtocolV1,
    ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1, FixtureInputMemberV1,
    FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1, RedactionStateV1,
    ReplayClaimV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
use serde_json::Value as JsonValue;
use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const INPUTS: [&[u8]; 7] = [
    include_bytes!("../../../../fixtures/conformance/inputs/artifact-positive.json"),
    include_bytes!("../../../../fixtures/conformance/inputs/replay-negative.json"),
    include_bytes!("../../../../fixtures/conformance/inputs/knowledge-malformed.json"),
    include_bytes!("../../../../fixtures/conformance/inputs/gateway-resource-limit.json"),
    include_bytes!("../../../../fixtures/conformance/inputs/plugin-deletion.json"),
    include_bytes!("../../../../fixtures/conformance/inputs/metric-downgrade.json"),
    include_bytes!("../../../../fixtures/conformance/inputs/empirical-independent.json"),
];
const EXPECTED: [&[u8]; 7] = [
    include_bytes!("../../../../fixtures/conformance/expected/artifact-positive.json"),
    include_bytes!("../../../../fixtures/conformance/expected/replay-negative.json"),
    include_bytes!("../../../../fixtures/conformance/expected/knowledge-malformed.json"),
    include_bytes!("../../../../fixtures/conformance/expected/gateway-resource-limit.json"),
    include_bytes!("../../../../fixtures/conformance/expected/plugin-deletion.json"),
    include_bytes!("../../../../fixtures/conformance/expected/metric-downgrade.json"),
    include_bytes!("../../../../fixtures/conformance/expected/empirical-independent.json"),
];

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
            materialize_profile(
                &output_root,
                &signing_key,
                claim_layer,
                layer_name,
                *lifecycle,
                lifecycle_name,
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

fn materialize_profile(
    output_root: &Path,
    signing_key: &SigningKey,
    claim_layer: ClaimLayerV1,
    layer_name: &str,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
) -> Result<(), Box<dyn Error>> {
    let profile = profile_for_claim_layer(claim_layer);
    materialize_profile_from_profile(
        output_root,
        signing_key,
        profile,
        lifecycle,
        lifecycle_name,
        layer_name,
    )
}

fn materialize_profile_from_profile(
    output_root: &Path,
    signing_key: &SigningKey,
    mut profile: ConformanceProfileV1,
    lifecycle: ProfileLifecycleV1,
    lifecycle_name: &str,
    layer_name: &str,
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
        let (members, expected_results) = bundle_inputs(&profile, mode)?;
        let bundle = ConformanceBundleV1::materialize(&profile, mode, members, expected_results)?
            .sign(signing_key)?;
        let bundle_digest = bundle.bundle_digest()?;
        write_materialized_file(
            output_root,
            format!("{prefix}/manifest-{mode_name}-{}.cbor", hex(&bundle_digest)),
            &bundle.manifest_bytes()?,
        )?;
        write_materialized_file(
            output_root,
            format!("{prefix}/bundle-{mode_name}-{}.cfb1", hex(&bundle_digest)),
            &bundle.to_canonical_cbor()?,
        )?;
    }
    Ok(())
}

fn profile_for_claim_layer(claim_layer: ClaimLayerV1) -> ConformanceProfileV1 {
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
    let fixtures = (0..7)
        .map(|index| {
            fixture(
                index,
                claim_layer,
                schema_digest,
                provenance_digest,
                notice_digest,
                sbom_digest,
                limitations_digest,
            )
        })
        .collect::<Vec<_>>();
    let mut profile = ConformanceProfileV1 {
        profile_id: profile_id(claim_layer).to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: *blake3::hash(normative).as_bytes(),
        execution_profile_digests: vec![digest(1)],
        public_schema_digests: vec![schema_digest],
        fixtures,
        allowed_divergences: Vec::new(),
        evaluator_protocol: evaluator_protocol(),
        independence_requirements: IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: digest(16),
            requirements_digest: digest(17),
        },
        compatibility_digest: digest(18),
        limitations_digest,
        provenance_digest,
        previous_profile_digest: None,
        stable_evidence: Vec::new(),
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    profile
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

fn fixture(
    index: usize,
    claim_layer: ClaimLayerV1,
    schema_digest: [u8; 32],
    provenance_digest: [u8; 32],
    notice_digest: [u8; 32],
    sbom_digest: [u8; 32],
    limitations_digest: [u8; 32],
) -> FixtureDescriptorV1 {
    let input = INPUTS[index];
    let expected = EXPECTED[index];
    FixtureDescriptorV1 {
        case_id: format!("case-{index:02}"),
        mandatory: true,
        claim_layer,
        execution_profile_digest: digest(1),
        public_schema_digest: schema_digest,
        modes: vec![
            pos_conformance::ExecutionModeV1::Local,
            pos_conformance::ExecutionModeV1::AirGapped,
        ],
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        inputs: vec![FixtureInputMemberV1 {
            member_id: format!("input-{index:02}.json"),
            size_bytes: input.len() as u64,
            digest: *blake3::hash(input).as_bytes(),
            provenance_digest,
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
            notices_digest: notice_digest,
            sbom_digest,
            source_digest: provenance_digest,
            build_digest: provenance_digest,
            publication_review_digest: provenance_digest,
            limitations_digest,
        },
        compatibility_digest: digest(11),
    }
}

fn evaluator_protocol() -> EvaluatorProtocolV1 {
    EvaluatorProtocolV1 {
        protocol_id: "pigloros.evaluator.v1".to_owned(),
        protocol_digest: digest(13),
        request_schema_digest: digest(14),
        report_schema_digest: digest(15),
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

fn bundle_inputs(
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn Error>> {
    let execution_mode = match mode {
        BundleModeV1::Local => pos_conformance::ExecutionModeV1::Local,
        BundleModeV1::AirGapped => pos_conformance::ExecutionModeV1::AirGapped,
    };
    let mut members = Vec::new();
    let mut expected_results = Vec::new();
    for (index, fixture) in profile.fixtures.iter().enumerate() {
        let input = INPUTS[index];
        for member in &fixture.inputs {
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
    append_supporting_members(&mut members);
    Ok((members, expected_results))
}

fn append_supporting_members(members: &mut Vec<BundleMemberV1>) {
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
        include_bytes!("../../../../fixtures/conformance/expected-authority/inventory.json")
            .to_vec(),
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

const fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
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
    use pos_conformance::SafeErrorCodeV1;

    fn signing_key_hex() -> String {
        "07".repeat(32)
    }

    fn output_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pigloros-conformance-{name}-{}",
            std::process::id()
        ))
    }

    fn local_bundle_digest(
        profile: &ConformanceProfileV1,
        signing_key: &SigningKey,
    ) -> Result<[u8; 32], Box<dyn Error>> {
        let (members, expected_results) = bundle_inputs(profile, BundleModeV1::Local)?;
        Ok(ConformanceBundleV1::materialize(
            profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?
        .sign(signing_key)?
        .bundle_digest()?)
    }

    #[test]
    fn materializer_run_covers_all_profile_layers() -> Result<(), Box<dyn Error>> {
        let output = output_root("run");
        let arguments = [
            OsString::from("materialize"),
            output.clone().into_os_string(),
        ];
        run(arguments.into_iter(), Ok(signing_key_hex()))?;
        assert!(output.join("artifact-integrity/draft").is_dir());
        assert!(output.join("empirical-evaluation/draft").is_dir());
        std::fs::remove_dir_all(output)?;
        Ok(())
    }

    #[test]
    fn materializer_argument_and_key_errors_are_explicit() -> Result<(), Box<dyn Error>> {
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
        std::fs::create_dir_all(&output)?;
        let arguments = [
            OsString::from("materialize"),
            output.clone().into_os_string(),
        ];
        assert!(run(arguments.into_iter(), Ok(signing_key_hex())).is_err());
        std::fs::remove_dir_all(output)?;
        let arguments = [OsString::from("materialize"), OsString::from("missing")];
        assert!(run(
            arguments.into_iter(),
            std::env::var("PIGLOROS_CONFORMANCE_MISSING_SIGNING_KEY")
        )
        .is_err());
        let blocker = output_root("blocker");
        std::fs::write(&blocker, b"not a directory")?;
        let child = blocker.join("child");
        let arguments = [OsString::from("materialize"), child.into_os_string()];
        assert!(run(arguments.into_iter(), Ok(signing_key_hex())).is_err());
        std::fs::remove_file(blocker)?;
        assert!(signing_key_from_encoded(std::env::var(
            "PIGLOROS_CONFORMANCE_MISSING_SIGNING_KEY"
        ))
        .is_err());
        assert!(signing_key_from_encoded(Ok("not-a-key".to_owned())).is_err());
        Ok(())
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
        assert_eq!(
            publication_lifecycles_from_bytes(candidate)?,
            vec![
                (ProfileLifecycleV1::Draft, "draft"),
                (ProfileLifecycleV1::Candidate, "candidate")
            ]
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

        let mut invalid_expected = profile_for_claim_layer(ClaimLayerV1::ArtifactIntegrity);
        invalid_expected.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding);
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
        if output.exists() {
            std::fs::remove_dir_all(output)?;
        }

        let mut invalid_profile = profile_for_claim_layer(ClaimLayerV1::ArtifactIntegrity);
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
        if output.exists() {
            std::fs::remove_dir_all(output)?;
        }

        let mut unsupported_mode = profile_for_claim_layer(ClaimLayerV1::ArtifactIntegrity);
        unsupported_mode.fixtures[0].modes.clear();
        assert!(bundle_inputs(&unsupported_mode, BundleModeV1::Local).is_err());

        let output = output_root("write-error");
        std::fs::create_dir_all(output.join("directory"))?;
        assert!(write_materialized_file(&output, "directory", b"bytes").is_err());
        std::fs::remove_dir_all(output)?;
        Ok(())
    }

    #[test]
    fn materializer_manifest_and_bundle_write_errors_are_explicit() -> Result<(), Box<dyn Error>> {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let profile = profile_for_claim_layer(ClaimLayerV1::ArtifactIntegrity);
        let digest = local_bundle_digest(&profile, &signing_key)?;
        let prefix = "artifact-integrity/draft";

        let manifest_root = output_root("manifest-error");
        std::fs::create_dir_all(manifest_root.join(prefix))?;
        std::fs::create_dir_all(
            manifest_root.join(format!("{prefix}/manifest-local-{}.cbor", hex(&digest))),
        )?;
        assert!(materialize_profile_from_profile(
            &manifest_root,
            &signing_key,
            profile,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        std::fs::remove_dir_all(manifest_root)?;

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let profile = profile_for_claim_layer(ClaimLayerV1::ArtifactIntegrity);
        let digest = local_bundle_digest(&profile, &signing_key)?;
        let bundle_root = output_root("bundle-error");
        std::fs::create_dir_all(bundle_root.join(prefix))?;
        std::fs::write(
            bundle_root.join(format!("{prefix}/manifest-local-{}.cbor", hex(&digest))),
            b"existing",
        )?;
        std::fs::create_dir_all(
            bundle_root.join(format!("{prefix}/bundle-local-{}.cfb1", hex(&digest))),
        )?;
        assert!(materialize_profile_from_profile(
            &bundle_root,
            &signing_key,
            profile,
            ProfileLifecycleV1::Draft,
            "draft",
            "artifact-integrity",
        )
        .is_err());
        std::fs::remove_dir_all(bundle_root)?;
        Ok(())
    }
}
