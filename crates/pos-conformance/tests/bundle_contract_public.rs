#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_conformance::{
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, CapabilityPolicyV1,
    ClaimLayerV1, ConformanceBundleV1, ConformanceProfileV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1,
    FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

const PROFILE_MEMBER_PATH: &str = "profile/CPF1.cbor";
const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/adr-059-execution-matrix.json";
const AUTHORITY_FIXTURE_IDS: [&str; 11] = [
    "RPL-001", "PRF-001", "PRF-002", "DIV-001", "INV-001", "INV-002", "INV-003", "RES-001",
    "LIVE-001", "ERA-001", "SEC-001",
];

#[cfg_attr(coverage_nightly, coverage(off))]
mod fixtures {
    use super::*;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn append_path_component(input: &mut Vec<u8>, value: &str) {
        input.extend_from_slice(&(value.len() as u64).to_be_bytes());
        input.extend_from_slice(value.as_bytes());
    }

    fn input_path(case_id: &str, profile_digest: &[u8; 32], member_id: &str) -> String {
        let mut input = Vec::new();
        input.extend_from_slice(b"PiglorOS.CPF1InputPath.v1\0");
        append_path_component(&mut input, case_id);
        input.push(0);
        input.extend_from_slice(profile_digest);
        append_path_component(&mut input, member_id);
        format!("inputs/{}.bin", blake3::hash(&input).to_hex())
    }

    fn expected_path(case_id: &str, profile_digest: &[u8; 32]) -> String {
        let mut input = Vec::new();
        input.extend_from_slice(b"PiglorOS.CPF1ExpectedPath.v1\0");
        append_path_component(&mut input, case_id);
        input.push(0);
        input.extend_from_slice(profile_digest);
        format!("expected/{}.bin", blake3::hash(&input).to_hex())
    }

    fn profile(provenance_digest: [u8; 32]) -> ConformanceProfileV1 {
        let input = b"public candidate input".to_vec();
        let expected = b"public candidate expected".to_vec();
        let schema_digest = digest(b"public schema");
        let fixture = FixtureDescriptorV1 {
            case_id: "ART-001".to_owned(),
            mandatory: true,
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            execution_profile_digest: [1; 32],
            public_schema_digest: schema_digest,
            modes: vec![pos_conformance::ExecutionModeV1::Local],
            subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
            inputs: vec![FixtureInputMemberV1 {
                member_id: "input.json".to_owned(),
                size_bytes: input.len() as u64,
                digest: digest(&input),
                provenance_digest,
            }],
            expected: ExpectedResultV1::CanonicalBytes {
                digest: digest(&expected),
                bytes: expected,
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
            capability_policy: CapabilityPolicyV1 {
                network_allowed: false,
                capability_ids: vec!["read-public-bundle".to_owned()],
            },
            provenance: FixtureProvenanceV1 {
                licence_id: "MIT".to_owned(),
                notices_digest: digest(include_bytes!(
                    "../../../fixtures/conformance/support/NOTICE"
                )),
                sbom_digest: digest(include_bytes!(
                    "../../../fixtures/conformance/support/sbom.json"
                )),
                source_digest: provenance_digest,
                build_digest: provenance_digest,
                publication_review_digest: provenance_digest,
                limitations_digest: digest(include_bytes!(
                    "../../../fixtures/conformance/support/limitations.md"
                )),
            },
            compatibility_digest: [11; 32],
        };
        let mut profile = ConformanceProfileV1 {
            profile_id: "pigloros.public-candidate-test".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Candidate,
            normative_spec_digest: digest(include_bytes!(
                "../../../fixtures/conformance/support/normative-requirements.md"
            )),
            execution_profile_digests: vec![[1; 32]],
            public_schema_digests: vec![schema_digest],
            fixtures: vec![fixture],
            allowed_divergences: Vec::new(),
            evaluator_protocol: EvaluatorProtocolV1 {
                protocol_id: "pigloros.evaluator.v1".to_owned(),
                protocol_digest: [13; 32],
                request_schema_digest: [14; 32],
                report_schema_digest: [15; 32],
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
            },
            independence_requirements: IndependenceRequirementsV1 {
                technical_independence_required: true,
                authorship_independence_required: true,
                organizational_independence_required: false,
                trust_policy_snapshot_digest: [16; 32],
                requirements_digest: [17; 32],
            },
            compatibility_digest: [18; 32],
            limitations_digest: digest(include_bytes!(
                "../../../fixtures/conformance/support/limitations.md"
            )),
            provenance_digest,
            previous_profile_digest: None,
            stable_evidence: Vec::new(),
            profile_digest: [0; 32],
        };
        profile.profile_digest = profile.digest();
        profile
    }

    fn authority_members() -> Result<Vec<BundleMemberV1>, Box<dyn std::error::Error>> {
        let mut inventory: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        inventory["lifecycle"] = JsonValue::String("Candidate".to_owned());
        let entries = inventory["entries"]
            .as_array_mut()
            .ok_or("missing entries")?;
        let mut members = Vec::with_capacity(entries.len() * 2);
        for (index, entry) in entries.iter_mut().enumerate() {
            let fixture_id = AUTHORITY_FIXTURE_IDS[index];
            let fixture_bytes = serde_json::to_vec(&serde_json::json!({"fixture_id": fixture_id}))?;
            let result_bytes = serde_json::to_vec(
                &serde_json::json!({"fixture_id": fixture_id, "expected": true}),
            )?;
            let fixture_digest = digest(&fixture_bytes);
            let result_digest = digest(&result_bytes);
            let fixture_path = format!("fixtures/{fixture_id}.json");
            let result_path = format!("results/{fixture_id}.json");
            entry["materialization_status"] = JsonValue::String("materialized".to_owned());
            entry["fixture_bytes_path"] = JsonValue::String(fixture_path.clone());
            entry["fixture_bytes_digest"] = JsonValue::String(hex(&fixture_digest));
            entry["expected_result_path"] = JsonValue::String(result_path.clone());
            entry["expected_result_digest"] = JsonValue::String(hex(&result_digest));
            members.push(BundleMemberV1::authority(
                format!("authority/{fixture_path}"),
                fixture_bytes,
                BundleMemberRoleV1::AuthorityFixture,
            ));
            members.push(BundleMemberV1::authority(
                format!("authority/{result_path}"),
                result_bytes,
                BundleMemberRoleV1::AuthorityExpectedResult,
            ));
        }
        let inventory_bytes = serde_json::to_vec(&inventory)?;
        members.push(BundleMemberV1::authority(
            AUTHORITY_INVENTORY_MEMBER_PATH,
            inventory_bytes,
            BundleMemberRoleV1::AuthorityInventory,
        ));
        Ok(members)
    }

    fn candidate_bundle() -> Result<
        Result<ConformanceBundleV1, pos_conformance::BundleContractErrorV1>,
        Box<dyn std::error::Error>,
    > {
        let mut provenance: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        let mut authority_members = authority_members()?;
        let mut matrix: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/matrix/adr-059-complete.json"
        ))?;
        matrix["lifecycle"] = JsonValue::String("Candidate".to_owned());
        for row in matrix["rows"].as_array_mut().ok_or("missing rows")? {
            row["executed_case_count"] = JsonValue::Number(16_u64.into());
        }
        let result_digest = authority_members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityExpectedResult)
            .ok_or("missing authority result")?
            .digest;
        for case in matrix["cases"].as_array_mut().ok_or("missing cases")? {
            case["executed"] = JsonValue::Bool(true);
            case["expected_result_digest"] = JsonValue::String(hex(&result_digest));
        }
        let matrix_bytes = serde_json::to_vec(&matrix)?;
        let matrix_digest = digest(&matrix_bytes);
        authority_members.push(BundleMemberV1::authority(
            EXECUTION_MATRIX_MEMBER_PATH,
            matrix_bytes,
            BundleMemberRoleV1::ExecutionMatrix,
        ));
        provenance["candidate_status"] = JsonValue::String("approved".to_owned());
        provenance["deletion_review"] = JsonValue::String("approved".to_owned());
        provenance["secret_scan"] = JsonValue::String("clean".to_owned());
        provenance["authority_inventory"]["status"] = JsonValue::String("Candidate".to_owned());
        provenance["authority_inventory"]["sha256_digest"] = JsonValue::String(
            Sha256::digest(
                &authority_members
                    .iter()
                    .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
                    .ok_or("missing inventory")?
                    .bytes,
            )
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        );
        provenance["adr_059_execution_matrix"]["status"] =
            JsonValue::String("Candidate".to_owned());
        provenance["adr_059_execution_matrix"]["sha256_digest"] =
            JsonValue::String(hex(&matrix_digest));
        provenance["adr_059_execution_matrix"]["executed_case_count"] =
            JsonValue::Number(192_u64.into());
        let provenance_bytes = serde_json::to_vec(&provenance)?;
        let provenance_digest = digest(&provenance_bytes);
        let profile = profile(provenance_digest);
        let input = b"public candidate input".to_vec();
        let expected = b"public candidate expected".to_vec();
        let input_path = input_path(
            "ART-001",
            &profile.execution_profile_digests[0],
            "input.json",
        );
        let expected_path = expected_path("ART-001", &profile.execution_profile_digests[0]);
        let mut members = vec![
            BundleMemberV1::new(input_path, input, false),
            BundleMemberV1::new(expected_path.clone(), expected.clone(), true),
            BundleMemberV1::supporting(
                "support/normative-requirements.md",
                include_bytes!("../../../fixtures/conformance/support/normative-requirements.md")
                    .to_vec(),
                BundleMemberRoleV1::NormativeSpecification,
            ),
            BundleMemberV1::supporting(
                "support/schema-cpf1-v1.cddl",
                include_bytes!("../../../fixtures/conformance/support/schema-cpf1-v1.cddl")
                    .to_vec(),
                BundleMemberRoleV1::Schema,
            ),
            BundleMemberV1::supporting(
                "support/LICENSE",
                include_bytes!("../../../fixtures/conformance/support/LICENSE").to_vec(),
                BundleMemberRoleV1::Licence,
            ),
            BundleMemberV1::supporting(
                "support/NOTICE",
                include_bytes!("../../../fixtures/conformance/support/NOTICE").to_vec(),
                BundleMemberRoleV1::Notice,
            ),
            BundleMemberV1::supporting(
                "support/sbom.json",
                include_bytes!("../../../fixtures/conformance/support/sbom.json").to_vec(),
                BundleMemberRoleV1::Sbom,
            ),
            BundleMemberV1::supporting(
                "support/provenance.json",
                provenance_bytes,
                BundleMemberRoleV1::Provenance,
            ),
            BundleMemberV1::supporting(
                "support/limitations.md",
                include_bytes!("../../../fixtures/conformance/support/limitations.md").to_vec(),
                BundleMemberRoleV1::Limitations,
            ),
        ];
        members.append(&mut authority_members);
        let expected_results = vec![BundleExpectedResultV1 {
            case_id: "ART-001".to_owned(),
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            execution_profile_digest: [1; 32],
            mode: BundleModeV1::Local,
            member_path: expected_path,
            digest: digest(&expected),
        }];
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?)
    }
}

#[test]
fn public_candidate_materialization_reaches_fail_closed_authority_gate(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixtures::candidate_bundle()?,
        Err(pos_conformance::BundleContractErrorV1::CandidateEvidenceMissing)
    );
    Ok(())
}
