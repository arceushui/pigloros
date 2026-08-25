#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    BundleExpectedResultV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, CapabilityPolicyV1,
    ClaimLayerV1, ConformanceBundleV1, ConformanceProfileV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1,
    FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, SubjectAdapterKindV1, VerificationOutcomeV1,
};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::io::Cursor;

const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/adr-059-execution-matrix.json";
const AUTHORITY_FIXTURE_IDS: [&str; 11] = [
    "RPL-001", "PRF-001", "PRF-002", "DIV-001", "INV-001", "INV-002", "INV-003", "RES-001",
    "LIVE-001", "ERA-001", "SEC-001",
];

fn top_fields(value: &mut Value) -> Result<&mut Vec<Value>, Box<dyn std::error::Error>> {
    match value {
        Value::Array(fields) if fields.len() == 6 => Ok(fields),
        _ => Err("archive value has an invalid shape".into()),
    }
}

fn archive_array(
    value: &mut Value,
    index: usize,
) -> Result<&mut Vec<Value>, Box<dyn std::error::Error>> {
    let fields = top_fields(value)?;
    match fields.get_mut(index) {
        Some(Value::Array(fields)) => Ok(fields),
        _ => Err("archive field is not an array".into()),
    }
}

fn archive_member<'a>(
    value: &'a mut Value,
    path: &str,
) -> Result<&'a mut Vec<Value>, Box<dyn std::error::Error>> {
    let members = archive_array(value, 3)?;
    let member = members
        .iter_mut()
        .find(|member| matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text(path.to_owned()))))
        .ok_or("archive member is missing")?;
    match member {
        Value::Array(fields) => Ok(fields),
        _ => Err("archive member is not an array".into()),
    }
}

fn archive_descriptor<'a>(
    value: &'a mut Value,
    path: &str,
) -> Result<&'a mut Vec<Value>, Box<dyn std::error::Error>> {
    let manifest = archive_array(value, 2)?;
    let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
        return Err("archive descriptors are missing".into());
    };
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text(path.to_owned()))))
        .ok_or("archive descriptor is missing")?;
    match descriptor {
        Value::Array(fields) => Ok(fields),
        _ => Err("archive descriptor is not an array".into()),
    }
}

fn archive_expected(value: &mut Value) -> Result<&mut Vec<Value>, Box<dyn std::error::Error>> {
    let manifest = archive_array(value, 2)?;
    let Some(Value::Array(expected)) = manifest.get_mut(5) else {
        return Err("archive expected results are missing".into());
    };
    match expected.first_mut() {
        Some(Value::Array(fields)) => Ok(fields),
        _ => Err("archive expected result is missing".into()),
    }
}

fn encode_archive(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn replace_first_byte(
    bytes: &mut Vec<u8>,
    needle: u8,
    replacement: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let position = bytes
        .iter()
        .position(|byte| *byte == needle)
        .ok_or("byte sequence is missing")?;
    bytes.splice(position..=position, replacement.iter().copied());
    Ok(())
}

fn signed_archive_variant(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(Cursor::new(bundle.to_canonical_cbor()?))?;
    mutate(&mut value)?;
    let fields = top_fields(&mut value)?;
    let manifest_bytes = encode_archive(&fields[2])?;
    fields[4] = Value::Bytes(signing_key.verifying_key().to_bytes().to_vec());
    fields[5] = Value::Bytes(signing_key.sign(&manifest_bytes).to_bytes().to_vec());
    encode_archive(&value)
}

fn post_signed_archive_variant(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let archive = signed_archive_variant(bundle, signing_key, |_| Ok(()))?;
    let mut value: Value = ciborium::from_reader(Cursor::new(archive))?;
    mutate(&mut value)?;
    encode_archive(&value)
}

fn mutate_profile(
    value: &mut Value,
    mutate: impl FnOnce(&mut Vec<Value>),
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_bytes = match archive_member(value, "profile/CPF1.cbor")?.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile bytes are missing".into()),
    };
    let mut profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
    let Value::Array(profile_fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    mutate(profile_fields);
    let profile_bytes = encode_archive(&profile)?;
    let digest = *blake3::hash(&profile_bytes).as_bytes();
    archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(profile_bytes.clone());
    let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
    descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
    descriptor[2] = Value::Bytes(digest.to_vec());
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub mod fixtures {
    use super::*;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
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

    fn fixture(
        provenance_digest: [u8; 32],
        input: &[u8],
        expected: Vec<u8>,
        schema_digest: [u8; 32],
    ) -> FixtureDescriptorV1 {
        FixtureDescriptorV1 {
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
                digest: digest(input),
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
        }
    }

    fn evaluator_protocol() -> EvaluatorProtocolV1 {
        EvaluatorProtocolV1 {
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
        }
    }

    fn profile(provenance_digest: [u8; 32]) -> ConformanceProfileV1 {
        let input = b"public candidate input";
        let expected = b"public candidate expected".to_vec();
        let schema_digest = digest(include_bytes!(
            "../../../fixtures/conformance/support/schema-cpf1-v1.cddl"
        ));
        let fixture = fixture(provenance_digest, input, expected, schema_digest);
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
            evaluator_protocol: evaluator_protocol(),
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

    fn candidate_authority_data(
    ) -> Result<(Vec<BundleMemberV1>, Vec<u8>), Box<dyn std::error::Error>> {
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
        let inventory = authority_members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory")?;
        let inventory_digest = Sha256::digest(&inventory.bytes);
        provenance["authority_inventory"]["sha256_digest"] =
            JsonValue::String(hex(&inventory_digest));
        provenance["adr_059_execution_matrix"]["status"] =
            JsonValue::String("Candidate".to_owned());
        provenance["adr_059_execution_matrix"]["sha256_digest"] =
            JsonValue::String(hex(&matrix_digest));
        provenance["adr_059_execution_matrix"]["executed_case_count"] =
            JsonValue::Number(192_u64.into());
        let provenance_bytes = serde_json::to_vec(&provenance)?;
        Ok((authority_members, provenance_bytes))
    }

    fn candidate_members(
        profile: &ConformanceProfileV1,
        provenance_bytes: Vec<u8>,
        mut authority_members: Vec<BundleMemberV1>,
    ) -> (Vec<BundleMemberV1>, BundleExpectedResultV1) {
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
        let expected_result = BundleExpectedResultV1 {
            case_id: "ART-001".to_owned(),
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            execution_profile_digest: [1; 32],
            mode: BundleModeV1::Local,
            member_path: expected_path,
            digest: digest(&expected),
        };
        (members, expected_result)
    }

    /// Construct the Candidate bundle used by the public materialization test.
    ///
    /// # Errors
    ///
    /// Returns an error if the checked-in fixture data cannot be decoded or
    /// serialized into the test bundle.
    pub fn candidate_bundle() -> Result<
        Result<ConformanceBundleV1, pos_conformance::BundleContractErrorV1>,
        Box<dyn std::error::Error>,
    > {
        let (authority_members, provenance_bytes) = candidate_authority_data()?;
        let profile = profile(digest(&provenance_bytes));
        let (members, expected_result) =
            candidate_members(&profile, provenance_bytes, authority_members);
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            vec![expected_result],
        ))
    }

    /// Construct a Candidate bundle whose publication-review digest is wrong.
    ///
    /// # Errors
    ///
    /// Returns an error if the checked-in authority fixture data cannot be
    /// decoded or serialized into the test bundle.
    pub fn candidate_bundle_with_review_mismatch() -> Result<
        Result<ConformanceBundleV1, pos_conformance::BundleContractErrorV1>,
        Box<dyn std::error::Error>,
    > {
        let (authority_members, provenance_bytes) = candidate_authority_data()?;
        let mut profile = profile(digest(&provenance_bytes));
        profile.fixtures[0].provenance.publication_review_digest =
            profile.fixtures[0].provenance.notices_digest;
        profile.profile_digest = profile.digest();
        let (mut members, expected_result) =
            candidate_members(&profile, provenance_bytes, authority_members);
        members.push(BundleMemberV1::supporting(
            "support/publication-review",
            include_bytes!("../../../fixtures/conformance/support/NOTICE").to_vec(),
            BundleMemberRoleV1::Provenance,
        ));
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            vec![expected_result],
        ))
    }

    /// Construct a Candidate bundle with an invalid provenance authority path.
    ///
    /// # Errors
    ///
    /// Returns an error if the checked-in authority fixture data cannot be
    /// decoded or serialized into the test bundle.
    pub fn candidate_bundle_with_invalid_provenance_binding() -> Result<
        Result<ConformanceBundleV1, pos_conformance::BundleContractErrorV1>,
        Box<dyn std::error::Error>,
    > {
        let (authority_members, provenance_bytes) = candidate_authority_data()?;
        let mut provenance: JsonValue = serde_json::from_slice(&provenance_bytes)?;
        provenance["authority_inventory"]["path"] = JsonValue::String("wrong.json".to_owned());
        let provenance_bytes = serde_json::to_vec(&provenance)?;
        let profile = profile(digest(&provenance_bytes));
        let (members, expected_result) =
            candidate_members(&profile, provenance_bytes, authority_members);
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            vec![expected_result],
        ))
    }

    /// Construct a Candidate bundle with a matrix coordinate outside the
    /// independently supplied authority-result set.
    ///
    /// # Errors
    ///
    /// Returns an error if the checked-in authority fixture data cannot be
    /// decoded or serialized into the test bundle.
    pub fn candidate_bundle_with_invalid_matrix_coordinate() -> Result<
        Result<ConformanceBundleV1, pos_conformance::BundleContractErrorV1>,
        Box<dyn std::error::Error>,
    > {
        let (mut authority_members, provenance_bytes) = candidate_authority_data()?;
        let matrix_index = authority_members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing execution matrix")?;
        let mut matrix: JsonValue = serde_json::from_slice(&authority_members[matrix_index].bytes)?;
        matrix["cases"][0]["expected_result_digest"] = JsonValue::String("00".repeat(32));
        let matrix_bytes = serde_json::to_vec(&matrix)?;
        authority_members[matrix_index]
            .bytes
            .clone_from(&matrix_bytes);
        authority_members[matrix_index].digest = digest(&matrix_bytes);

        let mut provenance: JsonValue = serde_json::from_slice(&provenance_bytes)?;
        provenance["adr_059_execution_matrix"]["sha256_digest"] =
            JsonValue::String(hex(&Sha256::digest(&matrix_bytes)));
        let provenance_bytes = serde_json::to_vec(&provenance)?;
        let profile = profile(digest(&provenance_bytes));
        let (members, expected_result) =
            candidate_members(&profile, provenance_bytes, authority_members);
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            vec![expected_result],
        ))
    }

    /// Construct a valid Draft bundle for public archive-path coverage.
    ///
    /// # Errors
    ///
    /// Returns an error if the checked-in fixture data cannot be transformed
    /// into the Draft authority shape.
    pub fn draft_bundle() -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        let (mut authority_members, mut provenance_bytes) = candidate_authority_data()?;
        authority_members.retain(|member| {
            !matches!(
                member.role,
                BundleMemberRoleV1::AuthorityFixture | BundleMemberRoleV1::AuthorityExpectedResult
            )
        });

        let inventory_index = authority_members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing authority inventory")?;
        let mut inventory: JsonValue =
            serde_json::from_slice(&authority_members[inventory_index].bytes)?;
        inventory["lifecycle"] = JsonValue::String("Draft".to_owned());
        for entry in inventory["entries"]
            .as_array_mut()
            .ok_or("missing inventory entries")?
        {
            entry["materialization_status"] = JsonValue::String("pending".to_owned());
            for field in [
                "fixture_bytes_path",
                "fixture_bytes_digest",
                "expected_result_path",
                "expected_result_digest",
            ] {
                entry[field] = JsonValue::Null;
            }
        }
        let inventory_bytes = serde_json::to_vec(&inventory)?;
        authority_members[inventory_index]
            .bytes
            .clone_from(&inventory_bytes);
        authority_members[inventory_index].digest = digest(&inventory_bytes);

        let matrix_index = authority_members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing execution matrix")?;
        let mut matrix: JsonValue = serde_json::from_slice(&authority_members[matrix_index].bytes)?;
        matrix["lifecycle"] = JsonValue::String("Draft".to_owned());
        for row in matrix["rows"].as_array_mut().ok_or("missing matrix rows")? {
            row["executed_case_count"] = JsonValue::Number(0_u64.into());
        }
        for case in matrix["cases"]
            .as_array_mut()
            .ok_or("missing matrix cases")?
        {
            case["executed"] = JsonValue::Bool(false);
            case["expected_result_digest"] = JsonValue::Null;
        }
        let matrix_bytes = serde_json::to_vec(&matrix)?;
        authority_members[matrix_index]
            .bytes
            .clone_from(&matrix_bytes);
        authority_members[matrix_index].digest = digest(&matrix_bytes);

        let mut provenance: JsonValue = serde_json::from_slice(&provenance_bytes)?;
        provenance["authority_inventory"]["status"] = JsonValue::String("Draft".to_owned());
        provenance["authority_inventory"]["sha256_digest"] =
            JsonValue::String(hex(&Sha256::digest(&inventory_bytes)));
        provenance["adr_059_execution_matrix"]["status"] = JsonValue::String("Draft".to_owned());
        provenance["adr_059_execution_matrix"]["sha256_digest"] =
            JsonValue::String(hex(&Sha256::digest(&matrix_bytes)));
        provenance["adr_059_execution_matrix"]["executed_case_count"] =
            JsonValue::Number(0_u64.into());
        provenance_bytes = serde_json::to_vec(&provenance)?;

        let mut profile = profile(digest(&provenance_bytes));
        profile.lifecycle = ProfileLifecycleV1::Draft;
        profile.profile_digest = profile.digest();
        let (members, expected_result) =
            candidate_members(&profile, provenance_bytes, authority_members);
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            vec![expected_result],
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

#[test]
fn public_draft_archive_round_trip_and_independent_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;
    let manifest = bundle.manifest_bytes()?;
    assert_eq!(manifest, bundle.manifest_bytes()?);
    assert!(bundle.bundle_digest()?.iter().any(|byte| *byte != 0));

    let archive = bundle.to_canonical_cbor()?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Ok(())
    );
    assert_eq!(ConformanceBundleV1::from_canonical_cbor(&archive)?, bundle);
    Ok(())
}

#[test]
fn public_bundle_rejection_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;

    let mut invalid_magic = bundle.clone();
    invalid_magic.manifest.magic = "invalid".to_owned();
    assert_eq!(
        invalid_magic.validate(),
        Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
    );

    let mut invalid_signature = bundle.clone();
    invalid_signature.signature = pos_core::Signature::from_bytes([1; 64]);
    assert_eq!(
        invalid_signature.validate(),
        Err(pos_conformance::BundleContractErrorV1::SignatureInvalid)
    );

    let mut missing_profile = bundle.clone();
    missing_profile
        .members
        .retain(|member| member.role != BundleMemberRoleV1::Profile);
    assert_eq!(
        missing_profile.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let archive = bundle.to_canonical_cbor()?;
    let mut trailing = archive;
    trailing.push(0);
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&trailing),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    assert_eq!(
        pos_conformance::verify_archive_independently(&trailing),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    Ok(())
}

fn assert_archive_rejected(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let archive = signed_archive_variant(bundle, signing_key, mutate)?;
    assert!(pos_conformance::verify_archive_independently(&archive).is_err());
    Ok(())
}

fn assert_post_signed_archive_rejected(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let archive = post_signed_archive_variant(bundle, signing_key, mutate)?;
    assert!(pos_conformance::verify_archive_independently(&archive).is_err());
    Ok(())
}

fn assert_archive_shape_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    for mutate in [
        Box::new(|value: &mut Value| {
            top_fields(value)?[0] = Value::Text("wrong".to_owned());
            Ok(())
        }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[1] = Value::Integer(2_u64.into());
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[2] = Value::Integer(2_u64.into());
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[4] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[5] = Value::Null;
            Ok(())
        }),
    ] {
        assert_archive_rejected(bundle, signing_key, mutate)?;
    }
    Ok(())
}

fn assert_archive_member_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_archive_rejected(bundle, signing_key, |value| {
        archive_member(value, "profile/CPF1.cbor")?[2] = Value::Integer(0_u64.into());
        archive_descriptor(value, "profile/CPF1.cbor")?[3] = Value::Integer(0_u64.into());
        Ok(())
    })?;
    assert_post_signed_archive_rejected(bundle, signing_key, |value| {
        top_fields(value)?[5] = Value::Bytes(vec![0]);
        Ok(())
    })?;
    assert_post_signed_archive_rejected(bundle, signing_key, |value| {
        top_fields(value)?[4] = Value::Bytes(vec![0xff; 32]);
        Ok(())
    })?;
    for mutate in [
        Box::new(|value: &mut Value| {
            archive_member(value, "profile/CPF1.cbor")?[1] = Value::Null;
            Ok(())
        }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
        Box::new(|value: &mut Value| {
            archive_member(value, "profile/CPF1.cbor")?[2] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[1] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[2] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[3] = Value::Null;
            Ok(())
        }),
    ] {
        assert_archive_rejected(bundle, signing_key, mutate)?;
    }
    Ok(())
}

fn assert_archive_expected_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_archive_rejected(bundle, signing_key, |value| {
        archive_expected(value)?[4] = Value::Null;
        Ok(())
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        archive_expected(value)?[5] = Value::Null;
        Ok(())
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        let expected_path = {
            let expected = archive_expected(value)?;
            let Value::Text(path) = &expected[4] else {
                return Err("expected path is not text".into());
            };
            path.clone()
        };
        archive_descriptor(value, &expected_path)?[3] = Value::Integer(0_u64.into());
        Ok(())
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        archive_expected(value)?[5] = Value::Bytes(vec![0; 32]);
        Ok(())
    })?;
    Ok(())
}

fn assert_archive_profile_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    for mutate in [
        Box::new(|value: &mut Value| {
            mutate_profile(value, |fields| fields[0] = Value::Text("wrong".to_owned()))
        }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
        Box::new(|value: &mut Value| {
            mutate_profile(value, |fields| fields[1] = Value::Integer(2_u64.into()))
        }),
        Box::new(|value: &mut Value| {
            mutate_profile(value, |fields| fields[4] = Value::Integer(1_u64.into()))
        }),
    ] {
        assert_archive_rejected(bundle, signing_key, mutate)?;
    }
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[16] = Value::Bytes(vec![7; 32]))?;
        archive_array(value, 2)?[3] = Value::Bytes(vec![7; 32]);
        Ok(())
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        let profile_member = archive_member(value, "profile/CPF1.cbor")?;
        let Some(Value::Bytes(profile_bytes)) = profile_member.get(1) else {
            return Err("profile bytes are missing".into());
        };
        let mut profile_bytes = profile_bytes.clone();
        replace_first_byte(&mut profile_bytes, 0x01, &[0x18, 0x01])?;
        profile_member[1] = Value::Bytes(profile_bytes.clone());
        let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
        descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
        Ok(())
    })?;
    Ok(())
}

#[test]
fn public_independent_archive_rejection_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;
    assert!(pos_conformance::verify_archive_independently(&[0x01, 0x00]).is_err());
    assert!(pos_conformance::verify_archive_independently(&[0x9a, 0, 1, 0, 1]).is_err());
    assert!(pos_conformance::verify_archive_independently(&[0x5a, 0x04, 0, 0, 1]).is_err());
    let mut deeply_nested = vec![0x81; 34];
    deeply_nested.push(0xf6);
    assert!(pos_conformance::verify_archive_independently(&deeply_nested).is_err());
    assert_archive_shape_rejections(&bundle, &signing_key)?;
    assert_archive_member_rejections(&bundle, &signing_key)?;
    assert_archive_expected_rejections(&bundle, &signing_key)?;
    assert_archive_profile_rejections(&bundle, &signing_key)?;

    let mut noncanonical_archive = signed_archive_variant(&bundle, &signing_key, |_| Ok(()))?;
    replace_first_byte(&mut noncanonical_archive, 0x01, &[0x18, 0x01])?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&noncanonical_archive),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );

    for (mutate, expected) in [
        (
            Box::new(|value: &mut Value| {
                mutate_profile(value, |fields| {
                    if let Some(Value::Array(protocol)) = fields.get_mut(10) {
                        if let Some(Value::Array(caps)) = protocol.get_mut(4) {
                            caps.pop();
                        }
                    }
                })
            }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
            pos_conformance::BundleContractErrorV1::ProfileInvalid,
        ),
        (
            Box::new(|value: &mut Value| {
                mutate_profile(value, |fields| {
                    if let Some(Value::Array(protocol)) = fields.get_mut(10) {
                        if let Some(Value::Array(caps)) = protocol.get_mut(4) {
                            caps[0] = Value::Integer(0_u64.into());
                        }
                    }
                })
            }),
            pos_conformance::BundleContractErrorV1::MemberOutOfBounds,
        ),
        (
            Box::new(|value: &mut Value| {
                mutate_profile(value, |fields| {
                    if let Some(Value::Array(protocol)) = fields.get_mut(10) {
                        if let Some(Value::Array(caps)) = protocol.get_mut(4) {
                            caps[5] = Value::Integer(1_u64.into());
                        }
                    }
                })
            }),
            pos_conformance::BundleContractErrorV1::MemberOutOfBounds,
        ),
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(expected)
        );
    }

    assert_eq!(
        fixtures::candidate_bundle_with_review_mismatch()?,
        Err(pos_conformance::BundleContractErrorV1::CandidateEvidenceMissing)
    );
    assert_eq!(
        fixtures::candidate_bundle_with_invalid_provenance_binding()?,
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    assert_eq!(
        fixtures::candidate_bundle_with_invalid_matrix_coordinate()?,
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}
