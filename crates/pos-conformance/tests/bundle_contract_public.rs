#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, AllowedDivergenceV1,
    BundleExpectedResultV1, BundleMemberDescriptorV1, BundleMemberRoleV1, BundleMemberV1,
    BundleModeV1, CapabilityPolicyV1, ClaimLayerV1, ConformanceBundlePairV1, ConformanceBundleV1,
    ConformanceProfileV1, DivergenceMismatchKindV1, EvaluatorHardCapsV1, EvaluatorProtocolV1,
    ExecutionModeV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1, FixtureInputMemberV1,
    FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1, RedactionStateV1,
    ReplayClaimV1, SafeErrorCodeV1, SubjectAdapterKindV1, VerificationOutcomeV1,
    MAX_CONFORMANCE_BUNDLE_BYTES_V1,
};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/execution-matrix.json";
static MATERIALIZER_PROCESS_LOCK: Mutex<()> = Mutex::new(());

#[cfg_attr(coverage_nightly, coverage(off))]
fn materializer_process_guard() -> MutexGuard<'static, ()> {
    match MATERIALIZER_PROCESS_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

type ArchiveMutation = Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>;
type JsonMutation = Box<dyn FnOnce(&mut JsonValue)>;
type ProfileValueMutation = Box<dyn FnOnce(&mut Vec<Value>)>;
type CapMutation = Box<dyn Fn(&mut EvaluatorHardCapsV1)>;
type PublicBundleInputs = (
    ConformanceProfileV1,
    Vec<BundleMemberV1>,
    Vec<BundleExpectedResultV1>,
);

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

fn replace_archive_descriptor_value(
    value: &mut Value,
    path: &str,
    replacement: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = archive_array(value, 2)?;
    let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
        return Err("archive descriptors are missing".into());
    };
    let index = descriptors
        .iter()
        .position(|descriptor| {
            matches!(
                descriptor,
                Value::Array(fields)
                    if fields.first() == Some(&Value::Text(path.to_owned()))
            )
        })
        .ok_or("archive descriptor is missing")?;
    descriptors[index] = replacement;
    Ok(())
}

fn replace_archive_expected_value(
    value: &mut Value,
    replacement: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = archive_array(value, 2)?;
    let Some(Value::Array(expected)) = manifest.get_mut(5) else {
        return Err("archive expected results are missing".into());
    };
    let Some(first) = expected.first_mut() else {
        return Err("archive expected result is missing".into());
    };
    *first = replacement;
    Ok(())
}

fn replace_profile_bytes(
    value: &mut Value,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(bytes.to_vec());
    Ok(())
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

fn archive_expected_results(
    value: &mut Value,
) -> Result<&mut Vec<Value>, Box<dyn std::error::Error>> {
    let manifest = archive_array(value, 2)?;
    match manifest.get_mut(5) {
        Some(Value::Array(results)) => Ok(results),
        _ => Err("archive expected results are missing".into()),
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

fn make_cfb1_version_noncanonical(bytes: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    const CANONICAL_HEADER: &[u8] = b"\x86\x64CFB1\x01";
    if !bytes.starts_with(CANONICAL_HEADER) {
        return Err("canonical CFB1 header is missing".into());
    }
    bytes.splice(
        CANONICAL_HEADER.len() - 1..CANONICAL_HEADER.len(),
        [0x18, 0x01],
    );
    Ok(())
}

fn cbor_length_header(major: u8, length: u32) -> Vec<u8> {
    let mut bytes = vec![(major << 5) | 0x1a];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes
}

fn assert_preflight_boundary(exact: &[u8], over: &[u8]) {
    assert_eq!(
        pos_conformance::verify_archive_independently(exact),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    assert_eq!(
        pos_conformance::verify_archive_independently(over),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );
}

fn signed_archive_variant(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(Cursor::new(canonical_archive_bytes(bundle)?))?;
    mutate(&mut value)?;
    let fields = top_fields(&mut value)?;
    let manifest_bytes = encode_archive(&fields[2])?;
    fields[4] = Value::Bytes(signing_key.verifying_key().to_bytes().to_vec());
    fields[5] = Value::Bytes(signing_key.sign(&manifest_bytes).to_bytes().to_vec());
    encode_archive(&value)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn canonical_archive_bytes(
    bundle: &ConformanceBundleV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    static DRAFT_ARCHIVE: OnceLock<Result<(ConformanceBundleV1, Vec<u8>), String>> =
        OnceLock::new();
    match DRAFT_ARCHIVE.get_or_init(|| {
        let draft = signed_draft_bundle().map_err(|error| error.to_string())?;
        let bytes = draft
            .to_canonical_cbor()
            .map_err(|error| error.to_string())?;
        Ok((draft, bytes))
    }) {
        Ok((draft, bytes)) if draft == bundle => Ok(bytes.clone()),
        Ok(_) => bundle.to_canonical_cbor().map_err(Into::into),
        Err(error) => Err(std::io::Error::other(error.clone()).into()),
    }
}

fn independently_signed_changed_bundle(
    original: &ConformanceBundleV1,
    changed: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(Cursor::new(original.to_canonical_cbor()?))?;
    for member in &changed.members {
        archive_member(&mut value, &member.path)?[1] = Value::Bytes(member.bytes.clone());
    }
    let manifest: Value = ciborium::from_reader(Cursor::new(changed.manifest_bytes()?))?;
    let fields = top_fields(&mut value)?;
    fields[2] = manifest;
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

fn test_domain_digest(
    domain: &[u8],
    value: &Value,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let encoded = encode_archive(value)?;
    let mut source = Vec::with_capacity(domain.len() + encoded.len() + 1);
    source.extend_from_slice(domain);
    source.push(0);
    source.extend_from_slice(&encoded);
    Ok(*blake3::hash(&source).as_bytes())
}

fn mutate_profile_and_rebind_identity(
    value: &mut Value,
    mutate: impl FnOnce(&mut Vec<Value>),
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_bytes = match archive_member(value, "profile/CPF1.cbor")?.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile bytes are missing".into()),
    };
    let mut profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
    let Value::Array(fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    mutate(fields);
    fields[17] = Value::Null;
    let stable_evidence = test_domain_digest(
        b"PiglorOS.ConformanceProfileStableEvidence.v1",
        &Value::Array(Vec::new()),
    )?;
    let profile_digest = test_domain_digest(
        b"PiglorOS.ConformanceProfile.v1",
        &Value::Array(vec![
            Value::Array(fields.clone()),
            Value::Bytes(stable_evidence.to_vec()),
        ]),
    )?;
    fields[17] = Value::Bytes(profile_digest.to_vec());
    let profile_bytes = encode_archive(&profile)?;
    let member_digest = *blake3::hash(&profile_bytes).as_bytes();
    archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(profile_bytes.clone());
    let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
    descriptor[1] = Value::Integer(u64::try_from(profile_bytes.len())?.into());
    descriptor[2] = Value::Bytes(member_digest.to_vec());
    archive_array(value, 2)?[3] = Value::Bytes(profile_digest.to_vec());
    Ok(())
}

fn mutate_profile_and_rebind_expected_member(
    value: &mut Value,
    mutate: impl FnOnce(&mut Vec<Value>),
) -> Result<(), Box<dyn std::error::Error>> {
    mutate_profile(value, mutate)?;
    let profile_bytes = match archive_member(value, "profile/CPF1.cbor")?.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile bytes are missing".into()),
    };
    let profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
    let Value::Array(profile_fields) = profile else {
        return Err("profile is not an array".into());
    };
    let Some(Value::Array(fixtures)) = profile_fields.get(9) else {
        return Err("profile fixtures are missing".into());
    };
    let Some(Value::Array(fixture)) = fixtures.first() else {
        return Err("profile fixture is missing".into());
    };
    let Some(Value::Array(expected)) = fixture.get(8) else {
        return Err("fixture expected result is missing".into());
    };
    let expected_bytes = if expected.first() == Some(&Value::Integer(0_u64.into())) {
        match expected.get(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("canonical expected bytes are missing".into()),
        }
    } else {
        encode_archive(&Value::Array(expected.clone()))?
    };
    let expected_path = match archive_expected(value)?.get(4) {
        Some(Value::Text(path)) => path.clone(),
        _ => return Err("expected-result path is missing".into()),
    };
    let expected_digest = blake3::hash(&expected_bytes);
    let expected_member = archive_member(value, &expected_path)?;
    expected_member[1] = Value::Bytes(expected_bytes.clone());
    let descriptor = archive_descriptor(value, &expected_path)?;
    descriptor[1] = Value::Integer(u64::try_from(expected_bytes.len())?.into());
    descriptor[2] = Value::Bytes(expected_digest.as_bytes().to_vec());
    archive_expected(value)?[5] = Value::Bytes(expected_digest.as_bytes().to_vec());
    Ok(())
}

fn mutate_first_profile_fixture(
    value: &mut Value,
    mutate: impl FnOnce(&mut Vec<Value>),
) -> Result<(), Box<dyn std::error::Error>> {
    mutate_profile(value, |fields| {
        if let Value::Array(fixtures) = &mut fields[9] {
            if let Value::Array(fixture) = &mut fixtures[0] {
                mutate(fixture);
            }
        }
    })
}

fn mutate_archive_matrix(
    value: &mut Value,
    mutate: impl FnOnce(&mut JsonValue),
) -> Result<(), Box<dyn std::error::Error>> {
    let matrix_digest = mutate_archive_json_member(value, EXECUTION_MATRIX_MEMBER_PATH, mutate)?;

    let profile_member = archive_member(value, "profile/CPF1.cbor")?;
    let profile_bytes = match profile_member.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile bytes are missing".into()),
    };
    let mut profile = ConformanceProfileV1::from_canonical_cbor(&profile_bytes)?;
    profile.execution_matrix_digest = matrix_digest;
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    profile_member[1] = Value::Bytes(profile_bytes.clone());
    let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
    descriptor[1] = Value::Integer(u64::try_from(profile_bytes.len())?.into());
    descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
    archive_array(value, 2)?[3] = Value::Bytes(profile.profile_digest.to_vec());
    Ok(())
}

fn mutate_archive_json_member(
    value: &mut Value,
    path: &str,
    mutate: impl FnOnce(&mut JsonValue),
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let member = archive_member(value, path)?;
    let matrix_bytes = match member.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("JSON authority bytes are missing".into()),
    };
    let mut matrix: JsonValue = serde_json::from_slice(&matrix_bytes)?;
    mutate(&mut matrix);
    let matrix_bytes = serde_json::to_vec(&matrix)?;
    let matrix_digest = *blake3::hash(&matrix_bytes).as_bytes();
    member[1] = Value::Bytes(matrix_bytes.clone());
    let descriptor = archive_descriptor(value, path)?;
    descriptor[1] = Value::Integer(u64::try_from(matrix_bytes.len())?.into());
    descriptor[2] = Value::Bytes(matrix_digest.to_vec());
    Ok(matrix_digest)
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub mod fixtures {
    use super::*;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn input_path(case_id: &str, profile_digest: &[u8; 32], member_id: &str) -> String {
        fixture_input_member_path(
            case_id,
            ClaimLayerV1::ArtifactIntegrity,
            profile_digest,
            member_id,
        )
    }

    fn expected_path(case_id: &str, profile_digest: &[u8; 32]) -> String {
        expected_result_member_path(case_id, ClaimLayerV1::ArtifactIntegrity, profile_digest)
    }

    fn draft_fixture_descriptor(
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
            modes: vec![
                pos_conformance::ExecutionModeV1::Local,
                pos_conformance::ExecutionModeV1::Fork,
            ],
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
        let input = b"public draft input";
        let expected = b"public draft expected".to_vec();
        let schema_digest = digest(include_bytes!(
            "../../../fixtures/conformance/support/schema-cpf1-v1.cddl"
        ));
        let fixture = draft_fixture_descriptor(provenance_digest, input, expected, schema_digest);
        let mut profile = ConformanceProfileV1 {
            profile_id: "pigloros.w8.knowledge-non-interference.1.0.0".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            normative_spec_digest: digest(include_bytes!(
                "../../../fixtures/conformance/support/normative-requirements.md"
            )),
            execution_matrix_digest: digest(include_bytes!(
                "../../../fixtures/conformance/matrix/execution-matrix.json"
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

    fn draft_authority_members() -> (Vec<BundleMemberV1>, Vec<u8>) {
        let inventory_bytes =
            include_bytes!("../../../fixtures/conformance/expected-authority/inventory.json")
                .to_vec();
        let matrix_bytes =
            include_bytes!("../../../fixtures/conformance/matrix/execution-matrix.json").to_vec();
        let provenance_bytes =
            include_bytes!("../../../fixtures/conformance/support/provenance.json").to_vec();
        let members = vec![
            BundleMemberV1::authority_inventory(inventory_bytes),
            BundleMemberV1::execution_matrix(matrix_bytes),
        ];
        (members, provenance_bytes)
    }

    fn draft_members(
        profile: &ConformanceProfileV1,
        provenance_bytes: Vec<u8>,
        mut authority_members: Vec<BundleMemberV1>,
    ) -> (Vec<BundleMemberV1>, BundleExpectedResultV1) {
        let input = b"public draft input".to_vec();
        let expected = b"public draft expected".to_vec();
        let input_path = input_path(
            "ART-001",
            &profile.execution_profile_digests[0],
            "input.json",
        );
        let expected_path = expected_path("ART-001", &profile.execution_profile_digests[0]);
        let mut members = vec![
            BundleMemberV1::fixture_input(input_path, input),
            BundleMemberV1::expected_result(expected_path.clone(), expected.clone()),
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

    /// Construct a valid Draft bundle for public archive-path coverage.
    ///
    /// # Errors
    ///
    /// Returns an error if the checked-in fixture data cannot be transformed
    /// into the Draft authority shape.
    pub fn draft_bundle() -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        let (authority_members, provenance_bytes) = draft_authority_members();
        let profile = profile(digest(&provenance_bytes));
        let (members, expected_result) =
            draft_members(&profile, provenance_bytes, authority_members);
        Ok(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            vec![expected_result],
        )?)
    }
}

#[test]
fn public_member_constructors_derive_typed_content_addresses() {
    let supporting_bytes = b"public supporting bytes".to_vec();
    let supporting = BundleMemberV1::supporting(
        "support/public.txt",
        supporting_bytes.clone(),
        BundleMemberRoleV1::NormativeSpecification,
    );
    assert_eq!(supporting.path, "support/public.txt");
    assert_eq!(supporting.bytes, supporting_bytes);
    assert_eq!(
        supporting.digest,
        *blake3::hash(&supporting.bytes).as_bytes()
    );
    assert_eq!(supporting.role, BundleMemberRoleV1::NormativeSpecification);

    let authority_bytes = b"public authority bytes".to_vec();
    let authority = BundleMemberV1::authority_inventory(authority_bytes.clone());
    assert_eq!(authority.path, AUTHORITY_INVENTORY_MEMBER_PATH);
    assert_eq!(authority.bytes, authority_bytes);
    assert_eq!(authority.digest, *blake3::hash(&authority.bytes).as_bytes());
    assert_eq!(authority.role, BundleMemberRoleV1::AuthorityInventory);
}

fn archive_paths(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut directories = vec![root.to_owned()];
    let mut archives = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                directories.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "cfb1")
            {
                archives.push(path);
            }
        }
    }
    archives.sort();
    Ok(archives)
}

fn materialized_layers(root: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let metadata: JsonValue =
        serde_json::from_slice(&fs::read(root.join("MATERIALIZATION-METADATA.json"))?)?;
    let layers = metadata
        .get("layers")
        .and_then(JsonValue::as_array)
        .ok_or("materialization metadata layers are missing")?;
    layers
        .iter()
        .map(|layer| {
            layer
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "materialization metadata layer is invalid".into())
        })
        .collect()
}

struct TemporaryOutput(PathBuf);

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

fn is_release_archive_filename(archive: &Path) -> bool {
    archive.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        let bytes = name.as_bytes();
        bytes.len() == 69
            && bytes[64..] == b".cfb1"[..]
            && bytes[..64].iter().copied().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
            })
    })
}

fn verify_materialized_layer(layer_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let layer_archives = archive_paths(&layer_root.join("draft"))?;
    assert_eq!(layer_archives.len(), 2);
    assert!(layer_archives
        .iter()
        .all(|archive| is_release_archive_filename(archive)));
    let mut modes = Vec::new();
    for archive_path in layer_archives {
        let bundle = ConformanceBundleV1::from_canonical_cbor(&fs::read(archive_path)?)?;
        modes.push(bundle.manifest.mode);
        let profile_bytes = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::Profile)
            .ok_or("materialized bundle profile is missing")?
            .bytes
            .as_slice();
        let profile = ConformanceProfileV1::from_canonical_cbor(profile_bytes)?;
        assert_eq!(profile.lifecycle, ProfileLifecycleV1::Draft);
        assert_eq!(profile.execution_profile_digests.len(), 2);
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
                .filter(|fixture| fixture.modes == [pos_conformance::ExecutionModeV1::AirGapped])
                .count(),
            7
        );
        assert!(profile.fixtures.iter().all(|fixture| {
            fixture
                .inputs
                .first()
                .is_some_and(|input| input.member_id.starts_with("inputs/"))
        }));
        assert_eq!(bundle.manifest.expected_results.len(), 7);
        assert!(bundle.members.iter().any(|member| {
            member.role == BundleMemberRoleV1::AuthorityInventory
                && member.path == AUTHORITY_INVENTORY_MEMBER_PATH
        }));
        assert!(bundle
            .manifest
            .expected_results
            .iter()
            .all(|expected| expected.mode == bundle.manifest.mode));
        assert_eq!(
            profile.execution_matrix_digest,
            *blake3::hash(include_bytes!(
                "../../../fixtures/conformance/matrix/execution-matrix.json"
            ))
            .as_bytes()
        );
    }
    modes.sort_by_key(|mode| match mode {
        BundleModeV1::Local => 0,
        BundleModeV1::AirGapped => 1,
    });
    assert_eq!(modes, vec![BundleModeV1::Local, BundleModeV1::AirGapped]);
    Ok(())
}

#[test]
fn public_materializer_and_verifier_binaries_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    let _materializer_process_guard = materializer_process_guard();
    let root = std::env::temp_dir().join(format!(
        "pigloros-conformance-public-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _temporary_output = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let output_root = root.join("publication");

    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let materializer_status = Command::new(materializer_binary)
        .current_dir(&root)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg("publication")
        .status()?;
    assert!(materializer_status.success());
    assert!(fs::read_dir(&root)?.all(|entry| {
        entry.is_ok_and(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".pigloros-")
        })
    }));

    let archives = archive_paths(&output_root)?;
    assert_eq!(archives.len(), 14);
    for layer in materialized_layers(&output_root)? {
        verify_materialized_layer(&output_root.join(layer))?;
    }
    let verifier_binary = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    let verifier_status = Command::new(&verifier_binary).args(&archives).status()?;
    assert!(verifier_status.success());

    let addressed_archive = archives.first().ok_or("materializer produced no archive")?;
    let unaddressed_archive = root.join("valid-bytes-without-address.cfb1");
    fs::copy(addressed_archive, &unaddressed_archive)?;
    assert!(!Command::new(verifier_binary)
        .arg(unaddressed_archive)
        .status()?
        .success());
    Ok(())
}

#[test]
fn public_materializer_fingerprint_binds_complete_output_set(
) -> Result<(), Box<dyn std::error::Error>> {
    let _materializer_process_guard = materializer_process_guard();
    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let signing_key = "0707070707070707070707070707070707070707070707070707070707070707";
    let fingerprint = Command::new(materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg("--fingerprint")
        .output()?;
    assert!(fingerprint.status.success());
    let encoded = fingerprint
        .stdout
        .strip_suffix(b"\n")
        .ok_or("missing newline")?;
    assert_eq!(encoded.len(), 64);
    assert_eq!(
        encoded, b"881b01d5d523002dfb5948f7f32e58971146d23972992a020e53a5bad2c9943b",
        "materialization fingerprint must bind the complete required output set"
    );
    assert!(encoded
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
    Ok(())
}

#[test]
fn public_materializer_rejects_invalid_invocations() -> Result<(), Box<dyn std::error::Error>> {
    let _materializer_process_guard = materializer_process_guard();
    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let signing_key = "0707070707070707070707070707070707070707070707070707070707070707";
    let unique = format!(
        "pigloros-conformance-invalid-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let missing_key_output = std::env::temp_dir().join(format!("{unique}-missing-key"));
    let invalid_key_output = std::env::temp_dir().join(format!("{unique}-invalid-key"));
    let existing_output = std::env::temp_dir().join(format!("{unique}-existing"));
    let missing_parent = std::env::temp_dir().join(format!("{unique}-missing-parent/output"));
    let blocked_root = std::env::temp_dir().join(format!("{unique}-blocked"));
    fs::create_dir_all(&existing_output)?;
    fs::write(&blocked_root, b"not a directory")?;

    assert!(!Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .status()?
        .success());
    assert!(!Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .args([&missing_key_output, &invalid_key_output])
        .status()?
        .success());
    let existing_output_result = Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(&existing_output)
        .output()?;
    assert!(!existing_output_result.status.success());
    assert!(existing_output.is_dir());
    assert!(fs::read_dir(&existing_output)?.next().is_none());
    assert!(!Command::new(&materializer_binary)
        .arg(&missing_key_output)
        .status()?
        .success());
    assert!(!Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", "not-a-key")
        .arg(&invalid_key_output)
        .status()?
        .success());
    assert!(!Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(blocked_root.join("child"))
        .status()?
        .success());
    assert!(!Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(&missing_parent)
        .status()?
        .success());
    assert!(!Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg("/")
        .status()?
        .success());

    fs::remove_dir_all(existing_output)?;
    fs::remove_file(blocked_root)?;
    assert!(!missing_key_output.exists());
    assert!(!invalid_key_output.exists());
    assert!(!missing_parent.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn public_materializer_rejects_a_symlinked_parent() -> Result<(), Box<dyn std::error::Error>> {
    let _materializer_process_guard = materializer_process_guard();
    let unique = format!(
        "pigloros-conformance-symlink-parent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    let trusted_parent = root.join("trusted-parent");
    let linked_parent = root.join("linked-parent");
    fs::create_dir_all(&trusted_parent)?;
    std::os::unix::fs::symlink(&trusted_parent, &linked_parent)?;
    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let output = Command::new(materializer_binary)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg(linked_parent.join("publication"))
        .output()?;
    assert!(!trusted_parent.join("publication").exists());
    fs::remove_dir_all(root)?;
    assert!(!output.status.success());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn public_materializer_preserves_atomic_publication_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    let _materializer_process_guard = materializer_process_guard();
    let root = std::env::temp_dir().join(format!(
        "pigloros-conformance-atomic-publication-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _temporary_output = TemporaryOutput(root.clone());
    let protected_parent = root.join("protected-parent");
    let protected_target = root.join("protected-target");
    fs::create_dir_all(&protected_parent)?;
    fs::create_dir_all(&protected_target)?;
    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let signing_key = "0707070707070707070707070707070707070707070707070707070707070707";

    let symlink_destination = root.join("publication-link");
    std::os::unix::fs::symlink(&protected_target, &symlink_destination)?;
    let symlink_status = Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(&symlink_destination)
        .status()?;
    assert!(!symlink_status.success());
    assert!(fs::symlink_metadata(&symlink_destination)?
        .file_type()
        .is_symlink());
    assert!(fs::read_dir(&protected_target)?.next().is_none());

    fs::set_permissions(&protected_parent, fs::Permissions::from_mode(0o500))?;
    let protected_status = Command::new(&materializer_binary)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(protected_parent.join("publication"))
        .status();
    fs::set_permissions(&protected_parent, fs::Permissions::from_mode(0o700))?;
    assert!(!protected_status?.success());
    assert!(fs::read_dir(&protected_parent)?.next().is_none());
    Ok(())
}

#[test]
fn public_verifier_rejects_directory_input() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!(
        "pigloros-conformance-directory-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let verifier_binary = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    let status = Command::new(verifier_binary).arg(&directory).status()?;
    fs::remove_dir_all(&directory)?;
    assert!(!status.success());
    Ok(())
}

#[test]
fn public_verifier_rejects_missing_or_invalid_archive() -> Result<(), Box<dyn std::error::Error>> {
    let verifier_binary = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    assert!(!Command::new(&verifier_binary).status()?.success());

    let path = std::env::temp_dir().join(format!(
        "pigloros-invalid-public-cfb1-{}-{}.cbor",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::write(&path, [0x9f, 0xff])?;
    let status = Command::new(&verifier_binary).arg(&path).status()?;
    fs::remove_file(path)?;
    assert!(!status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn public_verifier_rejects_unsafe_or_oversized_archive_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "pigloros-public-verifier-boundaries-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _temporary_output = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let verifier_binary = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    let missing = root.join("missing.cfb1");
    assert!(!Command::new(&verifier_binary)
        .arg(&missing)
        .status()?
        .success());

    let invalid_utf8 = root.join(std::ffi::OsString::from_vec(vec![0xff]));
    fs::write(&invalid_utf8, b"not-an-archive")?;
    assert!(!Command::new(&verifier_binary)
        .arg(&invalid_utf8)
        .status()?
        .success());

    let oversized = root.join("oversized.cfb1");
    fs::File::create(&oversized)?.set_len(MAX_CONFORMANCE_BUNDLE_BYTES_V1 + 1)?;
    assert!(!Command::new(&verifier_binary)
        .arg(&oversized)
        .status()?
        .success());

    let symlink = root.join("archive-link.cfb1");
    std::os::unix::fs::symlink(&oversized, &symlink)?;
    assert!(!Command::new(&verifier_binary)
        .arg(&symlink)
        .status()?
        .success());

    let fifo = root.join("archive.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(!Command::new(&verifier_binary).arg(fifo).status()?.success());
    Ok(())
}

#[test]
fn public_draft_archive_round_trip_and_independent_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    assert_eq!(bundle.validate(), Ok(()));
    let manifest = bundle.manifest_bytes()?;
    assert_eq!(manifest, bundle.manifest_bytes()?);
    let manifest_digest = bundle.manifest_digest()?;
    let mut manifest_source = b"PiglorOS.ConformanceBundle.v1\0".to_vec();
    manifest_source.extend_from_slice(&manifest);
    assert_eq!(manifest_digest, *blake3::hash(&manifest_source).as_bytes());

    let archive = bundle.to_canonical_cbor()?;
    let archive_digest = bundle.archive_digest()?;
    assert_eq!(archive_digest, *blake3::hash(&archive).as_bytes());
    let filename = bundle.release_filename()?;
    assert_eq!(
        filename,
        format!("{}.cfb1", pos_conformance::hex_digest(&archive_digest))
    );
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Ok(())
    );
    assert_eq!(
        pos_conformance::verify_archive_release_filename(&archive, &filename),
        Ok(())
    );

    let root = std::env::temp_dir().join(format!(
        "pigloros-public-verifier-valid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _temporary_output = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let archive_path = root.join(&filename);
    fs::write(&archive_path, &archive)?;
    let verifier_binary = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    assert!(Command::new(verifier_binary)
        .arg(archive_path)
        .status()?
        .success());

    for invalid_filename in [
        format!("{}.cfb1", "0".repeat(63)),
        format!("{}.cfb1", "g".repeat(64)),
        format!("{}.CFB1", pos_conformance::hex_digest(&archive_digest)),
        format!(
            "{}.cfb1",
            pos_conformance::hex_digest(&archive_digest).to_uppercase()
        ),
        format!(
            "bundle-local-{}.cfb1",
            pos_conformance::hex_digest(&manifest_digest)
        ),
    ] {
        assert_eq!(
            pos_conformance::verify_archive_release_filename(&archive, &invalid_filename),
            Err(pos_conformance::BundleContractErrorV1::ReleaseFilenameInvalid)
        );
    }
    let mut changed_archive = archive.clone();
    changed_archive[0] ^= 1;
    assert_eq!(
        pos_conformance::verify_archive_release_filename(&changed_archive, &filename),
        Err(pos_conformance::BundleContractErrorV1::ArchiveDigestMismatch)
    );
    let re_signed = fixtures::draft_bundle()?.sign(&SigningKey::from_bytes(&[7; 32]))?;
    assert_eq!(re_signed.manifest_digest()?, manifest_digest);
    assert_ne!(re_signed.archive_digest()?, archive_digest);
    assert_ne!(re_signed.release_filename()?, filename);
    assert_eq!(ConformanceBundleV1::from_canonical_cbor(&archive)?, bundle);
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_rebound_semantic_versions(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    for version in [
        "1",
        "1.2",
        "1..3",
        "01.2.3",
        "12345678901.2.3",
        "x.2.3",
        "1.2.3+",
        "1.2.3+build_1",
        "1.2.3+build..1",
        "1.2.3-",
        "1.2.3-01",
        "1.2.3-alpha..1",
        "1.2.3-alpha_1",
    ] {
        let invalid_profile = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile_and_rebind_identity(value, |fields| {
                fields[3] = Value::Text(version.to_owned());
            })
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&invalid_profile),
            Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
        );
    }
    for version in [
        "1.2.3-alpha",
        "1.2.3+build",
        "1.2.3-alpha.1+build.01",
        "1.2.3-a-b+build-id",
    ] {
        let valid_profile = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile_and_rebind_identity(value, |fields| {
                fields[3] = Value::Text(version.to_owned());
            })
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&valid_profile),
            Ok(())
        );
    }
    Ok(())
}

#[test]
fn public_independent_verifier_enforces_each_rebound_cpf1_header_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ProfileValueMutation> = vec![
        Box::new(|fields| fields[0] = Value::Text("CPFX".to_owned())),
        Box::new(|fields| fields[1] = Value::Integer(2_u64.into())),
        Box::new(|fields| fields[4] = Value::Integer(1_u64.into())),
    ];
    for mutate in mutations {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile_and_rebind_identity(value, mutate)
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
        );
    }
    Ok(())
}

#[test]
fn public_archive_decoders_enforce_member_paths_and_accept_predecessor_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let invalid_path = signed_archive_variant(&bundle, &signing_key, |value| {
        let members = archive_array(value, 3)?;
        let Some(Value::Array(member)) = members.first_mut() else {
            return Err("archive member is missing".into());
        };
        member[0] = Value::Text(String::new());

        let manifest = archive_array(value, 2)?;
        let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
            return Err("archive descriptors are missing".into());
        };
        let Some(Value::Array(descriptor)) = descriptors.first_mut() else {
            return Err("archive descriptor is missing".into());
        };
        descriptor[0] = Value::Text(String::new());
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&invalid_path),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );
    assert_eq!(
        pos_conformance::verify_archive_independently(&invalid_path),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );

    let predecessor = signed_archive_variant(&bundle, &signing_key, |value| {
        mutate_profile_and_rebind_identity(value, |fields| {
            fields[16] = Value::Bytes(vec![9; 32]);
        })
    })?;
    assert!(ConformanceBundleV1::from_canonical_cbor(&predecessor).is_ok());
    assert_eq!(
        pos_conformance::verify_archive_independently(&predecessor),
        Ok(())
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_cpf1_semantic_variants(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ArchiveMutation> = cpf1_root_semantic_mutations()
        .into_iter()
        .chain(cpf1_header_and_range_mutations())
        .chain(cpf1_divergence_shape_mutations())
        .chain(cpf1_fixture_semantic_mutations())
        .chain(cpf1_ordering_and_cap_mutations())
        .chain(cpf1_fixture_detail_mutations())
        .chain(cpf1_fixture_branch_mutations())
        .chain(cpf1_fixture_result_mutations())
        .chain(cpf1_malformed_fixture_value_mutations())
        .chain(cpf1_divergent_fixture_mutations())
        .chain(cpf1_bound_expected_result_mutations())
        .chain(cpf1_selected_cap_mutations())
        .collect();
    for (mutation_index, mutate) in mutations.into_iter().enumerate() {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate(value)?;
            mutate_profile_and_rebind_identity(value, |_| {})
        })?;
        assert!(
            pos_conformance::verify_archive_independently(&archive).is_err(),
            "semantic mutation {mutation_index} was accepted"
        );
    }
    Ok(())
}

fn cpf1_root_semantic_mutations() -> Vec<ArchiveMutation> {
    let mut mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[2] = Value::Text("profile#matrix=old".to_owned());
            })
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[5] = Value::Bytes(vec![0; 32]))),
        Box::new(|value| mutate_profile(value, |fields| fields[6] = Value::Bytes(vec![0; 32]))),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[7] {
                    digests.clear();
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[7] {
                    digests[0] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[8] {
                    digests[0] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[16] = Value::Bytes(vec![0; 32]))),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[0] = Value::Text(String::new());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[1] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[0] = Value::Null;
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[3] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[4] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[2] = Value::Text(String::new());
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[2] = Value::Text("x".repeat(257));
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[3] = Value::Integer(1_u64.into());
            })
        }),
    ];
    for version in [
        "1.2",
        "1..3",
        "01.2.3",
        "12345678901.2.3",
        "x.2.3",
        "1.2.3+",
        "1.2.3+build_1",
        "1.2.3+build..1",
        "1.2.3-",
        "1.2.3-01",
        "1.2.3-alpha..1",
        "1.2.3-alpha_1",
    ] {
        mutations.push(Box::new(move |value| {
            mutate_profile(value, |fields| fields[3] = Value::Text(version.to_owned()))
        }));
    }
    mutations
}

fn cpf1_header_and_range_mutations() -> Vec<ArchiveMutation> {
    let mut mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            mutate_profile(value, |fields| fields[0] = Value::Text("CPFX".to_owned()))
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[1] = Value::Integer(2_u64.into()))),
        Box::new(|value| mutate_profile(value, |fields| fields[4] = Value::Integer(1_u64.into()))),
        Box::new(|value| mutate_profile(value, |fields| fields[13] = Value::Bytes(vec![0; 32]))),
        Box::new(|value| mutate_profile(value, |fields| fields[14] = Value::Bytes(vec![0; 32]))),
        Box::new(|value| mutate_profile(value, |fields| fields[15] = Value::Bytes(vec![0; 32]))),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[7] =
                    Value::Array(vec![Value::Bytes(vec![2; 32]), Value::Bytes(vec![1; 32])]);
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[8] =
                    Value::Array(vec![Value::Bytes(vec![2; 32]), Value::Bytes(vec![1; 32])]);
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[2] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[3] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[0] = Value::Text("x".repeat(129));
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[0] = Value::Integer(1_u64.into());
                }
            })
        }),
    ];
    for cap_index in 1_usize..=7 {
        mutations.push(Box::new(move |value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[cap_index] = Value::Integer(0_u64.into());
                    }
                }
            })
        }));
    }
    mutations.push(Box::new(|value| {
        mutate_profile(value, |fields| {
            if let Value::Array(protocol) = &mut fields[11] {
                if let Value::Array(caps) = &mut protocol[4] {
                    caps[9] = Value::Integer((1024_u64 * 1024 + 1).into());
                }
            }
        })
    }));
    mutations
}

fn cpf1_fixture_semantic_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[0] = Value::Text(String::new());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[0] = Value::Text("x".repeat(129));
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[1] = Value::Null;
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[2] = Value::Integer(7_u64.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[4] = Value::Bytes(vec![0; 32]);
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[5] = Value::Array(Vec::new());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[6] = Value::Integer(3_u64.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[11] = Value::Integer(3_u64.into());
                        fixture[12] = Value::Integer(0_u64.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        if let Value::Array(bounds) = &mut fixture[13] {
                            bounds[0] = Value::Integer(0_u64.into());
                        }
                    }
                }
            })
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[15] = Value::Bytes(vec![0; 32]))),
    ]
}

fn cpf1_divergence_shape_mutations() -> Vec<ArchiveMutation> {
    [(9_u64, 1_usize), (0, 0), (0, 129)]
        .into_iter()
        .map(|(kind, coordinate_length)| {
            Box::new(move |value: &mut Value| {
                mutate_profile(value, |fields| {
                    fields[10] = Value::Array(vec![Value::Array(vec![
                        Value::Integer(kind.into()),
                        Value::Bytes(vec![0; coordinate_length]),
                    ])]);
                })
            }) as ArchiveMutation
        })
        .collect()
}

fn cpf1_ordering_and_cap_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[7] {
                    digests.push(digests[0].clone());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[8] {
                    digests.push(digests[0].clone());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[0] = Value::Integer(u64::MAX.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[8] = Value::Integer(129_u64.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[1] = Value::Integer(1_u64.into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[2] = Value::Integer(1_u64.into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[4] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[10] = Value::Array(vec![
                    Value::Array(vec![Value::Integer(1_u64.into()), Value::Bytes(vec![2])]),
                    Value::Array(vec![Value::Integer(1_u64.into()), Value::Bytes(vec![1])]),
                ]);
            })
        }),
    ]
}

fn cpf1_fixture_detail_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[3] = Value::Bytes(vec![0; 32]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[7] = Value::Array(vec![Value::Array(vec![
                    Value::Text("input".to_owned()),
                    Value::Integer(0_u64.into()),
                    Value::Bytes(vec![1; 32]),
                    Value::Bytes(vec![1; 32]),
                ])]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[8] = Value::Array(vec![Value::Integer(3_u64.into()); 5]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[9] = Value::Integer(6_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[10] = Value::Integer(14_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[11] = Value::Integer(1_u64.into());
                fixture[12] = Value::Integer(0_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[13] = Value::Array(vec![Value::Integer(1_u64.into()); 7]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] =
                    Value::Array(vec![Value::Integer(1_u64.into()), Value::Array(Vec::new())]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[15] = Value::Array(vec![Value::Text(String::new()); 7]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[16] = Value::Bytes(vec![0; 32]);
            })
        }),
    ]
}

fn cpf1_fixture_branch_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[3] = Value::Bytes(vec![2; 32]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[4] = Value::Bytes(vec![3; 32]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[5] = Value::Array(vec![Value::Integer(2_u64.into())]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[5] = Value::Array(vec![Value::Integer(4_u64.into())]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[5] = Value::Array(vec![
                    Value::Integer(0_u64.into()),
                    Value::Integer(0_u64.into()),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[0] = Value::Text("non-ascii-\u{00e9}".to_owned());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[1] = Value::Integer(u64::MAX.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[2] = Value::Bytes(vec![0; 32]);
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[3] = Value::Bytes(vec![0; 32]);
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    inputs.push(inputs[0].clone());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[0] = Value::Text(String::new());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[0] = Value::Text("x".repeat(257));
                    }
                }
            })
        }),
    ]
}

fn cpf1_fixture_result_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[1] = Value::Bytes(Vec::new());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[2] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[8] = Value::Array(vec![
                    Value::Integer(2_u64.into()),
                    Value::Bytes(Vec::new()),
                    Value::Bytes(Vec::new()),
                    Value::Null,
                    Value::Array(vec![Value::Integer(0_u64.into()), Value::Bytes(vec![1])]),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[9] = Value::Integer(0_u64.into());
                fixture[10] = Value::Integer(12_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] = Value::Array(vec![
                    Value::Bool(false),
                    Value::Array(vec![
                        Value::Text("z".to_owned()),
                        Value::Text("a".to_owned()),
                    ]),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] =
                    Value::Array(vec![Value::Integer(0_u64.into()), Value::Array(Vec::new())]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] = Value::Array(vec![
                    Value::Bool(false),
                    Value::Array(vec![Value::Text(String::new())]),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] = Value::Array(vec![
                    Value::Bool(false),
                    Value::Array(vec![Value::Text("x".repeat(129))]),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(provenance) = &mut fixture[15] {
                    provenance[1] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(provenance) = &mut fixture[15] {
                    provenance[0] = Value::Text("x".repeat(129));
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(provenance) = &mut fixture[15] {
                    provenance[6] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
    ]
}

fn cpf1_malformed_fixture_value_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[0] = Value::Null;
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[8] = Value::Array(vec![
                    Value::Integer(2_u64.into()),
                    Value::Bytes(Vec::new()),
                    Value::Bytes(Vec::new()),
                    Value::Null,
                    Value::Array(vec![Value::Null, Value::Bytes(vec![1])]),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[8] = Value::Array(vec![
                    Value::Integer(2_u64.into()),
                    Value::Bytes(Vec::new()),
                    Value::Bytes(Vec::new()),
                    Value::Null,
                    Value::Array(vec![Value::Integer(0_u64.into()), Value::Null]),
                ]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[0] = Value::Integer(1_u64.into());
                    expected[3] = Value::Integer(12_u64.into());
                }
                fixture[9] = Value::Integer(3_u64.into());
                fixture[10] = Value::Integer(12_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(bounds) = &mut fixture[13] {
                    bounds[3] = Value::Integer(1_u64.into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] = Value::Array(vec![Value::Bool(false), Value::Null]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    inputs[0] = Value::Null;
                }
            })
        }),
    ]
}

fn cpf1_divergent_fixture_mutations() -> Vec<ArchiveMutation> {
    vec![Box::new(|value| {
        mutate_profile(value, |fields| {
            fields[10] = Value::Array(vec![Value::Array(vec![
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![1]),
            ])]);
            if let Value::Array(fixtures) = &mut fields[9] {
                if let Value::Array(fixture) = &mut fixtures[0] {
                    fixture[8] = Value::Array(vec![
                        Value::Integer(2_u64.into()),
                        Value::Bytes(Vec::new()),
                        Value::Bytes(Vec::new()),
                        Value::Null,
                        Value::Array(vec![Value::Integer(0_u64.into()), Value::Bytes(vec![1])]),
                    ]);
                    fixture[9] = Value::Integer(1_u64.into());
                    fixture[10] = Value::Null;
                }
            }
        })
    })]
}

fn cpf1_bound_expected_result_mutations() -> Vec<ArchiveMutation> {
    let typed_failure = |outcome: u64, observed_error: Option<u64>| {
        Box::new(move |value: &mut Value| {
            mutate_profile_and_rebind_expected_member(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        if let Value::Array(expected) = &mut fixture[8] {
                            expected[0] = Value::Integer(1_u64.into());
                            expected[3] = Value::Integer(7_u64.into());
                        }
                        fixture[9] = Value::Integer(outcome.into());
                        fixture[10] = observed_error
                            .map_or(Value::Null, |error| Value::Integer(error.into()));
                    }
                }
            })
        }) as ArchiveMutation
    };
    let divergence = |allowed_coordinate: u8, observed_error: Option<u64>| {
        Box::new(move |value: &mut Value| {
            mutate_profile_and_rebind_expected_member(value, |fields| {
                fields[10] = Value::Array(vec![Value::Array(vec![
                    Value::Integer(0_u64.into()),
                    Value::Bytes(vec![allowed_coordinate]),
                ])]);
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[8] = Value::Array(vec![
                            Value::Integer(2_u64.into()),
                            Value::Bytes(Vec::new()),
                            Value::Bytes(Vec::new()),
                            Value::Null,
                            Value::Array(vec![Value::Integer(0_u64.into()), Value::Bytes(vec![1])]),
                        ]);
                        fixture[9] = Value::Integer(1_u64.into());
                        fixture[10] = observed_error
                            .map_or(Value::Null, |error| Value::Integer(error.into()));
                    }
                }
            })
        }) as ArchiveMutation
    };
    vec![
        typed_failure(1, None),
        divergence(2, None),
        divergence(1, Some(7)),
    ]
}

fn cpf1_selected_cap_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[5] = Value::Array(vec![Value::Integer(1_u64.into())]);
                if let Value::Array(capabilities) = &mut fixture[14] {
                    capabilities[0] = Value::Bool(true);
                }
            })
        }),
        Box::new(|value| duplicate_first_fixture_with_cap(value, 1, 1)),
    ]
}

#[test]
fn public_independent_verifier_accepts_exact_profile_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let exact_case_cap = signed_archive_variant(&bundle, &signing_key, |value| {
        duplicate_first_fixture_with_cap(value, 1, 2)?;
        mutate_profile_and_rebind_identity(value, |_| {})
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&exact_case_cap),
        Ok(())
    );

    let exact_expected_bound = signed_archive_variant(&bundle, &signing_key, |value| {
        mutate_profile_and_rebind_identity(value, |fields| {
            if let Value::Array(fixtures) = &mut fields[9] {
                for fixture in fixtures {
                    if let Value::Array(fixture) = fixture {
                        let expected_length = match &fixture[8] {
                            Value::Array(expected) => match expected.get(1) {
                                Some(Value::Bytes(bytes)) if !bytes.is_empty() => {
                                    u64::try_from(bytes.len()).ok()
                                }
                                _ => None,
                            },
                            _ => None,
                        };
                        if let (Some(expected_length), Value::Array(bounds)) =
                            (expected_length, &mut fixture[13])
                        {
                            bounds[3] = Value::Integer(expected_length.into());
                            break;
                        }
                    }
                }
            }
        })
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&exact_expected_bound),
        Ok(())
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_each_matrix_invariant(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let matrix_cases: Vec<JsonMutation> = vec![
        Box::new(|value| value["magic"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["version"] = JsonValue::Number(2_u64.into())),
        Box::new(|value| value["lifecycle"] = JsonValue::String("Candidate".to_owned())),
        Box::new(|value| value["row_count"] = JsonValue::Number(11_u64.into())),
        Box::new(|value| value["variant_count"] = JsonValue::Number(3_u64.into())),
        Box::new(|value| value["mode_count"] = JsonValue::Number(3_u64.into())),
        Box::new(|value| value["case_count"] = JsonValue::Number(191_u64.into())),
        Box::new(|value| value["executed_case_count"] = JsonValue::Number(1_u64.into())),
        Box::new(|value| value["rows"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["rows"][0]["variants"] = JsonValue::Array(Vec::new())),
        Box::new(|value| value["rows"][0]["modes"] = JsonValue::Array(Vec::new())),
        Box::new(|value| value["rows"][0]["case_count"] = JsonValue::Number(15_u64.into())),
        Box::new(|value| {
            value["rows"][0]["executed_case_count"] = JsonValue::Number(1_u64.into());
        }),
        Box::new(|value| value["cases"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["variant"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["mode"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["case_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| {
            value["equality_predicates"][0]["fixture_id"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["AuthEq"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["PublicEq"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["OpEq"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| value["cases"][0]["executed"] = JsonValue::Bool(true)),
        Box::new(|value| {
            value["cases"][0]["expected_result_digest"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["cases"][0]["authority_fixture_id"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["cases"][0]["authority_result_digest"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["cases"][0]["expected_result"] = JsonValue::String("wrong".to_owned());
        }),
    ];
    for mutate in matrix_cases {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_archive_matrix(value, mutate)
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
        );
    }
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_authority_inventory_variants(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<JsonMutation> = vec![
        Box::new(|value| value["magic"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["version"] = JsonValue::Number(2_u64.into())),
        Box::new(|value| value["digest_algorithm"] = JsonValue::String("SHA-256".to_owned())),
        Box::new(|value| value["lifecycle"] = JsonValue::String("Candidate".to_owned())),
        Box::new(|value| value["entries"] = JsonValue::Array(Vec::new())),
        Box::new(|value| {
            value["entries"][0]["fixture_id"] = JsonValue::String("wrong".to_owned());
        }),
    ];
    for mutate in mutations {
        let changed = mutate_bound_json_member(&bundle, AUTHORITY_INVENTORY_MEMBER_PATH, mutate)?;
        let archive = independently_signed_changed_bundle(&bundle, &changed, &signing_key)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
        );
    }
    Ok(())
}

#[test]
fn public_independent_verifier_binds_expected_bytes_and_fixture_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;

    let changed_expected = archive_with_changed_expected(&bundle, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&changed_expected),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let missing_input = archive_without_first_fixture_input(&bundle, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&missing_input),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let misplaced_support = archive_with_misplaced_support(&bundle, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&misplaced_support),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let mixed_case_secret = archive_with_mixed_case_secret(&bundle, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&mixed_case_secret),
        Err(pos_conformance::BundleContractErrorV1::SecretMaterialDetected)
    );

    let stale_matrix_binding = archive_with_stale_matrix_binding(&bundle, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&stale_matrix_binding),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_expected_result_envelope_variants(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            let expected = archive_expected(value)?;
            expected[4] = Value::Text("expected/missing.bin".to_owned());
            Ok(())
        }),
        Box::new(|value| {
            let expected = archive_expected(value)?;
            expected[5] = Value::Bytes(vec![0; 32]);
            Ok(())
        }),
        Box::new(|value| {
            let expected = archive_expected(value)?;
            expected[1] = Value::Integer(7_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            let expected = archive_expected(value)?;
            expected[2] = Value::Bytes(vec![2; 32]);
            Ok(())
        }),
        Box::new(|value| {
            let expected = archive_expected(value)?;
            expected[3] = Value::Integer(2_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected_results(value)?.clear();
            Ok(())
        }),
        Box::new(|value| {
            let manifest = archive_array(value, 2)?;
            manifest[1] = Value::Integer(1_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            let manifest = archive_array(value, 2)?;
            manifest[2] = Value::Integer(2_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            let descriptors = archive_array(value, 2)?;
            if let Value::Array(members) = &mut descriptors[4] {
                members.pop();
            }
            Ok(())
        }),
    ];
    for mutate in mutations {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert!(pos_conformance::verify_archive_independently(&archive).is_err());
    }
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_re_signed_contract_invariant_mutations(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;

    let non_cfb1_manifest = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_array(value, 2)?[0] = Value::Text("not-cfb1".to_owned());
        Ok(())
    })?;
    assert!(ConformanceBundleV1::from_canonical_cbor(&non_cfb1_manifest).is_err());
    assert_eq!(
        pos_conformance::verify_archive_independently(&non_cfb1_manifest),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );

    let unordered_expected_results = signed_archive_variant(&bundle, &signing_key, |value| {
        let expected_results = archive_expected_results(value)?;
        let duplicate = expected_results
            .first()
            .cloned()
            .ok_or("archive expected result is missing")?;
        expected_results.push(duplicate);
        Ok(())
    })?;
    assert!(ConformanceBundleV1::from_canonical_cbor(&unordered_expected_results).is_err());
    assert_eq!(
        pos_conformance::verify_archive_independently(&unordered_expected_results),
        Err(pos_conformance::BundleContractErrorV1::NonCanonicalOrder)
    );

    let malformed_profile = signed_archive_variant(&bundle, &signing_key, |value| {
        mutate_profile(value, |fields| fields[6] = Value::Array(Vec::new()))
    })?;
    assert!(ConformanceBundleV1::from_canonical_cbor(&malformed_profile).is_err());
    assert_eq!(
        pos_conformance::verify_archive_independently(&malformed_profile),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_secret_markers_and_invalid_caps(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;

    for secret in [
        b"PRIVATE_KEY credential".as_slice(),
        b"BEGIN SECRET credential".as_slice(),
        b"Bearer 0123456789abcdef".as_slice(),
        br#"{"api_key":"0123456789abcdef"}"#.as_slice(),
        b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".as_slice(),
        b"ghp_0123456789abcdefghij".as_slice(),
        b"github_pat_0123456789abcdefghij".as_slice(),
        b"glpat-0123456789abcdefghij".as_slice(),
        b"xoxb-0123456789abcdefghij".as_slice(),
        b"xoxp-0123456789abcdefghij".as_slice(),
        b"sk_live_0123456789abcdef".as_slice(),
        b"sk_test_0123456789abcdef".as_slice(),
        b"AIza0123456789abcdefghijklmnopqrst".as_slice(),
        b"AKIA0123456789ABCDEF".as_slice(),
        b"prefix-AKIA0123456789ABCDEF".as_slice(),
        b"eyjabcdefgh.klmnopqrst.uvwxyzabcd".as_slice(),
        b"eyjabcdefg.abcdefghij.abcdefghij".as_slice(),
        b"prefix-eyjabcdefg.abcdefghij.abcdefghij".as_slice(),
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            let member = archive_member(value, "support/normative-requirements.md")?;
            member[1] = Value::Bytes(secret.to_vec());
            let descriptor = archive_descriptor(value, "support/normative-requirements.md")?;
            descriptor[1] = Value::Integer((secret.len() as u64).into());
            descriptor[2] = Value::Bytes(blake3::hash(secret).as_bytes().to_vec());
            Ok(())
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::SecretMaterialDetected)
        );
    }

    for cap_index in [0_usize, 5] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile(value, |fields| {
                if let Some(Value::Array(protocol)) = fields.get_mut(11) {
                    if let Some(Value::Array(caps)) = protocol.get_mut(4) {
                        caps[cap_index] = Value::Integer(0_u64.into());
                    }
                }
            })
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
        );
    }
    Ok(())
}

fn archive_with_changed_expected(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        let path = {
            let expected = archive_expected(value)?;
            match &expected[4] {
                Value::Text(path) => path.clone(),
                _ => return Err("expected path is not text".into()),
            }
        };
        let member = archive_member(value, &path)?;
        let (changed_len, changed_digest) = {
            let Value::Bytes(bytes) = &mut member[1] else {
                return Err("expected member bytes are missing".into());
            };
            bytes.push(0);
            (bytes.len(), blake3::hash(bytes).as_bytes().to_vec())
        };
        let descriptor = archive_descriptor(value, &path)?;
        descriptor[1] = Value::Integer((changed_len as u64).into());
        descriptor[2] = Value::Bytes(changed_digest.clone());
        archive_expected(value)?[5] = Value::Bytes(changed_digest);
        Ok(())
    })
}

fn archive_without_first_fixture_input(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        let (member_index, path) = {
            let members = archive_array(value, 3)?;
            let index = members
                .iter()
                .position(|member| {
                    matches!(
                        member,
                        Value::Array(fields)
                            if fields.get(2) == Some(&Value::Integer(0_u64.into()))
                    )
                })
                .ok_or("fixture input is missing")?;
            let path = match &members[index] {
                Value::Array(fields) => match &fields[0] {
                    Value::Text(path) => path.clone(),
                    _ => return Err("fixture input path is missing".into()),
                },
                _ => return Err("fixture input is malformed".into()),
            };
            (index, path)
        };
        archive_array(value, 3)?.remove(member_index);
        let manifest = archive_array(value, 2)?;
        let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
            return Err("archive descriptors are missing".into());
        };
        let descriptor_index = descriptors
            .iter()
            .position(|descriptor| {
                matches!(
                    descriptor,
                    Value::Array(fields) if fields.first() == Some(&Value::Text(path.clone()))
                )
            })
            .ok_or("fixture input descriptor is missing")?;
        descriptors.remove(descriptor_index);
        Ok(())
    })
}

fn archive_with_misplaced_support(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        let member = archive_member(value, "support/normative-requirements.md")?;
        member[0] = Value::Text("support/normative-requirements.txt".to_owned());
        let descriptor = archive_descriptor(value, "support/normative-requirements.md")?;
        descriptor[0] = Value::Text("support/normative-requirements.txt".to_owned());
        Ok(())
    })
}

fn archive_with_mixed_case_secret(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        let member = archive_member(value, "support/normative-requirements.md")?;
        member[1] = Value::Bytes(b"\"PaSsWoRd\"".to_vec());
        let descriptor = archive_descriptor(value, "support/normative-requirements.md")?;
        descriptor[1] = Value::Integer((b"\"PaSsWoRd\"".len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(b"\"PaSsWoRd\"").as_bytes().to_vec());
        Ok(())
    })
}

fn archive_with_stale_matrix_binding(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        let matrix_bytes = {
            let member = archive_member(value, EXECUTION_MATRIX_MEMBER_PATH)?;
            let Value::Bytes(bytes) = &mut member[1] else {
                return Err("execution matrix bytes are missing".into());
            };
            bytes.push(b' ');
            bytes.clone()
        };
        let descriptor = archive_descriptor(value, EXECUTION_MATRIX_MEMBER_PATH)?;
        descriptor[1] = Value::Integer((matrix_bytes.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&matrix_bytes).as_bytes().to_vec());
        Ok(())
    })
}

#[test]
fn public_bundle_rejection_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;

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

#[test]
fn public_unsigned_bundle_contract_edges_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;

    let mut invalid_lifecycle = bundle.clone();
    invalid_lifecycle.manifest.lifecycle = ProfileLifecycleV1::Stable;
    assert_eq!(
        invalid_lifecycle.validate(),
        Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
    );

    let mut invalid_descriptor_path = bundle.clone();
    let descriptor_path = invalid_descriptor_path.manifest.members[0].path.clone();
    invalid_descriptor_path.manifest.members[0].path = format!("{descriptor_path}:");
    assert_eq!(
        invalid_descriptor_path.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );

    let fixture_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::FixtureInput)
        .ok_or("fixture input member is missing")?;
    let mut invalid_member_role = bundle.clone();
    invalid_member_role.manifest.members[fixture_index].role = BundleMemberRoleV1::Profile;
    assert_eq!(
        invalid_member_role.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );

    let mut invalid_input_role = bundle.clone();
    invalid_input_role.members[fixture_index].role = BundleMemberRoleV1::Profile;
    assert_eq!(
        invalid_input_role.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );

    let mut missing_expected_reference = bundle.clone();
    missing_expected_reference.manifest.expected_results.clear();
    assert_eq!(
        missing_expected_reference.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );

    let mut invalid_input_path = bundle;
    invalid_input_path.members[fixture_index].path = "inputs/not-declared.bin".to_owned();
    invalid_input_path.manifest.members[fixture_index].path = "inputs/not-declared.bin".to_owned();
    assert_eq!(
        invalid_input_path.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    Ok(())
}

#[test]
fn public_unsigned_bundle_member_edges_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let support_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::NormativeSpecification)
        .ok_or("normative support member is missing")?;
    let mut invalid_support_digest = bundle.clone();
    invalid_support_digest.members[support_index].bytes.push(0);
    assert_eq!(
        invalid_support_digest.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut invalid_member_path = bundle.clone();
    let support_path = invalid_member_path.members[support_index].path.clone();
    let invalid_path = format!("{support_path}\u{1}");
    invalid_member_path.members[support_index].path = invalid_path.clone();
    invalid_member_path.manifest.members[support_index].path = invalid_path;
    assert_eq!(
        invalid_member_path.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );

    let mut missing_support = bundle.clone();
    missing_support.members.remove(support_index);
    missing_support.manifest.members.remove(support_index);
    assert_eq!(
        missing_support.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let mut invalid_expected_digest = bundle.clone();
    invalid_expected_digest.manifest.expected_results[0].digest = [0; 32];
    assert_eq!(
        invalid_expected_digest.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut secret_member = bundle;
    secret_member.members[support_index].bytes = b"\"password\"".to_vec();
    secret_member.members[support_index].digest =
        *blake3::hash(&secret_member.members[support_index].bytes).as_bytes();
    secret_member.manifest.members[support_index].size_bytes =
        secret_member.members[support_index].bytes.len() as u64;
    secret_member.manifest.members[support_index].digest =
        secret_member.members[support_index].digest;
    assert_eq!(
        secret_member.validate(),
        Err(pos_conformance::BundleContractErrorV1::SecretMaterialDetected)
    );
    Ok(())
}

#[test]
fn public_bundle_rejects_every_unsafe_member_path_class() -> Result<(), Box<dyn std::error::Error>>
{
    let bundle = signed_draft_bundle()?;
    let support_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::NormativeSpecification)
        .ok_or("normative support member is missing")?;
    for invalid_path in [
        String::new(),
        "/absolute".to_owned(),
        "support//notice".to_owned(),
        "support/./notice".to_owned(),
        "support/../notice".to_owned(),
        "support\\notice".to_owned(),
        "support:notice".to_owned(),
        format!("support/{}notice", '\u{7f}'),
        "support/naïve".to_owned(),
        "x".repeat(257),
    ] {
        let mut invalid = bundle.clone();
        invalid.members[support_index].path = invalid_path.clone();
        invalid.manifest.members[support_index].path = invalid_path;
        invalid
            .members
            .sort_by(|left, right| left.path.cmp(&right.path));
        invalid.manifest.members.sort_unstable();
        assert_eq!(
            invalid.validate(),
            Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
        );
    }

    for path in ["support/space name".to_owned(), "x".repeat(256)] {
        let mut valid_boundary = bundle.clone();
        valid_boundary.members[support_index].path.clone_from(&path);
        valid_boundary.manifest.members[support_index]
            .path
            .clone_from(&path);
        valid_boundary
            .members
            .sort_by(|left, right| left.path.cmp(&right.path));
        valid_boundary.manifest.members.sort_unstable();
        assert_ne!(
            valid_boundary.validate(),
            Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
        );
    }
    Ok(())
}

fn signed_draft_bundle() -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
    static BUNDLE: OnceLock<Result<ConformanceBundleV1, String>> = OnceLock::new();
    BUNDLE
        .get_or_init(|| {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
            let bundle = fixtures::draft_bundle().map_err(|error| error.to_string())?;
            bundle.sign(&signing_key).map_err(|error| error.to_string())
        })
        .clone()
        .map_err(|error| std::io::Error::other(error).into())
}

fn assert_archive_decoder_rejected(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
    expected: pos_conformance::BundleContractErrorV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let archive = signed_archive_variant(bundle, signing_key, mutate)?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&archive),
        Err(expected)
    );
    Ok(())
}

fn assert_post_signed_archive_decoder_rejected(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    mutate: impl FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let archive = post_signed_archive_variant(bundle, signing_key, mutate)?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&archive),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    Ok(())
}

fn assert_json_member_rejected(
    bundle: &ConformanceBundleV1,
    path: &str,
    mutate: impl FnOnce(&mut JsonValue),
    expected: pos_conformance::BundleContractErrorV1,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let changed = mutate_bound_json_member(bundle, path, mutate)?;
    assert_eq!(changed.validate(), Err(expected), "{label}");
    Ok(())
}

fn replace_member_bytes(
    bundle: &mut ConformanceBundleV1,
    member_index: usize,
    bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let digest = *blake3::hash(&bytes).as_bytes();
    let path = bundle.members[member_index].path.clone();
    bundle.members[member_index].bytes = bytes;
    bundle.members[member_index].digest = digest;
    let size_bytes = u64::try_from(bundle.members[member_index].bytes.len())?;
    let descriptor = bundle
        .manifest
        .members
        .iter_mut()
        .find(|descriptor| descriptor.path == path)
        .ok_or("JSON descriptor is missing")?;
    descriptor.size_bytes = size_bytes;
    descriptor.digest = digest;
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn mutate_bound_json_member(
    bundle: &ConformanceBundleV1,
    path: &str,
    mutate: impl FnOnce(&mut JsonValue),
) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
    let mut changed = bundle.clone();
    let member_index = changed
        .members
        .iter()
        .position(|member| member.path == path)
        .ok_or("JSON member is missing")?;
    let mut json: JsonValue = serde_json::from_slice(&changed.members[member_index].bytes)?;
    mutate(&mut json);
    let bytes = serde_json::to_vec(&json)?;
    replace_member_bytes(&mut changed, member_index, bytes.clone())?;
    if path == AUTHORITY_INVENTORY_MEMBER_PATH {
        let provenance_index = changed
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("provenance member is missing")?;
        let mut provenance: JsonValue =
            serde_json::from_slice(&changed.members[provenance_index].bytes)?;
        provenance["authority_inventory"]["sha256_digest"] =
            JsonValue::String(hex_digest(&Sha256::digest(&bytes)));
        let provenance_bytes = serde_json::to_vec(&provenance)?;
        replace_member_bytes(&mut changed, provenance_index, provenance_bytes)?;
        rebind_profile_to_provenance(&mut changed, provenance_index)?;
    } else if path == EXECUTION_MATRIX_MEMBER_PATH {
        let provenance_index = changed
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("provenance member is missing")?;
        let mut provenance: JsonValue =
            serde_json::from_slice(&changed.members[provenance_index].bytes)?;
        provenance["adr_059_execution_matrix"]["blake3_digest"] =
            JsonValue::String(hex_digest(blake3::hash(&bytes).as_bytes()));
        let provenance_bytes = serde_json::to_vec(&provenance)?;
        replace_member_bytes(&mut changed, provenance_index, provenance_bytes)?;
        rebind_profile_to_provenance(&mut changed, provenance_index)?;
        rebind_profile_to_execution_matrix(&mut changed, member_index)?;
    } else if path == "support/provenance.json" {
        rebind_profile_to_provenance(&mut changed, member_index)?;
    }
    Ok(changed)
}

fn rebind_profile_to_provenance(
    bundle: &mut ConformanceBundleV1,
    provenance_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("profile member is missing")?;
    let mut profile =
        ConformanceProfileV1::from_canonical_cbor(&bundle.members[profile_index].bytes)?;
    let provenance_digest = bundle.members[provenance_index].digest;
    profile.provenance_digest = provenance_digest;
    for fixture in &mut profile.fixtures {
        fixture.provenance.source_digest = provenance_digest;
        fixture.provenance.build_digest = provenance_digest;
        fixture.provenance.publication_review_digest = provenance_digest;
    }
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    replace_member_bytes(bundle, profile_index, profile_bytes)?;
    bundle.manifest.profile_digest = profile.profile_digest;
    Ok(())
}

fn rebind_profile_to_execution_matrix(
    bundle: &mut ConformanceBundleV1,
    matrix_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("profile member is missing")?;
    let mut profile =
        ConformanceProfileV1::from_canonical_cbor(&bundle.members[profile_index].bytes)?;
    profile.execution_matrix_digest = bundle.members[matrix_index].digest;
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    replace_member_bytes(bundle, profile_index, profile_bytes)?;
    bundle.manifest.profile_digest = profile.profile_digest;
    Ok(())
}

fn public_bundle_inputs(
    bundle: &ConformanceBundleV1,
) -> Result<PublicBundleInputs, Box<dyn std::error::Error>> {
    let profile_member = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("profile member is missing")?;
    let profile = ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)?;
    let members = bundle
        .members
        .iter()
        .filter(|member| member.role != BundleMemberRoleV1::Profile)
        .cloned()
        .collect();
    Ok((profile, members, bundle.manifest.expected_results.clone()))
}

fn archive_at_each_selected_cap_boundary() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (mut profile, members, expected_results) = public_bundle_inputs(&base)?;
    let member_count = u32::try_from(members.len() + 1)?;
    let largest_path = members
        .iter()
        .map(|member| member.path.len())
        .chain(["profile/CPF1.cbor".len()])
        .max()
        .ok_or("bundle member path is missing")?;

    for _ in 0..8 {
        profile.profile_digest = profile.digest();
        let profile_bytes = profile.to_canonical_cbor()?;
        let largest_member = members
            .iter()
            .map(|member| member.bytes.len())
            .chain([profile_bytes.len()])
            .max()
            .ok_or("bundle member bytes are missing")?;
        let caps = &mut profile.evaluator_protocol.hard_caps;
        caps.max_profile_bytes = u64::try_from(profile_bytes.len())?;
        caps.max_bundle_members = member_count;
        caps.max_member_path_bytes = u16::try_from(largest_path)?;
        caps.max_member_bytes = u64::try_from(largest_member)?;
        profile.profile_digest = profile.digest();

        let bundle = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members.clone(),
            expected_results.clone(),
        )?
        .sign(&SigningKey::from_bytes(&[42; 32]))?;
        let archive = bundle.to_canonical_cbor()?;
        let archive_len = u64::try_from(archive.len())?;
        if profile.evaluator_protocol.hard_caps.max_total_bundle_bytes == archive_len
            && u64::try_from(profile_bytes.len())?
                == profile.evaluator_protocol.hard_caps.max_profile_bytes
        {
            return Ok(archive);
        }
        profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = archive_len;
    }
    Err("archive cap boundaries did not converge".into())
}

fn materialize_at_each_selected_cap_boundary(
) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (mut profile, members, expected_results) = public_bundle_inputs(&base)?;
    let member_count = u32::try_from(members.len() + 1)?;
    let largest_path = members
        .iter()
        .map(|member| member.path.len())
        .chain(["profile/CPF1.cbor".len()])
        .max()
        .ok_or("bundle member path is missing")?;
    let non_profile_bytes = members.iter().try_fold(0_u64, |total, member| {
        Ok::<_, Box<dyn std::error::Error>>(total + u64::try_from(member.bytes.len())?)
    })?;

    for _ in 0..8 {
        profile.profile_digest = profile.digest();
        let profile_bytes = profile.to_canonical_cbor()?;
        let profile_len = u64::try_from(profile_bytes.len())?;
        let largest_member = members
            .iter()
            .map(|member| member.bytes.len())
            .chain([profile_bytes.len()])
            .max()
            .ok_or("bundle member bytes are missing")?;
        let caps = &mut profile.evaluator_protocol.hard_caps;
        let next_caps = (
            profile_len,
            member_count,
            u16::try_from(largest_path)?,
            u64::try_from(largest_member)?,
            non_profile_bytes + profile_len,
        );
        let unchanged = (
            caps.max_profile_bytes,
            caps.max_bundle_members,
            caps.max_member_path_bytes,
            caps.max_member_bytes,
            caps.max_total_bundle_bytes,
        ) == next_caps;
        (
            caps.max_profile_bytes,
            caps.max_bundle_members,
            caps.max_member_path_bytes,
            caps.max_member_bytes,
            caps.max_total_bundle_bytes,
        ) = next_caps;
        profile.profile_digest = profile.digest();
        let bundle = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members.clone(),
            expected_results.clone(),
        )?;
        if unchanged {
            return Ok(bundle);
        }
    }
    Err("materialization cap boundaries did not converge".into())
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
    for mutate in [
        Box::new(|value: &mut Value| {
            top_fields(value)?[2] = Value::Null;
            Ok(())
        }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[1] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[1] = Value::Integer(2_u64.into());
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_array(value, 2)?[2] = Value::Null;
            Ok(())
        }),
    ] {
        assert_archive_rejected(bundle, signing_key, mutate)?;
    }
    for mutate in [
        Box::new(|value: &mut Value| {
            top_fields(value)?[0] = Value::Null;
            Ok(())
        }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
        Box::new(|value: &mut Value| {
            top_fields(value)?[1] = Value::Text("wrong".to_owned());
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
    assert_archive_rejected(bundle, signing_key, |value| {
        archive_member(value, "support/normative-requirements.md")?[2] =
            Value::Integer(14_u64.into());
        Ok(())
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        replace_archive_descriptor_value(
            value,
            "support/normative-requirements.md",
            Value::Integer(14_u64.into()),
        )
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        replace_archive_descriptor_value(value, "support/normative-requirements.md", Value::Null)
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
        replace_archive_expected_value(value, Value::Null)
    })?;
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
        mutate_profile(value, |fields| fields[17] = Value::Bytes(vec![7; 32]))?;
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
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[17] = Value::Null)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[0] = Value::Null)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[1] = Value::Text("wrong".to_owned()))
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[4] = Value::Text("wrong".to_owned()))
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[0] = Value::Null)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[1] = Value::Null)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[4] = Value::Null)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        archive_array(value, 2)?[3] = Value::Null;
        Ok(())
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        let mut noncanonical = match archive_member(value, "profile/CPF1.cbor")?.get(1) {
            Some(Value::Bytes(profile_bytes)) => profile_bytes.clone(),
            _ => return Err("profile bytes are missing".into()),
        };
        replace_first_byte(&mut noncanonical, 0, &[0x18, 0x00])?;
        replace_profile_bytes(value, &noncanonical)
    })?;
    Ok(())
}

fn assert_independent_profile_shape_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_archive_rejected(bundle, signing_key, |value| {
        replace_profile_bytes(value, &[0xff])
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        let empty = encode_archive(&Value::Array(Vec::new()))?;
        replace_profile_bytes(value, &empty)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| fields[11] = Value::Null)
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| {
            if let Value::Array(protocol) = &mut fields[11] {
                protocol[4] = Value::Null;
            }
        })
    })?;
    assert_archive_rejected(bundle, signing_key, |value| {
        mutate_profile(value, |fields| {
            if let Value::Array(protocol) = &mut fields[11] {
                if let Value::Array(caps) = &mut protocol[4] {
                    caps[0] = Value::Null;
                }
            }
        })
    })?;
    let invalid_text_profile = signed_archive_variant(bundle, signing_key, |value| {
        let invalid_profile = vec![0x61, 0xff];
        archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(invalid_profile.clone());
        let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
        descriptor[1] = Value::Integer((invalid_profile.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&invalid_profile).as_bytes().to_vec());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&invalid_text_profile),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

fn assert_independent_expected_result_field_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            archive_expected(value)?[0] = Value::Integer(1_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[1] = Value::Text("wrong".to_owned());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[1] = Value::Integer(99_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[2] = Value::Bytes(vec![0]);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[3] = Value::Text("wrong".to_owned());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[3] = Value::Integer(99_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[5] = Value::Bytes(vec![0]);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[4] = Value::Integer(1_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[5] = Value::Array(vec![Value::Null]);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[4] = Value::Text("expected/missing.bin".to_owned());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[3] = Value::Integer(1_u64.into());
            Ok(())
        }),
    ];
    for mutate in mutations {
        assert_archive_rejected(bundle, signing_key, mutate)?;
    }
    Ok(())
}

fn assert_independent_profile_archive_rejections(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let malformed_fixtures = signed_archive_variant(bundle, signing_key, |value| {
        let profile_bytes = match archive_member(value, "profile/CPF1.cbor")?.get(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("profile bytes are missing".into()),
        };
        let mut profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
        let Value::Array(fields) = &mut profile else {
            return Err("profile is not an array".into());
        };
        fields[9] = Value::Null;
        let profile_bytes = encode_archive(&profile)?;
        archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(profile_bytes.clone());
        let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
        descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&malformed_fixtures),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );

    let cap_limited_archive = signed_archive_variant(bundle, signing_key, |value| {
        let profile_bytes = match archive_member(value, "profile/CPF1.cbor")?.get(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("profile bytes are missing".into()),
        };
        let mut profile = ConformanceProfileV1::from_canonical_cbor(&profile_bytes)?;
        let total_cap = u64::try_from(profile_bytes.len())?;
        profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = total_cap;
        let profile_digest = profile.digest();
        let mut profile_value: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
        let Value::Array(fields) = &mut profile_value else {
            return Err("profile is not an array".into());
        };
        let Value::Array(protocol) = &mut fields[11] else {
            return Err("profile protocol is not an array".into());
        };
        let Value::Array(caps) = &mut protocol[4] else {
            return Err("profile caps are not an array".into());
        };
        caps[5] = Value::Integer(total_cap.into());
        fields[17] = Value::Bytes(profile_digest.to_vec());
        let profile_bytes = encode_archive(&profile_value)?;
        archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(profile_bytes.clone());
        let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
        descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
        archive_array(value, 2)?[3] = Value::Bytes(profile_digest.to_vec());
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&cap_limited_archive),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_each_expected_result_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    assert_independent_expected_result_field_rejections(&bundle, &signing_key)?;
    assert_independent_profile_archive_rejections(&bundle, &signing_key)
}

fn raw_archive_with_header(top_header: &[u8], first: &[u8], members: &[u8]) -> Vec<u8> {
    raw_archive_with_tail(top_header, first, members, &[0x58, 0x20], &[0x58, 0x40])
}

fn raw_archive_with_tail(
    top_header: &[u8],
    first: &[u8],
    members: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut bytes = top_header.to_vec();
    bytes.extend_from_slice(first);
    bytes.extend_from_slice(&[0x01, 0x80]);
    bytes.extend_from_slice(members);
    bytes.extend_from_slice(public_key);
    if public_key == [0x58, 0x20].as_slice() {
        bytes.extend_from_slice(&[0; 32]);
    }
    bytes.extend_from_slice(signature);
    if signature == [0x58, 0x40].as_slice() {
        bytes.extend_from_slice(&[0; 64]);
    }
    bytes
}

fn raw_archive(first: &[u8], members: &[u8]) -> Vec<u8> {
    raw_archive_with_header(&[0x86], first, members)
}

fn exact_member_array() -> Vec<u8> {
    let mut bytes = vec![0x9a, 0, 1, 0, 0];
    for _ in 0..65_536 {
        bytes.extend_from_slice(&[0x83, 0x60, 0x40, 0x00]);
    }
    bytes
}

#[test]
fn public_independent_verifier_rejects_unknown_matching_member_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let archive = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_member(value, "support/normative-requirements.md")?[2] =
            Value::Integer(14_u64.into());
        archive_descriptor(value, "support/normative-requirements.md")?[3] =
            Value::Integer(14_u64.into());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    Ok(())
}

#[test]
fn public_independent_verifier_classifies_role_mismatch_as_undeclared(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let archive = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_member(value, "support/normative-requirements.md")?[2] =
            Value::Integer(0_u64.into());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );
    Ok(())
}

fn assert_raw_independent_archive_rejections() {
    assert!(pos_conformance::verify_archive_independently(&[0x01, 0x00]).is_err());
    assert!(pos_conformance::verify_archive_independently(&[0x9a, 0, 1, 0, 1]).is_err());
    assert!(pos_conformance::verify_archive_independently(&[0x5a, 0x04, 0, 0, 1]).is_err());
    let mut deeply_nested = vec![0x81; 34];
    deeply_nested.push(0xf6);
    assert!(pos_conformance::verify_archive_independently(&deeply_nested).is_err());
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x60, 0x40, 0x00],
    ))
    .is_err());
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x60, 0x41],
    ))
    .is_err());
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x60, 0x59, 0x04, 0x00],
    ))
    .is_err());
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x59, 0x04, 0x00],
    ))
    .is_err());
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x60, 0x40, 0xc0],
    ))
    .is_err());
    assert!(
        pos_conformance::verify_archive_independently(&raw_archive_with_tail(
            &[0x86],
            &[0x60],
            &[0x80],
            &[0xc0],
            &[0x40],
        ))
        .is_err()
    );
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x79, 0x01, 0x01],
    ))
    .is_err());
    assert!(pos_conformance::verify_archive_independently(&raw_archive(
        &[0x60],
        &exact_member_array(),
    ))
    .is_err());
}

#[test]
fn public_independent_archive_rejection_paths_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    assert_raw_independent_archive_rejections();
    assert_archive_shape_rejections(&bundle, &signing_key)?;
    assert_archive_member_rejections(&bundle, &signing_key)?;
    assert_archive_expected_rejections(&bundle, &signing_key)?;
    assert_archive_profile_rejections(&bundle, &signing_key)?;
    assert_independent_profile_shape_rejections(&bundle, &signing_key)?;

    let mut noncanonical_archive = signed_archive_variant(&bundle, &signing_key, |_| Ok(()))?;
    make_cfb1_version_noncanonical(&mut noncanonical_archive)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&noncanonical_archive),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );

    for (mutate, expected) in [
        (
            Box::new(|value: &mut Value| {
                mutate_profile(value, |fields| {
                    if let Some(Value::Array(protocol)) = fields.get_mut(11) {
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
                    if let Some(Value::Array(protocol)) = fields.get_mut(11) {
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
                    if let Some(Value::Array(protocol)) = fields.get_mut(11) {
                        if let Some(Value::Array(caps)) = protocol.get_mut(4) {
                            caps[5] = Value::Integer(1_u64.into());
                        }
                    }
                })
            }),
            pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid,
        ),
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(expected)
        );
    }

    Ok(())
}

#[test]
fn public_archive_preflight_distinguishes_exact_and_exceeded_resource_bounds() {
    let prefixed = |item: Vec<u8>| {
        let mut archive = vec![0x86];
        archive.extend(item);
        archive
    };
    for (major, maximum) in [(2_u8, 64 * 1024 * 1024), (3, 256), (4, 65_536)] {
        assert_preflight_boundary(
            &prefixed(cbor_length_header(major, maximum)),
            &prefixed(cbor_length_header(major, maximum + 1)),
        );
    }

    let member_array = |length| {
        let mut archive = vec![0x86, 0xf6, 0xf6, 0xf6];
        archive.extend(cbor_length_header(4, length));
        archive
    };
    assert_preflight_boundary(&member_array(65_536), &member_array(65_537));

    let nested = |array_count| {
        let mut archive = vec![0x86];
        archive.extend(std::iter::repeat_n(0x81, array_count));
        archive.push(0xf6);
        archive
    };
    assert_preflight_boundary(&nested(30), &nested(31));
}

#[test]
fn public_archive_decoder_rejects_each_manifest_field_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            top_fields(value)?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            top_fields(value)?[1] = Value::Integer(2_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[1] = Value::Integer(9_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[2] = Value::Integer(9_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[3] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[4] = Value::Array(vec![Value::Null]);
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[5] = Value::Array(vec![Value::Null]);
            Ok(())
        }),
    ];
    for mutate in mutations {
        assert_archive_decoder_rejected(
            &bundle,
            &signing_key,
            mutate,
            pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid,
        )?;
    }

    let missing_profile = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_array(value, 3)?.retain(|member| {
            !matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text("profile/CPF1.cbor".to_owned())))
        });
        let manifest = archive_array(value, 2)?;
        let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
            return Err("archive descriptors are missing".into());
        };
        descriptors.retain(|descriptor| {
            !matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text("profile/CPF1.cbor".to_owned())))
        });
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&missing_profile),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );
    Ok(())
}

#[test]
fn public_archive_decoder_rejects_each_member_and_expected_field_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            archive_member(value, "support/normative-requirements.md")?[2] =
                Value::Integer(99_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[1] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[2] = Value::Bytes(vec![0]);
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[3] = Value::Integer(99_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[1] = Value::Integer(99_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[2] = Value::Bytes(vec![0]);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[3] = Value::Integer(99_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[4] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[5] = Value::Bytes(vec![0]);
            Ok(())
        }),
    ];
    for mutate in mutations {
        assert_archive_decoder_rejected(
            &bundle,
            &signing_key,
            mutate,
            pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid,
        )?;
    }
    let mut invalid_utf8_magic = bundle.to_canonical_cbor()?;
    replace_first_byte(&mut invalid_utf8_magic, b'C', &[0xff])?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&invalid_utf8_magic),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    assert_eq!(
        pos_conformance::verify_archive_independently(&invalid_utf8_magic),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );
    assert_post_signed_archive_decoder_rejected(&bundle, &signing_key, |value| {
        top_fields(value)?[4] = Value::Bytes(vec![0]);
        Ok(())
    })?;
    assert_post_signed_archive_decoder_rejected(&bundle, &signing_key, |value| {
        top_fields(value)?[5] = Value::Bytes(vec![0]);
        Ok(())
    })?;
    Ok(())
}

fn assert_expected_scalar_bound_mismatches(bundle: &ConformanceBundleV1) {
    let mut wrong_mode = bundle.clone();
    wrong_mode.manifest.expected_results[0].mode = BundleModeV1::AirGapped;
    assert_eq!(
        wrong_mode.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut zero_digest = bundle.clone();
    zero_digest.manifest.expected_results[0].digest = [0; 32];
    assert_eq!(
        zero_digest.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut wrong_digest = bundle.clone();
    wrong_digest.manifest.expected_results[0].digest = [1; 32];
    assert_eq!(
        wrong_digest.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut missing_fixture = bundle.clone();
    "missing-fixture".clone_into(&mut missing_fixture.manifest.expected_results[0].case_id);
    assert_eq!(
        missing_fixture.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );
}

fn assert_expected_member_bound_mismatches(
    bundle: &ConformanceBundleV1,
    expected_member_index: usize,
    expected_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut missing_member = bundle.clone();
    missing_member.members.remove(expected_member_index);
    missing_member
        .manifest
        .members
        .retain(|descriptor| descriptor.path != expected_path);
    assert_eq!(
        missing_member.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let mut empty_member = bundle.clone();
    empty_member.members[expected_member_index].bytes.clear();
    let empty_digest = *blake3::hash(&[]).as_bytes();
    empty_member.members[expected_member_index].digest = empty_digest;
    let descriptor = empty_member
        .manifest
        .members
        .iter_mut()
        .find(|descriptor| descriptor.path == expected_path)
        .ok_or("expected-result descriptor is missing")?;
    descriptor.size_bytes = 0;
    descriptor.digest = empty_digest;
    assert_eq!(
        empty_member.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let replacement_path = "expected/alternate.bin".to_owned();
    let mut undeclared_path = bundle.clone();
    replacement_path.clone_into(&mut undeclared_path.members[expected_member_index].path);
    replacement_path.clone_into(&mut undeclared_path.manifest.members[expected_member_index].path);
    undeclared_path.manifest.expected_results[0].member_path = replacement_path;
    undeclared_path
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    undeclared_path
        .manifest
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    assert_eq!(
        undeclared_path.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );
    Ok(())
}

fn assert_expected_order_mismatch(bundle: ConformanceBundleV1, expected_member_index: usize) {
    let expected_member = bundle.members[expected_member_index].clone();
    let duplicate_path = "expected/duplicate.bin".to_owned();
    let duplicate_member =
        BundleMemberV1::expected_result(duplicate_path.clone(), expected_member.bytes);
    let duplicate_descriptor = BundleMemberDescriptorV1 {
        path: duplicate_path.clone(),
        size_bytes: duplicate_member.bytes.len() as u64,
        digest: duplicate_member.digest,
        role: BundleMemberRoleV1::ExpectedResult,
    };
    let mut unordered = bundle;
    unordered.members.push(duplicate_member);
    unordered.manifest.members.push(duplicate_descriptor);
    let mut duplicate_expected = unordered.manifest.expected_results[0].clone();
    duplicate_expected.member_path = duplicate_path;
    unordered.manifest.expected_results.push(duplicate_expected);
    unordered
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    unordered
        .manifest
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    unordered.manifest.expected_results.sort_unstable();
    unordered.manifest.expected_results.reverse();
    assert_eq!(
        unordered.validate(),
        Err(pos_conformance::BundleContractErrorV1::NonCanonicalOrder)
    );
}

#[test]
fn public_expected_result_validation_rejects_each_bound_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let expected_member_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .ok_or("expected-result member is missing")?;
    let expected_path = bundle.members[expected_member_index].path.clone();
    assert_expected_scalar_bound_mismatches(&bundle);
    assert_expected_member_bound_mismatches(&bundle, expected_member_index, &expected_path)?;
    assert_expected_order_mismatch(bundle, expected_member_index);
    Ok(())
}

#[test]
fn public_materialization_caps_reject_bundle_shape_overflows(
) -> Result<(), Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (profile, members, expected_results) = public_bundle_inputs(&base)?;
    let input_size = profile.fixtures[0].inputs[0].size_bytes;
    let expected_size = match &profile.fixtures[0].expected {
        ExpectedResultV1::CanonicalBytes { bytes, .. } => u64::try_from(bytes.len())?,
        _ => return Err("draft fixture expected canonical bytes".into()),
    };
    let fixture_member_size = input_size.max(expected_size);
    let input_path_bytes = u16::try_from(profile.fixtures[0].inputs[0].member_id.len())?;
    let mutations: Vec<CapMutation> = vec![
        Box::new(|caps| caps.max_bundle_members = 2),
        Box::new(move |caps| caps.max_member_path_bytes = input_path_bytes),
        Box::new(move |caps| caps.max_member_bytes = fixture_member_size),
        Box::new(move |caps| caps.max_total_bundle_bytes = input_size),
    ];
    for mutate in mutations {
        let mut limited = profile.clone();
        mutate(&mut limited.evaluator_protocol.hard_caps);
        limited.profile_digest = limited.digest();
        assert_eq!(
            ConformanceBundleV1::materialize(
                &limited,
                BundleModeV1::Local,
                members.clone(),
                expected_results.clone(),
            ),
            Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn public_archive_encoder_enforces_the_encoded_bundle_cap() -> Result<(), Box<dyn std::error::Error>>
{
    let base = signed_draft_bundle()?;
    let (mut profile, members, expected_results) = public_bundle_inputs(&base)?;
    let profile_bytes = profile.to_canonical_cbor()?;
    let member_total =
        members
            .iter()
            .try_fold(u64::try_from(profile_bytes.len())?, |total, member| {
                Ok::<_, Box<dyn std::error::Error>>(total + u64::try_from(member.bytes.len())?)
            })?;
    profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = member_total + 1;
    profile.profile_digest = profile.digest();
    let bundle =
        ConformanceBundleV1::materialize(&profile, BundleModeV1::Local, members, expected_results)?
            .sign(&SigningKey::from_bytes(&[42; 32]))?;
    assert_eq!(
        bundle.to_canonical_cbor(),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_archive_accepts_each_exact_selected_cap_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let materialized = materialize_at_each_selected_cap_boundary()?;
    assert!(!materialized.members.is_empty());
    let archive = archive_at_each_selected_cap_boundary()?;
    assert!(ConformanceBundleV1::from_canonical_cbor(&archive).is_ok());
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Ok(())
    );

    let coordinate = vec![b'x'; 128];
    let divergence = public_expected_variant_bundle(
        BundleModeV1::AirGapped,
        ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::Artifact,
            first_coordinate: coordinate.clone(),
        },
        VerificationOutcomeV1::Diverged,
        None,
        vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::Artifact,
            first_coordinate: coordinate,
        }],
    )?;
    let divergence_archive = divergence.to_canonical_cbor()?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&divergence_archive),
        Ok(divergence)
    );
    assert_eq!(
        pos_conformance::verify_archive_independently(&divergence_archive),
        Ok(())
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_each_zero_archive_cap(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    for cap_index in [1_usize, 2, 3, 4, 6, 7] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile(value, |fields| {
                if let Some(Value::Array(protocol)) = fields.get_mut(11) {
                    if let Some(Value::Array(caps)) = protocol.get_mut(4) {
                        caps[cap_index] = Value::Integer(0_u64.into());
                    }
                }
            })
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn public_archive_decoders_enforce_selected_caps_at_their_validation_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    for cap_index in [0_usize, 2, 3, 4, 5] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile_and_rebind_identity(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[cap_index] = Value::Integer(1_u64.into());
                    }
                }
            })
        })?;
        let typed_error = if cap_index == 2 {
            pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid
        } else {
            pos_conformance::BundleContractErrorV1::ProfileInvalid
        };
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&archive),
            Err(typed_error)
        );
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_cross_field_cpf1_bound_violations(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            archive_array(value, 2)?[3] = Value::Bytes(vec![0; 32]);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[0] = Value::Text("missing-fixture".to_owned());
            Ok(())
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[9] = Value::Integer(99_u64.into());
                fixture[10] = Value::Null;
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[5] = Value::Integer(1_u64.into());
                    }
                }
            })
        }),
        Box::new(|value| duplicate_first_fixture_with_cap(value, 1, 1)),
        Box::new(|value| duplicate_first_fixture_with_cap(value, 2, 1)),
    ];
    for mutate in mutations {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert!(pos_conformance::verify_archive_independently(&archive).is_err());
    }
    Ok(())
}

fn duplicate_first_fixture_with_cap(
    value: &mut Value,
    cap_index: usize,
    cap_value: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    mutate_profile(value, |fields| {
        if let Value::Array(fixtures) = &mut fields[9] {
            let mut duplicate = fixtures[0].clone();
            if let Value::Array(fixture) = &mut duplicate {
                fixture[0] = Value::Text("ART-002".to_owned());
                fixture[1] = Value::Bool(false);
                fixture[7] = Value::Array(Vec::new());
            }
            fixtures.push(duplicate);
        }
        if let Value::Array(protocol) = &mut fields[11] {
            if let Value::Array(caps) = &mut protocol[4] {
                caps[cap_index] = Value::Integer(cap_value.into());
            }
        }
    })
}

#[test]
fn public_independent_verifier_reaches_rebound_cpf1_case_cap(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let archive = signed_archive_variant(&bundle, &signing_key, |value| {
        duplicate_first_fixture_with_cap(value, 1, 1)?;
        mutate_profile_and_rebind_identity(value, |_| {})
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn public_draft_authority_records_reject_each_malformed_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    reject_malformed_inventory_records(&bundle)?;
    reject_malformed_provenance_records(&bundle)?;
    reject_malformed_matrix_records(&bundle)
}

fn reject_malformed_inventory_records(
    bundle: &ConformanceBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_cases: Vec<JsonMutation> = vec![
        Box::new(|value| value["magic"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["magic"] = JsonValue::Null),
        Box::new(|value| value["version"] = JsonValue::Number(2_u64.into())),
        Box::new(|value| value["version"] = JsonValue::Null),
        Box::new(|value| value["lifecycle"] = JsonValue::String("Stable".to_owned())),
        Box::new(|value| value["lifecycle"] = JsonValue::Null),
        Box::new(|value| value["digest_algorithm"] = JsonValue::String("SHA-256".to_owned())),
        Box::new(|value| value["digest_algorithm"] = JsonValue::Null),
        Box::new(|value| value["entries"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| {
            value["entries"][0]["materialization_status"] =
                JsonValue::String("materialized".to_owned());
        }),
        Box::new(|value| {
            value["entries"][0]["fixture_bytes_path"] = JsonValue::String("x".to_owned());
        }),
        Box::new(|value| {
            value["entries"][0]["fixture_bytes_digest"] = JsonValue::String("x".to_owned());
        }),
        Box::new(|value| {
            value["entries"][0]["expected_result_path"] = JsonValue::String("x".to_owned());
        }),
        Box::new(|value| {
            value["entries"][0]["expected_result_digest"] = JsonValue::String("x".to_owned());
        }),
        Box::new(|value| {
            let duplicate = value["entries"][1]["fixture_id"].clone();
            value["entries"][0]["fixture_id"] = duplicate;
        }),
        Box::new(|value| {
            let _ = value
                .as_object_mut()
                .and_then(|fields| fields.remove("magic"));
        }),
        Box::new(|value| {
            let _ = value["entries"][0]
                .as_object_mut()
                .and_then(|fields| fields.remove("fixture_id"));
        }),
    ];
    for (index, mutate) in inventory_cases.into_iter().enumerate() {
        assert_json_member_rejected(
            bundle,
            "authority/expected-authority-inventory.json",
            mutate,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
            &format!("inventory case {index}"),
        )?;
    }
    assert_json_member_rejected(
        bundle,
        "authority/expected-authority-inventory.json",
        |value| {
            let _ = value["entries"].as_array_mut().map(Vec::pop);
        },
        pos_conformance::BundleContractErrorV1::MemberMissing,
        "inventory entries length",
    )?;
    assert_json_member_rejected(
        bundle,
        "authority/expected-authority-inventory.json",
        |value| value["entries"] = JsonValue::Null,
        pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
        "inventory entries shape",
    )?;
    for (label, mutate) in [
        (
            "inventory undeclared root key",
            Box::new(|value: &mut JsonValue| {
                value["candidate_evidence"] = JsonValue::Bool(true);
            }) as JsonMutation,
        ),
        (
            "inventory undeclared entry key",
            Box::new(|value: &mut JsonValue| {
                value["entries"][0]["candidate_evidence"] = JsonValue::Bool(true);
            }) as JsonMutation,
        ),
    ] {
        assert_json_member_rejected(
            bundle,
            "authority/expected-authority-inventory.json",
            mutate,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
            label,
        )?;
    }

    Ok(())
}

fn reject_malformed_provenance_records(
    bundle: &ConformanceBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let provenance_cases: Vec<JsonMutation> = vec![
        Box::new(|value| value["authority_inventory"] = JsonValue::Null),
        Box::new(|value| value["adr_059_execution_matrix"] = JsonValue::Null),
        Box::new(|value| value["authority_inventory"]["sha256_digest"] = JsonValue::Null),
        Box::new(|value| {
            value["authority_inventory"]["sha256_digest"] =
                JsonValue::String("not-a-digest".to_owned());
        }),
        Box::new(|value| {
            value["authority_inventory"]["sha256_digest"] = JsonValue::String("00".repeat(32));
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["blake3_digest"] = JsonValue::Null;
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["blake3_digest"] =
                JsonValue::String("not-a-digest".to_owned());
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["blake3_digest"] = JsonValue::String("00".repeat(32));
        }),
        Box::new(|value| {
            value["authority_inventory"]["path"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["authority_inventory"]["digest_algorithm"] =
                JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["authority_inventory"]["status"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["path"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["digest_algorithm"] =
                JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["status"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["adr_059_execution_matrix"]["executed_case_count"] =
                JsonValue::Number(1_u64.into());
        }),
    ];
    for (index, mutate) in provenance_cases.into_iter().enumerate() {
        assert_json_member_rejected(
            bundle,
            "support/provenance.json",
            mutate,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
            &format!("provenance inventory digest case {index}"),
        )?;
    }
    Ok(())
}

fn malformed_matrix_records() -> Vec<JsonMutation> {
    vec![
        Box::new(|value| value["magic"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["magic"] = JsonValue::Null),
        Box::new(|value| value["version"] = JsonValue::Number(2_u64.into())),
        Box::new(|value| value["version"] = JsonValue::Null),
        Box::new(|value| value["lifecycle"] = JsonValue::String("Candidate".to_owned())),
        Box::new(|value| value["lifecycle"] = JsonValue::Null),
        Box::new(|value| value["row_count"] = JsonValue::Number(11_u64.into())),
        Box::new(|value| value["variant_count"] = JsonValue::Number(3_u64.into())),
        Box::new(|value| value["mode_count"] = JsonValue::Number(3_u64.into())),
        Box::new(|value| value["case_count"] = JsonValue::Number(191_u64.into())),
        Box::new(|value| value["executed_case_count"] = JsonValue::Number(1_u64.into())),
        Box::new(|value| value["rows"] = JsonValue::Null),
        Box::new(|value| value["cases"] = JsonValue::Null),
        Box::new(|value| value["rows"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["rows"][0]["variants"] = JsonValue::Null),
        Box::new(|value| value["rows"][0]["variants"] = JsonValue::Array(Vec::new())),
        Box::new(|value| value["rows"][0]["modes"] = JsonValue::Array(Vec::new())),
        Box::new(|value| value["rows"][0]["case_count"] = JsonValue::Number(15_u64.into())),
        Box::new(|value| value["rows"][0]["executed_case_count"] = JsonValue::Number(1_u64.into())),
        Box::new(|value| {
            let _ = value["rows"][0]
                .as_object_mut()
                .and_then(|fields| fields.remove("fixture_id"));
        }),
        Box::new(|value| {
            let _ = value["rows"].as_array_mut().map(Vec::pop);
        }),
        Box::new(|value| value["cases"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["variant"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["mode"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["case_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| {
            let _ = value["cases"].as_array_mut().map(Vec::pop);
        }),
        Box::new(|value| value["cases"][0]["executed"] = JsonValue::Bool(true)),
        Box::new(|value| value["cases"][0]["executed"] = JsonValue::Null),
        Box::new(|value| {
            value["cases"][0]["expected_result_digest"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["cases"][0]["authority_fixture_id"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["cases"][0]["authority_result_digest"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["cases"][0]["expected_result"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| value["equality_predicates"] = JsonValue::Null),
        Box::new(|value| {
            let _ = value["equality_predicates"].as_array_mut().map(Vec::pop);
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["fixture_id"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["AuthEq"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["PublicEq"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            value["equality_predicates"][0]["OpEq"] = JsonValue::String("wrong".to_owned());
        }),
        Box::new(|value| {
            let _ = value["cases"][0]
                .as_object_mut()
                .and_then(|fields| fields.remove("case_id"));
        }),
        Box::new(|value| {
            let _ = value["equality_predicates"][0]
                .as_object_mut()
                .and_then(|fields| fields.remove("fixture_id"));
        }),
    ]
}

fn reject_malformed_matrix_records(
    bundle: &ConformanceBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, mutate) in malformed_matrix_records().into_iter().enumerate() {
        assert_json_member_rejected(
            bundle,
            "authority/execution-matrix.json",
            mutate,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
            &format!("matrix case {index}"),
        )?;
    }
    for (label, mutate) in [
        (
            "matrix undeclared root key",
            Box::new(|value: &mut JsonValue| {
                value["candidate_evidence"] = JsonValue::Bool(true);
            }) as JsonMutation,
        ),
        (
            "matrix row undeclared key",
            Box::new(|value: &mut JsonValue| {
                value["rows"][0]["candidate_evidence"] = JsonValue::Bool(true);
            }) as JsonMutation,
        ),
        (
            "matrix case undeclared key",
            Box::new(|value: &mut JsonValue| {
                value["cases"][0]["candidate_evidence"] = JsonValue::Bool(true);
            }) as JsonMutation,
        ),
        (
            "matrix predicate undeclared key",
            Box::new(|value: &mut JsonValue| {
                value["equality_predicates"][0]["candidate_evidence"] = JsonValue::Bool(true);
            }) as JsonMutation,
        ),
    ] {
        assert_json_member_rejected(
            bundle,
            "authority/execution-matrix.json",
            mutate,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
            label,
        )?;
    }
    Ok(())
}

fn rebind_archive_profile(
    value: &mut Value,
    profile: &ConformanceProfileV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_bytes = profile.to_canonical_cbor()?;
    archive_member(value, "profile/CPF1.cbor")?[1] = Value::Bytes(profile_bytes.clone());
    let descriptor = archive_descriptor(value, "profile/CPF1.cbor")?;
    descriptor[1] = Value::Integer(u64::try_from(profile_bytes.len())?.into());
    descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
    archive_array(value, 2)?[3] = Value::Bytes(profile.profile_digest.to_vec());
    Ok(())
}

fn archive_with_public_profile(
    bundle: &ConformanceBundleV1,
    profile: &ConformanceProfileV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        rebind_archive_profile(value, profile)
    })
}

fn expected_member_bytes(
    expected: &ExpectedResultV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match expected {
        ExpectedResultV1::CanonicalBytes { bytes, .. } => Ok(bytes.clone()),
        ExpectedResultV1::TypedFailure(_) | ExpectedResultV1::AllowedDivergence { .. } => {
            Ok(expected.to_canonical_bytes()?)
        }
    }
}

fn assert_expected_member_matches_profile_wire(
    bundle: &ConformanceBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_bytes = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::Profile)
        .map(|member| member.bytes.as_slice())
        .ok_or("profile member is missing")?;
    let profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
    let Value::Array(profile) = profile else {
        return Err("profile is not an array".into());
    };
    let Some(Value::Array(fixtures)) = profile.get(9) else {
        return Err("profile fixtures are missing".into());
    };
    let Some(Value::Array(fixture)) = fixtures.first() else {
        return Err("profile fixture is missing".into());
    };
    let profile_expected = fixture.get(8).ok_or("profile expected result is missing")?;
    let member_bytes = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .map(|member| member.bytes.as_slice())
        .ok_or("expected-result member is missing")?;
    let Value::Array(expected_fields) = profile_expected else {
        return Err("profile expected result is not an array".into());
    };
    if expected_fields.first() == Some(&Value::Integer(0_u64.into())) {
        let Some(Value::Bytes(expected_bytes)) = expected_fields.get(1) else {
            return Err("canonical expected bytes are missing".into());
        };
        assert_eq!(member_bytes, expected_bytes);
    } else {
        let member_expected: Value = ciborium::from_reader(Cursor::new(member_bytes))?;
        assert_eq!(&member_expected, profile_expected);
    }
    Ok(())
}

fn rebind_first_expected_result(
    profile: &ConformanceProfileV1,
    members: &mut [BundleMemberV1],
    expected_results: &mut [BundleExpectedResultV1],
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = profile
        .fixtures
        .first()
        .ok_or("profile fixture is missing")?;
    let path = expected_result_member_path(
        &fixture.case_id,
        fixture.claim_layer,
        &fixture.execution_profile_digest,
    );
    let bytes = expected_member_bytes(&fixture.expected)?;
    let digest = *blake3::hash(&bytes).as_bytes();
    let member = members
        .iter_mut()
        .find(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .ok_or("expected-result member is missing")?;
    *member = BundleMemberV1::expected_result(path.clone(), bytes);
    let expected = expected_results
        .first_mut()
        .ok_or("expected-result record is missing")?;
    expected.case_id.clone_from(&fixture.case_id);
    expected.claim_layer = fixture.claim_layer;
    expected.execution_profile_digest = fixture.execution_profile_digest;
    expected.member_path = path;
    expected.digest = digest;
    Ok(())
}

fn public_expected_variant_bundle(
    mode: BundleModeV1,
    expected: ExpectedResultV1,
    outcome: VerificationOutcomeV1,
    expected_error: Option<SafeErrorCodeV1>,
    allowed_divergences: Vec<AllowedDivergenceV1>,
) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (mut profile, mut members, mut expected_results) = public_bundle_inputs(&base)?;
    let fixture = profile
        .fixtures
        .first_mut()
        .ok_or("profile fixture is missing")?;
    fixture.modes = vec![
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Fork,
    ];
    fixture.expected = expected;
    fixture.expected_verification_outcome = outcome;
    fixture.expected_verification_error = expected_error;
    profile.allowed_divergences = allowed_divergences;
    rebind_first_expected_result(&profile, &mut members, &mut expected_results)?;
    expected_results[0].mode = mode;
    profile.profile_digest = profile.digest();
    Ok(
        ConformanceBundleV1::materialize(&profile, mode, members, expected_results)?
            .sign(&SigningKey::from_bytes(&[42; 32]))?,
    )
}

fn public_claim_variant_bundle(
    replay_claim: ReplayClaimV1,
    redaction_state: RedactionStateV1,
) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (mut profile, mut members, mut expected_results) = public_bundle_inputs(&base)?;
    let fixture = profile
        .fixtures
        .first_mut()
        .ok_or("profile fixture is missing")?;
    fixture.replay_claim = replay_claim;
    fixture.redaction_state = redaction_state;
    rebind_first_expected_result(&profile, &mut members, &mut expected_results)?;
    profile.profile_digest = profile.digest();
    Ok(
        ConformanceBundleV1::materialize(&profile, BundleModeV1::Local, members, expected_results)?
            .sign(&SigningKey::from_bytes(&[42; 32]))?,
    )
}

fn public_mode_pair() -> Result<ConformanceBundlePairV1, Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (mut profile, members, expected_results) = public_bundle_inputs(&base)?;
    profile.fixtures[0].modes = vec![
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Fork,
    ];
    profile.profile_digest = profile.digest();
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let local = ConformanceBundleV1::materialize(
        &profile,
        BundleModeV1::Local,
        members.clone(),
        expected_results.clone(),
    )?
    .sign(&signing_key)?;
    let mut air_gapped_results = expected_results;
    air_gapped_results[0].mode = BundleModeV1::AirGapped;
    let air_gapped = ConformanceBundleV1::materialize(
        &profile,
        BundleModeV1::AirGapped,
        members,
        air_gapped_results,
    )?
    .sign(&signing_key)?;
    Ok(ConformanceBundlePairV1 { local, air_gapped })
}

fn public_optional_result_pair() -> Result<ConformanceBundlePairV1, Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (mut profile, members, expected_results) = public_bundle_inputs(&base)?;
    profile.fixtures[0].mandatory = false;
    profile.fixtures[0].modes = vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped];
    profile.profile_digest = profile.digest();
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let local = ConformanceBundleV1::materialize(
        &profile,
        BundleModeV1::Local,
        members.clone(),
        expected_results,
    )?
    .sign(&signing_key)?;
    let air_gapped_members = members
        .into_iter()
        .filter(|member| member.role != BundleMemberRoleV1::ExpectedResult)
        .collect();
    let air_gapped = ConformanceBundleV1::materialize(
        &profile,
        BundleModeV1::AirGapped,
        air_gapped_members,
        Vec::new(),
    )?
    .sign(&signing_key)?;
    Ok(ConformanceBundlePairV1 { local, air_gapped })
}

#[test]
fn public_expected_result_variants_round_trip_through_independent_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bundles = vec![public_expected_variant_bundle(
        BundleModeV1::Local,
        ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete),
        VerificationOutcomeV1::InvalidManifest,
        Some(SafeErrorCodeV1::ClosureIncomplete),
        Vec::new(),
    )?];
    for outcome in [
        VerificationOutcomeV1::IncompatibleProfile,
        VerificationOutcomeV1::ResourceLimitExceeded,
    ] {
        bundles.push(public_expected_variant_bundle(
            BundleModeV1::Local,
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete),
            outcome,
            Some(SafeErrorCodeV1::ClosureIncomplete),
            Vec::new(),
        )?);
    }
    bundles.push(public_expected_variant_bundle(
        BundleModeV1::Local,
        ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ProvenanceMissing),
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        Some(SafeErrorCodeV1::ProvenanceMissing),
        Vec::new(),
    )?);
    let base = signed_draft_bundle()?;
    let (profile, _, _) = public_bundle_inputs(&base)?;
    bundles.push(public_expected_variant_bundle(
        BundleModeV1::Local,
        profile.fixtures[0].expected.clone(),
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        Some(SafeErrorCodeV1::ProvenanceMissing),
        Vec::new(),
    )?);
    let coordinate = b"/public/result/0".to_vec();
    bundles.push(public_expected_variant_bundle(
        BundleModeV1::AirGapped,
        ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::Artifact,
            first_coordinate: coordinate.clone(),
        },
        VerificationOutcomeV1::Diverged,
        None,
        vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::Artifact,
            first_coordinate: coordinate,
        }],
    )?);

    let mut wrong_typed_digest = bundles[0].clone();
    wrong_typed_digest.manifest.expected_results[0].digest = [99; 32];
    assert_eq!(
        wrong_typed_digest.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut wrong_typed_bytes = bundles[0].clone();
    let expected_member_index = wrong_typed_bytes
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .ok_or("expected-result member is missing")?;
    replace_member_bytes(
        &mut wrong_typed_bytes,
        expected_member_index,
        b"different typed result".to_vec(),
    )?;
    wrong_typed_bytes.manifest.expected_results[0].digest =
        wrong_typed_bytes.members[expected_member_index].digest;
    assert_eq!(
        wrong_typed_bytes.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    for bundle in bundles {
        let archive = bundle.to_canonical_cbor()?;
        assert_expected_member_matches_profile_wire(&bundle)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Ok(())
        );
        assert_eq!(ConformanceBundleV1::from_canonical_cbor(&archive)?, bundle);
    }
    Ok(())
}

#[test]
fn public_replay_claim_redaction_pairs_reach_independent_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    for (claim, redaction) in [
        (ReplayClaimV1::Exact, RedactionStateV1::None),
        (
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            RedactionStateV1::RedactedViews,
        ),
        (
            ReplayClaimV1::StructuralOnly,
            RedactionStateV1::StructuralOnly,
        ),
        (
            ReplayClaimV1::UnverifiableArtifactsMissing,
            RedactionStateV1::EvidenceMissing,
        ),
        (ReplayClaimV1::IncompatibleProfile, RedactionStateV1::None),
    ] {
        let bundle = public_claim_variant_bundle(claim, redaction)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&bundle.to_canonical_cbor()?),
            Ok(())
        );
    }
    Ok(())
}

#[test]
fn public_materialization_and_decoder_cover_each_lifecycle_variant(
) -> Result<(), Box<dyn std::error::Error>> {
    let base = signed_draft_bundle()?;
    let (profile, members, expected_results) = public_bundle_inputs(&base)?;
    for lifecycle in [
        ProfileLifecycleV1::Candidate,
        ProfileLifecycleV1::Stable,
        ProfileLifecycleV1::Retired,
    ] {
        let mut changed_profile = profile.clone();
        changed_profile.lifecycle = lifecycle;
        changed_profile.profile_digest = changed_profile.digest();
        assert_eq!(
            ConformanceBundleV1::materialize(
                &changed_profile,
                BundleModeV1::Local,
                members.clone(),
                expected_results.clone(),
            ),
            Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
        );
    }

    let signing_key = SigningKey::from_bytes(&[42; 32]);
    for lifecycle_code in 1_u64..=3 {
        let archive = signed_archive_variant(&base, &signing_key, |value| {
            archive_array(value, 2)?[1] = Value::Integer(lifecycle_code.into());
            Ok(())
        })?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&archive),
            Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
        );
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
        );
    }
    Ok(())
}

#[test]
fn public_bundle_descriptor_and_profile_bindings_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let profile_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("profile member is missing")?;
    let support_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::NormativeSpecification)
        .ok_or("normative member is missing")?;

    let mut profile_digest_mismatch = bundle.clone();
    profile_digest_mismatch.manifest.profile_digest = [99; 32];
    assert_eq!(
        profile_digest_mismatch.validate(),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );

    for (mutate, expected) in [
        (
            Box::new(move |value: &mut ConformanceBundleV1| {
                value.manifest.members[support_index].size_bytes += 1;
            }) as Box<dyn Fn(&mut ConformanceBundleV1)>,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
        ),
        (
            Box::new(move |value: &mut ConformanceBundleV1| {
                value.manifest.members[support_index].digest = [99; 32];
            }),
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
        ),
        (
            Box::new(move |value: &mut ConformanceBundleV1| {
                value.manifest.members[support_index].role = BundleMemberRoleV1::Schema;
            }),
            pos_conformance::BundleContractErrorV1::UndeclaredMember,
        ),
    ] {
        let mut changed = bundle.clone();
        mutate(&mut changed);
        assert_eq!(changed.validate(), Err(expected));
    }

    let mut missing_profile = bundle.clone();
    missing_profile.members.remove(profile_index);
    missing_profile.manifest.members.remove(profile_index);
    assert_eq!(
        missing_profile.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let mut renamed_profile = bundle.clone();
    renamed_profile.members[profile_index].path = "profile/not-cpf1.cbor".to_owned();
    renamed_profile.manifest.members[profile_index].path = "profile/not-cpf1.cbor".to_owned();
    assert_eq!(
        renamed_profile.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let mut unordered_members = bundle.clone();
    unordered_members.members.swap(0, 1);
    assert_eq!(
        unordered_members.validate(),
        Err(pos_conformance::BundleContractErrorV1::NonCanonicalOrder)
    );
    let mut unordered_descriptors = bundle;
    unordered_descriptors.manifest.members.swap(0, 1);
    assert_eq!(
        unordered_descriptors.validate(),
        Err(pos_conformance::BundleContractErrorV1::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn public_independent_member_records_bind_order_digest_and_profile_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;

    let unordered = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_array(value, 3)?.swap(0, 1);
        let manifest = archive_array(value, 2)?;
        let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
            return Err("archive descriptors are missing".into());
        };
        descriptors.swap(0, 1);
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&unordered),
        Err(pos_conformance::BundleContractErrorV1::NonCanonicalOrder)
    );

    let stale_digest = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_descriptor(value, "support/normative-requirements.md")?[2] =
            Value::Bytes(vec![99; 32]);
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&stale_digest),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let wrong_profile_path = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_member(value, "profile/CPF1.cbor")?[0] =
            Value::Text("profile/not-cpf1.cbor".to_owned());
        archive_descriptor(value, "profile/CPF1.cbor")?[0] =
            Value::Text("profile/not-cpf1.cbor".to_owned());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&wrong_profile_path),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );

    let profile_manifest_mismatch = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_array(value, 2)?[3] = Value::Bytes(vec![99; 32]);
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&profile_manifest_mismatch),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

fn unreferenced_mandatory_profile(
    profile: &ConformanceProfileV1,
) -> Result<ConformanceProfileV1, Box<dyn std::error::Error>> {
    let mut changed = profile.clone();
    let mut fixture = changed
        .fixtures
        .first()
        .cloned()
        .ok_or("profile fixture is missing")?;
    "ZZZ-UNREFERENCED".clone_into(&mut fixture.case_id);
    fixture.inputs.clear();
    fixture.mandatory = true;
    fixture.modes = vec![ExecutionModeV1::Local];
    changed.fixtures.push(fixture);
    changed.fixtures.sort_by_key(|fixture| {
        (
            fixture.case_id.clone(),
            fixture.claim_layer,
            fixture.execution_profile_digest,
        )
    });
    changed.profile_digest = changed.digest();
    Ok(changed)
}

#[test]
fn public_mandatory_fixture_identity_requires_an_expected_result(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let (profile, members, expected_results) = public_bundle_inputs(&bundle)?;
    let changed = unreferenced_mandatory_profile(&profile)?;
    assert_eq!(
        ConformanceBundleV1::materialize(&changed, BundleModeV1::Local, members, expected_results,),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );
    let archive = archive_with_public_profile(&bundle, &changed, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );
    Ok(())
}

#[test]
fn public_fixture_input_bindings_cover_size_digest_presence_and_declaration(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let (profile, _, _) = public_bundle_inputs(&bundle)?;

    let mut wrong_size = profile.clone();
    wrong_size.fixtures[0].inputs[0].size_bytes += 1;
    wrong_size.profile_digest = wrong_size.digest();
    let archive = archive_with_public_profile(&bundle, &wrong_size, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut wrong_digest = profile.clone();
    wrong_digest.fixtures[0].inputs[0].digest = [99; 32];
    wrong_digest.profile_digest = wrong_digest.digest();
    let archive = archive_with_public_profile(&bundle, &wrong_digest, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut undeclared_member = profile.clone();
    undeclared_member.fixtures[0].inputs.clear();
    undeclared_member.profile_digest = undeclared_member.digest();
    let archive = archive_with_public_profile(&bundle, &undeclared_member, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );

    let mut missing_member = profile;
    let provenance_digest = missing_member.fixtures[0].inputs[0].provenance_digest;
    missing_member.fixtures[0]
        .inputs
        .push(FixtureInputMemberV1 {
            member_id: "missing.json".to_owned(),
            size_bytes: 1,
            digest: [98; 32],
            provenance_digest,
        });
    missing_member.profile_digest = missing_member.digest();
    let archive = archive_with_public_profile(&bundle, &missing_member, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );
    Ok(())
}

#[test]
fn public_independent_fixture_input_rejects_empty_bound_member(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let input_path = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::FixtureInput)
        .map(|member| member.path.clone())
        .ok_or("fixture input is missing")?;
    let archive = signed_archive_variant(&bundle, &signing_key, |value| {
        archive_member(value, &input_path)?[1] = Value::Bytes(Vec::new());
        let descriptor = archive_descriptor(value, &input_path)?;
        descriptor[1] = Value::Integer(0_u64.into());
        descriptor[2] = Value::Bytes(blake3::hash(&[]).as_bytes().to_vec());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&archive),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

#[test]
fn public_supporting_member_bindings_cover_every_required_role(
) -> Result<(), Box<dyn std::error::Error>> {
    type ProfileMutation = Box<dyn Fn(&mut ConformanceProfileV1)>;

    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let (profile, _, _) = public_bundle_inputs(&bundle)?;
    let mutations: Vec<ProfileMutation> = vec![
        Box::new(|value| value.normative_spec_digest = [99; 32]),
        Box::new(|value| {
            value.public_schema_digests = vec![[99; 32]];
            value.fixtures[0].public_schema_digest = [99; 32];
        }),
        Box::new(|value| value.fixtures[0].provenance.licence_id = "Apache-2.0".to_owned()),
        Box::new(|value| value.fixtures[0].provenance.notices_digest = [99; 32]),
        Box::new(|value| value.fixtures[0].provenance.sbom_digest = [99; 32]),
        Box::new(|value| {
            value.provenance_digest = [99; 32];
            value.fixtures[0].provenance.source_digest = [99; 32];
            value.fixtures[0].provenance.build_digest = [99; 32];
            value.fixtures[0].provenance.publication_review_digest = [99; 32];
        }),
        Box::new(|value| {
            value.limitations_digest = [99; 32];
            value.fixtures[0].provenance.limitations_digest = [99; 32];
        }),
    ];
    for mutate in mutations {
        let mut changed = profile.clone();
        mutate(&mut changed);
        changed.profile_digest = changed.digest();
        let archive = archive_with_public_profile(&bundle, &changed, &signing_key)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
        );
    }
    Ok(())
}

fn remove_archive_member_and_descriptor(
    value: &mut Value,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let member_index = archive_array(value, 3)?
        .iter()
        .position(|member| {
            matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text(path.to_owned())))
        })
        .ok_or("archive member is missing")?;
    archive_array(value, 3)?.remove(member_index);
    let manifest = archive_array(value, 2)?;
    let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
        return Err("archive descriptors are missing".into());
    };
    let descriptor_index = descriptors
        .iter()
        .position(|descriptor| {
            matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text(path.to_owned())))
        })
        .ok_or("archive descriptor is missing")?;
    descriptors.remove(descriptor_index);
    Ok(())
}

fn duplicate_archive_member_and_descriptor(
    value: &mut Value,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let members = archive_array(value, 3)?;
    let member_index = members
        .iter()
        .position(|member| {
            matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text(path.to_owned())))
        })
        .ok_or("archive member is missing")?;
    let mut duplicate_member = members[member_index].clone();
    let Value::Array(member_fields) = &mut duplicate_member else {
        return Err("archive member is not an array".into());
    };
    member_fields[0] = Value::Text(format!("{path}x"));
    members.insert(member_index + 1, duplicate_member);

    let manifest = archive_array(value, 2)?;
    let Some(Value::Array(descriptors)) = manifest.get_mut(4) else {
        return Err("archive descriptors are missing".into());
    };
    let descriptor_index = descriptors
        .iter()
        .position(|descriptor| {
            matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text(path.to_owned())))
        })
        .ok_or("archive descriptor is missing")?;
    let mut duplicate_descriptor = descriptors[descriptor_index].clone();
    let Value::Array(descriptor_fields) = &mut duplicate_descriptor else {
        return Err("archive descriptor is not an array".into());
    };
    descriptor_fields[0] = Value::Text(format!("{path}x"));
    descriptors.insert(descriptor_index + 1, duplicate_descriptor);
    Ok(())
}

#[test]
fn public_independent_authority_slots_require_exact_members_and_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    for path in [
        AUTHORITY_INVENTORY_MEMBER_PATH,
        EXECUTION_MATRIX_MEMBER_PATH,
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            remove_archive_member_and_descriptor(value, path)
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }

    for path in [
        AUTHORITY_INVENTORY_MEMBER_PATH,
        EXECUTION_MATRIX_MEMBER_PATH,
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            duplicate_archive_member_and_descriptor(value, path)
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }

    for (path, replacement) in [
        (
            AUTHORITY_INVENTORY_MEMBER_PATH,
            "authority/expected-authority-inventoryX.json",
        ),
        (
            EXECUTION_MATRIX_MEMBER_PATH,
            "authority/execution-matrixX.json",
        ),
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            archive_member(value, path)?[0] = Value::Text(replacement.to_owned());
            archive_descriptor(value, path)?[0] = Value::Text(replacement.to_owned());
            Ok(())
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }

    for path in [
        AUTHORITY_INVENTORY_MEMBER_PATH,
        EXECUTION_MATRIX_MEMBER_PATH,
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            archive_member(value, path)?[1] = Value::Bytes(Vec::new());
            let descriptor = archive_descriptor(value, path)?;
            descriptor[1] = Value::Integer(0_u64.into());
            descriptor[2] = Value::Bytes(blake3::hash(&[]).as_bytes().to_vec());
            Ok(())
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }

    for path in [
        AUTHORITY_INVENTORY_MEMBER_PATH,
        EXECUTION_MATRIX_MEMBER_PATH,
    ] {
        let malformed = signed_archive_variant(&bundle, &signing_key, |value| {
            let bytes = b"not-json";
            archive_member(value, path)?[1] = Value::Bytes(bytes.to_vec());
            let descriptor = archive_descriptor(value, path)?;
            descriptor[1] = Value::Integer(u64::try_from(bytes.len())?.into());
            descriptor[2] = Value::Bytes(blake3::hash(bytes).as_bytes().to_vec());
            Ok(())
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&malformed),
            Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
        );
    }

    let (mut profile, _, _) = public_bundle_inputs(&bundle)?;
    profile.execution_matrix_digest = [99; 32];
    profile.profile_digest = profile.digest();
    let stale_binding = archive_with_public_profile(&bundle, &profile, &signing_key)?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&stale_binding),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

fn raw_duplicate_profile_archive() -> Vec<u8> {
    raw_archive(
        &[0x60],
        &[0x82, 0x83, 0x60, 0x40, 0x02, 0x83, 0x61, b'a', 0x40, 0x02],
    )
}

#[test]
fn public_preflight_rejects_unsafe_item_and_member_boundaries() {
    let oversized_member = raw_archive(
        &[0x60],
        &[0x81, 0x83, 0x60, 0x5a, 0x04, 0x00, 0x00, 0x01, 0x00],
    );
    let oversized_nested_array = raw_archive(&[0x9a, 0x00, 0x01, 0x00, 0x01], &[0x80]);
    let malformed_member = raw_archive(&[0x60], &[0x81, 0x82, 0x60, 0x40]);
    let member_with_byte_string_path = raw_archive(&[0x60], &[0x81, 0x83, 0x40, 0x40, 0x00]);
    let member_with_text_payload = raw_archive(&[0x60], &[0x81, 0x83, 0x60, 0x60, 0x00]);
    let member_with_text_role = raw_archive(&[0x60], &[0x81, 0x83, 0x60, 0x40, 0x60]);
    let mut excessive_nesting = vec![0x81; 32];
    excessive_nesting.push(0xf6);
    for archive in [
        oversized_member,
        oversized_nested_array,
        raw_archive(&excessive_nesting, &[0x80]),
        raw_archive(&[0x7a, 0, 0, 1, 1], &[0x80]),
    ] {
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
        );
    }
    for archive in [
        vec![0x9f],
        malformed_member,
        member_with_byte_string_path,
        member_with_text_payload,
        member_with_text_role,
        raw_archive(&[0x7f], &[0x80]),
        raw_archive(&[0xa0], &[0x80]),
        raw_archive(&[0xc0], &[0x80]),
        raw_archive(&[0xfa, 0, 0, 0, 0], &[0x80]),
        raw_archive(&[0xf7], &[0x80]),
    ] {
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }
    assert_eq!(
        pos_conformance::verify_archive_independently(&raw_duplicate_profile_archive()),
        Err(pos_conformance::BundleContractErrorV1::MemberMissing)
    );
}

#[test]
fn public_preflight_accepts_supported_scalar_widths_before_semantic_validation() {
    for first in [
        vec![0x20],
        vec![0xf4],
        vec![0xf6],
        vec![0x18, 0x17],
        vec![0x19, 0, 0x17],
        vec![0x1a, 0, 0, 0, 0x17],
        vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 0x17],
    ] {
        assert_eq!(
            pos_conformance::verify_archive_independently(&raw_archive(&first, &[0x80])),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }
}

#[test]
fn public_independent_preflight_enforces_each_profile_selected_archive_cap(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    for cap_index in [0_usize, 2, 3, 4, 5] {
        let archive = signed_archive_variant(&bundle, &signing_key, |value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[cap_index] = Value::Integer(1_u64.into());
                    }
                }
            })
        })?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }

    let shallow_profile = signed_archive_variant(&bundle, &signing_key, |value| {
        mutate_profile(value, |fields| {
            if let Value::Array(protocol) = &mut fields[11] {
                if let Value::Array(caps) = &mut protocol[4] {
                    caps[7] = Value::Integer(1_u64.into());
                }
            }
        })
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&shallow_profile),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );

    let oversized_log_cap = signed_archive_variant(&bundle, &signing_key, |value| {
        mutate_profile_and_rebind_identity(value, |fields| {
            if let Value::Array(protocol) = &mut fields[11] {
                if let Value::Array(caps) = &mut protocol[4] {
                    caps[9] = Value::Integer(1_048_577_u64.into());
                }
            }
        })
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&oversized_log_cap),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );
    Ok(())
}

fn archive_with_support_payload(
    bundle: &ConformanceBundleV1,
    signing_key: &SigningKey,
    bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_archive_variant(bundle, signing_key, |value| {
        archive_member(value, "support/normative-requirements.md")?[1] =
            Value::Bytes(bytes.to_vec());
        let descriptor = archive_descriptor(value, "support/normative-requirements.md")?;
        descriptor[1] = Value::Integer(u64::try_from(bytes.len())?.into());
        descriptor[2] = Value::Bytes(blake3::hash(bytes).as_bytes().to_vec());
        Ok(())
    })
}

#[test]
fn public_secret_detection_covers_nested_empty_digest_and_token_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    for secret in [
        br#"{"outer":[{"client-secret":1}]}"#.as_slice(),
        br#"{"token_digest":null}"#.as_slice(),
        br#"{"authorization":7}"#.as_slice(),
    ] {
        let archive = archive_with_support_payload(&bundle, &signing_key, secret)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::SecretMaterialDetected)
        );
    }
    for safe_boundary in [
        br#"{"password":null}"#.as_slice(),
        br#"{"password":""}"#.as_slice(),
        b"eyj".as_slice(),
        b"eyjshort.abcdefghij.abcdefghij".as_slice(),
        b"abcabcdefg.abcdefghij.abcdefghij".as_slice(),
        b"eyjabcdefg.short.abcdefghij".as_slice(),
        b"eyjabcdefg.abcdefghij.short".as_slice(),
    ] {
        let archive = archive_with_support_payload(&bundle, &signing_key, safe_boundary)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
        );
    }
    Ok(())
}

#[test]
fn public_air_gapped_profile_rejects_network_authority_before_materialization(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let (mut profile, members, mut expected_results) = public_bundle_inputs(&bundle)?;
    profile.fixtures[0].modes = vec![ExecutionModeV1::AirGapped];
    profile.fixtures[0].capability_policy.network_allowed = true;
    profile.profile_digest = profile.digest();
    expected_results[0].mode = BundleModeV1::AirGapped;
    assert_eq!(
        ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::AirGapped,
            members,
            expected_results,
        ),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn public_pair_validation_covers_modes_and_member_path_guards(
) -> Result<(), Box<dyn std::error::Error>> {
    let pair = public_mode_pair()?;
    assert_eq!(pair.validate(), Ok(()));
    for changed in [
        ConformanceBundlePairV1 {
            local: pair.air_gapped.clone(),
            air_gapped: pair.air_gapped.clone(),
        },
        ConformanceBundlePairV1 {
            local: pair.local.clone(),
            air_gapped: pair.local.clone(),
        },
    ] {
        assert_eq!(
            changed.validate(),
            Err(pos_conformance::BundleContractErrorV1::ModeParityMismatch)
        );
    }

    let mut changed_path = pair;
    let expected_index = changed_path
        .air_gapped
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .ok_or("expected-result member is missing")?;
    changed_path.air_gapped.members[expected_index].path = "expected/alternate.bin".to_owned();
    assert_eq!(
        changed_path.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );

    let optional_result_pair = public_optional_result_pair()?;
    let different_profile_pair = ConformanceBundlePairV1 {
        local: public_mode_pair()?.local,
        air_gapped: optional_result_pair.air_gapped.clone(),
    };
    assert_eq!(different_profile_pair.local.validate(), Ok(()));
    assert_eq!(different_profile_pair.air_gapped.validate(), Ok(()));
    assert_eq!(
        different_profile_pair.validate(),
        Err(pos_conformance::BundleContractErrorV1::ModeParityMismatch)
    );
    assert_eq!(optional_result_pair.local.validate(), Ok(()));
    assert_eq!(optional_result_pair.air_gapped.validate(), Ok(()));
    assert_eq!(
        optional_result_pair.validate(),
        Err(pos_conformance::BundleContractErrorV1::ModeParityMismatch)
    );
    Ok(())
}

#[test]
fn public_archive_decoder_rejects_noncanonical_archive_and_manifest_matrix(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mut noncanonical = signed_archive_variant(&bundle, &signing_key, |_| Ok(()))?;
    make_cfb1_version_noncanonical(&mut noncanonical)?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&noncanonical),
        Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
    );

    for (mutate, expected) in [
        (
            Box::new(|value: &mut Value| {
                archive_descriptor(value, "profile/CPF1.cbor")?[1] = Value::Integer(0_u64.into());
                Ok(())
            }) as ArchiveMutation,
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
        ),
        (
            Box::new(|value: &mut Value| {
                archive_descriptor(value, "profile/CPF1.cbor")?[2] = Value::Bytes(vec![99; 32]);
                Ok(())
            }),
            pos_conformance::BundleContractErrorV1::MemberDigestMismatch,
        ),
        (
            Box::new(|value: &mut Value| {
                archive_descriptor(value, "profile/CPF1.cbor")?[3] = Value::Integer(3_u64.into());
                Ok(())
            }),
            pos_conformance::BundleContractErrorV1::UndeclaredMember,
        ),
    ] {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&archive),
            Err(expected)
        );
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(expected)
        );
    }
    Ok(())
}

fn second_batch_profile_root_type_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| mutate_profile(value, |fields| fields[5] = Value::Text("digest".into()))),
        Box::new(|value| {
            mutate_profile(value, |fields| fields[7] = Value::Text("profiles".into()))
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[7] {
                    digests[0] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[8] = Value::Text("schemas".into()))),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(digests) = &mut fields[8] {
                    digests[0] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[10] = Value::Text("divergences".into());
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[10] = Value::Array(vec![Value::Text("record".into())]);
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[10] = Value::Array(vec![Value::Array(vec![
                    Value::Integer(0_u64.into()),
                    Value::Text("coordinate".into()),
                ])]);
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| fields[11] = Value::Text("protocol".into()))
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[1] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    protocol[4] = Value::Text("caps".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(protocol) = &mut fields[11] {
                    if let Value::Array(caps) = &mut protocol[4] {
                        caps[0] = Value::Text("cap".into());
                    }
                }
            })
        }),
    ]
}

fn second_batch_profile_authority_type_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[12] = Value::Text("requirements".into());
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[12] = Value::Array(vec![Value::Bool(true); 4]);
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[3] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(requirements) = &mut fields[12] {
                    requirements[4] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[13] = Value::Text("digest".into()))),
        Box::new(|value| mutate_profile(value, |fields| fields[14] = Value::Text("digest".into()))),
        Box::new(|value| mutate_profile(value, |fields| fields[15] = Value::Text("digest".into()))),
        Box::new(|value| mutate_profile(value, |fields| fields[17] = Value::Text("digest".into()))),
    ]
}

fn second_batch_fixture_identity_type_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_profile(value, |fields| fields[9] = Value::Text("fixtures".into()))
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    fixtures[0] = Value::Text("fixture".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_profile(value, |fields| {
                if let Value::Array(fixtures) = &mut fields[9] {
                    if let Some(first) = fixtures.first().cloned() {
                        fixtures.push(first);
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture.pop();
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[1] = Value::Integer(1_u64.into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[2] = Value::Text("layer".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[3] = Value::Text("digest".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[4] = Value::Text("digest".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[5] = Value::Text("modes".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[5] = Value::Array(vec![Value::Text("mode".into())]);
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[6] = Value::Text("adapter".into());
            })
        }),
    ]
}

fn second_batch_fixture_input_type_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[7] = Value::Text("inputs".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    inputs[0] = Value::Text("input".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input.pop();
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[0] = Value::Integer(1_u64.into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[1] = Value::Text("size".into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[2] = Value::Text("digest".into());
                    }
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(inputs) = &mut fixture[7] {
                    if let Value::Array(input) = &mut inputs[0] {
                        input[3] = Value::Text("digest".into());
                    }
                }
            })
        }),
    ]
}

fn second_batch_expected_type_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[8] = Value::Text("expected".into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected.pop();
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[0] = Value::Text("kind".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[1] = Value::Text("bytes".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[2] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[0] = Value::Integer(1_u64.into());
                    expected[3] = Value::Text("error".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(expected) = &mut fixture[8] {
                    expected[0] = Value::Integer(2_u64.into());
                    expected[4] = Value::Text("divergence".into());
                }
            })
        }),
    ]
}

fn second_batch_fixture_policy_type_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[9] = Value::Text("outcome".into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[9] = Value::Integer(99_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[10] = Value::Text("error".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| fixture[11] = Value::Text("claim".into()))
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[11] = Value::Integer(99_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[12] = Value::Text("redaction".into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[12] = Value::Integer(99_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[13] = Value::Text("bounds".into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(bounds) = &mut fixture[13] {
                    bounds[0] = Value::Text("bound".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[14] = Value::Text("capabilities".into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(capabilities) = &mut fixture[14] {
                    capabilities[0] = Value::Text("network".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(capabilities) = &mut fixture[14] {
                    capabilities[1] = Value::Text("identifiers".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[15] = Value::Text("provenance".into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                if let Value::Array(provenance) = &mut fixture[15] {
                    provenance[0] = Value::Integer(1_u64.into());
                    provenance[1] = Value::Text("digest".into());
                }
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[16] = Value::Text("digest".into());
            })
        }),
    ]
}

#[test]
fn public_independent_profile_rejects_remaining_type_and_shape_matrix(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations = second_batch_profile_root_type_mutations()
        .into_iter()
        .chain(second_batch_profile_authority_type_mutations())
        .chain(second_batch_fixture_identity_type_mutations())
        .chain(second_batch_fixture_input_type_mutations())
        .chain(second_batch_expected_type_mutations())
        .chain(second_batch_fixture_policy_type_mutations());
    for mutate in mutations {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
        );
    }
    Ok(())
}

fn second_batch_manifest_record_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            replace_archive_descriptor_value(
                value,
                "profile/CPF1.cbor",
                Value::Text("descriptor".into()),
            )
        }),
        Box::new(|value| {
            replace_archive_descriptor_value(value, "profile/CPF1.cbor", Value::Array(Vec::new()))
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[0] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[1] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[2] = Value::Text("digest".into());
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF1.cbor")?[3] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| replace_archive_expected_value(value, Value::Text("expected".into()))),
        Box::new(|value| replace_archive_expected_value(value, Value::Array(Vec::new()))),
        Box::new(|value| {
            archive_expected(value)?[0] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[1] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[2] = Value::Text("digest".into());
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[3] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[4] = Value::Bool(false);
            Ok(())
        }),
        Box::new(|value| {
            archive_expected(value)?[5] = Value::Text("digest".into());
            Ok(())
        }),
    ]
}

#[test]
fn public_archive_decoders_reject_remaining_envelope_and_record_types(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let envelope_mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            top_fields(value)?[0] = Value::Integer(1_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            top_fields(value)?[1] = Value::Text("version".into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[0] = Value::Integer(1_u64.into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[1] = Value::Text("lifecycle".into());
            Ok(())
        }),
        Box::new(|value| {
            archive_array(value, 2)?[2] = Value::Text("mode".into());
            Ok(())
        }),
    ];
    for mutate in envelope_mutations
        .into_iter()
        .chain(second_batch_manifest_record_mutations())
    {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }
    Ok(())
}

#[test]
fn public_archive_preflight_rejects_truncated_length_and_member_records() {
    let archives = [
        Vec::new(),
        vec![0x86],
        vec![0x86, 0x18],
        vec![0x86, 0x19, 0],
        vec![0x86, 0x1a, 0, 0, 0],
        vec![0x86, 0x1b, 0, 0, 0, 0],
        vec![0x86, 0x41],
        vec![0x86, 0x61],
        vec![0x86, 0x81],
        vec![0x86, 0x60, 0x01, 0x80],
        vec![0x86, 0x60, 0x01, 0x80, 0x81],
        vec![0x86, 0x60, 0x01, 0x80, 0x81, 0x83],
        vec![0x86, 0x60, 0x01, 0x80, 0x81, 0x83, 0x60],
        vec![0x86, 0x60, 0x01, 0x80, 0x81, 0x83, 0x60, 0x40],
    ];
    for archive in archives {
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            pos_conformance::verify_archive_independently(&archive),
            Err(pos_conformance::BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }
}

#[test]
fn public_structured_validation_reaches_member_profile_and_pair_continuations(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let mut excessive_members = bundle.clone();
    excessive_members.members.resize(
        65_537,
        BundleMemberV1::fixture_input("inputs/overflow.bin", vec![1]),
    );
    assert_eq!(
        excessive_members.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
    );

    let mut malformed_profile = bundle;
    let profile_index = malformed_profile
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("profile member is missing")?;
    replace_member_bytes(&mut malformed_profile, profile_index, vec![0xff])?;
    assert_eq!(
        malformed_profile.validate(),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );

    let pair = public_mode_pair()?;
    let mut invalid_local = pair.clone();
    invalid_local.local.manifest.magic = "invalid".to_owned();
    assert_eq!(
        invalid_local.validate(),
        Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
    );
    let mut invalid_air_gapped = pair;
    invalid_air_gapped.air_gapped.manifest.magic = "invalid".to_owned();
    assert_eq!(
        invalid_air_gapped.validate(),
        Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
    );
    Ok(())
}

#[test]
fn public_typed_bundle_reaches_bound_support_and_authority_failures(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let (profile, members, expected_results) = public_bundle_inputs(&bundle)?;

    let mut changed_expected = profile.clone();
    let expected_bytes = vec![7, 8, 9];
    changed_expected.fixtures[0].expected = ExpectedResultV1::CanonicalBytes {
        digest: *blake3::hash(&expected_bytes).as_bytes(),
        bytes: expected_bytes,
    };
    changed_expected.profile_digest = changed_expected.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &changed_expected,
            BundleModeV1::Local,
            members.clone(),
            expected_results.clone(),
        ),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut changed_input_members = members.clone();
    let changed_input = changed_input_members
        .iter_mut()
        .find(|member| member.role == BundleMemberRoleV1::FixtureInput)
        .ok_or("fixture-input member is missing")?;
    changed_input.bytes.push(0);
    changed_input.digest = *blake3::hash(&changed_input.bytes).as_bytes();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            changed_input_members,
            expected_results.clone(),
        ),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut mode_excluded = profile.clone();
    mode_excluded.fixtures[0].modes = vec![ExecutionModeV1::AirGapped];
    mode_excluded.profile_digest = mode_excluded.digest();
    let mode_excluded_members = members
        .iter()
        .filter(|member| member.role != BundleMemberRoleV1::FixtureInput)
        .cloned()
        .collect();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &mode_excluded,
            BundleModeV1::Local,
            mode_excluded_members,
            expected_results.clone(),
        ),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut changed_support = profile.clone();
    changed_support.normative_spec_digest = [99; 32];
    changed_support.profile_digest = changed_support.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &changed_support,
            BundleModeV1::Local,
            members.clone(),
            expected_results.clone(),
        ),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut changed_matrix = profile;
    changed_matrix.execution_matrix_digest = [99; 32];
    changed_matrix.profile_digest = changed_matrix.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &changed_matrix,
            BundleModeV1::Local,
            members,
            expected_results,
        ),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut extra_support = bundle;
    let member = BundleMemberV1::supporting(
        "support/extra-notice.md",
        b"extra notice".to_vec(),
        BundleMemberRoleV1::Notice,
    );
    extra_support
        .manifest
        .members
        .push(BundleMemberDescriptorV1 {
            path: member.path.clone(),
            size_bytes: u64::try_from(member.bytes.len())?,
            digest: member.digest,
            role: member.role,
        });
    extra_support.members.push(member);
    extra_support
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    extra_support.manifest.members.sort_unstable();
    assert_eq!(
        extra_support.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
    );
    Ok(())
}

#[test]
fn public_typed_fixture_input_rejects_each_independent_binding_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    let (profile, members, expected_results) = public_bundle_inputs(&bundle)?;
    let input_index = members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::FixtureInput)
        .ok_or("fixture-input member is missing")?;

    let mut empty = members.clone();
    empty[input_index].bytes.clear();
    empty[input_index].digest = *blake3::hash(&[]).as_bytes();
    let mut changed_content = members.clone();
    let first_byte = changed_content[input_index]
        .bytes
        .first_mut()
        .ok_or("fixture-input bytes are empty")?;
    *first_byte ^= 1;
    for changed_members in [empty, changed_content] {
        assert_eq!(
            ConformanceBundleV1::materialize(
                &profile,
                BundleModeV1::Local,
                changed_members,
                expected_results.clone(),
            ),
            Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
        );
    }

    let mut changed_declared_digest = profile;
    changed_declared_digest.fixtures[0].inputs[0].digest = [99; 32];
    changed_declared_digest.profile_digest = changed_declared_digest.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &changed_declared_digest,
            BundleModeV1::Local,
            members,
            expected_results,
        ),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

fn assert_duplicate_authority_roles_are_rejected(
    bundle: &ConformanceBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    for authority_role in [
        BundleMemberRoleV1::AuthorityInventory,
        BundleMemberRoleV1::ExecutionMatrix,
    ] {
        let mut duplicate_authority = bundle.clone();
        let mut duplicate = duplicate_authority
            .members
            .iter()
            .find(|member| member.role == authority_role)
            .cloned()
            .ok_or("authority member is missing")?;
        duplicate.path.push('x');
        duplicate_authority
            .manifest
            .members
            .push(BundleMemberDescriptorV1 {
                path: duplicate.path.clone(),
                size_bytes: u64::try_from(duplicate.bytes.len())?,
                digest: duplicate.digest,
                role: duplicate.role,
            });
        duplicate_authority.members.push(duplicate);
        duplicate_authority
            .members
            .sort_by(|left, right| left.path.cmp(&right.path));
        duplicate_authority.manifest.members.sort_unstable();
        assert_eq!(
            duplicate_authority.validate(),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }
    Ok(())
}

#[test]
fn public_authority_members_fail_closed_when_missing_or_malformed(
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = signed_draft_bundle()?;
    for missing_role in [
        BundleMemberRoleV1::Provenance,
        BundleMemberRoleV1::AuthorityInventory,
        BundleMemberRoleV1::ExecutionMatrix,
    ] {
        let mut missing_authority = bundle.clone();
        missing_authority
            .members
            .retain(|member| member.role != missing_role);
        missing_authority
            .manifest
            .members
            .retain(|descriptor| descriptor.role != missing_role);
        assert_eq!(
            missing_authority.validate(),
            Err(pos_conformance::BundleContractErrorV1::MemberMissing)
        );
    }

    assert_duplicate_authority_roles_are_rejected(&bundle)?;

    let mut malformed_provenance = bundle.clone();
    let provenance_index = malformed_provenance
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Provenance)
        .ok_or("provenance member is missing")?;
    replace_member_bytes(
        &mut malformed_provenance,
        provenance_index,
        b"not-json".to_vec(),
    )?;
    rebind_profile_to_provenance(&mut malformed_provenance, provenance_index)?;
    assert_eq!(
        malformed_provenance.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut malformed_inventory = bundle.clone();
    let inventory_index = malformed_inventory
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
        .ok_or("authority-inventory member is missing")?;
    let malformed_inventory_bytes = b"not-json".to_vec();
    replace_member_bytes(
        &mut malformed_inventory,
        inventory_index,
        malformed_inventory_bytes.clone(),
    )?;
    let provenance_index = malformed_inventory
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Provenance)
        .ok_or("provenance member is missing")?;
    let mut provenance: JsonValue =
        serde_json::from_slice(&malformed_inventory.members[provenance_index].bytes)?;
    provenance["authority_inventory"]["sha256_digest"] =
        JsonValue::String(hex_digest(&Sha256::digest(&malformed_inventory_bytes)));
    replace_member_bytes(
        &mut malformed_inventory,
        provenance_index,
        serde_json::to_vec(&provenance)?,
    )?;
    rebind_profile_to_provenance(&mut malformed_inventory, provenance_index)?;
    assert_eq!(
        malformed_inventory.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut malformed_matrix = bundle;
    let matrix_index = malformed_matrix
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
        .ok_or("execution-matrix member is missing")?;
    let malformed_matrix_bytes = b"not-json".to_vec();
    replace_member_bytes(
        &mut malformed_matrix,
        matrix_index,
        malformed_matrix_bytes.clone(),
    )?;
    let provenance_index = malformed_matrix
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::Provenance)
        .ok_or("provenance member is missing")?;
    let mut provenance: JsonValue =
        serde_json::from_slice(&malformed_matrix.members[provenance_index].bytes)?;
    provenance["adr_059_execution_matrix"]["blake3_digest"] =
        JsonValue::String(hex_digest(blake3::hash(&malformed_matrix_bytes).as_bytes()));
    replace_member_bytes(
        &mut malformed_matrix,
        provenance_index,
        serde_json::to_vec(&provenance)?,
    )?;
    rebind_profile_to_provenance(&mut malformed_matrix, provenance_index)?;
    rebind_profile_to_execution_matrix(&mut malformed_matrix, matrix_index)?;
    assert_eq!(
        malformed_matrix.validate(),
        Err(pos_conformance::BundleContractErrorV1::MemberDigestMismatch)
    );

    Ok(())
}

#[test]
fn public_authority_members_reject_a_non_draft_lifecycle() -> Result<(), Box<dyn std::error::Error>>
{
    let non_draft_inventory = mutate_bound_json_member(
        &signed_draft_bundle()?,
        AUTHORITY_INVENTORY_MEMBER_PATH,
        |inventory| inventory["lifecycle"] = JsonValue::String("Accepted".to_owned()),
    )?;
    let non_draft_authority = mutate_bound_json_member(
        &non_draft_inventory,
        EXECUTION_MATRIX_MEMBER_PATH,
        |matrix| matrix["lifecycle"] = JsonValue::String("Accepted".to_owned()),
    )?;
    assert_eq!(
        non_draft_authority.validate(),
        Err(pos_conformance::BundleContractErrorV1::LifecycleInvalid)
    );
    Ok(())
}
