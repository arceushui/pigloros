#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, BundleExpectedResultV1,
    BundleMemberDescriptorV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1, CapabilityPolicyV1,
    ClaimLayerV1, ConformanceBundleV1, ConformanceProfileV2, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1,
    FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, SubjectAdapterKindV1, VerificationOutcomeV1,
    MAX_CONFORMANCE_BUNDLE_BYTES_V1,
};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/execution-matrix.json";

type ArchiveMutation = Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>;
type JsonMutation = Box<dyn FnOnce(&mut JsonValue)>;
type CapMutation = Box<dyn Fn(&mut EvaluatorHardCapsV1)>;
type PublicBundleInputs = (
    ConformanceProfileV2,
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
    archive_member(value, "profile/CPF2.cbor")?[1] = Value::Bytes(bytes.to_vec());
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
    let profile_bytes = match archive_member(value, "profile/CPF2.cbor")?.get(1) {
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
    archive_member(value, "profile/CPF2.cbor")?[1] = Value::Bytes(profile_bytes.clone());
    let descriptor = archive_descriptor(value, "profile/CPF2.cbor")?;
    descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
    descriptor[2] = Value::Bytes(digest.to_vec());
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
    let member = archive_member(value, EXECUTION_MATRIX_MEMBER_PATH)?;
    let matrix_bytes = match member.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("execution matrix bytes are missing".into()),
    };
    let mut matrix: JsonValue = serde_json::from_slice(&matrix_bytes)?;
    mutate(&mut matrix);
    let matrix_bytes = serde_json::to_vec(&matrix)?;
    let matrix_digest = *blake3::hash(&matrix_bytes).as_bytes();
    member[1] = Value::Bytes(matrix_bytes.clone());
    let descriptor = archive_descriptor(value, EXECUTION_MATRIX_MEMBER_PATH)?;
    descriptor[1] = Value::Integer(u64::try_from(matrix_bytes.len())?.into());
    descriptor[2] = Value::Bytes(matrix_digest.to_vec());

    let profile_member = archive_member(value, "profile/CPF2.cbor")?;
    let profile_bytes = match profile_member.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile bytes are missing".into()),
    };
    let mut profile = ConformanceProfileV2::from_canonical_cbor(&profile_bytes)?;
    profile.execution_matrix_digest = matrix_digest;
    profile.profile_digest = profile.digest();
    let profile_bytes = profile.to_canonical_cbor()?;
    profile_member[1] = Value::Bytes(profile_bytes.clone());
    let descriptor = archive_descriptor(value, "profile/CPF2.cbor")?;
    descriptor[1] = Value::Integer(u64::try_from(profile_bytes.len())?.into());
    descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
    archive_array(value, 2)?[3] = Value::Bytes(profile.profile_digest.to_vec());
    Ok(())
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

    fn profile(provenance_digest: [u8; 32]) -> ConformanceProfileV2 {
        let input = b"public draft input";
        let expected = b"public draft expected".to_vec();
        let schema_digest = digest(include_bytes!(
            "../../../fixtures/conformance/support/schema-cpf2-v2.cddl"
        ));
        let fixture = fixture(provenance_digest, input, expected, schema_digest);
        let mut profile = ConformanceProfileV2 {
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
            BundleMemberV1::authority(
                AUTHORITY_INVENTORY_MEMBER_PATH,
                inventory_bytes,
                BundleMemberRoleV1::AuthorityInventory,
            ),
            BundleMemberV1::authority(
                EXECUTION_MATRIX_MEMBER_PATH,
                matrix_bytes,
                BundleMemberRoleV1::ExecutionMatrix,
            ),
        ];
        (members, provenance_bytes)
    }

    fn draft_members(
        profile: &ConformanceProfileV2,
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
            BundleMemberV1::new(input_path, input, false),
            BundleMemberV1::new(expected_path.clone(), expected.clone(), true),
            BundleMemberV1::supporting(
                "support/normative-requirements.md",
                include_bytes!("../../../fixtures/conformance/support/normative-requirements.md")
                    .to_vec(),
                BundleMemberRoleV1::NormativeSpecification,
            ),
            BundleMemberV1::supporting(
                "support/schema-cpf2-v2.cddl",
                include_bytes!("../../../fixtures/conformance/support/schema-cpf2-v2.cddl")
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
    assert!(!supporting.expected_result);

    let authority_bytes = b"public authority bytes".to_vec();
    let authority = BundleMemberV1::authority(
        "authority/public.json",
        authority_bytes.clone(),
        BundleMemberRoleV1::AuthorityInventory,
    );
    assert_eq!(authority.path, "authority/public.json");
    assert_eq!(authority.bytes, authority_bytes);
    assert_eq!(authority.digest, *blake3::hash(&authority.bytes).as_bytes());
    assert_eq!(authority.role, BundleMemberRoleV1::AuthorityInventory);
    assert!(!authority.expected_result);
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

#[test]
fn public_materializer_and_verifier_binaries_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    let output_root = std::env::temp_dir().join(format!(
        "pigloros-conformance-public-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _temporary_output = TemporaryOutput(output_root.clone());

    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let materializer_status = Command::new(materializer_binary)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg(&output_root)
        .status()?;
    assert!(materializer_status.success());

    let archives = archive_paths(&output_root)?;
    assert_eq!(archives.len(), 14);
    for layer in materialized_layers(&output_root)? {
        let layer_archives = archive_paths(&output_root.join(layer).join("draft"))?;
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
            let profile = ConformanceProfileV2::from_canonical_cbor(profile_bytes)?;
            assert_eq!(profile.lifecycle, ProfileLifecycleV1::Draft);
            assert_eq!(profile.execution_profile_digests.len(), 2);
            assert_eq!(profile.fixtures.len(), 14);
            assert_eq!(
                profile
                    .fixtures
                    .iter()
                    .filter(|fixture| {
                        fixture.modes == [pos_conformance::ExecutionModeV1::Local]
                    })
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
    }
    let verifier_binary = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    let verifier_status = Command::new(verifier_binary).args(&archives).status()?;
    assert!(verifier_status.success());
    Ok(())
}

#[test]
fn public_materializer_rejects_invalid_invocations() -> Result<(), Box<dyn std::error::Error>> {
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
    let existing_file = std::env::temp_dir().join(format!("{unique}-existing-file"));
    let missing_parent = std::env::temp_dir().join(format!("{unique}-missing-parent/output"));
    let blocked_root = std::env::temp_dir().join(format!("{unique}-blocked"));
    fs::create_dir_all(&existing_output)?;
    fs::write(&existing_file, b"must not be overwritten")?;
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
        .arg(&existing_file)
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
    assert_eq!(fs::read(&existing_file)?, b"must not be overwritten");
    fs::remove_file(existing_file)?;
    fs::remove_file(blocked_root)?;
    assert!(!missing_key_output.exists());
    assert!(!invalid_key_output.exists());
    assert!(!missing_parent.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn public_materializer_rejects_a_symlinked_parent() -> Result<(), Box<dyn std::error::Error>> {
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
    let root = std::env::temp_dir().join(format!(
        "pigloros-conformance-atomic-publication-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _temporary_output = TemporaryOutput(root.clone());
    let relative_parent = root.join("relative-parent");
    let protected_parent = root.join("protected-parent");
    let protected_target = root.join("protected-target");
    fs::create_dir_all(&relative_parent)?;
    fs::create_dir_all(&protected_parent)?;
    fs::create_dir_all(&protected_target)?;
    let materializer_binary = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let signing_key = "0707070707070707070707070707070707070707070707070707070707070707";

    let relative_status = Command::new(&materializer_binary)
        .current_dir(&relative_parent)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg("publication")
        .status()?;
    assert!(relative_status.success());
    assert!(relative_parent.join("publication").is_dir());
    assert!(fs::read_dir(&relative_parent)?.all(|entry| {
        entry.is_ok_and(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".pigloros-")
        })
    }));

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
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;
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
    for invalid_filename in [
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
fn public_independent_verifier_rejects_a_cpf2_semantic_invariant(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let invalid_profile = signed_archive_variant(&bundle, &signing_key, |value| {
        mutate_profile(value, |fields| fields[3] = Value::Text("1".to_owned()))
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&invalid_profile),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn public_independent_verifier_rejects_cpf2_semantic_variants(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let bundle = signed_draft_bundle()?;
    let mutations: Vec<ArchiveMutation> = cpf2_root_semantic_mutations()
        .into_iter()
        .chain(cpf2_header_and_range_mutations())
        .chain(cpf2_fixture_semantic_mutations())
        .chain(cpf2_ordering_and_cap_mutations())
        .chain(cpf2_fixture_detail_mutations())
        .chain(cpf2_fixture_branch_mutations())
        .chain(cpf2_fixture_result_mutations())
        .collect();
    for mutate in mutations {
        let archive = signed_archive_variant(&bundle, &signing_key, mutate)?;
        assert!(pos_conformance::verify_archive_independently(&archive).is_err());
    }
    Ok(())
}

fn cpf2_root_semantic_mutations() -> Vec<ArchiveMutation> {
    vec![
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
    ]
}

fn cpf2_header_and_range_mutations() -> Vec<ArchiveMutation> {
    let mut mutations: Vec<ArchiveMutation> = vec![
        Box::new(|value| {
            mutate_profile(value, |fields| fields[0] = Value::Text("CPF1".to_owned()))
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[1] = Value::Integer(1_u64.into()))),
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

fn cpf2_fixture_semantic_mutations() -> Vec<ArchiveMutation> {
    vec![
        Box::new(|value| {
            mutate_profile(value, |fields| {
                fields[10] = Value::Array(vec![Value::Array(vec![
                    Value::Integer(9_u64.into()),
                    Value::Bytes(Vec::new()),
                ])]);
            })
        }),
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
                        fixture[13] = Value::Array(vec![Value::Integer(0_u64.into()); 8]);
                    }
                }
            })
        }),
        Box::new(|value| mutate_profile(value, |fields| fields[15] = Value::Bytes(vec![0; 32]))),
    ]
}

fn cpf2_ordering_and_cap_mutations() -> Vec<ArchiveMutation> {
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

fn cpf2_fixture_detail_mutations() -> Vec<ArchiveMutation> {
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

fn cpf2_fixture_branch_mutations() -> Vec<ArchiveMutation> {
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
    ]
}

fn cpf2_fixture_result_mutations() -> Vec<ArchiveMutation> {
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
                fixture[9] = Value::Integer(3_u64.into());
                fixture[10] = Value::Integer(12_u64.into());
            })
        }),
        Box::new(|value| {
            mutate_first_profile_fixture(value, |fixture| {
                fixture[11] = Value::Integer(4_u64.into());
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
                if let Value::Array(provenance) = &mut fixture[15] {
                    provenance[1] = Value::Bytes(vec![0; 32]);
                }
            })
        }),
    ]
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
        b"sk_live_0123456789abcdef".as_slice(),
        b"sk_test_0123456789abcdef".as_slice(),
        b"AIza0123456789abcdefghijklmnopqrst".as_slice(),
        b"AKIA0123456789ABCDEF".as_slice(),
        b"eyjabcdefgh.klmnopqrst.uvwxyzabcd".as_slice(),
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
        let expected = archive_expected(value)?;
        let path = match &expected[4] {
            Value::Text(path) => path.clone(),
            _ => return Err("expected path is not text".into()),
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
        descriptor[2] = Value::Bytes(changed_digest);
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

    let mut invalid_expected_flag = bundle.clone();
    invalid_expected_flag.members[fixture_index].expected_result = true;
    assert_eq!(
        invalid_expected_flag.validate(),
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

    let expected_index = bundle
        .members
        .iter()
        .position(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .ok_or("expected-result member is missing")?;
    let mut invalid_expected_digest = bundle.clone();
    invalid_expected_digest.manifest.expected_results[0].digest = [0; 32];
    assert_eq!(
        invalid_expected_digest.validate(),
        Err(pos_conformance::BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut invalid_expected_role = bundle.clone();
    invalid_expected_role.members[expected_index].expected_result = false;
    assert_eq!(
        invalid_expected_role.validate(),
        Err(pos_conformance::BundleContractErrorV1::UndeclaredMember)
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

fn signed_draft_bundle() -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    Ok(fixtures::draft_bundle()?.sign(&signing_key)?)
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
        ConformanceProfileV2::from_canonical_cbor(&bundle.members[profile_index].bytes)?;
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
        ConformanceProfileV2::from_canonical_cbor(&bundle.members[profile_index].bytes)?;
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
    let profile = ConformanceProfileV2::from_canonical_cbor(&profile_member.bytes)?;
    let members = bundle
        .members
        .iter()
        .filter(|member| member.role != BundleMemberRoleV1::Profile)
        .cloned()
        .collect();
    Ok((profile, members, bundle.manifest.expected_results.clone()))
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
        archive_member(value, "profile/CPF2.cbor")?[2] = Value::Integer(0_u64.into());
        archive_descriptor(value, "profile/CPF2.cbor")?[3] = Value::Integer(0_u64.into());
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
            archive_member(value, "profile/CPF2.cbor")?[1] = Value::Null;
            Ok(())
        }) as Box<dyn FnOnce(&mut Value) -> Result<(), Box<dyn std::error::Error>>>,
        Box::new(|value: &mut Value| {
            archive_member(value, "profile/CPF2.cbor")?[2] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[1] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[2] = Value::Null;
            Ok(())
        }),
        Box::new(|value: &mut Value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[3] = Value::Null;
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
            mutate_profile(value, |fields| fields[1] = Value::Integer(1_u64.into()))
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
        let profile_member = archive_member(value, "profile/CPF2.cbor")?;
        let Some(Value::Bytes(profile_bytes)) = profile_member.get(1) else {
            return Err("profile bytes are missing".into());
        };
        let mut profile_bytes = profile_bytes.clone();
        replace_first_byte(&mut profile_bytes, 0x02, &[0x18, 0x02])?;
        profile_member[1] = Value::Bytes(profile_bytes.clone());
        let descriptor = archive_descriptor(value, "profile/CPF2.cbor")?;
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
        let mut noncanonical = match archive_member(value, "profile/CPF2.cbor")?.get(1) {
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
        archive_member(value, "profile/CPF2.cbor")?[1] = Value::Bytes(invalid_profile.clone());
        let descriptor = archive_descriptor(value, "profile/CPF2.cbor")?;
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
        let profile_bytes = match archive_member(value, "profile/CPF2.cbor")?.get(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("profile bytes are missing".into()),
        };
        let mut profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
        let Value::Array(fields) = &mut profile else {
            return Err("profile is not an array".into());
        };
        fields[9] = Value::Null;
        let profile_bytes = encode_archive(&profile)?;
        archive_member(value, "profile/CPF2.cbor")?[1] = Value::Bytes(profile_bytes.clone());
        let descriptor = archive_descriptor(value, "profile/CPF2.cbor")?;
        descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
        Ok(())
    })?;
    assert_eq!(
        pos_conformance::verify_archive_independently(&malformed_fixtures),
        Err(pos_conformance::BundleContractErrorV1::ProfileInvalid)
    );

    let cap_limited_archive = signed_archive_variant(bundle, signing_key, |value| {
        let profile_bytes = match archive_member(value, "profile/CPF2.cbor")?.get(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("profile bytes are missing".into()),
        };
        let mut profile = ConformanceProfileV2::from_canonical_cbor(&profile_bytes)?;
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
        archive_member(value, "profile/CPF2.cbor")?[1] = Value::Bytes(profile_bytes.clone());
        let descriptor = archive_descriptor(value, "profile/CPF2.cbor")?;
        descriptor[1] = Value::Integer((profile_bytes.len() as u64).into());
        descriptor[2] = Value::Bytes(blake3::hash(&profile_bytes).as_bytes().to_vec());
        archive_array(value, 2)?[3] = Value::Bytes(profile_digest.to_vec());
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&cap_limited_archive),
        Err(pos_conformance::BundleContractErrorV1::MemberOutOfBounds)
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
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;
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
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;
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
    let bundle = fixtures::draft_bundle()?.sign(&signing_key)?;
    assert_raw_independent_archive_rejections();
    assert_archive_shape_rejections(&bundle, &signing_key)?;
    assert_archive_member_rejections(&bundle, &signing_key)?;
    assert_archive_expected_rejections(&bundle, &signing_key)?;
    assert_archive_profile_rejections(&bundle, &signing_key)?;
    assert_independent_profile_shape_rejections(&bundle, &signing_key)?;

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
            pos_conformance::BundleContractErrorV1::MemberOutOfBounds,
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
            archive_descriptor(value, "profile/CPF2.cbor")?[0] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[1] = Value::Null;
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[2] = Value::Bytes(vec![0]);
            Ok(())
        }),
        Box::new(|value| {
            archive_descriptor(value, "profile/CPF2.cbor")?[3] = Value::Integer(99_u64.into());
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
    let duplicate_member = BundleMemberV1::new(duplicate_path.clone(), expected_member.bytes, true);
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
        Box::new(|value| value["version"] = JsonValue::Number(2_u64.into())),
        Box::new(|value| value["lifecycle"] = JsonValue::String("Stable".to_owned())),
        Box::new(|value| value["digest_algorithm"] = JsonValue::String("SHA-256".to_owned())),
        Box::new(|value| value["entries"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| {
            value["entries"][0]["materialization_status"] =
                JsonValue::String("materialized".to_owned());
        }),
        Box::new(|value| {
            value["entries"][0]["fixture_bytes_path"] = JsonValue::String("x".to_owned());
        }),
        Box::new(|value| {
            let duplicate = value["entries"][1]["fixture_id"].clone();
            value["entries"][0]["fixture_id"] = duplicate;
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
        Box::new(|value| value["authority_inventory"]["sha256_digest"] = JsonValue::Null),
        Box::new(|value| {
            value["authority_inventory"]["sha256_digest"] =
                JsonValue::String("not-a-digest".to_owned());
        }),
        Box::new(|value| {
            value["authority_inventory"]["sha256_digest"] = JsonValue::String("00".repeat(32));
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

fn reject_malformed_matrix_records(
    bundle: &ConformanceBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let matrix_cases: Vec<JsonMutation> = vec![
        Box::new(|value| value["magic"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["version"] = JsonValue::Number(2_u64.into())),
        Box::new(|value| value["lifecycle"] = JsonValue::String("Candidate".to_owned())),
        Box::new(|value| value["lifecycle"] = JsonValue::Null),
        Box::new(|value| value["row_count"] = JsonValue::Number(11_u64.into())),
        Box::new(|value| value["case_count"] = JsonValue::Number(191_u64.into())),
        Box::new(|value| value["rows"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["rows"][0]["variants"] = JsonValue::Null),
        Box::new(|value| value["rows"][0]["variants"] = JsonValue::Array(Vec::new())),
        Box::new(|value| value["rows"][0]["modes"] = JsonValue::Array(Vec::new())),
        Box::new(|value| value["rows"][0]["executed_case_count"] = JsonValue::Number(1_u64.into())),
        Box::new(|value| value["cases"][0]["fixture_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["variant"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["mode"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["cases"][0]["case_id"] = JsonValue::String("wrong".to_owned())),
        Box::new(|value| value["equality_predicates"] = JsonValue::Null),
    ];
    for (index, mutate) in matrix_cases.into_iter().enumerate() {
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
