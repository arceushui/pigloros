//! Public archive-contract regression tests for the current CPF1/FPR1/FPP1 surface.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, verify_archive_independently,
    verify_archive_release_filename, verify_release_tree_independently, ArtifactDescriptorV1,
    BundleContractErrorV1, BundleExpectedResultV1, BundleMemberDescriptorV1, BundleMemberRoleV1,
    BundleMemberV1, BundleModeV1, CapabilityPolicyV1, ClaimLayerV1, ConformanceBundlePairV1,
    ConformanceBundleV1, ConformanceProfileV1, DeterministicBudgetV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExecutionModeV1, FixtureDescriptorV1, FixtureFamilyV1,
    FixtureProvenanceV1, FixtureProviderEntryV1, FixtureProviderKeyV1, FixtureProviderPackageV1,
    FixtureProviderRegistryBindingV1, FixtureProviderRegistryV1, IndependenceRequirementsV1,
    NamespacedFailureV1, OperationalSafetyV1, ProfileLifecycleV1, ProviderFamilySchemaV1,
    RedactionStateV1, ReplayClaimV1, StrictOracleKindV1, StrictOracleV1, SubjectAdapterKindV1,
    VerificationOutcomeV1, DETERMINISTIC_BUDGET_HARD_CAPS_V1,
    FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

static MATERIALIZER_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn materializer_process_guard() -> MutexGuard<'static, ()> {
    MATERIALIZER_PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CURRENT_SCHEMA_BYTES: [&[u8]; 7] = [
    b"positive-schema",
    b"denied-schema",
    b"malformed-schema",
    b"resource-schema",
    b"deletion-schema",
    b"downgrade-schema",
    b"independent-schema",
];
const LICENCE_BYTES: &[u8] = b"MIT\n";
const NOTICE_BYTES: &[u8] = b"public notice\n";
const SBOM_BYTES: &[u8] = br#"{"bomFormat":"CycloneDX"}"#;
const SOURCE_PROVENANCE_BYTES: &[u8] = br#"{"source":"public"}"#;
const BUILD_PROVENANCE_BYTES: &[u8] = br#"{"builder":"public"}"#;
const PUBLICATION_REVIEW_BYTES: &[u8] = br#"{"review_status":"pending"}"#;
const LIMITATIONS_BYTES: &[u8] = b"# Limitations\n";
const NORMATIVE_BYTES: &[u8] = b"normative contract";
const MATRIX_BYTES: &[u8] = b"execution matrix";
const PROFILE_SCHEMA_BYTES: &[u8] = b"cpf1 schema";
const EXPECTED_BYTES: &[u8] = br#"{"status":"pending"}"#;
const PAYLOAD_BYTES: &[u8] = b"public fixture payload";

const fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn artifact(path: &str, media_type: &str, bytes: &[u8]) -> TestResult<ArtifactDescriptorV1> {
    Ok(ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: media_type.to_owned(),
        byte_length: u64::try_from(bytes.len())?,
        blake3_digest: *blake3::hash(bytes).as_bytes(),
    })
}

fn provider_key() -> FixtureProviderKeyV1 {
    FixtureProviderKeyV1 {
        provider_id: "pigloros.fixture.example".to_owned(),
        contract_version: "1.0.0".to_owned(),
        abi_major: 1,
        abi_minor: 0,
    }
}

struct CurrentBundleInputs {
    profile: ConformanceProfileV1,
    members: Vec<BundleMemberV1>,
    expected: Vec<BundleExpectedResultV1>,
}

struct ProviderContractInputs {
    family_schemas: Vec<ProviderFamilySchemaV1>,
    package_path: &'static str,
    package_bytes: Vec<u8>,
    registry_bytes: Vec<u8>,
}

fn current_provider_contract_inputs() -> TestResult<ProviderContractInputs> {
    let families = [
        FixtureFamilyV1::Positive,
        FixtureFamilyV1::Denied,
        FixtureFamilyV1::Malformed,
        FixtureFamilyV1::ResourceExhaustion,
        FixtureFamilyV1::DeletionRedaction,
        FixtureFamilyV1::Downgrade,
        FixtureFamilyV1::IndependentEvaluation,
    ];
    let family_schemas = families
        .into_iter()
        .zip(CURRENT_SCHEMA_BYTES)
        .enumerate()
        .map(|(index, (family, bytes))| {
            Ok(ProviderFamilySchemaV1 {
                family,
                schema_descriptor: artifact(
                    &format!("providers/example/schemas/{index}.schema.json"),
                    "application/schema+json",
                    bytes,
                )?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;

    let mut package = FixtureProviderPackageV1 {
        provider_key: provider_key(),
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        family_schemas: family_schemas.clone(),
        licence_descriptor: artifact("support/LICENSE", "text/plain", LICENCE_BYTES)?,
        notices_descriptor: artifact("support/NOTICE", "text/plain", NOTICE_BYTES)?,
        sbom_descriptor: artifact("support/sbom.json", "application/json", SBOM_BYTES)?,
        source_provenance_descriptor: artifact(
            "support/source-provenance.json",
            "application/json",
            SOURCE_PROVENANCE_BYTES,
        )?,
        limitations_descriptor: artifact(
            "support/limitations.md",
            "text/markdown",
            LIMITATIONS_BYTES,
        )?,
        package_digest: [0; 32],
    };
    package.package_digest = package.digest()?;
    let package_bytes = package.to_canonical_cbor()?;
    let package_path = "authority/providers/example.cbor";
    let package_descriptor = artifact(package_path, "application/cbor", &package_bytes)?;

    let entry = FixtureProviderEntryV1 {
        provider_key: provider_key(),
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        provider_package_descriptor: package_descriptor,
    };
    let mut registry = FixtureProviderRegistryV1 {
        providers: vec![entry],
        registry_digest: [0; 32],
    };
    registry.registry_digest = registry.digest()?;
    let registry_bytes = registry.to_canonical_cbor()?;

    Ok(ProviderContractInputs {
        family_schemas,
        package_path,
        package_bytes,
        registry_bytes,
    })
}

fn current_fixtures(
    family_schemas: &[ProviderFamilySchemaV1],
) -> TestResult<Vec<FixtureDescriptorV1>> {
    let execution = digest(31);
    let failure = NamespacedFailureV1 {
        owner_id: "pigloros.core".to_owned(),
        contract_version: "1.0.0".to_owned(),
        code_id: "provenance-missing".to_owned(),
    };
    family_schemas
        .iter()
        .map(|family_schema| {
            let family_name = match family_schema.family {
                FixtureFamilyV1::Positive => "positive",
                FixtureFamilyV1::Denied => "denied",
                FixtureFamilyV1::Malformed => "malformed",
                FixtureFamilyV1::ResourceExhaustion => "resource-exhaustion",
                FixtureFamilyV1::DeletionRedaction => "deletion-redaction",
                FixtureFamilyV1::Downgrade => "downgrade",
                FixtureFamilyV1::IndependentEvaluation => "independent-evaluation",
            };
            let case_id = format!("example-{family_name}");
            let expected_path =
                expected_result_member_path(&case_id, ClaimLayerV1::ArtifactIntegrity, &execution);
            let mut fixture = FixtureDescriptorV1 {
                case_id,
                mandatory: true,
                claim_layer: ClaimLayerV1::ArtifactIntegrity,
                family: family_schema.family,
                provider_key: provider_key(),
                subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
                execution_profile_digest: execution,
                modes: vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped],
                schema: family_schema.schema_descriptor.clone(),
                payload: artifact(
                    &format!("fixtures/{family_name}/input.bin"),
                    "application/octet-stream",
                    PAYLOAD_BYTES,
                )?,
                auxiliary: vec![artifact(
                    &expected_path,
                    "application/json",
                    EXPECTED_BYTES,
                )?],
                strict_oracle: StrictOracleV1 {
                    kind: StrictOracleKindV1::Failure,
                    output: None,
                    failure: Some(failure.clone()),
                    divergence: None,
                },
                expected_verification_outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
                expected_verification_error: Some(failure.clone()),
                replay_claim: ReplayClaimV1::UnverifiableArtifactsMissing,
                redaction_state: RedactionStateV1::EvidenceMissing,
                deterministic_budget: DeterministicBudgetV1 {
                    memory_bytes: 1024,
                    cpu_fuel: 1024,
                    host_calls: 16,
                    event_count: 16,
                    output_bytes: 1024,
                    storage_bytes: 1024,
                    execution_steps: 1024,
                    simulation_time_ns: 1024,
                },
                operational_safety: OperationalSafetyV1 { watchdog_ms: 1000 },
                capability_policy: CapabilityPolicyV1 {
                    network_allowed: false,
                    capability_ids: vec!["read-public-bundle".to_owned()],
                },
                trust_policy_snapshot_digest: None,
                release_admission_digest: None,
                provenance: FixtureProvenanceV1 {
                    licence_id: "MIT".to_owned(),
                    notices_digest: *blake3::hash(NOTICE_BYTES).as_bytes(),
                    sbom_digest: *blake3::hash(SBOM_BYTES).as_bytes(),
                    source_digest: *blake3::hash(SOURCE_PROVENANCE_BYTES).as_bytes(),
                    build_digest: *blake3::hash(BUILD_PROVENANCE_BYTES).as_bytes(),
                    publication_review_digest: *blake3::hash(PUBLICATION_REVIEW_BYTES).as_bytes(),
                    limitations_digest: *blake3::hash(LIMITATIONS_BYTES).as_bytes(),
                },
                transition: None,
                fixture_digest: [0; 32],
            };
            if fixture.family == FixtureFamilyV1::Downgrade {
                let mut next_provider = provider_key();
                next_provider.abi_minor = 1;
                fixture.trust_policy_snapshot_digest = Some(digest(43));
                fixture.release_admission_digest = Some(digest(44));
                fixture.transition = Some(pos_conformance::FixtureContractTransitionV1 {
                    from: provider_key(),
                    to: next_provider,
                });
            }
            fixture.fixture_digest = fixture.digest();
            Ok(fixture)
        })
        .collect()
}

fn current_profile(
    fixtures: Vec<FixtureDescriptorV1>,
    registry_bytes: &[u8],
) -> TestResult<ConformanceProfileV1> {
    let mut profile = ConformanceProfileV1 {
        profile_id: "pigloros.current.example".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: *blake3::hash(NORMATIVE_BYTES).as_bytes(),
        execution_matrix_digest: *blake3::hash(MATRIX_BYTES).as_bytes(),
        execution_profile_digests: vec![digest(31)],
        fixture_provider_registry: FixtureProviderRegistryBindingV1 {
            registry_artifact: artifact(
                FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
                "application/cbor",
                registry_bytes,
            )?,
            required_provider_keys: vec![provider_key()],
        },
        fixtures,
        allowed_divergences: Vec::new(),
        evaluator_protocol: EvaluatorProtocolV1 {
            protocol_id: "pigloros.evaluator.v1".to_owned(),
            protocol_digest: digest(51),
            request_schema_digest: digest(52),
            report_schema_digest: digest(53),
            hard_caps: EvaluatorHardCapsV1 {
                max_profile_bytes: 16 * 1024 * 1024,
                max_cases: 64,
                max_bundle_members: 256,
                max_member_path_bytes: 256,
                max_member_bytes: 64 * 1024 * 1024,
                max_total_bundle_bytes: 1024 * 1024 * 1024,
                max_compression_expansion: 100,
                max_structural_nesting: 32,
                max_coordinate_bytes: 128,
                max_diagnostic_bytes: 1024 * 1024,
                max_deterministic_memory_bytes: DETERMINISTIC_BUDGET_HARD_CAPS_V1.memory_bytes,
                max_deterministic_cpu_fuel: DETERMINISTIC_BUDGET_HARD_CAPS_V1.cpu_fuel,
                max_deterministic_host_calls: DETERMINISTIC_BUDGET_HARD_CAPS_V1.host_calls,
                max_deterministic_event_count: DETERMINISTIC_BUDGET_HARD_CAPS_V1.event_count,
                max_deterministic_output_bytes: DETERMINISTIC_BUDGET_HARD_CAPS_V1.output_bytes,
                max_deterministic_storage_bytes: DETERMINISTIC_BUDGET_HARD_CAPS_V1.storage_bytes,
                max_deterministic_execution_steps: DETERMINISTIC_BUDGET_HARD_CAPS_V1
                    .execution_steps,
                max_deterministic_simulation_time_ns: DETERMINISTIC_BUDGET_HARD_CAPS_V1
                    .simulation_time_ns,
            },
        },
        independence_requirements: IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: digest(54),
            requirements_digest: digest(55),
        },
        fixture_contract_policy_digest: *blake3::hash(PROFILE_SCHEMA_BYTES).as_bytes(),
        limitations_digest: *blake3::hash(LIMITATIONS_BYTES).as_bytes(),
        provenance_digest: *blake3::hash(PUBLICATION_REVIEW_BYTES).as_bytes(),
        previous_profile_digest: None,
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    Ok(profile)
}

fn current_bundle_inputs(mode: BundleModeV1) -> TestResult<CurrentBundleInputs> {
    let ProviderContractInputs {
        family_schemas,
        package_path,
        package_bytes,
        registry_bytes,
    } = current_provider_contract_inputs()?;

    let fixtures = current_fixtures(&family_schemas)?;
    let mut expected = fixtures
        .iter()
        .map(|fixture| {
            let descriptor = fixture
                .auxiliary
                .first()
                .ok_or("expected-result descriptor is absent")?;
            Ok(BundleExpectedResultV1 {
                case_id: fixture.case_id.clone(),
                claim_layer: fixture.claim_layer,
                execution_profile_digest: fixture.execution_profile_digest,
                mode,
                member_path: descriptor.member_path.clone(),
                digest: descriptor.blake3_digest,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    expected.sort_unstable();
    let profile = current_profile(fixtures, &registry_bytes)?;
    let mut members = family_schemas
        .iter()
        .zip(CURRENT_SCHEMA_BYTES)
        .map(|(schema, bytes)| {
            BundleMemberV1::supporting(
                schema.schema_descriptor.member_path.clone(),
                bytes.to_vec(),
                BundleMemberRoleV1::Schema,
            )
        })
        .collect::<Vec<_>>();
    members.extend(profile.fixtures.iter().flat_map(|fixture| {
        let payload = BundleMemberV1::fixture_input(
            fixture.payload.member_path.clone(),
            PAYLOAD_BYTES.to_vec(),
        );
        let expected = BundleMemberV1::expected_result(
            fixture.auxiliary[0].member_path.clone(),
            EXPECTED_BYTES.to_vec(),
        );
        [payload, expected]
    }));
    members.extend([
        BundleMemberV1::supporting(
            "support/normative-requirements.md",
            NORMATIVE_BYTES.to_vec(),
            BundleMemberRoleV1::NormativeSpecification,
        ),
        BundleMemberV1::supporting(
            "support/LICENSE",
            LICENCE_BYTES.to_vec(),
            BundleMemberRoleV1::Licence,
        ),
        BundleMemberV1::supporting(
            "support/NOTICE",
            NOTICE_BYTES.to_vec(),
            BundleMemberRoleV1::Notice,
        ),
        BundleMemberV1::supporting(
            "support/sbom.json",
            SBOM_BYTES.to_vec(),
            BundleMemberRoleV1::Sbom,
        ),
        BundleMemberV1::supporting(
            "support/source-provenance.json",
            SOURCE_PROVENANCE_BYTES.to_vec(),
            BundleMemberRoleV1::Provenance,
        ),
        BundleMemberV1::supporting(
            "support/build-provenance.json",
            BUILD_PROVENANCE_BYTES.to_vec(),
            BundleMemberRoleV1::Provenance,
        ),
        BundleMemberV1::supporting(
            "support/publication-review.json",
            PUBLICATION_REVIEW_BYTES.to_vec(),
            BundleMemberRoleV1::Provenance,
        ),
        BundleMemberV1::supporting(
            "support/limitations.md",
            LIMITATIONS_BYTES.to_vec(),
            BundleMemberRoleV1::Limitations,
        ),
        BundleMemberV1::supporting(
            "support/schema-cpf1-v1.cddl",
            PROFILE_SCHEMA_BYTES.to_vec(),
            BundleMemberRoleV1::Schema,
        ),
        BundleMemberV1::authority_inventory(b"authority inventory".to_vec()),
        BundleMemberV1::execution_matrix(MATRIX_BYTES.to_vec()),
        BundleMemberV1::fixture_provider_package(package_path, package_bytes),
        BundleMemberV1::fixture_provider_registry(registry_bytes),
    ]);
    Ok(CurrentBundleInputs {
        profile,
        members,
        expected,
    })
}

fn signed_current_bundle(mode: BundleModeV1) -> TestResult<ConformanceBundleV1> {
    let inputs = current_bundle_inputs(mode)?;
    ConformanceBundleV1::materialize(&inputs.profile, mode, inputs.members, inputs.expected)
        .and_then(|bundle| bundle.sign(&SigningKey::from_bytes(&[7; 32])))
        .map_err(Into::into)
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn contract_digest(domain: &[u8], fields: &[Value]) -> TestResult<[u8; 32]> {
    let bytes = encode_value(&Value::Array(fields.to_vec()))?;
    let mut preimage = Vec::with_capacity(domain.len() + 9 + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.push(0);
    preimage.extend_from_slice(&u64::try_from(bytes.len())?.to_be_bytes());
    preimage.extend_from_slice(&bytes);
    Ok(*blake3::hash(&preimage).as_bytes())
}

fn resign_archive(value: &mut Value) -> TestResult {
    let Value::Array(archive) = value else {
        return Err("archive is not an array".into());
    };
    let manifest_bytes = encode_value(&archive[0])?;
    let key = SigningKey::from_bytes(&[7; 32]);
    archive[2] = Value::Bytes(key.verifying_key().to_bytes().to_vec());
    archive[3] = Value::Bytes(key.sign(&manifest_bytes).to_bytes().to_vec());
    Ok(())
}

fn array_field<'a>(
    fields: &'a mut [Value],
    index: usize,
    name: &str,
) -> TestResult<&'a mut Vec<Value>> {
    match fields.get_mut(index) {
        Some(Value::Array(values)) => Ok(values),
        _ => Err(format!("{name} is not an array").into()),
    }
}

fn replace_value(fields: &mut [Value], index: usize, value: Value, name: &str) -> TestResult {
    let slot = fields
        .get_mut(index)
        .ok_or_else(|| format!("{name} is absent"))?;
    *slot = value;
    Ok(())
}

fn mutate_profile_archive(mutate: impl FnOnce(&mut [Value]) -> TestResult) -> TestResult<Vec<u8>> {
    mutate_profile_archive_staged(mutate, |_| Ok(()), |_| Ok(()))
}

fn mutate_profile_archive_after_fixture_digest(
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    mutate_profile_archive_staged(|_| Ok(()), mutate, |_| Ok(()))
}

fn mutate_profile_archive_after_profile_digest(
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    mutate_profile_archive_staged(|_| Ok(()), |_| Ok(()), mutate)
}

fn mutate_profile_archive_staged(
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
    mutate_after_fixture_digest: impl FnOnce(&mut [Value]) -> TestResult,
    mutate_after_profile_digest: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(archive_fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    let Value::Array(members) = &mut archive_fields[1] else {
        return Err("archive members are not an array".into());
    };
    let profile_member = members
        .iter_mut()
        .find(|member| {
            matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text("profile/CPF1.cbor".to_owned())))
        })
        .ok_or("profile member is absent")?;
    let Value::Array(profile_member_fields) = profile_member else {
        return Err("profile member is not an array".into());
    };
    let Value::Bytes(profile_bytes) = &profile_member_fields[1] else {
        return Err("profile member is not bytes".into());
    };
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let Value::Array(profile_fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    mutate(profile_fields)?;
    if let Some(Value::Array(fixtures)) = profile_fields.get_mut(9) {
        for fixture in fixtures {
            let Value::Array(fields) = fixture else {
                continue;
            };
            if fields.len() == 24 {
                fields[23] = Value::Bytes(
                    contract_digest(b"PiglorOS.Conformance.Fixture.v1", &fields[..23])?.to_vec(),
                );
            }
        }
    }
    mutate_after_fixture_digest(profile_fields)?;
    if profile_fields.len() == 18 {
        profile_fields[17] = Value::Bytes(
            contract_digest(b"PiglorOS.ConformanceProfile.v1", &profile_fields[..17])?.to_vec(),
        );
    }
    mutate_after_profile_digest(profile_fields)?;
    let profile_digest = match &profile_fields[17] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err("profile digest is not bytes".into()),
    };
    let new_profile_bytes = encode_value(&profile)?;
    profile_member_fields[1] = Value::Bytes(new_profile_bytes.clone());

    let Value::Array(manifest) = &mut archive_fields[0] else {
        return Err("manifest is not an array".into());
    };
    manifest[3] = Value::Bytes(profile_digest);
    let Value::Array(descriptors) = &mut manifest[4] else {
        return Err("manifest descriptors are not an array".into());
    };
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| {
            matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text("profile/CPF1.cbor".to_owned())))
        })
        .ok_or("profile descriptor is absent")?;
    let Value::Array(descriptor_fields) = descriptor else {
        return Err("profile descriptor is not an array".into());
    };
    descriptor_fields[1] = Value::Integer(u64::try_from(new_profile_bytes.len())?.into());
    descriptor_fields[2] = Value::Bytes(blake3::hash(&new_profile_bytes).as_bytes().to_vec());
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

fn mutate_archive(mutate: impl FnOnce(&mut [Value]) -> TestResult) -> TestResult<Vec<u8>> {
    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    mutate(fields)?;
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

fn mutate_unsealed_archive(mutate: impl FnOnce(&mut [Value]) -> TestResult) -> TestResult<Vec<u8>> {
    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    mutate(fields)?;
    encode_value(&archive)
}

fn archive_member_fields<'a>(
    archive: &'a mut [Value],
    path: &str,
) -> TestResult<&'a mut Vec<Value>> {
    let members = array_field(archive, 1, "archive members")?;
    let member = members
        .iter_mut()
        .find(|member| matches!(member, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(value)) if value == path)))
        .ok_or_else(|| format!("archive member {path} is absent"))?;
    match member {
        Value::Array(fields) => Ok(fields),
        _ => Err(format!("archive member {path} is not an array").into()),
    }
}

fn archive_descriptor_fields<'a>(
    archive: &'a mut [Value],
    path: &str,
) -> TestResult<&'a mut Vec<Value>> {
    let manifest = array_field(archive, 0, "manifest")?;
    let descriptors = array_field(manifest, 4, "member descriptors")?;
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| matches!(descriptor, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(value)) if value == path)))
        .ok_or_else(|| format!("archive descriptor {path} is absent"))?;
    match descriptor {
        Value::Array(fields) => Ok(fields),
        _ => Err(format!("archive descriptor {path} is not an array").into()),
    }
}

fn replace_archive_member_bytes(archive: &mut [Value], path: &str, bytes: &[u8]) -> TestResult {
    {
        let member = archive_member_fields(archive, path)?;
        replace_value(
            member,
            1,
            Value::Bytes(bytes.to_owned()),
            "archive member bytes",
        )?;
    }
    let descriptor = archive_descriptor_fields(archive, path)?;
    replace_value(
        descriptor,
        1,
        Value::Integer(u64::try_from(bytes.len())?.into()),
        "archive member length",
    )?;
    replace_value(
        descriptor,
        2,
        Value::Bytes(blake3::hash(bytes).as_bytes().to_vec()),
        "archive member digest",
    )
}

fn refresh_profile_registry_binding(archive: &mut [Value], registry_bytes: &[u8]) -> TestResult {
    let profile_bytes = match archive_member_fields(archive, "profile/CPF1.cbor")?.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile member is not bytes".into()),
    };
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let Value::Array(profile_fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    let binding = array_field(profile_fields, 8, "provider binding")?;
    let descriptor = array_field(binding, 0, "provider registry descriptor")?;
    replace_value(
        descriptor,
        2,
        Value::Integer(u64::try_from(registry_bytes.len())?.into()),
        "provider registry length",
    )?;
    replace_value(
        descriptor,
        3,
        Value::Bytes(blake3::hash(registry_bytes).as_bytes().to_vec()),
        "provider registry digest",
    )?;
    let profile_digest = contract_digest(b"PiglorOS.ConformanceProfile.v1", &profile_fields[..17])?;
    replace_value(
        profile_fields,
        17,
        Value::Bytes(profile_digest.to_vec()),
        "profile digest",
    )?;
    let profile_digest = match profile_fields.get(17) {
        Some(Value::Bytes(digest)) => digest.clone(),
        _ => return Err("profile digest is not bytes".into()),
    };
    let profile_bytes = encode_value(&profile)?;
    replace_archive_member_bytes(archive, "profile/CPF1.cbor", &profile_bytes)?;
    replace_value(
        array_field(archive, 0, "manifest")?,
        3,
        Value::Bytes(profile_digest),
        "manifest profile digest",
    )
}

fn mutate_provider_registry_fields(fields: &mut [Value], mutation: usize) -> TestResult<bool> {
    match mutation {
        0 => {
            replace_value(fields, 0, Value::Text("FPR0".to_owned()), "registry magic")?;
            Ok(false)
        }
        1 => {
            replace_value(fields, 1, Value::Integer(2_u64.into()), "registry version")?;
            Ok(false)
        }
        2 => {
            replace_value(fields, 2, Value::Array(Vec::new()), "registry providers")?;
            Ok(true)
        }
        3 => {
            replace_value(fields, 3, Value::Bytes(vec![0; 32]), "registry digest")?;
            Ok(false)
        }
        4 => {
            replace_value(
                array_field(fields, 2, "registry providers")?,
                0,
                Value::Array(Vec::new()),
                "registry provider entry",
            )?;
            Ok(true)
        }
        5 => {
            replace_value(
                array_field(
                    array_field(fields, 2, "registry providers")?,
                    0,
                    "provider entry",
                )?,
                4,
                Value::Integer(7_u64.into()),
                "provider claim layer",
            )?;
            Ok(true)
        }
        6 => {
            replace_value(
                array_field(
                    array_field(fields, 2, "registry providers")?,
                    0,
                    "provider entry",
                )?,
                5,
                Value::Integer(3_u64.into()),
                "provider subject adapter",
            )?;
            Ok(true)
        }
        7 => {
            replace_value(
                array_field(
                    array_field(
                        array_field(fields, 2, "registry providers")?,
                        0,
                        "provider entry",
                    )?,
                    6,
                    "provider package descriptor",
                )?,
                0,
                Value::Text("authority/providers/missing.cbor".to_owned()),
                "provider package path",
            )?;
            Ok(true)
        }
        8..=17 => mutate_provider_registry_extended(fields, mutation),
        _ => Err(format!("unsupported registry mutation {mutation}").into()),
    }
}

fn mutate_provider_registry_extended(fields: &mut [Value], mutation: usize) -> TestResult<bool> {
    let providers = array_field(fields, 2, "registry providers")?;
    if mutation == 16 {
        let duplicate = providers.first().ok_or("provider entry is absent")?.clone();
        providers.push(duplicate);
        return Ok(true);
    }
    let entry = array_field(providers, 0, "provider entry")?;
    match mutation {
        8 => replace_value(
            entry,
            0,
            Value::Text("INVALID".to_owned()),
            "provider identifier",
        )?,
        9 => replace_value(
            entry,
            1,
            Value::Text("01.0.0".to_owned()),
            "provider version",
        )?,
        10..=11 => replace_value(
            entry,
            mutation - 8,
            Value::Integer(65_536_u64.into()),
            "provider ABI",
        )?,
        12..=15 | 17 => {
            let descriptor = array_field(entry, 6, "provider package descriptor")?;
            let replacement = match mutation {
                12 => Value::Text("/invalid.cbor".to_owned()),
                13 => Value::Text("INVALID".to_owned()),
                14 => Value::Integer(0_u64.into()),
                15 => Value::Bytes(vec![0; 32]),
                17 => Value::Integer(999_u64.into()),
                _ => return Err(format!("unsupported registry descriptor {mutation}").into()),
            };
            replace_value(
                descriptor,
                if mutation == 17 { 2 } else { mutation - 12 },
                replacement,
                "provider package descriptor field",
            )?;
        }
        _ => return Err(format!("unsupported registry extension {mutation}").into()),
    }
    Ok(true)
}

fn mutate_provider_registry_archive(mutation: usize) -> TestResult<Vec<u8>> {
    mutate_provider_registry_archive_with(|fields| {
        mutate_provider_registry_fields(fields, mutation)
    })
}

fn mutate_provider_registry_archive_with(
    mutate: impl FnOnce(&mut [Value]) -> TestResult<bool>,
) -> TestResult<Vec<u8>> {
    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(archive_fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    let registry_bytes =
        match archive_member_fields(archive_fields, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1)?
            .get(1)
        {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("provider registry is not bytes".into()),
        };
    let mut registry: Value = ciborium::from_reader(registry_bytes.as_slice())?;
    let Value::Array(fields) = &mut registry else {
        return Err("provider registry is not an array".into());
    };
    if mutate(fields)? {
        let registry_digest =
            contract_digest(b"PiglorOS.Conformance.ProviderRegistry.v1", &fields[..3])?;
        replace_value(
            fields,
            3,
            Value::Bytes(registry_digest.to_vec()),
            "registry digest",
        )?;
    }
    let registry_bytes = encode_value(&registry)?;
    replace_archive_member_bytes(
        archive_fields,
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
        &registry_bytes,
    )?;
    refresh_profile_registry_binding(archive_fields, &registry_bytes)?;
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

fn mutate_provider_package_fields(fields: &mut [Value], mutation: usize) -> TestResult<bool> {
    match mutation {
        0 => {
            replace_value(fields, 0, Value::Text("FPP0".to_owned()), "package magic")?;
            Ok(false)
        }
        1 => {
            replace_value(fields, 1, Value::Integer(2_u64.into()), "package version")?;
            Ok(false)
        }
        2 => {
            replace_value(fields, 2, Value::Array(Vec::new()), "package provider key")?;
            Ok(false)
        }
        3 => {
            replace_value(fields, 5, Value::Array(Vec::new()), "package schemas")?;
            Ok(true)
        }
        4 => {
            replace_value(
                array_field(
                    array_field(fields, 5, "package schemas")?,
                    0,
                    "package schema",
                )?,
                0,
                Value::Integer(1_u64.into()),
                "package schema family",
            )?;
            Ok(true)
        }
        5 => {
            replace_value(
                array_field(
                    array_field(fields, 5, "package schemas")?,
                    0,
                    "package schema",
                )?,
                1,
                Value::Array(Vec::new()),
                "package schema descriptor",
            )?;
            Ok(true)
        }
        6 => {
            replace_value(
                array_field(fields, 6, "package licence descriptor")?,
                3,
                Value::Bytes(vec![0; 32]),
                "package licence digest",
            )?;
            Ok(true)
        }
        7 => {
            replace_value(fields, 11, Value::Bytes(vec![0; 32]), "package digest")?;
            Ok(false)
        }
        8..=21 => mutate_provider_package_extended(fields, mutation),
        _ => Err(format!("unsupported package mutation {mutation}").into()),
    }
}

fn mutate_provider_package_extended(fields: &mut [Value], mutation: usize) -> TestResult<bool> {
    match mutation {
        8..=9 => replace_value(
            array_field(fields, 2, "package provider key")?,
            mutation - 8,
            if mutation == 8 {
                Value::Text("INVALID".to_owned())
            } else {
                Value::Text("01.0.0".to_owned())
            },
            "package provider identity",
        )?,
        10..=11 => replace_value(
            array_field(fields, 2, "package provider key")?,
            mutation - 8,
            Value::Integer(65_536_u64.into()),
            "package provider ABI",
        )?,
        12 => replace_value(
            fields,
            3,
            Value::Integer(7_u64.into()),
            "package claim layer",
        )?,
        13 => replace_value(
            fields,
            4,
            Value::Integer(3_u64.into()),
            "package subject adapter",
        )?,
        14 => {
            array_field(fields, 5, "package schemas")?.pop();
        }
        15 => replace_value(
            array_field(fields, 5, "package schemas")?,
            0,
            Value::Array(Vec::new()),
            "package schema",
        )?,
        16..=19 => {
            let descriptor = array_field(
                array_field(
                    array_field(fields, 5, "package schemas")?,
                    0,
                    "package schema",
                )?,
                1,
                "package schema descriptor",
            )?;
            let replacement = match mutation {
                16 => Value::Text("/invalid.json".to_owned()),
                17 => Value::Text("INVALID".to_owned()),
                18 => Value::Integer(0_u64.into()),
                19 => Value::Bytes(vec![0; 32]),
                _ => return Err(format!("unsupported schema descriptor {mutation}").into()),
            };
            replace_value(
                descriptor,
                mutation - 16,
                replacement,
                "package schema descriptor field",
            )?;
        }
        20 => replace_value(fields, 7, Value::Null, "package notice descriptor")?,
        21 => {
            let schema_path = array_field(
                array_field(
                    array_field(fields, 5, "package schemas")?,
                    0,
                    "package schema",
                )?,
                1,
                "package schema descriptor",
            )?
            .first()
            .ok_or("package schema descriptor has no path")?
            .clone();
            replace_value(
                array_field(fields, 6, "package licence descriptor")?,
                0,
                schema_path,
                "colliding package licence path",
            )?;
        }
        _ => return Err(format!("unsupported package extension {mutation}").into()),
    }
    Ok(true)
}

fn mutate_provider_package_archive(mutation: usize) -> TestResult<Vec<u8>> {
    mutate_provider_package_archive_with(|fields| mutate_provider_package_fields(fields, mutation))
}

fn mutate_provider_package_archive_with(
    mutate: impl FnOnce(&mut [Value]) -> TestResult<bool>,
) -> TestResult<Vec<u8>> {
    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(archive_fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    let registry_bytes =
        match archive_member_fields(archive_fields, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1)?
            .get(1)
        {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("provider registry is not bytes".into()),
        };
    let mut registry: Value = ciborium::from_reader(registry_bytes.as_slice())?;
    let Value::Array(registry_fields) = &mut registry else {
        return Err("provider registry is not an array".into());
    };
    let package_path = match array_field(
        array_field(
            array_field(registry_fields, 2, "registry providers")?,
            0,
            "provider entry",
        )?,
        6,
        "package descriptor",
    )?
    .first()
    {
        Some(Value::Text(path)) => path.clone(),
        _ => return Err("provider package path is not text".into()),
    };
    let package_bytes = match archive_member_fields(archive_fields, &package_path)?.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("provider package is not bytes".into()),
    };
    let mut package: Value = ciborium::from_reader(package_bytes.as_slice())?;
    let Value::Array(package_fields) = &mut package else {
        return Err("provider package is not an array".into());
    };
    if mutate(package_fields)? {
        let package_digest = contract_digest(
            b"PiglorOS.Conformance.ProviderPackage.v1",
            &package_fields[..11],
        )?;
        replace_value(
            package_fields,
            11,
            Value::Bytes(package_digest.to_vec()),
            "package digest",
        )?;
    }
    let package_bytes = encode_value(&package)?;
    replace_archive_member_bytes(archive_fields, &package_path, &package_bytes)?;
    let package_descriptor = array_field(
        array_field(
            array_field(registry_fields, 2, "registry providers")?,
            0,
            "provider entry",
        )?,
        6,
        "package descriptor",
    )?;
    replace_value(
        package_descriptor,
        2,
        Value::Integer(u64::try_from(package_bytes.len())?.into()),
        "package length",
    )?;
    replace_value(
        package_descriptor,
        3,
        Value::Bytes(blake3::hash(&package_bytes).as_bytes().to_vec()),
        "package digest",
    )?;
    let registry_digest = contract_digest(
        b"PiglorOS.Conformance.ProviderRegistry.v1",
        &registry_fields[..3],
    )?;
    replace_value(
        registry_fields,
        3,
        Value::Bytes(registry_digest.to_vec()),
        "registry digest",
    )?;
    let registry_bytes = encode_value(&registry)?;
    replace_archive_member_bytes(
        archive_fields,
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
        &registry_bytes,
    )?;
    refresh_profile_registry_binding(archive_fields, &registry_bytes)?;
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

fn temporary_root(label: &str) -> TestResult<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("pigloros-{label}-{}-{nonce}", std::process::id())))
}

fn source_inventory_address() -> String {
    let digest: [u8; 32] =
        Sha256::digest(include_bytes!("../../../fixtures/conformance/SHA256SUMS")).into();
    pos_conformance::hex_digest(&digest)
}

struct TemporaryOutput(PathBuf);

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn release_files(root: &Path) -> TestResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[test]
fn current_signed_bundle_round_trips_through_typed_and_independent_verifiers() -> TestResult {
    for mode in [BundleModeV1::Local, BundleModeV1::AirGapped] {
        let bundle = signed_current_bundle(mode)?;
        bundle.validate()?;
        let manifest = bundle.manifest_bytes()?;
        assert!(!manifest.is_empty());
        assert_ne!(bundle.manifest_digest()?, [0; 32]);
        let archive = bundle.to_canonical_cbor()?;
        assert_eq!(ConformanceBundleV1::from_canonical_cbor(&archive)?, bundle);
        verify_archive_independently(&archive)?;
        let filename = bundle.release_filename()?;
        assert!(Path::new(&filename)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("cfb1")));
        assert_eq!(bundle.archive_digest()?, *blake3::hash(&archive).as_bytes());
        verify_archive_release_filename(&archive, &filename)?;
    }
    Ok(())
}

#[test]
fn current_bundle_pair_requires_profile_parity() -> TestResult {
    let local = signed_current_bundle(BundleModeV1::Local)?;
    let air_gapped = signed_current_bundle(BundleModeV1::AirGapped)?;
    let pair = ConformanceBundlePairV1 { local, air_gapped };
    assert_eq!(pair.validate(), Ok(()));

    let duplicate_local = pair.local.clone();
    assert_eq!(
        ConformanceBundlePairV1 {
            local: duplicate_local.clone(),
            air_gapped: duplicate_local,
        }
        .validate(),
        Err(BundleContractErrorV1::ModeParityMismatch)
    );

    let mut mismatched = pair;
    mismatched.air_gapped.manifest.profile_digest[0] ^= 1;
    let error = mismatched
        .validate()
        .err()
        .ok_or("mismatched profile identity accepted the bundle pair")?;
    assert!([
        BundleContractErrorV1::ProfileInvalid,
        BundleContractErrorV1::SignatureInvalid,
        BundleContractErrorV1::ModeParityMismatch,
    ]
    .contains(&error));
    Ok(())
}

#[test]
fn public_materializer_and_verifier_binaries_round_trip_current_archives() -> TestResult {
    let _guard = materializer_process_guard();
    let root = temporary_root("conformance-cli")?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let publication = root.join(source_inventory_address());
    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let status = Command::new(&materializer)
        .current_dir(&root)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg(&publication)
        .status()?;
    assert!(status.success());

    let files = release_files(&publication)?;
    let relative_files = files
        .iter()
        .map(|path| path.strip_prefix(&publication))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        relative_files
            .iter()
            .filter(|path| {
                path.starts_with("providers")
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "json")
            })
            .count(),
        49
    );
    assert!(relative_files
        .iter()
        .all(|path| !path.starts_with("support/schemas")));
    let archives = files
        .iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("cfb1"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(archives.len(), 14);
    let archive_bytes = archives
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()?;
    let archive_refs = archive_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    verify_release_tree_independently(&archive_refs)?;
    assert_eq!(
        verify_release_tree_independently(&archive_refs[..13]),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    let mut duplicate_mode = archive_refs.clone();
    duplicate_mode[1] = duplicate_mode[0];
    assert_eq!(
        verify_release_tree_independently(&duplicate_mode),
        Err(BundleContractErrorV1::ModeParityMismatch)
    );

    let foreign_registry_archive =
        signed_current_bundle(BundleModeV1::Local)?.to_canonical_cbor()?;
    let mut mismatched_registry = archive_refs.clone();
    mismatched_registry[0] = &foreign_registry_archive;
    assert_eq!(
        verify_release_tree_independently(&mismatched_registry),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    for (archive_path, bytes) in archives.iter().zip(&archive_bytes) {
        verify_archive_independently(bytes)?;
        let filename = archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("archive filename is not UTF-8")?;
        verify_archive_release_filename(bytes, filename)?;
    }
    let metadata_path = files
        .iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == "MATERIALIZATION-METADATA.json")
        })
        .ok_or("materialization metadata is absent")?;
    let metadata: serde_json::Value = serde_json::from_slice(&fs::read(metadata_path)?)?;
    assert_eq!(
        metadata["published_file_count"].as_u64(),
        Some(u64::try_from(files.len())?)
    );
    let verifier = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    assert!(Command::new(verifier).args(&archives).status()?.success());
    Ok(())
}

#[test]
fn independent_release_tree_requires_each_claim_layer() -> TestResult {
    let mut archives = Vec::new();
    for profile_index in 0..7 {
        for mode in [BundleModeV1::Local, BundleModeV1::AirGapped] {
            let mut inputs = current_bundle_inputs(mode)?;
            inputs.profile.profile_id = format!("duplicate-layer-profile-{profile_index}");
            inputs.profile.profile_digest = inputs.profile.digest();
            let archive = ConformanceBundleV1::materialize(
                &inputs.profile,
                mode,
                inputs.members,
                inputs.expected,
            )?
            .sign(&SigningKey::from_bytes(&[7; 32]))?
            .to_canonical_cbor()?;
            archives.push(archive);
        }
    }
    let archive_refs = archives.iter().map(Vec::as_slice).collect::<Vec<_>>();
    assert_eq!(
        verify_release_tree_independently(&archive_refs),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn privileged_materializer_test_drops_identity_and_rejects_foreign_parent() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let current_uid = Command::new("id").arg("-u").output()?;
    let running_as_root = current_uid.stdout == b"0\n";
    if !running_as_root {
        assert!(
            Command::new("sudo")
                .args(["-n", "true"])
                .status()?
                .success(),
            "public privilege-drop regression requires passwordless sudo"
        );
    }
    let user_identity = Command::new("id").args(["-u", "nobody"]).output()?;
    let group_identity = Command::new("id").args(["-g", "nobody"]).output()?;
    if !user_identity.status.success() || !group_identity.status.success() {
        return Err("root privilege-drop test requires the nobody identity".into());
    }
    let uid = std::str::from_utf8(&user_identity.stdout)?.trim();
    let gid = std::str::from_utf8(&group_identity.stdout)?.trim();

    let _guard = materializer_process_guard();
    let root = temporary_root("unprivileged-materializer")?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let source = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let executable = root.join("materializer-under-test");
    fs::copy(source, &executable)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
    let foreign_parent = root.join("foreign-parent");
    fs::create_dir(&foreign_parent)?;
    fs::set_permissions(&foreign_parent, fs::Permissions::from_mode(0o777))?;
    let mut chown = if running_as_root {
        Command::new("chown")
    } else {
        let mut command = Command::new("sudo");
        command.arg("-n").arg("chown");
        command
    };
    assert!(
        chown.arg("0:0").arg(&foreign_parent).status()?.success(),
        "privilege-drop test must create a foreign-owned parent"
    );
    let publication = foreign_parent.join(source_inventory_address());
    let mut materialize = if running_as_root {
        Command::new("setpriv")
    } else {
        let mut command = Command::new("sudo");
        command.arg("-n").arg("setpriv");
        command
    };
    let output = materialize
        .current_dir(&root)
        .args(["--clear-groups", "--regid", gid, "--reuid", uid, "--"])
        .arg("env")
        .arg(concat!(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY=",
            "0707070707070707070707070707070707070707070707070707070707070707"
        ))
        .arg(&executable)
        .arg(&publication)
        .output()?;
    assert!(
        !output.status.success(),
        "foreign-owned publication parent must be denied"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("UntrustedOutputDirectory"),
        "public CLI must expose the typed untrusted-parent denial"
    );
    assert!(
        !publication.exists(),
        "denial must not publish a final tree"
    );
    assert_eq!(
        fs::read_dir(&foreign_parent)?.count(),
        0,
        "denial must not leave staging residue"
    );
    Ok(())
}

#[test]
fn public_materializer_fingerprint_is_stable_and_invalid_invocations_fail() -> TestResult {
    let _guard = materializer_process_guard();
    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let key = "0707070707070707070707070707070707070707070707070707070707070707";
    let first = Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg("--fingerprint")
        .output()?;
    let second = Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg("--fingerprint")
        .output()?;
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stdout.strip_suffix(b"\n").map(<[u8]>::len), Some(64));

    let root = temporary_root("invalid-materializer")?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let output = root.join(source_inventory_address());
    let wrong_address = root.join("not-the-source-inventory-digest");
    assert!(!Command::new(&materializer).status()?.success());
    assert!(!Command::new(&materializer)
        .arg(&output)
        .arg("unexpected-second-output")
        .status()?
        .success());
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg(&wrong_address)
        .status()?
        .success());
    assert!(!Command::new(&materializer).arg(&output).status()?.success());
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", "not-a-key")
        .arg(&output)
        .status()?
        .success());
    fs::create_dir_all(&output)?;
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg(&output)
        .status()?
        .success());

    let relative_root = temporary_root("relative-materializer")?;
    let _relative_cleanup = TemporaryOutput(relative_root.clone());
    fs::create_dir_all(&relative_root)?;
    assert!(Command::new(&materializer)
        .current_dir(&relative_root)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg(source_inventory_address())
        .status()?
        .success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn public_binaries_reject_unsafe_filesystem_boundaries() -> TestResult {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = temporary_root("unsafe-public-boundaries")?;
    let _cleanup = TemporaryOutput(root.clone());
    let trusted = root.join("trusted");
    fs::create_dir_all(&trusted)?;
    let alias = root.join("alias");
    symlink(&trusted, &alias)?;

    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let signing_key = "0707070707070707070707070707070707070707070707070707070707070707";
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key,)
        .arg(alias.join(source_inventory_address()))
        .status()?
        .success());

    let absent_parent = root.join("absent").join(source_inventory_address());
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(absent_parent)
        .status()?
        .success());

    let regular_parent = root.join("regular-parent");
    fs::write(&regular_parent, b"not a directory")?;
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(regular_parent.join(source_inventory_address()))
        .status()?
        .success());

    let untrusted = root.join("untrusted");
    fs::create_dir(&untrusted)?;
    fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777))?;
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(untrusted.join(source_inventory_address()))
        .status()?
        .success());

    let trusted_sticky = root.join("trusted-sticky");
    fs::create_dir(&trusted_sticky)?;
    fs::set_permissions(&trusted_sticky, fs::Permissions::from_mode(0o1777))?;
    assert!(Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", signing_key)
        .arg(trusted_sticky.join(source_inventory_address()))
        .status()?
        .success());

    let verifier = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    assert!(!Command::new(&verifier).status()?.success());
    assert!(!Command::new(&verifier).arg(&trusted).status()?.success());

    let invalid_archive = trusted.join("invalid.cfb1");
    fs::write(&invalid_archive, b"not a canonical archive")?;
    assert!(!Command::new(&verifier)
        .arg(&invalid_archive)
        .status()?
        .success());
    let archive_alias = root.join("archive-alias.cfb1");
    symlink(&invalid_archive, &archive_alias)?;
    assert!(!Command::new(&verifier)
        .arg(&archive_alias)
        .status()?
        .success());

    let oversized_archive = trusted.join("oversized.cfb1");
    fs::File::create(&oversized_archive)?.set_len(1024 * 1024 * 1024 + 1)?;
    assert!(!Command::new(verifier)
        .arg(&oversized_archive)
        .status()?
        .success());
    Ok(())
}

#[test]
fn typed_bundle_validation_rejects_manifest_and_member_tampering() -> TestResult {
    let original = signed_current_bundle(BundleModeV1::Local)?;

    let mut wrong_magic = original.clone();
    wrong_magic.manifest.magic = "BAD1".to_owned();
    assert_eq!(
        wrong_magic.validate(),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );

    let mut wrong_lifecycle = original.clone();
    wrong_lifecycle.manifest.lifecycle = ProfileLifecycleV1::Candidate;
    assert_eq!(
        wrong_lifecycle.validate(),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );

    let mut missing_descriptor = original.clone();
    missing_descriptor.manifest.members.pop();
    assert_eq!(
        missing_descriptor.validate(),
        Err(BundleContractErrorV1::MemberOutOfBounds)
    );

    let mut unordered = original.clone();
    unordered.members.swap(0, 1);
    assert_eq!(
        unordered.validate(),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );

    let mut changed_bytes = original.clone();
    changed_bytes.members[0].bytes.push(1);
    assert_eq!(
        changed_bytes.validate(),
        Err(BundleContractErrorV1::MemberDigestMismatch)
    );

    let mut changed_descriptor = original;
    changed_descriptor.manifest.members[0].digest[0] ^= 1;
    assert_eq!(
        changed_descriptor.validate(),
        Err(BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

#[test]
fn public_bundle_entry_points_propagate_invalid_profile_and_bundle_state() -> TestResult {
    let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
    inputs.profile.profile_digest[0] ^= 1;
    assert_eq!(
        ConformanceBundleV1::materialize(
            &inputs.profile,
            BundleModeV1::Local,
            inputs.members,
            inputs.expected,
        ),
        Err(BundleContractErrorV1::ProfileInvalid)
    );

    let mut invalid = signed_current_bundle(BundleModeV1::Local)?;
    invalid.manifest.magic = "BAD1".to_owned();
    assert_eq!(
        invalid.clone().sign(&SigningKey::from_bytes(&[7; 32])),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        invalid.to_canonical_cbor(),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        invalid.archive_digest(),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        invalid.release_filename(),
        Err(BundleContractErrorV1::NonCanonicalOrder)
    );

    let mut missing_profile = signed_current_bundle(BundleModeV1::Local)?;
    missing_profile
        .members
        .retain(|member| member.role != BundleMemberRoleV1::Profile);
    missing_profile
        .manifest
        .members
        .retain(|descriptor| descriptor.role != BundleMemberRoleV1::Profile);
    assert_eq!(
        missing_profile.validate(),
        Err(BundleContractErrorV1::MemberMissing)
    );

    let mut invalid_key = signed_current_bundle(BundleModeV1::Local)?;
    invalid_key.signer_public_key = pos_core::PublicKey::from_bytes([0xff; 32]);
    assert_eq!(
        invalid_key.validate(),
        Err(BundleContractErrorV1::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn both_archive_decoders_reject_top_level_shape_errors() -> TestResult {
    for malformed in [
        Value::Null,
        Value::Array(Vec::new()),
        Value::Array(vec![Value::Null; 4]),
    ] {
        let bytes = encode_value(&malformed)?;
        assert_archive_rejected_by_both(&bytes, "top-level archive shape");
    }
    Ok(())
}

#[test]
fn typed_bundle_validation_rejects_profile_expected_and_signature_tampering() -> TestResult {
    let original = signed_current_bundle(BundleModeV1::Local)?;

    let mut profile_digest = original.clone();
    profile_digest.manifest.profile_digest[0] ^= 1;
    assert_eq!(
        profile_digest.validate(),
        Err(BundleContractErrorV1::ProfileInvalid)
    );

    let mut missing_expected = original.clone();
    missing_expected.manifest.expected_results.clear();
    assert_eq!(
        missing_expected.validate(),
        Err(BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut wrong_expected_mode = original.clone();
    wrong_expected_mode.manifest.expected_results[0].mode = BundleModeV1::AirGapped;
    assert_eq!(
        wrong_expected_mode.validate(),
        Err(BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut wrong_expected_digest = original.clone();
    wrong_expected_digest.manifest.expected_results[0].digest[0] ^= 1;
    assert_eq!(
        wrong_expected_digest.validate(),
        Err(BundleContractErrorV1::ExpectedResultMismatch)
    );

    let mut wrong_signature = original.clone();
    wrong_signature.signature = pos_core::Signature::from_bytes([0; 64]);
    assert_eq!(
        wrong_signature.validate(),
        Err(BundleContractErrorV1::SignatureInvalid)
    );

    let mut wrong_key = original;
    wrong_key.signer_public_key = pos_core::PublicKey::from_bytes([0; 32]);
    assert_eq!(
        wrong_key.validate(),
        Err(BundleContractErrorV1::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn typed_bundle_rejects_undeclared_provider_package_member() -> TestResult {
    let mut bundle = signed_current_bundle(BundleModeV1::Local)?;
    let member = BundleMemberV1::fixture_provider_package(
        "authority/providers/undeclared.cbor",
        b"undeclared".to_vec(),
    );
    let descriptor = BundleMemberDescriptorV1 {
        path: member.path.clone(),
        size_bytes: u64::try_from(member.bytes.len())?,
        digest: member.digest,
        role: member.role,
    };
    bundle.members.push(member);
    bundle.manifest.members.push(descriptor);
    bundle
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    bundle.manifest.members.sort();
    assert_eq!(
        bundle.validate(),
        Err(BundleContractErrorV1::UndeclaredMember)
    );
    Ok(())
}

#[test]
fn typed_bundle_rejects_undeclared_non_provider_member() -> TestResult {
    let mut bundle = signed_current_bundle(BundleModeV1::Local)?;
    let member = BundleMemberV1::supporting(
        "support/undeclared-notice.txt",
        b"undeclared".to_vec(),
        BundleMemberRoleV1::Notice,
    );
    bundle.manifest.members.push(BundleMemberDescriptorV1 {
        path: member.path.clone(),
        size_bytes: u64::try_from(member.bytes.len())?,
        digest: member.digest,
        role: member.role,
    });
    bundle.members.push(member);
    bundle
        .members
        .sort_by(|left, right| left.path.cmp(&right.path));
    bundle.manifest.members.sort();
    assert_eq!(
        bundle.validate(),
        Err(BundleContractErrorV1::UndeclaredMember)
    );
    Ok(())
}

#[test]
fn typed_bundle_binds_profile_authority_digests_to_members() -> TestResult {
    let mut bundle = signed_current_bundle(BundleModeV1::Local)?;
    let member = bundle
        .members
        .iter_mut()
        .find(|member| member.path == "support/normative-requirements.md")
        .ok_or("normative specification member is absent")?;
    member.bytes.push(b'!');
    member.digest = *blake3::hash(&member.bytes).as_bytes();
    let descriptor = bundle
        .manifest
        .members
        .iter_mut()
        .find(|descriptor| descriptor.path == member.path)
        .ok_or("normative specification descriptor is absent")?;
    descriptor.size_bytes = u64::try_from(member.bytes.len())?;
    descriptor.digest = member.digest;
    assert_eq!(
        bundle.validate(),
        Err(BundleContractErrorV1::MemberDigestMismatch)
    );
    Ok(())
}

#[test]
fn materialize_requires_draft_profile_and_complete_expected_binding() -> TestResult {
    let mut stable = current_bundle_inputs(BundleModeV1::Local)?;
    stable.profile.lifecycle = ProfileLifecycleV1::Candidate;
    stable.profile.profile_digest = stable.profile.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &stable.profile,
            BundleModeV1::Local,
            stable.members,
            stable.expected,
        ),
        Err(BundleContractErrorV1::LifecycleInvalid)
    );

    let missing = current_bundle_inputs(BundleModeV1::Local)?;
    assert_eq!(
        ConformanceBundleV1::materialize(
            &missing.profile,
            BundleModeV1::Local,
            missing.members,
            Vec::new(),
        ),
        Err(BundleContractErrorV1::ExpectedResultMismatch)
    );
    Ok(())
}

#[test]
fn materialize_rejects_each_missing_provider_support_member() -> TestResult {
    let paths = [
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
        "providers/example/schemas/6.schema.json",
        "support/LICENSE",
        "support/NOTICE",
        "support/sbom.json",
        "support/source-provenance.json",
        "support/build-provenance.json",
        "support/publication-review.json",
        "support/limitations.md",
    ];
    for path in paths {
        let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
        inputs.members.retain(|member| member.path != path);
        assert_eq!(
            ConformanceBundleV1::materialize(
                &inputs.profile,
                BundleModeV1::Local,
                inputs.members,
                inputs.expected,
            ),
            Err(BundleContractErrorV1::MemberMissing),
            "missing support member {path} was accepted",
        );
    }
    Ok(())
}

fn remove_archive_member_and_descriptor(archive: &mut [Value], path: &str) -> TestResult {
    let members = array_field(archive, 1, "archive members")?;
    let member_index = members
        .iter()
        .position(|member| {
            matches!(member, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(value)) if value == path))
        })
        .ok_or_else(|| format!("archive member {path} is absent"))?;
    members.remove(member_index);

    let descriptors = array_field(
        array_field(archive, 0, "manifest")?,
        4,
        "member descriptors",
    )?;
    let descriptor_index = descriptors
        .iter()
        .position(|descriptor| {
            matches!(descriptor, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(value)) if value == path))
        })
        .ok_or_else(|| format!("archive descriptor {path} is absent"))?;
    descriptors.remove(descriptor_index);
    Ok(())
}

#[test]
fn independent_verifier_rejects_provider_packages_with_missing_support_members() -> TestResult {
    for path in [
        "providers/example/schemas/0.schema.json",
        "providers/example/schemas/6.schema.json",
        "support/LICENSE",
        "support/NOTICE",
        "support/sbom.json",
        "support/source-provenance.json",
        "support/build-provenance.json",
        "support/publication-review.json",
        "support/limitations.md",
    ] {
        let archive =
            mutate_archive(|archive| remove_archive_member_and_descriptor(archive, path))?;
        assert_archive_rejected_by_both(&archive, path);
    }
    Ok(())
}

#[test]
fn archive_decoders_reject_a_noncanonical_manifest_version() -> TestResult {
    let canonical = signed_current_bundle(BundleModeV1::Local)?.to_canonical_cbor()?;
    let marker = [0x64, b'C', b'F', b'B', b'1', 0x00];
    let version_index = canonical
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|index| index + marker.len() - 1)
        .ok_or("canonical CFB1 lifecycle marker must exist")?;
    let mut noncanonical = canonical;
    noncanonical.splice(version_index..=version_index, [0x18, 0x00]);
    assert_archive_rejected_by_both(&noncanonical, "noncanonical manifest lifecycle");
    Ok(())
}

#[test]
fn materialize_rejects_an_unused_required_provider() -> TestResult {
    let mut unused_required = current_bundle_inputs(BundleModeV1::Local)?;
    let mut other_provider = provider_key();
    other_provider.provider_id = "pigloros.fixture.other".to_owned();
    unused_required
        .profile
        .fixture_provider_registry
        .required_provider_keys
        .push(other_provider);
    unused_required
        .profile
        .fixture_provider_registry
        .required_provider_keys
        .sort();
    unused_required.profile.profile_digest = unused_required.profile.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &unused_required.profile,
            BundleModeV1::Local,
            unused_required.members,
            unused_required.expected,
        ),
        Err(BundleContractErrorV1::ProfileInvalid),
    );
    Ok(())
}

#[test]
fn materialize_rejects_unknown_provider_and_family_schema_mismatch() -> TestResult {
    let mut unknown_provider = current_bundle_inputs(BundleModeV1::Local)?;
    let mut other_provider = provider_key();
    other_provider.provider_id = "pigloros.fixture.other".to_owned();
    unknown_provider.profile.fixtures[0].provider_key = other_provider.clone();
    unknown_provider.profile.fixtures[0].fixture_digest =
        unknown_provider.profile.fixtures[0].digest();
    unknown_provider
        .profile
        .fixture_provider_registry
        .required_provider_keys = vec![other_provider];
    unknown_provider.profile.profile_digest = unknown_provider.profile.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &unknown_provider.profile,
            BundleModeV1::Local,
            unknown_provider.members,
            unknown_provider.expected,
        ),
        Err(BundleContractErrorV1::ProfileInvalid),
    );

    let mut wrong_schema = current_bundle_inputs(BundleModeV1::Local)?;
    wrong_schema.profile.fixtures[0].schema = artifact(
        "providers/example/schemas/1.schema.json",
        "application/schema+json",
        CURRENT_SCHEMA_BYTES[1],
    )?;
    wrong_schema.profile.fixtures[0].fixture_digest = wrong_schema.profile.fixtures[0].digest();
    wrong_schema.profile.profile_digest = wrong_schema.profile.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &wrong_schema.profile,
            BundleModeV1::Local,
            wrong_schema.members,
            wrong_schema.expected,
        ),
        Err(BundleContractErrorV1::ProfileInvalid),
    );
    Ok(())
}

#[test]
fn materialize_rejects_more_expected_results_than_selected_fixtures() -> TestResult {
    let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
    let extra_path = "expected/extra.json";
    let extra_member = BundleMemberV1::expected_result(extra_path, EXPECTED_BYTES.to_vec());
    inputs.profile.fixtures[0].auxiliary.push(artifact(
        extra_path,
        "application/json",
        EXPECTED_BYTES,
    )?);
    inputs.profile.fixtures[0]
        .auxiliary
        .sort_by(|left, right| left.member_path.cmp(&right.member_path));
    inputs.profile.fixtures[0].fixture_digest = inputs.profile.fixtures[0].digest();
    inputs.profile.profile_digest = inputs.profile.digest();
    inputs.expected.push(BundleExpectedResultV1 {
        case_id: "example-positive".to_owned(),
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        execution_profile_digest: digest(31),
        mode: BundleModeV1::Local,
        member_path: extra_path.to_owned(),
        digest: extra_member.digest,
    });
    inputs.expected.sort();
    inputs.members.push(extra_member);
    assert_eq!(
        ConformanceBundleV1::materialize(
            &inputs.profile,
            BundleModeV1::Local,
            inputs.members,
            inputs.expected,
        ),
        Err(BundleContractErrorV1::ExpectedResultMismatch),
    );
    Ok(())
}

#[test]
fn bundle_pair_rejects_valid_bundles_for_different_profiles() -> TestResult {
    let local = signed_current_bundle(BundleModeV1::Local)?;
    let mut inputs = current_bundle_inputs(BundleModeV1::AirGapped)?;
    inputs.profile.profile_id = "pigloros.current.other".to_owned();
    inputs.profile.profile_digest = inputs.profile.digest();
    let air_gapped = ConformanceBundleV1::materialize(
        &inputs.profile,
        BundleModeV1::AirGapped,
        inputs.members,
        inputs.expected,
    )?
    .sign(&SigningKey::from_bytes(&[7; 32]))?;
    assert_eq!(
        ConformanceBundlePairV1 { local, air_gapped }.validate(),
        Err(BundleContractErrorV1::ModeParityMismatch),
    );
    Ok(())
}

#[test]
fn archive_decoders_reject_trailing_cbor_items() -> TestResult {
    let mut archive = signed_current_bundle(BundleModeV1::Local)?.to_canonical_cbor()?;
    archive.push(0);
    assert_archive_rejected_by_both(&archive, "trailing CBOR item");
    Ok(())
}

fn mutate_profile_fields(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        0..=19 => mutate_profile_header_fields(profile, mutation),
        20..=31 => mutate_profile_policy_fields(profile, mutation),
        32..=40 => mutate_profile_fixture_core_fields(profile, mutation),
        41..=48 => mutate_profile_fixture_tail_fields(profile, mutation),
        49..=73 => mutate_profile_text_contracts(profile, mutation),
        74..=90 => mutate_profile_nested_contracts(profile, mutation),
        91..=102 => mutate_profile_order_and_shape_contracts(profile, mutation),
        _ => Err(format!("unsupported profile mutation {mutation}").into()),
    }
}

fn mutate_profile_order_and_shape_contracts(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        91 => replace_value(
            profile,
            10,
            Value::Array(vec![Value::Array(Vec::new())]),
            "allowed divergence",
        ),
        92 => replace_value(
            profile,
            10,
            Value::Array(vec![Value::Array(vec![
                Value::Integer(9_u64.into()),
                Value::Bytes(vec![1]),
            ])]),
            "allowed divergence classification",
        ),
        93 => replace_value(
            profile,
            10,
            Value::Array(vec![Value::Array(vec![
                Value::Integer(0_u64.into()),
                Value::Bytes(Vec::new()),
            ])]),
            "allowed divergence coordinate",
        ),
        94 | 95 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                11,
                "strict oracle",
            )?,
            0,
            Value::Integer((if mutation == 94 { 0_u64 } else { 2 }).into()),
            "strict oracle kind",
        ),
        96 => {
            let executions = array_field(profile, 7, "profile executions")?;
            executions.push(
                executions
                    .first()
                    .ok_or("profile execution is absent")?
                    .clone(),
            );
            Ok(())
        }
        97 => {
            let providers = array_field(
                array_field(profile, 8, "provider binding")?,
                1,
                "required providers",
            )?;
            providers.push(
                providers
                    .first()
                    .ok_or("required provider is absent")?
                    .clone(),
            );
            Ok(())
        }
        98 => {
            let fixtures = array_field(profile, 9, "fixtures")?;
            fixtures.push(fixtures.first().ok_or("fixture is absent")?.clone());
            Ok(())
        }
        99 => replace_value(
            array_field(
                array_field(profile, 8, "provider binding")?,
                0,
                "provider registry descriptor",
            )?,
            0,
            Value::Text("authority/other-registry.cbor".to_owned()),
            "provider registry path",
        ),
        100 => replace_value(
            profile,
            3,
            Value::Text("1".repeat(65)),
            "oversized semantic version",
        ),
        101 => replace_value(
            profile,
            3,
            Value::Text("é.0.0".to_owned()),
            "non-ASCII semantic version",
        ),
        102 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                21,
                "fixture provenance",
            )?,
            3,
            Value::Bytes(vec![99; 32]),
            "fixture source provenance digest",
        ),
        _ => Err(format!("unsupported order or shape mutation {mutation}").into()),
    }
}

fn mutate_profile_text_contracts(profile: &mut [Value], mutation: usize) -> TestResult {
    let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
    let value = match mutation {
        49 | 66 => String::new(),
        50 => "a".repeat(129),
        51 => "é".to_owned(),
        52 => "-fixture".to_owned(),
        53 => "Fixture".to_owned(),
        54 => "1.0.0+".to_owned(),
        55 => "1.0.0+x+y".to_owned(),
        56 => "1.0.0-".to_owned(),
        57 => "1.0".to_owned(),
        58 => "1.0.0.0".to_owned(),
        59 => "01.0.0".to_owned(),
        60 => "12345678901.0.0".to_owned(),
        61 => "x.0.0".to_owned(),
        62 => "1.0.0-a..b".to_owned(),
        63 => "1.0.0-01".to_owned(),
        64 => "1.0.0-a_b".to_owned(),
        65 => "1.0.0+a..b".to_owned(),
        67 => "a".repeat(513),
        68 => "/absolute".to_owned(),
        69 => "a\\b".to_owned(),
        70 => "a\0b".to_owned(),
        71 => (0..17).map(|_| "a").collect::<Vec<_>>().join("/"),
        72 => "a//b".to_owned(),
        73 => "a/../b".to_owned(),
        _ => return Err(format!("unsupported text mutation {mutation}").into()),
    };
    match mutation {
        49..=53 => replace_value(profile, 2, Value::Text(value), "profile identifier"),
        54..=65 => replace_value(profile, 3, Value::Text(value), "profile version"),
        66..=73 => replace_value(
            array_field(fixture, 8, "fixture schema descriptor")?,
            0,
            Value::Text(value),
            "fixture schema path",
        ),
        _ => Err(format!("unsupported text mutation {mutation}").into()),
    }
}

fn mutate_profile_nested_contracts(profile: &mut [Value], mutation: usize) -> TestResult {
    let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
    match mutation {
        74 => replace_value(
            array_field(fixture, 8, "fixture schema descriptor")?,
            0,
            Value::Text(".".to_owned()),
            "fixture schema path",
        ),
        75 => replace_value(
            array_field(fixture, 8, "fixture schema descriptor")?,
            0,
            Value::Text("a/".to_owned() + &"b".repeat(129)),
            "fixture schema path",
        ),
        76..=83 => {
            let media_type = match mutation {
                76 => "ab",
                77 => "textplain",
                78 => "a/b/c",
                79 => "/json",
                80 => "json/",
                81 => "Text/plain",
                82 => "text/pl@in",
                83 => "téxt/plain",
                _ => return Err(format!("unsupported media type mutation {mutation}").into()),
            };
            replace_value(
                array_field(fixture, 8, "fixture schema descriptor")?,
                1,
                Value::Text(media_type.to_owned()),
                "fixture schema media type",
            )
        }
        84 => replace_value(
            array_field(fixture, 11, "strict oracle")?,
            2,
            Value::Null,
            "active strict oracle value",
        ),
        85 => replace_value(
            array_field(fixture, 11, "strict oracle")?,
            1,
            Value::Bytes(vec![1]),
            "inactive strict oracle value",
        ),
        86 => replace_value(
            array_field(fixture, 18, "capability policy")?,
            1,
            Value::Array(vec![
                Value::Text("z".to_owned()),
                Value::Text("a".to_owned()),
            ]),
            "capability identifiers",
        ),
        87 => replace_value(
            array_field(fixture, 18, "capability policy")?,
            1,
            Value::Array(vec![Value::Integer(1_u64.into())]),
            "capability identifiers",
        ),
        88 => replace_value(
            array_field(profile, 11, "evaluator protocol")?,
            1,
            Value::Bytes(vec![0; 32]),
            "evaluator input digest",
        ),
        89 => replace_value(
            array_field(
                array_field(profile, 11, "evaluator protocol")?,
                4,
                "evaluator hard caps",
            )?,
            9,
            Value::Integer(1_048_577_u64.into()),
            "evaluator final hard cap",
        ),
        90 => replace_value(
            array_field(profile, 12, "independence requirements")?,
            3,
            Value::Bytes(vec![0; 32]),
            "independent implementation digest",
        ),
        _ => Err(format!("unsupported nested mutation {mutation}").into()),
    }
}

fn mutate_profile_header_fields(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        0 => replace_value(profile, 0, Value::Text("BAD1".to_owned()), "profile magic"),
        1 => replace_value(profile, 1, Value::Integer(2_u64.into()), "profile version"),
        2 => replace_value(
            profile,
            2,
            Value::Text("Invalid Profile".to_owned()),
            "profile identifier",
        ),
        3 => replace_value(
            profile,
            3,
            Value::Text("01.0.0".to_owned()),
            "profile version",
        ),
        4 => replace_value(
            profile,
            4,
            Value::Integer(1_u64.into()),
            "profile lifecycle",
        ),
        5 => replace_value(profile, 7, Value::Array(Vec::new()), "profile executions"),
        6 => replace_value(
            array_field(profile, 8, "provider binding")?,
            1,
            Value::Array(Vec::new()),
            "required providers",
        ),
        7..=19 => mutate_fixture_fields(array_field(profile, 9, "fixtures")?, mutation),
        _ => Err(format!("unsupported profile mutation {mutation}").into()),
    }
}

fn mutate_profile_policy_fields(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        20 => replace_value(
            profile,
            16,
            Value::Bytes(vec![1; 31]),
            "fixture contract policy digest",
        ),
        21 => replace_value(
            array_field(profile, 11, "evaluator protocol")?,
            0,
            Value::Text(String::new()),
            "protocol identifier",
        ),
        22 => replace_value(
            array_field(
                array_field(profile, 11, "evaluator protocol")?,
                4,
                "evaluator hard caps",
            )?,
            0,
            Value::Integer(0_u64.into()),
            "profile byte cap",
        ),
        23 => replace_value(
            array_field(profile, 12, "independence requirements")?,
            0,
            Value::Null,
            "technical independence requirement",
        ),
        24 => replace_value(
            profile,
            5,
            Value::Bytes(vec![0; 32]),
            "normative specification digest",
        ),
        25 => replace_value(
            profile,
            6,
            Value::Bytes(vec![0; 32]),
            "execution matrix digest",
        ),
        26 => replace_value(
            profile,
            13,
            Value::Bytes(vec![0; 32]),
            "fixture policy digest",
        ),
        27 => replace_value(profile, 14, Value::Bytes(vec![0; 32]), "limitations digest"),
        28 => replace_value(profile, 15, Value::Bytes(vec![0; 32]), "provenance digest"),
        29 => replace_value(
            array_field(profile, 7, "profile executions")?,
            0,
            Value::Bytes(vec![1; 31]),
            "execution digest",
        ),
        30 => replace_value(
            array_field(
                array_field(profile, 8, "provider binding")?,
                0,
                "provider registry descriptor",
            )?,
            0,
            Value::Text("../registry.cbor".to_owned()),
            "registry member path",
        ),
        31 => replace_value(
            array_field(
                array_field(
                    array_field(profile, 8, "provider binding")?,
                    1,
                    "required providers",
                )?,
                0,
                "required provider",
            )?,
            1,
            Value::Text("01.0.0".to_owned()),
            "provider semantic version",
        ),
        _ => Err(format!("unsupported profile mutation {mutation}").into()),
    }
}

fn mutate_profile_fixture_core_fields(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        32 => replace_value(
            array_field(profile, 9, "fixtures")?,
            0,
            Value::Array(Vec::new()),
            "fixture record",
        ),
        33 => replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            0,
            Value::Text(String::new()),
            "fixture case identifier",
        ),
        34 => replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            1,
            Value::Integer(1_u64.into()),
            "fixture mandatory flag",
        ),
        35 => replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            6,
            Value::Bytes(vec![1; 31]),
            "fixture execution digest",
        ),
        36 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                7,
                "fixture modes",
            )?,
            0,
            Value::Integer(2_u64.into()),
            "fixture mode",
        ),
        37 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                8,
                "fixture schema descriptor",
            )?,
            1,
            Value::Text("not-a-media-type".to_owned()),
            "fixture schema media type",
        ),
        38 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                9,
                "fixture payload descriptor",
            )?,
            2,
            Value::Integer(0_u64.into()),
            "fixture payload size",
        ),
        39 => replace_value(
            array_field(
                array_field(
                    array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                    10,
                    "fixture auxiliary descriptors",
                )?,
                0,
                "fixture auxiliary descriptor",
            )?,
            3,
            Value::Bytes(vec![0; 32]),
            "fixture auxiliary digest",
        ),
        40 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                11,
                "strict oracle",
            )?,
            2,
            Value::Null,
            "strict oracle failure",
        ),
        _ => Err(format!("unsupported profile mutation {mutation}").into()),
    }
}

fn mutate_profile_fixture_tail_fields(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        41 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                13,
                "expected verification error",
            )?,
            0,
            Value::Text(String::new()),
            "expected verification error owner",
        ),
        42 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                18,
                "capability policy",
            )?,
            0,
            Value::Integer(0_u64.into()),
            "network capability",
        ),
        43 => replace_value(
            array_field(
                array_field(
                    array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                    18,
                    "capability policy",
                )?,
                1,
                "capability identifiers",
            )?,
            0,
            Value::Integer(1_u64.into()),
            "capability identifier",
        ),
        44 => replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                21,
                "fixture provenance",
            )?,
            1,
            Value::Bytes(vec![0; 32]),
            "fixture notice digest",
        ),
        45 => replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            19,
            Value::Bytes(vec![1; 31]),
            "trust policy snapshot digest",
        ),
        46 => replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            20,
            Value::Bytes(vec![1; 31]),
            "release admission digest",
        ),
        47 => replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            22,
            Value::Array(Vec::new()),
            "fixture transition",
        ),
        48 => replace_value(
            profile,
            16,
            Value::Bytes(vec![1; 31]),
            "previous profile digest",
        ),
        _ => Err(format!("unsupported profile mutation {mutation}").into()),
    }
}

fn mutate_fixture_fields(fixtures: &mut [Value], mutation: usize) -> TestResult {
    let fixture = array_field(fixtures, 0, "fixture")?;
    match mutation {
        7 => replace_value(
            fixture,
            2,
            Value::Integer(7_u64.into()),
            "fixture claim layer",
        ),
        8 => replace_value(fixture, 3, Value::Integer(7_u64.into()), "fixture family"),
        9 => replace_value(
            array_field(fixture, 4, "fixture provider")?,
            0,
            Value::Text("INVALID".to_owned()),
            "provider identifier",
        ),
        10 => replace_value(fixture, 5, Value::Integer(3_u64.into()), "subject adapter"),
        11 => replace_value(fixture, 7, Value::Array(Vec::new()), "fixture modes"),
        12 => replace_value(
            array_field(fixture, 11, "strict oracle")?,
            0,
            Value::Integer(3_u64.into()),
            "strict oracle kind",
        ),
        13 => replace_value(
            array_field(fixture, 16, "deterministic budget")?,
            0,
            Value::Integer(0_u64.into()),
            "memory budget",
        ),
        14 => replace_value(
            array_field(fixture, 17, "operational safety")?,
            0,
            Value::Integer(0_u64.into()),
            "watchdog",
        ),
        15 => replace_value(fixture, 18, Value::Null, "capability policy"),
        16 => replace_value(
            fixture,
            12,
            Value::Integer(6_u64.into()),
            "verification outcome",
        ),
        17 => replace_value(fixture, 14, Value::Integer(5_u64.into()), "replay claim"),
        18 => replace_value(fixture, 15, Value::Integer(4_u64.into()), "redaction state"),
        19 => replace_value(
            array_field(fixture, 21, "fixture provenance")?,
            0,
            Value::Text(String::new()),
            "licence identifier",
        ),
        _ => Err(format!("unsupported fixture mutation {mutation}").into()),
    }
}

fn assert_archive_rejected_by_both(archive: &[u8], label: &str) {
    assert!(
        verify_archive_independently(archive).is_err(),
        "{label} unexpectedly passed independent verification"
    );
    assert!(
        ConformanceBundleV1::from_canonical_cbor(archive).is_err(),
        "{label} unexpectedly passed typed verification"
    );
}

#[test]
fn independent_verifier_rejects_each_current_profile_contract_mutation() -> TestResult {
    for mutation in 0..103 {
        let archive = mutate_profile_archive(|profile| mutate_profile_fields(profile, mutation))?;
        if mutation == 4 {
            assert_eq!(
                verify_archive_independently(&archive),
                Err(BundleContractErrorV1::LifecycleInvalid)
            );
        } else {
            assert_archive_rejected_by_both(&archive, &format!("profile mutation {mutation}"));
        }
    }
    Ok(())
}

fn replace_nested_profile_value(
    profile: &mut [Value],
    path: &[usize],
    replacement: Value,
) -> TestResult {
    let (first, rest) = path.split_first().ok_or("profile path must not be empty")?;
    let mut selected = profile
        .get_mut(*first)
        .ok_or("profile path starts out of bounds")?;
    if rest.is_empty() {
        *selected = replacement;
        return Ok(());
    }
    let (field, parents) = rest
        .split_last()
        .ok_or("profile path must select a nested field")?;
    for index in parents {
        let Value::Array(fields) = selected else {
            return Err("profile path must select arrays".into());
        };
        selected = fields
            .get_mut(*index)
            .ok_or("profile path is out of bounds")?;
    }
    let Value::Array(fields) = selected else {
        return Err("profile path parent must be an array".into());
    };
    replace_value(fields, *field, replacement, "nested profile field")
}

fn raw_profile_type_paths() -> Vec<Vec<usize>> {
    let mut paths = (0..16).map(|field| vec![field]).collect::<Vec<_>>();
    paths.extend((0..4).map(|field| vec![8, 0, field]));
    paths.extend((0..4).map(|field| vec![8, 1, 0, field]));
    paths.push(vec![7, 0]);
    paths.extend(
        (0..=12)
            .chain(14..=18)
            .chain(std::iter::once(21))
            .map(|field| vec![9, 0, field]),
    );
    paths.extend((0..4).map(|field| vec![9, 0, 4, field]));
    paths.push(vec![9, 0, 7, 0]);
    for descriptor in [8, 9] {
        paths.extend((0..4).map(|field| vec![9, 0, descriptor, field]));
    }
    paths.extend((0..4).map(|field| vec![9, 0, 10, 0, field]));
    paths.extend([0, 2].map(|field| vec![9, 0, 11, field]));
    paths.extend((0..3).map(|field| vec![9, 0, 11, 2, field]));
    paths.extend((0..8).map(|field| vec![9, 0, 16, field]));
    paths.push(vec![9, 0, 17, 0]);
    paths.extend((0..2).map(|field| vec![9, 0, 18, field]));
    paths.extend((0..7).map(|field| vec![9, 0, 21, field]));
    paths.extend((0..5).map(|field| vec![11, field]));
    paths.extend((0..18).map(|field| vec![11, 4, field]));
    paths.extend((0..5).map(|field| vec![12, field]));
    paths
}

#[test]
fn independent_verifier_rejects_wrong_types_across_every_raw_profile_record() -> TestResult {
    for replacement in [Value::Null, Value::Map(Vec::new())] {
        for path in raw_profile_type_paths() {
            let archive = mutate_profile_archive(|profile| {
                replace_nested_profile_value(profile, &path, replacement.clone())
            })?;
            assert_archive_rejected_by_both(&archive, &format!("raw profile path {path:?}"));
        }
    }
    for path in [
        vec![16],
        vec![9, 0, 13],
        vec![9, 0, 19],
        vec![9, 0, 20],
        vec![9, 0, 22],
    ] {
        let archive = mutate_profile_archive(|profile| {
            replace_nested_profile_value(profile, &path, Value::Map(Vec::new()))
        })?;
        assert_archive_rejected_by_both(&archive, &format!("optional profile path {path:?}"));
    }
    Ok(())
}

#[test]
fn both_verifiers_reject_wrong_types_across_every_archive_record() -> TestResult {
    let mut paths = (0..4).map(|field| vec![field]).collect::<Vec<_>>();
    paths.extend((0..6).map(|field| vec![0, field]));
    paths.push(vec![0, 4, 0]);
    paths.extend((0..4).map(|field| vec![0, 4, 0, field]));
    paths.push(vec![0, 5, 0]);
    paths.extend((0..6).map(|field| vec![0, 5, 0, field]));
    paths.push(vec![1, 0]);
    paths.extend((0..3).map(|field| vec![1, 0, field]));

    for path in paths {
        let archive = mutate_unsealed_archive(|fields| {
            replace_nested_profile_value(fields, &path, Value::Map(Vec::new()))
        })?;
        assert_archive_rejected_by_both(&archive, &format!("raw archive path {path:?}"));
    }
    Ok(())
}

#[test]
fn both_verifiers_reject_divergence_classes_outside_the_cpf1_contract() -> TestResult {
    for classification in 7_u64..=8 {
        let archive = mutate_profile_archive(|profile| {
            replace_value(
                profile,
                10,
                Value::Array(vec![Value::Array(vec![
                    Value::Integer(classification.into()),
                    Value::Bytes(vec![1]),
                ])]),
                "allowed divergence",
            )
        })?;
        assert_archive_rejected_by_both(&archive, "out-of-contract divergence classification");
    }
    Ok(())
}

fn set_raw_divergence_fixture(
    profile: &mut [Value],
    classification: Value,
    coordinate: Value,
) -> TestResult {
    let divergence = Value::Array(vec![classification, coordinate]);
    replace_value(
        profile,
        10,
        Value::Array(vec![divergence.clone()]),
        "allowed divergence",
    )?;
    let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
    replace_value(
        fixture,
        11,
        Value::Array(vec![
            Value::Integer(2_u64.into()),
            Value::Null,
            Value::Null,
            divergence,
        ]),
        "divergence oracle",
    )?;
    replace_value(
        fixture,
        12,
        Value::Integer(1_u64.into()),
        "verification outcome",
    )?;
    replace_value(fixture, 13, Value::Null, "verification error")
}

#[test]
fn independent_verifier_exercises_active_divergence_oracles() -> TestResult {
    let valid = mutate_profile_archive(|profile| {
        set_raw_divergence_fixture(profile, Value::Integer(5_u64.into()), Value::Bytes(vec![1]))
    })?;
    verify_archive_independently(&valid)?;
    ConformanceBundleV1::from_canonical_cbor(&valid)?;

    for (classification, coordinate) in [
        (Value::Map(Vec::new()), Value::Bytes(vec![1])),
        (Value::Integer(5_u64.into()), Value::Map(Vec::new())),
        (Value::Integer(5_u64.into()), Value::Bytes(Vec::new())),
    ] {
        let invalid = mutate_profile_archive(|profile| {
            set_raw_divergence_fixture(profile, classification, coordinate)
        })?;
        assert_archive_rejected_by_both(&invalid, "malformed active divergence");
    }
    Ok(())
}

fn set_raw_downgrade_fixture(profile: &mut [Value]) -> TestResult {
    let fixture = array_field(array_field(profile, 9, "fixtures")?, 5, "downgrade fixture")?;
    let from = fixture
        .get(4)
        .ok_or("fixture provider key is absent")?
        .clone();
    let mut to = from.clone();
    let Value::Array(to_fields) = &mut to else {
        return Err("fixture provider key is not an array".into());
    };
    replace_value(
        to_fields,
        3,
        Value::Integer(1_u64.into()),
        "target ABI minor",
    )?;
    let schema_bytes = CURRENT_SCHEMA_BYTES[5];
    replace_value(
        fixture,
        8,
        Value::Array(vec![
            Value::Text("providers/example/schemas/5.schema.json".to_owned()),
            Value::Text("application/schema+json".to_owned()),
            Value::Integer(u64::try_from(schema_bytes.len())?.into()),
            Value::Bytes(blake3::hash(schema_bytes).as_bytes().to_vec()),
        ]),
        "downgrade schema",
    )?;
    replace_value(fixture, 19, Value::Bytes(vec![40; 32]), "trust snapshot")?;
    replace_value(fixture, 20, Value::Bytes(vec![41; 32]), "release admission")?;
    replace_value(
        fixture,
        22,
        Value::Array(vec![from, to]),
        "provider transition",
    )
}

#[test]
fn independent_verifier_exercises_active_provider_transitions() -> TestResult {
    let valid = mutate_profile_archive(set_raw_downgrade_fixture)?;
    verify_archive_independently(&valid)?;
    ConformanceBundleV1::from_canonical_cbor(&valid)?;

    for endpoint in 0..2 {
        let invalid = mutate_profile_archive(|profile| {
            set_raw_downgrade_fixture(profile)?;
            replace_nested_profile_value(profile, &[9, 5, 22, endpoint], Value::Map(Vec::new()))
        })?;
        assert_archive_rejected_by_both(&invalid, "malformed provider transition");
    }
    Ok(())
}

fn assert_independent_fixture_inventory_relationships() -> TestResult {
    let missing_family = mutate_profile_archive(|profile| {
        array_field(profile, 9, "fixtures")?.pop();
        Ok(())
    })?;
    assert_archive_rejected_by_both(&missing_family, "missing required fixture family");

    let complete_second_coordinate = mutate_profile_archive(|profile| {
        array_field(profile, 7, "profile executions")?.insert(0, Value::Bytes(vec![2; 32]));
        let originals = array_field(profile, 9, "fixtures")?.clone();
        let mut expanded = Vec::with_capacity(originals.len() * 2);
        for original in originals {
            let mut additional = original.clone();
            let Value::Array(fields) = &mut additional else {
                return Err("fixture must be an array".into());
            };
            fields[6] = Value::Bytes(vec![2; 32]);
            fields[7] = Value::Array(vec![Value::Integer(1_u64.into())]);
            expanded.push(additional);
            expanded.push(original);
        }
        *array_field(profile, 9, "fixtures")? = expanded;
        Ok(())
    })?;
    verify_archive_independently(&complete_second_coordinate)?;
    ConformanceBundleV1::from_canonical_cbor(&complete_second_coordinate)?;

    let incomplete_second_coordinate = mutate_profile_archive(|profile| {
        array_field(profile, 7, "profile executions")?.insert(0, Value::Bytes(vec![2; 32]));
        let originals = array_field(profile, 9, "fixtures")?.clone();
        let mut expanded = Vec::with_capacity(originals.len() * 2 - 1);
        for (index, original) in originals.into_iter().enumerate() {
            let mut additional = original.clone();
            let Value::Array(fields) = &mut additional else {
                return Err("fixture must be an array".into());
            };
            fields[6] = Value::Bytes(vec![2; 32]);
            fields[7] = Value::Array(vec![Value::Integer(1_u64.into())]);
            if index != 6 {
                expanded.push(additional);
            }
            expanded.push(original);
        }
        *array_field(profile, 9, "fixtures")? = expanded;
        Ok(())
    })?;
    assert_archive_rejected_by_both(
        &incomplete_second_coordinate,
        "incomplete provider execution mode coordinate",
    );

    let duplicate_coordinate_family = mutate_profile_archive(|profile| {
        let fixtures = array_field(profile, 9, "fixtures")?;
        let mut duplicate = fixtures.first().ok_or("fixture is absent")?.clone();
        let Value::Array(fields) = &mut duplicate else {
            return Err("fixture must be an array".into());
        };
        let Value::Text(case_id) = &mut fields[0] else {
            return Err("fixture case ID must be text".into());
        };
        case_id.push_str("-duplicate");
        fixtures.insert(1, duplicate);
        Ok(())
    })?;
    assert_archive_rejected_by_both(
        &duplicate_coordinate_family,
        "duplicate family in one provider execution mode coordinate",
    );
    Ok(())
}

fn assert_independent_fixture_semantic_relationships() -> TestResult {
    let unknown_provider = mutate_profile_archive(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?
                .get_mut(4)
                .and_then(|value| match value {
                    Value::Array(fields) => Some(fields.as_mut_slice()),
                    _ => None,
                })
                .ok_or("fixture provider is absent")?,
            0,
            Value::Text("other.provider".to_owned()),
            "fixture provider identifier",
        )
    })?;
    assert_archive_rejected_by_both(&unknown_provider, "unknown fixture provider");

    let outcome_mismatch = mutate_profile_archive(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            12,
            Value::Integer(1_u64.into()),
            "verification outcome",
        )
    })?;
    assert_archive_rejected_by_both(&outcome_mismatch, "oracle and outcome mismatch");

    let claim_mismatch = mutate_profile_archive(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            14,
            Value::Integer(0_u64.into()),
            "replay claim",
        )
    })?;
    assert_archive_rejected_by_both(&claim_mismatch, "replay and redaction mismatch");

    let misplaced_downgrade_authority = mutate_profile_archive(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            19,
            Value::Bytes(vec![70; 32]),
            "trust snapshot digest",
        )
    })?;
    assert_archive_rejected_by_both(
        &misplaced_downgrade_authority,
        "authority on non-downgrade fixture",
    );

    let incomplete_downgrade = mutate_profile_archive(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 5, "downgrade fixture")?,
            22,
            Value::Null,
            "provider transition",
        )
    })?;
    assert_archive_rejected_by_both(&incomplete_downgrade, "incomplete downgrade authority");

    let wrong_failure_owner = mutate_profile_archive(|profile| {
        let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
        for field in [11, 13] {
            let failure = if field == 11 {
                array_field(array_field(fixture, field, "oracle")?, 2, "oracle failure")?
            } else {
                array_field(fixture, field, "expected failure")?
            };
            replace_value(
                failure,
                0,
                Value::Text("other.provider".to_owned()),
                "failure owner",
            )?;
        }
        Ok(())
    })?;
    assert_archive_rejected_by_both(&wrong_failure_owner, "unowned provider failure");

    let unallowed_divergence = mutate_profile_archive(|profile| {
        set_raw_divergence_fixture(profile, Value::Integer(5_u64.into()), Value::Bytes(vec![1]))?;
        replace_value(profile, 10, Value::Array(Vec::new()), "allowed divergences")
    })?;
    assert_archive_rejected_by_both(&unallowed_divergence, "unallowed fixture divergence");
    Ok(())
}

#[test]
fn independent_verifier_matches_typed_fixture_relationship_validation() -> TestResult {
    assert_independent_fixture_inventory_relationships()?;
    assert_independent_fixture_semantic_relationships()
}

fn assert_deep_raw_profile_rejections() -> TestResult {
    for field in 0..3 {
        let invalid_manifest_header = mutate_archive(|archive| {
            replace_value(
                array_field(archive, 0, "manifest")?,
                field,
                Value::Null,
                "manifest header field",
            )
        })?;
        assert_archive_rejected_by_both(
            &invalid_manifest_header,
            &format!("non-scalar manifest header field {field}"),
        );
    }

    let invalid_member_collection =
        mutate_archive(|archive| replace_value(archive, 1, Value::Null, "archive members"))?;
    assert_archive_rejected_by_both(&invalid_member_collection, "non-array archive members");

    let mixed_claim_layers = mutate_profile_archive(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            2,
            Value::Integer(1_u64.into()),
            "fixture claim layer",
        )
    })?;
    assert_archive_rejected_by_both(&mixed_claim_layers, "mixed profile claim layers");

    let execution_without_fixtures = mutate_profile_archive(|profile| {
        array_field(profile, 7, "profile executions")?.insert(0, Value::Bytes(vec![2; 32]));
        Ok(())
    })?;
    assert_archive_rejected_by_both(
        &execution_without_fixtures,
        "execution profile without fixture modes",
    );

    let noncanonical_divergences = mutate_profile_archive(|profile| {
        replace_value(
            profile,
            10,
            Value::Array(vec![
                Value::Array(vec![Value::Integer(1_u64.into()), Value::Bytes(vec![2])]),
                Value::Array(vec![Value::Integer(0_u64.into()), Value::Bytes(vec![1])]),
            ]),
            "allowed divergences",
        )
    })?;
    assert_archive_rejected_by_both(
        &noncanonical_divergences,
        "noncanonical allowed divergences",
    );

    let duplicate_artifact_path = mutate_profile_archive(|profile| {
        let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
        let schema_path = array_field(fixture, 8, "fixture schema")?
            .first()
            .ok_or("fixture schema path is absent")?
            .clone();
        replace_value(
            array_field(
                array_field(fixture, 10, "auxiliary artifacts")?,
                0,
                "auxiliary artifact",
            )?,
            0,
            schema_path,
            "auxiliary artifact path",
        )
    })?;
    assert_archive_rejected_by_both(&duplicate_artifact_path, "duplicate fixture artifact path");

    let missing_bound_member = mutate_profile_archive(|profile| {
        replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                9,
                "fixture payload",
            )?,
            0,
            Value::Text("fixtures/missing/input.bin".to_owned()),
            "fixture payload path",
        )
    })?;
    assert_archive_rejected_by_both(&missing_bound_member, "unbound fixture payload");
    Ok(())
}

fn assert_deep_raw_archive_rejections() -> TestResult {
    let malformed_registry_bytes = mutate_archive(|archive| {
        let bytes = [0xff];
        replace_archive_member_bytes(archive, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, &bytes)?;
        refresh_profile_registry_binding(archive, &bytes)
    })?;
    assert_archive_rejected_by_both(
        &malformed_registry_bytes,
        "malformed bound provider registry",
    );

    let equal_transition_endpoints = mutate_profile_archive(|profile| {
        let transition = array_field(
            array_field(array_field(profile, 9, "fixtures")?, 5, "downgrade fixture")?,
            22,
            "provider transition",
        )?;
        let from = transition
            .first()
            .ok_or("provider transition source is absent")?
            .clone();
        replace_value(transition, 1, from, "provider transition target")
    })?;
    assert_archive_rejected_by_both(
        &equal_transition_endpoints,
        "equal provider transition endpoints",
    );

    let invalid_profile_digest_type = mutate_archive(|archive| {
        let profile_bytes = match archive_member_fields(archive, "profile/CPF1.cbor")?.get(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("profile member is not bytes".into()),
        };
        let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
        let Value::Array(profile_fields) = &mut profile else {
            return Err("profile is not an array".into());
        };
        replace_value(profile_fields, 17, Value::Null, "profile digest")?;
        replace_archive_member_bytes(archive, "profile/CPF1.cbor", &encode_value(&profile)?)
    })?;
    assert_archive_rejected_by_both(&invalid_profile_digest_type, "non-byte profile digest");

    let invalid_manifest_digest_type = mutate_archive(|archive| {
        replace_value(
            array_field(archive, 0, "manifest")?,
            3,
            Value::Null,
            "manifest profile digest",
        )
    })?;
    assert_archive_rejected_by_both(
        &invalid_manifest_digest_type,
        "non-byte manifest profile digest",
    );

    let unbound_expected_result = mutate_archive(|archive| {
        replace_value(
            array_field(
                array_field(array_field(archive, 0, "manifest")?, 5, "expected results")?,
                0,
                "expected result",
            )?,
            0,
            Value::Text("missing-case".to_owned()),
            "expected result case ID",
        )
    })?;
    assert_archive_rejected_by_both(&unbound_expected_result, "unbound expected result");

    let invalid_signature_key = mutate_unsealed_archive(|archive| {
        replace_value(
            archive,
            2,
            Value::Bytes(vec![0xff; 32]),
            "archive signer public key",
        )
    })?;
    assert_archive_rejected_by_both(&invalid_signature_key, "invalid signature public key");
    assert!(
        verify_release_tree_independently(&[invalid_signature_key.as_slice()]).is_err(),
        "release-tree verification accepted an invalid archive"
    );
    Ok(())
}

#[test]
fn independent_verifier_reaches_deep_raw_relationship_rejections() -> TestResult {
    assert_deep_raw_profile_rejections()?;
    assert_deep_raw_archive_rejections()
}

#[test]
fn independent_verifier_enforces_every_deterministic_budget_ceiling() -> TestResult {
    let ceilings = [
        1024 * 1024 * 1024_u64,
        1_000_000_000,
        1_000_000,
        1_000_000,
        64 * 1024 * 1024,
        1024 * 1024 * 1024,
        1_000_000_000,
        86_400_000_000_000,
    ];
    for (field, ceiling) in ceilings.into_iter().enumerate() {
        let archive = mutate_profile_archive(|profile| {
            replace_value(
                array_field(
                    array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                    16,
                    "deterministic budget",
                )?,
                field,
                Value::Integer(ceiling.saturating_add(1).into()),
                "deterministic budget field",
            )
        })?;
        assert_archive_rejected_by_both(&archive, &format!("deterministic budget ceiling {field}"));
    }
    Ok(())
}

#[test]
fn both_verifiers_bind_each_selected_deterministic_budget_ceiling() -> TestResult {
    for field in 0..8 {
        let exact = mutate_profile_archive(|profile| {
            let selected = {
                let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
                let budget = array_field(fixture, 16, "deterministic budget")?;
                budget
                    .get(field)
                    .cloned()
                    .ok_or_else(|| format!("deterministic budget field {field} is absent"))?
            };
            let protocol = array_field(profile, 11, "evaluator protocol")?;
            let hard_caps = array_field(protocol, 4, "evaluator hard caps")?;
            replace_value(
                hard_caps,
                10 + field,
                selected,
                "selected deterministic ceiling",
            )
        })?;
        verify_archive_independently(&exact)?;
        ConformanceBundleV1::from_canonical_cbor(&exact)?;

        let insufficient = mutate_profile_archive(|profile| {
            let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
            let budget = array_field(fixture, 16, "deterministic budget")?;
            let Value::Integer(selected) = budget
                .get(field)
                .ok_or_else(|| format!("deterministic budget field {field} is absent"))?
            else {
                return Err("deterministic budget field is not an integer".into());
            };
            let below = u64::try_from(*selected)?.saturating_sub(1);
            let protocol = array_field(profile, 11, "evaluator protocol")?;
            let hard_caps = array_field(protocol, 4, "evaluator hard caps")?;
            replace_value(
                hard_caps,
                10 + field,
                Value::Integer(below.into()),
                "selected deterministic ceiling",
            )
        })?;
        assert_archive_rejected_by_both(
            &insufficient,
            &format!("selected deterministic ceiling {field}"),
        );
    }
    Ok(())
}

#[test]
fn evaluator_hard_cap_digest_matches_the_independent_golden_vector() {
    let caps = EvaluatorHardCapsV1 {
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
    };
    assert_eq!(
        caps.digest(),
        [
            0xcb, 0xbd, 0x07, 0x01, 0x33, 0x23, 0x49, 0x2c, 0xb7, 0x48, 0xe9, 0xf7, 0x4b, 0x95,
            0x6c, 0x58, 0xc0, 0x3b, 0x3f, 0x01, 0x61, 0xe1, 0x76, 0xb4, 0x63, 0xdd, 0x62, 0xa2,
            0xdd, 0x7f, 0xa5, 0x09,
        ]
    );
}

#[test]
fn both_verifiers_reject_the_replaced_ten_field_hard_cap_shape() -> TestResult {
    let archive = mutate_profile_archive(|profile| {
        let protocol = array_field(profile, 11, "evaluator protocol")?;
        let hard_caps = array_field(protocol, 4, "evaluator hard caps")?;
        hard_caps.truncate(10);
        Ok(())
    })?;
    assert_archive_rejected_by_both(&archive, "ten-field evaluator hard caps");
    Ok(())
}

#[test]
fn both_verifiers_reject_stale_profile_identity_for_each_selected_ceiling() -> TestResult {
    for field in 0..8 {
        let archive = mutate_profile_archive_after_profile_digest(|profile| {
            let protocol = array_field(profile, 11, "evaluator protocol")?;
            let hard_caps = array_field(protocol, 4, "evaluator hard caps")?;
            let selected = match hard_caps
                .get(10 + field)
                .ok_or_else(|| format!("selected ceiling {field} is absent"))?
            {
                Value::Integer(value) => u64::try_from(*value)?,
                _ => return Err("selected deterministic ceiling is not an integer".into()),
            };
            replace_value(
                hard_caps,
                10 + field,
                Value::Integer(selected.saturating_sub(1).into()),
                "selected deterministic ceiling",
            )
        })?;
        assert_archive_rejected_by_both(
            &archive,
            &format!("stale profile identity after selected ceiling {field}"),
        );
    }
    Ok(())
}

#[test]
fn both_verifiers_accept_all_current_fixture_execution_modes() -> TestResult {
    let archive = mutate_profile_archive(|profile| {
        for fixture in array_field(profile, 9, "fixtures")? {
            let Value::Array(fields) = fixture else {
                return Err("fixture must be an array".into());
            };
            replace_value(
                fields,
                7,
                Value::Array(
                    (0_u64..=3)
                        .map(|mode| Value::Integer(mode.into()))
                        .collect(),
                ),
                "fixture execution modes",
            )?;
        }
        Ok(())
    })?;
    verify_archive_independently(&archive)?;
    ConformanceBundleV1::from_canonical_cbor(&archive)?;
    Ok(())
}

#[test]
fn independent_verifier_matches_typed_fixture_caps_and_schema_binding() -> TestResult {
    let excessive_auxiliary = mutate_profile_archive(|profile| {
        let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
        let template = array_field(fixture, 10, "auxiliary descriptors")?
            .first()
            .ok_or("auxiliary descriptor is absent")?
            .clone();
        let auxiliary = (0..65)
            .map(|index| {
                let mut descriptor = template.clone();
                let Value::Array(fields) = &mut descriptor else {
                    return Err("auxiliary descriptor is not an array".into());
                };
                fields[0] = Value::Text(format!("expected/excessive-{index:02}.json"));
                Ok(descriptor)
            })
            .collect::<TestResult<Vec<_>>>()?;
        replace_value(
            fixture,
            10,
            Value::Array(auxiliary),
            "auxiliary descriptors",
        )
    })?;
    assert_archive_rejected_by_both(&excessive_auxiliary, "excessive auxiliary descriptors");

    let excessive_capabilities = mutate_profile_archive(|profile| {
        replace_value(
            array_field(
                array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
                18,
                "capability policy",
            )?,
            1,
            Value::Array(
                (0..257)
                    .map(|index| Value::Text(format!("capability-{index:03}")))
                    .collect(),
            ),
            "capability identifiers",
        )
    })?;
    assert_archive_rejected_by_both(&excessive_capabilities, "excessive capabilities");

    let wrong_family_schema = mutate_profile_archive(|profile| {
        let fixtures = array_field(profile, 9, "fixtures")?;
        let denied_schema = array_field(fixtures, 1, "denied fixture")?
            .get(8)
            .ok_or("denied schema is absent")?
            .clone();
        replace_value(
            array_field(fixtures, 0, "positive fixture")?,
            8,
            denied_schema,
            "positive schema",
        )
    })?;
    assert_archive_rejected_by_both(&wrong_family_schema, "wrong provider family schema");
    Ok(())
}

#[test]
fn both_verifiers_reject_a_fixture_digest_changed_after_canonicalization() -> TestResult {
    let archive = mutate_profile_archive_after_fixture_digest(|profile| {
        replace_value(
            array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?,
            23,
            Value::Bytes(vec![9; 32]),
            "fixture digest",
        )
    })?;
    assert_archive_rejected_by_both(&archive, "fixture digest mismatch");
    Ok(())
}

#[test]
fn independent_verifier_rejects_network_for_air_gapped_fixture() -> TestResult {
    let archive = mutate_profile_archive(|profile| {
        let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
        replace_value(
            array_field(fixture, 18, "capability policy")?,
            0,
            Value::Bool(true),
            "network capability",
        )
    })?;
    assert_eq!(
        verify_archive_independently(&archive),
        Err(BundleContractErrorV1::ProfileInvalid)
    );

    let plugin_archive = mutate_profile_archive(|profile| {
        let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
        replace_value(fixture, 5, Value::Integer(2_u64.into()), "subject adapter")?;
        replace_value(
            fixture,
            7,
            Value::Array(vec![Value::Integer(0_u64.into())]),
            "fixture modes",
        )?;
        replace_value(
            array_field(fixture, 18, "capability policy")?,
            0,
            Value::Bool(true),
            "network capability",
        )
    })?;
    assert_eq!(
        verify_archive_independently(&plugin_archive),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn independent_verifier_rejects_each_current_provider_registry_mutation() -> TestResult {
    for mutation in 0..18 {
        let archive = mutate_provider_registry_archive(mutation)?;
        assert_archive_rejected_by_both(
            &archive,
            &format!("provider registry mutation {mutation}"),
        );
    }
    Ok(())
}

#[test]
fn independent_verifier_rejects_each_current_provider_package_mutation() -> TestResult {
    for mutation in 0..22 {
        let archive = mutate_provider_package_archive(mutation)?;
        assert_archive_rejected_by_both(&archive, &format!("provider package mutation {mutation}"));
    }
    Ok(())
}

#[test]
fn independent_verifier_rejects_wrong_types_across_provider_records() -> TestResult {
    let mut registry_paths = (0..3).map(|field| vec![field]).collect::<Vec<_>>();
    registry_paths.extend((0..7).map(|field| vec![2, 0, field]));
    registry_paths.extend((0..4).map(|field| vec![2, 0, 6, field]));
    for path in registry_paths {
        for replacement in [Value::Null, Value::Map(Vec::new())] {
            let archive = mutate_provider_registry_archive_with(|registry| {
                replace_nested_profile_value(registry, &path, replacement)?;
                Ok(true)
            })?;
            assert_archive_rejected_by_both(&archive, &format!("raw registry path {path:?}"));
        }
    }

    let mut package_paths = (0..11).map(|field| vec![field]).collect::<Vec<_>>();
    package_paths.extend((0..4).map(|field| vec![2, field]));
    package_paths.extend((0..2).map(|field| vec![5, 0, field]));
    package_paths.extend((0..4).map(|field| vec![5, 0, 1, field]));
    for descriptor in 6..=10 {
        package_paths.extend((0..4).map(|field| vec![descriptor, field]));
    }
    for path in package_paths {
        for replacement in [Value::Null, Value::Map(Vec::new())] {
            let archive = mutate_provider_package_archive_with(|package| {
                replace_nested_profile_value(package, &path, replacement)?;
                Ok(true)
            })?;
            assert_archive_rejected_by_both(&archive, &format!("raw package path {path:?}"));
        }
    }
    Ok(())
}

fn mutate_archive_fields(archive: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        0 => replace_value(
            array_field(archive, 0, "manifest")?,
            0,
            Value::Text("BAD1".to_owned()),
            "manifest magic",
        ),
        1 => replace_value(
            array_field(archive, 0, "manifest")?,
            1,
            Value::Integer(1_u64.into()),
            "manifest lifecycle",
        ),
        2 => replace_value(
            array_field(archive, 0, "manifest")?,
            2,
            Value::Integer(2_u64.into()),
            "manifest mode",
        ),
        3 => {
            array_field(
                array_field(archive, 0, "manifest")?,
                4,
                "member descriptors",
            )?
            .swap(0, 1);
            Ok(())
        }
        4 => replace_value(
            array_field(
                array_field(
                    array_field(archive, 0, "manifest")?,
                    4,
                    "member descriptors",
                )?,
                0,
                "member descriptor",
            )?,
            1,
            Value::Integer(0_u64.into()),
            "member length",
        ),
        5 => replace_value(
            array_field(
                array_field(
                    array_field(archive, 0, "manifest")?,
                    4,
                    "member descriptors",
                )?,
                0,
                "member descriptor",
            )?,
            2,
            Value::Bytes(vec![9; 32]),
            "member digest",
        ),
        6 => {
            array_field(array_field(archive, 0, "manifest")?, 5, "expected results")?.clear();
            Ok(())
        }
        7 => replace_value(
            array_field(
                array_field(array_field(archive, 0, "manifest")?, 5, "expected results")?,
                0,
                "expected result",
            )?,
            3,
            Value::Integer(1_u64.into()),
            "expected result mode",
        ),
        8 => {
            array_field(archive, 1, "archive members")?.swap(0, 1);
            Ok(())
        }
        9 => {
            array_field(archive, 1, "archive members")?.pop();
            Ok(())
        }
        10..=21 => mutate_archive_shape_fields(archive, mutation),
        22..=31 => mutate_archive_expected_fields(archive, mutation),
        32..=36 => mutate_archive_additional_fields(archive, mutation),
        _ => Err(format!("unsupported archive mutation {mutation}").into()),
    }
}

fn mutate_archive_shape_fields(archive: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
        10 => replace_value(archive, 0, Value::Null, "manifest"),
        11 => replace_value(
            array_field(archive, 0, "manifest")?,
            4,
            Value::Null,
            "member descriptors",
        ),
        12 => replace_value(
            array_field(archive, 0, "manifest")?,
            5,
            Value::Null,
            "expected results",
        ),
        13 => replace_value(
            array_field(
                array_field(archive, 0, "manifest")?,
                4,
                "member descriptors",
            )?,
            0,
            Value::Array(Vec::new()),
            "member descriptor",
        ),
        14..=17 => {
            let replacement = match mutation {
                14..=16 => Value::Null,
                17 => Value::Integer(14_u64.into()),
                _ => return Err(format!("unsupported descriptor mutation {mutation}").into()),
            };
            replace_value(
                array_field(
                    array_field(
                        array_field(archive, 0, "manifest")?,
                        4,
                        "member descriptors",
                    )?,
                    0,
                    "member descriptor",
                )?,
                mutation - 14,
                replacement,
                "member descriptor field",
            )
        }
        18 => replace_value(
            array_field(archive, 1, "archive members")?,
            0,
            Value::Array(Vec::new()),
            "archive member",
        ),
        19..=21 => replace_value(
            array_field(
                array_field(archive, 1, "archive members")?,
                0,
                "archive member",
            )?,
            mutation - 19,
            if mutation == 21 {
                Value::Integer(14_u64.into())
            } else {
                Value::Null
            },
            "archive member field",
        ),
        _ => Err(format!("unsupported archive shape mutation {mutation}").into()),
    }
}

fn mutate_archive_expected_fields(archive: &mut [Value], mutation: usize) -> TestResult {
    if mutation == 29 {
        return replace_value(
            array_field(archive, 0, "manifest")?,
            3,
            Value::Bytes(vec![0; 32]),
            "manifest profile digest",
        );
    }
    if mutation == 30 {
        return replace_value(
            array_field(
                array_field(archive, 1, "archive members")?,
                0,
                "archive member",
            )?,
            0,
            Value::Text("aaa".to_owned()),
            "archive member path",
        );
    }
    if mutation == 31 {
        return replace_value(
            array_field(
                array_field(
                    array_field(archive, 0, "manifest")?,
                    4,
                    "member descriptors",
                )?,
                0,
                "member descriptor",
            )?,
            0,
            Value::Text("aaa".to_owned()),
            "member descriptor path",
        );
    }
    let expected = array_field(
        array_field(array_field(archive, 0, "manifest")?, 5, "expected results")?,
        0,
        "expected result",
    )?;
    match mutation {
        22 => {
            *expected = Vec::new();
            Ok(())
        }
        23..=28 => replace_value(
            expected,
            mutation - 23,
            match mutation {
                24 => Value::Integer(256_u64.into()),
                26 => Value::Integer(2_u64.into()),
                _ => Value::Null,
            },
            "expected result field",
        ),
        _ => Err(format!("unsupported expected result mutation {mutation}").into()),
    }
}

fn mutate_archive_additional_fields(archive: &mut [Value], mutation: usize) -> TestResult {
    if matches!(mutation, 32..=34) {
        return replace_value(
            array_field(archive, 0, "manifest")?,
            1,
            Value::Integer(u64::try_from(mutation - 30)?.into()),
            "manifest lifecycle",
        );
    }
    let expected_results =
        array_field(array_field(archive, 0, "manifest")?, 5, "expected results")?;
    match mutation {
        35 => {
            expected_results.push(
                expected_results
                    .first()
                    .ok_or("expected result is absent")?
                    .clone(),
            );
            Ok(())
        }
        36 => replace_value(
            array_field(expected_results, 0, "expected result")?,
            5,
            Value::Bytes(vec![9; 32]),
            "expected result digest",
        ),
        _ => Err(format!("unsupported additional archive mutation {mutation}").into()),
    }
}

#[test]
fn independent_verifier_rejects_manifest_member_and_expected_mutations() -> TestResult {
    for mutation in 0..37 {
        let archive = mutate_archive(|archive| mutate_archive_fields(archive, mutation))?;
        assert_archive_rejected_by_both(&archive, &format!("archive mutation {mutation}"));
    }
    Ok(())
}

#[test]
fn independent_verifier_rejects_valid_archive_with_wrong_release_filename() -> TestResult {
    let archive = signed_current_bundle(BundleModeV1::Local)?.to_canonical_cbor()?;
    assert_eq!(
        verify_archive_release_filename(
            &archive,
            "0000000000000000000000000000000000000000000000000000000000000000.cfb1",
        ),
        Err(BundleContractErrorV1::ReleaseFilenameInvalid)
    );
    Ok(())
}

#[test]
fn member_constructors_hash_exact_raw_bytes_and_assign_current_roles() {
    let input = BundleMemberV1::fixture_input("fixtures/positive/input.json", b"input".to_vec());
    let expected =
        BundleMemberV1::expected_result("fixtures/positive/result.json", b"result".to_vec());
    let registry = BundleMemberV1::fixture_provider_registry(b"registry".to_vec());
    let package =
        BundleMemberV1::fixture_provider_package("providers/example.fpp1", b"package".to_vec());

    assert_eq!(input.role, BundleMemberRoleV1::FixtureInput);
    assert_eq!(expected.role, BundleMemberRoleV1::ExpectedResult);
    assert_eq!(registry.role, BundleMemberRoleV1::FixtureProviderRegistry);
    assert_eq!(package.role, BundleMemberRoleV1::FixtureProviderPackage);
    assert_eq!(input.digest, *blake3::hash(b"input").as_bytes());
    assert_eq!(expected.digest, *blake3::hash(b"result").as_bytes());
    assert_eq!(registry.digest, *blake3::hash(b"registry").as_bytes());
    assert_eq!(package.digest, *blake3::hash(b"package").as_bytes());
}

#[test]
fn deterministic_member_paths_bind_case_layer_execution_and_purpose() {
    let execution = [7; 32];
    let input = fixture_input_member_path(
        "fixture/positive",
        ClaimLayerV1::ArtifactIntegrity,
        &execution,
        "payload",
    );
    let same = fixture_input_member_path(
        "fixture/positive",
        ClaimLayerV1::ArtifactIntegrity,
        &execution,
        "payload",
    );
    let expected = expected_result_member_path(
        "fixture/positive",
        ClaimLayerV1::ArtifactIntegrity,
        &execution,
    );

    assert_eq!(input, same);
    assert_ne!(input, expected);
    assert!(input.starts_with("inputs/"));
    assert!(expected.starts_with("expected/"));
}

#[test]
fn independent_verifier_preflights_resource_bounds_before_decoding() {
    let oversized_byte_string = [0x5a, 0x04, 0x00, 0x00, 0x01];
    assert_eq!(
        verify_archive_independently(&oversized_byte_string),
        Err(BundleContractErrorV1::MemberOutOfBounds)
    );

    let oversized_text_string = [0x7a, 0x00, 0x00, 0x02, 0x01];
    assert_eq!(
        verify_archive_independently(&oversized_text_string),
        Err(BundleContractErrorV1::MemberOutOfBounds)
    );

    let excessive_item_count = [0x9a, 0x00, 0x01, 0x00, 0x01];
    assert_eq!(
        verify_archive_independently(&excessive_item_count),
        Err(BundleContractErrorV1::MemberOutOfBounds)
    );

    let mut excessive_nesting = vec![0x81; 34];
    excessive_nesting.push(0xf6);
    assert_eq!(
        verify_archive_independently(&excessive_nesting),
        Err(BundleContractErrorV1::MemberOutOfBounds)
    );

    for malformed in [&[][..], &[0x1a, 0, 0][..], &[0xa0][..], &[0xf7][..]] {
        assert!(verify_archive_independently(malformed).is_err());
    }
}

#[test]
fn independent_verifier_rejects_noncanonical_or_incomplete_archives() -> TestResult {
    let malformed = [0x84, 0x80, 0x80, 0x40, 0x40];
    let error = verify_archive_independently(&malformed)
        .err()
        .ok_or("noncanonical archive was accepted")?;
    assert!([
        BundleContractErrorV1::ArchiveEncodingInvalid,
        BundleContractErrorV1::LifecycleInvalid,
        BundleContractErrorV1::MemberMissing,
    ]
    .contains(&error));
    Ok(())
}

#[test]
fn release_filename_requires_a_verified_archive_before_digest_comparison() {
    let malformed = [0x84, 0x80, 0x80, 0x40, 0x40];
    assert_ne!(
        verify_archive_release_filename(&malformed, "not-an-archive.cfb1"),
        Ok(())
    );
}

fn malformed_archive(manifest: Vec<Value>) -> TestResult<Vec<u8>> {
    let value = Value::Array(vec![
        Value::Array(manifest),
        Value::Array(Vec::new()),
        Value::Bytes(vec![0; 32]),
        Value::Bytes(vec![0; 64]),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

#[test]
fn independent_verifier_rejects_each_manifest_shape_and_header_mutation() -> TestResult {
    let cases = [
        vec![],
        vec![Value::Text("CFB0".into())],
        vec![Value::Text("CFB1".into()), Value::Integer(1_u64.into())],
        vec![
            Value::Text("CFB1".into()),
            Value::Integer(0_u64.into()),
            Value::Integer(2_u64.into()),
        ],
        vec![
            Value::Text("CFB1".into()),
            Value::Integer(0_u64.into()),
            Value::Integer(0_u64.into()),
            Value::Bytes(vec![0; 32]),
            Value::Array(vec![]),
            Value::Array(vec![]),
        ],
    ];
    for manifest in cases {
        assert!(verify_archive_independently(&malformed_archive(manifest)?).is_err());
    }
    Ok(())
}

macro_rules! malformed_case {
    ($name:ident, $bytes:expr_2021) => {
        #[test]
        fn $name() -> TestResult {
            let bytes = $bytes;
            assert!(verify_archive_independently(bytes.as_ref()).is_err());
            Ok(())
        }
    };
}

malformed_case!(rejects_empty_archive, Vec::<u8>::new());
malformed_case!(rejects_non_cbor_archive, &[0xff]);
malformed_case!(rejects_indefinite_archive, &[0x9f, 0xff]);
malformed_case!(rejects_wrong_top_level_length, &[0x83, 0x80, 0x80, 0x40]);
malformed_case!(
    rejects_noncanonical_integer,
    &[0x84, 0x80, 0x80, 0x58, 0x20]
);
malformed_case!(rejects_empty_manifest, malformed_archive(Vec::new())?);
malformed_case!(
    rejects_one_field_manifest,
    malformed_archive(vec![Value::Text("CFB1".into())])?
);
malformed_case!(
    rejects_wrong_magic,
    malformed_archive(vec![
        Value::Text("BAD1".into()),
        Value::Integer(0_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Bytes(vec![1; 32]),
        Value::Array(vec![]),
        Value::Array(vec![])
    ])?
);
malformed_case!(
    rejects_candidate_lifecycle,
    malformed_archive(vec![
        Value::Text("CFB1".into()),
        Value::Integer(1_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Bytes(vec![1; 32]),
        Value::Array(vec![]),
        Value::Array(vec![])
    ])?
);
malformed_case!(
    rejects_unknown_mode,
    malformed_archive(vec![
        Value::Text("CFB1".into()),
        Value::Integer(0_u64.into()),
        Value::Integer(3_u64.into()),
        Value::Bytes(vec![1; 32]),
        Value::Array(vec![]),
        Value::Array(vec![])
    ])?
);

#[test]
fn fixed_uppercase_support_paths_are_valid_archive_member_names() {
    for path in ["support/LICENSE", "support/NOTICE", "profile/CPF1.cbor"] {
        let member = BundleMemberV1::supporting(path, vec![1], BundleMemberRoleV1::Schema);
        assert_eq!(member.path, path);
    }
}

#[test]
fn every_public_member_role_is_constructible() {
    let roles = [
        BundleMemberRoleV1::FixtureInput,
        BundleMemberRoleV1::ExpectedResult,
        BundleMemberRoleV1::Profile,
        BundleMemberRoleV1::NormativeSpecification,
        BundleMemberRoleV1::Schema,
        BundleMemberRoleV1::Licence,
        BundleMemberRoleV1::Notice,
        BundleMemberRoleV1::Sbom,
        BundleMemberRoleV1::Provenance,
        BundleMemberRoleV1::Limitations,
        BundleMemberRoleV1::AuthorityInventory,
        BundleMemberRoleV1::ExecutionMatrix,
        BundleMemberRoleV1::FixtureProviderRegistry,
        BundleMemberRoleV1::FixtureProviderPackage,
    ];
    for role in roles {
        let member = BundleMemberV1::supporting(format!("support/{role:?}"), vec![1], role);
        assert_eq!(member.role, role);
    }
}
