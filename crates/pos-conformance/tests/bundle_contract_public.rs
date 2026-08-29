//! Public archive-contract regression tests for the current CPF1/FPR1/FPP1 surface.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    expected_result_member_path, fixture_input_member_path, verify_archive_independently,
    verify_archive_release_filename, AllowedDivergenceV1, ArtifactDescriptorV1,
    BundleContractErrorV1, BundleExpectedResultV1, BundleMemberDescriptorV1, BundleMemberRoleV1,
    BundleMemberV1, BundleModeV1, CapabilityPolicyV1, ClaimLayerV1, ConformanceBundlePairV1,
    ConformanceBundleV1, ConformanceProfileV1, DeterministicBudgetV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExecutionModeV1, FixtureDescriptorV1, FixtureFamilyV1,
    FixtureProvenanceV1, FixtureProviderEntryV1, FixtureProviderKeyV1, FixtureProviderPackageV1,
    FixtureProviderRegistryBindingV1, FixtureProviderRegistryV1, IndependenceRequirementsV1,
    NamespacedFailureV1, OperationalSafetyV1, ProfileLifecycleV1, ProviderFamilySchemaV1,
    RedactionStateV1, ReplayClaimV1, StrictOracleKindV1, StrictOracleV1, SubjectAdapterKindV1,
    VerificationOutcomeV1, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
};
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
const PROVENANCE_BYTES: &[u8] = br#"{"source":"public"}"#;
const LIMITATIONS_BYTES: &[u8] = b"# Limitations\n";
const NORMATIVE_BYTES: &[u8] = b"normative contract";
const MATRIX_BYTES: &[u8] = b"execution matrix";
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
                    &format!("support/schemas/{index}.schema.json"),
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
            "support/provenance.json",
            "application/json",
            PROVENANCE_BYTES,
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

fn current_fixture(family_schemas: &[ProviderFamilySchemaV1]) -> TestResult<FixtureDescriptorV1> {
    let positive_schema = family_schemas
        .first()
        .ok_or("positive family schema is absent")?
        .schema_descriptor
        .clone();
    let execution = digest(31);
    let expected_path = expected_result_member_path(
        "example-positive",
        ClaimLayerV1::ArtifactIntegrity,
        &execution,
    );
    let failure = NamespacedFailureV1 {
        owner_id: "pigloros.core".to_owned(),
        contract_version: "1.0.0".to_owned(),
        code_id: "provenance-missing".to_owned(),
    };
    let mut fixture = FixtureDescriptorV1 {
        case_id: "example-positive".to_owned(),
        mandatory: true,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        family: FixtureFamilyV1::Positive,
        provider_key: provider_key(),
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        execution_profile_digest: execution,
        modes: vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped],
        schema: positive_schema,
        payload: artifact(
            "fixtures/positive/input.bin",
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
        expected_verification_error: Some(failure),
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
            source_digest: *blake3::hash(PROVENANCE_BYTES).as_bytes(),
            build_digest: digest(41),
            publication_review_digest: digest(42),
            limitations_digest: *blake3::hash(LIMITATIONS_BYTES).as_bytes(),
        },
        transition: None,
        fixture_digest: [0; 32],
    };
    fixture.fixture_digest = fixture.digest();
    Ok(fixture)
}

fn current_profile(
    fixture: FixtureDescriptorV1,
    registry_bytes: &[u8],
) -> TestResult<ConformanceProfileV1> {
    let mut profile = ConformanceProfileV1 {
        profile_id: "pigloros.current.example".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: *blake3::hash(NORMATIVE_BYTES).as_bytes(),
        execution_matrix_digest: *blake3::hash(MATRIX_BYTES).as_bytes(),
        execution_profile_digests: vec![fixture.execution_profile_digest],
        fixture_provider_registry: FixtureProviderRegistryBindingV1 {
            registry_artifact: artifact(
                FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
                "application/cbor",
                registry_bytes,
            )?,
            required_provider_keys: vec![provider_key()],
        },
        fixtures: vec![fixture],
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
            },
        },
        independence_requirements: IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: digest(54),
            requirements_digest: digest(55),
        },
        fixture_contract_policy_digest: digest(56),
        limitations_digest: *blake3::hash(LIMITATIONS_BYTES).as_bytes(),
        provenance_digest: *blake3::hash(PROVENANCE_BYTES).as_bytes(),
        previous_profile_digest: None,
        stable_evidence: Vec::new(),
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

    let fixture = current_fixture(&family_schemas)?;
    let execution = fixture.execution_profile_digest;
    let expected_path = expected_result_member_path(
        "example-positive",
        ClaimLayerV1::ArtifactIntegrity,
        &execution,
    );
    let profile = current_profile(fixture, &registry_bytes)?;

    let expected_member =
        BundleMemberV1::expected_result(expected_path.clone(), EXPECTED_BYTES.to_vec());
    let expected = vec![BundleExpectedResultV1 {
        case_id: "example-positive".to_owned(),
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        execution_profile_digest: execution,
        mode,
        member_path: expected_path,
        digest: expected_member.digest,
    }];
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
    members.extend([
        BundleMemberV1::fixture_input("fixtures/positive/input.bin", PAYLOAD_BYTES.to_vec()),
        expected_member,
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
            "support/provenance.json",
            PROVENANCE_BYTES.to_vec(),
            BundleMemberRoleV1::Provenance,
        ),
        BundleMemberV1::supporting(
            "support/limitations.md",
            LIMITATIONS_BYTES.to_vec(),
            BundleMemberRoleV1::Limitations,
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
    if profile_fields.len() == 18 {
        profile_fields[17] = Value::Bytes(
            contract_digest(b"PiglorOS.ConformanceProfile.v1", &profile_fields[..17])?.to_vec(),
        );
    }
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

fn temporary_root(label: &str) -> TestResult<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("pigloros-{label}-{}-{nonce}", std::process::id())))
}

struct TemporaryOutput(PathBuf);

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn release_archives(root: &Path) -> TestResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut archives = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("cfb1"))
            {
                archives.push(path);
            }
        }
    }
    archives.sort();
    Ok(archives)
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

    let mut mismatched = pair;
    mismatched.air_gapped.manifest.profile_digest[0] ^= 1;
    assert!(matches!(
        mismatched.validate(),
        Err(BundleContractErrorV1::ProfileInvalid
            | BundleContractErrorV1::SignatureInvalid
            | BundleContractErrorV1::ModeParityMismatch)
    ));
    Ok(())
}

#[test]
fn public_materializer_and_verifier_binaries_round_trip_current_archives() -> TestResult {
    let _guard = materializer_process_guard();
    let root = temporary_root("conformance-cli")?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let publication = root.join("publication");
    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let status = Command::new(&materializer)
        .current_dir(&root)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg("publication")
        .status()?;
    assert!(status.success());

    let archives = release_archives(&publication)?;
    assert_eq!(archives.len(), 14);
    for archive_path in &archives {
        let bytes = fs::read(archive_path)?;
        verify_archive_independently(&bytes)?;
        let filename = archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("archive filename is not UTF-8")?;
        verify_archive_release_filename(&bytes, filename)?;
    }
    let verifier = std::env::var_os("CARGO_BIN_EXE_verify-conformance-bundle")
        .ok_or("verifier binary path is unavailable")?;
    assert!(Command::new(verifier).args(&archives).status()?.success());
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
    let output = root.join("output");
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
        Err(BundleContractErrorV1::MemberMissing)
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

fn mutate_profile_fields(profile: &mut [Value], mutation: usize) -> TestResult {
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

#[test]
fn independent_verifier_rejects_each_current_profile_contract_mutation() -> TestResult {
    for mutation in 0..24 {
        let archive = mutate_profile_archive(|profile| mutate_profile_fields(profile, mutation))?;
        assert!(
            verify_archive_independently(&archive).is_err(),
            "profile mutation {mutation} unexpectedly verified"
        );
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
        _ => Err(format!("unsupported archive mutation {mutation}").into()),
    }
}

#[test]
fn independent_verifier_rejects_manifest_member_and_expected_mutations() -> TestResult {
    for mutation in 0..10 {
        let archive = mutate_archive(|archive| mutate_archive_fields(archive, mutation))?;
        assert!(
            verify_archive_independently(&archive).is_err(),
            "archive mutation {mutation} unexpectedly verified"
        );
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
    assert!(expected.starts_with("inputs/"));
}

#[test]
fn independent_verifier_rejects_noncanonical_or_incomplete_archives() {
    let malformed = [0x84, 0x80, 0x80, 0x40, 0x40];
    assert!(matches!(
        verify_archive_independently(&malformed),
        Err(BundleContractErrorV1::ArchiveEncodingInvalid
            | BundleContractErrorV1::LifecycleInvalid
            | BundleContractErrorV1::MemberMissing)
    ));
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
