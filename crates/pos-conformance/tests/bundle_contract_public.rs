#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public archive-contract regression tests for the current CPF1/FPR1/FPP1 surface.

pub mod support;

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
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use support::{
    ArchiveField, ArtifactDescriptorField, DescriptorField, FixtureField, ManifestField,
    MemberField, ProfileField, ProviderBindingField, TemporaryOutput,
};

static MATERIALIZER_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn materializer_process_guard() -> MutexGuard<'static, ()> {
    MATERIALIZER_PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum StagingMutation {
    ReplaceIdentity,
    RelaxPermissions,
    RelaxRetainedPermissions,
    CorruptFiles,
    InjectSymlink,
    InjectFifo,
    BlockFutureDirectory,
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn signal_process(child: &std::process::Child, signal: &str) -> TestResult {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("failed to send {signal} to materializer").into())
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn await_staging_directory(parent: &Path, child: &mut std::process::Child) -> TestResult<PathBuf> {
    for _ in 0..200_000 {
        if let Some(status) = child.try_wait()? {
            return Err(
                format!("materializer exited before staging was observable: {status}").into(),
            );
        }
        if let Some(staging) = fs::read_dir(parent)?.find_map(|entry| {
            entry.ok().and_then(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pigloros-conformance-staging-")
                    .then(|| entry.path())
            })
        }) {
            return Ok(staging);
        }
        std::thread::yield_now();
    }
    child.kill()?;
    child.wait()?;
    Err("materializer staging directory was not observable".into())
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn staged_regular_files(directory: &Path) -> TestResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            files.extend(staged_regular_files(&entry.path())?);
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
    Ok(files)
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn await_staged_regular_files(
    staging: &Path,
    child: &mut std::process::Child,
) -> TestResult<Vec<PathBuf>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "materializer exited before staged files were observable: {status}"
            )
            .into());
        }
        let files = staged_regular_files(staging)?;
        if files.len() >= 2 {
            return Ok(files);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    child.kill()?;
    child.wait()?;
    Err("materializer staged fewer than two regular files".into())
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn await_stopped_process(child: &mut std::process::Child) -> TestResult {
    let status_path = format!("/proc/{}/status", child.id());
    for _ in 0..200_000 {
        if let Some(status) = child.try_wait()? {
            return Err(format!("materializer exited before SIGSTOP: {status}").into());
        }
        if fs::read_to_string(&status_path)?.lines().any(|line| {
            line.strip_prefix("State:")
                .is_some_and(|state| state.trim_start().starts_with('T'))
        }) {
            return Ok(());
        }
        std::thread::yield_now();
    }
    child.kill()?;
    child.wait()?;
    Err("materializer did not enter the stopped state".into())
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn mutate_live_staging(
    materializer: &std::ffi::OsStr,
    key: &str,
    mutation: StagingMutation,
) -> TestResult<String> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Stdio;

    let root = temporary_root("materializer-staging-mutation")?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let destination = root.join(source_inventory_address());
    let mut child = Command::new(materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg(&destination)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let staging = await_staging_directory(&root, &mut child)?;
    let staged_files = if matches!(mutation, StagingMutation::CorruptFiles) {
        await_staged_regular_files(&staging, &mut child)?
    } else {
        Vec::new()
    };
    signal_process(&child, "STOP")?;
    await_stopped_process(&mut child)?;

    let mutation_result = match mutation {
        StagingMutation::ReplaceIdentity => {
            let retained = root.join("retained-staging");
            fs::rename(&staging, retained)
                .and_then(|()| fs::create_dir(&staging))
                .and_then(|()| fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)))
        }
        StagingMutation::RelaxPermissions => {
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))
        }
        StagingMutation::RelaxRetainedPermissions => {
            let retained = root.join("retained-staging");
            fs::rename(&staging, &retained)
                .and_then(|()| fs::set_permissions(&retained, fs::Permissions::from_mode(0o755)))
                .and_then(|()| fs::create_dir(&staging))
                .and_then(|()| fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)))
        }
        StagingMutation::CorruptFiles => staged_files
            .iter()
            .try_for_each(|path| fs::write(path, b"corrupted staged bytes")),
        StagingMutation::InjectSymlink => symlink("/dev/null", staging.join("injected-link"))
            .and_then(|()| fs::create_dir(&destination)),
        StagingMutation::InjectFifo => {
            let status = Command::new("mkfifo")
                .arg(staging.join("injected-fifo"))
                .status()?;
            if !status.success() {
                return Err("mkfifo could not create the staged special file".into());
            }
            fs::create_dir(&destination)
        }
        StagingMutation::BlockFutureDirectory => {
            symlink("/dev/null", staging.join("empirical-evaluation"))
        }
    };
    let resume_result = signal_process(&child, "CONT");
    if let Err(error) = mutation_result {
        child.kill()?;
        child.wait()?;
        return Err(error.into());
    }
    if let Err(error) = resume_result {
        child.kill()?;
        child.wait()?;
        return Err(error);
    }

    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    Ok(String::from_utf8(output.stderr)?)
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
const MATRIX_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/matrix/execution-matrix.json");
const AUTHORITY_INVENTORY_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/expected-authority/inventory.json");
const PROFILE_SCHEMA_BYTES: &[u8] = b"cpf1 schema";
const FIXTURE_CONTRACT_POLICY_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/fixture-family-contract.json");
const DRAFT_AUTHORITY_DECLARATION_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/draft-execution-authority.json");
const EVALUATOR_PROTOCOL_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/evaluator-protocol-v1.json");
const EVALUATOR_REQUEST_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/evaluator-request-v1.cddl");
const EVALUATOR_REPORT_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/evaluator-report-v1.cddl");
const SUPPORT_PACKAGE_MANIFEST_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/package-manifest.json");
const EXPECTED_BYTES: &[u8] = br#"{"status":"pending"}"#;
const PAYLOAD_BYTES: &[u8] = b"public fixture payload";
const DRAFT_FIXTURE_AUTHORITY_KEY: [u8; 32] = [7; 32];
const DRAFT_FIXTURE_AUTHORITY_PUBLIC_KEY: [u8; 32] = [
    0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
    0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,
];

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

const fn fixture_family_name(family: FixtureFamilyV1) -> &'static str {
    match family {
        FixtureFamilyV1::Positive => "positive",
        FixtureFamilyV1::Denied => "denied",
        FixtureFamilyV1::Malformed => "malformed",
        FixtureFamilyV1::ResourceExhaustion => "resource-exhaustion",
        FixtureFamilyV1::DeletionRedaction => "deletion-redaction",
        FixtureFamilyV1::Downgrade => "downgrade",
        FixtureFamilyV1::IndependentEvaluation => "independent-evaluation",
    }
}

fn fixture_from_schema(
    family_schema: &ProviderFamilySchemaV1,
    execution: [u8; 32],
) -> TestResult<FixtureDescriptorV1> {
    let failure = NamespacedFailureV1 {
        owner_id: "pigloros.core".to_owned(),
        contract_version: "1.0.0".to_owned(),
        code_id: "provenance-missing".to_owned(),
    };
    let family_name = fixture_family_name(family_schema.family);
    let case_id = format!("example-{family_name}");
    let expected_path =
        expected_result_member_path(&case_id, ClaimLayerV1::ArtifactIntegrity, &execution);
    let payload_path = fixture_input_member_path(
        &case_id,
        ClaimLayerV1::ArtifactIntegrity,
        &execution,
        "input.bin",
    );
    let evidence_bytes = draft_evidence_bytes(&case_id, family_name)?;
    let evidence_path = format!(
        "evidence/{case_id}/{}.json",
        pos_conformance::hex_digest(&execution)
    );
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
        payload: artifact(&payload_path, "application/octet-stream", PAYLOAD_BYTES)?,
        auxiliary: vec![
            artifact(&evidence_path, "application/json", &evidence_bytes)?,
            artifact(&expected_path, "application/json", EXPECTED_BYTES)?,
        ],
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
            source_digest: *blake3::hash(SOURCE_PROVENANCE_BYTES).as_bytes(),
            build_digest: *blake3::hash(BUILD_PROVENANCE_BYTES).as_bytes(),
            publication_review_digest: *blake3::hash(PUBLICATION_REVIEW_BYTES).as_bytes(),
            limitations_digest: *blake3::hash(LIMITATIONS_BYTES).as_bytes(),
        },
        transition: None,
        fixture_digest: [0; 32],
    };
    fixture.fixture_digest = fixture.digest();
    Ok(fixture)
}

fn draft_evidence_bytes(case_id: &str, family: &str) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "case_id": case_id,
        "claim_layer": "artifact-integrity",
        "executed_at": null,
        "execution_result": null,
        "family": family,
        "input_blake3_digest": pos_conformance::hex_digest(blake3::hash(PAYLOAD_BYTES).as_bytes()),
        "status": "pending"
    }))?)
}

fn bind_downgrade_authority(
    fixture: &mut FixtureDescriptorV1,
    trust_policy_snapshot_digest: [u8; 32],
) -> TestResult {
    if fixture.family != FixtureFamilyV1::Downgrade {
        return Ok(());
    }
    let mut next_provider = provider_key();
    next_provider.abi_minor = 1;
    let transition = pos_conformance::FixtureContractTransitionV1 {
        from: provider_key(),
        to: next_provider,
    };
    fixture.trust_policy_snapshot_digest = Some(trust_policy_snapshot_digest);
    fixture.release_admission_digest = Some(
        *blake3::hash(&release_admission_bytes(
            &fixture.case_id,
            fixture.execution_profile_digest,
            trust_policy_snapshot_digest,
            &transition.from,
            &transition.to,
        )?)
        .as_bytes(),
    );
    fixture.transition = Some(transition);
    fixture.fixture_digest = fixture.digest();
    Ok(())
}

fn current_fixtures(
    family_schemas: &[ProviderFamilySchemaV1],
    execution_profiles: &[[u8; 32]],
    trust_policy_snapshot_digest: [u8; 32],
) -> TestResult<Vec<FixtureDescriptorV1>> {
    let mut fixtures = execution_profiles
        .iter()
        .flat_map(|execution| {
            family_schemas.iter().map(move |family_schema| {
                let mut fixture = fixture_from_schema(family_schema, *execution)?;
                bind_downgrade_authority(&mut fixture, trust_policy_snapshot_digest)?;
                Ok(fixture)
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    fixtures.sort_by_key(|fixture| {
        (
            fixture.provider_key.clone(),
            fixture.family,
            fixture.case_id.clone(),
            fixture.execution_profile_digest,
            fixture.modes.clone(),
        )
    });
    Ok(fixtures)
}

fn current_profile(
    fixtures: Vec<FixtureDescriptorV1>,
    registry_bytes: &[u8],
    execution_profile_digests: Vec<[u8; 32]>,
    trust_policy_snapshot_digest: [u8; 32],
) -> TestResult<ConformanceProfileV1> {
    let mut profile = ConformanceProfileV1 {
        profile_id: "pigloros.current.example".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: *blake3::hash(NORMATIVE_BYTES).as_bytes(),
        execution_matrix_digest: *blake3::hash(MATRIX_BYTES).as_bytes(),
        execution_profile_digests,
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
            protocol_digest: *blake3::hash(EVALUATOR_PROTOCOL_BYTES).as_bytes(),
            request_schema_digest: *blake3::hash(EVALUATOR_REQUEST_SCHEMA_BYTES).as_bytes(),
            report_schema_digest: *blake3::hash(EVALUATOR_REPORT_SCHEMA_BYTES).as_bytes(),
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
            trust_policy_snapshot_digest,
            requirements_digest: digest(55),
        },
        fixture_contract_policy_digest: *blake3::hash(FIXTURE_CONTRACT_POLICY_BYTES).as_bytes(),
        limitations_digest: *blake3::hash(LIMITATIONS_BYTES).as_bytes(),
        provenance_digest: *blake3::hash(PUBLICATION_REVIEW_BYTES).as_bytes(),
        previous_profile_digest: None,
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile.digest();
    Ok(profile)
}

fn current_provenance_members() -> [BundleMemberV1; 3] {
    [
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
    ]
}

fn expected_results(
    fixtures: &[FixtureDescriptorV1],
    mode: BundleModeV1,
) -> TestResult<Vec<BundleExpectedResultV1>> {
    let mut expected = fixtures
        .iter()
        .map(|fixture| {
            let descriptor = fixture
                .auxiliary
                .iter()
                .find(|descriptor| !descriptor.member_path.starts_with("evidence/"))
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
    Ok(expected)
}

fn append_release_admissions(
    members: &mut Vec<BundleMemberV1>,
    fixtures: &[FixtureDescriptorV1],
) -> TestResult {
    for fixture in fixtures
        .iter()
        .filter(|fixture| fixture.family == FixtureFamilyV1::Downgrade)
    {
        let transition = fixture.transition.as_ref().ok_or("transition missing")?;
        members.push(BundleMemberV1::supporting(
            format!(
                "authority/release-admissions/{}-{}.rad1",
                fixture.case_id,
                pos_conformance::hex_digest(&fixture.execution_profile_digest)
            ),
            release_admission_bytes(
                &fixture.case_id,
                fixture.execution_profile_digest,
                fixture
                    .trust_policy_snapshot_digest
                    .ok_or("trust-policy digest missing")?,
                &transition.from,
                &transition.to,
            )?,
            BundleMemberRoleV1::ReleaseAdmission,
        ));
    }
    Ok(())
}

fn current_fixture_members(profile: &ConformanceProfileV1) -> TestResult<Vec<BundleMemberV1>> {
    profile
        .fixtures
        .iter()
        .map(current_fixture_member_set)
        .collect::<TestResult<Vec<_>>>()
        .map(|sets| sets.into_iter().flatten().collect())
}

fn current_fixture_member_set(fixture: &FixtureDescriptorV1) -> TestResult<[BundleMemberV1; 3]> {
    let evidence = fixture
        .auxiliary
        .iter()
        .find(|descriptor| descriptor.member_path.starts_with("evidence/"))
        .ok_or("evidence descriptor is absent")?;
    let expected = fixture
        .auxiliary
        .iter()
        .find(|descriptor| !descriptor.member_path.starts_with("evidence/"))
        .ok_or("expected-result descriptor is absent")?;
    Ok([
        BundleMemberV1::fixture_input(fixture.payload.member_path.clone(), PAYLOAD_BYTES.to_vec()),
        BundleMemberV1::evidence_status(
            evidence.member_path.clone(),
            draft_evidence_bytes(&fixture.case_id, fixture_family_name(fixture.family))?,
        ),
        BundleMemberV1::expected_result(expected.member_path.clone(), EXPECTED_BYTES.to_vec()),
    ])
}

fn current_static_support_members() -> Vec<BundleMemberV1> {
    vec![
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
            "support/limitations.md",
            LIMITATIONS_BYTES.to_vec(),
            BundleMemberRoleV1::Limitations,
        ),
        BundleMemberV1::supporting(
            "support/schema-cpf1-v1.cddl",
            PROFILE_SCHEMA_BYTES.to_vec(),
            BundleMemberRoleV1::Schema,
        ),
        BundleMemberV1::supporting(
            "support/evaluator-protocol-v1.json",
            EVALUATOR_PROTOCOL_BYTES.to_vec(),
            BundleMemberRoleV1::Schema,
        ),
        BundleMemberV1::supporting(
            "support/evaluator-request-v1.cddl",
            EVALUATOR_REQUEST_SCHEMA_BYTES.to_vec(),
            BundleMemberRoleV1::Schema,
        ),
        BundleMemberV1::supporting(
            "support/evaluator-report-v1.cddl",
            EVALUATOR_REPORT_SCHEMA_BYTES.to_vec(),
            BundleMemberRoleV1::Schema,
        ),
        BundleMemberV1::supporting(
            "support/fixture-family-contract.json",
            FIXTURE_CONTRACT_POLICY_BYTES.to_vec(),
            BundleMemberRoleV1::FixtureContractPolicy,
        ),
        BundleMemberV1::supporting(
            "support/package-manifest.json",
            SUPPORT_PACKAGE_MANIFEST_BYTES.to_vec(),
            BundleMemberRoleV1::Schema,
        ),
        BundleMemberV1::supporting(
            "support/draft-execution-authority.json",
            DRAFT_AUTHORITY_DECLARATION_BYTES.to_vec(),
            BundleMemberRoleV1::AuthorityDeclaration,
        ),
        BundleMemberV1::authority_inventory(AUTHORITY_INVENTORY_BYTES.to_vec()),
        BundleMemberV1::execution_matrix(MATRIX_BYTES.to_vec()),
    ]
}

fn current_authority_members(
    execution_profiles: &[Vec<u8>; 2],
    trust_policy_snapshot: Vec<u8>,
    package_path: &str,
    package_bytes: Vec<u8>,
    registry_bytes: Vec<u8>,
) -> Vec<BundleMemberV1> {
    vec![
        BundleMemberV1::supporting(
            "authority/execution-profiles/deterministic-local-v1.epf1",
            execution_profiles[0].clone(),
            BundleMemberRoleV1::ExecutionProfile,
        ),
        BundleMemberV1::supporting(
            "authority/execution-profiles/deterministic-air-gapped-v1.epf1",
            execution_profiles[1].clone(),
            BundleMemberRoleV1::ExecutionProfile,
        ),
        BundleMemberV1::supporting(
            "authority/trust-policy-snapshot.tps1",
            trust_policy_snapshot,
            BundleMemberRoleV1::TrustPolicySnapshot,
        ),
        BundleMemberV1::fixture_provider_package(package_path, package_bytes),
        BundleMemberV1::fixture_provider_registry(registry_bytes),
    ]
}

fn current_bundle_members(
    family_schemas: &[ProviderFamilySchemaV1],
    profile: &ConformanceProfileV1,
    execution_profiles: &[Vec<u8>; 2],
    trust_policy_snapshot: Vec<u8>,
    package_path: &str,
    package_bytes: Vec<u8>,
    registry_bytes: Vec<u8>,
) -> TestResult<Vec<BundleMemberV1>> {
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
    members.extend(current_fixture_members(profile)?);
    members.extend(current_static_support_members());
    members.extend(current_authority_members(
        execution_profiles,
        trust_policy_snapshot,
        package_path,
        package_bytes,
        registry_bytes,
    ));
    append_release_admissions(&mut members, &profile.fixtures)?;
    members.extend(current_provenance_members());
    Ok(members)
}

fn current_bundle_inputs(mode: BundleModeV1) -> TestResult<CurrentBundleInputs> {
    let ProviderContractInputs {
        family_schemas,
        package_path,
        package_bytes,
        registry_bytes,
    } = current_provider_contract_inputs()?;

    let execution_profiles = [
        execution_profile_bytes("deterministic-local-v1")?,
        execution_profile_bytes("deterministic-air-gapped-v1")?,
    ];
    let mut execution_profile_digests = execution_profiles
        .iter()
        .map(|profile| *blake3::hash(profile).as_bytes())
        .collect::<Vec<_>>();
    execution_profile_digests.sort_unstable();
    let trust_policy_snapshot = trust_policy_snapshot_bytes()?;
    let trust_policy_snapshot_digest = *blake3::hash(&trust_policy_snapshot).as_bytes();
    let fixtures = current_fixtures(
        &family_schemas,
        &execution_profile_digests,
        trust_policy_snapshot_digest,
    )?;
    let expected = expected_results(&fixtures, mode)?;
    let profile = current_profile(
        fixtures,
        &registry_bytes,
        execution_profile_digests,
        trust_policy_snapshot_digest,
    )?;
    let members = current_bundle_members(
        &family_schemas,
        &profile,
        &execution_profiles,
        trust_policy_snapshot,
        package_path,
        package_bytes,
        registry_bytes,
    )?;
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

#[test]
fn bundle_rejects_tampered_execution_authority_artifacts() -> TestResult {
    for role in [
        BundleMemberRoleV1::ExecutionProfile,
        BundleMemberRoleV1::TrustPolicySnapshot,
        BundleMemberRoleV1::ReleaseAdmission,
    ] {
        let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
        let member = inputs
            .members
            .iter_mut()
            .find(|member| member.role == role)
            .ok_or("Draft authority member is absent")?;
        let final_byte = member
            .bytes
            .last_mut()
            .ok_or("Draft authority member is empty")?;
        *final_byte ^= 1;
        member.digest = *blake3::hash(&member.bytes).as_bytes();
        assert!(ConformanceBundleV1::materialize(
            &inputs.profile,
            BundleModeV1::Local,
            inputs.members,
            inputs.expected,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn bundle_rejects_a_self_consistent_partial_execution_authority() -> TestResult {
    let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
    let omitted_path = "authority/execution-profiles/deterministic-air-gapped-v1.epf1";
    let omitted_digest = inputs
        .members
        .iter()
        .find(|member| member.path == omitted_path)
        .map(|member| member.digest)
        .ok_or("Air-Gapped execution profile is absent")?;
    inputs.members.retain(|member| member.path != omitted_path);
    inputs
        .profile
        .execution_profile_digests
        .retain(|digest| digest != &omitted_digest);
    inputs
        .profile
        .fixtures
        .retain(|fixture| fixture.execution_profile_digest != omitted_digest);
    inputs.profile.profile_digest = inputs.profile.digest();
    assert_eq!(
        ConformanceBundleV1::materialize(
            &inputs.profile,
            BundleModeV1::Local,
            inputs.members,
            inputs.expected,
        )
        .err(),
        Some(BundleContractErrorV1::ProfileInvalid)
    );
    Ok(())
}

#[test]
fn bundle_rejects_tampered_policy_and_authority_declaration() -> TestResult {
    for (path, role) in [
        (
            "support/fixture-family-contract.json",
            BundleMemberRoleV1::FixtureContractPolicy,
        ),
        (
            "support/draft-execution-authority.json",
            BundleMemberRoleV1::AuthorityDeclaration,
        ),
        (
            "support/evaluator-protocol-v1.json",
            BundleMemberRoleV1::Schema,
        ),
        (
            "support/evaluator-request-v1.cddl",
            BundleMemberRoleV1::Schema,
        ),
        (
            "support/evaluator-report-v1.cddl",
            BundleMemberRoleV1::Schema,
        ),
        ("support/package-manifest.json", BundleMemberRoleV1::Schema),
    ] {
        let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
        let member = inputs
            .members
            .iter_mut()
            .find(|member| member.path == path && member.role == role)
            .ok_or("bound support member is absent")?;
        member.bytes.push(b' ');
        member.digest = *blake3::hash(&member.bytes).as_bytes();
        assert!(ConformanceBundleV1::materialize(
            &inputs.profile,
            BundleModeV1::Local,
            inputs.members,
            inputs.expected,
        )
        .is_err());

        let bundle = signed_current_bundle(BundleModeV1::Local)?;
        let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
        let Value::Array(fields) = &mut archive else {
            return Err("archive is not an array".into());
        };
        replace_archive_member_bytes(fields, path, b"tampered")?;
        resign_archive(&mut archive)?;
        assert!(verify_archive_independently(&encode_value(&archive)?).is_err());
    }
    Ok(())
}

#[test]
fn bundle_rejects_self_declared_noncanonical_authority_sources() -> TestResult {
    for (role, updates_profile_digest) in [
        (BundleMemberRoleV1::ExecutionMatrix, true),
        (BundleMemberRoleV1::AuthorityInventory, false),
    ] {
        let mut inputs = current_bundle_inputs(BundleModeV1::Local)?;
        let member = inputs
            .members
            .iter_mut()
            .find(|member| member.role == role)
            .ok_or("canonical authority source is absent")?;
        member.bytes.push(b' ');
        member.digest = *blake3::hash(&member.bytes).as_bytes();
        if updates_profile_digest {
            inputs.profile.execution_matrix_digest = member.digest;
            inputs.profile.profile_digest = inputs.profile.digest();
        }
        assert_eq!(
            ConformanceBundleV1::materialize(
                &inputs.profile,
                BundleModeV1::Local,
                inputs.members,
                inputs.expected,
            )
            .err(),
            Some(BundleContractErrorV1::MemberDigestMismatch)
        );
    }
    Ok(())
}

fn mutate_draft_authority_archive(
    path: &str,
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(archive_fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    let authority_bytes = match archive_member_fields(archive_fields, path)?.get(1) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("authority member is not bytes".into()),
    };
    let mut authority: Value = ciborium::from_reader(authority_bytes.as_slice())?;
    let Value::Array(fields) = &mut authority else {
        return Err("authority member is not an array".into());
    };
    mutate(fields)?;
    if path == "authority/trust-policy-snapshot.tps1" {
        let unsigned = encode_value(&Value::Array(fields[..12].to_vec()))?;
        fields[12] = Value::Bytes(
            SigningKey::from_bytes(&DRAFT_FIXTURE_AUTHORITY_KEY)
                .sign(&unsigned)
                .to_bytes()
                .to_vec(),
        );
    }
    let encoded = encode_value(&authority)?;
    replace_archive_member_bytes(archive_fields, path, &encoded)?;
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

fn assert_authority_archive_rejected_by_both(archive: &[u8]) {
    assert!(ConformanceBundleV1::from_canonical_cbor(archive).is_err());
    assert!(verify_archive_independently(archive).is_err());
}

#[test]
fn authority_members_reject_closed_contract_mutations() -> TestResult {
    let changed_scheduler = mutate_draft_authority_archive(
        "authority/execution-profiles/deterministic-local-v1.epf1",
        |fields| {
            replace_value(
                fields,
                7,
                Value::Text("other-scheduler".to_owned()),
                "scheduler",
            )
        },
    )?;
    assert_authority_archive_rejected_by_both(&changed_scheduler);

    let changed_epoch =
        mutate_draft_authority_archive("authority/trust-policy-snapshot.tps1", |fields| {
            replace_value(
                fields,
                3,
                Value::Integer(2_u64.into()),
                "trust-policy epoch",
            )
        })?;
    assert_authority_archive_rejected_by_both(&changed_epoch);

    let bundle = signed_current_bundle(BundleModeV1::Local)?;
    let mut archive: Value = ciborium::from_reader(bundle.to_canonical_cbor()?.as_slice())?;
    let Value::Array(archive_fields) = &mut archive else {
        return Err("archive is not an array".into());
    };
    let path = "authority/execution-profiles/deterministic-local-v1.epf1";
    replace_value(
        archive_member_fields(archive_fields, path)?,
        0,
        Value::Text("authority/execution-profiles/wrong.epf1".to_owned()),
        "execution profile member path",
    )?;
    replace_value(
        archive_descriptor_fields(archive_fields, path)?,
        0,
        Value::Text("authority/execution-profiles/wrong.epf1".to_owned()),
        "execution profile descriptor path",
    )?;
    resign_archive(&mut archive)?;
    let wrong_path = encode_value(&archive)?;
    assert_authority_archive_rejected_by_both(&wrong_path);
    Ok(())
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    support::encode_value(value)
}

fn labeled_digest(label: &str, bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(label.len() + 1 + bytes.len());
    preimage.extend_from_slice(label.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(bytes);
    *blake3::hash(&preimage).as_bytes()
}

fn execution_profile_bytes(profile_id: &str) -> TestResult<Vec<u8>> {
    let fields = vec![
        Value::Text("EPF1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(profile_id.to_owned()),
        Value::Text("1.0.0".to_owned()),
        Value::Array(vec![
            Value::Integer(1_u64.into()),
            Value::Integer(2_u64.into()),
        ]),
        Value::Bool(false),
        Value::Array(Vec::new()),
        Value::Text("fixture-scheduler-v1".to_owned()),
        Value::Text("fixture-numeric-v1".to_owned()),
        Value::Text("fixture-schema-v1".to_owned()),
        Value::Text("fixture-artifact-v1".to_owned()),
        Value::Text("fixture-budget-v1".to_owned()),
        Value::Array(Vec::new()),
        Value::Null,
    ];
    let mut encoded = fields.clone();
    encoded.push(Value::Bytes(
        labeled_digest(
            "PiglorOS.ExecutionProfile.v1",
            &encode_value(&Value::Array(fields))?,
        )
        .to_vec(),
    ));
    encode_value(&Value::Array(encoded))
}

fn trust_policy_snapshot_bytes() -> TestResult<Vec<u8>> {
    let fields = vec![
        Value::Text("TPS1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text("pigloros.fixture.conformance-draft".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Text("pigloros.fixture.conformance-authority".to_owned()),
        Value::Bytes(DRAFT_FIXTURE_AUTHORITY_PUBLIC_KEY.to_vec()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Text("2030-01-01T00:00:00Z".to_owned()),
        Value::Null,
    ];
    let mut signed = fields.clone();
    signed.push(Value::Bytes(
        SigningKey::from_bytes(&DRAFT_FIXTURE_AUTHORITY_KEY)
            .sign(&encode_value(&Value::Array(fields))?)
            .to_bytes()
            .to_vec(),
    ));
    encode_value(&Value::Array(signed))
}

fn provider_key_value(key: &FixtureProviderKeyV1) -> Value {
    Value::Array(vec![
        Value::Text(key.provider_id.clone()),
        Value::Text(key.contract_version.clone()),
        Value::Integer(u64::from(key.abi_major).into()),
        Value::Integer(u64::from(key.abi_minor).into()),
    ])
}

fn release_admission_bytes(
    case_id: &str,
    execution_profile_digest: [u8; 32],
    trust_policy_snapshot_digest: [u8; 32],
    from: &FixtureProviderKeyV1,
    to: &FixtureProviderKeyV1,
) -> TestResult<Vec<u8>> {
    let fields = vec![
        Value::Text("RAD1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Text(case_id.to_owned()),
        Value::Bytes(execution_profile_digest.to_vec()),
        Value::Bytes(trust_policy_snapshot_digest.to_vec()),
        provider_key_value(from),
        provider_key_value(to),
        Value::Bool(false),
        Value::Text("pigloros.fixture.conformance-authority".to_owned()),
    ];
    let mut signed = fields.clone();
    signed.push(Value::Bytes(
        SigningKey::from_bytes(&DRAFT_FIXTURE_AUTHORITY_KEY)
            .sign(&encode_value(&Value::Array(fields))?)
            .to_bytes()
            .to_vec(),
    ));
    encode_value(&Value::Array(signed))
}

fn contract_digest(domain: &[u8], fields: &[Value]) -> TestResult<[u8; 32]> {
    support::contract_digest(domain, fields)
}

fn resign_archive(value: &mut Value) -> TestResult {
    support::resign_archive(value)
}

fn array_field<'a>(
    fields: &'a mut [Value],
    index: usize,
    name: &str,
) -> TestResult<&'a mut Vec<Value>> {
    support::array_field(fields, index, name)
}

fn fixture_with_family(fields: &mut [Value], family: u64) -> TestResult<&mut Vec<Value>> {
    fields
        .iter_mut()
        .find_map(|fixture| {
            let Value::Array(fixture_fields) = fixture else {
                return None;
            };
            matches!(fixture_fields.get(3), Some(Value::Integer(value)) if u64::try_from(*value) == Ok(family))
                .then_some(fixture_fields)
        })
        .ok_or_else(|| format!("fixture family {family} is absent").into())
}

fn replace_value(fields: &mut [Value], index: usize, value: Value, name: &str) -> TestResult {
    support::replace_value(fields, index, value, name)
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
    let Value::Array(members) = &mut archive_fields[ArchiveField::Members.index()] else {
        return Err("archive members are not an array".into());
    };
    let profile_member = members
        .iter_mut()
        .find(|member| {
            matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text(support::PROFILE_MEMBER_PATH.to_owned())))
        })
        .ok_or("profile member is absent")?;
    let Value::Array(profile_member_fields) = profile_member else {
        return Err("profile member is not an array".into());
    };
    let Value::Bytes(profile_bytes) = &profile_member_fields[MemberField::Bytes.index()] else {
        return Err("profile member is not bytes".into());
    };
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let Value::Array(profile_fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    mutate(profile_fields)?;
    if let Some(Value::Array(fixtures)) = profile_fields.get_mut(ProfileField::Fixtures.index()) {
        for fixture in fixtures {
            let Value::Array(fields) = fixture else {
                continue;
            };
            if fields.len() == FixtureField::Digest.index() + 1 {
                fields[FixtureField::Digest.index()] = Value::Bytes(
                    contract_digest(
                        b"PiglorOS.Conformance.Fixture.v1",
                        &fields[..FixtureField::Digest.index()],
                    )?
                    .to_vec(),
                );
            }
        }
    }
    mutate_after_fixture_digest(profile_fields)?;
    if profile_fields.len() == ProfileField::Digest.index() + 1 {
        profile_fields[ProfileField::Digest.index()] = Value::Bytes(
            contract_digest(
                b"PiglorOS.ConformanceProfile.v1",
                &profile_fields[..ProfileField::Digest.index()],
            )?
            .to_vec(),
        );
    }
    mutate_after_profile_digest(profile_fields)?;
    let profile_digest = match &profile_fields[ProfileField::Digest.index()] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err("profile digest is not bytes".into()),
    };
    let new_profile_bytes = encode_value(&profile)?;
    profile_member_fields[MemberField::Bytes.index()] = Value::Bytes(new_profile_bytes.clone());

    let Value::Array(manifest) = &mut archive_fields[ArchiveField::Manifest.index()] else {
        return Err("manifest is not an array".into());
    };
    manifest[ManifestField::ProfileDigest.index()] = Value::Bytes(profile_digest);
    let Value::Array(descriptors) = &mut manifest[ManifestField::MemberDescriptors.index()] else {
        return Err("manifest descriptors are not an array".into());
    };
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| {
            matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text(support::PROFILE_MEMBER_PATH.to_owned())))
        })
        .ok_or("profile descriptor is absent")?;
    let Value::Array(descriptor_fields) = descriptor else {
        return Err("profile descriptor is not an array".into());
    };
    descriptor_fields[DescriptorField::Length.index()] =
        Value::Integer(u64::try_from(new_profile_bytes.len())?.into());
    descriptor_fields[DescriptorField::Digest.index()] =
        Value::Bytes(blake3::hash(&new_profile_bytes).as_bytes().to_vec());
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
    support::archive_member_fields(archive, path)
}

fn archive_descriptor_fields<'a>(
    archive: &'a mut [Value],
    path: &str,
) -> TestResult<&'a mut Vec<Value>> {
    support::archive_descriptor_fields(archive, path)
}

fn replace_archive_member_bytes(archive: &mut [Value], path: &str, bytes: &[u8]) -> TestResult {
    support::replace_archive_member_bytes(archive, path, bytes)
}

fn refresh_profile_registry_binding(archive: &mut [Value], registry_bytes: &[u8]) -> TestResult {
    let profile_bytes = match archive_member_fields(archive, support::PROFILE_MEMBER_PATH)?
        .get(MemberField::Bytes.index())
    {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile member is not bytes".into()),
    };
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let Value::Array(profile_fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    let binding = array_field(
        profile_fields,
        ProfileField::ProviderRegistryBinding.index(),
        "provider binding",
    )?;
    let descriptor = array_field(
        binding,
        ProviderBindingField::RegistryDescriptor.index(),
        "provider registry descriptor",
    )?;
    replace_value(
        descriptor,
        ArtifactDescriptorField::Length.index(),
        Value::Integer(u64::try_from(registry_bytes.len())?.into()),
        "provider registry length",
    )?;
    replace_value(
        descriptor,
        ArtifactDescriptorField::Digest.index(),
        Value::Bytes(blake3::hash(registry_bytes).as_bytes().to_vec()),
        "provider registry digest",
    )?;
    let profile_digest = contract_digest(
        b"PiglorOS.ConformanceProfile.v1",
        &profile_fields[..ProfileField::Digest.index()],
    )?;
    replace_value(
        profile_fields,
        ProfileField::Digest.index(),
        Value::Bytes(profile_digest.to_vec()),
        "profile digest",
    )?;
    let profile_digest = match profile_fields.get(ProfileField::Digest.index()) {
        Some(Value::Bytes(digest)) => digest.clone(),
        _ => return Err("profile digest is not bytes".into()),
    };
    let profile_bytes = encode_value(&profile)?;
    replace_archive_member_bytes(archive, support::PROFILE_MEMBER_PATH, &profile_bytes)?;
    replace_value(
        array_field(archive, ArchiveField::Manifest.index(), "manifest")?,
        ManifestField::ProfileDigest.index(),
        Value::Bytes(profile_digest),
        "manifest profile digest",
    )
}

fn refresh_profile_matrix_binding(archive: &mut [Value], matrix_bytes: &[u8]) -> TestResult {
    let profile_bytes = match archive_member_fields(archive, support::PROFILE_MEMBER_PATH)?
        .get(MemberField::Bytes.index())
    {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("profile member is not bytes".into()),
    };
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let Value::Array(profile_fields) = &mut profile else {
        return Err("profile is not an array".into());
    };
    replace_value(
        profile_fields,
        ProfileField::ExecutionMatrixDigest.index(),
        Value::Bytes(blake3::hash(matrix_bytes).as_bytes().to_vec()),
        "execution matrix digest",
    )?;
    let profile_digest = contract_digest(
        b"PiglorOS.ConformanceProfile.v1",
        &profile_fields[..ProfileField::Digest.index()],
    )?;
    replace_value(
        profile_fields,
        ProfileField::Digest.index(),
        Value::Bytes(profile_digest.to_vec()),
        "profile digest",
    )?;
    let profile_bytes = encode_value(&profile)?;
    replace_archive_member_bytes(archive, support::PROFILE_MEMBER_PATH, &profile_bytes)?;
    replace_value(
        array_field(archive, ArchiveField::Manifest.index(), "manifest")?,
        ManifestField::ProfileDigest.index(),
        Value::Bytes(profile_digest.to_vec()),
        "manifest profile digest",
    )
}

const CURRENT_PROVIDER_INDEX: usize = 0;
const CURRENT_PROVIDER_SCHEMA_INDEX: usize = 0;

#[derive(Clone, Copy)]
enum ProviderRegistryField {
    Magic,
    Version,
    Providers,
    Digest,
}

impl ProviderRegistryField {
    const fn index(self) -> usize {
        match self {
            Self::Magic => 0,
            Self::Version => 1,
            Self::Providers => 2,
            Self::Digest => 3,
        }
    }
}

#[derive(Clone, Copy)]
enum ProviderEntryField {
    ClaimLayer,
    SubjectAdapter,
    PackageDescriptor,
}

impl ProviderEntryField {
    const fn index(self) -> usize {
        match self {
            Self::ClaimLayer => 4,
            Self::SubjectAdapter => 5,
            Self::PackageDescriptor => 6,
        }
    }
}

#[derive(Clone, Copy)]
enum ProviderKeyCborField {
    Identifier,
    Version,
    AbiMajor,
    AbiMinor,
}

impl ProviderKeyCborField {
    const fn index(self) -> usize {
        match self {
            Self::Identifier => 0,
            Self::Version => 1,
            Self::AbiMajor => 2,
            Self::AbiMinor => 3,
        }
    }
}

#[derive(Clone, Copy)]
enum ProviderPackageField {
    Magic,
    Version,
    ProviderKey,
    ClaimLayer,
    SubjectAdapter,
    FamilySchemas,
    LicenceDescriptor,
    NoticesDescriptor,
    Digest,
}

impl ProviderPackageField {
    const fn index(self) -> usize {
        match self {
            Self::Magic => 0,
            Self::Version => 1,
            Self::ProviderKey => 2,
            Self::ClaimLayer => 3,
            Self::SubjectAdapter => 4,
            Self::FamilySchemas => 5,
            Self::LicenceDescriptor => 6,
            Self::NoticesDescriptor => 7,
            Self::Digest => 11,
        }
    }
}

#[derive(Clone, Copy)]
enum ProviderFamilySchemaField {
    Family,
    Descriptor,
}

impl ProviderFamilySchemaField {
    const fn index(self) -> usize {
        match self {
            Self::Family => 0,
            Self::Descriptor => 1,
        }
    }
}

#[derive(Clone, Copy)]
enum ProviderRegistryMutation {
    InvalidMagic,
    InvalidVersion,
    EmptyProviders,
    InvalidDigest,
    InvalidProviderEntryShape,
    InvalidProviderClaimLayer,
    InvalidProviderSubjectAdapter,
    MissingProviderPackagePath,
    InvalidProviderIdentifier,
    NoncanonicalProviderVersion,
    InvalidProviderAbiMajor,
    InvalidProviderAbiMinor,
    AbsoluteProviderPackagePath,
    InvalidProviderPackageMediaType,
    InvalidProviderPackageLength,
    InvalidProviderPackageDigest,
    DuplicateProviderEntry,
}

impl ProviderRegistryMutation {
    const fn label(self) -> &'static str {
        match self {
            Self::InvalidMagic => "invalid registry magic",
            Self::InvalidVersion => "invalid registry version",
            Self::EmptyProviders => "empty registry providers",
            Self::InvalidDigest => "invalid registry digest",
            Self::InvalidProviderEntryShape => "invalid provider entry shape",
            Self::InvalidProviderClaimLayer => "invalid provider claim layer",
            Self::InvalidProviderSubjectAdapter => "invalid provider subject adapter",
            Self::MissingProviderPackagePath => "missing provider package path",
            Self::InvalidProviderIdentifier => "invalid provider identifier",
            Self::NoncanonicalProviderVersion => "noncanonical provider version",
            Self::InvalidProviderAbiMajor => "invalid provider ABI major",
            Self::InvalidProviderAbiMinor => "invalid provider ABI minor",
            Self::AbsoluteProviderPackagePath => "absolute provider package path",
            Self::InvalidProviderPackageMediaType => "invalid provider package media type",
            Self::InvalidProviderPackageLength => "invalid provider package length",
            Self::InvalidProviderPackageDigest => "invalid provider package digest",
            Self::DuplicateProviderEntry => "duplicate provider entry",
        }
    }
}

const PROVIDER_REGISTRY_MUTATIONS: [ProviderRegistryMutation; 17] = [
    ProviderRegistryMutation::InvalidMagic,
    ProviderRegistryMutation::InvalidVersion,
    ProviderRegistryMutation::EmptyProviders,
    ProviderRegistryMutation::InvalidDigest,
    ProviderRegistryMutation::InvalidProviderEntryShape,
    ProviderRegistryMutation::InvalidProviderClaimLayer,
    ProviderRegistryMutation::InvalidProviderSubjectAdapter,
    ProviderRegistryMutation::MissingProviderPackagePath,
    ProviderRegistryMutation::InvalidProviderIdentifier,
    ProviderRegistryMutation::NoncanonicalProviderVersion,
    ProviderRegistryMutation::InvalidProviderAbiMajor,
    ProviderRegistryMutation::InvalidProviderAbiMinor,
    ProviderRegistryMutation::AbsoluteProviderPackagePath,
    ProviderRegistryMutation::InvalidProviderPackageMediaType,
    ProviderRegistryMutation::InvalidProviderPackageLength,
    ProviderRegistryMutation::InvalidProviderPackageDigest,
    ProviderRegistryMutation::DuplicateProviderEntry,
];

#[derive(Clone, Copy)]
enum ProviderPackageMutation {
    InvalidMagic,
    InvalidVersion,
    EmptyProviderKey,
    EmptySchemas,
    InvalidSchemaFamily,
    InvalidSchemaDescriptor,
    InvalidLicenceDigest,
    InvalidDigest,
    InvalidProviderIdentifier,
    NoncanonicalProviderVersion,
    InvalidProviderAbiMajor,
    InvalidProviderAbiMinor,
    InvalidClaimLayer,
    InvalidSubjectAdapter,
    MissingFamilySchema,
    InvalidSchemaShape,
    AbsoluteSchemaPath,
    InvalidSchemaMediaType,
    InvalidSchemaLength,
    InvalidSchemaDigest,
    MissingNotices,
    CollidingSupportPath,
}

impl ProviderPackageMutation {
    const fn label(self) -> &'static str {
        match self {
            Self::InvalidMagic => "invalid package magic",
            Self::InvalidVersion => "invalid package version",
            Self::EmptyProviderKey => "empty package provider key",
            Self::EmptySchemas => "empty package schemas",
            Self::InvalidSchemaFamily => "invalid package schema family",
            Self::InvalidSchemaDescriptor => "invalid package schema descriptor",
            Self::InvalidLicenceDigest => "invalid package licence digest",
            Self::InvalidDigest => "invalid package digest",
            Self::InvalidProviderIdentifier => "invalid package provider identifier",
            Self::NoncanonicalProviderVersion => "noncanonical package provider version",
            Self::InvalidProviderAbiMajor => "invalid package provider ABI major",
            Self::InvalidProviderAbiMinor => "invalid package provider ABI minor",
            Self::InvalidClaimLayer => "invalid package claim layer",
            Self::InvalidSubjectAdapter => "invalid package subject adapter",
            Self::MissingFamilySchema => "missing package family schema",
            Self::InvalidSchemaShape => "invalid package schema shape",
            Self::AbsoluteSchemaPath => "absolute package schema path",
            Self::InvalidSchemaMediaType => "invalid package schema media type",
            Self::InvalidSchemaLength => "invalid package schema length",
            Self::InvalidSchemaDigest => "invalid package schema digest",
            Self::MissingNotices => "missing package notices",
            Self::CollidingSupportPath => "colliding package support path",
        }
    }
}

const PROVIDER_PACKAGE_MUTATIONS: [ProviderPackageMutation; 22] = [
    ProviderPackageMutation::InvalidMagic,
    ProviderPackageMutation::InvalidVersion,
    ProviderPackageMutation::EmptyProviderKey,
    ProviderPackageMutation::EmptySchemas,
    ProviderPackageMutation::InvalidSchemaFamily,
    ProviderPackageMutation::InvalidSchemaDescriptor,
    ProviderPackageMutation::InvalidLicenceDigest,
    ProviderPackageMutation::InvalidDigest,
    ProviderPackageMutation::InvalidProviderIdentifier,
    ProviderPackageMutation::NoncanonicalProviderVersion,
    ProviderPackageMutation::InvalidProviderAbiMajor,
    ProviderPackageMutation::InvalidProviderAbiMinor,
    ProviderPackageMutation::InvalidClaimLayer,
    ProviderPackageMutation::InvalidSubjectAdapter,
    ProviderPackageMutation::MissingFamilySchema,
    ProviderPackageMutation::InvalidSchemaShape,
    ProviderPackageMutation::AbsoluteSchemaPath,
    ProviderPackageMutation::InvalidSchemaMediaType,
    ProviderPackageMutation::InvalidSchemaLength,
    ProviderPackageMutation::InvalidSchemaDigest,
    ProviderPackageMutation::MissingNotices,
    ProviderPackageMutation::CollidingSupportPath,
];

fn provider_registry_entry(fields: &mut [Value]) -> TestResult<&mut Vec<Value>> {
    array_field(
        array_field(
            fields,
            ProviderRegistryField::Providers.index(),
            "registry providers",
        )?,
        CURRENT_PROVIDER_INDEX,
        "provider entry",
    )
}

fn provider_package_descriptor(entry: &mut [Value]) -> TestResult<&mut Vec<Value>> {
    array_field(
        entry,
        ProviderEntryField::PackageDescriptor.index(),
        "provider package descriptor",
    )
}

fn provider_package_schema(fields: &mut [Value]) -> TestResult<&mut Vec<Value>> {
    array_field(
        array_field(
            fields,
            ProviderPackageField::FamilySchemas.index(),
            "package schemas",
        )?,
        CURRENT_PROVIDER_SCHEMA_INDEX,
        "package schema",
    )
}

fn replace_mutated_value(
    fields: &mut [Value],
    index: usize,
    value: Value,
    name: &str,
    recompute_digest: bool,
) -> TestResult<bool> {
    replace_value(fields, index, value, name).map(|()| recompute_digest)
}

fn replace_registry_entry_field(
    fields: &mut [Value],
    field: ProviderEntryField,
    value: Value,
    name: &str,
) -> TestResult<bool> {
    replace_mutated_value(
        provider_registry_entry(fields)?,
        field.index(),
        value,
        name,
        true,
    )
}

fn replace_registry_field(
    fields: &mut [Value],
    field: ProviderRegistryField,
    value: Value,
    name: &str,
    recompute_digest: bool,
) -> TestResult<bool> {
    replace_mutated_value(fields, field.index(), value, name, recompute_digest)
}

fn invalidate_registry_magic(fields: &mut [Value]) -> TestResult<bool> {
    replace_registry_field(
        fields,
        ProviderRegistryField::Magic,
        Value::Text("FPR0".to_owned()),
        "registry magic",
        false,
    )
}

fn replace_registry_key_field(
    fields: &mut [Value],
    field: ProviderKeyCborField,
    value: Value,
    name: &str,
) -> TestResult<bool> {
    replace_mutated_value(
        provider_registry_entry(fields)?,
        field.index(),
        value,
        name,
        true,
    )
}

fn replace_registry_package_field(
    fields: &mut [Value],
    field: ArtifactDescriptorField,
    value: Value,
) -> TestResult<bool> {
    let descriptor = provider_package_descriptor(provider_registry_entry(fields)?)?;
    replace_mutated_value(
        descriptor,
        field.index(),
        value,
        "provider package descriptor field",
        true,
    )
}

fn invalidate_registry_entry_shape(fields: &mut [Value]) -> TestResult<bool> {
    let providers = array_field(
        fields,
        ProviderRegistryField::Providers.index(),
        "registry providers",
    )?;
    replace_mutated_value(
        providers,
        CURRENT_PROVIDER_INDEX,
        Value::Array(Vec::new()),
        "registry provider entry",
        true,
    )
}

fn duplicate_registry_entry(fields: &mut [Value]) -> TestResult<bool> {
    let providers = array_field(
        fields,
        ProviderRegistryField::Providers.index(),
        "registry providers",
    )?;
    let duplicate = providers.first().ok_or("provider entry is absent")?.clone();
    providers.push(duplicate);
    Ok(true)
}

fn mutate_provider_registry_fields(
    fields: &mut [Value],
    mutation: ProviderRegistryMutation,
) -> TestResult<bool> {
    match mutation {
        ProviderRegistryMutation::InvalidMagic => invalidate_registry_magic(fields),
        ProviderRegistryMutation::InvalidVersion => replace_registry_field(
            fields,
            ProviderRegistryField::Version,
            Value::Integer(2_u64.into()),
            "registry version",
            false,
        ),
        ProviderRegistryMutation::EmptyProviders => replace_registry_field(
            fields,
            ProviderRegistryField::Providers,
            Value::Array(Vec::new()),
            "registry providers",
            true,
        ),
        ProviderRegistryMutation::InvalidDigest => replace_registry_field(
            fields,
            ProviderRegistryField::Digest,
            Value::Bytes(vec![0; 32]),
            "registry digest",
            false,
        ),
        ProviderRegistryMutation::InvalidProviderEntryShape => {
            invalidate_registry_entry_shape(fields)
        }
        ProviderRegistryMutation::InvalidProviderClaimLayer => replace_registry_entry_field(
            fields,
            ProviderEntryField::ClaimLayer,
            Value::Integer(7_u64.into()),
            "provider claim layer",
        ),
        ProviderRegistryMutation::InvalidProviderSubjectAdapter => replace_registry_entry_field(
            fields,
            ProviderEntryField::SubjectAdapter,
            Value::Integer(3_u64.into()),
            "provider subject adapter",
        ),
        ProviderRegistryMutation::MissingProviderPackagePath => replace_registry_package_field(
            fields,
            ArtifactDescriptorField::Path,
            Value::Text("authority/providers/missing.cbor".to_owned()),
        ),
        ProviderRegistryMutation::InvalidProviderIdentifier => replace_registry_key_field(
            fields,
            ProviderKeyCborField::Identifier,
            Value::Text("INVALID".to_owned()),
            "provider identifier",
        ),
        ProviderRegistryMutation::NoncanonicalProviderVersion => replace_registry_key_field(
            fields,
            ProviderKeyCborField::Version,
            Value::Text("01.0.0".to_owned()),
            "provider version",
        ),
        ProviderRegistryMutation::InvalidProviderAbiMajor => replace_registry_key_field(
            fields,
            ProviderKeyCborField::AbiMajor,
            Value::Integer(65_536_u64.into()),
            "provider ABI",
        ),
        ProviderRegistryMutation::InvalidProviderAbiMinor => replace_registry_key_field(
            fields,
            ProviderKeyCborField::AbiMinor,
            Value::Integer(65_536_u64.into()),
            "provider ABI",
        ),
        ProviderRegistryMutation::AbsoluteProviderPackagePath => replace_registry_package_field(
            fields,
            ArtifactDescriptorField::Path,
            Value::Text("/invalid.cbor".to_owned()),
        ),
        ProviderRegistryMutation::InvalidProviderPackageMediaType => {
            replace_registry_package_field(
                fields,
                ArtifactDescriptorField::MediaType,
                Value::Text("INVALID".to_owned()),
            )
        }
        ProviderRegistryMutation::InvalidProviderPackageLength => replace_registry_package_field(
            fields,
            ArtifactDescriptorField::Length,
            Value::Integer(0_u64.into()),
        ),
        ProviderRegistryMutation::InvalidProviderPackageDigest => replace_registry_package_field(
            fields,
            ArtifactDescriptorField::Digest,
            Value::Bytes(vec![0; 32]),
        ),
        ProviderRegistryMutation::DuplicateProviderEntry => duplicate_registry_entry(fields),
    }
}

fn mutate_provider_registry_archive(mutation: ProviderRegistryMutation) -> TestResult<Vec<u8>> {
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
            .get(MemberField::Bytes.index())
        {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("provider registry is not bytes".into()),
        };
    let mut registry: Value = ciborium::from_reader(registry_bytes.as_slice())?;
    let Value::Array(fields) = &mut registry else {
        return Err("provider registry is not an array".into());
    };
    if mutate(fields)? {
        let registry_digest = contract_digest(
            b"PiglorOS.Conformance.ProviderRegistry.v1",
            &fields[..ProviderRegistryField::Digest.index()],
        )?;
        replace_value(
            fields,
            ProviderRegistryField::Digest.index(),
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

fn replace_package_field(
    fields: &mut [Value],
    field: ProviderPackageField,
    value: Value,
    name: &str,
    recompute_digest: bool,
) -> TestResult<bool> {
    replace_mutated_value(fields, field.index(), value, name, recompute_digest)
}

fn replace_package_key_field(
    fields: &mut [Value],
    field: ProviderKeyCborField,
    value: Value,
) -> TestResult<bool> {
    let key = array_field(
        fields,
        ProviderPackageField::ProviderKey.index(),
        "package provider key",
    )?;
    replace_mutated_value(key, field.index(), value, "package provider identity", true)
}

fn replace_package_schema_field(
    fields: &mut [Value],
    field: ProviderFamilySchemaField,
    value: Value,
    name: &str,
) -> TestResult<bool> {
    replace_mutated_value(
        provider_package_schema(fields)?,
        field.index(),
        value,
        name,
        true,
    )
}

fn replace_package_schema_descriptor_field(
    fields: &mut [Value],
    field: ArtifactDescriptorField,
    value: Value,
) -> TestResult<bool> {
    let descriptor = array_field(
        provider_package_schema(fields)?,
        ProviderFamilySchemaField::Descriptor.index(),
        "package schema descriptor",
    )?;
    replace_mutated_value(
        descriptor,
        field.index(),
        value,
        "package schema descriptor field",
        true,
    )
}

fn replace_package_artifact_field(
    fields: &mut [Value],
    descriptor: ProviderPackageField,
    field: ArtifactDescriptorField,
    value: Value,
    name: &str,
) -> TestResult<bool> {
    let descriptor = array_field(fields, descriptor.index(), name)?;
    replace_mutated_value(descriptor, field.index(), value, name, true)
}

fn remove_package_family_schema(fields: &mut [Value]) -> TestResult<bool> {
    array_field(
        fields,
        ProviderPackageField::FamilySchemas.index(),
        "package schemas",
    )?
    .pop();
    Ok(true)
}

fn invalidate_package_schema_shape(fields: &mut [Value]) -> TestResult<bool> {
    let schemas = array_field(
        fields,
        ProviderPackageField::FamilySchemas.index(),
        "package schemas",
    )?;
    replace_mutated_value(
        schemas,
        CURRENT_PROVIDER_SCHEMA_INDEX,
        Value::Array(Vec::new()),
        "package schema",
        true,
    )
}

fn collide_package_support_path(fields: &mut [Value]) -> TestResult<bool> {
    let schema_path = array_field(
        provider_package_schema(fields)?,
        ProviderFamilySchemaField::Descriptor.index(),
        "package schema descriptor",
    )?
    .first()
    .ok_or("package schema descriptor has no path")?
    .clone();
    replace_package_artifact_field(
        fields,
        ProviderPackageField::LicenceDescriptor,
        ArtifactDescriptorField::Path,
        schema_path,
        "colliding package licence path",
    )
}

enum ProviderPackageMutationAction {
    PackageField {
        field: ProviderPackageField,
        value: Value,
        name: &'static str,
        recompute_digest: bool,
    },
    ProviderKey {
        field: ProviderKeyCborField,
        value: Value,
    },
    SchemaField {
        field: ProviderFamilySchemaField,
        value: Value,
        name: &'static str,
    },
    SchemaDescriptor {
        field: ArtifactDescriptorField,
        value: Value,
    },
    LicenceDigest,
    RemoveFamilySchema,
    InvalidateSchemaShape,
    CollideSupportPath,
}

const fn package_field_action(
    field: ProviderPackageField,
    value: Value,
    name: &'static str,
    recompute_digest: bool,
) -> ProviderPackageMutationAction {
    ProviderPackageMutationAction::PackageField {
        field,
        value,
        name,
        recompute_digest,
    }
}

fn invalid_package_magic_action() -> ProviderPackageMutationAction {
    package_field_action(
        ProviderPackageField::Magic,
        Value::Text("FPP0".to_owned()),
        "package magic",
        false,
    )
}

fn invalid_package_version_action() -> ProviderPackageMutationAction {
    package_field_action(
        ProviderPackageField::Version,
        Value::Integer(2_u64.into()),
        "package version",
        false,
    )
}

fn provider_package_mutation_action(
    mutation: ProviderPackageMutation,
) -> ProviderPackageMutationAction {
    use ProviderPackageMutationAction::{
        CollideSupportPath, InvalidateSchemaShape, LicenceDigest, ProviderKey, RemoveFamilySchema,
        SchemaDescriptor, SchemaField,
    };

    match mutation {
        ProviderPackageMutation::InvalidMagic => invalid_package_magic_action(),
        ProviderPackageMutation::InvalidVersion => invalid_package_version_action(),
        ProviderPackageMutation::EmptyProviderKey => package_field_action(
            ProviderPackageField::ProviderKey,
            Value::Array(Vec::new()),
            "package provider key",
            false,
        ),
        ProviderPackageMutation::EmptySchemas => package_field_action(
            ProviderPackageField::FamilySchemas,
            Value::Array(Vec::new()),
            "package schemas",
            true,
        ),
        ProviderPackageMutation::InvalidSchemaFamily => SchemaField {
            field: ProviderFamilySchemaField::Family,
            value: Value::Integer(1_u64.into()),
            name: "package schema family",
        },
        ProviderPackageMutation::InvalidSchemaDescriptor => SchemaField {
            field: ProviderFamilySchemaField::Descriptor,
            value: Value::Array(Vec::new()),
            name: "package schema descriptor",
        },
        ProviderPackageMutation::InvalidLicenceDigest => LicenceDigest,
        ProviderPackageMutation::InvalidDigest => package_field_action(
            ProviderPackageField::Digest,
            Value::Bytes(vec![0; 32]),
            "package digest",
            false,
        ),
        ProviderPackageMutation::InvalidProviderIdentifier => ProviderKey {
            field: ProviderKeyCborField::Identifier,
            value: Value::Text("INVALID".to_owned()),
        },
        ProviderPackageMutation::NoncanonicalProviderVersion => ProviderKey {
            field: ProviderKeyCborField::Version,
            value: Value::Text("01.0.0".to_owned()),
        },
        ProviderPackageMutation::InvalidProviderAbiMajor => ProviderKey {
            field: ProviderKeyCborField::AbiMajor,
            value: Value::Integer(65_536_u64.into()),
        },
        ProviderPackageMutation::InvalidProviderAbiMinor => ProviderKey {
            field: ProviderKeyCborField::AbiMinor,
            value: Value::Integer(65_536_u64.into()),
        },
        ProviderPackageMutation::InvalidClaimLayer => package_field_action(
            ProviderPackageField::ClaimLayer,
            Value::Integer(7_u64.into()),
            "package claim layer",
            true,
        ),
        ProviderPackageMutation::InvalidSubjectAdapter => package_field_action(
            ProviderPackageField::SubjectAdapter,
            Value::Integer(3_u64.into()),
            "package subject adapter",
            true,
        ),
        ProviderPackageMutation::MissingFamilySchema => RemoveFamilySchema,
        ProviderPackageMutation::InvalidSchemaShape => InvalidateSchemaShape,
        ProviderPackageMutation::AbsoluteSchemaPath => SchemaDescriptor {
            field: ArtifactDescriptorField::Path,
            value: Value::Text("/invalid.json".to_owned()),
        },
        ProviderPackageMutation::InvalidSchemaMediaType => SchemaDescriptor {
            field: ArtifactDescriptorField::MediaType,
            value: Value::Text("INVALID".to_owned()),
        },
        ProviderPackageMutation::InvalidSchemaLength => SchemaDescriptor {
            field: ArtifactDescriptorField::Length,
            value: Value::Integer(0_u64.into()),
        },
        ProviderPackageMutation::InvalidSchemaDigest => SchemaDescriptor {
            field: ArtifactDescriptorField::Digest,
            value: Value::Bytes(vec![0; 32]),
        },
        ProviderPackageMutation::MissingNotices => package_field_action(
            ProviderPackageField::NoticesDescriptor,
            Value::Null,
            "package notice descriptor",
            true,
        ),
        ProviderPackageMutation::CollidingSupportPath => CollideSupportPath,
    }
}

fn mutate_provider_package_fields(
    fields: &mut [Value],
    mutation: ProviderPackageMutation,
) -> TestResult<bool> {
    match provider_package_mutation_action(mutation) {
        ProviderPackageMutationAction::PackageField {
            field,
            value,
            name,
            recompute_digest,
        } => replace_package_field(fields, field, value, name, recompute_digest),
        ProviderPackageMutationAction::ProviderKey { field, value } => {
            replace_package_key_field(fields, field, value)
        }
        ProviderPackageMutationAction::SchemaField { field, value, name } => {
            replace_package_schema_field(fields, field, value, name)
        }
        ProviderPackageMutationAction::SchemaDescriptor { field, value } => {
            replace_package_schema_descriptor_field(fields, field, value)
        }
        ProviderPackageMutationAction::LicenceDigest => replace_package_artifact_field(
            fields,
            ProviderPackageField::LicenceDescriptor,
            ArtifactDescriptorField::Digest,
            Value::Bytes(vec![0; 32]),
            "package licence digest",
        ),
        ProviderPackageMutationAction::RemoveFamilySchema => remove_package_family_schema(fields),
        ProviderPackageMutationAction::InvalidateSchemaShape => {
            invalidate_package_schema_shape(fields)
        }
        ProviderPackageMutationAction::CollideSupportPath => collide_package_support_path(fields),
    }
}

fn mutate_provider_package_archive(mutation: ProviderPackageMutation) -> TestResult<Vec<u8>> {
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
            .get(MemberField::Bytes.index())
        {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err("provider registry is not bytes".into()),
        };
    let mut registry: Value = ciborium::from_reader(registry_bytes.as_slice())?;
    let Value::Array(registry_fields) = &mut registry else {
        return Err("provider registry is not an array".into());
    };
    let package_path = match provider_package_descriptor(provider_registry_entry(registry_fields)?)?
        .get(ArtifactDescriptorField::Path.index())
    {
        Some(Value::Text(path)) => path.clone(),
        _ => return Err("provider package path is not text".into()),
    };
    let package_bytes = match archive_member_fields(archive_fields, &package_path)?
        .get(MemberField::Bytes.index())
    {
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
            &package_fields[..ProviderPackageField::Digest.index()],
        )?;
        replace_value(
            package_fields,
            ProviderPackageField::Digest.index(),
            Value::Bytes(package_digest.to_vec()),
            "package digest",
        )?;
    }
    let package_bytes = encode_value(&package)?;
    replace_archive_member_bytes(archive_fields, &package_path, &package_bytes)?;
    let package_descriptor =
        provider_package_descriptor(provider_registry_entry(registry_fields)?)?;
    replace_value(
        package_descriptor,
        ArtifactDescriptorField::Length.index(),
        Value::Integer(u64::try_from(package_bytes.len())?.into()),
        "package length",
    )?;
    replace_value(
        package_descriptor,
        ArtifactDescriptorField::Digest.index(),
        Value::Bytes(blake3::hash(&package_bytes).as_bytes().to_vec()),
        "package digest",
    )?;
    let registry_digest = contract_digest(
        b"PiglorOS.Conformance.ProviderRegistry.v1",
        &registry_fields[..ProviderRegistryField::Digest.index()],
    )?;
    replace_value(
        registry_fields,
        ProviderRegistryField::Digest.index(),
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
    support::temporary_root(label)
}

fn source_inventory_address() -> String {
    support::source_inventory_address()
}

fn release_files(root: &Path) -> TestResult<Vec<PathBuf>> {
    support::release_files(root)
}

fn assert_complete_execution_mode_closure(archive: &[u8]) -> TestResult {
    let bundle = ConformanceBundleV1::from_canonical_cbor(archive)?;
    let profile_member = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("materialized archive omits its CPF1 profile")?;
    let profile = ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)?;
    assert_eq!(profile.fixtures.len(), 28);
    for execution_profile in &profile.execution_profile_digests {
        for mode in [ExecutionModeV1::Local, ExecutionModeV1::AirGapped] {
            assert_eq!(
                profile
                    .fixtures
                    .iter()
                    .filter(|fixture| {
                        fixture.execution_profile_digest == *execution_profile
                            && fixture.modes.as_slice() == [mode]
                    })
                    .count(),
                7
            );
        }
    }
    Ok(())
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
        assert_complete_execution_mode_closure(bytes)?;
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
    assert!(Command::new(&verifier).args(&archives).status()?.success());
    assert!(!Command::new(verifier).arg(&archives[0]).status()?.success());
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
    let undeclared_key = Command::new(&materializer)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0808080808080808080808080808080808080808080808080808080808080808",
        )
        .arg(&output)
        .output()?;
    assert!(!undeclared_key.status.success());
    assert!(String::from_utf8_lossy(&undeclared_key.stderr)
        .contains("conformance signing key is not declared by the Draft authority"));
    fs::create_dir_all(&output)?;
    assert!(!Command::new(&materializer)
        .env("PIGLOROS_CONFORMANCE_SIGNING_KEY", key)
        .arg(&output)
        .status()?
        .success());
    assert!(fs::read_dir(&root)?.all(|entry| {
        entry.is_ok_and(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".pigloros-conformance-staging-")
        })
    }));

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

#[cfg(target_os = "linux")]
#[test]
fn public_materializer_rejects_live_staging_replacement_and_contamination() -> TestResult {
    let _guard = materializer_process_guard();
    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let key = "0707070707070707070707070707070707070707070707070707070707070707";

    for mutation in [
        StagingMutation::ReplaceIdentity,
        StagingMutation::RelaxPermissions,
        StagingMutation::RelaxRetainedPermissions,
    ] {
        let stderr = mutate_live_staging(materializer.as_os_str(), key, mutation)?;
        assert!(stderr.contains("UntrustedOutputDirectory"));
    }

    let stderr = mutate_live_staging(materializer.as_os_str(), key, StagingMutation::CorruptFiles)?;
    assert!(stderr.contains("ArchiveDigestMismatch"));

    let stderr = mutate_live_staging(
        materializer.as_os_str(),
        key,
        StagingMutation::InjectSymlink,
    )?;
    assert!(stderr.contains("SymlinkDetected"));

    let stderr = mutate_live_staging(materializer.as_os_str(), key, StagingMutation::InjectFifo)?;
    assert!(stderr.contains("UntrustedOutputDirectory"));

    let stderr = mutate_live_staging(
        materializer.as_os_str(),
        key,
        StagingMutation::BlockFutureDirectory,
    )?;
    assert!(stderr.contains("SymlinkDetected"));

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

    let unsigned = current_bundle_inputs(BundleModeV1::Local)?;
    let self_signed = ConformanceBundleV1::materialize(
        &unsigned.profile,
        BundleModeV1::Local,
        unsigned.members,
        unsigned.expected,
    )?;
    assert_eq!(
        self_signed.sign(&SigningKey::from_bytes(&[8; 32])),
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
fn archive_validation_rejects_provider_and_execution_closure_drift() -> TestResult {
    let mut undeclared_package = current_bundle_inputs(BundleModeV1::Local)?;
    undeclared_package
        .members
        .push(BundleMemberV1::fixture_provider_package(
            "authority/providers/undeclared.cbor",
            Vec::new(),
        ));
    assert_eq!(
        ConformanceBundleV1::materialize(
            &undeclared_package.profile,
            BundleModeV1::Local,
            undeclared_package.members,
            undeclared_package.expected,
        ),
        Err(BundleContractErrorV1::UndeclaredMember),
    );

    let undeclared_execution = mutate_profile_archive(|profile| {
        let replacement = Value::Bytes(vec![42; 32]);
        replace_value(
            array_field(profile, 7, "profile executions")?,
            0,
            replacement.clone(),
            "profile execution digest",
        )?;
        for fixture in array_field(profile, 9, "fixtures")? {
            let Value::Array(fields) = fixture else {
                return Err("fixture is not an array".into());
            };
            replace_value(fields, 6, replacement.clone(), "fixture execution digest")?;
        }
        Ok(())
    })?;
    assert_archive_rejected_by_both(&undeclared_execution, "undeclared execution profile");

    let undeclared_provider = mutate_profile_archive(|profile| {
        let replacement = Value::Array(vec![
            Value::Text("pigloros.fixture.undeclared".to_owned()),
            Value::Text("1.0.0".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Integer(0_u64.into()),
        ]);
        replace_value(
            array_field(
                array_field(profile, 8, "provider binding")?,
                1,
                "required providers",
            )?,
            0,
            replacement.clone(),
            "required provider",
        )?;
        for fixture in array_field(profile, 9, "fixtures")? {
            let Value::Array(fields) = fixture else {
                return Err("fixture is not an array".into());
            };
            replace_value(fields, 4, replacement.clone(), "fixture provider")?;
        }
        Ok(())
    })?;
    assert_archive_rejected_by_both(&undeclared_provider, "undeclared provider");
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
        execution_profile_digest: inputs.profile.execution_profile_digests[0],
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
        91..=101 => mutate_profile_order_and_shape_contracts(profile, mutation),
        102..=104 => mutate_profile_authority_shape(profile, mutation),
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
        _ => Err(format!("unsupported order or shape mutation {mutation}").into()),
    }
}

fn mutate_profile_authority_shape(profile: &mut [Value], mutation: usize) -> TestResult {
    match mutation {
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
        103 => replace_value(
            profile,
            5,
            Value::Bytes(vec![99; 32]),
            "bound normative specification digest",
        ),
        104 => replace_value(profile, 9, Value::Array(Vec::new()), "fixture inventory"),
        _ => Err(format!("unsupported authority shape mutation {mutation}").into()),
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
    for mutation in 0..105 {
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

#[test]
fn independent_verifier_exercises_active_provider_transitions() -> TestResult {
    let valid = mutate_profile_archive(|_| Ok(()))?;
    verify_archive_independently(&valid)?;
    ConformanceBundleV1::from_canonical_cbor(&valid)?;

    for endpoint in 0..2 {
        let invalid = mutate_profile_archive(|profile| {
            let transition = array_field(
                fixture_with_family(array_field(profile, 9, "fixtures")?, 5)?,
                22,
                "provider transition",
            )?;
            replace_value(
                transition,
                endpoint,
                Value::Map(Vec::new()),
                "provider transition endpoint",
            )
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
            fixture_with_family(array_field(profile, 9, "fixtures")?, 5)?,
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
    for (label, profile_bytes) in [
        ("malformed profile bytes", vec![0xff]),
        (
            "wrong profile field count",
            encode_value(&Value::Array(vec![Value::Null; 17]))?,
        ),
    ] {
        let archive = mutate_archive(|archive| {
            replace_archive_member_bytes(archive, "profile/CPF1.cbor", &profile_bytes)
        })?;
        assert_archive_rejected_by_both(&archive, label);
    }

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
            fixture_with_family(array_field(profile, 9, "fixtures")?, 5)?,
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
fn independent_verifier_rejects_archive_authority_structure_mutations() -> TestResult {
    let reordered = mutate_archive(|archive| {
        array_field(archive, 1, "archive members")?.swap(0, 1);
        array_field(
            array_field(archive, 0, "manifest")?,
            4,
            "member descriptors",
        )?
        .swap(0, 1);
        Ok(())
    })?;
    assert_archive_rejected_by_both(&reordered, "paired noncanonical member order");

    let missing_registry = mutate_archive(|archive| {
        array_field(archive, 1, "archive members")?.retain(|member| {
            !matches!(member, Value::Array(fields) if fields.first() == Some(&Value::Text(FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1.to_owned())))
        });
        array_field(
            array_field(archive, 0, "manifest")?,
            4,
            "member descriptors",
        )?
        .retain(|descriptor| {
            !matches!(descriptor, Value::Array(fields) if fields.first() == Some(&Value::Text(FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1.to_owned())))
        });
        Ok(())
    })?;
    assert_archive_rejected_by_both(&missing_registry, "missing provider registry member");

    let wrong_registry_shape = mutate_archive(|archive| {
        let registry_bytes = encode_value(&Value::Array(vec![Value::Null; 3]))?;
        replace_archive_member_bytes(
            archive,
            FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
            &registry_bytes,
        )?;
        refresh_profile_registry_binding(archive, &registry_bytes)
    })?;
    assert_archive_rejected_by_both(&wrong_registry_shape, "wrong provider registry shape");

    let undeclared_package = mutate_archive(|archive| {
        let path = "zz/undeclared-provider.fpp1";
        let bytes = encode_value(&Value::Array(Vec::new()))?;
        let digest = blake3::hash(&bytes).as_bytes().to_vec();
        array_field(archive, 1, "archive members")?.push(Value::Array(vec![
            Value::Text(path.to_owned()),
            Value::Bytes(bytes.clone()),
            Value::Integer(13_u64.into()),
        ]));
        array_field(
            array_field(archive, 0, "manifest")?,
            4,
            "member descriptors",
        )?
        .push(Value::Array(vec![
            Value::Text(path.to_owned()),
            Value::Integer(u64::try_from(bytes.len())?.into()),
            Value::Bytes(digest),
            Value::Integer(13_u64.into()),
        ]));
        Ok(())
    })?;
    assert_archive_rejected_by_both(&undeclared_package, "undeclared provider package");

    let mut matrix: serde_json::Value = serde_json::from_slice(MATRIX_BYTES)?;
    matrix["case_count"] = serde_json::Value::from(191);
    let matrix_bytes = serde_json::to_vec_pretty(&matrix)?;
    let invalid_matrix = mutate_archive(|archive| {
        replace_archive_member_bytes(archive, "authority/execution-matrix.json", &matrix_bytes)?;
        refresh_profile_matrix_binding(archive, &matrix_bytes)
    })?;
    assert_archive_rejected_by_both(&invalid_matrix, "noncanonical execution matrix");

    let mut inventory: serde_json::Value = serde_json::from_slice(AUTHORITY_INVENTORY_BYTES)?;
    inventory["entries"][0]["materialization_status"] =
        serde_json::Value::String("materialized".to_owned());
    let inventory_bytes = serde_json::to_vec_pretty(&inventory)?;
    let invalid_inventory = mutate_archive(|archive| {
        replace_archive_member_bytes(
            archive,
            "authority/expected-authority-inventory.json",
            &inventory_bytes,
        )
    })?;
    assert_archive_rejected_by_both(&invalid_inventory, "noncanonical authority inventory");
    Ok(())
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
        let denied_schema = fixture_with_family(fixtures, 1)?
            .get(8)
            .ok_or("denied schema is absent")?
            .clone();
        replace_value(
            fixture_with_family(fixtures, 0)?,
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
    for mutation in PROVIDER_REGISTRY_MUTATIONS {
        let archive = mutate_provider_registry_archive(mutation)?;
        assert_archive_rejected_by_both(&archive, mutation.label());
    }
    Ok(())
}

#[test]
fn independent_verifier_rejects_each_current_provider_package_mutation() -> TestResult {
    for mutation in PROVIDER_PACKAGE_MUTATIONS {
        let archive = mutate_provider_package_archive(mutation)?;
        assert_archive_rejected_by_both(&archive, mutation.label());
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
fn independent_verifier_rejects_invalid_raw_protocol_codes() -> TestResult {
    for (field, code, name) in [
        (3, 7_u64, "fixture family"),
        (5, 3_u64, "subject adapter"),
        (12, 6_u64, "verification outcome"),
        (14, 5_u64, "replay claim"),
        (15, 4_u64, "redaction state"),
    ] {
        let archive = mutate_profile_archive(|profile| {
            let fixture = array_field(array_field(profile, 9, "fixtures")?, 0, "fixture")?;
            replace_value(
                fixture,
                field,
                Value::Integer(code.into()),
                "raw fixture protocol code",
            )
        })?;
        assert!(
            verify_archive_independently(&archive).is_err(),
            "accepted invalid raw {name} code"
        );
    }

    let invalid_member_role = mutate_archive(|archive| {
        replace_value(
            archive_member_fields(archive, "profile/CPF1.cbor")?,
            2,
            Value::Integer(14_u64.into()),
            "raw member role",
        )?;
        replace_value(
            archive_descriptor_fields(archive, "profile/CPF1.cbor")?,
            3,
            Value::Integer(14_u64.into()),
            "raw descriptor role",
        )
    })?;
    assert!(verify_archive_independently(&invalid_member_role).is_err());
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
    let evidence =
        BundleMemberV1::evidence_status("evidence/positive/status.json", b"pending".to_vec());
    let registry = BundleMemberV1::fixture_provider_registry(b"registry".to_vec());
    let package =
        BundleMemberV1::fixture_provider_package("providers/example.fpp1", b"package".to_vec());

    assert_eq!(input.role, BundleMemberRoleV1::FixtureInput);
    assert_eq!(expected.role, BundleMemberRoleV1::ExpectedResult);
    assert_eq!(evidence.role, BundleMemberRoleV1::EvidenceStatus);
    assert_eq!(registry.role, BundleMemberRoleV1::FixtureProviderRegistry);
    assert_eq!(package.role, BundleMemberRoleV1::FixtureProviderPackage);
    assert_eq!(input.digest, *blake3::hash(b"input").as_bytes());
    assert_eq!(expected.digest, *blake3::hash(b"result").as_bytes());
    assert_eq!(evidence.digest, *blake3::hash(b"pending").as_bytes());
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
        BundleMemberRoleV1::ExecutionProfile,
        BundleMemberRoleV1::TrustPolicySnapshot,
        BundleMemberRoleV1::ReleaseAdmission,
        BundleMemberRoleV1::EvidenceStatus,
        BundleMemberRoleV1::FixtureContractPolicy,
        BundleMemberRoleV1::AuthorityDeclaration,
    ];
    for role in roles {
        let member = BundleMemberV1::supporting(format!("support/{role:?}"), vec![1], role);
        assert_eq!(member.role, role);
    }
}
