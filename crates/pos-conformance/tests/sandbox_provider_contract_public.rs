use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use pos_conformance::{
    AdmissionAuthorityV1, AdmissionGrantV1, ExecutionModeV1, LaunchPolicyV1, NetworkCapabilityV1,
    NetworkExchangePlanV1, PartitionDescriptorV1, PartitionRoleV1, PayloadDescriptorV1,
    PayloadDirectionV1, PayloadStreamValidatorV1, Pkcs7ProofV1, ProviderCapabilityV1,
    ReceiptAuthorityV1, RequestAuthorityV1, SandboxArchitectureV1, SandboxCancelRequestV1,
    SandboxCancelResponseV1, SandboxCancelResultV1, SandboxContractErrorV1,
    SandboxDescribeRequestV1, SandboxDescribeResponseV1, SandboxExecuteRequestV1, SandboxLimitV1,
    SandboxLocalErrorCodeV1, SandboxLocalErrorV1, SandboxPayloadChunkV1,
    SandboxProviderErrorCodeV1, SandboxProviderErrorV1, SandboxProviderManifestV1,
    SandboxProviderOperationV1, SandboxProviderReceiptV1, SandboxProviderResultV1,
    SandboxReconcileRequestV1, SandboxReconcileResponseV1, SandboxTerminalOutcomeV1,
    SignedImageManifestV1, MAX_SANDBOX_PAYLOAD_BYTES_V1, MAX_SANDBOX_PAYLOAD_CHUNKS_V1,
    SANDBOX_PAYLOAD_CHUNK_BYTES_V1,
};
use sha2::{Digest, Sha256};

use pos_reference::sandbox_provider_protocol as independent;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type ResultMutation = fn(&mut SandboxProviderResultV1);

fn verify_and_materialize_vector(name: &str, bytes: &[u8]) -> TestResult {
    let filename = format!("{name}.cbor");
    let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/sandbox-provider-v1")
        .join(&filename);
    if std::fs::read(&committed)? != bytes {
        return Err(format!("committed vector {} has drifted", committed.display()).into());
    }
    if let Some(root) = std::env::var_os("SANDBOX_PROVIDER_VECTOR_OUTPUT") {
        std::fs::create_dir_all(&root)?;
        std::fs::write(std::path::Path::new(&root).join(filename), bytes)?;
    }
    Ok(())
}

const X86_ROOT: [u8; 16] = [
    0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84, 0xb7, 0x09,
];
const X86_VERITY: [u8; 16] = [
    0x2c, 0x73, 0x57, 0xed, 0xeb, 0xd2, 0x46, 0xd9, 0xae, 0xc1, 0x23, 0xd4, 0x37, 0xec, 0x2b, 0xf5,
];
const X86_VERITY_SIGNATURE: [u8; 16] = [
    0x41, 0x09, 0x2b, 0x05, 0x9f, 0xc8, 0x45, 0x23, 0x99, 0x4f, 0x2d, 0xef, 0x04, 0x08, 0xb1, 0x76,
];
const AARCH64_ROOT: [u8; 16] = [
    0xb9, 0x21, 0xb0, 0x45, 0x1d, 0xf0, 0x41, 0xc3, 0xaf, 0x44, 0x4c, 0x6f, 0x28, 0x0d, 0x3f, 0xae,
];
const AARCH64_VERITY: [u8; 16] = [
    0xdf, 0x33, 0x00, 0xce, 0xd6, 0x9f, 0x4c, 0x92, 0x97, 0x8c, 0x9b, 0xfb, 0x0f, 0x38, 0xd8, 0x20,
];
const AARCH64_VERITY_SIGNATURE: [u8; 16] = [
    0x6d, 0xb6, 0x9d, 0xe6, 0x29, 0xf4, 0x47, 0x58, 0xa7, 0xa5, 0x96, 0x21, 0x90, 0xf0, 0x0c, 0xe3,
];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

const fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn manifest() -> SandboxProviderManifestV1 {
    SandboxProviderManifestV1 {
        provider_id: "org.pigloros.provider.reference".to_owned(),
        source_digest: digest(1),
        build_digest: digest(2),
        binary_digest: digest(3),
        public_contract_digest: digest(4),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        capabilities: vec![
            ProviderCapabilityV1 {
                capability_id: "managed-attempt-exec".to_owned(),
                capability_version: 1,
                minimum_strength: 1,
            },
            ProviderCapabilityV1 {
                capability_id: "process-isolation-controls".to_owned(),
                capability_version: 1,
                minimum_strength: 1,
            },
        ],
        architectures: vec![SandboxArchitectureV1::X86_64],
        dependency_digest: digest(5),
        sbom_digest: digest(6),
        licence_digest: digest(7),
        provenance_digest: digest(8),
        trust_epoch: 9,
        pcf1_digest: digest(10),
        required_hcp1_feature_set_digest: digest(11),
        provider_release_key_id: "release-key".to_owned(),
        manifest_digest: [0; 32],
        signature: [0; 64],
    }
}

fn launch_policy() -> LaunchPolicyV1 {
    LaunchPolicyV1 {
        policy_id: "local-strict".to_owned(),
        execution_mode: ExecutionModeV1::Local,
        sim1_digest: digest(12),
        effective_limits: vec![
            SandboxLimitV1 {
                limit_id: 0,
                value: 1,
            },
            SandboxLimitV1 {
                limit_id: 1,
                value: 4096,
            },
            SandboxLimitV1 {
                limit_id: 16,
                value: 30_000,
            },
        ],
        network_capabilities: vec![NetworkCapabilityV1 {
            capability_id: "tcp-loopback".to_owned(),
            address: vec![127, 0, 0, 1],
            destination_port: 8443,
            request_maximum: 4096,
            response_maximum: 8192,
        }],
        policy_digest: [0; 32],
    }
}

fn image_manifest() -> SignedImageManifestV1 {
    let der_bytes = vec![0x30, 0x01, 0x00];
    SignedImageManifestV1 {
        image_id: "reference-adapter-image".to_owned(),
        architecture: SandboxArchitectureV1::X86_64,
        root_image_length: 16_384,
        root_image_blake3_digest: digest(13),
        partitions: [
            partition(PartitionRoleV1::RootData, X86_ROOT, 1, 0),
            partition(PartitionRoleV1::RootVerity, X86_VERITY, 2, 4096),
            partition(
                PartitionRoleV1::RootVeritySignature,
                X86_VERITY_SIGNATURE,
                3,
                8192,
            ),
        ],
        root_hash_sha256: digest(14),
        root_hash_signature: Pkcs7ProofV1 {
            der_length: der_bytes.len() as u64,
            der_sha256: Sha256::digest(&der_bytes).into(),
            der_bytes,
        },
        signing_certificate_sha256: digest(15),
        kernel_keyring_serial: 7,
        executable_path: "/usr/bin/reference-adapter".to_owned(),
        executable_blake3_digest: digest(16),
        arguments: vec!["--stdio".to_owned()],
        image_trust_epoch: 9,
        image_project_key_id: "image-key".to_owned(),
        manifest_digest: [0; 32],
        signature: [0; 64],
    }
}

fn aarch64_image_manifest() -> SignedImageManifestV1 {
    let mut image = image_manifest();
    image.architecture = SandboxArchitectureV1::Aarch64;
    image.partitions[0].partition_type_uuid = AARCH64_ROOT;
    image.partitions[1].partition_type_uuid = AARCH64_VERITY;
    image.partitions[2].partition_type_uuid = AARCH64_VERITY_SIGNATURE;
    image
}

const fn partition(
    role: PartitionRoleV1,
    partition_type_uuid: [u8; 16],
    instance_seed: u8,
    start_bytes: u64,
) -> PartitionDescriptorV1 {
    PartitionDescriptorV1 {
        role,
        partition_type_uuid,
        partition_instance_uuid: [instance_seed; 16],
        start_bytes,
        length_bytes: 4096,
        content_blake3_digest: digest(instance_seed),
    }
}

fn network_plan(occurrence: u64) -> Result<NetworkExchangePlanV1, SandboxContractErrorV1> {
    NetworkExchangePlanV1 {
        exchange_id: [1; 16],
        occurrence,
        capability_id: "tcp-loopback".to_owned(),
        request_length: 3,
        request_digest: digest(17),
        response_maximum: 8,
        expected_response_digest: digest(18),
        retention_policy_digest: digest(19),
        plan_digest: [0; 32],
    }
    .seal()
}

#[test]
fn network_plan_digest_uses_normative_domain() -> TestResult {
    let plan = network_plan(0)?;
    let unsigned = Value::Array(vec![
        Value::Text("NXP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(plan.exchange_id.to_vec()),
        Value::Integer(plan.occurrence.into()),
        Value::Text(plan.capability_id.clone()),
        Value::Integer(plan.request_length.into()),
        Value::Bytes(plan.request_digest.to_vec()),
        Value::Integer(plan.response_maximum.into()),
        Value::Bytes(plan.expected_response_digest.to_vec()),
        Value::Bytes(plan.retention_policy_digest.to_vec()),
    ]);
    let mut encoded = Vec::new();
    ciborium::into_writer(&unsigned, &mut encoded)?;
    let mut preimage = b"PiglorOS.NetworkExchangePlan.v1\0".to_vec();
    preimage.extend_from_slice(&encoded);
    assert_eq!(plan.plan_digest, *blake3::hash(&preimage).as_bytes());
    Ok(())
}

fn execute_request() -> Result<SandboxExecuteRequestV1, SandboxContractErrorV1> {
    let input = b"canonical EAI1 stream".to_vec();
    Ok(SandboxExecuteRequestV1 {
        authority: RequestAuthorityV1 {
            request_id: [1; 16],
            apt1_digest: digest(20),
            policy_epoch: 4,
            nonce: [2; 16],
        },
        attempt_id: [3; 16],
        evr1_digest: digest(21),
        cpf1_digest: digest(22),
        cfb1_digest: digest(23),
        fixture_contract_digest: digest(24),
        fixture_digest: digest(25),
        execution_profile_digest: digest(26),
        lps1_digest: digest(27),
        sim1_digest: digest(28),
        apt1_digest: digest(20),
        trs1_digest: digest(29),
        rvs1_digest: digest(30),
        spm1_digest: digest(31),
        pcf1_digest: digest(32),
        pcr1_digest: digest(33),
        hcp1_digest: digest(34),
        capability_ids: vec!["managed-attempt-exec".to_owned()],
        adapter_input: PayloadDescriptorV1::from_bytes(PayloadDirectionV1::Input, &input)?,
        network_plans: vec![network_plan(0)?, network_plan(1)?],
        request_digest: [0; 32],
    })
}

const fn admission_authority() -> AdmissionAuthorityV1 {
    AdmissionAuthorityV1 {
        evr1_digest: digest(1),
        fixture_contract_digest: digest(2),
        fixture_digest: digest(3),
        execution_profile_digest: digest(4),
        lps1_digest: digest(5),
        sim1_digest: digest(6),
        apt1_digest: digest(7),
        trs1_digest: digest(8),
        rvs1_digest: digest(9),
        spm1_digest: digest(10),
        pcf1_digest: digest(11),
        pcr1_digest: digest(12),
        hcp1_digest: digest(13),
    }
}

const fn receipt_authority() -> ReceiptAuthorityV1 {
    ReceiptAuthorityV1 {
        agr1_digest: digest(1),
        spm1_digest: digest(2),
        provider_binary_digest: digest(3),
        lps1_digest: digest(4),
        sim1_digest: digest(5),
        apt1_digest: digest(6),
        trs1_digest: digest(7),
        rvs1_digest: digest(8),
    }
}

fn signed_receipt(key: &SigningKey) -> Result<SandboxProviderReceiptV1, SandboxContractErrorV1> {
    SandboxProviderReceiptV1 {
        attempt_id: [2; 16],
        authority: receipt_authority(),
        trust_epoch: 3,
        revocation_epoch: 4,
        policy_epoch: 5,
        hcp1_digest: digest(9),
        elm1_digest: digest(10),
        network_transcript_digests: vec![digest(11)],
        ready1_digest: Some(digest(12)),
        release1_digest: Some(digest(13)),
        requested_configuration_evidence: digest(14),
        kernel_observation_evidence: digest(15),
        negative_probe_evidence: digest(16),
        termination_evidence: digest(17),
        sau1_digest: digest(18),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        receipt_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(key)
}

#[derive(Clone, Copy)]
enum ReceiptStage {
    BeforeReady,
    Ready,
    Released,
}

fn signed_receipt_at_stage(
    key: &SigningKey,
    stage: ReceiptStage,
) -> Result<SandboxProviderReceiptV1, SandboxContractErrorV1> {
    let mut receipt = signed_receipt(key)?;
    match stage {
        ReceiptStage::BeforeReady => {
            receipt.ready1_digest = None;
            receipt.release1_digest = None;
        }
        ReceiptStage::Ready => receipt.release1_digest = None,
        ReceiptStage::Released => {}
    }
    receipt.sign(key)
}

fn signed_result_for_receipt(
    key: &SigningKey,
    receipt: &SandboxProviderReceiptV1,
    outcome: SandboxTerminalOutcomeV1,
    operational_events: Vec<u64>,
) -> Result<SandboxProviderResultV1, SandboxContractErrorV1> {
    let mut result = result_for_outcome(outcome)?;
    result.attempt_id = receipt.attempt_id;
    result.agr1_digest = Some(receipt.authority.agr1_digest);
    result.spr1_digest = Some(receipt.receipt_digest);
    result.operational_events = operational_events;
    result
        .runtime_attestation_key_id
        .clone_from(&receipt.runtime_attestation_key_id);
    result.sign(key)
}

fn assert_pair_valid(
    result: &SandboxProviderResultV1,
    receipt: &SandboxProviderReceiptV1,
) -> TestResult {
    result.validate_receipt_lifecycle(receipt)?;
    let decoded_result =
        independent::SandboxProviderResult::from_canonical_cbor(&result.to_canonical_cbor()?)?;
    let decoded_receipt =
        independent::SandboxProviderReceipt::from_canonical_cbor(&receipt.to_canonical_cbor()?)?;
    decoded_result.validate_receipt_lifecycle(&decoded_receipt)?;
    Ok(())
}

fn assert_pair_rejected(
    result: &SandboxProviderResultV1,
    receipt: &SandboxProviderReceiptV1,
) -> TestResult {
    assert_eq!(
        result.validate_receipt_lifecycle(receipt),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    let decoded_result =
        independent::SandboxProviderResult::from_canonical_cbor(&result.to_canonical_cbor()?)?;
    let decoded_receipt =
        independent::SandboxProviderReceipt::from_canonical_cbor(&receipt.to_canonical_cbor()?)?;
    assert_eq!(
        decoded_result.validate_receipt_lifecycle(&decoded_receipt),
        Err(independent::SandboxProviderProtocolError::InconsistentFields)
    );
    Ok(())
}

const fn operation_authority() -> RequestAuthorityV1 {
    RequestAuthorityV1 {
        request_id: [1; 16],
        apt1_digest: digest(2),
        policy_epoch: 3,
        nonce: [4; 16],
    }
}

#[test]
fn authority_contracts_round_trip_and_verify_signatures() -> TestResult {
    let key = signing_key();
    let manifest = manifest().sign(&key)?;
    let manifest_bytes = manifest.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderManifestV1::from_canonical_cbor(&manifest_bytes)?,
        manifest
    );
    manifest.verify_signature(&key.verifying_key())?;
    independent::SandboxProviderManifest::from_canonical_cbor(&manifest_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("spm1", &manifest_bytes)?;

    let policy = launch_policy().seal()?;
    let policy_bytes = policy.to_canonical_cbor()?;
    assert_eq!(LaunchPolicyV1::from_canonical_cbor(&policy_bytes)?, policy);
    independent::LaunchPolicy::from_canonical_cbor(&policy_bytes)?;
    verify_and_materialize_vector("lps1", &policy_bytes)?;

    let image = image_manifest().sign(&key)?;
    let image_bytes = image.to_canonical_cbor()?;
    assert_eq!(
        SignedImageManifestV1::from_canonical_cbor(&image_bytes)?,
        image
    );
    image.verify_signature(&key.verifying_key())?;
    independent::SignedImageManifest::from_canonical_cbor(&image_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("sim1", &image_bytes)?;
    Ok(())
}

#[test]
fn authority_contracts_cover_every_architecture_and_execution_mode() -> TestResult {
    let key = signing_key();
    let mut dual_architecture = manifest();
    dual_architecture
        .architectures
        .push(SandboxArchitectureV1::Aarch64);
    let dual_architecture = dual_architecture.sign(&key)?;
    let manifest_bytes = dual_architecture.to_canonical_cbor()?;
    dual_architecture.verify_signature(&key.verifying_key())?;
    independent::SandboxProviderManifest::from_canonical_cbor(&manifest_bytes)?
        .verify_signature(&key.verifying_key())?;

    let aarch64 = aarch64_image_manifest().sign(&key)?;
    let image_bytes = aarch64.to_canonical_cbor()?;
    assert_eq!(
        SignedImageManifestV1::from_canonical_cbor(&image_bytes)?,
        aarch64
    );
    independent::SignedImageManifest::from_canonical_cbor(&image_bytes)?
        .verify_signature(&key.verifying_key())?;

    for mode in [
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ] {
        let mut policy = launch_policy();
        policy.execution_mode = mode;
        if mode != ExecutionModeV1::Local {
            policy.network_capabilities.clear();
        }
        let policy = policy.seal()?;
        let policy_bytes = policy.to_canonical_cbor()?;
        assert_eq!(LaunchPolicyV1::from_canonical_cbor(&policy_bytes)?, policy);
        independent::LaunchPolicy::from_canonical_cbor(&policy_bytes)?;
    }
    Ok(())
}

#[test]
fn network_capability_identifier_grammar_and_ipv6_round_trip() -> TestResult {
    let mut policy = launch_policy();
    policy.network_capabilities = ["0", "a-b", "a.b", "a/b", "a_b"]
        .into_iter()
        .enumerate()
        .map(|(index, capability_id)| {
            Ok(NetworkCapabilityV1 {
                capability_id: capability_id.to_owned(),
                address: vec![u8::try_from(index)?; 16],
                destination_port: 8443,
                request_maximum: 4096,
                response_maximum: 8192,
            })
        })
        .collect::<Result<Vec<_>, std::num::TryFromIntError>>()?;
    let policy = policy.seal()?;
    let bytes = policy.to_canonical_cbor()?;
    assert_eq!(LaunchPolicyV1::from_canonical_cbor(&bytes)?, policy);
    independent::LaunchPolicy::from_canonical_cbor(&bytes)?;
    Ok(())
}

#[test]
fn authority_contracts_reject_order_digest_and_partition_changes() -> TestResult {
    let key = signing_key();
    let mut unordered = manifest();
    unordered.capabilities.reverse();
    assert_eq!(
        unordered.sign(&key),
        Err(SandboxContractErrorV1::NonCanonicalOrder)
    );

    let mut invalid_policy = launch_policy();
    invalid_policy.effective_limits[0].value = 0;
    assert_eq!(
        invalid_policy.seal(),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );

    let mut invalid_network_address = launch_policy();
    invalid_network_address.network_capabilities[0].address = vec![127; 5];
    assert_eq!(
        invalid_network_address.seal(),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );

    let mut invalid_image = image_manifest();
    invalid_image.partitions[1].partition_type_uuid = X86_ROOT;
    assert_eq!(
        invalid_image.sign(&key),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );

    let mut unordered_network = launch_policy();
    unordered_network
        .network_capabilities
        .push(unordered_network.network_capabilities[0].clone());
    assert_eq!(
        unordered_network.seal(),
        Err(SandboxContractErrorV1::NonCanonicalOrder)
    );

    let manifest = manifest().sign(&key)?;
    let bytes = manifest.to_canonical_cbor()?;
    let decoded = independent::SandboxProviderManifest::from_canonical_cbor(&bytes)?;
    let mut invalid_capability = decoded.clone();
    invalid_capability.capabilities[0].capability_id.clear();
    assert_eq!(
        invalid_capability.verify_signature(&key.verifying_key()),
        Err(independent::SandboxProviderProtocolError::FieldOutOfBounds)
    );
    let mut unordered_architectures = decoded;
    unordered_architectures
        .architectures
        .push(independent::SandboxArchitecture::X86_64);
    assert_eq!(
        unordered_architectures.verify_signature(&key.verifying_key()),
        Err(independent::SandboxProviderProtocolError::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn execute_and_admission_contracts_round_trip_and_reject_gaps() -> TestResult {
    let request = execute_request()?.seal()?;
    let request_bytes = request.to_canonical_cbor()?;
    assert_eq!(
        SandboxExecuteRequestV1::from_canonical_cbor(&request_bytes)?,
        request
    );
    independent::SandboxExecuteRequest::from_canonical_cbor(&request_bytes)?;
    verify_and_materialize_vector("spx1", &request_bytes)?;
    let mut gap = execute_request()?;
    gap.network_plans[1] = network_plan(2)?;
    assert_eq!(gap.seal(), Err(SandboxContractErrorV1::InconsistentFields));

    let key = signing_key();
    let grant = AdmissionGrantV1 {
        request_id: [1; 16],
        attempt_id: [2; 16],
        authority: admission_authority(),
        trust_epoch: 3,
        revocation_epoch: 4,
        policy_epoch: 5,
        elm1_digest: digest(14),
        input_digest: digest(15),
        exchange_plan_digests: vec![digest(16)],
        expected_launch_policy_digest: digest(17),
        expected_readback_set_digest: digest(18),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        grant_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let grant_bytes = grant.to_canonical_cbor()?;
    assert_eq!(AdmissionGrantV1::from_canonical_cbor(&grant_bytes)?, grant);
    grant.verify_signature(&key.verifying_key())?;
    independent::AdmissionGrant::from_canonical_cbor(&grant_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("agr1", &grant_bytes)?;
    Ok(())
}

#[test]
fn terminal_contracts_enforce_closed_unions_and_receipt_evidence() -> TestResult {
    let key = signing_key();
    let output = b"canonical EAO1 stream".to_vec();
    let result = SandboxProviderResultV1 {
        request_id: [1; 16],
        attempt_id: [2; 16],
        outcome: SandboxTerminalOutcomeV1::Completed,
        output: Some(PayloadDescriptorV1::from_bytes(
            PayloadDirectionV1::Output,
            &output,
        )?),
        agr1_digest: Some(digest(3)),
        spr1_digest: Some(digest(4)),
        operational_events: vec![0, 4, 10],
        runtime_attestation_key_id: "runtime-key".to_owned(),
        result_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let result_bytes = result.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderResultV1::from_canonical_cbor(&result_bytes)?,
        result
    );
    result.verify_signature(&key.verifying_key())?;
    independent::SandboxProviderResult::from_canonical_cbor(&result_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("spy1", &result_bytes)?;

    let mut invalid_union = result;
    invalid_union.output = None;
    assert_eq!(
        invalid_union.validate(),
        Err(SandboxContractErrorV1::InconsistentFields)
    );

    let error = SandboxProviderErrorV1 {
        operation: Some(1),
        request_id: Some([1; 16]),
        request_digest: Some(digest(2)),
        attempt_id: Some([3; 16]),
        code: SandboxProviderErrorCodeV1::AttemptInProgress,
        safe_detail: None,
        runtime_attestation_key_id: "runtime-key".to_owned(),
        error_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let error_bytes = error.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderErrorV1::from_canonical_cbor(&error_bytes)?,
        error
    );
    independent::SandboxProviderError::from_canonical_cbor(&error_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("spe1", &error_bytes)?;

    let receipt = signed_receipt(&key)?;
    let receipt_bytes = receipt.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderReceiptV1::from_canonical_cbor(&receipt_bytes)?,
        receipt
    );
    receipt.verify_signature(&key.verifying_key())?;
    independent::SandboxProviderReceipt::from_canonical_cbor(&receipt_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("spr1", &receipt_bytes)?;

    Ok(())
}

#[test]
fn spr1_preserves_each_valid_lifecycle_stage_and_rejects_false_evidence() -> TestResult {
    let key = signing_key();
    let receipt = signed_receipt(&key)?;

    let mut before_ready = receipt.clone();
    before_ready.ready1_digest = None;
    before_ready.release1_digest = None;
    let before_ready = before_ready.sign(&key)?;
    let before_ready_bytes = before_ready.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderReceiptV1::from_canonical_cbor(&before_ready_bytes)?,
        before_ready
    );
    assert_eq!(
        independent::SandboxProviderReceipt::from_canonical_cbor(&before_ready_bytes)?
            .ready1_digest,
        None
    );

    let mut after_ready = receipt.clone();
    after_ready.release1_digest = None;
    let after_ready = after_ready.sign(&key)?;
    let after_ready_bytes = after_ready.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderReceiptV1::from_canonical_cbor(&after_ready_bytes)?,
        after_ready
    );
    assert_eq!(
        independent::SandboxProviderReceipt::from_canonical_cbor(&after_ready_bytes)?
            .release1_digest,
        None
    );

    let mut release_without_ready = receipt.clone();
    release_without_ready.ready1_digest = None;
    assert_eq!(
        release_without_ready.validate(),
        Err(SandboxContractErrorV1::InconsistentFields)
    );

    let mut zero_ready_digest = receipt.clone();
    zero_ready_digest.ready1_digest = Some([0; 32]);
    assert_eq!(
        zero_ready_digest.validate(),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );

    let mut zero_release_digest = receipt;
    zero_release_digest.release1_digest = Some([0; 32]);
    assert_eq!(
        zero_release_digest.validate(),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );

    Ok(())
}

#[test]
fn result_receipt_pairs_accept_each_reachable_lifecycle_stage() -> TestResult {
    let key = signing_key();
    for (stage, outcome, events) in [
        (
            ReceiptStage::BeforeReady,
            SandboxTerminalOutcomeV1::Cancelled,
            vec![],
        ),
        (
            ReceiptStage::Ready,
            SandboxTerminalOutcomeV1::Cancelled,
            vec![11],
        ),
        (
            ReceiptStage::Ready,
            SandboxTerminalOutcomeV1::Cancelled,
            vec![11, 13],
        ),
        (
            ReceiptStage::Released,
            SandboxTerminalOutcomeV1::Cancelled,
            vec![11, 12],
        ),
        (
            ReceiptStage::Released,
            SandboxTerminalOutcomeV1::Completed,
            vec![0, 11, 12],
        ),
    ] {
        let receipt = signed_receipt_at_stage(&key, stage)?;
        let result = signed_result_for_receipt(&key, &receipt, outcome, events)?;
        assert_pair_valid(&result, &receipt)?;
    }
    Ok(())
}

#[test]
fn result_receipt_pairs_reject_identity_and_authority_mismatches() -> TestResult {
    let key = signing_key();
    let receipt = signed_receipt_at_stage(&key, ReceiptStage::Released)?;
    let result = signed_result_for_receipt(
        &key,
        &receipt,
        SandboxTerminalOutcomeV1::Completed,
        vec![11, 12],
    )?;
    let mutations: [ResultMutation; 4] = [
        |value| value.attempt_id = [9; 16],
        |value| value.agr1_digest = Some(digest(41)),
        |value| value.spr1_digest = Some(digest(42)),
        |value| value.runtime_attestation_key_id = "other-runtime-key".to_owned(),
    ];
    for mutate in mutations {
        let mut changed = result.clone();
        mutate(&mut changed);
        let changed = changed.sign(&key)?;
        assert_pair_rejected(&changed, &receipt)?;
    }
    Ok(())
}

#[test]
fn result_receipt_pair_validation_rejects_invalid_records_before_comparing_them() -> TestResult {
    let key = signing_key();
    let receipt = signed_receipt_at_stage(&key, ReceiptStage::Released)?;
    let result = signed_result_for_receipt(
        &key,
        &receipt,
        SandboxTerminalOutcomeV1::Completed,
        vec![11, 12],
    )?;

    let mut invalid_result = result.clone();
    invalid_result.result_digest[0] ^= 1;
    assert_eq!(
        invalid_result.validate_receipt_lifecycle(&receipt),
        Err(SandboxContractErrorV1::DigestMismatch)
    );

    let mut invalid_receipt = receipt.clone();
    invalid_receipt.receipt_digest[0] ^= 1;
    assert_eq!(
        result.validate_receipt_lifecycle(&invalid_receipt),
        Err(SandboxContractErrorV1::DigestMismatch)
    );

    let mut decoded_result =
        independent::SandboxProviderResult::from_canonical_cbor(&result.to_canonical_cbor()?)?;
    let decoded_receipt =
        independent::SandboxProviderReceipt::from_canonical_cbor(&receipt.to_canonical_cbor()?)?;
    decoded_result.result_digest[0] ^= 1;
    assert_eq!(
        decoded_result.validate_receipt_lifecycle(&decoded_receipt),
        Err(independent::SandboxProviderProtocolError::DigestMismatch)
    );

    let decoded_result =
        independent::SandboxProviderResult::from_canonical_cbor(&result.to_canonical_cbor()?)?;
    let mut decoded_receipt = decoded_receipt;
    decoded_receipt.receipt_digest[0] ^= 1;
    assert_eq!(
        decoded_result.validate_receipt_lifecycle(&decoded_receipt),
        Err(independent::SandboxProviderProtocolError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn result_receipt_pairs_reject_impossible_lifecycle_evidence() -> TestResult {
    let key = signing_key();
    let cases = [
        (ReceiptStage::BeforeReady, vec![11]),
        (ReceiptStage::BeforeReady, vec![12]),
        (ReceiptStage::BeforeReady, vec![13]),
        (ReceiptStage::Ready, vec![]),
        (ReceiptStage::Ready, vec![11, 11]),
        (ReceiptStage::Ready, vec![11, 12]),
        (ReceiptStage::Ready, vec![13, 11]),
        (ReceiptStage::Ready, vec![11, 13, 13]),
        (ReceiptStage::Released, vec![11]),
        (ReceiptStage::Released, vec![12]),
        (ReceiptStage::Released, vec![12, 11]),
        (ReceiptStage::Released, vec![11, 12, 12]),
        (ReceiptStage::Released, vec![11, 12, 13]),
    ];
    for (stage, events) in cases {
        let receipt = signed_receipt_at_stage(&key, stage)?;
        let result =
            signed_result_for_receipt(&key, &receipt, SandboxTerminalOutcomeV1::Cancelled, events)?;
        assert_pair_rejected(&result, &receipt)?;
    }
    Ok(())
}

#[test]
fn completed_result_requires_released_receipt_evidence() -> TestResult {
    let key = signing_key();
    for (stage, events) in [
        (ReceiptStage::BeforeReady, vec![]),
        (ReceiptStage::Ready, vec![11]),
        (ReceiptStage::Ready, vec![11, 13]),
    ] {
        let receipt = signed_receipt_at_stage(&key, stage)?;
        let result =
            signed_result_for_receipt(&key, &receipt, SandboxTerminalOutcomeV1::Completed, events)?;
        assert_pair_rejected(&result, &receipt)?;
    }
    Ok(())
}

#[test]
fn spy1_accepts_the_closed_sau1_event_domain_only() -> TestResult {
    let key = signing_key();
    let template = result_for_outcome(SandboxTerminalOutcomeV1::UnavailableAfterAdmission)?;
    for event in 0..=13 {
        let mut result = template.clone();
        result.operational_events = vec![event];
        let result = result.sign(&key)?;
        independent::SandboxProviderResult::from_canonical_cbor(&result.to_canonical_cbor()?)?;
    }

    let mut unknown_event = template;
    unknown_event.operational_events = vec![14];
    assert_eq!(
        unknown_event.sign(&key).err(),
        Some(SandboxContractErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn signed_provider_error_round_trips_safe_detail() -> TestResult {
    let key = signing_key();
    let error = SandboxProviderErrorV1 {
        operation: Some(1),
        request_id: Some([1; 16]),
        request_digest: Some(digest(2)),
        attempt_id: Some([3; 16]),
        code: SandboxProviderErrorCodeV1::AttemptInProgress,
        safe_detail: Some("attempt remains active".to_owned()),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        error_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let bytes = error.to_canonical_cbor()?;
    assert_eq!(SandboxProviderErrorV1::from_canonical_cbor(&bytes)?, error);
    independent::SandboxProviderError::from_canonical_cbor(&bytes)?
        .verify_signature(&key.verifying_key())?;
    Ok(())
}

fn result_for_outcome(
    outcome: SandboxTerminalOutcomeV1,
) -> Result<SandboxProviderResultV1, SandboxContractErrorV1> {
    let admitted = matches!(
        outcome,
        SandboxTerminalOutcomeV1::Completed
            | SandboxTerminalOutcomeV1::Cancelled
            | SandboxTerminalOutcomeV1::UnavailableAfterAdmission
    );
    let output = if outcome == SandboxTerminalOutcomeV1::Completed {
        Some(PayloadDescriptorV1::from_bytes(
            PayloadDirectionV1::Output,
            b"terminal output",
        )?)
    } else {
        None
    };
    Ok(SandboxProviderResultV1 {
        request_id: [1; 16],
        attempt_id: [2; 16],
        outcome,
        output,
        agr1_digest: admitted.then_some(digest(3)),
        spr1_digest: admitted.then_some(digest(4)),
        operational_events: vec![0],
        runtime_attestation_key_id: "runtime-key".to_owned(),
        result_digest: [0; 32],
        signature: [0; 64],
    })
}

#[test]
fn terminal_results_round_trip_every_closed_outcome() -> TestResult {
    let key = signing_key();
    for outcome in [
        SandboxTerminalOutcomeV1::Completed,
        SandboxTerminalOutcomeV1::Cancelled,
        SandboxTerminalOutcomeV1::UnavailableBeforeAdmission,
        SandboxTerminalOutcomeV1::Rejected,
        SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
    ] {
        let result = result_for_outcome(outcome)?.sign(&key)?;
        let bytes = result.to_canonical_cbor()?;
        assert_eq!(
            SandboxProviderResultV1::from_canonical_cbor(&bytes)?,
            result
        );
        result.verify_signature(&key.verifying_key())?;
        independent::SandboxProviderResult::from_canonical_cbor(&bytes)?
            .verify_signature(&key.verifying_key())?;
    }
    Ok(())
}

fn error_for_code(code: SandboxProviderErrorCodeV1) -> SandboxProviderErrorV1 {
    SandboxProviderErrorV1 {
        operation: Some(1),
        request_id: Some([1; 16]),
        request_digest: Some(digest(2)),
        attempt_id: Some([3; 16]),
        code,
        safe_detail: None,
        runtime_attestation_key_id: "runtime-key".to_owned(),
        error_digest: [0; 32],
        signature: [0; 64],
    }
}

#[test]
fn provider_errors_round_trip_every_closed_code_and_nullable_identity() -> TestResult {
    let key = signing_key();
    for code in [
        SandboxProviderErrorCodeV1::InvalidEncoding,
        SandboxProviderErrorCodeV1::UnsupportedVersion,
        SandboxProviderErrorCodeV1::FieldOutOfBounds,
        SandboxProviderErrorCodeV1::NonCanonicalOrder,
        SandboxProviderErrorCodeV1::DigestMismatch,
        SandboxProviderErrorCodeV1::SignatureInvalid,
        SandboxProviderErrorCodeV1::TrustRevoked,
        SandboxProviderErrorCodeV1::AuthorityMismatch,
        SandboxProviderErrorCodeV1::ProviderCapabilityMissing,
        SandboxProviderErrorCodeV1::ImageIdentityMismatch,
        SandboxProviderErrorCodeV1::SelfTestFailed,
        SandboxProviderErrorCodeV1::SandboxUnavailable,
        SandboxProviderErrorCodeV1::AdmissionBusy,
        SandboxProviderErrorCodeV1::AuditUnavailable,
        SandboxProviderErrorCodeV1::CleanupFailed,
        SandboxProviderErrorCodeV1::UnknownAttempt,
        SandboxProviderErrorCodeV1::RequestIdentityConflict,
        SandboxProviderErrorCodeV1::AttemptInProgress,
    ] {
        let error = error_for_code(code).sign(&key)?;
        let bytes = error.to_canonical_cbor()?;
        assert_eq!(SandboxProviderErrorV1::from_canonical_cbor(&bytes)?, error);
        error.verify_signature(&key.verifying_key())?;
        independent::SandboxProviderError::from_canonical_cbor(&bytes)?
            .verify_signature(&key.verifying_key())?;
    }

    let mut framing_error = error_for_code(SandboxProviderErrorCodeV1::InvalidEncoding);
    framing_error.operation = None;
    framing_error.request_id = None;
    framing_error.request_digest = None;
    framing_error.attempt_id = None;
    let framing_error = framing_error.sign(&key)?;
    let bytes = framing_error.to_canonical_cbor()?;
    assert_eq!(
        SandboxProviderErrorV1::from_canonical_cbor(&bytes)?,
        framing_error
    );
    independent::SandboxProviderError::from_canonical_cbor(&bytes)?
        .verify_signature(&key.verifying_key())?;

    let mut nul_detail = error_for_code(SandboxProviderErrorCodeV1::InvalidEncoding);
    nul_detail.safe_detail = Some("unsafe\0detail".to_owned());
    assert_eq!(
        nul_detail.sign(&key),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );
    let mut orphaned_digest = error_for_code(SandboxProviderErrorCodeV1::InvalidEncoding);
    orphaned_digest.request_id = None;
    assert_eq!(
        orphaned_digest.sign(&key),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    Ok(())
}

#[test]
fn control_document_limit_is_enforced_after_field_validation() -> TestResult {
    let mut request = execute_request()?;
    request.adapter_input.byte_length = 128 * 1024 * 1024 + 1;
    assert_eq!(
        request.seal(),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

fn payload_chunk(
    parent_digest: [u8; 32],
    direction: PayloadDirectionV1,
    index: u64,
    bytes: Vec<u8>,
) -> Result<SandboxPayloadChunkV1, SandboxContractErrorV1> {
    SandboxPayloadChunkV1 {
        parent_digest,
        request_id: [1; 16],
        attempt_id: [2; 16],
        direction,
        index,
        offset: index * SANDBOX_PAYLOAD_CHUNK_BYTES_V1 as u64,
        bytes,
        chunk_digest: [0; 32],
    }
    .seal()
}

#[test]
fn payload_chunks_round_trip_and_stream_through_independent_boundaries() -> TestResult {
    let parent = digest(90);
    let bytes = b"parent-bound payload".to_vec();
    let descriptor = PayloadDescriptorV1::from_bytes(PayloadDirectionV1::Input, &bytes)?;
    let chunk = payload_chunk(parent, PayloadDirectionV1::Input, 0, bytes)?;
    let encoded = chunk.to_canonical_cbor()?;
    assert_eq!(SandboxPayloadChunkV1::from_canonical_cbor(&encoded)?, chunk);
    let independently_decoded = independent::SandboxPayloadChunk::from_canonical_cbor(&encoded)?;

    let mut producer = PayloadStreamValidatorV1::new(
        parent,
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Input,
        descriptor.clone(),
    )?;
    producer.accept(&chunk)?;
    producer.finish()?;

    let mut consumer = independent::PayloadStreamValidator::new(
        parent,
        [1; 16],
        [2; 16],
        independent::PayloadDirection::Input,
        independent::PayloadDescriptor {
            byte_length: descriptor.byte_length,
            digest: descriptor.digest,
        },
    )?;
    consumer.accept(&independently_decoded)?;
    consumer.finish()?;
    verify_and_materialize_vector("sbc1", &encoded)?;
    Ok(())
}

#[test]
fn payload_stream_rejects_gap_interleave_missing_and_digest_mismatch() -> TestResult {
    let parent = digest(91);
    let full = vec![7; SANDBOX_PAYLOAD_CHUNK_BYTES_V1 + 1];
    let descriptor = PayloadDescriptorV1::from_bytes(PayloadDirectionV1::Output, &full)?;
    let first = payload_chunk(
        parent,
        PayloadDirectionV1::Output,
        0,
        full[..SANDBOX_PAYLOAD_CHUNK_BYTES_V1].to_vec(),
    )?;
    let second = payload_chunk(parent, PayloadDirectionV1::Output, 1, vec![7])?;

    let missing = PayloadStreamValidatorV1::new(
        parent,
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Output,
        descriptor.clone(),
    )?;
    assert_eq!(
        missing.finish(),
        Err(SandboxContractErrorV1::InconsistentFields)
    );

    let mut stream = PayloadStreamValidatorV1::new(
        parent,
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Output,
        descriptor.clone(),
    )?;
    assert_eq!(
        stream.accept(&second),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    stream.accept(&first)?;
    assert_eq!(
        stream.accept(&first),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    let foreign = payload_chunk(digest(92), PayloadDirectionV1::Output, 1, vec![7])?;
    assert_eq!(
        stream.accept(&foreign),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    stream.accept(&second)?;
    stream.finish()?;

    let mut corrupt = first.clone();
    corrupt.chunk_digest[0] ^= 1;
    let mut stream = PayloadStreamValidatorV1::new(
        parent,
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Output,
        descriptor.clone(),
    )?;
    assert_eq!(
        stream.accept(&corrupt),
        Err(SandboxContractErrorV1::DigestMismatch)
    );

    let mut bad_digest = descriptor;
    bad_digest.digest = digest(93);
    let mut stream = PayloadStreamValidatorV1::new(
        parent,
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Output,
        bad_digest,
    )?;
    stream.accept(&first)?;
    stream.accept(&second)?;
    assert_eq!(stream.finish(), Err(SandboxContractErrorV1::DigestMismatch));
    Ok(())
}

#[test]
fn independent_payload_stream_rejects_sequence_and_digest_failures() -> TestResult {
    let parent = digest(91);
    let full = vec![7; SANDBOX_PAYLOAD_CHUNK_BYTES_V1 + 1];
    let first = payload_chunk(
        parent,
        PayloadDirectionV1::Output,
        0,
        full[..SANDBOX_PAYLOAD_CHUNK_BYTES_V1].to_vec(),
    )?;
    let second = payload_chunk(parent, PayloadDirectionV1::Output, 1, vec![7])?;
    let foreign = payload_chunk(digest(92), PayloadDirectionV1::Output, 1, vec![7])?;
    let independent_descriptor = independent::PayloadDescriptor {
        byte_length: u64::try_from(full.len())?,
        digest: PayloadDescriptorV1::from_bytes(PayloadDirectionV1::Output, &full)?.digest,
    };
    let independent_first =
        independent::SandboxPayloadChunk::from_canonical_cbor(&first.to_canonical_cbor()?)?;
    let independent_second =
        independent::SandboxPayloadChunk::from_canonical_cbor(&second.to_canonical_cbor()?)?;
    let independent_foreign =
        independent::SandboxPayloadChunk::from_canonical_cbor(&foreign.to_canonical_cbor()?)?;

    let missing = independent::PayloadStreamValidator::new(
        parent,
        [1; 16],
        [2; 16],
        independent::PayloadDirection::Output,
        independent_descriptor.clone(),
    )?;
    assert_eq!(
        missing.finish(),
        Err(independent::SandboxProviderProtocolError::InconsistentFields)
    );

    let mut stream = independent::PayloadStreamValidator::new(
        parent,
        [1; 16],
        [2; 16],
        independent::PayloadDirection::Output,
        independent_descriptor.clone(),
    )?;
    assert_eq!(
        stream.accept(&independent_second),
        Err(independent::SandboxProviderProtocolError::InconsistentFields)
    );
    stream.accept(&independent_first)?;
    assert_eq!(
        stream.accept(&independent_first),
        Err(independent::SandboxProviderProtocolError::InconsistentFields)
    );
    assert_eq!(
        stream.accept(&independent_foreign),
        Err(independent::SandboxProviderProtocolError::InconsistentFields)
    );
    stream.accept(&independent_second)?;
    stream.finish()?;

    let mut corrupt = independent_first.clone();
    corrupt.chunk_digest[0] ^= 1;
    let mut stream = independent::PayloadStreamValidator::new(
        parent,
        [1; 16],
        [2; 16],
        independent::PayloadDirection::Output,
        independent_descriptor.clone(),
    )?;
    assert_eq!(
        stream.accept(&corrupt),
        Err(independent::SandboxProviderProtocolError::DigestMismatch)
    );

    let mut bad_digest = independent_descriptor;
    bad_digest.digest = digest(93);
    let mut stream = independent::PayloadStreamValidator::new(
        parent,
        [1; 16],
        [2; 16],
        independent::PayloadDirection::Output,
        bad_digest,
    )?;
    stream.accept(&independent_first)?;
    stream.accept(&independent_second)?;
    assert_eq!(
        stream.finish(),
        Err(independent::SandboxProviderProtocolError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn payload_stream_rejects_each_invalid_identity_and_descriptor() -> TestResult {
    let descriptor = PayloadDescriptorV1::from_bytes(PayloadDirectionV1::Input, b"payload")?;
    for (parent, request, attempt) in [
        ([0; 32], [1; 16], [2; 16]),
        (digest(96), [0; 16], [2; 16]),
        (digest(96), [1; 16], [0; 16]),
    ] {
        assert_eq!(
            PayloadStreamValidatorV1::new(
                parent,
                request,
                attempt,
                PayloadDirectionV1::Input,
                descriptor.clone(),
            )
            .err(),
            Some(SandboxContractErrorV1::FieldOutOfBounds)
        );
    }
    let oversized = PayloadDescriptorV1 {
        byte_length: MAX_SANDBOX_PAYLOAD_BYTES_V1 + 1,
        digest: digest(97),
    };
    assert_eq!(
        PayloadStreamValidatorV1::new(
            digest(96),
            [1; 16],
            [2; 16],
            PayloadDirectionV1::Input,
            oversized,
        )
        .err(),
        Some(SandboxContractErrorV1::FieldOutOfBounds)
    );

    let descriptor = independent::PayloadDescriptor {
        byte_length: 7,
        digest: descriptor.digest,
    };
    for (parent, request, attempt) in [
        ([0; 32], [1; 16], [2; 16]),
        (digest(96), [0; 16], [2; 16]),
        (digest(96), [1; 16], [0; 16]),
    ] {
        assert_eq!(
            independent::PayloadStreamValidator::new(
                parent,
                request,
                attempt,
                independent::PayloadDirection::Input,
                descriptor.clone(),
            )
            .err(),
            Some(independent::SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    let oversized = independent::PayloadDescriptor {
        byte_length: MAX_SANDBOX_PAYLOAD_BYTES_V1 + 1,
        digest: digest(97),
    };
    assert_eq!(
        independent::PayloadStreamValidator::new(
            digest(96),
            [1; 16],
            [2; 16],
            independent::PayloadDirection::Input,
            oversized,
        )
        .err(),
        Some(independent::SandboxProviderProtocolError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn payload_stream_accepts_empty_and_exact_128_mib_without_one_large_allocation() -> TestResult {
    let empty = PayloadDescriptorV1::from_bytes(PayloadDirectionV1::Input, &[])?;
    PayloadStreamValidatorV1::new(
        digest(94),
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Input,
        empty,
    )?
    .finish()?;

    let bytes = vec![9; SANDBOX_PAYLOAD_CHUNK_BYTES_V1];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SandboxInputBytes.v1\0");
    for _ in 0..MAX_SANDBOX_PAYLOAD_CHUNKS_V1 {
        hasher.update(&bytes);
    }
    let descriptor = PayloadDescriptorV1 {
        byte_length: MAX_SANDBOX_PAYLOAD_BYTES_V1,
        digest: *hasher.finalize().as_bytes(),
    };
    let mut stream = PayloadStreamValidatorV1::new(
        digest(95),
        [1; 16],
        [2; 16],
        PayloadDirectionV1::Input,
        descriptor,
    )?;
    for index in 0..MAX_SANDBOX_PAYLOAD_CHUNKS_V1 {
        stream.accept(&payload_chunk(
            digest(95),
            PayloadDirectionV1::Input,
            index,
            bytes.clone(),
        )?)?;
    }
    stream.finish()?;
    Ok(())
}

#[test]
fn describe_operation_round_trips_and_binds_response() -> TestResult {
    let key = signing_key();
    let authority = operation_authority();
    let describe = SandboxDescribeRequestV1 {
        authority: authority.clone(),
        request_digest: [0; 32],
    }
    .seal()?;
    let describe_bytes = describe.to_canonical_cbor()?;
    assert_eq!(
        SandboxDescribeRequestV1::from_canonical_cbor(&describe_bytes)?,
        describe
    );
    independent::SandboxDescribeRequest::from_canonical_cbor(&describe_bytes)?;
    verify_and_materialize_vector("sdq1", &describe_bytes)?;
    let described = SandboxDescribeResponseV1 {
        request_id: authority.request_id,
        spm1_digest: digest(5),
        provider_binary_digest: digest(6),
        hcp1_digest: digest(7),
        apt1_digest: authority.apt1_digest,
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let response_bytes = described.to_canonical_cbor()?;
    described.validate_for_request(&describe)?;
    described.verify_signature(&key.verifying_key())?;
    independent::SandboxDescribeResponse::from_canonical_cbor(&response_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("sdy1", &response_bytes)?;
    Ok(())
}

#[test]
fn cancel_operation_round_trips_and_binds_response() -> TestResult {
    let key = signing_key();
    let authority = operation_authority();
    let cancel = SandboxCancelRequestV1 {
        authority,
        attempt_id: [8; 16],
        agr1_digest: digest(9),
        request_digest: [0; 32],
    }
    .seal()?;
    let cancel_bytes = cancel.to_canonical_cbor()?;
    independent::SandboxCancelRequest::from_canonical_cbor(&cancel_bytes)?;
    verify_and_materialize_vector("scq1", &cancel_bytes)?;
    let cancelled = SandboxCancelResponseV1 {
        request_id: cancel.authority.request_id,
        attempt_id: cancel.attempt_id,
        result: SandboxCancelResultV1::CancelledAndCleaned,
        spy1_digest: digest(10),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let response_bytes = cancelled.to_canonical_cbor()?;
    cancelled.validate_for_request(&cancel)?;
    cancelled.verify_signature(&key.verifying_key())?;
    assert_eq!(
        SandboxCancelResponseV1::from_canonical_cbor(&response_bytes)?,
        cancelled
    );
    independent::SandboxCancelResponse::from_canonical_cbor(&response_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("scy1", &response_bytes)?;
    Ok(())
}

#[test]
fn reconcile_and_local_error_operations_round_trip() -> TestResult {
    let key = signing_key();
    let reconcile = SandboxReconcileRequestV1 {
        authority: operation_authority(),
        attempt_id: [8; 16],
        agr1_digest: digest(9),
        request_digest: [0; 32],
    }
    .seal()?;
    let reconcile_bytes = reconcile.to_canonical_cbor()?;
    independent::SandboxReconcileRequest::from_canonical_cbor(&reconcile_bytes)?;
    verify_and_materialize_vector("srq1", &reconcile_bytes)?;
    let reconciled = SandboxReconcileResponseV1 {
        request_id: reconcile.authority.request_id,
        attempt_id: reconcile.attempt_id,
        clean: true,
        reconciliation_evidence_digest: digest(11),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let response_bytes = reconciled.to_canonical_cbor()?;
    reconciled.validate_for_request(&reconcile)?;
    reconciled.verify_signature(&key.verifying_key())?;
    assert_eq!(
        SandboxReconcileResponseV1::from_canonical_cbor(&response_bytes)?,
        reconciled
    );
    independent::SandboxReconcileResponse::from_canonical_cbor(&response_bytes)?
        .verify_signature(&key.verifying_key())?;
    verify_and_materialize_vector("sry1", &response_bytes)?;

    let local_error = SandboxLocalErrorV1 {
        operation: Some(SandboxProviderOperationV1::Execute),
        request_id: Some([1; 16]),
        code: SandboxLocalErrorCodeV1::ControlChannelUnavailable,
        safe_detail: Some("selector socket unavailable".to_owned()),
    };
    let local_error_bytes = local_error.to_canonical_cbor()?;
    assert_eq!(
        SandboxLocalErrorV1::from_canonical_cbor(&local_error_bytes)?,
        local_error
    );
    independent::SandboxLocalError::from_canonical_cbor(&local_error_bytes)?;
    verify_and_materialize_vector("sle1", &local_error_bytes)?;
    Ok(())
}

#[test]
fn local_errors_round_trip_every_operation_and_failure_code() -> TestResult {
    let operations = [
        SandboxProviderOperationV1::Describe,
        SandboxProviderOperationV1::Execute,
        SandboxProviderOperationV1::Cancel,
        SandboxProviderOperationV1::Reconcile,
    ];
    let codes = [
        SandboxLocalErrorCodeV1::ProviderUnavailable,
        SandboxLocalErrorCodeV1::ProviderIdentityInvalid,
        SandboxLocalErrorCodeV1::PolicyUnavailable,
        SandboxLocalErrorCodeV1::ControlChannelUnavailable,
    ];
    for (operation, code) in operations.into_iter().zip(codes) {
        let error = SandboxLocalErrorV1 {
            operation: Some(operation),
            request_id: Some([1; 16]),
            code,
            safe_detail: None,
        };
        let bytes = error.to_canonical_cbor()?;
        assert_eq!(SandboxLocalErrorV1::from_canonical_cbor(&bytes)?, error);
        independent::SandboxLocalError::from_canonical_cbor(&bytes)?;
    }
    Ok(())
}

#[test]
fn signed_responses_reject_mismatched_request_bindings() -> TestResult {
    let key = signing_key();
    let describe = SandboxDescribeRequestV1 {
        authority: operation_authority(),
        request_digest: [0; 32],
    }
    .seal()?;
    let mismatched_describe = SandboxDescribeResponseV1 {
        request_id: [9; 16],
        spm1_digest: digest(5),
        provider_binary_digest: digest(6),
        hcp1_digest: digest(7),
        apt1_digest: describe.authority.apt1_digest,
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    assert_eq!(
        mismatched_describe.validate_for_request(&describe),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    let mut invalid_describe = describe.clone();
    invalid_describe.request_digest[0] ^= 1;
    assert_eq!(
        mismatched_describe.validate_for_request(&invalid_describe),
        Err(SandboxContractErrorV1::DigestMismatch)
    );
    let mut invalid_described = mismatched_describe;
    invalid_described.response_digest[0] ^= 1;
    assert_eq!(
        invalid_described.validate_for_request(&describe),
        Err(SandboxContractErrorV1::DigestMismatch)
    );

    let cancel = SandboxCancelRequestV1 {
        authority: operation_authority(),
        attempt_id: [8; 16],
        agr1_digest: digest(9),
        request_digest: [0; 32],
    }
    .seal()?;
    let mismatched_cancel = SandboxCancelResponseV1 {
        request_id: cancel.authority.request_id,
        attempt_id: [9; 16],
        result: SandboxCancelResultV1::AlreadyTerminal,
        spy1_digest: digest(10),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let bytes = mismatched_cancel.to_canonical_cbor()?;
    mismatched_cancel.verify_signature(&key.verifying_key())?;
    independent::SandboxCancelResponse::from_canonical_cbor(&bytes)?
        .verify_signature(&key.verifying_key())?;
    assert_eq!(
        mismatched_cancel.validate_for_request(&cancel),
        Err(SandboxContractErrorV1::InconsistentFields)
    );

    let mut invalid_cancel = cancel.clone();
    invalid_cancel.request_digest[0] ^= 1;
    assert_eq!(
        mismatched_cancel.validate_for_request(&invalid_cancel),
        Err(SandboxContractErrorV1::DigestMismatch)
    );
    let mut invalid_cancelled = mismatched_cancel;
    invalid_cancelled.response_digest[0] ^= 1;
    assert_eq!(
        invalid_cancelled.validate_for_request(&cancel),
        Err(SandboxContractErrorV1::DigestMismatch)
    );

    let reconcile = SandboxReconcileRequestV1 {
        authority: operation_authority(),
        attempt_id: [8; 16],
        agr1_digest: digest(9),
        request_digest: [0; 32],
    }
    .seal()?;
    let reconciled = SandboxReconcileResponseV1 {
        request_id: reconcile.authority.request_id,
        attempt_id: reconcile.attempt_id,
        clean: true,
        reconciliation_evidence_digest: digest(11),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    let mut invalid_reconcile = reconcile.clone();
    invalid_reconcile.request_digest[0] ^= 1;
    assert_eq!(
        reconciled.validate_for_request(&invalid_reconcile),
        Err(SandboxContractErrorV1::DigestMismatch)
    );
    let mut invalid_reconciled = reconciled;
    invalid_reconciled.response_digest[0] ^= 1;
    assert_eq!(
        invalid_reconciled.validate_for_request(&reconcile),
        Err(SandboxContractErrorV1::DigestMismatch)
    );
    Ok(())
}

#[test]
fn public_encoders_propagate_nested_validation_failures() -> TestResult {
    let mut execute = execute_request()?;
    execute.network_plans[0].plan_digest = [0; 32];
    assert_eq!(execute.seal(), Err(SandboxContractErrorV1::DigestMismatch));

    let local_error = SandboxLocalErrorV1 {
        operation: None,
        request_id: Some([0; 16]),
        code: SandboxLocalErrorCodeV1::ProviderUnavailable,
        safe_detail: None,
    };
    assert_eq!(
        local_error.to_canonical_cbor(),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
