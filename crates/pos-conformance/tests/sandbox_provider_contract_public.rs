use ed25519_dalek::SigningKey;
use pos_conformance::{
    AdapterInputV1, AdmissionAuthorityV1, AdmissionGrantV1, ExecutionModeV1, LaunchPolicyV1,
    NetworkCapabilityV1, NetworkExchangePlanV1, PartitionDescriptorV1, PartitionRoleV1,
    Pkcs7ProofV1, ProviderCapabilityV1, ReceiptAuthorityV1, RequestAuthorityV1,
    SandboxArchitectureV1, SandboxContractErrorV1, SandboxExecuteRequestV1, SandboxLimitV1,
    SandboxCancelRequestV1, SandboxCancelResponseV1, SandboxCancelResultV1,
    SandboxDescribeRequestV1, SandboxDescribeResponseV1, SandboxLocalErrorCodeV1,
    SandboxLocalErrorV1, SandboxOutputV1, SandboxProviderErrorCodeV1, SandboxProviderErrorV1,
    SandboxProviderManifestV1, SandboxProviderOperationV1, SandboxProviderReceiptV1,
    SandboxProviderResultV1, SandboxReconcileRequestV1, SandboxReconcileResponseV1,
    SandboxTerminalOutcomeV1, SignedImageManifestV1,
};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const X86_ROOT: [u8; 16] = [
    0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84,
    0xb7, 0x09,
];
const X86_VERITY: [u8; 16] = [
    0x2c, 0x73, 0x57, 0xed, 0xeb, 0xd2, 0x46, 0xd9, 0xae, 0xc1, 0x23, 0xd4, 0x37, 0xec,
    0x2b, 0xf5,
];
const X86_VERITY_SIGNATURE: [u8; 16] = [
    0x41, 0x09, 0x2b, 0x05, 0x9f, 0xc8, 0x45, 0x23, 0x99, 0x4f, 0x2d, 0xef, 0x04, 0x08,
    0xb1, 0x76,
];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn digest(seed: u8) -> [u8; 32] {
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

fn partition(
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

fn network_plan(occurrence: u64) -> NetworkExchangePlanV1 {
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
    .expect("valid network plan")
}

fn execute_request() -> SandboxExecuteRequestV1 {
    let input = b"canonical EAI1 stream".to_vec();
    SandboxExecuteRequestV1 {
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
        adapter_input: AdapterInputV1 {
            digest: *blake3::hash(&input).as_bytes(),
            bytes: input,
        },
        network_plans: vec![network_plan(0), network_plan(1)],
        request_digest: [0; 32],
    }
}

fn admission_authority() -> AdmissionAuthorityV1 {
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

fn receipt_authority() -> ReceiptAuthorityV1 {
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

#[test]
fn authority_contracts_round_trip_and_verify_signatures() -> TestResult {
    let key = signing_key();
    let manifest = manifest().sign(&key)?;
    assert_eq!(
        SandboxProviderManifestV1::from_canonical_cbor(&manifest.to_canonical_cbor()?)?,
        manifest
    );
    manifest.verify_signature(&key.verifying_key())?;

    let policy = launch_policy().seal()?;
    assert_eq!(
        LaunchPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor()?)?,
        policy
    );

    let image = image_manifest().sign(&key)?;
    assert_eq!(
        SignedImageManifestV1::from_canonical_cbor(&image.to_canonical_cbor()?)?,
        image
    );
    image.verify_signature(&key.verifying_key())?;
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

    let mut invalid_image = image_manifest();
    invalid_image.partitions[1].partition_type_uuid = X86_ROOT;
    assert_eq!(
        invalid_image.sign(&key),
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn execute_and_admission_contracts_round_trip_and_reject_gaps() -> TestResult {
    let request = execute_request().seal()?;
    assert_eq!(
        SandboxExecuteRequestV1::from_canonical_cbor(&request.to_canonical_cbor()?)?,
        request
    );
    let mut gap = execute_request();
    gap.network_plans[1] = network_plan(2);
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
    assert_eq!(
        AdmissionGrantV1::from_canonical_cbor(&grant.to_canonical_cbor()?)?,
        grant
    );
    grant.verify_signature(&key.verifying_key())?;
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
        output: Some(SandboxOutputV1 {
            digest: *blake3::hash(&output).as_bytes(),
            bytes: output,
        }),
        agr1_digest: Some(digest(3)),
        spr1_digest: Some(digest(4)),
        operational_events: vec![0, 4, 10],
        runtime_attestation_key_id: "runtime-key".to_owned(),
        result_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    assert_eq!(
        SandboxProviderResultV1::from_canonical_cbor(&result.to_canonical_cbor()?)?,
        result
    );
    result.verify_signature(&key.verifying_key())?;

    let mut invalid_union = result.clone();
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
    assert_eq!(
        SandboxProviderErrorV1::from_canonical_cbor(&error.to_canonical_cbor()?)?,
        error
    );

    let receipt = SandboxProviderReceiptV1 {
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
        aud1_digest: digest(18),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        receipt_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    assert_eq!(
        SandboxProviderReceiptV1::from_canonical_cbor(&receipt.to_canonical_cbor()?)?,
        receipt
    );
    receipt.verify_signature(&key.verifying_key())?;

    let mut release_without_ready = receipt;
    release_without_ready.ready1_digest = None;
    assert_eq!(
        release_without_ready.validate(),
        Err(SandboxContractErrorV1::InconsistentFields)
    );
    Ok(())
}

#[test]
fn all_provider_operations_round_trip_and_bind_responses() -> TestResult {
    let key = signing_key();
    let authority = RequestAuthorityV1 {
        request_id: [1; 16],
        apt1_digest: digest(2),
        policy_epoch: 3,
        nonce: [4; 16],
    };
    let describe = SandboxDescribeRequestV1 {
        authority: authority.clone(),
        request_digest: [0; 32],
    }
    .seal()?;
    assert_eq!(
        SandboxDescribeRequestV1::from_canonical_cbor(&describe.to_canonical_cbor()?)?,
        describe
    );
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
    described.validate_for_request(&describe)?;
    described.verify_signature(&key.verifying_key())?;

    let cancel = SandboxCancelRequestV1 {
        authority: authority.clone(),
        attempt_id: [8; 16],
        agr1_digest: digest(9),
        request_digest: [0; 32],
    }
    .seal()?;
    let cancelled = SandboxCancelResponseV1 {
        request_id: authority.request_id,
        attempt_id: cancel.attempt_id,
        result: SandboxCancelResultV1::CancelledAndCleaned,
        spy1_digest: digest(10),
        runtime_attestation_key_id: "runtime-key".to_owned(),
        response_digest: [0; 32],
        signature: [0; 64],
    }
    .sign(&key)?;
    cancelled.validate_for_request(&cancel)?;
    assert_eq!(
        SandboxCancelResponseV1::from_canonical_cbor(&cancelled.to_canonical_cbor()?)?,
        cancelled
    );

    let reconcile = SandboxReconcileRequestV1 {
        authority,
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
    reconciled.validate_for_request(&reconcile)?;
    assert_eq!(
        SandboxReconcileResponseV1::from_canonical_cbor(&reconciled.to_canonical_cbor()?)?,
        reconciled
    );

    let local_error = SandboxLocalErrorV1 {
        operation: Some(SandboxProviderOperationV1::Execute),
        request_id: Some([1; 16]),
        code: SandboxLocalErrorCodeV1::ControlChannelUnavailable,
        safe_detail: Some("selector socket unavailable".to_owned()),
    };
    assert_eq!(
        SandboxLocalErrorV1::from_canonical_cbor(&local_error.to_canonical_cbor()?)?,
        local_error
    );
    Ok(())
}
