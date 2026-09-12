//! Public selector-owned provider and image admission tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::evaluator::{AttemptArtifact, AttemptTransportCaps, CaseAttempt};
use pos_reference::evaluator_protocol::{
    EvaluationRequest, ImplementationIdentity, OutputCapability, RequiredProviderCapability,
    SandboxRequirement, SubjectAdapterKind,
};
use pos_reference::profile::DeterministicBudget;
use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AdmittedSandboxImage, AdmittedSandboxProvider, AuthenticatedAdmissionGrant,
    HostCapabilityProfile, LaunchPolicy, NetworkExchangePlan, ProviderConformanceReport,
    SandboxAdministratorPolicy, SandboxAdmissionError, SandboxArchitecture, SandboxAuditRecord,
    SandboxExecuteRequest, SandboxProviderAdmissionInputs, SandboxProviderReceipt,
    SandboxRevocationSnapshot, SandboxTrustSnapshot, SelectorGrantCommitment,
};
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ROOT_DATA_X86_64: [u8; 16] = [
    0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84, 0xb7, 0x09,
];
const ROOT_VERITY_X86_64: [u8; 16] = [
    0x2c, 0x73, 0x57, 0xed, 0xeb, 0xd2, 0x46, 0xd9, 0xae, 0xc1, 0x23, 0xd4, 0x37, 0xec, 0x2b, 0xf5,
];
const ROOT_SIGNATURE_X86_64: [u8; 16] = [
    0x41, 0x09, 0x2b, 0x05, 0x9f, 0xc8, 0x45, 0x23, 0x99, 0x4f, 0x2d, 0xef, 0x04, 0x08, 0xb1, 0x76,
];

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

fn digest_value(domain: &[u8], value: &Value) -> TestResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&encode(value)?);
    Ok(*hasher.finalize().as_bytes())
}

fn sign_record(magic: &str, unsigned: Value, key: &SigningKey) -> TestResult<Vec<u8>> {
    let digest = digest_value(format!("PiglorOS.{magic}.v1\0").as_bytes(), &unsigned)?;
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend_from_slice(&digest);
    encode(&Value::Array(vec![
        unsigned,
        bytes(digest),
        Value::Bytes(key.sign(&message).to_bytes().to_vec()),
    ]))
}

fn resign_unsigned_field(
    encoded: &[u8],
    magic: &str,
    field: usize,
    replacement: Value,
    key: &SigningKey,
) -> TestResult<Vec<u8>> {
    resign_unsigned_fields(encoded, magic, &[(field, replacement)], key)
}

fn resign_unsigned_fields(
    encoded: &[u8],
    magic: &str,
    replacements: &[(usize, Value)],
    key: &SigningKey,
) -> TestResult<Vec<u8>> {
    let Value::Array(wrapper) = ciborium::from_reader(encoded)? else {
        return Err("signed wrapper must be an array".into());
    };
    let Value::Array(mut unsigned) = wrapper
        .into_iter()
        .next()
        .ok_or("signed wrapper prefix missing")?
    else {
        return Err("signed wrapper prefix must be an array".into());
    };
    for (field, replacement) in replacements {
        *unsigned.get_mut(*field).ok_or("unsigned field missing")? = replacement.clone();
    }
    sign_record(magic, Value::Array(unsigned), key)
}

fn replace_signed_signature(encoded: &[u8], signature: [u8; 64]) -> TestResult<Vec<u8>> {
    let Value::Array(mut wrapper) = ciborium::from_reader(encoded)? else {
        return Err("signed wrapper must be an array".into());
    };
    *wrapper
        .get_mut(2)
        .ok_or("signed wrapper signature missing")? = Value::Bytes(signature.to_vec());
    encode(&Value::Array(wrapper))
}

fn corrupt_signed_digest(encoded: &[u8]) -> TestResult<Vec<u8>> {
    let Value::Array(mut wrapper) = ciborium::from_reader(encoded)? else {
        return Err("signed wrapper must be an array".into());
    };
    *wrapper.get_mut(1).ok_or("signed wrapper digest missing")? = Value::Bytes(vec![0; 32]);
    encode(&Value::Array(wrapper))
}

fn self_digested_record(magic: &str, unsigned: Value) -> TestResult<Vec<u8>> {
    let digest = digest_value(format!("PiglorOS.{magic}.v1\0").as_bytes(), &unsigned)?;
    encode(&Value::Array(vec![unsigned, bytes(digest)]))
}

fn redigest_unsigned_field(
    encoded: &[u8],
    magic: &str,
    field: usize,
    replacement: Value,
) -> TestResult<Vec<u8>> {
    let Value::Array(wrapper) = ciborium::from_reader(encoded)? else {
        return Err("self-digested wrapper must be an array".into());
    };
    let Value::Array(mut unsigned) = wrapper
        .into_iter()
        .next()
        .ok_or("self-digested wrapper prefix missing")?
    else {
        return Err("self-digested wrapper prefix must be an array".into());
    };
    *unsigned.get_mut(field).ok_or("unsigned field missing")? = replacement;
    self_digested_record(magic, Value::Array(unsigned))
}

fn wrapped_digest(encoded: &[u8]) -> TestResult<[u8; 32]> {
    let Value::Array(wrapper) = ciborium::from_reader(encoded)? else {
        return Err("signed wrapper must be an array".into());
    };
    let Value::Bytes(digest) = &wrapper[1] else {
        return Err("signed wrapper digest must be bytes".into());
    };
    Ok(digest.as_slice().try_into()?)
}

fn ordered(values: Vec<Value>) -> TestResult<Vec<Value>> {
    let mut encoded = values
        .into_iter()
        .map(|value| encode(&value).map(|bytes| (bytes, value)))
        .collect::<TestResult<Vec<_>>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(encoded.into_iter().map(|(_, value)| value).collect())
}

fn key_record(id: &str, role: u64, key: &SigningKey) -> Value {
    Value::Array(vec![
        Value::Text(id.to_owned()),
        integer(role),
        Value::Bytes(key.verifying_key().to_bytes().to_vec()),
        integer(2),
    ])
}

struct SigningAuthority {
    root: SigningKey,
    policy: SigningKey,
    release: SigningKey,
    runtime: SigningKey,
    reviewer: SigningKey,
    image: SigningKey,
}

impl SigningAuthority {
    fn fixed() -> Self {
        Self {
            root: SigningKey::from_bytes(&[1; 32]),
            policy: SigningKey::from_bytes(&[2; 32]),
            release: SigningKey::from_bytes(&[3; 32]),
            runtime: SigningKey::from_bytes(&[4; 32]),
            reviewer: SigningKey::from_bytes(&[5; 32]),
            image: SigningKey::from_bytes(&[6; 32]),
        }
    }

    fn trust(&self) -> TestResult<SandboxTrustSnapshot> {
        let keys = ordered(vec![
            key_record("policy", 1, &self.policy),
            key_record("release", 2, &self.release),
            key_record("runtime", 3, &self.runtime),
            key_record("reviewer", 4, &self.reviewer),
            key_record("image", 5, &self.image),
        ])?;
        let certificate = Value::Array(vec![bytes([9; 32]), integer(77), integer(2)]);
        let unsigned = Value::Array(vec![
            Value::Text("TRS1".to_owned()),
            integer(1),
            integer(2),
            Value::Array(keys),
            Value::Array(vec![certificate]),
            Value::Text("root".to_owned()),
        ]);
        let encoded = sign_record("TRS1", unsigned, &self.root)?;
        Ok(SandboxTrustSnapshot::authenticate(
            &encoded,
            "root",
            &self.root.verifying_key(),
        )?)
    }
}

fn revocation(
    trust: &SandboxTrustSnapshot,
    authority: &SigningAuthority,
    revoked_providers: Vec<Value>,
    revoked_images: Vec<Value>,
) -> TestResult<SandboxRevocationSnapshot> {
    let unsigned = Value::Array(vec![
        Value::Text("RVS1".to_owned()),
        integer(1),
        bytes(trust.snapshot_digest()),
        integer(3),
        Value::Array(vec![]),
        Value::Array(ordered(revoked_providers)?),
        Value::Array(ordered(revoked_images)?),
        Value::Text("policy".to_owned()),
    ]);
    Ok(SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", unsigned, &authority.policy)?,
        trust,
    )?)
}

fn capability_value() -> Value {
    Value::Array(vec![
        Value::Text("execute".to_owned()),
        integer(1),
        integer(1),
    ])
}

fn feature_set_digest(required: &[String]) -> TestResult<[u8; 32]> {
    digest_value(
        b"PiglorOS.RequiredHostFeatureSet.v1\0",
        &Value::Array(
            required
                .iter()
                .map(|feature| Value::Text(feature.clone()))
                .collect(),
        ),
    )
}

fn provider_manifest(
    authority: &SigningAuthority,
    binary_digest: [u8; 32],
    feature_digest: [u8; 32],
) -> TestResult<Vec<u8>> {
    sign_record(
        "SPM1",
        Value::Array(vec![
            Value::Text("SPM1".to_owned()),
            integer(1),
            Value::Text("provider".to_owned()),
            bytes([10; 32]),
            bytes([11; 32]),
            bytes(binary_digest),
            bytes([12; 32]),
            Value::Text("runtime".to_owned()),
            Value::Array(vec![capability_value()]),
            Value::Array(vec![integer(0)]),
            bytes([13; 32]),
            bytes([14; 32]),
            bytes([15; 32]),
            bytes([16; 32]),
            integer(2),
            bytes([17; 32]),
            bytes(feature_digest),
            Value::Text("release".to_owned()),
        ]),
        &authority.release,
    )
}

fn syscall_set(architecture: u64) -> TestResult<Vec<u8>> {
    self_digested_record(
        "SCS1",
        Value::Array(vec![
            Value::Text("SCS1".to_owned()),
            integer(1),
            integer(architecture),
            Value::Array(vec![Value::Text("read".to_owned())]),
            Value::Array(vec![Value::Text("read".to_owned())]),
        ]),
    )
}

fn host_profile(
    authority: &SigningAuthority,
    feature_id: &str,
    passed: u64,
    architecture: u64,
) -> TestResult<Vec<u8>> {
    sign_record(
        "HCP1",
        Value::Array(vec![
            Value::Text("HCP1".to_owned()),
            integer(1),
            integer(architecture),
            Value::Text("6.12.0".to_owned()),
            Value::Array(vec![Value::Array(vec![
                Value::Text(feature_id.to_owned()),
                integer(passed),
                bytes([18; 32]),
            ])]),
            bytes([19; 32]),
            bytes([20; 32]),
            bytes([21; 32]),
            Value::Text("runtime".to_owned()),
        ]),
        &authority.runtime,
    )
}

fn conformance_report(
    authority: &SigningAuthority,
    binary_digest: [u8; 32],
    feature_digest: [u8; 32],
    hcp1_digest: [u8; 32],
    architecture: u64,
) -> TestResult<Vec<u8>> {
    let capability_digest = digest_value(
        b"PiglorOS.ProviderCapabilitySet.v1\0",
        &Value::Array(vec![capability_value()]),
    )?;
    sign_record(
        "PCR1",
        Value::Array(vec![
            Value::Text("PCR1".to_owned()),
            integer(1),
            bytes([17; 32]),
            bytes(binary_digest),
            bytes([12; 32]),
            bytes(capability_digest),
            bytes(feature_digest),
            integer(architecture),
            bytes(hcp1_digest),
            integer(0),
            Value::Text("reviewer".to_owned()),
        ]),
        &authority.reviewer,
    )
}

fn partition(role: u64, partition_type: [u8; 16], instance: u8, start: u64) -> Value {
    Value::Array(vec![
        integer(role),
        Value::Bytes(partition_type.to_vec()),
        Value::Bytes(vec![instance; 16]),
        integer(start),
        integer(1),
        bytes([instance; 32]),
    ])
}

fn image_manifest(
    authority: &SigningAuthority,
    root_image: &[u8],
    executable: &[u8],
    architecture: u64,
) -> TestResult<Vec<u8>> {
    let der = b"pkcs7";
    sign_record(
        "SIM1",
        Value::Array(vec![
            Value::Text("SIM1".to_owned()),
            integer(1),
            Value::Text("image".to_owned()),
            integer(architecture),
            integer(u64::try_from(root_image.len())?),
            bytes(*blake3::hash(root_image).as_bytes()),
            Value::Array(vec![
                partition(0, ROOT_DATA_X86_64, 1, 0),
                partition(1, ROOT_VERITY_X86_64, 2, 1),
                partition(2, ROOT_SIGNATURE_X86_64, 3, 2),
            ]),
            bytes([22; 32]),
            integer(4096),
            integer(4096),
            integer(1),
            Value::Bytes(vec![]),
            Value::Array(vec![
                integer(u64::try_from(der.len())?),
                Value::Bytes(Sha256::digest(der).to_vec()),
                Value::Bytes(der.to_vec()),
            ]),
            bytes([9; 32]),
            integer(77),
            Value::Text("/adapter".to_owned()),
            bytes(*blake3::hash(executable).as_bytes()),
            Value::Array(vec![]),
            integer(2),
            Value::Text("image".to_owned()),
        ]),
        &authority.image,
    )
}

struct PolicySelectionDigests {
    provider_manifest: [u8; 32],
    provider_binary: [u8; 32],
    broker_hard_caps: [u8; 32],
    conformance_report: [u8; 32],
    syscall_set: [u8; 32],
    launch_policy: [u8; 32],
    image_manifest: [u8; 32],
}

fn administrator_policy(
    trust: &SandboxTrustSnapshot,
    revocation: &SandboxRevocationSnapshot,
    authority: &SigningAuthority,
    selection: &PolicySelectionDigests,
) -> TestResult<SandboxAdministratorPolicy> {
    let unsigned = Value::Array(vec![
        Value::Text("APT1".to_owned()),
        integer(1),
        integer(4),
        bytes(selection.provider_manifest),
        bytes(selection.provider_binary),
        Value::Array(vec![bytes(selection.launch_policy)]),
        Value::Array(vec![bytes(selection.image_manifest)]),
        bytes(selection.broker_hard_caps),
        bytes([17; 32]),
        bytes(selection.conformance_report),
        bytes(trust.snapshot_digest()),
        bytes(revocation.snapshot_digest()),
        integer(trust.trust_epoch()),
        integer(revocation.revocation_epoch()),
        bytes(selection.syscall_set),
        Value::Text("policy".to_owned()),
    ]);
    Ok(SandboxAdministratorPolicy::authenticate(
        &sign_record("APT1", unsigned, &authority.policy)?,
        trust,
        revocation,
    )?)
}

fn launch_policy(sim1_digest: [u8; 32]) -> TestResult<Vec<u8>> {
    launch_policy_with_limits(sim1_digest, 1, commitment_limit_values())
}

fn launch_policy_with_limits(
    sim1_digest: [u8; 32],
    execution_mode: u64,
    limits: Vec<Value>,
) -> TestResult<Vec<u8>> {
    self_digested_record(
        "LPS1",
        Value::Array(vec![
            Value::Text("LPS1".to_owned()),
            integer(1),
            Value::Text("air-gapped".to_owned()),
            integer(execution_mode),
            bytes(sim1_digest),
            Value::Array(limits),
            Value::Array(vec![]),
        ]),
    )
}

fn commitment_limit_values() -> Vec<Value> {
    commitment_limit_values_with_concurrency(256)
}

fn commitment_limit_values_with_concurrency(concurrent_attempts: u64) -> Vec<Value> {
    (0..17)
        .map(|limit_id| {
            let value = if limit_id == 13 {
                concurrent_attempts
            } else {
                2_000
            };
            Value::Array(vec![integer(limit_id), integer(value)])
        })
        .collect()
}

fn broker_hard_caps() -> TestResult<Vec<u8>> {
    broker_hard_caps_with_limits(commitment_limit_values())
}

fn broker_hard_caps_with_limits(limits: Vec<Value>) -> TestResult<Vec<u8>> {
    encode(&Value::Array(vec![
        Value::Text("BHC1".to_owned()),
        integer(1),
        Value::Array(limits),
    ]))
}

fn broker_hard_caps_record(limits: Value) -> TestResult<Vec<u8>> {
    encode(&Value::Array(vec![
        Value::Text("BHC1".to_owned()),
        integer(1),
        limits,
    ]))
}

fn payload_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn execute_request(
    fixture: &Fixture,
    launch: &LaunchPolicy,
    capability_ids: &[&str],
) -> TestResult<Vec<u8>> {
    let input = b"input";
    let evaluation = fixture.evaluation_request(launch)?;
    let attempt = selector_attempt();
    self_digested_record(
        "SPX1",
        Value::Array(vec![
            Value::Text("SPX1".to_owned()),
            integer(1),
            Value::Array(vec![
                Value::Bytes(evaluation.request_id.to_vec()),
                bytes(fixture.policy.policy_digest()),
                integer(fixture.policy.policy_epoch()),
                Value::Bytes(vec![32; 16]),
            ]),
            Value::Bytes(vec![33; 16]),
            bytes(evaluation.request_digest),
            bytes([35; 32]),
            bytes([36; 32]),
            bytes([37; 32]),
            bytes(attempt.fixture_digest),
            bytes(evaluation.execution_profile_digest),
            bytes(launch.policy_digest),
            bytes(wrapped_digest(&fixture.sim1)?),
            bytes(fixture.policy.policy_digest()),
            bytes(fixture.trust.snapshot_digest()),
            bytes(fixture.revocation.snapshot_digest()),
            bytes(wrapped_digest(&fixture.spm1)?),
            bytes([17; 32]),
            bytes(wrapped_digest(&fixture.pcr1)?),
            bytes(wrapped_digest(&fixture.hcp1)?),
            Value::Array(
                capability_ids
                    .iter()
                    .map(|capability| Value::Text((*capability).to_owned()))
                    .collect(),
            ),
            Value::Array(vec![
                integer(u64::try_from(input.len())?),
                bytes(payload_digest(b"PiglorOS.SandboxInputBytes.v1\0", input)),
            ]),
            Value::Array(vec![]),
        ]),
    )
}

fn admission_grant(
    fixture: &Fixture,
    request: &SandboxExecuteRequest,
    launch: &LaunchPolicy,
    commitment: &SelectorGrantCommitment,
) -> TestResult<Vec<u8>> {
    let authority = &request.authority;
    sign_record(
        "AGR1",
        Value::Array(vec![
            Value::Text("AGR1".to_owned()),
            integer(1),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            bytes(authority.evr1_digest),
            bytes(authority.fixture_contract_digest),
            bytes(authority.fixture_digest),
            bytes(authority.execution_profile_digest),
            bytes(authority.lps1_digest),
            bytes(authority.sim1_digest),
            bytes(authority.apt1_digest),
            bytes(authority.trs1_digest),
            bytes(authority.rvs1_digest),
            bytes(authority.spm1_digest),
            bytes(authority.pcf1_digest),
            bytes(authority.pcr1_digest),
            bytes(authority.hcp1_digest),
            integer(fixture.trust.trust_epoch()),
            integer(fixture.revocation.revocation_epoch()),
            integer(fixture.policy.policy_epoch()),
            bytes(commitment.effective_limits_digest()),
            bytes(request.adapter_input.digest),
            Value::Array(vec![]),
            bytes(launch.policy_digest),
            bytes(commitment.expected_readback_set_digest()),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
}

fn selector_attempt() -> CaseAttempt {
    let artifact = |bytes: Vec<u8>| AttemptArtifact {
        digest: *blake3::hash(&bytes).as_bytes(),
        bytes,
    };
    CaseAttempt {
        case_id: "case".to_owned(),
        claim_layer: 1,
        family: 1,
        mode: 1,
        fixture_digest: [38; 32],
        schema: artifact(vec![1]),
        payload: artifact(vec![2]),
        auxiliary: Vec::new(),
        budget: DeterministicBudget {
            memory_bytes: 1,
            cpu_fuel: 1,
            host_calls: 1,
            event_count: 1,
            output_bytes: 1,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
        },
        watchdog_ms: 1,
        network_allowed: false,
        capability_ids: vec!["execute".to_owned()],
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 1,
            max_attempt_bytes: 3,
        },
    }
}

fn refresh_evaluation_request(request: &mut EvaluationRequest) -> TestResult {
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(())
}

fn network_exchange_plan() -> TestResult<NetworkExchangePlan> {
    let exchange_id = [41; 16];
    let request_digest = [42; 32];
    let expected_response_digest = [43; 32];
    let retention_policy_digest = [44; 32];
    let unsigned = Value::Array(vec![
        Value::Text("NXP1".to_owned()),
        integer(1),
        Value::Bytes(exchange_id.to_vec()),
        integer(0),
        Value::Text("execute".to_owned()),
        integer(1),
        bytes(request_digest),
        integer(1),
        bytes(expected_response_digest),
        bytes(retention_policy_digest),
    ]);
    Ok(NetworkExchangePlan {
        exchange_id,
        occurrence: 0,
        capability_id: "execute".to_owned(),
        request_length: 1,
        request_digest,
        response_maximum: 1,
        expected_response_digest,
        retention_policy_digest,
        plan_digest: digest_value(b"PiglorOS.NetworkExchangePlan.v1\0", &unsigned)?,
    })
}

fn audit_record(
    fixture: &Fixture,
    grant: &AdmissionGrant,
    sequence: u64,
    event: u64,
    previous: Option<[u8; 32]>,
) -> TestResult<Vec<u8>> {
    let authority = match event {
        0..=10 => vec![grant.grant_digest, grant.elm1_digest, [46; 32]],
        11 | 13 => vec![grant.grant_digest, [41; 32], [44; 32]],
        12 => vec![grant.grant_digest, [41; 32], [42; 32], [44; 32]],
        _ => return Err("unsupported audit fixture event".into()),
    };
    sign_record(
        "SAU1",
        Value::Array(vec![
            Value::Text("SAU1".to_owned()),
            integer(1),
            Value::Bytes(grant.attempt_id.to_vec()),
            integer(sequence),
            integer(event),
            Value::Array(authority.into_iter().map(bytes).collect()),
            previous.map_or(Value::Null, bytes),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
}

fn audit_chain(fixture: &Fixture, grant: &AdmissionGrant) -> TestResult<Vec<Vec<u8>>> {
    audit_chain_for_events(fixture, grant, &[11, 12])
}

fn audit_chain_for_events(
    fixture: &Fixture,
    grant: &AdmissionGrant,
    events: &[u8],
) -> TestResult<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(events.len());
    let mut previous = None;
    for (sequence, event) in events.iter().copied().enumerate() {
        let record = audit_record(
            fixture,
            grant,
            u64::try_from(sequence)?,
            u64::from(event),
            previous,
        )?;
        previous = Some(wrapped_digest(&record)?);
        records.push(record);
    }
    Ok(records)
}

fn provider_receipt(
    fixture: &Fixture,
    grant: &AdmissionGrant,
    audit_digest: [u8; 32],
) -> TestResult<Vec<u8>> {
    provider_receipt_for_lifecycle(fixture, grant, audit_digest, Some([41; 32]), Some([42; 32]))
}

fn provider_receipt_for_lifecycle(
    fixture: &Fixture,
    grant: &AdmissionGrant,
    audit_digest: [u8; 32],
    ready: Option<[u8; 32]>,
    release: Option<[u8; 32]>,
) -> TestResult<Vec<u8>> {
    sign_record(
        "SPR1",
        Value::Array(vec![
            Value::Text("SPR1".to_owned()),
            integer(1),
            Value::Bytes(grant.attempt_id.to_vec()),
            bytes(grant.grant_digest),
            bytes(grant.authority.spm1_digest),
            bytes(*blake3::hash(&fixture.provider_binary).as_bytes()),
            bytes(grant.authority.lps1_digest),
            bytes(grant.authority.sim1_digest),
            bytes(grant.authority.apt1_digest),
            bytes(grant.authority.trs1_digest),
            bytes(grant.authority.rvs1_digest),
            integer(grant.trust_epoch),
            integer(grant.revocation_epoch),
            integer(grant.policy_epoch),
            bytes(grant.authority.hcp1_digest),
            bytes(grant.elm1_digest),
            Value::Array(vec![]),
            ready.map_or(Value::Null, bytes),
            release.map_or(Value::Null, bytes),
            bytes([43; 32]),
            bytes([44; 32]),
            bytes([45; 32]),
            bytes([46; 32]),
            bytes(audit_digest),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
}

fn terminal_result(
    fixture: &Fixture,
    request: &SandboxExecuteRequest,
    grant: &AdmissionGrant,
    receipt: &SandboxProviderReceipt,
) -> TestResult<Vec<u8>> {
    terminal_result_for_outcome(fixture, request, grant, receipt, 0, &[11, 12])
}

fn terminal_result_for_outcome(
    fixture: &Fixture,
    request: &SandboxExecuteRequest,
    grant: &AdmissionGrant,
    receipt: &SandboxProviderReceipt,
    outcome: u64,
    events: &[u8],
) -> TestResult<Vec<u8>> {
    let output = b"output";
    sign_record(
        "SPY1",
        Value::Array(vec![
            Value::Text("SPY1".to_owned()),
            integer(1),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            integer(outcome),
            if outcome == 0 {
                Value::Array(vec![
                    integer(u64::try_from(output.len())?),
                    bytes(payload_digest(b"PiglorOS.SandboxOutputBytes.v1\0", output)),
                ])
            } else {
                Value::Null
            },
            bytes(grant.grant_digest),
            bytes(receipt.receipt_digest),
            Value::Array(
                events
                    .iter()
                    .copied()
                    .map(|event| integer(u64::from(event)))
                    .collect(),
            ),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
}

struct Fixture {
    authority: SigningAuthority,
    trust: SandboxTrustSnapshot,
    revocation: SandboxRevocationSnapshot,
    policy: SandboxAdministratorPolicy,
    required_features: Vec<String>,
    provider_binary: Vec<u8>,
    broker_hard_caps: Vec<u8>,
    spm1: Vec<u8>,
    scs1: Vec<u8>,
    hcp1: Vec<u8>,
    pcr1: Vec<u8>,
    root_image: Vec<u8>,
    executable: Vec<u8>,
    sim1: Vec<u8>,
    lps1: Vec<u8>,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let authority = SigningAuthority::fixed();
        let trust = authority.trust()?;
        let revocation = revocation(&trust, &authority, vec![], vec![])?;
        let required_features = vec!["cgroup-v2".to_owned()];
        let feature_digest = feature_set_digest(&required_features)?;
        let provider_binary = b"exact provider binary".to_vec();
        let broker_hard_caps = broker_hard_caps()?;
        let binary_digest = *blake3::hash(&provider_binary).as_bytes();
        let provider_record = provider_manifest(&authority, binary_digest, feature_digest)?;
        let scs1 = syscall_set(0)?;
        let hcp1 = host_profile(&authority, "cgroup-v2", 1, 0)?;
        let pcr1 = conformance_report(
            &authority,
            binary_digest,
            feature_digest,
            wrapped_digest(&hcp1)?,
            0,
        )?;
        let root_image = b"img".to_vec();
        let executable = b"adapter executable".to_vec();
        let image_record = image_manifest(&authority, &root_image, &executable, 0)?;
        let lps1 = launch_policy(wrapped_digest(&image_record)?)?;
        let policy = administrator_policy(
            &trust,
            &revocation,
            &authority,
            &PolicySelectionDigests {
                provider_manifest: wrapped_digest(&provider_record)?,
                provider_binary: binary_digest,
                broker_hard_caps: *blake3::hash(&broker_hard_caps).as_bytes(),
                conformance_report: wrapped_digest(&pcr1)?,
                syscall_set: wrapped_digest(&scs1)?,
                launch_policy: wrapped_digest(&lps1)?,
                image_manifest: wrapped_digest(&image_record)?,
            },
        )?;
        Ok(Self {
            authority,
            trust,
            revocation,
            policy,
            required_features,
            provider_binary,
            broker_hard_caps,
            spm1: provider_record,
            scs1,
            hcp1,
            pcr1,
            root_image,
            executable,
            sim1: image_record,
            lps1,
        })
    }

    fn inputs(&self) -> SandboxProviderAdmissionInputs<'_> {
        SandboxProviderAdmissionInputs {
            provider_manifest: &self.spm1,
            provider_binary_digest: *blake3::hash(&self.provider_binary).as_bytes(),
            broker_hard_caps: &self.broker_hard_caps,
            conformance_report: &self.pcr1,
            host_profile: &self.hcp1,
            syscall_set: &self.scs1,
            required_features: &self.required_features,
        }
    }

    fn admit(&self) -> Result<AdmittedSandboxProvider, SandboxAdmissionError> {
        AdmittedSandboxProvider::admit(&self.policy, &self.trust, &self.revocation, self.inputs())
    }

    fn evaluation_request(&self, launch: &LaunchPolicy) -> TestResult<EvaluationRequest> {
        let mut request = EvaluationRequest {
            request_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            profile_digest: [2; 32],
            fixture_bundle_digest: [3; 32],
            subject_adapter: SubjectAdapterKind::PublicPluginProtocol,
            subject_artifact_digest: *blake3::hash(&self.executable).as_bytes(),
            implementation: ImplementationIdentity {
                implementation_id: "subject".to_owned(),
                source_digest: [4; 32],
                build_digest: [5; 32],
                binary_digest: [6; 32],
                public_contract_digest: [7; 32],
                organization_id: None,
            },
            execution_profile_digest: [8; 32],
            trust_policy_snapshot_digest: [9; 32],
            output_capability: OutputCapability {
                capability_digest: [10; 32],
                report_bytes_limit: 1,
                diagnostic_bytes_limit: 0,
            },
            evaluator_protocol_digest: [11; 32],
            evaluator_hard_caps_digest: [12; 32],
            sandbox_requirement: Some(SandboxRequirement {
                lps1_digest: launch.policy_digest,
                sim1_digest: wrapped_digest(&self.sim1)?,
                required_provider_capability: RequiredProviderCapability {
                    capability_id: "execute".to_owned(),
                    capability_version: 1,
                    minimum_strength: 1,
                },
                apt1_digest: self.policy.policy_digest(),
                policy_epoch: self.policy.policy_epoch(),
            }),
            request_digest: [13; 32],
        };
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
        Ok(request)
    }

    fn selector_grant_commitment(
        &self,
        admitted: &AdmittedSandboxProvider,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
        request: &SandboxExecuteRequest,
    ) -> TestResult<SelectorGrantCommitment> {
        let evaluation = self.evaluation_request(launch)?;
        let attempt = selector_attempt();
        Ok(admitted.derive_selector_grant_commitment(
            image,
            launch,
            &evaluation,
            &attempt,
            &request.network_plans,
        )?)
    }

    fn admission_grant(
        &self,
        admitted: &AdmittedSandboxProvider,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
        request: &SandboxExecuteRequest,
    ) -> TestResult<Vec<u8>> {
        let commitment = self.selector_grant_commitment(admitted, image, launch, request)?;
        admission_grant(self, request, launch, &commitment)
    }

    fn authenticate_grant(
        &self,
        admitted: &AdmittedSandboxProvider,
        bytes: &[u8],
        request: &SandboxExecuteRequest,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
    ) -> Result<AuthenticatedAdmissionGrant, SandboxAdmissionError> {
        let evaluation = self
            .evaluation_request(launch)
            .map_err(|_| SandboxAdmissionError::ConformanceMismatch)?;
        let attempt = selector_attempt();
        let commitment = admitted.derive_selector_grant_commitment(
            image,
            launch,
            &evaluation,
            &attempt,
            &request.network_plans,
        )?;
        admitted.authenticate_grant(bytes, request, image, launch, &commitment)
    }

    fn policy_for_provider(
        &self,
        revocation: &SandboxRevocationSnapshot,
        provider_manifest: &[u8],
        conformance_report: &[u8],
    ) -> TestResult<SandboxAdministratorPolicy> {
        administrator_policy(
            &self.trust,
            revocation,
            &self.authority,
            &PolicySelectionDigests {
                provider_manifest: wrapped_digest(provider_manifest)?,
                provider_binary: *blake3::hash(&self.provider_binary).as_bytes(),
                broker_hard_caps: *blake3::hash(&self.broker_hard_caps).as_bytes(),
                conformance_report: wrapped_digest(conformance_report)?,
                syscall_set: wrapped_digest(&self.scs1)?,
                launch_policy: wrapped_digest(&self.lps1)?,
                image_manifest: wrapped_digest(&self.sim1)?,
            },
        )
    }

    fn policy_for_image(
        &self,
        image_manifest: &[u8],
        launch: &[u8],
    ) -> TestResult<SandboxAdministratorPolicy> {
        administrator_policy(
            &self.trust,
            &self.revocation,
            &self.authority,
            &PolicySelectionDigests {
                provider_manifest: wrapped_digest(&self.spm1)?,
                provider_binary: *blake3::hash(&self.provider_binary).as_bytes(),
                broker_hard_caps: *blake3::hash(&self.broker_hard_caps).as_bytes(),
                conformance_report: wrapped_digest(&self.pcr1)?,
                syscall_set: wrapped_digest(&self.scs1)?,
                launch_policy: wrapped_digest(launch)?,
                image_manifest: wrapped_digest(image_manifest)?,
            },
        )
    }

    fn policy_for_commitment_artifacts(
        &self,
        broker_hard_caps: &[u8],
        launch_policy: &[u8],
    ) -> TestResult<SandboxAdministratorPolicy> {
        administrator_policy(
            &self.trust,
            &self.revocation,
            &self.authority,
            &PolicySelectionDigests {
                provider_manifest: wrapped_digest(&self.spm1)?,
                provider_binary: *blake3::hash(&self.provider_binary).as_bytes(),
                broker_hard_caps: *blake3::hash(broker_hard_caps).as_bytes(),
                conformance_report: wrapped_digest(&self.pcr1)?,
                syscall_set: wrapped_digest(&self.scs1)?,
                launch_policy: wrapped_digest(launch_policy)?,
                image_manifest: wrapped_digest(&self.sim1)?,
            },
        )
    }

    fn admit_with_broker_hard_caps(
        &self,
        broker_hard_caps: &[u8],
    ) -> Result<AdmittedSandboxProvider, SandboxAdmissionError> {
        let policy = self
            .policy_for_commitment_artifacts(broker_hard_caps, &self.lps1)
            .map_err(|_| SandboxAdmissionError::ConformanceMismatch)?;
        let inputs = SandboxProviderAdmissionInputs {
            broker_hard_caps,
            ..self.inputs()
        };
        AdmittedSandboxProvider::admit(&policy, &self.trust, &self.revocation, inputs)
    }
}

#[test]
fn complete_provider_and_image_admission_binds_all_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    assert_eq!(admitted.manifest().provider_id, "provider");
    assert_eq!(
        admitted.syscall_set().architecture,
        SandboxArchitecture::X86_64
    );
    assert_eq!(
        admitted.host_profile().architecture,
        SandboxArchitecture::X86_64
    );
    assert_eq!(
        admitted.conformance_report().architecture,
        SandboxArchitecture::X86_64
    );
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    assert_eq!(image.manifest().executable_path, "/adapter");
    assert!(
        admitted.supports_required_capability(&RequiredProviderCapability {
            capability_id: "execute".to_owned(),
            capability_version: 1,
            minimum_strength: 1,
        })
    );
    assert!(
        !admitted.supports_required_capability(&RequiredProviderCapability {
            capability_id: "execute".to_owned(),
            capability_version: 2,
            minimum_strength: 1,
        })
    );
    assert!(
        !admitted.supports_required_capability(&RequiredProviderCapability {
            capability_id: "execute".to_owned(),
            capability_version: 1,
            minimum_strength: 2,
        })
    );
    Ok(())
}

#[test]
fn provider_admission_rejects_unselected_bytes_and_failed_features() -> TestResult {
    let fixture = Fixture::new()?;
    let wrong_binary = SandboxProviderAdmissionInputs {
        provider_binary_digest: *blake3::hash(b"changed").as_bytes(),
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            wrong_binary,
        ),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    let wrong_broker_caps = SandboxProviderAdmissionInputs {
        broker_hard_caps: b"changed",
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            wrong_broker_caps,
        ),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    let unselected_scs1 = syscall_set(1)?;
    let wrong_selection = SandboxProviderAdmissionInputs {
        syscall_set: &unselected_scs1,
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            wrong_selection,
        ),
        Err(SandboxAdmissionError::PolicyMismatch)
    );
    let failed_hcp1 = host_profile(&fixture.authority, "cgroup-v2", 0, 0)?;
    let failed_pcr1 = conformance_report(
        &fixture.authority,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        feature_set_digest(&fixture.required_features)?,
        wrapped_digest(&failed_hcp1)?,
        0,
    )?;
    let failed_policy = administrator_policy(
        &fixture.trust,
        &fixture.revocation,
        &fixture.authority,
        &PolicySelectionDigests {
            provider_manifest: wrapped_digest(&fixture.spm1)?,
            provider_binary: *blake3::hash(&fixture.provider_binary).as_bytes(),
            broker_hard_caps: *blake3::hash(&fixture.broker_hard_caps).as_bytes(),
            conformance_report: wrapped_digest(&failed_pcr1)?,
            syscall_set: wrapped_digest(&fixture.scs1)?,
            launch_policy: wrapped_digest(&fixture.lps1)?,
            image_manifest: wrapped_digest(&fixture.sim1)?,
        },
    )?;
    let failed_input = SandboxProviderAdmissionInputs {
        conformance_report: &failed_pcr1,
        host_profile: &failed_hcp1,
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(
            &failed_policy,
            &fixture.trust,
            &fixture.revocation,
            failed_input,
        ),
        Err(SandboxAdmissionError::HostCapabilityMismatch)
    );
    Ok(())
}

#[test]
fn provider_admission_rejects_cross_record_architecture_mismatch() -> TestResult {
    let fixture = Fixture::new()?;
    let hcp1 = host_profile(&fixture.authority, "cgroup-v2", 1, 1)?;
    let pcr1 = conformance_report(
        &fixture.authority,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        feature_set_digest(&fixture.required_features)?,
        wrapped_digest(&hcp1)?,
        1,
    )?;
    let policy = administrator_policy(
        &fixture.trust,
        &fixture.revocation,
        &fixture.authority,
        &PolicySelectionDigests {
            provider_manifest: wrapped_digest(&fixture.spm1)?,
            provider_binary: *blake3::hash(&fixture.provider_binary).as_bytes(),
            broker_hard_caps: *blake3::hash(&fixture.broker_hard_caps).as_bytes(),
            conformance_report: wrapped_digest(&pcr1)?,
            syscall_set: wrapped_digest(&fixture.scs1)?,
            launch_policy: wrapped_digest(&fixture.lps1)?,
            image_manifest: wrapped_digest(&fixture.sim1)?,
        },
    )?;
    let inputs = SandboxProviderAdmissionInputs {
        conformance_report: &pcr1,
        host_profile: &hcp1,
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs),
        Err(SandboxAdmissionError::ArchitectureMismatch)
    );
    Ok(())
}

#[test]
fn provider_admission_rejects_each_malformed_input_record() -> TestResult {
    let fixture = Fixture::new()?;
    for field in 0..4 {
        let malformed = b"not-cbor";
        let mut inputs = fixture.inputs();
        match field {
            0 => inputs.provider_manifest = malformed,
            1 => inputs.syscall_set = malformed,
            2 => inputs.host_profile = malformed,
            3 => inputs.conformance_report = malformed,
            _ => return Err("unknown admission input field".into()),
        }
        assert!(matches!(
            AdmittedSandboxProvider::admit(
                &fixture.policy,
                &fixture.trust,
                &fixture.revocation,
                inputs,
            ),
            Err(SandboxAdmissionError::Protocol(_))
        ));
    }
    Ok(())
}

#[test]
fn provider_admission_rejects_each_revoked_provider_identity() -> TestResult {
    let fixture = Fixture::new()?;
    for revoked_identity in [
        wrapped_digest(&fixture.spm1)?,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
    ] {
        let revocation = revocation(
            &fixture.trust,
            &fixture.authority,
            vec![bytes(revoked_identity)],
            vec![],
        )?;
        assert_eq!(
            AdmittedSandboxProvider::admit(
                &fixture.policy,
                &fixture.trust,
                &revocation,
                fixture.inputs(),
            ),
            Err(SandboxAdmissionError::Revoked)
        );
    }
    Ok(())
}

#[test]
fn provider_admission_rejects_each_untrusted_provider_signer() -> TestResult {
    let fixture = Fixture::new()?;
    for (field, replacement) in [
        (17, Value::Text("other-release".to_owned())),
        (7, Value::Text("other-runtime".to_owned())),
    ] {
        let manifest = resign_unsigned_field(
            &fixture.spm1,
            "SPM1",
            field,
            replacement,
            &fixture.authority.release,
        )?;
        let policy = fixture.policy_for_provider(&fixture.revocation, &manifest, &fixture.pcr1)?;
        let inputs = SandboxProviderAdmissionInputs {
            provider_manifest: &manifest,
            ..fixture.inputs()
        };
        assert!(matches!(
            AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs,),
            Err(SandboxAdmissionError::Trust(_))
        ));
    }

    let report = resign_unsigned_field(
        &fixture.pcr1,
        "PCR1",
        10,
        Value::Text("other-reviewer".to_owned()),
        &fixture.authority.reviewer,
    )?;
    let policy = fixture.policy_for_provider(&fixture.revocation, &fixture.spm1, &report)?;
    let inputs = SandboxProviderAdmissionInputs {
        conformance_report: &report,
        ..fixture.inputs()
    };
    assert!(matches!(
        AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs,),
        Err(SandboxAdmissionError::Trust(_))
    ));
    Ok(())
}

#[test]
fn provider_admission_rejects_each_cross_record_binding_substitution() -> TestResult {
    let fixture = Fixture::new()?;
    let wrong_epoch = resign_unsigned_field(
        &fixture.spm1,
        "SPM1",
        14,
        integer(fixture.trust.trust_epoch() + 1),
        &fixture.authority.release,
    )?;
    let policy = fixture.policy_for_provider(&fixture.revocation, &wrong_epoch, &fixture.pcr1)?;
    let inputs = SandboxProviderAdmissionInputs {
        provider_manifest: &wrong_epoch,
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs,),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let wrong_runtime = resign_unsigned_field(
        &fixture.hcp1,
        "HCP1",
        8,
        Value::Text("other-runtime".to_owned()),
        &fixture.authority.runtime,
    )?;
    let inputs = SandboxProviderAdmissionInputs {
        host_profile: &wrong_runtime,
        ..fixture.inputs()
    };
    assert_eq!(
        AdmittedSandboxProvider::admit(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            inputs,
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    for (record, magic, field, signer) in [
        (&fixture.pcr1, "PCR1", 2, &fixture.authority.reviewer),
        (&fixture.pcr1, "PCR1", 3, &fixture.authority.reviewer),
        (&fixture.pcr1, "PCR1", 4, &fixture.authority.reviewer),
        (&fixture.pcr1, "PCR1", 5, &fixture.authority.reviewer),
        (&fixture.pcr1, "PCR1", 6, &fixture.authority.reviewer),
        (&fixture.pcr1, "PCR1", 8, &fixture.authority.reviewer),
        (&fixture.spm1, "SPM1", 16, &fixture.authority.release),
    ] {
        let changed = resign_unsigned_field(record, magic, field, bytes([99; 32]), signer)?;
        let (manifest, report) = if magic == "SPM1" {
            (changed.as_slice(), fixture.pcr1.as_slice())
        } else {
            (fixture.spm1.as_slice(), changed.as_slice())
        };
        let policy = fixture.policy_for_provider(&fixture.revocation, manifest, report)?;
        let inputs = SandboxProviderAdmissionInputs {
            provider_manifest: manifest,
            conformance_report: report,
            ..fixture.inputs()
        };
        assert_eq!(
            AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs,),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }
    Ok(())
}

#[test]
fn image_admission_rejects_changed_revoked_and_foreign_bytes() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    assert_eq!(
        admitted.admit_image(&fixture.sim1, b"changed", &fixture.executable),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    assert_eq!(
        admitted.admit_image(&fixture.sim1, &fixture.root_image, b"changed"),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    for revoked_identity in [
        wrapped_digest(&fixture.sim1)?,
        *blake3::hash(&fixture.root_image).as_bytes(),
        *blake3::hash(&fixture.executable).as_bytes(),
    ] {
        let revoked = revocation(
            &fixture.trust,
            &fixture.authority,
            vec![],
            vec![bytes(revoked_identity)],
        )?;
        let revoked_policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        let revoked_admission = AdmittedSandboxProvider::admit(
            &revoked_policy,
            &fixture.trust,
            &revoked,
            fixture.inputs(),
        )?;
        assert_eq!(
            revoked_admission.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable,),
            Err(SandboxAdmissionError::Revoked)
        );
    }
    Ok(())
}

#[test]
fn image_admission_rejects_each_selection_and_authority_substitution() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let unselected = image_manifest(&fixture.authority, b"other-image", &fixture.executable, 0)?;
    assert_eq!(
        admitted.admit_image(&unselected, b"other-image", &fixture.executable),
        Err(SandboxAdmissionError::PolicyMismatch)
    );

    for (field, replacement, expected) in [
        (
            4,
            integer(u64::try_from(fixture.root_image.len())? + 1),
            SandboxAdmissionError::ArtifactMismatch,
        ),
        (
            18,
            integer(fixture.trust.trust_epoch() + 1),
            SandboxAdmissionError::ConformanceMismatch,
        ),
        (
            13,
            bytes([99; 32]),
            SandboxAdmissionError::CertificateMismatch,
        ),
        (14, integer(78), SandboxAdmissionError::CertificateMismatch),
    ] {
        let changed = resign_unsigned_field(
            &fixture.sim1,
            "SIM1",
            field,
            replacement,
            &fixture.authority.image,
        )?;
        let policy = fixture.policy_for_image(&changed, &fixture.lps1)?;
        let selected = AdmittedSandboxProvider::admit(
            &policy,
            &fixture.trust,
            &fixture.revocation,
            fixture.inputs(),
        )?;
        assert_eq!(
            selected.admit_image(&changed, &fixture.root_image, &fixture.executable),
            Err(expected)
        );
    }

    let unknown_key = resign_unsigned_field(
        &fixture.sim1,
        "SIM1",
        19,
        Value::Text("other-image".to_owned()),
        &fixture.authority.image,
    )?;
    let policy = fixture.policy_for_image(&unknown_key, &fixture.lps1)?;
    let selected = AdmittedSandboxProvider::admit(
        &policy,
        &fixture.trust,
        &fixture.revocation,
        fixture.inputs(),
    )?;
    assert!(matches!(
        selected.admit_image(&unknown_key, &fixture.root_image, &fixture.executable),
        Err(SandboxAdmissionError::Trust(_))
    ));
    Ok(())
}

#[test]
fn image_admission_rejects_provider_architecture_substitution() -> TestResult {
    let fixture = Fixture::new()?;
    let syscall_set = syscall_set(1)?;
    let host_profile = host_profile(&fixture.authority, "cgroup-v2", 1, 1)?;
    let report = conformance_report(
        &fixture.authority,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        feature_set_digest(&fixture.required_features)?,
        wrapped_digest(&host_profile)?,
        1,
    )?;
    let manifest = resign_unsigned_field(
        &fixture.spm1,
        "SPM1",
        9,
        Value::Array(vec![integer(1)]),
        &fixture.authority.release,
    )?;
    let policy = administrator_policy(
        &fixture.trust,
        &fixture.revocation,
        &fixture.authority,
        &PolicySelectionDigests {
            provider_manifest: wrapped_digest(&manifest)?,
            provider_binary: *blake3::hash(&fixture.provider_binary).as_bytes(),
            broker_hard_caps: *blake3::hash(&fixture.broker_hard_caps).as_bytes(),
            conformance_report: wrapped_digest(&report)?,
            syscall_set: wrapped_digest(&syscall_set)?,
            launch_policy: wrapped_digest(&fixture.lps1)?,
            image_manifest: wrapped_digest(&fixture.sim1)?,
        },
    )?;
    let inputs = SandboxProviderAdmissionInputs {
        provider_manifest: &manifest,
        conformance_report: &report,
        host_profile: &host_profile,
        syscall_set: &syscall_set,
        ..fixture.inputs()
    };
    let selected =
        AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs)?;
    assert_eq!(
        selected.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable),
        Err(SandboxAdmissionError::ArchitectureMismatch)
    );
    Ok(())
}

#[test]
fn launch_and_execute_admission_reject_each_selected_authority_mismatch() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let unselected_launch = launch_policy([99; 32])?;
    assert_eq!(
        admitted.admit_launch_policy(&unselected_launch, &image),
        Err(SandboxAdmissionError::PolicyMismatch)
    );

    let policy = fixture.policy_for_image(&fixture.sim1, &unselected_launch)?;
    let selected = AdmittedSandboxProvider::admit(
        &policy,
        &fixture.trust,
        &fixture.revocation,
        fixture.inputs(),
    )?;
    let image = selected.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    assert_eq!(
        selected.admit_launch_policy(&unselected_launch, &image),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request_bytes = execute_request(&fixture, &launch, &["execute"])?;
    let changed_request = redigest_unsigned_field(&request_bytes, "SPX1", 10, bytes([99; 32]))?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&changed_request)?;
    assert_eq!(
        fixture.authenticate_grant(
            &admitted,
            &fixture.admission_grant(&admitted, &image, &launch, &request)?,
            &request,
            &image,
            &launch,
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn host_profile_rejects_non_boolean_feature_proof_status() -> TestResult {
    let fixture = Fixture::new()?;
    let invalid_proof = Value::Array(vec![Value::Array(vec![
        Value::Text("cgroup-v2".to_owned()),
        integer(2),
        bytes([18; 32]),
    ])]);
    let changed = resign_unsigned_field(
        &fixture.hcp1,
        "HCP1",
        4,
        invalid_proof,
        &fixture.authority.runtime,
    )?;
    assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());
    let changed = resign_unsigned_field(
        &fixture.hcp1,
        "HCP1",
        4,
        Value::Array(vec![Value::Null]),
        &fixture.authority.runtime,
    )?;
    assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());
    for (feature_field, replacement) in [(0, Value::Null), (1, Value::Null), (2, Value::Null)] {
        let feature = Value::Array(vec![
            Value::Text("cgroup-v2".to_owned()),
            integer(1),
            bytes([18; 32]),
        ]);
        let Value::Array(mut feature_fields) = feature else {
            return Err("feature proof must be an array".into());
        };
        feature_fields[feature_field] = replacement;
        let changed = resign_unsigned_field(
            &fixture.hcp1,
            "HCP1",
            4,
            Value::Array(vec![Value::Array(feature_fields)]),
            &fixture.authority.runtime,
        )?;
        assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());
    }
    assert!(
        HostCapabilityProfile::from_canonical_cbor(&replace_signed_signature(
            &fixture.hcp1,
            [0; 64]
        )?)
        .is_err()
    );
    Ok(())
}

#[test]
fn provider_lifecycle_records_are_authenticated_against_admission() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = fixture.authenticate_grant(
        &admitted,
        &fixture.admission_grant(&admitted, &image, &launch, &request)?,
        &request,
        &image,
        &launch,
    )?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt = admitted.authenticate_receipt(
        &provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?,
        &grant,
    )?;
    let result = admitted.authenticate_terminal_result(
        &terminal_result(&fixture, &request, &grant, &receipt)?,
        &request,
        &grant,
        &receipt,
    )?;
    assert_eq!(result.spr1_digest, Some(receipt.receipt_digest));
    assert_eq!(result.attempt_id, request.attempt_id);
    assert_eq!(
        admitted
            .authenticate_audit_chain(&audit, &receipt, &result)?
            .len(),
        2
    );

    let unsupported = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["unsupported"],
    )?)?;
    assert_eq!(
        fixture.authenticate_grant(
            &admitted,
            &fixture.admission_grant(&admitted, &image, &launch, &unsupported)?,
            &unsupported,
            &image,
            &launch,
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn provider_terminal_audit_authority_covers_failure_and_denial_paths() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = fixture.authenticate_grant(
        &admitted,
        &fixture.admission_grant(&admitted, &image, &launch, &request)?,
        &request,
        &image,
        &launch,
    )?;

    for (outcome, events, ready) in [(4, vec![0], None), (1, vec![11, 13, 1], Some([41; 32]))] {
        let audit = audit_chain_for_events(&fixture, &grant, &events)?;
        let receipt = admitted.authenticate_receipt(
            &provider_receipt_for_lifecycle(
                &fixture,
                &grant,
                wrapped_digest(audit.last().ok_or("audit chain must not be empty")?)?,
                ready,
                None,
            )?,
            &grant,
        )?;
        let result = admitted.authenticate_terminal_result(
            &terminal_result_for_outcome(&fixture, &request, &grant, &receipt, outcome, &events)?,
            &request,
            &grant,
            &receipt,
        )?;
        assert_eq!(
            admitted
                .authenticate_audit_chain(&audit, &receipt, &result)?
                .len(),
            events.len()
        );
    }
    Ok(())
}

#[test]
fn admission_evidence_rejects_closed_host_and_report_boundaries() -> TestResult {
    let fixture = Fixture::new()?;
    let non_record = encode(&Value::Null)?;
    assert!(HostCapabilityProfile::from_canonical_cbor(&non_record).is_err());
    assert!(ProviderConformanceReport::from_canonical_cbor(&non_record).is_err());
    let invalid_architecture = resign_unsigned_field(
        &fixture.hcp1,
        "HCP1",
        2,
        integer(99),
        &fixture.authority.runtime,
    )?;
    assert!(HostCapabilityProfile::from_canonical_cbor(&invalid_architecture).is_err());
    for field in 2..=8 {
        let changed = resign_unsigned_field(
            &fixture.hcp1,
            "HCP1",
            field,
            Value::Null,
            &fixture.authority.runtime,
        )?;
        assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());
    }
    for (field, replacement) in [
        (3, Value::Text(String::new())),
        (4, Value::Array(Vec::new())),
        (5, bytes([0; 32])),
        (6, bytes([0; 32])),
        (7, bytes([0; 32])),
        (8, Value::Text(String::new())),
    ] {
        let changed = resign_unsigned_field(
            &fixture.hcp1,
            "HCP1",
            field,
            replacement,
            &fixture.authority.runtime,
        )?;
        assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());
    }

    let duplicate_features = Value::Array(vec![
        Value::Array(vec![
            Value::Text("cgroup-v2".to_owned()),
            integer(1),
            bytes([18; 32]),
        ]),
        Value::Array(vec![
            Value::Text("cgroup-v2".to_owned()),
            integer(1),
            bytes([18; 32]),
        ]),
    ]);
    let changed = resign_unsigned_field(
        &fixture.hcp1,
        "HCP1",
        4,
        duplicate_features,
        &fixture.authority.runtime,
    )?;
    assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());

    let mut profile = HostCapabilityProfile::from_canonical_cbor(&fixture.hcp1)?;
    profile.kernel_release.clear();
    assert!(profile
        .verify_signature(&fixture.authority.runtime.verifying_key())
        .is_err());
    Ok(())
}

#[test]
fn conformance_report_rejects_closed_wire_and_verification_boundaries() -> TestResult {
    let fixture = Fixture::new()?;
    for field in 2..=10 {
        let changed = resign_unsigned_field(
            &fixture.pcr1,
            "PCR1",
            field,
            Value::Null,
            &fixture.authority.reviewer,
        )?;
        assert!(ProviderConformanceReport::from_canonical_cbor(&changed).is_err());
    }
    let invalid_architecture = resign_unsigned_field(
        &fixture.pcr1,
        "PCR1",
        7,
        integer(99),
        &fixture.authority.reviewer,
    )?;
    assert!(ProviderConformanceReport::from_canonical_cbor(&invalid_architecture).is_err());
    for (field, replacement) in [
        (2, bytes([0; 32])),
        (3, bytes([0; 32])),
        (4, bytes([0; 32])),
        (5, bytes([0; 32])),
        (6, bytes([0; 32])),
        (8, bytes([0; 32])),
        (9, integer(1)),
        (10, Value::Text(String::new())),
    ] {
        let changed = resign_unsigned_field(
            &fixture.pcr1,
            "PCR1",
            field,
            replacement,
            &fixture.authority.reviewer,
        )?;
        assert!(ProviderConformanceReport::from_canonical_cbor(&changed).is_err());
    }
    assert!(
        ProviderConformanceReport::from_canonical_cbor(&replace_signed_signature(
            &fixture.pcr1,
            [0; 64]
        )?)
        .is_err()
    );
    let mut report = ProviderConformanceReport::from_canonical_cbor(&fixture.pcr1)?;
    report.pcf1_digest = [0; 32];
    assert!(report
        .verify_signature(&fixture.authority.reviewer.verifying_key())
        .is_err());
    Ok(())
}

#[test]
fn admission_entry_points_reject_malformed_records() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = fixture.authenticate_grant(
        &admitted,
        &fixture.admission_grant(&admitted, &image, &launch, &request)?,
        &request,
        &image,
        &launch,
    )?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt = admitted.authenticate_receipt(
        &provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?,
        &grant,
    )?;

    assert!(admitted
        .admit_image(b"not-cbor", &fixture.root_image, &fixture.executable)
        .is_err());
    assert!(admitted.admit_launch_policy(b"not-cbor", &image).is_err());
    assert!(fixture
        .authenticate_grant(&admitted, b"not-cbor", &request, &image, &launch)
        .is_err());
    assert!(admitted.authenticate_receipt(b"not-cbor", &grant).is_err());
    assert!(admitted
        .authenticate_terminal_result(b"not-cbor", &request, &grant, &receipt)
        .is_err());
    Ok(())
}

#[test]
fn admission_entry_points_reject_forged_signatures() -> TestResult {
    let fixture = Fixture::new()?;
    for record in 0..3 {
        let forged = match record {
            0 => replace_signed_signature(&fixture.spm1, [9; 64])?,
            1 => replace_signed_signature(&fixture.hcp1, [9; 64])?,
            2 => replace_signed_signature(&fixture.pcr1, [9; 64])?,
            _ => return Err("unsupported provider admission record".into()),
        };
        let inputs = match record {
            0 => SandboxProviderAdmissionInputs {
                provider_manifest: &forged,
                ..fixture.inputs()
            },
            1 => SandboxProviderAdmissionInputs {
                host_profile: &forged,
                ..fixture.inputs()
            },
            2 => SandboxProviderAdmissionInputs {
                conformance_report: &forged,
                ..fixture.inputs()
            },
            _ => return Err("unsupported provider admission record".into()),
        };
        assert!(AdmittedSandboxProvider::admit(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            inputs
        )
        .is_err());
    }

    let admitted = fixture.admit()?;
    let forged_image = replace_signed_signature(&fixture.sim1, [9; 64])?;
    assert!(admitted
        .admit_image(&forged_image, &fixture.root_image, &fixture.executable)
        .is_err());
    Ok(())
}

#[test]
fn provider_admission_rejects_invalid_required_feature_sets() -> TestResult {
    let fixture = Fixture::new()?;
    for required_features in [
        Vec::new(),
        vec![String::new()],
        vec!["cgroup-v2".to_owned(), "cgroup-v2".to_owned()],
        vec!["z-feature".to_owned(), "a-feature".to_owned()],
    ] {
        let inputs = SandboxProviderAdmissionInputs {
            required_features: &required_features,
            ..fixture.inputs()
        };
        assert_eq!(
            AdmittedSandboxProvider::admit(
                &fixture.policy,
                &fixture.trust,
                &fixture.revocation,
                inputs,
            ),
            Err(SandboxAdmissionError::HostCapabilityMismatch)
        );
    }
    Ok(())
}

#[test]
fn selector_derives_elm1_and_rbs1_from_selected_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let commitment = fixture.selector_grant_commitment(&admitted, &image, &launch, &request)?;

    assert_eq!(commitment.effective_limits().len(), 17);
    assert_eq!(commitment.effective_limits()[0].value, 1);
    assert_eq!(commitment.effective_limits()[4].value, 1);
    assert_eq!(commitment.effective_limits()[8].value, 1);
    assert_eq!(commitment.effective_limits()[9].value, 1);
    assert_eq!(commitment.effective_limits()[13].value, 256);
    assert!(commitment
        .effective_limits()
        .iter()
        .enumerate()
        .all(|(limit_id, limit)| usize::from(limit.limit_id) == limit_id));

    let Value::Array(wrapper) = ciborium::from_reader(commitment.expected_readback_set())? else {
        return Err("RBS1 wrapper must be an array".into());
    };
    let Some(Value::Array(unsigned)) = wrapper.first() else {
        return Err("RBS1 unsigned record must be an array".into());
    };
    assert_eq!(unsigned[0], Value::Text("RBS1".to_owned()));
    assert_eq!(
        wrapped_digest(commitment.expected_readback_set())?,
        commitment.expected_readback_set_digest()
    );
    assert_eq!(
        commitment.expected_readback_set_digest(),
        digest_value(
            b"PiglorOS.SandboxReadbackSet.v1\0",
            &Value::Array(unsigned.clone())
        )?
    );
    assert_ne!(
        commitment.expected_readback_set_digest(),
        digest_value(b"PiglorOS.RBS1.v1\0", &Value::Array(unsigned.clone()))?
    );
    Ok(())
}

#[test]
fn provider_admission_rejects_malformed_broker_hard_cap_records() -> TestResult {
    let fixture = Fixture::new()?;
    let mut reordered = commitment_limit_values();
    reordered.swap(0, 1);
    let mut out_of_range = commitment_limit_values();
    out_of_range[0] = Value::Array(vec![integer(257), integer(2_000)]);
    let mut invalid_value = commitment_limit_values();
    invalid_value[0] = Value::Array(vec![integer(0), Value::Null]);
    let mut invalid_limit_shape = commitment_limit_values();
    invalid_limit_shape[0] = Value::Null;
    let mut invalid_limit_identifier = commitment_limit_values();
    invalid_limit_identifier[0] = Value::Array(vec![Value::Null, integer(2_000)]);
    let malformed_records = vec![
        Vec::new(),
        vec![0; 1_025],
        vec![0xff],
        encode(&Value::Null)?,
        encode(&Value::Array(vec![
            Value::Null,
            integer(1),
            Value::Array(commitment_limit_values()),
        ]))?,
        encode(&Value::Array(vec![
            Value::Text("other".to_owned()),
            integer(1),
            Value::Array(commitment_limit_values()),
        ]))?,
        encode(&Value::Array(vec![
            Value::Text("BHC1".to_owned()),
            integer(2),
            Value::Array(commitment_limit_values()),
        ]))?,
        encode(&Value::Array(vec![
            Value::Text("BHC1".to_owned()),
            Value::Text("one".to_owned()),
            Value::Array(commitment_limit_values()),
        ]))?,
        broker_hard_caps_record(Value::Null)?,
        broker_hard_caps_record(Value::Array(vec![]))?,
        broker_hard_caps_with_limits(reordered)?,
        broker_hard_caps_with_limits(out_of_range)?,
        broker_hard_caps_with_limits(invalid_value)?,
        broker_hard_caps_with_limits(invalid_limit_shape)?,
        broker_hard_caps_with_limits(invalid_limit_identifier)?,
    ];

    for broker_hard_caps in malformed_records {
        assert!(matches!(
            fixture.admit_with_broker_hard_caps(&broker_hard_caps),
            Err(SandboxAdmissionError::Protocol(_))
        ));
    }
    Ok(())
}

#[test]
fn selector_commitment_rejects_invalid_evaluation_bindings() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let evaluation = fixture.evaluation_request(&launch)?;
    let attempt = selector_attempt();

    let mut invalid_evaluation = evaluation.clone();
    invalid_evaluation.execution_profile_digest = [0; 32];
    assert_eq!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &invalid_evaluation,
            &attempt,
            &[]
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let mut missing_requirement = evaluation.clone();
    missing_requirement.sandbox_requirement = None;
    refresh_evaluation_request(&mut missing_requirement)?;
    assert_eq!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &missing_requirement,
            &attempt,
            &[],
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    Ok(())
}

#[test]
fn selector_commitment_rejects_invalid_requirement_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let evaluation = fixture.evaluation_request(&launch)?;
    let attempt = selector_attempt();

    for replacement in [[45; 32], [46; 32], [47; 32]] {
        let mut mismatch = evaluation.clone();
        let Some(requirement) = mismatch.sandbox_requirement.as_mut() else {
            return Err("sandbox requirement missing".into());
        };
        match replacement[0] {
            45 => requirement.lps1_digest = replacement,
            46 => requirement.sim1_digest = replacement,
            47 => requirement.apt1_digest = replacement,
            _ => return Err("unknown selector authority field".into()),
        }
        refresh_evaluation_request(&mut mismatch)?;
        assert_eq!(
            admitted.derive_selector_grant_commitment(&image, &launch, &mismatch, &attempt, &[]),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }

    let mut epoch_mismatch = evaluation.clone();
    let Some(requirement) = epoch_mismatch.sandbox_requirement.as_mut() else {
        return Err("sandbox requirement missing".into());
    };
    requirement.policy_epoch += 1;
    refresh_evaluation_request(&mut epoch_mismatch)?;
    assert_eq!(
        admitted.derive_selector_grant_commitment(&image, &launch, &epoch_mismatch, &attempt, &[]),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    Ok(())
}

#[test]
fn selector_commitment_rejects_invalid_attempt_bindings() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let evaluation = fixture.evaluation_request(&launch)?;
    let attempt = selector_attempt();

    let mut mode_mismatch = attempt.clone();
    mode_mismatch.mode = 0;
    assert_eq!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &mode_mismatch,
            &[]
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let mut missing_fixture = attempt.clone();
    missing_fixture.fixture_digest = [0; 32];
    assert_eq!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &missing_fixture,
            &[]
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let mut missing_capability = attempt.clone();
    missing_capability.capability_ids.clear();
    assert_eq!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &missing_capability,
            &[],
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let mut unsupported_requirement = evaluation.clone();
    let Some(requirement) = unsupported_requirement.sandbox_requirement.as_mut() else {
        return Err("sandbox requirement missing".into());
    };
    requirement.required_provider_capability.capability_id = "missing".to_owned();
    refresh_evaluation_request(&mut unsupported_requirement)?;
    let mut unsupported_capability = attempt.clone();
    unsupported_capability.capability_ids = vec!["missing".to_owned()];
    assert_eq!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &unsupported_requirement,
            &unsupported_capability,
            &[],
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    Ok(())
}

#[test]
fn selector_commitment_rejects_invalid_network_plans_and_limits() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let evaluation = fixture.evaluation_request(&launch)?;
    let attempt = selector_attempt();

    let valid_plan = network_exchange_plan()?;
    let too_many_plans = vec![valid_plan.clone(); 257];
    assert!(matches!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &attempt,
            &too_many_plans,
        ),
        Err(SandboxAdmissionError::Protocol(_))
    ));
    let mut invalid_plan = valid_plan.clone();
    invalid_plan.plan_digest = [0; 32];
    assert!(matches!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &attempt,
            &[invalid_plan],
        ),
        Err(SandboxAdmissionError::Protocol(_))
    ));
    assert!(admitted
        .derive_selector_grant_commitment(&image, &launch, &evaluation, &attempt, &[valid_plan])
        .is_ok());

    let mut incomplete_launch = launch.clone();
    incomplete_launch.effective_limits.pop();
    assert!(matches!(
        admitted.derive_selector_grant_commitment(
            &image,
            &incomplete_launch,
            &evaluation,
            &attempt,
            &[],
        ),
        Err(SandboxAdmissionError::Protocol(_))
    ));
    let mut unordered_launch = launch.clone();
    unordered_launch.effective_limits.swap(0, 1);
    assert!(matches!(
        admitted.derive_selector_grant_commitment(
            &image,
            &unordered_launch,
            &evaluation,
            &attempt,
            &[],
        ),
        Err(SandboxAdmissionError::Protocol(_))
    ));
    let mut no_watchdog_launch = launch;
    no_watchdog_launch.effective_limits[4].value = 0;
    assert!(matches!(
        admitted.derive_selector_grant_commitment(
            &image,
            &no_watchdog_launch,
            &evaluation,
            &attempt,
            &[],
        ),
        Err(SandboxAdmissionError::Protocol(_))
    ));
    Ok(())
}

#[test]
fn selector_commitment_covers_each_execution_mode_and_concurrent_attempt_bound() -> TestResult {
    let fixture = Fixture::new()?;
    let sim1_digest = wrapped_digest(&fixture.sim1)?;
    let mut readback_digests = Vec::new();

    for mode in 0..4 {
        let launch_bytes = launch_policy_with_limits(sim1_digest, mode, commitment_limit_values())?;
        let policy =
            fixture.policy_for_commitment_artifacts(&fixture.broker_hard_caps, &launch_bytes)?;
        let inputs = SandboxProviderAdmissionInputs {
            broker_hard_caps: &fixture.broker_hard_caps,
            ..fixture.inputs()
        };
        let admitted =
            AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs)?;
        let image =
            admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
        let launch = admitted.admit_launch_policy(&launch_bytes, &image)?;
        let mut evaluation = fixture.evaluation_request(&launch)?;
        let Some(requirement) = evaluation.sandbox_requirement.as_mut() else {
            return Err("sandbox requirement missing".into());
        };
        requirement.apt1_digest = policy.policy_digest();
        requirement.policy_epoch = policy.policy_epoch();
        refresh_evaluation_request(&mut evaluation)?;
        let mut attempt = selector_attempt();
        attempt.mode = u8::try_from(mode)?;
        let commitment = admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &attempt,
            &[],
        )?;
        readback_digests.push(commitment.expected_readback_set_digest());
    }
    readback_digests.sort_unstable();
    readback_digests.dedup();
    assert_eq!(readback_digests.len(), 4);

    let high_limits = commitment_limit_values_with_concurrency(257);
    let broker_hard_caps = broker_hard_caps_with_limits(high_limits.clone())?;
    let launch_bytes = launch_policy_with_limits(sim1_digest, 1, high_limits)?;
    let policy = fixture.policy_for_commitment_artifacts(&broker_hard_caps, &launch_bytes)?;
    let inputs = SandboxProviderAdmissionInputs {
        broker_hard_caps: &broker_hard_caps,
        ..fixture.inputs()
    };
    let admitted =
        AdmittedSandboxProvider::admit(&policy, &fixture.trust, &fixture.revocation, inputs)?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&launch_bytes, &image)?;
    let mut evaluation = fixture.evaluation_request(&launch)?;
    let Some(requirement) = evaluation.sandbox_requirement.as_mut() else {
        return Err("sandbox requirement missing".into());
    };
    requirement.apt1_digest = policy.policy_digest();
    requirement.policy_epoch = policy.policy_epoch();
    refresh_evaluation_request(&mut evaluation)?;
    assert!(matches!(
        admitted.derive_selector_grant_commitment(
            &image,
            &launch,
            &evaluation,
            &selector_attempt(),
            &[],
        ),
        Err(SandboxAdmissionError::Protocol(_))
    ));
    Ok(())
}

#[test]
fn admission_grant_rejects_a_foreign_selector_commitment() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let commitment = fixture.selector_grant_commitment(&admitted, &image, &launch, &request)?;
    let grant = admission_grant(&fixture, &request, &launch, &commitment)?;

    let foreign_launch = LaunchPolicy {
        policy_digest: [99; 32],
        ..launch.clone()
    };
    assert_eq!(
        admitted.authenticate_grant(&grant, &request, &image, &foreign_launch, &commitment),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let mut foreign_evaluation = fixture.evaluation_request(&launch)?;
    foreign_evaluation.execution_profile_digest = [99; 32];
    foreign_evaluation.output_capability.capability_digest =
        foreign_evaluation.expected_output_capability_digest()?;
    foreign_evaluation.request_digest = foreign_evaluation.digest()?;
    let foreign_commitment = admitted.derive_selector_grant_commitment(
        &image,
        &launch,
        &foreign_evaluation,
        &selector_attempt(),
        &request.network_plans,
    )?;

    assert_eq!(
        admitted.authenticate_grant(&grant, &request, &image, &launch, &foreign_commitment),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let unsupported_request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute", "missing"],
    )?)?;
    let mut unsupported_attempt = selector_attempt();
    unsupported_attempt.capability_ids = vec!["execute".to_owned(), "missing".to_owned()];
    let unsupported_evaluation = fixture.evaluation_request(&launch)?;
    let unsupported_commitment = admitted.derive_selector_grant_commitment(
        &image,
        &launch,
        &unsupported_evaluation,
        &unsupported_attempt,
        &unsupported_request.network_plans,
    )?;
    let unsupported_grant = admission_grant(
        &fixture,
        &unsupported_request,
        &launch,
        &unsupported_commitment,
    )?;
    assert_eq!(
        admitted.authenticate_grant(
            &unsupported_grant,
            &unsupported_request,
            &image,
            &launch,
            &unsupported_commitment,
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn lifecycle_authentication_rejects_each_identity_and_chain_substitution() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant_bytes = fixture.admission_grant(&admitted, &image, &launch, &request)?;

    for (field, replacement) in [
        (20, bytes([99; 32])),
        (21, bytes([99; 32])),
        (24, bytes([99; 32])),
        (25, Value::Text("other-runtime".to_owned())),
    ] {
        let changed = resign_unsigned_field(
            &grant_bytes,
            "AGR1",
            field,
            replacement,
            &fixture.authority.runtime,
        )?;
        assert_eq!(
            fixture.authenticate_grant(&admitted, &changed, &request, &image, &launch),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }

    let grant = fixture.authenticate_grant(&admitted, &grant_bytes, &request, &image, &launch)?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt_bytes = provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?;
    for (field, replacement) in [
        (14, bytes([99; 32])),
        (24, Value::Text("other-runtime".to_owned())),
    ] {
        let changed = resign_unsigned_field(
            &receipt_bytes,
            "SPR1",
            field,
            replacement,
            &fixture.authority.runtime,
        )?;
        assert_eq!(
            admitted.authenticate_receipt(&changed, &grant),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }

    let receipt = admitted.authenticate_receipt(&receipt_bytes, &grant)?;
    let result_bytes = terminal_result(&fixture, &request, &grant, &receipt)?;
    for replacements in [
        vec![(2, Value::Bytes(vec![77; 16]))],
        vec![(9, Value::Text("other-runtime".to_owned()))],
        vec![
            (4, integer(2)),
            (5, Value::Null),
            (6, Value::Null),
            (7, Value::Null),
            (8, Value::Array(Vec::new())),
        ],
    ] {
        let changed = resign_unsigned_fields(
            &result_bytes,
            "SPY1",
            &replacements,
            &fixture.authority.runtime,
        )?;
        assert_eq!(
            admitted.authenticate_terminal_result(&changed, &request, &grant, &receipt),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }

    let result =
        admitted.authenticate_terminal_result(&result_bytes, &request, &grant, &receipt)?;
    assert!(admitted
        .authenticate_audit_chain(&[], &receipt, &result)
        .is_err());

    let changed_second =
        resign_unsigned_field(&audit[1], "SAU1", 3, integer(2), &fixture.authority.runtime)?;
    assert!(admitted
        .authenticate_audit_chain(&[audit[0].clone(), changed_second], &receipt, &result)
        .is_err());

    let changed_authority = resign_unsigned_field(
        &audit[1],
        "SAU1",
        5,
        Value::Array(vec![bytes([99; 32])]),
        &fixture.authority.runtime,
    )?;
    assert!(admitted
        .authenticate_audit_chain(&[audit[0].clone(), changed_authority], &receipt, &result)
        .is_err());
    Ok(())
}

#[test]
fn lifecycle_authentication_rejects_each_forged_signature() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant_bytes = fixture.admission_grant(&admitted, &image, &launch, &request)?;
    assert!(fixture
        .authenticate_grant(
            &admitted,
            &replace_signed_signature(&grant_bytes, [9; 64])?,
            &request,
            &image,
            &launch,
        )
        .is_err());
    let grant = fixture.authenticate_grant(&admitted, &grant_bytes, &request, &image, &launch)?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt_bytes = provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?;
    assert!(admitted
        .authenticate_receipt(&replace_signed_signature(&receipt_bytes, [9; 64])?, &grant)
        .is_err());
    let receipt = admitted.authenticate_receipt(&receipt_bytes, &grant)?;
    let result_bytes = terminal_result(&fixture, &request, &grant, &receipt)?;
    assert!(admitted
        .authenticate_terminal_result(
            &replace_signed_signature(&result_bytes, [9; 64])?,
            &request,
            &grant,
            &receipt,
        )
        .is_err());
    let result =
        admitted.authenticate_terminal_result(&result_bytes, &request, &grant, &receipt)?;

    let mut forged_audit = audit;
    forged_audit[0] = replace_signed_signature(&forged_audit[0], [9; 64])?;
    assert!(admitted
        .authenticate_audit_chain(&forged_audit, &receipt, &result)
        .is_err());
    Ok(())
}

#[test]
fn audit_record_rejects_every_malformed_wire_field() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = fixture.authenticate_grant(
        &admitted,
        &fixture.admission_grant(&admitted, &image, &launch, &request)?,
        &request,
        &image,
        &launch,
    )?;
    let record = audit_record(&fixture, &grant, 0, 11, None)?;
    assert!(SandboxAuditRecord::from_canonical_cbor(b"not-cbor").is_err());
    assert!(SandboxAuditRecord::from_canonical_cbor(&encode(&Value::Null)?).is_err());
    for field in 2..=7 {
        let replacement = if field == 6 {
            Value::Bool(true)
        } else {
            Value::Null
        };
        let changed = resign_unsigned_field(
            &record,
            "SAU1",
            field,
            replacement,
            &fixture.authority.runtime,
        )?;
        assert!(SandboxAuditRecord::from_canonical_cbor(&changed).is_err());
    }
    for (field, replacement) in [(4, integer(256)), (5, Value::Array(vec![Value::Null]))] {
        let changed = resign_unsigned_field(
            &record,
            "SAU1",
            field,
            replacement,
            &fixture.authority.runtime,
        )?;
        assert!(SandboxAuditRecord::from_canonical_cbor(&changed).is_err());
    }
    assert!(SandboxAuditRecord::from_canonical_cbor(&corrupt_signed_digest(&record)?).is_err());
    Ok(())
}
