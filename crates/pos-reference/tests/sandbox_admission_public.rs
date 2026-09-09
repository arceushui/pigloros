//! Public selector-owned provider and image admission tests.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::adapter_transport::{write_attempt, write_observation};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectObservation,
    SubjectResult,
};
use pos_reference::evaluator_protocol::{
    EvaluationRequest, ImplementationIdentity, OutputCapability, RequiredProviderCapability,
    SandboxRequirement, SubjectAdapterKind,
};
use pos_reference::profile::DeterministicBudget;
use pos_reference::provider_transport::{ProviderConnector, ProviderTransport, StagedOutput};
use pos_reference::root_selector::{
    RootSelectorAdmissionArtifacts, RootSelectorAuthoritySource, RootSelectorCasePlan,
    RootSelectorProvider, RootSelectorProviderReply, RootSelectorServer, RootSelectorServiceError,
};
use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AdmittedSandboxImage, AdmittedSandboxProvider, ExecuteAuthority,
    HostCapabilityProfile, LaunchPolicy, NetworkExchangePlan, PayloadDescriptor,
    ProviderConformanceReport, RootSelectorAdmission, RootSelectorAdmissionInputs,
    SandboxAdministratorPolicy, SandboxAdmissionError, SandboxArchitecture, SandboxAuditRecord,
    SandboxExecuteRequest, SandboxGrantExpectations, SandboxLocalError, SandboxLocalErrorCode,
    SandboxLocalErrorPhase, SandboxProviderAdmissionInputs, SandboxProviderOperation,
    SandboxProviderProtocolError, SandboxProviderReceipt, SandboxRevocationSnapshot,
    SandboxTerminalOutcome, SandboxTrustSnapshot,
};
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SelectorExercise = (Result<(), RootSelectorServiceError>, Vec<u8>, Vec<u8>);

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

fn required_feature_ids() -> Vec<String> {
    let mut values = [
        "cgroup-v2-cpu",
        "cgroup-v2-memory",
        "cgroup-v2-pids",
        "cgroup-kill",
        "managed-attempt-exec",
        "process-isolation-controls",
        "signed-root-image",
        "mount-namespace",
        "pid-namespace",
        "ipc-namespace",
        "uts-namespace",
        "user-namespace",
        "network-namespace",
        "nftables-atomic",
        "broker-lifecycle",
        "limit-observation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    values.sort_unstable();
    values
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
    failed_feature: Option<&str>,
    architecture: u64,
) -> TestResult<Vec<u8>> {
    let feature_proofs = ordered(
        required_feature_ids()
            .into_iter()
            .map(|feature| {
                let passed = u64::from(failed_feature != Some(feature.as_str()));
                Value::Array(vec![Value::Text(feature), integer(passed), bytes([18; 32])])
            })
            .collect(),
    )?;
    sign_record(
        "HCP1",
        Value::Array(vec![
            Value::Text("HCP1".to_owned()),
            integer(1),
            integer(architecture),
            Value::Text("6.12.0".to_owned()),
            Value::Array(feature_proofs),
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
    self_digested_record(
        "LPS1",
        Value::Array(vec![
            Value::Text("LPS1".to_owned()),
            integer(1),
            Value::Text("air-gapped".to_owned()),
            integer(1),
            bytes(sim1_digest),
            Value::Array(
                (0..=16)
                    .map(|limit_id| Value::Array(vec![integer(limit_id), integer(1)]))
                    .collect(),
            ),
            Value::Array(vec![]),
        ]),
    )
}

fn payload_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn staged_output(bytes: &[u8]) -> TestResult<StagedOutput> {
    let mut reader = bytes;
    Ok(StagedOutput::stage_verified(
        &mut reader,
        PayloadDescriptor {
            byte_length: bytes.len() as u64,
            digest: payload_digest(b"PiglorOS.SandboxOutputBytes.v1\0", bytes),
        },
    )?)
}

struct PairConnector(Vec<UnixStream>);

impl ProviderConnector for PairConnector {
    fn connect(&mut self) -> Result<UnixStream, RootSelectorServiceError> {
        self.0
            .pop()
            .ok_or(RootSelectorServiceError::ProviderUnavailable)
    }
}

fn provider_frame(stream: &mut UnixStream, record: &[u8]) -> TestResult {
    stream.write_all(&u32::try_from(record.len())?.to_be_bytes())?;
    stream.write_all(record)?;
    Ok(())
}

fn transport_admission(fixture: &Fixture) -> TestResult<RootSelectorAdmission> {
    Ok(RootSelectorAdmission::establish(
        &fixture.policy,
        &fixture.trust,
        &fixture.revocation,
        RootSelectorAdmissionInputs {
            provider: fixture.inputs(),
            image_manifest: &fixture.sim1,
            root_image: &fixture.root_image,
            executable: &fixture.executable,
            subject_artifact_digest: fixture.subject_digest(),
            launch_policy: &fixture.lps1,
            grant_expectations: Fixture::grant_expectations(),
        },
    )?)
}

fn transport_request(
    fixture: &Fixture,
    admission: &RootSelectorAdmission,
) -> TestResult<SandboxExecuteRequest> {
    Ok(SandboxExecuteRequest::from_canonical_cbor(
        &execute_request(fixture, admission.launch_policy(), &["execute"])?,
    )?)
}

fn provider_chunk(request: &SandboxExecuteRequest, parent: [u8; 32]) -> TestResult<Vec<u8>> {
    self_digested_record(
        "SBC1",
        Value::Array(vec![
            Value::Text("SBC1".to_owned()),
            integer(1),
            bytes(parent),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            integer(1),
            integer(0),
            integer(0),
            Value::Bytes(b"output".to_vec()),
        ]),
    )
}

#[test]
fn provider_transport_accepts_complete_framed_transcript_and_stages_output() -> TestResult {
    let fixture = Fixture::new()?;
    let admission = transport_admission(&fixture)?;
    let request = transport_request(&fixture, &admission)?;
    let grant = admission_grant(&fixture, &request, admission.launch_policy())?;
    let grant_record = AdmissionGrant::from_canonical_cbor(&grant)?;
    let audit = audit_chain(&fixture, &grant_record)?;
    let receipt = provider_receipt(
        &fixture,
        &grant_record,
        wrapped_digest(audit.last().ok_or("audit")?)?,
    )?;
    let receipt_record = SandboxProviderReceipt::from_canonical_cbor(&receipt)?;
    let result = terminal_result_with_output(
        &fixture,
        &request,
        &grant_record,
        &receipt_record,
        b"output",
    )?;
    let result_record =
        pos_reference::sandbox_provider_protocol::SandboxProviderResult::from_canonical_cbor(
            &result,
        )?;
    let (client, mut peer) = UnixStream::pair()?;
    let request_for_provider = request.clone();
    let server = thread::spawn(move || -> TestResult {
        let mut input = Vec::new();
        peer.read_to_end(&mut input)?;
        for record in [
            grant,
            audit[0].clone(),
            audit[1].clone(),
            receipt,
            provider_chunk(&request_for_provider, result_record.result_digest)?,
            result,
        ] {
            provider_frame(&mut peer, &record)?;
        }
        Ok(())
    });
    let mut transport = ProviderTransport::with_connector(PairConnector(vec![client]));
    let reply = transport.execute(&request, b"input", Duration::from_secs(1), &admission)?;
    server.join().map_err(|_| "provider panicked")??;
    let RootSelectorProviderReply::Admitted { mut output, .. } = reply else {
        return Err("expected admitted stream".into());
    };
    let mut bytes = Vec::new();
    output
        .as_mut()
        .ok_or("missing output")?
        .copy_to(&mut bytes)?;
    assert_eq!(bytes, b"output");
    Ok(())
}

fn execute_request(
    fixture: &Fixture,
    launch: &LaunchPolicy,
    capability_ids: &[&str],
) -> TestResult<Vec<u8>> {
    let input = b"input";
    self_digested_record(
        "SPX1",
        Value::Array(vec![
            Value::Text("SPX1".to_owned()),
            integer(1),
            Value::Array(vec![
                Value::Bytes(vec![31; 16]),
                bytes(fixture.policy.policy_digest()),
                integer(fixture.policy.policy_epoch()),
                Value::Bytes(vec![32; 16]),
            ]),
            Value::Bytes(vec![33; 16]),
            bytes([34; 32]),
            bytes([35; 32]),
            bytes([36; 32]),
            bytes([37; 32]),
            bytes([38; 32]),
            bytes([39; 32]),
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
            bytes([39; 32]),
            bytes(request.adapter_input.digest),
            Value::Array(vec![]),
            bytes(launch.policy_digest),
            bytes([40; 32]),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
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

fn terminal_result_with_output(
    fixture: &Fixture,
    request: &SandboxExecuteRequest,
    grant: &AdmissionGrant,
    receipt: &SandboxProviderReceipt,
    output: &[u8],
) -> TestResult<Vec<u8>> {
    sign_record(
        "SPY1",
        Value::Array(vec![
            Value::Text("SPY1".to_owned()),
            integer(1),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            integer(0),
            Value::Array(vec![
                integer(u64::try_from(output.len())?),
                bytes(payload_digest(b"PiglorOS.SandboxOutputBytes.v1\0", output)),
            ]),
            bytes(grant.grant_digest),
            bytes(receipt.receipt_digest),
            Value::Array(vec![integer(11), integer(12)]),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
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
        let required_features = required_feature_ids();
        let feature_digest = feature_set_digest(&required_features)?;
        let provider_binary = b"exact provider binary".to_vec();
        let broker_hard_caps = b"broker hard caps".to_vec();
        let binary_digest = *blake3::hash(&provider_binary).as_bytes();
        let provider_record = provider_manifest(&authority, binary_digest, feature_digest)?;
        let scs1 = syscall_set(0)?;
        let hcp1 = host_profile(&authority, None, 0)?;
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
            provider_binary: &self.provider_binary,
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

    fn subject_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.executable).as_bytes()
    }

    fn grant_expectations() -> SandboxGrantExpectations {
        SandboxGrantExpectations {
            required_provider_capability: RequiredProviderCapability {
                capability_id: "execute".to_owned(),
                capability_version: 1,
                minimum_strength: 1,
            },
            effective_limits_digest: [39; 32],
            expected_readback_set_digest: [40; 32],
        }
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
}

#[derive(Clone)]
struct FixedSelectorAuthority {
    plan: RootSelectorCasePlan,
}

struct FailingSelectorAuthority(RootSelectorServiceError);

impl RootSelectorAuthoritySource for FailingSelectorAuthority {
    fn resolve_case(
        &mut self,
        _: &EvaluationRequest,
        _: u16,
    ) -> Result<RootSelectorCasePlan, RootSelectorServiceError> {
        Err(self.0)
    }
}

#[derive(Clone, Copy)]
enum SelectorProviderMode {
    Valid,
    Unavailable,
    EvidenceFailure,
    BeforeAdmission,
    Error,
    InvalidBeforeAdmission,
    InvalidError,
    InvalidGrant,
    InvalidReceipt,
    MismatchedOutput,
    MissingOutput,
    MismatchedOutputDigest,
}

struct ScenarioSelectorProvider {
    signed: SignedSelectorProvider,
    mode: SelectorProviderMode,
}

impl RootSelectorProvider for ScenarioSelectorProvider {
    fn execute(
        &mut self,
        request: &SandboxExecuteRequest,
        _: &[u8],
        _: Duration,
        _: &RootSelectorAdmission,
    ) -> Result<RootSelectorProviderReply, RootSelectorServiceError> {
        if matches!(self.mode, SelectorProviderMode::Unavailable) {
            return Err(RootSelectorServiceError::ProviderUnavailable);
        }
        if matches!(self.mode, SelectorProviderMode::EvidenceFailure) {
            return Err(RootSelectorServiceError::ProviderEvidence);
        }
        if matches!(self.mode, SelectorProviderMode::InvalidBeforeAdmission) {
            return Ok(RootSelectorProviderReply::BeforeAdmission {
                result: b"not-cbor".to_vec(),
            });
        }
        if matches!(self.mode, SelectorProviderMode::InvalidError) {
            return Ok(RootSelectorProviderReply::Error {
                error: b"not-cbor".to_vec(),
            });
        }
        if matches!(self.mode, SelectorProviderMode::BeforeAdmission) {
            return Ok(RootSelectorProviderReply::BeforeAdmission {
                result: pre_admission_result(&self.signed.fixture, request)
                    .map_err(|_| RootSelectorServiceError::ProviderEvidence)?,
            });
        }
        if matches!(self.mode, SelectorProviderMode::Error) {
            return Ok(RootSelectorProviderReply::Error {
                error: provider_execute_error(&self.signed.fixture, request)
                    .map_err(|_| RootSelectorServiceError::ProviderEvidence)?,
            });
        }
        let mut reply = self
            .signed
            .reply(request)
            .map_err(|_| RootSelectorServiceError::ProviderEvidence)?;
        if let RootSelectorProviderReply::Admitted {
            grant,
            receipt,
            output,
            ..
        } = &mut reply
        {
            match self.mode {
                SelectorProviderMode::InvalidGrant => *grant = b"not-cbor".to_vec(),
                SelectorProviderMode::InvalidReceipt => *receipt = b"not-cbor".to_vec(),
                SelectorProviderMode::MismatchedOutput => {
                    *output = Some(staged_output(b"substituted")?);
                }
                SelectorProviderMode::MissingOutput => *output = None,
                SelectorProviderMode::MismatchedOutputDigest => {
                    let length = output
                        .as_ref()
                        .ok_or("output must exist")?
                        .descriptor()
                        .byte_length;
                    *output = Some(staged_output(&vec![0; length as usize])?);
                }
                SelectorProviderMode::Valid
                | SelectorProviderMode::Unavailable
                | SelectorProviderMode::EvidenceFailure
                | SelectorProviderMode::BeforeAdmission
                | SelectorProviderMode::InvalidBeforeAdmission
                | SelectorProviderMode::InvalidError
                | SelectorProviderMode::Error => {}
            }
        }
        Ok(reply)
    }
}

impl RootSelectorAuthoritySource for FixedSelectorAuthority {
    fn resolve_case(
        &mut self,
        _: &EvaluationRequest,
        _: u16,
    ) -> Result<RootSelectorCasePlan, RootSelectorServiceError> {
        Ok(self.plan.clone())
    }
}

struct SignedSelectorProvider {
    fixture: Fixture,
    launch: LaunchPolicy,
}

impl RootSelectorProvider for SignedSelectorProvider {
    fn execute(
        &mut self,
        request: &SandboxExecuteRequest,
        _: &[u8],
        _: Duration,
        _: &RootSelectorAdmission,
    ) -> Result<RootSelectorProviderReply, RootSelectorServiceError> {
        self.reply(request)
            .map_err(|_| RootSelectorServiceError::ProviderEvidence)
    }
}

impl SignedSelectorProvider {
    fn reply(&self, request: &SandboxExecuteRequest) -> TestResult<RootSelectorProviderReply> {
        let mut output_stream = Vec::new();
        write_observation(
            &mut output_stream,
            &SubjectObservation {
                result: SubjectResult::Output(b"selected".to_vec()),
                usage: ResourceUsage::default(),
            },
        )?;
        let grant = admission_grant(&self.fixture, request, &self.launch)?;
        let grant_record = AdmissionGrant::from_canonical_cbor(&grant)?;
        let audit = audit_chain(&self.fixture, &grant_record)?;
        let receipt = provider_receipt(&self.fixture, &grant_record, wrapped_digest(&audit[1])?)?;
        let receipt_record = SandboxProviderReceipt::from_canonical_cbor(&receipt)?;
        let result = terminal_result_with_output(
            &self.fixture,
            request,
            &grant_record,
            &receipt_record,
            &output_stream,
        )?;
        Ok(RootSelectorProviderReply::Admitted {
            grant,
            receipt,
            result,
            audit,
            output: Some(staged_output(&output_stream)?),
        })
    }
}

struct NonCompletedSelectorProvider {
    signed: SignedSelectorProvider,
    outcome: u64,
    unexpected_output: bool,
}

impl NonCompletedSelectorProvider {
    fn reply(&self, request: &SandboxExecuteRequest) -> TestResult<RootSelectorProviderReply> {
        let fixture = &self.signed.fixture;
        let grant = admission_grant(fixture, request, &self.signed.launch)?;
        let grant_record = AdmissionGrant::from_canonical_cbor(&grant)?;
        let (events, ready): (&[u8], _) = if self.outcome == 1 {
            (&[11, 13, 1], Some([41; 32]))
        } else {
            (&[0], None)
        };
        let audit = audit_chain_for_events(fixture, &grant_record, events)?;
        let receipt = provider_receipt_for_lifecycle(
            fixture,
            &grant_record,
            wrapped_digest(audit.last().ok_or("audit chain must not be empty")?)?,
            ready,
            None,
        )?;
        let receipt_record = SandboxProviderReceipt::from_canonical_cbor(&receipt)?;
        let result = terminal_result_for_outcome(
            fixture,
            request,
            &grant_record,
            &receipt_record,
            self.outcome,
            events,
        )?;
        Ok(RootSelectorProviderReply::Admitted {
            grant,
            receipt,
            result,
            audit,
            output: self
                .unexpected_output
                .then(|| staged_output(b"unexpected"))
                .transpose()?,
        })
    }
}

impl RootSelectorProvider for NonCompletedSelectorProvider {
    fn execute(
        &mut self,
        request: &SandboxExecuteRequest,
        _: &[u8],
        _: Duration,
        _: &RootSelectorAdmission,
    ) -> Result<RootSelectorProviderReply, RootSelectorServiceError> {
        self.reply(request)
            .map_err(|_| RootSelectorServiceError::ProviderEvidence)
    }
}

fn pre_admission_result(fixture: &Fixture, request: &SandboxExecuteRequest) -> TestResult<Vec<u8>> {
    sign_record(
        "SPY1",
        Value::Array(vec![
            Value::Text("SPY1".to_owned()),
            integer(1),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            integer(3),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Array(Vec::new()),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
}

fn provider_execute_error(
    fixture: &Fixture,
    request: &SandboxExecuteRequest,
) -> TestResult<Vec<u8>> {
    sign_record(
        "SPE1",
        Value::Array(vec![
            Value::Text("SPE1".to_owned()),
            integer(1),
            integer(1),
            Value::Bytes(request.request.request_id.to_vec()),
            bytes(request.request_digest),
            Value::Bytes(request.attempt_id.to_vec()),
            integer(11),
            Value::Text("sandbox unavailable".to_owned()),
            Value::Text("runtime".to_owned()),
        ]),
        &fixture.authority.runtime,
    )
}

fn selector_evaluation_request(fixture: &Fixture) -> TestResult<EvaluationRequest> {
    let mut request = EvaluationRequest {
        request_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        profile_digest: [35; 32],
        fixture_bundle_digest: [36; 32],
        subject_adapter: SubjectAdapterKind::PublicPluginProtocol,
        subject_artifact_digest: fixture.subject_digest(),
        implementation: ImplementationIdentity {
            implementation_id: "subject".to_owned(),
            source_digest: [47; 32],
            build_digest: [48; 32],
            binary_digest: fixture.subject_digest(),
            public_contract_digest: [49; 32],
            organization_id: None,
        },
        execution_profile_digest: [38; 32],
        trust_policy_snapshot_digest: [50; 32],
        output_capability: OutputCapability {
            capability_digest: [1; 32],
            report_bytes_limit: 1024,
            diagnostic_bytes_limit: 0,
        },
        evaluator_protocol_digest: [51; 32],
        evaluator_hard_caps_digest: [52; 32],
        sandbox_requirement: Some(SandboxRequirement {
            lps1_digest: wrapped_digest(&fixture.lps1)?,
            sim1_digest: wrapped_digest(&fixture.sim1)?,
            required_provider_capability: Fixture::grant_expectations()
                .required_provider_capability,
            apt1_digest: fixture.policy.policy_digest(),
            policy_epoch: fixture.policy.policy_epoch(),
        }),
        request_digest: [1; 32],
    };
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request)
}

fn selector_case_attempt() -> CaseAttempt {
    let artifact = |contents: &[u8]| AttemptArtifact {
        digest: *blake3::hash(contents).as_bytes(),
        bytes: contents.to_vec(),
    };
    CaseAttempt {
        case_id: "sandbox-case".to_owned(),
        claim_layer: 1,
        family: 1,
        mode: 1,
        fixture_digest: [37; 32],
        schema: artifact(b"schema"),
        payload: artifact(b"payload"),
        auxiliary: Vec::new(),
        budget: DeterministicBudget {
            memory_bytes: 1,
            cpu_fuel: 1,
            host_calls: 1,
            event_count: 1,
            output_bytes: 1024,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
        },
        watchdog_ms: 1_000,
        network_allowed: false,
        capability_ids: vec!["execute".to_owned()],
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 1024,
            max_attempt_bytes: 128 * 1024 * 1024,
        },
    }
}

fn selector_case_plan(
    fixture: &Fixture,
    request: &EvaluationRequest,
    attempt: CaseAttempt,
) -> TestResult<RootSelectorCasePlan> {
    Ok(RootSelectorCasePlan {
        expected_attempt: attempt,
        execute_authority: ExecuteAuthority {
            evr1_digest: request.request_digest,
            cpf1_digest: request.profile_digest,
            cfb1_digest: request.fixture_bundle_digest,
            fixture_contract_digest: [53; 32],
            fixture_digest: [37; 32],
            execution_profile_digest: request.execution_profile_digest,
            lps1_digest: wrapped_digest(&fixture.lps1)?,
            sim1_digest: wrapped_digest(&fixture.sim1)?,
            apt1_digest: fixture.policy.policy_digest(),
            trs1_digest: fixture.trust.snapshot_digest(),
            rvs1_digest: fixture.revocation.snapshot_digest(),
            spm1_digest: wrapped_digest(&fixture.spm1)?,
            pcf1_digest: [17; 32],
            pcr1_digest: wrapped_digest(&fixture.pcr1)?,
            hcp1_digest: wrapped_digest(&fixture.hcp1)?,
        },
        network_plans: Vec::new(),
        request_nonce: [54; 16],
        admission: RootSelectorAdmissionArtifacts {
            policy: fixture.policy.clone(),
            trust: fixture.trust.clone(),
            revocation: fixture.revocation.clone(),
            provider_manifest: fixture.spm1.clone(),
            provider_binary: fixture.provider_binary.clone(),
            broker_hard_caps: fixture.broker_hard_caps.clone(),
            conformance_report: fixture.pcr1.clone(),
            host_profile: fixture.hcp1.clone(),
            syscall_set: fixture.scs1.clone(),
            required_features: fixture.required_features.clone(),
            image_manifest: fixture.sim1.clone(),
            root_image: fixture.root_image.clone(),
            executable: fixture.executable.clone(),
            launch_policy: fixture.lps1.clone(),
            grant_expectations: Fixture::grant_expectations(),
        },
    })
}

fn selector_client_request(
    request: &EvaluationRequest,
    attempt: &CaseAttempt,
    ordinal: u16,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut attempt_stream = Vec::new();
    write_attempt(&mut attempt_stream, attempt)?;
    let mut provider_request_id = request.request_id;
    provider_request_id[14..].copy_from_slice(&ordinal.to_be_bytes());
    let mut attempt_id = request.request_id;
    attempt_id[14..].copy_from_slice(&(ordinal ^ 0x8000).to_be_bytes());
    let input_digest = payload_digest(b"PiglorOS.SandboxInputBytes.v1\0", &attempt_stream);
    let unsigned = Value::Array(vec![
        Value::Text("SLX1".to_owned()),
        integer(1),
        Value::Bytes(provider_request_id.to_vec()),
        Value::Bytes(attempt_id.to_vec()),
        Value::Bytes(request.to_canonical_cbor()?),
        Value::Array(vec![
            integer(u64::try_from(attempt_stream.len())?),
            bytes(input_digest),
        ]),
    ]);
    let digest = digest_value(b"PiglorOS.SLX1.v1\0", &unsigned)?;
    Ok((
        encode(&Value::Array(vec![unsigned, bytes(digest)]))?,
        attempt_stream,
    ))
}

fn exercise_root_selector<A, P>(
    authority: A,
    provider: P,
    request: &EvaluationRequest,
    attempt: &CaseAttempt,
    evaluator_uid_offset: u32,
) -> TestResult<SelectorExercise>
where
    A: RootSelectorAuthoritySource + Send + 'static,
    P: RootSelectorProvider + Send + 'static,
{
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("root-selector.sock");
    let listener = UnixListener::bind(&socket)?;
    let evaluator_uid = std::fs::metadata(temporary.path())?
        .uid()
        .saturating_add(evaluator_uid_offset);
    let mut server =
        RootSelectorServer::new(authority, provider, evaluator_uid, Duration::from_secs(2));
    let server_thread = thread::spawn(move || server.serve_once(&listener));
    let (control, attempt_stream) = selector_client_request(request, attempt, 0)?;
    let mut client = UnixStream::connect(&socket)?;
    if evaluator_uid_offset == 0 {
        client.write_all(&u32::try_from(control.len())?.to_be_bytes())?;
        client.write_all(&control)?;
        client.write_all(&attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
    }
    let mut response = Vec::new();
    if let Err(error) = client.read_to_end(&mut response) {
        if error.kind() != std::io::ErrorKind::ConnectionReset {
            return Err(error.into());
        }
    }
    let server_result = server_thread
        .join()
        .map_err(|_| "root selector thread panicked")?;
    if response.len() < 4 {
        return Ok((server_result, Vec::new(), Vec::new()));
    }
    let prefix: [u8; 4] = response[..4].try_into()?;
    let control_length = usize::try_from(u32::from_be_bytes(prefix))?;
    let control_end = 4_usize
        .checked_add(control_length)
        .ok_or("selector response length overflow")?;
    if control_end > response.len() {
        return Err("selector response was truncated".into());
    }
    Ok((
        server_result,
        response[4..control_end].to_vec(),
        response[control_end..].to_vec(),
    ))
}

fn exercise_disconnected_selector<A: RootSelectorAuthoritySource, P: RootSelectorProvider>(
    authority: A,
    provider: P,
    request: &EvaluationRequest,
    attempt: &CaseAttempt,
) -> TestResult<Result<(), RootSelectorServiceError>> {
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("disconnected-selector.sock");
    let listener = UnixListener::bind(&socket)?;
    let evaluator_uid = std::fs::metadata(temporary.path())?.uid();
    let mut server =
        RootSelectorServer::new(authority, provider, evaluator_uid, Duration::from_secs(2));
    let (control, attempt_stream) = selector_client_request(request, attempt, 0)?;
    let mut client = UnixStream::connect(&socket)?;
    client.set_write_timeout(Some(Duration::from_secs(2)))?;
    client.write_all(&u32::try_from(control.len())?.to_be_bytes())?;
    client.write_all(&control)?;
    client.write_all(&attempt_stream)?;
    client.shutdown(std::net::Shutdown::Both)?;
    drop(client);
    // Accept only after the peer is gone: no race with the response writer.
    Ok(server.serve_once(&listener))
}

fn assert_unsupported_host_feature_rejected(fixture: &Fixture) -> TestResult {
    let unsupported_features = vec!["invented-feature".to_owned()];
    let unsupported_digest = feature_set_digest(&unsupported_features)?;
    let unsupported_spm1 = provider_manifest(
        &fixture.authority,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        unsupported_digest,
    )?;
    let unsupported_pcr1 = conformance_report(
        &fixture.authority,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        unsupported_digest,
        wrapped_digest(&fixture.hcp1)?,
        0,
    )?;
    let unsupported_policy = administrator_policy(
        &fixture.trust,
        &fixture.revocation,
        &fixture.authority,
        &PolicySelectionDigests {
            provider_manifest: wrapped_digest(&unsupported_spm1)?,
            provider_binary: *blake3::hash(&fixture.provider_binary).as_bytes(),
            broker_hard_caps: *blake3::hash(&fixture.broker_hard_caps).as_bytes(),
            conformance_report: wrapped_digest(&unsupported_pcr1)?,
            syscall_set: wrapped_digest(&fixture.scs1)?,
            launch_policy: wrapped_digest(&fixture.lps1)?,
            image_manifest: wrapped_digest(&fixture.sim1)?,
        },
    )?;
    assert_eq!(
        AdmittedSandboxProvider::admit(
            &unsupported_policy,
            &fixture.trust,
            &fixture.revocation,
            SandboxProviderAdmissionInputs {
                provider_manifest: &unsupported_spm1,
                conformance_report: &unsupported_pcr1,
                required_features: &unsupported_features,
                ..fixture.inputs()
            },
        ),
        Err(SandboxAdmissionError::HostCapabilityMismatch)
    );
    Ok(())
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
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    assert_eq!(image.manifest().executable_path, "/adapter");
    Ok(())
}

#[test]
fn provider_admission_rejects_unselected_bytes_and_failed_features() -> TestResult {
    let fixture = Fixture::new()?;
    let wrong_binary = SandboxProviderAdmissionInputs {
        provider_binary: b"changed",
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
    let failed_hcp1 = host_profile(&fixture.authority, Some("cgroup-v2-cpu"), 0)?;
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
        Err(SandboxAdmissionError::Protocol(
            SandboxProviderProtocolError::FieldOutOfBounds
        ))
    );

    assert_unsupported_host_feature_rejected(&fixture)?;
    Ok(())
}

#[test]
fn provider_admission_rejects_cross_record_architecture_mismatch() -> TestResult {
    let fixture = Fixture::new()?;
    let hcp1 = host_profile(&fixture.authority, None, 1)?;
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
        admitted.admit_image(
            &fixture.sim1,
            b"changed",
            &fixture.executable,
            fixture.subject_digest(),
        ),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    assert_eq!(
        admitted.admit_image(
            &fixture.sim1,
            &fixture.root_image,
            b"changed",
            fixture.subject_digest(),
        ),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    assert_eq!(
        admitted.admit_image(
            &fixture.sim1,
            &fixture.root_image,
            &fixture.executable,
            [99; 32],
        ),
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
            revoked_admission.admit_image(
                &fixture.sim1,
                &fixture.root_image,
                &fixture.executable,
                fixture.subject_digest(),
            ),
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
        admitted.admit_image(
            &unselected,
            b"other-image",
            &fixture.executable,
            fixture.subject_digest(),
        ),
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
            selected.admit_image(
                &changed,
                &fixture.root_image,
                &fixture.executable,
                fixture.subject_digest(),
            ),
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
        selected.admit_image(
            &unknown_key,
            &fixture.root_image,
            &fixture.executable,
            fixture.subject_digest(),
        ),
        Err(SandboxAdmissionError::Trust(_))
    ));
    Ok(())
}

#[test]
fn image_admission_rejects_provider_architecture_substitution() -> TestResult {
    let fixture = Fixture::new()?;
    let syscall_set = syscall_set(1)?;
    let host_profile = host_profile(&fixture.authority, None, 1)?;
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
        selected.admit_image(
            &fixture.sim1,
            &fixture.root_image,
            &fixture.executable,
            fixture.subject_digest(),
        ),
        Err(SandboxAdmissionError::ArchitectureMismatch)
    );
    Ok(())
}

#[test]
fn launch_and_execute_admission_reject_each_selected_authority_mismatch() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
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
    let image = selected.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    assert_eq!(
        selected.admit_launch_policy(&unselected_launch, &image),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );

    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request_bytes = execute_request(&fixture, &launch, &["execute"])?;
    let changed_request = redigest_unsigned_field(&request_bytes, "SPX1", 10, bytes([99; 32]))?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&changed_request)?;
    assert_eq!(
        admitted.authenticate_grant(
            &admission_grant(&fixture, &request, &launch)?,
            &request,
            &image,
            &launch,
            &Fixture::grant_expectations(),
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn host_profile_requires_the_closed_passing_feature_set() -> TestResult {
    let fixture = Fixture::new()?;
    let Value::Array(wrapper) = ciborium::from_reader(fixture.hcp1.as_slice())? else {
        return Err("HCP1 wrapper must be an array".into());
    };
    let Value::Array(unsigned) = &wrapper[0] else {
        return Err("HCP1 unsigned value must be an array".into());
    };
    let Value::Array(mut noncanonical_proofs) = unsigned[4].clone() else {
        return Err("HCP1 feature proofs must be an array".into());
    };
    noncanonical_proofs.reverse();
    let noncanonical = resign_unsigned_field(
        &fixture.hcp1,
        "HCP1",
        4,
        Value::Array(noncanonical_proofs),
        &fixture.authority.runtime,
    )?;
    assert!(HostCapabilityProfile::from_canonical_cbor(&noncanonical).is_err());

    for feature_id in ["invented-feature", "cgroup-v2-cpu"] {
        let incomplete = Value::Array(vec![Value::Array(vec![
            Value::Text(feature_id.to_owned()),
            integer(1),
            bytes([18; 32]),
        ])]);
        let changed = resign_unsigned_field(
            &fixture.hcp1,
            "HCP1",
            4,
            incomplete,
            &fixture.authority.runtime,
        )?;
        assert!(HostCapabilityProfile::from_canonical_cbor(&changed).is_err());
    }
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
    let selector = RootSelectorAdmission::establish(
        &fixture.policy,
        &fixture.trust,
        &fixture.revocation,
        RootSelectorAdmissionInputs {
            provider: fixture.inputs(),
            image_manifest: &fixture.sim1,
            root_image: &fixture.root_image,
            executable: &fixture.executable,
            subject_artifact_digest: fixture.subject_digest(),
            launch_policy: &fixture.lps1,
            grant_expectations: Fixture::grant_expectations(),
        },
    )?;
    assert_eq!(
        selector.revocation_state()?.current().snapshot_digest(),
        fixture.revocation.snapshot_digest()
    );
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        selector.launch_policy(),
        &["execute"],
    )?)?;
    let grant_bytes = admission_grant(&fixture, &request, selector.launch_policy())?;
    let grant = AdmissionGrant::from_canonical_cbor(&grant_bytes)?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt_bytes = provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?;
    let receipt = SandboxProviderReceipt::from_canonical_cbor(&receipt_bytes)?;
    let result_bytes = terminal_result(&fixture, &request, &grant, &receipt)?;
    let execution = selector.authenticate_execution(
        &request,
        &grant_bytes,
        &receipt_bytes,
        &result_bytes,
        &audit,
    )?;
    assert_eq!(execution.result().spr1_digest, Some(receipt.receipt_digest));
    assert_eq!(execution.result().attempt_id, request.attempt_id);
    assert_eq!(execution.receipt(), &receipt);
    assert_eq!(execution.grant(), &grant);
    assert_eq!(execution.provenance_digest(), receipt.receipt_digest);
    assert_eq!(execution.audit().len(), 2);

    let unsupported = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        selector.launch_policy(),
        &["unsupported"],
    )?)?;
    assert_eq!(
        selector.authenticate_execution(
            &unsupported,
            &admission_grant(&fixture, &unsupported, selector.launch_policy())?,
            &receipt_bytes,
            &result_bytes,
            &audit,
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}

#[test]
fn root_selector_server_wires_request_admission_provider_and_authenticated_reply() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let plan = selector_case_plan(&fixture, &request, attempt.clone())?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let provider = SignedSelectorProvider { fixture, launch };
    let authority = FixedSelectorAuthority { plan };
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("root-selector.sock");
    let listener = UnixListener::bind(&socket)?;
    let evaluator_uid = std::fs::metadata(temporary.path())?.uid();
    let mut server =
        RootSelectorServer::new(authority, provider, evaluator_uid, Duration::from_secs(2));
    let server_thread = thread::spawn(move || server.serve_once(&listener));

    let (control, attempt_stream) = selector_client_request(&request, &attempt, 0)?;
    let mut client = UnixStream::connect(&socket)?;
    client.write_all(&u32::try_from(control.len())?.to_be_bytes())?;
    client.write_all(&control)?;
    client.write_all(&attempt_stream)?;
    client.shutdown(std::net::Shutdown::Write)?;

    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix)?;
    let mut response_control = vec![0_u8; usize::try_from(u32::from_be_bytes(prefix))?];
    client.read_exact(&mut response_control)?;
    let mut output_stream = Vec::new();
    client.read_to_end(&mut output_stream)?;
    server_thread
        .join()
        .map_err(|_| "root selector thread panicked")??;

    let Value::Array(wrapper) = ciborium::from_reader(response_control.as_slice())? else {
        return Err("SLY1 wrapper must be an array".into());
    };
    let Value::Array(fields) = wrapper.first().ok_or("SLY1 prefix missing")? else {
        return Err("SLY1 prefix must be an array".into());
    };
    assert_eq!(fields.first(), Some(&Value::Text("SLY1".to_owned())));
    assert!(!output_stream.is_empty());
    Ok(())
}

fn exercise_selector_provider_mode(mode: SelectorProviderMode) -> TestResult<SelectorExercise> {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let plan = selector_case_plan(&fixture, &request, attempt.clone())?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    exercise_root_selector(
        FixedSelectorAuthority { plan },
        ScenarioSelectorProvider {
            signed: SignedSelectorProvider { fixture, launch },
            mode,
        },
        &request,
        &attempt,
        0,
    )
}

#[test]
fn root_selector_server_reports_provider_failure_phases_as_sle1() -> TestResult {
    for (mode, phase, code, has_grant) in [
        (
            SelectorProviderMode::InvalidBeforeAdmission,
            SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            false,
        ),
        (
            SelectorProviderMode::InvalidError,
            SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            false,
        ),
        (
            SelectorProviderMode::Unavailable,
            SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
            SandboxLocalErrorCode::ProviderUnavailable,
            false,
        ),
        (
            SelectorProviderMode::EvidenceFailure,
            SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            false,
        ),
        (
            SelectorProviderMode::InvalidGrant,
            SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            false,
        ),
        (
            SelectorProviderMode::InvalidReceipt,
            SandboxLocalErrorPhase::AfterAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            true,
        ),
        (
            SelectorProviderMode::MismatchedOutput,
            SandboxLocalErrorPhase::AfterAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            true,
        ),
        (
            SelectorProviderMode::MissingOutput,
            SandboxLocalErrorPhase::AfterAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            true,
        ),
        (
            SelectorProviderMode::MismatchedOutputDigest,
            SandboxLocalErrorPhase::AfterAdmission,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
            true,
        ),
    ] {
        let (server_result, control, trailing) = exercise_selector_provider_mode(mode)?;
        assert_eq!(server_result, Ok(()));
        assert!(trailing.is_empty());
        let local = SandboxLocalError::from_canonical_cbor(&control)?;
        assert_eq!(local.phase, phase);
        assert_eq!(local.code, code);
        assert_eq!(local.agr1_digest.is_some(), has_grant);
    }
    Ok(())
}

#[test]
fn root_selector_authenticates_noncompleted_outcomes_and_rejects_their_output() -> TestResult {
    for (outcome, unexpected_output) in [(1, false), (4, false), (1, true), (4, true)] {
        let fixture = Fixture::new()?;
        let request = selector_evaluation_request(&fixture)?;
        let attempt = selector_case_attempt();
        let plan = selector_case_plan(&fixture, &request, attempt.clone())?;
        let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
        let (server_result, control, trailing) = exercise_root_selector(
            FixedSelectorAuthority { plan },
            NonCompletedSelectorProvider {
                signed: SignedSelectorProvider { fixture, launch },
                outcome,
                unexpected_output,
            },
            &request,
            &attempt,
            0,
        )?;
        assert_eq!(server_result, Ok(()));
        assert!(trailing.is_empty());
        if unexpected_output {
            let local = SandboxLocalError::from_canonical_cbor(&control)?;
            assert_eq!(local.phase, SandboxLocalErrorPhase::AfterAdmission);
            assert_eq!(local.code, SandboxLocalErrorCode::ProviderEvidenceInvalid);
            assert!(local.agr1_digest.is_some());
            continue;
        }
        let Value::Array(wrapper) = ciborium::from_reader(control.as_slice())? else {
            return Err("SLY1 wrapper must be an array".into());
        };
        let Value::Array(fields) = wrapper.first().ok_or("SLY1 prefix missing")? else {
            return Err("SLY1 prefix must be an array".into());
        };
        assert_eq!(fields.first(), Some(&Value::Text("SLY1".to_owned())));
        assert_eq!(fields.get(11), Some(&Value::Null));
        let Some(Value::Bytes(terminal)) = fields.get(7) else {
            return Err("SLY1 terminal result missing".into());
        };
        let result =
            pos_reference::sandbox_provider_protocol::SandboxProviderResult::from_canonical_cbor(
                terminal,
            )?;
        let expected_outcome = if outcome == 1 {
            SandboxTerminalOutcome::Cancelled
        } else {
            SandboxTerminalOutcome::UnavailableAfterAdmission
        };
        assert_eq!(result.outcome, expected_outcome);
        assert!(result.output.is_none());
    }
    Ok(())
}

#[test]
fn root_selector_server_forwards_authenticated_pre_admission_records() -> TestResult {
    for mode in [
        SelectorProviderMode::BeforeAdmission,
        SelectorProviderMode::Error,
    ] {
        let (server_result, control, trailing) = exercise_selector_provider_mode(mode)?;
        assert_eq!(server_result, Ok(()));
        assert!(trailing.is_empty());
        let Value::Array(wrapper) = ciborium::from_reader(control.as_slice())? else {
            return Err("SLY1 wrapper must be an array".into());
        };
        let Value::Array(fields) = wrapper.first().ok_or("SLY1 prefix missing")? else {
            return Err("SLY1 prefix must be an array".into());
        };
        assert_eq!(fields.first(), Some(&Value::Text("SLY1".to_owned())));
    }
    Ok(())
}

#[test]
fn root_selector_server_fails_closed_for_authority_and_peer_mismatches() -> TestResult {
    for (authority_error, expected_code) in [
        (
            RootSelectorServiceError::AuthorityUnavailable,
            SandboxLocalErrorCode::PolicyUnavailable,
        ),
        (
            RootSelectorServiceError::AuthorityMismatch,
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        ),
        (
            RootSelectorServiceError::Admission,
            SandboxLocalErrorCode::PolicyUnavailable,
        ),
    ] {
        let fixture = Fixture::new()?;
        let request = selector_evaluation_request(&fixture)?;
        let attempt = selector_case_attempt();
        let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
        let (server_result, control, trailing) = exercise_root_selector(
            FailingSelectorAuthority(authority_error),
            ScenarioSelectorProvider {
                signed: SignedSelectorProvider { fixture, launch },
                mode: SelectorProviderMode::Valid,
            },
            &request,
            &attempt,
            0,
        )?;
        assert_eq!(server_result, Ok(()));
        assert!(trailing.is_empty());
        let local = SandboxLocalError::from_canonical_cbor(&control)?;
        assert_eq!(local.phase, SandboxLocalErrorPhase::BeforeSpx1);
        assert_eq!(local.code, expected_code);
    }

    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let plan = selector_case_plan(&fixture, &request, attempt.clone())?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let (server_result, control, trailing) = exercise_root_selector(
        FixedSelectorAuthority { plan },
        ScenarioSelectorProvider {
            signed: SignedSelectorProvider { fixture, launch },
            mode: SelectorProviderMode::Valid,
        },
        &request,
        &attempt,
        1,
    )?;
    assert_eq!(server_result, Err(RootSelectorServiceError::InvalidRequest));
    assert!(control.is_empty());
    assert!(trailing.is_empty());

    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let (server_result, control, trailing) = exercise_root_selector(
        FailingSelectorAuthority(RootSelectorServiceError::Io),
        ScenarioSelectorProvider {
            signed: SignedSelectorProvider { fixture, launch },
            mode: SelectorProviderMode::Valid,
        },
        &request,
        &attempt,
        0,
    )?;
    assert_eq!(server_result, Err(RootSelectorServiceError::Io));
    assert!(control.is_empty());
    assert!(trailing.is_empty());
    Ok(())
}

#[test]
fn root_selector_server_rejects_an_empty_control_frame() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let plan = selector_case_plan(&fixture, &request, attempt)?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("root-selector.sock");
    let listener = UnixListener::bind(&socket)?;
    let evaluator_uid = std::fs::metadata(temporary.path())?.uid();
    let mut server = RootSelectorServer::new(
        FixedSelectorAuthority { plan },
        ScenarioSelectorProvider {
            signed: SignedSelectorProvider { fixture, launch },
            mode: SelectorProviderMode::Valid,
        },
        evaluator_uid,
        Duration::from_secs(2),
    );
    let server_thread = thread::spawn(move || server.serve_once(&listener));
    let mut client = UnixStream::connect(&socket)?;
    client.write_all(&0_u32.to_be_bytes())?;
    client.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let length = u32::from_be_bytes(response[..4].try_into()?);
    assert_eq!(usize::try_from(length)?, response.len() - 4);
    let error = SandboxLocalError::from_canonical_cbor(&response[4..])?;
    assert_eq!(error.phase, SandboxLocalErrorPhase::BeforeSpx1);
    assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
    assert_eq!(error.request_id, None);
    assert_eq!(error.attempt_id, None);
    assert_eq!(
        server_thread
            .join()
            .map_err(|_| "root selector thread panicked")?,
        Ok(())
    );
    Ok(())
}

#[test]
fn root_selector_reports_truncated_attempt_with_decoded_identities() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let plan = selector_case_plan(&fixture, &request, attempt.clone())?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("selector.sock");
    let listener = UnixListener::bind(&socket)?;
    let uid = std::fs::metadata(temporary.path())?.uid();
    let mut server = RootSelectorServer::new(
        FixedSelectorAuthority { plan },
        SignedSelectorProvider { fixture, launch },
        uid,
        Duration::from_secs(2),
    );
    let server_thread = thread::spawn(move || server.serve_once(&listener));
    let (control, _) = selector_client_request(&request, &attempt, 7)?;
    let mut client = UnixStream::connect(&socket)?;
    client.write_all(&u32::try_from(control.len())?.to_be_bytes())?;
    client.write_all(&control)?;
    client.shutdown(std::net::Shutdown::Write)?;
    let mut prefix = [0; 4];
    client.read_exact(&mut prefix)?;
    let mut response = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
    client.read_exact(&mut response)?;
    let error = SandboxLocalError::from_canonical_cbor(&response)?;
    assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
    assert_eq!(error.operation, Some(SandboxProviderOperation::Execute));
    let mut request_id = request.request_id;
    request_id[14..].copy_from_slice(&7_u16.to_be_bytes());
    let mut attempt_id = request.request_id;
    attempt_id[14..].copy_from_slice(&(7_u16 ^ 0x8000).to_be_bytes());
    assert_eq!(error.request_id, Some(request_id));
    assert_eq!(error.attempt_id, Some(attempt_id));
    let mut trailing = Vec::new();
    client.read_to_end(&mut trailing)?;
    assert!(trailing.is_empty());
    server_thread
        .join()
        .map_err(|_| "selector thread panicked")??;
    Ok(())
}

/// Exercise only the public listener boundary; reaching authority is a distinct failure.
fn selector_rejection(wire: &[u8]) -> TestResult<SandboxLocalError> {
    let fixture = Fixture::new()?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let temporary = tempfile::tempdir()?;
    let socket = temporary.path().join("rejection.sock");
    let listener = UnixListener::bind(&socket)?;
    let uid = std::fs::metadata(temporary.path())?.uid();
    let mut server = RootSelectorServer::new(
        FailingSelectorAuthority(RootSelectorServiceError::AuthorityUnavailable),
        SignedSelectorProvider { fixture, launch },
        uid,
        Duration::from_secs(2),
    );
    let server_thread = thread::spawn(move || server.serve_once(&listener));
    let mut client = UnixStream::connect(&socket)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.write_all(wire)?;
    client.shutdown(std::net::Shutdown::Write)?;
    let mut prefix = [0; 4];
    client.read_exact(&mut prefix)?;
    let mut response = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
    client.read_exact(&mut response)?;
    let mut trailing = Vec::new();
    client.read_to_end(&mut trailing)?;
    assert!(trailing.is_empty());
    server_thread
        .join()
        .map_err(|_| "selector thread panicked")??;
    let error = SandboxLocalError::from_canonical_cbor(&response)?;
    assert_eq!(error.phase, SandboxLocalErrorPhase::BeforeSpx1);
    assert_eq!(error.agr1_digest, None);
    assert_eq!(error.safe_detail, None);
    Ok(error)
}

fn selector_wire(control: &[u8], input: &[u8]) -> TestResult<Vec<u8>> {
    let mut wire = u32::try_from(control.len())?.to_be_bytes().to_vec();
    wire.extend_from_slice(control);
    wire.extend_from_slice(input);
    Ok(wire)
}

#[test]
fn root_selector_retains_only_canonical_partial_identities() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let (control, _) = selector_client_request(&request, &selector_case_attempt(), 0)?;
    let request_id = request.request_id;
    let mut attempt_id = request_id;
    attempt_id[14..].copy_from_slice(&0x8000_u16.to_be_bytes());
    // Cut within the transport prefix, magic/version, both IDs, EVR1 and self-digest.
    let wire = selector_wire(&control, &[])?;
    for end in [
        0,
        1,
        3,
        4,
        10,
        11,
        12,
        13,
        28,
        29,
        30,
        45,
        46,
        wire.len() - 1,
    ] {
        let error = selector_rejection(&wire[..end])?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(
            error.operation,
            (end >= 11).then_some(SandboxProviderOperation::Execute)
        );
        assert_eq!(error.request_id, (end >= 29).then_some(request_id));
        assert_eq!(error.attempt_id, (end >= 46).then_some(attempt_id));
    }
    // Preferred encoding is checked field by field; later noncanonical bytes do
    // not erase earlier identities, and an undecodable request blocks attempt ID.
    for (offset, replacement, expected_request, expected_attempt) in [
        (0, vec![0x98, 2], None, None),
        (7, vec![0x18, 1], None, None),
        (8, vec![0x58, 16], None, None),
        (25, vec![0x58, 16], Some(request_id), None),
    ] {
        let mut changed = control.clone();
        drop(changed.splice(offset..=offset, replacement));
        let error = selector_rejection(&selector_wire(&changed, &[])?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(
            error.operation,
            (offset != 0).then_some(SandboxProviderOperation::Execute)
        );
        assert_eq!(error.request_id, expected_request);
        assert_eq!(error.attempt_id, expected_attempt);
    }
    Ok(())
}

#[test]
fn root_selector_rejects_malformed_canonical_slx_and_invalid_digests() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let (control, _) = selector_client_request(&request, &selector_case_attempt(), 0)?;
    let request_id = request.request_id;
    let mut attempt_id = request_id;
    attempt_id[14..].copy_from_slice(&0x8000_u16.to_be_bytes());
    for (field, replacement, expected_request, expected_attempt) in [
        (0, Value::Text("OTHER".to_owned()), None, None),
        (0, Value::Null, None, None),
        (1, integer(2), None, None),
        (1, Value::Null, None, None),
        (2, Value::Bytes(vec![0; 16]), None, None),
        (2, Value::Bytes(vec![1; 15]), None, None),
        (2, Value::Null, None, None),
        (3, Value::Bytes(vec![0; 16]), Some(request_id), None),
        (3, Value::Bytes(vec![1; 15]), Some(request_id), None),
        (3, Value::Null, Some(request_id), None),
        (4, Value::Null, Some(request_id), Some(attempt_id)),
        (
            4,
            Value::Bytes(b"not-cbor".to_vec()),
            Some(request_id),
            Some(attempt_id),
        ),
        (
            4,
            Value::Bytes(corrupt_signed_digest(&request.to_canonical_cbor()?)?),
            Some(request_id),
            Some(attempt_id),
        ),
        (5, Value::Null, Some(request_id), Some(attempt_id)),
        (
            5,
            Value::Array(vec![integer(1)]),
            Some(request_id),
            Some(attempt_id),
        ),
        (
            5,
            Value::Array(vec![Value::Integer((-1).into()), bytes([1; 32])]),
            Some(request_id),
            Some(attempt_id),
        ),
        (
            5,
            Value::Array(vec![integer(134_217_729), Value::Bytes(vec![1; 31])]),
            Some(request_id),
            Some(attempt_id),
        ),
    ] {
        let changed = redigest_unsigned_field(&control, "SLX1", field, replacement)?;
        let error = selector_rejection(&selector_wire(&changed, &[])?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(
            error.operation,
            (field != 0).then_some(SandboxProviderOperation::Execute)
        );
        assert_eq!(error.request_id, expected_request);
        assert_eq!(error.attempt_id, expected_attempt);
    }
    let mut trailing_control = control.clone();
    trailing_control.push(0);
    let mut wrapper: Vec<Value> = ciborium::from_reader(control.as_slice())?;
    wrapper[1] = Value::Null;
    for changed in [
        corrupt_signed_digest(&control)?,
        trailing_control,
        encode(&Value::Array(wrapper))?,
    ] {
        let error = selector_rejection(&selector_wire(&changed, &[])?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(error.request_id, Some(request_id));
        assert_eq!(error.attempt_id, Some(attempt_id));
    }
    Ok(())
}

#[test]
fn root_selector_rejects_malformed_control_containers() -> TestResult {
    for value in [
        Value::Null,
        Value::Array(Vec::new()),
        Value::Array(vec![Value::Null, bytes([1; 32])]),
        Value::Array(vec![Value::Array(Vec::new()), bytes([1; 32])]),
    ] {
        let error = selector_rejection(&selector_wire(&encode(&value)?, &[])?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(error.operation, None);
        assert_eq!(error.request_id, None);
        assert_eq!(error.attempt_id, None);
    }
    Ok(())
}

#[test]
fn root_selector_rejects_malformed_attempt_bytes_with_valid_descriptors() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let (control, input) = selector_client_request(&request, &selector_case_attempt(), 0)?;
    let mut trailing_input = input.clone();
    trailing_input.push(0);
    for malformed in [
        Vec::new(),
        vec![0; 4],
        input[..input.len() - 1].to_vec(),
        trailing_input,
    ] {
        let changed = redigest_unsigned_field(
            &control,
            "SLX1",
            5,
            Value::Array(vec![
                integer(u64::try_from(malformed.len())?),
                bytes(payload_digest(
                    b"PiglorOS.SandboxInputBytes.v1\0",
                    &malformed,
                )),
            ]),
        )?;
        let error = selector_rejection(&selector_wire(&changed, &malformed)?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(error.request_id, Some(request.request_id));
        assert!(error.attempt_id.is_some());
    }
    let changed = redigest_unsigned_field(
        &control,
        "SLX1",
        5,
        Value::Array(vec![integer(u64::try_from(input.len())?), bytes([99; 32])]),
    )?;
    let error = selector_rejection(&selector_wire(&changed, &input)?)?;
    assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
    Ok(())
}

#[test]
fn root_selector_distinguishes_declared_ceiling_from_descriptor_mismatch() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let (control, input) = selector_client_request(&request, &selector_case_attempt(), 0)?;
    for length in [134_217_729, u64::MAX] {
        let changed = redigest_unsigned_field(
            &control,
            "SLX1",
            5,
            Value::Array(vec![integer(length), bytes([1; 32])]),
        )?;
        let error = selector_rejection(&selector_wire(&changed, &[])?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::PayloadLimitExceeded);
        assert_eq!(error.operation, Some(SandboxProviderOperation::Execute));
        assert_eq!(error.request_id, Some(request.request_id));
        assert!(error.attempt_id.is_some());
    }
    let error = selector_rejection(&16_777_217_u32.to_be_bytes())?;
    assert_eq!(error.code, SandboxLocalErrorCode::PayloadLimitExceeded);
    assert_eq!(error.operation, None);
    assert_eq!(error.request_id, None);
    assert_eq!(error.attempt_id, None);
    for length in [0, u64::try_from(input.len())? + 1, 134_217_728] {
        let changed = redigest_unsigned_field(
            &control,
            "SLX1",
            5,
            Value::Array(vec![
                integer(length),
                bytes(payload_digest(b"PiglorOS.SandboxInputBytes.v1\0", &input)),
            ]),
        )?;
        let error = selector_rejection(&selector_wire(&changed, &input)?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::InvalidSelectorRequest);
        assert_eq!(error.request_id, Some(request.request_id));
    }
    Ok(())
}

#[test]
fn root_selector_classifies_valid_but_wrong_derived_ids_as_authority_mismatch() -> TestResult {
    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let (control, input) = selector_client_request(&request, &selector_case_attempt(), 0)?;
    for field in [2, 3] {
        let changed = redigest_unsigned_field(&control, "SLX1", field, Value::Bytes(vec![99; 16]))?;
        let error = selector_rejection(&selector_wire(&changed, &input)?)?;
        assert_eq!(error.code, SandboxLocalErrorCode::RequestAuthorityMismatch);
        assert_eq!(error.operation, Some(SandboxProviderOperation::Execute));
        if field == 2 {
            assert_eq!(error.request_id, Some([99; 16]));
        } else {
            assert_eq!(error.attempt_id, Some([99; 16]));
        }
    }
    Ok(())
}

#[test]
fn root_selector_propagates_disconnected_response_errors() -> TestResult {
    for scenario in 0..6 {
        let fixture = Fixture::new()?;
        let request = selector_evaluation_request(&fixture)?;
        let attempt = selector_case_attempt();
        let mut plan = selector_case_plan(&fixture, &request, attempt.clone())?;
        match scenario {
            0 => plan.expected_attempt.watchdog_ms += 1,
            1 => plan.execute_authority.cpf1_digest = [99; 32],
            2 => plan.admission.provider_manifest = corrupt_signed_digest(&fixture.spm1)?,
            3 => {
                plan.admission
                    .grant_expectations
                    .required_provider_capability
                    .capability_id = "different-capability".to_owned();
            }
            _ => {}
        }
        let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
        let result = exercise_disconnected_selector(
            FixedSelectorAuthority { plan },
            ScenarioSelectorProvider {
                signed: SignedSelectorProvider { fixture, launch },
                mode: if scenario == 4 {
                    SelectorProviderMode::Unavailable
                } else {
                    SelectorProviderMode::Valid
                },
            },
            &request,
            &attempt,
        )?;
        assert_eq!(result, Err(RootSelectorServiceError::Io));
    }
    for error in [
        RootSelectorServiceError::AuthorityUnavailable,
        RootSelectorServiceError::AuthorityMismatch,
    ] {
        let fixture = Fixture::new()?;
        let request = selector_evaluation_request(&fixture)?;
        let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
        let result = exercise_disconnected_selector(
            FailingSelectorAuthority(error),
            ScenarioSelectorProvider {
                signed: SignedSelectorProvider { fixture, launch },
                mode: SelectorProviderMode::Unavailable,
            },
            &request,
            &selector_case_attempt(),
        )?;
        assert_eq!(result, Err(RootSelectorServiceError::Io));
    }
    Ok(())
}

#[test]
fn root_selector_rejects_missing_sandbox_requirement_before_authority_resolution() -> TestResult {
    let fixture = Fixture::new()?;
    let mut request = selector_evaluation_request(&fixture)?;
    request.sandbox_requirement = None;
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let (server_result, control, trailing) = exercise_root_selector(
        FailingSelectorAuthority(RootSelectorServiceError::Io),
        ScenarioSelectorProvider {
            signed: SignedSelectorProvider { fixture, launch },
            mode: SelectorProviderMode::Unavailable,
        },
        &request,
        &selector_case_attempt(),
        0,
    )?;
    assert_eq!(server_result, Ok(()));
    assert!(trailing.is_empty());
    let local = SandboxLocalError::from_canonical_cbor(&control)?;
    assert_eq!(local.phase, SandboxLocalErrorPhase::BeforeSpx1);
    assert_eq!(local.code, SandboxLocalErrorCode::RequestAuthorityMismatch);
    Ok(())
}

#[test]
fn root_selector_server_rejects_reconstructed_attempt_and_authority_drift() -> TestResult {
    for drift in 0_u8..14 {
        let fixture = Fixture::new()?;
        let mut request = selector_evaluation_request(&fixture)?;
        if drift == 13 {
            request
                .sandbox_requirement
                .iter_mut()
                .for_each(|requirement| requirement.policy_epoch += 1);
            request.output_capability.capability_digest =
                request.expected_output_capability_digest()?;
            request.request_digest = request.digest()?;
        }
        let attempt = selector_case_attempt();
        let mut plan = selector_case_plan(&fixture, &request, attempt.clone())?;
        match drift {
            0 => plan.expected_attempt.watchdog_ms += 1,
            1 => plan.execute_authority.cpf1_digest = [99; 32],
            2 => plan.network_plans.push(NetworkExchangePlan {
                exchange_id: [0; 16],
                occurrence: 0,
                capability_id: String::new(),
                request_length: 0,
                request_digest: [0; 32],
                response_maximum: 0,
                expected_response_digest: [0; 32],
                retention_policy_digest: [0; 32],
                plan_digest: [0; 32],
            }),
            3 => plan.admission.provider_manifest = corrupt_signed_digest(&fixture.spm1)?,
            4 => plan.request_nonce = [0; 16],
            5 => plan.execute_authority.evr1_digest = [99; 32],
            6 => plan.execute_authority.cfb1_digest = [99; 32],
            7 => plan.execute_authority.fixture_digest = [99; 32],
            8 => plan.execute_authority.execution_profile_digest = [99; 32],
            9 => plan.execute_authority.lps1_digest = [99; 32],
            10 => plan.execute_authority.sim1_digest = [99; 32],
            11 => plan.execute_authority.apt1_digest = [99; 32],
            12 => {
                let different_launch = launch_policy([99; 32])?;
                plan.admission.policy =
                    fixture.policy_for_image(&fixture.sim1, &different_launch)?;
            }
            _ => {}
        }
        let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
        let (server_result, control, trailing) = exercise_root_selector(
            FixedSelectorAuthority { plan },
            ScenarioSelectorProvider {
                signed: SignedSelectorProvider { fixture, launch },
                mode: SelectorProviderMode::Valid,
            },
            &request,
            &attempt,
            0,
        )?;
        assert_eq!(server_result, Ok(()));
        assert!(trailing.is_empty());
        let local = SandboxLocalError::from_canonical_cbor(&control)?;
        assert_eq!(local.phase, SandboxLocalErrorPhase::BeforeSpx1);
        assert_eq!(
            local.code,
            if drift == 3 {
                SandboxLocalErrorCode::PolicyUnavailable
            } else {
                SandboxLocalErrorCode::RequestAuthorityMismatch
            }
        );
    }

    let fixture = Fixture::new()?;
    let request = selector_evaluation_request(&fixture)?;
    let attempt = selector_case_attempt();
    let mut plan = selector_case_plan(&fixture, &request, attempt.clone())?;
    plan.admission
        .grant_expectations
        .required_provider_capability
        .capability_id = "different-capability".to_owned();
    let launch = LaunchPolicy::from_canonical_cbor(&fixture.lps1)?;
    let (server_result, control, trailing) = exercise_root_selector(
        FixedSelectorAuthority { plan },
        ScenarioSelectorProvider {
            signed: SignedSelectorProvider { fixture, launch },
            mode: SelectorProviderMode::Valid,
        },
        &request,
        &attempt,
        0,
    )?;
    assert_eq!(server_result, Ok(()));
    assert!(trailing.is_empty());
    let local = SandboxLocalError::from_canonical_cbor(&control)?;
    assert_eq!(local.phase, SandboxLocalErrorPhase::BeforeSpx1);
    assert_eq!(local.code, SandboxLocalErrorCode::RequestAuthorityMismatch);
    Ok(())
}

#[test]
fn root_selector_establishment_fails_closed_at_each_admission_stage() -> TestResult {
    let fixture = Fixture::new()?;
    let establish = |provider_manifest: &[u8],
                     image_manifest: &[u8],
                     subject_digest: [u8; 32],
                     launch_policy: &[u8]| {
        RootSelectorAdmission::establish(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            RootSelectorAdmissionInputs {
                provider: SandboxProviderAdmissionInputs {
                    provider_manifest,
                    ..fixture.inputs()
                },
                image_manifest,
                root_image: &fixture.root_image,
                executable: &fixture.executable,
                subject_artifact_digest: subject_digest,
                launch_policy,
                grant_expectations: Fixture::grant_expectations(),
            },
        )
    };
    assert!(establish(
        b"not-cbor",
        &fixture.sim1,
        fixture.subject_digest(),
        &fixture.lps1
    )
    .is_err());
    assert!(establish(
        &fixture.spm1,
        b"not-cbor",
        fixture.subject_digest(),
        &fixture.lps1
    )
    .is_err());
    assert_eq!(
        establish(&fixture.spm1, &fixture.sim1, [99; 32], &fixture.lps1),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    assert!(establish(
        &fixture.spm1,
        &fixture.sim1,
        fixture.subject_digest(),
        b"not-cbor"
    )
    .is_err());
    Ok(())
}

#[test]
fn root_selector_rejects_each_incomplete_execution_evidence_stage() -> TestResult {
    let fixture = Fixture::new()?;
    let selector = RootSelectorAdmission::establish(
        &fixture.policy,
        &fixture.trust,
        &fixture.revocation,
        RootSelectorAdmissionInputs {
            provider: fixture.inputs(),
            image_manifest: &fixture.sim1,
            root_image: &fixture.root_image,
            executable: &fixture.executable,
            subject_artifact_digest: fixture.subject_digest(),
            launch_policy: &fixture.lps1,
            grant_expectations: Fixture::grant_expectations(),
        },
    )?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        selector.launch_policy(),
        &["execute"],
    )?)?;
    let grant_bytes = admission_grant(&fixture, &request, selector.launch_policy())?;
    let grant = AdmissionGrant::from_canonical_cbor(&grant_bytes)?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt_bytes = provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?;
    let receipt = SandboxProviderReceipt::from_canonical_cbor(&receipt_bytes)?;
    let result_bytes = terminal_result(&fixture, &request, &grant, &receipt)?;

    for result in [
        selector.authenticate_execution(
            &request,
            b"not-cbor",
            &receipt_bytes,
            &result_bytes,
            &audit,
        ),
        selector.authenticate_execution(&request, &grant_bytes, b"not-cbor", &result_bytes, &audit),
        selector.authenticate_execution(
            &request,
            &grant_bytes,
            &receipt_bytes,
            b"not-cbor",
            &audit,
        ),
        selector.authenticate_execution(
            &request,
            &grant_bytes,
            &receipt_bytes,
            &result_bytes,
            &[b"not-cbor".to_vec()],
        ),
    ] {
        assert!(result.is_err());
    }
    Ok(())
}

#[test]
fn provider_terminal_audit_authority_covers_failure_and_denial_paths() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = admitted.authenticate_grant(
        &admission_grant(&fixture, &request, &launch)?,
        &request,
        &image,
        &launch,
        &Fixture::grant_expectations(),
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
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = admitted.authenticate_grant(
        &admission_grant(&fixture, &request, &launch)?,
        &request,
        &image,
        &launch,
        &Fixture::grant_expectations(),
    )?;
    let audit = audit_chain(&fixture, &grant)?;
    let receipt = admitted.authenticate_receipt(
        &provider_receipt(&fixture, &grant, wrapped_digest(&audit[1])?)?,
        &grant,
    )?;

    assert!(admitted
        .admit_image(
            b"not-cbor",
            &fixture.root_image,
            &fixture.executable,
            fixture.subject_digest(),
        )
        .is_err());
    assert!(admitted.admit_launch_policy(b"not-cbor", &image).is_err());
    assert!(admitted
        .authenticate_grant(
            b"not-cbor",
            &request,
            &image,
            &launch,
            &Fixture::grant_expectations(),
        )
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
        .admit_image(
            &forged_image,
            &fixture.root_image,
            &fixture.executable,
            fixture.subject_digest(),
        )
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

fn assert_grant_substitutions(
    fixture: &Fixture,
    admitted: &AdmittedSandboxProvider,
    image: &AdmittedSandboxImage,
    launch: &LaunchPolicy,
    request: &SandboxExecuteRequest,
    grant_bytes: &[u8],
) -> TestResult {
    for (field, replacement) in [
        (20, bytes([99; 32])),
        (21, bytes([99; 32])),
        (24, bytes([99; 32])),
        (25, Value::Text("other-runtime".to_owned())),
    ] {
        let changed = resign_unsigned_field(
            grant_bytes,
            "AGR1",
            field,
            replacement,
            &fixture.authority.runtime,
        )?;
        assert_eq!(
            admitted.authenticate_grant(
                &changed,
                request,
                image,
                launch,
                &Fixture::grant_expectations(),
            ),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }

    for required_provider_capability in [
        RequiredProviderCapability {
            capability_id: "other".to_owned(),
            capability_version: 1,
            minimum_strength: 1,
        },
        RequiredProviderCapability {
            capability_id: "execute".to_owned(),
            capability_version: 2,
            minimum_strength: 1,
        },
        RequiredProviderCapability {
            capability_id: "execute".to_owned(),
            capability_version: 1,
            minimum_strength: 2,
        },
    ] {
        let expectations = SandboxGrantExpectations {
            required_provider_capability,
            ..Fixture::grant_expectations()
        };
        assert_eq!(
            admitted.authenticate_grant(grant_bytes, request, image, launch, &expectations),
            Err(SandboxAdmissionError::ConformanceMismatch)
        );
    }
    Ok(())
}

#[test]
fn lifecycle_authentication_rejects_each_identity_and_chain_substitution() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant_bytes = admission_grant(&fixture, &request, &launch)?;
    assert_grant_substitutions(&fixture, &admitted, &image, &launch, &request, &grant_bytes)?;
    let grant = admitted.authenticate_grant(
        &grant_bytes,
        &request,
        &image,
        &launch,
        &Fixture::grant_expectations(),
    )?;
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
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant_bytes = admission_grant(&fixture, &request, &launch)?;
    assert!(admitted
        .authenticate_grant(
            &replace_signed_signature(&grant_bytes, [9; 64])?,
            &request,
            &image,
            &launch,
            &Fixture::grant_expectations(),
        )
        .is_err());
    let grant = admitted.authenticate_grant(
        &grant_bytes,
        &request,
        &image,
        &launch,
        &Fixture::grant_expectations(),
    )?;
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

    let forged_receipt = SandboxProviderReceipt::from_canonical_cbor(&replace_signed_signature(
        &receipt_bytes,
        [9; 64],
    )?)?;
    let result =
        pos_reference::sandbox_provider_protocol::SandboxProviderResult::from_canonical_cbor(
            &result_bytes,
        )?;
    assert!(admitted
        .authenticate_audit_chain(&audit, &forged_receipt, &result)
        .is_err());
    let forged_result =
        pos_reference::sandbox_provider_protocol::SandboxProviderResult::from_canonical_cbor(
            &replace_signed_signature(&result_bytes, [9; 64])?,
        )?;
    assert!(admitted
        .authenticate_audit_chain(&audit, &receipt, &forged_result)
        .is_err());
    let mut forged_audit = audit;
    forged_audit[0] = replace_signed_signature(&forged_audit[0], [9; 64])?;
    assert!(admitted
        .authenticate_audit_chain(&forged_audit, &receipt, &result)
        .is_err());

    let mut invalid_receipt = receipt;
    invalid_receipt.attempt_id = [0; 16];
    assert!(admitted
        .authenticate_terminal_result(&result_bytes, &request, &grant, &invalid_receipt)
        .is_err());
    Ok(())
}

#[test]
fn audit_record_rejects_every_malformed_wire_field() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    let image = admitted.admit_image(
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
        fixture.subject_digest(),
    )?;
    let launch = admitted.admit_launch_policy(&fixture.lps1, &image)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(&execute_request(
        &fixture,
        &launch,
        &["execute"],
    )?)?;
    let grant = admitted.authenticate_grant(
        &admission_grant(&fixture, &request, &launch)?,
        &request,
        &image,
        &launch,
        &Fixture::grant_expectations(),
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
