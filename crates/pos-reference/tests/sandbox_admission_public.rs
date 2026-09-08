//! Public selector-owned provider and image admission tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AdmittedSandboxProvider, LaunchPolicy, SandboxAdministratorPolicy,
    SandboxAdmissionError, SandboxArchitecture, SandboxExecuteRequest,
    SandboxProviderAdmissionInputs, SandboxProviderReceipt, SandboxRevocationSnapshot,
    SandboxTrustSnapshot,
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

fn self_digested_record(magic: &str, unsigned: Value) -> TestResult<Vec<u8>> {
    let digest = digest_value(format!("PiglorOS.{magic}.v1\0").as_bytes(), &unsigned)?;
    encode(&Value::Array(vec![unsigned, bytes(digest)]))
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
        bytes([24; 32]),
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
            Value::Array(vec![Value::Array(vec![integer(0), integer(1)])]),
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
        11 => vec![grant.grant_digest, [41; 32], [44; 32]],
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
    let ready = audit_record(fixture, grant, 0, 11, None)?;
    let released = audit_record(fixture, grant, 1, 12, Some(wrapped_digest(&ready)?))?;
    Ok(vec![ready, released])
}

fn provider_receipt(
    fixture: &Fixture,
    grant: &AdmissionGrant,
    audit_digest: [u8; 32],
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
            bytes([41; 32]),
            bytes([42; 32]),
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
    let output = b"output";
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

struct Fixture {
    authority: SigningAuthority,
    trust: SandboxTrustSnapshot,
    revocation: SandboxRevocationSnapshot,
    policy: SandboxAdministratorPolicy,
    required_features: Vec<String>,
    provider_binary: Vec<u8>,
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
            conformance_report: &self.pcr1,
            host_profile: &self.hcp1,
            syscall_set: &self.scs1,
            required_features: &self.required_features,
        }
    }

    fn admit(&self) -> Result<AdmittedSandboxProvider, SandboxAdmissionError> {
        AdmittedSandboxProvider::admit(&self.policy, &self.trust, &self.revocation, self.inputs())
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
        let policy = fixture.policy_for_provider(&revocation, &fixture.spm1, &fixture.pcr1)?;
        assert_eq!(
            AdmittedSandboxProvider::admit(&policy, &fixture.trust, &revocation, fixture.inputs(),),
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
        (&fixture.pcr1, "PCR1", 4, &fixture.authority.reviewer),
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
    let revoked = revocation(
        &fixture.trust,
        &fixture.authority,
        vec![],
        vec![bytes(wrapped_digest(&fixture.sim1)?)],
    )?;
    let revoked_policy = administrator_policy(
        &fixture.trust,
        &revoked,
        &fixture.authority,
        &PolicySelectionDigests {
            provider_manifest: wrapped_digest(&fixture.spm1)?,
            provider_binary: *blake3::hash(&fixture.provider_binary).as_bytes(),
            conformance_report: wrapped_digest(&fixture.pcr1)?,
            syscall_set: wrapped_digest(&fixture.scs1)?,
            launch_policy: wrapped_digest(&fixture.lps1)?,
            image_manifest: wrapped_digest(&fixture.sim1)?,
        },
    )?;
    let revoked_admission = AdmittedSandboxProvider::admit(
        &revoked_policy,
        &fixture.trust,
        &revoked,
        fixture.inputs(),
    )?;
    assert_eq!(
        revoked_admission.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable),
        Err(SandboxAdmissionError::Revoked)
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
    let grant = admitted.authenticate_grant(
        &admission_grant(&fixture, &request, &launch)?,
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
        admitted.authenticate_grant(
            &admission_grant(&fixture, &unsupported, &launch)?,
            &unsupported,
            &image,
            &launch,
        ),
        Err(SandboxAdmissionError::ConformanceMismatch)
    );
    Ok(())
}
