//! Public selector-owned provider and image admission tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    AdmittedSandboxProvider, SandboxAdministratorPolicy, SandboxAdmissionError,
    SandboxArchitecture, SandboxProviderAdmissionInputs, SandboxRevocationSnapshot,
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

fn ordered(mut values: Vec<Value>) -> TestResult<Vec<Value>> {
    let mut encoded = values
        .drain(..)
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

fn administrator_policy(
    trust: &SandboxTrustSnapshot,
    revocation: &SandboxRevocationSnapshot,
    authority: &SigningAuthority,
    spm1_digest: [u8; 32],
    binary_digest: [u8; 32],
    pcr1_digest: [u8; 32],
    scs1_digest: [u8; 32],
    sim1_digest: [u8; 32],
) -> TestResult<SandboxAdministratorPolicy> {
    let unsigned = Value::Array(vec![
        Value::Text("APT1".to_owned()),
        integer(1),
        integer(4),
        bytes(spm1_digest),
        bytes(binary_digest),
        Value::Array(vec![bytes([23; 32])]),
        Value::Array(vec![bytes(sim1_digest)]),
        bytes([24; 32]),
        bytes([17; 32]),
        bytes(pcr1_digest),
        bytes(trust.snapshot_digest()),
        bytes(revocation.snapshot_digest()),
        integer(trust.trust_epoch()),
        integer(revocation.revocation_epoch()),
        bytes(scs1_digest),
        Value::Text("policy".to_owned()),
    ]);
    Ok(SandboxAdministratorPolicy::authenticate(
        &sign_record("APT1", unsigned, &authority.policy)?,
        trust,
        revocation,
    )?)
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
        let spm1 = provider_manifest(&authority, binary_digest, feature_digest)?;
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
        let sim1 = image_manifest(&authority, &root_image, &executable, 0)?;
        let policy = administrator_policy(
            &trust,
            &revocation,
            &authority,
            wrapped_digest(&spm1)?,
            binary_digest,
            wrapped_digest(&pcr1)?,
            wrapped_digest(&scs1)?,
            wrapped_digest(&sim1)?,
        )?;
        Ok(Self {
            authority,
            trust,
            revocation,
            policy,
            required_features,
            provider_binary,
            spm1,
            scs1,
            hcp1,
            pcr1,
            root_image,
            executable,
            sim1,
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
        &fixture.policy,
        &fixture.trust,
        &fixture.revocation,
        &fixture.sim1,
        &fixture.root_image,
        &fixture.executable,
    )?;
    assert_eq!(image.executable_path, "/adapter");
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
        wrapped_digest(&fixture.spm1)?,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        wrapped_digest(&failed_pcr1)?,
        wrapped_digest(&fixture.scs1)?,
        wrapped_digest(&fixture.sim1)?,
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
        wrapped_digest(&fixture.spm1)?,
        *blake3::hash(&fixture.provider_binary).as_bytes(),
        wrapped_digest(&pcr1)?,
        wrapped_digest(&fixture.scs1)?,
        wrapped_digest(&fixture.sim1)?,
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
fn image_admission_rejects_changed_revoked_and_foreign_bytes() -> TestResult {
    let fixture = Fixture::new()?;
    let admitted = fixture.admit()?;
    assert_eq!(
        admitted.admit_image(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            &fixture.sim1,
            b"changed",
            &fixture.executable,
        ),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    assert_eq!(
        admitted.admit_image(
            &fixture.policy,
            &fixture.trust,
            &fixture.revocation,
            &fixture.sim1,
            &fixture.root_image,
            b"changed",
        ),
        Err(SandboxAdmissionError::ArtifactMismatch)
    );
    let revoked = revocation(
        &fixture.trust,
        &fixture.authority,
        vec![],
        vec![bytes(wrapped_digest(&fixture.sim1)?)],
    )?;
    assert_eq!(
        admitted.admit_image(
            &fixture.policy,
            &fixture.trust,
            &revoked,
            &fixture.sim1,
            &fixture.root_image,
            &fixture.executable,
        ),
        Err(SandboxAdmissionError::Revoked)
    );
    Ok(())
}
