//! Signed SIC1 installation fixture shared by unit tests and, through the
//! `test-support` feature, by privileged public-seam tests in other crates.
//!
//! Every record is signed with fixed test-only keys. Nothing here is release
//! or runtime authority, and deployable dependency graphs never enable the
//! feature (`scripts/check_test_support_features.py`).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::authority::AdmittedSelectorProvider;
use super::{
    hex_name, manifest_digest, HeldInstallationArtifact, InstallationManifest, InstallationObject,
    InstallationObjectKind, InstalledSelectorState, MANIFEST_NAME,
};
use crate::evaluator_protocol::{encode, ProtocolError};
use crate::sandbox_provider_protocol::{PartitionDescriptor, PartitionRole};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(crate) const ROOT_SELECTOR_CAPABILITY: &str = "read-public-bundle";

pub(crate) fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

pub(crate) fn digest(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

pub(crate) fn encode_manifest(fields: Vec<Value>) -> Result<Vec<u8>, ProtocolError> {
    let unsigned = Value::Array(fields);
    let digest = manifest_digest(&unsigned)?;
    encode(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
}

pub(crate) fn sign_record(
    magic: &str,
    unsigned: Value,
    signer: &SigningKey,
) -> TestResult<Vec<u8>> {
    let mut digest = blake3::Hasher::new();
    digest.update(format!("PiglorOS.{magic}.v1\0").as_bytes());
    digest.update(&encode(&unsigned)?);
    let digest = digest.finalize();
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend_from_slice(digest.as_bytes());
    Ok(encode(&Value::Array(vec![
        unsigned,
        Value::Bytes(digest.as_bytes().to_vec()),
        Value::Bytes(signer.sign(&message).to_bytes().to_vec()),
    ]))?)
}

pub(crate) fn signed_record_digest(bytes: &[u8]) -> TestResult<[u8; 32]> {
    let value: Value = ciborium::from_reader(bytes)?;
    let Value::Array(wrapper) = value else {
        return Err("signed record wrapper is not an array".into());
    };
    let Value::Bytes(digest) = wrapper.get(1).ok_or("signed record digest missing")? else {
        return Err("signed record digest is not bytes".into());
    };
    Ok(digest.as_slice().try_into()?)
}

pub(crate) fn held_artifact(
    kind: u8,
    identity: [u8; 32],
    bytes: &[u8],
) -> TestResult<HeldInstallationArtifact> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(bytes)?;
    Ok(HeldInstallationArtifact {
        file: file.into_file(),
        object: InstallationObject {
            kind: InstallationObjectKind::from_code(kind)?,
            identity,
            content_digest: *blake3::hash(bytes).as_bytes(),
            byte_length: bytes.len().try_into()?,
        },
    })
}

struct ProviderAuthority {
    root: SigningKey,
    policy: SigningKey,
    release: SigningKey,
    runtime: SigningKey,
    reviewer: SigningKey,
    image: SigningKey,
}

fn provider_authority() -> ProviderAuthority {
    ProviderAuthority {
        root: SigningKey::from_bytes(&[1; 32]),
        policy: SigningKey::from_bytes(&[2; 32]),
        release: SigningKey::from_bytes(&[3; 32]),
        runtime: SigningKey::from_bytes(&[4; 32]),
        reviewer: SigningKey::from_bytes(&[5; 32]),
        image: SigningKey::from_bytes(&[6; 32]),
    }
}

fn ordered(values: Vec<Value>) -> TestResult<Vec<Value>> {
    let mut encoded = values
        .into_iter()
        .map(|value| encode(&value).map(|bytes| (bytes, value)))
        .collect::<Result<Vec<_>, _>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(encoded.into_iter().map(|(_, value)| value).collect())
}

fn trust_key(id: &str, role: u64, key: &SigningKey) -> Value {
    Value::Array(vec![
        Value::Text(id.to_owned()),
        integer(role),
        Value::Bytes(key.verifying_key().to_bytes().to_vec()),
        integer(2),
    ])
}

/// Decode the producer's recorded 64 hexadecimal digits; nothing is computed.
fn hex_digest(text: &[u8]) -> TestResult<[u8; 32]> {
    let text = std::str::from_utf8(text)?;
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2).unwrap_or(""), 16))
        .collect::<Result<Vec<u8>, _>>()?
        .try_into()
        .map_err(|_| "recorded digest is not 32 bytes".into())
}

fn provider_trust(authority: &ProviderAuthority, signing: &ImageSigning) -> TestResult<Vec<u8>> {
    let keys = ordered(vec![
        trust_key("policy", 1, &authority.policy),
        trust_key("release", 2, &authority.release),
        trust_key("runtime", 3, &authority.runtime),
        trust_key("reviewer", 4, &authority.reviewer),
        trust_key("image", 5, &authority.image),
    ])?;
    sign_record(
        "TRS1",
        Value::Array(vec![
            Value::Text("TRS1".to_owned()),
            integer(1),
            integer(2),
            Value::Array(keys),
            Value::Array(vec![Value::Array(vec![
                digest(Sha256::digest(signing.certificate).into()),
                Value::Text(signing.key_description.to_owned()),
                integer(2),
            ])]),
            Value::Text("root".to_owned()),
        ]),
        &authority.root,
    )
}

fn provider_revocation(
    authority: &ProviderAuthority,
    trust_digest: [u8; 32],
) -> TestResult<Vec<u8>> {
    sign_record(
        "RVS1",
        Value::Array(vec![
            Value::Text("RVS1".to_owned()),
            integer(1),
            digest(trust_digest),
            integer(3),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
            Value::Text("policy".to_owned()),
        ]),
        &authority.policy,
    )
}

fn feature_digest(features: &[String]) -> TestResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.RequiredHostFeatureSet.v1\0");
    hasher.update(&encode(&Value::Array(
        features
            .iter()
            .map(|feature| Value::Text(feature.clone()))
            .collect(),
    ))?);
    Ok(*hasher.finalize().as_bytes())
}

fn provider_manifest(
    authority: &ProviderAuthority,
    binary_digest: [u8; 32],
    features_digest: [u8; 32],
) -> TestResult<Vec<u8>> {
    sign_record(
        "SPM1",
        Value::Array(vec![
            Value::Text("SPM1".to_owned()),
            integer(1),
            Value::Text("provider".to_owned()),
            digest([10; 32]),
            digest([11; 32]),
            digest(binary_digest),
            digest([12; 32]),
            Value::Text("runtime".to_owned()),
            Value::Array(vec![Value::Array(vec![
                Value::Text(ROOT_SELECTOR_CAPABILITY.to_owned()),
                integer(1),
                integer(1),
            ])]),
            Value::Array(vec![integer(0)]),
            digest([13; 32]),
            digest([14; 32]),
            digest([15; 32]),
            digest([16; 32]),
            integer(2),
            digest([17; 32]),
            digest(features_digest),
            Value::Text("release".to_owned()),
        ]),
        &authority.release,
    )
}

fn syscall_record() -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(vec![
        Value::Text("SCS1".to_owned()),
        integer(1),
        integer(0),
        Value::Array(vec![Value::Text("read".to_owned())]),
        Value::Array(vec![Value::Text("read".to_owned())]),
    ]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SCS1.v1\0");
    hasher.update(&encode(&unsigned)?);
    Ok(encode(&Value::Array(vec![
        unsigned,
        digest(*hasher.finalize().as_bytes()),
    ]))?)
}

fn host_profile(authority: &ProviderAuthority) -> TestResult<Vec<u8>> {
    let proofs = ordered(
        crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
            .iter()
            .map(|feature| {
                Value::Array(vec![
                    Value::Text((*feature).to_owned()),
                    integer(1),
                    digest([18; 32]),
                ])
            })
            .collect(),
    )?;
    sign_record(
        "HCP1",
        Value::Array(vec![
            Value::Text("HCP1".to_owned()),
            integer(1),
            integer(0),
            Value::Text("6.12.0".to_owned()),
            Value::Array(proofs),
            digest([19; 32]),
            digest([20; 32]),
            digest([21; 32]),
            Value::Text("runtime".to_owned()),
        ]),
        &authority.runtime,
    )
}

fn conformance_report(
    authority: &ProviderAuthority,
    binary_digest: [u8; 32],
    features_digest: [u8; 32],
    host_profile_digest: [u8; 32],
) -> TestResult<Vec<u8>> {
    let capability = Value::Array(vec![
        Value::Text(ROOT_SELECTOR_CAPABILITY.to_owned()),
        integer(1),
        integer(1),
    ]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ProviderCapabilitySet.v1\0");
    hasher.update(&encode(&Value::Array(vec![capability]))?);
    sign_record(
        "PCR1",
        Value::Array(vec![
            Value::Text("PCR1".to_owned()),
            integer(1),
            digest([17; 32]),
            digest(binary_digest),
            digest([12; 32]),
            digest(*hasher.finalize().as_bytes()),
            digest(features_digest),
            integer(0),
            digest(host_profile_digest),
            integer(0),
            Value::Text("reviewer".to_owned()),
        ]),
        &authority.reviewer,
    )
}

struct ProviderPolicySelection {
    provider_manifest: [u8; 32],
    provider_binary: [u8; 32],
    hard_caps: [u8; 32],
    conformance_report: [u8; 32],
    syscall_set: [u8; 32],
    launch_policy: [u8; 32],
    image_manifest: [u8; 32],
}

fn provider_policy(
    authority: &ProviderAuthority,
    trust_digest: [u8; 32],
    revocation_digest: [u8; 32],
    selection: &ProviderPolicySelection,
) -> TestResult<Vec<u8>> {
    sign_record(
        "APT1",
        Value::Array(vec![
            Value::Text("APT1".to_owned()),
            integer(1),
            integer(4),
            digest(selection.provider_manifest),
            digest(selection.provider_binary),
            Value::Array(vec![digest(selection.launch_policy)]),
            Value::Array(vec![digest(selection.image_manifest)]),
            digest(selection.hard_caps),
            digest([17; 32]),
            digest(selection.conformance_report),
            digest(trust_digest),
            digest(revocation_digest),
            integer(2),
            integer(3),
            digest(selection.syscall_set),
            Value::Text("policy".to_owned()),
        ]),
        &authority.policy,
    )
}

fn image_manifest(
    authority: &ProviderAuthority,
    root_image: &[u8],
    executable: &[u8],
    descriptors: &[PartitionDescriptor; 3],
    signing: &ImageSigning,
    salt: [u8; 32],
) -> TestResult<Vec<u8>> {
    let der = signing.proof.as_slice();
    let partitions = descriptors
        .iter()
        .enumerate()
        .map(|(index, partition)| {
            Ok(Value::Array(vec![
                integer(u64::try_from(index)?),
                Value::Bytes(partition.partition_type_uuid.to_vec()),
                Value::Bytes(partition.partition_instance_uuid.to_vec()),
                integer(partition.start_bytes),
                integer(partition.length_bytes),
                digest(partition.content_blake3_digest),
            ]))
        })
        .collect::<TestResult<Vec<_>>>()?;
    sign_record(
        "SIM1",
        Value::Array(vec![
            Value::Text("SIM1".to_owned()),
            integer(1),
            Value::Text("image".to_owned()),
            integer(0),
            integer(u64::try_from(root_image.len())?),
            digest(*blake3::hash(root_image).as_bytes()),
            Value::Array(partitions),
            digest(signing.root_hash),
            integer(4096),
            integer(4096),
            integer(1),
            digest(salt),
            Value::Array(vec![
                integer(u64::try_from(der.len())?),
                Value::Bytes(Sha256::digest(der).to_vec()),
                Value::Bytes(der.to_vec()),
            ]),
            digest(Sha256::digest(signing.certificate).into()),
            Value::Text(signing.key_description.to_owned()),
            Value::Text("/adapter".to_owned()),
            digest(*blake3::hash(executable).as_bytes()),
            Value::Array(Vec::new()),
            integer(2),
            Value::Text("image".to_owned()),
        ]),
        &authority.image,
    )
}

fn launch_policy(image_manifest: [u8; 32]) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(vec![
        Value::Text("LPS1".to_owned()),
        integer(1),
        Value::Text("air-gapped".to_owned()),
        integer(1),
        digest(image_manifest),
        Value::Array(selector_limit_values()),
        Value::Array(Vec::new()),
    ]);
    let encoded = encode(&unsigned)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.LPS1.v1\0");
    hasher.update(&encoded);
    Ok(encode(&Value::Array(vec![
        unsigned,
        digest(*hasher.finalize().as_bytes()),
    ]))?)
}

fn selector_limit_values() -> Vec<Value> {
    (0..17)
        .map(|limit_id| {
            let value = if limit_id == 13 { 256 } else { 2_000 };
            Value::Array(vec![integer(limit_id), integer(value)])
        })
        .collect()
}

fn broker_hard_caps() -> Result<Vec<u8>, ProtocolError> {
    encode(&Value::Array(vec![
        Value::Text("BHC1".to_owned()),
        integer(1),
        Value::Array(selector_limit_values()),
    ]))
}

/// Expanded systemd-repart DDI and its independently described partitions.
pub(crate) fn ddi_fixture(architecture: &str) -> TestResult<(Vec<u8>, [PartitionDescriptor; 3])> {
    macro_rules! vector {
        ($architecture:literal) => {
            (
                include_bytes!(concat!(
                    "../../../tests/vectors/sim1-ddi/",
                    $architecture,
                    "/image.raw.gz"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    "../../../tests/vectors/sim1-ddi/",
                    $architecture,
                    "/partitions.json"
                ))
                .as_slice(),
            )
        };
    }
    let (compressed, sidecar) = match architecture {
        "x86-64" => vector!("x86-64"),
        "arm64" => vector!("arm64"),
        _ => return Err("unknown DDI fixture".into()),
    };
    let mut image = Vec::new();
    flate2::read::GzDecoder::new(compressed).read_to_end(&mut image)?;
    let partitions = sidecar_partitions(sidecar, &image)?;
    Ok((image, partitions))
}

pub(crate) fn sidecar_partitions(
    sidecar: &[u8],
    image: &[u8],
) -> TestResult<[PartitionDescriptor; 3]> {
    let declared: [([u8; 16], [u8; 16], u64, u64); 3] = serde_json::from_slice(sidecar)?;
    let mut partitions = Vec::new();
    for (role, (partition_type_uuid, partition_instance_uuid, start_bytes, length_bytes)) in [
        PartitionRole::RootData,
        PartitionRole::RootVerity,
        PartitionRole::RootVeritySignature,
    ]
    .into_iter()
    .zip(declared)
    {
        let start = usize::try_from(start_bytes)?;
        let end = usize::try_from(start_bytes + length_bytes)?;
        let bytes = image.get(start..end).ok_or("fixture extent missing")?;
        partitions.push(PartitionDescriptor {
            role,
            partition_type_uuid,
            partition_instance_uuid,
            start_bytes,
            length_bytes,
            content_blake3_digest: *blake3::hash(bytes).as_bytes(),
        });
    }
    partitions
        .try_into()
        .map_err(|_| "fixture partition count".into())
}

/// The 32-byte verity salt systemd-repart wrote into a DDI fixture.
pub(crate) fn ddi_salt(architecture: &str) -> TestResult<[u8; 32]> {
    let verity: &[u8] = match architecture {
        "x86-64" => include_bytes!("../../../tests/vectors/sim1-ddi/x86-64/verity.json"),
        "arm64" => include_bytes!("../../../tests/vectors/sim1-ddi/arm64/verity.json"),
        _ => return Err("unknown DDI fixture".into()),
    };
    let verity: serde_json::Value = serde_json::from_slice(verity)?;
    let text = verity["salt"].as_str().ok_or("DDI salt is not text")?;
    // Decode the producer's recorded salt; no salt value is written here.
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2).unwrap_or(""), 16))
        .collect::<Result<Vec<u8>, _>>()?
        .try_into()
        .map_err(|_| "DDI salt is not 32 bytes".into())
}

/// The real x86-64 systemd-repart image with its partitions, verity salt,
/// root hash, proof and signer.
pub(crate) fn admitted_state() -> TestResult<InstalledSelectorState> {
    let (image, partitions) = ddi_fixture("x86-64")?;
    admitted_state_with_salt(
        &image,
        b"adapter",
        &partitions,
        &ImageSigning::ddi("x86-64")?,
        ddi_salt("x86-64")?,
    )
}

pub(crate) fn admitted_state_with_salt(
    root_image: &[u8],
    executable: &[u8],
    partitions: &[PartitionDescriptor; 3],
    signing: &ImageSigning,
    salt: [u8; 32],
) -> TestResult<InstalledSelectorState> {
    let authority = provider_authority();
    let trust = provider_trust(&authority, signing)?;
    let trust_digest = signed_record_digest(&trust)?;
    let revocation = provider_revocation(&authority, trust_digest)?;
    let revocation_digest = signed_record_digest(&revocation)?;
    let features = crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
        .map(str::to_owned)
        .to_vec();
    let features_digest = feature_digest(&features)?;
    let provider_binary = b"exact provider binary";
    let provider_binary_digest = *blake3::hash(provider_binary).as_bytes();
    let hard_caps = broker_hard_caps()?;
    let hard_caps_digest = *blake3::hash(&hard_caps).as_bytes();
    let manifest = provider_manifest(&authority, provider_binary_digest, features_digest)?;
    let manifest_digest = signed_record_digest(&manifest)?;
    let syscall = syscall_record()?;
    let syscall_digest = signed_record_digest(&syscall)?;
    let host = host_profile(&authority)?;
    let host_digest = signed_record_digest(&host)?;
    let report = conformance_report(
        &authority,
        provider_binary_digest,
        features_digest,
        host_digest,
    )?;
    let report_digest = signed_record_digest(&report)?;
    let image = image_manifest(
        &authority, root_image, executable, partitions, signing, salt,
    )?;
    let image_digest = signed_record_digest(&image)?;
    let launch = launch_policy(image_digest)?;
    let launch_digest = signed_record_digest(&launch)?;
    let policy = provider_policy(
        &authority,
        trust_digest,
        revocation_digest,
        &ProviderPolicySelection {
            provider_manifest: manifest_digest,
            provider_binary: provider_binary_digest,
            hard_caps: hard_caps_digest,
            conformance_report: report_digest,
            syscall_set: syscall_digest,
            launch_policy: launch_digest,
            image_manifest: image_digest,
        },
    )?;
    let policy_digest = signed_record_digest(&policy)?;
    let artifacts = [
        (0, trust_digest, trust.as_slice()),
        (1, revocation_digest, revocation.as_slice()),
        (2, policy_digest, policy.as_slice()),
        (3, manifest_digest, manifest.as_slice()),
        (4, report_digest, report.as_slice()),
        (5, [17; 32], b"conformance-profile".as_slice()),
        (6, host_digest, host.as_slice()),
        (7, syscall_digest, syscall.as_slice()),
        (8, launch_digest, launch.as_slice()),
        (9, image_digest, image.as_slice()),
        (10, hard_caps_digest, hard_caps.as_slice()),
        (11, provider_binary_digest, provider_binary.as_slice()),
        (12, *blake3::hash(root_image).as_bytes(), root_image),
        (13, *blake3::hash(executable).as_bytes(), executable),
    ];
    let mut installed = BTreeMap::new();
    for (kind, identity, bytes) in artifacts {
        let artifact = held_artifact(kind, identity, bytes)?;
        installed.insert((artifact.object.kind, artifact.object.identity), artifact);
    }
    let objects = installed
        .values()
        .map(|artifact| artifact.object.clone())
        .collect();
    Ok(InstalledSelectorState {
        root: tempfile::tempdir().and_then(|directory| File::open(directory.path()))?,
        manifest_file: tempfile::NamedTempFile::new()?.into_file(),
        manifest_bytes: Vec::new(),
        manifest: InstallationManifest {
            root_key_id: "root".to_owned(),
            root_public_key: authority.root.verifying_key().to_bytes(),
            trust_digest,
            revocation_digest,
            policy_digest,
            execute_socket: "/run/pigloros/provider-execute.sock".to_owned(),
            control_socket: "/run/pigloros/provider-control.sock".to_owned(),
            required_features: features,
            objects,
            digest: [1; 32],
        },
        artifacts: installed,
    })
}

/// The release signing material one fixture's SIM1 and TRS1 bind.
pub(crate) struct ImageSigning {
    pub(crate) root_hash: [u8; 32],
    pub(crate) proof: Vec<u8>,
    pub(crate) certificate: &'static [u8],
    pub(crate) key_description: &'static str,
}

impl ImageSigning {
    /// A DDI fixture's own systemd-repart root hash, proof and signer,
    /// as its root-verity-sig partition embeds them.
    pub(crate) fn ddi(architecture: &str) -> TestResult<Self> {
        // The kernel's x509 descriptions of each signer.der: CN, then SKID.
        let (root_hash, proof, certificate, key_description): (&[u8], &[u8], _, _) =
            match architecture {
                "x86-64" => (
                    include_bytes!("../../../tests/vectors/sim1-ddi/x86-64/root-hash.txt"),
                    include_bytes!("../../../tests/vectors/sim1-ddi/x86-64/proof.der"),
                    include_bytes!("../../../tests/vectors/sim1-ddi/x86-64/signer.der").as_slice(),
                    "PiglorOS SIM1 DDI fixture x86-64: \
                     e0b3c91db94dc506da3652b0ace1603e49009f3e",
                ),
                "arm64" => (
                    include_bytes!("../../../tests/vectors/sim1-ddi/arm64/root-hash.txt"),
                    include_bytes!("../../../tests/vectors/sim1-ddi/arm64/proof.der"),
                    include_bytes!("../../../tests/vectors/sim1-ddi/arm64/signer.der").as_slice(),
                    "PiglorOS SIM1 DDI fixture arm64: \
                     cee4947773692d91c1a7e728a9b98d6223ec099d",
                ),
                _ => return Err("unknown DDI fixture".into()),
            };
        Ok(Self {
            root_hash: hex_digest(root_hash)?,
            proof: proof.to_vec(),
            certificate,
            key_description,
        })
    }
}

pub(crate) fn materialize_state(
    root: &Path,
    state: InstalledSelectorState,
) -> TestResult<AdmittedSelectorProvider> {
    let admitted = state.authenticate_bootstrap()?.admit_provider()?;
    let installed = admitted.bootstrap().installed();
    for directory in ["authority", "providers", "images"] {
        let path = root.join(directory);
        fs::create_dir(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    for object in installed.manifest().objects() {
        let artifact = installed.artifact(object.kind(), object.identity())?;
        let bytes = artifact.read_control(object.byte_length())?;
        let path = root
            .join(object.kind().directory())
            .join(hex_name(object.content_digest()));
        fs::write(&path, bytes)?;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(object.kind().required_mode()),
        )?;
    }

    let manifest = installed.manifest();
    let (root_key_id, root_public_key) = manifest.offline_root();
    let authority = manifest.authority_digests();
    let (execute_socket, control_socket) = manifest.provider_sockets();
    let objects = manifest
        .objects()
        .iter()
        .map(|object| {
            Value::Array(vec![
                integer(u64::from(object.kind().code())),
                digest(object.identity()),
                digest(object.content_digest()),
                integer(object.byte_length()),
            ])
        })
        .collect();
    let manifest_bytes = encode_manifest(vec![
        Value::Text("SIC1".to_owned()),
        integer(1),
        Value::Text(root_key_id.to_owned()),
        digest(root_public_key),
        digest(authority[0]),
        digest(authority[1]),
        digest(authority[2]),
        Value::Text(execute_socket.to_string_lossy().into_owned()),
        Value::Text(control_socket.to_string_lossy().into_owned()),
        Value::Array(
            manifest
                .required_features()
                .iter()
                .cloned()
                .map(Value::Text)
                .collect(),
        ),
        Value::Array(objects),
    ])?;
    let manifest_path = root.join(MANIFEST_NAME);
    fs::write(&manifest_path, manifest_bytes)?;
    fs::set_permissions(manifest_path, fs::Permissions::from_mode(0o400))?;
    Ok(admitted)
}
