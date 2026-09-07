//! Canonical wire records for the ADR-069 release-barrier feasibility proof.

use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use std::io::Cursor;

const FDL1_DOMAIN: &[u8] = b"PiglorOS.FDL1.v1\0";
const LPV1_DOMAIN: &[u8] = b"PiglorOS.LPV1.v1\0";
const RDY1_DOMAIN: &[u8] = b"PiglorOS.RDY1.v1\0";
const RLS1_DOMAIN: &[u8] = b"PiglorOS.RLS1.v1\0";
const RLS1_SIGNATURE_DOMAIN: &[u8] = b"PiglorOS.RLS1.Signature.v1\0";

pub const PROOF_SIGNING_KEY: [u8; 32] = [0x69; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdLayout {
    pub mode: u8,
    pub entries: Vec<(u64, u8)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchParameters {
    pub attempt_id: [u8; 16],
    pub nonce: [u8; 32],
    pub sim1_digest: [u8; 32],
    pub adapter_path: String,
    pub adapter_arguments: Vec<String>,
    pub expected_fd_layout_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdIdentity {
    pub mount_id: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ready {
    pub attempt_id: [u8; 16],
    pub nonce: [u8; 32],
    pub invocation_id: [u8; 16],
    pub launcher_digest: [u8; 32],
    pub launcher_identity: FdIdentity,
    pub sim1_digest: [u8; 32],
    pub adapter_digest: [u8; 32],
    pub adapter_identity: FdIdentity,
    pub launch_parameter_digest: [u8; 32],
    pub expected_fd_layout_digest: [u8; 32],
    pub observed_fd_layout_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    pub attempt_id: [u8; 16],
    pub nonce: [u8; 32],
    pub ready_digest: [u8; 32],
    pub trs1_digest: [u8; 32],
    pub rvs1_digest: [u8; 32],
    pub apt1_digest: [u8; 32],
    pub trust_epoch: u64,
    pub revocation_epoch: u64,
    pub policy_epoch: u64,
    pub expected_readback_digest: [u8; 32],
    pub observed_readback_digest: [u8; 32],
    pub deadline_monotonic_ns: u64,
    pub runtime_key_id: String,
}

pub fn encode_fd_layout(layout: &FdLayout) -> Result<Vec<u8>, String> {
    if layout.mode > 3 {
        return Err("FDL1 execution mode is outside 0..3".to_owned());
    }
    let mut previous = None;
    let mut entries = Vec::with_capacity(layout.entries.len());
    for &(number, role) in &layout.entries {
        if role > 1 || previous.is_some_and(|value| number <= value) {
            return Err("FDL1 entries are invalid or non-canonical".to_owned());
        }
        previous = Some(number);
        entries.push(Value::Array(vec![
            integer(number),
            integer(u64::from(role)),
        ]));
    }
    encode_self_digested(
        Value::Array(vec![
            text("FDL1"),
            integer(1),
            integer(u64::from(layout.mode)),
            Value::Array(entries),
        ]),
        FDL1_DOMAIN,
    )
}

pub fn fd_layout_digest(layout: &FdLayout) -> Result<[u8; 32], String> {
    envelope_digest(&encode_fd_layout(layout)?)
}

pub fn encode_launch_parameters(parameters: &LaunchParameters) -> Result<Vec<u8>, String> {
    if parameters.adapter_path.is_empty()
        || parameters.adapter_path.len() > 512
        || parameters.adapter_arguments.len() > 256
        || parameters
            .adapter_arguments
            .iter()
            .any(|argument| argument.len() > 256)
    {
        return Err("LPV1 bounds are invalid".to_owned());
    }
    let prefix = Value::Array(vec![
        text("LPV1"),
        integer(1),
        bytes(parameters.attempt_id),
        bytes(parameters.nonce),
        bytes(parameters.sim1_digest),
        text(&parameters.adapter_path),
        Value::Array(
            parameters
                .adapter_arguments
                .iter()
                .map(|argument| text(argument))
                .collect(),
        ),
        bytes(parameters.expected_fd_layout_digest),
    ]);
    let encoded = encode_self_digested(prefix, LPV1_DOMAIN)?;
    if encoded.len() > 64 * 1024 {
        return Err("LPV1 exceeds 64 KiB".to_owned());
    }
    Ok(encoded)
}

pub fn decode_launch_parameters(encoded: &[u8]) -> Result<LaunchParameters, String> {
    let prefix = decode_self_digested(encoded, "LPV1", LPV1_DOMAIN)?;
    if prefix.len() != 8 {
        return Err("LPV1 has the wrong field count".to_owned());
    }
    let arguments = array(&prefix[6])?
        .iter()
        .map(string)
        .collect::<Result<Vec<_>, _>>()?;
    let value = LaunchParameters {
        attempt_id: fixed_bytes(&prefix[2])?,
        nonce: fixed_bytes(&prefix[3])?,
        sim1_digest: fixed_bytes(&prefix[4])?,
        adapter_path: string(&prefix[5])?,
        adapter_arguments: arguments,
        expected_fd_layout_digest: fixed_bytes(&prefix[7])?,
    };
    if encode_launch_parameters(&value)? != encoded {
        return Err("LPV1 is not canonical".to_owned());
    }
    Ok(value)
}

pub fn launch_parameter_digest(encoded: &[u8]) -> Result<[u8; 32], String> {
    envelope_digest(encoded)
}

pub fn encode_ready(ready: &Ready) -> Result<Vec<u8>, String> {
    encode_self_digested(
        Value::Array(vec![
            text("RDY1"),
            integer(1),
            bytes(ready.attempt_id),
            bytes(ready.nonce),
            bytes(ready.invocation_id),
            bytes(ready.launcher_digest),
            fd_identity(ready.launcher_identity),
            bytes(ready.sim1_digest),
            bytes(ready.adapter_digest),
            fd_identity(ready.adapter_identity),
            bytes(ready.launch_parameter_digest),
            bytes(ready.expected_fd_layout_digest),
            bytes(ready.observed_fd_layout_digest),
        ]),
        RDY1_DOMAIN,
    )
}

pub fn decode_ready(encoded: &[u8]) -> Result<Ready, String> {
    let prefix = decode_self_digested(encoded, "RDY1", RDY1_DOMAIN)?;
    if prefix.len() != 13 {
        return Err("ReadyV1 has the wrong field count".to_owned());
    }
    let value = Ready {
        attempt_id: fixed_bytes(&prefix[2])?,
        nonce: fixed_bytes(&prefix[3])?,
        invocation_id: fixed_bytes(&prefix[4])?,
        launcher_digest: fixed_bytes(&prefix[5])?,
        launcher_identity: decode_fd_identity(&prefix[6])?,
        sim1_digest: fixed_bytes(&prefix[7])?,
        adapter_digest: fixed_bytes(&prefix[8])?,
        adapter_identity: decode_fd_identity(&prefix[9])?,
        launch_parameter_digest: fixed_bytes(&prefix[10])?,
        expected_fd_layout_digest: fixed_bytes(&prefix[11])?,
        observed_fd_layout_digest: fixed_bytes(&prefix[12])?,
    };
    if encode_ready(&value)? != encoded {
        return Err("ReadyV1 is not canonical".to_owned());
    }
    Ok(value)
}

pub fn ready_digest(encoded: &[u8]) -> Result<[u8; 32], String> {
    envelope_digest(encoded)
}

pub fn encode_release(release: &Release, signing_key: &SigningKey) -> Result<Vec<u8>, String> {
    if release.runtime_key_id.is_empty() || release.runtime_key_id.len() > 128 {
        return Err("ReleaseV1 runtime key ID is invalid".to_owned());
    }
    let prefix = Value::Array(vec![
        text("RLS1"),
        integer(1),
        bytes(release.attempt_id),
        bytes(release.nonce),
        bytes(release.ready_digest),
        bytes(release.trs1_digest),
        bytes(release.rvs1_digest),
        bytes(release.apt1_digest),
        integer(release.trust_epoch),
        integer(release.revocation_epoch),
        integer(release.policy_epoch),
        bytes(release.expected_readback_digest),
        bytes(release.observed_readback_digest),
        integer(release.deadline_monotonic_ns),
        text(&release.runtime_key_id),
    ]);
    let prefix_bytes = encode_value(&prefix)?;
    let digest = domain_digest(RLS1_DOMAIN, &prefix_bytes);
    let signature = signing_key.sign(&signature_preimage(digest));
    encode_value(&Value::Array(vec![
        prefix,
        bytes(digest),
        bytes(signature.to_bytes()),
    ]))
}

pub fn decode_release(encoded: &[u8]) -> Result<(Release, [u8; 32], [u8; 64]), String> {
    let outer = decode_canonical(encoded)?;
    let fields = array(&outer)?;
    if fields.len() != 3 {
        return Err("ReleaseV1 wrapper has the wrong field count".to_owned());
    }
    let prefix = array(&fields[0])?;
    if prefix.len() != 15 || string(&prefix[0])? != "RLS1" || number(&prefix[1])? != 1 {
        return Err("ReleaseV1 prefix is invalid".to_owned());
    }
    let digest = fixed_bytes(&fields[1])?;
    let expected = domain_digest(RLS1_DOMAIN, &encode_value(&fields[0])?);
    if digest != expected {
        return Err("ReleaseV1 self-digest is invalid".to_owned());
    }
    let signature = fixed_bytes(&fields[2])?;
    let release = Release {
        attempt_id: fixed_bytes(&prefix[2])?,
        nonce: fixed_bytes(&prefix[3])?,
        ready_digest: fixed_bytes(&prefix[4])?,
        trs1_digest: fixed_bytes(&prefix[5])?,
        rvs1_digest: fixed_bytes(&prefix[6])?,
        apt1_digest: fixed_bytes(&prefix[7])?,
        trust_epoch: number(&prefix[8])?,
        revocation_epoch: number(&prefix[9])?,
        policy_epoch: number(&prefix[10])?,
        expected_readback_digest: fixed_bytes(&prefix[11])?,
        observed_readback_digest: fixed_bytes(&prefix[12])?,
        deadline_monotonic_ns: number(&prefix[13])?,
        runtime_key_id: string(&prefix[14])?,
    };
    if release.runtime_key_id.is_empty() || release.runtime_key_id.len() > 128 {
        return Err("ReleaseV1 runtime key ID is invalid".to_owned());
    }
    Ok((release, digest, signature))
}

pub fn verify_release_signature(
    digest: [u8; 32],
    signature: [u8; 64],
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    verifying_key
        .verify(
            &signature_preimage(digest),
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| format!("ReleaseV1 signature is invalid: {error}"))
}

pub fn proof_signing_key() -> SigningKey {
    SigningKey::from_bytes(&PROOF_SIGNING_KEY)
}

pub fn proof_digest(label: &str) -> [u8; 32] {
    *blake3::hash(label.as_bytes()).as_bytes()
}

fn encode_self_digested(prefix: Value, domain: &[u8]) -> Result<Vec<u8>, String> {
    let digest = domain_digest(domain, &encode_value(&prefix)?);
    encode_value(&Value::Array(vec![prefix, bytes(digest)]))
}

fn decode_self_digested(encoded: &[u8], magic: &str, domain: &[u8]) -> Result<Vec<Value>, String> {
    let outer = decode_canonical(encoded)?;
    let fields = array(&outer)?;
    if fields.len() != 2 {
        return Err(format!("{magic} wrapper has the wrong field count"));
    }
    let prefix = array(&fields[0])?;
    if prefix.len() < 2 || string(&prefix[0])? != magic || number(&prefix[1])? != 1 {
        return Err(format!("{magic} prefix is invalid"));
    }
    let actual: [u8; 32] = fixed_bytes(&fields[1])?;
    let expected = domain_digest(domain, &encode_value(&fields[0])?);
    if actual != expected {
        return Err(format!("{magic} self-digest is invalid"));
    }
    Ok(prefix.to_vec())
}

fn envelope_digest(encoded: &[u8]) -> Result<[u8; 32], String> {
    let value = decode_canonical(encoded)?;
    let fields = array(&value)?;
    if fields.len() < 2 {
        return Err("record wrapper is incomplete".to_owned());
    }
    fixed_bytes(&fields[1])
}

fn decode_canonical(encoded: &[u8]) -> Result<Value, String> {
    let mut reader = Cursor::new(encoded);
    let value: Value = ciborium::from_reader(&mut reader).map_err(|error| error.to_string())?;
    if usize::try_from(reader.position()).ok() != Some(encoded.len())
        || encode_value(&value)? != encoded
    {
        return Err("record is not deterministic canonical CBOR".to_owned());
    }
    Ok(value)
}

fn encode_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).map_err(|error| error.to_string())?;
    Ok(encoded)
}

fn domain_digest(domain: &[u8], encoded_prefix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(encoded_prefix);
    *hasher.finalize().as_bytes()
}

fn signature_preimage(digest: [u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(RLS1_SIGNATURE_DOMAIN.len() + digest.len());
    preimage.extend_from_slice(RLS1_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&digest);
    preimage
}

fn fd_identity(identity: FdIdentity) -> Value {
    Value::Array(vec![integer(identity.mount_id), integer(identity.inode)])
}

fn decode_fd_identity(value: &Value) -> Result<FdIdentity, String> {
    let fields = array(value)?;
    if fields.len() != 2 {
        return Err("FD identity has the wrong field count".to_owned());
    }
    Ok(FdIdentity {
        mount_id: number(&fields[0])?,
        inode: number(&fields[1])?,
    })
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes<const N: usize>(value: [u8; N]) -> Value {
    Value::Bytes(value.to_vec())
}

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn array(value: &Value) -> Result<&[Value], String> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("expected CBOR array".to_owned()),
    }
}

fn string(value: &Value) -> Result<String, String> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err("expected CBOR text".to_owned()),
    }
}

fn number(value: &Value) -> Result<u64, String> {
    match value {
        Value::Integer(value) => (*value)
            .try_into()
            .map_err(|_| "expected non-negative CBOR integer".to_owned()),
        _ => Err("expected CBOR integer".to_owned()),
    }
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], String> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| format!("expected {N} CBOR bytes")),
        _ => Err("expected CBOR bytes".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_parameters() -> LaunchParameters {
        LaunchParameters {
            attempt_id: [1; 16],
            nonce: [2; 32],
            sim1_digest: [3; 32],
            adapter_path: "/usr/bin/adapter".to_owned(),
            adapter_arguments: vec!["/usr/bin/adapter".to_owned(), "local".to_owned()],
            expected_fd_layout_digest: [4; 32],
        }
    }

    #[test]
    fn canonical_launch_parameters_round_trip() {
        let expected = launch_parameters();
        let encoded = encode_launch_parameters(&expected).expect("encode LPV1");
        assert_eq!(decode_launch_parameters(&encoded), Ok(expected));
    }

    #[test]
    fn changed_launch_parameters_digest_is_rejected() {
        let mut encoded = encode_launch_parameters(&launch_parameters()).expect("encode LPV1");
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(decode_launch_parameters(&encoded).is_err());
    }

    #[test]
    fn fd_layout_requires_ordered_unique_descriptors_and_closed_roles() {
        let valid = FdLayout {
            mode: 0,
            entries: vec![(3, 0), (4, 1)],
        };
        assert!(encode_fd_layout(&valid).is_ok());
        assert!(encode_fd_layout(&FdLayout {
            mode: 0,
            entries: vec![(4, 1), (3, 0)],
        })
        .is_err());
        assert!(encode_fd_layout(&FdLayout {
            mode: 0,
            entries: vec![(3, 2)],
        })
        .is_err());
    }

    #[test]
    fn canonical_ready_round_trip() {
        let ready = Ready {
            attempt_id: [1; 16],
            nonce: [2; 32],
            invocation_id: [3; 16],
            launcher_digest: [4; 32],
            launcher_identity: FdIdentity {
                mount_id: 5,
                inode: 6,
            },
            sim1_digest: [7; 32],
            adapter_digest: [8; 32],
            adapter_identity: FdIdentity {
                mount_id: 9,
                inode: 10,
            },
            launch_parameter_digest: [11; 32],
            expected_fd_layout_digest: [12; 32],
            observed_fd_layout_digest: [12; 32],
        };
        let encoded = encode_ready(&ready).expect("encode ReadyV1");
        assert_eq!(decode_ready(&encoded), Ok(ready));
    }

    #[test]
    fn signed_release_round_trip() {
        let signing_key = proof_signing_key();
        let release = Release {
            attempt_id: [1; 16],
            nonce: [2; 32],
            ready_digest: [3; 32],
            trs1_digest: [4; 32],
            rvs1_digest: [5; 32],
            apt1_digest: [6; 32],
            trust_epoch: 7,
            revocation_epoch: 8,
            policy_epoch: 9,
            expected_readback_digest: [10; 32],
            observed_readback_digest: [11; 32],
            deadline_monotonic_ns: 12,
            runtime_key_id: "proof-runtime-key".to_owned(),
        };
        let encoded = encode_release(&release, &signing_key).expect("encode ReleaseV1");
        let (actual, digest, signature) = decode_release(&encoded).expect("decode ReleaseV1");
        assert_eq!(actual, release);
        assert_eq!(
            verify_release_signature(digest, signature, &signing_key.verifying_key()),
            Ok(())
        );
        let mut changed_signature = signature;
        changed_signature[0] ^= 1;
        assert!(
            verify_release_signature(digest, changed_signature, &signing_key.verifying_key())
                .is_err()
        );
    }
}
