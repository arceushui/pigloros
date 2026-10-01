// Shared PTR1/PRV1 record builders for the plugin trust integration tests.
//
// `tests/plugin_trust_public.rs` and `tests/plugin_release_query_public.rs`
// textually `include!` this file so both targets build records the same way
// without a crate-visible fixture API. It is not a test target itself.
use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/plugin_trust_vectors.rs"
));

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// ADR-103 root key ID, recomputed independently of the crate internals.
fn root_key_id(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/plugin-root-key-id/v1\0");
    hasher.update(&public);
    *hasher.finalize().as_bytes()
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes<const N: usize>(value: [u8; N]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// Sign the exact 11-field unsigned prefix and append the signature array.
fn signed_record(
    mut fields: Vec<Value>,
    domain: &[u8],
    signer: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&encode(&Value::Array(fields.clone()))?);
    let public = signer.verifying_key().to_bytes();
    fields.push(Value::Array(vec![Value::Array(vec![
        bytes(root_key_id(public)),
        bytes(signer.sign(&message).to_bytes()),
    ])]));
    encode(&Value::Array(fields))
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn publisher_public() -> [u8; 32] {
    SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()
}

fn publisher_entry(owner: &str, epoch: u64, public: [u8; 32]) -> Value {
    Value::Array(vec![
        Value::Text(owner.to_owned()),
        unsigned(3),
        unsigned(epoch),
        bytes(public),
    ])
}

fn grant(plugin_id: &str, owner: &str) -> Value {
    Value::Array(vec![
        Value::Text(plugin_id.to_owned()),
        Value::Text(owner.to_owned()),
    ])
}

/// PTR1 fields 0-10 for scope `scope`, valid for UTC seconds 0..100.
fn root_fields(
    version: u64,
    previous: Option<[u8; 32]>,
    publishers: Vec<Value>,
    grants: Vec<Value>,
) -> Vec<Value> {
    let public = signer().verifying_key().to_bytes();
    vec![
        Value::Text("PTR1".to_owned()),
        unsigned(1),
        Value::Text("scope".to_owned()),
        unsigned(version),
        unsigned(0),
        unsigned(100),
        previous.map_or(Value::Null, bytes),
        unsigned(1),
        Value::Array(vec![Value::Array(vec![
            bytes(root_key_id(public)),
            bytes(public),
        ])]),
        Value::Array(publishers),
        Value::Array(grants),
    ]
}

/// A PTR1 granting `plugin-a` to `publisher`, epoch 1.
fn root(version: u64, previous: Option<[u8; 32]>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_record(
        root_fields(
            version,
            previous,
            vec![publisher_entry("publisher", 1, publisher_public())],
            vec![grant("plugin-a", "publisher")],
        ),
        ROOT_SIGNATURE_DOMAIN,
        &signer(),
    )
}

/// PRV1 fields 0-10 for scope `scope`, valid for UTC seconds 0..100.
fn revocation_fields(
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
    tick: u64,
    keys: Vec<Value>,
    artifacts: Vec<Value>,
) -> Vec<Value> {
    vec![
        Value::Text("PRV1".to_owned()),
        unsigned(1),
        Value::Text("scope".to_owned()),
        unsigned(epoch),
        unsigned(0),
        unsigned(100),
        bytes(root_digest),
        previous.map_or(Value::Null, bytes),
        unsigned(tick),
        Value::Array(keys),
        Value::Array(artifacts),
    ]
}

/// An empty PRV1 with effective Tick 5.
fn revocation(
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_record(
        revocation_fields(root_digest, epoch, previous, 5, Vec::new(), Vec::new()),
        REVOCATION_SIGNATURE_DOMAIN,
        &signer(),
    )
}
