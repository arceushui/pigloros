use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, PluginTrustRootRecordV1, TrustedPluginRootAnchorV1,
};

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

#[test]
fn public_verifier_distinguishes_unknown_root_key_from_invalid_signature() -> TestResult {
    let ptr1 = hex_bytes(PTR1_HEX)?;
    let prv1 = hex_bytes(PRV1_HEX)?;
    let baseline_anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&ptr1))?;
    let evidence = verify_plugin_trust_v1(&baseline_anchor, &[&ptr1], &[&prv1], 0, 10)?;
    assert_eq!(
        evidence.verified_root_history().collect::<Vec<_>>(),
        vec![(42, digest(&ptr1))]
    );
    assert_eq!(
        evidence.verified_revocation_history().collect::<Vec<_>>(),
        vec![(7, digest(&prv1))]
    );
    let signature_start = ptr1.len() - 64;
    let signer_id_start = signature_start - 34;
    assert_eq!(&ptr1[signer_id_start - 2..signer_id_start], &[0x58, 0x20]);

    let mut unknown_signer = ptr1.clone();
    unknown_signer[signer_id_start] ^= 1;
    let unknown_anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&unknown_signer))?;
    assert!(matches!(
        verify_plugin_trust_v1(&unknown_anchor, &[&unknown_signer], &[&prv1], 0, 10),
        Err(PluginTrustErrorV1::UnknownRootKey)
    ));

    let mut invalid_signature = ptr1;
    let last_signature_byte = invalid_signature.last_mut().ok_or("empty PTR1")?;
    *last_signature_byte ^= 1;
    let invalid_anchor =
        TrustedPluginRootAnchorV1::new("trust.example", digest(&invalid_signature))?;
    assert!(matches!(
        verify_plugin_trust_v1(&invalid_anchor, &[&invalid_signature], &[&prv1], 0, 10),
        Err(PluginTrustErrorV1::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn verified_history_exposes_only_complete_authenticated_chains() -> TestResult {
    let genesis_root = root(1, None)?;
    let genesis_root_digest = digest(&genesis_root);
    let genesis_revocation = revocation(genesis_root_digest, 1, None)?;
    let genesis_revocation_digest = digest(&genesis_revocation);
    let next_root = root(2, Some(genesis_root_digest))?;
    let next_root_digest = digest(&next_root);
    let next_revocation = revocation(next_root_digest, 2, Some(genesis_revocation_digest))?;
    let next_revocation_digest = digest(&next_revocation);
    let anchor = TrustedPluginRootAnchorV1::new("scope", genesis_root_digest)?;

    let evidence = verify_plugin_trust_v1(
        &anchor,
        &[&genesis_root, &next_root],
        &[&genesis_revocation, &next_revocation],
        50,
        5,
    )?;
    assert_eq!(
        evidence.verified_root_history().collect::<Vec<_>>(),
        vec![(1, genesis_root_digest), (2, next_root_digest)]
    );
    assert_eq!(
        evidence.verified_revocation_history().collect::<Vec<_>>(),
        vec![(1, genesis_revocation_digest), (2, next_revocation_digest)]
    );
    assert_eq!(evidence.terminal_root(), (2, next_root_digest));
    assert_eq!(evidence.terminal_revocation(), (2, next_revocation_digest));

    let forked_root = root(2, Some([0xa5; 32]))?;
    assert!(matches!(
        verify_plugin_trust_v1(
            &anchor,
            &[&genesis_root, &forked_root],
            &[&genesis_revocation, &next_revocation],
            50,
            5,
        ),
        Err(PluginTrustErrorV1::DigestMismatch)
    ));
    let forked_revocation = revocation(next_root_digest, 2, Some([0xa5; 32]))?;
    assert!(matches!(
        verify_plugin_trust_v1(
            &anchor,
            &[&genesis_root, &next_root],
            &[&genesis_revocation, &forked_revocation],
            50,
            5,
        ),
        Err(PluginTrustErrorV1::DigestMismatch)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(
            &anchor,
            &[&next_root],
            &[&genesis_revocation, &next_revocation],
            50,
            5,
        ),
        Err(PluginTrustErrorV1::AnchorMismatch)
    ));
    Ok(())
}

#[test]
fn full_history_limits_are_lifetime_ceilings() -> TestResult {
    let genesis_root = root(1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&genesis_root))?;
    let mut roots = vec![genesis_root];
    for version in 2..=65 {
        let previous = digest(roots.last().ok_or("no PTR1")?);
        roots.push(root(version, Some(previous))?);
    }
    let terminal_root = digest(roots.get(63).ok_or("no 64th PTR1")?);
    let mut revocations = vec![revocation(terminal_root, 1, None)?];
    for epoch in 2..=257 {
        let previous = digest(revocations.last().ok_or("no PRV1")?);
        revocations.push(revocation(terminal_root, epoch, Some(previous))?);
    }
    let root_refs = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let revocation_refs = revocations.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence =
        verify_plugin_trust_v1(&anchor, &root_refs[..64], &revocation_refs[..256], 50, 5)?;
    assert_eq!(evidence.verified_root_history().count(), 64);
    assert_eq!(evidence.verified_revocation_history().count(), 256);
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &root_refs[..65], &revocation_refs[..256], 50, 5),
        Err(PluginTrustErrorV1::RootHistoryCapacityExceeded)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &root_refs[..64], &revocation_refs[..257], 50, 5),
        Err(PluginTrustErrorV1::RevocationHistoryCapacityExceeded)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &root_refs[1..64], &revocation_refs[..256], 50, 5),
        Err(PluginTrustErrorV1::AnchorMismatch)
    ));
    Ok(())
}

#[test]
fn empty_histories_fail_closed_without_evidence() -> TestResult {
    let genesis_root = root(1, None)?;
    let genesis_revocation = revocation(digest(&genesis_root), 1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&genesis_root))?;
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &[], &[&genesis_revocation], 50, 5),
        Err(PluginTrustErrorV1::ChainDiscontinuity)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &[&genesis_root], &[], 50, 5),
        Err(PluginTrustErrorV1::ChainDiscontinuity)
    ));
    Ok(())
}

#[test]
fn root_threshold_outside_one_to_thirty_two_fails_closed() -> TestResult {
    for threshold in [0, 33, 256, u64::MAX] {
        let mut fields = root_fields(
            1,
            None,
            vec![publisher_entry("publisher", 1, publisher_public())],
            vec![grant("plugin-a", "publisher")],
        );
        fields[7] = unsigned(threshold);
        let encoded = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&encoded),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
    }
    Ok(())
}
