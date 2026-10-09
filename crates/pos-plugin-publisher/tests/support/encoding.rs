#![cfg(any(test, feature = "test-support"))]
//! Independent PTR1, PRV1, and TPS1 encoders and signers.
//!
//! Every record here is encoded from the public format and signed with
//! deterministic fixture keys, independently of the verifier and the registry
//! under test. A [`Policy`] picks the public keys the terminal PTR1 lists, a
//! [`Spec`] picks the evaluation coordinates and the revocations, and a
//! [`Material`] bundles the verified evidence with the operator-signed TPS1
//! that exactly maps it.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    plugin_revoked_key_id_v1, plugin_root_key_id_v1, PluginTrustPolicyAnchorV1, TrustPolicyRootV1,
    TrustPolicySnapshotV1, PLUGIN_OPERATOR_ROLE_V1,
};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, TrustedPluginRootAnchorV1, VerifiedPluginTrustEvidenceV1,
};

use super::BoxResult;

/// The default publisher owner of a world.
pub const OWNER: &str = "publisher";
/// The second owner, whose grant and keys the PTR1 also lists.
pub const OTHER_OWNER: &str = "other-a";
/// The policy scope of every fixture record.
pub const SCOPE: &str = "scope";
/// The default evaluation UTC second, inside the default release interval.
pub const UTC: i64 = 50;
/// The evaluation Tick, also the Tick at which every revocation takes effect.
pub const TICK: u64 = 5;

const FAR_FUTURE: &str = "2030-01-01T00:00:00Z";
const ROOT_EXPIRES: i64 = 100;
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn signed(value: i64) -> Value {
    Value::Integer(value.into())
}

fn bytes_value(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn encode(value: &Value) -> BoxResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// The BLAKE3 digest of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn root_key_id(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/plugin-root-key-id/v1\0");
    hasher.update(&public);
    *hasher.finalize().as_bytes()
}

fn operator_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn root_signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn root_public() -> [u8; 32] {
    root_signer().verifying_key().to_bytes()
}

fn signed_record(mut fields: Vec<Value>, domain: &[u8]) -> BoxResult<Vec<u8>> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&encode(&Value::Array(fields.clone()))?);
    fields.push(Value::Array(vec![Value::Array(vec![
        bytes_value(root_key_id(root_public())),
        Value::Bytes(root_signer().sign(&message).to_bytes().to_vec()),
    ])]));
    encode(&Value::Array(fields))
}

/// The public keys the terminal PTR1 lists, and who may publish what.
#[derive(Clone, Copy)]
pub struct Policy {
    /// The other owner's epoch-1 key.
    pub other: [u8; 32],
    /// The publisher's epoch-1 key.
    pub publisher_one: [u8; 32],
    /// The publisher's epoch-2 key, when the PTR1 lists one.
    pub publisher_two: Option<[u8; 32]>,
    /// The Plugin ID the PTR1 grants to the publisher.
    pub plugin_id: &'static str,
    /// The publisher owner.
    pub owner: &'static str,
}

/// The revocations one PRV1 record carries, cumulative over every earlier record.
#[derive(Clone, Debug, Default)]
pub struct Revocations {
    /// Publisher key epochs revoked.
    pub epochs: Vec<u64>,
    /// Release digests revoked.
    pub artifacts: Vec<[u8; 32]>,
}

/// The evaluation coordinates and the PRV1 history of one evidence.
///
/// The history is the `adopted` records, which are immutable once a registry has
/// retained them, followed by one terminal record carrying `revoked_epochs` and
/// `revoked_artifacts`.
#[derive(Clone, Default)]
pub struct Spec {
    /// Added to [`UTC`] to get the evaluation second.
    pub utc_offset: i64,
    /// Publisher key epochs the terminal PRV1 revokes.
    pub revoked_epochs: Vec<u64>,
    /// Release digests the terminal PRV1 revokes.
    pub revoked_artifacts: Vec<[u8; 32]>,
    /// The revocations of the PRV1 records before the terminal one, oldest first.
    pub adopted: Vec<Revocations>,
}

impl Spec {
    /// The evaluation UTC second.
    #[must_use]
    pub const fn utc(&self) -> i64 {
        UTC + self.utc_offset
    }
}

fn ptr1(policy: Policy) -> BoxResult<Vec<u8>> {
    let publisher = |owner: &str, epoch: u64, key: [u8; 32]| {
        Value::Array(vec![
            text(owner),
            unsigned(3),
            unsigned(epoch),
            bytes_value(key),
        ])
    };
    let mut publishers = vec![
        publisher(OTHER_OWNER, 1, policy.other),
        publisher(policy.owner, 1, policy.publisher_one),
    ];
    if let Some(key) = policy.publisher_two {
        publishers.push(publisher(policy.owner, 2, key));
    }
    signed_record(
        vec![
            text("PTR1"),
            unsigned(1),
            text(SCOPE),
            unsigned(1),
            signed(0),
            signed(ROOT_EXPIRES),
            Value::Null,
            unsigned(1),
            Value::Array(vec![Value::Array(vec![
                bytes_value(root_key_id(root_public())),
                bytes_value(root_public()),
            ])]),
            Value::Array(publishers),
            Value::Array(vec![Value::Array(vec![
                text(policy.plugin_id),
                text(policy.owner),
            ])]),
        ],
        ROOT_SIGNATURE_DOMAIN,
    )
}

fn prv1(
    policy: Policy,
    revocations: &Revocations,
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
) -> BoxResult<Vec<u8>> {
    let mut epochs = revocations.epochs.clone();
    epochs.sort_unstable();
    let keys = epochs
        .into_iter()
        .map(|revoked| {
            let key = match (revoked, policy.publisher_two) {
                (2, Some(key)) => key,
                _ => policy.publisher_one,
            };
            Value::Array(vec![
                text(policy.owner),
                unsigned(3),
                unsigned(revoked),
                bytes_value(key),
                unsigned(TICK),
                unsigned(1),
                Value::Null,
            ])
        })
        .collect::<Vec<_>>();
    let mut digests = revocations.artifacts.clone();
    digests.sort_unstable();
    let artifacts = digests
        .into_iter()
        .map(|revoked| {
            Value::Array(vec![
                bytes_value(revoked),
                unsigned(TICK),
                unsigned(1),
                Value::Null,
            ])
        })
        .collect::<Vec<_>>();
    signed_record(
        vec![
            text("PRV1"),
            unsigned(1),
            text(SCOPE),
            unsigned(epoch),
            signed(0),
            signed(ROOT_EXPIRES),
            bytes_value(root_digest),
            previous.map_or(Value::Null, bytes_value),
            unsigned(TICK),
            Value::Array(keys),
            Value::Array(artifacts),
        ],
        REVOCATION_SIGNATURE_DOMAIN,
    )
}

/// The PRV1 history of `spec`: the adopted records unchanged, then the terminal
/// record, each chained to the previous one by its full-byte digest.
fn revocation_chain(policy: Policy, spec: &Spec, root_digest: [u8; 32]) -> BoxResult<Vec<Vec<u8>>> {
    let terminal = Revocations {
        epochs: spec.revoked_epochs.clone(),
        artifacts: spec.revoked_artifacts.clone(),
    };
    let mut records: Vec<Vec<u8>> = Vec::new();
    for (index, revocations) in spec.adopted.iter().chain([&terminal]).enumerate() {
        let epoch = u64::try_from(index)? + 1;
        let previous = records.last().map(|record| digest(record));
        let record = prv1(policy, revocations, root_digest, epoch, previous)?;
        records.push(record);
    }
    Ok(records)
}

/// Verified evidence and the operator-signed TPS1 that exactly maps it.
pub struct Material {
    /// The verified PTR1/PRV1 evidence.
    pub evidence: VerifiedPluginTrustEvidenceV1,
    /// The TPS1 bytes mapping exactly that evidence.
    pub tps1: Vec<u8>,
    /// The evaluation UTC second the evidence was verified at.
    pub utc: i64,
}

impl Material {
    /// The BLAKE3 digest of the TPS1 bytes.
    #[must_use]
    pub fn tps1_digest(&self) -> [u8; 32] {
        digest(&self.tps1)
    }
}

fn tps1(
    evidence: &VerifiedPluginTrustEvidenceV1,
    previous: Option<[u8; 32]>,
) -> BoxResult<Vec<u8>> {
    let version = evidence.terminal_root().0;
    let mut trust_roots = evidence
        .terminal_root_keys()
        .map(|(key_id, public_key)| TrustPolicyRootV1 {
            key_id: plugin_root_key_id_v1(key_id),
            root_version: version,
            algorithm: "Ed25519".to_owned(),
            public_key,
        })
        .collect::<Vec<_>>();
    trust_roots.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    let mut revoked_key_ids = evidence
        .effective_key_revocations()
        .map(|(owner, epoch, public_key)| plugin_revoked_key_id_v1(&owner, epoch, public_key))
        .collect::<Vec<_>>();
    revoked_key_ids.sort();
    let mut revoked_artifact_digests = evidence
        .effective_artifact_revocations()
        .collect::<Vec<_>>();
    revoked_artifact_digests.sort_unstable();
    let mut snapshot = TrustPolicySnapshotV1 {
        policy_id: SCOPE.to_owned(),
        epoch: evidence.terminal_revocation().0,
        effective_timeline_position: 9,
        trust_roots,
        revoked_key_ids,
        revoked_artifact_digests,
        minimum_versions: Vec::new(),
        offline_valid_through: FAR_FUTURE.to_owned(),
        previous_snapshot_digest: previous,
        operator_signature: [0; 64],
    };
    snapshot.operator_signature = operator_signer()
        .sign(&snapshot.operator_signature_message_v1()?)
        .to_bytes();
    Ok(snapshot.to_canonical_cbor()?)
}

impl Policy {
    /// Evidence for `spec` and the genesis-shaped TPS1 that maps it.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn material(self, spec: &Spec) -> BoxResult<Material> {
        self.material_chained(spec, None)
    }

    /// Evidence for `spec` and the TPS1 that maps it and names `previous` as
    /// its predecessor snapshot.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn material_chained(self, spec: &Spec, previous: Option<[u8; 32]>) -> BoxResult<Material> {
        let root = ptr1(self)?;
        let revocations = revocation_chain(self, spec, digest(&root))?;
        let records = revocations.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let anchor = TrustedPluginRootAnchorV1::new(SCOPE, digest(&root))?;
        let evidence =
            verify_plugin_trust_v1(&anchor, &[root.as_slice()], &records, spec.utc(), TICK)?;
        Ok(Material {
            tps1: tps1(&evidence, previous)?,
            evidence,
            utc: spec.utc(),
        })
    }

    /// The registry anchor of this policy and its genesis TPS1 bytes.
    ///
    /// # Errors
    /// Returns the fixture construction or anchor error.
    pub fn anchor(self) -> BoxResult<(PluginTrustPolicyAnchorV1, Vec<u8>)> {
        let genesis = self.material(&Spec::default())?;
        let anchor = PluginTrustPolicyAnchorV1::new(
            SCOPE,
            digest(&ptr1(self)?),
            operator_signer().verifying_key().to_bytes(),
            PLUGIN_OPERATOR_ROLE_V1,
            digest(&genesis.tps1),
        )?;
        Ok((anchor, genesis.tps1))
    }
}
