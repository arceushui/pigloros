#![cfg(any(test, feature = "test-support"))]
//! Independent PTR1, PRV1, and TPS1 encoders and signers.
//!
//! Every record here is encoded from the public format and signed with
//! deterministic fixture keys, independently of the verifier and the registry
//! under test. A [`Policy`] picks the public keys the terminal PTR1 lists, a
//! [`Spec`] picks the evaluation coordinates and the revocations, and a
//! [`Material`] bundles the verified evidence with the operator-signed TPS1
//! that exactly maps it.

use std::collections::BTreeMap;

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
/// The default evaluation Tick, also the default Tick of every PRV1 record and so the Tick at which
/// every revocation takes effect.
pub const TICK: u64 = 5;

/// The default instant until which a TPS1 is valid offline, far beyond every fixture second.
pub const FAR_FUTURE: &str = "2030-01-01T00:00:00Z";
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
    /// Further Plugin IDs the PTR1 grants to the publisher, for a world that installs several
    /// Plugins into one registry.
    pub extra_plugin_ids: &'static [&'static str],
    /// The publisher owner.
    pub owner: &'static str,
    /// The instant (`YYYY-MM-DDTHH:MM:SSZ`) until which every TPS1 of the world is valid offline.
    pub tps1_valid_through: &'static str,
}

/// The revocations one PRV1 record carries, cumulative over every earlier record.
///
/// The verifier's Tick rules shape the encoding: a new entry takes the Tick of the record that
/// first lists it, carried entries keep theirs, and record Ticks are non-decreasing. A record
/// therefore carries one `tick`, and each entry's own Tick is derived from the history.
#[derive(Clone, Debug)]
pub struct Revocations {
    /// Publisher key epochs revoked.
    pub epochs: Vec<u64>,
    /// Release digests revoked.
    pub artifacts: Vec<[u8; 32]>,
    /// The Tick of this PRV1 record.
    pub tick: u64,
}

/// The evaluation coordinates and the PRV1 history of one evidence.
///
/// The history is the `adopted` records, which are immutable once a registry has
/// retained them, followed by one terminal record carrying `revoked_epochs` and
/// `revoked_artifacts`. Every entry takes the Tick of the record that first lists it.
#[derive(Clone)]
pub struct Spec {
    /// Added to [`UTC`] to get the evaluation second.
    pub utc_offset: i64,
    /// The evaluation Tick.
    pub tick: u64,
    /// The Tick of the terminal PRV1 record, and so of every entry it lists first. It must not
    /// be below the Tick of the last adopted record.
    pub record_tick: u64,
    /// Publisher key epochs the terminal PRV1 revokes.
    pub revoked_epochs: Vec<u64>,
    /// Release digests the terminal PRV1 revokes.
    pub revoked_artifacts: Vec<[u8; 32]>,
    /// The revocations of the PRV1 records before the terminal one, oldest first.
    pub adopted: Vec<Revocations>,
    /// Release digests that only the operator's TPS1 denies; no PRV1 record lists them.
    pub operator_denied: Vec<[u8; 32]>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            utc_offset: 0,
            tick: TICK,
            record_tick: TICK,
            revoked_epochs: Vec::new(),
            revoked_artifacts: Vec::new(),
            adopted: Vec::new(),
            operator_denied: Vec::new(),
        }
    }
}

impl Spec {
    /// The evaluation UTC second.
    #[must_use]
    pub const fn utc(&self) -> i64 {
        UTC + self.utc_offset
    }
}

/// The Plugin ID grants of the PTR1, strictly ascending by Plugin ID as the verifier requires.
fn grants(policy: Policy) -> Vec<Value> {
    let mut ids = vec![policy.plugin_id];
    ids.extend_from_slice(policy.extra_plugin_ids);
    ids.sort_unstable();
    ids.dedup();
    ids.into_iter()
        .map(|id| Value::Array(vec![text(id), text(policy.owner)]))
        .collect()
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
            Value::Array(grants(policy)),
        ],
        ROOT_SIGNATURE_DOMAIN,
    )
}

/// The Tick at which each revocation first appeared: the record Tick of the earliest record that
/// lists it. A carried entry keeps that Tick in every later record.
#[derive(Default)]
struct FirstSeen {
    epochs: BTreeMap<u64, u64>,
    artifacts: BTreeMap<[u8; 32], u64>,
}

impl FirstSeen {
    /// Record `revocations` as the next record: entries not seen before take its Tick.
    fn record(&mut self, revocations: &Revocations) {
        let tick = revocations.tick;
        for epoch in &revocations.epochs {
            self.epochs.entry(*epoch).or_insert(tick);
        }
        for artifact in &revocations.artifacts {
            self.artifacts.entry(*artifact).or_insert(tick);
        }
    }

    /// The Tick at which key epoch `epoch` first appeared.
    fn epoch_tick(&self, epoch: u64, default: u64) -> u64 {
        self.epochs.get(&epoch).copied().unwrap_or(default)
    }

    /// The Tick at which release digest `artifact` first appeared.
    fn artifact_tick(&self, artifact: [u8; 32], default: u64) -> u64 {
        self.artifacts.get(&artifact).copied().unwrap_or(default)
    }
}

fn prv1(
    policy: Policy,
    revocations: &Revocations,
    seen: &FirstSeen,
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
            let tick = seen.epoch_tick(revoked, revocations.tick);
            Value::Array(vec![
                text(policy.owner),
                unsigned(3),
                unsigned(revoked),
                bytes_value(key),
                unsigned(tick),
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
            let tick = seen.artifact_tick(revoked, revocations.tick);
            Value::Array(vec![
                bytes_value(revoked),
                unsigned(tick),
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
            unsigned(revocations.tick),
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
        tick: spec.record_tick,
    };
    let mut seen = FirstSeen::default();
    let mut records: Vec<Vec<u8>> = Vec::new();
    for (index, revocations) in spec.adopted.iter().chain([&terminal]).enumerate() {
        seen.record(revocations);
        let epoch = u64::try_from(index)? + 1;
        let previous = records.last().map(|record| digest(record));
        let record = prv1(policy, revocations, &seen, root_digest, epoch, previous)?;
        records.push(record);
    }
    Ok(records)
}

/// Verified evidence and the operator-signed TPS1 that exactly maps it, with the records and the
/// anchor the evidence was verified from.
pub struct Material {
    /// The verified PTR1/PRV1 evidence.
    pub evidence: VerifiedPluginTrustEvidenceV1,
    /// The TPS1 bytes mapping exactly that evidence.
    pub tps1: Vec<u8>,
    /// The evaluation UTC second the evidence was verified at.
    pub utc: i64,
    ptr1: Vec<u8>,
    prv1: Vec<Vec<u8>>,
    root_anchor: TrustedPluginRootAnchorV1,
}

impl Material {
    /// The BLAKE3 digest of the TPS1 bytes.
    #[must_use]
    pub fn tps1_digest(&self) -> [u8; 32] {
        digest(&self.tps1)
    }

    /// The raw bytes of the PTR1 record the evidence was verified from.
    #[must_use]
    pub fn ptr1(&self) -> &[u8] {
        &self.ptr1
    }

    /// The raw bytes of every PRV1 record, oldest first.
    #[must_use]
    pub fn prv1_records(&self) -> &[Vec<u8>] {
        &self.prv1
    }

    /// The operator-pinned PTR1 anchor the evidence was verified under.
    #[must_use]
    pub const fn root_anchor(&self) -> &TrustedPluginRootAnchorV1 {
        &self.root_anchor
    }
}

fn tps1(
    evidence: &VerifiedPluginTrustEvidenceV1,
    previous: Option<[u8; 32]>,
    operator_denied: &[[u8; 32]],
    valid_through: &str,
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
        .chain(operator_denied.iter().copied())
        .collect::<Vec<_>>();
    revoked_artifact_digests.sort_unstable();
    revoked_artifact_digests.dedup();
    let mut snapshot = TrustPolicySnapshotV1 {
        policy_id: SCOPE.to_owned(),
        epoch: evidence.terminal_revocation().0,
        effective_timeline_position: 9,
        trust_roots,
        revoked_key_ids,
        revoked_artifact_digests,
        minimum_versions: Vec::new(),
        offline_valid_through: valid_through.to_owned(),
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
        let tick = spec.tick;
        let evidence =
            verify_plugin_trust_v1(&anchor, &[root.as_slice()], &records, spec.utc(), tick)?;
        Ok(Material {
            tps1: tps1(
                &evidence,
                previous,
                &spec.operator_denied,
                self.tps1_valid_through,
            )?,
            evidence,
            utc: spec.utc(),
            ptr1: root,
            prv1: revocations,
            root_anchor: anchor,
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
