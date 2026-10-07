//! Shared Plugin trust policy registry fixtures (ADR-103 revision 4).
//!
//! One [`Env`] is one policy scope with an operator key, a PTR1 root key, and
//! publisher keys. [`Spec`] picks the PTR1/PRV1 chain shape and the evaluation
//! coordinates, [`TpsSpec`] picks the TPS1 content, and [`Material`] bundles
//! the verified evidence with the matching operator-signed TPS1. Every digest
//! here is recomputed from the public encodings, independently of the registry.
//! The public tests and the adapter unit tests include this one file; the
//! items are public so that no test crate sees them as unused.
//!
//! [`Backend`] abstracts the store under test, so the shared vectors run unchanged on the
//! Memory adapter and on the `SQLite` adapter: [`Harness`] is generic over it and defaults to
//! `MemoryStore`, and [`Guard`] keeps the `SQLite` file's temporary directory alive.

use std::{error::Error, sync::Arc};

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    plugin_revoked_key_id_v1, plugin_root_key_id_v1, MinimumArtifactVersionV1,
    PluginTrustPolicyAnchorV1, TrustPolicyRootV1, TrustPolicySnapshotV1, PLUGIN_OPERATOR_ROLE_V1,
};
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::ScriptedTrustedWallSourceV1,
    CanonicalBytes, EntityId, ErasureContainmentGateV1, Event, EventDraft, Hasher, Kind,
    OwnerIdV1, TimelineId,
};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginManifestProjectionFixtureV1, TrustedPluginRootAnchorV1,
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;
use pos_store::{
    memory::MemoryStore,
    plugin_trust_registry::{
        ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
        PluginRollbackReceiptV1, PluginTrustLedgerRowV1, PluginTrustPolicyRegistryV1,
        PolicyAdvanceOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1,
        TrustedUtcSecondV1,
    },
};

pub use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1 as RegistryError;

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;
pub type Registry<T> = Result<T, RegistryError>;
pub type Pair = (u64, [u8; 32]);

/// The default evaluation UTC second and Tick.
pub const UTC: i64 = 50;
pub const TICK: u64 = 5;
/// The publisher owner every fixture manifest names.
pub const OWNER: &str = "publisher";
/// A TPS1 expiry far after every fixture UTC second.
pub const FAR_FUTURE: &str = "2030-01-01T00:00:00Z";

const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";
const ROOT_EXPIRES: i64 = 100;

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn signed(value: i64) -> Value {
    Value::Integer(value.into())
}

fn bytes_value(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// BLAKE3-256 of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// ADR-103 root key ID, recomputed from the public domain-separated encoding.
fn root_key_id(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/plugin-root-key-id/v1\0");
    hasher.update(&public);
    *hasher.finalize().as_bytes()
}

/// The operator signing key every fixture TPS1 uses.
#[must_use]
pub fn operator_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

/// The pinned operator verification key.
#[must_use]
pub fn operator_public() -> [u8; 32] {
    operator_signer().verifying_key().to_bytes()
}

fn root_signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn root_public() -> [u8; 32] {
    root_signer().verifying_key().to_bytes()
}

/// The public key of the `publisher` owner at key epoch 1 or 2.
#[must_use]
pub fn publisher_public(epoch: u64) -> [u8; 32] {
    let seed = if epoch == 1 { 8 } else { 10 };
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn other_publisher_public() -> [u8; 32] {
    SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
}

fn signed_record(mut fields: Vec<Value>, domain: &[u8]) -> TestResult<Vec<u8>> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&encode(&Value::Array(fields.clone()))?);
    fields.push(Value::Array(vec![Value::Array(vec![
        bytes_value(root_key_id(root_public())),
        Value::Bytes(root_signer().sign(&message).to_bytes().to_vec()),
    ])]));
    encode(&Value::Array(fields))
}

/// The PTR1/PRV1 chain shape and the evaluation coordinates of one evidence.
#[derive(Clone, Debug)]
pub struct Spec {
    /// Terminal PTR1 version; the chain holds this many records.
    pub roots: u64,
    /// Changes the digest of every non-genesis PTR1 record.
    pub root_variant: u8,
    /// Terminal PRV1 epoch; the chain holds this many records.
    pub epochs: u64,
    /// Changes the digest of every PRV1 record.
    pub revocation_variant: u8,
    /// Publisher key epochs the terminal PRV1 revokes, effective at `revocation_tick`.
    pub revoked_publisher_epochs: Vec<u64>,
    /// Artifact digests the terminal PRV1 revokes, effective at `revocation_tick`.
    pub revoked_artifacts: Vec<[u8; 32]>,
    /// The Tick at which the revocations become effective.
    pub revocation_tick: u64,
    /// The evaluation UTC second.
    pub utc: i64,
    /// The evaluation Tick.
    pub tick: u64,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            roots: 1,
            root_variant: 0,
            epochs: 1,
            revocation_variant: 0,
            revoked_publisher_epochs: Vec::new(),
            revoked_artifacts: Vec::new(),
            revocation_tick: TICK,
            utc: UTC,
            tick: TICK,
        }
    }
}

impl Spec {
    /// The same chain evaluated at other coordinates.
    #[must_use]
    pub fn at(&self, utc: i64, tick: u64) -> Self {
        Self {
            utc,
            tick,
            ..self.clone()
        }
    }
}

fn ptr1(scope: &str, version: u64, previous: Option<[u8; 32]>, variant: u8) -> TestResult<Vec<u8>> {
    let publisher = |epoch: u64| {
        Value::Array(vec![
            Value::Text(OWNER.to_owned()),
            unsigned(3),
            unsigned(epoch),
            bytes_value(publisher_public(epoch)),
        ])
    };
    let other = Value::Array(vec![
        Value::Text("other-a".to_owned()),
        unsigned(3),
        unsigned(1),
        bytes_value(other_publisher_public()),
    ]);
    let grant = |plugin_id: &str| {
        Value::Array(vec![
            Value::Text(plugin_id.to_owned()),
            Value::Text(OWNER.to_owned()),
        ])
    };
    let expires = if version == 1 {
        ROOT_EXPIRES
    } else {
        ROOT_EXPIRES + i64::from(variant)
    };
    signed_record(
        vec![
            Value::Text("PTR1".to_owned()),
            unsigned(1),
            Value::Text(scope.to_owned()),
            unsigned(version),
            signed(0),
            signed(expires),
            previous.map_or(Value::Null, bytes_value),
            unsigned(1),
            Value::Array(vec![Value::Array(vec![
                bytes_value(root_key_id(root_public())),
                bytes_value(root_public()),
            ])]),
            Value::Array(vec![other, publisher(1), publisher(2)]),
            Value::Array(vec![
                grant("plugin-a"),
                grant("plugin-b"),
                grant("plugin-c"),
            ]),
        ],
        ROOT_SIGNATURE_DOMAIN,
    )
}

struct RevocationRecord<'a> {
    scope: &'a str,
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
    spec: &'a Spec,
    terminal: bool,
}

fn prv1(record: &RevocationRecord<'_>) -> TestResult<Vec<u8>> {
    let spec = record.spec;
    let (keys, artifacts) = if record.terminal {
        let mut epochs = spec.revoked_publisher_epochs.clone();
        epochs.sort_unstable();
        let mut digests = spec.revoked_artifacts.clone();
        digests.sort_unstable();
        (
            epochs
                .into_iter()
                .map(|epoch| {
                    Value::Array(vec![
                        Value::Text(OWNER.to_owned()),
                        unsigned(3),
                        unsigned(epoch),
                        bytes_value(publisher_public(epoch)),
                        unsigned(spec.revocation_tick),
                        unsigned(1),
                        Value::Null,
                    ])
                })
                .collect::<Vec<_>>(),
            digests
                .into_iter()
                .map(|digest| {
                    Value::Array(vec![
                        bytes_value(digest),
                        unsigned(spec.revocation_tick),
                        unsigned(1),
                        Value::Null,
                    ])
                })
                .collect::<Vec<_>>(),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    signed_record(
        vec![
            Value::Text("PRV1".to_owned()),
            unsigned(1),
            Value::Text(record.scope.to_owned()),
            unsigned(record.epoch),
            signed(0),
            signed(ROOT_EXPIRES + i64::from(spec.revocation_variant)),
            bytes_value(record.root_digest),
            record.previous.map_or(Value::Null, bytes_value),
            unsigned(spec.revocation_tick),
            Value::Array(keys),
            Value::Array(artifacts),
        ],
        REVOCATION_SIGNATURE_DOMAIN,
    )
}

/// The complete encoded PTR1 and PRV1 histories of one [`Spec`].
pub struct Chain {
    pub roots: Vec<Vec<u8>>,
    pub revocations: Vec<Vec<u8>>,
}

/// Build the histories of `spec`.
///
/// PRV1 record `k` names the PTR1 of version `min(k, roots)`: a root digest never moves to
/// an earlier root, and the terminal PRV1 names the terminal PTR1.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn chain(scope: &str, spec: &Spec) -> TestResult<Chain> {
    let mut roots: Vec<Vec<u8>> = Vec::new();
    for version in 1..=spec.roots {
        let previous = roots.last().map(|record| digest(record));
        let variant = if version == 1 { 0 } else { spec.root_variant };
        roots.push(ptr1(scope, version, previous, variant)?);
    }
    let mut revocations: Vec<Vec<u8>> = Vec::new();
    for epoch in 1..=spec.epochs {
        let previous = revocations.last().map(|record| digest(record));
        let version = epoch.min(spec.roots);
        let root = usize::try_from(version - 1)?;
        revocations.push(prv1(&RevocationRecord {
            scope,
            root_digest: digest(roots.get(root).ok_or("no root")?),
            epoch,
            previous,
            spec,
            terminal: epoch == spec.epochs,
        })?);
    }
    Ok(Chain { roots, revocations })
}

/// Verify the chain of `spec` at its own coordinates.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn evidence(scope: &str, spec: &Spec) -> TestResult<VerifiedPluginTrustEvidenceV1> {
    let built = chain(scope, spec)?;
    let genesis = built.roots.first().ok_or("no genesis")?;
    let anchor = TrustedPluginRootAnchorV1::new(scope, digest(genesis))?;
    let roots = built.roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let revocations = built
        .revocations
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    Ok(verify_plugin_trust_v1(
        &anchor,
        &roots,
        &revocations,
        spec.utc,
        spec.tick,
    )?)
}

/// The TPS1 content beyond the mapping the evidence dictates.
#[derive(Clone, Debug)]
pub struct TpsSpec {
    pub previous: Option<[u8; 32]>,
    pub position: u64,
    pub offline_valid_through: String,
    /// Operator-signed artifact denials PRV1 does not list.
    pub extra_artifacts: Vec<[u8; 32]>,
    /// Adds a non-`ptr1-` root, a non-`pkr1-` revoked key ID, and a minimum version.
    pub extras: bool,
}

impl Default for TpsSpec {
    fn default() -> Self {
        Self {
            previous: None,
            position: 9,
            offline_valid_through: FAR_FUTURE.to_owned(),
            extra_artifacts: Vec::new(),
            extras: false,
        }
    }
}

impl TpsSpec {
    /// A TPS1 that names `previous` as its predecessor.
    #[must_use]
    pub fn after(previous: [u8; 32]) -> Self {
        Self {
            previous: Some(previous),
            ..Self::default()
        }
    }
}

/// The operator-signed TPS1 that exactly maps `evidence`.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn tps1(
    scope: &str,
    evidence: &VerifiedPluginTrustEvidenceV1,
    spec: &TpsSpec,
) -> TestResult<Vec<u8>> {
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
    let mut revoked_key_ids = evidence
        .effective_key_revocations()
        .map(|(owner, epoch, public_key)| plugin_revoked_key_id_v1(&owner, epoch, public_key))
        .collect::<Vec<_>>();
    let mut revoked_artifact_digests = evidence
        .effective_artifact_revocations()
        .chain(spec.extra_artifacts.iter().copied())
        .collect::<Vec<_>>();
    let mut minimum_versions = Vec::new();
    if spec.extras {
        trust_roots.push(TrustPolicyRootV1 {
            key_id: "global.root".to_owned(),
            root_version: 4,
            algorithm: "Ed25519".to_owned(),
            public_key: [0x55; 32],
        });
        revoked_key_ids.push("legacy.key".to_owned());
        minimum_versions.push(MinimumArtifactVersionV1 {
            artifact_kind: "plugin".to_owned(),
            semantic_version: "1.2.3".to_owned(),
        });
    }
    trust_roots.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    revoked_key_ids.sort();
    revoked_artifact_digests.sort_unstable();
    revoked_artifact_digests.dedup();
    let mut snapshot = TrustPolicySnapshotV1 {
        policy_id: scope.to_owned(),
        epoch: evidence.terminal_revocation().0,
        effective_timeline_position: spec.position,
        trust_roots,
        revoked_key_ids,
        revoked_artifact_digests,
        minimum_versions,
        offline_valid_through: spec.offline_valid_through.clone(),
        previous_snapshot_digest: spec.previous,
        operator_signature: [0; 64],
    };
    snapshot.operator_signature = operator_signer()
        .sign(&snapshot.operator_signature_message_v1()?)
        .to_bytes();
    Ok(snapshot.to_canonical_cbor()?)
}

/// Verified evidence and the operator-signed TPS1 that maps it.
pub struct Material {
    pub evidence: VerifiedPluginTrustEvidenceV1,
    pub tps1: Vec<u8>,
    pub utc: i64,
    pub tick: u64,
}

impl Material {
    /// A fixture value.
    #[must_use]
    pub fn tps1_digest(&self) -> [u8; 32] {
        digest(&self.tps1)
    }

    /// A fixture value.
    #[must_use]
    pub const fn terminal_root(&self) -> Pair {
        self.evidence.terminal_root()
    }

    /// A fixture value.
    #[must_use]
    pub const fn terminal_revocation(&self) -> Pair {
        self.evidence.terminal_revocation()
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn trusted(&self) -> TestResult<TrustedUtcSecondV1> {
        trusted(self.utc)
    }
}

/// One policy scope: its operator-pinned anchor and the genesis TPS1.
pub struct Env {
    pub scope: String,
    pub anchor: PluginTrustPolicyAnchorV1,
    pub genesis_tps1: Vec<u8>,
    pub genesis_root_digest: [u8; 32],
}

impl Env {
    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn new(scope: &str) -> TestResult<Self> {
        let genesis_tps1 = tps1(
            scope,
            &evidence(scope, &Spec::default())?,
            &TpsSpec::default(),
        )?;
        let genesis_root_digest = chain(scope, &Spec::default())?
            .roots
            .first()
            .map(|record| digest(record))
            .ok_or("no genesis")?;
        let anchor = PluginTrustPolicyAnchorV1::new(
            scope,
            genesis_root_digest,
            operator_public(),
            PLUGIN_OPERATOR_ROLE_V1,
            digest(&genesis_tps1),
        )?;
        Ok(Self {
            scope: scope.to_owned(),
            anchor,
            genesis_tps1,
            genesis_root_digest,
        })
    }

    /// Anchors for this scope that differ from the real one in exactly one field each:
    /// the PTR1 genesis digest, the operator key, and the genesis TPS1 digest.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn anchors_with_one_changed_field(&self) -> TestResult<Vec<PluginTrustPolicyAnchorV1>> {
        let foreign_operator = SigningKey::from_bytes(&[0x12; 32])
            .verifying_key()
            .to_bytes();
        let build = |ptr1: [u8; 32], operator: [u8; 32], genesis_tps1: [u8; 32]| {
            PluginTrustPolicyAnchorV1::new(
                &self.scope,
                ptr1,
                operator,
                PLUGIN_OPERATOR_ROLE_V1,
                genesis_tps1,
            )
        };
        let root = self.genesis_root_digest;
        let tps1 = self.anchor.genesis_tps1_digest();
        Ok(vec![
            build([9; 32], operator_public(), tps1)?,
            build(root, foreign_operator, tps1)?,
            build(root, operator_public(), [8; 32])?,
        ])
    }

    /// Evidence for `spec` and the TPS1 that maps it.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn material(&self, spec: &Spec, tps: &TpsSpec) -> TestResult<Material> {
        let evidence = evidence(&self.scope, spec)?;
        let tps1 = tps1(&self.scope, &evidence, tps)?;
        Ok(Material {
            evidence,
            tps1,
            utc: spec.utc,
            tick: spec.tick,
        })
    }

    /// The default genesis material: PTR1 version 1, PRV1 epoch 1, no denials.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn genesis(&self) -> TestResult<Material> {
        self.material(&Spec::default(), &TpsSpec::default())
    }
}

/// A fixture PMF1 projection: only the fields the registry reads.
#[derive(Clone, Debug)]
pub struct ManifestSpec {
    pub plugin_id: String,
    pub pmf1: u8,
    pub release: u8,
    pub previous: Option<u8>,
    pub epoch: u64,
    pub not_after: i64,
}

impl ManifestSpec {
    /// A fixture value.
    #[must_use]
    pub fn new(plugin_id: &str, pmf1: u8, release: u8, previous: Option<u8>) -> Self {
        Self {
            plugin_id: plugin_id.to_owned(),
            pmf1,
            release,
            previous,
            epoch: 1,
            not_after: 100,
        }
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn projection(&self) -> TestResult<ValidatedPluginManifestProjectionV1> {
        Ok(ValidatedPluginManifestProjectionV1::from(
            PluginManifestProjectionFixtureV1 {
                pmf1_digest: [self.pmf1; 32],
                plugin_id: self.plugin_id.clone(),
                owner: OwnerIdV1::new(OWNER)?,
                role: 3,
                epoch: self.epoch,
                not_before: 0,
                not_after: self.not_after,
                release_digest: [self.release; 32],
                previous_release_digest: self.previous.map(|previous| [previous; 32]),
                descriptor_digests: vec![[0x30; 32], [0x33; 32]],
            },
        ))
    }

    /// A fixture value.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        [self.pmf1; 32]
    }

    /// A fixture value.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        [self.release; 32]
    }
}

/// One trusted UTC second sampled through the sealed scripted wall source.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn trusted(second: i64) -> TestResult<TrustedUtcSecondV1> {
    let micros = u64::try_from(second)? * 1_000_000;
    Ok(TrustedUtcSecondV1::from_source(
        &mut ScriptedTrustedWallSourceV1::from_micros([micros]),
    )?)
}

/// An activation Event whose payload is `tag`; entity and correlation differ per call.
#[must_use]
pub fn activation(timeline: TimelineId, tag: u8) -> ActivationEventInputV1 {
    ActivationEventInputV1 {
        timeline,
        draft: EventDraft::new(
            EntityId::new(),
            Kind::new("plugin.activation.v1"),
            CanonicalBytes::from_vec(vec![tag]),
        ),
    }
}

/// The erasure gate a fixture store starts with.
pub enum Gate {
    /// A test-open gate that this handle also holds, so a test can block a Timeline.
    Bound(Arc<ErasureContainmentGateV1>),
    /// No gate at all: protected operations fail closed.
    Absent,
    /// The constructor's own fail-closed gate, never bound by a host.
    FailClosed,
}

impl Gate {
    /// A bound gate that admits every protected operation.
    #[must_use]
    pub fn open() -> Self {
        Self::Bound(Arc::new(ErasureContainmentGateV1::new_test_open()))
    }
}

/// Keeps the temporary directory of a file-backed fixture store alive; `None` for Memory.
pub struct Guard {
    pub directory: Option<tempfile::TempDir>,
}

/// A store under test: a Plugin trust registry that also appends and reads Events.
pub trait Backend: PluginTrustPolicyRegistryV1 + EventStore + Sized {
    /// A fresh store with `gate` and `hasher` (BLAKE3 when `None`).
    ///
    /// # Errors
    /// Returns the fixture construction error.
    fn build(gate: Gate, hasher: Option<Box<dyn Hasher>>) -> TestResult<(Self, Guard)>;
}

impl Backend for MemoryStore {
    fn build(gate: Gate, hasher: Option<Box<dyn Hasher>>) -> TestResult<(Self, Guard)> {
        let mut store = hasher.map_or_else(Self::new, Self::with_hasher);
        match gate {
            Gate::Bound(gate) => store.bind_erasure_gate(gate)?,
            Gate::Absent => store = store.without_erasure_gate(),
            Gate::FailClosed => {}
        }
        Ok((store, Guard { directory: None }))
    }
}

#[cfg(feature = "sqlite")]
impl Backend for SqliteStore {
    fn build(gate: Gate, hasher: Option<Box<dyn Hasher>>) -> TestResult<(Self, Guard)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("plugin-trust.db");
        let path = path.to_str().ok_or("the temporary path is not UTF-8")?;
        let mut store = match hasher {
            Some(hasher) => Self::open_with_hasher(path, hasher)?,
            None => Self::open(path)?,
        };
        match gate {
            Gate::Bound(gate) => store.bind_erasure_gate(gate)?,
            Gate::Absent => store = store.without_erasure_gate(),
            Gate::FailClosed => {}
        }
        Ok((
            store,
            Guard {
                directory: Some(directory),
            },
        ))
    }
}

/// A store with an open erasure gate and one activation Timeline.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn bound_store<B: Backend>() -> TestResult<(B, TimelineId, Guard)> {
    let (mut store, guard) = B::build(Gate::open(), None)?;
    let timeline = store.create_timeline("plugin-activation")?.id();
    Ok((store, timeline, guard))
}

/// The first release of `plugin-a`.
#[must_use]
pub fn release_one() -> ManifestSpec {
    ManifestSpec::new("plugin-a", 0x01, 0x11, None)
}

/// The direct successor of [`release_one`].
#[must_use]
pub fn release_two() -> ManifestSpec {
    ManifestSpec::new("plugin-a", 0x03, 0x12, Some(0x11))
}

/// The direct successor of [`release_two`].
#[must_use]
pub fn release_three() -> ManifestSpec {
    ManifestSpec::new("plugin-a", 0x05, 0x13, Some(0x12))
}

/// A chain of `roots` PTR1 records and `epochs` PRV1 records at the default coordinates.
#[must_use]
pub fn spec(roots: u64, epochs: u64) -> Spec {
    Spec {
        roots,
        epochs,
        ..Spec::default()
    }
}

/// A TPS1 that names `previous` as its predecessor.
#[must_use]
pub fn tps_after(previous: &Material) -> TpsSpec {
    TpsSpec::after(previous.tps1_digest())
}

/// Everything observable about one scope and its activation Timeline.
#[derive(Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub policy: RetainedPolicyStateV1,
    pub ledger: Vec<PluginTrustLedgerRowV1>,
    pub decisions: Vec<Option<RetainedReleaseDecisionV1>>,
    pub active: Vec<Option<ActiveReleaseV1>>,
    pub events: Vec<Event>,
}

/// One store with one provisioned scope and one activation Timeline.
///
/// `store` is declared before `guard`, so a file-backed store closes before its directory goes.
pub struct Harness<S = MemoryStore> {
    pub store: S,
    pub env: Env,
    pub timeline: TimelineId,
    pub guard: Guard,
}

impl Harness {
    /// A Memory harness.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn new() -> TestResult<Self> {
        Self::open()
    }
}

impl<S: Backend> Harness<S> {
    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn open() -> TestResult<Self> {
        let (mut store, timeline, guard) = bound_store::<S>()?;
        let env = Env::new("scope")?;
        store.provision(&env.anchor, &env.genesis_tps1)?;
        Ok(Self {
            store,
            env,
            timeline,
            guard,
        })
    }

    /// The default policy (PTR1 1, PRV1 1) evaluated at other coordinates.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn same_policy(&self, utc: i64, tick: u64) -> TestResult<Material> {
        self.env
            .material(&Spec::default().at(utc, tick), &TpsSpec::default())
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn admit_with(
        &mut self,
        material: &Material,
        manifest: &ManifestSpec,
        activation: ActivationEventInputV1,
    ) -> TestResult<Registry<AdmittedPluginReleaseReceiptV1>> {
        Ok(self.store.admit(
            &self.env.anchor,
            &material.tps1,
            &material.evidence,
            &manifest.projection()?,
            material.trusted()?,
            material.tick,
            activation,
        ))
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn admit(
        &mut self,
        material: &Material,
        manifest: &ManifestSpec,
        tag: u8,
    ) -> TestResult<Registry<AdmittedPluginReleaseReceiptV1>> {
        let input = activation(self.timeline, tag);
        self.admit_with(material, manifest, input)
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn advance(&mut self, material: &Material) -> TestResult<Registry<PolicyAdvanceOutcomeV1>> {
        Ok(self.store.advance_policy(
            &self.env.anchor,
            &material.tps1,
            &material.evidence,
            material.trusted()?,
            material.tick,
        ))
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn rollback_with(
        &mut self,
        material: &Material,
        target: &ManifestSpec,
        activation: ActivationEventInputV1,
    ) -> TestResult<Registry<PluginRollbackReceiptV1>> {
        Ok(self.store.rollback(
            &self.env.anchor,
            &material.tps1,
            &material.evidence,
            &target.projection()?,
            material.trusted()?,
            material.tick,
            activation,
        ))
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn rollback(
        &mut self,
        material: &Material,
        target: &ManifestSpec,
        tag: u8,
    ) -> TestResult<Registry<PluginRollbackReceiptV1>> {
        let input = activation(self.timeline, tag);
        self.rollback_with(material, target, input)
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn snapshot(&self, manifests: &[&ManifestSpec]) -> TestResult<Snapshot> {
        let scope = self.env.scope.as_str();
        let mut decisions = Vec::new();
        let mut active = Vec::new();
        for manifest in manifests {
            decisions.push(
                self.store
                    .retained_release_decision(scope, manifest.pmf1_digest())?,
            );
            active.push(self.store.active_release(scope, &manifest.plugin_id)?);
        }
        Ok(Snapshot {
            policy: self.store.retained_policy_state(scope)?,
            ledger: self.store.ledger(scope)?,
            decisions,
            active,
            events: self.store.read(self.timeline, SeqRange::all())?,
        })
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn events(&self) -> TestResult<Vec<Event>> {
        Ok(self.store.read(self.timeline, SeqRange::all())?)
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn policy(&self) -> TestResult<RetainedPolicyStateV1> {
        Ok(self.store.retained_policy_state(&self.env.scope)?)
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn ledger(&self) -> TestResult<Vec<PluginTrustLedgerRowV1>> {
        Ok(self.store.ledger(&self.env.scope)?)
    }

    /// A fixture step.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn active(&self, plugin_id: &str) -> TestResult<ActiveReleaseV1> {
        self.store
            .active_release(&self.env.scope, plugin_id)?
            .ok_or_else(|| "no active release".into())
    }

    /// Admit `manifest` and assert that exactly `expected` came back with nothing changed.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    ///
    /// # Panics
    /// Panics when the assertion fails.
    pub fn assert_admit_denied(
        &mut self,
        material: &Material,
        manifest: &ManifestSpec,
        expected: RegistryError,
    ) -> TestResult {
        let before = self.snapshot(&[manifest])?;
        assert_eq!(self.admit(material, manifest, 1)?, Err(expected));
        assert_eq!(self.snapshot(&[manifest])?, before);
        Ok(())
    }

    /// Roll back to `target` and assert that exactly `expected` came back with nothing changed.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    ///
    /// # Panics
    /// Panics when the assertion fails.
    pub fn assert_rollback_denied(
        &mut self,
        material: &Material,
        target: &ManifestSpec,
        expected: RegistryError,
    ) -> TestResult {
        let before = self.snapshot(&[target])?;
        assert_eq!(self.rollback(material, target, 1)?, Err(expected));
        assert_eq!(self.snapshot(&[target])?, before);
        Ok(())
    }

    /// Advance the policy and assert that exactly `expected` came back with nothing changed.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    ///
    /// # Panics
    /// Panics when the assertion fails.
    pub fn assert_advance_denied(
        &mut self,
        material: &Material,
        expected: RegistryError,
    ) -> TestResult {
        let before = self.snapshot(&[])?;
        assert_eq!(self.advance(material)?, Err(expected));
        assert_eq!(self.snapshot(&[])?, before);
        Ok(())
    }
}
