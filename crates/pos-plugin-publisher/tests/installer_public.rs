//! The signed Plugin release installer at the public seam (ADR-061 revision 2,
//! ADR-103 revision 4).
//!
//! Releases are signed and published by the #571 publisher into a real local
//! OCI store, trust evidence is built from independently encoded PTR1, PRV1,
//! and TPS1 records, and admission runs against the Memory adapter of the
//! Plugin trust policy registry through a call-recording spy. Every refusal
//! before the registry is checked against an observable-state-identical registry, an
//! empty `admit` log, and an unconsumed trusted wall source.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    plugin_revoked_key_id_v1, plugin_root_key_id_v1, PluginFloorKindV1,
    PluginTrustBridgeErrorV1, PluginTrustPolicyAnchorV1, TrustPolicyRootV1,
    TrustPolicySnapshotV1, PLUGIN_OPERATOR_ROLE_V1,
};
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::ScriptedTrustedWallSourceV1,
    CanonicalBytes, EntityId, ErasureContainmentGateV1, Event, EventDraft, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Kind, OwnerIdV1, TimelineId,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
};
use pos_crypto::plugin_manifest::{
    PluginArtifactInputV1, PluginDependencyInputV1, PluginReleaseDraftV1,
    PluginReleaseSignatureErrorV1, PluginSchemaInputV1,
};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, TrustedPluginRootAnchorV1,
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_crypto::signing::generate_keypair;
use pos_plugin_publisher::{
    install_plugin_release_v1, publish_plugin_release_v1, sign_plugin_release_v1,
    verify_plugin_release_historical_v1, ContentValidationV1, InstalledPluginReleaseV1,
    PluginInstallRequestV1, PluginReleaseInstallErrorV1, PublishedPluginReleaseV1,
    ReleaseSignatureMathV1, SigningKeyStateV1,
};
use pos_plugin_release::{
    build_oci_closure_v1, BundleAddressV1, LocalOciPublisherV1, PublishOutcomeV1,
    ReleaseClosureInputV1, ReleaseSourceErrorV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, ActiveReleaseV1, PluginTrustCommitOutcomeV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, RetainedPolicyStateV1,
    RetainedReleaseDecisionV1,
};
use sha2::{Digest as _, Sha256};

#[path = "support/spy_registry.rs"]
pub mod spy_registry;

use spy_registry::SpyRegistry;

type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = BoxResult<()>;
type Draft<'a> = PluginReleaseDraftV1<'a>;
type Installed = Result<InstalledPluginReleaseV1, PluginReleaseInstallErrorV1>;
type WallSource = ScriptedTrustedWallSourceV1;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const OWNER: &str = "publisher";
const OTHER_OWNER: &str = "other-a";
const SCOPE: &str = "scope";
const UTC: i64 = 50;
const TICK: u64 = 5;
const FAR_FUTURE: &str = "2030-01-01T00:00:00Z";
const ROOT_EXPIRES: i64 = 100;
const COMPONENT_BYTES: &[u8] = b"\0asm component";
const WIT_BYTES: &[u8] = b"wit archive";
const EVENT_SCHEMA: &[u8] = br#"{"$id":"event"}"#;
const STATE_SCHEMA: &[u8] = br#"{"$id":"state"}"#;
const PROVENANCE_BYTES: &[u8] = b"in-toto provenance";
const SBOM_BYTES: &[u8] = b"spdx sbom";
const LICENCE_BYTES: &[u8] = b"licence text";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";

// ---------------------------------------------------------------------------
// Release fixtures
// ---------------------------------------------------------------------------

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> BoxResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-installer-public-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }

    fn store(&self) -> BoxResult<LocalOciPublisherV1> {
        Ok(LocalOciPublisherV1::open(&self.0)?)
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        drop(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(0o700),
        ));
        drop(fs::remove_dir_all(&self.0));
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    digest
}

fn input(bytes: &[u8]) -> PluginArtifactInputV1<'_> {
    PluginArtifactInputV1 {
        bytes,
        sha256: sha256(bytes),
    }
}

fn schema(id: u32, document: &[u8]) -> PluginSchemaInputV1<'_> {
    PluginSchemaInputV1 {
        id,
        version: 1,
        artifact: input(document),
        max_bytes: 65_536,
    }
}

/// One release shape: who publishes which version, linked to which release.
#[derive(Clone, Copy)]
struct Shape {
    owner: &'static str,
    version: &'static str,
    previous: Option<[u8; 32]>,
}

impl Shape {
    const fn first() -> Self {
        Self {
            owner: OWNER,
            version: "1.0.0",
            previous: None,
        }
    }
}

/// A valid draft valid for UTC seconds `[40, 60)`.
fn make_draft<'a>(shape: Shape) -> BoxResult<Draft<'a>> {
    Ok(PluginReleaseDraftV1 {
        plugin_id: "plugin-a".to_owned(),
        release_version: shape.version.to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 1,
            required_features: vec!["clock".to_owned()],
        },
        component: input(COMPONENT_BYTES),
        wit: input(WIT_BYTES),
        event_schemas: vec![schema(1, EVENT_SCHEMA)],
        state_schema: schema(2, STATE_SCHEMA),
        configuration_schema: None,
        capabilities: vec![PluginCapabilityDescriptorV1 {
            capability_id: "kv".to_owned(),
            operation: "read".to_owned(),
            resource_pattern: "state/*".to_owned(),
            purpose: "Read Plugin state".to_owned(),
            audience: "plugin".to_owned(),
            required: true,
            max_calls: 10,
            max_request_bytes: 1_024,
            max_response_bytes: 2_048,
        }],
        budget: DeterministicBudgetV1 {
            memory_bytes: 65_536,
            fuel: 1 << 40,
            host_calls: 256,
            event_count: 24,
            event_bytes: 4_096,
            state_bytes: 4_096,
            log_calls: 24,
            log_bytes: 256,
        },
        dependencies: vec![PluginDependencyInputV1 {
            dependency_id: "dep".to_owned(),
            release_digest: [0x42; 32],
            min_minor: 0,
            max_minor: 0,
            required_features: vec!["clock".to_owned()],
            capability_ids: Vec::new(),
            class: 0,
        }],
        provenance: input(PROVENANCE_BYTES),
        sbom: input(SBOM_BYTES),
        licences: vec![input(LICENCE_BYTES)],
        owner: OwnerIdV1::new(shape.owner)?,
        not_before: 40,
        not_after: 60,
        previous_release_digest: shape.previous,
    })
}

/// The OCI closure of `pmf1` and the draft's artifacts, with an explicit
/// component layer so a test can bind a PMF1 to the wrong component bytes.
fn closure(draft: &Draft<'_>, pmf1: &[u8], component: &[u8]) -> BoxResult<VerifiedReleaseBundleV1> {
    let mut schemas = draft
        .event_schemas
        .iter()
        .map(|schema| schema.artifact.bytes)
        .collect::<Vec<_>>();
    schemas.push(draft.state_schema.artifact.bytes);
    Ok(build_oci_closure_v1(&ReleaseClosureInputV1 {
        pmf1,
        component,
        wit: draft.wit.bytes,
        schemas,
        provenance: draft.provenance.bytes,
        sbom: draft.sbom.bytes,
        licences: draft.licences.iter().map(|item| item.bytes).collect(),
        migration_fixtures: Vec::new(),
    })?)
}

fn address_of(outcome: PublishOutcomeV1) -> BundleAddressV1 {
    match outcome {
        PublishOutcomeV1::Published(address) | PublishOutcomeV1::AlreadyPublished(address) => {
            address
        }
    }
}

fn pmf1_digest(bundle: &VerifiedReleaseBundleV1) -> [u8; 32] {
    *blake3::hash(bundle.pmf1()).as_bytes()
}

// ---------------------------------------------------------------------------
// Trust evidence fixtures: independently encoded PTR1, PRV1, and TPS1
// ---------------------------------------------------------------------------

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

fn digest(bytes: &[u8]) -> [u8; 32] {
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

/// The public keys the terminal PTR1 lists.
#[derive(Clone, Copy)]
struct Policy {
    other: [u8; 32],
    publisher_one: [u8; 32],
    publisher_two: Option<[u8; 32]>,
}

/// The evaluation coordinates and the revocations of one evidence.
#[derive(Clone, Default)]
struct Spec {
    utc_offset: i64,
    revoked_epochs: Vec<u64>,
    revoked_artifacts: Vec<[u8; 32]>,
}

impl Spec {
    const fn utc(&self) -> i64 {
        UTC + self.utc_offset
    }
}

fn ptr1(policy: Policy) -> BoxResult<Vec<u8>> {
    let publisher = |owner: &str, epoch: u64, key: [u8; 32]| {
        Value::Array(vec![text(owner), unsigned(3), unsigned(epoch), bytes_value(key)])
    };
    let mut publishers = vec![
        publisher(OTHER_OWNER, 1, policy.other),
        publisher(OWNER, 1, policy.publisher_one),
    ];
    if let Some(key) = policy.publisher_two {
        publishers.push(publisher(OWNER, 2, key));
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
            Value::Array(vec![Value::Array(vec![text("plugin-a"), text(OWNER)])]),
        ],
        ROOT_SIGNATURE_DOMAIN,
    )
}

fn prv1(policy: Policy, root_digest: [u8; 32], spec: &Spec) -> BoxResult<Vec<u8>> {
    let mut epochs = spec.revoked_epochs.clone();
    epochs.sort_unstable();
    let keys = epochs
        .into_iter()
        .map(|epoch| {
            let key = match (epoch, policy.publisher_two) {
                (2, Some(key)) => key,
                _ => policy.publisher_one,
            };
            Value::Array(vec![
                text(OWNER),
                unsigned(3),
                unsigned(epoch),
                bytes_value(key),
                unsigned(TICK),
                unsigned(1),
                Value::Null,
            ])
        })
        .collect::<Vec<_>>();
    let mut digests = spec.revoked_artifacts.clone();
    digests.sort_unstable();
    let artifacts = digests
        .into_iter()
        .map(|digest| {
            Value::Array(vec![
                bytes_value(digest),
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
            unsigned(1),
            signed(0),
            signed(ROOT_EXPIRES),
            bytes_value(root_digest),
            Value::Null,
            unsigned(TICK),
            Value::Array(keys),
            Value::Array(artifacts),
        ],
        REVOCATION_SIGNATURE_DOMAIN,
    )
}

/// Verified evidence and the operator-signed TPS1 that exactly maps it.
struct Material {
    evidence: VerifiedPluginTrustEvidenceV1,
    tps1: Vec<u8>,
    utc: i64,
}

fn tps1(evidence: &VerifiedPluginTrustEvidenceV1) -> BoxResult<Vec<u8>> {
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
        previous_snapshot_digest: None,
        operator_signature: [0; 64],
    };
    snapshot.operator_signature = operator_signer()
        .sign(&snapshot.operator_signature_message_v1()?)
        .to_bytes();
    Ok(snapshot.to_canonical_cbor()?)
}

impl Policy {
    fn material(self, spec: &Spec) -> BoxResult<Material> {
        let root = ptr1(self)?;
        let revocation = prv1(self, digest(&root), spec)?;
        let anchor = TrustedPluginRootAnchorV1::new(SCOPE, digest(&root))?;
        let evidence = verify_plugin_trust_v1(
            &anchor,
            &[root.as_slice()],
            &[revocation.as_slice()],
            spec.utc(),
            TICK,
        )?;
        Ok(Material {
            tps1: tps1(&evidence)?,
            evidence,
            utc: spec.utc(),
        })
    }

    fn anchor(self) -> BoxResult<(PluginTrustPolicyAnchorV1, Vec<u8>)> {
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

fn wall(utc: i64) -> BoxResult<WallSource> {
    Ok(ScriptedTrustedWallSourceV1::from_micros([
        u64::try_from(utc)? * 1_000_000,
    ]))
}

fn activation(timeline: TimelineId, tag: u8) -> ActivationEventInputV1 {
    ActivationEventInputV1 {
        timeline,
        draft: EventDraft::new(
            EntityId::new(),
            Kind::new("plugin.activation.v1"),
            CanonicalBytes::from_vec(vec![tag]),
        ),
    }
}

// ---------------------------------------------------------------------------
// The world: keys, store, policy, and a provisioned spy registry
// ---------------------------------------------------------------------------

fn key_bytes(material: &SigningKeyMaterial) -> [u8; 32] {
    *material.public_verification_key().as_bytes()
}

fn register(
    keys: &mut KeyRegistryStateV1,
    owner: &str,
    epoch: u64,
) -> BoxResult<SigningKeyMaterial> {
    let (signing_key, _verifying_key) = generate_keypair();
    let material = SigningKeyMaterial::new(signing_key);
    keys.register_key(KeyRegistrationV1::new(
        KeyIdentityV1::new(OwnerIdV1::new(owner)?, KeyRoleV1::PluginReleaseSigning, epoch),
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    Ok(material)
}

struct World {
    root: PrivateRoot,
    store: LocalOciPublisherV1,
    keys: KeyRegistryStateV1,
    publisher: SigningKeyMaterial,
    other: SigningKeyMaterial,
    policy: Policy,
    anchor: PluginTrustPolicyAnchorV1,
    registry: SpyRegistry,
    timeline: TimelineId,
}

impl World {
    /// A world whose PTR1 lists the publisher's real epoch-1 key, and whose
    /// registry is provisioned from the matching genesis TPS1.
    fn new() -> BoxResult<Self> {
        Self::build(None, true)
    }

    /// `listed` replaces the key PTR1 lists for the publisher's epoch 1.
    fn build(listed: Option<[u8; 32]>, provision: bool) -> BoxResult<Self> {
        let root = PrivateRoot::new()?;
        let store = root.store()?;
        let mut keys = KeyRegistryStateV1::new();
        let publisher = register(&mut keys, OWNER, 1)?;
        let other = register(&mut keys, OTHER_OWNER, 1)?;
        let policy = Policy {
            other: key_bytes(&other),
            publisher_one: listed
                .unwrap_or_else(|| key_bytes(&publisher)),
            publisher_two: None,
        };
        let (anchor, genesis_tps1) = policy.anchor()?;
        let mut memory = MemoryStore::new();
        memory.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let timeline = memory.create_timeline("plugin-activation")?.id();
        let mut registry = SpyRegistry::new(memory);
        if provision {
            registry.provision(&anchor, &genesis_tps1)?;
        }
        Ok(Self {
            root,
            store,
            keys,
            publisher,
            other,
            policy,
            anchor,
            registry,
            timeline,
        })
    }

    /// Sign and publish a release by the publisher at epoch 1.
    fn publish(&mut self, shape: Shape) -> BoxResult<PublishedPluginReleaseV1> {
        Ok(publish_plugin_release_v1(
            &mut self.keys,
            &self.publisher,
            1,
            &make_draft(shape)?,
            &self.store,
        )?)
    }

    /// Publish arbitrary PMF1 bytes bound to the default draft's artifacts.
    fn publish_raw(&self, pmf1: &[u8], component: &[u8]) -> BoxResult<BundleAddressV1> {
        let bundle = closure(&make_draft(Shape::first())?, pmf1, component)?;
        Ok(address_of(self.store.publish(&bundle)?))
    }

    /// Publish the default draft with a PMF1 signature of the caller's choosing.
    fn publish_with_signature(
        &self,
        shape: Shape,
        signature: [u8; 64],
    ) -> BoxResult<BundleAddressV1> {
        let draft = make_draft(shape)?;
        let pmf1 = draft.unsigned()?.with_signature(1, signature)?;
        self.publish_raw(&pmf1, COMPONENT_BYTES)
    }

    /// The signature bytes of the other owner's own valid release.
    fn other_owner_signature(&mut self) -> BoxResult<[u8; 64]> {
        let shape = Shape {
            owner: OTHER_OWNER,
            ..Shape::first()
        };
        let signature =
            sign_plugin_release_v1(&mut self.keys, &self.other, 1, &make_draft(shape)?)?;
        Ok(*signature.signature())
    }

    fn material(&self) -> BoxResult<Material> {
        self.policy.material(&Spec::default())
    }

    fn install_with(
        &mut self,
        address: &BundleAddressV1,
        material: &Material,
        wall: &mut WallSource,
        tag: u8,
    ) -> Installed {
        install_plugin_release_v1(
            &self.store,
            address,
            &mut self.registry,
            wall,
            PluginInstallRequestV1 {
                anchor: &self.anchor,
                tps1_bytes: &material.tps1,
                evidence: &material.evidence,
                activation: activation(self.timeline, tag),
            },
        )
    }

    /// Install with the default evidence and a wall source at the evidence UTC.
    fn install(&mut self, address: &BundleAddressV1, tag: u8) -> BoxResult<Installed> {
        let material = self.material()?;
        let mut source = wall(material.utc)?;
        Ok(self.install_with(address, &material, &mut source, tag))
    }

    fn snapshot(&self, digests: &[[u8; 32]]) -> BoxResult<Snapshot> {
        let store = &self.registry.store;
        let mut decisions = Vec::new();
        for pmf1 in digests {
            decisions.push(store.retained_release_decision(SCOPE, *pmf1)?);
        }
        Ok(Snapshot {
            policy: store.retained_policy_state(SCOPE)?,
            ledger: store.ledger(SCOPE)?,
            decisions,
            active: store.active_release(SCOPE, "plugin-a")?,
            events: store.read(self.timeline, SeqRange::all())?,
        })
    }
}

/// Everything observable about the registry and the activation Timeline.
#[derive(Debug, PartialEq)]
struct Snapshot {
    policy: RetainedPolicyStateV1,
    ledger: Vec<PluginTrustLedgerRowV1>,
    decisions: Vec<Option<RetainedReleaseDecisionV1>>,
    active: Option<ActiveReleaseV1>,
    events: Vec<Event>,
}

/// The installation was refused before the registry: exactly `expected`, no
/// `admit` call, no clock sample, and an observable-state-identical registry.
fn assert_refused_before_registry(
    world: &mut World,
    address: &BundleAddressV1,
    material: &Material,
    expected: PluginReleaseInstallErrorV1,
) -> TestResult {
    let digests = [pmf1_digest(&world.store.read_verified(address)?)];
    let before = world.snapshot(&digests)?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(address, material, &mut source, 1);
    assert_eq!(result.err(), Some(expected));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

const fn signature_error() -> PluginReleaseInstallErrorV1 {
    PluginReleaseInstallErrorV1::Signature(PluginReleaseSignatureErrorV1::InvalidSignature)
}

const fn authorization_error(error: PluginTrustErrorV1) -> PluginReleaseInstallErrorV1 {
    PluginReleaseInstallErrorV1::Authorization(error)
}

// ---------------------------------------------------------------------------
// Positive installation
// ---------------------------------------------------------------------------

#[test]
fn installs_a_signed_release_and_returns_the_admission_and_execution_projection() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let bundle = world.store.read_verified(published.address())?;
    let installed = world
        .install(published.address(), 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    let decision = installed.admission().decision();
    assert_eq!(installed.admission().outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(decision.scope(), SCOPE);
    assert_eq!(decision.plugin_id(), "plugin-a");
    assert_eq!(decision.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(decision.release_digest(), published.release_digest());
    assert_eq!(decision.previous_release_digest(), None);
    assert_eq!(decision.trusted_utc_second(), UTC);
    assert_eq!(decision.tick(), TICK);
    // The execution projection is the one of the same PMF1 bytes.
    let execution = installed.execution();
    assert_eq!(execution.plugin_id(), "plugin-a");
    assert_eq!(execution.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(execution.release_digest(), published.release_digest());
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    assert!(execution.is_bound_to(&projection));
    // The signature fact names the exact signer and the resolved key.
    let signature = installed.release_signature();
    assert_eq!(signature.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(signature.release_digest(), published.release_digest());
    assert_eq!(signature.owner(), OwnerIdV1::new(OWNER)?);
    assert_eq!(signature.epoch(), 1);
    assert_eq!(
        signature.public_key(),
        world.key_bytes(&publisher)
    );
    // Content validation was explicitly not performed (#574).
    assert_eq!(installed.content_validation(), ContentValidationV1::NotPerformed);
    // One admit call, at the sampled UTC second and the evidence's own Tick.
    let material = world.material()?;
    assert_eq!(world.registry.admits.len(), 1);
    assert_eq!(world.registry.admits[0].utc, UTC);
    assert_eq!(world.registry.admits[0].tick, TICK);
    assert_eq!(world.registry.admits[0].tps1, material.tps1);
    assert_eq!(world.registry.admits[0].timeline, world.timeline);
    // The release is active and exactly one activation Event was appended.
    let active = world.registry.active_release(SCOPE, "plugin-a")?;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(pmf1_digest(&bundle))
    );
    assert_eq!(world.registry.store.read(world.timeline, SeqRange::all())?.len(), 1);
    Ok(())
}

#[test]
fn installing_the_same_release_twice_is_an_idempotent_replay() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let first = world
        .install(published.address(), 1)?
        .map_err(|error| format!("first install failed: {error}"))?;
    let digests = [pmf1_digest(&world.store.read_verified(published.address())?)];
    let before = world.snapshot(&digests)?;
    let second = world
        .install(published.address(), 1)?
        .map_err(|error| format!("second install failed: {error}"))?;
    assert_eq!(first.admission().outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(
        second.admission().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(second.admission().decision(), first.admission().decision());
    assert_eq!(second.execution(), first.execution());
    // A replay appends no Event, writes no ledger row, and repoints nothing.
    assert_eq!(world.snapshot(&digests)?, before);
    assert_eq!(world.registry.admits.len(), 2);
    Ok(())
}

#[test]
fn a_changed_activation_identity_for_the_same_release_conflicts() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    assert!(world.install(published.address(), 1)?.is_ok());
    let digests = [pmf1_digest(&world.store.read_verified(published.address())?)];
    let before = world.snapshot(&digests)?;
    let result = world.install(published.address(), 2)?;
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::ReleaseConflict
        ))
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// The release chain passes through typed
// ---------------------------------------------------------------------------

#[test]
fn the_release_chain_is_enforced_by_the_registry_and_passes_through() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    let installed = world
        .install(second.address(), 2)?
        .map_err(|error| format!("successor install failed: {error}"))?;
    assert_eq!(
        installed.admission().decision().previous_release_digest(),
        Some(first.release_digest())
    );
    // A release that is neither the active content nor its direct successor.
    let unlinked = world.publish(Shape {
        version: "3.0.0",
        ..Shape::first()
    })?;
    let digests = [
        pmf1_digest(&world.store.read_verified(unlinked.address())?),
        pmf1_digest(&world.store.read_verified(first.address())?),
    ];
    let before = world.snapshot(&digests)?;
    let refused = world.install(unlinked.address(), 3)?;
    let violation = PluginReleaseInstallErrorV1::Registry(
        PluginTrustPolicyRegistryErrorV1::ReleaseChainViolation,
    );
    assert_eq!(refused.err(), Some(violation));
    assert_eq!(world.snapshot(&digests)?, before);
    // Presenting the superseded release again with its original identity is a
    // replay: the active pointer stays on the successor.
    let replay = world
        .install(first.address(), 1)?
        .map_err(|error| format!("replay failed: {error}"))?;
    assert_eq!(
        replay.admission().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    let active = world.registry.active_release(SCOPE, "plugin-a")?;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(installed.admission().decision().pmf1_digest())
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry errors pass through typed
// ---------------------------------------------------------------------------

#[test]
fn every_registry_error_variant_passes_through_typed() -> TestResult {
    let errors = [
        PluginTrustPolicyRegistryErrorV1::MissingState,
        PluginTrustPolicyRegistryErrorV1::CorruptState,
        PluginTrustPolicyRegistryErrorV1::AnchorMismatch,
        PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable,
        PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed,
        PluginTrustPolicyRegistryErrorV1::ReleaseChainViolation,
        PluginTrustPolicyRegistryErrorV1::ReleaseConflict,
        PluginTrustPolicyRegistryErrorV1::UnknownRollbackTarget,
        PluginTrustPolicyRegistryErrorV1::NoActiveRelease,
        PluginTrustPolicyRegistryErrorV1::RollbackTargetActive,
        PluginTrustPolicyRegistryErrorV1::ActivationEventRejected,
        PluginTrustPolicyRegistryErrorV1::NestedTransaction,
        PluginTrustPolicyRegistryErrorV1::WalRequired,
        PluginTrustPolicyRegistryErrorV1::StorageBusy,
        PluginTrustPolicyRegistryErrorV1::StorageFailed,
        PluginTrustPolicyRegistryErrorV1::StorageIndeterminate,
        PluginTrustPolicyRegistryErrorV1::StorePoisoned,
        PluginTrustPolicyRegistryErrorV1::Bridge(PluginTrustBridgeErrorV1::EvaluationUtcMismatch),
        PluginTrustPolicyRegistryErrorV1::Floor(
            pos_conformance::PluginFloorErrorV1::Rollback(PluginFloorKindV1::Root),
        ),
        PluginTrustPolicyRegistryErrorV1::Trust(PluginTrustErrorV1::ArtifactRevoked),
    ];
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let digests = [pmf1_digest(&world.store.read_verified(published.address())?)];
    let before = world.snapshot(&digests)?;
    for error in errors {
        world.registry.forced = Some(error);
        let result = world.install(published.address(), 1)?;
        assert_eq!(result.err(), Some(PluginReleaseInstallErrorV1::Registry(error)));
        assert_eq!(world.snapshot(&digests)?, before);
    }
    assert_eq!(world.registry.admits.len(), errors.len());
    Ok(())
}

/// A real registry refusal, not a forced one: the sampled UTC second is below
/// the retained highest second (the policy snapshot carries that high-water
/// mark), and the observable registry state is identical before and after.
#[test]
fn a_real_registry_refusal_leaves_the_observable_state_identical() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    let digests = [pmf1_digest(&world.store.read_verified(second.address())?)];
    let before = world.snapshot(&digests)?;
    assert_eq!(before.policy.highest_trusted_utc_second(), Some(UTC));
    let earlier = world.policy.material(&Spec {
        utc_offset: -1,
        ..Spec::default()
    })?;
    let mut source = wall(earlier.utc)?;
    let result = world.install_with(second.address(), &earlier, &mut source, 2);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed
        ))
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn an_unprovisioned_registry_refuses_after_the_signature_verified() -> TestResult {
    let mut world = World::build(None, false)?;
    let published = world.publish(Shape::first())?;
    let result = world.install(published.address(), 1)?;
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::MissingState
        ))
    );
    assert_eq!(world.registry.admits.len(), 1);
    Ok(())
}

#[test]
fn the_registry_binds_the_sampled_second_to_the_evidence() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let digests = [pmf1_digest(&world.store.read_verified(published.address())?)];
    let before = world.snapshot(&digests)?;
    let material = world.material()?;
    let mut skewed = wall(UTC + 1)?;
    let result = world.install_with(published.address(), &material, &mut skewed, 1);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::Bridge(
                PluginTrustBridgeErrorV1::EvaluationUtcMismatch
            )
        ))
    );
    assert_eq!(world.registry.admits[0].utc, UTC + 1);
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn an_unavailable_trusted_clock_refuses_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let material = world.material()?;
    let mut exhausted = ScriptedTrustedWallSourceV1::from_micros([]);
    let result = world.install_with(published.address(), &material, &mut exhausted, 1);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable
        ))
    );
    assert!(world.registry.admits.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Signature refusals happen before the registry
// ---------------------------------------------------------------------------

#[test]
fn a_release_with_a_bad_signature_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let material = world.material()?;
    // Unsigned: the all-zero signature of an unsigned PMF1.
    let unsigned_release = world.publish_with_signature(Shape::first(), [0; 64])?;
    assert_refused_before_registry(&mut world, &unsigned_release, &material, signature_error())?;
    // One flipped bit of an otherwise valid signature.
    let valid = *sign_plugin_release_v1(
        &mut world.keys,
        &world.publisher,
        1,
        &make_draft(Shape::first())?,
    )?
    .signature();
    let mut flipped = valid;
    flipped[10] ^= 1;
    let flipped_release = world.publish_with_signature(Shape::first(), flipped)?;
    assert_refused_before_registry(&mut world, &flipped_release, &material, signature_error())?;
    // The other owner's valid signature spliced into the publisher's PMF1.
    let foreign = world.other_owner_signature()?;
    let foreign_release = world.publish_with_signature(Shape::first(), foreign)?;
    assert_refused_before_registry(&mut world, &foreign_release, &material, signature_error())?;
    // The control: the genuine signature installs.
    let genuine = world.publish_with_signature(Shape::first(), valid)?;
    assert!(world.install(&genuine, 1)?.is_ok());
    Ok(())
}

#[test]
fn a_release_signed_by_an_unlisted_key_is_refused_before_the_registry() -> TestResult {
    // PTR1 lists a different key for the publisher's epoch 1 than the one that signed.
    let mut world = World::build(Some([0x5a; 32]), true)?;
    let published = world.publish(Shape::first())?;
    let material = world.material()?;
    assert_refused_before_registry(&mut world, published.address(), &material, signature_error())
}

#[test]
fn signature_verification_precedes_the_registry_call() -> TestResult {
    let mut world = World::new()?;
    let forged = world.publish_with_signature(Shape::first(), [0x77; 64])?;
    let genuine = world.publish(Shape {
        version: "2.0.0",
        ..Shape::first()
    })?;
    // Even a registry that would fail every call is never reached by a bad signature.
    world.registry.forced = Some(PluginTrustPolicyRegistryErrorV1::StorageFailed);
    let refused = world.install(&forged, 1)?;
    assert_eq!(refused.err(), Some(signature_error()));
    assert!(world.registry.admits.is_empty());
    // A good signature reaches the registry, and its error is the one returned.
    let reached = world.install(genuine.address(), 1)?;
    assert_eq!(
        reached.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::StorageFailed
        ))
    );
    assert_eq!(world.registry.admits.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Authorization refusals happen before the signature and the registry
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_publisher_key_is_refused_before_signature_and_registry() -> TestResult {
    let mut world = World::new()?;
    let genuine = world.publish(Shape::first())?;
    let forged = world.publish_with_signature(
        Shape {
            version: "2.0.0",
            ..Shape::first()
        },
        [0x77; 64],
    )?;
    let revoked = world.policy.material(&Spec {
        revoked_epochs: vec![1],
        ..Spec::default()
    })?;
    let expected = authorization_error(PluginTrustErrorV1::PublisherKeyRevoked);
    assert_refused_before_registry(&mut world, genuine.address(), &revoked, expected.clone())?;
    // The authorization error outranks the signature error of a forged release.
    assert_refused_before_registry(&mut world, &forged, &revoked, expected)
}

#[test]
fn an_unlisted_publisher_epoch_is_refused_before_signature_and_registry() -> TestResult {
    let mut world = World::new()?;
    let second = register(&mut world.keys, OWNER, 2)?;
    let draft = make_draft(Shape::first())?;
    let published =
        publish_plugin_release_v1(&mut world.keys, &second, 2, &draft, &world.store)?;
    let material = world.material()?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        authorization_error(PluginTrustErrorV1::UnknownPublisherKey),
    )
}

#[test]
fn a_release_outside_its_validity_interval_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let expected = authorization_error(PluginTrustErrorV1::ManifestExpired);
    // The interval is [40, 60): 60 is expired and 39 is not yet valid.
    for offset in [10, -11] {
        let material = world.policy.material(&Spec {
            utc_offset: offset,
            ..Spec::default()
        })?;
        let address = published.address();
        assert_refused_before_registry(&mut world, address, &material, expected.clone())?;
    }
    Ok(())
}

#[test]
fn a_revoked_release_digest_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let material = world.policy.material(&Spec {
        revoked_artifacts: vec![published.release_digest()],
        ..Spec::default()
    })?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        authorization_error(PluginTrustErrorV1::ArtifactRevoked),
    )
}

#[test]
fn a_release_by_an_owner_without_the_grant_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let shape = Shape {
        owner: OTHER_OWNER,
        ..Shape::first()
    };
    let draft = make_draft(shape)?;
    let published =
        publish_plugin_release_v1(&mut world.keys, &world.other, 1, &draft, &world.store)?;
    let material = world.material()?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        authorization_error(PluginTrustErrorV1::PluginIdNotGranted),
    )
}

// ---------------------------------------------------------------------------
// Tampered or unreadable releases
// ---------------------------------------------------------------------------

#[test]
fn a_pmf1_that_does_not_bind_its_component_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let draft = make_draft(Shape::first())?;
    let pmf1 = draft.unsigned()?.with_signature(1, [0; 64])?;
    let mismatched = world.publish_raw(&pmf1, b"another component")?;
    let material = world.material()?;
    let digests = [pmf1_digest(&world.store.read_verified(&mismatched)?)];
    let before = world.snapshot(&digests)?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(&mismatched, &material, &mut source, 1);
    assert!(matches!(
        result,
        Err(PluginReleaseInstallErrorV1::Manifest(_))
    ));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn a_noncanonical_pmf1_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let garbage = world.publish_raw(b"not a PMF1", COMPONENT_BYTES)?;
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(&garbage, &material, &mut source, 1);
    assert!(matches!(
        result,
        Err(PluginReleaseInstallErrorV1::Manifest(_))
    ));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

fn overwrite_component(directory: &Path) -> BoxResult<usize> {
    let mut changed = 0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            changed += overwrite_component(&path)?;
        } else if fs::read(&path)? == COMPONENT_BYTES {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            fs::write(&path, vec![0x55; COMPONENT_BYTES.len()])?;
            changed += 1;
        }
    }
    Ok(changed)
}

#[test]
fn a_release_corrupted_in_the_store_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    assert!(overwrite_component(&world.root.0)? >= 1);
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(published.address(), &material, &mut source, 1);
    assert!(matches!(result, Err(PluginReleaseInstallErrorV1::Source(_))));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

#[test]
fn an_unknown_address_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let scratch = PrivateRoot::new()?;
    let other_store = scratch.store()?;
    let published = publish_plugin_release_v1(
        &mut world.keys,
        &world.publisher,
        1,
        &make_draft(Shape::first())?,
        &other_store,
    )?;
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(published.address(), &material, &mut source, 1);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Source(ReleaseSourceErrorV1::NotFound))
    );
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Historical validity is not current trust
// ---------------------------------------------------------------------------

#[test]
fn a_rotated_and_revoked_key_still_verifies_historically_but_is_not_installable() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let bundle = world.store.read_verified(published.address())?;
    // Rotate: a later epoch supersedes epoch 1 in the key registry.
    drop(register(&mut world.keys, OWNER, 2)?);
    let historical = verify_plugin_release_historical_v1(&bundle, &world.keys)?;
    assert_eq!(historical.signature(), ReleaseSignatureMathV1::Valid);
    assert_eq!(historical.key_state(), SigningKeyStateV1::Rotated);
    // Current trust evidence revokes the epoch-1 key: the installer refuses.
    let revoked = world.policy.material(&Spec {
        revoked_epochs: vec![1],
        ..Spec::default()
    })?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &revoked,
        authorization_error(PluginTrustErrorV1::PublisherKeyRevoked),
    )
}
