#![cfg(any(test, feature = "test-support"))]
//! The signed-release world: keys, a local OCI store, the trust policy, and a
//! provisioned spy registry.
//!
//! [`World`] publishes releases through the real publisher into a real local
//! OCI store, builds trust evidence from independently encoded PTR1, PRV1, and
//! TPS1 records, provisions the Memory adapter of the Plugin trust policy
//! registry from the matching genesis TPS1, and installs through the real
//! installer. It also steps the policy forward (key and release revocation)
//! and performs an operator rollback; both are test fixtures only, because
//! production has no entry point for either.

use std::sync::{atomic::AtomicU64, Arc};

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::ScriptedTrustedWallSourceV1,
    CanonicalBytes, EntityId, ErasureContainmentGateV1, Event, EventDraft, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Kind, OwnerIdV1, TimelineId,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;
use pos_crypto::signing::generate_keypair;
use pos_plugin_release::{BundleAddressV1, LocalOciPublisherV1, ReleaseSourceV1};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    CurrentReleaseEvaluationV1, PluginRollbackReceiptV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1,
    RetainedPolicyStateV1, RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

use super::encoding::{Material, Policy, Revocations, Spec, FAR_FUTURE, OTHER_OWNER, OWNER, SCOPE};
use super::release::{address_of, closure, make_draft, PrivateRoot, Shape};
use super::spy_registry::SpyRegistry;
use super::BoxResult;
use crate::{
    install_plugin_release_v1, publish_plugin_release_v1, sign_plugin_release_v1,
    InstalledPluginReleaseV1, PluginInstallRequestV1, PluginReleaseInstallErrorV1,
    PublishedPluginReleaseV1,
};

/// The result of one install call.
pub type Installed = Result<InstalledPluginReleaseV1, PluginReleaseInstallErrorV1>;
/// The scripted trusted wall source the installer samples.
pub type WallSource = ScriptedTrustedWallSourceV1;
/// A typed registry result.
pub type Registry<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

/// Added to the evaluation second, it lands on the first expired second of the
/// default `[40, 60)` validity interval.
pub const EXPIRED_UTC_OFFSET: i64 = 10;
/// Added to the evaluation second, it lands one second before the default
/// validity interval starts.
pub const NOT_YET_VALID_UTC_OFFSET: i64 = -11;

/// A wall source holding exactly one sample at `utc` seconds.
///
/// # Errors
/// Returns the conversion error for a negative second.
pub fn wall(utc: i64) -> BoxResult<WallSource> {
    Ok(ScriptedTrustedWallSourceV1::from_micros([u64::try_from(
        utc,
    )? * 1_000_000]))
}

/// A one-Event activation input on `timeline`, distinguished by `tag`.
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

/// The public verification key bytes of a signing key.
#[must_use]
pub const fn key_bytes(material: &SigningKeyMaterial) -> [u8; 32] {
    *material.public_verification_key().as_bytes()
}

/// Generate a Plugin release signing key and register it for `owner` at `epoch`.
///
/// # Errors
/// Returns the owner identifier or key registration error.
pub fn register(
    keys: &mut KeyRegistryStateV1,
    owner: &str,
    epoch: u64,
) -> BoxResult<SigningKeyMaterial> {
    let material = generate_key();
    register_key(keys, owner, epoch, &material)?;
    Ok(material)
}

/// A fresh Plugin release signing key that is not registered anywhere yet.
#[must_use]
pub fn generate_key() -> SigningKeyMaterial {
    let (signing_key, _verifying_key) = generate_keypair();
    SigningKeyMaterial::new(signing_key)
}

/// Register `material` as the Plugin release signing key of `owner` at `epoch`.
///
/// # Errors
/// Returns the owner identifier or key registration error.
pub fn register_key(
    keys: &mut KeyRegistryStateV1,
    owner: &str,
    epoch: u64,
    material: &SigningKeyMaterial,
) -> BoxResult<()> {
    keys.register_key(KeyRegistrationV1::new(
        KeyIdentityV1::new(
            OwnerIdV1::new(owner)?,
            KeyRoleV1::PluginReleaseSigning,
            epoch,
        ),
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    Ok(())
}

fn publish_signed(
    keys: &mut KeyRegistryStateV1,
    signer: &SigningKeyMaterial,
    store: &LocalOciPublisherV1,
    shape: Shape,
) -> BoxResult<PublishedPluginReleaseV1> {
    let draft = make_draft(shape)?;
    let published = publish_plugin_release_v1(keys, signer, shape.epoch, &draft, store)?;
    Ok(published)
}

/// `spec` with its terminal PRV1 record adopted as an immutable earlier record and a new
/// terminal record that so far carries the same revocations.
fn next_epoch(spec: &Spec) -> Spec {
    let mut next = spec.clone();
    next.adopted.push(Revocations {
        epochs: spec.revoked_epochs.clone(),
        artifacts: spec.revoked_artifacts.clone(),
        tick: spec.record_tick,
    });
    next
}

/// Who may publish which Plugin, whether the PTR1 lists the real publisher key,
/// whether the registry is provisioned, and the shared clock of the spy registry.
///
/// `Config` is `Clone` and not `Copy`, because the clock is an `Arc`; callers pass it by value.
#[derive(Clone)]
pub struct Config {
    /// The Plugin ID the PTR1 grants to the publisher.
    pub plugin_id: &'static str,
    /// The publisher owner. Must differ from `OTHER_OWNER`, whose epoch-1 key the world
    /// also registers: the same owner and epoch would be registered twice.
    pub owner: &'static str,
    /// Replaces the key the PTR1 lists for the publisher's epoch 1.
    pub listed_key: Option<[u8; 32]>,
    /// Further Plugin IDs the PTR1 grants to the publisher.
    pub extra_plugin_ids: &'static [&'static str],
    /// Whether to provision the registry from the genesis TPS1.
    pub provision: bool,
    /// Whether the PTR1 also lists an epoch-2 key for the publisher. The key is generated but
    /// not registered until `World::register_second_epoch`.
    pub second_epoch_key: bool,
    /// The clock the spy registry stamps its `evaluate_current_release` calls with; `None`
    /// builds the spy without a clock, so it records stamp 0.
    pub clock: Option<Arc<AtomicU64>>,
    /// The instant (`YYYY-MM-DDTHH:MM:SSZ`) until which every TPS1 is valid offline.
    pub tps1_valid_through: &'static str,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            plugin_id: Shape::first().plugin_id,
            owner: OWNER,
            listed_key: None,
            extra_plugin_ids: &[],
            provision: true,
            second_epoch_key: false,
            clock: None,
            tps1_valid_through: FAR_FUTURE,
        }
    }
}

/// Everything observable about the registry and the activation Timeline.
#[derive(Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// The retained policy state.
    pub policy: RetainedPolicyStateV1,
    /// The whole ledger.
    pub ledger: Vec<PluginTrustLedgerRowV1>,
    /// The retained decision of each asked-for PMF1 digest.
    pub decisions: Vec<Option<RetainedReleaseDecisionV1>>,
    /// The active release of the world's Plugin.
    pub active: Option<ActiveReleaseV1>,
    /// Every Event of the activation Timeline.
    pub events: Vec<Event>,
}

/// Keys, store, policy, and a provisioned spy registry.
pub struct World {
    /// The private root of the local OCI store.
    pub root: PrivateRoot,
    /// The local OCI store releases are published into.
    pub store: LocalOciPublisherV1,
    /// The Key registry state the publisher signs against.
    pub keys: KeyRegistryStateV1,
    /// The publisher's epoch-1 key.
    pub publisher: SigningKeyMaterial,
    /// The other owner's epoch-1 key.
    pub other: SigningKeyMaterial,
    /// The publisher's epoch-2 key, when the config asked for one.
    pub second: Option<SigningKeyMaterial>,
    /// The public keys and grants the PTR1 lists.
    pub policy: Policy,
    /// The registry anchor of the policy.
    pub anchor: PluginTrustPolicyAnchorV1,
    /// The Memory registry behind its call-recording spy.
    pub registry: SpyRegistry,
    /// The activation Timeline.
    pub timeline: TimelineId,
    /// The chain shape and revocations of the current evidence.
    pub spec: Spec,
    /// The digest of the TPS1 the current one succeeded, if any.
    pub previous: Option<[u8; 32]>,
}

impl World {
    /// A world whose PTR1 lists the publisher's real epoch-1 key, and whose
    /// registry is provisioned from the matching genesis TPS1.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn new() -> BoxResult<Self> {
        Self::with_config(Config::default())
    }

    /// `listed` replaces the key PTR1 lists for the publisher's epoch 1, and
    /// `provision` decides whether the registry is provisioned.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn build(listed: Option<[u8; 32]>, provision: bool) -> BoxResult<Self> {
        Self::with_config(Config {
            listed_key: listed,
            provision,
            ..Config::default()
        })
    }

    /// A default world whose spy registry stamps its evaluations from `clock`.
    ///
    /// The test creates the `Arc` once and shares it with every other recorder that must be
    /// ordered against the registry (it becomes the spy's `clock`).
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn with_clock(clock: Arc<AtomicU64>) -> BoxResult<Self> {
        Self::with_config(Config {
            clock: Some(clock),
            ..Config::default()
        })
    }

    /// A world for `config`.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn with_config(config: Config) -> BoxResult<Self> {
        let root = PrivateRoot::new()?;
        let store = root.store()?;
        let mut keys = KeyRegistryStateV1::new();
        let publisher = register(&mut keys, config.owner, 1)?;
        let other = register(&mut keys, OTHER_OWNER, 1)?;
        let second = config.second_epoch_key.then(generate_key);
        let policy = Policy {
            other: key_bytes(&other),
            publisher_one: config.listed_key.unwrap_or_else(|| key_bytes(&publisher)),
            publisher_two: second.as_ref().map(key_bytes),
            plugin_id: config.plugin_id,
            extra_plugin_ids: config.extra_plugin_ids,
            owner: config.owner,
            tps1_valid_through: config.tps1_valid_through,
        };
        let (anchor, genesis_tps1) = policy.anchor()?;
        let mut memory = MemoryStore::new();
        memory.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let timeline = memory.create_timeline("plugin-activation")?.id();
        let mut registry = SpyRegistry::new(memory);
        registry.clock = config.clock;
        if config.provision {
            registry.provision(&anchor, &genesis_tps1)?;
        }
        Ok(Self {
            root,
            store,
            keys,
            publisher,
            other,
            second,
            policy,
            anchor,
            registry,
            timeline,
            spec: Spec::default(),
            previous: None,
        })
    }

    /// The first release shape of this world's Plugin and publisher.
    #[must_use]
    pub const fn first_shape(&self) -> Shape {
        Shape {
            plugin_id: self.policy.plugin_id,
            owner: self.policy.owner,
            ..Shape::first()
        }
    }

    /// Sign and publish a release by the publisher at the shape's epoch.
    ///
    /// # Errors
    /// Returns the draft or publication error.
    pub fn publish(&mut self, shape: Shape) -> BoxResult<PublishedPluginReleaseV1> {
        publish_signed(&mut self.keys, &self.publisher, &self.store, shape)
    }

    /// Sign and publish a release with `signer`, registered for the shape's
    /// owner and epoch (see `register`).
    ///
    /// # Errors
    /// Returns the draft or publication error.
    pub fn publish_with(
        &mut self,
        signer: &SigningKeyMaterial,
        shape: Shape,
    ) -> BoxResult<PublishedPluginReleaseV1> {
        publish_signed(&mut self.keys, signer, &self.store, shape)
    }

    /// Register the epoch-2 key (see `Config::second_epoch_key`) for the publisher.
    ///
    /// # Errors
    /// Returns an error when the world has no epoch-2 key, or the registration error.
    pub fn register_second_epoch(&mut self) -> BoxResult<()> {
        let second = self.second.as_ref().ok_or("no epoch-2 key")?;
        register_key(&mut self.keys, self.policy.owner, 2, second)
    }

    /// Sign and publish a release with the epoch-2 key; the shape's epoch should be 2.
    ///
    /// # Errors
    /// Returns an error when the world has no epoch-2 key, or the draft or publication error.
    pub fn publish_second_epoch(&mut self, shape: Shape) -> BoxResult<PublishedPluginReleaseV1> {
        let second = self.second.as_ref().ok_or("no epoch-2 key")?;
        publish_signed(&mut self.keys, second, &self.store, shape)
    }

    /// Publish arbitrary PMF1 bytes bound to the default draft's artifacts.
    ///
    /// # Errors
    /// Returns the draft, closure, or store error.
    pub fn publish_raw(&self, pmf1: &[u8], component: &[u8]) -> BoxResult<BundleAddressV1> {
        let bundle = closure(&make_draft(Shape::first())?, pmf1, component)?;
        Ok(address_of(self.store.publish(&bundle)?))
    }

    /// Publish the default draft with a PMF1 signature of the caller's choosing.
    ///
    /// # Errors
    /// Returns the draft, signing-envelope, closure, or store error.
    pub fn publish_with_signature(
        &self,
        shape: Shape,
        signature: [u8; 64],
    ) -> BoxResult<BundleAddressV1> {
        let draft = make_draft(shape)?;
        let pmf1 = draft.unsigned()?.with_signature(shape.epoch, signature)?;
        self.publish_raw(&pmf1, shape.component)
    }

    /// The signature bytes of the other owner's own valid release.
    ///
    /// # Errors
    /// Returns the draft or signing error.
    pub fn other_owner_signature(&mut self) -> BoxResult<[u8; 64]> {
        let shape = Shape {
            owner: OTHER_OWNER,
            ..self.first_shape()
        };
        let signature =
            sign_plugin_release_v1(&mut self.keys, &self.other, 1, &make_draft(shape)?)?;
        Ok(*signature.signature())
    }

    /// The evidence of the current policy at the default coordinates.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn material(&self) -> BoxResult<Material> {
        self.policy.material_chained(&self.spec, self.previous)
    }

    /// The current policy evaluated one second past the default interval end.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn expired_material(&self) -> BoxResult<Material> {
        self.shifted_material(EXPIRED_UTC_OFFSET)
    }

    /// The current policy evaluated before the default interval starts.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn not_yet_valid_material(&self) -> BoxResult<Material> {
        self.shifted_material(NOT_YET_VALID_UTC_OFFSET)
    }

    fn shifted_material(&self, utc_offset: i64) -> BoxResult<Material> {
        let spec = Spec {
            utc_offset,
            ..self.spec.clone()
        };
        self.policy.material_chained(&spec, self.previous)
    }

    /// The current policy with the publisher key epochs revoked in evidence
    /// only; the registry is not advanced.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn key_revoked_material(&self, epochs: &[u64]) -> BoxResult<Material> {
        let spec = self.revoking_keys(epochs);
        self.policy.material_chained(&spec, self.previous)
    }

    /// The current policy with the release digests revoked in evidence only;
    /// the registry is not advanced.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn artifact_revoked_material(&self, digests: &[[u8; 32]]) -> BoxResult<Material> {
        let spec = self.revoking_artifacts(digests);
        self.policy.material_chained(&spec, self.previous)
    }

    fn revoking_keys(&self, epochs: &[u64]) -> Spec {
        let mut spec = self.spec.clone();
        spec.revoked_epochs.extend_from_slice(epochs);
        spec
    }

    fn revoking_artifacts(&self, digests: &[[u8; 32]]) -> Spec {
        let mut spec = self.spec.clone();
        spec.revoked_artifacts.extend_from_slice(digests);
        spec
    }

    /// Install with explicit evidence and wall source.
    ///
    /// # Errors
    /// Returns the installer's typed refusal.
    pub fn install_with(
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

    /// Install with the current evidence and a wall source at the evidence UTC.
    ///
    /// # Errors
    /// Returns the fixture construction error; the install result is the value.
    pub fn install(&mut self, address: &BundleAddressV1, tag: u8) -> BoxResult<Installed> {
        let material = self.material()?;
        let mut source = wall(material.utc)?;
        Ok(self.install_with(address, &material, &mut source, tag))
    }

    /// Advance the registry policy by one PRV1 epoch that revokes the
    /// publisher key `epochs`, keeping every earlier revocation.
    ///
    /// The new record and the evaluation keep the current Ticks.
    ///
    /// Test fixture only: production has no policy-advance entry point.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn advance_revoking_keys(
        &mut self,
        epochs: &[u64],
    ) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let mut next = next_epoch(&self.spec);
        next.revoked_epochs.extend_from_slice(epochs);
        self.advance_to(next)
    }

    /// Advance the registry policy by one PRV1 epoch that revokes the release
    /// `digests`, keeping every earlier revocation.
    ///
    /// The new record and the evaluation keep the current Ticks.
    ///
    /// Test fixture only: production has no policy-advance entry point.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn advance_revoking_artifacts(
        &mut self,
        digests: &[[u8; 32]],
    ) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let mut next = next_epoch(&self.spec);
        next.revoked_artifacts.extend_from_slice(digests);
        self.advance_to(next)
    }

    /// As [`Self::advance_revoking_artifacts()`], with the new PRV1 record at Tick
    /// `record_tick` (the Tick at which every new revocation takes effect) and the advance
    /// evaluated at Tick `tick`.
    ///
    /// A revocation with `record_tick` above `tick` is adopted before it is effective. The
    /// record Tick must not be below the Tick of the record before it.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn advance_revoking_artifacts_at(
        &mut self,
        digests: &[[u8; 32]],
        record_tick: u64,
        tick: u64,
    ) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let mut next = next_epoch(&self.spec);
        next.revoked_artifacts.extend_from_slice(digests);
        next.record_tick = record_tick;
        next.tick = tick;
        self.advance_to(next)
    }

    /// Advance the registry policy by one PRV1 epoch, with no new PRV1 revocation, whose TPS1
    /// also denies the release `digests`: a denial that only the operator's TPS1 carries.
    ///
    /// The TPS1 is adopted through `advance_policy` (the gate requires the supplied TPS1 to be
    /// the retained one byte for byte), and the world's current evidence follows it.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn advance_operator_denying(
        &mut self,
        digests: &[[u8; 32]],
    ) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let mut next = next_epoch(&self.spec);
        next.operator_denied.extend_from_slice(digests);
        self.advance_to(next)
    }

    /// Advance the registry policy by one PRV1 epoch with no new revocation, evaluated
    /// `utc_offset` seconds after the default second. The world's evidence follows it, so a
    /// later advance, install or evidence is built at that second.
    ///
    /// Test fixture only: production has no policy-advance entry point.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn advance_policy_at(
        &mut self,
        utc_offset: i64,
    ) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let mut next = next_epoch(&self.spec);
        next.utc_offset = utc_offset;
        self.advance_to(next)
    }

    /// Evidence and a valid TPS1 successor of the retained TPS1 for a PRV1 epoch that revokes
    /// the release `digests` at the record Tick `record_tick`, which the registry has not
    /// adopted. The world is left unchanged.
    ///
    /// # Errors
    /// Returns the fixture construction, registry read or trust verification error.
    pub fn unadopted_material(
        &self,
        digests: &[[u8; 32]],
        record_tick: u64,
    ) -> BoxResult<Material> {
        let (_, _, material) = self.unadopted_advance(digests, record_tick, self.spec.tick)?;
        Ok(material)
    }

    /// As [`Self::unadopted_material()`], evaluated at the Tick `tick`, with the `Spec` and the
    /// predecessor TPS1 digest it was built from.
    ///
    /// A test that adopts the material through the host's policy refresh (not through
    /// [`Self::advance_to()`]) then stores the returned pair in `spec` and `previous`, so that
    /// the world's current evidence follows the adoption.
    ///
    /// # Errors
    /// Returns the fixture construction, registry read or trust verification error.
    pub fn unadopted_advance(
        &self,
        digests: &[[u8; 32]],
        record_tick: u64,
        tick: u64,
    ) -> BoxResult<(Spec, Option<[u8; 32]>, Material)> {
        let previous = Some(self.registry.retained_policy_state(SCOPE)?.tps1_digest());
        let mut next = next_epoch(&self.spec);
        next.revoked_artifacts.extend_from_slice(digests);
        next.record_tick = record_tick;
        next.tick = tick;
        let material = self.policy.material_chained(&next, previous)?;
        Ok((next, previous, material))
    }

    /// The current evidence with its terminal PRV1 record forked: the same epoch, the same
    /// entries and the same TPS1 bytes, and a record Tick one higher, so the record digest
    /// differs from the retained one.
    ///
    /// The terminal record must list no revocation that no earlier record carries; otherwise
    /// that revocation's Tick moves too.
    ///
    /// # Errors
    /// Returns the fixture construction or trust verification error.
    pub fn forked_floor_material(&self) -> BoxResult<Material> {
        let spec = Spec {
            record_tick: self.spec.record_tick + 1,
            ..self.spec.clone()
        };
        self.policy.material_chained(&spec, self.previous)
    }

    /// Advance to `next`, chaining its TPS1 to the retained one, at the evaluation Tick
    /// `next.tick`. The world's current evidence follows only a committed advance.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn advance_to(&mut self, next: Spec) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let previous = Some(self.registry.retained_policy_state(SCOPE)?.tps1_digest());
        let material = self.policy.material_chained(&next, previous)?;
        let mut source = wall(material.utc)?;
        let utc = TrustedUtcSecondV1::from_source(&mut source)?;
        let advanced = self.registry.advance_policy(
            &self.anchor,
            &material.tps1,
            &material.evidence,
            utc,
            next.tick,
        );
        if advanced.is_ok() {
            self.spec = next;
            self.previous = previous;
        }
        Ok(advanced)
    }

    /// Operator rollback of the active release to the already admitted release
    /// at `target`, with the current evidence.
    ///
    /// Test fixture only: production has no rollback entry point.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn rollback_to(
        &mut self,
        target: &BundleAddressV1,
        tag: u8,
    ) -> BoxResult<Registry<PluginRollbackReceiptV1>> {
        let bundle = self.store.read_verified(target)?;
        let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
        let material = self.material()?;
        let mut source = wall(material.utc)?;
        let utc = TrustedUtcSecondV1::from_source(&mut source)?;
        Ok(self.registry.rollback(
            &self.anchor,
            &material.tps1,
            &material.evidence,
            &projection,
            utc,
            self.spec.tick,
            activation(self.timeline, tag),
        ))
    }

    /// Admit the release at `address` straight through the registry with the current evidence,
    /// bypassing the installer: no PMF1 signature is checked, because the registry does not
    /// check it (`registry` is a public field).
    ///
    /// Together with `publish_with_signature` it plants a release whose field 26 is invalid
    /// as the active release, which only the execution gate's own signature check refuses.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn admit_directly(
        &mut self,
        address: &BundleAddressV1,
        tag: u8,
    ) -> BoxResult<Registry<AdmittedPluginReleaseReceiptV1>> {
        let bundle = self.store.read_verified(address)?;
        let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
        let material = self.material()?;
        let utc = TrustedUtcSecondV1::from_source(&mut wall(material.utc)?)?;
        Ok(self.registry.admit(
            &self.anchor,
            &material.tps1,
            &material.evidence,
            &projection,
            utc,
            self.spec.tick,
            activation(self.timeline, tag),
        ))
    }

    /// Evaluate the release at `target` read-only through the spy registry with the current
    /// evidence, at the trusted UTC second `utc` and the Tick `tick`.
    ///
    /// The evidence is built at the default coordinates, so another `utc` or `tick` is refused
    /// by the registry's coordinate checks; the call is recorded either way.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn evaluate_at(
        &self,
        target: &BundleAddressV1,
        utc: i64,
        tick: u64,
    ) -> BoxResult<Registry<CurrentReleaseEvaluationV1>> {
        let bundle = self.store.read_verified(target)?;
        let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
        let material = self.material()?;
        let trusted = TrustedUtcSecondV1::from_source(&mut wall(utc)?)?;
        Ok(self.registry.evaluate_current_release(
            &self.anchor,
            &material.tps1,
            &material.evidence,
            &projection,
            trusted,
            tick,
        ))
    }

    /// Evaluate the release at `target` read-only with explicit `material` (not the world's
    /// current evidence), at the trusted UTC second `utc` and the Tick `tick`.
    ///
    /// # Errors
    /// Returns the fixture construction error; the registry result is the value.
    pub fn evaluate_material_at(
        &self,
        target: &BundleAddressV1,
        material: &Material,
        utc: i64,
        tick: u64,
    ) -> BoxResult<Registry<CurrentReleaseEvaluationV1>> {
        let bundle = self.store.read_verified(target)?;
        let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
        let trusted = TrustedUtcSecondV1::from_source(&mut wall(utc)?)?;
        Ok(self.registry.evaluate_current_release(
            &self.anchor,
            &material.tps1,
            &material.evidence,
            &projection,
            trusted,
            tick,
        ))
    }

    /// Everything observable about the registry and the activation Timeline,
    /// with the retained decision of each PMF1 digest in `digests`.
    ///
    /// # Errors
    /// Returns the registry or store read error.
    pub fn snapshot(&self, digests: &[[u8; 32]]) -> BoxResult<Snapshot> {
        let store = &self.registry.store;
        let mut decisions = Vec::new();
        for pmf1 in digests {
            decisions.push(store.retained_release_decision(SCOPE, *pmf1)?);
        }
        Ok(Snapshot {
            policy: store.retained_policy_state(SCOPE)?,
            ledger: store.ledger(SCOPE)?,
            decisions,
            active: store.active_release(SCOPE, self.policy.plugin_id)?,
            events: store.read(self.timeline, SeqRange::all())?,
        })
    }
}
