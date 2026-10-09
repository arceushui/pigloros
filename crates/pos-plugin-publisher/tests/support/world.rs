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

use std::sync::Arc;

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
    ActivationEventInputV1, ActiveReleaseV1, PluginRollbackReceiptV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1,
    RetainedPolicyStateV1, RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

use super::encoding::{Material, Policy, Revocations, Spec, OTHER_OWNER, OWNER, SCOPE, TICK};
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
    });
    next
}

/// Who may publish which Plugin, whether the PTR1 lists the real publisher key,
/// and whether the registry is provisioned.
#[derive(Clone, Copy)]
pub struct Config {
    /// The Plugin ID the PTR1 grants to the publisher.
    pub plugin_id: &'static str,
    /// The publisher owner. Must differ from `OTHER_OWNER`, whose epoch-1 key the world
    /// also registers: the same owner and epoch would be registered twice.
    pub owner: &'static str,
    /// Replaces the key the PTR1 lists for the publisher's epoch 1.
    pub listed_key: Option<[u8; 32]>,
    /// Whether to provision the registry from the genesis TPS1.
    pub provision: bool,
    /// Whether the PTR1 also lists an epoch-2 key for the publisher. The key is generated but
    /// not registered until `World::register_second_epoch`.
    pub second_epoch_key: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            plugin_id: Shape::first().plugin_id,
            owner: OWNER,
            listed_key: None,
            provision: true,
            second_epoch_key: false,
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
            owner: config.owner,
        };
        let (anchor, genesis_tps1) = policy.anchor()?;
        let mut memory = MemoryStore::new();
        memory.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let timeline = memory.create_timeline("plugin-activation")?.id();
        let mut registry = SpyRegistry::new(memory);
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

    /// Advance to `next`, chaining its TPS1 to the retained one. The world's
    /// current evidence follows only a committed advance.
    fn advance_to(&mut self, next: Spec) -> BoxResult<Registry<PolicyAdvanceOutcomeV1>> {
        let previous = Some(self.registry.retained_policy_state(SCOPE)?.tps1_digest());
        let material = self.policy.material_chained(&next, previous)?;
        let mut source = wall(material.utc)?;
        let utc = TrustedUtcSecondV1::from_source(&mut source)?;
        let advanced = self.registry.advance_policy(
            &self.anchor,
            &material.tps1,
            &material.evidence,
            utc,
            TICK,
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
            TICK,
            activation(self.timeline, tag),
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
