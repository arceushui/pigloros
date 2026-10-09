//! The community release install entry and its host-owned activation Event (ADR-061 revision 7
//! decision 9). Linux only, like the signed installer it wraps.
//!
//! The wrapper reads and projects the release closure once, builds the activation draft from
//! that projection, and hands the signed installer a one-shot source that holds the one bundle
//! it read. The installer therefore projects, checks the signature of and admits exactly the
//! bytes the payload describes. The wrapper never calls the registry's `admit` or `rollback`.

use std::cell::RefCell;

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::event::{CanonicalBytes, EventDraft, Kind};
use pos_core::ids::{EntityId, TimelineId};
use pos_core::trusted_clock::TrustedWallSourceV1;
use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
use pos_crypto::plugin_manifest::PluginManifestErrorV1;
use pos_crypto::plugin_trust::VerifiedPluginTrustEvidenceV1;
use pos_plugin_publisher::{
    install_plugin_release_v1, InstalledPluginReleaseV1, PluginInstallRequestV1,
    PluginReleaseInstallErrorV1,
};
use pos_plugin_release::{
    BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_store::plugin_trust_registry::{ActivationEventInputV1, PluginTrustPolicyRegistryV1};
use thiserror::Error;

use super::{cbor, PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

/// Where the activation Event of an install is committed: the Plugin Timeline the composition
/// owns for the scope, and the composition's host entity on it.
///
/// The Timeline is part of the registry's idempotency identity; the entity is not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationTargetV1 {
    /// The Timeline that hosts the activation Event.
    pub timeline: TimelineId,
    /// The composition's host entity on that Timeline.
    pub entity: EntityId,
}

/// The trusted inputs of one community release install.
///
/// They are the installer's request without the activation Event, which the wrapper builds, plus
/// the activation target.
#[derive(Debug)]
pub struct CommunityInstallRequestV1<'a> {
    /// The operator-pinned policy anchor of the scope.
    pub anchor: &'a PluginTrustPolicyAnchorV1,
    /// The signed canonical TPS1 bytes; the registry authenticates them.
    pub tps1_bytes: &'a [u8],
    /// The verified PTR1/PRV1 evidence; its coordinates are the transaction's.
    pub evidence: &'a VerifiedPluginTrustEvidenceV1,
    /// Where the activation Event goes.
    pub target: ActivationTargetV1,
}

/// A closed failure of the community release install entry.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CommunityInstallErrorV1 {
    /// The release source could not produce the verified closure.
    #[error(transparent)]
    Source(ReleaseSourceErrorV1),
    /// The closure's PMF1 failed strict decoding, binding, or digest checks.
    #[error(transparent)]
    Manifest(PluginManifestErrorV1),
    /// The signed installer refused the release.
    #[error(transparent)]
    Install(PluginReleaseInstallErrorV1),
}

/// Install the community release at `address`, committing its activation Event.
///
/// The closure is read once from `source`; the Plugin ID and the digests of the activation
/// payload come from its projection, and the installer receives that same bundle through a
/// one-shot source, so a source whose closure would change on a second read cannot affect the
/// install. Installing the same release again with the same evidence is the registry's
/// idempotent replay and appends no second Event.
///
/// # Errors
/// Returns `Source` when the closure cannot be read, `Manifest` when its PMF1 is not a canonical
/// V1 manifest, and `Install` for every refusal of the signed installer.
pub fn install_community_release_v1(
    source: &impl ReleaseSourceV1,
    address: &BundleAddressV1,
    registry: &mut impl PluginTrustPolicyRegistryV1,
    wall: &mut impl TrustedWallSourceV1,
    request: CommunityInstallRequestV1<'_>,
) -> Result<InstalledPluginReleaseV1, CommunityInstallErrorV1> {
    let bundle = source
        .read_verified(address)
        .map_err(CommunityInstallErrorV1::Source)?;
    let execution = PluginExecutionProjectionV1::from_verified_bundle(&bundle)
        .map_err(CommunityInstallErrorV1::Manifest)?;
    let activation = activation_input(request.anchor.scope(), &execution, request.target);
    let once = OneShotSource::new(address.clone(), bundle);
    install_plugin_release_v1(
        &once,
        address,
        registry,
        wall,
        PluginInstallRequestV1 {
            anchor: request.anchor,
            tps1_bytes: request.tps1_bytes,
            evidence: request.evidence,
            activation,
        },
    )
    .map_err(CommunityInstallErrorV1::Install)
}

/// The activation Event draft of one release on `target`.
fn activation_input(
    scope: &str,
    execution: &PluginExecutionProjectionV1,
    target: ActivationTargetV1,
) -> ActivationEventInputV1 {
    let payload = activation_payload(
        scope,
        execution.plugin_id(),
        &execution.pmf1_digest(),
        &execution.release_digest(),
    );
    ActivationEventInputV1 {
        timeline: target.timeline,
        draft: EventDraft::new(
            target.entity,
            Kind::new(PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1),
            CanonicalBytes::from_vec(payload),
        ),
    }
}

/// The canonical CBOR array `[scope, plugin_id, pmf1_digest, release_digest]`. It carries no
/// UTC second, no Tick and no per-attempt value, so a retry after an indeterminate commit
/// compares equal.
fn activation_payload(
    scope: &str,
    plugin_id: &str,
    pmf1_digest: &[u8; 32],
    release_digest: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::array(&mut out, 4);
    cbor::text(&mut out, scope);
    cbor::text(&mut out, plugin_id);
    cbor::bytes(&mut out, pmf1_digest);
    cbor::bytes(&mut out, release_digest);
    out
}

/// A release source that returns the one bundle it holds, once, for one address.
///
/// A read of another address is `NotFound` without consuming the bundle, so the installer's own
/// address check cannot burn it; a second read of the same address is `NotFound`.
struct OneShotSource {
    address: BundleAddressV1,
    bundle: RefCell<Option<VerifiedReleaseBundleV1>>,
}

impl OneShotSource {
    const fn new(address: BundleAddressV1, bundle: VerifiedReleaseBundleV1) -> Self {
        Self {
            address,
            bundle: RefCell::new(Some(bundle)),
        }
    }
}

impl ReleaseSourceV1 for OneShotSource {
    fn read_verified(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        if *address != self.address {
            return Err(ReleaseSourceErrorV1::NotFound);
        }
        self.bundle
            .borrow_mut()
            .take()
            .ok_or(ReleaseSourceErrorV1::NotFound)
    }
}
