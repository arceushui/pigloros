//! The signed Plugin release installer (ADR-061 revision 2, ADR-103 revision 4).
//!
//! One call installs one release in a fixed, fail-closed order. Nothing before
//! the last step changes any registry state, and the registry is never
//! consulted for a release whose signature has not verified:
//!
//! 1. read the verified OCI closure by address from a release source;
//! 2. project the complete PMF1 (trust projection and execution projection)
//!    from that closure alone;
//! 3. authorize the projection with the caller's verified trust evidence, which
//!    resolves the publisher key (a signature alone is not trust admission);
//! 4. verify the PMF1 release signature under the resolved key;
//! 5. sample the sealed trusted wall source;
//! 6. only then call the registry's `admit` with the evidence's own Tick.
//!
//! The installer accepts no projection, public key, clock value, or Tick from
//! its caller, and it builds no activation Event: the trusted composition
//! supplies the already validated [`ActivationEventInputV1`].
//!
//! Content validation of the release artifacts (WIT archive paths, provenance,
//! SBOM, licence text, schema documents) is deferred to follow-up #574. The
//! installer verifies only descriptor digests and bytes, through the OCI
//! closure and the PMF1 decoder, and says so in its receipt through
//! [`ContentValidationV1::NotPerformed`].

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::trusted_clock::TrustedWallSourceV1;
use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
use pos_crypto::plugin_manifest::{
    verify_plugin_release_signature_v1, PluginManifestErrorV1, PluginReleaseSignatureErrorV1,
    VerifiedPluginReleaseSignatureV1,
};
use pos_crypto::plugin_trust::{
    PluginTrustErrorV1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_plugin_release::{
    BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, AdmittedPluginReleaseReceiptV1, PluginTrustPolicyRegistryErrorV1,
    PluginTrustPolicyRegistryV1, TrustedUtcSecondV1,
};
use thiserror::Error;

/// A closed failure of Plugin release installation.
///
/// Every variant means the registry committed nothing for this call, except
/// `Registry` carrying `StorageIndeterminate`: the commit outcome is then
/// unknown and the caller must resolve it with the registry's recovery rules
/// (ADR-103 revision 4 decision 12).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PluginReleaseInstallErrorV1 {
    /// The release source could not produce the verified closure.
    #[error(transparent)]
    Source(#[from] ReleaseSourceErrorV1),
    /// The closure's PMF1 failed strict decoding, binding, or digest checks.
    #[error(transparent)]
    Manifest(#[from] PluginManifestErrorV1),
    /// The caller's trust evidence does not authorize this release: expired,
    /// unknown or revoked key, ungranted Plugin ID, revoked artifact, or
    /// revocation capacity exhausted. It is raised by the installer's own
    /// `authorize_release` before the signature and the registry; the
    /// registry's own `Registry(Trust(..))` is the same check re-run inside
    /// `admit` and is reachable only after the signature verified.
    #[error(transparent)]
    Authorization(#[from] PluginTrustErrorV1),
    /// The PMF1 signature failed verification under the authorized key.
    #[error(transparent)]
    Signature(#[from] PluginReleaseSignatureErrorV1),
    /// The registry refused the admission, or the trusted time was unavailable.
    #[error(transparent)]
    Registry(#[from] PluginTrustPolicyRegistryErrorV1),
}

/// The trusted inputs of one installation that the installer cannot derive.
///
/// The anchor, the signed TPS1 bytes, the verified evidence, and the
/// activation Event come from the private trusted composition. The release
/// bytes, the projection, the key, the UTC second, and the Tick never do.
#[derive(Debug)]
pub struct PluginInstallRequestV1<'a> {
    /// The operator-pinned policy anchor of the scope.
    pub anchor: &'a PluginTrustPolicyAnchorV1,
    /// The signed canonical TPS1 bytes; the registry authenticates them.
    pub tps1_bytes: &'a [u8],
    /// The verified PTR1/PRV1 evidence; its coordinates are the transaction's.
    pub evidence: &'a VerifiedPluginTrustEvidenceV1,
    /// The already validated activation Event, built by the composition.
    pub activation: ActivationEventInputV1,
}

/// What the installer did and did not check about the release content.
///
/// The enum is deliberately closed (no `#[non_exhaustive]`): content
/// validation (#574) replaces it in place in a coordinated breaking change,
/// since the product is unreleased.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentValidationV1 {
    /// Descriptor digests and bytes were verified; WIT, provenance, SBOM,
    /// licence, and schema content were not validated (follow-up #574).
    NotPerformed,
}

/// One installed release: the registry's admission receipt, the execution
/// requirements of the same PMF1, and the proof that its signature verified.
///
/// It is constructed only by [`install_plugin_release_v1()`]. The admission
/// receipt claims trust-policy admission and the signature fact claims
/// mathematical validity, in that order of verification; neither is a claim
/// about artifact content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledPluginReleaseV1 {
    admission: AdmittedPluginReleaseReceiptV1,
    execution: PluginExecutionProjectionV1,
    signature: VerifiedPluginReleaseSignatureV1,
}

impl InstalledPluginReleaseV1 {
    /// The registry's admission receipt, committed or an idempotent replay.
    #[must_use]
    pub const fn admission(&self) -> &AdmittedPluginReleaseReceiptV1 {
        &self.admission
    }

    /// The execution requirements projected from the same PMF1 bytes.
    #[must_use]
    pub const fn execution(&self) -> &PluginExecutionProjectionV1 {
        &self.execution
    }

    /// The verified release signature that preceded the admission.
    #[must_use]
    pub const fn release_signature(&self) -> VerifiedPluginReleaseSignatureV1 {
        self.signature
    }

    /// Content validation was not performed (follow-up #574).
    #[must_use]
    pub const fn content_validation(&self) -> ContentValidationV1 {
        ContentValidationV1::NotPerformed
    }
}

/// Install the release at `address`: verify its signature, then admit it.
///
/// `source` yields the verified closure; the trust projection, the execution
/// projection, the resolved key, and the signature claim are all derived from
/// that closure and `request.evidence`. The UTC second comes from `wall`, the
/// sealed trusted wall source, and the Tick is the evidence's own, so the
/// registry's coordinate-equality check binds both to the evidence. The
/// signature is verified before the wall source is sampled and before any
/// registry call, so a release whose signature is invalid never reaches the
/// registry and consumes no clock sample.
///
/// Installing the same release again with the same evidence and activation
/// identity returns the registry's original receipt as an idempotent replay.
///
/// # Errors
/// Returns `Source` when the closure cannot be read, `Manifest` when its PMF1
/// is not a canonical V1 manifest, `Authorization` when the evidence does not
/// authorize the release, `Signature` when field 26 does not verify under the
/// authorized key, and `Registry` for a trusted-time failure or the registry's
/// own typed refusal of the admission.
pub fn install_plugin_release_v1(
    source: &impl ReleaseSourceV1,
    address: &BundleAddressV1,
    registry: &mut impl PluginTrustPolicyRegistryV1,
    wall: &mut impl TrustedWallSourceV1,
    request: PluginInstallRequestV1<'_>,
) -> Result<InstalledPluginReleaseV1, PluginReleaseInstallErrorV1> {
    let bundle = source.read_verified(address)?;
    let (projection, execution) = project(&bundle)?;
    let authorization = request.evidence.authorize_release(&projection)?;
    let signature = verify_plugin_release_signature_v1(&bundle, &authorization)?;
    let trusted_utc = TrustedUtcSecondV1::from_source(wall)?;
    let (_, tick) = request.evidence.evaluation_coordinates();
    let admission = registry.admit(
        request.anchor,
        request.tps1_bytes,
        request.evidence,
        &projection,
        trusted_utc,
        tick,
        request.activation,
    )?;
    Ok(InstalledPluginReleaseV1 {
        admission,
        execution,
        signature,
    })
}

/// The trust projection and the execution projection of one closure.
type Projections = (ValidatedPluginManifestProjectionV1, PluginExecutionProjectionV1);

/// Both projections of one closure; they run the same validation, so either
/// both exist or the first failure is returned.
fn project(bundle: &VerifiedReleaseBundleV1) -> Result<Projections, PluginManifestErrorV1> {
    ValidatedPluginManifestProjectionV1::from_verified_bundle(bundle).and_then(|projection| {
        PluginExecutionProjectionV1::from_verified_bundle(bundle)
            .map(|execution| (projection, execution))
    })
}
