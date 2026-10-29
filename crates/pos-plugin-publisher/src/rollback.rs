//! The production Plugin release rollback entry (ADR-103 revision 7, decision 4.3).
//!
//! One call re-activates one previously admitted release in the installer's
//! fixed, fail-closed order. Nothing before the last step changes any registry
//! state, and the registry is never consulted for a target whose signature has
//! not verified:
//!
//! 1. read the target's verified OCI closure by address from a release source;
//! 2. project the complete PMF1 (trust projection and execution projection)
//!    from that closure alone;
//! 3. authorize the projection with the caller's verified trust evidence, which
//!    resolves the publisher key;
//! 4. verify the PMF1 release signature under the resolved key;
//! 5. sample the sealed trusted wall source;
//! 6. only then call the registry's `rollback` with the evidence's own Tick and
//!    the verified signature as the release proof, which the registry requires
//!    to bind its own authorization of the target.
//!
//! Steps 1 to 5 are the installer's own private prefix, so the two orders
//! cannot drift. ADR-103 revision 7 names this module the sole non-test caller
//! of the registry's `rollback`; it may not call `admit`, `provision`, or
//! `advance_policy`. No operator command, HTTP route, or remote trigger reaches
//! it (revision 7, Q9).
//!
//! The entry accepts no projection, public key, clock value, or Tick from its
//! caller, and it builds no activation Event: the trusted composition supplies
//! the already validated [`ActivationEventInputV1`] for the target. Rollback
//! cannot restore a revoked release: the target is authorized against the
//! caller's current evidence before anything else happens.

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::trusted_clock::PluginTrustWallSourceV1;
use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
use pos_crypto::plugin_manifest::{
    PluginManifestErrorV1, PluginReleaseSignatureErrorV1, VerifiedPluginReleaseSignatureV1,
};
use pos_crypto::plugin_trust::{PluginTrustErrorV1, VerifiedPluginTrustEvidenceV1};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1};
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, PluginRollbackReceiptV1, PluginTrustPolicyRegistryErrorV1,
    PluginTrustPolicyRegistryV1,
};
use thiserror::Error;

use crate::install::verify_release_v1;

/// A closed failure of Plugin release rollback.
///
/// Every variant means the registry committed nothing for this call, except
/// `Registry` carrying `StorageIndeterminate`: the commit outcome is then
/// unknown and the caller must resolve it with the registry's recovery rules
/// (ADR-103 revision 4 decision 12).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PluginReleaseRollbackErrorV1 {
    /// The release source could not produce the target's verified closure.
    #[error(transparent)]
    Source(#[from] ReleaseSourceErrorV1),
    /// The target closure's PMF1 failed strict decoding, binding, or digest checks.
    #[error(transparent)]
    Manifest(#[from] PluginManifestErrorV1),
    /// The caller's trust evidence does not authorize the target, for example
    /// because its publisher key or its release digest is now revoked. It is
    /// raised before the signature check and the registry.
    #[error(transparent)]
    Authorization(#[from] PluginTrustErrorV1),
    /// The target's PMF1 signature failed verification under the authorized key.
    #[error(transparent)]
    Signature(#[from] PluginReleaseSignatureErrorV1),
    /// The registry refused the rollback, or the trusted time was unavailable.
    #[error(transparent)]
    Registry(#[from] PluginTrustPolicyRegistryErrorV1),
}

/// The trusted inputs of one rollback that the entry cannot derive.
///
/// The anchor, the signed TPS1 bytes, the verified evidence, and the
/// activation Event come from the private trusted composition. The target's
/// bytes, its projection, the key, the UTC second, and the Tick never do.
#[derive(Debug)]
pub struct PluginRollbackRequestV1<'a> {
    /// The operator-pinned policy anchor of the scope.
    pub anchor: &'a PluginTrustPolicyAnchorV1,
    /// The signed canonical TPS1 bytes; the registry authenticates them.
    pub tps1_bytes: &'a [u8],
    /// The verified PTR1/PRV1 evidence; its coordinates are the transaction's.
    pub evidence: &'a VerifiedPluginTrustEvidenceV1,
    /// The already validated activation Event of the target, built by the composition.
    pub activation: ActivationEventInputV1,
}

/// One rolled-back release: the registry's rollback receipt, the execution
/// requirements of the target's PMF1, and the proof that its signature verified.
///
/// It is constructed only by [`rollback_plugin_release_v1()`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolledBackPluginReleaseV1 {
    receipt: PluginRollbackReceiptV1,
    execution: PluginExecutionProjectionV1,
    signature: VerifiedPluginReleaseSignatureV1,
}

impl RolledBackPluginReleaseV1 {
    /// The registry's rollback receipt, committed or an idempotent replay.
    #[must_use]
    pub const fn receipt(&self) -> &PluginRollbackReceiptV1 {
        &self.receipt
    }

    /// The execution requirements projected from the target's PMF1 bytes.
    #[must_use]
    pub const fn execution(&self) -> &PluginExecutionProjectionV1 {
        &self.execution
    }

    /// The verified release signature of the target that preceded the rollback.
    #[must_use]
    pub const fn release_signature(&self) -> VerifiedPluginReleaseSignatureV1 {
        self.signature
    }
}

/// Roll the active release of the target's Plugin ID back to the already
/// admitted release at `address`: verify its signature, then re-activate it.
///
/// `source` yields the target's verified closure; the trust projection, the
/// execution projection, the resolved key, and the signature claim are all
/// derived from that closure and `request.evidence`. The UTC second comes from
/// `wall`, the sealed trusted wall source, and the Tick is the evidence's own.
/// The signature is verified before the wall source is sampled and before any
/// registry call, so a target whose signature is invalid never reaches the
/// registry and consumes no clock sample.
///
/// Repeating the same rollback with the same evidence and activation identity
/// (for example after a lost acknowledgement) returns the registry's original
/// receipt as an idempotent replay.
///
/// # Errors
/// Returns `Source` when the closure cannot be read, `Manifest` when its PMF1
/// is not a canonical V1 manifest, `Authorization` when the evidence does not
/// authorize the target, `Signature` when field 26 does not verify under the
/// authorized key, and `Registry` for a trusted-time failure or the registry's
/// own typed refusal of the rollback (for example `UnknownRollbackTarget`,
/// `NoActiveRelease`, or `RollbackTargetActive`).
pub fn rollback_plugin_release_v1(
    source: &impl ReleaseSourceV1,
    address: &BundleAddressV1,
    registry: &mut (impl PluginTrustPolicyRegistryV1 + ?Sized),
    wall: &mut impl PluginTrustWallSourceV1,
    request: PluginRollbackRequestV1<'_>,
) -> Result<RolledBackPluginReleaseV1, PluginReleaseRollbackErrorV1> {
    let verified =
        verify_release_v1::<PluginReleaseRollbackErrorV1>(source, address, request.evidence, wall)?;
    let receipt = registry.rollback(
        request.anchor,
        request.tps1_bytes,
        request.evidence,
        &verified.projection,
        &verified.signature,
        verified.point,
        request.activation,
    )?;
    Ok(RolledBackPluginReleaseV1 {
        receipt,
        execution: verified.execution,
        signature: verified.signature,
    })
}
