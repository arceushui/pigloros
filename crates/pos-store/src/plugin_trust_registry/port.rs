//! The Plugin trust policy registry port.

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};

use super::error::PluginTrustPolicyRegistryErrorV1;
use super::types::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    PluginRollbackReceiptV1, PluginTrustLedgerRowV1, PolicyAdvanceOutcomeV1, ProvisionOutcomeV1,
    RetainedPolicyStateV1, RetainedReleaseDecisionV1,
};
use super::utc::TrustedUtcSecondV1;

/// The durable Plugin trust policy registry (ADR-103 revision 4).
///
/// Only the private trusted composition boundary constructs the anchor,
/// trusted-time, Tick, and manifest-projection inputs;
/// `scripts/check_plugin_trust_registry_impls.py` restricts implementations,
/// constructors, and call sites. A decision, receipt,
/// retained record, or ledger row claims trust-policy admission only: it never
/// claims the PMF1 publisher signature is valid, and no method accepts one of
/// them as live authority.
///
/// Writes take `&mut self` and commit all of their state or none; reads take
/// `&self`. A write validates the signed TPS1 bytes itself with
/// `authenticate_plugin_tps1_v1`; no caller supplies an authenticated TPS1.
pub trait PluginTrustPolicyRegistryV1 {
    /// Create the scope from the signed genesis TPS1, or confirm it already exists.
    ///
    /// Consults no clock and creates no PTR1/PRV1 floor.
    ///
    /// # Errors
    /// Returns the closed registry error of the failing step.
    fn provision(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
    ) -> Result<ProvisionOutcomeV1, PluginTrustPolicyRegistryErrorV1>;

    /// Admit and activate one release, or return the identical earlier decision.
    ///
    /// # Errors
    /// Returns the closed registry error of the first failing step.
    fn admit(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> Result<AdmittedPluginReleaseReceiptV1, PluginTrustPolicyRegistryErrorV1>;

    /// Record newer valid policy evidence without admitting any release.
    ///
    /// # Errors
    /// Returns the closed registry error of the first failing step.
    fn advance_policy(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> Result<PolicyAdvanceOutcomeV1, PluginTrustPolicyRegistryErrorV1>;

    /// Re-activate a previously admitted release of the active Plugin ID.
    ///
    /// # Errors
    /// Returns the closed registry error of the first failing step.
    fn rollback(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        target: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> Result<PluginRollbackReceiptV1, PluginTrustPolicyRegistryErrorV1>;

    /// The retained decision for `(scope, PMF1 digest)`, or `None` when the digest is absent.
    ///
    /// # Errors
    /// Returns `MissingState` for an absent scope, or a storage error.
    fn retained_release_decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> Result<Option<RetainedReleaseDecisionV1>, PluginTrustPolicyRegistryErrorV1>;

    /// The active release of `(scope, exact Plugin ID)`, or `None` when none is active.
    ///
    /// # Errors
    /// Returns `MissingState` for an absent scope, or a storage error.
    fn active_release(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> Result<Option<ActiveReleaseV1>, PluginTrustPolicyRegistryErrorV1>;

    /// The retained TPS1, floors, and highest trusted UTC second of `scope`.
    ///
    /// # Errors
    /// Returns `MissingState` for an absent scope, or a storage error.
    fn retained_policy_state(
        &self,
        scope: &str,
    ) -> Result<RetainedPolicyStateV1, PluginTrustPolicyRegistryErrorV1>;

    /// The append-only ledger of `scope` in row order.
    ///
    /// # Errors
    /// Returns `MissingState` for an absent scope, or a storage error.
    fn ledger(
        &self,
        scope: &str,
    ) -> Result<Vec<PluginTrustLedgerRowV1>, PluginTrustPolicyRegistryErrorV1>;
}
