//! The Plugin trust policy registry port (ADR-103 revisions 4, 5 and 7).

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_crypto::plugin_manifest::VerifiedPluginReleaseSignatureV1;
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};

use super::error::PluginTrustPolicyRegistryErrorV1;
use super::types::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    CurrentReleaseEvaluationV1, PluginRollbackReceiptV1, PluginTrustLedgerRowV1,
    PolicyAdvanceOutcomeV1, ProvisionOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1,
};
use super::utc::TrustedUtcSecondV1;

/// The trusted UTC second and the Tick of one `admit` or `rollback` transaction.
///
/// A call argument only: no decision, receipt, or ledger row retains it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustEvaluationPointV1 {
    /// The UTC second sampled from the sealed wall source.
    pub trusted_utc: TrustedUtcSecondV1,
    /// The host Tick of the transaction.
    pub tick: u64,
}

impl TrustEvaluationPointV1 {
    /// The point at `trusted_utc` and `tick`.
    #[must_use]
    pub const fn new(trusted_utc: TrustedUtcSecondV1, tick: u64) -> Self {
        Self { trusted_utc, tick }
    }
}

/// The durable Plugin trust policy registry (ADR-103 revisions 4, 5 and 7).
///
/// Only the private trusted composition boundary constructs the anchor,
/// trusted-time, Tick, and manifest-projection inputs;
/// `scripts/check_plugin_trust_registry_impls.py` restricts implementations,
/// constructors, and call sites. A decision, receipt,
/// retained record, or ledger row claims trust-policy admission only: it never
/// claims the PMF1 publisher signature is valid, and no method accepts one of
/// them as live authority.
///
/// `admit` and `rollback` require a release proof (revision 7): a
/// `VerifiedPluginReleaseSignatureV1` that must name the complete-PMF1 digest,
/// the release digest and the public key of the registry's own authorization
/// of the projection, else `ReleaseProofMismatch`. The registry checks that
/// binding only; it does not re-verify the signature and retains nothing from
/// the proof. Their UTC second and Tick are one [`TrustEvaluationPointV1`].
///
/// Writes take `&mut self` and commit all of their state or none; reads take
/// `&self`, and so does the read-only `evaluate_current_release`. A write validates the
/// signed TPS1 bytes itself with `authenticate_plugin_tps1_v1`; no caller supplies an
/// authenticated TPS1.
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
    /// `release_proof` must bind the authorized release and key; `point` is the
    /// trusted UTC second and the Tick of the transaction.
    ///
    /// # Errors
    /// Returns the closed registry error of the first failing step.
    fn admit(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        release_proof: &VerifiedPluginReleaseSignatureV1,
        point: TrustEvaluationPointV1,
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
    /// `release_proof` must bind the authorized target and key; `point` is the
    /// trusted UTC second and the Tick of the transaction.
    ///
    /// # Errors
    /// Returns the closed registry error of the first failing step.
    fn rollback(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        target: &ValidatedPluginManifestProjectionV1,
        release_proof: &VerifiedPluginReleaseSignatureV1,
        point: TrustEvaluationPointV1,
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

    /// Re-run the admission checks of `projection` at a fresh UTC second and Tick and require
    /// it to be the active release of its Plugin ID, writing nothing.
    ///
    /// Takes no Event input, never adopts newer policy, and never raises the highest trusted
    /// UTC second. The returned value is not a receipt and no method accepts it.
    ///
    /// # Errors
    /// Returns the closed registry error of the first failing step, including
    /// `PolicyNotAdvanced` and `ReleaseNotActive`.
    fn evaluate_current_release(
        &self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> Result<CurrentReleaseEvaluationV1, PluginTrustPolicyRegistryErrorV1>;
}
