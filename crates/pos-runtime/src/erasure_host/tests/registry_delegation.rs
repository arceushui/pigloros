//! The registry port of the fault store delegates to the Memory store it wraps, so a host
//! opened over a fault store is a valid standard host on Linux (R8-W3).

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    CurrentReleaseEvaluationV1, PluginRollbackReceiptV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1,
    ProvisionOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

use super::FaultStoreV1;

type Registry<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

impl PluginTrustPolicyRegistryV1 for FaultStoreV1 {
    fn provision(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
    ) -> Registry<ProvisionOutcomeV1> {
        self.inner.provision(anchor, tps1_bytes)
    }

    fn admit(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> Registry<AdmittedPluginReleaseReceiptV1> {
        self.inner.admit(
            anchor,
            tps1_bytes,
            evidence,
            projection,
            trusted_utc,
            tick,
            activation,
        )
    }

    fn advance_policy(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> Registry<PolicyAdvanceOutcomeV1> {
        self.inner
            .advance_policy(anchor, tps1_bytes, evidence, trusted_utc, tick)
    }

    fn rollback(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        target: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> Registry<PluginRollbackReceiptV1> {
        self.inner.rollback(
            anchor,
            tps1_bytes,
            evidence,
            target,
            trusted_utc,
            tick,
            activation,
        )
    }

    fn retained_release_decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> Registry<Option<RetainedReleaseDecisionV1>> {
        self.inner.retained_release_decision(scope, pmf1_digest)
    }

    fn active_release(&self, scope: &str, plugin_id: &str) -> Registry<Option<ActiveReleaseV1>> {
        self.inner.active_release(scope, plugin_id)
    }

    fn retained_policy_state(&self, scope: &str) -> Registry<RetainedPolicyStateV1> {
        self.inner.retained_policy_state(scope)
    }

    fn ledger(&self, scope: &str) -> Registry<Vec<PluginTrustLedgerRowV1>> {
        self.inner.ledger(scope)
    }

    fn evaluate_current_release(
        &self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> Registry<CurrentReleaseEvaluationV1> {
        self.inner.evaluate_current_release(
            anchor,
            tps1_bytes,
            evidence,
            projection,
            trusted_utc,
            tick,
        )
    }
}
