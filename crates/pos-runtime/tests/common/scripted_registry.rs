//! A `pos-runtime`-local fake of the Plugin trust policy registry port (R7-G3, R7-G4).
//!
//! It wraps a shared reference to the world's spy registry, counts every call it receives, and
//! can force one typed error instead of delegating `evaluate_current_release`, which the spy's
//! own forced error does not cover. The gate takes the registry by shared reference, so the
//! write methods are unreachable here and refuse with a nested-transaction error.

use std::sync::atomic::{AtomicUsize, Ordering};

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_plugin_publisher::test_support::spy_registry::SpyRegistry;
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    CurrentReleaseEvaluationV1, PluginRollbackReceiptV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1 as Reg, PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1,
    ProvisionOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

type Registry<T> = Result<T, Reg>;

/// The counting wrapper and fake registry.
pub struct Scripted<'a> {
    inner: &'a SpyRegistry,
    forced: Option<Reg>,
    calls: AtomicUsize,
}

impl<'a> Scripted<'a> {
    /// A wrapper that delegates every read and counts the calls.
    #[must_use]
    pub const fn counting(inner: &'a SpyRegistry) -> Self {
        Self {
            inner,
            forced: None,
            calls: AtomicUsize::new(0),
        }
    }

    /// A wrapper whose `evaluate_current_release` returns `error`.
    #[must_use]
    pub const fn failing(inner: &'a SpyRegistry, error: Reg) -> Self {
        Self {
            inner,
            forced: Some(error),
            calls: AtomicUsize::new(0),
        }
    }

    /// How many calls the wrapper received.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn count(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl PluginTrustPolicyRegistryV1 for Scripted<'_> {
    fn provision(
        &mut self,
        _anchor: &PluginTrustPolicyAnchorV1,
        _tps1_bytes: &[u8],
    ) -> Registry<ProvisionOutcomeV1> {
        Err(Reg::NestedTransaction)
    }

    fn admit(
        &mut self,
        _anchor: &PluginTrustPolicyAnchorV1,
        _tps1_bytes: &[u8],
        _evidence: &VerifiedPluginTrustEvidenceV1,
        _projection: &ValidatedPluginManifestProjectionV1,
        _trusted_utc: TrustedUtcSecondV1,
        _tick: u64,
        _activation: ActivationEventInputV1,
    ) -> Registry<AdmittedPluginReleaseReceiptV1> {
        Err(Reg::NestedTransaction)
    }

    fn advance_policy(
        &mut self,
        _anchor: &PluginTrustPolicyAnchorV1,
        _tps1_bytes: &[u8],
        _evidence: &VerifiedPluginTrustEvidenceV1,
        _trusted_utc: TrustedUtcSecondV1,
        _tick: u64,
    ) -> Registry<PolicyAdvanceOutcomeV1> {
        Err(Reg::NestedTransaction)
    }

    fn rollback(
        &mut self,
        _anchor: &PluginTrustPolicyAnchorV1,
        _tps1_bytes: &[u8],
        _evidence: &VerifiedPluginTrustEvidenceV1,
        _target: &ValidatedPluginManifestProjectionV1,
        _trusted_utc: TrustedUtcSecondV1,
        _tick: u64,
        _activation: ActivationEventInputV1,
    ) -> Registry<PluginRollbackReceiptV1> {
        Err(Reg::NestedTransaction)
    }

    fn retained_release_decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> Registry<Option<RetainedReleaseDecisionV1>> {
        self.count();
        self.inner.retained_release_decision(scope, pmf1_digest)
    }

    fn active_release(&self, scope: &str, plugin_id: &str) -> Registry<Option<ActiveReleaseV1>> {
        self.count();
        self.inner.active_release(scope, plugin_id)
    }

    fn retained_policy_state(&self, scope: &str) -> Registry<RetainedPolicyStateV1> {
        self.count();
        self.inner.retained_policy_state(scope)
    }

    fn ledger(&self, scope: &str) -> Registry<Vec<PluginTrustLedgerRowV1>> {
        self.count();
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
        self.count();
        if let Some(error) = self.forced {
            return Err(error);
        }
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
