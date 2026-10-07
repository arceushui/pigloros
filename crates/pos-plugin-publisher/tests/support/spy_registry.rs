#![cfg(any(test, feature = "test-support"))]
//! A Plugin trust policy registry spy for the installer's ordering vectors.
//!
//! [`SpyRegistry`] wraps the Memory adapter, records every `admit` call, and can
//! force a typed registry error instead of delegating. Every other method
//! delegates unchanged, so a test reads the real retained state through it.

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::TimelineId;
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    PluginRollbackReceiptV1, PluginTrustLedgerRowV1, PluginTrustPolicyRegistryErrorV1,
    PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1, ProvisionOutcomeV1,
    RetainedPolicyStateV1, RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

/// What one `admit` call received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmitCall {
    pub utc: i64,
    pub tick: u64,
    pub tps1: Vec<u8>,
    pub timeline: TimelineId,
}

/// The Memory adapter plus a call log and an optional forced `admit` error.
pub struct SpyRegistry {
    pub store: MemoryStore,
    pub admits: Vec<AdmitCall>,
    pub forced: Option<PluginTrustPolicyRegistryErrorV1>,
}

impl SpyRegistry {
    /// A spy over `store` that delegates every call.
    #[must_use]
    pub const fn new(store: MemoryStore) -> Self {
        Self {
            store,
            admits: Vec::new(),
            forced: None,
        }
    }
}

type Registry<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

impl PluginTrustPolicyRegistryV1 for SpyRegistry {
    fn provision(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
    ) -> Registry<ProvisionOutcomeV1> {
        self.store.provision(anchor, tps1_bytes)
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
        self.admits.push(AdmitCall {
            utc: trusted_utc.as_i64(),
            tick,
            tps1: tps1_bytes.to_vec(),
            timeline: activation.timeline,
        });
        if let Some(error) = self.forced {
            return Err(error);
        }
        self.store.admit(
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
        self.store
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
        self.store.rollback(
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
        self.store.retained_release_decision(scope, pmf1_digest)
    }

    fn active_release(&self, scope: &str, plugin_id: &str) -> Registry<Option<ActiveReleaseV1>> {
        self.store.active_release(scope, plugin_id)
    }

    fn retained_policy_state(&self, scope: &str) -> Registry<RetainedPolicyStateV1> {
        self.store.retained_policy_state(scope)
    }

    fn ledger(&self, scope: &str) -> Registry<Vec<PluginTrustLedgerRowV1>> {
        self.store.ledger(scope)
    }
}
