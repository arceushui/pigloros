#![cfg(any(test, feature = "test-support"))]
//! A Plugin trust policy registry spy for the installer's ordering vectors.
//!
//! [`SpyRegistry`] wraps the Memory adapter, records every `admit` call and every
//! `evaluate_current_release` call, and can force a typed registry error instead of delegating an
//! `admit`. Every other method delegates unchanged, so a test reads the real retained state
//! through it.
//!
//! The ordered [`SpyRegistry::calls`] log holds both kinds of call in call order. An evaluation
//! entry carries a stamp: a spy whose [`SpyRegistry::clock`] is set (the world does so for
//! `World::with_clock`) records `fetch_add(1) + 1` of the shared clock for every evaluation (a
//! 1-based `u64`), and a spy built with [`SpyRegistry::new`] has no clock and records stamp 0, so
//! stamp 0 means "no clock". An `admit` never touches the clock and is unstamped.

use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::TimelineId;
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::{
    ActivationEventInputV1, ActiveReleaseV1, AdmittedPluginReleaseReceiptV1,
    CurrentReleaseEvaluationV1, PluginRollbackReceiptV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1,
    ProvisionOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

/// What one `admit` call received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmitCall {
    pub utc: i64,
    pub tick: u64,
    pub tps1: Vec<u8>,
    pub timeline: TimelineId,
}

/// One recorded registry call, in call order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    /// An `admit` call (unstamped; the same call is also in [`SpyRegistry::admits`]).
    Admit(AdmitCall),
    /// An `evaluate_current_release` call.
    Evaluate {
        /// The shared clock's `fetch_add(1) + 1`, or 0 for a spy without a clock.
        stamp: u64,
        /// The call's trusted UTC second.
        utc: i64,
        /// The call's Tick.
        tick: u64,
    },
}

/// The Memory adapter plus a call log and an optional forced `admit` error.
pub struct SpyRegistry {
    pub store: MemoryStore,
    pub admits: Vec<AdmitCall>,
    pub forced: Option<PluginTrustPolicyRegistryErrorV1>,
    /// Every `admit` and `evaluate_current_release` call in call order.
    ///
    /// Interior-mutable because `evaluate_current_release` takes `&self`. The `RefCell` makes the
    /// spy `!Sync`, which the port does not require.
    pub calls: RefCell<Vec<Call>>,
    /// The clock that stamps evaluations; `None` records stamp 0.
    pub clock: Option<Arc<AtomicU64>>,
}

impl SpyRegistry {
    /// A spy over `store` that delegates every call and has no clock.
    #[must_use]
    pub const fn new(store: MemoryStore) -> Self {
        Self {
            store,
            admits: Vec::new(),
            forced: None,
            calls: RefCell::new(Vec::new()),
            clock: None,
        }
    }

    /// The stamp of the next evaluation: 0 without a clock, else the clock's next 1-based value.
    fn next_stamp(&self) -> u64 {
        self.clock
            .as_ref()
            .map_or(0, |clock| clock.fetch_add(1, Ordering::SeqCst) + 1)
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
        let call = AdmitCall {
            utc: trusted_utc.as_i64(),
            tick,
            tps1: tps1_bytes.to_vec(),
            timeline: activation.timeline,
        };
        self.calls.get_mut().push(Call::Admit(call.clone()));
        self.admits.push(call);
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

    /// Records the call, then delegates; the `forced` error does not apply to evaluations.
    fn evaluate_current_release(
        &self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> Registry<CurrentReleaseEvaluationV1> {
        let call = Call::Evaluate {
            stamp: self.next_stamp(),
            utc: trusted_utc.as_i64(),
            tick,
        };
        self.calls.borrow_mut().push(call);
        self.store.evaluate_current_release(
            anchor,
            tps1_bytes,
            evidence,
            projection,
            trusted_utc,
            tick,
        )
    }
}
