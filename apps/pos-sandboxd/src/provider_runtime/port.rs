//! The execute port an `Open` runtime serves through (ADR-069 R11 §7.3 and
//! Amendment 1 §7.5).
//!
//! Restart reconciliation hands the runtime one [`ExecutePort`]: the
//! lifecycle over the reconciled registry and the staging ledger it shares
//! with source admission, the held staging directory and network capture
//! store of step 7, the provider namespaces, the SPI1 cleanup budget, and the
//! system bus transport with the multi-thread runtime that drives it. Both
//! outlive reconciliation: every admitted attempt runs on them.
//!
//! Until #1488 the port serves the `AirGapped` and `Fork` modes only; a
//! `Local` or `Replay` case is refused with SPE1 `8 ProviderCapabilityMissing` (journal
//! 23069). Each admitted attempt's launcher barrier is the production
//! [`ProviderReleaseBarrier`] over the runtime key, the manager's unit
//! identity and the kernel readback, with the attempt's own cancellation in
//! its `AuthorityCheck`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use pos_reference::evaluator_domain::ExecutionMode;
use pos_reference::sandbox_provider_protocol::{NetworkCaptureStore, SandboxExecutionMode};
use tokio::runtime::Runtime;

use crate::{
    fresh_nonce, AdmittedAttempt, AdmittedRuntimeKey, AttemptLaunch, AttemptLifecycle,
    AttemptLifecycleError, AuthorityCheck, BarrierError, BarrierFactory, CancelSignal,
    CleanupBudget, FailClosedLocalNetwork, KernelObservedReadback, KeyFileRuntimeSigner, ModePlan,
    OwnedAttempt, ProviderNamespaces, ProviderReleaseBarrier, RetainedResponse, RootRecheck,
    StagingDirectory, StagingLedger, SystemdAttemptSteps, SystemdTransientUnitTransport,
};

/// What an `Open` runtime's execute port holds for the life of the process.
pub(super) struct ExecutePort {
    /// The lifecycle over the reconciled registry.
    pub(super) lifecycle: AttemptLifecycle,
    /// The ledger the lifecycle closes, which charges every source.
    pub(super) ledger: StagingLedger,
    /// The held, private staging directory (R11 §5.3).
    pub(super) staging: StagingDirectory,
    /// The held network capture store (R11 Amendment 1 §5.4).
    pub(super) captures: Arc<NetworkCaptureStore>,
    /// The provider's own namespaces, retained at step 7.
    pub(super) namespaces: ProviderNamespaces,
    /// The SPI1 terminal cleanup budget.
    pub(super) budget: CleanupBudget,
    /// Execute admission closed after a provider signing fault (R9 §5).
    pub(super) closed: AtomicBool,
    // The bus connection is dropped before the runtime that drives it.
    /// The single system bus transport.
    pub(super) transport: SystemdTransientUnitTransport,
    /// The multi-thread runtime every attempt and wait runs on.
    pub(super) runtime: Runtime,
}

/// Whether the port serves a case of `mode`: `AirGapped` and `Fork` until
/// #1488 adds the `Local` and `Replay` mode plans.
pub(super) const fn serves(mode: ExecutionMode) -> bool {
    matches!(mode, ExecutionMode::AirGapped | ExecutionMode::Fork)
}

/// The network plan of an admitted `mode` the port serves: `Fork`'s own,
/// and `AirGapped`'s for every other, whose execution then refuses the
/// mismatch.
const fn mode_plan(mode: SandboxExecutionMode) -> ModePlan {
    match mode {
        SandboxExecutionMode::Fork => ModePlan::Fork,
        _ => ModePlan::AirGapped,
    }
}

/// Builds each attempt's production launcher barrier.
pub(super) struct RuntimeBarriers {
    signer: Arc<KeyFileRuntimeSigner>,
    transport: SystemdTransientUnitTransport,
    namespaces: ProviderNamespaces,
}

impl BarrierFactory for RuntimeBarriers {
    type Barrier<'r> = ProviderReleaseBarrier<
        Arc<KeyFileRuntimeSigner>,
        SystemdTransientUnitTransport,
        RootRecheck<'r>,
        KernelObservedReadback,
    >;
    type Error = BarrierError;

    fn barrier<'r>(
        self,
        attempt: &AdmittedAttempt,
        root: RootRecheck<'r>,
        cancel: CancelSignal,
    ) -> Result<Self::Barrier<'r>, BarrierError> {
        fresh_nonce()
            .map_err(BarrierError::Nonce)
            .and_then(|nonce| {
                ProviderReleaseBarrier::new(
                    attempt,
                    nonce,
                    self.signer,
                    self.transport,
                    AuthorityCheck::new(root, KernelObservedReadback::new(self.namespaces), cancel),
                )
            })
    }
}

impl ExecutePort {
    /// Whether execute admission is still open on the port.
    pub(super) fn open(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    /// Close execute admission for the life of the process.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Join an exact repeat of `attempt_id` whose SPX1 digests to
    /// `request_digest` (port step J), waiting at most until `until`;
    /// `None` once `until` passed (item P1).
    pub(super) fn join_until(
        &self,
        attempt_id: [u8; 16],
        request_digest: [u8; 32],
        until: Instant,
    ) -> Option<Result<Option<Arc<RetainedResponse>>, AttemptLifecycleError>> {
        self.runtime.block_on(async {
            tokio::time::timeout_at(
                until.into(),
                self.lifecycle.join(attempt_id, request_digest),
            )
            .await
            .ok()
        })
    }

    /// Run the owned attempt admitted in `mode` to its end and retain its
    /// signed terminal response.
    ///
    /// # Errors
    /// Those of [`AttemptLifecycle::retain_response`]: a response that
    /// cannot be signed is a provider fault, and nothing is emitted.
    pub(super) fn run(
        &self,
        owned: OwnedAttempt<'_>,
        mode: SandboxExecutionMode,
        signer: &Arc<KeyFileRuntimeSigner>,
        key: AdmittedRuntimeKey<'_>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let network = FailClosedLocalNetwork;
        let steps = SystemdAttemptSteps::new(&self.transport, &network, Arc::clone(&self.captures));
        let launch = AttemptLaunch {
            mode: mode_plan(mode),
            barrier: RuntimeBarriers {
                signer: Arc::clone(signer),
                transport: self.transport.clone(),
                namespaces: self.namespaces,
            },
        };
        let ended = self
            .runtime
            .block_on(owned.run(&steps, launch, self.budget));
        self.lifecycle.retain_response(ended, &**signer, key)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn the_port_serves_air_gapped_and_fork_only() {
        assert!(serves(ExecutionMode::AirGapped));
        assert!(serves(ExecutionMode::Fork));
        assert!(!serves(ExecutionMode::Local));
        assert!(!serves(ExecutionMode::Replay));
        assert!(matches!(
            mode_plan(SandboxExecutionMode::Fork),
            ModePlan::Fork
        ));
        for mode in [
            SandboxExecutionMode::AirGapped,
            SandboxExecutionMode::Local,
            SandboxExecutionMode::Replay,
        ] {
            assert!(matches!(mode_plan(mode), ModePlan::AirGapped));
        }
    }
}
