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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use pos_reference::evaluator_domain::ExecutionMode;
use pos_reference::sandbox_provider_protocol::{
    NetworkCaptureStore, SandboxCancelRequest, SandboxCancelResponse, SandboxCancelResponseFields,
    SandboxExecutionMode, SandboxProviderErrorCode, SandboxProviderResult,
};
use tokio::runtime::Runtime;

use crate::{
    fresh_nonce, sign_verified, AdmittedAttempt, AdmittedRuntimeKey, AttemptLaunch,
    AttemptLifecycle, AttemptLifecycleError, AuthorityCheck, BarrierError, BarrierFactory,
    CancelSignal, CleanupBudget, FailClosedLocalNetwork, KernelObservedReadback,
    KeyFileRuntimeSigner, ModePlan, OwnedAttempt, ProviderNamespaces, ProviderReleaseBarrier,
    RetainedResponse, RootRecheck, RuntimeAttestationSigner, StagingDirectory, StagingLedger,
    SystemdAttemptSteps, SystemdTransientUnitTransport,
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
    /// Each cancelled attempt's last SCQ1 digest and the SCY1 that answered
    /// it, so an exact repeat gets the same result (base §4).
    pub(super) cancelled: Mutex<BTreeMap<[u8; 16], CancelAnswer>>,
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

/// The SCY1 that answered an attempt's last SCQ1, by that request's digest.
#[derive(Debug)]
pub(super) struct CancelAnswer {
    request_digest: [u8; 32],
    scy1: Vec<u8>,
}

/// How often a cancellation looks again for the response its attempt is
/// still signing.
const SETTLE_POLL: Duration = Duration::from_millis(10);

/// The SPE1 code of a cancellation the lifecycle refused: an attempt this
/// runtime does not hold under the named AGR1 is unknown (`15`), one whose
/// cleanup was not proved `14`, and any other refusal `11`.
pub(super) const fn cancel_code(error: &AttemptLifecycleError) -> SandboxProviderErrorCode {
    match error {
        AttemptLifecycleError::UnknownAttempt | AttemptLifecycleError::GrantMismatch => {
            SandboxProviderErrorCode::UnknownAttempt
        }
        AttemptLifecycleError::CleanupFailed => SandboxProviderErrorCode::CleanupFailed,
        _ => SandboxProviderErrorCode::SandboxUnavailable,
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

    /// Answer the authenticated SCQ1 `request` (base §4, §10): cancel the
    /// attempt, wait until `until` for its stored response, and sign an
    /// SCY1 that binds its terminal SPY1 digest, `0` when the attempt was
    /// already terminal and `1` when this request cancelled it. An exact
    /// repeat of the attempt's last SCQ1 gets the same SCY1 bytes.
    ///
    /// # Errors
    /// `Some` SPE1 code: the lifecycle's refusal (see [`cancel_code`]), or
    /// `11` when no terminal SPY1 exists to bind: an attempt that awaited
    /// its input, or one withdrawn before its run, which leave none yet (the
    /// N6 question on the SRY1 draft), one that has none by `until`, or one
    /// re-issued just before it could be bound. `None` when the SCY1 cannot be signed under the
    /// admitted key: nothing is emitted (R9 §5).
    pub(super) fn cancel(
        &self,
        request: &SandboxCancelRequest,
        until: Instant,
        (signer, key): (&KeyFileRuntimeSigner, AdmittedRuntimeKey<'_>),
    ) -> Result<Vec<u8>, Option<SandboxProviderErrorCode>> {
        if let Some(repeated) = self.repeated_cancel(request) {
            return Ok(repeated);
        }
        // A cancellation of an attempt still awaiting its input is recorded
        // for its ending, which has no SPY1 yet: like a withdrawal, it is
        // refused with 11 until the N6 decision, never bound to a fabricated
        // SPY1.
        let awaiting = self
            .lifecycle
            .awaits_input(request.attempt_id, request.agr1_digest);
        let result = self
            .runtime
            .block_on(self.lifecycle.cancel(request))
            .map_err(|error| Some(cancel_code(&error)))?;
        if awaiting {
            return Err(Some(SandboxProviderErrorCode::SandboxUnavailable));
        }
        // The SCY1 binds the stored response's SPY1, which it delivers: no
        // re-issue may replace it after this.
        let spy1 = self
            .settled(request.attempt_id, request.agr1_digest, until)
            .filter(|response| self.lifecycle.claim_delivery(request.attempt_id, response))
            .and_then(|response| {
                SandboxProviderResult::from_canonical_cbor(response.response().result).ok()
            })
            .map(|result| result.result_digest())
            .ok_or(Some(SandboxProviderErrorCode::SandboxUnavailable))?;
        SandboxCancelResponse::self_digested(SandboxCancelResponseFields {
            request_id: request.request.request_id,
            attempt_id: request.attempt_id,
            result,
            terminal_spy1_digest: spy1,
            runtime_attestation_key_id: signer.runtime_attestation_key_id().to_owned(),
        })
        .ok()
        .and_then(|record| sign_verified(signer, key, record).ok())
        .and_then(|verified| SandboxCancelResponse::new(verified, key.key()).ok())
        .and_then(|response| response.to_canonical_cbor().ok())
        .inspect(|bytes| {
            self.cancelled
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    request.attempt_id,
                    CancelAnswer {
                        request_digest: request.request_digest,
                        scy1: bytes.clone(),
                    },
                );
        })
        .ok_or(None)
    }

    /// The SCY1 that answered `request` before, if it is an exact repeat of
    /// the attempt's last SCQ1.
    fn repeated_cancel(&self, request: &SandboxCancelRequest) -> Option<Vec<u8>> {
        self.cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request.attempt_id)
            .filter(|answer| answer.request_digest == request.request_digest)
            .map(|answer| answer.scy1.clone())
    }

    /// The stored response of the attempt of `agr1_digest`, waiting until
    /// `until` while the attempt is still active or its response pending.
    fn settled(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
        until: Instant,
    ) -> Option<Arc<RetainedResponse>> {
        self.runtime.block_on(async {
            loop {
                let current = self.lifecycle.terminal_response(attempt_id, agr1_digest);
                match current {
                    Ok(response) => return Some(response),
                    Err(
                        AttemptLifecycleError::AttemptActive
                        | AttemptLifecycleError::ResponsePending,
                    ) if Instant::now() < until => tokio::time::sleep(SETTLE_POLL).await,
                    Err(_) => return None,
                }
            }
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

    /// The production barrier factory builds the release barrier over the
    /// runtime key, the manager's unit identity, the kernel readback and
    /// the attempt's own cancellation.
    #[test]
    fn the_runtime_barrier_factory_builds_the_production_barrier(
    ) -> crate::provider_runtime::tests::TestResult {
        let attempt = AdmittedAttempt::for_test(
            crate::test_fixtures::ATTEMPT,
            crate::test_fixtures::authority(),
            SandboxExecutionMode::AirGapped,
        )?;
        let (_tree, port) =
            crate::provider_runtime::tests::test_port(crate::StagingLimits { aggregate_bytes: 1 })?;
        let root = || Ok(crate::test_fixtures::checked_root(&attempt));
        let barriers = RuntimeBarriers {
            signer: Arc::new(KeyFileRuntimeSigner::from_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
                "runtime".to_owned(),
            )),
            transport: port.transport.clone(),
            namespaces: port.namespaces,
        };
        let barrier = barriers.barrier(&attempt, &root, crate::AttemptCancel::new().signal())?;
        assert!(barrier.sent_release().is_none());
        Ok(())
    }

    #[test]
    fn cancel_refusals_name_their_codes() {
        for (error, code) in [
            (
                AttemptLifecycleError::UnknownAttempt,
                SandboxProviderErrorCode::UnknownAttempt,
            ),
            (
                AttemptLifecycleError::GrantMismatch,
                SandboxProviderErrorCode::UnknownAttempt,
            ),
            (
                AttemptLifecycleError::CleanupFailed,
                SandboxProviderErrorCode::CleanupFailed,
            ),
            (
                AttemptLifecycleError::Fenced,
                SandboxProviderErrorCode::SandboxUnavailable,
            ),
        ] {
            assert_eq!(cancel_code(&error), code, "{error:?}");
        }
    }
}
