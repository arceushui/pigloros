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
//! The port serves the `AirGapped`, `Fork` and `Replay` modes; a `Local` case
//! is refused with SPE1 `8 ProviderCapabilityMissing` (R11 Amendment 1 §7.5
//! row 9) until #1488 serves it. Replay is evidence-only with empty plans
//! (#1488 journal 23125, G3): no FD 3 and no bytes reach the adapter.
//!
//! Each admitted attempt's launcher barrier is the production
//! [`ProviderReleaseBarrier`] over the runtime key, the manager's unit
//! identity and the kernel readback, with the attempt's own cancellation in
//! its `AuthorityCheck`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_reference::evaluator_domain::ExecutionMode;
use pos_reference::sandbox_provider_protocol::{
    NetworkCaptureStore, SandboxCancelRequest, SandboxCancelResponse, SandboxCancelResponseFields,
    SandboxExecutionMode, SandboxProviderErrorCode, SandboxReconcileRequest,
    SandboxReconcileResponse, SandboxReconcileResponseFields,
};
use tokio::runtime::Runtime;

use crate::{
    fresh_nonce, sign_verified, AdmittedAttempt, AdmittedRuntimeKey, AttemptLaunch,
    AttemptLifecycle, AttemptLifecycleError, AuthorityCheck, BarrierError, BarrierFactory,
    CancelSignal, CleanupBudget, FailClosedLocalNetwork, KernelObservedReadback,
    KeyFileRuntimeSigner, ModePlan, NetlinkUnitNetwork, OwnedAttempt, ProviderNamespaces,
    ProviderReleaseBarrier, RetainedResponse, RootRecheck, RuntimeAttestationSigner,
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

/// Whether the port serves a case of `mode`: every mode but `Local`, which
/// stays refused (SPE1 `8`) until #1488 serves it.
pub(super) const fn serves(mode: ExecutionMode) -> bool {
    matches!(
        mode,
        ExecutionMode::AirGapped | ExecutionMode::Fork | ExecutionMode::Replay
    )
}

/// The network plan of an admitted `mode` the port serves: `Fork`'s own,
/// `Replay`'s with no exchanges, and `AirGapped`'s for every other, whose
/// execution then refuses the mismatch.
///
/// A Replay case has no exchange to resolve: the plans it reconstructs are
/// empty, because a non-empty SPX1 plan list fails the reconstruction
/// equality (R11 Amendment 1 §7.5 row 7).
const fn mode_plan(mode: SandboxExecutionMode) -> ModePlan {
    match mode {
        SandboxExecutionMode::Fork => ModePlan::Fork,
        SandboxExecutionMode::Replay => ModePlan::Replay {
            exchanges: Vec::new(),
        },
        _ => ModePlan::AirGapped,
    }
}

/// The SPE1 code of a cancel or reconcile the lifecycle refused (ADR-069
/// R15 §3.3, N5, N7 and N11): an attempt this runtime does not hold under
/// the named AGR1 is unknown (`15`); one still active, not proved clean or
/// whose response faulted `14`; a request ID recorded with other bytes
/// `16`; a further distinct request ID once the attempt holds four `12`;
/// and a response still pending at the bound, or any other refusal, `11`.
pub(super) const fn control_code(error: &AttemptLifecycleError) -> SandboxProviderErrorCode {
    match error {
        AttemptLifecycleError::UnknownAttempt | AttemptLifecycleError::GrantMismatch => {
            SandboxProviderErrorCode::UnknownAttempt
        }
        AttemptLifecycleError::AttemptActive
        | AttemptLifecycleError::CleanupFailed
        | AttemptLifecycleError::ResponseUnavailable => SandboxProviderErrorCode::CleanupFailed,
        AttemptLifecycleError::RequestConflict => SandboxProviderErrorCode::RequestIdentityConflict,
        AttemptLifecycleError::ControlRequestsExhausted => SandboxProviderErrorCode::AdmissionBusy,
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
        KernelObservedReadback<NetlinkUnitNetwork>,
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
                    AuthorityCheck::new(
                        root,
                        KernelObservedReadback::new(self.namespaces, NetlinkUnitNetwork),
                        cancel,
                    ),
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

    /// Answer the authenticated SCQ1 `request` (base §4, §10; ADR-069 R15
    /// §3.6 item 2(a)): cancel the attempt, wait for its signed terminal
    /// response, holding no lock, and sign an SCY1 that binds its SPY1
    /// digest: `0` when the attempt was already terminal and `1` when this
    /// request cancelled it. The wait follows the attempt until it ended,
    /// then waits for its response until `until`, or one control `interval`
    /// after the end when it was still active. An exact repeat is answered
    /// from the current state.
    ///
    /// # Errors
    /// `Some` SPE1 code: the lifecycle's refusal (see [`control_code`]).
    /// `None` when the SCY1 cannot be built or signed under the admitted
    /// key: a provider fault, which emits nothing and closes execute
    /// admission (R9 §5). The response it would have bound stays delivered:
    /// no re-issue replaces it.
    pub(super) fn cancel(
        &self,
        request: &SandboxCancelRequest,
        (until, interval): (Instant, Duration),
        (signer, key): (&KeyFileRuntimeSigner, AdmittedRuntimeKey<'_>),
    ) -> Result<Vec<u8>, Option<SandboxProviderErrorCode>> {
        let (result, response) = self
            .runtime
            .block_on(
                self.lifecycle
                    .cancel_and_bind(request, until.into(), interval),
            )
            .map_err(|error| Some(control_code(&error)))?;
        SandboxCancelResponse::self_digested(SandboxCancelResponseFields {
            request_id: request.request.request_id,
            attempt_id: request.attempt_id,
            result,
            terminal_spy1_digest: response.terminal_digests().0,
            runtime_attestation_key_id: signer.runtime_attestation_key_id().to_owned(),
        })
        .ok()
        .and_then(|record| sign_verified(signer, key, record).ok())
        .and_then(|verified| SandboxCancelResponse::new(verified, key.key()).ok())
        .and_then(|response| response.to_canonical_cbor().ok())
        .ok_or_else(|| self.fault())
    }

    /// Answer the authenticated SRQ1 `request` (ADR-069 R15 §3.3): reconcile
    /// the attempt, waiting on a pending response until `until`, holding no
    /// lock, and sign an SRY1 over the digest of its retained
    /// `reconciliation-evidence-v1`. A repeated request for the same AGR1
    /// gets the same digest, and an exact repeat the same bytes.
    ///
    /// # Errors
    /// `Some` SPE1 code: the lifecycle's refusal (see [`control_code`]).
    /// `None` when the SRY1 cannot be built or signed under the admitted
    /// key: a provider fault, which emits nothing and closes execute
    /// admission (R9 §5). The attempt stays reconciled.
    pub(super) fn reconcile(
        &self,
        request: &SandboxReconcileRequest,
        until: Instant,
        (signer, key): (&KeyFileRuntimeSigner, AdmittedRuntimeKey<'_>),
    ) -> Result<Vec<u8>, Option<SandboxProviderErrorCode>> {
        let reconciled = self
            .runtime
            .block_on(self.lifecycle.reconcile_within(request, until.into()))
            .map_err(|error| Some(control_code(&error)))?;
        SandboxReconcileResponse::self_digested(SandboxReconcileResponseFields {
            request_id: request.request.request_id,
            attempt_id: request.attempt_id,
            reconciliation_evidence_digest: reconciled.evidence_digest(),
            runtime_attestation_key_id: signer.runtime_attestation_key_id().to_owned(),
        })
        .ok()
        .and_then(|record| sign_verified(signer, key, record).ok())
        .and_then(|verified| SandboxReconcileResponse::new(verified, key.key()).ok())
        .and_then(|response| response.to_canonical_cbor().ok())
        .ok_or_else(|| self.fault())
    }

    /// A provider fault answering a control request: nothing is emitted and
    /// execute admission closes (R9 §5).
    fn fault(&self) -> Option<SandboxProviderErrorCode> {
        self.close();
        None
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
    fn the_port_serves_every_mode_but_local() {
        assert!(serves(ExecutionMode::AirGapped));
        assert!(serves(ExecutionMode::Fork));
        assert!(serves(ExecutionMode::Replay));
        assert!(!serves(ExecutionMode::Local));
        assert!(matches!(
            mode_plan(SandboxExecutionMode::Fork),
            ModePlan::Fork
        ));
        assert!(matches!(
            mode_plan(SandboxExecutionMode::Replay),
            ModePlan::Replay { exchanges } if exchanges.is_empty()
        ));
        for mode in [SandboxExecutionMode::AirGapped, SandboxExecutionMode::Local] {
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
    fn control_refusals_name_their_codes() {
        use SandboxProviderErrorCode as Code;
        for (error, code) in [
            (AttemptLifecycleError::UnknownAttempt, Code::UnknownAttempt),
            (AttemptLifecycleError::GrantMismatch, Code::UnknownAttempt),
            (AttemptLifecycleError::AttemptActive, Code::CleanupFailed),
            (AttemptLifecycleError::CleanupFailed, Code::CleanupFailed),
            (
                AttemptLifecycleError::ResponseUnavailable,
                Code::CleanupFailed,
            ),
            (
                AttemptLifecycleError::RequestConflict,
                Code::RequestIdentityConflict,
            ),
            (
                AttemptLifecycleError::ControlRequestsExhausted,
                Code::AdmissionBusy,
            ),
            (
                AttemptLifecycleError::ResponsePending,
                Code::SandboxUnavailable,
            ),
            (AttemptLifecycleError::Fenced, Code::SandboxUnavailable),
        ] {
            assert_eq!(control_code(&error), code, "{error:?}");
        }
    }
}
