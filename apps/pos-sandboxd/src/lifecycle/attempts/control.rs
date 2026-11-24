//! Cancel and reconcile, and the request ledger they share with execute
//! (ADR-069 R15 §3.3, §3.4, §3.6 items 1 and 2, N5, N7 and N11).
//!
//! Every SCQ1 and SRQ1 first passes the request ledger under the attempts
//! lock: a recorded request ID with other bytes is `RequestConflict` (SPE1
//! `16`); an attempt that is unknown, only claimed, or held under another
//! AGR1 is unknown (`15`); and a further distinct request ID once the
//! attempt holds four entries is `ControlRequestsExhausted` (`12`). Only an
//! SCY1 or SRY1 answer adds an entry, so no refusal can exhaust them. An
//! exact repeat of a recorded request is answered from the current state.
//!
//! A cancellation records itself on an attempt awaiting its input, fences
//! one whose run has not started, and signals a running one; it never
//! tombstones the attempt. [`AttemptLifecycle::bind_cancel`] then waits on
//! the slot, holding no lock: while the attempt is active, until it ended
//! (within the run's own deadlines), then for its signed response within
//! one control interval. The SCY1 binds the retained signed response, which
//! the binding marks delivered under the attempts lock.
//!
//! A reconcile succeeds only for an attempt that ended with its cleanup
//! proved, or with nothing committed, and whose signed terminal response is
//! retained. Under one hold of the attempts lock it marks the response
//! delivered, builds the `reconciliation-evidence-v1` tuple from the slot's
//! AGR1 and the response's SPY1 and final SAU1, and tombstones the attempt
//! with those bytes, releasing its admission, response and output. No
//! successor and no further SPY1 write can follow. A later reconcile replays
//! the same bytes.

use std::sync::Arc;
use std::time::Duration;

use pos_reference::sandbox_provider_protocol::{
    CancelSource, ReconciliationEvidence, ReconciliationEvidenceFields, SandboxCancelRequest,
    SandboxCancellationResult, SandboxReconcileRequest,
};
use tokio::sync::watch;
use tokio::time::Instant;

use super::retention::Retained;
use super::{
    lock, AttemptLifecycle, AttemptLifecycleError, Cleaned, ReconciledAttempt, Slot, Table,
};
use crate::RetainedResponse;

/// The most SCQ1 and SRQ1 request IDs one attempt records (R15 N11).
const MAX_CONTROL_REQUESTS: u8 = 4;

/// The request ID and self-digest of one control request.
type ControlIdentity = ([u8; 16], [u8; 32]);

impl<I> Table<I> {
    /// The slot that the control request `identity` of `attempt_id` under
    /// `grant` names, after the request ledger: other bytes under a recorded
    /// ID conflict, an unknown, claimed or other grant's attempt is unknown,
    /// a `cancel` of a reconciled attempt is unknown (R11 Amendment 1
    /// invariant 31, before the cap: it can never succeed), and a new ID
    /// beyond the attempt's four entries is refused.
    fn control(
        &mut self,
        attempt_id: [u8; 16],
        grant: [u8; 32],
        (request_id, digest): ControlIdentity,
        cancel: bool,
    ) -> Result<&mut Slot<I>, AttemptLifecycleError> {
        let recorded = match self.requests.get(&request_id) {
            Some(recorded) if *recorded != digest => {
                return Err(AttemptLifecycleError::RequestConflict)
            }
            recorded => recorded.is_some(),
        };
        let full = !recorded
            && self
                .controls
                .get(&attempt_id)
                .is_some_and(|entries| *entries >= MAX_CONTROL_REQUESTS);
        match self.slots.get_mut(&attempt_id) {
            // A claim has no AGR1 a control request could name.
            None | Some(Slot::Claimed { .. }) => Err(AttemptLifecycleError::UnknownAttempt),
            Some(slot) if slot.agr1_digest() != Some(grant) => {
                Err(AttemptLifecycleError::GrantMismatch)
            }
            Some(Slot::Reconciled { .. }) if cancel => Err(AttemptLifecycleError::UnknownAttempt),
            Some(_) if full => Err(AttemptLifecycleError::ControlRequestsExhausted),
            Some(slot) => Ok(slot),
        }
    }

    /// Record the answered control request `identity` of `attempt_id`, once.
    fn record_control(&mut self, attempt_id: [u8; 16], (request_id, digest): ControlIdentity) {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.requests.entry(request_id) {
            entry.insert(digest);
            *self.controls.entry(attempt_id).or_default() += 1;
        }
    }
}

/// What a cancellation found.
enum Signalled {
    /// The attempt had already ended, clean.
    Terminal,
    /// The attempt has not started its run: its ending records the
    /// cancellation.
    Recorded,
    /// The attempt runs; this wakes when it ended.
    Running(watch::Receiver<bool>),
}

/// What a cancellation of `slot` finds, under the attempts lock: a started
/// run is signalled and fenced, and an attempt awaiting its input or whose
/// run has not started records it for its ending. The ledger check already
/// refused a claim and a reconciled attempt, so any other slot has ended.
fn signal<I>(slot: &mut Slot<I>) -> Result<Signalled, AttemptLifecycleError> {
    match slot {
        Slot::Ended {
            cleaned: Cleaned::Unproved,
            ..
        } => Err(AttemptLifecycleError::CleanupFailed),
        Slot::Granted { cancel, .. } => {
            // Nothing is committed before its input is admitted; its
            // recorded ending carries the first cancellation.
            cancel.get_or_insert(CancelSource::CancelRequest);
            Ok(Signalled::Recorded)
        }
        Slot::Running {
            state,
            ended,
            started,
            ..
        } => {
            // An owner that has not begun reads the cancellation under the
            // attempts lock and ends with nothing committed.
            state.cancel(CancelSource::CancelRequest);
            Ok(if *started {
                Signalled::Running(ended.clone())
            } else {
                Signalled::Recorded
            })
        }
        _ => Ok(Signalled::Terminal),
    }
}

/// What a waiting control request finds for its attempt.
enum Settling {
    /// Nothing more to wait for: the binding answers.
    Settled,
    /// The attempt is active: this wakes once it ended.
    Active(watch::Receiver<bool>),
    /// The attempt ended and its response is pending: this wakes once it is
    /// retained or refused.
    Pending(watch::Receiver<bool>),
}

/// What a reconcile found under the attempts lock.
enum Reconciling {
    /// The answer.
    Done(Result<ReconciledAttempt, AttemptLifecycleError>),
    /// The attempt ended and its response is pending: this wakes once it is
    /// retained or refused.
    Pending(watch::Receiver<bool>),
}

/// The reconciliation evidence of `response`, the retained signed terminal
/// response of `attempt_id` admitted under `grant` (R15 §3.2).
fn evidence_of(
    attempt_id: [u8; 16],
    grant: [u8; 32],
    response: &RetainedResponse,
) -> Result<ReconciliationEvidence, AttemptLifecycleError> {
    let (terminal_spy1_digest, final_sau1_digest) = response.terminal_digests();
    // Every field is a nonzero identity or BLAKE3 digest of a validated
    // record.
    ReconciliationEvidence::new(&ReconciliationEvidenceFields {
        attempt_id,
        agr1_digest: grant,
        terminal_spy1_digest,
        final_sau1_digest,
    })
    .ok()
    .ok_or(AttemptLifecycleError::ResponseUnavailable)
}

impl<I> AttemptLifecycle<I> {
    /// Cancel the attempt `request` names (base ADR-069 §4, R15 §3.6 item
    /// 2(a)), after the request ledger's checks.
    ///
    /// An attempt awaiting its input, or admitted and not yet running,
    /// records the cancellation for its ending, which commits nothing; a
    /// running one is signalled and fenced, and this waits until it ended,
    /// within its watchdog and cleanup budget. Either is reported cancelled
    /// (`1`): cancellation outranks every other outcome (ADR-069 §8). An
    /// attempt that already ended clean is `0`. The attempt is never
    /// tombstoned here; [`Self::bind_cancel`] binds the SCY1 to its signed
    /// response.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::RequestConflict`] for a recorded request ID
    /// with other bytes; [`AttemptLifecycleError::UnknownAttempt`] and
    /// [`AttemptLifecycleError::GrantMismatch`] for another attempt or
    /// grant, or a reconciled one;
    /// [`AttemptLifecycleError::ControlRequestsExhausted`] for a fifth
    /// distinct request ID; [`AttemptLifecycleError::CleanupFailed`] for an
    /// attempt whose cleanup was not proved.
    pub async fn cancel(
        &self,
        request: &SandboxCancelRequest,
    ) -> Result<SandboxCancellationResult, AttemptLifecycleError> {
        self.cancelled(request).await.map(|(result, _)| result)
    }

    /// [`Self::cancel`], then [`Self::bind_cancel`]: the SCY1 result and the
    /// response it binds (R15 §3.6 item 2(a)). When the cancellation waited
    /// for a started run to end, the wait for its response is one
    /// `interval` from that end, not from `until`.
    ///
    /// # Errors
    /// Those of [`Self::cancel`] and [`Self::bind_cancel`].
    pub async fn cancel_and_bind(
        &self,
        request: &SandboxCancelRequest,
        until: Instant,
        interval: Duration,
    ) -> Result<(SandboxCancellationResult, Arc<RetainedResponse>), AttemptLifecycleError> {
        let (result, waited) = self.cancelled(request).await?;
        let until = if waited {
            Instant::now() + interval
        } else {
            until
        };
        self.bind_cancel(request, until, interval)
            .await
            .map(|response| (result, response))
    }

    /// The cancellation of `request`, and whether it waited for a started
    /// run to end.
    async fn cancelled(
        &self,
        request: &SandboxCancelRequest,
    ) -> Result<(SandboxCancellationResult, bool), AttemptLifecycleError> {
        let signalled = {
            let mut attempts = lock(&self.attempts);
            attempts
                .control(
                    request.attempt_id,
                    request.agr1_digest,
                    (request.request.request_id, request.request_digest),
                    true,
                )
                .and_then(signal)
        };
        let mut ended = match signalled? {
            Signalled::Terminal => return Ok((SandboxCancellationResult::AlreadyTerminal, false)),
            Signalled::Recorded => {
                return Ok((SandboxCancellationResult::CancelledAndCleaned, false))
            }
            Signalled::Running(ended) => ended,
        };
        // A dropped run ends the wait too; the slot then says what is known.
        ended.wait_for(|ended| *ended).await.ok();
        if self.ended_clean(request.attempt_id) {
            Ok((SandboxCancellationResult::CancelledAndCleaned, true))
        } else {
            Err(AttemptLifecycleError::CleanupFailed)
        }
    }

    /// Whether the attempt ended clean: its cleanup was proved, it ended
    /// with nothing committed, or it was already reconciled.
    fn ended_clean(&self, attempt_id: [u8; 16]) -> bool {
        matches!(
            lock(&self.attempts).get(&attempt_id),
            Some(
                Slot::Ended {
                    cleaned: Cleaned::NothingCommitted | Cleaned::Proved,
                    ..
                } | Slot::Reconciled { .. }
            )
        )
    }

    /// The retained signed response that the SCY1 answering `request` binds
    /// (R15 §3.6 item 2(a)), marked delivered under the attempts lock, so no
    /// re-issue replaces it; the request is then recorded in the ledger.
    ///
    /// The wait holds no lock. While the attempt is active it waits until
    /// the attempt ended, which happens within the run's own deadlines; then
    /// for its response until `until`, or `interval` after the end when the
    /// attempt was still active.
    ///
    /// # Errors
    /// Those of [`Self::cancel`]'s ledger checks;
    /// [`AttemptLifecycleError::CleanupFailed`] for an attempt whose
    /// cleanup was not proved; [`AttemptLifecycleError::ResponseUnavailable`]
    /// for a faulted response; [`AttemptLifecycleError::ResponsePending`]
    /// for one still pending at the bound.
    pub async fn bind_cancel(
        &self,
        request: &SandboxCancelRequest,
        until: Instant,
        interval: Duration,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let mut until = until;
        loop {
            let settling = self.settling(request.attempt_id);
            match settling {
                Settling::Settled => break,
                Settling::Active(mut ended) => {
                    // A replaced slot ends the wait too.
                    ended.wait_for(|ended| *ended).await.ok();
                    until = Instant::now() + interval;
                }
                Settling::Pending(mut settled) => {
                    if tokio::time::timeout_at(until, settled.wait_for(|settled| *settled))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        self.bind(request)
    }

    /// What a control request of `attempt_id` waits for now.
    fn settling(&self, attempt_id: [u8; 16]) -> Settling {
        match lock(&self.attempts).get(&attempt_id) {
            Some(Slot::Granted { changed, .. }) => Settling::Active(changed.subscribe()),
            Some(Slot::Running { ended, .. }) => Settling::Active(ended.clone()),
            Some(Slot::Ended {
                response: Retained::Pending,
                settled,
                ..
            }) => Settling::Pending(settled.subscribe()),
            _ => Settling::Settled,
        }
    }

    /// Bind the SCY1 of `request` under the attempts lock.
    fn bind(
        &self,
        request: &SandboxCancelRequest,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let identity = (request.request.request_id, request.request_digest);
        let mut attempts = lock(&self.attempts);
        let response =
            match attempts.control(request.attempt_id, request.agr1_digest, identity, true)? {
                Slot::Ended {
                    cleaned: Cleaned::Unproved,
                    ..
                } => Err(AttemptLifecycleError::CleanupFailed),
                Slot::Ended {
                    response: Retained::Signed(response),
                    ..
                } => Ok(Arc::clone(response)),
                Slot::Ended {
                    response: Retained::Faulted,
                    ..
                } => Err(AttemptLifecycleError::ResponseUnavailable),
                // A pending response: the ledger check refused a claim and a
                // reconciled attempt, and the wait outlasted any active slot.
                _ => Err(AttemptLifecycleError::ResponsePending),
            }?;
        response.mark_delivered();
        attempts.record_control(request.attempt_id, identity);
        drop(attempts);
        Ok(response)
    }

    /// Reconcile the attempt `request` names now, without waiting for a
    /// pending response (R15 §3.3 and §3.4).
    ///
    /// The first success marks the retained response delivered, builds the
    /// attempt's `reconciliation-evidence-v1` once and tombstones the
    /// attempt with it, all under the attempts lock; its admission, response
    /// and output are released after the lock. A later request for the
    /// reconciled attempt replays the same evidence. Each success records
    /// the request in the ledger.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::RequestConflict`],
    /// [`AttemptLifecycleError::UnknownAttempt`],
    /// [`AttemptLifecycleError::GrantMismatch`] and
    /// [`AttemptLifecycleError::ControlRequestsExhausted`] from the ledger
    /// checks; [`AttemptLifecycleError::AttemptActive`] for an attempt that
    /// has not ended; [`AttemptLifecycleError::CleanupFailed`] for one whose
    /// cleanup was not proved; [`AttemptLifecycleError::ResponseUnavailable`]
    /// for a faulted response; and [`AttemptLifecycleError::ResponsePending`]
    /// while its response is pending.
    pub fn reconcile(
        &self,
        request: &SandboxReconcileRequest,
    ) -> Result<ReconciledAttempt, AttemptLifecycleError> {
        match self.reconciling(request) {
            Reconciling::Done(reconciled) => reconciled,
            Reconciling::Pending(_) => Err(AttemptLifecycleError::ResponsePending),
        }
    }

    /// [`Self::reconcile`], waiting on a pending response until `until`,
    /// holding no lock (R15 §3.3, N7). A response still pending then is
    /// [`AttemptLifecycleError::ResponsePending`].
    ///
    /// # Errors
    /// Those of [`Self::reconcile`].
    pub async fn reconcile_within(
        &self,
        request: &SandboxReconcileRequest,
        until: Instant,
    ) -> Result<ReconciledAttempt, AttemptLifecycleError> {
        loop {
            let mut settled = match self.reconciling(request) {
                Reconciling::Done(reconciled) => return reconciled,
                Reconciling::Pending(settled) => settled,
            };
            if tokio::time::timeout_at(until, settled.wait_for(|settled| *settled))
                .await
                .is_err()
            {
                return Err(AttemptLifecycleError::ResponsePending);
            }
        }
    }

    /// One reconcile of `request` under the attempts lock.
    fn reconciling(&self, request: &SandboxReconcileRequest) -> Reconciling {
        let attempt_id = request.attempt_id;
        let grant = request.agr1_digest;
        let identity = (request.request.request_id, request.request_digest);
        let mut attempts = lock(&self.attempts);
        let evidence = match attempts.control(attempt_id, grant, identity, false) {
            Err(refusal) => Err(refusal),
            Ok(Slot::Reconciled { evidence, .. }) => Ok((*evidence, false)),
            Ok(Slot::Claimed { .. } | Slot::Granted { .. } | Slot::Running { .. }) => {
                Err(AttemptLifecycleError::AttemptActive)
            }
            Ok(Slot::Ended {
                cleaned: Cleaned::Unproved,
                ..
            }) => Err(AttemptLifecycleError::CleanupFailed),
            Ok(Slot::Ended {
                response: Retained::Faulted,
                ..
            }) => Err(AttemptLifecycleError::ResponseUnavailable),
            Ok(Slot::Ended {
                response: Retained::Pending,
                settled,
                ..
            }) => return Reconciling::Pending(settled.subscribe()),
            Ok(Slot::Ended {
                response: Retained::Signed(response),
                ..
            }) => {
                // The tuple is built from a delivered, so final, response.
                response.mark_delivered();
                #[cfg(test)]
                self.evidence_built
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                evidence_of(attempt_id, grant, response).map(|evidence| (evidence, true))
            }
        };
        let (evidence, first) = match evidence {
            Ok(built) => built,
            Err(refusal) => return Reconciling::Done(Err(refusal)),
        };
        // The transition to `Reconciled` is taken under the same lock.
        let released =
            first.then(|| attempts.set(attempt_id, Slot::Reconciled { grant, evidence }));
        attempts.record_control(attempt_id, identity);
        drop(attempts);
        // The admission, response and output are released outside the lock.
        drop(released);
        Reconciling::Done(Ok(ReconciledAttempt {
            attempt_id,
            evidence,
        }))
    }
}

#[cfg(test)]
impl<I> AttemptLifecycle<I> {
    /// How many reconciliation-evidence tuples this lifecycle built.
    pub(crate) fn evidence_built(&self) -> usize {
        self.evidence_built
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Retain a signed test response for the ended attempt `attempt_id`,
    /// whose response is pending, and wake its waiters: what a signed
    /// terminal response does for the fake attempts of these tests.
    pub(crate) fn sign_for_test(
        &self,
        attempt_id: [u8; 16],
    ) -> crate::test_fixtures::TestResult<Arc<RetainedResponse>> {
        let signed = RetainedResponse::signed_for_test()
            .map_err(|error| -> Box<dyn std::error::Error> { error })?;
        let mut attempts = lock(&self.attempts);
        match attempts.slots.get_mut(&attempt_id) {
            Some(Slot::Ended {
                response: response @ Retained::Pending,
                settled,
                ..
            }) => {
                *response = Retained::Signed(Arc::clone(&signed));
                settled.send_replace(true);
                Ok(signed)
            }
            _ => Err("the attempt has no pending response".into()),
        }
    }

    /// Record a provider fault for the ended attempt `attempt_id`, whose
    /// response is pending, and wake its waiters.
    pub(crate) fn fault_for_test(&self, attempt_id: [u8; 16]) {
        let mut attempts = lock(&self.attempts);
        if let Some(Slot::Ended {
            response, settled, ..
        }) = attempts.slots.get_mut(&attempt_id)
        {
            *response = Retained::Faulted;
            settled.send_replace(true);
        }
    }

    /// Signal the cancellation `request` under the attempts lock without
    /// waiting, as [`Self::cancel`] does first: whether it was accepted.
    pub(crate) fn signal_for_test(&self, request: &SandboxCancelRequest) -> bool {
        lock(&self.attempts)
            .control(
                request.attempt_id,
                request.agr1_digest,
                (request.request.request_id, request.request_digest),
                true,
            )
            .and_then(signal)
            .is_ok()
    }

    /// The SCQ1 and SRQ1 entries `attempt_id` holds in the ledger.
    pub(crate) fn control_entries(&self, attempt_id: [u8; 16]) -> u8 {
        lock(&self.attempts)
            .controls
            .get(&attempt_id)
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A tuple the encoder refuses is a fault, never evidence.
    #[test]
    fn evidence_of_a_zero_identity_is_refused() -> crate::test_fixtures::TestResult {
        let response = RetainedResponse::signed_for_test().map_err(|error| error.to_string())?;
        assert!(matches!(
            evidence_of([0; 16], [1; 32], &response),
            Err(AttemptLifecycleError::ResponseUnavailable)
        ));
        assert!(evidence_of([1; 16], [1; 32], &response).is_ok());
        Ok(())
    }
}
