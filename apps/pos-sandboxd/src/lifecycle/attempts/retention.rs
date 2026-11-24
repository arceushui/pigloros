//! The signed terminal response each ended attempt retains until it is
//! reconciled (ADR-069 R9 §4.7; Redmine #443 journal 22723, 8c).
//!
//! The lifecycle ends an attempt first and its response is signed after,
//! outside the attempts lock: until then the response is pending, and a
//! request for it is told the attempt is still active. A response that
//! cannot be assembled or signed is a provider fault (R9 §5; owner reading
//! G2): the lifecycle is quarantined and the attempt's response stays
//! unavailable until restart reconciliation. Reconciling the attempt
//! releases its response with the rest of its slot.
//!
//! The retained response is the stored full response of ADR-069 §4: with a
//! Completed outcome it carries the output SBC1 records, so it replays byte
//! for byte. An exact repeated execute joins the attempt through
//! [`AttemptLifecycle::join`]: it waits while the attempt is active, then
//! receives the same response as the original connection. It never admits,
//! so it emits no second AGR1.
//!
//! #1358 transports the response and its output. When the output transfer
//! times out it calls [`AttemptLifecycle::reissue_response`], which retains
//! the R9 §4.7 successor in place of the first response unless it was
//! delivered: #443 alone signs the evidence. A delivered response is final,
//! so the reconciliation evidence built from it equals what the selector
//! accepted (ADR-069 R15 §3.5).

use std::sync::Arc;

use pos_reference::sandbox_provider_protocol::TransferRecord;
use tokio::sync::watch;

use super::{lock, AttemptLifecycle, AttemptLifecycleError, Slot};
use crate::{
    AdmittedRuntimeKey, EndedAttempt, EvidenceFault, RequestedConfiguration, ResponseFault,
    RetainedResponse, RuntimeAttestationSigner,
};

/// What a wait for an attempt's response names it by.
#[derive(Clone, Copy)]
enum Named {
    /// An exact repeated execute's SPX1 digest.
    Request([u8; 32]),
    /// A cancellation's AGR1 digest.
    Grant([u8; 32]),
}

/// What a repeated execute found.
enum Joined {
    /// The response to replay; `None` for an attempt this runtime never
    /// knew.
    Ready(Option<Arc<RetainedResponse>>),
    /// The attempt is not settled yet: this wakes when it may be.
    Waiting(watch::Receiver<bool>),
}

/// The terminal response an ended attempt holds.
#[derive(Debug)]
pub(super) enum Retained {
    /// Not signed yet.
    Pending,
    /// Signed and verified under the admitted key.
    Signed(Arc<RetainedResponse>),
    /// Refused as a provider fault.
    Faulted,
}

impl<I> AttemptLifecycle<I> {
    /// Sign the terminal response of `ended`, which this lifecycle ended,
    /// and retain it, with the output of a Completed attempt, until the
    /// attempt is reconciled (R9 §4.7 steps 7 to 9); every joined repeat
    /// then receives it. A response already retained is returned as it is:
    /// it is signed once.
    /// A response whose classification quarantines (a contradiction, any
    /// code-2 candidate or the fail-closed fallback, R9 §4.6.4 and §4.6.5)
    /// is retained and closes admission. A response already settled is
    /// returned without signing or chunking anything again.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] for an attempt that has not
    /// ended here or was reconciled, [`AttemptLifecycleError::GrantMismatch`]
    /// when `ended` names another AGR1 than the attempt's, and
    /// [`AttemptLifecycleError::Response`] when the response cannot be
    /// assembled or signed: the lifecycle is then quarantined and the
    /// attempt's response stays [`AttemptLifecycleError::ResponseUnavailable`].
    pub fn retain_response<S, R>(
        &self,
        ended: EndedAttempt<S>,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError>
    where
        S: RequestedConfiguration,
        R: RuntimeAttestationSigner,
    {
        let attempt = (ended.attempt_id(), ended.admission().grant().digest());
        self.settled(attempt).unwrap_or_else(|| {
            let response = ended.signed_response(signer, admitted).map(Arc::new);
            self.store(attempt, None, response)
        })
    }

    /// The response the ended attempt of `grant` already settled on: the
    /// one retained, or the closed refusal after a fault. `None` while it is
    /// pending, and for any other slot, whose refusal `store` reports.
    fn settled(
        &self,
        (attempt_id, grant): ([u8; 16], [u8; 32]),
    ) -> Option<Result<Arc<RetainedResponse>, AttemptLifecycleError>> {
        match lock(&self.attempts).get(&attempt_id) {
            Some(Slot::Ended {
                grant: admitted,
                response: Retained::Signed(response),
                ..
            }) if *admitted == grant => Some(Ok(Arc::clone(response))),
            Some(Slot::Ended {
                grant: admitted,
                response: Retained::Faulted,
                ..
            }) if *admitted == grant => Some(Err(AttemptLifecycleError::ResponseUnavailable)),
            _ => None,
        }
    }

    /// Join an exact repeated execute of `attempt_id` whose SPX1 digests to
    /// `request_digest` (ADR-069 §4). SPX1 binds the EVR1 digest, so equal
    /// digests of the two validated records mean the exact original EVR1
    /// and SPX1 bytes.
    ///
    /// While the attempt is active the repeat waits for it, within the
    /// original attempt's watchdog and cleanup budget and its response's
    /// signing: it is never admitted, so no second AGR1 is sent and no
    /// `AttemptInProgress` terminal exists. It then receives the very
    /// response the original connection does. A repeat during a claim waits
    /// on the claim, then on the attempt it becomes (ADR-069 R11 Amendment 1,
    /// §7.5 port step J). `Ok(None)` means no exchange holds the attempt: it
    /// was never known, or its claim was released or its AGR1 write failed,
    /// and the repeat re-enters the port at step 7 as a new exchange. The
    /// caller bounds the wait by the repeat's own initial control deadline;
    /// dropping the future leaves the attempt as it is.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] once the attempt was
    /// reconciled, also while the repeat waited;
    /// [`AttemptLifecycleError::RequestConflict`] for other request bytes;
    /// and [`AttemptLifecycleError::ResponseUnavailable`] when no response
    /// will be signed.
    pub async fn join(
        &self,
        attempt_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<Option<Arc<RetainedResponse>>, AttemptLifecycleError> {
        self.settled_as(attempt_id, Named::Request(request_digest))
            .await
    }

    /// The response the attempt of `agr1_digest` settles on, waiting while
    /// it is granted, runs or its response is still signed; the caller
    /// bounds the wait. `Ok(None)` for an attempt this runtime never knew.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] once the attempt was
    /// reconciled, [`AttemptLifecycleError::GrantMismatch`] for another
    /// AGR1, also of a claim, which has none, and
    /// [`AttemptLifecycleError::ResponseUnavailable`] when no response will
    /// be signed.
    pub async fn settled_response(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<Option<Arc<RetainedResponse>>, AttemptLifecycleError> {
        self.settled_as(attempt_id, Named::Grant(agr1_digest)).await
    }

    /// Wait until the attempt `named` names is settled.
    async fn settled_as(
        &self,
        attempt_id: [u8; 16],
        named: Named,
    ) -> Result<Option<Arc<RetainedResponse>>, AttemptLifecycleError> {
        loop {
            let mut settled = match self.joined(attempt_id, named)? {
                Joined::Ready(response) => return Ok(response),
                Joined::Waiting(settled) => settled,
            };
            // A replaced slot ends the wait too; the next look says why.
            settled.wait_for(|settled| *settled).await.ok();
        }
    }

    /// What a wait for the attempt `named` names finds now, under the
    /// attempts lock.
    fn joined(&self, attempt_id: [u8; 16], named: Named) -> Result<Joined, AttemptLifecycleError> {
        match lock(&self.attempts).get(&attempt_id) {
            None => Ok(Joined::Ready(None)),
            Some(Slot::Reconciled { .. }) => Err(AttemptLifecycleError::UnknownAttempt),
            Some(
                Slot::Claimed { request, .. }
                | Slot::Granted { request, .. }
                | Slot::Running { request, .. }
                | Slot::Ended { request, .. },
            ) if matches!(named, Named::Request(digest) if *request != digest) => {
                Err(AttemptLifecycleError::RequestConflict)
            }
            Some(slot) if matches!(named, Named::Grant(digest) if slot.agr1_digest() != Some(digest)) => {
                Err(AttemptLifecycleError::GrantMismatch)
            }
            // A claim converts or is released, and a granted attempt is
            // admitted or ends: either replaces the slot, which wakes this.
            Some(Slot::Claimed { changed, .. } | Slot::Granted { changed, .. }) => {
                Ok(Joined::Waiting(changed.subscribe()))
            }
            Some(Slot::Running { ended, .. }) => Ok(Joined::Waiting(ended.clone())),
            Some(Slot::Ended {
                response: Retained::Pending,
                settled,
                ..
            }) => Ok(Joined::Waiting(settled.subscribe())),
            Some(Slot::Ended {
                response: Retained::Faulted,
                ..
            }) => Err(AttemptLifecycleError::ResponseUnavailable),
            Some(Slot::Ended {
                response: Retained::Signed(response),
                ..
            }) => Ok(Joined::Ready(Some(Arc::clone(response)))),
        }
    }

    /// The retained terminal response of the attempt `agr1_digest` admitted:
    /// the seam the provider daemon (#1358) serves from.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] for an unknown or
    /// reconciled attempt, [`AttemptLifecycleError::GrantMismatch`] for
    /// another grant, [`AttemptLifecycleError::AttemptActive`] while the
    /// attempt runs, [`AttemptLifecycleError::ResponsePending`] once it ended
    /// and before its response was retained, and
    /// [`AttemptLifecycleError::ResponseUnavailable`] after a provider fault.
    pub fn terminal_response(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        match lock(&self.attempts).get(&attempt_id) {
            None | Some(Slot::Reconciled { .. } | Slot::Claimed { .. }) => {
                Err(AttemptLifecycleError::UnknownAttempt)
            }
            Some(slot) if slot.agr1_digest() != Some(agr1_digest) => {
                Err(AttemptLifecycleError::GrantMismatch)
            }
            Some(Slot::Granted { .. } | Slot::Running { .. }) => {
                Err(AttemptLifecycleError::AttemptActive)
            }
            Some(Slot::Ended {
                response: Retained::Pending,
                ..
            }) => Err(AttemptLifecycleError::ResponsePending),
            Some(Slot::Ended {
                response: Retained::Faulted,
                ..
            }) => Err(AttemptLifecycleError::ResponseUnavailable),
            Some(Slot::Ended {
                response: Retained::Signed(response),
                ..
            }) => Ok(Arc::clone(response)),
        }
    }

    /// Record that `response`, the stored response of `attempt_id`, is now
    /// delivered, under the attempts lock, as one connection is about to
    /// write the first byte of its SPY1; no re-issue replaces it from then
    /// on (ADR-069 R15 §3.6 item 1). An SCY1 or a reconcile marks it under
    /// the same lock. `false` when it is no longer the stored response: it
    /// was re-issued meanwhile, or the attempt was reconciled, and its SPY1
    /// must not be written.
    pub fn claim_delivery(&self, attempt_id: [u8; 16], response: &Arc<RetainedResponse>) -> bool {
        let attempts = lock(&self.attempts);
        let stored = matches!(
            attempts.get(&attempt_id),
            Some(Slot::Ended {
                response: Retained::Signed(current),
                ..
            }) if Arc::ptr_eq(current, response)
        );
        if stored {
            response.mark_delivered();
        }
        drop(attempts);
        stored
    }

    /// Re-issue `expected`, the retained Completed response of the attempt
    /// whose output transfer timed out on this connection (R9 §4.7), and
    /// retain the successor in its place. `transfer` must carry the
    /// connection's own transfer of that response's output, starting after
    /// the cleanup finished; it is `None` when a time of the output transfer
    /// could not be read.
    ///
    /// The successor is built from `expected`, never from a response
    /// stored since, and stored only while, under the attempts lock,
    /// `expected` is still the retained response and not delivered (base
    /// §4). Otherwise it is discarded, whatever its signing or clock fault:
    /// a response re-issued meanwhile is returned instead, the first
    /// re-issue to store having won. A successor of a still-retained,
    /// undelivered response that cannot be signed, or whose
    /// `output-transfer` time could not be read (R9 Amendment 1 change F),
    /// is a provider fault (R9 §5): the stored response is replaced by a
    /// fault and stays unavailable.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] and
    /// [`AttemptLifecycleError::GrantMismatch`] for an attempt that does not
    /// retain a response of `expected`'s AGR1;
    /// [`AttemptLifecycleError::ResponseUnavailable`] once its response
    /// faulted; [`AttemptLifecycleError::ResponseDelivered`] once `expected`
    /// was delivered whole, which keeps it;
    /// [`AttemptLifecycleError::Response`] with
    /// [`ResponseFault::Evidence`] for a response that cannot be re-issued
    /// with `transfer`, which keeps the retained response, unless the fault
    /// is [`EvidenceFault::Clock`]; and with [`ResponseFault::Sign`] for a
    /// successor that cannot be signed. A clock or signing fault quarantines
    /// the lifecycle.
    pub fn reissue_response<R: RuntimeAttestationSigner>(
        &self,
        attempt_id: [u8; 16],
        expected: &Arc<RetainedResponse>,
        transfer: Option<TransferRecord>,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let attempt = (attempt_id, expected.agr1_digest());
        split_refusal(expected.successor(transfer, signer, admitted))
            .map_err(AttemptLifecycleError::from)
            .and_then(|successor| self.store(attempt, Some(expected), successor.map(Arc::new)))
    }

    /// Retain `signed` for the ended attempt of `grant` whose response is
    /// still `expected` (pending when `None`), or record its fault. A
    /// response that changed meanwhile is returned instead.
    fn store(
        &self,
        (attempt_id, grant): ([u8; 16], [u8; 32]),
        expected: Option<&Arc<RetainedResponse>>,
        signed: Result<Arc<RetainedResponse>, ResponseFault>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let mut attempts = lock(&self.attempts);
        let (response, settled) = match attempts.slots.get_mut(&attempt_id) {
            Some(Slot::Ended {
                grant: admitted,
                response,
                settled,
                ..
            }) if *admitted == grant => (response, settled),
            Some(Slot::Ended { .. }) => return Err(AttemptLifecycleError::GrantMismatch),
            _ => return Err(AttemptLifecycleError::UnknownAttempt),
        };
        if let Some(current) = superseded(response, expected) {
            return current;
        }
        *response = signed.as_ref().map_or(Retained::Faulted, |signed| {
            Retained::Signed(Arc::clone(signed))
        });
        settled.send_replace(true);
        drop(attempts);
        self.settle(signed)
    }

    /// Quarantine on a fault, or on a retained response whose
    /// classification quarantines (R9 §4.6.1).
    fn settle(
        &self,
        signed: Result<Arc<RetainedResponse>, ResponseFault>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        if signed.as_ref().map_or(true, |signed| {
            signed.records().classification().quarantined()
        }) {
            self.quarantine();
        }
        signed.map_err(Into::into)
    }
}

/// A re-issue refusal that keeps the retained response, or the successor or
/// fault to store in its place: every evidence refusal keeps it, except an
/// `output-transfer` time the clock could not report, a provider fault (R9
/// Amendment 1 change F).
fn split_refusal(
    successor: Result<RetainedResponse, ResponseFault>,
) -> Result<Result<RetainedResponse, ResponseFault>, ResponseFault> {
    match successor {
        Err(ResponseFault::Evidence(refused)) if !matches!(refused, EvidenceFault::Clock) => {
            Err(ResponseFault::Evidence(refused))
        }
        successor => Ok(successor),
    }
}

/// What a store finds instead of the `expected` response: `None` when it
/// may store, else the response stored meanwhile or the closed refusal.
fn superseded(
    response: &Retained,
    expected: Option<&Arc<RetainedResponse>>,
) -> Option<Result<Arc<RetainedResponse>, AttemptLifecycleError>> {
    match (response, expected) {
        (Retained::Pending, None) => None,
        // A delivered response is kept: the selector may hold its SPY1.
        (Retained::Signed(current), Some(expected)) if Arc::ptr_eq(current, expected) => current
            .delivered()
            .then_some(Err(AttemptLifecycleError::ResponseDelivered)),
        (Retained::Signed(current), _) => Some(Ok(Arc::clone(current))),
        (Retained::Faulted | Retained::Pending, _) => {
            Some(Err(AttemptLifecycleError::ResponseUnavailable))
        }
    }
}
