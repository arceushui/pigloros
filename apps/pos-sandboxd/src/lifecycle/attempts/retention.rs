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
//! the R9 §4.7 successor in place of the first response: #443 alone signs
//! the evidence.

use std::sync::Arc;

use pos_reference::sandbox_provider_protocol::TransferRecord;
use tokio::sync::watch;

use super::{lock, AttemptLifecycle, AttemptLifecycleError, Slot};
use crate::{
    AdmittedRuntimeKey, EndedAttempt, EvidenceFault, RequestedConfiguration, ResponseFault,
    RetainedResponse, RuntimeAttestationSigner,
};

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
    /// reconciled or withdrawn, also while the repeat waited;
    /// [`AttemptLifecycleError::RequestConflict`] for other request bytes;
    /// and [`AttemptLifecycleError::ResponseUnavailable`] when no response
    /// will be signed.
    pub async fn join(
        &self,
        attempt_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<Option<Arc<RetainedResponse>>, AttemptLifecycleError> {
        loop {
            let mut settled = match self.joined(attempt_id, request_digest)? {
                Joined::Ready(response) => return Ok(response),
                Joined::Waiting(settled) => settled,
            };
            // A replaced slot ends the wait too; the next look says why.
            settled.wait_for(|settled| *settled).await.ok();
        }
    }

    /// What a repeat of `attempt_id` finds now, under the attempts lock.
    fn joined(
        &self,
        attempt_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<Joined, AttemptLifecycleError> {
        match lock(&self.attempts).get(&attempt_id) {
            None => Ok(Joined::Ready(None)),
            Some(Slot::Reconciled { .. }) => Err(AttemptLifecycleError::UnknownAttempt),
            Some(
                Slot::Claimed { request, .. }
                | Slot::Granted { request, .. }
                | Slot::Running { request, .. }
                | Slot::Ended { request, .. },
            ) if *request != request_digest => Err(AttemptLifecycleError::RequestConflict),
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

    /// Re-issue the retained Completed response of the attempt after its
    /// output transfer timed out (R9 §4.7), and retain the successor in its
    /// place. `transfer` must carry the retained output and start after the
    /// cleanup finished; it is `None` when a time of the output transfer
    /// could not be read.
    ///
    /// A successor that cannot be signed, or whose `output-transfer` time
    /// could not be read (R9 Amendment 1 change F), is a provider fault (R9
    /// §5): the stored response is replaced by a fault and stays
    /// unavailable. Of two concurrent re-issues, the first to store wins,
    /// and the other returns the winner's successor.
    ///
    /// # Errors
    /// Those of [`AttemptLifecycle::terminal_response`];
    /// [`AttemptLifecycleError::Response`] with
    /// [`ResponseFault::Evidence`] for a response that cannot be re-issued
    /// with `transfer`, which keeps the retained response, unless the fault
    /// is [`EvidenceFault::Clock`]; and with [`ResponseFault::Sign`] for a
    /// successor that cannot be signed. A clock or signing fault quarantines
    /// the lifecycle.
    pub fn reissue_response<R: RuntimeAttestationSigner>(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
        transfer: Option<TransferRecord>,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let stored = self.terminal_response(attempt_id, agr1_digest)?;
        split_refusal(stored.successor(transfer, signer, admitted))
            .map_err(AttemptLifecycleError::from)
            .and_then(|successor| {
                self.store(
                    (attempt_id, agr1_digest),
                    Some(&stored),
                    successor.map(Arc::new),
                )
            })
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
        (Retained::Signed(current), Some(expected)) if Arc::ptr_eq(current, expected) => None,
        (Retained::Signed(current), _) => Some(Ok(Arc::clone(current))),
        (Retained::Faulted | Retained::Pending, _) => {
            Some(Err(AttemptLifecycleError::ResponseUnavailable))
        }
    }
}
