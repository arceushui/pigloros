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
//! #1358 transports the response and its output. When the output transfer
//! times out it calls [`AttemptLifecycle::reissue_response`], which retains
//! the R9 §4.7 successor in place of the first response: #443 alone signs
//! the evidence.

use std::sync::Arc;

use pos_reference::sandbox_provider_protocol::TransferRecord;

use super::{lock, AttemptLifecycle, AttemptLifecycleError, Slot};
use crate::{
    AdmittedRuntimeKey, EndedAttempt, RequestedConfiguration, ResponseFault, RetainedResponse,
    RuntimeAttestationSigner,
};

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
    /// and retain it until the attempt is reconciled (R9 §4.7 steps 7 to 9).
    /// A response already retained is returned as it is: it is signed once.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] for an attempt that has not
    /// ended here or was reconciled, and
    /// [`AttemptLifecycleError::Response`] when the response cannot be
    /// assembled or signed: the lifecycle is then quarantined and the
    /// attempt's response stays [`AttemptLifecycleError::ResponseUnavailable`].
    pub fn retain_response<S, R>(
        &self,
        ended: &EndedAttempt<S>,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError>
    where
        S: RequestedConfiguration,
        R: RuntimeAttestationSigner,
    {
        let response = ended.signed_response(signer, admitted).map(Arc::new);
        self.store(ended.attempt_id(), None, response)
    }

    /// The retained terminal response of the attempt `agr1_digest` admitted:
    /// the seam the provider daemon (#1358) serves from.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] for an unknown or
    /// reconciled attempt, [`AttemptLifecycleError::GrantMismatch`] for
    /// another grant, [`AttemptLifecycleError::AttemptActive`] while the
    /// attempt runs or its response is not yet signed, and
    /// [`AttemptLifecycleError::ResponseUnavailable`] after a provider fault.
    pub fn terminal_response(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        match lock(&self.attempts).get(&attempt_id) {
            None | Some(Slot::Reconciled { .. }) => Err(AttemptLifecycleError::UnknownAttempt),
            Some(slot) if slot.grant() != agr1_digest => Err(AttemptLifecycleError::GrantMismatch),
            Some(
                Slot::Running { .. }
                | Slot::Ended {
                    response: Retained::Pending,
                    ..
                },
            ) => Err(AttemptLifecycleError::AttemptActive),
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
    /// place.
    ///
    /// # Errors
    /// Those of [`AttemptLifecycle::terminal_response`];
    /// [`AttemptLifecycleError::Response`] with
    /// [`ResponseFault::Evidence`] for a response that cannot be re-issued
    /// with `transfer`, which keeps the retained response; and with
    /// [`ResponseFault::Sign`] for a successor that cannot be signed, a
    /// provider fault that quarantines the lifecycle.
    pub fn reissue_response<R: RuntimeAttestationSigner>(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
        transfer: TransferRecord,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let stored = self.terminal_response(attempt_id, agr1_digest)?;
        match stored.successor(transfer, signer, admitted) {
            Err(ResponseFault::Evidence(refused)) => Err(ResponseFault::Evidence(refused).into()),
            successor => self.store(attempt_id, Some(&stored), successor.map(Arc::new)),
        }
    }

    /// Retain `signed` for the ended attempt whose response is still
    /// `expected` (pending when `None`), or record its fault and quarantine.
    /// A response that changed meanwhile is returned instead.
    fn store(
        &self,
        attempt_id: [u8; 16],
        expected: Option<&Arc<RetainedResponse>>,
        signed: Result<Arc<RetainedResponse>, ResponseFault>,
    ) -> Result<Arc<RetainedResponse>, AttemptLifecycleError> {
        let mut attempts = lock(&self.attempts);
        let Some(Slot::Ended { response, .. }) = attempts.slots.get_mut(&attempt_id) else {
            return Err(AttemptLifecycleError::UnknownAttempt);
        };
        let current = match (&*response, expected) {
            (Retained::Pending, None) => None,
            (Retained::Signed(current), Some(expected)) if Arc::ptr_eq(current, expected) => None,
            (Retained::Signed(current), _) => Some(Ok(Arc::clone(current))),
            (Retained::Faulted | Retained::Pending, _) => {
                Some(Err(AttemptLifecycleError::ResponseUnavailable))
            }
        };
        if let Some(current) = current {
            return current;
        }
        *response = signed.as_ref().map_or(Retained::Faulted, |signed| {
            Retained::Signed(Arc::clone(signed))
        });
        drop(attempts);
        signed.map_err(|fault| {
            self.quarantine();
            fault.into()
        })
    }
}
