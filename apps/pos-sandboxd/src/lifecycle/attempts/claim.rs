//! The pre-AGR1 claim of one exchange (ADR-069 R11 Amendment 1, item P8).
//!
//! The execute port claims the attempt in the attempts table before any
//! attempt or input reservation (port step A). The claim counts toward the
//! 256-attempt cap, so a recovery snapshot can still carry every live
//! attempt. A fence voids every claim. The claim converts under the attempts
//! lock as the last check right before the AGR1 write, and that lock covers
//! nothing else: never the held-image join, the signing or the write, since
//! `fence()` takes it and a control exchange ends within 100 ms (R11 §8.3).
//! If the write then fails, the converted slot is removed. An exact repeat
//! waits on the claim or the converted slot through
//! [`AttemptLifecycle::join`]: when either is removed it re-enters the port
//! at step 7 as a new exchange.

use std::sync::atomic::Ordering;

use tokio::sync::watch;

use super::{lock, AttemptLifecycle, AttemptLifecycleError, Slot, MAX_LIVE_ATTEMPTS};
use crate::VerifiedStagedInput;

/// One exchange's claim of its attempt before AGR1.
///
/// Only [`AttemptLifecycle::claim`] creates one. Dropping it before
/// [`Self::convert`] releases the claim and wakes its waiters.
#[derive(Debug)]
pub struct ExchangeClaim<'l, I = VerifiedStagedInput> {
    held: Held<'l, I>,
}

/// The converted slot of an exchange whose AGR1 is being written.
///
/// Dropping it before [`Self::written`] means the write failed: the slot is
/// removed and its waiters are woken, and no attempt is admitted (R11
/// Amendment 1 §7.5).
#[derive(Debug)]
pub struct GrantWrite<'l, I = VerifiedStagedInput> {
    held: Held<'l, I>,
}

/// The slot one claim or grant write holds, removed on drop unless
/// released.
#[derive(Debug)]
struct Held<'l, I> {
    lifecycle: &'l AttemptLifecycle<I>,
    attempt_id: [u8; 16],
    armed: bool,
}

impl<I> Drop for Held<'_, I> {
    fn drop(&mut self) {
        if self.armed {
            let mut attempts = lock(&self.lifecycle.attempts);
            // Only this exchange converts its claim, and after a fence no
            // other exchange can claim the attempt, so a claimed or granted
            // slot is this one's.
            let ours = matches!(
                attempts.get(&self.attempt_id),
                Some(Slot::Claimed { .. } | Slot::Granted { .. })
            );
            let removed = ours.then(|| attempts.remove(self.attempt_id));
            drop(attempts);
            // Its waiters are woken outside the attempts lock.
            drop(removed);
        }
    }
}

impl<I> AttemptLifecycle<I> {
    /// Claim `attempt_id` for the exchange whose SPX1, with request ID
    /// `request_id`, digests to `request_digest` (R11 Amendment 1 §7.5, port
    /// step A).
    ///
    /// # Errors
    /// [`AttemptLifecycleError::Fenced`] once the runtime was fenced;
    /// [`AttemptLifecycleError::UnknownAttempt`] for a reconciled or
    /// withdrawn attempt; [`AttemptLifecycleError::RequestConflict`] for a
    /// known attempt, or a request ID claimed before, with other bytes;
    /// [`AttemptLifecycleError::AttemptKnown`] for a known attempt with the
    /// same bytes, which joins it instead; and
    /// [`AttemptLifecycleError::TooManyLiveAttempts`] at 256 live attempts.
    pub fn claim(
        &self,
        attempt_id: [u8; 16],
        request_id: [u8; 16],
        request_digest: [u8; 32],
    ) -> Result<ExchangeClaim<'_, I>, AttemptLifecycleError> {
        let mut attempts = lock(&self.attempts);
        let request_reused = attempts
            .requests
            .get(&request_id)
            .is_some_and(|claimed| *claimed != request_digest);
        let refusal = if self.fenced.load(Ordering::Acquire) {
            Some(AttemptLifecycleError::Fenced)
        } else {
            match attempts.get(&attempt_id) {
                Some(Slot::Reconciled { .. }) => Some(AttemptLifecycleError::UnknownAttempt),
                Some(
                    Slot::Claimed { request, .. }
                    | Slot::Granted { request, .. }
                    | Slot::Running { request, .. }
                    | Slot::Ended { request, .. },
                ) if *request != request_digest => Some(AttemptLifecycleError::RequestConflict),
                Some(_) => Some(AttemptLifecycleError::AttemptKnown),
                None if request_reused => Some(AttemptLifecycleError::RequestConflict),
                // A recovery snapshot must be able to carry every live
                // attempt.
                None if attempts.live >= MAX_LIVE_ATTEMPTS => {
                    Some(AttemptLifecycleError::TooManyLiveAttempts)
                }
                None => None,
            }
        };
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        attempts.requests.insert(request_id, request_digest);
        let claimed = Slot::Claimed {
            request: request_digest,
            changed: watch::channel(false).0,
        };
        attempts.set(attempt_id, claimed);
        drop(attempts);
        Ok(ExchangeClaim {
            held: Held {
                lifecycle: self,
                attempt_id,
                armed: true,
            },
        })
    }
}

impl<'l, I> ExchangeClaim<'l, I> {
    /// Convert the claim for the AGR1 that digests to `grant_digest`, under
    /// the attempts lock, as the last check before that AGR1 is written.
    /// From here a fence never refuses the attempt's admission or failed
    /// input, so it gets a stored terminal response.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::Fenced`] when a fence voided the claim; the
    /// exchange then writes no AGR1 byte.
    pub fn convert(
        mut self,
        grant_digest: [u8; 32],
    ) -> Result<GrantWrite<'l, I>, AttemptLifecycleError> {
        let lifecycle = self.held.lifecycle;
        let mut attempts = lock(&lifecycle.attempts);
        let request = match attempts.get(&self.held.attempt_id) {
            Some(Slot::Claimed { request, .. }) => *request,
            _ => return Err(AttemptLifecycleError::Fenced),
        };
        let granted = Slot::Granted {
            grant: grant_digest,
            request,
            cancel: None,
            changed: watch::channel(false).0,
        };
        let claimed = attempts.set(self.held.attempt_id, granted);
        drop(attempts);
        // The claim wakes its waiters outside the attempts lock.
        drop(claimed);
        let held = Held {
            lifecycle,
            attempt_id: self.held.attempt_id,
            armed: true,
        };
        self.held.armed = false;
        Ok(GrantWrite { held })
    }
}

impl<I> GrantWrite<'_, I> {
    /// The AGR1 was completely written: the attempt is admitted, and its
    /// input is awaited.
    pub fn written(mut self) {
        self.held.armed = false;
    }
}

#[cfg(test)]
impl<I> AttemptLifecycle<I> {
    /// Claim `attempt_id` under the test SPX1 digest `[0x5d; 32]`, convert
    /// it for `grant` and write that AGR1, as the execute port does before
    /// the attempt's input is admitted.
    pub(crate) fn granted_for_test(
        &self,
        attempt_id: [u8; 16],
        grant: [u8; 32],
    ) -> Result<(), AttemptLifecycleError> {
        self.claim(attempt_id, attempt_id, [0x5d; 32])
            .and_then(|claim| claim.convert(grant))
            .map(GrantWrite::written)
    }

    /// [`Self::admit_input`] after the AGR1 of `input` was granted.
    pub(super) fn admit_granted(
        &self,
        input: I,
    ) -> Result<super::OwnedAttempt<'_, I>, AttemptLifecycleError>
    where
        I: super::AdmittedInput,
    {
        self.granted_for_test(input.attempt_id(), input.grant_digest())
            .and_then(|()| self.admit_input(input))
    }
}

#[cfg(test)]
impl AttemptLifecycle {
    /// [`Self::record_failed_input`] after the AGR1 of `failed` was granted.
    pub(crate) fn failed_granted(
        &self,
        failed: &pos_reference::provider_admission::execution::FailedInput,
    ) -> Result<crate::EndedAttempt<crate::SystemdVerifiedStart>, AttemptLifecycleError> {
        self.granted_for_test(failed.attempt_id(), failed.grant().digest())
            .and_then(|()| self.record_failed_input(failed))
    }
}
