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
//! at step 7 as a new exchange. A claim released, voided or whose write
//! failed admitted nothing, so its request ID is free again; after AGR1 the
//! request ID stays known for as long as the attempt or its tombstone.
//!
//! Once AGR1 was written the exchange owes the attempt its input: an
//! [`AwaitedInput`] is consumed by the admission or the failed input. An
//! exchange that ends without either was interrupted after AGR1: base §4
//! retains the grant and classifies it as a post-admission failure, so the
//! dropped input is recorded and signed exactly as a failed input (TME1
//! progress 0, `input.complete = false`, code 10; Redmine #443 journal
//! 22592), never left as an orphaned slot.

use std::sync::atomic::Ordering;

use tokio::sync::watch;

use pos_reference::provider_admission::execution::FailedInput;

use crate::{AdmittedRuntimeKey, KeyFileRuntimeSigner, RuntimeAttestationSigner};

use super::{lock, AttemptLifecycle, AttemptLifecycleError, OwnedAttempt, Slot, MAX_LIVE_ATTEMPTS};
use crate::{EndedAttempt, SystemdVerifiedStart, VerifiedStagedInput};

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

/// The failed input of an exchange interrupted after its AGR1, as far as
/// its transfer got: the serving layer's staging state supplies it.
pub type InterruptedInput<'l> = Box<dyn FnOnce() -> FailedInput + Send + 'l>;

/// A granted attempt whose AGR1 was completely written, awaiting its
/// input.
///
/// Its admission or its failed input consumes it. Dropping it otherwise
/// means the exchange was interrupted after AGR1, a routine post-admission
/// failure (base ADR-069 §4): its [`InterruptedInput`] is recorded exactly
/// as [`Self::record_failed_input`] records a failed input, and its response
/// is signed and retained, so joined repeats receive the stored code-10
/// response and the lifecycle stays open. Only a refusal while it is
/// settled, which means the caller named another attempt or grant, faults
/// the attempt and quarantines the lifecycle.
pub struct AwaitedInput<
    'l,
    I = VerifiedStagedInput,
    R: RuntimeAttestationSigner = KeyFileRuntimeSigner,
> {
    lifecycle: &'l AttemptLifecycle<I>,
    attempt_id: [u8; 16],
    interrupted: Option<InterruptedInput<'l>>,
    signer: &'l R,
    admitted: AdmittedRuntimeKey<'l>,
}

impl<I, R: RuntimeAttestationSigner> std::fmt::Debug for AwaitedInput<'_, I, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwaitedInput")
            .field("attempt_id", &self.attempt_id)
            .field("owed", &self.interrupted.is_some())
            .finish_non_exhaustive()
    }
}

/// The slot one claim or grant write holds, released on drop unless it was
/// passed on.
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
            let released = attempts.release(self.attempt_id);
            drop(attempts);
            // Its waiters are woken outside the attempts lock.
            drop(released);
        }
    }
}

impl<I, R: RuntimeAttestationSigner> Drop for AwaitedInput<'_, I, R> {
    fn drop(&mut self) {
        if let Some(interrupted) = self.interrupted.take() {
            // The same record, signing and retention as a failed input; a
            // response that cannot be signed is faulted there (R9 §5).
            match self
                .lifecycle
                .record_failed::<SystemdVerifiedStart, _>(&interrupted())
            {
                Ok(ended) => drop(self.lifecycle.retain_response(
                    ended,
                    self.signer,
                    self.admitted,
                )),
                Err(_) => self.fault(),
            }
        }
    }
}

impl<I, R: RuntimeAttestationSigner> AwaitedInput<'_, I, R> {
    /// The caller named another attempt or grant than the one it owes: the
    /// awaited attempt is recorded as ended with no response, a provider
    /// fault that quarantines the lifecycle, so its slot is not orphaned.
    fn fault(&self) {
        let mut attempts = lock(&self.lifecycle.attempts);
        let abandoned = attempts.abandon(self.attempt_id);
        drop(attempts);
        if abandoned.is_some() {
            self.lifecycle.quarantine();
        }
        // Its waiters are woken outside the attempts lock.
        drop(abandoned);
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
            request_id,
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
        let (request, request_id) = match attempts.get(&self.held.attempt_id) {
            Some(Slot::Claimed {
                request,
                request_id,
                ..
            }) => (*request, *request_id),
            _ => return Err(AttemptLifecycleError::Fenced),
        };
        let granted = Slot::Granted {
            grant: grant_digest,
            request,
            request_id,
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

impl<'l, I> GrantWrite<'l, I> {
    /// The AGR1 was completely written: the attempt is admitted, and its
    /// input is awaited. `interrupted` supplies the failed input should the
    /// exchange end without one, and `signer` signs its response under
    /// `admitted`.
    #[must_use = "a dropped awaited input records an interrupted input"]
    pub fn written<R: RuntimeAttestationSigner>(
        mut self,
        interrupted: InterruptedInput<'l>,
        signer: &'l R,
        admitted: AdmittedRuntimeKey<'l>,
    ) -> AwaitedInput<'l, I, R> {
        self.held.armed = false;
        AwaitedInput {
            lifecycle: self.held.lifecycle,
            attempt_id: self.held.attempt_id,
            interrupted: Some(interrupted),
            signer,
            admitted,
        }
    }
}

impl<'l, I, R: RuntimeAttestationSigner> AwaitedInput<'l, I, R> {
    /// Settle the obligation with `settled`. A refusal means the caller
    /// named another attempt or grant: a provider bug, which faults it.
    fn settle<T>(
        mut self,
        settled: impl FnOnce(&'l AttemptLifecycle<I>) -> Result<T, AttemptLifecycleError>,
    ) -> Result<T, AttemptLifecycleError> {
        self.interrupted = None;
        let settled = settled(self.lifecycle);
        if settled.is_err() {
            self.fault();
        }
        settled
    }
}

impl<'l, I, R: RuntimeAttestationSigner> AwaitedInput<'l, I, R> {
    /// Take exclusive ownership of the attempt `input` admitted.
    pub(super) fn admit_owned(self, input: I) -> Result<OwnedAttempt<'l, I>, AttemptLifecycleError>
    where
        I: super::AdmittedInput,
    {
        self.settle(|lifecycle| lifecycle.admit_input(input))
    }

    /// Record the attempt `failed` names as ended by its failed input.
    pub(super) fn record_failed_admission<S, F: super::FailedAdmission>(
        self,
        failed: &F,
    ) -> Result<EndedAttempt<S>, AttemptLifecycleError> {
        self.settle(|lifecycle| lifecycle.record_failed(failed))
    }
}

impl<'l, R: RuntimeAttestationSigner> AwaitedInput<'l, VerifiedStagedInput, R> {
    /// Take exclusive ownership of the attempt `input` admitted.
    ///
    /// The lifecycle keeps the admission, and its staging reservation, until
    /// the attempt is withdrawn before it started, its run is dropped part-way
    /// (after the lifecycle was quarantined), or it is reconciled after it
    /// ended clean. An attempt that ended with its cleanup unproved keeps it:
    /// its reconcile reports [`AttemptLifecycleError::CleanupFailed`]. A
    /// fence or cancellation since the conversion never refuses it: its run
    /// records the cancelled ending with nothing committed (ADR-069 R11
    /// Amendment 1, item P8).
    ///
    /// # Errors
    /// [`AttemptLifecycleError::GrantMismatch`] when `input` was admitted
    /// under another AGR1, and [`AttemptLifecycleError::UnknownAttempt`]
    /// for another attempt. The refused input is dropped, releasing its
    /// reservation, and the awaited attempt ends with no response: a
    /// provider fault that quarantines the lifecycle.
    pub fn admit(
        self,
        input: VerifiedStagedInput,
    ) -> Result<OwnedAttempt<'l>, AttemptLifecycleError> {
        self.admit_owned(input)
    }

    /// Record the attempt whose input failed after its AGR1 was sent.
    ///
    /// The attempt is admitted, so it is never relaunched and ends in a
    /// stored `UnavailableAfterAdmission`, not in SPE1 (ADR-069 §4). It
    /// ended with nothing committed: no intent, directory, root or unit, and
    /// its staging reservation was already released. It stays known until it
    /// is reconciled; a cancellation reports it already terminal. It is not
    /// part of a recovery snapshot, since it left nothing to recover. A
    /// fence since the conversion never refuses it, and the first
    /// cancellation requested meanwhile is its TME1 `cancel-source` (owner
    /// decision 2026-11-15, Redmine #443 journal 22319).
    ///
    /// # Errors
    /// Those of [`Self::admit`].
    pub fn record_failed_input(
        self,
        failed: &FailedInput,
    ) -> Result<EndedAttempt<SystemdVerifiedStart>, AttemptLifecycleError> {
        self.record_failed_admission(failed)
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
            .map(|write| {
                let mut awaited = write.written_for_test(grant);
                // The test admits or records the attempt itself.
                awaited.interrupted = None;
            })
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
impl<I> AttemptLifecycle<I> {
    /// The request IDs this runtime still knows, with their SPX1 digests.
    pub(super) fn lock_requests(&self) -> std::collections::BTreeMap<[u8; 16], [u8; 32]> {
        lock(&self.attempts).requests.clone()
    }
}

#[cfg(test)]
impl AttemptLifecycle {
    /// [`AwaitedInput::record_failed_input`] after the AGR1 of `failed` was
    /// granted.
    pub(crate) fn failed_granted(
        &self,
        failed: &FailedInput,
    ) -> Result<EndedAttempt<SystemdVerifiedStart>, AttemptLifecycleError> {
        self.claim(failed.attempt_id(), failed.attempt_id(), [0x5d; 32])
            .and_then(|claim| claim.convert(failed.grant().digest()))
            .and_then(|write| {
                write
                    .written_for_test(failed.grant().digest())
                    .record_failed_input(failed)
            })
    }
}

#[cfg(test)]
impl<'l, I> GrantWrite<'l, I> {
    /// [`Self::written`] with the test runtime key, whose interrupted input
    /// is the fixture failed input of `grant`.
    pub(crate) fn written_for_test(self, grant: [u8; 32]) -> AwaitedInput<'l, I> {
        static SIGNER: std::sync::OnceLock<KeyFileRuntimeSigner> = std::sync::OnceLock::new();
        static KEY: std::sync::OnceLock<ed25519_dalek::VerifyingKey> = std::sync::OnceLock::new();
        let signing = || ed25519_dalek::SigningKey::from_bytes(&crate::test_fixtures::RUNTIME_SEED);
        let signer = SIGNER.get_or_init(|| {
            KeyFileRuntimeSigner::from_signing_key(
                signing(),
                crate::test_fixtures::RUNTIME_KEY_ID.to_owned(),
            )
        });
        let key = KEY.get_or_init(|| signing().verifying_key());
        let attempt_id = self.held.attempt_id;
        self.written(
            Box::new(move || FailedInput::fixture(attempt_id, grant)),
            signer,
            AdmittedRuntimeKey::new(crate::test_fixtures::RUNTIME_KEY_ID, key),
        )
    }
}
