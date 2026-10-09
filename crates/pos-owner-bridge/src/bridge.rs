//! `OwnerBridge` (ADR-110 §10): enroll with D2 confirmation, unlock, status and quarantine.

mod restart;

use std::time::Instant;

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, OwnerUserHandle, PrfInput, SubjectCredentialBindingV1,
};
use zeroize::Zeroizing;

use restart::Pending;

use crate::ceremony::driver::CeremonyDriver;
use crate::ceremony::plan::{
    Assertion, Budget, CeremonyPlan, Registration, Slots, StoredGet, Verified,
};
use crate::{
    BindingUpdate, BridgeError, BridgeStatus, CeremonyHost, CeremonyReply, CleanupStore,
    ConfirmedBinding, EnrollmentContext, EnrollmentPort, MonotonicClock, PrfOutput, ProcessProbe,
    QuarantineCode, RejectedCode, RootFingerprint, SecureRandom, UnavailableCode, UnlockPort,
};

/// The failure when the slots are not in the bridge's hands: a host dropped the driver.
const SLOTS_HELD: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// Bridge construction options.
///
/// The ceremony generation starts at the ADR-110 §6 value of 1; only tests can start it elsewhere.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    start_generation: u32,
    owner_window: Option<u64>,
}

impl BridgeConfig {
    /// Options for a bridge whose unlock ceremonies are owned by `owner_window`.
    #[must_use]
    pub const fn new(owner_window: Option<u64>) -> Self {
        Self {
            start_generation: 1,
            owner_window,
        }
    }

    /// Start the per-process generation at `generation`, so tests can reach its limit.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn with_start_generation(self, generation: u32) -> Self {
        Self {
            start_generation: generation,
            ..self
        }
    }
}

impl Default for BridgeConfig {
    /// No owner window, and the generation starting at 1.
    fn default() -> Self {
        Self::new(None)
    }
}

/// The progress of a restart check (ADR-110 §16).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartProgress {
    /// Every recorded process is gone.
    Done {
        /// Records of absent processes whose folder or record could not be removed yet.
        deferred: usize,
    },
    /// A recorded process is still present: poll again at `wake`.
    Waiting {
        /// When the next probe is due.
        wake: Instant,
    },
}

/// The owner bridge: draws each ceremony's randomness on the owner thread, hands the driver to
/// the host that owns the surface, and runs the enrollment and unlock flows around the result.
///
/// ADR-110 §10 writes this type as generic over the surface. ADR §1a and §6 put the surface and
/// the driver on the host's surface thread, so the bridge here is generic over the
/// [`CeremonyHost`] that owns them instead.
pub struct OwnerBridge<H: CeremonyHost, R: SecureRandom, C: MonotonicClock> {
    host: H,
    random: R,
    clock: C,
    generation: u32,
    owner_window: Option<u64>,
    status: BridgeStatus,
    slots: Option<Box<Slots>>,
    quarantined: bool,
    started: bool,
    restart: Option<Pending>,
    restart_failure: Option<BridgeError>,
}

/// An enrollment failure and the candidate that still needs `abandon`.
struct EnrollFailure<C> {
    error: BridgeError,
    candidate: Option<C>,
}

impl<C> From<BridgeError> for EnrollFailure<C> {
    fn from(error: BridgeError) -> Self {
        Self {
            error,
            candidate: None,
        }
    }
}

/// The fixed inputs of one Create ceremony that later steps reuse.
struct CreatedCredential {
    registration: Registration,
    user_handle: OwnerUserHandle,
    prf_input: PrfInput,
}

fn split_array<const N: usize>(bytes: &[u8]) -> (Zeroizing<[u8; N]>, &[u8]) {
    bytes.split_first_chunk::<N>().map_or_else(
        || (Zeroizing::new([0; N]), &[][..]),
        |(head, rest)| (Zeroizing::new(*head), rest),
    )
}

fn stored_from_registration(
    registration: &Registration,
    user_handle: OwnerUserHandle,
) -> StoredGet {
    StoredGet {
        credential_id: registration.credential_id.clone(),
        user_handle,
        public_key: registration.public_key,
        backup_eligible: registration.backup_eligible,
        backup_state: registration.backup_state,
        sign_count: registration.sign_count,
    }
}

impl<H: CeremonyHost, R: SecureRandom, C: MonotonicClock> OwnerBridge<H, R, C> {
    /// Allocate the bridge and its preallocated ceremony buffers.
    #[must_use]
    pub fn new(host: H, random: R, clock: C, config: BridgeConfig) -> Self {
        Self {
            host,
            random,
            clock,
            generation: config.start_generation,
            owner_window: config.owner_window,
            status: BridgeStatus::Ready,
            slots: Some(Slots::allocate()),
            quarantined: false,
            started: false,
            restart: None,
            restart_failure: None,
        }
    }

    /// The current status.
    #[must_use]
    pub const fn status(&self) -> BridgeStatus {
        self.status
    }

    /// Whether the request image and both PRF slots are zero; `true` while a quarantined driver
    /// holds the slots.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn secret_slots_clear(&self) -> bool {
        self.slots.as_deref().is_none_or(Slots::secrets_clear)
    }

    /// Poll the quarantined ceremonies for their browser exit; the status clears once the last
    /// quarantined driver the host holds has finished its cleanup.
    pub fn poll_quarantine(&mut self) -> BridgeStatus {
        if self.quarantined {
            let polled = self.host.poll_quarantine();
            if let Some(driver) = polled.driver {
                self.generation = driver.generation();
                self.slots = Some(driver.into_slots());
                // Another driver the host still holds may have a live browser.
                self.quarantined = polled.remaining;
                if !polled.remaining {
                    self.status = BridgeStatus::Ready;
                }
            }
        }
        self.status
    }

    /// Probe stale cleanup records at process start (ADR-110 §16): the first pass.
    ///
    /// While a recorded browser process is still present the status is
    /// `Quarantined(StaleProcessPresent)` and the result is `Waiting`: the host calls
    /// [`OwnerBridge::poll_restart_check`] at the instant it names, once a second for 30 s. The
    /// portable core never sleeps.
    ///
    /// It must run before any ceremony: its orphan-folder sweep would remove the folder of a live
    /// ceremony. A bridge that ever started a ceremony refuses it.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable(InterfaceUnavailable)` when a ceremony was ever started or the store
    /// cannot list its records, and `Quarantine(StaleProcessPresent)` when a record cannot be
    /// decoded or does not name the folder its ceremony ID derives. The last two hold the bridge
    /// in their status until the next check succeeds.
    pub fn start_restart_check(
        &mut self,
        store: &mut dyn CleanupStore,
        probe: &mut dyn ProcessProbe,
    ) -> Result<RestartProgress, BridgeError> {
        if self.started {
            return Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable,
            ));
        }
        let now = self.clock.now();
        let outcome = restart::begin(store, probe, now);
        self.settle_restart(outcome)
    }

    /// Probe again if the next probe is due; call it at the instant [`RestartProgress::Waiting`]
    /// named. Without a pending check it reports `Done` with nothing deferred, unless the last
    /// restart check ended in a failure: then it returns that failure again. A ceremony's
    /// quarantine or a latched `Unavailable` status is not a restart-check failure and is not
    /// reported here; [`OwnerBridge::status`] is authoritative.
    ///
    /// # Errors
    ///
    /// Returns `Quarantine(StaleProcessPresent)` once a recorded process is still present after
    /// 30 repeats; the surface then stays quarantined, and so does every later poll until a new
    /// check succeeds.
    pub fn poll_restart_check(
        &mut self,
        store: &mut dyn CleanupStore,
        probe: &mut dyn ProcessProbe,
    ) -> Result<RestartProgress, BridgeError> {
        let Some(pending) = self.restart.take() else {
            return self
                .restart_failure
                .map_or(Ok(RestartProgress::Done { deferred: 0 }), Err);
        };
        let now = self.clock.now();
        let outcome = restart::poll(pending, store, probe, now);
        self.settle_restart(outcome)
    }

    fn settle_restart(
        &mut self,
        outcome: Result<restart::Progress, BridgeError>,
    ) -> Result<RestartProgress, BridgeError> {
        self.restart = None;
        self.restart_failure = outcome.as_ref().err().copied();
        match outcome {
            Ok(restart::Progress::Done(deferred)) => {
                self.status = BridgeStatus::Ready;
                Ok(RestartProgress::Done { deferred })
            }
            Ok(restart::Progress::Waiting(pending)) => {
                let wake = pending.wake();
                self.restart = Some(pending);
                self.status = BridgeStatus::Quarantined(QuarantineCode::StaleProcessPresent);
                Ok(RestartProgress::Waiting { wake })
            }
            Err(error) => {
                self.status = BridgeStatus::after_restart(Some(error));
                Err(error)
            }
        }
    }

    fn begin(&mut self) -> Result<(), BridgeError> {
        self.status.admission()?;
        self.status = BridgeStatus::Busy;
        self.started = true;
        Ok(())
    }

    fn end<T>(&mut self, result: &Result<T, BridgeError>) {
        self.status = BridgeStatus::after(result.as_ref().err().copied());
    }

    /// Zero the slots the bridge holds. While a driver holds them, or a host dropped it, there is
    /// nothing to wipe and nothing is allocated.
    fn wipe_slots(&mut self) {
        if let Some(slots) = self.slots.as_deref_mut() {
            slots.wipe_all();
        }
    }

    /// Run `operation` on the slots the bridge holds. They are absent while a quarantined driver
    /// holds them, or when a host broke its contract and dropped the driver without a quarantine;
    /// `begin` admits the second case, and the bridge then fails each call with `SLOTS_HELD`
    /// rather than allocate new slots (ADR-110 §5.6 allocates once, at construction).
    fn with_slots<T>(&mut self, operation: impl FnOnce(&mut Slots) -> T) -> Result<T, BridgeError> {
        self.slots.as_deref_mut().map(operation).ok_or(SLOTS_HELD)
    }

    fn draw_plan(&mut self, request: PlanRequest) -> Result<CeremonyPlan, BridgeError> {
        if self.generation == u32::MAX {
            return Err(BridgeError::Unavailable(
                UnavailableCode::GenerationExhausted,
            ));
        }
        let mut block = Zeroizing::new([0_u8; 112]);
        let used = match request.kind {
            CeremonyKind::Create => 112,
            CeremonyKind::Get => 48,
        };
        self.random
            .fill(block.get_mut(..used).unwrap_or_default())
            .map_err(BridgeError::Unavailable)?;
        let t0 = self.clock.now();
        let (id, rest) = split_array::<16>(block.as_slice());
        let (challenge, rest) = split_array::<32>(rest);
        let (user_handle, rest) = split_array::<32>(rest);
        let (fresh_prf, _) = split_array::<32>(rest);
        Ok(CeremonyPlan {
            kind: request.kind,
            ceremony_id: CeremonyId::from_bytes(*id),
            challenge,
            user_handle,
            prf_input: request
                .prf_input
                .map_or(fresh_prf, |input| Zeroizing::new(*input.as_bytes())),
            stored: request.stored,
            t0,
            generation: self.generation,
            owner_window: request.owner_window,
            budget: request.budget,
        })
    }

    fn run_ceremony(&mut self, plan: CeremonyPlan) -> Result<Verified, BridgeError> {
        let slots = self.slots.take().ok_or(SLOTS_HELD)?;
        let reply = self.host.run(CeremonyDriver::new(plan, slots));
        self.conclude(reply)
    }

    fn conclude(&mut self, reply: CeremonyReply) -> Result<Verified, BridgeError> {
        if let Some(driver) = reply.driver {
            self.generation = driver.generation();
            self.slots = Some(driver.into_slots());
        }
        // A host that keeps a quarantined driver says so by the result alone. A host that also
        // returns the driver breaks that contract and leaves the bridge quarantined (fail
        // closed): only `poll_quarantine` clears the flag.
        self.quarantined = matches!(reply.result, Err(BridgeError::Quarantine(_)));
        reply.result
    }

    fn create_ceremony(
        &mut self,
        context: &EnrollmentContext,
    ) -> Result<CreatedCredential, BridgeError> {
        let plan = self.draw_plan(PlanRequest {
            kind: CeremonyKind::Create,
            stored: None,
            prf_input: None,
            budget: None,
            owner_window: context.owner_window,
        })?;
        let (user_handle, prf_input) = (plan.owner_user_handle(), plan.prf_input_value());
        let registration = self
            .run_ceremony(plan)
            .and_then(Verified::into_registration)?;
        Ok(CreatedCredential {
            registration,
            user_handle,
            prf_input,
        })
    }

    fn get_ceremony(
        &mut self,
        stored: StoredGet,
        prf_input: PrfInput,
        budget: Option<Budget>,
    ) -> Result<Assertion, BridgeError> {
        let plan = self.draw_plan(PlanRequest {
            kind: CeremonyKind::Get,
            stored: Some(stored),
            prf_input: Some(prf_input),
            budget,
            owner_window: self.owner_window,
        })?;
        self.run_ceremony(plan).and_then(Verified::into_assertion)
    }

    /// Run enrollment E1 to E5 (ADR-110 §8). A failure after `seal_candidate` returned a candidate
    /// and before `commit` calls `abandon` once; no other failure does.
    ///
    /// # Errors
    ///
    /// Returns the ceremony, verification, budget or owner-port failure that ended enrollment.
    pub fn enroll<P: EnrollmentPort>(
        &mut self,
        context: &EnrollmentContext,
        port: &mut P,
    ) -> Result<(), BridgeError> {
        self.begin()?;
        let outcome = self.enroll_steps(context, port).map_err(|failure| {
            if let Some(candidate) = failure.candidate {
                port.abandon(candidate);
            }
            failure.error
        });
        self.wipe_slots();
        self.end(&outcome);
        outcome
    }

    fn enroll_steps<P: EnrollmentPort>(
        &mut self,
        context: &EnrollmentContext,
        port: &mut P,
    ) -> Result<(), EnrollFailure<P::Candidate>> {
        let created = self.create_ceremony(context)?;
        let budget = Budget::enrollment(self.clock.now());
        require_unbound(port, &created.registration)?;
        let stored = self.source_prf(&created, budget)?;
        let (candidate, sealed) = self
            .with_slots(|slots| {
                let sealed = port.seal_candidate(PrfOutput::new(&slots.create_prf), context);
                slots.create_prf.fill(0);
                sealed
            })?
            .map_err(BridgeError::Owner)?;
        let run = EnrollmentRun {
            context,
            created,
            stored,
            budget,
        };
        self.confirm_and_commit(port, &run, candidate, &sealed)
    }

    fn source_prf(
        &mut self,
        created: &CreatedCredential,
        budget: Budget,
    ) -> Result<StoredGet, BridgeError> {
        let mut stored = stored_from_registration(&created.registration, created.user_handle);
        if !created.registration.prf_present {
            let assertion = self.get_ceremony(stored.clone(), created.prf_input, Some(budget))?;
            stored.sign_count = assertion.sign_count;
            stored.backup_state = assertion.backup_state;
        }
        self.with_slots(|slots| {
            slots.create_prf.copy_from_slice(slots.prf.as_slice());
            slots.prf.fill(0);
        })?;
        Ok(stored)
    }

    fn confirm_and_commit<P: EnrollmentPort>(
        &mut self,
        port: &mut P,
        run: &EnrollmentRun<'_>,
        candidate: P::Candidate,
        sealed: &RootFingerprint,
    ) -> Result<(), EnrollFailure<P::Candidate>> {
        let confirmation = match self.confirm(port, run, &candidate, sealed) {
            Ok(confirmation) => confirmation,
            Err(error) => {
                return Err(EnrollFailure {
                    error,
                    candidate: Some(candidate),
                })
            }
        };
        let binding = ConfirmedBinding::from_confirmation(
            run.context,
            &run.created.registration,
            run.created.user_handle,
            confirmation,
        );
        match binding {
            Ok(binding) => port
                .commit(candidate, binding)
                .map_err(|error| EnrollFailure::from(BridgeError::Owner(error))),
            Err(error) => Err(EnrollFailure {
                error,
                candidate: Some(candidate),
            }),
        }
    }

    fn confirm<P: EnrollmentPort>(
        &mut self,
        port: &mut P,
        run: &EnrollmentRun<'_>,
        candidate: &P::Candidate,
        sealed: &RootFingerprint,
    ) -> Result<Assertion, BridgeError> {
        let assertion =
            self.get_ceremony(run.stored.clone(), run.created.prf_input, Some(run.budget))?;
        let confirmed = self
            .with_slots(|slots| {
                let confirmed = port.confirm_candidate(candidate, PrfOutput::new(&slots.prf));
                slots.prf.fill(0);
                confirmed
            })?
            .map_err(BridgeError::Owner)?;
        if sealed.constant_time_eq(&confirmed) {
            Ok(assertion)
        } else {
            Err(BridgeError::Rejected(RejectedCode::EnrollmentConfirmation))
        }
    }

    /// Unlock with a Get ceremony, then open, persist and release (ADR-110 §8).
    ///
    /// # Errors
    ///
    /// Returns the ceremony, verification or owner-port failure; a failed binding update
    /// releases no root.
    pub fn unlock<P: UnlockPort>(
        &mut self,
        binding: &SubjectCredentialBindingV1<'_>,
        prf_input: &[u8; 32],
        port: &mut P,
    ) -> Result<P::Session, BridgeError> {
        self.begin()?;
        let outcome = self.unlock_steps(binding, prf_input, port);
        self.wipe_slots();
        self.end(&outcome);
        outcome
    }

    fn unlock_steps<P: UnlockPort>(
        &mut self,
        binding: &SubjectCredentialBindingV1<'_>,
        prf_input: &[u8; 32],
        port: &mut P,
    ) -> Result<P::Session, BridgeError> {
        let stored = StoredGet {
            credential_id: binding.credential_id().to_vec(),
            user_handle: binding.user_handle(),
            public_key: binding.public_key(),
            backup_eligible: binding.backup_eligible(),
            backup_state: binding.backup_state(),
            sign_count: binding.sign_count(),
        };
        let assertion = self.get_ceremony(stored, PrfInput::from_bytes(*prf_input), None)?;
        let pending = self
            .with_slots(|slots| {
                let pending = port.open_pending(PrfOutput::new(&slots.prf));
                slots.prf.fill(0);
                pending
            })?
            .map_err(BridgeError::Owner)?;
        let update = BindingUpdate {
            sign_count: assertion.sign_count,
            backup_state: assertion.backup_state,
        };
        port.persist_binding_update(&update)
            .map_err(BridgeError::Owner)?;
        Ok(port.release(pending))
    }
}

/// Everything E4 and E5 reuse from E1 and E2.
struct EnrollmentRun<'a> {
    context: &'a EnrollmentContext,
    created: CreatedCredential,
    stored: StoredGet,
    budget: Budget,
}

/// What `draw_plan` needs to know about the ceremony it plans.
struct PlanRequest {
    kind: CeremonyKind,
    stored: Option<StoredGet>,
    prf_input: Option<PrfInput>,
    budget: Option<Budget>,
    owner_window: Option<u64>,
}

fn require_unbound<P: EnrollmentPort>(
    port: &mut P,
    registration: &Registration,
) -> Result<(), BridgeError> {
    let unbound = port
        .credential_unbound(&registration.credential_id)
        .map_err(BridgeError::Owner)?;
    if unbound {
        Ok(())
    } else {
        Err(BridgeError::Rejected(RejectedCode::CredentialAlreadyBound))
    }
}
