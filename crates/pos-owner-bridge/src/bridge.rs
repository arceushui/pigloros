//! `OwnerBridge` (ADR-110 §10): enroll with D2 confirmation, unlock, status and quarantine.

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, OwnerUserHandle, PrfInput, SubjectCredentialBindingV1,
    WebAuthnChallenge,
};
use zeroize::Zeroizing;

use crate::ceremony::driver::{drive, CeremonyDriver, StepEnv};
use crate::ceremony::plan::{
    Assertion, Budget, CeremonyPlan, Registration, Slots, StoredGet, Verified,
};
use crate::ceremony::timing::ENROLLMENT_BUDGET;
use crate::restart::restart_check;
use crate::{
    BindingUpdate, BridgeError, BridgeStatus, ConfirmedBinding, EnrollmentContext, EnrollmentPort,
    HostPorts, MonotonicClock, OwnerWebSurface, PrfOutput, ProcessProbe, RejectedCode,
    RootFingerprint, SecureRandom, UnavailableCode, UnlockPort,
};

/// Bridge construction options.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeConfig {
    /// The per-process generation the first ceremony starts at; `0` means `1`.
    pub start_generation: u32,
    /// The owning application window handle, used by unlock ceremonies.
    pub owner_window: Option<u64>,
}

/// The owner bridge: composes the surface, randomness, clock and host ports into ceremonies.
pub struct OwnerBridge<S: OwnerWebSurface, R: SecureRandom, C: MonotonicClock> {
    surface: S,
    random: R,
    clock: C,
    host: HostPorts,
    generation: u32,
    owner_window: Option<u64>,
    status: BridgeStatus,
    slots: Option<Box<Slots>>,
    quarantined: Option<CeremonyDriver>,
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

fn split_array<const N: usize>(bytes: &[u8]) -> ([u8; N], &[u8]) {
    bytes
        .split_first_chunk::<N>()
        .map_or(([0; N], &[][..]), |(head, rest)| (*head, rest))
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

impl<S: OwnerWebSurface, R: SecureRandom, C: MonotonicClock> OwnerBridge<S, R, C> {
    /// Allocate the bridge and its preallocated ceremony buffers.
    #[must_use]
    pub fn new(surface: S, random: R, clock: C, host: HostPorts, config: BridgeConfig) -> Self {
        Self {
            surface,
            random,
            clock,
            host,
            generation: config.start_generation.max(1),
            owner_window: config.owner_window,
            status: BridgeStatus::Ready,
            slots: Some(Slots::allocate()),
            quarantined: None,
        }
    }

    /// The current status.
    #[must_use]
    pub const fn status(&self) -> BridgeStatus {
        self.status
    }

    /// Poll a quarantined ceremony for its browser exit; cleanup completing clears the status.
    pub fn poll_quarantine(&mut self) -> BridgeStatus {
        if let Some(mut driver) = self.quarantined.take() {
            let mut env = StepEnv {
                surface: &mut self.surface,
                clock: &self.clock,
                loopback: &mut *self.host.loopback,
                store: &mut *self.host.store,
            };
            if driver.poll_cleanup(&mut env) {
                self.slots = Some(driver.into_slots());
                self.status = BridgeStatus::Ready;
            } else {
                self.quarantined = Some(driver);
            }
        }
        self.status
    }

    /// Probe stale cleanup records at process start (ADR-110 §16).
    ///
    /// # Errors
    ///
    /// Returns `Quarantine(StaleProcessPresent)` when a recorded browser process is still
    /// present, or `Unavailable(InterfaceUnavailable)` when the store cannot be read.
    pub fn restart_check(&mut self, probe: &mut dyn ProcessProbe) -> Result<(), BridgeError> {
        let outcome = restart_check(&mut *self.host.store, probe, &self.clock);
        self.status = BridgeStatus::after(outcome.err());
        outcome
    }

    fn begin(&mut self) -> Result<(), BridgeError> {
        self.status.admission()?;
        self.status = BridgeStatus::Busy;
        Ok(())
    }

    fn end<T>(&mut self, result: &Result<T, BridgeError>) {
        self.status = BridgeStatus::after(result.as_ref().err().copied());
    }

    fn with_slots<T>(&mut self, operation: impl FnOnce(&mut Slots) -> T) -> T {
        let mut slots = self.slots.take().unwrap_or_else(Slots::allocate);
        let outcome = operation(&mut slots);
        self.slots = Some(slots);
        outcome
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
            ceremony_id: CeremonyId::from_bytes(id),
            challenge: WebAuthnChallenge::from_bytes(challenge),
            user_handle: OwnerUserHandle::from_bytes(user_handle),
            prf_input: request
                .prf_input
                .unwrap_or_else(|| PrfInput::from_bytes(fresh_prf)),
            stored: request.stored,
            t0,
            generation: self.generation,
            owner_window: request.owner_window,
            budget: request.budget,
        })
    }

    fn run_ceremony(&mut self, plan: CeremonyPlan) -> Result<Verified, BridgeError> {
        let slots = self.slots.take().unwrap_or_else(Slots::allocate);
        let mut driver = CeremonyDriver::new(plan, slots);
        let mut env = StepEnv {
            surface: &mut self.surface,
            clock: &self.clock,
            loopback: &mut *self.host.loopback,
            store: &mut *self.host.store,
        };
        let result = drive(&mut driver, &mut env);
        self.generation = driver.generation();
        self.conclude(driver, result)
    }

    fn conclude(
        &mut self,
        driver: CeremonyDriver,
        result: Result<Verified, BridgeError>,
    ) -> Result<Verified, BridgeError> {
        if matches!(result, Err(BridgeError::Quarantine(_))) {
            self.quarantined = Some(driver);
        } else {
            self.slots = Some(driver.into_slots());
        }
        result
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
        let (user_handle, prf_input) = (plan.user_handle, plan.prf_input);
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

    /// Run enrollment E1 to E5 (ADR-110 §8). Every failure calls `abandon` exactly once.
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
            port.abandon(failure.candidate);
            failure.error
        });
        self.with_slots(Slots::wipe_all);
        self.end(&outcome);
        outcome
    }

    fn enroll_steps<P: EnrollmentPort>(
        &mut self,
        context: &EnrollmentContext,
        port: &mut P,
    ) -> Result<(), EnrollFailure<P::Candidate>> {
        let created = self.create_ceremony(context)?;
        let budget = Budget {
            start: self.clock.now(),
            limit: ENROLLMENT_BUDGET,
        };
        require_unbound(port, &created.registration)?;
        let stored = self.source_prf(&created, budget)?;
        let (candidate, sealed) = self
            .with_slots(|slots| {
                let sealed = port.seal_candidate(PrfOutput::new(&slots.create_prf), context);
                slots.create_prf.fill(0);
                sealed
            })
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
        });
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
            })
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
        self.with_slots(Slots::wipe_all);
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
            })
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
