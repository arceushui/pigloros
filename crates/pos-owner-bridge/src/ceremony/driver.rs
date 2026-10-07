//! The ceremony state machine (ADR-110 §6): one non-blocking `step` per timer tick or event.

use std::time::Instant;

use pos_owner_bridge_codec::{
    encode_cleanup_record, encode_create_options, encode_get_options, CeremonyKind,
    CleanupRecordV1, ControlState, CreateOptionsV1, GetOptionsV1, OwnerBridgeControlV1,
    CONTROL_HEADER_BYTES, MAX_CLEANUP_RECORD_BYTES,
};

use super::consume::{check_reply_header, parse_and_verify, protocol_from_codec, snapshot};
use super::plan::{CeremonyPlan, Slots, Verified};
use super::release::{reachable, read_state, release_loop, ReleaseMode};
use super::timing::{
    expired, poll_interval, receipt_window, CHALLENGE_TTL, EXIT_WINDOW, INTERACTION, MAX_POSTS,
    PUMP_INTERVAL, READINESS, RELEASE_WINDOW,
};
use crate::{
    folder_name, BridgeError, CleanupStore, LifecycleCode, LoopbackPort, MonotonicClock,
    NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity, ProtocolCode, QuarantineCode,
    ServedSnapshot, SurfaceError, SurfaceEvent, SurfaceSpec, UnavailableCode,
};

const HEADER: usize = CONTROL_HEADER_BYTES;
const UNEXPECTED_STATE: BridgeError = BridgeError::Protocol(ProtocolCode::UnexpectedState);
const COPY_MISMATCH: BridgeError = BridgeError::Protocol(ProtocolCode::CopyMismatch);
const CLEANUP_STORE_FAILED: BridgeError =
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

const fn lifecycle(code: LifecycleCode) -> BridgeError {
    BridgeError::Lifecycle(code)
}

/// The next host generation after `current`.
///
/// # Errors
///
/// Returns `Unavailable(GenerationExhausted)` when the next value would reach `u32::MAX`.
pub const fn next_generation(current: u32) -> Result<u32, BridgeError> {
    match current.checked_add(1) {
        Some(next) if next < u32::MAX => Ok(next),
        _ => Err(BridgeError::Unavailable(
            UnavailableCode::GenerationExhausted,
        )),
    }
}

/// The served-count rule: exactly one verified completion for the current navigation.
///
/// # Errors
///
/// Returns `Unavailable(AssetIntegrity)` for a digest mismatch or no completion, and
/// `Protocol(DuplicateDocumentLoad)` for a second completion.
pub const fn check_served(served: ServedSnapshot) -> Result<(), BridgeError> {
    if !served.integrity_ok || served.count == 0 {
        Err(BridgeError::Unavailable(UnavailableCode::AssetIntegrity))
    } else if served.count > 1 {
        Err(BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad))
    } else {
        Ok(())
    }
}

/// The collaborators one `step` may use.
pub struct StepEnv<'a> {
    /// The platform surface.
    pub surface: &'a mut dyn OwnerWebSurface,
    /// The monotonic clock.
    pub clock: &'a dyn MonotonicClock,
    /// The loopback listener view.
    pub loopback: &'a mut dyn LoopbackPort,
    /// The cleanup-record store.
    pub store: &'a mut dyn CleanupStore,
}

/// The result of one `step`.
#[derive(Debug)]
pub enum Step {
    /// The ceremony continues; step again on the next tick or event.
    Pending,
    /// The ceremony ended (`Completed(ok|err)`) or entered quarantine.
    Finished(Result<Verified, BridgeError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Opening,
    AwaitingLoad,
    Posted,
    Releasing { since: Instant, state_live: bool },
    AwaitingExit { since: Instant },
    Quarantined,
    Done,
}

/// One ceremony from `Idle` to `Completed` or `Quarantined`.
pub struct CeremonyDriver {
    plan: CeremonyPlan,
    slots: Box<Slots>,
    phase: Phase,
    generation: u32,
    reply_header: [u8; HEADER],
    identity: Option<ProcessIdentity>,
    record: Vec<u8>,
    navigation: Option<NavigationId>,
    loaded: Option<NavigationId>,
    posts: u8,
    post_returned_at: Instant,
    first_past_empty: Option<Instant>,
    last_poll: Option<Instant>,
    known: ControlState,
    buffers_live: bool,
    exit_seen: bool,
    surface_finished: bool,
    error: Option<BridgeError>,
    verified: Option<Verified>,
}

impl CeremonyDriver {
    /// Start a ceremony from `plan`, using the preallocated `slots`.
    #[must_use]
    pub const fn new(plan: CeremonyPlan, slots: Box<Slots>) -> Self {
        let (generation, t0) = (plan.generation, plan.t0);
        Self {
            plan,
            slots,
            phase: Phase::Opening,
            generation,
            reply_header: [0; HEADER],
            identity: None,
            record: Vec::new(),
            navigation: None,
            loaded: None,
            posts: 0,
            post_returned_at: t0,
            first_past_empty: None,
            last_poll: None,
            known: ControlState::Empty,
            buffers_live: false,
            exit_seen: false,
            surface_finished: false,
            error: None,
            verified: None,
        }
    }

    /// The current host generation.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// The number of pairs posted so far.
    #[must_use]
    pub const fn posts(&self) -> u8 {
        self.posts
    }

    /// Return the preallocated slots once the ceremony is over.
    #[must_use]
    pub fn into_slots(self) -> Box<Slots> {
        self.slots
    }

    /// The PRF result of the latest verified ceremony.
    #[must_use]
    pub fn slots(&self) -> &Slots {
        &self.slots
    }

    /// Advance the ceremony. Never blocks beyond the surface calls it makes.
    pub fn step(&mut self, env: &mut StepEnv<'_>) -> Step {
        let now = env.clock.now();
        if let Some(error) = self.drain_events(env.surface) {
            let error = self.bump_generation().err().unwrap_or(error);
            return self.fail(env, now, error);
        }
        match self.phase {
            Phase::Opening => self.open(env, now),
            Phase::AwaitingLoad => self.await_load(env, now),
            Phase::Posted => self.posted(env, now),
            Phase::Releasing { since, state_live } => self.releasing(env, now, since, state_live),
            Phase::AwaitingExit { since } => self.awaiting_exit(env, now, since),
            Phase::Quarantined | Phase::Done => Step::Pending,
        }
    }

    /// The next instant at which the ceremony itself needs attention, if any.
    ///
    /// A pump may sleep until then; surface events still need polling at the pump interval.
    #[must_use]
    pub fn next_wake(&self) -> Option<Instant> {
        let budget = self.plan.budget.map(|budget| budget.start + budget.limit);
        let phase = match self.phase {
            Phase::Opening | Phase::AwaitingLoad => self.readiness_wake(),
            Phase::Posted => self.posted_wake(),
            Phase::Releasing { since, .. } => Some(since + RELEASE_WINDOW),
            Phase::AwaitingExit { since } => Some(since + EXIT_WINDOW),
            Phase::Quarantined | Phase::Done => None,
        };
        [phase, budget].into_iter().flatten().min()
    }

    fn readiness_wake(&self) -> Option<Instant> {
        self.first_past_empty
            .is_none()
            .then(|| self.plan.t0 + READINESS)
    }

    fn posted_wake(&self) -> Option<Instant> {
        match self.known {
            ControlState::Empty => {
                let window = self.post_returned_at + receipt_window(self.posts);
                Some(
                    self.readiness_wake()
                        .map_or(window, |readiness| readiness.min(window)),
                )
            }
            ControlState::Received | ControlState::Writing => {
                self.first_past_empty.map(|first| first + INTERACTION)
            }
            _ => Some(self.post_returned_at),
        }
    }

    const fn pre_release(&self) -> bool {
        matches!(
            self.phase,
            Phase::Opening | Phase::AwaitingLoad | Phase::Posted
        )
    }

    fn drain_events(&mut self, surface: &mut dyn OwnerWebSurface) -> Option<BridgeError> {
        let mut failure = None;
        while let Some(event) = surface.take_event() {
            if let Some(error) = self.apply_event(event) {
                failure.get_or_insert(error);
            }
        }
        failure
    }

    fn apply_event(&mut self, event: SurfaceEvent) -> Option<BridgeError> {
        match event {
            SurfaceEvent::BrowserExited { browser_pid } => self.apply_exit(browser_pid),
            _ if !self.pre_release() => None,
            SurfaceEvent::DomContentLoaded(id) => self.apply_loaded(id),
            SurfaceEvent::NavigationViolation => {
                Some(lifecycle(LifecycleCode::NavigationViolation))
            }
            SurfaceEvent::FrameCreated => Some(lifecycle(LifecycleCode::FrameCreated)),
            SurfaceEvent::RendererFailed => Some(lifecycle(LifecycleCode::RendererFailed)),
            SurfaceEvent::ControllerLost => Some(lifecycle(LifecycleCode::ControllerLost)),
        }
    }

    fn apply_exit(&mut self, browser_pid: u32) -> Option<BridgeError> {
        let ours = self
            .identity
            .is_some_and(|identity| identity.browser_pid == browser_pid);
        if ours {
            self.exit_seen = true;
        }
        (ours && self.pre_release()).then_some(lifecycle(LifecycleCode::RendererFailed))
    }

    fn apply_loaded(&mut self, id: NavigationId) -> Option<BridgeError> {
        if self.phase == Phase::AwaitingLoad && self.loaded.is_none() {
            self.loaded = Some(id);
            None
        } else {
            Some(lifecycle(LifecycleCode::NavigationViolation))
        }
    }

    fn bump_generation(&mut self) -> Result<(), BridgeError> {
        self.generation = next_generation(self.generation)?;
        Ok(())
    }

    fn budget_failure(&self, now: Instant) -> Option<BridgeError> {
        let over = self
            .plan
            .budget
            .is_some_and(|budget| expired(now, budget.start, budget.limit));
        over.then_some(lifecycle(LifecycleCode::EnrollmentBudgetExceeded))
    }

    fn readiness_failure(&self, now: Instant) -> Option<BridgeError> {
        let over = self.first_past_empty.is_none() && expired(now, self.plan.t0, READINESS);
        over.then_some(lifecycle(LifecycleCode::ReadinessTimeout))
    }

    fn pre_post_failure(&self, now: Instant) -> Option<BridgeError> {
        if let Some(error) = self.budget_failure(now) {
            return Some(error);
        }
        self.readiness_failure(now)
    }

    fn cleanup_record(&self, identity: &ProcessIdentity, name: &str) -> Vec<u8> {
        let mut buffer = [0_u8; MAX_CLEANUP_RECORD_BYTES];
        let length = CleanupRecordV1::new(
            self.plan.ceremony_id,
            name,
            identity.browser_pid,
            identity.creation_filetime,
            identity.image_path_sha256,
        )
        .and_then(|record| encode_cleanup_record(&record, &mut buffer))
        .unwrap_or(0);
        buffer.get(..length).unwrap_or_default().to_vec()
    }

    fn open(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        if let Some(error) = self.pre_post_failure(now) {
            return self.fail(env, now, error);
        }
        let spec = SurfaceSpec {
            ceremony_id: self.plan.ceremony_id,
            folder_name: folder_name(&self.plan.ceremony_id),
            owner_window: self.plan.owner_window,
        };
        let identity = match env.surface.open(&spec) {
            Ok(identity) => identity,
            Err(error) => return self.fail(env, now, error.error()),
        };
        self.identity = Some(identity);
        self.record = self.cleanup_record(&identity, &spec.folder_name);
        if env.store.write_record(&self.record).is_err() {
            return self.fail(env, now, CLEANUP_STORE_FAILED);
        }
        if let Err(error) = env.loopback.probe_ipv6() {
            return self.fail(env, now, error);
        }
        env.loopback.begin_navigation();
        match env.surface.navigate() {
            Ok(navigation) => {
                self.navigation = Some(navigation);
                self.phase = Phase::AwaitingLoad;
                Step::Pending
            }
            Err(error) => self.fail(env, now, error.error()),
        }
    }

    fn await_load(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        if let Some(error) = self.pre_post_failure(now) {
            return self.fail(env, now, error);
        }
        let Some(loaded) = self.loaded else {
            return Step::Pending;
        };
        if self.navigation != Some(loaded) {
            let violation = BridgeError::Lifecycle(LifecycleCode::NavigationViolation);
            let error = self.bump_generation().err().unwrap_or(violation);
            return self.fail(env, now, error);
        }
        if let Err(error) = env.loopback.probe_ipv6() {
            return self.fail(env, now, error);
        }
        self.post_pair(env, now)
    }

    fn write_request(&mut self) -> Result<[u8; HEADER], BridgeError> {
        let plan = &self.plan;
        let image = self.slots.request.as_mut_bytes();
        image.fill(0);
        let (head, payload) = image.split_at_mut(HEADER);
        let credential_id = plan
            .stored
            .as_ref()
            .map(|stored| stored.credential_id.as_slice())
            .unwrap_or_default();
        let length = match plan.kind {
            CeremonyKind::Create => {
                let options = CreateOptionsV1::new(
                    plan.ceremony_id,
                    plan.challenge,
                    plan.user_handle,
                    plan.prf_input,
                );
                encode_create_options(&options, payload)
            }
            CeremonyKind::Get => GetOptionsV1::new(
                plan.ceremony_id,
                plan.challenge,
                credential_id,
                plan.prf_input,
            )
            .and_then(|options| encode_get_options(&options, payload)),
        }
        .unwrap_or(0);
        let request = OwnerBridgeControlV1::new_request(
            plan.kind,
            self.generation,
            plan.ceremony_id,
            u32::try_from(length).unwrap_or(0),
        )
        .map_err(protocol_from_codec)?;
        head.copy_from_slice(&request.encode());
        let reply = OwnerBridgeControlV1::new_reply(plan.kind, self.generation, plan.ceremony_id);
        Ok(reply.map_or([0; HEADER], OwnerBridgeControlV1::encode))
    }

    fn post_pair(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        let served = env.loopback.served();
        if let Err(error) = check_served(served) {
            return self.fail(env, now, error);
        }
        let reply_header = match self.write_request() {
            Ok(header) => header,
            Err(error) => return self.fail(env, now, error),
        };
        if let Err(error) = env
            .surface
            .create_and_write(&self.slots.request, &reply_header)
        {
            return self.fail(env, now, error.error());
        }
        self.buffers_live = true;
        self.reply_header = reply_header;
        self.known = ControlState::Empty;
        let guard = PostGuard {
            generation: self.generation,
            navigation_id: self.navigation.unwrap_or(NavigationId(0)),
            served_count: served.count,
        };
        if let Err(error) = env.surface.post(&guard) {
            return self.fail(env, now, error.error());
        }
        self.posts += 1;
        self.post_returned_at = env.clock.now();
        self.last_poll = None;
        self.phase = Phase::Posted;
        Step::Pending
    }

    fn posted(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        if let Some(error) = self.budget_failure(now) {
            return self.fail(env, now, error);
        }
        if let Err(error) = self.poll(env, now) {
            return self.fail_unexpected(error, now);
        }
        match self.known {
            ControlState::Ready => self.consume(env, now),
            ControlState::Failed => self.fail(env, now, lifecycle(LifecycleCode::ClientFailed)),
            ControlState::Empty => self.await_receipt(env, now),
            _ => self.await_reply(env, now),
        }
    }

    fn poll(&mut self, env: &StepEnv<'_>, now: Instant) -> Result<(), BridgeError> {
        let since = self
            .first_past_empty
            .map(|first| now.saturating_duration_since(first));
        let due = self
            .last_poll
            .is_none_or(|last| expired(now, last, poll_interval(since)));
        if !due {
            return Ok(());
        }
        self.last_poll = Some(now);
        let observed = read_state(env.surface)?;
        if observed == self.known {
            return Ok(());
        }
        if !reachable(self.known, observed) {
            return Err(UNEXPECTED_STATE);
        }
        self.observe_advance(observed, now);
        Ok(())
    }

    fn observe_advance(&mut self, observed: ControlState, now: Instant) {
        if self.known == ControlState::Empty {
            self.first_past_empty = Some(now);
        }
        self.known = observed;
    }

    fn await_receipt(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        if expired(now, self.plan.t0, READINESS) {
            return self.timing_failure(env, now);
        }
        if !expired(now, self.post_returned_at, receipt_window(self.posts)) {
            return Step::Pending;
        }
        if self.posts >= MAX_POSTS {
            return self.timing_failure(env, now);
        }
        self.retire_and_repost(env, now)
    }

    fn await_reply(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        let over = self
            .first_past_empty
            .is_some_and(|first| expired(now, first, INTERACTION));
        if over {
            return self.fail(env, now, lifecycle(LifecycleCode::InteractionTimeout));
        }
        Step::Pending
    }

    fn timing_failure(&mut self, env: &StepEnv<'_>, now: Instant) -> Step {
        match release_loop(env.surface, ControlState::Empty, ReleaseMode::Timing) {
            Ok(None) => {
                self.error
                    .get_or_insert(lifecycle(LifecycleCode::ReadinessTimeout));
                self.slots.wipe_ceremony();
                self.phase = Phase::Releasing {
                    since: env.clock.now(),
                    state_live: true,
                };
                Step::Pending
            }
            Ok(Some(advanced)) => self.void_timing_failure(advanced, now),
            Err(error) => self.fail_unexpected(error, now),
        }
    }

    fn void_timing_failure(&mut self, advanced: ControlState, now: Instant) -> Step {
        self.observe_advance(advanced, now);
        Step::Pending
    }

    fn retire_and_repost(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        match release_loop(env.surface, ControlState::Empty, ReleaseMode::Timing) {
            Ok(Some(advanced)) => return self.void_timing_failure(advanced, now),
            Err(error) => return self.fail_unexpected(error, now),
            Ok(None) => {}
        }
        let zeroed = env.surface.zero_close_buffers();
        self.buffers_live = false;
        if zeroed.is_err() {
            return self.finish_close(env, zeroed);
        }
        if let Err(error) = self.bump_generation() {
            return self.fail(env, now, error);
        }
        self.post_pair(env, now)
    }

    fn consume(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        if expired(now, self.plan.t0, CHALLENGE_TTL) {
            return self.fail(env, now, lifecycle(LifecycleCode::ChallengeExpired));
        }
        let won = env
            .surface
            .reply_compare_exchange(ControlState::Ready as u32, ControlState::Consuming as u32);
        match won {
            Ok(true) => self.known = ControlState::Consuming,
            Ok(false) | Err(_) => return self.fail_unexpected(UNEXPECTED_STATE, now),
        }
        match self.verify_reply(env) {
            Ok(verified) => self.finish_success(env, now, verified),
            Err(error) => self.fail(env, now, error),
        }
    }

    fn verify_reply(&mut self, env: &StepEnv<'_>) -> Result<Verified, BridgeError> {
        let slots = &mut *self.slots;
        slots.copy_a.select(self.plan.kind);
        slots.copy_b.select(self.plan.kind);
        snapshot(env.surface, &mut slots.copy_a)?;
        snapshot(env.surface, &mut slots.copy_b)?;
        if slots.copy_a.as_bytes() != slots.copy_b.as_bytes() {
            return Err(COPY_MISMATCH);
        }
        slots.copy_b.wipe();
        let length = check_reply_header(&self.reply_header, slots.copy_a.as_bytes())?;
        let payload = slots
            .copy_a
            .as_bytes()
            .get(HEADER..HEADER + length)
            .unwrap_or_default();
        let verified = parse_and_verify(&self.plan, payload, &mut slots.prf)?;
        if expired(env.clock.now(), self.plan.t0, CHALLENGE_TTL) {
            return Err(lifecycle(LifecycleCode::ChallengeExpired));
        }
        slots.copy_a.wipe();
        Ok(verified)
    }

    fn finish_success(&mut self, env: &StepEnv<'_>, now: Instant, verified: Verified) -> Step {
        match release_loop(env.surface, ControlState::Consuming, ReleaseMode::Terminal) {
            Ok(_) => {
                self.verified = Some(verified);
                self.slots.wipe_copies();
                self.phase = Phase::Releasing {
                    since: env.clock.now(),
                    state_live: true,
                };
                Step::Pending
            }
            Err(error) => self.fail_unexpected(error, now),
        }
    }

    fn fail(&mut self, env: &mut StepEnv<'_>, now: Instant, error: BridgeError) -> Step {
        self.error.get_or_insert(error);
        self.verified = None;
        self.slots.wipe_ceremony();
        if self.identity.is_none() {
            self.phase = Phase::Done;
            return Step::Finished(Err(error));
        }
        if !self.buffers_live {
            return self.close_environment(env);
        }
        match release_loop(env.surface, self.known, ReleaseMode::Terminal) {
            Ok(_) => {
                self.phase = Phase::Releasing {
                    since: env.clock.now(),
                    state_live: true,
                };
                Step::Pending
            }
            Err(unexpected) => self.fail_unexpected(unexpected, now),
        }
    }

    fn fail_unexpected(&mut self, error: BridgeError, now: Instant) -> Step {
        self.error = Some(error);
        self.verified = None;
        self.slots.wipe_ceremony();
        self.phase = Phase::Releasing {
            since: now,
            state_live: false,
        };
        Step::Pending
    }

    fn releasing(
        &mut self,
        env: &mut StepEnv<'_>,
        now: Instant,
        since: Instant,
        state_live: bool,
    ) -> Step {
        let released = state_live && read_state(env.surface) == Ok(ControlState::Releasing);
        if released || expired(now, since, RELEASE_WINDOW) {
            self.close_environment(env)
        } else {
            Step::Pending
        }
    }

    fn close_environment(&mut self, env: &mut StepEnv<'_>) -> Step {
        let zeroed = if self.buffers_live {
            env.surface.zero_close_buffers()
        } else {
            Ok(())
        };
        self.buffers_live = false;
        self.finish_close(env, zeroed)
    }

    fn finish_close(&mut self, env: &mut StepEnv<'_>, zeroed: Result<(), SurfaceError>) -> Step {
        let closed = env.surface.close_controller();
        if zeroed.is_err() || closed.is_err() {
            return self.quarantine(QuarantineCode::ControllerCloseFailed);
        }
        self.phase = Phase::AwaitingExit {
            since: env.clock.now(),
        };
        Step::Pending
    }

    fn awaiting_exit(&mut self, env: &mut StepEnv<'_>, now: Instant, since: Instant) -> Step {
        if self.exit_seen {
            return self.complete(env);
        }
        if expired(now, since, EXIT_WINDOW) {
            return self.quarantine(QuarantineCode::CleanupTimeout);
        }
        Step::Pending
    }

    fn cleanup(&mut self, env: &mut StepEnv<'_>) -> bool {
        if !self.surface_finished {
            self.surface_finished = env.surface.finish().is_ok();
        }
        self.surface_finished && env.store.delete_record(&self.record).is_ok()
    }

    fn complete(&mut self, env: &mut StepEnv<'_>) -> Step {
        if !self.cleanup(env) {
            return self.quarantine(QuarantineCode::CleanupTimeout);
        }
        self.phase = Phase::Done;
        let outcome = self
            .error
            .map_or_else(|| self.verified.take().ok_or(UNEXPECTED_STATE), Err);
        Step::Finished(outcome)
    }

    fn quarantine(&mut self, code: QuarantineCode) -> Step {
        let error = BridgeError::Quarantine(code);
        self.error = Some(error);
        self.verified = None;
        self.slots.wipe_ceremony();
        self.phase = Phase::Quarantined;
        Step::Finished(Err(error))
    }

    /// Poll a quarantined ceremony for its browser exit. Returns `true` once cleanup finished.
    pub fn poll_cleanup(&mut self, env: &mut StepEnv<'_>) -> bool {
        self.drain_events(env.surface);
        if self.phase != Phase::Quarantined || !self.exit_seen || !self.cleanup(env) {
            return false;
        }
        self.phase = Phase::Done;
        true
    }
}

/// The most steps `drive` takes before giving up on a ceremony that never finishes.
///
/// A legitimate ceremony ends in far fewer: its worst case is about 14,000 pump intervals.
pub const MAX_STEPS: u32 = 50_000;

/// Pump `driver` until it finishes: step, then pause one pump interval or until its next wake.
///
/// A driver that is still pending after [`MAX_STEPS`] steps fails closed with
/// `Protocol(UnexpectedState)`.
///
/// # Errors
///
/// Returns the ceremony's failure once it finishes.
pub fn drive(driver: &mut CeremonyDriver, env: &mut StepEnv<'_>) -> Result<Verified, BridgeError> {
    (0..MAX_STEPS)
        .find_map(|_| match driver.step(env) {
            Step::Finished(result) => Some(result),
            Step::Pending => {
                env.clock.pause_for(PUMP_INTERVAL, driver.next_wake());
                None
            }
        })
        .unwrap_or(Err(UNEXPECTED_STATE))
}
