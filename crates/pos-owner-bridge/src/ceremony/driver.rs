//! The ceremony state machine (ADR-110 §6): one non-blocking `step` per timer tick or event.
//!
//! The driver never sleeps and never loops waiting. It is an owned, `Send` value: the bridge builds
//! it on the owner thread and hands it to the host, whose surface thread owns it, calls `step`
//! from its `WM_TIMER` and `WebView2` callbacks, and sleeps until `next_wake` (ADR-110 §1a, §6;
//! see `CeremonyHost`). Secrets cross threads only inside its preallocated `Box<Slots>`. Every
//! phase has a timer, so a driver that is stepped on a monotonic clock always finishes:
//!
//! | Phase                     | Ends by                                                        |
//! | ------------------------- | -------------------------------------------------------------- |
//! | opening, awaiting load    | the page load, or `READINESS` from T0 (`ReadinessTimeout`)     |
//! | posted, awaiting receipt  | a state past `EMPTY`, or the readiness bound / eight posts     |
//! | posted, past `EMPTY`      | `READY` or `FAILED`, or `INTERACTION` after the first advance  |
//! | releasing                 | `RELEASING` observed, or `RELEASE_WINDOW`                      |
//! | awaiting exit             | the browser exit, or `EXIT_WINDOW` (`CleanupTimeout`)          |
//!
//! The 300 s enrollment budget is enforced while a ceremony is opening, loading or posted; it
//! ends at E4 verification, so it is not checked while the driver releases and waits for exit,
//! and `next_wake` ignores it from then on.

use std::time::Instant;

use pos_owner_bridge_codec::{
    encode_create_options, encode_get_options, CeremonyKind, ControlState, CreateOptionsV1,
    GetOptionsV1, OwnerBridgeControlV1, CONTROL_HEADER_BYTES,
};

use super::consume::{check_reply_header, parse_and_verify, snapshot};
use super::plan::{CeremonyPlan, Slots, Verified};
use super::protocol_from_codec;
use super::release::{reachable, read_state, release_loop, ReleaseMode};
use super::timing::{
    expired, poll_interval, receipt_window, CHALLENGE_TTL, EXIT_WINDOW, INTERACTION, MAX_POSTS,
    READINESS, RELEASE_WINDOW, SERVED_SETTLE,
};
use crate::{
    cleanup_record_bytes, folder_name, BridgeError, CleanupStore, LifecycleCode, LoopbackPort,
    MonotonicClock, NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity, ProtocolCode,
    QuarantineCode, ServedSnapshot, SurfaceError, SurfaceEvent, SurfaceSpec, UnavailableCode,
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
const fn next_generation(current: u32) -> Result<u32, BridgeError> {
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
const fn check_served(served: ServedSnapshot) -> Result<(), BridgeError> {
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
    /// The ceremony had already finished: there is nothing left to step, so a host that loops until
    /// `Finished` must also stop on `Done`.
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Opening,
    AwaitingLoad { navigation: NavigationId },
    Posted { navigation: NavigationId },
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
    record: Option<Vec<u8>>,
    loaded: Option<NavigationId>,
    posts: u8,
    post_returned_at: Instant,
    first_past_empty: Option<Instant>,
    last_poll: Option<Instant>,
    served_since: Option<Instant>,
    known: ControlState,
    buffers_live: bool,
    exit_seen: bool,
    surface_finished: bool,
    outcome: Result<Verified, BridgeError>,
}

impl CeremonyDriver {
    /// Start a ceremony from `plan`, using the preallocated `slots`.
    #[must_use]
    pub(crate) const fn new(plan: CeremonyPlan, slots: Box<Slots>) -> Self {
        let (generation, t0) = (plan.generation, plan.t0);
        Self {
            plan,
            slots,
            phase: Phase::Opening,
            generation,
            reply_header: [0; HEADER],
            identity: None,
            record: None,
            loaded: None,
            posts: 0,
            post_returned_at: t0,
            first_past_empty: None,
            last_poll: None,
            served_since: None,
            known: ControlState::Empty,
            buffers_live: false,
            exit_seen: false,
            surface_finished: false,
            outcome: Err(UNEXPECTED_STATE),
        }
    }

    /// The current host generation.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// The number of pairs posted so far.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn posts(&self) -> u8 {
        self.posts
    }

    /// Whether the request image is all zero.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn request_clear(&self) -> bool {
        self.slots.request.as_bytes().iter().all(|byte| *byte == 0)
    }

    /// Whether the plan's challenge, user handle and PRF input are all zero.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn plan_secrets_clear(&self) -> bool {
        self.plan.secrets_clear()
    }

    /// The ceremony's T0.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn t0(&self) -> Instant {
        self.plan.t0
    }

    /// Start a ceremony from `plan` with freshly allocated slots.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test(plan: CeremonyPlan) -> Self {
        Self::new(plan, Slots::allocate())
    }

    /// Return the preallocated slots once the ceremony is over.
    #[must_use]
    pub fn into_slots(self) -> Box<Slots> {
        self.slots
    }

    /// The PRF result of the latest verified ceremony.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn prf(&self) -> &[u8; 32] {
        &self.slots.prf
    }

    /// Advance the ceremony. Never blocks beyond the surface calls it makes.
    ///
    /// A host calls this from its timer and from each surface event until it returns
    /// `Finished`; after that it returns `Done`, which a host that loops must also stop on. A
    /// host that finished a ceremony in quarantine keeps the driver (see `QuarantineKeeper`) and
    /// calls `poll_cleanup` until the browser exit and `finish()` are done.
    pub fn step(&mut self, env: &mut StepEnv<'_>) -> Step {
        let now = env.clock.now();
        self.watch_served(env);
        if let Some(error) = self.drain_events(env.surface) {
            let error = self.bump_generation().err().unwrap_or(error);
            return self.fail(env, now, error);
        }
        match self.phase {
            Phase::Opening => self.open(env, now),
            Phase::AwaitingLoad { navigation } => self.await_load(env, now, navigation),
            Phase::Posted { navigation } => self.posted(env, now, navigation),
            Phase::Releasing { since, state_live } => self.releasing(env, now, since, state_live),
            Phase::AwaitingExit { since } => self.awaiting_exit(env, now, since),
            Phase::Quarantined | Phase::Done => Step::Done,
        }
    }

    /// After the reply was consumed, a second document completion in this generation still fails
    /// the ceremony (ADR-110 §4): the verified result is discarded, so no port method follows, and
    /// the release and exit phases carry on with their timers.
    fn watch_served(&mut self, env: &StepEnv<'_>) {
        let consumed = matches!(
            self.phase,
            Phase::Releasing { .. } | Phase::AwaitingExit { .. }
        );
        if consumed && self.outcome.is_ok() && env.loopback.served().count > 1 {
            self.outcome = Err(BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad));
            self.slots.wipe_ceremony();
        }
    }

    /// The next instant at which the ceremony itself needs attention, if any.
    ///
    /// A host may sleep until then; surface events still need polling at the timer interval.
    #[must_use]
    pub fn next_wake(&self) -> Option<Instant> {
        let phase = match self.phase {
            Phase::Opening | Phase::AwaitingLoad { .. } => self.load_wake(),
            Phase::Posted { .. } => self.posted_wake(),
            Phase::Releasing { since, .. } => Some(since + RELEASE_WINDOW),
            Phase::AwaitingExit { since } => Some(since + EXIT_WINDOW),
            Phase::Quarantined | Phase::Done => None,
        };
        let budget = self
            .plan
            .budget
            .filter(|_| self.pre_release())
            .map(|budget| budget.start() + budget.limit());
        [phase, budget].into_iter().flatten().min()
    }

    fn load_wake(&self) -> Option<Instant> {
        let served = self.served_since.map(|since| since + SERVED_SETTLE);
        [self.readiness_wake(), served].into_iter().flatten().min()
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
            Phase::Opening | Phase::AwaitingLoad { .. } | Phase::Posted { .. }
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
        if !ours {
            return None;
        }
        self.exit_seen = true;
        if self.pre_release() {
            return Some(lifecycle(LifecycleCode::RendererFailed));
        }
        // A browser exit consumes the ceremony (ADR-110 §6). An exit before release fails the
        // ceremony and `step` bumps the generation there; an exit after release bumps it here.
        // Saturating keeps a verified result: a generation at the limit refuses the next
        // ceremony with `GenerationExhausted` instead.
        self.generation = self.generation.saturating_add(1);
        None
    }

    fn apply_loaded(&mut self, id: NavigationId) -> Option<BridgeError> {
        if matches!(self.phase, Phase::AwaitingLoad { .. }) && self.loaded.is_none() {
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
            .is_some_and(|budget| expired(now, budget.start(), budget.limit()));
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
        let ceremony_id = self.plan.ceremony_id;
        let record = match cleanup_record_bytes(ceremony_id, &spec.folder_name, &identity) {
            Ok(record) => record,
            Err(error) => return self.fail(env, now, error),
        };
        if env.store.write_record(&record).is_err() {
            return self.fail(env, now, CLEANUP_STORE_FAILED);
        }
        self.record = Some(record);
        if let Err(error) = env.loopback.probe_ipv6() {
            return self.fail(env, now, error);
        }
        env.loopback.begin_navigation();
        match env.surface.navigate() {
            Ok(navigation) => {
                self.phase = Phase::AwaitingLoad { navigation };
                Step::Pending
            }
            Err(error) => self.fail(env, now, error.error()),
        }
    }

    fn await_load(
        &mut self,
        env: &mut StepEnv<'_>,
        now: Instant,
        navigation: NavigationId,
    ) -> Step {
        if let Some(error) = self.pre_post_failure(now) {
            return self.fail(env, now, error);
        }
        let Some(loaded) = self.loaded else {
            return Step::Pending;
        };
        if navigation != loaded {
            let violation = BridgeError::Lifecycle(LifecycleCode::NavigationViolation);
            let error = self.bump_generation().err().unwrap_or(violation);
            return self.fail(env, now, error);
        }
        if let Err(error) = env.loopback.probe_ipv6() {
            return self.fail(env, now, error);
        }
        if self.served_settling(env.loopback.served(), now) {
            return Step::Pending;
        }
        self.post_pair(env, now, navigation)
    }

    /// Whether a served count of zero may still be the benign race with the listener thread.
    ///
    /// A zero with a clean digest is re-read until `SERVED_SETTLE` after the first zero; a bad
    /// digest is never a race and a persisting zero is judged by `post_pair`.
    fn served_settling(&mut self, served: ServedSnapshot, now: Instant) -> bool {
        if !served.integrity_ok || served.count != 0 {
            return false;
        }
        let since = *self.served_since.get_or_insert(now);
        !expired(now, since, SERVED_SETTLE)
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
                    plan.challenge(),
                    plan.owner_user_handle(),
                    plan.prf_input_value(),
                );
                encode_create_options(&options, payload)
            }
            CeremonyKind::Get => GetOptionsV1::new(
                plan.ceremony_id,
                plan.challenge(),
                credential_id,
                plan.prf_input_value(),
            )
            .and_then(|options| encode_get_options(&options, payload)),
        }
        .map_err(protocol_from_codec)?;
        let request = OwnerBridgeControlV1::new_request(
            plan.kind,
            self.generation,
            plan.ceremony_id,
            u32::try_from(length).unwrap_or(u32::MAX),
        )
        .map_err(protocol_from_codec)?;
        head.copy_from_slice(&request.encode());
        OwnerBridgeControlV1::new_reply(plan.kind, self.generation, plan.ceremony_id)
            .map(OwnerBridgeControlV1::encode)
            .map_err(protocol_from_codec)
    }

    fn post_pair(&mut self, env: &mut StepEnv<'_>, now: Instant, navigation: NavigationId) -> Step {
        if let Err(error) = check_served(env.loopback.served()) {
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
        // ADR-110 §5.5 step 3: the served count is read again immediately before the post, after
        // the buffers were written, so a completion that arrived meanwhile cannot be posted over.
        let served = env.loopback.served();
        if let Err(error) = check_served(served) {
            return self.fail(env, now, error);
        }
        let guard = PostGuard {
            generation: self.generation,
            navigation_id: navigation,
            served_count: served.count,
        };
        if let Err(error) = env.surface.post(&guard) {
            return self.fail(env, now, error.error());
        }
        self.posts += 1;
        self.post_returned_at = env.clock.now();
        self.last_poll = None;
        self.phase = Phase::Posted { navigation };
        Step::Pending
    }

    fn posted(&mut self, env: &mut StepEnv<'_>, now: Instant, navigation: NavigationId) -> Step {
        if let Some(error) = self.budget_failure(now) {
            return self.fail(env, now, error);
        }
        // The served count is re-read at every step, so a late second completion in this
        // generation surfaces as `DuplicateDocumentLoad` promptly, not only at consumption.
        if let Err(error) = check_served(env.loopback.served()) {
            return self.fail(env, now, error);
        }
        if let Err(error) = self.poll(env, now) {
            return self.fail_unexpected(error, now);
        }
        match self.known {
            ControlState::Ready => self.consume(env, now),
            ControlState::Failed => self.fail(env, now, lifecycle(LifecycleCode::ClientFailed)),
            ControlState::Empty => self.await_receipt(env, now, navigation),
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

    fn await_receipt(
        &mut self,
        env: &mut StepEnv<'_>,
        now: Instant,
        navigation: NavigationId,
    ) -> Step {
        if expired(now, self.plan.t0, READINESS) {
            return self.timing_failure(env, now);
        }
        if !expired(now, self.post_returned_at, receipt_window(self.posts)) {
            return Step::Pending;
        }
        if self.posts >= MAX_POSTS {
            return self.timing_failure(env, now);
        }
        self.retire_and_repost(env, now, navigation)
    }

    fn await_reply(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        if self.interaction_over(now) {
            return self.fail(env, now, lifecycle(LifecycleCode::InteractionTimeout));
        }
        Step::Pending
    }

    /// Whether the interaction window, which ends at the `READY -> CONSUMING` CAS, has run out.
    fn interaction_over(&self, now: Instant) -> bool {
        self.first_past_empty
            .is_some_and(|first| expired(now, first, INTERACTION))
    }

    fn timing_failure(&mut self, env: &StepEnv<'_>, now: Instant) -> Step {
        match release_loop(env.surface, ControlState::Empty, ReleaseMode::Timing) {
            Ok(None) => {
                self.outcome = Err(lifecycle(LifecycleCode::ReadinessTimeout));
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

    fn retire_and_repost(
        &mut self,
        env: &mut StepEnv<'_>,
        now: Instant,
        navigation: NavigationId,
    ) -> Step {
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
        self.post_pair(env, now, navigation)
    }

    fn consume(&mut self, env: &mut StepEnv<'_>, now: Instant) -> Step {
        // ADR-110 §6: the interaction window ends at the CAS, so a READY first read after it
        // is not consumed.
        if self.interaction_over(now) {
            return self.fail(env, now, lifecycle(LifecycleCode::InteractionTimeout));
        }
        if expired(now, self.plan.t0, CHALLENGE_TTL) {
            return self.fail(env, now, lifecycle(LifecycleCode::ChallengeExpired));
        }
        let won = env
            .surface
            .reply_compare_exchange(ControlState::Ready as u32, ControlState::Consuming as u32);
        match won {
            Ok(true) => self.known = ControlState::Consuming,
            Ok(false) => return self.fail_unexpected(UNEXPECTED_STATE, now),
            Err(error) => return self.fail_unexpected(error.error(), now),
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
                self.outcome = Ok(verified);
                self.slots.wipe_buffers();
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
        self.outcome = Err(error);
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
        self.outcome = Err(error);
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
        self.surface_finished
            && self
                .record
                .as_deref()
                .is_none_or(|record| env.store.delete_record(record).is_ok())
    }

    fn complete(&mut self, env: &mut StepEnv<'_>) -> Step {
        if !self.cleanup(env) {
            return self.quarantine(QuarantineCode::CleanupTimeout);
        }
        self.phase = Phase::Done;
        Step::Finished(std::mem::replace(&mut self.outcome, Err(UNEXPECTED_STATE)))
    }

    fn quarantine(&mut self, code: QuarantineCode) -> Step {
        let error = BridgeError::Quarantine(code);
        self.outcome = Err(error);
        self.slots.wipe_ceremony();
        self.plan.wipe_secrets();
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

#[cfg(test)]
mod tests;
