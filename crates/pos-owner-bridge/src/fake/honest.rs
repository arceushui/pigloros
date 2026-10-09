//! A well-behaved page, with configurable timing, delivery order, abort behaviour and tampering.
//!
//! It follows ADR-110 §5.5: it polls for its listener, matches buffers by generation, moves the
//! state word only by compare-exchange, aborts a pending `WebAuthn` call before releasing, and
//! releases everything when the host asks or the page deadline passes.

use std::time::Duration;

use pos_owner_bridge_codec::{
    decode_create_options, decode_get_options, CeremonyId, CeremonyKind, ControlRole, ControlState,
    OwnerBridgeCodecError, OwnerBridgeControlV1, OwnerUserHandle, WebAuthnChallenge,
    CONTROL_HEADER_BYTES,
};
use sha2::{Digest, Sha256};

use super::buffers::{offset, state, Actor, Buffers, LogEntry, Role};
use super::signer::{FixtureSigner, ReplyShape};
use super::surface::{HookPhase, HostOp, PageModel};

/// The page polls the state word at this interval.
pub const POLL: Duration = Duration::from_millis(20);

/// The longest the page waits for its abort handler.
pub const ABORT_WAIT: Duration = Duration::from_millis(500);

/// The single page deadline, from script start.
pub const DEADLINE: Duration = Duration::from_secs(155);

/// The longest the page polls for `chrome.webview`.
pub const LISTENER_LIMIT: Duration = Duration::from_secs(5);

/// How buffers reach the page after each post.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    /// Request, then reply.
    Normal,
    /// Reply, then request.
    ReplyFirst,
    /// Only the request.
    RequestOnly,
    /// The request twice, then the reply.
    DuplicateRequest,
    /// The request now; the reply after the next post (two pairs interleave).
    HoldReply,
    /// Both buffers after the next post (a retired pair arrives after its successor).
    HoldPair,
}

/// What the page's abort handler does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortBehavior {
    /// The handler runs at once; its compare-exchange loses; then the page releases.
    Runs,
    /// The platform ignores `abort()`: the page releases after the bounded wait.
    Ignored,
    /// The handler runs only after the bounded wait, finding the buffer detached.
    Late,
    /// A control page that releases before its handler runs.
    ReleaseFirst,
    /// A hostile page that ignores every release request and its own deadline. The host must
    /// still finish its cleanup on timers alone.
    NeverRelease,
}

/// A deviation applied to the published reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tamper {
    /// No deviation.
    None,
    /// The payload carries another ceremony ID.
    PayloadId,
    /// The header carries another ceremony ID.
    HeaderId,
    /// The header carries another generation.
    HeaderGeneration,
    /// The header carries another kind.
    HeaderKind,
    /// The header carries another role byte.
    HeaderRole,
    /// The payload length is zero.
    LengthZero,
    /// The payload length exceeds the capacity.
    LengthHuge,
    /// The payload is replaced by these raw bytes.
    Raw(Vec<u8>),
}

/// Everything configurable about the honest page.
#[derive(Clone, Debug)]
pub struct HonestConfig {
    /// The credential ID the fixture authenticator holds.
    pub credential_id: Vec<u8>,
    /// How long after script start the `chrome.webview` listener registers.
    pub listener_delay: Duration,
    /// How long after `RECEIVED` the `WebAuthn` call resolves; `None` means it never does.
    pub respond_after: Option<Duration>,
    /// Report a cancel (`FAILED`) instead of a result.
    pub cancel: bool,
    /// The authenticator secret the PRF derives from.
    pub prf_secret: [u8; 32],
    /// What Create reports about the PRF extension.
    pub create_prf: CreatePrf,
    /// A PRF value that replaces the derived one in every Get.
    pub substitute_get_prf: Option<[u8; 32]>,
    /// The first signature counter value minus one.
    pub start_counter: u32,
    /// Counter values for successive Get ceremonies; later Gets count up from the last one.
    pub get_counters: Vec<u32>,
    /// Report counter zero in every assertion.
    pub zero_counter: bool,
    /// The user handle reported in assertions.
    pub assertion_user_handle: Option<OwnerUserHandle>,
    /// A hook that changes every reply shape before it is encoded.
    pub tweak: Option<fn(&mut ReplyShape)>,
    /// A deviation applied to the published reply.
    pub tamper: Tamper,
    /// How buffers reach the page.
    pub delivery: Delivery,
    /// What the abort handler does.
    pub abort: AbortBehavior,
}

impl HonestConfig {
    /// A page that registers its listener after 20 ms and approves after 300 ms.
    #[must_use]
    pub fn standard(credential_id: &[u8]) -> Self {
        Self {
            credential_id: credential_id.to_vec(),
            listener_delay: Duration::from_millis(20),
            respond_after: Some(Duration::from_millis(300)),
            cancel: false,
            prf_secret: [0x5a; 32],
            create_prf: CreatePrf::Returned,
            substitute_get_prf: None,
            start_counter: 0,
            get_counters: Vec::new(),
            zero_counter: false,
            assertion_user_handle: None,
            tweak: None,
            tamper: Tamper::None,
            delivery: Delivery::Normal,
            abort: AbortBehavior::Runs,
        }
    }
}

const fn immediate(delivery: Delivery) -> &'static [Role] {
    match delivery {
        Delivery::Normal => &[Role::Request, Role::Reply],
        Delivery::ReplyFirst => &[Role::Reply, Role::Request],
        Delivery::RequestOnly | Delivery::HoldReply => &[Role::Request],
        Delivery::DuplicateRequest => &[Role::Request, Role::Request, Role::Reply],
        Delivery::HoldPair => &[],
    }
}

const fn withheld(delivery: Delivery) -> &'static [Role] {
    match delivery {
        Delivery::HoldReply => &[Role::Reply],
        Delivery::HoldPair => &[Role::Request, Role::Reply],
        _ => &[],
    }
}

/// What Create reports about the PRF extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreatePrf {
    /// `enabled` with a `first` result.
    Returned,
    /// `enabled` without a result, so enrollment needs a restricted assertion.
    EnabledOnly,
    /// Not enabled: the authenticator has no PRF.
    Unsupported,
}

#[derive(Clone, Copy, Debug)]
enum Task {
    Arrive { pair: usize, role: Role },
    Respond,
    Release,
    ReleaseNow,
    Handler { type_error: bool },
    Deadline,
}

#[derive(Clone, Copy, Debug)]
struct Scheduled {
    at: Duration,
    task: Task,
}

#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    generation: u32,
    request: Option<usize>,
    reply: Option<usize>,
}

#[derive(Clone, Debug)]
struct Active {
    pair: usize,
    kind: CeremonyKind,
    id: CeremonyId,
    challenge: WebAuthnChallenge,
    prf_input: [u8; 32],
    user_handle: Option<[u8; 32]>,
    responded: bool,
    done: bool,
}

/// The honest page model.
pub struct HonestPage {
    config: HonestConfig,
    signer: FixtureSigner,
    script_start: Duration,
    registers: bool,
    tasks: Vec<Scheduled>,
    held: Vec<(usize, Role)>,
    entries: Vec<Entry>,
    dead: Vec<u32>,
    active: Option<Active>,
    expired: bool,
    counter: u32,
    gets: usize,
}

impl HonestPage {
    /// Create the page and its fixture authenticator.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPayload` when the fixture scalars are invalid.
    pub fn new(config: HonestConfig) -> Result<Self, OwnerBridgeCodecError> {
        let signer = FixtureSigner::new(&config.credential_id)?;
        let counter = config.start_counter;
        Ok(Self {
            registers: config.listener_delay <= LISTENER_LIMIT,
            config,
            signer,
            script_start: Duration::ZERO,
            tasks: Vec::new(),
            held: Vec::new(),
            entries: Vec::new(),
            dead: Vec::new(),
            active: None,
            expired: false,
            counter,
            gets: 0,
        })
    }

    fn schedule(&mut self, at: Duration, task: Task) {
        self.tasks.push(Scheduled { at, task });
    }

    fn pop_due(&mut self, now: Duration) -> Option<Scheduled> {
        let index = self
            .tasks
            .iter()
            .enumerate()
            .filter(|(_, scheduled)| scheduled.at <= now)
            .min_by_key(|(_, scheduled)| scheduled.at)
            .map(|(index, _)| index)?;
        Some(self.tasks.remove(index))
    }

    fn run(&mut self, buffers: &mut Buffers, scheduled: Scheduled) {
        let at = scheduled.at;
        buffers.now = at;
        match scheduled.task {
            Task::Arrive { pair, role } => self.arrive(buffers, at, pair, role),
            Task::Respond => self.respond(buffers),
            Task::Release => self.release_requested(buffers, at),
            Task::ReleaseNow => self.release_active(buffers),
            Task::Handler { type_error } => self.handler(buffers, type_error),
            Task::Deadline => self.deadline(buffers, at),
        }
    }

    fn boundary(&self, now: Duration) -> Duration {
        let since = now.saturating_sub(self.script_start).as_millis();
        let step = POLL.as_millis();
        let ticks = since.div_ceil(step) * step;
        self.script_start + Duration::from_millis(u64::try_from(ticks).unwrap_or(0))
    }

    fn header(buffers: &Buffers, pair: usize, role: Role) -> Option<OwnerBridgeControlV1> {
        let slot = buffers.pair_at(pair);
        let (bytes, expected) = match role {
            Role::Request => (&slot.request, ControlRole::Request),
            Role::Reply => (&slot.reply, ControlRole::Reply),
        };
        let prefix = bytes.get(..CONTROL_HEADER_BYTES).unwrap_or_default();
        let header = OwnerBridgeControlV1::decode(prefix).ok()?;
        (header.role() == expected).then_some(header)
    }

    fn release_entry(buffers: &mut Buffers, entry: Entry) {
        entry
            .reply
            .into_iter()
            .for_each(|pair| buffers.release(pair, Role::Reply));
        entry
            .request
            .into_iter()
            .for_each(|pair| buffers.release(pair, Role::Request));
    }

    fn drop_entry(&mut self, buffers: &mut Buffers, generation: u32) {
        self.entries
            .iter()
            .position(|entry| entry.generation == generation)
            .map(|index| self.entries.remove(index))
            .into_iter()
            .for_each(|entry| Self::release_entry(buffers, entry));
    }

    fn arrive(&mut self, buffers: &mut Buffers, at: Duration, pair: usize, role: Role) {
        if !self.registers || at < self.script_start + self.config.listener_delay {
            buffers.lose(pair, role);
            return;
        }
        buffers.deliver(pair, role);
        let header =
            Self::header(buffers, pair, role).filter(|_| !self.expired && self.active.is_none());
        let Some(header) = header else {
            buffers.release(pair, role);
            return;
        };
        let generation = header.generation();
        if self.dead.contains(&generation) {
            buffers.release(pair, role);
            return;
        }
        if self.is_duplicate(generation, role) {
            self.drop_entry(buffers, generation);
            buffers.release(pair, role);
            self.dead.push(generation);
            return;
        }
        let entry = self.insert(generation, role, pair);
        let Some((request_pair, reply_pair)) = entry.request.zip(entry.reply) else {
            return;
        };
        self.activate(buffers, at, generation, request_pair, reply_pair);
    }

    fn is_duplicate(&self, generation: u32, role: Role) -> bool {
        self.entries.iter().any(|entry| {
            entry.generation == generation
                && match role {
                    Role::Request => entry.request.is_some(),
                    Role::Reply => entry.reply.is_some(),
                }
        })
    }

    fn insert(&mut self, generation: u32, role: Role, pair: usize) -> Entry {
        let mut entry = self
            .entries
            .iter()
            .find(|entry| entry.generation == generation)
            .copied()
            .unwrap_or_else(|| Entry {
                generation,
                ..Entry::default()
            });
        match role {
            Role::Request => entry.request = Some(pair),
            Role::Reply => entry.reply = Some(pair),
        }
        self.entries
            .retain(|stored| stored.generation != generation);
        self.entries.push(entry);
        entry
    }

    /// The `WebAuthn` call a complete, valid, still-empty pair would start.
    fn pair_facts(buffers: &Buffers, request_pair: usize, reply_pair: usize) -> Option<Active> {
        let request = Self::header(buffers, request_pair, Role::Request)?;
        let matching = Self::header(buffers, reply_pair, Role::Reply).is_some_and(|reply| {
            request.generation() == reply.generation()
                && request.ceremony_id() == reply.ceremony_id()
                && request.kind() == reply.kind()
        });
        let states = request.state() == ControlState::Ready
            && buffers.state_of(reply_pair) == Some(state::EMPTY);
        let length = request.payload_len() as usize;
        let payload = buffers
            .pair_at(request_pair)
            .request
            .get(offset::PAYLOAD..offset::PAYLOAD + length)
            .unwrap_or_default();
        let (challenge, prf_input, user_handle) = match request.kind() {
            CeremonyKind::Create => decode_create_options(payload).map(|options| {
                (
                    options.challenge(),
                    *options.prf_input().as_bytes(),
                    Some(*options.user_handle().as_bytes()),
                )
            }),
            CeremonyKind::Get => decode_get_options(payload)
                .map(|options| (options.challenge(), *options.prf_input().as_bytes(), None)),
        }
        .ok()?;
        (matching && states).then(|| Active {
            pair: reply_pair,
            kind: request.kind(),
            id: request.ceremony_id(),
            challenge,
            prf_input,
            user_handle,
            responded: false,
            done: false,
        })
    }

    fn activate(
        &mut self,
        buffers: &mut Buffers,
        at: Duration,
        generation: u32,
        request_pair: usize,
        reply_pair: usize,
    ) {
        let Some(active) = Self::pair_facts(buffers, request_pair, reply_pair) else {
            self.drop_entry(buffers, generation);
            return;
        };
        buffers.cas(Actor::Page, reply_pair, state::EMPTY, state::RECEIVED);
        buffers.log.push(LogEntry::PageWebAuthn {
            pair: reply_pair,
            ceremony_id: *active.id.as_bytes(),
            challenge: *active.challenge.as_bytes(),
            prf_input: active.prf_input,
            user_handle: active.user_handle,
        });
        self.active = Some(active);
        for other in std::mem::take(&mut self.entries) {
            if other.generation != generation {
                Self::release_entry(buffers, other);
            }
        }
        self.config
            .respond_after
            .into_iter()
            .for_each(|delay| self.schedule(at + delay, Task::Respond));
    }

    fn derived_prf(&self, prf_input: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.config.prf_secret);
        hasher.update(prf_input);
        hasher.finalize().into()
    }

    fn build_payload(&mut self, active: &Active) -> Option<Vec<u8>> {
        let derived = self.derived_prf(&active.prf_input);
        let mut shape = match active.kind {
            CeremonyKind::Create => ReplyShape {
                prf_enabled: self.config.create_prf != CreatePrf::Unsupported,
                ..ReplyShape::honest(
                    0,
                    (self.config.create_prf == CreatePrf::Returned).then_some(derived),
                )
            },
            CeremonyKind::Get => {
                self.counter += 1;
                self.gets += 1;
                let scripted = self.config.get_counters.get(self.gets - 1).copied();
                let counter = if self.config.zero_counter {
                    0
                } else {
                    scripted.unwrap_or(self.counter)
                };
                let prf = self.config.substitute_get_prf.unwrap_or(derived);
                ReplyShape {
                    user_handle: self.config.assertion_user_handle,
                    ..ReplyShape::honest(counter, Some(prf))
                }
            }
        };
        self.config
            .tweak
            .into_iter()
            .for_each(|tweak| tweak(&mut shape));
        let payload = match active.kind {
            CeremonyKind::Create => {
                self.signer
                    .attestation_payload(active.id, &active.challenge, &shape)
            }
            CeremonyKind::Get => {
                self.signer
                    .assertion_payload(active.id, &active.challenge, &shape)
            }
        };
        payload.ok()
    }

    fn flip(buffers: &mut Buffers, pair: usize, at_offset: usize) {
        let current = buffers
            .pair_at(pair)
            .reply
            .get(at_offset)
            .copied()
            .unwrap_or(0);
        buffers.set_reply_byte(pair, at_offset, !current);
    }

    fn tamper(&self, buffers: &mut Buffers, pair: usize) {
        let generation = buffers.pair_at(pair).generation;
        match &self.config.tamper {
            Tamper::None => {}
            Tamper::PayloadId => Self::flip(buffers, pair, offset::PAYLOAD + 8),
            Tamper::HeaderId => Self::flip(buffers, pair, offset::CEREMONY_ID),
            Tamper::HeaderGeneration => {
                buffers.set_reply_word(pair, offset::GENERATION, generation.wrapping_add(1));
            }
            Tamper::HeaderKind => Self::flip(buffers, pair, 9),
            Tamper::HeaderRole => buffers.set_reply_byte(pair, 8, 0),
            Tamper::LengthZero => buffers.set_reply_word(pair, offset::PAYLOAD_LEN, 0),
            Tamper::LengthHuge => buffers.set_reply_word(pair, offset::PAYLOAD_LEN, 70_000),
            Tamper::Raw(bytes) => buffers.write_payload(pair, bytes),
        }
    }

    fn respond(&mut self, buffers: &mut Buffers) {
        self.active
            .clone()
            .filter(|active| !active.done && !active.responded)
            .into_iter()
            .for_each(|active| self.respond_to(buffers, &active));
    }

    fn respond_to(&mut self, buffers: &mut Buffers, active: &Active) {
        self.active
            .iter_mut()
            .for_each(|live| live.responded = true);
        let pair = active.pair;
        let target = if self.config.cancel {
            state::FAILED
        } else {
            state::WRITING
        };
        if !buffers.cas(Actor::Page, pair, state::RECEIVED, target) {
            self.release_active(buffers);
            return;
        }
        if self.config.cancel {
            return;
        }
        let Some(payload) = self.build_payload(active) else {
            buffers.cas(Actor::Page, pair, state::WRITING, state::FAILED);
            return;
        };
        buffers.write_payload(pair, &payload);
        self.tamper(buffers, pair);
        buffers.cas(Actor::Page, pair, state::WRITING, state::READY);
    }

    fn release_requested(&mut self, buffers: &mut Buffers, at: Duration) {
        self.active
            .clone()
            .filter(|active| !active.done && self.config.abort != AbortBehavior::NeverRelease)
            .into_iter()
            .for_each(|active| {
                if active.responded {
                    self.release_active(buffers);
                } else {
                    self.abort(buffers, at, active.pair);
                }
            });
    }

    fn abort(&mut self, buffers: &mut Buffers, at: Duration, pair: usize) {
        buffers.log.push(LogEntry::PageAbort { pair, at });
        self.tasks
            .retain(|scheduled| !matches!(scheduled.task, Task::Respond));
        self.active
            .iter_mut()
            .for_each(|live| live.responded = true);
        match self.config.abort {
            AbortBehavior::Runs => {
                self.handler(buffers, false);
                self.release_active(buffers);
            }
            AbortBehavior::Ignored => self.schedule(at + ABORT_WAIT, Task::ReleaseNow),
            AbortBehavior::Late => {
                self.schedule(at + ABORT_WAIT, Task::ReleaseNow);
                let later = at + ABORT_WAIT + Duration::from_millis(100);
                self.schedule(later, Task::Handler { type_error: true });
            }
            // `NeverRelease` never gets here: `release_requested` and `deadline` skip it.
            AbortBehavior::ReleaseFirst | AbortBehavior::NeverRelease => {
                self.release_active(buffers);
                self.handler(buffers, true);
            }
        }
    }

    fn handler(&self, buffers: &mut Buffers, type_error: bool) {
        self.active.iter().for_each(|active| {
            if !type_error {
                buffers.cas(Actor::Page, active.pair, state::RECEIVED, state::FAILED);
            }
            buffers.log.push(LogEntry::PageHandler {
                pair: active.pair,
                type_error,
            });
        });
    }

    fn release_active(&mut self, buffers: &mut Buffers) {
        self.active
            .iter_mut()
            .find(|active| !active.done)
            .map(|active| {
                active.done = true;
                active.pair
            })
            .into_iter()
            .for_each(|pair| {
                buffers.zero_reply_payload(pair);
                buffers.store(Actor::Page, pair, state::RELEASING);
                buffers.release(pair, Role::Reply);
                buffers.release(pair, Role::Request);
            });
    }

    fn deadline(&mut self, buffers: &mut Buffers, at: Duration) {
        self.expired = true;
        buffers.log.push(LogEntry::PageDeadline { at });
        if self.config.abort == AbortBehavior::NeverRelease {
            return;
        }
        let pending = self
            .active
            .as_ref()
            .filter(|active| !active.done && !active.responded)
            .map(|active| active.pair);
        if let Some(pair) = pending {
            self.abort(buffers, at, pair);
        } else {
            self.release_active(buffers);
        }
        for entry in std::mem::take(&mut self.entries) {
            Self::release_entry(buffers, entry);
        }
    }
}

impl PageModel for HonestPage {
    fn on_script_start(&mut self, buffers: &mut Buffers, at: Duration) {
        buffers.teardown_page();
        self.script_start = at;
        self.tasks.clear();
        self.held.clear();
        self.entries.clear();
        self.dead.clear();
        self.active = None;
        self.expired = false;
        self.schedule(at + DEADLINE, Task::Deadline);
    }

    fn next_activity(&self) -> Option<Duration> {
        self.tasks.iter().map(|scheduled| scheduled.at).min()
    }

    fn on_post(&mut self, _buffers: &mut Buffers, now: Duration, pair: usize) {
        for &role in immediate(self.config.delivery) {
            self.schedule(now, Task::Arrive { pair, role });
        }
        for (held_pair, role) in std::mem::take(&mut self.held) {
            self.schedule(
                now,
                Task::Arrive {
                    pair: held_pair,
                    role,
                },
            );
        }
        for &role in withheld(self.config.delivery) {
            self.held.push((pair, role));
        }
    }

    fn advance(&mut self, buffers: &mut Buffers, now: Duration) {
        while let Some(scheduled) = self.pop_due(now) {
            self.run(buffers, scheduled);
        }
    }

    fn on_host_op(&mut self, _buffers: &mut Buffers, now: Duration, op: HostOp, phase: HookPhase) {
        let HostOp::Cas {
            pair,
            new,
            won: Some(true),
            ..
        } = op
        else {
            return;
        };
        let watching = self
            .active
            .as_ref()
            .is_some_and(|active| active.pair == pair && !active.done);
        if phase == HookPhase::After && new == state::RELEASE_REQUESTED && watching {
            let at = self.boundary(now);
            self.schedule(at, Task::Release);
        }
    }
}
