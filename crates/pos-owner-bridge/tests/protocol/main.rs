//! The owner-port seam on Linux: state machine, timing bounds, D2 call order, quarantine and
//! the 10,000-seed oracle, all driven by `FakeSurface` and fake owner ports.

mod channel;
mod driver_paths;
mod enrollment;
mod fakes;
mod oracle;
mod quarantine;
mod timing;
mod unlock;

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::rc::Rc;
use std::time::Duration;

use pos_owner_bridge::ceremony::driver::{CeremonyDriver, StepEnv};
use pos_owner_bridge::ceremony::plan::{CeremonyPlan, StoredGet, Verified};
use pos_owner_bridge::fake::buffers::{Actor, Buffers, LogEntry};
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::signer::{Backup, ReplyShape, FIXTURE_COSE_KEY};
use pos_owner_bridge::fake::stepper::{FakeHost, FakeStepper};
use pos_owner_bridge::fake::surface::{
    FakeSurface, FakeSurfaceHandle, HookPhase, HostOp, PageModel, SurfaceConfig,
};
use pos_owner_bridge::{
    BindingUpdate, BridgeConfig, BridgeError, ConfirmedBinding, EnrollmentContext, EnrollmentPort,
    MonotonicClock, OwnerBridge, OwnerError, OwnerErrorKind, PrfOutput, RootFingerprint,
    SurfaceEvent, UnlockPort,
};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerBridgeCodecError, OwnerUserHandle, PrfInput,
    SubjectCredentialBindingInputV1, SubjectCredentialBindingV1, SubjectId, TransportCodes,
    WebAuthnChallenge,
};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

/// A codec failure made into a std error for test `?` chains.
#[derive(Debug)]
struct CodecFailure(pub OwnerBridgeCodecError);

impl std::fmt::Display for CodecFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "codec failure: {}", self.0)
    }
}

impl Error for CodecFailure {}

/// Make a codec result usable with `?` in a boxed-error test.
trait Boxed<T> {
    fn boxed(self) -> Result<T, Box<dyn Error>>;
}

impl<T> Boxed<T> for Result<T, OwnerBridgeCodecError> {
    fn boxed(self) -> Result<T, Box<dyn Error>> {
        self.map_err(|error| Box::new(CodecFailure(error)) as Box<dyn Error>)
    }
}

const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];

fn bytes32(first: u8) -> [u8; 32] {
    std::array::from_fn(|index| first.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn bytes16(first: u8) -> [u8; 16] {
    std::array::from_fn(|index| first.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn user_handle() -> OwnerUserHandle {
    OwnerUserHandle::from_bytes(bytes32(0x40))
}

fn stored_fixture(sign_count: u32) -> Result<StoredGet, Box<dyn Error>> {
    Ok(StoredGet::new(
        CREDENTIAL_ID.to_vec(),
        user_handle(),
        CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?,
        false,
        false,
        sign_count,
    ))
}

fn create_plan(clock: &FakeClock) -> CeremonyPlan {
    CeremonyPlan::for_test(
        CeremonyKind::Create,
        CeremonyId::from_bytes(bytes16(0)),
        WebAuthnChallenge::from_bytes(bytes32(0x20)),
        user_handle(),
        PrfInput::from_bytes(bytes32(0x60)),
        clock.now(),
    )
}

fn get_plan(clock: &FakeClock, stored: StoredGet) -> CeremonyPlan {
    CeremonyPlan::for_test(
        CeremonyKind::Get,
        CeremonyId::from_bytes(bytes16(0)),
        WebAuthnChallenge::from_bytes(bytes32(0x20)),
        user_handle(),
        PrfInput::from_bytes(bytes32(0x60)),
        clock.now(),
    )
    .with_stored(Some(stored))
}

fn unlock_binding(
    owner: &str,
    sign_count: u32,
) -> Result<SubjectCredentialBindingV1<'_>, Box<dyn std::error::Error>> {
    SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
        owner_id: owner,
        subject_id: SubjectId::from_bytes(bytes16(0x10)),
        epoch: 1,
        credential_id: &CREDENTIAL_ID,
        user_handle: user_handle(),
        public_key: CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?,
        backup_eligible: false,
        backup_state: false,
        sign_count,
        transports: TransportCodes::new(&[0]).boxed()?,
    })
    .boxed()
}

/// Reply tweaks the tests share: each makes one thing about a fixture reply wrong.
const fn wrong_key(shape: &mut ReplyShape) {
    shape.wrong_key = true;
}

fn wrong_raw_id(shape: &mut ReplyShape) {
    shape.raw_id = Some(vec![9, 9]);
}

const fn wrong_user_handle(shape: &mut ReplyShape) {
    shape.user_handle = Some(OwnerUserHandle::from_bytes([1; 32]));
}

const fn eligible(shape: &mut ReplyShape) {
    shape.backup = Backup::Eligible;
}

const fn no_prf(shape: &mut ReplyShape) {
    shape.prf = None;
}

fn malformed_prf(shape: &mut ReplyShape) {
    shape.prf_item = Some(vec![0x41, 0x07]);
}

fn expected_prf(config: &HonestConfig) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(config.prf_secret);
    hasher.update(bytes32(0x60));
    hasher.finalize().into()
}

fn new_driver(plan: CeremonyPlan) -> CeremonyDriver {
    CeremonyDriver::for_test(plan)
}

/// A fake surface rig for driving one `CeremonyDriver` directly.
struct DriverRig {
    clock: FakeClock,
    loopback: FakeLoopback,
    store: FakeStore,
    surface: FakeSurface,
    handle: FakeSurfaceHandle,
    steps: u32,
}

impl DriverRig {
    fn new(page: HonestConfig, surface: SurfaceConfig) -> Result<Self, Box<dyn Error>> {
        Self::with_hook(page, Hook::None, surface)
    }

    fn with_hook(
        page: HonestConfig,
        hook: Hook,
        surface: SurfaceConfig,
    ) -> Result<Self, Box<dyn Error>> {
        let clock = FakeClock::start();
        let loopback = FakeLoopback::default();
        let page = Wrapped::new(page, hook, clock.clone(), loopback.clone())?;
        Ok(Self::build(clock, loopback, Box::new(page), surface))
    }

    fn build(
        clock: FakeClock,
        loopback: FakeLoopback,
        page: Box<dyn PageModel>,
        surface: SurfaceConfig,
    ) -> Self {
        let surface = FakeSurface::new(clock.clone(), loopback.clone(), page, surface);
        let handle = surface.handle();
        Self {
            clock,
            loopback,
            store: FakeStore::default(),
            surface,
            handle,
            steps: 0,
        }
    }

    fn env(&mut self) -> StepEnv<'_> {
        StepEnv {
            surface: &mut self.surface,
            clock: &self.clock,
            loopback: &mut self.loopback,
            store: &mut self.store,
        }
    }

    /// Run `plan` to completion and return its result and the finished driver.
    fn run(&mut self, plan: CeremonyPlan) -> (Result<Verified, BridgeError>, CeremonyDriver) {
        let mut driver = new_driver(plan);
        let result = self.step_to_end(&mut driver);
        (result, driver)
    }

    /// Step `driver` to the end with the fake stepper.
    fn step_to_end(&mut self, driver: &mut CeremonyDriver) -> Result<Verified, BridgeError> {
        let mut stepper = FakeStepper::new(self.clock.clone());
        let result = stepper.run(driver, &mut self.env());
        self.steps += stepper.steps();
        result
    }
}

fn honest(prf_listener_delay_ms: u64) -> HonestConfig {
    HonestConfig {
        listener_delay: Duration::from_millis(prf_listener_delay_ms),
        ..HonestConfig::standard(&CREDENTIAL_ID)
    }
}

/// A full bridge rig: the owner-thread bridge over a fake host that owns the surface.
struct Rig {
    clock: FakeClock,
    loopback: FakeLoopback,
    store: FakeStore,
    surface: FakeSurfaceHandle,
    steps: Rc<Cell<u32>>,
    t0s: Rc<RefCell<Vec<Duration>>>,
    bridge: OwnerBridge<FakeHost, FakeRandom, FakeClock>,
}

impl Rig {
    fn new(page: HonestConfig, random: FakeRandom) -> Result<Self, Box<dyn Error>> {
        Self::with_hook(page, Hook::None, random, BridgeConfig::default())
    }

    fn with_hook(
        page: HonestConfig,
        hook: Hook,
        random: FakeRandom,
        config: BridgeConfig,
    ) -> Result<Self, Box<dyn Error>> {
        Self::with_surface(page, hook, random, config, SurfaceConfig::default())
    }

    fn with_surface(
        page: HonestConfig,
        hook: Hook,
        random: FakeRandom,
        config: BridgeConfig,
        surface_config: SurfaceConfig,
    ) -> Result<Self, Box<dyn Error>> {
        let clock = FakeClock::start();
        let loopback = FakeLoopback::default();
        let store = FakeStore::default();
        let page = Wrapped::new(page, hook, clock.clone(), loopback.clone())?;
        let surface = FakeSurface::new(
            clock.clone(),
            loopback.clone(),
            Box::new(page),
            surface_config,
        );
        let handle = surface.handle();
        let host = FakeHost::new(clock.clone(), surface, loopback.clone(), store.clone());
        let (steps, t0s) = (host.steps_counter(), host.t0_log());
        let bridge = OwnerBridge::new(host, random, clock.clone(), config);
        Ok(Self {
            clock,
            loopback,
            store,
            surface: handle,
            steps,
            t0s,
            bridge,
        })
    }
}

fn context() -> EnrollmentContext {
    EnrollmentContext {
        owner_id: "owner".to_owned(),
        subject_id: SubjectId::from_bytes(bytes16(0x10)),
        epoch: 1,
        owner_window: None,
    }
}

/// One call an owner port received, in order.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Unbound,
    Seal,
    Confirm,
    Commit,
    Abandon,
    Open,
    Persist,
    Release,
}

/// The in-memory root and wrap of the fake owner adapter.
struct Candidate {
    sealed_with: [u8; 32],
    root: [u8; 32],
}

fn fingerprint(root: &[u8; 32]) -> RootFingerprint {
    RootFingerprint::from_bytes(Sha256::digest(root).into())
}

/// A fake ADR-091 owner adapter that checks the D2 contract the real one must honour.
struct FakeEnrollment {
    calls: Vec<Call>,
    already_bound: bool,
    unbound_error: Option<OwnerError>,
    seal_error: Option<OwnerError>,
    commit_error: Option<OwnerError>,
    lie_in_confirm: bool,
    seal_prf: Option<[u8; 32]>,
    confirm_prf: Option<[u8; 32]>,
    committed: Option<ConfirmedBinding>,
    surface: Option<FakeSurfaceHandle>,
    seal_delay: Option<(FakeClock, Duration)>,
    /// `(environments opened, environments finished)` at each PRF-bearing call.
    at_calls: Vec<(usize, usize)>,
}

impl FakeEnrollment {
    const fn new() -> Self {
        Self {
            calls: Vec::new(),
            already_bound: false,
            unbound_error: None,
            seal_error: None,
            commit_error: None,
            lie_in_confirm: false,
            seal_prf: None,
            confirm_prf: None,
            committed: None,
            surface: None,
            seal_delay: None,
            at_calls: Vec::new(),
        }
    }

    fn observe(&mut self) {
        if let Some(surface) = &self.surface {
            let log = surface.log();
            let opened = log
                .iter()
                .filter(|entry| matches!(entry, LogEntry::Opened { .. }))
                .count();
            let finished = log
                .iter()
                .filter(|entry| **entry == LogEntry::Finished)
                .count();
            self.at_calls.push((opened, finished));
        }
    }
}

impl EnrollmentPort for FakeEnrollment {
    type Candidate = Candidate;

    fn credential_unbound(&mut self, _credential_id: &[u8]) -> Result<bool, OwnerError> {
        self.calls.push(Call::Unbound);
        self.unbound_error.map_or(Ok(!self.already_bound), Err)
    }

    fn seal_candidate(
        &mut self,
        prf: PrfOutput<'_>,
        _context: &EnrollmentContext,
    ) -> Result<(Candidate, RootFingerprint), OwnerError> {
        self.calls.push(Call::Seal);
        self.observe();
        if let Some((clock, delay)) = &self.seal_delay {
            clock.advance(*delay);
        }
        self.seal_prf = Some(*prf.as_bytes());
        if let Some(error) = self.seal_error {
            return Err(error);
        }
        let root = [0x77; 32];
        let candidate = Candidate {
            sealed_with: *prf.as_bytes(),
            root,
        };
        Ok((candidate, fingerprint(&root)))
    }

    fn confirm_candidate(
        &mut self,
        candidate: &Candidate,
        prf: PrfOutput<'_>,
    ) -> Result<RootFingerprint, OwnerError> {
        self.calls.push(Call::Confirm);
        self.observe();
        self.confirm_prf = Some(*prf.as_bytes());
        if self.lie_in_confirm {
            return Ok(fingerprint(&[0x11; 32]));
        }
        if candidate.sealed_with != *prf.as_bytes() {
            return Err(OwnerError::new(OwnerErrorKind::Wrap));
        }
        Ok(fingerprint(&candidate.root))
    }

    fn commit(
        &mut self,
        _candidate: Candidate,
        binding: ConfirmedBinding,
    ) -> Result<(), OwnerError> {
        self.calls.push(Call::Commit);
        if let Some(error) = self.commit_error {
            return Err(error);
        }
        self.committed = Some(binding);
        Ok(())
    }

    fn abandon(&mut self, _candidate: Candidate) {
        self.calls.push(Call::Abandon);
    }
}

/// A fake unlock adapter.
struct FakeUnlock {
    calls: Vec<Call>,
    open_error: Option<OwnerError>,
    persist_error: Option<OwnerError>,
    updates: Vec<BindingUpdate>,
    prf: Option<[u8; 32]>,
    surface: Option<FakeSurfaceHandle>,
    at_calls: Vec<(usize, usize)>,
}

impl FakeUnlock {
    const fn new() -> Self {
        Self {
            calls: Vec::new(),
            open_error: None,
            persist_error: None,
            updates: Vec::new(),
            prf: None,
            surface: None,
            at_calls: Vec::new(),
        }
    }
}

impl UnlockPort for FakeUnlock {
    type Pending = [u8; 32];
    type Session = [u8; 32];

    fn open_pending(&mut self, prf: PrfOutput<'_>) -> Result<[u8; 32], OwnerError> {
        self.calls.push(Call::Open);
        if let Some(surface) = &self.surface {
            let log = surface.log();
            let opened = log
                .iter()
                .filter(|entry| matches!(entry, LogEntry::Opened { .. }))
                .count();
            let finished = log
                .iter()
                .filter(|entry| **entry == LogEntry::Finished)
                .count();
            self.at_calls.push((opened, finished));
        }
        self.prf = Some(*prf.as_bytes());
        self.open_error.map_or(Ok(*prf.as_bytes()), Err)
    }

    fn persist_binding_update(&mut self, update: &BindingUpdate) -> Result<(), OwnerError> {
        self.calls.push(Call::Persist);
        self.updates.push(*update);
        self.persist_error.map_or(Ok(()), Err)
    }

    fn release(&mut self, pending: [u8; 32]) -> [u8; 32] {
        self.calls.push(Call::Release);
        pending
    }
}

/// A deviation injected at a host operation, on top of the honest page.
#[derive(Clone, Debug)]
enum Hook {
    None,
    /// The page rewrites a payload byte between the host's two copies.
    TearBetweenCopies,
    /// The page stores this state word right after the host's first copy.
    StateAfterFirstCopy(u32),
    /// Time passes during the host's second copy.
    SlowSecondCopy(Duration),
    /// The page moves the state word from `EMPTY` just before the host's retirement CAS.
    RaceRetire(u32),
    /// The page tries `EMPTY -> RECEIVED` right after the host's retirement CAS won.
    AfterRetire,
    /// Once the host first tries the release CAS, the page stores these values, one per access.
    Storm(Vec<u32>),
    /// The page writes into the read-only request buffer when the pair is posted.
    RequestWrite,
    /// The page moves the state word from `EMPTY` just before the host's `nth` retirement CAS.
    RaceNthRetire {
        nth: u32,
        value: u32,
    },
    /// The page stores this value just before the host's `READY -> CONSUMING` CAS.
    RaceConsume(u32),
    /// Just before the host's end-of-ceremony release CAS from a state past `EMPTY`, the page's
    /// own compare-exchange `from -> to` lands.
    RaceEnd {
        from: u32,
        to: u32,
    },
    /// This lifecycle event surfaces right after the page starts its `WebAuthn` call.
    LifecycleAfterReceived(SurfaceEvent),
    /// The listener reports a second document completion at this moment.
    SecondCompletion(Moment),
}

/// When a second document completion reaches the listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Moment {
    /// Right after the host won the consuming compare-exchange: the release phase sees it.
    Consumed,
    /// Right before the host zeroes and closes the buffers: the exit phase sees it.
    Closing,
}

/// The honest page plus one scripted deviation.
struct Wrapped {
    inner: HonestPage,
    hook: Hook,
    clock: FakeClock,
    armed: bool,
    storm: Vec<u32>,
    retires: u32,
    injected: bool,
    loopback: FakeLoopback,
}

impl Wrapped {
    fn new(
        config: HonestConfig,
        hook: Hook,
        clock: FakeClock,
        loopback: FakeLoopback,
    ) -> Result<Self, Box<dyn Error>> {
        let storm = match &hook {
            Hook::Storm(values) => values.clone(),
            _ => Vec::new(),
        };
        Ok(Self {
            inner: HonestPage::new(config).boxed()?,
            hook,
            clock,
            armed: false,
            storm,
            retires: 0,
            injected: false,
            loopback,
        })
    }

    /// A second document completion reaches the listener at its scripted moment.
    fn complete_again(&self, op: HostOp, phase: HookPhase) {
        let Hook::SecondCompletion(moment) = self.hook else {
            return;
        };
        let due = match moment {
            Moment::Consumed => matches!(
                (op, phase),
                (
                    HostOp::Cas {
                        new: 3,
                        won: Some(true),
                        ..
                    },
                    HookPhase::After
                )
            ),
            Moment::Closing => matches!((op, phase), (HostOp::ZeroClose { .. }, HookPhase::Before)),
        };
        if due {
            self.loopback.set_served(2, true);
        }
    }

    fn storm_store(&mut self, buffers: &mut Buffers, pair: usize) {
        if self.armed && !self.storm.is_empty() {
            let value = self.storm.remove(0);
            buffers.store(Actor::Page, pair, value);
        }
    }
}

impl PageModel for Wrapped {
    fn on_script_start(&mut self, buffers: &mut Buffers, at: Duration) {
        self.injected = false;
        self.inner.on_script_start(buffers, at);
    }

    fn on_post(&mut self, buffers: &mut Buffers, now: Duration, pair: usize) {
        self.inner.on_post(buffers, now, pair);
        if matches!(self.hook, Hook::RequestWrite) {
            buffers.write_request(pair, now);
        }
    }

    fn advance(&mut self, buffers: &mut Buffers, now: Duration) {
        self.inner.advance(buffers, now);
        if let Hook::LifecycleAfterReceived(event) = self.hook {
            let started = buffers
                .log
                .iter()
                .any(|entry| matches!(entry, LogEntry::PageWebAuthn { .. }));
            if started && !self.injected {
                self.injected = true;
                buffers.schedule(now, event);
            }
        }
    }

    fn next_activity(&self) -> Option<Duration> {
        self.inner.next_activity()
    }

    fn on_host_op(&mut self, buffers: &mut Buffers, now: Duration, op: HostOp, phase: HookPhase) {
        self.inner.on_host_op(buffers, now, op, phase);
        self.complete_again(op, phase);
        match (&self.hook, op, phase) {
            (Hook::TearBetweenCopies, HostOp::Copy { pair, count: 1 }, HookPhase::After) => {
                buffers.set_reply_byte(pair, 80, 0xee);
            }
            (
                Hook::StateAfterFirstCopy(value),
                HostOp::Copy { pair, count: 1 },
                HookPhase::After,
            ) => {
                buffers.store(Actor::Page, pair, *value);
            }
            (Hook::SlowSecondCopy(delay), HostOp::Copy { count: 2, .. }, HookPhase::After) => {
                self.clock.advance(*delay);
            }
            (
                Hook::RaceRetire(value),
                HostOp::Cas {
                    pair,
                    current: 0,
                    new: 4,
                    ..
                },
                HookPhase::Before,
            ) => {
                buffers.cas(Actor::Page, pair, 0, *value);
            }
            (
                Hook::RaceNthRetire { nth, value },
                HostOp::Cas {
                    pair,
                    current: 0,
                    new: 4,
                    ..
                },
                HookPhase::Before,
            ) => {
                self.retires += 1;
                if self.retires == *nth {
                    buffers.cas(Actor::Page, pair, 0, *value);
                }
            }
            (
                Hook::RaceConsume(value),
                HostOp::Cas {
                    pair,
                    current: 2,
                    new: 3,
                    ..
                },
                HookPhase::Before,
            ) => buffers.store(Actor::Page, pair, *value),
            (
                Hook::RaceEnd { from, to },
                HostOp::Cas {
                    pair,
                    current: 1..=7,
                    new: 4,
                    ..
                },
                HookPhase::Before,
            ) => {
                buffers.cas(Actor::Page, pair, *from, *to);
            }
            (
                Hook::AfterRetire,
                HostOp::Cas {
                    pair,
                    new: 4,
                    won: Some(true),
                    ..
                },
                HookPhase::After,
            ) => {
                buffers.cas(Actor::Page, pair, 0, 7);
            }
            (Hook::Storm(_), HostOp::Cas { pair, new: 4, .. }, HookPhase::Before) => {
                self.armed = true;
                self.storm_store(buffers, pair);
            }
            (
                Hook::Storm(_),
                HostOp::Load { pair } | HostOp::Cas { pair, .. },
                HookPhase::Before,
            ) => {
                self.storm_store(buffers, pair);
            }
            _ => {}
        }
    }
}
