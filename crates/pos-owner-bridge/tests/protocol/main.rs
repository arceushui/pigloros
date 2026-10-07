//! The owner-port seam on Linux: state machine, timing bounds, D2 call order, quarantine and
//! the 10,000-seed oracle, all driven by `FakeSurface` and fake owner ports.

mod driver_paths;
mod enrollment;
mod fakes;
mod oracle;
mod quarantine;
mod release_loop;
mod timing;
mod unlock;

use std::error::Error;
use std::time::Duration;

use pos_owner_bridge::ceremony::driver::{drive, CeremonyDriver, StepEnv};
use pos_owner_bridge::ceremony::plan::{CeremonyPlan, Slots, StoredGet, Verified};
use pos_owner_bridge::fake::buffers::{Actor, Buffers, LogEntry};
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::signer::FIXTURE_COSE_KEY;
use pos_owner_bridge::fake::surface::{
    FakeSurface, FakeSurfaceHandle, HookPhase, HostOp, PageModel, SurfaceConfig,
};
use pos_owner_bridge::{
    BindingUpdate, BridgeConfig, BridgeError, ConfirmedBinding, EnrollmentContext, EnrollmentPort,
    HostPorts, MonotonicClock, OwnerBridge, OwnerError, OwnerErrorKind, PrfOutput, RootFingerprint,
    UnlockPort,
};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerBridgeCodecError, OwnerUserHandle, PrfInput,
    SubjectId, WebAuthnChallenge,
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
    Ok(StoredGet {
        credential_id: CREDENTIAL_ID.to_vec(),
        user_handle: user_handle(),
        public_key: CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?,
        backup_eligible: false,
        backup_state: false,
        sign_count,
    })
}

fn create_plan(clock: &FakeClock) -> CeremonyPlan {
    CeremonyPlan {
        kind: CeremonyKind::Create,
        ceremony_id: CeremonyId::from_bytes(bytes16(0)),
        challenge: WebAuthnChallenge::from_bytes(bytes32(0x20)),
        user_handle: user_handle(),
        prf_input: PrfInput::from_bytes(bytes32(0x60)),
        stored: None,
        t0: clock.now(),
        generation: 1,
        owner_window: None,
        budget: None,
    }
}

fn get_plan(clock: &FakeClock, stored: StoredGet) -> CeremonyPlan {
    CeremonyPlan {
        kind: CeremonyKind::Get,
        stored: Some(stored),
        ..create_plan(clock)
    }
}

fn expected_prf(config: &HonestConfig) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(config.prf_secret);
    hasher.update(bytes32(0x60));
    hasher.finalize().into()
}

fn new_driver(plan: CeremonyPlan) -> CeremonyDriver {
    CeremonyDriver::new(plan, Slots::allocate())
}

/// A fake surface rig for driving one `CeremonyDriver` directly.
struct DriverRig {
    clock: FakeClock,
    loopback: FakeLoopback,
    store: FakeStore,
    surface: FakeSurface,
    handle: FakeSurfaceHandle,
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
        let page = Wrapped::new(page, hook, clock.clone())?;
        Ok(Self::build(clock, Box::new(page), surface))
    }

    fn build(clock: FakeClock, page: Box<dyn PageModel>, surface: SurfaceConfig) -> Self {
        let loopback = FakeLoopback::default();
        let surface = FakeSurface::new(clock.clone(), loopback.clone(), page, surface);
        let handle = surface.handle();
        Self {
            clock,
            loopback,
            store: FakeStore::default(),
            surface,
            handle,
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
        let result = drive(&mut driver, &mut self.env());
        (result, driver)
    }
}

fn honest(prf_listener_delay_ms: u64) -> HonestConfig {
    HonestConfig {
        listener_delay: Duration::from_millis(prf_listener_delay_ms),
        ..HonestConfig::standard(&CREDENTIAL_ID)
    }
}

/// A full bridge rig with fake host ports.
struct Rig {
    clock: FakeClock,
    loopback: FakeLoopback,
    store: FakeStore,
    surface: FakeSurfaceHandle,
    bridge: OwnerBridge<FakeSurface, FakeRandom, FakeClock>,
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
        let page = Wrapped::new(page, hook, clock.clone())?;
        let surface = FakeSurface::new(
            clock.clone(),
            loopback.clone(),
            Box::new(page),
            surface_config,
        );
        let handle = surface.handle();
        let host = HostPorts {
            loopback: Box::new(loopback.clone()),
            store: Box::new(store.clone()),
        };
        let bridge = OwnerBridge::new(surface, random, clock.clone(), host, config);
        Ok(Self {
            clock,
            loopback,
            store,
            surface: handle,
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
    Abandon { candidate: bool },
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

    fn abandon(&mut self, candidate: Option<Candidate>) {
        self.calls.push(Call::Abandon {
            candidate: candidate.is_some(),
        });
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
}

/// The honest page plus one scripted deviation.
struct Wrapped {
    inner: HonestPage,
    hook: Hook,
    clock: FakeClock,
    armed: bool,
    storm: Vec<u32>,
    retires: u32,
}

impl Wrapped {
    fn new(config: HonestConfig, hook: Hook, clock: FakeClock) -> Result<Self, Box<dyn Error>> {
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
        })
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
    }

    fn next_activity(&self) -> Option<Duration> {
        self.inner.next_activity()
    }

    fn on_host_op(&mut self, buffers: &mut Buffers, now: Duration, op: HostOp, phase: HookPhase) {
        self.inner.on_host_op(buffers, now, op, phase);
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
