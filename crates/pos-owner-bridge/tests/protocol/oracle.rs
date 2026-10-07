//! The 10,000-seed deterministic oracle (ADR-110 appendix §15, invariants I1 to I15).

use std::time::Duration;

use pos_owner_bridge::ceremony::plan::Verified;
use pos_owner_bridge::fake::buffers::{Actor, LogEntry, Pair, Role};
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{AbortBehavior, CreatePrf, Delivery, HonestConfig, Tamper};
use pos_owner_bridge::fake::signer::{Backup, ReplyShape, FIXTURE_COSE_KEY};
use pos_owner_bridge::fake::surface::{FakeSurfaceHandle, SurfaceConfig, SurfaceFaults};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, BridgeStatus, NavigationId, OwnerError, OwnerErrorKind,
    SurfaceEvent, UnavailableCode,
};
use pos_owner_bridge_codec::{
    CoseEs256PublicKey, OwnerUserHandle, SubjectCredentialBindingInputV1,
    SubjectCredentialBindingV1, SubjectId, TransportCodes,
};

use super::{
    bytes16, bytes32, context, create_plan, get_plan, honest, stored_fixture, user_handle, Boxed,
    Call, DriverRig, FakeEnrollment, FakeUnlock, Hook, Rig, TestResult, CREDENTIAL_ID,
};

const SEED_BASE: u64 = 0x0A11_0B21_D6E0_0000;
const SEEDS: u64 = 10_000;
const WINDOWS_MS: [u64; 8] = [250, 250, 500, 500, 1_000, 1_000, 2_000, 2_000];

type Failure = Result<(), String>;
type NamedTweak = (&'static str, fn(&mut ReplyShape));
type AnyError = Box<dyn std::error::Error>;

struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }

    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    const fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Result<T, AnyError> {
        let index = usize::try_from(self.below(u64::try_from(items.len())?))?;
        items
            .get(index)
            .cloned()
            .ok_or_else(|| "empty choice".into())
    }

    fn millis(&mut self, choices: &[u64]) -> Result<Duration, AnyError> {
        Ok(Duration::from_millis(self.pick(choices)?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Create,
    Get,
    Enroll,
    Unlock,
}

#[derive(Debug)]
struct Scenario {
    seed: u64,
    kind: Kind,
    page: HonestConfig,
    hook: Hook,
    surface: SurfaceConfig,
    events: Vec<(Duration, SurfaceEvent)>,
    stored_counter: u32,
    port_lies: bool,
    port_bound: bool,
    tweak_name: Option<&'static str>,
}

const fn wrong_key(shape: &mut ReplyShape) {
    shape.wrong_key = true;
}

fn wrong_raw_id(shape: &mut ReplyShape) {
    shape.raw_id = Some(vec![9, 9]);
}

const fn eligible(shape: &mut ReplyShape) {
    shape.backup = Backup::Eligible;
}

const fn no_prf(shape: &mut ReplyShape) {
    shape.prf = None;
}

const fn wrong_handle(shape: &mut ReplyShape) {
    shape.user_handle = Some(OwnerUserHandle::from_bytes([3; 32]));
}

fn sample_page(rng: &mut Rng) -> Result<(HonestConfig, Option<&'static str>), AnyError> {
    let mut page = honest(0);
    let mut tweak_name = None;
    page.listener_delay = rng.millis(&[0, 20, 150, 400, 900, 2_500, 4_900, 6_000])?;
    page.respond_after = if rng.chance(15) {
        None
    } else {
        Some(rng.millis(&[0, 50, 300, 900, 4_000, 40_000, 119_000, 130_000])?)
    };
    page.cancel = rng.chance(8);
    page.zero_counter = rng.chance(10);
    page.create_prf = rng.pick(&[
        CreatePrf::Returned,
        CreatePrf::Returned,
        CreatePrf::EnabledOnly,
        CreatePrf::Unsupported,
    ])?;
    page.substitute_get_prf = rng.chance(5).then_some([0xee; 32]);
    page.delivery = if rng.chance(60) {
        Delivery::Normal
    } else {
        rng.pick(&[
            Delivery::ReplyFirst,
            Delivery::RequestOnly,
            Delivery::DuplicateRequest,
            Delivery::HoldReply,
            Delivery::HoldPair,
        ])?
    };
    page.abort = rng.pick(&[
        AbortBehavior::Runs,
        AbortBehavior::Runs,
        AbortBehavior::Ignored,
        AbortBehavior::Late,
        AbortBehavior::ReleaseFirst,
    ])?;
    page.tamper = if rng.chance(75) {
        Tamper::None
    } else {
        rng.pick(&[
            Tamper::PayloadId,
            Tamper::HeaderId,
            Tamper::HeaderGeneration,
            Tamper::HeaderKind,
            Tamper::HeaderRole,
            Tamper::LengthZero,
            Tamper::LengthHuge,
            Tamper::Raw(vec![0xff]),
            Tamper::Raw(vec![0x98, 0x0a]),
        ])?
    };
    if !rng.chance(85) {
        let tweaks: [NamedTweak; 5] = [
            ("wrong_key", wrong_key),
            ("wrong_raw_id", wrong_raw_id),
            ("eligible", eligible),
            ("no_prf", no_prf),
            ("wrong_handle", wrong_handle),
        ];
        let (name, tweak) = rng.pick(&tweaks)?;
        page.tweak = Some(tweak);
        tweak_name = Some(name);
    }
    Ok((page, tweak_name))
}

fn sample_hook(rng: &mut Rng) -> Result<Hook, AnyError> {
    if rng.chance(55) {
        return Ok(Hook::None);
    }
    let count = rng.below(8) + 1;
    let storm: Vec<u32> = (0..count)
        .map(|_| u32::try_from(rng.below(9)).unwrap_or(0))
        .collect();
    let state = u32::try_from(rng.below(8))?;
    let slow = Duration::from_secs(rng.below(160));
    let landed = rng.pick(&[7, 1, 6, 2])?;
    rng.pick(&[
        Hook::TearBetweenCopies,
        Hook::StateAfterFirstCopy(state),
        Hook::SlowSecondCopy(slow),
        Hook::RaceRetire(landed),
        Hook::AfterRetire,
        Hook::Storm(storm),
        Hook::RequestWrite,
    ])
}

fn sample_surface(rng: &mut Rng) -> Result<SurfaceConfig, AnyError> {
    let load_delay = rng.millis(&[0, 100, 500, 3_000, 20_000])?;
    let exit_delay = rng.pick(&[
        Some(Duration::ZERO),
        Some(Duration::from_millis(180)),
        Some(Duration::from_millis(4_900)),
        Some(Duration::from_millis(5_100)),
        None,
    ])?;
    let mut surface = SurfaceConfig {
        load_delay,
        exit_delay,
        ..SurfaceConfig::default()
    };
    if rng.chance(6) {
        surface.served_completions = u32::try_from(rng.below(3))?;
    }
    surface.served_integrity_ok = !rng.chance(3);
    if rng.chance(8) {
        let refused = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
        surface.faults = rng.pick(&[
            SurfaceFaults {
                open: Some(refused),
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                navigate: Some(refused),
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                create: Some(refused),
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                post: Some(refused),
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                state: Some(refused),
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                zero_close: true,
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                close_controller: true,
                ..SurfaceFaults::default()
            },
            SurfaceFaults {
                finish: true,
                ..SurfaceFaults::default()
            },
        ])?;
    }
    Ok(surface)
}

fn sample_events(rng: &mut Rng) -> Result<Vec<(Duration, SurfaceEvent)>, AnyError> {
    let mut events = Vec::new();
    if rng.chance(35) {
        for _ in 0..=rng.below(3) {
            let at = Duration::from_millis(rng.below(30_000));
            let event = rng.pick(&[
                SurfaceEvent::NavigationViolation,
                SurfaceEvent::FrameCreated,
                SurfaceEvent::RendererFailed,
                SurfaceEvent::ControllerLost,
                SurfaceEvent::BrowserExited { browser_pid: 4242 },
                SurfaceEvent::BrowserExited { browser_pid: 7 },
                SurfaceEvent::DomContentLoaded(NavigationId(1)),
                SurfaceEvent::DomContentLoaded(NavigationId(5)),
            ])?;
            events.push((at, event));
        }
    }
    Ok(events)
}

fn scenario(seed: u64) -> Result<Scenario, AnyError> {
    let mut rng = Rng(seed);
    let kind = rng.pick(&[
        Kind::Create,
        Kind::Create,
        Kind::Get,
        Kind::Enroll,
        Kind::Unlock,
    ])?;
    let noisy = kind == Kind::Create || rng.chance(70);
    let (page, tweak_name) = if noisy {
        sample_page(&mut rng)?
    } else {
        (honest(0), None)
    };
    let hook = if noisy {
        sample_hook(&mut rng)?
    } else {
        Hook::None
    };
    let surface = if noisy {
        sample_surface(&mut rng)?
    } else {
        SurfaceConfig::default()
    };
    let events = if noisy {
        sample_events(&mut rng)?
    } else {
        Vec::new()
    };
    let stored_counter = if rng.chance(10) { 5 } else { 0 };
    let (port_lies, port_bound) = (noisy && rng.chance(10), noisy && rng.chance(10));
    Ok(Scenario {
        seed,
        kind,
        page,
        hook,
        surface,
        events,
        stored_counter,
        port_lies,
        port_bound,
        tweak_name,
    })
}

/// Everything the invariants look at after one run.
struct Evidence {
    log: Vec<LogEntry>,
    pairs: Vec<Pair>,
    elapsed: Duration,
    error: Option<BridgeError>,
    ok: bool,
    records_left: usize,
    prf_zero: bool,
    port_calls: Vec<Call>,
    port_sealed: Option<[u8; 32]>,
    port_confirmed: Option<[u8; 32]>,
    port_at_calls: Vec<(usize, usize)>,
    quarantine_refused: bool,
}

fn schedule(handle: &FakeSurfaceHandle, events: &[(Duration, SurfaceEvent)]) {
    for (at, event) in events {
        handle.schedule(*at, *event);
    }
}

fn settle(handle: &FakeSurfaceHandle, clock: &FakeClock) -> (Vec<LogEntry>, Vec<Pair>, Duration) {
    let elapsed = clock.elapsed();
    clock.advance(Duration::from_secs(200));
    handle.settle();
    let log = handle.log();
    let pairs = handle.with_buffers(|buffers| buffers.pairs.clone());
    (log, pairs, elapsed)
}

fn run_single(sc: &Scenario) -> Result<Evidence, AnyError> {
    let mut rig = DriverRig::with_hook(sc.page.clone(), sc.hook.clone(), sc.surface)?;
    schedule(&rig.handle, &sc.events);
    let plan = if sc.kind == Kind::Create {
        create_plan(&rig.clock)
    } else {
        get_plan(&rig.clock, stored_fixture(sc.stored_counter)?)
    };
    let (result, driver) = rig.run(plan);
    let (log, pairs, elapsed) = settle(&rig.handle, &rig.clock);
    Ok(Evidence {
        log,
        pairs,
        elapsed,
        error: result.as_ref().err().copied(),
        ok: matches!(
            result,
            Ok(Verified::Registration(_) | Verified::Assertion(_))
        ),
        records_left: rig.store.records_now().len(),
        prf_zero: result.is_ok() || *driver.slots().prf == [0; 32],
        port_calls: Vec::new(),
        port_sealed: None,
        port_confirmed: None,
        port_at_calls: Vec::new(),
        quarantine_refused: true,
    })
}

fn run_enroll(sc: &Scenario) -> Result<Evidence, AnyError> {
    let random = FakeRandom::seeded(sc.seed);
    let mut rig = Rig::with_surface(
        sc.page.clone(),
        sc.hook.clone(),
        random,
        BridgeConfig::default(),
        sc.surface,
    )?;
    schedule(&rig.surface, &sc.events);
    let mut port = FakeEnrollment::new();
    port.surface = Some(rig.surface.clone());
    port.already_bound = sc.port_bound;
    port.lie_in_confirm = sc.port_lies;
    let outcome = rig.bridge.enroll(&context(), &mut port);
    let calls_before = port.calls.len();
    let refused = if matches!(rig.bridge.status(), BridgeStatus::Quarantined(_)) {
        let again = rig.bridge.enroll(&context(), &mut port);
        matches!(again, Err(BridgeError::Quarantine(_))) && port.calls.len() == calls_before
    } else {
        true
    };
    let (log, pairs, elapsed) = settle(&rig.surface, &rig.clock);
    Ok(Evidence {
        log,
        pairs,
        elapsed,
        error: outcome.err(),
        ok: outcome.is_ok(),
        records_left: rig.store.records_now().len(),
        prf_zero: true,
        port_calls: port.calls.iter().take(calls_before).cloned().collect(),
        port_sealed: port.seal_prf,
        port_confirmed: port.confirm_prf,
        port_at_calls: port.at_calls.clone(),
        quarantine_refused: refused,
    })
}

fn run_unlock(sc: &Scenario) -> Result<Evidence, AnyError> {
    let random = FakeRandom::seeded(sc.seed);
    let mut rig = Rig::with_surface(
        sc.page.clone(),
        sc.hook.clone(),
        random,
        BridgeConfig::default(),
        sc.surface,
    )?;
    schedule(&rig.surface, &sc.events);
    let mut port = FakeUnlock::new();
    port.surface = Some(rig.surface.clone());
    if sc.port_lies {
        port.persist_error = Some(OwnerError::new(OwnerErrorKind::DurableWrite));
    }
    let binding = SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
        owner_id: "owner",
        subject_id: SubjectId::from_bytes(bytes16(0x10)),
        epoch: 1,
        credential_id: &CREDENTIAL_ID,
        user_handle: user_handle(),
        public_key: CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?,
        backup_eligible: false,
        backup_state: false,
        sign_count: sc.stored_counter,
        transports: TransportCodes::new(&[0]).boxed()?,
    })
    .boxed()?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    let calls_before = port.calls.len();
    let refused = if matches!(rig.bridge.status(), BridgeStatus::Quarantined(_)) {
        let again = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
        matches!(again, Err(BridgeError::Quarantine(_))) && port.calls.len() == calls_before
    } else {
        true
    };
    let (log, pairs, elapsed) = settle(&rig.surface, &rig.clock);
    Ok(Evidence {
        log,
        pairs,
        elapsed,
        error: outcome.err(),
        ok: outcome.is_ok(),
        records_left: rig.store.records_now().len(),
        prf_zero: true,
        port_calls: port.calls.iter().take(calls_before).cloned().collect(),
        port_sealed: None,
        port_confirmed: None,
        port_at_calls: port.at_calls.clone(),
        quarantine_refused: refused,
    })
}

fn fail<T>(name: &str, detail: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("{name}: {detail}"))
}

fn slices(log: &[LogEntry]) -> Vec<&[LogEntry]> {
    let starts: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches!(entry, LogEntry::Opened { .. }))
        .map(|(index, _)| index)
        .collect();
    starts
        .iter()
        .enumerate()
        .filter_map(|(position, start)| {
            let end = starts.get(position + 1).copied().unwrap_or(log.len());
            log.get(*start..end)
        })
        .collect()
}

const fn quiet_state_hook(hook: &Hook) -> bool {
    !matches!(hook, Hook::Storm(_) | Hook::StateAfterFirstCopy(_))
}

/// I13 and the bookkeeping that every protocol-following run must satisfy.
fn check_discipline(ev: &Evidence, sc: &Scenario) -> Failure {
    if let Some(LogEntry::Violation(text)) = ev
        .log
        .iter()
        .find(|entry| matches!(entry, LogEntry::Violation(_)))
    {
        return fail("surface-contract", text);
    }
    if ev.log.iter().any(|entry| {
        matches!(
            entry,
            LogEntry::Store {
                actor: Actor::Host,
                ..
            }
        )
    }) {
        return fail(
            "I13 host plain store",
            "the host stored into the state word",
        );
    }
    let stray = ev.log.iter().any(
        |entry| matches!(entry, LogEntry::Store { actor: Actor::Page, value, .. } if *value != 5),
    );
    if stray && quiet_state_hook(&sc.hook) {
        return fail(
            "I13 page plain store",
            "a protocol-following page stored a non-release value",
        );
    }
    if ev.elapsed > Duration::from_mins(10) {
        return fail("bounded time", format!("{:?}", ev.elapsed));
    }
    if !ev.prf_zero {
        return fail("secrets", "a PRF survived a failed ceremony");
    }
    Ok(())
}

/// I2: each ceremony ID is used by one ceremony and consumed at most once.
fn check_ids(ev: &Evidence) -> Failure {
    let mut seen: Vec<[u8; 16]> = Vec::new();
    for pair in &ev.pairs {
        if seen.last() != Some(&pair.ceremony_id) {
            if seen.contains(&pair.ceremony_id) {
                return fail(
                    "I2 id reuse",
                    "a ceremony ID came back after another ceremony",
                );
            }
            seen.push(pair.ceremony_id);
        }
    }
    for id in &seen {
        let consumed = ev
            .log
            .iter()
            .filter(|entry| match entry {
                LogEntry::Cas {
                    actor: Actor::Host,
                    current: 2,
                    new: 3,
                    won: true,
                    pair,
                    ..
                } => ev
                    .pairs
                    .get(*pair)
                    .is_some_and(|slot| slot.ceremony_id == *id),
                _ => false,
            })
            .count();
        if consumed > 1 {
            return fail("I2 double consume", format!("{consumed} consumptions"));
        }
    }
    Ok(())
}

/// I3: every pair is zeroed and closed, and every environment closes its controller.
fn check_cleanup(ev: &Evidence, sc: &Scenario) -> Failure {
    if !sc.surface.faults.zero_close && ev.pairs.iter().any(|pair| !pair.host_closed) {
        return fail("I3 open buffers", "a pair was never closed");
    }
    let closes = !sc.surface.faults.close_controller;
    let all = slices(&ev.log);
    for (index, slice) in all.iter().enumerate() {
        let last = index + 1 == all.len();
        let closed_at = slice
            .iter()
            .position(|entry| *entry == LogEntry::ControllerClosed);
        if closes && closed_at.is_none() {
            return fail("I3 controller", "a ceremony never closed its controller");
        }
        let exited = slice.contains(&LogEntry::ExitObserved);
        let quarantined = matches!(ev.error, Some(BridgeError::Quarantine(_)));
        if closes && !exited && !(last && quarantined) {
            return fail(
                "I3 exit",
                "a ceremony ended without its browser exit or a quarantine",
            );
        }
        let last_zero = slice
            .iter()
            .rposition(|entry| matches!(entry, LogEntry::ZeroClose { .. }));
        if let (Some(zero), Some(close)) = (last_zero, closed_at) {
            if zero > close {
                return fail(
                    "I3 order",
                    "buffers were zeroed after the controller closed",
                );
            }
        }
    }
    Ok(())
}

/// I4, I5 and I10: copies, posts and re-posts.
fn check_posts(ev: &Evidence, sc: &Scenario) -> Failure {
    let mut last_post: Option<usize> = None;
    for (index, entry) in ev.log.iter().enumerate() {
        if let LogEntry::HostCopy { pair, state } = entry {
            let won = ev.log.get(..index).is_some_and(|before| {
                before.iter().any(|earlier| {
                    matches!(earlier, LogEntry::Cas { actor: Actor::Host, pair: p, current: 2, new: 3, won: true, .. } if p == pair)
                })
            });
            if !won || (*state != 3 && quiet_state_hook(&sc.hook)) || last_post != Some(*pair) {
                return fail(
                    "I4 copy",
                    format!("pair {pair} copied without owning the reply"),
                );
            }
        }
        if let LogEntry::Post { pair, .. } = entry {
            last_post = Some(*pair);
        }
    }
    for slice in slices(&ev.log) {
        check_slice_posts(slice)?;
    }
    Ok(())
}

fn check_slice_posts(slice: &[LogEntry]) -> Failure {
    let open_at = slice.iter().find_map(|entry| match entry {
        LogEntry::Opened { at } => Some(*at),
        _ => None,
    });
    let posts: Vec<(usize, u32, Duration, usize)> = slice
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| match entry {
            LogEntry::Post {
                pair,
                generation,
                at,
            } => Some((*pair, *generation, *at, index)),
            _ => None,
        })
        .collect();
    if posts.len() > 8 {
        return fail("I10 posts", format!("{} pairs posted", posts.len()));
    }
    for (number, window) in posts.windows(2).enumerate() {
        let [previous, next] = window else { continue };
        let (previous, next) = (*previous, *next);
        let needed = Duration::from_millis(WINDOWS_MS.get(number).copied().unwrap_or(2_000));
        if next.1 <= previous.1 || next.2 < previous.2 + needed {
            return fail(
                "I10 windows",
                format!("post {} too early or reusing a generation", number + 2),
            );
        }
        let retired_first = slice.get(previous.3..next.3).is_some_and(|between| {
            between.iter().any(
                |entry| matches!(entry, LogEntry::ZeroClose { pair, .. } if *pair == previous.0),
            )
        });
        if !retired_first {
            return fail(
                "I5 retire order",
                "a successor was posted before its predecessor was zeroed",
            );
        }
    }
    if let (Some(open), Some(last)) = (open_at, posts.last()) {
        if last.2 > open + Duration::from_secs(15) {
            return fail(
                "I10 readiness",
                "a pair was posted after the readiness bound",
            );
        }
    }
    let received = slice
        .iter()
        .filter(|entry| {
            matches!(
                entry,
                LogEntry::Cas {
                    actor: Actor::Page,
                    new: 7,
                    won: true,
                    ..
                }
            )
        })
        .count();
    let activated = slice
        .iter()
        .filter(|entry| matches!(entry, LogEntry::PageWebAuthn { .. }))
        .count();
    if received > 1 || activated > 1 {
        return fail(
            "I10/I12 receipt",
            format!("{received} RECEIVED pairs, {activated} WebAuthn calls"),
        );
    }
    Ok(())
}

/// I11: once the host moved a reply away from `EMPTY` it never reads `EMPTY` again.
fn check_aba(ev: &Evidence, sc: &Scenario) -> Failure {
    if !quiet_state_hook(&sc.hook) {
        return Ok(());
    }
    let mut moved: Vec<usize> = Vec::new();
    for entry in &ev.log {
        match entry {
            LogEntry::Cas {
                actor: Actor::Host,
                pair,
                new: 4,
                won: true,
                ..
            } => moved.push(*pair),
            LogEntry::Cas {
                actor: Actor::Page,
                pair,
                current: 0,
                won: true,
                ..
            } if moved.contains(pair) => {
                return fail("I11 ABA", "a page CAS from EMPTY won on a retired pair");
            }
            LogEntry::HostLoad { pair, value: 0 } if moved.contains(pair) => {
                return fail("I11 ABA", "a retired pair read EMPTY again");
            }
            _ => {}
        }
    }
    Ok(())
}

fn expected_release(abort: AbortBehavior, at: Duration) -> Duration {
    match abort {
        AbortBehavior::Runs | AbortBehavior::ReleaseFirst => at,
        AbortBehavior::Ignored | AbortBehavior::Late => at + Duration::from_millis(500),
    }
}

/// I12 and I14: the page releases everything it received, and its abort ordering holds.
fn check_page(ev: &Evidence, sc: &Scenario) -> Failure {
    let last_id = ev.pairs.last().map(|pair| pair.ceremony_id);
    for pair in ev
        .pairs
        .iter()
        .filter(|pair| Some(pair.ceremony_id) == last_id)
    {
        for (delivered, released) in pair.delivered.iter().zip(pair.released) {
            if *delivered && !released {
                return fail(
                    "I12/I14 retained buffer",
                    "the page kept a buffer past its deadline",
                );
            }
        }
    }
    let type_errors = ev
        .log
        .iter()
        .filter(|entry| {
            matches!(
                entry,
                LogEntry::PageHandler {
                    type_error: true,
                    ..
                }
            )
        })
        .count();
    if type_errors > 0
        && !matches!(
            sc.page.abort,
            AbortBehavior::Late | AbortBehavior::ReleaseFirst
        )
    {
        return fail("I14 handler", "an abort handler hit a detached buffer");
    }
    for (index, entry) in ev.log.iter().enumerate() {
        let LogEntry::PageAbort { pair, at } = entry else {
            continue;
        };
        let released = ev
            .log
            .iter()
            .enumerate()
            .find_map(|(position, other)| match other {
                LogEntry::PageReleased {
                    pair: p,
                    role: Role::Reply,
                    at,
                } if p == pair => Some((position, *at)),
                _ => None,
            });
        let Some((position, released_at)) = released else {
            return fail("I14 release", "an aborted pair was never released");
        };
        let expected = expected_release(sc.page.abort, *at);
        if released_at != expected {
            return fail(
                "I14 500 ms",
                format!("released at {released_at:?}, expected {expected:?}"),
            );
        }
        let handler =
            ev.log
                .iter()
                .enumerate()
                .skip(index)
                .find_map(|(at_index, other)| match other {
                    LogEntry::PageHandler {
                        pair: p,
                        type_error,
                    } if p == pair => Some((at_index, *type_error)),
                    _ => None,
                });
        match (sc.page.abort, handler) {
            (AbortBehavior::Runs, Some((at_index, false))) if at_index < position => {}
            (AbortBehavior::Ignored, None) => {}
            (AbortBehavior::Late | AbortBehavior::ReleaseFirst, Some((at_index, true)))
                if at_index > position => {}
            other => return fail("I14 ordering", format!("{other:?}")),
        }
    }
    Ok(())
}

/// I15: the release CAS loop never exceeds eight attempts, and an honest page costs at most four.
fn check_loop(ev: &Evidence, sc: &Scenario) -> Failure {
    let limit = if quiet_state_hook(&sc.hook) { 4 } else { 8 };
    let mut attempts = 0;
    for entry in &ev.log {
        match entry {
            LogEntry::Cas {
                actor: Actor::Host,
                new: 4,
                ..
            } => {
                attempts += 1;
                if attempts > limit {
                    return fail("I15 attempts", format!("{attempts} attempts"));
                }
            }
            LogEntry::Cas {
                actor: Actor::Host, ..
            }
            | LogEntry::HostCopy { .. }
            | LogEntry::ZeroClose { .. } => {
                attempts = 0;
            }
            _ => {}
        }
    }
    Ok(())
}

/// I1, I7, I8 and I9 on the owner ports.
fn check_ports(ev: &Evidence, sc: &Scenario) -> Failure {
    if ev
        .port_at_calls
        .iter()
        .any(|(opened, finished)| opened != finished)
    {
        return fail(
            "I1 handover",
            "a secret reached a port while an environment was open",
        );
    }
    if !ev.quarantine_refused {
        return fail(
            "I8 quarantine",
            "a quarantined bridge accepted a new ceremony",
        );
    }
    if sc.kind != Kind::Enroll {
        return Ok(());
    }
    let committed = ev.port_calls.contains(&Call::Commit);
    let abandons = ev
        .port_calls
        .iter()
        .filter(|call| matches!(call, Call::Abandon { .. }))
        .count();
    if ev.ok != committed || abandons != usize::from(!ev.ok) {
        return fail(
            "I7 commit/abandon",
            format!("ok {} calls {:?}", ev.ok, ev.port_calls),
        );
    }
    if committed && (ev.port_sealed != ev.port_confirmed || sc.port_lies || sc.port_bound) {
        return fail(
            "I9 commit",
            "committed despite a different fingerprint or a bound credential",
        );
    }
    if ev.ok && ev.port_calls != [Call::Unbound, Call::Seal, Call::Confirm, Call::Commit] {
        return fail("D2 order", format!("{:?}", ev.port_calls));
    }
    Ok(())
}

fn must_fail_reason(sc: &Scenario) -> Option<&'static str> {
    let creates = matches!(sc.kind, Kind::Create | Kind::Enroll);
    let reasons = [
        (sc.page.tamper != Tamper::None, "tamper"),
        (
            sc.page.tweak.is_some()
                && sc.kind != Kind::Create
                && !(sc.kind == Kind::Enroll && sc.tweak_name == Some("eligible")),
            "tweak",
        ),
        (
            creates && sc.page.create_prf == CreatePrf::Unsupported,
            "unsupported prf",
        ),
        (sc.surface.served_completions != 1, "served count"),
        (!sc.surface.served_integrity_ok, "integrity"),
        (sc.surface.faults != SurfaceFaults::default(), "fault"),
        (sc.page.cancel, "cancel"),
        (
            sc.page.listener_delay > Duration::from_secs(5),
            "listener never registers",
        ),
        (sc.kind == Kind::Enroll && sc.port_lies, "confirmation lies"),
        (sc.kind == Kind::Enroll && sc.port_bound, "credential bound"),
        (
            sc.kind == Kind::Unlock && sc.port_lies,
            "binding update fails",
        ),
        (
            matches!(sc.hook, Hook::TearBetweenCopies | Hook::RequestWrite),
            "hook",
        ),
    ];
    reasons
        .into_iter()
        .find(|(applies, _)| *applies)
        .map(|(_, reason)| reason)
}

fn must_fail(sc: &Scenario) -> bool {
    must_fail_reason(sc).is_some()
}

fn is_clean(sc: &Scenario) -> bool {
    !must_fail(sc)
        && sc.events.is_empty()
        && matches!(sc.hook, Hook::None)
        && sc.page.substitute_get_prf.is_none()
        && sc.page.tweak.is_none()
        && matches!(sc.page.delivery, Delivery::Normal | Delivery::ReplyFirst)
        && sc.page.listener_delay <= Duration::from_millis(4_900)
        && sc
            .page
            .respond_after
            .is_some_and(|after| after <= Duration::from_secs(100))
        && sc.surface.load_delay <= Duration::from_secs(3)
        && sc
            .surface
            .exit_delay
            .is_some_and(|delay| delay <= Duration::from_millis(4_900))
        && sc.stored_counter == 0
}

fn check_outcome(ev: &Evidence, sc: &Scenario) -> Failure {
    if ev.ok && must_fail(sc) {
        return fail(
            "false accept",
            format!("{:?}\n{sc:#?}", must_fail_reason(sc)),
        );
    }
    if !ev.ok && is_clean(sc) {
        return fail("false reject", format!("{:?}", ev.error));
    }
    let quarantined = matches!(ev.error, Some(BridgeError::Quarantine(_)));
    let unrecorded = sc.surface.faults.open.is_some() || sc.surface.faults.navigate.is_some();
    if !quarantined && !unrecorded && ev.records_left != 0 {
        return fail("cleanup record", "a cleanup record outlived its ceremony");
    }
    Ok(())
}

/// How many seeds of each kind completed and how long each kind took.
#[derive(Debug, Default)]
struct Tally {
    seeds: [u32; 4],
    completed: [u32; 4],
    spent: [Duration; 4],
}

const fn kind_slot(kind: Kind) -> usize {
    match kind {
        Kind::Create => 0,
        Kind::Get => 1,
        Kind::Enroll => 2,
        Kind::Unlock => 3,
    }
}

fn run_seed(index: u64, tally: &mut Tally) -> Result<(), AnyError> {
    let sc = scenario(SEED_BASE + index)?;
    let started = std::time::Instant::now();
    let evidence = match sc.kind {
        Kind::Create | Kind::Get => run_single(&sc)?,
        Kind::Enroll => run_enroll(&sc)?,
        Kind::Unlock => run_unlock(&sc)?,
    };
    let slot = kind_slot(sc.kind);
    if let (Some(seeds), Some(completed), Some(spent)) = (
        tally.seeds.get_mut(slot),
        tally.completed.get_mut(slot),
        tally.spent.get_mut(slot),
    ) {
        *seeds += 1;
        *completed += u32::from(evidence.ok);
        *spent += started.elapsed();
    }
    let verdict = check_discipline(&evidence, &sc)
        .and_then(|()| check_ids(&evidence))
        .and_then(|()| check_cleanup(&evidence, &sc))
        .and_then(|()| check_posts(&evidence, &sc))
        .and_then(|()| check_aba(&evidence, &sc))
        .and_then(|()| check_page(&evidence, &sc))
        .and_then(|()| check_loop(&evidence, &sc))
        .and_then(|()| check_ports(&evidence, &sc))
        .and_then(|()| check_outcome(&evidence, &sc));
    verdict.map_err(|message| format!("seed {:#x} ({:?}): {message}", sc.seed, sc.kind).into())
}

#[test]
fn ten_thousand_seeded_interleavings_hold_every_invariant() -> TestResult {
    let started = std::time::Instant::now();
    let mut tally = Tally::default();
    for index in 0..SEEDS {
        run_seed(index, &mut tally)?;
    }
    // The ADR bound is 60 s on a hosted runner; instrumented coverage runs get more room.
    let budget = if cfg!(coverage) {
        Duration::from_mins(5)
    } else {
        Duration::from_mins(1)
    };
    assert!(
        started.elapsed() < budget,
        "{:?} {tally:?}",
        started.elapsed()
    );
    Ok(())
}
