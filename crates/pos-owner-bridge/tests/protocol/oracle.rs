//! The 10,000-seed deterministic oracle (ADR-110 appendix §15, invariants I1 to I15).

use std::time::Duration;

use pos_owner_bridge::ceremony::plan::Verified;
use pos_owner_bridge::ceremony::timing::READINESS;
use pos_owner_bridge::fake::buffers::{Actor, LogEntry, Pair, Role};
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::POLL;
use pos_owner_bridge::fake::honest::{AbortBehavior, CreatePrf, Delivery, HonestConfig, Tamper};
use pos_owner_bridge::fake::signer::ReplyShape;
use pos_owner_bridge::fake::surface::{FakeSurfaceHandle, SurfaceConfig, SurfaceFaults};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, BridgeStatus, LifecycleCode, NavigationId, OwnerError,
    OwnerErrorKind, ProtocolCode, SurfaceEvent, UnavailableCode,
};

use super::{
    bytes32, context, create_plan, eligible, get_plan, honest, no_prf, stored_fixture,
    unlock_binding, wrong_key, wrong_raw_id, wrong_user_handle, Call, DriverRig, FakeEnrollment,
    FakeUnlock, Hook, Moment, Rig, TestResult,
};

const SEED_BASE: u64 = 0x0A11_0B21_D6E0_0000;
const SEEDS: u64 = 10_000;
/// The most steps one seed may take: three ceremonies at the stepper's own per-run limit.
const STEP_BUDGET: u32 = 300_000;
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
        AbortBehavior::NeverRelease,
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
            ("wrong_handle", wrong_user_handle),
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
    let nth = u32::try_from(rng.below(8))? + 1;
    let consumed = rng.pick(&[2, 6, 7, 1, 0, 4, 9])?;
    let (from, to) = rng.pick(&[(7, 6), (7, 1), (7, 2), (1, 2), (1, 6)])?;
    let moment = rng.pick(&[Moment::Consumed, Moment::Closing])?;
    let lifecycle = rng.pick(&[
        SurfaceEvent::NavigationViolation,
        SurfaceEvent::FrameCreated,
        SurfaceEvent::RendererFailed,
        SurfaceEvent::ControllerLost,
    ])?;
    rng.pick(&[
        Hook::TearBetweenCopies,
        Hook::StateAfterFirstCopy(state),
        Hook::SlowSecondCopy(slow),
        Hook::RaceRetire(landed),
        Hook::RaceNthRetire { nth, value: landed },
        Hook::AfterRetire,
        Hook::Storm(storm),
        Hook::RequestWrite,
        Hook::RaceConsume(consumed),
        Hook::RaceEnd { from, to },
        Hook::LifecycleAfterReceived(lifecycle),
        Hook::SecondCompletion(moment),
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
    steps: u32,
    t0s: Vec<Duration>,
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
        prf_zero: result.is_ok() || (*driver.prf() == [0; 32] && driver.request_clear()),
        port_calls: Vec::new(),
        port_sealed: None,
        port_confirmed: None,
        port_at_calls: Vec::new(),
        quarantine_refused: true,
        steps: rig.steps,
        t0s: vec![rig.clock.offset_of(driver.t0())],
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
    let t0s = rig.t0s.borrow().clone();
    Ok(Evidence {
        log,
        pairs,
        elapsed,
        error: outcome.err(),
        ok: outcome.is_ok(),
        records_left: rig.store.records_now().len(),
        prf_zero: outcome.is_ok() || rig.bridge.secret_slots_clear(),
        port_calls: port.calls.iter().take(calls_before).cloned().collect(),
        port_sealed: port.seal_prf,
        port_confirmed: port.confirm_prf,
        port_at_calls: port.at_calls.clone(),
        quarantine_refused: refused,
        steps: rig.steps.get(),
        t0s,
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
    let binding = unlock_binding("owner", sc.stored_counter)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    let calls_before = port.calls.len();
    let refused = if matches!(rig.bridge.status(), BridgeStatus::Quarantined(_)) {
        let again = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
        matches!(again, Err(BridgeError::Quarantine(_))) && port.calls.len() == calls_before
    } else {
        true
    };
    let (log, pairs, elapsed) = settle(&rig.surface, &rig.clock);
    let t0s = rig.t0s.borrow().clone();
    Ok(Evidence {
        log,
        pairs,
        elapsed,
        error: outcome.err(),
        ok: outcome.is_ok(),
        records_left: rig.store.records_now().len(),
        prf_zero: outcome.is_ok() || rig.bridge.secret_slots_clear(),
        port_calls: port.calls.iter().take(calls_before).cloned().collect(),
        port_sealed: None,
        port_confirmed: None,
        port_at_calls: port.at_calls.clone(),
        quarantine_refused: refused,
        steps: rig.steps.get(),
        t0s,
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

/// Whether the page follows the protocol under `hook`: it never plain-stores over the host.
const fn quiet_state_hook(hook: &Hook) -> bool {
    !matches!(
        hook,
        Hook::Storm(_) | Hook::StateAfterFirstCopy(_) | Hook::RaceConsume(_)
    )
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
        return fail(
            "secrets",
            "a PRF or the request image survived a failed ceremony",
        );
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
        let ids: Vec<[u8; 16]> = slice
            .iter()
            .filter_map(|entry| match entry {
                LogEntry::Post { pair, .. } => ev.pairs.get(*pair).map(|slot| slot.ceremony_id),
                _ => None,
            })
            .collect();
        if ids.iter().any(|id| Some(id) != ids.first()) {
            return fail("I10 re-post", "a re-post changed the ceremony ID");
        }
    }
    check_repost_payloads(&ev.pairs)
}

/// I10: a re-post changes only its generation, never the ceremony ID, challenge or options.
fn check_repost_payloads(pairs: &[Pair]) -> Failure {
    if pairs.iter().any(|pair| pair.payload.is_empty()) {
        return fail(
            "I10 payload",
            "a pair was posted without its request payload",
        );
    }
    for window in pairs.windows(2) {
        let [first, second] = window else { continue };
        if first.ceremony_id == second.ceremony_id && first.payload != second.payload {
            return fail("I10 re-post", "a re-post changed the challenge or options");
        }
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
        AbortBehavior::Runs | AbortBehavior::ReleaseFirst | AbortBehavior::NeverRelease => at,
        AbortBehavior::Ignored | AbortBehavior::Late => at + Duration::from_millis(500),
    }
}

/// I12 and I14 retention: every buffer of every ceremony is released, and each page releases
/// everything it held within 500 ms after its deadline fired.
fn check_retention(ev: &Evidence, sc: &Scenario) -> Failure {
    if sc.page.abort == AbortBehavior::NeverRelease {
        return Ok(());
    }
    for slice in slices(&ev.log) {
        // The active pair is the last one the host posted. Only for it can the host's release
        // request be what makes the page release: a retired or never-activated pair, or a page
        // holding a buffer back, releases at the page's own deadline.
        let active = slice.iter().rev().find_map(|entry| match entry {
            LogEntry::Post { pair, .. } => Some(*pair),
            _ => None,
        });
        let requested = sc.page.delivery == Delivery::Normal
            && slice.iter().any(|entry| {
                matches!(
                    entry,
                    LogEntry::Cas { actor: Actor::Host, pair, new: 4, won: true, .. }
                        if Some(*pair) == active
                )
            });
        let late = slice.iter().find_map(|entry| match entry {
            LogEntry::PageReleased { pair, at, .. }
                if requested && Some(*pair) == active && *at > ev.elapsed =>
            {
                Some((*pair, *at))
            }
            _ => None,
        });
        if let Some((pair, at)) = late {
            return fail(
                "I14 release before settle",
                format!(
                    "the active pair {pair} was released at {at:?}, after the host finished at \
                     {:?}: only the settle() advance made the page release",
                    ev.elapsed
                ),
            );
        }
    }
    for pair in &ev.pairs {
        for (delivered, released) in pair.delivered.iter().zip(pair.released) {
            if *delivered && !released {
                return fail(
                    "I12/I14 retained buffer",
                    "the page kept a buffer of some ceremony past its end",
                );
            }
        }
    }
    for slice in slices(&ev.log) {
        let Some((fired, deadline)) =
            slice
                .iter()
                .enumerate()
                .find_map(|(index, entry)| match entry {
                    LogEntry::PageDeadline { at } => Some((index, *at)),
                    _ => None,
                })
        else {
            continue;
        };
        for entry in slice.iter().take(fired) {
            let LogEntry::PageReceived { pair, role } = entry else {
                continue;
            };
            let released_at = slice.iter().find_map(|other| match other {
                LogEntry::PageReleased {
                    pair: p,
                    role: r,
                    at,
                } if p == pair && r == role => Some(*at),
                _ => None,
            });
            if released_at.is_none_or(|at| at > deadline + Duration::from_millis(500)) {
                return fail(
                    "I14 500 ms after the deadline",
                    format!(
                        "pair {pair} {role:?} released at {released_at:?}, deadline {deadline:?}"
                    ),
                );
            }
        }
    }
    Ok(())
}

/// I12: the page calls `WebAuthn` only for a complete, valid pair whose `EMPTY -> RECEIVED` won.
fn check_activation(ev: &Evidence, sc: &Scenario) -> Failure {
    let activations: Vec<(usize, usize)> = ev
        .log
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| match entry {
            LogEntry::PageWebAuthn { pair, .. } => Some((index, *pair)),
            _ => None,
        })
        .collect();
    if sc.page.delivery == Delivery::DuplicateRequest && !activations.is_empty() {
        return fail("I12 duplicate", "the page acted on a duplicated generation");
    }
    for (index, pair) in activations {
        let before = ev.log.get(..index).unwrap_or_default();
        let received = |wanted: Role| {
            before.iter().any(|entry| {
                matches!(entry, LogEntry::PageReceived { pair: p, role } if *p == pair && *role == wanted)
            })
        };
        if !(received(Role::Request) && received(Role::Reply)) {
            return fail("I12 incomplete", "the page acted on an incomplete entry");
        }
        if before
            .iter()
            .any(|entry| matches!(entry, LogEntry::ZeroClose { pair: p, .. } if *p == pair))
        {
            return fail("I12 zero-filled", "the page acted on a zero-filled header");
        }
        let cas = |wanted: bool| {
            before.iter().any(|entry| {
                matches!(
                    entry,
                    LogEntry::Cas { actor: Actor::Page, pair: p, current: 0, new: 7, won, .. }
                        if *p == pair && *won == wanted
                )
            })
        };
        if !cas(true) || cas(false) {
            return fail(
                "I12 failed CAS",
                "the page acted without a won EMPTY -> RECEIVED",
            );
        }
    }
    Ok(())
}

/// I13: a timing failure never overwrites a pair whose page has advanced.
fn check_overwrite(ev: &Evidence, sc: &Scenario) -> Failure {
    if !quiet_state_hook(&sc.hook) {
        return Ok(());
    }
    let all = slices(&ev.log);
    let timing = ev.error == Some(BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout));
    for (index, slice) in all.iter().enumerate() {
        let ended_by_timing = timing && index + 1 == all.len();
        for (position, entry) in slice.iter().enumerate() {
            let LogEntry::Cas {
                actor: Actor::Host,
                pair,
                current,
                new: 4,
                ..
            } = entry
            else {
                continue;
            };
            // A retirement is a release that a later post follows.
            let retired = slice
                .iter()
                .skip(position)
                .any(|later| matches!(later, LogEntry::Post { .. }));
            if (retired || ended_by_timing) && *current != 0 {
                return fail(
                    "I13 overwrite",
                    format!("a timing failure released pair {pair} from state {current}"),
                );
            }
        }
    }
    Ok(())
}

/// I10: no pair is posted after the ceremony's own T0 plus the readiness bound, whichever
/// environment it was posted in, so a re-post never restarts the clock.
fn check_t0(ev: &Evidence) -> Failure {
    for slice in slices(&ev.log) {
        let Some(opened) = slice.iter().find_map(|entry| match entry {
            LogEntry::Opened { at } => Some(*at),
            _ => None,
        }) else {
            continue;
        };
        let t0 = ev
            .t0s
            .iter()
            .copied()
            .filter(|t0| *t0 <= opened)
            .max()
            .ok_or_else(|| "I10 T0: no T0 precedes an opened environment".to_owned())?;
        for entry in slice {
            if let LogEntry::Post { at, .. } = entry {
                if *at < t0 || *at > t0 + READINESS {
                    return fail(
                        "I10 T0",
                        format!("a pair was posted at {at:?}, T0 was {t0:?}"),
                    );
                }
            }
        }
    }
    Ok(())
}

/// I14: with no `WebAuthn` call pending, the page releases at its next poll, with no abort wait.
fn check_no_call_pending(ev: &Evidence, sc: &Scenario) -> Failure {
    if !quiet_state_hook(&sc.hook) || sc.page.abort == AbortBehavior::NeverRelease {
        return Ok(());
    }
    for entry in &ev.log {
        let LogEntry::Cas {
            actor: Actor::Host,
            pair,
            new: 4,
            won: true,
            at,
            ..
        } = entry
        else {
            continue;
        };
        let active = ev
            .log
            .iter()
            .any(|other| matches!(other, LogEntry::PageWebAuthn { pair: p, .. } if p == pair));
        let aborted = ev
            .log
            .iter()
            .any(|other| matches!(other, LogEntry::PageAbort { pair: p, .. } if p == pair));
        if !active || aborted {
            continue;
        }
        let released = ev.log.iter().find_map(|other| match other {
            LogEntry::PageReleased {
                pair: p,
                role: Role::Reply,
                at,
            } if p == pair => Some(*at),
            _ => None,
        });
        if released.is_none_or(|released| released > *at + POLL) {
            return fail(
                "I14 no call pending",
                format!("pair {pair} released at {released:?}, requested at {at:?}"),
            );
        }
    }
    Ok(())
}

/// A lifecycle violation after `RECEIVED` while the call is pending makes the page abort.
fn check_lifecycle_abort(ev: &Evidence, sc: &Scenario) -> Failure {
    let Hook::LifecycleAfterReceived(_) = sc.hook else {
        return Ok(());
    };
    let pending = sc
        .page
        .respond_after
        .is_none_or(|after| after >= Duration::from_millis(50));
    let started = ev
        .log
        .iter()
        .any(|entry| matches!(entry, LogEntry::PageWebAuthn { .. }));
    let aborted = ev
        .log
        .iter()
        .any(|entry| matches!(entry, LogEntry::PageAbort { .. }));
    let honest_release = sc.page.abort != AbortBehavior::NeverRelease
        && sc.surface.faults == SurfaceFaults::default();
    if pending && started && honest_release && !aborted {
        return fail(
            "lifecycle abort",
            "a lifecycle violation with a call pending did not make the page abort",
        );
    }
    Ok(())
}

/// Whether the page deadline fired while the host was still working: the host stalled past it.
///
/// After a normal ceremony the deadline only fires once the settle step lets the fake clock run
/// on, which is after the host closed its controller.
fn stalled_past_the_deadline(ev: &Evidence) -> bool {
    let deadline = ev
        .log
        .iter()
        .position(|entry| matches!(entry, LogEntry::PageDeadline { .. }));
    let closed = ev
        .log
        .iter()
        .rposition(|entry| matches!(entry, LogEntry::ControllerClosed));
    deadline
        .zip(closed)
        .is_some_and(|(deadline, closed)| deadline < closed)
}

/// A bounded number of steps per seed: a deterministic stand-in for the wall-clock bound.
fn check_steps(ev: &Evidence) -> Failure {
    if ev.steps > STEP_BUDGET {
        return fail("bounded steps", format!("{} steps", ev.steps));
    }
    Ok(())
}

/// I12 and I14: the page's abort ordering holds.
fn check_page(ev: &Evidence, sc: &Scenario) -> Failure {
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
    // An unlock that fails in its ceremony (anything but an owner-port failure) never reaches the
    // port: an illegal observation or a second completion after verification discards the result.
    let ceremony_failed = ev
        .error
        .is_some_and(|error| !matches!(error, BridgeError::Owner(_)));
    if sc.kind == Kind::Unlock && ceremony_failed && !ev.port_calls.is_empty() {
        return fail(
            "I15 discard",
            "a failed ceremony still reached the owner port with its verified result",
        );
    }
    if sc.kind != Kind::Enroll {
        return Ok(());
    }
    let committed = ev.port_calls.contains(&Call::Commit);
    let sealed = ev.port_calls.contains(&Call::Seal);
    let abandons = ev
        .port_calls
        .iter()
        .filter(|call| matches!(call, Call::Abandon))
        .count();
    // `abandon` takes a candidate: exactly one call when a sealed candidate did not commit, and
    // none when there was no candidate or `commit` consumed it.
    if ev.ok != committed || abandons != usize::from(sealed && !committed) {
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
        (
            matches!(sc.hook, Hook::SecondCompletion(_)),
            "a second document completion after consumption",
        ),
        (
            matches!(sc.hook, Hook::RaceConsume(value) if value != 2),
            "the page changed the state word before consumption",
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
    let unexpected = ev.error == Some(BridgeError::Protocol(ProtocolCode::UnexpectedState));
    // A stalled host (`SlowSecondCopy`) can outlast the page deadline, whose release then stores
    // `RELEASING` over `CONSUMING`; that is a host fault, not an honest-page skip.
    let stalled = matches!(sc.hook, Hook::SlowSecondCopy(_)) && stalled_past_the_deadline(ev);
    if unexpected && quiet_state_hook(&sc.hook) && !stalled {
        return fail(
            "I15 honest page",
            "a protocol-following page caused UnexpectedState",
        );
    }
    let quarantined = matches!(ev.error, Some(BridgeError::Quarantine(_)));
    let unrecorded = sc.surface.faults.open.is_some() || sc.surface.faults.navigate.is_some();
    if !quarantined && !unrecorded && ev.records_left != 0 {
        return fail("cleanup record", "a cleanup record outlived its ceremony");
    }
    Ok(())
}

/// How many seeds of each kind ran and completed.
#[derive(Debug, Default)]
struct Tally {
    seeds: [u32; 4],
    completed: [u32; 4],
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
    let evidence = match sc.kind {
        Kind::Create | Kind::Get => run_single(&sc)?,
        Kind::Enroll => run_enroll(&sc)?,
        Kind::Unlock => run_unlock(&sc)?,
    };
    let slot = kind_slot(sc.kind);
    if let (Some(seeds), Some(completed)) =
        (tally.seeds.get_mut(slot), tally.completed.get_mut(slot))
    {
        *seeds += 1;
        *completed += u32::from(evidence.ok);
    }
    let verdict = check_discipline(&evidence, &sc)
        .and_then(|()| check_ids(&evidence))
        .and_then(|()| check_cleanup(&evidence, &sc))
        .and_then(|()| check_posts(&evidence, &sc))
        .and_then(|()| check_aba(&evidence, &sc))
        .and_then(|()| check_retention(&evidence, &sc))
        .and_then(|()| check_activation(&evidence, &sc))
        .and_then(|()| check_overwrite(&evidence, &sc))
        .and_then(|()| check_t0(&evidence))
        .and_then(|()| check_no_call_pending(&evidence, &sc))
        .and_then(|()| check_lifecycle_abort(&evidence, &sc))
        .and_then(|()| check_steps(&evidence))
        .and_then(|()| check_page(&evidence, &sc))
        .and_then(|()| check_loop(&evidence, &sc))
        .and_then(|()| check_ports(&evidence, &sc))
        .and_then(|()| check_outcome(&evidence, &sc));
    verdict
        .map_err(|message| format!("seed {:#x} ({:?}): {message}\n{sc:?}", sc.seed, sc.kind).into())
}

#[test]
fn ten_thousand_seeded_interleavings_hold_every_invariant() -> TestResult {
    let mut tally = Tally::default();
    for index in 0..SEEDS {
        run_seed(index, &mut tally)?;
    }
    // The bound is deterministic: each seed is held to `STEP_BUDGET` steps, and every kind of
    // ceremony must both run and complete. The CI job timeout is the wall-clock guard.
    assert!(tally.seeds.iter().all(|seeds| *seeds > 0), "{tally:?}");
    assert!(
        tally.completed.iter().all(|completed| *completed > 0),
        "{tally:?}"
    );
    Ok(())
}
