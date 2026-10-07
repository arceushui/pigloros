//! The owner-thread and surface-thread hand-off: the driver moves as an owned `Send` value, the
//! owner thread blocks on the reply, and every way the channel can fail is a clean error.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;
use std::thread;

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::channel::{channel, ChannelHost, SurfaceEndpoint, SurfaceRequest};
use pos_owner_bridge::fake::buffers::LogEntry;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, BridgeStatus, CeremonyHost, CeremonyReply, OwnerBridge,
    QuarantineCode, QuarantineKeeper, SystemClock, UnavailableCode,
};

use super::{
    bytes32, context, create_plan, honest, unlock_binding, Call, FakeEnrollment, FakeUnlock,
    TestResult,
};

const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// A surface thread that vanished after accepting a driver: its browser may still be alive.
const ABANDONED: BridgeError = BridgeError::Quarantine(QuarantineCode::CleanupTimeout);

const fn assert_send<T: Send>() {}

/// Serve the surface half on its own thread, with a fake surface built on that thread.
fn spawn_surface(
    page: HonestConfig,
    config: SurfaceConfig,
    endpoint: SurfaceEndpoint,
) -> thread::JoinHandle<Result<usize, String>> {
    thread::spawn(move || {
        let clock = FakeClock::start();
        let loopback = FakeLoopback::default();
        let page = HonestPage::new(page).map_err(|error| error.to_string())?;
        let surface = FakeSurface::new(clock.clone(), loopback.clone(), Box::new(page), config);
        let handle = surface.handle();
        FakeHost::new(clock, surface, loopback, FakeStore::default()).serve(&endpoint);
        Ok(handle
            .log()
            .iter()
            .filter(|entry| matches!(entry, LogEntry::Opened { .. }))
            .count())
    })
}

fn driver() -> CeremonyDriver {
    CeremonyDriver::for_test(create_plan(&FakeClock::start()))
}

#[test]
fn the_values_that_cross_the_hand_off_are_send() {
    assert_send::<CeremonyDriver>();
    assert_send::<CeremonyReply>();
    assert_send::<ChannelHost>();
    assert_send::<SurfaceEndpoint>();
}

#[test]
fn an_enrollment_runs_across_two_threads_and_the_prf_never_leaves_the_driver() -> TestResult {
    let (host, endpoint) = channel();
    let surface = spawn_surface(honest(0), SurfaceConfig::default(), endpoint);
    let mut bridge = OwnerBridge::new(
        host,
        FakeRandom::seeded(5),
        SystemClock,
        BridgeConfig::default(),
    );
    let mut port = FakeEnrollment::new();
    bridge.enroll(&context(), &mut port)?;
    assert_eq!(
        port.calls,
        [Call::Unbound, Call::Seal, Call::Confirm, Call::Commit]
    );
    assert_eq!(bridge.status(), BridgeStatus::Ready);
    drop(bridge);
    // Two ceremonies opened two environments on the surface thread.
    assert_eq!(
        surface.join().map_err(|_| "the surface thread panicked")?,
        Ok(2)
    );
    Ok(())
}

#[test]
fn an_unlock_runs_across_two_threads() -> TestResult {
    let (host, endpoint) = channel();
    let surface = spawn_surface(honest(0), SurfaceConfig::default(), endpoint);
    let mut bridge = OwnerBridge::new(
        host,
        FakeRandom::seeded(6),
        SystemClock,
        BridgeConfig::default(),
    );
    let binding = unlock_binding("owner", 0)?;
    let mut port = FakeUnlock::new();
    bridge.unlock(&binding, &bytes32(0x60), &mut port)?;
    assert_eq!(port.calls.len(), 3);
    drop(bridge);
    assert_eq!(
        surface.join().map_err(|_| "the surface thread panicked")?,
        Ok(1)
    );
    Ok(())
}

#[test]
fn a_quarantined_ceremony_stays_with_the_surface_thread_until_its_exit_arrives() {
    let (mut host, endpoint) = channel();
    let config = SurfaceConfig {
        exit_delay: None,
        ..SurfaceConfig::default()
    };
    let surface = spawn_surface(honest(0), config, endpoint);
    let reply = host.run(driver());
    assert!(matches!(reply.result, Err(BridgeError::Quarantine(_))));
    assert!(reply.driver.is_none());
    assert!(host.poll_quarantine().is_none());
    drop(host);
    assert!(surface.join().is_ok());
}

#[test]
fn a_surface_thread_that_is_gone_fails_the_ceremony_and_returns_the_driver() {
    let (mut host, endpoint) = channel();
    drop(endpoint);
    let reply = host.run(driver());
    assert_eq!(reply.result.err(), Some(UNAVAILABLE));
    assert!(reply.driver.is_some());
    assert!(host.poll_quarantine().is_none());
}

#[test]
fn a_surface_thread_that_drops_a_command_without_replying_quarantines_the_ceremony() {
    let (mut host, endpoint) = channel();
    let surface = thread::spawn(move || {
        let request = endpoint.recv();
        drop(endpoint);
        request.is_some()
    });
    let reply = host.run(driver());
    assert_eq!(reply.result.err(), Some(ABANDONED));
    assert!(reply.driver.is_none());
    assert_eq!(surface.join().ok(), Some(true));
}

#[test]
fn a_reply_of_the_wrong_kind_is_a_failure_not_a_result() {
    let (mut host, endpoint) = channel();
    let surface = thread::spawn(move || {
        let first = endpoint.recv();
        let delivered_poll = endpoint.reply_poll(None);
        let second = endpoint.recv();
        let delivered_run = endpoint.reply_run(CeremonyReply {
            result: Err(UNAVAILABLE),
            driver: None,
        });
        (
            first.is_some(),
            delivered_poll,
            second.is_some(),
            delivered_run,
        )
    });
    let reply = host.run(driver());
    assert_eq!(reply.result.err(), Some(ABANDONED));
    assert!(host.poll_quarantine().is_none());
    assert_eq!(surface.join().ok(), Some((true, true, true, true)));
}

#[test]
fn the_endpoint_can_poll_without_blocking_and_notices_a_missing_owner() {
    let (mut host, endpoint) = channel();
    assert!(matches!(endpoint.try_recv(), Err(TryRecvError::Empty)));
    let surface = thread::spawn(move || {
        let request = endpoint.recv();
        let polled = matches!(request, Some(SurfaceRequest::PollQuarantine));
        let delivered = endpoint.reply_poll(None);
        let end = endpoint.recv();
        // The owner drops its request sender before its reply receiver, so one reply may still
        // be buffered; the second one cannot be, and fails once the receiver is gone.
        let buffered = endpoint.reply_poll(None);
        let delivered_last = endpoint.reply_poll(None);
        (polled, delivered, end.is_none(), buffered && delivered_last)
    });
    assert!(host.poll_quarantine().is_none());
    drop(host);
    assert_eq!(surface.join().ok(), Some((true, true, true, false)));
}

#[test]
fn a_command_waiting_in_the_channel_is_seen_without_blocking() -> TestResult {
    let (mut host, endpoint) = channel();
    let owner = thread::spawn(move || host.run(driver()).result.err());
    let request = loop {
        match endpoint.try_recv() {
            Ok(request) => break request,
            Err(TryRecvError::Empty) => thread::yield_now(),
            Err(TryRecvError::Disconnected) => return Err("the owner side vanished".into()),
        }
    };
    assert!(matches!(request, SurfaceRequest::Run(_)));
    assert!(endpoint.reply_run(CeremonyReply {
        result: Err(UNAVAILABLE),
        driver: None,
    }));
    assert_eq!(
        owner.join().map_err(|_| "owner panicked")?,
        Some(UNAVAILABLE)
    );
    assert!(matches!(
        endpoint.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
    Ok(())
}

#[test]
fn a_surface_thread_that_vanishes_mid_ceremony_leaves_the_bridge_quarantined() -> TestResult {
    let (host, endpoint) = channel();
    let surface = thread::spawn(move || {
        let request = endpoint.recv();
        drop(endpoint);
        request.is_some()
    });
    let mut bridge = OwnerBridge::new(
        host,
        FakeRandom::seeded(8),
        SystemClock,
        BridgeConfig::default(),
    );
    let binding = unlock_binding("owner", 0)?;
    let mut port = FakeUnlock::new();
    assert_eq!(
        bridge.unlock(&binding, &bytes32(0x60), &mut port).err(),
        Some(ABANDONED)
    );
    assert_eq!(
        bridge.status(),
        BridgeStatus::Quarantined(QuarantineCode::CleanupTimeout)
    );
    assert_eq!(
        bridge.poll_quarantine(),
        BridgeStatus::Quarantined(QuarantineCode::CleanupTimeout)
    );
    assert!(port.calls.is_empty());
    assert_eq!(surface.join().ok(), Some(true));
    Ok(())
}

/// A host that reports a quarantine and also hands the driver back, which a correct host never
/// does; the bridge must still be able to clear the quarantine through `poll_quarantine`.
struct ConfusedHost {
    release: Rc<RefCell<Option<CeremonyDriver>>>,
}

impl CeremonyHost for ConfusedHost {
    fn run(&mut self, driver: CeremonyDriver) -> CeremonyReply {
        CeremonyReply {
            result: Err(ABANDONED),
            driver: Some(driver),
        }
    }

    fn poll_quarantine(&mut self) -> Option<CeremonyDriver> {
        self.release.borrow_mut().take()
    }
}

#[test]
fn a_quarantine_result_with_a_returned_driver_still_clears_through_the_poll() -> TestResult {
    let release = Rc::new(RefCell::new(None));
    let host = ConfusedHost {
        release: Rc::clone(&release),
    };
    let clock = FakeClock::start();
    let mut bridge = OwnerBridge::new(
        host,
        FakeRandom::seeded(8),
        clock.clone(),
        BridgeConfig::default(),
    );
    let binding = unlock_binding("owner", 0)?;
    let mut port = FakeUnlock::new();
    assert_eq!(
        bridge.unlock(&binding, &bytes32(0x60), &mut port).err(),
        Some(ABANDONED)
    );
    assert_eq!(
        bridge.poll_quarantine(),
        BridgeStatus::Quarantined(QuarantineCode::CleanupTimeout)
    );
    *release.borrow_mut() = Some(CeremonyDriver::for_test(create_plan(&clock)));
    assert_eq!(bridge.poll_quarantine(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn the_quarantine_keeper_keeps_only_a_quarantined_driver_until_its_cleanup_finished() {
    let mut keeper = QuarantineKeeper::new();
    let returned = keeper.finish(driver(), Err(UNAVAILABLE));
    assert!(returned.driver.is_some());
    assert!(keeper.poll(|_| true).is_none());
    let kept = keeper.finish(driver(), Err(ABANDONED));
    assert!(kept.driver.is_none());
    assert_eq!(kept.result.err(), Some(ABANDONED));
    assert!(keeper.poll(|_| false).is_none());
    assert!(keeper.poll(|_| true).is_some());
    assert!(keeper.poll(|_| true).is_none());
}

#[test]
fn a_second_quarantine_keeps_the_first_driver_and_hands_the_second_back() {
    let mut keeper = QuarantineKeeper::new();
    let first = keeper.finish(driver(), Err(ABANDONED));
    assert!(first.driver.is_none());
    let later = CeremonyDriver::for_test(create_plan(&FakeClock::start()).with_generation(5));
    let second = keeper.finish(later, Err(ABANDONED));
    assert_eq!(second.driver.map(|returned| returned.generation()), Some(5));
    // The driver that stays is the first one, generation 1.
    assert_eq!(keeper.poll(|_| true).map(|held| held.generation()), Some(1));
    assert!(keeper.poll(|_| true).is_none());
}
