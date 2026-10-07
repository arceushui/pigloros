use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use pos_owner_bridge::listener::bind::{
    bind_loopback, check_ipv6_absent, classify_bind_error, BindError, Ipv6Mode, LoopbackBinder,
    StdBinder,
};
use pos_owner_bridge::listener::{ListenerConfig, LoopbackListener};
use pos_owner_bridge::{BridgeError, LoopbackPort, UnavailableCode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NO_PROBE_ERROR: i32 = 0;

/// A scripted binder: IPv4 and IPv6 results are fixed, and the probe error is shared and mutable.
struct ScriptedBinder {
    v4: Result<(), BindError>,
    v6: Result<(), BindError>,
    probe: Arc<AtomicI32>,
}

fn ephemeral() -> Result<TcpListener, BindError> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| BindError::Other)
}

impl LoopbackBinder for ScriptedBinder {
    fn bind_v4(&mut self) -> Result<TcpListener, BindError> {
        self.v4.and_then(|()| ephemeral())
    }

    fn bind_v6(&mut self) -> Result<TcpListener, BindError> {
        self.v6.and_then(|()| ephemeral())
    }

    fn probe_v6(&mut self) -> Result<(), BindError> {
        match self.probe.load(Ordering::SeqCst) {
            NO_PROBE_ERROR => Ok(()),
            code => Err(BindError::Unavailable(code)),
        }
    }
}

fn binder(
    v4: Result<(), BindError>,
    v6: Result<(), BindError>,
    probe_error: i32,
) -> (ScriptedBinder, Arc<AtomicI32>) {
    let probe = Arc::new(AtomicI32::new(probe_error));
    let scripted = ScriptedBinder {
        v4,
        v6,
        probe: Arc::clone(&probe),
    };
    (scripted, probe)
}

const PORT_UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::PortUnavailable);
const LOOPBACK_CHANGED: BridgeError = BridgeError::Unavailable(UnavailableCode::LoopbackChanged);

#[test]
fn both_sockets_bind_in_dual_mode() -> TestResult {
    let (mut scripted, _) = binder(Ok(()), Ok(()), NO_PROBE_ERROR);
    let sockets = bind_loopback(&mut scripted)?;
    assert_eq!(sockets.mode, Ipv6Mode::Dual);
    assert!(sockets.v6.is_some());
    Ok(())
}

#[test]
fn identical_absence_runs_ipv4_only() -> TestResult {
    let (mut scripted, _) = binder(Ok(()), Err(BindError::Unavailable(10_047)), 10_047);
    let sockets = bind_loopback(&mut scripted)?;
    assert_eq!(
        sockets.mode,
        Ipv6Mode::Absent {
            startup_error: 10_047
        }
    );
    assert!(sockets.v6.is_none());
    Ok(())
}

#[test]
fn a_succeeding_startup_probe_is_a_loopback_change() {
    let (mut scripted, _) = binder(Ok(()), Err(BindError::Unavailable(10_047)), NO_PROBE_ERROR);
    assert_eq!(bind_loopback(&mut scripted).err(), Some(LOOPBACK_CHANGED));
}

#[test]
fn a_different_startup_probe_error_is_a_loopback_change() {
    let (mut scripted, _) = binder(Ok(()), Err(BindError::Unavailable(10_047)), 10_049);
    assert_eq!(bind_loopback(&mut scripted).err(), Some(LOOPBACK_CHANGED));
}

#[test]
fn ipv6_in_use_or_other_failures_fail_closed() {
    for failure in [BindError::InUse, BindError::Other] {
        let (mut scripted, _) = binder(Ok(()), Err(failure), NO_PROBE_ERROR);
        assert_eq!(bind_loopback(&mut scripted).err(), Some(PORT_UNAVAILABLE));
    }
}

#[test]
fn an_ipv4_failure_fails_closed_in_every_mode() {
    for v6 in [Ok(()), Err(BindError::Unavailable(97))] {
        let (mut scripted, _) = binder(Err(BindError::InUse), v6, 97);
        assert_eq!(bind_loopback(&mut scripted).err(), Some(PORT_UNAVAILABLE));
    }
}

#[test]
fn the_probe_check_accepts_only_the_identical_error_value() {
    let (mut scripted, probe) = binder(Ok(()), Ok(()), 97);
    assert_eq!(check_ipv6_absent(&mut scripted, 97), Ok(()));
    probe.store(99, Ordering::SeqCst);
    assert_eq!(check_ipv6_absent(&mut scripted, 97), Err(LOOPBACK_CHANGED));
    probe.store(NO_PROBE_ERROR, Ordering::SeqCst);
    assert_eq!(check_ipv6_absent(&mut scripted, 97), Err(LOOPBACK_CHANGED));
}

#[test]
fn the_listener_reports_loopback_changed_when_ipv6_appears_after_startup() -> TestResult {
    let (scripted, probe) = binder(Ok(()), Err(BindError::Unavailable(97)), 97);
    let mut listener = LoopbackListener::start(Box::new(scripted), ListenerConfig::adr())?;
    assert_eq!(listener.mode(), Ipv6Mode::Absent { startup_error: 97 });
    assert!(listener.v6_addr().is_none());
    assert_eq!(listener.probe_ipv6(), Ok(()));
    probe.store(NO_PROBE_ERROR, Ordering::SeqCst);
    assert_eq!(listener.probe_ipv6(), Err(LOOPBACK_CHANGED));
    Ok(())
}

#[test]
fn a_dual_listener_probe_is_a_no_op() -> TestResult {
    let (scripted, _) = binder(Ok(()), Ok(()), NO_PROBE_ERROR);
    let mut listener = LoopbackListener::start(Box::new(scripted), ListenerConfig::adr())?;
    assert_eq!(listener.mode(), Ipv6Mode::Dual);
    assert!(listener.v6_addr().is_some());
    assert_eq!(listener.probe_ipv6(), Ok(()));
    Ok(())
}

#[test]
fn the_listener_refuses_to_start_when_binding_fails() {
    let (scripted, _) = binder(Err(BindError::InUse), Ok(()), NO_PROBE_ERROR);
    let started = LoopbackListener::start(Box::new(scripted), ListenerConfig::adr());
    assert_eq!(started.err(), Some(PORT_UNAVAILABLE));
}

#[test]
fn bind_failures_are_classified_by_kind_and_platform_value() {
    let in_use = io::Error::from(io::ErrorKind::AddrInUse);
    assert_eq!(classify_bind_error(&in_use), BindError::InUse);
    for code in [97, 99, 10_047, 10_049] {
        let absent = io::Error::from_raw_os_error(code);
        assert_eq!(classify_bind_error(&absent), BindError::Unavailable(code));
    }
    let other = io::Error::from_raw_os_error(1);
    assert_eq!(classify_bind_error(&other), BindError::Other);
    assert_eq!(
        classify_bind_error(&io::Error::other("no code")),
        BindError::Other
    );
}

#[test]
fn the_std_binder_binds_ephemeral_ports_and_reports_a_conflict() -> TestResult {
    let first = StdBinder::new(0).bind_v4()?;
    let port = first.local_addr()?.port();
    assert_eq!(StdBinder::new(port).bind_v4().err(), Some(BindError::InUse));
    let held = StdBinder::new(0).bind_v6();
    assert!(held.is_ok() || matches!(held, Err(BindError::Unavailable(_))));
    let probe = StdBinder::new(0).probe_v6();
    assert!(probe.is_ok() || matches!(probe, Err(BindError::Unavailable(_))));
    Ok(())
}
