//! The U-tier: the Linux adapters over a kernel `uhid` device backed by the software
//! authenticator (ADR-110 E20 LG; Redmine #1476).
//!
//! The owner U-tier job starts the `uhid-fido` example under `sudo`, hands the hidraw node to the
//! runner user, and then runs these tests as that user. `OWNER_CTAP_UHID` names the scenario the
//! device was prepared for (`one`, `two` or `unplug`); a test returns at once in every other
//! scenario, so the ordinary hosted test jobs skip them. `OWNER_CTAP_UHID_PIN` is the
//! authenticator's PIN, `OWNER_CTAP_UHID_STOP` the file whose creation unplugs the `unplug`
//! device, and each test appends one line to the file named by `OWNER_CTAP_UHID_EVIDENCE`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use pos_owner_bridge::{BridgeError, LifecycleCode, OsRandom, SystemClock};
use pos_owner_ctap::hid::REPORT_BYTES;
use pos_owner_ctap::hidraw::{discover, DEV_DIR, SYSFS_HIDRAW};
use pos_owner_ctap::{CtapAuthenticator, HidTransport, HidrawTransport, TransportError, TtyPrompt};

use super::{enroll_and_unlock, pty, Pty, TestResult, User, PROMPT};

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);

fn scenario_is(name: &str) -> bool {
    std::env::var("OWNER_CTAP_UHID").is_ok_and(|value| value == name)
}

fn evidence(line: &str) -> TestResult {
    if let Some(path) = std::env::var_os("OWNER_CTAP_UHID_EVIDENCE") {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "U {line}")?;
    }
    Ok(())
}

fn open() -> Result<HidrawTransport, BridgeError> {
    HidrawTransport::open_in(Path::new(SYSFS_HIDRAW), Path::new(DEV_DIR))
}

#[test]
fn the_one_virtual_device_is_discovered_and_opened() -> TestResult {
    if !scenario_is("one") {
        return Ok(());
    }
    let node = discover(Path::new(SYSFS_HIDRAW), Path::new(DEV_DIR))?;
    assert!(node.starts_with(DEV_DIR));
    HidrawTransport::open_node(&node).map_err(|_| "the runner user cannot open the node")?;
    evidence(&format!("discovered and opened {}", node.display()))
}

#[test]
fn a_read_with_no_report_waits_out_its_timeout() -> TestResult {
    if !scenario_is("one") {
        return Ok(());
    }
    let mut transport = open()?;
    let started = Instant::now();
    let mut report = [0; REPORT_BYTES];
    assert_eq!(
        transport.read_report(&mut report, Duration::from_millis(200)),
        Ok(false)
    );
    assert!(started.elapsed() >= Duration::from_millis(150));
    evidence("an idle read timed out")
}

#[test]
fn a_ceremony_runs_through_the_kernel_with_a_pin_typed_at_a_pseudo_terminal() -> TestResult {
    if !scenario_is("one") {
        return Ok(());
    }
    let pin = std::env::var("OWNER_CTAP_UHID_PIN")?;
    let Pty { master, slave } = pty()?;
    let mut port = CtapAuthenticator::new(open()?, TtyPrompt::new(slave)?, OsRandom);
    let (outcome, typed) = thread::scope(|scope| {
        let user = scope.spawn(|| {
            let mut user = User::new(&master);
            for _ in 0..3 {
                user.wait_for(PROMPT)?;
                user.type_line(format!("{pin}\n").as_bytes())?;
            }
            Ok::<(), String>(())
        });
        (
            enroll_and_unlock(&mut port, &SystemClock, 2, Duration::from_mins(2)),
            user.join(),
        )
    });
    let outputs = outcome?;
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(typed.map_err(|_| ()), Ok(Ok(())));
    evidence("one enrollment and two unlocks, three PINs typed at a pseudo-terminal")
}

#[test]
fn two_virtual_devices_are_refused() -> TestResult {
    if !scenario_is("two") {
        return Ok(());
    }
    assert_eq!(
        discover(Path::new(SYSFS_HIDRAW), Path::new(DEV_DIR)),
        Err(CLIENT_FAILED)
    );
    assert_eq!(open().err(), Some(CLIENT_FAILED));
    evidence("two devices refused")
}

#[test]
fn an_unplugged_device_fails_the_transport() -> TestResult {
    if !scenario_is("unplug") {
        return Ok(());
    }
    let mut transport = open()?;
    let mut report = [0; REPORT_BYTES];
    assert_eq!(
        transport.read_report(&mut report, Duration::from_millis(50)),
        Ok(false)
    );
    let stop = std::env::var_os("OWNER_CTAP_UHID_STOP").ok_or("OWNER_CTAP_UHID_STOP is not set")?;
    std::fs::write(stop, b"stop")?;
    let limit = Instant::now() + Duration::from_secs(10);
    let mut gone = false;
    while !gone && Instant::now() < limit {
        gone = transport
            .read_report(&mut report, Duration::from_millis(200))
            .is_err();
    }
    assert!(gone);
    assert_eq!(transport.write_report(&report), Err(TransportError));
    evidence("an unplugged device failed the read and the write")
}
