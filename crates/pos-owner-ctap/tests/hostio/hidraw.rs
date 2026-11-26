//! The hidraw transport over datagram pairs and a temporary sysfs: discovery, frames and polls.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;

use pos_owner_bridge::{BridgeError, LifecycleCode};
use pos_owner_ctap::hid::REPORT_BYTES;
use pos_owner_ctap::hidraw::{discover, is_fido_descriptor};
use pos_owner_ctap::{HidTransport, HidrawTransport, TransportError};

use super::{Fake, TestResult, FIDO};

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const SHORT: Duration = Duration::from_millis(10);

fn report(seed: u8) -> [u8; REPORT_BYTES] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

/// A transport over one end of a datagram pair, and the other end.
fn pair() -> Result<(HidrawTransport, UnixDatagram), Box<dyn std::error::Error>> {
    let (device, peer) = UnixDatagram::pair()?;
    Ok((HidrawTransport::from_fd(OwnedFd::from(device)), peer))
}

#[test]
fn an_output_report_is_written_with_the_report_id_byte() -> TestResult {
    let (mut transport, peer) = pair()?;
    let sent = report(7);
    assert_eq!(transport.write_report(&sent), Ok(()));
    let mut frame = [0; 128];
    assert_eq!(peer.recv(&mut frame)?, REPORT_BYTES + 1);
    assert_eq!(frame[0], 0);
    assert_eq!(frame[1..=REPORT_BYTES], sent);
    Ok(())
}

#[test]
fn a_write_to_a_removed_device_fails() -> TestResult {
    let (mut transport, peer) = pair()?;
    drop(peer);
    assert_eq!(transport.write_report(&report(1)), Err(TransportError));
    Ok(())
}

#[test]
fn a_wait_with_nothing_to_read_idles() -> TestResult {
    let (mut transport, _peer) = pair()?;
    let mut received = [0; REPORT_BYTES];
    assert_eq!(transport.read_report(&mut received, SHORT), Ok(false));
    assert_eq!(received, [0; REPORT_BYTES]);
    Ok(())
}

#[test]
fn an_input_report_is_read() -> TestResult {
    let (mut transport, peer) = pair()?;
    let sent = report(9);
    peer.send(&sent)?;
    let mut received = [0; REPORT_BYTES];
    assert_eq!(transport.read_report(&mut received, SHORT), Ok(true));
    assert_eq!(received, sent);
    Ok(())
}

#[test]
fn a_short_input_report_fails() -> TestResult {
    let (mut transport, peer) = pair()?;
    peer.send(&[1; 10])?;
    let mut received = [0; REPORT_BYTES];
    assert_eq!(
        transport.read_report(&mut received, SHORT),
        Err(TransportError)
    );
    Ok(())
}

#[test]
fn a_hung_up_device_fails_the_read() -> TestResult {
    let (device, peer) = UnixDatagram::pair()?;
    peer.send(&report(3))?;
    device.shutdown(std::net::Shutdown::Both)?;
    let mut transport = HidrawTransport::from_fd(OwnedFd::from(device));
    let mut received = [0; REPORT_BYTES];
    assert_eq!(
        transport.read_report(&mut received, SHORT),
        Err(TransportError)
    );
    Ok(())
}

#[test]
fn a_node_is_opened_and_a_missing_one_is_refused() {
    assert!(HidrawTransport::open_node(Path::new("/dev/null")).is_ok());
    assert_eq!(
        HidrawTransport::open_node(Path::new("/nonexistent/hidraw9")).err(),
        Some(TransportError)
    );
}

#[test]
fn exactly_one_fido_device_is_found_among_others() -> TestResult {
    let fake = Fake::new("one")?;
    fake.add("hidraw0", &[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0])?;
    fake.add("hidraw1", &FIDO)?;
    fake.add_without_descriptor("hidraw2")?;
    assert_eq!(
        discover(&fake.sysfs(), &fake.dev()),
        Ok(fake.node("hidraw1"))
    );
    assert!(HidrawTransport::open_in(&fake.sysfs(), &fake.dev()).is_ok());
    Ok(())
}

#[test]
fn a_descriptor_that_cannot_be_read_refuses_only_that_device() -> TestResult {
    let fake = Fake::new("unreadable")?;
    fake.add("hidraw0", &FIDO)?;
    // A directory where the descriptor file should be: reading it fails.
    fake.add_without_descriptor("hidraw1")?;
    std::fs::create_dir(fake.sysfs().join("hidraw1/device/report_descriptor"))?;
    fake.add("hidraw2", &[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0])?;
    assert_eq!(
        discover(&fake.sysfs(), &fake.dev()),
        Ok(fake.node("hidraw0"))
    );
    Ok(())
}

#[test]
fn a_sysfs_that_cannot_be_listed_is_refused() -> TestResult {
    let fake = Fake::new("unlistable")?;
    let file = fake.sysfs().join("not-a-directory");
    std::fs::write(&file, b"")?;
    assert_eq!(discover(&file, &fake.dev()), Err(CLIENT_FAILED));
    Ok(())
}

#[test]
fn no_fido_device_is_refused() -> TestResult {
    let fake = Fake::new("none")?;
    fake.add("hidraw0", &[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0])?;
    assert_eq!(discover(&fake.sysfs(), &fake.dev()), Err(CLIENT_FAILED));
    Ok(())
}

#[test]
fn two_fido_devices_are_refused() -> TestResult {
    let fake = Fake::new("two")?;
    fake.add("hidraw0", &FIDO)?;
    fake.add("hidraw1", &FIDO)?;
    assert_eq!(discover(&fake.sysfs(), &fake.dev()), Err(CLIENT_FAILED));
    assert_eq!(
        HidrawTransport::open_in(&fake.sysfs(), &fake.dev()).err(),
        Some(CLIENT_FAILED)
    );
    Ok(())
}

#[test]
fn a_missing_sysfs_is_refused() -> TestResult {
    let fake = Fake::new("missing")?;
    assert_eq!(
        discover(&fake.sysfs().join("absent"), &fake.dev()),
        Err(CLIENT_FAILED)
    );
    Ok(())
}

#[test]
fn a_node_that_cannot_be_opened_is_refused() -> TestResult {
    let fake = Fake::new("unopenable")?;
    fake.add("hidraw0", &FIDO)?;
    std::fs::remove_file(fake.node("hidraw0"))?;
    assert_eq!(
        HidrawTransport::open_in(&fake.sysfs(), &fake.dev()).err(),
        Some(CLIENT_FAILED)
    );
    Ok(())
}

#[test]
fn only_a_fido_application_collection_is_a_fido_descriptor() {
    assert!(is_fido_descriptor(&FIDO));
    // Other global items before the usage page do not matter.
    assert!(is_fido_descriptor(&[
        0x15, 0x00, 0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0xc0
    ]));
    let refused: [&[u8]; 8] = [
        // Usage 2 instead of 1.
        &[0x06, 0xd0, 0xf1, 0x09, 0x02, 0xa1, 0x01, 0xc0],
        // Another usage page.
        &[0x06, 0xd1, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0xc0],
        // A physical collection.
        &[0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x00, 0xc0],
        // A truncated item.
        &[0x06, 0xd0, 0xf1, 0x09],
        // No collection at all.
        &[0x06, 0xd0, 0xf1, 0x09, 0x01],
        // A long item.
        &[
            0xfe, 0x02, 0x01, 0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0xc0,
        ],
        // Empty.
        &[],
        // The collection comes before the usage.
        &[0xa1, 0x01, 0x06, 0xd0, 0xf1, 0x09, 0x01],
    ];
    for descriptor in refused {
        assert!(!is_fido_descriptor(descriptor));
    }
}
