//! The virtual FIDO device of the ADR-110 E20 U-tier (Redmine #1476).
//!
//! It creates `--devices` kernel `uhid` devices with the FIDO report descriptor (usage page
//! `0xF1D0`, usage `0x01`), each backed by a `SoftAuthenticator` with the PIN `--pin` behind a
//! `MemoryHid`, and then serves them: every 64-byte output report the kernel hands over is fed
//! to the in-memory CTAPHID device, and every reply report goes back as an input report. After
//! the devices exist it creates the `--ready` file, and it serves until the `--stop` file exists.
//! Closing the devices on exit destroys them, so a test can also unplug a device by creating the
//! stop file. Only the setup that runs this binary uses `sudo` (`/dev/uhid` is root only).
//!
//! It is test support and never deployable. A kernel without the `uhid` module refuses it, and
//! on a platform other than Linux it does nothing.

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use pos_owner_bridge::fake::clock::FakeClock;
#[cfg(target_os = "linux")]
use pos_owner_ctap::fdwait::{wait_readable, Wait};
#[cfg(target_os = "linux")]
use pos_owner_ctap::{HidTransport, MemoryHid, SoftAuthenticator};
#[cfg(target_os = "linux")]
use rustix::fs::{open, Mode, OFlags};
#[cfg(target_os = "linux")]
use rustix::io::{read, write};

#[cfg(target_os = "linux")]
const UHID_OUTPUT: u32 = 6;
#[cfg(target_os = "linux")]
const UHID_CREATE2: u32 = 11;
#[cfg(target_os = "linux")]
const UHID_INPUT2: u32 = 12;
#[cfg(target_os = "linux")]
const BUS_USB: u16 = 0x03;
#[cfg(target_os = "linux")]
const VENDOR: u32 = 0x1209;
#[cfg(target_os = "linux")]
const DATA_MAX: usize = 4096;
#[cfg(target_os = "linux")]
const EVENT_BYTES: usize = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + DATA_MAX;
#[cfg(target_os = "linux")]
const DESCRIPTOR_OFFSET: usize = EVENT_BYTES - DATA_MAX;
#[cfg(target_os = "linux")]
const REPORT_BYTES: usize = 64;

/// The CTAPHID report descriptor: one 64-byte input and one 64-byte output report on usage page
/// `0xF1D0`, usage `0x01`.
#[cfg(target_os = "linux")]
const FIDO_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

#[cfg(target_os = "linux")]
struct Options {
    ready: PathBuf,
    stop: PathBuf,
    pin: String,
    devices: usize,
}

#[cfg(target_os = "linux")]
struct Virtual {
    fd: OwnedFd,
    hid: MemoryHid,
}

#[cfg(target_os = "linux")]
fn options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let (mut ready, mut stop, mut pin, mut devices) = (None, None, None, 1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--ready" => ready = Some(PathBuf::from(value)),
            "--stop" => stop = Some(PathBuf::from(value)),
            "--pin" => pin = Some(value),
            "--devices" => {
                devices = value
                    .parse()
                    .ok()
                    .filter(|count| *count > 0)
                    .ok_or("--devices needs a positive number")?;
            }
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(Options {
        ready: ready.ok_or("--ready is required")?,
        stop: stop.ok_or("--stop is required")?,
        pin: pin.ok_or("--pin is required")?,
        devices,
    })
}

/// A `UHID_CREATE2` event for the virtual device number `index`.
#[cfg(target_os = "linux")]
fn create2(index: usize) -> Vec<u8> {
    let mut event = vec![0; EVENT_BYTES];
    event[..4].copy_from_slice(&UHID_CREATE2.to_le_bytes());
    let name = format!("pigloros-owner-ctap-{index}");
    event[4..4 + name.len()].copy_from_slice(name.as_bytes());
    let size = u16::try_from(FIDO_DESCRIPTOR.len()).unwrap_or(0);
    event[260..262].copy_from_slice(&size.to_le_bytes());
    event[262..264].copy_from_slice(&BUS_USB.to_le_bytes());
    event[264..268].copy_from_slice(&VENDOR.to_le_bytes());
    event[268..272].copy_from_slice(&1_u32.to_le_bytes());
    event[DESCRIPTOR_OFFSET..DESCRIPTOR_OFFSET + FIDO_DESCRIPTOR.len()]
        .copy_from_slice(&FIDO_DESCRIPTOR);
    event
}

/// A `UHID_INPUT2` event carrying one input `report`.
#[cfg(target_os = "linux")]
fn input2(report: &[u8; REPORT_BYTES]) -> Vec<u8> {
    let mut event = vec![0; EVENT_BYTES];
    event[..4].copy_from_slice(&UHID_INPUT2.to_le_bytes());
    let size = u16::try_from(REPORT_BYTES).unwrap_or(0);
    event[4..6].copy_from_slice(&size.to_le_bytes());
    event[6..6 + REPORT_BYTES].copy_from_slice(report);
    event
}

#[cfg(target_os = "linux")]
fn send(device: &Virtual, event: &[u8]) -> Result<(), String> {
    match write(&device.fd, event) {
        Ok(written) if written == event.len() => Ok(()),
        other => Err(format!("uhid write failed: {other:?}")),
    }
}

/// Feed one kernel event to the device. Only `UHID_OUTPUT` carries a CTAPHID report: the hidraw
/// write is the report ID byte `0` and the 64-byte report.
#[cfg(target_os = "linux")]
fn serve(device: &mut Virtual, event: &[u8]) -> Result<(), String> {
    if event[..4] != UHID_OUTPUT.to_le_bytes() {
        return Ok(());
    }
    let size = usize::from(u16::from_le_bytes([
        event[4 + DATA_MAX],
        event[5 + DATA_MAX],
    ]));
    let data = &event[4..4 + size.min(DATA_MAX)];
    let payload = match size {
        65 => &data[1..],
        64 => data,
        _ => return Ok(()),
    };
    let mut report = [0; REPORT_BYTES];
    report.copy_from_slice(payload);
    device
        .hid
        .write_report(&report)
        .map_err(|_| "the in-memory device refused a report".to_owned())?;
    let mut reply = [0; REPORT_BYTES];
    while device
        .hid
        .read_report(&mut reply, Duration::ZERO)
        .map_err(|_| "the in-memory device failed a read".to_owned())?
    {
        send(device, &input2(&reply))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), String> {
    let options = options()?;
    let mut devices = Vec::new();
    for index in 0..options.devices {
        let fd = open(
            "/dev/uhid",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| format!("cannot open /dev/uhid: {error}"))?;
        let soft = SoftAuthenticator::new(&format!("uhid-{index}"), options.pin.as_bytes(), false);
        let device = Virtual {
            fd,
            hid: MemoryHid::new(soft, FakeClock::start()),
        };
        send(&device, &create2(index))?;
        devices.push(device);
    }
    std::fs::write(&options.ready, b"ready").map_err(|error| format!("ready file: {error}"))?;
    let mut event = vec![0; EVENT_BYTES];
    while !options.stop.exists() {
        for device in &mut devices {
            if wait_readable(&device.fd, Duration::from_millis(50)) == Wait::Readable {
                let received = read(&device.fd, &mut event[..])
                    .map_err(|error| format!("uhid read failed: {error}"))?;
                if received == EVENT_BYTES {
                    serve(device, &event)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
