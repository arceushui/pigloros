#![cfg(target_os = "linux")]
//! Tests of the ADR-110 E20 Linux adapters (Redmine #1476, slice S2).
//!
//! The P-tier tests run in every hosted test job: the hidraw transport over datagram pairs and a
//! temporary sysfs, the terminal prompt over pseudo-terminals, and the process hardening. The
//! U-tier tests (`uhid`) run only in the owner U-tier job, which sets `OWNER_CTAP_UHID` to the
//! scenario its kernel `uhid` device was prepared for; everywhere else they return at once.

mod harden;
mod hidraw;
mod tty;
mod uhid;

use std::cell::Cell;
use std::error::Error;
use std::fmt::Display;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::{
    BridgeError, MonotonicClock, OwnerAuthenticatorPort, ReplyImage, RequestImage,
};
use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, encode_create_options, encode_get_options,
    verify_assertion_reply, verify_attestation_reply, AssertionVerificationContext, CeremonyId,
    CeremonyKind, CreateOptionsV1, CreateVerificationContext, GetOptionsV1, OwnerBridgeControlV1,
    OwnerUserHandle, PrfInput, StoredCredential, WebAuthnChallenge, CONTROL_HEADER_BYTES,
};
use pos_owner_ctap::fdwait::{wait_readable, Wait};
use pos_owner_ctap::{Drbg, PinBuffer, PinPrompt, TtyPrompt};
use rustix::fs::{openat, Mode, OFlags, CWD};
use rustix::io::{read, write};
use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
use rustix::termios::{tcgetattr, LocalModes};

type TestResult = Result<(), Box<dyn Error>>;

/// The prompt text that ends the line a user answers.
const PROMPT: &[u8] = b"attempts left): ";

/// The PIN every software authenticator of these tests has.
const PIN: &[u8] = b"2468";

/// The FIDO report descriptor: usage page `0xF1D0`, usage `0x01`, one 64-byte report each way.
const FIDO: [u8; 34] = [
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

/// Whether `haystack` holds `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A temporary directory with a fake `sysfs` and `dev` inside, removed on drop.
struct Fake(PathBuf);

impl Fake {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pos-owner-ctap-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(path.join("sys"))?;
        std::fs::create_dir_all(path.join("dev"))?;
        Ok(Self(path))
    }

    fn sysfs(&self) -> PathBuf {
        self.0.join("sys")
    }

    fn dev(&self) -> PathBuf {
        self.0.join("dev")
    }

    /// Add the device `name`: its report descriptor in the sysfs and an empty regular file as its
    /// node.
    fn add(&self, name: &str, descriptor: &[u8]) -> TestResult {
        let device = self.sysfs().join(name).join("device");
        std::fs::create_dir_all(&device)?;
        std::fs::write(device.join("report_descriptor"), descriptor)?;
        std::fs::write(self.dev().join(name), b"")?;
        Ok(())
    }

    /// Add the device `name` with a sysfs entry but no readable report descriptor.
    fn add_without_descriptor(&self, name: &str) -> TestResult {
        Ok(std::fs::create_dir_all(
            self.sysfs().join(name).join("device"),
        )?)
    }

    fn node(&self, name: &str) -> PathBuf {
        self.dev().join(name)
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A pseudo-terminal: the master is the user's side, the slave the owner's terminal.
struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}

fn pty() -> Result<Pty, Box<dyn Error>> {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let name = ptsname(&master, Vec::new())?;
    let slave = openat(
        CWD,
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(Pty { master, slave })
}

/// A clock on the fake clock that moves `step` every time it is read, so a loop that never
/// reaches the device still reaches its deadline instead of spinning.
struct Ticking {
    clock: FakeClock,
    step: Duration,
    reads: Cell<u32>,
}

impl Ticking {
    const fn new(clock: FakeClock, step: Duration) -> Self {
        Self {
            clock,
            step,
            reads: Cell::new(0),
        }
    }
}

impl MonotonicClock for Ticking {
    fn now(&self) -> Instant {
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        self.clock.now() + self.step * reads
    }
}

/// The user at the terminal: it reads what the owner shows and types what it is asked.
struct User<'a> {
    master: &'a OwnedFd,
    seen: Vec<u8>,
    cursor: usize,
}

impl<'a> User<'a> {
    const fn new(master: &'a OwnedFd) -> Self {
        Self {
            master,
            seen: Vec::new(),
            cursor: 0,
        }
    }

    fn seen(&self) -> &[u8] {
        &self.seen
    }

    /// Read what is on the terminal within `wait`, and say whether the terminal is still there.
    fn pull(&mut self, wait: Duration) -> bool {
        if wait_readable(self.master, wait) == Wait::Idle {
            return true;
        }
        let mut chunk = [0; 256];
        let got = read(self.master, &mut chunk[..]).unwrap_or(0);
        self.seen.extend_from_slice(&chunk[..got]);
        got > 0
    }

    /// Wait until `marker` shows up in output not matched before.
    fn wait_for(&mut self, marker: &[u8]) -> Result<(), String> {
        let limit = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(at) = self.seen[self.cursor..]
                .windows(marker.len())
                .position(|window| window == marker)
            {
                self.cursor += at + marker.len();
                return Ok(());
            }
            if Instant::now() >= limit || !self.pull(Duration::from_millis(20)) {
                return Err("the expected prompt text never appeared".to_owned());
            }
        }
    }

    /// Type `bytes`.
    fn type_line(&self, bytes: &[u8]) -> Result<(), String> {
        match write(self.master, bytes) {
            Ok(written) if written == bytes.len() => Ok(()),
            other => Err(format!("typing failed: {other:?}")),
        }
    }

    /// Read until the terminal is gone or five seconds pass.
    fn finish(&mut self) {
        let limit = Instant::now() + Duration::from_secs(5);
        while Instant::now() < limit && self.pull(Duration::from_millis(20)) {}
    }
}

/// What one prompt run did.
struct Run {
    result: Result<(), BridgeError>,
    output: Vec<u8>,
    before: LocalModes,
    after: LocalModes,
}

/// Run one `read_pin` with a ticking clock of `step` and a deadline `limit` away, while `script`
/// plays the user, and report the result, the output and the terminal's local modes before and
/// after.
fn run_prompt(
    step: Duration,
    limit: Duration,
    script: impl FnOnce(&mut User<'_>) -> Result<(), String> + Send,
) -> Result<Run, Box<dyn Error>> {
    let Pty { master, slave } = pty()?;
    let mut prompt = TtyPrompt::new(slave)?;
    let before = tcgetattr(&master)?.local_modes;
    let clock = Ticking::new(FakeClock::start(), step);
    let deadline = clock.now() + limit;
    let mut pin = PinBuffer::new();
    std::thread::scope(|scope| {
        let user = scope.spawn(|| {
            let mut user = User::new(&master);
            let played = script(&mut user);
            user.finish();
            played.map(|()| user.seen)
        });
        let result = prompt.read_pin(4, &mut pin, deadline, &clock);
        let after = tcgetattr(&master).map(|modes| modes.local_modes);
        drop(prompt);
        let output = user
            .join()
            .map_err(|_| "the user thread panicked".to_owned())??;
        Ok(Run {
            result,
            output,
            before,
            after: after?,
        })
    })
}

/// Make a codec or verifier failure usable with `?`.
fn text<T, E: Display>(result: Result<T, E>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

/// One ceremony's host-drawn values, derived from a label.
struct Ceremony {
    id: CeremonyId,
    challenge: WebAuthnChallenge,
    user: OwnerUserHandle,
    prf: PrfInput,
}

impl Ceremony {
    fn drawn(label: &str) -> Self {
        let mut drbg = Drbg::new(label);
        let mut id = [0; 16];
        id.copy_from_slice(&drbg.draw()[..16]);
        Self {
            id: CeremonyId::from_bytes(id),
            challenge: WebAuthnChallenge::from_bytes(drbg.draw()),
            user: OwnerUserHandle::from_bytes(drbg.draw()),
            prf: PrfInput::from_bytes(drbg.draw()),
        }
    }

    fn image(
        &self,
        kind: CeremonyKind,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, String>,
    ) -> Result<RequestImage, String> {
        let mut image = RequestImage::zeroed();
        let (header, payload) = image.as_mut_bytes().split_at_mut(CONTROL_HEADER_BYTES);
        let length = encode(payload)?;
        let length = text(u32::try_from(length))?;
        let request = text(OwnerBridgeControlV1::new_request(kind, 1, self.id, length))?;
        header.copy_from_slice(&request.encode());
        Ok(image)
    }
}

fn perform(
    port: &mut dyn OwnerAuthenticatorPort,
    clock: &dyn MonotonicClock,
    request: &RequestImage,
    kind: CeremonyKind,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut reply = ReplyImage::zeroed();
    reply.select(kind);
    let deadline = clock.now() + Duration::from_mins(2);
    let length = port.perform(request, &mut reply, deadline, clock)?;
    Ok(reply.as_bytes()[..length].to_vec())
}

/// Enroll one credential, then unlock with it `gets` times, and return each verified PRF output.
///
/// Every unlock uses the enrollment's PRF input, so the outputs must be equal. The port is
/// asked for one PIN or user-verification entry per ceremony.
fn enroll_and_unlock(
    port: &mut dyn OwnerAuthenticatorPort,
    clock: &dyn MonotonicClock,
    gets: usize,
) -> Result<Vec<[u8; 32]>, Box<dyn Error>> {
    let create = Ceremony::drawn("create");
    let options = CreateOptionsV1::new(create.id, create.challenge, create.user, create.prf);
    let request = create.image(CeremonyKind::Create, |payload| {
        text(encode_create_options(&options, payload))
    })?;
    let payload = perform(port, clock, &request, CeremonyKind::Create)?;
    let reply = text(decode_attestation_reply(&payload))?;
    let context = CreateVerificationContext::new(create.id, create.challenge);
    let enrolled = text(verify_attestation_reply(&reply, context))?;
    assert!(reply.prf_enabled());
    assert_eq!(enrolled.transports().as_slice(), [0]);

    let mut outputs = Vec::new();
    for round in 0..gets {
        let get = Ceremony {
            prf: create.prf,
            ..Ceremony::drawn(&format!("get-{round}"))
        };
        let options = text(GetOptionsV1::new(
            get.id,
            get.challenge,
            enrolled.credential_id(),
            get.prf,
        ))?;
        let request = get.image(CeremonyKind::Get, |payload| {
            text(encode_get_options(&options, payload))
        })?;
        let payload = perform(port, clock, &request, CeremonyKind::Get)?;
        let reply = text(decode_assertion_reply(&payload))?;
        let stored = text(StoredCredential::new(
            enrolled.credential_id(),
            create.user,
            enrolled.public_key(),
            false,
            false,
            enrolled.sign_count(),
        ))?;
        let context = AssertionVerificationContext::new(get.id, get.challenge, stored);
        let verified = text(verify_assertion_reply(&reply, context))?;
        outputs.push(*verified.prf_first().as_bytes());
    }
    Ok(outputs)
}
