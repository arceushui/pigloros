use std::cell::Cell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::{BridgeError, LifecycleCode, MonotonicClock, UnavailableCode};

use super::{
    Channel, HidTransport, TransportError, CMD_CANCEL, CMD_CBOR, CMD_ERROR, CMD_INIT,
    CMD_KEEPALIVE, MAX_MESSAGE_BYTES, REPORT_BYTES,
};

type Report = [u8; REPORT_BYTES];

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const TIMEOUT: BridgeError = BridgeError::Lifecycle(LifecycleCode::InteractionTimeout);
const CID: [u8; 4] = [0, 0, 0, 9];
const BROADCAST: [u8; 4] = [0xff; 4];

enum Read {
    Report(Report),
    Fail,
}

/// A device that plays back scripted reports and records what it was sent.
struct Scripted {
    reads: VecDeque<Read>,
    writes: Vec<Report>,
    writable: usize,
    clock: FakeClock,
}

impl Scripted {
    fn new(clock: &FakeClock, reports: Vec<Report>) -> Self {
        Self {
            reads: reports.into_iter().map(Read::Report).collect(),
            writes: Vec::new(),
            writable: usize::MAX,
            clock: clock.clone(),
        }
    }
}

impl HidTransport for Scripted {
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        if self.writes.len() == self.writable {
            return Err(TransportError);
        }
        self.writes.push(*report);
        Ok(())
    }

    fn read_report(
        &mut self,
        report: &mut Report,
        timeout: Duration,
    ) -> Result<bool, TransportError> {
        match self.reads.pop_front() {
            Some(Read::Report(next)) => {
                *report = next;
                Ok(true)
            }
            Some(Read::Fail) => Err(TransportError),
            None => {
                self.clock.advance(timeout);
                Ok(false)
            }
        }
    }
}

fn frames(cid: [u8; 4], command: u8, payload: &[u8]) -> Vec<Report> {
    let mut reports = Vec::new();
    let mut report = [0; REPORT_BYTES];
    report[..4].copy_from_slice(&cid);
    report[4] = command;
    report[5..7].copy_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    let first = payload.len().min(57);
    report[7..7 + first].copy_from_slice(&payload[..first]);
    reports.push(report);
    for (sequence, chunk) in (0..=u8::MAX).zip(payload[first..].chunks(59)) {
        let mut report = [0; REPORT_BYTES];
        report[..4].copy_from_slice(&cid);
        report[4] = sequence;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.push(report);
    }
    reports
}

fn nonce() -> [u8; 8] {
    std::array::from_fn(|index| u8::try_from(index).unwrap_or(0) + 0x30)
}

fn init_reply(nonce: [u8; 8], capabilities: u8) -> Vec<Report> {
    init_reply_on(nonce, CID, capabilities)
}

fn init_reply_on(nonce: [u8; 8], cid: [u8; 4], capabilities: u8) -> Vec<Report> {
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&cid);
    payload.extend_from_slice(&[2, 1, 0, 0, capabilities]);
    frames(BROADCAST, CMD_INIT, &payload)
}

fn payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// A clock that moves one millisecond every time it is read, on top of the shared fake clock, so
/// a loop that never reads the device still reaches the deadline instead of spinning.
struct Ticking {
    clock: FakeClock,
    reads: Cell<u32>,
}

impl Ticking {
    fn new(clock: &FakeClock) -> Self {
        Self {
            clock: clock.clone(),
            reads: Cell::new(0),
        }
    }
}

impl MonotonicClock for Ticking {
    fn now(&self) -> Instant {
        self.reads.set(self.reads.get() + 1);
        self.clock.now() + Duration::from_millis(u64::from(self.reads.get()))
    }
}

fn open(device: &mut Scripted, clock: &FakeClock) -> Result<[u8; 4], BridgeError> {
    let clock = Ticking::new(clock);
    let deadline = clock.now() + Duration::from_secs(10);
    Channel::open(device, &clock, deadline, nonce()).map(|channel| channel.cid)
}

fn transact(
    device: &mut Scripted,
    clock: &FakeClock,
    request: &[u8],
    limit: usize,
) -> Result<Vec<u8>, BridgeError> {
    let clock = Ticking::new(clock);
    let deadline = clock.now() + Duration::from_secs(10);
    Channel::open(device, &clock, deadline, nonce())
        .and_then(|mut channel| channel.transact(CMD_CBOR, request, limit))
}

#[test]
fn init_allocates_the_channel_from_the_matching_reply() {
    let clock = FakeClock::start();
    let mut device = Scripted::new(&clock, init_reply(nonce(), 0x0c));
    assert_eq!(open(&mut device, &clock), Ok(CID));
    let sent = device.writes[0];
    assert_eq!(sent[..7], [0xff, 0xff, 0xff, 0xff, CMD_INIT, 0, 8]);
    assert_eq!(sent[7..15], nonce());
}

#[test]
fn init_refuses_a_short_reply_and_a_device_without_cbor() {
    let clock = FakeClock::start();
    let short = frames(BROADCAST, CMD_INIT, &[nonce().as_slice(), &[0; 8]].concat());
    let mut device = Scripted::new(&clock, short);
    assert_eq!(open(&mut device, &clock), Err(CLIENT_FAILED));
    let mut device = Scripted::new(&clock, init_reply(nonce(), 0x08));
    let unsupported = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
    assert_eq!(open(&mut device, &clock), Err(unsupported));
}

#[test]
fn init_refuses_a_reserved_new_channel_id() {
    let clock = FakeClock::start();
    for reserved in [[0; 4], [0xff; 4]] {
        let mut device = Scripted::new(&clock, init_reply_on(nonce(), reserved, 0x0c));
        assert_eq!(open(&mut device, &clock), Err(CLIENT_FAILED));
    }
}

#[test]
fn init_skips_replies_to_another_nonce_and_never_cancels_the_broadcast() {
    let clock = FakeClock::start();
    let mut other = nonce();
    other[0] ^= 1;
    let mut reports = init_reply(other, 0x04);
    reports.extend(init_reply(nonce(), 0x04));
    let mut device = Scripted::new(&clock, reports);
    assert_eq!(open(&mut device, &clock), Ok(CID));

    let mut device = Scripted::new(&clock, init_reply(other, 0x04));
    assert_eq!(open(&mut device, &clock), Err(TIMEOUT));
    assert_eq!(device.writes.len(), 1);
}

#[test]
fn init_gives_up_at_the_deadline_between_replies_to_another_nonce() {
    let clock = FakeClock::start();
    let mut other = nonce();
    other[0] ^= 1;
    let mut device = Scripted::new(&clock, init_reply(other, 0x04));
    let ticking = Ticking::new(&clock);
    let deadline = ticking.now() + Duration::from_millis(2);
    assert_eq!(
        Channel::open(&mut device, &ticking, deadline, nonce()).map(|_| ()),
        Err(TIMEOUT)
    );
    assert_eq!(device.writes.len(), 1);
    assert_eq!(device.reads.len(), 1);
}

#[test]
fn nothing_is_sent_once_the_deadline_has_passed() {
    let clock = FakeClock::start();
    let mut device = Scripted::new(&clock, init_reply(nonce(), 0x04));
    let ticking = Ticking::new(&clock);
    let deadline = ticking.now() + Duration::from_secs(10);
    let opened = Channel::open(&mut device, &ticking, deadline, nonce()).map(|mut channel| {
        clock.advance(Duration::from_secs(10));
        channel.transact(CMD_CBOR, &[4], 100)
    });
    assert_eq!(opened, Ok(Err(TIMEOUT)));
    assert_eq!(device.writes.len(), 1);
    let mut late = Scripted::new(&clock, init_reply(nonce(), 0x04));
    assert_eq!(
        Channel::open(&mut late, &ticking, deadline, nonce()).map(|_| ()),
        Err(TIMEOUT)
    );
    assert!(late.writes.is_empty());
}

#[test]
fn long_messages_are_split_and_reassembled_in_sequence() {
    let clock = FakeClock::start();
    let request = payload(200);
    let response = payload(MAX_MESSAGE_BYTES);
    let mut reports = init_reply(nonce(), 0x04);
    reports.extend(frames(CID, CMD_CBOR, &response));
    let mut device = Scripted::new(&clock, reports);
    assert_eq!(
        transact(&mut device, &clock, &request, MAX_MESSAGE_BYTES),
        Ok(response)
    );
    let written = &device.writes[1..];
    assert_eq!(written, frames(CID, CMD_CBOR, &request));
}

#[test]
fn keep_alives_and_other_channels_are_skipped() {
    let clock = FakeClock::start();
    let response = payload(100);
    let mut framed = frames(CID, CMD_CBOR, &response);
    let mut reports = init_reply(nonce(), 0x04);
    reports.extend(frames([1, 2, 3, 4], CMD_CBOR, &[1]));
    reports.extend(frames(CID, CMD_KEEPALIVE, &[2]));
    reports.push(framed.remove(0));
    reports.extend(frames([1, 2, 3, 4], CMD_KEEPALIVE, &[1]));
    reports.extend(framed);
    let mut device = Scripted::new(&clock, reports);
    assert_eq!(transact(&mut device, &clock, &[4], 1_000), Ok(response));
}

#[test]
fn misframed_or_oversized_replies_fail_the_client() {
    let clock = FakeClock::start();
    let mut wrong_sequence = frames(CID, CMD_CBOR, &payload(100));
    wrong_sequence[1][4] = 1;
    let replies = [
        frames(CID, CMD_ERROR, &[0x06]),
        frames(CID, CMD_INIT, &[0; 17]),
        frames(CID, CMD_CBOR, &payload(101)),
        wrong_sequence,
    ];
    for reply in replies {
        let mut reports = init_reply(nonce(), 0x04);
        reports.extend(reply);
        let mut device = Scripted::new(&clock, reports);
        assert_eq!(transact(&mut device, &clock, &[4], 100), Err(CLIENT_FAILED));
    }
    let mut reports = init_reply(nonce(), 0x04);
    reports.extend(frames(CID, CMD_CBOR, &payload(MAX_MESSAGE_BYTES + 1)));
    let mut device = Scripted::new(&clock, reports);
    let result = transact(&mut device, &clock, &[4], usize::MAX);
    assert_eq!(result, Err(CLIENT_FAILED));
}

#[test]
fn a_request_over_the_limit_is_never_sent() {
    let clock = FakeClock::start();
    for (length, limit) in [
        (101, 100),
        (MAX_MESSAGE_BYTES + 1, usize::MAX),
        (70_000, usize::MAX),
    ] {
        let mut device = Scripted::new(&clock, init_reply(nonce(), 0x04));
        assert_eq!(
            transact(&mut device, &clock, &payload(length), limit),
            Err(CLIENT_FAILED)
        );
        assert_eq!(device.writes.len(), 1);
    }
    let mut reports = init_reply(nonce(), 0x04);
    reports.extend(frames(CID, CMD_CBOR, &[9]));
    let mut device = Scripted::new(&clock, reports);
    assert_eq!(
        transact(&mut device, &clock, &payload(100), 100),
        Ok(vec![9])
    );
}

#[test]
fn the_deadline_cancels_the_request() {
    let clock = FakeClock::start();
    let mut device = Scripted::new(&clock, init_reply(nonce(), 0x04));
    let started = clock.now();
    assert_eq!(transact(&mut device, &clock, &[4], 100), Err(TIMEOUT));
    let elapsed = clock.now() - started;
    assert!(elapsed > Duration::from_millis(9_900) && elapsed <= Duration::from_secs(10));
    let cancel = device.writes[2];
    assert_eq!(cancel[..7], [0, 0, 0, 9, CMD_CANCEL, 0, 0]);

    let mut device = Scripted::new(&clock, init_reply(nonce(), 0x04));
    device.writable = 2;
    assert_eq!(transact(&mut device, &clock, &[4], 100), Err(CLIENT_FAILED));
}

#[test]
fn the_deadline_also_bounds_a_reply_cut_short() {
    let clock = FakeClock::start();
    let mut reports = init_reply(nonce(), 0x04);
    reports.push(frames(CID, CMD_CBOR, &payload(100))[0]);
    let mut device = Scripted::new(&clock, reports);
    assert_eq!(transact(&mut device, &clock, &[4], 1_000), Err(TIMEOUT));
}

#[test]
fn transport_failures_fail_the_client() {
    let clock = FakeClock::start();
    let mut device = Scripted::new(&clock, Vec::new());
    device.writable = 0;
    assert_eq!(open(&mut device, &clock), Err(CLIENT_FAILED));

    for writable in [1, 2] {
        let mut device = Scripted::new(&clock, init_reply(nonce(), 0x04));
        device.writable = writable;
        assert_eq!(
            transact(&mut device, &clock, &payload(100), 1_000),
            Err(CLIENT_FAILED)
        );
    }

    let mut device = Scripted::new(&clock, init_reply(nonce(), 0x04));
    device.reads.push_back(Read::Fail);
    assert_eq!(transact(&mut device, &clock, &[4], 100), Err(CLIENT_FAILED));
}
