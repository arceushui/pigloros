//! `MemoryHid`: the in-memory CTAPHID device side of a [`SoftAuthenticator`] (ADR-110 E20 LG).
//!
//! It reassembles output reports into messages, answers `CTAPHID_INIT` and `CTAPHID_CBOR`
//! (sending one keep-alive before each CBOR reply), records `CTAPHID_CANCEL`, and frames replies
//! into input reports. A test may replace the reply to any CBOR request that starts with a given
//! prefix, once. When no report is waiting, a read lets the whole timeout pass on the fake clock.
//! It is test support and never deployable.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use pos_owner_bridge::fake::clock::FakeClock;

use crate::hid::{
    HidTransport, TransportError, CMD_CANCEL, CMD_CBOR, CMD_INIT, CMD_KEEPALIVE, REPORT_BYTES,
};
use crate::soft::SoftAuthenticator;

const INIT_DATA: usize = REPORT_BYTES - 7;
const CONT_DATA: usize = REPORT_BYTES - 5;
const CAPABILITIES: u8 = 0x0c;
const KEEPALIVE_UP_NEEDED: u8 = 0x02;

struct Device {
    authenticator: SoftAuthenticator,
    clock: FakeClock,
    next_cid: u32,
    message: Option<(u8, usize, Vec<u8>)>,
    replies: VecDeque<[u8; REPORT_BYTES]>,
    overrides: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    requests: Vec<Vec<u8>>,
    cancels: usize,
}

/// A shared in-memory FIDO HID device; clones share one device.
#[derive(Clone)]
pub struct MemoryHid(Rc<RefCell<Device>>);

impl MemoryHid {
    /// A device for `authenticator` on the fake `clock`.
    #[must_use]
    pub fn new(authenticator: SoftAuthenticator, clock: FakeClock) -> Self {
        Self(Rc::new(RefCell::new(Device {
            authenticator,
            clock,
            next_cid: 1,
            message: None,
            replies: VecDeque::new(),
            overrides: Vec::new(),
            requests: Vec::new(),
            cancels: 0,
        })))
    }

    /// Run `inspect` on the authenticator.
    pub fn with_authenticator<T>(&self, inspect: impl FnOnce(&mut SoftAuthenticator) -> T) -> T {
        inspect(&mut self.0.borrow_mut().authenticator)
    }

    /// Answer the next CBOR request that starts with `prefix` with the raw `reply`.
    ///
    /// The reply is the status byte and body sent instead of the authenticator's.
    pub fn override_reply(&self, prefix: &[u8], reply: &[u8]) {
        self.0
            .borrow_mut()
            .overrides
            .push((prefix.to_vec(), Some(reply.to_vec())));
    }

    /// Never answer the next CBOR request that starts with `prefix`.
    ///
    /// The client then reaches its deadline.
    pub fn drop_reply(&self, prefix: &[u8]) {
        self.0.borrow_mut().overrides.push((prefix.to_vec(), None));
    }

    /// Every CBOR request received so far, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.0.borrow().requests.clone()
    }

    /// How many `CTAPHID_CANCEL` messages arrived.
    #[must_use]
    pub fn cancels(&self) -> usize {
        self.0.borrow().cancels
    }
}

impl Device {
    fn frame(&mut self, cid: [u8; 4], command: u8, payload: &[u8]) {
        let (first, rest) = payload.split_at(payload.len().min(INIT_DATA));
        let mut report = [0; REPORT_BYTES];
        report[..4].copy_from_slice(&cid);
        report[4] = command;
        report[5..7].copy_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
        report[7..7 + first.len()].copy_from_slice(first);
        self.replies.push_back(report);
        for (sequence, chunk) in (0..=u8::MAX).zip(rest.chunks(CONT_DATA)) {
            let mut report = [0; REPORT_BYTES];
            report[..4].copy_from_slice(&cid);
            report[4] = sequence;
            report[5..5 + chunk.len()].copy_from_slice(chunk);
            self.replies.push_back(report);
        }
    }

    fn receive(&mut self, report: &[u8; REPORT_BYTES]) {
        let mut cid = [0; 4];
        cid.copy_from_slice(&report[..4]);
        let (command, length, mut data) = self.message.take().map_or_else(
            || {
                let length = usize::from(u16::from_be_bytes([report[5], report[6]]));
                (report[4], length, report[7..].to_vec())
            },
            |(command, length, mut data)| {
                data.extend_from_slice(&report[5..]);
                (command, length, data)
            },
        );
        if data.len() < length {
            self.message = Some((command, length, data));
            return;
        }
        data.truncate(length);
        self.dispatch(cid, command, &data);
    }

    fn dispatch(&mut self, cid: [u8; 4], command: u8, message: &[u8]) {
        match command {
            CMD_INIT => {
                let mut reply = message.to_vec();
                reply.extend_from_slice(&self.next_cid.to_be_bytes());
                reply.extend_from_slice(&[2, 1, 0, 0, CAPABILITIES]);
                self.next_cid += 1;
                self.frame(cid, CMD_INIT, &reply);
            }
            CMD_CBOR => {
                self.requests.push(message.to_vec());
                let reply = self
                    .overrides
                    .iter()
                    .position(|(prefix, _)| message.starts_with(prefix))
                    .map_or_else(
                        || Some(self.authenticator.process(message)),
                        |index| self.overrides.remove(index).1,
                    );
                if let Some(reply) = reply {
                    self.frame(cid, CMD_KEEPALIVE, &[KEEPALIVE_UP_NEEDED]);
                    self.frame(cid, CMD_CBOR, &reply);
                }
            }
            _ => self.cancels += usize::from(command == CMD_CANCEL),
        }
    }
}

impl HidTransport for MemoryHid {
    fn write_report(&mut self, report: &[u8; REPORT_BYTES]) -> Result<(), TransportError> {
        self.0.borrow_mut().receive(report);
        Ok(())
    }

    fn read_report(
        &mut self,
        report: &mut [u8; REPORT_BYTES],
        timeout: Duration,
    ) -> Result<bool, TransportError> {
        let mut device = self.0.borrow_mut();
        if let Some(next) = device.replies.pop_front() {
            *report = next;
            return Ok(true);
        }
        device.clock.advance(timeout);
        Ok(false)
    }
}
