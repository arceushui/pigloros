//! CTAPHID framing over a [`HidTransport`] (CTAP 2.1 PS §11.2; ADR-110 E20 LS2, LT6).
//!
//! A message is one initialization packet (channel, command, 16-bit length, 57 data bytes) and
//! up to 128 continuation packets (channel, sequence, 59 data bytes), so no message exceeds
//! [`MAX_MESSAGE_BYTES`]. Reassembly is bounded by the authenticator's `maxMsgSize` and that hard
//! cap. Packets of other channels, and `CTAPHID_INIT` replies to another client's nonce, are
//! ignored. Keep-alives are skipped but never extend the ceremony deadline. No message is sent
//! once the deadline has passed, and a request still outstanding at the deadline is cancelled
//! with `CTAPHID_CANCEL` on its channel (ADR-110 E20 LS3); the broadcast `CTAPHID_INIT` is never
//! cancelled.

use std::time::{Duration, Instant};

use pos_owner_bridge::{BridgeError, LifecycleCode, MonotonicClock, UnavailableCode};

/// The size of one HID report, without the report ID.
pub const REPORT_BYTES: usize = 64;

/// The largest CTAPHID message: 57 bytes in the first packet and 59 in each of 128 more.
///
/// ADR-110 E20 LT6 makes this the hard cap on reassembly, and the limit for an authenticator
/// whose `authenticatorGetInfo` names no `maxMsgSize`.
pub const MAX_MESSAGE_BYTES: usize = 7_609;

const INIT_DATA: usize = REPORT_BYTES - 7;
const CONT_DATA: usize = REPORT_BYTES - 5;
const BROADCAST: [u8; 4] = [0xff; 4];
const INIT_REPLY_BYTES: usize = 17;
const CAPABILITY_CBOR: u8 = 0x04;

/// `CTAPHID_INIT`.
pub const CMD_INIT: u8 = 0x86;
/// `CTAPHID_CBOR`.
pub const CMD_CBOR: u8 = 0x90;
/// `CTAPHID_CANCEL`.
pub const CMD_CANCEL: u8 = 0x91;
/// `CTAPHID_KEEPALIVE`.
pub const CMD_KEEPALIVE: u8 = 0xbb;
/// `CTAPHID_ERROR`.
pub const CMD_ERROR: u8 = 0xbf;

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const TIMEOUT: BridgeError = BridgeError::Lifecycle(LifecycleCode::InteractionTimeout);

/// A transport failure, such as a removed device. It carries no detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportError;

impl From<TransportError> for BridgeError {
    /// A transport failure is `Lifecycle(ClientFailed)` (ADR-110 E20 LS7).
    fn from(_: TransportError) -> Self {
        CLIENT_FAILED
    }
}

/// One FIDO HID device: 64-byte output and input reports.
///
/// The Linux hidraw implementation is ADR-110 E20 S2; tests use an in-memory device.
pub trait HidTransport {
    /// Write one output report. The transport adds the report ID.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when the report cannot be written.
    fn write_report(&mut self, report: &[u8; REPORT_BYTES]) -> Result<(), TransportError>;

    /// Wait at most `timeout` for one input report and return whether one arrived.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when the device cannot be read.
    fn read_report(
        &mut self,
        report: &mut [u8; REPORT_BYTES],
        timeout: Duration,
    ) -> Result<bool, TransportError>;
}

/// A CTAPHID channel bound to one ceremony's deadline.
pub struct Channel<'a> {
    transport: &'a mut dyn HidTransport,
    clock: &'a dyn MonotonicClock,
    deadline: Instant,
    cid: [u8; 4],
}

impl<'a> Channel<'a> {
    /// Allocate a channel with `CTAPHID_INIT` and the 8-byte `nonce`.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for a transport or framing failure or a reserved new
    /// channel id (all zeros or all ones), `Lifecycle(InteractionTimeout)` at `deadline`, and
    /// `Unavailable(PrfUnsupported)` for a device without the CBOR capability.
    pub fn open(
        transport: &'a mut dyn HidTransport,
        clock: &'a dyn MonotonicClock,
        deadline: Instant,
        nonce: [u8; 8],
    ) -> Result<Self, BridgeError> {
        let mut channel = Self {
            transport,
            clock,
            deadline,
            cid: BROADCAST,
        };
        channel.send(CMD_INIT, &nonce, MAX_MESSAGE_BYTES)?;
        let reply = loop {
            if channel.remaining().is_zero() {
                return Err(TIMEOUT);
            }
            let reply = channel.receive(CMD_INIT, MAX_MESSAGE_BYTES)?;
            if reply.starts_with(&nonce) {
                break reply;
            }
        };
        let reply = reply.get(..INIT_REPLY_BYTES).ok_or(CLIENT_FAILED)?;
        if reply[16] & CAPABILITY_CBOR == 0 {
            return Err(BridgeError::Unavailable(UnavailableCode::PrfUnsupported));
        }
        channel.cid.copy_from_slice(&reply[8..12]);
        if channel.cid == BROADCAST || channel.cid == [0; 4] {
            return Err(CLIENT_FAILED);
        }
        Ok(channel)
    }

    /// Send `payload` as one `command` message and return the reply payload.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` when either message exceeds `limit`, the transport
    /// fails, the device reports `CTAPHID_ERROR` or the reply is misframed, and
    /// `Lifecycle(InteractionTimeout)` once the deadline passes: nothing is sent after it, and a
    /// request still outstanding at it is cancelled.
    pub fn transact(
        &mut self,
        command: u8,
        payload: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, BridgeError> {
        self.send(command, payload, limit)?;
        self.receive(command, limit)
    }

    fn send(&mut self, command: u8, payload: &[u8], limit: usize) -> Result<(), BridgeError> {
        if self.remaining().is_zero() {
            return Err(TIMEOUT);
        }
        let length = u16::try_from(payload.len())
            .ok()
            .filter(|_| payload.len() <= limit.min(MAX_MESSAGE_BYTES))
            .ok_or(CLIENT_FAILED)?;
        let (first, rest) = payload.split_at(payload.len().min(INIT_DATA));
        let mut report = [0; REPORT_BYTES];
        report[..4].copy_from_slice(&self.cid);
        report[4] = command;
        report[5..7].copy_from_slice(&length.to_be_bytes());
        report[7..7 + first.len()].copy_from_slice(first);
        self.transport.write_report(&report)?;
        for (sequence, chunk) in (0..=u8::MAX).zip(rest.chunks(CONT_DATA)) {
            let mut report = [0; REPORT_BYTES];
            report[..4].copy_from_slice(&self.cid);
            report[4] = sequence;
            report[5..5 + chunk.len()].copy_from_slice(chunk);
            self.transport.write_report(&report)?;
        }
        Ok(())
    }

    /// Wait for the next report of this channel.
    fn next_report(&mut self) -> Result<[u8; REPORT_BYTES], BridgeError> {
        let mut report = [0; REPORT_BYTES];
        loop {
            let remaining = self.remaining();
            if remaining.is_zero() {
                return self.cancel();
            }
            if self.transport.read_report(&mut report, remaining)? && report[..4] == self.cid {
                return Ok(report);
            }
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(self.clock.now())
    }

    /// Cancel the outstanding request at the deadline (ADR-110 E20 LS3).
    ///
    /// The broadcast `CTAPHID_INIT` has no channel to cancel, so nothing is sent for it.
    fn cancel(&mut self) -> Result<[u8; REPORT_BYTES], BridgeError> {
        if self.cid == BROADCAST {
            return Err(TIMEOUT);
        }
        let mut report = [0; REPORT_BYTES];
        report[..4].copy_from_slice(&self.cid);
        report[4] = CMD_CANCEL;
        self.transport.write_report(&report)?;
        Err(TIMEOUT)
    }

    fn receive(&mut self, command: u8, limit: usize) -> Result<Vec<u8>, BridgeError> {
        let report = loop {
            let report = self.next_report()?;
            if report[4] != CMD_KEEPALIVE {
                break report;
            }
        };
        let length = usize::from(u16::from_be_bytes([report[5], report[6]]));
        if report[4] != command || length > limit.min(MAX_MESSAGE_BYTES) {
            return Err(CLIENT_FAILED);
        }
        let mut message = Vec::with_capacity(length);
        message.extend_from_slice(&report[7..7 + length.min(INIT_DATA)]);
        let mut sequence = 0;
        while message.len() < length {
            let report = self.next_report()?;
            if report[4] != sequence {
                return Err(CLIENT_FAILED);
            }
            let take = (length - message.len()).min(CONT_DATA);
            message.extend_from_slice(&report[5..5 + take]);
            sequence += 1;
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests;
