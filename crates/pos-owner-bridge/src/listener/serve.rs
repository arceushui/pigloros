//! One loopback connection: bounded read, closed admission, fixed responses (ADR-110 §4).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_owner_bridge_codec::{admit_loopback_http_request, LoopbackRequestDisposition};
use sha2::{Digest, Sha256};

use super::assets::{BAD_REQUEST_RESPONSE, NOT_FOUND_RESPONSE, OWNER_HTML, OWNER_RESPONSE_HEAD};
use super::ledger::ServedLedger;

/// The stack buffer of every connection and the header block limit.
pub const REQUEST_BUFFER_BYTES: usize = 8_192;

/// The three connection deadlines of ADR-110 §4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerTimeouts {
    /// Close a connection that sends no byte within this time of `accept`.
    pub first_byte: Duration,
    /// Time allowed from the first byte to the complete header block.
    pub header: Duration,
    /// Write idle limit for the response.
    pub idle: Duration,
}

/// The ADR-110 deadlines: 1 s first byte, 2 s header block, 30 s idle.
pub const ADR_TIMEOUTS: ListenerTimeouts = ListenerTimeouts {
    first_byte: Duration::from_secs(1),
    header: Duration::from_secs(2),
    idle: Duration::from_secs(30),
};

/// What every connection shares.
#[derive(Debug)]
pub struct ServeContext {
    /// The served-count ledger.
    pub ledger: Arc<ServedLedger>,
    /// The connection deadlines.
    pub timeouts: ListenerTimeouts,
    /// The digest every completed owner response must match.
    pub expected_digest: [u8; 32],
}

/// How reading one request ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    /// A complete header block of this many bytes is buffered.
    Complete(usize),
    /// The header block did not fit the buffer.
    TooLarge,
    /// The peer sent nothing in time, closed, or failed: close without a response.
    Silent,
}

/// The shortest read timeout a socket accepts; a passed deadline reads for this long and fails.
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

/// The remaining time until `deadline`, or `None` when it has passed.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

fn header_end(buffered: &[u8]) -> bool {
    buffered.windows(4).any(|window| window == b"\r\n\r\n")
}

/// Read one request head with the first-byte and header deadlines.
pub fn read_request(
    stream: &mut TcpStream,
    buffer: &mut [u8; REQUEST_BUFFER_BYTES],
    timeouts: ListenerTimeouts,
) -> ReadOutcome {
    let mut deadline = Instant::now() + timeouts.first_byte;
    let mut filled = 0;
    loop {
        let left = remaining(deadline).unwrap_or(MIN_TIMEOUT);
        let (_, room) = buffer.split_at_mut(filled.min(REQUEST_BUFFER_BYTES));
        let outcome = stream
            .set_read_timeout(Some(left))
            .and_then(|()| stream.read(room));
        let received = match outcome {
            Ok(0) | Err(_) => return ReadOutcome::Silent,
            Ok(received) => received,
        };
        if filled == 0 {
            deadline = Instant::now() + timeouts.header;
        }
        filled += received;
        if buffer.get(..filled).is_some_and(header_end) {
            return ReadOutcome::Complete(filled);
        }
        if filled == REQUEST_BUFFER_BYTES {
            return ReadOutcome::TooLarge;
        }
    }
}

/// Write `bytes`, hashing exactly what the writer accepted. Returns whether all bytes went out.
pub fn write_hashed<W: Write>(writer: &mut W, bytes: &[u8], hasher: &mut Sha256) -> bool {
    let mut remaining_bytes = bytes;
    while !remaining_bytes.is_empty() {
        let accepted = match writer.write(remaining_bytes) {
            Ok(0) | Err(_) => return false,
            Ok(accepted) => accepted,
        };
        let (sent, rest) = remaining_bytes.split_at(accepted.min(remaining_bytes.len()));
        hasher.update(sent);
        remaining_bytes = rest;
    }
    true
}

/// The result of writing the owner response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerWrite {
    /// The connection failed before the whole response was accepted.
    Incomplete,
    /// The whole response was accepted; `digest_ok` says whether it matched the pinned digest.
    Complete {
        /// Whether the digest of the accepted bytes equals the expected digest.
        digest_ok: bool,
    },
}

/// Write the full owner response and compare the digest of the accepted bytes.
pub fn write_owner_response<W: Write>(writer: &mut W, expected_digest: &[u8; 32]) -> OwnerWrite {
    let mut hasher = Sha256::new();
    let head_sent = write_hashed(writer, OWNER_RESPONSE_HEAD.as_bytes(), &mut hasher);
    if !head_sent || !write_hashed(writer, OWNER_HTML, &mut hasher) {
        return OwnerWrite::Incomplete;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    OwnerWrite::Complete {
        digest_ok: digest == *expected_digest,
    }
}

/// Answer one read request on `writer`: the owner document, the fixed `404`, or the fixed `400`.
///
/// `admitted` is `None` for a malformed request. A completed owner response is recorded in
/// the served ledger; a failed one is not.
pub fn respond<W: Write>(
    writer: &mut W,
    admitted: Option<LoopbackRequestDisposition>,
    context: &ServeContext,
) {
    match admitted {
        None => drop(writer.write_all(BAD_REQUEST_RESPONSE.as_bytes())),
        Some(LoopbackRequestDisposition::NotFound) => {
            drop(writer.write_all(NOT_FOUND_RESPONSE.as_bytes()));
        }
        Some(LoopbackRequestDisposition::OwnerDocument) => {
            if let OwnerWrite::Complete { digest_ok } =
                write_owner_response(writer, &context.expected_digest)
            {
                context.ledger.complete(digest_ok);
            }
        }
    }
}

/// Serve one accepted connection to completion, then close it.
pub fn serve_connection(mut stream: TcpStream, context: &ServeContext) {
    let mut buffer = [0_u8; REQUEST_BUFFER_BYTES];
    let admitted = match read_request(&mut stream, &mut buffer, context.timeouts) {
        ReadOutcome::Silent => return,
        ReadOutcome::TooLarge => None,
        ReadOutcome::Complete(length) => buffer
            .get(..length)
            .and_then(|head| admit_loopback_http_request(head).ok()),
    };
    let armed = stream
        .set_write_timeout(Some(context.timeouts.idle))
        .is_ok();
    armed.then(|| respond(&mut stream, admitted, context));
}
