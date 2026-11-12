//! One loopback connection: bounded read, closed admission, fixed responses (ADR-110 §4).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_owner_bridge_codec::{admit_loopback_http_request, LoopbackRequestDisposition};
use sha2::{Digest, Sha256};

use super::assets::{Response, BAD_REQUEST_RESPONSE, NOT_FOUND_RESPONSE};
use super::ledger::ServedLedger;
use super::ListenerTimeouts;
use crate::{MonotonicClock, SystemClock};

/// The stack buffer of every connection and the header block limit.
pub(super) const REQUEST_BUFFER_BYTES: usize = 8_192;

/// What every connection shares.
#[derive(Debug)]
pub(super) struct ServeContext {
    /// The served-count ledger.
    pub(super) ledger: Arc<ServedLedger>,
    /// The connection deadlines.
    pub(super) timeouts: ListenerTimeouts,
    /// The digest every completed owner response must match.
    pub(super) expected_digest: [u8; 32],
    /// One immutable compiled response; never supplied by network input.
    pub(super) response: &'static Response,
    /// Test-only count of connections that supplied at least one request byte.
    #[cfg(feature = "test-support")]
    pub(super) received: Arc<std::sync::atomic::AtomicU64>,
    /// Aggregate test-only connection outcomes.
    #[cfg(feature = "test-support")]
    pub(super) observations: Arc<super::Observations>,
}

/// How reading one request ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadOutcome {
    /// A complete header block of this many bytes is buffered.
    Complete(usize),
    /// The header block did not fit the buffer.
    TooLarge,
    /// The peer sent nothing in time, closed, or failed: close without a response.
    Silent,
}

/// Closed diagnostic categories; all retain the same silent production outcome.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SilentReason {
    Eof,
    Timeout,
    Other,
}

/// The remaining time until `deadline`, or `None` when it has passed.
fn remaining(deadline: Instant, clock: &impl MonotonicClock) -> Option<Duration> {
    deadline
        .checked_duration_since(clock.now())
        .filter(|left| !left.is_zero())
}

fn header_end(buffered: &[u8]) -> bool {
    buffered.windows(4).any(|window| window == b"\r\n\r\n")
}

/// A byte source whose next read can be given a time limit; a `TcpStream` is one, and a scripted
/// reader is another in the tests.
pub(super) trait TimedRead: Read {
    /// Fail the next read that is still blocked after `limit`.
    fn limit_next_read(&mut self, limit: Duration) -> io::Result<()>;
}

impl TimedRead for TcpStream {
    fn limit_next_read(&mut self, limit: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(limit))
    }
}

/// Read one request head with the first-byte and header deadlines.
pub(super) fn read_request<S: TimedRead>(
    stream: &mut S,
    buffer: &mut [u8; REQUEST_BUFFER_BYTES],
    accepted_at: Instant,
    timeouts: ListenerTimeouts,
    clock: &impl MonotonicClock,
    mut first_byte: impl FnMut(),
    #[cfg(feature = "test-support")] mut silent: impl FnMut(SilentReason),
) -> ReadOutcome {
    let mut deadline = accepted_at + timeouts.first_byte;
    let mut filled = 0;
    loop {
        let Some(left) = remaining(deadline, clock) else {
            #[cfg(feature = "test-support")]
            silent(SilentReason::Timeout);
            return ReadOutcome::Silent;
        };
        let (_, room) = buffer.split_at_mut(filled.min(REQUEST_BUFFER_BYTES));
        let outcome = stream
            .limit_next_read(left)
            .and_then(|()| stream.read(room));
        let received = match outcome {
            Ok(0) => {
                #[cfg(feature = "test-support")]
                silent(SilentReason::Eof);
                return ReadOutcome::Silent;
            }
            Err(error) => {
                #[cfg(not(feature = "test-support"))]
                drop(error);
                #[cfg(feature = "test-support")]
                silent(match error.kind() {
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => SilentReason::Timeout,
                    _ => SilentReason::Other,
                });
                return ReadOutcome::Silent;
            }
            Ok(received) => received,
        };
        if filled == 0 {
            first_byte();
            deadline = clock.now() + timeouts.header;
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
pub(super) fn write_hashed<W: Write>(writer: &mut W, bytes: &[u8], hasher: &mut Sha256) -> bool {
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
pub(super) enum OwnerWrite {
    /// The connection failed before the whole response was accepted.
    Incomplete,
    /// The whole response was accepted; `digest_ok` says whether it matched the pinned digest.
    Complete {
        /// Whether the digest of the accepted bytes equals the expected digest.
        digest_ok: bool,
    },
}

/// Write the full owner response and compare the digest of the accepted bytes.
pub(super) fn write_owner_response<W: Write>(
    writer: &mut W,
    expected_digest: &[u8; 32],
    response: &Response,
) -> OwnerWrite {
    let mut hasher = Sha256::new();
    let head_sent = write_hashed(writer, response.head.as_bytes(), &mut hasher);
    if !head_sent || !write_hashed(writer, response.body, &mut hasher) {
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
pub(super) fn respond<W: Write>(
    writer: &mut W,
    admitted: Option<LoopbackRequestDisposition>,
    context: &ServeContext,
) {
    match admitted {
        // A failed write of a fixed error response only closes the connection: it carries no
        // served count and there is nothing further to report.
        None => drop(writer.write_all(BAD_REQUEST_RESPONSE.as_bytes())),
        Some(LoopbackRequestDisposition::NotFound) => {
            drop(writer.write_all(NOT_FOUND_RESPONSE.as_bytes()));
        }
        Some(LoopbackRequestDisposition::OwnerDocument) => {
            if let OwnerWrite::Complete { digest_ok } =
                write_owner_response(writer, &context.expected_digest, context.response)
            {
                context.ledger.complete(digest_ok);
            }
        }
    }
}

/// Serve one accepted connection to completion, then close it.
pub(super) fn serve_connection(
    mut stream: TcpStream,
    accepted_at: Instant,
    context: &ServeContext,
) {
    let mut buffer = [0_u8; REQUEST_BUFFER_BYTES];
    let outcome = read_request(
        &mut stream,
        &mut buffer,
        accepted_at,
        context.timeouts,
        &SystemClock,
        || {
            #[cfg(feature = "test-support")]
            context
                .received
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        },
        #[cfg(feature = "test-support")]
        |reason| {
            use std::sync::atomic::Ordering;
            let observations = &context.observations;
            let counter = match reason {
                SilentReason::Eof => &observations.silent_eof,
                SilentReason::Timeout => &observations.silent_timeout,
                SilentReason::Other => &observations.silent_error,
            };
            counter.fetch_add(1, Ordering::SeqCst);
        },
    );
    #[cfg(feature = "test-support")]
    {
        let counter = match outcome {
            ReadOutcome::Silent => &context.observations.silent,
            ReadOutcome::Complete(_) => &context.observations.complete,
            ReadOutcome::TooLarge => &context.observations.too_large,
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let admitted = match outcome {
        ReadOutcome::Silent => return,
        ReadOutcome::TooLarge => None,
        ReadOutcome::Complete(length) => buffer
            .get(..length)
            .and_then(|head| admit_loopback_http_request(head).ok()),
    };
    let armed = stream
        .set_write_timeout(Some(context.timeouts.idle))
        .is_ok();
    if armed {
        respond(&mut stream, admitted, context);
    }
}
