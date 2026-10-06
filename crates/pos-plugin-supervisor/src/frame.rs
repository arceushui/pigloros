//! Bounded, length-prefixed worker IPC frames (ADR-061 revision 4, decision 4).
//!
//! A frame is a four-byte big-endian length, from 1 to the frame limit,
//! followed by exactly that many bytes holding one canonical CBOR envelope. A
//! length above the limit is rejected before any body byte is read.

use std::io::{self, Read, Write};

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_crypto::plugin_worker_ipc::{
    MAX_WORKER_COMPONENT_BYTES_V1, MAX_WORKER_INVOCATION_BYTES_V1,
};

/// Request envelope bytes beyond the Component and invocation.
///
/// The negotiation record is at most 256 features of 128 bytes plus two
/// digests, the world and eight limits: well under 64 KiB.
const REQUEST_ENVELOPE_BYTES: usize = 65_536;
/// Response envelope bytes beyond the Event, state and log budgets.
const RESPONSE_ENVELOPE_BYTES: u64 = 1_048_576;

/// Why a frame could not be read or written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameFaultV1 {
    /// The stream ended before the complete frame.
    Truncated,
    /// The length is zero or above the frame limit.
    OutOfBounds,
    /// Bytes follow the single expected frame.
    Trailing,
    /// The stream failed.
    Io,
}

/// The frame limits of one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerFrameLimitsV1 {
    response_bytes: usize,
}

impl WorkerFrameLimitsV1 {
    /// The largest request frame: the largest Component and invocation.
    ///
    /// The worker reads its request before it knows the invocation's limits,
    /// so the request limit is the same for every invocation.
    pub const REQUEST_BYTES: usize =
        MAX_WORKER_COMPONENT_BYTES_V1 + MAX_WORKER_INVOCATION_BYTES_V1 + REQUEST_ENVELOPE_BYTES;

    /// The frame limits derived from the effective execution-profile limits.
    ///
    /// The response may hold the effective Event, state and log bytes plus
    /// 1 MiB of envelope and record structure.
    #[must_use]
    pub fn for_limits(limits: &DeterministicBudgetV1) -> Self {
        let response = limits
            .event_bytes
            .saturating_add(limits.state_bytes)
            .saturating_add(limits.log_bytes)
            .saturating_add(RESPONSE_ENVELOPE_BYTES);
        Self {
            response_bytes: usize::try_from(response).unwrap_or(usize::MAX),
        }
    }

    /// The largest response frame body, in bytes.
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

/// Write one frame of 1 to `limit` bytes and flush it.
///
/// # Errors
/// Returns `OutOfBounds` for an empty or over-limit body, before writing
/// anything, and `Io` when the stream fails.
pub fn write_frame(
    writer: &mut impl Write,
    bytes: &[u8],
    limit: usize,
) -> Result<(), FrameFaultV1> {
    let length = u32::try_from(bytes.len())
        .ok()
        .filter(|_| (1..=limit).contains(&bytes.len()))
        .ok_or(FrameFaultV1::OutOfBounds)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(bytes))
        .and_then(|()| writer.flush())
        .map_err(|_| FrameFaultV1::Io)
}

/// Read one frame of 1 to `limit` bytes.
///
/// # Errors
/// Returns `Truncated` when the stream ends inside the prefix or body,
/// `OutOfBounds` for a zero or over-limit length (no body byte is read), and
/// `Io` when the stream fails.
pub fn read_frame(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, FrameFaultV1> {
    let mut prefix = [0; 4];
    read_exactly(reader, &mut prefix)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .ok()
        .filter(|length| (1..=limit).contains(length))
        .ok_or(FrameFaultV1::OutOfBounds)?;
    let mut bytes = vec![0; length];
    read_exactly(reader, &mut bytes).map(|()| bytes)
}

/// Require the stream to end right after the frame.
///
/// # Errors
/// Returns `Trailing` when another byte follows and `Io` when the stream
/// fails.
pub fn require_end(reader: &mut impl Read) -> Result<(), FrameFaultV1> {
    let mut byte = [0];
    match reader.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(FrameFaultV1::Trailing),
        Err(_) => Err(FrameFaultV1::Io),
    }
}

fn read_exactly(reader: &mut impl Read, buffer: &mut [u8]) -> Result<(), FrameFaultV1> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            FrameFaultV1::Truncated
        } else {
            FrameFaultV1::Io
        }
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("broken"))
        }
    }

    /// Accepts writes but fails to flush.
    struct Unflushable(Vec<u8>);

    impl Write for Unflushable {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("unflushable"))
        }
    }

    #[test]
    fn frames_round_trip_up_to_the_limit() {
        let mut out = Vec::new();
        assert_eq!(write_frame(&mut out, b"abc", 3), Ok(()));
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
        let mut reader = out.as_slice();
        assert_eq!(read_frame(&mut reader, 3), Ok(b"abc".to_vec()));
        assert_eq!(require_end(&mut reader), Ok(()));
        let mut large = Vec::new();
        assert_eq!(write_frame(&mut large, &[7; 300], 300), Ok(()));
        assert_eq!(large[..4], [0, 0, 1, 44]);
        assert_eq!(read_frame(&mut large.as_slice(), 300), Ok(vec![7; 300]));
    }

    #[test]
    fn empty_and_over_limit_frames_are_never_written() {
        let mut out = Vec::new();
        assert_eq!(write_frame(&mut out, b"", 3), Err(FrameFaultV1::OutOfBounds));
        assert_eq!(write_frame(&mut out, b"abcd", 3), Err(FrameFaultV1::OutOfBounds));
        assert!(out.is_empty());
        assert_eq!(write_frame(&mut Broken, b"a", 1), Err(FrameFaultV1::Io));
        let mut unflushable = Unflushable(Vec::new());
        assert_eq!(write_frame(&mut unflushable, b"a", 1), Err(FrameFaultV1::Io));
        assert_eq!(unflushable.0, [0, 0, 0, 1, b'a']);
    }

    #[test]
    fn malformed_frames_are_faults() {
        let read = |bytes: &[u8], limit| read_frame(&mut &bytes[..], limit);
        assert_eq!(read(&[0, 0, 0, 0], 3), Err(FrameFaultV1::OutOfBounds));
        assert_eq!(read(&[0, 0, 0, 4, 1, 2, 3, 4], 3), Err(FrameFaultV1::OutOfBounds));
        assert_eq!(read(&[0, 0, 0, 3, 1, 2], 3), Err(FrameFaultV1::Truncated));
        assert_eq!(read(&[0, 0], 3), Err(FrameFaultV1::Truncated));
        assert_eq!(read(&[], 3), Err(FrameFaultV1::Truncated));
        assert_eq!(read_frame(&mut Broken, 3), Err(FrameFaultV1::Io));
        assert_eq!(require_end(&mut &[0][..]), Err(FrameFaultV1::Trailing));
        assert_eq!(require_end(&mut Broken), Err(FrameFaultV1::Io));
    }

    #[test]
    fn frame_limits_follow_the_effective_budget() {
        let limits = DeterministicBudgetV1 {
            event_bytes: 10,
            state_bytes: 200,
            log_bytes: 3_000,
            ..DeterministicBudgetV1::MINIMA
        };
        let frames = WorkerFrameLimitsV1::for_limits(&limits);
        assert_eq!(frames.response_bytes(), 1_048_576 + 3_210);
        let saturated = DeterministicBudgetV1 {
            event_bytes: u64::MAX,
            ..limits
        };
        let frames = WorkerFrameLimitsV1::for_limits(&saturated);
        assert_eq!(frames.response_bytes(), usize::MAX);
        assert_eq!(
            WorkerFrameLimitsV1::REQUEST_BYTES,
            33_554_432 + 2 * 1_048_576 + 2 * 65_536
        );
    }
}
