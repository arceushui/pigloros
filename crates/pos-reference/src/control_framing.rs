//! Shared bounded framing for root-owned control channels.

use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure while reading or writing a bounded control frame.
pub enum ControlFrameError {
    /// The frame violates the bounded framing contract.
    Invalid,
    /// The underlying stream could not complete the operation.
    Io,
}

/// Writes one non-empty, length-prefixed frame within `maximum` bytes.
///
/// # Errors
///
/// Returns [`ControlFrameError::Invalid`] for an empty or oversized frame and
/// [`ControlFrameError::Io`] when the stream cannot accept the complete frame.
pub fn write_frame(
    writer: &mut impl Write,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ControlFrameError> {
    let length = u32::try_from(bytes.len())
        .ok()
        .filter(|length| *length != 0 && bytes.len() <= maximum)
        .ok_or(ControlFrameError::Invalid)?;
    writer
        .write_all(&length.to_be_bytes())
        .map_err(|_| ControlFrameError::Io)?;
    writer.write_all(bytes).map_err(|_| ControlFrameError::Io)
}

/// Reads one optional, length-prefixed frame within `maximum` bytes.
///
/// # Errors
///
/// Returns [`ControlFrameError::Invalid`] for a zero or oversized declared
/// length and [`ControlFrameError::Io`] for an incomplete stream operation.
pub fn read_frame(
    reader: &mut impl Read,
    maximum: usize,
) -> Result<Option<Vec<u8>>, ControlFrameError> {
    let mut prefix = [0_u8; 4];
    let first = reader
        .read(&mut prefix[..1])
        .map_err(|_| ControlFrameError::Io)?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut prefix[1..])
        .map_err(|_| ControlFrameError::Io)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .ok()
        .filter(|length| *length != 0 && *length <= maximum)
        .ok_or(ControlFrameError::Invalid)?;
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| ControlFrameError::Io)?;
    Ok(Some(bytes))
}

/// Requires the framed stream to be exactly at EOF.
///
/// # Errors
///
/// Returns [`ControlFrameError::Invalid`] when trailing bytes remain and
/// [`ControlFrameError::Io`] when the EOF check cannot read the stream.
pub fn require_eof(reader: &mut impl Read) -> Result<(), ControlFrameError> {
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte).map_err(|_| ControlFrameError::Io)? {
        0 => Ok(()),
        _ => Err(ControlFrameError::Invalid),
    }
}
