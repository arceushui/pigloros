//! The ceremony: plan, state machine, release loop, consumption and timing bounds.
//!
//! The seam is [`driver`] (a host owns the [`driver::CeremonyDriver`] on its STA thread and calls
//! `step` from its timer and event callbacks, ADR-110 §6), [`plan`] and [`timing`]. `consume` and
//! `release` are implementation detail.

use std::ops::Range;

use pos_owner_bridge_codec::OwnerBridgeCodecError;

use crate::{BridgeError, ProtocolCode};

mod consume;
pub mod driver;
pub mod plan;
mod release;
pub mod timing;

#[cfg(test)]
mod tests;

/// Map a codec failure while decoding a reply to its protocol code.
#[must_use]
pub(crate) const fn protocol_from_codec(error: OwnerBridgeCodecError) -> BridgeError {
    let code = match error {
        OwnerBridgeCodecError::NonCanonicalCbor => ProtocolCode::NonCanonical,
        OwnerBridgeCodecError::BoundsExceeded
        | OwnerBridgeCodecError::BufferTooSmall
        | OwnerBridgeCodecError::InvalidControlBounds => ProtocolCode::LengthOutOfBounds,
        _ => ProtocolCode::Malformed,
    };
    BridgeError::Protocol(code)
}

// The scanner below (`head`, `skip_item`, `prf_span`, `replace_prf`) is a temporary bridge-side
// lenient decode of the one reply item the closed decoder refuses to describe. Remove it when
// Redmine #563 gives the codec a PRF-state reason.

/// Both reply payloads are one array of ten items, and the PRF result is the ninth.
const REPLY_ITEMS: u64 = 10;
const PRF_ITEM: usize = 8;

/// Nested arrays only occur as the transport codes, which hold at most six entries.
const MAX_NESTED_ITEMS: u64 = 6;

/// A 32-byte byte string of zeros: a stand-in that keeps a reply decodable while its PRF item
/// is being examined.
pub(crate) const PRF_PLACEHOLDER: [u8; 34] = [
    0x58, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];

/// CBOR `null`: how the packaged page reports an absent PRF result. Only the fixture authenticator
/// and the tests encode it; the bridge itself only reads replies.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const PRF_NULL: [u8; 1] = [0xf6];

/// The major type, argument and first body offset of the CBOR head at `at`.
///
/// Only the argument widths a reply can use are understood: up to four bytes.
fn head(input: &[u8], at: usize) -> Option<(u8, u64, usize)> {
    let first = *input.get(at)?;
    let (major, extra) = (first >> 5, first & 31);
    let width = match extra {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        _ => return None,
    };
    let value = if width == 0 {
        u64::from(extra)
    } else {
        let argument = input.get(at + 1..at + 1 + width)?;
        argument
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
    };
    Some((major, value, at + 1 + width))
}

/// The offset just past the item at `at`, for the item shapes a reply contains: integers, byte and
/// text strings, short arrays of those, and the simple values `false`, `true` and `null`.
fn skip_item(input: &[u8], at: usize, depth: u8) -> Option<usize> {
    let (major, value, body) = head(input, at)?;
    match major {
        0 | 1 => Some(body),
        2 | 3 => {
            let end = body.checked_add(usize::try_from(value).ok()?)?;
            (end <= input.len()).then_some(end)
        }
        4 if depth == 0 && value <= MAX_NESTED_ITEMS => {
            (0..value).try_fold(body, |position, _| skip_item(input, position, depth + 1))
        }
        7 if body == at + 1 && matches!(value, 20..=22) => Some(body),
        _ => None,
    }
}

/// Where the PRF item of a reply payload sits, when every item before it can be skipped.
pub(crate) fn prf_span(payload: &[u8]) -> Option<Range<usize>> {
    let (major, count, first) = head(payload, 0)?;
    if major != 4 || count != REPLY_ITEMS {
        return None;
    }
    let start = (0..PRF_ITEM).try_fold(first, |position, _| skip_item(payload, position, 0))?;
    let end = skip_item(payload, start, 0)?;
    Some(start..end)
}

/// `payload` with its PRF item replaced by `item`, or `None` when the item cannot be located.
pub(crate) fn replace_prf(payload: &[u8], item: &[u8]) -> Option<Vec<u8>> {
    let span = prf_span(payload)?;
    let mut replaced = payload.get(..span.start).unwrap_or_default().to_vec();
    replaced.extend_from_slice(item);
    replaced.extend_from_slice(payload.get(span.end..).unwrap_or_default());
    Some(replaced)
}
