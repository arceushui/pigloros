//! The ceremony: plan, state machine, release loop, consumption and timing bounds.
//!
//! The seam is [`driver`] (a host owns the [`driver::CeremonyDriver`] on its STA thread and calls
//! `step` from its timer and event callbacks, ADR-110 §6), [`plan`] and [`timing`]. `consume` and
//! `release` are implementation detail.

use pos_owner_bridge_codec::OwnerBridgeCodecError;

use crate::{BridgeError, ProtocolCode};

mod consume;
pub mod driver;
pub mod plan;
mod release;
pub mod timing;

#[cfg(test)]
mod tests;

/// Map a codec failure while decoding a reply to its bridge error.
///
/// A reply field the codec refuses because of its shape carries its own verification reason
/// (the user handle and the PRF fields); every other failure is a protocol code.
#[must_use]
pub(crate) const fn protocol_from_codec(error: OwnerBridgeCodecError) -> BridgeError {
    let code = match error {
        OwnerBridgeCodecError::Verification(reason) => {
            return BridgeError::from_verification_reason(reason);
        }
        OwnerBridgeCodecError::NonCanonicalCbor => ProtocolCode::NonCanonical,
        OwnerBridgeCodecError::BoundsExceeded
        | OwnerBridgeCodecError::BufferTooSmall
        | OwnerBridgeCodecError::InvalidControlBounds => ProtocolCode::LengthOutOfBounds,
        _ => ProtocolCode::Malformed,
    };
    BridgeError::Protocol(code)
}
