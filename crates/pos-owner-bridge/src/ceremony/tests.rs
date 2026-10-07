//! The codec-error mapping.

use pos_owner_bridge_codec::{OwnerBridgeCodecError, VerificationReason};

use super::protocol_from_codec;
use crate::{BridgeError, ProtocolCode, RejectedCode, UnavailableCode};

const fn protocol(code: ProtocolCode) -> BridgeError {
    BridgeError::Protocol(code)
}

#[test]
fn a_codec_failure_maps_to_its_protocol_code() {
    assert_eq!(
        protocol_from_codec(OwnerBridgeCodecError::NonCanonicalCbor),
        protocol(ProtocolCode::NonCanonical)
    );
    for bounds in [
        OwnerBridgeCodecError::BoundsExceeded,
        OwnerBridgeCodecError::BufferTooSmall,
        OwnerBridgeCodecError::InvalidControlBounds,
    ] {
        assert_eq!(
            protocol_from_codec(bounds),
            protocol(ProtocolCode::LengthOutOfBounds)
        );
    }
    assert_eq!(
        protocol_from_codec(OwnerBridgeCodecError::InvalidCbor),
        protocol(ProtocolCode::Malformed)
    );
}

#[test]
fn a_reply_field_reason_from_the_codec_decoder_keeps_its_bridge_error() {
    assert_eq!(
        protocol_from_codec(OwnerBridgeCodecError::Verification(
            VerificationReason::UserHandleMismatch
        )),
        BridgeError::Rejected(RejectedCode::UserHandleMismatch)
    );
    for reason in [VerificationReason::PrfMalformed, VerificationReason::PrfAbsent] {
        assert_eq!(
            protocol_from_codec(OwnerBridgeCodecError::Verification(reason)),
            BridgeError::Unavailable(UnavailableCode::PrfUnsupported)
        );
    }
}
