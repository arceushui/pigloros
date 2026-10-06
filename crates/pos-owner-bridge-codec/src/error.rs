use core::fmt;

/// Closed failures emitted by the owner-bridge codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerBridgeCodecError {
    /// A fixed caller-owned output buffer cannot hold the requested encoding.
    BufferTooSmall,
    /// A control header did not have its exact required byte length.
    InvalidControlHeaderLength,
    /// A control header did not begin with the `PWB1` marker.
    InvalidControlMagic,
    /// A control header used an unsupported version or header length.
    InvalidControlVersion,
    /// A control header used an unknown role, kind, or state code.
    InvalidControlValue,
    /// A control header contained a nonzero reserved byte or flags field.
    NonzeroReserved,
    /// A control header used an invalid generation, capacity, or payload length.
    InvalidControlBounds,
    /// A loopback HTTP request did not meet the closed owner-document contract.
    InvalidHttpRequest,
    /// One deterministic-CBOR item had an invalid type, length, or structure.
    InvalidCbor,
    /// A deterministic-CBOR item did not use its shortest representation.
    NonCanonicalCbor,
    /// A deterministic-CBOR value exceeded one of the closed protocol bounds.
    BoundsExceeded,
    /// A decoded value had trailing input after its complete closed schema.
    TrailingBytes,
    /// A closed payload field had a wrong fixed value or an invalid enum value.
    InvalidPayload,
}

impl fmt::Display for OwnerBridgeCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BufferTooSmall => "owner-bridge output buffer is too small",
            Self::InvalidControlHeaderLength => "owner-bridge control header has an invalid length",
            Self::InvalidControlMagic => "owner-bridge control header has an invalid magic",
            Self::InvalidControlVersion => "owner-bridge control header has an invalid version",
            Self::InvalidControlValue => "owner-bridge control header has an invalid value",
            Self::NonzeroReserved => "owner-bridge input has a nonzero reserved field",
            Self::InvalidControlBounds => "owner-bridge control header has invalid bounds",
            Self::InvalidHttpRequest => "owner-bridge loopback HTTP request is invalid",
            Self::InvalidCbor => "owner-bridge input is not valid deterministic CBOR",
            Self::NonCanonicalCbor => "owner-bridge CBOR is not canonical",
            Self::BoundsExceeded => "owner-bridge input exceeds a closed bound",
            Self::TrailingBytes => "owner-bridge input has trailing bytes",
            Self::InvalidPayload => "owner-bridge payload violates its closed schema",
        };
        formatter.write_str(message)
    }
}
