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
    /// A reply field failed a closed verification rule while it was decoded.
    ///
    /// Only the shape of the user handle and of the PRF fields can fail this
    /// way, because the typed reply cannot carry a malformed value on to the
    /// verifier.
    Verification(VerificationReason),
}

impl OwnerBridgeCodecError {
    const fn message(self) -> &'static str {
        match self {
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
            Self::Verification(reason) => reason.message(),
        }
    }
}

impl fmt::Display for OwnerBridgeCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Closed reason that the ADR-110 `WebAuthn` verifier rejected one reply.
///
/// Every variant names exactly one verification failure class. The bridge maps
/// each reason to its ADR-110 section 11 error code; no reason carries payload
/// bytes, identifiers, challenges, or PRF material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationReason {
    /// The reply ceremony ID is not the ceremony the host opened.
    CeremonyIdMismatch,
    /// A Create reply reported that PRF is not enabled for the credential.
    PrfUnsupported,
    /// Client data, authenticator data, or an envelope is structurally invalid.
    ///
    /// This covers malformed or oversized JSON, duplicate members, bad length
    /// fields, reserved authenticator flags, and a missing or unexpected
    /// attested-credential-data flag.
    Malformed,
    /// `clientDataJSON.origin` is absent or is not the loopback owner origin.
    Origin,
    /// `authenticatorData.rpIdHash` is not `SHA-256("localhost")`.
    RpIdHash,
    /// `clientDataJSON.type` is absent or is wrong for the ceremony kind.
    ClientDataType,
    /// `clientDataJSON.challenge` is absent, escaped, or not the host challenge.
    Challenge,
    /// `crossOrigin` is not `false`, or `topOrigin` or `tokenBinding` is present.
    CrossOrigin,
    /// The authenticator data does not set the user-present flag.
    UserPresence,
    /// The authenticator data does not set the user-verified flag.
    UserVerification,
    /// The attestation object is not the closed `none` attestation envelope.
    AttestationFormat,
    /// The COSE key algorithm is not ES256 (`-7`).
    Algorithm,
    /// The COSE key is not the closed EC2 P-256 shape or its point is invalid.
    CoseKey,
    /// The authenticator extension map or its trailing-byte accounting is invalid.
    Extensions,
    /// The ES256 signature is not strict DER or does not verify.
    Signature,
    /// The reply credential ID is not the credential ID the host expected.
    CredentialMismatch,
    /// The reply user handle is present and differs from the stored handle.
    UserHandleMismatch,
    /// The assertion counter did not advance and is not the both-zero case.
    CounterRegression,
    /// The backup-eligible flag changed, or backup state is set without eligibility.
    BackupFlags,
    /// A PRF field of the reply has the wrong shape or `second` is not null.
    PrfMalformed,
    /// A Get reply carries no PRF result (`null`) where one is required.
    PrfAbsent,
}

impl VerificationReason {
    const fn message(self) -> &'static str {
        match self {
            Self::CeremonyIdMismatch => "reply ceremony ID does not match the open ceremony",
            Self::PrfUnsupported => "credential reports no PRF support",
            Self::Malformed => "reply is structurally malformed",
            Self::Origin => "client data origin is not the owner origin",
            Self::RpIdHash => "authenticator RP ID hash is wrong",
            Self::ClientDataType => "client data type is wrong for the ceremony",
            Self::Challenge => "client data challenge is not the host challenge",
            Self::CrossOrigin => "client data reports a cross-origin context",
            Self::UserPresence => "authenticator did not assert user presence",
            Self::UserVerification => "authenticator did not assert user verification",
            Self::AttestationFormat => "attestation is not the closed none format",
            Self::Algorithm => "credential algorithm is not ES256",
            Self::CoseKey => "credential public key is not the closed ES256 key",
            Self::Extensions => "authenticator extensions are invalid",
            Self::Signature => "assertion signature is invalid",
            Self::CredentialMismatch => "credential ID is not the expected credential",
            Self::UserHandleMismatch => "user handle does not match the stored handle",
            Self::CounterRegression => "assertion counter did not advance",
            Self::BackupFlags => "authenticator backup flags are inconsistent",
            Self::PrfMalformed => "PRF fields are malformed",
            Self::PrfAbsent => "required PRF result is absent",
        }
    }
}

impl fmt::Display for VerificationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}
