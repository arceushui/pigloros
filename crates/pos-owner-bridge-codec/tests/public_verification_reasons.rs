use pos_owner_bridge_codec::{OwnerBridgeCodecError, VerificationReason as Reason};

const MESSAGES: [(Reason, &str); 21] = [
    (
        Reason::CeremonyIdMismatch,
        "reply ceremony ID does not match the open ceremony",
    ),
    (Reason::PrfUnsupported, "credential reports no PRF support"),
    (Reason::Malformed, "reply is structurally malformed"),
    (Reason::Origin, "client data origin is not the owner origin"),
    (Reason::RpIdHash, "authenticator RP ID hash is wrong"),
    (
        Reason::ClientDataType,
        "client data type is wrong for the ceremony",
    ),
    (
        Reason::Challenge,
        "client data challenge is not the host challenge",
    ),
    (
        Reason::CrossOrigin,
        "client data reports a cross-origin context",
    ),
    (
        Reason::UserPresence,
        "authenticator did not assert user presence",
    ),
    (
        Reason::UserVerification,
        "authenticator did not assert user verification",
    ),
    (
        Reason::AttestationFormat,
        "attestation is not the closed none format",
    ),
    (Reason::Algorithm, "credential algorithm is not ES256"),
    (
        Reason::CoseKey,
        "credential public key is not the closed ES256 key",
    ),
    (Reason::Extensions, "authenticator extensions are invalid"),
    (Reason::Signature, "assertion signature is invalid"),
    (
        Reason::CredentialMismatch,
        "credential ID is not the expected credential",
    ),
    (
        Reason::UserHandleMismatch,
        "user handle does not match the stored handle",
    ),
    (
        Reason::CounterRegression,
        "assertion counter did not advance",
    ),
    (
        Reason::BackupFlags,
        "authenticator backup flags are inconsistent",
    ),
    (Reason::PrfMalformed, "PRF fields are malformed"),
    (Reason::PrfAbsent, "required PRF result is absent"),
];

#[test]
fn every_verification_reason_has_one_distinct_message() {
    for (index, (reason, message)) in MESSAGES.iter().enumerate() {
        assert_eq!(reason.to_string(), *message);
        for (other, _) in MESSAGES.iter().skip(index + 1) {
            assert_ne!(reason, other);
        }
    }
}

#[test]
fn a_verification_reason_is_carried_by_the_codec_error() {
    let error = OwnerBridgeCodecError::Verification(Reason::PrfMalformed);
    assert_eq!(error.to_string(), "PRF fields are malformed");
}
