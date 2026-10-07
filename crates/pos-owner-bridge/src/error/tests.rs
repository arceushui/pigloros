//! The verification-reason mapping and the security-event classification.

use pos_owner_bridge_codec::VerificationReason as Reason;

use crate::{BridgeError, ProtocolCode, RejectedCode, UnavailableCode};

const fn rejected(code: RejectedCode) -> BridgeError {
    BridgeError::Rejected(code)
}

#[test]
fn every_verification_reason_maps_to_its_adr_code() {
    let prf = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
    let cases: [(Reason, BridgeError); 21] = [
        (
            Reason::CeremonyIdMismatch,
            BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch),
        ),
        (
            Reason::Malformed,
            BridgeError::Protocol(ProtocolCode::Malformed),
        ),
        (Reason::PrfUnsupported, prf),
        (Reason::PrfMalformed, prf),
        (Reason::PrfAbsent, prf),
        (Reason::Origin, rejected(RejectedCode::Origin)),
        (Reason::RpIdHash, rejected(RejectedCode::RpIdHash)),
        (
            Reason::ClientDataType,
            rejected(RejectedCode::ClientDataType),
        ),
        (Reason::Challenge, rejected(RejectedCode::Challenge)),
        (Reason::CrossOrigin, rejected(RejectedCode::CrossOrigin)),
        (Reason::UserPresence, rejected(RejectedCode::UserPresence)),
        (
            Reason::UserVerification,
            rejected(RejectedCode::UserVerification),
        ),
        (
            Reason::AttestationFormat,
            rejected(RejectedCode::AttestationFormat),
        ),
        (Reason::Algorithm, rejected(RejectedCode::Algorithm)),
        (Reason::CoseKey, rejected(RejectedCode::CoseKey)),
        (Reason::Extensions, rejected(RejectedCode::Extensions)),
        (Reason::Signature, rejected(RejectedCode::Signature)),
        (
            Reason::CredentialMismatch,
            rejected(RejectedCode::CredentialMismatch),
        ),
        (
            Reason::UserHandleMismatch,
            rejected(RejectedCode::UserHandleMismatch),
        ),
        (
            Reason::CounterRegression,
            rejected(RejectedCode::CounterRegression),
        ),
        (Reason::BackupFlags, rejected(RejectedCode::BackupFlags)),
    ];
    for (reason, expected) in cases {
        assert_eq!(BridgeError::from_verification_reason(reason), expected);
    }
}

#[test]
fn every_verification_rejection_is_user_retryable_and_a_missing_prf_is_not() {
    let prf = BridgeError::from_verification_reason(Reason::PrfAbsent);
    assert!(!prf.is_user_retryable());
    let origin = BridgeError::from_verification_reason(Reason::Origin);
    assert!(origin.is_user_retryable());
}

#[test]
fn only_a_counter_regression_and_a_failed_confirmation_are_security_events() {
    for code in [
        RejectedCode::CounterRegression,
        RejectedCode::EnrollmentConfirmation,
    ] {
        assert!(rejected(code).is_security_event());
    }
    for code in [
        RejectedCode::Signature,
        RejectedCode::CredentialAlreadyBound,
    ] {
        assert!(!rejected(code).is_security_event());
    }
    let prf = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
    assert!(!prf.is_security_event());
}
