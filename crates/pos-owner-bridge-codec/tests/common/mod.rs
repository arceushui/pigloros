use pos_owner_bridge_codec::{OwnerBridgeCodecError, VerificationReason};

/// Lifts a verifier rejection into the codec error so a test can use `?` on it.
pub fn verified<T>(result: Result<T, VerificationReason>) -> Result<T, OwnerBridgeCodecError> {
    result.map_err(OwnerBridgeCodecError::Verification)
}
