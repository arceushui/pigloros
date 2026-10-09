//! Reply consumption: A/B copies, header and payload checks, and verification (ADR-110 §5.6).
//!
//! The merged codec verifier reports every verification failure as one error, so a failed
//! Create is `Rejected(AttestationFormat)` and a failed Get is `Rejected(Signature)` until
//! Redmine #563 lets the codec report its reason. The bridge itself still distinguishes the
//! checks it makes before verifying: a credential ID or user handle that is not the stored one,
//! a ceremony ID that is not the outstanding one, and a required PRF that is absent or malformed.
//!
//! The closed codec decoder rejects a Get reply whose PRF is not a 32-byte string, but the
//! packaged page reports an absent PRF as CBOR `null` there, and a Create reply may carry a
//! malformed PRF too. When a reply fails to decode, the bridge swaps its PRF item for a valid
//! stand-in and decodes again: if only the PRF was wrong, the failure is
//! `Unavailable(PrfUnsupported)` (ADR-110 §1 and §7), otherwise it is the codec's own protocol
//! error.
//!
//! Precedence: a reply that fails to decode only because its PRF is absent or malformed is
//! `PrfUnsupported` even when its signature would not have verified, because the signature is
//! never reached. That failure is not user-retryable, which fits ADR-110 §1: a real ceremony needs
//! a present, correctly shaped PRF result. This scan is a temporary bridge-side lenient decode,
//! to be removed when Redmine #563 gives the codec a PRF-state reason.

use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, verify_assertion_reply,
    verify_attestation_reply, AssertionReplyV1, AssertionVerificationContext, AttestationReplyV1,
    CeremonyId, CeremonyKind, ControlState, CreateVerificationContext, OwnerBridgeCodecError,
    StoredCredential, CONTROL_HEADER_BYTES,
};
use zeroize::Zeroizing;

use super::plan::{Assertion, CeremonyPlan, Registration, Verified};
use super::release::read_state;
use super::{protocol_from_codec, replace_prf, PRF_PLACEHOLDER};
use crate::{
    BridgeError, OwnerWebSurface, ProtocolCode, RejectedCode, ReplyImage, SurfaceError,
    UnavailableCode,
};

const HEADER: usize = CONTROL_HEADER_BYTES;

/// Copy the full reply capacity and require the state word to still be `CONSUMING`.
///
/// # Errors
///
/// Returns the surface failure, or `Protocol(CopyMismatch)` when the state changed.
pub(super) fn snapshot(
    surface: &dyn OwnerWebSurface,
    image: &mut ReplyImage,
) -> Result<(), BridgeError> {
    surface.reply_copy(image).map_err(SurfaceError::error)?;
    match read_state(surface) {
        Ok(ControlState::Consuming) => Ok(()),
        other => Err(other
            .err()
            .unwrap_or(BridgeError::Protocol(ProtocolCode::CopyMismatch))),
    }
}

fn same_range(initial: &[u8; HEADER], header: &[u8; HEADER], from: usize, to: usize) -> bool {
    initial.get(from..to) == header.get(from..to)
}

/// Check every reply-header byte except `payload_len` and `state` against the initialised
/// header, then bound `payload_len`. Returns the payload length.
///
/// # Errors
///
/// Returns `CeremonyIdMismatch`, `GenerationMismatch`, `KindMismatch`, `HeaderTampered` or
/// `LengthOutOfBounds`, in that order.
pub(super) fn check_reply_header(
    initial: &[u8; HEADER],
    copy: &[u8],
) -> Result<usize, BridgeError> {
    let protocol = |code| Err(BridgeError::Protocol(code));
    let Some((header, _)) = copy.split_first_chunk::<HEADER>() else {
        return protocol(ProtocolCode::LengthOutOfBounds);
    };
    if !same_range(initial, header, 16, 32) {
        return protocol(ProtocolCode::CeremonyIdMismatch);
    }
    if !same_range(initial, header, 12, 16) {
        return protocol(ProtocolCode::GenerationMismatch);
    }
    if !same_range(initial, header, 9, 10) {
        return protocol(ProtocolCode::KindMismatch);
    }
    let untouched = [(0, 9), (10, 12), (32, 36), (44, HEADER)];
    if untouched
        .iter()
        .any(|&(from, to)| !same_range(initial, header, from, to))
    {
        return protocol(ProtocolCode::HeaderTampered);
    }
    let length = u32::from_le_bytes([header[36], header[37], header[38], header[39]]) as usize;
    if length == 0 || length > copy.len().saturating_sub(HEADER) {
        return protocol(ProtocolCode::LengthOutOfBounds);
    }
    Ok(length)
}

fn registration_from(
    reply: &AttestationReplyV1<'_>,
    plan: &CeremonyPlan,
    prf: &mut [u8; 32],
) -> Result<Registration, BridgeError> {
    if !reply.prf_enabled() {
        return Err(BridgeError::Unavailable(UnavailableCode::PrfUnsupported));
    }
    let context = CreateVerificationContext::new(plan.ceremony_id, plan.challenge());
    let verified = verify_attestation_reply(reply, context)
        .or(Err(BridgeError::Rejected(RejectedCode::AttestationFormat)))?;
    let first = verified.prf_first();
    if let Some(result) = first {
        prf.copy_from_slice(result.as_bytes());
    }
    Ok(Registration {
        credential_id: verified.credential_id().to_vec(),
        public_key: verified.public_key(),
        transports: verified.transports(),
        backup_eligible: verified.backup_eligible(),
        backup_state: verified.backup_state(),
        sign_count: verified.sign_count(),
        prf_present: first.is_some(),
    })
}

fn assertion_from(
    reply: &AssertionReplyV1<'_>,
    plan: &CeremonyPlan,
    prf: &mut [u8; 32],
) -> Result<Assertion, BridgeError> {
    let mismatch = BridgeError::Rejected(RejectedCode::CredentialMismatch);
    let stored = plan.stored.as_ref().ok_or(mismatch)?;
    if reply.raw_id() != stored.credential_id.as_slice() {
        return Err(mismatch);
    }
    if reply
        .user_handle()
        .is_some_and(|handle| handle != stored.user_handle)
    {
        return Err(BridgeError::Rejected(RejectedCode::UserHandleMismatch));
    }
    let verified = StoredCredential::new(
        &stored.credential_id,
        stored.user_handle,
        stored.public_key,
        stored.backup_eligible,
        stored.backup_state,
        stored.sign_count,
    )
    .map_err(protocol_from_codec)
    .and_then(|credential| {
        let context =
            AssertionVerificationContext::new(plan.ceremony_id, plan.challenge(), credential);
        verify_assertion_reply(reply, context)
            .or(Err(BridgeError::Rejected(RejectedCode::Signature)))
    })?;
    prf.copy_from_slice(verified.prf_first().as_bytes());
    Ok(Assertion {
        sign_count: verified.sign_count(),
        backup_state: verified.backup_state(),
    })
}

fn ceremony_id_of(kind: CeremonyKind, payload: &[u8]) -> Result<CeremonyId, OwnerBridgeCodecError> {
    match kind {
        CeremonyKind::Create => {
            decode_attestation_reply(payload).map(AttestationReplyV1::ceremony_id)
        }
        CeremonyKind::Get => decode_assertion_reply(payload).map(AssertionReplyV1::ceremony_id),
    }
}

/// The failure of a reply that did not decode (see the module documentation).
fn decode_failure(
    plan: &CeremonyPlan,
    payload: &[u8],
    error: OwnerBridgeCodecError,
) -> BridgeError {
    let standin = replace_prf(payload, &PRF_PLACEHOLDER);
    let id = standin.map(|bytes| ceremony_id_of(plan.kind, &bytes));
    match id {
        Some(Ok(id)) if id == plan.ceremony_id => {
            BridgeError::Unavailable(UnavailableCode::PrfUnsupported)
        }
        Some(Ok(_)) => BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch),
        _ => protocol_from_codec(error),
    }
}

/// Decode, check and verify the payload held in copy A, writing the PRF into `prf`.
///
/// # Errors
///
/// Returns the decode failure as a protocol error, a ceremony-ID mismatch, or the
/// verification failure as a rejection.
pub(super) fn parse_and_verify(
    plan: &CeremonyPlan,
    payload: &[u8],
    prf: &mut Zeroizing<[u8; 32]>,
) -> Result<Verified, BridgeError> {
    match plan.kind {
        CeremonyKind::Create => {
            let reply = decode_attestation_reply(payload)
                .map_err(|error| decode_failure(plan, payload, error))?;
            if reply.ceremony_id() != plan.ceremony_id {
                return Err(BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch));
            }
            registration_from(&reply, plan, prf).map(Verified::Registration)
        }
        CeremonyKind::Get => {
            let reply = decode_assertion_reply(payload)
                .map_err(|error| decode_failure(plan, payload, error))?;
            if reply.ceremony_id() != plan.ceremony_id {
                return Err(BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch));
            }
            assertion_from(&reply, plan, prf).map(Verified::Assertion)
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
