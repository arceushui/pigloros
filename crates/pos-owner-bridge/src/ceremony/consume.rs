//! Reply consumption: A/B copies, header and payload checks, and verification (ADR-110 §5.6).
//!
//! The codec decoder and verifier report one `VerificationReason` per failure, and
//! `BridgeError::from_verification_reason` maps each to its ADR-110 §11 code. A decode failure
//! of the user handle or of a PRF field carries its reason too. An absent, unsupported or
//! malformed required PRF is `Unavailable(PrfUnsupported)` (ADR-110 §1 and §7).
//!
//! Precedence: the decoder rejects a malformed PRF field before the verifier looks at anything
//! else, so a reply with a bad PRF is `PrfUnsupported` even when its ceremony ID or signature
//! would not have verified. A structural defect that comes earlier in the payload, or a
//! non-canonical encoding of the PRF item itself, still reports its own protocol error.

use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, verify_assertion_reply,
    verify_attestation_reply, AssertionReplyV1, AssertionVerificationContext, AttestationReplyV1,
    CeremonyKind, ControlState, CreateVerificationContext, StoredCredential, CONTROL_HEADER_BYTES,
};
use zeroize::Zeroizing;

use super::plan::{Assertion, CeremonyPlan, Registration, Verified};
use super::release::read_state;
use super::protocol_from_codec;
use crate::{BridgeError, OwnerWebSurface, ProtocolCode, RejectedCode, ReplyImage, SurfaceError};

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
    let context = CreateVerificationContext::new(plan.ceremony_id, plan.challenge());
    let verified = verify_attestation_reply(reply, context)
        .map_err(BridgeError::from_verification_reason)?;
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
    let stored = plan
        .stored
        .as_ref()
        .ok_or(BridgeError::Rejected(RejectedCode::CredentialMismatch))?;
    let credential = StoredCredential::new(
        &stored.credential_id,
        stored.user_handle,
        stored.public_key,
        stored.backup_eligible,
        stored.backup_state,
        stored.sign_count,
    )
    .map_err(protocol_from_codec)?;
    let context =
        AssertionVerificationContext::new(plan.ceremony_id, plan.challenge(), credential);
    let verified =
        verify_assertion_reply(reply, context).map_err(BridgeError::from_verification_reason)?;
    prf.copy_from_slice(verified.prf_first().as_bytes());
    Ok(Assertion {
        sign_count: verified.sign_count(),
        backup_state: verified.backup_state(),
    })
}

/// Decode, check and verify the payload held in copy A, writing the PRF into `prf`.
///
/// # Errors
///
/// Returns the decode failure, or the verification failure, as its ADR-110 §11 error.
pub(super) fn parse_and_verify(
    plan: &CeremonyPlan,
    payload: &[u8],
    prf: &mut Zeroizing<[u8; 32]>,
) -> Result<Verified, BridgeError> {
    match plan.kind {
        CeremonyKind::Create => {
            let reply = decode_attestation_reply(payload).map_err(protocol_from_codec)?;
            registration_from(&reply, plan, prf).map(Verified::Registration)
        }
        CeremonyKind::Get => {
            let reply = decode_assertion_reply(payload).map_err(protocol_from_codec)?;
            assertion_from(&reply, plan, prf).map(Verified::Assertion)
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
