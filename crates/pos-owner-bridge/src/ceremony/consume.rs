//! Reply consumption: A/B copies, header and payload checks, and verification (ADR-110 §5.6).

use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, parse_assertion_authenticator_data,
    verify_assertion_reply, verify_attestation_reply, AssertionAuthenticatorData, AssertionReplyV1,
    AssertionVerificationContext, AttestationReplyV1, CeremonyKind, ControlState,
    CreateVerificationContext, OwnerBridgeCodecError, StoredCredential, CONTROL_HEADER_BYTES,
};
use zeroize::Zeroizing;

use super::plan::{Assertion, CeremonyPlan, Registration, StoredGet, Verified};
use super::release::read_state;
use crate::{
    BridgeError, OwnerWebSurface, ProtocolCode, RejectedCode, ReplyImage, SurfaceError,
    UnavailableCode,
};

const HEADER: usize = CONTROL_HEADER_BYTES;

/// Map a codec failure while decoding a reply to its protocol code.
#[must_use]
pub const fn protocol_from_codec(error: OwnerBridgeCodecError) -> BridgeError {
    let code = match error {
        OwnerBridgeCodecError::NonCanonicalCbor => ProtocolCode::NonCanonical,
        OwnerBridgeCodecError::BoundsExceeded
        | OwnerBridgeCodecError::BufferTooSmall
        | OwnerBridgeCodecError::InvalidControlBounds => ProtocolCode::LengthOutOfBounds,
        _ => ProtocolCode::Malformed,
    };
    BridgeError::Protocol(code)
}

/// Copy the full reply capacity and require the state word to still be `CONSUMING`.
///
/// # Errors
///
/// Returns the surface failure, or `Protocol(CopyMismatch)` when the state changed.
pub fn snapshot(surface: &dyn OwnerWebSurface, image: &mut ReplyImage) -> Result<(), BridgeError> {
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
pub fn check_reply_header(initial: &[u8; HEADER], copy: &[u8]) -> Result<usize, BridgeError> {
    let (header, _) = copy
        .split_first_chunk::<HEADER>()
        .unwrap_or((&[0; HEADER], &[]));
    let protocol = |code| Err(BridgeError::Protocol(code));
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
    let context = CreateVerificationContext::new(plan.ceremony_id, plan.challenge);
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

const fn counter_regressed(stored: u32, new: u32) -> bool {
    new <= stored && (new != 0 || stored != 0)
}

const fn classify_authenticator(
    data: AssertionAuthenticatorData,
    stored: &StoredGet,
) -> RejectedCode {
    if data.backup_eligible() != stored.backup_eligible {
        RejectedCode::BackupFlags
    } else if counter_regressed(stored.sign_count, data.sign_count()) {
        RejectedCode::CounterRegression
    } else {
        RejectedCode::Signature
    }
}

fn classify_assertion_failure(reply: &AssertionReplyV1<'_>, stored: &StoredGet) -> RejectedCode {
    parse_assertion_authenticator_data(reply.authenticator_data())
        .map_or(RejectedCode::Signature, |data| {
            classify_authenticator(data, stored)
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
            AssertionVerificationContext::new(plan.ceremony_id, plan.challenge, credential);
        verify_assertion_reply(reply, context)
            .map_err(|_| BridgeError::Rejected(classify_assertion_failure(reply, stored)))
    })?;
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
/// Returns the decode failure as a protocol error, a ceremony-ID mismatch, or the
/// verification failure as a rejection.
pub fn parse_and_verify(
    plan: &CeremonyPlan,
    payload: &[u8],
    prf: &mut Zeroizing<[u8; 32]>,
) -> Result<Verified, BridgeError> {
    match plan.kind {
        CeremonyKind::Create => {
            let reply = decode_attestation_reply(payload).map_err(protocol_from_codec)?;
            if reply.ceremony_id() != plan.ceremony_id {
                return Err(BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch));
            }
            registration_from(&reply, plan, prf).map(Verified::Registration)
        }
        CeremonyKind::Get => {
            let reply = decode_assertion_reply(payload).map_err(protocol_from_codec)?;
            if reply.ceremony_id() != plan.ceremony_id {
                return Err(BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch));
            }
            assertion_from(&reply, plan, prf).map(Verified::Assertion)
        }
    }
}
