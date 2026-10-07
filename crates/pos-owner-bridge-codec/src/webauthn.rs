use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    parse_assertion_authenticator_data, parse_none_attestation_object, validate_client_data_json,
    AssertionAuthenticatorData, AssertionReplyV1, AttestationReplyV1, CeremonyId,
    CoseEs256PublicKey, OwnerBridgeCodecError, OwnerUserHandle, PrfResult, TransportCodes,
    VerificationReason, WebAuthnChallenge, MAX_AUTHENTICATOR_DATA_BYTES,
};

const MIN_CREDENTIAL_ID_BYTES: usize = 1;
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
/// The authenticator-data bound plus the 32-byte client-data digest.
const SIGNED_MESSAGE_BYTES: usize = MAX_AUTHENTICATOR_DATA_BYTES + 32;
// The buffer is sized for the closed 1,024-byte bound; a change to either constant must be
// made on purpose.
const _: () = assert!(SIGNED_MESSAGE_BYTES == 1_056);

/// Host-owned invariants for verifying a Create reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateVerificationContext {
    ceremony_id: CeremonyId,
    challenge: WebAuthnChallenge,
}

impl CreateVerificationContext {
    /// Construct the exact one-use ceremony context that a Create reply must
    /// match.
    #[must_use]
    pub const fn new(ceremony_id: CeremonyId, challenge: WebAuthnChallenge) -> Self {
        Self {
            ceremony_id,
            challenge,
        }
    }
}

/// Owner-stored credential material used by the closed Get verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredCredential<'a> {
    credential_id: &'a [u8],
    user_handle: OwnerUserHandle,
    public_key: CoseEs256PublicKey,
    backup_eligible: bool,
    sign_count: u32,
}

impl<'a> StoredCredential<'a> {
    /// Construct the credential portion of a Get verification context.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when `credential_id`
    /// is not within the required 1–1024-byte `WebAuthn` range.
    pub const fn new(
        credential_id: &'a [u8],
        user_handle: OwnerUserHandle,
        public_key: CoseEs256PublicKey,
        backup_eligible: bool,
        backup_state: bool,
        sign_count: u32,
    ) -> Result<Self, OwnerBridgeCodecError> {
        if credential_id.len() < MIN_CREDENTIAL_ID_BYTES
            || credential_id.len() > MAX_CREDENTIAL_ID_BYTES
            || (backup_state && !backup_eligible)
        {
            return Err(OwnerBridgeCodecError::BoundsExceeded);
        }
        Ok(Self {
            credential_id,
            user_handle,
            public_key,
            backup_eligible,
            sign_count,
        })
    }
}

/// Host-owned invariants for verifying one Get assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssertionVerificationContext<'a> {
    ceremony_id: CeremonyId,
    challenge: WebAuthnChallenge,
    credential: StoredCredential<'a>,
}

impl<'a> AssertionVerificationContext<'a> {
    /// Construct the exact one-use Get context and its stored credential.
    #[must_use]
    pub const fn new(
        ceremony_id: CeremonyId,
        challenge: WebAuthnChallenge,
        credential: StoredCredential<'a>,
    ) -> Self {
        Self {
            ceremony_id,
            challenge,
            credential,
        }
    }
}

/// A Create reply that passed the closed `WebAuthn` verification subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRegistration<'a> {
    credential_id: &'a [u8],
    public_key: CoseEs256PublicKey,
    transports: TransportCodes,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
    prf_first: Option<PrfResult>,
}

impl<'a> VerifiedRegistration<'a> {
    /// Return the authenticated credential ID.
    #[must_use]
    pub const fn credential_id(self) -> &'a [u8] {
        self.credential_id
    }

    /// Return the validated COSE ES256 public key.
    #[must_use]
    pub const fn public_key(self) -> CoseEs256PublicKey {
        self.public_key
    }

    /// Return the non-authoritative transport hints supplied by the page.
    #[must_use]
    pub const fn transports(self) -> TransportCodes {
        self.transports
    }

    /// Return the validated registration backup-eligibility flag.
    #[must_use]
    pub const fn backup_eligible(self) -> bool {
        self.backup_eligible
    }

    /// Return the validated registration backup-state flag.
    #[must_use]
    pub const fn backup_state(self) -> bool {
        self.backup_state
    }

    /// Return the validated registration signature counter.
    #[must_use]
    pub const fn sign_count(self) -> u32 {
        self.sign_count
    }

    /// Return the optional renderer-supplied Create PRF result.
    #[must_use]
    pub const fn prf_first(self) -> Option<PrfResult> {
        self.prf_first
    }
}

/// A Get assertion that passed the closed `WebAuthn` verification subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedAssertion {
    backup_state: bool,
    sign_count: u32,
    prf_first: PrfResult,
}

impl VerifiedAssertion {
    /// Return the accepted assertion backup-state flag.
    #[must_use]
    pub const fn backup_state(self) -> bool {
        self.backup_state
    }

    /// Return the accepted assertion signature counter.
    #[must_use]
    pub const fn sign_count(self) -> u32 {
        self.sign_count
    }

    /// Return the renderer-supplied Get PRF result.
    #[must_use]
    pub const fn prf_first(self) -> PrfResult {
        self.prf_first
    }
}

/// Verify a closed Create reply under ADR-110's `none` attestation policy.
///
/// # Errors
///
/// Returns the closed [`VerificationReason`] of the first failed check:
/// ceremony ID, PRF support, client data, attestation object, authenticator
/// data, COSE key, or public-key point.
pub fn verify_attestation_reply<'a>(
    reply: &AttestationReplyV1<'a>,
    context: CreateVerificationContext,
) -> Result<VerifiedRegistration<'a>, VerificationReason> {
    if reply.ceremony_id() != context.ceremony_id {
        return Err(VerificationReason::CeremonyIdMismatch);
    }
    if !reply.prf_enabled() {
        return Err(VerificationReason::PrfUnsupported);
    }
    validate_client_data_json(
        reply.client_data_json(),
        crate::CeremonyKind::Create,
        &context.challenge,
    )?;
    let data = parse_none_attestation_object(reply.attestation_object(), reply.raw_id())?;
    validate_public_key(data.public_key())?;
    Ok(VerifiedRegistration {
        credential_id: data.credential_id(),
        public_key: data.public_key(),
        transports: reply.transports(),
        backup_eligible: data.backup_eligible(),
        backup_state: data.backup_state(),
        sign_count: data.sign_count(),
        prf_first: reply.prf_first(),
    })
}

/// Verify a closed Get assertion against one stored credential binding.
///
/// # Errors
///
/// Returns the closed [`VerificationReason`] of the first failed check, in this order:
/// ceremony ID, credential ID, client data, authenticator data (RP ID hash, flags and
/// extensions), the stored public key, the signature, and only then the checks that compare the
/// reply with the stored binding: backup eligibility, user handle and counter.
///
/// The signature comes first on purpose (a decider ruling; ADR-110 §7 lists the signature
/// bullet before the backup-eligibility and counter bullets), so `BackupFlags`,
/// `UserHandleMismatch` and `CounterRegression` can only describe an authenticated reply. A
/// forged reply fails with `Signature` and can never raise a counter-regression security event.
pub fn verify_assertion_reply(
    reply: &AssertionReplyV1<'_>,
    context: AssertionVerificationContext<'_>,
) -> Result<VerifiedAssertion, VerificationReason> {
    if reply.ceremony_id() != context.ceremony_id {
        return Err(VerificationReason::CeremonyIdMismatch);
    }
    if reply.raw_id() != context.credential.credential_id {
        return Err(VerificationReason::CredentialMismatch);
    }
    validate_client_data_json(
        reply.client_data_json(),
        crate::CeremonyKind::Get,
        &context.challenge,
    )?;
    let data = parse_assertion_authenticator_data(reply.authenticator_data())?;
    let verifying_key = validating_key(context.credential.public_key)?;
    verify_signature(
        &verifying_key,
        reply.authenticator_data(),
        reply.client_data_json(),
        reply.signature(),
    )?;
    check_stored_binding(reply, data, context.credential)?;
    Ok(VerifiedAssertion {
        backup_state: data.backup_state(),
        sign_count: data.sign_count(),
        prf_first: reply.prf_first(),
    })
}

/// Compare an authenticated reply with the stored binding. It runs only after the signature
/// verified.
fn check_stored_binding(
    reply: &AssertionReplyV1<'_>,
    data: AssertionAuthenticatorData,
    credential: StoredCredential<'_>,
) -> Result<(), VerificationReason> {
    let handle_mismatch = reply
        .user_handle()
        .is_some_and(|handle| handle != credential.user_handle);
    if data.backup_eligible() != credential.backup_eligible {
        Err(VerificationReason::BackupFlags)
    } else if handle_mismatch {
        Err(VerificationReason::UserHandleMismatch)
    } else if !counter_advanced(credential.sign_count, data.sign_count()) {
        Err(VerificationReason::CounterRegression)
    } else {
        Ok(())
    }
}

const fn counter_advanced(stored: u32, current: u32) -> bool {
    (stored == 0 && current == 0) || current > stored
}

fn validate_public_key(key: CoseEs256PublicKey) -> Result<(), VerificationReason> {
    validating_key(key).map(|_| ())
}

fn validating_key(key: CoseEs256PublicKey) -> Result<VerifyingKey, VerificationReason> {
    VerifyingKey::from_sec1_bytes(&key.uncompressed_sec1_bytes())
        .or(Err(VerificationReason::CoseKey))
}

fn verify_signature(
    verifying_key: &VerifyingKey,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_bytes: &[u8],
) -> Result<(), VerificationReason> {
    let signature = Signature::from_der(signature_bytes).or(Err(VerificationReason::Signature))?;

    let client_data_digest: [u8; 32] = Sha256::digest(client_data_json).into();
    // `verify_signature` is private and reached only through
    // `AssertionReplyV1`, which bounds authenticator data to 1,024 bytes.
    let message_length = authenticator_data.len() + client_data_digest.len();
    let mut signed_message = [0; SIGNED_MESSAGE_BYTES];
    signed_message[..authenticator_data.len()].copy_from_slice(authenticator_data);
    signed_message[authenticator_data.len()..message_length].copy_from_slice(&client_data_digest);
    verifying_key
        .verify(&signed_message[..message_length], &signature)
        .or(Err(VerificationReason::Signature))
}
