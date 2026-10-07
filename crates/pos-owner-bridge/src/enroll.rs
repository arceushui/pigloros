//! Enrollment with confirmation (ADR-110 §8, D2): the port trait and its types.

use pos_owner_bridge_codec::{
    CoseEs256PublicKey, OwnerBridgeCodecError, OwnerUserHandle, SubjectCredentialBindingInputV1,
    SubjectCredentialBindingV1, SubjectId, TransportCodes,
};

use crate::ceremony::consume::protocol_from_codec;
use crate::ceremony::plan::{Assertion, Registration};
use crate::{BridgeError, OwnerError, PrfOutput};

/// The ADR-091 `key_material_digest` of a generated root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootFingerprint([u8; 32]);

impl RootFingerprint {
    /// Wrap the 32 digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compare two fingerprints without an early exit.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        let difference = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        difference == 0
    }
}

/// Who is enrolling: the owner, subject and epoch the new binding belongs to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentContext {
    /// The durable owner identifier.
    pub owner_id: String,
    /// The subject whose epoch owns the new credential.
    pub subject_id: SubjectId,
    /// The durable subject-key epoch.
    pub epoch: u64,
    /// The owning application window handle, when one exists.
    pub owner_window: Option<u64>,
}

/// A credential binding that only the bridge can construct, after D2 confirmation succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedBinding {
    owner_id: String,
    subject_id: SubjectId,
    epoch: u64,
    credential_id: Vec<u8>,
    user_handle: OwnerUserHandle,
    public_key: CoseEs256PublicKey,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
    transports: TransportCodes,
}

impl ConfirmedBinding {
    /// Build the binding from the registration and the confirmation assertion (ADR-097 A2: the
    /// committed BS and signCount are the confirmation's; BE is the registration's).
    pub(crate) fn from_confirmation(
        context: &EnrollmentContext,
        registration: &Registration,
        user_handle: OwnerUserHandle,
        confirmation: Assertion,
    ) -> Result<Self, BridgeError> {
        let confirmed = Self {
            owner_id: context.owner_id.clone(),
            subject_id: context.subject_id,
            epoch: context.epoch,
            credential_id: registration.credential_id.clone(),
            user_handle,
            public_key: registration.public_key,
            backup_eligible: registration.backup_eligible,
            backup_state: confirmation.backup_state,
            sign_count: confirmation.sign_count,
            transports: registration.transports,
        };
        confirmed.binding().map_err(protocol_from_codec)?;
        Ok(confirmed)
    }

    /// The validated `SubjectCredentialBindingV1` to stage.
    ///
    /// # Errors
    ///
    /// Returns the codec failure when a field violates the closed binding schema.
    pub fn binding(&self) -> Result<SubjectCredentialBindingV1<'_>, OwnerBridgeCodecError> {
        SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
            owner_id: &self.owner_id,
            subject_id: self.subject_id,
            epoch: self.epoch,
            credential_id: &self.credential_id,
            user_handle: self.user_handle,
            public_key: self.public_key,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            sign_count: self.sign_count,
            transports: self.transports,
        })
    }
}

/// The ADR-091 owner adapter's enrollment port; a fake implements it in tests.
///
/// Port methods run only after the ceremony's browser exit and `finish()`.
pub trait EnrollmentPort {
    /// The in-memory root and `SubjectKeyWrapV1`; never persisted before `commit`.
    type Candidate;

    /// `false` if any `SubjectCredentialBindingV1` (any subject, any epoch) holds this ID.
    ///
    /// # Errors
    ///
    /// Returns the adapter failure.
    fn credential_unbound(&mut self, credential_id: &[u8]) -> Result<bool, OwnerError>;

    /// Generate the root, build the wrap in memory, and return its fingerprint.
    ///
    /// # Errors
    ///
    /// Returns the adapter failure.
    fn seal_candidate(
        &mut self,
        prf: PrfOutput<'_>,
        context: &EnrollmentContext,
    ) -> Result<(Self::Candidate, RootFingerprint), OwnerError>;

    /// Return `Ok` only after an authenticated AES-GCM open under the PRF-derived key; the
    /// fingerprint is computed over the bytes that open produced.
    ///
    /// # Errors
    ///
    /// Returns the adapter failure for a wrong PRF, a tampered wrap or a tampered tag.
    fn confirm_candidate(
        &mut self,
        candidate: &Self::Candidate,
        prf: PrfOutput<'_>,
    ) -> Result<RootFingerprint, OwnerError>;

    /// Durably stage and register the confirmed binding; repeats the unbound check.
    ///
    /// # Errors
    ///
    /// Returns the adapter failure.
    fn commit(
        &mut self,
        candidate: Self::Candidate,
        binding: ConfirmedBinding,
    ) -> Result<(), OwnerError>;

    /// Zeroize and discard an enrollment that did not commit. `candidate` is `None` when the
    /// enrollment failed before `seal_candidate` returned or `commit` already consumed it.
    fn abandon(&mut self, candidate: Option<Self::Candidate>);
}
