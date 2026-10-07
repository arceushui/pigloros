//! The inputs and outputs of one ceremony.

use std::fmt;
use std::time::{Duration, Instant};

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerUserHandle, PrfInput, TransportCodes,
    WebAuthnChallenge,
};
use zeroize::Zeroizing;

use super::timing::ENROLLMENT_BUDGET;
use crate::{BridgeError, ProtocolCode, ReplyImage, RequestImage};

/// An enrollment budget: the ceremony fails once `limit` has passed since `start`.
///
/// Production code can only build the ADR-110 §8 budget of five minutes; the length is a
/// constant of the protocol, not configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    start: Instant,
    limit: Duration,
}

impl Budget {
    /// The ADR-110 §8 enrollment budget, running from `start` (E1 `Completed(ok)`).
    #[must_use]
    pub const fn enrollment(start: Instant) -> Self {
        Self {
            start,
            limit: ENROLLMENT_BUDGET,
        }
    }

    /// A budget of another length, so tests can reach the budget bound quickly.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn with_limit(start: Instant, limit: Duration) -> Self {
        Self { start, limit }
    }

    /// When the budget started.
    #[must_use]
    pub const fn start(self) -> Instant {
        self.start
    }

    /// The total time allowed.
    #[must_use]
    pub const fn limit(self) -> Duration {
        self.limit
    }
}

/// The stored credential a Get ceremony is restricted to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredGet {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) user_handle: OwnerUserHandle,
    pub(crate) public_key: CoseEs256PublicKey,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    pub(crate) sign_count: u32,
}

impl StoredGet {
    /// A stored credential, so tests can restrict a Get ceremony to it.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn new(
        credential_id: Vec<u8>,
        user_handle: OwnerUserHandle,
        public_key: CoseEs256PublicKey,
        backup_eligible: bool,
        backup_state: bool,
        sign_count: u32,
    ) -> Self {
        Self {
            credential_id,
            user_handle,
            public_key,
            backup_eligible,
            backup_state,
            sign_count,
        }
    }
}

/// Everything one ceremony needs, with the random block already drawn.
///
/// Only the bridge builds one. Its `Debug` output omits every secret: the challenge, the user
/// handle and the PRF input.
///
/// Those three secrets are stored in `Zeroizing` arrays that are wiped when the plan drops. The
/// protection is partial: the accessors copy them into `Copy` codec values (and the unlock
/// caller's PRF input arrives as a `Copy` `PrfInput`), and those copies are not wiped.
pub struct CeremonyPlan {
    pub(crate) kind: CeremonyKind,
    pub(crate) ceremony_id: CeremonyId,
    pub(crate) challenge: Zeroizing<[u8; 32]>,
    pub(crate) user_handle: Zeroizing<[u8; 32]>,
    pub(crate) prf_input: Zeroizing<[u8; 32]>,
    pub(crate) stored: Option<StoredGet>,
    pub(crate) t0: Instant,
    pub(crate) generation: u32,
    pub(crate) owner_window: Option<u64>,
    pub(crate) budget: Option<Budget>,
}

impl CeremonyPlan {
    /// The challenge the page will be asked to sign, as the codec type.
    ///
    /// The plan's own copy is wiped on drop, but every accessor returns a short-lived `Copy`
    /// codec value that is not wiped.
    #[must_use]
    pub fn challenge(&self) -> WebAuthnChallenge {
        WebAuthnChallenge::from_bytes(*self.challenge)
    }

    /// The user handle as the codec type.
    pub(crate) fn owner_user_handle(&self) -> OwnerUserHandle {
        OwnerUserHandle::from_bytes(*self.user_handle)
    }

    /// The PRF input as the codec type.
    pub(crate) fn prf_input_value(&self) -> PrfInput {
        PrfInput::from_bytes(*self.prf_input)
    }
}

impl fmt::Debug for CeremonyPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CeremonyPlan")
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .field("restricted", &self.stored.is_some())
            .field("budgeted", &self.budget.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "test-support")]
impl CeremonyPlan {
    /// A plan at generation 1 with no restriction, budget or owner window.
    #[must_use]
    pub fn for_test(
        kind: CeremonyKind,
        ceremony_id: CeremonyId,
        challenge: WebAuthnChallenge,
        user_handle: OwnerUserHandle,
        prf_input: PrfInput,
        t0: Instant,
    ) -> Self {
        Self {
            kind,
            ceremony_id,
            challenge: Zeroizing::new(*challenge.as_bytes()),
            user_handle: Zeroizing::new(*user_handle.as_bytes()),
            prf_input: Zeroizing::new(*prf_input.as_bytes()),
            stored: None,
            t0,
            generation: 1,
            owner_window: None,
            budget: None,
        }
    }

    /// Restrict the ceremony to `stored`, or to nothing.
    #[must_use]
    pub fn with_stored(self, stored: Option<StoredGet>) -> Self {
        Self { stored, ..self }
    }

    /// Start at `generation`.
    #[must_use]
    pub fn with_generation(self, generation: u32) -> Self {
        Self { generation, ..self }
    }

    /// Run under `budget`.
    #[must_use]
    pub fn with_budget(self, budget: Budget) -> Self {
        Self {
            budget: Some(budget),
            ..self
        }
    }

    /// The ceremony's identifier.
    #[must_use]
    pub const fn ceremony_id(&self) -> CeremonyId {
        self.ceremony_id
    }
}

/// A verified registration (Create) with every non-secret field the owner flow needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    /// The authenticated credential ID.
    pub credential_id: Vec<u8>,
    /// The validated public key.
    pub public_key: CoseEs256PublicKey,
    /// The page-reported transport hints.
    pub transports: TransportCodes,
    /// The registration backup-eligibility flag.
    pub backup_eligible: bool,
    /// The registration backup-state flag.
    pub backup_state: bool,
    /// The registration signature counter.
    pub sign_count: u32,
    /// Whether the create PRF result is held in the PRF slot.
    pub prf_present: bool,
}

/// A verified assertion (Get); its PRF result is held in the PRF slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Assertion {
    /// The accepted signature counter.
    pub sign_count: u32,
    /// The accepted backup-state flag.
    pub backup_state: bool,
}

/// The verified result of one ceremony.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verified {
    /// A Create ceremony result.
    Registration(Registration),
    /// A Get ceremony result.
    Assertion(Assertion),
}

impl Verified {
    /// The registration of a Create ceremony.
    ///
    /// # Errors
    ///
    /// Returns `Protocol(KindMismatch)` for an assertion.
    pub fn into_registration(self) -> Result<Registration, BridgeError> {
        match self {
            Self::Registration(registration) => Ok(registration),
            Self::Assertion(_) => Err(BridgeError::Protocol(ProtocolCode::KindMismatch)),
        }
    }

    /// The assertion of a Get ceremony.
    ///
    /// # Errors
    ///
    /// Returns `Protocol(KindMismatch)` for a registration.
    pub fn into_assertion(self) -> Result<Assertion, BridgeError> {
        match self {
            Self::Assertion(assertion) => Ok(assertion),
            Self::Registration(_) => Err(BridgeError::Protocol(ProtocolCode::KindMismatch)),
        }
    }
}

/// The buffers allocated once when the bridge is constructed and reused by every ceremony.
pub struct Slots {
    /// The request image written for each post.
    pub(crate) request: RequestImage,
    /// Copy A of the reply buffer.
    pub(crate) copy_a: ReplyImage,
    /// Copy B of the reply buffer.
    pub(crate) copy_b: ReplyImage,
    /// The PRF result of the latest verified ceremony.
    pub(crate) prf: Zeroizing<[u8; 32]>,
    /// The enrollment's source PRF (`P_c` or `P_s`).
    pub(crate) create_prf: Zeroizing<[u8; 32]>,
}

impl Slots {
    /// Allocate every buffer once.
    #[must_use]
    pub(crate) fn allocate() -> Box<Self> {
        Box::new(Self {
            request: RequestImage::zeroed(),
            copy_a: ReplyImage::zeroed(),
            copy_b: ReplyImage::zeroed(),
            prf: Zeroizing::new([0; 32]),
            create_prf: Zeroizing::new([0; 32]),
        })
    }

    /// Zero both reply copies. The PRF slots are not touched.
    pub(crate) fn wipe_copies(&mut self) {
        self.copy_a.wipe();
        self.copy_b.wipe();
    }

    /// Zero both reply copies and the ceremony PRF slot. The enrollment slot is not touched.
    pub(crate) fn wipe_ceremony(&mut self) {
        self.wipe_copies();
        self.prf.fill(0);
    }

    /// Zero every secret slot.
    pub(crate) fn wipe_all(&mut self) {
        self.wipe_ceremony();
        self.create_prf.fill(0);
    }
}

#[cfg(test)]
mod tests;
