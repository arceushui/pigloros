//! The inputs and outputs of one ceremony.

use std::time::{Duration, Instant};

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerUserHandle, PrfInput, TransportCodes,
    WebAuthnChallenge,
};
use zeroize::Zeroizing;

use crate::{BridgeError, ProtocolCode, ReplyImage, RequestImage};

/// An enrollment budget: the ceremony fails once `limit` has passed since `start`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    /// When the budget started (E1 `Completed(ok)`).
    pub start: Instant,
    /// The total time allowed.
    pub limit: Duration,
}

/// The stored credential a Get ceremony is restricted to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredGet {
    /// The one allowed credential ID.
    pub credential_id: Vec<u8>,
    /// The stored user handle.
    pub user_handle: OwnerUserHandle,
    /// The stored public key.
    pub public_key: CoseEs256PublicKey,
    /// The stored backup-eligibility flag.
    pub backup_eligible: bool,
    /// The stored backup-state flag.
    pub backup_state: bool,
    /// The latest accepted signature counter.
    pub sign_count: u32,
}

/// Everything one ceremony needs, with the random block already drawn.
#[derive(Clone, Debug)]
pub struct CeremonyPlan {
    /// Create or Get.
    pub kind: CeremonyKind,
    /// The one-use ceremony ID.
    pub ceremony_id: CeremonyId,
    /// The one-use challenge.
    pub challenge: WebAuthnChallenge,
    /// The user handle (Create only; unused for Get).
    pub user_handle: OwnerUserHandle,
    /// The PRF input.
    pub prf_input: PrfInput,
    /// The restricted credential (`Some` for Get).
    pub stored: Option<StoredGet>,
    /// T0: the successful CSPRNG fill of the random block.
    pub t0: Instant,
    /// The host generation of the first post.
    pub generation: u32,
    /// The owning application window handle, when one exists.
    pub owner_window: Option<u64>,
    /// The enrollment budget, when this ceremony is part of an enrollment.
    pub budget: Option<Budget>,
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
    pub request: RequestImage,
    /// Copy A of the reply buffer.
    pub copy_a: ReplyImage,
    /// Copy B of the reply buffer.
    pub copy_b: ReplyImage,
    /// The PRF result of the latest verified ceremony.
    pub prf: Zeroizing<[u8; 32]>,
    /// The enrollment's source PRF (`P_c` or `P_s`).
    pub create_prf: Zeroizing<[u8; 32]>,
}

impl Slots {
    /// Allocate every buffer once.
    #[must_use]
    pub fn allocate() -> Box<Self> {
        Box::new(Self {
            request: RequestImage::zeroed(),
            copy_a: ReplyImage::zeroed(),
            copy_b: ReplyImage::zeroed(),
            prf: Zeroizing::new([0; 32]),
            create_prf: Zeroizing::new([0; 32]),
        })
    }

    /// Zero both reply copies. The PRF slots are not touched.
    pub fn wipe_copies(&mut self) {
        self.copy_a.wipe();
        self.copy_b.wipe();
    }

    /// Zero both reply copies and the ceremony PRF slot. The enrollment slot is not touched.
    pub fn wipe_ceremony(&mut self) {
        self.wipe_copies();
        self.prf.fill(0);
    }

    /// Zero every secret slot.
    pub fn wipe_all(&mut self) {
        self.wipe_ceremony();
        self.create_prf.fill(0);
    }
}
