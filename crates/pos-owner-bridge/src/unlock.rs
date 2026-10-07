//! Unlock (ADR-110 §8): the port trait and its types.

use crate::{OwnerError, PrfOutput};

/// The signature counter and backup state an accepted assertion must persist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingUpdate {
    /// The accepted signature counter.
    pub sign_count: u32,
    /// The accepted backup-state flag.
    pub backup_state: bool,
}

/// The ADR-091 owner adapter's unlock port; a fake implements it in tests.
///
/// Port methods run only after the ceremony's browser exit and `finish()`.
pub trait UnlockPort {
    /// A root unwrapped but not yet released.
    ///
    /// The bridge drops it unreleased when `persist_binding_update` fails, so an implementation
    /// must zeroize the root on drop.
    type Pending;
    /// The unlocked session.
    type Session;

    /// Unwrap under the PRF-derived key without releasing.
    ///
    /// # Errors
    ///
    /// Returns the adapter failure.
    fn open_pending(&mut self, prf: PrfOutput<'_>) -> Result<Self::Pending, OwnerError>;

    /// Durably write the accepted counter and backup state.
    ///
    /// # Errors
    ///
    /// Returns the adapter failure; no root is released.
    fn persist_binding_update(&mut self, update: &BindingUpdate) -> Result<(), OwnerError>;

    /// Release the unwrapped root as a session.
    fn release(&mut self, pending: Self::Pending) -> Self::Session;
}
