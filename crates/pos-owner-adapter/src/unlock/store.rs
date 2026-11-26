#![cfg(any(test, feature = "test-support"))]
//! The bound store's side of unlock: the ADR-097 §5 registry cross-check.

use pos_core::EntityId;
use pos_owner_bridge::{OwnerError, OwnerErrorKind};

use crate::enrollment::VolatileEnrollmentStore;

const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);

/// The registry read of unlock, injected into the unlock adapter.
///
/// The adapter calls it once, while opening, under the E16 lifetime lock and
/// the subject owner's shared session lock. Only
/// [`VolatileEnrollmentStore`] implements this trait until the protected
/// store implementation lands (#1373).
pub trait UnlockStore {
    /// The root fingerprint of the exact live registry identity.
    ///
    /// In one read snapshot, return the ADR-091 `key_material_digest` that
    /// the bound store's registry holds for the `SubjectDataEncryption`
    /// identity `(owner_id, subject_id, epoch)`, provided that identity is
    /// registered and live: active, or retained for historical decryption.
    ///
    /// # Errors
    /// Returns the store's failure. An absent, `DestructionPending` or
    /// `Destroyed` identity must refuse (ADR-091; ADR-097 §5 rejects new
    /// unlocks once destruction is pending), and so must an unreadable or
    /// malformed registry.
    fn registered_root_material_digest(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
        epoch: u64,
    ) -> Result<[u8; 32], OwnerError>;
}

/// The volatile store models no destruction, so each of its registrations is
/// live.
impl UnlockStore for VolatileEnrollmentStore {
    fn registered_root_material_digest(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
        epoch: u64,
    ) -> Result<[u8; 32], OwnerError> {
        self.registrations()
            .iter()
            .find(|registration| {
                registration.owner_id == owner_id
                    && registration.subject_id == subject_id
                    && registration.epoch == epoch
            })
            .map(|registration| registration.root_material_digest)
            .ok_or(REGISTRY)
    }
}
