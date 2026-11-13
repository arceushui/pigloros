//! Persistent Gateway execution-mode binding of one store (ADR-134 §8).
//!
//! A store records the one Gateway execution-mode profile it serves
//! under, with a `binding_epoch` that starts at 1 and increments on every
//! rotation and migration. The core holds only a neutral, bounded profile
//! reference: it never sees the profile record bytes, strings or meaning, which stay private
//! to the Gateway.
//!
//! Every binding change needs an opaque permit that only the trusted host
//! composition root mints through [`GatewayModeBindingHostV1`]. An adapter
//! instance attaches the binding's epoch before its first write; its one
//! append choke point then refuses, with
//! [`crate::CoreError::ModeBindingStale`], any Event write whose attached
//! epoch differs from the persisted one or that an unattached instance makes
//! to a bound store.

use std::num::NonZeroU64;

use crate::{Seq, TimelineId};

/// Maximum UTF-8 bytes of one bound profile identifier.
pub const MAX_GATEWAY_MODE_PROFILE_ID_BYTES: usize = 64;

/// Closed failures of the store mode-binding port.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GatewayModeBindingErrorV1 {
    /// A profile reference or persisted binding record is malformed.
    #[error("gateway mode binding record is invalid")]
    InvalidRecord,
    /// The store has no binding.
    #[error("store is not bound to a gateway execution mode")]
    Unbound,
    /// The store holds records but no binding, so it can never be bound.
    #[error("store is populated but not bound to a gateway execution mode")]
    PopulatedUnbound,
    /// The store is already bound.
    #[error("store is already bound to a gateway execution mode")]
    AlreadyBound,
    /// The persisted binding is not the one the change starts from.
    #[error("store is bound to a different gateway execution mode")]
    Mismatch,
    /// The adapter cannot read or commit the binding.
    #[error("gateway mode binding is unavailable")]
    Unavailable,
}

/// Neutral reference to one Gateway execution-mode profile: a bounded
/// identifier and the profile's 32-byte digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayModeProfileRefV1 {
    profile_id: String,
    profile_digest: [u8; 32],
}

impl GatewayModeProfileRefV1 {
    /// Bind a profile identifier of 1 to [`MAX_GATEWAY_MODE_PROFILE_ID_BYTES`]
    /// lower-case ASCII letters, digits or hyphens to its digest.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::InvalidRecord`] for an empty,
    /// oversized or non-canonical identifier.
    pub fn try_new(
        profile_id: &str,
        profile_digest: [u8; 32],
    ) -> Result<Self, GatewayModeBindingErrorV1> {
        let canonical = (1..=MAX_GATEWAY_MODE_PROFILE_ID_BYTES).contains(&profile_id.len())
            && profile_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        canonical
            .then(|| Self {
                profile_id: profile_id.to_owned(),
                profile_digest,
            })
            .ok_or(GatewayModeBindingErrorV1::InvalidRecord)
    }

    /// The bounded profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// The profile's 32-byte digest.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
}

/// One persisted binding: the profile and the epoch it was bound at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayModeBindingRecordV1 {
    profile: GatewayModeProfileRefV1,
    binding_epoch: NonZeroU64,
}

impl GatewayModeBindingRecordV1 {
    /// Pair a profile with the epoch it is bound at.
    #[must_use]
    pub const fn new(profile: GatewayModeProfileRefV1, binding_epoch: NonZeroU64) -> Self {
        Self {
            profile,
            binding_epoch,
        }
    }

    /// The bound profile.
    #[must_use]
    pub const fn profile(&self) -> &GatewayModeProfileRefV1 {
        &self.profile
    }

    /// The epoch this binding was recorded at.
    #[must_use]
    pub const fn binding_epoch(&self) -> NonZeroU64 {
        self.binding_epoch
    }
}

/// Which change recorded one binding-history entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayModeBindingKindV1 {
    /// The first binding of an empty store.
    Bind,
    /// A one-hop revision of the same profile identifier.
    Rotate,
    /// An explicit operator migration to another profile identifier.
    Migrate,
}

impl GatewayModeBindingKindV1 {
    /// The persisted code: 1 bind, 2 rotate, 3 migrate.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Bind => 1,
            Self::Rotate => 2,
            Self::Migrate => 3,
        }
    }

    /// Decode a persisted code.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::InvalidRecord`] for any other code.
    pub const fn from_code(code: u8) -> Result<Self, GatewayModeBindingErrorV1> {
        match code {
            1 => Ok(Self::Bind),
            2 => Ok(Self::Rotate),
            3 => Ok(Self::Migrate),
            _ => Err(GatewayModeBindingErrorV1::InvalidRecord),
        }
    }
}

/// One immutable binding-history entry. The entry of an epoch never changes,
/// so a disclosure resolved through it stays stable across later changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayModeBindingHistoryEntryV1 {
    record: GatewayModeBindingRecordV1,
    kind: GatewayModeBindingKindV1,
}

impl GatewayModeBindingHistoryEntryV1 {
    /// Pair a binding record with the change that recorded it.
    #[must_use]
    pub const fn new(record: GatewayModeBindingRecordV1, kind: GatewayModeBindingKindV1) -> Self {
        Self { record, kind }
    }

    /// The binding recorded at this epoch.
    #[must_use]
    pub const fn record(&self) -> &GatewayModeBindingRecordV1 {
        &self.record
    }

    /// The change that recorded it.
    #[must_use]
    pub const fn kind(&self) -> GatewayModeBindingKindV1 {
        self.kind
    }
}

/// Opaque capability to bind one empty store to `to` at epoch 1.
#[derive(Debug)]
pub struct GatewayModeBindPermitV1 {
    to: GatewayModeProfileRefV1,
}

impl GatewayModeBindPermitV1 {
    /// The profile the store is bound to.
    #[must_use]
    pub const fn to(&self) -> &GatewayModeProfileRefV1 {
        &self.to
    }
}

/// Opaque capability for a one-hop rotation: the same profile identifier
/// with a new digest.
#[derive(Debug)]
pub struct GatewayModeRotationPermitV1 {
    from: GatewayModeProfileRefV1,
    to: GatewayModeProfileRefV1,
}

impl GatewayModeRotationPermitV1 {
    /// The binding the store must currently hold.
    #[must_use]
    pub const fn from(&self) -> &GatewayModeProfileRefV1 {
        &self.from
    }

    /// The profile the store is bound to after the rotation.
    #[must_use]
    pub const fn to(&self) -> &GatewayModeProfileRefV1 {
        &self.to
    }
}

/// Opaque capability for an explicit operator migration to another profile
/// identifier.
#[derive(Debug)]
pub struct GatewayModeMigrationPermitV1 {
    from: GatewayModeProfileRefV1,
    to: GatewayModeProfileRefV1,
}

impl GatewayModeMigrationPermitV1 {
    /// The binding the store must currently hold.
    #[must_use]
    pub const fn from(&self) -> &GatewayModeProfileRefV1 {
        &self.from
    }

    /// The profile the store is bound to after the migration.
    #[must_use]
    pub const fn to(&self) -> &GatewayModeProfileRefV1 {
        &self.to
    }
}

/// Host-composition owner of the store mode-binding capability.
///
/// Constructing this value declares that the caller is the trusted
/// composition root of the store it binds. The host must not expose this
/// owner or its permits to Plugin code.
#[derive(Debug)]
pub struct GatewayModeBindingHostV1 {
    _composition_root: (),
}

impl GatewayModeBindingHostV1 {
    /// Declare the trusted composition root.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _composition_root: (),
        }
    }

    /// Authorize binding an empty store to `to`.
    #[must_use]
    pub const fn authorize_bind(&self, to: GatewayModeProfileRefV1) -> GatewayModeBindPermitV1 {
        GatewayModeBindPermitV1 { to }
    }

    /// Authorize a one-hop rotation: the same profile identifier with a new
    /// digest.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::Mismatch`] when the identifiers
    /// differ or the digests are equal.
    pub fn authorize_rotation(
        &self,
        from: GatewayModeProfileRefV1,
        to: GatewayModeProfileRefV1,
    ) -> Result<GatewayModeRotationPermitV1, GatewayModeBindingErrorV1> {
        (from.profile_id == to.profile_id && from.profile_digest != to.profile_digest)
            .then_some(GatewayModeRotationPermitV1 { from, to })
            .ok_or(GatewayModeBindingErrorV1::Mismatch)
    }

    /// Authorize an explicit operator migration to another profile
    /// identifier.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::Mismatch`] when the identifiers are
    /// equal.
    pub fn authorize_migration(
        &self,
        from: GatewayModeProfileRefV1,
        to: GatewayModeProfileRefV1,
    ) -> Result<GatewayModeMigrationPermitV1, GatewayModeBindingErrorV1> {
        (from.profile_id != to.profile_id)
            .then_some(GatewayModeMigrationPermitV1 { from, to })
            .ok_or(GatewayModeBindingErrorV1::Mismatch)
    }
}

impl Default for GatewayModeBindingHostV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Store port for the persistent Gateway execution-mode binding.
///
/// Every binding change is one durable transaction. A successful bind,
/// attach, rotation or migration attaches the resulting epoch to this adapter
/// instance; from then on the adapter's append choke point records the
/// attached epoch for every committed Event range and refuses a write when
/// the persisted epoch differs.
pub trait GatewayModeBindingPortV1 {
    /// Bind an empty store (no Events, authority, `OwnTracks`, Fork-authority
    /// or binding records) to the permit's profile at epoch 1.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::AlreadyBound`] for a bound store,
    /// [`GatewayModeBindingErrorV1::PopulatedUnbound`] for a populated one, and
    /// [`GatewayModeBindingErrorV1::Unavailable`] when the adapter cannot commit.
    fn bind_empty_store_mode(
        &mut self,
        permit: GatewayModeBindPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1>;

    /// Attach the persisted binding's epoch to this adapter instance.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::Unbound`] for an unbound store and a
    /// closed invalid-record or unavailable error when the binding cannot be
    /// trusted or read.
    fn attach_mode_binding(
        &mut self,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1>;

    /// Rotate the binding one hop: epoch + 1 and a history entry of kind
    /// [`GatewayModeBindingKindV1::Rotate`].
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::Unbound`] for an unbound store,
    /// [`GatewayModeBindingErrorV1::Mismatch`] when the persisted binding is
    /// not the permit's `from`, and a closed unavailable error when the
    /// adapter cannot commit.
    fn rotate_mode(
        &mut self,
        permit: GatewayModeRotationPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1>;

    /// Migrate the binding to another profile: epoch + 1 and a history entry
    /// of kind [`GatewayModeBindingKindV1::Migrate`].
    ///
    /// # Errors
    /// Returns the errors of [`Self::rotate_mode`].
    fn migrate_mode(
        &mut self,
        permit: GatewayModeMigrationPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1>;

    /// Load the current binding, if any.
    ///
    /// # Errors
    /// Returns a closed invalid-record or unavailable error.
    fn load_mode_binding(
        &self,
    ) -> Result<Option<GatewayModeBindingRecordV1>, GatewayModeBindingErrorV1>;

    /// Load every binding-history entry in epoch order.
    ///
    /// # Errors
    /// Returns a closed invalid-record or unavailable error.
    fn load_mode_binding_history(
        &self,
    ) -> Result<Vec<GatewayModeBindingHistoryEntryV1>, GatewayModeBindingErrorV1>;

    /// Load the epoch recorded for the commit that wrote segment-local
    /// sequence `local_seq` of `timeline`, or `None` when no commit-epoch
    /// record covers it (an Event written while the store was unbound).
    ///
    /// # Errors
    /// Returns a closed invalid-record or unavailable error.
    fn load_commit_epoch(
        &self,
        timeline: TimelineId,
        local_seq: Seq,
    ) -> Result<Option<NonZeroU64>, GatewayModeBindingErrorV1>;
}

/// The append choke point's decision for one Event range.
///
/// `persisted` is the store's current binding epoch, `attached` the epoch
/// attached to the writing adapter instance.
///
/// # Errors
/// Returns [`crate::CoreError::ModeBindingStale`] when the store is bound and
/// the writer is unattached or attached to another epoch, or when the writer
/// is attached and the store holds no binding.
pub fn commit_epoch_for_append_v1(
    persisted: Option<NonZeroU64>,
    attached: Option<NonZeroU64>,
) -> Result<Option<NonZeroU64>, crate::CoreError> {
    if persisted == attached {
        Ok(persisted)
    } else {
        Err(crate::CoreError::ModeBindingStale)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn profile(id: &str, byte: u8) -> GatewayModeProfileRefV1 {
        GatewayModeProfileRefV1::try_new(id, [byte; 32])
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
    }

    #[test]
    fn profile_identifiers_are_bounded_canonical_text() {
        let longest = "a".repeat(MAX_GATEWAY_MODE_PROFILE_ID_BYTES);
        assert!(GatewayModeProfileRefV1::try_new(&longest, [0; 32]).is_ok());
        assert!(GatewayModeProfileRefV1::try_new("gateway-mode-local-v1", [0; 32]).is_ok());
        for invalid in [
            String::new(),
            "a".repeat(MAX_GATEWAY_MODE_PROFILE_ID_BYTES + 1),
            "Upper".to_owned(),
            "under_score".to_owned(),
            "space d".to_owned(),
        ] {
            assert_eq!(
                GatewayModeProfileRefV1::try_new(&invalid, [0; 32]),
                Err(GatewayModeBindingErrorV1::InvalidRecord)
            );
        }
        let reference = profile("gateway-mode-local-v1", 7);
        assert_eq!(reference.profile_id(), "gateway-mode-local-v1");
        assert_eq!(reference.profile_digest(), [7; 32]);
    }

    #[test]
    fn kind_codes_round_trip_and_reject_unknown_codes() {
        for kind in [
            GatewayModeBindingKindV1::Bind,
            GatewayModeBindingKindV1::Rotate,
            GatewayModeBindingKindV1::Migrate,
        ] {
            assert_eq!(GatewayModeBindingKindV1::from_code(kind.code()), Ok(kind));
        }
        assert_eq!(GatewayModeBindingKindV1::Bind.code(), 1);
        assert_eq!(GatewayModeBindingKindV1::Rotate.code(), 2);
        assert_eq!(GatewayModeBindingKindV1::Migrate.code(), 3);
        for code in [0, 4, u8::MAX] {
            assert_eq!(
                GatewayModeBindingKindV1::from_code(code),
                Err(GatewayModeBindingErrorV1::InvalidRecord)
            );
        }
    }

    #[test]
    fn records_and_history_entries_keep_their_fields() {
        let record = GatewayModeBindingRecordV1::new(profile("p", 1), NonZeroU64::MIN);
        assert_eq!(record.profile(), &profile("p", 1));
        assert_eq!(record.binding_epoch(), NonZeroU64::MIN);
        let entry =
            GatewayModeBindingHistoryEntryV1::new(record.clone(), GatewayModeBindingKindV1::Rotate);
        assert_eq!(entry.record(), &record);
        assert_eq!(entry.kind(), GatewayModeBindingKindV1::Rotate);
    }

    #[test]
    fn the_host_mints_only_well_formed_changes() {
        let host = GatewayModeBindingHostV1::default();
        assert_eq!(host.authorize_bind(profile("a", 1)).to(), &profile("a", 1));

        let rotation = host.authorize_rotation(profile("a", 1), profile("a", 2));
        let rotation =
            rotation.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
        assert_eq!(rotation.from(), &profile("a", 1));
        assert_eq!(rotation.to(), &profile("a", 2));
        for (from, to) in [
            (profile("a", 1), profile("a", 1)),
            (profile("a", 1), profile("b", 2)),
        ] {
            assert_eq!(
                host.authorize_rotation(from, to).err(),
                Some(GatewayModeBindingErrorV1::Mismatch)
            );
        }

        let migration = host.authorize_migration(profile("a", 1), profile("b", 1));
        let migration = migration
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
        assert_eq!(migration.from(), &profile("a", 1));
        assert_eq!(migration.to(), &profile("b", 1));
        assert_eq!(
            host.authorize_migration(profile("a", 1), profile("a", 2))
                .err(),
            Some(GatewayModeBindingErrorV1::Mismatch)
        );
    }

    #[test]
    fn the_choke_point_admits_only_matching_epochs() {
        let one = NonZeroU64::MIN;
        let two = NonZeroU64::MIN.saturating_add(1);
        assert_eq!(commit_epoch_for_append_v1(None, None).ok(), Some(None));
        assert_eq!(
            commit_epoch_for_append_v1(Some(two), Some(two)).ok(),
            Some(Some(two))
        );
        for (persisted, attached) in [
            (Some(one), None),
            (None, Some(one)),
            (Some(two), Some(one)),
            (Some(one), Some(two)),
        ] {
            assert!(matches!(
                commit_epoch_for_append_v1(persisted, attached),
                Err(crate::CoreError::ModeBindingStale)
            ));
        }
    }

    #[test]
    fn errors_have_closed_messages() {
        for error in [
            GatewayModeBindingErrorV1::InvalidRecord,
            GatewayModeBindingErrorV1::Unbound,
            GatewayModeBindingErrorV1::PopulatedUnbound,
            GatewayModeBindingErrorV1::AlreadyBound,
            GatewayModeBindingErrorV1::Mismatch,
            GatewayModeBindingErrorV1::Unavailable,
        ] {
            assert!(error.to_string().contains("gateway") || error.to_string().contains("store"));
        }
    }
}
