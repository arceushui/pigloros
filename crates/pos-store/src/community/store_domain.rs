//! The crate-private store-domain seam (owner decision on #560, note 22571;
//! split in note 22722).
//!
//! It is the one interface through which the installed community owners
//! reach a backend's protected domain. It is an implementation detail of
//! ADR-129 §1 "sealed persistence", not an authority trait: it exposes the
//! domain's store incarnation, the guarded load of a persisted grant chain
//! and a reservation on the domain's own trusted clock, and every decision
//! is still evaluated by the installed owner itself (A5.9).
//!
//! The trait is nominally `pub` only because the public evaluator methods
//! are generic over it, and a `pub(super)` bound on a public method trips the
//! denied `private_bounds` lint. It lives in this private module and is
//! re-exported nowhere, so no caller outside `community` can name or
//! implement it: §1 ("no caller-implemented authority trait") and R6.2(6)
//! still hold. [`MemoryCommunityDomainV1`] is its only implementation; the
//! `SQLite` domain adds the second in Stack B (A5.6, R6.10 parity).

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
use pos_core::trusted_clock::{
    reserve_trusted_clock, GuardMonotonicSourceV1, TrustedClockReservationV1, TrustedWallSourceV1,
    WaitBudgetV1,
};
use pos_core::{AuthorityPersistencePortV1, Hash, PersistedAuthorityV1};

use super::memory_domain::MemoryCommunityDomainV1;

/// One backend's protected community domain, as its installed owners see
/// it.
pub trait CommunityStoreDomainV1 {
    /// The nonzero incarnation naming this domain's protected store.
    fn store_incarnation(&self) -> [u8; 16];

    /// Load the persisted grant chain whose leaf is `leaf_grant_id` from
    /// this domain's own authority store, under the domain's guard.
    ///
    /// `leaf_grant_id` is an untrusted locator: the chain is evidence for
    /// the owner's own evaluation, never a decision.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a missing, foreign or unloadable
    /// chain (A5.5).
    fn load_authority(&self, leaf_grant_id: Hash) -> Result<PersistedAuthorityV1, Error>;

    /// Commit one ADR-112 trusted-clock reservation on this domain's own
    /// installed clock authority, with a fresh wait budget and no owner
    /// lock. Its sample `t_r` is the operation's one trusted sample (owner
    /// decision on #560, note 22722, G1).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for every reservation failure: no
    /// trusted wall sample, a rollback, a latched overrun or a storage
    /// failure (A5.5).
    fn reserve_clock(
        &mut self,
        wall: &mut dyn TrustedWallSourceV1,
        mono: &mut dyn GuardMonotonicSourceV1,
    ) -> Result<TrustedClockReservationV1, Error>;
}

impl CommunityStoreDomainV1 for MemoryCommunityDomainV1 {
    fn store_incarnation(&self) -> [u8; 16] {
        self.store_incarnation
    }

    fn load_authority(&self, leaf_grant_id: Hash) -> Result<PersistedAuthorityV1, Error> {
        self.store
            .load_authority(leaf_grant_id)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }

    fn reserve_clock(
        &mut self,
        wall: &mut dyn TrustedWallSourceV1,
        mono: &mut dyn GuardMonotonicSourceV1,
    ) -> Result<TrustedClockReservationV1, Error> {
        reserve_trusted_clock(&mut self.clock, wall, mono, &mut WaitBudgetV1::new(), None)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }
}
