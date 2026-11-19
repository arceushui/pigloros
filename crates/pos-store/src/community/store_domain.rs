//! The crate-private store-domain seam (owner decision on #560, note 22571;
//! split in note 22722).
//!
//! It is the one interface through which the installed community owners
//! reach a backend's protected domain. It is an implementation detail of
//! ADR-129 §1 "sealed persistence", not an authority trait: it exposes only
//! the domain's store incarnation and the guarded load of a persisted grant
//! chain, and every decision is still evaluated by the installed owner
//! itself (A5.9).
//!
//! The trait is nominally `pub` only because the public evaluator methods
//! are generic over it, and a `pub(super)` bound on a public method trips the
//! denied `private_bounds` lint. It lives in this private module and is
//! re-exported nowhere, so no caller outside `community` can name or
//! implement it: §1 ("no caller-implemented authority trait") and R6.2(6)
//! still hold. [`MemoryCommunityDomainV1`] is its only implementation; the
//! `SQLite` domain adds the second in Stack B (A5.6, R6.10 parity).

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
use pos_core::{AuthorityPersistencePortV1, Hash, PersistedAuthorityV1};

use super::memory_domain::MemoryCommunityDomainV1;

/// One backend's protected community domain, as its installed owners see
/// it.
pub trait CommunityStoreDomainV1 {
    /// The nonzero incarnation naming this domain's protected store.
    fn store_incarnation(&self) -> [u8; 16];

    /// Load the persisted grant chain whose leaf is `leaf_grant_id` from
    /// this domain's own authority store.
    ///
    /// `leaf_grant_id` is an untrusted locator: the chain is evidence for
    /// the owner's own evaluation, never a decision.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a missing, foreign or unloadable
    /// chain (A5.5).
    fn load_authority(&self, leaf_grant_id: Hash) -> Result<PersistedAuthorityV1, Error>;
}

impl CommunityStoreDomainV1 for MemoryCommunityDomainV1 {
    fn store_incarnation(&self) -> [u8; 16] {
        Self::store_incarnation(self)
    }

    fn load_authority(&self, leaf_grant_id: Hash) -> Result<PersistedAuthorityV1, Error> {
        self.store
            .load_authority(leaf_grant_id)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }
}
