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

use pos_core::community_lifecycle::{
    CommunityAuthorityViewRowV1, CommunityClockLatchV1, CommunityLifecycleErrorV1 as Error,
};
use pos_core::trusted_clock::{
    reserve_trusted_clock, GuardMonotonicSourceV1, TrustedClockReservationV1, TrustedWallSourceV1,
    WaitBudgetV1,
};
use pos_core::{
    AuthorityPersistencePortV1, AuthorizationRequestV1, CapabilityGrantV1, Hash,
    PersistedAuthorityV1,
};

use super::private_hash::authority_bindings_digest;
#[cfg(target_os = "linux")]
use crate::plugin_trust_registry::{
    ActiveReleaseV1, PluginTrustPolicyRegistryV1, RetainedPolicyStateV1,
};

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

    /// The domain's current community inventory generation (owner decision
    /// on #560, note 22722, G5): 0 at bootstrap, incremented once per
    /// committed inventory effect, read into CAU1 and compared-and-swapped
    /// with CSI1 on commit.
    fn inventory_generation(&self) -> u64;

    /// The CAV1 `clock_latch` of this domain's installed trusted clock: its
    /// overrun count and whether it is latched (ADR-129 §3).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when no latch row is committed yet or
    /// the row is out of range.
    fn clock_latch(&self) -> Result<CommunityClockLatchV1, Error>;

    /// The Plugin trust state of `(scope, plugin_id)` in this domain's own
    /// `PluginTrustPolicyRegistryV1` (R6.5(1)): the retained policy state
    /// and the active release, if any.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a missing scope or any registry
    /// error (R6.5(4)).
    #[cfg(target_os = "linux")]
    fn plugin_trust(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> Result<(RetainedPolicyStateV1, Option<ActiveReleaseV1>), Error>;

    /// The CAV1 authority row of the chain `leaf_grant_id` names, read now
    /// from this domain's own authority store (ADR-129 §3, R6.7).
    ///
    /// T is the leaf's authority Timeline; head and epoch are the
    /// persisted ones read with the chain. The registry digest and policy
    /// revisions are the CAP1-pinned values the evaluated request carried.
    /// The binding digest covers the chain's current, re-stamped CPG1
    /// binding digests, root to leaf, and the BLAKE3 of each persisted
    /// canonical CRF1, in persisted order (owner decision on #560,
    /// 2026-11-19).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for an unloadable chain or record.
    fn authority_row(
        &self,
        leaf_grant_id: Hash,
        pins: &AuthorizationRequestV1,
    ) -> Result<CommunityAuthorityViewRowV1, Error> {
        self.load_authority(leaf_grant_id).and_then(|persisted| {
            let grants = persisted.chain().grants();
            grants
                .iter()
                .map(CapabilityGrantV1::binding_digest)
                .collect::<Result<Vec<_>, _>>()
                .ok()
                .zip(
                    persisted
                        .revocations()
                        .iter()
                        .map(|revocation| {
                            revocation.encode().map(|bytes| {
                                Hash::from_bytes(*blake3::hash(bytes.as_slice()).as_bytes())
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .ok(),
                )
                .and_then(|(grant_digests, revocation_digests)| {
                    authority_bindings_digest(&grant_digests, &revocation_digests)
                })
                .zip(grants.last())
                .map(|(binding_digest, leaf)| CommunityAuthorityViewRowV1 {
                    authority_timeline: leaf.issuance_timeline(),
                    head_seq: persisted.head_position().as_u64(),
                    revocation_epoch: persisted.revocation_epoch(),
                    registry_digest: pins.authority_registry_digest(),
                    capability_policy_revision: pins.capability_policy_revision(),
                    consent_policy_revision: pins.consent_policy_revision(),
                    binding_digest,
                })
                .ok_or(Error::EvidenceUnavailable)
        })
    }
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

    fn reserve_clock(
        &mut self,
        wall: &mut dyn TrustedWallSourceV1,
        mono: &mut dyn GuardMonotonicSourceV1,
    ) -> Result<TrustedClockReservationV1, Error> {
        reserve_trusted_clock(&mut self.clock, wall, mono, &mut WaitBudgetV1::new(), None)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }

    fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    fn clock_latch(&self) -> Result<CommunityClockLatchV1, Error> {
        self.clock
            .rows()
            .overrun_latch
            .first()
            .and_then(|row| {
                u64::try_from(row.overrun_count)
                    .ok()
                    .map(|overrun_count| CommunityClockLatchV1 {
                        overrun_count,
                        latched: row.latched != 0,
                    })
            })
            .ok_or(Error::EvidenceUnavailable)
    }

    #[cfg(target_os = "linux")]
    fn plugin_trust(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> Result<(RetainedPolicyStateV1, Option<ActiveReleaseV1>), Error> {
        self.store
            .retained_policy_state(scope)
            .ok()
            .zip(self.store.active_release(scope, plugin_id).ok())
            .ok_or(Error::EvidenceUnavailable)
    }
}
