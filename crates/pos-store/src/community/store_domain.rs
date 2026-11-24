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
    community_authority_bindings_digest_v1, CommunityAuthorityViewRowV1, CommunityClockLatchV1,
    CommunityLifecycleErrorV1 as Error,
};
use pos_core::hasher::Hasher;
use pos_core::store::EventStore;
#[cfg(target_os = "linux")]
use pos_core::trusted_clock::open_release_guard;
use pos_core::trusted_clock::{
    reserve_trusted_clock, GuardMonotonicSourceV1, TrustedClockReservationV1, TrustedWallSourceV1,
    WaitBudgetV1,
};
#[cfg(target_os = "linux")]
use pos_core::WallTime;
use pos_core::{
    AuthorityPersistencePortV1, AuthorizationRequestV1, CapabilityGrantV1, Hash,
    PersistedAuthorityV1,
};

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

    /// The final writer's decision-bound check on this domain's own clock
    /// (A5.4; owner decision on #560, 2026-11-20, item 1).
    ///
    /// It opens the ADR-112 release guard for `reservation`, the operation's
    /// one reservation, and takes the writer's time as the reservation
    /// sample `t_r` plus the `mono` time elapsed since the guard start.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when the guard cannot open, the
    /// monotonic source rolls back, or the writer's time is at or after
    /// `bound` (A5.5).
    #[cfg(target_os = "linux")]
    fn check_writer_bound(
        &mut self,
        reservation: TrustedClockReservationV1,
        mono: &mut dyn GuardMonotonicSourceV1,
        bound: WallTime,
    ) -> Result<(), Error>;

    /// The domain's own Event history and the pinned Hasher its chains are
    /// built with: the store-side re-check of an observation (ADR-129
    /// revision 9, R9.6). Reads keep the store's own erasure fences.
    fn event_history(&self) -> (&dyn EventStore, &dyn Hasher);

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

    /// The retained policy state of `scope` in this domain's own
    /// `PluginTrustPolicyRegistryV1` (R6.5(1)).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a missing scope or any registry
    /// error (R6.5(4)).
    #[cfg(target_os = "linux")]
    fn plugin_trust_policy(&self, scope: &str) -> Result<RetainedPolicyStateV1, Error>;

    /// The active release of `(scope, plugin_id)` in the same registry, if
    /// any.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a missing scope or any registry
    /// error (R6.5(4)).
    #[cfg(target_os = "linux")]
    fn active_release(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> Result<Option<ActiveReleaseV1>, Error>;

    /// The CAV1 authority row of the chain `leaf_grant_id` names, read now
    /// from this domain's own authority store (ADR-129 §3, R6.7).
    ///
    /// T is the leaf's authority Timeline; head and epoch are the
    /// persisted ones read with the chain. The registry digest and policy
    /// revisions are the CAP1-pinned values the evaluated request carried.
    /// The binding digest covers the chain's current, re-stamped CPG1
    /// binding digests, root to leaf (owner decision 12), and each persisted
    /// CRF1's digest in persisted Timeline order. A CRF1 digest is the
    /// BLAKE3 of its canonical CRF1 bytes (owner decision 14), the record
    /// identity, as a CPG1 binding digest is the BLAKE3 of the canonical
    /// CPG1. It is not `CapabilityRevocationV1`'s private field-wise
    /// binding digest: that one binds a revocation permit to the
    /// persistence host's attestation and is no record identity.
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
                .map(|(grant_digests, revocation_digests)| {
                    community_authority_bindings_digest_v1(&grant_digests, &revocation_digests)
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

    #[cfg(target_os = "linux")]
    fn check_writer_bound(
        &mut self,
        reservation: TrustedClockReservationV1,
        mono: &mut dyn GuardMonotonicSourceV1,
        bound: WallTime,
    ) -> Result<(), Error> {
        open_release_guard(&mut self.clock, reservation, &mut WaitBudgetV1::new(), mono)
            .ok()
            .and_then(|guard| {
                mono.mark()
                    .checked_elapsed_since(guard.guard_started_at())
                    .map(|elapsed| {
                        let elapsed = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
                        guard
                            .reservation()
                            .sampled_at()
                            .as_micros()
                            .saturating_add(elapsed)
                    })
            })
            .filter(|now| *now < bound.as_micros())
            .map(drop)
            .ok_or(Error::EvidenceUnavailable)
    }

    fn event_history(&self) -> (&dyn EventStore, &dyn Hasher) {
        (&self.store, self.store.event_hasher())
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
    fn plugin_trust_policy(&self, scope: &str) -> Result<RetainedPolicyStateV1, Error> {
        self.store
            .retained_policy_state(scope)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }

    #[cfg(target_os = "linux")]
    fn active_release(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> Result<Option<ActiveReleaseV1>, Error> {
        PluginTrustPolicyRegistryV1::active_release(&self.store, scope, plugin_id)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }
}
