//! The Memory pass Reserve's record publication (#560 A4c-3c-ii; ADR-129
//! R10.7 step 5j, R11.1(4), R13.2 and R15.1(2)-(3)).
//!
//! [`MemoryCommunityDomainV1::stage_reserve`] and
//! [`MemoryCommunityDomainV1::apply_reserve`] keep the pass state, the pass
//! record and the pending entry. This is the half that publishes what a
//! Reserve commits besides them, in the one guarded step that applies them:
//!
//! - the pass's one metadata key (R15.1(2)): parent CPK1, `LifecycleControl`,
//!   the empty scope and the metadata horizon, whose request digest is the
//!   Reserve's metadata `write` request digest (R11.1(4)). The key stays
//!   encryption-open, because every later operation of the pass (Abort,
//!   Seal, Commit) seals its own CNE1 records under it, and a closed key
//!   makes each of them give 14;
//! - the failure cohort key (R15.1(3), owner decision on #560, 2026-11-26):
//!   parent CPK1, `LifecycleControl`, the pass scope set `S_pass`, the
//!   failure horizon `min(quarantine_not_after_micros, H_g)` (R15.2) and
//!   the pass CRI1's request digest, with the due members' roster indices as
//!   its slots. It stays encryption-open for the failure records an Abort
//!   protects with it;
//! - the CRI1 and the CPR1 and each key's CCI1, sealed under the metadata
//!   key as CNE1 records over the CSM1 cover of every pass metadata record:
//!   the CMA1 anchor `(T, G)`, the key's protection ID, no scope members and
//!   the metadata horizon;
//! - the successor CSI1 (annex §4, "Identity floor"), sealed under the same
//!   key and swapped in with the inventory generation, which advances once.
//!
//! The Reserve's own CAU1 and CAV1 (R8.1(6)) are not built here: they need
//! the `run_pass` authority decisions, which no code evaluates yet.
//!
//! The writer compares the inventory generation and the CSI1 the call read,
//! as initialization's writer does, then commits keys, records, selection
//! and pass state together; a refusal before that leaves the domain
//! unchanged.

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityCopyHolderV1, CommunityCopyInventoryInputV1, CommunityCopyInventoryV1,
    CommunityCopyStateV1, CommunityKeyIntentInputV1, CommunityLifecycleErrorV1 as Error,
    CommunityMemberSlotsV1, CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1,
    CommunityMetadataScopeV1, CommunityRecordKindsV1, CommunityReservationRequestV1,
    CommunityReservationV1, CommunityScopeMembersV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};
use zeroize::Zeroizing;

use super::memory_domain::MemoryCommunityDomainV1;
use super::pass_install::CommunityHorizonPolicyV1;
use super::pass_writer::{community_reserve_selection_v1, CommunityStagedReserveV1};
use super::private_hash::scope_set_digest;
use super::protection::{CommunityArtifactProtectorV1, CommunityProtectionCohortV1};
use super::quarantine::CommunityQuarantineContextV1;
use super::sealer::SealedMetadataV1;
use super::vault::{fresh_identity, VaultKeyV1};

/// Preferred CBOR encoding of the empty scope-member array.
const EMPTY_SCOPE_ROWS: [u8; 1] = [0x80];

/// The trusted inputs of one Reserve's publication. None of it comes from
/// a guest.
#[derive(Clone, Copy)]
pub struct CommunityReservePublicationV1<'a> {
    /// The installed CDP1 the pass was reserved under and the domain's
    /// installed metadata policy.
    pub context: CommunityQuarantineContextV1<'a>,
    /// The Reserve's metadata `write` decision's request digest, which the
    /// pass metadata key's CKP1 keeps (R11.1(4), R15.1(2)).
    pub metadata_request_digest: Hash,
}

/// The original Reserve of one `(T, reservation_operation_id)`: its CRI1
/// and CPR1, read back from the records the Reserve sealed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityOriginalReserveV1 {
    request: Zeroizing<Vec<u8>>,
    reservation: Zeroizing<Vec<u8>>,
}

impl CommunityOriginalReserveV1 {
    /// The canonical CRI1.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// The canonical CPR1.
    #[must_use]
    pub fn reservation(&self) -> &[u8] {
        &self.reservation
    }
}

/// One committed Reserve's sealed records, retained under its pass metadata
/// key.
pub(super) struct CommittedReserveV1 {
    /// The protection ID of the pass metadata key that sealed `records`.
    metadata_key: [u8; 16],
    /// The pass's `H_r`, the CPR1's evidence horizon: the original evidence
    /// is expired at or after it (R13.2(4)).
    evidence_not_after_micros: u64,
    /// The sealed CRI1, the CPR1, the metadata key's CCI1 and the failure
    /// cohort key's CCI1, in that order.
    records: Vec<SealedMetadataV1>,
}

/// A key and its CCI1 key-vault copy descriptor.
struct KeyedV1 {
    key: VaultKeyV1,
    copy: CommunityCopyInventoryV1,
}

/// Everything one Reserve commits, staged before the writer.
struct PreparedReserveV1 {
    metadata: VaultKeyV1,
    failure: VaultKeyV1,
    records: Vec<SealedMetadataV1>,
    selection: SealedMetadataV1,
    /// The CSI1 address the call read: the swap's expected value.
    read_selection: Hash,
    /// The inventory generation the call read (G5).
    inventory_generation: u64,
}

impl MemoryCommunityDomainV1 {
    /// Publish a staged Reserve: provision its two keys, seal its records
    /// and the successor CSI1, and commit them with the pass state.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], publishes:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityReservePublicationV1, CommunityStagedReserveV1, MemoryCommunityDomainV1,
    /// };
    /// fn forge(
    ///     domain: &mut MemoryCommunityDomainV1,
    ///     staged: CommunityStagedReserveV1,
    ///     publication: CommunityReservePublicationV1<'_>,
    /// ) {
    ///     let _ = domain.publish_reserved_pass(staged, publication);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a CDP1 other than the one the pass was
    /// reserved under and for a key or record the codecs refuse,
    /// `EvidenceUnavailable` for a missing selection, key policy or pass
    /// state and for an inventory generation or CSI1 that moved since the
    /// call read them, `StaleGeneration` and `ContextClosed` as
    /// [`community_reserve_selection_v1`] gives them, `Conflict` for a key ID
    /// already in the vault and, as the apply's checks give them, `Conflict`
    /// and `PassUnresolved`, and `CapacityExhausted` when a key cannot seal.
    /// The domain is unchanged.
    ///
    /// The order matters: the CSI1 successor is built first, so a token
    /// staged before another Reserve published has stale ordinals and is
    /// refused with `InvalidBinding` there, before the apply's compares. A
    /// fresh token never reaches them either, because `stage_reserve`
    /// refuses a recorded identity and a second unresolved pass itself; they
    /// are the writer's backstop, reached directly through
    /// `check_reserve_publication`.
    pub fn publish_reserved_pass(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        staged: CommunityStagedReserveV1,
        publication: CommunityReservePublicationV1<'_>,
    ) -> Result<(), Error> {
        let prepared = self.prepare_reserve_records(seal, &staged, publication)?;
        self.check_reserve_publication(&staged, &prepared)?;
        self.commit_reserve_publication(staged, prepared);
        Ok(())
    }

    /// The original CRI1 and CPR1 of the Reserve of `(timeline,
    /// reservation_operation_id)`, authenticated under its pass metadata
    /// key: what a lost Reserve response discovers (R8.1(7)).
    ///
    /// `sample_micros` is the discovering call's one trusted sample. At or
    /// after the pass's `H_r`, the CPR1's evidence horizon, the original
    /// evidence is expired and discovery gives 13 (R13.2(4), R10.7 step 4a).
    /// Evidence that is gone (a pass nobody reserved, or a key or record
    /// that no longer opens) gives 12 first, then expired evidence 13: a
    /// disposed original cannot also be called expired (R10.7 4a:
    /// "disposed or expired original evidence 12 or 13"). A resolved pass is
    /// judged the same way.
    /// It has no production caller yet: the discovery pipeline must take the
    /// sample from the domain's own clock reservation, as every lifecycle
    /// call does.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a pass nobody reserved here and
    /// for a record that no longer opens under its key, and
    /// `EvidenceExpired` for a sample at or after `H_r`.
    pub fn original_reserve(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
        sample_micros: u64,
    ) -> Result<CommunityOriginalReserveV1, Error> {
        let key = (timeline, reservation_operation_id);
        let (committed, vault) = self.reserve_vault(key)?;
        check_discoverable(committed, sample_micros)?;
        let open = |index: usize| {
            committed
                .records
                .get(index)
                .ok_or(Error::EvidenceUnavailable)
                .and_then(|sealed| vault.open(sealed))
        };
        Ok(CommunityOriginalReserveV1 {
            request: open(0)?,
            reservation: open(1)?,
        })
    }

    /// The sealed records of a committed Reserve and the pass metadata key
    /// that seals them.
    fn reserve_vault(
        &self,
        key: (TimelineId, [u8; 16]),
    ) -> Result<(&CommittedReserveV1, &VaultKeyV1), Error> {
        let committed = self
            .reserve_publications
            .get(&key)
            .ok_or(Error::EvidenceUnavailable)?;
        self.keys
            .get(&committed.metadata_key)
            .map(|vault| (committed, vault))
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Provision both keys and seal every record, leaving the domain
    /// untouched: the CDP1 must be the Reserve's (3), the CSI1 successor is
    /// built from the one the call reads, and every record is sealed under
    /// the metadata key.
    fn prepare_reserve_records(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        staged: &CommunityStagedReserveV1,
        publication: CommunityReservePublicationV1<'_>,
    ) -> Result<PreparedReserveV1, Error> {
        let reservation = staged.record.reserved.reservation;
        if publication.context.profile.digest() != reservation.profile_digest {
            return Err(Error::InvalidBinding);
        }
        let (anchor, current, read_selection) = self.read_selection(publication.context)?;
        let successor = community_reserve_selection_v1(
            &current,
            staged.key.0,
            reservation.pass_key.generation(),
            staged.native_ordinal,
            staged.pass_ordinal,
        )?;
        let policy = self.pass_horizons.ok_or(Error::EvidenceUnavailable)?;
        let horizon = metadata_horizon(&publication);
        let mut metadata = provision_metadata_key(staged, &publication)?;
        let failure = provision_failure_key(seal, staged, policy)?;
        let scope = reserve_scope(self.store_incarnation, anchor, &metadata.key, horizon)?;
        let [request, pass] = reserve_plaintexts(staged)?;
        let copies = [
            metadata.copy.to_canonical_cbor(),
            failure.copy.to_canonical_cbor(),
        ];
        let mut sealed = seal_records(
            &mut metadata.key,
            &scope,
            &[
                (CommunityMetadataSchemaV1::Cri1, request.as_slice()),
                (CommunityMetadataSchemaV1::Cpr1, pass.as_slice()),
                (CommunityMetadataSchemaV1::Cci1, copies[0].as_slice()),
                (CommunityMetadataSchemaV1::Cci1, copies[1].as_slice()),
                (CommunityMetadataSchemaV1::Csi1, successor.as_slice()),
            ],
        )?;
        let selection = sealed.pop().ok_or(Error::EvidenceUnavailable)?;
        Ok(PreparedReserveV1 {
            metadata: metadata.key,
            failure: failure.key,
            records: sealed,
            selection,
            read_selection,
            inventory_generation: self.inventory_generation,
        })
    }

    /// The writer's compares before anything is published: the apply's own
    /// refusals, two fresh key IDs (`Conflict`), and the inventory generation
    /// and CSI1 the call read still being current (G5).
    ///
    /// The G5 compare cannot fire through [`Self::publish_reserved_pass`],
    /// which holds `&mut self` from the read to the commit; it guards a
    /// future caller that stages and commits in separate guarded steps, and
    /// is tested by a direct call.
    fn check_reserve_publication(
        &self,
        staged: &CommunityStagedReserveV1,
        prepared: &PreparedReserveV1,
    ) -> Result<(), Error> {
        self.check_apply_reserve(staged)?;
        self.check_fresh_keys(prepared)?;
        let current = self
            .selection
            .as_ref()
            .map(|(_, sealed)| sealed.address)
            .or_else(|| {
                self.bootstrap
                    .as_ref()
                    .map(|record| record.selection.address)
            });
        if self.inventory_generation != prepared.inventory_generation
            || current != Some(prepared.read_selection)
        {
            return Err(Error::EvidenceUnavailable);
        }
        Ok(())
    }

    /// The two keys' protection IDs differ and neither is in the vault
    /// already: a reused host-allocated ID would overwrite a live key, and
    /// with it an earlier pass's records (`Conflict`).
    fn check_fresh_keys(&self, prepared: &PreparedReserveV1) -> Result<(), Error> {
        let ids = [&prepared.metadata, &prepared.failure]
            .map(|key| key.intent().as_input().protection_operation_id);
        if ids[0] == ids[1] || ids.iter().any(|id| self.keys.contains_key(id)) {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }

    /// The atomic commit: the keys stay open, the successor CSI1 is the
    /// selection from now on, the inventory generation advances once and
    /// the pass state, record and pending entry are applied.
    fn commit_reserve_publication(
        &mut self,
        staged: CommunityStagedReserveV1,
        prepared: PreparedReserveV1,
    ) {
        let metadata_id = prepared
            .metadata
            .intent()
            .as_input()
            .protection_operation_id;
        let failure_id = prepared.failure.intent().as_input().protection_operation_id;
        self.keys.insert(metadata_id, prepared.metadata);
        self.keys.insert(failure_id, prepared.failure);
        self.selection = Some((metadata_id, prepared.selection));
        self.inventory_generation += 1;
        self.reserve_publications.insert(
            staged.key,
            CommittedReserveV1 {
                metadata_key: metadata_id,
                evidence_not_after_micros: staged
                    .record
                    .reserved
                    .reservation
                    .evidence_not_after_micros,
                records: prepared.records,
            },
        );
        self.publish_reserve(staged);
    }
}

/// The Reserve's original evidence is not expired at `sample_micros`: its
/// `H_r` is after the sample (`EvidenceExpired` otherwise).
const fn check_discoverable(
    committed: &CommittedReserveV1,
    sample_micros: u64,
) -> Result<(), Error> {
    if sample_micros >= committed.evidence_not_after_micros {
        Err(Error::EvidenceExpired)
    } else {
        Ok(())
    }
}

/// The NMP1 metadata horizon: the metadata key's and every CNE1 record's.
const fn metadata_horizon(publication: &CommunityReservePublicationV1<'_>) -> u64 {
    publication
        .context
        .binding
        .metadata_policy
        .as_input()
        .metadata_not_after_micros
}

/// The pass metadata key and its CCI1 (R11.1(4), R15.1(2)).
fn provision_metadata_key(
    staged: &CommunityStagedReserveV1,
    publication: &CommunityReservePublicationV1<'_>,
) -> Result<KeyedV1, Error> {
    let reserved = &staged.record.reserved;
    let pass_key = reserved.reservation.pass_key;
    let parent = CommunityArtifactOperationV1::Pass(pass_key);
    let horizon = metadata_horizon(publication);
    VaultKeyV1::provision(CommunityKeyIntentInputV1 {
        protection_operation_id: reserved.metadata_key,
        parent_operation: parent,
        timeline: pass_key.timeline(),
        generation: pass_key.generation(),
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
        evidence_not_after_micros: horizon,
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(CommunityArtifactKindV1::LifecycleControl),
        member_slots: CommunityMemberSlotsV1::empty(),
        material_fingerprint: Hash::zero(),
        authority_request_digest: publication.metadata_request_digest,
    })
    .and_then(|key| {
        fresh_identity()
            .and_then(|copy_id| {
                CommunityCopyInventoryV1::new(CommunityCopyInventoryInputV1 {
                    copy_id,
                    revision: 1,
                    predecessor: None,
                    parent_operation: parent,
                    timeline: pass_key.timeline(),
                    generation: pass_key.generation(),
                    holder: CommunityCopyHolderV1::KeyVault,
                    holder_digest: key.intent().digest(),
                    purpose: CommunityArtifactPurposeV1::LifecycleControl,
                    scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
                    object_commitment: None,
                    state: CommunityCopyStateV1::Owned,
                    deadline_micros: horizon,
                })
            })
            .map(|copy| KeyedV1 { key, copy })
    })
}

/// The failure cohort key and its CCI1 (R15.1(3)), through the protector
/// that provisions every cohort key.
fn provision_failure_key(
    seal: &'static AuthorityTrustRootSealV1,
    staged: &CommunityStagedReserveV1,
    policy: CommunityHorizonPolicyV1,
) -> Result<KeyedV1, Error> {
    failure_cohort(staged, policy).and_then(|cohort| {
        CommunityArtifactProtectorV1::provision_identified(
            seal,
            cohort,
            staged.record.reserved.failure_cohort_key,
        )
        .map(|protector| {
            let (key, copy) = protector.into_parts();
            KeyedV1 { key, copy }
        })
    })
}

/// The failure cohort of a pass: its scope set and the pass CSB1 as cover,
/// the failure horizon (R15.2) and the due members' slots (owner decision
/// on #560, 2026-11-26).
///
/// R15.1(3) allows kind 6 (`LifecycleControl`) only. The key also allows
/// kind 8 (`ClassificationProof`), which the protector and the extractor
/// require of every cohort key for its CAR1 proof envelopes (erratum
/// candidate).
fn failure_cohort(
    staged: &CommunityStagedReserveV1,
    policy: CommunityHorizonPolicyV1,
) -> Result<CommunityProtectionCohortV1, Error> {
    let reserved = &staged.record.reserved;
    let pass_key = reserved.reservation.pass_key;
    reserved
        .members
        .iter()
        .map(|member| u16::try_from(member.roster_index).map_err(|_| Error::InvalidBinding))
        .collect::<Result<Vec<u16>, Error>>()
        .and_then(|slots| CommunityMemberSlotsV1::new(&slots))
        .map(|member_slots| CommunityProtectionCohortV1 {
            parent_operation: CommunityArtifactOperationV1::Pass(pass_key),
            timeline: pass_key.timeline(),
            generation: pass_key.generation(),
            purpose: CommunityArtifactPurposeV1::LifecycleControl,
            scope_set_digest: staged.failure_scope,
            // The pass CSB1 digest covers the records this key protects when
            // an Abort protects them; the Reserve protects none with it.
            scope_cover_digest: Hash::zero(),
            evidence_not_after_micros: policy
                .retention
                .quarantine_not_after_micros
                .min(reserved.generation_horizon_micros),
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(CommunityArtifactKindV1::LifecycleControl)
                .with(CommunityArtifactKindV1::ClassificationProof),
            member_slots,
            authority_request_digest: staged.request.authority_request_digest,
        })
}

/// The CSM1 cover of every metadata record the Reserve seals: the CMA1
/// anchor `(T, G)`, the metadata key's protection ID, no scope members and
/// the metadata horizon.
fn reserve_scope(
    store_incarnation: [u8; 16],
    anchor: (TimelineId, [u8; 16]),
    key: &VaultKeyV1,
    metadata_horizon: u64,
) -> Result<CommunityMetadataScopeV1<'static>, Error> {
    CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
        store_incarnation,
        metadata_anchor_timeline: anchor.0,
        metadata_anchor_generation: anchor.1,
        protection_operation_id: key.intent().as_input().protection_operation_id,
        scope_members: CommunityScopeMembersV1::from_members(&[]),
        metadata_not_after_micros: metadata_horizon,
    })
}

/// The canonical CRI1 and CPR1 of the pass.
fn reserve_plaintexts(staged: &CommunityStagedReserveV1) -> Result<[Zeroizing<Vec<u8>>; 2], Error> {
    let request = CommunityReservationRequestV1::new(staged.request)?;
    let reservation = CommunityReservationV1::new(staged.record.reserved.reservation)?;
    Ok([request.to_canonical_cbor(), reservation.to_canonical_cbor()])
}

/// Seal each record under `key`, in order.
fn seal_records(
    key: &mut VaultKeyV1,
    scope: &CommunityMetadataScopeV1<'_>,
    records: &[(CommunityMetadataSchemaV1, &[u8])],
) -> Result<Vec<SealedMetadataV1>, Error> {
    records
        .iter()
        .map(|(schema, plaintext)| key.seal(scope, *schema, plaintext))
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
