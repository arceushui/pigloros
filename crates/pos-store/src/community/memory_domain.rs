//! Retained-Memory community domain construction and bootstrap.
//!
//! The domain is the retained store context: its `MemoryStore`, store
//! incarnation, key vault and native metadata stay together, and replacing it
//! loses them. It has no process-restart durability and never reconstructs a
//! lost identity.

use std::collections::BTreeMap;

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityCopyHolderV1, CommunityCopyInventoryInputV1, CommunityCopyInventoryV1,
    CommunityCopyStateV1, CommunityKeyIntentInputV1, CommunityLifecycleErrorV1 as Error,
    CommunityMemberSlotsV1, CommunityMetadataAnchorV1, CommunityMetadataPolicyV1,
    CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1, CommunityMetadataScopeV1,
    CommunityRecordKindsV1, CommunityScopeMembersV1, CommunitySelectionInputV1,
    CommunitySelectionV1, CommunityTimelineFloorsV1,
};
use pos_core::{
    AuthorityPersistencePortV1, AuthorizationDecisionV1, Hash, PersistedAuthorityV1, TimelineId,
};
use zeroize::Zeroizing;

use super::metadata_authority::{CommunityMetadataAuthorityV1, MetadataActionV1};
use super::private_hash::scope_set_digest;
use super::sealer::SealedMetadataV1;
use super::vault::{fresh_identity, VaultKeyV1};
use crate::memory::MemoryStore;

/// Preferred CBOR encoding of the empty scope-member array.
const EMPTY_SCOPE_ROWS: [u8; 1] = [0x80];

/// Closed bootstrap request: the original control identity and the
/// Timeline/generation that anchor native metadata.
///
/// ADR-129 §3 commits CMA1 at bootstrap, and its T/G are "the real first
/// admitted Timeline/generation". The anchor pair is therefore
/// caller-asserted by the trusted composition until the first generation
/// initialization (CGI1) binds it; this type does not verify that pair
/// against an admitted generation. A2 (initialize) MUST check the stored
/// anchor against the first admitted Timeline/generation when it writes
/// CGI1 and fail closed on any mismatch.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityBootstrapRequestV1 {
    pub(super) control_id: [u8; 16],
    pub(super) anchor_timeline: TimelineId,
    pub(super) anchor_generation: [u8; 16],
}

impl CommunityBootstrapRequestV1 {
    /// Validate the nonzero control identity and anchor coordinates.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for any zero identity.
    pub fn new(
        control_id: [u8; 16],
        anchor_timeline: TimelineId,
        anchor_generation: [u8; 16],
    ) -> Result<Self, Error> {
        if control_id == [0; 16]
            || anchor_generation == [0; 16]
            || anchor_timeline.inner().to_bytes() == [0; 16]
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self {
                control_id,
                anchor_timeline,
                anchor_generation,
            })
        }
    }
}

/// Installed bindings that retained native metadata must match.
#[derive(Clone, Copy)]
pub struct CommunityDomainBindingV1<'a> {
    /// Exact installed NMP1 metadata policy.
    pub metadata_policy: &'a CommunityMetadataPolicyV1,
    /// Installed catalogue identity recorded in CSI1.
    pub installed_catalogue_digest: Hash,
    /// Qualified native profile identity recorded in CSI1.
    pub native_profile_digest: Hash,
}

/// How a domain open resolved; none of these issues a guest permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityDomainOpenedV1 {
    /// A proven-empty domain committed its anchor, intent and CSI1.
    Bootstrapped,
    /// The exact original bootstrap request was found; nothing was created.
    ResolvedOriginal,
    /// An existing domain verified; this request created nothing.
    Existing,
}

/// Retained bootstrap records; later community operations extend the domain
/// from sibling modules, so fields are visible within `community` only.
pub(super) struct BootstrapRecordV1 {
    pub(super) request: CommunityBootstrapRequestV1,
    pub(super) protection_id: [u8; 16],
    pub(super) copy_id: [u8; 16],
    pub(super) anchor: Zeroizing<Vec<u8>>,
    pub(super) authority_request_digest: Hash,
    pub(super) selection: SealedMetadataV1,
    pub(super) key_copy: SealedMetadataV1,
}

impl BootstrapRecordV1 {
    fn classify(
        &self,
        request: CommunityBootstrapRequestV1,
    ) -> Result<CommunityDomainOpenedV1, Error> {
        if self.request == request {
            Ok(CommunityDomainOpenedV1::ResolvedOriginal)
        } else if self.request.control_id == request.control_id {
            Err(Error::Conflict)
        } else {
            Ok(CommunityDomainOpenedV1::Existing)
        }
    }
}

/// Sealed retained-Memory community domain.
///
/// It exposes no key, material, record or State getter. Every operation
/// evaluates its own metadata-service authority from the installed inputs
/// over its own persisted grant chain; it never accepts a decision.
///
/// ADR-129 says missing or stale metadata authority "closes the context".
/// This crate reads that as per-call fail-closed: every operation re-checks
/// authority against the store's current head and refuses with
/// `EvidenceUnavailable`. Nothing is latched; restoring a revoked grant is
/// itself an explicit authority act recorded in the same store.
///
/// Fields are visible within the sealed `community` module only, so each
/// later lifecycle operation adds its own sibling module and `impl` block.
pub struct MemoryCommunityDomainV1 {
    pub(super) store: MemoryStore,
    pub(super) store_incarnation: [u8; 16],
    pub(super) keys: BTreeMap<[u8; 16], VaultKeyV1>,
    pub(super) bootstrap: Option<BootstrapRecordV1>,
}

impl MemoryCommunityDomainV1 {
    /// Take ownership of a store as a new, empty protected domain.
    ///
    /// The domain is proven empty by construction: community key, anchor,
    /// selection and copy records live only in this domain, never in the
    /// `MemoryStore`, so a fresh domain holds none of them whatever the store
    /// already contains. The store contributes only its authority records.
    ///
    /// The trusted composition provisions the store incarnation, so it can
    /// persist the exact metadata grant for this resource before handing the
    /// store over; nothing here can add a grant afterwards.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero incarnation.
    pub fn new(store: MemoryStore, store_incarnation: [u8; 16]) -> Result<Self, Error> {
        if store_incarnation == [0; 16] {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self {
                store,
                store_incarnation,
                keys: BTreeMap::new(),
                bootstrap: None,
            })
        }
    }

    /// The nonzero incarnation naming this domain's metadata resource.
    #[must_use]
    pub const fn store_incarnation(&self) -> [u8; 16] {
        self.store_incarnation
    }

    /// Whether native metadata has been bootstrapped.
    #[must_use]
    pub const fn is_bootstrapped(&self) -> bool {
        self.bootstrap.is_some()
    }

    /// Load the policy's current persisted grant chain from this domain's
    /// own authority store.
    fn metadata_authority(
        &self,
        policy: &CommunityMetadataPolicyV1,
    ) -> Result<PersistedAuthorityV1, Error> {
        self.store
            .load_authority(policy.as_input().metadata_authority_leaf_grant)
            .ok()
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Bootstrap a proven-empty domain, or verify an existing one.
    ///
    /// The domain evaluates its own metadata-service authority: it loads the
    /// policy's current grant chain and asks `authority` for the exact
    /// request this operation needs (write to bootstrap, inspect to reopen)
    /// on this domain's resource. No decision is accepted from the caller:
    ///
    /// ```compile_fail,E0308
    /// use pos_store::community::{
    ///     CommunityBootstrapRequestV1, CommunityDomainBindingV1, MemoryCommunityDomainV1,
    /// };
    /// fn forge(
    ///     domain: &mut MemoryCommunityDomainV1,
    ///     binding: CommunityDomainBindingV1<'_>,
    ///     request: CommunityBootstrapRequestV1,
    ///     decoded: &pos_core::AuthorizationDecisionV1,
    /// ) {
    ///     let _ = domain.open(binding, decoded, request);
    /// }
    /// ```
    ///
    /// A missing, revoked or out-of-scope grant refuses this call only
    /// (per-call fail-closed, no latch); see the type documentation.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when current authority does not allow the
    /// exact request, and for a missing or conflicting anchor, key intent,
    /// CSI1 or copy record; `Conflict` when the control identity names
    /// another request.
    pub fn open(
        &mut self,
        binding: CommunityDomainBindingV1<'_>,
        authority: &mut CommunityMetadataAuthorityV1,
        request: CommunityBootstrapRequestV1,
    ) -> Result<CommunityDomainOpenedV1, Error> {
        if self.is_bootstrapped() {
            self.admit(
                binding.metadata_policy,
                authority,
                MetadataActionV1::Inspect,
            )
            .and_then(|_| self.reopen(binding, request))
        } else {
            self.admit(binding.metadata_policy, authority, MetadataActionV1::Write)
                .and_then(|decision| {
                    self.create(binding, request, decision.request_digest())
                        .map(|()| CommunityDomainOpenedV1::Bootstrapped)
                })
        }
    }

    /// Per-call fail-closed evaluation of the exact request against the
    /// chain loaded now; it latches nothing, so each operation repeats it.
    fn admit(
        &self,
        policy: &CommunityMetadataPolicyV1,
        authority: &mut CommunityMetadataAuthorityV1,
        action: MetadataActionV1,
    ) -> Result<AuthorizationDecisionV1, Error> {
        self.metadata_authority(policy).and_then(|persisted| {
            authority.authorize(policy, &persisted, self.store_incarnation, action)
        })
    }

    fn reopen(
        &self,
        binding: CommunityDomainBindingV1<'_>,
        request: CommunityBootstrapRequestV1,
    ) -> Result<CommunityDomainOpenedV1, Error> {
        self.bootstrap
            .as_ref()
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|record| {
                self.verify(binding, record)
                    .and_then(|()| record.classify(request))
            })
    }

    fn verify(
        &self,
        binding: CommunityDomainBindingV1<'_>,
        record: &BootstrapRecordV1,
    ) -> Result<(), Error> {
        self.keys
            .get(&record.protection_id)
            .filter(|key| {
                key_matches(
                    key,
                    record,
                    binding.metadata_policy.as_input().metadata_not_after_micros,
                )
            })
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|key| {
                self.verify_anchor(binding, record)
                    .and_then(|()| key.open(&record.selection))
                    .and_then(|selection| self.verify_selection(binding, &selection))
                    .and_then(|()| key.open(&record.key_copy))
                    .and_then(|copy| verify_copy(&copy, record, key))
            })
    }

    fn verify_anchor(
        &self,
        binding: CommunityDomainBindingV1<'_>,
        record: &BootstrapRecordV1,
    ) -> Result<(), Error> {
        CommunityMetadataAnchorV1::from_canonical_cbor(&record.anchor, binding.metadata_policy)
            .ok()
            .filter(|anchor| {
                let anchor = anchor.as_input();
                anchor.store_incarnation == self.store_incarnation
                    && anchor.anchor_timeline == record.request.anchor_timeline
                    && anchor.anchor_generation == record.request.anchor_generation
            })
            .map(drop)
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Check the initial CSI1 bootstrap committed: no producer, no Timeline
    /// floors and the installed policy's metadata horizon.
    fn verify_selection(
        &self,
        binding: CommunityDomainBindingV1<'_>,
        plaintext: &[u8],
    ) -> Result<(), Error> {
        CommunitySelectionV1::from_canonical_cbor(plaintext)
            .ok()
            .filter(|selection| {
                let selection = selection.as_input();
                selection.store_incarnation == self.store_incarnation
                    && selection.installed_catalogue_digest == binding.installed_catalogue_digest
                    && selection.native_profile_digest == binding.native_profile_digest
                    && selection.highest_native_producer_ordinal == 0
                    && selection.timeline_floors.is_empty()
                    && selection.metadata_not_after_micros
                        == binding.metadata_policy.as_input().metadata_not_after_micros
            })
            .map(drop)
            .ok_or(Error::EvidenceUnavailable)
    }

    fn create(
        &mut self,
        binding: CommunityDomainBindingV1<'_>,
        request: CommunityBootstrapRequestV1,
        authority_request_digest: Hash,
    ) -> Result<(), Error> {
        fresh_identity()
            .and_then(|protection_id| {
                fresh_identity().and_then(|copy_id| {
                    self.seal_bootstrap(
                        binding,
                        BootstrapRecordIds {
                            request,
                            protection_id,
                            copy_id,
                        },
                        authority_request_digest,
                    )
                })
            })
            .map(|(key, record)| {
                self.keys.insert(record.protection_id, key);
                self.bootstrap = Some(record);
            })
    }

    fn seal_bootstrap(
        &self,
        binding: CommunityDomainBindingV1<'_>,
        ids: BootstrapRecordIds,
        authority_request_digest: Hash,
    ) -> Result<(VaultKeyV1, BootstrapRecordV1), Error> {
        let policy = binding.metadata_policy;
        let horizon = policy.as_input().metadata_not_after_micros;
        let request = ids.request;
        CommunityMetadataAnchorV1::new(
            self.store_incarnation,
            request.anchor_timeline,
            request.anchor_generation,
            policy,
        )
        .and_then(|anchor| {
            CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
                store_incarnation: self.store_incarnation,
                metadata_anchor_timeline: request.anchor_timeline,
                metadata_anchor_generation: request.anchor_generation,
                protection_operation_id: ids.protection_id,
                scope_members: CommunityScopeMembersV1::from_members(&[]),
                metadata_not_after_micros: horizon,
            })
            .and_then(|scope| {
                VaultKeyV1::provision(bootstrap_intent(&ids, horizon, authority_request_digest))
                    .and_then(|key| self.seal_records(binding, &ids, &scope, key))
            })
            .map(|(key, selection, key_copy)| {
                (
                    key,
                    BootstrapRecordV1 {
                        request,
                        protection_id: ids.protection_id,
                        copy_id: ids.copy_id,
                        anchor: anchor.to_canonical_cbor(),
                        authority_request_digest,
                        selection,
                        key_copy,
                    },
                )
            })
        })
    }

    fn seal_records(
        &self,
        binding: CommunityDomainBindingV1<'_>,
        ids: &BootstrapRecordIds,
        scope: &CommunityMetadataScopeV1<'_>,
        mut key: VaultKeyV1,
    ) -> Result<(VaultKeyV1, SealedMetadataV1, SealedMetadataV1), Error> {
        let horizon = binding.metadata_policy.as_input().metadata_not_after_micros;
        CommunitySelectionV1::new(CommunitySelectionInputV1 {
            store_incarnation: self.store_incarnation,
            installed_catalogue_digest: binding.installed_catalogue_digest,
            native_profile_digest: binding.native_profile_digest,
            highest_native_producer_ordinal: 0,
            timeline_floors: CommunityTimelineFloorsV1::from_floors(&[]),
            metadata_not_after_micros: horizon,
        })
        .and_then(|selection| {
            key.seal(
                scope,
                CommunityMetadataSchemaV1::Csi1,
                &selection.to_canonical_cbor(),
            )
        })
        .and_then(|selection| {
            CommunityCopyInventoryV1::new(key_copy_descriptor(ids, &key, horizon))
                .and_then(|copy| {
                    key.seal(
                        scope,
                        CommunityMetadataSchemaV1::Cci1,
                        &copy.to_canonical_cbor(),
                    )
                })
                .map(|key_copy| (selection, key_copy))
        })
        .map(|(selection, key_copy)| {
            key.close();
            (key, selection, key_copy)
        })
    }
}

#[derive(Clone, Copy)]
struct BootstrapRecordIds {
    request: CommunityBootstrapRequestV1,
    protection_id: [u8; 16],
    copy_id: [u8; 16],
}

const fn control_kinds() -> CommunityRecordKindsV1 {
    CommunityRecordKindsV1::empty().with(CommunityArtifactKindV1::LifecycleControl)
}

fn bootstrap_intent(
    ids: &BootstrapRecordIds,
    horizon: u64,
    authority_request_digest: Hash,
) -> CommunityKeyIntentInputV1 {
    CommunityKeyIntentInputV1 {
        protection_operation_id: ids.protection_id,
        parent_operation: CommunityArtifactOperationV1::Control(ids.request.control_id),
        timeline: ids.request.anchor_timeline,
        generation: ids.request.anchor_generation,
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
        evidence_not_after_micros: horizon,
        allowed_record_kinds: control_kinds(),
        member_slots: CommunityMemberSlotsV1::empty(),
        material_fingerprint: Hash::zero(),
        authority_request_digest,
    }
}

fn key_copy_descriptor(
    ids: &BootstrapRecordIds,
    key: &VaultKeyV1,
    horizon: u64,
) -> CommunityCopyInventoryInputV1 {
    CommunityCopyInventoryInputV1 {
        copy_id: ids.copy_id,
        revision: 1,
        predecessor: None,
        parent_operation: CommunityArtifactOperationV1::Control(ids.request.control_id),
        timeline: ids.request.anchor_timeline,
        generation: ids.request.anchor_generation,
        holder: CommunityCopyHolderV1::KeyVault,
        holder_digest: key.intent().digest(),
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
        object_commitment: None,
        state: CommunityCopyStateV1::Owned,
        deadline_micros: horizon,
    }
}

/// The retained key is exactly the bootstrap intent for this record and its
/// material is the material that intent names.
///
/// Purpose is not compared separately: CKP1 admits a kind only under a
/// purpose that permits it, and only `LifecycleControl` permits the exact
/// control kind set, so the kind comparison already fixes the purpose.
fn key_matches(key: &VaultKeyV1, record: &BootstrapRecordV1, horizon: u64) -> bool {
    let intent = key.intent().as_input();
    key.material_matches_intent()
        && intent.protection_operation_id == record.protection_id
        && intent.parent_operation
            == CommunityArtifactOperationV1::Control(record.request.control_id)
        && intent.timeline == record.request.anchor_timeline
        && intent.generation == record.request.anchor_generation
        && intent.scope_set_digest == scope_set_digest(&EMPTY_SCOPE_ROWS)
        && intent.evidence_not_after_micros == horizon
        && intent.allowed_record_kinds == control_kinds()
        && intent.member_slots == CommunityMemberSlotsV1::empty()
        && intent.authority_request_digest == record.authority_request_digest
}

/// The initial key-vault copy descriptor names this record's copy, this
/// exact key intent and the empty bootstrap scope.
fn verify_copy(
    plaintext: &[u8],
    record: &BootstrapRecordV1,
    key: &VaultKeyV1,
) -> Result<(), Error> {
    CommunityCopyInventoryV1::from_canonical_cbor(plaintext)
        .ok()
        .filter(|copy| {
            let copy = copy.as_input();
            copy.copy_id == record.copy_id
                && copy.holder == CommunityCopyHolderV1::KeyVault
                && copy.holder_digest == key.intent().digest()
                && copy.scope_set_digest == scope_set_digest(&EMPTY_SCOPE_ROWS)
        })
        .map(drop)
        .ok_or(Error::EvidenceUnavailable)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
