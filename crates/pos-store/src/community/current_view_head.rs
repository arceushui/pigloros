//! The head of a CAV1 (ADR-129 revision 16, R16.5(4) and R16.2(4)).
//!
//! One place builds what every CAV1 of an initialized Timeline T states
//! about T's selection: the frontier, the head ref and the authority rows.
//!
//! - The head ref is the CMI1 six-field `materialization_ref` of the
//!   `StateRevision` CSR1 COW1 of the first roster member (CGI1
//!   `ordered_CMB1_digests[0]`) in the selected CSH1. It is null only for a
//!   code-0 initialize that reads no selected head, which is the
//!   initialization's own CAV1 and does not come through here.
//! - The authority rows are one per distinct `(authority_timeline,
//!   head_seq, revocation_epoch)`. The metadata chain's row is always
//!   present, and is not repeated when another row has its key.

use pos_core::community_lifecycle::{
    CommunityAuthorityViewRowV1, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationReferenceV1, CommunityMaterializationV1, CommunityPassFrontierV1,
};
use pos_core::{AuthorizationRequestV1, Hash, TimelineId};
use zeroize::Zeroizing;

use super::memory_domain::MemoryCommunityDomainV1;
use super::store_domain::CommunityStoreDomainV1;

/// The record magic of a `StateRevision` COW1.
const CSR1: [u8; 4] = *b"CSR1";

/// T's selected head as a CAV1 reads it: the frontier of the selected CSH1
/// and the head ref of its first roster member's CSR1.
///
/// The domain keeps one per initialized Timeline, beside its pass state.
/// Initialization sets it and a Commit replaces it with the head it
/// selects.
#[derive(Clone, Copy)]
pub(super) struct CommunitySelectedViewV1 {
    pub(super) frontier: CommunityPassFrontierV1,
    pub(super) head_ref: CommunityMaterializationReferenceV1,
}

impl CommunitySelectedViewV1 {
    /// The initialization head's view: the `Initial` frontier and the CMI1
    /// reference of the first CSR1 among `materializations`, which are in
    /// graph order (per roster slot: CSC1, CIS1, CSR1, two CPN1s).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when no CMI1 is a CSR1's.
    pub(super) fn initial(materializations: &[Zeroizing<Vec<u8>>]) -> Result<Self, Error> {
        materializations
            .iter()
            .filter_map(|bytes| CommunityMaterializationV1::from_canonical_cbor(bytes).ok())
            .find(|materialization| materialization.as_input().record_magic == CSR1)
            .map(|materialization| Self {
                frontier: CommunityPassFrontierV1::Initial,
                head_ref: materialization.as_input().materialization,
            })
            .ok_or(Error::EvidenceUnavailable)
    }
}

/// The frontier, head ref and authority rows of one CAV1.
pub(super) struct CommunityHeadViewV1 {
    pub(super) frontier: CommunityPassFrontierV1,
    /// Always `Some` here: every operation that comes through reads T's
    /// selected head.
    pub(super) selected_head: Option<CommunityMaterializationReferenceV1>,
    pub(super) authority_rows: Vec<CommunityAuthorityViewRowV1>,
}

impl MemoryCommunityDomainV1 {
    /// The head view of T's CAV1: T's selected frontier and head ref, and
    /// `chains` joined by the row of the metadata `write` decision's chain
    /// (`metadata`: its leaf grant and request), read now.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a Timeline with no selected head
    /// and for an unloadable metadata chain.
    pub(super) fn head_view(
        &self,
        timeline: TimelineId,
        chains: Vec<CommunityAuthorityViewRowV1>,
        metadata: (Hash, &AuthorizationRequestV1),
    ) -> Result<CommunityHeadViewV1, Error> {
        self.selected_views
            .get(&timeline)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|selected| {
                CommunityStoreDomainV1::authority_row(self, metadata.0, metadata.1).map(|row| {
                    CommunityHeadViewV1 {
                        frontier: selected.frontier,
                        selected_head: Some(selected.head_ref),
                        authority_rows: with_metadata_row(chains, row),
                    }
                })
            })
    }
}

/// The CAV1 sort key of an authority row.
const fn row_key(row: &CommunityAuthorityViewRowV1) -> ([u8; 16], u64, u64) {
    (
        row.authority_timeline.inner().to_bytes(),
        row.head_seq,
        row.revocation_epoch,
    )
}

/// `rows` and the metadata chain's row, ascending by key. The metadata
/// row is dropped when another row has its key (R16.2(4)).
fn with_metadata_row(
    mut rows: Vec<CommunityAuthorityViewRowV1>,
    metadata: CommunityAuthorityViewRowV1,
) -> Vec<CommunityAuthorityViewRowV1> {
    if rows.iter().all(|row| row_key(row) != row_key(&metadata)) {
        rows.push(metadata);
    }
    rows.sort_by_key(row_key);
    rows
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests;
