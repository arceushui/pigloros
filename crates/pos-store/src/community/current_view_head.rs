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
    CommunityAuthorityViewRowV1, CommunityInitializationRequestV1,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationReferenceV1,
    CommunityMaterializationV1, CommunityPassFrontierV1,
};
use pos_core::{AuthorizationRequestV1, Hash, TimelineId};
use zeroize::Zeroizing;

use super::memory_domain::MemoryCommunityDomainV1;
use super::native_graph::CommunityInitializationGraphV1;
use super::store_domain::CommunityStoreDomainV1;

/// The record magic of a `StateRevision` COW1.
const CSR1: [u8; 4] = *b"CSR1";

/// T's selected head as a CAV1 reads it: the frontier of the selected CSH1
/// and the head ref of its first roster member's CSR1.
///
/// The domain keeps one per initialized Timeline, beside its pass state.
/// Initialization sets it and a Commit replaces it with the head it
/// selects.
///
/// Invariant: `head_digest` is `pass_states[T].head`, the digest of the CSH1
/// this view reads. [`MemoryCommunityDomainV1::head_view`] refuses a view
/// whose digest differs, so a CAV1 never states a head other than the one
/// the fences compare. A Commit MUST replace both in one transaction.
#[derive(Clone, Copy)]
pub(super) struct CommunitySelectedViewV1 {
    pub(super) head_digest: Hash,
    pub(super) frontier: CommunityPassFrontierV1,
    pub(super) head_ref: CommunityMaterializationReferenceV1,
}

impl CommunitySelectedViewV1 {
    /// The initialization head's view: `head_digest`, the `Initial` frontier
    /// and the CMI1 reference of the CSR1 of the first member the CGI1
    /// `cgi1` lists (`ordered_CMB1_digests[0]`), found in `graph` by its
    /// CMB1 digest; `materializations` hold the graph's CMI1s in record
    /// order.
    ///
    /// # Errors
    /// Returns the CGI1 and CMI1 codec refusals, and `EvidenceUnavailable`
    /// for an empty list, a member the graph does not hold and a record that
    /// is not a CSR1's.
    pub(super) fn initial(
        head_digest: Hash,
        cgi1: &[u8],
        graph: &CommunityInitializationGraphV1,
        materializations: &[Zeroizing<Vec<u8>>],
    ) -> Result<Self, Error> {
        CommunityInitializationRequestV1::from_canonical_cbor(cgi1)
            .and_then(|request| {
                request
                    .as_input()
                    .member_binding_digests
                    .iter()
                    .next()
                    .and_then(|first| graph.state_revision_index(first))
                    .ok_or(Error::EvidenceUnavailable)
            })
            .and_then(|index| Self::at(head_digest, index, materializations))
    }

    /// The view whose head ref is the CSR1 CMI1 at `index` of
    /// `materializations`.
    ///
    /// # Errors
    /// Returns the CMI1 codec refusal, and `EvidenceUnavailable` for an
    /// index out of range and a record that is not a CSR1's.
    pub(super) fn at(
        head_digest: Hash,
        index: usize,
        materializations: &[Zeroizing<Vec<u8>>],
    ) -> Result<Self, Error> {
        materializations
            .get(index)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|bytes| CommunityMaterializationV1::from_canonical_cbor(bytes))
            .and_then(|materialization| {
                Some(materialization)
                    .filter(|materialization| materialization.as_input().record_magic == CSR1)
                    .map(|materialization| Self {
                        head_digest,
                        frontier: CommunityPassFrontierV1::Initial,
                        head_ref: materialization.as_input().materialization,
                    })
                    .ok_or(Error::EvidenceUnavailable)
            })
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
    /// T's selected view when it reads the head the pass state holds: the one
    /// accept/refuse rule of [`Self::head_view`].
    pub(super) fn agreed_view(&self, timeline: TimelineId) -> Option<&CommunitySelectedViewV1> {
        self.selected_views
            .get(&timeline)
            .zip(self.pass_states.get(&timeline))
            .filter(|(selected, state)| selected.head_digest == state.head)
            .map(|(selected, _)| selected)
    }

    /// The head view of T's CAV1: T's selected frontier and head ref, and
    /// `chains` joined by the row of the metadata `write` decision's chain
    /// (`metadata`: its leaf grant and request), read now.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a Timeline with no selected head,
    /// a selected view whose digest is not the pass state's head and an
    /// unloadable metadata chain.
    pub(super) fn head_view(
        &self,
        timeline: TimelineId,
        chains: Vec<CommunityAuthorityViewRowV1>,
        metadata: (Hash, &AuthorizationRequestV1),
    ) -> Result<CommunityHeadViewV1, Error> {
        self.agreed_view(timeline)
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
