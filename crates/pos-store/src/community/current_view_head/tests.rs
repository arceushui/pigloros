//! The CAV1 head view (I235, ADR-129 R16.2(4) and R16.5(4)): the authority
//! row rule, the initialization head's view, and the fixtures the three
//! CAV1 sites' tests compare against.

use pos_core::community_lifecycle::{
    CommunityAuthorityViewRowV1, CommunityMaterializationReferenceV1, CommunityMaterializationV1,
};
use pos_core::{Hash, TimelineId};
use ulid::Ulid;

use super::{with_metadata_row, CommunitySelectedViewV1};
use crate::community::MemoryCommunityDomainV1;
use crate::community_initialization_fixture::{hash, Fallible};

/// T's initialization records, opened, in sealed order.
pub(in crate::community) fn opened_records(
    domain: &MemoryCommunityDomainV1,
) -> Fallible<Vec<zeroize::Zeroizing<Vec<u8>>>> {
    let committed = domain
        .initializations
        .values()
        .next()
        .ok_or("no initialization")?;
    let vault = domain
        .keys
        .get(&committed.metadata_key)
        .ok_or("no metadata key")?;
    Ok(committed
        .records
        .iter()
        .filter_map(|sealed| vault.open(sealed).ok())
        .collect())
}

/// The CMI1 reference of every `StateRevision` CSR1 of T's initialization,
/// in roster order, read back from its sealed records: an independent
/// rebuild of what R16.5(4) names.
pub(in crate::community) fn state_revisions(
    domain: &MemoryCommunityDomainV1,
) -> Fallible<Vec<CommunityMaterializationReferenceV1>> {
    let committed = domain
        .initializations
        .values()
        .next()
        .ok_or("no initialization")?;
    let vault = domain
        .keys
        .get(&committed.metadata_key)
        .ok_or("no metadata key")?;
    Ok(committed
        .records
        .iter()
        .filter_map(|sealed| vault.open(sealed).ok())
        .filter_map(|bytes| CommunityMaterializationV1::from_canonical_cbor(&bytes).ok())
        .filter(|materialization| materialization.as_input().record_magic == *b"CSR1")
        .map(|materialization| materialization.as_input().materialization)
        .collect())
}

/// What a Commit installs in one transaction (R16.5(4)): T's new head
/// digest in the pass state and the selected view of that head, whose ref is
/// a real CSR1 CMI1 reference. The Commit slice replaces this with its real
/// transaction, which installs the same pair.
pub(in crate::community) fn simulate_commit(
    domain: &mut MemoryCommunityDomainV1,
    timeline: TimelineId,
    view: &CommunitySelectedViewV1,
) -> Fallible<()> {
    domain
        .pass_states
        .get_mut(&timeline)
        .ok_or("no pass state")?
        .head = view.head_digest;
    domain.selected_views.insert(timeline, *view);
    Ok(())
}

/// Whether `head_view` accepts T's selected view: it names the head the pass
/// state holds. It asks the domain's own rule, so the two cannot drift.
pub(in crate::community) fn views_agree(
    domain: &MemoryCommunityDomainV1,
    timeline: TimelineId,
) -> bool {
    domain.agreed_view(timeline).is_some()
}

fn row(timeline: u8, head: u64, epoch: u64, tag: u8) -> CommunityAuthorityViewRowV1 {
    CommunityAuthorityViewRowV1 {
        authority_timeline: TimelineId::from_ulid(Ulid::from_bytes([timeline; 16])),
        head_seq: head,
        revocation_epoch: epoch,
        registry_digest: hash(tag),
        capability_policy_revision: hash(tag),
        consent_policy_revision: hash(tag),
        binding_digest: hash(tag),
    }
}

fn tags(rows: &[CommunityAuthorityViewRowV1]) -> Vec<Hash> {
    rows.iter().map(|row| row.binding_digest).collect()
}

/// R16.2(4): the metadata chain's row is not repeated when another row has
/// its key, whichever coordinate is compared.
#[test]
fn a_metadata_row_with_the_same_key_is_not_repeated() {
    let chain = row(2, 5, 1, 0x11);
    let rows = with_metadata_row(vec![chain], row(2, 5, 1, 0x22));
    assert_eq!(tags(&rows), vec![hash(0x11)]);
}

/// A metadata row that differs in any one coordinate of the key joins the
/// rows, ascending by `(authority_timeline, head_seq, epoch)`.
#[test]
fn a_metadata_row_with_another_key_joins_the_rows_in_order() {
    for metadata in [row(3, 5, 1, 0x22), row(2, 6, 1, 0x22), row(2, 5, 2, 0x22)] {
        let rows = with_metadata_row(vec![row(2, 5, 1, 0x11)], metadata);
        assert_eq!(tags(&rows), vec![hash(0x11), hash(0x22)]);
    }
    for metadata in [row(1, 5, 1, 0x22), row(2, 4, 1, 0x22), row(2, 5, 0, 0x22)] {
        let rows = with_metadata_row(vec![row(2, 5, 1, 0x11)], metadata);
        assert_eq!(tags(&rows), vec![hash(0x22), hash(0x11)]);
    }
}

/// The metadata row stands alone when no chain row exists.
#[test]
fn a_metadata_row_stands_alone() {
    let rows = with_metadata_row(vec![], row(2, 5, 1, 0x22));
    assert_eq!(tags(&rows), vec![hash(0x22)]);
}
