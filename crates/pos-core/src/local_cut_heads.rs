//! ADR-082 kind-4 expected-head and kind-5 result-head rows and their packing.
//!
//! These rows and their LCP1/LCT1 tables are portable shapes. Packing them
//! proves only that the rows hash to a table reference; it does not establish
//! that a source owner observed the heads or that an installed owner selected
//! the cut.

use crate::local_cut_seal::{
    domain_digest, encode_bytes, encode_head, encode_optional_hash, local_cut_tree_scope_v1,
    LocalCutBranchChildV1, LocalCutSealErrorV2, LocalCutTableRefV1, BRANCH_DOMAIN, PAGE_DOMAIN,
};
use crate::{Hash, TimelineId};

const EXPECTED_HEADS_KIND: u64 = 4;
const RESULT_HEADS_KIND: u64 = 5;
const PAGE_ROWS: usize = 64;
const BRANCH_CHILDREN: usize = 240;

/// One prospective kind-4 expected Timeline head; not a source-owner observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutExpectedHeadRowV1 {
    /// Exact owned Timeline identity.
    pub timeline_id: TimelineId,
    /// Expected stitched logical head before the cut.
    pub logical_head: u64,
    /// Expected stitched chain hash; native genesis may be any owner value.
    pub stitched_chain_hash: Hash,
    /// Source Timeline whose native segment the stitched history follows.
    pub source_timeline_id: TimelineId,
    /// Expected native source-segment head.
    pub source_segment_head: u64,
    /// Expected native source chain hash.
    pub source_chain_hash: Hash,
    /// Logical prefix inherited through Fork lineage.
    pub logical_prefix: u64,
    /// Fork lineage proof digest, null without Fork lineage.
    pub lineage_proof_hash: Option<Hash>,
    /// Last recorded WCB1 for the Timeline, null before its first binding.
    pub predecessor_wcb_hash: Option<Hash>,
}

impl LocalCutExpectedHeadRowV1 {
    /// Encode exactly the nine definite ADR-082 kind-4 row fields.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(224);
        encode_head(&mut out, 4, 9);
        encode_bytes(&mut out, &self.timeline_id.inner().to_bytes());
        encode_head(&mut out, 0, self.logical_head);
        encode_bytes(&mut out, self.stitched_chain_hash.as_bytes());
        encode_bytes(&mut out, &self.source_timeline_id.inner().to_bytes());
        encode_head(&mut out, 0, self.source_segment_head);
        encode_bytes(&mut out, self.source_chain_hash.as_bytes());
        encode_head(&mut out, 0, self.logical_prefix);
        encode_optional_hash(&mut out, self.lineage_proof_hash);
        encode_optional_hash(&mut out, self.predecessor_wcb_hash);
        out
    }
}

/// One prospective kind-5 result Timeline head; not a source-owner observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutResultHeadRowV1 {
    /// Exact owned Timeline identity.
    pub timeline_id: TimelineId,
    /// Stitched logical head after the cut.
    pub result_logical_head: u64,
    /// Stitched chain hash after the cut.
    pub result_stitched_hash: Hash,
    /// Native source-segment head after the cut.
    pub result_source_segment_head: u64,
    /// Native source chain hash after the cut.
    pub result_source_chain_hash: Hash,
    /// WCB1 recorded for the Timeline by this cut.
    pub successor_wcb_hash: Hash,
    /// Events committed for the Timeline by this cut.
    pub event_count: u64,
}

impl LocalCutResultHeadRowV1 {
    /// Encode exactly the seven definite ADR-082 kind-5 row fields.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        encode_head(&mut out, 4, 7);
        encode_bytes(&mut out, &self.timeline_id.inner().to_bytes());
        encode_head(&mut out, 0, self.result_logical_head);
        encode_bytes(&mut out, self.result_stitched_hash.as_bytes());
        encode_head(&mut out, 0, self.result_source_segment_head);
        encode_bytes(&mut out, self.result_source_chain_hash.as_bytes());
        encode_bytes(&mut out, self.successor_wcb_hash.as_bytes());
        encode_head(&mut out, 0, self.event_count);
        out
    }
}

/// Canonically packed kind-4 or kind-5 records, still unauthenticated by any owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutHeadsTableV1 {
    reference: LocalCutTableRefV1,
    node_records: Vec<Vec<u8>>,
}

impl LocalCutHeadsTableV1 {
    /// Pack ordered kind-4 rows into the minimal ADR-082 LCP1/LCT1 tree.
    ///
    /// # Errors
    /// Rejects unsorted or duplicate Timelines and a table above the row cap.
    pub fn expected_heads(
        owner_id: [u8; 32],
        cut_id: u64,
        rows: &[LocalCutExpectedHeadRowV1],
    ) -> Result<Self, LocalCutSealErrorV2> {
        check_sorted(rows.iter().map(|row| row.timeline_id))?;
        let encoded = rows
            .iter()
            .map(LocalCutExpectedHeadRowV1::to_canonical_cbor)
            .collect::<Vec<_>>();
        pack(
            EXPECTED_HEADS_KIND,
            local_cut_tree_scope_v1(owner_id, cut_id),
            &encoded,
        )
    }

    /// Pack ordered kind-5 rows into the minimal ADR-082 LCP1/LCT1 tree.
    ///
    /// # Errors
    /// Rejects unsorted or duplicate Timelines and a table above the row cap.
    pub fn result_heads(
        owner_id: [u8; 32],
        cut_id: u64,
        rows: &[LocalCutResultHeadRowV1],
    ) -> Result<Self, LocalCutSealErrorV2> {
        check_sorted(rows.iter().map(|row| row.timeline_id))?;
        let encoded = rows
            .iter()
            .map(LocalCutResultHeadRowV1::to_canonical_cbor)
            .collect::<Vec<_>>();
        pack(
            RESULT_HEADS_KIND,
            local_cut_tree_scope_v1(owner_id, cut_id),
            &encoded,
        )
    }

    /// Return the exact `[row_count, root]` reference of the packed table.
    #[must_use]
    pub const fn table_ref(&self) -> LocalCutTableRefV1 {
        self.reference
    }

    /// Borrow every LCP1 page and LCT1 branch, pages first, root last.
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.node_records
    }
}

fn check_sorted(timelines: impl Iterator<Item = TimelineId>) -> Result<(), LocalCutSealErrorV2> {
    let timelines = timelines.collect::<Vec<_>>();
    if timelines.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(LocalCutSealErrorV2::RowsNotSorted)
    } else {
        Ok(())
    }
}

/// Pack encoded rows 64 per page and children 240 per branch, left to right.
///
/// One page is its own root; otherwise branches rise until a single root
/// remains. The table reference rejects a row count above the ADR-082 cap.
fn pack(
    kind: u64,
    tree_scope: Hash,
    rows: &[Vec<u8>],
) -> Result<LocalCutHeadsTableV1, LocalCutSealErrorV2> {
    let mut node_records = Vec::new();
    let mut level = Vec::new();
    for (index, chunk) in rows.chunks(PAGE_ROWS).enumerate() {
        let first_ordinal = (index * PAGE_ROWS) as u64;
        let page = encode_page(kind, tree_scope, first_ordinal, chunk);
        level.push(LocalCutBranchChildV1 {
            first_ordinal,
            row_count: chunk.len() as u64,
            node_hash: domain_digest(PAGE_DOMAIN, &page),
        });
        node_records.push(page);
    }
    let mut height = 0_u8;
    while level.len() > 1 {
        height += 1;
        let mut parents = Vec::new();
        for children in level.chunks(BRANCH_CHILDREN) {
            let branch = encode_branch(kind, tree_scope, height, children);
            parents.push(LocalCutBranchChildV1 {
                first_ordinal: children[0].first_ordinal,
                row_count: children.iter().map(|child| child.row_count).sum(),
                node_hash: domain_digest(BRANCH_DOMAIN, &branch),
            });
            node_records.push(branch);
        }
        level = parents;
    }
    LocalCutTableRefV1::new(rows.len() as u64, level.first().map(|root| root.node_hash))
        .map(|reference| LocalCutHeadsTableV1 {
            reference,
            node_records,
        })
}

fn encode_page(kind: u64, tree_scope: Hash, first_ordinal: u64, rows: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_head(&mut out, 4, 6);
    encode_bytes(&mut out, b"LCP1");
    encode_head(&mut out, 0, 1);
    encode_head(&mut out, 0, kind);
    encode_bytes(&mut out, tree_scope.as_bytes());
    encode_head(&mut out, 0, first_ordinal);
    encode_head(&mut out, 4, rows.len() as u64);
    for row in rows {
        out.extend_from_slice(row);
    }
    out
}

fn encode_branch(
    kind: u64,
    tree_scope: Hash,
    height: u8,
    children: &[LocalCutBranchChildV1],
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_head(&mut out, 4, 8);
    encode_bytes(&mut out, b"LCT1");
    encode_head(&mut out, 0, 1);
    encode_head(&mut out, 0, kind);
    encode_bytes(&mut out, tree_scope.as_bytes());
    encode_head(&mut out, 0, u64::from(height));
    encode_head(&mut out, 0, children[0].first_ordinal);
    encode_head(
        &mut out,
        0,
        children.iter().map(|child| child.row_count).sum(),
    );
    encode_head(&mut out, 4, children.len() as u64);
    for child in children {
        encode_head(&mut out, 4, 3);
        encode_head(&mut out, 0, child.first_ordinal);
        encode_head(&mut out, 0, child.row_count);
        encode_bytes(&mut out, child.node_hash.as_bytes());
    }
    out
}
