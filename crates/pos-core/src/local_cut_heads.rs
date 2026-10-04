//! ADR-082 kind-4 expected-head and kind-5 result-head rows and their packing.
//!
//! These rows and their LCP1/LCT1 tables are portable shapes. Packing them
//! proves only that the rows hash to a table reference; it does not establish
//! that a source owner observed the heads or that an installed owner selected
//! the cut.

use crate::local_cut_seal::{
    encode_bytes, encode_head, encode_optional_hash, local_cut_tree_scope_v1, pack_local_cut_table,
    LocalCutSealErrorV2, LocalCutTableRefV1, Reader,
};
use crate::{Hash, TimelineId};

const EXPECTED_HEADS_KIND: u64 = 4;
const RESULT_HEADS_KIND: u64 = 5;

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

    /// Decode exactly the canonical nine-field kind-4 row.
    ///
    /// # Errors
    /// Rejects a malformed, truncated, extended or nonpreferred encoding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, LocalCutSealErrorV2> {
        let mut reader = Reader::new(bytes);
        reader.array(9)?;
        let row = Self {
            timeline_id: reader.timeline()?,
            logical_head: reader.uint()?,
            stitched_chain_hash: reader.hash()?,
            source_timeline_id: reader.timeline()?,
            source_segment_head: reader.uint()?,
            source_chain_hash: reader.hash()?,
            logical_prefix: reader.uint()?,
            lineage_proof_hash: reader.optional_hash()?,
            predecessor_wcb_hash: reader.optional_hash()?,
        };
        finish_row(&reader, bytes, &row.to_canonical_cbor())?;
        Ok(row)
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

    /// Decode exactly the canonical seven-field kind-5 row.
    ///
    /// # Errors
    /// Rejects a malformed, truncated, extended or nonpreferred encoding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, LocalCutSealErrorV2> {
        let mut reader = Reader::new(bytes);
        reader.array(7)?;
        let row = Self {
            timeline_id: reader.timeline()?,
            result_logical_head: reader.uint()?,
            result_stitched_hash: reader.hash()?,
            result_source_segment_head: reader.uint()?,
            result_source_chain_hash: reader.hash()?,
            successor_wcb_hash: reader.hash()?,
            event_count: reader.uint()?,
        };
        finish_row(&reader, bytes, &row.to_canonical_cbor())?;
        Ok(row)
    }
}

/// Require a decoded row to span its input and re-encode to the same bytes.
fn finish_row(
    reader: &Reader<'_>,
    bytes: &[u8],
    canonical: &[u8],
) -> Result<(), LocalCutSealErrorV2> {
    if !reader.is_finished() {
        Err(LocalCutSealErrorV2::InvalidEncoding)
    } else if canonical != bytes {
        Err(LocalCutSealErrorV2::NonCanonical)
    } else {
        Ok(())
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
        pack(EXPECTED_HEADS_KIND, owner_id, cut_id, &encoded)
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
        pack(RESULT_HEADS_KIND, owner_id, cut_id, &encoded)
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

fn check_sorted(
    timelines: impl Iterator<Item = TimelineId> + Clone,
) -> Result<(), LocalCutSealErrorV2> {
    let mut pairs = timelines.clone().zip(timelines.skip(1));
    if pairs.any(|(left, right)| left >= right) {
        Err(LocalCutSealErrorV2::RowsNotSorted)
    } else {
        Ok(())
    }
}

/// Pack one cut's encoded rows of `kind` with the shared LCP1/LCT1 packer.
///
/// The ADR-082 row cap is enforced once, by the table reference after
/// packing. An earlier length check would return the same `FieldOutOfBounds`;
/// only the work it saves would differ, which no public-seam test can observe
/// without allocating more than a million rows, so none is made.
fn pack(
    kind: u64,
    owner_id: [u8; 32],
    cut_id: u64,
    rows: &[Vec<u8>],
) -> Result<LocalCutHeadsTableV1, LocalCutSealErrorV2> {
    let tree_scope = local_cut_tree_scope_v1(owner_id, cut_id);
    let packed = pack_local_cut_table(kind, tree_scope, rows);
    packed.map(|(reference, node_records)| LocalCutHeadsTableV1 {
        reference,
        node_records,
    })
}
