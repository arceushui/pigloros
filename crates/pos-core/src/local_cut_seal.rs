//! Portable LCS2 seal and table-reference shapes, without local-cut authority.
//!
//! A structurally valid seal does not establish that an installed owner selected
//! its manifest binding, committed a cut, or retained protected native bytes.

use crate::{Hash, TimelineId};
use std::collections::BTreeMap;

/// Maximum accepted size of one preferred LCS2 seal.
pub const MAX_LOCAL_CUT_SEAL_BYTES_V2: usize = 16_384;
/// Maximum structural row count of an ADR-082 local-cut table.
pub const MAX_LOCAL_CUT_TABLE_ROWS_V1: u64 = 1_048_576;

const DOMAIN: &[u8] = b"pigloros.local-cut.seal.v2\0";
const PAGE_DOMAIN: &[u8] = b"pigloros.local-cut.page.v1\0";
const BRANCH_DOMAIN: &[u8] = b"pigloros.local-cut.branch.v1\0";
const CUT_SCOPE_DOMAIN: &[u8] = b"pigloros.local-cut.scope.v1\0";
const MANIFEST_BINDING_KIND: u64 = 14;
const MAX_PAGE_ROWS: usize = 64;
const MAX_BRANCH_CHILDREN: usize = 240;
const MAX_TABLE_NODE_BYTES: usize = 65_536;

/// Closed structural LCS2 errors; none represents an owner decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalCutSealErrorV2 {
    #[error("invalid LCS2 encoding")]
    InvalidEncoding,
    #[error("noncanonical LCS2 encoding")]
    NonCanonical,
    #[error("unsupported LCS2 version")]
    UnsupportedVersion,
    #[error("LCS2 field is out of bounds")]
    FieldOutOfBounds,
    #[error("LCS2 content address is zero")]
    ZeroContentAddress,
    #[error("LCS2 table reference has an invalid count/root pair")]
    InvalidTableReference,
    #[error("LCS2 manifest-binding rows are not sorted and unique")]
    RowsNotSorted,
    #[error("LCS2 table node has an invalid kind, scope, ordinal, or packing")]
    InvalidTableNode,
    #[error("LCS2 table records do not match their reference")]
    TableMismatch,
}

/// One bounded ADR-082 packed-table reference: empty iff its root is null.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutTableRefV1 {
    row_count: u64,
    root_hash: Option<Hash>,
}

impl LocalCutTableRefV1 {
    /// Validate a structural table reference, without traversing its nodes.
    ///
    /// # Errors
    /// Rejects excess rows, a missing/nonempty root, or a zero content address.
    pub fn new(row_count: u64, root_hash: Option<Hash>) -> Result<Self, LocalCutSealErrorV2> {
        if row_count > MAX_LOCAL_CUT_TABLE_ROWS_V1 {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        if (row_count == 0) != root_hash.is_none() {
            return Err(LocalCutSealErrorV2::InvalidTableReference);
        }
        if root_hash.is_some_and(|hash| hash == Hash::zero()) {
            return Err(LocalCutSealErrorV2::ZeroContentAddress);
        }
        Ok(Self {
            row_count,
            root_hash,
        })
    }

    #[must_use]
    pub const fn row_count(self) -> u64 {
        self.row_count
    }

    #[must_use]
    pub const fn root_hash(self) -> Option<Hash> {
        self.root_hash
    }
}

/// One prospective kind-14 manifest binding; only the installed owner can authenticate it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutManifestBindingRowV1 {
    pub timeline_id: TimelineId,
    pub scope: Hash,
    pub wcs_hash: Hash,
    pub msr_hash: Hash,
    pub msb_hash: Hash,
}

impl LocalCutManifestBindingRowV1 {
    /// Check only the portable nonzero-address shape.
    ///
    /// # Errors
    /// Rejects zero scope or content addresses.
    pub fn validate(self) -> Result<Self, LocalCutSealErrorV2> {
        if [self.scope, self.wcs_hash, self.msr_hash, self.msb_hash].contains(&Hash::zero()) {
            Err(LocalCutSealErrorV2::ZeroContentAddress)
        } else {
            Ok(self)
        }
    }
}

/// Derive the ADR-082 cut tree scope, without asserting that the cut exists.
#[must_use]
pub fn local_cut_tree_scope_v1(owner_id: [u8; 32], cut_id: u64) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CUT_SCOPE_DOMAIN);
    hasher.update(&owner_id);
    hasher.update(&cut_id.to_be_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// One canonical LCP1 page for kind-14 rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutManifestBindingPageV1 {
    tree_scope: Hash,
    first_ordinal: u64,
    rows: Vec<LocalCutManifestBindingRowV1>,
}

impl LocalCutManifestBindingPageV1 {
    /// Construct a page with bounded, sorted, unique rows.
    ///
    /// # Errors
    /// Rejects invalid scope, row count, ordinal range, or row order.
    pub fn new(
        tree_scope: Hash,
        first_ordinal: u64,
        rows: Vec<LocalCutManifestBindingRowV1>,
    ) -> Result<Self, LocalCutSealErrorV2> {
        if tree_scope == Hash::zero() {
            return Err(LocalCutSealErrorV2::ZeroContentAddress);
        }
        if rows.is_empty()
            || rows.len() > MAX_PAGE_ROWS
            || first_ordinal
                .checked_add(rows.len() as u64)
                .is_none_or(|end| end > MAX_LOCAL_CUT_TABLE_ROWS_V1)
        {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        if rows.windows(2).any(|pair| {
            pair[0].timeline_id.inner().to_bytes() >= pair[1].timeline_id.inner().to_bytes()
        }) {
            return Err(LocalCutSealErrorV2::RowsNotSorted);
        }
        for row in &rows {
            row.validate()?;
        }
        Ok(Self {
            tree_scope,
            first_ordinal,
            rows,
        })
    }

    #[must_use]
    pub const fn first_ordinal(&self) -> u64 {
        self.first_ordinal
    }

    #[must_use]
    pub fn rows(&self) -> &[LocalCutManifestBindingRowV1] {
        &self.rows
    }

    /// Encode exactly six definite LCP1 fields.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 * self.rows.len() + 64);
        encode_head(&mut out, 4, 6);
        encode_bytes(&mut out, b"LCP1");
        encode_head(&mut out, 0, 1);
        encode_head(&mut out, 0, MANIFEST_BINDING_KIND);
        encode_bytes(&mut out, self.tree_scope.as_bytes());
        encode_head(&mut out, 0, self.first_ordinal);
        encode_head(&mut out, 4, self.rows.len() as u64);
        for row in &self.rows {
            encode_head(&mut out, 4, 5);
            encode_bytes(&mut out, &row.timeline_id.inner().to_bytes());
            for hash in [row.scope, row.wcs_hash, row.msr_hash, row.msb_hash] {
                encode_bytes(&mut out, hash.as_bytes());
            }
        }
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(PAGE_DOMAIN, &self.to_canonical_cbor())
    }

    /// Parse only a canonical kind-14 page in the expected cut scope.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, wrong-kind/scope, unsorted, or oversized pages.
    pub fn from_canonical_cbor(
        expected_scope: Hash,
        bytes: &[u8],
    ) -> Result<Self, LocalCutSealErrorV2> {
        if bytes.len() > MAX_TABLE_NODE_BYTES {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.array(6)?;
        if reader.fixed_bytes::<4>()? != *b"LCP1" {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        if reader.uint()? != 1 {
            return Err(LocalCutSealErrorV2::UnsupportedVersion);
        }
        if reader.uint()? != MANIFEST_BINDING_KIND || reader.hash()? != expected_scope {
            return Err(LocalCutSealErrorV2::InvalidTableNode);
        }
        let first_ordinal = reader.uint()?;
        let row_count = reader.array_len()?;
        if !(1..=MAX_PAGE_ROWS as u64).contains(&row_count) {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        let mut rows = Vec::new();
        for _ in 0..row_count {
            reader.array(5)?;
            let timeline_id = TimelineId::from_ulid(ulid::Ulid::from_bytes(reader.fixed_bytes()?));
            rows.push(LocalCutManifestBindingRowV1 {
                timeline_id,
                scope: reader.hash()?,
                wcs_hash: reader.hash()?,
                msr_hash: reader.hash()?,
                msb_hash: reader.hash()?,
            });
        }
        if reader.offset != bytes.len() {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        let page = Self::new(expected_scope, first_ordinal, rows)?;
        if page.to_canonical_cbor() != bytes {
            return Err(LocalCutSealErrorV2::NonCanonical);
        }
        Ok(page)
    }
}

/// One ordered LCT1 child range and its node content address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutBranchChildV1 {
    pub first_ordinal: u64,
    pub row_count: u64,
    pub node_hash: Hash,
}

/// One canonical LCT1 branch for kind-14 pages or lower branches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutManifestBindingBranchV1 {
    tree_scope: Hash,
    height: u8,
    first_ordinal: u64,
    row_count: u64,
    children: Vec<LocalCutBranchChildV1>,
}

impl LocalCutManifestBindingBranchV1 {
    /// Construct a contiguous height-one or height-two branch.
    ///
    /// # Errors
    /// Rejects invalid fanout, height, zero child hashes/counts, or gaps/overflow.
    pub fn new(
        tree_scope: Hash,
        height: u8,
        first_ordinal: u64,
        children: Vec<LocalCutBranchChildV1>,
    ) -> Result<Self, LocalCutSealErrorV2> {
        if tree_scope == Hash::zero() {
            return Err(LocalCutSealErrorV2::ZeroContentAddress);
        }
        if !(1..=2).contains(&height) || children.is_empty() || children.len() > MAX_BRANCH_CHILDREN
        {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        let mut next = first_ordinal;
        for child in &children {
            if child.first_ordinal != next
                || child.row_count == 0
                || child.node_hash == Hash::zero()
            {
                return Err(LocalCutSealErrorV2::InvalidTableNode);
            }
            next = next
                .checked_add(child.row_count)
                .ok_or(LocalCutSealErrorV2::FieldOutOfBounds)?;
        }
        if next > MAX_LOCAL_CUT_TABLE_ROWS_V1 {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        Ok(Self {
            tree_scope,
            height,
            first_ordinal,
            row_count: next - first_ordinal,
            children,
        })
    }

    #[must_use]
    pub const fn row_count(&self) -> u64 {
        self.row_count
    }

    #[must_use]
    pub const fn first_ordinal(&self) -> u64 {
        self.first_ordinal
    }

    #[must_use]
    pub const fn height(&self) -> u8 {
        self.height
    }

    #[must_use]
    pub fn children(&self) -> &[LocalCutBranchChildV1] {
        &self.children
    }

    /// Encode exactly eight definite LCT1 fields.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 * self.children.len() + 64);
        encode_head(&mut out, 4, 8);
        encode_bytes(&mut out, b"LCT1");
        encode_head(&mut out, 0, 1);
        encode_head(&mut out, 0, MANIFEST_BINDING_KIND);
        encode_bytes(&mut out, self.tree_scope.as_bytes());
        encode_head(&mut out, 0, u64::from(self.height));
        encode_head(&mut out, 0, self.first_ordinal);
        encode_head(&mut out, 0, self.row_count);
        encode_head(&mut out, 4, self.children.len() as u64);
        for child in &self.children {
            encode_head(&mut out, 4, 3);
            encode_head(&mut out, 0, child.first_ordinal);
            encode_head(&mut out, 0, child.row_count);
            encode_bytes(&mut out, child.node_hash.as_bytes());
        }
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(BRANCH_DOMAIN, &self.to_canonical_cbor())
    }

    /// Parse only a canonical kind-14 branch in the expected cut scope.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, wrong-kind/scope, gapped, or oversized branches.
    pub fn from_canonical_cbor(
        expected_scope: Hash,
        bytes: &[u8],
    ) -> Result<Self, LocalCutSealErrorV2> {
        if bytes.len() > MAX_TABLE_NODE_BYTES {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.array(8)?;
        if reader.fixed_bytes::<4>()? != *b"LCT1" {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        if reader.uint()? != 1 {
            return Err(LocalCutSealErrorV2::UnsupportedVersion);
        }
        if reader.uint()? != MANIFEST_BINDING_KIND || reader.hash()? != expected_scope {
            return Err(LocalCutSealErrorV2::InvalidTableNode);
        }
        let height =
            u8::try_from(reader.uint()?).map_err(|_| LocalCutSealErrorV2::FieldOutOfBounds)?;
        let first_ordinal = reader.uint()?;
        let row_count = reader.uint()?;
        let child_count = reader.array_len()?;
        if !(1..=MAX_BRANCH_CHILDREN as u64).contains(&child_count) {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        let mut children = Vec::new();
        for _ in 0..child_count {
            reader.array(3)?;
            children.push(LocalCutBranchChildV1 {
                first_ordinal: reader.uint()?,
                row_count: reader.uint()?,
                node_hash: reader.hash()?,
            });
        }
        if reader.offset != bytes.len() {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        let branch = Self::new(expected_scope, height, first_ordinal, children)?;
        if branch.row_count != row_count {
            return Err(LocalCutSealErrorV2::InvalidTableNode);
        }
        if branch.to_canonical_cbor() != bytes {
            return Err(LocalCutSealErrorV2::NonCanonical);
        }
        Ok(branch)
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Canonically packed kind-14 records, still unauthenticated by any owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutManifestBindingTableV1 {
    tree_scope: Hash,
    rows: Vec<LocalCutManifestBindingRowV1>,
    reference: LocalCutTableRefV1,
    records: Vec<Vec<u8>>,
}

impl LocalCutManifestBindingTableV1 {
    /// Pack ordered kind-14 rows into the minimal ADR-082 LCP1/LCT1 tree.
    ///
    /// # Errors
    /// Rejects zero cut IDs, excess/unsorted rows, or invalid row addresses.
    pub fn new(
        owner_id: [u8; 32],
        cut_id: u64,
        rows: Vec<LocalCutManifestBindingRowV1>,
    ) -> Result<Self, LocalCutSealErrorV2> {
        if cut_id == 0 || rows.len() as u64 > MAX_LOCAL_CUT_TABLE_ROWS_V1 {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        if rows.windows(2).any(|pair| {
            pair[0].timeline_id.inner().to_bytes() >= pair[1].timeline_id.inner().to_bytes()
        }) {
            return Err(LocalCutSealErrorV2::RowsNotSorted);
        }
        for row in &rows {
            row.validate()?;
        }
        let tree_scope = local_cut_tree_scope_v1(owner_id, cut_id);
        let mut records = Vec::new();
        let mut level = Vec::new();
        for (index, chunk) in rows.chunks(MAX_PAGE_ROWS).enumerate() {
            let first_ordinal = (index * MAX_PAGE_ROWS) as u64;
            let page =
                LocalCutManifestBindingPageV1::new(tree_scope, first_ordinal, chunk.to_vec())?;
            level.push(LocalCutBranchChildV1 {
                first_ordinal,
                row_count: chunk.len() as u64,
                node_hash: page.digest(),
            });
            records.push(page.to_canonical_cbor());
        }
        let root_hash = if level.len() > 1 {
            let mut parent_level = Vec::new();
            for children in level.chunks(MAX_BRANCH_CHILDREN) {
                let branch = LocalCutManifestBindingBranchV1::new(
                    tree_scope,
                    1,
                    children[0].first_ordinal,
                    children.to_vec(),
                )?;
                parent_level.push(LocalCutBranchChildV1 {
                    first_ordinal: branch.first_ordinal(),
                    row_count: branch.row_count(),
                    node_hash: branch.digest(),
                });
                records.push(branch.to_canonical_cbor());
            }
            if parent_level.len() == 1 {
                Some(parent_level[0].node_hash)
            } else {
                let root = LocalCutManifestBindingBranchV1::new(tree_scope, 2, 0, parent_level)?;
                let hash = root.digest();
                records.push(root.to_canonical_cbor());
                Some(hash)
            }
        } else {
            level.first().map(|node| node.node_hash)
        };
        let reference = LocalCutTableRefV1::new(rows.len() as u64, root_hash)?;
        Ok(Self {
            tree_scope,
            rows,
            reference,
            records,
        })
    }

    /// Validate a complete collection of content-addressed kind-14 nodes.
    ///
    /// The records may arrive in any order; no hash or CBOR shape grants cut
    /// selection authority without the installed owner and signed receipt.
    ///
    /// # Errors
    /// Rejects omitted, extra, duplicate, gapped, noncanonical, incorrectly
    /// packed, wrong-scope/kind, or misaddressed records.
    pub fn from_records(
        owner_id: [u8; 32],
        cut_id: u64,
        reference: LocalCutTableRefV1,
        records: &[Vec<u8>],
    ) -> Result<Self, LocalCutSealErrorV2> {
        let row_count = reference.row_count();
        let page_count = row_count.div_ceil(MAX_PAGE_ROWS as u64);
        let branch_count = if page_count > 1 {
            page_count.div_ceil(MAX_BRANCH_CHILDREN as u64)
        } else {
            0
        };
        let root_count = u64::from(branch_count > 1);
        if records.len() as u64 != page_count + branch_count + root_count {
            return Err(LocalCutSealErrorV2::TableMismatch);
        }
        let tree_scope = local_cut_tree_scope_v1(owner_id, cut_id);
        let mut pages = Vec::new();
        let mut supplied = BTreeMap::new();
        for bytes in records {
            let digest = if bytes.starts_with(&[0x86, 0x44, b'L', b'C', b'P', b'1']) {
                let page = LocalCutManifestBindingPageV1::from_canonical_cbor(tree_scope, bytes)?;
                let digest = page.digest();
                pages.push(page);
                digest
            } else if bytes.starts_with(&[0x88, 0x44, b'L', b'C', b'T', b'1']) {
                let branch =
                    LocalCutManifestBindingBranchV1::from_canonical_cbor(tree_scope, bytes)?;
                branch.digest()
            } else {
                return Err(LocalCutSealErrorV2::InvalidEncoding);
            };
            if supplied.insert(digest, bytes.as_slice()).is_some() {
                return Err(LocalCutSealErrorV2::TableMismatch);
            }
        }
        if pages.len() as u64 != page_count {
            return Err(LocalCutSealErrorV2::TableMismatch);
        }
        pages.sort_unstable_by_key(LocalCutManifestBindingPageV1::first_ordinal);
        let mut rows = Vec::new();
        for page in pages {
            if page.first_ordinal() != rows.len() as u64 {
                return Err(LocalCutSealErrorV2::InvalidTableNode);
            }
            rows.extend_from_slice(page.rows());
        }
        if rows.len() as u64 != row_count {
            return Err(LocalCutSealErrorV2::TableMismatch);
        }
        let canonical = Self::new(owner_id, cut_id, rows)?;
        if canonical.reference != reference || canonical.records.len() != supplied.len() {
            return Err(LocalCutSealErrorV2::TableMismatch);
        }
        for bytes in &canonical.records {
            let digest = if bytes[0] == 0x86 {
                domain_digest(PAGE_DOMAIN, bytes)
            } else {
                domain_digest(BRANCH_DOMAIN, bytes)
            };
            if supplied.get(&digest) != Some(&bytes.as_slice()) {
                return Err(LocalCutSealErrorV2::TableMismatch);
            }
        }
        Ok(canonical)
    }

    #[must_use]
    pub const fn tree_scope(&self) -> Hash {
        self.tree_scope
    }

    #[must_use]
    pub const fn table_ref(&self) -> LocalCutTableRefV1 {
        self.reference
    }

    #[must_use]
    pub fn rows(&self) -> &[LocalCutManifestBindingRowV1] {
        &self.rows
    }

    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }
}

/// Untrusted prospective LCS2 fields. The installed owner must validate them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutSealInputV2 {
    pub owner_id: [u8; 32],
    pub cut_id: u64,
    pub tick: u64,
    pub membership_epoch: u32,
    pub configuration_generation: u64,
    pub schedule_ns: u64,
    pub previous_visible_receipt_hash: Option<Hash>,
    pub expected_inventory_generation: Hash,
    pub membership_table: LocalCutTableRefV1,
    pub composition_table: LocalCutTableRefV1,
    pub inbox_table: LocalCutTableRefV1,
    pub invocation_table: LocalCutTableRefV1,
    pub expected_heads_table: LocalCutTableRefV1,
    pub ebp_native_hash: Hash,
    pub execution_profile_native_hash: Hash,
    pub recording_context_table: LocalCutTableRefV1,
    pub owner_operational_policy_hash: Hash,
    pub explicit_attempt_hash: Option<Hash>,
    pub ingress_preallocation_native_hash: Hash,
    pub manifest_binding_table: LocalCutTableRefV1,
}

/// Preferred twenty-two-field LCS2 structure, not an authenticated cut seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutSealV2(LocalCutSealInputV2);

impl LocalCutSealV2 {
    /// Validate finite structural fields; owner/table bijections are separate.
    ///
    /// # Errors
    /// Rejects zero mandatory addresses, invalid positive counters or table caps.
    pub fn new(input: LocalCutSealInputV2) -> Result<Self, LocalCutSealErrorV2> {
        if input.cut_id == 0 || input.tick == 0 || input.configuration_generation == 0 {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        if [
            input.expected_inventory_generation,
            input.ebp_native_hash,
            input.execution_profile_native_hash,
            input.owner_operational_policy_hash,
            input.ingress_preallocation_native_hash,
        ]
        .contains(&Hash::zero())
            || [
                input.previous_visible_receipt_hash,
                input.explicit_attempt_hash,
            ]
            .into_iter()
            .flatten()
            .any(|hash| hash == Hash::zero())
        {
            return Err(LocalCutSealErrorV2::ZeroContentAddress);
        }
        if input.inbox_table.row_count > 65_536 || input.invocation_table.row_count > 65_536 {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn as_input(&self) -> &LocalCutSealInputV2 {
        &self.0
    }

    /// Encode the unique preferred definite LCS2 record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = &self.0;
        let mut out = Vec::with_capacity(512);
        encode_head(&mut out, 4, 22);
        encode_bytes(&mut out, b"LCS2");
        encode_head(&mut out, 0, 1);
        encode_bytes(&mut out, &input.owner_id);
        for value in [input.cut_id, input.tick] {
            encode_head(&mut out, 0, value);
        }
        encode_head(&mut out, 0, u64::from(input.membership_epoch));
        encode_head(&mut out, 0, input.configuration_generation);
        encode_head(&mut out, 0, input.schedule_ns);
        encode_optional_hash(&mut out, input.previous_visible_receipt_hash);
        encode_bytes(&mut out, input.expected_inventory_generation.as_bytes());
        for reference in [
            input.membership_table,
            input.composition_table,
            input.inbox_table,
            input.invocation_table,
            input.expected_heads_table,
        ] {
            encode_table_ref(&mut out, reference);
        }
        encode_bytes(&mut out, input.ebp_native_hash.as_bytes());
        encode_bytes(&mut out, input.execution_profile_native_hash.as_bytes());
        encode_table_ref(&mut out, input.recording_context_table);
        encode_bytes(&mut out, input.owner_operational_policy_hash.as_bytes());
        encode_optional_hash(&mut out, input.explicit_attempt_hash);
        encode_bytes(&mut out, input.ingress_preallocation_native_hash.as_bytes());
        encode_table_ref(&mut out, input.manifest_binding_table);
        out
    }

    /// Ordinary BLAKE3 over the approved LCS2 domain, NUL and exact bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode one bounded preferred LCS2 structure; old LCS1 is not upcast.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized and unsupported wire forms.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, LocalCutSealErrorV2> {
        if bytes.len() > MAX_LOCAL_CUT_SEAL_BYTES_V2 {
            return Err(LocalCutSealErrorV2::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.array(22)?;
        if reader.fixed_bytes::<4>()? != *b"LCS2" {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        if reader.uint()? != 1 {
            return Err(LocalCutSealErrorV2::UnsupportedVersion);
        }
        let owner_id = reader.fixed_bytes()?;
        let cut_id = reader.uint()?;
        let tick = reader.uint()?;
        let membership_epoch =
            u32::try_from(reader.uint()?).map_err(|_| LocalCutSealErrorV2::FieldOutOfBounds)?;
        let configuration_generation = reader.uint()?;
        let schedule_ns = reader.uint()?;
        let previous_visible_receipt_hash = reader.optional_hash()?;
        let expected_inventory_generation = reader.hash()?;
        let membership_table = reader.table_ref()?;
        let composition_table = reader.table_ref()?;
        let inbox_table = reader.table_ref()?;
        let invocation_table = reader.table_ref()?;
        let expected_heads_table = reader.table_ref()?;
        let ebp_native_hash = reader.hash()?;
        let execution_profile_native_hash = reader.hash()?;
        let recording_context_table = reader.table_ref()?;
        let owner_operational_policy_hash = reader.hash()?;
        let explicit_attempt_hash = reader.optional_hash()?;
        let ingress_preallocation_native_hash = reader.hash()?;
        let manifest_binding_table = reader.table_ref()?;
        if reader.offset != bytes.len() {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        let record = Self::new(LocalCutSealInputV2 {
            owner_id,
            cut_id,
            tick,
            membership_epoch,
            configuration_generation,
            schedule_ns,
            previous_visible_receipt_hash,
            expected_inventory_generation,
            membership_table,
            composition_table,
            inbox_table,
            invocation_table,
            expected_heads_table,
            ebp_native_hash,
            execution_profile_native_hash,
            recording_context_table,
            owner_operational_policy_hash,
            explicit_attempt_hash,
            ingress_preallocation_native_hash,
            manifest_binding_table,
        })?;
        if record.to_canonical_cbor() != bytes {
            return Err(LocalCutSealErrorV2::NonCanonical);
        }
        Ok(record)
    }
}

fn encode_table_ref(out: &mut Vec<u8>, reference: LocalCutTableRefV1) {
    encode_head(out, 4, 2);
    encode_head(out, 0, reference.row_count);
    encode_optional_hash(out, reference.root_hash);
}

fn encode_optional_hash(out: &mut Vec<u8>, hash: Option<Hash>) {
    if let Some(hash) = hash {
        encode_bytes(out, hash.as_bytes());
    } else {
        out.push(0xf6);
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        // The low byte is exact here because the value is below 24.
        out.push((major << 5) | value.to_be_bytes()[7]);
    } else if let Ok(value) = u8::try_from(value) {
        out.extend_from_slice(&[(major << 5) | 0x18, value]);
    } else if let Ok(value) = u16::try_from(value) {
        out.push((major << 5) | 0x19);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push((major << 5) | 0x1a);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push((major << 5) | 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], LocalCutSealErrorV2> {
        // Seal input is capped at 16 KiB, node input at 64 KiB, and each read
        // requests at most 32 bytes on supported targets.
        let end = self.offset + length;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(LocalCutSealErrorV2::InvalidEncoding)?;
        self.offset = end;
        Ok(slice)
    }

    fn head(&mut self, major: u8) -> Result<u64, LocalCutSealErrorV2> {
        let initial = self.take(1)?[0];
        if initial >> 5 != major {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        match initial & 31 {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.take(1)?[0])),
            25 => {
                let mut bytes = [0; 2];
                bytes.copy_from_slice(self.take(2)?);
                Ok(u64::from(u16::from_be_bytes(bytes)))
            }
            26 => {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(self.take(4)?);
                Ok(u64::from(u32::from_be_bytes(bytes)))
            }
            27 => {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(self.take(8)?);
                Ok(u64::from_be_bytes(bytes))
            }
            _ => Err(LocalCutSealErrorV2::InvalidEncoding),
        }
    }

    fn array(&mut self, count: u64) -> Result<(), LocalCutSealErrorV2> {
        if self.head(4)? == count {
            Ok(())
        } else {
            Err(LocalCutSealErrorV2::InvalidEncoding)
        }
    }

    fn array_len(&mut self) -> Result<u64, LocalCutSealErrorV2> {
        self.head(4)
    }

    fn uint(&mut self) -> Result<u64, LocalCutSealErrorV2> {
        self.head(0)
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], LocalCutSealErrorV2> {
        if self.head(2)? != N as u64 {
            return Err(LocalCutSealErrorV2::InvalidEncoding);
        }
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.take(N)?);
        Ok(bytes)
    }

    fn hash(&mut self) -> Result<Hash, LocalCutSealErrorV2> {
        Ok(Hash::from_bytes(self.fixed_bytes()?))
    }

    fn optional_hash(&mut self) -> Result<Option<Hash>, LocalCutSealErrorV2> {
        if self.bytes.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            Ok(None)
        } else {
            self.hash().map(Some)
        }
    }

    fn table_ref(&mut self) -> Result<LocalCutTableRefV1, LocalCutSealErrorV2> {
        self.array(2)?;
        let count = self.uint()?;
        let root = self.optional_hash()?;
        LocalCutTableRefV1::new(count, root)
    }
}
