//! ADR-064 counterfactual dependency record contract and read port.
//!
//! The counterfactual coordinator derives the closed dependency graph from the
//! committed edges of a parent Timeline prefix and from the provisional edges
//! of a Fork generation. This module is the consumer-side storage contract for
//! those rows: a per-Tick [`TickDependencyRecordV1`] that commits atomically
//! with the Tick's Events, the write-side
//! [`CounterfactualDependencyRecordingPortV1`], and the paged
//! [`CounterfactualDependencyReadPortV1`]. It names no backend type and
//! contains no adapter, coordinator, or producer code.
//!
//! # Carrying `IDP1` without the conformance crate
//!
//! `pos-conformance` and `pos-time` depend on `pos-core`, so this contract
//! cannot name their decoded `InputDependencyV1` or `DependencyNodeV1`.
//! Like the `RCF1` and `SIV1` bytes of the storage port, an edge travels as
//! exact canonical `IDP1` bytes in a core-native newtype,
//! [`DependencyEdgeRecordV1`]. Construction verifies, without a CBOR decoder:
//!
//! - the size bound ([`MAX_DEPENDENCY_EDGE_BYTES_V1`]) before anything else;
//! - the nine-field array head, then the text magic and version `1`;
//! - that the consumer node coordinate inside the bytes is byte-for-byte the
//!   canonical encoding of the supplied [`DependencyNodeCoordinateV1`];
//! - that the supplied source digest is nonzero;
//! - that the source node is a six-field array whose owner text is 1 to
//!   [`MAX_DEPENDENCY_OWNER_ID_BYTES_V1`] bytes, so the 16 KiB edge bound
//!   cannot be spent on owner padding, and that its artifact digest is the
//!   supplied source digest. The conformance codec
//!   (`crates/pos-conformance/src/counterfactual/dependency.rs`) validates
//!   the owners of BOTH coordinates as 1 to 128 bytes, so this bound rejects
//!   nothing the conformance codec accepts;
//! - that the five remaining fields are well-formed definite-length items
//!   and that nothing trails them.
//!
//! `IDP1` carries no self-digest, so [`DependencyEdgeRecordV1::digest`] is the
//! domain-separated BLAKE3 digest of the bytes
//! (`PiglorOS.InputDependency.v1`, a zero byte, the bytes), the same value the
//! conformance `InputDependencyV1` digest computes. What this module
//! deliberately does not verify, and the conformance codec must, is: the
//! shortest-form integers and UTF-8 of the source node and of the five
//! trailing fields, the source coordinate's own bounds and its strict
//! precedence of the consumer, the class code, the Tick range covering both
//! endpoints, the authorization digest, the classification rule, and the
//! nonzero provenance digest. The parity test of this contract belongs in
//! `pos-conformance`, which already owns the `IDP1` codec; it lives in
//! `crates/pos-conformance/tests` beside the storage-port parity test and
//! proves that every conformance-encoded edge is accepted here with the
//! extracted coordinates.
//!
//! # ADR gap decisions
//!
//! - **Per-parent-Timeline committed prefix.** Nodes and edges whose origin is
//!   [`RecordedNodeOriginV1::Committed`] belong to the inherited parent
//!   prefix. They are recorded once per parent Timeline and addressed with
//!   [`DependencyReadScopeV1::ParentPrefix`]; they are never copied into each
//!   Fork. Nodes of origin [`RecordedNodeOriginV1::Provisional`] belong to
//!   one Fork generation and are addressed with
//!   [`DependencyReadScopeV1::ForkGeneration`]. A reader stitches a Fork's
//!   graph by reading the parent prefix through the parent-cut Tick and then
//!   the Fork generation. The Tick windows are disjoint (committed nodes lie
//!   at or before the parent cut and provisional nodes after it) and each
//!   scope is canonically ordered, so stitching is plain concatenation.
//! - **One origin and one Tick per record.** A [`TickDependencyRecordV1`]
//!   holds the nodes of one origin and is recorded at one Tick, so a record
//!   is either a parent-prefix record or a Fork-generation record, never
//!   both. The Fork write methods accept only provisional records;
//!   recording committed parent rows is the factual-Tick producer's write
//!   (see Deferred).
//! - **Root nodes ride the first Tick record at or after their effective
//!   Tick.** `pos-time` requires one `InterventionAssigned` node per plan
//!   intervention at the intervention's effective Tick, and frozen and
//!   fixed-policy roots need homes too, but the recompute Ticks of a Fork
//!   need not include those Ticks. Root-class nodes
//!   ([`RecordedDependencyClassV1::is_root`]) may therefore carry a Tick at
//!   or before the record's Tick; they are recorded with the first Tick
//!   record of their origin whose Tick is at or after their own. Every other
//!   node (`EndogenousRecomputed`, `PresentationOnly`) must carry exactly the
//!   record's Tick. The record checks the bound (`BindingMismatch` for a root
//!   node after the record's Tick or a non-root node at any other Tick). The
//!   rest of the placement is the producer's and coordinator's obligation,
//!   because the store sees neither the plan nor the omitted rows: that a
//!   root rides the *first* such record, and that the LAST record's Tick is
//!   at or after the maximum root effective Tick. A root whose effective
//!   Tick is after the last recomputed Tick has no record at all, and
//!   `pos-time` then fails with `InterventionNodeMissing`. Reads filter and
//!   order by the node's own Tick, never the record's, so a root node is
//!   addressed at its effective Tick. Because a root can arrive in a later
//!   record behind a reader's cursor, paging a generation that is still being
//!   written is not stable. That is a READER and coordinator obligation: read
//!   a generation only after the final Tick record of the generation is
//!   committed (a parent prefix likewise only once it is complete). An adapter
//!   cannot know whether a generation is still being written, so it just
//!   serves the committed state.
//! - **Generation qualification.** Provisional rows are written under the
//!   Fork generation the same transaction commits (the new generation for an
//!   invalidation, the expected basis generation for a later Tick) and are
//!   read with the exact generation. A read at any other generation, which
//!   includes every quarantined earlier generation, is
//!   `MixedForkGeneration`; [`DependencyReadScopeV1::ensure_current`] is the
//!   one place that rule lives.
//! - **Digest ownership.** The host derives the dependency-graph digest from
//!   the recorded graph and publishes it with
//!   [`crate::CounterfactualStorePortV1::publish_counterfactual_facts`]. The
//!   store neither computes nor mutates it, and nothing here touches
//!   [`crate::CounterfactualFactsV1`].
//! - **Parallel methods.** The recording methods are new methods of a new
//!   supertrait of the storage port. No signature of
//!   [`crate::CounterfactualStorePortV1`] or of its invalidation input and
//!   command types changes, so existing fakes and callers keep compiling.
//! - **Structural checks only.** The store enforces what it can without the
//!   plan: bounds (node, edge, declared-input, and aggregate edge-byte
//!   counts), strictly ascending unique nodes, canonical edge order, that
//!   every edge consumer is a node of the same record, and that every edge
//!   is declared by its consumer. The unknown-edge policy, horizon, class,
//!   and authorization rules stay in `pos-time` validation. A declared input
//!   without an edge is legal here because `FullSuffixFromCut` records it as
//!   a missing edge; [`TickDependencyRecordV1::uncovered_input_count`]
//!   reports how many there are.
//! - **Bounds.** A graph holds at most 1,000,000 nodes and 4,000,000 edges
//!   ([`MAX_RECORDED_DEPENDENCY_NODES_V1`],
//!   [`MAX_RECORDED_DEPENDENCY_EDGES_V1`]) per recorded set, and `pos-time`
//!   rejects a graph whose declared inputs exceed its edge bound, so the
//!   recorded set's declared-input total is held to the same edge bound.
//!   Adapters enforce all three with
//!   [`TickDependencyRecordV1::ensure_set_capacity`], passing the set's
//!   [`RecordedSetCountsV1`]. Adapters check each recorded set on its own
//!   only: the graph `pos-time` consumes is the stitched parent prefix plus
//!   Fork generation, which `pos-time` also caps at the same node and edge
//!   totals, and a digest can repeat across the two sets. The host and
//!   `pos-time` reject an oversized or duplicated stitched graph (fail
//!   closed); no adapter can see both sets. One record commits
//!   inside one Event Store transaction, so it is capped far lower
//!   ([`MAX_TICK_DEPENDENCY_NODES_V1`] and
//!   [`MAX_TICK_DEPENDENCY_EDGES_V1`], the same one to four ratio, which
//!   also bounds [`TickDependencyRecordV1::declared_input_count`]). The
//!   16 KiB per-edge cap alone would let 262,144 edges hold 4 GiB, so a
//!   record's edges are also capped at
//!   [`MAX_TICK_DEPENDENCY_EDGE_BYTES_V1`] bytes in total, 128 MiB: 512 bytes
//!   per edge at the full edge count, well above the roughly 240 bytes of a
//!   typical edge and the roughly 600 bytes of one with the longest legal
//!   owner IDs and rule IDs, and still 32 times below 4 GiB.
//!
//! # Adapter obligations
//!
//! - Commit the record in the same atomic step as the Tick's Events (and, for
//!   an invalidation, the generation increment). A stale, conflicting,
//!   failed, or unknown-outcome commit records nothing.
//! - Reject a record that is not provisional, or whose Tick is not the
//!   invalidation's first Tick, with `BindingMismatch`, and a record that
//!   would exceed the recorded-set bounds with `FieldOutOfBounds`; both
//!   commit nothing.
//! - Reject a node whose artifact digest is already recorded in the same
//!   recorded set. A record checks digest uniqueness only within itself, but
//!   `pos-time` requires it across the whole graph, and only the adapter
//!   sees the set.
//! - Also reject a node whose position key `(tick, scheduler_position,
//!   owner_id, output_ordinal)` is already recorded in the same recorded
//!   set, alongside and not instead of digest uniqueness. A root rides a
//!   record at or after its own Tick, so two records of one set can carry
//!   roots at one position key with different digests; each record is valid
//!   alone, and without this check the collision would only surface at read
//!   time as `DuplicateIdentity`. Order rows by position key globally across
//!   the records of the set, never by insertion order.
//! - Persist each record's Tick. It is not recoverable from the node Ticks
//!   (a record made only of early roots carries them all before its Tick),
//!   and a later record's Tick must be compared with it, not with the
//!   maximum node Tick. The record Tick must be STRICTLY GREATER than the
//!   maximum persisted record Tick of the same recorded set; gaps are
//!   allowed, and a violation is `BindingMismatch`. The dependency set of a
//!   Fork generation is built only through the `_with_dependencies` methods,
//!   starting at the invalidation's `first_tick` (the coordinator seam #552
//!   must always use them). While the set has no records yet, compare the
//!   record Tick with the generation's persisted first Tick (known from the
//!   invalidation) and reject a record Tick below it with `BindingMismatch`.
//! - The record Tick is STAGER-ASSERTED. Nothing in the store can verify that
//!   it is the Tick the drafts commit ([`CounterfactualBasisV1`] carries a
//!   Seq, not a Tick), so #552 owns the correspondence between the record
//!   Tick and its drafts. An adapter reads the parent cut and the first Tick
//!   from the Fork's persisted row; a write path for the parent prefix
//!   belongs to #554.
//! - Map [`CounterfactualDependencyErrorV1`] to the storage error with
//!   `CounterfactualStoreErrorV1::from`: `InvalidEncoding` for encoding and
//!   unknown-enum faults, `FieldOutOfBounds` for bounds, page-limit, and
//!   missing-provenance faults, `BindingMismatch` for binding, consumer,
//!   input, and cursor faults, and the namesake for the version, order, and
//!   duplicate faults. A row that fails re-validation when it is
//!   READ BACK from storage is corrupt state, not a caller fault: use
//!   [`CounterfactualDependencyErrorV1::READ_BACK_FAULT`] (`CorruptState`).
//! - For a Fork, reject a record whose provisional Ticks are not strictly
//!   after the parent cut; nothing in this contract knows the cut, and a
//!   provisional node at or before it would overlap the committed prefix it
//!   is stitched to.
//! - Serve a Fork-generation read through the Fork's erasure read fence and
//!   a parent-prefix read through the parent Timeline's own erasure read
//!   fence, including its inherited scopes when the parent is itself a Fork,
//!   exactly as every other Timeline read. A parent-prefix read names no
//!   Fork, so the Fork's fence does not apply to it. Both fail closed
//!   without a bound erasure gate. Serve the committed state as it stands;
//!   that a generation is settled is the reader's obligation (see the
//!   root-node rule). Order rows by the canonical coordinate and edge order,
//!   and build pages with [`DependencyPageV1::try_new`], which also checks
//!   that nodes and parent-prefix edges belong to the request scope (a Fork
//!   scope cannot tell its edges apart and accepts them all), or
//!   [`DependencyPageV1::from_ordered`], which trusts its rows. Its only
//!   failure is a request cursor of the other row kind, a CALLER fault:
//!   map it with `CounterfactualStoreErrorV1::from` (`BindingMismatch`), and
//!   reserve `CorruptState` for STORED rows that fail `try_new` or scope
//!   re-validation.
//! - Recover an `OutcomeUnknown` write exactly as the storage port does; the
//!   record is part of the same transaction, so the receipt or basis read
//!   that settles the Tick settles the record.
//!
//! # Deferred
//!
//! - #550 through #553: the Memory and `SQLite` adapters of these traits, the
//!   coordinator wiring, and the frontier source that reads them.
//! - #554: the factual-Tick producer that records `Committed` parent-prefix
//!   rows, which will add its own parallel write method.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::counterfactual_store::{read_hash, skip_item};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, CborReadError, CounterfactualBasisV1,
    CounterfactualInvalidationCommandV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1,
    ForkGenerationV1, Hash, PipelineDraftBatchV1, StoredCounterfactualArtifactV1, TimelineId,
};

/// Maximum number of nodes one graph records per set.
pub const MAX_RECORDED_DEPENDENCY_NODES_V1: usize = 1_000_000;
/// Maximum number of edges one graph records per set.
pub const MAX_RECORDED_DEPENDENCY_EDGES_V1: usize = 4_000_000;
/// Maximum number of nodes in one Tick record.
pub const MAX_TICK_DEPENDENCY_NODES_V1: usize = 65_536;
/// Maximum number of edges in one Tick record.
pub const MAX_TICK_DEPENDENCY_EDGES_V1: usize = 262_144;
/// Maximum number of declared input digests of one node.
pub const MAX_DEPENDENCY_NODE_INPUTS_V1: usize = 4_096;
/// Maximum encoded size of one `IDP1` edge.
pub const MAX_DEPENDENCY_EDGE_BYTES_V1: usize = 16 * 1024;
/// Maximum total encoded size of the edges of one Tick record, 128 MiB.
pub const MAX_TICK_DEPENDENCY_EDGE_BYTES_V1: usize = 128 * 1024 * 1024;
/// Maximum UTF-8 byte length of a node owner ID.
pub const MAX_DEPENDENCY_OWNER_ID_BYTES_V1: usize = 128;
/// Maximum number of rows in one page.
pub const MAX_DEPENDENCY_PAGE_ROWS_V1: usize = 1_024;

const EDGE_ARRAY_HEAD: u8 = 0x89;
const EDGE_PREFIX: [u8; 6] = [0x64, b'I', b'D', b'P', b'1', 0x01];
const EDGE_DIGEST_DOMAIN: &[u8] = b"PiglorOS.InputDependency.v1";
const NODE_ARRAY_HEAD: u8 = 0x86;
/// The CBOR major type of a node owner ID.
const OWNER_TEXT_MAJOR: u8 = 3;
/// Edge fields after the source: class, range, authorization, rule, provenance.
const EDGE_TAIL_FIELDS: usize = 5;
/// The range and rule arrays hold only scalars.
const EDGE_TAIL_ARRAY_DEPTH: u8 = 1;

/// Closed failures of the dependency record contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CounterfactualDependencyErrorV1 {
    /// `IDP1` bytes are malformed, truncated, or have trailing bytes.
    #[error("dependency edge encoding is invalid")]
    InvalidEncoding,
    /// The `IDP1` magic or schema version is not supported.
    #[error("dependency edge version is unsupported")]
    UnsupportedVersion,
    /// A field, count, or size exceeds its bound.
    #[error("dependency field is out of bounds")]
    FieldOutOfBounds,
    /// A class or origin code is outside its closed set.
    #[error("dependency enum code is unknown")]
    UnknownEnum,
    /// Nodes, inputs, edges, or page rows are not strictly ascending.
    #[error("dependency rows are not canonical")]
    NonCanonicalOrder,
    /// Two nodes, inputs, edges, or page rows share one identity.
    #[error("dependency rows repeat an identity")]
    DuplicateIdentity,
    /// A node has no provenance digest.
    #[error("dependency node provenance is missing")]
    ProvenanceMissing,
    /// Supplied fields disagree with the bytes or the record they bind.
    #[error("dependency bindings disagree")]
    BindingMismatch,
    /// An edge consumer is not a node of the same record.
    #[error("dependency edge consumer is not in the record")]
    UnknownConsumer,
    /// An edge source is not a declared input of its consumer.
    #[error("dependency edge input is not declared")]
    UndeclaredInput,
    /// A page cursor is malformed, of the wrong kind, or out of scope.
    #[error("dependency page cursor is invalid")]
    InvalidCursor,
    /// A page limit is zero or above the page maximum.
    #[error("dependency page limit is invalid")]
    InvalidPageLimit,
}

impl CounterfactualDependencyErrorV1 {
    /// The storage error for a row that fails re-validation on read-back.
    ///
    /// Persisted state is corrupt then, and the caller is not at fault.
    pub const READ_BACK_FAULT: CounterfactualStoreErrorV1 =
        CounterfactualStoreErrorV1::CorruptState;
}

/// Map a dependency fault to the nearest storage error.
///
/// See the module's adapter obligations. Use
/// [`CounterfactualDependencyErrorV1::READ_BACK_FAULT`] for read-back faults.
impl From<CounterfactualDependencyErrorV1> for CounterfactualStoreErrorV1 {
    fn from(error: CounterfactualDependencyErrorV1) -> Self {
        match error {
            CounterfactualDependencyErrorV1::InvalidEncoding
            | CounterfactualDependencyErrorV1::UnknownEnum => Self::InvalidEncoding,
            CounterfactualDependencyErrorV1::UnsupportedVersion => Self::UnsupportedVersion,
            CounterfactualDependencyErrorV1::FieldOutOfBounds
            | CounterfactualDependencyErrorV1::ProvenanceMissing
            | CounterfactualDependencyErrorV1::InvalidPageLimit => Self::FieldOutOfBounds,
            CounterfactualDependencyErrorV1::NonCanonicalOrder => Self::NonCanonicalOrder,
            CounterfactualDependencyErrorV1::DuplicateIdentity => Self::DuplicateIdentity,
            CounterfactualDependencyErrorV1::BindingMismatch
            | CounterfactualDependencyErrorV1::UnknownConsumer
            | CounterfactualDependencyErrorV1::UndeclaredInput
            | CounterfactualDependencyErrorV1::InvalidCursor => Self::BindingMismatch,
        }
    }
}

type DependencyResult<T> = Result<T, CounterfactualDependencyErrorV1>;

/// Closed dependency class of a node, with the `IDP1` wire codes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecordedDependencyClassV1 {
    /// Frozen exogenous input, code 0.
    ExogenousFrozen = 0,
    /// Intervention-assigned value, code 1.
    InterventionAssigned = 1,
    /// Endogenous recomputed state, code 2.
    EndogenousRecomputed = 2,
    /// Fixed-policy value, code 3.
    FixedPolicy = 3,
    /// Presentation-only output, code 4.
    PresentationOnly = 4,
}

impl RecordedDependencyClassV1 {
    /// Every class, indexed by its wire code.
    pub const ALL: [Self; 5] = [
        Self::ExogenousFrozen,
        Self::InterventionAssigned,
        Self::EndogenousRecomputed,
        Self::FixedPolicy,
        Self::PresentationOnly,
    ];

    /// Return the stable wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Whether nodes of this class are roots of the recomputation: frozen
    /// exogenous, intervention-assigned, and fixed-policy values.
    ///
    /// A root node may be recorded with a Tick record after its own Tick.
    #[must_use]
    pub const fn is_root(self) -> bool {
        matches!(
            self,
            Self::ExogenousFrozen | Self::InterventionAssigned | Self::FixedPolicy
        )
    }

    /// Return the class carrying `code`.
    ///
    /// # Errors
    /// Returns `UnknownEnum` for a code outside the closed set.
    pub const fn from_code(code: u64) -> DependencyResult<Self> {
        match code {
            0 => Ok(Self::ExogenousFrozen),
            1 => Ok(Self::InterventionAssigned),
            2 => Ok(Self::EndogenousRecomputed),
            3 => Ok(Self::FixedPolicy),
            4 => Ok(Self::PresentationOnly),
            _ => Err(CounterfactualDependencyErrorV1::UnknownEnum),
        }
    }
}

/// Where a node's output was committed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecordedNodeOriginV1 {
    /// Inherited parent prefix, recorded once per parent Timeline, code 0.
    Committed = 0,
    /// Provisional Fork generation, code 1.
    Provisional = 1,
}

impl RecordedNodeOriginV1 {
    /// Return the stable code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the origin carrying `code`.
    ///
    /// # Errors
    /// Returns `UnknownEnum` for a code outside the closed set.
    pub const fn from_code(code: u64) -> DependencyResult<Self> {
        match code {
            0 => Ok(Self::Committed),
            1 => Ok(Self::Provisional),
            _ => Err(CounterfactualDependencyErrorV1::UnknownEnum),
        }
    }
}

/// Return the first adjacent pair that is not strictly ascending.
fn check_order<T>(items: &[T], compare: impl Fn(&T, &T) -> Ordering) -> DependencyResult<()> {
    items
        .windows(2)
        .try_for_each(|pair| match compare(&pair[0], &pair[1]) {
            Ordering::Less => Ok(()),
            Ordering::Equal => Err(CounterfactualDependencyErrorV1::DuplicateIdentity),
            Ordering::Greater => Err(CounterfactualDependencyErrorV1::NonCanonicalOrder),
        })
}

fn valid_owner(owner_id: &str) -> bool {
    (1..=MAX_DEPENDENCY_OWNER_ID_BYTES_V1).contains(&owner_id.len())
}

/// One node coordinate `[tick, scheduler_position, owner_id, output_ordinal,
/// schema_id, artifact_digest]`.
///
/// The derived order compares the fields in that order, with the owner as
/// UTF-8 bytes. It is the ADR-064 node order of `pos-time`, which orders
/// nodes by [`Self::position_key`] and so never needs the schema or digest to
/// break a tie.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DependencyNodeCoordinateV1 {
    tick: u64,
    scheduler_position: u32,
    owner_id: String,
    output_ordinal: u32,
    schema_id: u32,
    artifact_digest: Hash,
}

impl DependencyNodeCoordinateV1 {
    /// Validate and build one coordinate.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` unless the owner is 1 to
    /// [`MAX_DEPENDENCY_OWNER_ID_BYTES_V1`] bytes, the schema ID is nonzero,
    /// and the artifact digest is nonzero.
    pub fn try_new(
        tick: u64,
        scheduler_position: u32,
        owner_id: String,
        output_ordinal: u32,
        schema_id: u32,
        artifact_digest: Hash,
    ) -> DependencyResult<Self> {
        if valid_owner(&owner_id) && schema_id != 0 && artifact_digest != Hash::zero() {
            Ok(Self {
                tick,
                scheduler_position,
                owner_id,
                output_ordinal,
                schema_id,
                artifact_digest,
            })
        } else {
            Err(CounterfactualDependencyErrorV1::FieldOutOfBounds)
        }
    }

    /// Return the Tick.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Return the scheduler position.
    #[must_use]
    pub const fn scheduler_position(&self) -> u32 {
        self.scheduler_position
    }

    /// Borrow the owner ID.
    #[must_use]
    pub const fn owner_id(&self) -> &str {
        self.owner_id.as_str()
    }

    /// Return the output ordinal.
    #[must_use]
    pub const fn output_ordinal(&self) -> u32 {
        self.output_ordinal
    }

    /// Return the schema ID.
    #[must_use]
    pub const fn schema_id(&self) -> u32 {
        self.schema_id
    }

    /// Return the artifact digest that identifies the node.
    #[must_use]
    pub const fn artifact_digest(&self) -> Hash {
        self.artifact_digest
    }

    /// Return `(tick, scheduler_position, owner_id, output_ordinal)`, the key
    /// that strictly orders the nodes of a record.
    #[must_use]
    pub const fn position_key(&self) -> (u64, u32, &str, u32) {
        (
            self.tick,
            self.scheduler_position,
            self.owner_id.as_str(),
            self.output_ordinal,
        )
    }

    /// Encode the coordinate as the six-field `IDP1` node array.
    fn encoded(&self) -> Vec<u8> {
        let mut out = vec![NODE_ARRAY_HEAD];
        encode_head(&mut out, 0, self.tick);
        encode_head(&mut out, 0, u64::from(self.scheduler_position));
        encode_bytes(&mut out, self.owner_id.as_bytes(), OWNER_TEXT_MAJOR);
        encode_head(&mut out, 0, u64::from(self.output_ordinal));
        encode_head(&mut out, 0, u64::from(self.schema_id));
        encode_hash(&mut out, self.artifact_digest);
        out
    }
}

/// One declared node of a Tick record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyNodeRecordV1 {
    coordinate: DependencyNodeCoordinateV1,
    class: RecordedDependencyClassV1,
    origin: RecordedNodeOriginV1,
    input_digests: Vec<Hash>,
    provenance_digest: Hash,
}

impl DependencyNodeRecordV1 {
    /// Validate and build one node record.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for more than
    /// [`MAX_DEPENDENCY_NODE_INPUTS_V1`] inputs or a zero input digest,
    /// `ProvenanceMissing` for a zero provenance digest, and
    /// `NonCanonicalOrder` or `DuplicateIdentity` unless the input digests
    /// are strictly ascending.
    pub fn try_new(
        coordinate: DependencyNodeCoordinateV1,
        class: RecordedDependencyClassV1,
        origin: RecordedNodeOriginV1,
        input_digests: Vec<Hash>,
        provenance_digest: Hash,
    ) -> DependencyResult<Self> {
        if input_digests.len() > MAX_DEPENDENCY_NODE_INPUTS_V1
            || input_digests.contains(&Hash::zero())
        {
            Err(CounterfactualDependencyErrorV1::FieldOutOfBounds)
        } else if provenance_digest == Hash::zero() {
            Err(CounterfactualDependencyErrorV1::ProvenanceMissing)
        } else {
            check_order(&input_digests, Ord::cmp).map(|()| Self {
                coordinate,
                class,
                origin,
                input_digests,
                provenance_digest,
            })
        }
    }

    /// Borrow the node coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> &DependencyNodeCoordinateV1 {
        &self.coordinate
    }

    /// Return the dependency class.
    #[must_use]
    pub const fn class(&self) -> RecordedDependencyClassV1 {
        self.class
    }

    /// Return the node origin.
    #[must_use]
    pub const fn origin(&self) -> RecordedNodeOriginV1 {
        self.origin
    }

    /// Borrow the strictly ascending declared input digests.
    #[must_use]
    pub fn input_digests(&self) -> &[Hash] {
        &self.input_digests
    }

    /// Return the provenance digest.
    #[must_use]
    pub const fn provenance_digest(&self) -> Hash {
        self.provenance_digest
    }
}

/// Exact canonical `IDP1` edge bytes bound to their consumer and source.
///
/// [`Self::try_from_canonical`] verifies the framing and the two extracted
/// fields; the module documentation lists what the conformance codec still
/// verifies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyEdgeRecordV1 {
    bytes: Vec<u8>,
    consumer: DependencyNodeCoordinateV1,
    source_digest: Hash,
    digest: Hash,
}

impl DependencyEdgeRecordV1 {
    /// Verify exact `IDP1` bytes against the supplied consumer and source.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` above [`MAX_DEPENDENCY_EDGE_BYTES_V1`] or
    /// for a zero `source_digest` (checked first), and for a source node
    /// whose owner text is empty or above
    /// [`MAX_DEPENDENCY_OWNER_ID_BYTES_V1`] bytes; `InvalidEncoding` for a
    /// wrong array head, a malformed source node or tail, or trailing bytes;
    /// `UnsupportedVersion` for another magic or version; and
    /// `BindingMismatch` unless the bytes carry exactly `consumer` as the
    /// consumer node and `source_digest` as the source artifact digest.
    pub fn try_from_canonical(
        bytes: Vec<u8>,
        consumer: DependencyNodeCoordinateV1,
        source_digest: Hash,
    ) -> DependencyResult<Self> {
        if bytes.len() > MAX_DEPENDENCY_EDGE_BYTES_V1 || source_digest == Hash::zero() {
            return Err(CounterfactualDependencyErrorV1::FieldOutOfBounds);
        }
        let expected_consumer = consumer.encoded();
        let verified = bytes
            .strip_prefix(&[EDGE_ARRAY_HEAD])
            .ok_or(CounterfactualDependencyErrorV1::InvalidEncoding)
            .and_then(|fields| {
                fields
                    .strip_prefix(&EDGE_PREFIX)
                    .ok_or(CounterfactualDependencyErrorV1::UnsupportedVersion)
            })
            .and_then(|fields| {
                fields
                    .strip_prefix(expected_consumer.as_slice())
                    .ok_or(CounterfactualDependencyErrorV1::BindingMismatch)
            })
            .and_then(source_artifact_digest)
            .and_then(|extracted| {
                if extracted == source_digest {
                    Ok(())
                } else {
                    Err(CounterfactualDependencyErrorV1::BindingMismatch)
                }
            });
        verified.map(|()| Self {
            digest: edge_digest(&bytes),
            bytes,
            consumer,
            source_digest,
        })
    }

    /// Borrow the exact canonical `IDP1` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the verified consumer coordinate.
    #[must_use]
    pub const fn consumer(&self) -> &DependencyNodeCoordinateV1 {
        &self.consumer
    }

    /// Return the verified source artifact digest.
    #[must_use]
    pub const fn source_digest(&self) -> Hash {
        self.source_digest
    }

    /// Return the domain-separated digest of the `IDP1` bytes.
    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    /// Compare by the `IDP1` edge-list key: the consumer's position key and
    /// then the source digest.
    #[must_use]
    pub fn order_cmp(&self, other: &Self) -> Ordering {
        (self.consumer.position_key(), self.source_digest)
            .cmp(&(other.consumer.position_key(), other.source_digest))
    }
}

type CursorResult<T> = Result<T, CborReadError>;

/// Report a structural read failure as `InvalidEncoding`.
fn malformed<T>(read: CursorResult<T>) -> DependencyResult<T> {
    read.or(Err(CounterfactualDependencyErrorV1::InvalidEncoding))
}

/// Skip the source node's array head, tick, and scheduler position.
fn skip_source_head(cursor: &mut CborCursor<'_>) -> CursorResult<()> {
    cursor
        .fixed(&[NODE_ARRAY_HEAD])
        .and_then(|()| (0..2).try_for_each(|_| skip_item(cursor, 1)))
}

/// Skip the source node's ordinal and schema, then read its artifact digest.
fn read_source_digest(cursor: &mut CborCursor<'_>) -> CursorResult<Hash> {
    (0..2)
        .try_for_each(|_| skip_item(cursor, 1))
        .and_then(|()| read_hash(cursor))
}

/// Check that a source owner text length is 1 to the owner bound.
fn owner_text_length(length: u64) -> DependencyResult<usize> {
    usize::try_from(length)
        .ok()
        .filter(|bytes| (1..=MAX_DEPENDENCY_OWNER_ID_BYTES_V1).contains(bytes))
        .ok_or(CounterfactualDependencyErrorV1::FieldOutOfBounds)
}

/// Read the source node's artifact digest and check the edge tail.
fn source_artifact_digest(rest: &[u8]) -> DependencyResult<Hash> {
    let mut cursor = CborCursor::new(rest);
    malformed(skip_source_head(&mut cursor))
        .and_then(|()| malformed(cursor.head(OWNER_TEXT_MAJOR)))
        .and_then(owner_text_length)
        .and_then(|length| malformed(cursor.take(length)))
        .and_then(|_| malformed(read_source_digest(&mut cursor)))
        .and_then(|digest| {
            let tail = (0..EDGE_TAIL_FIELDS)
                .try_for_each(|_| skip_item(&mut cursor, EDGE_TAIL_ARRAY_DEPTH));
            malformed(tail).map(|()| digest)
        })
        .and_then(|digest| {
            if cursor.is_finished() {
                Ok(digest)
            } else {
                Err(CounterfactualDependencyErrorV1::InvalidEncoding)
            }
        })
}

fn edge_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EDGE_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// The row counts already recorded in one recorded set: a parent Timeline's
/// committed prefix or one Fork generation.
///
/// Named fields keep the three counts from being transposed at the call to
/// [`TickDependencyRecordV1::ensure_set_capacity`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordedSetCountsV1 {
    /// Nodes already recorded in the set.
    pub nodes: usize,
    /// Edges already recorded in the set.
    pub edges: usize,
    /// Declared-input digests, in total, of the nodes already recorded.
    pub inputs: usize,
}

/// The nodes and edges of one Tick, committed with that Tick's Events.
///
/// Nodes are strictly ascending by [`DependencyNodeCoordinateV1::position_key`]
/// with unique artifact digests; edges are in canonical `IDP1` order
/// ([`DependencyEdgeRecordV1::order_cmp`]) with no repeated key; every edge
/// consumer is a node of this record and every edge source is a declared
/// input of its consumer. All nodes share the record's origin; root-class
/// nodes carry a Tick at or before the record's Tick and every other node
/// carries exactly the record's Tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TickDependencyRecordV1 {
    tick: u64,
    origin: RecordedNodeOriginV1,
    nodes: Vec<DependencyNodeRecordV1>,
    edges: Vec<DependencyEdgeRecordV1>,
}

impl TickDependencyRecordV1 {
    /// Validate the structural contract and build one Tick record.
    ///
    /// # Errors
    /// Returns, in check order: `FieldOutOfBounds` above
    /// [`MAX_TICK_DEPENDENCY_NODES_V1`] nodes, [`MAX_TICK_DEPENDENCY_EDGES_V1`]
    /// edges or declared inputs, or [`MAX_TICK_DEPENDENCY_EDGE_BYTES_V1`]
    /// encoded edge bytes; `BindingMismatch` for a node of another origin, a
    /// root-class node after `tick`, or any other node not at `tick`;
    /// `NonCanonicalOrder` or `DuplicateIdentity`
    /// for unordered or repeated nodes, repeated node digests, or unordered
    /// or repeated edges; `UnknownConsumer` for an edge whose consumer is not
    /// a node of the record; and `UndeclaredInput` for an edge whose source
    /// its consumer did not declare.
    pub fn try_new(
        tick: u64,
        origin: RecordedNodeOriginV1,
        nodes: Vec<DependencyNodeRecordV1>,
        edges: Vec<DependencyEdgeRecordV1>,
    ) -> DependencyResult<Self> {
        if !within_record_bounds(&nodes, &edges) {
            return Err(CounterfactualDependencyErrorV1::FieldOutOfBounds);
        }
        check_nodes(tick, origin, &nodes)
            .and_then(|()| check_edges(&nodes, &edges))
            .map(|()| Self {
                tick,
                origin,
                nodes,
                edges,
            })
    }

    /// Return the Tick the record is committed at; root-class nodes may carry
    /// an earlier Tick.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Return the origin of every node.
    #[must_use]
    pub const fn origin(&self) -> RecordedNodeOriginV1 {
        self.origin
    }

    /// Borrow the nodes in canonical order.
    #[must_use]
    pub fn nodes(&self) -> &[DependencyNodeRecordV1] {
        &self.nodes
    }

    /// Borrow the edges in canonical order.
    #[must_use]
    pub fn edges(&self) -> &[DependencyEdgeRecordV1] {
        &self.edges
    }

    /// Return the total number of input digests the nodes declare.
    #[must_use]
    pub fn declared_input_count(&self) -> usize {
        declared_inputs(&self.nodes)
    }

    /// Return how many declared inputs have no edge in this record.
    ///
    /// Every edge is declared by its consumer and a consumer's edges have
    /// distinct sources, so this is the declared inputs minus the edges.
    #[must_use]
    pub fn uncovered_input_count(&self) -> usize {
        self.declared_input_count().saturating_sub(self.edges.len())
    }

    /// Check that recording this record keeps one recorded set within the
    /// graph bounds, given the rows already recorded in that set.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` when the set would exceed
    /// [`MAX_RECORDED_DEPENDENCY_NODES_V1`] nodes,
    /// [`MAX_RECORDED_DEPENDENCY_EDGES_V1`] edges, or
    /// [`MAX_RECORDED_DEPENDENCY_EDGES_V1`] declared inputs.
    pub fn ensure_set_capacity(&self, recorded: RecordedSetCountsV1) -> DependencyResult<()> {
        if recorded.nodes.saturating_add(self.nodes.len()) > MAX_RECORDED_DEPENDENCY_NODES_V1
            || recorded.edges.saturating_add(self.edges.len()) > MAX_RECORDED_DEPENDENCY_EDGES_V1
            || recorded.inputs.saturating_add(self.declared_input_count())
                > MAX_RECORDED_DEPENDENCY_EDGES_V1
        {
            Err(CounterfactualDependencyErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    /// Check that this record may be written to a Fork generation.
    ///
    /// # Errors
    /// Returns `BindingMismatch` unless every node is provisional.
    pub fn ensure_provisional(&self) -> Result<(), CounterfactualStoreErrorV1> {
        if self.origin == RecordedNodeOriginV1::Provisional {
            Ok(())
        } else {
            Err(CounterfactualStoreErrorV1::BindingMismatch)
        }
    }
}

fn declared_inputs(nodes: &[DependencyNodeRecordV1]) -> usize {
    nodes.iter().map(|node| node.input_digests.len()).sum()
}

fn edge_bytes(edges: &[DependencyEdgeRecordV1]) -> usize {
    edges
        .iter()
        .fold(0, |total, edge| total.saturating_add(edge.bytes.len()))
}

/// The count, declared-input, and aggregate edge-byte bounds of one record.
fn within_record_bounds(
    nodes: &[DependencyNodeRecordV1],
    edges: &[DependencyEdgeRecordV1],
) -> bool {
    nodes.len() <= MAX_TICK_DEPENDENCY_NODES_V1
        && edges.len() <= MAX_TICK_DEPENDENCY_EDGES_V1
        && declared_inputs(nodes) <= MAX_TICK_DEPENDENCY_EDGES_V1
        && edge_bytes(edges) <= MAX_TICK_DEPENDENCY_EDGE_BYTES_V1
}

/// Whether a node's Tick fits a record at `tick`: a root-class node may
/// precede it, every other node must equal it.
const fn tick_fits(node: &DependencyNodeRecordV1, tick: u64) -> bool {
    if node.class.is_root() {
        node.coordinate.tick <= tick
    } else {
        node.coordinate.tick == tick
    }
}

fn check_nodes(
    tick: u64,
    origin: RecordedNodeOriginV1,
    nodes: &[DependencyNodeRecordV1],
) -> DependencyResult<()> {
    if nodes
        .iter()
        .any(|node| node.origin != origin || !tick_fits(node, tick))
    {
        return Err(CounterfactualDependencyErrorV1::BindingMismatch);
    }
    check_order(nodes, |left, right| {
        left.coordinate
            .position_key()
            .cmp(&right.coordinate.position_key())
    })
    .and_then(|()| {
        let mut seen = BTreeSet::new();
        nodes.iter().try_for_each(|node| {
            if seen.insert(node.coordinate.artifact_digest) {
                Ok(())
            } else {
                Err(CounterfactualDependencyErrorV1::DuplicateIdentity)
            }
        })
    })
}

fn check_edges(
    nodes: &[DependencyNodeRecordV1],
    edges: &[DependencyEdgeRecordV1],
) -> DependencyResult<()> {
    let check = |edge: &DependencyEdgeRecordV1| check_edge(nodes, edge);
    check_order(edges, DependencyEdgeRecordV1::order_cmp)
        .and_then(|()| edges.iter().try_for_each(check))
}

fn check_edge(
    nodes: &[DependencyNodeRecordV1],
    edge: &DependencyEdgeRecordV1,
) -> DependencyResult<()> {
    nodes
        .binary_search_by(|node| {
            node.coordinate
                .position_key()
                .cmp(&edge.consumer.position_key())
        })
        .ok()
        .map(|index| &nodes[index])
        .filter(|node| node.coordinate == edge.consumer)
        .ok_or(CounterfactualDependencyErrorV1::UnknownConsumer)
        .and_then(|node| {
            node.input_digests
                .binary_search(&edge.source_digest)
                .map(drop)
                .or(Err(CounterfactualDependencyErrorV1::UndeclaredInput))
        })
}

/// A page position: the key of the last row a page returned.
///
/// A node cursor is the node's position key; an edge cursor adds the source
/// digest. The derived order is the canonical row order of both kinds.
///
/// The four position fields repeat those of [`DependencyNodeCoordinateV1`] on
/// purpose. A cursor is only a position key: it has no schema ID or artifact
/// digest, and an edge cursor carries an optional source digest instead. It
/// stays a separate type so a cursor cannot be mistaken for a node identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DependencyPageCursorV1 {
    tick: u64,
    scheduler_position: u32,
    owner_id: String,
    output_ordinal: u32,
    source_digest: Option<Hash>,
}

impl DependencyPageCursorV1 {
    /// Validate and build one cursor; `source_digest` is `Some` for an edge
    /// cursor and `None` for a node cursor.
    ///
    /// # Errors
    /// Returns `InvalidCursor` unless the owner is 1 to
    /// [`MAX_DEPENDENCY_OWNER_ID_BYTES_V1`] bytes and a source digest is
    /// nonzero.
    pub fn try_new(
        tick: u64,
        scheduler_position: u32,
        owner_id: String,
        output_ordinal: u32,
        source_digest: Option<Hash>,
    ) -> DependencyResult<Self> {
        if valid_owner(&owner_id) && source_digest != Some(Hash::zero()) {
            Ok(Self {
                tick,
                scheduler_position,
                owner_id,
                output_ordinal,
                source_digest,
            })
        } else {
            Err(CounterfactualDependencyErrorV1::InvalidCursor)
        }
    }

    /// Return the Tick.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Return the scheduler position.
    #[must_use]
    pub const fn scheduler_position(&self) -> u32 {
        self.scheduler_position
    }

    /// Borrow the owner ID.
    #[must_use]
    pub const fn owner_id(&self) -> &str {
        self.owner_id.as_str()
    }

    /// Return the output ordinal.
    #[must_use]
    pub const fn output_ordinal(&self) -> u32 {
        self.output_ordinal
    }

    /// Return the edge source digest, or `None` for a node cursor.
    #[must_use]
    pub const fn source_digest(&self) -> Option<Hash> {
        self.source_digest
    }

    fn at(coordinate: &DependencyNodeCoordinateV1, source_digest: Option<Hash>) -> Self {
        Self {
            tick: coordinate.tick,
            scheduler_position: coordinate.scheduler_position,
            owner_id: coordinate.owner_id.clone(),
            output_ordinal: coordinate.output_ordinal,
            source_digest,
        }
    }
}

/// One row kind a read port pages: a node or an edge.
pub trait DependencyPagedRowV1 {
    /// Whether this row's cursor carries an edge source digest.
    const KEYED_BY_SOURCE: bool;

    /// Whether this row belongs to `scope`.
    ///
    /// A node carries its origin, so a parent-prefix scope holds committed
    /// nodes through its Tick and a Fork scope holds provisional nodes. An
    /// edge carries no origin: a parent-prefix scope holds edges whose
    /// consumer Tick is within it, and a Fork scope cannot tell its edges
    /// from any other, so it accepts every edge.
    #[must_use]
    fn in_scope(&self, scope: DependencyReadScopeV1) -> bool;

    /// Return the cursor that resumes after this row.
    #[must_use]
    fn cursor(&self) -> DependencyPageCursorV1;
}

impl DependencyPagedRowV1 for DependencyNodeRecordV1 {
    const KEYED_BY_SOURCE: bool = false;

    fn in_scope(&self, scope: DependencyReadScopeV1) -> bool {
        let committed = self.origin == RecordedNodeOriginV1::Committed;
        let tick = self.coordinate.tick;
        scope
            .through_tick()
            .map_or(!committed, |through| committed && tick <= through)
    }

    fn cursor(&self) -> DependencyPageCursorV1 {
        DependencyPageCursorV1::at(&self.coordinate, None)
    }
}

impl DependencyPagedRowV1 for DependencyEdgeRecordV1 {
    const KEYED_BY_SOURCE: bool = true;

    fn in_scope(&self, scope: DependencyReadScopeV1) -> bool {
        scope
            .through_tick()
            .is_none_or(|through_tick| self.consumer.tick <= through_tick)
    }

    fn cursor(&self) -> DependencyPageCursorV1 {
        DependencyPageCursorV1::at(&self.consumer, Some(self.source_digest))
    }
}

/// Which recorded rows a read addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyReadScopeV1 {
    /// The committed prefix of a parent Timeline, through `through_tick`.
    ParentPrefix {
        /// Parent Timeline the prefix was recorded on.
        timeline: TimelineId,
        /// Last Tick, inclusive, the read may return.
        through_tick: u64,
    },
    /// The provisional rows of one exact Fork generation.
    ForkGeneration(ForkGenerationV1),
}

impl DependencyReadScopeV1 {
    /// Return the last Tick, inclusive, a parent-prefix scope may return, or
    /// `None` for a Fork scope, which no Tick bounds.
    #[must_use]
    pub const fn through_tick(self) -> Option<u64> {
        match self {
            Self::ParentPrefix { through_tick, .. } => Some(through_tick),
            Self::ForkGeneration(_) => None,
        }
    }

    /// Check the scope against the Fork's committed generation.
    ///
    /// A parent-prefix scope names no generation and always passes. A Fork
    /// scope routes through [`ForkGenerationV1::resolve_read`], so a read of
    /// any other generation, including a quarantined earlier one, is
    /// `MixedForkGeneration`.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration` unless a Fork scope names
    /// `current_generation`.
    pub fn ensure_current(self, current_generation: u64) -> Result<(), CounterfactualStoreErrorV1> {
        match self {
            Self::ParentPrefix { .. } => Ok(()),
            Self::ForkGeneration(at) => at
                .resolve_read(current_generation, StoredCounterfactualArtifactV1::Absent)
                .map(drop),
        }
    }
}

/// One validated page request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyPageRequestV1 {
    scope: DependencyReadScopeV1,
    after: Option<DependencyPageCursorV1>,
    limit: usize,
}

impl DependencyPageRequestV1 {
    /// Validate and build one request for at most `limit` rows after `after`.
    ///
    /// # Errors
    /// Returns `InvalidPageLimit` unless `limit` is 1 to
    /// [`MAX_DEPENDENCY_PAGE_ROWS_V1`], and `InvalidCursor` for a cursor
    /// beyond a parent prefix's `through_tick`.
    pub fn try_new(
        scope: DependencyReadScopeV1,
        after: Option<DependencyPageCursorV1>,
        limit: usize,
    ) -> DependencyResult<Self> {
        if !(1..=MAX_DEPENDENCY_PAGE_ROWS_V1).contains(&limit) {
            Err(CounterfactualDependencyErrorV1::InvalidPageLimit)
        } else if beyond_scope(scope, after.as_ref()) {
            Err(CounterfactualDependencyErrorV1::InvalidCursor)
        } else {
            Ok(Self {
                scope,
                after,
                limit,
            })
        }
    }

    /// Return the addressed scope.
    #[must_use]
    pub const fn scope(&self) -> DependencyReadScopeV1 {
        self.scope
    }

    /// Borrow the cursor the page must start after, if any.
    #[must_use]
    pub const fn after(&self) -> Option<&DependencyPageCursorV1> {
        self.after.as_ref()
    }

    /// Return the maximum number of rows in the page.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

fn beyond_scope(scope: DependencyReadScopeV1, after: Option<&DependencyPageCursorV1>) -> bool {
    after
        .zip(scope.through_tick())
        .is_some_and(|(cursor, through_tick)| cursor.tick > through_tick)
}

/// One page of rows and the cursor that continues after it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyPageV1<T> {
    items: Vec<T>,
    next: Option<DependencyPageCursorV1>,
}

impl<T: DependencyPagedRowV1> DependencyPageV1<T> {
    /// Validate one adapter-built page against its request.
    ///
    /// Nodes and parent-prefix edges must belong to the request scope
    /// ([`DependencyPagedRowV1::in_scope`]); edges carry no origin, so a Fork
    /// scope cannot reject an edge that another scope recorded.
    ///
    /// # Errors
    /// Returns `InvalidCursor` when the request cursor is of the other row
    /// kind, `FieldOutOfBounds` for more rows than the limit,
    /// `BindingMismatch` for a row outside the request scope,
    /// `NonCanonicalOrder` or `DuplicateIdentity` unless the rows are
    /// strictly ascending and after the request cursor, and `InvalidCursor`
    /// unless `next` is `None` or the cursor of the last row of a full page.
    pub fn try_new(
        request: &DependencyPageRequestV1,
        items: Vec<T>,
        next: Option<DependencyPageCursorV1>,
    ) -> DependencyResult<Self> {
        check_cursor_kind::<T>(request)
            .and_then(|()| check_items(request, &items))
            .and_then(|()| {
                let cursors: Vec<DependencyPageCursorV1> = request
                    .after
                    .iter()
                    .cloned()
                    .chain(items.iter().map(T::cursor))
                    .collect();
                check_order(&cursors, Ord::cmp)
            })
            .and_then(|()| {
                if continuation_valid(request, &items, next.as_ref()) {
                    Ok(Self { items, next })
                } else {
                    Err(CounterfactualDependencyErrorV1::InvalidCursor)
                }
            })
    }

    /// Build the page of `rows`, which must be in canonical order, after the
    /// request cursor, with a continuation when more rows remain.
    ///
    /// The rows are trusted: they must already belong to the request scope.
    ///
    /// # Errors
    /// Returns `InvalidCursor` when the request cursor is of the other row
    /// kind.
    pub fn from_ordered(request: &DependencyPageRequestV1, rows: &[T]) -> DependencyResult<Self>
    where
        T: Clone,
    {
        check_cursor_kind::<T>(request).map(|()| {
            let start = request.after.as_ref().map_or(0, |after| {
                rows.partition_point(|row| row.cursor() <= *after)
            });
            let remaining = &rows[start..];
            let items: Vec<T> = remaining.iter().take(request.limit).cloned().collect();
            let next = items
                .last()
                .filter(|_| remaining.len() > request.limit)
                .map(T::cursor);
            Self { items, next }
        })
    }

    /// Borrow the rows.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Borrow the cursor of the next page, or `None` after the last page.
    #[must_use]
    pub const fn next(&self) -> Option<&DependencyPageCursorV1> {
        self.next.as_ref()
    }
}

fn check_items<T: DependencyPagedRowV1>(
    request: &DependencyPageRequestV1,
    items: &[T],
) -> DependencyResult<()> {
    if items.len() > request.limit {
        Err(CounterfactualDependencyErrorV1::FieldOutOfBounds)
    } else if items.iter().all(|row| row.in_scope(request.scope)) {
        Ok(())
    } else {
        Err(CounterfactualDependencyErrorV1::BindingMismatch)
    }
}

fn check_cursor_kind<T: DependencyPagedRowV1>(
    request: &DependencyPageRequestV1,
) -> DependencyResult<()> {
    if request
        .after
        .as_ref()
        .is_none_or(|cursor| cursor.source_digest.is_some() == T::KEYED_BY_SOURCE)
    {
        Ok(())
    } else {
        Err(CounterfactualDependencyErrorV1::InvalidCursor)
    }
}

fn continuation_valid<T: DependencyPagedRowV1>(
    request: &DependencyPageRequestV1,
    items: &[T],
    next: Option<&DependencyPageCursorV1>,
) -> bool {
    next.is_none_or(|cursor| {
        let last = items.last().map(T::cursor);
        items.len() == request.limit && last.as_ref() == Some(cursor)
    })
}

/// Write side of the dependency record: parallel methods that commit a
/// [`TickDependencyRecordV1`] with the Tick's Events.
///
/// Every method commits its record in the same atomic step as the Tick's
/// Events and generation increment; a stale, conflicting, failed, or
/// unknown-outcome commit records nothing. See the module's adapter
/// obligations. Only the core coordinator may hold this capability.
pub trait CounterfactualDependencyRecordingPortV1: CounterfactualStorePortV1 {
    /// Atomically commit the whole invalidation command and its first Tick's
    /// dependency record.
    ///
    /// Behaves exactly like
    /// [`CounterfactualStorePortV1::commit_counterfactual_invalidation`], and
    /// additionally records `record` under the new generation in the same
    /// transaction. The record must be provisional and at the command's
    /// first Tick.
    ///
    /// # Errors
    /// Returns what the storage port returns, and `BindingMismatch` for a
    /// record that is not provisional or not at the first Tick,
    /// `FieldOutOfBounds` for a record that would exceed the recorded-set
    /// bounds, and `DuplicateIdentity` for a node whose artifact digest or
    /// position key is already recorded. Every error and every conflict
    /// records nothing; after `OutcomeUnknown` the caller recovers with
    /// [`CounterfactualStorePortV1::committed_generation_receipt`].
    fn commit_counterfactual_invalidation_with_dependencies(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1>;

    /// Atomically recheck `expected` and append one later recomputation Tick
    /// together with its dependency record.
    ///
    /// Behaves exactly like
    /// [`CounterfactualStorePortV1::append_counterfactual_tick`], and
    /// additionally records `record` under the basis generation in the same
    /// transaction. The record must be provisional and its Tick strictly
    /// greater than the maximum record Tick already persisted in that
    /// generation (gaps are allowed), or, while the generation has no
    /// records, not below the generation's first Tick. The Tick is
    /// stager-asserted: the store cannot check it against the drafts.
    ///
    /// # Errors
    /// Returns what the storage port returns, and `BindingMismatch` for a
    /// record that is not provisional or whose Tick is not strictly after
    /// the persisted record Ticks (or below the first Tick),
    /// `FieldOutOfBounds` for a record that would exceed the recorded-set
    /// bounds, and `DuplicateIdentity` for a node whose artifact digest or
    /// position key is already recorded. Every error and every stale outcome
    /// records nothing; after `OutcomeUnknown` the caller recovers with
    /// [`CounterfactualStorePortV1::current_counterfactual_basis`].
    fn append_counterfactual_tick_with_dependencies(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1>;
}

/// Read side of the dependency record: paged, canonically ordered reads.
///
/// A root node can arrive in a later record behind a reader's cursor, so a
/// READER must read a generation only after the final Tick record of the
/// generation is committed; paging a generation that is still being written
/// is not stable. Adapters just serve committed state. An existing Timeline
/// or Fork generation with no recorded rows yields an empty page; the host
/// decides completeness from the graph digest it published. A Timeline that
/// is unknown or erased,
/// as a parent prefix's or a Fork's, is `ForkNotFound` and never an empty
/// page, the code every `pos-store` Timeline read maps a missing Timeline
/// onto, so a reader cannot mistake erasure for "no dependencies". See
/// [`DependencyReadScopeV1::ensure_current`] for generation qualification and
/// the module's adapter obligations for the read fence of each scope.
///
/// Pages do not echo their scope or generation: the caller owns the scope it
/// asked for and must not mix pages of different requests. A Fork read cannot
/// be bounded by a horizon Tick, unlike a parent prefix, but both kinds of
/// page are ordered by Tick, so a reader such as the frontier source can
/// stop paging once a row's Tick passes its horizon.
pub trait CounterfactualDependencyReadPortV1 {
    /// Read one page of nodes in canonical coordinate order.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration` for a Fork scope that is not the
    /// committed generation, `ForkNotFound` for an unknown or erased
    /// Timeline of either scope, `BindingMismatch` for a request cursor of
    /// the other row kind, `CorruptState` for a stored row that fails
    /// re-validation, or `StorageFailure`.
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, CounterfactualStoreErrorV1>;

    /// Read one page of edges in canonical `IDP1` edge-list order.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration` for a Fork scope that is not the
    /// committed generation, `ForkNotFound` for an unknown or erased
    /// Timeline of either scope, `BindingMismatch` for a request cursor of
    /// the other row kind, `CorruptState` for a stored row that fails
    /// re-validation, or `StorageFailure`.
    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, CounterfactualStoreErrorV1>;
}
