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
//! - that the source node is a six-field array and that its artifact digest
//!   is the supplied source digest;
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
//!   holds the nodes of exactly one Tick and one origin, so a record is
//!   either a parent-prefix record or a Fork-generation record, never both.
//!   The Fork write methods accept only provisional records; recording
//!   committed parent rows is the factual-Tick producer's write (see
//!   Deferred).
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
//!   plan: bounds, strictly ascending unique nodes, canonical edge order,
//!   that every edge consumer is a node of the same record, and that every
//!   edge is declared by its consumer. The unknown-edge policy, horizon,
//!   class, and authorization rules stay in `pos-time` validation. A declared
//!   input without an edge is legal here because `FullSuffixFromCut` records
//!   it as a missing edge; [`TickDependencyRecordV1::uncovered_input_count`]
//!   reports how many there are.
//! - **Bounds.** A graph holds at most 1,000,000 nodes and 4,000,000 edges
//!   ([`MAX_RECORDED_DEPENDENCY_NODES_V1`],
//!   [`MAX_RECORDED_DEPENDENCY_EDGES_V1`]) per recorded set, which adapters
//!   enforce with [`TickDependencyRecordV1::ensure_set_capacity`]. One
//!   record commits inside one Event Store transaction, so it is capped far
//!   lower ([`MAX_TICK_DEPENDENCY_NODES_V1`] and
//!   [`MAX_TICK_DEPENDENCY_EDGES_V1`], the same one to four ratio).
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
//! - Serve reads through the Fork's erasure read fence, ordered by the
//!   canonical coordinate and edge order, and build pages with
//!   [`DependencyPageV1::try_new`] or [`DependencyPageV1::from_ordered`].
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
/// Maximum UTF-8 byte length of a node owner ID.
pub const MAX_DEPENDENCY_OWNER_ID_BYTES_V1: usize = 128;
/// Maximum number of rows in one page.
pub const MAX_DEPENDENCY_PAGE_ROWS_V1: usize = 1_024;

const EDGE_ARRAY_HEAD: u8 = 0x89;
const EDGE_PREFIX: [u8; 6] = [0x64, b'I', b'D', b'P', b'1', 0x01];
const EDGE_DIGEST_DOMAIN: &[u8] = b"PiglorOS.InputDependency.v1";
const NODE_ARRAY_HEAD: u8 = 0x86;
/// Node fields before the artifact digest: tick, position, owner, ordinal, schema.
const NODE_PREFIX_FIELDS: usize = 5;
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
fn check_order<T>(
    items: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
) -> DependencyResult<()> {
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
        encode_bytes(&mut out, self.owner_id.as_bytes(), 3);
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
    /// Returns `FieldOutOfBounds` above [`MAX_DEPENDENCY_EDGE_BYTES_V1`]
    /// (checked first), `InvalidEncoding` for a wrong array head, a
    /// malformed source node or tail, or trailing bytes,
    /// `UnsupportedVersion` for another magic or version, and
    /// `BindingMismatch` unless the bytes carry exactly `consumer` as the
    /// consumer node and `source_digest` as the source artifact digest.
    pub fn try_from_canonical(
        bytes: Vec<u8>,
        consumer: DependencyNodeCoordinateV1,
        source_digest: Hash,
    ) -> DependencyResult<Self> {
        if bytes.len() > MAX_DEPENDENCY_EDGE_BYTES_V1 {
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
            .and_then(|rest| {
                source_artifact_digest(rest)
                    .or(Err(CounterfactualDependencyErrorV1::InvalidEncoding))
            })
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

/// Read the source node's artifact digest and check the edge tail.
fn source_artifact_digest(rest: &[u8]) -> Result<Hash, CborReadError> {
    let mut cursor = CborCursor::new(rest);
    cursor.fixed(&[NODE_ARRAY_HEAD])?;
    (0..NODE_PREFIX_FIELDS).try_for_each(|_| skip_item(&mut cursor, 1))?;
    let digest = read_hash(&mut cursor)?;
    (0..EDGE_TAIL_FIELDS).try_for_each(|_| skip_item(&mut cursor, EDGE_TAIL_ARRAY_DEPTH))?;
    if cursor.is_finished() {
        Ok(digest)
    } else {
        Err(CborReadError::InvalidEncoding)
    }
}

fn edge_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EDGE_DIGEST_DOMAIN);
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// The nodes and edges of one Tick, committed with that Tick's Events.
///
/// Nodes are strictly ascending by [`DependencyNodeCoordinateV1::position_key`]
/// with unique artifact digests; edges are in canonical `IDP1` order
/// ([`DependencyEdgeRecordV1::order_cmp`]) with no repeated key; every edge
/// consumer is a node of this record and every edge source is a declared
/// input of its consumer. All nodes share the record's Tick and origin.
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
    /// [`MAX_TICK_DEPENDENCY_NODES_V1`] nodes or
    /// [`MAX_TICK_DEPENDENCY_EDGES_V1`] edges; `BindingMismatch` for a node
    /// of another Tick or origin; `NonCanonicalOrder` or `DuplicateIdentity`
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
        if nodes.len() > MAX_TICK_DEPENDENCY_NODES_V1
            || edges.len() > MAX_TICK_DEPENDENCY_EDGES_V1
        {
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

    /// Return the Tick of every node.
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

    /// Return how many declared inputs have no edge in this record.
    ///
    /// Every edge is declared by its consumer and a consumer's edges have
    /// distinct sources, so this is the declared inputs minus the edges.
    #[must_use]
    pub fn uncovered_input_count(&self) -> usize {
        let declared: usize = self.nodes.iter().map(|node| node.input_digests.len()).sum();
        declared.saturating_sub(self.edges.len())
    }

    /// Check that recording this record keeps one recorded set within the
    /// graph bounds, given the rows already recorded in that set.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` when the set would exceed
    /// [`MAX_RECORDED_DEPENDENCY_NODES_V1`] nodes or
    /// [`MAX_RECORDED_DEPENDENCY_EDGES_V1`] edges.
    pub const fn ensure_set_capacity(
        &self,
        recorded_nodes: usize,
        recorded_edges: usize,
    ) -> DependencyResult<()> {
        if recorded_nodes.saturating_add(self.nodes.len()) > MAX_RECORDED_DEPENDENCY_NODES_V1
            || recorded_edges.saturating_add(self.edges.len()) > MAX_RECORDED_DEPENDENCY_EDGES_V1
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

fn check_nodes(
    tick: u64,
    origin: RecordedNodeOriginV1,
    nodes: &[DependencyNodeRecordV1],
) -> DependencyResult<()> {
    if nodes
        .iter()
        .any(|node| node.coordinate.tick != tick || node.origin != origin)
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

    /// Return the cursor that resumes after this row.
    #[must_use]
    fn cursor(&self) -> DependencyPageCursorV1;
}

impl DependencyPagedRowV1 for DependencyNodeRecordV1 {
    const KEYED_BY_SOURCE: bool = false;

    fn cursor(&self) -> DependencyPageCursorV1 {
        DependencyPageCursorV1::at(&self.coordinate, None)
    }
}

impl DependencyPagedRowV1 for DependencyEdgeRecordV1 {
    const KEYED_BY_SOURCE: bool = true;

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
    pub fn ensure_current(
        self,
        current_generation: u64,
    ) -> Result<(), CounterfactualStoreErrorV1> {
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
        } else if after.as_ref().is_some_and(|cursor| beyond_scope(scope, cursor)) {
            Err(CounterfactualDependencyErrorV1::InvalidCursor)
        } else {
            Ok(Self { scope, after, limit })
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

const fn beyond_scope(scope: DependencyReadScopeV1, cursor: &DependencyPageCursorV1) -> bool {
    match scope {
        DependencyReadScopeV1::ParentPrefix { through_tick, .. } => cursor.tick > through_tick,
        DependencyReadScopeV1::ForkGeneration(_) => false,
    }
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
    /// # Errors
    /// Returns `InvalidCursor` when the request cursor is of the other row
    /// kind, `FieldOutOfBounds` for more rows than the limit,
    /// `NonCanonicalOrder` or `DuplicateIdentity` unless the rows are
    /// strictly ascending and after the request cursor, and `InvalidCursor`
    /// unless `next` is `None` or the cursor of the last row of a full page.
    pub fn try_new(
        request: &DependencyPageRequestV1,
        items: Vec<T>,
        next: Option<DependencyPageCursorV1>,
    ) -> DependencyResult<Self> {
        check_cursor_kind::<T>(request)
            .and_then(|()| {
                if items.len() > request.limit {
                    Err(CounterfactualDependencyErrorV1::FieldOutOfBounds)
                } else {
                    Ok(())
                }
            })
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
    /// record that is not provisional or not at the first Tick and
    /// `FieldOutOfBounds` for a record that would exceed the recorded-set
    /// bounds. Every error and every conflict records nothing; after
    /// `OutcomeUnknown` the caller recovers with
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
    /// transaction. The record must be provisional and its Tick must come
    /// after every Tick already recorded in that generation.
    ///
    /// # Errors
    /// Returns what the storage port returns, and `BindingMismatch` for a
    /// record that is not provisional or not after the recorded Ticks and
    /// `FieldOutOfBounds` for a record that would exceed the recorded-set
    /// bounds. Every error and every stale outcome records nothing; after
    /// `OutcomeUnknown` the caller recovers with
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
/// Reads serve settled state only. A scope with no recorded rows yields an
/// empty page; the host decides completeness from the graph digest it
/// published. See [`DependencyReadScopeV1::ensure_current`] for generation
/// qualification.
pub trait CounterfactualDependencyReadPortV1 {
    /// Read one page of nodes in canonical coordinate order.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration` for a Fork scope that is not the
    /// committed generation, `ForkNotFound`, `CorruptState`, or
    /// `StorageFailure`.
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, CounterfactualStoreErrorV1>;

    /// Read one page of edges in canonical `IDP1` edge-list order.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration` for a Fork scope that is not the
    /// committed generation, `ForkNotFound`, `CorruptState`, or
    /// `StorageFailure`.
    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, CounterfactualStoreErrorV1>;
}
