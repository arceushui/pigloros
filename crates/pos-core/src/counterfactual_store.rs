//! ADR-064 counterfactual storage transaction port.
//!
//! The core `CounterfactualCoordinator` stages one suffix invalidation as a
//! single Event Store transaction at a Tick Boundary: the `RCF1` frontier, the
//! `SIV1` invalidation, the Fork generation increment, the invalid-artifact
//! index, the cache/checkpoint eviction set, and the first recomputation Tick.
//! [`CounterfactualStorePortV1`] is the one narrow port for that transaction
//! and for generation-qualified reads. It names no backend type; Memory and
//! `SQLite` adapters, graph logic, coordination, the suffix loop, and caches
//! are owned elsewhere.
//!
//! # Carrying `RCF1` and `SIV1` without the conformance crate
//!
//! `pos-conformance` depends on `pos-core`, so this port cannot name the
//! decoded `RecomputationFrontierV1` and `SuffixInvalidationV1` records.
//! Like the other core persistence ports (for example the MAT1 bytes of the
//! adapter recording store), it carries them as exact canonical bytes in
//! core-native newtypes. Construction verifies, without a CBOR decoder, the
//! facts this transaction binds:
//!
//! - the outer definite-length array head, the text magic, and version `1`;
//! - the size bound before anything else is read;
//! - the trailing 32-byte self-digest, recomputed with the ADR-064 domain
//!   over the unsigned array of every preceding field;
//! - the header fields the transaction compares: the `RCF1` plan and
//!   dependency-graph digests, and the `SIV1` plan digest, Fork ID, prior and
//!   new generations (shortest-form unsigned integers), frontier digest, and
//!   Tick Boundary commit coordinate (field 15). The `SIV1` fields 8 through
//!   14 between them are walked as definite-length CBOR items without
//!   interpreting their content.
//!
//! The complete schema contract (list bounds, ordering, coordinate ranges) is
//! validated by the conformance codecs before the coordinator constructs these
//! values; this module never re-derives frontiers or invalidated artifacts.
//! In particular, deriving the invalid-artifact index and the eviction set
//! from the `SIV1` content is the coordinator's responsibility (#338); the
//! port only checks that both are canonical digest sets that never name the
//! command's own `RCF1` or `SIV1`.
//!
//! # ADR gap decisions
//!
//! - **Frontier recheck.** The store cannot re-derive a frontier, so the
//!   "plan/frontier digest" recheck compares the plan digest and the
//!   dependency-graph digest the frontier was derived from. The frontier
//!   digest itself is bound by requiring the `SIV1` frontier digest to equal
//!   the recomputed `RCF1` digest.
//! - **Logical Head.** ADR-064 rechecks the "parent Logical Head". A Fork's
//!   parent cut is immutable once the Fork is created, and the coordinator
//!   (#338) validates the `CFP1` parent cut against the Fork's recorded
//!   parent cut before it calls this port. The port therefore rechecks the
//!   one head that can still move: the Fork Timeline's committed head. That
//!   recheck is the concurrency guard for every atomic Tick append.
//! - **Commit coordinate.** The `SIV1` commit coordinate
//!   `[timeline_id, seq, tick]` names the Tick Boundary the transaction
//!   commits at: the Fork Timeline, the expected committed Fork head (the last
//!   `Seq` before the first recomputation Tick, so the first Tick's Events
//!   follow it), and the first recomputation Tick.
//! - **Invalid-artifact index and eviction set.** Both are strictly ascending
//!   unique digest sets. The index is bounded by the `SIV1` limit of
//!   1,000,000 invalid artifact records; the eviction set by 131,072, the sum
//!   of the `SIV1` checkpoint and Projection/snapshot digest limits.
//! - **First recomputation Tick.** Its drafts reuse the bounded, ordered,
//!   non-empty [`PipelineDraftBatchV1`]; a Tick Boundary always commits at
//!   least one Event.
//! - **Later recomputation Ticks.** Each later Tick is appended with
//!   [`CounterfactualStorePortV1::append_counterfactual_tick`] under the
//!   whole [`CounterfactualBasisV1`] the suffix expects (built with
//!   [`CounterfactualGenerationReceiptV1::tick_basis`]), so a newer
//!   generation, a moved Fork head, or changed published facts make the Tick
//!   stale and commit nothing. The epoch recheck "immediately before commit"
//!   is therefore performed inside the commit itself.
//! - **Persisted basis.** Callers read the Fork's committed head,
//!   generation, and published facts with
//!   [`CounterfactualStorePortV1::current_counterfactual_basis`] instead of
//!   trusting host-attested epochs; the write paths still recheck atomically.
//! - **Head that did not advance.** A first or later Tick whose staged head
//!   is not strictly greater than the expected head is `CorruptState` in
//!   every adapter, and nothing commits.

use std::cmp::Ordering;

use crate::{CborCursor, CborReadError, Hash, PipelineDraftBatchV1, Seq, TimelineId};

/// Maximum encoded size of `RCF1` bytes carried by the port.
pub const MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1: usize = 64 * 1024 * 1024;
/// Maximum encoded size of `SIV1` bytes carried by the port.
pub const MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1: usize = 128 * 1024 * 1024;
/// Maximum number of digests in one invalid-artifact index.
pub const MAX_COUNTERFACTUAL_INVALID_ARTIFACTS_V1: usize = 1_000_000;
/// Maximum number of digests in one cache/checkpoint eviction set.
pub const MAX_COUNTERFACTUAL_EVICTIONS_V1: usize = 131_072;

const DIGEST_FIELD_HEAD: [u8; 2] = [0x58, 0x20];
const DIGEST_FIELD_BYTES: usize = 34;
const ID_FIELD_HEAD: [u8; 1] = [0x50];
const COMMIT_COORDINATE_HEAD: [u8; 1] = [0x83];
/// `SIV1` fields 8 through 14 sit between the frontier digest and the commit
/// coordinate.
const SKIPPED_INVALIDATION_FIELDS: usize = 7;
/// Field 10 nests invalid artifacts, each holding a producer node.
const MAX_SKIPPED_ARRAY_DEPTH: u8 = 3;

const FRONTIER_FRAMING: ArtifactFramingV1 = ArtifactFramingV1 {
    array_head: 0x91,
    unsigned_head: 0x90,
    prefix: [0x64, b'R', b'C', b'F', b'1', 0x01],
    domain: b"PiglorOS.RecomputationFrontier.v1",
    max_bytes: MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1,
};

const INVALIDATION_FRAMING: ArtifactFramingV1 = ArtifactFramingV1 {
    array_head: 0x92,
    unsigned_head: 0x91,
    prefix: [0x64, b'S', b'I', b'V', b'1', 0x01],
    domain: b"PiglorOS.SuffixInvalidation.v1",
    max_bytes: MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1,
};

/// Closed failures of the counterfactual storage port.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CounterfactualStoreErrorV1 {
    /// `RCF1`/`SIV1` bytes are malformed or truncated.
    #[error("counterfactual artifact encoding is invalid")]
    InvalidEncoding,
    /// The artifact magic or schema version is not supported.
    #[error("counterfactual artifact version is unsupported")]
    UnsupportedVersion,
    /// An artifact or digest set exceeds its bound.
    #[error("counterfactual store field is out of bounds")]
    FieldOutOfBounds,
    /// A digest set is not in strictly ascending order.
    #[error("counterfactual digest set is not canonical")]
    NonCanonicalOrder,
    /// A digest set repeats one digest.
    #[error("counterfactual digest set repeats a digest")]
    DuplicateIdentity,
    /// An artifact's trailing digest does not match its content.
    #[error("counterfactual artifact digest does not match its content")]
    DigestMismatch,
    /// The `SIV1` new generation is not exactly its prior generation plus one.
    #[error("counterfactual generation is not the prior generation plus one")]
    PriorGenerationMismatch,
    /// The command's Fork, `RCF1`, and `SIV1` bind different identities.
    #[error("counterfactual command bindings disagree")]
    BindingMismatch,
    /// A read names a generation other than the Fork's committed generation.
    #[error("counterfactual read mixes Fork generations")]
    MixedForkGeneration,
    /// A read names an artifact quarantined by a committed invalidation.
    #[error("counterfactual read names a quarantined artifact")]
    InvalidArtifactReuse,
    /// The Fork is absent or invisible to this store.
    #[error("counterfactual Fork was not found")]
    ForkNotFound,
    /// Persisted counterfactual state is malformed or inconsistent.
    #[error("counterfactual store state is corrupt")]
    CorruptState,
    /// The store cannot commit or determine the outcome of the operation.
    #[error("counterfactual storage operation failed")]
    StorageFailure,
}

struct ArtifactFramingV1 {
    array_head: u8,
    unsigned_head: u8,
    prefix: [u8; 6],
    domain: &'static [u8],
    max_bytes: usize,
}

impl ArtifactFramingV1 {
    /// Verify size, framing, and self-digest; return the fields after the
    /// version and the verified digest.
    fn verify<'a>(&self, bytes: &'a [u8]) -> Result<(&'a [u8], Hash), CounterfactualStoreErrorV1> {
        if bytes.len() > self.max_bytes {
            return Err(CounterfactualStoreErrorV1::FieldOutOfBounds);
        }
        let (unsigned, digest) =
            split_digest_field(bytes).ok_or(CounterfactualStoreErrorV1::InvalidEncoding)?;
        let unsigned_fields = unsigned
            .strip_prefix(&[self.array_head])
            .ok_or(CounterfactualStoreErrorV1::InvalidEncoding)?;
        let fields = unsigned_fields
            .strip_prefix(&self.prefix)
            .ok_or(CounterfactualStoreErrorV1::UnsupportedVersion)?;
        if self.unsigned_digest(unsigned_fields) == digest {
            Ok((fields, digest))
        } else {
            Err(CounterfactualStoreErrorV1::DigestMismatch)
        }
    }

    fn unsigned_digest(&self, unsigned_fields: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.domain);
        hasher.update(&[0, self.unsigned_head]);
        hasher.update(unsigned_fields);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }
}

fn split_digest_field(bytes: &[u8]) -> Option<(&[u8], Hash)> {
    let at = bytes.len().checked_sub(DIGEST_FIELD_BYTES)?;
    let (unsigned, field) = bytes.split_at(at);
    let (head, digest) = field.split_at(DIGEST_FIELD_HEAD.len());
    (head == DIGEST_FIELD_HEAD).then(|| (unsigned, hash_from_slice(digest)))
}

const fn hash_from_slice(bytes: &[u8]) -> Hash {
    let mut value = [0_u8; 32];
    value.copy_from_slice(bytes);
    Hash::from_bytes(value)
}

fn read_id(cursor: &mut CborCursor<'_>) -> Result<[u8; 16], CborReadError> {
    cursor
        .fixed(&ID_FIELD_HEAD)
        .and_then(|()| cursor.take(16))
        .map(|bytes| {
            let mut id = [0_u8; 16];
            id.copy_from_slice(bytes);
            id
        })
}

fn read_hash(cursor: &mut CborCursor<'_>) -> Result<Hash, CborReadError> {
    cursor
        .fixed(&DIGEST_FIELD_HEAD)
        .and_then(|()| cursor.take(32))
        .map(hash_from_slice)
}

/// Read one shortest-form CBOR unsigned integer.
fn read_unsigned(cursor: &mut CborCursor<'_>) -> Result<u64, CborReadError> {
    let (width, minimum) = match cursor.byte()? {
        small @ 0..=23 => return Ok(u64::from(small)),
        24 => (1, 24),
        25 => (2, 0x100),
        26 => (4, 0x1_0000),
        27 => (8, 0x1_0000_0000),
        _ => return Err(CborReadError::InvalidEncoding),
    };
    cursor.unsigned_bytes(width).and_then(|value| {
        if value >= minimum {
            Ok(value)
        } else {
            Err(CborReadError::InvalidEncoding)
        }
    })
}

/// Skip one definite-length unsigned integer, byte string, text string, or
/// array of at most `array_depth` nested levels.
fn skip_item(cursor: &mut CborCursor<'_>, array_depth: u8) -> Result<(), CborReadError> {
    let first = cursor.byte()?;
    let argument = match first & 0x1f {
        small @ 0..=23 => u64::from(small),
        24 => cursor.number::<1>()?,
        25 => cursor.number::<2>()?,
        26 => cursor.number::<4>()?,
        27 => cursor.number::<8>()?,
        _ => return Err(CborReadError::InvalidEncoding),
    };
    match (first >> 5, array_depth) {
        (0, _) => Ok(()),
        (2 | 3, _) => usize::try_from(argument)
            .or(Err(CborReadError::InvalidEncoding))
            .and_then(|length| cursor.take(length))
            .map(drop),
        (4, 1..) => (0..argument).try_for_each(|_| skip_item(cursor, array_depth - 1)),
        _ => Err(CborReadError::InvalidEncoding),
    }
}

/// Exact `RCF1` bytes whose framing, size, self-digest, and header digests
/// were verified by [`Self::try_from_canonical`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecomputationFrontierBytesV1 {
    bytes: Vec<u8>,
    digest: Hash,
    plan_digest: Hash,
    dependency_graph_digest: Hash,
}

impl RecomputationFrontierBytesV1 {
    /// Verify exact canonical `RCF1` bytes and extract their bound digests.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` above
    /// [`MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1`] (checked first),
    /// `InvalidEncoding` for wrong framing or truncated header fields,
    /// `UnsupportedVersion` for another magic or version, and
    /// `DigestMismatch` when the trailing frontier digest is wrong.
    pub fn try_from_canonical(bytes: Vec<u8>) -> Result<Self, CounterfactualStoreErrorV1> {
        let (fields, digest) = FRONTIER_FRAMING.verify(&bytes)?;
        let (plan_digest, dependency_graph_digest) =
            frontier_header(fields).or(Err(CounterfactualStoreErrorV1::InvalidEncoding))?;
        Ok(Self {
            bytes,
            digest,
            plan_digest,
            dependency_graph_digest,
        })
    }

    /// Borrow the exact canonical `RCF1` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the verified `RCF1` frontier digest (field 16).
    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    /// Return the counterfactual plan digest (field 3).
    #[must_use]
    pub const fn plan_digest(&self) -> Hash {
        self.plan_digest
    }

    /// Return the dependency-graph digest the frontier was derived from (field 5).
    #[must_use]
    pub const fn dependency_graph_digest(&self) -> Hash {
        self.dependency_graph_digest
    }
}

fn frontier_header(fields: &[u8]) -> Result<(Hash, Hash), CborReadError> {
    let mut cursor = CborCursor::new(fields);
    read_id(&mut cursor)?;
    let plan_digest = read_hash(&mut cursor)?;
    read_hash(&mut cursor)?;
    read_hash(&mut cursor).map(|dependency_graph_digest| (plan_digest, dependency_graph_digest))
}

/// Exact `SIV1` bytes whose framing, size, self-digest, header fields, and
/// generation increment were verified by [`Self::try_from_canonical`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuffixInvalidationBytesV1 {
    bytes: Vec<u8>,
    digest: Hash,
    header: InvalidationHeaderV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InvalidationHeaderV1 {
    plan_digest: Hash,
    fork_id: [u8; 16],
    prior_generation: u64,
    new_generation: u64,
    frontier_digest: Hash,
    commit_timeline_id: [u8; 16],
    commit_seq: u64,
    commit_tick: u64,
}

impl SuffixInvalidationBytesV1 {
    /// Verify exact canonical `SIV1` bytes and extract their bound fields.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` above
    /// [`MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1`] (checked first),
    /// `InvalidEncoding` for wrong framing, truncated or malformed fields up
    /// to the commit coordinate, or a non-shortest generation or commit
    /// coordinate integer, `UnsupportedVersion` for another magic or
    /// version, `DigestMismatch` when the trailing invalidation digest is
    /// wrong, and `PriorGenerationMismatch` unless the new generation is
    /// exactly the prior generation plus one.
    pub fn try_from_canonical(bytes: Vec<u8>) -> Result<Self, CounterfactualStoreErrorV1> {
        let (fields, digest) = INVALIDATION_FRAMING.verify(&bytes)?;
        let header =
            invalidation_header(fields).or(Err(CounterfactualStoreErrorV1::InvalidEncoding))?;
        if header.prior_generation.checked_add(1) != Some(header.new_generation) {
            return Err(CounterfactualStoreErrorV1::PriorGenerationMismatch);
        }
        Ok(Self {
            bytes,
            digest,
            header,
        })
    }

    /// Borrow the exact canonical `SIV1` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the verified `SIV1` invalidation digest (field 17).
    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }

    /// Return the counterfactual plan digest (field 3).
    #[must_use]
    pub const fn plan_digest(&self) -> Hash {
        self.header.plan_digest
    }

    /// Return the 16-byte Fork ID (field 4).
    #[must_use]
    pub const fn fork_id(&self) -> [u8; 16] {
        self.header.fork_id
    }

    /// Return the prior Fork generation (field 5).
    #[must_use]
    pub const fn prior_generation(&self) -> u64 {
        self.header.prior_generation
    }

    /// Return the new Fork generation (field 6).
    #[must_use]
    pub const fn new_generation(&self) -> u64 {
        self.header.new_generation
    }

    /// Return the bound `RCF1` frontier digest (field 7).
    #[must_use]
    pub const fn frontier_digest(&self) -> Hash {
        self.header.frontier_digest
    }

    /// Return the Tick Boundary commit coordinate's 16-byte Timeline ID (field 15).
    #[must_use]
    pub const fn commit_timeline_id(&self) -> [u8; 16] {
        self.header.commit_timeline_id
    }

    /// Return the Tick Boundary commit coordinate's Fork head `Seq` (field 15).
    #[must_use]
    pub const fn commit_seq(&self) -> u64 {
        self.header.commit_seq
    }

    /// Return the Tick Boundary commit coordinate's Tick (field 15).
    #[must_use]
    pub const fn commit_tick(&self) -> u64 {
        self.header.commit_tick
    }
}

fn invalidation_header(fields: &[u8]) -> Result<InvalidationHeaderV1, CborReadError> {
    let mut cursor = CborCursor::new(fields);
    read_id(&mut cursor)?;
    let plan_digest = read_hash(&mut cursor)?;
    let fork_id = read_id(&mut cursor)?;
    let prior_generation = read_unsigned(&mut cursor)?;
    let new_generation = read_unsigned(&mut cursor)?;
    let frontier_digest = read_hash(&mut cursor)?;
    (0..SKIPPED_INVALIDATION_FIELDS)
        .try_for_each(|_| skip_item(&mut cursor, MAX_SKIPPED_ARRAY_DEPTH))?;
    cursor.fixed(&COMMIT_COORDINATE_HEAD)?;
    let commit_timeline_id = read_id(&mut cursor)?;
    let commit_seq = read_unsigned(&mut cursor)?;
    read_unsigned(&mut cursor).map(|commit_tick| InvalidationHeaderV1 {
        plan_digest,
        fork_id,
        prior_generation,
        new_generation,
        frontier_digest,
        commit_timeline_id,
        commit_seq,
        commit_tick,
    })
}

/// Which persisted fact made an invalidation stale, in canonical check order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationConflictV1 {
    /// The Fork Logical Head moved.
    LogicalHead,
    /// The admitted plan digest changed.
    PlanDigest,
    /// The committed dependency graph the frontier was derived from changed.
    DependencyGraphDigest,
    /// The committed Fork generation is not the `SIV1` prior generation.
    PriorGeneration,
    /// The trust epoch changed.
    TrustEpoch,
    /// The revocation epoch changed.
    RevocationEpoch,
    /// The erasure epoch changed.
    ErasureEpoch,
}

/// The host-published facts of one Fork that every counterfactual write is
/// rechecked against.
///
/// The host publishes them with
/// [`CounterfactualStorePortV1::publish_counterfactual_facts`]; adapters
/// persist them per Fork and return them inside
/// [`CounterfactualStorePortV1::current_counterfactual_basis`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualFactsV1 {
    /// Admitted counterfactual plan digest.
    pub plan_digest: Hash,
    /// Committed dependency-graph digest frontiers are derived from.
    pub dependency_graph_digest: Hash,
    /// Trust-policy epoch.
    pub trust_epoch: u64,
    /// Authority revocation epoch.
    pub revocation_epoch: u64,
    /// Erasure epoch.
    pub erasure_epoch: u64,
}

impl CounterfactualFactsV1 {
    /// Return the first epoch of `current` that differs from these facts, in
    /// canonical order: trust, revocation, erasure.
    ///
    /// This is the only place epochs are compared;
    /// [`CounterfactualBasisV1::first_conflict`] delegates to it.
    #[must_use]
    pub fn first_epoch_change(&self, current: &Self) -> Option<InvalidationConflictV1> {
        first_difference([
            (
                self.trust_epoch == current.trust_epoch,
                InvalidationConflictV1::TrustEpoch,
            ),
            (
                self.revocation_epoch == current.revocation_epoch,
                InvalidationConflictV1::RevocationEpoch,
            ),
            (
                self.erasure_epoch == current.erasure_epoch,
                InvalidationConflictV1::ErasureEpoch,
            ),
        ])
    }
}

/// Return the conflict of the first check whose facts differ.
fn first_difference<const N: usize>(
    checks: [(bool, InvalidationConflictV1); N],
) -> Option<InvalidationConflictV1> {
    checks
        .into_iter()
        .find_map(|(same, conflict)| (!same).then_some(conflict))
}

/// The persisted state of one Fork a counterfactual write is derived against.
///
/// The coordinator's expected basis comes from
/// [`CounterfactualInvalidationCommandV1::expected_basis`], and the suffix
/// loop's from [`CounterfactualGenerationReceiptV1::tick_basis`]; an adapter
/// reads the persisted basis inside its transaction and commits only when
/// [`Self::first_conflict`] returns `None`.
///
/// The Logical Head here is the Fork Timeline's moving committed head, not
/// ADR-064's "parent Logical Head": a Fork's parent cut is immutable once the
/// Fork is created, and the coordinator (#338) validates the `CFP1` parent
/// cut against the Fork's recorded parent cut before calling the port. The
/// port rechecks the moving Fork head, which guards every atomic Tick append
/// against concurrent writers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualBasisV1 {
    /// Committed Logical Head of the Fork Timeline.
    pub fork_logical_head: Seq,
    /// Committed Fork generation.
    pub generation: u64,
    /// Host-published facts of the Fork.
    pub facts: CounterfactualFactsV1,
}

impl CounterfactualBasisV1 {
    /// Return the first persisted fact that differs from this expected basis,
    /// in canonical order: Logical Head, plan digest, dependency-graph
    /// digest, generation, then the epochs of
    /// [`CounterfactualFactsV1::first_epoch_change`].
    #[must_use]
    pub fn first_conflict(&self, persisted: &Self) -> Option<InvalidationConflictV1> {
        first_difference([
            (
                self.fork_logical_head == persisted.fork_logical_head,
                InvalidationConflictV1::LogicalHead,
            ),
            (
                self.facts.plan_digest == persisted.facts.plan_digest,
                InvalidationConflictV1::PlanDigest,
            ),
            (
                self.facts.dependency_graph_digest == persisted.facts.dependency_graph_digest,
                InvalidationConflictV1::DependencyGraphDigest,
            ),
            (
                self.generation == persisted.generation,
                InvalidationConflictV1::PriorGeneration,
            ),
        ])
        .or_else(|| self.facts.first_epoch_change(&persisted.facts))
    }

    /// Build the outcome of a later Tick committed on this basis.
    ///
    /// This is the adapter-only constructor of
    /// [`CounterfactualTickOutcomeV1::Committed`]: only a
    /// [`CounterfactualStorePortV1`] adapter calls it, inside
    /// [`CounterfactualStorePortV1::append_counterfactual_tick`], before it
    /// installs the Tick. `head` is the Fork Logical Head after the Tick's
    /// Events; a Tick commits at least one Event, so it must be strictly
    /// greater than this basis's head.
    ///
    /// # Errors
    /// Returns `CorruptState` unless `head` is greater than
    /// [`Self::fork_logical_head`]; the adapter then commits nothing.
    pub const fn committed_tick(
        &self,
        head: Seq,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        if head.as_u64() > self.fork_logical_head.as_u64() {
            Ok(CounterfactualTickOutcomeV1::Committed { head })
        } else {
            Err(CounterfactualStoreErrorV1::CorruptState)
        }
    }
}

/// Outcome of one later recomputation Tick append; there is no partial variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualTickOutcomeV1 {
    /// Every Event of the Tick committed; `head` is the Fork Logical Head
    /// after them.
    Committed {
        /// Fork Logical Head after the Tick's Events.
        head: Seq,
    },
    /// A persisted fact differed from the expected basis; nothing committed.
    Stale(InvalidationConflictV1),
}

/// Caller-supplied parts of one counterfactual invalidation transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualInvalidationInputV1 {
    /// Fork Timeline whose generation is incremented.
    pub fork: TimelineId,
    /// Expected committed Logical Head of the Fork Timeline.
    pub fork_logical_head: Seq,
    /// Expected trust-policy epoch.
    pub trust_epoch: u64,
    /// Expected authority revocation epoch.
    pub revocation_epoch: u64,
    /// Expected erasure epoch.
    pub erasure_epoch: u64,
    /// Verified `RCF1` frontier.
    pub frontier: RecomputationFrontierBytesV1,
    /// Verified `SIV1` invalidation.
    pub invalidation: SuffixInvalidationBytesV1,
    /// Strictly ascending digests of every artifact quarantined by this generation.
    pub invalid_artifacts: Vec<Hash>,
    /// Strictly ascending cache and checkpoint digests evicted with this generation.
    pub evictions: Vec<Hash>,
    /// Tick number of the first recomputation Tick.
    pub first_tick: u64,
    /// Ordered Event drafts of the first recomputation Tick.
    pub first_tick_drafts: PipelineDraftBatchV1,
}

/// One complete, validated counterfactual invalidation transaction.
///
/// An adapter commits all of it under the new generation or none of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualInvalidationCommandV1 {
    input: CounterfactualInvalidationInputV1,
}

impl CounterfactualInvalidationCommandV1 {
    /// Bind the Fork, `RCF1`, `SIV1`, index, eviction set, and first Tick.
    ///
    /// The `SIV1` commit coordinate must name this Tick Boundary: the Fork
    /// Timeline, the expected committed Fork head `fork_logical_head` (the
    /// last `Seq` before the first Tick's Events), and `first_tick`. Which
    /// artifacts belong in the index and eviction set is derived by the
    /// coordinator (#338) from the `SIV1` content and is not re-derived here.
    ///
    /// # Errors
    /// Returns `BindingMismatch` unless the `SIV1` Fork ID and commit
    /// Timeline are `fork`, the `SIV1` and `RCF1` plan digests agree, the
    /// `SIV1` frontier digest is the `RCF1` digest, the commit `Seq` is
    /// `fork_logical_head`, and the commit Tick is `first_tick`. Returns
    /// `FieldOutOfBounds`, `NonCanonicalOrder`, or `DuplicateIdentity` for an
    /// oversized, unordered, or repeating invalid-artifact index or eviction
    /// set, and then `BindingMismatch` when either set names the command's
    /// own `RCF1` or `SIV1` digest, so a committed record can never be
    /// quarantined by its own transaction.
    pub fn try_new(
        input: CounterfactualInvalidationInputV1,
    ) -> Result<Self, CounterfactualStoreErrorV1> {
        let fork_id = input.fork.inner().to_bytes();
        let bound = (
            input.invalidation.fork_id(),
            input.invalidation.plan_digest(),
            input.invalidation.frontier_digest(),
            input.invalidation.commit_timeline_id(),
            input.invalidation.commit_seq(),
            input.invalidation.commit_tick(),
        );
        let expected = (
            fork_id,
            input.frontier.plan_digest(),
            input.frontier.digest(),
            fork_id,
            input.fork_logical_head.as_u64(),
            input.first_tick,
        );
        if bound != expected {
            return Err(CounterfactualStoreErrorV1::BindingMismatch);
        }
        ordered_digest_set(
            &input.invalid_artifacts,
            MAX_COUNTERFACTUAL_INVALID_ARTIFACTS_V1,
        )
        .and_then(|()| ordered_digest_set(&input.evictions, MAX_COUNTERFACTUAL_EVICTIONS_V1))
        .and_then(|()| {
            if quarantines_own_records(&input) {
                Err(CounterfactualStoreErrorV1::BindingMismatch)
            } else {
                Ok(Self { input })
            }
        })
    }

    /// Return the Fork Timeline.
    #[must_use]
    pub const fn fork(&self) -> TimelineId {
        self.input.fork
    }

    /// Return the basis an adapter must find persisted before committing.
    #[must_use]
    pub const fn expected_basis(&self) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head: self.input.fork_logical_head,
            generation: self.input.invalidation.prior_generation(),
            facts: CounterfactualFactsV1 {
                plan_digest: self.input.frontier.plan_digest(),
                dependency_graph_digest: self.input.frontier.dependency_graph_digest(),
                trust_epoch: self.input.trust_epoch,
                revocation_epoch: self.input.revocation_epoch,
                erasure_epoch: self.input.erasure_epoch,
            },
        }
    }

    /// Return the Fork generation this transaction commits.
    #[must_use]
    pub const fn new_generation(&self) -> ForkGenerationV1 {
        ForkGenerationV1 {
            fork: self.input.fork,
            generation: self.input.invalidation.new_generation(),
        }
    }

    /// Borrow the verified `RCF1` frontier.
    #[must_use]
    pub const fn frontier(&self) -> &RecomputationFrontierBytesV1 {
        &self.input.frontier
    }

    /// Borrow the verified `SIV1` invalidation.
    #[must_use]
    pub const fn invalidation(&self) -> &SuffixInvalidationBytesV1 {
        &self.input.invalidation
    }

    /// Borrow the ascending invalid-artifact index.
    #[must_use]
    pub fn invalid_artifacts(&self) -> &[Hash] {
        &self.input.invalid_artifacts
    }

    /// Borrow the ascending cache/checkpoint eviction set.
    #[must_use]
    pub fn evictions(&self) -> &[Hash] {
        &self.input.evictions
    }

    /// Return the first recomputation Tick number.
    #[must_use]
    pub const fn first_tick(&self) -> u64 {
        self.input.first_tick
    }

    /// Borrow the first recomputation Tick's ordered drafts.
    #[must_use]
    pub const fn first_tick_drafts(&self) -> &PipelineDraftBatchV1 {
        &self.input.first_tick_drafts
    }

    /// Build the receipt for this command after its whole transaction committed.
    ///
    /// This is the adapter-only constructor: only a
    /// [`CounterfactualStorePortV1`] adapter calls it, inside
    /// [`CounterfactualStorePortV1::commit_counterfactual_invalidation`],
    /// after the whole transaction committed. It stays public because the
    /// Memory and `SQLite` adapters live in another crate; the receipt is
    /// meaningful only as that method's return value.
    ///
    /// `first_tick_head` is the Fork Logical Head after the first Tick's
    /// Events. A Tick Boundary commits at least one Event, so it must be
    /// strictly greater than the expected head. Adapters build the receipt
    /// from the staged head before installing anything, so this rejection
    /// commits nothing.
    ///
    /// # Errors
    /// Returns `CorruptState` unless `first_tick_head` is greater than the
    /// command's expected Fork head. This is the single error every adapter
    /// reports for a first Tick whose head did not advance.
    pub const fn committed_receipt(
        &self,
        first_tick_head: Seq,
    ) -> Result<CounterfactualGenerationReceiptV1, CounterfactualStoreErrorV1> {
        if first_tick_head.as_u64() <= self.input.fork_logical_head.as_u64() {
            return Err(CounterfactualStoreErrorV1::CorruptState);
        }
        Ok(CounterfactualGenerationReceiptV1 {
            generation: self.new_generation(),
            frontier_digest: self.input.frontier.digest(),
            invalidation_digest: self.input.invalidation.digest(),
            first_tick: self.input.first_tick,
            first_tick_head,
            facts: self.expected_basis().facts,
        })
    }
}

/// Whether the ascending index or eviction set names the command's own
/// `RCF1` or `SIV1` digest.
fn quarantines_own_records(input: &CounterfactualInvalidationInputV1) -> bool {
    let own = [input.frontier.digest(), input.invalidation.digest()];
    [&input.invalid_artifacts, &input.evictions]
        .into_iter()
        .any(|set| own.iter().any(|digest| set.binary_search(digest).is_ok()))
}

fn ordered_digest_set(digests: &[Hash], maximum: usize) -> Result<(), CounterfactualStoreErrorV1> {
    if digests.len() > maximum {
        return Err(CounterfactualStoreErrorV1::FieldOutOfBounds);
    }
    digests
        .windows(2)
        .try_for_each(|pair| match pair[0].cmp(&pair[1]) {
            Ordering::Less => Ok(()),
            Ordering::Equal => Err(CounterfactualStoreErrorV1::DuplicateIdentity),
            Ordering::Greater => Err(CounterfactualStoreErrorV1::NonCanonicalOrder),
        })
}

/// One generation-qualified Fork coordinate; every read names one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkGenerationV1 {
    /// Fork Timeline.
    pub fork: TimelineId,
    /// Fork generation.
    pub generation: u64,
}

impl ForkGenerationV1 {
    /// Resolve one stored artifact for a read at this generation.
    ///
    /// Adapters route every read through this rule so that a quarantined or
    /// other-generation artifact is never exposed.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration` unless `current_generation` is this
    /// generation, and `InvalidArtifactReuse` for a quarantined artifact.
    pub fn resolve_read(
        self,
        current_generation: u64,
        stored: StoredCounterfactualArtifactV1,
    ) -> Result<Option<Vec<u8>>, CounterfactualStoreErrorV1> {
        if self.generation != current_generation {
            return Err(CounterfactualStoreErrorV1::MixedForkGeneration);
        }
        match stored {
            StoredCounterfactualArtifactV1::Absent => Ok(None),
            StoredCounterfactualArtifactV1::Quarantined => {
                Err(CounterfactualStoreErrorV1::InvalidArtifactReuse)
            }
            StoredCounterfactualArtifactV1::Authoritative(bytes) => Ok(Some(bytes)),
        }
    }
}

/// An adapter's view of one artifact digest on a Fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredCounterfactualArtifactV1 {
    /// No artifact with this digest exists on the Fork.
    Absent,
    /// A committed invalidation quarantined the artifact; its bytes stay for audit only.
    Quarantined,
    /// The artifact is authoritative at the current generation.
    Authoritative(Vec<u8>),
}

/// Receipt of one fully committed invalidation transaction.
///
/// Only [`CounterfactualInvalidationCommandV1::committed_receipt`] builds a
/// receipt, from a command whose `SIV1` binds the Fork, the new generation,
/// the `RCF1` digest, and the Tick Boundary commit coordinate. A receipt
/// therefore matches exactly one `SIV1`; holders verify that the receipt's
/// generation actually committed by reading that `SIV1` at
/// [`Self::generation`] and checking [`Self::matches_invalidation`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualGenerationReceiptV1 {
    generation: ForkGenerationV1,
    frontier_digest: Hash,
    invalidation_digest: Hash,
    first_tick: u64,
    first_tick_head: Seq,
    facts: CounterfactualFactsV1,
}

impl CounterfactualGenerationReceiptV1 {
    /// Return the committed Fork generation.
    #[must_use]
    pub const fn generation(&self) -> ForkGenerationV1 {
        self.generation
    }

    /// Return the committed `RCF1` frontier digest.
    #[must_use]
    pub const fn frontier_digest(&self) -> Hash {
        self.frontier_digest
    }

    /// Return the committed `SIV1` invalidation digest.
    #[must_use]
    pub const fn invalidation_digest(&self) -> Hash {
        self.invalidation_digest
    }

    /// Return the committed first recomputation Tick number.
    #[must_use]
    pub const fn first_tick(&self) -> u64 {
        self.first_tick
    }

    /// Return the Fork Logical Head after the first Tick's Events.
    #[must_use]
    pub const fn first_tick_head(&self) -> Seq {
        self.first_tick_head
    }

    /// Return the host-published facts the generation was committed under.
    #[must_use]
    pub const fn facts(&self) -> CounterfactualFactsV1 {
        self.facts
    }

    /// Return the basis a later Tick of this generation is appended on, with
    /// the Fork Logical Head `fork_logical_head` before that Tick.
    #[must_use]
    pub const fn tick_basis(&self, fork_logical_head: Seq) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head,
            generation: self.generation.generation,
            facts: self.facts,
        }
    }

    /// Whether `invalidation` is the `SIV1` this receipt committed.
    ///
    /// The receipt was built from a command whose `SIV1` was verified to
    /// bind this receipt's Fork, generation (`new_generation`), frontier
    /// digest, plan digest, and first Tick (`commit_tick`). Equal
    /// invalidation digests imply only those `SIV1`-carried bindings: the
    /// receipt's `first_tick_head` and published facts are attested by the
    /// adapter that committed it, and a match proves the receipt was built
    /// from this `SIV1`, not that it was committed. Read the `SIV1` at the
    /// receipt's generation through the port to prove the commit.
    #[must_use]
    pub fn matches_invalidation(&self, invalidation: &SuffixInvalidationBytesV1) -> bool {
        self.invalidation_digest == invalidation.digest()
    }
}

/// Outcome of one invalidation transaction; there is no partial variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualInvalidationOutcomeV1 {
    /// Every part of the command committed under the new generation.
    Committed(CounterfactualGenerationReceiptV1),
    /// A persisted fact differed from the expected basis; nothing committed.
    InvalidationConflict(InvalidationConflictV1),
}

/// Host-only Event Store port for atomic generation invalidation and
/// generation-qualified reads.
///
/// Only the core `CounterfactualCoordinator` may hold this capability; it
/// must never be exposed to Plugin, provider, Driver, or evaluator code.
///
/// # Adapter obligations
///
/// - Persist, per Fork, the [`CounterfactualFactsV1`] published with
///   [`Self::publish_counterfactual_facts`] and the committed generation, so
///   every basis recheck compares committed facts rather than caller input.
/// - Compare an expected basis with the persisted one only through
///   [`CounterfactualBasisV1::first_conflict`], inside the same
///   serialization point as the write it guards.
/// - Admit the Events of the first and every later recomputation Tick under
///   the same rules as a generic append of those drafts on the Fork,
///   including the non-geographic/consent Event guard (`pos-store`'s
///   `ensure_non_geographic_drafts`), whose rejection is concealed as
///   `ForkNotFound`, and inside the Fork's erasure write fence.
/// - Serve [`Self::current_fork_generation`],
///   [`Self::current_counterfactual_basis`], and
///   [`Self::read_generation_artifact`] through the Fork's erasure read
///   fence.
/// - Route every artifact read through [`ForkGenerationV1::resolve_read`].
/// - Build receipts only with
///   [`CounterfactualInvalidationCommandV1::committed_receipt`] and later
///   Tick outcomes only with [`CounterfactualBasisV1::committed_tick`], from
///   the staged head and before installing anything. A head that did not
///   advance is reported as `CorruptState` and commits nothing.
///
/// Epoch monotonicity of those published facts is a host obligation; the
/// port compares them for equality only.
pub trait CounterfactualStorePortV1 {
    /// Publish the host-owned counterfactual facts of one Fork.
    ///
    /// The first publication starts the Fork at generation 0. A later one
    /// replaces only the facts; the committed generation and artifacts stay.
    /// Republishing a different plan or dependency-graph digest without a
    /// new generation makes every in-flight basis `Stale` with
    /// `PlanDigest` or `DependencyGraphDigest`.
    /// This is a host operation; the coordinator never calls it.
    ///
    /// # Errors
    /// Returns `ForkNotFound` unless `fork` is a visible Fork Timeline, and
    /// `CorruptState` or `StorageFailure`; every error publishes nothing.
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1>;

    /// Atomically recheck the expected basis and commit the whole command.
    ///
    /// Inside one serialization point the adapter reads the persisted
    /// [`CounterfactualBasisV1`] of the command's Fork, returns
    /// [`CounterfactualInvalidationOutcomeV1::InvalidationConflict`] with the
    /// first conflict when it differs, and otherwise commits `RCF1`, `SIV1`,
    /// the generation increment, the invalid-artifact index, the eviction
    /// set, and the first Tick's Events as one transaction.
    ///
    /// # Errors
    /// Returns `ForkNotFound`, `CorruptState`, or `StorageFailure`. Every
    /// error and every conflict commits nothing; `StorageFailure` may also
    /// mean the outcome is unknown.
    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1>;

    /// Atomically recheck `expected` and append one later recomputation Tick.
    ///
    /// Inside one serialization point the adapter reads the persisted
    /// [`CounterfactualBasisV1`] of `fork`, returns
    /// [`CounterfactualTickOutcomeV1::Stale`] with the first conflict when it
    /// differs from `expected` (another generation, a moved Fork head, or
    /// changed facts), and otherwise appends `drafts` as one Tick and returns
    /// [`CounterfactualBasisV1::committed_tick`] of the new head.
    ///
    /// # Errors
    /// Returns `ForkNotFound` (also for a draft the generic append guard
    /// rejects), `CorruptState`, or `StorageFailure`. Every error and every
    /// stale outcome commits nothing; `StorageFailure` may also mean the
    /// outcome is unknown.
    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1>;

    /// Return the Fork's committed generation coordinate.
    ///
    /// # Errors
    /// Returns `ForkNotFound`, `CorruptState`, or `StorageFailure`.
    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1>;

    /// Return the Fork's persisted basis: its committed Logical Head and
    /// generation and its published facts, read at one consistent point.
    ///
    /// # Errors
    /// Returns `ForkNotFound` (also before any facts were published),
    /// `CorruptState`, or `StorageFailure`.
    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, CounterfactualStoreErrorV1>;

    /// Read one artifact by digest at an exact Fork generation.
    ///
    /// Adapters resolve the stored state with
    /// [`ForkGenerationV1::resolve_read`]; quarantined bytes are never returned.
    ///
    /// # Errors
    /// Returns `MixedForkGeneration`, `InvalidArtifactReuse`, `ForkNotFound`,
    /// `CorruptState`, or `StorageFailure`.
    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, CounterfactualStoreErrorV1>;
}
