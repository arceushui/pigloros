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
//! - the fixed-position header fields the transaction compares: the `RCF1`
//!   plan and dependency-graph digests, and the `SIV1` plan digest, Fork ID,
//!   prior and new generations (shortest-form unsigned integers), and
//!   frontier digest.
//!
//! The complete schema contract (list bounds, ordering, coordinate ranges) is
//! validated by the conformance codecs before the coordinator constructs these
//! values; this module never re-derives frontiers or invalidated artifacts.
//!
//! # ADR gap decisions
//!
//! - **Frontier recheck.** The store cannot re-derive a frontier, so the
//!   "plan/frontier digest" recheck compares the plan digest and the
//!   dependency-graph digest the frontier was derived from. The frontier
//!   digest itself is bound by requiring the `SIV1` frontier digest to equal
//!   the recomputed `RCF1` digest.
//! - **Logical Head.** The rechecked Logical Head is the Fork Timeline's
//!   committed head that the new generation is parented on.
//! - **Invalid-artifact index and eviction set.** Both are strictly ascending
//!   unique digest sets. The index is bounded by the `SIV1` limit of
//!   1,000,000 invalid artifact records; the eviction set by 131,072, the sum
//!   of the `SIV1` checkpoint and Projection/snapshot digest limits.
//! - **First recomputation Tick.** Its drafts reuse the bounded, ordered,
//!   non-empty [`PipelineDraftBatchV1`]; a Tick Boundary always commits at
//!   least one Event.

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
fn read_generation(cursor: &mut CborCursor<'_>) -> Result<u64, CborReadError> {
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
}

impl SuffixInvalidationBytesV1 {
    /// Verify exact canonical `SIV1` bytes and extract their bound fields.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` above
    /// [`MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1`] (checked first),
    /// `InvalidEncoding` for wrong framing, truncated header fields, or a
    /// non-shortest generation, `UnsupportedVersion` for another magic or
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
}

fn invalidation_header(fields: &[u8]) -> Result<InvalidationHeaderV1, CborReadError> {
    let mut cursor = CborCursor::new(fields);
    read_id(&mut cursor)?;
    let plan_digest = read_hash(&mut cursor)?;
    let fork_id = read_id(&mut cursor)?;
    let prior_generation = read_generation(&mut cursor)?;
    let new_generation = read_generation(&mut cursor)?;
    read_hash(&mut cursor).map(|frontier_digest| InvalidationHeaderV1 {
        plan_digest,
        fork_id,
        prior_generation,
        new_generation,
        frontier_digest,
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

/// The persisted facts an invalidation was derived against.
///
/// The coordinator's expected basis comes from
/// [`CounterfactualInvalidationCommandV1::expected_basis`]; an adapter reads
/// the persisted basis inside its transaction and commits only when
/// [`Self::first_conflict`] returns `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualBasisV1 {
    /// Committed Logical Head of the Fork Timeline the new generation follows.
    pub fork_logical_head: Seq,
    /// Admitted counterfactual plan digest.
    pub plan_digest: Hash,
    /// Committed dependency-graph digest the frontier was derived from.
    pub dependency_graph_digest: Hash,
    /// Committed Fork generation.
    pub generation: u64,
    /// Trust-policy epoch.
    pub trust_epoch: u64,
    /// Authority revocation epoch.
    pub revocation_epoch: u64,
    /// Erasure epoch.
    pub erasure_epoch: u64,
}

impl CounterfactualBasisV1 {
    /// Return the first persisted fact that differs from this expected basis.
    #[must_use]
    pub fn first_conflict(&self, persisted: &Self) -> Option<InvalidationConflictV1> {
        [
            (
                self.fork_logical_head == persisted.fork_logical_head,
                InvalidationConflictV1::LogicalHead,
            ),
            (
                self.plan_digest == persisted.plan_digest,
                InvalidationConflictV1::PlanDigest,
            ),
            (
                self.dependency_graph_digest == persisted.dependency_graph_digest,
                InvalidationConflictV1::DependencyGraphDigest,
            ),
            (
                self.generation == persisted.generation,
                InvalidationConflictV1::PriorGeneration,
            ),
            (
                self.trust_epoch == persisted.trust_epoch,
                InvalidationConflictV1::TrustEpoch,
            ),
            (
                self.revocation_epoch == persisted.revocation_epoch,
                InvalidationConflictV1::RevocationEpoch,
            ),
            (
                self.erasure_epoch == persisted.erasure_epoch,
                InvalidationConflictV1::ErasureEpoch,
            ),
        ]
        .into_iter()
        .find_map(|(same, conflict)| (!same).then_some(conflict))
    }
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
    /// # Errors
    /// Returns `BindingMismatch` unless the `SIV1` Fork ID is `fork`, the
    /// `SIV1` and `RCF1` plan digests agree, and the `SIV1` frontier digest is
    /// the `RCF1` digest. Returns `FieldOutOfBounds`, `NonCanonicalOrder`, or
    /// `DuplicateIdentity` for an oversized, unordered, or repeating
    /// invalid-artifact index or eviction set.
    pub fn try_new(
        input: CounterfactualInvalidationInputV1,
    ) -> Result<Self, CounterfactualStoreErrorV1> {
        let bound = (
            input.invalidation.fork_id(),
            input.invalidation.plan_digest(),
            input.invalidation.frontier_digest(),
        );
        let expected = (
            input.fork.inner().to_bytes(),
            input.frontier.plan_digest(),
            input.frontier.digest(),
        );
        if bound != expected {
            return Err(CounterfactualStoreErrorV1::BindingMismatch);
        }
        ordered_digest_set(
            &input.invalid_artifacts,
            MAX_COUNTERFACTUAL_INVALID_ARTIFACTS_V1,
        )
        .and_then(|()| ordered_digest_set(&input.evictions, MAX_COUNTERFACTUAL_EVICTIONS_V1))
        .map(|()| Self { input })
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
            plan_digest: self.input.frontier.plan_digest(),
            dependency_graph_digest: self.input.frontier.dependency_graph_digest(),
            generation: self.input.invalidation.prior_generation(),
            trust_epoch: self.input.trust_epoch,
            revocation_epoch: self.input.revocation_epoch,
            erasure_epoch: self.input.erasure_epoch,
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
    /// `first_tick_head` is the Fork Logical Head after the first Tick's Events.
    #[must_use]
    pub const fn committed_receipt(
        &self,
        first_tick_head: Seq,
    ) -> CounterfactualGenerationReceiptV1 {
        CounterfactualGenerationReceiptV1 {
            generation: self.new_generation(),
            frontier_digest: self.input.frontier.digest(),
            invalidation_digest: self.input.invalidation.digest(),
            first_tick: self.input.first_tick,
            first_tick_head,
        }
    }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualGenerationReceiptV1 {
    generation: ForkGenerationV1,
    frontier_digest: Hash,
    invalidation_digest: Hash,
    first_tick: u64,
    first_tick_head: Seq,
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
pub trait CounterfactualStorePortV1 {
    /// Atomically recheck the expected basis and commit the whole command.
    ///
    /// Inside one serialization point the adapter reads the persisted
    /// [`CounterfactualBasisV1`], returns
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

    /// Return the Fork's committed generation coordinate.
    ///
    /// # Errors
    /// Returns `ForkNotFound`, `CorruptState`, or `StorageFailure`.
    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1>;

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
