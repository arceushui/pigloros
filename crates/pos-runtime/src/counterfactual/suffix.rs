//! ADR-064 endogenous suffix recomputation after the first atomic Tick.
//!
//! [`CounterfactualCoordinatorV1::recompute_suffix`] extends the admission
//! slice: once [`CounterfactualCoordinatorV1::admit`] committed a generation
//! and its first recomputation Tick, this slice recomputes every later
//! endogenous Tick through the plan horizon, in canonical Tick order, under
//! that one generation, and emits one `RCP1` checkpoint per committed Tick and
//! one `CFR1` result per call.
//!
//! One call:
//!
//! 1. validates the CFP1 plan, bounds the suffix to at most
//!    [`MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1`] Ticks, so the `CFR1`
//!    checkpoint list can hold one checkpoint per Tick, and requires a
//!    nonzero `CFR1` result ID and evaluator identity digest, so the result
//!    can be sealed;
//! 2. reads the Fork's persisted basis, proves the receipt's generation is
//!    still the committed generation, and reads the generation's committed
//!    `SIV1`, which must be the receipt's own `SIV1` (its digest, verified
//!    once while decoding, is the receipt's invalidation digest) and must
//!    bind the plan;
//! 3. recovers the committed suffix from the Event Store alone (see
//!    **Recovery** below);
//! 4. commits each remaining Tick through the horizon: it stages the Tick
//!    through the same [`CounterfactualTickStagerV1`] seam and staged inputs
//!    as the first Tick (the plan's exact frozen `ExogenousFrozen` and
//!    `FixedPolicy` descriptors and the Interventions effective at that
//!    Tick), and appends the Tick's Events together with its checkpoint Event
//!    as one batch through
//!    [`CounterfactualStorePortV1::append_counterfactual_tick`];
//! 5. emits every checkpoint of the generation and one sealed `CFR1`.
//!
//! [`CounterfactualCoordinatorV1::recompute_suffix_with_dependencies`] is
//! the same call for a generation admitted with
//! [`CounterfactualCoordinatorV1::admit_with_dependencies`]: each Tick is
//! staged through the [`CounterfactualDeclaringTickStagerV1`] seam, its
//! declaration is validated as the Tick's dependency record before any store
//! call (every declared node strictly after the last committed Tick; see the
//! coordinator module's **Dependency records** decision), and the Tick is
//! appended through
//! [`CounterfactualDependencyRecordingPortV1::append_counterfactual_tick_with_dependencies`],
//! which records it atomically with the Tick's Events. Recovery, the
//! checkpoint chain, and every artifact are those of the plain call: the
//! record is not part of the chained state, so a generation recomputed with
//! dependencies emits exactly the checkpoints and `CFR1` of one recomputed
//! without. A rejected declaration is
//! [`CounterfactualSuffixFailureV1::DependencyDeclarationRejected`], a
//! `PluginFailure` terminal code like every other staging rejection, and a
//! retry re-stages the same Tick from the same inputs.
//!
//! A call on an already complete generation stages and commits nothing, but
//! still compares the receipt's Tick basis with the persisted basis once: a
//! difference is [`CounterfactualSuffixErrorV1::InvalidationConflict`],
//! because the completed generation is stale and its result is not
//! re-emitted.
//!
//! The first failed Tick stops the call. A Tick that fails to stage, is
//! stale, or whose append the store rejects commits nothing, because its
//! only write is the one atomic append, and it is reported as
//! [`CounterfactualSuffixRunV1::failure`] with a `Failed` `CFR1` whose
//! committed range ends at the last committed Tick, so the suffix stays
//! explicitly incomplete. Calling again recovers the same committed state and
//! retries that Tick with the same staged inputs; a retry that succeeds
//! produces the same checkpoints and result as an uninterrupted run.
//!
//! An append whose outcome is unknown (`OutcomeUnknown`) is resolved with
//! the port's recovery read, the persisted basis. When it still equals the
//! Tick basis, the Tick did not commit (a committed Tick always advances the
//! head) and it fails as `AtomicCommitFailed` like a rejected append.
//! Otherwise the head or a fact moved, or the read failed, so the Tick may
//! have committed: the call returns
//! [`CounterfactualSuffixErrorV1::TickOutcomeUnknown`] and seals no `CFR1`.
//! Calling again derives the committed suffix from the Event Store alone.
//! A store that reports a committed head other than the Tick's checkpoint
//! Event is [`CounterfactualSuffixErrorV1::CommittedHeadMismatch`], also
//! without a `CFR1`. Those two errors may follow Ticks this call already
//! committed, which stay committed and are recovered by the next call; every
//! other [`CounterfactualSuffixErrorV1`] is detected before any Tick is
//! staged and commits nothing.
//!
//! # ADR gap decisions
//!
//! - **Generation fence.** Every later Tick is appended with
//!   [`CounterfactualStorePortV1::append_counterfactual_tick`] under
//!   [`CounterfactualGenerationReceiptV1::tick_basis`] of the last committed
//!   head. The store rechecks, inside the append, the generation, the Fork
//!   head, and the published plan, dependency-graph, trust, revocation, and
//!   erasure facts, so a newer generation, an Event appended by any other
//!   writer, or a changed epoch makes the Tick stale
//!   ([`CounterfactualSuffixFailureV1::InvalidationConflict`]) and commits
//!   nothing. This is the ADR's epoch recheck "immediately before commit".
//! - **Admitted and current facts.** The admitted facts are the receipt's
//!   committed facts ([`CounterfactualGenerationReceiptV1::facts`]); the
//!   current ones are the store's persisted basis. No host input is trusted
//!   for either.
//! - **Checkpoint persistence.** The port has no checkpoint store, so each
//!   `RCP1` is persisted as the payload of one coordinator-owned
//!   [`COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1`] Event appended in the same
//!   atomic batch as the Tick's Events, attributed to the Fork's own entity
//!   ID. The shared staging seam rejects a staged draft of that type
//!   ([`CounterfactualSuffixFailureV1::ReservedEventType`]), and the staged
//!   drafts plus the checkpoint Event must fit one
//!   [`PipelineDraftBatchV1`]; otherwise the Tick is
//!   [`CounterfactualSuffixFailureV1::StagedTickRejected`]. The first Tick,
//!   committed by admission, has no checkpoint Event: its range is fixed by
//!   the `SIV1` commit coordinate and the receipt, and its `RCP1` is
//!   re-derived on every call.
//! - **`RCP1` content.** No Plugin or Projection state serialization exists
//!   yet, so both lists are empty. The one state digest, owned by
//!   [`SUFFIX_STATE_OWNER_V1`], chains the `SIV1` digest through every
//!   committed Tick: `blake3("PiglorOS.CounterfactualSuffixState.v1\0" ||
//!   previous || trust_be || revocation_be || erasure_be || tick_be ||
//!   draft_digest)`, over the receipt's committed epochs, where
//!   `draft_digest` is the [`pos_core::pipeline_draft_vector_digest_v1`] of
//!   the Tick's Event drafts with their wall time cleared, because wall time
//!   is presentation-only and store-assigned. `seq` is the Fork `Seq` of the
//!   Tick's last recomputed Event and `scheduler_position` is `0`, the Tick
//!   Boundary. Every Tick reads the whole frozen closure, so the exogenous
//!   cursor stands after the last `ExogenousFrozen` descriptor. The
//!   provenance root is the `SIV1` provenance digest.
//! - **`RCP1` sealing.** `pos-conformance` offers no single-pass seal, so a
//!   new `RCP1` is sealed through its public API: the digest encodes the
//!   unsigned fields once, and the validated canonical encoding encodes them
//!   twice more. Recovery never re-seals a committed `RCP1` it only
//!   decodes, so this cost is paid once per committed Tick, plus once per
//!   call for the re-derived first Tick (see **Recovery**).
//! - **Recovery.** Recovery reads exactly the Fork Events after the `SIV1`
//!   commit coordinate through the persisted head with
//!   [`EventStore::read_bounded`], in pages of at most
//!   [`MAX_PIPELINE_DRAFTS_PER_BATCH`] Events whose payload and Event type
//!   bytes total at most [`MAX_PIPELINE_DRAFT_BATCH_BYTES`], each Event type
//!   at most [`MAX_FORK_EVENT_TYPE_BYTES_V1`] bytes, the bound the shared
//!   staging seam enforces. An honest Tick (at most one batch of Events and
//!   bytes) therefore always fits one read; a page over the byte cap is
//!   halved until it fits, and a single Event over it, like any other failed
//!   read, is `StorageFailure`. A page that is not exactly the requested
//!   range is a [`CounterfactualSuffixErrorV1::RecoveryMismatch`]. The first
//!   Tick is the Events through the receipt's
//!   first-Tick head; every later Tick ends with one checkpoint Event, and
//!   the persisted head must be the last checkpoint Event, so a foreign or
//!   unmarked trailing Event is a mismatch, and so are a recovered later Tick
//!   without a recomputed Event before its checkpoint Event and a recovered
//!   last Tick past the plan horizon. Every committed `RCP1` is decoded and
//!   must be exactly this generation's checkpoint of the next Tick at its
//!   `Seq` (plan, Tick, `Seq`, scheduler position, lists, cursor, and
//!   provenance). The walk buffers the recomputed Events of the Tick it is
//!   inside, across page boundaries: an honest Tick is at most one batch, so
//!   a buffer of more than [`MAX_PIPELINE_DRAFTS_PER_BATCH`] - 1 recomputed
//!   Events (the checkpoint Event takes the last slot) or more than
//!   [`MAX_PIPELINE_DRAFT_BATCH_BYTES`] payload and Event type bytes is a
//!   mismatch. At every checkpoint Event it recomputes the
//!   chained state from the previous verified state, the receipt's epochs,
//!   the Tick number, and the buffered Events, and requires it to equal the
//!   state the committed `RCP1` records, so every Tick's state is verified
//!   in the single walk, with one hash pass per Tick, no extra read, and no
//!   re-sealing. A rewritten, reordered, or dropped Tick therefore breaks
//!   the chain and is a mismatch. The first Tick's `RCP1` is re-derived from
//!   the committed Events (at most one read) and the first later Tick's
//!   chain links it, so that link binds the first Tick's content and the
//!   receipt's first-Tick head. The final chained state, which becomes
//!   the `CFR1` suffix digest, is the verified one, and recovery resumes from
//!   the last checkpoint.
//! - **`CFR1` content.** The first Tick is the receipt's first recomputation
//!   Tick; the suffix digest is the final chained state digest; the
//!   dependency root is the committed `RCF1` frontier digest, which binds the
//!   dependency-graph digest (recording generated edges is deferred); the
//!   provenance root is the `SIV1` provenance digest. A completed result keeps
//!   the plan's replay claim. An incomplete one weakens only the claims CFR1
//!   forbids for an incomplete suffix, `Exact` and
//!   `ExactAuthoritativeWithRedactedViews`, to `StructuralOnly`, the
//!   strongest permitted claim; every other claim is kept unchanged.
//! - **Terminal codes.** A stale Tick basis is `InvalidationConflict`; a
//!   stager failure, an empty, malformed, or oversized staged batch, a
//!   reserved Event type, and a rejected dependency declaration are
//!   `PluginFailure`; an append the store rejects or fails (`ForkNotFound`,
//!   `CorruptState`, `StorageFailure`, or a dependency record the store
//!   rejects, such as a `DuplicateIdentity` across records), or whose
//!   unknown outcome the persisted basis proves uncommitted, is
//!   `AtomicCommitFailed`. The failing coordinate is the first uncommitted
//!   Tick at scheduler position `0`, without a safe digest.
//!
//! # Deferred
//!
//! - **First-Tick Event content.** No committed artifact records the first
//!   Tick's draft digest: neither the receipt nor `SIV1` carries it. Until
//!   the next Tick commits, recovery binds only the first Tick's exact Event
//!   range (the `SIV1` commit coordinate through the receipt's first-Tick
//!   head); an altered first-Tick Event of that range relies on the store's
//!   own atomic commit. Once the next Tick commits, its chained state
//!   binds the first Tick's content, and every call then verifies it.
//! - **Keyed integrity.** The chained state is an unkeyed public digest, so
//!   recovery detects inconsistent edits, corruption, and buggy adapters, not
//!   forgery: an adversary who can rewrite Events and the checkpoint payloads
//!   that chain over them (or a writer that bypasses the coordinator and
//!   appends a whole well-formed Tick at the head between calls) is not
//!   distinguished from a committed Tick. Keyed or signed checkpoints are not
//!   part of this slice. Intermediate Ticks are verified on every call by the
//!   recovery walk, but only against the chain, never against an independent
//!   record of what each Tick staged.

use pos_conformance::counterfactual::checkpoint::{
    CheckpointDigestEntryV1, ExogenousCursorV1, RecomputeCheckpointV1,
};
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1,
};
use pos_conformance::counterfactual::result::{
    CounterfactualCheckpointRefV1, CounterfactualResultV1, CounterfactualTerminalErrorCodeV1,
    CounterfactualTerminalErrorV1, CounterfactualTerminalStateV1,
    MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1,
};
use pos_conformance::{ReplayClaimV1, SuffixInvalidationV1};
use pos_core::{
    pipeline_draft_vector_digest_v1, CanonicalBytes, CoreError, CounterfactualBasisV1,
    CounterfactualDependencyErrorV1, CounterfactualDependencyRecordingPortV1,
    CounterfactualFactsV1, CounterfactualGenerationReceiptV1, CounterfactualStoreErrorV1,
    CounterfactualStorePortV1, CounterfactualTickOutcomeV1, EntityId, Event, EventDraft,
    EventReadBounds, EventStore, FactualPrefixReadPortV1, Hash, InvalidationConflictV1, Kind,
    PipelineContractErrorV1, PipelineDraftBatchV1, Seq, SeqRange, TimelineId,
    MAX_FORK_EVENT_TYPE_BYTES_V1, MAX_PIPELINE_DRAFTS_PER_BATCH, MAX_PIPELINE_DRAFT_BATCH_BYTES,
};

use super::coordinator::{
    CounterfactualAdmissionErrorV1, CounterfactualCoordinatorV1,
    CounterfactualDeclaringTickStagerV1, CounterfactualTickStagerV1, PlainSeamV1, RecordingSeamV1,
    TickSeamV1, COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1,
};

/// `RCP1` owner of the chained suffix state digest.
pub const SUFFIX_STATE_OWNER_V1: &str = "counterfactual.suffix";

/// The largest Tick span after the first recomputation Tick: one checkpoint
/// per Tick must fit [`MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1`].
const MAX_SUFFIX_TICK_SPAN: u64 = MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1 as u64 - 1;
const SUFFIX_STATE_DOMAIN: &[u8] = b"PiglorOS.CounterfactualSuffixState.v1\0";
/// Events per recovery read: one Tick batch, so a Tick never needs two.
const PAGE_EVENTS: u64 = MAX_PIPELINE_DRAFTS_PER_BATCH as u64;
/// Total payload and Event type bytes of one recovery read: one Tick batch,
/// whose content bytes already count every payload and Event type, so one
/// honest Tick always fits one read.
const PAGE_TOTAL_BYTES: usize = MAX_PIPELINE_DRAFT_BATCH_BYTES;
/// Bounds of one recovery read: one page of Events within one batch's bytes,
/// each Event type within the bound the staging seam enforces.
///
/// The payload cap equals the total cap on purpose: one honest draft may
/// carry nearly all of its batch's bytes, so no single payload needs a
/// tighter cap than the whole page.
const PAGE_BOUNDS: EventReadBounds = EventReadBounds::new_with_total_bytes(
    MAX_PIPELINE_DRAFT_BATCH_BYTES,
    MAX_FORK_EVENT_TYPE_BYTES_V1,
    usize::MAX,
    MAX_PIPELINE_DRAFTS_PER_BATCH,
    PAGE_TOTAL_BYTES,
);
/// A failed Event Store read; the store reports nothing more specific.
const STORAGE_FAILURE: CounterfactualSuffixErrorV1 =
    CounterfactualSuffixErrorV1::Store(CounterfactualStoreErrorV1::StorageFailure);

/// Why one recomputation Tick failed; nothing of it was committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualSuffixFailureV1 {
    /// A persisted fact differs from the generation's Tick basis: a newer
    /// generation, a moved Fork head, or a changed published fact.
    InvalidationConflict(InvalidationConflictV1),
    /// The stager failed to stage the Tick.
    PluginFailure,
    /// The staged drafts, with the checkpoint Event, are empty, malformed, or
    /// oversized.
    StagedTickRejected(PipelineContractErrorV1),
    /// A staged draft uses the coordinator-owned checkpoint Event type.
    ReservedEventType,
    /// The staged dependency declaration is not a valid provisional record
    /// of the Tick, or a declared node lies at or before the last committed
    /// Tick (`BindingMismatch`); see
    /// [`CounterfactualAdmissionErrorV1::DependencyDeclarationRejected`].
    DependencyDeclarationRejected(CounterfactualDependencyErrorV1),
    /// The Event Store rejected or failed the Tick's atomic append.
    AtomicCommitFailed,
}

impl CounterfactualSuffixFailureV1 {
    /// Return the closed `CFR1` terminal error code of this failure.
    #[must_use]
    pub const fn code(self) -> CounterfactualTerminalErrorCodeV1 {
        match self {
            Self::InvalidationConflict(_) => {
                CounterfactualTerminalErrorCodeV1::InvalidationConflict
            }
            Self::PluginFailure
            | Self::StagedTickRejected(_)
            | Self::ReservedEventType
            | Self::DependencyDeclarationRejected(_) => {
                CounterfactualTerminalErrorCodeV1::PluginFailure
            }
            Self::AtomicCommitFailed => CounterfactualTerminalErrorCodeV1::AtomicCommitFailed,
        }
    }
}

/// Closed safe errors of one suffix recomputation call.
///
/// Every error except [`Self::TickOutcomeUnknown`] and
/// [`Self::CommittedHeadMismatch`] is detected before any Tick is staged and
/// commits nothing; those two may follow Ticks the call already committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CounterfactualSuffixErrorV1 {
    /// The CFP1 plan is invalid.
    #[error("counterfactual plan is invalid")]
    Plan(#[source] CounterfactualPlanContractErrorV1),
    /// The suffix has more Ticks than one result can checkpoint.
    #[error("counterfactual suffix exceeds the checkpoint bound")]
    SuffixTooLong,
    /// The `CFR1` result ID or evaluator identity digest is zero.
    #[error("counterfactual result identity is invalid")]
    InvalidResultIdentity,
    /// The committed generation's `SIV1` does not bind the plan.
    #[error("counterfactual suffix does not belong to the plan")]
    PlanMismatch,
    /// The Fork's cut is mid-Tick, or the plan's parent cut Tick is not the
    /// cut Tick derived from the parent's recorded prefix.
    #[error("counterfactual parent cut was not found")]
    ParentCutNotFound,
    /// The committed invalidation or suffix Events do not match the receipt.
    #[error("counterfactual suffix does not match the committed generation")]
    RecoveryMismatch,
    /// A persisted fact differs from an already complete generation's Tick
    /// basis; the generation is stale.
    #[error("counterfactual generation is stale")]
    InvalidationConflict(InvalidationConflictV1),
    /// An `RCP1` or `CFR1` artifact could not be sealed.
    ///
    /// Every input of both is validated before the first Tick is staged (the
    /// plan, the committed `SIV1`, and the result identity), and the first
    /// Tick's `RCP1` is sealed during recovery, so sealing is not expected to
    /// fail once a Tick is staged. Were it to, Ticks this call already
    /// committed would stay committed and the next call would recover them.
    #[error("counterfactual suffix artifact could not be encoded")]
    ArtifactEncoding,
    /// The counterfactual store rejected or failed a read.
    #[error("counterfactual store operation failed")]
    Store(#[source] CounterfactualStoreErrorV1),
    /// A Tick append's outcome is unknown and the persisted basis no longer
    /// proves it uncommitted: the Tick may have committed. No `CFR1` is
    /// sealed; call `recompute_suffix` again, whose recovery derives the
    /// committed suffix from the Event Store.
    #[error("counterfactual Tick outcome is unknown")]
    TickOutcomeUnknown,
    /// The store reported a committed head other than the appended Tick's
    /// checkpoint Event, violating the port contract. No `CFR1` is sealed.
    #[error("counterfactual store reported another committed head")]
    CommittedHeadMismatch,
}

/// One suffix recomputation request for a committed generation.
#[derive(Clone, Copy)]
pub struct CounterfactualSuffixRequestV1<'a> {
    /// The admitted CFP1 plan.
    pub plan: &'a CounterfactualPlanV1,
    /// The receipt of the admitted generation and its first Tick.
    pub receipt: CounterfactualGenerationReceiptV1,
    /// `CFR1` result ID of this call.
    pub result_id: [u8; 16],
    /// `CFR1` evaluator identity digest.
    pub evaluator_identity_digest: [u8; 32],
}

/// The artifacts one suffix recomputation call emits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualSuffixRunV1 {
    /// Canonical `RCP1` bytes of every committed Tick of the generation, in
    /// Tick order.
    pub checkpoints: Vec<Vec<u8>>,
    /// Canonical `CFR1` bytes: `Completed` through the horizon, otherwise
    /// `Failed` at the first uncommitted Tick.
    pub result: Vec<u8>,
    /// The Tick failure that left the suffix incomplete, if any.
    pub failure: Option<CounterfactualSuffixFailureV1>,
}

/// The facts every Tick of one call is bound to.
struct SuffixContextV1<'a> {
    plan: &'a CounterfactualPlanV1,
    receipt: CounterfactualGenerationReceiptV1,
    provenance: [u8; 32],
    result_id: [u8; 16],
    evaluator_identity_digest: [u8; 32],
}

impl SuffixContextV1<'_> {
    const fn fork(&self) -> TimelineId {
        self.receipt.generation().fork
    }
}

/// The committed suffix through its last committed Tick.
struct ProgressV1 {
    generation: u64,
    tick: u64,
    head: u64,
    state: [u8; 32],
    checkpoints: Vec<Vec<u8>>,
    refs: Vec<CounterfactualCheckpointRefV1>,
}

impl ProgressV1 {
    /// Record one committed Tick ending at Fork `Seq` `head`.
    fn advance(&mut self, tick: u64, head: u64, checkpoint: CheckpointV1) {
        self.tick = tick;
        self.head = head;
        self.state = checkpoint.state;
        self.refs.push(CounterfactualCheckpointRefV1 {
            tick,
            fork_generation: self.generation,
            checkpoint_digest: checkpoint.digest,
        });
        self.checkpoints.push(checkpoint.bytes);
    }
}

/// One sealed `RCP1` with the chained state it records.
struct CheckpointV1 {
    state: [u8; 32],
    bytes: Vec<u8>,
    digest: [u8; 32],
}

/// The recomputed Events of the Tick a recovery walk is inside, carried across
/// page boundaries until the Tick's checkpoint Event.
#[derive(Default)]
struct TickEventsV1 {
    drafts: Vec<EventDraft>,
    bytes: usize,
}

impl TickEventsV1 {
    /// Buffer one committed Event and report whether the Tick now exceeds one
    /// batch.
    ///
    /// Returns `true` once the buffer is at the count bound or over the byte
    /// bound, so the Tick cannot be an honest single batch.
    ///
    /// That bounds the memory a walk can use. An honest Tick stages at most
    /// one batch, whose last draft is its checkpoint Event, so it buffers
    /// fewer than [`MAX_PIPELINE_DRAFTS_PER_BATCH`] Events and at most
    /// [`MAX_PIPELINE_DRAFT_BATCH_BYTES`] payload and Event type bytes.
    fn exceeds_batch_after_push(&mut self, event: Event) -> bool {
        self.bytes = self
            .bytes
            .saturating_add(event.payload.len())
            .saturating_add(event.event_type.as_str().len());
        self.drafts.push(committed_draft(event));
        self.drafts.len() >= MAX_PIPELINE_DRAFTS_PER_BATCH
            || self.bytes > MAX_PIPELINE_DRAFT_BATCH_BYTES
    }

    /// Hand out the buffered drafts and start the next Tick empty.
    fn take(&mut self) -> Vec<EventDraft> {
        self.bytes = 0;
        std::mem::take(&mut self.drafts)
    }
}

/// One Tick step: a closed failure that committed nothing, or a closed error.
type TickStepV1 = Result<Option<CounterfactualSuffixFailureV1>, CounterfactualSuffixErrorV1>;

impl<S: EventStore + CounterfactualStorePortV1> CounterfactualCoordinatorV1<S> {
    /// Release the exclusively owned store, so a test can change it and hand
    /// it to a new coordinator.
    ///
    /// Available only with the `test-support` feature: deployable builds
    /// never hand the host-only port capability out of the coordinator.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Recover the committed suffix of `request`'s generation and commit every
    /// remaining Tick through the plan horizon.
    ///
    /// See the module documentation for the recovery, commit, and artifact
    /// rules. A failed Tick is reported in the returned run, not as an error.
    ///
    /// # Errors
    /// Returns the first closed safe error. Every error except
    /// [`CounterfactualSuffixErrorV1::TickOutcomeUnknown`] and
    /// [`CounterfactualSuffixErrorV1::CommittedHeadMismatch`] is detected
    /// before any Tick is staged and commits nothing; after those two, call
    /// again to recover what committed. On an already complete generation, a
    /// persisted fact that differs from the generation's Tick basis is
    /// [`CounterfactualSuffixErrorV1::InvalidationConflict`].
    pub fn recompute_suffix(
        &mut self,
        request: &CounterfactualSuffixRequestV1<'_>,
        stager: &mut impl CounterfactualTickStagerV1,
    ) -> Result<CounterfactualSuffixRunV1, CounterfactualSuffixErrorV1> {
        self.recompute_suffix_through(request, &mut PlainSeamV1(stager))
    }

    /// Recover the committed suffix of `request`'s generation and commit every
    /// remaining Tick through the plan horizon, each with its declared
    /// dependency record.
    ///
    /// This is [`Self::recompute_suffix`] with the staged declarations; see
    /// the module documentation.
    ///
    /// # Errors
    /// Those of [`Self::recompute_suffix`]: a rejected declaration is a Tick
    /// failure reported in the returned run, not an error. A mid-Tick cut or
    /// a `parent_cut_tick` that is not the parent's recorded cut Tick is
    /// [`CounterfactualSuffixErrorV1::ParentCutNotFound`], before any Tick is
    /// staged.
    pub fn recompute_suffix_with_dependencies(
        &mut self,
        request: &CounterfactualSuffixRequestV1<'_>,
        stager: &mut impl CounterfactualDeclaringTickStagerV1,
    ) -> Result<CounterfactualSuffixRunV1, CounterfactualSuffixErrorV1>
    where
        S: CounterfactualDependencyRecordingPortV1 + FactualPrefixReadPortV1,
    {
        self.recompute_suffix_through(request, &mut RecordingSeamV1(stager))
    }

    /// The one suffix body: recover, then stage and append every remaining
    /// Tick through `seam`.
    fn recompute_suffix_through<M: TickSeamV1<S>>(
        &mut self,
        request: &CounterfactualSuffixRequestV1<'_>,
        seam: &mut M,
    ) -> Result<CounterfactualSuffixRunV1, CounterfactualSuffixErrorV1> {
        let plan = request.plan;
        plan.validate().map_err(CounterfactualSuffixErrorV1::Plan)?;
        if plan
            .horizon_tick
            .saturating_sub(request.receipt.first_tick())
            > MAX_SUFFIX_TICK_SPAN
        {
            return Err(CounterfactualSuffixErrorV1::SuffixTooLong);
        }
        if request.result_id == [0; 16] || request.evaluator_identity_digest == [0; 32] {
            return Err(CounterfactualSuffixErrorV1::InvalidResultIdentity);
        }
        let (basis, invalidation) = self.checked_invalidation::<M>(request)?;
        let context = SuffixContextV1 {
            plan,
            receipt: request.receipt,
            provenance: invalidation.provenance_digest,
            result_id: request.result_id,
            evaluator_identity_digest: request.evaluator_identity_digest,
        };
        let head = basis.fork_logical_head;
        let mut progress = self.recover(&context, invalidation.commit_seq, head.as_u64())?;
        if progress.tick > plan.horizon_tick {
            return Err(CounterfactualSuffixErrorV1::RecoveryMismatch);
        }
        if progress.tick >= plan.horizon_tick {
            if let Some(conflict) = context.receipt.tick_basis(head).first_conflict(&basis) {
                return Err(CounterfactualSuffixErrorV1::InvalidationConflict(conflict));
            }
        }
        let failure = loop {
            if progress.tick >= plan.horizon_tick {
                break Ok(None);
            }
            match self.commit_tick(&context, &mut progress, seam) {
                Ok(None) => {}
                stopped => break stopped,
            }
        };
        failure.and_then(|failure| finish(&context, progress, failure))
    }

    /// [`Self::committed_invalidation`], then the parent cut check of `M`;
    /// nothing is staged first.
    fn checked_invalidation<M: TickSeamV1<S>>(
        &self,
        request: &CounterfactualSuffixRequestV1<'_>,
    ) -> Result<(CounterfactualBasisV1, SuffixInvalidationV1), CounterfactualSuffixErrorV1> {
        let committed = self.committed_invalidation(request)?;
        M::check_parent_cut(&self.store, request.plan)
            .map_err(|error| parent_cut_error(&error))?;
        Ok(committed)
    }

    /// Read the persisted basis, prove the receipt's generation is the
    /// committed one, and read and bind its `SIV1`.
    fn committed_invalidation(
        &self,
        request: &CounterfactualSuffixRequestV1<'_>,
    ) -> Result<(CounterfactualBasisV1, SuffixInvalidationV1), CounterfactualSuffixErrorV1> {
        let receipt = request.receipt;
        let generation = receipt.generation();
        let basis = self
            .store
            .current_counterfactual_basis(generation.fork)
            .map_err(CounterfactualSuffixErrorV1::Store)?;
        if basis.generation != generation.generation {
            return Err(CounterfactualSuffixErrorV1::Store(
                CounterfactualStoreErrorV1::MixedForkGeneration,
            ));
        }
        let invalidation = self
            .store
            .read_generation_artifact(generation, receipt.invalidation_digest())
            .map_err(CounterfactualSuffixErrorV1::Store)?
            .and_then(|bytes| SuffixInvalidationV1::from_canonical_cbor(&bytes).ok())
            .filter(|invalidation| {
                Hash::from_bytes(invalidation.invalidation_digest) == receipt.invalidation_digest()
            })
            .ok_or(CounterfactualSuffixErrorV1::RecoveryMismatch)?;
        if invalidation.plan_digest == request.plan.plan_digest {
            Ok((basis, invalidation))
        } else {
            Err(CounterfactualSuffixErrorV1::PlanMismatch)
        }
    }

    /// Rebuild the committed suffix from the Fork Events after `commit_seq`
    /// through the persisted `head`.
    fn recover(
        &self,
        context: &SuffixContextV1<'_>,
        commit_seq: u64,
        head: u64,
    ) -> Result<ProgressV1, CounterfactualSuffixErrorV1> {
        let first_tick = context.receipt.first_tick();
        let first_head = context.receipt.first_tick_head().as_u64();
        let mut progress = ProgressV1 {
            generation: context.receipt.generation().generation,
            tick: first_tick,
            head: commit_seq,
            state: *context.receipt.invalidation_digest().as_bytes(),
            checkpoints: Vec::new(),
            refs: Vec::new(),
        };
        let first = self.first_checkpoint(context, &progress)?;
        progress.advance(first_tick, first_head, first);
        let mut next = first_head.saturating_add(1);
        let mut tick_events = TickEventsV1::default();
        while next <= head {
            let to = head.min(next.saturating_add(PAGE_EVENTS - 1));
            let page = self.read_page(context.fork(), next, to)?;
            let count = page.len() as u64;
            for (seq, event) in (next..).zip(page) {
                if event.event_type.as_str() == COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1 {
                    let tick = progress.tick.saturating_add(1);
                    let drafts = tick_events.take();
                    let payload = event.payload.as_slice();
                    let checkpoint =
                        verified_checkpoint(context, &progress, tick, seq, payload, &drafts)?;
                    progress.advance(tick, seq, checkpoint);
                } else if tick_events.exceeds_batch_after_push(event) {
                    // No honest Tick has more Events or bytes than one batch.
                    return Err(CounterfactualSuffixErrorV1::RecoveryMismatch);
                }
            }
            next = next.saturating_add(count);
        }
        // Every Event after the first Tick belongs to a checkpointed Tick.
        if progress.head == head {
            Ok(progress)
        } else {
            Err(CounterfactualSuffixErrorV1::RecoveryMismatch)
        }
    }

    /// Read exactly the non-empty Fork range `from..=to` in one read.
    ///
    /// A shorter or longer answer, and an empty range (`to < from`), are a
    /// mismatch: every Tick commits at least one Event.
    fn read_exact(
        &self,
        fork: TimelineId,
        from: u64,
        to: u64,
    ) -> Result<Vec<Event>, CounterfactualSuffixErrorV1> {
        exact_page(
            self.store
                .read_bounded(fork, page_range(from, to), PAGE_BOUNDS),
            from,
            to,
        )
    }

    /// Read exactly a non-empty prefix of the Fork range `from..=to`.
    ///
    /// A read over [`PAGE_TOTAL_BYTES`] is halved until it fits; a single
    /// Event over it is a failed read.
    fn read_page(
        &self,
        fork: TimelineId,
        from: u64,
        mut to: u64,
    ) -> Result<Vec<Event>, CounterfactualSuffixErrorV1> {
        loop {
            match self
                .store
                .read_bounded(fork, page_range(from, to), PAGE_BOUNDS)
            {
                Err(CoreError::ReadBytesTooLarge { .. }) if to > from => {
                    to = from + (to - from) / 2;
                }
                read => return exact_page(read, from, to),
            }
        }
    }

    /// Re-derive the first Tick's `RCP1`, whose committed Events follow
    /// `previous` through the receipt's first-Tick head.
    fn first_checkpoint(
        &self,
        context: &SuffixContextV1<'_>,
        previous: &ProgressV1,
    ) -> Result<CheckpointV1, CounterfactualSuffixErrorV1> {
        let from = previous.head.saturating_add(1);
        let last_seq = context.receipt.first_tick_head().as_u64();
        let drafts: Vec<EventDraft> = self
            .read_exact(context.fork(), from, last_seq)?
            .into_iter()
            .map(committed_draft)
            .collect();
        let tick = context.receipt.first_tick();
        next_checkpoint(context, previous.state, tick, &drafts, last_seq)
    }

    /// Stage, checkpoint, and atomically commit the next Tick under the
    /// generation's Tick basis.
    ///
    /// The seam stages the Tick after the last committed one, so a declared
    /// node must lie strictly after `progress.tick`. Returns the failure of a
    /// Tick that committed nothing; see [`Self::append_tick`] for the errors.
    fn commit_tick<M: TickSeamV1<S>>(
        &mut self,
        context: &SuffixContextV1<'_>,
        progress: &mut ProgressV1,
        seam: &mut M,
    ) -> TickStepV1 {
        let tick = progress.tick.saturating_add(1);
        let generation = context.receipt.generation();
        let (batch, record) = match seam.stage(context.plan, generation, tick, progress.tick) {
            Ok(staged) => staged,
            Err(error) => return Ok(Some(staging_failure(&error))),
        };
        let drafts = batch.drafts();
        let bodies: Vec<EventDraft> = drafts.iter().map(content_draft).collect();
        let seq = progress.head.saturating_add(drafts.len() as u64);
        // Sealing a well-formed `RCP1` does not fail; an error flows out as is.
        next_checkpoint(context, progress.state, tick, &bodies, seq).and_then(|checkpoint| {
            self.append_tick::<M>(context, progress, tick, drafts, checkpoint, &record)
        })
    }

    /// Append the staged `drafts` and the Tick's checkpoint Event as one
    /// batch under the generation's Tick basis, with the seam's `record`.
    ///
    /// Returns the failure of a Tick that committed nothing.
    ///
    /// # Errors
    /// Returns `TickOutcomeUnknown` when the append's outcome is unknown and
    /// the persisted basis does not prove it uncommitted, and
    /// `CommittedHeadMismatch` when the store reports a committed head other
    /// than the checkpoint Event's `Seq`; neither advances the progress.
    fn append_tick<M: TickSeamV1<S>>(
        &mut self,
        context: &SuffixContextV1<'_>,
        progress: &mut ProgressV1,
        tick: u64,
        drafts: &[EventDraft],
        checkpoint: CheckpointV1,
        record: &M::Record,
    ) -> TickStepV1 {
        let mut tick_drafts = drafts.to_vec();
        tick_drafts.push(checkpoint_draft(context.fork(), &checkpoint.bytes));
        let batch = match PipelineDraftBatchV1::try_new(tick_drafts) {
            Ok(batch) => batch,
            Err(rejection) => {
                return Ok(Some(CounterfactualSuffixFailureV1::StagedTickRejected(
                    rejection,
                )))
            }
        };
        let expected = context.receipt.tick_basis(Seq::from_u64(progress.head));
        // The checkpoint Event is the batch's last Event.
        let checkpoint_seq = progress.head.saturating_add(batch.drafts().len() as u64);
        match M::append_tick(&mut self.store, context.fork(), &expected, &batch, record) {
            Ok(CounterfactualTickOutcomeV1::Committed { head })
                if head.as_u64() == checkpoint_seq =>
            {
                progress.advance(tick, checkpoint_seq, checkpoint);
                Ok(None)
            }
            Ok(CounterfactualTickOutcomeV1::Committed { .. }) => {
                Err(CounterfactualSuffixErrorV1::CommittedHeadMismatch)
            }
            Ok(CounterfactualTickOutcomeV1::Stale(conflict)) => Ok(Some(
                CounterfactualSuffixFailureV1::InvalidationConflict(conflict),
            )),
            Err(CounterfactualStoreErrorV1::OutcomeUnknown) => {
                self.unknown_tick_outcome(context.fork(), &expected)
            }
            Err(_) => Ok(Some(CounterfactualSuffixFailureV1::AtomicCommitFailed)),
        }
    }

    /// Resolve an append whose outcome is unknown with the persisted basis:
    /// an unchanged basis proves the Tick did not commit, because a committed
    /// Tick always advances the head; anything else leaves it unknown.
    fn unknown_tick_outcome(
        &self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
    ) -> TickStepV1 {
        match self.store.current_counterfactual_basis(fork) {
            Ok(persisted) if expected.first_conflict(&persisted).is_none() => {
                Ok(Some(CounterfactualSuffixFailureV1::AtomicCommitFailed))
            }
            _ => Err(CounterfactualSuffixErrorV1::TickOutcomeUnknown),
        }
    }
}

/// Map a parent cut check error: a failed read is the store's, any other
/// error is the rejected cut.
const fn parent_cut_error(error: &CounterfactualAdmissionErrorV1) -> CounterfactualSuffixErrorV1 {
    match error {
        CounterfactualAdmissionErrorV1::Store(store) => CounterfactualSuffixErrorV1::Store(*store),
        _ => CounterfactualSuffixErrorV1::ParentCutNotFound,
    }
}

/// Map a staging error of the shared stager seam to its Tick failure.
///
/// The seam returns only `PluginFailure`, `StagedTickRejected`,
/// `ReservedEventType`, and `DependencyDeclarationRejected`;
/// [`declaration_failure`] tells the last from `PluginFailure`.
const fn staging_failure(error: &CounterfactualAdmissionErrorV1) -> CounterfactualSuffixFailureV1 {
    match error {
        CounterfactualAdmissionErrorV1::StagedTickRejected(rejection) => {
            CounterfactualSuffixFailureV1::StagedTickRejected(*rejection)
        }
        CounterfactualAdmissionErrorV1::ReservedEventType => {
            CounterfactualSuffixFailureV1::ReservedEventType
        }
        other => declaration_failure(other),
    }
}

/// Map a rejected declaration to its Tick failure, and any other staging
/// error (the stager's own `PluginFailure`) to `PluginFailure`.
const fn declaration_failure(
    error: &CounterfactualAdmissionErrorV1,
) -> CounterfactualSuffixFailureV1 {
    match error {
        CounterfactualAdmissionErrorV1::DependencyDeclarationRejected(rejection) => {
            CounterfactualSuffixFailureV1::DependencyDeclarationRejected(*rejection)
        }
        _ => CounterfactualSuffixFailureV1::PluginFailure,
    }
}

/// The Fork range `from..=to`.
const fn page_range(from: u64, to: u64) -> SeqRange {
    SeqRange::bounded(Seq::from_u64(from), Seq::from_u64(to))
}

/// Require a read of `from..=to` to have succeeded with exactly its Events.
fn exact_page(
    read: Result<Vec<Event>, CoreError>,
    from: u64,
    to: u64,
) -> Result<Vec<Event>, CounterfactualSuffixErrorV1> {
    let events = read.or(Err(STORAGE_FAILURE))?;
    if events.len() as u64 == to.saturating_sub(from).saturating_add(1) {
        Ok(events)
    } else {
        Err(CounterfactualSuffixErrorV1::RecoveryMismatch)
    }
}

/// The coordinator-owned Event carrying one Tick's `RCP1` bytes.
fn checkpoint_draft(fork: TimelineId, checkpoint: &[u8]) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(fork.inner()),
        Kind::new(COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1),
        CanonicalBytes::from_vec(checkpoint.to_vec()),
    )
}

/// The content of one staged draft, without its wall time.
fn content_draft(draft: &EventDraft) -> EventDraft {
    EventDraft {
        wall_time: None,
        ..draft.clone()
    }
}

/// The draft content of one committed Event, without its wall time.
fn committed_draft(event: Event) -> EventDraft {
    EventDraft {
        entity: event.entity,
        event_type: event.event_type,
        payload: event.payload,
        causation_id: event.causation_id,
        correlation_id: event.correlation_id,
        schema_version: event.schema_version,
        wall_time: None,
    }
}

/// Chain one Tick's draft digest onto the previous suffix state under the
/// receipt's committed epochs; every draft already has its wall time cleared.
fn chain_state(
    previous: &[u8; 32],
    facts: &CounterfactualFactsV1,
    tick: u64,
    drafts: &[EventDraft],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SUFFIX_STATE_DOMAIN);
    hasher.update(previous);
    hasher.update(&facts.trust_epoch.to_be_bytes());
    hasher.update(&facts.revocation_epoch.to_be_bytes());
    hasher.update(&facts.erasure_epoch.to_be_bytes());
    hasher.update(&tick.to_be_bytes());
    hasher.update(pipeline_draft_vector_digest_v1(drafts).as_bytes());
    *hasher.finalize().as_bytes()
}

/// The unsealed `RCP1` of `tick` with chained `state`, whose last
/// recomputed Event is `seq`.
fn unsealed_checkpoint(
    context: &SuffixContextV1<'_>,
    tick: u64,
    seq: u64,
    state: [u8; 32],
) -> RecomputeCheckpointV1 {
    let plan = context.plan;
    RecomputeCheckpointV1 {
        plan_digest: plan.plan_digest,
        tick,
        seq,
        scheduler_position: 0,
        plugin_state_digests: Vec::new(),
        projection_digests: Vec::new(),
        state_digests: vec![CheckpointDigestEntryV1 {
            owner_id: SUFFIX_STATE_OWNER_V1.to_owned(),
            digest: state,
        }],
        exogenous_cursor: ExogenousCursorV1 {
            consumed_descriptors: plan.exogenous_descriptors.len() as u64,
            last_descriptor_digest: plan
                .exogenous_descriptors
                .last()
                .map(|descriptor| descriptor.artifact_digest),
        },
        provenance_root: context.provenance,
        checkpoint_digest: [0; 32],
    }
}

/// Build and seal the `RCP1` of `tick`, whose last recomputed Event is `seq`.
fn next_checkpoint(
    context: &SuffixContextV1<'_>,
    previous: [u8; 32],
    tick: u64,
    drafts: &[EventDraft],
    seq: u64,
) -> Result<CheckpointV1, CounterfactualSuffixErrorV1> {
    let state = chain_state(&previous, &context.receipt.facts(), tick, drafts);
    let unsigned = unsealed_checkpoint(context, tick, seq, state);
    unsigned
        .digest()
        .and_then(|digest| {
            RecomputeCheckpointV1 {
                checkpoint_digest: digest,
                ..unsigned
            }
            .to_canonical_cbor()
            .map(|bytes| CheckpointV1 {
                state,
                bytes,
                digest,
            })
        })
        .or(Err(CounterfactualSuffixErrorV1::ArtifactEncoding))
}

/// Decode one committed `RCP1` and require it to be exactly this
/// generation's checkpoint of `tick` at `seq`, with its own chained state.
fn committed_checkpoint(
    context: &SuffixContextV1<'_>,
    tick: u64,
    seq: u64,
    payload: &[u8],
) -> Result<CheckpointV1, CounterfactualSuffixErrorV1> {
    RecomputeCheckpointV1::from_canonical_cbor(payload)
        .ok()
        .and_then(|decoded| {
            decoded
                .state_digests
                .first()
                .map(|entry| entry.digest)
                .and_then(|state| {
                    let expected = RecomputeCheckpointV1 {
                        checkpoint_digest: decoded.checkpoint_digest,
                        ..unsealed_checkpoint(context, tick, seq, state)
                    };
                    (decoded == expected).then(|| CheckpointV1 {
                        state,
                        bytes: payload.to_vec(),
                        digest: decoded.checkpoint_digest,
                    })
                })
        })
        .ok_or(CounterfactualSuffixErrorV1::RecoveryMismatch)
}

/// Verify the committed `RCP1` of the Tick ending with checkpoint Event `seq`.
///
/// It must be exactly this generation's checkpoint, and its chained state must
/// follow from the Tick's recomputed `drafts` and the verified state of the
/// Tick before it. A Tick without a recomputed Event is rejected, because
/// every Tick commits at least one.
fn verified_checkpoint(
    context: &SuffixContextV1<'_>,
    previous: &ProgressV1,
    tick: u64,
    seq: u64,
    payload: &[u8],
    drafts: &[EventDraft],
) -> Result<CheckpointV1, CounterfactualSuffixErrorV1> {
    if drafts.is_empty() {
        return Err(CounterfactualSuffixErrorV1::RecoveryMismatch);
    }
    let last = seq.saturating_sub(1);
    committed_checkpoint(context, tick, last, payload).and_then(|checkpoint| {
        let state = chain_state(&previous.state, &context.receipt.facts(), tick, drafts);
        if checkpoint.state == state {
            Ok(checkpoint)
        } else {
            Err(CounterfactualSuffixErrorV1::RecoveryMismatch)
        }
    })
}

/// The strongest claim CFR1 permits for an incomplete suffix: only an exact
/// claim is weakened, to `StructuralOnly`; every other claim is kept.
const fn incomplete_claim(claim: ReplayClaimV1) -> ReplayClaimV1 {
    match claim {
        ReplayClaimV1::Exact | ReplayClaimV1::ExactAuthoritativeWithRedactedViews => {
            ReplayClaimV1::StructuralOnly
        }
        ReplayClaimV1::StructuralOnly
        | ReplayClaimV1::UnverifiableArtifactsMissing
        | ReplayClaimV1::IncompatibleProfile => claim,
    }
}

/// Seal the `CFR1` of this call and emit it with every checkpoint.
fn finish(
    context: &SuffixContextV1<'_>,
    progress: ProgressV1,
    failure: Option<CounterfactualSuffixFailureV1>,
) -> Result<CounterfactualSuffixRunV1, CounterfactualSuffixErrorV1> {
    let plan = context.plan;
    let receipt = context.receipt;
    let (terminal_state, terminal_error, replay_claim) = failure.map_or(
        (
            CounterfactualTerminalStateV1::Completed,
            None,
            plan.replay_claim,
        ),
        |failure| {
            (
                CounterfactualTerminalStateV1::Failed,
                Some(CounterfactualTerminalErrorV1 {
                    code: failure.code(),
                    tick: progress.tick.saturating_add(1),
                    scheduler_position: 0,
                    safe_digest: None,
                }),
                incomplete_claim(plan.replay_claim),
            )
        },
    );
    let unsigned = CounterfactualResultV1 {
        result_id: context.result_id,
        plan_digest: plan.plan_digest,
        fork_id: context.fork().inner().to_bytes(),
        fork_generation: progress.generation,
        first_tick: receipt.first_tick(),
        horizon_tick: plan.horizon_tick,
        committed_through_tick: Some(progress.tick),
        checkpoints: progress.refs,
        terminal_state,
        terminal_error,
        suffix_digest: progress.state,
        dependency_root: *receipt.frontier_digest().as_bytes(),
        provenance_root: context.provenance,
        replay_claim,
        execution_profile_digest: plan.execution_profile.profile_digest,
        trust_policy_snapshot_digest: plan.trust_policy.snapshot_digest,
        evaluator_identity_digest: context.evaluator_identity_digest,
        result_digest: [0; 32],
    };
    unsigned
        .digest()
        .and_then(|result_digest| {
            CounterfactualResultV1 {
                result_digest,
                ..unsigned
            }
            .to_canonical_cbor()
        })
        .map(|result| CounterfactualSuffixRunV1 {
            checkpoints: progress.checkpoints,
            result,
            failure,
        })
        .or(Err(CounterfactualSuffixErrorV1::ArtifactEncoding))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{EventId, SchemaVersion, WallTime};

    use super::*;

    /// One committed Event of type `x` whose payload is `payload_len` bytes.
    fn event_of(payload_len: usize) -> Event {
        Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("x"),
            payload: CanonicalBytes::from_vec(vec![0; payload_len]),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0; 32]),
        }
    }

    #[test]
    fn the_count_bound_leaves_the_checkpoint_event_the_last_slot() {
        let mut buffer = TickEventsV1::default();
        for _ in 1..MAX_PIPELINE_DRAFTS_PER_BATCH {
            assert!(!buffer.exceeds_batch_after_push(event_of(0)));
        }
        assert_eq!(buffer.drafts.len(), MAX_PIPELINE_DRAFTS_PER_BATCH - 1);
        assert!(buffer.exceeds_batch_after_push(event_of(0)));
    }

    #[test]
    fn the_byte_bound_counts_payload_and_event_type_bytes_exactly() {
        let mut buffer = TickEventsV1::default();
        // The Event type adds one byte: exactly the bound is still one batch.
        let at_bound = event_of(MAX_PIPELINE_DRAFT_BATCH_BYTES - 1);
        assert!(!buffer.exceeds_batch_after_push(at_bound));
        assert_eq!(buffer.bytes, MAX_PIPELINE_DRAFT_BATCH_BYTES);
        assert!(buffer.exceeds_batch_after_push(event_of(0)));
    }

    #[test]
    fn taking_the_drafts_starts_the_next_tick_empty() {
        let mut buffer = TickEventsV1::default();
        let over_bound = event_of(MAX_PIPELINE_DRAFT_BATCH_BYTES);
        assert!(buffer.exceeds_batch_after_push(over_bound));
        assert_eq!(buffer.take().len(), 1);
        assert!(buffer.drafts.is_empty());
        assert_eq!(buffer.bytes, 0);
        let at_bound = event_of(MAX_PIPELINE_DRAFT_BATCH_BYTES - 1);
        assert!(!buffer.exceeds_batch_after_push(at_bound));
    }
}
