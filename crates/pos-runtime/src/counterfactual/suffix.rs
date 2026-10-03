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
//! 1. validates the CFP1 plan and bounds the suffix to at most
//!    [`MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1`] Ticks, so the `CFR1`
//!    checkpoint list can hold one checkpoint per Tick;
//! 2. proves the receipt's generation is still the Fork's committed
//!    generation and reads the generation's committed `SIV1`, which must bind
//!    the plan;
//! 3. recovers the committed suffix from the Event Store alone: the first
//!    Tick is exactly the `first_tick_head - commit_seq` Events after the
//!    `SIV1` commit coordinate through the receipt's first-Tick head, and
//!    every later Tick ends with one checkpoint Event whose payload is that
//!    Tick's exact `RCP1` bytes. Every later `RCP1` is re-derived from the
//!    committed Events, chained through the first Tick's state, and must
//!    match byte for byte, so a missing first-Tick Event, and any foreign,
//!    unmarked, or altered Event after the first Tick, are each a
//!    [`CounterfactualSuffixErrorV1::RecoveryMismatch`];
//! 4. commits each remaining Tick through the horizon: it stages the Tick
//!    through the same [`CounterfactualTickStagerV1`] seam and staged inputs
//!    as the first Tick (the plan's exact frozen `ExogenousFrozen` and
//!    `FixedPolicy` descriptors and the Interventions effective at that
//!    Tick), checks the host's current trust, revocation, and erasure epochs
//!    against the admitted ones immediately before the commit, and appends
//!    the Tick's Events together with its checkpoint Event as one atomic
//!    batch;
//! 5. emits every checkpoint of the generation and one sealed `CFR1`.
//!
//! A call on an already complete generation stages and commits nothing, but
//! still checks the current epochs once: a changed epoch is
//! [`CounterfactualSuffixErrorV1::EpochChanged`], because the completed
//! generation is stale and its result is not re-emitted.
//!
//! The first failed Tick stops the call. It commits nothing, because its
//! only write is the one atomic append, and it is reported as
//! [`CounterfactualSuffixRunV1::failure`] with a `Failed` `CFR1` whose
//! committed range ends at the last committed Tick, so the suffix stays
//! explicitly incomplete. Calling again recovers the same committed state and
//! retries that Tick with the same staged inputs; a retry that succeeds
//! produces the same checkpoints and result as an uninterrupted run.
//! Errors returned as [`CounterfactualSuffixErrorV1`] are detected before
//! any Tick is staged and commit nothing either.
//!
//! # ADR gap decisions
//!
//! - **Generation fence without a new port.** The #335 port commits only the
//!   invalidation transaction. Later Ticks use the generic
//!   [`EventStore::append`], which commits one batch atomically on both
//!   adapters. The coordinator exclusively owns the store, so no other writer
//!   can interleave with a call; the call proves at its start that the
//!   receipt's generation is still committed and that the committed Events
//!   are exactly the recovered Ticks, and every generation increment commits
//!   at least one Event, so a stale generation is always detected.
//! - **Checkpoint persistence.** The port has no checkpoint store, so each
//!   `RCP1` is persisted as the payload of one coordinator-owned
//!   [`COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1`] Event appended in the same
//!   atomic batch as the Tick's Events, attributed to the Fork's own entity
//!   ID. A stager may not use that Event type
//!   ([`CounterfactualSuffixFailureV1::ReservedEventType`]). The first Tick,
//!   committed by admission, has no checkpoint Event: its range is fixed by
//!   the `SIV1` commit coordinate and the receipt, and its `RCP1` is
//!   re-derived on every call. Recovery binds its Event count to that range;
//!   its Event content is bound by the next Tick's committed `RCP1`, which
//!   chains the first Tick's state.
//! - **`RCP1` content.** No Plugin or Projection state serialization exists
//!   yet, so both lists are empty. The one state digest, owned by
//!   [`SUFFIX_STATE_OWNER_V1`], chains the `SIV1` digest through every
//!   committed Tick: `blake3("PiglorOS.CounterfactualSuffixState.v1\0" ||
//!   previous || trust_be || revocation_be || erasure_be || tick_be ||
//!   draft_digest)`, over the admitted epochs, where `draft_digest` is the
//!   [`pos_core::pipeline_draft_vector_digest_v1`] of the Tick's Event drafts
//!   with their wall time cleared, because wall time is presentation-only and
//!   store-assigned. `seq` is the Fork `Seq` of the Tick's last recomputed
//!   Event and `scheduler_position` is `0`, the Tick Boundary. Every Tick reads
//!   the whole frozen closure, so the exogenous cursor stands after the last
//!   `ExogenousFrozen` descriptor. The provenance root is the `SIV1`
//!   provenance digest.
//! - **`CFR1` content.** The first Tick is the receipt's first recomputation
//!   Tick; the suffix digest is the final chained state digest; the
//!   dependency root is the committed `RCF1` frontier digest, which binds the
//!   dependency-graph digest (recording generated edges is deferred); the
//!   provenance root is the `SIV1` provenance digest. A completed result keeps
//!   the plan's replay claim. An incomplete one weakens only the claims CFR1
//!   forbids for an incomplete suffix, `Exact` and
//!   `ExactAuthoritativeWithRedactedViews`, to `StructuralOnly`, the
//!   strongest permitted claim; every other claim is kept unchanged.
//! - **Terminal codes.** An epoch change is `InvalidationConflict`; a stager
//!   failure, an empty, malformed, or oversized staged batch, and a reserved
//!   Event type are `PluginFailure`; a rejected append is
//!   `AtomicCommitFailed`. The failing coordinate is the first uncommitted
//!   Tick at scheduler position `0`, without a safe digest.
//! - **Epoch changes.** The store keeps the published epochs only for the
//!   invalidation recheck, so the host supplies its current epochs through
//!   [`CounterfactualEpochSourceV1`] before every commit. A changed epoch
//!   makes the generation stale; re-admitting it is the host's decision.
//! - **Admitted epochs.** The admitted trust epoch is the plan's TPS1 epoch,
//!   which admission committed and the committed `SIV1` binds through the
//!   plan digest. Neither the receipt, `SIV1`, nor the port exposes the
//!   committed revocation and erasure epochs, so those two are
//!   host-attested ([`CounterfactualAttestedEpochsV1`]). Every chained state
//!   digest covers the admitted epochs, so once a later Tick committed, a
//!   call attesting other epochs re-derives other `RCP1` bytes and is a
//!   [`CounterfactualSuffixErrorV1::RecoveryMismatch`].
//! - **Recovery reads.** Recovery reads the committed suffix with the generic
//!   [`EventStore::read`]; an Event Store read failure is reported as
//!   `StorageFailure`.
//!
//! # Deferred
//!
//! - **Committed revocation and erasure epochs.** While only the first Tick
//!   is committed, nothing committed binds the attested revocation and
//!   erasure epochs, so a host that attests its new epochs after a
//!   revocation or erasure change can still recompute that stale generation.
//!   The first later Tick then embeds those attested epochs in the chained
//!   `RCP1` state for good, so a wrong first attestation is locked in and
//!   later calls with the true epochs fail with `RecoveryMismatch`.
//!   Closing this needs the port to expose the epochs persisted at
//!   admission (or the receipt to carry them).
//! - **First-Tick Event content.** No committed artifact records the first
//!   Tick's draft digest, so until the next Tick commits, an altered
//!   first-Tick Event of the right count is not detected by recovery; it
//!   relies on the store's own atomic commit.

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
    pipeline_draft_vector_digest_v1, CanonicalBytes, CounterfactualGenerationReceiptV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, EntityId, Event, EventDraft, EventStore,
    InvalidationConflictV1, Kind, PipelineContractErrorV1, Seq, SeqRange, TimelineId,
};

use super::coordinator::{
    stage_first_tick, CounterfactualAdmissionErrorV1, CounterfactualCoordinatorV1,
    CounterfactualTickStagerV1,
};

/// Event type of the coordinator-owned Event carrying one Tick's `RCP1`.
pub const COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1: &str = "counterfactual.checkpoint";
/// `RCP1` owner of the chained suffix state digest.
pub const SUFFIX_STATE_OWNER_V1: &str = "counterfactual.suffix";

/// The largest Tick span after the first recomputation Tick: one checkpoint
/// per Tick must fit [`MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1`].
const MAX_SUFFIX_TICK_SPAN: u64 = 65_535;
const SUFFIX_STATE_DOMAIN: &[u8] = b"PiglorOS.CounterfactualSuffixState.v1\0";

/// The trust, revocation, and erasure epochs a generation was admitted under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualEpochsV1 {
    /// Trust-policy epoch.
    pub trust: u64,
    /// Authority revocation epoch.
    pub revocation: u64,
    /// Erasure epoch.
    pub erasure: u64,
}

impl CounterfactualEpochsV1 {
    /// Return the first epoch of `current` that differs from these epochs.
    #[must_use]
    pub fn first_change(&self, current: &Self) -> Option<InvalidationConflictV1> {
        [
            (
                self.trust == current.trust,
                InvalidationConflictV1::TrustEpoch,
            ),
            (
                self.revocation == current.revocation,
                InvalidationConflictV1::RevocationEpoch,
            ),
            (
                self.erasure == current.erasure,
                InvalidationConflictV1::ErasureEpoch,
            ),
        ]
        .into_iter()
        .find_map(|(same, conflict)| (!same).then_some(conflict))
    }
}

/// The host-attested revocation and erasure epochs a generation was admitted
/// under.
///
/// No committed artifact the port exposes carries them, so the host attests
/// them; the module documentation describes what binds them and the
/// deferred gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualAttestedEpochsV1 {
    /// Authority revocation epoch the admission committed under.
    pub revocation: u64,
    /// Erasure epoch the admission committed under.
    pub erasure: u64,
}

/// Host source of the current trust, revocation, and erasure epochs.
pub trait CounterfactualEpochSourceV1 {
    /// Return the host's current epochs.
    fn current_epochs(&self) -> CounterfactualEpochsV1;
}

/// Why one recomputation Tick failed; nothing of it was committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualSuffixFailureV1 {
    /// A host epoch changed since admission; the generation is stale.
    EpochChanged(InvalidationConflictV1),
    /// The stager failed to stage the Tick.
    PluginFailure,
    /// The staged drafts are empty, malformed, or oversized.
    StagedTickRejected(PipelineContractErrorV1),
    /// A staged draft uses the coordinator-owned checkpoint Event type.
    ReservedEventType,
    /// The Event Store rejected the Tick's atomic append.
    AtomicCommitFailed,
}

impl CounterfactualSuffixFailureV1 {
    /// Return the closed `CFR1` terminal error code of this failure.
    #[must_use]
    pub const fn code(self) -> CounterfactualTerminalErrorCodeV1 {
        match self {
            Self::EpochChanged(_) => CounterfactualTerminalErrorCodeV1::InvalidationConflict,
            Self::PluginFailure | Self::StagedTickRejected(_) | Self::ReservedEventType => {
                CounterfactualTerminalErrorCodeV1::PluginFailure
            }
            Self::AtomicCommitFailed => CounterfactualTerminalErrorCodeV1::AtomicCommitFailed,
        }
    }
}

/// Closed safe errors detected before any Tick is staged; nothing commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CounterfactualSuffixErrorV1 {
    /// The CFP1 plan is invalid.
    #[error("counterfactual plan is invalid")]
    Plan(#[source] CounterfactualPlanContractErrorV1),
    /// The suffix has more Ticks than one result can checkpoint.
    #[error("counterfactual suffix exceeds the checkpoint bound")]
    SuffixTooLong,
    /// The committed generation's `SIV1` does not bind the plan.
    #[error("counterfactual suffix does not belong to the plan")]
    PlanMismatch,
    /// The committed invalidation or suffix Events do not match the generation.
    #[error("counterfactual suffix does not match the committed generation")]
    RecoveryMismatch,
    /// A host epoch changed since admission of an already complete
    /// generation; the generation is stale.
    #[error("counterfactual generation is stale")]
    EpochChanged(InvalidationConflictV1),
    /// An `RCP1` or `CFR1` artifact could not be sealed.
    #[error("counterfactual suffix artifact could not be encoded")]
    ArtifactEncoding,
    /// The counterfactual store rejected or failed a read.
    #[error("counterfactual store operation failed")]
    Store(#[source] CounterfactualStoreErrorV1),
}

/// One suffix recomputation request for a committed generation.
#[derive(Clone, Copy)]
pub struct CounterfactualSuffixRequestV1<'a> {
    /// The admitted CFP1 plan; its TPS1 epoch is the admitted trust epoch.
    pub plan: &'a CounterfactualPlanV1,
    /// The receipt of the admitted generation and its first Tick.
    pub receipt: CounterfactualGenerationReceiptV1,
    /// The host-attested revocation and erasure epochs of the admission.
    pub attested_epochs: CounterfactualAttestedEpochsV1,
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
    admitted_epochs: CounterfactualEpochsV1,
    provenance: [u8; 32],
    result_id: [u8; 16],
    evaluator_identity_digest: [u8; 32],
}

impl SuffixContextV1<'_> {
    const fn fork(&self) -> TimelineId {
        self.receipt.generation().fork
    }

    /// Return the first host epoch that changed since admission.
    fn epoch_change(
        &self,
        epochs: &impl CounterfactualEpochSourceV1,
    ) -> Option<InvalidationConflictV1> {
        self.admitted_epochs.first_change(&epochs.current_epochs())
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

impl<S: EventStore + CounterfactualStorePortV1> CounterfactualCoordinatorV1<S> {
    /// Release the exclusively owned store, for example to reopen it later.
    #[must_use]
    pub const fn into_store(self) -> S {
        self.store
    }

    /// Recover the committed suffix of `request`'s generation and commit every
    /// remaining Tick through the plan horizon.
    ///
    /// See the module documentation for the recovery, commit, and artifact
    /// rules. A failed Tick is reported in the returned run, not as an error.
    ///
    /// # Errors
    /// Returns the first closed safe error detected before any Tick is
    /// staged; every error commits nothing. On an already complete
    /// generation, a changed host epoch is
    /// [`CounterfactualSuffixErrorV1::EpochChanged`].
    pub fn recompute_suffix(
        &mut self,
        request: &CounterfactualSuffixRequestV1<'_>,
        epochs: &impl CounterfactualEpochSourceV1,
        stager: &mut impl CounterfactualTickStagerV1,
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
        let invalidation = self.committed_invalidation(request)?;
        let context = SuffixContextV1 {
            plan,
            receipt: request.receipt,
            admitted_epochs: CounterfactualEpochsV1 {
                trust: plan.trust_policy.epoch,
                revocation: request.attested_epochs.revocation,
                erasure: request.attested_epochs.erasure,
            },
            provenance: invalidation.provenance_digest,
            result_id: request.result_id,
            evaluator_identity_digest: request.evaluator_identity_digest,
        };
        let mut progress = self.recover(&context, invalidation.commit_seq)?;
        if progress.tick >= plan.horizon_tick {
            if let Some(conflict) = context.epoch_change(epochs) {
                return Err(CounterfactualSuffixErrorV1::EpochChanged(conflict));
            }
        }
        while progress.tick < plan.horizon_tick {
            if let Some(failure) = self.commit_tick(&context, &mut progress, epochs, stager)? {
                return finish(&context, progress, Some(failure));
            }
        }
        finish(&context, progress, None)
    }

    /// Prove the receipt's generation is committed and read its `SIV1`.
    fn committed_invalidation(
        &self,
        request: &CounterfactualSuffixRequestV1<'_>,
    ) -> Result<SuffixInvalidationV1, CounterfactualSuffixErrorV1> {
        let generation = request.receipt.generation();
        let current = self
            .store
            .current_fork_generation(generation.fork)
            .map_err(CounterfactualSuffixErrorV1::Store)?;
        if current != generation {
            return Err(CounterfactualSuffixErrorV1::Store(
                CounterfactualStoreErrorV1::MixedForkGeneration,
            ));
        }
        let bytes = self
            .store
            .read_generation_artifact(generation, request.receipt.invalidation_digest())
            .map_err(CounterfactualSuffixErrorV1::Store)?
            .ok_or(CounterfactualSuffixErrorV1::RecoveryMismatch)?;
        let invalidation = SuffixInvalidationV1::from_canonical_cbor(&bytes)
            .or(Err(CounterfactualSuffixErrorV1::RecoveryMismatch))?;
        if invalidation.plan_digest == request.plan.plan_digest {
            Ok(invalidation)
        } else {
            Err(CounterfactualSuffixErrorV1::PlanMismatch)
        }
    }

    /// Rebuild the committed suffix from the Fork Events after `commit_seq`.
    ///
    /// The first Tick must be exactly the Events from `commit_seq + 1`
    /// through the receipt's first-Tick head.
    fn recover(
        &self,
        context: &SuffixContextV1<'_>,
        commit_seq: u64,
    ) -> Result<ProgressV1, CounterfactualSuffixErrorV1> {
        let from = Seq::from_u64(commit_seq.saturating_add(1));
        let events = self
            .store
            .read(context.fork(), SeqRange::from_seq(from))
            .or(Err(CounterfactualSuffixErrorV1::Store(
                CounterfactualStoreErrorV1::StorageFailure,
            )))?;
        let first_tick = context.receipt.first_tick();
        let first_head = context.receipt.first_tick_head().as_u64();
        let split = events.partition_point(|event| event.seq.as_u64() <= first_head);
        let (first_events, later_events) = events.split_at(split);
        if first_events.len() as u64 != first_head.saturating_sub(commit_seq) {
            return Err(CounterfactualSuffixErrorV1::RecoveryMismatch);
        }
        let first_drafts: Vec<EventDraft> = first_events.iter().map(committed_draft).collect();
        let seed = *context.receipt.invalidation_digest().as_bytes();
        let first = next_checkpoint(context, seed, first_tick, &first_drafts, first_head)?;
        let mut progress = ProgressV1 {
            generation: context.receipt.generation().generation,
            tick: first_tick,
            head: first_head,
            state: seed,
            checkpoints: Vec::new(),
            refs: Vec::new(),
        };
        progress.advance(first_tick, first_head, first);
        recover_marked_ticks(context, &mut progress, later_events).map(|()| progress)
    }

    /// Stage, checkpoint, and atomically commit the next Tick; the epochs are
    /// checked immediately before the commit.
    ///
    /// Returns the failure of a Tick that committed nothing.
    fn commit_tick(
        &mut self,
        context: &SuffixContextV1<'_>,
        progress: &mut ProgressV1,
        epochs: &impl CounterfactualEpochSourceV1,
        stager: &mut impl CounterfactualTickStagerV1,
    ) -> Result<Option<CounterfactualSuffixFailureV1>, CounterfactualSuffixErrorV1> {
        let tick = progress.tick.saturating_add(1);
        let batch = match stage_first_tick(stager, context.plan, context.receipt.generation(), tick)
        {
            Ok(batch) => batch,
            Err(error) => return Ok(Some(staging_failure(&error))),
        };
        let drafts = batch.drafts();
        if drafts.iter().any(is_checkpoint_event) {
            return Ok(Some(CounterfactualSuffixFailureV1::ReservedEventType));
        }
        let content: Vec<EventDraft> = drafts.iter().map(content_draft).collect();
        let seq = progress.head.saturating_add(drafts.len() as u64);
        let checkpoint = next_checkpoint(context, progress.state, tick, &content, seq)?;
        let mut tick_drafts = drafts.to_vec();
        tick_drafts.push(checkpoint_draft(context.fork(), &checkpoint.bytes));
        if let Some(conflict) = context.epoch_change(epochs) {
            return Ok(Some(CounterfactualSuffixFailureV1::EpochChanged(conflict)));
        }
        if self.store.append(context.fork(), &tick_drafts).is_err() {
            return Ok(Some(CounterfactualSuffixFailureV1::AtomicCommitFailed));
        }
        progress.advance(tick, seq.saturating_add(1), checkpoint);
        Ok(None)
    }
}

/// Re-derive every Tick that ends with a checkpoint Event and require the
/// committed `RCP1` bytes to match; no Event may follow the last one.
fn recover_marked_ticks(
    context: &SuffixContextV1<'_>,
    progress: &mut ProgressV1,
    events: &[Event],
) -> Result<(), CounterfactualSuffixErrorV1> {
    let mut pending: Vec<EventDraft> = Vec::new();
    for event in events {
        if event.event_type.as_str() == COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1 {
            let tick = progress.tick.saturating_add(1);
            let seq = progress.head.saturating_add(pending.len() as u64);
            let checkpoint = next_checkpoint(context, progress.state, tick, &pending, seq)?;
            if checkpoint.bytes.as_slice() != event.payload.as_slice() {
                return Err(CounterfactualSuffixErrorV1::RecoveryMismatch);
            }
            progress.advance(tick, event.seq.as_u64(), checkpoint);
            pending.clear();
        } else {
            pending.push(committed_draft(event));
        }
    }
    if pending.is_empty() {
        Ok(())
    } else {
        Err(CounterfactualSuffixErrorV1::RecoveryMismatch)
    }
}

/// Map a staging error of the shared stager seam to its Tick failure.
const fn staging_failure(error: &CounterfactualAdmissionErrorV1) -> CounterfactualSuffixFailureV1 {
    match error {
        CounterfactualAdmissionErrorV1::StagedTickRejected(rejection) => {
            CounterfactualSuffixFailureV1::StagedTickRejected(*rejection)
        }
        _ => CounterfactualSuffixFailureV1::PluginFailure,
    }
}

fn is_checkpoint_event(draft: &EventDraft) -> bool {
    draft.event_type.as_str() == COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1
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
fn committed_draft(event: &Event) -> EventDraft {
    EventDraft {
        entity: event.entity,
        event_type: event.event_type.clone(),
        payload: event.payload.clone(),
        causation_id: event.causation_id,
        correlation_id: event.correlation_id,
        schema_version: event.schema_version,
        wall_time: None,
    }
}

/// Chain one Tick's draft digest onto the previous suffix state under the
/// admitted epochs; every draft already has its wall time cleared.
fn chain_state(
    previous: &[u8; 32],
    epochs: &CounterfactualEpochsV1,
    tick: u64,
    drafts: &[EventDraft],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SUFFIX_STATE_DOMAIN);
    hasher.update(previous);
    hasher.update(&epochs.trust.to_be_bytes());
    hasher.update(&epochs.revocation.to_be_bytes());
    hasher.update(&epochs.erasure.to_be_bytes());
    hasher.update(&tick.to_be_bytes());
    hasher.update(pipeline_draft_vector_digest_v1(drafts).as_bytes());
    *hasher.finalize().as_bytes()
}

/// Build and seal the `RCP1` of `tick`, whose last recomputed Event is `seq`.
fn next_checkpoint(
    context: &SuffixContextV1<'_>,
    previous: [u8; 32],
    tick: u64,
    drafts: &[EventDraft],
    seq: u64,
) -> Result<CheckpointV1, CounterfactualSuffixErrorV1> {
    let plan = context.plan;
    let state = chain_state(&previous, &context.admitted_epochs, tick, drafts);
    let unsigned = RecomputeCheckpointV1 {
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
    };
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

/// Keep the bound constant tied to the `CFR1` checkpoint limit.
const _: () = assert!(MAX_SUFFIX_TICK_SPAN + 1 == MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1 as u64);
