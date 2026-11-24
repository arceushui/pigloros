//! The Memory pass writer: the Reserve, Commit and Abort transitions of a
//! Timeline's pass state (#560 A4c-2; ADR-129 revisions 10, 13 and 14).
//!
//! Each transition has two halves, like [`super::initialize`]'s writer. A
//! `stage_*` method reads the domain under the guard, runs the writer's
//! re-checks and refuses without changing anything; an `apply_*` method,
//! which only the trusted composition root can call, makes the change in
//! the same guarded step. The Reserve pipeline (A4c-3) stages, publishes the
//! materialization's ARD1 batch and the pass records, and then applies, so
//! a refusal before the apply leaves no pass state behind.
//!
//! The re-checks are R10.7 step 5j in its order: the generation (5), the
//! head and frontier, the counters and then the erasure budget (6), the
//! quarantine (9), and the caps (14) before the recording horizon (19). The
//! caps and the horizon are the planner's own check ([`admit_caps`]); the
//! budget is its own bound ([`trace_room`]) with every other reservation
//! pending (R13.1(4)).
//!
//! Counted set (R14, RN.1(1)): a minted materialization adds one control
//! operation in its Reserve transaction and stays counted when its pass
//! Aborts; an Annotation CPN1 adds one in the Commit transaction that binds
//! it. Abort and `SetReason` never count and are never refused for a cap or
//! the budget: an Abort only has to bind no more rows than its pending entry
//! holds (R13.1(5)).

use pos_core::community_lifecycle::{
    CommunityGraphCountsV1, CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1,
    CommunityPassGraphTermsV1, CommunityScopeMemberV1, CommunitySharedCountsV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};

use super::erasure_budget::CommunityErasureBudgetPortV1;
use super::memory_domain::MemoryCommunityDomainV1;
use super::pass_planner::{
    admit_caps, trace_room, CommunityPassCapsV1, CommunityPassReadPortV1,
    CommunityQuarantineIndexV1,
};
use super::pass_state::CommunityPendingReservationV1;

/// The observation materialization a Reserve mints (R9.7), as its stage-1
/// quote derived it.
#[derive(Clone)]
pub struct CommunityMintedObservationV1 {
    /// Its Observation CPN1.
    pub reference: CommunityNativeNodeReferenceV1,
    /// What its records add to T's selected closure until a Commit binds
    /// them (R11.3(3)).
    pub graph: CommunityPassGraphTermsV1,
    /// Its actual additions to the recorded set, added in the Reserve
    /// transaction and kept when the pass Aborts (R10.3(6)).
    pub additions: CommunitySharedCountsV1,
    /// The ARD1 rows it binds to T in the Reserve transaction (R13.1(4)).
    pub rows: u64,
    /// The digest of the Observation CPN1 ref its scope rows are read by.
    pub scope_reference: Hash,
    /// Its scope rows (R11.4(3)).
    pub scope: Vec<CommunityScopeMemberV1>,
}

/// One Reserve's writer inputs, from the planner's quote and the call.
#[derive(Clone)]
pub struct CommunityReserveInputV1 {
    /// T.
    pub timeline: TimelineId,
    /// T's active generation G the planner read (R10.5).
    pub generation: [u8; 16],
    /// The call's `reservation_operation_id`.
    pub reservation_operation_id: [u8; 16],
    /// `H(CSH1)` of the selected head the planner read.
    pub selected_head: Hash,
    /// The counters the quote was built over (R10.3(6)).
    pub prior_shared_counts: CommunitySharedCountsV1,
    /// The CQK1 digest of every roster member, due or not (R10.6).
    pub roster_quarantine_keys: Vec<Hash>,
    /// The installed CDP1 recording horizon (R10.4(3)).
    pub recording_not_after_micros: u64,
    /// `t_r`, the call's trusted-clock reservation sample.
    pub reservation_sample_micros: u64,
    /// The worst-case ARD1 rows of the pass: State, recording and the trace
    /// rows planned, the materialization's included (R13.1(4)).
    pub pass_rows: u64,
    /// `F_p`, the pass failure reserve in targets (R13.1(5)).
    pub failure_reserve: u64,
    /// The materialization this call mints, or `None` for a reused one.
    pub minted: Option<CommunityMintedObservationV1>,
}

/// A Reserve that passed every writer re-check and awaits its apply.
pub struct CommunityStagedReserveV1 {
    key: (TimelineId, [u8; 16]),
    entry: CommunityPendingReservationV1,
    minted: Option<CommunityMintedObservationV1>,
}

/// One Commit's writer inputs (R10.3(6), R11.3, R13.1(4)).
#[derive(Clone)]
pub struct CommunityCommitInputV1 {
    /// T.
    pub timeline: TimelineId,
    /// The reservation being committed.
    pub reservation_operation_id: [u8; 16],
    /// `H(CSH1)` of the head the Commit selects.
    pub selected_head: Hash,
    /// The new CGR1 `graph_counts`.
    pub graph: CommunityGraphCountsV1,
    /// The pass's actual additions, its Annotation CPN1s included.
    pub additions: CommunitySharedCountsV1,
    /// The Annotation CPN1s the Commit binds: each is one control
    /// operation (R14, RN.1(1)).
    pub annotations: u64,
    /// The logical digests of the CES1s the Commit adds to the selected
    /// closure.
    pub closure: Vec<Hash>,
    /// The Observation CPN1 whose records are in the selected closure
    /// from now on.
    pub observation: Option<CommunityNativeNodeReferenceV1>,
    /// The ARD1 rows the Commit binds, at most the pending entry's.
    pub bound_rows: u64,
    /// The scope rows of the nodes it mints, by ref digest (R11.4(3)).
    pub scope_rows: Vec<(Hash, Vec<CommunityScopeMemberV1>)>,
}

/// A Commit that fits its pending entry and awaits its apply.
pub struct CommunityStagedCommitV1(CommunityCommitInputV1);

/// An Abort that fits its pending entry and awaits its apply.
#[derive(Clone, Copy)]
pub struct CommunityStagedAbortV1 {
    key: (TimelineId, [u8; 16]),
}

impl MemoryCommunityDomainV1 {
    /// Re-check a Reserve at the writer (R10.7 step 5j) and stage it.
    ///
    /// # Errors
    /// Returns `InvalidBinding` when the minted rows exceed the pass rows,
    /// `Conflict` for a reservation identity already pending and
    /// `EvidenceUnavailable` for a Timeline with no pass state; then in the
    /// step-5j order `StaleGeneration` (5), `StaleFrontier` (6) for a moved
    /// head, moved counters or a budget the pending reservations now fill,
    /// `Quarantined` (9), `CapacityExhausted` (14) and
    /// `RecordingUnavailable` (19), and the budget read's error.
    pub fn stage_reserve(
        &self,
        input: CommunityReserveInputV1,
    ) -> Result<CommunityStagedReserveV1, Error> {
        let bound = input.minted.as_ref().map_or(0, |minted| minted.rows);
        if bound > input.pass_rows {
            return Err(Error::InvalidBinding);
        }
        let key = (input.timeline, input.reservation_operation_id);
        if self.pending_reservations.contains_key(&key) {
            return Err(Error::Conflict);
        }
        let state = self
            .pass_states
            .get(&input.timeline)
            .ok_or(Error::EvidenceUnavailable)?;
        if state.generation != input.generation {
            return Err(Error::StaleGeneration);
        }
        if state.head != input.selected_head || state.counters != input.prior_shared_counts {
            return Err(Error::StaleFrontier);
        }
        self.check_reserve_budget(&input)?;
        if input.roster_quarantine_keys.iter().any(|member| {
            self.quarantine_reasons(*member)
                .is_some_and(|reasons| !reasons.is_empty())
        }) {
            return Err(Error::Quarantined);
        }
        admit_caps(
            CommunityPassCapsV1 {
                outcomes: self.retained_pass_outcomes(input.timeline, input.generation),
                operations: self.control_operations(input.timeline, input.generation),
                recording_not_after_micros: input.recording_not_after_micros,
                reservation_sample_micros: input.reservation_sample_micros,
            },
            input.minted.is_some(),
        )
        .map(|()| {
            // The materialization's rows bind in the Reserve transaction;
            // the entry holds only the rest and `F_p` (R13.1(4)).
            let pass_rows = input.pass_rows - bound;
            CommunityStagedReserveV1 {
                key,
                entry: CommunityPendingReservationV1 {
                    targets: 2 * pass_rows + input.failure_reserve,
                    rows: pass_rows + input.failure_reserve / 2,
                },
                minted: input.minted,
            }
        })
    }

    /// R13.1(4) at the writer: every actor of T's scope still fits the
    /// pass's worst-case rows and `F_p` beside every pending reservation.
    /// A misfit is 6, not 14: the planner already judged the quote.
    fn check_reserve_budget(&self, input: &CommunityReserveInputV1) -> Result<(), Error> {
        self.erasure_budget(input.timeline).and_then(|budget| {
            let fits = budget.actors.iter().all(|actor| {
                let pending = self.pending_erasure_demand(actor.actor);
                trace_room(
                    &budget,
                    actor,
                    &pending,
                    input.timeline,
                    input.pass_rows,
                    input.failure_reserve,
                )
                .is_some()
            });
            if fits {
                Ok(())
            } else {
                Err(Error::StaleFrontier)
            }
        })
    }

    /// Apply a staged Reserve in the guarded step that published its
    /// records: one more retained outcome, the pending entry and, for a
    /// minted materialization, its additions to the counters, the closure
    /// terms and scope rows a reuse reads and one more control operation.
    pub fn apply_reserve(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: CommunityStagedReserveV1,
    ) {
        let (timeline, _) = staged.key;
        self.pending_reservations.insert(staged.key, staged.entry);
        self.pass_states.entry(timeline).and_modify(|state| {
            let counts = state.generations.entry(state.generation).or_default();
            counts.outcomes += 1;
            if let Some(minted) = staged.minted {
                counts.materializations += 1;
                state.counters = add_counts(state.counters, minted.additions);
                state.observations.insert(minted.reference, minted.graph);
                state
                    .scope_rows
                    .insert(minted.scope_reference, minted.scope);
            }
        });
    }

    /// Check a Commit against its pending entry: it binds no more rows than
    /// the entry holds (R13.1(4)).
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a reservation with no pending entry or
    /// a Commit binding more rows than the entry, and `EvidenceUnavailable`
    /// for a Timeline with no pass state.
    pub fn stage_commit(
        &self,
        input: CommunityCommitInputV1,
    ) -> Result<CommunityStagedCommitV1, Error> {
        self.entry_of(
            (input.timeline, input.reservation_operation_id),
            input.bound_rows,
        )
        .map(|()| CommunityStagedCommitV1(input))
    }

    /// Apply a staged Commit: the entry is replaced by the rows it bound,
    /// the counters, selected graph, head and closure advance, the
    /// materialization's records are in the closure and an Annotation CPN1
    /// is one more control operation each.
    pub fn apply_commit(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: CommunityStagedCommitV1,
    ) {
        let input = staged.0;
        self.pending_reservations
            .remove(&(input.timeline, input.reservation_operation_id));
        self.pass_states.entry(input.timeline).and_modify(|state| {
            state.counters = add_counts(state.counters, input.additions);
            state.graph = input.graph;
            state.head = input.selected_head;
            state.closure.extend(input.closure);
            if let Some(observation) = input.observation {
                state.observations.remove(&observation);
            }
            state.scope_rows.extend(input.scope_rows);
            state
                .generations
                .entry(state.generation)
                .or_default()
                .annotations += input.annotations;
        });
    }

    /// Check an Abort against its pending entry: it registers no more rows
    /// than the entry holds, and no cap or budget refuses it (R13.1(5)).
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a reservation with no pending entry or
    /// an Abort registering more rows than the entry, and
    /// `EvidenceUnavailable` for a Timeline with no pass state.
    pub fn stage_abort(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
        registered_rows: u64,
    ) -> Result<CommunityStagedAbortV1, Error> {
        let key = (timeline, reservation_operation_id);
        self.entry_of(key, registered_rows)
            .map(|()| CommunityStagedAbortV1 { key })
    }

    /// Apply a staged Abort: the entry is replaced by the rows it
    /// registered. The retained outcome, the materialization's counters,
    /// control operation and closure terms stay, so the next pass reuses
    /// its records (R13.1(4)).
    pub fn apply_abort(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: CommunityStagedAbortV1,
    ) {
        self.pending_reservations.remove(&staged.key);
    }

    fn entry_of(&self, key: (TimelineId, [u8; 16]), rows: u64) -> Result<(), Error> {
        if !self.pass_states.contains_key(&key.0) {
            return Err(Error::EvidenceUnavailable);
        }
        match self.pending_reservations.get(&key) {
            Some(entry) if rows <= entry.rows => Ok(()),
            _ => Err(Error::InvalidBinding),
        }
    }
}

/// The counters with `added` on top, saturating like every counter.
const fn add_counts(
    counters: CommunitySharedCountsV1,
    added: CommunitySharedCountsV1,
) -> CommunitySharedCountsV1 {
    CommunitySharedCountsV1 {
        nodes: counters.nodes.saturating_add(added.nodes),
        edges: counters.edges.saturating_add(added.edges),
        declared_inputs: counters
            .declared_inputs
            .saturating_add(added.declared_inputs),
        encoded_record_bytes: counters
            .encoded_record_bytes
            .saturating_add(added.encoded_record_bytes),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
