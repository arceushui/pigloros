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
//! The re-checks are R10.7 step 5j in its order: the Logical Head and chain
//! compare of the minted or reused cut (12), the decision bound (13), the
//! generation (5), the head, the counters, the reuse horizon and then the
//! erasure budget (6), the quarantine (9), and the caps (14) before the
//! recording horizon (19). The writer recomputes `H_g` and `H_r` from the
//! installed horizons and its sample (R13.4(2)) and refuses a record that
//! differs. The caps and the horizon are the planner's own check
//! ([`admit_caps`]); the budget is its own bound ([`trace_room`]) with
//! every other reservation pending (R13.1(4)).
//!
//! Counted set (R14, RN.1(1)): a minted materialization adds one control
//! operation in its Reserve transaction and stays counted when its pass
//! Aborts; an Annotation CPN1 adds one in the Commit transaction that binds
//! it. Abort and `SetReason` never count and are never refused for a cap or
//! the budget: an Abort only has to bind no more rows than its pending entry
//! holds (R13.1(5)).
//!
//! The pipeline is single-writer: it stages and then applies under one
//! guard, so the stage re-checks still hold at the apply. An apply
//! re-validates only what is cheap to check: the pass state, the recorded
//! identity and the pending entries (a Reserve), or the entry (a Commit or
//! Abort).
//! A Reserve is refused with `Conflict` when its identity is recorded in
//! the CRI1 index (`pass_records`), resolved or not, or is pending, at stage
//! and again at the apply. It is refused with `PassUnresolved` (code 7)
//! at stage when T already has an unresolved pass. A second Reserve staged
//! before the first was applied is invisible at stage, so only the apply
//! refuses it (`PassUnresolved`, from T's pending entries). A Commit or
//! Abort is refused when its entry is gone or too small, which also refuses
//! their replay.
//!
//! A Reserve allocates its native producer ordinal and its pass ordinal
//! (annex §4): `stage_reserve` computes the next of each without changing
//! anything, and `apply_reserve` refuses (`Conflict`) a token whose ordinals
//! another burn or pass has moved since, then advances both. A minted
//! materialization must carry the ordinal the step-5h burn made last, which
//! no minted Reserve has consumed yet.
//!
//! A Reserve replay is refused here as well as by the pipeline's step 4a
//! discovery: `pass_records` keeps every pass with its status after it
//! resolves, so a recorded identity, pending or resolved, is a `Conflict`
//! at stage, before the generation, head and counters are compared, and
//! again at the apply. The discovery still answers a replay from its
//! original outcome first; this refusal is the backstop.
//!
//! No apply re-runs the budget, caps, head or counters compares; a token
//! staged before another operation changed them is for the pipeline to
//! discard.

use pos_core::community_lifecycle::{
    community_prepared_input_set_digest_v1, CommunityGraphCountsV1,
    CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1, CommunityPassGraphTermsV1,
    CommunityPassKeyV1, CommunityReservationInputV1, CommunityReservationRequestInputV1,
    CommunityReservationRequestV1, CommunityReservationV1, CommunityScopeMemberV1,
    CommunitySelectionInputV1, CommunitySelectionV1, CommunitySharedCountsV1,
    CommunityTimelineFloorsV1,
};
use pos_core::store::EventStore;
use pos_core::{AuthorityTrustRootSealV1, Hash, Seq, TimelineId};
use zeroize::Zeroizing;

use super::erasure_budget::{CommunityErasureBudgetPortV1, CommunityPendingReservationV1};
use super::memory_domain::MemoryCommunityDomainV1;
use super::observation::{fork_segments, EVENT_READ_BOUNDS};
use super::pass_install::{reservation_horizons, CommunityReservationHorizonsV1};
use super::pass_planner::{
    admit_caps, decision_bound, trace_room, CommunityPassCapsV1, CommunityPassReadPortV1,
    CommunityQuarantineIndexV1,
};
use super::pass_record::{
    CommunityPassMemberDigestsV1, CommunityPassRecordV1, CommunityPassStatusV1,
    CommunityReservedPassV1,
};
use super::pass_state::{CommunityPassStateV1, CommunityRetainedObservationV1};

/// The horizons a Reserve is judged by: `H_g` and `H_r`, and the installed
/// recording horizon (R10.4(3)).
#[derive(Clone, Copy)]
struct WriterHorizonsV1 {
    horizons: CommunityReservationHorizonsV1,
    recording_not_after_micros: u64,
}

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
    /// The earliest `evidence_not_after` of its records, kept for a later
    /// reuse (R9.2).
    pub not_after_micros: u64,
    /// The cut its CPE1 observes: the writer compares it with the store
    /// (R9.7 step 6) and keeps it with the observation for a later reuse.
    pub cut: CommunityObservationCutV1,
}

/// The Event history a materialization's CPE1 observes (ADR-129 R9.3, R9.7).
#[derive(Clone)]
pub struct CommunityObservationCutV1 {
    /// `through_seq`, which must still be T's Logical Head.
    pub through_seq: u64,
    /// The chain hash at each owning Timeline's cut: T at `through_seq` and
    /// every Fork-prefix source at its immutable Fork cut. The writer
    /// derives which are required from the topology, so a missing entry
    /// refuses; an entry for any other Timeline or sequence is inert and is
    /// never compared.
    pub chain_heads: Vec<(TimelineId, u64, Hash)>,
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
    /// `t_r`, the call's trusted-clock reservation sample.
    ///
    /// The writer cannot check it. The pipeline that makes the domain's
    /// clock reservation (A4c-3c-ii) must take the sample from it.
    pub reservation_sample_micros: u64,
    /// The worst-case ARD1 rows of the pass: State and recording rows, the
    /// materialization's included, and no trace (R13.1(4), R15.5).
    pub pass_rows: u64,
    /// `F_p`, the pass failure reserve in targets: `2 * trace_rows`
    /// (R13.1(5)).
    pub failure_reserve: u64,
    /// The materialization this call mints, or `None` for a reused one.
    pub minted: Option<CommunityMintedObservationV1>,
    /// The Observation CPN1 this call reuses: `Some` exactly when no
    /// materialization is minted. The domain holds its horizon and cut
    /// from the Reserve that minted it (R9.2).
    pub reused: Option<CommunityNativeNodeReferenceV1>,
    /// The pre-Reserve request the call carries (R8.1(7)): its T, G,
    /// identity and expected head must be the call's own and its profile
    /// the installed one. The writer mints the CPR1 from it with the
    /// ordinals it allocates; the requested evidence horizon is not
    /// compared, the writer's own `H_r` is the CPR1's.
    ///
    /// Its `prepared_input_set_digest` must be the identity of the pass
    /// facts' `[cmb1, cin1]` pairs, strictly ordered by member digest (3).
    pub request: CommunityReservationRequestInputV1,
    /// What the pass record keeps beyond the CPR1: the quote and the digests
    /// of its members (R8.1(7), R15.3(2)).
    pub pass: CommunityReservePassFactsV1,
}

/// The pass facts a Reserve call supplies; the writer adds the CPR1 and the
/// horizons it computes.
#[derive(Clone)]
pub struct CommunityReservePassFactsV1 {
    /// `H(CBQ1)`, the pass quote.
    pub cbq1_digest: Hash,
    /// The quote's maximum required nodes, edges and bytes.
    pub quote_maxima: [u64; 3],
    /// The trace rows held in the pass's entry: `n_due + 1` (R15.5).
    pub trace_rows: u64,
    /// Each due member's digests, in roster order (R15.3(2)).
    pub members: Vec<CommunityPassMemberDigestsV1>,
    /// The protection ID of the pass's one metadata key (R15.1(2)).
    pub metadata_key: [u8; 16],
    /// The protection ID of the failure cohort key (R15.1(3)).
    pub failure_cohort_key: [u8; 16],
    /// `H("ScopeSet", rows)` of the pass scope set `S_pass`, the union of
    /// the due members' CIR1 scope rows (R11.1(2), R11.4(2)): the failure
    /// cohort key's scope set. The pipeline fills it from the plan.
    pub scope_set_digest: Hash,
}

/// A Reserve that passed every writer re-check and awaits its apply.
pub struct CommunityStagedReserveV1 {
    pub(super) key: (TimelineId, [u8; 16]),
    entry: CommunityPendingReservationV1,
    minted: Option<CommunityMintedObservationV1>,
    pub(super) record: CommunityPassRecordV1,
    pub(super) native_ordinal: u64,
    pub(super) pass_ordinal: u64,
    /// The CRI1 fields the pass was reserved over.
    pub(super) request: CommunityReservationRequestInputV1,
    /// The failure cohort key's scope set digest.
    pub(super) failure_scope: Hash,
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
pub struct CommunityStagedAbortV1 {
    key: (TimelineId, [u8; 16]),
    rows: u64,
}

impl MemoryCommunityDomainV1 {
    /// Re-check a Reserve at the writer (R10.7 step 5j) and stage it.
    ///
    /// An unresolved pass of T is refused here (`PassUnresolved`, code 7). A
    /// second reservation staged but not yet applied is invisible at stage
    /// and is refused only at [`Self::apply_reserve`].
    ///
    /// # Errors
    /// In order. `InvalidBinding` when the minted rows exceed the pass rows,
    /// when the request's T, G, identity or expected head differs from the
    /// call's, when the request is not a valid CRI1 (a requested horizon
    /// outside `1..=i64::MAX` too: a `run_pass` refusal never gives 2,
    /// R10.4(2)), when its prepared input set digest is not the pass facts'
    /// pairs', or when the pass facts disagree (members, trace rows, `F_p`,
    /// key IDs). `EvidenceUnavailable` with no installed horizons.
    /// `InvalidBinding` when the request names a profile other than the
    /// installed one or the roster keys or member rows do not fit the
    /// installed roster. `Conflict` for a reservation identity already
    /// recorded, resolved or not, and `PassUnresolved` (7) for another
    /// unresolved pass of T; these precede 5j, as R10.7 steps 4a and 4c do,
    /// and the byte-equal bound-content compare of R8.1(7) is the call
    /// layer's.
    ///
    /// Then `EvidenceUnavailable` for a Timeline with no pass state;
    /// `InvalidBinding` when T was initialized under another profile than
    /// the request names; and in the step-5j order `EvidenceUnavailable` for
    /// a reused reference no Reserve minted and for a Logical Head or chain
    /// that no longer matches the minted or the reused cut (12), with
    /// `InvalidBinding` for a call that names both or neither of a minted
    /// and a reused observation and for a minted observation that does not
    /// carry the ordinal the last 5h burn made and no Reserve consumed;
    /// `EvidenceExpired` (13) when `H_g` does not outlast the decision
    /// bound; `StaleGeneration` (5); `StaleFrontier` (6) for a moved head or
    /// counters, a reused observation of another generation or one that
    /// outlives less than `H_g`, a minted observation whose records end
    /// before `H_g`, or a budget the pending reservations now fill (the
    /// budget read's error otherwise); `Quarantined` (9);
    /// `CapacityExhausted` (14); `RecordingUnavailable` (19). Last,
    /// `CapacityExhausted` (14) when an ordinal has no next value and
    /// `InvalidBinding` when the CPR1 does not validate (an `H_r` outside
    /// `1..=i64::MAX`).
    pub fn stage_reserve(
        &self,
        input: CommunityReserveInputV1,
    ) -> Result<CommunityStagedReserveV1, Error> {
        let bound = input.minted.as_ref().map_or(0, |minted| minted.rows);
        let key = (input.timeline, input.reservation_operation_id);
        let (cri1, horizons) = self.check_identity(&input, key)?;
        let state = self.state_under_profile(&input)?;
        self.recheck_reserve(&input, state, horizons)?;
        // The Reserve allocates its native producer ordinal and its pass
        // ordinal in its own transaction (annex §4). Nothing is burned here.
        let outcome = horizons.horizons.outcome_micros;
        let (reservation, ordinals) = self.reservation_for(&input, &cri1, state, outcome)?;
        let facts = input.pass;
        // The materialization's rows bind in the Reserve transaction; the
        // entry holds only the rest and `F_p` (R13.1(4)).
        Ok(CommunityStagedReserveV1 {
            key,
            entry: CommunityPendingReservationV1::for_pass(
                input.pass_rows - bound,
                input.failure_reserve,
            ),
            record: CommunityPassRecordV1 {
                reserved: CommunityReservedPassV1 {
                    reservation,
                    cbq1_digest: facts.cbq1_digest,
                    quote_maxima: facts.quote_maxima,
                    trace_rows: facts.trace_rows,
                    members: facts.members,
                    metadata_key: facts.metadata_key,
                    failure_cohort_key: facts.failure_cohort_key,
                    generation_horizon_micros: horizons.horizons.generation_micros,
                    outcome_horizon_micros: outcome,
                },
                prior_shared_counts: input.prior_shared_counts,
                materialization: input.minted.as_ref().map(|minted| minted.additions),
                status: CommunityPassStatusV1::Reserved,
                sealed_result_digest: None,
                live: true,
            },
            minted: input.minted,
            native_ordinal: ordinals.0,
            pass_ordinal: ordinals.1,
            request: input.request,
            failure_scope: facts.scope_set_digest,
        })
    }

    /// T's pass state, checked against the request's profile.
    ///
    /// Returns `EvidenceUnavailable` with no pass state and `InvalidBinding`
    /// when T was initialized under another profile than the request names.
    /// [`Self::recheck_reserve`] relies on this and does not compare the
    /// profile again.
    fn state_under_profile(
        &self,
        input: &CommunityReserveInputV1,
    ) -> Result<&CommunityPassStateV1, Error> {
        let state = self
            .pass_states
            .get(&input.timeline)
            .ok_or(Error::EvidenceUnavailable)?;
        if state.profile_digest == input.request.profile_digest {
            Ok(state)
        } else {
            Err(Error::InvalidBinding)
        }
    }

    /// The CPR1 of a Reserve and the ordinals it allocated: the next native
    /// producer ordinal and the next pass ordinal of T.
    fn reservation_for(
        &self,
        input: &CommunityReserveInputV1,
        cri1: &CommunityReservationRequestV1,
        state: &CommunityPassStateV1,
        outcome: u64,
    ) -> Result<(CommunityReservationInputV1, (u64, u64)), Error> {
        let ordinals = self.next_ordinals(state)?;
        mint_reservation(input, cri1, ordinals, outcome).map(|reservation| (reservation, ordinals))
    }

    /// The next native producer ordinal (the burned counter's) and the next
    /// pass ordinal (T's floor's).
    ///
    /// Exhaustion gives 14 without closing the context, as `initialize`'s
    /// allocator does; the parent says exhaustion closes the context, which
    /// is unreachable in practice (a `u64` counter) and left to the
    /// context-closure slice.
    fn next_ordinals(&self, state: &CommunityPassStateV1) -> Result<(u64, u64), Error> {
        let native = self
            .native_producer_ordinal
            .checked_add(1)
            .ok_or(Error::CapacityExhausted)?;
        let pass = state
            .highest_pass_ordinal
            .checked_add(1)
            .ok_or(Error::CapacityExhausted)?;
        Ok((native, pass))
    }

    /// Burn the next native producer ordinal for a minted materialization.
    ///
    /// This is R10.7 step 5h (R9.7 step 4), the only step that burns an
    /// ordinal on its own: a later refusal leaves it burned, and a reused
    /// observation never calls it. A minted Reserve must carry the ordinal
    /// burned last and not yet consumed (3), so its nodes cannot collide with
    /// an earlier pass's producer ordinal. A Reserve that fails after the
    /// pipeline published the materialization's ARD1 rows leaves the burn
    /// outstanding; only the pipeline's mandatory 5h re-burn keeps the
    /// ordinal from being reused.
    ///
    /// # Errors
    /// Returns `CapacityExhausted` when the counter has no next ordinal; the
    /// counter is unchanged.
    pub fn burn_materialization_ordinal(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
    ) -> Result<u64, Error> {
        self.allocate_producer_ordinal().inspect(|ordinal| {
            self.burned_materialization = Some(*ordinal);
        })
    }

    /// `H_g`, `H_r` and the recording horizon, the writer's own from its
    /// sample and the installed horizons (R13.4(2)).
    ///
    /// The request must name the installed profile. Neither the reservation
    /// sample nor the recording horizon is read from the record: the
    /// pipeline must take the sample from the domain clock reservation.
    fn horizons_for(&self, input: &CommunityReserveInputV1) -> Result<WriterHorizonsV1, Error> {
        let policy = self.pass_horizons.ok_or(Error::EvidenceUnavailable)?;
        let horizons = reservation_horizons(
            policy.retention,
            policy.owners,
            input.reservation_sample_micros,
        );
        // One CQK1 per installed roster member and only installed roster rows
        // (R10.6): a short list would skip the whole-roster refusal 9.
        let roster = policy.roster_len;
        if input.roster_quarantine_keys.len() != roster
            || input
                .pass
                .members
                .iter()
                .any(|member| member.roster_index >= roster)
            || input.request.profile_digest != policy.profile_digest
        {
            return Err(Error::InvalidBinding);
        }
        Ok(WriterHorizonsV1 {
            horizons,
            recording_not_after_micros: policy.retention.recording_not_after_micros,
        })
    }

    /// The step-5j re-checks of a Reserve against T's state, in order: the
    /// Logical Head and chain (12), the decision bound (13), the
    /// generation (5), the head, counters and reuse horizon (6), the budget
    /// (6), the quarantine (9) and the caps (14, 19).
    ///
    /// The state is the one [`Self::state_under_profile`] returned, so T was
    /// initialized under the profile the request names.
    fn recheck_reserve(
        &self,
        input: &CommunityReserveInputV1,
        state: &CommunityPassStateV1,
        writer: WriterHorizonsV1,
    ) -> Result<(), Error> {
        // The Logical Head and chain compare comes first, with the
        // authority re-check (R10.7 step 5j: 12), for the cut a minted
        // observation observed and for the cut a reused one observed. A call
        // names exactly one.
        let (cut, retained) = match (&input.minted, input.reused) {
            (Some(minted), None) => {
                // R10.7 5h burned the ordinal the materialization's nodes
                // carry just before this Reserve, and nothing consumed it.
                if Some(minted.reference.producer_ordinal) != self.burned_materialization {
                    return Err(Error::InvalidBinding);
                }
                (&minted.cut, None)
            }
            (None, Some(reference)) => {
                let retained = state
                    .retained
                    .get(&reference)
                    .ok_or(Error::EvidenceUnavailable)?;
                (&retained.cut, Some(retained))
            }
            _ => return Err(Error::InvalidBinding),
        };
        self.check_cut(input.timeline, cut)?;
        // The State records this pass writes live to `H_g` (R13.2(2)): it
        // must outlast the pass's decision bound, as every selected record
        // must (annex §4; R13.2(5), R10.7 note M10: 13 at 5j).
        if writer.horizons.generation_micros <= decision_bound(input.reservation_sample_micros) {
            return Err(Error::EvidenceExpired);
        }
        check_frontier(state, input)?;
        // The reuse is of the same `(T, G)` and its records outlive `H_g`:
        // the pass's State records depend on the reused Observation CPN1 and
        // live to `H_g` (R9.2; R13.2(2), (4a); R10.7 steps 5c and 5j: 6).
        let reuse_stale = retained.is_some_and(|retained| {
            retained.generation != input.generation
                || retained.not_after_micros < writer.horizons.generation_micros
        });
        // A minted observation's records end at `H_g` at the earliest too:
        // the caller's horizon is judged, then kept for a later reuse.
        let mint_short = input
            .minted
            .as_ref()
            .is_some_and(|minted| minted.not_after_micros < writer.horizons.generation_micros);
        if reuse_stale || mint_short {
            return Err(Error::StaleFrontier);
        }
        self.check_reserve_budget(input)?;
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
                recording_not_after_micros: writer.recording_not_after_micros,
                reservation_sample_micros: input.reservation_sample_micros,
            },
            input.minted.is_some(),
        )
    }

    /// R9.7 step 6: T's Logical Head is still the cut's `through_seq`, T's
    /// chain hash at it and every Fork-prefix source's at its immutable
    /// Fork cut are the ones observed. The required cuts come from the
    /// topology, never from the caller.
    fn check_cut(
        &self,
        timeline: TimelineId,
        cut: &CommunityObservationCutV1,
    ) -> Result<(), Error> {
        let events: &dyn EventStore = &self.store;
        let observed = |owner: TimelineId, seq: u64| {
            cut.chain_heads.iter().any(|(entry, entry_seq, expected)| {
                *entry == owner
                    && *entry_seq == seq
                    && events
                        .chain_hash_at(owner, Seq::from_u64(seq))
                        .is_ok_and(|hash| hash == *expected)
            })
        };
        let head_holds = events
            .logical_head(timeline)
            .is_ok_and(|head| head.as_u64() == cut.through_seq);
        fork_segments(events, timeline, EVENT_READ_BOUNDS.max_fork_depth()).and_then(|segments| {
            // A segment starts one after its Fork cut, so a source's cut is
            // the next segment's start less one.
            let prefix_holds = segments
                .iter()
                .zip(segments.iter().skip(1))
                .all(|(source, child)| observed(source.0, child.1 - 1));
            if head_holds && observed(timeline, cut.through_seq) && prefix_holds {
                Ok(())
            } else {
                Err(Error::EvidenceUnavailable)
            }
        })
    }

    /// The request's binding to the call and the installed horizons it must
    /// fit (`InvalidBinding`), then the identity and T checks that R10.7
    /// steps 4a and 4c put before 5j: a recorded identity, resolved or not,
    /// is a replay (`Conflict`, R8.1(7)) and an unresolved pass of T is
    /// `PassUnresolved`. It returns the validated CRI1 and the horizons the
    /// Reserve is judged by.
    fn check_identity(
        &self,
        input: &CommunityReserveInputV1,
        key: (TimelineId, [u8; 16]),
    ) -> Result<(CommunityReservationRequestV1, WriterHorizonsV1), Error> {
        let cri1 = check_binding(input)?;
        let horizons = self.horizons_for(input)?;
        if self.pass_records.contains_key(&key) || self.pending_reservations.contains_key(&key) {
            return Err(Error::Conflict);
        }
        if self.unresolved_pass(input.timeline).is_some() {
            return Err(Error::PassUnresolved);
        }
        Ok((cri1, horizons))
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

    /// Apply a staged Reserve in the guarded step that published its records.
    ///
    /// It adds one retained outcome, the pending entry and the pass record
    /// (the CRI1 index entry, status Reserved) and, for a minted
    /// materialization, its additions to the counters, the closure terms and
    /// scope rows a reuse reads, the observation it retains for reuse and one
    /// more control operation.
    ///
    /// # Errors
    /// Returns `Conflict` when the reservation identity is recorded already,
    /// resolved or not, or when the ordinals staged are no longer the next
    /// ones (another burn or pass moved them), `PassUnresolved` (7) when
    /// another reservation of T is pending, and `EvidenceUnavailable` when
    /// the Timeline has no pass state; the domain is unchanged.
    pub fn apply_reserve(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: CommunityStagedReserveV1,
    ) -> Result<(), Error> {
        self.check_apply_reserve(&staged)?;
        self.publish_reserve(staged);
        Ok(())
    }

    /// Publish a checked Reserve: its ordinals, the burn its materialization
    /// consumes, the entry, the record and the pass state.
    pub(super) fn publish_reserve(&mut self, staged: CommunityStagedReserveV1) {
        let (timeline, _) = staged.key;
        self.native_producer_ordinal = staged.native_ordinal;
        if staged.minted.is_some() {
            // The burned ordinal is consumed by the materialization.
            self.burned_materialization = None;
        }
        self.pending_reservations.insert(staged.key, staged.entry);
        self.pass_records.insert(staged.key, staged.record);
        self.pass_states.entry(timeline).and_modify(|state| {
            state.highest_pass_ordinal = staged.pass_ordinal;
            record_reserve(state, staged.minted);
        });
    }

    /// The cheap re-validation of an apply: the identity checks, then the
    /// ordinals staged are still the next ones (`Conflict`).
    pub(super) fn check_apply_reserve(
        &self,
        staged: &CommunityStagedReserveV1,
    ) -> Result<(), Error> {
        self.check_apply_identity(staged.key)?;
        self.check_ordinals(staged)
    }

    /// The identity is not recorded (`Conflict`), T has no other pending
    /// reservation (`PassUnresolved`) and has pass state
    /// (`EvidenceUnavailable`).
    fn check_apply_identity(&self, key: (TimelineId, [u8; 16])) -> Result<(), Error> {
        let (timeline, _) = key;
        if self.pending_reservations.contains_key(&key) || self.pass_records.contains_key(&key) {
            return Err(Error::Conflict);
        }
        if self
            .pending_reservations
            .range((timeline, [0; 16])..=(timeline, [u8::MAX; 16]))
            .next()
            .is_some()
        {
            return Err(Error::PassUnresolved);
        }
        if !self.pass_states.contains_key(&timeline) {
            return Err(Error::EvidenceUnavailable);
        }
        Ok(())
    }

    /// The ordinals staged are still the next ones: another burn or pass in
    /// between makes the token stale (`Conflict`). Through
    /// `publish_reserved_pass` the CSI1 successor refuses such a token first,
    /// with `InvalidBinding`, so this compare serves `apply_reserve`.
    fn check_ordinals(&self, staged: &CommunityStagedReserveV1) -> Result<(), Error> {
        let next_pass = self
            .pass_states
            .get(&staged.key.0)
            .and_then(|state| state.highest_pass_ordinal.checked_add(1));
        if next_pass == Some(staged.pass_ordinal)
            && self.native_producer_ordinal.checked_add(1) == Some(staged.native_ordinal)
        {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }

    /// Check a Commit against its pending entry: it binds no more rows than
    /// the entry holds (R13.1(4)).
    ///
    /// It does not require the pass to be Sealed: that rule is A5's, which
    /// reads the record's status before it stages the Commit.
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

    /// Apply a staged Commit in the guarded step that published its records.
    ///
    /// The entry is removed (the rows it bound are the pipeline's own
    /// batch's). The counters, selected graph, head and closure advance, the
    /// materialization's records are in the closure and each Annotation CPN1
    /// is one more control operation.
    ///
    /// # Errors
    /// Returns the [`Self::stage_commit`] refusals again: the entry must
    /// still be pending and still hold the rows bound; the domain is
    /// unchanged.
    pub fn apply_commit(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: CommunityStagedCommitV1,
    ) -> Result<(), Error> {
        let input = staged.0;
        let key = (input.timeline, input.reservation_operation_id);
        self.entry_of(key, input.bound_rows).map(|()| {
            self.pending_reservations.remove(&key);
            self.set_pass_status(key.0, key.1, CommunityPassStatusV1::Committed);
            self.pass_states.entry(input.timeline).and_modify(|state| {
                state.counters = add_counts(state.counters, input.additions);
                state.graph = input.graph;
                state.head = input.selected_head;
                state.closure.extend(input.closure);
                if let Some(observation) = input.observation {
                    state.observations.remove(&observation);
                }
                state.scope_rows.extend(input.scope_rows);
                let counts = state.generations.entry(state.generation).or_default();
                counts.annotations = counts.annotations.saturating_add(input.annotations);
            });
        })
    }

    /// Check an Abort against its pending entry: it registers no more rows
    /// than the entry holds, and no cap or budget refuses it (R13.1(5)).
    ///
    /// It does not check the live call: an Abort of a pass whose `run_pass`
    /// call is live gives 15 in A4e-2 (R8.3(3)), from the record's `live`.
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
            .map(|()| CommunityStagedAbortV1 {
                key,
                rows: registered_rows,
            })
    }

    /// Apply a staged Abort in the guarded step that published its records.
    ///
    /// The entry is removed (the rows it registered are the pipeline's own
    /// batch's). The retained outcome, the materialization's counters,
    /// control operation and closure terms stay, so the next pass reuses its
    /// records (R13.1(4)).
    ///
    /// # Errors
    /// Returns the [`Self::stage_abort`] refusals again: the entry must
    /// still be pending and still hold the rows registered; the domain is
    /// unchanged.
    pub fn apply_abort(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: &CommunityStagedAbortV1,
    ) -> Result<(), Error> {
        let CommunityStagedAbortV1 { key, rows } = *staged;
        self.entry_of(key, rows).map(|()| {
            self.pending_reservations.remove(&key);
            self.set_pass_status(key.0, key.1, CommunityPassStatusV1::Aborted);
        })
    }

    fn entry_of(&self, key: (TimelineId, [u8; 16]), rows: u64) -> Result<(), Error> {
        if !self.pass_states.contains_key(&key.0) {
            return Err(Error::EvidenceUnavailable);
        }
        // A pending entry belongs to an unresolved pass (R13.1(4)); the
        // Sealed-before-Commit rule is A5's and the live-call 15 is
        // A4e-2's, both on the record's status and `live` flag.
        let held = self.pending_reservations.get(&key).filter(|_| {
            self.pass_records
                .get(&key)
                .is_some_and(|record| record.status.unresolved())
        });
        match held {
            Some(entry) if rows <= entry.rows => Ok(()),
            _ => Err(Error::InvalidBinding),
        }
    }
}

/// The request is a valid CRI1 of the call's own, and the pass facts agree
/// (R8.1(7), R15.3(2), R15.5).
///
/// One member digest row per due member, ascending by roster index,
/// `n_due + 1` trace rows, `F_p` of two targets each, two distinct key IDs,
/// and no more minted rows than pass rows. An invalid CRI1 (a zero digest or
/// identity, a requested horizon outside `1..=i64::MAX`) is 3: a `run_pass`
/// refusal never gives 2 (R10.4(2)).
fn check_binding(input: &CommunityReserveInputV1) -> Result<CommunityReservationRequestV1, Error> {
    let request = input.request;
    let facts = &input.pass;
    let due = facts.members.len() as u64;
    let ascending = facts
        .members
        .iter()
        .zip(facts.members.iter().skip(1))
        .all(|(earlier, later)| earlier.roster_index < later.roster_index);
    if (
        request.timeline,
        request.generation,
        request.reservation_operation_id,
        request.expected_head_digest,
    ) != (
        input.timeline,
        input.generation,
        input.reservation_operation_id,
        input.selected_head,
    ) || due == 0
        || !ascending
        || facts.trace_rows != due + 1
        || input.failure_reserve != facts.trace_rows.saturating_mul(2)
        || facts.metadata_key == facts.failure_cohort_key
        || input
            .minted
            .as_ref()
            .is_some_and(|minted| minted.rows > input.pass_rows)
        || !names_the_members(input)
    {
        Err(Error::InvalidBinding)
    } else {
        CommunityReservationRequestV1::new(request).map_err(|_| Error::InvalidBinding)
    }
}

/// The request's prepared input set is the pass facts' `[cmb1, cin1]` pairs
/// ordered by member digest (parent annex, "prepared input set preimage").
fn names_the_members(input: &CommunityReserveInputV1) -> bool {
    let mut pairs: Vec<(Hash, Hash)> = input
        .pass
        .members
        .iter()
        .map(|member| (member.cmb1_digest, member.cin1_digest))
        .collect();
    pairs.sort_by_key(|pair| pair.0);
    community_prepared_input_set_digest_v1(&pairs) == Ok(input.request.prepared_input_set_digest)
}

/// The CPR1 of a Reserve: the pass key and native producer ordinal it
/// allocated, the CRI1 digest and the request's own bindings.
///
/// A CPR1 that does not validate (an `H_r` outside `1..=i64::MAX`) is 3, not
/// 2 (R10.4(2)).
fn mint_reservation(
    input: &CommunityReserveInputV1,
    cri1: &CommunityReservationRequestV1,
    ordinals: (u64, u64),
    evidence_not_after_micros: u64,
) -> Result<CommunityReservationInputV1, Error> {
    let request = input.request;
    CommunityPassKeyV1::new(input.timeline, input.generation, ordinals.1)
        .and_then(|pass_key| {
            CommunityReservationV1::new(CommunityReservationInputV1 {
                pass_key,
                request_digest: cri1.digest(),
                native_producer_ordinal: ordinals.0,
                predecessor_head_digest: request.expected_head_digest,
                roster_digest: request.roster_digest,
                prepared_input_set_digest: request.prepared_input_set_digest,
                profile_digest: request.profile_digest,
                evidence_not_after_micros,
            })
        })
        .map(|reservation| *reservation.as_input())
        // The CPR1 constructor refuses an `H_r` outside `1..=i64::MAX` with 2;
        // a `run_pass` refusal never gives 2 (R10.4(2)), so it is 3. The
        // installation checks guarantee `H_r <= H_g <= i64::MAX`, so this is
        // reached only by writing the installed horizons directly.
        .map_err(|_| Error::InvalidBinding)
}

/// The CSI1 plaintext a Reserve's committed successor holds.
///
/// It carries the burned native producer ordinal and T's new pass floor
/// (annex §4, "Identity floor"), every other field and floor row kept.
/// Sealing it under the pass's metadata key and swapping it in are the
/// record publication's (A4c-3c-ii).
///
/// # Errors
/// Returns `EvidenceUnavailable` for a CSI1 that is malformed or has no
/// floor row for T, `ContextClosed` (17) for a floor closed to new
/// allocation, `StaleGeneration` (5) when T's active generation is not
/// `generation`, and `InvalidBinding` for an ordinal that is not above the
/// CSI1's native ordinal or not the next of T's floor.
pub fn community_reserve_selection_v1(
    current: &[u8],
    timeline: TimelineId,
    generation: [u8; 16],
    native_ordinal: u64,
    pass_ordinal: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let selection = CommunitySelectionV1::from_canonical_cbor(current)
        .map_err(|_| Error::EvidenceUnavailable)?;
    let fields = selection.as_input();
    let mut floors = fields
        .timeline_floors
        .iter()
        .collect::<Result<Vec<_>, Error>>()?;
    let floor = floors
        .iter_mut()
        .find(|floor| floor.timeline == timeline)
        .ok_or(Error::EvidenceUnavailable)?;
    if floor.closed {
        return Err(Error::ContextClosed);
    }
    if floor.active_generation != Some(generation) {
        return Err(Error::StaleGeneration);
    }
    if native_ordinal <= fields.highest_native_producer_ordinal
        || floor.highest_pass_ordinal.checked_add(1) != Some(pass_ordinal)
    {
        return Err(Error::InvalidBinding);
    }
    floor.highest_pass_ordinal = pass_ordinal;
    CommunitySelectionV1::new(CommunitySelectionInputV1 {
        store_incarnation: fields.store_incarnation,
        installed_catalogue_digest: fields.installed_catalogue_digest,
        native_profile_digest: fields.native_profile_digest,
        highest_native_producer_ordinal: native_ordinal,
        timeline_floors: CommunityTimelineFloorsV1::from_floors(&floors),
        metadata_not_after_micros: fields.metadata_not_after_micros,
    })
    .map(|successor| successor.to_canonical_cbor())
}

/// One more retained outcome and, for a minted materialization, its
/// additions to the counters, its closure terms and scope rows, the
/// observation it retains for reuse and one more control operation.
fn record_reserve(state: &mut CommunityPassStateV1, minted: Option<CommunityMintedObservationV1>) {
    let counts = state.generations.entry(state.generation).or_default();
    counts.outcomes = counts.outcomes.saturating_add(1);
    if let Some(minted) = minted {
        counts.materializations = counts.materializations.saturating_add(1);
        state.counters = add_counts(state.counters, minted.additions);
        state.observations.insert(minted.reference, minted.graph);
        state.retained.insert(
            minted.reference,
            CommunityRetainedObservationV1 {
                generation: state.generation,
                not_after_micros: minted.not_after_micros,
                cut: minted.cut,
            },
        );
        state
            .scope_rows
            .insert(minted.scope_reference, minted.scope);
    }
}

/// The generation (5), then the head and the counters (6), the call was
/// planned over: R10.7 step 5j.
fn check_frontier(
    state: &CommunityPassStateV1,
    input: &CommunityReserveInputV1,
) -> Result<(), Error> {
    if state.generation != input.generation {
        return Err(Error::StaleGeneration);
    }
    if state.head != input.selected_head || state.counters != input.prior_shared_counts {
        return Err(Error::StaleFrontier);
    }
    Ok(())
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
