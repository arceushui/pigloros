//! The backend-neutral `run_pass` planner (#560 A4b-1; ADR-129 revision 10).
//!
//! It runs the planner-side checks of the ordered R10.7 table, after the
//! call's discovery (step 4a, the Reserve index of A4c) found no original
//! operation:
//!
//! - step 4 ([`plan_community_pass_v1`]): 4b a per-T active operation (15),
//!   4c an unresolved pass under another identity (7), 4d the stale boundary
//!   (6, R10.5), 4e a quarantined roster member (9, R10.6), 4f an expired
//!   generation or selected-root horizon (13), and 4g an empty due set,
//!   which is `NoPass` (R10.1, R10.2);
//! - step 5d and 5e ([`CommunityPassDueV1::admit`]): the retained-outcome
//!   and control-operation caps (14, R10.4(4)) and the recording horizon
//!   (19, R10.4(3));
//! - step 5g ([`CommunityPassDueV1::quote`]), in the R11.5(1) order as
//!   revision 13 restates it (R13.4(1)): the R10.3 CBQ1 quote, the live key
//!   count (R11.1(6)), the ARD1 graph demand (R11.3), the erasure-target
//!   budget (R13.1(3)), the pass CSB1/CPV1 bounds (R11.4(1)–(3)) and the CAU1
//!   object bound (R11.4(4)), each State demand first (14) and then with the
//!   recording (19).
//!
//! Steps 5a–5c (the step-5 decisions, the trust gate and the observation
//! reuse decision) and 5f (the materialization's history read and fold) run
//! between these calls, in the Reserve pipeline (A4c). The R10.4(5)
//! installation check is [`check_community_pass_installation_v1`].
//!
//! The planner reads the domain only through [`CommunityQuarantineIndexV1`]
//! and [`CommunityPassReadPortV1`] and commits nothing: every backend's `run_pass` uses the same planner,
//! and the Reserve writer re-checks generation, head, counters, quarantine,
//! caps and the recording horizon (R10.7 step 5j).

use std::collections::{BTreeMap, BTreeSet};

use pos_core::community_lifecycle::{
    community_member_due_v1, CommunityDurableProfileV1, CommunityGraphCountsV1,
    CommunityHostProgressV1, CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1,
    CommunityPassDemandV1, CommunityPassDomainV1, CommunityPassGraphTermsV1,
    CommunityPassObservationV1, CommunityPassQuoteInputV1, CommunityPassQuoteMemberV1,
    CommunityPassQuoteV1, CommunityPreparedInvocationInputV1, CommunityProtectionSizesV1,
    CommunityQuarantineKeyV1, CommunityQuarantineReasonV1, CommunityScopeMemberV1,
    CommunitySharedCountsV1, CommunityTypedInputRefV1, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_DECISION_DEADLINE_MICROS_V1, COMMUNITY_ERASURE_ROW_LIMIT_V1,
    COMMUNITY_ERASURE_TARGET_LINE_V1, COMMUNITY_RETAINED_PASS_OUTCOMES_V1,
    MAX_COMMUNITY_COVERAGE_ROWS_V1, MAX_COMMUNITY_SCOPE_MEMBERS_V1,
};
use pos_core::{EntityId, Hash, TimelineId};

use super::erasure_budget::{
    CommunityErasureActorV1, CommunityErasureBudgetPortV1, CommunityErasureBudgetV1,
    CommunityPendingErasureV1,
};
#[cfg(target_os = "linux")]
use super::memory_domain::MemoryCommunityDomainV1;
use super::observation::{CommunityObservationQuoteV1, CommunityObservationSourcesV1};

/// The domain's quarantine index read (R10.6(2)).
///
/// Like [`super::store_domain::CommunityStoreDomainV1`], the trait is
/// nominally `pub` only because the public planner is generic over it; it
/// is re-exported nowhere, so no caller outside `community` can implement
/// it. [`MemoryCommunityDomainV1`] serves it from its A4e-1 quarantine
/// index.
pub trait CommunityQuarantineIndexV1 {
    /// The active reason set of the index row of the CQK1 whose digest is
    /// `key`: `None` when no row exists, which in an open context means the
    /// member was never quarantined, or its 0..=4 active reasons. A row
    /// closed due to unavailable evidence has a non-empty set (R10.6(2)–(3)).
    fn quarantine_reasons(&self, key: Hash) -> Option<Vec<CommunityQuarantineReasonV1>>;
}

#[cfg(target_os = "linux")]
impl CommunityQuarantineIndexV1 for MemoryCommunityDomainV1 {
    fn quarantine_reasons(&self, key: Hash) -> Option<Vec<CommunityQuarantineReasonV1>> {
        self.quarantine_index
            .get(&key)
            .map(|ledger| ledger.reasons.iter().map(|row| row.reason).collect())
    }
}

/// The other domain reads the planner needs, under the call's guard: the
/// recorded-set counters (R10.3(6)), the retained-outcome and
/// control-operation counts (R10.4(4)), the live key count (R11.1(6)), the
/// selected CGR1 counts and closure index (R11.3) and the scope rows of the
/// step inputs (R11.4(3)). They are domain-private and have no wire form;
/// the Memory domain adds their storage and implements this port in A4c.
/// Its supertrait is the erasure-budget read (R13.1(2)), which the Memory
/// domain already serves. The trait is re-exported nowhere.
pub trait CommunityPassReadPortV1: CommunityErasureBudgetPortV1 {
    /// T's cumulative recorded-set counters (R10.3(6)).
    fn recorded_set_counters(&self, timeline: TimelineId) -> CommunitySharedCountsV1;

    /// The passes of `(T, G)` that hold a CPR1 whose detailed outcome is
    /// not yet disposed: Committed, Aborted and unresolved (R10.4(4)).
    fn retained_pass_outcomes(&self, timeline: TimelineId, generation: [u8; 16]) -> u64;

    /// The retained control and protection operations of `(T, G)`
    /// (R10.4(4)).
    fn control_operations(&self, timeline: TimelineId, generation: [u8; 16]) -> u64;

    /// The domain's live key count: CKP1 keys in its key vault that are not
    /// Tombstoned (R11.1(6)).
    fn live_keys(&self) -> u64;

    /// T's selected CGR1 `graph_counts`: the initialization CGR1's for an
    /// Initial frontier (R11.3(1)).
    fn selected_graph(&self, timeline: TimelineId) -> CommunityGraphCountsV1;

    /// Whether a CES1 with this logical digest is already in T's selected
    /// closure, from the closure index (R11.3(3)).
    fn event_source_in_closure(&self, timeline: TimelineId, event_source: Hash) -> bool;

    /// What a reused Observation CPN1's materialization adds to T's selected
    /// closure: its exact records when they are not yet in it (an Aborted
    /// Reserve), zero when they are (R11.3(3)).
    fn observation_graph(
        &self,
        timeline: TimelineId,
        observation: CommunityNativeNodeReferenceV1,
    ) -> CommunityPassGraphTermsV1;

    /// A mode-0, mode-1 or mode-2 ref's scope rows (R11.4(3)): a native
    /// node's from the CSB1 of the operation that minted it, an Event's or
    /// CES1's from its owning Timeline's one whole-Timeline row.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when the rows cannot be read.
    fn scope_rows(
        &self,
        timeline: TimelineId,
        reference: CommunityTypedInputRefV1<'_>,
    ) -> Result<Vec<CommunityScopeMemberV1>, Error>;

    /// The worst-case demand of `actor`'s unresolved reservations, every T
    /// of its scope (R13.1(4)), from the A4c pending-reservation ledger. The
    /// planner adds it to the committed budget.
    fn pending_erasure_demand(&self, actor: EntityId) -> CommunityPendingErasureV1;
}

/// Installed composition inputs of the planner. None comes from a caller.
#[derive(Clone, Copy)]
pub struct CommunityPassInstallationV1<'a> {
    /// The installed CDP1 of T's active generation.
    pub profile: &'a CommunityDurableProfileV1<'a>,
    /// Each roster row's CNT1 State limit `S_m`, in roster order, from
    /// pos-runtime's `community_state_limits_v1`, as for initialize.
    pub state_limit_bytes: &'a [u64],
}

/// One roster member's committed progress, read under the guard.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityPassMemberViewV1 {
    /// The member's CMB1 digest, from the generation's CGI1 roster.
    pub member_binding_digest: Hash,
    /// The member's committed CMS1 `last_step_sim_time`.
    pub last_step_simulation_time: Option<u64>,
}

/// T's selected state that the backend read under the guard (R10.5: the
/// caller names no generation or head).
#[derive(Clone, Copy)]
pub struct CommunityPassViewV1<'a> {
    /// The selected CST1, which names T and its active generation G.
    pub host_progress: &'a CommunityHostProgressV1,
    /// Every roster member's progress, in roster order.
    pub members: &'a [CommunityPassMemberViewV1],
    /// Another operation is active on T (step 4b).
    pub operation_active: bool,
    /// T has an unresolved pass under another identity (step 4c).
    pub unresolved_pass: bool,
    /// The selected head root's `evidence_not_after`: the CGR1's for a
    /// Committed frontier, the CGA1's for Initial (step 4f).
    pub selected_root_not_after_micros: u64,
}

/// The `run_pass` request values the planner judges.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityPassRequestV1 {
    /// Requested host Tick.
    pub tick: u64,
    /// Requested Simulation Time, in nanoseconds.
    pub simulation_time: u64,
    /// `t_r`, the call's trusted-clock reservation sample.
    pub reservation_sample_micros: u64,
}

/// One due member's step inputs for the quote, assembled by the Reserve
/// pipeline before step 5g (R10.3(4)).
#[derive(Clone, Copy)]
pub struct CommunityPassStepInputsV1<'a> {
    /// The member's exact CIN1 fields; the provenance root is ignored.
    pub prepared_invocation: CommunityPreparedInvocationInputV1<'a>,
    /// The member's CIR1 refs, except a ref to an observation this call
    /// mints.
    pub step_inputs: &'a [CommunityTypedInputRefV1<'a>],
    /// Whether the member's CIR1 also names the Observation CPN1 this call
    /// mints.
    pub consumes_minted_observation: bool,
}

/// A planned pass: the step-4 result.
pub enum CommunityPassPlanV1<'a> {
    /// No roster member is due (R10.2): no Reserve, ordinal, CRI1 index
    /// entry, materialization or CBQ1, and no step-5 decision.
    NoPass,
    /// At least one member is due.
    Due(CommunityPassDueV1<'a>),
}

/// A pass with a non-empty due set, ready for steps 5d–5g.
pub struct CommunityPassDueV1<'a> {
    installation: CommunityPassInstallationV1<'a>,
    view: CommunityPassViewV1<'a>,
    request: CommunityPassRequestV1,
    due: Vec<usize>,
}

/// Steps 4b–4g of the R10.7 table, in order; the first failing check
/// returns.
///
/// Two composition preconditions come first; they are not R10.7 steps.
/// The installed State limits must cover the roster (a composition error,
/// `InvalidBinding`), and the view must carry one member per roster row
/// (`EvidenceUnavailable`, as R8.1(8) step 3b treats a roster mismatch).
/// The caller (A4c) must supply `view.members` in roster order, each with
/// the CMB1 digest that the generation's CGI1 `ordered_CMB1_digests` lists
/// for that row; the planner does not re-derive the CMB1s.
///
/// # Errors
/// Returns `InvalidBinding` when the installed State limits do not cover
/// the roster; `EvidenceUnavailable` when the view's members do not cover
/// the roster; then `OperationActive` (4b), `PassUnresolved` (4c),
/// `StaleFrontier` (4d), `Quarantined` (4e) with the CQK1 errors of a
/// roster row, and `EvidenceExpired` (4f).
pub fn plan_community_pass_v1<'a, Q: CommunityQuarantineIndexV1>(
    index: &Q,
    installation: CommunityPassInstallationV1<'a>,
    view: CommunityPassViewV1<'a>,
    request: CommunityPassRequestV1,
) -> Result<CommunityPassPlanV1<'a>, Error> {
    let roster = installation.profile.as_input().roster.len();
    if installation.state_limit_bytes.len() != roster {
        return Err(Error::InvalidBinding);
    }
    if view.members.len() != roster {
        return Err(Error::EvidenceUnavailable);
    }
    active(view)
        .and_then(|()| stale(view.host_progress, request))
        .and_then(|()| quarantine(index, installation, view.host_progress.timeline()))
        .and_then(|()| expiry(installation, view, request))
        .map(|()| {
            let due = due_members(installation, view, request);
            if due.is_empty() {
                CommunityPassPlanV1::NoPass
            } else {
                CommunityPassPlanV1::Due(CommunityPassDueV1 {
                    installation,
                    view,
                    request,
                    due,
                })
            }
        })
}

/// Steps 4b and 4c.
const fn active(view: CommunityPassViewV1<'_>) -> Result<(), Error> {
    if view.operation_active {
        Err(Error::OperationActive)
    } else if view.unresolved_pass {
        Err(Error::PassUnresolved)
    } else {
        Ok(())
    }
}

/// Step 4d (R10.5): a request below a committed CST1 value is stale.
fn stale(progress: &CommunityHostProgressV1, request: CommunityPassRequestV1) -> Result<(), Error> {
    let below =
        |committed: Option<u64>, requested: u64| committed.is_some_and(|value| requested < value);
    if below(progress.host_tick(), request.tick)
        || below(progress.simulation_time(), request.simulation_time)
    {
        Err(Error::StaleFrontier)
    } else {
        Ok(())
    }
}

/// Step 4e (R10.6): any roster member, due or not, with a non-empty active
/// reason set gives 9.
fn quarantine<Q: CommunityQuarantineIndexV1>(
    index: &Q,
    installation: CommunityPassInstallationV1<'_>,
    timeline: TimelineId,
) -> Result<(), Error> {
    installation
        .profile
        .as_input()
        .roster
        .iter()
        .try_for_each(|member| {
            CommunityQuarantineKeyV1::new(timeline, member.stable_entry(), member.implementation())
                .and_then(|key| {
                    if index
                        .quarantine_reasons(key.digest())
                        .is_some_and(|reasons| !reasons.is_empty())
                    {
                        Err(Error::Quarantined)
                    } else {
                        Ok(())
                    }
                })
        })
}

/// Step 4f: the generation horizon and the selected root's horizon must
/// outlast `t_r` plus the decision deadline.
const fn expiry(
    installation: CommunityPassInstallationV1<'_>,
    view: CommunityPassViewV1<'_>,
    request: CommunityPassRequestV1,
) -> Result<(), Error> {
    let bound = deadline(request);
    let generation = installation
        .profile
        .as_input()
        .retention
        .generation_not_after_micros;
    if generation <= bound || view.selected_root_not_after_micros <= bound {
        Err(Error::EvidenceExpired)
    } else {
        Ok(())
    }
}

/// `t_r` plus the CDP1 decision deadline (27 s).
const fn deadline(request: CommunityPassRequestV1) -> u64 {
    decision_bound(request.reservation_sample_micros)
}

/// `t_r` plus the decision deadline, for a reservation sample `t_r`.
const fn decision_bound(reservation_sample_micros: u64) -> u64 {
    reservation_sample_micros.saturating_add(COMMUNITY_DECISION_DEADLINE_MICROS_V1)
}

/// The counts and horizons that steps 5d and 5e, and the Reserve writer's
/// re-check of them (step 5j), judge.
#[derive(Clone, Copy)]
pub(super) struct CommunityPassCapsV1 {
    pub(super) outcomes: u64,
    pub(super) operations: u64,
    pub(super) recording_not_after_micros: u64,
    pub(super) reservation_sample_micros: u64,
}

/// Steps 5d and 5e: the retained-outcome cap, the control-operation cap
/// when minting (14), then the recording horizon (19). The one
/// implementation the planner and the Reserve writer share.
pub(super) const fn admit_caps(caps: CommunityPassCapsV1, minting: bool) -> Result<(), Error> {
    if caps.outcomes >= COMMUNITY_RETAINED_PASS_OUTCOMES_V1
        || (minting && caps.operations >= COMMUNITY_CONTROL_OPERATIONS_V1)
    {
        Err(Error::CapacityExhausted)
    } else if caps.recording_not_after_micros <= decision_bound(caps.reservation_sample_micros) {
        Err(Error::RecordingUnavailable)
    } else {
        Ok(())
    }
}

/// Step 4g (R10.1): the due roster indices, in roster order.
fn due_members(
    installation: CommunityPassInstallationV1<'_>,
    view: CommunityPassViewV1<'_>,
    request: CommunityPassRequestV1,
) -> Vec<usize> {
    installation
        .profile
        .as_input()
        .roster
        .iter()
        .zip(view.members)
        .enumerate()
        .filter(|(_, (member, progress))| {
            community_member_due_v1(
                progress.last_step_simulation_time,
                member.cadence_interval_ns(),
                request.simulation_time,
            )
        })
        .map(|(index, _)| index)
        .collect()
}

impl CommunityPassDueV1<'_> {
    /// The due members' roster indices, in roster order. All of them are
    /// invoked in one atomic pass (R10.1).
    #[must_use]
    pub fn due_members(&self) -> &[usize] {
        &self.due
    }

    /// Steps 5d and 5e: the retained-outcome cap, the control-operation cap
    /// when this call mints its observation (R10.4(4)), then the recording
    /// horizon (R10.4(3)). A reused observation needs no control operation.
    ///
    /// # Errors
    /// Returns `CapacityExhausted` when a new reservation or a minted
    /// materialization would exceed its cap, and `RecordingUnavailable` when
    /// `recording_not_after_micros` is at most `t_r` plus the decision
    /// deadline.
    pub fn admit<P: CommunityPassReadPortV1>(&self, port: &P, minting: bool) -> Result<(), Error> {
        let timeline = self.view.host_progress.timeline();
        let generation = self.view.host_progress.generation();
        let outcomes = port.retained_pass_outcomes(timeline, generation);
        let operations = port.control_operations(timeline, generation);
        let recording = self
            .installation
            .profile
            .as_input()
            .retention
            .recording_not_after_micros;
        admit_caps(
            CommunityPassCapsV1 {
                outcomes,
                operations,
                recording_not_after_micros: recording,
                reservation_sample_micros: self.request.reservation_sample_micros,
            },
            minting,
        )
    }

    /// Step 5g in the R11.5(1) order with the R13.4(1) budget: the R10.3
    /// CBQ1 quote, the live key count, the ARD1 graph demand, the erasure
    /// budget, the pass CSB1/CPV1 bounds and the CAU1 object bound. Each is
    /// checked for State demand first and then with the recording
    /// (R10.4(2)).
    ///
    /// `steps` has one entry per due member, in due order.
    ///
    /// # Errors
    /// Returns `InvalidBinding` when `steps` does not cover the due set or a
    /// member's scope differs from the pass scope (R11.1(2)); the quote
    /// errors of [`CommunityPassQuoteV1::new`], the stage-2 errors of a
    /// minted observation and the port's scope-read and budget-read errors;
    /// then `CapacityExhausted` when a State demand does not fit and
    /// `RecordingUnavailable` when only a full demand does not.
    pub fn quote<P: CommunityPassReadPortV1>(
        &self,
        port: &P,
        steps: &[CommunityPassStepInputsV1<'_>],
        observation: CommunityPassObservationUseV1<'_>,
    ) -> Result<CommunityPassQuotedV1, Error> {
        if steps.len() != self.due.len() {
            return Err(Error::InvalidBinding);
        }
        let timeline = self.view.host_progress.timeline();
        CommunityProtectionSizesV1::new(timeline, self.view.host_progress.generation())
            .and_then(|sizes| share(port, timeline, &sizes, observation))
            .and_then(|share| {
                self.pass_quote(port, steps, share.observation)
                    .and_then(|quote| {
                        quote
                            .require_fit()
                            .and_then(|()| quote.demand(share.domain(port, timeline)))
                            .and_then(|demand| {
                                demand
                                    .require_keys()
                                    .and_then(|()| demand.require_graph())
                                    .and_then(|()| erasure_budget(port, timeline, &demand))
                                    .and_then(|trace_rows| {
                                        scope_bounds(port, timeline, steps, &share.scope)
                                            .and_then(|()| demand.require_objects())
                                            .map(|()| (demand, trace_rows))
                                    })
                            })
                            .map(|(demand, trace_rows)| CommunityPassQuotedV1 {
                                quote,
                                demand,
                                trace_rows,
                            })
                    })
            })
    }

    fn pass_quote<P: CommunityPassReadPortV1>(
        &self,
        port: &P,
        steps: &[CommunityPassStepInputsV1<'_>],
        observation: Option<CommunityPassObservationV1>,
    ) -> Result<CommunityPassQuoteV1, Error> {
        let profile = self.installation.profile;
        let roster = profile.as_input().roster;
        let members: Vec<_> = self
            .due
            .iter()
            .zip(steps)
            .map(|(index, step)| CommunityPassQuoteMemberV1 {
                member_binding_digest: self.view.members[*index].member_binding_digest,
                negotiated_tuple_digest: roster[*index].digests()[2],
                state_limit_bytes: self.installation.state_limit_bytes[*index],
                prepared_invocation: step.prepared_invocation,
                step_inputs: step.step_inputs,
                consumes_minted_observation: step.consumes_minted_observation,
            })
            .collect();
        let timeline = self.view.host_progress.timeline();
        CommunityPassQuoteV1::new(CommunityPassQuoteInputV1 {
            timeline,
            generation: self.view.host_progress.generation(),
            profile_digest: profile.digest(),
            prior_shared_counts: port.recorded_set_counters(timeline),
            members: &members,
            minted_observation: observation,
        })
    }
}

/// A pass that fits step 5g: its CBQ1 quote, the demands it was checked
/// with and the trace headroom.
pub struct CommunityPassQuotedV1 {
    quote: CommunityPassQuoteV1,
    demand: CommunityPassDemandV1,
    trace_rows: u64,
}

impl CommunityPassQuotedV1 {
    /// The pass CBQ1 quote.
    #[must_use]
    pub const fn quote(&self) -> &CommunityPassQuoteV1 {
        &self.quote
    }

    /// The key, graph, object and erasure demands over the guarded domain
    /// counts; the Reserve writer records the erasure rows and `F_p` as the
    /// pass's pending entry (R13.1(4)).
    #[must_use]
    pub const fn demand(&self) -> &CommunityPassDemandV1 {
        &self.demand
    }

    /// The trace rows (CAT1, GCA1 and Annotation CPN1s) the erasure budget
    /// still admits after the State, recording and `F_p` demand, in every
    /// actor's scope; the rest are omitted with reason 3 `AnnotationBudget`
    /// (R13.1(3)). `u64::MAX` when T has no actor to bound it.
    #[must_use]
    pub const fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
}

/// R13.1(3) at step 5g: for every actor of T's scope, the committed
/// `targets(A)`, the pending reservations, `F_q(A)`, `F_p` and the pass's
/// State rows at two targets each stay within the community line, and every
/// `rows(U)` with its pending rows and its `F_q^rows(U)`, T's also with the
/// new rows and the `F_p` rows, within 4,096: else 14. Then the same with the recording
/// rows: else 19. The result is the trace rows still admitted.
fn erasure_budget<P: CommunityPassReadPortV1>(
    port: &P,
    timeline: TimelineId,
    demand: &CommunityPassDemandV1,
) -> Result<u64, Error> {
    port.erasure_budget(timeline).and_then(|budget| {
        let [state, total] = demand.erasure_rows();
        let rooms: Vec<[Option<u64>; 2]> = budget
            .actors
            .iter()
            .map(|actor| {
                let pending = port.pending_erasure_demand(actor.actor);
                let room = |rows| {
                    trace_room(
                        &budget,
                        actor,
                        &pending,
                        timeline,
                        rows,
                        demand.failure_reserve(),
                    )
                };
                [room(state), room(total)]
            })
            .collect();
        if rooms.iter().any(|[state, _]| state.is_none()) {
            Err(Error::CapacityExhausted)
        } else {
            rooms
                .iter()
                .try_fold(u64::MAX, |least, [_, total]| {
                    total.map(|room| least.min(room))
                })
                .ok_or(Error::RecordingUnavailable)
        }
    })
}

/// The trace rows one actor's budget still admits after binding `rows`
/// to `timeline` and holding the `reserve` targets of `F_p`, or `None` when
/// they do not fit. `initialize` checks its context with the same rows
/// (`5n`) and reserve (`F_q`'s `8n` targets).
pub(super) fn trace_room(
    budget: &CommunityErasureBudgetV1,
    actor: &CommunityErasureActorV1,
    pending: &CommunityPendingErasureV1,
    timeline: TimelineId,
    rows: u64,
    reserve: u64,
) -> Option<u64> {
    let used = actor.targets + pending.targets + actor.quarantine_reserve + reserve + 2 * rows;
    COMMUNITY_ERASURE_TARGET_LINE_V1
        .checked_sub(used)
        .and_then(|targets| {
            budget
                .rows
                .iter()
                .try_fold(targets / 2, |room, (affected, committed)| {
                    let added = if *affected == timeline {
                        rows + reserve / 2
                    } else {
                        0
                    };
                    let pending = pending.rows.get(affected).copied().unwrap_or(0);
                    let held = budget.quarantine_rows.get(affected).copied().unwrap_or(0);
                    COMMUNITY_ERASURE_ROW_LIMIT_V1
                        .checked_sub(committed + pending + added + held)
                        .map(|free| {
                            if *affected == timeline {
                                room.min(free)
                            } else {
                                room
                            }
                        })
                })
        })
}

/// The pass's observation: one this call mints, or a committed one it
/// reuses (R10.7 step 5c).
#[derive(Clone, Copy)]
pub enum CommunityPassObservationUseV1<'a> {
    /// The stage-1 result of the observation this call mints.
    Minted(&'a CommunityObservationSourcesV1),
    /// The committed Observation CPN1 this call reuses.
    Reused(CommunityNativeNodeReferenceV1),
}

/// The observation's share of the quote: its CBQ1 row when minted, its
/// closure additions, its store keys and, when minted, its scope rows.
fn share<P: CommunityPassReadPortV1>(
    port: &P,
    timeline: TimelineId,
    sizes: &CommunityProtectionSizesV1,
    observation: CommunityPassObservationUseV1<'_>,
) -> Result<Share, Error> {
    match observation {
        CommunityPassObservationUseV1::Minted(sources) => sources
            .quote_terms(sizes, |digest| {
                port.event_source_in_closure(timeline, digest)
            })
            .map(Share::minted),
        CommunityPassObservationUseV1::Reused(reference) => Ok(Share {
            observation: None,
            graph: port.observation_graph(timeline, reference),
            keys: 0,
            rows: 0,
            scope: Vec::new(),
        }),
    }
}

struct Share {
    observation: Option<CommunityPassObservationV1>,
    graph: CommunityPassGraphTermsV1,
    keys: u64,
    /// The ARD1 rows a minted materialization binds at Reserve; a reused
    /// one's are bound already, even after an Abort (R13.1(4)).
    rows: u64,
    scope: Vec<CommunityScopeMemberV1>,
}

impl Share {
    fn minted(quote: CommunityObservationQuoteV1) -> Self {
        Self {
            observation: Some(quote.observation),
            graph: quote.graph,
            keys: quote.keys,
            rows: quote.erasure_rows,
            scope: quote.scope,
        }
    }

    /// The domain counts the demands start from, with this share.
    fn domain<P: CommunityPassReadPortV1>(
        &self,
        port: &P,
        timeline: TimelineId,
    ) -> CommunityPassDomainV1 {
        CommunityPassDomainV1 {
            selected_graph: port.selected_graph(timeline),
            live_keys: port.live_keys(),
            observation_graph: self.graph,
            observation_keys: self.keys,
            observation_rows: self.rows,
        }
    }
}

/// One scope row's identity: its five fields.
type RowKey = ([u8; 32], [u8; 16], [u8; 32], [u8; 32], u64);

const fn row_key(row: &CommunityScopeMemberV1) -> RowKey {
    (
        *row.scope_reference.as_bytes(),
        row.source_timeline.inner().to_bytes(),
        *row.owner_reference.as_bytes(),
        *row.retention_lease_reference.as_bytes(),
        row.not_after_micros,
    )
}

/// R11.4(1)–(3) and R11.1(2): the pass's distinct CIR1 refs (its CSB1
/// `coverage_rows` and CPV1 `source_root_refs`) are at most 4,096; every
/// member's scope union equals the pass scope; and the pass scope (its
/// `scope_members`) is at most 2,048 rows.
fn scope_bounds<P: CommunityPassReadPortV1>(
    port: &P,
    timeline: TimelineId,
    steps: &[CommunityPassStepInputsV1<'_>],
    minted: &[CommunityScopeMemberV1],
) -> Result<(), Error> {
    let mut refs = BTreeSet::new();
    let mut minting = false;
    for step in steps {
        refs.extend(
            step.step_inputs
                .iter()
                .map(|input| *input.digest().as_bytes()),
        );
        minting |= step.consumes_minted_observation;
    }
    if refs.len() + usize::from(minting) > MAX_COMMUNITY_COVERAGE_ROWS_V1 {
        return Err(Error::CapacityExhausted);
    }
    let mut rows = BTreeMap::new();
    steps
        .iter()
        .map(|step| member_scope(port, timeline, step, minted, &mut rows))
        .collect::<Result<Vec<_>, Error>>()
        .and_then(|scopes| {
            let pass: BTreeSet<RowKey> = scopes.iter().flatten().copied().collect();
            if scopes.iter().any(|scope| *scope != pass) {
                Err(Error::InvalidBinding)
            } else if pass.len() > MAX_COMMUNITY_SCOPE_MEMBERS_V1 {
                Err(Error::CapacityExhausted)
            } else {
                Ok(())
            }
        })
}

/// `S_m`: the union of the scope rows of a member's CIR1 refs (R11.4(3)),
/// reading each distinct ref once.
fn member_scope<P: CommunityPassReadPortV1>(
    port: &P,
    timeline: TimelineId,
    step: &CommunityPassStepInputsV1<'_>,
    minted: &[CommunityScopeMemberV1],
    cache: &mut BTreeMap<[u8; 32], Vec<RowKey>>,
) -> Result<BTreeSet<RowKey>, Error> {
    let mut scope: BTreeSet<RowKey> = if step.consumes_minted_observation {
        minted.iter().map(row_key).collect()
    } else {
        BTreeSet::new()
    };
    step.step_inputs
        .iter()
        .try_for_each(|input| {
            let digest = *input.digest().as_bytes();
            let rows = cache.get(&digest).cloned().map_or_else(
                || {
                    input_rows(port, timeline, *input).map(|rows| {
                        let keys: Vec<RowKey> = rows.iter().map(row_key).collect();
                        cache.insert(digest, keys.clone());
                        keys
                    })
                },
                Ok,
            );
            rows.map(|rows| scope.extend(rows))
        })
        .map(|()| scope)
}

/// A ref's scope rows (R11.4(3)): modes 3 and 4 have none; the others are
/// read from the domain.
fn input_rows<P: CommunityPassReadPortV1>(
    port: &P,
    timeline: TimelineId,
    input: CommunityTypedInputRefV1<'_>,
) -> Result<Vec<CommunityScopeMemberV1>, Error> {
    match input {
        CommunityTypedInputRefV1::Metadata { .. }
        | CommunityTypedInputRefV1::SourceGenesis { .. } => Ok(Vec::new()),
        _ => port.scope_rows(timeline, input),
    }
}

#[cfg(test)]
mod tests;
