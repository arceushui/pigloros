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
//! - the CBQ1 part of step 5g ([`CommunityPassDueV1::quote`]): the R10.3
//!   quote, State demand first (14) and then State plus recording demand
//!   (19), under the R10.4(1) fit rule.
//!
//! Steps 5a–5c (the step-5 decisions, the trust gate and the observation
//! reuse decision) and 5f (the materialization's history read and fold) run
//! between these calls, in the Reserve pipeline (A4c). The key, encryption
//! and graph demands of R10.4(2), the R10.4(6) format bounds and the
//! R10.4(5) install check are not part of this planner.
//!
//! The planner reads the domain only through [`CommunityQuarantineIndexV1`]
//! and [`CommunityPassReadPortV1`] and commits nothing: every backend's `run_pass` uses the same planner,
//! and the Reserve writer re-checks generation, head, counters, quarantine,
//! caps and the recording horizon (R10.7 step 5j).

use pos_core::community_lifecycle::{
    community_member_due_v1, CommunityDurableProfileV1, CommunityHostProgressV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassObservationV1, CommunityPassQuoteInputV1,
    CommunityPassQuoteMemberV1, CommunityPassQuoteV1, CommunityPreparedInvocationInputV1,
    CommunityQuarantineKeyV1, CommunityQuarantineReasonV1, CommunitySharedCountsV1,
    CommunityTypedInputRefV1, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_DECISION_DEADLINE_MICROS_V1, COMMUNITY_RETAINED_PASS_OUTCOMES_V1,
};
use pos_core::{Hash, TimelineId};

#[cfg(target_os = "linux")]
use super::memory_domain::MemoryCommunityDomainV1;

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
/// recorded-set counters (R10.3(6)) and the retained-outcome and
/// control-operation counts (R10.4(4)). They are domain-private and have no
/// wire form; the Memory domain adds their storage and implements this
/// port in A4c. The trait is re-exported nowhere.
pub trait CommunityPassReadPortV1 {
    /// T's cumulative recorded-set counters (R10.3(6)).
    fn recorded_set_counters(&self, timeline: TimelineId) -> CommunitySharedCountsV1;

    /// The passes of `(T, G)` that hold a CPR1 whose detailed outcome is
    /// not yet disposed: Committed, Aborted and unresolved (R10.4(4)).
    fn retained_pass_outcomes(&self, timeline: TimelineId, generation: [u8; 16]) -> u64;

    /// The retained control and protection operations of `(T, G)`
    /// (R10.4(4)).
    fn control_operations(&self, timeline: TimelineId, generation: [u8; 16]) -> u64;
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
    request
        .reservation_sample_micros
        .saturating_add(COMMUNITY_DECISION_DEADLINE_MICROS_V1)
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
        if outcomes >= COMMUNITY_RETAINED_PASS_OUTCOMES_V1
            || (minting && operations >= COMMUNITY_CONTROL_OPERATIONS_V1)
        {
            Err(Error::CapacityExhausted)
        } else if recording <= deadline(self.request) {
            Err(Error::RecordingUnavailable)
        } else {
            Ok(())
        }
    }

    /// The CBQ1 part of step 5g: the R10.3 quote over the due members, with
    /// the counters read under the guard as `prior_shared_counts`, checked
    /// State first and then with the recording (R10.4(1)–(2)).
    ///
    /// `steps` has one entry per due member, in due order. `minted` is the
    /// [`super::CommunityObservationSourcesV1::quote_terms`] of the observation this
    /// call mints, or `None` when it reuses one.
    ///
    /// # Errors
    /// Returns `InvalidBinding` when `steps` does not cover the due set;
    /// the quote errors of [`CommunityPassQuoteV1::new`]; then
    /// `CapacityExhausted` when the State demand does not fit and
    /// `RecordingUnavailable` when only the full demand does not.
    pub fn quote<P: CommunityPassReadPortV1>(
        &self,
        port: &P,
        steps: &[CommunityPassStepInputsV1<'_>],
        minted: Option<CommunityPassObservationV1>,
    ) -> Result<CommunityPassQuoteV1, Error> {
        if steps.len() == self.due.len() {
            self.pass_quote(port, steps, minted)
                .and_then(|quote| quote.require_fit().map(|()| quote))
        } else {
            Err(Error::InvalidBinding)
        }
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

#[cfg(test)]
mod tests;
