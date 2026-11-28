//! The community erasure-target budget read (ADR-129 revision 13, R13.1).
//!
//! [`CommunityErasureBudgetV1`] is what the store domain counts for a
//! Timeline T under the guard: for every actor whose affected scope contains
//! T, its `targets(A)` and standing quarantine reserve `F_q(A)`, and `rows(U)`
//! for every U of those scopes. It counts committed store data only; the
//! planner adds the pending reservations (R13.1(4)) it reads from
//! [`super::pass_planner::CommunityPassReadPortV1`] and the operation's own
//! rows. [`CommunityErasureBudgetPortV1`] is the read; like the planner's
//! other ports it is re-exported nowhere, and [`MemoryCommunityDomainV1`]
//! serves it from the store's incremental counters.

use std::collections::BTreeMap;

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
#[cfg(target_os = "linux")]
use pos_core::community_lifecycle::COMMUNITY_QUARANTINE_RESERVE_PER_MEMBER_V1;
use pos_core::{EntityId, TimelineId};

#[cfg(target_os = "linux")]
use super::memory_domain::MemoryCommunityDomainV1;
#[cfg(target_os = "linux")]
use super::pass_planner::{trace_room, CommunityPassReadPortV1};

/// The store domain's committed erasure budget, read under the guard
/// (ADR-129 revision 13, R13.1(2)).
pub trait CommunityErasureBudgetPortV1 {
    /// T's committed budget: every actor whose affected scope contains T
    /// with its `targets(A)` and `F_q(A)`, and `rows(U)` of every U of their
    /// affected scopes.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a topology the store cannot walk.
    fn erasure_budget(&self, timeline: TimelineId) -> Result<CommunityErasureBudgetV1, Error>;
}

/// One actor of T's scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityErasureActorV1 {
    /// The actor A.
    pub actor: EntityId,
    /// `targets(A)`, the ADR-136 closure size of A's private-subject-data
    /// request (R13.1(1)).
    pub targets: u64,
    /// `F_q(A)`, the quarantine reserve of every initialized context on a
    /// Timeline of `affected(A)` (R13.1(5)).
    pub quarantine_reserve: u64,
}

/// The committed budget of T's scope (R13.1(2)).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommunityErasureBudgetV1 {
    /// Every actor whose affected scope contains T, in actor order.
    pub actors: Vec<CommunityErasureActorV1>,
    /// `rows(U)` of every U in those affected scopes, of any class.
    pub rows: BTreeMap<TimelineId, u64>,
    /// `F_q^rows(U)` for every U of `rows`: the unspent `SetReason` rows of
    /// every initialized context on U, which the rows bound holds back
    /// (ADR-129 revision 14, RN.3). A U with no context has none.
    pub quarantine_rows: BTreeMap<TimelineId, u64>,
}

/// An actor's unresolved reservations (R13.1(4)): their worst-case targets
/// and the rows they may bind to each Timeline.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommunityPendingErasureV1 {
    /// The pending targets in the actor's scope.
    pub targets: u64,
    /// The pending rows per Timeline.
    pub rows: BTreeMap<TimelineId, u64>,
}

/// One unresolved reservation's worst-case demand (R13.1(4)): the pass
/// rows and `F_p` it still holds, in targets and in rows bound to its
/// Timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CommunityPendingReservationV1 {
    pub(super) targets: u64,
    pub(super) rows: u64,
}

impl CommunityPendingReservationV1 {
    /// The demand of `rows` ARD1 rows at two targets each, holding `reserve`
    /// targets of `F_p` (R13.1(4)-(5)) and half of them as rows. `F_p` is
    /// `2(n + 1)` targets, always even; an odd `reserve` would round its
    /// rows down.
    ///
    /// The planner's budget check and the Reserve writer's ledger entry use
    /// this one formula.
    pub(super) const fn for_pass(rows: u64, reserve: u64) -> Self {
        Self {
            targets: rows.saturating_mul(2).saturating_add(reserve),
            rows: rows.saturating_add(reserve / 2),
        }
    }
}

/// One initialized Timeline's quarantine reserve inputs: the roster
/// members of its contexts and its active `(member, reason)` pairs.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CommunityErasureContextV1 {
    pub(super) members: u64,
    pub(super) active_pairs: u64,
}

#[cfg(target_os = "linux")]
impl CommunityErasureContextV1 {
    /// `8n` less the two targets each active pair already spent.
    pub(super) const fn reserve(self) -> u64 {
        (COMMUNITY_QUARANTINE_RESERVE_PER_MEMBER_V1 * self.members)
            .saturating_sub(2 * self.active_pairs)
    }

    /// `F_q^rows`: one row for every two unspent targets (ADR-129 revision
    /// 14, RN.3).
    pub(super) const fn reserve_rows(self) -> u64 {
        self.reserve() / 2
    }
}

#[cfg(target_os = "linux")]
impl CommunityErasureBudgetPortV1 for MemoryCommunityDomainV1 {
    fn erasure_budget(&self, timeline: TimelineId) -> Result<CommunityErasureBudgetV1, Error> {
        self.store
            .community_erasure_scope(timeline)
            .map(|(actors, rows)| CommunityErasureBudgetV1 {
                quarantine_rows: rows
                    .keys()
                    .filter_map(|affected| {
                        self.erasure_contexts
                            .get(affected)
                            .map(|context| (*affected, context.reserve_rows()))
                    })
                    .collect(),
                actors: actors
                    .iter()
                    .map(|(actor, targets, affected)| CommunityErasureActorV1 {
                        actor: *actor,
                        targets: *targets,
                        quarantine_reserve: affected
                            .iter()
                            .filter_map(|affected| self.erasure_contexts.get(affected))
                            .map(|context| context.reserve())
                            .sum(),
                    })
                    .collect(),
                rows,
            })
    }
}

#[cfg(target_os = "linux")]
impl MemoryCommunityDomainV1 {
    /// Register an initialized context of `members` roster members on
    /// `timeline` (R13.1(5)), in the initialization commit.
    pub(super) fn count_erasure_context(&mut self, timeline: TimelineId, members: u64) {
        self.erasure_contexts.entry(timeline).or_default().members += members;
    }

    /// Record that `timeline`'s active `(member, reason)` pairs went from
    /// `before` to `after`, in the transaction that changes the quarantine
    /// index: a `SetReason` spends a pair's reserve, a reset re-arms it.
    pub(super) fn count_quarantine_pairs(&mut self, timeline: TimelineId, before: u64, after: u64) {
        let context = self.erasure_contexts.entry(timeline).or_default();
        context.active_pairs = (context.active_pairs + after).saturating_sub(before);
    }
}

#[cfg(target_os = "linux")]
impl MemoryCommunityDomainV1 {
    /// R13.1(3) for `initialize`: for every actor of `timeline`'s scope,
    /// `targets(A)` with the pending reservations, the context's `5n` rows at
    /// two targets each and its `F_q` of `8n` targets stay within the
    /// community line, and every `rows(U)` with its pending rows and
    /// `F_q^rows(U)`, `timeline`'s also with the `5n` rows and its own
    /// `4n` `F_q` rows, stays within 4,096 (ADR-129 revisions 13 and 14,
    /// RN.3).
    ///
    /// # Errors
    /// Returns `CapacityExhausted` when either line does not fit, and the
    /// budget read's error.
    pub(super) fn check_initialize_budget(
        &self,
        timeline: TimelineId,
        members: u64,
    ) -> Result<(), Error> {
        // The context's `5n` rows and `F_q` fit exactly like a pass's rows
        // and `F_p` (R13.1(3)): one implementation of the bound.
        self.check_budget_fit(
            timeline,
            5 * members,
            COMMUNITY_QUARANTINE_RESERVE_PER_MEMBER_V1 * members,
        )
    }

    /// R13.1(3) for a reset: re-arming the `F_q` shares of `spent` pairs
    /// holds `2 * spent` targets and `spent` rows more of T's reserve. They
    /// must fit for every actor of the scope like any reserve, or the reset
    /// gives 14 and the quarantine stays.
    ///
    /// # Errors
    /// Returns `CapacityExhausted` when the re-armed reserve does not fit,
    /// and the budget read's error.
    pub(super) fn check_rearm_budget(&self, timeline: TimelineId, spent: u64) -> Result<(), Error> {
        self.check_budget_fit(timeline, 0, 2 * spent)
    }

    /// Whether `rows` more rows and `reserve` more reserve targets on
    /// `timeline` fit every actor of its scope (R13.1(3)): `14` otherwise.
    fn check_budget_fit(&self, timeline: TimelineId, rows: u64, reserve: u64) -> Result<(), Error> {
        self.erasure_budget(timeline).and_then(|budget| {
            let fits = budget.actors.iter().all(|actor| {
                let pending = self.pending_erasure_demand(actor.actor);
                trace_room(&budget, actor, &pending, timeline, rows, reserve).is_some()
            });
            if fits {
                Ok(())
            } else {
                Err(Error::CapacityExhausted)
            }
        })
    }
}
