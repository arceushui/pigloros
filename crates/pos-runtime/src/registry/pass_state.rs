//! Per-Driver pass state of a factual Tick (ADR-064 Revision 3, R3.4.7-R3.4.10).
//!
//! A pass forwards committed Events to the Drivers it steps. The host retains,
//! for every Driver, the Events it consumed in passes that recorded no step
//! node (the carried set) and the consumed-history digest its next recorded
//! step must cover. This module bounds a pass from that registry state alone,
//! before any Driver steps:
//!
//! 1. the per-Driver room rule of R3.4.8, which collapses a full carried set
//!    when the Driver has new Events;
//! 2. the pass-level carried-set accounting, which collapses the largest
//!    remaining carried set while a sum is at or above its cap;
//! 3. the trim of the newly forwarded `(Driver, Event)` pairs, highest `seq`
//!    first and the highest schedule position first at equal `seq`.
//!
//! A collapse is applied to the entry at planning time. The carried-set append
//! and the cursors are staged in the pending step and applied at commit.

use std::{cmp::Reverse, collections::BTreeMap};

use indexmap::IndexMap;
use pos_core::{
    factual_history_content_digest, output_policy::OutputAuthorityV1, Event, FactualEventRefV1,
    Hash, Kind, PluginId, Seq, MAX_FACTUAL_FORWARDED_EDGES_PER_TICK_V1,
    MAX_FACTUAL_FORWARDED_EVENTS_PER_TICK_V1, MAX_FORWARDED_EVENTS_PER_DRIVER_V1,
};

use super::{
    factual_dependencies::EventFact, subscribed_event_visible, HistoryInputV1, OperationContext,
    PluginEntry, PluginRegistry,
};

/// One Event forwarded to a Driver: its `seq` and payload hash.
pub(super) type ForwardedPair = (Seq, Hash);

/// What the plan needs to know about one stepped Driver.
pub(super) struct ForwardInput<'a> {
    /// The Driver's carried set.
    pub(super) carried: &'a BTreeMap<Seq, Hash>,
    /// The Driver's Event cursor.
    pub(super) cursor: Seq,
    /// The Driver's new forwardable Events in ascending `seq` order.
    pub(super) fresh: Vec<ForwardedPair>,
}

/// What a pass does for one stepped Driver.
pub(super) struct ForwardPlan {
    /// The Events forwarded to the Driver: a `seq`-ordered prefix of its new
    /// forwardable Events.
    pub(super) forwarded: Vec<ForwardedPair>,
    /// Whether the Driver's carried set collapses into its history node.
    pub(super) collapse: bool,
    /// The Event cursor the Driver takes when the pass commits.
    pub(super) cursor: Seq,
}

/// One Driver's plan while the passes of the accounting refine it.
struct Working {
    collapse: bool,
    wanted: usize,
    forwarded: Vec<ForwardedPair>,
}

/// The distinct Events and the Event edges one pass declares.
#[derive(Default)]
struct EventLoad {
    holders: BTreeMap<Seq, usize>,
    edges: usize,
}

impl EventLoad {
    fn add(&mut self, seq: Seq) {
        *self.holders.entry(seq).or_default() += 1;
        self.edges += 1;
    }

    fn remove(&mut self, seq: Seq) {
        let held = self.holders.entry(seq).or_default();
        *held -= 1;
        if *held == 0 {
            self.holders.remove(&seq);
        }
        self.edges -= 1;
    }

    /// Whether a sum is at or above its cap: no headroom is left.
    fn at_cap(&self) -> bool {
        self.holders.len() >= MAX_FACTUAL_FORWARDED_EVENTS_PER_TICK_V1
            || self.edges >= MAX_FACTUAL_FORWARDED_EDGES_PER_TICK_V1
    }

    /// Whether a sum is above its cap.
    fn over_cap(&self) -> bool {
        self.holders.len() > MAX_FACTUAL_FORWARDED_EVENTS_PER_TICK_V1
            || self.edges > MAX_FACTUAL_FORWARDED_EDGES_PER_TICK_V1
    }
}

/// Bound a pass over the stepped Drivers, in schedule order (R3.4.7).
///
/// The returned plans are in the order of `inputs`.
pub(super) fn plan_forwarding(
    inputs: &[ForwardInput<'_>],
    observed_through: Seq,
) -> Vec<ForwardPlan> {
    let mut work: Vec<Working> = inputs.iter().map(apply_room_rule).collect();
    let mut load = collapse_to_pass_budget(inputs, &mut work);
    trim_to_pass_budget(&mut work, &mut load);
    inputs
        .iter()
        .zip(work)
        .map(|(input, driver)| settle_cursor(input.cursor, driver, observed_through))
        .collect()
}

/// Step (A), the per-Driver rule of R3.4.8.
///
/// The room is sized here, against the Driver's own carried set as it stands
/// before steps (B) and (C), and is not recomputed afterwards.
///
/// With room left the lowest new Events are forwarded. With no room and new
/// Events the carried set collapses and the lowest new Events are forwarded
/// into the emptied set. With no new Events nothing changes.
fn apply_room_rule(input: &ForwardInput<'_>) -> Working {
    let carried = input.carried.len();
    let collapse = carried >= MAX_FORWARDED_EVENTS_PER_DRIVER_V1 && !input.fresh.is_empty();
    let held = if collapse { 0 } else { carried };
    let room = MAX_FORWARDED_EVENTS_PER_DRIVER_V1.saturating_sub(held);
    Working {
        collapse,
        wanted: input.fresh.len(),
        forwarded: input.fresh.iter().take(room).copied().collect(),
    }
}

/// Step (B), the pass-level accounting: collapse the largest remaining
/// carried set (ties: the lowest schedule position) while a sum is at or above
/// its cap, so that at least one new pair always fits.
///
/// Step (B) only collapses: it never re-sizes a forwarded list. The fixed order
/// is (A) then (B) then (C), so a Driver's room was computed in step (A) from
/// its own carried set before any step (B) collapse, and a later collapse of
/// that set does not give the Driver more room. Step (C) only trims.
///
/// Returns the load of the carried sets that remain.
fn collapse_to_pass_budget(inputs: &[ForwardInput<'_>], work: &mut [Working]) -> EventLoad {
    let mut load = EventLoad::default();
    for (input, driver) in inputs.iter().zip(work.iter()) {
        if !driver.collapse {
            for seq in input.carried.keys() {
                load.add(*seq);
            }
        }
    }
    while load.at_cap() {
        let index = largest_carried(inputs, work);
        work[index].collapse = true;
        for seq in inputs[index].carried.keys() {
            load.remove(*seq);
        }
    }
    load
}

/// The position of the largest carried set that has not collapsed, the lowest
/// position at equal size.
fn largest_carried(inputs: &[ForwardInput<'_>], work: &[Working]) -> usize {
    inputs
        .iter()
        .zip(work)
        .enumerate()
        .max_by_key(|(index, (input, driver))| (live_size(input, driver), Reverse(*index)))
        .map_or(0, |(index, _)| index)
}

/// The size of a Driver's carried set once the collapses so far are applied.
fn live_size(input: &ForwardInput<'_>, driver: &Working) -> usize {
    if driver.collapse {
        0
    } else {
        input.carried.len()
    }
}

/// Step (C): trim the newly forwarded pairs, one `(Driver, Event)` pair at a
/// time, until both bounds hold.
///
/// The pair with the highest `seq` goes first and, at equal `seq`, the pair of
/// the highest schedule position. A Driver loses its pairs from the end of its
/// list, so every list stays a `seq`-ordered prefix.
fn trim_to_pass_budget(work: &mut [Working], load: &mut EventLoad) {
    let mut pairs: Vec<(Seq, usize)> = Vec::new();
    for (position, driver) in work.iter().enumerate() {
        for (seq, _) in &driver.forwarded {
            load.add(*seq);
            pairs.push((*seq, position));
        }
    }
    if !load.over_cap() {
        return;
    }
    pairs.sort_unstable();
    for (seq, position) in pairs.into_iter().rev() {
        if !load.over_cap() {
            break;
        }
        work[position].forwarded.pop();
        load.remove(seq);
    }
}

/// The cursor a Driver takes: the pass's cut when nothing was trimmed, the last
/// forwarded `seq` when it was trimmed, its own cursor when nothing is left.
fn settle_cursor(cursor: Seq, driver: Working, observed_through: Seq) -> ForwardPlan {
    let trimmed = driver.forwarded.len() < driver.wanted;
    let next = if trimmed {
        driver.forwarded.last().map_or(cursor, |pair| pair.0)
    } else {
        observed_through
    };
    ForwardPlan {
        forwarded: driver.forwarded,
        collapse: driver.collapse,
        cursor: next,
    }
}

impl PluginRegistry {
    /// Plan what every Driver of the pass is forwarded and apply the collapses.
    ///
    /// The plans are in the order of `driver_ids`, the host schedule order. A
    /// collapse records a fact about Events consumed in earlier committed
    /// passes, so it is applied here and survives an aborted pass.
    pub(super) fn plan_pass_forwarding(
        &mut self,
        driver_ids: &[PluginId],
        cut: (Seq, &[Event]),
        operation: &OperationContext,
    ) -> Vec<ForwardPlan> {
        let (observed_through, committed_events) = cut;
        let ephemeral = self.ephemeral_event_types();
        let new_events: Vec<Vec<ForwardedPair>> = driver_ids
            .iter()
            .map(|id| {
                fresh_pairs(
                    &self.plugins[id],
                    committed_events,
                    observed_through,
                    operation,
                    &ephemeral,
                )
            })
            .collect();
        let inputs: Vec<ForwardInput<'_>> = driver_ids
            .iter()
            .zip(new_events)
            .map(|(id, fresh)| ForwardInput {
                carried: &self.plugins[id].carried,
                cursor: self.plugins[id].event_cursor,
                fresh,
            })
            .collect();
        let plans = plan_forwarding(&inputs, observed_through);
        for (id, plan) in driver_ids.iter().zip(&plans) {
            if plan.collapse {
                collapse_carried(&mut self.plugins[id]);
            }
        }
        plans
    }

    /// The Event types whose admitted output declaration is `Ephemeral`.
    ///
    /// An Ephemeral output cannot affect authoritative State, so such an Event
    /// is not forwarded as a Driver input on the Tick path (D9).
    ///
    /// Every declaration of an admitted output policy names an Event type its
    /// own Plugin owns (a foreign declaration is refused at registration with
    /// `CapabilityMismatch`), and one Event type has one owner. Flattening the
    /// declarations of all entries is therefore the same as keying each by the
    /// `owned_event_types` of the Plugin that declares it.
    fn ephemeral_event_types(&self) -> Vec<Kind> {
        self.plugins
            .values()
            .filter_map(|entry| entry.output_admission.as_ref())
            .flat_map(|admission| admission.policy().fields().output_declarations.iter())
            .filter(|declaration| declaration.authority() == OutputAuthorityV1::Ephemeral)
            .map(|declaration| Kind::new(declaration.event_type()))
            .collect()
    }
}

/// The new Events a Driver may be forwarded, in ascending `seq` order.
///
/// They are subscribed, visible to the Driver and shown by this pass's
/// consent, after its cursor, at or before the pass's cut, and not
/// Ephemeral-declared.
fn fresh_pairs(
    entry: &PluginEntry,
    committed_events: &[Event],
    observed_through: Seq,
    operation: &OperationContext,
    ephemeral: &[Kind],
) -> Vec<ForwardedPair> {
    let subscriptions = &entry.event_observation.event_subscriptions;
    let mut pairs: Vec<ForwardedPair> = committed_events
        .iter()
        .filter(|event| {
            event.seq > entry.event_cursor
                && event.seq <= observed_through
                && !ephemeral.contains(&event.event_type)
                && subscribed_event_visible(event, subscriptions, operation)
        })
        .map(|event| (event.seq, event.payload_hash))
        .collect();
    pairs.sort_unstable_by_key(|pair| pair.0);
    pairs
}

/// The covered Events of a history digest.
fn covered_events(pairs: impl Iterator<Item = (Seq, Hash)>) -> Vec<FactualEventRefV1> {
    pairs
        .map(|(seq, payload_hash)| FactualEventRefV1 { seq, payload_hash })
        .collect()
}

/// Collapse a Driver's carried set into its pending history node (R3.4.10).
///
/// The new node chains onto the content digest of the state it replaces.
fn collapse_carried(entry: &mut PluginEntry) {
    let covered = covered_events(entry.carried.iter().map(|(seq, hash)| (*seq, *hash)));
    let first = covered.first().map_or(Seq::ZERO, |event| event.seq);
    let last = covered.last().map_or(Seq::ZERO, |event| event.seq);
    entry.history = HistoryInputV1::Pending {
        content: factual_history_content_digest(entry.history.content(), first, last, &covered),
    };
    entry.carried.clear();
    entry.carried_kinds.clear();
}

/// The history state a restore gives every Driver (R3.4.10).
///
/// One node covers the Driver-visible history from `seq` 1 through the
/// restored head, shared by every restored Driver. A history without a
/// visible Event creates none.
pub(super) fn restored_history(visible_events: &[Event], restored_head: Seq) -> HistoryInputV1 {
    if visible_events.is_empty() {
        HistoryInputV1::None
    } else {
        let covered = covered_events(
            visible_events
                .iter()
                .map(|event| (event.seq, event.payload_hash)),
        );
        HistoryInputV1::Pending {
            content: factual_history_content_digest(
                Hash::zero(),
                Seq::from_u64(1),
                restored_head,
                &covered,
            ),
        }
    }
}

/// Settle the carried sets of the stepped Drivers when their pass commits.
///
/// A commit that recorded a Tick consumed every carried set in a step node.
/// A commit that recorded nothing appends the forwarded Events to the sets,
/// with their Event types from the pass's facts.
pub(super) fn settle_carried_sets(
    plugins: &mut IndexMap<PluginId, PluginEntry>,
    driver_ids: &[PluginId],
    forwarded: Vec<Vec<ForwardedPair>>,
    facts: &BTreeMap<Seq, EventFact>,
    recorded: bool,
) {
    for (id, pairs) in driver_ids.iter().zip(forwarded) {
        if let Some(entry) = plugins.get_mut(id) {
            if recorded {
                entry.carried.clear();
                entry.carried_kinds.clear();
            } else {
                entry.carried_kinds.extend(forwarded_kinds(&pairs, facts));
                entry.carried.extend(pairs);
            }
        }
    }
}

/// The Event type of each forwarded pair, as the pass saw the Event.
fn forwarded_kinds(pairs: &[ForwardedPair], facts: &BTreeMap<Seq, EventFact>) -> Vec<(Seq, Kind)> {
    let mut kinds = Vec::new();
    for (seq, _) in pairs {
        if let Some(fact) = facts.get(seq) {
            kinds.push((*seq, fact.event_type.clone()));
        }
    }
    kinds
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const THROUGH: u64 = 100_000;

    fn payload(seq: u64) -> Hash {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seq.to_be_bytes());
        Hash::from_bytes(bytes)
    }

    fn pair(seq: u64) -> ForwardedPair {
        (Seq::from_u64(seq), payload(seq))
    }

    fn pairs(first: u64, last: u64) -> Vec<ForwardedPair> {
        (first..=last).map(pair).collect()
    }

    fn carried(first: u64, last: u64) -> BTreeMap<Seq, Hash> {
        (first..=last).map(pair).collect()
    }

    /// One stepped Driver: its carried set, cursor and new forwardable Events.
    struct SteppedDriver {
        carried: BTreeMap<Seq, Hash>,
        cursor: u64,
        fresh: Vec<ForwardedPair>,
    }

    impl SteppedDriver {
        const fn new(carried: BTreeMap<Seq, Hash>, cursor: u64, fresh: Vec<ForwardedPair>) -> Self {
            Self {
                carried,
                cursor,
                fresh,
            }
        }
    }

    fn plan(drivers: &[SteppedDriver]) -> Vec<ForwardPlan> {
        let inputs: Vec<ForwardInput<'_>> = drivers
            .iter()
            .map(|driver| ForwardInput {
                carried: &driver.carried,
                cursor: Seq::from_u64(driver.cursor),
                fresh: driver.fresh.clone(),
            })
            .collect();
        plan_forwarding(&inputs, Seq::from_u64(THROUGH))
    }

    fn seq_of(planned: &ForwardPlan) -> Vec<u64> {
        planned
            .forwarded
            .iter()
            .map(|forwarded| forwarded.0.as_u64())
            .collect()
    }

    /// Every Driver's forwarded list is a `seq`-ordered prefix of its new Events.
    fn assert_prefixes(drivers: &[SteppedDriver], plans: &[ForwardPlan]) {
        for (driver, planned) in drivers.iter().zip(plans) {
            let kept = planned.forwarded.len();
            assert_eq!(planned.forwarded.as_slice(), &driver.fresh[..kept]);
        }
    }

    fn collapses(plans: &[ForwardPlan]) -> Vec<bool> {
        plans.iter().map(|plan| plan.collapse).collect()
    }

    #[test]
    fn the_worked_example_forwards_the_room_trims_the_rest_then_collapses() {
        // c = 100, n = 5,000: room = 3,737.
        let fresh = pairs(101, 5_100);
        let drivers = [SteppedDriver::new(carried(1, 100), 100, fresh)];
        let plans = plan(&drivers);
        assert!(!plans[0].collapse);
        assert_eq!(plans[0].forwarded.len(), 3_737);
        assert_prefixes(&drivers, &plans);
        assert_eq!(plans[0].cursor, Seq::from_u64(3_837));

        // After an empty pass c = 3,837; the 1,263 trimmed Events are new.
        let fresh = pairs(3_838, 5_100);
        let drivers = [SteppedDriver::new(carried(1, 3_837), 3_837, fresh)];
        let plans = plan(&drivers);
        assert!(plans[0].collapse);
        assert_eq!(plans[0].forwarded.len(), 1_263);
        assert_eq!(plans[0].cursor, Seq::from_u64(THROUGH));
    }

    #[test]
    fn the_room_rule_is_exact_at_its_boundaries() {
        // n = 3,737 fits; n = 3,738 trims one.
        let exact = [SteppedDriver::new(carried(1, 100), 100, pairs(101, 3_837))];
        let plans = plan(&exact);
        assert_eq!(plans[0].forwarded.len(), 3_737);
        assert_eq!(plans[0].cursor, Seq::from_u64(THROUGH));
        let over = [SteppedDriver::new(carried(1, 100), 100, pairs(101, 3_838))];
        let plans = plan(&over);
        assert_eq!(plans[0].forwarded.len(), 3_737);
        assert_eq!(plans[0].cursor, Seq::from_u64(3_837));

        // A full set with no new Event keeps its set and moves its cursor.
        let idle = [SteppedDriver::new(carried(1, 3_837), 3_837, Vec::new())];
        let plans = plan(&idle);
        assert!(!plans[0].collapse && plans[0].forwarded.is_empty());
        assert_eq!(plans[0].cursor, Seq::from_u64(THROUGH));

        // One new Event on a full set collapses it; room 1 forwards one.
        let full = [SteppedDriver::new(
            carried(1, 3_837),
            3_837,
            pairs(3_838, 3_839),
        )];
        let plans = plan(&full);
        assert!(plans[0].collapse);
        assert_eq!(seq_of(&plans[0]), [3_838, 3_839]);
        let almost = [SteppedDriver::new(
            carried(1, 3_836),
            3_836,
            pairs(3_837, 3_838),
        )];
        let plans = plan(&almost);
        assert!(!plans[0].collapse);
        assert_eq!(seq_of(&plans[0]), [3_837]);
        assert_eq!(plans[0].cursor, Seq::from_u64(3_837));
    }

    #[test]
    fn the_room_rule_runs_before_the_largest_first_loop() {
        // Four Drivers hold 3,837 each and one holds 1,100: 16,448 in all. The
        // fourth has new Events, so rule (2) collapses it first and the sum
        // falls under the cap. Largest-first alone would have collapsed the
        // first Driver (lowest position at equal size) instead.
        let mut drivers: Vec<SteppedDriver> = (0..4_u64)
            .map(|index| {
                let first = 1 + 3_837 * index;
                SteppedDriver::new(carried(first, first + 3_836), 15_348, Vec::new())
            })
            .collect();
        drivers.push(SteppedDriver::new(
            carried(15_349, 16_448),
            15_348,
            Vec::new(),
        ));
        drivers[3].fresh = vec![pair(50_000)];
        let plans = plan(&drivers);
        assert_eq!(collapses(&plans), [false, false, false, true, false]);
        assert_eq!(seq_of(&plans[3]), [50_000]);
    }

    #[test]
    fn a_step_b_collapse_does_not_resize_the_forwarded_list_of_step_a() {
        // The first Driver carries 3,000 Events and has 1,000 new ones: step
        // (A) leaves room for 837 and forwards them. Seven more Drivers carry
        // 2,048 distinct Events each, so the carried sum is 17,336 and step (B)
        // collapses the largest set, the first Driver's. The collapse does not
        // re-room it: it keeps the 837 of step (A) and the other new Events
        // wait for a later pass.
        let first = SteppedDriver::new(carried(1, 3_000), 3_000, pairs(3_001, 4_000));
        let mut drivers = vec![first];
        for index in 0..7_u64 {
            let first = 10_001 + 2_048 * index;
            let set = carried(first, first + 2_047);
            drivers.push(SteppedDriver::new(set, 30_000, Vec::new()));
        }
        let plans = plan(&drivers);
        let mut expected = [false; 8];
        expected[0] = true;
        assert_eq!(collapses(&plans), expected);
        assert_eq!(plans[0].forwarded.len(), 837);
        assert_eq!(seq_of(&plans[0]).last(), Some(&3_837));
        assert_eq!(plans[0].cursor, Seq::from_u64(3_837));
        assert_prefixes(&drivers, &plans);
    }

    #[test]
    fn a_seq_carried_and_forwarded_to_two_drivers_counts_once_in_the_distinct_sum() {
        // The distinct cap counts the union of the carried and the forwarded
        // Events of the pass: a `seq` that one Driver carries and another is
        // forwarded is one distinct Event, not two. The first four Drivers
        // carry 3,837 Events each and the fifth 1,035: 16,383 distinct, one
        // under the cap of 16,384. The sixth Driver is forwarded `seq` 1 and
        // 2, which the first Driver already carries. The union stays 16,383 and
        // nothing is trimmed; an additive count would reach 16,385 and trim.
        let mut drivers: Vec<SteppedDriver> = (0..4_u64)
            .map(|index| {
                let first = 1 + 3_837 * index;
                SteppedDriver::new(carried(first, first + 3_836), 20_000, Vec::new())
            })
            .collect();
        drivers.push(SteppedDriver::new(
            carried(15_349, 16_383),
            20_000,
            Vec::new(),
        ));
        drivers.push(SteppedDriver::new(BTreeMap::new(), 0, pairs(1, 2)));
        let plans = plan(&drivers);
        assert!(collapses(&plans).iter().all(|collapse| !collapse));
        assert_eq!(seq_of(&plans[5]), [1, 2]);
        assert_eq!(plans[5].cursor, Seq::from_u64(THROUGH));
    }

    #[test]
    fn the_loop_collapses_the_largest_set_and_the_lowest_position_at_a_tie() {
        // 18,100 distinct Events: the sets of 3,000 tie, the first one goes.
        let mut drivers = vec![SteppedDriver::new(carried(1, 100), 0, Vec::new())];
        for index in 0..6_u64 {
            let first = 101 + 3_000 * index;
            drivers.push(SteppedDriver::new(
                carried(first, first + 2_999),
                0,
                Vec::new(),
            ));
        }
        let plans = plan(&drivers);
        assert_eq!(
            collapses(&plans),
            [false, true, false, false, false, false, false]
        );
    }

    #[test]
    fn the_loop_repeats_while_a_sum_stays_at_or_above_its_cap() {
        // Six full sets hold 23,022 distinct Events: two collapses are needed.
        let drivers: Vec<SteppedDriver> = (0..6_u64)
            .map(|index| {
                let first = 1 + 3_837 * index;
                SteppedDriver::new(carried(first, first + 3_836), 23_022, Vec::new())
            })
            .collect();
        let plans = plan(&drivers);
        let expected = [true, true, false, false, false, false];
        assert_eq!(collapses(&plans), expected);
    }

    #[test]
    fn vector_one_distinct_cap_sum_exactly_at_the_cap_collapses_once_more() {
        // Eight Drivers carry 2,048 distinct Events each: 16,384 in all.
        let mut drivers: Vec<SteppedDriver> = (0..8_u64)
            .map(|index| {
                let first = 1 + 2_048 * index;
                SteppedDriver::new(carried(first, first + 2_047), 16_384, Vec::new())
            })
            .collect();
        drivers[7].fresh = vec![pair(50_000)];
        let plans = plan(&drivers);
        assert_eq!(
            collapses(&plans),
            [true, false, false, false, false, false, false, false]
        );
        assert_eq!(seq_of(&plans[7]), [50_000]);
        assert_eq!(plans[7].cursor, Seq::from_u64(THROUGH));
    }

    #[test]
    fn vector_two_edge_cap_sum_exactly_at_the_cap_collapses_once_more() {
        // 64 Drivers carry the same 2,048 Events: 131,072 edges, 2,048 distinct.
        let mut drivers: Vec<SteppedDriver> = (0..64)
            .map(|_| SteppedDriver::new(carried(1, 2_048), 2_048, Vec::new()))
            .collect();
        drivers[63].fresh = vec![pair(3_000)];
        let plans = plan(&drivers);
        let collapsed = collapses(&plans);
        assert!(collapsed[0]);
        assert_eq!(collapsed.iter().filter(|collapse| **collapse).count(), 1);
        assert_eq!(seq_of(&plans[63]), [3_000]);
    }

    #[test]
    fn vector_three_one_edge_of_headroom_forwards_one_pair_then_collapses() {
        // 63 Drivers carry 2,048 shared Events and one carries 2,047: 131,071
        // edges. Two Drivers want one new Event.
        let build = |wanting: [usize; 2]| -> Vec<SteppedDriver> {
            let mut drivers: Vec<SteppedDriver> = (0..63)
                .map(|_| SteppedDriver::new(carried(1, 2_048), 2_048, Vec::new()))
                .collect();
            drivers.push(SteppedDriver::new(carried(1, 2_047), 2_048, Vec::new()));
            for position in wanting {
                drivers[position].fresh = vec![pair(3_000)];
            }
            drivers
        };
        let drivers = build([3, 10]);
        let plans = plan(&drivers);
        assert!(collapses(&plans).iter().all(|collapse| !collapse));
        // The lower position keeps the pair; the other is trimmed and its
        // cursor stays where it was.
        assert_eq!(seq_of(&plans[3]), [3_000]);
        assert_eq!(plans[3].cursor, Seq::from_u64(THROUGH));
        assert!(plans[10].forwarded.is_empty());
        assert_eq!(plans[10].cursor, Seq::from_u64(2_048));
        assert_prefixes(&drivers, &plans);

        // After an empty pass the first Driver carries 2,049 Events: the sum
        // is exactly at the cap, the now-largest set collapses and the
        // trimmed pair is forwarded.
        let mut next = build([10, 10]);
        next[3].carried.insert(Seq::from_u64(3_000), payload(3_000));
        let plans = plan(&next);
        let collapsed = collapses(&plans);
        assert!(collapsed[3]);
        assert_eq!(collapsed.iter().filter(|collapse| **collapse).count(), 1);
        assert_eq!(seq_of(&plans[10]), [3_000]);
        assert_eq!(plans[10].cursor, Seq::from_u64(THROUGH));
    }

    #[test]
    fn the_trim_removes_the_highest_seq_first_and_the_highest_position_at_equal_seq() {
        // 40 Drivers want the same 3,837 Events: 153,480 edges against 131,072.
        // 22,408 pairs go: seqs 3,837 down to 3,278 for everyone, then the
        // eight highest positions lose seq 3,277 as well.
        let drivers: Vec<SteppedDriver> = (0..40)
            .map(|_| SteppedDriver::new(BTreeMap::new(), 0, pairs(1, 3_837)))
            .collect();
        let plans = plan(&drivers);
        assert_prefixes(&drivers, &plans);
        for (position, planned) in plans.iter().enumerate() {
            let last = if position < 32 { 3_277 } else { 3_276 };
            assert_eq!(planned.forwarded.len(), last);
            let cursor = Seq::from_u64(u64::try_from(last).unwrap_or(0));
            assert_eq!(planned.cursor, cursor);
        }
    }

    #[test]
    fn the_distinct_cap_trims_from_the_tail_of_the_last_scheduled_driver() {
        // Five Drivers want 3,837 distinct Events each: 19,185 against 16,384.
        let drivers: Vec<SteppedDriver> = (0..5_u64)
            .map(|index| {
                let first = 1 + 3_837 * index;
                SteppedDriver::new(BTreeMap::new(), 0, pairs(first, first + 3_836))
            })
            .collect();
        let plans = plan(&drivers);
        assert_prefixes(&drivers, &plans);
        for planned in &plans[..4] {
            assert_eq!(planned.forwarded.len(), 3_837);
            assert_eq!(planned.cursor, Seq::from_u64(THROUGH));
        }
        assert_eq!(plans[4].forwarded.len(), 3_837 - 2_801);
        assert_eq!(plans[4].cursor, Seq::from_u64(15_348 + 1_036));
    }
}
