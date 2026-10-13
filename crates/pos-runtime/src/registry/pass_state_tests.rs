//! Registry state of the factual pass: owner IDs, forwarding, the carried set
//! and the history state (ADR-064 Revision 3, R3.2.4, R3.4.7-R3.4.10).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use pos_core::clock::WallTime;
use pos_core::crypto::Hash;
use pos_core::event::{CanonicalBytes, SchemaVersion};
use pos_core::ids::{EntityId, EventId};
use pos_core::output_policy::{
    OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1, OutputPolicyInputV1, OutputPolicyV1,
};
use pos_core::{
    factual_history_content_digest, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1,
    FactualEventRefV1, FidelityBudgetV1, PluginCpuReservationV1, WorkloadProfileV1,
};

use super::test_ext::TestValueExt;
use super::*;
use crate::driver::ObservationView;

pub(super) type Seen = Arc<Mutex<Vec<u64>>>;

const PLAIN: &str = "probe.plain";
const EPHEMERAL: &str = "probe.ephemeral";

pub(super) fn gated_registry() -> PluginRegistry {
    PluginRegistry::new().with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

/// A Driver that logs the `seq` of every Event it is forwarded.
pub(super) struct Probe {
    name: &'static str,
    marker: u64,
    subscriptions: Vec<Kind>,
    seen: Seen,
}

impl Driver for Probe {
    fn name(&self) -> &'static str {
        self.name
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_nanos(self.marker)
    }

    fn event_subscriptions(&self) -> &[Kind] {
        &self.subscriptions
    }

    fn step(
        &mut self,
        _: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let events = observations.events();
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(events.iter().map(|event| event.seq.as_u64()));
        Ok(StepOutput::empty())
    }
}

pub(super) fn probe(name: &'static str, marker: u64, types: &[&str]) -> (Probe, Seen) {
    let seen = Seen::default();
    let driver = Probe {
        name,
        marker,
        subscriptions: types.iter().map(|kind| Kind::new(*kind)).collect(),
        seen: Arc::clone(&seen),
    };
    (driver, seen)
}

fn taken(seen: &Seen) -> Vec<u64> {
    let mut guard = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::mem::take(&mut *guard)
}

fn payload_hash(seq: u64) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seq.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn event(seq: u64, event_type: &str) -> Event {
    Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(b"payload"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: payload_hash(seq),
    }
}

fn plain_events(first: u64, last: u64) -> Vec<Event> {
    (first..=last).map(|seq| event(seq, PLAIN)).collect()
}

fn carried_set(first: u64, last: u64) -> BTreeMap<Seq, Hash> {
    (first..=last)
        .map(|seq| (Seq::from_u64(seq), payload_hash(seq)))
        .collect()
}

fn refs(first: u64, last: u64) -> Vec<FactualEventRefV1> {
    (first..=last)
        .map(|seq| FactualEventRefV1 {
            seq: Seq::from_u64(seq),
            payload_hash: payload_hash(seq),
        })
        .collect()
}

/// The history digest over the refs of `first..=last`, chained onto `previous`.
fn history_digest(previous: Hash, first: u64, last: u64) -> Hash {
    let covered = refs(first, last);
    let (from, through) = (Seq::from_u64(first), Seq::from_u64(last));
    factual_history_content_digest(previous, from, through, &covered)
}

/// A registry of Drivers subscribed to `PLAIN`, in schedule order.
fn plain_registry(count: u64) -> (PluginRegistry, TimelineId, Vec<Seen>) {
    let mut registry = gated_registry();
    let mut logs = Vec::new();
    for marker in 1..=count {
        let (driver, seen) = probe("probe", marker, &[PLAIN]);
        registry.register_test_driver(Box::new(driver));
        logs.push(seen);
    }
    registry.compose_non_participant_drivers().test_ok();
    (registry, TimelineId::new(), logs)
}

pub(super) fn ids(registry: &PluginRegistry) -> Vec<PluginId> {
    registry.plugins.keys().copied().collect()
}

fn step(
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    through: u64,
    events: &[Event],
) -> Vec<EventDraft> {
    let cut = Seq::from_u64(through);
    registry
        .step_all_anchored_with_events(timeline, &root_ancestry(timeline), cut, events)
        .test_ok()
}

/// Step every Driver over the plain Events `1..=through`, cut at `through`.
fn step_plain(registry: &mut PluginRegistry, timeline: TimelineId, through: u64) {
    let events = plain_events(1, through);
    assert!(step(registry, timeline, through, &events).is_empty());
}

fn commit_empty(registry: &mut PluginRegistry, through: u64) {
    registry.commit_step_at(Seq::from_u64(through), 1).test_ok();
}

fn pending_content(registry: &PluginRegistry, id: PluginId) -> Option<Hash> {
    match registry.plugins[&id].pass_state.history {
        HistoryInputV1::None => None,
        HistoryInputV1::Pending { content } => Some(content),
    }
}

#[test]
fn positions_follow_schedule_order_and_an_empty_pass_fills_the_carried_sets() {
    let (mut registry, timeline, logs) = plain_registry(2);
    step_plain(&mut registry, timeline, 3);

    let pending = registry.pending_step.as_ref().test_ok();
    assert_eq!(pending.driver_ids, ids(&registry));
    assert_eq!(pending.forwarded.len(), 2);
    assert_eq!(pending.event_cursors.len(), 2);
    for log in &logs {
        assert_eq!(taken(log), [1, 2, 3]);
    }
    commit_empty(&mut registry, 3);

    for id in ids(&registry) {
        let entry = &registry.plugins[&id];
        assert_eq!(entry.pass_state.carried, carried_set(1, 3));
        assert_eq!(entry.event_cursor, Seq::from_u64(3));
        assert_eq!(entry.pass_state.history, HistoryInputV1::None);
    }
    // Only the Events after the cursor are forwarded, up to the cut.
    let events = plain_events(1, 6);
    assert!(step(&mut registry, timeline, 5, &events).is_empty());
    for log in &logs {
        assert_eq!(taken(log), [4, 5]);
    }
    commit_empty(&mut registry, 5);
    for id in ids(&registry) {
        assert_eq!(registry.plugins[&id].pass_state.carried, carried_set(1, 5));
    }
}

#[test]
fn a_recorded_commit_consumes_the_carried_sets() {
    let (mut registry, timeline, _) = plain_registry(1);
    step_plain(&mut registry, timeline, 2);
    let mut pending = registry.pending_step.take().test_ok();
    pending.staged_drafts.push(EventDraft::new(
        EntityId::new(),
        Kind::new(PLAIN),
        CanonicalBytes::from_static(b"draft"),
    ));
    registry.commit_pending_step(pending);

    let entry = &registry.plugins[&ids(&registry)[0]];
    assert!(entry.pass_state.carried.is_empty());
    assert_eq!(entry.event_cursor, Seq::from_u64(2));
}

#[test]
fn the_room_rule_trims_collapses_and_chains_as_the_worked_example_pins() {
    let (mut registry, timeline, logs) = plain_registry(1);
    let id = ids(&registry)[0];
    registry.plugins[&id].pass_state.carried = carried_set(1, 100);
    registry.plugins[&id].event_cursor = Seq::from_u64(100);

    // c = 100, n = 5,000: 3,737 forwarded, 1,263 trimmed, no collapse.
    step_plain(&mut registry, timeline, 5_100);
    let seen = taken(&logs[0]);
    assert_eq!(seen.len(), 3_737);
    assert_eq!(seen.last().copied(), Some(3_837));
    assert_eq!(pending_content(&registry, id), None);
    commit_empty(&mut registry, 5_100);
    assert_eq!(
        registry.plugins[&id].pass_state.carried,
        carried_set(1, 3_837)
    );
    assert_eq!(registry.plugins[&id].event_cursor, Seq::from_u64(3_837));

    // The trimmed Events are forwardable again: room = 0, n = 1,263.
    step_plain(&mut registry, timeline, 5_100);
    let expected = history_digest(Hash::zero(), 1, 3_837);
    assert_eq!(pending_content(&registry, id), Some(expected));
    assert!(registry.plugins[&id].pass_state.carried.is_empty());
    let seen = taken(&logs[0]);
    assert_eq!(seen.first().copied(), Some(3_838));
    assert_eq!(seen.len(), 1_263);
    commit_empty(&mut registry, 5_100);
    assert_eq!(
        registry.plugins[&id].pass_state.carried,
        carried_set(3_838, 5_100)
    );
    assert_eq!(registry.plugins[&id].event_cursor, Seq::from_u64(5_100));
}

#[test]
fn a_collapse_survives_an_aborted_pass_but_the_append_and_cursors_do_not() {
    let (mut registry, timeline, _) = plain_registry(1);
    let id = ids(&registry)[0];
    let previous = Hash::from_bytes([9; 32]);
    registry.plugins[&id].pass_state.carried = carried_set(1, 3_837);
    registry.plugins[&id].event_cursor = Seq::from_u64(3_837);
    registry.plugins[&id].pass_state.history = HistoryInputV1::Pending { content: previous };

    step_plain(&mut registry, timeline, 3_838);
    let chained = history_digest(previous, 1, 3_837);
    assert_eq!(pending_content(&registry, id), Some(chained));
    registry.abort_step();

    let entry = &registry.plugins[&id];
    assert!(entry.pass_state.carried.is_empty());
    assert_eq!(entry.event_cursor, Seq::from_u64(3_837));
    let pending = HistoryInputV1::Pending { content: chained };
    assert_eq!(entry.pass_state.history, pending);

    // The next pass declares the same node: the set is empty, so no second
    // collapse can happen.
    step_plain(&mut registry, timeline, 3_838);
    assert_eq!(pending_content(&registry, id), Some(chained));
}

#[test]
fn a_full_carried_set_without_new_events_keeps_its_set_and_cursor() {
    let (mut registry, timeline, logs) = plain_registry(1);
    let id = ids(&registry)[0];
    registry.plugins[&id].pass_state.carried = carried_set(1, 3_837);
    registry.plugins[&id].event_cursor = Seq::from_u64(3_837);

    step_plain(&mut registry, timeline, 3_837);
    assert!(taken(&logs[0]).is_empty());
    assert_eq!(pending_content(&registry, id), None);
    commit_empty(&mut registry, 3_837);
    assert_eq!(
        registry.plugins[&id].pass_state.carried,
        carried_set(1, 3_837)
    );
    assert_eq!(registry.plugins[&id].event_cursor, Seq::from_u64(3_837));
}

#[test]
fn the_pass_level_accounting_collapses_the_largest_carried_set_at_the_cap() {
    // Vector (1): eight Drivers carry 2,048 distinct Events each, 16,384 in
    // all. Every room is at least 1, yet one more collapse makes room.
    let (mut registry, timeline, logs) = plain_registry(8);
    let all = ids(&registry);
    for (index, id) in all.iter().enumerate() {
        let first = 1 + 2_048 * u64::try_from(index).unwrap_or(0);
        registry.plugins[id].pass_state.carried = carried_set(first, first + 2_047);
        registry.plugins[id].event_cursor = Seq::from_u64(16_384);
    }
    step_plain(&mut registry, timeline, 16_385);

    let expected = history_digest(Hash::zero(), 1, 2_048);
    assert_eq!(pending_content(&registry, all[0]), Some(expected));
    assert!(registry.plugins[&all[0]].pass_state.carried.is_empty());
    for id in &all[1..] {
        assert_eq!(pending_content(&registry, *id), None);
        assert_eq!(registry.plugins[id].pass_state.carried.len(), 2_048);
    }
    for log in &logs {
        assert_eq!(taken(log), [16_385]);
    }
}

#[test]
fn a_cadence_skipped_driver_keeps_its_carried_set_and_cursor() {
    let (mut registry, timeline, logs) = plain_registry(2);
    let all = ids(&registry);
    let ancestry = root_ancestry(timeline);
    let first = plain_events(1, 2);
    let cut = Seq::from_u64(2);
    registry
        .tick_cadenced_anchored_with_events(timeline, &ancestry, 100, cut, &first)
        .test_ok();
    commit_empty(&mut registry, 2);
    for log in &logs {
        assert_eq!(taken(log), [1, 2]);
    }

    // One nanosecond later only the Driver with the 1 ns interval is due.
    let later = plain_events(1, 4);
    let cut = Seq::from_u64(4);
    registry
        .tick_cadenced_anchored_with_events(timeline, &ancestry, 101, cut, &later)
        .test_ok();
    commit_empty(&mut registry, 4);
    assert_eq!(taken(&logs[0]), [3, 4]);
    assert!(taken(&logs[1]).is_empty());
    assert_eq!(
        registry.plugins[&all[0]].pass_state.carried,
        carried_set(1, 4)
    );
    assert_eq!(
        registry.plugins[&all[1]].pass_state.carried,
        carried_set(1, 2)
    );
    assert_eq!(registry.plugins[&all[1]].event_cursor, Seq::from_u64(2));
}

/// Register an Ephemeral-declared producer of `EPHEMERAL` events.
fn register_ephemeral_producer(registry: &mut PluginRegistry) {
    let plugin_id = PluginId::new();
    let fidelity = |level, max_events, max_bytes, max_cpu_us| FidelityBudgetV1 {
        level,
        max_events,
        max_bytes,
        max_cpu_us,
        shared_host_cpu_reservation_us: 0,
    };
    let budget = ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
        revision: 1,
        workload_profile: WorkloadProfileV1::Interactive,
        cut_budget_family: 0,
        max_event_bytes: 4_096,
        fidelity_budgets: [
            fidelity(0, 1_000, 64 * 1024 * 1024, 500_000),
            fidelity(1, 1_000, 64 * 1024 * 1024, 250_000),
            fidelity(2, 1_000, 16 * 1024 * 1024, 50_000),
        ],
        plugin_cpu_reservations: vec![PluginCpuReservationV1 {
            plugin_id,
            cpu_reservations_us: [10; 3],
        }],
        accounting_semantics: 0,
        execution_profile_hash: Hash::from_bytes([0x41; 32]),
        max_pass_wall_duration_us: 1_000,
    })
    .test_ok();
    let declaration = OutputDeclarationV1::new(
        EPHEMERAL.to_owned(),
        OutputAuthorityV1::Ephemeral,
        OutputFidelityV1::L0,
        4_096,
        None,
        None,
    )
    .test_ok();
    let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "test".to_owned(),
        implementation_hash: Hash::from_bytes([0x42; 32]),
        base_configuration_digest: Hash::from_bytes([0x43; 32]),
        executable_profile_hash: budget.digest(),
        retention_policy_hash: Hash::from_bytes([0x44; 32]),
        policy_revision: 1,
        output_declarations: vec![declaration],
    })
    .test_ok();
    let (driver, _) = probe("producer", 99, &[]);
    registry
        .register_test_driver_with_output_policy(
            plugin_id,
            "test",
            policy,
            budget,
            Box::new(driver),
        )
        .test_ok();
}

#[test]
fn an_ephemeral_declared_event_is_not_forwarded_but_the_history_node_keeps_it() {
    let mut registry = gated_registry();
    register_ephemeral_producer(&mut registry);
    let (consumer, seen) = probe("consumer", 1, &[PLAIN, EPHEMERAL]);
    registry.register_test_driver(Box::new(consumer));
    registry.compose_non_participant_drivers().test_ok();
    let timeline = TimelineId::new();
    let events = [event(1, EPHEMERAL), event(2, PLAIN), event(3, EPHEMERAL)];

    assert!(step(&mut registry, timeline, 3, &events).is_empty());
    assert_eq!(taken(&seen), [2]);
    commit_empty(&mut registry, 3);
    let consumer_id = ids(&registry)[1];
    assert_eq!(
        registry.plugins[&consumer_id].pass_state.carried,
        carried_set(2, 2)
    );

    // A restore hands the Driver the whole visible history, Ephemeral-typed
    // Events included, and the history node covers all of them.
    registry
        .restore_driver_state(&restore_segment(timeline, 3), &events)
        .test_ok();
    let expected = history_digest(Hash::zero(), 1, 3);
    assert_eq!(pending_content(&registry, consumer_id), Some(expected));
}

const fn restore_segment(timeline: TimelineId, through: u64) -> [TimelineHistorySegment; 1] {
    let through = Seq::from_u64(through);
    [TimelineHistorySegment::new(timeline, through)]
}

#[test]
fn a_restore_sets_one_shared_pending_history_node_and_the_restored_head() {
    let (mut registry, timeline, _) = plain_registry(2);
    let consent = Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1);
    let mut events = plain_events(1, 3);
    events[1].event_type = consent;
    registry
        .restore_driver_state(&restore_segment(timeline, 3), &events)
        .test_ok();

    // The consent Event is host control-plane history: it is not covered.
    let covered = [refs(1, 1)[0], refs(3, 3)[0]];
    let one = Seq::from_u64(1);
    let expected = factual_history_content_digest(Hash::zero(), one, Seq::from_u64(3), &covered);
    for id in ids(&registry) {
        assert_eq!(pending_content(&registry, id), Some(expected));
        assert_eq!(registry.plugins[&id].event_cursor, Seq::from_u64(3));
        assert!(registry.plugins[&id].pass_state.carried.is_empty());
    }
}

#[test]
fn a_restore_with_only_non_visible_events_sets_the_cursor_and_no_node() {
    let (mut registry, timeline, _) = plain_registry(1);
    let consent = Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1);
    let mut events = plain_events(1, 2);
    for item in &mut events {
        item.event_type = consent.clone();
    }
    registry
        .restore_driver_state(&restore_segment(timeline, 2), &events)
        .test_ok();
    let id = ids(&registry)[0];
    assert_eq!(pending_content(&registry, id), None);
    assert_eq!(registry.plugins[&id].event_cursor, Seq::from_u64(2));

    // An empty history restores to no node as well.
    registry
        .restore_driver_state(&restore_segment(timeline, 0), &[])
        .test_ok();
    assert_eq!(pending_content(&registry, id), None);
}

#[test]
fn a_restore_on_a_used_registry_resets_the_carried_set_and_the_history() {
    let (mut registry, timeline, _) = plain_registry(1);
    let id = ids(&registry)[0];
    step_plain(&mut registry, timeline, 2);
    commit_empty(&mut registry, 2);
    registry.plugins[&id].pass_state.history = HistoryInputV1::Pending {
        content: Hash::from_bytes([7; 32]),
    };
    assert_eq!(registry.plugins[&id].pass_state.carried, carried_set(1, 2));

    registry
        .restore_driver_state(&restore_segment(timeline, 4), &plain_events(1, 4))
        .test_ok();
    assert!(registry.plugins[&id].pass_state.carried.is_empty());
    let expected = history_digest(Hash::zero(), 1, 4);
    assert_eq!(pending_content(&registry, id), Some(expected));
    assert_eq!(registry.plugins[&id].event_cursor, Seq::from_u64(4));
}
