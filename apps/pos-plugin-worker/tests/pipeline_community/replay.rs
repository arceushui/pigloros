//! PCF-CPH-011 and PCF-CPH-012: Replay and lost-acknowledgement recovery parity (#635).
//!
//! Replay and recovery work from committed evidence, never by running a Plugin again
//! (ADR-021 decision 7). A Replay registry folds the committed Events of either isolation class
//! into the same projection as the live registry that committed them, and it steps no Driver:
//! the first-party twin does not run and the community Driver launches no worker. The
//! projection is a first-party observer's Reducer, which every registry folds alike; it records
//! the Timeline Order and type of each Event of the fixtures' entity and the size of their
//! payloads. The observer joins the live registry only after its pass is observed, so both
//! registries run the same fold over the same committed Events and their projections are equal
//! by construction; what the case proves is that the Events of either class fold and that no
//! Plugin runs. The Replay refusal is proven at the registry seam that steps Drivers, not
//! through a whole host pass.
//!
//! A pass whose commit acknowledgement is lost is in doubt: the store committed the batch, and
//! the registry keeps the staged pass. Recovery resubmits the retained basis once and returns the
//! receipt of the batch the lost commit wrote. It commits nothing twice, runs no first-party
//! Driver and launches no worker, and a second recovery finds nothing in doubt. The community
//! member's receipt stays staged until the recovery, which adopts its state; that bookkeeping
//! belongs to the community isolation class, so it is recorded, not compared.

use std::sync::atomic::Ordering;

use pos_core::{
    Capability, Event, EventDraft, Kind, PipelineCommitReceiptV1, Plugin, PluginId, Reducer, Seq,
    State, TimelineId,
};
use pos_plugin_publisher::test_support::{encoding::TICK, world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::{initial, World as PassWorld};
use pos_runtime::community_plugin_host::{
    CommunityPassOutcomeV1, CommunityPluginModeV1 as Mode, PassResultV1,
};
use pos_runtime::{PluginAvailabilityV1, PluginRegistrationV1, PluginRegistry, RuntimeError};
use serde_json::Value;

use crate::authority::refusal_of;
use crate::failure::{describe, record_pass, Mixed, Pass, SIBLING};
use crate::first_party::{entity_of, native_pin, register_switched, register_twin, Switched};
use crate::harness::Capture;
use crate::parity::{record, Order, ENTITY, STORE, TWIN_TYPE};
use crate::support::lane::{publish, Lane, Published, ALPHA, EVENT_TYPE};
use crate::support::subcase::WORKER;
use crate::support::test_ok::TestOk;

/// The Plugin name, Reducer name and pin role of the projection observer.
const OBSERVER: &str = "parity-projection";
/// The Event type the observer owns; no Driver emits it.
const OBSERVER_TYPE: &str = "parity.projection";
/// The projection field that lists every folded Event as `seq:type`, in Timeline Order.
const LEDGER: &str = "ledger";
/// The projection field that sums the payload sizes of the folded Events.
const PAYLOAD_BYTES: &str = "payload-bytes";

/// A first-party Plugin with a Reducer and no Driver, whose projection the cases compare.
struct Observer {
    id: PluginId,
}

impl Plugin for Observer {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        OBSERVER
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(OBSERVER_TYPE)],
            has_reducer: true,
            ..Capability::default()
        }
    }
}

/// The observer's Reducer: it folds every Event the registry offers it.
struct Ledger;

impl Reducer for Ledger {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        let previous = state.get(LEDGER).and_then(Value::as_str);
        let previous = previous.unwrap_or_default();
        let separator = if previous.is_empty() { "" } else { "," };
        let (seq, event_type) = (event.seq.as_u64(), event.event_type.as_str());
        let ledger = format!("{previous}{separator}{seq}:{event_type}");
        let folded = state.get(PAYLOAD_BYTES).and_then(Value::as_u64);
        let size = event.payload.as_slice().len();
        let size = u64::try_from(size).unwrap_or(u64::MAX);
        let bytes = folded.unwrap_or_default().saturating_add(size);
        state.set(LEDGER, Value::from(ledger));
        state.set(PAYLOAD_BYTES, Value::from(bytes));
    }
}

/// Register the projection observer in `registry`.
///
/// # Errors
/// Returns the registry's registration error.
fn add_observer(registry: &mut PluginRegistry) -> BoxResult<()> {
    let plugin = Observer {
        id: PluginId::new(),
    };
    let available = PluginAvailabilityV1::Available;
    let registration = PluginRegistrationV1::new(native_pin(OBSERVER)?, available);
    let reducer: Box<dyn Reducer> = Box::new(Ledger);
    Ok(registry.register_pinned_generated(&plugin, registration, Some(reducer), None)?)
}

/// The ledger of the fixtures' entity in `state`, or `none`.
fn ledger_of(state: Option<&State>) -> String {
    let ledger = state.and_then(|state| state.get(LEDGER));
    let ledger = ledger.and_then(Value::as_str);
    ledger.unwrap_or("none").to_owned()
}

/// What a live and a Replay registry folded from the same committed Events.
struct Folded {
    /// The live registry's ledger of the fixtures' entity.
    live: String,
    /// The Replay registry's ledger of the fixtures' entity.
    replay: String,
    /// Whether the two whole projection snapshots are equal, payload sizes included.
    same: bool,
}

/// Read the projections `live` and `replay` folded from `events` on `timeline`.
///
/// # Errors
/// Returns the registry's export refusal or the projection's read refusal.
fn read_both(
    live: PluginRegistry,
    replay: PluginRegistry,
    timeline: TimelineId,
    events: &[Event],
) -> BoxResult<Folded> {
    let head = events.last().map_or(Seq::ZERO, |event| event.seq);
    let live = live.into_authorized_projections(timeline, head, 0, None, Some(events))?;
    let replay = replay.into_authorized_projections(timeline, head, 0, None, Some(events))?;
    let entity = entity_of(ENTITY)?;
    let live_state = live.state_for_reducer(timeline, OBSERVER, &entity)?;
    let replay_state = replay.state_for_reducer(timeline, OBSERVER, &entity)?;
    let same = live.state_snapshot(timeline)? == replay.state_snapshot(timeline)?;
    Ok(Folded {
        live: ledger_of(live_state.as_ref()),
        replay: ledger_of(replay_state.as_ref()),
        same,
    })
}

/// A Replay registry over the twin, the community Driver and the observer, in that order.
///
/// The community Driver is built from `entries` in `mode`; the twin's switches are returned with
/// the lane.
///
/// # Errors
/// Returns the error of registering a Plugin or of building the lane.
fn replay_lane(
    signed: &SignedWorld,
    entries: &[Published],
    mode: Mode,
) -> BoxResult<(Lane, Switched)> {
    let mut pass = PassWorld::new(WORKER);
    let gate = pass.gate.clone();
    pass.registry = PluginRegistry::new_replay().with_erasure_gate(gate);
    let twin = register_switched(&mut pass.registry, SIBLING, entity_of(ENTITY)?)?;
    let mut lane = Lane::over(signed, entries, mode, pass)?;
    add_observer(&mut lane.pass.registry)?;
    Ok((lane, twin))
}

/// The typed refusal of a Replay registry's attempt to step its Drivers, or what it staged.
fn step_refusal(stepped: Result<Vec<EventDraft>, RuntimeError>) -> String {
    match stepped {
        Ok(drafts) => format!("Stepped({})", drafts.len()),
        Err(RuntimeError::ModeMismatch { expected, got }) => {
            format!("ModeMismatch({expected},{got})")
        }
        Err(error) => refusal_of(&error),
    }
}

/// The Timeline Order, type, entity and payload bytes of every Event.
fn content(events: &[Event]) -> Vec<String> {
    let row = |event: &Event| {
        let (seq, event_type) = (event.seq.as_u64(), event.event_type.as_str());
        let payload = event.payload.as_slice();
        format!("{seq}:{event_type}:{}:{payload:?}", event.entity)
    };
    events.iter().map(row).collect()
}

/// A live pass of a mixed lane in one Execution Mode, and the Replay of what it committed.
struct Replayed {
    /// The live pass, which commits both Events.
    live: Pass,
    /// The live and the Replay projections.
    folded: Folded,
    /// The Replay registry's refusal to step its Drivers.
    step: String,
    /// The Replay registry's Driver steps, in registration order.
    replay_steps: String,
    /// The live lane's Driver steps while the Replay ran, in registration order.
    live_steps: String,
    /// What the live pass committed.
    content: Vec<String>,
}

impl Replayed {
    /// Whether the Replay folded what the live registry folded, and nothing ran meanwhile.
    ///
    /// The ledger must name both classes' Events, and no Driver of either registry may step
    /// while the Replay runs.
    fn holds(&self) -> bool {
        let ledger = &self.folded.live;
        self.folded.same
            && *ledger == self.folded.replay
            && ledger.contains(TWIN_TYPE)
            && ledger.contains(EVENT_TYPE)
            && self.replay_steps == "0,0"
            && self.live_steps == "0,0"
    }
}

/// Commit both Events through a live mixed lane in `mode`, then replay them.
///
/// The live registry and a Replay registry over the same Plugins fold the committed Events, and
/// the Replay registry is asked to step its Drivers once.
fn replayed(signed: &SignedWorld, entries: &[Published], mode: Mode) -> BoxResult<Replayed> {
    let mut mixed = Mixed::in_mode(signed, entries, SIBLING, Order::TwinFirst, mode)?;
    let live = mixed.pass(signed)?;
    let timeline = mixed.lane.pass.timeline;
    let committed = mixed.lane.pass.events();
    let ancestry = pos_core::fork_ancestry(&mixed.lane.pass.store, timeline)?;
    add_observer(&mut mixed.lane.pass.registry)?;
    mixed.lane.pass.registry.fold_events(timeline, &committed);
    let (mut replay, twin) = replay_lane(signed, entries, mode)?;
    let registry = &mut replay.pass.registry;
    registry.fold_events(timeline, &committed);
    let head = committed.last().map_or(Seq::ZERO, |event| event.seq);
    let step = registry.step_all_anchored_with_events(timeline, &ancestry, head, &committed);
    let twin_steps = twin.steps.load(Ordering::SeqCst);
    let launches = replay.handle().receipts().len();
    let live_steps = mixed.steps_since();
    let live_registry = std::mem::take(&mut mixed.lane.pass.registry);
    let replay_registry = std::mem::take(&mut replay.pass.registry);
    Ok(Replayed {
        live,
        folded: read_both(live_registry, replay_registry, timeline, &committed)?,
        step: step_refusal(step),
        replay_steps: format!("{twin_steps},{launches}"),
        live_steps,
        content: content(&committed),
    })
}

/// Record one live pass and its Replay under `path`.
fn record_replayed(capture: &mut Capture, path: &str, replayed: &Replayed) {
    let live = format!("{path}-live");
    record(capture, &live, &replayed.live.observed);
    let mut put = |key: &str, value: &dyn std::fmt::Display| {
        capture.record(STORE, &format!("{path}.{key}"), value);
    };
    put("live-projection", &replayed.folded.live);
    put("replay-projection", &replayed.folded.replay);
    put("replay-equals-live", &replayed.folded.same);
    put("replay-step", &replayed.step);
    put("replay-steps", &replayed.replay_steps);
    put("live-steps-during-replay", &replayed.live_steps);
}

/// PCF-CPH-011: Replay folds committed Events of either class without running a Plugin.
///
/// A mixed lane commits the first-party twin's and the community Driver's Events in one pass on
/// the real worker. A Replay registry over the same two Drivers and the projection observer
/// folds them into the projection the live registry folds, refuses to step its Drivers, and
/// neither registry steps the twin or launches a worker. The Local and Air-Gapped lanes commit
/// the same Events, payload bytes included, and fold the same projection.
#[must_use]
pub fn replay_parity() -> Capture {
    replay().test_ok()
}

fn replay() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let local = replayed(&signed, entries, Mode::Local)?;
    let air_gapped = replayed(&signed, entries, Mode::AirGapped)?;
    let mut capture = Capture::default();
    record_replayed(&mut capture, "local", &local);
    record_replayed(&mut capture, "air-gapped", &air_gapped);
    let either = local.holds() && air_gapped.holds();
    let key = "parity.replay-equals-live-either-class";
    capture.record(STORE, key, either);
    let same = local.content == air_gapped.content && local.folded.live == air_gapped.folded.live;
    capture.record(STORE, "parity.local-equals-air-gapped", same);
    Ok(capture)
}

/// Recover the pass `lane`'s registry holds in doubt, described as the pass result it settles.
fn recover(lane: &mut Lane) -> CommunityPassOutcomeV1 {
    let store = &mut lane.pass.store;
    let recovered = lane.pass.registry.recover_scheduled_pass(store);
    let result = recovered.map_or_else(
        |error| PassResultV1::Failed {
            host: None,
            error: Box::new(error),
        },
        |receipt| PassResultV1::Committed(receipt.map(Box::new)),
    );
    CommunityPassOutcomeV1 {
        tick: TICK,
        utc: None,
        gates: Vec::new(),
        result,
    }
}

/// What a second recovery of `lane` finds.
fn recover_again(lane: &mut Lane) -> String {
    let store = &mut lane.pass.store;
    match lane.pass.registry.recover_scheduled_pass(store) {
        Ok(receipt) => format!("Recovered({})", receipt.as_ref().map_or(0, events_of)),
        Err(RuntimeError::NoScheduledAdmissionInDoubt) => "NoScheduledAdmissionInDoubt".to_owned(),
        Err(error) => refusal_of(&error),
    }
}

/// The number of Events `receipt` names.
fn events_of(receipt: &PipelineCommitReceiptV1) -> usize {
    receipt.committed_events().len()
}

/// A pass whose commit acknowledgement was lost, and its recovery.
struct Recovery {
    /// The pass in doubt.
    lost: Pass,
    /// The recovery, described as the pass result it settles, with the Driver steps it ran.
    recovered: Pass,
    /// Whether the Timeline after the recovery is the one the lost commit wrote.
    unchanged: bool,
    /// Whether the recovery stepped a Driver or launched a worker.
    reran: bool,
    /// What a second recovery finds.
    again: String,
}

impl Recovery {
    /// Whether the pass was in doubt and its recovery ran no Plugin and committed nothing again.
    ///
    /// The recovery must return a receipt of the committed batch, and only once.
    fn holds(&self) -> bool {
        self.lost.observed.result() == "InDoubt"
            && self.lost.observed.committed() == 0
            && self.recovered.observed.result() == "Committed"
            && self.recovered.observed.committed() > 0
            && self.unchanged
            && !self.reran
            && self.again == "NoScheduledAdmissionInDoubt"
    }
}

/// What the community member of a mixed lane shows.
struct Trace {
    /// The failure and disposition of every receipt.
    receipts: String,
    /// Whether the member's committed state is still the initial one or adopted a step's.
    state: &'static str,
}

/// What the community member of `mixed` shows now.
fn trace(mixed: &Mixed) -> Trace {
    let adopted = mixed.lane.handle().committed_state() != initial();
    Trace {
        receipts: mixed.receipts(),
        state: if adopted { "adopted" } else { "initial" },
    }
}

/// A mixed lane whose pass loses its commit acknowledgement, then recovers it.
///
/// Both Drivers stage before the commit; the community member is returned as it was before and
/// after the recovery.
fn mixed_recovery(
    signed: &SignedWorld,
    entries: &[Published],
) -> BoxResult<(Recovery, Trace, Trace)> {
    let mut mixed = Mixed::new(signed, entries, SIBLING, Order::TwinFirst)?;
    let lost = mixed.lost_pass(signed)?;
    let before = trace(&mixed);
    let events = mixed.lane.pass.events();
    let outcome = recover(&mut mixed.lane);
    let steps = mixed.steps_since();
    let reran = steps != "0,0";
    let recovered = describe(&mixed.lane, &outcome, steps);
    let after = trace(&mixed);
    let recovery = Recovery {
        lost,
        recovered,
        unchanged: events == mixed.lane.pass.events(),
        reran,
        again: recover_again(&mut mixed.lane),
    };
    Ok((recovery, before, after))
}

/// A first-party-only lane whose pass loses its commit acknowledgement, then recovers it.
fn first_party_recovery(signed: &SignedWorld) -> BoxResult<Recovery> {
    let mut pass = PassWorld::new(WORKER);
    let steps = register_twin(&mut pass.registry, EVENT_TYPE, entity_of(ENTITY)?)?;
    let mut lane = Lane::over(signed, &[], Mode::Local, pass)?;
    let outcome = lane.run_lost(signed)?;
    let stepped = steps.load(Ordering::SeqCst);
    let lost = describe(&lane, &outcome, stepped.to_string());
    let events = lane.pass.events();
    let outcome = recover(&mut lane);
    let rerun = steps.load(Ordering::SeqCst) - stepped;
    let recovered = describe(&lane, &outcome, rerun.to_string());
    Ok(Recovery {
        lost,
        recovered,
        unchanged: events == lane.pass.events(),
        reran: rerun != 0,
        again: recover_again(&mut lane),
    })
}

/// Record a recovery under `path`.
fn record_recovery(capture: &mut Capture, path: &str, recovery: &Recovery) {
    record_pass(capture, &format!("{path}-lost"), &recovery.lost);
    let recovered = format!("{path}-recovered");
    record_pass(capture, &recovered, &recovery.recovered);
    let unchanged = format!("{path}.timeline-unchanged-by-recovery");
    capture.record(STORE, &unchanged, recovery.unchanged);
    let again = format!("{path}.recover-again");
    capture.record(STORE, &again, &recovery.again);
}

/// Record what the community member shows under `path`.
fn record_trace(capture: &mut Capture, path: &str, trace: &Trace) {
    let receipts = format!("{path}.community-receipts");
    capture.record(STORE, &receipts, &trace.receipts);
    let state = format!("{path}.community-state");
    capture.record(STORE, &state, trace.state);
}

/// PCF-CPH-012: lost-acknowledgement recovery without running a Plugin again.
///
/// A mixed lane's pass on the real worker, and a first-party-only lane's pass, each commit
/// through an admission port that loses the acknowledgement: the pass is in doubt and the batch
/// is on the Timeline. `recover_scheduled_pass` returns a receipt that names exactly the Events
/// the lost commit wrote, commits nothing again, steps no first-party Driver and launches no
/// worker; a second recovery finds nothing in doubt. The community member's receipt is staged
/// until the recovery commits it and adopts its state.
#[must_use]
pub fn lost_acknowledgement_recovery() -> Capture {
    lost_acknowledgement().test_ok()
}

fn lost_acknowledgement() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let (mixed, before, after) = mixed_recovery(&signed, entries)?;
    let first_party = first_party_recovery(&signed)?;
    let mut capture = Capture::default();
    record_recovery(&mut capture, "mixed", &mixed);
    record_trace(&mut capture, "mixed-lost", &before);
    record_trace(&mut capture, "mixed-recovered", &after);
    record_recovery(&mut capture, "first-party", &first_party);
    let either = mixed.holds() && first_party.holds();
    let key = "parity.recovered-without-rerun-either-class";
    capture.record(STORE, key, either);
    Ok(capture)
}
