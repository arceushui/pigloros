//! PCF-CPH-001 and PCF-CPH-002: first-party versus community semantic parity (#489).
//!
//! A first-party native Driver and a community Driver on the real worker commit through the same
//! scheduled pass and admission path, with the same authority outcome (ADR-021 decision 7).
//!
//! Parity is semantic: the result of the pass, the Timeline Order and Event types, the entity of
//! each Event, the commit receipt, the number of Driver steps, the availability of every
//! registered Plugin and the scheduled observation profile. The owner's isolation class is
//! recorded and is expected to differ; payload bytes are compared only between the Local and
//! Air-Gapped runs of the same community release.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use pos_core::{Event, ScheduledObservationProfileV1};
use pos_plugin_publisher::test_support::{world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::World as PassWorld;
use pos_runtime::community_plugin_host::{
    CommunityPassOutcomeV1, CommunityPluginModeV1 as Mode, PassResultV1,
};
use pos_runtime::{PluginRegistry, ScheduledDriverBindingV1};

use crate::first_party::{entity_of, register_twin};
use crate::harness::{Capture, PROFILE_KEY};
use crate::support::lane::{publish, Lane, Published, ALPHA, EVENT_TYPE};
use crate::support::subcase::WORKER;

/// The only store of the community pass world.
const STORE: &str = "memory";
/// The entity of the community fixture's Event: the first member's invocation ID, sixteen bytes
/// of 1, as ULID text. The twin emits for the same entity.
const ENTITY: &str = "01040G2081040G2081040G2081";
/// The Event type the first-party twin owns beside the community Plugin in a mixed registry.
const TWIN_TYPE: &str = "parity.first-party";

/// Unwrap a fixture step, failing the runner with the unexpected error.
///
/// `resume_unwind` is deliberate: the workspace denies `unwrap`, `expect` and `panic!`, and the
/// suite harness catches the unwind and reports it as a `RunnerPanicked` failure of the case.
pub trait TestOk<T> {
    /// The value, or an unwind that names the error.
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

/// What one pass shows of its authority outcome, the owner's isolation class aside.
#[derive(Debug, PartialEq, Eq)]
struct Authority {
    result: &'static str,
    timeline: String,
    entities: String,
    receipt_names_events: bool,
    steps: String,
    availability: String,
    profile: String,
}

/// One observed pass.
struct Observed {
    authority: Authority,
    /// `type=isolation` of every Event, in Timeline Order.
    owners: Vec<String>,
    /// Whether the Events follow the host schedule order of their owners.
    follows_schedule: bool,
    payloads: Vec<Vec<u8>>,
}

const fn result_name(result: &PassResultV1) -> &'static str {
    match result {
        PassResultV1::Committed(Some(_)) => "Committed",
        PassResultV1::Committed(None) => "CommittedNothing",
        PassResultV1::Refused => "Refused",
        PassResultV1::Failed { .. } => "Failed",
        PassResultV1::InDoubt => "InDoubt",
    }
}

/// Whether the commit receipt names exactly the committed Events, in Timeline Order.
fn receipt_names(result: &PassResultV1, events: &[Event]) -> bool {
    let PassResultV1::Committed(Some(receipt)) = result else {
        return false;
    };
    let named = receipt.committed_events().iter();
    let named = named.map(|event| (event.event_id(), event.seq()));
    named.eq(events.iter().map(|event| (event.id, event.seq)))
}

/// The owning Plugin's name and isolation class of every Event type. The composition and the
/// ownership rows are both in registration order.
fn owners(registry: &PluginRegistry) -> BTreeMap<String, (String, String)> {
    let mut owners = BTreeMap::new();
    let rows = registry.plugin_ownership_rows();
    for (plugin, (types, _closure)) in registry.composition().plugins.into_iter().zip(rows) {
        let isolation = plugin.pin.map_or_else(
            || "Unpinned".to_owned(),
            |pin| format!("{:?}", pin.isolation()),
        );
        for event_type in types {
            owners.insert(event_type, (plugin.name.clone(), isolation.clone()));
        }
    }
    owners
}

/// The availability of every registered Plugin, in registration order.
fn availability(registry: &PluginRegistry) -> String {
    let plugins = registry.composition().plugins;
    let names: Vec<String> = plugins
        .iter()
        .map(|plugin| {
            let availability = registry.availability(plugin.id);
            availability.map_or_else(|| "None".to_owned(), |value| format!("{value:?}"))
        })
        .collect();
    names.join(",")
}

/// The scheduled observation profile of every registered Driver, once each.
fn profile(registry: &PluginRegistry) -> String {
    let plugins = registry.composition().plugins;
    let mut profiles: Vec<&str> = plugins
        .iter()
        .map(|plugin| {
            let binding = registry.scheduled_binding(plugin.id);
            match binding.map(ScheduledDriverBindingV1::profile) {
                Some(ScheduledObservationProfileV1::NonParticipant) => "non-participant",
                Some(ScheduledObservationProfileV1::ParticipantBound) => "participant-bound",
                None => "unassigned",
            }
        })
        .collect();
    profiles.dedup();
    profiles.join(",")
}

/// Describe the pass `outcome` of `lane`, whose Drivers stepped `steps` times in registration
/// order.
fn observe(lane: &Lane, outcome: &CommunityPassOutcomeV1, steps: String) -> Observed {
    let registry = &lane.pass.registry;
    let events = lane.pass.events();
    let owners = owners(registry);
    let owner_of = |event: &Event| owners.get(event.event_type.as_str()).cloned();
    let owned: Vec<(String, String)> = events.iter().filter_map(owner_of).collect();
    let schedule: Vec<String> = registry.plugin_names().map(str::to_owned).collect();
    let emitted: Vec<&String> = owned.iter().map(|(name, _)| name).collect();
    let scheduled: Vec<&String> = schedule
        .iter()
        .filter(|name| emitted.contains(name))
        .collect();
    let timeline: Vec<String> = events
        .iter()
        .map(|event| format!("{}:{}", event.seq.as_u64(), event.event_type.as_str()))
        .collect();
    let entities: Vec<String> = events
        .iter()
        .map(|event| event.entity.to_string())
        .collect();
    let typed = events.iter().zip(&owned);
    let owner_types = typed.map(|(event, (_, isolation))| {
        let event_type = event.event_type.as_str();
        format!("{event_type}={isolation}")
    });
    let payload = |event: &Event| event.payload.as_slice().to_vec();
    Observed {
        authority: Authority {
            result: result_name(&outcome.result),
            timeline: timeline.join(","),
            entities: entities.join(","),
            receipt_names_events: receipt_names(&outcome.result, &events),
            steps,
            availability: availability(registry),
            profile: profile(registry),
        },
        owners: owner_types.collect(),
        follows_schedule: owned.len() == events.len() && emitted == scheduled,
        payloads: events.iter().map(payload).collect(),
    }
}

/// Record what `observed` shows under `path`.
fn record(capture: &mut Capture, path: &str, observed: &Observed) {
    let authority = &observed.authority;
    let mut put = |key: &str, value: &dyn std::fmt::Display| {
        capture.record(STORE, &format!("{path}.{key}"), value);
    };
    put("result", &authority.result);
    put("timeline", &authority.timeline);
    put("entity", &authority.entities);
    put("receipt.names-events", &authority.receipt_names_events);
    put("steps", &authority.steps);
    put("availability", &authority.availability);
    put("owner", &observed.owners.join(","));
    put("follows-host-schedule", &observed.follows_schedule);
    capture.record(STORE, PROFILE_KEY, &authority.profile);
}

/// The Local pass of a lane over the first-party twin alone, owning the fixture's Event type.
fn first_party_pass(signed: &SignedWorld) -> BoxResult<Observed> {
    let mut pass = PassWorld::new(WORKER);
    let (_, steps) = register_twin(&mut pass.registry, EVENT_TYPE, entity_of(ENTITY)?)?;
    let mut lane = Lane::over(signed, &[], Mode::Local, pass)?;
    let outcome = lane.run(signed)?;
    let steps = steps.load(Ordering::SeqCst).to_string();
    Ok(observe(&lane, &outcome, steps))
}

/// The pass of a lane in `mode` over the community release `entries` alone.
fn community_pass(signed: &SignedWorld, entries: &[Published], mode: Mode) -> BoxResult<Observed> {
    let mut lane = Lane::new(signed, entries, mode)?;
    let outcome = lane.run(signed)?;
    let steps = lane.handle().receipts().len().to_string();
    Ok(observe(&lane, &outcome, steps))
}

/// PCF-CPH-001: single-pass first-party versus community semantic parity.
///
/// The first-party twin and the community release, each alone in its registry, commit their
/// Event through the same pass with the same authority outcome, and the community release's
/// Local and Air-Gapped passes are identical, payload bytes included.
#[must_use]
pub fn single_pass_parity() -> Capture {
    single_pass().test_ok()
}

fn single_pass() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let first_party = first_party_pass(&signed)?;
    let local = community_pass(&signed, entries, Mode::Local)?;
    let air_gapped = community_pass(&signed, entries, Mode::AirGapped)?;
    let mut capture = Capture::default();
    record(&mut capture, "first-party", &first_party);
    record(&mut capture, "community-local", &local);
    record(&mut capture, "community-air-gapped", &air_gapped);
    let parity = first_party.authority == local.authority;
    capture.record(STORE, "parity.first-party-equals-community", parity);
    let same = local.authority == air_gapped.authority
        && local.owners == air_gapped.owners
        && local.payloads == air_gapped.payloads;
    capture.record(STORE, "parity.local-equals-air-gapped", same);
    Ok(capture)
}

/// Which Driver a mixed registry registers first.
#[derive(Clone, Copy)]
enum Order {
    TwinFirst,
    CommunityFirst,
}

/// The Local pass of one registry holding both the twin and the community release, registered
/// in `order`.
fn mixed_pass(signed: &SignedWorld, entries: &[Published], order: Order) -> BoxResult<Observed> {
    let entity = entity_of(ENTITY)?;
    let (mut lane, twin) = match order {
        Order::TwinFirst => {
            let mut pass = PassWorld::new(WORKER);
            let (_, twin) = register_twin(&mut pass.registry, TWIN_TYPE, entity)?;
            (Lane::over(signed, entries, Mode::Local, pass)?, twin)
        }
        Order::CommunityFirst => {
            let mut lane = Lane::new(signed, entries, Mode::Local)?;
            let (_, twin) = register_twin(&mut lane.pass.registry, TWIN_TYPE, entity)?;
            (lane, twin)
        }
    };
    let outcome = lane.run(signed)?;
    let community = lane.handle().receipts().len();
    let twin = twin.load(Ordering::SeqCst);
    let steps = match order {
        Order::TwinFirst => format!("{twin},{community}"),
        Order::CommunityFirst => format!("{community},{twin}"),
    };
    Ok(observe(&lane, &outcome, steps))
}

/// The owners of `observed` in a fixed order, so that two registration orders compare.
fn sorted(observed: &Observed) -> Vec<String> {
    let mut owners = observed.owners.clone();
    owners.sort_unstable();
    owners
}

/// PCF-CPH-002: a mixed registry commits in host schedule order.
///
/// In one registry holding both Drivers, the pass commits both Events in one batch, in host
/// schedule order, whichever isolation class is registered first; the committed Events, owners
/// and entities are the same in either registration order.
#[must_use]
pub fn mixed_registry_order() -> Capture {
    mixed_registry().test_ok()
}

fn mixed_registry() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let twin_first = mixed_pass(&signed, entries, Order::TwinFirst)?;
    let community_first = mixed_pass(&signed, entries, Order::CommunityFirst)?;
    let mut capture = Capture::default();
    record(&mut capture, "twin-first", &twin_first);
    record(&mut capture, "community-first", &community_first);
    let same = sorted(&twin_first) == sorted(&community_first)
        && twin_first.authority.entities == community_first.authority.entities;
    capture.record(STORE, "same-events-either-order", same);
    Ok(capture)
}
