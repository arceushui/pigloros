//! PCF-CPH-007 to PCF-CPH-009: missing, unavailable and invalid Plugins fail closed (#633).
//!
//! A missing, unavailable or invalid required Plugin fails closed with a typed outcome, and the
//! host has no runtime default (ADR-021 decision 7). Exact composition resolution gives the same
//! typed refusal for a first-party and a community requirement. A pass refuses an unavailable
//! Plugin of either class with the same typed refusal before any Driver runs, and resumes once
//! the host makes the Plugin available again.
//!
//! Only the community path has a release: a release that is not the active one is refused at
//! the trust gate, and a release whose capability the host denies never becomes a Driver. The
//! first-party counterparts of an invalid draft are the authority refusals of PCF-CPH-003; an
//! invalid community guest output needs a new guest Component and is recorded as an exclusion.

use pos_core::PluginId;
use pos_plugin_publisher::test_support::{release::Shape, world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::{GatedSpec, Source, World as PassWorld};
use pos_plugin_supervisor::register_community_driver;
use pos_plugin_supervisor::test_support::{community_pin, DriverPlugin};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1 as HostError, CommunityPluginModeV1 as Mode,
    RevocationBasisV1 as Revoke,
};
use pos_runtime::{
    PluginAvailabilityV1, PluginExecutionModeV1, PluginIsolationV1, PluginPinV1, PluginRegistry,
    RequiredPluginCompositionV1, RequiredPluginV1,
};

use crate::authority::{community_driver, composition_refusal, refusal_of, snapshot};
use crate::failure::{record_pass, Mixed, Pass, SIBLING};
use crate::first_party::{entity_of, native_pin, register_twin, NAME};
use crate::harness::Capture;
use crate::parity::{record, Order, ENTITY, STORE, TWIN_TYPE};
use crate::support::lane::{
    gated_release, profile, publish, publish_shape, trust_material, Published, Swap, ALPHA, ALPHA_C,
    WATCHDOG,
};
use crate::support::subcase::WORKER;
use crate::support::test_ok::TestOk;

/// The version every test Plugin reports.
const VERSION: &str = "0.1.0";

/// The requirement of every Plugin `registry` holds, in registration order.
///
/// The Plugin named `flipped` is required under the other isolation class.
fn registered(
    registry: &PluginRegistry,
    flipped: Option<&str>,
) -> BoxResult<Vec<RequiredPluginV1>> {
    let mut required = Vec::new();
    for plugin in registry.composition().plugins {
        let pin = plugin.pin.ok_or("an unpinned Plugin")?;
        let pin = if flipped == Some(plugin.name.as_str()) {
            other_isolation(&pin)?
        } else {
            pin
        };
        required.push(RequiredPluginV1::try_new(plugin.id, plugin.version, pin)?);
    }
    Ok(required)
}

/// `pin` under the other accepted isolation class.
fn other_isolation(pin: &PluginPinV1) -> BoxResult<PluginPinV1> {
    let isolation = match pin.isolation() {
        PluginIsolationV1::OperatorTrustedNative => PluginIsolationV1::GovernedCommunity,
        PluginIsolationV1::GovernedCommunity => PluginIsolationV1::OperatorTrustedNative,
    };
    let (kind, digest) = (pin.implementation_kind(), pin.configuration_digest());
    let other = PluginPinV1::try_new(kind, isolation, digest, pin.roles().to_vec())?;
    Ok(other)
}

/// The typed outcome of resolving the Local composition `required` against `registry`.
fn resolve(registry: &PluginRegistry, required: Vec<RequiredPluginV1>) -> BoxResult<String> {
    let required = RequiredPluginCompositionV1::try_new(PluginExecutionModeV1::Local, required)?;
    let refused = registry.resolve_required_composition(&required).err();
    let refusal = refused.as_ref().map(composition_refusal);
    Ok(refusal.unwrap_or_else(|| "Resolved".to_owned()))
}

/// The typed outcome of resolving every registered Plugin and one unregistered Plugin under
/// `pin`.
fn resolve_with_missing(registry: &PluginRegistry, pin: PluginPinV1) -> BoxResult<String> {
    let mut required = registered(registry, None)?;
    required.push(RequiredPluginV1::try_new(PluginId::new(), VERSION, pin)?);
    resolve(registry, required)
}

/// The successor of `first` on the C fixture, installed as the active release.
fn successor(signed: &mut SignedWorld, first: &Published) -> BoxResult<Published> {
    let shape = Shape {
        version: "2.0.0",
        previous: Some(first.release),
        ..ALPHA_C.shape()
    };
    publish_shape(signed, ALPHA_C, shape, 2)
}

/// The pass of `mixed` once its community member names a release that is not the active one.
///
/// The member's successor is installed and rolled back, and the member is supplied from the
/// successor's closure: the Plugin has no active release there.
fn not_active(signed: &mut SignedWorld, first: &Published, mixed: &mut Mixed) -> BoxResult<Pass> {
    let second = successor(signed, first)?;
    signed.rollback_to(&first.address, 3)??;
    let expected = mixed.lane.parts[0].expected.clone();
    mixed.lane.rehost(signed, &second.address, &expected)?;
    mixed.lane.follow(signed)?;
    mixed.pass(signed)
}

/// PCF-CPH-007: a missing implementation fails closed.
///
/// Exact resolution of a composition that requires an unregistered first-party Plugin, or an
/// unregistered community Plugin, is refused with the same `MissingImplementation`, while the
/// registered composition alone resolves. A community member whose release is not the active
/// one is refused at the trust gate: the pass runs no Driver, the first-party sibling is not run
/// in its place, and nothing is committed.
#[must_use]
pub fn missing_implementation() -> Capture {
    missing().test_ok()
}

fn missing() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let first = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&first);
    let mut mixed = Mixed::new(&signed, entries, SIBLING, Order::TwinFirst)?;
    let registry = &mixed.lane.pass.registry;
    let present = resolve(registry, registered(registry, None)?)?;
    let first_party = resolve_with_missing(registry, native_pin("missing-first-party")?)?;
    let community = resolve_with_missing(registry, community_pin(0x4d, "missing-community"))?;
    let pass = not_active(&mut signed, &first, &mut mixed)?;
    let mut capture = Capture::default();
    capture.record(STORE, "registered.resolve", &present);
    capture.record(STORE, "first-party-missing.resolve", &first_party);
    capture.record(STORE, "community-missing.resolve", &community);
    record(&mut capture, "community-not-active", &pass.observed);
    capture.record(STORE, "community-not-active.gate", &pass.gate);
    let same = first_party == community;
    capture.record(STORE, "parity.same-missing-either-class", same);
    Ok(capture)
}

/// Two passes refused for an unavailable Plugin and the pass after it is available again.
struct Refused {
    revoked: Pass,
    unavailable: Pass,
    resumed: Pass,
}

/// The ID of the Plugin named `name` in `registry`.
fn plugin_id(registry: &PluginRegistry, name: &str) -> BoxResult<PluginId> {
    let plugins = registry.composition().plugins;
    let found = plugins.into_iter().find(|plugin| plugin.name == name);
    Ok(found.ok_or("no Plugin of that name")?.id)
}

/// Record `availability` for the Plugin `id` of `mixed`, then run one pass.
fn set_and_pass(
    signed: &SignedWorld,
    mixed: &mut Mixed,
    id: PluginId,
    availability: PluginAvailabilityV1,
) -> BoxResult<Pass> {
    mixed.lane.pass.registry.set_availability(id, availability)?;
    mixed.pass(signed)
}

/// The first-party sibling, registered after the community release, made unavailable by the
/// host, then available again.
fn first_party_unavailable(signed: &SignedWorld, entries: &[Published]) -> BoxResult<Refused> {
    let mut mixed = Mixed::new(signed, entries, SIBLING, Order::CommunityFirst)?;
    let id = plugin_id(&mixed.lane.pass.registry, NAME)?;
    Ok(Refused {
        revoked: set_and_pass(signed, &mut mixed, id, PluginAvailabilityV1::Revoked)?,
        unavailable: set_and_pass(signed, &mut mixed, id, PluginAvailabilityV1::Unavailable)?,
        resumed: set_and_pass(signed, &mut mixed, id, PluginAvailabilityV1::Available)?,
    })
}

/// Quarantine the community member of `mixed` for the host's `error`, then run one pass.
fn quarantine_and_pass(
    signed: &SignedWorld,
    mixed: &mut Mixed,
    error: HostError,
) -> BoxResult<Pass> {
    let handle = &mixed.lane.parts[0].handle;
    handle.record_refusal(error);
    handle.sync_registry(&mut mixed.lane.pass.registry)?;
    mixed.pass(signed)
}

/// The community release, registered after the first-party sibling, quarantined by the host,
/// then cleared.
fn community_unavailable(signed: &SignedWorld, entries: &[Published]) -> BoxResult<Refused> {
    let mut mixed = Mixed::new(signed, entries, SIBLING, Order::TwinFirst)?;
    let revoked = HostError::ArtifactRevoked {
        basis: Revoke::Artifact,
    };
    let revoked = quarantine_and_pass(signed, &mut mixed, revoked)?;
    let unavailable = quarantine_and_pass(signed, &mut mixed, HostError::WorkerCrashed)?;
    mixed.clear()?;
    Ok(Refused {
        revoked,
        unavailable,
        resumed: mixed.pass(signed)?,
    })
}

/// Record the refused and the resumed passes under `path`.
fn record_refused(capture: &mut Capture, path: &str, refused: &Refused) {
    record_pass(capture, &format!("{path}-revoked"), &refused.revoked);
    let unavailable = format!("{path}-unavailable");
    record_pass(capture, &unavailable, &refused.unavailable);
    record_pass(capture, &format!("{path}-resumed"), &refused.resumed);
}

/// PCF-CPH-008: an unavailable implementation fails closed with the same typed refusal.
///
/// A first-party Plugin the host marks `Revoked` or `Unavailable`, and a community Plugin the
/// host quarantines as `Revoked` (a revoked artifact) or `Unavailable` (a crashed worker), each
/// refuse the whole pass with the same `ImplementationUnavailable` before any Driver runs, the
/// available sibling of the other class included. Once the Plugin is available again, the next
/// pass commits both Events.
#[must_use]
pub fn unavailable_implementation() -> Capture {
    unavailable().test_ok()
}

fn unavailable() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let first_party = first_party_unavailable(&signed, entries)?;
    let community = community_unavailable(&signed, entries)?;
    let mut capture = Capture::default();
    record_refused(&mut capture, "first-party", &first_party);
    record_refused(&mut capture, "community", &community);
    let same = first_party.revoked.refusal == community.revoked.refusal
        && first_party.unavailable.refusal == community.unavailable.refusal;
    capture.record(STORE, "parity.same-refusal-either-class", same);
    Ok(capture)
}

/// A community Driver of `entry` registered under an operator-trusted native pin: the refusal,
/// and whether the registry is unchanged.
fn native_pinned(signed: &SignedWorld, entry: &Published) -> BoxResult<(String, bool)> {
    let mut pass = PassWorld::new(WORKER);
    let before = snapshot(&pass.registry);
    let plugin = DriverPlugin {
        id: PluginId::new(),
        name: entry.spec.plugin_id,
        event_type: entry.spec.event_type,
        has_driver: true,
    };
    let driver = community_driver(signed, entry, plugin.id)?;
    let pin = native_pin("native-pinned-community")?;
    let registered = register_community_driver(&mut pass.registry, &plugin, pin, driver);
    let refusal = registered.map_or_else(|error| refusal_of(&error), |()| "accepted".to_owned());
    Ok((refusal, snapshot(&pass.registry) == before))
}

/// A release of `plugin-a` that requires a capability, in its own signed world, built into a
/// Driver beside the first-party twin: the refusal, and whether the registry is unchanged.
///
/// The host denies every required capability, so the release never becomes a Driver.
fn denied_release() -> BoxResult<(String, bool)> {
    let mut signed = SignedWorld::new()?;
    let shape = Shape {
        required_capability: true,
        ..ALPHA.shape()
    };
    let entry = publish_shape(&mut signed, ALPHA, shape, 1)?;
    let mut pass = PassWorld::new(WORKER);
    register_twin(&mut pass.registry, TWIN_TYPE, entity_of(ENTITY)?)?;
    let before = snapshot(&pass.registry);
    let swap = Swap::of(trust_material(&signed, &signed.material()?));
    let built = pass.add_gated(GatedSpec {
        name: entry.spec.plugin_id,
        event_type: entry.spec.event_type,
        gated: gated_release(&signed, &entry, &swap)?,
        profile: profile(Mode::Local),
        watchdog: WATCHDOG,
        source: Box::new(Source::numbered(1)),
        register: true,
    });
    let refusal = built.err().map(HostError::name).unwrap_or("accepted");
    Ok((refusal.to_owned(), snapshot(&pass.registry) == before))
}

/// Record a refusal and whether it left the registry unchanged under `path`.
fn record_refusal(capture: &mut Capture, path: &str, refusal: &str, unchanged: bool) {
    capture.record(STORE, &format!("{path}.refusal"), refusal);
    capture.record(STORE, &format!("{path}.registry-unchanged"), unchanged);
}

/// PCF-CPH-009: an invalid implementation fails closed.
///
/// Exact resolution of a composition whose pin of the first-party Plugin, or of the community
/// Plugin, names the other isolation class is refused with the same
/// `IncompatibleImplementation(Isolation)`. A community Driver under an operator-trusted pin is
/// refused at registration with that refusal, and a release whose required capability the host
/// denies never becomes a Driver; neither changes the registry or launches a worker.
#[must_use]
pub fn invalid_implementation() -> Capture {
    invalid().test_ok()
}

fn invalid() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let mixed = Mixed::new(&signed, entries, SIBLING, Order::TwinFirst)?;
    let registry = &mixed.lane.pass.registry;
    let first_party = resolve(registry, registered(registry, Some(NAME))?)?;
    let community = resolve(registry, registered(registry, Some(ALPHA.plugin_id))?)?;
    let (pinned, pinned_unchanged) = native_pinned(&signed, &alpha)?;
    let (denied, denied_unchanged) = denied_release()?;
    let mut capture = Capture::default();
    capture.record(STORE, "first-party-pin.resolve", &first_party);
    capture.record(STORE, "community-pin.resolve", &community);
    record_refusal(&mut capture, "native-pin", &pinned, pinned_unchanged);
    record_refusal(&mut capture, "denied-release", &denied, denied_unchanged);
    let same = first_party == community;
    capture.record(STORE, "parity.same-refusal-either-class", same);
    Ok(capture)
}
