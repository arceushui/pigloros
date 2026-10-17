//! PCF-CPH-007 to PCF-CPH-009 and PCF-CPH-014: missing, unavailable and invalid Plugins fail
//! closed (#633, #655).
//!
//! A missing, unavailable or invalid required Plugin fails closed with a typed outcome, and the
//! host has no runtime default (ADR-021 decision 7). Exact composition resolution gives the same
//! typed refusal for a first-party and a community requirement. A pass refuses an unavailable
//! Plugin of either class with the same typed refusal before any Driver runs, and resumes once
//! the host makes the Plugin available again.
//!
//! Only the community path has a release: a release that is not the active one is refused at
//! the trust gate, and a release whose capability the host denies, whose ABI the real worker
//! does not support or whose manifest is not PMF1 never becomes a Driver. A community guest
//! output that fails validation discards the whole pass and quarantines nothing; its
//! first-party counterpart is the invalid-draft authority refusal of PCF-CPH-003. The probe
//! guest returns that invalid output on the real worker when its observation selects it.

use pos_core::PluginId;
use pos_plugin_publisher::test_support::{release::Shape, world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::{GatedSpec, Source, StoreKind, World as PassWorld};
use pos_plugin_supervisor::test_support::{community_pin, DriverPlugin};
use pos_plugin_supervisor::{register_community_driver, CommunityDriverV1};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostAbiV1 as HostAbi, CommunityPluginHostErrorV1 as HostError,
    CommunityPluginModeV1 as Mode, RevocationBasisV1 as Revoke,
};
use pos_runtime::{
    PluginAvailabilityV1, PluginExecutionModeV1, PluginIsolationV1, PluginPinV1, PluginRegistry,
    RequiredPluginCompositionV1, RequiredPluginV1,
};

use crate::authority::{
    community_driver, composition_refusal, driver_config, first_party_proposal, refusal_of,
    snapshot, PROBE, PROPOSER,
};
use crate::failure::{record_pass, Mixed, Pass, SIBLING};
use crate::first_party::{entity_of, native_pin, register_twin, NAME};
use crate::harness::Capture;
use crate::parity::{on_every_store, record, Observed, Order, StoreCapture, ENTITY, TWIN_TYPE};
use crate::support::lane::{
    gated_release, profile, publish, publish_shape, trust_material, Published, Swap, ALPHA,
    ALPHA_C, WATCHDOG,
};
use crate::support::subcase::WORKER;

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
    on_every_store(missing)
}

/// The resolutions read the registry alone and the refused pass commits nothing, so the store
/// of kind `kind` holds no Event and the values are the same on every store.
fn missing(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let first = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&first);
    let mut mixed = Mixed::new(kind, &signed, entries, SIBLING, Order::TwinFirst)?;
    let registry = &mixed.lane.pass.registry;
    let present = resolve(registry, registered(registry, None)?)?;
    let first_party = resolve_with_missing(registry, native_pin("missing-first-party")?)?;
    let community = resolve_with_missing(registry, community_pin(0x4d, "missing-community"))?;
    let pass = not_active(&mut signed, &first, &mut mixed)?;
    capture.record("registered.resolve", &present);
    capture.record("first-party-missing.resolve", &first_party);
    capture.record("community-missing.resolve", &community);
    record(capture, "community-not-active", &pass.observed);
    capture.record("community-not-active.gate", &pass.gate);
    let same = first_party == community;
    capture.record("parity.same-missing-either-class", same);
    Ok(())
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
    mixed
        .lane
        .pass
        .registry
        .set_availability(id, availability)?;
    mixed.pass(signed)
}

/// The first-party sibling, registered after the community release, made unavailable by the
/// host, then available again, on a `kind` store.
fn first_party_unavailable(
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<Refused> {
    let mut mixed = Mixed::new(kind, signed, entries, SIBLING, Order::CommunityFirst)?;
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
/// then cleared, on a `kind` store.
///
/// The revocation is injected through the handle's refusal record, the path the host itself uses
/// to quarantine; that a real revoked artifact yields that refusal is proven at the trust gate.
fn community_unavailable(
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<Refused> {
    let mut mixed = Mixed::new(kind, signed, entries, SIBLING, Order::TwinFirst)?;
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
fn record_refused(capture: &mut StoreCapture<'_>, path: &str, refused: &Refused) {
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
    on_every_store(unavailable)
}

fn unavailable(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let first_party = first_party_unavailable(&signed, entries, kind)?;
    let community = community_unavailable(&signed, entries, kind)?;
    record_refused(capture, "first-party", &first_party);
    record_refused(capture, "community", &community);
    let same = first_party.revoked.refusal == community.revoked.refusal
        && first_party.unavailable.refusal == community.unavailable.refusal;
    capture.record("parity.same-refusal-either-class", same);
    Ok(())
}

/// A community Driver of `entry` registered under an operator-trusted native pin in a pass world
/// on a `kind` store: the refusal, and whether the registry is unchanged.
fn native_pinned(
    signed: &SignedWorld,
    entry: &Published,
    kind: StoreKind,
) -> BoxResult<(String, bool)> {
    let mut pass = PassWorld::on(kind, WORKER);
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

/// A pass world on a `kind` store that holds the first-party twin alone.
fn twin_world(kind: StoreKind) -> BoxResult<PassWorld> {
    let mut pass = PassWorld::on(kind, WORKER);
    register_twin(&mut pass.registry, TWIN_TYPE, entity_of(ENTITY)?)?;
    Ok(pass)
}

/// The refusal of gating `entry`, or of building and registering a Driver from it in `pass`.
///
/// This is the one gated-and-register path of the fail-closed releases. A release it refuses
/// never reaches the registry, so a caller's registry-unchanged check fails only if the refusal
/// regresses to `accepted`.
fn gated_refusal(
    signed: &SignedWorld,
    entry: &Published,
    pass: &mut PassWorld,
) -> BoxResult<String> {
    let swap = Swap::of(trust_material(signed, &signed.material()?));
    let gated = match gated_release(signed, entry, &swap) {
        Ok(gated) => gated,
        Err(error) => {
            let host = error.downcast_ref::<HostError>().copied();
            let name = host.map(HostError::name);
            let refusal = name.map_or_else(|| format!("Unexpected({error})"), str::to_owned);
            return Ok(refusal);
        }
    };
    let built = pass.add_gated(GatedSpec {
        name: entry.spec.plugin_id,
        event_type: entry.spec.event_type,
        gated,
        profile: profile(Mode::Local),
        watchdog: WATCHDOG,
        source: Box::new(Source::numbered(1)),
        register: true,
    });
    Ok(built.err().map_or("accepted", HostError::name).to_owned())
}

/// The refusal of `entry` through [`gated_refusal`] beside the first-party twin, in a pass world
/// on a `kind` store, and whether the registry is unchanged.
fn twin_refusal(
    signed: &SignedWorld,
    entry: &Published,
    kind: StoreKind,
) -> BoxResult<(String, bool)> {
    let mut pass = twin_world(kind)?;
    let before = snapshot(&pass.registry);
    let refusal = gated_refusal(signed, entry, &mut pass)?;
    Ok((refusal, snapshot(&pass.registry) == before))
}

/// A release of `plugin-a` that requires a capability, in its own signed world, built into a
/// Driver beside the first-party twin in a pass world on a `kind` store: the refusal, and
/// whether the registry is unchanged.
///
/// The host denies every required capability, so the release never becomes a Driver.
fn denied_release(kind: StoreKind) -> BoxResult<(String, bool)> {
    let mut signed = SignedWorld::new()?;
    let shape = Shape {
        required_capability: true,
        ..ALPHA.shape()
    };
    let entry = publish_shape(&mut signed, ALPHA, shape, 1)?;
    twin_refusal(&signed, &entry, kind)
}

/// Record a refusal and whether it left the registry unchanged under `path`.
fn record_refusal(capture: &mut StoreCapture<'_>, path: &str, refusal: &str, unchanged: bool) {
    capture.record(&format!("{path}.refusal"), refusal);
    capture.record(&format!("{path}.registry-unchanged"), unchanged);
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
    on_every_store(invalid)
}

/// No pass runs: the resolutions and refusals read the registry alone, so the store of kind
/// `kind` holds no Event and the values are the same on every store.
fn invalid(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let mixed = Mixed::new(kind, &signed, entries, SIBLING, Order::TwinFirst)?;
    let registry = &mixed.lane.pass.registry;
    let first_party = resolve(registry, registered(registry, Some(NAME))?)?;
    let community = resolve(registry, registered(registry, Some(ALPHA.plugin_id))?)?;
    let (pinned, pinned_unchanged) = native_pinned(&signed, &alpha, kind)?;
    let (denied, denied_unchanged) = denied_release(kind)?;
    capture.record("first-party-pin.resolve", &first_party);
    capture.record("community-pin.resolve", &community);
    record_refusal(capture, "native-pin", &pinned, pinned_unchanged);
    record_refusal(capture, "denied-release", &denied, denied_unchanged);
    let same = first_party == community;
    capture.record("parity.same-refusal-either-class", same);
    Ok(())
}

/// The observation on which the probe guest returns an output whose digest does not match.
const BAD_DIGEST: &[u8] = b"bad-digest";

/// A pass whose community guest output is invalid, the next pass, and the member's receipts.
struct InvalidOutput {
    failed: Pass,
    next: Pass,
    receipts: String,
}

/// A community Driver on the probe guest whose output digest does not match on the real worker,
/// after the first-party sibling staged, then the next pass on the unsteered observation, on a
/// `kind` store.
///
/// Nothing is quarantined, so the host clears nothing before the next pass.
fn community_invalid_output(
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<InvalidOutput> {
    let mut mixed = Mixed::new(kind, signed, entries, SIBLING, Order::TwinFirst)?;
    mixed.lane.selector.set(Some(BAD_DIGEST.to_vec()));
    let failed = mixed.pass(signed)?;
    mixed.lane.selector.set(None);
    let next = mixed.pass(signed)?;
    Ok(InvalidOutput {
        failed,
        next,
        receipts: mixed.receipts(),
    })
}

/// The refusal of a Driver built from `entry` against the real worker's V1 host ABI, ABI 0.0
/// alone, which is registered in `registry` if it is built.
///
/// Negotiation refuses before registration, so the caller's registry-unchanged check fails only
/// if the refusal regresses to `accepted`. This is a registration-time refusal only: the pass
/// harness negotiates under ABI 0.0 to 0.1, which accepts the release, and the real worker then
/// rejects the transported record, which the supervisor reports as `WorkerCrashed`.
fn worker_abi_refusal(
    signed: &SignedWorld,
    entry: &Published,
    registry: &mut PluginRegistry,
) -> BoxResult<String> {
    let plugin = DriverPlugin {
        id: PluginId::new(),
        name: entry.spec.plugin_id,
        event_type: entry.spec.event_type,
        has_driver: true,
    };
    let config = match driver_config(signed, entry, plugin.id, &HostAbi::v1())? {
        Ok(config) => config,
        Err(error) => return Ok(error.name().to_owned()),
    };
    let driver = CommunityDriverV1::new(config).0;
    let pin = community_pin(0x41, "abi-invalid-release");
    let registered = register_community_driver(registry, &plugin, pin, driver);
    let refusal = registered.map_or_else(|error| refusal_of(&error), |()| "accepted".to_owned());
    Ok(refusal)
}

/// A release of `plugin-a` that declares ABI minor 1 alone, in its own signed world, built into
/// a Driver beside the first-party twin in a pass world on a `kind` store: the refusal, and
/// whether the registry is unchanged.
///
/// The real worker supports ABI 0.0 alone, so negotiation finds no common minor.
/// This is a registration-time refusal: the registry-unchanged check guards the accept path.
fn abi_invalid_release(kind: StoreKind) -> BoxResult<(String, bool)> {
    let mut signed = SignedWorld::new()?;
    let shape = ALPHA.shape().with_abi_minors(1, 1);
    let entry = publish_shape(&mut signed, ALPHA, shape, 1)?;
    let mut pass = twin_world(kind)?;
    let before = snapshot(&pass.registry);
    let refusal = worker_abi_refusal(&signed, &entry, &mut pass.registry)?;
    Ok((refusal, snapshot(&pass.registry) == before))
}

/// A closure of `plugin-a` whose manifest bytes are not PMF1, in its own signed world, gated
/// and built into a Driver beside the first-party twin in a pass world on a `kind` store: the
/// refusal, and whether the registry is unchanged.
///
/// The closure is published but never installed, and it has no release digest.
/// The trust gate refuses it before registration, so the registry-unchanged check guards the
/// accept path.
fn manifest_invalid_release(kind: StoreKind) -> BoxResult<(String, bool)> {
    let signed = SignedWorld::new()?;
    let component = Shape::first().component;
    let address = signed.publish_raw(b"not a PMF1", component)?;
    let entry = Published {
        spec: ALPHA,
        address,
        release: [0; 32],
    };
    twin_refusal(&signed, &entry, kind)
}

/// Whether a failed pass discarded the whole pass: it failed with a typed refusal, committed
/// nothing, and quarantined no Plugin.
fn discarded_whole(observed: &Observed, refusal: &str) -> bool {
    observed.result() == "Failed"
        && observed.committed() == 0
        && observed.all_available()
        && refusal != "none"
}

/// PCF-CPH-014: invalid guest output and invalid releases fail closed.
///
/// A community Driver on the probe guest whose output digest does not match on the real worker,
/// after the first-party sibling staged, fails the pass with `InvalidGuestOutput`: nothing is
/// committed, the sibling's staged output is discarded and no Plugin is quarantined, so the next
/// pass commits both Events without the host clearing anything. The first-party counterpart, a
/// Driver's invalid draft of another Plugin's Event type, discards its whole pass the same way
/// under the authority refusal of PCF-CPH-003. A release whose ABI the real worker does not
/// support, and a closure whose manifest is not PMF1, never become a Driver and leave the
/// registry unchanged.
#[must_use]
pub fn invalid_output_and_releases() -> Capture {
    on_every_store(invalid_output)
}

fn invalid_output(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let probe = publish(&mut signed, PROBE, 1)?;
    let entries = std::slice::from_ref(&probe);
    let community = community_invalid_output(&signed, entries, kind)?;
    let first_party = first_party_proposal(&signed, PROPOSER, kind)?;
    let (abi, abi_unchanged) = abi_invalid_release(kind)?;
    let (raw, raw_unchanged) = manifest_invalid_release(kind)?;
    record_pass(capture, "community-invalid-output", &community.failed);
    record(capture, "community-next", &community.next.observed);
    capture.record("community.community-receipts", &community.receipts);
    record(capture, "first-party-invalid-draft", &first_party.observed);
    capture.record("first-party-invalid-draft.refusal", &first_party.refusal);
    record_refusal(capture, "abi-invalid-release", &abi, abi_unchanged);
    record_refusal(capture, "manifest-invalid-release", &raw, raw_unchanged);
    let failed = &community.failed;
    let discarded = discarded_whole(&failed.observed, &failed.refusal)
        && discarded_whole(&first_party.observed, &first_party.refusal);
    capture.record("parity.whole-pass-discarded-either-class", discarded);
    Ok(())
}
