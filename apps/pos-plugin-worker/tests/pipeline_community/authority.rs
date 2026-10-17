//! PCF-CPH-003, PCF-CPH-004 and PCF-CPH-013: proposal rejection and single-lineage owner parity
//! (#632, #654).
//!
//! A Driver that proposes an Event type its own Plugin does not own is refused with the same
//! typed authority error whether it is an operator-trusted native Driver or a community Driver on
//! the real worker; the pass commits nothing and quarantines no Plugin. An Event type has one
//! owning Plugin whichever isolation class claims it first, and a later claim of either class is
//! refused before the registry changes (ADR-021 decision 7).
//!
//! The Rust guest emits only `prototype.driven`, so the community Driver of PCF-CPH-003 proposes
//! a foreign type by owning another type than the one its guest emits. The community Driver of
//! PCF-CPH-013 runs the probe guest, which the lane steers with the `reserved` selector to
//! propose the host's reserved release-activation type itself.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use pos_core::{PluginId, EVENT_TYPE_CONSENT_REVOKED_V1};
use pos_plugin_publisher::test_support::{world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::{initial, Source, StoreKind, World as PassWorld};
use pos_plugin_supervisor::test_support::{community_pin, DriverPlugin};
use pos_plugin_supervisor::{
    register_community_driver, CommunityDriverConfigV1, CommunityDriverSettingsV1,
    CommunityDriverV1, CommunityPluginSupervisorV1, WorkerProgramV1,
};
use pos_runtime::community_plugin_host::{
    classify_pass_failure, CommunityPassOutcomeV1, CommunityPluginHostAbiV1,
    CommunityPluginHostErrorV1, CommunityPluginModeV1 as Mode, PassResultV1,
    PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1,
};
use pos_runtime::{PluginCompositionErrorV1, PluginRegistry, RuntimeError};

use crate::failure::{describe, record_pass, Mixed, Pass, SIBLING};
use crate::first_party::{entity_of, register_native, register_twin, Native};
use crate::harness::Capture;
use crate::parity::{
    observe, on_every_store, record, same_authority, Observed, Order, StoreCapture, ENTITY,
    TWIN_TYPE,
};
use crate::support::lane::{
    gated_release, profile, publish, trust_material, Lane, Published, Spec, Swap, ALPHA,
    EVENT_TYPE, PROBE_GUEST, WATCHDOG,
};
use crate::support::subcase::WORKER;

/// The first-party Plugin that owns the fixture's Event type in the proposal cases.
const OWNER: Native = Native {
    name: "first-party-owner",
    owned: EVENT_TYPE,
    emitted: EVENT_TYPE,
    role: "first-party-owner",
};
/// A first-party Plugin that owns a type of its own and proposes the owner's.
pub const PROPOSER: Native = Native {
    name: "first-party-proposer",
    owned: TWIN_TYPE,
    emitted: EVENT_TYPE,
    role: "first-party-proposer",
};
/// A first-party Plugin that proposes the host's reserved release-activation type.
const RESERVED: Native = native_of(PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1);

/// A first-party Plugin that owns a type of its own and proposes `emitted`.
const fn native_of(emitted: &'static str) -> Native {
    Native {
        emitted,
        ..PROPOSER
    }
}
/// The community member that owns a type of its own while its guest proposes the owner's.
const COMMUNITY_PROPOSER: Spec = Spec {
    event_type: "parity.community",
    ..ALPHA
};
/// The consent Event type reserved to the Gateway consent host, which no Plugin may claim.
const RESERVED_CLAIM: &str = EVENT_TYPE_CONSENT_REVOKED_V1;
/// The community member on the probe guest, which owns the fixture's Event type.
pub const PROBE: Spec = Spec {
    guest: PROBE_GUEST,
    ..ALPHA
};
/// The selector on which the probe guest drafts the host's reserved release-activation type.
const RESERVED_SELECTOR: &[u8] = b"reserved";

/// The typed refusal `error` names, without the ID of the refused Plugin.
#[must_use]
pub fn refusal_of(error: &RuntimeError) -> String {
    match error {
        RuntimeError::Authority(authority) => format!("Authority({authority:?})"),
        RuntimeError::CommunityPlugin(host) => format!("CommunityPlugin({})", host.name()),
        RuntimeError::DriverPanicked { name } => format!("DriverPanicked({name})"),
        RuntimeError::ResourceExhausted {
            driver,
            requested,
            limit,
        } => format!("ResourceExhausted({driver},{requested}>{limit})"),
        RuntimeError::ReservedHostDraft { event_type } => {
            format!("ReservedHostDraft({event_type})")
        }
        RuntimeError::ReservedConsentEventType { event_type, .. } => {
            format!("ReservedConsentEventType({event_type})")
        }
        RuntimeError::ReservedHostEventType { event_type, .. } => {
            format!("ReservedHostEventType({event_type})")
        }
        RuntimeError::Composition(composition) => composition_refusal(composition),
        other => format!("Unexpected({other})"),
    }
}

/// The typed refusal a composition `error` names, without the ID of the refused Plugin.
#[must_use]
pub fn composition_refusal(error: &PluginCompositionErrorV1) -> String {
    match error {
        PluginCompositionErrorV1::DuplicateEventTypeOwner { event_type } => {
            format!("DuplicateEventTypeOwner({event_type})")
        }
        PluginCompositionErrorV1::MissingImplementation { .. } => {
            "MissingImplementation".to_owned()
        }
        PluginCompositionErrorV1::IncompatibleImplementation { field, .. } => {
            format!("IncompatibleImplementation({field:?})")
        }
        PluginCompositionErrorV1::ImplementationUnavailable { availability, .. } => {
            format!("ImplementationUnavailable({availability:?})")
        }
        other => format!("Composition({other:?})"),
    }
}

/// How `classify_pass_failure` classifies the error that failed the pass `result`, or `none`.
fn failure_class(result: &PassResultV1) -> String {
    let PassResultV1::Failed { error, .. } = result else {
        return "none".to_owned();
    };
    format!("{:?}", classify_pass_failure(error))
}

/// The refusal that failed the pass `result`, or `none`.
///
/// A failure the community Plugin host classifies as its own appends that host error, so a pinned
/// refusal also pins whether the host classified the failure as its own.
#[must_use]
pub fn pass_refusal(result: &PassResultV1) -> String {
    let PassResultV1::Failed { host, error } = result else {
        return "none".to_owned();
    };
    let refusal = refusal_of(error);
    let Some(host) = host else {
        return refusal;
    };
    format!("{refusal} host={host:?}")
}

/// The typed refusal of a registration `claim`, or `accepted`.
fn claim_refusal<T>(claim: BoxResult<T>) -> String {
    let Err(error) = claim else {
        return "accepted".to_owned();
    };
    let typed = error.downcast_ref::<RuntimeError>();
    typed.map_or_else(|| format!("Unexpected({error})"), refusal_of)
}

/// Everything a refused registration must leave unchanged.
#[must_use]
pub fn snapshot(registry: &PluginRegistry) -> String {
    let composition = registry.composition();
    let ownership = registry.plugin_ownership_rows();
    let (plugins, drivers) = (registry.len(), registry.driver_count());
    format!("{composition:?} {ownership:?} {plugins} {drivers}")
}

/// One refused proposal pass.
pub struct Proposal {
    /// The authority outcome of the pass.
    pub observed: Observed,
    /// The typed refusal that failed the pass.
    pub refusal: String,
    /// How the host classifies the error that failed the pass.
    pub class: String,
}

/// The Local pass of a registry on a `kind` store holding [`OWNER`] and then the first-party
/// `native` proposer.
///
/// # Errors
/// Returns the error of registering either Plugin, of building the lane or of its pass.
pub fn first_party_proposal(
    signed: &SignedWorld,
    native: Native,
    kind: StoreKind,
) -> BoxResult<Proposal> {
    let entity = entity_of(ENTITY)?;
    let mut pass = PassWorld::on(kind, WORKER);
    let owner = register_native(&mut pass.registry, OWNER, entity)?;
    let proposed = register_native(&mut pass.registry, native, entity)?;
    let mut lane = Lane::over(signed, &[], Mode::Local, pass)?;
    let outcome = lane.run(signed)?;
    let owner = owner.load(Ordering::SeqCst);
    let proposed = proposed.load(Ordering::SeqCst);
    Ok(Proposal {
        observed: observe(&lane, &outcome, format!("{owner},{proposed}")),
        refusal: pass_refusal(&outcome.result),
        class: failure_class(&outcome.result),
    })
}

/// The Local pass of a registry on a `kind` store holding [`OWNER`] and then the community
/// member of `entries`.
fn community_proposal(
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<Proposal> {
    let mut pass = PassWorld::on(kind, WORKER);
    let owner = register_native(&mut pass.registry, OWNER, entity_of(ENTITY)?)?;
    let mut lane = Lane::over(signed, entries, Mode::Local, pass)?;
    let outcome = lane.run(signed)?;
    let owner = owner.load(Ordering::SeqCst);
    let community = lane.handle().receipts().len();
    Ok(Proposal {
        observed: observe(&lane, &outcome, format!("{owner},{community}")),
        refusal: pass_refusal(&outcome.result),
        class: failure_class(&outcome.result),
    })
}

/// Record what the refused proposal shows under `path`.
fn record_proposal(capture: &mut StoreCapture<'_>, path: &str, proposal: &Proposal) {
    record(capture, path, &proposal.observed);
    capture.record(&format!("{path}.refusal"), &proposal.refusal);
}

/// PCF-CPH-003: a proposal of another Plugin's Event type is refused identically.
///
/// A first-party Driver and a community Driver on the real worker each propose the Event type a
/// first-party owner holds. Either pass fails with the same typed authority refusal, commits
/// nothing and leaves every Plugin available. A first-party proposal of the host's reserved
/// release-activation type is refused with the reserved-draft refusal.
#[must_use]
pub fn foreign_proposal_parity() -> Capture {
    on_every_store(foreign_proposal)
}

fn foreign_proposal(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let member = publish(&mut signed, COMMUNITY_PROPOSER, 1)?;
    let first_party = first_party_proposal(&signed, PROPOSER, kind)?;
    let community = community_proposal(&signed, std::slice::from_ref(&member), kind)?;
    let reserved = first_party_proposal(&signed, RESERVED, kind)?;
    record_proposal(capture, "first-party", &first_party);
    record_proposal(capture, "community", &community);
    record_proposal(capture, "first-party-reserved", &reserved);
    let parity = same_authority(&first_party.observed, &community.observed)
        && first_party.refusal == community.refusal;
    capture.record("parity.first-party-equals-community", parity);
    Ok(())
}

/// A community Driver built from the gated release of `entry` for `plugin_id`.
///
/// Its registration is refused, so it never launches the worker.
///
/// # Errors
/// Returns the error of gating the release or of building the Driver's configuration.
pub fn community_driver(
    signed: &SignedWorld,
    entry: &Published,
    plugin_id: PluginId,
) -> BoxResult<CommunityDriverV1> {
    let abi = CommunityPluginHostAbiV1::new(0, 1, vec!["clock".to_owned()]);
    let abi = abi.map_err(|error| format!("{error:?}"))?;
    let config = driver_config(signed, entry, plugin_id, &abi)?;
    let config = config.map_err(|error| format!("{error:?}"))?;
    Ok(CommunityDriverV1::new(config).0)
}

/// The configuration of a community Driver from the gated release of `entry`, or its refusal.
///
/// The Driver is for `plugin_id` and negotiates the release against the host ABI `abi`.
///
/// # Errors
/// Returns the error of gating the release or of building the Driver's supervisor.
pub fn driver_config(
    signed: &SignedWorld,
    entry: &Published,
    plugin_id: PluginId,
    abi: &CommunityPluginHostAbiV1,
) -> BoxResult<Result<CommunityDriverConfigV1, CommunityPluginHostErrorV1>> {
    let swap = Swap::of(trust_material(signed, &signed.material()?));
    let gated = gated_release(signed, entry, &swap)?;
    let program = WorkerProgramV1::new(PathBuf::from(WORKER)).ok_or("an invalid worker path")?;
    let supervisor = CommunityPluginSupervisorV1::new(program, WATCHDOG);
    let settings = CommunityDriverSettingsV1 {
        plugin_id,
        name: entry.spec.plugin_id,
        tick_interval: Duration::from_millis(100),
        subscriptions: Vec::new(),
        supervisor: supervisor.ok_or("an invalid supervisor")?,
        source: Box::new(Source::numbered(1)),
        initial_state: initial(),
    };
    let hosted = profile(Mode::Local);
    let id = entry.spec.plugin_id;
    let config = CommunityDriverConfigV1::from_gated(gated, abi, &hosted, id, settings);
    Ok(config)
}

/// Claim `event_type` for a community Plugin built from `entry`, on the community path.
///
/// # Errors
/// Returns the error of building the Driver, then `register_community_driver`'s refusal.
fn community_claim(
    signed: &SignedWorld,
    entry: &Published,
    registry: &mut PluginRegistry,
    event_type: &'static str,
) -> BoxResult<()> {
    let plugin = DriverPlugin {
        id: PluginId::new(),
        name: entry.spec.plugin_id,
        event_type,
        has_driver: true,
    };
    let driver = community_driver(signed, entry, plugin.id)?;
    let pin = community_pin(0x43, "community-claim");
    Ok(register_community_driver(registry, &plugin, pin, driver)?)
}

/// One refused claim and the pass that follows it.
struct Claim {
    refusal: String,
    unchanged: bool,
    observed: Observed,
}

/// A community claim on the fixture's type, which the first-party twin owns, then a pass on a
/// `kind` store.
fn community_claims_native_type(
    signed: &SignedWorld,
    entry: &Published,
    kind: StoreKind,
) -> BoxResult<Claim> {
    let mut pass = PassWorld::on(kind, WORKER);
    let steps = register_twin(&mut pass.registry, EVENT_TYPE, entity_of(ENTITY)?)?;
    let before = snapshot(&pass.registry);
    let claim = community_claim(signed, entry, &mut pass.registry, EVENT_TYPE);
    let refusal = claim_refusal(claim);
    let unchanged = snapshot(&pass.registry) == before;
    let mut lane = Lane::over(signed, &[], Mode::Local, pass)?;
    let outcome = lane.run(signed)?;
    let steps = steps.load(Ordering::SeqCst).to_string();
    Ok(Claim {
        refusal,
        unchanged,
        observed: observe(&lane, &outcome, steps),
    })
}

/// A first-party claim on the fixture's type, which the community member of `entries` owns,
/// then a pass on a `kind` store.
fn native_claims_community_type(
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<Claim> {
    let mut lane = Lane::on(kind, signed, entries, Mode::Local)?;
    let before = snapshot(&lane.pass.registry);
    let claim = register_twin(&mut lane.pass.registry, EVENT_TYPE, entity_of(ENTITY)?);
    let refusal = claim_refusal(claim);
    let unchanged = snapshot(&lane.pass.registry) == before;
    let outcome = lane.run(signed)?;
    let steps = lane.handle().receipts().len().to_string();
    Ok(Claim {
        refusal,
        unchanged,
        observed: observe(&lane, &outcome, steps),
    })
}

/// Record what the refused claim and the following pass show under `path`.
fn record_claim(capture: &mut StoreCapture<'_>, path: &str, claim: &Claim) {
    capture.record(&format!("{path}.refusal"), &claim.refusal);
    capture.record(&format!("{path}.registry-unchanged"), claim.unchanged);
    record(capture, path, &claim.observed);
}

/// The refusals of a first-party and a community claim on the reserved consent type, in one
/// empty registry, and whether that registry is unchanged.
///
/// No pass runs, so the store of kind `kind` holds no Event and does not affect the refusals.
fn reserved_claims(
    signed: &SignedWorld,
    entry: &Published,
    kind: StoreKind,
) -> BoxResult<(String, String, bool)> {
    reserved_claims_of(signed, entry, kind, RESERVED_CLAIM)
}

/// The refusals of a first-party and a community claim on the reserved `event_type`, in one
/// empty registry, and whether that registry is unchanged.
///
/// No pass runs, so the store of kind `kind` holds no Event and does not affect the refusals.
///
/// # Errors
/// Returns the error of building the first-party entity or the community Driver.
pub fn reserved_claims_of(
    signed: &SignedWorld,
    entry: &Published,
    kind: StoreKind,
    event_type: &'static str,
) -> BoxResult<(String, String, bool)> {
    let mut pass = PassWorld::on(kind, WORKER);
    let before = snapshot(&pass.registry);
    let native = register_twin(&mut pass.registry, event_type, entity_of(ENTITY)?);
    let native = claim_refusal(native);
    let community = community_claim(signed, entry, &mut pass.registry, event_type);
    let community = claim_refusal(community);
    Ok((native, community, snapshot(&pass.registry) == before))
}

/// PCF-CPH-004: single-lineage action-owner resolution across isolation classes.
///
/// A community claim on the type a first-party twin owns, and a first-party claim on the type a
/// community member owns, are refused with the same typed ownership refusal and leave the
/// registry unchanged; the next pass commits the type under its one first owner. A claim of the
/// Gateway's reserved consent type is refused the same way for either class.
#[must_use]
pub fn single_lineage_owner() -> Capture {
    on_every_store(single_lineage)
}

fn single_lineage(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let by_community = community_claims_native_type(&signed, &alpha, kind)?;
    let entries = std::slice::from_ref(&alpha);
    let by_first_party = native_claims_community_type(&signed, entries, kind)?;
    let (native, community, unchanged) = reserved_claims(&signed, &alpha, kind)?;
    record_claim(capture, "community-claim", &by_community);
    record_claim(capture, "first-party-claim", &by_first_party);
    capture.record("reserved-claim.first-party.refusal", &native);
    capture.record("reserved-claim.community.refusal", &community);
    capture.record("reserved-claim.registry-unchanged", unchanged);
    let same = by_community.refusal == by_first_party.refusal && native == community;
    capture.record("parity.same-refusal-either-class", same);
    Ok(())
}

/// The name of a community host error, or `none`.
fn error_name(error: Option<CommunityPluginHostErrorV1>) -> &'static str {
    error.map_or("none", CommunityPluginHostErrorV1::name)
}

/// What the host made of the first member of `lane` in the pass `outcome`, as
/// `launch-failure/availability/last-failure`.
///
/// The launch failure is the host's entry for the member; the availability and the last failure
/// are its handle's, which the host mirrors into the registry.
fn member_state(lane: &Lane, outcome: &CommunityPassOutcomeV1) -> String {
    let entry = outcome.gates.first();
    let launch = entry.and_then(|gate| gate.launch_failure);
    let handle = lane.handle();
    let availability = handle.availability();
    let last = error_name(handle.last_failure());
    format!("{}/{availability:?}/{last}", error_name(launch))
}

/// One pass of a mixed lane and how the host classified it.
struct Classified {
    pass: Pass,
    class: String,
    member: String,
}

/// Run one pass of `mixed` and classify it.
fn classified(mixed: &mut Mixed, signed: &SignedWorld) -> BoxResult<Classified> {
    let outcome = mixed.lane.run(signed)?;
    let steps = mixed.steps_since();
    let class = failure_class(&outcome.result);
    let member = member_state(&mixed.lane, &outcome);
    let pass = describe(&mixed.lane, &outcome, steps);
    Ok(Classified {
        pass,
        class,
        member,
    })
}

/// PCF-CPH-013: a community proposal of a reserved host type is refused as a first-party one.
///
/// A community Driver on the real worker whose probe guest drafts the host's reserved
/// release-activation type, after the first-party sibling staged, fails the pass with the same
/// reserved-draft refusal, of the same failure class, as the first-party proposal of that type:
/// the registry refuses the draft before ownership, the community host does not classify the
/// refusal as its own, the whole pass commits nothing, and no Plugin is quarantined. The next
/// pass, with the guest unsteered, commits both Events without clearing anything.
#[must_use]
pub fn reserved_proposal_parity() -> Capture {
    on_every_store(reserved_proposal)
}

fn reserved_proposal(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let reserved = ReservedProposal {
        prefix: "",
        emitted: RESERVED.emitted,
        selector: RESERVED_SELECTOR,
    };
    reserved_proposal_of(kind, capture, &reserved)
}

/// One reserved host Event type a Driver of either class proposes.
pub struct ReservedProposal {
    /// The prefix of every capture key; empty for PCF-CPH-013.
    pub prefix: &'static str,
    /// The reserved host Event type the first-party Driver drafts.
    pub emitted: &'static str,
    /// The probe guest selector under which the community Driver drafts it.
    pub selector: &'static [u8],
}

/// Record the PCF-CPH-013 proposal pair of `reserved` on a `kind` store: a first-party and a
/// community proposal of the type are refused alike, and the next unsteered pass commits.
///
/// # Errors
/// Returns the error of publishing the probe guest, of building either lane or of a pass.
pub fn reserved_proposal_of(
    kind: StoreKind,
    capture: &mut StoreCapture<'_>,
    reserved: &ReservedProposal,
) -> BoxResult<()> {
    let key = |name: &str| format!("{}{name}", reserved.prefix);
    let mut signed = SignedWorld::new()?;
    let probe = publish(&mut signed, PROBE, 1)?;
    let first_party = first_party_proposal(&signed, native_of(reserved.emitted), kind)?;
    let entries = std::slice::from_ref(&probe);
    let mut mixed = Mixed::new(kind, &signed, entries, SIBLING, Order::TwinFirst)?;
    mixed.lane.selector.set(Some(reserved.selector.to_vec()));
    let community = classified(&mut mixed, &signed)?;
    mixed.lane.selector.set(None);
    let next = mixed.pass(&signed)?;
    record_proposal(capture, &key("first-party-reserved"), &first_party);
    let class = &first_party.class;
    capture.record(&key("first-party-reserved.pass-failure"), class);
    record_pass(capture, &key("community-reserved"), &community.pass);
    capture.record(&key("community-reserved.pass-failure"), &community.class);
    capture.record(&key("community-reserved.gate"), &community.pass.gate);
    capture.record(&key("community-reserved.member"), &community.member);
    record(capture, &key("community-next"), &next.observed);
    capture.record(&key("community.community-receipts"), mixed.receipts());
    let parity = same_authority(&first_party.observed, &community.pass.observed)
        && first_party.refusal == community.pass.refusal
        && first_party.class == community.class;
    capture.record(&key("parity.first-party-equals-community"), parity);
    Ok(())
}
