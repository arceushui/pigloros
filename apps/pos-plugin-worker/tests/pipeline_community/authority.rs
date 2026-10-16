//! PCF-CPH-003 and PCF-CPH-004: proposal rejection and single-lineage owner parity (#632).
//!
//! A Driver that proposes an Event type its own Plugin does not own is refused with the same
//! typed authority error whether it is an operator-trusted native Driver or a community Driver on
//! the real worker; the pass commits nothing and quarantines no Plugin. An Event type has one
//! owning Plugin whichever isolation class claims it first, and a later claim of either class is
//! refused before the registry changes (ADR-021 decision 7).
//!
//! The real community guests emit only `prototype.driven`, so the community Driver proposes a
//! foreign type by owning another type than the one its guest emits. A community proposal of a
//! reserved host type would need a new guest Component: the profile records it as an exclusion,
//! and only the first-party refusal of that proposal is pinned here.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use pos_core::{PluginId, EVENT_TYPE_CONSENT_REVOKED_V1};
use pos_plugin_publisher::test_support::{world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::{initial, Source, World as PassWorld};
use pos_plugin_supervisor::test_support::{community_pin, DriverPlugin};
use pos_plugin_supervisor::{
    register_community_driver, CommunityDriverConfigV1, CommunityDriverSettingsV1,
    CommunityDriverV1, CommunityPluginSupervisorV1, WorkerProgramV1,
};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostAbiV1, CommunityPluginModeV1 as Mode, PassResultV1,
    PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1,
};
use pos_runtime::{PluginCompositionErrorV1, PluginRegistry, RuntimeError};

use crate::first_party::{entity_of, register_native, register_twin, Native};
use crate::harness::Capture;
use crate::parity::{observe, record, same_authority, Observed, ENTITY, STORE};
use crate::support::lane::{
    gated_release, profile, publish, trust_material, Lane, Published, Spec, Swap, ALPHA, EVENT_TYPE,
    WATCHDOG,
};
use crate::support::subcase::WORKER;
use crate::support::test_ok::TestOk;

/// The first-party Plugin that owns the fixture's Event type in the proposal cases.
const OWNER: Native = Native {
    name: "first-party-owner",
    owned: EVENT_TYPE,
    emitted: EVENT_TYPE,
    role: "first-party-owner",
};
/// A first-party Plugin that owns a type of its own and proposes the owner's.
const PROPOSER: Native = Native {
    name: "first-party-proposer",
    owned: "parity.first-party",
    emitted: EVENT_TYPE,
    role: "first-party-proposer",
};
/// A first-party Plugin that proposes the host's reserved release-activation type.
const RESERVED: Native = Native {
    emitted: PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1,
    ..PROPOSER
};
/// The community member that owns a type of its own while its guest proposes the owner's.
const COMMUNITY_PROPOSER: Spec = Spec {
    event_type: "parity.community",
    ..ALPHA
};
/// The consent Event type reserved to the Gateway consent host, which no Plugin may claim.
const RESERVED_CLAIM: &str = EVENT_TYPE_CONSENT_REVOKED_V1;

/// The typed refusal `error` names, without the name of the refused Plugin.
fn refusal_of(error: &RuntimeError) -> String {
    match error {
        RuntimeError::Authority(authority) => format!("Authority({authority:?})"),
        RuntimeError::ReservedHostDraft { event_type } => {
            format!("ReservedHostDraft({event_type})")
        }
        RuntimeError::ReservedConsentEventType { event_type, .. } => {
            format!("ReservedConsentEventType({event_type})")
        }
        RuntimeError::Composition(composition) => composition_refusal(composition),
        other => format!("Unexpected({other})"),
    }
}

/// The typed refusal a composition `error` names.
fn composition_refusal(error: &PluginCompositionErrorV1) -> String {
    match error {
        PluginCompositionErrorV1::DuplicateEventTypeOwner { event_type } => {
            format!("DuplicateEventTypeOwner({event_type})")
        }
        other => format!("Composition({other:?})"),
    }
}

/// The refusal that failed the pass `result`, or `none`.
fn pass_refusal(result: &PassResultV1) -> String {
    let PassResultV1::Failed { error, .. } = result else {
        return "none".to_owned();
    };
    refusal_of(error)
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
fn snapshot(registry: &PluginRegistry) -> String {
    let composition = registry.composition();
    let ownership = registry.plugin_ownership_rows();
    let (plugins, drivers) = (registry.len(), registry.driver_count());
    format!("{composition:?} {ownership:?} {plugins} {drivers}")
}

/// One refused proposal pass.
struct Proposal {
    observed: Observed,
    refusal: String,
}

/// The Local pass of a registry holding [`OWNER`] and then the first-party `proposer`.
fn first_party_proposal(signed: &SignedWorld, proposer: Native) -> BoxResult<Proposal> {
    let entity = entity_of(ENTITY)?;
    let mut pass = PassWorld::new(WORKER);
    let owner = register_native(&mut pass.registry, OWNER, entity)?;
    let proposed = register_native(&mut pass.registry, proposer, entity)?;
    let mut lane = Lane::over(signed, &[], Mode::Local, pass)?;
    let outcome = lane.run(signed)?;
    let owner = owner.load(Ordering::SeqCst);
    let proposed = proposed.load(Ordering::SeqCst);
    Ok(Proposal {
        observed: observe(&lane, &outcome, format!("{owner},{proposed}")),
        refusal: pass_refusal(&outcome.result),
    })
}

/// The Local pass of a registry holding [`OWNER`] and then the community member of `entries`.
fn community_proposal(signed: &SignedWorld, entries: &[Published]) -> BoxResult<Proposal> {
    let mut pass = PassWorld::new(WORKER);
    let owner = register_native(&mut pass.registry, OWNER, entity_of(ENTITY)?)?;
    let mut lane = Lane::over(signed, entries, Mode::Local, pass)?;
    let outcome = lane.run(signed)?;
    let owner = owner.load(Ordering::SeqCst);
    let community = lane.handle().receipts().len();
    Ok(Proposal {
        observed: observe(&lane, &outcome, format!("{owner},{community}")),
        refusal: pass_refusal(&outcome.result),
    })
}

/// Record what the refused proposal shows under `path`.
fn record_proposal(capture: &mut Capture, path: &str, proposal: &Proposal) {
    record(capture, path, &proposal.observed);
    capture.record(STORE, &format!("{path}.refusal"), &proposal.refusal);
}

/// PCF-CPH-003: a proposal of another Plugin's Event type is refused identically.
///
/// A first-party Driver and a community Driver on the real worker each propose the Event type a
/// first-party owner holds. Either pass fails with the same typed authority refusal, commits
/// nothing and leaves every Plugin available. A first-party proposal of the host's reserved
/// release-activation type is refused with the reserved-draft refusal.
#[must_use]
pub fn foreign_proposal_parity() -> Capture {
    foreign_proposal().test_ok()
}

fn foreign_proposal() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let member = publish(&mut signed, COMMUNITY_PROPOSER, 1)?;
    let first_party = first_party_proposal(&signed, PROPOSER)?;
    let community = community_proposal(&signed, std::slice::from_ref(&member))?;
    let reserved = first_party_proposal(&signed, RESERVED)?;
    let mut capture = Capture::default();
    record_proposal(&mut capture, "first-party", &first_party);
    record_proposal(&mut capture, "community", &community);
    record_proposal(&mut capture, "first-party-reserved", &reserved);
    let parity = same_authority(&first_party.observed, &community.observed)
        && first_party.refusal == community.refusal;
    capture.record(STORE, "parity.first-party-equals-community", parity);
    Ok(capture)
}

/// A community Driver built from the gated release of `entry` for `plugin_id`.
///
/// Its registration is refused, so it never launches the worker.
fn community_driver(
    signed: &SignedWorld,
    entry: &Published,
    plugin_id: PluginId,
) -> BoxResult<CommunityDriverV1> {
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
    let abi = CommunityPluginHostAbiV1::new(0, 1, vec!["clock".to_owned()]);
    let abi = abi.map_err(|error| format!("{error:?}"))?;
    let hosted = profile(Mode::Local);
    let id = entry.spec.plugin_id;
    let config = CommunityDriverConfigV1::from_gated(gated, &abi, &hosted, id, settings);
    let config = config.map_err(|error| format!("{error:?}"))?;
    Ok(CommunityDriverV1::new(config).0)
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

/// A community claim on the fixture's type, which the first-party twin owns, then a pass.
fn community_claims_native_type(signed: &SignedWorld, entry: &Published) -> BoxResult<Claim> {
    let mut pass = PassWorld::new(WORKER);
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
/// then a pass.
fn native_claims_community_type(signed: &SignedWorld, entries: &[Published]) -> BoxResult<Claim> {
    let mut lane = Lane::new(signed, entries, Mode::Local)?;
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
fn record_claim(capture: &mut Capture, path: &str, claim: &Claim) {
    capture.record(STORE, &format!("{path}.refusal"), &claim.refusal);
    capture.record(STORE, &format!("{path}.registry-unchanged"), claim.unchanged);
    record(capture, path, &claim.observed);
}

/// The refusals of a first-party and a community claim on the reserved consent type, in one
/// empty registry, and whether that registry is unchanged.
fn reserved_claims(signed: &SignedWorld, entry: &Published) -> BoxResult<(String, String, bool)> {
    let mut pass = PassWorld::new(WORKER);
    let before = snapshot(&pass.registry);
    let native = register_twin(&mut pass.registry, RESERVED_CLAIM, entity_of(ENTITY)?);
    let native = claim_refusal(native);
    let community = community_claim(signed, entry, &mut pass.registry, RESERVED_CLAIM);
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
    single_lineage().test_ok()
}

fn single_lineage() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let by_community = community_claims_native_type(&signed, &alpha)?;
    let by_first_party = native_claims_community_type(&signed, std::slice::from_ref(&alpha))?;
    let (native, community, unchanged) = reserved_claims(&signed, &alpha)?;
    let mut capture = Capture::default();
    record_claim(&mut capture, "community-claim", &by_community);
    record_claim(&mut capture, "first-party-claim", &by_first_party);
    capture.record(STORE, "reserved-claim.first-party.refusal", &native);
    capture.record(STORE, "reserved-claim.community.refusal", &community);
    capture.record(STORE, "reserved-claim.registry-unchanged", unchanged);
    let same = by_community.refusal == by_first_party.refusal && native == community;
    capture.record(STORE, "parity.same-refusal-either-class", same);
    Ok(capture)
}
