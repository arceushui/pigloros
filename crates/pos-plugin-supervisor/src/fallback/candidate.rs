//! Candidate construction (ADR-119 section 4.4 step 2): source, re-verification, facts, the
//! Driver and its host member, and the prepared entry.

use pos_core::trusted_clock::PluginTrustWallSourceV1;
use pos_core::{
    CompositionPinV1, FallbackSkipReasonV1 as Skip, FallbackSkippedCandidateV1, Hash, PluginId,
};
use pos_runtime::community_plugin_host::{
    gate_for_driver, CommunityPluginExpectationV1, CommunityPluginHostErrorV1,
    GatedCommunityReleaseV1,
};
use pos_runtime::composition_fallback::validate_fallback_candidate_v1;
use pos_runtime::{
    community_pin_v1, FallbackCandidateFactsV1, FallbackDriverSettingsV1, FallbackExecutionFactsV1,
    FallbackHostFactsV1, PluginAvailabilityV1, PluginRegistrationV1, PluginRegistry,
    PreparedRegistrationV1,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

use super::{Context, FallbackCandidateInputV1, FallbackReferenceV1, FallbackReleaseSupplyV1};
use crate::adapter::{CommunityDriverConfigV1, CommunityDriverV1};
use crate::member::CommunityMemberV1;

/// The gate admitted a release, but not the IMK1 one: the IMK1 release is not admitted.
const NOT_ADMITTED: RefusalV1 = RefusalV1 {
    reason: Skip::ReleaseNotCurrent,
    gate: None,
};

/// Why a candidate was not built: its closed skip reason and, when the trust gate refused the
/// release, the gate's own refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RefusalV1 {
    pub(super) reason: Skip,
    pub(super) gate: Option<CommunityPluginHostErrorV1>,
}

impl From<Skip> for RefusalV1 {
    fn from(reason: Skip) -> Self {
        Self { reason, gate: None }
    }
}

/// What one candidate is built for.
struct BuildV1<'a> {
    /// The DFP1 entry key.
    entry_key: &'a str,
    /// The declared pin of the implementation to build.
    pin: &'a CompositionPinV1,
    /// The Plugin the candidate replaces, or `None` for a fresh install at restart.
    replacing: Option<PluginId>,
    /// Whether to re-check the section 4.1 facts against the entry's primary; the primary
    /// itself (an owner return, or a restart's effective implementation) is not compared with
    /// itself.
    verify_facts: bool,
    /// The Tick of the boundary.
    tick: u64,
}

/// A built candidate: its prepared entry, which holds its Driver, and its host member, which
/// holds its handle. Dropping it tears both down.
pub(super) struct BuiltV1 {
    pub(super) prepared: PreparedRegistrationV1,
    pub(super) member: CommunityMemberV1,
}

/// The skipped record of `pin`.
pub(super) fn skip_of(pin: &CompositionPinV1, reason: Skip) -> FallbackSkippedCandidateV1 {
    FallbackSkippedCandidateV1 {
        implementation_digest: pin.implementation().digest(),
        reason,
    }
}

/// Build `pin` for `entry_key` over `context`, replacing `replacing` (`None` at restart), with
/// the facts re-checked when `verify_facts`.
pub(super) fn build_in<S, T, W>(
    context: Context<'_, '_, S, T, W>,
    entry_key: &str,
    pin: &CompositionPinV1,
    replacing: Option<PluginId>,
    verify_facts: bool,
) -> Result<BuiltV1, RefusalV1>
where
    S: ?Sized,
    T: PluginTrustPolicyRegistryV1 + ?Sized,
    W: PluginTrustWallSourceV1,
{
    let wanted = BuildV1 {
        entry_key,
        pin,
        replacing,
        verify_facts,
        tick: context.tick,
    };
    let registry = &*context.registry;
    build_candidate(
        registry,
        context.trust,
        context.wall,
        context.supply,
        &wanted,
    )
}

/// Build the candidate `build` names, or the reason it is skipped.
///
/// The order is ADR-119 section 4.4 step 2: the release source (`SourceUnavailable`); the
/// trust gate at a fresh trusted UTC second and the boundary's Tick, which runs
/// `evaluate_current_release` and must admit exactly the IMK1 release (`ReleaseNotCurrent`,
/// with the gate's refusal when it refused); the facts (`FactsMismatch`); the Driver, handle
/// and member (`MemberBuildFailed`); then the dry-run preparation (`PrepareRefused`).
fn build_candidate<T, W>(
    registry: &PluginRegistry,
    trust: &T,
    wall: &mut W,
    supply: &mut dyn FallbackReleaseSupplyV1,
    build: &BuildV1<'_>,
) -> Result<BuiltV1, RefusalV1>
where
    T: PluginTrustPolicyRegistryV1 + ?Sized,
    W: PluginTrustWallSourceV1,
{
    let key = build.pin.implementation();
    let input = supply
        .candidate(build.entry_key, key)
        .ok_or(Skip::SourceUnavailable)?;
    let gated = gate(trust, wall, &input, build)?;
    verified(&*supply, &input, &gated, build)?;
    let assembled = assemble(input, gated, build)?;
    prepare(registry, assembled, build).map_err(RefusalV1::from)
}

/// The facts re-check of `build`, when it asks for one.
fn verified(
    supply: &dyn FallbackReleaseSupplyV1,
    input: &FallbackCandidateInputV1,
    gated: &GatedCommunityReleaseV1,
    build: &BuildV1<'_>,
) -> Result<(), Skip> {
    if !build.verify_facts {
        return Ok(());
    }
    let reference = supply.reference(build.entry_key);
    verify_facts(reference.as_ref(), input, gated, build)
}

/// The dry-run preparation of an assembled candidate under its community pin.
fn prepare(
    registry: &PluginRegistry,
    assembled: AssembledV1,
    build: &BuildV1<'_>,
) -> Result<BuiltV1, Skip> {
    let AssembledV1 {
        driver,
        member,
        plugin,
    } = assembled;
    let key = build.pin.implementation();
    let community = community_pin_v1(key.release_digest(), build.pin.roles().to_vec());
    let registration = community
        .map(|pin| PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available))
        .or(Err(Skip::PrepareRefused));
    let driver: Box<dyn pos_runtime::Driver> = Box::new(driver);
    let prepared = registration.and_then(|registration| {
        let prepared = registry.prepare_pinned_generated_v1(
            plugin.as_ref(),
            registration,
            Some(driver),
            build.replacing,
        );
        prepared.or(Err(Skip::PrepareRefused))
    });
    prepared.map(|prepared| BuiltV1 { prepared, member })
}

/// Gate the candidate's release once, at a fresh trusted second and the boundary's Tick.
fn gate<T, W>(
    trust: &T,
    wall: &mut W,
    input: &FallbackCandidateInputV1,
    build: &BuildV1<'_>,
) -> Result<GatedCommunityReleaseV1, RefusalV1>
where
    T: PluginTrustPolicyRegistryV1 + ?Sized,
    W: PluginTrustWallSourceV1,
{
    let key = build.pin.implementation();
    let expectation = CommunityPluginExpectationV1 {
        plugin_id: key.plugin_id().to_owned(),
        release: None,
    };
    let gated = gate_for_driver(
        trust,
        &expectation,
        input.source.as_ref(),
        &input.address,
        input.material.as_ref(),
        wall,
        build.tick,
    );
    let gated = gated.map_err(|error| RefusalV1 {
        reason: Skip::ReleaseNotCurrent,
        gate: Some(error),
    })?;
    let admitted = Hash::from_bytes(gated.release_digest()) == key.release_digest();
    admitted.then_some(gated).ok_or(NOT_ADMITTED)
}

/// Re-check rules 1-6 of the candidate against the entry's primary (ADR-119 section 4.4,
/// "Candidate re-verification").
///
/// The admitted release is the one the gate just accepted. Rule 7 is not re-evaluated at the
/// boundary: the candidate carries the primary's frozen conformance set.
fn verify_facts(
    reference: Option<&FallbackReferenceV1>,
    input: &FallbackCandidateInputV1,
    gated: &GatedCommunityReleaseV1,
    build: &BuildV1<'_>,
) -> Result<(), Skip> {
    let reference = reference.ok_or(Skip::FactsMismatch)?;
    let settings = FallbackDriverSettingsV1 {
        tick_interval: input.settings.tick_interval,
        subscriptions: input.settings.subscriptions.clone(),
    };
    let host = FallbackHostFactsV1 {
        active_release_digest: Some(Hash::from_bytes(gated.release_digest())),
        conformance_profiles: reference.primary.host.conformance_profiles.clone(),
        ..input.host.clone()
    };
    let execution = FallbackExecutionFactsV1::from_projection(gated.execution());
    let plugin = input.plugin.as_ref();
    let pin = build.pin.clone();
    let facts = FallbackCandidateFactsV1::collect(plugin, pin, settings, execution, host);
    let (composition, primary) = (&reference.composition, &reference.primary);
    let valid = facts.ok().is_some_and(|facts| {
        validate_fallback_candidate_v1(build.entry_key, composition, primary, &facts).is_ok()
    });
    valid.then_some(()).ok_or(Skip::FactsMismatch)
}

/// A candidate's Driver, its host member and its Plugin.
struct AssembledV1 {
    driver: CommunityDriverV1,
    member: CommunityMemberV1,
    plugin: Box<dyn pos_core::Plugin>,
}

/// The candidate's Driver, built from the gated release, its host member, and its Plugin.
fn assemble(
    input: FallbackCandidateInputV1,
    gated: GatedCommunityReleaseV1,
    build: &BuildV1<'_>,
) -> Result<AssembledV1, Skip> {
    let FallbackCandidateInputV1 {
        plugin,
        source,
        address,
        material,
        settings,
        host_abi,
        profile,
        host: _,
    } = input;
    if settings.plugin_id != plugin.id() {
        return Err(Skip::MemberBuildFailed);
    }
    let plugin_id = build.pin.implementation().plugin_id();
    let expectation = CommunityPluginExpectationV1 {
        plugin_id: plugin_id.to_owned(),
        release: Some((gated.pmf1_digest(), gated.release_digest())),
    };
    let config =
        CommunityDriverConfigV1::from_gated(gated, &host_abi, &profile, plugin_id, settings);
    let config = config.or(Err(Skip::MemberBuildFailed))?;
    let (driver, handle) = CommunityDriverV1::new(config);
    let member = CommunityMemberV1::new(handle, source, address, material, expectation);
    Ok(AssembledV1 {
        driver,
        member,
        plugin,
    })
}
