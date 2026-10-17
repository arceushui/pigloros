//! Restart composition and the restart activation for trigger code 1 (ADR-119 section 4.4,
//! "Restart activation, code 1").

use std::collections::BTreeMap;

use pos_core::trusted_clock::PluginTrustWallSourceV1;
use pos_core::{
    CompositionPinV1, FallbackActivationOriginV1, FallbackSkipReasonV1 as Skip,
    FallbackSkippedCandidateV1, FallbackTriggerCodeV1, PluginId, Seq,
};
use pos_runtime::community_plugin_host::CommunityPluginHostV1;
use pos_runtime::composition_fallback::enforce_required_plugin_v1;
use pos_runtime::{FallbackTriggerCauseV1, PluginRegistry, ScheduledDriverBindingV1};
use pos_store::composition_fallback_registry::{
    CompositionFallbackTargetV1, FallbackActivateRequestV1,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

use super::candidate::{build_candidate, BuildV1, BuiltV1};
use super::derive::{
    effective_composition_v1, read_prefix, FallbackEffectiveCompositionV1, FallbackEffectiveEntryV1,
};
use super::{
    CompositionBoundaryV1, FallbackBoundaryContextV1, FallbackBoundaryErrorV1 as Error,
    FallbackBoundaryStoreV1, FallbackEntryOutcomeV1 as Outcome,
};
use crate::member::CommunityMemberV1;

type Context<'c, 'a, S, T, W> = &'c mut FallbackBoundaryContextV1<'a, S, T, W>;

/// A step after a restart activation's commit, or the final restore, failed.
const RESTART_FAILED: Error =
    Error::InvariantFault("a restart step after the activation commit failed");

/// One community slot of the composer's recipe, in recipe order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackRestartSlotV1 {
    /// The slot's stable entry key; a declared entry's key is its DFP1 entry key.
    pub entry_key: String,
    /// The composer's base implementation of the slot.
    pub base: CompositionPinV1,
}

/// A composition rebuilt at restart.
pub struct FallbackRestartV1 {
    /// The boundary over the rebuilt composition.
    pub boundary: CompositionBoundaryV1,
    /// The host over the rebuilt members, in recipe order.
    pub host: CommunityPluginHostV1<CommunityMemberV1>,
    /// The restart activations that committed (trigger code 1).
    pub outcomes: Vec<Outcome>,
}

/// What the restart composition has built so far.
struct ComposedV1 {
    revision: u64,
    bindings: BTreeMap<String, PluginId>,
    members: Vec<CommunityMemberV1>,
    outcomes: Vec<Outcome>,
}

/// Compose every community slot at restart, in recipe order (ADR-119 section 4.4, "Restart
/// activation, code 1").
///
/// The effective composition is derived from the fold. Each slot's effective implementation
/// (the base implementation of a slot no policy declares) is built and installed fresh. When
/// a declared entry's effective implementation is missing, its release source or its admitted
/// release, that is trigger code 1: each later candidate on the chain is re-verified (rules
/// 1-6 and the trust gate), its source checked, its member built and its entry prepared with
/// no primary to replace; the first that validates is activated and installed fresh in the
/// slot's place. The swap seams are not used. Every Driver is then restored over the full
/// prefix.
///
/// # Errors
/// Returns the derivation's errors; [`Error::SlotUnavailable`] when a slot's effective
/// implementation cannot be built and no candidate can replace it (a slot nobody declared,
/// a cause other than a missing implementation, a refused restart activation, or an exhausted
/// chain); and an invariant fault when a step after a restart activation's commit, or the
/// final restore, fails. A failed restart composes nothing usable and is retried from the fold.
pub fn compose_restart_v1<S, T, W>(
    context: Context<'_, '_, S, T, W>,
    scope: String,
    target: CompositionFallbackTargetV1,
    slots: &[FallbackRestartSlotV1],
) -> Result<FallbackRestartV1, Error>
where
    S: FallbackBoundaryStoreV1 + ?Sized,
    T: PluginTrustPolicyRegistryV1 + ?Sized,
    W: PluginTrustWallSourceV1,
{
    let composition = effective_composition_v1(&*context.store, &scope, target.timeline)?;
    let composed = ComposedV1 {
        revision: composition.state_revision,
        bindings: BTreeMap::new(),
        members: Vec::new(),
        outcomes: Vec::new(),
    };
    let restart = RestartV1 {
        scope: &scope,
        target,
        composition: &composition,
    };
    let composed = slots.iter().try_fold(composed, |composed, slot| {
        restart.slot(context, composed, slot)
    })?;
    let prefix = read_prefix(&*context.store, target.timeline).or(Err(RESTART_FAILED));
    let restored = prefix.and_then(|prefix| {
        let restored = context
            .registry
            .restore_driver_state(&prefix.segments, &prefix.events);
        restored.or(Err(RESTART_FAILED))
    });
    restored.map(|()| FallbackRestartV1 {
        boundary: CompositionBoundaryV1::new(scope, target, composed.bindings),
        host: CommunityPluginHostV1::new(composed.members),
        outcomes: composed.outcomes,
    })
}

/// The expected state and Tick of one restart activation, and its skipped candidates.
struct RestartCommitV1 {
    revision: u64,
    head: Seq,
    tick: u64,
    skipped: Vec<FallbackSkippedCandidateV1>,
}

/// The fixed inputs of one restart composition.
struct RestartV1<'r> {
    scope: &'r str,
    target: CompositionFallbackTargetV1,
    composition: &'r FallbackEffectiveCompositionV1,
}

impl RestartV1<'_> {
    /// Compose one slot: its effective implementation, or the code-1 activation of a missing
    /// declared one.
    fn slot<S, T, W>(
        &self,
        context: Context<'_, '_, S, T, W>,
        composed: ComposedV1,
        slot: &FallbackRestartSlotV1,
    ) -> Result<ComposedV1, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let effective = self.composition.entry(&slot.entry_key);
        let pin = effective.map_or(&slot.base, |effective| &effective.effective);
        let built = build_fresh(context, &slot.entry_key, pin, false);
        match (built, effective) {
            (Ok(built), _) => {
                let installed = install(context.registry, composed, &slot.entry_key, built);
                installed.ok_or(Error::SlotUnavailable(Skip::PrepareRefused))
            }
            (Err(Skip::SourceUnavailable | Skip::ReleaseNotCurrent), Some(effective)) => {
                self.missing(context, composed, effective)
            }
            (Err(reason), _) => Err(Error::SlotUnavailable(reason)),
        }
    }

    /// Trigger code 1: activate and install the first later candidate that validates.
    fn missing<S, T, W>(
        &self,
        context: Context<'_, '_, S, T, W>,
        composed: ComposedV1,
        effective: &FallbackEffectiveEntryV1,
    ) -> Result<ComposedV1, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let key = effective.entry.entry_key();
        let start = usize::from(effective.chain_position) + 1;
        let mut skipped = Vec::new();
        for pin in effective.chain().into_iter().skip(start) {
            match build_fresh(context, key, pin, true) {
                Ok(built) => {
                    let store = &*context.store;
                    let head = store
                        .logical_head(self.target.timeline)
                        .unwrap_or(Seq::ZERO);
                    let commit = RestartCommitV1 {
                        revision: composed.revision,
                        head,
                        tick: context.tick,
                        skipped,
                    };
                    let request = self.request(effective, pin, commit);
                    return Self::activate(context, composed, request, built);
                }
                Err(reason) => skipped.push(FallbackSkippedCandidateV1 {
                    implementation_digest: pin.implementation().digest(),
                    reason,
                }),
            }
        }
        Err(Error::SlotUnavailable(Skip::SourceUnavailable))
    }

    /// The code-1 activation request of `pin`.
    fn request(
        &self,
        effective: &FallbackEffectiveEntryV1,
        pin: &CompositionPinV1,
        commit: RestartCommitV1,
    ) -> FallbackActivateRequestV1 {
        let cause = FallbackTriggerCauseV1::MissingImplementation;
        FallbackActivateRequestV1 {
            scope: self.scope.to_owned(),
            target: self.target,
            expected_state_revision: commit.revision,
            expected_logical_head: commit.head,
            entry_key: effective.entry.entry_key().to_owned(),
            closing_tenure_ordinal: effective.tenure_ordinal,
            from: effective.effective.implementation().clone(),
            to: pin.implementation().clone(),
            trigger_code: FallbackTriggerCodeV1::MissingImplementation,
            trigger_basis: cause.basis(FallbackActivationOriginV1::Automatic),
            skipped: commit.skipped,
            tick: commit.tick,
        }
    }

    /// Commit the restart activation, then install the candidate fresh in the slot's place.
    fn activate<S, T, W>(
        context: Context<'_, '_, S, T, W>,
        composed: ComposedV1,
        request: FallbackActivateRequestV1,
        built: BuiltV1,
    ) -> Result<ComposedV1, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: ?Sized,
    {
        let committed = context.store.activate(&request);
        let receipt = committed.map_err(Error::Registry)?;
        let row = receipt.row().clone();
        let key = request.entry_key.clone();
        let installed = install(context.registry, composed, &key, built);
        installed.ok_or(RESTART_FAILED).map(|mut composed| {
            composed.revision = row.state_revision();
            composed.outcomes.push(Outcome::Activated {
                entry_key: request.entry_key,
                to: request.to,
                skipped: request.skipped,
                row: Box::new(row),
            });
            composed
        })
    }
}

/// Build `pin` for `entry_key` with no primary to replace, and check its implementation key.
fn build_fresh<S, T, W>(
    context: Context<'_, '_, S, T, W>,
    entry_key: &str,
    pin: &CompositionPinV1,
    verify_facts: bool,
) -> Result<BuiltV1, Skip>
where
    S: ?Sized,
    T: PluginTrustPolicyRegistryV1 + ?Sized,
    W: PluginTrustWallSourceV1,
{
    let wanted = BuildV1 {
        entry_key,
        pin,
        replacing: None,
        verify_facts,
        tick: context.tick,
    };
    let registry = &*context.registry;
    let built = build_candidate(
        registry,
        context.trust,
        context.wall,
        context.supply,
        &wanted,
    );
    built.and_then(|built| {
        let prepared = &built.prepared;
        let bound = enforce_required_plugin_v1(prepared.version(), prepared.pin(), pin);
        bound.map(|()| built).or(Err(Skip::PrepareRefused))
    })
}

/// Install `built` fresh with the non-participant profile and record its slot.
fn install(
    registry: &mut PluginRegistry,
    mut composed: ComposedV1,
    entry_key: &str,
    built: BuiltV1,
) -> Option<ComposedV1> {
    let BuiltV1 { prepared, member } = built;
    let id = prepared.plugin_id();
    let binding = [(id, ScheduledDriverBindingV1::NonParticipant)];
    let installed = registry.install_prepared_v1(prepared).ok();
    let profiled = installed.and_then(|()| registry.compose_scheduled_profiles(&binding).ok());
    profiled.map(|()| {
        composed.bindings.insert(entry_key.to_owned(), id);
        composed.members.push(member);
        composed
    })
}
