//! Restart composition and the restart activation (ADR-119 section 4.4, "Restart activation,
//! code 1" and "Crash and restart").

use std::collections::BTreeMap;

use pos_core::trusted_clock::PluginTrustWallSourceV1;
use pos_core::{
    CompositionPinV1, FallbackActivationModeV1, FallbackActivationOriginV1,
    FallbackSkipReasonV1 as Skip, FallbackSkippedCandidateV1, FallbackTriggerCodeV1, PluginId, Seq,
    SeqRange, TimelineId,
};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1 as HostError, CommunityPluginHostV1, TrustDenialBasisV1,
};
use pos_runtime::composition_fallback::{classify_fallback_trigger_v1, enforce_required_plugin_v1};
use pos_runtime::{FallbackTriggerCauseV1, PluginRegistry, ScheduledDriverBindingV1};
use pos_store::composition_fallback_registry::{
    CompositionFallbackTargetV1, FallbackActivateRequestV1,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

use super::candidate::{build_in, skip_of, BuiltV1, RefusalV1};
use super::closure::fallback_tenures_v1;
use super::derive::{
    effective_composition_v1, read_prefix, FallbackEffectiveCompositionV1, FallbackEffectiveEntryV1,
};
use super::{
    CompositionBoundaryV1, Context, FallbackBoundaryErrorV1 as Error, FallbackBoundaryStoreV1,
    FallbackEntryOutcomeV1 as Outcome,
};
use crate::member::CommunityMemberV1;

/// A step after a restart activation's commit, or the final restore, failed.
const RESTART_FAILED: Error =
    Error::InvariantFault("a restart step after the activation commit failed");
/// The Events that name each slot's tenures do not fold.
const TENURES_UNRESOLVED: Error =
    Error::InvariantFault("the tenures of the restart slots cannot be derived");

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
/// activation, code 1" and "Crash and restart").
///
/// The effective composition is derived from the fold. Each slot's effective implementation
/// is built and installed fresh. A declared entry's comes from the registry; any other slot's
/// is its latest tenure's ([`fallback_tenures_v1`]), which is the base implementation unless
/// an activation opened a later tenure, as for an entry a withdrawal froze. The trust gate
/// and the implementation-key check run, the section 4.1 facts are not re-checked, and no swap
/// seam is used. When a declared entry's effective implementation is refused:
///
/// - with no release source or no admitted release of its IMK1, that is trigger code 1;
/// - with a revoked release, that is trigger code 4: a Driver can only be built from a release
///   the trust gate accepted, so the revoked release cannot be installed for the first pass's
///   gate to refuse, and the restart takes the gate's own `ArtifactRevoked` as the observation
///   the first gate would have made.
///
/// When the entry is automatic and declares that code, each later candidate on the chain is
/// re-verified (the trust gate and rules 1-6), its member built and its entry prepared with no
/// primary to replace; the first that validates is activated with that code and installed in
/// the slot's place. Every Driver is then restored over the full prefix.
///
/// # Errors
/// Returns the derivation's errors. Returns [`Error::SlotUnavailable`] with the refusal's
/// reason when a slot cannot be composed, and nothing is committed for it: a slot no policy
/// declares, a refusal with no restart trigger (an untrusted release, a member build or
/// preparation failure), a manual entry or one that does not declare the trigger, and an
/// exhausted chain. Returns [`Error::StoreUnavailable`] when the Timeline's Events, or its
/// Logical Head before a restart activation, cannot be read; [`Error::Registry`] when the
/// port refuses the activation; and an invariant fault when the slots' tenures cannot be
/// derived from the Events, or when the install after the commit or the final restore fails.
/// A failed restart composes nothing usable and is retried from the fold.
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
    let slots = resolved_slots(&*context.store, &scope, target.timeline, slots)?;
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

/// The recipe's `slots`, each on the implementation of its latest tenure in the Events of
/// `timeline`; nothing is composed when those Events cannot be read.
fn resolved_slots<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    scope: &str,
    timeline: TimelineId,
    slots: &[FallbackRestartSlotV1],
) -> Result<Vec<FallbackRestartSlotV1>, Error> {
    let events = store.read(timeline, SeqRange::all());
    let events = events.or(Err(Error::StoreUnavailable));
    let tenures = events.and_then(|events| {
        let tenures = fallback_tenures_v1(scope, slots, &events);
        tenures.or(Err(TENURES_UNRESOLVED))
    });
    tenures.map(|tenures| {
        let resolved = slots.iter().map(|slot| tenures.restart_slot(slot));
        resolved.collect()
    })
}

/// A restart refusal whose implementation key does not bind the built implementation.
const KEY_UNBOUND: RefusalV1 = RefusalV1 {
    reason: Skip::PrepareRefused,
    gate: None,
};

/// The trigger code and cause of one restart activation.
type RestartTriggerV1 = (FallbackTriggerCodeV1, FallbackTriggerCauseV1);

/// The expected state, Tick and trigger of one restart activation, and its skipped candidates.
struct RestartCommitV1 {
    revision: u64,
    head: Seq,
    tick: u64,
    trigger: RestartTriggerV1,
    skipped: Vec<FallbackSkippedCandidateV1>,
}

/// The fixed inputs of one restart composition.
struct RestartV1<'r> {
    scope: &'r str,
    target: CompositionFallbackTargetV1,
    composition: &'r FallbackEffectiveCompositionV1,
}

/// The restart trigger of a refused effective implementation, if it has one.
///
/// A missing implementation is code 1: no release source, or no admitted release of its IMK1
/// (the gate refuses it as not active, or admits another release). A revoked release is code
/// 4: a Driver can only be built from a release the gate accepted, so the restart observes the
/// gate's `ArtifactRevoked` here, where the first pass's gate would observe it. Every other
/// refusal has no restart trigger.
fn restart_trigger(refusal: RefusalV1) -> Option<RestartTriggerV1> {
    let not_active = HostError::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::NotActive,
    };
    let missing = FallbackTriggerCauseV1::MissingImplementation;
    let cause = match (refusal.reason, refusal.gate) {
        (Skip::SourceUnavailable, _) | (Skip::ReleaseNotCurrent, None) => Some(missing),
        (Skip::ReleaseNotCurrent, Some(error)) if error == not_active => Some(missing),
        (Skip::ReleaseNotCurrent, Some(error)) => {
            Some(FallbackTriggerCauseV1::from_host_error(error))
        }
        _ => None,
    };
    let restartable = |code: &FallbackTriggerCodeV1| {
        matches!(
            code,
            FallbackTriggerCodeV1::MissingImplementation | FallbackTriggerCodeV1::ArtifactRevoked
        )
    };
    cause.and_then(|cause| {
        let code = classify_fallback_trigger_v1(cause).filter(restartable);
        code.map(|code| (code, cause))
    })
}

impl RestartV1<'_> {
    /// Compose one slot: its effective implementation, or the restart activation that replaces
    /// a missing or revoked declared one.
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
            (Err(refusal), Some(effective)) => self.replace(context, composed, effective, refusal),
            (Err(refusal), None) => Err(Error::SlotUnavailable(refusal.reason)),
        }
    }

    /// Replace the refused effective implementation of `effective` when its refusal has a
    /// restart trigger that the automatic entry declares; otherwise the restart fails closed
    /// with [`Error::SlotUnavailable`] and nothing is committed.
    fn replace<S, T, W>(
        &self,
        context: Context<'_, '_, S, T, W>,
        composed: ComposedV1,
        effective: &FallbackEffectiveEntryV1,
        refusal: RefusalV1,
    ) -> Result<ComposedV1, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let entry = &effective.entry;
        let automatic = entry.activation_mode() == FallbackActivationModeV1::Automatic;
        let declared = |(code, _): &RestartTriggerV1| automatic && entry.triggers().contains(code);
        let trigger = restart_trigger(refusal).filter(declared);
        let Some(trigger) = trigger else {
            return Err(Error::SlotUnavailable(refusal.reason));
        };
        self.walk(context, composed, effective, trigger)
    }

    /// Activate and install the first later candidate that validates.
    fn walk<S, T, W>(
        &self,
        context: Context<'_, '_, S, T, W>,
        composed: ComposedV1,
        effective: &FallbackEffectiveEntryV1,
        trigger: RestartTriggerV1,
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
                    let timeline = self.target.timeline;
                    let head = context.store.logical_head(timeline);
                    let head = head.or(Err(Error::StoreUnavailable));
                    return head.and_then(|head| {
                        let commit = RestartCommitV1 {
                            revision: composed.revision,
                            head,
                            tick: context.tick,
                            trigger,
                            skipped,
                        };
                        let request = self.request(effective, pin, commit);
                        Self::activate(context, composed, request, built)
                    });
                }
                Err(refusal) => skipped.push(skip_of(pin, refusal.reason)),
            }
        }
        Err(Error::SlotUnavailable(Skip::SourceUnavailable))
    }

    /// The restart activation request of `pin`.
    fn request(
        &self,
        effective: &FallbackEffectiveEntryV1,
        pin: &CompositionPinV1,
        commit: RestartCommitV1,
    ) -> FallbackActivateRequestV1 {
        let (code, cause) = commit.trigger;
        FallbackActivateRequestV1 {
            scope: self.scope.to_owned(),
            target: self.target,
            expected_state_revision: commit.revision,
            expected_logical_head: commit.head,
            entry_key: effective.entry.entry_key().to_owned(),
            closing_tenure_ordinal: effective.tenure_ordinal,
            from: effective.effective.implementation().clone(),
            to: pin.implementation().clone(),
            trigger_code: code,
            trigger_basis: cause.basis(FallbackActivationOriginV1::Automatic),
            skipped: commit.skipped,
            tick: commit.tick,
        }
    }

    /// Commit the restart activation, then install the candidate fresh in the slot's place.
    ///
    /// A refused commit fails the restart closed with the registry's refusal; a failed
    /// install after the commit is an invariant fault, and the next restart recomposes from
    /// the fold, which then names the activated candidate.
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
        let committed = committed.map_err(Error::Registry);
        committed.and_then(|receipt| {
            let row = receipt.row().clone();
            let key = request.entry_key.clone();
            let installed = install(context.registry, composed, &key, built);
            installed.ok_or(RESTART_FAILED).map(|mut composed| {
                composed.revision = row.state_revision();
                composed.outcomes.push(Outcome::Activated {
                    entry_key: request.entry_key,
                    to: Box::new(request.to),
                    skipped: request.skipped,
                    row: Box::new(row),
                });
                composed
            })
        })
    }
}

/// Build `pin` for `entry_key` with no primary to replace, and check its implementation key.
///
/// The effective implementation (`verify_facts` false) gets the trust gate and the
/// implementation-key check but no section 4.1 facts re-check: it is the entry's declared
/// primary, or a candidate the fold activated after its own re-verification.
fn build_fresh<S, T, W>(
    context: Context<'_, '_, S, T, W>,
    entry_key: &str,
    pin: &CompositionPinV1,
    verify_facts: bool,
) -> Result<BuiltV1, RefusalV1>
where
    S: ?Sized,
    T: PluginTrustPolicyRegistryV1 + ?Sized,
    W: PluginTrustWallSourceV1,
{
    let built = build_in(context, entry_key, pin, None, verify_facts);
    built.and_then(|built| {
        let prepared = &built.prepared;
        let bound = enforce_required_plugin_v1(prepared.version(), prepared.pin(), pin);
        bound.map(|()| built).or(Err(KEY_UNBOUND))
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
