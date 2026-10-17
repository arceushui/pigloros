//! The mid-run composition boundary transaction and the owner actions (ADR-119 sections 4.3
//! and 4.4).

use pos_core::trusted_clock::PluginTrustWallSourceV1;
use pos_core::{
    CompositionPinV1, Event, FallbackActivatedPayloadV1, FallbackActivationModeV1,
    FallbackActivationOriginV1 as Origin, FallbackSkipReasonV1 as Skip, FallbackSkippedCandidateV1,
    FallbackTriggerBasisV1, FallbackTriggerCodeV1, ImplementationKeyV1, Seq, SeqRange, TimelineId,
};
use pos_runtime::community_plugin_host::{CommunityPassOutcomeV1, CommunityPluginHostV1};
use pos_runtime::composition_fallback::{classify_fallback_trigger_v1, enforce_required_plugin_v1};
use pos_runtime::{FallbackHostGrantsV1, PluginRegistry, RegisteredPlugin};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, FallbackActivateRequestV1, FallbackLedgerRowV1,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

use super::candidate::{build_candidate, BuildV1, BuiltV1};
use super::derive::{
    effective_composition_v1, read_prefix, FallbackEffectiveCompositionV1,
    FallbackEffectiveEntryV1, PrefixV1,
};
use super::trigger::fallback_trigger_cause_v1;
use super::{
    CompositionBoundaryV1, FallbackBoundaryContextV1, FallbackBoundaryErrorV1 as Error,
    FallbackBoundaryStoreV1, FallbackEntryOutcomeV1 as Outcome, ObservationV1,
    COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1,
};
use crate::member::CommunityMemberV1;

type Host = CommunityPluginHostV1<CommunityMemberV1>;
type Context<'c, 'a, S, T, W> = &'c mut FallbackBoundaryContextV1<'a, S, T, W>;
/// A validated target and its pin, or the reason it is skipped and its pin.
type AttemptV1<'p> = Result<(SwapV1, &'p CompositionPinV1), (Skip, &'p CompositionPinV1)>;

/// The live registry does not run the effective composition (ADR-119 section 4.7).
const LIVE_DIVERGED: Error =
    Error::InvariantFault("the live registry differs from the effective composition");
/// A step after the commit failed (ADR-119 section 4.4, "After the commit").
const SWAP_FAILED: Error = Error::InvariantFault("a step after the activation commit failed");
/// The activation that opened the closing tenure cannot be read back.
const TENURE_UNRESOLVED: Error =
    Error::InvariantFault("the activation that opened the tenure is not readable");

/// The trigger an activation records: the code and its `trigger_basis`.
#[derive(Clone, Copy)]
struct TriggerV1 {
    code: FallbackTriggerCodeV1,
    basis: FallbackTriggerBasisV1,
}

/// A candidate that passed the host-level `validate_swap` (ADR-119 section 4.4 step 3).
struct SwapV1 {
    built: BuiltV1,
    /// The host schedule index of the primary's member.
    index: usize,
    /// The pre-commit prefix, read and validated.
    prefix: PrefixV1,
}

/// The state the automatic transaction folds over the entries.
struct FoldedV1 {
    revision: u64,
    outcomes: Vec<Outcome>,
}

impl FoldedV1 {
    /// Record `reaction`; a committed activation advances the expected state revision.
    fn push(mut self, reaction: Option<Outcome>) -> Self {
        if let Some(Outcome::Activated { row, .. }) = &reaction {
            self.revision = row.state_revision();
        }
        self.outcomes.extend(reaction);
        self
    }
}

impl CompositionBoundaryV1 {
    /// Run the composition boundary transaction after the pass `outcome` returned (ADR-119
    /// section 4.4).
    ///
    /// It re-derives the effective composition and requires the live registry to run it. For
    /// each declared entry whose member failed with an eligible cause in a `Failed` or
    /// `Refused` pass, it keeps the observation for owner actions. When the entry declares
    /// the code: a manual entry waits for its owner, and an automatic entry walks forward
    /// along its chain, skipping each candidate that fails steps 2-3, and commits and swaps
    /// the first that passes. Entries are handled in policy order, each at the state revision
    /// the previous one left.
    ///
    /// # Errors
    /// Returns [`Error::Faulted`] after an earlier invariant fault, the registry's refusal of
    /// the derivation, and an invariant fault, which latches, when the live registry differs
    /// from the effective composition or a step after a commit failed.
    pub fn run_boundary_v1<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        outcome: &CommunityPassOutcomeV1,
    ) -> Result<Vec<Outcome>, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let composition = self.checked(&*context.store, context.registry)?;
        let folded = FoldedV1 {
            revision: composition.state_revision,
            outcomes: Vec::new(),
        };
        let mut entries = composition.entries.iter();
        let folded = entries.try_fold(folded, |folded, effective| {
            self.step(context, host, outcome, effective, folded)
        });
        folded.map(|folded| folded.outcomes)
    }

    /// Activate the implementation `target` of `entry_key` on the owner's behalf (ADR-119
    /// section 4.3, "Chain and owner actions").
    ///
    /// A candidate, adjacent or not, needs a current eligible observation of the effective
    /// implementation whose code the entry declares; the activation records that code with
    /// `origin=owner`. The entry's declared primary is the bounded return: it is allowed only
    /// from a candidate tenure, needs no observation, re-runs the trust gate, and records the
    /// closing tenure's code with `origin=owner`. A target that fails steps 2-3 is reported as
    /// [`Outcome::Exhausted`] and nothing is committed.
    ///
    /// # Errors
    /// Returns [`Error::NotGranted`] without the `composition.fallback.activate` grant, the
    /// derivation's errors, [`Error::UnknownEntry`], [`Error::InvalidTarget`] for a target that
    /// is not another listed implementation, [`Error::NoObservation`] or
    /// [`Error::TriggerNotDeclared`] for a candidate, and the invariant faults of the commit.
    pub fn owner_activate_v1<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        grants: &FallbackHostGrantsV1,
        entry_key: &str,
        target: &ImplementationKeyV1,
    ) -> Result<Outcome, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        if !grants.holds(COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1) {
            return Err(Error::NotGranted);
        }
        let composition = self.checked(&*context.store, context.registry)?;
        let effective = composition.entry(entry_key).ok_or(Error::UnknownEntry)?;
        let current = usize::from(effective.chain_position);
        let chain = effective.chain();
        let position = chain
            .iter()
            .position(|pin| pin.implementation() == target)
            .filter(|position| *position != current)
            .ok_or(Error::InvalidTarget)?;
        let trigger = if position == 0 {
            self.returning(&*context.store, effective)
        } else {
            self.observed(effective)
        };
        let revision = composition.state_revision;
        trigger.and_then(|trigger| {
            let pin = chain[position];
            let attempt = self.attempt(context, host, effective, pin, position > 0);
            self.settle(context, host, effective, attempt, trigger, revision)
        })
    }

    /// Derive the effective composition and require the live registry to run it.
    fn checked<S: FallbackBoundaryStoreV1 + ?Sized>(
        &mut self,
        store: &S,
        registry: &PluginRegistry,
    ) -> Result<FallbackEffectiveCompositionV1, Error> {
        if self.faulted {
            return Err(Error::Faulted);
        }
        let composition = effective_composition_v1(store, &self.scope, self.target.timeline)?;
        let plugins = registry.composition().plugins;
        let live = composition
            .entries
            .iter()
            .all(|effective| self.runs(&plugins, effective));
        self.faulted = !live;
        live.then_some(composition).ok_or(LIVE_DIVERGED)
    }

    /// Whether the Plugin bound to `effective`'s entry is registered as its effective
    /// implementation: the IMK1 version label and release digest.
    fn runs(&self, plugins: &[RegisteredPlugin], effective: &FallbackEffectiveEntryV1) -> bool {
        let bound = self.binding(effective.entry.entry_key());
        let registered = bound.and_then(|id| plugins.iter().find(|plugin| plugin.id == id));
        registered.is_some_and(|plugin| {
            let pin = plugin.pin.as_ref();
            enforce_required_plugin_v1(&plugin.version, pin, &effective.effective).is_ok()
        })
    }

    /// The eligible observation of `effective`'s member in `outcome`, if any.
    fn observe(
        &self,
        effective: &FallbackEffectiveEntryV1,
        outcome: &CommunityPassOutcomeV1,
    ) -> Option<ObservationV1> {
        let bound = self.binding(effective.entry.entry_key());
        let cause = bound.and_then(|plugin| fallback_trigger_cause_v1(outcome, plugin));
        let code = cause.and_then(classify_fallback_trigger_v1);
        let digest = effective.effective.implementation().digest();
        cause.zip(code).map(|(cause, code)| ObservationV1 {
            effective: digest,
            cause,
            code,
        })
    }

    /// Handle one entry of the automatic transaction.
    fn step<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        outcome: &CommunityPassOutcomeV1,
        effective: &FallbackEffectiveEntryV1,
        folded: FoldedV1,
    ) -> Result<FoldedV1, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        match self.observe(effective, outcome) {
            None => Ok(folded),
            Some(observation) => {
                let key = effective.entry.entry_key().to_owned();
                self.observations.insert(key, observation);
                let revision = folded.revision;
                let reaction = self.react(context, host, effective, observation, revision);
                reaction.map(|reaction| folded.push(reaction))
            }
        }
    }

    /// React to an eligible observation: nothing for an undeclared code, wait for the owner
    /// in manual mode, otherwise walk the chain.
    fn react<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        effective: &FallbackEffectiveEntryV1,
        observation: ObservationV1,
        revision: u64,
    ) -> Result<Option<Outcome>, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let entry = &effective.entry;
        if !entry.triggers().contains(&observation.code) {
            return Ok(None);
        }
        if entry.activation_mode() == FallbackActivationModeV1::Manual {
            return Ok(Some(Outcome::AwaitingOwner {
                entry_key: entry.entry_key().to_owned(),
                code: observation.code,
            }));
        }
        let trigger = TriggerV1 {
            code: observation.code,
            basis: observation.cause.basis(Origin::Automatic),
        };
        self.advance(context, host, effective, trigger, revision)
            .map(Some)
    }

    /// Walk forward along the chain from the effective implementation and activate the first
    /// candidate that passes steps 2-3, or report every skipped candidate.
    fn advance<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        effective: &FallbackEffectiveEntryV1,
        trigger: TriggerV1,
        revision: u64,
    ) -> Result<Outcome, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let start = usize::from(effective.chain_position) + 1;
        let mut skipped = Vec::new();
        for pin in effective.chain().into_iter().skip(start) {
            match self.attempt(context, host, effective, pin, true) {
                Ok((swap, _)) => {
                    let commit = CommitV1 {
                        effective,
                        pin,
                        trigger,
                        skipped,
                        revision,
                    };
                    return self.commit_and_swap(context, host, swap, commit);
                }
                Err((reason, _)) => skipped.push(skip_of(pin, reason)),
            }
        }
        Ok(Outcome::Exhausted {
            entry_key: effective.entry.entry_key().to_owned(),
            skipped,
        })
    }

    /// Commit and swap a validated target, or report it skipped (an owner action).
    fn settle<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        effective: &FallbackEffectiveEntryV1,
        attempt: AttemptV1<'_>,
        trigger: TriggerV1,
        revision: u64,
    ) -> Result<Outcome, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        match attempt {
            Ok((swap, pin)) => {
                let commit = CommitV1 {
                    effective,
                    pin,
                    trigger,
                    skipped: Vec::new(),
                    revision,
                };
                self.commit_and_swap(context, host, swap, commit)
            }
            Err((reason, pin)) => Ok(Outcome::Exhausted {
                entry_key: effective.entry.entry_key().to_owned(),
                skipped: vec![skip_of(pin, reason)],
            }),
        }
    }

    /// Steps 2 and 3 for `pin`: build the candidate and run the host-level `validate_swap`.
    fn attempt<'p, S, T, W>(
        &self,
        context: Context<'_, '_, S, T, W>,
        host: &Host,
        effective: &FallbackEffectiveEntryV1,
        pin: &'p CompositionPinV1,
        verify_facts: bool,
    ) -> AttemptV1<'p>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: PluginTrustPolicyRegistryV1 + ?Sized,
        W: PluginTrustWallSourceV1,
    {
        let entry_key = effective.entry.entry_key();
        let wanted = BuildV1 {
            entry_key,
            pin,
            replacing: self.binding(entry_key),
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
        let timeline = self.target.timeline;
        let swap = built.and_then(|built| {
            validate_swap(
                context.registry,
                host,
                &*context.store,
                timeline,
                pin,
                built,
            )
        });
        swap.map(|swap| (swap, pin)).map_err(|reason| (reason, pin))
    }

    /// Steps 4-6: commit the activation, then swap and restore, which cannot fail after a
    /// valid dry run; any failure after the commit is the latched invariant fault.
    fn commit_and_swap<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        swap: SwapV1,
        commit: CommitV1<'_>,
    ) -> Result<Outcome, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: ?Sized,
    {
        let request = commit.request(self, swap.prefix.head, context.tick);
        let committed = commit_activation(&mut *context.store, &request);
        committed.map_or_else(Ok, |row| self.activated(context, host, swap, request, row))
    }

    /// Steps 5-6 after a commit: the fault latches unless both succeed.
    fn activated<S, T, W>(
        &mut self,
        context: Context<'_, '_, S, T, W>,
        host: &mut Host,
        swap: SwapV1,
        request: FallbackActivateRequestV1,
        row: FallbackLedgerRowV1,
    ) -> Result<Outcome, Error>
    where
        S: FallbackBoundaryStoreV1 + ?Sized,
        T: ?Sized,
    {
        self.faulted = true;
        let candidate = swap.built.prepared.plugin_id();
        let timeline = self.target.timeline;
        let event = activation_event(&*context.store, timeline, &row, &request);
        let applied = event.and_then(|event| apply(context.registry, host, swap, event));
        self.faulted = applied.is_none();
        let activated = applied.map(|()| {
            let FallbackActivateRequestV1 {
                entry_key,
                to,
                skipped,
                ..
            } = request;
            self.observations.remove(&entry_key);
            self.bindings.insert(entry_key.clone(), candidate);
            Outcome::Activated {
                entry_key,
                to: Box::new(to),
                skipped,
                row: Box::new(row),
            }
        });
        activated.ok_or(SWAP_FAILED)
    }

    /// The owner's candidate trigger: the current eligible observation of the effective
    /// implementation, whose code the entry must declare.
    fn observed(&self, effective: &FallbackEffectiveEntryV1) -> Result<TriggerV1, Error> {
        let digest = effective.effective.implementation().digest();
        let observation = self
            .observations
            .get(effective.entry.entry_key())
            .filter(|observation| observation.effective == digest)
            .ok_or(Error::NoObservation)?;
        let trigger = TriggerV1 {
            code: observation.code,
            basis: observation.cause.basis(Origin::Owner),
        };
        let declared = effective.entry.triggers().contains(&observation.code);
        declared.then_some(trigger).ok_or(Error::TriggerNotDeclared)
    }

    /// The owner's return trigger: the code and cause of the activation that opened the
    /// closing tenure, with `origin=owner`.
    fn returning<S: FallbackBoundaryStoreV1 + ?Sized>(
        &self,
        store: &S,
        effective: &FallbackEffectiveEntryV1,
    ) -> Result<TriggerV1, Error> {
        let timeline = self.target.timeline;
        let closing = effective.tenure_ordinal.saturating_sub(1);
        let key = effective.entry.entry_key();
        let opened = store.lookup_activation(&self.scope, timeline, key, closing);
        let event = opened
            .ok()
            .flatten()
            .and_then(|row| read_event(store, timeline, &row));
        let payload = event.and_then(|event| decoded_activation(&event));
        let trigger = payload.map(|payload| {
            let input = payload.as_input();
            TriggerV1 {
                code: input.trigger_code,
                basis: FallbackTriggerBasisV1 {
                    cause: input.trigger_basis.cause,
                    origin: Origin::Owner,
                },
            }
        });
        trigger.ok_or(TENURE_UNRESOLVED)
    }
}

/// What one activation commits.
struct CommitV1<'e> {
    effective: &'e FallbackEffectiveEntryV1,
    pin: &'e CompositionPinV1,
    trigger: TriggerV1,
    skipped: Vec<FallbackSkippedCandidateV1>,
    revision: u64,
}

impl CommitV1<'_> {
    /// The port request: close the current tenure on the effective implementation.
    fn request(
        self,
        boundary: &CompositionBoundaryV1,
        head: Seq,
        tick: u64,
    ) -> FallbackActivateRequestV1 {
        FallbackActivateRequestV1 {
            scope: boundary.scope.clone(),
            target: boundary.target,
            expected_state_revision: self.revision,
            expected_logical_head: head,
            entry_key: self.effective.entry.entry_key().to_owned(),
            closing_tenure_ordinal: self.effective.tenure_ordinal,
            from: self.effective.effective.implementation().clone(),
            to: self.pin.implementation().clone(),
            trigger_code: self.trigger.code,
            trigger_basis: self.trigger.basis,
            skipped: self.skipped,
            tick,
        }
    }
}

/// The skipped record of `pin`.
fn skip_of(pin: &CompositionPinV1, reason: Skip) -> FallbackSkippedCandidateV1 {
    FallbackSkippedCandidateV1 {
        implementation_digest: pin.implementation().digest(),
        reason,
    }
}

/// The host-level `validate_swap(entry_key, prepared, k, prefix)` (ADR-119 section 4.4 step 3).
///
/// It checks the implementation key (`Plugin::version()` and the pin's configuration digest
/// against IMK1), finds the primary's host member `k` by `member.plugin() == primary_id` in
/// host schedule order, reads the pre-commit prefix and validates it as every restore does,
/// and finally runs the registry's dry run with its capacity reservation. Any failure skips
/// the candidate (`SwapRefused`) with nothing changed.
fn validate_swap<S: FallbackBoundaryStoreV1 + ?Sized>(
    registry: &mut PluginRegistry,
    host: &Host,
    store: &S,
    timeline: TimelineId,
    pin: &CompositionPinV1,
    built: BuiltV1,
) -> Result<SwapV1, Skip> {
    let prepared = &built.prepared;
    let bound = enforce_required_plugin_v1(prepared.version(), prepared.pin(), pin).is_ok();
    let index = prepared
        .replacing()
        .and_then(|primary| host.member_index(primary))
        .filter(|_| bound);
    let prefix = checked_prefix(read_prefix(store, timeline));
    let checked = index
        .ok_or(Skip::SwapRefused)
        .and_then(|index| prefix.map(|prefix| (index, prefix)));
    let (index, prefix) = checked?;
    registry
        .validate_swap_v1(&built.prepared)
        .or(Err(Skip::SwapRefused))?;
    Ok(SwapV1 {
        built,
        index,
        prefix,
    })
}

/// The pre-commit prefix if it was read and passes the check every restore runs.
pub(super) fn checked_prefix(
    read: Result<PrefixV1, pos_core::CoreError>,
) -> Result<PrefixV1, Skip> {
    let valid = |prefix: &PrefixV1| {
        PluginRegistry::validate_recovery_prefix_v1(&prefix.segments, &prefix.events).is_ok()
    };
    read.ok().filter(valid).ok_or(Skip::SwapRefused)
}

/// Commit the activation (step 4). After a refusal, a committed activation of the same tenure
/// is adopted only when the commit outcome was unknown (`StorageIndeterminate`); otherwise the
/// refusal stands, nothing changed, and the entry's outcome is `NotCommitted`.
pub(super) fn commit_activation<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &mut S,
    request: &FallbackActivateRequestV1,
) -> Result<FallbackLedgerRowV1, Outcome> {
    let committed = store.activate(request);
    let committed = committed
        .map(|receipt| receipt.row().clone())
        .or_else(|error| adopt(&*store, request, error));
    committed.map_err(|error| Outcome::NotCommitted {
        entry_key: request.entry_key.clone(),
        error,
    })
}

/// The activation the port recorded for the request's tenure, adopted after an unknown commit
/// outcome; `error` otherwise, or when the lookup finds nothing.
fn adopt<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    request: &FallbackActivateRequestV1,
    error: CompositionFallbackRegistryErrorV1,
) -> Result<FallbackLedgerRowV1, CompositionFallbackRegistryErrorV1> {
    let timeline = request.target.timeline;
    let (key, closing) = (&request.entry_key, request.closing_tenure_ordinal);
    let found = store.lookup_activation(&request.scope, timeline, key, closing);
    let unknown = error == CompositionFallbackRegistryErrorV1::StorageIndeterminate;
    found.ok().flatten().filter(|_| unknown).ok_or(error)
}

/// The committed Event of `row`.
fn read_event<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    timeline: TimelineId,
    row: &FallbackLedgerRowV1,
) -> Option<Event> {
    let identity = row.event();
    let events = store
        .read(timeline, SeqRange::from_seq(identity.seq()))
        .ok();
    let mut events = events.into_iter().flatten();
    events.find(|event| event.id == identity.event_id())
}

/// The decoded activation payload of `event`.
fn decoded_activation(event: &Event) -> Option<FallbackActivatedPayloadV1> {
    FallbackActivatedPayloadV1::from_canonical_cbor(event.payload.as_slice()).ok()
}

/// The activation Event the commit returned, which must activate the request's target.
fn activation_event<S: FallbackBoundaryStoreV1 + ?Sized>(
    store: &S,
    timeline: TimelineId,
    row: &FallbackLedgerRowV1,
    request: &FallbackActivateRequestV1,
) -> Option<Event> {
    let event = read_event(store, timeline, row);
    event.filter(|event| {
        decoded_activation(event).is_some_and(|payload| {
            let input = payload.as_input();
            input.entry_key == request.entry_key && input.to == request.to
        })
    })
}

/// Steps 5 and 6: swap the registry entry and the host member, then restore the candidate's
/// entry from the prefix extended by the activation Event. `None` when any step fails.
fn apply(
    registry: &mut PluginRegistry,
    host: &mut Host,
    swap: SwapV1,
    activation: Event,
) -> Option<()> {
    let SwapV1 {
        built,
        index,
        prefix,
    } = swap;
    let BuiltV1 { prepared, member } = built;
    let candidate = prepared.plugin_id();
    let prefix = prefix.extended(activation);
    let (segments, events) = (&prefix.segments, &prefix.events);
    registry
        .swap_entry_v1(prepared)
        .ok()
        .and_then(|()| host.replace_member(index, member).ok())
        .and_then(|_primary| {
            let restored = registry.restore_entry_from_history_v1(candidate, segments, events);
            restored.ok()
        })
}
