//! The ADR-119 composition boundary transaction and chain (section 4.4, slice 6, #667).
//!
//! The composition boundary transaction (CBT) is host-only. It runs at the Tick Boundary after
//! a failed or refused pass has returned, and it is neither a pass nor a tick. It holds both
//! the registry and the community host, so it is the host-level orchestration over the
//! `pos-runtime` seams of slice 5:
//!
//! 1. it re-derives the effective composition from the composition fallback registry
//!    ([`effective_composition_v1`]) and reads the trigger from the pass outcome
//!    ([`fallback_trigger_cause_v1`]);
//! 2. it builds the first valid candidate: the trusted host supplies its release source and
//!    Plugin ([`FallbackReleaseSupplyV1`]), the trust gate re-verifies the release at the
//!    boundary's Tick and a fresh trusted UTC second, the section 4.1 facts are re-checked
//!    (rule 7 excepted), and its Driver, handle and host member are built and its entry
//!    prepared;
//! 3. it runs the host-level `validate_swap`: the implementation key, the host member of the
//!    primary, the pre-commit prefix read and its validation, and the registry dry run;
//! 4. it commits the activation through the port, and adopts a committed activation it finds
//!    by lookup after a refused or indeterminate commit;
//! 5. it swaps the registry entry and the host member, both infallible after step 3;
//! 6. it restores the candidate's entry from the prefix, extended by the activation Event.
//!
//! A candidate that fails steps 2 or 3 is skipped with its closed reason and dropped with its
//! handle; nothing is committed for it. A failure after the commit is the section 4.7
//! invariant fault: the boundary latches it and refuses every later transaction, and a restart
//! recomposes from the fold ([`compose_restart_v1`]), which also runs the restart activation
//! of trigger code 1.
//!
//! Owner actions ([`CompositionBoundaryV1::owner_activate_v1`]) need the host-native grant
//! [`COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1`]. A candidate needs a current eligible
//! observation whose code the entry declares; the primary is the bounded return, which needs
//! no observation and re-runs the trust gate. Observations live in memory and are lost on
//! restart (#560). The CBT never issues a pass.

use std::collections::BTreeMap;

use pos_core::store::EventStore;
use pos_core::{
    FallbackSkipReasonV1, FallbackSkippedCandidateV1, FallbackTriggerCodeV1, Hash,
    ImplementationKeyV1, PluginId,
};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1};
use pos_runtime::community_plugin_host::{
    CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, PluginTrustMaterialSourceV1,
};
use pos_runtime::{
    FallbackCandidateFactsV1, FallbackHostFactsV1, FallbackTriggerCauseV1, PluginRegistry,
    RequiredPluginCompositionV1,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, CompositionFallbackRegistryV1, CompositionFallbackTargetV1,
    FallbackLedgerRowV1,
};

use crate::adapter::CommunityDriverSettingsV1;

mod boundary;
mod candidate;
mod derive;
mod restart;
mod trigger;

pub use derive::{
    effective_composition_v1, FallbackEffectiveCompositionV1, FallbackEffectiveEntryV1,
};
pub use restart::{compose_restart_v1, FallbackRestartSlotV1, FallbackRestartV1};
pub use trigger::fallback_trigger_cause_v1;

/// The host-native grant that authorizes an owner activation (ADR-119 section 4.3).
pub const COMPOSITION_FALLBACK_ACTIVATE_GRANT_V1: &str = "composition.fallback.activate";

/// A store that hosts both the Event store and the composition fallback registry on one
/// connection (ADR-119 section 4.3).
pub trait FallbackBoundaryStoreV1: EventStore + CompositionFallbackRegistryV1 {}

impl<T: EventStore + CompositionFallbackRegistryV1 + ?Sized> FallbackBoundaryStoreV1 for T {}

/// Everything the trusted host supplies to build one implementation's Driver and host member.
///
/// The release source and address are the ones ADR-061 revision 7 decisions 11 and 16 require
/// for every Plugin; the composition fallback registry keeps only digests.
pub struct FallbackCandidateInputV1 {
    /// The Plugin object of the implementation; its ID is a fresh run-local ID.
    pub plugin: Box<dyn pos_core::Plugin>,
    /// The source of the release closure.
    pub source: Box<dyn ReleaseSourceV1>,
    /// The address of the release closure in `source`.
    pub address: BundleAddressV1,
    /// The source of the operator-pinned anchors and signed records.
    pub material: Box<dyn PluginTrustMaterialSourceV1>,
    /// The Driver settings; `settings.plugin_id` must be the Plugin's ID.
    pub settings: CommunityDriverSettingsV1,
    /// The host ABI the Driver negotiates against.
    pub host_abi: CommunityPluginHostAbiV1,
    /// The host execution profile the Driver negotiates under.
    pub profile: CommunityPluginExecutionProfileV1,
    /// The host's publisher facts of the release (rule 2). The boundary sets the admitted
    /// release digest from the gate and keeps the frozen conformance set (rule 7 is not
    /// re-checked at the boundary).
    pub host: FallbackHostFactsV1,
}

/// What re-verification compares one entry's candidates against: the effective required
/// composition and the facts of the entry's declared primary, as the declaration used them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackReferenceV1 {
    /// The effective required composition, which holds the primary's derived requirement.
    pub composition: RequiredPluginCompositionV1,
    /// The facts of the entry's declared primary.
    pub primary: FallbackCandidateFactsV1,
}

/// The trusted host's supply of releases and reference facts (ADR-119 section 4.4 step 2).
pub trait FallbackReleaseSupplyV1 {
    /// The inputs that build `key`'s implementation for `entry_key`, or `None` when its release
    /// source is missing or unreadable (`SourceUnavailable`).
    fn candidate(
        &mut self,
        entry_key: &str,
        key: &ImplementationKeyV1,
    ) -> Option<FallbackCandidateInputV1>;

    /// The reference facts of `entry_key`, or `None` when the host has none
    /// (`FactsMismatch`).
    fn reference(&self, entry_key: &str) -> Option<FallbackReferenceV1>;
}

/// What one boundary transaction borrows: the registry, the store, the trust registry, the
/// trusted wall clock, the host's supply, and the Tick of the boundary.
pub struct FallbackBoundaryContextV1<'a, S: ?Sized, T: ?Sized, W> {
    /// The live registry.
    pub registry: &'a mut PluginRegistry,
    /// The Event store and composition fallback registry.
    pub store: &'a mut S,
    /// The Plugin trust policy registry the gate evaluates releases against.
    pub trust: &'a T,
    /// The trusted wall clock the gate samples one UTC second from.
    pub wall: &'a mut W,
    /// The trusted host's supply.
    pub supply: &'a mut dyn FallbackReleaseSupplyV1,
    /// The Tick of the boundary, recorded in the activation's ledger row.
    pub tick: u64,
}

/// A failure of one boundary transaction (ADR-119 sections 4.3, 4.4 and 4.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FallbackBoundaryErrorV1 {
    /// An earlier invariant fault latched: the host must restart.
    #[error("the composition boundary has faulted; the host must restart")]
    Faulted,
    /// The live registry differs from the effective composition, or a step after the commit
    /// failed (ADR-119 section 4.7). The boundary latches it.
    #[error("composition boundary invariant fault: {0}")]
    InvariantFault(&'static str),
    /// The composition fallback registry refused a read.
    #[error("composition fallback registry refused: {0}")]
    Registry(CompositionFallbackRegistryErrorV1),
    /// The principal does not hold `composition.fallback.activate`.
    #[error("the principal does not hold composition.fallback.activate")]
    NotGranted,
    /// The entry is not in the current policy.
    #[error("the entry is not in the current fallback policy")]
    UnknownEntry,
    /// The owner named no other implementation listed for the entry.
    #[error("the owner activation target is not another listed implementation")]
    InvalidTarget,
    /// A candidate activation without a current eligible observation of the effective
    /// implementation.
    #[error("no current eligible observation for the entry")]
    NoObservation,
    /// The observed trigger code is not one of the entry's declared triggers.
    #[error("the observed trigger code is not declared for the entry")]
    TriggerNotDeclared,
    /// A restart could not compose a slot: its effective implementation fails with this
    /// reason and no candidate replaces it.
    #[error("a restart slot cannot be composed: {0:?}")]
    SlotUnavailable(FallbackSkipReasonV1),
}

/// What one boundary transaction did for one entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackEntryOutcomeV1 {
    /// The activation committed; the entry now runs `to`.
    Activated {
        /// The DFP1 entry key.
        entry_key: String,
        /// The implementation the new tenure runs.
        to: ImplementationKeyV1,
        /// The candidates skipped before `to`.
        skipped: Vec<FallbackSkippedCandidateV1>,
        /// The ledger row of the activation.
        row: Box<FallbackLedgerRowV1>,
    },
    /// A manual entry recorded the observation and waits for its owner.
    AwaitingOwner {
        /// The DFP1 entry key.
        entry_key: String,
        /// The observed trigger code.
        code: FallbackTriggerCodeV1,
    },
    /// No candidate validated, or none is left on the chain: nothing was committed.
    Exhausted {
        /// The DFP1 entry key.
        entry_key: String,
        /// Every candidate tried, with its closed reason.
        skipped: Vec<FallbackSkippedCandidateV1>,
    },
    /// The registry refused the commit: nothing changed, and the old composition stays in
    /// force.
    NotCommitted {
        /// The DFP1 entry key.
        entry_key: String,
        /// The registry's refusal.
        error: CompositionFallbackRegistryErrorV1,
    },
}

/// One eligible observation held for an owner action (in memory only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservationV1 {
    /// The IMK1 digest of the implementation that failed.
    effective: Hash,
    /// The closed cause.
    cause: FallbackTriggerCauseV1,
    /// The eligible trigger code of the cause.
    code: FallbackTriggerCodeV1,
}

/// The live composition boundary of one `(scope, timeline)`.
///
/// It holds which run-local Plugin each declared entry key runs, the eligible observations
/// for owner actions, and the latched invariant fault. It lives in memory: a restart builds it
/// again with [`compose_restart_v1`] or [`Self::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionBoundaryV1 {
    scope: String,
    target: CompositionFallbackTargetV1,
    bindings: BTreeMap<String, PluginId>,
    observations: BTreeMap<String, ObservationV1>,
    faulted: bool,
}

impl CompositionBoundaryV1 {
    /// The boundary of `scope` on `target`, whose entry keys run the Plugins of `bindings`.
    ///
    /// `target.timeline` must be the Timeline the community passes step (ADR-119 section 4.3).
    #[must_use]
    pub const fn new(
        scope: String,
        target: CompositionFallbackTargetV1,
        bindings: BTreeMap<String, PluginId>,
    ) -> Self {
        Self {
            scope,
            target,
            bindings,
            observations: BTreeMap::new(),
            faulted: false,
        }
    }

    /// The run-local Plugin `entry_key` runs, if the boundary binds it.
    #[must_use]
    pub fn binding(&self, entry_key: &str) -> Option<PluginId> {
        self.bindings.get(entry_key).copied()
    }

    /// The trigger code of the observation held for `entry_key`, if any.
    #[must_use]
    pub fn observation(&self, entry_key: &str) -> Option<FallbackTriggerCodeV1> {
        self.observations
            .get(entry_key)
            .map(|observed| observed.code)
    }

    /// Whether an invariant fault latched.
    #[must_use]
    pub const fn is_faulted(&self) -> bool {
        self.faulted
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
