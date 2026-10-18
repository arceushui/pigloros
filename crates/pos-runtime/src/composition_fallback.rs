//! ADR-119 explicit domain fallback: candidate facts, validation and triggers.
//!
//! This module holds the `pos-runtime` seams of ADR-119 section 7 slice 3:
//!
//! - the facts-only community registration path. It registers a candidate in
//!   a scratch [`PluginRegistry`] behind a [`FallbackDriverShellV1`], a stub
//!   Driver that is never stepped, so no handle and no worker exist
//!   (section 4.1, "Validation input");
//! - the derivation and enforcement of [`RequiredPluginV1`] from IMK1;
//! - the scratch validation of a candidate against the primary, rules 1-7;
//! - the trigger-eligibility classifier of section 4.2;
//! - the runtime `declare` of section 4.3 (slice 4).
//!
//! It activates and swaps nothing: those are later slices.

use std::collections::BTreeSet;
use std::time::Duration;

use pos_core::event::Kind;
use pos_core::ids::{PluginId, TimelineId};
use pos_core::output_policy::OutputDeclarationV1;
use pos_core::plugin::Plugin;
use pos_core::{CompositionPinV1, Hash};
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginCapabilityDescriptorV1, PluginExecutionProjectionV1,
};

use crate::driver::{Driver, ObservationView, ProjectionKey, StepOutput};
use crate::{
    community_pin_v1, PluginCompositionErrorV1, PluginPinV1, PluginRegistry, RequiredPluginV1,
    RuntimeError, ScheduledDriverBindingV1,
};

mod declaration;
mod trigger;
mod validation;

pub use declaration::{
    declare_composition_fallback_v1, FallbackDeclarationV1, FallbackDeclareErrorV1,
    FallbackEntryFactsV1, FallbackHostGrantsV1, COMPOSITION_FALLBACK_DECLARE_GRANT_V1,
};
pub use trigger::{
    classify_fallback_trigger_v1, declared_fallback_trigger_v1, FallbackTriggerCauseV1,
};
pub use validation::validate_fallback_candidate_v1;

/// The host-supplied Driver values of one community implementation.
///
/// It has the shape of the supervisor's `CommunityDriverSettingsV1` fields
/// `tick_interval` and `subscriptions`. `pos-runtime` cannot name that type,
/// so the supervisor passes the same plain values in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackDriverSettingsV1 {
    /// Minimum interval between ticks (`driver_interval`).
    pub tick_interval: Duration,
    /// The projection states the Driver observes.
    pub subscriptions: Vec<ProjectionKey>,
}

/// The stub Driver shell of the facts-only registration path.
///
/// It is a `CommunityDriverV1`-shaped Driver owned by `pos-runtime`, with no
/// handle and no worker. It answers the registry's registration-time
/// questions from the host-supplied settings and is never stepped: a step is
/// refused.
#[derive(Debug)]
pub struct FallbackDriverShellV1 {
    name: &'static str,
    settings: FallbackDriverSettingsV1,
}

impl FallbackDriverShellV1 {
    /// A shell for the Plugin named `name`.
    #[must_use]
    pub const fn new(name: &'static str, settings: FallbackDriverSettingsV1) -> Self {
        Self { name, settings }
    }
}

impl Driver for FallbackDriverShellV1 {
    /// Refuse: the shell exists only to register facts.
    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Err(RuntimeError::CapabilityMismatch {
            name: self.name.to_owned(),
            reason: "an ADR-119 facts-only Driver shell is never stepped".to_owned(),
        })
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn tick_interval(&self) -> Duration {
        self.settings.tick_interval
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.settings.subscriptions
    }
}

/// What a registry holds for one registered implementation (ADR-119 section
/// 4.1, "Validation input").
///
/// Only a registry builds it: through the facts-only path for a candidate, or
/// from the live registry for the primary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackRegistryFactsV1 {
    pub(crate) plugin_id: PluginId,
    pub(crate) version: String,
    pub(crate) pin: Option<PluginPinV1>,
    pub(crate) owned_event_types: Vec<String>,
    pub(crate) schemas: Vec<Option<String>>,
    pub(crate) outputs: Vec<OutputDeclarationV1>,
    pub(crate) cpu_reservations_us: Option<[u32; 3]>,
    pub(crate) subscriptions: Vec<ProjectionKey>,
    pub(crate) event_subscriptions: Vec<Kind>,
    pub(crate) driver_interval: Option<Duration>,
    pub(crate) binding: Option<ScheduledDriverBindingV1>,
}

impl FallbackRegistryFactsV1 {
    /// The run-local Plugin ID of the registered implementation.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }
}

/// The PMF1 execution facts of one release: capability descriptors and the
/// deterministic budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackExecutionFactsV1 {
    /// The PMF1 Plugin ID text.
    pub plugin_id: String,
    /// The PMF1 release digest.
    pub release_digest: Hash,
    /// Every capability descriptor, PMF1 field 14.
    pub capabilities: Vec<PluginCapabilityDescriptorV1>,
    /// The declared deterministic budget, PMF1 field 15.
    pub budget: DeterministicBudgetV1,
}

impl FallbackExecutionFactsV1 {
    /// The facts of one validated PMF1 execution projection.
    #[must_use]
    pub fn from_projection(projection: &PluginExecutionProjectionV1) -> Self {
        Self {
            plugin_id: projection.plugin_id().to_owned(),
            release_digest: Hash::from_bytes(projection.release_digest()),
            capabilities: projection.capabilities().to_vec(),
            budget: projection.budget(),
        }
    }
}

/// What the trusted host supplies about one release at declaration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackHostFactsV1 {
    /// The release digest of the trust registry's active pointer for the
    /// release's Plugin ID, if one is active (rule 6).
    pub active_release_digest: Option<Hash>,
    /// The release's publisher identity, as the trusted host attributes it
    /// from the signed release (rule 2). `None` when the host cannot
    /// attribute it: such a candidate is treated as cross-publisher.
    pub publisher: Option<String>,
    /// The Event-type namespaces granted to the release's publisher at
    /// install (rule 2). Each grant covers the types `<namespace>.<rest>`;
    /// a cross-publisher candidate needs a grant for every owned type.
    pub namespace_grants: Vec<String>,
    /// The `ConformanceProfile` digests (CNR1 field 4) of passing reports on
    /// Stable-lifecycle profiles whose subject is the release (rule 7).
    pub conformance_profiles: BTreeSet<Hash>,
}

/// Every fact ADR-119 rules 1-7 compare for one implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackCandidateFactsV1 {
    /// The implementation's declared PPN1.
    pub pin: CompositionPinV1,
    /// What a registry holds for it.
    pub registry: FallbackRegistryFactsV1,
    /// Its PMF1 execution facts.
    pub execution: FallbackExecutionFactsV1,
    /// What the trusted host supplies about it.
    pub host: FallbackHostFactsV1,
}

impl FallbackCandidateFactsV1 {
    /// Collect a candidate's facts through the facts-only registration path.
    ///
    /// # Errors
    /// Returns the error of [`PluginRegistry::fallback_scratch_facts_v1`].
    pub fn collect(
        plugin: &dyn Plugin,
        pin: CompositionPinV1,
        settings: FallbackDriverSettingsV1,
        execution: FallbackExecutionFactsV1,
        host: FallbackHostFactsV1,
    ) -> Result<Self, RuntimeError> {
        let registry = PluginRegistry::fallback_scratch_facts_v1(plugin, &pin, settings)?;
        Ok(Self {
            pin,
            registry,
            execution,
            host,
        })
    }
}

/// The ADR-119 section 4.1 rule a fallback entry breaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackValidationFieldV1 {
    /// Rule 1: the PMF1 Plugin ID or release digest differs from the PPN1's IMK1.
    Identity,
    /// Rule 1: the candidate's roles differ from the primary's.
    Roles,
    /// Rule 1: the primary and the candidate share a Plugin ID text or a run-local Plugin ID.
    Distinctness,
    /// `Plugin::version()` differs from the IMK1 `version_text`.
    Version,
    /// The registered pin's `configuration_digest` differs from the IMK1 release digest.
    ConfigurationDigest,
    /// Rule 1: the effective composition with the candidate fails `try_new`, or the
    /// primary's derived requirement is not in the composition.
    Composition,
    /// Rule 2: the owned Event types differ.
    EventTypes,
    /// Rule 2: an owned type's schema differs.
    Schemas,
    /// Rule 2: an EOP1 authority or fidelity differs, or `max_bytes` exceeds the primary's.
    OutputPolicy,
    /// Rule 2: a cross-publisher candidate lacks a namespace grant for an owned type.
    Namespace,
    /// Rule 3: a capability descriptor is not the primary's.
    Capabilities,
    /// Rule 3: a projection or Event subscription is not the primary's.
    Subscriptions,
    /// Rule 4: a PMF1 limit or CPU reservation exceeds the primary's.
    Budgets,
    /// Rule 5: the observation profile is not the primary's non-participant one.
    Profile,
    /// Rule 5: the `driver_interval` differs.
    DriverInterval,
    /// Rule 6: the candidate release is not the active admitted release.
    Admission,
    /// Rule 7: a primary conformance profile digest is missing from the candidate's set.
    Conformance,
}

/// ADR-119 `InvalidFallbackPolicy{entry, field}`.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid fallback policy entry '{entry_key}': {field:?}")]
pub struct InvalidFallbackPolicyV1 {
    /// The DFP1 entry key.
    pub entry_key: String,
    /// The rule the entry breaks.
    pub field: FallbackValidationFieldV1,
}

/// The `RequiredPluginV1` of one community entry (ADR-119 section 4.1).
///
/// Its version is the IMK1 host-supplied `version_text` and its pin is
/// `(Plugin, GovernedCommunity, configuration_digest = release_digest, roles)`.
///
/// # Errors
/// Returns the closed metadata error of the pin or the requirement.
pub fn required_plugin_v1(
    plugin_id: PluginId,
    pin: &CompositionPinV1,
) -> Result<RequiredPluginV1, PluginCompositionErrorV1> {
    let key = pin.implementation();
    community_pin_v1(key.release_digest(), pin.roles().to_vec())
        .and_then(|community| RequiredPluginV1::try_new(plugin_id, key.version(), community))
}

/// Enforce the IMK1 binding of one registered implementation.
///
/// `Plugin::version()` must equal the `version_text` label, and the
/// registered pin's `configuration_digest` must equal the release digest.
///
/// # Errors
/// Returns [`FallbackValidationFieldV1::Version`] or
/// [`FallbackValidationFieldV1::ConfigurationDigest`].
pub fn enforce_required_plugin_v1(
    registered_version: &str,
    registered_pin: Option<&PluginPinV1>,
    pin: &CompositionPinV1,
) -> Result<(), FallbackValidationFieldV1> {
    use FallbackValidationFieldV1 as Field;
    let key = pin.implementation();
    let digest = registered_pin.map(PluginPinV1::configuration_digest);
    let mismatch = digest != Some(key.release_digest());
    let field = if registered_version == key.version() {
        mismatch.then_some(Field::ConfigurationDigest)
    } else {
        Some(Field::Version)
    };
    field.map_or(Ok(()), Err)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
