//! The ADR-119 facts-only community registration path (section 4.1,
//! "Validation input").
//!
//! A candidate is registered in a scratch registry of its own, never next to
//! the primary in the live registry, behind a [`FallbackDriverShellV1`]: the
//! registry runs its ordinary registration checks and captures the Driver's
//! observation, and no handle or worker exists. The facts are then read back
//! from the registered entry.

use pos_core::output_policy::OutputDeclarationV1;
use pos_core::{CompositionPinV1, Kind, Plugin, PluginId};

use super::{PluginEntry, PluginRegistry};
use crate::composition_fallback::{
    FallbackDriverSettingsV1, FallbackDriverShellV1, FallbackRegistryFactsV1,
};
use crate::{
    community_pin_v1, Driver, OutputAdmissionV1, PluginAvailabilityV1, PluginPinV1,
    PluginRegistrationV1, ProjectionKey, RuntimeError, ScheduledDriverBindingV1,
};

impl PluginRegistry {
    /// Register `plugin` facts-only in a fresh scratch registry and return
    /// its facts.
    ///
    /// The pin is the community pin derived from `pin`'s IMK1 release digest
    /// and roles; the Driver is a [`FallbackDriverShellV1`] over `settings`,
    /// assigned the non-participant profile as `register_community_driver`
    /// assigns it. The scratch registry, and so the shell, is dropped before
    /// this returns, so the shell is never stepped.
    ///
    /// # Errors
    /// Returns the pin's closed metadata error, then the registry's ordinary
    /// registration and profile-composition errors.
    pub fn fallback_scratch_facts_v1(
        plugin: &dyn Plugin,
        pin: &CompositionPinV1,
        settings: FallbackDriverSettingsV1,
    ) -> Result<FallbackRegistryFactsV1, RuntimeError> {
        let key = pin.implementation();
        let mut scratch = Self::new();
        community_pin_v1(key.release_digest(), pin.roles().to_vec())
            .map_err(RuntimeError::from)
            .and_then(|community| scratch.register_fallback_shell(plugin, community, settings))
            .and_then(|()| scratch.fallback_registry_facts_v1(plugin.id()))
    }

    /// Register `plugin` behind a facts-only shell, non-participant.
    fn register_fallback_shell(
        &mut self,
        plugin: &dyn Plugin,
        pin: PluginPinV1,
        settings: FallbackDriverSettingsV1,
    ) -> Result<(), RuntimeError> {
        let shell = FallbackDriverShellV1::new(plugin.name(), settings);
        let driver: Box<dyn Driver> = Box::new(shell);
        let registration = PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available);
        let binding = [(plugin.id(), ScheduledDriverBindingV1::NonParticipant)];
        Self::register_pinned_generated(self, plugin, registration, None, Some(driver))
            .and_then(|()| self.compose_scheduled_profiles(&binding))
    }

    /// The ADR-119 facts this registry holds for one registered Plugin.
    ///
    /// The live registry answers this for the primary; the scratch registry
    /// of [`Self::fallback_scratch_facts_v1`] answers it for a candidate.
    ///
    /// # Errors
    /// Returns [`RuntimeError::NoDriver`] when `plugin_id` is not registered.
    pub fn fallback_registry_facts_v1(
        &self,
        plugin_id: PluginId,
    ) -> Result<FallbackRegistryFactsV1, RuntimeError> {
        self.plugins
            .get(&plugin_id)
            .map(|entry| self.entry_facts(plugin_id, entry))
            .ok_or_else(|| RuntimeError::NoDriver {
                name: plugin_id.to_string(),
            })
    }

    fn entry_facts(&self, plugin_id: PluginId, entry: &PluginEntry) -> FallbackRegistryFactsV1 {
        let owned_event_types = sorted_types(&entry.owned_event_types);
        let schemas = self.owned_schemas(&owned_event_types);
        let admission = entry.output_admission.as_ref();
        let driver = entry.driver.as_deref();
        FallbackRegistryFactsV1 {
            plugin_id,
            version: entry.version.clone(),
            pin: entry.registration.as_ref().map(registered_pin),
            owned_event_types,
            schemas,
            outputs: admission.map_or_else(Vec::new, output_declarations),
            cpu_reservations_us: cpu_reservations(plugin_id, admission),
            subscriptions: driver_subscriptions(driver),
            event_subscriptions: entry.event_observation.event_subscriptions.clone(),
            driver_interval: driver.map(Driver::tick_interval),
            binding: self.scheduled_binding(plugin_id),
        }
    }

    /// The registered JSON schema of each type, in the order given.
    fn owned_schemas(&self, owned_event_types: &[String]) -> Vec<Option<String>> {
        owned_event_types
            .iter()
            .map(|event_type| self.schema_of(event_type))
            .collect()
    }

    fn schema_of(&self, event_type: &str) -> Option<String> {
        self.schemas
            .iter()
            .find(|schema| schema.event_type.as_str() == event_type)
            .and_then(|schema| schema.json_schema.clone())
    }
}

fn sorted_types(owned_event_types: &[Kind]) -> Vec<String> {
    let mut types: Vec<String> = owned_event_types
        .iter()
        .map(|kind| kind.as_str().to_owned())
        .collect();
    types.sort();
    types
}

fn registered_pin(registration: &PluginRegistrationV1) -> PluginPinV1 {
    registration.pin().clone()
}

fn output_declarations(admission: &OutputAdmissionV1) -> Vec<OutputDeclarationV1> {
    admission.policy().fields().output_declarations.clone()
}

/// The subscriptions of the entry's Driver, if it has one.
fn driver_subscriptions(d: Option<&dyn Driver>) -> Vec<ProjectionKey> {
    d.map_or_else(Vec::new, |d| d.subscriptions().to_vec())
}

/// The per-fidelity CPU reservations the admitted budget holds for the Plugin.
fn cpu_reservations(
    plugin_id: PluginId,
    admission: Option<&OutputAdmissionV1>,
) -> Option<[u32; 3]> {
    admission?
        .budget()
        .fields()
        .plugin_cpu_reservations
        .iter()
        .find(|reservation| reservation.plugin_id == plugin_id)
        .map(|reservation| reservation.cpu_reservations_us)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "fallback_facts_tests.rs"]
mod tests;
