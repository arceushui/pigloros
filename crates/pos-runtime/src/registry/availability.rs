//! Host-observed Plugin availability at pass time (ADR-061, #543).
//!
//! The host records a quarantine or revocation of a registered, pinned Plugin
//! through [`PluginRegistry::set_availability`]. A scheduled pass then refuses
//! to step a Driver whose recorded availability is anything but
//! [`PluginAvailabilityV1::Available`], before any Driver runs and before any
//! state is staged. The availability is in-memory registry state: it is lost
//! on restart, and setting it fabricates no Event.
//!
//! Registration and composition resolution are unchanged. A Plugin registered
//! without a pin has no availability and is never refused here.

use pos_core::PluginId;

use super::{AnchoredSelection, AnchoredSelectionResult, PluginRegistry};
use crate::composition::{PluginAvailabilityV1, PluginCompositionErrorV1, PluginRegistrationV1};
use crate::error::RuntimeError;

impl PluginRegistry {
    /// Set the host-observed availability of a registered, pinned Plugin.
    ///
    /// The pin is kept. The availability is in memory only. A pass that would
    /// step the Plugin's Driver fails with
    /// [`PluginCompositionErrorV1::ImplementationUnavailable`] until the host
    /// sets [`PluginAvailabilityV1::Available`] again.
    ///
    /// # Errors
    /// Returns [`PluginCompositionErrorV1::MissingImplementation`] for an
    /// unregistered Plugin and [`PluginCompositionErrorV1::UnpinnedImplementation`]
    /// for one registered without a pin, both as [`RuntimeError::Composition`].
    pub fn set_availability(
        &mut self,
        plugin_id: PluginId,
        availability: PluginAvailabilityV1,
    ) -> Result<(), RuntimeError> {
        let entry = self
            .plugins
            .get_mut(&plugin_id)
            .ok_or(PluginCompositionErrorV1::MissingImplementation { plugin_id })?;
        let registration = entry
            .registration
            .as_mut()
            .ok_or(PluginCompositionErrorV1::UnpinnedImplementation { plugin_id })?;
        *registration = PluginRegistrationV1::new(registration.pin().clone(), availability);
        Ok(())
    }

    /// The recorded availability of a pinned Plugin, or `None` when the Plugin
    /// is unregistered or has no pin.
    #[must_use]
    pub fn availability(&self, plugin_id: PluginId) -> Option<PluginAvailabilityV1> {
        self.plugins
            .get(&plugin_id)
            .and_then(|entry| entry.registration.as_ref())
            .map(PluginRegistrationV1::availability)
    }

    /// The Drivers a pass selects, refused when any is not available.
    pub(super) fn collect_available_selection(
        &self,
        selection: AnchoredSelection,
    ) -> Result<AnchoredSelectionResult, RuntimeError> {
        self.collect_anchored_selection(selection)
            .and_then(|selected| {
                self.ensure_selected_available(&selected.0)
                    .map(|()| selected)
            })
    }

    fn ensure_selected_available(&self, driver_ids: &[PluginId]) -> Result<(), RuntimeError> {
        driver_ids
            .iter()
            .try_for_each(|plugin_id| self.ensure_available(*plugin_id))
    }

    fn ensure_available(&self, plugin_id: PluginId) -> Result<(), RuntimeError> {
        match self.availability(plugin_id) {
            Some(availability) if availability != PluginAvailabilityV1::Available => {
                Err(PluginCompositionErrorV1::ImplementationUnavailable {
                    plugin_id,
                    availability,
                }
                .into())
            }
            _ => Ok(()),
        }
    }
}
