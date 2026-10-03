//! ADR-021 Revision 3 composition-time scheduled observation profiles (#504).
//!
//! The host fixes each scheduled Driver's observation profile when it
//! composes the registry. The profile comes only from the Driver's ADR-059
//! Participant binding: a Driver bound to a Participant is participant-bound,
//! and any other Driver is non-participant only when the host explicitly
//! assigns it that profile. Pass contents, Driver output, Plugin
//! self-description, subscriptions and provider responses never assign one.
//!
//! Every scheduled staging path requires the whole composition to carry the
//! path's profile before any Driver runs. The anchored paths
//! (`step_all_anchored*` and `tick_cadenced_anchored*`) require
//! non-participant Drivers. [`PluginRegistry::stage_authorized_scheduled_pass`]
//! requires participant-bound Drivers, and each one may observe only its own
//! Participant's view. An unassigned Driver, or a Driver of the other profile,
//! is rejected before staging, so the pass stages and commits nothing. The
//! unanchored `step_all` and `tick_cadenced` paths reject a participant-bound
//! Driver. One composition never mixes the two profiles, because mixed passes
//! are prohibited until an accepted decision defines them.
//! [`RuntimeError::AuthorityFenceRequired`] stays as defense in depth.

use std::collections::HashMap;

use pos_core::{EntityId, ObservationSnapshotV1, PluginId, ScheduledObservationProfileV1};
use thiserror::Error;

use super::{unauthorized, AuthorizedDriverViewV1, PluginEntry, PluginRegistry};
use crate::error::RuntimeError;

/// The host's composition-time binding of one scheduled Driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduledDriverBindingV1 {
    /// The Driver is bound to this ADR-059 Participant. Only the planned
    /// Wave 9 Scenario Room host composes one in production; test hosts
    /// compose one at the runtime seam.
    Participant(EntityId),
    /// The host explicitly assigns the Driver the non-participant profile.
    NonParticipant,
}

impl ScheduledDriverBindingV1 {
    /// The scheduled observation profile this binding fixes.
    #[must_use]
    pub const fn profile(self) -> ScheduledObservationProfileV1 {
        match self {
            Self::Participant(_) => ScheduledObservationProfileV1::ParticipantBound,
            Self::NonParticipant => ScheduledObservationProfileV1::NonParticipant,
        }
    }
}

/// Closed failures of composition-time profile assignment.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ScheduledProfileErrorV1 {
    /// A registered Driver has no observation profile assignment.
    #[error("scheduled Driver '{driver}' has no observation profile assignment")]
    UnassignedDriver { driver: String },
    /// A binding names a Plugin that is not a registered Driver.
    #[error("plugin {plugin_id} is not a registered scheduled Driver")]
    NotADriver { plugin_id: PluginId },
    /// A Driver is bound twice; its profile is fixed once.
    #[error("scheduled Driver '{driver}' already has an observation profile")]
    AlreadyAssigned { driver: String },
    /// One composition would hold both observation profiles.
    #[error("one composition cannot mix participant-bound and non-participant Drivers")]
    MixedProfiles,
    /// A Driver is offered to a path of the other observation profile.
    #[error("scheduled Driver '{driver}' is not composed for the {required:?} profile")]
    ProfileMismatch {
        driver: String,
        required: ScheduledObservationProfileV1,
    },
}

/// Assigned bindings, keyed by Driver Plugin.
pub(super) type ScheduledBindings = HashMap<PluginId, ScheduledDriverBindingV1>;

impl PluginRegistry {
    /// Fix scheduled observation profiles from the host's composition bindings.
    ///
    /// Each binding assigns one registered Driver exactly one profile.
    /// Together with earlier assignments, the bindings must cover every
    /// registered Driver, and every Driver must share one profile. Nothing is
    /// assigned on error.
    ///
    /// # Errors
    /// Returns [`RuntimeError::ScheduledProfile`] for a binding of an
    /// unregistered or Driverless Plugin, a Driver bound twice, an unassigned
    /// Driver, or a composition that mixes both profiles.
    pub fn compose_scheduled_profiles(
        &mut self,
        bindings: &[(PluginId, ScheduledDriverBindingV1)],
    ) -> Result<(), RuntimeError> {
        let composed = self.composed_bindings(bindings)?;
        self.scheduled_profiles = composed;
        Ok(())
    }

    /// Compose every Driver of a host without Participants as non-participant.
    ///
    /// The host explicitly assigns each still-unassigned Driver the
    /// non-participant profile, then requires the whole composition to be
    /// non-participant. Experiment sessions and backtests compose their
    /// Drivers this way.
    ///
    /// # Errors
    /// Returns [`RuntimeError::ScheduledProfile`] when any Driver is
    /// participant-bound.
    pub fn compose_non_participant_drivers(&mut self) -> Result<(), RuntimeError> {
        let unassigned = self.unassigned_as_non_participant();
        self.compose_scheduled_profiles(&unassigned)?;
        self.require_scheduled_profile(ScheduledObservationProfileV1::NonParticipant)
    }

    /// The fixed binding of a registered Driver, if the host assigned one.
    #[must_use]
    pub fn scheduled_binding(&self, plugin_id: PluginId) -> Option<ScheduledDriverBindingV1> {
        self.scheduled_profiles.get(&plugin_id).copied()
    }

    /// Require every registered Driver to be assigned `required` before a
    /// pass of that profile stages anything.
    pub(super) fn require_scheduled_profile(
        &self,
        required: ScheduledObservationProfileV1,
    ) -> Result<(), RuntimeError> {
        self.drivers()
            .try_for_each(|(plugin_id, entry)| match self.profile_of(*plugin_id) {
                Some(profile) if profile == required => Ok(()),
                Some(_) => Err(ScheduledProfileErrorV1::ProfileMismatch {
                    driver: entry.name.clone(),
                    required,
                }),
                None => Err(ScheduledProfileErrorV1::UnassignedDriver {
                    driver: entry.name.clone(),
                }),
            })
            .map_err(RuntimeError::ScheduledProfile)
    }

    /// Reject a participant-bound Driver before an unanchored step, which
    /// would invoke it outside its authorized view.
    pub(super) fn reject_participant_bound_drivers(&self) -> Result<(), RuntimeError> {
        let participant = Some(ScheduledObservationProfileV1::ParticipantBound);
        self.drivers()
            .find(|(plugin_id, _)| self.profile_of(**plugin_id) == participant)
            .map_or(Ok(()), |(_, entry)| {
                let error = ScheduledProfileErrorV1::ProfileMismatch {
                    driver: entry.name.clone(),
                    required: ScheduledObservationProfileV1::NonParticipant,
                };
                Err(RuntimeError::ScheduledProfile(error))
            })
    }

    /// Require each released view to be its own Driver's bound Participant's
    /// view.
    pub(super) fn require_bound_participants(
        &self,
        views: &[AuthorizedDriverViewV1],
        snapshots: &[ObservationSnapshotV1],
    ) -> Result<(), RuntimeError> {
        let bound = views.iter().zip(snapshots).all(|(view, snapshot)| {
            self.scheduled_binding(view.plugin_id)
                == Some(ScheduledDriverBindingV1::Participant(snapshot.participant_id()))
        });
        if bound {
            Ok(())
        } else {
            Err(unauthorized())
        }
    }

    fn profile_of(&self, plugin_id: PluginId) -> Option<ScheduledObservationProfileV1> {
        self.scheduled_binding(plugin_id)
            .map(ScheduledDriverBindingV1::profile)
    }

    /// Every registered Plugin that has a Driver, in registration order.
    fn drivers(&self) -> impl Iterator<Item = (&PluginId, &PluginEntry)> {
        self.plugins
            .iter()
            .filter(|(_, entry)| entry.driver.is_some())
    }

    /// A non-participant binding for every still-unassigned Driver.
    fn unassigned_as_non_participant(&self) -> Vec<(PluginId, ScheduledDriverBindingV1)> {
        self.drivers()
            .filter(|(plugin_id, _)| self.profile_of(**plugin_id).is_none())
            .map(|(plugin_id, _)| (*plugin_id, ScheduledDriverBindingV1::NonParticipant))
            .collect()
    }

    /// The current assignments extended by `bindings`, once they are complete
    /// and single-profile.
    fn composed_bindings(
        &self,
        bindings: &[(PluginId, ScheduledDriverBindingV1)],
    ) -> Result<ScheduledBindings, ScheduledProfileErrorV1> {
        let mut composed = self.scheduled_profiles.clone();
        for (plugin_id, binding) in bindings {
            let driver = self.driver_name(*plugin_id)?;
            if composed.insert(*plugin_id, *binding).is_some() {
                return Err(ScheduledProfileErrorV1::AlreadyAssigned { driver });
            }
        }
        self.require_assigned(&composed)
            .and_then(|()| single_profile(&composed))
            .map(|()| composed)
    }

    /// The name of the registered Driver of `plugin_id`.
    fn driver_name(&self, plugin_id: PluginId) -> Result<String, ScheduledProfileErrorV1> {
        self.plugins
            .get(&plugin_id)
            .filter(|entry| entry.driver.is_some())
            .map(|entry| entry.name.clone())
            .ok_or(ScheduledProfileErrorV1::NotADriver { plugin_id })
    }

    /// Require every registered Driver to have an assignment in `composed`.
    fn require_assigned(
        &self,
        composed: &ScheduledBindings,
    ) -> Result<(), ScheduledProfileErrorV1> {
        self.drivers()
            .find(|(plugin_id, _)| !composed.contains_key(*plugin_id))
            .map_or(Ok(()), |(_, entry)| {
                Err(ScheduledProfileErrorV1::UnassignedDriver {
                    driver: entry.name.clone(),
                })
            })
    }
}

/// Require every assignment in `composed` to fix the same profile.
fn single_profile(composed: &ScheduledBindings) -> Result<(), ScheduledProfileErrorV1> {
    let mut profiles = composed
        .values()
        .copied()
        .map(ScheduledDriverBindingV1::profile);
    let first = profiles.next();
    if profiles.all(|profile| Some(profile) == first) {
        Ok(())
    } else {
        Err(ScheduledProfileErrorV1::MixedProfiles)
    }
}
