//! The registration split of ADR-119 section 4.4 step 2: `prepare` runs every
//! registration check without mutating the registry, and `install` applies
//! the mutations.
//!
//! Every ordinary registration path prepares, then installs at once. The
//! ADR-119 swap seams (`fallback_swap`) prepare a candidate with the primary
//! it replaces excluded from the Event-type and role checks, and never install
//! it: the swap moves the prepared entry into the primary's index instead.

use pos_core::output_policy::OutputPolicyV1;
use pos_core::{
    clock::Seq, ActionApprover, Capability, FactualOwnerIdV1, Kind, Plugin, PluginId, Reducer,
};

use super::fallback_swap::FallbackSwapRefusalV1;
use super::{
    DriverEventObservation, PassState, PendingRegistrationCallbacksV1, PluginEntry, PluginRegistry,
    ReducerSlotV1, RegistrationOptions, StepChainV1,
};
use crate::composition::{
    ManifestRegistrationErrorV1, PluginCompositionErrorV1, PluginPinV1, PluginRegistrationV1,
};
use crate::driver::Driver;
use crate::error::RuntimeError;
use crate::output_admission::{OutputAdmissionV1, OutputPolicyBindingV1, OutputPolicyClosureV1};
use crate::schema::EventTypeSchema;

/// The callbacks a prepared registration carries into the registry.
pub(super) struct PreparedCallbacks {
    pub(super) driver: Option<Box<dyn Driver>>,
    pub(super) reducer: Option<Box<dyn Reducer>>,
    pub(super) approver: Option<Box<dyn ActionApprover>>,
    pub(super) approver_event_types: Vec<Kind>,
}

/// What only an ordinary install adds next to the registry entry.
pub(super) struct PreparedRoutes {
    reducer: Option<Box<dyn Reducer>>,
    reducer_slot: ReducerSlotV1,
    approver_event_types: Vec<Kind>,
}

/// One registration that passed every registry check and is not installed.
///
/// [`PluginRegistry::prepare_pinned_generated_v1`] returns it (ADR-119
/// section 4.4 step 2). [`PluginRegistry::install_prepared_v1`] installs it,
/// and [`PluginRegistry::swap_entry_v1`] moves it into the index of the
/// primary it replaces. It carries the Driver and the Driver observation
/// captured at preparation, and it is bound to the registry revision it was
/// prepared at: any later registration or swap makes it stale.
pub struct PreparedRegistrationV1 {
    pub(super) id: PluginId,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) owned_event_types: Vec<Kind>,
    pub(super) callbacks: PreparedCallbacks,
    pub(super) event_observation: DriverEventObservation,
    pub(super) options: RegistrationOptions,
    pub(super) owner_id: FactualOwnerIdV1,
    pub(super) replacing: Option<PluginId>,
    pub(super) revision: u64,
}

impl PreparedRegistrationV1 {
    /// The prepared Plugin.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.id
    }

    /// The prepared Plugin's `Plugin::version()`.
    #[must_use]
    pub const fn version(&self) -> &str {
        self.version.as_str()
    }

    /// The prepared registration's pin, if it carries one.
    #[must_use]
    pub fn pin(&self) -> Option<&PluginPinV1> {
        let registration = self.options.registration.as_ref();
        registration.map(PluginRegistrationV1::pin)
    }

    /// The primary this registration was prepared to replace, if any.
    #[must_use]
    pub const fn replacing(&self) -> Option<PluginId> {
        self.replacing
    }

    /// The registry entry, and the routes only an ordinary install adds.
    pub(super) fn into_parts(self) -> (PreparedRoutes, PluginEntry) {
        let PreparedCallbacks {
            driver,
            reducer,
            approver,
            approver_event_types,
        } = self.callbacks;
        let routes = PreparedRoutes {
            reducer,
            reducer_slot: self.options.reducer_slot,
            approver_event_types,
        };
        let entry = PluginEntry {
            name: self.name,
            version: self.version,
            owned_event_types: self.owned_event_types,
            driver,
            approver,
            last_tick: None,
            event_cursor: Seq::ZERO,
            registration: self.options.registration,
            output_admission: self.options.output_admission,
            manifest_slot: self.options.manifest_slot,
            event_observation: self.event_observation,
            pass_state: PassState::new(self.owner_id),
            chain: StepChainV1::Lookup,
        };
        (routes, entry)
    }
}

impl PluginRegistry {
    /// Run every check of one registration without mutating the registry.
    ///
    /// With `replacing = Some(primary)`, the exclusive Event-type and role
    /// checks ignore the primary's registration. The `PluginId` check does
    /// not, and the candidate must differ from the primary.
    pub(super) fn prepare_registration<I: IntoIterator<Item = Kind>>(
        &self,
        plugin: &dyn Plugin,
        binding: OutputPolicyBindingV1,
        reducer: Option<Box<dyn Reducer>>,
        callbacks: PendingRegistrationCallbacksV1<I>,
        options: RegistrationOptions,
        replacing: Option<PluginId>,
    ) -> Result<PreparedRegistrationV1, RuntimeError> {
        let registration = options.registration.as_ref();
        let context = self.checked_context(plugin, &binding, registration, replacing)?;
        let options = Self::admit_output(plugin, binding, &context.2.owned_event_types, options)?;
        let PendingRegistrationCallbacksV1 {
            driver,
            approver,
            approver_event_types,
        } = callbacks;
        let callbacks = PreparedCallbacks {
            driver,
            reducer,
            approver,
            approver_event_types: approver_event_types.into_iter().collect(),
        };
        self.prepare_slice(plugin, callbacks, context, options, replacing)
    }

    /// The registration context after the manifest, identity, ownership,
    /// binding and role checks, in that order.
    fn checked_context(
        &self,
        plugin: &dyn Plugin,
        binding: &OutputPolicyBindingV1,
        registration: Option<&PluginRegistrationV1>,
        replacing: Option<PluginId>,
    ) -> Result<(PluginId, String, Capability), RuntimeError> {
        self.ensure_registrable(plugin.id(), replacing)?;
        let context = self.owned_registration_context(plugin, replacing)?;
        if !binding.verifies_erased_owner_instance(plugin) {
            return Err(RuntimeError::OutputAdmission(
                crate::OutputAdmissionErrorV1::PluginMismatch,
            ));
        }
        self.validate_option_roles(registration, replacing)?;
        Ok(context)
    }

    /// Refuse any registration while a manifest batch is prepared, and a
    /// candidate that is the primary it replaces.
    fn ensure_registrable(
        &self,
        candidate: PluginId,
        replacing: Option<PluginId>,
    ) -> Result<(), RuntimeError> {
        // A prepared manifest batch admits only installed manifest-slot
        // registrations, which stay closed until Wave 9.
        if self.manifest_batch.is_some() {
            return Err(ManifestRegistrationErrorV1::BatchState.into());
        }
        // `replace_index` with an equal key would silently succeed.
        if replacing == Some(candidate) {
            return Err(FallbackSwapRefusalV1::SameAsPrimary.into());
        }
        Ok(())
    }

    fn validate_option_roles(
        &self,
        registration: Option<&PluginRegistrationV1>,
        replacing: Option<PluginId>,
    ) -> Result<(), PluginCompositionErrorV1> {
        registration.map_or(Ok(()), |registration| {
            self.validate_registration_roles(registration, replacing)
        })
    }

    /// Every registered entry except the registration `replacing` names.
    pub(super) fn entries_other_than(
        &self,
        replacing: Option<PluginId>,
    ) -> impl Iterator<Item = &PluginEntry> {
        self.plugins
            .iter()
            .filter(move |(id, _)| Some(**id) != replacing)
            .map(|(_, entry)| entry)
    }

    /// Mint the output admission of a binding whose declarations are exactly
    /// the Plugin's owned Event types.
    fn admit_output(
        plugin: &dyn Plugin,
        binding: OutputPolicyBindingV1,
        owned_event_types: &[Kind],
        mut options: RegistrationOptions,
    ) -> Result<RegistrationOptions, RuntimeError> {
        let (output_policy, executable_budget, artifacts, _source, owner_token) =
            binding.into_parts();
        let closure = OutputPolicyClosureV1::from_artifacts(
            &output_policy.to_canonical_cbor(),
            &executable_budget.to_canonical_cbor(),
            artifacts.implementation_artifact(),
            artifacts.configuration_artifact(),
            artifacts.execution_profile_artifact(),
            artifacts.retention_policy_artifact(),
        )?;
        check_output_declarations(plugin, closure.output_policy(), owned_event_types)?;
        let admission = OutputAdmissionV1::try_new_verified(
            plugin.id(),
            plugin.version(),
            closure,
            owner_token,
        )?;
        debug_assert_eq!(admission.owner_token(), Some(owner_token));
        options.output_admission = Some(admission);
        Ok(options)
    }

    /// The capability checks and the Driver observation capture of one
    /// registration whose identity and ownership already passed.
    pub(super) fn prepare_slice(
        &self,
        plugin: &dyn Plugin,
        callbacks: PreparedCallbacks,
        context: (PluginId, String, Capability),
        options: RegistrationOptions,
        replacing: Option<PluginId>,
    ) -> Result<PreparedRegistrationV1, RuntimeError> {
        let (id, name, cap) = context;
        check_callback_presence(&name, &cap, &callbacks)?;
        check_approver_routes(&name, &cap, &callbacks)?;
        // The Driver rule runs before any registry mutation (ADR-021
        // Revision 4 Decision 1).
        let event_observation = DriverEventObservation::capture(callbacks.driver.as_deref())?;
        let owner_id = self.owner_id_for_options(&options, &name);
        let version = plugin.version().to_owned();
        Ok(PreparedRegistrationV1 {
            id,
            name,
            version,
            owned_event_types: cap.owned_event_types,
            callbacks,
            event_observation,
            options,
            owner_id,
            replacing,
            revision: self.registration_revision,
        })
    }

    /// Apply every mutation of one prepared registration.
    ///
    /// Installing the reducer is the only fallible step, and it runs before
    /// the schemas, routes or entries change.
    pub(super) fn install_prepared(
        &mut self,
        prepared: PreparedRegistrationV1,
    ) -> Result<(), RuntimeError> {
        let id = prepared.id;
        let (routes, entry) = prepared.into_parts();
        self.install_reducer(id, &entry.name, routes.reducer, routes.reducer_slot)?;
        for kind in &entry.owned_event_types {
            self.schemas.register_claimed(EventTypeSchema {
                event_type: kind.clone(),
                description: format!("owned by plugin '{}'", entry.name),
                json_schema: None,
            });
        }
        if entry.approver.is_some() {
            for kind in &routes.approver_event_types {
                self.approver_map.insert(kind.clone(), id);
            }
        }
        self.plugins.insert(id, entry);
        self.registration_revision += 1;
        self.restored_binding = None;
        Ok(())
    }
}

/// Every output declaration must name an owned type, and every owned type
/// must be declared.
fn check_output_declarations(
    plugin: &dyn Plugin,
    output_policy: &OutputPolicyV1,
    owned_event_types: &[Kind],
) -> Result<(), RuntimeError> {
    let declarations = &output_policy.fields().output_declarations;
    let owns = |event_type: &str| {
        owned_event_types
            .iter()
            .any(|kind| kind.as_str() == event_type)
    };
    if let Some(declaration) = declarations
        .iter()
        .find(|declaration| !owns(declaration.event_type()))
    {
        return Err(RuntimeError::CapabilityMismatch {
            name: plugin.name().to_owned(),
            reason: format!(
                "output policy declares event type '{}' outside the Plugin capability",
                declaration.event_type()
            ),
        });
    }
    let declares = |kind: &Kind| {
        declarations
            .iter()
            .any(|declaration| declaration.event_type() == kind.as_str())
    };
    if let Some(kind) = owned_event_types.iter().find(|&kind| !declares(kind)) {
        return Err(RuntimeError::CapabilityMismatch {
            name: plugin.name().to_owned(),
            reason: format!(
                "Plugin capability owns event type '{}' without an output-policy declaration",
                kind.as_str()
            ),
        });
    }
    Ok(())
}

/// The `has_driver` and `has_reducer` capability checks.
fn check_callback_presence(
    name: &str,
    cap: &Capability,
    callbacks: &PreparedCallbacks,
) -> Result<(), RuntimeError> {
    if cap.has_driver != callbacks.driver.is_some() {
        return Err(RuntimeError::CapabilityMismatch {
            name: name.to_owned(),
            reason: if cap.has_driver {
                "has_driver=true but no driver provided".to_owned()
            } else {
                "has_driver=false but a driver was provided".to_owned()
            },
        });
    }
    if cap.has_reducer != callbacks.reducer.is_some() {
        return Err(RuntimeError::CapabilityMismatch {
            name: name.to_owned(),
            reason: if cap.has_reducer {
                "has_reducer=true but no reducer provided".to_owned()
            } else {
                "has_reducer=false but a reducer was provided".to_owned()
            },
        });
    }
    Ok(())
}

/// Approver routes need an approver, and each must be a Plugin-owned type.
///
/// The shared ownership check has already rejected any type another
/// registration owns, so a second approver route for one type cannot pass.
fn check_approver_routes(
    name: &str,
    cap: &Capability,
    callbacks: &PreparedCallbacks,
) -> Result<(), RuntimeError> {
    let routes = &callbacks.approver_event_types;
    if callbacks.approver.is_none() && !routes.is_empty() {
        return Err(RuntimeError::CapabilityMismatch {
            name: name.to_owned(),
            reason: "approver event types were supplied without an approver".to_owned(),
        });
    }
    if let Some(kind) = routes
        .iter()
        .find(|kind| !cap.owned_event_types.contains(kind))
    {
        return Err(RuntimeError::CapabilityMismatch {
            name: name.to_owned(),
            reason: format!("approver event type '{kind}' is not plugin-owned"),
        });
    }
    Ok(())
}
