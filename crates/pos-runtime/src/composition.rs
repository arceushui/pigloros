//! Immutable structural descriptions and fail-closed resolution of effective
//! Plugin runtime composition.

use std::{collections::HashSet, sync::Arc};

use pos_core::{
    manifest_owner_link::ManifestAdmissionCatalogV1, AdapterAdmissionV1, Hash, PluginId,
};

/// Closed failures of the host's complete pre-registration manifest batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestRegistrationErrorV1 {
    #[error("manifest registration batch is missing or already prepared")]
    BatchState,
    #[error("manifest registration requires an empty live local registry")]
    RegistryState,
    #[error("manifest registration batch has no admitted Plugins")]
    EmptyBatch,
    #[error("manifest registration does not match the installed Plugin")]
    PluginMismatch,
    #[error("manifest registration slot is missing, duplicated or mismatched")]
    SlotMismatch,
    #[error("manifest registration requires an available pin and retained output closure")]
    UnverifiedRegistration,
    #[error("manifest registration batch is incomplete or changed")]
    IncompleteBatch,
}

/// Private registry-issued proof of one complete, identity-bound Plugin batch.
///
/// This is not a native owner receipt, serializable authority, or Replay permit.
/// Only the actual owner transaction can consume a current capability and
/// commit the catalog and scoped policy copies under ADR-089.
pub struct AdmittedCompositionV1 {
    pub(crate) registry_identity: Arc<()>,
    pub(crate) registration_revision: u64,
    pub(crate) catalog: ManifestAdmissionCatalogV1,
    pub(crate) adapter_admission: AdapterAdmissionV1,
}

impl AdmittedCompositionV1 {
    /// The checked catalog proposed for the later native owner transaction.
    #[must_use]
    pub const fn catalog(&self) -> &ManifestAdmissionCatalogV1 {
        &self.catalog
    }

    /// The exact adapter contract snapshot derived from this Plugin roster.
    #[must_use]
    pub const fn adapter_admission(&self) -> &AdapterAdmissionV1 {
        &self.adapter_admission
    }
}

/// Maximum number of explicitly required Plugin implementations in one V1 composition.
pub const MAX_REQUIRED_PLUGINS_V1: usize = 32;

/// Whether domain behavior crosses the Plugin port or an owning public Adapter port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainImplementationKindV1 {
    Plugin,
    PublicAdapter,
}

/// Execution isolation retained independently from domain semantics and authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginIsolationV1 {
    OperatorTrustedNative,
    GovernedCommunity,
}

/// Host-observed readiness of one explicitly registered implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginAvailabilityV1 {
    Available,
    Disabled,
    Unavailable,
    Revoked,
    Trapped,
    ResourceExhausted,
}

/// Execution mode for which a composition was resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginExecutionModeV1 {
    Local,
    AirGapped,
    Replay,
}

/// Which exact pin field made a required implementation incompatible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginPinFieldV1 {
    Version,
    ConfigurationDigest,
    ImplementationKind,
    Isolation,
    Roles,
}

/// Closed composition validation and resolution failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PluginCompositionErrorV1 {
    #[error("Plugin composition metadata is invalid")]
    InvalidMetadata,
    #[error("required Plugin composition is empty")]
    EmptyComposition,
    #[error("required Plugin composition exceeds its V1 bound")]
    CompositionTooLarge,
    #[error("Plugin implementation {plugin_id} appears more than once")]
    DuplicateImplementation { plugin_id: PluginId },
    #[error("domain role '{role}' has more than one owner")]
    DuplicateRole { role: String },
    #[error("required Plugin implementation {plugin_id} is not registered")]
    MissingImplementation { plugin_id: PluginId },
    #[error("required Plugin implementation {plugin_id} was not registered through a pinned seam")]
    UnpinnedImplementation { plugin_id: PluginId },
    #[error("required Plugin implementation {plugin_id} has an incompatible pin")]
    IncompatibleImplementation {
        plugin_id: PluginId,
        field: PluginPinFieldV1,
    },
    #[error("required Plugin implementation {plugin_id} is not available")]
    ImplementationUnavailable {
        plugin_id: PluginId,
        availability: PluginAvailabilityV1,
    },
    #[error("registered Plugin execution order differs from the required composition")]
    ExecutionOrderMismatch,
    #[error("composition execution mode does not match the registry mode")]
    ExecutionModeMismatch,
}

/// Host-trusted metadata that pins one Plugin or public Adapter implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginPinV1 {
    implementation_kind: DomainImplementationKindV1,
    isolation: PluginIsolationV1,
    configuration_digest: Hash,
    roles: Vec<String>,
}

impl PluginPinV1 {
    /// Validate one exact implementation pin.
    ///
    /// Role order is authoritative and becomes part of resolved evidence.
    ///
    /// # Errors
    /// Returns a closed metadata error for a zero digest, empty role set,
    /// empty role, or duplicate role.
    pub fn try_new(
        implementation_kind: DomainImplementationKindV1,
        isolation: PluginIsolationV1,
        configuration_digest: Hash,
        roles: Vec<String>,
    ) -> Result<Self, PluginCompositionErrorV1> {
        let mut unique_roles = HashSet::with_capacity(roles.len());
        if configuration_digest == Hash::zero()
            || roles.is_empty()
            || roles
                .iter()
                .any(|role| role.is_empty() || !unique_roles.insert(role.as_str()))
        {
            return Err(PluginCompositionErrorV1::InvalidMetadata);
        }
        Ok(Self {
            implementation_kind,
            isolation,
            configuration_digest,
            roles,
        })
    }

    #[must_use]
    pub const fn implementation_kind(&self) -> DomainImplementationKindV1 {
        self.implementation_kind
    }

    #[must_use]
    pub const fn isolation(&self) -> PluginIsolationV1 {
        self.isolation
    }

    #[must_use]
    pub const fn configuration_digest(&self) -> Hash {
        self.configuration_digest
    }

    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
}

/// Host registration state for one exact implementation pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginRegistrationV1 {
    pin: PluginPinV1,
    availability: PluginAvailabilityV1,
}

impl PluginRegistrationV1 {
    #[must_use]
    pub const fn new(pin: PluginPinV1, availability: PluginAvailabilityV1) -> Self {
        Self { pin, availability }
    }

    #[must_use]
    pub const fn pin(&self) -> &PluginPinV1 {
        &self.pin
    }

    #[must_use]
    pub const fn availability(&self) -> PluginAvailabilityV1 {
        self.availability
    }
}

/// One exact required implementation in deterministic execution order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredPluginV1 {
    plugin_id: PluginId,
    version: String,
    pin: PluginPinV1,
}

impl RequiredPluginV1 {
    /// Validate one exact Plugin requirement.
    ///
    /// # Errors
    /// Returns a closed metadata error for a nil identity or malformed version.
    pub fn try_new(
        plugin_id: PluginId,
        version: impl Into<String>,
        pin: PluginPinV1,
    ) -> Result<Self, PluginCompositionErrorV1> {
        let version = version.into();
        if plugin_id.inner().to_bytes() == [0; 16] || version.is_empty() {
            return Err(PluginCompositionErrorV1::InvalidMetadata);
        }
        Ok(Self {
            plugin_id,
            version,
            pin,
        })
    }

    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn pin(&self) -> &PluginPinV1 {
        &self.pin
    }
}

/// Complete ordered Plugin composition required for one execution profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredPluginCompositionV1 {
    mode: PluginExecutionModeV1,
    plugins: Vec<RequiredPluginV1>,
}

impl RequiredPluginCompositionV1 {
    /// Validate one complete ordered requirement without defining a fallback.
    ///
    /// # Errors
    /// Returns a closed error for an empty/oversized composition or duplicate
    /// implementation/role ownership.
    pub fn try_new(
        mode: PluginExecutionModeV1,
        plugins: Vec<RequiredPluginV1>,
    ) -> Result<Self, PluginCompositionErrorV1> {
        if plugins.is_empty() {
            return Err(PluginCompositionErrorV1::EmptyComposition);
        }
        if plugins.len() > MAX_REQUIRED_PLUGINS_V1 {
            return Err(PluginCompositionErrorV1::CompositionTooLarge);
        }
        let mut plugin_ids = HashSet::with_capacity(plugins.len());
        let mut roles = HashSet::new();
        for plugin in &plugins {
            if !plugin_ids.insert(plugin.plugin_id) {
                return Err(PluginCompositionErrorV1::DuplicateImplementation {
                    plugin_id: plugin.plugin_id,
                });
            }
            if let Some(role) = plugin
                .pin
                .roles
                .iter()
                .find(|role| !roles.insert(role.as_str()))
            {
                return Err(PluginCompositionErrorV1::DuplicateRole { role: role.clone() });
            }
        }
        Ok(Self { mode, plugins })
    }

    #[must_use]
    pub const fn mode(&self) -> PluginExecutionModeV1 {
        self.mode
    }

    #[must_use]
    pub fn plugins(&self) -> &[RequiredPluginV1] {
        &self.plugins
    }
}

/// Minimized exact evidence that every required implementation resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPluginV1 {
    plugin_id: PluginId,
    name: String,
    version: String,
    pin: PluginPinV1,
}

impl ResolvedPluginV1 {
    pub(crate) const fn new(
        plugin_id: PluginId,
        name: String,
        version: String,
        pin: PluginPinV1,
    ) -> Self {
        Self {
            plugin_id,
            name,
            version,
            pin,
        }
    }

    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn pin(&self) -> &PluginPinV1 {
        &self.pin
    }
}

/// Ordered composition evidence produced only after complete fail-closed resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPluginCompositionV1 {
    mode: PluginExecutionModeV1,
    plugins: Vec<ResolvedPluginV1>,
}

impl ResolvedPluginCompositionV1 {
    pub(crate) const fn new(mode: PluginExecutionModeV1, plugins: Vec<ResolvedPluginV1>) -> Self {
        Self { mode, plugins }
    }

    #[must_use]
    pub const fn mode(&self) -> PluginExecutionModeV1 {
        self.mode
    }

    #[must_use]
    pub fn plugins(&self) -> &[ResolvedPluginV1] {
        &self.plugins
    }
}

/// The ordered identity and version of one registered plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredPlugin {
    pub id: PluginId,
    pub name: String,
    pub version: String,
    /// Present only when the host used the explicit pinned registration seam.
    pub pin: Option<PluginPinV1>,
}

/// Validation-relevant metadata for one effective event schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredEventSchema {
    pub event_type: String,
    pub json_schema: Option<String>,
}

/// Deterministic structural description of a [`crate::PluginRegistry`].
///
/// Plugin registration order is retained because it determines driver
/// execution order. Effective schemas are canonicalized into lexical order.
/// This describes runtime registration topology only; it neither hashes nor
/// attests opaque code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginComposition {
    /// Plugins in their actual registration order.
    pub plugins: Vec<RegisteredPlugin>,
    /// Effective schemas in lexical event-type order.
    pub schemas: Vec<RegisteredEventSchema>,
}
