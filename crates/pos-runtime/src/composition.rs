//! Immutable structural descriptions and fail-closed resolution of effective
//! Plugin runtime composition.

use std::{collections::HashSet, sync::Arc};

use pos_core::{
    executable_budget::ExecutableBudgetErrorV1,
    manifest_owner_link::{ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1},
    AdapterAdmissionV1, Hash, PluginId,
};

/// Closed failures of the host's complete pre-registration manifest batch.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
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
    #[error(
        "Plugin {plugin_name:?} ({plugin_id}) has no manifest slot; register it with \
         PluginRegistry::register_local and a ManifestSlotV1"
    )]
    MissingSlot {
        plugin_name: String,
        plugin_id: PluginId,
    },
    #[error("manifest registration requires an available pin and retained output closure")]
    UnverifiedRegistration,
    #[error("manifest registration batch is incomplete or changed")]
    IncompleteBatch,
    #[error(
        "the composition's CPU reservation table does not fit one executable budget ({0}); \
         register at most 256 Plugins, with reservations within the budget's CPU limits"
    )]
    ReservationTable(#[from] ExecutableBudgetErrorV1),
}

/// Maximum byte length of a [`ManifestSlotV1`].
pub const MAX_MANIFEST_SLOT_BYTES_V1: usize = 64;

/// Closed rejection of a host-authored manifest slot.
///
/// Messages name the offending slot (never more than 64 bytes of it) or Plugin
/// and say what to change.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestSlotErrorV1 {
    #[error("manifest slot is empty; use A-Z a-z 0-9 . _ - (1-64 bytes)")]
    Empty,
    #[error("manifest slot is {length} bytes; use A-Z a-z 0-9 . _ - (1-64 bytes)")]
    TooLong { length: usize },
    #[error(
        "manifest slot {slot:?} contains {character:?} at byte {index}; use A-Z a-z 0-9 . _ - \
         (1-64 bytes)"
    )]
    InvalidCharacter {
        slot: String,
        character: char,
        index: usize,
    },
    #[error("manifest slot {slot:?} is already registered; give Plugin {plugin:?} another slot")]
    Duplicate { slot: String, plugin: String },
}

/// A host-authored, stable name for one Plugin in a local composition.
///
/// A slot is 1-64 ASCII bytes from `A-Z a-z 0-9 . _ -`. The embedding
/// application chooses it, passes it once to
/// [`crate::PluginRegistry::register_local`], and may record it in its own
/// reproduction recipe. It is not derived from the Plugin name or `PluginId`
/// and must hold no participant, secret or other private text.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestSlotV1(String);

const fn is_manifest_slot_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
}

impl ManifestSlotV1 {
    /// Validate a slot against the ADR-088 grammar.
    ///
    /// # Errors
    /// Returns [`ManifestSlotErrorV1`] for an empty, over-long or
    /// out-of-grammar slot.
    pub fn try_new(slot: &str) -> Result<Self, ManifestSlotErrorV1> {
        if slot.is_empty() {
            return Err(ManifestSlotErrorV1::Empty);
        }
        if slot.len() > MAX_MANIFEST_SLOT_BYTES_V1 {
            return Err(ManifestSlotErrorV1::TooLong { length: slot.len() });
        }
        if let Some((index, character)) = slot
            .char_indices()
            .find(|&(_, character)| !is_manifest_slot_character(character))
        {
            return Err(ManifestSlotErrorV1::InvalidCharacter {
                slot: slot.to_owned(),
                character,
                index,
            });
        }
        Ok(Self(slot.to_owned()))
    }

    /// The validated slot text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
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

/// Exact EOP1 and OPC1 native bytes read from one current admitted Plugin.
///
/// This value is an extraction result, not owner persistence or an admission
/// receipt. Its constructor stays private to the complete Plugin registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedManifestPolicySourceV1 {
    stable_slot: String,
    plugin_id: PluginId,
    plugin_name: String,
    plugin_version: String,
    implementation_hash: Hash,
    eop1_native_digest: Hash,
    closure_hash: Hash,
    eop1_bytes: Vec<u8>,
    opc1_bytes: Vec<u8>,
}

impl AdmittedManifestPolicySourceV1 {
    /// Build a native source after the Plugin registry validates the admitted roster.
    pub(crate) fn from_registry(
        row: &ManifestAdmissionCatalogRowV1,
        eop1_bytes: Vec<u8>,
        opc1_bytes: Vec<u8>,
    ) -> Self {
        Self {
            stable_slot: row.stable_slot.clone(),
            plugin_id: row.plugin_id,
            plugin_name: row.plugin_name.clone(),
            plugin_version: row.plugin_version.clone(),
            implementation_hash: row.implementation_hash,
            eop1_native_digest: row.eop1_native_digest,
            closure_hash: row.closure_hash,
            eop1_bytes,
            opc1_bytes,
        }
    }

    /// Stable slot bound by the complete registry capability.
    #[must_use]
    pub fn stable_slot(&self) -> &str {
        &self.stable_slot
    }

    /// Actual allocated `PluginId`, including reducer-only Plugins.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    /// Exact Plugin display name retained by the registry.
    #[must_use]
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Exact Plugin version retained by the registry.
    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    /// Host-admitted implementation pin.
    #[must_use]
    pub const fn implementation_hash(&self) -> Hash {
        self.implementation_hash
    }

    /// ADR-077 EOP1 native identity.
    #[must_use]
    pub const fn eop1_native_digest(&self) -> Hash {
        self.eop1_native_digest
    }

    /// ADR-088 OPC1 exact closure identity.
    #[must_use]
    pub const fn closure_hash(&self) -> Hash {
        self.closure_hash
    }

    /// Exact canonical EOP1 bytes retained by output admission.
    #[must_use]
    pub fn eop1_bytes(&self) -> &[u8] {
        &self.eop1_bytes
    }

    /// Exact canonical OPC1 bytes retained by output admission.
    #[must_use]
    pub fn opc1_bytes(&self) -> &[u8] {
        &self.opc1_bytes
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
    /// ADR-024 Revision 1: at most one owning Plugin registration per Event
    /// type in one registry. The error names the type, not the incumbent.
    #[error("Event type '{event_type}' has more than one owner")]
    DuplicateEventTypeOwner { event_type: String },
    /// A cursor-based Driver subscribes to a consent-sensitive Event type.
    ///
    /// ADR-021 Revision 4 Decision 1: a scheduled Driver that does not read
    /// the full verified prefix may not subscribe to a consent-sensitive
    /// type. The error names the first such subscription.
    #[error("cursor-based Driver subscribes to consent-sensitive Event type '{event_type}'")]
    CursorSubscriptionToConsentSensitiveType { event_type: String },
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
