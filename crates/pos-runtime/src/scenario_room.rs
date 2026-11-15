//! The ADR-041 Scenario Room descriptor seam (Redmine #1397, parent #303).
//!
//! A participant authors a [`ScenarioRoomInputV1`]; the runtime admits it as
//! one immutable [`ScenarioRoomDescriptorV1`] revision. Admission validates
//! every field, sorts the lists into their canonical order, resolves every
//! requested plugin against the deployment's bundled
//! [`ScenarioRoomCatalogueV1`], and computes the three ADR-041 hashes:
//!
//! - `plugin_composition_hash` over the requested plugins and the
//!   `capability_set_hash` of each registered Plugin;
//! - `rule_set_hash` over the RFC 8785 bytes of the rules;
//! - `descriptor_hash` over the RFC 8785 bytes of every other descriptor
//!   member.
//!
//! The runtime, never the caller, generates the room's `correlation_id`
//! ([`RoomCorrelationIdV1::generate`]). The `room.revision.v1` payload is
//! the RFC 8785 encoding of the whole descriptor
//! ([`ScenarioRoomDescriptorV1::payload`]), and
//! [`ScenarioRoomDescriptorV1::from_payload`] reads it back only when it
//! re-encodes to the same bytes. The encodings are the Proposed ADR-041
//! amendment of Redmine #303. ADR-041 section 10 requires all of this in
//! `pos-runtime`, unconditionally, with no feature flag.
//!
//! Every string the encoder writes is drawn from an alphabet that RFC 8785
//! writes verbatim (ULIDs, lower-case hex, lower-case keys, dotted versions
//! and four kind names), so no string needs an escape.

use std::{collections::BTreeSet, num::NonZeroU64};

use pos_core::{AppendDedupKey, AppendDedupScope, AppendIdentity, EntityId, Hash, Kind};
use serde::Deserialize;

/// The only Scenario Room descriptor schema version (ADR-041 section 1).
pub const SCENARIO_ROOM_SCHEMA_VERSION_V1: u64 = 1;
/// The largest `room.revision.v1` payload, in bytes (ADR-041 section 1).
pub const MAX_ROOM_DESCRIPTOR_BYTES_V1: usize = 4_096;
/// The most plugins one room names (ADR-041 section 1).
pub const MAX_ROOM_PLUGINS_V1: usize = crate::composition::MAX_REQUIRED_PLUGINS_V1;
/// The most rules one room declares (ADR-041 section 1).
pub const MAX_ROOM_RULES_V1: usize = 64;
/// The most participants one room names (Gateway v1 `room_participants`).
pub const MAX_ROOM_PARTICIPANTS_V1: usize = 64;
/// The most initial conditions one room declares (Gateway v1
/// `room_initial_conditions`).
pub const MAX_ROOM_INITIAL_CONDITIONS_V1: usize = 64;
/// The longest room horizon, in Ticks (Gateway v1 `horizon_ticks`).
pub const MAX_ROOM_TICKS_V1: u32 = 65_535;
/// The largest magnitude of a micro-unit value and the largest revision:
/// the I-JSON safe-integer bound, so every number survives a JSON reader.
pub const MAX_ROOM_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;

const MAX_KEY_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 64;
const CAPABILITY_SET_TAG: &[u8] = b"PiglorOS.ScenarioRoom.CapabilitySet.v1\0";
const PLUGIN_COMPOSITION_TAG: &[u8] = b"PiglorOS.ScenarioRoom.PluginComposition.v1\0";
const DEDUP_KEY_CONTEXT: &str = "PiglorOS ScenarioRoom AppendDedup v1";
const DEDUP_SCOPE_CONTEXT: &str = "PiglorOS ScenarioRoom AppendDedupScope v1";

/// The descriptor field a refused input names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioRoomFieldV1 {
    TickDurationMs,
    MaxTicks,
    Plugins,
    PluginId,
    PluginVersion,
    Rules,
    RuleId,
    RuleValue,
    Participants,
    InitialConditions,
    Dimension,
    ConditionValue,
    ConditionEntity,
}

/// The Scenario Room limit a refused input exceeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioRoomLimitV1 {
    Plugins,
    Rules,
    Participants,
    InitialConditions,
    DescriptorBytes,
    Revision,
}

/// Why a Scenario Room input or stored revision is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScenarioRoomErrorV1 {
    /// The descriptor names a schema version other than 1.
    #[error("unknown Scenario Room descriptor schema version")]
    UnsupportedSchemaVersion,
    /// A field is malformed, duplicated or out of its range.
    #[error("invalid Scenario Room descriptor field {0:?}")]
    InvalidField(ScenarioRoomFieldV1),
    /// A list or the descriptor exceeds its bound.
    #[error("Scenario Room limit exceeded: {0:?}")]
    LimitExceeded(ScenarioRoomLimitV1),
    /// A requested plugin is not bundled at exactly that version, or the
    /// bundled catalogue names it more than once.
    #[error("the room names a plugin the deployment does not bundle at that version")]
    PluginNotBundled,
    /// A rule's first segment names no requested plugin.
    #[error("the room declares a rule that names no requested plugin")]
    RuleWithoutPlugin,
    /// The operating system could not supply correlation entropy, or drew
    /// sixteen zero bytes.
    #[error("the room correlation ID could not be generated")]
    EntropyUnavailable,
    /// A stored `room.revision.v1` payload does not decode to an admissible
    /// descriptor with the same bytes.
    #[error("the stored Scenario Room revision is corrupt")]
    CorruptPayload,
}

/// One plugin a room requests, by name and exact version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomPluginRefV1 {
    pub plugin_id: String,
    pub version: String,
}

/// One declarative rule value, in integer micro-units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomRuleV1 {
    pub rule_id: String,
    pub value_micro: i64,
}

/// What a room participant is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomParticipantKindV1 {
    Persona,
    Agent,
    Society,
    WorldBody,
}

impl RoomParticipantKindV1 {
    /// The wire name of the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persona => "persona",
            Self::Agent => "agent",
            Self::Society => "society",
            Self::WorldBody => "world-body",
        }
    }

    /// The kind with wire name `name`, if there is one.
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Self> {
        [Self::Persona, Self::Agent, Self::Society, Self::WorldBody]
            .into_iter()
            .find(|kind| kind.as_str() == name)
    }
}

/// One entity that takes part in the room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomParticipantV1 {
    pub entity_id: EntityId,
    pub kind: RoomParticipantKindV1,
}

/// One starting value of one participant's dimension, in micro-units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomInitialConditionV1 {
    pub entity_id: EntityId,
    pub dimension: String,
    pub value_micro: i64,
}

/// The participant-authored members of one ADR-041 descriptor.
///
/// The server-owned members (room ID, revision, correlation ID and the three
/// hashes) are not part of the input and cannot be supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioRoomInputV1 {
    pub schema_version: u64,
    pub tick_duration_ms: u32,
    pub max_ticks: u32,
    pub scheduler_seed: [u8; 32],
    pub scheduler_policy: u8,
    pub intervention_policy: u8,
    pub plugins: Vec<RoomPluginRefV1>,
    pub rules: Vec<RoomRuleV1>,
    pub participants: Vec<RoomParticipantV1>,
    pub initial_conditions: Vec<RoomInitialConditionV1>,
    pub governance_ref: EntityId,
    pub privacy_export_ref: EntityId,
}

/// The runtime-generated correlation identity of one room: sixteen bytes
/// that are not all zero (ADR-041 section 1). It never comes from a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomCorrelationIdV1([u8; 16]);

impl RoomCorrelationIdV1 {
    /// Draw a fresh correlation ID from the operating system.
    ///
    /// # Errors
    /// [`ScenarioRoomErrorV1::EntropyUnavailable`] when the operating system
    /// supplies no entropy or the draw is all zero; no fallback is used.
    pub fn generate() -> Result<Self, ScenarioRoomErrorV1> {
        Self::generate_with(getrandom::fill)
    }

    fn generate_with(
        entropy: fn(&mut [u8]) -> Result<(), getrandom::Error>,
    ) -> Result<Self, ScenarioRoomErrorV1> {
        let mut bytes = [0; 16];
        entropy(&mut bytes)
            .ok()
            .and_then(|()| Self::from_bytes(bytes))
            .ok_or(ScenarioRoomErrorV1::EntropyUnavailable)
    }

    fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }

    /// The sixteen bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// One Plugin the deployment bundles, as a room may name it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BundledPluginV1 {
    name: String,
    version: String,
    capability_set_hash: Hash,
}

/// The Plugins a deployment bundles, from which a room's plugins resolve
/// (ADR-041 section 1; Wave 9 specification section 9). Only
/// [`crate::PluginRegistry::scenario_room_catalogue_v1`] builds one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScenarioRoomCatalogueV1 {
    plugins: Vec<BundledPluginV1>,
}

impl ScenarioRoomCatalogueV1 {
    pub(crate) fn from_registered<'a>(
        registered: impl Iterator<Item = (&'a str, &'a str, Hash)>,
    ) -> Self {
        Self {
            plugins: registered
                .map(|(name, version, capability_set_hash)| BundledPluginV1 {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    capability_set_hash,
                })
                .collect(),
        }
    }

    /// The `capability_set_hash` of the one bundled Plugin `plugin` names.
    fn resolve(&self, plugin: &RoomPluginRefV1) -> Result<Hash, ScenarioRoomErrorV1> {
        let mut matches = self.plugins.iter().filter(|bundled| {
            bundled.name == plugin.plugin_id && bundled.version == plugin.version
        });
        match (matches.next(), matches.next()) {
            (Some(bundled), None) => Ok(bundled.capability_set_hash),
            _ => Err(ScenarioRoomErrorV1::PluginNotBundled),
        }
    }
}

/// The `capability_set_hash` of one registered Plugin (amendment A3): the
/// BLAKE3 of its sorted, distinct capability names, which are its owned
/// Event types and so also the names of the schemas it registers (#303
/// decision 4a).
pub(crate) fn capability_set_hash_v1<'a>(
    owned_event_types: impl Iterator<Item = &'a Kind>,
) -> Hash {
    let names: BTreeSet<&str> = owned_event_types.map(Kind::as_str).collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_SET_TAG);
    hash_count(&mut hasher, names.len());
    for name in names {
        crate::hash_framed(&mut hasher, name.as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn hash_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&u64::try_from(count).unwrap_or(u64::MAX).to_le_bytes());
}

/// One immutable, admitted Scenario Room revision (ADR-041 section 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioRoomDescriptorV1 {
    room_id: EntityId,
    revision: NonZeroU64,
    input: ScenarioRoomInputV1,
    correlation_id: RoomCorrelationIdV1,
    plugin_composition_hash: Hash,
    rule_set_hash: Hash,
    descriptor_hash: Hash,
    payload: Vec<u8>,
}

impl ScenarioRoomDescriptorV1 {
    /// Admit revision 1 of a new room.
    ///
    /// # Errors
    /// Every refusal of [`ScenarioRoomErrorV1`] except `EntropyUnavailable`
    /// and `CorruptPayload`.
    pub fn admit_first(
        room_id: EntityId,
        correlation_id: RoomCorrelationIdV1,
        input: ScenarioRoomInputV1,
        catalogue: &ScenarioRoomCatalogueV1,
    ) -> Result<Self, ScenarioRoomErrorV1> {
        Self::admit(room_id, NonZeroU64::MIN, correlation_id, input, catalogue)
    }

    /// Admit the revision after `self`: same room and correlation ID, the next
    /// revision number, and a complete new input (no automatic merge).
    ///
    /// # Errors
    /// The refusals of [`Self::admit_first`], and
    /// [`ScenarioRoomLimitV1::Revision`] after revision 2^53 - 1.
    pub fn admit_next(
        &self,
        input: ScenarioRoomInputV1,
        catalogue: &ScenarioRoomCatalogueV1,
    ) -> Result<Self, ScenarioRoomErrorV1> {
        self.revision
            .checked_add(1)
            .filter(|next| next.get() <= MAX_ROOM_SAFE_INTEGER_V1)
            .ok_or(ScenarioRoomErrorV1::LimitExceeded(
                ScenarioRoomLimitV1::Revision,
            ))
            .and_then(|next| Self::admit(self.room_id, next, self.correlation_id, input, catalogue))
    }

    fn admit(
        room_id: EntityId,
        revision: NonZeroU64,
        correlation_id: RoomCorrelationIdV1,
        input: ScenarioRoomInputV1,
        catalogue: &ScenarioRoomCatalogueV1,
    ) -> Result<Self, ScenarioRoomErrorV1> {
        let input = canonical_input(input)?;
        let plugin_composition_hash = plugin_composition_hash(&input.plugins, catalogue)?;
        Self::assemble(
            room_id,
            revision,
            correlation_id,
            input,
            plugin_composition_hash,
        )
    }

    /// Compute the rule-set and descriptor hashes and the payload of a
    /// canonical input, and apply the payload bound.
    fn assemble(
        room_id: EntityId,
        revision: NonZeroU64,
        correlation_id: RoomCorrelationIdV1,
        input: ScenarioRoomInputV1,
        plugin_composition_hash: Hash,
    ) -> Result<Self, ScenarioRoomErrorV1> {
        let rule_set_hash = blake3_hash(rules_json(&input.rules).as_bytes());
        let mut descriptor = Self {
            room_id,
            revision,
            input,
            correlation_id,
            plugin_composition_hash,
            rule_set_hash,
            descriptor_hash: Hash::zero(),
            payload: Vec::new(),
        };
        let mut members = descriptor.members();
        descriptor.descriptor_hash = blake3_hash(object(members.clone()).as_bytes());
        members.push((
            "descriptor_hash",
            string(&hex(descriptor.descriptor_hash.as_bytes())),
        ));
        descriptor.payload = object(members).into_bytes();
        (descriptor.payload.len() <= MAX_ROOM_DESCRIPTOR_BYTES_V1)
            .then_some(descriptor)
            .ok_or(ScenarioRoomErrorV1::LimitExceeded(
                ScenarioRoomLimitV1::DescriptorBytes,
            ))
    }

    /// Read a stored `room.revision.v1` payload back.
    ///
    /// The payload must decode to a descriptor that passes every admission
    /// check except plugin resolution (which needs a registry, so the stored
    /// `plugin_composition_hash` is kept) and that re-encodes to exactly the
    /// same bytes, with the same `rule_set_hash` and `descriptor_hash`.
    ///
    /// # Errors
    /// [`ScenarioRoomErrorV1::CorruptPayload`].
    pub fn from_payload(payload: &[u8]) -> Result<Self, ScenarioRoomErrorV1> {
        serde_json::from_slice::<WireDescriptor>(payload)
            .ok()
            .and_then(WireDescriptor::into_parts)
            .and_then(|parts| {
                canonical_input(parts.input).ok().and_then(|input| {
                    Self::assemble(
                        parts.room_id,
                        parts.revision,
                        parts.correlation_id,
                        input,
                        parts.plugin_composition_hash,
                    )
                    .ok()
                    .map(|descriptor| (descriptor, parts.stored_hashes))
                })
            })
            .filter(|(descriptor, stored_hashes)| {
                descriptor.payload == payload
                    && *stored_hashes == (descriptor.rule_set_hash, descriptor.descriptor_hash)
            })
            .map(|(descriptor, _)| descriptor)
            .ok_or(ScenarioRoomErrorV1::CorruptPayload)
    }

    /// The members of the descriptor object without `descriptor_hash`, each
    /// with its RFC 8785 value.
    fn members(&self) -> Vec<(&'static str, String)> {
        let input = &self.input;
        vec![
            ("room_id", string(&self.room_id.to_string())),
            ("revision", self.revision.to_string()),
            ("schema_version", input.schema_version.to_string()),
            ("tick_duration_ms", input.tick_duration_ms.to_string()),
            ("max_ticks", input.max_ticks.to_string()),
            ("scheduler_seed", string(&hex(&input.scheduler_seed))),
            ("scheduler_policy", input.scheduler_policy.to_string()),
            ("intervention_policy", input.intervention_policy.to_string()),
            (
                "plugins",
                array(input.plugins.iter().map(|plugin| {
                    object(vec![
                        ("plugin_id", string(&plugin.plugin_id)),
                        ("version", string(&plugin.version)),
                    ])
                })),
            ),
            ("rules", rules_json(&input.rules)),
            (
                "participants",
                array(input.participants.iter().map(|participant| {
                    object(vec![
                        ("entity_id", string(&participant.entity_id.to_string())),
                        ("kind", string(participant.kind.as_str())),
                    ])
                })),
            ),
            (
                "initial_conditions",
                array(input.initial_conditions.iter().map(|condition| {
                    object(vec![
                        ("entity_id", string(&condition.entity_id.to_string())),
                        ("dimension", string(&condition.dimension)),
                        ("value_micro", condition.value_micro.to_string()),
                    ])
                })),
            ),
            ("governance_ref", string(&input.governance_ref.to_string())),
            (
                "privacy_export_ref",
                string(&input.privacy_export_ref.to_string()),
            ),
            (
                "correlation_id",
                string(&hex(self.correlation_id.as_bytes())),
            ),
            (
                "plugin_composition_hash",
                string(&hex(self.plugin_composition_hash.as_bytes())),
            ),
            ("rule_set_hash", string(&hex(self.rule_set_hash.as_bytes()))),
        ]
    }

    /// The room this revision belongs to.
    #[must_use]
    pub const fn room_id(&self) -> EntityId {
        self.room_id
    }

    /// The immutable revision number, from 1.
    #[must_use]
    pub const fn revision(&self) -> NonZeroU64 {
        self.revision
    }

    /// The admitted input, with every list in its canonical order.
    #[must_use]
    pub const fn input(&self) -> &ScenarioRoomInputV1 {
        &self.input
    }

    /// The room's runtime-generated correlation ID.
    #[must_use]
    pub const fn correlation_id(&self) -> RoomCorrelationIdV1 {
        self.correlation_id
    }

    /// The ADR-041 `plugin_composition_hash` (amendment A4).
    #[must_use]
    pub const fn plugin_composition_hash(&self) -> Hash {
        self.plugin_composition_hash
    }

    /// The ADR-041 `rule_set_hash` (amendment A5).
    #[must_use]
    pub const fn rule_set_hash(&self) -> Hash {
        self.rule_set_hash
    }

    /// The ADR-041 `descriptor_hash` (amendment A6).
    #[must_use]
    pub const fn descriptor_hash(&self) -> Hash {
        self.descriptor_hash
    }

    /// The `room.revision.v1` payload: the RFC 8785 bytes of the whole
    /// descriptor, at most [`MAX_ROOM_DESCRIPTOR_BYTES_V1`] long.
    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// The ADR-038 append identity of this revision (amendment A8): a key
    /// over `descriptor_hash` and a scope over the room, so an identical
    /// proposal is a duplicate of the existing revision (ADR-041 section 7).
    #[must_use]
    pub fn append_identity(&self) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash(blake3::derive_key(
                DEDUP_KEY_CONTEXT,
                self.descriptor_hash.as_bytes(),
            )),
            AppendDedupScope::from_keyed_hash(blake3::derive_key(
                DEDUP_SCOPE_CONTEXT,
                &self.room_id.inner().to_bytes(),
            )),
        )
    }
}

/// Validate an input and sort its lists into their canonical order
/// (amendment A1). The checks run in this order, and the first that fails
/// is the refusal: the schema version, the list bounds, each field, then
/// uniqueness and the cross-references after sorting.
fn canonical_input(
    mut input: ScenarioRoomInputV1,
) -> Result<ScenarioRoomInputV1, ScenarioRoomErrorV1> {
    first_failure(&field_checks(&input))?;
    input
        .plugins
        .sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    input
        .rules
        .sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    input
        .participants
        .sort_by_key(|participant| participant.entity_id);
    input.initial_conditions.sort_by(|left, right| {
        (left.entity_id, &left.dimension).cmp(&(right.entity_id, &right.dimension))
    });
    first_failure(&order_checks(&input)).map(|()| input)
}

/// The schema-version, bound and per-field checks of an unsorted input.
fn field_checks(input: &ScenarioRoomInputV1) -> Vec<(bool, ScenarioRoomErrorV1)> {
    use ScenarioRoomErrorV1::{InvalidField, LimitExceeded, UnsupportedSchemaVersion};
    use ScenarioRoomFieldV1 as Field;
    use ScenarioRoomLimitV1 as Limit;
    vec![
        (
            input.schema_version == SCENARIO_ROOM_SCHEMA_VERSION_V1,
            UnsupportedSchemaVersion,
        ),
        (
            input.plugins.len() <= MAX_ROOM_PLUGINS_V1,
            LimitExceeded(Limit::Plugins),
        ),
        (
            input.rules.len() <= MAX_ROOM_RULES_V1,
            LimitExceeded(Limit::Rules),
        ),
        (
            input.participants.len() <= MAX_ROOM_PARTICIPANTS_V1,
            LimitExceeded(Limit::Participants),
        ),
        (
            input.initial_conditions.len() <= MAX_ROOM_INITIAL_CONDITIONS_V1,
            LimitExceeded(Limit::InitialConditions),
        ),
        (
            input.tick_duration_ms >= 1,
            InvalidField(Field::TickDurationMs),
        ),
        (
            (1..=MAX_ROOM_TICKS_V1).contains(&input.max_ticks),
            InvalidField(Field::MaxTicks),
        ),
        (!input.plugins.is_empty(), InvalidField(Field::Plugins)),
        (
            input
                .plugins
                .iter()
                .all(|plugin| is_key(&plugin.plugin_id) && !plugin.plugin_id.contains('.')),
            InvalidField(Field::PluginId),
        ),
        (
            input
                .plugins
                .iter()
                .all(|plugin| is_version(&plugin.version)),
            InvalidField(Field::PluginVersion),
        ),
        (
            input.rules.iter().all(|rule| is_key(&rule.rule_id)),
            InvalidField(Field::RuleId),
        ),
        (
            input.rules.iter().all(|rule| is_safe(rule.value_micro)),
            InvalidField(Field::RuleValue),
        ),
        (
            !input.participants.is_empty(),
            InvalidField(Field::Participants),
        ),
        (
            input
                .initial_conditions
                .iter()
                .all(|condition| is_key(&condition.dimension)),
            InvalidField(Field::Dimension),
        ),
        (
            input
                .initial_conditions
                .iter()
                .all(|condition| is_safe(condition.value_micro)),
            InvalidField(Field::ConditionValue),
        ),
    ]
}

/// The uniqueness and cross-reference checks of a sorted input.
fn order_checks(input: &ScenarioRoomInputV1) -> Vec<(bool, ScenarioRoomErrorV1)> {
    use ScenarioRoomErrorV1::InvalidField;
    use ScenarioRoomFieldV1 as Field;
    vec![
        (
            strictly_ascending(input.plugins.iter().map(|plugin| &plugin.plugin_id)),
            InvalidField(Field::Plugins),
        ),
        (
            strictly_ascending(input.rules.iter().map(|rule| &rule.rule_id)),
            InvalidField(Field::Rules),
        ),
        (
            strictly_ascending(
                input
                    .participants
                    .iter()
                    .map(|participant| participant.entity_id),
            ),
            InvalidField(Field::Participants),
        ),
        (
            strictly_ascending(
                input
                    .initial_conditions
                    .iter()
                    .map(|condition| (condition.entity_id, &condition.dimension)),
            ),
            InvalidField(Field::InitialConditions),
        ),
        (
            input.initial_conditions.iter().all(|condition| {
                input
                    .participants
                    .iter()
                    .any(|participant| participant.entity_id == condition.entity_id)
            }),
            InvalidField(Field::ConditionEntity),
        ),
        (
            input.rules.iter().all(|rule| {
                rule.rule_id.split('.').next().is_some_and(|owner| {
                    input.plugins.iter().any(|plugin| plugin.plugin_id == owner)
                })
            }),
            ScenarioRoomErrorV1::RuleWithoutPlugin,
        ),
    ]
}

/// The error of the first check that does not hold.
fn first_failure(checks: &[(bool, ScenarioRoomErrorV1)]) -> Result<(), ScenarioRoomErrorV1> {
    checks
        .iter()
        .find(|(holds, _)| !holds)
        .map_or(Ok(()), |(_, error)| Err(*error))
}

fn strictly_ascending<T: Ord>(items: impl Iterator<Item = T>) -> bool {
    let items: Vec<T> = items.collect();
    items.windows(2).all(|pair| pair[0] < pair[1])
}

/// `^[a-z][a-z0-9_.-]*$`, 1 to 128 bytes.
fn is_key(text: &str) -> bool {
    text.len() <= MAX_KEY_BYTES
        && text.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
}

/// `^[0-9]+\.[0-9]+\.[0-9]+$`, at most 64 bytes.
fn is_version(text: &str) -> bool {
    text.len() <= MAX_VERSION_BYTES
        && text.split('.').count() == 3
        && text
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

const fn is_safe(value: i64) -> bool {
    value.unsigned_abs() <= MAX_ROOM_SAFE_INTEGER_V1
}

/// The amendment A4 hash of the requested plugins, in their canonical order.
fn plugin_composition_hash(
    plugins: &[RoomPluginRefV1],
    catalogue: &ScenarioRoomCatalogueV1,
) -> Result<Hash, ScenarioRoomErrorV1> {
    let capability_hashes = plugins
        .iter()
        .map(|plugin| catalogue.resolve(plugin))
        .collect::<Result<Vec<_>, _>>()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PLUGIN_COMPOSITION_TAG);
    hash_count(&mut hasher, plugins.len());
    for (plugin, capability_hash) in plugins.iter().zip(capability_hashes) {
        crate::hash_framed(&mut hasher, plugin.plugin_id.as_bytes());
        crate::hash_framed(&mut hasher, plugin.version.as_bytes());
        hasher.update(capability_hash.as_bytes());
    }
    Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
}

fn blake3_hash(bytes: &[u8]) -> Hash {
    Hash::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn rules_json(rules: &[RoomRuleV1]) -> String {
    array(rules.iter().map(|rule| {
        object(vec![
            ("rule_id", string(&rule.rule_id)),
            ("value_micro", rule.value_micro.to_string()),
        ])
    }))
}

/// An RFC 8785 object: members sorted by name (every name is ASCII, so
/// bytewise order is the UTF-16 order RFC 8785 requires).
fn object(mut members: Vec<(&'static str, String)>) -> String {
    members.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut out = String::from("{");
    for (index, (name, value)) in members.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(name);
        out.push_str("\":");
        out.push_str(value);
    }
    out.push('}');
    out
}

fn array(items: impl Iterator<Item = String>) -> String {
    format!("[{}]", items.collect::<Vec<_>>().join(","))
}

/// An RFC 8785 string of a value whose alphabet needs no escape.
fn string(text: &str) -> String {
    format!("\"{text}\"")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|digit| char::from(DIGITS[usize::from(digit)]))
        .collect()
}

fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0; N];
    let decoded = text.len() == 2 * N
        && text
            .as_bytes()
            .chunks_exact(2)
            .zip(out.iter_mut())
            .all(|(pair, byte)| {
                nibble(pair[0])
                    .zip(nibble(pair[1]))
                    .map(|(high, low)| *byte = (high << 4) | low)
                    .is_some()
            });
    decoded.then_some(out)
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

fn entity(text: &str) -> Option<EntityId> {
    ulid::Ulid::from_string(text).ok().map(EntityId::from_ulid)
}

/// The decoded members of a stored payload, before any check.
struct WireParts {
    room_id: EntityId,
    revision: NonZeroU64,
    correlation_id: RoomCorrelationIdV1,
    plugin_composition_hash: Hash,
    /// The stored `rule_set_hash` and `descriptor_hash`, which the
    /// recomputed ones must equal.
    stored_hashes: (Hash, Hash),
    input: ScenarioRoomInputV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDescriptor {
    room_id: String,
    revision: u64,
    schema_version: u64,
    tick_duration_ms: u32,
    max_ticks: u32,
    scheduler_seed: String,
    scheduler_policy: u8,
    intervention_policy: u8,
    plugins: Vec<WirePlugin>,
    rules: Vec<WireRule>,
    participants: Vec<WireParticipant>,
    initial_conditions: Vec<WireCondition>,
    governance_ref: String,
    privacy_export_ref: String,
    correlation_id: String,
    plugin_composition_hash: String,
    rule_set_hash: String,
    descriptor_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePlugin {
    plugin_id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRule {
    rule_id: String,
    value_micro: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireParticipant {
    entity_id: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCondition {
    entity_id: String,
    dimension: String,
    value_micro: i64,
}

impl WireDescriptor {
    fn into_parts(self) -> Option<WireParts> {
        let participants = self
            .participants
            .iter()
            .map(|participant| {
                entity(&participant.entity_id)
                    .zip(RoomParticipantKindV1::from_wire(&participant.kind))
            })
            .map(|pair| pair.map(|(entity_id, kind)| RoomParticipantV1 { entity_id, kind }))
            .collect::<Option<Vec<_>>>();
        let initial_conditions = self
            .initial_conditions
            .into_iter()
            .map(|condition| {
                entity(&condition.entity_id).map(|entity_id| RoomInitialConditionV1 {
                    entity_id,
                    dimension: condition.dimension,
                    value_micro: condition.value_micro,
                })
            })
            .collect::<Option<Vec<_>>>();
        let identity = entity(&self.room_id)
            .zip(
                NonZeroU64::new(self.revision)
                    .filter(|revision| revision.get() <= MAX_ROOM_SAFE_INTEGER_V1),
            )
            .zip(hex_bytes::<16>(&self.correlation_id).and_then(RoomCorrelationIdV1::from_bytes))
            .zip(hex_bytes::<32>(&self.plugin_composition_hash).map(Hash::from_bytes))
            .zip(hex_bytes::<32>(&self.scheduler_seed))
            .zip(entity(&self.governance_ref).zip(entity(&self.privacy_export_ref)))
            .zip(
                hex_bytes::<32>(&self.rule_set_hash)
                    .map(Hash::from_bytes)
                    .zip(hex_bytes::<32>(&self.descriptor_hash).map(Hash::from_bytes)),
            );
        identity.zip(participants.zip(initial_conditions)).map(
            |(
                (
                    (
                        ((((room_id, revision), correlation_id), plugin_composition_hash), seed),
                        refs,
                    ),
                    stored_hashes,
                ),
                (participants, initial_conditions),
            )| WireParts {
                room_id,
                revision,
                correlation_id,
                plugin_composition_hash,
                stored_hashes,
                input: ScenarioRoomInputV1 {
                    schema_version: self.schema_version,
                    tick_duration_ms: self.tick_duration_ms,
                    max_ticks: self.max_ticks,
                    scheduler_seed: seed,
                    scheduler_policy: self.scheduler_policy,
                    intervention_policy: self.intervention_policy,
                    plugins: self
                        .plugins
                        .into_iter()
                        .map(|plugin| RoomPluginRefV1 {
                            plugin_id: plugin.plugin_id,
                            version: plugin.version,
                        })
                        .collect(),
                    rules: self
                        .rules
                        .into_iter()
                        .map(|rule| RoomRuleV1 {
                            rule_id: rule.rule_id,
                            value_micro: rule.value_micro,
                        })
                        .collect(),
                    participants,
                    initial_conditions,
                    governance_ref: refs.0,
                    privacy_export_ref: refs.1,
                },
            },
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
