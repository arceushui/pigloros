use ciborium::value::Value;
use pos_core::ids::{EntityId, PluginId, TimelineId};
use std::collections::HashSet;
use std::io::Cursor;
use thiserror::Error;
use ulid::Ulid;

const MAX_ACTIONS: usize = 64;
const MAX_ACTION_ID_BYTES: usize = 64;
const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_PLUGIN_VERSION_BYTES: usize = 32;
const MAX_PROVIDER_VERSION_BYTES: usize = 64;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 4096;
const MAX_ENCODED_CATALOGUE_BYTES: usize = 4096;
const MAX_ENCODED_REQUEST_BYTES: usize = 4096;
const MAX_ENCODED_RECORD_BYTES: usize = 4096;
const MAX_ENCODED_ACTION_BYTES: usize = 512;
const MAX_ACTION_INDEX: u8 = 63;
const MAX_CONFIDENCE_PPM: u32 = 1_000_000;

const CATALOGUE_MAGIC: [u8; 4] = *b"PAC1";
const REQUEST_MAGIC: [u8; 4] = *b"PQR1";
const DECISION_MAGIC: [u8; 4] = *b"PDP1";
const RECORD_MAGIC: [u8; 4] = *b"PDR1";
const ACTION_MAGIC: [u8; 4] = *b"PAA1";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgentDecisionError {
    #[error("invalid action catalogue count")]
    InvalidActionCatalogueCount,
    #[error("invalid action identifier length")]
    InvalidActionIdentifierLength,
    #[error("invalid action identifier control character")]
    InvalidActionIdentifierControlCharacter,
    #[error("duplicate action identifier")]
    DuplicateActionIdentifier,
    #[error("invalid provider identifier length")]
    InvalidProviderIdentifierLength,
    #[error("invalid provider identifier grammar")]
    InvalidProviderIdentifierGrammar,
    #[error("invalid plugin version length")]
    InvalidPluginVersionLength,
    #[error("invalid plugin version character")]
    InvalidPluginVersionCharacter,
    #[error("invalid provider version length")]
    InvalidProviderVersionLength,
    #[error("invalid provider version character")]
    InvalidProviderVersionCharacter,
    #[error("invalid action index")]
    InvalidActionIndex,
    #[error("invalid confidence")]
    InvalidConfidence,
    #[error("invalid provider response length")]
    InvalidProviderResponseLength,
    #[error("malformed agent decision wire value")]
    MalformedWire,
    #[error("unsupported agent decision wire version")]
    UnsupportedWireVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCatalogueV1 {
    action_ids: Vec<String>,
}

impl ActionCatalogueV1 {
    /// Builds a declaration-ordered action catalogue.
    ///
    /// # Errors
    ///
    /// Returns [`AgentDecisionError`] when the count, identifier length,
    /// identifier control characters, or identifier uniqueness violate V1.
    pub fn try_new(action_ids: Vec<String>) -> Result<Self, AgentDecisionError> {
        if !(1..=MAX_ACTIONS).contains(&action_ids.len()) {
            return Err(AgentDecisionError::InvalidActionCatalogueCount);
        }

        let mut seen = HashSet::with_capacity(action_ids.len());
        for action_id in &action_ids {
            validate_action_identifier(action_id)?;
            if !seen.insert(action_id.as_str()) {
                return Err(AgentDecisionError::DuplicateActionIdentifier);
            }
        }

        Ok(Self { action_ids })
    }

    #[must_use]
    pub fn action(&self, index: u8) -> Option<&str> {
        self.action_ids.get(usize::from(index)).map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.action_ids.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.action_ids.is_empty()
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] when the V1 size bound is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, AgentDecisionError> {
        let mut output = Vec::new();
        write_array(&mut output, 3);
        write_bytes(&mut output, &CATALOGUE_MAGIC);
        write_uint(&mut output, 1);
        write_array(&mut output, self.action_ids.len());
        for action_id in &self.action_ids {
            write_text(&mut output, action_id);
        }
        finish_encoded(output, MAX_ENCODED_CATALOGUE_BYTES)
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] for any non-canonical V1 input.
    pub fn decode(input: &[u8]) -> Result<Self, AgentDecisionError> {
        let values = decode_array(input, MAX_ENCODED_CATALOGUE_BYTES)?;
        if values.len() != 3
            || !matches_magic(values.first(), CATALOGUE_MAGIC)
            || uint(values.get(1)) != Some(1)
        {
            return Err(AgentDecisionError::MalformedWire);
        }
        let Some(Value::Array(entries)) = values.get(2) else {
            return Err(AgentDecisionError::MalformedWire);
        };
        let mut action_ids = Vec::with_capacity(entries.len());
        for entry in entries {
            let action_id = text(Some(entry)).ok_or(AgentDecisionError::MalformedWire)?;
            action_ids.push(action_id.to_owned());
        }
        let decoded = Self::try_new(action_ids).map_err(|_| AgentDecisionError::MalformedWire)?;
        canonical_equals(input, &decoded.encode()?)?;
        Ok(decoded)
    }

    /// # Errors
    ///
    /// Propagates the V1 encoding size error.
    pub fn hash(&self) -> Result<[u8; 32], AgentDecisionError> {
        self.encode()
            .map(|encoded| derive_hash("pigloros.agent.catalogue.v1", &encoded))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProviderProvenanceV1 {
    plugin_id: PluginId,
    plugin_version: String,
    plugin_content_hash: [u8; 32],
    provider_id: String,
    provider_version: String,
    provider_content_hash: [u8; 32],
}

impl AgentProviderProvenanceV1 {
    /// Builds the host-owned provider provenance.
    ///
    /// # Errors
    ///
    /// Returns [`AgentDecisionError`] when an identifier or version violates
    /// its V1 length, ASCII, or grammar requirements.
    pub fn try_new(
        plugin_id: PluginId,
        plugin_version: String,
        plugin_content_hash: [u8; 32],
        provider_id: String,
        provider_version: String,
        provider_content_hash: [u8; 32],
    ) -> Result<Self, AgentDecisionError> {
        validate_printable_ascii(
            &plugin_version,
            MAX_PLUGIN_VERSION_BYTES,
            AgentDecisionError::InvalidPluginVersionLength,
            AgentDecisionError::InvalidPluginVersionCharacter,
        )?;
        validate_provider_identifier(&provider_id)?;
        validate_printable_ascii(
            &provider_version,
            MAX_PROVIDER_VERSION_BYTES,
            AgentDecisionError::InvalidProviderVersionLength,
            AgentDecisionError::InvalidProviderVersionCharacter,
        )?;

        Ok(Self {
            plugin_id,
            plugin_version,
            plugin_content_hash,
            provider_id,
            provider_version,
            provider_content_hash,
        })
    }

    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub const fn plugin_content_hash(&self) -> [u8; 32] {
        self.plugin_content_hash
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    #[must_use]
    pub const fn provider_content_hash(&self) -> [u8; 32] {
        self.provider_content_hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDecisionRequestV1 {
    timeline_id: TimelineId,
    observed_through: u64,
    agent_id: EntityId,
    driver_tick: u64,
    catalogue_hash: [u8; 32],
    provenance: AgentProviderProvenanceV1,
}

impl AgentDecisionRequestV1 {
    #[must_use]
    pub fn new(
        timeline_id: TimelineId,
        observed_through: u64,
        agent_id: EntityId,
        driver_tick: u64,
        catalogue_hash: [u8; 32],
        provenance: AgentProviderProvenanceV1,
    ) -> Self {
        Self {
            timeline_id,
            observed_through,
            agent_id,
            driver_tick,
            catalogue_hash,
            provenance,
        }
    }

    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn observed_through(&self) -> u64 {
        self.observed_through
    }

    #[must_use]
    pub const fn agent_id(&self) -> EntityId {
        self.agent_id
    }

    #[must_use]
    pub const fn driver_tick(&self) -> u64 {
        self.driver_tick
    }

    #[must_use]
    pub const fn catalogue_hash(&self) -> [u8; 32] {
        self.catalogue_hash
    }

    #[must_use]
    pub const fn provenance(&self) -> &AgentProviderProvenanceV1 {
        &self.provenance
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] when the V1 size bound is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, AgentDecisionError> {
        let mut output = Vec::new();
        write_array(&mut output, 13);
        write_bytes(&mut output, &REQUEST_MAGIC);
        write_uint(&mut output, 1);
        write_request_fields(&mut output, self);
        finish_encoded(output, MAX_ENCODED_REQUEST_BYTES)
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] for any non-canonical V1 input.
    pub fn decode(input: &[u8]) -> Result<Self, AgentDecisionError> {
        let values = decode_array(input, MAX_ENCODED_REQUEST_BYTES)?;
        if values.len() != 13
            || !matches_magic(values.first(), REQUEST_MAGIC)
            || uint(values.get(1)) != Some(1)
        {
            return Err(AgentDecisionError::MalformedWire);
        }
        let decoded = decode_request_fields(&values[2..])?;
        canonical_equals(input, &decoded.encode()?)?;
        Ok(decoded)
    }

    /// # Errors
    ///
    /// Propagates the V1 encoding size error.
    pub fn hash(&self) -> Result<[u8; 32], AgentDecisionError> {
        self.encode()
            .map(|encoded| derive_hash("pigloros.agent.request.v1", &encoded))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionIndexV1(u8);

impl TryFrom<u8> for ActionIndexV1 {
    type Error = AgentDecisionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > MAX_ACTION_INDEX {
            return Err(AgentDecisionError::InvalidActionIndex);
        }
        Ok(Self(value))
    }
}

impl ActionIndexV1 {
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfidencePpmV1(u32);

impl TryFrom<u32> for ConfidencePpmV1 {
    type Error = AgentDecisionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > MAX_CONFIDENCE_PPM {
            return Err(AgentDecisionError::InvalidConfidence);
        }
        Ok(Self(value))
    }
}

impl ConfidencePpmV1 {
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedProviderBytes(Vec<u8>);

impl TryFrom<Vec<u8>> for BoundedProviderBytes {
    type Error = AgentDecisionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(AgentDecisionError::InvalidProviderResponseLength);
        }
        Ok(Self(value))
    }
}

impl BoundedProviderBytes {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDecisionV1 {
    Accepted {
        action_index: ActionIndexV1,
        confidence: ConfidencePpmV1,
    },
    NoAction,
}

impl ProviderDecisionV1 {
    /// Builds an accepted provider decision from bounded wire values.
    ///
    /// # Errors
    ///
    /// Returns [`AgentDecisionError`] when the action index or confidence is
    /// outside the V1 range.
    pub fn accepted(action_index: u8, confidence: u32) -> Result<Self, AgentDecisionError> {
        Ok(Self::Accepted {
            action_index: ActionIndexV1::try_from(action_index)?,
            confidence: ConfidencePpmV1::try_from(confidence)?,
        })
    }

    #[must_use]
    pub const fn no_action() -> Self {
        Self::NoAction
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] when the V1 size bound is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, AgentDecisionError> {
        let mut output = Vec::new();
        match self {
            Self::Accepted {
                action_index,
                confidence,
            } => {
                write_array(&mut output, 5);
                write_bytes(&mut output, &DECISION_MAGIC);
                write_uint(&mut output, 1);
                write_uint(&mut output, 0);
                write_uint(&mut output, u64::from(action_index.get()));
                write_uint(&mut output, u64::from(confidence.get()));
            }
            Self::NoAction => {
                write_array(&mut output, 3);
                write_bytes(&mut output, &DECISION_MAGIC);
                write_uint(&mut output, 1);
                write_uint(&mut output, 1);
            }
        }
        finish_encoded(output, MAX_PROVIDER_RESPONSE_BYTES)
    }

    /// # Errors
    ///
    /// Returns malformed input, unsupported PDP1 versions, or invalid accepted values.
    pub fn decode(input: &[u8]) -> Result<Self, AgentDecisionError> {
        let values = decode_array(input, MAX_PROVIDER_RESPONSE_BYTES)?;
        if !matches_magic(values.first(), DECISION_MAGIC) {
            return Err(AgentDecisionError::MalformedWire);
        }
        let version = uint(values.get(1)).ok_or(AgentDecisionError::MalformedWire)?;
        if version != 1 {
            return Err(AgentDecisionError::UnsupportedWireVersion);
        }
        let kind = uint(values.get(2)).ok_or(AgentDecisionError::MalformedWire)?;
        let decoded = match kind {
            0 if values.len() == 5 => {
                let action_index = uint(values.get(3))
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or(AgentDecisionError::MalformedWire)?;
                let confidence = uint(values.get(4))
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(AgentDecisionError::MalformedWire)?;
                Self::accepted(action_index, confidence)?
            }
            1 if values.len() == 3 => Self::NoAction,
            _ => return Err(AgentDecisionError::MalformedWire),
        };
        canonical_equals(input, &decoded.encode()?)?;
        Ok(decoded)
    }

    #[must_use]
    pub fn hash_response(response: &[u8]) -> [u8; 32] {
        derive_hash("pigloros.agent.response.v1", response)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureCode {
    Unavailable,
    Timeout,
    Rejected,
    RateLimited,
}

impl ProviderFailureCode {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unavailable => 1,
            Self::Timeout => 2,
            Self::Rejected => 3,
            Self::RateLimited => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderAttempt {
    Response(BoundedProviderBytes),
    NoResponse,
    Failed(ProviderFailureCode),
    Oversized { response_digest: Option<[u8; 32]> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionNoActionCodeV1 {
    ProviderUnavailable,
    ProviderTimeout,
    ProviderRejected,
    ProviderRateLimited,
    ProviderNoAction,
    ResponseTooLarge,
    ResponseMalformed,
    ResponseVersionUnsupported,
    ResponseValueInvalid,
}

impl DecisionNoActionCodeV1 {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ProviderUnavailable => 1,
            Self::ProviderTimeout => 2,
            Self::ProviderRejected => 3,
            Self::ProviderRateLimited => 4,
            Self::ProviderNoAction => 5,
            Self::ResponseTooLarge => 6,
            Self::ResponseMalformed => 7,
            Self::ResponseVersionUnsupported => 8,
            Self::ResponseValueInvalid => 9,
        }
    }
}

impl From<ProviderFailureCode> for DecisionNoActionCodeV1 {
    fn from(value: ProviderFailureCode) -> Self {
        match value {
            ProviderFailureCode::Unavailable => Self::ProviderUnavailable,
            ProviderFailureCode::Timeout => Self::ProviderTimeout,
            ProviderFailureCode::Rejected => Self::ProviderRejected,
            ProviderFailureCode::RateLimited => Self::ProviderRateLimited,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionResultV1 {
    Accepted {
        action_index: ActionIndexV1,
        confidence: ConfidencePpmV1,
    },
    NoAction(DecisionNoActionCodeV1),
}

impl From<ProviderDecisionV1> for DecisionResultV1 {
    fn from(value: ProviderDecisionV1) -> Self {
        match value {
            ProviderDecisionV1::Accepted {
                action_index,
                confidence,
            } => Self::Accepted {
                action_index,
                confidence,
            },
            ProviderDecisionV1::NoAction => {
                Self::NoAction(DecisionNoActionCodeV1::ProviderNoAction)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionRecordV1 {
    request: AgentDecisionRequestV1,
    request_hash: [u8; 32],
    response_digest: Option<[u8; 32]>,
    result: DecisionResultV1,
}

impl DecisionRecordV1 {
    #[must_use]
    pub fn new(
        request: AgentDecisionRequestV1,
        request_hash: [u8; 32],
        response_digest: Option<[u8; 32]>,
        result: DecisionResultV1,
    ) -> Self {
        Self {
            request,
            request_hash,
            response_digest,
            result,
        }
    }

    #[must_use]
    pub const fn request(&self) -> &AgentDecisionRequestV1 {
        &self.request
    }

    #[must_use]
    pub const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub const fn response_digest(&self) -> Option<[u8; 32]> {
        self.response_digest
    }

    #[must_use]
    pub const fn result(&self) -> DecisionResultV1 {
        self.result
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] when the V1 size bound is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, AgentDecisionError> {
        let mut output = Vec::new();
        write_array(&mut output, 16);
        write_bytes(&mut output, &RECORD_MAGIC);
        write_uint(&mut output, 1);
        write_request_fields(&mut output, &self.request);
        write_bytes(&mut output, &self.request_hash);
        write_response_digest(&mut output, self.response_digest);
        write_result(&mut output, self.result);
        finish_encoded(output, MAX_ENCODED_RECORD_BYTES)
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] for any non-canonical V1 input.
    pub fn decode(input: &[u8]) -> Result<Self, AgentDecisionError> {
        let values = decode_array(input, MAX_ENCODED_RECORD_BYTES)?;
        if values.len() != 16
            || !matches_magic(values.first(), RECORD_MAGIC)
            || uint(values.get(1)) != Some(1)
        {
            return Err(AgentDecisionError::MalformedWire);
        }
        let request = decode_request_fields(&values[2..13])?;
        let request_hash = bytes::<32>(values.get(13)).ok_or(AgentDecisionError::MalformedWire)?;
        let response_digest = decode_response_digest(values.get(14))?;
        let result = decode_result(values.get(15))?;
        let decoded = Self::new(request, request_hash, response_digest, result);
        canonical_equals(input, &decoded.encode()?)?;
        Ok(decoded)
    }

    /// # Errors
    ///
    /// Propagates the V1 encoding size error.
    pub fn hash(&self) -> Result<[u8; 32], AgentDecisionError> {
        self.encode()
            .map(|encoded| derive_hash("pigloros.agent.record.v1", &encoded))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentActionV1 {
    action_id: String,
    confidence: ConfidencePpmV1,
    driver_tick: u64,
    catalogue_hash: [u8; 32],
    decision_record_hash: [u8; 32],
}

impl AgentActionV1 {
    /// Builds a derived Agent action from validated protocol values.
    ///
    /// # Errors
    ///
    /// Returns [`AgentDecisionError`] when the action identifier or confidence
    /// violates the V1 bounds.
    pub fn try_new(
        action_id: String,
        confidence: u32,
        driver_tick: u64,
        catalogue_hash: [u8; 32],
        decision_record_hash: [u8; 32],
    ) -> Result<Self, AgentDecisionError> {
        validate_action_identifier(&action_id)?;
        Ok(Self {
            action_id,
            confidence: ConfidencePpmV1::try_from(confidence)?,
            driver_tick,
            catalogue_hash,
            decision_record_hash,
        })
    }

    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    #[must_use]
    pub const fn confidence(&self) -> ConfidencePpmV1 {
        self.confidence
    }

    #[must_use]
    pub const fn driver_tick(&self) -> u64 {
        self.driver_tick
    }

    #[must_use]
    pub const fn catalogue_hash(&self) -> [u8; 32] {
        self.catalogue_hash
    }

    #[must_use]
    pub const fn decision_record_hash(&self) -> [u8; 32] {
        self.decision_record_hash
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] when the V1 size bound is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, AgentDecisionError> {
        let mut output = Vec::new();
        write_array(&mut output, 7);
        write_bytes(&mut output, &ACTION_MAGIC);
        write_uint(&mut output, 1);
        write_text(&mut output, &self.action_id);
        write_uint(&mut output, u64::from(self.confidence.get()));
        write_uint(&mut output, self.driver_tick);
        write_bytes(&mut output, &self.catalogue_hash);
        write_bytes(&mut output, &self.decision_record_hash);
        finish_encoded(output, MAX_ENCODED_ACTION_BYTES)
    }

    /// # Errors
    ///
    /// Returns [`AgentDecisionError::MalformedWire`] for any non-canonical V1 input.
    pub fn decode(input: &[u8]) -> Result<Self, AgentDecisionError> {
        let values = decode_array(input, MAX_ENCODED_ACTION_BYTES)?;
        if values.len() != 7
            || !matches_magic(values.first(), ACTION_MAGIC)
            || uint(values.get(1)) != Some(1)
        {
            return Err(AgentDecisionError::MalformedWire);
        }
        let action_id = text(values.get(2)).ok_or(AgentDecisionError::MalformedWire)?;
        let confidence = uint(values.get(3))
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AgentDecisionError::MalformedWire)?;
        let driver_tick = uint(values.get(4)).ok_or(AgentDecisionError::MalformedWire)?;
        let catalogue_hash = bytes::<32>(values.get(5)).ok_or(AgentDecisionError::MalformedWire)?;
        let decision_record_hash =
            bytes::<32>(values.get(6)).ok_or(AgentDecisionError::MalformedWire)?;
        let decoded = Self::try_new(
            action_id.to_owned(),
            confidence,
            driver_tick,
            catalogue_hash,
            decision_record_hash,
        )
        .map_err(|_| AgentDecisionError::MalformedWire)?;
        canonical_equals(input, &decoded.encode()?)?;
        Ok(decoded)
    }
}

fn write_request_fields(output: &mut Vec<u8>, request: &AgentDecisionRequestV1) {
    write_bytes(output, &request.timeline_id.inner().to_bytes());
    write_uint(output, request.observed_through);
    write_bytes(output, &request.agent_id.inner().to_bytes());
    write_uint(output, request.driver_tick);
    write_bytes(output, &request.catalogue_hash);
    write_bytes(output, &request.provenance.plugin_id.inner().to_bytes());
    write_text(output, &request.provenance.plugin_version);
    write_bytes(output, &request.provenance.plugin_content_hash);
    write_text(output, &request.provenance.provider_id);
    write_text(output, &request.provenance.provider_version);
    write_bytes(output, &request.provenance.provider_content_hash);
}

fn decode_request_fields(values: &[Value]) -> Result<AgentDecisionRequestV1, AgentDecisionError> {
    if values.len() != 11 {
        return Err(AgentDecisionError::MalformedWire);
    }
    let timeline_id = bytes::<16>(values.first())
        .map(Ulid::from)
        .map(TimelineId::from_ulid);
    let observed_through = uint(values.get(1));
    let agent_id = bytes::<16>(values.get(2))
        .map(Ulid::from)
        .map(EntityId::from_ulid);
    let driver_tick = uint(values.get(3));
    let catalogue_hash = bytes::<32>(values.get(4));
    let plugin_id = bytes::<16>(values.get(5))
        .map(Ulid::from)
        .map(PluginId::from_ulid);
    let plugin_version = text(values.get(6));
    let plugin_content_hash = bytes::<32>(values.get(7));
    let provider_id = text(values.get(8));
    let provider_version = text(values.get(9));
    let provider_content_hash = bytes::<32>(values.get(10));

    let (
        Some(timeline_id),
        Some(observed_through),
        Some(agent_id),
        Some(driver_tick),
        Some(catalogue_hash),
    ) = (
        timeline_id,
        observed_through,
        agent_id,
        driver_tick,
        catalogue_hash,
    )
    else {
        return Err(AgentDecisionError::MalformedWire);
    };
    let (
        Some(plugin_id),
        Some(plugin_version),
        Some(plugin_content_hash),
        Some(provider_id),
        Some(provider_version),
        Some(provider_content_hash),
    ) = (
        plugin_id,
        plugin_version,
        plugin_content_hash,
        provider_id,
        provider_version,
        provider_content_hash,
    )
    else {
        return Err(AgentDecisionError::MalformedWire);
    };
    let provenance = AgentProviderProvenanceV1::try_new(
        plugin_id,
        plugin_version.to_owned(),
        plugin_content_hash,
        provider_id.to_owned(),
        provider_version.to_owned(),
        provider_content_hash,
    )
    .map_err(|_| AgentDecisionError::MalformedWire)?;
    Ok(AgentDecisionRequestV1::new(
        timeline_id,
        observed_through,
        agent_id,
        driver_tick,
        catalogue_hash,
        provenance,
    ))
}

fn write_response_digest(output: &mut Vec<u8>, digest: Option<[u8; 32]>) {
    if let Some(digest) = digest {
        write_array(output, 2);
        write_uint(output, 1);
        write_bytes(output, &digest);
    } else {
        write_array(output, 1);
        write_uint(output, 0);
    }
}

fn decode_response_digest(value: Option<&Value>) -> Result<Option<[u8; 32]>, AgentDecisionError> {
    let Some(Value::Array(values)) = value else {
        return Err(AgentDecisionError::MalformedWire);
    };
    match values.as_slice() {
        [kind] if uint(Some(kind)) == Some(0) => Ok(None),
        [kind, digest] if uint(Some(kind)) == Some(1) => bytes::<32>(Some(digest))
            .ok_or(AgentDecisionError::MalformedWire)
            .map(Some),
        _ => Err(AgentDecisionError::MalformedWire),
    }
}

fn write_result(output: &mut Vec<u8>, result: DecisionResultV1) {
    match result {
        DecisionResultV1::Accepted {
            action_index,
            confidence,
        } => {
            write_array(output, 3);
            write_uint(output, 0);
            write_uint(output, u64::from(action_index.get()));
            write_uint(output, u64::from(confidence.get()));
        }
        DecisionResultV1::NoAction(code) => {
            write_array(output, 2);
            write_uint(output, 1);
            write_uint(output, u64::from(code.code()));
        }
    }
}

fn decode_result(value: Option<&Value>) -> Result<DecisionResultV1, AgentDecisionError> {
    let Some(Value::Array(values)) = value else {
        return Err(AgentDecisionError::MalformedWire);
    };
    match values.as_slice() {
        [kind, index, confidence] if uint(Some(kind)) == Some(0) => {
            let index = uint(Some(index))
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(AgentDecisionError::MalformedWire)?;
            let confidence = uint(Some(confidence))
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(AgentDecisionError::MalformedWire)?;
            let action_index =
                ActionIndexV1::try_from(index).map_err(|_| AgentDecisionError::MalformedWire)?;
            let confidence = ConfidencePpmV1::try_from(confidence)
                .map_err(|_| AgentDecisionError::MalformedWire)?;
            Ok(DecisionResultV1::Accepted {
                action_index,
                confidence,
            })
        }
        [kind, code] if uint(Some(kind)) == Some(1) => decode_no_action_code(uint(Some(code))),
        _ => Err(AgentDecisionError::MalformedWire),
    }
}

fn decode_no_action_code(code: Option<u64>) -> Result<DecisionResultV1, AgentDecisionError> {
    let Some(code) = code else {
        return Err(AgentDecisionError::MalformedWire);
    };
    let no_action = match code {
        1 => DecisionNoActionCodeV1::ProviderUnavailable,
        2 => DecisionNoActionCodeV1::ProviderTimeout,
        3 => DecisionNoActionCodeV1::ProviderRejected,
        4 => DecisionNoActionCodeV1::ProviderRateLimited,
        5 => DecisionNoActionCodeV1::ProviderNoAction,
        6 => DecisionNoActionCodeV1::ResponseTooLarge,
        7 => DecisionNoActionCodeV1::ResponseMalformed,
        8 => DecisionNoActionCodeV1::ResponseVersionUnsupported,
        9 => DecisionNoActionCodeV1::ResponseValueInvalid,
        _ => return Err(AgentDecisionError::MalformedWire),
    };
    Ok(DecisionResultV1::NoAction(no_action))
}

fn write_array(output: &mut Vec<u8>, length: usize) {
    write_header(output, 4, u64::try_from(length).unwrap_or(u64::MAX));
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    write_header(output, 2, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    output.extend_from_slice(bytes);
}

fn write_text(output: &mut Vec<u8>, text: &str) {
    write_header(output, 3, u64::try_from(text.len()).unwrap_or(u64::MAX));
    output.extend_from_slice(text.as_bytes());
}

fn write_uint(output: &mut Vec<u8>, value: u64) {
    write_header(output, 0, value);
}

fn write_header(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | u8::try_from(value).unwrap_or(0)),
        24..=255 => {
            output.push(prefix | 0x18);
            output.push(u8::try_from(value).unwrap_or(0));
        }
        256..=65_535 => {
            output.push(prefix | 0x19);
            output.extend_from_slice(&u16::try_from(value).unwrap_or(0).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            output.push(prefix | 0x1a);
            output.extend_from_slice(&u32::try_from(value).unwrap_or(0).to_be_bytes());
        }
        _ => {
            output.push(prefix | 0x1b);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn finish_encoded(output: Vec<u8>, limit: usize) -> Result<Vec<u8>, AgentDecisionError> {
    if output.len() > limit {
        return Err(AgentDecisionError::MalformedWire);
    }
    Ok(output)
}

fn decode_array(input: &[u8], limit: usize) -> Result<Vec<Value>, AgentDecisionError> {
    if input.len() > limit {
        return Err(AgentDecisionError::MalformedWire);
    }
    let mut cursor = Cursor::new(input);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| AgentDecisionError::MalformedWire)?;
    if usize::try_from(cursor.position()).ok() != Some(input.len()) {
        return Err(AgentDecisionError::MalformedWire);
    }
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(AgentDecisionError::MalformedWire),
    }
}

fn canonical_equals(input: &[u8], encoded: &[u8]) -> Result<(), AgentDecisionError> {
    if input != encoded {
        return Err(AgentDecisionError::MalformedWire);
    }
    Ok(())
}

fn matches_magic(value: Option<&Value>, expected: [u8; 4]) -> bool {
    match value {
        Some(Value::Bytes(bytes)) => bytes.as_slice() == expected,
        _ => false,
    }
}

fn uint(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Integer(value)) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn text(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::Text(value)) => Some(value),
        _ => None,
    }
}

fn bytes<const N: usize>(value: Option<&Value>) -> Option<[u8; N]> {
    match value {
        Some(Value::Bytes(value)) => value.as_slice().try_into().ok(),
        _ => None,
    }
}

fn derive_hash(context: &'static str, bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, bytes)
}

fn validate_action_identifier(value: &str) -> Result<(), AgentDecisionError> {
    if !(1..=MAX_ACTION_ID_BYTES).contains(&value.len()) {
        return Err(AgentDecisionError::InvalidActionIdentifierLength);
    }
    if value.chars().any(char::is_control) {
        return Err(AgentDecisionError::InvalidActionIdentifierControlCharacter);
    }
    Ok(())
}

fn validate_provider_identifier(value: &str) -> Result<(), AgentDecisionError> {
    if !(1..=MAX_PROVIDER_ID_BYTES).contains(&value.len()) {
        return Err(AgentDecisionError::InvalidProviderIdentifierLength);
    }

    let bytes = value.as_bytes();
    if !is_provider_edge(bytes[0]) || !is_provider_edge(bytes[bytes.len() - 1]) {
        return Err(AgentDecisionError::InvalidProviderIdentifierGrammar);
    }
    let middle = bytes.get(1..bytes.len() - 1).unwrap_or_default();
    if middle.iter().copied().any(|byte| !is_provider_middle(byte)) {
        return Err(AgentDecisionError::InvalidProviderIdentifierGrammar);
    }
    Ok(())
}

const fn is_provider_edge(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

const fn is_provider_middle(byte: u8) -> bool {
    is_provider_edge(byte) || matches!(byte, b'.' | b'_' | b'-')
}

fn validate_printable_ascii(
    value: &str,
    max_bytes: usize,
    length_error: AgentDecisionError,
    character_error: AgentDecisionError,
) -> Result<(), AgentDecisionError> {
    if !(1..=max_bytes).contains(&value.len()) {
        return Err(length_error);
    }
    if value.bytes().any(|byte| !(b'!'..=b'~').contains(&byte)) {
        return Err(character_error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::ids::PluginId;

    const HASH: [u8; 32] = [7; 32];

    fn provenance(
        provider_id: &str,
        plugin_version: &str,
        provider_version: &str,
    ) -> Result<AgentProviderProvenanceV1, AgentDecisionError> {
        AgentProviderProvenanceV1::try_new(
            PluginId::new(),
            plugin_version.to_owned(),
            HASH,
            provider_id.to_owned(),
            provider_version.to_owned(),
            HASH,
        )
    }

    #[test]
    fn bounded_catalogue_count_and_identifier_lengths() {
        let identifiers = [(0, false), (1, true), (64, true), (65, false)];

        for (count, valid) in identifiers {
            let catalogue = ActionCatalogueV1::try_new(
                (0..count).map(|index| format!("move-{index}")).collect(),
            );
            assert_eq!(catalogue.is_ok(), valid, "catalogue count {count}");
        }

        for (length, valid) in [(0, false), (1, true), (64, true), (65, false)] {
            let catalogue = ActionCatalogueV1::try_new(vec!["a".repeat(length)]);
            assert_eq!(catalogue.is_ok(), valid, "identifier byte length {length}");
        }
    }

    #[test]
    fn bounded_catalogue_rejects_duplicate_and_control_identifiers() {
        assert!(ActionCatalogueV1::try_new(vec!["move".to_owned(), "move".to_owned()]).is_err());

        for control in (0_u8..=0x1f).chain(std::iter::once(0x7f)) {
            let identifier = format!("move{}north", char::from(control));
            assert!(
                ActionCatalogueV1::try_new(vec![identifier]).is_err(),
                "{control:#x}"
            );
        }

        assert!(ActionCatalogueV1::try_new(vec!["move\u{0085}north".to_owned()]).is_err());
        assert!(ActionCatalogueV1::try_new(vec!["møve".to_owned()]).is_ok());
    }

    #[test]
    fn bounded_provenance_text_grammar() {
        for (provider_id, valid) in [
            ("", false),
            ("a", true),
            ("a0", true),
            ("0a", true),
            ("a.b-c_d", true),
            ("a".repeat(64).as_str(), true),
            ("a".repeat(65).as_str(), false),
            ("A", false),
            ("-a", false),
            ("a-", false),
            ("a/a", false),
            ("a/", false),
            ("å", false),
        ] {
            assert_eq!(
                provenance(provider_id, "v", "v").is_ok(),
                valid,
                "{provider_id:?}"
            );
        }

        for (version, valid) in [
            ("", false),
            ("!", true),
            ("~", true),
            (" ", false),
            ("\u{007f}", false),
            ("é", false),
            ("!".repeat(32).as_str(), true),
            ("!".repeat(33).as_str(), false),
        ] {
            assert_eq!(
                provenance("local", version, "v").is_ok(),
                valid,
                "{version:?}"
            );
        }

        for (version, valid) in [
            ("", false),
            ("!".repeat(64).as_str(), true),
            ("!".repeat(65).as_str(), false),
        ] {
            assert_eq!(
                provenance("local", "v", version).is_ok(),
                valid,
                "{version:?}"
            );
        }
    }

    #[test]
    fn bounded_decision_numbers_and_response_bytes() {
        for (confidence, valid) in [(0, true), (1_000_000, true), (1_000_001, false)] {
            assert_eq!(ConfidencePpmV1::try_from(confidence).is_ok(), valid);
        }

        for (index, valid) in [(0, true), (63, true), (64, false)] {
            assert_eq!(ActionIndexV1::try_from(index).is_ok(), valid);
        }

        for (length, valid) in [(0, true), (4096, true), (4097, false)] {
            assert_eq!(
                BoundedProviderBytes::try_from(vec![0; length]).is_ok(),
                valid
            );
        }
    }

    #[test]
    fn bounded_provider_failure_codes_match_authoritative_assignments() {
        for (failure, expected_code) in [
            (ProviderFailureCode::Unavailable, 1),
            (ProviderFailureCode::Timeout, 2),
            (ProviderFailureCode::Rejected, 3),
            (ProviderFailureCode::RateLimited, 4),
        ] {
            assert_eq!(failure.code(), expected_code, "{failure:?}");
        }
    }

    #[test]
    fn bounded_protocol_values_preserve_validated_inputs() {
        let catalogue = ActionCatalogueV1::try_new(vec!["move".to_owned()]).unwrap();
        let provenance = provenance("local-provider", "1.0.0", "2026.08").unwrap();
        let request = AgentDecisionRequestV1::new(
            pos_core::ids::TimelineId::new(),
            0,
            pos_core::ids::EntityId::new(),
            0,
            HASH,
            provenance.clone(),
        );
        let decision = ProviderDecisionV1::accepted(0, 1_000_000).unwrap();
        let record = DecisionRecordV1::new(request, HASH, Some(HASH), decision.into());
        let action = AgentActionV1::try_new("move".to_owned(), 0, 0, HASH, HASH).unwrap();

        assert_eq!(catalogue.action(0), Some("move"));
        assert_eq!(record.response_digest(), Some(HASH));
        assert_eq!(action.action_id(), "move");
        assert_eq!(ProviderFailureCode::Timeout.code(), 2);
        assert!(matches!(
            ProviderAttempt::Oversized {
                response_digest: Some(HASH)
            },
            ProviderAttempt::Oversized { .. }
        ));
    }
}
