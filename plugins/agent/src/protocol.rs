use pos_core::ids::{EntityId, PluginId, TimelineId};
use std::collections::HashSet;
use thiserror::Error;

const MAX_ACTIONS: usize = 64;
const MAX_ACTION_ID_BYTES: usize = 64;
const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_PLUGIN_VERSION_BYTES: usize = 32;
const MAX_PROVIDER_VERSION_BYTES: usize = 64;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 4096;
const MAX_ACTION_INDEX: u8 = 63;
const MAX_CONFIDENCE_PPM: u32 = 1_000_000;

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
