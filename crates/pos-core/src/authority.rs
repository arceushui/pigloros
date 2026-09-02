//! Provider-neutral authority contracts and evaluation (ADR-059).
//!
//! Authentication adapters establish a [`PrincipalRefV1`]. The trusted host
//! then composes subject consent, capability scope, delegation, and revocation
//! through [`AuthorityEvaluatorV1`]. This module selects no authentication
//! provider, bearer-token format, or policy engine and performs no I/O.

use std::{cmp::Ordering, io::Cursor};

use ciborium::Value;

use crate::{CanonicalBytes, EntityId, Hash, PluginId, TimelineId};

const PRINCIPAL_MAGIC: [u8; 4] = *b"PRV1";
const AUTHENTICATED_MAGIC: [u8; 4] = *b"APV1";
const GRANT_MAGIC: [u8; 4] = *b"CPV1";
const DECISION_MAGIC: [u8; 4] = *b"ADV1";
const VERSION: u8 = 1;

/// Capability action required before a child grant may be issued.
pub const DELEGATE_ACTION_V1: &str = "authority.grant.delegate";
/// Maximum UTF-8 length of one authority-domain string.
pub const MAX_AUTHORITY_TEXT_BYTES: usize = 128;
/// Maximum members in any ordered capability-scope set.
pub const MAX_AUTHORITY_SCOPE_MEMBERS: usize = 32;
/// Maximum accepted parent-to-child delegation depth.
pub const MAX_AUTHORITY_DELEGATION_DEPTH: u8 = 16;

/// Closed validation and codec errors for authority records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorityErrorV1 {
    #[error("authority record has the wrong magic")]
    WrongMagic,
    #[error("authority record has the wrong version")]
    WrongVersion,
    #[error("authority record has the wrong array length")]
    WrongArrayLength,
    #[error("authority record contains a field with the wrong type")]
    WrongFieldType,
    #[error("authority record contains trailing bytes")]
    TrailingBytes,
    #[error("authority record is not deterministic CBOR")]
    NonCanonicalEncoding,
    #[error("authority record could not be encoded or decoded")]
    Cbor,
    #[error("authority text is empty or exceeds its bound")]
    InvalidText,
    #[error("authority identity digest must not be zero")]
    ZeroIdentity,
    #[error("authority interval is empty or reversed")]
    InvalidInterval,
    #[error("authority scope is empty or exceeds its bound")]
    InvalidScope,
    #[error("authority set members must be strictly ordered")]
    NonCanonicalOrder,
    #[error("authority delegation depth is invalid")]
    InvalidDelegationDepth,
    #[error("authorization decision digest does not match its fields")]
    DecisionDigestMismatch,
}

/// Stable authorization identity within one trust domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PrincipalRefV1 {
    principal_id: [u8; 16],
    trust_domain: String,
}

impl PrincipalRefV1 {
    /// Construct a stable Principal reference.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::InvalidText`] for an invalid trust domain.
    pub fn try_new(
        principal_id: [u8; 16],
        trust_domain: impl Into<String>,
    ) -> Result<Self, AuthorityErrorV1> {
        let trust_domain = trust_domain.into();
        validate_text(&trust_domain)
            .and_then(|()| {
                if principal_id == [0; 16] {
                    Err(AuthorityErrorV1::ZeroIdentity)
                } else {
                    Ok(())
                }
            })
            .map(|()| Self {
                principal_id,
                trust_domain,
            })
    }

    #[must_use]
    pub const fn principal_id(&self) -> &[u8; 16] {
        &self.principal_id
    }

    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Encode the exact deterministic-CBOR Principal record.
    ///
    /// # Errors
    /// Returns a closed codec error if encoding fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&encode_principal(self)).map(CanonicalBytes::from_vec)
    }

    /// Decode and validate an exact deterministic-CBOR Principal record.
    ///
    /// # Errors
    /// Returns a closed validation or codec error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        decode_array(bytes.as_slice(), 4).and_then(|fields| decode_principal(&fields))
    }
}

/// Adapter assurance is an opaque deployment-defined positive level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceLevelV1(u8);

impl AssuranceLevelV1 {
    /// Construct a non-zero assurance level.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::WrongFieldType`] for zero.
    pub const fn try_new(value: u8) -> Result<Self, AuthorityErrorV1> {
        if value == 0 {
            Err(AuthorityErrorV1::WrongFieldType)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Unvalidated constructor fields for an authenticated-principal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipalDraftV1 {
    pub principal: PrincipalRefV1,
    pub adapter_id: String,
    pub assurance: AssuranceLevelV1,
    pub issued_at_micros: u64,
    pub expires_at_micros: u64,
    pub binding_digest: Hash,
}

/// Minimized evidence emitted by a trusted authentication adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipalResultV1 {
    principal: PrincipalRefV1,
    adapter_id: String,
    assurance: AssuranceLevelV1,
    issued_at_micros: u64,
    expires_at_micros: u64,
    binding_digest: Hash,
}

impl AuthenticatedPrincipalResultV1 {
    /// Validate adapter evidence without retaining credentials or bearer material.
    ///
    /// # Errors
    /// Returns a closed error for invalid text, interval, or identity fields.
    pub fn try_from_draft(draft: AuthenticatedPrincipalDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_text(&draft.adapter_id)
            .and_then(|()| validate_interval(draft.issued_at_micros, draft.expires_at_micros))
            .and_then(|()| validate_hash(draft.binding_digest))
            .map(|()| Self {
                principal: draft.principal,
                adapter_id: draft.adapter_id,
                assurance: draft.assurance,
                issued_at_micros: draft.issued_at_micros,
                expires_at_micros: draft.expires_at_micros,
                binding_digest: draft.binding_digest,
            })
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }

    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    #[must_use]
    pub const fn assurance(&self) -> AssuranceLevelV1 {
        self.assurance
    }

    #[must_use]
    pub const fn issued_at_micros(&self) -> u64 {
        self.issued_at_micros
    }

    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    #[must_use]
    pub const fn binding_digest(&self) -> Hash {
        self.binding_digest
    }

    /// Encode the exact deterministic-CBOR adapter result.
    ///
    /// # Errors
    /// Returns a closed codec error if encoding fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&Value::Array(vec![
            bytes(&AUTHENTICATED_MAGIC),
            uint(VERSION),
            encode_principal(self.principal()),
            text(self.adapter_id()),
            uint(self.assurance.get()),
            uint(self.issued_at_micros),
            uint(self.expires_at_micros),
            hash_value(self.binding_digest),
        ]))
        .map(CanonicalBytes::from_vec)
    }

    /// Decode and validate an exact deterministic-CBOR adapter result.
    ///
    /// # Errors
    /// Returns a closed validation or codec error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        let fields = decode_array(bytes.as_slice(), 8)?;
        expect_header(&fields, AUTHENTICATED_MAGIC)?;
        Self::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: decode_principal_value(&fields[2])?,
            adapter_id: decode_text(&fields[3])?,
            assurance: AssuranceLevelV1::try_new(decode_u8(&fields[4])?)?,
            issued_at_micros: decode_u64(&fields[5])?,
            expires_at_micros: decode_u64(&fields[6])?,
            binding_digest: decode_hash(&fields[7])?,
        })
    }
}

/// Capability recipient. A Plugin installation remains bound to its controlling
/// Principal instead of gaining an ambient identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityGranteeV1 {
    Principal(PrincipalRefV1),
    PluginInstallation {
        controller: PrincipalRefV1,
        plugin_id: PluginId,
        installation_id: [u8; 16],
    },
}

impl AuthorityGranteeV1 {
    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        match self {
            Self::Principal(principal)
            | Self::PluginInstallation {
                controller: principal,
                ..
            } => principal,
        }
    }

    #[must_use]
    pub const fn plugin_id(&self) -> Option<PluginId> {
        match self {
            Self::Principal(_) => None,
            Self::PluginInstallation { plugin_id, .. } => Some(*plugin_id),
        }
    }
}

/// Unvalidated fields for a capability scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityScopeDraftV1 {
    pub resources: Vec<String>,
    pub actions: Vec<String>,
    pub purposes: Vec<String>,
    pub audiences: Vec<String>,
    pub actor_entity_ids: Vec<EntityId>,
    pub participant_ids: Vec<EntityId>,
    pub plugin_id: Option<PluginId>,
    pub max_uses: u64,
    pub budget: u64,
    pub environment_constraints: Vec<String>,
}

/// Exact authority allowed by one grant. Every vector is a strictly ordered set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityScopeV1 {
    resources: Vec<String>,
    actions: Vec<String>,
    purposes: Vec<String>,
    audiences: Vec<String>,
    actor_entity_ids: Vec<EntityId>,
    participant_ids: Vec<EntityId>,
    plugin_id: Option<PluginId>,
    max_uses: u64,
    budget: u64,
    environment_constraints: Vec<String>,
}

impl CapabilityScopeV1 {
    /// Validate a strictly ordered, bounded capability scope.
    ///
    /// # Errors
    /// Returns a closed error for empty required sets, invalid text, or ordering.
    pub fn try_from_draft(draft: CapabilityScopeDraftV1) -> Result<Self, AuthorityErrorV1> {
        let usage_limits = validate_usage_limits(draft.max_uses, draft.budget);
        validate_required_text_set(&draft.resources)
            .and_then(|()| validate_required_text_set(&draft.actions))
            .and_then(|()| validate_required_text_set(&draft.purposes))
            .and_then(|()| validate_required_text_set(&draft.audiences))
            .and_then(|()| validate_ordered_set(&draft.actor_entity_ids, true))
            .and_then(|()| validate_ordered_set(&draft.participant_ids, false))
            .and_then(|()| validate_entity_set(&draft.actor_entity_ids))
            .and_then(|()| validate_entity_set(&draft.participant_ids))
            .and_then(|()| validate_optional_plugin_id(draft.plugin_id))
            .and_then(|()| validate_text_set(&draft.environment_constraints, false))
            .and(usage_limits)
            .map(|()| Self {
                resources: draft.resources,
                actions: draft.actions,
                purposes: draft.purposes,
                audiences: draft.audiences,
                actor_entity_ids: draft.actor_entity_ids,
                participant_ids: draft.participant_ids,
                plugin_id: draft.plugin_id,
                max_uses: draft.max_uses,
                budget: draft.budget,
                environment_constraints: draft.environment_constraints,
            })
    }

    #[must_use]
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    #[must_use]
    pub fn actions(&self) -> &[String] {
        &self.actions
    }

    #[must_use]
    pub fn purposes(&self) -> &[String] {
        &self.purposes
    }

    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    #[must_use]
    pub fn actor_entity_ids(&self) -> &[EntityId] {
        &self.actor_entity_ids
    }

    #[must_use]
    pub fn participant_ids(&self) -> &[EntityId] {
        &self.participant_ids
    }

    #[must_use]
    pub const fn plugin_id(&self) -> Option<PluginId> {
        self.plugin_id
    }

    #[must_use]
    pub const fn max_uses(&self) -> u64 {
        self.max_uses
    }

    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.budget
    }

    #[must_use]
    pub fn environment_constraints(&self) -> &[String] {
        &self.environment_constraints
    }

    fn permits(&self, request: &AuthorizationRequestV1) -> bool {
        let identity_matches = self
            .actor_entity_ids
            .binary_search(&request.actor_entity_id)
            .is_ok();
        let participant_matches = request.participant_id.map_or_else(
            || self.participant_ids.is_empty(),
            |participant| self.participant_ids.binary_search(&participant).is_ok(),
        );
        let usage_is_bounded = request.use_count <= self.max_uses;
        let budget_is_bounded = request.budget <= self.budget;
        let environment_matches = is_subset(
            &self.environment_constraints,
            &request.environment_constraints,
        );
        self.resources.binary_search(&request.resource).is_ok()
            && self.actions.binary_search(&request.action).is_ok()
            && self.purposes.binary_search(&request.purpose).is_ok()
            && self.audiences.binary_search(&request.audience).is_ok()
            && identity_matches
            && participant_matches
            && self.plugin_id == request.plugin_id
            && usage_is_bounded
            && budget_is_bounded
            && environment_matches
    }

    fn is_attenuation_of(&self, parent: &Self) -> bool {
        is_subset(&self.resources, &parent.resources)
            && is_subset(&self.actions, &parent.actions)
            && is_subset(&self.purposes, &parent.purposes)
            && is_subset(&self.audiences, &parent.audiences)
            && is_subset(&self.actor_entity_ids, &parent.actor_entity_ids)
            && is_subset(&self.participant_ids, &parent.participant_ids)
            && plugin_is_attenuated(self.plugin_id, parent.plugin_id)
            && self.max_uses <= parent.max_uses
            && self.budget <= parent.budget
            && is_subset(
                &parent.environment_constraints,
                &self.environment_constraints,
            )
    }
}

/// Unvalidated constructor fields for a capability grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrantDraftV1 {
    pub grant_id: Hash,
    pub grantor: PrincipalRefV1,
    pub grantee: AuthorityGranteeV1,
    pub scope: CapabilityScopeV1,
    pub valid_from_position: u64,
    pub valid_until_position: u64,
    pub parent_grant_id: Option<Hash>,
    pub delegation_depth: u8,
    pub max_delegation_depth: u8,
    pub consent_references: Vec<Hash>,
    pub policy_revision: Hash,
    pub issuance_timeline: TimelineId,
    pub issuance_seq: u64,
    pub revocation_epoch: u64,
    pub revocation_fence: Option<u64>,
}

/// Immutable, provider-neutral capability grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrantV1 {
    grant_id: Hash,
    grantor: PrincipalRefV1,
    grantee: AuthorityGranteeV1,
    scope: CapabilityScopeV1,
    valid_from_position: u64,
    valid_until_position: u64,
    parent_grant_id: Option<Hash>,
    delegation_depth: u8,
    max_delegation_depth: u8,
    consent_references: Vec<Hash>,
    policy_revision: Hash,
    issuance_timeline: TimelineId,
    issuance_seq: u64,
    revocation_epoch: u64,
    revocation_fence: Option<u64>,
}

impl CapabilityGrantV1 {
    /// Validate an immutable capability grant.
    ///
    /// # Errors
    /// Returns a closed error for invalid identity, interval, depth, or consent set.
    pub fn try_from_draft(draft: CapabilityGrantDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_hash(draft.grant_id)
            .and_then(|()| validate_hash(draft.policy_revision))
            .and_then(|()| validate_grantee(&draft.grantee))
            .and_then(|()| validate_timeline_id(draft.issuance_timeline))
            .and_then(|()| validate_interval(draft.valid_from_position, draft.valid_until_position))
            .and_then(|()| validate_optional_hash(draft.parent_grant_id))
            .and_then(|()| validate_hash_set(&draft.consent_references))
            .and_then(|()| validate_delegation_depth(&draft))
            .and_then(|()| {
                if draft.issuance_seq > draft.valid_from_position
                    || draft.revocation_fence.is_some_and(|fence| {
                        fence < draft.valid_from_position || fence > draft.valid_until_position
                    })
                {
                    Err(AuthorityErrorV1::InvalidInterval)
                } else {
                    Ok(())
                }
            })
            .map(|()| Self {
                grant_id: draft.grant_id,
                grantor: draft.grantor,
                grantee: draft.grantee,
                scope: draft.scope,
                valid_from_position: draft.valid_from_position,
                valid_until_position: draft.valid_until_position,
                parent_grant_id: draft.parent_grant_id,
                delegation_depth: draft.delegation_depth,
                max_delegation_depth: draft.max_delegation_depth,
                consent_references: draft.consent_references,
                policy_revision: draft.policy_revision,
                issuance_timeline: draft.issuance_timeline,
                issuance_seq: draft.issuance_seq,
                revocation_epoch: draft.revocation_epoch,
                revocation_fence: draft.revocation_fence,
            })
    }

    #[must_use]
    pub const fn grant_id(&self) -> Hash {
        self.grant_id
    }
    #[must_use]
    pub const fn grantor(&self) -> &PrincipalRefV1 {
        &self.grantor
    }
    #[must_use]
    pub const fn grantee(&self) -> &AuthorityGranteeV1 {
        &self.grantee
    }
    #[must_use]
    pub const fn scope(&self) -> &CapabilityScopeV1 {
        &self.scope
    }
    #[must_use]
    pub const fn valid_from_position(&self) -> u64 {
        self.valid_from_position
    }
    #[must_use]
    pub const fn valid_until_position(&self) -> u64 {
        self.valid_until_position
    }
    #[must_use]
    pub const fn parent_grant_id(&self) -> Option<Hash> {
        self.parent_grant_id
    }
    #[must_use]
    pub const fn delegation_depth(&self) -> u8 {
        self.delegation_depth
    }
    #[must_use]
    pub const fn max_delegation_depth(&self) -> u8 {
        self.max_delegation_depth
    }
    #[must_use]
    pub fn consent_references(&self) -> &[Hash] {
        &self.consent_references
    }
    #[must_use]
    pub const fn policy_revision(&self) -> Hash {
        self.policy_revision
    }
    #[must_use]
    pub const fn issuance_timeline(&self) -> TimelineId {
        self.issuance_timeline
    }
    #[must_use]
    pub const fn issuance_seq(&self) -> u64 {
        self.issuance_seq
    }
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
    #[must_use]
    pub const fn revocation_fence(&self) -> Option<u64> {
        self.revocation_fence
    }

    /// Encode the exact deterministic-CBOR capability grant.
    ///
    /// # Errors
    /// Returns a closed codec error if encoding fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&encode_grant(self)).map(CanonicalBytes::from_vec)
    }

    /// Decode and validate an exact deterministic-CBOR capability grant.
    ///
    /// # Errors
    /// Returns a closed validation or codec error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        decode_array(bytes.as_slice(), 17).and_then(|fields| decode_grant(&fields))
    }
}

/// Consent evidence remains a separate input from capability authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentEvidenceV1 {
    NotRequired,
    Active { reference: Hash },
    Missing,
    RevokedAtFence,
    Expired,
    Indeterminate,
}

/// Unvalidated authorization-request fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequestDraftV1 {
    pub authenticated: AuthenticatedPrincipalResultV1,
    pub actor_entity_id: EntityId,
    pub subject_id: Option<EntityId>,
    pub participant_id: Option<EntityId>,
    pub plugin_id: Option<PluginId>,
    pub resource: String,
    pub action: String,
    pub purpose: String,
    pub audience: String,
    pub at_time_micros: u64,
    pub authority_timeline: TimelineId,
    pub at_position: u64,
    pub use_count: u64,
    pub budget: u64,
    pub policy_revision: Hash,
    pub revocation_epoch: u64,
    pub revocation_state_current: bool,
    pub consent: ConsentEvidenceV1,
    pub environment_constraints: Vec<String>,
}

/// Exact inputs resolved by the host before authority evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequestV1 {
    authenticated: AuthenticatedPrincipalResultV1,
    actor_entity_id: EntityId,
    subject_id: Option<EntityId>,
    participant_id: Option<EntityId>,
    plugin_id: Option<PluginId>,
    resource: String,
    action: String,
    purpose: String,
    audience: String,
    at_time_micros: u64,
    authority_timeline: TimelineId,
    at_position: u64,
    use_count: u64,
    budget: u64,
    policy_revision: Hash,
    revocation_epoch: u64,
    revocation_state_current: bool,
    consent: ConsentEvidenceV1,
    environment_constraints: Vec<String>,
}

impl AuthorizationRequestV1 {
    /// Validate a fully resolved host request.
    ///
    /// # Errors
    /// Returns a closed error for invalid text, identity, counts, or ordering.
    pub fn try_from_draft(draft: AuthorizationRequestDraftV1) -> Result<Self, AuthorityErrorV1> {
        let usage_limits = validate_usage_limits(draft.use_count, draft.budget);
        validate_text(&draft.resource)
            .and_then(|()| validate_text(&draft.action))
            .and_then(|()| validate_text(&draft.purpose))
            .and_then(|()| validate_text(&draft.audience))
            .and_then(|()| validate_hash(draft.policy_revision))
            .and_then(|()| validate_entity_id(draft.actor_entity_id))
            .and_then(|()| validate_optional_entity_id(draft.subject_id))
            .and_then(|()| validate_optional_entity_id(draft.participant_id))
            .and_then(|()| validate_optional_plugin_id(draft.plugin_id))
            .and_then(|()| validate_timeline_id(draft.authority_timeline))
            .and_then(|()| validate_text_set(&draft.environment_constraints, false))
            .and(usage_limits)
            .and_then(|()| match draft.consent {
                ConsentEvidenceV1::Active { reference } => validate_hash(reference),
                _ => Ok(()),
            })
            .map(|()| Self {
                authenticated: draft.authenticated,
                actor_entity_id: draft.actor_entity_id,
                subject_id: draft.subject_id,
                participant_id: draft.participant_id,
                plugin_id: draft.plugin_id,
                resource: draft.resource,
                action: draft.action,
                purpose: draft.purpose,
                audience: draft.audience,
                at_time_micros: draft.at_time_micros,
                authority_timeline: draft.authority_timeline,
                at_position: draft.at_position,
                use_count: draft.use_count,
                budget: draft.budget,
                policy_revision: draft.policy_revision,
                revocation_epoch: draft.revocation_epoch,
                revocation_state_current: draft.revocation_state_current,
                consent: draft.consent,
                environment_constraints: draft.environment_constraints,
            })
    }

    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedPrincipalResultV1 {
        &self.authenticated
    }
    #[must_use]
    pub const fn actor_entity_id(&self) -> EntityId {
        self.actor_entity_id
    }
    #[must_use]
    pub const fn subject_id(&self) -> Option<EntityId> {
        self.subject_id
    }
    #[must_use]
    pub const fn participant_id(&self) -> Option<EntityId> {
        self.participant_id
    }
    #[must_use]
    pub const fn plugin_id(&self) -> Option<PluginId> {
        self.plugin_id
    }
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
    #[must_use]
    pub const fn at_time_micros(&self) -> u64 {
        self.at_time_micros
    }
    #[must_use]
    pub const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }
    #[must_use]
    pub const fn at_position(&self) -> u64 {
        self.at_position
    }
    #[must_use]
    pub const fn use_count(&self) -> u64 {
        self.use_count
    }
    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.budget
    }
    #[must_use]
    pub const fn policy_revision(&self) -> Hash {
        self.policy_revision
    }
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
    #[must_use]
    pub const fn revocation_state_current(&self) -> bool {
        self.revocation_state_current
    }
    #[must_use]
    pub const fn consent(&self) -> ConsentEvidenceV1 {
        self.consent
    }
    #[must_use]
    pub fn environment_constraints(&self) -> &[String] {
        &self.environment_constraints
    }
}

/// Closed authorization result categories from ADR-059.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationOutcomeV1 {
    Active,
    AuthenticationExpired,
    PrincipalMismatch,
    ConsentMissing,
    ConsentRevokedAtFence,
    ConsentExpired,
    CapabilityMissing,
    ScopeMismatch,
    DelegationInvalid,
    ParentInvalid,
    Expired,
    RevokedAtFence,
    RevocationStateStale,
    IndeterminateFailClosed,
}

impl AuthorizationOutcomeV1 {
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Active)
    }

    const fn code(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::AuthenticationExpired => 1,
            Self::PrincipalMismatch => 2,
            Self::ConsentMissing => 3,
            Self::ConsentRevokedAtFence => 4,
            Self::ConsentExpired => 5,
            Self::CapabilityMissing => 6,
            Self::ScopeMismatch => 7,
            Self::DelegationInvalid => 8,
            Self::ParentInvalid => 9,
            Self::Expired => 10,
            Self::RevokedAtFence => 11,
            Self::RevocationStateStale => 12,
            Self::IndeterminateFailClosed => 13,
        }
    }

    const fn from_code(code: u8) -> Result<Self, AuthorityErrorV1> {
        match code {
            0 => Ok(Self::Active),
            1 => Ok(Self::AuthenticationExpired),
            2 => Ok(Self::PrincipalMismatch),
            3 => Ok(Self::ConsentMissing),
            4 => Ok(Self::ConsentRevokedAtFence),
            5 => Ok(Self::ConsentExpired),
            6 => Ok(Self::CapabilityMissing),
            7 => Ok(Self::ScopeMismatch),
            8 => Ok(Self::DelegationInvalid),
            9 => Ok(Self::ParentInvalid),
            10 => Ok(Self::Expired),
            11 => Ok(Self::RevokedAtFence),
            12 => Ok(Self::RevocationStateStale),
            13 => Ok(Self::IndeterminateFailClosed),
            _ => Err(AuthorityErrorV1::WrongFieldType),
        }
    }
}

/// Host-owned immutable answer for one exact request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecisionV1 {
    principal: PrincipalRefV1,
    actor_entity_id: EntityId,
    grant_id: Option<Hash>,
    policy_revision: Hash,
    authority_timeline: TimelineId,
    at_position: u64,
    outcome: AuthorizationOutcomeV1,
    request_digest: Hash,
    decision_digest: Hash,
}

impl AuthorizationDecisionV1 {
    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }
    #[must_use]
    pub const fn actor_entity_id(&self) -> EntityId {
        self.actor_entity_id
    }
    #[must_use]
    pub const fn grant_id(&self) -> Option<Hash> {
        self.grant_id
    }
    #[must_use]
    pub const fn policy_revision(&self) -> Hash {
        self.policy_revision
    }
    #[must_use]
    pub const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }
    #[must_use]
    pub const fn at_position(&self) -> u64 {
        self.at_position
    }
    #[must_use]
    pub const fn outcome(&self) -> AuthorizationOutcomeV1 {
        self.outcome
    }
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }
    #[must_use]
    pub const fn decision_digest(&self) -> Hash {
        self.decision_digest
    }
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.outcome.is_allowed()
    }

    /// Encode the exact deterministic-CBOR authorization decision.
    ///
    /// # Errors
    /// Returns a closed codec error if encoding fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityErrorV1> {
        encode_value(&encode_decision(self)).map(CanonicalBytes::from_vec)
    }

    /// Decode and validate an exact deterministic-CBOR authorization decision.
    ///
    /// # Errors
    /// Returns a closed validation, digest, or codec error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        decode_array(bytes.as_slice(), 11).and_then(|fields| decode_decision(&fields))
    }
}

/// Stateless authority evaluator. Storage and authentication adapters remain outside this seam.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorityEvaluatorV1;

impl AuthorityEvaluatorV1 {
    /// Evaluate adapter evidence, consent, capability, delegation, and revocation
    /// in ADR-059 order and return a closed decision.
    #[must_use]
    pub fn authorize(
        request: &AuthorizationRequestV1,
        grant_chain: &[CapabilityGrantV1],
    ) -> AuthorizationDecisionV1 {
        let outcome = authorization_outcome(request, grant_chain);
        let grant_id = grant_chain.last().map(CapabilityGrantV1::grant_id);
        let request_digest = request_digest(request);
        let mut decision = AuthorizationDecisionV1 {
            principal: request.authenticated.principal.clone(),
            actor_entity_id: request.actor_entity_id,
            grant_id,
            policy_revision: request.policy_revision,
            authority_timeline: request.authority_timeline,
            at_position: request.at_position,
            outcome,
            request_digest,
            decision_digest: Hash::zero(),
        };
        decision.decision_digest = decision_digest(&decision);
        decision
    }
}

fn authorization_outcome(
    request: &AuthorizationRequestV1,
    grant_chain: &[CapabilityGrantV1],
) -> AuthorizationOutcomeV1 {
    if request.at_time_micros < request.authenticated.issued_at_micros
        || request.at_time_micros >= request.authenticated.expires_at_micros
    {
        return AuthorizationOutcomeV1::AuthenticationExpired;
    }
    let consent_outcome = evaluate_consent(request);
    if consent_outcome != AuthorizationOutcomeV1::Active {
        return consent_outcome;
    }
    let Some(leaf) = grant_chain.last() else {
        return AuthorizationOutcomeV1::CapabilityMissing;
    };
    if leaf.grantee.principal() != request.authenticated.principal() {
        return AuthorizationOutcomeV1::PrincipalMismatch;
    }
    if !leaf.scope.permits(request) {
        return AuthorizationOutcomeV1::ScopeMismatch;
    }
    match validate_delegation_chain(request, grant_chain) {
        ChainValidity::Valid => {}
        ChainValidity::DelegationInvalid => {
            return AuthorizationOutcomeV1::DelegationInvalid;
        }
        ChainValidity::ParentInvalid => return AuthorizationOutcomeV1::ParentInvalid,
    }
    if !request.revocation_state_current {
        return AuthorizationOutcomeV1::RevocationStateStale;
    }
    let timeline_is_current = request.authority_timeline == leaf.issuance_timeline;
    let revocation_epoch_is_current = request.revocation_epoch == leaf.revocation_epoch;
    let policy_is_current = request.policy_revision == leaf.policy_revision;
    if !timeline_is_current || !revocation_epoch_is_current || !policy_is_current {
        return AuthorizationOutcomeV1::IndeterminateFailClosed;
    }
    match validate_temporal_chain(request, grant_chain) {
        TemporalValidity::Valid => AuthorizationOutcomeV1::Active,
        TemporalValidity::Expired => AuthorizationOutcomeV1::Expired,
        TemporalValidity::RevokedAtFence => AuthorizationOutcomeV1::RevokedAtFence,
    }
}

const fn evaluate_consent(request: &AuthorizationRequestV1) -> AuthorizationOutcomeV1 {
    if request.subject_id.is_none() {
        return match request.consent {
            ConsentEvidenceV1::Indeterminate => AuthorizationOutcomeV1::IndeterminateFailClosed,
            _ => AuthorizationOutcomeV1::Active,
        };
    }
    match request.consent {
        ConsentEvidenceV1::Active { .. } => AuthorizationOutcomeV1::Active,
        ConsentEvidenceV1::Missing | ConsentEvidenceV1::NotRequired => {
            AuthorizationOutcomeV1::ConsentMissing
        }
        ConsentEvidenceV1::RevokedAtFence => AuthorizationOutcomeV1::ConsentRevokedAtFence,
        ConsentEvidenceV1::Expired => AuthorizationOutcomeV1::ConsentExpired,
        ConsentEvidenceV1::Indeterminate => AuthorizationOutcomeV1::IndeterminateFailClosed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainValidity {
    Valid,
    DelegationInvalid,
    ParentInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemporalValidity {
    Valid,
    Expired,
    RevokedAtFence,
}

fn validate_delegation_chain(
    request: &AuthorizationRequestV1,
    chain: &[CapabilityGrantV1],
) -> ChainValidity {
    let mut previous: Option<&CapabilityGrantV1> = None;
    let mut seen_grants = Vec::with_capacity(chain.len());
    for (index, grant) in chain.iter().enumerate() {
        if seen_grants.contains(&grant.grant_id) {
            return ChainValidity::DelegationInvalid;
        }
        seen_grants.push(grant.grant_id);
        let is_leaf = index + 1 == chain.len();
        let parent_timeline_is_current = grant.issuance_timeline == request.authority_timeline;
        let parent_policy_is_current = grant.policy_revision == request.policy_revision;
        let parent_revocation_is_current = grant.revocation_epoch == request.revocation_epoch;
        if !is_leaf
            && (!parent_timeline_is_current
                || !parent_policy_is_current
                || !parent_revocation_is_current)
        {
            return ChainValidity::ParentInvalid;
        }
        if request.subject_id.is_some() && !grant_covers_consent(grant, request.consent) {
            return ChainValidity::ParentInvalid;
        }
        if let Some(parent) = previous {
            if !valid_child(parent, grant) {
                return ChainValidity::DelegationInvalid;
            }
        } else if grant.parent_grant_id.is_some() || grant.delegation_depth != 0 {
            return ChainValidity::ParentInvalid;
        }
        previous = Some(grant);
    }
    ChainValidity::Valid
}

fn validate_temporal_chain(
    request: &AuthorizationRequestV1,
    chain: &[CapabilityGrantV1],
) -> TemporalValidity {
    for grant in chain {
        if request.at_position < grant.valid_from_position
            || request.at_position >= grant.valid_until_position
        {
            return TemporalValidity::Expired;
        }
        if grant
            .revocation_fence
            .is_some_and(|fence| request.at_position >= fence)
        {
            return TemporalValidity::RevokedAtFence;
        }
    }
    TemporalValidity::Valid
}

fn valid_child(parent: &CapabilityGrantV1, child: &CapabilityGrantV1) -> bool {
    let depth_is_next = child.delegation_depth == parent.delegation_depth.saturating_add(1);
    let depth_is_bounded = child.delegation_depth <= parent.max_delegation_depth;
    let descendants_are_bounded = child.max_delegation_depth <= parent.max_delegation_depth;
    let grantor_is_delegate = matches!(
        &parent.grantee,
        AuthorityGranteeV1::Principal(principal) if child.grantor == *principal
    );
    child.parent_grant_id == Some(parent.grant_id)
        && depth_is_next
        && depth_is_bounded
        && descendants_are_bounded
        && grantor_is_delegate
        && parent
            .scope
            .actions
            .binary_search_by(|action| action.as_str().cmp(DELEGATE_ACTION_V1))
            .is_ok()
        && child.scope.is_attenuation_of(&parent.scope)
        && child.valid_from_position >= parent.valid_from_position
        && child.valid_until_position <= parent.valid_until_position
        && is_subset(&child.consent_references, &parent.consent_references)
}

fn grant_covers_consent(grant: &CapabilityGrantV1, evidence: ConsentEvidenceV1) -> bool {
    match evidence {
        ConsentEvidenceV1::Active { reference } => {
            grant.consent_references.binary_search(&reference).is_ok()
        }
        _ => false,
    }
}

fn plugin_is_attenuated(child: Option<PluginId>, parent: Option<PluginId>) -> bool {
    child == parent
}

fn is_subset<T: Ord>(child: &[T], parent: &[T]) -> bool {
    child
        .iter()
        .all(|value| parent.binary_search(value).is_ok())
}

const fn validate_text(value: &str) -> Result<(), AuthorityErrorV1> {
    if value.is_empty() || value.len() > MAX_AUTHORITY_TEXT_BYTES {
        Err(AuthorityErrorV1::InvalidText)
    } else {
        Ok(())
    }
}

fn validate_required_text_set(values: &[String]) -> Result<(), AuthorityErrorV1> {
    validate_text_set(values, true)
}

fn validate_text_set(values: &[String], required: bool) -> Result<(), AuthorityErrorV1> {
    validate_ordered_set(values, required)
        .and_then(|()| values.iter().try_for_each(|value| validate_text(value)))
}

fn validate_ordered_set<T: Ord>(values: &[T], required: bool) -> Result<(), AuthorityErrorV1> {
    if values.len() > MAX_AUTHORITY_SCOPE_MEMBERS || (required && values.is_empty()) {
        return Err(AuthorityErrorV1::InvalidScope);
    }
    if values
        .windows(2)
        .all(|pair| pair[0].cmp(&pair[1]) == Ordering::Less)
    {
        Ok(())
    } else {
        Err(AuthorityErrorV1::NonCanonicalOrder)
    }
}

fn validate_hash(value: Hash) -> Result<(), AuthorityErrorV1> {
    if value == Hash::zero() {
        Err(AuthorityErrorV1::ZeroIdentity)
    } else {
        Ok(())
    }
}

fn validate_optional_hash(value: Option<Hash>) -> Result<(), AuthorityErrorV1> {
    value.map_or(Ok(()), validate_hash)
}

fn validate_hash_set(values: &[Hash]) -> Result<(), AuthorityErrorV1> {
    validate_ordered_set(values, false)
        .and_then(|()| values.iter().copied().try_for_each(validate_hash))
}

fn validate_entity_set(values: &[EntityId]) -> Result<(), AuthorityErrorV1> {
    values.iter().copied().try_for_each(validate_entity_id)
}

fn validate_entity_id(value: EntityId) -> Result<(), AuthorityErrorV1> {
    if value.inner() == ulid::Ulid::nil() {
        Err(AuthorityErrorV1::ZeroIdentity)
    } else {
        Ok(())
    }
}

fn validate_optional_entity_id(value: Option<EntityId>) -> Result<(), AuthorityErrorV1> {
    value.map_or(Ok(()), validate_entity_id)
}

fn validate_optional_plugin_id(value: Option<PluginId>) -> Result<(), AuthorityErrorV1> {
    value.map_or(Ok(()), |plugin| {
        if plugin.inner() == ulid::Ulid::nil() {
            Err(AuthorityErrorV1::ZeroIdentity)
        } else {
            Ok(())
        }
    })
}

fn validate_timeline_id(value: TimelineId) -> Result<(), AuthorityErrorV1> {
    if value.inner() == ulid::Ulid::nil() {
        Err(AuthorityErrorV1::ZeroIdentity)
    } else {
        Ok(())
    }
}

fn validate_grantee(value: &AuthorityGranteeV1) -> Result<(), AuthorityErrorV1> {
    match value {
        AuthorityGranteeV1::Principal(_) => Ok(()),
        AuthorityGranteeV1::PluginInstallation {
            plugin_id,
            installation_id,
            ..
        } => validate_optional_plugin_id(Some(*plugin_id)).and_then(|()| {
            if *installation_id == [0; 16] {
                Err(AuthorityErrorV1::ZeroIdentity)
            } else {
                Ok(())
            }
        }),
    }
}

const fn validate_interval(start: u64, end: u64) -> Result<(), AuthorityErrorV1> {
    if start < end {
        Ok(())
    } else {
        Err(AuthorityErrorV1::InvalidInterval)
    }
}

const fn validate_delegation_depth(draft: &CapabilityGrantDraftV1) -> Result<(), AuthorityErrorV1> {
    if draft.max_delegation_depth > MAX_AUTHORITY_DELEGATION_DEPTH
        || draft.delegation_depth > draft.max_delegation_depth
        || (draft.delegation_depth == 0) != draft.parent_grant_id.is_none()
    {
        Err(AuthorityErrorV1::InvalidDelegationDepth)
    } else {
        Ok(())
    }
}

const fn validate_usage_limits(max_uses: u64, budget: u64) -> Result<(), AuthorityErrorV1> {
    if max_uses == 0 || budget == 0 {
        Err(AuthorityErrorV1::InvalidScope)
    } else {
        Ok(())
    }
}

fn request_digest(request: &AuthorizationRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.AuthorizationRequest.v1\0");
    digest_part(&mut hasher, request.authenticated.principal.principal_id());
    digest_part(
        &mut hasher,
        request.authenticated.principal.trust_domain().as_bytes(),
    );
    digest_part(&mut hasher, &entity_bytes(request.actor_entity_id));
    digest_optional_entity(&mut hasher, request.subject_id);
    digest_optional_entity(&mut hasher, request.participant_id);
    digest_optional_plugin(&mut hasher, request.plugin_id);
    digest_part(&mut hasher, request.resource.as_bytes());
    digest_part(&mut hasher, request.action.as_bytes());
    digest_part(&mut hasher, request.purpose.as_bytes());
    digest_part(&mut hasher, request.audience.as_bytes());
    hasher.update(&request.at_time_micros.to_be_bytes());
    hasher.update(&timeline_bytes(request.authority_timeline));
    hasher.update(&request.at_position.to_be_bytes());
    hasher.update(&request.use_count.to_be_bytes());
    hasher.update(&request.budget.to_be_bytes());
    hasher.update(request.policy_revision.as_bytes());
    hasher.update(&request.revocation_epoch.to_be_bytes());
    hasher.update(&[u8::from(request.revocation_state_current)]);
    digest_consent(&mut hasher, request.consent);
    for constraint in &request.environment_constraints {
        digest_part(&mut hasher, constraint.as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn decision_digest(decision: &AuthorizationDecisionV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.AuthorizationDecision.v1\0");
    digest_part(&mut hasher, decision.principal.principal_id());
    digest_part(&mut hasher, decision.principal.trust_domain().as_bytes());
    hasher.update(&entity_bytes(decision.actor_entity_id));
    digest_optional_hash(&mut hasher, decision.grant_id);
    hasher.update(decision.policy_revision.as_bytes());
    hasher.update(&timeline_bytes(decision.authority_timeline));
    hasher.update(&decision.at_position.to_be_bytes());
    hasher.update(&[decision.outcome.code()]);
    hasher.update(decision.request_digest.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn digest_part(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn digest_optional_entity(hasher: &mut blake3::Hasher, value: Option<EntityId>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(entity) => {
            hasher.update(&[1]);
            hasher.update(&entity_bytes(entity));
        }
    }
}

fn digest_optional_plugin(hasher: &mut blake3::Hasher, value: Option<PluginId>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(plugin) => {
            hasher.update(&[1]);
            hasher.update(&plugin_bytes(plugin));
        }
    }
}

fn digest_optional_hash(hasher: &mut blake3::Hasher, value: Option<Hash>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(hash) => {
            hasher.update(&[1]);
            hasher.update(hash.as_bytes());
        }
    }
}

fn digest_consent(hasher: &mut blake3::Hasher, consent: ConsentEvidenceV1) {
    match consent {
        ConsentEvidenceV1::NotRequired => {
            hasher.update(&[0]);
        }
        ConsentEvidenceV1::Active { reference } => {
            hasher.update(&[1]);
            hasher.update(reference.as_bytes());
        }
        ConsentEvidenceV1::Missing => {
            hasher.update(&[2]);
        }
        ConsentEvidenceV1::RevokedAtFence => {
            hasher.update(&[3]);
        }
        ConsentEvidenceV1::Expired => {
            hasher.update(&[4]);
        }
        ConsentEvidenceV1::Indeterminate => {
            hasher.update(&[5]);
        }
    }
}

fn entity_bytes(value: EntityId) -> [u8; 16] {
    let raw: u128 = value.inner().into();
    raw.to_be_bytes()
}

fn plugin_bytes(value: PluginId) -> [u8; 16] {
    let raw: u128 = value.inner().into();
    raw.to_be_bytes()
}

fn timeline_bytes(value: TimelineId) -> [u8; 16] {
    let raw: u128 = value.inner().into();
    raw.to_be_bytes()
}

fn encode_value(value: &Value) -> Result<Vec<u8>, AuthorityErrorV1> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)
        .map_err(|_| AuthorityErrorV1::Cbor)
        .map(|()| encoded)
}

fn decode_array(bytes: &[u8], expected_len: usize) -> Result<Vec<Value>, AuthorityErrorV1> {
    let mut cursor = Cursor::new(bytes);
    ciborium::from_reader(&mut cursor)
        .map_err(|_| AuthorityErrorV1::Cbor)
        .and_then(|value| {
            if cursor.position() != bytes.len() as u64 {
                return Err(AuthorityErrorV1::TrailingBytes);
            }
            encode_value(&value).and_then(|canonical| {
                if canonical != bytes {
                    return Err(AuthorityErrorV1::NonCanonicalEncoding);
                }
                match value {
                    Value::Array(fields) if fields.len() == expected_len => Ok(fields),
                    Value::Array(_) => Err(AuthorityErrorV1::WrongArrayLength),
                    _ => Err(AuthorityErrorV1::WrongFieldType),
                }
            })
        })
}

fn expect_header(fields: &[Value], magic: [u8; 4]) -> Result<(), AuthorityErrorV1> {
    match &fields[0] {
        Value::Bytes(value) if value.as_slice() == magic => {
            decode_u8(&fields[1]).and_then(|version| {
                if version == VERSION {
                    Ok(())
                } else {
                    Err(AuthorityErrorV1::WrongVersion)
                }
            })
        }
        _ => Err(AuthorityErrorV1::WrongMagic),
    }
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn uint<T: Into<ciborium::value::Integer>>(value: T) -> Value {
    Value::Integer(value.into())
}
fn hash_value(value: Hash) -> Value {
    bytes(value.as_bytes())
}
fn optional_hash_value(value: Option<Hash>) -> Value {
    value.map_or(Value::Null, hash_value)
}
fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Null, uint)
}
fn optional_plugin_value(value: Option<PluginId>) -> Value {
    value.map_or(Value::Null, |plugin| bytes(&plugin_bytes(plugin)))
}

fn encode_principal(value: &PrincipalRefV1) -> Value {
    Value::Array(vec![
        bytes(&PRINCIPAL_MAGIC),
        uint(VERSION),
        bytes(value.principal_id()),
        text(value.trust_domain()),
    ])
}

fn decode_principal(fields: &[Value]) -> Result<PrincipalRefV1, AuthorityErrorV1> {
    expect_header(fields, PRINCIPAL_MAGIC).and_then(|()| {
        decode_fixed::<16>(&fields[2]).and_then(|principal_id| {
            decode_text(&fields[3])
                .and_then(|trust_domain| PrincipalRefV1::try_new(principal_id, trust_domain))
        })
    })
}

fn decode_principal_value(value: &Value) -> Result<PrincipalRefV1, AuthorityErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == 4 => decode_principal(fields),
        Value::Array(_) => Err(AuthorityErrorV1::WrongArrayLength),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}

fn exact_array(value: &Value, expected_len: usize) -> Result<&[Value], AuthorityErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == expected_len => Ok(fields),
        Value::Array(_) => Err(AuthorityErrorV1::WrongArrayLength),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}

fn encode_grantee(value: &AuthorityGranteeV1) -> Value {
    match value {
        AuthorityGranteeV1::Principal(principal) => {
            Value::Array(vec![uint(0u8), encode_principal(principal)])
        }
        AuthorityGranteeV1::PluginInstallation {
            controller,
            plugin_id,
            installation_id,
        } => Value::Array(vec![
            uint(1u8),
            encode_principal(controller),
            bytes(&plugin_bytes(*plugin_id)),
            bytes(installation_id),
        ]),
    }
}

fn decode_grantee(value: &Value) -> Result<AuthorityGranteeV1, AuthorityErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == 2 => decode_u8(&fields[0]).and_then(|tag| {
            if tag == 0 {
                decode_principal_value(&fields[1]).map(AuthorityGranteeV1::Principal)
            } else {
                Err(AuthorityErrorV1::WrongFieldType)
            }
        }),
        Value::Array(fields) if fields.len() == 4 => decode_u8(&fields[0]).and_then(|tag| {
            if tag != 1 {
                return Err(AuthorityErrorV1::WrongFieldType);
            }
            decode_principal_value(&fields[1]).and_then(|controller| {
                decode_plugin(&fields[2]).and_then(|plugin_id| {
                    decode_fixed::<16>(&fields[3]).map(|installation_id| {
                        AuthorityGranteeV1::PluginInstallation {
                            controller,
                            plugin_id,
                            installation_id,
                        }
                    })
                })
            })
        }),
        Value::Array(_) => Err(AuthorityErrorV1::WrongArrayLength),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}

fn encode_string_set(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| text(value)).collect())
}
fn encode_entity_set(values: &[EntityId]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| bytes(&entity_bytes(*value)))
            .collect(),
    )
}
fn encode_hash_set(values: &[Hash]) -> Value {
    Value::Array(values.iter().map(|value| hash_value(*value)).collect())
}

fn encode_scope(value: &CapabilityScopeV1) -> Value {
    Value::Array(vec![
        encode_string_set(value.resources()),
        encode_string_set(value.actions()),
        encode_string_set(value.purposes()),
        encode_string_set(value.audiences()),
        encode_entity_set(value.actor_entity_ids()),
        encode_entity_set(value.participant_ids()),
        optional_plugin_value(value.plugin_id()),
        uint(value.max_uses()),
        uint(value.budget()),
        encode_string_set(value.environment_constraints()),
    ])
}

fn decode_scope(value: &Value) -> Result<CapabilityScopeV1, AuthorityErrorV1> {
    let fields = exact_array(value, 10)?;
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: decode_string_set(&fields[0])?,
        actions: decode_string_set(&fields[1])?,
        purposes: decode_string_set(&fields[2])?,
        audiences: decode_string_set(&fields[3])?,
        actor_entity_ids: decode_entity_set(&fields[4])?,
        participant_ids: decode_entity_set(&fields[5])?,
        plugin_id: decode_optional_plugin(&fields[6])?,
        max_uses: decode_u64(&fields[7])?,
        budget: decode_u64(&fields[8])?,
        environment_constraints: decode_string_set(&fields[9])?,
    })
}

fn encode_grant(value: &CapabilityGrantV1) -> Value {
    Value::Array(vec![
        bytes(&GRANT_MAGIC),
        uint(VERSION),
        hash_value(value.grant_id),
        encode_principal(&value.grantor),
        encode_grantee(&value.grantee),
        encode_scope(&value.scope),
        uint(value.valid_from_position),
        uint(value.valid_until_position),
        optional_hash_value(value.parent_grant_id),
        uint(value.delegation_depth),
        uint(value.max_delegation_depth),
        encode_hash_set(&value.consent_references),
        hash_value(value.policy_revision),
        bytes(&timeline_bytes(value.issuance_timeline)),
        uint(value.issuance_seq),
        uint(value.revocation_epoch),
        optional_u64_value(value.revocation_fence),
    ])
}

fn decode_grant(fields: &[Value]) -> Result<CapabilityGrantV1, AuthorityErrorV1> {
    expect_header(fields, GRANT_MAGIC)?;
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: decode_hash(&fields[2])?,
        grantor: decode_principal_value(&fields[3])?,
        grantee: decode_grantee(&fields[4])?,
        scope: decode_scope(&fields[5])?,
        valid_from_position: decode_u64(&fields[6])?,
        valid_until_position: decode_u64(&fields[7])?,
        parent_grant_id: decode_optional_hash(&fields[8])?,
        delegation_depth: decode_u8(&fields[9])?,
        max_delegation_depth: decode_u8(&fields[10])?,
        consent_references: decode_hash_set(&fields[11])?,
        policy_revision: decode_hash(&fields[12])?,
        issuance_timeline: decode_timeline(&fields[13])?,
        issuance_seq: decode_u64(&fields[14])?,
        revocation_epoch: decode_u64(&fields[15])?,
        revocation_fence: decode_optional_u64(&fields[16])?,
    })
}

fn encode_decision(value: &AuthorizationDecisionV1) -> Value {
    Value::Array(vec![
        bytes(&DECISION_MAGIC),
        uint(VERSION),
        encode_principal(&value.principal),
        bytes(&entity_bytes(value.actor_entity_id)),
        optional_hash_value(value.grant_id),
        hash_value(value.policy_revision),
        bytes(&timeline_bytes(value.authority_timeline)),
        uint(value.at_position),
        uint(value.outcome.code()),
        hash_value(value.request_digest),
        hash_value(value.decision_digest),
    ])
}

fn decode_decision(fields: &[Value]) -> Result<AuthorizationDecisionV1, AuthorityErrorV1> {
    expect_header(fields, DECISION_MAGIC)?;
    let decoded = AuthorizationDecisionV1 {
        principal: decode_principal_value(&fields[2])?,
        actor_entity_id: decode_entity(&fields[3])?,
        grant_id: decode_optional_hash(&fields[4])?,
        policy_revision: decode_hash(&fields[5])?,
        authority_timeline: decode_timeline(&fields[6])?,
        at_position: decode_u64(&fields[7])?,
        outcome: AuthorizationOutcomeV1::from_code(decode_u8(&fields[8])?)?,
        request_digest: decode_hash(&fields[9])?,
        decision_digest: decode_hash(&fields[10])?,
    };
    validate_hash(decoded.policy_revision)?;
    validate_hash(decoded.request_digest)?;
    validate_hash(decoded.decision_digest)?;
    if decision_digest(&decoded) == decoded.decision_digest {
        Ok(decoded)
    } else {
        Err(AuthorityErrorV1::DecisionDigestMismatch)
    }
}

fn decode_text(value: &Value) -> Result<String, AuthorityErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
fn decode_u8(value: &Value) -> Result<u8, AuthorityErrorV1> {
    match value {
        Value::Integer(value) => u8::try_from(*value).map_err(|_| AuthorityErrorV1::WrongFieldType),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
fn decode_u64(value: &Value) -> Result<u64, AuthorityErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| AuthorityErrorV1::WrongFieldType)
        }
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
fn decode_fixed<const N: usize>(value: &Value) -> Result<[u8; N], AuthorityErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityErrorV1::WrongFieldType),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
fn decode_hash(value: &Value) -> Result<Hash, AuthorityErrorV1> {
    decode_fixed::<32>(value).map(Hash::from_bytes)
}
fn decode_optional_hash(value: &Value) -> Result<Option<Hash>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_hash(value).map(Some),
    }
}
fn decode_optional_u64(value: &Value) -> Result<Option<u64>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_u64(value).map(Some),
    }
}
fn decode_entity(value: &Value) -> Result<EntityId, AuthorityErrorV1> {
    decode_fixed::<16>(value)
        .map(|raw| EntityId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(raw))))
}
fn decode_plugin(value: &Value) -> Result<PluginId, AuthorityErrorV1> {
    decode_fixed::<16>(value)
        .map(|raw| PluginId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(raw))))
}
fn decode_optional_plugin(value: &Value) -> Result<Option<PluginId>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_plugin(value).map(Some),
    }
}
fn decode_timeline(value: &Value) -> Result<TimelineId, AuthorityErrorV1> {
    decode_fixed::<16>(value)
        .map(|raw| TimelineId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(raw))))
}
fn decode_string_set(value: &Value) -> Result<Vec<String>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_text).collect(),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
fn decode_entity_set(value: &Value) -> Result<Vec<EntityId>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_entity).collect(),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
fn decode_hash_set(value: &Value) -> Result<Vec<Hash>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_hash).collect(),
        _ => Err(AuthorityErrorV1::WrongFieldType),
    }
}
