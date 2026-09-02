//! Provider-neutral authority contracts and evaluation (ADR-059).
//!
//! Authentication adapters establish a [`PrincipalRefV1`]. The trusted host
//! then composes subject consent, capability scope, delegation, and revocation
//! through [`AuthorityEvaluatorV1`]. This module selects no authentication
//! provider, bearer-token format, or policy engine and performs no I/O.

use std::{cmp::Ordering, io::Cursor};

use ciborium::Value;

use crate::{CanonicalBytes, EntityId, Hash, PluginId, Seq, TimelineId, WallTime};

const PRINCIPAL_MAGIC: [u8; 4] = *b"PRN1";
const GRANT_MAGIC: [u8; 4] = *b"CPG1";
const DECISION_MAGIC: [u8; 4] = *b"AUD1";
const VERSION: u8 = 1;

const MAX_PRINCIPAL_RECORD_BYTES: usize = 1_024;
const MAX_CAPABILITY_RECORD_BYTES: usize = 64 * 1_024;
const MAX_DECISION_RECORD_BYTES: usize = 64 * 1_024;

/// Capability action required before a child grant may be issued.
pub const DELEGATE_ACTION_V1: &str = "authority.grant.delegate";
/// Maximum UTF-8 length of one authority-domain string.
pub const MAX_AUTHORITY_TEXT_BYTES: usize = 128;
/// Maximum members in any ordered capability-scope set.
pub const MAX_AUTHORITY_SCOPE_MEMBERS: usize = 32;
/// Maximum resource selectors or actions in one capability scope.
pub const MAX_AUTHORITY_SELECTORS: usize = 128;
/// Maximum accepted parent-to-child delegation depth.
pub const MAX_AUTHORITY_DELEGATION_DEPTH: u8 = 16;

/// Closed validation and codec errors for authority records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorityErrorV1 {
    #[error("authority record encoding is invalid")]
    InvalidEncoding,
    #[error("authority record version is unsupported")]
    UnsupportedVersion,
    #[error("authority field is outside its public bound")]
    FieldOutOfBounds,
    #[error("authority record contains an unknown enum value")]
    UnknownEnum,
    #[error("authority policy could not produce a trustworthy answer")]
    PolicyIndeterminate,
    #[error("authority digest does not match its bound fields")]
    DigestMismatch,
    #[error("authority set members must be strictly ordered")]
    NonCanonicalOrder,
    #[error("authority record contains a duplicate identity")]
    DuplicateIdentity,
    #[error("principal could not be resolved by the trusted host")]
    PrincipalUnresolved,
    #[error("required consent is missing")]
    ConsentMissing,
    #[error("required capability is missing")]
    CapabilityMissing,
    #[error("delegation is invalid")]
    DelegationInvalid,
    #[error("authority was revoked at the evaluation fence")]
    RevokedAtFence,
    #[error("revocation state is stale")]
    RevocationStateStale,
    #[error("authority source is unavailable")]
    SourceUnavailable,
    #[error("authority source is unauthorized")]
    UnauthorizedSource,
    #[error("required provenance is missing")]
    ProvenanceMissing,
    #[error("authority evaluation exceeded its budget")]
    BudgetExceeded,
    #[error("non-interference evaluation diverged")]
    NonInterferenceDivergence,
}

impl AuthorityErrorV1 {
    /// Return the stable AUD1 safe-error code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidEncoding => 0,
            Self::UnsupportedVersion => 1,
            Self::FieldOutOfBounds => 2,
            Self::UnknownEnum => 3,
            Self::NonCanonicalOrder => 4,
            Self::DuplicateIdentity => 5,
            Self::PrincipalUnresolved => 6,
            Self::ConsentMissing => 7,
            Self::CapabilityMissing => 8,
            Self::DelegationInvalid => 9,
            Self::RevokedAtFence => 10,
            Self::RevocationStateStale => 11,
            Self::PolicyIndeterminate => 12,
            Self::SourceUnavailable => 13,
            Self::UnauthorizedSource => 14,
            Self::ProvenanceMissing => 15,
            Self::DigestMismatch => 16,
            Self::BudgetExceeded => 17,
            Self::NonInterferenceDivergence => 18,
        }
    }

    /// Decode one stable AUD1 safe-error code.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::UnknownEnum`] for an unknown code.
    pub const fn from_code(code: u8) -> Result<Self, Self> {
        match code {
            0 => Ok(Self::InvalidEncoding),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::FieldOutOfBounds),
            3 => Ok(Self::UnknownEnum),
            4 => Ok(Self::NonCanonicalOrder),
            5 => Ok(Self::DuplicateIdentity),
            6 => Ok(Self::PrincipalUnresolved),
            7 => Ok(Self::ConsentMissing),
            8 => Ok(Self::CapabilityMissing),
            9 => Ok(Self::DelegationInvalid),
            10 => Ok(Self::RevokedAtFence),
            11 => Ok(Self::RevocationStateStale),
            12 => Ok(Self::PolicyIndeterminate),
            13 => Ok(Self::SourceUnavailable),
            14 => Ok(Self::UnauthorizedSource),
            15 => Ok(Self::ProvenanceMissing),
            16 => Ok(Self::DigestMismatch),
            17 => Ok(Self::BudgetExceeded),
            18 => Ok(Self::NonInterferenceDivergence),
            _ => Err(Self::UnknownEnum),
        }
    }
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
    /// Returns [`AuthorityErrorV1::FieldOutOfBounds`] for an invalid trust domain.
    pub fn try_new(
        principal_id: [u8; 16],
        trust_domain: impl Into<String>,
    ) -> Result<Self, AuthorityErrorV1> {
        let trust_domain = trust_domain.into();
        validate_text(&trust_domain)
            .and_then(|()| {
                if principal_id == [0; 16] {
                    Err(AuthorityErrorV1::FieldOutOfBounds)
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
        decode_bounded_array(bytes.as_slice(), MAX_PRINCIPAL_RECORD_BYTES, 4)
            .and_then(|fields| decode_principal(&fields))
    }
}

/// Adapter assurance is an opaque deployment-defined positive level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceLevelV1(u8);

impl AssuranceLevelV1 {
    /// Construct a non-zero assurance level.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::FieldOutOfBounds`] for zero.
    pub const fn try_new(value: u8) -> Result<Self, AuthorityErrorV1> {
        if value == 0 {
            Err(AuthorityErrorV1::FieldOutOfBounds)
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
    pub issued_at: WallTime,
    pub expires_at: WallTime,
    pub binding_digest: Hash,
}

/// Minimized evidence emitted by a trusted authentication adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipalResultV1 {
    principal: PrincipalRefV1,
    adapter_id: String,
    assurance: AssuranceLevelV1,
    issued_at: WallTime,
    expires_at: WallTime,
    binding_digest: Hash,
}

impl AuthenticatedPrincipalResultV1 {
    /// Validate adapter evidence without retaining credentials or bearer material.
    ///
    /// # Errors
    /// Returns a closed error for invalid text, interval, or identity fields.
    pub fn try_from_draft(draft: AuthenticatedPrincipalDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_text(&draft.adapter_id)
            .and_then(|()| validate_wall_interval(draft.issued_at, draft.expires_at))
            .and_then(|()| validate_hash(draft.binding_digest))
            .map(|()| Self {
                principal: draft.principal,
                adapter_id: draft.adapter_id,
                assurance: draft.assurance,
                issued_at: draft.issued_at,
                expires_at: draft.expires_at,
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
    pub const fn issued_at(&self) -> WallTime {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> WallTime {
        self.expires_at
    }

    #[must_use]
    pub const fn binding_digest(&self) -> Hash {
        self.binding_digest
    }

    /// Return the complete adapter-result binding attested by the host registry.
    #[must_use]
    pub fn registry_binding_digest(&self) -> Hash {
        authenticated_registry_binding_digest(self)
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

    #[must_use]
    pub const fn installation_id(&self) -> Option<[u8; 16]> {
        match self {
            Self::Principal(_) => None,
            Self::PluginInstallation {
                installation_id, ..
            } => Some(*installation_id),
        }
    }
}

/// Responsibility carried by a Principal for one authorization request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthorityRoleV1 {
    Actor,
    Approver,
    Evaluator,
}

/// Grantee class to which a parent explicitly permits onward delegation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DelegateClassV1 {
    Principal,
}

/// Immutable trust roots resolved from the host's authoritative registry.
///
/// Callers must obtain this snapshot from the trusted host boundary. Supplying
/// plugin-provided or request-provided values here does not establish authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRegistrySnapshotV1 {
    registry_digest: Hash,
    authentication_bindings: Vec<Hash>,
    capability_bindings: Vec<Hash>,
    consent_bindings: Vec<Hash>,
}

impl AuthorityRegistrySnapshotV1 {
    /// Construct a canonical snapshot from records verified by the trusted host.
    ///
    /// # Errors
    /// Returns a closed error for zero, duplicate, unordered, or unbounded fields.
    pub fn try_new(
        registry_digest: Hash,
        authentication_bindings: Vec<Hash>,
        capability_bindings: Vec<Hash>,
        consent_bindings: Vec<Hash>,
    ) -> Result<Self, AuthorityErrorV1> {
        validate_hash(registry_digest)?;
        validate_required_hash_set(&authentication_bindings)?;
        validate_hash_set(&capability_bindings)?;
        validate_hash_set(&consent_bindings)?;
        Ok(Self {
            registry_digest,
            authentication_bindings,
            capability_bindings,
            consent_bindings,
        })
    }

    #[must_use]
    pub const fn registry_digest(&self) -> Hash {
        self.registry_digest
    }

    fn trusts_authentication(&self, request: &AuthorizationRequestV1) -> bool {
        request.authority_registry_digest == self.registry_digest
            && self
                .authentication_bindings
                .binary_search(&request.authenticated.registry_binding_digest())
                .is_ok()
    }

    fn trusts_consent(&self, request: &AuthorizationRequestV1) -> bool {
        match &request.consent {
            ConsentEvidenceV1::Resolved { grants } => grants.iter().all(|grant| {
                grant.authority_registry_digest == self.registry_digest
                    && self
                        .consent_bindings
                        .binary_search(&grant.binding_digest())
                        .is_ok()
            }),
            _ => true,
        }
    }

    fn trusts_capabilities(&self, grant_chain: &DelegationChainV1) -> bool {
        grant_chain.grants.iter().all(|grant| {
            grant.authority_registry_digest == self.registry_digest
                && grant
                    .binding_digest()
                    .is_ok_and(|binding| self.capability_bindings.binary_search(&binding).is_ok())
        })
    }
}

/// Host-resolved status of one immutable consent record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentGrantStatusV1 {
    Active,
    RevokedAtFence,
    Expired,
}

/// Unvalidated fields for an immutable ADR-039 consent reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentGrantRefDraftV1 {
    pub consent_id: Hash,
    pub subject_id: EntityId,
    pub data_categories: Vec<String>,
    pub purposes: Vec<String>,
    pub audiences: Vec<String>,
    pub action_classes: Vec<String>,
    pub valid_from: WallTime,
    pub valid_until: WallTime,
    pub withdrawal_retention_policy: String,
    pub policy_revision: Hash,
    pub issuer: PrincipalRefV1,
    pub issuer_evidence: Hash,
    pub status: ConsentGrantStatusV1,
    pub revocation_fence: Option<Seq>,
    pub authority_registry_digest: Hash,
}

/// Immutable consent record resolved by the host before capability evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentGrantRefV1 {
    consent_id: Hash,
    subject_id: EntityId,
    data_categories: Vec<String>,
    purposes: Vec<String>,
    audiences: Vec<String>,
    action_classes: Vec<String>,
    valid_from: WallTime,
    valid_until: WallTime,
    withdrawal_retention_policy: String,
    policy_revision: Hash,
    issuer: PrincipalRefV1,
    issuer_evidence: Hash,
    status: ConsentGrantStatusV1,
    revocation_fence: Option<Seq>,
    authority_registry_digest: Hash,
}

impl ConsentGrantRefV1 {
    /// Validate a complete immutable consent reference.
    ///
    /// # Errors
    /// Returns a closed error when identity, scope, validity, or evidence is invalid.
    pub fn try_from_draft(draft: ConsentGrantRefDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_hash(draft.consent_id)
            .and_then(|()| validate_entity_id(draft.subject_id))
            .and_then(|()| validate_required_text_set(&draft.data_categories))
            .and_then(|()| validate_required_text_set(&draft.purposes))
            .and_then(|()| validate_required_text_set(&draft.audiences))
            .and_then(|()| validate_required_text_set(&draft.action_classes))
            .and_then(|()| validate_wall_interval(draft.valid_from, draft.valid_until))
            .and_then(|()| validate_text(&draft.withdrawal_retention_policy))
            .and_then(|()| validate_hash(draft.policy_revision))
            .and_then(|()| validate_hash(draft.issuer_evidence))
            .and_then(|()| validate_hash(draft.authority_registry_digest))
            .and_then(|()| validate_consent_status(draft.status, draft.revocation_fence))
            .map(|()| Self {
                consent_id: draft.consent_id,
                subject_id: draft.subject_id,
                data_categories: draft.data_categories,
                purposes: draft.purposes,
                audiences: draft.audiences,
                action_classes: draft.action_classes,
                valid_from: draft.valid_from,
                valid_until: draft.valid_until,
                withdrawal_retention_policy: draft.withdrawal_retention_policy,
                policy_revision: draft.policy_revision,
                issuer: draft.issuer,
                issuer_evidence: draft.issuer_evidence,
                status: draft.status,
                revocation_fence: draft.revocation_fence,
                authority_registry_digest: draft.authority_registry_digest,
            })
    }

    #[must_use]
    pub const fn consent_id(&self) -> Hash {
        self.consent_id
    }
    #[must_use]
    pub const fn subject_id(&self) -> EntityId {
        self.subject_id
    }
    #[must_use]
    pub fn data_categories(&self) -> &[String] {
        &self.data_categories
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
    pub fn action_classes(&self) -> &[String] {
        &self.action_classes
    }
    #[must_use]
    pub const fn valid_from(&self) -> WallTime {
        self.valid_from
    }
    #[must_use]
    pub const fn valid_until(&self) -> WallTime {
        self.valid_until
    }
    #[must_use]
    pub fn withdrawal_retention_policy(&self) -> &str {
        &self.withdrawal_retention_policy
    }
    #[must_use]
    pub const fn policy_revision(&self) -> Hash {
        self.policy_revision
    }
    #[must_use]
    pub const fn issuer(&self) -> &PrincipalRefV1 {
        &self.issuer
    }
    #[must_use]
    pub const fn issuer_evidence(&self) -> Hash {
        self.issuer_evidence
    }
    #[must_use]
    pub const fn status(&self) -> ConsentGrantStatusV1 {
        self.status
    }
    #[must_use]
    pub const fn revocation_fence(&self) -> Option<Seq> {
        self.revocation_fence
    }
    #[must_use]
    pub const fn authority_registry_digest(&self) -> Hash {
        self.authority_registry_digest
    }

    /// Return the digest that a trusted registry attests for this exact record.
    #[must_use]
    pub fn binding_digest(&self) -> Hash {
        consent_grant_digest(self)
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
    pub subject_ids: Vec<EntityId>,
    pub participant_ids: Vec<EntityId>,
    pub plugin_id: Option<PluginId>,
    pub principal_roles: Vec<AuthorityRoleV1>,
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
    subject_ids: Vec<EntityId>,
    participant_ids: Vec<EntityId>,
    plugin_id: Option<PluginId>,
    principal_roles: Vec<AuthorityRoleV1>,
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
        validate_required_selector_set(&draft.resources)
            .and_then(|()| validate_required_selector_set(&draft.actions))
            .and_then(|()| validate_required_text_set(&draft.purposes))
            .and_then(|()| validate_required_text_set(&draft.audiences))
            .and_then(|()| validate_ordered_set(&draft.actor_entity_ids, true))
            .and_then(|()| validate_ordered_set(&draft.subject_ids, false))
            .and_then(|()| validate_ordered_set(&draft.participant_ids, false))
            .and_then(|()| validate_ordered_set(&draft.principal_roles, true))
            .and_then(|()| validate_entity_set(&draft.actor_entity_ids))
            .and_then(|()| validate_entity_set(&draft.subject_ids))
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
                subject_ids: draft.subject_ids,
                participant_ids: draft.participant_ids,
                plugin_id: draft.plugin_id,
                principal_roles: draft.principal_roles,
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
    pub fn subject_ids(&self) -> &[EntityId] {
        &self.subject_ids
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
    pub fn principal_roles(&self) -> &[AuthorityRoleV1] {
        &self.principal_roles
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
        let subject_matches = request.subject_id.map_or_else(
            || self.subject_ids.is_empty(),
            |subject| self.subject_ids.binary_search(&subject).is_ok(),
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
            && subject_matches
            && participant_matches
            && self.plugin_id == request.plugin_id
            && self
                .principal_roles
                .binary_search(&request.principal_role)
                .is_ok()
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
            && is_subset(&self.subject_ids, &parent.subject_ids)
            && is_subset(&self.participant_ids, &parent.participant_ids)
            && is_subset(&self.principal_roles, &parent.principal_roles)
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
    pub trust_domain: String,
    pub scope: CapabilityScopeV1,
    pub valid_from_position: Seq,
    pub valid_until_position: Seq,
    pub parent_grant_id: Option<Hash>,
    pub delegation_depth: u8,
    pub max_delegation_depth: u8,
    pub permitted_delegate_classes: Vec<DelegateClassV1>,
    pub consent_references: Vec<Hash>,
    pub policy_revision: Hash,
    pub issuance_timeline: TimelineId,
    pub issuance_seq: Seq,
    pub revocation_epoch: u64,
    pub revocation_fence: Option<Seq>,
    pub authority_registry_digest: Hash,
}

/// Immutable, provider-neutral capability grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrantV1 {
    grant_id: Hash,
    grantor: PrincipalRefV1,
    grantee: AuthorityGranteeV1,
    trust_domain: String,
    scope: CapabilityScopeV1,
    valid_from_position: Seq,
    valid_until_position: Seq,
    parent_grant_id: Option<Hash>,
    delegation_depth: u8,
    max_delegation_depth: u8,
    permitted_delegate_classes: Vec<DelegateClassV1>,
    consent_references: Vec<Hash>,
    policy_revision: Hash,
    issuance_timeline: TimelineId,
    issuance_seq: Seq,
    revocation_epoch: u64,
    revocation_fence: Option<Seq>,
    authority_registry_digest: Hash,
}

impl CapabilityGrantV1 {
    /// Validate an immutable capability grant.
    ///
    /// # Errors
    /// Returns a closed error for invalid identity, interval, depth, or consent set.
    pub fn try_from_draft(draft: CapabilityGrantDraftV1) -> Result<Self, AuthorityErrorV1> {
        validate_hash(draft.grant_id)
            .and_then(|()| validate_hash(draft.policy_revision))
            .and_then(|()| validate_hash(draft.authority_registry_digest))
            .and_then(|()| validate_grantee(&draft.grantee))
            .and_then(|()| validate_text(&draft.trust_domain))
            .and_then(|()| {
                if draft.grantor.trust_domain() == draft.trust_domain
                    && draft.grantee.principal().trust_domain() == draft.trust_domain
                {
                    Ok(())
                } else {
                    Err(AuthorityErrorV1::PrincipalUnresolved)
                }
            })
            .and_then(|()| validate_grantee_scope(&draft.grantee, &draft.scope))
            .and_then(|()| validate_timeline_id(draft.issuance_timeline))
            .and_then(|()| {
                validate_seq_interval(draft.valid_from_position, draft.valid_until_position)
            })
            .and_then(|()| validate_optional_hash(draft.parent_grant_id))
            .and_then(|()| validate_hash_set(&draft.consent_references))
            .and_then(|()| validate_delegation_depth(&draft))
            .and_then(|()| validate_ordered_set(&draft.permitted_delegate_classes, false))
            .and_then(|()| {
                if draft.issuance_seq > draft.valid_from_position
                    || draft.revocation_fence.is_some_and(|fence| {
                        fence < draft.valid_from_position || fence > draft.valid_until_position
                    })
                {
                    Err(AuthorityErrorV1::FieldOutOfBounds)
                } else {
                    Ok(())
                }
            })
            .map(|()| Self {
                grant_id: draft.grant_id,
                grantor: draft.grantor,
                grantee: draft.grantee,
                trust_domain: draft.trust_domain,
                scope: draft.scope,
                valid_from_position: draft.valid_from_position,
                valid_until_position: draft.valid_until_position,
                parent_grant_id: draft.parent_grant_id,
                delegation_depth: draft.delegation_depth,
                max_delegation_depth: draft.max_delegation_depth,
                permitted_delegate_classes: draft.permitted_delegate_classes,
                consent_references: draft.consent_references,
                policy_revision: draft.policy_revision,
                issuance_timeline: draft.issuance_timeline,
                issuance_seq: draft.issuance_seq,
                revocation_epoch: draft.revocation_epoch,
                revocation_fence: draft.revocation_fence,
                authority_registry_digest: draft.authority_registry_digest,
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
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
    #[must_use]
    pub const fn scope(&self) -> &CapabilityScopeV1 {
        &self.scope
    }
    #[must_use]
    pub const fn valid_from_position(&self) -> Seq {
        self.valid_from_position
    }
    #[must_use]
    pub const fn valid_until_position(&self) -> Seq {
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
    pub fn permitted_delegate_classes(&self) -> &[DelegateClassV1] {
        &self.permitted_delegate_classes
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
    pub const fn issuance_seq(&self) -> Seq {
        self.issuance_seq
    }
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
    #[must_use]
    pub const fn revocation_fence(&self) -> Option<Seq> {
        self.revocation_fence
    }
    #[must_use]
    pub const fn authority_registry_digest(&self) -> Hash {
        self.authority_registry_digest
    }

    /// Return the digest that a trusted registry attests for this exact record.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::InvalidEncoding`] if canonical encoding fails.
    pub fn binding_digest(&self) -> Result<Hash, AuthorityErrorV1> {
        self.encode()
            .map(|encoded| Hash::from_bytes(*blake3::hash(encoded.as_slice()).as_bytes()))
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
        decode_bounded_array(bytes.as_slice(), MAX_CAPABILITY_RECORD_BYTES, 20)
            .and_then(|fields| decode_grant(&fields))
    }
}

/// Bounded root-to-leaf capability chain. Each element uses the canonical CPG1 codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationChainV1 {
    grants: Vec<CapabilityGrantV1>,
}

impl DelegationChainV1 {
    /// Validate canonical root-to-leaf order and strict attenuation.
    ///
    /// An empty chain represents a request for which no capability was resolved.
    ///
    /// # Errors
    /// Returns a closed error for excessive depth, duplicate identity, broken links,
    /// backdated issuance, or widened authority.
    pub fn try_from_grants(grants: Vec<CapabilityGrantV1>) -> Result<Self, AuthorityErrorV1> {
        validate_chain_structure(&grants).map(|()| Self { grants })
    }

    #[must_use]
    pub fn grants(&self) -> &[CapabilityGrantV1] {
        &self.grants
    }

    /// Encode each grant using the approved CPG1 record representation.
    ///
    /// # Errors
    /// Returns a closed codec error if a grant cannot be encoded.
    pub fn encode_grants(&self) -> Result<Vec<CanonicalBytes>, AuthorityErrorV1> {
        self.grants.iter().map(CapabilityGrantV1::encode).collect()
    }

    /// Decode a bounded root-to-leaf sequence of canonical CPG1 records.
    ///
    /// # Errors
    /// Returns a closed codec or delegation error for malformed input.
    pub fn decode_grants(records: &[CanonicalBytes]) -> Result<Self, AuthorityErrorV1> {
        if records.len() > usize::from(MAX_AUTHORITY_DELEGATION_DEPTH) + 1 {
            return Err(AuthorityErrorV1::FieldOutOfBounds);
        }
        records
            .iter()
            .map(CapabilityGrantV1::decode)
            .collect::<Result<Vec<_>, _>>()
            .and_then(Self::try_from_grants)
    }
}

/// Consent evidence remains a separate input from capability authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsentEvidenceV1 {
    NotRequired,
    Resolved { grants: Vec<ConsentGrantRefV1> },
    Missing,
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
    pub installation_id: Option<[u8; 16]>,
    pub principal_role: AuthorityRoleV1,
    pub resource: String,
    pub data_category: String,
    pub action: String,
    pub purpose: String,
    pub audience: String,
    pub at_time: WallTime,
    pub authority_timeline: TimelineId,
    pub at_position: Seq,
    pub use_count: u64,
    pub budget: u64,
    pub policy_revision: Hash,
    pub revocation_epoch: u64,
    pub revocation_state_current: bool,
    pub authority_registry_digest: Hash,
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
    installation_id: Option<[u8; 16]>,
    principal_role: AuthorityRoleV1,
    resource: String,
    data_category: String,
    action: String,
    purpose: String,
    audience: String,
    at_time: WallTime,
    authority_timeline: TimelineId,
    at_position: Seq,
    use_count: u64,
    budget: u64,
    policy_revision: Hash,
    revocation_epoch: u64,
    revocation_state_current: bool,
    authority_registry_digest: Hash,
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
            .and_then(|()| validate_text(&draft.data_category))
            .and_then(|()| validate_text(&draft.action))
            .and_then(|()| validate_text(&draft.purpose))
            .and_then(|()| validate_text(&draft.audience))
            .and_then(|()| validate_hash(draft.policy_revision))
            .and_then(|()| validate_entity_id(draft.actor_entity_id))
            .and_then(|()| validate_optional_entity_id(draft.subject_id))
            .and_then(|()| validate_optional_entity_id(draft.participant_id))
            .and_then(|()| validate_optional_plugin_id(draft.plugin_id))
            .and_then(|()| validate_plugin_context(draft.plugin_id, draft.installation_id))
            .and_then(|()| validate_timeline_id(draft.authority_timeline))
            .and_then(|()| validate_text_set(&draft.environment_constraints, false))
            .and_then(|()| validate_consent_evidence(&draft.consent))
            .and(usage_limits)
            .and_then(|()| validate_hash(draft.authority_registry_digest))
            .map(|()| Self {
                authenticated: draft.authenticated,
                actor_entity_id: draft.actor_entity_id,
                subject_id: draft.subject_id,
                participant_id: draft.participant_id,
                plugin_id: draft.plugin_id,
                installation_id: draft.installation_id,
                principal_role: draft.principal_role,
                resource: draft.resource,
                data_category: draft.data_category,
                action: draft.action,
                purpose: draft.purpose,
                audience: draft.audience,
                at_time: draft.at_time,
                authority_timeline: draft.authority_timeline,
                at_position: draft.at_position,
                use_count: draft.use_count,
                budget: draft.budget,
                policy_revision: draft.policy_revision,
                revocation_epoch: draft.revocation_epoch,
                revocation_state_current: draft.revocation_state_current,
                authority_registry_digest: draft.authority_registry_digest,
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
    pub const fn installation_id(&self) -> Option<[u8; 16]> {
        self.installation_id
    }
    #[must_use]
    pub const fn principal_role(&self) -> AuthorityRoleV1 {
        self.principal_role
    }
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
    #[must_use]
    pub fn data_category(&self) -> &str {
        &self.data_category
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
    pub const fn at_time(&self) -> WallTime {
        self.at_time
    }
    #[must_use]
    pub const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }
    #[must_use]
    pub const fn at_position(&self) -> Seq {
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
    pub const fn authority_registry_digest(&self) -> Hash {
        self.authority_registry_digest
    }
    #[must_use]
    pub const fn consent(&self) -> &ConsentEvidenceV1 {
        &self.consent
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
    RevokedAtFence,
    Expired,
    ParentInvalid,
    ConsentMissing,
    RevocationStateStale,
    IndeterminateFailClosed,
}

impl AuthorizationOutcomeV1 {
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Return the stable AUD1 outcome code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::RevokedAtFence => 1,
            Self::Expired => 2,
            Self::ParentInvalid => 3,
            Self::ConsentMissing => 4,
            Self::RevocationStateStale => 5,
            Self::IndeterminateFailClosed => 6,
        }
    }

    /// Decode one stable AUD1 outcome code.
    ///
    /// # Errors
    /// Returns [`AuthorityErrorV1::UnknownEnum`] for an unknown code.
    pub const fn from_code(code: u8) -> Result<Self, AuthorityErrorV1> {
        match code {
            0 => Ok(Self::Active),
            1 => Ok(Self::RevokedAtFence),
            2 => Ok(Self::Expired),
            3 => Ok(Self::ParentInvalid),
            4 => Ok(Self::ConsentMissing),
            5 => Ok(Self::RevocationStateStale),
            6 => Ok(Self::IndeterminateFailClosed),
            _ => Err(AuthorityErrorV1::UnknownEnum),
        }
    }
}

/// Host-owned immutable answer for one exact request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecisionV1 {
    principal: PrincipalRefV1,
    principal_role: AuthorityRoleV1,
    actor_entity_id: EntityId,
    subject_id: Option<EntityId>,
    participant_id: Option<EntityId>,
    plugin_id: Option<PluginId>,
    installation_id: Option<[u8; 16]>,
    originating_principal: Option<PrincipalRefV1>,
    acting_delegates: Vec<PrincipalRefV1>,
    grant_id: Option<Hash>,
    policy_revision: Hash,
    authority_timeline: TimelineId,
    at_position: Seq,
    authority_registry_digest: Hash,
    outcome: AuthorizationOutcomeV1,
    error: Option<AuthorityErrorV1>,
    request_digest: Hash,
    decision_digest: Hash,
}

impl AuthorizationDecisionV1 {
    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }
    #[must_use]
    pub const fn principal_role(&self) -> AuthorityRoleV1 {
        self.principal_role
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
    pub const fn installation_id(&self) -> Option<[u8; 16]> {
        self.installation_id
    }
    #[must_use]
    pub const fn originating_principal(&self) -> Option<&PrincipalRefV1> {
        self.originating_principal.as_ref()
    }
    #[must_use]
    pub fn acting_delegates(&self) -> &[PrincipalRefV1] {
        &self.acting_delegates
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
    pub const fn at_position(&self) -> Seq {
        self.at_position
    }
    #[must_use]
    pub const fn authority_registry_digest(&self) -> Hash {
        self.authority_registry_digest
    }
    #[must_use]
    pub const fn outcome(&self) -> AuthorizationOutcomeV1 {
        self.outcome
    }
    #[must_use]
    pub const fn error(&self) -> Option<AuthorityErrorV1> {
        self.error
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
    /// Decoding establishes structural and digest integrity only. A caller must
    /// obtain authoritative decisions from its trusted host boundary; decoded
    /// plugin or transport input does not become authoritative by parsing it.
    ///
    /// # Errors
    /// Returns a closed validation, digest, or codec error for malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityErrorV1> {
        decode_bounded_array(bytes.as_slice(), MAX_DECISION_RECORD_BYTES, 20)
            .and_then(|fields| decode_decision(&fields))
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
        grant_chain: &DelegationChainV1,
        trusted_registry: &AuthorityRegistrySnapshotV1,
    ) -> AuthorizationDecisionV1 {
        let evaluation = authorization_evaluation(request, grant_chain, trusted_registry);
        let request_digest = request_digest(request);
        let (originating_principal, acting_delegates, grant_id) =
            if evaluation.grant_evidence_is_trusted {
                (
                    grant_chain
                        .grants
                        .first()
                        .map(|grant| grant.grantor.clone()),
                    grant_chain
                        .grants
                        .iter()
                        .map(|grant| grant.grantee.principal().clone())
                        .collect(),
                    grant_chain.grants.last().map(CapabilityGrantV1::grant_id),
                )
            } else {
                (None, Vec::new(), None)
            };
        let mut decision = AuthorizationDecisionV1 {
            principal: request.authenticated.principal.clone(),
            principal_role: request.principal_role,
            actor_entity_id: request.actor_entity_id,
            subject_id: request.subject_id,
            participant_id: request.participant_id,
            plugin_id: request.plugin_id,
            installation_id: request.installation_id,
            originating_principal,
            acting_delegates,
            grant_id,
            policy_revision: request.policy_revision,
            authority_timeline: request.authority_timeline,
            at_position: request.at_position,
            authority_registry_digest: request.authority_registry_digest,
            outcome: evaluation.outcome,
            error: evaluation.error,
            request_digest,
            decision_digest: Hash::zero(),
        };
        decision.decision_digest = decision_digest(&decision);
        decision
    }
}

#[derive(Clone, Copy)]
struct AuthorizationEvaluationV1 {
    outcome: AuthorizationOutcomeV1,
    error: Option<AuthorityErrorV1>,
    grant_evidence_is_trusted: bool,
}

impl AuthorizationEvaluationV1 {
    const fn active() -> Self {
        Self {
            outcome: AuthorizationOutcomeV1::Active,
            error: None,
            grant_evidence_is_trusted: true,
        }
    }

    const fn denied(outcome: AuthorizationOutcomeV1, error: Option<AuthorityErrorV1>) -> Self {
        Self {
            outcome,
            error,
            grant_evidence_is_trusted: false,
        }
    }

    const fn denied_with_trusted_grant(
        outcome: AuthorizationOutcomeV1,
        error: Option<AuthorityErrorV1>,
    ) -> Self {
        Self {
            outcome,
            error,
            grant_evidence_is_trusted: true,
        }
    }
}

fn authorization_evaluation(
    request: &AuthorizationRequestV1,
    grant_chain: &DelegationChainV1,
    trusted_registry: &AuthorityRegistrySnapshotV1,
) -> AuthorizationEvaluationV1 {
    if request.at_time < request.authenticated.issued_at
        || request.at_time >= request.authenticated.expires_at
    {
        return AuthorizationEvaluationV1::denied(AuthorizationOutcomeV1::Expired, None);
    }
    if !trusted_registry.trusts_authentication(request) {
        return AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::PrincipalUnresolved),
        );
    }
    let consent_evaluation = evaluate_consent(request);
    if consent_evaluation.outcome != AuthorizationOutcomeV1::Active {
        return consent_evaluation;
    }
    if !trusted_registry.trusts_consent(request) {
        return AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::ConsentMissing,
            Some(AuthorityErrorV1::ConsentMissing),
        );
    }
    let Some(leaf) = grant_chain.grants.last() else {
        return AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::CapabilityMissing),
        );
    };
    if !trusted_registry.trusts_capabilities(grant_chain) {
        return AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::CapabilityMissing),
        );
    }
    if leaf.grantee.principal() != request.authenticated.principal() {
        return AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::PrincipalUnresolved),
        );
    }
    if !grantee_context_matches(request, leaf) {
        return AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::CapabilityMissing),
        );
    }
    if !leaf.scope.permits(request) {
        return AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::CapabilityMissing),
        );
    }
    match validate_delegation_chain(request, grant_chain) {
        ChainValidity::Valid => {}
        ChainValidity::ParentInvalid => {
            return AuthorizationEvaluationV1::denied_with_trusted_grant(
                AuthorizationOutcomeV1::ParentInvalid,
                Some(AuthorityErrorV1::DelegationInvalid),
            );
        }
    }
    if !request.revocation_state_current {
        return AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::RevocationStateStale,
            Some(AuthorityErrorV1::RevocationStateStale),
        );
    }
    let timeline_is_current = request.authority_timeline == leaf.issuance_timeline;
    let revocation_epoch_is_current = request.revocation_epoch == leaf.revocation_epoch;
    let policy_is_current = request.policy_revision == leaf.policy_revision;
    if !timeline_is_current || !revocation_epoch_is_current || !policy_is_current {
        return AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::PolicyIndeterminate),
        );
    }
    match validate_temporal_chain(request, grant_chain) {
        TemporalValidity::Valid => AuthorizationEvaluationV1::active(),
        TemporalValidity::Expired => AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::Expired,
            None,
        ),
        TemporalValidity::RevokedAtFence => AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::RevokedAtFence,
            Some(AuthorityErrorV1::RevokedAtFence),
        ),
        TemporalValidity::ParentInvalid => AuthorizationEvaluationV1::denied_with_trusted_grant(
            AuthorizationOutcomeV1::ParentInvalid,
            Some(AuthorityErrorV1::DelegationInvalid),
        ),
    }
}

fn grantee_context_matches(request: &AuthorizationRequestV1, grant: &CapabilityGrantV1) -> bool {
    match &grant.grantee {
        AuthorityGranteeV1::Principal(_) => {
            request.plugin_id.is_none() && request.installation_id.is_none()
        }
        AuthorityGranteeV1::PluginInstallation {
            plugin_id,
            installation_id,
            ..
        } => {
            request.plugin_id == Some(*plugin_id)
                && request.installation_id == Some(*installation_id)
                && grant.scope.plugin_id == Some(*plugin_id)
        }
    }
}

fn evaluate_consent(request: &AuthorizationRequestV1) -> AuthorizationEvaluationV1 {
    if request.subject_id.is_none() {
        return match &request.consent {
            ConsentEvidenceV1::NotRequired => AuthorizationEvaluationV1::active(),
            ConsentEvidenceV1::Indeterminate => AuthorizationEvaluationV1::denied(
                AuthorizationOutcomeV1::IndeterminateFailClosed,
                Some(AuthorityErrorV1::PolicyIndeterminate),
            ),
            _ => AuthorizationEvaluationV1::denied(
                AuthorizationOutcomeV1::ConsentMissing,
                Some(AuthorityErrorV1::ConsentMissing),
            ),
        };
    }
    match &request.consent {
        ConsentEvidenceV1::Resolved { grants } => grants
            .iter()
            .map(|grant| evaluate_consent_grant(request, grant))
            .find(|evaluation| evaluation.outcome != AuthorizationOutcomeV1::Active)
            .unwrap_or_else(AuthorizationEvaluationV1::active),
        ConsentEvidenceV1::Missing | ConsentEvidenceV1::NotRequired => {
            AuthorizationEvaluationV1::denied(
                AuthorizationOutcomeV1::ConsentMissing,
                Some(AuthorityErrorV1::ConsentMissing),
            )
        }
        ConsentEvidenceV1::Indeterminate => AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::IndeterminateFailClosed,
            Some(AuthorityErrorV1::PolicyIndeterminate),
        ),
    }
}

fn evaluate_consent_grant(
    request: &AuthorizationRequestV1,
    grant: &ConsentGrantRefV1,
) -> AuthorizationEvaluationV1 {
    let matches_request = Some(grant.subject_id) == request.subject_id
        && grant
            .data_categories
            .binary_search(&request.data_category)
            .is_ok()
        && grant.purposes.binary_search(&request.purpose).is_ok()
        && grant.audiences.binary_search(&request.audience).is_ok()
        && grant.action_classes.binary_search(&request.action).is_ok()
        && grant.policy_revision == request.policy_revision
        && grant.authority_registry_digest == request.authority_registry_digest;
    if !matches_request {
        AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::ConsentMissing,
            Some(AuthorityErrorV1::ConsentMissing),
        )
    } else if grant.status == ConsentGrantStatusV1::Expired
        || request.at_time < grant.valid_from
        || request.at_time >= grant.valid_until
    {
        AuthorizationEvaluationV1::denied(AuthorizationOutcomeV1::Expired, None)
    } else if grant.status == ConsentGrantStatusV1::RevokedAtFence
        || grant
            .revocation_fence
            .is_some_and(|fence| request.at_position >= fence)
    {
        AuthorizationEvaluationV1::denied(
            AuthorizationOutcomeV1::RevokedAtFence,
            Some(AuthorityErrorV1::RevokedAtFence),
        )
    } else {
        AuthorizationEvaluationV1::active()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainValidity {
    Valid,
    ParentInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemporalValidity {
    Valid,
    Expired,
    RevokedAtFence,
    ParentInvalid,
}

fn validate_chain_structure(chain: &[CapabilityGrantV1]) -> Result<(), AuthorityErrorV1> {
    if chain.len() > usize::from(MAX_AUTHORITY_DELEGATION_DEPTH) + 1 {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
    }
    let mut seen_grants = Vec::with_capacity(chain.len());
    let mut seen_delegates = Vec::with_capacity(chain.len());
    let mut previous: Option<&CapabilityGrantV1> = None;
    for grant in chain {
        if seen_grants.contains(&grant.grant_id)
            || seen_delegates.contains(grant.grantee.principal())
        {
            return Err(AuthorityErrorV1::DuplicateIdentity);
        }
        seen_grants.push(grant.grant_id);
        seen_delegates.push(grant.grantee.principal().clone());
        if let Some(parent) = previous {
            if !valid_child(parent, grant) {
                return Err(AuthorityErrorV1::DelegationInvalid);
            }
        } else if grant.parent_grant_id.is_some() || grant.delegation_depth != 0 {
            return Err(AuthorityErrorV1::DelegationInvalid);
        }
        previous = Some(grant);
    }
    Ok(())
}

fn validate_delegation_chain(
    request: &AuthorizationRequestV1,
    chain: &DelegationChainV1,
) -> ChainValidity {
    for (index, grant) in chain.grants.iter().enumerate() {
        let is_leaf = index + 1 == chain.grants.len();
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
        if request.subject_id.is_some() && !grant_covers_consent(grant, &request.consent) {
            return ChainValidity::ParentInvalid;
        }
    }
    ChainValidity::Valid
}

fn validate_temporal_chain(
    request: &AuthorizationRequestV1,
    chain: &DelegationChainV1,
) -> TemporalValidity {
    for (index, grant) in chain.grants.iter().enumerate() {
        let is_leaf = index + 1 == chain.grants.len();
        if request.at_position < grant.valid_from_position
            || request.at_position >= grant.valid_until_position
        {
            return if is_leaf {
                TemporalValidity::Expired
            } else {
                TemporalValidity::ParentInvalid
            };
        }
        if grant
            .revocation_fence
            .is_some_and(|fence| request.at_position >= fence)
        {
            return if is_leaf {
                TemporalValidity::RevokedAtFence
            } else {
                TemporalValidity::ParentInvalid
            };
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
    let delegate_class_is_permitted = parent
        .permitted_delegate_classes
        .binary_search(&DelegateClassV1::Principal)
        .is_ok();
    let issuance_follows_parent = child.issuance_timeline == parent.issuance_timeline
        && child.issuance_seq > parent.issuance_seq;
    let issuance_is_within_parent_authority = child.issuance_seq >= parent.valid_from_position
        && parent
            .revocation_fence
            .is_none_or(|fence| child.issuance_seq < fence);
    child.parent_grant_id == Some(parent.grant_id)
        && depth_is_next
        && depth_is_bounded
        && descendants_are_bounded
        && grantor_is_delegate
        && delegate_class_is_permitted
        && issuance_follows_parent
        && issuance_is_within_parent_authority
        && parent
            .scope
            .actions
            .binary_search_by(|action| action.as_str().cmp(DELEGATE_ACTION_V1))
            .is_ok()
        && child.scope.is_attenuation_of(&parent.scope)
        && child.valid_from_position >= parent.valid_from_position
        && child.valid_until_position <= parent.valid_until_position
        && child.consent_references == parent.consent_references
}

fn grant_covers_consent(grant: &CapabilityGrantV1, evidence: &ConsentEvidenceV1) -> bool {
    match evidence {
        ConsentEvidenceV1::Resolved { grants } => {
            grant.consent_references.len() == grants.len()
                && grants
                    .iter()
                    .zip(&grant.consent_references)
                    .all(|(consent, reference)| consent.consent_id == *reference)
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
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_required_text_set(values: &[String]) -> Result<(), AuthorityErrorV1> {
    validate_text_set(values, true)
}

fn validate_required_selector_set(values: &[String]) -> Result<(), AuthorityErrorV1> {
    validate_ordered_set_with_limit(values, true, MAX_AUTHORITY_SELECTORS)
        .and_then(|()| values.iter().try_for_each(|value| validate_text(value)))
}

fn validate_text_set(values: &[String], required: bool) -> Result<(), AuthorityErrorV1> {
    validate_ordered_set(values, required)
        .and_then(|()| values.iter().try_for_each(|value| validate_text(value)))
}

fn validate_ordered_set<T: Ord>(values: &[T], required: bool) -> Result<(), AuthorityErrorV1> {
    validate_ordered_set_with_limit(values, required, MAX_AUTHORITY_SCOPE_MEMBERS)
}

fn validate_ordered_set_with_limit<T: Ord>(
    values: &[T],
    required: bool,
    limit: usize,
) -> Result<(), AuthorityErrorV1> {
    if values.len() > limit || (required && values.is_empty()) {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
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
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_optional_hash(value: Option<Hash>) -> Result<(), AuthorityErrorV1> {
    value.map_or(Ok(()), validate_hash)
}

fn validate_hash_set(values: &[Hash]) -> Result<(), AuthorityErrorV1> {
    if values.len() > MAX_AUTHORITY_SELECTORS {
        return Err(AuthorityErrorV1::FieldOutOfBounds);
    }
    validate_ordered_set(values, false)
        .and_then(|()| values.iter().copied().try_for_each(validate_hash))
}

fn validate_required_hash_set(values: &[Hash]) -> Result<(), AuthorityErrorV1> {
    if values.is_empty() {
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        validate_hash_set(values)
    }
}

fn validate_consent_evidence(value: &ConsentEvidenceV1) -> Result<(), AuthorityErrorV1> {
    match value {
        ConsentEvidenceV1::Resolved { grants } => {
            if grants.is_empty() || grants.len() > MAX_AUTHORITY_SCOPE_MEMBERS {
                return Err(AuthorityErrorV1::FieldOutOfBounds);
            }
            if grants
                .windows(2)
                .all(|pair| pair[0].consent_id < pair[1].consent_id)
            {
                Ok(())
            } else {
                Err(AuthorityErrorV1::NonCanonicalOrder)
            }
        }
        _ => Ok(()),
    }
}

const fn validate_consent_status(
    status: ConsentGrantStatusV1,
    revocation_fence: Option<Seq>,
) -> Result<(), AuthorityErrorV1> {
    if matches!(status, ConsentGrantStatusV1::RevokedAtFence) && revocation_fence.is_none() {
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_entity_set(values: &[EntityId]) -> Result<(), AuthorityErrorV1> {
    values.iter().copied().try_for_each(validate_entity_id)
}

fn validate_entity_id(value: EntityId) -> Result<(), AuthorityErrorV1> {
    if value.inner() == ulid::Ulid::nil() {
        Err(AuthorityErrorV1::FieldOutOfBounds)
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
            Err(AuthorityErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    })
}

fn validate_timeline_id(value: TimelineId) -> Result<(), AuthorityErrorV1> {
    if value.inner() == ulid::Ulid::nil() {
        Err(AuthorityErrorV1::FieldOutOfBounds)
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
                Err(AuthorityErrorV1::FieldOutOfBounds)
            } else {
                Ok(())
            }
        }),
    }
}

fn validate_grantee_scope(
    grantee: &AuthorityGranteeV1,
    scope: &CapabilityScopeV1,
) -> Result<(), AuthorityErrorV1> {
    match grantee {
        AuthorityGranteeV1::Principal(_) if scope.plugin_id.is_none() => Ok(()),
        AuthorityGranteeV1::PluginInstallation { plugin_id, .. }
            if scope.plugin_id == Some(*plugin_id) =>
        {
            Ok(())
        }
        _ => Err(AuthorityErrorV1::FieldOutOfBounds),
    }
}

fn validate_plugin_context(
    plugin_id: Option<PluginId>,
    installation_id: Option<[u8; 16]>,
) -> Result<(), AuthorityErrorV1> {
    match (plugin_id, installation_id) {
        (None, None) => Ok(()),
        (Some(_), Some(id)) if id != [0; 16] => Ok(()),
        _ => Err(AuthorityErrorV1::FieldOutOfBounds),
    }
}

const fn validate_interval(start: u64, end: u64) -> Result<(), AuthorityErrorV1> {
    if start < end {
        Ok(())
    } else {
        Err(AuthorityErrorV1::FieldOutOfBounds)
    }
}

const fn validate_wall_interval(start: WallTime, end: WallTime) -> Result<(), AuthorityErrorV1> {
    validate_interval(start.as_micros(), end.as_micros())
}

const fn validate_seq_interval(start: Seq, end: Seq) -> Result<(), AuthorityErrorV1> {
    validate_interval(start.as_u64(), end.as_u64())
}

const fn validate_delegation_depth(draft: &CapabilityGrantDraftV1) -> Result<(), AuthorityErrorV1> {
    if draft.max_delegation_depth > MAX_AUTHORITY_DELEGATION_DEPTH
        || draft.delegation_depth > draft.max_delegation_depth
        || (draft.delegation_depth == 0) != draft.parent_grant_id.is_none()
    {
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

const fn validate_usage_limits(max_uses: u64, budget: u64) -> Result<(), AuthorityErrorV1> {
    if max_uses == 0 || budget == 0 {
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn request_digest(request: &AuthorizationRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.AuthorizationRequest.v1\0");
    digest_authenticated(&mut hasher, &request.authenticated);
    hasher.update(&entity_bytes(request.actor_entity_id));
    digest_optional_fixed(&mut hasher, request.subject_id.map(entity_bytes));
    digest_optional_fixed(&mut hasher, request.participant_id.map(entity_bytes));
    digest_optional_fixed(&mut hasher, request.plugin_id.map(plugin_bytes));
    digest_optional_fixed(&mut hasher, request.installation_id);
    hasher.update(&[role_code(request.principal_role)]);
    digest_part(&mut hasher, request.resource.as_bytes());
    digest_part(&mut hasher, request.data_category.as_bytes());
    digest_part(&mut hasher, request.action.as_bytes());
    digest_part(&mut hasher, request.purpose.as_bytes());
    digest_part(&mut hasher, request.audience.as_bytes());
    hasher.update(&request.at_time.as_micros().to_be_bytes());
    hasher.update(&timeline_bytes(request.authority_timeline));
    hasher.update(&request.at_position.as_u64().to_be_bytes());
    hasher.update(&request.use_count.to_be_bytes());
    hasher.update(&request.budget.to_be_bytes());
    hasher.update(request.policy_revision.as_bytes());
    hasher.update(&request.revocation_epoch.to_be_bytes());
    hasher.update(&[u8::from(request.revocation_state_current)]);
    hasher.update(request.authority_registry_digest.as_bytes());
    digest_consent(&mut hasher, &request.consent);
    hasher.update(&(request.environment_constraints.len() as u64).to_be_bytes());
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
    hasher.update(&[role_code(decision.principal_role)]);
    hasher.update(&entity_bytes(decision.actor_entity_id));
    digest_optional_fixed(&mut hasher, decision.subject_id.map(entity_bytes));
    digest_optional_fixed(&mut hasher, decision.participant_id.map(entity_bytes));
    digest_optional_fixed(&mut hasher, decision.plugin_id.map(plugin_bytes));
    digest_optional_fixed(&mut hasher, decision.installation_id);
    digest_optional_principal(&mut hasher, decision.originating_principal.as_ref());
    hasher.update(&(decision.acting_delegates.len() as u64).to_be_bytes());
    for delegate in &decision.acting_delegates {
        digest_principal(&mut hasher, delegate);
    }
    digest_optional_hash(&mut hasher, decision.grant_id);
    hasher.update(decision.policy_revision.as_bytes());
    hasher.update(&timeline_bytes(decision.authority_timeline));
    hasher.update(&decision.at_position.as_u64().to_be_bytes());
    hasher.update(decision.authority_registry_digest.as_bytes());
    hasher.update(&[decision.outcome.code()]);
    digest_optional_error(&mut hasher, decision.error);
    hasher.update(decision.request_digest.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn authenticated_registry_binding_digest(value: &AuthenticatedPrincipalResultV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.AuthenticatedPrincipalResult.registry.v1\0");
    digest_authenticated(&mut hasher, value);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn digest_authenticated(hasher: &mut blake3::Hasher, value: &AuthenticatedPrincipalResultV1) {
    digest_principal(hasher, &value.principal);
    digest_part(hasher, value.adapter_id.as_bytes());
    hasher.update(&[value.assurance.get()]);
    hasher.update(&value.issued_at.as_micros().to_be_bytes());
    hasher.update(&value.expires_at.as_micros().to_be_bytes());
    hasher.update(value.binding_digest.as_bytes());
}

fn digest_principal(hasher: &mut blake3::Hasher, value: &PrincipalRefV1) {
    hasher.update(value.principal_id());
    digest_part(hasher, value.trust_domain().as_bytes());
}

fn digest_part(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn digest_optional_bytes(hasher: &mut blake3::Hasher, value: Option<&[u8]>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(bytes) => {
            hasher.update(&[1]);
            digest_part(hasher, bytes);
        }
    }
}

fn digest_optional_fixed<const N: usize>(hasher: &mut blake3::Hasher, value: Option<[u8; N]>) {
    digest_optional_bytes(hasher, value.as_ref().map(<[u8; N]>::as_slice));
}

fn digest_optional_hash(hasher: &mut blake3::Hasher, value: Option<Hash>) {
    digest_optional_bytes(
        hasher,
        value.as_ref().map(|hash| hash.as_bytes().as_slice()),
    );
}

fn digest_optional_principal(hasher: &mut blake3::Hasher, value: Option<&PrincipalRefV1>) {
    hasher.update(&[u8::from(value.is_some())]);
    if let Some(principal) = value {
        digest_principal(hasher, principal);
    }
}

fn digest_optional_error(hasher: &mut blake3::Hasher, value: Option<AuthorityErrorV1>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(error) => {
            hasher.update(&[1, error.code()]);
        }
    }
}

fn digest_consent(hasher: &mut blake3::Hasher, consent: &ConsentEvidenceV1) {
    match consent {
        ConsentEvidenceV1::NotRequired => {
            hasher.update(&[0]);
        }
        ConsentEvidenceV1::Resolved { grants } => {
            hasher.update(&[1]);
            hasher.update(&(grants.len() as u64).to_be_bytes());
            for grant in grants {
                digest_consent_grant(hasher, grant);
            }
        }
        ConsentEvidenceV1::Missing => {
            hasher.update(&[2]);
        }
        ConsentEvidenceV1::Indeterminate => {
            hasher.update(&[3]);
        }
    }
}

fn digest_consent_grant(hasher: &mut blake3::Hasher, grant: &ConsentGrantRefV1) {
    hasher.update(grant.consent_id.as_bytes());
    hasher.update(&entity_bytes(grant.subject_id));
    for values in [
        &grant.data_categories,
        &grant.purposes,
        &grant.audiences,
        &grant.action_classes,
    ] {
        hasher.update(&(values.len() as u64).to_be_bytes());
        for value in values {
            digest_part(hasher, value.as_bytes());
        }
    }
    hasher.update(&grant.valid_from.as_micros().to_be_bytes());
    hasher.update(&grant.valid_until.as_micros().to_be_bytes());
    digest_part(hasher, grant.withdrawal_retention_policy.as_bytes());
    hasher.update(grant.policy_revision.as_bytes());
    digest_principal(hasher, &grant.issuer);
    hasher.update(grant.issuer_evidence.as_bytes());
    hasher.update(&[consent_status_code(grant.status)]);
    digest_optional_fixed(
        hasher,
        grant
            .revocation_fence
            .map(Seq::as_u64)
            .map(u64::to_be_bytes),
    );
    hasher.update(grant.authority_registry_digest.as_bytes());
}

fn consent_grant_digest(grant: &ConsentGrantRefV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ConsentGrantRef.v1\0");
    digest_consent_grant(&mut hasher, grant);
    Hash::from_bytes(*hasher.finalize().as_bytes())
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
        .map_err(|_| AuthorityErrorV1::InvalidEncoding)
        .map(|()| encoded)
}

fn decode_array(bytes: &[u8], expected_len: usize) -> Result<Vec<Value>, AuthorityErrorV1> {
    let mut cursor = Cursor::new(bytes);
    ciborium::from_reader(&mut cursor)
        .map_err(|_| AuthorityErrorV1::InvalidEncoding)
        .and_then(|value| {
            if cursor.position() != bytes.len() as u64 {
                return Err(AuthorityErrorV1::InvalidEncoding);
            }
            encode_value(&value).and_then(|canonical| {
                if canonical != bytes {
                    return Err(AuthorityErrorV1::InvalidEncoding);
                }
                match value {
                    Value::Array(fields) if fields.len() == expected_len => Ok(fields),
                    _ => Err(AuthorityErrorV1::InvalidEncoding),
                }
            })
        })
}

fn decode_bounded_array(
    bytes: &[u8],
    max_bytes: usize,
    expected_len: usize,
) -> Result<Vec<Value>, AuthorityErrorV1> {
    if bytes.len() > max_bytes {
        Err(AuthorityErrorV1::FieldOutOfBounds)
    } else {
        decode_array(bytes, expected_len)
    }
}

fn expect_header(fields: &[Value], magic: [u8; 4]) -> Result<(), AuthorityErrorV1> {
    match &fields[0] {
        Value::Bytes(value) if value.as_slice() == magic => {
            decode_u8(&fields[1]).and_then(|version| {
                if version == VERSION {
                    Ok(())
                } else {
                    Err(AuthorityErrorV1::UnsupportedVersion)
                }
            })
        }
        _ => Err(AuthorityErrorV1::InvalidEncoding),
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
fn optional_seq_value(value: Option<Seq>) -> Value {
    value.map_or(Value::Null, |seq| uint(seq.as_u64()))
}
fn optional_plugin_value(value: Option<PluginId>) -> Value {
    value.map_or(Value::Null, |plugin| bytes(&plugin_bytes(plugin)))
}
fn optional_entity_value(value: Option<EntityId>) -> Value {
    value.map_or(Value::Null, |entity| bytes(&entity_bytes(entity)))
}
fn optional_fixed_value<const N: usize>(value: Option<[u8; N]>) -> Value {
    value.map_or(Value::Null, |raw| bytes(&raw))
}
fn optional_principal_value(value: Option<&PrincipalRefV1>) -> Value {
    value.map_or(Value::Null, encode_principal)
}

fn optional_error_value(value: Option<AuthorityErrorV1>) -> Value {
    value.map_or(Value::Null, |error| uint(error.code()))
}

const fn role_code(value: AuthorityRoleV1) -> u8 {
    match value {
        AuthorityRoleV1::Actor => 0,
        AuthorityRoleV1::Approver => 1,
        AuthorityRoleV1::Evaluator => 2,
    }
}

const fn delegate_class_code(value: DelegateClassV1) -> u8 {
    match value {
        DelegateClassV1::Principal => 0,
    }
}

const fn consent_status_code(value: ConsentGrantStatusV1) -> u8 {
    match value {
        ConsentGrantStatusV1::Active => 0,
        ConsentGrantStatusV1::RevokedAtFence => 1,
        ConsentGrantStatusV1::Expired => 2,
    }
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
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}

fn exact_array(value: &Value, expected_len: usize) -> Result<&[Value], AuthorityErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == expected_len => Ok(fields),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
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
                Err(AuthorityErrorV1::UnknownEnum)
            }
        }),
        Value::Array(fields) if fields.len() == 4 => decode_u8(&fields[0]).and_then(|tag| {
            if tag != 1 {
                return Err(AuthorityErrorV1::UnknownEnum);
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
        _ => Err(AuthorityErrorV1::InvalidEncoding),
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
fn encode_role_set(values: &[AuthorityRoleV1]) -> Value {
    Value::Array(values.iter().map(|value| uint(role_code(*value))).collect())
}
fn encode_delegate_class_set(values: &[DelegateClassV1]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| uint(delegate_class_code(*value)))
            .collect(),
    )
}
fn encode_principal_set(values: &[PrincipalRefV1]) -> Value {
    Value::Array(values.iter().map(encode_principal).collect())
}

fn encode_scope(value: &CapabilityScopeV1) -> Value {
    Value::Array(vec![
        encode_string_set(value.resources()),
        encode_string_set(value.actions()),
        encode_string_set(value.purposes()),
        encode_string_set(value.audiences()),
        encode_entity_set(value.actor_entity_ids()),
        encode_entity_set(value.subject_ids()),
        encode_entity_set(value.participant_ids()),
        optional_plugin_value(value.plugin_id()),
        encode_role_set(value.principal_roles()),
        uint(value.max_uses()),
        uint(value.budget()),
        encode_string_set(value.environment_constraints()),
    ])
}

fn decode_scope(value: &Value) -> Result<CapabilityScopeV1, AuthorityErrorV1> {
    let fields = exact_array(value, 12)?;
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: decode_string_set(&fields[0])?,
        actions: decode_string_set(&fields[1])?,
        purposes: decode_string_set(&fields[2])?,
        audiences: decode_string_set(&fields[3])?,
        actor_entity_ids: decode_entity_set(&fields[4])?,
        subject_ids: decode_entity_set(&fields[5])?,
        participant_ids: decode_entity_set(&fields[6])?,
        plugin_id: decode_optional_plugin(&fields[7])?,
        principal_roles: decode_role_set(&fields[8])?,
        max_uses: decode_u64(&fields[9])?,
        budget: decode_u64(&fields[10])?,
        environment_constraints: decode_string_set(&fields[11])?,
    })
}

fn encode_grant(value: &CapabilityGrantV1) -> Value {
    Value::Array(vec![
        bytes(&GRANT_MAGIC),
        uint(VERSION),
        hash_value(value.grant_id),
        encode_principal(&value.grantor),
        encode_grantee(&value.grantee),
        text(&value.trust_domain),
        encode_scope(&value.scope),
        uint(value.valid_from_position.as_u64()),
        uint(value.valid_until_position.as_u64()),
        optional_hash_value(value.parent_grant_id),
        uint(value.delegation_depth),
        uint(value.max_delegation_depth),
        encode_delegate_class_set(&value.permitted_delegate_classes),
        encode_hash_set(&value.consent_references),
        hash_value(value.policy_revision),
        bytes(&timeline_bytes(value.issuance_timeline)),
        uint(value.issuance_seq.as_u64()),
        uint(value.revocation_epoch),
        optional_seq_value(value.revocation_fence),
        hash_value(value.authority_registry_digest),
    ])
}

fn decode_grant(fields: &[Value]) -> Result<CapabilityGrantV1, AuthorityErrorV1> {
    expect_header(fields, GRANT_MAGIC)?;
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: decode_hash(&fields[2])?,
        grantor: decode_principal_value(&fields[3])?,
        grantee: decode_grantee(&fields[4])?,
        trust_domain: decode_text(&fields[5])?,
        scope: decode_scope(&fields[6])?,
        valid_from_position: Seq::from_u64(decode_u64(&fields[7])?),
        valid_until_position: Seq::from_u64(decode_u64(&fields[8])?),
        parent_grant_id: decode_optional_hash(&fields[9])?,
        delegation_depth: decode_u8(&fields[10])?,
        max_delegation_depth: decode_u8(&fields[11])?,
        permitted_delegate_classes: decode_delegate_class_set(&fields[12])?,
        consent_references: decode_hash_set(&fields[13])?,
        policy_revision: decode_hash(&fields[14])?,
        issuance_timeline: decode_timeline(&fields[15])?,
        issuance_seq: Seq::from_u64(decode_u64(&fields[16])?),
        revocation_epoch: decode_u64(&fields[17])?,
        revocation_fence: decode_optional_seq(&fields[18])?,
        authority_registry_digest: decode_hash(&fields[19])?,
    })
}

fn encode_decision(value: &AuthorizationDecisionV1) -> Value {
    Value::Array(vec![
        bytes(&DECISION_MAGIC),
        uint(VERSION),
        encode_principal(&value.principal),
        uint(role_code(value.principal_role)),
        bytes(&entity_bytes(value.actor_entity_id)),
        optional_entity_value(value.subject_id),
        optional_entity_value(value.participant_id),
        optional_plugin_value(value.plugin_id),
        optional_fixed_value(value.installation_id),
        optional_principal_value(value.originating_principal.as_ref()),
        encode_principal_set(&value.acting_delegates),
        optional_hash_value(value.grant_id),
        hash_value(value.policy_revision),
        bytes(&timeline_bytes(value.authority_timeline)),
        uint(value.at_position.as_u64()),
        hash_value(value.authority_registry_digest),
        uint(value.outcome.code()),
        optional_error_value(value.error),
        hash_value(value.request_digest),
        hash_value(value.decision_digest),
    ])
}

fn decode_decision(fields: &[Value]) -> Result<AuthorizationDecisionV1, AuthorityErrorV1> {
    expect_header(fields, DECISION_MAGIC)
        .and_then(|()| decode_decision_fields(fields))
        .and_then(validate_decision)
}

fn decode_decision_fields(fields: &[Value]) -> Result<AuthorizationDecisionV1, AuthorityErrorV1> {
    Ok(AuthorizationDecisionV1 {
        principal: decode_principal_value(&fields[2])?,
        principal_role: decode_role(&fields[3])?,
        actor_entity_id: decode_entity(&fields[4])?,
        subject_id: decode_optional_entity(&fields[5])?,
        participant_id: decode_optional_entity(&fields[6])?,
        plugin_id: decode_optional_plugin(&fields[7])?,
        installation_id: decode_optional_fixed(&fields[8])?,
        originating_principal: decode_optional_principal(&fields[9])?,
        acting_delegates: decode_principal_set(&fields[10])?,
        grant_id: decode_optional_hash(&fields[11])?,
        policy_revision: decode_hash(&fields[12])?,
        authority_timeline: decode_timeline(&fields[13])?,
        at_position: Seq::from_u64(decode_u64(&fields[14])?),
        authority_registry_digest: decode_hash(&fields[15])?,
        outcome: AuthorizationOutcomeV1::from_code(decode_u8(&fields[16])?)?,
        error: decode_optional_error(&fields[17])?,
        request_digest: decode_hash(&fields[18])?,
        decision_digest: decode_hash(&fields[19])?,
    })
}

fn validate_decision(
    decoded: AuthorizationDecisionV1,
) -> Result<AuthorizationDecisionV1, AuthorityErrorV1> {
    validate_hash(decoded.policy_revision)
        .and_then(|()| validate_hash(decoded.request_digest))
        .and_then(|()| validate_hash(decoded.decision_digest))
        .and_then(|()| validate_hash(decoded.authority_registry_digest))
        .and_then(|()| validate_optional_hash(decoded.grant_id))
        .and_then(|()| validate_timeline_id(decoded.authority_timeline))
        .and_then(|()| validate_entity_id(decoded.actor_entity_id))
        .and_then(|()| validate_optional_entity_id(decoded.subject_id))
        .and_then(|()| validate_optional_entity_id(decoded.participant_id))
        .and_then(|()| validate_optional_plugin_id(decoded.plugin_id))
        .and_then(|()| validate_plugin_context(decoded.plugin_id, decoded.installation_id))
        .and_then(|()| validate_decision_evidence(&decoded))
        .and_then(|()| {
            if decoded.acting_delegates.len() > usize::from(MAX_AUTHORITY_DELEGATION_DEPTH) + 1 {
                Err(AuthorityErrorV1::FieldOutOfBounds)
            } else if decision_digest(&decoded) == decoded.decision_digest {
                Ok(decoded)
            } else {
                Err(AuthorityErrorV1::DigestMismatch)
            }
        })
}

fn validate_decision_evidence(decision: &AuthorizationDecisionV1) -> Result<(), AuthorityErrorV1> {
    if decision
        .acting_delegates
        .iter()
        .enumerate()
        .any(|(index, principal)| decision.acting_delegates[..index].contains(principal))
    {
        return Err(AuthorityErrorV1::DuplicateIdentity);
    }
    let complete_grant_evidence = match decision.grant_id {
        Some(_) => {
            decision.originating_principal.is_some() && !decision.acting_delegates.is_empty()
        }
        None => decision.originating_principal.is_none() && decision.acting_delegates.is_empty(),
    };
    let active_is_complete = decision.outcome != AuthorizationOutcomeV1::Active
        || (decision.grant_id.is_some()
            && decision.acting_delegates.last() == Some(&decision.principal));
    let outcome_matches_error = match decision.outcome {
        AuthorizationOutcomeV1::Active | AuthorizationOutcomeV1::Expired => {
            decision.error.is_none()
        }
        AuthorizationOutcomeV1::RevokedAtFence => {
            decision.error == Some(AuthorityErrorV1::RevokedAtFence)
        }
        AuthorizationOutcomeV1::ParentInvalid => {
            decision.error == Some(AuthorityErrorV1::DelegationInvalid)
        }
        AuthorizationOutcomeV1::ConsentMissing => {
            decision.error == Some(AuthorityErrorV1::ConsentMissing)
        }
        AuthorizationOutcomeV1::RevocationStateStale => {
            decision.error == Some(AuthorityErrorV1::RevocationStateStale)
        }
        AuthorizationOutcomeV1::IndeterminateFailClosed => matches!(
            decision.error,
            Some(
                AuthorityErrorV1::PrincipalUnresolved
                    | AuthorityErrorV1::CapabilityMissing
                    | AuthorityErrorV1::PolicyIndeterminate
                    | AuthorityErrorV1::SourceUnavailable
                    | AuthorityErrorV1::UnauthorizedSource
                    | AuthorityErrorV1::ProvenanceMissing
                    | AuthorityErrorV1::BudgetExceeded
                    | AuthorityErrorV1::NonInterferenceDivergence
            )
        ),
    };
    if complete_grant_evidence && active_is_complete && outcome_matches_error {
        Ok(())
    } else {
        Err(AuthorityErrorV1::ProvenanceMissing)
    }
}

fn decode_text(value: &Value) -> Result<String, AuthorityErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_u8(value: &Value) -> Result<u8, AuthorityErrorV1> {
    match value {
        Value::Integer(value) => {
            u8::try_from(*value).map_err(|_| AuthorityErrorV1::InvalidEncoding)
        }
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_u64(value: &Value) -> Result<u64, AuthorityErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| AuthorityErrorV1::InvalidEncoding)
        }
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_fixed<const N: usize>(value: &Value) -> Result<[u8; N], AuthorityErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| AuthorityErrorV1::InvalidEncoding),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
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
fn decode_optional_seq(value: &Value) -> Result<Option<Seq>, AuthorityErrorV1> {
    decode_optional_u64(value).map(|value| value.map(Seq::from_u64))
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
fn decode_optional_entity(value: &Value) -> Result<Option<EntityId>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_entity(value).map(Some),
    }
}
fn decode_optional_fixed<const N: usize>(
    value: &Value,
) -> Result<Option<[u8; N]>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_fixed(value).map(Some),
    }
}
fn decode_optional_principal(value: &Value) -> Result<Option<PrincipalRefV1>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_principal_value(value).map(Some),
    }
}

fn decode_optional_error(value: &Value) -> Result<Option<AuthorityErrorV1>, AuthorityErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => decode_u8(value)
            .and_then(AuthorityErrorV1::from_code)
            .map(Some),
    }
}
fn decode_role(value: &Value) -> Result<AuthorityRoleV1, AuthorityErrorV1> {
    match decode_u8(value)? {
        0 => Ok(AuthorityRoleV1::Actor),
        1 => Ok(AuthorityRoleV1::Approver),
        2 => Ok(AuthorityRoleV1::Evaluator),
        _ => Err(AuthorityErrorV1::UnknownEnum),
    }
}
fn decode_delegate_class(value: &Value) -> Result<DelegateClassV1, AuthorityErrorV1> {
    match decode_u8(value)? {
        0 => Ok(DelegateClassV1::Principal),
        _ => Err(AuthorityErrorV1::UnknownEnum),
    }
}
fn decode_timeline(value: &Value) -> Result<TimelineId, AuthorityErrorV1> {
    decode_fixed::<16>(value)
        .map(|raw| TimelineId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(raw))))
}
fn decode_string_set(value: &Value) -> Result<Vec<String>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_text).collect(),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_entity_set(value: &Value) -> Result<Vec<EntityId>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_entity).collect(),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_hash_set(value: &Value) -> Result<Vec<Hash>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_hash).collect(),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_role_set(value: &Value) -> Result<Vec<AuthorityRoleV1>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_role).collect(),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_delegate_class_set(value: &Value) -> Result<Vec<DelegateClassV1>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_delegate_class).collect(),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
fn decode_principal_set(value: &Value) -> Result<Vec<PrincipalRefV1>, AuthorityErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode_principal_value).collect(),
        _ => Err(AuthorityErrorV1::InvalidEncoding),
    }
}
