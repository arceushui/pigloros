//! Installed community administrative and in-operation execution authority
//! (ADR-129 A5.1, A5.2(3a), A5.3(2), A5.8 and revision 6 R6.2).
//!
//! The concrete owner evaluates every request itself (A5.9). For one
//! administrative call it:
//! 1. derives the closed administrative request from the operation shape
//!    ([`CommunityAdministrativeRequestV1::derive`], A5.5 step 1);
//! 2. authenticates the call's one FAE1 under the CAP1-pinned FAP1, its bound
//!    nonce, its validity at a fresh trusted wall sample and the CAP1 actor
//!    row ([`CommunityLifecycleAuthorityV1::authenticate`], R6.2(3)–(4));
//! 3. evaluates the administrative request and each in-operation member
//!    request against the chain it loaded from its own store, under a
//!    per-request snapshot admitted only through the installed as-issued
//!    attestation set (R6.2(5)).
//!
//! Every authority failure is the single code 12 `EvidenceUnavailable`
//! (A5.5). Composition defects refuse installation with `InvalidBinding`;
//! they are never call results. No method accepts an authentication result,
//! registry snapshot, principal, actor or decision from its caller.
//!
//! The evaluators reach a domain only through the crate-private store-domain
//! seam (owner decision on #560, note 22571): they are generic over it, so
//! every backend's domain is evaluated by the same code. The Memory domain is
//! its only implementation until the `SQLite` domain lands.
//!
//! Execution authority exists only inside an administrative call: a member
//! request is built from the call's own Timeline and operation constraint.
//! Community `run_pass` and `verify_recording` authority is therefore
//! unavailable until the F7 amendment (R6.2(6)); nothing here can build it.

use pos_core::community_lifecycle::{
    community_authentication_nonce_v1, community_capability_attestation_digest_v1, ArtifactRefV1,
    CommunityAuthorityCatalogueV1, CommunityInitializationSourceV1,
    CommunityLifecycleErrorV1 as Error, CommunityMemberBindingV1, COMMUNITY_AUD_SCHEMA_V1,
    COMMUNITY_PRINCIPAL_SCHEMA_V1,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalEvidenceV1, ForkAuthenticationPolicyV1,
};
use pos_core::trusted_clock::{
    GuardMonotonicSourceV1, TrustedClockReservationV1, TrustedWallSourceV1,
};
use pos_core::{
    AuthenticatedPrincipalResultV1, AuthorityEvaluatorV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, AuthorityTrustRootSealV1, AuthorizationDecisionV1,
    AuthorizationRequestDraftV1, AuthorizationRequestV1, CanonicalBytes, ConsentEvidenceV1,
    EntityId, Hash, PersistedAuthorityV1, TimelineId, WallTime, MAX_AUTHORITY_TEXT_BYTES,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, VerifiedAuthenticatedPrincipalEvidenceV1,
};

use super::attestation::{authenticated_result, evaluation_snapshot};
use super::initializer::CommunityInitializerOwnerV1;
use super::store_domain::CommunityStoreDomainV1;

const LIFECYCLE_CATEGORY: &str = "community.lifecycle-control";
const EXECUTION_CATEGORY: &str = "community.execution-state";
const INITIALIZER_CATEGORY: &str = "community.initial-state";
const PURPOSE: &str = "lifecycle-administration";

/// The five closed administrative actions (ADR-129 §1, A5.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityAdministrativeActionV1 {
    /// First initialization of a Timeline.
    Initialize,
    /// Generation transition of an initialized Timeline.
    Transition,
    /// Fork from the current parent generation.
    Fork,
    /// Retirement of the current generation.
    Retire,
    /// Authenticated quarantine reset.
    QuarantineReset,
}

impl CommunityAdministrativeActionV1 {
    /// The exact authority action string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "community.initialize.v1",
            Self::Transition => "community.transition.v1",
            Self::Fork => "community.fork.v1",
            Self::Retire => "community.retire.v1",
            Self::QuarantineReset => "community.quarantine.reset.v1",
        }
    }

    /// The `<k>` of the operation constraint: `i` for CGI1 operations, `f`
    /// for Fork and `c` for control operations.
    const fn operation_kind(self) -> char {
        match self {
            Self::Initialize | Self::Transition => 'i',
            Self::Fork => 'f',
            Self::Retire | Self::QuarantineReset => 'c',
        }
    }

    /// Whether the operation reads or writes State (A5.2(2)–(4)).
    const fn uses_state(self) -> bool {
        matches!(self, Self::Initialize | Self::Transition | Self::Fork)
    }
}

/// The caller-form shape of one administrative entry point (A5.3(0)).
///
/// It carries only the fields the action derivation reads. Host-derived
/// fields (G, refs, horizons and the Fork child T) have no place here.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityAdministrativeOperationV1 {
    /// `initialize`: initialization or transition of `timeline`.
    Initialize {
        /// CGI1 target Timeline.
        timeline: TimelineId,
        /// CGI1 `operation_id`.
        operation_id: [u8; 16],
        /// CGI1 `initial_source`.
        initial_source: CommunityInitializationSourceV1,
        /// CGI1 expected prior generation.
        expected_prior_generation: Option<[u8; 16]>,
        /// CGI1 expected prior head.
        expected_prior_head_digest: Option<Hash>,
    },
    /// `fork_current`: the child CGI1's source and prior.
    ForkCurrent {
        /// Child CGI1 `initial_source`; it must be a Fork source.
        initial_source: CommunityInitializationSourceV1,
        /// Child CGI1 expected prior generation.
        expected_prior_generation: Option<[u8; 16]>,
        /// Child CGI1 expected prior head.
        expected_prior_head_digest: Option<Hash>,
    },
    /// `control` CGC1 reason 1 Retirement.
    Retire {
        /// CGC1 Timeline.
        timeline: TimelineId,
        /// CGC1 control operation identity.
        control_operation_id: [u8; 16],
    },
    /// `control` CQC1 `AuthenticatedReset`.
    QuarantineReset {
        /// CQK1 Timeline.
        timeline: TimelineId,
        /// CQC1 control operation identity.
        control_operation_id: [u8; 16],
    },
}

/// One derived administrative request: action, resource Timeline and
/// operation identity (A5.1 action-derivation table).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityAdministrativeRequestV1 {
    action: CommunityAdministrativeActionV1,
    timeline: TimelineId,
    operation_id: [u8; 16],
}

impl CommunityAdministrativeRequestV1 {
    /// Derive the action and resource Timeline from an operation shape.
    ///
    /// This depends on the caller's shape only and runs before any
    /// authority call (A5.5 step 1).
    ///
    /// # Errors
    /// Returns `InvalidBinding` for every shape outside the A5.1 table: an
    /// `initialize` with a Fork source, a prior-State source without a prior
    /// or a half-null prior; a `fork_current` without a Fork source or with a
    /// prior; and a zero Timeline or operation identity.
    pub fn derive(operation: &CommunityAdministrativeOperationV1) -> Result<Self, Error> {
        use CommunityAdministrativeActionV1 as Action;
        use CommunityAdministrativeOperationV1 as Operation;
        use CommunityInitializationSourceV1 as Source;
        let derived = match *operation {
            Operation::Initialize {
                timeline,
                operation_id,
                initial_source,
                expected_prior_generation,
                expected_prior_head_digest,
            } => match (
                initial_source,
                expected_prior_generation.is_some(),
                expected_prior_head_digest.is_some(),
            ) {
                (Source::Initializer(_), false, false) => {
                    Some((Action::Initialize, timeline, operation_id))
                }
                (Source::Initializer(_) | Source::PriorState(_), true, true) => {
                    Some((Action::Transition, timeline, operation_id))
                }
                _ => None,
            },
            Operation::ForkCurrent {
                initial_source:
                    Source::Fork {
                        timeline,
                        operation_id,
                        ..
                    },
                expected_prior_generation: None,
                expected_prior_head_digest: None,
            } => Some((Action::Fork, timeline, operation_id)),
            Operation::ForkCurrent { .. } => None,
            Operation::Retire {
                timeline,
                control_operation_id,
            } => Some((Action::Retire, timeline, control_operation_id)),
            Operation::QuarantineReset {
                timeline,
                control_operation_id,
            } => Some((Action::QuarantineReset, timeline, control_operation_id)),
        };
        derived
            .filter(|(_, timeline, operation_id)| {
                timeline.inner().to_bytes() != [0; 16] && *operation_id != [0; 16]
            })
            .map(|(action, timeline, operation_id)| Self {
                action,
                timeline,
                operation_id,
            })
            .ok_or(Error::InvalidBinding)
    }

    /// The derived administrative action.
    #[must_use]
    pub const fn action(&self) -> CommunityAdministrativeActionV1 {
        self.action
    }

    /// The resource Timeline: the target T, or the parent T for Fork.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// The exact 52-byte resource `community:<T32>:lifecycle`.
    #[must_use]
    pub fn resource(&self) -> String {
        let mut resource = String::with_capacity(52);
        resource.push_str("community:");
        push_hex(&mut resource, &self.timeline.inner().to_bytes());
        resource.push_str(":lifecycle");
        resource
    }

    /// The exact 54-byte constraint `community.operation:<k>:<O32>`.
    #[must_use]
    pub fn operation_constraint(&self) -> String {
        let mut constraint = String::with_capacity(54);
        constraint.push_str("community.operation:");
        constraint.push(self.action.operation_kind());
        constraint.push(':');
        push_hex(&mut constraint, &self.operation_id);
        constraint
    }
}

/// The two in-operation member data-use actions (A5.2(2)–(3)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityMemberActionV1 {
    /// Read a carried or Fork-parent member State.
    Read,
    /// Execute a member of the new roster.
    Execute,
}

impl CommunityMemberActionV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Execute => "execute",
        }
    }
}

/// Installed authority inputs, fixed at the trusted composition root.
pub struct CommunityLifecycleAuthorityInputV1 {
    /// The pinned CAP1.
    pub catalogue: CommunityAuthorityCatalogueV1,
    /// The community FAP1 whose digest CAP1 pins.
    pub authentication_policy: ForkAuthenticationPolicyV1,
    /// The attestation snapshot the store's persistence host was built from.
    pub attestation: AuthorityRegistrySnapshotV1,
    /// Every Fork-admission FAP1 installed by the same composition root.
    pub fork_admission_policies: Vec<ForkAuthenticationPolicyV1>,
    /// The installed recipient of the selected cells (A5.2(2)–(3)), the
    /// audience of every in-operation member request; 1..128 bytes.
    pub member_recipient: String,
    /// The nonzero incarnation of the one domain this authority serves.
    ///
    /// This binds the authority to the trusted composition's incarnation
    /// label, not to a store identity: a domain presenting the installed
    /// label is accepted by design. Its evidence still comes from that
    /// domain's own store, and every chain grant must verify against the
    /// installed attestation snapshot.
    pub store_incarnation: [u8; 16],
}

/// Installed community lifecycle authority with its trusted wall and guard
/// monotonic sources, which every call's trusted-clock reservation uses.
pub struct CommunityLifecycleAuthorityV1 {
    catalogue: CommunityAuthorityCatalogueV1,
    catalogue_digest: Hash,
    policy: ForkAuthenticationPolicyV1,
    attestation: AuthorityRegistrySnapshotV1,
    member_recipient: String,
    store_incarnation: [u8; 16],
    wall: Box<dyn TrustedWallSourceV1>,
    mono: Box<dyn GuardMonotonicSourceV1>,
}

impl CommunityLifecycleAuthorityV1 {
    /// Install the authority at the trusted composition root, which alone
    /// holds the [`AuthorityTrustRootSealV1`] (#1374). Without the seal it
    /// cannot be installed:
    ///
    /// ```compile_fail,E0061
    /// use pos_core::trusted_clock::{GuardMonotonicSourceV1, TrustedWallSourceV1};
    /// use pos_store::community::{
    ///     CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1,
    /// };
    /// fn forge(
    ///     input: CommunityLifecycleAuthorityInputV1,
    ///     wall: impl TrustedWallSourceV1 + 'static,
    ///     mono: impl GuardMonotonicSourceV1 + 'static,
    /// ) {
    ///     let _ = CommunityLifecycleAuthorityV1::new(input, wall, mono);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidBinding` (a composition refusal, R6.2(2)) when the
    /// FAP1 digest differs from CAP1's, the attestation snapshot's registry
    /// digest or attestation digest differs from CAP1's, or any community
    /// adapter key also appears in an installed Fork-admission FAP1, and for
    /// an empty or over-128-byte member recipient, and for a zero store
    /// incarnation.
    pub fn new(
        _seal: &AuthorityTrustRootSealV1,
        input: CommunityLifecycleAuthorityInputV1,
        wall: impl TrustedWallSourceV1 + 'static,
        mono: impl GuardMonotonicSourceV1 + 'static,
    ) -> Result<Self, Error> {
        let pins = input.catalogue.as_input();
        let overlap = input
            .authentication_policy
            .adapters()
            .iter()
            .any(|adapter| {
                input.fork_admission_policies.iter().any(|fork| {
                    fork.adapters()
                        .iter()
                        .any(|other| other.verifying_key == adapter.verifying_key)
                })
            });
        if input.authentication_policy.digest().ok() != Some(pins.fap1_digest)
            || input.attestation.registry_digest() != pins.authority_registry_digest
            || community_capability_attestation_digest_v1(&input.attestation)
                != pins.capability_attestation_digest
            || overlap
            || !(1..=MAX_AUTHORITY_TEXT_BYTES).contains(&input.member_recipient.len())
            || input.store_incarnation == [0; 16]
        {
            return Err(Error::InvalidBinding);
        }
        Ok(Self {
            catalogue_digest: input.catalogue.digest(),
            catalogue: input.catalogue,
            policy: input.authentication_policy,
            attestation: input.attestation,
            member_recipient: input.member_recipient,
            store_incarnation: input.store_incarnation,
            wall: Box::new(wall),
            mono: Box::new(mono),
        })
    }

    /// The CAP1-pinned Plugin trust scope of every CAV1 trust row (D9).
    pub(super) fn trust_scope(&self) -> &str {
        &self.catalogue.as_input().trust_scope
    }

    /// The installed member recipient, CAU1's recipient identity (G6).
    pub(super) fn member_recipient(&self) -> &str {
        &self.member_recipient
    }

    /// Authenticate one administrative call from its one FAE1 (R6.2(3)).
    ///
    /// The FAE1 must decode canonically, verify under the installed FAP1,
    /// carry the nonce bound to H(CAP1) and this request's resource, action
    /// and operation constraint, and be valid at the operation's one trusted
    /// sample. Its principal must have a CAP1 actor row. The FAE1 is a bearer
    /// credential: only its digest is kept, as the result's binding digest.
    ///
    /// Only a verified credential reserves the trusted clock, on `domain`'s
    /// own clock authority. The reservation sample `t_r` is both `now` for
    /// the validity check and every request's `at_time`, so R6.2(3)(iii) has
    /// one shared sample, and the call's decision bound is
    /// `min(D, expires_at)` (owner decision on #560, note 22722, G1).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for any of those failures, for a domain
    /// other than the installed one, and when the trusted clock cannot
    /// reserve (A5.5, "no trusted wall sample").
    pub fn authenticate<D: CommunityStoreDomainV1>(
        &mut self,
        credential: &[u8],
        request: CommunityAdministrativeRequestV1,
        domain: &mut D,
    ) -> Result<CommunityAuthorityCallV1, Error> {
        let nonce = community_authentication_nonce_v1(
            self.catalogue_digest,
            &request.resource(),
            request.action.as_str(),
            &request.operation_constraint(),
        );
        AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(credential)
            .ok()
            .and_then(|evidence| {
                verify_authenticated_principal_evidence_v1(&self.policy, evidence).ok()
            })
            .filter(|verified| verified.evidence().record().operation_nonce == nonce)
            .filter(|_| domain.store_incarnation() == self.store_incarnation)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|verified| {
                domain
                    .reserve_clock(self.wall.as_mut(), self.mono.as_mut())
                    .map(|reservation| (verified, reservation))
            })
            .ok()
            .filter(|(verified, reservation)| {
                let record = verified.evidence().record();
                let now = reservation.sampled_at().as_micros();
                record.issued_at <= now && now < record.expires_at
            })
            .and_then(|(verified, reservation)| self.call(request, &verified, &reservation))
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Derive `authenticated` and the actor from verified evidence (R6.2(3)(iv), (4)).
    fn call(
        &self,
        request: CommunityAdministrativeRequestV1,
        verified: &VerifiedAuthenticatedPrincipalEvidenceV1,
        reservation: &TrustedClockReservationV1,
    ) -> Option<CommunityAuthorityCallV1> {
        principal_digest_v1(&verified.evidence().record().principal)
            .ok()
            .and_then(|principal| self.catalogue.actor_for(principal))
            .and_then(|actor_entity_id| {
                authenticated_result(verified).map(|authenticated| CommunityAuthorityCallV1 {
                    catalogue_digest: self.catalogue_digest,
                    request,
                    decision_bound: reservation.decision_bound().min(authenticated.expires_at()),
                    authenticated,
                    actor_entity_id,
                    reservation_id: reservation.reservation_seq(),
                    at_time: reservation.sampled_at(),
                })
            })
    }

    /// Evaluate the call's administrative request (A5.1) against the chain
    /// `leaf_grant_id` names, loaded now from the domain's own store.
    ///
    /// `leaf_grant_id` is an untrusted locator (A5.1). No loaded chain is
    /// accepted from the caller, so a chain read before a revocation can
    /// never be evaluated as current.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a call another authority issued, a
    /// domain other than the installed one, a missing or foreign leaf, a
    /// leaf that binds consent references, a chain grant not attested as
    /// issued, or a decision that is not `Active`.
    pub fn authorize_administrative<D: CommunityStoreDomainV1>(
        &self,
        call: &CommunityAuthorityCallV1,
        domain: &D,
        leaf_grant_id: Hash,
    ) -> Result<CommunityAuthorityAdmissionV1, Error> {
        self.evaluate(
            call,
            domain,
            leaf_grant_id,
            RequestShapeV1 {
                resource: call.request.resource(),
                data_category: LIFECYCLE_CATEGORY,
                action: call.request.action.as_str(),
                audience: &self.catalogue.as_input().audience,
            },
        )
    }

    /// Evaluate one in-operation member request (A5.2(3a), A5.8) on
    /// `community:<T32>:member:<M64>`, where T is the call's resource
    /// Timeline: the target T, or the parent T for Fork. The audience is the
    /// installed member recipient.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a retire or reset call, which uses
    /// no State, and for every failure `authorize_administrative` refuses.
    pub fn authorize_member<D: CommunityStoreDomainV1>(
        &self,
        call: &CommunityAuthorityCallV1,
        member: &CommunityMemberBindingV1<'_>,
        action: CommunityMemberActionV1,
        domain: &D,
        leaf_grant_id: Hash,
    ) -> Result<CommunityAuthorityAdmissionV1, Error> {
        if !call.request.action.uses_state() {
            return Err(Error::EvidenceUnavailable);
        }
        let mut resource = String::with_capacity(114);
        resource.push_str("community:");
        push_hex(&mut resource, &call.request.timeline.inner().to_bytes());
        resource.push_str(":member:");
        push_hex(&mut resource, member.stable_member_digest().as_bytes());
        self.evaluate(
            call,
            domain,
            leaf_grant_id,
            RequestShapeV1 {
                resource,
                data_category: EXECUTION_CATEGORY,
                action: action.as_str(),
                audience: &self.member_recipient,
            },
        )
    }

    /// Evaluate one R6.1 initializer `read` request on
    /// `community-initializer:<D64>`, where `<D64>` is `initializer`, the
    /// `H(CSC1)` digest of an installed roster State, as lower-case hex. The
    /// audience is the installed member recipient, the recipient of the new
    /// generation's selected cells (R6.1(4)).
    ///
    /// The planner asks for one decision per distinct initializer digest of
    /// a code-0 operation (R6.1(5)), and only for a code-0 source: the call
    /// carries the action, not the CGI1 source, so a prior-State transition
    /// is not refused here.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a Fork, retire or reset call, which
    /// starts from no initializer; for an owner installed for another
    /// authority catalogue or a digest it does not hold; and for every
    /// failure `authorize_administrative` refuses.
    pub fn authorize_initializer<D: CommunityStoreDomainV1>(
        &self,
        call: &CommunityAuthorityCallV1,
        owner: &CommunityInitializerOwnerV1,
        initializer: Hash,
        domain: &D,
        leaf_grant_id: Hash,
    ) -> Result<CommunityAuthorityAdmissionV1, Error> {
        if !matches!(
            call.request.action,
            CommunityAdministrativeActionV1::Initialize
                | CommunityAdministrativeActionV1::Transition
        ) || owner.catalogue_digest() != self.catalogue_digest
            || !owner.holds(initializer)
        {
            return Err(Error::EvidenceUnavailable);
        }
        let mut resource = String::with_capacity(86);
        resource.push_str("community-initializer:");
        push_hex(&mut resource, initializer.as_bytes());
        self.evaluate(
            call,
            domain,
            leaf_grant_id,
            RequestShapeV1 {
                resource,
                data_category: INITIALIZER_CATEGORY,
                action: "read",
                audience: &self.member_recipient,
            },
        )
    }

    /// Check the call is this authority's and the domain is the one it was
    /// installed for, load the chain from the domain's own store through the
    /// store-domain seam (#560, note 22571), and evaluate it.
    fn evaluate<D: CommunityStoreDomainV1>(
        &self,
        call: &CommunityAuthorityCallV1,
        domain: &D,
        leaf_grant_id: Hash,
        shape: RequestShapeV1<'_>,
    ) -> Result<CommunityAuthorityAdmissionV1, Error> {
        if call.catalogue_digest != self.catalogue_digest
            || domain.store_incarnation() != self.store_incarnation
        {
            return Err(Error::EvidenceUnavailable);
        }
        domain
            .load_authority(leaf_grant_id)
            .ok()
            .and_then(|persisted| self.admit(call, &persisted, shape))
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Build the exact request, admit the chain through the attestation set
    /// and require an `Active` decision.
    ///
    /// The leaf lookup cannot miss: a loaded chain is never empty.
    fn admit(
        &self,
        call: &CommunityAuthorityCallV1,
        persisted: &PersistedAuthorityV1,
        shape: RequestShapeV1<'_>,
    ) -> Option<CommunityAuthorityAdmissionV1> {
        let pins = self.catalogue.as_input();
        persisted
            .chain()
            .grants()
            .last()
            .filter(|leaf| leaf.consent_references().is_empty())
            .and_then(|leaf| {
                AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
                    authenticated: call.authenticated.clone(),
                    actor_entity_id: call.actor_entity_id,
                    subject_id: None,
                    participant_id: None,
                    plugin_id: None,
                    installation_id: None,
                    principal_role: AuthorityRoleV1::Actor,
                    resource: shape.resource,
                    data_category: shape.data_category.to_owned(),
                    action: shape.action.to_owned(),
                    purpose: PURPOSE.to_owned(),
                    audience: shape.audience.to_owned(),
                    at_time: call.at_time,
                    authority_timeline: leaf.issuance_timeline(),
                    at_position: persisted.head_position(),
                    consent_timeline: None,
                    consent_at_position: None,
                    use_count: 1,
                    budget: 1,
                    consent_policy_revision: pins.consent_policy_revision,
                    capability_policy_revision: pins.capability_policy_revision,
                    revocation_epoch: persisted.revocation_epoch(),
                    revocation_state_current: true,
                    authority_registry_digest: pins.authority_registry_digest,
                    consent: ConsentEvidenceV1::NotRequired,
                    environment_constraints: vec![call.request.operation_constraint()],
                })
                .ok()
            })
            .and_then(|request| {
                evaluation_snapshot(
                    &self.attestation,
                    pins.authority_registry_digest,
                    call.authenticated.registry_binding_digest(),
                    persisted,
                )
                .map(|snapshot| {
                    let decision =
                        AuthorityEvaluatorV1::authorize(&request, persisted.chain(), &snapshot);
                    (request, decision)
                })
            })
            .filter(|(_, decision)| decision.is_allowed())
            .and_then(|(request, decision)| admission(request, decision))
    }
}

/// The request fields that differ between the mappings.
struct RequestShapeV1<'a> {
    resource: String,
    data_category: &'static str,
    action: &'static str,
    audience: &'a str,
}

/// One authenticated administrative call (R6.2(6)).
///
/// It holds the derived request, the `authenticated` result and actor
/// derived from the call's FAE1, and the trusted-clock reservation sample
/// every request of the call uses as `at_time`.
///
/// It is bound to the H(CAP1) of the authority that issued it, and another
/// authority refuses it. It serves one operation: its `at_time` is the
/// operation's single trusted sample, and the operation's final writer
/// refuses at or after its [`Self::decision_bound`] (A5.4).
///
/// It has no public constructor; only [`CommunityLifecycleAuthorityV1::authenticate`]
/// produces it.
pub struct CommunityAuthorityCallV1 {
    catalogue_digest: Hash,
    request: CommunityAdministrativeRequestV1,
    authenticated: AuthenticatedPrincipalResultV1,
    actor_entity_id: EntityId,
    reservation_id: u64,
    at_time: WallTime,
    decision_bound: WallTime,
}

impl CommunityAuthorityCallV1 {
    /// The derived administrative request this call authenticated for.
    #[must_use]
    pub const fn request(&self) -> &CommunityAdministrativeRequestV1 {
        &self.request
    }

    /// The positive sequence of this call's committed trusted-clock
    /// reservation, the CAU1 `clock_bound` `reservation_id` (G1).
    #[must_use]
    pub const fn reservation_id(&self) -> u64 {
        self.reservation_id
    }

    /// The trusted-clock reservation sample `t_r` of this call.
    #[must_use]
    pub const fn at_time(&self) -> WallTime {
        self.at_time
    }

    /// The credential's expiry (R6.2(3)(iii)).
    #[must_use]
    pub const fn expires_at(&self) -> WallTime {
        self.authenticated.expires_at()
    }

    /// The operation's effective decision bound: the earlier of the
    /// reservation's `D = t_r + 32 s` and the credential's expiry (owner
    /// decision on #560, note 22722, G1). CAU1 records it and the final
    /// writer refuses at or after it (A5.4).
    #[must_use]
    pub const fn decision_bound(&self) -> WallTime {
        self.decision_bound
    }
}

/// One `Active` decision for the exact request the owner built, with the
/// refs derived from it (A5.3(2)). It is minted only by the owner's own
/// evaluation; nothing accepts it back as authority.
pub struct CommunityAuthorityAdmissionV1 {
    request: AuthorizationRequestV1,
    decision: AuthorizationDecisionV1,
    leaf_grant_id: Hash,
    authorization_ref: ArtifactRefV1,
    principal_ref: ArtifactRefV1,
}

impl CommunityAuthorityAdmissionV1 {
    /// The exact request evaluated.
    #[must_use]
    pub const fn request(&self) -> &AuthorizationRequestV1 {
        &self.request
    }

    /// The `Active` decision for that request.
    #[must_use]
    pub const fn decision(&self) -> &AuthorizationDecisionV1 {
        &self.decision
    }

    /// The leaf grant the `Active` decision evaluated, captured when the
    /// admission was minted: only an `Active` decision, which always names
    /// its leaf, is admitted.
    #[must_use]
    pub const fn leaf_grant_id(&self) -> Hash {
        self.leaf_grant_id
    }

    /// `[0x4341_0002, len(AUD1), BLAKE3-256(AUD1)]` over the canonical AUD1.
    #[must_use]
    pub const fn authorization_ref(&self) -> ArtifactRefV1 {
        self.authorization_ref
    }

    /// `[0x4341_0003, len(PRN1), BLAKE3-256(PRN1)]` over the decision's
    /// canonical principal.
    #[must_use]
    pub const fn principal_ref(&self) -> ArtifactRefV1 {
        self.principal_ref
    }
}

fn admission(
    request: AuthorizationRequestV1,
    decision: AuthorizationDecisionV1,
) -> Option<CommunityAuthorityAdmissionV1> {
    decision
        .encode()
        .ok()
        .zip(decision.principal().encode().ok())
        .zip(decision.grant_id())
        .map(
            |((aud, principal), leaf_grant_id)| CommunityAuthorityAdmissionV1 {
                authorization_ref: artifact_ref(COMMUNITY_AUD_SCHEMA_V1, &aud),
                principal_ref: artifact_ref(COMMUNITY_PRINCIPAL_SCHEMA_V1, &principal),
                request,
                decision,
                leaf_grant_id,
            },
        )
}

fn artifact_ref(schema_id: u32, bytes: &CanonicalBytes) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id,
        byte_length: bytes.as_slice().len() as u64,
        digest: *blake3::hash(bytes.as_slice()).as_bytes(),
    }
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
