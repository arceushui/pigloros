//! The consent-bound half of a Principal's authority (#309, owner
//! decisions 1(a) and 2(b); ADR-039, ADR-059).
//!
//! A Principal whose provisioning binds consents holds two grants. Its base
//! grant covers the operations no consent governs. Its consent-bound grant
//! covers the consented operations: it names the consent subject and
//! references every consent on the Principal's one consent Timeline, so the
//! ADR-059 evaluator requires each referenced consent to be active and to
//! cover the request. A request is decided on the consent-bound chain exactly
//! when that grant's scope covers its resource, action and purpose; every
//! other request, including the exempt operations
//! ([`GatewayOperationV1::consent_exempt`]), is decided on the base chain,
//! so a revoked consent blocks only the operations it governs.
//!
//! A consent is revoked at its ADR-039 fence: the sequence of its
//! `consent.revoked.v1` Event on the consent Timeline. The host brings the
//! consent Timeline head current before every decision, so a revocation takes
//! effect before the next decision.

use pos_core::{
    AuthorityViewV1, ConsentEvidenceV1, ConsentGrantRefV1, EntityId, EventId, Hash, Seq, TimelineId,
};

use super::{GatewayAuthorizationRequest, GatewayOperationV1};

/// One consent as the host discloses it: the `EventId` of its
/// `consent.granted.v1` Event (D7), its parties and its revocation, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayConsentV1 {
    consent_ref: EventId,
    grantee: EntityId,
    grant_seq: Seq,
    export_permitted: bool,
    revocation: Option<(EventId, Seq)>,
}

impl GatewayConsentV1 {
    /// One consent granted by the Event `consent_ref` at `grant_seq` to
    /// `grantee`, revoked by the Event and at the fence `revocation` names.
    #[must_use]
    pub const fn new(
        consent_ref: EventId,
        grantee: EntityId,
        grant_seq: Seq,
        export_permitted: bool,
        revocation: Option<(EventId, Seq)>,
    ) -> Self {
        Self {
            consent_ref,
            grantee,
            grant_seq,
            export_permitted,
            revocation,
        }
    }

    /// This consent, revoked by the Event `revocation` at its ADR-039
    /// `fence`.
    #[must_use]
    pub const fn revoked_at(self, revocation: EventId, fence: Seq) -> Self {
        Self {
            revocation: Some((revocation, fence)),
            ..self
        }
    }

    /// The `EventId` of the consent's `consent.granted.v1` Event (D7).
    #[must_use]
    pub const fn consent_ref(&self) -> EventId {
        self.consent_ref
    }

    /// The entity the consent grants.
    #[must_use]
    pub const fn grantee(&self) -> EntityId {
        self.grantee
    }

    /// The consent Timeline sequence of the grant.
    #[must_use]
    pub const fn grant_seq(&self) -> Seq {
        self.grant_seq
    }

    /// Whether the consent permits export.
    #[must_use]
    pub const fn export_permitted(&self) -> bool {
        self.export_permitted
    }

    /// The `consent.revoked.v1` Event and its fence, once revoked.
    #[must_use]
    pub const fn revocation(&self) -> Option<(EventId, Seq)> {
        self.revocation
    }
}

/// Every consent of one consent Timeline at one head: the ADR-059 records
/// the evaluator decides with, in consent-ID order, and their disclosure, in
/// Timeline order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConsentsV1 {
    timeline: TimelineId,
    head: Seq,
    subject: EntityId,
    references: Vec<ConsentGrantRefV1>,
    disclosed: Vec<GatewayConsentV1>,
}

impl GatewayConsentsV1 {
    /// The consents of `subject` on `timeline` at `head`.
    #[must_use]
    pub const fn new(
        timeline: TimelineId,
        head: Seq,
        subject: EntityId,
        references: Vec<ConsentGrantRefV1>,
        disclosed: Vec<GatewayConsentV1>,
    ) -> Self {
        Self {
            timeline,
            head,
            subject,
            references,
            disclosed,
        }
    }

    /// The consent Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// The consent Timeline head the consents were read at.
    #[must_use]
    pub const fn head(&self) -> Seq {
        self.head
    }

    /// The consent subject.
    #[must_use]
    pub const fn subject(&self) -> EntityId {
        self.subject
    }

    /// The consents in consent Timeline order.
    #[must_use]
    pub fn disclosed(&self) -> &[GatewayConsentV1] {
        &self.disclosed
    }

    /// The consent `consent_ref` names, if it is one of these.
    #[must_use]
    pub fn named(&self, consent_ref: EventId) -> Option<&GatewayConsentV1> {
        self.disclosed
            .iter()
            .find(|consent| consent.consent_ref == consent_ref)
    }

    /// The registry bindings of the ADR-059 records.
    pub(crate) fn bindings(&self) -> impl Iterator<Item = Hash> + '_ {
        self.references
            .iter()
            .map(ConsentGrantRefV1::binding_digest)
    }
}

/// The consent-bound chain of a Principal and its consents; the consents
/// are `None` until the host first reads the consent Timeline.
#[derive(Clone, Debug)]
pub struct GatewayConsentedAuthorityV1 {
    view: AuthorityViewV1,
    timeline: TimelineId,
    consents: Option<GatewayConsentsV1>,
}

impl GatewayConsentedAuthorityV1 {
    /// The consent-bound chain `view`, whose consents are recorded on
    /// `timeline` and, once read, are `consents`.
    #[must_use]
    pub const fn new(
        view: AuthorityViewV1,
        timeline: TimelineId,
        consents: Option<GatewayConsentsV1>,
    ) -> Self {
        Self {
            view,
            timeline,
            consents,
        }
    }

    /// The consent-bound chain.
    #[must_use]
    pub const fn view(&self) -> &AuthorityViewV1 {
        &self.view
    }

    /// The consent Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// The consents, once read.
    #[must_use]
    pub const fn consents(&self) -> Option<&GatewayConsentsV1> {
        self.consents.as_ref()
    }

    /// Whether the consent-bound grant covers `request`: its resource,
    /// action and purpose are all in the grant's scope.
    pub(crate) fn covers(&self, request: &GatewayAuthorizationRequest) -> bool {
        self.view
            .authority()
            .chain()
            .grants()
            .last()
            .is_some_and(|leaf| {
                let scope = leaf.scope();
                scope.resources().contains(&request.resource)
                    && scope.actions().contains(&request.action)
                    && scope.purposes().contains(&request.purpose)
            })
    }

    /// Bind `request` to the consents: the subject, every referenced consent
    /// and the consent Timeline coordinate the evaluator checks. Unread
    /// consents leave the request stale, so it fails closed as
    /// `RevocationStateStale`.
    pub(crate) fn bind(
        &self,
        mut request: GatewayAuthorizationRequest,
    ) -> GatewayAuthorizationRequest {
        match &self.consents {
            Some(consents) => {
                request.subject_id = Some(consents.subject);
                request.consent_timeline = Some(consents.timeline);
                request.consent_at_position = Some(consents.head);
                request.consent = ConsentEvidenceV1::Resolved {
                    grants: consents.references.clone(),
                };
            }
            None => request.revocation_state_current = false,
        }
        request
    }
}

impl GatewayOperationV1 {
    /// The operations no consent may govern: reading the Session, revoking
    /// a consent and the network capability stay available whatever consent
    /// is revoked (owner decision 2(b) on #309), and an action is decided
    /// again at its admission commit fence on the base chain alone.
    pub const CONSENT_EXEMPT: &'static [Self] = &[
        Self::NETWORK,
        Self::READ_SESSION,
        Self::REVOKE_CONSENT,
        Self::SUBMIT_WORLD_ACTION,
    ];

    /// Whether no consent may govern this operation.
    #[must_use]
    pub fn consent_exempt(self) -> bool {
        Self::CONSENT_EXEMPT.contains(&self)
    }
}
