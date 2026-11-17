//! The consent-bound part of a Principal's authority (#309, owner decisions
//! 1(a) and 2(b); ADR-039, ADR-059).
//!
//! A Principal whose provisioning binds consents holds one root grant of the
//! operations no consent governs and, for each consent, one consent-bound root
//! grant of the operations that consent governs: the granted operations whose
//! resource is one of the consent's data categories and whose purpose is the
//! consent's purpose. Each consent-bound grant names the consent subject and
//! references exactly its own consent, so the ADR-059 evaluator requires that
//! consent to be active and to cover the request. A request is decided on the
//! chain of the consent whose grant covers its resource, action and purpose,
//! and every other request on the root chain, so revoking a consent blocks
//! exactly the operations it governs. No consent governs an exempt operation
//! ([`GatewayOperationV1::consent_exempt`]).
//!
//! A consent is revoked at its ADR-039 fence: the sequence of its first
//! `consent.revoked.v1` Event on the consent Timeline. The host brings the
//! consent Timeline head current before every decision, so a revocation takes
//! effect before the next decision.

use pos_core::{
    AuthorityViewV1, ConsentEvidenceV1, ConsentGrantRefV1, CorrelationId, EntityId, EventId, Hash,
    Seq, TimelineId,
};

use super::{GatewayAuthorizationRequest, GatewayOperationV1};

/// The revocation of one consent: the `consent.revoked.v1` Event, its fence
/// and the revocation key the host recorded with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayConsentRevocationV1 {
    event: EventId,
    fence: Seq,
    key: Option<CorrelationId>,
}

impl GatewayConsentRevocationV1 {
    /// The revocation recorded by `event` at `fence` under `key`.
    #[must_use]
    pub const fn new(event: EventId, fence: Seq, key: Option<CorrelationId>) -> Self {
        Self { event, fence, key }
    }

    /// The `consent.revoked.v1` Event.
    #[must_use]
    pub const fn event(&self) -> EventId {
        self.event
    }

    /// The ADR-039 fence: the Event's consent Timeline sequence.
    #[must_use]
    pub const fn fence(&self) -> Seq {
        self.fence
    }

    /// The revocation key recorded with the Event, if any.
    #[must_use]
    pub const fn key(&self) -> Option<CorrelationId> {
        self.key
    }
}

/// One consent as the host discloses it: the `EventId` of its
/// `consent.granted.v1` Event (D7), its grantee, its sequence, whether it
/// permits export, and its revocation, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayConsentV1 {
    consent_ref: EventId,
    grantee: EntityId,
    grant_seq: Seq,
    export_permitted: bool,
    revocation: Option<GatewayConsentRevocationV1>,
}

impl GatewayConsentV1 {
    /// One consent granted by the Event `consent_ref` at `grant_seq` to
    /// `grantee`, not yet revoked.
    #[must_use]
    pub const fn new(
        consent_ref: EventId,
        grantee: EntityId,
        grant_seq: Seq,
        export_permitted: bool,
    ) -> Self {
        Self {
            consent_ref,
            grantee,
            grant_seq,
            export_permitted,
            revocation: None,
        }
    }

    /// This consent, revoked by `revocation`.
    #[must_use]
    pub const fn revoked_by(self, revocation: GatewayConsentRevocationV1) -> Self {
        Self {
            revocation: Some(revocation),
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

    /// The consent's revocation, once revoked.
    #[must_use]
    pub const fn revocation(&self) -> Option<GatewayConsentRevocationV1> {
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

    /// The consents `actor` is a party to, as its subject or its grantee.
    pub fn of_party(&self, actor: EntityId) -> impl Iterator<Item = &GatewayConsentV1> {
        let subject = self.subject == actor;
        self.disclosed
            .iter()
            .filter(move |consent| subject || consent.grantee == actor)
    }

    /// The consent `consent_ref` names, if `actor` is a party to it.
    #[must_use]
    pub fn named_for(&self, actor: EntityId, consent_ref: EventId) -> Option<GatewayConsentV1> {
        self.of_party(actor)
            .find(|consent| consent.consent_ref == consent_ref)
            .copied()
    }

    /// The registry bindings of the ADR-059 records.
    pub(crate) fn bindings(&self) -> impl Iterator<Item = Hash> + '_ {
        self.references
            .iter()
            .map(ConsentGrantRefV1::binding_digest)
    }

    /// The ADR-059 records the consent IDs `referenced` name.
    fn referenced(&self, referenced: &[Hash]) -> Vec<ConsentGrantRefV1> {
        self.references
            .iter()
            .filter(|reference| referenced.contains(&reference.consent_id()))
            .cloned()
            .collect()
    }
}

/// The consent-bound chains of a Principal, one per consent, and its
/// consents; the consents are `None` until the host first reads the consent
/// Timeline.
#[derive(Clone, Debug)]
pub struct GatewayConsentedAuthorityV1 {
    views: Vec<AuthorityViewV1>,
    timeline: TimelineId,
    consents: Option<GatewayConsentsV1>,
}

impl GatewayConsentedAuthorityV1 {
    /// The consent-bound chains `views`, whose consents are recorded on
    /// `timeline` and, once read, are `consents`.
    #[must_use]
    pub const fn new(
        views: Vec<AuthorityViewV1>,
        timeline: TimelineId,
        consents: Option<GatewayConsentsV1>,
    ) -> Self {
        Self {
            views,
            timeline,
            consents,
        }
    }

    /// The consent-bound chains, one per consent.
    #[must_use]
    pub fn views(&self) -> &[AuthorityViewV1] {
        &self.views
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

    /// The summed head positions of the consent-bound chains.
    pub(crate) fn head_position(&self) -> u64 {
        self.views
            .iter()
            .map(|view| view.authority().head_position().as_u64())
            .fold(0, u64::saturating_add)
    }

    /// The consent-bound chain whose grant covers `request`: its resource,
    /// action and purpose are all in the grant's scope.
    pub(crate) fn covering(
        &self,
        request: &GatewayAuthorizationRequest,
    ) -> Option<&AuthorityViewV1> {
        self.views.iter().find(|view| {
            view.authority()
                .chain()
                .grants()
                .last()
                .is_some_and(|leaf| {
                    let scope = leaf.scope();
                    scope.resources().contains(&request.resource)
                        && scope.actions().contains(&request.action)
                        && scope.purposes().contains(&request.purpose)
                })
        })
    }

    /// Bind `request`, decided on `view`, to the consent `view` references:
    /// the subject, that consent's ADR-059 record and the consent Timeline
    /// coordinate the evaluator checks. Unread consents bind nothing, so the
    /// grant's subject scope refuses the request.
    pub(crate) fn bind(
        &self,
        view: &AuthorityViewV1,
        mut request: GatewayAuthorizationRequest,
    ) -> GatewayAuthorizationRequest {
        if let Some(consents) = &self.consents {
            let referenced = view
                .authority()
                .chain()
                .grants()
                .last()
                .map_or_else(Vec::new, |leaf| {
                    consents.referenced(leaf.consent_references())
                });
            request.subject_id = Some(consents.subject);
            request.consent_timeline = Some(consents.timeline);
            request.consent_at_position = Some(consents.head);
            request.consent = ConsentEvidenceV1::Resolved { grants: referenced };
        }
        request
    }
}

impl GatewayOperationV1 {
    /// The operations no consent may govern (owner decision 2(b) on #309):
    /// reading the Session stays available whatever consent is revoked,
    /// revoking a consent must stay possible after another is revoked, and
    /// the network capability authorizes no data operation.
    pub const CONSENT_EXEMPT: &'static [Self] =
        &[Self::NETWORK, Self::READ_SESSION, Self::REVOKE_CONSENT];

    /// Whether no consent may govern this operation.
    #[must_use]
    pub fn consent_exempt(self) -> bool {
        Self::CONSENT_EXEMPT.contains(&self)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A party sees exactly the consents it is the subject or the grantee of,
    /// and each consent discloses whether it permits export.
    #[test]
    fn a_party_sees_the_consents_it_is_subject_or_grantee_of() {
        let subject = EntityId::new();
        let grantee = EntityId::new();
        let exported = GatewayConsentV1::new(EventId::new(), grantee, Seq::from_u64(1), true);
        let withheld =
            GatewayConsentV1::new(EventId::new(), EntityId::new(), Seq::from_u64(2), false);
        let consents = GatewayConsentsV1::new(
            TimelineId::new(),
            Seq::from_u64(2),
            subject,
            Vec::new(),
            vec![exported, withheld],
        );
        assert!(exported.export_permitted());
        assert!(!withheld.export_permitted());
        assert_eq!(
            consents.of_party(subject).copied().collect::<Vec<_>>(),
            [exported, withheld]
        );
        assert_eq!(
            consents.of_party(grantee).copied().collect::<Vec<_>>(),
            [exported]
        );
        assert_eq!(consents.of_party(EntityId::new()).count(), 0);
        assert_eq!(
            consents.named_for(subject, withheld.consent_ref()),
            Some(withheld)
        );
        assert_eq!(consents.named_for(grantee, withheld.consent_ref()), None);
    }
}
