//! The served `POST /v1/me/consent-revocations` (#309, ADR-039; owner
//! decisions 1(a) and 2(b)).
//!
//! The acting Principal revokes one of its own consents, named by the
//! `EventId` of its `consent.granted.v1` Event (D7). The revocation is one
//! `consent.revoked.v1` Event on the Principal's consent Timeline, and its
//! sequence is the ADR-039 fence: the revocation is appended while the host
//! holds the authority commit fence exclusively, after every operation
//! admitted before it has released the fence, and the pinned consents are
//! recomposed before the fence is released, so no decision after it uses the
//! revoked consent. Revocation is monotonic: revoking a revoked consent
//! returns its original revocation (`200`).
//!
//! A consent the acting entity is not a party to (as its subject or its
//! grantee) is `404 not-found-or-unavailable`. The revocation Event carries
//! the request's revocation key, a digest of the Principal, the acting entity
//! and its `Idempotency-Key`, as its correlation identity, so the binding of
//! a key to the consent it revoked survives a restart: reusing the key for
//! another consent is `409 idempotency-conflict`. A revocation needs no
//! consent of its own, so it stays available whatever consent is revoked.
//!
//! The answer is a function of the recorded revocation alone: `generation`
//! is its fence and `mode_profile` the binding its commit was produced
//! under, so the original answer is the same after any later authority,
//! consent or mode change.

use pos_core::{CorrelationId, EntityId, EventId, TimelineId};
use serde_json::{json, Value};
use ulid::Ulid;

use super::{GatewayAuthorization, GatewayConsentV1, GatewayConsentsV1};
use crate::{
    mode_profile::GatewayProducedUnderV1, Gateway, GatewayError, GatewayOperationPermitV1,
};

/// The `$id` of the served `ConsentRevocation` schema.
const CONSENT_REVOCATION_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:consent-revocation";
/// The domain of the provenance digest: BLAKE3 of this prefix, the 16
/// Principal ID bytes, `generation` as a big-endian u64, the ASCII
/// `mode_profile_digest` and `binding_epoch` as a big-endian u64.
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewayConsentRevocation.v1\0";
/// The derivation context of a revocation key.
const REVOCATION_KEY_CONTEXT: &str = "pigloros gateway consent revocation key v1";

/// The outcome of one revocation request.
pub(crate) enum ConsentRevocationOutcomeV1 {
    /// The revocation this request recorded (`201`).
    Recorded(Value),
    /// The consent's original revocation (`200`).
    Original(Value),
}

impl GatewayAuthorization {
    /// The pinned consents and the ID of the Principal whose leaf grant
    /// holds them.
    fn principal_consents(&self) -> Option<(GatewayConsentsV1, [u8; 16])> {
        let pinned = self.pinned();
        let principal = pinned
            .view
            .authority()
            .chain()
            .grants()
            .last()
            .map(|leaf| *leaf.grantee().principal().principal_id());
        pinned
            .consented
            .as_ref()
            .and_then(|consented| consented.consents().cloned())
            .zip(principal)
    }
}

/// The revocation key of `idempotency_key` sent by `actor` of `principal`.
fn revocation_key(principal: [u8; 16], actor: EntityId, idempotency_key: &str) -> CorrelationId {
    let mut hasher = blake3::Hasher::new_derive_key(REVOCATION_KEY_CONTEXT);
    hasher.update(&principal);
    hasher.update(&actor.inner().to_bytes());
    hasher.update(idempotency_key.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    CorrelationId::from_ulid(Ulid::from_bytes(bytes))
}

/// One recorded consent revocation as `ConsentRevocation` discloses it.
struct ConsentRevocationV1 {
    /// The revoking Principal's ID.
    principal: [u8; 16],
    /// The revoked consent.
    consent_ref: EventId,
    /// The `consent.revoked.v1` Event.
    revocation: EventId,
    /// Its fence on the consent Timeline.
    generation: u64,
}

impl ConsentRevocationV1 {
    /// The `ConsentRevocation` resource, produced under `mode`.
    fn to_json(&self, mode: &GatewayProducedUnderV1) -> Value {
        let (mode_profile_digest, binding_epoch) = mode.provenance_fields();
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVENANCE_DOMAIN);
        hasher.update(&self.principal);
        hasher.update(&self.generation.to_be_bytes());
        hasher.update(mode_profile_digest.as_bytes());
        hasher.update(&binding_epoch.to_be_bytes());
        json!({
            "schema_id": CONSENT_REVOCATION_SCHEMA_ID,
            "id": self.revocation.to_string(),
            "generation": self.generation,
            "provenance": {
                "digest": hasher.finalize().to_hex().to_string(),
                "origin": "host-derived",
            },
            "mode_profile": mode.disclosure(),
            "execution_profile": {
                "profile_kind": "epf1",
                "state": "unavailable",
                "reason": "not-installed",
            },
            "availability": {"state": "available", "withheld": []},
            "consent_ref": self.consent_ref.to_string(),
            "state": "revoked",
            "future_protected_work": "denied",
        })
    }
}

impl Gateway {
    /// The consent `consent_ref` of the acting Principal as its consent
    /// Timeline holds it now, when `actor` is its subject or grantee (#309;
    /// the consent lookup #303 checks a room's consent reference with).
    ///
    /// The host first brings its pinned authority current with the store,
    /// so a revocation recorded by any writer is seen. Do not call it while
    /// holding an operation permit: bringing the authority current may take
    /// the commit fence exclusively.
    ///
    /// # Errors
    /// Returns [`GatewayError::AuthorizationUnavailable`] (`401`) on a
    /// composition without an authorizer, and
    /// [`GatewayError::AuthorizationEvidenceUnavailable`] (`503`) when the
    /// host cannot read its authority or consent Timeline.
    pub(crate) async fn consent_current(
        &self,
        actor: EntityId,
        consent_ref: EventId,
    ) -> Result<Option<GatewayConsentV1>, GatewayError> {
        let Some(authorization) = self.authorization.clone() else {
            return Err(GatewayError::AuthorizationUnavailable);
        };
        self.bring_current(&authorization)
            .await
            .map_err(|_| GatewayError::AuthorizationEvidenceUnavailable)
            .map(|()| {
                authorization
                    .principal_consents()
                    .and_then(|(consents, _)| consents.named_for(actor, consent_ref))
            })
    }

    /// Revoke the acting Principal's consent `consent_ref` under the permit
    /// of its `consent.revoke` decision, for the idempotency key `key`.
    ///
    /// # Errors
    /// Returns [`GatewayError::AuthorizationUnavailable`] (`401`) on a
    /// composition without an authorizer, [`GatewayError::ResourceUnavailable`]
    /// (`404`) for a consent the acting entity is not a party to,
    /// [`GatewayError::IngressConflict`] (`409`) for a key that revoked
    /// another consent, and the append and authority failures of the
    /// revocation.
    pub(crate) async fn revoke_consent_v1(
        &self,
        permit: GatewayOperationPermitV1,
        consent_ref: EventId,
        key: &str,
    ) -> Result<ConsentRevocationOutcomeV1, GatewayError> {
        let actor = permit
            .decision()
            .map(super::GatewayAuthorizationDecision::actor_entity_id);
        // The revocation waits for every operation admitted before it,
        // including its own admission.
        drop(permit);
        let Some((authorization, actor)) = self.authorization.clone().zip(actor) else {
            return Err(GatewayError::AuthorizationUnavailable);
        };
        if self.consent_current(actor, consent_ref).await?.is_none() {
            return Err(GatewayError::ResourceUnavailable);
        }
        let _fence = authorization.exclusive_fence().await;
        let (consents, principal) = self.current_consents(&authorization).await?;
        let revocation_key = revocation_key(principal, actor, key);
        let keyed = consents.disclosed().iter().find(|consent| {
            consent
                .revocation()
                .is_some_and(|revocation| revocation.key() == Some(revocation_key))
        });
        if keyed.is_some_and(|keyed| keyed.consent_ref() != consent_ref) {
            return Err(GatewayError::IngressConflict);
        }
        let Some(consent) = consents.named_for(actor, consent_ref) else {
            return Err(GatewayError::ResourceUnavailable);
        };
        if consent.revocation().is_some() {
            return self
                .revocation_json(consents.timeline(), principal, &consent)
                .await
                .map(ConsentRevocationOutcomeV1::Original);
        }
        self.issue_keyed_consent_revocation(
            &consents.timeline().to_string(),
            pos_core::ConsentRevokedV1 {
                subject_id: consents.subject(),
                grantee_id: consent.grantee(),
                grant_seq: consent.grant_seq().as_u64(),
                fence_seq: consents.head().as_u64().saturating_add(1),
            },
            Some(revocation_key),
        )
        .await?;
        let (revoked, _) = self.current_consents(&authorization).await?;
        match revoked.named_for(actor, consent_ref) {
            Some(consent) => self
                .revocation_json(revoked.timeline(), principal, &consent)
                .await
                .map(ConsentRevocationOutcomeV1::Recorded),
            None => Err(GatewayError::AuthorizationEvidenceUnavailable),
        }
    }

    /// The `ConsentRevocation` of the revoked `consent` of `principal`,
    /// produced under the binding its revocation's commit records.
    async fn revocation_json(
        &self,
        timeline: TimelineId,
        principal: [u8; 16],
        consent: &GatewayConsentV1,
    ) -> Result<Value, GatewayError> {
        let Some(revocation) = consent.revocation() else {
            return Err(GatewayError::AuthorizationEvidenceUnavailable);
        };
        self.store
            .produced_under(timeline, revocation.fence())
            .await
            .ok()
            .flatten()
            .map(|mode| {
                ConsentRevocationV1 {
                    principal,
                    consent_ref: consent.consent_ref(),
                    revocation: revocation.event(),
                    generation: revocation.fence().as_u64(),
                }
                .to_json(&mode)
            })
            .ok_or(GatewayError::AuthorizationEvidenceUnavailable)
    }

    /// Bring the pinned consents current with the store while the caller
    /// holds the authority commit fence exclusively, and return them with
    /// the Principal's ID.
    async fn current_consents(
        &self,
        authorization: &GatewayAuthorization,
    ) -> Result<(GatewayConsentsV1, [u8; 16]), GatewayError> {
        let record = match authorization.source_leaf() {
            Some(leaf) => self.authority_record(authorization, leaf).await,
            None => Err(super::GatewayAuthorizationError::AuthorityUnavailable),
        };
        let refreshed = match record {
            Ok(record) => match self.with_consent_events(authorization, record).await {
                Ok(record) => authorization.refresh_held(record),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        refreshed
            .ok()
            .and_then(|()| authorization.principal_consents())
            .ok_or(GatewayError::AuthorizationEvidenceUnavailable)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::mode_profile::{test_binding, GatewayModeProfileIdV1};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// A recorded revocation serializes exactly as the frozen
    /// `consent-revocation-recorded` golden example, which the contract
    /// checker validates against the frozen `ConsentRevocation` schema.
    #[test]
    fn a_revocation_serializes_as_its_frozen_golden_example() -> TestResult {
        let example: Value = serde_json::from_str(include_str!(
            "../../../../contracts/gateway/v1/compatibility/examples/consent-revocation-recorded.json"
        ))?;
        let event = |text: &str| -> TestResult<EventId> {
            Ok(EventId::from_ulid(Ulid::from_string(text)?))
        };
        let revocation = ConsentRevocationV1 {
            principal: Ulid::from_string("01JC0GATEWAYW90PR1NC1PA1A1")?.to_bytes(),
            consent_ref: event("01JC0GATEWAYW90C0NSENT0001")?,
            revocation: event("01JC0GATEWAYW90REV0KE00001")?,
            generation: 2,
        };
        let mode = test_binding(GatewayModeProfileIdV1::Local, []).produced_under();
        assert_eq!(revocation.to_json(&mode), example["response"]["body"]);
        Ok(())
    }

    /// A revocation key binds the Principal, the actor and the key.
    #[test]
    fn a_revocation_key_binds_principal_actor_and_key() {
        let actor = EntityId::new();
        let key = revocation_key([1; 16], actor, "key");
        assert_eq!(key, revocation_key([1; 16], actor, "key"));
        assert_ne!(key, revocation_key([2; 16], actor, "key"));
        assert_ne!(key, revocation_key([1; 16], EntityId::new(), "key"));
        assert_ne!(key, revocation_key([1; 16], actor, "other"));
    }
}
