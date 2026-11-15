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
//! A consent the Principal does not hold, or whose subject or grantee is not
//! the acting entity, is `404 not-found-or-unavailable`. The idempotency key
//! of each recent revocation stays bound to the consent it named for the life
//! of the serving process: reusing it for another consent is
//! `409 idempotency-conflict`. A revocation needs no consent of its own, so it
//! stays available whatever consent is revoked.

use pos_core::{EventId, Hash, Seq};
use serde_json::{json, Value};

use super::{GatewayAuthorization, GatewayConsentV1, GatewayConsentsV1};
use crate::{mode_profile::GatewaySessionModeV1, Gateway, GatewayError, GatewayOperationPermitV1};

/// The `$id` of the served `ConsentRevocation` schema.
const CONSENT_REVOCATION_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:consent-revocation";
/// The domain of the provenance digest: BLAKE3 of this prefix, the 16
/// Principal ID bytes, `generation` as a big-endian u64, the ASCII
/// `mode_profile_digest` and `binding_epoch` as a big-endian u64.
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewayConsentRevocation.v1\0";
/// The revocation idempotency keys one serving process retains.
const MAX_REVOCATION_KEYS: usize = 1_024;

/// The outcome of one revocation request.
pub(crate) enum ConsentRevocationOutcomeV1 {
    /// The revocation this request recorded (`201`).
    Recorded(Value),
    /// The consent's original revocation (`200`).
    Original(Value),
}

impl GatewayAuthorization {
    /// The consent `consent_ref` of the pinned consents, when the actor of
    /// `permit` is its subject or grantee.
    fn revocable(
        &self,
        permit: &GatewayOperationPermitV1,
        consent_ref: EventId,
    ) -> Option<GatewayConsentV1> {
        let actor = permit
            .decision()
            .map(super::GatewayAuthorizationDecision::actor_entity_id);
        let pinned = self.pinned();
        pinned
            .consented
            .as_ref()
            .and_then(|consented| consented.consents())
            .and_then(|consents| {
                consents.named(consent_ref).copied().filter(|consent| {
                    actor == Some(consent.grantee()) || actor == Some(consents.subject())
                })
            })
    }

    /// Bind `key` to `consent_ref`: `false` when it already names another
    /// consent.
    fn bind_revocation_key(&self, key: Hash, consent_ref: EventId) -> bool {
        let mut keys = self
            .revocation_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bound = keys
            .iter()
            .find(|(bound, _)| *bound == key)
            .map(|(_, consent)| *consent);
        if bound.is_none() {
            if keys.len() >= MAX_REVOCATION_KEYS {
                keys.pop_front();
            }
            keys.push_back((key, consent_ref));
        }
        drop(keys);
        bound.is_none_or(|bound| bound == consent_ref)
    }

    /// The `ConsentRevocation` of the revoked `consent`, or `None` for an
    /// authorizer bound to no execution mode.
    ///
    /// `generation` is the authority generation (D8) from which the
    /// revocation is effective: the pinned authority head plus the
    /// revocation's fence on the consent Timeline.
    fn revocation_json(&self, consent: &GatewayConsentV1) -> Option<Value> {
        let pinned = self.pinned();
        let authority = pinned.view.authority();
        let consent_chain_head = pinned.consented.as_ref().map_or(Seq::ZERO, |consented| {
            consented.view().authority().head_position()
        });
        let authority_head = authority
            .head_position()
            .as_u64()
            .saturating_add(consent_chain_head.as_u64());
        let principal = authority
            .chain()
            .grants()
            .last()
            .map(|leaf| *leaf.grantee().principal().principal_id());
        self.session_mode
            .as_ref()
            .zip(consent.revocation())
            .zip(principal)
            .map(|((mode, (revocation, fence)), principal)| {
                ConsentRevocationV1 {
                    principal,
                    consent_ref: consent.consent_ref(),
                    revocation,
                    generation: authority_head.saturating_add(fence.as_u64()),
                }
                .to_json(mode)
            })
    }
}

/// One recorded consent revocation as `ConsentRevocation` discloses it.
struct ConsentRevocationV1 {
    /// The revoking Principal's ID.
    principal: [u8; 16],
    /// The revoked consent.
    consent_ref: EventId,
    /// The `consent.revoked.v1` Event.
    revocation: EventId,
    /// The authority generation from which the revocation is effective.
    generation: u64,
}

impl ConsentRevocationV1 {
    /// The `ConsentRevocation` resource, under the binding `mode`.
    fn to_json(&self, mode: &GatewaySessionModeV1) -> Value {
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
            "mode_profile": mode.produced_under(),
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
    /// Revoke the acting Principal's consent `consent_ref` under the permit
    /// of its `consent.revoke` decision, for the idempotency key `key`.
    ///
    /// # Errors
    /// Returns [`GatewayError::AuthorizationUnavailable`] (`401`) on a
    /// composition without an authorizer bound to an execution mode,
    /// [`GatewayError::ResourceUnavailable`] (`404`) for a consent the
    /// acting entity may not revoke, [`GatewayError::IngressConflict`]
    /// (`409`) for a key bound to another consent, and the append and
    /// authority failures of the revocation.
    pub(crate) async fn revoke_consent_v1(
        &self,
        permit: GatewayOperationPermitV1,
        consent_ref: EventId,
        key: &str,
    ) -> Result<ConsentRevocationOutcomeV1, GatewayError> {
        let Some(authorization) = self.authorization.clone() else {
            return Err(GatewayError::AuthorizationUnavailable);
        };
        let Some(consent) = authorization.revocable(&permit, consent_ref) else {
            return Err(GatewayError::ResourceUnavailable);
        };
        let key = Hash::from_bytes(*blake3::hash(key.as_bytes()).as_bytes());
        if !authorization.bind_revocation_key(key, consent_ref) {
            return Err(GatewayError::IngressConflict);
        }
        // The revocation waits for every operation admitted before it,
        // including its own admission.
        drop(permit);
        let _fence = authorization.exclusive_fence().await;
        let current = self.current_consents(&authorization).await?;
        // A recorded consent never disappears; it may have been revoked.
        let consent = current.named(consent_ref).copied().unwrap_or(consent);
        if consent.revocation().is_some() {
            return authorization
                .revocation_json(&consent)
                .map(ConsentRevocationOutcomeV1::Original)
                .ok_or(GatewayError::AuthorizationUnavailable);
        }
        self.issue_consent_revocation(
            &current.timeline().to_string(),
            pos_core::ConsentRevokedV1 {
                subject_id: current.subject(),
                grantee_id: consent.grantee(),
                grant_seq: consent.grant_seq().as_u64(),
                fence_seq: current.head().as_u64().saturating_add(1),
            },
        )
        .await?;
        let revoked = self.current_consents(&authorization).await?;
        revoked
            .named(consent.consent_ref())
            .and_then(|consent| authorization.revocation_json(consent))
            .map(ConsentRevocationOutcomeV1::Recorded)
            .ok_or(GatewayError::AuthorizationEvidenceUnavailable)
    }

    /// Bring the pinned consents current with the store while the caller
    /// holds the authority commit fence exclusively, and return them.
    async fn current_consents(
        &self,
        authorization: &GatewayAuthorization,
    ) -> Result<GatewayConsentsV1, GatewayError> {
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
            .and_then(|()| {
                let pinned = authorization.pinned();
                pinned
                    .consented
                    .as_ref()
                    .and_then(|consented| consented.consents().cloned())
            })
            .ok_or(GatewayError::AuthorizationEvidenceUnavailable)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::mode_profile::{test_binding, GatewayModeProfileIdV1};
    use ulid::Ulid;

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
            generation: 4,
        };
        let mode = test_binding(GatewayModeProfileIdV1::Local, []).session_mode();
        assert_eq!(revocation.to_json(&mode), example["response"]["body"]);
        Ok(())
    }
}
