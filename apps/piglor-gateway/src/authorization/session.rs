//! The served `GET /v1/session` resource (#1362, owner decisions on #302,
//! ADR-134 §5).
//!
//! A `Session` is a pure projection of the host's own authority: the pinned
//! Local Principal chain the read's decision used, the evaluator's answer for
//! every served operation and capability, and the bound execution mode.
//! Nothing is taken from the request but the acting entity, which only
//! selects the decision; a client can never supply a grant, a consent or a
//! mode. The read itself is a protected operation
//! ([`crate::GatewayOperationV1::READ_SESSION`]) of the reusable
//! authorization seam, so an unprovisioned host answers it `401` before any
//! lookup and a denial is answered only once its evidence is recorded.
//!
//! - `generation` is the head position of the pinned authority (its chain,
//!   plus its consent-bound chain when its provisioning binds consents) plus
//!   the head of the Principal's consent Timeline (D8). Each consent is named
//!   by the `EventId` of its `consent.granted.v1` Event (D7) and is `revoked`
//!   from its ADR-039 fence on (#309). A Principal whose provisioning binds no
//!   consent has a consent head of 0 and no consents.
//! - `provenance.digest` is the BLAKE3 of the disclosed facts the Session is
//!   derived from (see `PROVENANCE_DOMAIN`), so a client recomputes it.
//! - `execution_profile` is the EPF1 profile, `unavailable` until #461.
//! - In a mode without network the Principal network capability is never
//!   listed: binding refuses an authority that names it, and the projection
//!   drops it as well.

use pos_core::{EntityId, EventId, PrincipalRefV1, Seq};
use serde_json::{json, Value};

use super::{
    GatewayAuthorization, GatewayAuthorizationDecision, GatewayAuthorizationRequest,
    GatewayConsentedAuthorityV1, GatewayConsentsV1, GatewayOperationV1,
};
use crate::{
    mode_profile::{GatewaySessionModeV1, GATEWAY_NETWORK_CAPABILITY_V1},
    Gateway, GatewayError, GatewayOperationPermitV1,
};

/// The `$id` of the served `Session` schema.
const SESSION_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:session";
/// The served contract version; `-draft` drops only at Wave 9 acceptance.
const CONTRACT_VERSION: &str = "1.0.0-draft";
/// The domain of the provenance digest: BLAKE3 of this prefix, the 16
/// Principal ID bytes, `generation` as a big-endian u64, the ASCII
/// `mode_profile_digest` and `binding_epoch` as a big-endian u64.
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewaySession.v1\0";

/// One disclosed consent: the `EventId` of its `consent.granted.v1` Event
/// (D7), whether it is revoked, and whether it permits export.
type SessionConsentV1 = (EventId, bool, bool);

/// One Principal's Session, derived by the host under the read's permit.
struct GatewaySessionV1 {
    /// The Principal the decision authenticated.
    principal: PrincipalRefV1,
    /// The actors of the Principal's leaf grant, never empty.
    entity_ids: Vec<EntityId>,
    /// The served operations and capabilities the grant covers, sorted.
    grants: Vec<&'static str>,
    /// The head position of the pinned authority: its chain plus its
    /// consent-bound chain.
    authority_head: Seq,
    /// The head of the Principal's consent Timeline; 0 when it has none.
    consent_head: Seq,
    /// The Principal's consents, in consent Timeline order.
    consents: Vec<SessionConsentV1>,
    /// The current execution mode of the serving store.
    mode: GatewaySessionModeV1,
}

impl GatewaySessionV1 {
    /// The authority generation (D8): authority head plus consent head.
    const fn generation(&self) -> u64 {
        self.authority_head
            .as_u64()
            .saturating_add(self.consent_head.as_u64())
    }

    /// The `Session` resource of the Gateway v1 contract.
    fn to_json(&self) -> Value {
        let id = ulid::Ulid::from_bytes(*self.principal.principal_id()).to_string();
        let generation = self.generation();
        let network_capability = self.grants.contains(&GATEWAY_NETWORK_CAPABILITY_V1);
        json!({
            "schema_id": SESSION_SCHEMA_ID,
            "id": id,
            "generation": generation,
            "provenance": {
                "digest": self.provenance_digest(generation),
                "origin": "host-derived",
            },
            "mode_profile": self.mode.disclosure(network_capability),
            "execution_profile": {
                "profile_kind": "epf1",
                "state": "unavailable",
                "reason": "not-installed",
            },
            "availability": {"state": "available", "withheld": []},
            "principal": {
                "principal_id": id,
                "entity_ids": self
                    .entity_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            },
            "grants": self.grants,
            "consents": self
                .consents
                .iter()
                .map(|(consent_ref, revoked, export_permitted)| {
                    let state = if *revoked { "revoked" } else { "granted" };
                    json!({
                        "consent_ref": consent_ref.to_string(),
                        "state": state,
                        "export_permitted": export_permitted,
                    })
                })
                .collect::<Vec<_>>(),
            "contract": {"api_major": "v1", "contract_version": CONTRACT_VERSION},
        })
    }

    /// The provenance digest of `PROVENANCE_DOMAIN` at `generation`.
    fn provenance_digest(&self, generation: u64) -> String {
        let (mode_profile_digest, binding_epoch) = self.mode.provenance_fields();
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVENANCE_DOMAIN);
        hasher.update(self.principal.principal_id());
        hasher.update(&generation.to_be_bytes());
        hasher.update(mode_profile_digest.as_bytes());
        hasher.update(&binding_epoch.to_be_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

impl GatewayAuthorization {
    /// The `Session` of the Principal `decision` admitted to read it, or
    /// `None` for an authorizer bound to no execution mode.
    ///
    /// Call it while the decision's permit holds the commit fence, so the
    /// pinned authority read here is the one the decision used. The grants
    /// are every [`GatewayOperationV1::ALL`] entry the pinned authority
    /// allows the decision's actor, decided by the same evaluator as
    /// [`Self::authorize`] and recording nothing; the network capability is
    /// dropped in a mode without network. The entities are the leaf grant's
    /// actors. A chain without a leaf grant or a leaf without an actor
    /// discloses nothing: neither is reachable, because a resolved chain
    /// holds at least one grant and a capability scope at least one actor,
    /// but the projection fails closed rather than emit an invalid Session.
    pub(crate) fn session_json(&self, decision: &GatewayAuthorizationDecision) -> Option<Value> {
        let pinned = self.pinned();
        let authority = pinned.view.authority();
        let consented = pinned.consented.as_ref();
        let consent_chain_head = consented.map_or(0, GatewayConsentedAuthorityV1::head_position);
        let consents = consented.and_then(GatewayConsentedAuthorityV1::consents);
        let entity_ids = authority
            .chain()
            .grants()
            .last()
            .map(|leaf| leaf.scope().actor_entity_ids().to_vec())
            .filter(|actors| !actors.is_empty());
        self.session_mode
            .clone()
            .zip(entity_ids)
            .map(|(mode, entity_ids)| {
                let actor = decision.actor_entity_id();
                let at_time = decision.request().at_time;
                GatewaySessionV1 {
                    principal: decision.principal().clone(),
                    entity_ids,
                    grants: GatewayOperationV1::ALL
                        .iter()
                        .copied()
                        .filter(|operation| {
                            mode.network_allowed() || *operation != GatewayOperationV1::NETWORK
                        })
                        .filter(|operation| {
                            self.evaluate(GatewayAuthorizationRequest::operation(
                                actor, *operation, None, at_time,
                            ))
                            .is_ok_and(|evaluated| evaluated.is_allowed())
                        })
                        .map(GatewayOperationV1::name)
                        .collect(),
                    authority_head: Seq::from_u64(
                        authority
                            .head_position()
                            .as_u64()
                            .saturating_add(consent_chain_head),
                    ),
                    consent_head: consents.map_or(Seq::ZERO, GatewayConsentsV1::head),
                    consents: consents.map_or_else(Vec::new, |consents| {
                        consents
                            .of_party(actor)
                            .map(|consent| {
                                (
                                    consent.consent_ref(),
                                    consent.revocation().is_some(),
                                    consent.export_permitted(),
                                )
                            })
                            .collect()
                    }),
                    mode,
                }
                .to_json()
            })
    }
}

impl Gateway {
    /// The `Session` of the Principal whose `permit` admitted
    /// [`crate::GatewayOperationV1::READ_SESSION`]; the permit keeps the
    /// commit fence while the Session is derived.
    ///
    /// # Errors
    /// Returns [`GatewayError::AuthorizationUnavailable`] (`401`) on a
    /// composition that protects nothing (it has no Principal to disclose)
    /// or whose authorizer is bound to no execution mode.
    pub(crate) fn session_v1(
        &self,
        permit: &GatewayOperationPermitV1,
    ) -> Result<Value, GatewayError> {
        permit
            .decision()
            .zip(self.authorization.as_deref())
            .and_then(|(decision, authorization)| authorization.session_json(decision))
            .ok_or(GatewayError::AuthorizationUnavailable)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        local_principal::{
            load_local_principal, provision_local_principal, LocalPrincipalProvisionV1,
        },
        mode_profile::{test_binding, GatewayModeProfileIdV1},
    };
    use pos_core::WallTime;
    use pos_store::memory::MemoryStore;
    use ulid::Ulid;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const ACTOR: &str = "01JC0GATEWAYF1XTVREACT0R00";

    /// D7 and D8: a Session with consents serializes exactly as the frozen
    /// `session-consent-disclosure` golden example, which the contract
    /// checker validates against the frozen `Session` schema.
    #[test]
    fn a_session_with_consents_serializes_as_its_frozen_golden_example() -> TestResult {
        let example: Value = serde_json::from_str(include_str!(
            "../../../../contracts/gateway/v1/compatibility/examples/session-consent-disclosure.json"
        ))?;
        let event = |text: &str| -> TestResult<EventId> {
            Ok(EventId::from_ulid(Ulid::from_string(text)?))
        };
        let session = GatewaySessionV1 {
            principal: PrincipalRefV1::try_new(
                Ulid::from_string("01JC0GATEWAYW90PR1NC1PA1A1")?.to_bytes(),
                "local",
            )?,
            entity_ids: vec![EntityId::from_ulid(Ulid::from_string(ACTOR)?)],
            grants: vec!["session.read", "timeline.create", "timeline.events.read"],
            authority_head: Seq::from_u64(1),
            consent_head: Seq::from_u64(2),
            consents: vec![
                (event("01JC0GATEWAYW90C0NSENT0001")?, false, true),
                (event("01JC0GATEWAYW90C0NSENT0002")?, true, false),
            ],
            mode: test_binding(GatewayModeProfileIdV1::Local, []).session_mode(),
        };
        assert_eq!(session.generation(), 3);
        assert_eq!(session.to_json(), example["response"]["body"]);
        Ok(())
    }

    /// The authorizer of a recorded Local Principal granted `operations`,
    /// disclosing the Session mode of `mode` without the binding check, as
    /// an authority replaced after binding would.
    fn authorizer(
        operations: &[GatewayOperationV1],
        mode: GatewayModeProfileIdV1,
    ) -> TestResult<(GatewayAuthorization, EntityId)> {
        let actor = EntityId::from_ulid(Ulid::from_string(ACTOR)?);
        let provision = LocalPrincipalProvisionV1::try_new(
            &PrincipalRefV1::try_new([1; 16], "local")?,
            [actor],
            operations.iter().copied(),
        )?;
        let mut store = MemoryStore::new();
        provision_local_principal(&mut store, &provision)?;
        let mut authorization =
            load_local_principal(&store)?.ok_or("a provisioned store recomposes")?;
        authorization.session_mode = Some(test_binding(mode, []).session_mode());
        Ok((authorization, actor))
    }

    /// Defence in depth for ADR-134 §4: even an authority that names the
    /// network capability never lists it in a mode without network.
    #[test]
    fn a_mode_without_network_never_lists_the_network_capability() -> TestResult {
        let operations = [
            GatewayOperationV1::NETWORK,
            GatewayOperationV1::READ_SESSION,
        ];
        for (mode, grants, network) in [
            (
                GatewayModeProfileIdV1::AirGapped,
                vec!["session.read"],
                "absent",
            ),
            (
                GatewayModeProfileIdV1::Local,
                vec!["gateway.network.v1", "session.read"],
                "capability-granted",
            ),
        ] {
            let (authorization, actor) = authorizer(&operations, mode)?;
            let decision = authorization.authorize(GatewayAuthorizationRequest::operation(
                actor,
                GatewayOperationV1::READ_SESSION,
                None,
                WallTime::now(),
            ))?;
            let session = authorization
                .session_json(&decision)
                .ok_or("a bound authorizer discloses its Session")?;
            assert_eq!(session["grants"], json!(grants));
            assert_eq!(session["mode_profile"]["network"], network);
        }
        Ok(())
    }
}
