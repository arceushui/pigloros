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
//! - `generation` is the head position of the pinned authority chain plus
//!   the head of the Principal's consent Timeline (D8). A Local Principal
//!   grant binds no consent (D4 provisions explicit operation grants only),
//!   so that head is 0 and `consents` is empty; a consent, when a grant binds
//!   one, is named by the `EventId` of its `consent.granted.v1` Event (D7).
//! - `provenance.digest` is the BLAKE3 of the disclosed facts the Session is
//!   derived from (see `PROVENANCE_DOMAIN`), so a client recomputes it.
//! - `execution_profile` is the EPF1 profile, `unavailable` until #461.

use pos_core::{EntityId, PrincipalRefV1, Seq};
use serde_json::{json, Value};

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

/// One Principal's Session, derived by the host under the read's permit.
pub(crate) struct GatewaySessionV1 {
    /// The Principal the decision authenticated.
    pub(crate) principal: PrincipalRefV1,
    /// The actors of the Principal's leaf grant.
    pub(crate) entity_ids: Vec<EntityId>,
    /// The served operations and capabilities the grant covers, sorted.
    pub(crate) grants: Vec<&'static str>,
    /// The head position of the pinned authority chain.
    pub(crate) authority_head: Seq,
    /// The current execution mode of the serving store.
    pub(crate) mode: GatewaySessionModeV1,
}

impl GatewaySessionV1 {
    /// The `Session` resource of the Gateway v1 contract.
    pub(crate) fn to_json(&self) -> Value {
        let id = ulid::Ulid::from_bytes(*self.principal.principal_id()).to_string();
        // The consent Timeline head term of D8 is 0: no Local Principal grant
        // binds a consent Timeline.
        let generation = self.authority_head.as_u64();
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
            "consents": [],
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

impl Gateway {
    /// The `Session` of the Principal whose `permit` admitted
    /// [`crate::GatewayOperationV1::READ_SESSION`]; the permit keeps the commit
    /// fence while the Session is derived.
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
            .and_then(|(decision, authorization)| authorization.session(decision))
            .map(|session| session.to_json())
            .ok_or(GatewayError::AuthorizationUnavailable)
    }
}
