//! Fixture-only Local admission for provider tests in other crates.
//!
//! The authenticated selector chain that normally yields a
//! [`LocalNetworkAdmission`] cannot be assembled outside this crate's own
//! tests, yet provider composition tests need one to bind to an attempt. This
//! module builds it directly from the fields a provider binds against. The
//! fixture signs and authenticates nothing, so it is compiled only for tests
//! and the `test-support` feature, which never reaches a deployable graph.

use ciborium::value::Value;

use super::{AuthenticatedAdmissionGrant, LocalNetworkAdmission, NetworkProxyLimits};
use crate::sandbox_provider_protocol::codec::{
    bytes_value, digest_with_domain, text_value, uint_value,
};
use crate::sandbox_provider_protocol::{
    AdmissionAuthority, AdmissionGrant, NetworkCapability, NetworkExchangePlan,
    NetworkRetentionPolicy, SandboxProviderProtocolError,
};

const REQUEST_DOMAIN: &[u8] = b"PiglorOS.NetworkRequestBytes.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"PiglorOS.NetworkResponseBytes.v1\0";
const PLAN_DOMAIN: &[u8] = b"PiglorOS.NetworkExchangePlan.v1\0";

fn content_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

impl NetworkExchangePlan {
    /// A sealed NXP1 plan for one exact request and response, for tests only.
    ///
    /// # Errors
    /// Returns a protocol error if the plan digest cannot be encoded.
    pub fn fixture(
        exchange_id: [u8; 16],
        occurrence: u64,
        capability_id: &str,
        request: &[u8],
        response: &[u8],
    ) -> Result<Self, SandboxProviderProtocolError> {
        let mut plan = Self {
            exchange_id,
            occurrence,
            capability_id: capability_id.to_owned(),
            request_length: request.len() as u64,
            request_digest: content_digest(REQUEST_DOMAIN, request),
            response_maximum: response.len() as u64,
            expected_response_digest: content_digest(RESPONSE_DOMAIN, response),
            retention_policy_digest: NetworkRetentionPolicy::RetainIndefinitely.digest()?,
            plan_digest: [0; 32],
        };
        plan.plan_digest = digest_with_domain(
            PLAN_DOMAIN,
            &Value::Array(vec![
                text_value("NXP1"),
                uint_value(1),
                bytes_value(&plan.exchange_id),
                uint_value(plan.occurrence),
                text_value(&plan.capability_id),
                uint_value(plan.request_length),
                bytes_value(&plan.request_digest),
                uint_value(plan.response_maximum),
                bytes_value(&plan.expected_response_digest),
                bytes_value(&plan.retention_policy_digest),
            ]),
        )?;
        Ok(plan)
    }
}

impl LocalNetworkAdmission {
    /// A Local admission over `exchanges` and `limits` bound to a grant that
    /// names `attempt_id`, `authority` and the three epochs (trust,
    /// revocation, policy), for tests only.
    ///
    /// Nothing is authenticated: the grant carries filler digests and a zero
    /// signature, and no plan is checked against an endpoint.
    #[must_use]
    pub fn fixture(
        attempt_id: [u8; 16],
        authority: AdmissionAuthority,
        epochs: [u64; 3],
        exchanges: Vec<(NetworkExchangePlan, NetworkCapability)>,
        limits: NetworkProxyLimits,
    ) -> Self {
        Self {
            grant: AuthenticatedAdmissionGrant(AdmissionGrant {
                request_id: [1; 16],
                attempt_id,
                expected_launch_policy_digest: authority.lps1_digest,
                authority,
                trust_epoch: epochs[0],
                revocation_epoch: epochs[1],
                policy_epoch: epochs[2],
                elm1_digest: [2; 32],
                input_digest: [3; 32],
                exchange_plan_digests: exchanges.iter().map(|(plan, _)| plan.plan_digest).collect(),
                expected_readback_set_digest: [4; 32],
                runtime_attestation_key_id: "fixture-runtime-key".to_owned(),
                grant_digest: [5; 32],
                signature: [0; 64],
            }),
            exchanges,
            limits,
        }
    }
}
