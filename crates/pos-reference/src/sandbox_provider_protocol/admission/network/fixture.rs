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

impl LocalNetworkAdmission {
    /// The same fixture admission for another request, for tests only.
    #[must_use]
    pub const fn with_request_id(mut self, request_id: [u8; 16]) -> Self {
        self.grant.0.request_id = request_id;
        self
    }

    /// The same fixture admission expecting another launch policy digest, for
    /// tests only.
    #[must_use]
    pub const fn with_expected_launch_policy_digest(mut self, digest: [u8; 32]) -> Self {
        self.grant.0.expected_launch_policy_digest = digest;
        self
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::sandbox_provider_protocol::{
        NetworkExchangeRequest, NetworkExchangeTranscript, NetworkProxyLimits,
    };

    const REQUEST: &[u8] = b"fixture request";
    const RESPONSE: &[u8] = b"fixture response";

    fn plan() -> Result<NetworkExchangePlan, Box<dyn Error>> {
        Ok(NetworkExchangePlan::fixture(
            [9; 16], 0, "execute", REQUEST, RESPONSE,
        )?)
    }

    #[test]
    fn the_fixture_plan_binds_exactly_its_request_and_response() -> Result<(), Box<dyn Error>> {
        let plan = plan()?;
        assert!(NetworkExchangeRequest::new(&plan, REQUEST).is_ok());
        assert!(NetworkExchangeRequest::new(&plan, b"another request").is_err());
        assert!(NetworkExchangeTranscript::capture([1; 16], &plan, REQUEST, RESPONSE).is_ok());
        assert!(NetworkExchangeTranscript::capture([1; 16], &plan, REQUEST, b"other").is_err());
        assert_eq!(plan.request_length, REQUEST.len() as u64);
        assert_eq!(plan.response_maximum, RESPONSE.len() as u64);
        Ok(())
    }

    #[test]
    fn the_fixture_admission_carries_the_grant_it_was_given() -> Result<(), Box<dyn Error>> {
        let plan = plan()?;
        let capability = NetworkCapability {
            capability_id: "execute".to_owned(),
            address: vec![127, 0, 0, 1],
            destination_port: 9,
            request_maximum: 1_024,
            response_maximum: 1_024,
        };
        let limits = NetworkProxyLimits {
            request_bytes: 10,
            response_bytes: 20,
            milliseconds: 30,
        };
        let authority = AdmissionAuthority {
            evr1_digest: [1; 32],
            fixture_contract_digest: [2; 32],
            fixture_digest: [3; 32],
            execution_profile_digest: [4; 32],
            lps1_digest: [5; 32],
            sim1_digest: [6; 32],
            apt1_digest: [7; 32],
            trs1_digest: [8; 32],
            rvs1_digest: [9; 32],
            spm1_digest: [10; 32],
            pcf1_digest: [11; 32],
            pcr1_digest: [12; 32],
            hcp1_digest: [13; 32],
        };
        let admission = LocalNetworkAdmission::fixture(
            [4; 16],
            authority.clone(),
            [1, 2, 3],
            vec![(plan.clone(), capability)],
            limits,
        );
        let grant = admission.grant();
        assert_eq!(grant.attempt_id, [4; 16]);
        assert_eq!(grant.authority, authority);
        assert_eq!(grant.expected_launch_policy_digest, [5; 32]);
        assert_eq!(
            [
                grant.trust_epoch,
                grant.revocation_epoch,
                grant.policy_epoch
            ],
            [1, 2, 3]
        );
        assert_eq!(grant.exchange_plan_digests, [plan.plan_digest]);
        assert_eq!(admission.limits(), limits);
        assert_eq!(admission.exchanges().len(), 1);
        Ok(())
    }
}
