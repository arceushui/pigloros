//! Binding of Local network inputs to authenticated admission evidence.

use std::collections::BTreeMap;

use super::{AuthenticatedAdmissionGrant, SelectorGrantCommitment, MAX_NETWORK_PLANS};
use crate::sandbox_provider_protocol::{
    execution::validate_network_plans, LaunchPolicy, NetworkCapability, NetworkExchangePlan,
    NetworkExchangeRequest, SandboxExecutionMode, SandboxProviderProtocolError,
};

/// Exact selector-derived ELM1 ceilings owned by the Local proxy.
///
/// Byte ceilings are cumulative for the attempt, not renewed per exchange.
/// Zero remains zero capacity. The active runtime owns counters and the
/// monotonic deadline; broker admission controls 13–15 are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkProxyLimits {
    /// ELM1 limit 10, total NXQ1 request payload bytes.
    pub request_bytes: u64,
    /// ELM1 limit 11, total NXY1 response payload bytes.
    pub response_bytes: u64,
    /// ELM1 limit 12, monotonic proxy deadline in milliseconds.
    pub milliseconds: u64,
}

/// Immutable Local plans, exact endpoints and limits bound to one signed AGR1.
///
/// This retains admission evidence, not live connection authority. The provider
/// must separately bind it to its active attempt, current authority heads,
/// namespace/firewall and FD3 ownership before any connection can open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNetworkAdmission {
    grant: AuthenticatedAdmissionGrant,
    exchanges: Vec<(NetworkExchangePlan, NetworkCapability)>,
    limits: NetworkProxyLimits,
}

impl AuthenticatedAdmissionGrant {
    /// Bind exact Local policy and ordered plans to this grant and its ELM1.
    ///
    /// Canonical LPS1 is decoded again so mutable public policy fields cannot
    /// substitute an endpoint behind an unchanged digest. Neither provider
    /// input nor the caller supplies an independent numeric limit override.
    ///
    /// # Errors
    /// Rejects non-Local or foreign policy, mismatched selector commitments,
    /// reordered/missing/substituted plans, ambiguous capability IDs, unsupported
    /// retention, oversized requests, and plans exceeding endpoint byte bounds.
    pub fn bind_local_network(
        &self,
        commitment: &SelectorGrantCommitment,
        canonical_policy: &[u8],
        plans: &[NetworkExchangePlan],
    ) -> Result<LocalNetworkAdmission, SandboxProviderProtocolError> {
        LaunchPolicy::from_canonical_cbor(canonical_policy).and_then(|policy| {
            validate_binding(self, commitment, &policy, plans).and_then(|()| {
                endpoints(&policy).and_then(|endpoints| {
                    plans
                        .iter()
                        .map(|plan| bind_exchange(plan, &endpoints))
                        .collect::<Result<Vec<_>, _>>()
                        .map(|exchanges| LocalNetworkAdmission {
                            grant: self.clone(),
                            exchanges,
                            // The opaque commitment derives exactly all 17 ordered limits.
                            limits: NetworkProxyLimits {
                                request_bytes: commitment.effective_limits[10].value,
                                response_bytes: commitment.effective_limits[11].value,
                                milliseconds: commitment.effective_limits[12].value,
                            },
                        })
                })
            })
        })
    }
}

impl LocalNetworkAdmission {
    /// Original authenticated grant retained for the active-attempt binding.
    #[must_use]
    pub const fn grant(&self) -> &AuthenticatedAdmissionGrant {
        &self.grant
    }

    /// Plans and their unique exact endpoints, in the authenticated caller order.
    #[must_use]
    pub fn exchanges(
        &self,
    ) -> impl ExactSizeIterator<Item = (&NetworkExchangePlan, &NetworkCapability)> {
        self.exchanges
            .iter()
            .map(|(plan, endpoint)| (plan, endpoint))
    }

    /// Immutable snapshot of the selector-derived cumulative proxy ceilings.
    #[must_use]
    pub const fn limits(&self) -> NetworkProxyLimits {
        self.limits
    }
}

fn validate_binding(
    grant: &AuthenticatedAdmissionGrant,
    commitment: &SelectorGrantCommitment,
    policy: &LaunchPolicy,
    plans: &[NetworkExchangePlan],
) -> Result<(), SandboxProviderProtocolError> {
    if policy.execution_mode != SandboxExecutionMode::Local {
        return Err(SandboxProviderProtocolError::InconsistentFields);
    }
    let actual = (
        [
            grant.authority.lps1_digest,
            grant.expected_launch_policy_digest,
            commitment.authority.launch_policy,
        ],
        grant.elm1_digest,
        grant.expected_readback_set_digest,
    );
    let expected = (
        [policy.policy_digest; 3],
        commitment.effective_limits_digest,
        commitment.expected_readback_set_digest,
    );
    if actual != expected {
        return Err(SandboxProviderProtocolError::InconsistentFields);
    }
    if plans.len() > MAX_NETWORK_PLANS {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    validate_network_plans(plans).and_then(|()| {
        let digests = plans
            .iter()
            .map(|plan| plan.plan_digest)
            .collect::<Vec<_>>();
        if [digests.as_slice(); 2]
            == [
                grant.exchange_plan_digests.as_slice(),
                commitment.network_plan_digests.as_slice(),
            ]
        {
            Ok(())
        } else {
            Err(SandboxProviderProtocolError::InconsistentFields)
        }
    })
}

fn endpoints(
    policy: &LaunchPolicy,
) -> Result<BTreeMap<&str, &NetworkCapability>, SandboxProviderProtocolError> {
    let mut endpoints = BTreeMap::new();
    for capability in &policy.network_capabilities {
        if endpoints
            .insert(capability.capability_id.as_str(), capability)
            .is_some()
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
    }
    Ok(endpoints)
}

fn bind_exchange(
    plan: &NetworkExchangePlan,
    endpoints: &BTreeMap<&str, &NetworkCapability>,
) -> Result<(NetworkExchangePlan, NetworkCapability), SandboxProviderProtocolError> {
    NetworkExchangeRequest::validate_plan(plan).and_then(|()| {
        endpoints
            .get(plan.capability_id.as_str())
            .ok_or(SandboxProviderProtocolError::InconsistentFields)
            .and_then(|endpoint| {
                let request_exceeds_bound = plan.request_length > endpoint.request_maximum;
                let response_exceeds_bound = plan.response_maximum > endpoint.response_maximum;
                if request_exceeds_bound || response_exceeds_bound {
                    Err(SandboxProviderProtocolError::FieldOutOfBounds)
                } else {
                    Ok((plan.clone(), (*endpoint).clone()))
                }
            })
    })
}
