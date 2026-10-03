//! `MemoryStore` adapter for the ADR-105 `FIP1` issuer-policy port.
//!
//! The retained history is one vector whose last entry is the floor, so a
//! single push installs the policy and advances the floor together.

use super::MemoryStore;
use crate::fork_attribution_issuer_policy::{
    admit_fork_attribution_issuer, pinned_issuer_policy, plan_issuer_policy_install,
    AuthenticatedOperatorPolicyPinV1, ForkAttributionIssuerAdmissionBasisV1,
    ForkAttributionIssuerAdmissionQueryV1, ForkAttributionIssuerAdmissionV1,
    ForkAttributionIssuerPolicyErrorV1, ForkAttributionIssuerPolicyInstallationPortV1,
    IssuerPolicyFloorV1, IssuerPolicyInstallOutcomeV1, IssuerPolicyInstallReceiptV1,
};

impl ForkAttributionIssuerPolicyInstallationPortV1 for MemoryStore {
    fn install(
        &mut self,
        pin: &AuthenticatedOperatorPolicyPinV1,
        policy_bytes: &[u8],
    ) -> Result<IssuerPolicyInstallReceiptV1, ForkAttributionIssuerPolicyErrorV1> {
        pinned_issuer_policy(pin, policy_bytes).and_then(|candidate| {
            let current = self.fork_attribution_issuer_policies.last();
            let receipt = plan_issuer_policy_install(&candidate, current)?;
            if receipt.outcome == IssuerPolicyInstallOutcomeV1::Installed {
                self.fork_attribution_issuer_policies.push(candidate);
            }
            Ok(receipt)
        })
    }

    fn issuer_policy_floor(
        &self,
    ) -> Result<Option<IssuerPolicyFloorV1>, ForkAttributionIssuerPolicyErrorV1> {
        let floor = self.fork_attribution_issuer_policies.last();
        Ok(floor.map(IssuerPolicyFloorV1::of))
    }

    fn admit_issuer(
        &self,
        query: &ForkAttributionIssuerAdmissionQueryV1,
    ) -> Result<ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1> {
        let history = &self.fork_attribution_issuer_policies;
        admit_fork_attribution_issuer(query, |basis| {
            let policy = match basis {
                ForkAttributionIssuerAdmissionBasisV1::CommittedImport { policy_generation } => {
                    history
                        .iter()
                        .find(|policy| policy.input().generation == policy_generation)
                }
                ForkAttributionIssuerAdmissionBasisV1::AbsentImport => history.last(),
            };
            Ok(policy.cloned())
        })
    }
}
