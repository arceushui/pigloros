//! Exact CIN1 preparation from the existing invocation and every host option.

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1, CommunityPreparedInvocationInputV1, CommunityPreparedInvocationV1,
};
use pos_core::Hash;

use super::{InvocationOptionsV1, PluginInvocationV1};

impl PluginInvocationV1 {
    /// Borrow all actual step inputs for the pre-Reserve CIN1 record.
    ///
    /// No observation, State or budget-ID allocation is made here. Encoding
    /// subsequently copies into a zeroizing output; its owner must account for
    /// that copy and the original Runtime/worker buffers. This is data preparation,
    /// not source verification, current-use admission or permission to invoke.
    ///
    /// # Errors
    /// Rejects invalid invocation bounds/ID grammar or zero required identities
    /// and digests. The installed owner must independently authenticate the member,
    /// actual source artifacts, profile, trust and provenance before Reserve.
    pub fn prepared_record(
        &self,
        member_binding_digest: Hash,
        options: InvocationOptionsV1,
    ) -> Result<CommunityPreparedInvocationV1<'_>, CommunityLifecycleErrorV1> {
        CommunityPreparedInvocationV1::new(CommunityPreparedInvocationInputV1 {
            member_binding_digest,
            invocation_id: self.invocation_id,
            timeline_position: self.timeline_position,
            output_base_ordinal: self.output_base_ordinal,
            principal_ref: self.principal_ref,
            authorization_ref: self.authorization_decision,
            observation_snapshot_ref: self.observation_snapshot,
            observation_bytes: &self.observation_bytes,
            prior_state_schema_digest: self.prior_state_schema,
            prior_state_bytes: &self.prior_state_bytes,
            execution_profile_digest: self.execution_profile_digest,
            trust_policy_snapshot_digest: self.trust_policy_snapshot_digest,
            deterministic_budget_id: &self.deterministic_budget_id,
            deterministic_random_domain: self.deterministic_random_domain,
            provenance_root: self.provenance_root,
            simulation_time: options.host_inputs.simulation_time,
            watchdog_epochs: options.watchdog_epochs,
        })
    }
}
