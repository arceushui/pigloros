//! Initial producer binding to actual retained tuple/member/State data.

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDurableProfileV1, CommunityInitializationProducerInputV1,
    CommunityInitializationProducerV1, CommunityInitializationRequestV1,
    CommunityLifecycleErrorV1 as Error, CommunityMemberBindingV1, CommunityStateContentV1,
};
use pos_core::Hash;

use super::CommunityNegotiatedTupleV1;

impl CommunityNegotiatedTupleV1<'_> {
    /// Bind CIS1 to the exact request, negotiated member and initial CSC1.
    ///
    /// Derive identities from the complete supplied records, without accepting
    /// replacements for their hashes. This prepares untrusted data only: the
    /// qualified owner must independently verify the actual initializer, full
    /// source scope, current authority and complete generation roster.
    ///
    /// # Errors
    /// Rejects a foreign member/release/tuple, substituted State/schema/source,
    /// absent roster member, zero producer links or extended/invalid horizon.
    /// Neither successful preparation nor CIS1 decoding issues a guest permit.
    pub fn initialization_producer(
        &self,
        request: &CommunityInitializationRequestV1<'_>,
        member: &CommunityMemberBindingV1<'_>,
        profile: &CommunityDurableProfileV1<'_>,
        state: &CommunityStateContentV1<'_>,
        scope_binding_digest: Hash,
        evidence_not_after_micros: u64,
    ) -> Result<CommunityInitializationProducerV1, Error> {
        initial_state_digest(self, member, state).and_then(|state_content_digest| {
            profile_initializer(self, request, member, profile).and_then(|initializer_ref| {
                if evidence_not_after_micros > request.as_input().evidence_not_after_micros {
                    return Err(Error::InvalidBinding);
                }
                CommunityInitializationProducerV1::new(CommunityInitializationProducerInputV1 {
                    generation_request_digest: request.digest(),
                    member_binding_digest: member.digest(),
                    initializer_ref,
                    state_content_digest,
                    scope_binding_digest,
                    evidence_not_after_micros,
                })
            })
        })
    }
}

fn initial_state_digest(
    tuple: &CommunityNegotiatedTupleV1<'_>,
    member: &CommunityMemberBindingV1<'_>,
    state: &CommunityStateContentV1<'_>,
) -> Result<Hash, Error> {
    let binding = member.as_input();
    let state_digest = state.digest();
    if binding.implementation.plugin_id() != tuple.negotiated().plugin_id()
        || binding.implementation.release_digest().as_bytes()
            != &tuple.negotiated().release_digest()
        || binding.pmf1_digest.as_bytes() != &tuple.negotiated().pmf1_digest()
        || binding.negotiated_tuple_digest != tuple.digest()
        || binding.state_schema_digest != state.schema_digest()
        || binding.initial_state_content_digest != state_digest
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(state_digest)
    }
}

fn profile_initializer(
    tuple: &CommunityNegotiatedTupleV1<'_>,
    request: &CommunityInitializationRequestV1<'_>,
    member: &CommunityMemberBindingV1<'_>,
    profile: &CommunityDurableProfileV1<'_>,
) -> Result<ArtifactRefV1, Error> {
    let fields = profile.as_input();
    let request = request.as_input();
    let binding = member.as_input();
    if request.profile_digest != profile.digest()
        || Some(*fields.execution_profile_digest.as_bytes())
            != tuple.negotiated().execution_profile_digest()
        || request.evidence_not_after_micros > fields.retention.generation_not_after_micros
        || !request
            .member_binding_digests
            .iter()
            .any(|digest| digest == member.digest())
    {
        return Err(Error::InvalidBinding);
    }
    fields
        .roster
        .iter()
        .find(|row| row.stable_entry() == binding.stable_entry)
        .filter(|row| {
            row.implementation() == binding.implementation
                && row.digests()
                    == [
                        binding.pmf1_digest,
                        binding.state_schema_digest,
                        binding.negotiated_tuple_digest,
                    ]
        })
        .map(pos_core::community_lifecycle::CommunityProfileMemberV1::initializer)
        .ok_or(Error::InvalidBinding)
}
