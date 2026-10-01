//! Gateway composition for ADR-021 human action admission (#319).
//!
//! The Gateway is the trusted host for one authenticated human request. Inside
//! its single store command, after Principal authorization has been rechecked
//! at the commit fence, it:
//!
//! 1. persists the authority chain behind that decision (before the
//!    Timeline's erasure fence opens, in the same command) and publishes the
//!    Timeline's admission fence from it, so the store composes the persisted
//!    chain, erasure generation, and remaining Event budget at commit;
//! 2. derives the attempt from the authenticated Principal, the Timeline, the
//!    caller's idempotency key, and the exact request, so an exact retry is
//!    the same attempt and a different Principal never shares a key, and
//!    groups the key under the acting Entity's consent cleanup scope; and
//! 3. hands the proposal to [`PluginRegistry::admit_human_action`], which
//!    recovers a retained receipt without approval or runs the owning
//!    `ActionApprover` and commits through the admitted-batch port.
//!
//! The Principal and the acting `EntityId` stay distinct: the Principal scopes
//! the idempotency key and the authorization evidence, while the proposal
//! names the acting Entity. A first-party caller has no other route.

use pos_core::{
    pipeline_authority_revision_v1, pipeline_erasure_revision_v1, AppendDedupKey, AppendIdentity,
    EntityId, Hash, PersistedAuthorityV1, PipelineAdmissionFenceV1, PipelineAttemptIdV1,
    PipelineContractErrorV1, PipelineEvidenceRefV1, PipelineObservationAnchorV1, PipelineOutcomeV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, ProposedAction, Seq, TimelineId,
};
use pos_runtime::{
    HumanActionAdmissionErrorV1, HumanActionAdmissionV1, HumanActionReceiptV1, PluginRegistry,
    ScheduledAdmissionPortsV1,
};

use super::ActionAttemptRequest;
use crate::{
    authorization::{GatewayAuthorization, GatewayAuthorizationDecision},
    ingress_dedup_scope,
};

const DOMAIN: &[u8] = b"PiglorOS.GatewayHumanActionAdmission.v1\0";

/// Everything the host binds for one human action inside its store command.
pub(super) struct GatewayActionAdmission<'a> {
    pub(super) registry: &'a PluginRegistry,
    pub(super) authorization: &'a GatewayAuthorization,
    pub(super) authority: &'a (Hash, PersistedAuthorityV1),
    pub(super) decision: &'a GatewayAuthorizationDecision,
    pub(super) proposal: &'a ProposedAction,
    pub(super) attempt: ActionAttemptRequest,
    pub(super) timeline: TimelineId,
    pub(super) logical_head: Seq,
    pub(super) remaining_event_budget: u64,
}

impl GatewayActionAdmission<'_> {
    /// Publish the authority fence, then recover or approve and admit.
    ///
    /// # Errors
    /// Returns a typed admission error; none commits an Event.
    pub(super) fn admit(
        &self,
        ports: &mut dyn ScheduledAdmissionPortsV1,
    ) -> Result<HumanActionReceiptV1, HumanActionAdmissionErrorV1> {
        self.publish_fence(ports)
            .and_then(|revisions| {
                self.admission(revisions)
                    .map_err(HumanActionAdmissionErrorV1::Contract)
            })
            .and_then(|admission| {
                self.registry
                    .admit_human_action(ports, self.proposal, &admission)
            })
    }

    /// Publish the Timeline's admission fence from the persisted authority.
    fn publish_fence(
        &self,
        ports: &mut dyn ScheduledAdmissionPortsV1,
    ) -> Result<PipelineSecurityRevisionsV1, HumanActionAdmissionErrorV1> {
        let (grant, authority) = self.authority;
        self.revisions(authority)
            .and_then(|revisions| {
                PipelineAdmissionFenceV1::try_new(
                    *grant,
                    revisions,
                    None,
                    self.remaining_event_budget,
                )
                .map(|fence| (fence, revisions))
            })
            .map_err(HumanActionAdmissionErrorV1::Contract)
            .and_then(|(fence, revisions)| {
                ports
                    .set_pipeline_admission_fence(self.timeline, fence)
                    .map(|()| revisions)
                    .map_err(HumanActionAdmissionErrorV1::Store)
            })
    }

    /// The complete security revision set for the persisted authority.
    ///
    /// Authority and erasure are read from their persisted owners. The other
    /// revisions are derived from the same persisted chain and the host's
    /// pinned registry, so they move whenever that authority moves.
    fn revisions(
        &self,
        authority: &PersistedAuthorityV1,
    ) -> Result<PipelineSecurityRevisionsV1, PipelineContractErrorV1> {
        let grants = authority.chain().grants();
        let consent = grants
            .iter()
            .flat_map(|grant| grant.consent_references().iter().map(Hash::as_bytes))
            .map(<[u8; 32]>::as_slice)
            .collect::<Vec<_>>();
        let grant_ids = grants
            .iter()
            .map(pos_core::CapabilityGrantV1::grant_id)
            .collect::<Vec<_>>();
        let policies = grants
            .iter()
            .map(pos_core::CapabilityGrantV1::policy_revision)
            .collect::<Vec<_>>();
        let (registry, revocation_current) = self.authorization.execution_profile();
        PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
            authority: pipeline_authority_revision_v1(authority),
            consent: keyed(b"consent", &consent),
            capability: keyed(b"capability", &hash_slices(&grant_ids)),
            delegation: keyed(
                b"delegation",
                &[&authority.revocation_epoch().to_be_bytes()],
            ),
            policy: keyed(b"policy", &hash_slices(&policies)),
            execution_profile: keyed(
                b"execution-profile",
                &[registry.as_bytes(), &[u8::from(revocation_current)]],
            ),
            erasure: pipeline_erasure_revision_v1(
                self.registry
                    .clone_erasure_gate()
                    .and_then(|gate| gate.inventory_generation().ok()),
            ),
        })
    }

    /// Bind the request to its Principal-scoped attempt and observation.
    fn admission(
        &self,
        security_revisions: PipelineSecurityRevisionsV1,
    ) -> Result<HumanActionAdmissionV1, PipelineContractErrorV1> {
        let principal = self.decision.principal();
        let caller_key = self
            .attempt
            .idempotency_key
            .unwrap_or_else(fresh_caller_key);
        let key = keyed(
            b"idempotency",
            &[
                principal.principal_id(),
                principal.trust_domain().as_bytes(),
                &self.timeline.inner().to_bytes(),
                caller_key.as_bytes(),
            ],
        );
        let observed_through = self.attempt.observed_through.unwrap_or(self.logical_head);
        let mut attempt = [0_u8; 16];
        attempt.copy_from_slice(&self.request_fingerprint(key).as_bytes()[..16]);
        PipelineAttemptIdV1::try_new(attempt)
            .and_then(|attempt_id| {
                PipelineObservationAnchorV1::try_new(
                    self.timeline,
                    observed_through,
                    keyed(
                        b"observation",
                        &[
                            &self.timeline.inner().to_bytes(),
                            &observed_through.as_u64().to_be_bytes(),
                        ],
                    ),
                )
                .map(|observation| (attempt_id, observation))
            })
            .and_then(|(attempt_id, observation)| {
                PipelineEvidenceRefV1::try_new(keyed(
                    b"authorization",
                    &[
                        self.decision.decision_digest().as_bytes(),
                        self.decision.request_digest().as_bytes(),
                        self.decision.operation_binding().as_bytes(),
                    ],
                ))
                .map(|authorization| HumanActionAdmissionV1 {
                    attempt_id,
                    // The acting Entity's consent cleanup group, so a consent
                    // revocation releases its retry keys (ADR-039).
                    idempotency: AppendIdentity::new(
                        AppendDedupKey::from_keyed_hash(*key.as_bytes()),
                        ingress_dedup_scope(self.proposal.actor_entity_id),
                    ),
                    observation,
                    authorization,
                    security_revisions,
                })
            })
    }

    /// Fingerprint the exact request under its idempotency key.
    ///
    /// The caller's cursor enters as supplied, not as resolved, so an exact
    /// retry without a cursor stays the same attempt after the head moves.
    fn request_fingerprint(&self, key: Hash) -> Hash {
        let cursor = self.attempt.observed_through.map_or([0_u8; 9], |seq| {
            let mut bytes = [1_u8; 9];
            bytes[1..].copy_from_slice(&seq.as_u64().to_be_bytes());
            bytes
        });
        keyed(
            b"attempt",
            &[
                key.as_bytes(),
                &self.proposal.actor_entity_id.inner().to_bytes(),
                self.proposal.event_type.as_str().as_bytes(),
                self.proposal.capability.as_str().as_bytes(),
                self.proposal.payload.as_slice(),
                &cursor,
            ],
        )
    }
}

/// Persist the authority chain behind a decision in the admission store.
///
/// The host runs this in the same store command as the admission but before
/// the Timeline's erasure fence opens, because authority persistence commits
/// its own store transaction. A chain the store cannot persist or resolve is
/// [`PipelineOutcomeV1::PolicyIndeterminate`].
pub(super) fn persist_authority(
    authorization: &GatewayAuthorization,
    ports: &mut dyn ScheduledAdmissionPortsV1,
) -> Result<(Hash, PersistedAuthorityV1), HumanActionAdmissionErrorV1> {
    authorization.persist_authority(ports).map_err(|_| {
        HumanActionAdmissionErrorV1::NotAdmitted(Box::new(PipelineOutcomeV1::PolicyIndeterminate))
    })
}

/// The only form in which a caller's idempotency key is retained.
pub(super) fn caller_key_digest(key: &str) -> Hash {
    keyed(b"caller-key", &[key.as_bytes()])
}

/// A one-use caller key for a request that supplied none.
fn fresh_caller_key() -> Hash {
    keyed(b"fresh-caller-key", &[&EntityId::new().inner().to_bytes()])
}

fn hash_slices(values: &[Hash]) -> Vec<&[u8]> {
    values
        .iter()
        .map(|value| value.as_bytes().as_slice())
        .collect()
}

/// Derive one domain-separated value over length-framed fields.
fn keyed(label: &[u8], fields: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(label);
    hasher.update(b"\0");
    for field in fields {
        hasher.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
