//! Gateway composition for ADR-021 human action admission (#319).
//!
//! The Gateway is the trusted host for one authenticated human request. Inside
//! its single store command, after Principal authorization has been rechecked
//! at the commit fence, it:
//!
//! 1. persists the authority chain and every revocation record behind that
//!    decision (before the Timeline's erasure fence opens, in the same
//!    command) and publishes the Timeline's admission fence from the chain as
//!    the store then resolves it, so the store composes the persisted chain,
//!    its revocation records, erasure generation, and remaining Event budget
//!    at commit, including a revocation another host persisted;
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
//!
//! Failures keep their owner: a fence, attempt, observation, or evidence
//! value this host cannot derive is
//! [`HumanActionAdmissionErrorV1::HostContract`] (unavailable), never a domain
//! rejection of the proposal. An exact retry is recovered only after the
//! request is authorized again, so a retry after its grant was revoked or
//! expired is denied rather than handed the retained receipt (fail closed).
//!
//! The Timeline's admission fence is one last-writer-wins row. Sharing one
//! `SQLite` file with another host that republishes the same Timeline's fence
//! (for example a local experiment session) is unsupported for liveness: an
//! interleaved republish makes this attempt fail closed, never commit against
//! the other host's fence.

use pos_core::{
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendIdentity, EntityId, Hash, PersistedAuthorityV1, PipelineAdmissionFenceV1,
    PipelineAttemptIdV1, PipelineContractErrorV1, PipelineEvidenceRefV1,
    PipelineObservationAnchorV1, PipelineOutcomeV1, PipelineSecurityRevisionsDraftV1,
    PipelineSecurityRevisionsV1, ProposedAction, Seq, TimelineId,
};
use pos_runtime::{
    HumanActionAdmissionErrorV1, HumanActionAdmissionV1, HumanActionReceiptV1, PluginRegistry,
    ScheduledAdmissionPortsV1,
};

use super::ActionAttemptRequest;
use crate::{
    authorization::{GatewayAuthorization, GatewayAuthorizationDecision},
    ingress_dedup_scope,
    mode_profile::GatewayExecutionModeRevisionV1,
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
                    .map_err(HumanActionAdmissionErrorV1::HostContract)
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
            .map_err(HumanActionAdmissionErrorV1::HostContract)
            .and_then(|(fence, revisions)| {
                ports
                    .set_pipeline_admission_fence(self.timeline, fence)
                    .map(|()| revisions)
                    .map_err(HumanActionAdmissionErrorV1::Store)
            })
    }

    /// The complete security revision set for the persisted authority.
    ///
    /// Authority, delegation, and erasure are read from their persisted
    /// owners: delegation binds the chain's delegation edges and every
    /// persisted revocation record on its authority Timeline, so a revocation
    /// another host persisted moves it even at an unchanged epoch. The other
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
        let (registry, revocation_current, mode) = self.authorization.execution_profile();
        execution_mode_revision(registry, revocation_current, mode).and_then(|execution_profile| {
            PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
                authority: pipeline_authority_revision_v1(authority),
                consent: keyed(b"consent", &consent),
                capability: keyed(b"capability", &hash_slices(&grant_ids)),
                delegation: pipeline_delegation_revision_v1(authority),
                policy: keyed(b"policy", &hash_slices(&policies)),
                execution_profile,
                erasure: pipeline_erasure_revision_v1(
                    self.registry
                        .clone_erasure_gate()
                        .and_then(|gate| gate.inventory_generation().ok()),
                ),
            })
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
                    authority_grant: self.authority.0,
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

/// Persist the authority chain and every revocation record behind a decision
/// in the admission store.
///
/// The host runs this in the same store command as the admission but before
/// the Timeline's erasure fence opens, because authority persistence commits
/// its own store transaction. A view the store cannot persist or resolve is
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

/// The ADR-134 §6 execution-profile security revision: the bound GMP1
/// digest, the EPF1 field (explicit-absent until #461), the sorted operator
/// grant tags, the pinned authority registry digest and the revocation
/// freshness. An unbound composition has no execution mode, so its contract
/// is incomplete and it admits nothing.
fn execution_mode_revision(
    registry: Hash,
    revocation_current: bool,
    mode: Option<&GatewayExecutionModeRevisionV1>,
) -> Result<Hash, PipelineContractErrorV1> {
    mode.map(|mode| {
        let [mode_profile, epf1, grants] = mode.fields();
        keyed(
            b"execution-mode-profile",
            &[
                mode_profile,
                epf1,
                grants,
                registry.as_bytes(),
                &[u8::from(revocation_current)],
            ],
        )
    })
    .ok_or(PipelineContractErrorV1::Incomplete)
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{execution_mode_revision, keyed};
    use crate::mode_profile::{test_binding, GatewayModeProfileIdV1, GatewayNetworkGrantV1};
    use pos_core::{Hash, PipelineContractErrorV1};

    #[test]
    fn the_execution_profile_revision_binds_the_bound_mode() {
        let registry = Hash::from_bytes([7; 32]);
        assert_eq!(
            execution_mode_revision(registry, true, None),
            Err(PipelineContractErrorV1::Incomplete)
        );
        let local = test_binding(GatewayModeProfileIdV1::Local, []).revision_input();
        let granted = test_binding(
            GatewayModeProfileIdV1::Local,
            [GatewayNetworkGrantV1::OwnTracks],
        )
        .revision_input();
        let air_gapped = test_binding(GatewayModeProfileIdV1::AirGapped, []).revision_input();
        let revision = |mode, registry, current| {
            execution_mode_revision(registry, current, Some(mode))
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
        };
        let base = revision(&local, registry, true);
        let [mode_profile, epf1, grants] = local.fields();
        assert_eq!(
            base,
            keyed(
                b"execution-mode-profile",
                &[mode_profile, epf1, grants, &[7; 32], &[1]]
            )
        );
        assert_eq!(epf1, [0x00]);
        assert_ne!(
            base,
            keyed(b"execution-profile", &[&[7; 32], &[1]]),
            "the label is domain-separated from the old placeholder"
        );
        for moved in [
            revision(&air_gapped, registry, true),
            revision(&granted, registry, true),
            revision(&local, Hash::from_bytes([8; 32]), true),
            revision(&local, registry, false),
        ] {
            assert_ne!(moved, base);
        }
    }
}
