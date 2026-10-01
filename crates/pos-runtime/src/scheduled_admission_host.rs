//! Local host composition for ADR-021 scheduled-pass admission (#480).
//!
//! A local experiment session is the trusted composition root for its own
//! scheduled AI Driver passes. [`LocalScheduledAdmissionHostV1`] owns that
//! root: it persists one local session authority grant in the session store,
//! publishes each Timeline's [`PipelineAdmissionFenceV1`] from the current
//! persisted authority and erasure revisions, and admits every staged pass
//! through [`PluginRegistry::admit_scheduled_pass`] with host-issued attempt,
//! idempotency, and validation identities. Plugin, Driver, and provider code
//! never receives this host, its grant, or the store ports it uses.
//!
//! The consent, capability, delegation, policy, and execution-profile
//! revisions are fixed local-session values. Republication of those revisions
//! by their owning contracts remains the #316 deferral; the authority and
//! erasure revisions are always read from persisted state.

use std::sync::OnceLock;

use pos_core::{
    pipeline_authority_revision_v1, pipeline_erasure_revision_v1, store::EventStore,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AuthorityErrorV1, AuthorityGranteeV1,
    AuthorityPersistenceHostV1, AuthorityPersistencePortV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, EntityId, EventDraft, Hash, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineAttemptIdV1,
    PipelineCommitReceiptV1, PipelineEvidenceRefV1, PipelineSecurityRevisionsDraftV1,
    PipelineSecurityRevisionsV1, PrincipalRefV1, Seq, TimelineId,
};
use ulid::Ulid;

use crate::{PluginRegistry, RuntimeError, ScheduledPassAdmissionV1};

/// Store capabilities a trusted host needs to admit scheduled passes.
///
/// The admitted-batch port, the admission-fence publisher, and authority
/// persistence must belong to the same store as the Timeline, so the store
/// compares the fence and persisted authority inside its admission
/// transaction.
pub trait ScheduledAdmissionStoreV1:
    EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
{
}

impl<T> ScheduledAdmissionStoreV1 for T where
    T: EventStore
        + PipelineAdmissionPortV1
        + PipelineAdmissionFencePublisherV1
        + AuthorityPersistencePortV1
{
}

const TRUST_DOMAIN: &str = "local.experiment";
const DOMAIN: &[u8] = b"PiglorOS.LocalScheduledAdmission.v1\0";
/// The local session root's actor, principal, and authority Timeline identity.
const LOCAL_ROOT: u128 = 1;

static SHARED: OnceLock<Option<LocalScheduledAdmissionHostV1>> = OnceLock::new();

/// Trusted local host that admits scheduled passes for experiment sessions.
///
/// The host holds the only persistence identity for its local session
/// authority root. One process-wide host lets every session that shares a
/// store, including its Forks and resumed sessions, bind that store to the
/// same identity.
pub struct LocalScheduledAdmissionHostV1 {
    authority: AuthorityPersistenceHostV1,
    grant: CapabilityGrantV1,
}

impl LocalScheduledAdmissionHostV1 {
    /// Return the process-wide local admission host.
    ///
    /// # Errors
    /// Returns [`RuntimeError::Authority`] when the local session authority
    /// root cannot be composed.
    pub fn shared() -> Result<&'static Self, RuntimeError> {
        SHARED
            .get_or_init(|| Self::compose().ok())
            .as_ref()
            .ok_or(RuntimeError::Authority(
                AuthorityErrorV1::PrincipalUnresolved,
            ))
    }

    /// The persisted local session grant named by every published fence.
    #[must_use]
    pub const fn authority_grant(&self) -> Hash {
        self.grant.grant_id()
    }

    /// Observe the admission state for the next pass on `timeline`.
    ///
    /// The first observation of a Timeline binds `store` to this host and
    /// persists the local session grant. Every observation then derives the
    /// security revisions from the persisted authority chain and the erasure
    /// inventory generation of `registry`'s gate, and republishes the
    /// Timeline's fence only when they changed; a republished fence keeps its
    /// remaining Event budget. Call this before staging the pass: the store
    /// rejects its basis if a revision changes before commit.
    ///
    /// # Errors
    /// Returns an authority persistence, contract, or store error.
    pub fn observe(
        &self,
        registry: &PluginRegistry,
        store: &mut dyn ScheduledAdmissionStoreV1,
        timeline: TimelineId,
    ) -> Result<PipelineSecurityRevisionsV1, RuntimeError> {
        store
            .pipeline_admission_fence(timeline)
            .map_err(RuntimeError::Store)
            .and_then(|fence| {
                let bound = if fence.is_none() {
                    self.bind(store)
                } else {
                    Ok(())
                };
                bound.map(|()| fence)
            })
            .and_then(|fence| {
                store
                    .load_authority(self.authority_grant())
                    .map_err(RuntimeError::AuthorityPersistence)
                    .and_then(|authority| {
                        local_revisions(
                            pipeline_authority_revision_v1(&authority),
                            pipeline_erasure_revision_v1(
                                registry
                                    .clone_erasure_gate()
                                    .and_then(|gate| gate.inventory_generation().ok()),
                            ),
                        )
                    })
                    .map(|revisions| (fence, revisions))
            })
            .and_then(|(fence, revisions)| {
                if fence.is_some_and(|current| {
                    current.security_revisions() == revisions
                        && current.authority_grant() == self.authority_grant()
                }) {
                    return Ok(revisions);
                }
                let budget = fence
                    .as_ref()
                    .map_or(u64::MAX, PipelineAdmissionFenceV1::remaining_event_budget);
                PipelineAdmissionFenceV1::try_new(self.authority_grant(), revisions, None, budget)
                    .map_err(RuntimeError::PipelineContract)
                    .and_then(|next| {
                        store
                            .set_pipeline_admission_fence(timeline, next)
                            .map_err(RuntimeError::Store)
                    })
                    .map(|()| revisions)
            })
    }

    /// Admit the pass staged in `registry` with fresh host-issued identities.
    ///
    /// `revisions` must come from [`Self::observe`] before the pass was
    /// staged, and `commit_head` is the Logical Head the host read after the
    /// pass. `validated` is the draft vector the host schema-validated; its
    /// digest is the pass's host-validation evidence reference.
    ///
    /// # Errors
    /// Returns the same errors as [`PluginRegistry::admit_scheduled_pass`].
    pub fn admit(
        &self,
        registry: &mut PluginRegistry,
        store: &mut dyn ScheduledAdmissionStoreV1,
        revisions: PipelineSecurityRevisionsV1,
        commit_head: Seq,
        commit_now_secs: u64,
        validated: &[EventDraft],
    ) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let attempt = EntityId::new().inner().to_bytes();
        PipelineAttemptIdV1::try_new(attempt)
            .and_then(|attempt_id| {
                PipelineEvidenceRefV1::try_new(validation_digest(&attempt, validated)).map(
                    |provider_validation| ScheduledPassAdmissionV1 {
                        attempt_id,
                        idempotency: AppendIdentity::new(
                            AppendDedupKey::from_keyed_hash(
                                *keyed(b"idempotency", &attempt).as_bytes(),
                            ),
                            AppendDedupScope::from_keyed_hash(*keyed(b"scope", &[]).as_bytes()),
                        ),
                        provider_validation,
                        security_revisions: revisions,
                        commit_head,
                        commit_now_secs,
                    },
                )
            })
            .map_err(RuntimeError::PipelineContract)
            .and_then(|admission| registry.admit_scheduled_pass(store, &admission))
    }

    fn bind(&self, store: &mut dyn ScheduledAdmissionStoreV1) -> Result<(), RuntimeError> {
        store
            .bind_authority_persistence(self.authority.persistence_binding())
            .and_then(|()| self.authority.authorize_grant(&self.grant))
            .and_then(|permit| store.issue_capability_grant(permit, &self.grant))
            .map(|_| ())
            .map_err(RuntimeError::AuthorityPersistence)
    }

    fn compose() -> Result<Self, AuthorityErrorV1> {
        let registry_digest = keyed(b"registry", &[]);
        PrincipalRefV1::try_new(LOCAL_ROOT.to_be_bytes(), TRUST_DOMAIN)
            .and_then(|principal| {
                local_scope().and_then(|scope| {
                    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
                        grant_id: keyed(b"grant", &[]),
                        grantor: principal.clone(),
                        grantee: AuthorityGranteeV1::Principal(principal),
                        trust_domain: TRUST_DOMAIN.to_owned(),
                        scope,
                        valid_from_position: Seq::from_u64(1),
                        valid_until_position: Seq::from_u64(u64::MAX),
                        parent_grant_id: None,
                        delegation_depth: 0,
                        max_delegation_depth: 0,
                        permitted_delegate_classes: Vec::new(),
                        consent_references: Vec::new(),
                        policy_revision: keyed(b"policy", &[]),
                        issuance_timeline: TimelineId::from_ulid(Ulid(LOCAL_ROOT)),
                        issuance_seq: Seq::from_u64(1),
                        revocation_epoch: 0,
                        revocation_fence: None,
                        authority_registry_digest: registry_digest,
                    })
                })
            })
            .and_then(|grant| {
                grant
                    .binding_digest()
                    .and_then(|binding| {
                        AuthorityRegistrySnapshotV1::try_new(
                            registry_digest,
                            vec![keyed(b"authentication", &[])],
                            vec![binding],
                            Vec::new(),
                        )
                    })
                    .map(|registry| Self {
                        authority: AuthorityPersistenceHostV1::new(&registry),
                        grant,
                    })
            })
    }
}

fn local_scope() -> Result<CapabilityScopeV1, AuthorityErrorV1> {
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["timeline".to_owned()],
        actions: vec!["scheduled.admit".to_owned()],
        purposes: vec!["simulation".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![EntityId::from_ulid(Ulid(LOCAL_ROOT))],
        subject_ids: Vec::new(),
        participant_ids: Vec::new(),
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: u64::MAX,
        budget: u64::MAX,
        environment_constraints: vec!["local-only".to_owned()],
    })
}

/// The complete local security revisions for one persisted authority and
/// erasure revision.
fn local_revisions(
    authority: Hash,
    erasure: Hash,
) -> Result<PipelineSecurityRevisionsV1, RuntimeError> {
    PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
        authority,
        consent: keyed(b"consent", &[]),
        capability: keyed(b"capability", &[]),
        delegation: keyed(b"delegation", &[]),
        policy: keyed(b"policy", &[]),
        execution_profile: keyed(b"execution-profile", &[]),
        erasure,
    })
    .map_err(RuntimeError::PipelineContract)
}

/// Bind one attempt to the exact draft vector the host validated.
fn validation_digest(attempt: &[u8; 16], drafts: &[EventDraft]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(b"validation\0");
    hasher.update(attempt);
    hasher.update(&(drafts.len() as u64).to_be_bytes());
    for draft in drafts {
        let entity = draft.entity.inner().to_bytes();
        for field in [
            entity.as_slice(),
            draft.event_type.as_str().as_bytes(),
            draft.payload.as_slice(),
        ] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Derive one domain-separated local-session identity.
fn keyed(label: &[u8], value: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(label);
    hasher.update(b"\0");
    hasher.update(value);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
