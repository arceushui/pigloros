//! Revocation records behind a host authority view persist into the
//! admission store and move its delegation revision (#483).

use std::sync::{Arc, Barrier};

use pos_core::{
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AuthorityGranteeV1,
    AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1,
    CanonicalBytes, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, CoreError, DelegateClassV1,
    EntityId, ErasureContainmentGateV1, EventDraft, EventStore, Hash, Kind, PersistedAuthorityV1,
    PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineAttemptDraftV1, PipelineAttemptIdV1,
    PipelineAttemptV1, PipelineDraftBatchV1, PipelineEvidenceRefV1, PipelineIngressV1,
    PipelineObservationAnchorV1, PipelineOutcomeV1, PipelinePreconditionV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, PrincipalRefV1, Seq, SeqRange,
    TentativePipelineResultV1, TimelineId, DELEGATE_ACTION_V1, PIPELINE_CONTRACT_VERSION_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use ulid::Ulid;

use super::{harness::Capture, support::TestOk};

/// The ports one host needs to persist authority and admit a batch.
trait AdmissionStore:
    EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
{
}

impl<T> AdmissionStore for T where
    T: EventStore
        + PipelineAdmissionPortV1
        + PipelineAdmissionFencePublisherV1
        + AuthorityPersistencePortV1
{
}

const fn digest(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const REGISTRY: Hash = digest(7);
const POLICY: Hash = digest(9);

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(30_u128))
}

fn principal(value: u8) -> PrincipalRefV1 {
    PrincipalRefV1::try_new([value; 16], "local.test").test_ok()
}

fn stores() -> Vec<(&'static str, Box<dyn AdmissionStore>)> {
    let mut stores: Vec<(&'static str, Box<dyn AdmissionStore>)> = vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ];
    for (_, store) in &mut stores {
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
            .test_ok();
    }
    stores
}

fn open_file(path: &str) -> SqliteStore {
    let mut store = SqliteStore::open(path).test_ok();
    EventStore::bind_erasure_gate(
        &mut store,
        Arc::new(ErasureContainmentGateV1::new_test_open()),
    )
    .test_ok();
    store
}

/// One grant of the shared authority Timeline. A grant without a parent is
/// a root issued by Principal 1.
fn grant(
    id: u8,
    grantee: u8,
    parent: Option<&CapabilityGrantV1>,
    issuance: u64,
) -> CapabilityGrantV1 {
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: digest(id),
        grantor: parent.map_or_else(
            || principal(1),
            |parent| parent.grantee().principal().clone(),
        ),
        grantee: AuthorityGranteeV1::Principal(principal(grantee)),
        trust_domain: "local.test".to_owned(),
        scope: CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["world".to_owned()],
            actions: vec!["act".to_owned(), DELEGATE_ACTION_V1.to_owned()],
            purposes: vec!["simulation".to_owned()],
            audiences: vec!["local-host".to_owned()],
            actor_entity_ids: vec![entity(10)],
            subject_ids: vec![entity(50)],
            participant_ids: vec![entity(20)],
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 10,
            budget: 100,
            environment_constraints: vec!["local-only".to_owned()],
        })
        .test_ok(),
        valid_from_position: Seq::from_u64(issuance),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: parent.map(CapabilityGrantV1::grant_id),
        delegation_depth: u8::from(parent.is_some()),
        max_delegation_depth: 2,
        permitted_delegate_classes: vec![DelegateClassV1::Principal],
        consent_references: vec![digest(8)],
        policy_revision: POLICY,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(issuance),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })
    .test_ok()
}

/// Root `R`, its delegated child `C`, and an independent root `S`.
struct Grants {
    root: CapabilityGrantV1,
    child: CapabilityGrantV1,
    sibling: CapabilityGrantV1,
}

impl Grants {
    fn new() -> Self {
        let root = grant(1, 2, None, 1);
        let child = grant(2, 3, Some(&root), 2);
        let sibling = grant(3, 4, None, 3);
        Self {
            root,
            child,
            sibling,
        }
    }

    const fn all(&self) -> [&CapabilityGrantV1; 3] {
        [&self.root, &self.child, &self.sibling]
    }

    /// A trusted host for the shared registry; every host has its own
    /// persistence identity.
    fn host(&self) -> AuthorityPersistenceHostV1 {
        let mut bindings = self
            .all()
            .iter()
            .map(|grant| grant.binding_digest().test_ok())
            .collect::<Vec<_>>();
        bindings.sort_unstable();
        AuthorityPersistenceHostV1::new(
            &AuthorityRegistrySnapshotV1::try_new(REGISTRY, vec![digest(200)], bindings, vec![])
                .test_ok(),
        )
    }

    /// The view of `leaf`'s chain from another host's history in which
    /// `revoked` were revoked at fences 4, 5, … with epochs 1, 2, ….
    fn view(&self, revoked: &[&CapabilityGrantV1], leaf: &CapabilityGrantV1) -> AuthorityViewV1 {
        let authority = self.host();
        let mut state = AuthorityPersistenceStateV1::new();
        for grant in self.all() {
            state
                .issue_grant(authority.authorize_grant(grant).test_ok(), grant.clone())
                .test_ok();
        }
        for (offset, grant) in (0_u64..).zip(revoked) {
            let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
                grant_id: grant.grant_id(),
                authority_timeline: authority_timeline(),
                fence_position: Seq::from_u64(4 + offset),
                revocation_epoch: 1 + offset,
                policy_revision: POLICY,
                authority_registry_digest: REGISTRY,
            })
            .test_ok();
            state
                .revoke_grant(
                    authority.authorize_revocation(grant, &revocation).test_ok(),
                    revocation,
                )
                .test_ok();
        }
        state.view(leaf.grant_id()).test_ok()
    }

    fn resolved(
        &self,
        revoked: &[&CapabilityGrantV1],
        leaf: &CapabilityGrantV1,
    ) -> PersistedAuthorityV1 {
        self.view(revoked, leaf).authority().clone()
    }
}

/// The complete security revisions for one persisted authority.
fn revisions(authority: &PersistedAuthorityV1) -> PipelineSecurityRevisionsV1 {
    PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
        authority: pipeline_authority_revision_v1(authority),
        consent: digest(11),
        capability: digest(12),
        delegation: pipeline_delegation_revision_v1(authority),
        policy: digest(14),
        execution_profile: digest(15),
        erasure: pipeline_erasure_revision_v1(None),
    })
    .test_ok()
}

fn publish(
    store: &mut dyn AdmissionStore,
    timeline: TimelineId,
    revisions: PipelineSecurityRevisionsV1,
) {
    store
        .set_pipeline_admission_fence(
            timeline,
            PipelineAdmissionFenceV1::try_new(digest(2), revisions, None, 100).test_ok(),
        )
        .test_ok();
}

fn basis(
    timeline: TimelineId,
    key: u8,
    head: u64,
    revisions: PipelineSecurityRevisionsV1,
) -> PipelineAdmissionBasisV1 {
    PipelineAdmissionBasisV1::try_from_draft(PipelineAdmissionBasisDraftV1 {
        contract_version: PIPELINE_CONTRACT_VERSION_V1,
        attempt: Some(
            PipelineAttemptV1::try_from_draft(PipelineAttemptDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt_id: Some(PipelineAttemptIdV1::try_new([key; 16]).test_ok()),
                ingress: Some(PipelineIngressV1::HumanProposedAction),
                observation: Some(
                    PipelineObservationAnchorV1::try_new(timeline, Seq::from_u64(head), digest(61))
                        .test_ok(),
                ),
                idempotency: Some(AppendIdentity::new(
                    AppendDedupKey::from_keyed_hash([key; 32]),
                    AppendDedupScope::from_keyed_hash([62; 32]),
                )),
            })
            .test_ok(),
        ),
        tentative_result: Some(TentativePipelineResultV1::HumanDomainApproval(
            PipelineEvidenceRefV1::try_new(digest(60)).test_ok(),
        )),
        precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(
            head,
        ))),
        security_revisions: Some(revisions),
        batch: Some(
            PipelineDraftBatchV1::try_new(vec![EventDraft::new(
                entity(5),
                Kind::new("world.action"),
                CanonicalBytes::from_vec(vec![key]),
            )])
            .test_ok(),
        ),
    })
    .test_ok()
}

fn committed(store: &dyn AdmissionStore, timeline: TimelineId) -> usize {
    store.read(timeline, SeqRange::all()).test_ok().len()
}

fn outcome(result: Result<PipelineOutcomeV1, CoreError>) -> String {
    match result {
        Ok(PipelineOutcomeV1::Committed(_)) => "Committed".to_owned(),
        Ok(outcome) => format!("{outcome:?}"),
        Err(error) => format!("error:{error}"),
    }
}

/// PCF-REV-001: a revocation the host learned is persisted with its records;
/// it stales an earlier basis even at an unchanged chain, and a revocation
/// of the chain's root is composed at the store as `AuthorityRevoked`.
pub(super) fn learned_revocation_is_persisted() -> Capture {
    let mut capture = Capture::default();
    let grants = Grants::new();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("revocation-records").test_ok().id();
        let host = grants.host();
        let current = host
            .persist_authority(backend.as_mut(), &grants.view(&[], &grants.child))
            .test_ok();
        let published = revisions(&current);
        publish(backend.as_mut(), timeline, published);

        let learned = host
            .persist_authority(
                backend.as_mut(),
                &grants.view(&[&grants.sibling], &grants.child),
            )
            .test_ok();
        capture.record(store, "learned.records", learned.revocations().len());
        capture.record(
            store,
            "stale-basis",
            outcome(backend.admit_pipeline_batch(&basis(timeline, 2, 0, published))),
        );
        let refreshed = revisions(&learned);
        capture.record(store, "fence-moved", refreshed != published);
        publish(backend.as_mut(), timeline, refreshed);
        capture.record(
            store,
            "refreshed-basis",
            outcome(backend.admit_pipeline_batch(&basis(timeline, 3, 0, refreshed))),
        );

        host.persist_authority(
            backend.as_mut(),
            &grants.view(&[&grants.sibling, &grants.root], &grants.child),
        )
        .test_ok();
        capture.record(
            store,
            "root-revoked",
            outcome(backend.admit_pipeline_batch(&basis(timeline, 4, 1, refreshed))),
        );
        capture.record(store, "committed", committed(backend.as_ref(), timeline));
    }
    capture
}

/// PCF-REV-002: two revocation states with equal epochs yield different
/// delegation revisions, and the delegation edges of a chain are bound.
pub(super) fn equal_epochs_distinct_revisions() -> Capture {
    let mut capture = Capture::default();
    let grants = Grants::new();
    let unrevoked = grants.resolved(&[], &grants.sibling);
    let child_revoked = grants.resolved(&[&grants.child], &grants.sibling);
    let root_revoked = grants.resolved(&[&grants.root], &grants.sibling);
    capture.record(
        "none",
        "epochs-equal",
        child_revoked.revocation_epoch() == root_revoked.revocation_epoch(),
    );
    capture.record(
        "none",
        "authority-revisions-equal",
        pipeline_authority_revision_v1(&child_revoked)
            == pipeline_authority_revision_v1(&root_revoked),
    );
    let delegation =
        [&unrevoked, &child_revoked, &root_revoked].map(pipeline_delegation_revision_v1);
    capture.record(
        "none",
        "delegation-revisions-distinct",
        delegation[0] != delegation[1]
            && delegation[0] != delegation[2]
            && delegation[1] != delegation[2],
    );
    capture.record(
        "none",
        "delegation-edges-bound",
        pipeline_delegation_revision_v1(&grants.resolved(&[], &grants.root))
            != pipeline_delegation_revision_v1(&grants.resolved(&[], &grants.child)),
    );
    capture
}

/// PCF-REV-003: on `SQLite`, a revocation another connection persists while
/// one host admits never lets a stale basis commit after it, on that
/// connection or a fresh one.
pub(super) fn cross_connection_staleness() -> Capture {
    let mut capture = Capture::default();
    let grants = Grants::new();
    let directory = tempfile::tempdir().test_ok();
    let path = directory
        .path()
        .join("revocation-race.sqlite")
        .to_string_lossy()
        .into_owned();
    let (timeline, stale) = {
        let mut store = open_file(&path);
        let timeline = store.create_timeline("revocation-race").test_ok().id();
        let current = grants
            .host()
            .persist_authority(&mut store, &grants.view(&[], &grants.child))
            .test_ok();
        let published = revisions(&current);
        publish(&mut store, timeline, published);
        (timeline, published)
    };

    let revoked = grants.view(&[&grants.root], &grants.child);
    let barrier = Arc::new(Barrier::new(2));
    let admitting = {
        let barrier = Arc::clone(&barrier);
        let mut store = open_file(&path);
        std::thread::spawn(move || {
            barrier.wait();
            store.admit_pipeline_batch(&basis(timeline, 1, 0, stale))
        })
    };
    let revoking = {
        let barrier = Arc::clone(&barrier);
        let revoked = revoked.clone();
        let other = grants.host();
        let mut store = open_file(&path);
        std::thread::spawn(move || {
            barrier.wait();
            other.persist_authority(&mut store, &revoked)
        })
    };
    let admitted = admitting.join().test_ok();
    // Only a host that lost on lock contention persists the same view again.
    let persisted = revoking.join().test_ok().or_else(|error| {
        if error == AuthorityPersistenceErrorV1::Unavailable {
            grants
                .host()
                .persist_authority(&mut open_file(&path), &revoked)
        } else {
            Err(error)
        }
    });
    let race_committed = usize::from(matches!(admitted, Ok(PipelineOutcomeV1::Committed(_))));
    capture.record(
        "sqlite",
        "revocation-persisted",
        persisted
            .test_ok()
            .chain()
            .grants()
            .first()
            .is_some_and(|root| root.revocation_fence().is_some()),
    );
    capture.record(
        "sqlite",
        "race.commits-match-store",
        committed(&open_file(&path), timeline) == race_committed,
    );

    let mut open = open_file(&path);
    let reloaded = grants
        .host()
        .persist_authority(&mut open, &grants.view(&[], &grants.child))
        .test_ok();
    capture.record(
        "sqlite",
        "stale-view-reloads-revoked-chain",
        &reloaded == revoked.authority(),
    );
    capture.record(
        "sqlite",
        "same-connection",
        outcome(open.admit_pipeline_batch(&basis(timeline, 2, 0, stale))),
    );
    capture.record(
        "sqlite",
        "fresh-connection",
        outcome(open_file(&path).admit_pipeline_batch(&basis(timeline, 3, 0, stale))),
    );
    capture.record(
        "sqlite",
        "committed-after-revocation",
        committed(&open_file(&path), timeline) == race_committed,
    );
    capture
}
