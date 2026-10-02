//! Persisted authority views carry their revocation records into the
//! admission store, and the delegation revision binds them (#483). Replaying a
//! view the store already holds writes no authority state (#491).

use std::path::Path;
use std::sync::{Arc, Barrier};

use pos_core::{
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AuthorityCommitOutcomeV1, AuthorityGranteeV1,
    AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1,
    CanonicalBytes, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, CoreError, DelegateClassV1,
    EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
    ErasureProtectedEffectDispositionV1, ErasureProtectedEffectIntervalV1, EventDraft, EventStore,
    Hash, Kind, PersistedAuthorityV1, PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1,
    PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1, PipelineAdmissionPortV1,
    PipelineAttemptDraftV1, PipelineAttemptIdV1, PipelineAttemptV1, PipelineDraftBatchV1,
    PipelineEvidenceRefV1, PipelineIngressV1, PipelineObservationAnchorV1, PipelineOutcomeV1,
    PipelinePreconditionV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1,
    PrincipalRefV1, Seq, SeqRange, TentativePipelineResultV1, TimelineId, DELEGATE_ACTION_V1,
    PIPELINE_CONTRACT_VERSION_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;
use ulid::Ulid;

trait Harness:
    EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
{
}

impl<T> Harness for T where
    T: EventStore
        + PipelineAdmissionPortV1
        + PipelineAdmissionFencePublisherV1
        + AuthorityPersistencePortV1
{
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const REGISTRY: Hash = hash(7);
const POLICY: Hash = hash(9);

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(30_u128))
}

fn principal(value: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([value; 16], "local.test"))
}

fn stores() -> Vec<(&'static str, Box<dyn Harness>)> {
    vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(ok(SqliteStore::open(":memory:")))),
    ]
}

fn open_file(path: &Path) -> SqliteStore {
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    store
}

/// One grant of the shared authority Timeline.
///
/// `parent` delegates from that grant's grantee; a grant without a parent is
/// a root issued by Principal 1.
fn grant(
    id: u8,
    grantee: u8,
    parent: Option<&CapabilityGrantV1>,
    issuance: (u64, u64),
) -> CapabilityGrantV1 {
    let (issuance, epoch) = issuance;
    ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash(id),
        grantor: parent.map_or_else(
            || principal(1),
            |parent| parent.grantee().principal().clone(),
        ),
        grantee: AuthorityGranteeV1::Principal(principal(grantee)),
        trust_domain: "local.test".to_owned(),
        scope: ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
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
        })),
        valid_from_position: Seq::from_u64(issuance),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: parent.map(CapabilityGrantV1::grant_id),
        delegation_depth: u8::from(parent.is_some()),
        max_delegation_depth: 2,
        permitted_delegate_classes: vec![DelegateClassV1::Principal],
        consent_references: vec![hash(8)],
        policy_revision: POLICY,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(issuance),
        revocation_epoch: epoch,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    }))
}

/// Root `R` (1), its delegated child `C` (2), and an independent root `S` (3).
struct Grants {
    root: CapabilityGrantV1,
    child: CapabilityGrantV1,
    sibling: CapabilityGrantV1,
}

impl Grants {
    fn new() -> Self {
        let root = grant(1, 2, None, (1, 0));
        let child = grant(2, 3, Some(&root), (2, 0));
        let sibling = grant(3, 4, None, (3, 0));
        Self {
            root,
            child,
            sibling,
        }
    }

    const fn all(&self) -> [&CapabilityGrantV1; 3] {
        [&self.root, &self.child, &self.sibling]
    }
}

/// A trusted host for the shared registry; every host gets its own identity.
fn host(grants: &Grants) -> AuthorityPersistenceHostV1 {
    host_for(&grants.all())
}

fn host_for(grants: &[&CapabilityGrantV1]) -> AuthorityPersistenceHostV1 {
    let mut bindings = grants
        .iter()
        .map(|grant| ok(grant.binding_digest()))
        .collect::<Vec<_>>();
    bindings.sort_unstable();
    AuthorityPersistenceHostV1::new(&ok(AuthorityRegistrySnapshotV1::try_new(
        REGISTRY,
        vec![hash(200)],
        bindings,
        vec![],
    )))
}

fn revocation(grant: &CapabilityGrantV1, fence: u64, epoch: u64) -> CapabilityRevocationV1 {
    ok(CapabilityRevocationV1::try_from_draft(
        CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: authority_timeline(),
            fence_position: Seq::from_u64(fence),
            revocation_epoch: epoch,
            policy_revision: POLICY,
            authority_registry_digest: REGISTRY,
        },
    ))
}

/// The authority history another host holds: every grant issued in order,
/// then `revoked` revoked at fences 4, 5, … with epochs 1, 2, ….
fn history(grants: &Grants, revoked: &[&CapabilityGrantV1]) -> AuthorityPersistenceStateV1 {
    let authority = host(grants);
    let mut state = AuthorityPersistenceStateV1::new();
    for grant in grants.all() {
        ok(state.issue_grant(ok(authority.authorize_grant(grant)), grant.clone()));
    }
    for (offset, grant) in (0_u64..).zip(revoked) {
        let revocation = revocation(grant, 4 + offset, 1 + offset);
        ok(state.revoke_grant(
            ok(authority.authorize_revocation(grant, &revocation)),
            revocation,
        ));
    }
    state
}

/// The view of `leaf`'s chain resolved from another host's history.
fn view(
    grants: &Grants,
    revoked: &[&CapabilityGrantV1],
    leaf: &CapabilityGrantV1,
) -> AuthorityViewV1 {
    ok(history(grants, revoked).view(leaf.grant_id()))
}

/// The chain a store resolves for that same history.
fn resolved(
    grants: &Grants,
    revoked: &[&CapabilityGrantV1],
    leaf: &CapabilityGrantV1,
) -> PersistedAuthorityV1 {
    view(grants, revoked, leaf).authority().clone()
}

/// The complete security revisions for one persisted authority.
fn revisions(
    authority: &PersistedAuthorityV1,
    delegation: Option<Hash>,
) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority: pipeline_authority_revision_v1(authority),
            consent: hash(11),
            capability: hash(12),
            delegation: delegation.unwrap_or_else(|| pipeline_delegation_revision_v1(authority)),
            policy: hash(14),
            execution_profile: hash(15),
            erasure: pipeline_erasure_revision_v1(None),
        },
    ))
}

fn publish(store: &mut dyn Harness, timeline: TimelineId, revisions: PipelineSecurityRevisionsV1) {
    ok(store.set_pipeline_admission_fence(
        timeline,
        ok(PipelineAdmissionFenceV1::try_new(
            hash(2),
            revisions,
            None,
            100,
        )),
    ));
}

fn basis(
    timeline: TimelineId,
    key: u8,
    head: u64,
    revisions: PipelineSecurityRevisionsV1,
) -> PipelineAdmissionBasisV1 {
    ok(PipelineAdmissionBasisV1::try_from_draft(
        PipelineAdmissionBasisDraftV1 {
            contract_version: PIPELINE_CONTRACT_VERSION_V1,
            attempt: Some(ok(PipelineAttemptV1::try_from_draft(
                PipelineAttemptDraftV1 {
                    contract_version: PIPELINE_CONTRACT_VERSION_V1,
                    attempt_id: Some(ok(PipelineAttemptIdV1::try_new([key; 16]))),
                    ingress: Some(PipelineIngressV1::HumanProposedAction),
                    observation: Some(ok(PipelineObservationAnchorV1::try_new(
                        timeline,
                        Seq::from_u64(head),
                        hash(61),
                    ))),
                    idempotency: Some(AppendIdentity::new(
                        AppendDedupKey::from_keyed_hash([key; 32]),
                        AppendDedupScope::from_keyed_hash([62; 32]),
                    )),
                },
            ))),
            tentative_result: Some(TentativePipelineResultV1::HumanDomainApproval(ok(
                PipelineEvidenceRefV1::try_new(hash(60)),
            ))),
            precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(
                head,
            ))),
            security_revisions: Some(revisions),
            batch: Some(ok(PipelineDraftBatchV1::try_new(vec![EventDraft::new(
                entity(5),
                Kind::new("world.action"),
                CanonicalBytes::from_vec(vec![key]),
            )]))),
        },
    ))
}

fn event_count(store: &dyn Harness, timeline: TimelineId) -> usize {
    ok(store.read(timeline, SeqRange::all())).len()
}

const fn is_commit(outcome: &Result<PipelineOutcomeV1, CoreError>) -> bool {
    matches!(outcome, Ok(PipelineOutcomeV1::Committed(_)))
}

#[test]
fn a_view_replays_its_revocation_records_and_their_ancestors_idempotently() {
    let grants = Grants::new();
    // The sibling's view names a revocation of the child, so it also carries
    // the child and the child's unrevoked parent that the epoch depends on.
    let learned = view(&grants, &[&grants.child], &grants.sibling);
    assert_eq!(learned.authority().revocation_epoch(), 1);
    assert_eq!(
        learned.authority().revocations(),
        [revocation(&grants.child, 4, 1)]
    );
    for (name, mut store) in stores() {
        let authority = host(&grants);
        let persisted = ok(authority.persist_authority(store.as_mut(), &learned));
        assert_eq!(&persisted, learned.authority(), "{name}");
        // An exact retry and a record the store already holds are unchanged.
        assert_eq!(
            &ok(authority.persist_authority(store.as_mut(), &learned)),
            learned.authority(),
            "{name}"
        );
        let child = ok(store.load_authority(grants.child.grant_id()));
        assert_eq!(
            child,
            resolved(&grants, &[&grants.child], &grants.child),
            "{name}"
        );
        assert_eq!(
            child.chain().grants()[1].revocation_fence(),
            Some(Seq::from_u64(4)),
            "{name}"
        );
    }
}

#[test]
fn a_grant_issued_after_a_revocation_replays_after_it_in_timeline_order() {
    let grants = Grants::new();
    // A root issued at fence 5, after the child's revocation advanced the
    // Timeline to epoch 1, is persistable only after that revocation.
    let late = grant(4, 5, None, (5, 1));
    let [root, child, sibling] = grants.all();
    let authority = host_for(&[root, child, sibling, &late]);
    let mut state = history(&grants, &[&grants.child]);
    ok(state.issue_grant(ok(authority.authorize_grant(&late)), late.clone()));
    let late_view = ok(state.view(late.grant_id()));
    assert_eq!(late_view.authority().revocations().len(), 1);
    for (name, mut store) in stores() {
        assert_eq!(
            &ok(authority.persist_authority(store.as_mut(), &late_view)),
            late_view.authority(),
            "{name}"
        );
    }
}

#[test]
fn a_view_another_host_cannot_attest_or_that_conflicts_fails_closed() {
    let grants = Grants::new();
    let revoked = view(&grants, &[&grants.root], &grants.root);
    let stores = stores().into_iter().zip(stores()).zip(stores());
    for (((name, mut unattested), (_, mut bound)), (_, mut conflicting)) in stores {
        // A host whose registry attests only the root cannot persist a view
        // whose revocation history names a grant outside its registry.
        let root_only = AuthorityPersistenceHostV1::new(&ok(AuthorityRegistrySnapshotV1::try_new(
            REGISTRY,
            vec![hash(200)],
            vec![ok(grants.root.binding_digest())],
            vec![],
        )));
        assert_eq!(
            root_only.persist_authority(
                unattested.as_mut(),
                &view(&grants, &[&grants.child], &grants.sibling)
            ),
            Err(AuthorityPersistenceErrorV1::Unavailable),
            "{name}"
        );
        // The failed replay leaves its valid Timeline-Order prefix: the root
        // grant committed before the unattested child was refused.
        let prefix = ok(unattested.load_authority(grants.root.grant_id()));
        assert_eq!(prefix.head_position(), Seq::from_u64(1), "{name}");
        assert_eq!(prefix.chain().grants().len(), 1, "{name}");
        assert!(
            unattested.load_authority(grants.child.grant_id()).is_err(),
            "{name}"
        );

        // A store bound to another host refuses the whole view.
        ok(bound.bind_authority_persistence(host(&grants).persistence_binding()));
        assert_eq!(
            host(&grants).persist_authority(bound.as_mut(), &revoked),
            Err(AuthorityPersistenceErrorV1::Unavailable),
            "{name}"
        );

        // A store that already holds a different revocation at that epoch
        // conflicts with the view instead of merging two histories.
        let authority = host(&grants);
        let sibling_revoked = view(&grants, &[&grants.sibling], &grants.sibling);
        ok(authority.persist_authority(conflicting.as_mut(), &sibling_revoked));
        assert_eq!(
            authority.persist_authority(conflicting.as_mut(), &revoked),
            Err(AuthorityPersistenceErrorV1::StaleEpoch),
            "{name}"
        );
    }
}

#[test]
fn a_partially_diverged_view_fails_closed_after_its_shared_prefix() {
    let grants = Grants::new();
    for (name, mut store) in stores() {
        let authority = host(&grants);
        // The store's history revoked the sibling at epoch 1; the view's
        // history shares every grant but revoked the child at that epoch.
        let stored = resolved(&grants, &[&grants.sibling], &grants.child);
        assert_eq!(
            ok(authority.persist_authority(
                store.as_mut(),
                &view(&grants, &[&grants.sibling], &grants.child)
            )),
            stored,
            "{name}"
        );
        assert_eq!(
            authority.persist_authority(
                store.as_mut(),
                &view(&grants, &[&grants.child], &grants.sibling)
            ),
            Err(AuthorityPersistenceErrorV1::StaleEpoch),
            "{name}"
        );
        // Nothing of the diverged history was merged.
        assert_eq!(
            ok(store.load_authority(grants.child.grant_id())),
            stored,
            "{name}"
        );
    }
}

#[test]
fn equal_epoch_revocation_states_have_distinct_delegation_revisions() {
    let grants = Grants::new();
    let unrevoked = resolved(&grants, &[], &grants.sibling);
    let child_revoked = resolved(&grants, &[&grants.child], &grants.sibling);
    let root_revoked = resolved(&grants, &[&grants.root], &grants.sibling);
    assert_eq!(
        child_revoked.revocation_epoch(),
        root_revoked.revocation_epoch()
    );
    // The authority revision names only the chain and its epoch, so it cannot
    // tell which grant was revoked; the delegation revision binds the record.
    assert_eq!(
        pipeline_authority_revision_v1(&child_revoked),
        pipeline_authority_revision_v1(&root_revoked)
    );
    let delegation =
        [&unrevoked, &child_revoked, &root_revoked].map(pipeline_delegation_revision_v1);
    assert_ne!(delegation[0], delegation[1]);
    assert_ne!(delegation[0], delegation[2]);
    assert_ne!(delegation[1], delegation[2]);

    // Delegation edges are bound too: a chain differs from its own prefix.
    assert_ne!(
        pipeline_delegation_revision_v1(&resolved(&grants, &[], &grants.root)),
        pipeline_delegation_revision_v1(&resolved(&grants, &[], &grants.child))
    );
}

#[test]
fn a_learned_revocation_is_persisted_and_stales_or_revokes_the_basis_at_commit() {
    let grants = Grants::new();
    for (name, mut store) in stores() {
        let timeline = ok(store.create_timeline("revocation-records")).id();
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
        let authority = host(&grants);
        let current =
            ok(authority.persist_authority(store.as_mut(), &view(&grants, &[], &grants.child)));
        let published = revisions(&current, None);
        publish(store.as_mut(), timeline, published);

        // A fence and basis that agree on a delegation revision the persisted
        // chain does not have are rejected.
        let forged = revisions(&current, Some(hash(99)));
        publish(store.as_mut(), timeline, forged);
        assert_eq!(
            ok(store.admit_pipeline_batch(&basis(timeline, 1, 0, forged))),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        publish(store.as_mut(), timeline, published);

        // The host learns that the sibling was revoked. Persisting that view
        // moves the persisted delegation revision, so the basis published
        // before it is stale even though the chain itself is not revoked.
        let learned = ok(authority.persist_authority(
            store.as_mut(),
            &view(&grants, &[&grants.sibling], &grants.child),
        ));
        assert_eq!(learned.revocations().len(), 1, "{name}");
        assert_eq!(
            ok(store.admit_pipeline_batch(&basis(timeline, 2, 0, published))),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        let refreshed = revisions(&learned, None);
        assert_ne!(refreshed, published, "{name}");
        publish(store.as_mut(), timeline, refreshed);
        assert!(
            is_commit(&store.admit_pipeline_batch(&basis(timeline, 3, 0, refreshed))),
            "{name}"
        );

        // A revocation of the chain's parent is composed at the store, not by
        // any in-memory recheck of the host.
        ok(authority.persist_authority(
            store.as_mut(),
            &view(&grants, &[&grants.sibling, &grants.root], &grants.child),
        ));
        assert_eq!(
            ok(store.admit_pipeline_batch(&basis(timeline, 4, 1, refreshed))),
            PipelineOutcomeV1::AuthorityRevoked,
            "{name}"
        );
        assert_eq!(event_count(store.as_ref(), timeline), 1, "{name}");
    }
}

#[test]
fn sqlite_hosts_racing_a_revocation_never_commit_after_it_is_persisted() {
    let grants = Grants::new();
    let directory = ok(tempdir());
    let path = directory.path().join("revocation-race.db");
    let (timeline, stale) = {
        let mut store = open_file(&path);
        let timeline = ok(store.create_timeline("revocation-race")).id();
        let current =
            ok(host(&grants).persist_authority(&mut store, &view(&grants, &[], &grants.child)));
        let published = revisions(&current, None);
        publish(&mut store, timeline, published);
        (timeline, published)
    };

    // One host admits on its own connection while another host, on another
    // connection, persists a revocation of the chain's root.
    let revoked = view(&grants, &[&grants.root], &grants.child);
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
        let other = host(&grants);
        let mut store = open_file(&path);
        std::thread::spawn(move || {
            barrier.wait();
            other.persist_authority(&mut store, &revoked)
        })
    };
    let admitted = ok(admitting.join());
    let persisted = ok(revoking.join());
    // Only a host that lost on lock contention (its store transaction could
    // not begin) persists the same view again; any other failure is a defect.
    let persisted = persisted.or_else(|error| {
        assert_eq!(error, AuthorityPersistenceErrorV1::Unavailable);
        host(&grants).persist_authority(&mut open_file(&path), &revoked)
    });
    assert!(ok(persisted).chain().grants()[0]
        .revocation_fence()
        .is_some());
    let before = usize::from(is_commit(&admitted));
    assert_eq!(event_count(&open_file(&path), timeline), before);

    // Once the revocation is persisted, a host that persists its own stale
    // view loads the revoked chain, and neither its connection nor a fresh one
    // commits on the basis published before the revocation.
    let mut open = open_file(&path);
    let reloaded =
        ok(host(&grants).persist_authority(&mut open, &view(&grants, &[], &grants.child)));
    assert_eq!(&reloaded, revoked.authority());
    assert_eq!(
        ok(open.admit_pipeline_batch(&basis(timeline, 2, 0, stale))),
        PipelineOutcomeV1::AuthorityRevoked
    );
    assert_eq!(
        ok(open_file(&path).admit_pipeline_batch(&basis(timeline, 3, 0, stale))),
        PipelineOutcomeV1::AuthorityRevoked
    );
    assert_eq!(event_count(&open_file(&path), timeline), before);
}

fn data_version(connection: &rusqlite::Connection) -> i64 {
    ok(connection.query_row("PRAGMA data_version", [], |row| row.get(0)))
}

/// Make every later authority-state write on the file abort.
fn reject_authority_state_writes(path: &Path) {
    ok(ok(rusqlite::Connection::open(path)).execute_batch(
        "CREATE TRIGGER reject_authority_insert BEFORE INSERT ON authority_state
         BEGIN SELECT RAISE(ABORT, 'authority state written'); END;
         CREATE TRIGGER reject_authority_update BEFORE UPDATE ON authority_state
         BEGIN SELECT RAISE(ABORT, 'authority state written'); END;",
    ));
}

#[test]
fn every_record_of_a_persisted_view_replays_unchanged_on_both_stores() {
    let grants = Grants::new();
    let learned = view(&grants, &[&grants.child], &grants.sibling);
    let revoked = revocation(&grants.child, 4, 1);
    for (name, mut store) in stores() {
        let authority = host(&grants);
        let persisted = ok(authority.persist_authority(store.as_mut(), &learned));
        for grant in grants.all() {
            assert_eq!(
                ok(store.issue_capability_grant(ok(authority.authorize_grant(grant)), grant)),
                AuthorityCommitOutcomeV1::Unchanged,
                "{name}"
            );
        }
        assert_eq!(
            ok(store.revoke_capability_grant(
                ok(authority.authorize_revocation(&grants.child, &revoked)),
                &revoked
            )),
            AuthorityCommitOutcomeV1::Unchanged,
            "{name}"
        );
        assert_eq!(
            ok(store.load_authority(grants.sibling.grant_id())),
            persisted,
            "{name}"
        );
    }
}

#[test]
fn an_idempotent_sqlite_replay_writes_no_authority_state_and_keeps_other_connections_open() {
    let grants = Grants::new();
    let directory = ok(tempdir());
    let path = directory.path().join("unchanged-replay.db");
    let learned = view(&grants, &[&grants.sibling], &grants.child);
    let (timeline, published) = {
        let mut store = open_file(&path);
        let timeline = ok(store.create_timeline("unchanged-replay")).id();
        let persisted = ok(host(&grants).persist_authority(&mut store, &learned));
        let published = revisions(&persisted, None);
        publish(&mut store, timeline, published);
        (timeline, published)
    };
    reject_authority_state_writes(&path);
    let mut replaying = open_file(&path);
    let observer = ok(rusqlite::Connection::open(&path));
    let mut admitting = open_file(&path);
    let before = data_version(&observer);

    // Another host replays every record of a view the file already holds.
    // Any authority-state write would abort, so success proves none ran.
    assert_eq!(
        &ok(host(&grants).persist_authority(&mut replaying, &learned)),
        learned.authority()
    );
    // No other connection observes a commit, so a store whose erasure gate is
    // bound to the file's data version keeps admitting instead of failing
    // closed.
    assert_eq!(data_version(&observer), before);
    assert!(is_commit(
        &admitting.admit_pipeline_batch(&basis(timeline, 1, 0, published))
    ));
}

#[test]
fn an_unchanged_sqlite_replay_needs_no_write_lock_but_a_new_record_does() {
    let grants = Grants::new();
    let directory = ok(tempdir());
    let path = directory.path().join("replay-lock.db");
    let current = view(&grants, &[], &grants.child);
    let learned = view(&grants, &[&grants.sibling], &grants.child);
    let authority = host(&grants);
    let mut store = open_file(&path);
    let persisted = ok(authority.persist_authority(&mut store, &current));

    let writer = ok(rusqlite::Connection::open(&path));
    ok(writer.execute_batch("BEGIN IMMEDIATE"));
    assert_eq!(
        ok(authority.persist_authority(&mut store, &current)),
        persisted
    );
    // A record the file lacks still waits for the write lock and fails closed
    // when it cannot take it.
    assert_eq!(
        authority.persist_authority(&mut store, &learned),
        Err(AuthorityPersistenceErrorV1::Unavailable)
    );
    ok(writer.execute_batch("ROLLBACK"));
    assert_eq!(
        &ok(authority.persist_authority(&mut store, &learned)),
        learned.authority()
    );
}

#[test]
fn a_sqlite_store_inside_a_transaction_still_refuses_an_unchanged_replay() {
    let grants = Grants::new();
    let directory = ok(tempdir());
    let path = directory.path().join("replay-in-transaction.db");
    let current = view(&grants, &[], &grants.child);
    let authority = host(&grants);
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    let persisted = ok(authority.persist_authority(&mut store, &current));

    let interval = ok(store.begin_protected_effect_interval());
    assert_eq!(interval, ErasureProtectedEffectIntervalV1::Owned);
    assert_eq!(
        authority.persist_authority(&mut store, &current),
        Err(AuthorityPersistenceErrorV1::Unavailable)
    );
    ok(store
        .finish_protected_effect_interval(interval, ErasureProtectedEffectDispositionV1::Rollback));
    assert_eq!(
        ok(authority.persist_authority(&mut store, &current)),
        persisted
    );
}
