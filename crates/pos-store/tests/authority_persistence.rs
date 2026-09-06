use std::sync::{Arc, Barrier};

use ciborium::Value;
use pos_core::{
    AuthorityCommitOutcomeV1, AuthorityGranteeV1, AuthorityPersistenceErrorV1,
    AuthorityPersistencePortV1, AuthorityPersistenceStateV1, AuthorityRoleV1,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, DelegateClassV1, EntityId, Hash, PrincipalRefV1,
    Seq, TimelineId, DELEGATE_ACTION_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore, EventStore};
use tempfile::tempdir;
use ulid::Ulid;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

fn principal(value: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([value; 16], "local.test"))
}

fn scope(actions: &[&str], actors: Vec<EntityId>) -> CapabilityScopeV1 {
    ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["profile".to_owned()],
        actions: actions.iter().map(|value| (*value).to_owned()).collect(),
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: actors,
        subject_ids: vec![entity(50)],
        participant_ids: vec![entity(20)],
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 10,
        budget: 100,
        environment_constraints: vec!["local-only".to_owned()],
    }))
}

fn root_grant() -> CapabilityGrantV1 {
    root_grant_at(1)
}

fn root_grant_at(issuance_position: u64) -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash(1),
        grantor: principal(1),
        grantee: AuthorityGranteeV1::Principal(principal(2)),
        trust_domain: "local.test".to_owned(),
        scope: scope(&[DELEGATE_ACTION_V1, "read"], vec![entity(10), entity(11)]),
        valid_from_position: Seq::from_u64(issuance_position),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 2,
        permitted_delegate_classes: vec![DelegateClassV1::Principal],
        consent_references: vec![hash(8)],
        policy_revision: hash(9),
        issuance_timeline: timeline(30),
        issuance_seq: Seq::from_u64(issuance_position),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }))
}

fn child_grant() -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash(2),
        grantor: principal(2),
        grantee: AuthorityGranteeV1::Principal(principal(3)),
        trust_domain: "local.test".to_owned(),
        scope: scope(&["read"], vec![entity(10)]),
        valid_from_position: Seq::from_u64(2),
        valid_until_position: Seq::from_u64(90),
        parent_grant_id: Some(hash(1)),
        delegation_depth: 1,
        max_delegation_depth: 1,
        permitted_delegate_classes: vec![],
        consent_references: vec![hash(8)],
        policy_revision: hash(9),
        issuance_timeline: timeline(30),
        issuance_seq: Seq::from_u64(2),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }))
}

fn revocation() -> CapabilityRevocationV1 {
    revocation_at(3)
}

fn revocation_at(fence_position: u64) -> CapabilityRevocationV1 {
    ok(CapabilityRevocationV1::try_from_draft(
        CapabilityRevocationDraftV1 {
            grant_id: hash(1),
            authority_timeline: timeline(30),
            fence_position: Seq::from_u64(fence_position),
            revocation_epoch: 1,
            policy_revision: hash(9),
            authority_registry_digest: hash(7),
        },
    ))
}

fn exercise_port(
    store: &mut dyn AuthorityPersistencePortV1,
) -> Result<Vec<AuthorityCommitOutcomeV1>, AuthorityPersistenceErrorV1> {
    let root = root_grant();
    let child = child_grant();
    let revocation = revocation();
    let outcomes = vec![
        store.issue_capability_grant(&root)?,
        store.issue_capability_grant(&root)?,
        store.issue_capability_grant(&child)?,
        store.revoke_capability_grant(&revocation)?,
        store.revoke_capability_grant(&revocation)?,
    ];
    let resolved = store.load_authority(hash(2))?;
    assert_eq!(resolved.revocation_epoch(), 1);
    assert_eq!(resolved.head_position(), Seq::from_u64(3));
    assert_eq!(resolved.chain().grants().len(), 2);
    assert_eq!(
        resolved.chain().grants()[0].revocation_fence(),
        Some(Seq::from_u64(3))
    );
    assert_eq!(resolved.chain().grants()[1].revocation_fence(), None);
    Ok(outcomes)
}

#[test]
fn memory_and_sqlite_have_identical_public_authority_contracts() {
    let mut memory = MemoryStore::new();
    let mut sqlite = ok(SqliteStore::open_in_memory());
    let expected = vec![
        AuthorityCommitOutcomeV1::Committed,
        AuthorityCommitOutcomeV1::Unchanged,
        AuthorityCommitOutcomeV1::Committed,
        AuthorityCommitOutcomeV1::Committed,
        AuthorityCommitOutcomeV1::Unchanged,
    ];
    assert_eq!(ok(exercise_port(&mut memory)), expected);
    assert_eq!(ok(exercise_port(&mut sqlite)), expected);
}

#[test]
fn authority_state_round_trip_preserves_versions_links_and_fences() {
    let mut state = AuthorityPersistenceStateV1::new();
    assert_eq!(
        ok(state.issue_grant(root_grant())),
        AuthorityCommitOutcomeV1::Committed
    );
    assert_eq!(
        ok(state.issue_grant(child_grant())),
        AuthorityCommitOutcomeV1::Committed
    );
    assert_eq!(
        ok(state.revoke_grant(revocation())),
        AuthorityCommitOutcomeV1::Committed
    );
    let bytes = ok(state.to_persistence_bytes());
    let restored = ok(AuthorityPersistenceStateV1::from_persistence_bytes(&bytes));
    assert_eq!(restored, state);
    assert_eq!(restored.grants().count(), 2);
    assert_eq!(restored.revocations().count(), 1);
}

#[test]
fn conflicts_stale_epochs_and_timeline_reordering_fail_closed() {
    let mut state = AuthorityPersistenceStateV1::new();
    assert_eq!(
        state.issue_grant(child_grant()),
        Err(AuthorityPersistenceErrorV1::Conflict)
    );
    ok(state.issue_grant(root_grant()));

    let mut conflict = child_grant();
    let mut draft = CapabilityGrantDraftV1 {
        grant_id: conflict.grant_id(),
        grantor: conflict.grantor().clone(),
        grantee: conflict.grantee().clone(),
        trust_domain: conflict.trust_domain().to_owned(),
        scope: conflict.scope().clone(),
        valid_from_position: conflict.valid_from_position(),
        valid_until_position: conflict.valid_until_position(),
        parent_grant_id: conflict.parent_grant_id(),
        delegation_depth: conflict.delegation_depth(),
        max_delegation_depth: conflict.max_delegation_depth(),
        permitted_delegate_classes: conflict.permitted_delegate_classes().to_vec(),
        consent_references: conflict.consent_references().to_vec(),
        policy_revision: conflict.policy_revision(),
        issuance_timeline: conflict.issuance_timeline(),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: conflict.revocation_epoch(),
        revocation_fence: conflict.revocation_fence(),
        authority_registry_digest: conflict.authority_registry_digest(),
    };
    conflict = ok(CapabilityGrantV1::try_from_draft(draft.clone()));
    assert_eq!(
        state.issue_grant(conflict),
        Err(AuthorityPersistenceErrorV1::TimelineOrder)
    );
    draft.issuance_seq = Seq::from_u64(2);
    draft.revocation_epoch = 1;
    assert_eq!(
        state.issue_grant(ok(CapabilityGrantV1::try_from_draft(draft))),
        Err(AuthorityPersistenceErrorV1::StaleEpoch)
    );

    ok(state.issue_grant(child_grant()));
    ok(state.revoke_grant(revocation()));
    let mut conflicting_revocation = CapabilityRevocationDraftV1 {
        grant_id: hash(1),
        authority_timeline: timeline(30),
        fence_position: Seq::from_u64(4),
        revocation_epoch: 2,
        policy_revision: hash(9),
        authority_registry_digest: hash(7),
    };
    assert_eq!(
        state.revoke_grant(ok(CapabilityRevocationV1::try_from_draft(
            conflicting_revocation
        ))),
        Err(AuthorityPersistenceErrorV1::Conflict)
    );
    conflicting_revocation.grant_id = hash(2);
    conflicting_revocation.revocation_epoch = 1;
    assert_eq!(
        state.revoke_grant(ok(CapabilityRevocationV1::try_from_draft(
            conflicting_revocation
        ))),
        Err(AuthorityPersistenceErrorV1::StaleEpoch)
    );
}

#[test]
fn sqlite_reopen_cannot_reactivate_revoked_authority() {
    let directory = ok(tempdir());
    let path = directory.path().join("authority.db");
    {
        let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
        ok(exercise_port(&mut store));
    }
    let reopened = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    let resolved = ok(reopened.load_authority(hash(2)));
    assert_eq!(resolved.revocation_epoch(), 1);
    assert_eq!(
        resolved.chain().grants()[1].valid_until_position(),
        Seq::from_u64(90)
    );
    assert_eq!(
        resolved.chain().grants()[0].revocation_fence(),
        Some(Seq::from_u64(3))
    );
}

#[test]
fn concurrent_sqlite_revocation_is_serialized_and_idempotent() {
    let directory = ok(tempdir());
    let path = directory.path().join("concurrent.db");
    {
        let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
        ok(store.issue_capability_grant(&root_grant()));
    }
    let barrier = Arc::new(Barrier::new(2));
    let handles = [(), ()].map(|()| {
        let barrier = Arc::clone(&barrier);
        let path = path.clone();
        std::thread::spawn(move || {
            let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
            barrier.wait();
            store.revoke_capability_grant(&revocation())
        })
    });
    let mut outcomes = handles
        .into_iter()
        .map(|handle| ok(ok(handle.join())))
        .collect::<Vec<_>>();
    outcomes.sort_by_key(|outcome| match outcome {
        AuthorityCommitOutcomeV1::Committed => 0,
        AuthorityCommitOutcomeV1::Unchanged => 1,
    });
    assert_eq!(
        outcomes,
        vec![
            AuthorityCommitOutcomeV1::Committed,
            AuthorityCommitOutcomeV1::Unchanged
        ]
    );
}

#[test]
fn sqlite_migration_preserves_existing_timelines_and_adds_no_authority() {
    let directory = ok(tempdir());
    let path = directory.path().join("migration.db");
    let timeline_id = {
        let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
        ok(store.create_timeline("existing")).id()
    };
    {
        let connection = ok(rusqlite::Connection::open(&path));
        ok(connection.execute_batch("DROP TABLE authority_state"));
    }
    let migrated = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    assert_eq!(
        ok(migrated.get_timeline(timeline_id)).map(|timeline| timeline.id()),
        Some(timeline_id)
    );
    assert_eq!(
        migrated.load_authority(hash(1)),
        Err(AuthorityPersistenceErrorV1::Conflict)
    );
}

#[test]
fn malformed_persisted_authority_fails_reopen() {
    let directory = ok(tempdir());
    let path = directory.path().join("malformed.db");
    {
        let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
        ok(store.issue_capability_grant(&root_grant()));
    }
    {
        let connection = ok(rusqlite::Connection::open(&path));
        ok(connection.execute(
            "UPDATE authority_state SET state_cbor = X'00' WHERE singleton = 1",
            [],
        ));
    }
    assert!(SqliteStore::open(path.to_str().unwrap_or_default()).is_err());
}

#[test]
fn failed_sqlite_authority_write_rolls_back_without_partial_state() {
    let directory = ok(tempdir());
    let path = directory.path().join("rollback.db");
    {
        let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
        ok(exercise_port(&mut store));
    }
    {
        let connection = ok(rusqlite::Connection::open(&path));
        ok(connection.execute_batch(
            "CREATE TRIGGER reject_authority_update
             BEFORE UPDATE ON authority_state
             BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
        ));
    }
    {
        let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
        assert_eq!(
            store.issue_capability_grant(&root_grant()),
            Err(AuthorityPersistenceErrorV1::Unavailable)
        );
    }
    {
        let connection = ok(rusqlite::Connection::open(&path));
        ok(connection.execute_batch("DROP TRIGGER reject_authority_update"));
    }
    let reopened = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    let retained = ok(reopened.load_authority(hash(2)));
    assert_eq!(retained.revocation_epoch(), 1);
    assert_eq!(
        retained.chain().grants()[0].revocation_fence(),
        Some(Seq::from_u64(3))
    );
}

#[test]
fn revocation_codec_is_canonical_and_rejects_zero_fields() {
    let value = revocation();
    assert_eq!(
        ok(CapabilityRevocationV1::decode(&ok(value.encode()))),
        value
    );
    let mut trailing = ok(value.encode()).as_slice().to_vec();
    trailing.push(0);
    assert_eq!(
        CapabilityRevocationV1::decode(&pos_core::CanonicalBytes::from_vec(trailing)),
        Err(AuthorityPersistenceErrorV1::InvalidRecord)
    );
    assert_eq!(
        CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: Hash::zero(),
            authority_timeline: timeline(30),
            fence_position: Seq::ZERO,
            revocation_epoch: 0,
            policy_revision: Hash::zero(),
            authority_registry_digest: Hash::zero(),
        }),
        Err(AuthorityPersistenceErrorV1::InvalidRecord)
    );
}

#[test]
fn authority_state_rejects_a_backdated_persisted_revocation() {
    let mut state = AuthorityPersistenceStateV1::new();
    ok(state.issue_grant(root_grant_at(5)));
    ok(state.revoke_grant(revocation_at(6)));
    let encoded = ok(state.to_persistence_bytes());
    let mut outer: Value = ok(ciborium::de::from_reader(encoded.as_slice()));
    let Value::Array(outer_fields) = &mut outer else {
        std::panic::resume_unwind(Box::new("APS1 fixture must be an array"));
    };
    let Value::Array(revocations) = &mut outer_fields[3] else {
        std::panic::resume_unwind(Box::new("APS1 revocations must be an array"));
    };
    let Value::Bytes(revocation_bytes) = &mut revocations[0] else {
        std::panic::resume_unwind(Box::new("APS1 revocation must contain canonical bytes"));
    };
    let mut revocation_value: Value = ok(ciborium::de::from_reader(revocation_bytes.as_slice()));
    let Value::Array(revocation_fields) = &mut revocation_value else {
        std::panic::resume_unwind(Box::new("CRF1 fixture must be an array"));
    };
    revocation_fields[4] = Value::Integer(2_u64.into());
    revocation_bytes.clear();
    ok(ciborium::ser::into_writer(
        &revocation_value,
        &mut *revocation_bytes,
    ));
    let mut backdated = Vec::new();
    ok(ciborium::ser::into_writer(&outer, &mut backdated));

    assert_eq!(
        AuthorityPersistenceStateV1::from_persistence_bytes(&backdated),
        Err(AuthorityPersistenceErrorV1::InvalidRecord)
    );
}
