use pos_core::store::EventStore;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    CreateForkAdmittedRequestV1, ForkAdmissionAuthorityPortV1, ForkAdmissionErrorV1, Hash,
    OwnerIdV1, PrincipalOwnerTrustV1, PrincipalRefV1, TimelineId, WallTime,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn authenticated() -> Result<AuthenticatedPrincipalResultV1, Box<dyn std::error::Error>> {
    Ok(AuthenticatedPrincipalResultV1::try_from_draft(
        AuthenticatedPrincipalDraftV1 {
            principal: PrincipalRefV1::try_new([7; 16], "fork.test")?,
            adapter_id: "host.adapter".to_owned(),
            assurance: AssuranceLevelV1::try_new(2)?,
            issued_at: WallTime::from_micros(10),
            expires_at: WallTime::from_micros(100),
            binding_digest: Hash::from_bytes([9; 32]),
        },
    )?)
}

fn trust(
    authenticated: &AuthenticatedPrincipalResultV1,
) -> Result<PrincipalOwnerTrustV1, ForkAdmissionErrorV1> {
    PrincipalOwnerTrustV1::new(
        "host.adapter".to_owned(),
        2,
        vec![authenticated.registry_binding_digest()],
    )
}

fn request(
    parent: TimelineId,
    authenticated: AuthenticatedPrincipalResultV1,
) -> CreateForkAdmittedRequestV1 {
    CreateForkAdmittedRequestV1 {
        operation_id: Hash::from_bytes([3; 32]),
        authenticated,
        parent_timeline_id: parent,
        completed_fold_cursor: 0,
        post_fold_tick_boundary: 0,
        room_revision_descriptor_hash: Hash::from_bytes([4; 32]),
        plugin_composition_hash: Hash::from_bytes([5; 32]),
        attribution_required: true,
        child_name: "admitted-child".to_owned(),
    }
}

fn assert_contract(store: &mut dyn ForkAdmissionAuthorityPortV1, parent: TimelineId) -> TestResult {
    let authenticated = authenticated()?;
    store.bind_principal_owner_trust(trust(&authenticated)?)?;
    let binding = store.commit_local_binding(
        Hash::from_bytes([1; 32]),
        &authenticated,
        OwnerIdV1::new("creator")?,
        WallTime::from_micros(20),
    )?;
    let admission = request(parent, authenticated.clone());
    let receipt = store.create_fork_admitted(&admission, WallTime::from_micros(20))?;
    assert_eq!(
        store.create_fork_admitted(&admission, WallTime::from_micros(20))?,
        receipt
    );
    assert_eq!(
        store
            .read_fork_admission(receipt.child_id)?
            .expect("FAR1")
            .input()
            .principal_owner_binding_digest,
        binding.digest()
    );
    let mut conflict = admission;
    conflict.child_name = "other".to_owned();
    assert_eq!(
        store.create_fork_admitted(&conflict, WallTime::from_micros(20)),
        Err(ForkAdmissionErrorV1::Conflict)
    );
    assert_eq!(
        store.commit_local_binding(
            Hash::from_bytes([2; 32]),
            &authenticated,
            OwnerIdV1::new("other")?,
            WallTime::from_micros(20)
        ),
        Err(ForkAdmissionErrorV1::PrincipalOwnerConflict)
    );
    Ok(())
}

#[test]
fn memory_fork_admission_is_atomic_and_idempotent_at_the_public_port() -> TestResult {
    let mut store = MemoryStore::new();
    let parent = store.create_timeline("parent")?;
    assert_contract(&mut store, parent.id())
}

#[test]
fn sqlite_fork_admission_is_atomic_and_idempotent_at_the_public_port() -> TestResult {
    let mut store = SqliteStore::open_in_memory()?;
    let parent = store.create_timeline("parent")?;
    assert_contract(&mut store, parent.id())
}

#[test]
fn admission_rejects_a_parent_head_outside_the_completed_fold_boundary() -> TestResult {
    let mut store = MemoryStore::new();
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    store.bind_principal_owner_trust(trust(&authenticated)?)?;
    store.commit_local_binding(
        Hash::from_bytes([1; 32]),
        &authenticated,
        OwnerIdV1::new("creator")?,
        WallTime::from_micros(20),
    )?;
    let mut request = request(parent.id(), authenticated);
    request.completed_fold_cursor = 1;
    request.post_fold_tick_boundary = 1;
    assert_eq!(
        store.create_fork_admitted(&request, WallTime::from_micros(20)),
        Err(ForkAdmissionErrorV1::StaleFoldBoundary)
    );
    assert_eq!(store.list_timelines()?.len(), 1);
    Ok(())
}
