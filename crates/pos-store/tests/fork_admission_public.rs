use pos_core::store::EventStore;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    CreateForkAdmittedRequestV1, ForkAdmissionAuthorityPortV1, ForkAdmissionErrorV1,
    ForkAdmissionHostV1, Hash, LocalPrincipalOwnerBindingPermitV1, OwnerIdV1, PrincipalRefV1,
    TimelineId, WallTime,
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

fn host(
    authenticated: &AuthenticatedPrincipalResultV1,
) -> Result<ForkAdmissionHostV1, ForkAdmissionErrorV1> {
    ForkAdmissionHostV1::new(
        "host.adapter".to_owned(),
        2,
        vec![authenticated.registry_binding_digest()],
    )
}

fn binding_permit(
    host: &ForkAdmissionHostV1,
    authenticated: &AuthenticatedPrincipalResultV1,
    operation_id: Hash,
    owner: OwnerIdV1,
) -> Result<LocalPrincipalOwnerBindingPermitV1, ForkAdmissionErrorV1> {
    host.permit_local_binding(
        operation_id,
        authenticated,
        owner,
        WallTime::from_micros(20),
    )
}

fn request(
    host: &ForkAdmissionHostV1,
    parent: TimelineId,
    authenticated: &AuthenticatedPrincipalResultV1,
) -> Result<CreateForkAdmittedRequestV1, ForkAdmissionErrorV1> {
    host.permit_fork_creation(
        authenticated,
        Hash::from_bytes([3; 32]),
        parent,
        0,
        0,
        Hash::from_bytes([4; 32]),
        Hash::from_bytes([5; 32]),
        true,
        "admitted-child".to_owned(),
        WallTime::from_micros(20),
    )
}

fn request_at_cut(
    host: &ForkAdmissionHostV1,
    parent: TimelineId,
    authenticated: &AuthenticatedPrincipalResultV1,
    completed_fold_cursor: u64,
) -> Result<CreateForkAdmittedRequestV1, ForkAdmissionErrorV1> {
    host.permit_fork_creation(
        authenticated,
        Hash::from_bytes([3; 32]),
        parent,
        completed_fold_cursor,
        completed_fold_cursor,
        Hash::from_bytes([4; 32]),
        Hash::from_bytes([5; 32]),
        true,
        "admitted-child".to_owned(),
        WallTime::from_micros(20),
    )
}

fn assert_contract<S: ForkAdmissionAuthorityPortV1 + EventStore>(
    store: &mut S,
    parent: TimelineId,
) -> TestResult {
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding_permit = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    let binding = store.commit_local_binding(&binding_permit)?;
    assert_eq!(store.commit_local_binding(&binding_permit)?, binding);

    let admission = request(&host, parent, &authenticated)?;
    let receipt = store.create_fork_admitted(&admission)?;
    assert_eq!(store.create_fork_admitted(&admission)?, receipt);
    assert_eq!(
        store
            .read_fork_admission(receipt.child_id)?
            .ok_or("missing FAR1")?
            .input()
            .principal_owner_binding_digest,
        binding.digest()
    );
    assert!(matches!(
        store.append(
            receipt.child_id,
            &[pos_core::EventDraft::new(
                pos_core::EntityId::new(),
                pos_core::Kind::new("fork.test"),
                pos_core::CanonicalBytes::from_vec(vec![1]),
            )],
        ),
        Err(pos_core::CoreError::TimelineNotFound(id)) if id == receipt.child_id
    ));
    assert!(matches!(
        store.append_committed(receipt.child_id, &[]),
        Err(pos_core::CoreError::TimelineNotFound(id)) if id == receipt.child_id
    ));

    let conflict = host.permit_fork_creation(
        &authenticated,
        Hash::from_bytes([3; 32]),
        parent,
        0,
        0,
        Hash::from_bytes([4; 32]),
        Hash::from_bytes([5; 32]),
        true,
        "other".to_owned(),
        WallTime::from_micros(20),
    )?;
    assert_eq!(
        store.create_fork_admitted(&conflict),
        Err(ForkAdmissionErrorV1::Conflict)
    );
    let conflicting_binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([2; 32]),
        OwnerIdV1::new("other")?,
    )?;
    assert_eq!(
        store.commit_local_binding(&conflicting_binding),
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
fn exact_permits_allow_retry_after_authentication_expiry() -> TestResult {
    let mut store = MemoryStore::new();
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let admission = request(&host, parent.id(), &authenticated)?;
    let receipt = store.create_fork_admitted(&admission)?;
    assert_eq!(
        host.permit_local_binding(
            Hash::from_bytes([2; 32]),
            &authenticated,
            OwnerIdV1::new("creator")?,
            WallTime::from_micros(101),
        ),
        Err(ForkAdmissionErrorV1::Unauthenticated)
    );
    assert_eq!(
        host.permit_fork_creation(
            &authenticated,
            Hash::from_bytes([4; 32]),
            parent.id(),
            0,
            0,
            Hash::from_bytes([4; 32]),
            Hash::from_bytes([5; 32]),
            true,
            "new-child".to_owned(),
            WallTime::from_micros(101),
        ),
        Err(ForkAdmissionErrorV1::Unauthenticated)
    );
    assert_eq!(
        store.commit_local_binding(&binding)?,
        binding.binding().clone()
    );
    assert_eq!(store.create_fork_admitted(&admission)?, receipt);
    Ok(())
}

#[test]
fn admission_rejects_a_parent_head_outside_the_completed_fold_boundary() -> TestResult {
    let mut store = MemoryStore::new();
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let request = request_at_cut(&host, parent.id(), &authenticated, 1)?;
    assert_eq!(
        store.create_fork_admitted(&request),
        Err(ForkAdmissionErrorV1::StaleFoldBoundary)
    );
    assert_eq!(store.list_timelines()?.len(), 1);
    Ok(())
}

#[test]
fn foreign_host_binding_and_permits_fail_closed() -> TestResult {
    let mut store = MemoryStore::new();
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let trusted_host = host(&authenticated)?;
    let foreign_host = host(&authenticated)?;
    store.bind_fork_admission_host(trusted_host.host_binding())?;
    assert_eq!(
        store.bind_fork_admission_host(foreign_host.host_binding()),
        Err(ForkAdmissionErrorV1::Unauthenticated)
    );
    let foreign_binding = binding_permit(
        &foreign_host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    assert_eq!(
        store.commit_local_binding(&foreign_binding),
        Err(ForkAdmissionErrorV1::Unauthenticated)
    );
    let foreign_request = request(&foreign_host, parent.id(), &authenticated)?;
    assert_eq!(
        store.create_fork_admitted(&foreign_request),
        Err(ForkAdmissionErrorV1::Unauthenticated)
    );
    Ok(())
}

#[test]
fn far1_rejects_reserved_import_origin_code_two() -> TestResult {
    let mut store = MemoryStore::new();
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let receipt = store.create_fork_admitted(&request(&host, parent.id(), &authenticated)?)?;
    let mut bytes = store
        .read_fork_admission(receipt.child_id)?
        .ok_or("missing FAR1")?
        .to_canonical_cbor();
    *bytes.last_mut().ok_or("missing origin")? = 2;
    assert_eq!(
        pos_core::ForkAdmissionRecordV1::from_canonical_cbor(&bytes),
        Err(pos_core::ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable)
    );
    Ok(())
}

#[test]
fn sqlite_corrupt_far1_or_pob1_rows_fail_closed_at_the_public_read_port() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 SQLite path")?)?;
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let receipt = store.create_fork_admitted(&request(&host, parent.id(), &authenticated)?)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_principal_owner_bindings SET owner_id = 'corrupt'",
        [],
    )?;
    assert_eq!(
        store.read_fork_admission(receipt.child_id),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_corrupt_pob1_row_fails_closed_on_exact_operation_retry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-binding-retry.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 SQLite path")?)?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let permit = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&permit)?;
    rusqlite::Connection::open(&path)?.execute(
        "UPDATE fork_principal_owner_bindings SET owner_id = 'corrupt'",
        [],
    )?;
    assert_eq!(
        store.commit_local_binding(&permit),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_corrupt_far1_bytes_fail_closed_at_the_public_read_port() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 SQLite path")?)?;
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let receipt = store.create_fork_admitted(&request(&host, parent.id(), &authenticated)?)?;
    rusqlite::Connection::open(&path)?
        .execute("UPDATE fork_admissions SET far1_cbor = zeroblob(1)", [])?;
    assert_eq!(
        store.read_fork_admission(receipt.child_id),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_corrupt_far1_operation_commitment_fails_closed_on_read_and_retry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 SQLite path")?)?;
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let request = request(&host, parent.id(), &authenticated)?;
    let receipt = store.create_fork_admitted(&request)?;
    rusqlite::Connection::open(&path)?.execute(
        "UPDATE fork_admissions SET operation_commitment = ?1",
        rusqlite::params![[8_u8; 32].as_slice()],
    )?;
    assert_eq!(
        store.read_fork_admission(receipt.child_id),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.create_fork_admitted(&request),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_corrupt_far1_operation_id_row_fails_closed_at_the_public_read_port() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 SQLite path")?)?;
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    let receipt = store.create_fork_admitted(&request(&host, parent.id(), &authenticated)?)?;
    rusqlite::Connection::open(&path)?.execute(
        "UPDATE fork_admissions SET operation_id = ?1",
        rusqlite::params![[8_u8; 32].as_slice()],
    )?;
    assert_eq!(
        store.read_fork_admission(receipt.child_id),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_rolls_back_child_metadata_when_far1_insert_fails() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 SQLite path")?)?;
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let host = host(&authenticated)?;
    store.bind_fork_admission_host(host.host_binding())?;
    let binding = binding_permit(
        &host,
        &authenticated,
        Hash::from_bytes([1; 32]),
        OwnerIdV1::new("creator")?,
    )?;
    store.commit_local_binding(&binding)?;
    rusqlite::Connection::open(&path)?.execute_batch("CREATE TRIGGER reject_far1 BEFORE INSERT ON fork_admissions BEGIN SELECT RAISE(ABORT, 'reject'); END;")?;
    assert_eq!(
        store.create_fork_admitted(&request(&host, parent.id(), &authenticated)?),
        Err(ForkAdmissionErrorV1::StorageIndeterminate)
    );
    assert_eq!(store.list_timelines()?.len(), 1);
    Ok(())
}
