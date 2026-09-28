use pos_core::store::EventStore;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    CanonicalBytes, EntityId, EventDraft, ForkAdmissionAuthorityPortV1, ForkAdmissionHostV1,
    ForkAdmissionIntentInputV1, ForkEventAuthorityHostV1, ForkEventProvenanceAuthorityPortV1,
    ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, Hash, Kind, OwnerIdV1, PrincipalRefV1,
    WallTime,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn authenticated() -> Result<AuthenticatedPrincipalResultV1, Box<dyn std::error::Error>> {
    Ok(AuthenticatedPrincipalResultV1::try_from_draft(
        AuthenticatedPrincipalDraftV1 {
            principal: PrincipalRefV1::try_new([7; 16], "fork-event.test")?,
            adapter_id: "host.adapter".to_owned(),
            assurance: AssuranceLevelV1::try_new(2)?,
            issued_at: WallTime::from_micros(10),
            expires_at: WallTime::from_micros(100),
            binding_digest: Hash::from_bytes([9; 32]),
        },
    )?)
}

fn exercise<S: EventStore + ForkAdmissionAuthorityPortV1 + ForkEventProvenanceAuthorityPortV1>(
    store: &mut S,
) -> TestResult {
    let parent = store.create_timeline("parent")?;
    let authenticated = authenticated()?;
    let admission_host = ForkAdmissionHostV1::new(
        "host.adapter".to_owned(),
        2,
        vec![authenticated.registry_binding_digest()],
    )?;
    store.bind_fork_admission_host(admission_host.host_binding())?;
    let binding = admission_host.permit_local_binding(
        Hash::from_bytes([1; 32]),
        &authenticated,
        OwnerIdV1::new("creator")?,
        WallTime::from_micros(20),
    )?;
    store.commit_local_binding(&binding)?;
    let request = admission_host.permit_fork_creation(
        &authenticated,
        ForkAdmissionIntentInputV1 {
            operation_id: Hash::from_bytes([2; 32]),
            parent_timeline_id: parent.id(),
            completed_fold_cursor: 0,
            post_fold_tick_boundary: 0,
            room_revision_descriptor_hash: Hash::from_bytes([3; 32]),
            plugin_composition_hash: Hash::from_bytes([4; 32]),
            attribution_required: true,
            child_name: "child".to_owned(),
        },
        WallTime::from_micros(20),
    )?;
    let child = store.create_fork_admitted(&request)?.child_id;
    let admission = store.read_fork_admission(child)?.ok_or("missing FAR1")?;
    let host = ForkEventAuthorityHostV1::new(
        "host.registrar".to_owned(),
        vec![ForkExternalInputRouteV1::new(
            ForkEventSourceDescriptorV1::new("gateway.action.v1", Hash::from_bytes([5; 32]))?,
            true,
        )],
    )?;
    store.bind_fork_event_authority_host(host.binding())?;
    let registration = host.permit_registration(Hash::from_bytes([6; 32]), admission.clone())?;
    let receipt = store.register_classifier(&registration)?;
    assert_eq!(store.register_classifier(&registration)?, receipt);
    let permit = host.permit_external_input(
        child,
        admission.digest(),
        "gateway.adapter".to_owned(),
        ForkEventSourceDescriptorV1::new("gateway.action.v1", Hash::from_bytes([5; 32]))?,
    )?;
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("fork.input"),
        CanonicalBytes::from_vec(vec![1, 2, 3]),
    )
    .with_wall_time(WallTime::from_micros(30));
    let appended = store.append_classified(&permit, Hash::from_bytes([7; 32]), draft.clone())?;
    assert_eq!(
        store.recover_classified_append(&permit, Hash::from_bytes([7; 32]), &draft)?,
        Some(appended.clone())
    );
    let suffix = store.read_fork_event_suffix(child, appended.event.seq.as_u64())?;
    assert_eq!(suffix.len(), 1);
    assert!(suffix[0].1.is_some());
    Ok(())
}

#[test]
fn memory_classified_fork_append_is_durable_at_the_public_port() -> TestResult {
    exercise(&mut MemoryStore::new())
}

#[test]
fn sqlite_classified_fork_append_is_durable_at_the_public_port() -> TestResult {
    exercise(&mut SqliteStore::open_in_memory()?)
}
