//! ADR-141 P6 and P7 at the public host seam: an actor-owned root created
//! under its identity joins a later erasure of its owner and stays outside
//! an earlier one, and a closed composition never recovers a store that
//! holds an active request, scoped or not.

use super::*;

/// The identity these tests create a root under.
const fn identified_root() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x5f; 16]))
}

/// Submit request 1 of the actor and drive it until its freeze commits.
fn freeze_actor_request(host: &mut ErasureExecutionHostV1) -> TestResult {
    submitted(host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let steps = driven_steps(host, |step| *step == LocalErasureStepV1::Frozen)?;
    assert_eq!(steps.last(), Some(&LocalErasureStepV1::Frozen));
    Ok(())
}

/// The Timelines request 1 committed to its scope.
fn frozen_scope_timelines(host: &mut ErasureExecutionHostV1) -> TestResult<Vec<TimelineId>> {
    let verified = host
        .read_sender()?
        .erasure_state(request_of(1)?)?
        .ok_or("request missing")?;
    let scope = verified.scope().ok_or("no committed scope")?;
    Ok(scope.scope_timeline_ids().to_vec())
}

/// Create the identified root, owned by the actor.
fn create_identified_root(host: &mut ErasureExecutionHostV1) -> TestResult<pos_core::Timeline> {
    let mut sender = host.command_sender()?;
    let root = sender.create_owned_root_with_id(identified_root(), "identified", actor())?;
    Ok(root)
}

/// ADR-141 P6, on both adapters: a later erasure of the owner selects a
/// root created under its identity, and freezes it.
#[test]
fn a_later_erasure_of_the_owner_selects_a_root_created_with_its_identity() -> TestResult {
    for adapter in ADAPTERS {
        let mut fixture = Fixture::plain(adapter)?;
        create_identified_root(&mut fixture.host)?;
        freeze_actor_request(&mut fixture.host)?;
        let scope = frozen_scope_timelines(&mut fixture.host)?;
        assert!(scope.contains(&identified_root()));
        let mut reads = fixture.host.read_sender()?;
        assert_eq!(
            reads.timeline(identified_root()).map(drop),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
    }
    Ok(())
}

/// ADR-141 P6, on both adapters: under its owner's frozen request, a root
/// created under its identity is positively checked and stays outside that
/// request, readable.
#[test]
fn a_root_created_with_its_identity_under_an_active_request_stays_outside_it() -> TestResult {
    for adapter in ADAPTERS {
        let mut fixture = Fixture::plain(adapter)?;
        freeze_actor_request(&mut fixture.host)?;
        let created = create_identified_root(&mut fixture.host)?;
        assert_eq!(created.meta.owner, Some(actor()));
        let scope = frozen_scope_timelines(&mut fixture.host)?;
        assert!(!scope.contains(&identified_root()));
        let mut reads = fixture.host.read_sender()?;
        assert_eq!(reads.timeline(identified_root())?, Some(created));
    }
    Ok(())
}

/// Whether `request` has committed an erasure scope.
fn request_scope_committed(
    host: &mut ErasureExecutionHostV1,
    request: ErasureReferenceV1,
) -> TestResult<bool> {
    let verified = host
        .read_sender()?
        .erasure_state(request)?
        .ok_or("request missing")?;
    Ok(verified.scope().is_some())
}

/// Close the fixture's host and keep its `SQLite` store.
fn closed_store(fixture: Fixture) -> TestResult<LocalStore> {
    let Fixture { host, sqlite, .. } = fixture;
    drop(host);
    Ok(sqlite.ok_or("a SQLite fixture keeps its store")?)
}

/// Recover `store` under the explicitly closed composition.
fn closed_recovery(store: &LocalStore) -> Result<(), ErasureHostErrorV1> {
    let composition = ErasureCoordinatorCompositionV1::closed();
    let recovered = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Sqlite {
            path: store.path.clone(),
        },
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    );
    recovered.map(drop)
}

/// ADR-141 P7 control (`SQLite`, which closes and reopens): the closed
/// composition recovers the same fixture store while it holds no request.
#[test]
fn a_closed_composition_recovers_a_store_without_requests() -> TestResult {
    let store = closed_store(Fixture::plain(Adapter::Sqlite)?)?;
    assert_eq!(closed_recovery(&store), Ok(()));
    Ok(())
}

/// ADR-141 P7 (`SQLite`): a store whose only request is submitted and has
/// no scope is refused under the closed composition. Recovery observes the
/// topology of every request head, scoped or not, and the closed authority
/// answers no observation, so recovery is unavailable.
#[test]
fn a_closed_composition_refuses_a_store_with_an_unscoped_request() -> TestResult {
    let mut fixture = Fixture::plain(Adapter::Sqlite)?;
    submitted(&mut fixture.host, 1, ErasureScopeV1::PrivateSubjectData)?;
    assert!(!request_scope_committed(&mut fixture.host, request_of(1)?)?);
    let store = closed_store(fixture)?;
    assert_eq!(
        closed_recovery(&store),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

/// ADR-141 P7 (`SQLite`): a store whose only request is frozen, with a
/// committed scope, is refused under the closed composition.
#[test]
fn a_closed_composition_refuses_a_store_with_a_scoped_request() -> TestResult {
    let mut fixture = Fixture::plain(Adapter::Sqlite)?;
    freeze_actor_request(&mut fixture.host)?;
    assert!(request_scope_committed(&mut fixture.host, request_of(1)?)?);
    let store = closed_store(fixture)?;
    assert_eq!(
        closed_recovery(&store),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    Ok(())
}
