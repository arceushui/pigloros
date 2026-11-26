//! ADR-141 P6 and P7 at the public host seam: an actor-owned root created
//! under its identity joins a later erasure of its owner and stays outside
//! an earlier one, and a closed composition never recovers a store that
//! holds active requests.

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

/// ADR-141 P7 (`SQLite`, which closes and reopens): a closed composition
/// refuses to recover a store that holds a scoped request, frozen, and an
/// unscoped one, only submitted.
#[test]
fn a_closed_composition_refuses_a_store_with_active_requests() -> TestResult {
    let mut fixture = Fixture::plain(Adapter::Sqlite)?;
    freeze_actor_request(&mut fixture.host)?;
    let unscoped = fixture
        .host
        .command_sender()?
        .submit_local_erasure(&LocalErasureSubmissionV1 {
            actor: other_actor(),
            ..submission(2, ErasureScopeV1::PrivateSubjectData)?
        })
        .map_err(fail)?
        .state
        .request();
    let unscoped_state = fixture
        .host
        .read_sender()?
        .erasure_state(unscoped)?
        .ok_or("unscoped request missing")?;
    assert!(unscoped_state.scope().is_none());
    let Fixture { host, sqlite, .. } = fixture;
    drop(host);
    let store = sqlite.ok_or("a SQLite fixture keeps its store")?;
    let recovered = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Sqlite { path: store.path },
        &ErasureCoordinatorCompositionV1::closed(),
        ErasureRecoveryLimitsV1::compiled_maximum(),
    );
    assert!(recovered.is_err());
    Ok(())
}
