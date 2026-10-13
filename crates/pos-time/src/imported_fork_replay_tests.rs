//! Real imported native authority consumed by the public protected Replay seam.

#[path = "../../pos-store/tests/support/fae1_fixture.rs"]
pub mod fixture;

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use fixture::{pin_policy, request_for, Fallible, Port, Shape, Spec, World, PARENT_CUT};
use pos_core::{
    CoreError, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1, Hash, Reducer,
    Seq, State, TimelineId, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayForkSourceV1, WorldReplayUseV1, WorldReplayVerificationErrorV1,
    WorldReplayVerifierV1,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkReplayReadLimitsV1, ForkReplayRequirementV1,
    StoreConfig,
};

use crate::test_support::{with_release, ProtectedFixture};

struct Count;
static FOLDED_EVENTS: AtomicUsize = AtomicUsize::new(0);

impl Reducer for Count {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("n", serde_json::json!(0));
        state
    }

    fn apply(&self, state: &mut State, _event: &pos_core::Event) {
        FOLDED_EVENTS.fetch_add(1, Ordering::SeqCst);
        let next = state
            .get("n")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            + 1;
        state.set("n", serde_json::json!(next));
    }
}

fn count() -> Box<dyn Reducer> {
    Box::new(Count)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    Omitted,
    Foreign,
    FinalIdentity,
    NoProfile,
    UnequalLimits,
}

struct ImportedVerifier {
    child: TimelineId,
    parent: TimelineId,
    requirement: ForkReplayRequirementV1,
    secondary: Option<(TimelineId, ForkReplayRequirementV1)>,
    fault: Fault,
    admissions: AtomicUsize,
}

impl WorldReplayVerifierV1 for ImportedVerifier {
    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        let phase = self.admissions.fetch_add(1, Ordering::SeqCst);
        let child = requested.timeline_id();
        let mut requirement = self
            .secondary
            .filter(|(timeline, _)| *timeline == child)
            .map_or(self.requirement, |(_, required)| required);
        let initial_admissions = if self.secondary.is_some() { 2 } else { 1 };
        if matches!(self.fault, Fault::Foreign)
            || (matches!(self.fault, Fault::FinalIdentity) && phase >= initial_admissions)
        {
            requirement = ForkReplayRequirementV1::new(
                child,
                requirement.publication_logical_head(),
                Hash::from_bytes([0xff; 32]),
                requirement.authority_origin_digest(),
            )
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        }
        let sources = vec![
            WorldReplayForkSourceV1::new(child, Some(requirement))?,
            WorldReplayForkSourceV1::new(self.parent, None)?,
        ];
        let required = if matches!(self.fault, Fault::Omitted) {
            Vec::new()
        } else {
            vec![requirement]
        };
        let profile = if matches!(self.fault, Fault::NoProfile) {
            None
        } else {
            Some(Hash::from_bytes([0xe1; 32]))
        };
        let bytes = 64 * 1024 * 1024
            + usize::from(matches!(self.fault, Fault::UnequalLimits) && child != self.child);
        let limits = ForkReplayReadLimitsV1::new(8, 1_024, 65_536, bytes, 30_000_000)
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        Ok(
            pos_runtime::world_replay::test_verified_world_replay_with_fork_attribution(
                pos_runtime::world_replay::test_verified_world_replay(
                    closure,
                    requested,
                    generation,
                    ErasureReplayClaimV1::Exact,
                ),
                profile,
                sources,
                required,
                limits,
            ),
        )
    }
}

fn populate<S: Port>(
    store: &mut S,
    world: &World,
    shape: Shape,
    destroyed_key: bool,
) -> Fallible<ForkReplayRequirementV1> {
    let built = world.build(&Spec {
        destroyed_key,
        ..Spec::default()
    })?;
    world.seed_destination(store)?;
    pin_policy(store, &built.policy)?;
    store.import_verified(&request_for(world, &built))?;
    let child = world.child_at(0)?.id;
    let head = PARENT_CUT + shape.events();
    let committed = store.read_committed(child, head)?;
    Ok(ForkReplayRequirementV1::new(
        child,
        Seq::from_u64(head),
        committed.record_id,
        committed.authority_origin_digest,
    )?)
}

fn run_on_host(
    mut host: ErasureExecutionHostV1,
    child: TimelineId,
    fault: Fault,
    cut: Option<Seq>,
) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let gate = host.containment_gate();
    let generation = gate.inventory_generation()?;
    let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        child,
        Hash::from_bytes(generation.digest()),
    )?;
    let mut registry = fixture.registry(gate);
    let before = registry.state_snapshot(child)?;
    let mut reads = host.read_sender()?;
    FOLDED_EVENTS.store(0, Ordering::SeqCst);
    let result = with_release(|release| match cut {
        None => crate::replay(
            &mut reads,
            child,
            &mut registry,
            &closure,
            release,
            &fixture.fold(),
        ),
        Some(cut) => crate::replay_at(
            &mut reads,
            child,
            cut,
            &mut registry,
            &closure,
            release,
            &fixture.fold(),
        ),
    });
    if fault == Fault::None {
        result?;
        let minimum_folded = cut.map_or(PARENT_CUT, Seq::as_u64);
        assert!(FOLDED_EVENTS.load(Ordering::SeqCst) >= usize::try_from(minimum_folded)?);
    } else {
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
        assert_eq!(registry.state_snapshot(child)?, before);
        if matches!(fault, Fault::FinalIdentity) {
            assert!(FOLDED_EVENTS.load(Ordering::SeqCst) > 0);
        } else {
            assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[test]
fn imported_mixed_and_empty_sources_reach_replay_and_replay_at_on_both_adapters() -> Fallible<()> {
    for shape in [
        Shape::Mixed,
        Shape::EmptyClassified,
        Shape::EmptyUnclassified,
    ] {
        for (fault, cut, destroyed_key) in [
            Fault::None,
            Fault::Omitted,
            Fault::Foreign,
            Fault::FinalIdentity,
            Fault::NoProfile,
        ]
        .into_iter()
        .flat_map(|fault| [None, Some(Seq::from_u64(2))].map(|cut| (fault, cut)))
        .flat_map(|(fault, cut)| {
            [false, true]
                .into_iter()
                .filter(move |destroyed| !*destroyed || fault == Fault::None)
                .map(move |destroyed| (fault, cut, destroyed))
        })
        {
            let world = World::new(shape, false)?;
            let child = world.child_at(0)?.id;
            let mut memory = MemoryStore::new();
            let requirement = populate(&mut memory, &world, shape, destroyed_key)?;
            let verifier = || {
                Arc::new(ImportedVerifier {
                    child,
                    parent: world.root,
                    requirement,
                    secondary: None,
                    fault,
                    admissions: AtomicUsize::new(0),
                })
            };
            let composition =
                ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
            let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
                memory,
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run_on_host(host, child, fault, cut)?;
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("imported-replay.sqlite");
            let path = path.to_str().ok_or("utf-8 path")?;
            let mut sqlite = SqliteStore::open(path)?;
            assert_eq!(
                populate(&mut sqlite, &world, shape, destroyed_key)?,
                requirement
            );
            drop(sqlite);
            let composition =
                ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
            let host = ErasureExecutionHostV1::open_with_authority(
                StoreConfig::Sqlite {
                    path: path.to_owned(),
                },
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run_on_host(host, child, fault, cut)?;
        }
    }
    Ok(())
}

fn populate_pair<S: Port>(store: &mut S, world: &World) -> Fallible<[ForkReplayRequirementV1; 2]> {
    let first = populate(store, world, Shape::Mixed, false)?;
    let built = world.build(&Spec::distinct(1))?;
    pin_policy(store, &built.policy)?;
    store.import_verified(&request_for(world, &built))?;
    let child = world.child_at(1)?.id;
    let committed = store.read_committed(child, PARENT_CUT)?;
    let second = ForkReplayRequirementV1::new(
        child,
        Seq::from_u64(PARENT_CUT),
        committed.record_id,
        committed.authority_origin_digest,
    )?;
    Ok([first, second])
}

fn compare_on_host(
    mut host: ErasureExecutionHostV1,
    requirements: [ForkReplayRequirementV1; 2],
    fault: Fault,
) -> Fallible<()> {
    let fixture_a = ProtectedFixture::new("count", count);
    let gate = host.containment_gate();
    let generation = Hash::from_bytes(gate.inventory_generation()?.digest());
    let timelines = requirements.map(ForkReplayRequirementV1::child_timeline_id);
    let closures = timelines
        .map(|timeline| {
            WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                timeline, generation,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut a = fixture_a.registry(gate.clone());
    let mut b = fixture_a.registry(gate);
    let before_a = a.state_snapshot(timelines[0])?;
    let before_b = b.state_snapshot(timelines[1])?;
    let mut reads = host.read_sender()?;
    FOLDED_EVENTS.store(0, Ordering::SeqCst);
    let result = with_release(|release| {
        crate::compare(
            &mut reads,
            timelines,
            Seq::from_u64(PARENT_CUT),
            [&mut a, &mut b],
            [&closures[0], &closures[1]],
            release,
            [&fixture_a.fold(), &fixture_a.fold()],
        )
    });
    if fault == Fault::None {
        let diff = result?;
        assert_eq!(diff.fork_seq, Seq::from_u64(PARENT_CUT));
        assert!(!diff.diverged_entities.is_empty());
    } else {
        assert_eq!(
            result.map(|_| ()).map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
        assert_eq!(a.state_snapshot(timelines[0])?, before_a);
        assert_eq!(b.state_snapshot(timelines[1])?, before_b);
        if matches!(fault, Fault::FinalIdentity) {
            assert!(FOLDED_EVENTS.load(Ordering::SeqCst) > 0);
        } else {
            assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[test]
fn compare_checks_both_imported_arms_before_folding_and_after_both_folds() -> Fallible<()> {
    for fault in [
        Fault::None,
        Fault::Omitted,
        Fault::FinalIdentity,
        Fault::UnequalLimits,
    ] {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::EmptyUnclassified)?;
        let mut memory = MemoryStore::new();
        let requirements = populate_pair(&mut memory, &world)?;
        let verifier = || {
            Arc::new(ImportedVerifier {
                child: requirements[0].child_timeline_id(),
                parent: world.root,
                requirement: requirements[0],
                secondary: Some((requirements[1].child_timeline_id(), requirements[1])),
                fault,
                admissions: AtomicUsize::new(0),
            })
        };
        let composition =
            ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
        let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
            memory,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        compare_on_host(host, requirements, fault)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("compare.sqlite");
        let path = path.to_str().ok_or("utf-8 path")?;
        let mut sqlite = SqliteStore::open(path)?;
        assert_eq!(populate_pair(&mut sqlite, &world)?, requirements);
        drop(sqlite);
        let composition =
            ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
        let host = ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite {
                path: path.to_owned(),
            },
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        compare_on_host(host, requirements, fault)?;
    }
    Ok(())
}
