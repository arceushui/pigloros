//! Real imported native authority consumed by the public protected Replay seam.

#[path = "../../pos-store/tests/support/fae1_fixture.rs"]
pub mod fixture;

mod cumulative_budget;
pub mod lifecycle;
mod runtime_budget;

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use fixture::{pin_policy, request_for, Built, Fallible, Port, Shape, Spec, World, PARENT_CUT};
use pos_core::{
    store::{EventReadBounds, EventStore},
    CoreError, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1, Hash,
    KeyDestructionRequestV1, KeyRegistryStateV1, Reducer, Seq, State, TimelineId,
    WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayForkSourceV1, WorldReplayUseV1, WorldReplayVerificationErrorV1,
    WorldReplayVerifierV1,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkManifestPublicationPortV1,
    ForkReplayReadLimitsV1, ForkReplayRequirementV1, StoreConfig,
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
    FinalRequirements,
    FinalLimits,
    NoProfile,
    UnequalLimits,
    NodeLimit,
    RowLimit,
    ByteLimit,
}

impl Fault {
    const fn after_folding(self) -> bool {
        matches!(
            self,
            Self::FinalIdentity | Self::FinalRequirements | Self::FinalLimits
        )
    }

    const fn global_limits(self) -> bool {
        matches!(
            self,
            Self::UnequalLimits | Self::NodeLimit | Self::RowLimit | Self::ByteLimit
        )
    }
}

struct ImportedVerifier {
    child: TimelineId,
    parent: TimelineId,
    requirement: ForkReplayRequirementV1,
    secondary: Option<(TimelineId, ForkReplayRequirementV1)>,
    fault: Fault,
    fault_target: Option<TimelineId>,
    limits_override: Option<ForkReplayReadLimitsV1>,
    admissions: AtomicUsize,
}

impl WorldReplayVerifierV1 for ImportedVerifier {
    fn read_profile(
        &self,
        _closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        _generation: ErasureReferenceV1,
    ) -> Result<(EventReadBounds, ForkReplayReadLimitsV1), WorldReplayVerificationErrorV1> {
        let fault = if self
            .fault_target
            .is_none_or(|target| target == intent.timeline_id())
        {
            self.fault
        } else {
            Fault::None
        };
        let nodes = if fault == Fault::NodeLimit { 1 } else { 1_024 };
        let rows = if fault == Fault::RowLimit { 1 } else { 65_536 };
        let bytes = if fault == Fault::ByteLimit {
            1
        } else {
            64 * 1024 * 1024
                + usize::from(fault == Fault::UnequalLimits && intent.timeline_id() != self.child)
        };
        let (bounds, _) = crate::test_support::ordinary_read_profile()?;
        ForkReplayReadLimitsV1::new(8, nodes, rows, bytes, 30_000_000)
            .map(|limits| (bounds, self.limits_override.unwrap_or(limits)))
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        self.verify_with_max_events(closure, requested, generation, None)
    }
}

impl ImportedVerifier {
    /// Select a finite Event allowance before the test owner seals its result.
    /// Normal fixtures keep their exact existing bounds and fault behavior.
    fn verify_with_max_events(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
        max_events: Option<usize>,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        let phase = self.admissions.fetch_add(1, Ordering::SeqCst);
        let child = requested.timeline_id();
        let fault = if self.fault_target.is_none_or(|target| target == child) {
            self.fault
        } else {
            Fault::None
        };
        let mut requirement = self
            .secondary
            .filter(|(timeline, _)| *timeline == child)
            .map_or(self.requirement, |(_, required)| required);
        let initial_admissions = if self.secondary.is_some() { 2 } else { 1 };
        let final_phase = phase >= initial_admissions;
        if matches!(fault, Fault::Foreign) || (matches!(fault, Fault::FinalIdentity) && final_phase)
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
        let required = if matches!(fault, Fault::Omitted)
            || (matches!(fault, Fault::FinalRequirements) && final_phase)
        {
            Vec::new()
        } else {
            vec![requirement]
        };
        let profile = if matches!(fault, Fault::NoProfile) {
            None
        } else {
            Some(Hash::from_bytes([0xe1; 32]))
        };
        let nodes = if fault == Fault::NodeLimit { 1 } else { 1_024 };
        let rows = if fault == Fault::RowLimit { 1 } else { 65_536 };
        let bytes = if fault == Fault::ByteLimit {
            1
        } else {
            64 * 1024 * 1024
                + usize::from(
                    (matches!(fault, Fault::UnequalLimits) && child != self.child)
                        || (matches!(fault, Fault::FinalLimits) && final_phase),
                )
        };
        let limits = ForkReplayReadLimitsV1::new(8, nodes, rows, bytes, 30_000_000)
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        let limits = self.limits_override.unwrap_or(limits);
        let verified = pos_runtime::world_replay::test_verified_world_replay(
            closure,
            requested,
            generation,
            ErasureReplayClaimV1::Exact,
            limits,
        );
        let verified = if let Some(max_events) = max_events {
            let bounds = verified.read_bounds();
            pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
                closure.digest(),
                closure.timeline_id(),
                closure.source_head(),
                requested.clone(),
                generation,
                ErasureReplayClaimV1::Exact,
                (
                    EventReadBounds::new_with_total_bytes_and_elapsed(
                        bounds.max_payload_bytes(),
                        bounds.max_event_type_bytes(),
                        bounds.max_fork_depth(),
                        max_events,
                        bounds.max_total_bytes(),
                        bounds.max_elapsed_micros(),
                    ),
                    limits,
                ),
            )
        } else {
            verified
        };
        Ok(
            pos_runtime::world_replay::test_verified_world_replay_with_fork_attribution(
                verified, profile, sources, required, limits,
            ),
        )
    }
}

fn populate<S: Port>(
    store: &mut S,
    world: &World,
    built: &Built,
) -> Fallible<ForkReplayRequirementV1> {
    world.seed_destination(store)?;
    pin_policy(store, &built.policy)?;
    store.import_verified(&request_for(world, built))?;
    let child = world.child_at(0)?;
    let head = PARENT_CUT + child.shape.events();
    let committed = store.read_committed(child.id, head)?;
    Ok(ForkReplayRequirementV1::new(
        child.id,
        Seq::from_u64(head),
        committed.record_id,
        committed.authority_origin_digest,
    )?)
}

/// Seed one immutable database image, before any host owns its authority.
/// Only closed, fully checkpointed images may be copied into isolated cases.
fn closed_sqlite_fixture(
    world: &World,
    built: &Built,
) -> Fallible<(tempfile::TempDir, ForkReplayRequirementV1)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("imported-replay.sqlite");
    let mut sqlite = SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?;
    let requirement = populate(&mut sqlite, world, built)?;
    drop(sqlite);
    // SQLite's final connection close checkpoints and removes these sidecars.
    // Fail rather than copy an image whose committed pages could remain in WAL.
    assert!(!path.with_extension("sqlite-wal").try_exists()?);
    assert!(!path.with_extension("sqlite-shm").try_exists()?);
    Ok((directory, requirement))
}

fn run_on_host(
    mut host: ErasureExecutionHostV1,
    child: TimelineId,
    publication_head: Seq,
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
    let expected_folded = usize::try_from(cut.unwrap_or(publication_head).as_u64())?;
    if fault == Fault::None {
        result?;
        // The signed fixture has a contiguous logical history. Even though
        // authority validates the whole suffix, Replay-at may fold only its
        // requested prefix, including a cut before the child segment.
        assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), expected_folded);
    } else {
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
        assert_eq!(registry.state_snapshot(child)?, before);
        if fault.after_folding() {
            assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), expected_folded);
        } else {
            assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

fn imported_replay_cases() -> impl Iterator<Item = (Fault, Option<Seq>, bool)> {
    [
        Fault::None,
        Fault::Omitted,
        Fault::Foreign,
        Fault::FinalIdentity,
        Fault::FinalRequirements,
        Fault::FinalLimits,
        Fault::NoProfile,
        Fault::NodeLimit,
        Fault::RowLimit,
        Fault::ByteLimit,
    ]
    .into_iter()
    .flat_map(|fault| {
        [
            None,
            Some(Seq::from_u64(2)),
            Some(Seq::from_u64(PARENT_CUT)),
        ]
        .map(|cut| (fault, cut))
    })
    .flat_map(|(fault, cut)| {
        [false, true]
            .into_iter()
            .filter(move |destroyed| !*destroyed || fault == Fault::None)
            .map(move |destroyed| (fault, cut, destroyed))
    })
}

#[test]
fn imported_mixed_and_empty_sources_reach_replay_and_replay_at_on_both_adapters() -> Fallible<()> {
    let mut cases = [0; 3];
    for shape in [
        Shape::Mixed,
        Shape::EmptyClassified,
        Shape::EmptyUnclassified,
    ] {
        // Share immutable signed input, never destination state or host authority.
        let world = World::new(shape, false)?;
        let child = world.child_at(0)?.id;
        let built = [
            world.build(&Spec::default())?,
            world.build(&Spec {
                destroyed_key: true,
                ..Spec::default()
            })?,
        ];
        let sqlite_images = [
            closed_sqlite_fixture(&world, &built[0])?,
            closed_sqlite_fixture(&world, &built[1])?,
        ];
        for (fault, cut, destroyed_key) in imported_replay_cases() {
            let image_index = usize::from(destroyed_key);
            let built = &built[image_index];
            let mut memory = MemoryStore::new();
            let requirement = populate(&mut memory, &world, built)?;
            let run = |host| {
                run_on_host(
                    host,
                    child,
                    requirement.publication_logical_head(),
                    fault,
                    cut,
                )
            };
            let verifier = || {
                Arc::new(ImportedVerifier {
                    child,
                    parent: world.root,
                    requirement,
                    secondary: None,
                    fault,
                    fault_target: None,
                    limits_override: None,
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
            run(host)?;
            cases[0] += 1;
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("imported-replay.sqlite");
            let (image_directory, image_requirement) = &sqlite_images[image_index];
            assert_eq!(*image_requirement, requirement);
            let image = image_directory.path().join("imported-replay.sqlite");
            // Each case still gets a distinct database, fresh host, gate,
            // verifier/admission counter, registry and release authority.
            assert_eq!(std::fs::copy(&image, &path)?, image.metadata()?.len());
            let path = path.to_str().ok_or("utf-8 path")?;
            let sqlite = SqliteStore::open(path)?;
            let committed =
                sqlite.read_committed(child, requirement.publication_logical_head().as_u64())?;
            assert_eq!(committed.record_id, requirement.signed_manifest_record_id());
            assert_eq!(
                committed.authority_origin_digest,
                requirement.authority_origin_digest()
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
            run(host)?;
            cases[1] += 1;
            let composition =
                ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
            let host = ErasureExecutionHostV1::open_read_only_with_authority(
                path,
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run(host)?;
            cases[2] += 1;
        }
    }
    assert_eq!(cases, [99; 3]);
    Ok(())
}

fn populate_pair<S: Port>(store: &mut S, world: &World) -> Fallible<[ForkReplayRequirementV1; 2]> {
    let first = populate(store, world, &world.build(&Spec::default())?)?;
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
    let expected_folded = requirements.iter().try_fold(0_usize, |sum, requirement| {
        Ok::<_, Box<dyn std::error::Error>>(
            sum + usize::try_from(requirement.publication_logical_head().as_u64())?,
        )
    })?;
    if fault == Fault::None {
        let diff = result?;
        assert_eq!(diff.fork_seq, Seq::from_u64(PARENT_CUT));
        assert!(!diff.diverged_entities.is_empty());
        assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), expected_folded);
    } else {
        assert_eq!(
            result.map(|_| ()).map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
        assert_eq!(a.state_snapshot(timelines[0])?, before_a);
        assert_eq!(b.state_snapshot(timelines[1])?, before_b);
        if fault.after_folding() {
            assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), expected_folded);
        } else {
            assert_eq!(FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[test]
fn compare_saved_native_evidence_mismatch_refuses_and_releases_both_arms() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    let mut memory = MemoryStore::new();
    let requirements = populate_pair(&mut memory, &world)?;
    assert_ne!(requirements[0], requirements[1]);
    let verifier = Arc::new(ImportedVerifier {
        child: requirements[0].child_timeline_id(),
        parent: world.root,
        requirement: requirements[0],
        secondary: Some((requirements[1].child_timeline_id(), requirements[1])),
        fault: Fault::None,
        fault_target: None,
        limits_override: None,
        admissions: AtomicUsize::new(0),
    });
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier);
    let mut host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
        memory,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let generation = Hash::from_bytes(host.containment_gate().inventory_generation()?.digest());
    let closures = requirements
        .map(|requirement| {
            WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                requirement.child_timeline_id(),
                generation,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    for changed_arm in [0, 1] {
        crate::compare::tests::assert_saved_native_evidence_refused(
            &mut host.read_sender()?,
            requirements,
            [&closures[0], &closures[1]],
            changed_arm,
        )?;
        assert_eq!(host.status(), pos_runtime::ErasureHostStatusV1::Ready);
    }
    // The real public operation must still succeed after both rollback paths.
    compare_on_host(host, requirements, Fault::None)
}

#[test]
fn compare_checks_both_imported_arms_before_folding_and_after_both_folds() -> Fallible<()> {
    for (fault, fault_arm) in [
        Fault::None,
        Fault::Omitted,
        Fault::Foreign,
        Fault::FinalIdentity,
        Fault::FinalRequirements,
        Fault::FinalLimits,
        Fault::NoProfile,
        Fault::UnequalLimits,
        Fault::NodeLimit,
        Fault::RowLimit,
        Fault::ByteLimit,
    ]
    .into_iter()
    .flat_map(|fault| {
        [0, 1]
            .into_iter()
            .filter(move |arm| *arm == 0 || (fault != Fault::None && !fault.global_limits()))
            .map(move |arm| (fault, arm))
    }) {
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
                // Resource refusal must use equal limits on both arms, so it
                // reaches the actual shared ledger rather than only the
                // earlier mismatched-profile rejection. Other faults target
                // each arm independently, including changes after both folds.
                fault_target: if fault.global_limits() {
                    None
                } else {
                    Some(requirements[fault_arm].child_timeline_id())
                },
                limits_override: None,
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
        let composition =
            ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier());
        let host = ErasureExecutionHostV1::open_read_only_with_authority(
            path,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        compare_on_host(host, requirements, fault)?;
    }
    Ok(())
}

/// Deliberately attempt a valid ordinary write on a separate thread and
/// pre-opened connection inside the test verifier, at every admission phase.
/// The reader holds its interval while joining the writer's bounded probe.
/// This is
/// adversarial test instrumentation, not a callback from the attribution
/// bridge or a production verifier qualification.
struct ReservationVerifier {
    inner: ImportedVerifier,
    writer: Mutex<SqliteStore>,
    next: KeyRegistryStateV1,
    refused: AtomicUsize,
}

impl WorldReplayVerifierV1 for ReservationVerifier {
    fn read_profile(
        &self,
        closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        generation: ErasureReferenceV1,
    ) -> Result<(EventReadBounds, ForkReplayReadLimitsV1), WorldReplayVerificationErrorV1> {
        self.inner.read_profile(closure, intent, generation)
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        let reader_thread = std::thread::current().id();
        let refused = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert_ne!(std::thread::current().id(), reader_thread);
                    self.writer
                        .lock()
                        .map(|mut writer| {
                            matches!(
                                writer.save_key_registry(&self.next),
                                Err(CoreError::Storage(_))
                            )
                        })
                        .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)
                })
                .join()
                .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)
        })??;
        if !refused {
            return Err(WorldReplayVerificationErrorV1::EvidenceUnavailable);
        }
        self.refused.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(closure, requested, generation)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ConsumerCall {
    Replay,
    ReplayAt,
    Compare,
}

fn reservation_verifier(
    writer: SqliteStore,
    world: &World,
    requirements: [ForkReplayRequirementV1; 2],
    call: ConsumerCall,
) -> Fallible<(Arc<ReservationVerifier>, KeyRegistryStateV1)> {
    // The owner joins each probe before releasing its reservation, so waiting
    // for that reservation cannot make progress. Still attempt the real write.
    writer.use_nonblocking_writer_for_test()?;
    let before = writer.load_key_registry()?.ok_or("persisted registry")?;
    let identity = world.anchors.first().ok_or("timeline key")?.0;
    let material = before
        .key_record(identity)
        .and_then(|record| record.private_material_digest)
        .ok_or("live timeline material")?;
    let mut next = before.clone();
    next.begin_key_destruction(KeyDestructionRequestV1::new(
        identity,
        material,
        Hash::from_bytes([0x73; 32]),
    ))?;
    next.validate()?;
    let verifier = Arc::new(ReservationVerifier {
        inner: ImportedVerifier {
            child: requirements[0].child_timeline_id(),
            parent: world.root,
            requirement: requirements[0],
            secondary: (call == ConsumerCall::Compare)
                .then_some((requirements[1].child_timeline_id(), requirements[1])),
            fault: Fault::None,
            fault_target: None,
            limits_override: None,
            admissions: AtomicUsize::new(0),
        },
        writer: Mutex::new(writer),
        next,
        refused: AtomicUsize::new(0),
    });
    Ok((verifier, before))
}

#[test]
fn sqlite_protected_consumers_hold_writer_reservation_through_both_phases() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for read_only in [false, true] {
            let mut world = World::new(Shape::Mixed, false)?;
            if call == ConsumerCall::Compare {
                world.add_child(Shape::EmptyUnclassified)?;
            }
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("protected-reservation.sqlite");
            let path = path.to_str().ok_or("utf-8 reservation fixture path")?;
            let mut writer = SqliteStore::open(path)?;
            let requirements = if call == ConsumerCall::Compare {
                populate_pair(&mut writer, &world)?
            } else {
                let requirement = populate(&mut writer, &world, &world.build(&Spec::default())?)?;
                [requirement, requirement]
            };
            let (verifier, before) = reservation_verifier(writer, &world, requirements, call)?;
            let composition = ErasureCoordinatorCompositionV1::closed()
                .with_world_replay_verifier(verifier.clone());
            let host = if read_only {
                ErasureExecutionHostV1::open_read_only_with_authority(
                    path,
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )?
            } else {
                ErasureExecutionHostV1::open_with_authority(
                    StoreConfig::Sqlite {
                        path: path.to_owned(),
                    },
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )?
            };
            match call {
                ConsumerCall::Replay | ConsumerCall::ReplayAt => run_on_host(
                    host,
                    requirements[0].child_timeline_id(),
                    requirements[0].publication_logical_head(),
                    Fault::None,
                    (call == ConsumerCall::ReplayAt).then_some(Seq::from_u64(2)),
                )?,
                ConsumerCall::Compare => compare_on_host(host, requirements, Fault::None)?,
            }
            assert_eq!(
                verifier.refused.load(Ordering::SeqCst),
                if call == ConsumerCall::Compare { 4 } else { 2 }
            );
            let mut writer = verifier
                .writer
                .lock()
                .map_err(|_| "probe writer poisoned")?;
            assert_eq!(writer.load_key_registry()?, Some(before));
            // The very same request succeeds after release, so earlier
            // failures were not a malformed replacement or read-only writer.
            writer.save_key_registry(&verifier.next)?;
            assert_eq!(writer.load_key_registry()?, Some(verifier.next.clone()));
            drop(writer);
        }
    }
    Ok(())
}
