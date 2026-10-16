//! Native setup refusal through each public consumer, before any State install.

use super::*;
use crate::test_support::{closure_for_host, open_exact_host, ordinary_read_profile};
use pos_core::trusted_clock::MonotonicMarkV1;
use pos_core::{CanonicalBytes, EntityId, ErasureReplayClaimV1, Event, EventDraft, Kind};
use pos_runtime::{
    VerifiedWorldReplayV1, WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};

fn ordinary_pair(host: &mut ErasureExecutionHostV1) -> Fallible<([TimelineId; 2], Event)> {
    let mut commands = host.command_sender()?;
    let root = commands.create_timeline("early refusal root")?.id();
    let event = commands
        .append(
            root,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("fixture.event"),
                CanonicalBytes::from_vec(Vec::new()),
            )],
        )?
        .pop()
        .ok_or("missing seed Event")?;
    let a = commands
        .fork_timeline(root, Seq::from_u64(1), "early a")?
        .id();
    let b = commands
        .fork_timeline(root, Seq::from_u64(1), "early b")?
        .id();
    Ok(([a, b], event))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirstMark {
    Healthy,
    Expired,
    Regressed,
}

impl FirstMark {
    fn clock(self, earlier: ScriptedGuardMonotonicSourceV1, start: MonotonicMarkV1) -> Clock {
        let mut clock = match self {
            Self::Regressed => earlier,
            Self::Healthy => ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]),
            Self::Expired => ScriptedGuardMonotonicSourceV1::new([Duration::from_secs(31)]),
        };
        let mark = clock.mark();
        match self {
            Self::Healthy => assert!(mark
                .checked_elapsed_since(start)
                .is_some_and(|elapsed| elapsed < Duration::from_secs(30))),
            Self::Expired => assert!(mark
                .checked_elapsed_since(start)
                .is_some_and(|elapsed| elapsed > Duration::from_secs(30))),
            Self::Regressed => assert_eq!(mark.checked_elapsed_since(start), None),
        }
        Arc::new(Mutex::new(clock))
    }
}

#[test]
fn every_public_consumer_refuses_an_invalid_first_operation_mark() -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let mut host = open_exact_host();
    let (timelines, event) = ordinary_pair(&mut host)?;
    let closures = timelines.map(|timeline| closure_for_host(&mut host, timeline));
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for first in [FirstMark::Healthy, FirstMark::Expired, FirstMark::Regressed] {
            let mut a = fixture.registry(host.containment_gate());
            let mut b = fixture.registry(host.containment_gate());
            a.apply_event(timelines[0], &event);
            b.apply_event(timelines[1], &event);
            let before = [a.retained_state_for_test(), b.retained_state_for_test()];
            super::super::FOLDED_EVENTS.store(0, Ordering::SeqCst);
            let phases = Rc::new(RefCell::new(Vec::new()));
            let recorded = Rc::clone(&phases);
            let observer = Rc::new(move |phase| recorded.borrow_mut().push(phase));
            // This origin precedes the real release g0 without a sleep.
            let earlier = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let health = crate::ReleaseHealthV1::new();
            let mut sender = host.read_sender()?;
            let result = with_release_health(&health, |release| {
                let clock = first.clock(earlier, release.guard.guard_started_at());
                let _restore = RestoreClock(CLOCK.with(|slot| slot.replace(Some(clock.clone()))));
                let result = with_replay_observer(observer, || match call {
                    ConsumerCall::Replay => crate::replay(
                        &mut sender,
                        timelines[0],
                        &mut a,
                        &closures[0],
                        release,
                        &fixture.fold(),
                    ),
                    ConsumerCall::ReplayAt => crate::replay_at(
                        &mut sender,
                        timelines[0],
                        Seq::from_u64(1),
                        &mut a,
                        &closures[0],
                        release,
                        &fixture.fold(),
                    ),
                    ConsumerCall::Compare => crate::compare(
                        &mut sender,
                        timelines,
                        Seq::from_u64(1),
                        [&mut a, &mut b],
                        [&closures[0], &closures[1]],
                        release,
                        [&fixture.fold(), &fixture.fold()],
                    )
                    .map(|_| ()),
                });
                if first != FirstMark::Healthy {
                    // One precondition sample, then precisely the constructor
                    // sample: no later budget checkpoint or native fence ran.
                    assert_eq!(test_ok(clock.lock()).samples_taken(), 2);
                }
                result
            });
            if first == FirstMark::Healthy {
                result?;
                assert!(phases.borrow().contains(&Phase::Installed));
                assert_eq!(
                    super::super::FOLDED_EVENTS.load(Ordering::SeqCst),
                    if call == ConsumerCall::Compare { 2 } else { 1 }
                );
            } else {
                assert_eq!(
                    result.map_err(|error| error.to_string()),
                    Err(CoreError::ArtifactUnavailable.to_string())
                );
                assert_eq!(*phases.borrow(), vec![Phase::FailureP2]);
                assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 0);
            }
            assert_eq!(
                [a.retained_state_for_test(), b.retained_state_for_test()],
                before
            );
            assert_eq!(host.status(), ErasureHostStatusV1::Ready);
            assert_eq!(health.guard_release_late(), None);
        }
    }
    Ok(())
}

#[derive(Default)]
struct EarlyVerifier {
    refused_profile: Mutex<Option<TimelineId>>,
    structural: AtomicBool,
    profiles: Mutex<Vec<TimelineId>>,
    admissions: Mutex<Vec<TimelineId>>,
    limits: Mutex<Option<pos_store::ForkReplayReadLimitsV1>>,
}

impl EarlyVerifier {
    fn profile(
        &self,
    ) -> Result<
        (pos_core::EventReadBounds, pos_store::ForkReplayReadLimitsV1),
        WorldReplayVerificationErrorV1,
    > {
        let (bounds, limits) = ordinary_read_profile()?;
        Ok((bounds, test_ok(self.limits.lock()).unwrap_or(limits)))
    }
}

impl WorldReplayVerifierV1 for EarlyVerifier {
    fn read_profile(
        &self,
        _closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        _generation: pos_core::ErasureReferenceV1,
    ) -> Result<
        (pos_core::EventReadBounds, pos_store::ForkReplayReadLimitsV1),
        WorldReplayVerificationErrorV1,
    > {
        test_ok(self.profiles.lock()).push(intent.timeline_id());
        if *test_ok(self.refused_profile.lock()) == Some(intent.timeline_id()) {
            return Err(WorldReplayVerificationErrorV1::EvidenceUnavailable);
        }
        self.profile()
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: pos_core::ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        test_ok(self.admissions.lock()).push(requested.timeline_id());
        Ok(pos_runtime::world_replay::test_verified_world_replay(
            closure,
            requested,
            generation,
            if self.structural.load(Ordering::SeqCst) {
                ErasureReplayClaimV1::StructuralOnly
            } else {
                ErasureReplayClaimV1::Exact
            },
            self.profile()?.1,
        ))
    }
}

#[test]
fn compare_preparation_refuses_each_arm_before_native_fences() -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let verifier = Arc::new(EarlyVerifier::default());
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let mut host = ErasureExecutionHostV1::open_with_authority(
        pos_store::StoreConfig::Memory,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let (timelines, event) = ordinary_pair(&mut host)?;
    let closures = timelines.map(|timeline| closure_for_host(&mut host, timeline));
    for refused in [Some(timelines[0]), Some(timelines[1]), None] {
        *test_ok(verifier.refused_profile.lock()) = refused;
        test_ok(verifier.profiles.lock()).clear();
        test_ok(verifier.admissions.lock()).clear();
        let mut a = fixture.registry(host.containment_gate());
        let mut b = fixture.registry(host.containment_gate());
        a.apply_event(timelines[0], &event);
        b.apply_event(timelines[1], &event);
        let before = [a.retained_state_for_test(), b.retained_state_for_test()];
        super::super::FOLDED_EVENTS.store(0, Ordering::SeqCst);
        let phases = Rc::new(RefCell::new(Vec::new()));
        let recorded = Rc::clone(&phases);
        let observer = Rc::new(move |phase| recorded.borrow_mut().push(phase));
        let mut sender = host.read_sender()?;
        let result = with_replay_observer(observer, || {
            crate::test_support::with_release(|release| {
                crate::compare(
                    &mut sender,
                    timelines,
                    Seq::from_u64(1),
                    [&mut a, &mut b],
                    [&closures[0], &closures[1]],
                    release,
                    [&fixture.fold(), &fixture.fold()],
                )
            })
        });
        let expected_profiles = if refused == Some(timelines[0]) {
            &timelines[..1]
        } else {
            &timelines[..]
        };
        assert_eq!(*test_ok(verifier.profiles.lock()), expected_profiles);
        if refused.is_some() {
            assert_eq!(
                result.map(|_| ()).map_err(|error| error.to_string()),
                Err(CoreError::ArtifactUnavailable.to_string())
            );
            assert!(test_ok(verifier.admissions.lock()).is_empty());
            assert_eq!(*phases.borrow(), vec![Phase::FailureP2]);
            assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        } else {
            assert!(result?.diverged_entities.is_empty());
            assert_eq!(
                *test_ok(verifier.admissions.lock()),
                vec![timelines[0], timelines[1], timelines[0], timelines[1]]
            );
            assert!(phases.borrow().contains(&Phase::Installed));
            assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 2);
        }
        assert_eq!(
            [a.retained_state_for_test(), b.retained_state_for_test()],
            before
        );
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
    Ok(())
}

#[test]
fn replay_refuses_a_structural_admission_before_folding() -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let verifier = Arc::new(EarlyVerifier::default());
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let mut host = ErasureExecutionHostV1::open_with_authority(
        pos_store::StoreConfig::Memory,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let (timelines, event) = ordinary_pair(&mut host)?;
    let closure = closure_for_host(&mut host, timelines[0]);
    // Reuse the valid immutable history to isolate Time's own authority check
    // from the later Runtime Event reader and fold/install barriers.
    for structural in [true, false] {
        verifier.structural.store(structural, Ordering::SeqCst);
        test_ok(verifier.admissions.lock()).clear();
        let mut registry = fixture.registry(host.containment_gate());
        registry.apply_event(timelines[0], &event);
        let before = registry.retained_state_for_test();
        super::super::FOLDED_EVENTS.store(0, Ordering::SeqCst);
        let mut sender = host.read_sender()?;
        let result = crate::test_support::with_release(|release| {
            crate::replay(
                &mut sender,
                timelines[0],
                &mut registry,
                &closure,
                release,
                &fixture.fold(),
            )
        });
        if structural {
            assert_eq!(
                result.map_err(|error| error.to_string()),
                Err(CoreError::ArtifactUnavailable.to_string())
            );
            assert_eq!(*test_ok(verifier.admissions.lock()), vec![timelines[0]]);
            assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        } else {
            result?;
            assert_eq!(*test_ok(verifier.admissions.lock()), vec![timelines[0]; 2]);
            assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 1);
        }
        assert_eq!(registry.retained_state_for_test(), before);
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
    Ok(())
}

fn probe_observed_heads(
    host: &mut ErasureExecutionHostV1,
    timelines: [TimelineId; 2],
    closures: &[WorldReplayClosureV1; 2],
    limits: pos_store::ForkReplayReadLimitsV1,
    expected_heads: usize,
) -> Fallible<()> {
    let mut sender = host.read_sender()?;
    let mut prepared = Vec::new();
    for (timeline, closure) in timelines.into_iter().zip(closures) {
        let intent = pos_runtime::WorldReplayReadIntentV1::new(
            timeline,
            ErasureProtectedOperationV1::Export,
            SeqRange::all(),
            vec!["count".to_owned()],
            Vec::new(),
        )?;
        let selected = sender.prepare_world_replay_read(closure, intent)?;
        assert_eq!(selected.fork_read_limits(), limits);
        prepared.push(selected);
    }
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let started = clock.mark();
    let mut budget = pos_store::ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
    let mut observed = Vec::new();
    let result = sender.with_world_replay_read_fence(
        &[&prepared[0], &prepared[1]],
        &mut budget,
        |sender, budget| {
            for preparation in &prepared {
                let requested = sender.observe_world_replay_use(preparation, budget)?;
                assert_eq!(requested.source_logical_head(), Seq::from_u64(1));
                observed.push(requested.timeline_id());
            }
            Ok(())
        },
        |(), verdict| verdict,
    );
    assert_eq!(observed, timelines[..expected_heads]);
    assert_eq!(
        result,
        if expected_heads == 2 {
            Ok(())
        } else {
            Err(pos_core::ErasureHostErrorV1::AdapterFailure)
        }
    );
    assert_eq!(budget.check_time().is_ok(), expected_heads == 2);
    Ok(())
}

#[test]
fn compare_observed_heads_share_the_fence_visit_budget_in_arm_order() -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let verifier = Arc::new(EarlyVerifier::default());
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let mut host = ErasureExecutionHostV1::open_with_authority(
        pos_store::StoreConfig::Memory,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let (timelines, event) = ordinary_pair(&mut host)?;
    let closures = timelines.map(|timeline| closure_for_host(&mut host, timeline));
    // Each arm's fence reads [child,root], then [root]: three visits.
    // Each observed head traverses [child,root]: two more visits. Thus six
    // funds the entire pair's fence, eight also funds A, and ten funds A+B.
    // These totals follow the two-level history, not measured debit counters.
    for (visits, heads, admissions) in [(6, 0, 0), (8, 1, 0), (10, 2, 2), (1_024, 2, 4)] {
        let limits = pos_store::ForkReplayReadLimitsV1::new(
            8,
            visits,
            262_144,
            256 * 1024 * 1024,
            30_000_000,
        )?;
        *test_ok(verifier.limits.lock()) = Some(limits);
        probe_observed_heads(&mut host, timelines, &closures, limits, heads)?;
        test_ok(verifier.profiles.lock()).clear();
        test_ok(verifier.admissions.lock()).clear();
        let mut a = fixture.registry(host.containment_gate());
        let mut b = fixture.registry(host.containment_gate());
        a.apply_event(timelines[0], &event);
        b.apply_event(timelines[1], &event);
        let before = [a.retained_state_for_test(), b.retained_state_for_test()];
        super::super::FOLDED_EVENTS.store(0, Ordering::SeqCst);
        let mut sender = host.read_sender()?;
        let result = crate::test_support::with_release(|release| {
            crate::compare(
                &mut sender,
                timelines,
                Seq::from_u64(1),
                [&mut a, &mut b],
                [&closures[0], &closures[1]],
                release,
                [&fixture.fold(), &fixture.fold()],
            )
        });
        assert_eq!(*test_ok(verifier.profiles.lock()), timelines);
        let expected_admissions: Vec<_> = timelines.into_iter().cycle().take(admissions).collect();
        assert_eq!(*test_ok(verifier.admissions.lock()), expected_admissions);
        if visits == 1_024 {
            assert!(result?.diverged_entities.is_empty());
            assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 2);
        } else {
            assert_eq!(
                result.map(|_| ()).map_err(|error| error.to_string()),
                Err(CoreError::ArtifactUnavailable.to_string())
            );
            assert_eq!(super::super::FOLDED_EVENTS.load(Ordering::SeqCst), 0);
        }
        assert_eq!(
            [a.retained_state_for_test(), b.retained_state_for_test()],
            before
        );
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
    Ok(())
}

fn refused_begin(call: ConsumerCall, read_only: bool, denied: Connection) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("refused-begin.sqlite");
    let path = path.to_str().ok_or("fixture path")?;
    let mut seed = SqliteStore::open(path)?;
    let requirements = populate_pair(&mut seed, &world)?;
    let timelines = requirements.map(ForkReplayRequirementV1::child_timeline_id);
    let writer = SqliteStore::open(path)?;
    drop(seed);
    let (verifier, before_keys) = reservation_verifier(writer, &world, requirements, call)?;
    let store = if read_only {
        SqliteStore::open_read_only(path)?
    } else {
        SqliteStore::open(path)?
    };
    let record = Arc::new(Mutex::new(Transcript::default()));
    let armed = Arc::new(AtomicBool::new(false));
    let native_record = Arc::clone(&record);
    let native_armed = Arc::clone(&armed);
    store.observe_interval_transactions_for_test(Arc::new(move |connection, operation| {
        if !native_armed.load(Ordering::SeqCst) {
            return true;
        }
        test_ok(native_record.lock())
            .native
            .push((connection, operation));
        !(connection == denied && operation == TransactionOperation::Begin)
    }))?;
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let mut host = ErasureExecutionHostV1::recover_sqlite_fixture_with_authority(
        store,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let gate = host.containment_gate();
    let mut a = fixture.registry(gate.clone());
    let mut b = fixture.registry(gate);
    let before = [a.retained_state_for_test(), b.retained_state_for_test()];
    let invocation = Invocation {
        case: Case {
            call,
            boundary: Boundary::Normal,
            cleanup: Cleanup::Clean,
        },
        timelines,
        closures: closures_for(&host, timelines),
        fixture: &fixture,
        record: Arc::clone(&record),
        writer: None,
    };
    armed.store(true, Ordering::SeqCst);
    let result = test_ok(invocation.run(&mut host, [&mut a, &mut b], false));
    assert_eq!(
        result.map(|_| ()).map_err(|error| error.to_string()),
        Err(CoreError::ArtifactUnavailable.to_string()),
    );
    assert_eq!(
        [a.retained_state_for_test(), b.retained_state_for_test()],
        before
    );
    assert_eq!(host.status(), ErasureHostStatusV1::Poisoned);
    assert!(host.read_sender().is_err());
    assert!(host.command_sender().is_err());
    {
        let record = test_ok(record.lock());
        let expected = if denied == Connection::Writer {
            vec![(Connection::Writer, TransactionOperation::Begin)]
        } else {
            vec![
                (Connection::Writer, TransactionOperation::Begin),
                (Connection::Reader, TransactionOperation::Begin),
                (Connection::Writer, TransactionOperation::Rollback),
            ]
        };
        assert_eq!(record.native, expected);
        assert!(!record.phases.contains(&Phase::Installed));
        assert!(!record.phases.contains(&Phase::Staged));
        assert!(record.phases.contains(&Phase::FailureP2));
        drop(record);
    }
    // Check before dropping the failed host: cleanup, not connection teardown,
    // must release the successfully acquired writer when reader BEGIN fails.
    let mut writer = verifier
        .writer
        .lock()
        .map_err(|_| "writer fixture poisoned")?;
    assert_eq!(writer.load_key_registry()?, Some(before_keys));
    writer.save_key_registry(&verifier.next)?;
    assert_eq!(writer.load_key_registry()?, Some(verifier.next.clone()));
    drop(writer);
    Ok(())
}

#[test]
fn begin_refusal_poison_closes_all_consumers_and_releases_partial_acquisition() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for (read_only, denied) in [
            (false, Connection::Writer),
            (true, Connection::Writer),
            (true, Connection::Reader),
        ] {
            refused_begin(call, read_only, denied)?;
        }
    }
    Ok(())
}
