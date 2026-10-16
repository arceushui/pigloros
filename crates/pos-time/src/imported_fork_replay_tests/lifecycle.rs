//! ADR-118 r4 witnesses through the public Time entrypoints and real `SQLite`.

use super::fixture::{Fallible, Shape, World, PARENT_CUT};
use super::{
    count, populate_pair, reservation_verifier, ConsumerCall, Count, Fault, ImportedVerifier,
    ReservationVerifier,
};
use crate::test_support::{test_ok, with_release_health, ProtectedFixture};
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    CoreError, ErasureProtectedOperationV1, ErasureRecoveryLimitsV1, Hash, Seq, StateRegistry,
    TimelineId, WorldReplayClosureV1,
};
use pos_runtime::{
    world_replay::test_support::{with_replay_observer, ReplayPhaseV1 as Phase},
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, ErasureHostStatusV1,
    ErasureReadSenderV1,
};
use pos_state::ProjectionRegistry;
use pos_store::{
    memory::MemoryStore,
    sqlite::{
        interval_test_support::{IntervalConnectionV1 as Connection, TransactionOperation},
        SqliteStore,
    },
    ForkReplayRequirementV1,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

type Clock = Arc<Mutex<ScriptedGuardMonotonicSourceV1>>;
type Snapshot = HashMap<String, StateRegistry>;

thread_local! {
    static CLOCK: RefCell<Option<Clock>> = const { RefCell::new(None) };
}

/// Returns the scripted clock installed for the current lifecycle test.
#[must_use]
pub fn operation_clock() -> Option<Clock> {
    CLOCK.with(|slot| slot.borrow().clone())
}

struct RestoreClock(Option<Clock>);

impl Drop for RestoreClock {
    fn drop(&mut self) {
        CLOCK.with(|slot| slot.replace(self.0.take()));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boundary {
    Normal,
    FinalClock,
    PostMoveClock,
    CleanupClock,
    PanicStaged,
    PanicBeforeComplete,
}

impl Boundary {
    const fn panics(self) -> bool {
        matches!(self, Self::PanicStaged | Self::PanicBeforeComplete)
    }

    const fn installs(self) -> bool {
        matches!(
            self,
            Self::Normal | Self::PostMoveClock | Self::CleanupClock
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cleanup {
    Clean,
    Reader,
    Writer,
    Both,
}

#[derive(Clone, Copy)]
struct Case {
    call: ConsumerCall,
    boundary: Boundary,
    cleanup: Cleanup,
}

struct Invocation<'a> {
    case: Case,
    timelines: [TimelineId; 2],
    closures: [WorldReplayClosureV1; 2],
    fixture: &'a ProtectedFixture,
    record: Arc<Mutex<Transcript>>,
    writer: Option<Arc<ReservationVerifier>>,
}

fn closures_for(
    host: &ErasureExecutionHostV1,
    timelines: [TimelineId; 2],
) -> [WorldReplayClosureV1; 2] {
    let generation = test_ok(host.containment_gate().inventory_generation());
    timelines.map(|timeline| {
        test_ok(
            WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                timeline,
                Hash::from_bytes(generation.digest()),
            ),
        )
    })
}

#[derive(Default)]
struct Transcript {
    phases: Vec<Phase>,
    native: Vec<(Connection, TransactionOperation)>,
    denied_reader: bool,
    denied_writer: bool,
    writer_probes: usize,
    writer_escapes: usize,
}

fn writer_is_denied(verifier: &ReservationVerifier) -> bool {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                verifier.writer.lock().is_ok_and(|mut writer| {
                    matches!(
                        writer.save_key_registry(&verifier.next),
                        Err(CoreError::Storage(_))
                    )
                })
            })
            .join()
            .unwrap_or(false)
    })
}

fn probe_writer(record: &Mutex<Transcript>, verifier: &ReservationVerifier) {
    let denied = writer_is_denied(verifier);
    let mut record = test_ok(record.lock());
    record.writer_probes += 1;
    record.writer_escapes += usize::from(!denied);
}

const fn deny_cleanup(record: &mut Transcript, connection: Connection, cleanup: Cleanup) -> bool {
    match connection {
        Connection::Reader if matches!(cleanup, Cleanup::Reader | Cleanup::Both) => {
            !std::mem::replace(&mut record.denied_reader, true)
        }
        Connection::Writer if matches!(cleanup, Cleanup::Writer | Cleanup::Both) => {
            !std::mem::replace(&mut record.denied_writer, true)
        }
        _ => false,
    }
}

fn install_native_observer(
    store: &SqliteStore,
    record: Arc<Mutex<Transcript>>,
    armed: Arc<AtomicBool>,
    verifier: Arc<ReservationVerifier>,
    cleanup: Cleanup,
) -> Fallible<()> {
    store.observe_interval_transactions_for_test(Arc::new(move |connection, operation| {
        if !armed.load(Ordering::SeqCst) {
            return true;
        }
        let deny = match record.lock() {
            Ok(mut record) => {
                record.native.push((connection, operation));
                operation == TransactionOperation::Rollback
                    && deny_cleanup(&mut record, connection, cleanup)
            }
            Err(_) => return false,
        };
        if operation == TransactionOperation::Rollback {
            // This callback is SQLite's actual pre-ROLLBACK authorizer, not
            // an approximation of the Runtime settlement boundary.
            probe_writer(&record, &verifier);
        }
        !deny
    }))?;
    Ok(())
}

fn observe_phase(
    phase: Phase,
    record: &Mutex<Transcript>,
    clock: &Clock,
    boundary: Boundary,
    writer: Option<&ReservationVerifier>,
) {
    test_ok(record.lock()).phases.push(phase);
    if matches!(
        phase,
        Phase::BeforeComplete | Phase::Installed | Phase::BeforeRollback
    ) {
        if let Some(writer) = writer {
            probe_writer(record, writer);
        }
    }
    if matches!(
        (boundary, phase),
        (Boundary::FinalClock, Phase::Staged)
            | (Boundary::PostMoveClock, Phase::Installed)
            | (Boundary::CleanupClock, Phase::BeforeRollback)
    ) {
        test_ok(clock.lock()).push(Duration::from_secs(31));
    }
    if matches!(
        (boundary, phase),
        (Boundary::PanicStaged, Phase::Staged)
            | (Boundary::PanicBeforeComplete, Phase::BeforeComplete)
    ) {
        std::panic::resume_unwind(Box::new("replay lifecycle witness"));
    }
}

impl Invocation<'_> {
    fn run(
        &self,
        host: &mut ErasureExecutionHostV1,
        registries: [&mut ProjectionRegistry; 2],
        held_memory: bool,
    ) -> std::thread::Result<Result<Option<crate::ForkDiff>, CoreError>> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sender = test_ok(host.read_sender());
            if held_memory {
                let [a, b] = registries;
                let mut result = None;
                test_ok(sender.with_protected_effect_fence(
                    self.timelines[0],
                    ErasureProtectedOperationV1::Read,
                    &mut |sender| {
                        result = Some(self.invoke(sender, [&mut *a, &mut *b]));
                        // The real enclosing owner must still exclude writers
                        // after the inner public Time operation returns.
                        probe_writer(
                            &self.record,
                            test_ok(self.writer.as_deref().ok_or("writer")),
                        );
                    },
                ));
                test_ok(result.ok_or("public Time result"))
            } else {
                self.invoke(&mut sender, registries)
            }
        }))
    }

    fn invoke(
        &self,
        sender: &mut ErasureReadSenderV1<'_>,
        registries: [&mut ProjectionRegistry; 2],
    ) -> Result<Option<crate::ForkDiff>, CoreError> {
        let Case { call, boundary, .. } = self.case;
        let timelines = self.timelines;
        let closures = &self.closures;
        let fixture = self.fixture;
        let health = crate::ReleaseHealthV1::new();
        with_release_health(&health, |release| {
            // Construct after g0 so the first scripted sample cannot regress.
            let mut clock = Arc::new(Mutex::new(ScriptedGuardMonotonicSourceV1::new([
                Duration::ZERO,
            ])));
            let _restore = RestoreClock(CLOCK.with(|slot| slot.replace(Some(Arc::clone(&clock)))));
            let phase_clock = Arc::clone(&clock);
            let phase_record = Arc::clone(&self.record);
            let phase_writer = self.writer.clone();
            let observer = Rc::new(move |phase| {
                observe_phase(
                    phase,
                    &phase_record,
                    &phase_clock,
                    boundary,
                    phase_writer.as_deref(),
                );
            });
            let started = release.guard.guard_started_at();
            let [a, b] = registries;
            let result = with_replay_observer(observer, || match call {
                ConsumerCall::Replay => crate::replay(
                    sender,
                    timelines[0],
                    a,
                    &closures[0],
                    release,
                    &fixture.fold(),
                )
                .map(|()| None),
                ConsumerCall::ReplayAt => crate::replay_at(
                    sender,
                    timelines[0],
                    Seq::from_u64(2),
                    a,
                    &closures[0],
                    release,
                    &fixture.fold(),
                )
                .map(|()| None),
                ConsumerCall::Compare => crate::compare(
                    sender,
                    timelines,
                    Seq::from_u64(PARENT_CUT),
                    [a, b],
                    [&closures[0], &closures[1]],
                    release,
                    [&fixture.fold(), &fixture.fold()],
                )
                .map(Some),
            });
            if matches!(boundary, Boundary::PostMoveClock | Boundary::CleanupClock) {
                assert!(clock
                    .mark()
                    .checked_elapsed_since(started)
                    .is_some_and(|elapsed| elapsed >= Duration::from_secs(31)));
            }
            assert_eq!(health.overrun_signal(), None);
            assert_eq!(health.guard_release_late(), None);
            result
        })
    }
}

fn expected_state(events: &[pos_core::Event]) -> Snapshot {
    let mut registry = StateRegistry::new();
    for event in events {
        registry.apply(&Count, event);
    }
    HashMap::from([("count".to_owned(), registry)])
}

fn expected_pair(
    store: &dyn EventStore,
    timelines: [TimelineId; 2],
    call: ConsumerCall,
) -> Fallible<[Snapshot; 2]> {
    let a = store.read(timelines[0], SeqRange::all())?;
    let b = store.read(timelines[1], SeqRange::all())?;
    Ok([
        expected_state(if call == ConsumerCall::ReplayAt {
            &a[..2]
        } else {
            &a
        }),
        expected_state(&b),
    ])
}

fn assert_transcript(
    record: &Transcript,
    expected_gates: &[TimelineId],
    boundary: Boundary,
    owned: bool,
    arms: usize,
) {
    let mut active = Vec::new();
    for phase in &record.phases {
        match *phase {
            Phase::GateEntered(timeline) => active.push(timeline),
            Phase::GateLeaving(timeline) => assert_eq!(active.pop(), Some(timeline)),
            Phase::Staged | Phase::BeforeComplete | Phase::Installed => {
                assert_eq!(active, expected_gates);
            }
            Phase::BeforeRollback | Phase::AfterRollback if !boundary.panics() => {
                assert_eq!(active, expected_gates);
            }
            _ => {}
        }
    }
    assert!(active.is_empty());
    let count = |expected| {
        record
            .phases
            .iter()
            .filter(|phase| **phase == expected)
            .count()
    };
    assert_eq!(count(Phase::Installed), usize::from(boundary.installs()));
    assert_eq!(count(Phase::BeforeRollback), usize::from(owned));
    assert_eq!(count(Phase::AfterRollback), usize::from(owned));
    assert_eq!(count(Phase::FailureP2), usize::from(!boundary.installs()));
    assert_eq!(
        count(Phase::FailureForget),
        if boundary == Boundary::FinalClock {
            arms
        } else {
            0
        }
    );
    assert_eq!(record.writer_escapes, 0);
}

fn assert_outcome(
    outcome: std::thread::Result<Result<Option<crate::ForkDiff>, CoreError>>,
    host: &mut ErasureExecutionHostV1,
    registries: [&ProjectionRegistry; 2],
    expected: &[Snapshot; 2],
    before: &[Snapshot; 2],
    case: Case,
) {
    let Case {
        call,
        boundary,
        cleanup,
    } = case;
    if boundary.panics() {
        let payload = outcome
            .err()
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing unwind")));
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"replay lifecycle witness")
        );
    } else {
        let result = test_ok(outcome);
        if boundary.installs() {
            let diff = test_ok(result);
            if call == ConsumerCall::Compare {
                let diff = test_ok(diff.ok_or("Compare diff"));
                assert_eq!(diff.fork_seq, Seq::from_u64(PARENT_CUT));
                assert!(!diff.diverged_entities.is_empty());
            } else {
                assert!(diff.is_none());
            }
        } else {
            assert_eq!(
                result.map(|_| ()).map_err(|error| error.to_string()),
                Err(CoreError::ArtifactUnavailable.to_string())
            );
        }
    }
    for (index, registry) in registries.into_iter().enumerate() {
        let installed = boundary.installs() && (index == 0 || call == ConsumerCall::Compare);
        assert_eq!(
            registry.retained_state_for_test(),
            if installed {
                expected[index].clone()
            } else {
                before[index].clone()
            }
        );
    }
    let poisoned = cleanup != Cleanup::Clean || boundary.panics();
    assert_eq!(
        host.status(),
        if poisoned {
            ErasureHostStatusV1::Poisoned
        } else {
            ErasureHostStatusV1::Ready
        }
    );
    if poisoned {
        assert!(host.read_sender().is_err());
        assert!(host.command_sender().is_err());
        assert!(host.containment_gate().inventory_generation().is_err());
    }
}

fn sqlite_case(
    call: ConsumerCall,
    read_only: bool,
    held_memory: bool,
    boundary: Boundary,
    cleanup: Cleanup,
) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    let directory = tempfile::tempdir()?;
    let path = if held_memory {
        format!(
            "file:replay-lifecycle-{}?mode=memory&cache=shared",
            TimelineId::new()
        )
    } else {
        directory
            .path()
            .join("lifecycle.sqlite")
            .to_str()
            .ok_or("fixture path")?
            .to_owned()
    };
    let mut writer = SqliteStore::open(&path)?;
    let requirements = populate_pair(&mut writer, &world)?;
    let timelines = requirements.map(ForkReplayRequirementV1::child_timeline_id);
    let expected = expected_pair(&writer, timelines, call)?;
    writer.use_nonblocking_writer_for_test()?;
    let (verifier, before_keys) = reservation_verifier(writer, &world, requirements, call)?;
    let store = if read_only {
        SqliteStore::open_read_only(&path)?
    } else {
        SqliteStore::open(&path)?
    };
    let record = Arc::new(Mutex::new(Transcript::default()));
    let armed = Arc::new(AtomicBool::new(false));
    install_native_observer(
        &store,
        Arc::clone(&record),
        Arc::clone(&armed),
        Arc::clone(&verifier),
        cleanup,
    )?;
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
    let case = Case {
        call,
        boundary,
        cleanup,
    };
    let invocation = Invocation {
        case,
        timelines,
        closures: closures_for(&host, timelines),
        fixture: &fixture,
        record: Arc::clone(&record),
        writer: Some(Arc::clone(&verifier)),
    };
    armed.store(true, Ordering::SeqCst);
    let outcome = invocation.run(&mut host, [&mut a, &mut b], held_memory);
    assert_outcome(outcome, &mut host, [&a, &b], &expected, &before, case);
    let mut gates = vec![timelines[0], world.root];
    if call == ConsumerCall::Compare {
        gates.extend([timelines[1], world.root]);
    }
    {
        let record = test_ok(record.lock());
        assert_transcript(
            &record,
            &gates,
            boundary,
            !held_memory,
            if call == ConsumerCall::Compare { 2 } else { 1 },
        );
        assert_native_cleanup(&record, read_only, held_memory, cleanup);
    }
    // A failed cleanup may still own native resources; poisoning prevents
    // reuse, and closing that host releases them. Clean release needs no drop.
    if cleanup != Cleanup::Clean {
        drop(host);
    }
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

fn assert_native_cleanup(
    record: &Transcript,
    read_only: bool,
    held_memory: bool,
    cleanup: Cleanup,
) {
    let begins: Vec<_> = record
        .native
        .iter()
        .filter(|(_, op)| *op == TransactionOperation::Begin)
        .map(|(connection, _)| *connection)
        .collect();
    assert_eq!(
        begins,
        if read_only {
            vec![Connection::Writer, Connection::Reader]
        } else {
            vec![Connection::Writer]
        }
    );
    let rollbacks: Vec<_> = record
        .native
        .iter()
        .filter(|(_, op)| *op == TransactionOperation::Rollback)
        .map(|(connection, _)| *connection)
        .collect();
    if held_memory {
        assert!(rollbacks.is_empty());
    } else {
        assert_eq!(
            rollbacks.first(),
            Some(if read_only {
                &Connection::Reader
            } else {
                &Connection::Writer
            })
        );
        assert!(rollbacks.contains(&Connection::Writer));
        assert_eq!(
            record.denied_reader,
            matches!(cleanup, Cleanup::Reader | Cleanup::Both)
        );
        assert_eq!(
            record.denied_writer,
            matches!(cleanup, Cleanup::Writer | Cleanup::Both)
        );
    }
    assert!(record.writer_probes > 0);
}

#[test]
fn sqlite_public_consumers_exclude_writers_through_install_and_native_rollback() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for read_only in [false, true] {
            for boundary in [
                Boundary::Normal,
                Boundary::FinalClock,
                Boundary::PostMoveClock,
                Boundary::CleanupClock,
                Boundary::PanicStaged,
                Boundary::PanicBeforeComplete,
            ] {
                sqlite_case(call, read_only, false, boundary, Cleanup::Clean)?;
            }
        }
    }
    Ok(())
}

#[test]
fn sqlite_cleanup_faults_preserve_installed_success_and_poison_future_work() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for read_only in [false, true] {
            for cleanup in if read_only {
                &[Cleanup::Reader, Cleanup::Writer, Cleanup::Both][..]
            } else {
                &[Cleanup::Writer][..]
            } {
                for boundary in [Boundary::Normal, Boundary::FinalClock] {
                    sqlite_case(call, read_only, false, boundary, *cleanup)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn named_memory_enclosing_owner_retains_its_unowned_interval_through_public_time() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        sqlite_case(call, false, true, Boundary::Normal, Cleanup::Clean)?;
    }
    Ok(())
}

#[test]
fn memory_public_consumers_keep_original_clock_and_unowned_cleanup_semantics() -> Fallible<()> {
    for call in [
        ConsumerCall::Replay,
        ConsumerCall::ReplayAt,
        ConsumerCall::Compare,
    ] {
        for boundary in [
            Boundary::Normal,
            Boundary::FinalClock,
            Boundary::PostMoveClock,
            Boundary::PanicStaged,
            Boundary::PanicBeforeComplete,
        ] {
            let fixture = ProtectedFixture::new("count", count);
            let mut world = World::new(Shape::Mixed, false)?;
            world.add_child(Shape::EmptyUnclassified)?;
            let mut store = MemoryStore::new();
            let requirements = populate_pair(&mut store, &world)?;
            let timelines = requirements.map(ForkReplayRequirementV1::child_timeline_id);
            let expected = expected_pair(&store, timelines, call)?;
            let verifier = Arc::new(ImportedVerifier {
                child: timelines[0],
                parent: world.root,
                requirement: requirements[0],
                secondary: (call == ConsumerCall::Compare)
                    .then_some((timelines[1], requirements[1])),
                fault: Fault::None,
                fault_target: None,
                limits_override: None,
                admissions: AtomicUsize::new(0),
            });
            let composition =
                ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier);
            let mut host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
                store,
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            let gate = host.containment_gate();
            let mut a = fixture.registry(gate.clone());
            let mut b = fixture.registry(gate);
            let before = [a.retained_state_for_test(), b.retained_state_for_test()];
            let record = Arc::new(Mutex::new(Transcript::default()));
            let case = Case {
                call,
                boundary,
                cleanup: Cleanup::Clean,
            };
            let invocation = Invocation {
                case,
                timelines,
                closures: closures_for(&host, timelines),
                fixture: &fixture,
                record: Arc::clone(&record),
                writer: None,
            };
            let outcome = invocation.run(&mut host, [&mut a, &mut b], false);
            assert_outcome(outcome, &mut host, [&a, &b], &expected, &before, case);
            let mut gates = vec![timelines[0], world.root];
            if call == ConsumerCall::Compare {
                gates.extend([timelines[1], world.root]);
            }
            let transcript = test_ok(record.lock());
            assert_transcript(
                &transcript,
                &gates,
                boundary,
                false,
                if call == ConsumerCall::Compare { 2 } else { 1 },
            );
        }
    }
    Ok(())
}
