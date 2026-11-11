//! Restart after a crash at every durable transition of an attempt (#1200).
//!
//! Attempts run through the lifecycle composition over the real registry,
//! the real terminal cleanup, and fake systemd and kernel ports: the planned
//! intent, the attempt and root directories and their PAI2 extension, the
//! activation request marker, the attached root and its PAI3 extension, the
//! unit start, the unit stop, the root release, the removal of both
//! directories, and the intent deleted last.
//!
//! The transitions are not listed by hand. A clean run counts every registry
//! I/O operation (each write, fsync, rename, mkdir, readback, rmdir and
//! unlink) and records every boundary between steps that are not registry
//! I/O (the mount request, the attached root, the unit start, the ended
//! execution, the stopped unit and the released root). A fresh run is then
//! interrupted at each of them in turn:
//!
//! * a crash immediately before an I/O operation, or at a boundary, unwinds
//!   the process without any further I/O, leaving what a real crash leaves:
//!   the disk as it was, a started unit still loaded and an attached root
//!   still mounted;
//! * a failed I/O operation is first handled by the live owner, which must
//!   report cleanup only when it proved all of it and must close itself to
//!   new intents; the process then crashes.
//!
//! Restart reconciliation then runs over what was left. With any one of its
//! applicable proofs withheld it must fail closed, removing nothing while
//! admission stays closed. With every proof given it must remove everything,
//! the intent last, after which admission reopens. The counts are pinned, so
//! an unreviewed new transition fails here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use pos_reference::sandbox_provider_protocol::{RequestAuthority, SandboxExecutionMode};

use super::*;
use crate::test_fixtures::{
    authority, checked_root, fake_root_release, in_lock_test_process, recorded_identity,
    release_fake_root, restart_after_crash, with_io_crash, with_io_fault, CrashSurvivors,
    FakeRootRelease, TeardownFixture, TeardownReset, TeardownStop, TestResult, UncertainProof,
};
use crate::{
    BoundAttemptCgroup, ReleasedAttemptRoot, RestartReconciliationError, TransientServiceUnitName,
    UnitCgroup,
};

const SIM1: [u8; 32] = [9; 32];

/// The registry I/O operations of one clean lifecycle.
const IO_OPERATIONS: usize = 173;

/// A crash boundary between two lifecycle steps that are not registry I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boundary {
    /// The `MountImage` request was sent after its durable marker: loop/dm
    /// devices may exist, nothing is mounted.
    RequestSent,
    /// The root is attached and verified, before its PAI3 record.
    RootAttached,
    /// The unit start was requested, before its cgroup was bound.
    UnitSubmitted,
    /// The execution ended; the unit is still loaded.
    ExecutionEnded,
    /// Terminal cleanup stopped and unloaded the unit; the root is mounted.
    UnitStopped,
    /// The root was detached and its devices observed absent.
    RootReleased,
}

/// The boundaries of one clean lifecycle, in order.
const LIFECYCLE: [Boundary; 6] = [
    Boundary::RequestSent,
    Boundary::RootAttached,
    Boundary::UnitSubmitted,
    Boundary::ExecutionEnded,
    Boundary::UnitStopped,
    Boundary::RootReleased,
];

/// The unwinding payload of a crash at a boundary.
struct BoundaryCrash;

/// The external resources a run holds, and the boundary it crashes at.
#[derive(Debug, Default)]
struct World {
    /// Crash at this boundary occurrence, counted over the whole run.
    crash_at: Option<usize>,
    reached: Mutex<Vec<Boundary>>,
    /// The attempt whose unit is loaded.
    unit: Mutex<Option<[u8; 16]>>,
    /// The attempt whose root is mounted.
    mounted: Mutex<Option<[u8; 16]>>,
}

impl World {
    /// Record `boundary`, and crash there if this occurrence is the one.
    fn reach(&self, boundary: Boundary) {
        lock(&self.reached).push(boundary);
        let occurrence = lock(&self.reached).len() - 1;
        if self.crash_at == Some(occurrence) {
            resume_unwind(Box::new(BoundaryCrash));
        }
    }
}

/// The admission of the attempt `[id; 16]`.
struct CrashInput {
    id: u8,
    world: Arc<World>,
}

/// The attached fixture root of one attempt.
struct CrashRoot {
    fake: FakeRootRelease,
    world: Arc<World>,
}

impl RootRelease for CrashRoot {
    fn release(
        self,
        directory: &PreparedAttemptDirectory,
        deadline: Instant,
    ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_ {
        let Self { fake, world } = self;
        // Terminal cleanup releases the root only after it stopped the unit.
        *lock(&world.unit) = None;
        world.reach(Boundary::UnitStopped);
        async move {
            let released = release_fake_root(fake, directory, deadline).await;
            if released.is_ok() {
                *lock(&world.mounted) = None;
                world.reach(Boundary::RootReleased);
            }
            released
        }
    }
}

impl AdmittedInput for CrashInput {
    type Root = CrashRoot;

    fn attempt_id(&self) -> [u8; 16] {
        [self.id; 16]
    }

    fn sim1_digest(&self) -> [u8; 32] {
        SIM1
    }

    fn grant_digest(&self) -> [u8; 32] {
        [self.id ^ 0xa5; 32]
    }

    fn prepare(
        &self,
        planned: CommittedPlannedAttempt,
    ) -> Result<PreparedAttemptDirectory, SystemdAttemptRegistryError> {
        planned.prepare_fixture_directory()
    }

    fn activate<'a>(
        &'a self,
        directory: &'a PreparedAttemptDirectory,
    ) -> impl Future<Output = Result<CrashRoot, ImageActivationError>> + Send + 'a {
        // As in production, the request is recorded durably before it is
        // sent, and nothing is sent when that record fails.
        let activated = directory
            .record_activation_request()
            .map_err(|_| ImageActivationError::AttachFailure)
            .and_then(|()| {
                self.world.reach(Boundary::RequestSent);
                fake_root_release(directory, true).map_err(|_| ImageActivationError::AttachFailure)
            })
            .map(|fake| {
                *lock(&self.world.mounted) = Some(self.attempt_id());
                self.world.reach(Boundary::RootAttached);
                CrashRoot {
                    fake,
                    world: Arc::clone(&self.world),
                }
            });
        std::future::ready(activated)
    }

    fn attempt(
        &self,
        directory: &PreparedAttemptDirectory,
    ) -> Result<AdmittedAttempt, ExecuteError> {
        AdmittedAttempt::for_test(
            self.attempt_id(),
            authority(),
            SandboxExecutionMode::AirGapped,
        )
        .map(|attempt| attempt.with_execution(directory.execution_ownership()))
        .map_err(|_| ExecuteError::DirectoryIdentity)
    }

    fn recheck(
        &self,
        _root: &CrashRoot,
        directory: &PreparedAttemptDirectory,
    ) -> Result<CheckedRoot, ImageActivationError> {
        // As in production, the root's facts are recorded (PAI3) by the
        // recheck immediately before the unit starts.
        recorded_identity(directory)
            .map_err(|_| ImageActivationError::EvidenceMismatch)
            .and_then(|identity| {
                directory
                    .record_root(&identity, || Ok(()))
                    .map_err(|_| ImageActivationError::EvidenceMismatch)
            })
            .and_then(|()| {
                self.attempt(directory)
                    .map(|attempt| checked_root(&attempt))
                    .map_err(|_| ImageActivationError::EvidenceMismatch)
            })
    }
}

/// The fake execution over one fake systemd manager, and the real terminal
/// cleanup through that manager's transport.
struct CrashSteps<'f> {
    transport: &'f SystemdTransientUnitTransport,
    cgroup: Mutex<Option<BoundAttemptCgroup>>,
    world: Arc<World>,
}

impl AttemptSteps<CrashInput> for CrashSteps<'_> {
    type Launch = ();
    type Started = ();
    type Cgroup = BoundAttemptCgroup;

    fn execute<'a>(
        &'a self,
        (): (),
        input: &'a CrashInput,
        directory: &'a PreparedAttemptDirectory,
        root: &'a CrashRoot,
        _cancel: CancelSignal,
    ) -> impl Future<Output = Executed<(), BoundAttemptCgroup>> + Send + 'a {
        let ownership = directory.execution_ownership();
        // As in production: claim, recheck the root, then request the start.
        let submitted = ownership
            .claim()
            .and_then(|()| {
                input
                    .recheck(root, directory)
                    .map_err(ExecuteError::Recheck)
            })
            .and_then(|_checked| ownership.submit())
            .map_err(|error| ExecuteFailure {
                error,
                unit: UnitState::NotStarted,
                cgroup: None,
            });
        let started = submitted.map(|()| {
            *lock(&self.world.unit) = Some(input.attempt_id());
            self.world.reach(Boundary::UnitSubmitted);
            let taken = lock(&self.cgroup).take();
            taken.map(|cgroup| {
                ownership.bind_cgroup(cgroup.identity());
                self.world.reach(Boundary::ExecutionEnded);
                AttemptExecution {
                    attempt_id: input.attempt_id(),
                    started: (),
                    cgroup,
                    ending: AttemptEnding::CgroupEmpty,
                    network: NetworkEvidence::None,
                }
            })
        });
        let executed: Executed<(), BoundAttemptCgroup> = match started {
            Ok(Some(execution)) => Ok(execution),
            Ok(None) => Err(ExecuteFailure {
                error: ExecuteError::HostTimeout,
                unit: UnitState::Unknown,
                cgroup: None,
            }),
            Err(failure) => Err(failure),
        };
        std::future::ready(executed)
    }

    fn finish(
        &self,
        directory: PreparedAttemptDirectory,
        cgroup: Option<BoundAttemptCgroup>,
        root: Option<CrashRoot>,
        deadlines: AttemptCleanupDeadlines,
    ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + '_
    {
        finish_with(self.transport, directory, cgroup, root, deadlines)
    }
}

/// A private runtime tree, as the provider's `/run/pigloros/sandbox`.
fn runtime() -> TestResult<tempfile::TempDir> {
    let runtime = tempfile::tempdir()?;
    for path in [
        runtime.path().to_path_buf(),
        runtime.path().join("registry"),
        runtime.path().join("attempts"),
    ] {
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(runtime)
}

/// A new registry owner, which admission requires.
fn registry(
    runtime: &Path,
) -> TestResult<Result<SystemdAttemptRegistry, SystemdAttemptRegistryError>> {
    let parent = File::open(runtime)?;
    Ok(SystemdAttemptRegistry::from_runtime_directory(
        &parent,
        parent.metadata()?.uid(),
    ))
}

/// Grace ends at 100 ms, the unit kill at 200 ms, shutdown at 300 ms, the
/// unit is absent by 500 ms and the root released by 700 ms.
fn budget() -> TestResult<CleanupBudget> {
    Ok(CleanupBudget::new(
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_millis(300),
        Duration::from_millis(500),
        Duration::from_millis(700),
    )?)
}

const fn reconcile_request(attempt_id: [u8; 16]) -> SandboxReconcileRequest {
    SandboxReconcileRequest {
        request: RequestAuthority {
            request_id: attempt_id,
            apt1_digest: [1; 32],
            policy_epoch: 6,
            nonce: attempt_id,
        },
        attempt_id,
        agr1_digest: [attempt_id[0] ^ 0xa5; 32],
        request_digest: [4; 32],
    }
}

/// Run attempts 1 to `count` one after another, each to its end.
async fn lives(
    lifecycle: &AttemptLifecycle<CrashInput>,
    count: u8,
    world: &Arc<World>,
) -> TestResult<Vec<EndedAttempt<()>>> {
    let mut ended = Vec::new();
    for id in 1..=count {
        let fixture = TeardownFixture::new(id, TeardownStop::Empty, TeardownReset::Unload).await?;
        let steps = CrashSteps {
            transport: &fixture.transport,
            cgroup: Mutex::new(Some(fixture.bound)),
            world: Arc::clone(world),
        };
        let input = CrashInput {
            id,
            world: Arc::clone(world),
        };
        let owned = lifecycle.admit_input(input)?;
        let budget = budget()?;
        ended.push(Box::pin(owned.run_with(&steps, (), budget)).await);
    }
    Ok(ended)
}

/// Where a run is interrupted.
#[derive(Clone, Copy, Debug)]
enum Interruption {
    /// Nowhere: every attempt runs to its proved cleanup.
    None,
    /// Registry I/O operation `n` fails; the live owner handles it.
    FailsAtIo(usize),
    /// The process crashes immediately before registry I/O operation `n`.
    CrashesAtIo(usize),
    /// The process crashes at boundary occurrence `n`.
    CrashesAtBoundary(usize),
}

/// What a run left behind.
struct Run {
    /// Each attempt's live outcome; `None` when the process crashed.
    ended: Option<Vec<EndedAttempt<()>>>,
    /// The registry I/O operations started.
    ios: usize,
    /// The boundaries reached.
    reached: Vec<Boundary>,
    /// The unit and root still live.
    survivors: CrashSurvivors,
}

/// The value of a run unless it crashed at a boundary.
fn unless_crashed<T>(caught: std::thread::Result<T>) -> Option<T> {
    match caught {
        Ok(value) => Some(value),
        Err(payload) if payload.is::<BoundaryCrash>() => None,
        Err(payload) => resume_unwind(payload),
    }
}

/// Run `count` lifecycles in `runtime`, interrupted by `interruption`, and
/// leave the process state as the crash does.
fn run(runtime: &Path, count: u8, interruption: Interruption) -> TestResult<Run> {
    let tokio = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()?;
    // Opening the owner writes its activation marker before the counted run.
    let ledger = crate::StagingLedger::new(crate::StagingLimits {
        aggregate_bytes: 1024,
    });
    let lifecycle = AttemptLifecycle::new(
        registry(runtime)??,
        ledger,
        &crate::ReconciledRestart::for_test(),
    );
    let crash_at = match interruption {
        Interruption::CrashesAtBoundary(at) => Some(at),
        Interruption::None | Interruption::FailsAtIo(_) | Interruption::CrashesAtIo(_) => None,
    };
    let world = Arc::new(World {
        crash_at,
        ..World::default()
    });
    let live = || tokio.block_on(Box::pin(lives(&lifecycle, count, &world)));
    let (ended, ios) = match interruption {
        Interruption::None => {
            let (ended, ios) = with_io_fault(None, live);
            (Some(ended), ios)
        }
        Interruption::FailsAtIo(at) => {
            let (ended, ios) = with_io_fault(Some(at), live);
            (Some(ended), ios)
        }
        Interruption::CrashesAtIo(at) => with_io_crash(at, live),
        Interruption::CrashesAtBoundary(_) => {
            let (caught, ios) = with_io_fault(None, || catch_unwind(AssertUnwindSafe(live)));
            (unless_crashed(caught), ios)
        }
    };
    let ended = ended.transpose()?;
    let survivors = CrashSurvivors {
        unit: (*lock(&world.unit))
            .map(TransientServiceUnitName::from_attempt_id)
            .transpose()?,
        mounted: *lock(&world.mounted),
    };
    if let (Interruption::FailsAtIo(at), Some(ended)) = (interruption, &ended) {
        assert_live_owner_fails_closed(&lifecycle, ended, &survivors, runtime, at)?;
    }
    let reached = lock(&world.reached).clone();
    // The crash: every in-memory owner is gone.
    drop(lifecycle);
    drop(tokio);
    Ok(Run {
        ended,
        ios,
        reached,
        survivors,
    })
}

/// After a failed operation, the live owner reported an attempt reconciled
/// only when its cleanup left nothing, and it committed no new intent.
fn assert_live_owner_fails_closed(
    lifecycle: &AttemptLifecycle<CrashInput>,
    ended: &[EndedAttempt<()>],
    survivors: &CrashSurvivors,
    runtime: &Path,
    at: usize,
) -> TestResult {
    for attempt in ended {
        let reported = lifecycle.reconcile(&reconcile_request(attempt.attempt_id()));
        match attempt.cleanup() {
            Ok(None) => {
                return Err(format!("operation {at}: a started attempt was withdrawn").into())
            }
            Ok(Some(cleaned)) => {
                assert!(reported.is_ok(), "operation {at}: {reported:?}");
                assert_eq!(*survivors, CrashSurvivors::default(), "operation {at}");
                let key = cleaned.intent().unit_name().attempt_component();
                assert!(
                    !runtime.join("registry").join(key).exists(),
                    "operation {at}"
                );
                assert!(
                    !runtime.join("attempts").join(key).exists(),
                    "operation {at}"
                );
            }
            Err(error) => assert!(
                matches!(reported, Err(AttemptLifecycleError::CleanupFailed)),
                "operation {at}: {error:?} reported as {reported:?}"
            ),
        }
    }
    let refused = lifecycle
        .registry
        .commit_planned(&PlannedAttemptIntent::new([0xee; 16], SIM1)?);
    assert!(
        matches!(
            refused,
            Err(SystemdAttemptRegistryError::ReconciliationRequired)
        ),
        "operation {at}: the failed owner still commits: {refused:?}"
    );
    Ok(())
}

/// Every registry entry with its bytes, and every path below `attempts`.
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    registry: BTreeMap<String, Vec<u8>>,
    attempts: BTreeSet<PathBuf>,
}

fn snapshot(runtime: &Path) -> TestResult<Snapshot> {
    let mut registry = BTreeMap::new();
    for entry in fs::read_dir(runtime.join("registry"))? {
        let entry = entry?;
        registry.insert(
            entry.file_name().to_string_lossy().into_owned(),
            fs::read(entry.path())?,
        );
    }
    let mut attempts = BTreeSet::new();
    let mut pending = vec![runtime.join("attempts")];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            attempts.insert(path.strip_prefix(runtime)?.to_path_buf());
        }
    }
    Ok(Snapshot { registry, attempts })
}

/// The attempt records, without temporary writes or the activation marker.
fn records(snapshot: &Snapshot) -> impl Iterator<Item = (&String, &Vec<u8>)> {
    snapshot
        .registry
        .iter()
        .filter(|(name, _)| !name.starts_with('.') && *name != "activation")
}

/// What one attempt's crash left, in words: an interrupted temporary write,
/// the committed stage, the attempt and root directories, a loaded unit and
/// a mounted root.
fn frontier(snapshot: &Snapshot, survivors: &CrashSurvivors, id: u8) -> TestResult<String> {
    let unit = TransientServiceUnitName::from_attempt_id([id; 16])?;
    let key = unit.attempt_component();
    let attempt = Path::new("attempts").join(key);
    let stage = snapshot
        .registry
        .get(key)
        .and_then(|bytes| bytes.get(..4))
        .map_or_else(
            || "none".to_owned(),
            |tag| String::from_utf8_lossy(tag).into_owned(),
        );
    let words = [
        (
            snapshot.registry.keys().any(|name| name.starts_with('.')),
            "tmp",
        ),
        (true, stage.as_str()),
        (snapshot.attempts.contains(&attempt), "attempt"),
        (snapshot.attempts.contains(&attempt.join("root")), "root"),
        (survivors.unit.is_some(), "unit"),
        (survivors.mounted.is_some(), "mounted"),
    ];
    Ok(words
        .iter()
        .filter(|(present, _)| *present)
        .map(|(_, word)| *word)
        .collect::<Vec<_>>()
        .join(" "))
}

/// The proofs restart reconciliation consults for this crash state.
fn consulted_proofs(snapshot: &Snapshot, survivors: &CrashSurvivors) -> Vec<UncertainProof> {
    let mut proofs = vec![UncertainProof::Network, UncertainProof::ProviderLoops];
    if survivors.unit.is_some() {
        proofs.push(UncertainProof::UnitStop);
    }
    for (name, bytes) in records(snapshot) {
        let tag = bytes.get(..4);
        let root = Path::new("attempts").join(name).join("root");
        if matches!(tag, Some(b"PAI2" | b"PAI3")) && snapshot.attempts.contains(&root) {
            proofs.push(UncertainProof::RootDetach);
        }
        if matches!(tag, Some(b"PAI3")) {
            proofs.push(UncertainProof::RecordedDevices);
        }
    }
    proofs
}

/// Whether `error` is the refusal of the withheld `proof`.
const fn refused_by(proof: UncertainProof, error: &RestartReconciliationError) -> bool {
    match proof {
        UncertainProof::None => false,
        UncertainProof::UnitStop => matches!(error, RestartReconciliationError::UnitStop(_)),
        UncertainProof::RootDetach => matches!(error, RestartReconciliationError::Root(_)),
        UncertainProof::Network => matches!(error, RestartReconciliationError::Network(_)),
        UncertainProof::RecordedDevices => {
            matches!(error, RestartReconciliationError::Devices(None))
        }
        UncertainProof::ProviderLoops => {
            matches!(error, RestartReconciliationError::ProviderLoops(None))
        }
    }
}

/// Restart over what `run` left: with each consulted proof withheld it
/// fails closed and removes nothing, if `withheld`; with every proof given
/// it removes every attempt, and admission reopens.
fn assert_restart_reconciles(run: &Run, runtime: &Path, label: &str, withheld: bool) -> TestResult {
    let tokio = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let crashed = snapshot(runtime)?;
    let proofs = if withheld {
        consulted_proofs(&crashed, &run.survivors)
    } else {
        Vec::new()
    };
    for proof in proofs {
        let refused = tokio.block_on(Box::pin(restart_after_crash(
            runtime,
            &run.survivors,
            proof,
        )))?;
        assert!(
            refused
                .as_ref()
                .err()
                .is_some_and(|error| refused_by(proof, error)),
            "{label}, {proof:?} withheld: {refused:?}"
        );
        assert_eq!(
            snapshot(runtime)?,
            crashed,
            "{label}, {proof:?} withheld: a refused restart removed state"
        );
        // Admission stays closed while anything but the marker remains.
        if crashed.registry.len() > 1 {
            assert!(
                matches!(
                    registry(runtime)?,
                    Err(SystemdAttemptRegistryError::ReconciliationRequired)
                ),
                "{label}, {proof:?} withheld: admission reopened"
            );
        }
    }
    let reconciled = tokio
        .block_on(Box::pin(restart_after_crash(
            runtime,
            &run.survivors,
            UncertainProof::None,
        )))?
        .map_err(|error| format!("{label}: restart with every proof failed: {error:?}"))?;
    let removed = reconciled
        .attempts()
        .iter()
        .map(|intent| intent.unit_name().attempt_component().to_owned())
        .collect::<Vec<_>>();
    let recorded = records(&crashed)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    assert_eq!(removed, recorded, "{label}: reconciled attempts");
    let clean = snapshot(runtime)?;
    assert_eq!(
        clean.registry.keys().collect::<Vec<_>>(),
        ["activation"],
        "{label}: registry after restart"
    );
    assert!(clean.attempts.is_empty(), "{label}: {:?}", clean.attempts);
    // Admission reopens over the reconciled registry.
    registry(runtime)??.commit_planned(&PlannedAttemptIntent::new([0xee; 16], SIM1)?)?;
    Ok(())
}

/// A clean run of `count` lifecycles, with its pinned transition counts.
fn clean_run(count: u8) -> TestResult<Run> {
    let runtime = runtime()?;
    let clean = run(runtime.path(), count, Interruption::None)?;
    let ended = clean.ended.as_ref().ok_or("the clean run crashed")?;
    assert_eq!(ended.len(), usize::from(count));
    for attempt in ended {
        assert!(
            matches!(attempt.cleanup(), Ok(Some(_))),
            "{:?}",
            attempt.cleanup()
        );
    }
    assert_eq!(
        clean.ios,
        IO_OPERATIONS * usize::from(count),
        "registry I/O operations of {count} clean lifecycles: review and count the new transitions"
    );
    assert_eq!(clean.reached, LIFECYCLE.repeat(usize::from(count)));
    assert_eq!(clean.survivors, CrashSurvivors::default());
    let left = snapshot(runtime.path())?;
    assert_eq!(left.registry.keys().collect::<Vec<_>>(), ["activation"]);
    assert!(left.attempts.is_empty());
    Ok(clean)
}

/// Crash or fail at every interruption `at` yields for `count` lifecycles,
/// checking restart over each; returns each crash's frontier of the last
/// attempt, consecutive repeats merged.
fn interrupt_each(
    count: u8,
    interruptions: impl Iterator<Item = Interruption>,
    withheld: bool,
) -> TestResult<Vec<String>> {
    let mut frontiers: Vec<String> = Vec::new();
    for interruption in interruptions {
        let runtime = runtime()?;
        let left = run(runtime.path(), count, interruption)?;
        let label = format!("{interruption:?}");
        match interruption {
            Interruption::CrashesAtIo(at) => {
                assert!(left.ended.is_none(), "{label}: no crash");
                // The crash ran no further registry I/O.
                assert_eq!(left.ios, at + 1, "{label}");
            }
            Interruption::CrashesAtBoundary(at) => {
                assert!(left.ended.is_none(), "{label}: no crash");
                assert_eq!(left.reached.len(), at + 1, "{label}");
            }
            Interruption::FailsAtIo(_) | Interruption::None => {
                assert!(left.ended.is_some(), "{label}: crashed");
            }
        }
        let crashed = snapshot(runtime.path())?;
        let last = records(&crashed)
            .filter_map(|(name, _)| u8::from_str_radix(name.get(..2)?, 16).ok())
            .max()
            .unwrap_or(1);
        let state = frontier(&crashed, &left.survivors, last)?;
        if frontiers.last() != Some(&state) {
            frontiers.push(state.clone());
        }
        assert_restart_reconciles(
            &left,
            runtime.path(),
            &format!("{label} at {state}"),
            withheld,
        )?;
    }
    Ok(frontiers)
}

#[test]
fn a_crash_before_every_registry_operation_reconciles_or_fails_closed() -> TestResult {
    if !in_lock_test_process(
        "lifecycle::attempts::crash_points::a_crash_before_every_registry_operation_reconciles_or_fails_closed",
    )? {
        return Ok(());
    }
    let clean = clean_run(1)?;
    let frontiers = interrupt_each(1, (0..clean.ios).map(Interruption::CrashesAtIo), true)?;
    assert_eq!(
        frontiers,
        [
            // The planned intent: nothing, its interrupted write, then PAI1.
            "none",
            "tmp none",
            "PAI1",
            // mkdir of the attempt, then of its root, before PAI2.
            "PAI1 attempt",
            "PAI1 attempt root",
            "tmp PAI1 attempt root",
            "PAI2 attempt root",
            // The activation marker's interrupted write.
            "tmp PAI2 attempt root",
            "PAI2 attempt root",
            // The attached root, its interrupted PAI3 write, then PAI3; the
            // root release verifies the tree with the unit already stopped.
            "PAI2 attempt root mounted",
            "tmp PAI2 attempt root mounted",
            "PAI3 attempt root mounted",
            // The released root, then the root removed with the attempt
            // present (#721), both removed, and the intent deleted last.
            "PAI3 attempt root",
            "PAI3 attempt",
            "PAI3",
            "none",
        ]
    );
    Ok(())
}

#[test]
fn a_crash_at_every_lifecycle_boundary_reconciles_or_fails_closed() -> TestResult {
    if !in_lock_test_process(
        "lifecycle::attempts::crash_points::a_crash_at_every_lifecycle_boundary_reconciles_or_fails_closed",
    )? {
        return Ok(());
    }
    let clean = clean_run(1)?;
    let frontiers = interrupt_each(
        1,
        (0..clean.reached.len()).map(Interruption::CrashesAtBoundary),
        true,
    )?;
    assert_eq!(
        frontiers,
        [
            // The request was sent: any loop device is the sweep's to find.
            "PAI2 attempt root",
            "PAI2 attempt root mounted",
            // A started unit survives until the stop, the root until release.
            "PAI3 attempt root unit mounted",
            "PAI3 attempt root mounted",
            "PAI3 attempt root",
        ]
    );
    Ok(())
}

#[test]
fn a_failure_of_every_registry_operation_is_never_reported_clean() -> TestResult {
    if !in_lock_test_process(
        "lifecycle::attempts::crash_points::a_failure_of_every_registry_operation_is_never_reported_clean",
    )? {
        return Ok(());
    }
    let clean = clean_run(1)?;
    interrupt_each(1, (0..clean.ios).map(Interruption::FailsAtIo), false)?;
    Ok(())
}

#[test]
fn eight_lifecycles_reconcile_after_a_crash_at_every_transition() -> TestResult {
    if !in_lock_test_process(
        "lifecycle::attempts::crash_points::eight_lifecycles_reconcile_after_a_crash_at_every_transition",
    )? {
        return Ok(());
    }
    let clean = clean_run(8)?;
    // Every registry operation of the first and the last attempt, and each
    // operation of the six middle attempts once: its offset picks which of
    // them crashes there. Every boundary of every attempt.
    let io = (0..clean.ios)
        .filter(|at| {
            let (attempt, offset) = (at / IO_OPERATIONS, at % IO_OPERATIONS);
            attempt == 0 || attempt == 7 || attempt == 1 + offset % 6
        })
        .map(Interruption::CrashesAtIo);
    let boundaries = (0..clean.reached.len()).map(Interruption::CrashesAtBoundary);
    interrupt_each(8, io.chain(boundaries), false)?;
    Ok(())
}
