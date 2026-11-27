//! The #216 malicious and limit fixtures (ADR-069 section 9).
//!
//! Each fixture is one adapter behavior that the provider's conformance suite
//! binds to one public outcome. A probe fixture attempts the forbidden
//! operations of [`crate::probe`] and then reports honestly only if every one
//! was denied; otherwise it fails with [`AdapterRunError::Escaped`], which the
//! provider sees as a crashed adapter and not as a contained one. A limit
//! fixture runs past its bound and, if the sandbox does not stop it, goes on
//! to report honestly, so an unenforced limit shows as a completed attempt.
//! Every bound is an argument, so the host tests use tiny ones.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use pos_reference::adapter_transport::write_attempt;
use pos_reference::evaluator::CaseAttempt;

use crate::probe::{self, contained, Targets};
use crate::AdapterRunError;

/// How long each task of the task-exhaustion fixture stays alive.
const TASK_LIFETIME: Duration = Duration::from_millis(1_500);
/// How long the orphan idles, in milliseconds: far past any attempt.
const ORPHAN_MILLISECONDS: &str = "600000";
/// The size of one memory-exhaustion allocation.
const MEMORY_CHUNK: usize = 1 << 20;
/// The byte of the oversized-output filler.
const OUTPUT_FILLER: u8 = 0x5a;
/// The byte of the work-area and memory fillers.
const HELD_FILLER: u8 = 0xa5;
/// The marker of the malformed-output fixture: not an EAO1 stream.
const MALFORMED: &[u8] = b"not an EAO1 stream\n";

/// One fixture. A bound is always nonzero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fixture {
    /// Open host paths, the cgroup tree and a mount.
    FilesystemEscape,
    /// Write to the read-only root.
    ReadOnlyRootWrite,
    /// Write this many bytes to the work area.
    WorkAreaExhaustion(u64),
    /// Open raw, packet, TCP, UDP and Unix sockets.
    NetworkEscape,
    /// Signal every other process ID.
    ForeignSignals,
    /// Leave a detached child behind.
    OrphanedChild,
    /// Keep this many tasks alive at once.
    TaskExhaustion(u64),
    /// Hold this many bytes of touched memory.
    MemoryExhaustion(u64),
    /// Sleep this many milliseconds.
    WatchdogExpiry(u64),
    /// Write this many bytes to standard output before any frame.
    OversizedOutput(u64),
    /// Fail at once.
    AdapterCrash,
    /// Write bytes that are not an EAO1 stream.
    MalformedOutput,
    /// Sleep this many milliseconds, then exit (the orphan's own mode).
    Idle(u64),
}

/// What the run does after a fixture's effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum After {
    /// Report the honest observation.
    Report,
    /// The fixture wrote the whole of standard output itself.
    Written,
}

impl Fixture {
    /// The fixture's bound, for the fixtures that take one.
    #[must_use]
    pub const fn bound(self) -> Option<u64> {
        match self {
            Self::WorkAreaExhaustion(bound)
            | Self::TaskExhaustion(bound)
            | Self::MemoryExhaustion(bound)
            | Self::WatchdogExpiry(bound)
            | Self::OversizedOutput(bound)
            | Self::Idle(bound) => Some(bound),
            _ => None,
        }
    }

    /// This fixture with the argument-vector bound: a bound is required
    /// exactly by the fixtures that take one, and is never zero. The bound of
    /// a table row is a placeholder that the parsed bound replaces.
    #[must_use]
    pub const fn with_bound(self, bound: Option<u64>) -> Option<Self> {
        match (self, bound) {
            (Self::WorkAreaExhaustion(_), Some(value)) if value != 0 => {
                Some(Self::WorkAreaExhaustion(value))
            }
            (Self::TaskExhaustion(_), Some(value)) if value != 0 => {
                Some(Self::TaskExhaustion(value))
            }
            (Self::MemoryExhaustion(_), Some(value)) if value != 0 => {
                Some(Self::MemoryExhaustion(value))
            }
            (Self::WatchdogExpiry(_), Some(value)) if value != 0 => {
                Some(Self::WatchdogExpiry(value))
            }
            (Self::OversizedOutput(_), Some(value)) if value != 0 => {
                Some(Self::OversizedOutput(value))
            }
            (Self::Idle(_), Some(value)) if value != 0 => Some(Self::Idle(value)),
            (
                Self::FilesystemEscape
                | Self::ReadOnlyRootWrite
                | Self::NetworkEscape
                | Self::ForeignSignals
                | Self::OrphanedChild
                | Self::AdapterCrash
                | Self::MalformedOutput,
                None,
            ) => Some(self),
            _ => None,
        }
    }
}

/// Run the fixture's effect, writing to `output` where the fixture owns
/// standard output.
///
/// # Errors
/// [`AdapterRunError::Escaped`] when a probe fixture's operation succeeded,
/// [`AdapterRunError::Crashed`] for the crash fixture and
/// [`AdapterRunError::Output`] when the fixture's own output cannot be written.
pub fn apply(
    fixture: Fixture,
    attempt: &CaseAttempt,
    targets: &Targets<'_>,
    output: &mut impl Write,
) -> Result<After, AdapterRunError> {
    match fixture {
        Fixture::FilesystemEscape => judge(&probe::filesystem_escape(targets)),
        Fixture::ReadOnlyRootWrite => judge(&probe::read_only_root_write(Path::new(targets.root))),
        Fixture::NetworkEscape => judge(&probe::network_escape(targets)),
        Fixture::ForeignSignals => judge(&probe::foreign_signals(targets.last_pid)),
        Fixture::AdapterCrash => Err(AdapterRunError::Crashed),
        Fixture::MalformedOutput => write_all(output, MALFORMED).map(|()| After::Written),
        Fixture::OversizedOutput(bytes) => write_filler(output, bytes).map(|()| After::Written),
        Fixture::OrphanedChild => Ok(then_report(leave_own_orphan(attempt))),
        Fixture::WorkAreaExhaustion(bytes) => {
            Ok(then_report(fill_work_area(Path::new(targets.work), bytes)))
        }
        Fixture::TaskExhaustion(tasks) => Ok(then_report(exhaust_tasks(tasks, TASK_LIFETIME))),
        Fixture::MemoryExhaustion(bytes) => Ok(then_report(exhaust_memory(bytes))),
        Fixture::WatchdogExpiry(milliseconds) | Fixture::Idle(milliseconds) => {
            std::thread::sleep(Duration::from_millis(milliseconds));
            Ok(After::Report)
        }
    }
}

/// Whatever the effect did, refused or complete, the run goes on to report
/// honestly.
///
/// This is deliberate: an adapter's own report never tells an enforced limit
/// from an unenforced one. The kernel evidence does (ADR-069 section 8): the
/// `pids.events.local` `max` delta ends a task-exhaustion attempt with
/// `TaskLimit` whatever the adapter then exits with (it outranks
/// `ProcessCrash`), and the `/work` capacity read-back (ELM1 limit 9) shows the
/// work area's ceiling, while a refused `/work` write (`ENOSPC`) is a denied
/// operation that ends the attempt `Completed`, as the conformance suite
/// expects of a contained adapter. An adapter that ended differently on a
/// refusal would turn the contained work-area case into a failure.
fn then_report<T>(_effect: T) -> After {
    After::Report
}

/// Report honestly if every attempt was denied.
///
/// # Errors
/// [`AdapterRunError::Escaped`] when any attempt succeeded or none was made.
pub fn judge(attempts: &[probe::Attempt]) -> Result<After, AdapterRunError> {
    if contained(attempts) {
        Ok(After::Report)
    } else {
        Err(AdapterRunError::Escaped)
    }
}

fn write_all(output: &mut impl Write, bytes: &[u8]) -> Result<(), AdapterRunError> {
    output
        .write_all(bytes)
        .and_then(|()| output.flush())
        .or(Err(AdapterRunError::Output))
}

/// Write exactly `bytes` of filler with no frame around them.
fn write_filler(output: &mut impl Write, bytes: u64) -> Result<(), AdapterRunError> {
    io::copy(&mut io::repeat(OUTPUT_FILLER).take(bytes), output)
        .and_then(|_| output.flush())
        .or(Err(AdapterRunError::Output))
}

/// [`leave_orphan`] with this executable.
fn leave_own_orphan(attempt: &CaseAttempt) -> Option<u32> {
    std::env::current_exe()
        .ok()
        .and_then(|executable| leave_orphan(&executable, attempt))
}

/// Start a detached idle child of `executable`, hand it `attempt` on its
/// standard input, do not wait for it, and return its process ID.
///
/// The child is the adapter in its idle mode, which reads one EAI1 attempt
/// before it idles, so it needs the attempt to outlive its parent. If it
/// cannot be started or fed there is nothing to orphan.
#[must_use]
pub fn leave_orphan(executable: &Path, attempt: &CaseAttempt) -> Option<u32> {
    Command::new(executable)
        .args(["idle", ORPHAN_MILLISECONDS])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut child| {
            if feed(&mut child, attempt).is_some() {
                Some(child.id())
            } else {
                // It was not fed, so it would only fail and linger as a zombie.
                child.kill().ok();
                child.wait().ok();
                None
            }
        })
}

/// Write `attempt` to the child's standard input and close it.
fn feed(child: &mut Child, attempt: &CaseAttempt) -> Option<()> {
    child
        .stdin
        .take()
        .and_then(|mut stdin| write_attempt(&mut stdin, attempt).ok())
}

/// Write `bytes` to one file of `area` and return how many were written.
///
/// # Errors
/// Fails when the file cannot be created or the area refuses the write. Either
/// is a denied operation of the fixture, not a failure of the run.
pub fn fill_work_area(area: &Path, bytes: u64) -> io::Result<u64> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(area.join("fill"))
        .and_then(|mut file| io::copy(&mut io::repeat(HELD_FILLER).take(bytes), &mut file))
}

/// Keep `tasks` threads alive together for `lifetime`, stop starting more at
/// the first refusal, and return how many were started.
#[must_use]
pub fn exhaust_tasks(tasks: u64, lifetime: Duration) -> usize {
    let started: Vec<_> = (0..tasks)
        .map_while(|_| {
            std::thread::Builder::new()
                .spawn(move || std::thread::sleep(lifetime))
                .ok()
        })
        .collect();
    let count = started.len();
    for handle in started {
        drop(handle.join());
    }
    count
}

/// Hold `bytes` of touched memory, rounded up to whole `MEMORY_CHUNK`s, and
/// return how many bytes are held.
///
/// The allocation is deliberate and unbounded by the process itself: only the
/// sandbox's memory limit stops it, which is what the fixture proves. A host
/// test must use a small `bytes`.
#[must_use]
pub fn exhaust_memory(bytes: u64) -> u64 {
    let held: Vec<Vec<u8>> = (0..bytes.div_ceil(MEMORY_CHUNK as u64))
        .map(|_| vec![HELD_FILLER; MEMORY_CHUNK])
        .collect();
    std::hint::black_box(&held);
    held.iter().map(|chunk| chunk.len() as u64).sum()
}
