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
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::probe::{self, contained};
use crate::AdapterRunError;

/// How long each task of the task-exhaustion fixture stays alive.
const TASK_LIFETIME: Duration = Duration::from_millis(1_500);
/// The size of one memory-exhaustion allocation.
const MEMORY_CHUNK: usize = 1 << 20;
/// The size of one write of the output and work-area fixtures.
const WRITE_CHUNK: usize = 64 << 10;
/// The work area (`TemporaryFileSystem=/work`).
const WORK_AREA: &str = "/work";
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
pub fn apply(fixture: Fixture, output: &mut impl Write) -> Result<After, AdapterRunError> {
    match fixture {
        Fixture::FilesystemEscape => judge(&probe::filesystem_escape()),
        Fixture::ReadOnlyRootWrite => judge(&probe::read_only_root_write(Path::new("/"))),
        Fixture::NetworkEscape => judge(&probe::network_escape()),
        Fixture::ForeignSignals => judge(&probe::foreign_signals(probe::LAST_PROBED_PID)),
        Fixture::AdapterCrash => Err(AdapterRunError::Crashed),
        Fixture::MalformedOutput => write_all(output, MALFORMED).map(|()| After::Written),
        Fixture::OversizedOutput(bytes) => write_filler(output, bytes).map(|()| After::Written),
        Fixture::OrphanedChild => {
            leave_orphan();
            Ok(After::Report)
        }
        Fixture::WorkAreaExhaustion(bytes) => {
            fill_work_area(Path::new(WORK_AREA), bytes);
            Ok(After::Report)
        }
        Fixture::TaskExhaustion(tasks) => {
            exhaust_tasks(tasks);
            Ok(After::Report)
        }
        Fixture::MemoryExhaustion(bytes) => {
            exhaust_memory(bytes);
            Ok(After::Report)
        }
        Fixture::WatchdogExpiry(milliseconds) | Fixture::Idle(milliseconds) => {
            std::thread::sleep(Duration::from_millis(milliseconds));
            Ok(After::Report)
        }
    }
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

/// Write `bytes` of filler, in chunks, with no frame around them.
fn write_filler(output: &mut impl Write, bytes: u64) -> Result<(), AdapterRunError> {
    let chunk = vec![0x5a_u8; WRITE_CHUNK];
    let mut remaining = bytes;
    while remaining > 0 {
        let length = usize::try_from(remaining).map_or(WRITE_CHUNK, |rest| rest.min(WRITE_CHUNK));
        write_all(output, &chunk[..length])?;
        remaining -= length as u64;
    }
    Ok(())
}

/// Start a detached idle child of this executable and do not wait for it. If
/// it cannot be started there is nothing to orphan.
pub fn leave_orphan() {
    let child = std::env::current_exe().and_then(|executable| {
        Command::new(executable)
            .args(["idle", "600000"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    });
    drop(child);
}

/// Write `bytes` to one file of `area`. A refusal (a full area) is a denied
/// operation, not a failure.
pub fn fill_work_area(area: &Path, bytes: u64) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(area.join("fill"))
        .ok();
    let chunk = vec![0xa5_u8; WRITE_CHUNK];
    let mut remaining = bytes;
    while let (Some(file), true) = (file.as_mut(), remaining > 0) {
        let length = usize::try_from(remaining).map_or(WRITE_CHUNK, |rest| rest.min(WRITE_CHUNK));
        if file.write_all(&chunk[..length]).is_err() {
            break;
        }
        remaining -= length as u64;
    }
}

/// Keep `tasks` threads alive together for [`TASK_LIFETIME`]; stop starting
/// more at the first refusal.
pub fn exhaust_tasks(tasks: u64) {
    let started: Vec<_> = (0..tasks)
        .map_while(|_| {
            std::thread::Builder::new()
                .spawn(|| std::thread::sleep(TASK_LIFETIME))
                .ok()
        })
        .collect();
    for handle in started {
        drop(handle.join());
    }
}

/// Hold `bytes` of memory, one touched chunk at a time.
pub fn exhaust_memory(bytes: u64) {
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut total = 0_u64;
    while total < bytes {
        held.push(vec![0xa5_u8; MEMORY_CHUNK]);
        total += MEMORY_CHUNK as u64;
    }
    std::hint::black_box(&held);
}
