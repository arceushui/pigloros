//! Launching one fresh worker subprocess (ADR-061 revision 4, decision 1).
//!
//! The supervisor starts the worker program directly:
//! - with a cleared environment, forwarding only [`FORWARDED_ENVIRONMENT`];
//! - with `/` as its working directory;
//! - with its standard input and output as the only IPC pipes and its
//!   standard error on `/dev/null`. The standard library opens every
//!   descriptor close-on-exec; before each launch the supervisor also marks
//!   close-on-exec every descriptor from 3 upwards that its own process
//!   inherited without that flag. The worker refuses to run if it still
//!   inherited anything else (see [`crate::worker_process`]);
//! - with the supervisor's process ID as its only argument, so the worker can
//!   bind its parent-death signal to it;
//! - with hard and soft rlimit ceilings on CPU time, data (memory), file size
//!   and core size, set through `prlimit` before the request is sent, so no
//!   Component byte reaches the worker before its ceilings hold.
//!
//! No namespace, cgroup or seccomp layer is added (ADR-072).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use rustix::process::{prlimit, Pid, Resource, Rlimit};

use crate::frame::WorkerFrameLimitsV1;
use crate::ipc::MAX_WORKER_COMPONENT_BYTES_V1;

/// Environment variables forwarded to the worker; every other is cleared.
///
/// Production builds forward nothing. Coverage-instrumented builds forward
/// only the LLVM profile path, so an instrumented worker can record its
/// coverage.
#[cfg(not(coverage))]
pub const FORWARDED_ENVIRONMENT: &[&str] = &[];
/// Environment variables forwarded to the worker; every other is cleared.
///
/// Production builds forward nothing. Coverage-instrumented builds forward
/// only the LLVM profile path, so an instrumented worker can record its
/// coverage.
#[cfg(coverage)]
pub const FORWARDED_ENVIRONMENT: &[&str] = &["LLVM_PROFILE_FILE"];

/// Data-segment bytes the worker runtime needs beyond guest memory and the
/// request: the compiled Component, the engine and the process itself.
const WORKER_RUNTIME_DATA_BYTES: u64 = 512 * 1_048_576;
/// CPU seconds granted beyond the whole watchdog seconds, so the wall-time
/// watchdog, not the CPU ceiling, stops a long invocation.
const CPU_MARGIN_SECONDS: u64 = 2;
/// File bytes reserved for the coverage profile: none in production builds.
#[cfg(not(coverage))]
const PROFILE_FILE_BYTES: u64 = 0;
/// File bytes reserved for the coverage profile an instrumented worker writes.
#[cfg(coverage)]
const PROFILE_FILE_BYTES: u64 = 1 << 30;

/// The absolute path of the worker program the supervisor launches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProgramV1 {
    path: PathBuf,
}

impl WorkerProgramV1 {
    /// The worker program at `path`, or `None` for a relative path.
    ///
    /// The path is never resolved through `PATH`, which the worker does not
    /// inherit.
    #[must_use]
    pub fn new(path: PathBuf) -> Option<Self> {
        path.is_absolute().then_some(Self { path })
    }

    /// The absolute program path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The process rlimit ceilings of one worker (hard and soft are equal).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerResourceCeilingsV1 {
    /// `RLIMIT_CPU`, in seconds.
    pub cpu_seconds: u64,
    /// `RLIMIT_DATA`, in bytes.
    ///
    /// Linux charges writable private mappings, including linear memory as
    /// Wasmtime commits it, against this ceiling, but not the inaccessible
    /// address-space reservations that Wasmtime makes for guard regions. An
    /// `RLIMIT_AS` ceiling would refuse those reservations.
    pub data_bytes: u64,
    /// `RLIMIT_FSIZE`, in bytes.
    ///
    /// The worker writes no regular file, but Wasmtime writes each
    /// copy-on-write linear-memory image into an in-memory file, which this
    /// ceiling also bounds. It is the effective guest memory plus the largest
    /// Component.
    pub file_size_bytes: u64,
    /// `RLIMIT_CORE`, in bytes: no core dump carries guest memory.
    pub core_bytes: u64,
}

impl WorkerResourceCeilingsV1 {
    /// The ceilings for one invocation under `limits` and `watchdog`.
    ///
    /// Data covers the effective guest memory, twice the largest request
    /// frame (the frame and its decoded copy) and the worker runtime.
    #[must_use]
    pub const fn for_invocation(limits: &DeterministicBudgetV1, watchdog: Duration) -> Self {
        Self {
            cpu_seconds: watchdog.as_secs().saturating_add(CPU_MARGIN_SECONDS),
            data_bytes: limits
                .memory_bytes
                .saturating_add(2 * WorkerFrameLimitsV1::REQUEST_BYTES as u64)
                .saturating_add(WORKER_RUNTIME_DATA_BYTES),
            file_size_bytes: limits
                .memory_bytes
                .saturating_add(MAX_WORKER_COMPONENT_BYTES_V1 as u64)
                .saturating_add(PROFILE_FILE_BYTES),
            core_bytes: 0,
        }
    }

    const fn entries(&self) -> [(Resource, u64); 4] {
        [
            (Resource::Cpu, self.cpu_seconds),
            (Resource::Data, self.data_bytes),
            (Resource::Fsize, self.file_size_bytes),
            (Resource::Core, self.core_bytes),
        ]
    }
}

/// A launched worker, killed and reaped when dropped.
pub(crate) struct WorkerProcess {
    pub(crate) child: Child,
}

impl WorkerProcess {
    /// Kill the worker, if it still runs, and reap it.
    pub(crate) fn stop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A confined worker and its two IPC pipes.
pub(crate) struct LaunchedWorker {
    pub(crate) process: WorkerProcess,
    pub(crate) stdin: ChildStdin,
    pub(crate) stdout: ChildStdout,
}

/// Start `program` and apply `ceilings` before it receives any request.
///
/// Returns `None` when the program cannot start or a ceiling cannot be set;
/// a started worker is then killed.
pub(crate) fn launch(
    program: &WorkerProgramV1,
    ceilings: &WorkerResourceCeilingsV1,
) -> Option<LaunchedWorker> {
    close_fds::set_fds_cloexec_threadsafe(3, &[]);
    let mut process = WorkerProcess {
        child: command(program).spawn().ok()?,
    };
    let pipes = process.child.stdin.take().zip(process.child.stdout.take());
    pipes
        .filter(|_| confine(&process.child, ceilings))
        .map(|(stdin, stdout)| LaunchedWorker {
            process,
            stdin,
            stdout,
        })
}

fn command(program: &WorkerProgramV1) -> Command {
    let forwarded = FORWARDED_ENVIRONMENT
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)));
    let mut command = Command::new(program.path());
    command
        .arg(std::process::id().to_string())
        .env_clear()
        .envs(forwarded)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

/// Set every ceiling as both the soft and the hard limit of `child`.
fn confine(child: &Child, ceilings: &WorkerResourceCeilingsV1) -> bool {
    let pid = Pid::from_child(child);
    ceilings.entries().into_iter().all(|(resource, value)| {
        let limit = Rlimit {
            current: Some(value),
            maximum: Some(value),
        };
        prlimit(Some(pid), resource, limit).is_ok()
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn only_absolute_programs_are_accepted() {
        assert_eq!(WorkerProgramV1::new(PathBuf::from("worker")), None);
        let program = WorkerProgramV1::new(PathBuf::from("/usr/bin/worker"));
        assert_eq!(
            program.as_ref().map(WorkerProgramV1::path),
            Some(Path::new("/usr/bin/worker"))
        );
    }

    #[test]
    fn ceilings_follow_the_watchdog_and_memory_budget() {
        let limits = DeterministicBudgetV1 {
            memory_bytes: 65_536,
            ..DeterministicBudgetV1::MINIMA
        };
        let ceilings =
            WorkerResourceCeilingsV1::for_invocation(&limits, Duration::from_millis(3_500));
        assert_eq!(ceilings.cpu_seconds, 5);
        let request = WorkerFrameLimitsV1::REQUEST_BYTES as u64;
        assert_eq!(ceilings.data_bytes, 65_536 + 2 * request + 512 * 1_048_576);
        let file_size = 65_536 + 33_554_432 + PROFILE_FILE_BYTES;
        assert_eq!(ceilings.file_size_bytes, file_size);
        assert_eq!(ceilings.core_bytes, 0);
        let entries = ceilings.entries();
        assert_eq!(
            entries.map(|(_, value)| value),
            [5, ceilings.data_bytes, file_size, 0]
        );
        assert_eq!(entries[0].0, Resource::Cpu);
        assert_eq!(entries[1].0, Resource::Data);
        assert_eq!(entries[2].0, Resource::Fsize);
        assert_eq!(entries[3].0, Resource::Core);
        let longest = WorkerResourceCeilingsV1::for_invocation(&limits, Duration::MAX);
        assert_eq!(longest.cpu_seconds, u64::MAX);
    }

    #[test]
    fn a_missing_program_does_not_launch() {
        let program = WorkerProgramV1::new(PathBuf::from("/nonexistent/pigloros-worker"));
        let ceilings = WorkerResourceCeilingsV1::for_invocation(
            &DeterministicBudgetV1::MINIMA,
            Duration::from_secs(1),
        );
        let launched = program.and_then(|program| launch(&program, &ceilings));
        assert!(launched.is_none());
    }
}
