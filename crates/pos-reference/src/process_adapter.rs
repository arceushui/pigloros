//! Shell-free process adapter for public subject protocol executables.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use rustix::process::{kill_process_group, Pid, Signal};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::adapter_transport::{read_observation, write_attempt};
use crate::evaluator::{AdapterError, CaseAttempt, SubjectAdapter, SubjectObservation};
use crate::evaluator_protocol::SubjectAdapterKind;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Out-of-process public adapter identity and executable invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessAdapter {
    kind: SubjectAdapterKind,
    subject_artifact_digest: [u8; 32],
    program: PathBuf,
    arguments: Vec<OsString>,
}

impl ProcessAdapter {
    /// Construct a shell-free adapter command. The executable must be an
    /// absolute path so ambient `PATH` cannot select a different subject.
    ///
    /// # Errors
    /// Returns an identity error for a relative or empty executable path.
    pub fn new(
        kind: SubjectAdapterKind,
        subject_artifact_digest: [u8; 32],
        program: impl Into<PathBuf>,
        arguments: Vec<OsString>,
    ) -> Result<Self, AdapterError> {
        let program = program.into();
        if !program.is_absolute() || program.as_os_str().is_empty() {
            return Err(AdapterError::ProtocolFailure);
        }
        Ok(Self {
            kind,
            subject_artifact_digest,
            program,
            arguments,
        })
    }

    fn invoke(&self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        let started = Instant::now();
        let watchdog = Duration::from_millis(attempt.watchdog_ms);
        let mut child = command(&self.program, &self.arguments)
            .spawn()
            .map_err(|_| AdapterError::Unavailable)?;
        let (stdin, stdout) = child
            .stdin
            .take()
            .zip(child.stdout.take())
            .ok_or(AdapterError::ProtocolFailure)?;
        let (writer_tx, writer_rx) = mpsc::sync_channel(1);
        let (reader_tx, reader_rx) = mpsc::sync_channel(1);
        let writer_worker = writer_tx.clone();
        let reader_worker = reader_tx.clone();
        let request = attempt.clone();
        let maximum_output = attempt.budget.output_bytes;
        let _writer = thread::spawn(move || {
            let _ignored = writer_worker.send(write_attempt(stdin, &request));
        });
        let _reader = thread::spawn(move || {
            let _ignored = reader_worker.send(read_observation(stdout, maximum_output));
        });
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| AdapterError::ProtocolFailure)?
            {
                break status;
            }
            if started.elapsed() >= watchdog {
                terminate(&mut child);
                return Err(AdapterError::WatchdogExpired);
            }
            thread::sleep(POLL_INTERVAL);
        };
        let wrote = receive_before(&writer_rx, started, watchdog).inspect_err(|_| {
            terminate(&mut child);
        })?;
        drop(writer_tx);
        let response = receive_before(&reader_rx, started, watchdog).inspect_err(|_| {
            terminate(&mut child);
        })?;
        drop(reader_tx);
        if !status.success() || wrote.is_err() {
            return Err(AdapterError::Unavailable);
        }
        response.map_err(|_| AdapterError::ProtocolFailure)
    }
}

impl SubjectAdapter for ProcessAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        self.kind
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_artifact_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.invoke(attempt)
    }
}

fn command(program: &Path, arguments: &[OsString]) -> Command {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    #[cfg(unix)]
    command.process_group(0);
    command
}

fn receive_before<T>(
    receiver: &mpsc::Receiver<T>,
    started: Instant,
    watchdog: Duration,
) -> Result<T, AdapterError> {
    let remaining = watchdog.saturating_sub(started.elapsed());
    receiver
        .recv_timeout(remaining)
        .map_err(|_| AdapterError::WatchdogExpired)
}

#[cfg(unix)]
fn terminate(child: &mut std::process::Child) {
    let process_group = Pid::from_child(child);
    kill_process_group(process_group, Signal::KILL).unwrap_or(());
    child.kill().unwrap_or(());
    drop(child.wait());
}

#[cfg(not(unix))]
fn terminate(child: &mut std::process::Child) {
    drop(child.kill());
    drop(child.wait());
}
