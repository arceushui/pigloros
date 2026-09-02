//! Shell-free process adapter for public subject protocol executables.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter_transport::{decode_observation, encode_attempt};
use crate::evaluator::{AdapterError, CaseAttempt, SubjectAdapter, SubjectObservation};
use crate::evaluator_protocol::SubjectAdapterKind;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TRANSPORT_OVERHEAD_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

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
        let request = encode_attempt(attempt).map_err(|_| AdapterError::ProtocolFailure)?;
        let maximum_response = response_limit(attempt)?;
        let mut child = command(&self.program, &self.arguments)
            .spawn()
            .map_err(|_| AdapterError::Unavailable)?;
        let stdin = child.stdin.take().ok_or(AdapterError::ProtocolFailure)?;
        let stdout = child.stdout.take().ok_or(AdapterError::ProtocolFailure)?;
        let writer = thread::spawn(move || write_request(stdin, &request));
        let reader = thread::spawn(move || read_response(stdout, maximum_response));
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(attempt.watchdog_ms))
            .ok_or(AdapterError::ProtocolFailure)?;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| AdapterError::ProtocolFailure)?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                let _ = reader.join();
                return Err(AdapterError::WatchdogExpired);
            }
            thread::sleep(POLL_INTERVAL);
        };
        let wrote = writer.join().map_err(|_| AdapterError::ProtocolFailure)?;
        let response = reader.join().map_err(|_| AdapterError::ProtocolFailure)?;
        if !status.success() || wrote.is_err() {
            return Err(AdapterError::Unavailable);
        }
        let response = response.map_err(|_| AdapterError::ProtocolFailure)?;
        decode_observation(&response).map_err(|_| AdapterError::ProtocolFailure)
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
    command
}

fn response_limit(attempt: &CaseAttempt) -> Result<usize, AdapterError> {
    let output =
        usize::try_from(attempt.budget.output_bytes).map_err(|_| AdapterError::ProtocolFailure)?;
    output
        .checked_add(TRANSPORT_OVERHEAD_BYTES)
        .map(|value| value.min(MAX_RESPONSE_BYTES))
        .ok_or(AdapterError::ProtocolFailure)
}

fn write_request(mut stdin: std::process::ChildStdin, request: &[u8]) -> std::io::Result<()> {
    stdin.write_all(request)
}

fn read_response(
    mut stdout: std::process::ChildStdout,
    maximum: usize,
) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut oversized = false;
    loop {
        let count = stdout.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if response.len().saturating_add(count) <= maximum {
            response.extend_from_slice(&buffer[..count]);
        } else {
            oversized = true;
        }
    }
    if oversized {
        Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "adapter response exceeds deterministic output authority",
        ))
    } else {
        Ok(response)
    }
}
