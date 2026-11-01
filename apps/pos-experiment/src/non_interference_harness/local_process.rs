//! The fresh-process Local runner and its host transport.
//!
//! Every run spawns a new host process with a cleared environment (only the
//! variables declared with
//! [`NonInterferenceLocalProcessRunnerV1::with_env`]) in a working directory
//! of its own: a new empty directory for a cold run, the case's primed
//! directory for a warm run. The runner writes one canonical
//! [`NonInterferenceLocalRequestV1`] to the process's standard input and reads
//! one capture frame (`NLC1`: magic, version, raw capture) from its standard
//! output. The process is host-side: it places the unauthorized value in the
//! row's denied channel and runs the subject on the permitted input. The
//! runner binds the run's provenance (the program bytes, the request and the
//! response) into the capture.
//!
//! The request is written on its own thread while the output is drained, so
//! a process that writes before it reads cannot deadlock the runner. A host
//! kill timeout ([`NonInterferenceLocalProcessRunnerV1::with_timeout`]) bounds
//! every run: a process still running at the deadline is killed and the run
//! is the operational
//! [`NonInterferenceNonExecutedCauseV1::Unavailable`], never `Budget`, which
//! stays reserved for deterministic budgets. Frames are decoded straight into
//! their typed schema; a frame that fails it is `UnknownField` when its
//! top-level or capture keys include a key the schema does not declare, and
//! `Unavailable` otherwise.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use pos_conformance::{
    ExecutionModeV1, NonInterferenceHostRunV1, NonInterferenceRawCaptureV1,
    NonInterferenceVariantV1,
};
use serde::{Deserialize, Serialize};

use super::{
    NonInterferenceModeRunnerV1, NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
};

/// Magic of the request the Local runner writes to a fresh process.
pub const NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1: &str = "NLQ1";
/// Magic of the capture frame a fresh process writes back.
pub const NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1: &str = "NLC1";
/// The default bound on one process's standard output.
pub const DEFAULT_NON_INTERFERENCE_LOCAL_OUTPUT_BUDGET_V1: u64 = 16 * 1024 * 1024;
/// The default host kill timeout of one process.
pub const DEFAULT_NON_INTERFERENCE_LOCAL_TIMEOUT_V1: Duration = Duration::from_secs(120);

const REQUEST_FIELDS_V1: [&str; 8] = [
    "magic",
    "version",
    "fixture_id",
    "variant",
    "mode",
    "preparation",
    "permitted_input",
    "unauthorized_value",
];
const FRAME_FIELDS_V1: [&str; 3] = ["magic", "version", "capture"];
const CAPTURE_FIELDS_V1: [&str; 6] = [
    "surface_names",
    "authoritative",
    "public",
    "operational",
    "unexpected_network_accesses",
    "provenance_digest",
];
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(5);

const PROVENANCE_DOMAIN_V1: &[u8] = b"PiglorOS.NonInterference.LocalProvenance.v1";
const MAX_REQUEST_BYTES_V1: u64 = 8 * 1024 * 1024;

/// The request one fresh process reads from its standard input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceLocalRequestV1 {
    pub magic: String,
    pub version: u16,
    pub fixture_id: String,
    pub variant: NonInterferenceVariantV1,
    pub mode: ExecutionModeV1,
    pub preparation: NonInterferencePreparationV1,
    pub permitted_input: Vec<u8>,
    /// Host-owned: the process places it in the row's denied channel and
    /// never hands it to the subject.
    pub unauthorized_value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureFrameV1 {
    magic: String,
    version: u16,
    capture: NonInterferenceRawCaptureV1,
}

/// Only the capture's keys, every value ignored: the second, structural
/// reading of a frame that failed its schema.
#[derive(Deserialize)]
struct CaptureKeysV1 {
    capture: BTreeMap<String, serde::de::IgnoredAny>,
}

/// The Local runner: one fresh process per run.
#[derive(Debug)]
pub struct NonInterferenceLocalProcessRunnerV1 {
    program: PathBuf,
    program_digest: [u8; 32],
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    work_root: PathBuf,
    warm_directory: PathBuf,
    directories: u64,
    output_budget: u64,
    timeout: Duration,
}

impl NonInterferenceLocalProcessRunnerV1 {
    /// A runner of `program` whose run directories are created below
    /// `work_root`, which must belong to this runner alone: a run directory
    /// that already exists is never reused, and the run is unavailable.
    ///
    /// # Errors
    /// Returns the I/O error when the program bytes cannot be read for its
    /// provenance digest.
    pub fn new(program: PathBuf, work_root: PathBuf) -> std::io::Result<Self> {
        fs::read(&program).map(|bytes| Self {
            program_digest: *blake3::hash(&bytes).as_bytes(),
            program,
            arguments: Vec::new(),
            environment: Vec::new(),
            warm_directory: work_root.clone(),
            work_root,
            directories: 0,
            output_budget: DEFAULT_NON_INTERFERENCE_LOCAL_OUTPUT_BUDGET_V1,
            timeout: DEFAULT_NON_INTERFERENCE_LOCAL_TIMEOUT_V1,
        })
    }

    /// Append one argument to every spawned command.
    #[must_use]
    pub fn with_argument(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Declare one environment variable of every spawned process; no other
    /// variable is inherited.
    #[must_use]
    pub fn with_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.push((name.into(), value.into()));
        self
    }

    /// Bound one process's standard output; a larger output is
    /// [`NonInterferenceNonExecutedCauseV1::Budget`].
    #[must_use]
    pub const fn with_output_budget(mut self, bytes: u64) -> Self {
        self.output_budget = bytes;
        self
    }

    /// Bound one process's run time; a process still running at the
    /// deadline is killed and the run is
    /// [`NonInterferenceNonExecutedCauseV1::Unavailable`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn fresh_directory(&mut self) -> Result<PathBuf, NonInterferenceNonExecutedCauseV1> {
        self.directories += 1;
        let directory = self.work_root.join(format!("run-{}", self.directories));
        fs::create_dir_all(&self.work_root)
            .and_then(|()| fs::create_dir(&directory))
            .map(|()| directory)
            .map_err(NonInterferenceNonExecutedCauseV1::from)
    }

    fn spawn(
        &self,
        directory: &Path,
        request: &[u8],
    ) -> Result<Vec<u8>, NonInterferenceNonExecutedCauseV1> {
        let deadline = Instant::now() + self.timeout;
        let mut child = Command::new(&self.program)
            .args(&self.arguments)
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(NonInterferenceNonExecutedCauseV1::from)?;
        let writer = child.stdin.take().map(|mut stdin| {
            let request = request.to_vec();
            thread::spawn(move || stdin.write_all(&request))
        });
        let (sender, receiver) = mpsc::channel();
        let limit = self.output_budget.saturating_add(1);
        let _reader = child.stdout.take().map(|stdout| {
            thread::spawn(move || {
                let mut output = Vec::new();
                sender
                    .send(stdout.take(limit).read_to_end(&mut output).map(|_| output))
                    .is_ok()
            })
        });
        let budget = self.output_budget;
        let outcome = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| NonInterferenceNonExecutedCauseV1::Unavailable)
            .and_then(|read| read.map_err(NonInterferenceNonExecutedCauseV1::from))
            .and_then(|output| {
                if output.len() as u64 > budget {
                    Err(NonInterferenceNonExecutedCauseV1::Budget)
                } else {
                    Ok(output)
                }
            })
            .and_then(|output| exit_status(&mut child, deadline).map(|status| (output, status)));
        if outcome.is_err() {
            child.kill().and_then(|()| child.wait()).ok();
        }
        let written = writer
            .and_then(|handle| handle.join().ok())
            .is_some_and(|written| written.is_ok());
        outcome.and_then(|(output, status)| {
            if written && status.success() {
                Ok(output)
            } else {
                Err(NonInterferenceNonExecutedCauseV1::Unavailable)
            }
        })
    }

    fn provenance(&self, request: &[u8], response: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVENANCE_DOMAIN_V1);
        hasher.update(&[0]);
        hasher.update(&self.program_digest);
        for value in [request, response] {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        *hasher.finalize().as_bytes()
    }
}

impl NonInterferenceModeRunnerV1 for NonInterferenceLocalProcessRunnerV1 {
    fn mode(&self) -> ExecutionModeV1 {
        ExecutionModeV1::Local
    }

    /// A warm case gets a new directory the priming run and the pair share;
    /// a cold case needs nothing, since every cold run gets its own.
    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        match preparation {
            NonInterferencePreparationV1::Cold => Ok(()),
            NonInterferencePreparationV1::Warm => self
                .fresh_directory()
                .map(|directory| self.warm_directory = directory),
        }
    }

    fn execute(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        let request = NonInterferenceLocalRequestV1 {
            magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
            version: 1,
            fixture_id: run.subject.fixture_id.to_owned(),
            variant: run.subject.variant,
            mode: run.subject.mode,
            preparation,
            permitted_input: run.subject.permitted_input.to_vec(),
            unauthorized_value: run.unauthorized_value.to_vec(),
        };
        let directory = match preparation {
            NonInterferencePreparationV1::Warm => Ok(self.warm_directory.clone()),
            NonInterferencePreparationV1::Cold => self.fresh_directory(),
        }?;
        let request = encode(&request)?;
        let response = self.spawn(&directory, &request)?;
        decode_capture(&response).map(|mut capture| {
            capture.provenance_digest = self.provenance(&request, &response);
            capture
        })
    }
}

/// Serve one Local run in a fresh host process: read the request from
/// `input`, run `subject` on it in the process's working directory and write
/// the capture frame to `output`.
///
/// # Errors
/// Returns the cause when the request is not a canonical `NLQ1` request, the
/// subject does not execute, or the frame cannot be written; the process
/// should then exit non-zero without a frame.
pub fn serve_non_interference_local_subject_v1<R, W, F>(
    input: R,
    mut output: W,
    subject: F,
) -> Result<(), NonInterferenceNonExecutedCauseV1>
where
    R: Read,
    W: Write,
    F: FnOnce(
        &NonInterferenceLocalRequestV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1>,
{
    let mut bytes = Vec::new();
    input
        .take(MAX_REQUEST_BYTES_V1)
        .read_to_end(&mut bytes)
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|_| decode_request(&bytes))
        .and_then(|request| subject(&request))
        .and_then(|capture| {
            encode(&CaptureFrameV1 {
                magic: NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1.to_owned(),
                version: 1,
                capture,
            })
        })
        .and_then(|frame| {
            output
                .write_all(&frame)
                .and_then(|()| output.flush())
                .map_err(NonInterferenceNonExecutedCauseV1::from)
        })
}

fn decode_request(
    bytes: &[u8],
) -> Result<NonInterferenceLocalRequestV1, NonInterferenceNonExecutedCauseV1> {
    decode::<NonInterferenceLocalRequestV1>(bytes, &REQUEST_FIELDS_V1, None).and_then(|request| {
        if request.magic == NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1 && request.version == 1 {
            Ok(request)
        } else {
            Err(NonInterferenceNonExecutedCauseV1::Unsupported)
        }
    })
}

fn decode_capture(
    bytes: &[u8],
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    decode::<CaptureFrameV1>(bytes, &FRAME_FIELDS_V1, Some(&CAPTURE_FIELDS_V1)).and_then(|frame| {
        if frame.magic == NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1 && frame.version == 1 {
            Ok(frame.capture)
        } else {
            Err(NonInterferenceNonExecutedCauseV1::Unsupported)
        }
    })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NonInterferenceNonExecutedCauseV1> {
    pos_crypto::canonical::encode(value)
        .map(|bytes| bytes.as_slice().to_vec())
        .map_err(|_| NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// Wait for the process to exit until `deadline`.
fn exit_status(
    child: &mut Child,
    deadline: Instant,
) -> Result<ExitStatus, NonInterferenceNonExecutedCauseV1> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
            Ok(None) | Err(_) => return Err(NonInterferenceNonExecutedCauseV1::Unavailable),
        }
    }
}

/// Decode one frame straight into its typed schema. A frame that fails it
/// is [`NonInterferenceNonExecutedCauseV1::UnknownField`] when a top-level
/// key is not in `fields` or, with `capture_fields`, a key of its capture is
/// not in them; any other failure is
/// [`NonInterferenceNonExecutedCauseV1::Unavailable`].
fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    fields: &[&str],
    capture_fields: Option<&[&str]>,
) -> Result<T, NonInterferenceNonExecutedCauseV1> {
    ciborium::from_reader::<T, _>(bytes).map_err(|_| {
        let unknown = |keys: &BTreeMap<String, serde::de::IgnoredAny>, declared: &[&str]| {
            keys.keys().any(|key| !declared.contains(&key.as_str()))
        };
        let top = ciborium::from_reader::<BTreeMap<String, serde::de::IgnoredAny>, _>(bytes)
            .is_ok_and(|keys| unknown(&keys, fields));
        let nested = capture_fields.is_some_and(|declared| {
            ciborium::from_reader::<CaptureKeysV1, _>(bytes)
                .is_ok_and(|frame| unknown(&frame.capture, declared))
        });
        if top || nested {
            NonInterferenceNonExecutedCauseV1::UnknownField
        } else {
            NonInterferenceNonExecutedCauseV1::Unavailable
        }
    })
}
