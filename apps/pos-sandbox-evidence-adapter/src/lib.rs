#![forbid(unsafe_code)]

//! The adapter the #444 QEMU evidence DDI carries as `/adapter`.
//!
//! The one argument selects the behavior, from the [`MODES`] table.
//! [`Mode::Honest`] reads one EAI1 attempt and reports the BLAKE3 digest of
//! its payload member as the EAO1 output, with the one resource counter it can
//! know exactly: the output bytes. Every other counter is zero, as the adapter
//! measures none of them. The argument vector is part of the signed SIM1.
//!
//! A further fixture mode is a new [`Mode`] variant, a [`MODES`] row and a new
//! arm of [`observe`]. Modes that must misbehave on the wire (garbage, extra
//! bytes, nothing, a hang, memory exhaustion) cannot go through [`observe`]
//! and the validating `write_observation`, so they need their own seam in
//! [`run`] before the observation is written.
//!
//! The EAO1 stream is built in memory and written once, so a failure writes
//! no EAO1 byte at all, and ends the process with a distinct code.

pub mod fixture;
pub mod probe;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::ExitCode;

pub use fixture::{apply, After, Fixture};
use pos_reference::adapter_transport::{read_attempt, write_observation};
use pos_reference::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};

/// The behavior one argument selects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Report the payload's BLAKE3 digest as the output.
    Honest,
    /// A #216 malicious or limit fixture, which then reports honestly unless
    /// it ends the run itself.
    Fixture(Fixture),
}

/// Every mode and the argument that selects it: the one source of the
/// parser. A bounded fixture's row carries the placeholder bound `0`; the
/// command line gives the real one (`MODE BOUND`).
pub const MODES: &[(&str, Mode)] = &[
    ("honest", Mode::Honest),
    (
        "filesystem-escape",
        Mode::Fixture(Fixture::FilesystemEscape),
    ),
    (
        "read-only-root-write",
        Mode::Fixture(Fixture::ReadOnlyRootWrite),
    ),
    (
        "work-area-exhaustion",
        Mode::Fixture(Fixture::WorkAreaExhaustion(0)),
    ),
    ("network-escape", Mode::Fixture(Fixture::NetworkEscape)),
    ("foreign-signals", Mode::Fixture(Fixture::ForeignSignals)),
    ("orphaned-child", Mode::Fixture(Fixture::OrphanedChild)),
    ("task-exhaustion", Mode::Fixture(Fixture::TaskExhaustion(0))),
    (
        "memory-exhaustion",
        Mode::Fixture(Fixture::MemoryExhaustion(0)),
    ),
    ("watchdog-expiry", Mode::Fixture(Fixture::WatchdogExpiry(0))),
    (
        "oversized-output",
        Mode::Fixture(Fixture::OversizedOutput(0)),
    ),
    ("adapter-crash", Mode::Fixture(Fixture::AdapterCrash)),
    ("malformed-output", Mode::Fixture(Fixture::MalformedOutput)),
    ("idle", Mode::Fixture(Fixture::Idle(0))),
];

impl Mode {
    /// The mode the arguments select: `<mode-id>` or `<mode-id> <bound>`,
    /// the bound a nonzero decimal exactly for the fixtures that take one.
    fn parse(arguments: &[OsString]) -> Option<Self> {
        let (name, bound) = match arguments {
            [name] => (name, None),
            [name, bound] => (name, Some(bound.to_str()?.parse::<u64>().ok()?)),
            _ => return None,
        };
        let (_, mode) = MODES.iter().find(|(row, _)| name.to_str() == Some(row))?;
        match (mode, bound) {
            (Self::Honest, None) => Some(Self::Honest),
            (Self::Fixture(fixture), _) => fixture.with_bound(bound).map(Self::Fixture),
            (Self::Honest, Some(_)) => None,
        }
    }
}

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunError {
    /// The arguments are not exactly one known mode.
    #[error("usage: pos-sandbox-evidence-adapter MODE [BOUND]")]
    Usage,
    /// The EAI1 attempt stream does not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire,
    /// The EAO1 stream could not be written.
    #[error("the EAO1 observation stream could not be written")]
    Output,
    /// A probe fixture's forbidden operation succeeded.
    #[error("a forbidden operation was not denied")]
    Escaped,
    /// The crash fixture ended the run.
    #[error("the adapter crashed on purpose")]
    Crashed,
}

impl AdapterRunError {
    /// The process exit code of the failure.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Usage => 64,
            Self::Wire => 2,
            Self::Output => 4,
            Self::Escaped => 3,
            Self::Crashed => 70,
        }
    }
}

/// The exit code of a run: success, or the code of the error.
#[must_use]
pub fn exit_code(result: Result<(), AdapterRunError>) -> ExitCode {
    result.map_or_else(|error| ExitCode::from(error.code()), |()| ExitCode::SUCCESS)
}

/// Select the mode from `arguments` (`MODE` or `MODE BOUND`), read one EAI1 stream from `reader`,
/// and write one EAO1 stream to `writer`.
///
/// # Errors
/// [`AdapterRunError::Usage`] for anything but one known mode and its bound,
/// [`AdapterRunError::Wire`] for an attempt that does not decode (a missing,
/// truncated or extended stream included) and [`AdapterRunError::Output`]
/// when the observation cannot be encoded or written, and
/// [`AdapterRunError::Escaped`] or [`AdapterRunError::Crashed`] from a fixture.
pub fn run(
    arguments: impl IntoIterator<Item = OsString>,
    reader: impl Read,
    mut writer: impl Write,
) -> Result<(), AdapterRunError> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    let mode = Mode::parse(&arguments).ok_or(AdapterRunError::Usage)?;
    let attempt = read_attempt(reader).or(Err(AdapterRunError::Wire))?;
    let after = match mode {
        Mode::Honest => After::Report,
        Mode::Fixture(fixture) => apply(fixture, &mut writer)?,
    };
    match after {
        After::Written => Ok(()),
        After::Report => {
            // One buffer, one write: a failed write cannot leave a partial
            // stream that the provider would capture as an incomplete EAO1.
            let mut stream = Vec::new();
            write_observation(&mut stream, &observe(mode, &attempt))
                .or(Err(AdapterRunError::Output))?;
            writer
                .write_all(&stream)
                .and_then(|()| writer.flush())
                .or(Err(AdapterRunError::Output))
        }
    }
}

/// The observation `mode` reports for `attempt`.
#[must_use]
pub fn observe(mode: Mode, attempt: &CaseAttempt) -> SubjectObservation {
    match mode {
        Mode::Honest | Mode::Fixture(_) => {
            let output = blake3::hash(&attempt.payload.bytes).as_bytes().to_vec();
            let usage = ResourceUsage {
                output_bytes: output.len() as u64,
                ..ResourceUsage::default()
            };
            SubjectObservation {
                result: SubjectResult::Output(output),
                usage,
            }
        }
    }
}
