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
//! The EAO1 stream is encoded and validated in memory first, so an encoding
//! or validation failure writes nothing. A valid stream then reaches the
//! writer in one `write_all`; a failing writer can still leave part of it
//! (a pipe may accept some bytes), and the process ends with a distinct code.

pub mod fixture;
pub mod probe;

use std::ffi::{OsStr, OsString};
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
        split_arguments(arguments).and_then(|(name, bound)| Self::select(name, bound))
    }

    /// The table row `name` names, with the parsed `bound` where it takes one.
    fn select(name: &OsStr, bound: Option<u64>) -> Option<Self> {
        MODES
            .iter()
            .find(|(row, _)| name.to_str() == Some(*row))
            .and_then(|(_, mode)| mode.with_bound(bound))
    }

    /// This mode with the argument-vector bound: the honest mode takes none.
    fn with_bound(self, bound: Option<u64>) -> Option<Self> {
        match (self, bound) {
            (Self::Honest, None) => Some(Self::Honest),
            (Self::Fixture(fixture), _) => fixture.with_bound(bound).map(Self::Fixture),
            (Self::Honest, Some(_)) => None,
        }
    }
}

/// The mode id and the optional bound of an argument vector of one or two
/// arguments. The bound must be UTF-8 decimal digits that fit a `u64`.
fn split_arguments(arguments: &[OsString]) -> Option<(&OsStr, Option<u64>)> {
    match arguments {
        [name] => Some((name.as_os_str(), None)),
        [name, bound] => parse_bound(bound).map(|bound| (name.as_os_str(), Some(bound))),
        _ => None,
    }
}

fn parse_bound(bound: &OsStr) -> Option<u64> {
    bound.to_str().and_then(|text| text.parse().ok())
}

/// Why the adapter wrote no observation. The discriminant is the process exit
/// code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[repr(u8)]
pub enum AdapterRunError {
    /// The arguments are not exactly one known mode.
    #[error("usage: pos-sandbox-evidence-adapter MODE [BOUND]")]
    Usage = 64,
    /// The EAI1 attempt stream does not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire = 2,
    /// The EAO1 stream could not be written.
    #[error("the EAO1 observation stream could not be written")]
    Output = 4,
    /// A probe fixture's forbidden operation succeeded.
    #[error("a forbidden operation was not denied")]
    Escaped = 3,
    /// The crash fixture ended the run.
    #[error("the adapter crashed on purpose")]
    Crashed = 70,
}

impl AdapterRunError {
    /// The process exit code of the failure.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// The exit code of a run: success, or the code of the error.
#[must_use]
pub fn exit_code(result: Result<(), AdapterRunError>) -> ExitCode {
    result.map_or_else(|error| ExitCode::from(error.code()), |()| ExitCode::SUCCESS)
}

/// Select the mode from `arguments` (`MODE` or `MODE BOUND`), read one EAI1
/// stream from `reader`, and write one EAO1 stream to `writer`.
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
    Mode::parse(&arguments)
        .ok_or(AdapterRunError::Usage)
        .and_then(|mode| {
            read_attempt(reader)
                .or(Err(AdapterRunError::Wire))
                .map(|attempt| (mode, attempt))
        })
        .and_then(|(mode, attempt)| conclude(mode, &attempt, &mut writer))
}

/// Apply the mode's effect, then report honestly unless the fixture wrote the
/// whole of the output itself.
fn conclude(
    mode: Mode,
    attempt: &CaseAttempt,
    writer: &mut impl Write,
) -> Result<(), AdapterRunError> {
    effect(mode, writer).and_then(|after| match after {
        After::Written => Ok(()),
        After::Report => report(mode, attempt, writer),
    })
}

/// The mode's effect: none for the honest mode, the fixture's otherwise.
fn effect(mode: Mode, writer: &mut impl Write) -> Result<After, AdapterRunError> {
    match mode {
        Mode::Honest => Ok(After::Report),
        Mode::Fixture(fixture) => apply(fixture, writer),
    }
}

/// Write the observation `mode` reports for `attempt`.
fn report(
    mode: Mode,
    attempt: &CaseAttempt,
    writer: &mut impl Write,
) -> Result<(), AdapterRunError> {
    // One buffer, one `write_all`: an encoding or validation failure writes
    // nothing, and a valid stream is never written in pieces by this function.
    let mut stream = Vec::new();
    write_observation(&mut stream, &observe(mode, attempt))
        .or(Err(AdapterRunError::Output))
        .and_then(|()| {
            writer
                .write_all(&stream)
                .and_then(|()| writer.flush())
                .or(Err(AdapterRunError::Output))
        })
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
