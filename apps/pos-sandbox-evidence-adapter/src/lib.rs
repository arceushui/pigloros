#![forbid(unsafe_code)]

//! The adapter the #444 QEMU evidence DDI carries as `/adapter`.
//!
//! The one argument selects the behavior. [`Mode::Honest`] reads one EAI1
//! attempt and reports the BLAKE3 digest of its payload member as the EAO1
//! output, with the one resource counter it can know exactly: the output
//! bytes. Every other counter is zero, as the adapter measures none of them.
//! Further fixture modes are new [`Mode`] variants and new arms of
//! [`observe`]; the argument vector is part of the signed SIM1.
//!
//! Failures write no EAO1 byte and end the process with a distinct code.

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

impl Mode {
    /// The argument that selects the mode.
    #[must_use]
    pub const fn argument(self) -> &'static str {
        match self {
            Self::Honest => "honest",
            Self::Fixture(fixture) => fixture.id(),
        }
    }

    /// The bound argument that follows the mode, for the fixtures that take one.
    #[must_use]
    pub const fn bound(self) -> Option<u64> {
        match self {
            Self::Honest => None,
            Self::Fixture(fixture) => fixture.bound(),
        }
    }

    /// The mode the arguments select: `<mode-id>` or `<mode-id> <bound>`.
    fn parse(arguments: &[OsString]) -> Option<Self> {
        let (id, bound) = match arguments {
            [id] => (id.to_str()?, None),
            [id, bound] => (id.to_str()?, Some(bound.to_str()?.parse::<u64>().ok()?)),
            _ => return None,
        };
        if id == "honest" {
            bound.is_none().then_some(Self::Honest)
        } else {
            Fixture::parse(id, bound).map(Self::Fixture)
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
/// [`AdapterRunError::Wire`] for an attempt that does not decode and
/// [`AdapterRunError::Output`] when the observation cannot be written.
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
            write_observation(writer, &observe(mode, &attempt)).or(Err(AdapterRunError::Output))
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
