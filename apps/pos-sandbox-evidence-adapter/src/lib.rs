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

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::ExitCode;

use pos_reference::adapter_transport::{read_attempt, write_observation};
use pos_reference::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};

/// The behavior one argument selects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Report the payload's BLAKE3 digest as the output.
    Honest,
}

impl Mode {
    /// The argument that selects the mode.
    #[must_use]
    pub const fn argument(self) -> &'static str {
        match self {
            Self::Honest => "honest",
        }
    }

    fn parse(argument: &OsString) -> Option<Self> {
        match argument.to_str() {
            Some("honest") => Some(Self::Honest),
            _ => None,
        }
    }
}

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunError {
    /// The arguments are not exactly one known mode.
    #[error("usage: pos-sandbox-evidence-adapter honest")]
    Usage,
    /// The EAI1 attempt stream does not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire,
    /// The EAO1 stream could not be written.
    #[error("the EAO1 observation stream could not be written")]
    Output,
}

impl AdapterRunError {
    /// The process exit code of the failure.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Usage => 64,
            Self::Wire => 2,
            Self::Output => 4,
        }
    }
}

/// The exit code of a run: success, or the code of the error.
#[must_use]
pub fn exit_code(result: Result<(), AdapterRunError>) -> ExitCode {
    result.map_or_else(|error| ExitCode::from(error.code()), |()| ExitCode::SUCCESS)
}

/// Select the mode from `arguments`, read one EAI1 stream from `reader`,
/// and write one EAO1 stream to `writer`.
///
/// # Errors
/// [`AdapterRunError::Usage`] for anything but one known mode argument,
/// [`AdapterRunError::Wire`] for an attempt that does not decode and
/// [`AdapterRunError::Output`] when the observation cannot be written.
pub fn run(
    arguments: impl IntoIterator<Item = OsString>,
    reader: impl Read,
    writer: impl Write,
) -> Result<(), AdapterRunError> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [argument] => Mode::parse(argument).ok_or(AdapterRunError::Usage),
        _ => Err(AdapterRunError::Usage),
    }
    .and_then(|mode| {
        read_attempt(reader)
            .or(Err(AdapterRunError::Wire))
            .map(|attempt| observe(mode, &attempt))
    })
    .and_then(|observation| {
        write_observation(writer, &observation).or(Err(AdapterRunError::Output))
    })
}

/// The observation `mode` reports for `attempt`.
#[must_use]
pub fn observe(mode: Mode, attempt: &CaseAttempt) -> SubjectObservation {
    match mode {
        Mode::Honest => {
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
