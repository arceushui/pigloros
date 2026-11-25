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

use std::ffi::{OsStr, OsString};
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

/// Every mode and the argument that selects it: the one source of the
/// parser.
pub const MODES: &[(&str, Mode)] = &[("honest", Mode::Honest)];

impl Mode {
    fn parse(argument: &OsStr) -> Option<Self> {
        MODES
            .iter()
            .find(|(name, _)| argument.to_str() == Some(name))
            .map(|(_, mode)| *mode)
    }
}

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunError {
    /// The arguments are not exactly one known mode.
    #[error("usage: pos-sandbox-evidence-adapter MODE")]
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
/// [`AdapterRunError::Wire`] for an attempt that does not decode (a missing,
/// truncated or extended stream included) and [`AdapterRunError::Output`]
/// when the observation cannot be encoded or written.
pub fn run(
    arguments: impl IntoIterator<Item = OsString>,
    reader: impl Read,
    mut writer: impl Write,
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
        // One buffer, one write: a failed write cannot leave a partial stream
        // that the provider would capture as an incomplete EAO1.
        let mut stream = Vec::new();
        write_observation(&mut stream, &observation)
            .or(Err(AdapterRunError::Output))
            .map(|()| stream)
    })
    .and_then(|stream| {
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
