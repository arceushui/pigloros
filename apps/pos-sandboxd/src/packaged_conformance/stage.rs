//! The stager mode of the #444 evidence driver (feature `test-support`).
//!
//! `pos-sandboxd-conformance stage IMAGE CERTIFICATE_DER KEY_DESCRIPTION
//! ADAPTER SPI1 KEY_FILE_NAME PROVIDER_BINARY EXPORT_DIRECTORY
//! [ADAPTER_ARGUMENT...]` stages the signed test installation around the
//! caller's image, adapter and provider binary
//! ([`StagedInstallation::stage_provider_execution`]), so that the composed
//! `provider-runtime` can run as the staged binary. It writes the selector's
//! side of the staged execution into the existing `EXPORT_DIRECTORY`, one new
//! private file each: the SPX1 request, the EVR1 evaluation and the EAI1
//! input, which the `execute` mode reads. Its report is one line, `staged`
//! and the installed provider executable's path. It then holds the
//! installation until its control input closes, and removes it again.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use pos_reference::provider_admission::test_support::{
    StagedImage, StagedInstallation, StagedProvider,
};

use super::execute::{EVALUATION_FILE, INPUT_FILE, SPX1_FILE};
use super::{hold, report_line, ConformanceError, HOST_ARCHITECTURE};

/// One stager run's files, read from its arguments.
#[derive(Debug)]
struct StageCase {
    image: Vec<u8>,
    certificate: Vec<u8>,
    key_description: String,
    adapter: Vec<u8>,
    adapter_arguments: Vec<String>,
    spi1: Vec<u8>,
    key_file_name: String,
    provider_binary: PathBuf,
    export: PathBuf,
}

impl StageCase {
    /// Read `IMAGE CERTIFICATE_DER KEY_DESCRIPTION ADAPTER SPI1
    /// KEY_FILE_NAME PROVIDER_BINARY EXPORT_DIRECTORY [ADAPTER_ARGUMENT...]`.
    ///
    /// # Errors
    /// [`ConformanceError::StageUsage`] for fewer arguments or text
    /// arguments that are not UTF-8, and [`ConformanceError::Io`] when a
    /// file cannot be read.
    fn from_arguments(arguments: &[OsString]) -> Result<Self, ConformanceError> {
        let Some((
            [image, certificate, description, adapter, spi1, key_file_name, binary, export],
            rest,
        )) = arguments.split_first_chunk()
        else {
            return Err(ConformanceError::StageUsage);
        };
        // The text arguments first: a malformed one is a usage error before any I/O.
        let key_description = text(description)?;
        let key_file_name = text(key_file_name)?;
        let adapter_arguments = rest.iter().map(text).collect::<Result<_, _>>()?;
        Ok(Self {
            image: fs::read(image)?,
            certificate: fs::read(certificate)?,
            key_description,
            adapter: fs::read(adapter)?,
            adapter_arguments,
            spi1: fs::read(spi1)?,
            key_file_name,
            provider_binary: PathBuf::from(binary),
            export: PathBuf::from(export),
        })
    }

    /// Stage the installation and its execution fixture, and write the
    /// selector's side of it into the export directory.
    ///
    /// # Errors
    /// [`ConformanceError::Stage`] when the fixed installation exists, the
    /// image is not a three partition systemd-repart DDI, or any staged file
    /// is refused, and [`ConformanceError::Io`] when an export file cannot be
    /// created. The installation is removed again in that case.
    fn stage(&self) -> Result<StagedInstallation, ConformanceError> {
        StagedInstallation::stage_provider_execution(&StagedProvider {
            image: StagedImage {
                architecture: HOST_ARCHITECTURE,
                image: &self.image,
                certificate: &self.certificate,
                key_description: &self.key_description,
                executable: &self.adapter,
                arguments: &self.adapter_arguments,
            },
            binary: &self.provider_binary,
            installation: &self.spi1,
            key_file_name: &self.key_file_name,
        })
        .map_err(|error| ConformanceError::Stage(error.to_string()))
        .and_then(|staged| {
            write_export(
                &self.export,
                &[
                    (SPX1_FILE, staged.request()),
                    (EVALUATION_FILE, staged.evaluation()),
                    (INPUT_FILE, staged.input()),
                ],
            )
            .map(|()| staged)
        })
    }
}

/// Write each of `files` as a new file of `directory`, readable and writable
/// by its owner only. A file that exists already is never overwritten.
///
/// # Errors
/// [`ConformanceError::Io`] when `directory` is missing, or a file exists or
/// cannot be written.
fn write_export(directory: &Path, files: &[(&str, &[u8])]) -> Result<(), ConformanceError> {
    files.iter().try_for_each(|(name, bytes)| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))
            .and_then(|mut file| file.write_all(bytes))
            .map_err(ConformanceError::Io)
    })
}

/// One command-line argument as text.
fn text(argument: &OsString) -> Result<String, ConformanceError> {
    argument
        .to_str()
        .map(str::to_owned)
        .ok_or(ConformanceError::StageUsage)
}

/// Run the stager: stage, report the provider executable, hold until
/// `control` reaches end of input, then remove the installation.
///
/// # Errors
/// The first [`ConformanceError`] that keeps the installation from being
/// staged, or from reading `control` and writing `report`.
pub(super) fn run_stage(
    arguments: &[OsString],
    control: impl Read,
    report: &mut impl Write,
) -> Result<(), ConformanceError> {
    let staged = StageCase::from_arguments(arguments)?.stage()?;
    report_line(
        report,
        &format!("staged\t{}", staged.provider_executable().display()),
    )?;
    hold(control)?;
    drop(staged);
    report_line(report, "unstaged")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
