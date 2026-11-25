//! #444 packaged-closure conformance driver (feature `test-support`).
//!
//! Only the disposable QEMU TCG evidence guest runs it, through the
//! `pos-sandboxd-conformance` binary. One run is one case:
//!
//! 1. `ConformanceCase::stage` stages the signed test installation around
//!    one caller-built SIM1 DDI, its signer certificate and the exact bytes
//!    and arguments of the image's `/adapter`
//!    (`StagedInstallation::stage_image`, dev/test trust domain).
//! 2. [`activate`] admits that image through the production
//!    `ProviderImageSnapshot`, commits a planned attempt in the fixed
//!    registry, prepares its directory and calls the production
//!    [`activate_admitted_root`] against the packaged mountfsd and kernel.
//! 3. [`run`] then reports the outcome on one line, holds a mounted root
//!    until its control input closes, so the guest collector can record the
//!    live kernel state, releases it with the caller's [`Release`] (the
//!    production detach) and removes the attempt directory.
//!
//! The guest collector provisions the fixed runtime directories, records the
//! kernel state and passes everything to the host checker, which owns every
//! judgement. Nothing here creates a unit, a process or launch authority.

use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

use pos_reference::provider_admission::test_support::{StagedImage, StagedInstallation};
use pos_reference::provider_admission::{HeldImageAdmission, ProviderImageSnapshot};
use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use pos_reference::selector::InstallationError;

use crate::{
    activate_admitted_root, ImageActivationError, PlannedAttemptIntent, PreparedAttemptDirectory,
    SystemdAttemptRegistry, SystemdAttemptRegistryError, VerifiedRootMount,
};

/// The fixed nonzero `AttemptId` of every evidence case.
const ATTEMPT_ID: [u8; 16] = *b"pigloros-444-evd";

/// The absolute cleanup deadline a held root's detach gets after release.
const RELEASE_DEADLINE: Duration = Duration::from_mins(1);

/// The release of a held root from the attempt directory it is attached to.
pub type Release<'directory> =
    Pin<Box<dyn Future<Output = Result<(), ImageActivationError>> + Send + 'directory>>;

#[cfg(target_arch = "x86_64")]
const HOST_ARCHITECTURE: SandboxArchitecture = SandboxArchitecture::X86_64;
#[cfg(target_arch = "aarch64")]
const HOST_ARCHITECTURE: SandboxArchitecture = SandboxArchitecture::Aarch64;

/// Why a case could not reach activation, or its report could not be written.
#[derive(Debug, thiserror::Error)]
pub enum ConformanceError {
    /// The arguments are not `IMAGE CERTIFICATE_DER KEY_DESCRIPTION ADAPTER
    /// [ADAPTER_ARGUMENT...]`.
    #[error(
        "usage: pos-sandboxd-conformance IMAGE CERTIFICATE_DER KEY_DESCRIPTION ADAPTER \
         [ADAPTER_ARGUMENT...]"
    )]
    Usage,
    /// An input file, the control input or the report failed.
    #[error("conformance I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The test installation could not be staged around the image.
    #[error("staging the test installation failed: {0}")]
    Stage(String),
    /// Production image admission refused the staged installation.
    #[error("provider image admission failed: {0}")]
    Admission(#[from] InstallationError),
    /// The fixed attempt registry refused the planned attempt.
    #[error("the attempt registry failed: {0}")]
    Registry(#[from] SystemdAttemptRegistryError),
}

/// One case's image, signer certificate, kernel key description, and the
/// adapter the image's `/adapter` holds, with its signed argument vector.
#[derive(Debug)]
struct ConformanceCase {
    image: Vec<u8>,
    certificate: Vec<u8>,
    key_description: String,
    adapter: Vec<u8>,
    adapter_arguments: Vec<String>,
}

impl ConformanceCase {
    /// Read `IMAGE CERTIFICATE_DER KEY_DESCRIPTION ADAPTER
    /// [ADAPTER_ARGUMENT...]`.
    ///
    /// # Errors
    /// Returns [`ConformanceError::Usage`] for fewer arguments or text
    /// arguments that are not UTF-8, and [`ConformanceError::Io`] when a
    /// file cannot be read.
    fn from_arguments(arguments: &[OsString]) -> Result<Self, ConformanceError> {
        let [image, certificate, description, adapter, adapter_arguments @ ..] = arguments else {
            return Err(ConformanceError::Usage);
        };
        Self::read(
            [image, certificate, adapter],
            description,
            adapter_arguments,
        )
    }

    /// Read the three files and convert the text arguments.
    fn read(
        [image, certificate, adapter]: [&OsString; 3],
        description: &OsString,
        adapter_arguments: &[OsString],
    ) -> Result<Self, ConformanceError> {
        Ok(Self {
            image: fs::read(image)?,
            certificate: fs::read(certificate)?,
            key_description: text(description)?,
            adapter: fs::read(adapter)?,
            adapter_arguments: adapter_arguments
                .iter()
                .map(text)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Stage the signed test installation around this case's image, for the
    /// architecture this driver was built for.
    ///
    /// # Errors
    /// Returns [`ConformanceError::Stage`] when the image is not a three
    /// partition systemd-repart DDI, the fixed installation already exists,
    /// or the staged records are refused.
    fn stage(&self) -> Result<StagedInstallation, ConformanceError> {
        StagedInstallation::stage_image(&StagedImage {
            architecture: HOST_ARCHITECTURE,
            image: &self.image,
            certificate: &self.certificate,
            key_description: &self.key_description,
            executable: &self.adapter,
            arguments: &self.adapter_arguments,
        })
        .map_err(|error| ConformanceError::Stage(error.to_string()))
    }
}

/// The prepared attempt directory and the production activation outcome.
#[derive(Debug)]
pub struct ActivatedCase {
    /// The attempt directory the root was, or would have been, attached to.
    pub directory: PreparedAttemptDirectory,
    /// [`activate_admitted_root`]'s result for the staged image.
    pub outcome: Result<VerifiedRootMount, ImageActivationError>,
}

/// Admit the staged image, prepare one attempt and activate its root.
///
/// The fixed registry at `/run/pigloros/sandbox/registry` and its `attempts`
/// sibling must already exist, empty and private, as provider startup leaves
/// them. A refused activation is an outcome, not an error.
///
/// # Errors
/// Returns [`ConformanceError::Admission`] when production admission refuses
/// the staged installation, and [`ConformanceError::Registry`] when the
/// registry refuses the planned attempt or its directory.
pub async fn activate(staged: &StagedInstallation) -> Result<ActivatedCase, ConformanceError> {
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let (admission, directory) = prepare(&snapshot)?;
    let outcome = activate_admitted_root(&admission, &directory).await;
    Ok(ActivatedCase { directory, outcome })
}

fn prepare(
    snapshot: &ProviderImageSnapshot,
) -> Result<(HeldImageAdmission<'_>, PreparedAttemptDirectory), ConformanceError> {
    snapshot
        .admit_held_image()
        .map_err(ConformanceError::Admission)
        .and_then(|admission| {
            SystemdAttemptRegistry::open()
                .and_then(|registry| {
                    PlannedAttemptIntent::new(
                        ATTEMPT_ID,
                        snapshot.image().manifest().manifest_digest,
                    )
                    .and_then(|intent| registry.commit_planned(&intent))
                })
                .and_then(|committed| committed.prepare_directory(&admission))
                .map(|directory| (admission, directory))
                .map_err(ConformanceError::Registry)
        })
}

/// One command-line argument as text.
fn text(argument: &OsString) -> Result<String, ConformanceError> {
    argument
        .to_str()
        .map(str::to_owned)
        .ok_or(ConformanceError::Usage)
}

/// The tokio runtime the driver runs on: one thread, with I/O and timers.
///
/// # Errors
/// Returns [`ConformanceError::Io`] when the runtime cannot be built.
pub fn runtime() -> Result<tokio::runtime::Runtime, ConformanceError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ConformanceError::Io)
}

/// The production report text of a mounted root: its mount ID and attempt
/// root path, for [`run`]'s `describe`.
#[must_use]
pub fn describe(mount: &VerifiedRootMount) -> String {
    format!("{}\t{}", mount.mount_id(), mount.root_directory().as_str())
}

/// The production detach of a held root, under a one-minute deadline from
/// now, for [`run`]'s `release`.
#[must_use]
pub fn release(mount: VerifiedRootMount, directory: &PreparedAttemptDirectory) -> Release<'_> {
    Box::pin(async move {
        mount
            .detach(directory, tokio::time::Instant::now() + RELEASE_DEADLINE)
            .await
            .map(drop)
    })
}

/// Run one case from `IMAGE CERTIFICATE_DER KEY_DESCRIPTION ADAPTER
/// [ADAPTER_ARGUMENT...]`.
///
/// Its report lines are, in order: the activation (`mounted` with
/// `describe`'s text, or `refused` with the error), the release (`detached`,
/// `failed` or `none`) and the attempt directory's removal. A mounted root is
/// held until `control` reaches end of input and then released by `release`.
///
/// # Errors
/// Returns the first [`ConformanceError`] that keeps the case from reaching
/// activation, or from reading `control` and writing `report`.
pub async fn run<Describe, Detach>(
    arguments: Vec<OsString>,
    control: impl Read + Send,
    report: &mut (impl Write + Send),
    describe: Describe,
    release: Detach,
) -> Result<(), ConformanceError>
where
    Describe: FnOnce(&VerifiedRootMount) -> String + Send,
    Detach: for<'directory> FnOnce(
            VerifiedRootMount,
            &'directory PreparedAttemptDirectory,
        ) -> Release<'directory>
        + Send,
{
    let case = ConformanceCase::from_arguments(&arguments)?;
    let staged = case.stage()?;
    let ActivatedCase { directory, outcome } = activate(&staged).await?;
    exercise(outcome, describe, release, &directory, control, report).await?;
    report_line(report, &removal_line(&directory.remove_unmounted()))
}

/// Report one activation outcome, hold a mounted root until `control`
/// reaches end of input, then release it from `held` and report the release.
///
/// A refused activation is reported, waits for `control` the same way and
/// is reported as having nothing to release.
async fn exercise<Root, Held, Describe, Detach>(
    outcome: Result<Root, ImageActivationError>,
    describe: Describe,
    release: Detach,
    held: &Held,
    control: impl Read + Send,
    report: &mut (impl Write + Send),
) -> Result<(), ConformanceError>
where
    Root: Send,
    Held: Sync,
    Describe: FnOnce(&Root) -> String + Send,
    Detach: for<'held> FnOnce(Root, &'held Held) -> Release<'held> + Send,
{
    let activation = outcome.as_ref().map_or_else(
        |error| format!("activation\trefused\t{error:?}"),
        |root| format!("activation\tmounted\t{}", describe(root)),
    );
    report_line(report, &activation)?;
    hold(control)?;
    let released = match outcome {
        Ok(root) => Some(release(root, held).await),
        Err(_) => None,
    };
    report_line(report, &release_line(released))
}

/// Read `control` to its end: the collector closes it once it has recorded
/// the held root.
fn hold(mut control: impl Read) -> Result<(), ConformanceError> {
    io::copy(&mut control, &mut io::sink())
        .map(|_| ())
        .map_err(ConformanceError::Io)
}

fn release_line(released: Option<Result<(), ImageActivationError>>) -> String {
    match released {
        None => "release\tnone".to_owned(),
        Some(Ok(())) => "release\tdetached".to_owned(),
        Some(Err(error)) => format!("release\tfailed\t{error:?}"),
    }
}

/// The report line for the attempt directory's removal.
fn removal_line(removed: &Result<(), SystemdAttemptRegistryError>) -> String {
    removed.as_ref().map_or_else(
        |error| format!("removal\tfailed\t{error:?}"),
        |()| "removal\tremoved".to_owned(),
    )
}

/// Write one report line and flush it, so the collector sees it at once.
fn report_line(report: &mut impl Write, line: &str) -> Result<(), ConformanceError> {
    writeln!(report, "{line}")
        .and_then(|()| report.flush())
        .map_err(ConformanceError::Io)
}

/// The process exit status for a run, reporting an error on `diagnostics`.
#[must_use]
pub fn exit_status(result: Result<(), ConformanceError>, diagnostics: &mut impl Write) -> ExitCode {
    result.map_or_else(
        |error| {
            drop(writeln!(diagnostics, "pos-sandboxd-conformance: {error}"));
            ExitCode::FAILURE
        },
        |()| ExitCode::SUCCESS,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
