//! The execute mode of the #444 evidence driver (feature `test-support`).
//!
//! `pos-sandboxd-conformance execute EXPORT_DIRECTORY MAIN_PID` is the
//! selector's side of one SPX1 exchange with the composed `provider-runtime`
//! that systemd runs as the staged binary. It reads what the stager exported
//! (the SPX1 request, the EVR1 evaluation and the EAI1 input), admits the
//! fixed installation as the root selector does, derives the case's grant
//! commitment ([`GuestProviderClient::commitment`]) and runs the exchange
//! with the process `MAIN_PID` over the execute socket that SIC1 names. A
//! provider that is still opening answers SPE1 `11`; the exchange is asked
//! again for [`EXECUTE_WINDOW`] on the monotonic clock.
//!
//! The report is `execute executed` and one `NAME<TAB>VALUE` line of evidence per
//! observation the selector made, or one `execute` line for an exchange that
//! produced no execution (`GuestProviderClient::execute_report`). That is an
//! outcome, not an error: the guest checker judges every line.

use std::ffi::OsString;
use std::fmt::Display;
use std::fs;
use std::io::{Cursor, Write};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pos_reference::evaluator_protocol::EvaluationRequest;
use pos_reference::provider_transport::guest::{
    GuestExecuteJob, GuestInstantClock, GuestProviderClient,
};
use pos_reference::selector::installation::authority::AuthenticatedSelectorBootstrap;
use pos_reference::selector::installation::InstalledSelectorState;

use super::{report_line, ConformanceError};

/// The file the stager writes the SPX1 request to, and this mode reads.
pub(super) const SPX1_FILE: &str = "spx1";
/// The file of the EVR1 evaluation.
pub(super) const EVALUATION_FILE: &str = "evaluation";
/// The file of the EAI1 input.
pub(super) const INPUT_FILE: &str = "input";

/// The staged execution is the installation's case 0.
const CASE_ORDINAL: u16 = 0;

/// How long a provider that is still opening is asked again.
const EXECUTE_WINDOW: Duration = Duration::from_mins(2);

/// One execute run's files and provider process, read from its arguments.
#[derive(Debug)]
struct ExecuteCase {
    spx1: Vec<u8>,
    evaluation: EvaluationRequest,
    input: Vec<u8>,
    main_pid: NonZeroU64,
}

impl ExecuteCase {
    /// Read `EXPORT_DIRECTORY MAIN_PID`.
    ///
    /// # Errors
    /// [`ConformanceError::ExecuteUsage`] for another number of arguments or
    /// a `MAIN_PID` that is not a positive integer, [`ConformanceError::Io`]
    /// when a file cannot be read, and [`ConformanceError::Execute`] when the
    /// evaluation does not decode.
    fn from_arguments(arguments: &[OsString]) -> Result<Self, ConformanceError> {
        let [directory, main_pid] = arguments else {
            return Err(ConformanceError::ExecuteUsage);
        };
        let main_pid: NonZeroU64 = main_pid
            .to_str()
            .and_then(|text| text.parse().ok())
            .ok_or(ConformanceError::ExecuteUsage)?;
        let directory = Path::new(directory);
        let evaluation = fs::read(directory.join(EVALUATION_FILE))?;
        Ok(Self {
            spx1: fs::read(directory.join(SPX1_FILE))?,
            evaluation: EvaluationRequest::from_canonical_cbor(&evaluation).map_err(refused)?,
            input: fs::read(directory.join(INPUT_FILE))?,
            main_pid,
        })
    }
}

/// A step of the selector's side that failed, as a [`ConformanceError`].
fn refused(error: impl Display) -> ConformanceError {
    ConformanceError::Execute(error.to_string())
}

/// Run one execute exchange against the provider `arguments` name and write
/// its report.
///
/// # Errors
/// The first [`ConformanceError`] that keeps the exchange from being asked
/// (arguments, files, admission of the installation, the commitment, the
/// client), or from writing `report`.
pub(super) fn run_execute(
    arguments: &[OsString],
    report: &mut impl Write,
) -> Result<(), ConformanceError> {
    let case = ExecuteCase::from_arguments(arguments)?;
    let admitted = InstalledSelectorState::open()
        .and_then(InstalledSelectorState::authenticate_bootstrap)
        .and_then(AuthenticatedSelectorBootstrap::admit_provider)?;
    let grant =
        GuestProviderClient::commitment(&admitted, &case.evaluation, CASE_ORDINAL, unix_seconds())
            .map_err(refused)?;
    let client =
        GuestProviderClient::for_admitted_provider(&admitted, case.main_pid).map_err(refused)?;
    client
        .execute_report(
            admitted.provider(),
            &grant,
            &GuestExecuteJob {
                evaluation: &case.evaluation,
                spx1: &case.spx1,
            },
            &mut Cursor::new(case.input),
            &GuestInstantClock::start(),
            EXECUTE_WINDOW,
        )
        .map_err(refused)?
        .iter()
        .try_for_each(|line| report_line(report, line))
}

/// The seconds since the Unix epoch on the system clock, or zero before it.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
