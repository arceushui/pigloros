use std::error::Error;
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

use pos_reference::provider_transport::guest::{
    GuestExecuteError, GuestReportError, GuestWaitError,
};
use pos_reference::sandbox_provider_protocol::SandboxProviderErrorCode;

use super::{
    failure_line, report_outcome, run_execute, unix_seconds, ExecuteCase, EVALUATION_FILE,
    INPUT_FILE, SPX1_FILE,
};
use crate::packaged_conformance::ConformanceError;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A writer whose every operation fails.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken report"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("broken report"))
    }
}

/// An export directory holding a decodable evaluation, an SPX1 and an input.
fn export() -> TestResult<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    let corpus = pos_reference::selector_test_support::air_gapped_corpus()?;
    std::fs::write(directory.path().join(EVALUATION_FILE), corpus.request)?;
    std::fs::write(directory.path().join(SPX1_FILE), b"spx1 bytes")?;
    std::fs::write(directory.path().join(INPUT_FILE), b"input bytes")?;
    Ok(directory)
}

fn arguments(directory: &Path, pid: &str) -> Vec<OsString> {
    vec![directory.as_os_str().to_owned(), pid.into()]
}

#[test]
fn the_case_reads_the_exported_files_and_the_provider_process() -> TestResult {
    let directory = export()?;
    let case = ExecuteCase::from_arguments(&arguments(directory.path(), "4242"))?;
    assert_eq!(case.spx1, b"spx1 bytes");
    assert_eq!(case.input, b"input bytes");
    assert_eq!(case.main_pid.get(), 4242);
    assert_eq!(
        case.evaluation.to_canonical_cbor()?,
        pos_reference::selector_test_support::air_gapped_corpus()?.request
    );
    Ok(())
}

#[test]
fn the_case_refuses_unusable_arguments() -> TestResult {
    let directory = export()?;
    let path = directory.path();
    let mut not_text = arguments(path, "1");
    not_text[1] = OsString::from_vec(vec![0xff]);
    for wrong in [
        Vec::new(),
        vec![path.as_os_str().to_owned()],
        arguments(path, "0"),
        arguments(path, "-1"),
        arguments(path, "pid"),
        not_text,
    ] {
        assert!(matches!(
            ExecuteCase::from_arguments(&wrong),
            Err(ConformanceError::ExecuteUsage)
        ));
    }
    let mut three = arguments(path, "1");
    three.push("extra".into());
    assert!(matches!(
        ExecuteCase::from_arguments(&three),
        Err(ConformanceError::ExecuteUsage)
    ));
    Ok(())
}

#[test]
fn a_missing_file_is_an_io_error_and_a_bad_evaluation_is_refused() -> TestResult {
    for name in [EVALUATION_FILE, SPX1_FILE, INPUT_FILE] {
        let directory = export()?;
        std::fs::remove_file(directory.path().join(name))?;
        assert!(matches!(
            ExecuteCase::from_arguments(&arguments(directory.path(), "7")),
            Err(ConformanceError::Io(_))
        ));
    }
    let directory = export()?;
    std::fs::write(directory.path().join(EVALUATION_FILE), b"not cbor")?;
    assert!(matches!(
        ExecuteCase::from_arguments(&arguments(directory.path(), "7")),
        Err(ConformanceError::Execute(_))
    ));
    Ok(())
}

#[test]
fn execute_stops_at_the_installation_that_is_not_there() -> TestResult {
    let directory = export()?;
    let mut report = Vec::new();
    let refused = run_execute(&arguments(directory.path(), "7"), &mut report);
    assert!(matches!(refused, Err(ConformanceError::Admission(_))));
    assert!(report.is_empty());
    assert!(matches!(
        run_execute(&[], &mut report),
        Err(ConformanceError::ExecuteUsage)
    ));
    Ok(())
}

#[test]
fn an_execution_is_reported_line_by_line_after_its_outcome() -> TestResult {
    let mut report = Vec::new();
    report_outcome(
        Ok(7_u8),
        |value| Ok(vec![format!("value\t{value}"), "second\tline".to_owned()]),
        &mut report,
    )?;
    assert_eq!(
        String::from_utf8(report)?,
        "execute\texecuted\nvalue\t7\nsecond\tline\n"
    );
    Ok(())
}

#[test]
fn an_unreportable_execution_or_a_broken_report_is_an_error() {
    let mut report = Vec::new();
    let unreportable = report_outcome(Ok(()), |()| Err(GuestReportError), &mut report);
    assert!(matches!(unreportable, Err(ConformanceError::Execute(_))));
    assert_eq!(String::from_utf8_lossy(&report), "execute\texecuted\n");
    let broken = report_outcome(Ok(()), |()| Ok(Vec::new()), &mut Broken);
    assert!(matches!(broken, Err(ConformanceError::Io(_))));
    let mut lines = Vec::new();
    let broken_lines = report_outcome(
        Ok(()),
        |()| Ok(vec!["a".to_owned()]),
        &mut FailsAfter::new(&mut lines, 1),
    );
    assert!(matches!(broken_lines, Err(ConformanceError::Io(_))));
}

/// A writer that accepts `allowed` flushes and then fails.
struct FailsAfter<'a> {
    inner: &'a mut Vec<u8>,
    allowed: usize,
}

impl<'a> FailsAfter<'a> {
    fn new(inner: &'a mut Vec<u8>, allowed: usize) -> Self {
        Self { inner, allowed }
    }
}

impl Write for FailsAfter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.allowed == 0 {
            return Err(io::Error::other("broken report"));
        }
        self.allowed -= 1;
        Ok(())
    }
}

#[test]
fn a_failed_exchange_is_an_outcome_line_not_an_error() -> TestResult {
    let outcomes = [
        (
            GuestWaitError::Refused(Some(SandboxProviderErrorCode::SandboxUnavailable)),
            "execute\trefused\tSandboxUnavailable",
        ),
        (
            GuestWaitError::Refused(None),
            "execute\trefused\tundecodable",
        ),
        (
            GuestWaitError::Execute(GuestExecuteError::BeforeAdmission),
            "execute\tfailed\tprovider execution failed before admission",
        ),
    ];
    for (error, line) in outcomes {
        assert_eq!(failure_line(error), line);
        let mut report = Vec::new();
        report_outcome(Err::<(), _>(error), |()| Ok(Vec::new()), &mut report)?;
        assert_eq!(String::from_utf8(report)?, format!("{line}\n"));
    }
    Ok(())
}

#[test]
fn the_clock_reads_seconds_since_the_epoch() {
    // 2023-11-14 is long past, and the value is seconds, not milliseconds.
    assert!(unix_seconds() > 1_700_000_000);
    assert!(unix_seconds() < 100_000_000_000);
}
