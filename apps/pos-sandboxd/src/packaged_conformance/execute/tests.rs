use std::error::Error;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;

use super::{run_execute, unix_seconds, ExecuteCase, EVALUATION_FILE, INPUT_FILE, SPX1_FILE};
use crate::packaged_conformance::ConformanceError;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// An export directory holding a decodable evaluation, an SPX1 and an input.
fn export() -> TestResult<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    let corpus = pos_reference::selector_test_support::air_gapped_corpus()?;
    for (name, bytes) in [
        (EVALUATION_FILE, corpus.request.as_slice()),
        (SPX1_FILE, b"spx1 bytes"),
        (INPUT_FILE, b"input bytes"),
    ] {
        std::fs::write(directory.path().join(name), bytes)?;
    }
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
fn the_clock_reads_seconds_since_the_epoch() {
    // 2023-11-14 is long past, and the value is seconds, not milliseconds.
    assert!(unix_seconds() > 1_700_000_000);
    assert!(unix_seconds() < 100_000_000_000);
}
