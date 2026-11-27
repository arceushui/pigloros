use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt as _;

use super::{export_files, run_stage, write_export, StageCase, GUEST_LIMITS};
use crate::packaged_conformance::{describe, release, run_mode, ConformanceError, Mode};
use pos_reference::provider_admission::test_support::StagedLimits;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn the_stager_reads_its_files_and_adapter_arguments() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut paths = Vec::new();
    for (name, bytes) in [
        ("image", "image bytes"),
        ("certificate", "certificate bytes"),
        ("adapter", "adapter bytes"),
        ("spi1", "spi1 bytes"),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes)?;
        paths.push(path.into_os_string().into_string().map_err(|_| "path")?);
    }
    let [image, certificate, adapter, spi1] = &paths[..] else {
        return Err("four paths".into());
    };
    let provider = "/provider/binary";
    let full = |extra: &[&str]| {
        let mut values = vec![
            image.as_str(),
            certificate.as_str(),
            "CN: 01",
            adapter.as_str(),
            spi1.as_str(),
            "runtime.key",
            provider,
            "/export/directory",
        ];
        values.extend_from_slice(extra);
        arguments(&values)
    };

    let case = StageCase::from_arguments(&full(&[]))?;
    assert_eq!(case.image, b"image bytes");
    assert_eq!(case.certificate, b"certificate bytes");
    assert_eq!(case.key_description, "CN: 01");
    assert_eq!(case.adapter, b"adapter bytes");
    assert_eq!(case.spi1, b"spi1 bytes");
    assert_eq!(case.key_file_name, "runtime.key");
    assert_eq!(case.provider_binary, std::path::Path::new(provider));
    assert_eq!(case.export, std::path::Path::new("/export/directory"));
    assert!(case.adapter_arguments.is_empty());
    let case = StageCase::from_arguments(&full(&["honest", "7"]))?;
    assert_eq!(case.adapter_arguments, ["honest", "7"]);

    // Too few arguments, and each text argument that is not UTF-8.
    let mut wrong = vec![arguments(&[]), full(&[])[..7].to_vec()];
    for index in [2, 5] {
        let mut bad = full(&[]);
        bad[index] = OsString::from_vec(vec![0xff]);
        wrong.push(bad);
    }
    wrong.push({
        let mut bad = full(&["honest"]);
        bad[8] = OsString::from_vec(vec![0xff]);
        bad
    });
    for wrong in wrong {
        assert!(matches!(
            StageCase::from_arguments(&wrong),
            Err(ConformanceError::StageUsage)
        ));
    }

    // Each file is read, so a missing one is an I/O error.
    for index in [0, 1, 3, 4] {
        let mut missing = full(&[]);
        missing[index] = directory.path().join("missing").into_os_string();
        assert!(matches!(
            StageCase::from_arguments(&missing),
            Err(ConformanceError::Io(_))
        ));
    }

    // A malformed text argument is a usage error before any file is read, even
    // beside a missing file.
    for index in [2, 5, 8] {
        let mut bad = full(&["honest"]);
        bad[index] = OsString::from_vec(vec![0xff]);
        bad[0] = directory.path().join("missing").into_os_string();
        bad[4] = directory.path().join("missing").into_os_string();
        assert!(matches!(
            StageCase::from_arguments(&bad),
            Err(ConformanceError::StageUsage)
        ));
    }
    Ok(())
}

#[test]
fn the_stager_refuses_unusable_arguments_before_staging_anything() {
    assert!(matches!(
        run_stage(&arguments(&["only"]), io::empty(), &mut Vec::new()),
        Err(ConformanceError::StageUsage)
    ));
}

#[tokio::test]
async fn the_stage_argument_selects_the_stager() {
    let outcome = run_mode(
        arguments(&["stage"]),
        io::empty(),
        &mut Vec::new(),
        describe,
        release,
    )
    .await;
    assert!(matches!(outcome, Err(ConformanceError::StageUsage)));
}

#[test]
fn the_stager_reports_nothing_when_staging_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut paths = Vec::new();
    for (name, bytes) in [
        ("image", "not a disk image"),
        ("certificate", ""),
        ("adapter", "adapter"),
        ("spi1", "s"),
        ("provider", "provider"),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes)?;
        paths.push(path.into_os_string());
    }
    let [image, certificate, adapter, spi1, provider] = &paths[..] else {
        return Err("five paths".into());
    };
    let mut report = Vec::new();
    let refused = run_stage(
        &[
            image.clone(),
            certificate.clone(),
            "CN: 01".into(),
            adapter.clone(),
            spi1.clone(),
            "runtime.key".into(),
            provider.clone(),
            directory.path().into(),
        ],
        io::empty(),
        &mut report,
    );
    assert!(
        matches!(&refused, Err(ConformanceError::Stage(reason)) if reason.contains("GPT")),
        "{refused:?}"
    );
    assert!(report.is_empty());
    Ok(())
}

#[test]
fn an_image_that_is_not_a_ddi_is_refused_before_anything_is_staged() -> TestResult {
    let directory = tempfile::tempdir()?;
    let binary = directory.path().join("provider");
    std::fs::write(&binary, b"provider bytes")?;
    let case = StageCase {
        image: b"not a disk image".to_vec(),
        certificate: Vec::new(),
        key_description: "CN: 01".to_owned(),
        adapter: b"adapter".to_vec(),
        adapter_arguments: vec!["honest".to_owned()],
        spi1: vec![1],
        key_file_name: "runtime.key".to_owned(),
        provider_binary: binary,
        export: directory.path().to_owned(),
    };
    let refused = case.stage();
    assert!(
        matches!(&refused, Err(ConformanceError::Stage(reason)) if reason.contains("GPT")),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn the_export_writes_each_file_new_and_private() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    write_export(directory.path(), &[("one", b"first"), ("two", b"second")])?;
    for (name, bytes) in [("one", "first"), ("two", "second")] {
        let path = directory.path().join(name);
        assert_eq!(std::fs::read_to_string(&path)?, bytes);
        assert_eq!(
            std::fs::metadata(path)?.permissions().mode() & 0o7777,
            0o600
        );
    }
    // A file that exists is never overwritten, and a missing directory is refused.
    assert!(matches!(
        write_export(directory.path(), &[("one", b"other")]),
        Err(ConformanceError::Io(_))
    ));
    assert_eq!(
        std::fs::read_to_string(directory.path().join("one"))?,
        "first"
    );
    assert!(matches!(
        write_export(&directory.path().join("missing"), &[("one", b"x")]),
        Err(ConformanceError::Io(_))
    ));
    Ok(())
}

#[test]
fn the_first_argument_selects_the_mode() {
    for (first, mode) in [
        ("stage", Some(Mode::Stage)),
        ("execute", Some(Mode::Execute)),
        ("image.raw", None),
        ("Stage", None),
        ("", None),
    ] {
        assert_eq!(Mode::select(&arguments(&[first, "rest"])), mode);
    }
    assert_eq!(Mode::select(&[]), None);
    assert_eq!(Mode::select(&[OsString::from_vec(vec![0xff])]), None);
}

#[tokio::test]
async fn the_execute_argument_selects_the_execute_mode() {
    let outcome = run_mode(
        arguments(&["execute"]),
        io::empty(),
        &mut Vec::new(),
        describe,
        release,
    )
    .await;
    assert!(matches!(outcome, Err(ConformanceError::ExecuteUsage)));
}

#[test]
fn a_failed_export_removes_the_files_it_created_and_nothing_else() -> TestResult {
    let directory = tempfile::tempdir()?;
    // The second file exists already: the first, created by this call, is removed again, and
    // the file that was already there is untouched.
    std::fs::write(directory.path().join("two"), "old")?;
    let refused = write_export(
        directory.path(),
        &[("one", b"first"), ("two", b"second"), ("three", b"third")],
    );
    assert!(matches!(refused, Err(ConformanceError::Io(_))));
    assert!(!directory.path().join("one").exists());
    assert!(!directory.path().join("three").exists());
    assert_eq!(
        std::fs::read_to_string(directory.path().join("two"))?,
        "old"
    );
    // Once the obstacle is gone the same call succeeds, so a rerun works.
    std::fs::remove_file(directory.path().join("two"))?;
    write_export(
        directory.path(),
        &[("one", b"first"), ("two", b"second"), ("three", b"third")],
    )?;
    assert_eq!(
        std::fs::read_to_string(directory.path().join("three"))?,
        "third"
    );
    Ok(())
}

#[test]
fn a_failed_write_removes_the_created_files_and_a_stuck_one_is_reported() -> TestResult {
    use std::io::Write as _;

    let files: &[(&str, &[u8])] = &[("one", b"first"), ("two", b"second")];
    // The second write fails after its file was created: both created files are removed.
    let directory = tempfile::tempdir()?;
    let failing = |file: &mut std::fs::File, bytes: &[u8]| {
        if bytes == b"second" {
            Err(io::Error::other("disk full"))
        } else {
            file.write_all(bytes)
        }
    };
    let refused = export_files(directory.path(), files, failing);
    assert!(
        matches!(&refused, Err(ConformanceError::Io(error)) if error.to_string() == "disk full")
    );
    assert!(!directory.path().join("one").exists());
    assert!(!directory.path().join("two").exists());

    // A created file that is already gone is no cleanup failure: the write error stays.
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_owned();
    let vanishing = |file: &mut std::fs::File, bytes: &[u8]| {
        if bytes == b"second" {
            std::fs::remove_file(path.join("one"))?;
            Err(io::Error::other("disk full"))
        } else {
            file.write_all(bytes)
        }
    };
    let refused = export_files(directory.path(), files, vanishing);
    assert!(
        matches!(&refused, Err(ConformanceError::Io(error)) if error.to_string() == "disk full")
    );

    // A created file that cannot be removed (a directory took its place) is reported with the write
    // error, and the files created after it are removed all the same.
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_owned();
    let three: &[(&str, &[u8])] = &[("one", b"first"), ("two", b"second"), ("three", b"third")];
    let stuck = |file: &mut std::fs::File, bytes: &[u8]| {
        if bytes == b"third" {
            std::fs::remove_file(path.join("one"))?;
            std::fs::create_dir(path.join("one"))?;
            Err(io::Error::other("disk full"))
        } else {
            file.write_all(bytes)
        }
    };
    let refused = export_files(directory.path(), three, stuck);
    assert!(
        matches!(&refused, Err(ConformanceError::Stage(reason))
            if reason.contains("not removed") && reason.contains("disk full")),
        "{refused:?}"
    );
    assert!(!directory.path().join("two").exists());
    assert!(!directory.path().join("three").exists());
    assert!(directory.path().join("one").is_dir());
    Ok(())
}

#[test]
fn the_guest_case_has_the_limits_of_a_real_attempt() {
    // Each value is written out, so that a changed operator in the constant is a failure.
    for limits in [GUEST_LIMITS.broker, GUEST_LIMITS.launch] {
        assert_eq!(limits[0], 134_217_728, "memory: 128 MiB");
        assert_eq!(limits[2], 256, "tasks");
        assert_eq!(limits[3], 1_000_000, "one whole CPU");
        assert_eq!(limits[4], 120_000, "attempt watchdog, ms");
        assert_eq!(limits[6], 16_777_216, "files: 16 MiB");
        assert_eq!(limits[8], 1_048_576, "output: 1 MiB");
        assert_eq!(limits[9], 16_777_216, "work area: 16 MiB");
    }
    assert_eq!(GUEST_LIMITS.budget[0], 134_217_728);
    assert_eq!(GUEST_LIMITS.budget[4], 1_048_576);
    assert_eq!(GUEST_LIMITS.budget[5], 16_777_216);
    assert_eq!(GUEST_LIMITS.watchdog_ms, StagedLimits::EXCHANGE_MS);
}
