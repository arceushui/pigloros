use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt as _;

use super::{run_stage, StageCase};
use crate::packaged_conformance::{describe, release, run_mode, ConformanceError};

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
    assert!(case.adapter_arguments.is_empty());
    let case = StageCase::from_arguments(&full(&["honest", "7"]))?;
    assert_eq!(case.adapter_arguments, ["honest", "7"]);

    // Too few arguments, and each text argument that is not UTF-8.
    let mut wrong = vec![arguments(&[]), full(&[])[..6].to_vec()];
    for index in [2, 5] {
        let mut bad = full(&[]);
        bad[index] = OsString::from_vec(vec![0xff]);
        wrong.push(bad);
    }
    wrong.push({
        let mut bad = full(&["honest"]);
        bad[7] = OsString::from_vec(vec![0xff]);
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
    for index in [2, 5, 7] {
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
    };
    let refused = case.stage();
    assert!(
        matches!(&refused, Err(ConformanceError::Stage(reason)) if reason.contains("GPT")),
        "{refused:?}"
    );
    Ok(())
}
