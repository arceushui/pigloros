use std::error::Error;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt as _;

use super::{
    exercise, exit_status, removal_line, report_line, run, runtime, ConformanceCase,
    ConformanceError, ImageActivationError, PreparedAttemptDirectory, Release,
    SystemdAttemptRegistryError, VerifiedRootMount,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A reader or writer whose every operation fails.
struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken control input"))
    }
}

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken report"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("broken report"))
    }
}

/// Writes succeed, but every flush fails.
struct Unflushable(Vec<u8>);

impl Write for Unflushable {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("unflushable report"))
    }
}

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn detached(root: u64, _: &()) -> Release<'_> {
    Box::pin(async move {
        assert_eq!(root, 7);
        Ok(())
    })
}

fn unverified((): (), _: &()) -> Release<'_> {
    Box::pin(async { Err(ImageActivationError::ResourceAbsenceUnverified) })
}

fn never_released((): (), _: &()) -> Release<'_> {
    Box::pin(async { Ok(()) })
}

fn describe(_: &VerifiedRootMount) -> String {
    String::new()
}

fn release(mount: VerifiedRootMount, _: &PreparedAttemptDirectory) -> Release<'_> {
    drop(mount);
    Box::pin(async { Ok(()) })
}

#[test]
fn arguments_are_exactly_image_certificate_and_utf8_description() -> TestResult {
    let directory = tempfile::tempdir()?;
    let image = directory.path().join("image.raw");
    let certificate = directory.path().join("signer.der");
    std::fs::write(&image, b"image bytes")?;
    std::fs::write(&certificate, b"certificate bytes")?;
    let (image, certificate) = (
        image.to_str().ok_or("temporary path")?,
        certificate.to_str().ok_or("temporary path")?,
    );

    let case = ConformanceCase::from_arguments(&arguments(&[image, certificate, "CN: 01"]))?;
    assert_eq!(case.image, b"image bytes");
    assert_eq!(case.certificate, b"certificate bytes");
    assert_eq!(case.key_description, "CN: 01");

    for wrong in [
        arguments(&[]),
        arguments(&[image, certificate]),
        arguments(&[image, certificate, "CN: 01", "extra"]),
        vec![
            image.into(),
            certificate.into(),
            OsString::from_vec(vec![0xff]),
        ],
    ] {
        assert!(matches!(
            ConformanceCase::from_arguments(&wrong),
            Err(ConformanceError::Usage)
        ));
    }
    let missing = directory.path().join("missing");
    let missing = missing.to_str().ok_or("temporary path")?;
    for unreadable in [[missing, certificate], [image, missing]] {
        assert!(matches!(
            ConformanceCase::from_arguments(&arguments(&[unreadable[0], unreadable[1], "CN: 01"])),
            Err(ConformanceError::Io(_))
        ));
    }
    Ok(())
}

#[test]
fn an_image_that_is_not_a_ddi_is_refused_before_staging() {
    let case = ConformanceCase {
        image: b"not a disk image".to_vec(),
        certificate: Vec::new(),
        key_description: "CN: 01".to_owned(),
    };
    let refused = case.stage();
    assert!(
        matches!(&refused, Err(ConformanceError::Stage(reason)) if reason.contains("GPT")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_mounted_root_is_held_until_control_closes_then_released() -> TestResult {
    let mut report = Vec::new();
    exercise(
        Ok::<_, ImageActivationError>(7_u64),
        |root| format!("{root}\t/run/pigloros/sandbox/attempts/a/root"),
        detached,
        &(),
        b"collector done\n".as_slice(),
        &mut report,
    )
    .await?;
    assert_eq!(
        String::from_utf8(report)?,
        "activation\tmounted\t7\t/run/pigloros/sandbox/attempts/a/root\nrelease\tdetached\n"
    );

    let mut report = Vec::new();
    exercise(
        Ok::<_, ImageActivationError>(()),
        |()| "root".to_owned(),
        unverified,
        &(),
        io::empty(),
        &mut report,
    )
    .await?;
    assert_eq!(
        String::from_utf8(report)?,
        "activation\tmounted\troot\nrelease\tfailed\tResourceAbsenceUnverified\n"
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_activation_has_nothing_to_release() -> TestResult {
    let mut report = Vec::new();
    exercise(
        Err::<(), _>(ImageActivationError::MethodRejected),
        |()| String::new(),
        never_released,
        &(),
        io::empty(),
        &mut report,
    )
    .await?;
    assert_eq!(
        String::from_utf8(report)?,
        "activation\trefused\tMethodRejected\nrelease\tnone\n"
    );
    Ok(())
}

#[tokio::test]
async fn a_broken_report_or_control_input_fails_the_case() {
    let refused = || Err::<(), _>(ImageActivationError::HostFeatureUnavailable);
    let broken_report = exercise(
        refused(),
        |()| String::new(),
        never_released,
        &(),
        io::empty(),
        &mut Broken,
    )
    .await;
    assert!(matches!(broken_report, Err(ConformanceError::Io(_))));
    let broken_control = exercise(
        refused(),
        |()| String::new(),
        never_released,
        &(),
        Broken,
        &mut Vec::new(),
    )
    .await;
    assert!(matches!(broken_control, Err(ConformanceError::Io(_))));
    let mut unflushable = Unflushable(Vec::new());
    assert!(matches!(
        report_line(&mut unflushable, "line"),
        Err(ConformanceError::Io(_))
    ));
    assert_eq!(unflushable.0, b"line\n");
}

#[test]
fn removal_and_exit_status_report_each_outcome() {
    assert_eq!(removal_line(&Ok(())), "removal\tremoved");
    assert_eq!(
        removal_line(&Err(SystemdAttemptRegistryError::UnsafeRegistry)),
        "removal\tfailed\tUnsafeRegistry"
    );

    let mut diagnostics = Vec::new();
    assert_eq!(
        format!("{:?}", exit_status(Ok(()), &mut diagnostics)),
        format!("{:?}", std::process::ExitCode::SUCCESS)
    );
    assert!(diagnostics.is_empty());
    assert_eq!(
        format!(
            "{:?}",
            exit_status(Err(ConformanceError::Usage), &mut diagnostics)
        ),
        format!("{:?}", std::process::ExitCode::FAILURE)
    );
    assert_eq!(
        String::from_utf8_lossy(&diagnostics),
        "pos-sandboxd-conformance: usage: pos-sandboxd-conformance IMAGE CERTIFICATE_DER \
         KEY_DESCRIPTION\n"
    );
}

#[test]
fn every_error_names_its_stage() {
    for (error, expected) in [
        (
            ConformanceError::Io(io::Error::other("closed")),
            "conformance I/O failed: closed",
        ),
        (
            ConformanceError::Stage("no GPT".to_owned()),
            "staging the test installation failed: no GPT",
        ),
        (
            ConformanceError::Admission(
                pos_reference::selector::SelectorBoundaryError::ArtifactInvalid,
            ),
            "provider image admission failed: ",
        ),
        (
            ConformanceError::Registry(SystemdAttemptRegistryError::UnsafeRegistry),
            "the attempt registry failed: unsafe systemd attempt registry",
        ),
    ] {
        assert!(error.to_string().starts_with(expected), "{error}");
    }
}

#[tokio::test]
async fn a_run_stops_at_the_first_step_that_fails() -> TestResult {
    let usage = run(Vec::new(), io::empty(), &mut Vec::new(), describe, release).await;
    assert!(matches!(usage, Err(ConformanceError::Usage)));

    let directory = tempfile::tempdir()?;
    let image = directory.path().join("image.raw");
    std::fs::write(&image, b"not a disk image")?;
    let mut report = Vec::new();
    let staging = run(
        vec![image.clone().into(), image.into(), "CN: 01".into()],
        io::empty(),
        &mut report,
        describe,
        release,
    )
    .await;
    assert!(matches!(staging, Err(ConformanceError::Stage(_))));
    assert!(report.is_empty());
    Ok(())
}

#[test]
fn the_runtime_has_a_time_driver() -> TestResult {
    // The timer is created inside the runtime, which must drive it.
    runtime()?.block_on(async { tokio::time::sleep(std::time::Duration::ZERO).await });
    Ok(())
}
