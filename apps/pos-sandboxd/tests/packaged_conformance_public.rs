//! #444 evidence-guest driver through its public seams and binary.
//!
//! As root in the isolated container, the signed test installation is staged
//! at its fixed path and passed through production admission, the fixed
//! attempt registry and `activate_admitted_root`. The container's kernel
//! command line lacks `systemd.allow_userspace_verity=0`, so activation is
//! refused before mountfsd is called; the packaged positive cases run only in
//! the QEMU evidence guest (`.github/workflows/qemu-closure-evidence.yml`).
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::{
    error::Error,
    ffi::OsString,
    fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_sandboxd::packaged_conformance::{activate, describe, release, run, ConformanceError};
use pos_sandboxd::ImageActivationError;

type TestResult = Result<(), Box<dyn Error>>;

const PRIVILEGED_COMPOSITION_TEST: &str = "PIGLOROS_PRIVILEGED_COMPOSITION_TEST";
const RUNTIME: [&str; 4] = [
    "/run/pigloros",
    "/run/pigloros/sandbox",
    "/run/pigloros/sandbox/registry",
    "/run/pigloros/sandbox/attempts",
];
// The kernel's x509 description of the x86-64 sim1-ddi vector's signer.der.
const VECTOR_KEY_DESCRIPTION: &str =
    "PiglorOS SIM1 DDI fixture x86-64: e0b3c91db94dc506da3652b0ace1603e49009f3e";

fn run_isolated(test_name: &str) -> TestResult {
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(test_name)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "isolated test {test_name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

/// The empty private runtime directories provider startup leaves.
fn provision(components: &[&str]) -> TestResult {
    if Path::new(RUNTIME[0]).exists() {
        fs::remove_dir_all(RUNTIME[0])?;
    }
    for component in components {
        fs::create_dir(component)?;
        fs::set_permissions(component, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A report that refuses every write.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken report"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("broken report"))
    }
}

#[tokio::test]
async fn the_driver_reaches_production_activation_and_reports_its_refusal() -> TestResult {
    if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none() {
        return run_isolated("the_driver_reaches_production_activation_and_reports_its_refusal");
    }
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err("the isolated conformance child is not root".into());
    }
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/pos-reference/tests/vectors/sim1-ddi/x86-64");
    // Private to this test and removed with it, unlike a fixed /tmp path.
    let scratch = tempfile::tempdir()?;
    let image = scratch.path().join("image.raw");
    let expanded = Command::new("gzip")
        .arg("-dc")
        .arg(vectors.join("image.raw.gz"))
        .stdout(fs::File::create(&image)?)
        .status()?;
    assert!(expanded.success());
    let adapter = scratch.path().join("adapter");
    fs::write(&adapter, b"adapter")?;
    let arguments = || -> Vec<OsString> {
        vec![
            image.clone().into(),
            vectors.join("signer.der").into(),
            VECTOR_KEY_DESCRIPTION.into(),
            adapter.clone().into(),
        ]
    };

    // Without the provider's runtime directories the registry refuses, and
    // the staged installation is removed again.
    let refused = run(arguments(), io::empty(), &mut Vec::new(), describe, release).await;
    assert!(matches!(refused, Err(ConformanceError::Registry(_))));
    assert!(!Path::new("/var/lib/pigloros").exists());

    // An installation changed after staging fails production admission.
    {
        let staged = StagedInstallation::stage()?;
        fs::remove_dir_all("/var/lib/pigloros/sandbox/images")?;
        assert!(matches!(
            activate(&staged).await,
            Err(ConformanceError::Admission(_))
        ));
    }

    // With them, the attempt is registered and its directory prepared, and
    // production activation refuses on this host's kernel command line.
    provision(&RUNTIME)?;
    {
        let staged = StagedInstallation::stage()?;
        let case = activate(&staged).await?;
        assert_eq!(
            case.outcome.as_ref().err(),
            Some(&ImageActivationError::HostFeatureUnavailable)
        );
        assert!(Path::new("/run/pigloros/sandbox/attempts")
            .read_dir()?
            .next()
            .is_some());
    }

    // A report that cannot be written fails the run after activation.
    provision(&RUNTIME)?;
    let broken = run(arguments(), io::empty(), &mut Broken, describe, release).await;
    assert!(matches!(broken, Err(ConformanceError::Io(_))));

    // The whole case: refused, nothing to release, directory removed.
    provision(&RUNTIME)?;
    let mut report = Vec::new();
    run(arguments(), io::empty(), &mut report, describe, release).await?;
    assert_eq!(
        String::from_utf8(report)?,
        "activation\trefused\tHostFeatureUnavailable\nrelease\tnone\nremoval\tremoved\n"
    );
    assert!(Path::new("/run/pigloros/sandbox/attempts")
        .read_dir()?
        .next()
        .is_none());
    assert!(!Path::new("/var/lib/pigloros").exists());

    // The binary wires the same run to its arguments and standard streams.
    provision(&RUNTIME)?;
    let output = Command::new(env!("CARGO_BIN_EXE_pos-sandboxd-conformance"))
        .args(arguments())
        // The child's coverage profile must not replace this process's.
        .env(
            "LLVM_PROFILE_FILE",
            // Cargo's own scratch directory, which outlives the test so that
            // the coverage run can merge the profile.
            Path::new(env!("CARGO_TARGET_TMPDIR")).join("conformance-binary-%p.profraw"),
        )
        .stdin(Stdio::null())
        .output()?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "activation\trefused\tHostFeatureUnavailable\nrelease\tnone\nremoval\tremoved\n"
    );
    assert!(!Path::new("/var/lib/pigloros").exists());
    Ok(())
}

/// Unprivileged and outside the container, so the coverage run records the
/// binary's own profile beside this test's.
#[test]
fn the_binary_fails_a_usage_error_with_a_diagnostic_and_no_report() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_pos-sandboxd-conformance"))
        .stdin(Stdio::null())
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "pos-sandboxd-conformance: usage: pos-sandboxd-conformance IMAGE CERTIFICATE_DER \
         KEY_DESCRIPTION ADAPTER [ADAPTER_ARGUMENT...]\n"
    );
    Ok(())
}
