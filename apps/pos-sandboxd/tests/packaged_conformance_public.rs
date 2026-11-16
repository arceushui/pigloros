//! #444 evidence-guest driver through its public seams and binary.
//!
//! As root in the isolated container, the signed test installation is staged
//! at its fixed path and passed through production admission, the fixed
//! attempt registry and `activate_admitted_root`. The container's kernel
//! command line lacks `systemd.allow_userspace_verity=0`, so activation is
//! refused before mountfsd is called; the packaged positive cases run only in
//! the QEMU evidence guest (`.github/workflows/qemu-closure-evidence.yml`).
#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_sandboxd::packaged_conformance::{activate, exercise, removal_line, ConformanceError};
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

#[tokio::test]
async fn the_driver_reaches_production_activation_and_reports_its_refusal() -> TestResult {
    if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none() {
        return run_isolated("the_driver_reaches_production_activation_and_reports_its_refusal");
    }
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err("the isolated conformance child is not root".into());
    }

    // Without the provider's runtime directories the registry refuses.
    {
        let staged = StagedInstallation::stage()?;
        assert!(matches!(
            activate(&staged).await,
            Err(ConformanceError::Registry(_))
        ));
    }

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
        let mut report = Vec::new();
        exercise(
            case.outcome,
            |root| root.mount_id().to_string(),
            |_| async { Ok(()) },
            std::io::empty(),
            &mut report,
        )
        .await?;
        assert_eq!(
            String::from_utf8(report)?,
            "activation\trefused\tHostFeatureUnavailable\nrelease\tnone\n"
        );
        assert_eq!(
            removal_line(&case.directory.remove_unmounted()),
            "removal\tremoved"
        );
        assert!(Path::new("/run/pigloros/sandbox/attempts")
            .read_dir()?
            .next()
            .is_none());
    }

    // The binary composes the same steps from its three arguments.
    provision(&RUNTIME)?;
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/pos-reference/tests/vectors/sim1-ddi/x86-64");
    let image = Path::new("/tmp/conformance-image.raw");
    let expanded = Command::new("gzip")
        .arg("-dc")
        .arg(vectors.join("image.raw.gz"))
        .stdout(fs::File::create(image)?)
        .status()?;
    assert!(expanded.success());
    let output = Command::new(env!("CARGO_BIN_EXE_pos-sandboxd-conformance"))
        .arg(image)
        .arg(vectors.join("signer.der"))
        .arg(VECTOR_KEY_DESCRIPTION)
        // The child's coverage profile must not replace this process's.
        .env("LLVM_PROFILE_FILE", "/tmp/conformance-binary-%p.profraw")
        .stdin(Stdio::null())
        .output()?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "activation\trefused\tHostFeatureUnavailable\nrelease\tnone\nremoval\tremoved\n"
    );
    assert!(!Path::new("/var/lib/pigloros").exists());

    // A usage error fails the run with a diagnostic and no report.
    let output = Command::new(env!("CARGO_BIN_EXE_pos-sandboxd-conformance"))
        .env("LLVM_PROFILE_FILE", "/tmp/conformance-binary-%p.profraw")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.starts_with("pos-sandboxd-conformance: usage:"));
    Ok(())
}
