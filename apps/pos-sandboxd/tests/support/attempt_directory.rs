// Shared isolated-root setup for the authenticated attempt boundary.

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    process::Command,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn fixed_registry() -> Result<(), BoxError> {
    for component in [
        "/run/pigloros",
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/registry",
        "/run/pigloros/sandbox/attempts",
    ] {
        fs::create_dir(component)?;
        fs::set_permissions(component, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn require_isolated_root(test_name: &str) -> Result<bool, BoxError> {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
        if fs::metadata("/proc/self")?.uid() != 0 {
            return Err("the isolated child is not root".into());
        }
        return Ok(true);
    }
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(test_name)
        .output()?;
    if output.status.success() {
        return Ok(false);
    }
    Err(format!(
        "isolated test {test_name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}
