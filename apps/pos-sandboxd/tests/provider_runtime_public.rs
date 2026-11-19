//! The provider runtime's startup authority and `provider-runtime` mode
//! through the public seams (ADR-069 R11 §5.1 and §10, #1358).
//!
//! As root in the isolated container, the signed test installation is staged
//! at its fixed path. Neither this test binary nor the built `pos-sandboxd`
//! is the admitted provider binary, so a startup that admits SIC1 always
//! stops at the self-binding; the later steps, the bind, `READY=1` and the
//! serving are exercised in the crate's own tests.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT;
use pos_reference::selector::SelectorBoundaryError;
use pos_sandboxd::{start_runtime_authority, ProviderStartupError};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Run `name` again as root in the isolated container, or report that this
/// process already is that run.
fn in_isolated_root(name: &str) -> TestResult<bool> {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
        return Ok(true);
    }
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(name)
        .output()?;
    assert!(
        output.status.success(),
        "isolated test {name} failed: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(false)
}

#[test]
fn startup_refuses_a_missing_or_pending_installation_and_a_foreign_executable() -> TestResult {
    if !in_isolated_root(
        "startup_refuses_a_missing_or_pending_installation_and_a_foreign_executable",
    )? {
        return Ok(());
    }
    // Step 2: no SIC1.
    assert!(matches!(
        start_runtime_authority(),
        Err(ProviderStartupError::Installation(_))
    ));
    let staged = StagedInstallation::stage()?;
    // Step 3: SIC1 is admitted, but this process does not run its binary.
    assert_eq!(
        start_runtime_authority().err(),
        Some(ProviderStartupError::SelfBinding)
    );
    // SIR1 pending: SIC1 itself is refused, before any other step.
    let pending = Path::new(SANDBOX_ARTIFACT_ROOT).join("installation-update.cbor");
    fs::write(&pending, b"pending")?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o400))?;
    assert_eq!(
        start_runtime_authority().err(),
        Some(ProviderStartupError::Installation(
            SelectorBoundaryError::ArtifactInvalid
        ))
    );
    drop(staged);
    Ok(())
}

/// The built provider binary.
const BINARY: &str = env!("CARGO_BIN_EXE_pos-sandboxd");
/// The runtime directory the SIC1 test endpoints lie in.
const RUNTIME: &str = "/run/pigloros";

/// Run `pos-sandboxd provider-runtime` with `NOTIFY_SOCKET` naming
/// `manager`'s abstract address, and socket-activation variables that the
/// mode must ignore.
fn provider_runtime(manager: &str) -> TestResult<Output> {
    Ok(Command::new(BINARY)
        .arg("provider-runtime")
        .env("NOTIFY_SOCKET", format!("@{manager}"))
        .env("LISTEN_FDS", "2")
        .env("LISTEN_PID", std::process::id().to_string())
        .output()?)
}

/// Assert a failed start: one diagnostic line, no node in the runtime
/// directory and no datagram to the manager.
fn assert_refused_before_binding(output: &Output, manager: &UnixDatagram) -> TestResult<String> {
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = String::from_utf8(output.stderr.clone())?;
    assert_eq!(diagnostic.lines().count(), 1, "{diagnostic}");
    assert_eq!(fs::read_dir(RUNTIME)?.count(), 0);
    let mut datagram = [0; 16];
    assert!(manager.recv(&mut datagram).is_err());
    Ok(diagnostic)
}

#[test]
fn the_provider_runtime_mode_binds_nothing_when_startup_refuses() -> TestResult {
    if !in_isolated_root("the_provider_runtime_mode_binds_nothing_when_startup_refuses")? {
        return Ok(());
    }
    fs::create_dir(RUNTIME)?;
    fs::set_permissions(RUNTIME, fs::Permissions::from_mode(0o755))?;
    let name = "pigloros-provider-runtime-public";
    let manager = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name)?)?;
    manager.set_nonblocking(true)?;
    // No SIC1.
    assert!(
        assert_refused_before_binding(&provider_runtime(name)?, &manager)?
            .starts_with("pos-sandboxd: sandbox selector")
    );
    // SIC1 admits a provider binary that is not this executable.
    let staged = StagedInstallation::stage()?;
    assert_eq!(
        assert_refused_before_binding(&provider_runtime(name)?, &manager)?,
        "pos-sandboxd: the running executable is not the admitted provider binary\n"
    );
    drop(staged);
    // Any further argument is a usage error.
    let extra = Command::new(BINARY)
        .args(["provider-runtime", "extra"])
        .output()?;
    assert_eq!(extra.status.code(), Some(2));
    Ok(())
}

/// The production sources of the `provider-runtime` mode.
fn runtime_sources() -> TestResult<Vec<PathBuf>> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = vec![source.join("provider_runtime.rs")];
    for entry in fs::read_dir(source.join("provider_runtime"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_name().is_some_and(|name| name != "tests.rs")
        {
            sources.push(path);
        }
    }
    Ok(sources)
}

#[test]
fn the_provider_runtime_reads_only_notify_socket_from_its_environment() -> TestResult {
    // R11 §10 invariant 2: the runtime reads `NOTIFY_SOCKET` and no other
    // variable. Test modules live in `tests.rs` files and inline modules
    // after the production code.
    let mut reads = Vec::new();
    for path in runtime_sources()? {
        let text = fs::read_to_string(&path)?;
        let production = text
            .split("#[cfg(test)]\n#[cfg_attr(coverage_nightly, coverage(off))]\nmod tests {")
            .next()
            .unwrap_or_default();
        reads.extend(
            production
                .lines()
                .filter(|line| line.contains("env::") || line.contains("env!"))
                .map(|line| line.trim().to_owned()),
        );
    }
    assert_eq!(reads, ["std::env::var_os(\"NOTIFY_SOCKET\").as_deref(),"]);
    Ok(())
}
