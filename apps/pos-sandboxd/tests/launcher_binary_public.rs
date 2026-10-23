//! The `pos-sandboxd` binary's launcher mode, driven as a real process.
//!
//! The binary is statically linked and root-bound in production. These tests
//! run it unprivileged, so every launch ends before the adapter could run;
//! each asserts the exact refusal. The in-process tests in `pos-sandboxd`
//! cover the full ready/release exchange against real sockets.

use std::{
    error::Error,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    process::{Command, Output, Stdio},
};

use pos_reference::sandbox_provider_protocol::{
    fdl1_digest, FdLayoutEntry, FdRole, LaunchParameters, SandboxExecutionMode,
};
use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};

type TestResult = Result<(), Box<dyn Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-sandboxd");

fn lpv1_hex() -> Result<String, Box<dyn Error>> {
    let layout = [FdLayoutEntry {
        fd_number: 3,
        role: FdRole::Release,
    }];
    let parameters = LaunchParameters::new(
        [1; 16],
        std::array::from_fn(|_| 2),
        [3; 32],
        "/adapter".to_owned(),
        vec!["--serve".to_owned()],
        fdl1_digest(SandboxExecutionMode::AirGapped, &layout)?,
    )?;
    Ok(hex(&parameters.to_canonical_cbor()?))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn no_mode_and_unknown_modes_print_usage_and_exit_two() -> TestResult {
    for arguments in [
        &[][..],
        &["serve"][..],
        &["serve", "00"][..],
        &["launch-barrier"][..],
    ] {
        let output = Command::new(BINARY).args(arguments).output()?;
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(stderr(&output).starts_with("usage: pos-sandboxd launch-barrier"));
    }
    let extra = Command::new(BINARY)
        .args(["launch-barrier", "00", "extra"])
        .output()?;
    assert_eq!(extra.status.code(), Some(2));
    Ok(())
}

#[test]
fn a_malformed_or_non_utf8_lpv1_is_refused() -> TestResult {
    for argument in [
        OsStr::new("zz"),
        OsStr::new("00"),
        OsStr::from_bytes(&[0xff]),
    ] {
        let output = Command::new(BINARY)
            .arg("launch-barrier")
            .arg(argument)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            stderr(&output),
            "pos-sandboxd: launch parameters are not a valid LPV1\n"
        );
    }
    Ok(())
}

#[test]
fn a_launch_without_the_systemd_environment_is_refused() -> TestResult {
    let output = Command::new(BINARY)
        .args(["launch-barrier", &lpv1_hex()?])
        .env_clear()
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output),
        "pos-sandboxd: launch environment is invalid\n"
    );
    Ok(())
}

#[test]
fn a_launch_for_another_pid_is_refused() -> TestResult {
    let output = Command::new(BINARY)
        .args(["launch-barrier", &lpv1_hex()?])
        .env_clear()
        .env("LISTEN_PID", "1")
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "piglor-release-v1")
        .env("INVOCATION_ID", "0123456789abcdef0123456789abcdef")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output),
        "pos-sandboxd: launch environment is invalid\n"
    );
    Ok(())
}

/// Start the launcher through `sh` so `LISTEN_PID` can name the launcher's own
/// pid (`sh` execs the binary and keeps its pid) and the release socket is
/// descriptor 3. The provider end is closed first, so the launch can never
/// block, and it is not root, so the peer check or an earlier check refuses.
#[test]
fn an_adopted_release_channel_from_a_non_root_peer_is_refused() -> TestResult {
    let (provider, launcher) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    drop(provider);
    // Every inherited descriptor above 3 (for example the test runner's) is
    // closed first, so the layout check sees exactly the release channel.
    let script = r#"exec 3<&0 0</dev/null
fd=4; while [ "$fd" -lt 64 ]; do eval "exec $fd>&-" 2>/dev/null; fd=$((fd + 1)); done
LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=piglor-release-v1 \
INVOCATION_ID=0123456789abcdef0123456789abcdef exec "$0" launch-barrier "$1""#;
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(BINARY)
        .arg(lpv1_hex()?)
        .stdin(Stdio::from(launcher))
        .output()?;
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    // The release channel is a valid adopted descriptor, so the refusal is the
    // peer check for a non-root user; as root the launch proceeds to the
    // adapter, which does not exist in the unit's root here.
    let expected = if rustix::process::getuid().is_root() {
        "pos-sandboxd: adapter is not a regular native ELF beneath the root\n"
    } else {
        "pos-sandboxd: release channel peer is not the root provider\n"
    };
    assert_eq!(stderr(&output), expected);
    Ok(())
}
