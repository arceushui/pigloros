#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! ADR-087's provider-wide no-local-process-creation invariant.
//!
//! The mountfsd transport receives reply descriptors atomically with
//! `MSG_CMSG_CLOEXEC`, but other in-process receivers do not: zbus 5.19
//! receives system-bus descriptors without it. The provider therefore never
//! creates a local process, so no descriptor can be inherited across a local
//! exec. This test checks every production source linked into the provider
//! (`pos-sandboxd` and its `pos-reference` dependency, excluding `#[cfg(test)]`
//! modules and the separate `pos-reference` binaries) and the manifests that
//! choose its runtime features.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

type TestResult = Result<(), Box<dyn Error>>;

/// Process-creation APIs, renamed or grouped `std::process` imports, zbus's
/// unchecked system-bus address (`unixexec` and `ibus` start processes), and
/// zlink's non-atomic Unix stream.
const FORBIDDEN: [&str; 21] = [
    "process::Command",
    "libc::fork",
    "libc::exec",
    "libc::system",
    "libc::popen",
    "libc::clone",
    "Connection::system()",
    "process as",
    "process::{",
    "Command::new",
    "CommandExt",
    "tokio::process",
    "fork(",
    "vfork",
    "execv",
    "fexecve",
    "posix_spawn",
    "pidfd_spawn",
    "clone3",
    "zlink::tokio",
    "unix::Stream",
];

#[cfg_attr(coverage_nightly, coverage(off))]
fn manifest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn provider_source_roots() -> [PathBuf; 2] {
    let root = manifest_root();
    [
        root.join("src"),
        root.join("../../crates/pos-reference/src"),
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) -> TestResult {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "bin") {
                rust_sources(&path, sources)?;
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_name().is_some_and(|name| name != "tests.rs")
        {
            sources.push(path);
        }
    }
    Ok(())
}

/// Production lines of one source: everything before a trailing inline
/// `#[cfg(test)] mod name {` block. The repository places such blocks last;
/// this check refuses any file where production code follows one.
#[cfg_attr(coverage_nightly, coverage(off))]
fn production_lines(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().collect();
    let mut production = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index] == "#[cfg(test)]" {
            let mut item = index + 1;
            while lines.get(item).is_some_and(|line| line.starts_with("#[")) {
                item += 1;
            }
            let module = lines
                .get(item)
                .is_some_and(|line| line.starts_with("mod ") && line.ends_with(" {"));
            if module {
                let tail: Vec<&str> = lines[item + 1..]
                    .iter()
                    .copied()
                    .filter(|line| !line.is_empty())
                    .collect();
                assert_eq!(tail.last(), Some(&"}"), "{}", path.display());
                assert!(
                    tail[..tail.len() - 1]
                        .iter()
                        .all(|line| line.starts_with(char::is_whitespace)),
                    "production code follows a test module in {}",
                    path.display()
                );
                return Ok(production);
            }
        }
        production.push(lines[index].to_owned());
        index += 1;
    }
    Ok(production)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn provider_production_code_never_creates_a_local_process() -> TestResult {
    let mut sources = Vec::new();
    for root in provider_source_roots() {
        rust_sources(&root, &mut sources)?;
    }
    assert!(
        sources
            .iter()
            .any(|path| path.ends_with("image_activator/socket.rs")),
        "the scan must include the mountfsd transport"
    );
    for path in &sources {
        for (number, line) in production_lines(path)?.iter().enumerate() {
            for token in FORBIDDEN {
                assert!(
                    !line.contains(token),
                    "{}:{}: `{token}` in provider production code",
                    path.display(),
                    number + 1
                );
            }
        }
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_mountfsd_receive_requests_close_on_exec_atomically() -> TestResult {
    let socket = manifest_root().join("src/image_activator/socket.rs");
    let production = production_lines(&socket)?.join("\n");
    assert_eq!(production.matches("recvmsg(").count(), 1);
    assert!(production.contains("RecvFlags::CMSG_CLOEXEC"));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn provider_manifests_enable_no_process_runtime() -> TestResult {
    let root = manifest_root();
    for manifest in [
        root.join("Cargo.toml"),
        root.join("../../crates/pos-reference/Cargo.toml"),
    ] {
        let text = fs::read_to_string(&manifest)?;
        let dependencies = text
            .split("\n[dev-dependencies]")
            .next()
            .unwrap_or_default();
        // Tokio's `process` feature spawns children. rustix's `process`
        // feature (getpid, getrlimit) creates no process and is not checked.
        let tokio = dependencies
            .split("\ntokio = ")
            .nth(1)
            .and_then(|entry| entry.split('}').next())
            .unwrap_or_default();
        assert!(
            !tokio.contains("\"process\"") && !dependencies.contains("async-process"),
            "{} enables a process-spawning runtime feature for production",
            manifest.display()
        );
    }
    Ok(())
}
