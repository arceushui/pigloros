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

/// The one production file that may name the kernel's descriptor-exec call
/// (owner decision Q9.9). ADR-087 A.3 governs the daemon mode; the launcher's
/// final step replaces its own image and creates no process.
const LAUNCHER_EXEC: &str = "launcher/exec.rs";

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
            // Only the exact descriptor-exec name is allowed, and only in the
            // launcher's exec file: removing it must leave no forbidden token.
            let checked = if path.ends_with(LAUNCHER_EXEC) {
                line.replace("execveat", "")
            } else {
                line.clone()
            };
            for token in FORBIDDEN {
                assert!(
                    !checked.contains(token),
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
            .and_then(|entry| {
                // An inline table ends at `}`; a plain version string at the line end.
                let end = if entry.starts_with('{') { '}' } else { '\n' };
                entry.split(end).next()
            })
            .unwrap_or_default();
        assert!(
            !tokio.contains("\"process\"") && !dependencies.contains("async-process"),
            "{} enables a process-spawning runtime feature for production",
            manifest.display()
        );
    }
    Ok(())
}

fn non_comment_text(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(production_lines(path)?
        .iter()
        .filter(|line| !line.trim_start().starts_with("//"))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_launcher_release_step_is_the_only_descriptor_exec() -> TestResult {
    let mut sources = Vec::new();
    for root in provider_source_roots() {
        rust_sources(&root, &mut sources)?;
    }
    let mut exec_files = Vec::new();
    for path in &sources {
        if non_comment_text(path)?.contains("execveat") {
            exec_files.push(path.clone());
        }
    }
    assert_eq!(exec_files.len(), 1, "{exec_files:?}");
    assert!(exec_files[0].ends_with(LAUNCHER_EXEC));
    let text = non_comment_text(&exec_files[0])?;
    // Exactly one call, on the held descriptor, with an empty path,
    // AT_EMPTY_PATH, the explicit argument vector and an empty environment.
    // Whitespace is removed first, so the check survives rustfmt layout.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(compact.matches("execveat(").count(), 1);
    assert!(compact.contains("execveat(adapter,c\"\",argv,&environment,AtFlags::AT_EMPTY_PATH)"));
    assert!(compact.contains("letenvironment:[CString;0]=[];"));
    assert_eq!(compact.matches("AT_EMPTY_PATH").count(), 1);
    Ok(())
}

/// Imports the launcher may use from `pos_reference`: the launch records and
/// the two digest helpers, nothing from admission or the verifier.
const LAUNCHER_PROTOCOL_NAMES: [&str; 13] = [
    "blake3_digest_of",
    "fdl1_digest",
    "ExecutionRelease",
    "FdIdentity",
    "FdLayoutEntry",
    "FdRole",
    "LaunchParameters",
    "LauncherReady",
    "LauncherReadyFields",
    "SandboxExecutionMode",
    "sandbox_provider_protocol",
    "self",
    "pos_reference",
];
/// Crates and path roots the launcher may import from.
const LAUNCHER_IMPORT_ROOTS: [&str; 7] = [
    "std",
    "super",
    "self",
    "rustix",
    "nix",
    "sd_listen_fds",
    "pos_reference",
];

/// Each `use` statement of the text, flattened to one line.
fn use_statements(text: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if current.is_none()
            && (trimmed.starts_with("use ")
                || trimmed.starts_with("pub use ")
                || trimmed.starts_with("pub(super) use "))
        {
            current = Some(String::new());
        }
        if let Some(statement) = current.as_mut() {
            statement.push_str(trimmed);
            statement.push(' ');
            if trimmed.ends_with(';') {
                statements.extend(current.take());
            }
        }
    }
    statements
}

/// ADR-087 reading (owner decision Q9.11): the launcher code path never calls
/// the verifier. Its sources import only from an allowlist of crates, and from
/// `pos_reference` only the launch records and digest helpers.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_launcher_never_reaches_admission_or_the_verifier() -> TestResult {
    const FORBIDDEN_REACH: [&str; 6] = [
        "crate::",
        "provider_admission",
        "image_proof",
        "webpki",
        "x509",
        "ReleaseSigner",
    ];
    let mut sources = Vec::new();
    rust_sources(&manifest_root().join("src/launcher"), &mut sources)?;
    assert!(sources.len() >= 7, "{sources:?}");
    for path in &sources {
        let text = non_comment_text(path)?;
        for token in FORBIDDEN_REACH {
            assert!(
                !text.contains(token),
                "{}: launcher code reaches `{token}`",
                path.display()
            );
        }
        for statement in use_statements(&text) {
            let body = statement
                .trim_start_matches("pub(super) ")
                .trim_start_matches("pub ")
                .trim_start_matches("use ")
                .trim_start_matches("::");
            let root = body
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default();
            assert!(
                LAUNCHER_IMPORT_ROOTS.contains(&root),
                "{}: launcher imports from `{root}`",
                path.display()
            );
            if root == "pos_reference" {
                for name in body
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .filter(|name| !name.is_empty())
                {
                    assert!(
                        LAUNCHER_PROTOCOL_NAMES.contains(&name),
                        "{}: launcher imports `{name}` from pos_reference",
                        path.display()
                    );
                }
            }
        }
        // Any other path into the protocol crate is also refused.
        assert_eq!(
            text.matches("pos_reference::").count(),
            use_statements(&text)
                .iter()
                .map(|statement| statement.matches("pos_reference::").count())
                .sum::<usize>(),
            "{}: inline pos_reference path outside a use statement",
            path.display()
        );
    }
    Ok(())
}
