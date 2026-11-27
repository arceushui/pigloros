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
//!
//! The root selector is held to the same rule (ADR-069 R12 I18): systemd
//! creates the provider runtime, and the selector only asks for it over the
//! system bus. The scan and the manifest check therefore also cover the
//! `apps/pos-root-selector` package.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

type TestResult = Result<(), Box<dyn Error>>;

/// The launcher source allowed to name the kernel's descriptor-exec call.
/// Its final step replaces its own image without creating a process.
const LAUNCHER_EXEC: &str = "launcher/exec.rs";

/// Tokens that include another file's bytes, text or source. Provider code could hide a forbidden
/// call in an unscanned file this way, so every use is checked against [`INCLUDES`].
const INCLUDE_TOKENS: [&str; 3] = ["include!(", "include_bytes!(", "include_str!("];

/// The files that include another file, with the exact paths each may include. The included Rust
/// support files are scanned for the forbidden tokens too (see `SUPPORT_ROOTS`), so an include of
/// a new support file, or of a path not listed here, fails this test and needs a review. Data
/// (test vectors and the guest syscall names) cannot create a process.
const INCLUDES: [(&str, &[&str]); 5] = [
    (
        "pos-reference/src/lib.rs",
        &[
            "/tests/support/mod.rs",
            "/tests/support/sandbox_admission_fixture.rs",
        ],
    ),
    ("pos-reference/src/root_selector.rs", &["tests/vectors/"]),
    (
        "pos-reference/src/selector/installation.rs",
        &["tests/vectors/"],
    ),
    (
        "pos-reference/src/selector/installation/fixture.rs",
        &["tests/vectors/", "guest-syscalls-"],
    ),
    (
        "pos-sandboxd/src/test_fixtures.rs",
        &[
            "/tests/support/staged_execution.rs",
            "/tests/support/attempt_directory.rs",
            "pos-conformance/vectors/",
        ],
    ),
];

/// The directories of the Rust support files that the sources include. They are scanned whole.
const SUPPORT_ROOTS: [&str; 2] = ["../../crates/pos-reference/tests/support", "tests/support"];

/// The one place a support file starts a process: the privileged test fixture re-runs its own test
/// binary through `scripts/run-isolated-test.sh` (test-only, `attempt_directory.rs`).
const SUPPORT_EXEMPT_FILE: &str = "attempt_directory.rs";
/// The exempt lines, whole (after trimming), each of which must occur exactly once in the file.
const SUPPORT_EXEMPT_LINES: [&str; 2] = ["process::Command,", "let output = Command::new(runner)"];

/// The guest syscall allow-list data files and the process-creating names each may hold. The
/// allow-list lets systemd's executor and the launcher start the adapter, so these names are
/// expected; a new `fork`, `clone`, `exec` or `spawn` family name in a data file is a reviewed
/// change to this table.
const GUEST_SYSCALL_FILES: [(&str, &[&str]); 2] = [
    (
        "../../crates/pos-reference/src/selector/installation/guest-syscalls-x86_64.txt",
        &["clone", "clone3", "execve", "execveat"],
    ),
    (
        "../../crates/pos-reference/src/selector/installation/guest-syscalls-aarch64.txt",
        &["clone", "clone3", "execve", "execveat"],
    ),
];

/// Name fragments of every syscall that creates a process or replaces a process image.
const PROCESS_SYSCALL_FRAGMENTS: [&str; 4] = ["fork", "clone", "exec", "spawn"];

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
fn provider_source_roots() -> [PathBuf; 3] {
    let root = manifest_root();
    [
        root.join("src"),
        root.join("../../crates/pos-reference/src"),
        root.join("../pos-root-selector/src"),
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
    // The R11 provider installation modules (#1358), the R12 recovery peer
    // (#349, I16), and the selector's lifecycle adapter and recovery
    // operation (#349, I18) are held to the rule too.
    for module in [
        "provider_lifecycle.rs",
        "launcher/process_identity.rs",
        "selector/recovery.rs",
        "selector/recovery/authority.rs",
        "selector/recovery/host.rs",
        "selector/recovery/port.rs",
        "selector/recovery/session.rs",
        "provider_installation.rs",
        "provider_installation/codec.rs",
        "provider_installation/files.rs",
        "provider_runtime.rs",
        "provider_runtime/endpoint.rs",
        "provider_runtime/notify.rs",
        "provider_runtime/reconcile.rs",
        "provider_runtime/recovery_peer.rs",
        "provider_runtime/revocation.rs",
        "provider_runtime/serving.rs",
    ] {
        assert!(
            sources.iter().any(|path| path.ends_with(module)),
            "the scan must include {module}"
        );
    }
    assert!(
        sources
            .iter()
            .any(|path| path.ends_with("pos-root-selector/src/main.rs")),
        "the scan must include the root selector entrypoint"
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
        let lines = production_lines(path)?;
        let allowed: &[&str] = INCLUDES
            .iter()
            .find(|(file, _)| path.ends_with(file))
            .map_or(&[], |(_, allowed)| *allowed);
        assert_includes_are_listed(path, &lines, |window| {
            allowed.iter().any(|fragment| window.contains(fragment))
        });
    }
    Ok(())
}

/// Every include token in `lines` has, in its own macro call (up to the closing parenthesis that
/// matches the one after the token), a path that `listed` accepts.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_includes_are_listed(path: &Path, lines: &[String], listed: impl Fn(&str) -> bool) {
    for (number, line) in lines.iter().enumerate() {
        for token in INCLUDE_TOKENS {
            for (column, _) in line.match_indices(token) {
                let rest = format!("{}\n{}", &line[column..], lines[number + 1..].join("\n"));
                let open = token.len() - 1;
                let mut depth = 0_usize;
                let closed = rest[open..].char_indices().find_map(|(offset, character)| {
                    match character {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(open + offset + 1);
                            }
                        }
                        _ => {}
                    }
                    None
                });
                assert!(
                    closed.is_some(),
                    "{}:{}: `{token}` has no closing parenthesis",
                    path.display(),
                    number + 1
                );
                let end = closed.unwrap_or(rest.len());
                assert!(
                    listed(&rest[..end]),
                    "{}:{}: `{token}` of an unlisted path in provider code",
                    path.display(),
                    number + 1
                );
            }
        }
    }
}

/// The Rust support files that the sources include hold no process creation either, apart from
/// the one exempt site, and include only test vectors or each other.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn included_support_files_never_create_a_local_process() -> TestResult {
    let mut sources = Vec::new();
    let mut siblings = Vec::new();
    for root in SUPPORT_ROOTS {
        rust_sources(&manifest_root().join(root), &mut sources)?;
    }
    for path in &sources {
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            siblings.push(name.to_owned());
        }
    }
    for needed in [
        "mod.rs",
        "sandbox_admission_fixture.rs",
        SUPPORT_EXEMPT_FILE,
    ] {
        assert!(
            siblings.iter().any(|name| name == needed),
            "the support scan must include {needed}"
        );
    }
    for path in &sources {
        let text = fs::read_to_string(path)?;
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        for (number, line) in lines.iter().enumerate() {
            let exempt = path.ends_with(SUPPORT_EXEMPT_FILE)
                && SUPPORT_EXEMPT_LINES
                    .iter()
                    .any(|allowed| line.trim() == *allowed);
            for token in FORBIDDEN {
                assert!(
                    exempt || !line.contains(token),
                    "{}:{}: `{token}` in an included support file",
                    path.display(),
                    number + 1
                );
            }
        }
        if path.ends_with(SUPPORT_EXEMPT_FILE) {
            for allowed in SUPPORT_EXEMPT_LINES {
                assert_eq!(
                    lines.iter().filter(|line| line.trim() == allowed).count(),
                    1,
                    "`{allowed}` must occur exactly once in {}",
                    path.display()
                );
            }
        }
        assert_includes_are_listed(path, &lines, |window| {
            window.contains("\"../vectors/")
                || window.contains("\"../../../../fixtures/conformance/")
                || siblings
                    .iter()
                    .any(|name| window.contains(&format!("\"{name}\"")))
        });
    }
    Ok(())
}

/// The guest allow-list data files are data, not Rust, so the token scan never reads them. The
/// process-related names in them are pinned here instead.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn guest_syscall_lists_hold_only_the_expected_process_names() -> TestResult {
    for (file, expected) in GUEST_SYSCALL_FILES {
        let text = fs::read_to_string(manifest_root().join(file))?;
        let mut process_names: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|name| {
                PROCESS_SYSCALL_FRAGMENTS
                    .iter()
                    .any(|fragment| name.contains(fragment))
            })
            .collect();
        process_names.sort_unstable();
        assert_eq!(process_names, expected, "{file}");
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
        root.join("../pos-root-selector/Cargo.toml"),
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
const LAUNCHER_IMPORT_ROOTS: [&str; 14] = [
    "std",
    "super",
    "self",
    // The launcher's own child modules.
    "adapter",
    "barrier",
    "descriptors",
    "environment",
    "error",
    "exec",
    "host",
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
        "RuntimeAttestationSigner",
    ];
    let mut sources = Vec::new();
    rust_sources(&manifest_root().join("src/launcher"), &mut sources)?;
    assert!(sources.len() >= 7, "{sources:?}");
    for needed in ["host.rs", "barrier.rs", "process_identity.rs"] {
        assert!(
            sources.iter().any(|path| path.ends_with(needed)),
            "the launcher scan must include {needed}"
        );
    }
    for path in &sources {
        let text = non_comment_text(path)?;
        // `provider_identity` opens a pidfd on pid 1: in the launcher's namespace that is the
        // launcher itself, so only the provider may call it. Outside `process_identity.rs`
        // (which defines it; its launcher-side readers are checked instead) the name may only appear as a field access
        // (`parameters.provider_identity`): a call, an import or an alias (`... as x`) names it
        // without a leading dot.
        if path.ends_with("process_identity.rs") {
            for reader in ["fn own_process_identity", "fn peer_process_identity"] {
                let body = text.split(reader).nth(1).and_then(|rest| {
                    rest.split("\nfn ")
                        .next()
                        .and_then(|rest| rest.split("\npub(crate) fn ").next())
                });
                assert!(body.is_some(), "{reader} must exist in process_identity.rs");
                assert!(
                    !body.unwrap_or_default().contains("provider_identity"),
                    "{reader} must not call `provider_identity`"
                );
            }
        } else {
            for (column, _) in text.match_indices("provider_identity") {
                assert!(
                    text[..column].ends_with('.'),
                    "{}: launcher code names `provider_identity` other than as a field",
                    path.display()
                );
            }
        }
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
