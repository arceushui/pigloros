#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! ADR-069 R12 I15 and I18: where the root selector is composed.
//!
//! The `pos-root-selector` binary lives only in this package (owner decision
//! O7), so `pos-reference` keeps no copy of it, and this package's entrypoint
//! is the only production code that activates the selector runtime. Exactly
//! one production type implements `ProviderLifecyclePort`, the systemd
//! adapter of `pos-sandboxd`; only this entrypoint composes it, and it reaches
//! the system bus only through `connect_system` (Unix transport, no
//! `unixexec`).

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ACTIVATION: &str = "RootSelectorRuntime::activate";
const COMPOSITION: &str = "SystemdProviderLifecycle::connect";
const ADAPTER: &str = "apps/pos-sandboxd/src/provider_lifecycle.rs";

#[cfg_attr(coverage_nightly, coverage(off))]
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every production Rust source under `directory`. Test-only files are
/// skipped: `tests.rs` modules and `tests/` and `support/` directories.
#[cfg_attr(coverage_nightly, coverage(off))]
fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) -> TestResult {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str());
        if path.is_dir() {
            if !matches!(name, Some("tests" | "support" | "target" | "benches")) {
                rust_sources(&path, sources)?;
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && name != Some("tests.rs")
        {
            sources.push(path);
        }
    }
    Ok(())
}

/// Lines of `path` before its trailing inline `#[cfg(test)] mod name {` block.
#[cfg_attr(coverage_nightly, coverage(off))]
fn production_text(path: &Path) -> TestResult<String> {
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().collect();
    let mut production = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if *line == "#[cfg(test)]" {
            let module = lines[index + 1..]
                .iter()
                .find(|line| !line.starts_with("#["))
                .is_some_and(|line| line.starts_with("mod ") && line.ends_with(" {"));
            if module {
                break;
            }
        }
        if !line.trim_start().starts_with("//") {
            production.push(*line);
        }
    }
    Ok(production.join("\n"))
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn pos_reference_keeps_no_root_selector_binary() -> TestResult {
    let reference = workspace_root().join("crates/pos-reference");
    assert!(!reference.join("src/bin/pos-root-selector.rs").exists());
    assert!(!reference.join("src/bin/pos-root-selector").exists());
    let manifest = fs::read_to_string(reference.join("Cargo.toml"))?;
    assert!(!manifest.contains("pos-root-selector"));
    let own = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))?;
    assert!(own.contains("[[bin]]\nname = \"pos-root-selector\"\npath = \"src/main.rs\""));
    Ok(())
}

/// Every production source of the workspace whose text contains `token`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn production_files_containing(token: &str) -> TestResult<Vec<PathBuf>> {
    let root = workspace_root();
    let mut sources = Vec::new();
    for directory in ["crates", "apps", "plugins"] {
        rust_sources(&root.join(directory), &mut sources)?;
    }
    let mut found = Vec::new();
    for path in &sources {
        if production_text(path)?.contains(token) {
            found.push(fs::canonicalize(path)?);
        }
    }
    Ok(found)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn entrypoint() -> TestResult<PathBuf> {
    Ok(fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
    )?)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn only_the_selector_entrypoint_activates_the_runtime() -> TestResult {
    assert_eq!(
        production_files_containing(ACTIVATION)?,
        vec![entrypoint()?]
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn exactly_one_production_lifecycle_port_is_composed_only_here() -> TestResult {
    let adapter = fs::canonicalize(workspace_root().join(ADAPTER))?;
    assert_eq!(
        production_files_containing("ProviderLifecyclePort for ")?,
        vec![adapter.clone()]
    );
    let text = production_text(&adapter)?;
    assert_eq!(
        text.matches("impl ProviderLifecyclePort for SystemdProviderLifecycle {")
            .count(),
        1
    );
    assert_eq!(text.matches("ProviderLifecyclePort for ").count(), 1);
    assert_eq!(
        production_files_containing(COMPOSITION)?,
        vec![entrypoint()?]
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_adapter_reaches_the_system_bus_only_through_connect_system() -> TestResult {
    let text = production_text(&workspace_root().join(ADAPTER))?;
    assert_eq!(
        text.matches("SystemdTransientUnitTransport::connect_system()")
            .count(),
        1
    );
    for forbidden in [
        "Connection::system",
        "unixexec",
        "Builder::address",
        "connection::Builder",
        "from_connection",
        "Address::",
    ] {
        assert!(!text.contains(forbidden), "`{forbidden}` in the adapter");
    }
    // The shared transport refuses every non-Unix system-bus address.
    let bus = production_text(&workspace_root().join("apps/pos-sandboxd/src/system_bus.rs"))?;
    assert!(bus.contains("matches!(address.transport(), Transport::Unix(_))"));
    Ok(())
}
