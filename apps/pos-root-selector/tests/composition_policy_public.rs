#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! ADR-069 R12 I15 and I18: where the root selector is composed.
//!
//! The `pos-root-selector` binary lives only in this package (owner decision
//! O7), so `pos-reference` keeps no copy of it, and this package's entrypoint
//! is the only production code that activates the selector runtime.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The selector runtime type. Only its defining module and the entrypoint
/// may name it, so no alias, re-export or qualified path such as
/// `<RootSelectorRuntime>::activate` can reach `activate` elsewhere.
const RUNTIME_TYPE: &str = "RootSelectorRuntime";
const DEFINING_MODULE: &str = "crates/pos-reference/src/root_selector.rs";

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

/// The crates that can link the selector runtime. Their trailing test
/// modules are excluded under the provider A.3 scan's rule
/// (`apps/pos-sandboxd/tests/provider_process_creation_public.rs`); every
/// other source is scanned whole, test code included.
const SELECTOR_CRATES: [&str; 3] = [
    "crates/pos-reference/",
    "apps/pos-sandboxd/",
    "apps/pos-root-selector/",
];

/// The scanned text of one source: non-comment lines, cut at the trailing
/// test module only inside the selector crates.
#[cfg_attr(coverage_nightly, coverage(off))]
fn scanned_text(path: &Path) -> TestResult<String> {
    let relative = path
        .strip_prefix(workspace_root())?
        .to_string_lossy()
        .replace('\\', "/");
    if SELECTOR_CRATES
        .iter()
        .any(|root| relative.starts_with(root))
    {
        return production_text(path);
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Non-comment lines of `path` before its trailing inline
/// `#[cfg(test)] mod name {` block. As in the provider's A.3 scan, a file
/// where production code follows such a block is refused.
#[cfg_attr(coverage_nightly, coverage(off))]
fn production_text(path: &Path) -> TestResult<String> {
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
                break;
            }
        }
        if !lines[index].trim_start().starts_with("//") {
            production.push(lines[index]);
        }
        index += 1;
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

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn only_the_selector_entrypoint_activates_the_runtime() -> TestResult {
    let root = workspace_root();
    let mut sources = Vec::new();
    for directory in ["crates", "apps", "plugins"] {
        rust_sources(&root.join(directory), &mut sources)?;
    }
    let entrypoint = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))?;
    let defining = fs::canonicalize(root.join(DEFINING_MODULE))?;
    let mut naming = Vec::new();
    for path in &sources {
        if scanned_text(path)?.contains(RUNTIME_TYPE) {
            naming.push(fs::canonicalize(path)?);
        }
    }
    naming.sort();
    let mut expected = vec![defining.clone(), entrypoint.clone()];
    expected.sort();
    assert_eq!(naming, expected);
    // The entrypoint activates once, and the defining module never calls its
    // own public constructor.
    let main = production_text(&entrypoint)?;
    assert_eq!(main.matches("RootSelectorRuntime::activate(").count(), 1);
    assert_eq!(main.matches("activate").count(), 1, "{main}");
    let module = production_text(&defining)?;
    assert_eq!(module.matches("::activate(").count(), 0);
    Ok(())
}
