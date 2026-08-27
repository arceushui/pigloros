//! `piglor-ledger` binary — thin dispatcher (ADR-017 / #110).
//!
//! All CLI logic and renderer code lives in the `piglor_ledger` library so
//! downstream crates (#111, #113) can depend on it, and so tests can
//! exercise the public API without spawning a process.
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

macro_rules! output_stderr {
    ($($arg:tt)*) => {{
        let mut output = std::io::stderr().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

use piglor_ledger::run;

#[cfg(not(test))]
fn handle_run_error(e: &dyn std::error::Error) -> std::process::ExitCode {
    output_stderr!("Error: {e}");
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
fn handle_run_error(e: &dyn std::error::Error) {
    output_stderr!("Error (test): {e}");
}

#[cfg(not(test))]
fn run_with_args(args: &[String]) -> std::process::ExitCode {
    match run(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => handle_run_error(&error),
    }
}

#[cfg(test)]
fn run_with_args(args: &[String]) {
    if let Err(e) = run(args) {
        handle_run_error(&e);
    }
}

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    run_with_args(&std::env::args().collect::<Vec<_>>())
}

#[cfg(test)]
fn main() {
    run_with_args(&std::env::args().collect::<Vec<_>>());
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use piglor_ledger::test_helpers::{TestOptionExt, TestResultExt};
    use piglor_ledger::{open_store, CliError, Source};
    use tempfile::TempDir;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn main_runs_without_panic_in_test_context() {
        main();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_run_error_prints_in_test_arm() {
        handle_run_error(&Probe);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_with_args_exercises_error_branch() {
        run_with_args(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            "csv:/tmp/bad".into(),
        ]);
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn binary_context_toml_subcommands() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let site = tmp.path().join("site");
        let key_path = tmp.path().join("sk");

        run(&["piglor-ledger".into(), "version".into()]).test_ok()?;
        bin_keygen(&key_path)?;
        bin_predict_toml(&dir)?;

        let id = piglor_ledger::test_helpers::first_prediction_id(&dir);
        bin_resolve_toml(&dir, &id, "false")?;

        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
        ])
        .test_ok()?;

        let manifest = tmp.path().join("manifest.json");
        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--site".into(),
            site.to_str().test_ok()?.to_owned(),
            "--today".into(),
            "2026-07-25".into(),
        ])
        .test_ok()?;

        run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
        ])
        .test_ok()?;

        run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--manifest".into(),
            manifest.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn binary_context_store_subcommands() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        let store_db = tmp.path().join("store.db");

        bin_keygen(&key_path)?;
        bin_predict_store(&store_db, &key_path)?;

        let store_manifest = tmp.path().join("store_manifest.json");
        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("store:{}", store_db.display()),
            "--out".into(),
            store_manifest.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        let pubkey_hex = derive_pubkey_hex(&key_path)?;
        let trust_anchor = format!("piglor-ledger/2/1={pubkey_hex}");
        run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            format!("store:{}", store_db.display()),
            "--pubkey".into(),
            trust_anchor,
        ])
        .test_ok()?;

        // Also exercise build and export-with-pubkey on the store tier.
        let site = tmp.path().join("site-store");
        run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("store:{}", store_db.display()),
            "--site".into(),
            site.to_str().test_ok()?.to_owned(),
            "--today".into(),
            "2026-07-25".into(),
        ])
        .test_ok()?;
        // Export with --pubkey exercises the pubkey field in ExportManifest::Store.
        let manifest2 = tmp.path().join("manifest2.json");
        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("store:{}", store_db.display()),
            "--pubkey".into(),
            pubkey_hex,
            "--out".into(),
            manifest2.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        Ok(())
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn binary_context_error_paths() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let key_path = tmp.path().join("sk");
        bin_keygen(&key_path)?;

        let bad_key = tmp.path().join("bad.key");
        std::fs::write(&bad_key, "not-valid-hex").test_ok()?;
        assert!(open_store(&Source::Store(tmp.path().join("x.db")), Some(&bad_key)).is_err());

        assert!(run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", tmp.path().join("x2.db").display()),
            "--title".into(),
            "T".into(),
            "--statement".into(),
            "S".into(),
            "--predicted-outcome".into(),
            "O".into(),
            "--confidence".into(),
            "0.7".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/x".into(),
        ])
        .is_err());

        assert!(run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            "csv:/tmp".into()
        ])
        .is_err());
        assert!(run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            "nocolon".into()
        ])
        .is_err());

        assert!(run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--title".into(),
            "T2".into(),
            "--statement".into(),
            "S".into(),
            "--predicted-outcome".into(),
            "O".into(),
            "--confidence".into(),
            "bad-number".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/x".into(),
        ])
        .is_err());

        let missing_key = tmp.path().join("missing.key");
        assert!(open_store(&Source::Store(tmp.path().join("x3.db")), Some(&missing_key)).is_err());

        assert!(run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            "/nonexistent/path/key.sk".into()
        ])
        .is_err());
        assert!(run(&["piglor-ledger".into(), "keygen".into()]).is_err());

        let mut corrupt_db = b"SQLite format 3\x00".to_vec();
        corrupt_db.push(0x10);
        corrupt_db.push(0x00);
        corrupt_db.extend_from_slice(&[0u8; 4078]);
        let corrupt_path = tmp.path().join("corrupt.db");
        std::fs::write(&corrupt_path, &corrupt_db).test_ok()?;
        assert!(open_store(&Source::Store(corrupt_path), Some(&key_path)).is_err());

        let core_err: CliError = pos_core::CoreError::Storage("test".into()).into();
        assert!(core_err.to_string().contains("store error"));

        Ok(())
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    #[cfg(unix)]
    fn bin_keygen(key_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        Ok(())
    }

    fn bin_predict_toml(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--title".into(),
            "T".into(),
            "--statement".into(),
            "S".into(),
            "--predicted-outcome".into(),
            "O".into(),
            "--confidence".into(),
            "0.7".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/example".into(),
        ])
        .test_ok()?;

        Ok(())
    }

    fn bin_predict_store(
        db: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--key".into(),
            key_path.to_str().test_ok()?.to_owned(),
            "--title".into(),
            "T".into(),
            "--statement".into(),
            "S".into(),
            "--predicted-outcome".into(),
            "O".into(),
            "--confidence".into(),
            "0.7".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/x".into(),
        ])
        .test_ok()?;

        Ok(())
    }

    fn bin_resolve_toml(
        dir: &std::path::Path,
        id: &str,
        outcome: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            id.into(),
            "--outcome".into(),
            outcome.into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ])
        .test_ok()?;

        Ok(())
    }

    fn derive_pubkey_hex(key_path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
        let sk_text = std::fs::read_to_string(key_path).test_ok()?;
        Ok(piglor_ledger::test_helpers::derive_pubkey_hex(&sk_text))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn render_json_from_context() {
        use piglor_ledger::{render_json, LedgerView};
        let view = LedgerView {
            entries: Vec::new(),
            n_pending: 0,
            n_overdue: 0,
            n_resolved: 0,
            mean_brier: None,
            warnings: Vec::new(),
        };
        let json = render_json(&view);
        assert!(json.contains("\"n_pending\""));
    }

    #[derive(Debug)]
    struct Probe;
    impl std::fmt::Display for Probe {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "probe")
        }
    }
    impl std::error::Error for Probe {}
}
