//! CLI parsing, source translation, and subcommand dispatch for
//! `piglor-ledger keygen|predict|resolve|export|build|verify`
//! (ADR-017 Decision 4).
//!
//! All dispatch is testable through [`run`] using `&[String]` args — the
//! binary in `src/main.rs` is just `run(&env::args().collect())`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pos_core::{ids::TimelineId, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1};
use pos_crypto::chain::Blake3Hasher;
use pos_crypto::{
    key_roles::key_material_digest,
    signing::{generate_keypair, public_key_from_verifying_key},
};
use pos_plugin_ledger::{
    EventLedgerStore, LedgerStore, LedgerView, NewPrediction, TomlLedgerStore,
};
use pos_store::StoreConfig;

use crate::hex::hex_decode;
use crate::{hex_encode, render_html, render_json, render_redirect, CliError};

/// Parsed `--source toml:DIR|store:DB` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Curated tier rooted at `dir` (TOML file pairs).
    Toml(PathBuf),
    /// Live tier at `SQLite` `db` path (signed events).
    Store(PathBuf),
}

impl Source {
    /// Parse a `toml:DIR` or `store:DB` string.
    ///
    /// # Errors
    /// Returns [`CliError::BadSource`] if the prefix is unknown.
    pub fn parse(s: &str) -> Result<Self, CliError> {
        let (tier, rest) = s
            .split_once(':')
            .ok_or_else(|| CliError::BadSource(format!("{s:?} (expected toml:DIR or store:DB)")))?;
        match tier {
            "toml" => Ok(Self::Toml(PathBuf::from(rest))),
            "store" => Ok(Self::Store(PathBuf::from(rest))),
            other => Err(CliError::BadSource(format!(
                "{other:?} (expected toml: or store:)"
            ))),
        }
    }
}

/// Read a hex-encoded Ed25519 secret key from `path`.
///
/// # Errors
/// Returns [`CliError::BadKey`] on read or hex-decode failure.
fn load_signing_key(path: &Path) -> Result<ed25519_dalek::SigningKey, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| CliError::BadKey(e.to_string()))?;
    let text = text.trim();
    let bytes = hex_decode(text).map_err(|e| CliError::BadKey(format!("hex decode: {e}")))?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| CliError::BadKey("expected 32 bytes".to_owned()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

fn ledger_signing_registry(
    signing_key: &ed25519_dalek::SigningKey,
) -> (Arc<Mutex<KeyRegistryStateV1>>, KeyIdentityV1) {
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    // The fixed role/epoch and generated key material are valid by construction.
    // If that invariant ever changes, the empty registry fails authorization
    // in EventLedgerStore rather than allowing an unsigned operation.
    let _registration_result = registry
        .register_key(KeyRegistrationV1::new(
            identity,
            key_material_digest(&signing_key.to_bytes()),
            Some(public_key_from_verifying_key(&signing_key.verifying_key())),
        ))
        .is_ok();
    (Arc::new(Mutex::new(registry)), identity)
}

/// Open the source as a `Box<dyn LedgerStore>`. Store tier requires
/// `--key` pointing at a hex-encoded Ed25519 secret key (ADR-017 Decision 5b).
///
/// # Errors
/// Returns [`CliError::BadSource`] for tier mismatches, plus adapter open
/// errors.
pub fn open_store(source: &Source, key: Option<&Path>) -> Result<Box<dyn LedgerStore>, CliError> {
    match source {
        Source::Toml(dir) => Ok(Box::new(TomlLedgerStore::new(dir))),
        Source::Store(db) => {
            let key_path = key.ok_or_else(|| {
                CliError::BadSource("store: source requires --key <path>".to_owned())
            })?;
            let signing_key = load_signing_key(key_path)?;
            let (registry, identity) = ledger_signing_registry(&signing_key);
            let mut event_store = pos_store::open_store(StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .map_err(|e| CliError::BadSource(e.to_string()))?;
            let timeline_id = find_or_create_ledger_timeline(&mut *event_store)?;
            Ok(Box::new(
                EventLedgerStore::new(
                    event_store,
                    timeline_id,
                    crate::well_known_entity(),
                    signing_key,
                    registry,
                    identity,
                    Box::new(Blake3Hasher),
                )
                .map_err(|error| CliError::BadSource(error.to_string()))?,
            ))
        }
    }
}

/// Return today's date as `YYYY-MM-DD` (UTC) without pulling in a date crate.
///
/// # Panics
///
/// Never panics: `duration_since(UNIX_EPOCH)` uses `unwrap_or_default`.
#[must_use]
pub fn today_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    days_since_epoch_to_date(u32::try_from(secs / 86_400).unwrap_or(u32::MAX))
}

/// Convert a count of days since 1970-01-01 to `YYYY-MM-DD` (UTC).
///
/// Leap-year-correct proleptic Gregorian calendar; used by [`today_utc`] and
/// unit-tested separately.
#[must_use]
fn days_since_epoch_to_date(mut days: u32) -> String {
    let mut year = 1970u32;
    loop {
        let is_leap =
            year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100));
        let dy = if is_leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let leap = year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100));
    let month_days: [u32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;
    format!("{year:04}-{month:02}-{day:02}")
}

/// Find the timeline named `"ledger"`; create it if the store is empty.
fn find_or_create_ledger_timeline(
    store: &mut dyn pos_core::store::EventStore,
) -> Result<TimelineId, CliError> {
    for tl in store.list_timelines()? {
        if tl.meta.name.as_deref() == Some("ledger") {
            return Ok(tl.id());
        }
    }
    let tl = store.create_timeline("ledger")?;
    Ok(tl.id())
}

/// Dispatch `args` as a CLI invocation.
///
/// `args[0]` is the program name (matches `std::env::args()`); the
/// subcommand is `args[1]`.
///
/// # Errors
/// Returns [`CliError`] on any failure. Used by `src/main.rs`.
pub fn run(args: &[String]) -> Result<(), CliError> {
    match args.get(1).map(String::as_str) {
        Some("keygen") => cmd_keygen(&args[2..]),
        Some("predict") => cmd_predict(&args[2..]),
        Some("resolve") => cmd_resolve(&args[2..]),
        Some("export") => cmd_export(&args[2..]),
        Some("build") => cmd_build(&args[2..]),
        Some("verify") => cmd_verify(&args[2..]),
        Some("version") => {
            output_stdout!("piglor-ledger {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            output_stderr!("Usage: piglor-ledger <keygen|predict|resolve|export|build|verify>");
            output_stderr!(
                "  keygen --out <path>  (Unix only; path must be private and git-ignored)"
            );
            output_stderr!("  predict --source toml:DIR|store:DB [--key <path>] --title T --statement S --predicted-outcome O --confidence 0..1 --made-at TS --resolve-by DATE --osf URL [--scenario NAME]");
            output_stderr!("  resolve --source toml:DIR|store:DB [--key <path>] --id ULID --outcome true|false --resolved-at TS");
            output_stderr!("  export --source toml:DIR|store:DB [--out FILE] [--today YYYY-MM-DD] [--pubkey HEX]");
            output_stderr!("  build  --source toml:DIR|store:DB [--key PATH] --site DIR [--today YYYY-MM-DD] [--pubkey HEX]");
            output_stderr!("  verify --source toml:DIR|store:DB [--pubkey HEX (optional trust check for store:)] [--manifest FILE]");
            Ok(())
        }
    }
}

/// Pull `--name value` and `--name value` pairs from args. Returns `None`
/// if the flag was not present, `Some(value)` if present. `--name value` and
/// `--name=value` are both accepted.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v);
        }
        if a == name {
            return iter.next().map(String::as_str);
        }
    }
    None
}

fn require<'a>(args: &'a [String], name: &str) -> Result<&'a str, CliError> {
    flag(args, name).ok_or_else(|| CliError::BadSource(format!("missing required flag --{name}")))
}

fn cmd_keygen(args: &[String]) -> Result<(), CliError> {
    require(args, "--out").map(PathBuf::from).and_then(|out| {
        let (sk, vk) = generate_keypair();
        crate::key_output::write_new_secret_key(&out, hex_encode(&sk.to_bytes()).as_bytes()).map(
            |()| {
                output_stdout!(
                    "wrote secret key to {} (public key: {})",
                    out.display(),
                    hex_encode(&vk.to_bytes())
                );
                    output_stderr!(
                        "warning: {} contains a signing secret; keep it outside version control \
                         and verify it is ignored before use (for Git, pass this path as a separate \
                         argument to `git check-ignore --`)",
                        out.display()
                    );
            },
        )
    })
}

fn cmd_predict(args: &[String]) -> Result<(), CliError> {
    let source = Source::parse(require(args, "--source")?)?;
    let key = flag(args, "--key").map(PathBuf::from);
    let title = require(args, "--title")?.to_owned();
    let statement = require(args, "--statement")?.to_owned();
    let predicted_outcome = require(args, "--predicted-outcome")?.to_owned();
    let confidence: f64 = require(args, "--confidence")?
        .parse()
        .map_err(|e| CliError::BadSource(format!("--confidence: {e}")))?;
    let made_at = require(args, "--made-at")?.to_owned();
    let resolve_by = require(args, "--resolve-by")?.to_owned();
    let osf_link = require(args, "--osf")?.to_owned();
    let scenario = flag(args, "--scenario").map(str::to_owned);
    let new = NewPrediction {
        title,
        statement,
        predicted_outcome,
        confidence,
        scenario,
        made_at,
        resolve_by,
        osf_link,
    };
    let mut store = open_store(&source, key.as_deref())?;
    let id = store.register(new)?;
    output_stdout!("{id}");
    Ok(())
}

fn cmd_resolve(args: &[String]) -> Result<(), CliError> {
    let source = Source::parse(require(args, "--source")?)?;
    let key = flag(args, "--key").map(PathBuf::from);
    let id = require(args, "--id")?.to_owned();
    let outcome_str = require(args, "--outcome")?;
    let outcome = match outcome_str {
        "true" => true,
        "false" => false,
        other => {
            return Err(CliError::BadSource(format!(
                "--outcome {other} (expected true|false)"
            )));
        }
    };
    let resolved_at = require(args, "--resolved-at")?.to_owned();
    let outcome = pos_plugin_ledger::LedgerOutcome::try_new(id, outcome, resolved_at)?;
    let mut store = open_store(&source, key.as_deref())?;
    store.resolve(outcome)?;
    output_stdout!("resolved");
    Ok(())
}

fn cmd_export(args: &[String]) -> Result<(), CliError> {
    let source = Source::parse(require(args, "--source")?)?;
    let today = flag(args, "--today").map_or_else(today_utc, str::to_owned);
    let out_path = flag(args, "--out").map(PathBuf::from);
    let pubkey = flag(args, "--pubkey").map(str::to_owned);
    let export = crate::export::build(&source, &today, pubkey)?;
    let json = serde_json::to_string_pretty(&export)?;
    if let Some(path) = out_path {
        std::fs::write(&path, &json)?;
        output_stdout!("wrote {} ({} bytes)", path.display(), json.len());
    } else {
        output_stdout!("{json}");
    }
    Ok(())
}

fn cmd_build(args: &[String]) -> Result<(), CliError> {
    let source = Source::parse(require(args, "--source")?)?;
    let key = flag(args, "--key").map(PathBuf::from);
    let site = PathBuf::from(require(args, "--site")?);
    let pubkey = flag(args, "--pubkey").map(str::to_owned);
    let today = flag(args, "--today").map_or_else(today_utc, str::to_owned);
    let ledger = match &source {
        Source::Toml(dir) => TomlLedgerStore::new(dir).load(&today)?,
        Source::Store(db) => {
            let key_path = key.as_deref().ok_or_else(|| {
                CliError::BadSource("store: source requires --key <path>".to_owned())
            })?;
            let mut store = pos_store::open_store(StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .map_err(|e| CliError::BadSource(e.to_string()))?;
            let timeline_id = find_or_create_ledger_timeline(&mut *store)?;
            let sk = load_signing_key(key_path)?;
            let (registry, identity) = ledger_signing_registry(&sk);
            let ledger_store = EventLedgerStore::new(
                store,
                timeline_id,
                crate::well_known_entity(),
                sk,
                registry,
                identity,
                Box::new(Blake3Hasher),
            )
            .map_err(|error| CliError::BadSource(error.to_string()))?;
            ledger_store.load(&today)?
        }
    };
    let view = LedgerView::from(&ledger);
    let html = render_html(&view, pubkey.as_deref());
    let json = render_json(&view);
    let ledger_dir = site.join("ledger");
    std::fs::create_dir_all(&ledger_dir)?;
    std::fs::write(ledger_dir.join("index.html"), html)?;
    std::fs::write(ledger_dir.join("ledger.json"), json)?;
    std::fs::write(site.join("index.html"), render_redirect())?;
    output_stdout!(
        "wrote {} and {}",
        ledger_dir.join("index.html").display(),
        ledger_dir.join("ledger.json").display()
    );
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), CliError> {
    let source = Source::parse(require(args, "--source")?)?;
    let manifest_path = flag(args, "--manifest").map(PathBuf::from);
    let pubkey = flag(args, "--pubkey").map(str::to_owned);
    let report = crate::verify::run(&source, pubkey.as_deref(), manifest_path.as_deref())?;
    output_stdout!("{report}");
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::hex::nib;
    use crate::test_helpers::{running_as_root, TestOptionExt, TestResultExt};
    use pos_core::store::EventStore;
    use tempfile::TempDir;

    #[cfg(unix)]
    static KEYGEN_FAULT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn days_since_epoch_covers_leap_year_and_feb() {
        // 1970-01-01 = day 0
        assert_eq!(days_since_epoch_to_date(0), "1970-01-01");
        // 2026-07-27 = known date (non-leap year)
        // days from epoch: 56 years + leap adjustments + day-of-year
        // Just test that output has correct format and known values.
        let d2026 = days_since_epoch_to_date(20661); // 2026-07-27
        assert!(d2026.starts_with("2026-"), "{d2026}");
        // 2024 is a leap year — Feb 29 exists
        // 2024-02-29 = day 19782 from epoch (2024 is 54 years after 1970)
        let feb29 = days_since_epoch_to_date(19782);
        assert_eq!(feb29, "2024-02-29", "leap Feb 29 must map correctly");
        // 2024-03-01 = day 19783
        let mar1 = days_since_epoch_to_date(19783);
        assert_eq!(mar1, "2024-03-01");
        // 2000 is a 400-year leap year — Feb 29
        let y2000_feb29 = days_since_epoch_to_date(11016);
        assert_eq!(y2000_feb29, "2000-02-29");
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn source_parses_toml_and_store() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Source::parse("toml:/tmp/x").test_ok()?,
            Source::Toml(PathBuf::from("/tmp/x"))
        );
        assert_eq!(
            Source::parse("store:/tmp/x.db").test_ok()?,
            Source::Store(PathBuf::from("/tmp/x.db"))
        );
        assert!(Source::parse("/tmp/x").is_err());
        assert!(Source::parse("csv:/tmp/x").is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn hex_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [0u8, 1, 0xfe, 0xff];
        let s = hex_encode(&bytes);
        assert_eq!(s, "0001feff");
        assert_eq!(hex_decode(&s).test_ok()?, bytes.to_vec());
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn nib_covers_all_digits() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(nib('0').test_ok()?, 0);
        assert_eq!(nib('9').test_ok()?, 9);
        assert_eq!(nib('a').test_ok()?, 10);
        assert_eq!(nib('F').test_ok()?, 15);
        assert!(nib('g').is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn flag_handles_space_and_equals_forms() {
        let args: Vec<String> = ["--a", "one", "--b=two"]
            .iter()
            .copied()
            .map(str::to_owned)
            .collect();
        assert_eq!(flag(&args, "--a"), Some("one"));
        assert_eq!(flag(&args, "--b"), Some("two"));
        assert_eq!(flag(&args, "--c"), None);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn require_errors_on_missing() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = vec!["--only".to_string(), "one".to_string()];
        assert!(require(&args, "--missing").is_err());
        assert_eq!(require(&args, "--only").test_ok()?, "one");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn usage_includes_all_subcommands() -> Result<(), Box<dyn std::error::Error>> {
        run(&["piglor-ledger".to_string()]).test_ok()?;
        run(&["piglor-ledger".to_string(), "version".to_string()]).test_ok()?;

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_writes_hex_secret_key_and_prints_pubkey() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let text = std::fs::read_to_string(&key_path).test_ok()?;
        let bytes = hex_decode(text.trim()).test_ok()?;
        assert_eq!(bytes.len(), 32);

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_writes_secret_key_with_owner_only_permissions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        assert_eq!(
            std::fs::metadata(key_path).test_ok()?.permissions().mode() & 0o777,
            0o600
        );

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_accepts_relative_path_in_private_directory() -> Result<(), Box<dyn std::error::Error>>
    {
        let key_path = PathBuf::from(format!(".keygen-relative-{}.key", ulid::Ulid::generate()));

        run_keygen(&key_path).test_ok()?;

        assert!(key_path.exists());
        std::fs::remove_file(key_path).test_ok()?;

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_filesystem_root_without_writing() -> Result<(), Box<dyn std::error::Error>> {
        let err = run_keygen(Path::new("/")).test_err()?;

        assert!(err.to_string().contains("already exists"), "{err}");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_existing_output_file_without_overwriting_it(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");
        std::fs::write(&key_path, "keep this key material").test_ok()?;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).test_ok()?;

        let err = run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_err()?;

        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(
            std::fs::read_to_string(key_path).test_ok()?,
            "keep this key material"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_insecure_existing_output_file() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");
        std::fs::write(&key_path, "public key material").test_ok()?;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).test_ok()?;

        let err = run_keygen(&key_path).test_err()?;

        assert!(err.to_string().contains("insecure mode 0644"), "{err}");
        assert_eq!(
            std::fs::read_to_string(key_path).test_ok()?,
            "public key material"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_symlink_output_without_following_it() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDir::new().test_ok()?;
        let target = tmp.path().join("target.key");
        std::fs::write(&target, "target key material").test_ok()?;
        let link = tmp.path().join("secret.key");
        std::os::unix::fs::symlink(&target, &link).test_ok()?;

        let err = run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            link.to_str().test_ok()?.to_owned(),
        ])
        .test_err()?;

        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(
            std::fs::read_to_string(target).test_ok()?,
            "target key material"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_ancestor_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let real = tmp.path().join("real");
        std::fs::create_dir_all(real.join("private")).test_ok()?;
        let link = tmp.path().join("linked");
        std::os::unix::fs::symlink(&real, &link).test_ok()?;
        let key_path = link.join("private").join("secret.key");

        let err = run_keygen(&key_path).test_err()?;

        assert!(err.to_string().contains("ancestor"), "{err}");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!real.join("private").join("secret.key").exists());

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_non_directory_ancestor() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let parent = tmp.path().join("not-a-directory");
        std::fs::write(&parent, "file").test_ok()?;
        let key_path = parent.join("secret.key");

        let err = run_keygen(&key_path).test_err()?;

        assert!(err.to_string().contains("not a directory"), "{err}");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_insecure_containing_directory() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().test_ok()?;
        let parent = tmp.path().join("shared");
        std::fs::create_dir(&parent).test_ok()?;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).test_ok()?;
        let key_path = parent.join("secret.key");

        let err = run_keygen(&key_path).test_err()?;

        assert!(err.to_string().contains("insecure mode 0777"), "{err}");
        assert!(!key_path.exists());

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_rejects_insecure_non_sticky_ancestor() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().test_ok()?;
        let shared = tmp.path().join("shared");
        let private = shared.join("private");
        std::fs::create_dir_all(&private).test_ok()?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).test_ok()?;
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).test_ok()?;
        let key_path = private.join("secret.key");

        let err = run_keygen(&key_path).test_err()?;

        assert!(err.to_string().contains("insecure mode 0777"), "{err}");
        assert!(!key_path.exists());

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_cleans_partial_outputs_and_retry_succeeds() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::key_output::{clear_faults, install_faults, FaultStage};

        let _guard = KEYGEN_FAULT_TEST_LOCK.lock().test_ok()?;
        for (name, stage) in [
            ("inspect-created", FaultStage::InspectCreated),
            ("insecure-mode", FaultStage::ForceInsecureMode),
            ("write", FaultStage::Write),
            ("file-sync", FaultStage::FileSync),
            ("directory-sync", FaultStage::DirectorySync),
        ] {
            let tmp = TempDir::new().test_ok()?;
            let key_path = tmp.path().join(format!("{name}.key"));
            install_faults(&key_path, &[stage]);
            let err = run_keygen(&key_path).test_err()?;
            clear_faults();

            assert!(err.to_string().contains("retry is safe"), "{name}: {err}");
            assert!(!key_path.exists(), "{name}: partial output remained");
            run_keygen(&key_path).test_ok()?;
            assert!(key_path.exists(), "{name}: retry did not create key");
        }

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_reports_cleanup_remove_uncertainty() -> Result<(), Box<dyn std::error::Error>> {
        use crate::key_output::{clear_faults, install_faults, FaultStage};

        let _guard = KEYGEN_FAULT_TEST_LOCK.lock().test_ok()?;
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");
        install_faults(&key_path, &[FaultStage::Write, FaultStage::CleanupRemove]);
        let err = run_keygen(&key_path).test_err()?;
        clear_faults();

        assert!(err.to_string().contains("cleanup is uncertain"), "{err}");
        assert!(
            key_path.exists(),
            "injected removal failure should retain output"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_reports_cleanup_directory_sync_uncertainty() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::key_output::{clear_faults, install_faults, FaultStage};

        let _guard = KEYGEN_FAULT_TEST_LOCK.lock().test_ok()?;
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");
        install_faults(
            &key_path,
            &[FaultStage::Write, FaultStage::CleanupDirectorySync],
        );
        let err = run_keygen(&key_path).test_err()?;
        clear_faults();

        assert!(
            err.to_string().contains("cleanup durability is uncertain"),
            "{err}"
        );
        assert!(!key_path.exists());

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_surfaces_precreation_io_failures_with_path() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::key_output::{clear_faults, install_faults, FaultStage};

        let _guard = KEYGEN_FAULT_TEST_LOCK.lock().test_ok()?;
        for (name, stage) in [
            ("ancestor", FaultStage::InspectAncestor),
            ("parent", FaultStage::OpenParent),
            ("output", FaultStage::InspectOutput),
            ("create", FaultStage::Create),
        ] {
            let tmp = TempDir::new().test_ok()?;
            let key_path = tmp.path().join(format!("{name}.key"));
            install_faults(&key_path, &[stage]);
            let err = run_keygen(&key_path).test_err()?;
            clear_faults();

            assert!(
                err.to_string().contains(&key_path.display().to_string()),
                "{name}: {err}"
            );
            assert!(err.source().is_some(), "{name}: missing I/O source");
            assert!(!key_path.exists());
        }

        let relative = PathBuf::from("relative-fault.key");
        install_faults(&relative, &[FaultStage::ResolveRelative]);
        let err = run_keygen(&relative).test_err()?;
        clear_faults();
        assert!(err.to_string().contains("resolve relative path"), "{err}");
        assert!(!relative.exists());

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_fails_when_output_path_is_unwritable() -> Result<(), Box<dyn std::error::Error>> {
        // A missing parent prevents secure create_new output creation.
        let err = run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            "/nonexistent/dir/key.sk".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("inspect ancestor"), "{err}");

        Ok(())
    }

    #[cfg(not(unix))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_is_explicitly_unsupported() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("secret.key");

        let err = run_keygen(&key_path).test_err()?;

        assert!(err.to_string().contains("requires Unix"), "{err}");
        assert!(!key_path.exists());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn keygen_missing_out_flag_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L176: `?` on require(args, "--out") in cmd_keygen.
        let err = run(&["piglor-ledger".into(), "keygen".into()]).test_err()?;
        assert!(err.to_string().contains("--out"));

        Ok(())
    }

    fn run_keygen(key_path: &Path) -> Result<(), CliError> {
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_string_lossy().into_owned(),
        ])
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_store_source_without_key_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L211: `?` on open_store in cmd_predict for the store tier
        // when --key is absent.
        let tmp = tempfile::TempDir::new().test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", tmp.path().join("x.db").display()),
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
        .test_err()?;
        assert!(err.to_string().contains("--key"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_resolve_build_round_trip_toml() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let site = tmp.path().join("site");

        run_predict(&dir, "Title", "Stmt", 0.8)?;
        let id = crate::test_helpers::first_prediction_id(&dir);

        run_resolve(&dir, &id, true, "2026-07-30T09:00:00Z")?;

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

        let index_html =
            std::fs::read_to_string(site.join("ledger").join("index.html")).test_ok()?;
        let ledger_json =
            std::fs::read_to_string(site.join("ledger").join("ledger.json")).test_ok()?;
        let root = std::fs::read_to_string(site.join("index.html")).test_ok()?;
        assert!(
            index_html.contains("mean Brier Score: 0.040 (n=1)"),
            "{index_html}"
        );
        assert!(index_html.contains("Status: resolved"));
        assert!(ledger_json.contains("\"n_resolved\": 1"));
        assert!(ledger_json.contains("\"n_pending\": 0"));
        assert!(root.contains("url=/ledger/"));

        Ok(())
    }

    fn run_predict(
        dir: &Path,
        title: &str,
        statement: &str,
        confidence: f64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--title".into(),
            title.into(),
            "--statement".into(),
            statement.into(),
            "--predicted-outcome".into(),
            "Kyoto".into(),
            "--confidence".into(),
            confidence.to_string(),
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

    fn run_resolve(
        dir: &Path,
        id: &str,
        outcome: bool,
        resolved_at: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            id.into(),
            "--outcome".into(),
            outcome.to_string(),
            "--resolved-at".into(),
            resolved_at.into(),
        ])
        .test_ok()?;

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_rejects_missing_osf_in_toml() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
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
            "0.5".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            // No --osf flag
        ])
        .test_err()?;
        assert!(err.to_string().contains("--osf"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_is_byte_identical_on_re_run() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "Deterministic", "Stmt", 0.7)?;
        // Resolve by walking the prediction file
        let preds_dir = dir.join("predictions");
        let id = std::fs::read_dir(&preds_dir)
            .test_ok()?
            .next()
            .test_ok()?
            .test_ok()?
            .path()
            .file_stem()
            .test_ok()?
            .to_str()
            .test_ok()?
            .to_owned();
        run_resolve(&dir, &id, true, "2026-07-30T09:00:00Z")?;

        let site_a = tmp.path().join("site_a");
        let site_b = tmp.path().join("site_b");
        for site in [&site_a, &site_b] {
            run(&[
                "piglor-ledger".into(),
                "build".into(),
                "--source".into(),
                format!("toml:{}", dir.display()),
                "--site".into(),
                site.to_str().test_ok()?.to_owned(),
                "--today".into(),
                "2026-07-25".into(),
                "--pubkey".into(),
                "deadbeef".into(),
            ])
            .test_ok()?;
        }
        let a_html = std::fs::read_to_string(site_a.join("ledger").join("index.html")).test_ok()?;
        let b_html = std::fs::read_to_string(site_b.join("ledger").join("index.html")).test_ok()?;
        assert_eq!(a_html, b_html);
        let a_json =
            std::fs::read_to_string(site_a.join("ledger").join("ledger.json")).test_ok()?;
        let b_json =
            std::fs::read_to_string(site_b.join("ledger").join("ledger.json")).test_ok()?;
        assert_eq!(a_json, b_json);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_rejects_bad_outcome_value() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".into(),
            "--outcome".into(),
            "maybe".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("--outcome maybe"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_required_flag_errors() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("toml:{}", tmp.path().display()),
        ])
        .test_err()?;
        assert!(err.to_string().contains("--title"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_source_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L205:57: `?` on require(args, "--source") in cmd_predict.
        let err = run(&["piglor-ledger".into(), "predict".into()]).test_err()?;
        assert!(err.to_string().contains("--source"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_invalid_confidence_in_store_register_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Covers L228: `?` on store.register(new) when confidence is out of range.
        // Confidence 2.0 parses as a valid float but fails NewPrediction::validate().
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
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
            "2.0".into(), // valid float, invalid range
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/example".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("confidence"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_bad_id_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L248: `?` on LedgerOutcome::try_new when id is not a ULID.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            "not-a-ulid".into(), // invalid ULID
            "--outcome".into(),
            "true".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("invalid resolution"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_store_open_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L249: `?` on open_store in cmd_resolve when key is missing.
        let tmp = TempDir::new().test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("store:{}", tmp.path().join("x.db").display()),
            "--id".into(),
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".into(),
            "--outcome".into(),
            "true".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
            // No --key → open_store fails
        ])
        .test_err()?;
        assert!(err.to_string().contains("--key"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_store_resolve_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L250: `?` on store.resolve when prediction doesn't exist.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".into(),
            "--outcome".into(),
            "true".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("unknown prediction"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn export_build_error_propagates() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L260: `?` on export::build when source has invalid date.
        // Uses the cmd_export path which calls build() with an invalid today.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--today".into(),
            "bad-date".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("invalid today"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn export_write_error_propagates() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L264: `?` on std::fs::write(&path, &json) in cmd_export.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            "/nonexistent/dir/output.json".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("io error"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_open_store_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L277: `?` on open_store in cmd_build when source is invalid.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        // Use invalid today to make store.load fail at L278.
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--site".into(),
            tmp.path().join("site").to_str().test_ok()?.to_owned(),
            "--today".into(),
            "bad-date".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("invalid today"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_create_dir_fails() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L283: `?` on std::fs::create_dir_all in cmd_build.
        // Use a file as the site parent to make create_dir_all fail.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        // Create a FILE at the site path so create_dir_all fails.
        let site_path = tmp.path().join("site_file");
        std::fs::write(&site_path, "blocking file").test_ok()?;
        // The ledger dir would be site_file/ledger but site_file is a file.
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--site".into(),
            site_path.to_str().test_ok()?.to_owned(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("io error"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_run_error_propagates() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L299: `?` on verify::run in cmd_verify when pubkey is bad.
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let _store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            // No --pubkey on an empty store → the persisted registry is required first.
        ])
        .test_err()?;
        assert!(err.to_string().contains("role/epoch registry"), "{err}");

        Ok(())
    }

    // ── Coverage: bad source prefix in each subcommand ─────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_bad_source_prefix_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L234:59: `?` on Source::parse in cmd_resolve when prefix is bad.
        let err = run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            "csv:/tmp".into(),
            "--id".into(),
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".into(),
            "--outcome".into(),
            "true".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("csv"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn export_bad_source_prefix_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L256:59: `?` on Source::parse in cmd_export when prefix is bad.
        let err = run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            "csv:/tmp".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("csv"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_bad_source_prefix_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L273:59: `?` on Source::parse in cmd_build when prefix is bad.
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            "csv:/tmp".into(),
            "--site".into(),
            "/tmp/site".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("csv"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_bad_source_prefix_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L296:59: `?` on Source::parse in cmd_verify when prefix is bad.
        let err = run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            "csv:/tmp".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("csv"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_store_without_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        // Store-backed builds are signing-authorized and require an explicit key.
        let tmp = TempDir::new().test_ok()?;
        let db_path = tmp.path().join("x.db");
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("store:{}", db_path.display()),
            "--site".into(),
            tmp.path().join("site").to_str().test_ok()?.to_owned(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("--key"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_write_html_fails() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L284-L285: `?` on std::fs::write(index.html) in cmd_build.
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return Ok(());
        }
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "T", "S", 0.7)?;
        let site = tmp.path().join("site");
        let ledger_dir = site.join("ledger");
        std::fs::create_dir_all(&ledger_dir).test_ok()?;
        // Make ledger dir read-only so writing index.html fails.
        std::fs::set_permissions(&ledger_dir, std::fs::Permissions::from_mode(0o555)).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--site".into(),
            site.to_str().test_ok()?.to_owned(),
        ]);
        std::fs::set_permissions(&ledger_dir, std::fs::Permissions::from_mode(0o755)).test_ok()?;
        assert!(err.is_err(), "expected write failure");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_write_ledger_json_fails() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L286: `?` on std::fs::write(ledger.json) in cmd_build.
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return Ok(());
        }
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "T", "S", 0.7)?;
        let site = tmp.path().join("site");
        let ledger_dir = site.join("ledger");
        std::fs::create_dir_all(&ledger_dir).test_ok()?;
        // Make ledger.json a read-only file so writing it fails (index.html can still write).
        let ledger_json = ledger_dir.join("ledger.json");
        std::fs::write(&ledger_json, "").test_ok()?;
        std::fs::set_permissions(&ledger_json, std::fs::Permissions::from_mode(0o444)).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--site".into(),
            site.to_str().test_ok()?.to_owned(),
        ]);
        std::fs::set_permissions(&ledger_json, std::fs::Permissions::from_mode(0o644)).test_ok()?;
        assert!(err.is_err(), "expected write failure on ledger.json");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_write_root_index_fails() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L287: `?` on std::fs::write(site/index.html) in cmd_build.
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return Ok(());
        }
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "T", "S", 0.7)?;
        let site = tmp.path().join("site");
        std::fs::create_dir_all(&site).test_ok()?;
        let ledger_dir = site.join("ledger");
        std::fs::create_dir_all(&ledger_dir).test_ok()?;
        // Block root index.html by pre-creating it as read-only.
        let root_index = site.join("index.html");
        std::fs::write(&root_index, "").test_ok()?;
        std::fs::set_permissions(&root_index, std::fs::Permissions::from_mode(0o444)).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--site".into(),
            site.to_str().test_ok()?.to_owned(),
        ]);
        std::fs::set_permissions(&root_index, std::fs::Permissions::from_mode(0o644)).test_ok()?;
        assert!(err.is_err(), "expected write failure on site/index.html");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_rejects_non_numeric_confidence() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L213: the `format!("--confidence: {e}")` closure in cmd_predict
        // when confidence fails to parse as f64.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        let err = run(&[
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
            "not-a-number".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/example".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("--confidence"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn bad_source_prefix_errors() -> Result<(), Box<dyn std::error::Error>> {
        let err = run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            "csv:/tmp".into(),
            "--title".into(),
            "T".into(),
        ])
        .test_err()?;
        assert!(err.to_string().contains("csv"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn load_signing_key_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let path = tmp.path().join("k");
        let (sk, _) = generate_keypair();
        std::fs::write(&path, hex_encode(&sk.to_bytes())).test_ok()?;
        let loaded = load_signing_key(&path).test_ok()?;
        assert_eq!(loaded.to_bytes(), sk.to_bytes());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn load_signing_key_rejects_garbage() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let path = tmp.path().join("k");
        std::fs::write(&path, "not hex").test_ok()?;
        assert!(load_signing_key(&path).is_err());
        std::fs::write(&path, "00").test_ok()?;
        assert!(load_signing_key(&path).is_err()); // wrong length

        Ok(())
    }

    // ── Coverage: open_store(Source::Store, …) ──────────────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_store_requires_key() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("l.db");
        assert!(open_store(&Source::Store(db), None).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn core_error_converts_to_bad_source_via_from() {
        // Covers the From<pos_core::CoreError> for CliError impl.
        // This impl is used when list_timelines() or read() fails with
        // a CoreError and ? propagates it as CliError::Store.
        let core_err = pos_core::CoreError::Storage("disk full".into());
        let cli_err: CliError = core_err.into();
        assert!(cli_err.to_string().contains("store error"), "{cli_err}");
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_store_with_bad_key_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L99: the `?` on `load_signing_key(key_path)?` in open_store
        // when the key file exists but contains invalid hex content.
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("l.db");
        let bad_key = tmp.path().join("bad.key");
        std::fs::write(&bad_key, "not-valid-hex").test_ok()?;
        let err = open_store(&Source::Store(db), Some(&bad_key));
        assert!(err.is_err());

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_sqlite_fails_on_invalid_path() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L103: `format!("open sqlite: {e}")` when the SQLite path is
        // invalid (parent directory does not exist).
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let bad_db = tmp.path().join("nonexistent_subdir").join("ledger.db");
        let err = open_store(&Source::Store(bad_db), Some(&key_path));
        // Either the open itself fails or the subsequent list_timelines fails.
        assert!(err.is_err(), "expected error for invalid path");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_sqlite_with_corrupted_db_fails() -> Result<(), Box<dyn std::error::Error>> {
        // Targets L130: the `?` on list_timelines when the DB is corrupt.
        // Also covers L135: `?` on create_timeline when DB is corrupt.
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        // SQLite magic + page size 4096 + zero-filled first page.
        let bad_db = tmp.path().join("bad.db");
        let mut content = b"SQLite format 3\x00".to_vec();
        content.push(0x10);
        content.push(0x00);
        content.extend_from_slice(&[0u8; 4078]);
        std::fs::write(&bad_db, content).test_ok()?;
        let err = open_store(&Source::Store(bad_db), Some(&key_path));
        // Either open (L103) or list_timelines (L130) fails.
        assert!(err.is_err(), "expected error for corrupted DB");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_readonly_db_fails_on_create_timeline() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L135: `?` on create_timeline when the DB is read-only.
        // Creates a valid empty SQLite DB, then makes it read-only so that
        // create_timeline fails.
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return Ok(());
        }
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let db = tmp.path().join("readonly.db");
        // Open the DB once to create a valid empty SQLite file with schema.
        {
            let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .test_ok()?;
            // Create a non-ledger timeline so list_timelines iterates without finding "ledger".
            store.create_timeline("other").test_ok()?;
        }
        // Make it read-only so create_timeline("ledger") fails.
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o444)).test_ok()?;
        let err = open_store(&Source::Store(db.clone()), Some(&key_path));
        // Restore permissions so cleanup works.
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).test_ok()?;
        // Either list_timelines or create_timeline failed due to read-only DB.
        assert!(err.is_err(), "expected error from read-only DB");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn find_or_create_list_timelines_fails_on_corrupt_db() -> Result<(), Box<dyn std::error::Error>>
    {
        // Covers L130: `?` on list_timelines when the DB has a corrupt
        // timeline name column (cannot be decoded as UTF-8/ULID).
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let db = tmp.path().join("corrupt.db");
        // Create a valid DB with one timeline.
        {
            let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .test_ok()?;
            store.create_timeline("other").test_ok()?;
        }
        // Corrupt the timeline id so list_timelines fails to decode it.
        {
            let conn = rusqlite::Connection::open(&db).test_ok()?;
            conn.execute("UPDATE timelines SET id = X'0102'", [])
                .test_ok()?;
        }
        let err = open_store(&Source::Store(db), Some(&key_path));
        assert!(err.is_err(), "expected error from corrupt DB");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_reuse_existing_ledger_timeline() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L133 (return Ok early when ledger timeline found) and
        // also exercises the `?` on list_timelines with a valid store.
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let db = tmp.path().join("existing.db");
        // First open creates the "ledger" timeline.
        open_store(&Source::Store(db.clone()), Some(&key_path)).test_ok()?;
        // Second open finds the existing timeline and returns early.
        open_store(&Source::Store(db), Some(&key_path)).test_ok()?;

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn load_signing_key_fails_when_file_missing() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L53: the `e.to_string()` closure and `?` in load_signing_key
        // when the file does not exist.
        let tmp = TempDir::new().test_ok()?;
        let missing = tmp.path().join("nonexistent.key");
        let err = load_signing_key(&missing);
        assert!(err.is_err());
        assert!(err.test_err()?.to_string().contains("invalid --key"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn ledger_signing_registry_rejects_invalid_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let (signing_key, _) = pos_crypto::signing::generate_keypair();
        let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 0);
        let mut registry = KeyRegistryStateV1::new();
        let error = registry
            .register_key(KeyRegistrationV1::new(
                identity,
                key_material_digest(&signing_key.to_bytes()),
                Some(public_key_from_verifying_key(&signing_key.verifying_key())),
            ))
            .test_err()?;
        assert!(error.to_string().contains("key epoch zero"), "{error}");
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn hex_decode_second_nibble_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L71: `nib(l)?` — the second nibble error sub-region.
        // "0g" has a valid first nibble ('0') and an invalid second nibble ('g').
        let err = hex_decode("0g");
        assert!(err.is_err());
        assert!(err.test_err()?.contains("bad hex"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn cmd_resolve_false_outcome_sets_false() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L241: the "false" arm in cmd_resolve.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "ResolveToFalse", "S", 0.7)?;
        let id = crate::test_helpers::first_prediction_id(&dir);
        run_resolve(&dir, &id, false, "2026-07-30T09:00:00Z")?;
        // Verify the resolution was stored as false.
        let ledger = pos_plugin_ledger::TomlLedgerStore::new(&dir)
            .load("2026-07-25")
            .test_ok()?;
        assert!(!ledger.entries()[0].resolution.as_ref().test_ok()?.outcome);

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_store_with_key_succeeds_and_well_known_entity_covered(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Exercises: well_known_entity(), the store: branch of open_store,
        // and find_or_create_ledger_timeline (new timeline).
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("l.db");
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let store = open_store(&Source::Store(db.clone()), Some(&key_path));
        assert!(
            store.is_ok(),
            "open_store with valid store key must succeed"
        );

        // Open a second time: now the timeline already exists, so
        // find_or_create_ledger_timeline returns early from the `for` loop
        // (the "already-exists" branch — previously uncovered).
        let store2 = open_store(&Source::Store(db), Some(&key_path));
        assert!(store2.is_ok(), "second open (reuse branch) must succeed");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn open_store_rejects_a_persisted_registry_for_another_key() -> Result<(), Box<dyn Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("mismatched.db");
        let key_path = tmp.path().join("sk");
        run_keygen(&key_path)?;
        let mut raw = pos_store::sqlite::SqliteStore::open(db.to_str().test_ok()?).test_ok()?;
        raw.create_timeline("ledger").test_ok()?;
        raw.save_key_registry(&KeyRegistryStateV1::new())
            .test_ok()?;
        drop(raw);

        let error = open_store(&Source::Store(db), Some(&key_path)).test_err()?;
        assert!(error.to_string().contains("authorization"), "{error}");
        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn find_or_create_skips_non_ledger_timelines_in_loop() -> Result<(), Box<dyn std::error::Error>>
    {
        // Exercises line 134: the `}` closing the inner `if` in the `for` loop
        // of find_or_create_ledger_timeline — hit when we iterate a non-ledger
        // timeline and skip it, then find or create "ledger".
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("l.db");
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        // Create a non-ledger timeline in the store BEFORE opening via CLI.
        let mut raw = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        raw.create_timeline("other").test_ok()?;
        drop(raw);
        // Now open_store will iterate "other" (skips it), then create "ledger".
        let store = open_store(&Source::Store(db), Some(&key_path));
        assert!(
            store.is_ok(),
            "open_store with preceding non-ledger timeline"
        );

        Ok(())
    }

    // ── Coverage: cmd_export --out ──────────────────────────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn export_without_out_flag_prints_to_stdout() -> Result<(), Box<dyn std::error::Error>> {
        // Exercises the `None => output_stdout!("{json}")` branch (line 268).
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "ExportStdout", "S", 0.7)?;
        // No --out flag: the JSON is printed to stdout (Ok result).
        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
        ])
        .test_ok()?;

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn export_with_out_flag_writes_file() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "ExportOut", "S", 0.7)?;
        let out_path = tmp.path().join("manifest.json");
        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            out_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let text = std::fs::read_to_string(&out_path).test_ok()?;
        assert!(text.contains("\"tier\": \"toml\""));

        Ok(())
    }

    // ── Coverage: cmd_verify via run() ─────────────────────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_via_run_toml_ok() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "VerifyViaRun", "S", 0.7)?;
        run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
        ])
        .test_ok()?;

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_via_run_with_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        run_predict(&dir, "VerifyManifest", "S", 0.7)?;
        let manifest_path = tmp.path().join("manifest.json");
        run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        run(&[
            "piglor-ledger".into(),
            "verify".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--manifest".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;

        Ok(())
    }

    // ── Coverage: missing-flag ? error paths in each command ─────────────

    fn base_predict(dir: &std::path::Path) -> Vec<String> {
        vec![
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
        ]
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_statement_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L208: `?` on require("--statement")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_predict(dir);
        // Remove --statement and its value
        let pos = args.iter().position(|a| a == "--statement").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_predicted_outcome_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L209: `?` on require("--predicted-outcome")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_predict(dir);
        let pos = args
            .iter()
            .position(|a| a == "--predicted-outcome")
            .test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_confidence_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L210: `?` on require("--confidence")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_predict(dir);
        let pos = args.iter().position(|a| a == "--confidence").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_made_at_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L214: `?` on require("--made-at")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_predict(dir);
        let pos = args.iter().position(|a| a == "--made-at").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn predict_missing_resolve_by_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L215: `?` on require("--resolve-by")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_predict(dir);
        let pos = args.iter().position(|a| a == "--resolve-by").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    fn base_resolve(dir: &std::path::Path) -> Vec<String> {
        vec![
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".into(),
            "--outcome".into(),
            "true".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ]
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_missing_source_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L234: `?` on Source::parse(require("--source")?)
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_resolve(dir);
        let pos = args.iter().position(|a| a == "--source").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_missing_id_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L236: `?` on require("--id")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_resolve(dir);
        let pos = args.iter().position(|a| a == "--id").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_missing_outcome_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L237: `?` on require("--outcome")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_resolve(dir);
        let pos = args.iter().position(|a| a == "--outcome").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn resolve_missing_resolved_at_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L247: `?` on require("--resolved-at")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        let mut args = base_resolve(dir);
        let pos = args.iter().position(|a| a == "--resolved-at").test_ok()?;
        args.drain(pos..=pos + 1);
        assert!(run(&args).is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn export_missing_source_errors() {
        // Covers L256: `?` in cmd_export Source::parse(require("--source")?)
        assert!(run(&["piglor-ledger".into(), "export".into()]).is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_missing_source_errors() {
        // Covers L273: `?` in cmd_build Source::parse(require("--source")?)
        assert!(run(&["piglor-ledger".into(), "build".into()]).is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_missing_site_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L274: `?` on require("--site")
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path();
        assert!(run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            // No --site
        ])
        .is_err());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_missing_source_errors() {
        // Covers L296: `?` in cmd_verify Source::parse(require("--source")?)
        assert!(run(&["piglor-ledger".into(), "verify".into()]).is_err());
    }

    // ── Coverage: cmd_build store-branch error paths ──────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_store_invalid_path_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L321: `.map_err(|e| CliError::BadSource(e.to_string()))?`
        // in cmd_build when pos_store::open_store fails for the store source.
        let tmp = TempDir::new().test_ok()?;
        let bad_db = tmp.path().join("no_such_dir").join("ledger.db");
        let key_path = tmp.path().join("sk");
        run_keygen(&key_path)?;
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("store:{}", bad_db.display()),
            "--site".into(),
            tmp.path().join("site").to_str().test_ok()?.to_owned(),
            "--key".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ]);
        assert!(err.is_err(), "expected error for invalid store path");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_store_create_timeline_fails() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L322: `?` on find_or_create_ledger_timeline in cmd_build
        // when create_timeline fails (read-only DB with non-ledger timeline).
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return Ok(());
        }
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        run_keygen(&key_path)?;
        {
            let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .test_ok()?;
            store.create_timeline("other").test_ok()?;
        }
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o444)).test_ok()?;
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--site".into(),
            tmp.path().join("site").to_str().test_ok()?.to_owned(),
            "--key".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ]);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).test_ok()?;
        assert!(err.is_err(), "expected error from read-only DB");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_store_invalid_today_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L331: `?` on ledger_store.load(&today) in cmd_build
        // when the today string is not a valid date.
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        run_keygen(&key_path)?;
        let err = run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--site".into(),
            tmp.path().join("site").to_str().test_ok()?.to_owned(),
            "--today".into(),
            "bad-date".into(),
            "--key".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ]);
        assert!(err.is_err(), "expected error for invalid today");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn build_store_with_key_writes_the_site() -> Result<(), Box<dyn Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        let site = tmp.path().join("site");
        run_keygen(&key_path)?;
        run(&[
            "piglor-ledger".into(),
            "build".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--key".into(),
            key_path.to_str().test_ok()?.to_owned(),
            "--site".into(),
            site.to_str().test_ok()?.to_owned(),
            "--today".into(),
            "2026-07-25".into(),
        ])
        .test_ok()?;
        assert!(site.join("ledger/index.html").is_file());
        assert!(site.join("ledger/ledger.json").is_file());
        assert!(site.join("index.html").is_file());
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;
    use crate::test_helpers::TestResultExt;
    use pos_core::store::EventStore;
    use tempfile::TempDir;

    #[test]
    fn export_serialization_entrypoint_is_covered() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let source = temp.path().join("ledger");
        std::fs::create_dir_all(&source)?;
        run(&[
            "piglor-ledger".to_owned(),
            "export".to_owned(),
            "--source".to_owned(),
            format!("toml:{}", source.display()),
            "--today".to_owned(),
            "2026-07-25".to_owned(),
        ])
        .test_ok()?;
        Ok(())
    }

    #[test]
    fn build_store_missing_key_entrypoint_is_covered() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let database = temp.path().join("ledger.db");
        let missing_key = temp.path().join("missing.key");
        let error = run(&[
            "piglor-ledger".to_owned(),
            "build".to_owned(),
            "--source".to_owned(),
            format!("store:{}", database.display()),
            "--site".to_owned(),
            temp.path().join("site").display().to_string(),
            "--key".to_owned(),
            missing_key.display().to_string(),
            "--today".to_owned(),
            "2026-07-25".to_owned(),
        ])
        .test_err()?;
        assert!(error.to_string().contains("invalid --key"), "{error}");
        Ok(())
    }

    #[test]
    fn build_store_rejects_persisted_registry_without_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let database = temp.path().join("ledger.db");
        let key_path = temp.path().join("signing.key");
        let (signing_key, _) = generate_keypair();
        std::fs::write(&key_path, hex_encode(&signing_key.to_bytes()))?;
        let mut raw = pos_store::sqlite::SqliteStore::open(database.to_string_lossy().as_ref())?;
        raw.create_timeline("ledger")?;
        raw.save_key_registry(&KeyRegistryStateV1::new())?;
        drop(raw);

        let error = run(&[
            "piglor-ledger".to_owned(),
            "build".to_owned(),
            "--source".to_owned(),
            format!("store:{}", database.display()),
            "--site".to_owned(),
            temp.path().join("site").display().to_string(),
            "--key".to_owned(),
            key_path.display().to_string(),
            "--today".to_owned(),
            "2026-07-25".to_owned(),
        ])
        .test_err()?;
        assert!(error.to_string().contains("authorization"), "{error}");
        Ok(())
    }
}
