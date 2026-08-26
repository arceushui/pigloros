//! `piglor-ledger verify` — recomputes tamper-evidence for the current
//! source (ADR-017 Decision 5).
//!
//! TOML tier: recomputes the b3sum-compatible BLAKE3 of each file's raw
//! bytes and optionally compares against a previously-written [`ExportManifest`].
//! Store tier: re-reads ledger events from the `SQLite` store and verifies
//! Ed25519 signatures against the persisted role/epoch registry. An optional
//! `--pubkey` is an additional trust check for role-bound signatures.

use std::path::Path;

use pos_core::{event::Event, store::SeqRange, KeyRegistryStateV1};
use pos_crypto::{key_roles::verify_for_role, signing::verifying_key_from_public_key};
use pos_plugin_ledger::EVENT_TYPE_PREDICTION;

use crate::{cli::Source, export::ExportManifest, hex::hex_decode, CliError};

/// Summary of a verify run; printed to stdout and asserted on in tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyReport {
    /// Tier that was verified.
    pub tier: String,
    /// Number of files (toml) or events (store) inspected.
    pub n: usize,
    /// Outcome (`OK` or a failure message).
    pub outcome: VerifyOutcome,
}

/// Outcome of a verify run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyOutcome {
    /// All checks passed.
    Ok,
    /// One or more files were renamed, modified, or removed since export.
    Mismatch {
        /// Path (toml) or seq (store) of the offending entry.
        which: String,
        /// What was wrong.
        reason: String,
    },
}

impl std::fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.outcome {
            VerifyOutcome::Ok => write!(f, "OK: {} tier, {} entries", self.tier, self.n),
            VerifyOutcome::Mismatch { which, reason } => {
                write!(f, "FAIL: {} tier — {}: {}", self.tier, which, reason)
            }
        }
    }
}

/// Run verification against `source`.
///
/// If `manifest_path` is provided (TOML tier), the recomputed hashes are
/// compared against that manifest. For the store tier, the persisted registry
/// resolves each event identity; `pubkey_hex`, when provided, is an additional
/// trust check against the resolved public key.
///
/// # Errors
/// Returns [`CliError`] on adapter failure. Verification *failures* are
/// reported via `VerifyReport` (a non-error path) so the CLI prints a
/// readable report — only infrastructure errors propagate as `Err`.
pub fn run(
    source: &Source,
    pubkey_hex: Option<&str>,
    manifest_path: Option<&Path>,
) -> Result<VerifyReport, CliError> {
    match source {
        Source::Toml(dir) => verify_toml(dir, manifest_path),
        Source::Store(db) => verify_store(db, pubkey_hex),
    }
}

fn verify_toml(dir: &Path, manifest_path: Option<&Path>) -> Result<VerifyReport, CliError> {
    let mut hashes = collect_hashes(dir)?;
    hashes.sort_by(|a, b| a.0.cmp(&b.0));
    let n = hashes.len();
    if let Some(path) = manifest_path {
        let text = std::fs::read_to_string(path)?;
        let manifest: ExportManifest = serde_json::from_str(&text)?;
        let ExportManifest::Toml { files, .. } = manifest else {
            return Ok(VerifyReport {
                tier: "toml".to_owned(),
                n,
                outcome: VerifyOutcome::Mismatch {
                    which: "manifest".to_owned(),
                    reason: "manifest is not a toml-tier export".to_owned(),
                },
            });
        };
        let mut expected: Vec<(String, String)> =
            files.into_iter().map(|f| (f.path, f.hash)).collect();
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        if expected != hashes {
            let (which, reason) = describe_mismatch(&expected, &hashes);
            return Ok(VerifyReport {
                tier: "toml".to_owned(),
                n,
                outcome: VerifyOutcome::Mismatch { which, reason },
            });
        }
    }
    Ok(VerifyReport {
        tier: "toml".to_owned(),
        n,
        outcome: VerifyOutcome::Ok,
    })
}

fn describe_mismatch(
    expected: &[(String, String)],
    actual: &[(String, String)],
) -> (String, String) {
    let expected_paths: std::collections::BTreeSet<&String> =
        expected.iter().map(|(p, _)| p).collect();
    let actual_paths: std::collections::BTreeSet<&String> = actual.iter().map(|(p, _)| p).collect();
    for (path, hash) in actual {
        match expected.iter().find(|(p, _)| p == path) {
            None => return (path.clone(), "file added since export".to_owned()),
            Some((_, expected_hash)) if expected_hash != hash => {
                return (path.clone(), "hash differs from manifest".to_owned());
            }
            _ => {}
        }
    }
    // If we get here, no file in `actual` was added or modified — the
    // difference must be a removed file (a path present in `expected` but
    // absent from `actual`). The caller only calls this when expected != actual,
    // so at least one such missing path always exists.
    let missing = expected_paths
        .difference(&actual_paths)
        .next()
        .map_or("(unknown)", |s| s.as_str());
    (missing.to_owned(), "file removed since export".to_owned())
}

/// Walk `predictions/` and `resolutions/` returning `(rel_path, hex_hash)` pairs.
fn collect_hashes(dir: &Path) -> Result<Vec<(String, String)>, CliError> {
    let mut out = Vec::new();
    for sub in ["predictions", "resolutions"] {
        let subdir = dir.join(sub);
        let Ok(rd) = std::fs::read_dir(&subdir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let hash = blake3::hash(&bytes).to_hex().to_string();
            let rel = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push((rel, hash));
        }
    }
    Ok(out)
}

fn verify_store(db: &Path, pubkey_hex: Option<&str>) -> Result<VerifyReport, CliError> {
    let supplied_public_key = parse_supplied_public_key(pubkey_hex)?;

    let store = pos_store::open_store_read_only(&db.to_string_lossy())
        .map_err(|e| CliError::BadSource(e.to_string()))?;
    let registry = store
        .load_key_registry()
        .map_err(|e| CliError::BadSource(e.to_string()))?;
    if registry.is_none() {
        return Err(CliError::BadSource(
            "store verification requires a persisted role/epoch registry".to_owned(),
        ));
    }
    let timeline = store
        .list_timelines()?
        .into_iter()
        .find(|t| t.meta.name.as_deref() == Some("ledger"))
        .ok_or_else(|| CliError::BadSource("no 'ledger' timeline in store".into()))?;
    let events = store.read(timeline.id(), SeqRange::all())?;
    if events.is_empty() {
        return Err(CliError::BadSource(
            "store verification requires at least one ledger event".to_owned(),
        ));
    }
    let n = events.len();
    for event in &events {
        if let Some((which, reason)) =
            verify_store_event(event, supplied_public_key, registry.as_ref())?
        {
            return Ok(VerifyReport {
                tier: "store".to_owned(),
                n,
                outcome: VerifyOutcome::Mismatch { which, reason },
            });
        }
    }
    Ok(VerifyReport {
        tier: "store".to_owned(),
        n,
        outcome: VerifyOutcome::Ok,
    })
}

fn parse_supplied_public_key(
    pubkey_hex: Option<&str>,
) -> Result<Option<pos_core::PublicKey>, CliError> {
    pubkey_hex
        .map(|value| {
            let bytes = hex_decode(value)
                .map_err(|error| CliError::BadKey(format!("--pubkey: {error}")))?;
            let array: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| CliError::BadKey("--pubkey must be 32 bytes".to_owned()))?;
            Ok(pos_core::PublicKey::from_bytes(array))
        })
        .transpose()
}

fn verify_store_event(
    event: &Event,
    supplied_public_key: Option<pos_core::PublicKey>,
    registry: Option<&KeyRegistryStateV1>,
) -> Result<Option<(String, String)>, CliError> {
    let which = format!("seq={}", event.seq.as_u64());
    if event.event_type.as_str() != EVENT_TYPE_PREDICTION
        && event.event_type.as_str() != pos_plugin_ledger::EVENT_TYPE_OUTCOME
    {
        return Ok(Some((
            which,
            format!("unsupported event type {:?}", event.event_type.as_str()),
        )));
    }
    let Some(signature) = &event.signature else {
        return Ok(Some((which, "event is unsigned".to_owned())));
    };
    let Some(identity) = event.signature_identity else {
        return Ok(Some((
            which,
            "signed event lacks a role/epoch identity".to_owned(),
        )));
    };
    let registry_public_key = registry
        .and_then(|value| value.key_record(identity))
        .and_then(|record| record.public_verification_key);
    if let (Some(supplied), Some(registered)) = (supplied_public_key, registry_public_key) {
        if supplied != registered {
            return Ok(Some((
                which,
                "supplied public key does not match the persisted registry".to_owned(),
            )));
        }
    }
    let public_key = registry_public_key.ok_or_else(|| {
        CliError::BadSource("store verification has no public key for event identity".to_owned())
    })?;
    let verifying_key = verifying_key_from_public_key(&public_key)
        .map_err(|error| CliError::BadKey(error.to_string()))?;
    if let Err(error) = verify_for_role(
        &verifying_key,
        identity.role,
        identity.epoch,
        &event.payload,
        signature,
    ) {
        return Ok(Some((which, error.to_string())));
    }
    Ok(None)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{run, verify_store_event, Source, VerifyOutcome, VerifyReport};
    use crate::cli::run as cli_run;
    use crate::hex::{hex_decode, nib};
    use crate::test_helpers::{running_as_root, TestOptionExt, TestResultExt};
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Return the `(which, reason)` fields from a mismatch outcome.
    fn expect_mismatch(
        outcome: VerifyOutcome,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        match outcome {
            VerifyOutcome::Mismatch { which, reason } => Ok((which, reason)),
            VerifyOutcome::Ok => Err("expected Mismatch, got Ok".into()),
        }
    }

    fn run_store_event(
        event: pos_core::event::Event,
        registry: Option<&pos_core::KeyRegistryStateV1>,
        supplied_public_key: Option<pos_core::PublicKey>,
        signature_identity: Option<pos_core::KeyIdentityV1>,
        signed: bool,
    ) -> Result<Result<VerifyReport, crate::CliError>, Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        let timeline = store.create_timeline("ledger").test_ok()?;
        store.append_committed(timeline.id(), &[event]).test_ok()?;
        if let Some(registry) = registry {
            store.save_key_registry(registry).test_ok()?;
        }
        drop(store);
        if signed {
            let connection = rusqlite::Connection::open(&db)?;
            if let Some(identity) = signature_identity {
                connection.execute(
                    "UPDATE events SET signature = zeroblob(64), signature_role = ?1, signature_epoch = ?2",
                    rusqlite::params![
                        i64::from(identity.role.code()),
                        i64::try_from(identity.epoch)?,
                    ],
                )?;
            } else {
                connection.execute("UPDATE events SET signature = zeroblob(64)", [])?;
            }
        }
        let supplied_public_key = supplied_public_key.map(|key| crate::hex_encode(key.as_bytes()));
        Ok(run(
            &Source::Store(db),
            supplied_public_key.as_deref(),
            None,
        ))
    }

    /// Covers the `Ok` arm of `expect_mismatch`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn expect_mismatch_rejects_ok() {
        assert!(expect_mismatch(VerifyOutcome::Ok).is_err());
    }

    fn populated_toml(tmp: &TempDir) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        cli_run(&[
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
        Ok(dir)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_no_manifest_returns_ok_after_predict() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDir::new().test_ok()?;
        let dir = populated_toml(&tmp)?;
        let report = run(&Source::Toml(dir), None, None).test_ok()?;
        assert_eq!(report.tier, "toml");
        assert_eq!(report.outcome, VerifyOutcome::Ok);
        assert!(report.n >= 1);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_with_resolved_entry_covers_sort_closure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Covers L93: the sort closure `a.0.cmp(&b.0)` in verify_toml which
        // only runs when there are 2+ files to compare AND a manifest is provided.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        cli_run(&[
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
        let id = crate::test_helpers::first_prediction_id(&dir);
        cli_run(&[
            "piglor-ledger".into(),
            "resolve".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--id".into(),
            id,
            "--outcome".into(),
            "true".into(),
            "--resolved-at".into(),
            "2026-07-30T09:00:00Z".into(),
        ])
        .test_ok()?;
        // Export manifest with 2 files (prediction + resolution).
        let manifest_path = tmp.path().join("manifest.json");
        cli_run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        // Verify WITH manifest — this enters the `if let Some(path) = manifest_path`
        // branch and sorts both the expected (2 files) and actual (2 files) vectors.
        let report = run(&Source::Toml(dir), None, Some(&manifest_path)).test_ok()?;
        assert_eq!(report.outcome, VerifyOutcome::Ok);
        assert_eq!(report.n, 2);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_with_manifest_round_trips_ok() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = populated_toml(&tmp)?;
        let manifest_path = tmp.path().join("manifest.json");
        cli_run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let report = run(&Source::Toml(dir), None, Some(&manifest_path)).test_ok()?;
        assert_eq!(report.outcome, VerifyOutcome::Ok);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_detects_tampered_prediction_file() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = populated_toml(&tmp)?;
        let manifest_path = tmp.path().join("manifest.json");
        cli_run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let pred_path = std::fs::read_dir(dir.join("predictions"))
            .test_ok()?
            .next()
            .test_ok()?
            .test_ok()?
            .path();
        std::fs::write(&pred_path, "tampered = true\n").test_ok()?;
        let report = run(&Source::Toml(dir), None, Some(&manifest_path)).test_ok()?;
        let (which, reason) = expect_mismatch(report.outcome)?;
        assert!(which.starts_with("predictions/"), "{which}");
        assert!(reason.contains("hash differs"), "{reason}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_detects_removed_file() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = populated_toml(&tmp)?;
        let manifest_path = tmp.path().join("manifest.json");
        cli_run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        std::fs::remove_file(
            std::fs::read_dir(dir.join("predictions"))
                .test_ok()?
                .next()
                .test_ok()?
                .test_ok()?
                .path(),
        )
        .test_ok()?;
        let report = run(&Source::Toml(dir), None, Some(&manifest_path)).test_ok()?;
        let (which, reason) = expect_mismatch(report.outcome)?;
        assert!(which.starts_with("predictions/"), "{which}");
        assert!(reason.contains("removed"), "{reason}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_detects_added_file() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let dir = populated_toml(&tmp)?;
        let manifest_path = tmp.path().join("manifest.json");
        cli_run(&[
            "piglor-ledger".into(),
            "export".into(),
            "--source".into(),
            format!("toml:{}", dir.display()),
            "--out".into(),
            manifest_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        std::fs::write(dir.join("predictions").join("rogue.toml"), "x = 1\n").test_ok()?;
        let report = run(&Source::Toml(dir), None, Some(&manifest_path)).test_ok()?;
        let (which, reason) = expect_mismatch(report.outcome)?;
        assert!(which.ends_with("rogue.toml"), "{which}");
        assert!(reason.contains("added"), "{reason}");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_with_signed_events_passes() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let sk_text = std::fs::read_to_string(&key_path).test_ok()?;
        let pubkey = crate::test_helpers::derive_pubkey_hex(sk_text.trim());

        cli_run(&[
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
            "https://osf.io/example".into(),
        ])
        .test_ok()?;
        let report = run(&Source::Store(db), Some(&pubkey), None).test_ok()?;
        assert_eq!(report.tier, "store");
        assert_eq!(report.outcome, VerifyOutcome::Ok);
        assert!(report.n >= 1);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_without_registry_returns_bad_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let _store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        let err = run(&Source::Store(db.clone()), None, None).test_err()?;
        assert!(err.to_string().contains("role/epoch registry"));
        let err = run(&Source::Store(db), Some(&"aa".repeat(32)), None).test_err()?;
        assert!(err.to_string().contains("role/epoch registry"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_rejects_an_empty_ledger() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("empty-ledger.db");
        let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        store.create_timeline("ledger").test_ok()?;
        store
            .save_key_registry(&pos_core::KeyRegistryStateV1::new())
            .test_ok()?;
        drop(store);

        let error = run(&Source::Store(db), Some(&"aa".repeat(32)), None).test_err()?;
        assert!(error.to_string().contains("at least one ledger event"));
        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_with_wrong_pubkey_reports_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        cli_run(&[
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
            "https://osf.io/example".into(),
        ])
        .test_ok()?;
        let other_key = tmp.path().join("other_sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            other_key.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let other_text = std::fs::read_to_string(&other_key).test_ok()?;
        let wrong_pubkey = crate::test_helpers::derive_pubkey_hex(other_text.trim());

        let report = run(&Source::Store(db), Some(&wrong_pubkey), None).test_ok()?;
        let (_which, reason) = expect_mismatch(report.outcome)?;
        // The persisted registry is authoritative before Ed25519 verification.
        assert!(
            reason.contains("persisted registry"),
            "expected persisted-registry mismatch, got: {reason}"
        );

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_handles_unreadable_pubkey_gracefully() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let _ = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        // Odd-length: fails before nib() is called (hex_decode returns early).
        let err = run(&Source::Store(db.clone()), Some("not-hex"), None).test_err()?;
        assert!(err.to_string().contains("--pubkey"), "{err}");

        // Even-length with non-hex char: exercises the `_` error arm in nib().
        let err2 = run(&Source::Store(db), Some("zz"), None).test_err()?;
        assert!(err2.to_string().contains("--pubkey"), "{err2}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_wrong_length_pubkey_rejected() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L173: "--pubkey must be 32 bytes" when hex decodes to != 32 bytes.
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let _ = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        // "aabb" is valid hex (2 bytes) but not 32 bytes.
        let err = run(&Source::Store(db), Some("aabb"), None).test_err()?;
        assert!(err.to_string().contains("--pubkey"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_invalid_ed25519_key_rejected() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L175: `e.to_string()` in verifying_key_from_public_key error.
        // Find a 32-byte value that is invalid for ed25519-dalek by scanning.
        use pos_core::PublicKey;
        use pos_crypto::signing::verifying_key_from_public_key;

        // Scan 1..=255 until we find a byte pattern that is an invalid Ed25519
        // compressed point. The scan always succeeds because not all 32-byte
        // sequences are valid curve points.
        let invalid_byte = (1u8..=255)
            .find(|&candidate| {
                let pk = PublicKey::from_bytes([candidate; 32]);
                verifying_key_from_public_key(&pk).is_err()
            })
            .test_ok()?;
        let invalid_hex = format!("{invalid_byte:02x}").repeat(32);

        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        cli_run(&[
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
            "https://osf.io/example".into(),
        ])
        .test_ok()?;
        let connection = rusqlite::Connection::open(&db).test_ok()?;
        let mut invalid_registry = pos_core::KeyRegistryStateV1::new();
        invalid_registry
            .register_key(pos_core::KeyRegistrationV1::new(
                pos_core::KeyIdentityV1::new(pos_core::KeyRoleV1::TimelineIntegritySigning, 1),
                pos_crypto::key_roles::key_material_digest(&[0; 32]),
                Some(PublicKey::from_bytes([invalid_byte; 32])),
            ))
            .test_ok()?;
        let mut state_cbor = Vec::new();
        ciborium::into_writer(&invalid_registry, &mut state_cbor).test_ok()?;
        connection
            .execute(
                "UPDATE key_registry SET state_cbor = ?1",
                rusqlite::params![state_cbor],
            )
            .test_ok()?;
        let err = run(&Source::Store(db), Some(&invalid_hex), None).test_err()?;
        assert!(err.to_string().contains("invalid --key"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_handles_missing_ledger_timeline() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("novelty.db");
        let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        store
            .save_key_registry(&pos_core::KeyRegistryStateV1::new())
            .test_ok()?;
        drop(store);
        let err = run(&Source::Store(db), Some(&"0".repeat(64)), None).test_err()?;
        assert!(err.to_string().contains("ledger"));

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_with_invalid_sqlite_path_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L180: `format!("open sqlite: {e}")` in verify_store.
        let tmp = TempDir::new().test_ok()?;
        let bad_db = tmp.path().join("no_such_dir").join("ledger.db");
        // "a" * 64 is a valid 32-byte hex (all 0xaa bytes) to get past pubkey check.
        let err = run(&Source::Store(bad_db), Some(&"a".repeat(64)), None).test_err()?;
        assert!(!err.to_string().is_empty(), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_reports_registry_load_failure() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("malformed-registry.db");
        pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        let conn = rusqlite::Connection::open(&db).test_ok()?;
        conn.execute(
            "INSERT INTO key_registry (singleton, state_cbor) VALUES (1, X'01')",
            [],
        )
        .test_ok()?;

        let error = run(&Source::Store(db), Some(&"aa".repeat(32)), None).test_err()?;
        assert!(error.to_string().contains("serialization error"), "{error}");
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_with_corrupted_db_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L183: `format!("list timelines: {e}")` in verify_store.
        let tmp = TempDir::new().test_ok()?;
        let bad_db = tmp.path().join("corrupt.db");
        std::fs::write(&bad_db, b"not sqlite data at all\n").test_ok()?;
        // Use a valid 32-byte pubkey (all 'aa') to get past the pubkey validation.
        let err = run(&Source::Store(bad_db), Some(&"aa".repeat(32)), None);
        // Either open fails (L180) or list_timelines fails (L183).
        assert!(err.is_err(), "expected error for corrupted DB");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn report_display_covers_ok_and_mismatch() {
        let ok = VerifyReport {
            tier: "toml".to_owned(),
            n: 2,
            outcome: VerifyOutcome::Ok,
        };
        assert!(ok.to_string().contains("OK"));
        let bad = VerifyReport {
            tier: "store".to_owned(),
            n: 1,
            outcome: VerifyOutcome::Mismatch {
                which: "seq=1".to_owned(),
                reason: "tampered".to_owned(),
            },
        };
        assert!(bad.to_string().contains("FAIL"));
        assert!(bad.to_string().contains("seq=1"));
    }

    // ── Additional coverage tests ────────────────────────────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_with_store_tier_manifest_reports_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // verify_toml() receives a Store-tier manifest → the `else` branch
        // on lines 82-89 (manifest is not a toml-tier export).
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;

        // Write a store-tier manifest JSON to a file.
        let store_manifest = crate::export::ExportManifest::Store {
            today: "2026-07-25".into(),
            view: pos_plugin_ledger::LedgerView {
                entries: Vec::new(),
                n_pending: 0,
                n_overdue: 0,
                n_resolved: 0,
                mean_brier: None,
                warnings: Vec::new(),
            },
            events: Vec::new(),
            pubkey: None,
        };
        let manifest_path = tmp.path().join("store-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&store_manifest).test_ok()?,
        )
        .test_ok()?;

        let report = run(&Source::Toml(dir), None, Some(&manifest_path)).test_ok()?;
        let (which, reason) = expect_mismatch(report.outcome)?;
        assert_eq!(which, "manifest");
        assert!(reason.contains("not a toml-tier export"), "{reason}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_with_bad_json_manifest_is_error() -> Result<(), Box<dyn std::error::Error>> {
        // Exercises the serde_json::from_str error path (line 240-241).
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let manifest_path = tmp.path().join("bad.json");
        std::fs::write(&manifest_path, "not json at all").test_ok()?;
        let err = run(&Source::Toml(dir), None, Some(&manifest_path)).test_err()?;
        assert!(err.to_string().contains("json error"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn collect_hashes_skips_unreadable_predictions_dir() -> Result<(), Box<dyn std::error::Error>> {
        // collect_hashes is now lenient — any read_dir error just skips that
        // subdir (returns empty rather than propagating the error).
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        // predictions/ is a file, so read_dir skips it silently.
        std::fs::write(dir.join("predictions"), "not a dir").test_ok()?;
        let report = run(&Source::Toml(dir), None, None).test_ok()?;
        assert_eq!(report.n, 0);
        assert_eq!(report.outcome, VerifyOutcome::Ok);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn collect_hashes_skips_non_toml_files() -> Result<(), Box<dyn std::error::Error>> {
        // Exercises the `continue` on line 148: a non-.toml file is ignored.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(dir.join("predictions")).test_ok()?;
        std::fs::write(dir.join("predictions").join("README.md"), "hi").test_ok()?;
        let report = run(&Source::Toml(dir), None, None).test_ok()?;
        assert_eq!(report.n, 0); // README was skipped
        assert_eq!(report.outcome, VerifyOutcome::Ok);

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_unsigned_event_reports_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        // Exercises the `None => return Ok(VerifyReport { unsigned })` branch
        // (lines 196-203) in verify_store.
        use pos_core::{
            clock::{Seq, WallTime},
            event::{Event, Kind, SchemaVersion},
            ids::{EntityId, EventId},
        };
        use pos_crypto::chain::hash_payload;
        use pos_plugin_ledger::{draft_prediction, LedgerPrediction};

        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let sk_text = std::fs::read_to_string(&key_path).test_ok()?;
        let pubkey = crate::test_helpers::derive_pubkey_hex(sk_text.trim());

        // Write a prediction event but strip the signature directly via
        // the raw store so the event is unsigned.
        let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        let tl = store.create_timeline("ledger").test_ok()?;

        // Build a valid-looking prediction payload (minimal CBOR map).
        let pred = LedgerPrediction {
            prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned(),
            title: "T".to_owned(),
            statement: "S".to_owned(),
            predicted_outcome: "O".to_owned(),
            confidence: 0.7,
            scenario: None,
            made_at: "2026-07-25T12:00:00Z".to_owned(),
            resolve_by: "2026-08-01".to_owned(),
            osf_link: "https://osf.io/x".to_owned(),
        };
        let entity = EntityId::new();
        let draft = draft_prediction(entity, &pred);
        let payload = draft.payload;
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
            payload,
            wall_time: WallTime::now(),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None, // unsigned
            signature_identity: None,
            payload_hash,
        };
        store.append_committed(tl.id(), &[event]).test_ok()?;
        store
            .save_key_registry(&pos_core::KeyRegistryStateV1::new())
            .test_ok()?;
        drop(store);

        let report = run(&Source::Store(db), Some(&pubkey), None).test_ok()?;
        let (_which, reason) = expect_mismatch(report.outcome)?;
        assert!(reason.contains("unsigned"), "{reason}");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_rejects_unknown_event_types() -> Result<(), Box<dyn std::error::Error>> {
        // Store verification must not silently exclude an event from the ledger timeline.
        use pos_core::{
            clock::{Seq, WallTime},
            event::{CanonicalBytes, Event, Kind, SchemaVersion},
            ids::EventId,
        };
        use pos_crypto::chain::hash_payload;

        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let sk_text = std::fs::read_to_string(&key_path).test_ok()?;
        let pubkey = crate::test_helpers::derive_pubkey_hex(sk_text.trim());

        let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        let tl = store.create_timeline("ledger").test_ok()?;
        let payload = CanonicalBytes::from_vec(b"irrelevant".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: pos_core::ids::EntityId::new(),
            event_type: Kind::new("something.else"),
            payload,
            wall_time: WallTime::now(),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.append_committed(tl.id(), &[event]).test_ok()?;
        store
            .save_key_registry(&pos_core::KeyRegistryStateV1::new())
            .test_ok()?;
        drop(store);

        // verify_store should report the unknown event instead of silently accepting it.
        let report = run(&Source::Store(db), Some(&pubkey), None).test_ok()?;
        let (which, reason) = expect_mismatch(report.outcome)?;
        assert_eq!(which, "seq=1");
        assert!(reason.contains("unsupported event type"), "{reason}");
        assert_eq!(report.n, 1);

        Ok(())
    }

    #[test]
    fn verify_store_event_rejects_unbound_and_invalid_role_signatures(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use pos_core::{
            clock::{Seq, WallTime},
            event::{CanonicalBytes, Event, Kind, SchemaVersion},
            ids::{EntityId, EventId},
            KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, PublicKey,
        };
        use pos_crypto::{chain::hash_payload, key_roles::key_material_digest};

        let event = || {
            let payload = CanonicalBytes::from_static(b"signed payload");
            Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
                payload: payload.clone(),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                payload_hash: hash_payload(&payload),
            }
        };

        let mut missing_identity_event = event();
        missing_identity_event.signature = Some(pos_core::Signature::from_bytes([0; 64]));
        let (_, missing_identity_reason) = verify_store_event(
            &missing_identity_event,
            None,
            Some(&KeyRegistryStateV1::new()),
        )?
        .ok_or("expected missing identity mismatch")?;
        assert!(missing_identity_reason.contains("role/epoch identity"));

        let wrong_role = run_store_event(
            event(),
            Some(&KeyRegistryStateV1::new()),
            None,
            Some(KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1)),
            true,
        )?
        .test_err()?;
        assert!(wrong_role.to_string().contains("signed event"));

        let (signing_key, verifying_key) = pos_crypto::signing::generate_keypair();
        let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
        let registered_key = PublicKey::from_bytes(verifying_key.to_bytes());
        let mut registry = KeyRegistryStateV1::new();
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                key_material_digest(&signing_key.to_bytes()),
                Some(registered_key),
            ))
            .test_ok()?;

        let supplied_mismatch = run_store_event(
            event(),
            Some(&registry),
            Some(PublicKey::from_bytes([7; 32])),
            Some(identity),
            true,
        )?
        .test_ok()?;
        let (_, reason) = expect_mismatch(supplied_mismatch.outcome)?;
        assert!(reason.contains("persisted registry"));

        let no_public_key = run_store_event(
            event(),
            Some(&KeyRegistryStateV1::new()),
            None,
            Some(identity),
            true,
        )?
        .test_err()?;
        assert!(no_public_key.to_string().contains("no public key"));

        let invalid_signature =
            run_store_event(event(), Some(&registry), None, Some(identity), true)?.test_ok()?;
        let (_, reason) = expect_mismatch(invalid_signature.outcome)?;
        assert!(!reason.is_empty());

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn nib_rejects_invalid_hex_char() {
        // Exercises the `_` error arm in the test module's nib helper.
        assert!(nib('g').is_err());
        assert!(nib('z').is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_toml_manifest_read_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L79: `?` on std::fs::read_to_string(path) in verify_toml
        // when the manifest file doesn't exist.
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).test_ok()?;
        let missing_manifest = tmp.path().join("nonexistent.json");
        let err = run(&Source::Toml(dir), None, Some(&missing_manifest)).test_err()?;
        assert!(err.to_string().contains("io error"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn collect_hashes_readdir_entry_error() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L148: `entry?` in collect_hashes when a readdir entry fails.
        // Also covers L152: `std::fs::read(&path)?` when a file is unreadable.
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return Ok(());
        }
        let tmp = TempDir::new().test_ok()?;
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(dir.join("predictions")).test_ok()?;
        let pred_file = dir.join("predictions").join("test.toml");
        std::fs::write(&pred_file, "[data]\n").test_ok()?;
        // Make the file unreadable so fs::read fails at L152.
        std::fs::set_permissions(&pred_file, std::fs::Permissions::from_mode(0o000)).test_ok()?;
        let err = run(&Source::Toml(dir), None, None).test_err()?;
        std::fs::set_permissions(&pred_file, std::fs::Permissions::from_mode(0o644)).test_ok()?;
        assert!(err.to_string().contains("io error"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_corrupted_db_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L182: `?` on list_timelines in verify_store when DB is corrupt.
        let tmp = TempDir::new().test_ok()?;
        let bad_db = tmp.path().join("corrupt.db");
        let mut content = b"SQLite format 3\x00".to_vec();
        content.push(0x10);
        content.push(0x00);
        content.extend_from_slice(&[0u8; 4078]);
        std::fs::write(&bad_db, content).test_ok()?;
        // Use a valid 32-byte pubkey hex (all 'aa').
        let err = run(&Source::Store(bad_db), Some(&"aa".repeat(32)), None);
        // Either open or list_timelines fails — either is acceptable.
        assert!(err.is_err(), "expected error for corrupted DB");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_list_timelines_fails_on_corrupt_db() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L181: `?` on list_timelines in verify_store when the timeline
        // id column is corrupt (same SQLite injection technique as pos-cli).
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let db = tmp.path().join("corrupt.db");
        let sk_text = std::fs::read_to_string(&key_path).test_ok()?;
        let pubkey = crate::test_helpers::derive_pubkey_hex(sk_text.trim());
        {
            let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .test_ok()?;
            store.create_timeline("ledger").test_ok()?;
            store
                .save_key_registry(&pos_core::KeyRegistryStateV1::new())
                .test_ok()?;
        }
        {
            let conn = rusqlite::Connection::open(&db).test_ok()?;
            conn.execute("UPDATE timelines SET id = X'0102'", [])
                .test_ok()?;
        }
        let err = run(&Source::Store(db), Some(&pubkey), None).test_err()?;
        assert!(!err.to_string().is_empty(), "{err}");

        Ok(())
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verify_store_read_fails_on_corrupt_events() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L186: `?` on store.read when an Event identifier is corrupt.
        let tmp = TempDir::new().test_ok()?;
        let key_path = tmp.path().join("sk");
        cli_run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().test_ok()?.to_owned(),
        ])
        .test_ok()?;
        let db = tmp.path().join("corrupt_events.db");
        let sk_text = std::fs::read_to_string(&key_path).test_ok()?;
        let pubkey = crate::test_helpers::derive_pubkey_hex(sk_text.trim());
        // Add a real event so events table has data to corrupt.
        cli_run(&[
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
        // Corrupt event seq so store.read() fails.
        {
            let conn = rusqlite::Connection::open(&db).test_ok()?;
            conn.execute("UPDATE events SET event_id = 'not-a-ulid'", [])
                .test_ok()?;
        }
        let err = run(&Source::Store(db), Some(&pubkey), None).test_err()?;
        assert!(!err.to_string().is_empty(), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn hex_decode_second_nibble_error_in_verify() -> Result<(), Box<dyn std::error::Error>> {
        // Covers L230: `?` on nib(l) in hex_decode when second nibble is bad.
        // This exercises the `?` for the second nibble via a hex string where
        // the first nibble is valid but the second is not.
        let tmp = TempDir::new().test_ok()?;
        let db = tmp.path().join("ledger.db");
        let _ = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .test_ok()?;
        // "ag" = valid 'a' then invalid 'g' — triggers nib(l) error
        let err = run(&Source::Store(db), Some("ag"), None).test_err()?;
        assert!(err.to_string().contains("--pubkey"), "{err}");

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn nib_covers_uppercase() -> Result<(), Box<dyn std::error::Error>> {
        // Exercises 'A'..='F' arm in the test module's nib helper.
        assert_eq!(nib('A').test_ok()?, 10);
        assert_eq!(nib('F').test_ok()?, 15);

        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn hex_decode_first_nibble_error() {
        // Covers L697:28: `nib(h)?` first nibble error in test hex_decode_local.
        assert!(hex_decode("g0").is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn hex_decode_second_nibble_error_in_test_helper() {
        // Covers L697:44: `nib(l)?` second nibble error in test hex_decode_local.
        assert!(hex_decode("0g").is_err());
    }
}
