//! `piglor-ledger export` — produces a tamper-evident manifest of the
//! current source state for offline verification (ADR-017 Decision 5).
//!
//! TOML tier: entries + per-file BLAKE3 of raw file bytes (`b3sum`-compatible).
//! Store tier: entries + signed event records (payload + signature hex).

use std::path::Path;

use pos_core::store::SeqRange;
use pos_plugin_ledger::{LedgerStore, LedgerView};
use serde::{Deserialize, Serialize};

use crate::{cli::Source, hex_encode, CliError};

/// Manifest produced by `export` (one variant per tier).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "tier", rename_all = "snake_case")]
pub enum ExportManifest {
    /// Curated TOML tier manifest.
    Toml {
        /// RFC-3339 date used to derive overdue state.
        today: String,
        /// Folded ledger view (entries + headline counts).
        view: LedgerView,
        /// Per-file hashes (b3sum-compatible BLAKE3 of raw file bytes).
        files: Vec<FileHash>,
    },
    /// Live event-store tier manifest.
    Store {
        /// RFC-3339 date used to derive overdue state.
        today: String,
        /// Folded ledger view (entries + headline counts).
        view: LedgerView,
        /// Signed events appended to the ledger timeline, in seq order.
        events: Vec<SignedEventRecord>,
        /// Hex-encoded Ed25519 public key, when `--pubkey` was supplied.
        #[serde(skip_serializing_if = "Option::is_none")]
        pubkey: Option<String>,
    },
}

/// One file + its b3sum-compatible BLAKE3 hash (lowercase hex).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileHash {
    /// Path relative to the source root.
    pub path: String,
    /// Lowercase hex BLAKE3 of the file's raw bytes.
    pub hash: String,
}

/// One ledger event + its signature (store tier).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEventRecord {
    /// Event sequence number in the ledger timeline.
    pub seq: u64,
    /// Event type (`ledger.prediction` or `ledger.outcome`).
    pub event_type: String,
    /// Lowercase hex CBOR payload.
    pub payload_hex: String,
    /// Hex Ed25519 signature, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
}

/// Build an [`ExportManifest`] for `source` using `today` for overdue derivation.
///
/// `pubkey_hex`, when supplied on the store tier, is stored verbatim in the
/// manifest for offline verifier use.
///
/// # Errors
/// Returns [`CliError`] on adapter failure or store-tier timeline lookup.
pub fn build(
    source: &Source,
    today: &str,
    pubkey_hex: Option<String>,
) -> Result<ExportManifest, CliError> {
    match source {
        Source::Toml(dir) => build_toml(dir, today),
        Source::Store(db) => build_store(db, today, pubkey_hex),
    }
}

/// Build a manifest for the TOML tier.
fn build_toml(dir: &Path, today: &str) -> Result<ExportManifest, CliError> {
    let store = pos_plugin_ledger::TomlLedgerStore::new(dir);
    let ledger = store.load(today)?;
    let view = LedgerView::from(&ledger);
    let files = collect_toml_hashes(dir);
    Ok(ExportManifest::Toml {
        today: today.to_owned(),
        view,
        files,
    })
}

/// Walk `predictions/` and `resolutions/` and hash each TOML file's raw bytes.
fn collect_toml_hashes(dir: &Path) -> Vec<FileHash> {
    let mut out = Vec::new();
    for sub in ["predictions", "resolutions"] {
        let subdir = dir.join(sub);
        let Ok(rd) = std::fs::read_dir(&subdir) else {
            continue;
        };
        let mut paths: Vec<std::path::PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
            .collect();
        paths.sort();
        for path in paths {
            // `store.load` already read these files successfully, so a read
            // failure here requires concurrent deletion — treat as unreachable.
            let bytes = std::fs::read(&path)
                .expect("file readable by store.load; concurrent deletion is unsupported");
            let hash = blake3::hash(&bytes);
            let rel = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push(FileHash {
                path: rel,
                hash: hash.to_hex().to_string(),
            });
        }
    }
    out
}

/// Build a manifest for the store tier.
fn build_store(db: &Path, today: &str, pubkey: Option<String>) -> Result<ExportManifest, CliError> {
    let store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: db.to_string_lossy().into_owned(),
    })
    .map_err(|e| CliError::BadSource(e.to_string()))?;
    let timeline = store
        .list_timelines()?
        .into_iter()
        .find(|t| t.meta.name.as_deref() == Some("ledger"))
        .ok_or_else(|| CliError::BadSource("no 'ledger' timeline in store".into()))?;
    let events = store.read(timeline.id(), SeqRange::all())?;
    // Fold the ledger view via the port by reusing EventLedgerStore's load.
    // We have no key here — synthesise a throwaway one because load() doesn't
    // sign; only writes need a live key.
    let (sk, _) = pos_crypto::signing::generate_keypair();
    let ledger_store = pos_plugin_ledger::EventLedgerStore::new(
        store,
        timeline.id(),
        pos_core::ids::EntityId::new(),
        sk,
        Box::new(pos_crypto::chain::Blake3Hasher),
    );
    let ledger = ledger_store.load(today)?;
    let view = LedgerView::from(&ledger);
    let records: Vec<SignedEventRecord> = events
        .iter()
        .map(|e| SignedEventRecord {
            seq: e.seq.as_u64(),
            event_type: e.event_type.as_str().to_owned(),
            payload_hex: hex_encode(e.payload.as_slice()),
            signature_hex: e.signature.as_ref().map(|s| hex_encode(s.as_bytes())),
        })
        .collect();
    Ok(ExportManifest::Store {
        today: today.to_owned(),
        view,
        events: records,
        pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::run;
    use crate::hex::{hex_decode, nib};
    use tempfile::TempDir;

    fn populated_toml_dir() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).unwrap();
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
            "Kyoto".into(),
            "--confidence".into(),
            "0.7".into(),
            "--made-at".into(),
            "2026-07-25T12:00:00Z".into(),
            "--resolve-by".into(),
            "2026-08-01".into(),
            "--osf".into(),
            "https://osf.io/example".into(),
        ])
        .unwrap();
        let id = crate::test_helpers::first_prediction_id(&dir);
        run(&[
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
        .unwrap();
        // Return the TempDir parent so both `tmp` (with `ledger/`) survives.
        // The dir is tmp/ledger; we'll point build at it.
        // We need to keep the TempDir alive — return it.
        tmp
    }

    #[test]
    fn build_toml_produces_manifest_with_file_hashes_matching_b3sum() {
        let tmp = populated_toml_dir();
        let dir = tmp.path().join("ledger");
        let manifest = build(&Source::Toml(dir.clone()), "2026-07-25", None).unwrap();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("\"tier\": \"toml\""), "{json}");
        assert!(json.contains("\"today\": \"2026-07-25\""), "{json}");
        assert!(json.contains("\"n_resolved\": 1"), "{json}");
        assert!(json.contains("\"n_pending\": 0"), "{json}");
        // Parse as a generic JSON value to inspect file hashes without branching
        // on the enum variant (avoids unreachable match arms).
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let files = val["files"].as_array().unwrap();
        assert_eq!(
            files.len(),
            2,
            "expected 2 files (1 prediction + 1 resolution)"
        );
        for fh in files {
            let path = fh["path"].as_str().unwrap();
            let hash = fh["hash"].as_str().unwrap();
            let abs = dir.join(path);
            let bytes = std::fs::read(&abs).unwrap();
            let expected = blake3::hash(&bytes).to_hex().to_string();
            assert_eq!(hash, expected, "hash mismatch for {path}");
            assert_eq!(hash.len(), 64);
        }
        assert!(files[0]["path"]
            .as_str()
            .unwrap()
            .starts_with("predictions/"));
        assert!(files[1]["path"]
            .as_str()
            .unwrap()
            .starts_with("resolutions/"));
    }

    #[test]
    fn build_toml_empty_dir_yields_empty_manifest() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = build(&Source::Toml(dir), "2026-07-25", None).unwrap();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("\"tier\": \"toml\""), "{json}");
        assert!(json.contains("\"n_pending\": 0"), "{json}");
        assert!(json.contains("\"n_resolved\": 0"), "{json}");
        assert!(json.contains("\"files\": []"), "{json}");
    }

    #[test]
    fn build_store_without_ledger_timeline_errors() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("novelty.db");
        // Open and create a non-ledger timeline so the find fails.
        let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })
        .unwrap();
        store.create_timeline("other").unwrap();
        drop(store);
        let err = build_store(&db, "2026-07-25", None).unwrap_err();
        assert!(err.to_string().contains("ledger"));
    }

    #[test]
    fn build_store_with_signed_events_includes_signature_hex() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("ledger.db");
        // keygen + predict + resolve via the CLI
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().unwrap().to_owned(),
        ])
        .unwrap();
        let key_text = std::fs::read_to_string(&key_path).unwrap();
        let _pk = derive_pubkey_hex(&key_text);

        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--key".into(),
            key_path.to_str().unwrap().to_owned(),
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
        .unwrap();
        // Need a pubkey to verify; re-derive from the secret key for the manifest.
        let pubkey = derive_pubkey_hex(&key_text);
        let manifest = build_store(&db, "2026-07-25", Some(pubkey.clone())).unwrap();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("\"tier\": \"store\""), "{json}");
        assert!(
            json.contains(&format!("\"pubkey\": \"{pubkey}\"")),
            "{json}"
        );
        assert!(json.contains("\"n_pending\": 1"), "{json}");
        // Parse as a generic JSON value to inspect events without branching on the
        // enum variant (avoids unreachable match arms).
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let events = val["events"].as_array().unwrap();
        assert!(!events.is_empty(), "expected at least one event");
        assert!(
            events.iter().all(|e| e["signature_hex"].is_string()),
            "all events should be signed"
        );
    }

    fn derive_pubkey_hex(secret_hex: &str) -> String {
        let bytes = hex_decode(secret_hex.trim()).unwrap();
        let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
        let vk = sk.verifying_key();
        crate::hex_encode(&vk.to_bytes())
    }

    #[test]
    fn collect_toml_hashes_skips_unreadable_subdirs() {
        // With the simplified collect_toml_hashes (any read_dir error → skip),
        // an empty ledger dir produces an empty file list.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = build(&Source::Toml(dir), "2026-07-25", None).unwrap();
        // Check via JSON to avoid unreachable pattern-match branches.
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("\"tier\": \"toml\""), "{json}");
        assert!(json.contains("\"files\": []"), "{json}");
    }

    #[test]
    fn hex_decode_odd_length_is_error() {
        // Exercises the odd-length branch in hex_decode_local (line 358).
        assert!(hex_decode("a").is_err());
    }

    #[test]
    fn nib_rejects_invalid_hex_char() {
        // Exercises the `_` (error) arm of nib in this test module.
        assert!(nib('g').is_err());
    }

    #[test]
    fn nib_covers_uppercase() {
        // Exercises the 'A'..='F' arm of nib.
        assert_eq!(nib('A').unwrap(), 10);
        assert_eq!(nib('F').unwrap(), 15);
    }

    #[test]
    fn manifest_serialises_as_pretty_tagged_json() {
        let manifest = ExportManifest::Toml {
            today: "2026-07-25".into(),
            view: LedgerView {
                entries: Vec::new(),
                n_pending: 0,
                n_overdue: 0,
                n_resolved: 0,
                mean_brier: None,
                warnings: Vec::new(),
            },
            files: Vec::new(),
        };
        let s = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(s.contains("\"tier\": \"toml\""));
        assert!(s.contains("\"today\": \"2026-07-25\""));
        assert!(s.contains("\"n_resolved\": 0"));
        assert!(s.contains("\"entries\": []"));
        // Round-trips losslessly.
        let back: ExportManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn build_source_store_dispatches_to_build_store() {
        // Exercises the `Source::Store(db) => build_store(...)` arm (line 79)
        // of the public `build()` function.
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().unwrap().to_owned(),
        ])
        .unwrap();
        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--key".into(),
            key_path.to_str().unwrap().to_owned(),
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
        .unwrap();
        // Derive pubkey for the manifest.
        let sk_text = std::fs::read_to_string(&key_path).unwrap();
        let pubkey = derive_pubkey_hex(&sk_text);
        let manifest = build(&Source::Store(db), "2026-07-25", Some(pubkey)).unwrap();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("\"tier\": \"store\""), "{json}");
    }

    #[test]
    fn build_store_with_invalid_sqlite_path_errors() {
        // Covers L133: `format!("open sqlite: {e}")` in build_store when the
        // sqlite path is invalid (parent directory doesn't exist).
        let tmp = TempDir::new().unwrap();
        let bad_db = tmp.path().join("no_such_dir").join("ledger.db");
        let err = build_store(&bad_db, "2026-07-25", None).unwrap_err();
        // The error could be "store error" (wrapped CoreError) or "io error" depending on SQLite behavior.
        assert!(!err.to_string().is_empty(), "{err}");
    }

    #[test]
    fn build_store_with_corrupted_db_errors() {
        // Covers L136: `format!("list timelines: {e}")` in build_store when
        // the DB file is not a valid SQLite database.
        let tmp = TempDir::new().unwrap();
        let bad_db = tmp.path().join("corrupt.db");
        std::fs::write(&bad_db, b"this is not a sqlite file at all\n").unwrap();
        let err = build_store(&bad_db, "2026-07-25", None);
        // Either open fails (L133) or list_timelines fails (L136).
        assert!(err.is_err(), "expected error for corrupted DB");
    }

    #[test]
    fn hex_decode_second_nibble_error() {
        // Covers the `?` on nib(l) in hex_decode_local — second nibble invalid.
        assert!(hex_decode("0g").is_err());
    }

    #[test]
    fn hex_decode_first_nibble_error() {
        // Covers the `?` on nib(h) in hex_decode_local — first nibble invalid.
        assert!(hex_decode("g0").is_err());
    }

    #[test]
    fn build_toml_with_invalid_today_errors() {
        // Covers L86: `?` on store.load(today) in build_toml when today is invalid.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(&dir).unwrap();
        // Invalid date format triggers LedgerError::InvalidToday → CliError::Ledger.
        let err = build(&Source::Toml(dir), "not-a-date", None).unwrap_err();
        assert!(err.to_string().contains("invalid today"), "{err}");
    }

    #[test]
    fn build_toml_unreadable_prediction_returns_error() {
        // When a prediction file is unreadable, store.load fails with an
        // io error — demonstrating the error propagates through build_toml.
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("ledger");
        std::fs::create_dir_all(dir.join("predictions")).unwrap();
        let pred_file = dir
            .join("predictions")
            .join("01J3B0Y5ZK2J6MGK8D7QW3N0P9.toml");
        std::fs::write(
            &pred_file,
            "prediction_id = \"01J3B0Y5ZK2J6MGK8D7QW3N0P9\"\ntitle = \"T\"\nstatement = \"S\"\npredicted_outcome = \"O\"\nconfidence = 0.7\nmade_at = \"2026-07-25T12:00:00Z\"\nresolve_by = \"2026-08-01\"\nosf_link = \"https://osf.io/x\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&pred_file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err = build(&Source::Toml(dir), "2026-07-25", None);
        std::fs::set_permissions(&pred_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        // store.load fails because the prediction file is unreadable.
        assert!(err.is_err(), "expected error for unreadable file");
    }

    #[test]
    fn build_store_with_invalid_today_errors() {
        // Covers L152: `?` on ledger_store.load(today) in build_store.
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("ledger.db");
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().unwrap().to_owned(),
        ])
        .unwrap();
        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--key".into(),
            key_path.to_str().unwrap().to_owned(),
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
        .unwrap();
        let err = build_store(&db, "bad-date", None).unwrap_err();
        assert!(err.to_string().contains("invalid today"), "{err}");
    }

    #[test]
    fn build_store_list_timelines_fails_on_corrupt_db() {
        // Covers L136: `?` on list_timelines in build_store when timeline
        // id is corrupt (same SQLite injection technique as pos-cli).
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("corrupt.db");
        {
            let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
                path: db.to_string_lossy().into_owned(),
            })
            .unwrap();
            store.create_timeline("ledger").unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&db).expect("open for corruption");
            conn.execute("UPDATE timelines SET id = X'0102'", [])
                .expect("corrupt timeline id");
        }
        let err = build_store(&db, "2026-07-25", None).unwrap_err();
        assert!(!err.to_string().is_empty(), "{err}");
    }

    #[test]
    fn build_store_read_fails_on_corrupt_events() {
        // Covers L141: `?` on store.read when the event seq column is corrupt.
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("sk");
        run(&[
            "piglor-ledger".into(),
            "keygen".into(),
            "--out".into(),
            key_path.to_str().unwrap().to_owned(),
        ])
        .unwrap();
        let db = tmp.path().join("corrupt_events.db");
        // Add a real event so the timeline and events table have data.
        run(&[
            "piglor-ledger".into(),
            "predict".into(),
            "--source".into(),
            format!("store:{}", db.display()),
            "--key".into(),
            key_path.to_str().unwrap().to_owned(),
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
        .unwrap();
        // Corrupt the event seq column so store.read() fails.
        {
            let conn = rusqlite::Connection::open(&db).expect("open for corruption");
            conn.execute("UPDATE events SET seq = 'not-an-int'", [])
                .expect("corrupt event seq");
        }
        let err = build_store(&db, "2026-07-25", None).unwrap_err();
        assert!(!err.to_string().is_empty(), "{err}");
    }
}
