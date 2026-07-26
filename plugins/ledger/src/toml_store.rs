//! [`TomlLedgerStore`] — curated-tier adapter (ADR-017 Decision 1).
//!
//! Layout: `<dir>/predictions/<prediction_id>.toml` (immutable after
//! registration) and `<dir>/resolutions/<prediction_id>.toml` (added at
//! resolution) — append-only file pairs folded at load, the event-sourcing
//! shape without a database. Tamper anchors are git history, OSF
//! registration, and per-file BLAKE3 hashes (`b3sum`-verifiable).

use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    store::{LedgerStore, NewPrediction},
    Ledger, LedgerError, LedgerOutcome, LedgerPrediction,
};

/// TOML-file-backed [`LedgerStore`].
pub struct TomlLedgerStore {
    dir: PathBuf,
}

impl TomlLedgerStore {
    /// Open the adapter rooted at `dir` (created lazily on first write).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn predictions_dir(&self) -> PathBuf {
        self.dir.join("predictions")
    }

    fn resolutions_dir(&self) -> PathBuf {
        self.dir.join("resolutions")
    }

    /// Read every `*.toml` file in `dir` as `(filename_stem, value)`,
    /// sorted by filename for determinism. A missing directory is an empty
    /// source, not an error (ADR-017 Decision 6: empty ledger, still 200).
    fn read_dir_toml<T: DeserializeOwned>(dir: &Path) -> Result<Vec<(String, T)>, LedgerError> {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(LedgerError::Io(e)),
        };
        let mut paths: Vec<PathBuf> = rd
            // Entries that fail mid-iteration are skipped: every collected
            // path is read explicitly below, so real files still surface
            // errors loudly — and no untestable branch remains (coverage
            // policy: delete, don't exempt).
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("toml"))
            .collect();
        paths.sort();
        let mut items = Vec::new();
        for path in paths {
            let text = std::fs::read_to_string(&path)?;
            let value = toml::from_str::<T>(&text).map_err(|e| LedgerError::Toml {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
            let stem = path
                .file_stem()
                .expect("read_dir entries always have file names")
                .to_string_lossy()
                .into_owned();
            items.push((stem, value));
        }
        Ok(items)
    }

    fn write_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), LedgerError> {
        let text =
            toml::to_string_pretty(value).expect("ledger payloads serialize to TOML infallibly");
        std::fs::write(path, text).map_err(LedgerError::Io)
    }
}

impl LedgerStore for TomlLedgerStore {
    fn load(&self, today: &str) -> Result<Ledger, LedgerError> {
        let predictions = Self::read_dir_toml::<LedgerPrediction>(&self.predictions_dir())?;
        let resolutions = Self::read_dir_toml::<LedgerOutcome>(&self.resolutions_dir())?;
        let mut pairs: Vec<(LedgerPrediction, Option<LedgerOutcome>)> = Vec::new();
        for (stem, prediction) in predictions {
            if stem != prediction.prediction_id {
                return Err(LedgerError::InvalidPrediction(format!(
                    "filename stem {stem:?} does not match prediction_id {:?}",
                    prediction.prediction_id
                )));
            }
            pairs.push((prediction, None));
        }
        for (stem, outcome) in resolutions {
            if stem != outcome.prediction_id {
                return Err(LedgerError::InvalidResolution(format!(
                    "filename stem {stem:?} does not match prediction_id {:?}",
                    outcome.prediction_id
                )));
            }
            let Some(slot) = pairs
                .iter_mut()
                .find(|(p, _)| p.prediction_id == outcome.prediction_id)
                .map(|(_, slot)| slot)
            else {
                return Err(LedgerError::OrphanResolution(outcome.prediction_id));
            };
            *slot = Some(outcome);
        }
        Ledger::from_pairs(pairs, today)
    }

    fn register(&mut self, new: NewPrediction) -> Result<String, LedgerError> {
        new.validate()?;
        let prediction = new.into_prediction(ulid::Ulid::gen().to_string());
        std::fs::create_dir_all(self.predictions_dir())?;
        let path = self
            .predictions_dir()
            .join(format!("{}.toml", prediction.prediction_id));
        Self::write_toml(&path, &prediction)?;
        Ok(prediction.prediction_id)
    }

    fn find_resolve_status(&self, prediction_id: &str) -> Result<(bool, bool), LedgerError> {
        let prediction_path = self.predictions_dir().join(format!("{prediction_id}.toml"));
        let resolution_path = self.resolutions_dir().join(format!("{prediction_id}.toml"));
        Ok((prediction_path.exists(), resolution_path.exists()))
    }

    fn persist_resolve(&mut self, outcome: LedgerOutcome) -> Result<(), LedgerError> {
        let resolution_path = self
            .resolutions_dir()
            .join(format!("{}.toml", outcome.prediction_id));
        std::fs::create_dir_all(self.resolutions_dir())?;
        Self::write_toml(&resolution_path, &outcome)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{contract, LedgerOutcome};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn port_contract() {
        contract::run(&mut |dir| Box::new(TomlLedgerStore::new(dir)) as Box<dyn LedgerStore>);
    }

    fn make_store() -> (TomlLedgerStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        (TomlLedgerStore::new(tmp.path()), tmp)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_dir_on_file_path_is_io_error() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("predictions");
        std::fs::write(&file, "not a dir").unwrap();
        let store = TomlLedgerStore::new(tmp.path());
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn resolutions_read_dir_failure_is_io_error() {
        let tmp = TempDir::new().unwrap();
        // Create predictions dir so the first read_dir_toml succeeds.
        std::fs::create_dir_all(tmp.path().join("predictions")).unwrap();
        // Make resolutions a file so the second read_dir_toml fails.
        std::fs::write(tmp.path().join("resolutions"), "not a dir").unwrap();
        let store = TomlLedgerStore::new(tmp.path());
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn unparseable_toml_is_toml_error() {
        let (mut store, tmp) = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let path = tmp.path().join("predictions").join(format!("{id}.toml"));
        std::fs::write(&path, "{ not toml").unwrap();
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::Toml { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn directory_named_toml_is_read_error() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("predictions")).unwrap();
        std::fs::create_dir(tmp.path().join("predictions").join("bad.toml")).unwrap();
        let store = TomlLedgerStore::new(tmp.path());
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stem_mismatch_is_invalid_prediction() {
        let (mut store, tmp) = make_store();
        store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let dir = tmp.path().join("predictions");
        let file = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap();
        std::fs::rename(file.path(), dir.join("01J3B0Y5ZK2J6MGK8D7QW3N0P9.toml")).unwrap();
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidPrediction(_)));
        assert!(err.to_string().contains("stem"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn resolution_stem_mismatch_is_invalid_resolution() {
        let (mut store, tmp) = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        store
            .resolve(LedgerOutcome {
                prediction_id: id.clone(),
                outcome: true,
                resolved_at: "2026-07-30T09:00:00Z".to_owned(),
            })
            .unwrap();
        let dir = tmp.path().join("resolutions");
        std::fs::rename(
            dir.join(format!("{id}.toml")),
            dir.join("01J3B0Y5ZK2J6MGK8D7QW3N0P9.toml"),
        )
        .unwrap();
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidResolution(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn orphan_resolution_is_error() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("resolutions")).unwrap();
        std::fs::write(
            tmp.path()
                .join("resolutions")
                .join("01J3B0Y5ZK2J6MGK8D7QW3N0P9.toml"),
            "prediction_id = \"01J3B0Y5ZK2J6MGK8D7QW3N0P9\"\noutcome = true\nresolved_at = \"2026-07-30T09:00:00Z\"\n",
        )
        .unwrap();
        let store = TomlLedgerStore::new(tmp.path());
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::OrphanResolution(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn missing_osf_link_file_is_excluded_with_warning() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("predictions")).unwrap();
        std::fs::write(
            tmp.path()
                .join("predictions")
                .join("01J3B0Y5ZK2J6MGK8D7QW3N0P9.toml"),
            "prediction_id = \"01J3B0Y5ZK2J6MGK8D7QW3N0P9\"\ntitle = \"t\"\nstatement = \"s\"\npredicted_outcome = \"o\"\nconfidence = 0.5\nmade_at = \"2026-07-25T12:00:00Z\"\nresolve_by = \"2026-08-01\"\nosf_link = \"\"\n",
        )
        .unwrap();
        let store = TomlLedgerStore::new(tmp.path());
        let ledger = store.load("2026-07-25").unwrap();
        assert!(ledger.entries().is_empty());
        assert_eq!(ledger.warnings().len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_with_predictions_path_blocked_by_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("predictions"), "a file").unwrap();
        let mut store = TomlLedgerStore::new(tmp.path());
        let err = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn resolve_with_resolutions_path_blocked_by_file() {
        let (mut store, tmp) = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        std::fs::write(tmp.path().join("resolutions"), "a file").unwrap();
        let err = store
            .resolve(LedgerOutcome {
                prediction_id: id.clone(),
                outcome: true,
                resolved_at: "2026-07-30T09:00:00Z".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
    }

    #[test]
    fn resolve_write_failure_is_io_error() {
        let (mut store, tmp) = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        // Make resolutions/ read-only so write_toml fails.
        std::fs::create_dir_all(tmp.path().join("resolutions")).unwrap();
        std::fs::set_permissions(
            tmp.path().join("resolutions"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        let err = store
            .resolve(LedgerOutcome {
                prediction_id: id.clone(),
                outcome: true,
                resolved_at: "2026-07-30T09:00:00Z".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
        // Restore permissions so TempDir cleanup doesn't fail.
        std::fs::set_permissions(
            tmp.path().join("resolutions"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_write_failure_is_io_error() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("predictions")).unwrap();
        std::fs::set_permissions(
            tmp.path().join("predictions"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        let mut store = TomlLedgerStore::new(tmp.path());
        let err = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap_err();
        assert!(matches!(err, LedgerError::Io(_)));
        std::fs::set_permissions(
            tmp.path().join("predictions"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn resolve_rejects_invalid_outcome_format() {
        let (mut store, _tmp) = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let err = store
            .resolve(LedgerOutcome {
                prediction_id: id.clone(),
                outcome: true,
                resolved_at: "not-a-datetime".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidResolution(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn non_toml_files_are_ignored() {
        let (mut store, tmp) = make_store();
        store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        std::fs::write(tmp.path().join("predictions").join("README.md"), "hi").unwrap();
        let ledger = store.load("2026-07-25").unwrap();
        assert_eq!(ledger.entries().len(), 1);
    }
}
