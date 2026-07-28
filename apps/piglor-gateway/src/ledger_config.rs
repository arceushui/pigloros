use crate::GatewayError;
use piglor_ledger::LedgerView;
use pos_plugin_ledger::{LedgerError, LedgerStore, NewPrediction, TomlLedgerStore};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

/// Shared handle for the mutable Prediction Ledger store.
pub(crate) type SharedLedgerStore = Arc<Mutex<Box<dyn LedgerStore + Send>>>;

/// Wraps a [`LedgerStore`] behind a mutex.
#[derive(Clone)]
pub struct LedgerGateway {
    store: SharedLedgerStore,
}

impl LedgerGateway {
    /// Wrap a boxed [`LedgerStore`] in a shared, locked handle.
    #[must_use]
    pub fn new(store: Box<dyn LedgerStore + Send>) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Register a prediction through the store, under lock.
    ///
    /// # Errors
    ///
    /// Returns a gateway error when the underlying ledger rejects the
    /// prediction.
    pub async fn register(&self, prediction: NewPrediction) -> Result<String, GatewayError> {
        let mut guard = self.store.lock().await;
        Ok(guard.register(prediction)?)
    }
}

/// Write-mode state machine for Prediction Ledger registration.
#[derive(Clone)]
pub enum LedgerWriteMode {
    /// Gate off — return 403.
    Disabled,
    /// Gate on but no adapter plugged in — return 503.
    Unconfigured,
    /// Gate on with a live adapter behind a mutex.
    Ready(LedgerGateway),
}

/// Startup configuration for the curated Prediction Ledger source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerConfig {
    source: Option<PathBuf>,
    write_enabled: bool,
}

impl LedgerConfig {
    /// Configure an optional TOML source directory and write feature gate.
    #[must_use]
    pub const fn new(source: Option<PathBuf>, write_enabled: bool) -> Self {
        Self {
            source,
            write_enabled,
        }
    }

    /// Load the configured Ledger view and construct its write mode.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the configured source cannot be read or
    /// parsed.
    pub fn load(self, today: &str) -> Result<(LedgerView, LedgerWriteMode), LedgerError> {
        let Some(source) = self.source else {
            let write_mode = if self.write_enabled {
                LedgerWriteMode::Unconfigured
            } else {
                LedgerWriteMode::Disabled
            };
            return Ok((LedgerView::default(), write_mode));
        };

        let store = TomlLedgerStore::new(&source);
        std::fs::read_dir(&source)
            .map_err(LedgerError::Io)
            .and_then(|_| store.load(today))
            .map(|ledger| {
                let write_mode = if self.write_enabled {
                    LedgerWriteMode::Ready(LedgerGateway::new(Box::new(store)))
                } else {
                    LedgerWriteMode::Disabled
                };
                (LedgerView::from(&ledger), write_mode)
            })
    }
}
