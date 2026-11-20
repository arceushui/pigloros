#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! `piglor-ledger` — Prediction Ledger CLI + static HTML renderer
//! (ADR-017 / Redmine #110).
//!
//! The binary (`src/main.rs`) is a thin dispatcher.  All renderer and CLI
//! logic lives here so downstream crates (#111 gateway, #113 close-out)
//! can depend on the library directly.

macro_rules! output_stdout {
    ($($arg:tt)*) => {{
        let mut output = std::io::stdout().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

macro_rules! output_stderr {
    ($($arg:tt)*) => {{
        let mut output = std::io::stderr().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

pub(crate) mod cli;
pub(crate) mod export;
pub mod hex;
mod host_store;
pub(crate) mod html;
pub(crate) mod json;
pub mod key_output;
pub(crate) mod verify;

use pos_local_erasure_loader::{
    LocalErasureOpenErrorV1, LocalErasureRecoveryV1, LocalErasureTrustSourceV1,
};

/// Private compatibility adapter for the ledger domain port.
///
/// The concrete store never escapes the execution host. Every implemented
/// `EventStore` operation delegates to a generation-bound host sender; all
/// other trait operations retain their fail-closed defaults.
struct HostedLedgerStore {
    host: std::sync::Mutex<pos_runtime::ErasureExecutionHostV1>,
    ledger_timeline: Option<pos_core::TimelineId>,
}

impl HostedLedgerStore {
    /// Open `config` under the erasure authority the shared loader composes
    /// from this process's deployment trust source.
    fn open(config: pos_store::StoreConfig) -> Result<Self, LocalErasureOpenErrorV1> {
        Self::open_with_trust(config, &LocalErasureTrustSourceV1::from_environment())
    }

    /// Open `config` under the erasure authority composed from `source`:
    /// closed for a store without an erasure store identity, else the Local
    /// erasure authority with no executor, or a typed refusal.
    fn open_with_trust(
        config: pos_store::StoreConfig,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<Self, LocalErasureOpenErrorV1> {
        LocalErasureRecoveryV1::open_host(config, source).map(Self::from_host)
    }

    /// [`Self::open`] over the `SQLite` file `path`, read-only.
    fn open_read_only(path: &str) -> Result<Self, LocalErasureOpenErrorV1> {
        Self::open_read_only_with_trust(path, &LocalErasureTrustSourceV1::from_environment())
    }

    /// [`Self::open_with_trust`] over the `SQLite` file `path`, read-only.
    fn open_read_only_with_trust(
        path: &str,
        source: &LocalErasureTrustSourceV1,
    ) -> Result<Self, LocalErasureOpenErrorV1> {
        LocalErasureRecoveryV1::open_read_only_host(path, source).map(Self::from_host)
    }

    const fn from_host(host: pos_runtime::ErasureExecutionHostV1) -> Self {
        Self {
            host: std::sync::Mutex::new(host),
            ledger_timeline: None,
        }
    }
}

/// Test support utilities shared across crate boundaries.
pub mod test_helpers;

pub use cli::{open_store, run, today_utc, Source};
pub use export::{build as build_manifest, ExportManifest};
pub use html::{render_html, render_redirect, CONTENT_SECURITY_POLICY};
pub use json::render_json;
pub use pos_plugin_ledger::LedgerView;
pub use verify::run as verify_source;

/// Bind the permissive host gate used by this crate's in-process store tests.
///
/// Production composition roots must install their authoritative recovered
/// gate; test fixtures use an empty gate so they can exercise ledger behavior
/// without fabricating erasure evidence.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn bind_test_store_gate(
    mut store: Box<dyn pos_core::store::EventStore>,
) -> Result<Box<dyn pos_core::store::EventStore>, pos_core::CoreError> {
    store.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    Ok(store)
}

/// Return the committed author identity used for ledger Events.
#[must_use]
pub(crate) fn well_known_entity() -> pos_core::ids::EntityId {
    const LEDGER_ENTITY_ULID: &str = "01J3B0Y5ZK2J6MGK8D7QW3N0A0";
    pos_core::ids::EntityId::from_ulid(
        ulid::Ulid::from_string(LEDGER_ENTITY_ULID).unwrap_or_else(|_| ulid::Ulid::nil()),
    )
}

/// Encode bytes as lowercase hex.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Errors surfaced by the CLI.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Bad `--source` argument.
    #[error("invalid --source: {0}")]
    BadSource(String),
    /// Bad `--key` argument (missing or unreadable).
    #[error("invalid --key: {0}")]
    BadKey(String),
    /// Secret-key output was structurally unsafe.
    #[error("refusing secret-key output {path}: {reason}; {cleanup}")]
    UnsafeKeyOutput {
        /// Output path.
        path: String,
        /// Safety rule that was violated.
        reason: String,
        /// Cleanup state and retry guidance.
        cleanup: String,
    },
    /// Secret-key output failed during an I/O operation.
    #[error("failed to {action} secret-key output {path}: {source}; {cleanup}")]
    KeyOutputIo {
        /// Operation that failed.
        action: &'static str,
        /// Output path.
        path: String,
        /// Original I/O failure.
        #[source]
        source: std::io::Error,
        /// Cleanup state and retry guidance.
        cleanup: String,
    },
    /// The platform cannot enforce the required key-file protection.
    #[error(
        "secret-key output {path} is unsupported on this platform: keygen requires Unix owner-only file modes"
    )]
    UnsupportedKeyOutput {
        /// Output path.
        path: String,
    },
    /// File I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialisation failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Underlying ledger port error.
    #[error(transparent)]
    Ledger(#[from] pos_plugin_ledger::LedgerError),
    /// Event-store backend error (e.g. corrupt DB, I/O failure during
    /// timeline ops).
    #[error("store error: {0}")]
    Store(String),
    /// Verification completed and found a mismatch.
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

impl From<pos_core::CoreError> for CliError {
    fn from(e: pos_core::CoreError) -> Self {
        Self::Store(e.to_string())
    }
}

// Test-only. The shared Local erasure signing fixtures and the key-less root
// store fixture of ADR-136 acceptance test 11 (#1450); the items are `pub`
// so this crate may use a subset.
#[cfg(target_os = "linux")]
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../../../crates/pos-local-erasure-loader/tests/support/signing.rs"]
pub mod signing;

#[cfg(target_os = "linux")]
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../../piglor-gateway/tests/support/keyless_store.rs"]
pub mod keyless_store;

/// ADR-136 acceptance test 11 for the ledger root (#1450): its read-write
/// and read-only opens compose the closed authority for a store without an
/// erasure store identity, recover a store that holds a Local erasure
/// request from valid credentials, and refuse missing or invalid ones.
#[cfg(target_os = "linux")]
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod keyless_erasure_tests {
    use pos_core::store::EventStore;
    use pos_local_erasure_loader::{
        LocalErasureLoadErrorV1, LocalErasureOpenErrorV1, LocalErasureTrustSourceV1,
    };
    use pos_runtime::LocalErasureCompositionErrorV1;
    use pos_store::StoreConfig;

    use super::keyless_store::KeylessStore;
    use super::signing::TestResult;
    use super::HostedLedgerStore;

    /// The refusals of the read-write and the read-only open of `store`
    /// from `source`.
    fn refusals(
        store: &KeylessStore,
        source: &LocalErasureTrustSourceV1,
    ) -> [Option<LocalErasureOpenErrorV1>; 2] {
        [
            HostedLedgerStore::open_with_trust(store.config(), source).err(),
            HostedLedgerStore::open_read_only_with_trust(&store.path, source).err(),
        ]
    }

    #[test]
    fn a_store_without_an_identity_opens_and_works() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("ledger.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let source = LocalErasureTrustSourceV1 {
            credential_directory: None,
            trust_state: directory.path().join("absent-trust.db"),
        };
        let mut store = HostedLedgerStore::open_with_trust(
            StoreConfig::Sqlite { path: path.clone() },
            &source,
        )?;
        let timeline = store.create_timeline("ledger")?;
        drop(store);
        let read_only = HostedLedgerStore::open_read_only_with_trust(&path, &source)?;
        assert_eq!(
            read_only
                .get_timeline(timeline.id())?
                .map(|found| found.id()),
            Some(timeline.id())
        );
        Ok(())
    }

    #[test]
    fn valid_credentials_recover_a_store_that_holds_a_request() -> TestResult {
        let store = KeylessStore::new()?;
        let source = store.valid_source("valid")?;
        let recovered = HostedLedgerStore::open_with_trust(store.config(), &source)?;
        let timelines = recovered.list_timelines()?.len();
        assert!(timelines > 0);
        drop(recovered);
        let read_only = HostedLedgerStore::open_read_only_with_trust(&store.path, &source)?;
        assert_eq!(read_only.list_timelines()?.len(), timelines);
        Ok(())
    }

    #[test]
    fn missing_credentials_are_a_typed_refusal() -> TestResult {
        let store = KeylessStore::new()?;
        let missing = Some(LocalErasureOpenErrorV1::Load(
            LocalErasureLoadErrorV1::CredentialsMissing,
        ));
        assert_eq!(
            refusals(&store, &store.missing_source()),
            [missing, missing]
        );
        Ok(())
    }

    #[test]
    fn an_invalid_bundle_or_signature_is_a_typed_refusal() -> TestResult {
        let store = KeylessStore::new()?;
        let invalid = Some(LocalErasureOpenErrorV1::Load(
            LocalErasureLoadErrorV1::Composition(LocalErasureCompositionErrorV1::BundleInvalid),
        ));
        for source in [
            store.invalid_bundle_source("invalid-bundle")?,
            store.forged_signature_source("forged-signature")?,
        ] {
            assert_eq!(refusals(&store, &source), [invalid, invalid]);
        }
        Ok(())
    }
}
