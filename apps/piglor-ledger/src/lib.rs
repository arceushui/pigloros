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

pub(crate) mod cli;
pub(crate) mod export;
pub mod hex;
pub(crate) mod html;
pub(crate) mod json;
pub(crate) mod key_output;
pub(crate) mod verify;

/// Test support utilities shared across crate boundaries.
pub mod test_helpers;

pub use cli::{open_store, run, today_utc, Source};
pub use export::{build as build_manifest, ExportManifest};
pub use html::{render_html, render_redirect, CONTENT_SECURITY_POLICY};
pub use json::render_json;
pub use pos_plugin_ledger::LedgerView;
pub use verify::run as verify_source;

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
}

impl From<pos_core::CoreError> for CliError {
    fn from(e: pos_core::CoreError) -> Self {
        Self::Store(e.to_string())
    }
}
