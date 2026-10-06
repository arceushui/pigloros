#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-crypto` — canonical CBOR encoding, BLAKE3 hash chain, Ed25519 sign/verify.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod canonical;
pub mod chain;
pub mod fork_attribution;
pub mod fork_attribution_authority;
pub mod fork_authentication;
pub mod key_roles;
pub mod plugin_execution;
pub mod plugin_manifest;
pub mod plugin_trust;
pub mod plugin_worker_ipc;
pub mod recipient_export;
pub mod recipient_key;
pub mod signing;
// Public module reachability keeps the crate-only strict CBOR reader shared by
// PTR1, PRV1, PMF1 and the worker IPC envelopes compatible with both
// `unreachable_pub` and Clippy's `redundant_pub_crate` lint.
#[doc(hidden)]
pub mod strict_cbor;
pub mod timeline_erasure;
