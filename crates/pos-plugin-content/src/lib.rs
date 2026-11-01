#![forbid(unsafe_code)]

//! Offline Plugin artifact content checks (ADR-061 R12, #574).
//!
//! The WIT preflight checks an archive's framing, safe paths, package syntax
//! and exact declared world entirely in memory. It does not verify a release
//! signature, authorize a publisher or claim that the whole bundle passed
//! content validation.

mod wit;

pub use wit::{validate_plugin_wit_v1, PluginWitContentErrorV1};
