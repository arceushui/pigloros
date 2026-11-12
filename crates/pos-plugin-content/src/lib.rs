#![forbid(unsafe_code)]

//! Offline Plugin artifact content checks (ADR-061 R12, #574).
//!
//! The WIT preflight checks framing, safe paths and the exact declared world.
//! The complete checker also validates declared schemas, in-toto provenance,
//! SPDX references and licence texts, then binds evidence to the exact PMF1
//! and release digests. Neither seam verifies a publisher signature, grants
//! admission/launch authority or certifies Plugin safety or licensing.

mod bundle;
mod wit;

pub use bundle::{
    validate_plugin_bundle_content_v1, PluginBundleContentArtifactV1, PluginBundleContentErrorV1,
    ValidatedPluginBundleContentV1,
};
pub use wit::{validate_plugin_wit_v1, PluginWitContentErrorV1};
