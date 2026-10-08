#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! Registry-authorized Plugin release publication (ADR-061 revision 2).
//!
//! The publisher turns one typed release draft with an explicit validity
//! interval into a signed, self-verified OCI release in a Linux-local ADR-102
//! store. It reads no ambient clock. Local OCI publication is Linux-only, so
//! the whole crate is empty on other targets.
//!
//! Historical verification, installation and content validation are separate
//! slices; publication here never admits or installs a release.

#[cfg(target_os = "linux")]
mod publish;

#[cfg(target_os = "linux")]
pub use publish::{
    publish_plugin_release_v1, publish_signed_plugin_release_v1, sign_plugin_release_v1,
    PluginReleasePublishErrorV1, PluginReleaseSignatureV1, PublishedPluginReleaseV1,
};
