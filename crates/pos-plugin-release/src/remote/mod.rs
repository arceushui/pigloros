//! Bounded remote release sources (ADR-061 amendment revision 1).
//!
//! A private HTTP engine owns routing, redirects, deadlines, credentials and
//! byte bounds, behind one process-shared bounded resolver. Each public
//! source only locates immutable descriptors and finishes through the shared
//! manifest planner and OCI closure verifier, so it returns the same verified
//! bundle view as every other source. The HTTP and TLS libraries never appear
//! in this public interface.

mod challenge;
mod config;
mod engine;
mod https;
mod oci;
mod resolver;

pub use config::{
    CredentialProviderV1, CredentialV1, OriginV1, RemoteConfigErrorV1, RemoteTransportConfigV1,
    TransportDeadlinesV1, TrustRootsV1,
};
pub use https::HttpsReleaseSourceV1;
pub use oci::OciReleaseSourceV1;

/// The log targets the remote transport and its HTTP and TLS libraries emit.
///
/// The transport libraries log request URIs at DEBUG and raw traffic at
/// TRACE. A host that enables a remote source must cap these targets, and
/// every target below them, at INFO, even when global DEBUG or TRACE is
/// requested. A deployment that cannot enforce that ceiling must not enable
/// remote sources.
pub const TRANSPORT_LOG_TARGETS_V1: &[&str] =
    &["pos_plugin_release", "rustls", "ureq", "ureq_proto"];
