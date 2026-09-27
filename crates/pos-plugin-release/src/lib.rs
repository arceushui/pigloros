#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! Bounded, source-neutral Plugin release transport and local OCI publication.
//!
//! This crate verifies OCI transport closure only. It deliberately does not
//! parse PMF1 or make signing, trust-admission, installation, or activation
//! decisions.

#[cfg(target_os = "linux")]
mod local;
mod oci;

/// Parse bounded canonical JSON shared by private transport adapters.
fn parse_jcs_object(bytes: &[u8]) -> Result<serde_json::Value, ReleaseSourceErrorV1> {
    oci::parse_jcs_object(bytes)
}

#[cfg(target_os = "linux")]
pub use local::PublishOutcomeV1;
#[cfg(target_os = "linux")]
pub use local::RecoveryOutcomeV1;
#[cfg(target_os = "linux")]
pub use local::RecoveryReportV1;
#[cfg(target_os = "linux")]
pub use local::{LocalOciPublicationErrorV1, LocalOciPublisherV1};
pub use oci::{
    verify_oci_closure_v1, BlobV1, BundleAddressV1, BundleMemberV1, ReleaseSourceErrorV1,
    ReleaseSourceV1, VerifiedReleaseBundleV1,
};
