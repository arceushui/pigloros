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

const MAX_JCS_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Parse bounded canonical JSON shared by private transport adapters.
fn parse_jcs_object(bytes: &[u8]) -> Result<serde_json::Value, ReleaseSourceErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_JCS_BYTES {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    // serde_json bounds recursive descent. Its Value representation contains
    // unique keys, so exact canonical reserialization also rejects duplicate
    // keys (including escaped aliases), whitespace and alternate encodings.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ReleaseSourceErrorV1::InvalidDescriptor)?;
    if value.to_string().as_bytes() != bytes {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    Ok(value)
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
