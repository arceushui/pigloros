#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! Bounded, source-neutral Plugin release transport and local OCI publication.
//!
//! This crate verifies and builds OCI transport closures only. It deliberately
//! does not parse PMF1 or make signing, trust-admission, installation, or
//! activation decisions.

mod build;
#[cfg(target_os = "linux")]
mod local;
mod oci;

use sha2::{Digest as _, Sha256};

const MAX_JCS_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

pub(crate) const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub(crate) const ARTIFACT_TYPE: &str = "application/vnd.pigloros.plugin.release.v1";
pub(crate) const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
pub(crate) const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
pub(crate) const EMPTY_CONFIG_BYTES: &[u8] = b"{}";
pub(crate) const PMF1_MEDIA_TYPE: &str = "application/vnd.pigloros.plugin.manifest.v1+cbor";
pub(crate) const COMPONENT_MEDIA_TYPE: &str = "application/vnd.pigloros.plugin.component.v1+wasm";
pub(crate) const WIT_MEDIA_TYPE: &str = "application/vnd.pigloros.plugin.wit.v1+tar";
pub(crate) const SCHEMA_MEDIA_TYPE: &str = "application/vnd.pigloros.plugin.schema.v1+json";
pub(crate) const PROVENANCE_MEDIA_TYPE: &str = "application/vnd.in-toto+json";
pub(crate) const SBOM_MEDIA_TYPE: &str = "application/spdx+json";
pub(crate) const LICENCE_MEDIA_TYPE: &str = "text/plain; charset=utf-8";
pub(crate) const MIGRATION_FIXTURE_MEDIA_TYPE: &str =
    "application/vnd.pigloros.plugin.migration-fixture.v1+cbor";

pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

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

/// What the installer did and did not check about the release content.
///
/// The enum is deliberately closed (no `#[non_exhaustive]`): content
/// validation (#574) replaces it in place in a coordinated breaking change,
/// since the product is unreleased. It lives here, next to the transport that
/// verifies the descriptor digests, so that the execution gate and the installer
/// share one fact without a dependency between them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentValidationV1 {
    /// Descriptor digests and bytes were verified; WIT, provenance, SBOM,
    /// licence, and schema content were not validated (follow-up #574).
    NotPerformed,
}

pub use build::{build_oci_closure_v1, ReleaseClosureInputV1};
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
