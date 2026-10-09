//! The host errors of the gate vectors, shared by the gate and mapping tests.

use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, RevocationBasisV1, TrustDenialBasisV1,
};

/// The closed community Plugin host error.
pub type Error = CommunityPluginHostErrorV1;

/// `ArtifactTrustDenied` with `basis`.
#[must_use]
pub const fn denied(basis: TrustDenialBasisV1) -> Error {
    Error::ArtifactTrustDenied { basis }
}

/// `ArtifactRevoked` with `basis`.
#[must_use]
pub const fn revoked(basis: RevocationBasisV1) -> Error {
    Error::ArtifactRevoked { basis }
}

pub const EXPIRED: Error = denied(TrustDenialBasisV1::Expired);
pub const NOT_ACTIVE: Error = denied(TrustDenialBasisV1::NotActive);
pub const UNTRUSTED: Error = denied(TrustDenialBasisV1::Untrusted);
pub const MISMATCH: Error = denied(TrustDenialBasisV1::PolicyMismatch);
/// `ArtifactTrustDenied{TrustStateUnavailable}`.
pub const TSU: Error = denied(TrustDenialBasisV1::TrustStateUnavailable);
pub const KEY: Error = revoked(RevocationBasisV1::PublisherKey);
pub const ARTIFACT: Error = revoked(RevocationBasisV1::Artifact);
pub const OPERATOR: Error = revoked(RevocationBasisV1::OperatorDenial);
pub const INVALID: Error = Error::InvalidManifest;
