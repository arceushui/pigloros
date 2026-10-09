//! R7-F5: the total error and basis mapping of the execution-time trust gate (ADR-061
//! revision 7 decision 3), at the public seam.
//!
//! Every variant of every wrapped enum is listed once with the host error that decision 3
//! assigns to it. The functions have no wildcard arm, so a variant added later fails to compile
//! until it is mapped, and the row counts below fail until it is listed here.
#![cfg(target_os = "linux")]

use pos_conformance::{PluginFloorErrorV1, PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_crypto::plugin_manifest::{PluginManifestErrorV1, PluginReleaseSignatureErrorV1};
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use pos_plugin_release::ReleaseSourceErrorV1;
use pos_runtime::community_plugin_host::{
    host_error_for_registry_v1, host_error_for_release_signature_v1,
    host_error_for_release_source_v1, host_error_for_trust_authorization_v1,
    host_error_for_trust_verification_v1, CommunityPluginHostErrorV1, RevocationBasisV1,
    TrustDenialBasisV1,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1 as Reg;

type Host = CommunityPluginHostErrorV1;

const fn denied(basis: TrustDenialBasisV1) -> Host {
    Host::ArtifactTrustDenied { basis }
}

const fn revoked(basis: RevocationBasisV1) -> Host {
    Host::ArtifactRevoked { basis }
}

const EXPIRED: Host = denied(TrustDenialBasisV1::Expired);
const NOT_ACTIVE: Host = denied(TrustDenialBasisV1::NotActive);
const UNTRUSTED: Host = denied(TrustDenialBasisV1::Untrusted);
const MISMATCH: Host = denied(TrustDenialBasisV1::PolicyMismatch);
const TSU: Host = denied(TrustDenialBasisV1::TrustStateUnavailable);
const KEY: Host = revoked(RevocationBasisV1::PublisherKey);
const ARTIFACT: Host = revoked(RevocationBasisV1::Artifact);
const OPERATOR: Host = revoked(RevocationBasisV1::OperatorDenial);
const INVALID: Host = Host::InvalidManifest;

/// Assert every `(input, expected)` row and return how many rows there were.
fn check<T: Copy + std::fmt::Debug>(rows: &[(T, Host)], map: fn(T) -> Host) -> usize {
    for (input, expected) in rows {
        assert_eq!(map(*input), *expected, "{input:?}");
    }
    rows.len()
}

#[test]
fn release_source_errors_map_to_unavailable_or_invalid_manifest() {
    use ReleaseSourceErrorV1 as S;
    let rows = [
        (S::InvalidAddress, TSU),
        (S::NotFound, TSU),
        (S::Uncommitted, TSU),
        (S::Io, TSU),
        (S::LockUnavailable, TSU),
        (S::RecoveryRequired, TSU),
        (S::BoundsExceeded, INVALID),
        (S::InvalidLayout, INVALID),
        (S::InvalidDescriptor, INVALID),
        (S::DigestMismatch, INVALID),
        (S::SizeMismatch, INVALID),
        (S::DuplicateMember, INVALID),
        (S::UnsupportedMediaType, INVALID),
    ];
    assert_eq!(check(&rows, host_error_for_release_source_v1), 13);
}

#[test]
fn verifier_errors_map_by_whether_the_material_verifies() {
    use PluginTrustErrorV1 as T;
    let rows = [
        (T::Expired, EXPIRED),
        (T::RootHistoryCapacityExceeded, TSU),
        (T::RevocationHistoryCapacityExceeded, TSU),
        (T::RevocationCapacityExhausted, TSU),
        (T::InvalidEncoding, UNTRUSTED),
        (T::BoundsExceeded, UNTRUSTED),
        (T::InvalidSignature, UNTRUSTED),
        (T::UnknownRootKey, UNTRUSTED),
        (T::ThresholdNotMet, UNTRUSTED),
        (T::AnchorMismatch, UNTRUSTED),
        (T::ChainDiscontinuity, UNTRUSTED),
        (T::DigestMismatch, UNTRUSTED),
        // Only `authorize_release` raises these; defensively unavailable.
        (T::IncompleteManifestProjection, TSU),
        (T::ManifestExpired, TSU),
        (T::UnknownPublisherKey, TSU),
        (T::PluginIdNotGranted, TSU),
        (T::PublisherKeyRevoked, TSU),
        (T::ArtifactRevoked, TSU),
    ];
    assert_eq!(check(&rows, host_error_for_trust_verification_v1), 18);
}

#[test]
fn authorization_errors_map_with_the_registry_trust_rows() {
    use PluginTrustErrorV1 as T;
    let rows = [
        (T::ManifestExpired, EXPIRED),
        (T::UnknownPublisherKey, UNTRUSTED),
        (T::PluginIdNotGranted, UNTRUSTED),
        (T::PublisherKeyRevoked, KEY),
        (T::ArtifactRevoked, ARTIFACT),
        (T::RevocationCapacityExhausted, TSU),
        (T::IncompleteManifestProjection, TSU),
        (T::InvalidEncoding, TSU),
        (T::BoundsExceeded, TSU),
        (T::InvalidSignature, TSU),
        (T::UnknownRootKey, TSU),
        (T::ThresholdNotMet, TSU),
        (T::AnchorMismatch, TSU),
        (T::ChainDiscontinuity, TSU),
        (T::DigestMismatch, TSU),
        (T::Expired, TSU),
        (T::RootHistoryCapacityExceeded, TSU),
        (T::RevocationHistoryCapacityExceeded, TSU),
    ];
    assert_eq!(check(&rows, host_error_for_trust_authorization_v1), 18);
}

#[test]
fn signature_errors_map_to_untrusted_or_invalid_manifest() {
    use PluginReleaseSignatureErrorV1 as G;
    let manifest = PluginManifestErrorV1::ReleaseDigestMismatch;
    let rows = [
        (G::InvalidSignature, UNTRUSTED),
        (G::AuthorizationMismatch, INVALID),
        (G::Manifest(manifest), INVALID),
    ];
    assert_eq!(check(&rows, host_error_for_release_signature_v1), 3);
}

#[test]
fn registry_errors_map_row_by_row() {
    let rows = [
        (Reg::ReleaseNotActive, NOT_ACTIVE),
        (Reg::PolicyNotAdvanced, MISMATCH),
        (Reg::AnchorMismatch, MISMATCH),
        (Reg::TrustedTimeRegressed, TSU),
        (Reg::StorePoisoned, TSU),
        (Reg::StorageFailed, TSU),
        (Reg::StorageBusy, TSU),
        (Reg::MissingState, TSU),
        (Reg::CorruptState, TSU),
        (Reg::TrustedTimeUnavailable, TSU),
        (Reg::ReleaseChainViolation, TSU),
        (Reg::ReleaseConflict, TSU),
        (Reg::UnknownRollbackTarget, TSU),
        (Reg::NoActiveRelease, TSU),
        (Reg::RollbackTargetActive, TSU),
        (Reg::ActivationEventRejected, TSU),
        (Reg::NestedTransaction, TSU),
        (Reg::WalRequired, TSU),
        (Reg::StorageIndeterminate, TSU),
    ];
    assert_eq!(check(&rows, host_error_for_registry_v1), 19);
}

#[test]
fn registry_bridge_errors_map_row_by_row() {
    use PluginTrustBridgeErrorV1 as B;
    let rows = [
        (B::InvalidSnapshot, UNTRUSTED),
        (B::InvalidOperatorSignature, UNTRUSTED),
        (B::ScopeMismatch, MISMATCH),
        (B::EpochMismatch, MISMATCH),
        (B::InvalidUtcFormat, MISMATCH),
        (B::BridgeRootMismatch, MISMATCH),
        (B::BridgeRevocationMismatch, MISMATCH),
        (B::ReservedPrefix, MISMATCH),
        (B::StaleSnapshot, MISMATCH),
        (B::SnapshotDiscontinuity, MISMATCH),
        (B::Expired, EXPIRED),
        (B::TpsArtifactDenied, OPERATOR),
        (B::InvalidAnchorScope, TSU),
        (B::InvalidAnchorRole, TSU),
        (B::InvalidAnchorOperatorKey, TSU),
        (B::EvaluationUtcMismatch, TSU),
        (B::EvaluationTickMismatch, TSU),
        (B::InvalidGenesis, TSU),
        (B::TpsCapExceeded, TSU),
    ];
    let wrapped = rows.map(|(inner, expected)| (Reg::Bridge(inner), expected));
    assert_eq!(check(&wrapped, host_error_for_registry_v1), 19);
}

#[test]
fn registry_floor_errors_map_row_by_row() {
    use PluginFloorKindV1 as K;
    let kinds = [K::Root, K::Revocation];
    let mut rows = vec![(PluginFloorErrorV1::PartialFloorState, TSU)];
    for kind in kinds {
        rows.push((PluginFloorErrorV1::Rollback(kind), MISMATCH));
        rows.push((PluginFloorErrorV1::Fork(kind), MISMATCH));
        rows.push((PluginFloorErrorV1::Discontinuity(kind), MISMATCH));
    }
    let wrapped = rows
        .into_iter()
        .map(|(inner, expected)| (Reg::Floor(inner), expected))
        .collect::<Vec<_>>();
    assert_eq!(check(&wrapped, host_error_for_registry_v1), 7);
}

#[test]
fn registry_trust_errors_use_the_authorization_rows() {
    use PluginTrustErrorV1 as T;
    let variants = [
        T::InvalidEncoding,
        T::BoundsExceeded,
        T::InvalidSignature,
        T::UnknownRootKey,
        T::ThresholdNotMet,
        T::AnchorMismatch,
        T::ChainDiscontinuity,
        T::DigestMismatch,
        T::Expired,
        T::RootHistoryCapacityExceeded,
        T::RevocationHistoryCapacityExceeded,
        T::RevocationCapacityExhausted,
        T::IncompleteManifestProjection,
        T::ManifestExpired,
        T::UnknownPublisherKey,
        T::PluginIdNotGranted,
        T::PublisherKeyRevoked,
        T::ArtifactRevoked,
    ];
    assert_eq!(variants.len(), 18);
    for variant in variants {
        assert_eq!(
            host_error_for_registry_v1(Reg::Trust(variant)),
            host_error_for_trust_authorization_v1(variant),
            "{variant:?}"
        );
    }
}
