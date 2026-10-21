//! R7-F5: the total error and basis mapping of the execution-time trust gate (ADR-061
//! revision 7 decision 3), at the public seam.
//!
//! Every variant of every wrapped enum is listed once with the host error that decision 3
//! assigns to it. Completeness is enforced by the exhaustive matches of the mapping functions,
//! which have no wildcard arm: a variant added later fails to compile until it is mapped.
#![cfg(target_os = "linux")]

use pos_conformance::{PluginFloorErrorV1, PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_crypto::plugin_manifest::{PluginManifestErrorV1, PluginReleaseSignatureErrorV1};
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use pos_plugin_release::ReleaseSourceErrorV1;
use pos_runtime::community_plugin_host::{
    host_error_for_registry_v1, host_error_for_release_signature_v1,
    host_error_for_release_source_v1, host_error_for_trust_authorization_v1,
    host_error_for_trust_verification_v1,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1 as Reg;

#[path = "common/host_errors.rs"]
pub mod host_errors;

use host_errors::{
    Error as Host, ARTIFACT, EXPIRED, INVALID, KEY, MISMATCH, NOT_ACTIVE, OPERATOR, TSU, UNTRUSTED,
};

/// Assert every `(input, expected)` row, and that the rows list each of the `arms` variants of
/// the input enum exactly once. `index` is an exhaustive `match` over the enum, so a variant
/// added later fails to compile there, and a forgotten or duplicated row fails the count.
fn check<T: Copy + std::fmt::Debug>(
    rows: &[(T, Host)],
    map: fn(T) -> Host,
    index: fn(T) -> usize,
    arms: usize,
) {
    for (input, expected) in rows {
        assert_eq!(map(*input), *expected, "{input:?}");
    }
    let mut listed = rows
        .iter()
        .map(|(input, _)| index(*input))
        .collect::<Vec<_>>();
    listed.sort_unstable();
    assert_eq!(listed, (0..arms).collect::<Vec<_>>());
}

const fn source_index(error: ReleaseSourceErrorV1) -> usize {
    match error {
        ReleaseSourceErrorV1::InvalidAddress => 0,
        ReleaseSourceErrorV1::NotFound => 1,
        ReleaseSourceErrorV1::BoundsExceeded => 2,
        ReleaseSourceErrorV1::InvalidLayout => 3,
        ReleaseSourceErrorV1::InvalidDescriptor => 4,
        ReleaseSourceErrorV1::DigestMismatch => 5,
        ReleaseSourceErrorV1::SizeMismatch => 6,
        ReleaseSourceErrorV1::DuplicateMember => 7,
        ReleaseSourceErrorV1::UnsupportedMediaType => 8,
        ReleaseSourceErrorV1::Uncommitted => 9,
        ReleaseSourceErrorV1::Io => 10,
        ReleaseSourceErrorV1::LockUnavailable => 11,
        ReleaseSourceErrorV1::RecoveryRequired => 12,
    }
}

const fn trust_ix(error: PluginTrustErrorV1) -> usize {
    match error {
        PluginTrustErrorV1::InvalidEncoding => 0,
        PluginTrustErrorV1::BoundsExceeded => 1,
        PluginTrustErrorV1::InvalidSignature => 2,
        PluginTrustErrorV1::UnknownRootKey => 3,
        PluginTrustErrorV1::ThresholdNotMet => 4,
        PluginTrustErrorV1::AnchorMismatch => 5,
        PluginTrustErrorV1::ChainDiscontinuity => 6,
        PluginTrustErrorV1::DigestMismatch => 7,
        PluginTrustErrorV1::Expired => 8,
        PluginTrustErrorV1::RootHistoryCapacityExceeded => 9,
        PluginTrustErrorV1::RevocationHistoryCapacityExceeded => 10,
        PluginTrustErrorV1::RevocationCapacityExhausted => 11,
        PluginTrustErrorV1::IncompleteManifestProjection => 12,
        PluginTrustErrorV1::ManifestExpired => 13,
        PluginTrustErrorV1::UnknownPublisherKey => 14,
        PluginTrustErrorV1::PluginIdNotGranted => 15,
        PluginTrustErrorV1::PublisherKeyRevoked => 16,
        PluginTrustErrorV1::ArtifactRevoked => 17,
    }
}

const fn sig_ix(error: PluginReleaseSignatureErrorV1) -> usize {
    match error {
        PluginReleaseSignatureErrorV1::Manifest(_) => 0,
        PluginReleaseSignatureErrorV1::AuthorizationMismatch => 1,
        PluginReleaseSignatureErrorV1::InvalidSignature => 2,
    }
}

const fn bridge_index(error: PluginTrustBridgeErrorV1) -> usize {
    match error {
        PluginTrustBridgeErrorV1::InvalidAnchorScope => 0,
        PluginTrustBridgeErrorV1::InvalidAnchorRole => 1,
        PluginTrustBridgeErrorV1::InvalidAnchorOperatorKey => 2,
        PluginTrustBridgeErrorV1::InvalidSnapshot => 3,
        PluginTrustBridgeErrorV1::InvalidOperatorSignature => 4,
        PluginTrustBridgeErrorV1::ScopeMismatch => 5,
        PluginTrustBridgeErrorV1::EpochMismatch => 6,
        PluginTrustBridgeErrorV1::EvaluationUtcMismatch => 7,
        PluginTrustBridgeErrorV1::EvaluationTickMismatch => 8,
        PluginTrustBridgeErrorV1::InvalidUtcFormat => 9,
        PluginTrustBridgeErrorV1::Expired => 10,
        PluginTrustBridgeErrorV1::BridgeRootMismatch => 11,
        PluginTrustBridgeErrorV1::BridgeRevocationMismatch => 12,
        PluginTrustBridgeErrorV1::ReservedPrefix => 13,
        PluginTrustBridgeErrorV1::TpsCapExceeded => 14,
        PluginTrustBridgeErrorV1::InvalidGenesis => 15,
        PluginTrustBridgeErrorV1::StaleSnapshot => 16,
        PluginTrustBridgeErrorV1::SnapshotDiscontinuity => 17,
        PluginTrustBridgeErrorV1::TpsArtifactDenied => 18,
    }
}

const fn kind_index(kind: PluginFloorKindV1) -> usize {
    match kind {
        PluginFloorKindV1::Root => 0,
        PluginFloorKindV1::Revocation => 1,
    }
}

const fn floor_index(error: PluginFloorErrorV1) -> usize {
    match error {
        PluginFloorErrorV1::PartialFloorState => 0,
        PluginFloorErrorV1::Rollback(kind) => 1 + kind_index(kind),
        PluginFloorErrorV1::Fork(kind) => 3 + kind_index(kind),
        PluginFloorErrorV1::Discontinuity(kind) => 5 + kind_index(kind),
    }
}

const fn registry_index(error: Reg) -> usize {
    match error {
        Reg::MissingState => 0,
        Reg::CorruptState => 1,
        Reg::AnchorMismatch => 2,
        Reg::TrustedTimeUnavailable => 3,
        Reg::TrustedTimeRegressed => 4,
        Reg::ReleaseChainViolation => 5,
        Reg::ReleaseConflict => 6,
        Reg::UnknownRollbackTarget => 7,
        Reg::NoActiveRelease => 8,
        Reg::RollbackTargetActive => 9,
        Reg::ActivationEventRejected => 10,
        Reg::NestedTransaction => 11,
        Reg::WalRequired => 12,
        Reg::StorageBusy => 13,
        Reg::StorageFailed => 14,
        Reg::StorageIndeterminate => 15,
        Reg::StorePoisoned => 16,
        Reg::PolicyNotAdvanced => 17,
        Reg::ReleaseNotActive => 18,
        Reg::Bridge(_) => 19,
        Reg::Floor(_) => 20,
        Reg::Trust(_) => 21,
    }
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
    check(&rows, host_error_for_release_source_v1, source_index, 13);
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
    check(&rows, host_error_for_trust_verification_v1, trust_ix, 18);
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
    check(&rows, host_error_for_trust_authorization_v1, trust_ix, 18);
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
    check(&rows, host_error_for_release_signature_v1, sig_ix, 3);
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
        // One representative of each wrapper; the wrapped variants have their own tests below.
        (
            Reg::Bridge(PluginTrustBridgeErrorV1::InvalidSnapshot),
            UNTRUSTED,
        ),
        (Reg::Floor(PluginFloorErrorV1::PartialFloorState), TSU),
        (Reg::Trust(PluginTrustErrorV1::ManifestExpired), EXPIRED),
    ];
    check(&rows, host_error_for_registry_v1, registry_index, 22);
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
    check(
        &rows,
        |inner| host_error_for_registry_v1(Reg::Bridge(inner)),
        bridge_index,
        19,
    );
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
    check(
        &rows,
        |inner| host_error_for_registry_v1(Reg::Floor(inner)),
        floor_index,
        7,
    );
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
    let rows = variants.map(|variant| (variant, host_error_for_trust_authorization_v1(variant)));
    check(
        &rows,
        |inner| host_error_for_registry_v1(Reg::Trust(inner)),
        trust_ix,
        18,
    );
}
