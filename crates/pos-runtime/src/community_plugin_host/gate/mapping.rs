//! The total error and basis mapping of the execution-time trust gate (ADR-061 revision 7
//! decision 3).
//!
//! Every input variant has exactly one row and no wildcard arm exists, so a variant added to a
//! wrapped enum fails to compile until it is mapped. The rule the rows implement: material that
//! does not verify is `Untrusted`; material that verifies but differs from the retained state is
//! `PolicyMismatch`; an unreadable or unusable state is `TrustStateUnavailable`; a time outside a
//! validity window is `Expired`.

use pos_conformance::{PluginFloorErrorV1, PluginTrustBridgeErrorV1};
use pos_crypto::plugin_manifest::PluginReleaseSignatureErrorV1;
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use pos_plugin_release::ReleaseSourceErrorV1;
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1;

use crate::community_plugin_host::error::{
    CommunityPluginHostErrorV1, RevocationBasisV1, TrustDenialBasisV1,
};

const fn denied(basis: TrustDenialBasisV1) -> CommunityPluginHostErrorV1 {
    CommunityPluginHostErrorV1::ArtifactTrustDenied { basis }
}

const fn revoked(basis: RevocationBasisV1) -> CommunityPluginHostErrorV1 {
    CommunityPluginHostErrorV1::ArtifactRevoked { basis }
}

/// `ArtifactTrustDenied{TrustStateUnavailable}`, the answer for a missing or unusable trust
/// state.
pub(super) const TRUST_STATE_UNAVAILABLE: CommunityPluginHostErrorV1 =
    denied(TrustDenialBasisV1::TrustStateUnavailable);

/// `ArtifactTrustDenied{NotActive}`, the answer for an address that does not hold the member's
/// release.
pub(super) const NOT_ACTIVE: CommunityPluginHostErrorV1 = denied(TrustDenialBasisV1::NotActive);

/// The host error of a release source failure.
///
/// Public so that the R7-F5 public vector can enumerate every input variant; the gate is the
/// only production caller.
///
/// A source that could not produce a closure is `TrustStateUnavailable`; a closure that was
/// produced but is malformed is `InvalidManifest`.
#[must_use]
pub const fn host_error_for_release_source_v1(
    error: ReleaseSourceErrorV1,
) -> CommunityPluginHostErrorV1 {
    match error {
        ReleaseSourceErrorV1::InvalidAddress
        | ReleaseSourceErrorV1::NotFound
        | ReleaseSourceErrorV1::Uncommitted
        | ReleaseSourceErrorV1::Io
        | ReleaseSourceErrorV1::LockUnavailable
        | ReleaseSourceErrorV1::RecoveryRequired => TRUST_STATE_UNAVAILABLE,
        ReleaseSourceErrorV1::BoundsExceeded
        | ReleaseSourceErrorV1::InvalidLayout
        | ReleaseSourceErrorV1::InvalidDescriptor
        | ReleaseSourceErrorV1::DigestMismatch
        | ReleaseSourceErrorV1::SizeMismatch
        | ReleaseSourceErrorV1::DuplicateMember
        | ReleaseSourceErrorV1::UnsupportedMediaType => CommunityPluginHostErrorV1::InvalidManifest,
    }
}

/// The host error of a failed `verify_plugin_trust_v1` (gate step 5).
///
/// Public for the R7-F5 public vector; the gate is the only production caller.
///
/// The variants that only `authorize_release` raises are unreachable from the verifier and map
/// defensively to `TrustStateUnavailable`.
#[must_use]
pub const fn host_error_for_trust_verification_v1(
    error: PluginTrustErrorV1,
) -> CommunityPluginHostErrorV1 {
    match error {
        PluginTrustErrorV1::Expired => denied(TrustDenialBasisV1::Expired),
        PluginTrustErrorV1::InvalidEncoding
        | PluginTrustErrorV1::BoundsExceeded
        | PluginTrustErrorV1::InvalidSignature
        | PluginTrustErrorV1::UnknownRootKey
        | PluginTrustErrorV1::ThresholdNotMet
        | PluginTrustErrorV1::AnchorMismatch
        | PluginTrustErrorV1::ChainDiscontinuity
        | PluginTrustErrorV1::DigestMismatch => denied(TrustDenialBasisV1::Untrusted),
        PluginTrustErrorV1::RootHistoryCapacityExceeded
        | PluginTrustErrorV1::RevocationHistoryCapacityExceeded
        | PluginTrustErrorV1::RevocationCapacityExhausted
        | PluginTrustErrorV1::IncompleteManifestProjection
        | PluginTrustErrorV1::ManifestExpired
        | PluginTrustErrorV1::UnknownPublisherKey
        | PluginTrustErrorV1::PluginIdNotGranted
        | PluginTrustErrorV1::PublisherKeyRevoked
        | PluginTrustErrorV1::ArtifactRevoked => TRUST_STATE_UNAVAILABLE,
    }
}

/// The host error of a failed `authorize_release`, as the registry wraps it in `Trust(..)` and
/// as the gate's own direct call raises it (gate step 7).
///
/// Public for the R7-F5 public vector; the gate is the only production caller.
///
/// Every variant without a row of its own is `TrustStateUnavailable`.
#[must_use]
pub const fn host_error_for_trust_authorization_v1(
    error: PluginTrustErrorV1,
) -> CommunityPluginHostErrorV1 {
    match error {
        PluginTrustErrorV1::ManifestExpired => denied(TrustDenialBasisV1::Expired),
        PluginTrustErrorV1::UnknownPublisherKey | PluginTrustErrorV1::PluginIdNotGranted => {
            denied(TrustDenialBasisV1::Untrusted)
        }
        PluginTrustErrorV1::PublisherKeyRevoked => revoked(RevocationBasisV1::PublisherKey),
        PluginTrustErrorV1::ArtifactRevoked => revoked(RevocationBasisV1::Artifact),
        PluginTrustErrorV1::InvalidEncoding
        | PluginTrustErrorV1::BoundsExceeded
        | PluginTrustErrorV1::InvalidSignature
        | PluginTrustErrorV1::UnknownRootKey
        | PluginTrustErrorV1::ThresholdNotMet
        | PluginTrustErrorV1::AnchorMismatch
        | PluginTrustErrorV1::ChainDiscontinuity
        | PluginTrustErrorV1::DigestMismatch
        | PluginTrustErrorV1::Expired
        | PluginTrustErrorV1::RootHistoryCapacityExceeded
        | PluginTrustErrorV1::RevocationHistoryCapacityExceeded
        | PluginTrustErrorV1::RevocationCapacityExhausted
        | PluginTrustErrorV1::IncompleteManifestProjection => TRUST_STATE_UNAVAILABLE,
    }
}

/// The host error of a failed PMF1 release signature check (gate step 7).
///
/// Public for the R7-F5 public vector; the gate is the only production caller.
#[must_use]
pub const fn host_error_for_release_signature_v1(
    error: PluginReleaseSignatureErrorV1,
) -> CommunityPluginHostErrorV1 {
    match error {
        PluginReleaseSignatureErrorV1::InvalidSignature => denied(TrustDenialBasisV1::Untrusted),
        PluginReleaseSignatureErrorV1::Manifest(_)
        | PluginReleaseSignatureErrorV1::AuthorizationMismatch => {
            CommunityPluginHostErrorV1::InvalidManifest
        }
    }
}

const fn bridge_error(error: PluginTrustBridgeErrorV1) -> CommunityPluginHostErrorV1 {
    match error {
        PluginTrustBridgeErrorV1::InvalidSnapshot
        | PluginTrustBridgeErrorV1::InvalidOperatorSignature => {
            denied(TrustDenialBasisV1::Untrusted)
        }
        PluginTrustBridgeErrorV1::ScopeMismatch
        | PluginTrustBridgeErrorV1::EpochMismatch
        | PluginTrustBridgeErrorV1::InvalidUtcFormat
        | PluginTrustBridgeErrorV1::BridgeRootMismatch
        | PluginTrustBridgeErrorV1::BridgeRevocationMismatch
        | PluginTrustBridgeErrorV1::ReservedPrefix
        | PluginTrustBridgeErrorV1::StaleSnapshot
        | PluginTrustBridgeErrorV1::SnapshotDiscontinuity => {
            denied(TrustDenialBasisV1::PolicyMismatch)
        }
        PluginTrustBridgeErrorV1::Expired => denied(TrustDenialBasisV1::Expired),
        PluginTrustBridgeErrorV1::TpsArtifactDenied => revoked(RevocationBasisV1::OperatorDenial),
        PluginTrustBridgeErrorV1::InvalidAnchorScope
        | PluginTrustBridgeErrorV1::InvalidAnchorRole
        | PluginTrustBridgeErrorV1::InvalidAnchorOperatorKey
        | PluginTrustBridgeErrorV1::EvaluationUtcMismatch
        | PluginTrustBridgeErrorV1::EvaluationTickMismatch
        | PluginTrustBridgeErrorV1::InvalidGenesis
        | PluginTrustBridgeErrorV1::TpsCapExceeded => TRUST_STATE_UNAVAILABLE,
    }
}

const fn floor_error(error: PluginFloorErrorV1) -> CommunityPluginHostErrorV1 {
    match error {
        PluginFloorErrorV1::Rollback(_)
        | PluginFloorErrorV1::Fork(_)
        | PluginFloorErrorV1::Discontinuity(_) => denied(TrustDenialBasisV1::PolicyMismatch),
        PluginFloorErrorV1::PartialFloorState => TRUST_STATE_UNAVAILABLE,
    }
}

/// The host error of a refused `evaluate_current_release` (gate step 6).
///
/// Public for the R7-F5 public vector; the gate is the only production caller.
///
/// Variants that no read-only evaluation raises are mapped defensively to
/// `TrustStateUnavailable`.
#[must_use]
pub const fn host_error_for_registry_v1(
    error: PluginTrustPolicyRegistryErrorV1,
) -> CommunityPluginHostErrorV1 {
    match error {
        PluginTrustPolicyRegistryErrorV1::ReleaseNotActive => denied(TrustDenialBasisV1::NotActive),
        PluginTrustPolicyRegistryErrorV1::PolicyNotAdvanced
        | PluginTrustPolicyRegistryErrorV1::AnchorMismatch => {
            denied(TrustDenialBasisV1::PolicyMismatch)
        }
        PluginTrustPolicyRegistryErrorV1::Bridge(inner) => bridge_error(inner),
        PluginTrustPolicyRegistryErrorV1::Floor(inner) => floor_error(inner),
        PluginTrustPolicyRegistryErrorV1::Trust(inner) => {
            host_error_for_trust_authorization_v1(inner)
        }
        PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed
        | PluginTrustPolicyRegistryErrorV1::StorePoisoned
        | PluginTrustPolicyRegistryErrorV1::StorageFailed
        | PluginTrustPolicyRegistryErrorV1::StorageBusy
        | PluginTrustPolicyRegistryErrorV1::MissingState
        | PluginTrustPolicyRegistryErrorV1::CorruptState
        | PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable
        | PluginTrustPolicyRegistryErrorV1::ReleaseChainViolation
        | PluginTrustPolicyRegistryErrorV1::ReleaseConflict
        | PluginTrustPolicyRegistryErrorV1::UnknownRollbackTarget
        | PluginTrustPolicyRegistryErrorV1::NoActiveRelease
        | PluginTrustPolicyRegistryErrorV1::RollbackTargetActive
        | PluginTrustPolicyRegistryErrorV1::ActivationEventRejected
        | PluginTrustPolicyRegistryErrorV1::NestedTransaction
        | PluginTrustPolicyRegistryErrorV1::WalRequired
        | PluginTrustPolicyRegistryErrorV1::StorageIndeterminate => TRUST_STATE_UNAVAILABLE,
    }
}
