//! Pure, bounded verification preflight for one ADR-058 RVR1 request.
//!
//! The preflight boundary only checks material already supplied by its caller.
//! It never resolves an artifact, contacts a provider, appends evidence, or
//! evaluates a subject.  Those effects belong to the owner of the following
//! boundary and cannot be hidden behind this function.

use crate::{
    domain_digest, ExecutionProfileContractErrorV1, ExecutionProfileV1, ReplayClaimV1,
    ReproManifestV1, ReproVerificationRequestV1, ReproducibilityClassV1, SafeErrorCodeV1,
    TrustPolicySnapshotContractErrorV1, TrustPolicySnapshotV1,
    MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1,
};
/// Maximum number of plugin-version entries admitted while hashing a manifest.
pub const MAX_VERIFICATION_PREFLIGHT_PLUGIN_VERSIONS_V1: usize = 256;
/// Maximum bytes for one manifest identifier while hashing a manifest.
pub const MAX_VERIFICATION_PREFLIGHT_IDENTIFIER_BYTES_V1: usize = 128;
/// Maximum canonical bytes for a manifest admitted by this bounded seam.
pub const MAX_VERIFICATION_PREFLIGHT_MANIFEST_BYTES_V1: usize = 16 * 1024;

/// The closed coordinates reported by the verification preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum VerificationPreflightCoordinateV1 {
    /// The RVR1 schema, size, canonical bytes, or digest.
    Request,
    /// The `ReproManifest` schema or digest binding.
    Manifest,
    /// The EPF1 schema or digest binding.
    ExecutionProfile,
    /// The TPS1 schema or digest binding.
    TrustPolicySnapshot,
    /// Trust-snapshot predecessor and epoch continuity.
    TrustContinuity,
    /// Trust-snapshot epoch ordering.
    TrustEpoch,
    /// Trust-root admission.
    TrustRoot,
    /// Trust-signature authentication.
    TrustSignature,
    /// Artifact-key or artifact-digest revocation.
    Revocation,
    /// The materialized artifact closure.
    ArtifactClosure,
    /// Compatibility between the selected profile and reproducibility class.
    ProfileClass,
    /// `ReplayClaim` eligibility for the selected reproducibility class.
    ReplayClaim,
}

impl std::fmt::Display for VerificationPreflightCoordinateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Request => "request",
            Self::Manifest => "manifest",
            Self::ExecutionProfile => "execution_profile",
            Self::TrustPolicySnapshot => "trust_policy_snapshot",
            Self::TrustContinuity => "trust_continuity",
            Self::TrustEpoch => "trust_epoch",
            Self::TrustRoot => "trust_root",
            Self::TrustSignature => "trust_signature",
            Self::Revocation => "revocation",
            Self::ArtifactClosure => "artifact_closure",
            Self::ProfileClass => "profile_class",
            Self::ReplayClaim => "replay_claim",
        })
    }
}

/// The first closed safe error found by [`preflight_verification_v1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPreflightErrorV1 {
    /// ADR-058's closed safe error code.
    pub code: SafeErrorCodeV1,
    /// The bounded field coordinate at which the code was found.
    pub coordinate: VerificationPreflightCoordinateV1,
}

impl VerificationPreflightErrorV1 {
    const fn new(code: SafeErrorCodeV1, coordinate: VerificationPreflightCoordinateV1) -> Self {
        Self { code, coordinate }
    }

    /// Return the ADR-058 safe error code.
    #[must_use]
    pub const fn code(self) -> SafeErrorCodeV1 {
        self.code
    }

    /// Return the bounded ADR-058 coordinate.
    #[must_use]
    pub const fn coordinate(self) -> VerificationPreflightCoordinateV1 {
        self.coordinate
    }
}

impl std::fmt::Display for VerificationPreflightErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} at {}",
            safe_error_name(self.code),
            self.coordinate
        )
    }
}

impl std::error::Error for VerificationPreflightErrorV1 {}

/// Whether the trust authority has authenticated the TPS1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustSignatureStatusV1 {
    /// The deployment trust authority authenticated the signature.
    Valid,
    /// Authentication failed or was unavailable.
    Invalid,
}

/// Whether the selected trust root is known to the deployment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustRootStatusV1 {
    /// The signing root is known and admitted.
    Known,
    /// No admitted root identifies the signer.
    Unknown,
}

/// Whether an artifact bound by RVR1 is revoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRevocationStatusV1 {
    /// No bound artifact is revoked.
    Clear,
    /// At least one bound artifact is revoked.
    Revoked,
}

/// Whether the complete artifact closure is available for verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactClosureStatusV1 {
    /// All closure members and provenance are available.
    Complete,
    /// One or more closure members or provenance records are absent.
    Incomplete,
}

/// Whether the selected EPF1 is supported by the verifier deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileSupportStatusV1 {
    /// The deployment supports this profile.
    Supported,
    /// The deployment does not support this profile.
    Unsupported,
}

/// Evidence supplied by the deployment-owned trust continuity boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustSnapshotContinuityV1 {
    /// Epoch of the predecessor observed by the trust authority, if any.
    pub previous_epoch: Option<u64>,
    /// Digest of the predecessor observed by the trust authority, if any.
    pub previous_snapshot_digest: Option<[u8; 32]>,
}

/// Bounded, side-effect-free evidence consumed by the preflight seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPreflightEvidenceV1 {
    /// Trust-root admission result.
    pub trust_root: TrustRootStatusV1,
    /// TPS1 operator-signature result.
    pub trust_signature: TrustSignatureStatusV1,
    /// Revocation result for the RVR1-bound artifacts.
    pub artifact_revocation: ArtifactRevocationStatusV1,
    /// Predecessor and epoch evidence for the selected TPS1.
    pub trust_continuity: TrustSnapshotContinuityV1,
    /// Closure completeness result.
    pub artifact_closure: ArtifactClosureStatusV1,
    /// EPF1 deployment support result.
    pub profile_support: ProfileSupportStatusV1,
}

/// The successful decision returned before any artifact or subject execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPreflightResultV1 {
    /// The class requested by RVR1 and confirmed by the manifest.
    pub reproducibility_class: ReproducibilityClassV1,
    /// The claim retained by the manifest after preflight.
    pub replay_claim: ReplayClaimV1,
}

impl VerificationPreflightResultV1 {
    /// Whether this decision may be reported as exact verification.
    ///
    /// A live-unverified run can pass bounded admission for structural work,
    /// but it can never produce an exact verification claim.
    #[must_use]
    pub const fn can_claim_exact_verification(self) -> bool {
        !matches!(
            self.reproducibility_class,
            ReproducibilityClassV1::LiveUnverified
        ) && matches!(
            self.replay_claim,
            ReplayClaimV1::Exact | ReplayClaimV1::ExactAuthoritativeWithRedactedViews
        )
    }
}

/// Inputs to the pure RVR1 verification-preflight function.
pub struct VerificationPreflightInputV1<'a> {
    /// The typed RVR1 request being admitted.
    pub request: &'a ReproVerificationRequestV1,
    /// Exact canonical bytes received for the RVR1 request.
    pub canonical_request_bytes: &'a [u8],
    /// Digest of the exact canonical RVR1 bytes at the request boundary.
    pub canonical_request_digest: [u8; 32],
    /// The typed manifest named by RVR1.
    pub manifest: &'a ReproManifestV1,
    /// The typed EPF1 named by RVR1.
    pub execution_profile: &'a ExecutionProfileV1,
    /// The typed TPS1 named by RVR1.
    pub trust_policy_snapshot: &'a TrustPolicySnapshotV1,
    /// Results from deployment-owned trust, closure, and profile boundaries.
    pub evidence: VerificationPreflightEvidenceV1,
}

/// Run ADR-058's ordered, pure verification preflight for one typed RVR1.
///
/// Checks are intentionally ordered as schema/size, canonical bytes, digest,
/// trust continuity/epoch/signature/revocation, closure, profile/class, then
/// `ReplayClaim` eligibility.  The first failure is returned with one closed
/// safe error code and one bounded coordinate.  No Driver, provider, append,
/// evaluator, or network operation is invoked.
///
/// # Errors
/// Returns only [`VerificationPreflightErrorV1`], containing the first closed
/// ADR-058 safe error and its coordinate.
pub fn preflight_verification_v1(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<VerificationPreflightResultV1, VerificationPreflightErrorV1> {
    preflight_request(input)?;
    let manifest_bytes = preflight_manifest(input)?;
    preflight_profile(input)?;
    let snapshot_bytes = preflight_snapshot(input)?;
    preflight_digest_bindings(input, &manifest_bytes, &snapshot_bytes)?;
    preflight_trust(input)?;
    preflight_closure(input)?;
    preflight_profile_class(input)?;
    preflight_replay_claim(input)
}

fn preflight_request(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<(), VerificationPreflightErrorV1> {
    if input.canonical_request_bytes.len() > MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1 {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::FieldOutOfBounds,
            VerificationPreflightCoordinateV1::Request,
        ));
    }
    input.request.validate().map_err(|_| {
        VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::FieldOutOfBounds,
            VerificationPreflightCoordinateV1::Request,
        )
    })?;
    let canonical = map_request_encoding(input.request.to_canonical_cbor())?;
    if canonical.as_slice() != input.canonical_request_bytes {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::InvalidEncoding,
            VerificationPreflightCoordinateV1::Request,
        ));
    }
    Ok(())
}

fn preflight_manifest(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<pos_core::CanonicalBytes, VerificationPreflightErrorV1> {
    validate_manifest_bounds(input.manifest)?;
    let bytes = map_manifest_encoding(pos_crypto::canonical::encode(input.manifest))?;
    if bytes.len() > MAX_VERIFICATION_PREFLIGHT_MANIFEST_BYTES_V1 {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::FieldOutOfBounds,
            VerificationPreflightCoordinateV1::Manifest,
        ));
    }
    Ok(bytes)
}

fn validate_manifest_bounds(
    manifest: &ReproManifestV1,
) -> Result<(), VerificationPreflightErrorV1> {
    if manifest.format_version != 1 {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::UnsupportedVersion,
            VerificationPreflightCoordinateV1::Manifest,
        ));
    }
    if manifest.execution_profile.is_empty()
        || manifest.execution_profile.len() > MAX_VERIFICATION_PREFLIGHT_IDENTIFIER_BYTES_V1
        || manifest.resource_limit == 0
        || manifest.plugin_versions.len() > MAX_VERIFICATION_PREFLIGHT_PLUGIN_VERSIONS_V1
        || manifest.plugin_versions.iter().any(|(name, version)| {
            name.is_empty()
                || name.len() > MAX_VERIFICATION_PREFLIGHT_IDENTIFIER_BYTES_V1
                || version.is_empty()
                || version.len() > MAX_VERIFICATION_PREFLIGHT_IDENTIFIER_BYTES_V1
        })
        || manifest.input_digest == [0; 32]
        || manifest.execution_profile_digest == [0; 32]
        || manifest.trust_policy_snapshot_digest == [0; 32]
        || manifest.artifact_closure_digest == [0; 32]
        || manifest.evaluator_digest == [0; 32]
        || manifest.scenario_room_digest == [0; 32]
        || manifest.scheduler_digest == [0; 32]
        || manifest.budget_digest == [0; 32]
    {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::FieldOutOfBounds,
            VerificationPreflightCoordinateV1::Manifest,
        ));
    }
    Ok(())
}

fn preflight_profile(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<(), VerificationPreflightErrorV1> {
    input
        .execution_profile
        .canonical_bytes_without_digest_validation()
        .map_err(|error| {
            map_profile_error(error, VerificationPreflightCoordinateV1::ExecutionProfile)
        })?;
    Ok(())
}

fn preflight_snapshot(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<pos_core::CanonicalBytes, VerificationPreflightErrorV1> {
    let bytes = input
        .trust_policy_snapshot
        .to_canonical_cbor()
        .map_err(|error| {
            map_snapshot_error(
                error,
                VerificationPreflightCoordinateV1::TrustPolicySnapshot,
            )
        })?;
    Ok(pos_core::CanonicalBytes::from_vec(bytes))
}

fn preflight_digest_bindings(
    input: &VerificationPreflightInputV1<'_>,
    manifest_bytes: &pos_core::CanonicalBytes,
    snapshot_bytes: &pos_core::CanonicalBytes,
) -> Result<(), VerificationPreflightErrorV1> {
    let request_digest = domain_digest(
        b"PiglorOS.ReproVerificationRequest.v1",
        input.canonical_request_bytes,
    );
    if request_digest != input.canonical_request_digest {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::DigestMismatch,
            VerificationPreflightCoordinateV1::Request,
        ));
    }
    let manifest_digest = domain_digest(b"PiglorOS.ReproManifest.v1", manifest_bytes.as_slice());
    if manifest_digest != input.request.manifest_digest {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::DigestMismatch,
            VerificationPreflightCoordinateV1::Manifest,
        ));
    }
    let profile_digest = input.execution_profile.digest();
    if profile_digest != input.request.execution_profile_digest
        || input.execution_profile.profile_digest != profile_digest
        || input.manifest.execution_profile_digest != input.request.execution_profile_digest
    {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::DigestMismatch,
            VerificationPreflightCoordinateV1::ExecutionProfile,
        ));
    }
    let snapshot_digest = *blake3::hash(snapshot_bytes.as_slice()).as_bytes();
    if snapshot_digest != input.request.trust_policy_snapshot_digest
        || input.manifest.trust_policy_snapshot_digest != input.request.trust_policy_snapshot_digest
    {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::DigestMismatch,
            VerificationPreflightCoordinateV1::TrustPolicySnapshot,
        ));
    }
    if input.manifest.artifact_closure_digest != input.request.artifact_closure_digest {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::DigestMismatch,
            VerificationPreflightCoordinateV1::ArtifactClosure,
        ));
    }
    if input.manifest.evaluator_digest != input.request.evaluator_digest {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::DigestMismatch,
            VerificationPreflightCoordinateV1::Manifest,
        ));
    }
    Ok(())
}

fn preflight_trust(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<(), VerificationPreflightErrorV1> {
    let snapshot = input.trust_policy_snapshot;
    let continuity = &input.evidence.trust_continuity;
    if let Some(expected_digest) = snapshot.previous_snapshot_digest {
        if continuity.previous_snapshot_digest != Some(expected_digest) {
            return Err(VerificationPreflightErrorV1::new(
                SafeErrorCodeV1::TrustSnapshotRollback,
                VerificationPreflightCoordinateV1::TrustContinuity,
            ));
        }
        match continuity.previous_epoch {
            None => {
                return Err(VerificationPreflightErrorV1::new(
                    SafeErrorCodeV1::TrustSnapshotRollback,
                    VerificationPreflightCoordinateV1::TrustEpoch,
                ));
            }
            Some(epoch) if epoch >= snapshot.epoch => {
                return Err(VerificationPreflightErrorV1::new(
                    SafeErrorCodeV1::TrustSnapshotRollback,
                    VerificationPreflightCoordinateV1::TrustContinuity,
                ));
            }
            Some(_) => {}
        }
    } else if snapshot.epoch != 1
        || continuity.previous_epoch.is_some()
        || continuity.previous_snapshot_digest.is_some()
    {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::TrustSnapshotRollback,
            VerificationPreflightCoordinateV1::TrustContinuity,
        ));
    }
    if matches!(input.evidence.trust_root, TrustRootStatusV1::Unknown) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::TrustRootUnknown,
            VerificationPreflightCoordinateV1::TrustRoot,
        ));
    }
    if matches!(
        input.evidence.trust_signature,
        TrustSignatureStatusV1::Invalid
    ) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::SignatureInvalid,
            VerificationPreflightCoordinateV1::TrustSignature,
        ));
    }
    let bound_digests = [
        input.request.manifest_digest,
        input.request.execution_profile_digest,
        input.request.trust_policy_snapshot_digest,
        input.request.artifact_closure_digest,
        input.request.evaluator_digest,
    ];
    if matches!(
        input.evidence.artifact_revocation,
        ArtifactRevocationStatusV1::Revoked
    ) || bound_digests
        .iter()
        .any(|digest| snapshot.revoked_artifact_digests.contains(digest))
    {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ArtifactRevoked,
            VerificationPreflightCoordinateV1::Revocation,
        ));
    }
    Ok(())
}

const fn preflight_closure(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<(), VerificationPreflightErrorV1> {
    if matches!(
        input.evidence.artifact_closure,
        ArtifactClosureStatusV1::Incomplete
    ) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ClosureIncomplete,
            VerificationPreflightCoordinateV1::ArtifactClosure,
        ));
    }
    Ok(())
}

fn preflight_profile_class(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<(), VerificationPreflightErrorV1> {
    if matches!(
        input.evidence.profile_support,
        ProfileSupportStatusV1::Unsupported
    ) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProfileUnsupported,
            VerificationPreflightCoordinateV1::ExecutionProfile,
        ));
    }
    if input.manifest.execution_profile != input.execution_profile.profile_id {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProfileClassMismatch,
            VerificationPreflightCoordinateV1::ProfileClass,
        ));
    }
    if input.manifest.reproducibility_class != input.request.reproducibility_class {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProfileClassMismatch,
            VerificationPreflightCoordinateV1::Manifest,
        ));
    }
    if !input
        .execution_profile
        .reproducibility_classes
        .contains(&input.request.reproducibility_class)
    {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProfileClassMismatch,
            VerificationPreflightCoordinateV1::ProfileClass,
        ));
    }
    Ok(())
}

const fn preflight_replay_claim(
    input: &VerificationPreflightInputV1<'_>,
) -> Result<VerificationPreflightResultV1, VerificationPreflightErrorV1> {
    let claim = input.manifest.replay_claim;
    if matches!(claim, ReplayClaimV1::IncompatibleProfile) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProfileUnsupported,
            VerificationPreflightCoordinateV1::ReplayClaim,
        ));
    }
    if matches!(claim, ReplayClaimV1::UnverifiableArtifactsMissing) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProvenanceMissing,
            VerificationPreflightCoordinateV1::ReplayClaim,
        ));
    }
    if matches!(
        input.request.reproducibility_class,
        ReproducibilityClassV1::LiveUnverified
    ) && matches!(
        claim,
        ReplayClaimV1::Exact | ReplayClaimV1::ExactAuthoritativeWithRedactedViews
    ) {
        return Err(VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::ProfileClassMismatch,
            VerificationPreflightCoordinateV1::ReplayClaim,
        ));
    }
    Ok(VerificationPreflightResultV1 {
        reproducibility_class: input.request.reproducibility_class,
        replay_claim: claim,
    })
}

fn map_request_encoding(
    result: Result<Vec<u8>, crate::ReproVerificationRequestContractErrorV1>,
) -> Result<Vec<u8>, VerificationPreflightErrorV1> {
    result.map_err(|_| {
        VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::InvalidEncoding,
            VerificationPreflightCoordinateV1::Request,
        )
    })
}

fn map_manifest_encoding(
    result: Result<pos_core::CanonicalBytes, pos_core::CoreError>,
) -> Result<pos_core::CanonicalBytes, VerificationPreflightErrorV1> {
    result.map_err(|_| {
        VerificationPreflightErrorV1::new(
            SafeErrorCodeV1::InvalidEncoding,
            VerificationPreflightCoordinateV1::Manifest,
        )
    })
}

const fn map_profile_error(
    error: ExecutionProfileContractErrorV1,
    coordinate: VerificationPreflightCoordinateV1,
) -> VerificationPreflightErrorV1 {
    // Keep this exhaustive table separate from the TPS1 mapping below: the
    // upstream contracts intentionally expose different error enums.
    let code = match error {
        ExecutionProfileContractErrorV1::InvalidEncoding => SafeErrorCodeV1::InvalidEncoding,
        ExecutionProfileContractErrorV1::UnsupportedVersion => SafeErrorCodeV1::UnsupportedVersion,
        ExecutionProfileContractErrorV1::FieldOutOfBounds => SafeErrorCodeV1::FieldOutOfBounds,
        ExecutionProfileContractErrorV1::NonCanonicalOrder => SafeErrorCodeV1::NonCanonicalOrder,
        ExecutionProfileContractErrorV1::DigestMismatch => SafeErrorCodeV1::DigestMismatch,
    };
    VerificationPreflightErrorV1::new(code, coordinate)
}

const fn map_snapshot_error(
    error: TrustPolicySnapshotContractErrorV1,
    coordinate: VerificationPreflightCoordinateV1,
) -> VerificationPreflightErrorV1 {
    let code = match error {
        TrustPolicySnapshotContractErrorV1::InvalidEncoding => SafeErrorCodeV1::InvalidEncoding,
        TrustPolicySnapshotContractErrorV1::UnsupportedSchemaVersion => {
            SafeErrorCodeV1::UnsupportedVersion
        }
        TrustPolicySnapshotContractErrorV1::FieldOutOfBounds => SafeErrorCodeV1::FieldOutOfBounds,
        TrustPolicySnapshotContractErrorV1::NonCanonicalOrder => SafeErrorCodeV1::NonCanonicalOrder,
    };
    VerificationPreflightErrorV1::new(code, coordinate)
}

const fn safe_error_name(code: SafeErrorCodeV1) -> &'static str {
    match code {
        SafeErrorCodeV1::InvalidEncoding => "invalid_encoding",
        SafeErrorCodeV1::UnsupportedVersion => "unsupported_version",
        SafeErrorCodeV1::FieldOutOfBounds => "field_out_of_bounds",
        SafeErrorCodeV1::NonCanonicalOrder => "non_canonical_order",
        SafeErrorCodeV1::DigestMismatch => "digest_mismatch",
        SafeErrorCodeV1::SignatureInvalid => "signature_invalid",
        SafeErrorCodeV1::TrustRootUnknown => "trust_root_unknown",
        SafeErrorCodeV1::TrustSnapshotRollback => "trust_snapshot_rollback",
        SafeErrorCodeV1::ArtifactRevoked => "artifact_revoked",
        SafeErrorCodeV1::ClosureIncomplete => "closure_incomplete",
        SafeErrorCodeV1::ProfileClassMismatch => "profile_class_mismatch",
        SafeErrorCodeV1::ProfileUnsupported => "profile_unsupported",
        SafeErrorCodeV1::ProvenanceMissing => "provenance_missing",
        SafeErrorCodeV1::ResourceLimitExceeded => "resource_limit_exceeded",
    }
}

#[cfg(test)]
mod tests {
    // These tests cover private exhaustive adapters whose foreign error
    // variants are not all constructible through the typed public seam.
    use super::*;

    #[test]
    fn maps_canonical_encoding_failures_to_closed_errors() {
        let request_error = map_request_encoding(Err(
            crate::ReproVerificationRequestContractErrorV1::InvalidEncoding,
        ));
        assert_eq!(
            request_error,
            Err(VerificationPreflightErrorV1::new(
                SafeErrorCodeV1::InvalidEncoding,
                VerificationPreflightCoordinateV1::Request,
            ))
        );
        assert_eq!(map_request_encoding(Ok(vec![1, 2, 3])), Ok(vec![1, 2, 3]));

        let manifest_error = map_manifest_encoding(Err(
            pos_core::CoreError::CanonicalCborSerialization("test".to_owned()),
        ));
        assert_eq!(
            manifest_error,
            Err(VerificationPreflightErrorV1::new(
                SafeErrorCodeV1::InvalidEncoding,
                VerificationPreflightCoordinateV1::Manifest,
            ))
        );
        assert_eq!(
            map_manifest_encoding(Ok(pos_core::CanonicalBytes::from_static(b"bytes"))),
            Ok(pos_core::CanonicalBytes::from_static(b"bytes"))
        );
    }

    #[test]
    fn maps_all_profile_contract_errors_to_closed_codes() {
        let coordinate = VerificationPreflightCoordinateV1::ExecutionProfile;
        let cases = [
            (
                ExecutionProfileContractErrorV1::InvalidEncoding,
                SafeErrorCodeV1::InvalidEncoding,
            ),
            (
                ExecutionProfileContractErrorV1::UnsupportedVersion,
                SafeErrorCodeV1::UnsupportedVersion,
            ),
            (
                ExecutionProfileContractErrorV1::FieldOutOfBounds,
                SafeErrorCodeV1::FieldOutOfBounds,
            ),
            (
                ExecutionProfileContractErrorV1::NonCanonicalOrder,
                SafeErrorCodeV1::NonCanonicalOrder,
            ),
            (
                ExecutionProfileContractErrorV1::DigestMismatch,
                SafeErrorCodeV1::DigestMismatch,
            ),
        ];
        for (error, code) in cases {
            assert_eq!(map_profile_error(error, coordinate).code(), code);
        }
    }

    #[test]
    fn maps_all_snapshot_contract_errors_to_closed_codes() {
        let coordinate = VerificationPreflightCoordinateV1::TrustPolicySnapshot;
        let cases = [
            (
                TrustPolicySnapshotContractErrorV1::InvalidEncoding,
                SafeErrorCodeV1::InvalidEncoding,
            ),
            (
                TrustPolicySnapshotContractErrorV1::UnsupportedSchemaVersion,
                SafeErrorCodeV1::UnsupportedVersion,
            ),
            (
                TrustPolicySnapshotContractErrorV1::FieldOutOfBounds,
                SafeErrorCodeV1::FieldOutOfBounds,
            ),
            (
                TrustPolicySnapshotContractErrorV1::NonCanonicalOrder,
                SafeErrorCodeV1::NonCanonicalOrder,
            ),
        ];
        for (error, code) in cases {
            assert_eq!(map_snapshot_error(error, coordinate).code(), code);
        }
    }
}
