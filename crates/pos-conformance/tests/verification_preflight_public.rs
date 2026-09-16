#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for ADR-058 RVR1 verification preflight.

use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1,
    preflight_verification_v1, ArtifactClosureStatusV1, ArtifactRevocationStatusV1,
    ExecutionModeV1, ExecutionProfileV1, ProfileSupportStatusV1, ReplayClaimV1, ReproManifestV1,
    ReproVerificationRequestV1, ReproducibilityClassV1, SafeErrorCodeV1, TrustPolicySnapshotV1,
    TrustRootStatusV1, TrustSignatureStatusV1, TrustSnapshotContinuityV1,
    VerificationPreflightCoordinateV1, VerificationPreflightErrorV1,
    VerificationPreflightEvidenceV1, VerificationPreflightInputV1,
    MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1, MAX_VERIFICATION_PREFLIGHT_PLUGIN_VERSIONS_V1,
};
use std::collections::BTreeMap;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    request: ReproVerificationRequestV1,
    canonical_request_bytes: Vec<u8>,
    canonical_request_digest: [u8; 32],
    manifest: ReproManifestV1,
    execution_profile: ExecutionProfileV1,
    trust_policy_snapshot: TrustPolicySnapshotV1,
    evidence: VerificationPreflightEvidenceV1,
}

impl Fixture {
    fn new(class: ReproducibilityClassV1) -> TestResult<Self> {
        let execution_profile = ExecutionProfileV1::from_canonical_cbor(
            &draft_execution_profile_bytes_v1("deterministic-local-v1")?,
        )?;
        let trust_policy_snapshot =
            TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
        let mut execution_profile = execution_profile;
        execution_profile.reproducibility_classes = vec![class];
        execution_profile.profile_digest = execution_profile.digest();
        let profile_digest = execution_profile.profile_digest;
        let trust_digest = trust_policy_snapshot.digest()?;
        let closure_digest = [8; 32];
        let evaluator_digest = [9; 32];
        let manifest = ReproManifestV1 {
            format_version: 1,
            input_digest: [10; 32],
            execution_mode: ExecutionModeV1::Local,
            fork_cut_seq: None,
            seed: 11,
            resource_limit: 12,
            network_enabled: false,
            reproducibility_class: class,
            execution_profile: execution_profile.profile_id.clone(),
            execution_profile_digest: profile_digest,
            trust_policy_snapshot_digest: trust_digest,
            artifact_closure_digest: closure_digest,
            evaluator_digest,
            replay_claim: if matches!(class, ReproducibilityClassV1::LiveUnverified) {
                ReplayClaimV1::StructuralOnly
            } else {
                ReplayClaimV1::Exact
            },
            plugin_versions: BTreeMap::new(),
            scenario_room_digest: [13; 32],
            scheduler_digest: [14; 32],
            budget_digest: [15; 32],
        };
        let manifest_digest = manifest_digest(&manifest)?;
        let request = ReproVerificationRequestV1 {
            request_digest: [1; 32],
            manifest_digest,
            reproducibility_class: class,
            execution_profile_digest: profile_digest,
            trust_policy_snapshot_digest: trust_digest,
            artifact_closure_digest: closure_digest,
            evaluator_digest,
            report_bytes_limit: 1024,
        };
        let canonical_request_bytes = request.to_canonical_cbor()?;
        let canonical_request_digest = request.digest()?;
        Ok(Self {
            request,
            canonical_request_bytes,
            canonical_request_digest,
            manifest,
            execution_profile,
            trust_policy_snapshot,
            evidence: VerificationPreflightEvidenceV1 {
                trust_root: TrustRootStatusV1::Known,
                trust_signature: TrustSignatureStatusV1::Valid,
                artifact_revocation: ArtifactRevocationStatusV1::Clear,
                trust_continuity: TrustSnapshotContinuityV1 {
                    previous_epoch: None,
                    previous_snapshot_digest: None,
                },
                artifact_closure: ArtifactClosureStatusV1::Complete,
                profile_support: ProfileSupportStatusV1::Supported,
            },
        })
    }

    fn input(&self) -> VerificationPreflightInputV1<'_> {
        VerificationPreflightInputV1 {
            request: &self.request,
            canonical_request_bytes: &self.canonical_request_bytes,
            canonical_request_digest: self.canonical_request_digest,
            manifest: &self.manifest,
            execution_profile: &self.execution_profile,
            trust_policy_snapshot: &self.trust_policy_snapshot,
            evidence: self.evidence.clone(),
        }
    }
}

fn manifest_digest(manifest: &ReproManifestV1) -> TestResult<[u8; 32]> {
    let bytes = pos_crypto::canonical::encode(manifest)?;
    let mut input = b"PiglorOS.ReproManifest.v1\0".to_vec();
    input.extend_from_slice(bytes.as_slice());
    Ok(*blake3::hash(&input).as_bytes())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn expect_failure<T>(
    result: &Result<T, VerificationPreflightErrorV1>,
    message: &'static str,
) -> VerificationPreflightErrorV1 {
    match result {
        Err(error) => *error,
        Ok(_) => std::panic::resume_unwind(Box::new(message)),
    }
}

#[test]
fn admits_each_reproducibility_class_without_collapsing_live_unverified() -> TestResult {
    let classes = [
        ReproducibilityClassV1::RecordedReplay,
        ReproducibilityClassV1::ProfileRecomputation,
        ReproducibilityClassV1::CrossProfileConformance,
        ReproducibilityClassV1::LiveUnverified,
    ];
    for class in classes {
        let fixture = Fixture::new(class)?;
        let result = preflight_verification_v1(&fixture.input())?;
        assert_eq!(result.reproducibility_class, class);
        assert_eq!(
            result.can_claim_exact_verification(),
            !matches!(class, ReproducibilityClassV1::LiveUnverified)
        );
    }
    Ok(())
}

#[test]
fn returns_the_first_failure_in_adr_order() -> TestResult {
    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.evidence.trust_signature = TrustSignatureStatusV1::Invalid;
    fixture.evidence.artifact_closure = ArtifactClosureStatusV1::Incomplete;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "trust precedes closure",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::SignatureInvalid);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::TrustSignature
    );

    fixture.canonical_request_bytes.push(0);
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "canonical bytes first",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::InvalidEncoding);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::Request
    );
    Ok(())
}

#[test]
fn enforces_digest_bounds_and_mutation_sensitivity() -> TestResult {
    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.canonical_request_digest[0] ^= 1;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "request digest mismatch",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::DigestMismatch);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::Request
    );

    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.manifest.evaluator_digest[0] ^= 1;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "manifest mutation",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::DigestMismatch);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::Manifest
    );

    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.manifest.plugin_versions = (0..=MAX_VERIFICATION_PREFLIGHT_PLUGIN_VERSIONS_V1)
        .map(|index| (format!("plugin-{index}"), "1.0.0".to_owned()))
        .collect();
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "manifest bound",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::FieldOutOfBounds);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::Manifest
    );

    let fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    let mut input = fixture.input();
    let oversized_request = vec![0; MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1 + 1];
    input.canonical_request_bytes = &oversized_request;
    let error = expect_failure(&preflight_verification_v1(&input), "request bound");
    assert_eq!(error.code(), SafeErrorCodeV1::FieldOutOfBounds);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::Request
    );
    Ok(())
}

#[test]
fn enforces_trust_continuity_revocation_closure_profile_and_claim() -> TestResult {
    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.evidence.trust_continuity.previous_epoch = Some(0);
    let error = expect_failure(&preflight_verification_v1(&fixture.input()), "rollback");
    assert_eq!(error.code(), SafeErrorCodeV1::TrustSnapshotRollback);

    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.evidence.trust_root = TrustRootStatusV1::Unknown;
    let error = expect_failure(&preflight_verification_v1(&fixture.input()), "unknown root");
    assert_eq!(error.code(), SafeErrorCodeV1::TrustRootUnknown);

    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.evidence.artifact_revocation = ArtifactRevocationStatusV1::Revoked;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "revoked artifact",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::ArtifactRevoked);

    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.evidence.artifact_closure = ArtifactClosureStatusV1::Incomplete;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "incomplete closure",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::ClosureIncomplete);

    let mut fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    fixture.evidence.profile_support = ProfileSupportStatusV1::Unsupported;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "unsupported profile",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::ProfileUnsupported);

    let mut fixture = Fixture::new(ReproducibilityClassV1::LiveUnverified)?;
    fixture.manifest.replay_claim = ReplayClaimV1::Exact;
    fixture.request.manifest_digest = manifest_digest(&fixture.manifest)?;
    fixture.canonical_request_bytes = fixture.request.to_canonical_cbor()?;
    fixture.canonical_request_digest = fixture.request.digest()?;
    let error = expect_failure(
        &preflight_verification_v1(&fixture.input()),
        "live exact claim",
    );
    assert_eq!(error.code(), SafeErrorCodeV1::ProfileClassMismatch);
    assert_eq!(
        error.coordinate(),
        VerificationPreflightCoordinateV1::ReplayClaim
    );
    Ok(())
}
