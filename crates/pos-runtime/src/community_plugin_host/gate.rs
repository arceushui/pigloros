//! The execution-time trust gate (ADR-061 revision 7 decisions 2 and 3, ADR-103 revision 5).
//!
//! The gate runs once per Plugin per Tick Boundary, before any invocation of that Plugin at
//! that Tick. It re-reads the release closure, re-verifies the PTR1 and PRV1 histories from the
//! composition's material, asks the registry's read-only `evaluate_current_release`, and
//! re-verifies the PMF1 release signature. It writes nothing, reads no clock, and caches
//! nothing. Linux only, like the registry port.

use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
use pos_crypto::plugin_manifest::verify_plugin_release_signature_v1;
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1, VerifiedReleaseBundleV1};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

use super::error::CommunityPluginHostErrorV1;

mod mapping;
mod material;
mod pass;
mod released;

pub use mapping::{
    host_error_for_registry_v1, host_error_for_release_signature_v1,
    host_error_for_release_source_v1, host_error_for_trust_authorization_v1,
    host_error_for_trust_verification_v1,
};
pub use material::{
    CommunityPluginTrustMaterialV1, PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1,
};
pub use pass::CommunityPassV1;
pub use released::{CommunityPassAuthorizationV1, GatedCommunityReleaseV1, ReleaseIdentityV1};

/// What the composition expects the address to hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginExpectationV1 {
    /// The member's expected PMF1 Plugin ID text.
    pub plugin_id: String,
    /// When a Driver already exists, the `(complete-PMF1 digest, release digest)` pair it was
    /// built for.
    pub release: Option<([u8; 32], [u8; 32])>,
}

/// The name of the Component layer of a release closure.
const COMPONENT_MEMBER: &str = "component";

/// Gate one release for one pass.
///
/// The first failing step returns its error and no later step runs; no registry call is made
/// after a failure before step 6. A closed pass is refused with
/// `ArtifactTrustDenied{TrustStateUnavailable}` before any other step. The steps are: read the
/// verified closure; project the complete PMF1; require the expected identity; read the trust
/// material; verify PTR1 and PRV1; evaluate the release through the registry; re-verify the
/// PMF1 release signature. A registry denial therefore wins over a signature fault.
///
/// # Errors
/// Returns the closed host error that decision 3 of ADR-061 revision 7 assigns to the first
/// failing step.
pub fn gate_community_release_v1(
    registry: &(impl PluginTrustPolicyRegistryV1 + ?Sized),
    expected: &CommunityPluginExpectationV1,
    source: &(impl ReleaseSourceV1 + ?Sized),
    address: &BundleAddressV1,
    material: &(impl PluginTrustMaterialSourceV1 + ?Sized),
    pass: &CommunityPassV1,
) -> Result<(GatedCommunityReleaseV1, CommunityPassAuthorizationV1), CommunityPluginHostErrorV1> {
    if !pass.is_open() {
        return Err(mapping::TRUST_STATE_UNAVAILABLE);
    }
    let bundle = source
        .read_verified(address)
        .map_err(host_error_for_release_source_v1)?;
    let (projection, execution) = project(&bundle)?;
    require_expected(expected, &execution)?;
    let trust = material
        .material()
        .or(Err(mapping::TRUST_STATE_UNAVAILABLE))?;
    let evidence = verify_plugin_trust_v1(
        trust.root_anchor(),
        &slices(trust.roots()),
        &slices(trust.revocations()),
        pass.utc().as_i64(),
        pass.tick(),
    )
    .map_err(host_error_for_trust_verification_v1)?;
    let evaluation = registry
        .evaluate_current_release(
            trust.policy_anchor(),
            trust.tps1_bytes(),
            &evidence,
            &projection,
            pass.utc(),
            pass.tick(),
        )
        .map_err(host_error_for_registry_v1)?;
    verify_signature(&bundle, &evidence, &projection)?;
    let gated = GatedCommunityReleaseV1::new(
        execution,
        component_bytes(&bundle),
        evaluation.tps1_digest(),
        pass.utc().as_i64(),
        pass.tick(),
    );
    let authorization = CommunityPassAuthorizationV1::issue(&gated, pass);
    Ok((gated, authorization))
}

type Projections = (
    ValidatedPluginManifestProjectionV1,
    PluginExecutionProjectionV1,
);

/// Both projections of one closure, bound to each other; any failure is `InvalidManifest`.
fn project(bundle: &VerifiedReleaseBundleV1) -> Result<Projections, CommunityPluginHostErrorV1> {
    let invalid = CommunityPluginHostErrorV1::InvalidManifest;
    ValidatedPluginManifestProjectionV1::from_verified_bundle(bundle)
        .and_then(|projection| {
            PluginExecutionProjectionV1::from_verified_bundle(bundle)
                .map(|execution| (projection, execution))
        })
        .or(Err(invalid))
        .and_then(|(projection, execution)| {
            execution
                .is_bound_to(&projection)
                .then_some((projection, execution))
                .ok_or(invalid)
        })
}

/// The Plugin ID, and the release pair when one is expected, equal the composition's.
fn require_expected(
    expected: &CommunityPluginExpectationV1,
    execution: &PluginExecutionProjectionV1,
) -> Result<(), CommunityPluginHostErrorV1> {
    let release_matches = expected.release.is_none_or(|(pmf1, release)| {
        execution.pmf1_digest() == pmf1 && execution.release_digest() == release
    });
    let matches = execution.plugin_id() == expected.plugin_id && release_matches;
    matches.then_some(()).ok_or(mapping::NOT_ACTIVE)
}

fn slices(records: &[Vec<u8>]) -> Vec<&[u8]> {
    records.iter().map(Vec::as_slice).collect()
}

/// Step 7: authorize the release under the evidence and verify field 26 under the resolved key.
///
/// The registry authorized the same projection under the same evidence at step 6, so the
/// authorization cannot fail here; its error is still mapped, without a separate branch.
fn verify_signature(
    bundle: &VerifiedReleaseBundleV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
    projection: &ValidatedPluginManifestProjectionV1,
) -> Result<(), CommunityPluginHostErrorV1> {
    evidence
        .authorize_release(projection)
        .map_err(host_error_for_trust_authorization_v1)
        .and_then(|authorization| {
            verify_plugin_release_signature_v1(bundle, &authorization)
                .map(|_| ())
                .map_err(host_error_for_release_signature_v1)
        })
}

/// The verified bytes of the closure's `component` layer.
///
/// The closure rules and the projection guarantee exactly one such layer.
fn component_bytes(bundle: &VerifiedReleaseBundleV1) -> Vec<u8> {
    bundle
        .members()
        .iter()
        .zip(bundle.member_bytes())
        .filter(|(member, _)| member.member() == COMPONENT_MEMBER)
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect()
}
