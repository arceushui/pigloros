//! Independent provider image evidence from the fixed SIC1 installation.
//!
//! This snapshot retains its own descriptors and authenticates the authorities
//! named by SPX1. It is not a current-generation reservation or a mount permit:
//! provider control-state admission and backend filesystem checks are separate.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::sandbox_provider_protocol::{
    AdmittedSandboxImage, LaunchPolicy, SandboxExecuteRequest, SignedImageManifest,
    VerifiedSandboxImageProof,
};
use crate::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use crate::selector::installation::{InstallationObjectKind, InstalledSelectorState};
use crate::selector::SelectorBoundaryError;

const CONTROL_LIMIT: u64 = 16 * 1024 * 1024;

/// Independently checked image evidence owning a complete installation snapshot.
///
/// Construction accepts only canonical SPX1 bytes and opens the fixed trusted
/// installation itself. No caller-supplied descriptor, proof, provider snapshot,
/// clock, or freshness claim can construct this value. A later provider runtime
/// must join it to current control state before granting activation authority.
#[derive(Debug)]
pub struct ProviderImageSnapshot {
    admitted: AdmittedSelectorProvider,
    request: SandboxExecuteRequest,
    image: AdmittedSandboxImage,
    proof: VerifiedSandboxImageProof,
    launch: LaunchPolicy,
}

impl ProviderImageSnapshot {
    /// Open the fixed installation and independently check SPX1's image inputs.
    ///
    /// # Errors
    /// Rejects malformed requests, pending installation recovery, unsafe files,
    /// unauthenticated or inconsistent authority, invalid image/GPT/executable
    /// bytes, unaccepted launch policy, and invalid or time-expired CMS proofs.
    pub fn open(request_bytes: &[u8]) -> Result<Self, SelectorBoundaryError> {
        SandboxExecuteRequest::from_canonical_cbor(request_bytes)
            .map_err(invalid)
            .and_then(|request| {
                InstalledSelectorState::open().and_then(|installed| {
                    Self::from_installation(installed, request, SystemTime::now)
                })
            })
    }

    fn from_installation(
        installed: InstalledSelectorState,
        request: SandboxExecuteRequest,
        clock: fn() -> SystemTime,
    ) -> Result<Self, SelectorBoundaryError> {
        installed
            .authenticate_bootstrap()
            .and_then(AuthenticatedSelectorBootstrap::admit_provider)
            .and_then(|admitted| {
                check_authority(&admitted, &request)?;
                let (image, proof) = check_image(&admitted, &request, clock)?;
                let launch_bytes = admitted
                    .bootstrap()
                    .installed()
                    .artifact(
                        InstallationObjectKind::LAUNCH_POLICY,
                        request.authority.lps1_digest,
                    )?
                    .read_control(CONTROL_LIMIT)?;
                admitted
                    .provider()
                    .admit_launch_policy(&launch_bytes, &image)
                    .map_err(invalid)
                    .and_then(|launch| {
                        if launch.policy_digest != request.authority.lps1_digest {
                            return Err(SelectorBoundaryError::ArtifactInvalid);
                        }
                        Ok(Self {
                            admitted,
                            request,
                            image,
                            proof,
                            launch,
                        })
                    })
            })
    }

    /// The canonical request whose immutable authority was checked.
    #[must_use]
    pub const fn request(&self) -> &SandboxExecuteRequest {
        &self.request
    }

    /// Image metadata bound to the retained image and executable descriptors.
    #[must_use]
    pub const fn image(&self) -> &AdmittedSandboxImage {
        &self.image
    }

    /// Independent CMS evidence at the snapshot's admission time.
    #[must_use]
    pub const fn proof(&self) -> &VerifiedSandboxImageProof {
        &self.proof
    }

    /// Authenticated launch-policy component, not permission to launch a unit.
    #[must_use]
    pub const fn launch_policy(&self) -> &LaunchPolicy {
        &self.launch
    }

    /// Recheck the same retained image/executable and CMS at fresh host time.
    ///
    /// This does not reopen paths or assert that the snapshot's authorities are
    /// still current. Provider control-state fencing remains mandatory.
    ///
    /// # Errors
    /// Rejects changed image inputs or a proof no longer valid at host time.
    pub fn recheck_held_image(&self) -> Result<VerifiedSandboxImageProof, SelectorBoundaryError> {
        check_image(&self.admitted, &self.request, SystemTime::now).map(|(_, proof)| proof)
    }
}

fn check_authority(
    admitted: &AdmittedSelectorProvider,
    request: &SandboxExecuteRequest,
) -> Result<(), SelectorBoundaryError> {
    let bootstrap = admitted.bootstrap();
    let provider = admitted.provider();
    let authority = &request.authority;
    let expected = [
        bootstrap.policy().policy_digest(),
        bootstrap.trust().snapshot_digest(),
        bootstrap.revocation().snapshot_digest(),
        provider.manifest().manifest_digest,
        provider.manifest().pcf1_digest,
        provider.conformance_report().report_digest,
        provider.host_profile().profile_digest,
    ];
    let supplied = [
        authority.apt1_digest,
        authority.trs1_digest,
        authority.rvs1_digest,
        authority.spm1_digest,
        authority.pcf1_digest,
        authority.pcr1_digest,
        authority.hcp1_digest,
    ];
    if expected != supplied || request.request.policy_epoch != bootstrap.policy().policy_epoch() {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}

fn check_image(
    admitted: &AdmittedSelectorProvider,
    request: &SandboxExecuteRequest,
    clock: fn() -> SystemTime,
) -> Result<(AdmittedSandboxImage, VerifiedSandboxImageProof), SelectorBoundaryError> {
    let installed = admitted.bootstrap().installed();
    let sim1 = installed
        .artifact(
            InstallationObjectKind::IMAGE_MANIFEST,
            request.authority.sim1_digest,
        )?
        .read_control(CONTROL_LIMIT)?;
    let manifest = SignedImageManifest::from_canonical_cbor(&sim1).map_err(invalid)?;
    if manifest.manifest_digest != request.authority.sim1_digest {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let root_image = installed.artifact(
        InstallationObjectKind::ROOT_IMAGE,
        manifest.root_image_blake3_digest,
    )?;
    let executable = installed.artifact(
        InstallationObjectKind::SUBJECT_EXECUTABLE,
        manifest.executable_blake3_digest,
    )?;
    admitted
        .provider()
        .admit_image_files(
            &sim1,
            root_image.file(),
            executable.file(),
            executable.object().byte_length(),
        )
        .map_err(invalid)
        .and_then(|image| {
            clock()
                .duration_since(UNIX_EPOCH)
                .map_err(invalid)
                .and_then(|time| {
                    admitted
                        .provider()
                        .verify_image_proof(&image, time.as_secs())
                        .map_err(invalid)
                })
                .map(|proof| (image, proof))
        })
}

fn invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::unix::fs::FileExt;
    use std::time::Duration;

    use super::*;
    use crate::selector::installation::tests::admitted_state;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn request_fixture() -> TestResult<SandboxExecuteRequest> {
        let admitted = admitted_state()?
            .authenticate_bootstrap()?
            .admit_provider()?;
        let mut request =
            crate::selector_transport_test_fixture::authenticated_transport_fixture()?.request;
        let bootstrap = admitted.bootstrap();
        let provider = admitted.provider();
        request.authority.apt1_digest = bootstrap.policy().policy_digest();
        request.authority.trs1_digest = bootstrap.trust().snapshot_digest();
        request.authority.rvs1_digest = bootstrap.revocation().snapshot_digest();
        request.authority.spm1_digest = provider.manifest().manifest_digest;
        request.authority.pcf1_digest = provider.manifest().pcf1_digest;
        request.authority.pcr1_digest = provider.conformance_report().report_digest;
        request.authority.hcp1_digest = provider.host_profile().profile_digest;
        let identity = |kind| {
            bootstrap
                .installed()
                .manifest()
                .objects()
                .iter()
                .find(|object| object.kind() == kind)
                .map(crate::selector::installation::InstallationObject::identity)
                .ok_or("missing image fixture object")
        };
        request.authority.sim1_digest = identity(InstallationObjectKind::IMAGE_MANIFEST)?;
        request.authority.lps1_digest = identity(InstallationObjectKind::LAUNCH_POLICY)?;
        request.request.apt1_digest = request.authority.apt1_digest;
        request.request.policy_epoch = bootstrap.policy().policy_epoch();
        canonical_request(request)
    }

    fn canonical_request(request: SandboxExecuteRequest) -> TestResult<SandboxExecuteRequest> {
        let encoded = SandboxExecuteRequest::for_selector(
            request.request,
            request.attempt_id,
            request.authority,
            request.capability_ids,
            request.adapter_input,
            request.network_plans,
        )?
        .to_canonical_cbor()?;
        SandboxExecuteRequest::from_canonical_cbor(&encoded).map_err(Into::into)
    }

    #[test]
    fn malformed_public_request_fails_before_installation_open() {
        assert!(ProviderImageSnapshot::open(b"SPX1").is_err());
    }

    #[test]
    fn independent_snapshot_retains_image_and_immutable_authority() -> TestResult {
        let request = request_fixture()?;
        let snapshot = ProviderImageSnapshot::from_installation(
            admitted_state()?,
            request.clone(),
            fixture_time,
        )?;
        assert_eq!(snapshot.request(), &request);
        assert_eq!(
            snapshot.image().manifest().manifest_digest,
            request.authority.sim1_digest
        );
        assert_eq!(
            snapshot.launch_policy().policy_digest,
            request.authority.lps1_digest
        );
        let (_, proof) = check_image(&snapshot.admitted, &request, fixture_time)?;
        assert_eq!(snapshot.proof(), &proof);
        Ok(())
    }

    #[test]
    fn independently_rejects_each_foreign_authority_and_policy_epoch() -> TestResult {
        let original = request_fixture()?;
        for index in 0..8 {
            let mut request = original.clone();
            let heads = [
                &mut request.authority.apt1_digest,
                &mut request.authority.trs1_digest,
                &mut request.authority.rvs1_digest,
                &mut request.authority.spm1_digest,
                &mut request.authority.pcf1_digest,
                &mut request.authority.pcr1_digest,
                &mut request.authority.hcp1_digest,
            ];
            if let Some(head) = heads.into_iter().nth(index) {
                head[0] ^= 1;
            } else {
                request.request.policy_epoch += 1;
            }
            request.request.apt1_digest = request.authority.apt1_digest;
            let request = canonical_request(request)?;
            assert!(ProviderImageSnapshot::from_installation(
                admitted_state()?,
                request,
                fixture_time
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn missing_selected_image_and_launch_policy_fail_closed() -> TestResult {
        for image in [true, false] {
            let mut request = request_fixture()?;
            if image {
                request.authority.sim1_digest[0] ^= 1;
            } else {
                request.authority.lps1_digest[0] ^= 1;
            }
            assert!(ProviderImageSnapshot::from_installation(
                admitted_state()?,
                canonical_request(request)?,
                fixture_time
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn provider_rejects_mislabelled_image_and_launch_records() -> TestResult {
        use crate::selector::installation::tests::reindex_artifact;

        for kind in [
            InstallationObjectKind::IMAGE_MANIFEST,
            InstallationObjectKind::LAUNCH_POLICY,
        ] {
            let mut state = admitted_state()?;
            let mut request = request_fixture()?;
            let selected = if kind == InstallationObjectKind::IMAGE_MANIFEST {
                &mut request.authority.sim1_digest
            } else {
                &mut request.authority.lps1_digest
            };
            let previous = *selected;
            selected[0] ^= 1;
            reindex_artifact(&mut state, kind, previous, *selected)?;
            assert!(ProviderImageSnapshot::from_installation(
                state,
                canonical_request(request)?,
                fixture_time
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn provider_rejects_missing_image_descriptors() -> TestResult {
        use crate::selector::installation::tests::omit_artifact;

        for kind in [
            InstallationObjectKind::ROOT_IMAGE,
            InstallationObjectKind::SUBJECT_EXECUTABLE,
        ] {
            let mut state = admitted_state()?;
            omit_artifact(&mut state, kind);
            assert!(ProviderImageSnapshot::from_installation(
                state,
                request_fixture()?,
                fixture_time
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn provider_rejects_truncated_control_descriptors() -> TestResult {
        for kind in [
            InstallationObjectKind::IMAGE_MANIFEST,
            InstallationObjectKind::LAUNCH_POLICY,
        ] {
            let state = admitted_state()?;
            let request = request_fixture()?;
            let identity = if kind == InstallationObjectKind::IMAGE_MANIFEST {
                request.authority.sim1_digest
            } else {
                request.authority.lps1_digest
            };
            state.artifact(kind, identity)?.file().set_len(0)?;
            assert!(
                ProviderImageSnapshot::from_installation(state, request, fixture_time).is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn retained_descriptor_mutation_is_rejected_on_recheck() -> TestResult {
        for role in [
            InstallationObjectKind::ROOT_IMAGE,
            InstallationObjectKind::SUBJECT_EXECUTABLE,
            InstallationObjectKind::IMAGE_MANIFEST,
        ] {
            let snapshot = ProviderImageSnapshot::from_installation(
                admitted_state()?,
                request_fixture()?,
                fixture_time,
            )?;
            let manifest = snapshot.image().manifest();
            let identity = match role {
                InstallationObjectKind::ROOT_IMAGE => manifest.root_image_blake3_digest,
                InstallationObjectKind::SUBJECT_EXECUTABLE => manifest.executable_blake3_digest,
                _ => manifest.manifest_digest,
            };
            let artifact = snapshot
                .admitted
                .bootstrap()
                .installed()
                .artifact(role, identity)?;
            let mut byte = [0];
            artifact.file().read_exact_at(&mut byte, 0)?;
            byte[0] ^= 1;
            artifact.file().write_all_at(&byte, 0)?;
            assert!(snapshot.recheck_held_image().is_err());
        }
        Ok(())
    }

    #[test]
    fn provider_independently_rejects_invalid_certificate_times() -> TestResult {
        let clocks: [fn() -> SystemTime; 3] = [
            || UNIX_EPOCH - Duration::from_secs(1),
            || UNIX_EPOCH,
            || UNIX_EPOCH + Duration::from_secs(2_200_000_000),
        ];
        for clock in clocks {
            assert!(ProviderImageSnapshot::from_installation(
                admitted_state()?,
                request_fixture()?,
                clock
            )
            .is_err());
        }
        Ok(())
    }
}
