//! Independent provider image evidence from the fixed SIC1 installation.
//!
//! A snapshot retains its own descriptors and authenticates the authorities
//! named by SPX1, including the first adapter's signed-EROFS root precheck.
//! Only [`ProviderImageSnapshot::admit_held_image`] joins that evidence to the
//! currently installed authority and yields the descriptor-bearing admission
//! for later image activation. Neither value is a mount or launch permit.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::FileExt as _;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::sandbox_provider_protocol::{
    AdmittedSandboxImage, LaunchPolicy, PartitionDescriptor, SandboxExecuteRequest,
    SignedImageManifest, VerifiedSandboxImageProof,
};
use crate::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use crate::selector::installation::{InstallationObjectKind, InstalledSelectorState};
use crate::selector::SelectorBoundaryError;

const CONTROL_LIMIT: u64 = 16 * 1024 * 1024;
// ADR-087 activation step 1: little-endian EROFS superblock magic at byte
// 1024 of the root partition (EROFS on-disk core format).
const EROFS_MAGIC_OFFSET: u64 = 1024;
const EROFS_MAGIC: [u8; 4] = 0xE0F5_E1E2_u32.to_le_bytes();
// cryptsetup's dm-verity superblock at the start of the hash partition,
// through the first 32 salt bytes (little-endian `struct verity_sb`).
const VERITY_SUPERBLOCK_PREFIX: usize = 88 + 32;
const VERITY_SIGNATURE: &[u8; 8] = b"verity\0\0";
// Superblock version 1, then hash type 1 (normal, salt prepended).
const VERITY_FORMAT: [u8; 8] = [1, 0, 0, 0, 1, 0, 0, 0];
const VERITY_ALGORITHM: [u8; 32] = *b"sha256\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
// 4096-byte data blocks, then 4096-byte hash blocks.
const VERITY_BLOCK_SIZES: [u8; 8] = [0, 16, 0, 0, 0, 16, 0, 0];
const VERITY_SALT_SIZE: [u8; 2] = [32, 0];

/// Independently checked image evidence owning a complete installation snapshot.
///
/// Construction accepts only canonical SPX1 bytes and opens the fixed trusted
/// installation itself. No caller-supplied descriptor, proof, provider snapshot,
/// clock, or freshness claim can construct this value. Only
/// [`Self::admit_held_image`] joins it to the currently installed authority.
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
    /// bytes, a non-EROFS root or mismatched verity superblock, unaccepted
    /// launch policy, and invalid or time-expired CMS proofs.
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
                let CheckedImage { image, proof, .. } = check_image(&admitted, &request, clock)?;
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

    /// Join this snapshot's retained image to the currently installed authority.
    ///
    /// The fixed installation is reopened: a pending SIR1 update rejects, and
    /// its authenticated APT1/TRS1/RVS1 and provider records must still be the
    /// exact authority this snapshot's SPX1 named. The selector commits SIR1
    /// before sending any RCU1 and removes it only after installing the
    /// successor SIC1, so at the instants checked a committed newer revocation
    /// is either pending or installed, and both reject. The same retained image,
    /// GPT, executable, EROFS root, verity superblock and CMS proof are then
    /// rechecked at fresh host time.
    ///
    /// This is a point-in-time check against installed selector heads, not a
    /// provider-held RVS1 floor or attempt reservation. A revocation committed
    /// during or after the call is handled only by RCU1 live-attempt
    /// cancellation, post-activation readback and the `StartTransientUnit`
    /// RVS1 recheck, which remain mandatory.
    ///
    /// # Errors
    /// Rejects pending recovery, stale or substituted authority, changed image
    /// inputs, a non-EROFS root or mismatched verity superblock, or a proof no
    /// longer valid at host time.
    pub fn admit_held_image(&self) -> Result<HeldImageAdmission<'_>, SelectorBoundaryError> {
        self.join_current(InstalledSelectorState::open(), SystemTime::now)
    }

    fn join_current(
        &self,
        current: Result<InstalledSelectorState, SelectorBoundaryError>,
        clock: fn() -> SystemTime,
    ) -> Result<HeldImageAdmission<'_>, SelectorBoundaryError> {
        current
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(AuthenticatedSelectorBootstrap::admit_provider)
            .and_then(|current| check_authority(&current, &self.request))
            .and_then(|()| check_image(&self.admitted, &self.request, clock))
            .map(|checked| HeldImageAdmission {
                snapshot: self,
                root_image: checked.root_image,
                proof: checked.proof,
            })
    }
}

/// One snapshot's retained image, admitted against current installed authority.
///
/// Only [`ProviderImageSnapshot::admit_held_image`] constructs this value. It
/// borrows the snapshot, and [`AsFd`] yields exactly the retained root-image
/// descriptor that every image, GPT, EROFS, verity superblock and CMS check
/// read; no caller can supply or substitute a descriptor, proof or authority.
/// It has no public constructor, `Clone` or serialization, and grants no
/// mount, launch or output authority by itself.
pub struct HeldImageAdmission<'snapshot> {
    snapshot: &'snapshot ProviderImageSnapshot,
    root_image: &'snapshot File,
    proof: VerifiedSandboxImageProof,
}

impl<'snapshot> HeldImageAdmission<'snapshot> {
    /// The snapshot whose retained descriptors and request were admitted.
    #[must_use]
    pub const fn snapshot(&self) -> &'snapshot ProviderImageSnapshot {
        self.snapshot
    }

    /// Independent CMS evidence at this admission's host time.
    #[must_use]
    pub const fn proof(&self) -> &VerifiedSandboxImageProof {
        &self.proof
    }
}

impl AsFd for HeldImageAdmission<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.root_image.as_fd()
    }
}

impl std::fmt::Debug for HeldImageAdmission<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HeldImageAdmission { .. }")
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

/// Image evidence checked from one admitted provider's retained descriptors.
struct CheckedImage<'a> {
    image: AdmittedSandboxImage,
    proof: VerifiedSandboxImageProof,
    root_image: &'a File,
}

fn check_image<'a>(
    admitted: &'a AdmittedSelectorProvider,
    request: &SandboxExecuteRequest,
    clock: fn() -> SystemTime,
) -> Result<CheckedImage<'a>, SelectorBoundaryError> {
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
            // SIM1 validation fixes partition ordinal 0 as the DPS root partition.
            check_erofs_root(root_image.file(), &image.manifest().partitions[0]).map(|()| image)
        })
        .and_then(|image| {
            let manifest = image.manifest();
            check_verity_superblock(
                root_image.file(),
                &manifest.partitions[1],
                &manifest.verity_salt,
            )
            .map(|()| image)
        })
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
                .map(|proof| CheckedImage {
                    image,
                    proof,
                    root_image: root_image.file(),
                })
        })
}

/// First-adapter `root=signed+erofs:=absent` precheck over the held image.
///
/// SIM1 decoding and GPT admission already require exactly the root,
/// root-verity and root-verity-sig DPS partitions with signed byte digests.
/// This adds ADR-087's EROFS superblock magic in the admitted root partition,
/// read from the same retained descriptor. It only rejects unsupported formats
/// before activation; mountfsd's image policy and kernel readback remain
/// authoritative for the mounted filesystem type.
fn check_erofs_root(
    root_image: &File,
    root: &PartitionDescriptor,
) -> Result<(), SelectorBoundaryError> {
    // Never read outside the admitted root partition.
    if root.length_bytes < EROFS_MAGIC_OFFSET + 4 {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let mut magic = [0; 4];
    root_image
        .read_exact_at(&mut magic, root.start_bytes + EROFS_MAGIC_OFFSET)
        .map_err(invalid)
        .and_then(|()| {
            if magic != EROFS_MAGIC {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            }
            Ok(())
        })
}

/// Pre-activation dm-verity superblock check over the same held image.
///
/// The root-verity partition (SIM1 ordinal 1) must start with a format-1
/// superblock whose hash algorithm, 4096-byte data and hash block sizes and
/// exact 32-byte salt equal SIM1. The live dm-verity table salt is checked
/// again after activation.
fn check_verity_superblock(
    root_image: &File,
    verity: &PartitionDescriptor,
    salt: &[u8; 32],
) -> Result<(), SelectorBoundaryError> {
    if verity.length_bytes < VERITY_SUPERBLOCK_PREFIX as u64 {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let mut header = [0; VERITY_SUPERBLOCK_PREFIX];
    root_image
        .read_exact_at(&mut header, verity.start_bytes)
        .map_err(invalid)
        .and_then(|()| {
            if header[..8] != *VERITY_SIGNATURE
                || header[8..16] != VERITY_FORMAT
                || header[32..64] != VERITY_ALGORITHM
                || header[64..72] != VERITY_BLOCK_SIZES
                || header[80..82] != VERITY_SALT_SIZE
                || header[88..] != *salt
            {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            }
            Ok(())
        })
}

fn invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

// Public test-only module, like the installation fixtures: the privileged
// root-selector composition test reuses its request fixture.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[doc(hidden)]
pub mod tests {
    use std::os::unix::fs::FileExt;
    use std::time::Duration;

    use super::*;
    use crate::selector::installation::tests::admitted_state;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_hours(500_000)
    }

    fn request_fixture() -> TestResult<SandboxExecuteRequest> {
        request_for(
            &admitted_state()?
                .authenticate_bootstrap()?
                .admit_provider()?,
        )
    }

    /// A canonical SPX1 naming exactly this admitted provider's authority.
    pub(crate) fn request_for(
        admitted: &AdmittedSelectorProvider,
    ) -> TestResult<SandboxExecuteRequest> {
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
        let checked = check_image(&snapshot.admitted, &request, fixture_time)?;
        assert_eq!(snapshot.proof(), &checked.proof);
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
            assert!(snapshot.join_current(current(), fixture_time).is_err());
        }
        Ok(())
    }

    fn current() -> Result<InstalledSelectorState, SelectorBoundaryError> {
        admitted_state().map_err(|_| SelectorBoundaryError::Io)
    }

    #[test]
    fn held_admission_bears_the_retained_root_descriptor_and_fresh_proof() -> TestResult {
        let snapshot = ProviderImageSnapshot::from_installation(
            admitted_state()?,
            request_fixture()?,
            fixture_time,
        )?;
        let admission = snapshot.join_current(current(), fixture_time)?;
        assert!(std::ptr::eq(admission.snapshot(), &raw const snapshot));
        assert_eq!(admission.proof(), snapshot.proof());
        assert_eq!(format!("{admission:?}"), "HeldImageAdmission { .. }");
        let held = snapshot.admitted.bootstrap().installed().artifact(
            InstallationObjectKind::ROOT_IMAGE,
            snapshot.image().manifest().root_image_blake3_digest,
        )?;
        let carried = rustix::fs::fstat(admission.as_fd())?;
        let retained = rustix::fs::fstat(held.file())?;
        assert_eq!(
            (carried.st_dev, carried.st_ino),
            (retained.st_dev, retained.st_ino)
        );
        let later = || fixture_time() + Duration::from_secs(1);
        assert_ne!(
            snapshot.join_current(current(), later)?.proof(),
            snapshot.proof()
        );
        Ok(())
    }

    // Deliberate exception: proof expiry is the one held-admission rejection
    // with no public-entry test. The public entry point uses the real host
    // clock by design, so a proof that expires between snapshot and admission
    // cannot be staged without an injectable production test bypass. Pending
    // SIR1, successor authority and held-descriptor mutation run through the
    // real `admit_held_image()` in the privileged root-selector test; the
    // private `join_current` cases for them here are additional unit evidence.
    #[test]
    fn held_admission_rejects_an_expired_proof_at_join_time() -> TestResult {
        let snapshot = ProviderImageSnapshot::from_installation(
            admitted_state()?,
            request_fixture()?,
            fixture_time,
        )?;
        let expired = || UNIX_EPOCH + Duration::from_secs(2_200_000_000);
        assert!(snapshot.join_current(current(), expired).is_err());
        Ok(())
    }

    #[test]
    fn held_admission_rejects_pending_recovery_and_successor_authority() -> TestResult {
        use crate::selector::installation::tests::updates::{complete_live_update, UpdateFixture};

        let fixture = UpdateFixture::new()?;
        let snapshot = ProviderImageSnapshot::from_installation(
            fixture.installed()?,
            request_fixture()?,
            fixture_time,
        )?;
        snapshot.join_current(fixture.installed(), fixture_time)?;

        // SIR1 is durable before any RCU1 is sent, so reopening fails closed.
        let committed = fixture.commit_live_update()?;
        assert!(fixture.installed().is_err());

        // The successor SIC1 selects the next RVS1 and APT1: the snapshot is stale.
        complete_live_update(committed)?;
        // The successor itself is admissible, so only the authority join rejects.
        fixture
            .installed()?
            .authenticate_bootstrap()?
            .admit_provider()?;
        let successor = fixture.installed()?;
        assert_ne!(
            successor.manifest().authority_digests(),
            snapshot
                .admitted
                .bootstrap()
                .installed()
                .manifest()
                .authority_digests()
        );
        assert!(snapshot.join_current(Ok(successor), fixture_time).is_err());
        Ok(())
    }

    #[test]
    fn provider_rejects_a_non_erofs_root_before_activation() -> TestResult {
        use crate::selector::installation::tests::{
            admitted_state_with_salt, ddi_fixture, ddi_partitions, ddi_salt, IMAGE_PROOF,
        };

        let (mut image, partitions) = ddi_fixture("x86-64")?;
        let magic = usize::try_from(partitions[0].start_bytes + EROFS_MAGIC_OFFSET)?;
        image[magic..magic + 4].copy_from_slice(&[0; 4]);
        let partitions = ddi_partitions("x86-64", &image)?;
        assert!(ProviderImageSnapshot::from_installation(
            admitted_state_with_salt(
                &image,
                b"adapter",
                &partitions,
                IMAGE_PROOF,
                ddi_salt("x86-64")?
            )?,
            request_fixture()?,
            fixture_time
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn provider_rejects_a_sim1_salt_other_than_the_held_superblock() -> TestResult {
        use crate::selector::installation::tests::{
            admitted_state_with_salt, ddi_fixture, ddi_salt, IMAGE_PROOF,
        };

        let (image, partitions) = ddi_fixture("x86-64")?;
        let mut other_salt = ddi_salt("x86-64")?;
        other_salt[0] ^= 1;
        assert!(ProviderImageSnapshot::from_installation(
            admitted_state_with_salt(&image, b"adapter", &partitions, IMAGE_PROOF, other_salt)?,
            request_fixture()?,
            fixture_time
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn verity_superblock_must_equal_sim1_on_both_architectures() -> TestResult {
        use std::io::Write as _;

        let write = |bytes: &[u8]| -> TestResult<File> {
            let mut file = tempfile::tempfile()?;
            file.write_all(bytes)?;
            Ok(file)
        };
        for architecture in ["x86-64", "arm64"] {
            let (image, partitions) =
                crate::selector::installation::tests::ddi_fixture(architecture)?;
            let salt = crate::selector::installation::tests::ddi_salt(architecture)?;
            let verity = &partitions[1];
            check_verity_superblock(&write(&image)?, verity, &salt)?;
            let mut other_salt = salt;
            other_salt[31] ^= 1;
            assert!(check_verity_superblock(&write(&image)?, verity, &other_salt).is_err());
            // Signature, version, hash type, algorithm, both block sizes, salt
            // size and salt each reject; the UUID and data-block count do not.
            let start = usize::try_from(verity.start_bytes)?;
            for (offset, rejects) in [
                (0, true),
                (8, true),
                (12, true),
                (16, false),
                (32, true),
                (40, true),
                (64, true),
                (68, true),
                (72, false),
                (80, true),
                (88, true),
                (119, true),
            ] {
                let mut changed = image.clone();
                changed[start + offset] ^= 1;
                assert_eq!(
                    check_verity_superblock(&write(&changed)?, verity, &salt).is_err(),
                    rejects,
                    "{architecture} offset {offset}"
                );
            }
            let mut short = verity.clone();
            short.length_bytes = u64::try_from(VERITY_SUPERBLOCK_PREFIX)? - 1;
            assert!(check_verity_superblock(&write(&image)?, &short, &salt).is_err());
            let mut beyond = verity.clone();
            beyond.start_bytes = u64::try_from(image.len())?;
            assert!(check_verity_superblock(&write(&image)?, &beyond, &salt).is_err());
        }
        Ok(())
    }

    #[test]
    fn erofs_precheck_accepts_systemd_repart_roots_on_both_architectures() -> TestResult {
        use std::io::Write as _;

        for architecture in ["x86-64", "arm64"] {
            let (image, partitions) =
                crate::selector::installation::tests::ddi_fixture(architecture)?;
            let mut file = tempfile::tempfile()?;
            file.write_all(&image)?;
            check_erofs_root(&file, &partitions[0])?;
            // The verity hash partition has no EROFS magic at byte 1024.
            assert!(check_erofs_root(&file, &partitions[1]).is_err());
            // The magic must lie inside the admitted root partition.
            let mut bounded = partitions[0].clone();
            bounded.length_bytes = EROFS_MAGIC_OFFSET + 4;
            check_erofs_root(&file, &bounded)?;
            bounded.length_bytes -= 1;
            assert!(check_erofs_root(&file, &bounded).is_err());
            let mut beyond = partitions[0].clone();
            beyond.start_bytes = u64::try_from(image.len())?;
            assert!(check_erofs_root(&file, &beyond).is_err());
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
