//! Privileged public-seam fixture: the fixed root-owned SIC1 installation.
//!
//! [`StagedInstallation::stage`] writes the signed test installation at the
//! fixed `/var/lib/pigloros/sandbox` path that [`super::ProviderImageSnapshot::open`]
//! reads, and returns a canonical SPX1 request naming its authority. It must
//! run as root inside the repository's isolated, disposable test container.
//! Every record is signed with fixed test-only keys and grants no authority
//! outside such a test.

use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::sandbox_provider_protocol::{
    ExecuteAuthority, PayloadDescriptor, RequestAuthority, SandboxExecuteRequest,
};
use crate::selector::installation::authority::AdmittedSelectorProvider;
use crate::selector::installation::fixture::{admitted_state, materialize_state};
use crate::selector::installation::{InstallationObjectKind, SANDBOX_ARTIFACT_ROOT};

const INSTALLATION_PARENT: &str = "/var/lib/pigloros";

/// The staged fixed installation, removed again when dropped.
#[derive(Debug)]
pub struct StagedInstallation {
    request: Vec<u8>,
    parent: (u64, u64),
}

impl StagedInstallation {
    /// Stage the signed test installation at the fixed root-owned path.
    ///
    /// # Errors
    /// Fails when the fixed installation parent already exists, so a host
    /// installation is never adopted or replaced, and on any write failure.
    pub fn stage() -> Result<Self, Box<dyn Error>> {
        let parent = Path::new(INSTALLATION_PARENT);
        if parent.exists() {
            return Err("the fixed installation parent already exists".into());
        }
        fs::create_dir(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        let mut staged = Self {
            request: Vec::new(),
            parent: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(SANDBOX_ARTIFACT_ROOT)?;
        fs::set_permissions(SANDBOX_ARTIFACT_ROOT, fs::Permissions::from_mode(0o700))?;
        let admitted = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), admitted_state()?)?;
        staged.request = request_for(&admitted)?;
        Ok(staged)
    }

    /// Canonical SPX1 bytes naming exactly the staged authority and image.
    #[must_use]
    pub const fn request(&self) -> &[u8] {
        self.request.as_slice()
    }
}

impl Drop for StagedInstallation {
    fn drop(&mut self) {
        let parent = Path::new(INSTALLATION_PARENT);
        let owned = fs::symlink_metadata(parent).is_ok_and(|metadata| {
            metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.parent
        });
        if owned {
            drop(fs::remove_dir_all(parent));
        }
    }
}

/// An SPX1 request whose checked authority is exactly the staged provider's.
///
/// Keep the authority fields in step with `provider_admission::tests::request_for`,
/// which patches the same fields onto the transport fixture's request.
///
/// Snapshot admission checks the APT1/TRS1/RVS1, provider, SIM1 and LPS1
/// digests and the policy epoch. The evaluation-side digests, identifiers and
/// input descriptor are fixed nonzero test values that it does not interpret.
fn request_for(admitted: &AdmittedSelectorProvider) -> Result<Vec<u8>, Box<dyn Error>> {
    let bootstrap = admitted.bootstrap();
    let provider = admitted.provider();
    let installed = |kind| {
        bootstrap
            .installed()
            .manifest()
            .objects()
            .iter()
            .find(|object| object.kind() == kind)
            .map(crate::selector::installation::InstallationObject::identity)
            .ok_or("the staged installation lacks an object")
    };
    let apt1_digest = bootstrap.policy().policy_digest();
    let request = SandboxExecuteRequest::for_selector(
        RequestAuthority {
            request_id: [1; 16],
            apt1_digest,
            policy_epoch: bootstrap.policy().policy_epoch(),
            nonce: [2; 16],
        },
        [3; 16],
        ExecuteAuthority {
            evr1_digest: [4; 32],
            cpf1_digest: [5; 32],
            cfb1_digest: [6; 32],
            fixture_contract_digest: [7; 32],
            fixture_digest: [8; 32],
            execution_profile_digest: [9; 32],
            lps1_digest: installed(InstallationObjectKind::LAUNCH_POLICY)?,
            sim1_digest: installed(InstallationObjectKind::IMAGE_MANIFEST)?,
            apt1_digest,
            trs1_digest: bootstrap.trust().snapshot_digest(),
            rvs1_digest: bootstrap.revocation().snapshot_digest(),
            spm1_digest: provider.manifest().manifest_digest,
            pcf1_digest: provider.manifest().pcf1_digest,
            pcr1_digest: provider.conformance_report().report_digest,
            hcp1_digest: provider.host_profile().profile_digest,
        },
        Vec::new(),
        PayloadDescriptor {
            byte_length: 5,
            digest: [10; 32],
        },
        Vec::new(),
    )?;
    Ok(request.to_canonical_cbor()?)
}
