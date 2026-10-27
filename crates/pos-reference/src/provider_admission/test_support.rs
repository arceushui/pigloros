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
    evaluation: Vec<u8>,
    input: Vec<u8>,
    parent: (u64, u64),
}

impl StagedInstallation {
    /// Stage the signed test installation at the fixed root-owned path.
    ///
    /// # Errors
    /// Fails when the fixed installation parent already exists, so a host
    /// installation is never adopted or replaced, and on any write failure.
    pub fn stage() -> Result<Self, Box<dyn Error>> {
        Self::stage_with_source(false)
    }

    /// Stage a complete authenticated EVR1/CFB1/TPS1 source and canonical input.
    ///
    /// # Errors
    /// Refuses an existing fixed installation and invalid fixture material.
    pub fn stage_execution() -> Result<Self, Box<dyn Error>> {
        Self::stage_with_source(true)
    }

    fn stage_with_source(execution: bool) -> Result<Self, Box<dyn Error>> {
        let parent = Path::new(INSTALLATION_PARENT);
        if parent.exists() {
            return Err("the fixed installation parent already exists".into());
        }
        fs::create_dir(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        let mut staged = Self {
            request: Vec::new(),
            evaluation: Vec::new(),
            input: Vec::new(),
            parent: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(SANDBOX_ARTIFACT_ROOT)?;
        fs::set_permissions(SANDBOX_ARTIFACT_ROOT, fs::Permissions::from_mode(0o700))?;
        if execution {
            let corpus = crate::selector_test_support::air_gapped_corpus()?;
            let (evaluation, state) = crate::selector::installation::fixture::execution_state(
                admitted_state()?,
                &corpus,
            )?;
            let admitted = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), state)?;
            let resolved = admitted
                .bootstrap()
                .resolve_installed_case(&evaluation, 0)?;
            crate::adapter_transport::write_attempt(&mut staged.input, resolved.attempt())?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"PiglorOS.SandboxInputBytes.v1\0");
            hasher.update(&staged.input);
            let input = PayloadDescriptor {
                byte_length: staged.input.len() as u64,
                digest: *hasher.finalize().as_bytes(),
            };
            let request = crate::selector_protocol::execute_request_for_case(
                &admitted,
                &evaluation,
                &resolved,
                input,
                0,
                [2; 16],
            )?;
            staged.request = request.to_canonical_cbor()?;
            staged.evaluation = evaluation.to_canonical_cbor()?;
        } else {
            let admitted = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), admitted_state()?)?;
            staged.request = request_for(&admitted)?;
        }
        Ok(staged)
    }

    /// Canonical SPX1 bytes naming exactly the staged authority and image.
    #[must_use]
    pub const fn request(&self) -> &[u8] {
        self.request.as_slice()
    }
    /// Canonical EVR1 for the complete execution fixture.
    #[must_use]
    pub fn evaluation(&self) -> &[u8] {
        &self.evaluation
    }

    /// Exact canonical EAI1..EIE1 input for this selected case.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Encode a self-consistent but deliberately substituted SPX1 for refusal tests.
    ///
    /// # Errors
    /// Rejects a mutation that violates the record codec itself.
    pub fn changed_request(
        &self,
        change: impl FnOnce(&mut SandboxExecuteRequest),
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut request = SandboxExecuteRequest::from_canonical_cbor(&self.request)?;
        change(&mut request);
        Ok(SandboxExecuteRequest::for_selector(
            request.request,
            request.attempt_id,
            request.authority,
            request.capability_ids,
            request.adapter_input,
            request.network_plans,
        )?
        .to_canonical_cbor()?)
    }

    /// Bind a changed, internally valid EAI1 case under the original fixture identity.
    ///
    /// This produces adversarial source bytes, never an admitted policy.
    ///
    /// # Errors
    /// Rejects a malformed changed case or record.
    pub fn changed_case_request(
        &self,
        change: impl FnOnce(&mut crate::evaluator::CaseAttempt),
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut attempt = crate::adapter_transport::read_attempt(self.input.as_slice())?;
        change(&mut attempt);
        let mut input = Vec::new();
        crate::adapter_transport::write_attempt(&mut input, &attempt)?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"PiglorOS.SandboxInputBytes.v1\0");
        hash.update(&input);
        self.changed_request(|request| {
            request.adapter_input = PayloadDescriptor {
                byte_length: input.len() as u64,
                digest: *hash.finalize().as_bytes(),
            }
        })
    }

    /// Write the two initial length-prefixed source records.
    ///
    /// # Errors
    /// Returns framing or stream I/O errors.
    pub fn write_source(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        for record in [&self.evaluation, &self.request] {
            fixture_frame(writer, record)?;
        }
        Ok(())
    }

    /// Write exact SPX1-bound input chunks after the provider issued AGR1.
    ///
    /// # Errors
    /// Returns a malformed fixture or stream I/O failure.
    pub fn write_input(&self, writer: &mut impl std::io::Write) -> Result<(), Box<dyn Error>> {
        use crate::evaluator_protocol::encode;
        use ciborium::value::Value;
        let request = SandboxExecuteRequest::from_canonical_cbor(&self.request)?;
        for (index, bytes) in self.input.chunks(1024 * 1024).enumerate() {
            let unsigned = Value::Array(vec![
                Value::Text("SBC1".to_owned()),
                Value::Integer(1.into()),
                Value::Bytes(request.request_digest.to_vec()),
                Value::Bytes(request.request.request_id.to_vec()),
                Value::Bytes(request.attempt_id.to_vec()),
                Value::Integer(0.into()),
                Value::Integer((index as u64).into()),
                Value::Integer(((index * 1024 * 1024) as u64).into()),
                Value::Bytes(bytes.to_vec()),
            ]);
            let mut hash = blake3::Hasher::new();
            hash.update(b"PiglorOS.SBC1.v1\0");
            hash.update(&encode(&unsigned)?);
            fixture_frame(
                writer,
                &encode(&Value::Array(vec![
                    unsigned,
                    Value::Bytes(hash.finalize().as_bytes().to_vec()),
                ]))?,
            )?;
        }
        Ok(())
    }

    /// The installed test runtime signer, used only inside disposable fixtures.
    #[must_use]
    pub fn sign_grant(message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        ed25519_dalek::SigningKey::from_bytes(&[4; 32])
            .sign(message)
            .to_bytes()
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

fn fixture_frame(writer: &mut impl std::io::Write, bytes: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(std::io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)
}
