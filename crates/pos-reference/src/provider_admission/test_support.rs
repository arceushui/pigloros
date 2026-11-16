//! Privileged public-seam fixture: the fixed root-owned SIC1 installation.
//!
//! [`StagedInstallation::stage`] writes the signed test installation at the
//! fixed `/var/lib/pigloros/sandbox` path that [`super::ProviderImageSnapshot::open`]
//! reads, and returns a canonical SPX1 request naming its authority. It must
//! run as root inside the repository's isolated, disposable test container,
//! or inside the disposable #444 QEMU evidence guest
//! ([`StagedInstallation::stage_image`]). Every record is signed with fixed
//! test-only keys and grants no authority outside such a test.

use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::sandbox_provider_protocol::{
    ExecuteAuthority, PartitionDescriptor, PartitionRole, PayloadDescriptor, RequestAuthority,
    SandboxArchitecture, SandboxExecuteRequest,
};
use crate::selector::installation::authority::AdmittedSelectorProvider;
use crate::selector::installation::fixture::{
    admitted_state, admitted_state_with_salt, ddi_fixture, materialize_state, ImageSigning,
};
use crate::selector::installation::{InstallationObjectKind, SANDBOX_ARTIFACT_ROOT};

const INSTALLATION_PARENT: &str = "/var/lib/pigloros";

/// A caller-built SIM1 DDI and the DER certificate whose key signed its root hash.
///
/// [`StagedInstallation::stage_image`] reads the partitions, the verity salt
/// and the signed root hash from the image itself, and names `certificate`
/// with `key_description` in the staged TRS1 and SIM1. Nothing checks that
/// the description is the kernel's description of the certificate.
///
/// The staged SIM1 names the executable `/adapter` with the BLAKE3 digest of
/// exactly the 7 bytes `adapter`, and activation reads it back through the
/// mounted root. An image that is to be activated must hold `/adapter` as a
/// regular file with exactly those bytes.
#[derive(Clone, Copy, Debug)]
pub struct StagedImage<'a> {
    /// The architecture of the image's root partitions and of every staged record.
    pub architecture: SandboxArchitecture,
    /// The raw GPT image: root, root-verity and root-verity-sig partitions.
    pub image: &'a [u8],
    /// The DER signer certificate the TRS1 and SIM1 bind.
    pub certificate: &'a [u8],
    /// The kernel key description the TRS1 and SIM1 carry for the certificate.
    pub key_description: &'a str,
}

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
        let (image, _) = ddi_fixture("x86-64")?;
        let signing = ImageSigning::ddi("x86-64")?;
        Self::stage_image(&StagedImage {
            architecture: signing.architecture,
            image: &image,
            certificate: &signing.certificate,
            key_description: &signing.key_description,
        })
    }

    /// [`Self::stage`], but around a caller-built image and its signer.
    ///
    /// # Errors
    /// Refuses an existing fixed installation, an image without exactly three
    /// GPT partitions, a root-verity-sig partition without a JSON `rootHash`
    /// and base64 `signature`, and any record the staged authority rejects.
    pub fn stage_image(image: &StagedImage<'_>) -> Result<Self, Box<dyn Error>> {
        let (partitions, signing, salt) = described(image)?;
        let state = admitted_state_with_salt(image.image, b"adapter", &partitions, &signing, salt)?;
        let mut staged = Self::create_parent()?;
        let admitted = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), state)?;
        staged.request = request_for(&admitted)?;
        Ok(staged)
    }

    /// Stage a complete authenticated EVR1/CFB1/TPS1 source and canonical input.
    ///
    /// # Errors
    /// Refuses an existing fixed installation and invalid fixture material.
    pub fn stage_execution() -> Result<Self, Box<dyn Error>> {
        let mut staged = Self::create_parent()?;
        let corpus = crate::selector_test_support::air_gapped_corpus()?;
        let (evaluation, state) =
            crate::selector::installation::fixture::execution_state(admitted_state()?, &corpus)?;
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
        Ok(staged)
    }

    /// Create the fixed, private installation directories, never adopting
    /// existing ones. The returned value removes them again when dropped.
    fn create_parent() -> Result<Self, Box<dyn Error>> {
        let parent = Path::new(INSTALLATION_PARENT);
        if parent.exists() {
            return Err("the fixed installation parent already exists".into());
        }
        fs::create_dir(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        let staged = Self {
            request: Vec::new(),
            evaluation: Vec::new(),
            input: Vec::new(),
            parent: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(SANDBOX_ARTIFACT_ROOT)?;
        fs::set_permissions(SANDBOX_ARTIFACT_ROOT, fs::Permissions::from_mode(0o700))?;
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

/// A DDI's three partition descriptors, its signing material and its verity salt.
type DescribedImage = ([PartitionDescriptor; 3], ImageSigning, [u8; 32]);

/// The partitions, signing material and verity salt a systemd-repart DDI carries.
///
/// The GPT entries are taken in table order, which systemd-repart writes as
/// root, root-verity and root-verity-sig; admission rejects any other order.
/// Every offset is checked: a malformed image is an error, never a panic.
fn described(image: &StagedImage<'_>) -> Result<DescribedImage, Box<dyn Error>> {
    const OVERFLOW: &str = "a GPT field overflows";
    let bytes = image.image;
    let sector = [512_usize, 4096]
        .into_iter()
        .find(|sector| bytes.get(*sector..*sector + 8) == Some(b"EFI PART".as_slice()))
        .ok_or("the image has no GPT header")?;
    let first_entry = usize::try_from(le64(bytes, sector + 72)?)?
        .checked_mul(sector)
        .ok_or(OVERFLOW)?;
    let count = usize::try_from(le32(bytes, sector + 80)?)?;
    let entry_size = usize::try_from(le32(bytes, sector + 84)?)?;
    if entry_size < 48 {
        return Err("a GPT entry is shorter than its fixed fields".into());
    }
    let sector_bytes = u64::try_from(sector)?;
    let mut partitions = Vec::new();
    for index in 0..count {
        let offset = index
            .checked_mul(entry_size)
            .and_then(|offset| offset.checked_add(first_entry))
            .ok_or(OVERFLOW)?;
        let entry = range(bytes, offset, entry_size)?;
        if entry[..16] == [0; 16] {
            continue;
        }
        let (first, last) = (le64(entry, 32)?, le64(entry, 40)?);
        let length = last
            .checked_sub(first)
            .and_then(|span| span.checked_add(1))
            .and_then(|sectors| sectors.checked_mul(sector_bytes))
            .ok_or("a GPT entry ends before it starts")?;
        let start = first.checked_mul(sector_bytes).ok_or(OVERFLOW)?;
        let content = range(bytes, usize::try_from(start)?, usize::try_from(length)?)?;
        partitions.push(PartitionDescriptor {
            role: [
                PartitionRole::RootData,
                PartitionRole::RootVerity,
                PartitionRole::RootVeritySignature,
            ]
            .get(partitions.len())
            .copied()
            .ok_or("the image has more than three partitions")?,
            partition_type_uuid: guid(&entry[..16]),
            partition_instance_uuid: guid(&entry[16..32]),
            start_bytes: start,
            length_bytes: length,
            content_blake3_digest: *blake3::hash(content).as_bytes(),
        });
    }
    let partitions: [PartitionDescriptor; 3] = partitions
        .try_into()
        .map_err(|_| "the image does not have exactly three partitions")?;
    // The format-1 verity superblock (cryptsetup `verity_sb`): a 32-byte salt.
    let superblock = extent(bytes, &partitions[1])?;
    if superblock.get(80..82) != Some([32, 0].as_slice()) {
        return Err("the verity superblock's salt is not 32 bytes".into());
    }
    let salt = range(superblock, 88, 32)?.try_into()?;
    let signature = extent(bytes, &partitions[2])?;
    let json = signature
        .iter()
        .position(|byte| *byte == 0)
        .map_or(signature, |end| &signature[..end]);
    let json: serde_json::Value = serde_json::from_slice(json)?;
    let root_hash = json["rootHash"]
        .as_str()
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("the root-verity-sig rootHash is not 64 lowercase hexadecimal digits")?;
    let root_hash = (0..32)
        .map(|index| u8::from_str_radix(&root_hash[2 * index..2 * index + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?
        .try_into()
        .map_err(|_| "the root-verity-sig rootHash is not 32 bytes")?;
    let proof = base64_decode(
        json["signature"]
            .as_str()
            .ok_or("the root-verity-sig JSON has no signature")?,
    )?;
    Ok((
        partitions,
        ImageSigning {
            architecture: image.architecture,
            root_hash,
            proof,
            certificate: image.certificate.to_vec(),
            key_description: image.key_description.to_owned(),
        },
        salt,
    ))
}

fn extent<'a>(
    bytes: &'a [u8],
    partition: &PartitionDescriptor,
) -> Result<&'a [u8], Box<dyn Error>> {
    range(
        bytes,
        usize::try_from(partition.start_bytes)?,
        usize::try_from(partition.length_bytes)?,
    )
}

fn range(bytes: &[u8], start: usize, length: usize) -> Result<&[u8], Box<dyn Error>> {
    start
        .checked_add(length)
        .and_then(|end| bytes.get(start..end))
        .ok_or_else(|| "a GPT extent lies outside the image".into())
}

fn le32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    Ok(u32::from_le_bytes(range(bytes, offset, 4)?.try_into()?))
}

fn le64(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_le_bytes(range(bytes, offset, 8)?.try_into()?))
}

/// A GPT GUID's mixed-endian bytes in RFC 4122 order, as SIM1 records them.
fn guid(bytes: &[u8]) -> [u8; 16] {
    let mut result: [u8; 16] = std::array::from_fn(|index| bytes[index]);
    result[..4].reverse();
    result[4..6].reverse();
    result[6..8].reverse();
    result
}

/// Standard padded base64, as systemd writes the root-verity-sig signature.
fn base64_decode(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if !text.len().is_multiple_of(4) {
        return Err("base64 length is not a multiple of four".into());
    }
    let mut output = Vec::with_capacity(text.len() / 4 * 3);
    for chunk in text.as_bytes().chunks(4) {
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        let mut value = 0_u32;
        for byte in &chunk[..4 - padding] {
            let digit = ALPHABET
                .iter()
                .position(|candidate| candidate == byte)
                .ok_or("invalid base64 digit")?;
            value = (value << 6) | u32::try_from(digit)?;
        }
        value <<= 6 * padding;
        output.extend_from_slice(&value.to_be_bytes()[1..4 - padding]);
    }
    Ok(output)
}

fn fixture_frame(writer: &mut impl std::io::Write, bytes: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(std::io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)
}
