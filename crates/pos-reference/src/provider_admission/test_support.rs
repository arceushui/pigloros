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

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::sandbox_provider_protocol::{
    Agr1, ExecuteAuthority, PartitionDescriptor, PartitionRole, PayloadDescriptor,
    RequestAuthority, SandboxArchitecture, SandboxExecuteRequest, SelfDigested, Verified,
};
use crate::selector::installation::authority::AdmittedSelectorProvider;
use crate::selector::installation::fixture::{
    admitted_state, admitted_state_with_arguments, ddi_fixture, materialize_state, ImageSigning,
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
/// `executable` and the fixed argument vector `arguments`, and activation
/// reads `/adapter` back through the mounted root. An image that is to be
/// activated must hold `/adapter` as a regular file with exactly the bytes of
/// `executable`.
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
    /// The exact bytes of the image's `/adapter`, whose digest the SIM1 binds.
    pub executable: &'a [u8],
    /// The SIM1's fixed adapter argument vector.
    pub arguments: &'a [String],
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
            executable: b"adapter",
            arguments: &[],
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
        let state = admitted_state_with_arguments(
            image.image,
            image.executable,
            &partitions,
            &signing,
            salt,
            image.arguments,
        )?;
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
            fixture_nonce(),
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

    /// The installed test runtime signer, used only inside disposable
    /// fixtures: it signs the sealed AGR1 and verifies before returning it.
    ///
    /// # Errors
    /// None in practice: the signature verifies under its own key.
    pub fn sign_grant(record: SelfDigested<Agr1>) -> std::io::Result<Verified<Agr1>> {
        Self::sign_grant_with(&[4; 32], record)
    }

    /// Sign the sealed AGR1 with the Ed25519 seed `seed` and verify it under
    /// that seed's own public key, which need not be the admitted one.
    ///
    /// # Errors
    /// None in practice: the signature verifies under its own key.
    pub fn sign_grant_with(
        seed: &[u8; 32],
        record: SelfDigested<Agr1>,
    ) -> std::io::Result<Verified<Agr1>> {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        let signature = key.sign(&record.signature_message()).to_bytes();
        record
            .verify(signature, &key.verifying_key())
            .map_err(std::io::Error::other)
    }
}

#[cfg(target_os = "linux")]
impl StagedInstallation {
    /// Read the source the selector end wrote to `provider` once and admit
    /// it, as a runtime that retained the staged installation at startup
    /// would: every mode is supported and no lifecycle claim is taken.
    ///
    /// # Errors
    /// A peer that is not root, and any read or admission refusal.
    pub fn admit_source(
        provider: std::os::unix::net::UnixStream,
        ledger: &super::execution::StagingLedger,
    ) -> Result<super::execution::PreparedProviderExecution, String> {
        use super::execution::{ExecutePeer, ExecuteSource, PreparedProviderExecution};
        let installation = crate::selector::installation::InstalledSelectorState::open()
            .and_then(crate::selector::installation::InstalledSelectorState::authenticate_bootstrap)
            .and_then(crate::selector::installation::authority::AuthenticatedSelectorBootstrap::admit_provider)
            .map(std::sync::Arc::new)
            .map_err(|error| error.to_string())?;
        let peer = ExecutePeer::authenticate(provider).map_err(|_| "the peer is not root")?;
        let source = ExecuteSource::read(peer, ledger, &installation)
            .map_err(|refusal| format!("{refusal:?}"))?;
        PreparedProviderExecution::admit(
            source,
            ledger,
            &installation,
            |_| true,
            |_| Ok::<(), std::convert::Infallible>(()),
        )
        .map_err(|refusal| format!("{refusal:?}"))
    }

    /// Create the staging file of `prepared` as `name` in `staging`, then
    /// write its AGR1 under the test runtime key.
    ///
    /// # Errors
    /// Any refusal of the staging file or the grant.
    pub fn grant_staged(
        staging: &super::execution::StagingDirectory,
        name: [u8; 16],
        prepared: super::execution::PreparedProviderExecution,
    ) -> Result<super::execution::GrantedInput, String> {
        staging
            .create_input(name, prepared)
            .map_err(|refusal| format!("{refusal:?}"))?
            .send_grant(Self::sign_grant, |(), _| {
                Ok::<(), std::convert::Infallible>(())
            })
            .map(|((), granted)| granted)
            .map_err(|failure| format!("{failure:?}"))
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
    let bytes = image.image;
    let sector = [512_u64, 4096]
        .into_iter()
        .find(|sector| range(bytes, *sector, 8).is_ok_and(|magic| magic == b"EFI PART"))
        .ok_or("the image has no GPT header")?;
    let first_entry = le64(bytes, sector + 72)?
        .checked_mul(sector)
        .ok_or("a GPT field overflows")?;
    let (count, entry_size) = (le32(bytes, sector + 80)?, le32(bytes, sector + 84)?);
    if entry_size < 48 {
        return Err("a GPT entry is shorter than its fixed fields".into());
    }
    // Both factors are 32-bit, so the table length cannot overflow 64 bits.
    let table = range(bytes, first_entry, u64::from(count) * u64::from(entry_size))?;
    let mut partitions = Vec::new();
    for entry in table.chunks_exact(entry_size as usize) {
        if entry[..16] == [0; 16] {
            continue;
        }
        let (first, last) = (le64(entry, 32)?, le64(entry, 40)?);
        let length = last
            .checked_sub(first)
            .and_then(|span| span.checked_add(1))
            .and_then(|sectors| sectors.checked_mul(sector))
            .ok_or("a GPT entry ends before it starts or overflows")?;
        let start = first.checked_mul(sector).ok_or("a GPT field overflows")?;
        let content = range(bytes, start, length)?;
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
    // cryptsetup's format-1 `verity_sb`: signature, version 1, hash type 1,
    // the salt size at 80 and a 32-byte salt from 88, as the checker reads it.
    let superblock = extent(bytes, &partitions[1])?;
    if superblock.get(..8) != Some(b"verity\0\0".as_slice()) {
        return Err("the root-verity partition has no verity superblock".into());
    }
    if superblock.get(8..16) != Some([1, 0, 0, 0, 1, 0, 0, 0].as_slice()) {
        return Err("the verity superblock is not version 1 with hash type 1".into());
    }
    if superblock.get(80..82) != Some([32, 0].as_slice()) {
        return Err("the verity superblock's salt is not 32 bytes".into());
    }
    let field = range(superblock, 88, 32)?;
    let salt: [u8; 32] = std::array::from_fn(|index| field[index]);
    let signature = extent(bytes, &partitions[2])?;
    let json = signature
        .iter()
        .position(|byte| *byte == 0)
        .map_or(signature, |end| &signature[..end]);
    let json: serde_json::Value = serde_json::from_slice(json)
        .map_err(|_| "the root-verity-sig partition is not one JSON value")?;
    let root_hash = json["rootHash"]
        .as_str()
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("the root-verity-sig rootHash is not 64 lowercase hexadecimal digits")?;
    let mut root_hash_bytes = [0; 32];
    for (byte, pair) in root_hash_bytes
        .iter_mut()
        .zip(root_hash.as_bytes().chunks_exact(2))
    {
        *byte = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    // Standard padded base64, as systemd writes the root-verity-sig signature.
    let proof = STANDARD
        .decode(
            json["signature"]
                .as_str()
                .ok_or("the root-verity-sig JSON has no signature")?,
        )
        .map_err(|error| format!("the root-verity-sig signature is not base64: {error}"))?;
    Ok((
        partitions,
        ImageSigning {
            architecture: image.architecture,
            root_hash: root_hash_bytes,
            proof,
            certificate: image.certificate.to_vec(),
            key_description: image.key_description.to_owned(),
        },
        salt,
    ))
}

/// One lowercase hexadecimal digit that the caller already validated.
const fn hex_value(digit: u8) -> u8 {
    if digit.is_ascii_digit() {
        digit - b'0'
    } else {
        digit - b'a' + 10
    }
}

fn extent<'a>(
    bytes: &'a [u8],
    partition: &PartitionDescriptor,
) -> Result<&'a [u8], Box<dyn Error>> {
    range(bytes, partition.start_bytes, partition.length_bytes)
}

/// The execute request's nonce, derived from a fixture label.
fn fixture_nonce() -> [u8; 16] {
    let digest = blake3::hash(b"PiglorOS.ProviderAdmissionFixtureNonce.v1\0");
    std::array::from_fn(|index| digest.as_bytes()[index])
}

fn range(bytes: &[u8], start: u64, length: u64) -> Result<&[u8], Box<dyn Error>> {
    start
        .checked_add(length)
        .and_then(|end| Some((usize::try_from(start).ok()?, usize::try_from(end).ok()?)))
        .and_then(|(start, end)| bytes.get(start..end))
        .ok_or_else(|| "a GPT extent lies outside the image".into())
}

fn le32(bytes: &[u8], offset: u64) -> Result<u32, Box<dyn Error>> {
    range(bytes, offset, 4)
        .map(|field| u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn le64(bytes: &[u8], offset: u64) -> Result<u64, Box<dyn Error>> {
    range(bytes, offset, 8)
        .map(|field| u64::from_le_bytes(std::array::from_fn(|index| field[index])))
}

/// A GPT GUID's mixed-endian bytes in RFC 4122 order, as SIM1 records them.
fn guid(bytes: &[u8]) -> [u8; 16] {
    let mut result: [u8; 16] = std::array::from_fn(|index| bytes[index]);
    result[..4].reverse();
    result[4..6].reverse();
    result[6..8].reverse();
    result
}

fn fixture_frame(writer: &mut impl std::io::Write, bytes: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(std::io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::{described, StagedImage};
    use crate::sandbox_provider_protocol::SandboxArchitecture;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// An expected refusal and the change to a valid DDI that causes it.
    type Case = (&'static str, fn(&mut Ddi));

    const ROOT_HASH: &str = "37e96f27ede7ca8a5e8eacd73dac416207f0cd8457df12055ca2492cd1be7457";

    /// A minimal three-partition GPT DDI at 512-byte sectors: one data
    /// sector, a verity superblock and the root-verity-sig JSON.
    struct Ddi {
        bytes: Vec<u8>,
    }

    impl Ddi {
        fn new() -> Self {
            let mut ddi = Self {
                bytes: vec![0; 512 * 8],
            };
            ddi.bytes[512..520].copy_from_slice(b"EFI PART");
            ddi.set_u64(512 + 72, 2);
            ddi.set_u32(512 + 80, 3);
            ddi.set_u32(512 + 84, 128);
            for (index, sector) in [5_u64, 6, 7].into_iter().enumerate() {
                let entry = 1024 + 128 * index;
                ddi.bytes[entry..entry + 16].fill(u8::try_from(index + 1).unwrap_or(0));
                ddi.bytes[entry + 16..entry + 32].fill(0xa0);
                ddi.set_u64(entry + 32, sector);
                ddi.set_u64(entry + 40, sector);
            }
            ddi.bytes[6 * 512..6 * 512 + 8].copy_from_slice(b"verity\0\0");
            ddi.set_u32(6 * 512 + 8, 1);
            ddi.set_u32(6 * 512 + 12, 1);
            ddi.bytes[6 * 512 + 80] = 32;
            ddi.bytes[6 * 512 + 88..6 * 512 + 120].fill(0x45);
            ddi.signature(ROOT_HASH);
            ddi
        }

        fn signature(&mut self, root_hash: &str) {
            let json = format!(r#"{{"rootHash":"{root_hash}","signature":"AQID"}}"#);
            self.bytes[7 * 512..8 * 512].fill(0);
            self.bytes[7 * 512..7 * 512 + json.len()].copy_from_slice(json.as_bytes());
        }

        fn set_u32(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn set_u64(&mut self, offset: usize, value: u64) {
            self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        fn refusal(&self) -> String {
            described(&StagedImage {
                architecture: SandboxArchitecture::X86_64,
                image: &self.bytes,
                certificate: b"certificate",
                key_description: "CN: 01",
                executable: b"adapter",
                arguments: &[],
            })
            .err()
            .map_or_else(|| "accepted".to_owned(), |error| error.to_string())
        }
    }

    #[test]
    fn a_well_formed_ddi_is_described_from_its_own_bytes() -> TestResult {
        let ddi = Ddi::new();
        let (partitions, signing, salt) = described(&StagedImage {
            architecture: SandboxArchitecture::Aarch64,
            image: &ddi.bytes,
            certificate: b"certificate",
            key_description: "CN: 01",
            executable: b"adapter",
            arguments: &[],
        })?;
        assert_eq!(
            partitions
                .each_ref()
                .map(|partition| (partition.start_bytes, partition.length_bytes)),
            [(5 * 512, 512), (6 * 512, 512), (7 * 512, 512)]
        );
        assert_eq!(partitions[1].partition_type_uuid, [2; 16]);
        assert_eq!(salt, [0x45; 32]);
        assert_eq!(signing.root_hash[0], 0x37);
        assert_eq!(signing.proof, [1, 2, 3]);
        assert_eq!(signing.architecture, SandboxArchitecture::Aarch64);
        Ok(())
    }

    #[test]
    fn every_malformed_field_is_an_error_not_a_panic() {
        let cases: [Case; 21] = [
            ("no GPT header", |ddi| {
                ddi.bytes[512] = b'X';
            }),
            ("shorter than its fixed fields", |ddi| {
                ddi.set_u32(512 + 84, 47);
            }),
            ("overflows", |ddi| {
                ddi.set_u64(512 + 72, u64::MAX);
            }),
            ("outside the image", |ddi| {
                ddi.set_u64(512 + 72, 8);
            }),
            ("ends before it starts", |ddi| {
                ddi.set_u64(1024 + 40, 4);
            }),
            ("ends before it starts", |ddi| {
                ddi.set_u64(1024 + 40, u64::MAX);
            }),
            ("overflows", |ddi| {
                ddi.set_u64(1024 + 32, u64::MAX / 2);
                ddi.set_u64(1024 + 40, u64::MAX / 2);
            }),
            ("exactly three partitions", |ddi| {
                ddi.bytes[1024 + 256..1024 + 272].fill(0);
            }),
            ("more than three partitions", |ddi| {
                ddi.set_u32(512 + 80, 4);
                ddi.bytes[1024 + 384..1024 + 400].fill(4);
                ddi.set_u64(1024 + 384 + 32, 5);
                ddi.set_u64(1024 + 384 + 40, 5);
            }),
            // A verity extent cut short by the end of the image.
            ("outside the image", |ddi| {
                ddi.bytes.truncate(6 * 512 + 100);
            }),
            ("no verity superblock", |ddi| {
                ddi.bytes[6 * 512] = b'X';
            }),
            ("version 1 with hash type 1", |ddi| {
                ddi.bytes[6 * 512 + 8] = 2;
            }),
            ("not one JSON value", |ddi| {
                ddi.bytes[7 * 512..7 * 512 + 8].copy_from_slice(b"not json");
            }),
            ("64 lowercase hexadecimal", |ddi| {
                let json = br#"{"signature":"AQID"}"#;
                ddi.bytes[7 * 512..8 * 512].fill(0);
                ddi.bytes[7 * 512..7 * 512 + json.len()].copy_from_slice(json);
            }),
            ("salt is not 32 bytes", |ddi| {
                ddi.bytes[6 * 512 + 80] = 64;
            }),
            ("64 lowercase hexadecimal", |ddi| {
                ddi.signature(&ROOT_HASH.to_uppercase());
            }),
            ("64 lowercase hexadecimal", |ddi| {
                ddi.signature(&ROOT_HASH[..62]);
            }),
            ("64 lowercase hexadecimal", |ddi| {
                ddi.signature(&ROOT_HASH.replace('3', "g"));
            }),
            ("the root-verity-sig JSON has no signature", |ddi| {
                let json = format!(r#"{{"rootHash":"{ROOT_HASH}"}}"#);
                ddi.bytes[7 * 512..7 * 512 + json.len()].copy_from_slice(json.as_bytes());
                ddi.bytes[7 * 512 + json.len()..8 * 512].fill(0);
            }),
            ("the root-verity-sig signature is not base64", |ddi| {
                let json = format!(r#"{{"rootHash":"{ROOT_HASH}","signature":"A"}}"#);
                ddi.bytes[7 * 512..7 * 512 + json.len()].copy_from_slice(json.as_bytes());
                ddi.bytes[7 * 512 + json.len()..8 * 512].fill(0);
            }),
            ("the root-verity-sig signature is not base64", |ddi| {
                let json = format!(r#"{{"rootHash":"{ROOT_HASH}","signature":"AQ!D"}}"#);
                ddi.bytes[7 * 512..7 * 512 + json.len()].copy_from_slice(json.as_bytes());
                ddi.bytes[7 * 512 + json.len()..8 * 512].fill(0);
            }),
        ];
        for (expected, change) in cases {
            let mut ddi = Ddi::new();
            change(&mut ddi);
            let refusal = ddi.refusal();
            assert!(refusal.contains(expected), "{expected}: {refusal}");
        }
    }
}
