//! Independent provider image evidence from the fixed SIC1 installation.
//!
//! A snapshot retains its own descriptors and authenticates the authorities
//! named by SPX1, including the first adapter's signed-EROFS root precheck.
//! Only [`ProviderImageSnapshot::admit_held_image`] joins that evidence to the
//! currently installed authority and yields the descriptor-bearing admission
//! for later image activation. Neither value is a mount or launch permit.

use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::Deserializer as _;

use crate::sandbox_provider_protocol::{
    AdmittedSandboxImage, LaunchPolicy, PartitionDescriptor, SandboxExecuteRequest,
    SignedImageManifest, VerifiedSandboxImageProof,
};
use crate::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use crate::selector::installation::{
    InstallationObjectKind, InstalledSelectorState, SANDBOX_ARTIFACT_ROOT,
};
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
// systemd v260.2 `acquire_sig_for_roothash` refuses a signature partition
// larger than this (src/shared/dissect-image.c L744: `partition_size > 4*1024*1024`).
const VERITY_SIGNATURE_LIMIT: usize = 4 * 1024 * 1024;

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
    binary: AdmittedProviderBinary,
}

/// The selected SIC1 provider executable, also the ADR-069 release launcher.
///
/// Only snapshot admission constructs this view. SIC1 has already opened the
/// root-owned mode-0500 content-addressed file without symlink traversal,
/// verified its bytes, and bound that digest to SPM1/APT1. The retained
/// descriptor supplies its device and inode; callers cannot supply these facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedProviderBinary {
    path: String,
    digest: [u8; 32],
    length: u64,
    device: u64,
    inode: u64,
}

impl AdmittedProviderBinary {
    /// The fixed, digest-addressed SIC1 source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The SPM1/APT1-bound BLAKE3 digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Exact admitted byte length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Device and inode of the retained installation descriptor.
    #[must_use]
    pub const fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
}

fn provider_binary(
    admitted: &AdmittedSelectorProvider,
) -> Result<AdmittedProviderBinary, SelectorBoundaryError> {
    let digest = admitted.provider().manifest().binary_digest;
    admitted
        .bootstrap()
        .installed()
        .artifact(InstallationObjectKind::PROVIDER_EXECUTABLE, digest)
        .and_then(|artifact| {
            artifact
                .file()
                .metadata()
                .map_err(invalid)
                .map(|metadata| AdmittedProviderBinary {
                    path: format!("{SANDBOX_ARTIFACT_ROOT}/providers/{}", lower_hex(&digest)),
                    digest,
                    length: artifact.object().byte_length(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                })
        })
}

impl ProviderImageSnapshot {
    /// Open the fixed installation and independently check SPX1's image inputs.
    ///
    /// # Errors
    /// Rejects malformed requests, pending installation recovery, unsafe files,
    /// unauthenticated or inconsistent authority, invalid image/GPT/executable
    /// bytes, a non-EROFS root, a mismatched verity superblock, a
    /// root-verity-sig partition whose JSON is malformed or names another root
    /// hash or signature than SIM1, unaccepted launch policy, and invalid or
    /// time-expired CMS proofs.
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
                provider_binary(&admitted).and_then(|binary| {
                    let CheckedImage { image, proof, .. } =
                        check_image(&admitted, &request, clock)?;
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
                                binary,
                            })
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

    /// The retained, authenticated provider executable used as the launcher.
    #[must_use]
    pub const fn provider_binary(&self) -> &AdmittedProviderBinary {
        &self.binary
    }

    /// Runtime signing identity selected by the authenticated SPM1.
    #[must_use]
    pub fn runtime_attestation_key_id(&self) -> &str {
        &self
            .admitted
            .provider()
            .manifest()
            .runtime_attestation_key_id
    }

    /// Runtime verifying key authenticated during provider admission.
    #[must_use]
    pub const fn runtime_attestation_key(&self) -> &ed25519_dalek::VerifyingKey {
        self.admitted.provider().runtime_attestation_key()
    }

    /// Exact SCS1 selected by the admitted APT1/provider authority.
    #[must_use]
    pub const fn syscall_set(&self) -> &crate::sandbox_provider_protocol::SandboxSyscallSet {
        self.admitted.provider().syscall_set()
    }

    /// Join this snapshot's retained image to the currently installed authority.
    ///
    /// The fixed installation is reopened: a pending SIR1 update rejects, and
    /// its authenticated APT1/TRS1/RVS1 and provider records must still be the
    /// exact authority this snapshot's SPX1 named. The selector commits SIR1
    /// before sending any RCU1 and removes it only after installing the
    /// successor SIC1, so at the instants checked a committed newer revocation
    /// is either pending or installed, and both reject. The same retained image,
    /// GPT, executable, EROFS root, verity superblock, root-verity-sig JSON and
    /// CMS proof are then rechecked at fresh host time.
    ///
    /// This is a point-in-time check against installed selector heads, not a
    /// provider-held RVS1 floor or attempt reservation. A revocation committed
    /// during or after the call is handled only by RCU1 live-attempt
    /// cancellation, post-activation readback and the `StartTransientUnit`
    /// RVS1 recheck, which remain mandatory.
    ///
    /// # Errors
    /// Rejects pending recovery, stale or substituted authority, changed image
    /// inputs, a non-EROFS root, a mismatched verity superblock or
    /// root-verity-sig JSON, or a proof no longer valid at host time.
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
            .and_then(|authority| {
                check_image(&self.admitted, &self.request, clock).map(|checked| {
                    HeldImageAdmission {
                        snapshot: self,
                        root_image: checked.root_image,
                        proof: checked.proof,
                        authority,
                    }
                })
            })
    }
}

/// One snapshot's retained image, admitted against current installed authority.
///
/// Only [`ProviderImageSnapshot::admit_held_image`] constructs this value. It
/// borrows the snapshot, and [`AsFd`] yields exactly the retained root-image
/// descriptor that every image, GPT, EROFS, verity superblock,
/// root-verity-sig and CMS check read; no caller can supply or substitute a
/// descriptor, proof or authority. It has no public constructor, `Clone` or
/// serialization, and grants no mount, launch or output authority by itself.
pub struct HeldImageAdmission<'snapshot> {
    snapshot: &'snapshot ProviderImageSnapshot,
    root_image: &'snapshot File,
    proof: VerifiedSandboxImageProof,
    authority: AdmittedAuthority,
}

/// The installed authority one admission was joined against.
///
/// It is read in the same step that proved the request's authority equals the
/// installed heads, so a provider that takes its entry reservation and
/// control-floor comparison from this value cannot race a later re-read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedAuthority {
    /// The installed APT1 digest.
    pub apt1_digest: [u8; 32],
    /// The installed TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// The installed RVS1 digest.
    pub rvs1_digest: [u8; 32],
    /// The installed trust epoch.
    pub trust_epoch: u64,
    /// The installed revocation epoch.
    pub revocation_epoch: u64,
    /// The installed policy epoch.
    pub policy_epoch: u64,
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

    /// The installed authority this admission was joined against.
    #[must_use]
    pub const fn authority(&self) -> AdmittedAuthority {
        self.authority
    }

    /// Re-read the installed authority and require it to still be the one
    /// this admission's request names (ADR-087 §2 step 7, immediately before
    /// `StartTransientUnit`).
    ///
    /// The fixed installation is reopened: a pending SIR1 update rejects, and
    /// the installed APT1, TRS1, RVS1 and provider records must still be the
    /// exact authority the request named. Because every digest binds its
    /// epoch, success returns the same authority that was admitted.
    ///
    /// # Errors
    /// Rejects pending recovery and any stale or substituted authority.
    pub fn recheck_authority(&self) -> Result<AdmittedAuthority, SelectorBoundaryError> {
        self.recheck_with(InstalledSelectorState::open())
    }

    fn recheck_with(
        &self,
        current: Result<InstalledSelectorState, SelectorBoundaryError>,
    ) -> Result<AdmittedAuthority, SelectorBoundaryError> {
        current
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(AuthenticatedSelectorBootstrap::admit_provider)
            .and_then(|current| check_authority(&current, &self.snapshot.request))
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
) -> Result<AdmittedAuthority, SelectorBoundaryError> {
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
    Ok(AdmittedAuthority {
        apt1_digest: authority.apt1_digest,
        trs1_digest: authority.trs1_digest,
        rvs1_digest: authority.rvs1_digest,
        trust_epoch: bootstrap.trust().trust_epoch(),
        revocation_epoch: bootstrap.revocation().revocation_epoch(),
        policy_epoch: bootstrap.policy().policy_epoch(),
    })
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
            let manifest = image.manifest();
            check_verity_signature(
                root_image.file(),
                &manifest.partitions[2],
                &manifest.root_hash_sha256,
                &manifest.root_hash_signature.der_bytes,
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

/// The two values systemd activates with, from the root-verity-sig JSON object.
struct VeritySignatureJson {
    root_hash: String,
    signature: String,
}

/// ADR-087 Part B.4 object shape (rev 31, accepted in rev 32).
///
/// Exactly one `rootHash` and one `signature` key, each with a string value.
/// Other keys, including `certificateFingerprint`, are skipped without being
/// interpreted, as systemd v260.2 does. Any duplicate key, or a key that
/// contains U+0000, rejects, where systemd would take the first match. Only
/// a JSON object reaches `visit_map`; an array, which systemd's key lookup
/// also rejects, does not.
struct JsonObject;

impl<'de> Visitor<'de> for JsonObject {
    type Value = VeritySignatureJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a root-verity-sig JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = BTreeSet::new();
        let (mut root_hash, mut signature) = (None, None);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "rootHash" => root_hash = Some(map.next_value::<String>()?),
                "signature" => signature = Some(map.next_value::<String>()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            // systemd's tokenizer decodes `\u0000` into a NUL byte and then
            // truncates the key at it, so `rootHash\u0000` would be the first
            // `rootHash` systemd finds; reject such keys like duplicates.
            if key.contains('\0') || !keys.insert(key) {
                return Err(A::Error::custom(
                    "duplicate or NUL-bearing root-verity-sig key",
                ));
            }
        }
        root_hash
            .zip(signature)
            .map(|(root_hash, signature)| VeritySignatureJson {
                root_hash,
                signature,
            })
            .ok_or_else(|| A::Error::custom("missing rootHash or signature"))
    }
}

/// Parse exactly one JSON object, with no whitespace before or after it.
///
/// systemd v260.2 rejects a raw DEL (0x7f) that `serde_json` accepts in a
/// string, so it rejects here too.
fn parse_verity_signature(text: &[u8]) -> Result<VeritySignatureJson, SelectorBoundaryError> {
    if text.contains(&0x7f)
        || [text.first(), text.last()]
            .into_iter()
            .flatten()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(text);
    deserializer
        .deserialize_map(JsonObject)
        .and_then(|json| deserializer.end().map(|()| json))
        .map_err(invalid)
}

/// Pre-activation root-verity-sig binding over the same held image.
///
/// systemd reads the root hash and PKCS#7 signature it activates with from
/// the JSON in SIM1's root-verity-sig partition (ordinal 2), not from SIM1.
/// ADR-087 Part B.4 (rev 31, accepted in rev 32) requires that partition to
/// be one JSON object followed only by NUL bytes, within systemd's 4 MiB
/// bound. `rootHash` must be exactly 64 hexadecimal digits that decode to
/// SIM1's root hash: equality to its hex encoding, ignoring ASCII case.
/// `signature` must be standard padded base64 without whitespace that
/// decodes to SIM1's exact PKCS#7 proof bytes: equality to the canonical
/// encoding of those bytes. Standard base64 with zero pad bits, which
/// systemd's decoder also requires, has exactly one encoding per byte
/// string, so this equals a strict decode compared byte for byte.
fn check_verity_signature(
    root_image: &File,
    signature: &PartitionDescriptor,
    root_hash: &[u8; 32],
    proof: &[u8],
) -> Result<(), SelectorBoundaryError> {
    usize::try_from(signature.length_bytes)
        .ok()
        .filter(|length| *length <= VERITY_SIGNATURE_LIMIT)
        .ok_or(SelectorBoundaryError::ArtifactInvalid)
        .and_then(|length| {
            let mut bytes = vec![0; length];
            root_image
                .read_exact_at(&mut bytes, signature.start_bytes)
                .map(|()| bytes)
                .map_err(invalid)
        })
        .and_then(|bytes| {
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            if bytes[end..].iter().any(|byte| *byte != 0) {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            }
            parse_verity_signature(&bytes[..end])
        })
        .and_then(|json| {
            if !json.root_hash.eq_ignore_ascii_case(&lower_hex(root_hash))
                || json.signature != base64(proof)
            {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            }
            Ok(())
        })
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect()
}

/// RFC 4648 standard base64 with padding, as systemd-repart writes it.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let sextets = [
            group[0] >> 2,
            ((group[0] & 3) << 4) + (group[1] >> 4),
            ((group[1] & 15) << 2) + (group[2] >> 6),
            group[2] & 63,
        ];
        // A chunk of n bytes yields n + 1 symbols, then `=` padding.
        for (index, sextet) in sextets.into_iter().enumerate() {
            encoded.push(if index <= chunk.len() {
                char::from(ALPHABET[usize::from(sextet)])
            } else {
                '='
            });
        }
    }
    encoded
}

fn invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

#[cfg(any(test, feature = "test-support"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[doc(hidden)]
pub mod test_support;

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
    ///
    /// Keep in step with `test_support::request_for`, which sets the same
    /// authority fields for other crates' privileged tests.
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
        assert_eq!(
            snapshot.syscall_set(),
            snapshot.admitted.provider().syscall_set()
        );
        let runtime = snapshot.admitted.runtime_attestation_key()?;
        assert_eq!(snapshot.runtime_attestation_key_id(), runtime.key_id);
        assert_eq!(
            snapshot.runtime_attestation_key().to_bytes(),
            runtime.public_key
        );
        let binary = snapshot.provider_binary();
        let retained = snapshot
            .admitted
            .bootstrap()
            .installed()
            .artifact(InstallationObjectKind::PROVIDER_EXECUTABLE, binary.digest())?;
        let metadata = retained.file().metadata()?;
        assert_eq!(
            binary.digest(),
            snapshot.admitted.provider().manifest().binary_digest
        );
        assert_eq!(binary.length(), metadata.len());
        assert_eq!(binary.identity(), (metadata.dev(), metadata.ino()));
        assert_eq!(
            binary.path(),
            format!(
                "{SANDBOX_ARTIFACT_ROOT}/providers/{}",
                lower_hex(&binary.digest())
            )
        );
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
        let bootstrap = snapshot.admitted.bootstrap();
        assert_eq!(
            admission.authority(),
            AdmittedAuthority {
                apt1_digest: bootstrap.policy().policy_digest(),
                trs1_digest: bootstrap.trust().snapshot_digest(),
                rvs1_digest: bootstrap.revocation().snapshot_digest(),
                trust_epoch: bootstrap.trust().trust_epoch(),
                revocation_epoch: bootstrap.revocation().revocation_epoch(),
                policy_epoch: bootstrap.policy().policy_epoch(),
            }
        );
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
        assert!(snapshot
            .join_current(fixture.installed(), fixture_time)
            .is_err());
        let admission = ProviderImageSnapshot::from_installation(
            admitted_state()?,
            request_fixture()?,
            fixture_time,
        )?;
        let admission = admission.join_current(current(), fixture_time)?;
        assert!(admission.recheck_with(Ok(successor)).is_err());
        Ok(())
    }

    #[test]
    fn recheck_returns_the_admitted_authority_and_rejects_unreadable_state() -> TestResult {
        let snapshot = ProviderImageSnapshot::from_installation(
            admitted_state()?,
            request_fixture()?,
            fixture_time,
        )?;
        let admission = snapshot.join_current(current(), fixture_time)?;
        assert_eq!(admission.recheck_with(current())?, admission.authority());
        assert!(admission
            .recheck_with(Err(SelectorBoundaryError::Io))
            .is_err());
        Ok(())
    }

    #[test]
    fn provider_rejects_a_non_erofs_root_before_activation() -> TestResult {
        use crate::selector::installation::tests::{
            admitted_state_with_salt, ddi_fixture, ddi_partitions, ddi_salt, ImageSigning,
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
                &ImageSigning::ddi("x86-64")?,
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
            admitted_state_with_salt, ddi_fixture, ddi_salt, ImageSigning,
        };

        let (image, partitions) = ddi_fixture("x86-64")?;
        let mut other_salt = ddi_salt("x86-64")?;
        other_salt[0] ^= 1;
        let signing = ImageSigning::ddi("x86-64")?;
        assert!(ProviderImageSnapshot::from_installation(
            admitted_state_with_salt(&image, b"adapter", &partitions, &signing, other_salt)?,
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
            // The superblock prefix must lie inside the admitted partition.
            let mut bounded = verity.clone();
            bounded.length_bytes = u64::try_from(VERITY_SUPERBLOCK_PREFIX)?;
            check_verity_superblock(&write(&image)?, &bounded, &salt)?;
            bounded.length_bytes -= 1;
            assert!(check_verity_superblock(&write(&image)?, &bounded, &salt).is_err());
            let mut beyond = verity.clone();
            beyond.start_bytes = u64::try_from(image.len())?;
            assert!(check_verity_superblock(&write(&image)?, &beyond, &salt).is_err());
        }
        Ok(())
    }

    /// The systemd-repart JSON text of a DDI fixture's root-verity-sig partition.
    fn ddi_signature_json(image: &[u8], signature: &PartitionDescriptor) -> TestResult<Vec<u8>> {
        let start = usize::try_from(signature.start_bytes)?;
        let partition = &image[start..start + usize::try_from(signature.length_bytes)?];
        let end = partition
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("fixture JSON is not NUL-terminated")?;
        Ok(partition[..end].to_vec())
    }

    /// `image` with its signature partition replaced by `json` and NUL padding.
    fn with_signature_json(
        image: &[u8],
        signature: &PartitionDescriptor,
        json: &[u8],
    ) -> TestResult<Vec<u8>> {
        let start = usize::try_from(signature.start_bytes)?;
        let length = usize::try_from(signature.length_bytes)?;
        let mut padded = json.to_vec();
        padded.resize(length, 0);
        let mut changed = image.to_vec();
        changed[start..start + length].copy_from_slice(&padded);
        Ok(changed)
    }

    fn replace_once(json: &[u8], from: &str, to: &str) -> TestResult<Vec<u8>> {
        let text = std::str::from_utf8(json)?;
        if text.matches(from).count() != 1 {
            return Err(format!("{from} does not occur once").into());
        }
        Ok(text.replacen(from, to, 1).into_bytes())
    }

    fn temporary_file(bytes: &[u8]) -> TestResult<File> {
        use std::io::Write as _;

        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        Ok(file)
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), encoded);
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xbf]), "+/+/");
        assert_eq!(lower_hex(&[0x00, 0x9f, 0xa0, 0xff]), "009fa0ff");
    }

    /// Accepted, then rejected, edits of one signature partition's JSON.
    type JsonVariants = (Vec<Vec<u8>>, Vec<Vec<u8>>);

    /// Edits of a DDI's systemd-repart JSON that admission accepts and rejects.
    fn signature_json_variants(
        json: &[u8],
        signing: &crate::selector::installation::tests::ImageSigning,
    ) -> TestResult<JsonVariants> {
        let text = std::str::from_utf8(json)?.to_owned();
        let root_hash = lower_hex(signing.root_hash());
        let encoded = base64(signing.proof());
        let root_pair = format!("\"rootHash\":\"{root_hash}\"");
        let signature_pair = format!("\"signature\":\"{encoded}\"");
        let fingerprint_start = text
            .find(",\"certificateFingerprint\"")
            .ok_or("no fingerprint")?;
        let fingerprint_pair =
            &text[fingerprint_start..text.find(",\"signature\"").ok_or("no signature")?];
        assert!(text.contains(&root_pair) && text.contains(&signature_pair));

        let mut other_root = root_hash.clone().into_bytes();
        other_root[0] = if other_root[0] == b'0' { b'1' } else { b'0' };
        let other_root = String::from_utf8(other_root)?;
        let mut other_signature = encoded.clone().into_bytes();
        other_signature[10] = if other_signature[10] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let other_signature = String::from_utf8(other_signature)?;
        let unpadded = encoded.trim_end_matches('=');
        let accepted: Vec<Vec<u8>> = vec![
            // Other keys, certificateFingerprint included, are not
            // interpreted; whitespace inside the object is JSON; hex digits
            // may be uppercase (ADR-087 Part B.4).
            replace_once(json, fingerprint_pair, "")?,
            replace_once(json, fingerprint_pair, ",\"certificateFingerprint\":null")?,
            replace_once(json, fingerprint_pair, ",\"certificateFingerprint\":\"x\"")?,
            replace_once(json, "}", ",\"extra\":{\"a\":[1,null,true]}}")?,
            replace_once(json, "{", "{ \n")?,
            replace_once(json, &root_hash, &root_hash.to_uppercase())?,
        ];
        let rejected: Vec<Vec<u8>> = vec![
            replace_once(json, &root_hash, &other_root)?,
            replace_once(json, &root_hash, &format!("{root_hash}00"))?,
            replace_once(json, &encoded, &other_signature)?,
            replace_once(json, &encoded, unpadded)?,
            replace_once(json, &encoded, &format!("!{}", &encoded[1..]))?,
            replace_once(
                json,
                &encoded,
                &format!("{}\\n{}", &encoded[..4], &encoded[4..]),
            )?,
            replace_once(json, &format!("{root_pair},"), "")?,
            replace_once(json, &format!(",{signature_pair}"), "")?,
            replace_once(json, "{", &format!("{{{root_pair},"))?,
            replace_once(json, "}", &format!(",{signature_pair}}}"))?,
            replace_once(
                json,
                fingerprint_pair,
                &format!("{fingerprint_pair}{fingerprint_pair}"),
            )?,
            replace_once(json, "}", ",\"x\":1,\"x\":2}")?,
            replace_once(json, &format!("\"{root_hash}\""), "1")?,
            replace_once(json, &format!("\"{encoded}\""), "1")?,
            replace_once(json, "}", ",\"extra\":tru}")?,
            replace_once(json, "}", ",}")?,
            format!("[\"{root_hash}\",\"{encoded}\"]").into_bytes(),
            replace_once(json, "}", "}x")?,
            replace_once(json, "}", "}{}")?,
            replace_once(json, "{", " {")?,
            replace_once(json, "{", "\t{")?,
            replace_once(
                json,
                "{",
                &format!("{{\"rootHash\\u0000\":\"{other_root}\","),
            )?,
            replace_once(json, "{", "{\"signature\\u0000\":\"\",")?,
            replace_once(json, "{", "{\"x\\u0000\":\"\",")?,
            replace_once(json, "}", ",\"extra\":\"\u{7f}\"}")?,
            replace_once(json, "}", "}\n")?,
            replace_once(json, "}", "}\r")?,
            Vec::new(),
        ];
        Ok((accepted, rejected))
    }

    #[test]
    fn verity_signature_json_must_equal_sim1_on_both_architectures() -> TestResult {
        use crate::selector::installation::tests::{ddi_fixture, ImageSigning};

        for architecture in ["x86-64", "arm64"] {
            let (image, partitions) = ddi_fixture(architecture)?;
            let signing = ImageSigning::ddi(architecture)?;
            let signature = &partitions[2];
            let check = |image: &[u8]| {
                temporary_file(image).map(|file| {
                    check_verity_signature(&file, signature, signing.root_hash(), signing.proof())
                })
            };
            // systemd-repart's own partition, unchanged, on both architectures.
            check(&image)??;
            let json = ddi_signature_json(&image, signature)?;
            let (accepted, rejected) = signature_json_variants(&json, &signing)?;
            for (variant, accepts) in accepted
                .iter()
                .map(|json| (json, true))
                .chain(rejected.iter().map(|json| (json, false)))
            {
                let result = check(&with_signature_json(&image, signature, variant)?)?;
                assert_eq!(
                    result.is_ok(),
                    accepts,
                    "{architecture}: {}",
                    String::from_utf8_lossy(variant)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn verity_signature_partition_framing_matches_systemd() -> TestResult {
        use crate::selector::installation::tests::{ddi_fixture, ImageSigning};

        for architecture in ["x86-64", "arm64"] {
            let (image, partitions) = ddi_fixture(architecture)?;
            let signing = ImageSigning::ddi(architecture)?;
            let signature = &partitions[2];
            let json = ddi_signature_json(&image, signature)?;
            // Only NUL bytes may follow the first NUL.
            let mut trailing = image.clone();
            let end = usize::try_from(signature.start_bytes + signature.length_bytes)?;
            trailing[end - 1] = b' ';
            let trailing_file = temporary_file(&trailing)?;
            assert!(check_verity_signature(
                &trailing_file,
                signature,
                signing.root_hash(),
                signing.proof()
            )
            .is_err());
            // A partition that the JSON fills exactly needs no NUL.
            let mut exact = signature.clone();
            exact.length_bytes = u64::try_from(json.len())?;
            let file = temporary_file(&image)?;
            check_verity_signature(&file, &exact, signing.root_hash(), signing.proof())?;
            let mut beyond = signature.clone();
            beyond.start_bytes = u64::try_from(image.len())?;
            assert!(
                check_verity_signature(&file, &beyond, signing.root_hash(), signing.proof())
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn verity_signature_partition_is_bounded_at_systemds_four_mib() -> TestResult {
        use crate::selector::installation::tests::{ddi_fixture, ImageSigning};

        let (image, partitions) = ddi_fixture("x86-64")?;
        let signing = ImageSigning::ddi("x86-64")?;
        let mut json = ddi_signature_json(&image, &partitions[2])?;
        json.resize(VERITY_SIGNATURE_LIMIT + 1, 0);
        let file = temporary_file(&json)?;
        let mut signature = partitions[2].clone();
        signature.start_bytes = 0;
        signature.length_bytes = u64::try_from(VERITY_SIGNATURE_LIMIT)?;
        check_verity_signature(&file, &signature, signing.root_hash(), signing.proof())?;
        signature.length_bytes += 1;
        assert!(
            check_verity_signature(&file, &signature, signing.root_hash(), signing.proof())
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn provider_rejects_a_signature_partition_other_than_sim1() -> TestResult {
        use crate::selector::installation::tests::{
            admitted_state_with_salt, ddi_fixture, ddi_partitions, ddi_salt, ImageSigning,
            IMAGE_PROOF,
        };

        let (image, partitions) = ddi_fixture("x86-64")?;
        let salt = ddi_salt("x86-64")?;
        let signing = ImageSigning::ddi("x86-64")?;
        // A SIM1 whose own root hash and proof verify, over an image whose
        // signature partition names systemd-repart's root hash and proof.
        let synthetic = ImageSigning::synthetic(IMAGE_PROOF);
        let open = |image: &[u8],
                    partitions: &[PartitionDescriptor; 3],
                    signing: &ImageSigning|
         -> TestResult<ProviderImageSnapshot> {
            let state = admitted_state_with_salt(image, b"adapter", partitions, signing, salt)?;
            Ok(ProviderImageSnapshot::from_installation(
                state,
                request_fixture()?,
                fixture_time,
            )?)
        };
        assert!(open(&image, &partitions, &synthetic).is_err());
        // The same image is admitted under the SIM1 its partition names.
        open(&image, &partitions, &signing)?;
        // One changed rootHash or signature character, digests recomputed.
        let json = ddi_signature_json(&image, &partitions[2])?;
        let root_hash = lower_hex(signing.root_hash());
        let mut other_root = root_hash.clone().into_bytes();
        other_root[63] = if other_root[63] == b'0' { b'1' } else { b'0' };
        let encoded = base64(signing.proof());
        let mut other_signature = encoded.clone().into_bytes();
        other_signature[0] = if other_signature[0] == b'A' {
            b'B'
        } else {
            b'A'
        };
        for (from, to) in [
            (root_hash, String::from_utf8(other_root)?),
            (encoded, String::from_utf8(other_signature)?),
        ] {
            let changed =
                with_signature_json(&image, &partitions[2], &replace_once(&json, &from, &to)?)?;
            let changed_partitions = ddi_partitions("x86-64", &changed)?;
            assert!(open(&changed, &changed_partitions, &signing).is_err());
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
