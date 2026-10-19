//! Closed parsing of one `MountImage` reply and its descriptor vector.
//!
//! The schema follows the systemd v260.2 `io.systemd.MountFileSystem`
//! definition and `mountwork.c` reply construction. Unknown or duplicate
//! fields, `continues`, extra partitions and any descriptor that is not the
//! single root mount at index 0 are malformed. A well-formed reply whose root
//! differs from the admitted SIM1 or requested policy is an evidence mismatch.
//! Optional fields mountfsd may emit are type-checked only; the provider's
//! own SIM1 and kernel readback remain the authoritative image evidence.

use std::{num::NonZeroU64, os::fd::OwnedFd};

use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use serde::{de::IgnoredAny, Deserialize};

use super::{policy, ImageActivationError, QuarantinedRootMount};

/// The admitted SIM1 root-data partition the reply must describe.
pub(super) struct ExpectedRoot {
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) architecture: SandboxArchitecture,
}

/// Accept exactly one sealed root mount, closing every descriptor otherwise.
pub(super) fn accept(
    frame: Result<&[u8], ImageActivationError>,
    descriptors: zlink::Result<Vec<OwnedFd>>,
    expected: &ExpectedRoot,
) -> Result<QuarantinedRootMount, ImageActivationError> {
    frame.and_then(parameters).and_then(|reply| {
        descriptors
            .map_err(malformed)
            .and_then(|descriptors| root_mount(&reply, descriptors, expected))
    })
}

fn parameters(message: &[u8]) -> Result<MountImageReply, ImageActivationError> {
    serde_json::from_slice::<SuccessEnvelope>(message)
        .map(|envelope| envelope.parameters)
        .or_else(|_| rejected(message))
}

fn rejected(message: &[u8]) -> Result<MountImageReply, ImageActivationError> {
    serde_json::from_slice::<FailureEnvelope>(message)
        .map_err(malformed)
        .and(Err(ImageActivationError::MethodRejected))
}

fn root_mount(
    reply: &MountImageReply,
    mut descriptors: Vec<OwnedFd>,
    expected: &ExpectedRoot,
) -> Result<QuarantinedRootMount, ImageActivationError> {
    let mount = descriptors.pop();
    match (reply.partitions.as_slice(), mount) {
        ([root], Some(mount)) if descriptors.is_empty() && root.mount_file_descriptor == 0 => {
            if matches_admitted_root(reply, root, expected) {
                Ok(QuarantinedRootMount { mount })
            } else {
                Err(ImageActivationError::EvidenceMismatch)
            }
        }
        _ => Err(ImageActivationError::MalformedReply),
    }
}

fn matches_admitted_root(
    reply: &MountImageReply,
    root: &PartitionInfo,
    expected: &ExpectedRoot,
) -> bool {
    root.designator == "root"
        && !root.writable
        && !root.grow_file_system
        && root.file_system_type == "erofs"
        && root.offset == expected.offset
        && root.size == expected.size
        && root
            .architecture
            .as_deref()
            .is_none_or(|architecture| architecture == systemd_architecture(expected.architecture))
        && !reply.single_file_system
        && policy::matches_requested(&reply.image_policy)
}

/// systemd's `architecture_to_string()` names for the SIM1 architectures.
const fn systemd_architecture(architecture: SandboxArchitecture) -> &'static str {
    match architecture {
        SandboxArchitecture::X86_64 => "x86-64",
        SandboxArchitecture::Aarch64 => "arm64",
    }
}

fn malformed<E>(_: E) -> ImageActivationError {
    ImageActivationError::MalformedReply
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessEnvelope {
    parameters: MountImageReply,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureEnvelope {
    #[serde(rename = "error")]
    _error: String,
    #[serde(default, rename = "parameters")]
    _parameters: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MountImageReply {
    partitions: Vec<PartitionInfo>,
    single_file_system: bool,
    image_policy: String,
    #[serde(rename = "imageSize")]
    _image_size: u64,
    #[serde(rename = "sectorSize")]
    _sector_size: u64,
    #[serde(default, rename = "imageName")]
    _image_name: Option<String>,
    #[serde(default, rename = "imageUuid")]
    _image_uuid: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PartitionInfo {
    designator: String,
    writable: bool,
    grow_file_system: bool,
    #[serde(default, rename = "partitionNumber")]
    _partition_number: Option<NonZeroU64>,
    #[serde(default)]
    architecture: Option<String>,
    #[serde(default, rename = "partitionUuid")]
    _partition_uuid: Option<String>,
    file_system_type: String,
    #[serde(default, rename = "partitionLabel")]
    _partition_label: Option<String>,
    size: u64,
    offset: u64,
    mount_file_descriptor: u64,
    #[serde(default, rename = "mountPoint")]
    _mount_point: Option<Vec<String>>,
}
