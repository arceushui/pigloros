//! ADR-087 private `io.systemd.MountFileSystem.MountImage` transport.
//!
//! One connection carries exactly one call. The held image descriptor travels
//! as index 0 of that call, and the reply must return exactly one root mount
//! descriptor in the same transaction. Reply descriptors are received
//! atomically close-on-exec by the `socket` read half, before zlink parses any
//! JSON, and the captured reply is then parsed again under a closed schema by
//! `reply`. No zlink type crosses this module's public surface.
//!
//! The atomic receive closes the receipt-to-sealing window for this
//! connection. Other in-process descriptor receivers, such as the zbus system
//! bus connection, do not request `MSG_CMSG_CLOEXEC`, so the provider also
//! keeps a process-wide rule that it never creates local processes. The
//! `provider_process_creation_public` integration test enforces that rule
//! over the provider's production sources and manifests.

mod policy;
mod reply;
mod socket;

use std::{
    future::Future,
    io,
    os::fd::{AsFd, OwnedFd},
    path::Path,
    time::Duration,
};

use pos_reference::{
    provider_admission::HeldImageAdmission, sandbox_provider_protocol::SandboxArchitecture,
};
use serde::{de::IgnoredAny, Deserialize};
use serde_json::{json, Value};
use tokio::net::UnixStream;
use zlink::{Call, Connection};

use self::{reply::ExpectedRoot, socket::SealedUnixSocket};

/// The only endpoint the provider connects to, socket-activated by systemd.
const MOUNTFSD_SOCKET: &str = "/run/systemd/io.systemd.MountFileSystem";
/// mountfsd runs as root; any other peer is rejected before the call.
const MOUNTFSD_PEER_UID: u32 = 0;

/// The ADR-087 activation port between provider lifecycle code and systemd.
///
/// Implementations perform one `MountImage` transaction and either return the
/// sealed quarantined root mount or a stable error. Lifecycle tests may use a
/// descriptor-aware fake behind this port.
pub trait ImageActivator {
    /// Activate one admitted image and return its quarantined root mount.
    ///
    /// Success grants no authority: the caller must still attach the mount and
    /// independently read back its identities before any unit exists.
    fn mount_image(
        self,
        image: ActivationImage,
    ) -> impl Future<Output = Result<QuarantinedRootMount, ImageActivationError>> + Send;
}

/// One admitted SIM1 image presented for activation.
///
/// It holds a close-on-exec duplicate of the retained image descriptor and the
/// admitted SIM1 root-data partition. Its only constructor is
/// [`Self::from_admission`], so no caller can present an unadmitted descriptor
/// to mountfsd.
#[derive(Debug)]
pub struct ActivationImage {
    descriptor: OwnedFd,
    root_offset: u64,
    root_size: u64,
    architecture: SandboxArchitecture,
}

impl ActivationImage {
    /// Present one held-image admission for activation.
    ///
    /// The descriptor is a close-on-exec duplicate of exactly the retained
    /// root image that the admission checked. The root partition and
    /// architecture come from the same admitted SIM1, and the reply must
    /// describe that partition. The authority was current only when
    /// `admit_held_image()` ran; the execute path (#441) must reserve the
    /// attempt atomically with admission. This grants no mount, launch or
    /// output authority; attachment and kernel readback still decide.
    ///
    /// # Errors
    /// Returns the operating-system error when the held descriptor cannot be
    /// duplicated.
    pub fn from_admission(admission: &HeldImageAdmission<'_>) -> io::Result<Self> {
        let manifest = admission.snapshot().image().manifest();
        // SIM1 validation fixes partition ordinal 0 as the DPS root partition.
        let root = &manifest.partitions[0];
        admission
            .as_fd()
            .try_clone_to_owned()
            .map(|descriptor| Self {
                descriptor,
                root_offset: root.start_bytes,
                root_size: root.length_bytes,
                architecture: manifest.architecture,
            })
    }
}

/// Exactly one sealed, detached root mount returned by `MountImage`.
///
/// The descriptor is close-on-exec from receipt and stays quarantined until
/// the attachment and readback slice consumes it. Dropping this value closes
/// the descriptor, which releases the detached mount so that systemd's loop
/// autoclear and deferred dm-verity removal can proceed.
#[derive(Debug)]
pub struct QuarantinedRootMount {
    mount: OwnedFd,
}

impl QuarantinedRootMount {
    /// Hand the sealed descriptor to the attachment and readback boundary.
    pub(crate) fn into_descriptor(self) -> OwnedFd {
        self.mount
    }

    /// A descriptor-aware fake's root mount, for attachment tests.
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) const fn from_descriptor(mount: OwnedFd) -> Self {
        Self { mount }
    }
}

/// Stable failures of the private `MountImage` transport.
///
/// No raw JSON, path, peer detail or host diagnostic crosses this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ImageActivationError {
    /// No mountfsd listens on the fixed socket.
    #[error("systemd-mountfsd is unavailable on this host")]
    HostFeatureUnavailable,
    /// The Varlink connection failed, closed early, or its peer is not root.
    #[error("systemd-mountfsd Varlink transport or peer failed")]
    Transport,
    /// mountfsd answered the call with a Varlink error.
    #[error("systemd-mountfsd rejected MountImage")]
    MethodRejected,
    /// The reply, its framing, or its descriptor vector is not the one
    /// accepted shape.
    #[error("systemd-mountfsd returned a malformed MountImage reply")]
    MalformedReply,
    /// A well-formed reply describes a mount other than the admitted SIM1
    /// signed EROFS root under the requested image policy.
    #[error("systemd-mountfsd activation evidence differs from the admitted image")]
    EvidenceMismatch,
    /// The held attempt directory changed, or the quarantined root mount
    /// could not be attached to it.
    #[error("the quarantined root mount could not be attached")]
    AttachFailure,
    /// A rejected, attached root mount could not be detached again.
    #[error("the rejected root mount could not be detached")]
    TeardownFailure,
}

/// A connected, root-peer `MountFileSystem` client for one transaction.
#[derive(Debug)]
pub struct MountfsdImageActivator {
    connection: Connection<SealedUnixSocket>,
}

impl MountfsdImageActivator {
    /// Owner decision Q7.4: one `MountImage` transaction is bounded to 60 s.
    pub(crate) const DEADLINE: Duration = Duration::from_mins(1);

    /// Connect to the fixed mountfsd socket and require a root peer.
    ///
    /// # Errors
    /// Returns [`ImageActivationError::HostFeatureUnavailable`] when no
    /// mountfsd listens there, and [`ImageActivationError::Transport`] for any
    /// other connection failure or a non-root peer.
    pub async fn connect() -> Result<Self, ImageActivationError> {
        Self::connect_at(Path::new(MOUNTFSD_SOCKET), MOUNTFSD_PEER_UID).await
    }

    async fn connect_at(path: &Path, peer_uid: u32) -> Result<Self, ImageActivationError> {
        UnixStream::connect(path)
            .await
            .map_err(|error| connect_failure(error.kind()))
            .and_then(|stream| Self::over(stream, peer_uid))
    }

    fn over(stream: UnixStream, peer_uid: u32) -> Result<Self, ImageActivationError> {
        rustix::net::sockopt::socket_peercred(&stream)
            .map_err(rustix::io::Errno::kind)
            .map_err(connect_failure)
            .and_then(|peer| trusted_peer(peer.uid.as_raw(), peer_uid))
            .map(|()| Self {
                connection: Connection::new(SealedUnixSocket::new(stream)),
            })
    }
}

impl ImageActivator for MountfsdImageActivator {
    async fn mount_image(
        self,
        image: ActivationImage,
    ) -> Result<QuarantinedRootMount, ImageActivationError> {
        self.mount_image_within(image, Self::DEADLINE).await
    }
}

impl MountfsdImageActivator {
    /// One `MountImage` transaction that must complete within `deadline`.
    ///
    /// Expiry is a transport failure. Dropping the pending call closes the
    /// held image duplicate and any partially received reply descriptors.
    async fn mount_image_within(
        mut self,
        image: ActivationImage,
        deadline: Duration,
    ) -> Result<QuarantinedRootMount, ImageActivationError> {
        let ActivationImage {
            descriptor,
            root_offset,
            root_size,
            architecture,
        } = image;
        // zlink's typed result only carries the reply descriptors. The exact
        // frame captured by the sealed read half is the authoritative reply.
        let outcome: Result<MountImageOutcome, tokio::time::error::Elapsed> = tokio::time::timeout(
            deadline,
            self.connection
                .call_method(&mount_image_call(), vec![descriptor]),
        )
        .await;
        outcome
            .map_err(|_| ImageActivationError::Transport)
            .and_then(|outcome| {
                reply::accept(
                    self.connection.read().read_half().frame(),
                    outcome.map(|(_, descriptors)| descriptors),
                    &ExpectedRoot {
                        offset: root_offset,
                        size: root_size,
                        architecture,
                    },
                )
            })
    }
}

/// The single ADR-087 request. Every field is sent explicitly; no password,
/// mount options, user namespace or separate Verity material is requested.
fn mount_image_call() -> Call<Value> {
    Call::new(json!({
        "method": "io.systemd.MountFileSystem.MountImage",
        "parameters": {
            "imageFileDescriptor": 0,
            "readOnly": true,
            "growFileSystems": false,
            "imagePolicy": policy::REQUESTED,
            "relaxExtensionReleaseChecks": false,
            "veritySharing": false,
            "allowInteractiveAuthentication": false,
        },
    }))
}

/// zlink's typed outcome of the one call: only its descriptors are used.
type MountImageOutcome = zlink::Result<(
    zlink::reply::Result<IgnoredAny, MountImageFailure>,
    Vec<OwnedFd>,
)>;

// zlink tries the error envelope before the successful reply. Requiring the
// Varlink `error` discriminator keeps successful parameters out of this type.
#[derive(Debug, Deserialize)]
#[serde(tag = "error")]
enum MountImageFailure {
    #[serde(other)]
    Rejected,
}

const fn connect_failure(kind: io::ErrorKind) -> ImageActivationError {
    match kind {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            ImageActivationError::HostFeatureUnavailable
        }
        _ => ImageActivationError::Transport,
    }
}

const fn trusted_peer(observed: u32, required: u32) -> Result<(), ImageActivationError> {
    if observed == required {
        Ok(())
    } else {
        Err(ImageActivationError::Transport)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
