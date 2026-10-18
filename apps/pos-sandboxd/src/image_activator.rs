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

use std::{future::Future, io, os::fd::OwnedFd, path::Path};

use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
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
/// admitted SIM1 root-data partition. It has no public constructor: only the
/// #438 held-image admission composition may create it, so no caller can
/// present an unadmitted descriptor to mountfsd.
#[derive(Debug)]
pub struct ActivationImage {
    descriptor: OwnedFd,
    root_offset: u64,
    root_size: u64,
    architecture: SandboxArchitecture,
}

/// Exactly one sealed, detached root mount returned by `MountImage`.
///
/// The descriptor is close-on-exec from receipt and stays quarantined until
/// the attachment and readback slice consumes it. Dropping this value closes
/// the descriptor, which releases the detached mount so that systemd's loop
/// autoclear and deferred dm-verity removal can proceed.
#[derive(Debug)]
pub struct QuarantinedRootMount {
    _mount: OwnedFd,
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
}

/// A connected, root-peer `MountFileSystem` client for one transaction.
#[derive(Debug)]
pub struct MountfsdImageActivator {
    connection: Connection<SealedUnixSocket>,
}

impl MountfsdImageActivator {
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
            .map_err(transport_failure)
            .and_then(|peer| trusted_peer(peer.uid.as_raw(), peer_uid))
            .map(|()| Self {
                connection: Connection::new(SealedUnixSocket::new(stream)),
            })
    }
}

impl ImageActivator for MountfsdImageActivator {
    async fn mount_image(
        mut self,
        image: ActivationImage,
    ) -> Result<QuarantinedRootMount, ImageActivationError> {
        let ActivationImage {
            descriptor,
            root_offset,
            root_size,
            architecture,
        } = image;
        // zlink's typed result only carries the reply descriptors. The exact
        // frame captured by the sealed read half is the authoritative reply.
        let outcome: zlink::Result<(
            zlink::reply::Result<IgnoredAny, MountImageFailure>,
            Vec<OwnedFd>,
        )> = self
            .connection
            .call_method(&mount_image_call(), vec![descriptor])
            .await;
        reply::accept(
            self.connection.read().read_half().frame(),
            outcome.map(|(_, descriptors)| descriptors),
            &ExpectedRoot {
                offset: root_offset,
                size: root_size,
                architecture,
            },
        )
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

fn transport_failure<E>(_: E) -> ImageActivationError {
    ImageActivationError::Transport
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
