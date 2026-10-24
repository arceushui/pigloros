//! Closed launcher failures. Every message is a fixed string; none carries
//! paths, descriptors or record bytes.

use std::io;

/// Why a release defect rejected `ReleaseV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseDefect {
    /// Not one complete canonical `ReleaseV1`: truncated, malformed, carrying
    /// control data, or zero length.
    Malformed,
    /// Another attempt's release.
    Attempt,
    /// Another launch's nonce.
    Nonce,
    /// It does not bind this launcher's `ReadyV1` digest.
    ReadyDigest,
    /// The monotonic deadline had already passed.
    Expired,
    /// A second message was already queued, or none could be ruled out.
    Duplicate,
}

/// Closed failures of the launch barrier. None is retryable.
#[derive(Debug, thiserror::Error)]
pub enum LauncherError {
    /// The LPV1 argument is missing, not lowercase hexadecimal, or invalid.
    #[error("launch parameters are not a valid LPV1")]
    Parameters,
    /// The systemd launch environment is missing or malformed.
    #[error("launch environment is invalid")]
    Environment,
    /// The inherited descriptors differ from the expected layout.
    #[error("inherited descriptor layout is invalid")]
    Layout,
    /// The release channel peer is not the root provider.
    #[error("release channel peer is not the root provider")]
    Peer,
    /// The adapter could not be opened beneath the root or is not the
    /// regular native ELF for this architecture.
    #[error("adapter is not a regular native ELF beneath the root")]
    Adapter,
    /// A descriptor identity or digest could not be read.
    #[error("launcher or adapter identity could not be read")]
    Identity,
    /// `ReadyV1` could not be sent as one message.
    #[error("ReadyV1 could not be sent")]
    Ready,
    /// No `ReleaseV1` arrived: EOF or a channel error.
    #[error("ReleaseV1 was not received")]
    ReleaseUnavailable,
    /// `ReleaseV1` was rejected.
    #[error("ReleaseV1 rejected: {0:?}")]
    Release(ReleaseDefect),
    /// Replacing the process image failed.
    #[error("adapter exec failed")]
    Exec(#[source] io::Error),
}
