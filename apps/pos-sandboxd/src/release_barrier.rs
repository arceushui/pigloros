//! Provider half of the ReadyV1/ReleaseV1 barrier (ADR-069 "Requested state,
//! observed state, and release barrier", #441).
//!
//! The provider receives exactly one `ReadyV1` on the release channel. It
//! accepts it only if the kernel-supplied `SCM_CREDENTIALS` pid equals the
//! transient unit's current `MainPID` and every launcher-derived binding equals
//! held or independently observed evidence. It then rechecks current authority
//! through the [`ReleaseRecheck`] port and sends exactly one `ReleaseV1`,
//! signed through the [`ReleaseSigner`] port. Neither message is retried.
//!
//! Current RVS1/APT1/TRS1 digests and epochs come from the held-image
//! authority (PR 2); the composition (PR 4) supplies them behind
//! [`ReleaseRecheck`] so this slice does not depend on that API's shape.

use std::{io::IoSliceMut, mem::MaybeUninit, os::fd::AsFd};

use pos_reference::sandbox_provider_protocol::{
    ExecutionRelease, ExecutionReleaseFields, FdIdentity, LauncherReady, LauncherReadyFields,
};
use rustix::net::{
    recvmsg, send, sockopt::set_socket_passcred, RecvAncillaryBuffer, RecvAncillaryMessage,
    RecvFlags, ReturnFlags, SendFlags,
};

use crate::release_signer::{issue_release, ReleaseSigner, ReleaseSignerError};

/// Largest `ReadyV1` datagram the provider accepts.
const MAX_READY_BYTES: usize = 4096;

/// Held or independently observed evidence for one launch (the `ReadyV1`
/// bindings of ADR-069).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedLauncherReady {
    /// The attempt.
    pub attempt_id: [u8; 16],
    /// The provider-issued single-use nonce.
    pub nonce: [u8; 32],
    /// The 16 bytes of systemd's `INVOCATION_ID` for the unit.
    pub launch_instance_id: [u8; 16],
    /// The admitted launcher binary digest.
    pub launcher_digest: [u8; 32],
    /// The `/proc/<MainPID>/exe` mount ID and inode.
    pub launcher_identity: FdIdentity,
    /// The admitted SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// The admitted adapter executable digest.
    pub adapter_digest: [u8; 32],
    /// The independently observed adapter mount ID and inode.
    pub adapter_identity: FdIdentity,
    /// The LPV1 self-digest the provider handed the launcher.
    pub launch_parameter_digest: [u8; 32],
    /// The expected FDL1 digest, which the observed layout must equal.
    pub expected_fdl1_digest: [u8; 32],
}

impl ExpectedLauncherReady {
    fn fields(&self) -> LauncherReadyFields {
        LauncherReadyFields {
            attempt_id: self.attempt_id,
            nonce: self.nonce,
            launch_instance_id: self.launch_instance_id,
            launcher_digest: self.launcher_digest,
            launcher_identity: self.launcher_identity,
            sim1_digest: self.sim1_digest,
            adapter_digest: self.adapter_digest,
            adapter_identity: self.adapter_identity,
            launch_parameter_digest: self.launch_parameter_digest,
            expected_fdl1_digest: self.expected_fdl1_digest,
            observed_fdl1_digest: self.expected_fdl1_digest,
        }
    }
}

/// Current authority and evidence bound into `ReleaseV1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBinding {
    /// Current TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// Current RVS1 digest.
    pub rvs1_digest: [u8; 32],
    /// Current APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Trust epoch.
    pub trust_epoch: u64,
    /// Revocation epoch.
    pub revocation_epoch: u64,
    /// Policy epoch.
    pub policy_epoch: u64,
    /// Expected readback-set digest.
    pub expected_readback_digest: [u8; 32],
    /// Observed readback-set digest.
    pub observed_readback_digest: [u8; 32],
    /// Absolute `CLOCK_MONOTONIC` release deadline in nanoseconds.
    pub deadline_monotonic_ns: u64,
}

/// The provider's last-moment recheck: current RVS1, policy/trust/image
/// epochs, cancellation, unit identity, requested configuration, kernel
/// observations and descriptor bindings. `Err` means do not release.
pub trait ReleaseRecheck {
    /// Recheck everything and return the current bindings, or why not.
    ///
    /// # Errors
    /// Returns [`ReleaseBarrierError::Recheck`] when any recheck fails.
    fn recheck(&self) -> Result<ReleaseBinding, ReleaseBarrierError>;
}

/// Closed failures of the provider half. None is retryable.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseBarrierError {
    /// The release channel failed or closed before one `ReadyV1` arrived.
    #[error("ReadyV1 was not received")]
    ReadyUnavailable,
    /// The datagram was truncated, oversized or carried control data other
    /// than one `SCM_CREDENTIALS`.
    #[error("ReadyV1 datagram is not one bounded message with one credential")]
    ReadyFraming,
    /// The kernel-supplied pid is not the unit's `MainPID`.
    #[error("ReadyV1 sender is not the unit MainPID")]
    PidMismatch,
    /// The bytes are not a canonical `ReadyV1`.
    #[error("ReadyV1 is malformed")]
    ReadyMalformed,
    /// A `ReadyV1` binding differs from held or observed evidence.
    #[error("ReadyV1 binding differs from the expected evidence")]
    ReadyMismatch,
    /// The last-moment recheck refused release.
    #[error("release recheck failed")]
    Recheck,
    /// `ReleaseV1` could not be built or signed.
    #[error(transparent)]
    Sign(#[from] ReleaseSignerError),
    /// `ReleaseV1` could not be sent as one message.
    #[error("ReleaseV1 could not be sent")]
    ReleaseSend,
}

/// Receive and verify one `ReadyV1`, recheck, and send one signed `ReleaseV1`.
///
/// `main_pid` is the transient unit's current `MainPID`, read back by the
/// caller. The channel is the provider end of the root-created
/// `SOCK_SEQPACKET` pair. Returns the sent release for durable evidence.
///
/// # Errors
/// Any [`ReleaseBarrierError`]; the caller must then fail the attempt without
/// sending a release.
pub fn release_after_ready(
    channel: impl AsFd,
    main_pid: u32,
    expected: &ExpectedLauncherReady,
    recheck: &dyn ReleaseRecheck,
    signer: &dyn ReleaseSigner,
) -> Result<ExecutionRelease, ReleaseBarrierError> {
    let ready = receive_ready(&channel, main_pid)?;
    if ready.fields != expected.fields() {
        return Err(ReleaseBarrierError::ReadyMismatch);
    }
    let binding = recheck.recheck()?;
    let release = issue_release(
        signer,
        ExecutionReleaseFields {
            attempt_id: expected.attempt_id,
            nonce: expected.nonce,
            ready1_digest: ready.digest,
            trs1_digest: binding.trs1_digest,
            rvs1_digest: binding.rvs1_digest,
            apt1_digest: binding.apt1_digest,
            trust_epoch: binding.trust_epoch,
            revocation_epoch: binding.revocation_epoch,
            policy_epoch: binding.policy_epoch,
            expected_readback_digest: binding.expected_readback_digest,
            observed_readback_digest: binding.observed_readback_digest,
            deadline_monotonic_ns: binding.deadline_monotonic_ns,
            runtime_attestation_key_id: signer.runtime_attestation_key_id().to_owned(),
        },
    )?;
    let bytes = release
        .to_canonical_cbor()
        .ok()
        .ok_or(ReleaseBarrierError::ReleaseSend)?;
    match send(&channel, &bytes, SendFlags::NOSIGNAL) {
        Ok(sent) if sent == bytes.len() => Ok(release),
        _ => Err(ReleaseBarrierError::ReleaseSend),
    }
}

fn receive_ready(channel: &impl AsFd, main_pid: u32) -> Result<LauncherReady, ReleaseBarrierError> {
    set_socket_passcred(channel, true).map_err(|_| ReleaseBarrierError::ReadyUnavailable)?;
    let mut buffer = [0_u8; MAX_READY_BYTES];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        channel,
        &mut [IoSliceMut::new(&mut buffer)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .ok()
    .ok_or(ReleaseBarrierError::ReadyUnavailable)?;
    if received.bytes == 0 {
        return Err(ReleaseBarrierError::ReadyUnavailable);
    }
    let mut credentials = Vec::new();
    let mut other_control = false;
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmCredentials(sender) = message {
            credentials.push(sender);
        } else {
            other_control = true;
        }
    }
    if received
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || other_control
        || credentials.len() != 1
    {
        return Err(ReleaseBarrierError::ReadyFraming);
    }
    if credentials
        .first()
        .map(|sender| u32::try_from(sender.pid.as_raw_nonzero().get()))
        != Some(Ok(main_pid))
    {
        return Err(ReleaseBarrierError::PidMismatch);
    }
    LauncherReady::from_canonical_cbor(&buffer[..received.bytes])
        .map_err(|_| ReleaseBarrierError::ReadyMalformed)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
