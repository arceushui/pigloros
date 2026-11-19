//! The `recovery-peer` mode (ADR-069 R12 §5).
//!
//! The root selector starts this mode as the recovery peer of one pending
//! SIR1, after it proved the previous runtime terminated (R12 §6). Its argv
//! is exactly `[recovery-peer, <32 lowercase hex recovery-endpoint-id>]`.
//! The peer contains no responder logic of its own: it answers one RCC1/RCU1
//! exchange through the R11 §8.1 [`RevocationUpdateResponder`], with
//! [`AuthorityResolution::Recovery`] and the registry as its attempt state.
//!
//! In order, the peer:
//! 1. takes the endpoint ID from argv; any other argv is refused;
//! 2. reads SIR1 from its fixed path, verifies its self-digest, and takes
//!    only the previous-provider binding's runtime key ID and public key
//!    ([`PendingRecoveryRuntimeKey`]);
//! 3. loads the runtime key that SPI1 names (R11 §4.4) and requires its
//!    public key to be that SIR1 key. Revocation does not apply: this is the
//!    control-only exception;
//! 4. binds `/run/pigloros/sandbox-selector-recovery/<id>.sock` under the R11
//!    §6 rules: it calls `listen()` itself, `chmodat`s the leaf to `0600` on
//!    its retained directory, and verifies mode `0600`, owner UID 0 and the
//!    socket type;
//! 5. sends `READY=1`;
//! 6. accepts exactly one connection, waiting at most 5 s for it, which
//!    must have UID 0 `SO_PEERCRED`;
//! 7. answers it within 100 ms of the accept and sends server EOF after
//!    RCA1.
//!
//! It then exits; every failure exits too, and no step is retried. The
//! attempt state is the empty view of the registry under its exclusive
//! `flock`, which is released before RCA1 is written (R12 §5.1). The peer
//! has no execute endpoint, AGR1, SPR1, output or staging, makes no
//! mountfsd or system-bus call and no registry write, and creates no
//! process.

use std::ffi::OsStr;
use std::future::Future;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Instant;

use pos_reference::sandbox_provider_protocol::{SandboxRevocationSnapshot, SandboxTrustSnapshot};
use pos_reference::selector::installation::authority::{
    AuthorityResolution, PendingRecoveryRuntimeKey,
};
use pos_reference::selector::SelectorBoundaryError;
use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::endpoint::ProviderEndpoint;
use super::serving::{exchange_deadline, Deadlined};
use super::{
    notify, unavailable, AttemptCleanupState, AttemptStateSource, ExchangeObserver,
    ExchangeOutcome, ProviderRuntimeError, RevocationUpdateResponder,
};
use crate::{
    AdmittedRuntimeKey, KeyFileRuntimeSigner, ProviderInstallation, ProviderInstallationError,
    RuntimeKey,
};

/// The mode's argument (R12 §5.5).
pub(crate) const RECOVERY_PEER_ARGUMENT: &str = "recovery-peer";
/// The fixed recovery endpoint directory (ADR-069 §4.1, R12 §7.2).
const RECOVERY_DIRECTORY: &str = "/run/pigloros/sandbox-selector-recovery";
/// The `SO_PEERCRED` UID the one connection must have.
const ROOT_UID: u32 = 0;
/// How long the peer waits for its one connection after `READY=1`. R12 sets
/// no timer for this interval: `TimeoutStartUSec` (§7.3, O2) ends at
/// readiness, and only `RuntimeMaxUSec` (5 s + 100 ms + 5 s, §7.3 item 2)
/// caps the whole peer. The selector connects as soon as its step-8 checks
/// pass (§6 steps 8 and 9), so this in-process bound stays within that
/// lifetime and lets the peer exit on every path even without its unit.
const ACCEPT_BOUND: Timespec = Timespec {
    tv_sec: 5,
    tv_nsec: 0,
};

/// Why the recovery peer exited without an acknowledgement. No variant
/// names a secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RecoveryPeerError {
    /// The argument is not 32 lowercase hexadecimal digits.
    #[error("the recovery endpoint ID is not 32 lowercase hexadecimal digits")]
    Arguments,
    /// SIR1 is missing, unsafe or malformed.
    #[error(transparent)]
    PendingRecovery(#[from] SelectorBoundaryError),
    /// SPI1 or its key file was refused, or the key is not SIR1's.
    #[error(transparent)]
    ProviderInstallation(#[from] ProviderInstallationError),
    /// The recovery endpoint could not be bound, verified or accepted on.
    #[error(transparent)]
    Endpoint(#[from] ProviderRuntimeError),
    /// The one connection is not from a UID 0 peer.
    #[error("the recovery connection is not from root")]
    ForeignPeer,
    /// The exchange wrote no RCA1.
    #[error("the recovery exchange was refused")]
    Refused,
}

/// The `recovery-peer` mode for the argument after the mode name.
///
/// It reads `NOTIFY_SOCKET` and no other environment variable.
pub(crate) fn serve_recovery_peer(endpoint_id: &OsStr) -> Result<(), RecoveryPeerError> {
    serve_with(endpoint_id, super::notify_socket().as_deref(), ROOT_UID)
}

/// The mode, notifying `notify_socket` and accepting a peer of `peer_uid`.
fn serve_with(
    endpoint_id: &OsStr,
    notify_socket: Option<&OsStr>,
    peer_uid: u32,
) -> Result<(), RecoveryPeerError> {
    let endpoint = endpoint_path(endpoint_id)?;
    let key = PendingRecoveryRuntimeKey::read()?;
    let signer = RuntimeKey::open(&ProviderInstallation::open()?)
        .and_then(|runtime_key| runtime_key.require_admitted(key.public_key()))?
        .into_signer(key.key_id().to_owned());
    let endpoint = ProviderEndpoint::bind(&endpoint)?;
    notify::notify_ready(notify_socket);
    let stream = accept_one(&endpoint)?;
    let accepted = Instant::now();
    if !peer_has_uid(&stream, peer_uid) {
        return Err(RecoveryPeerError::ForeignPeer);
    }
    let responder = RevocationUpdateResponder::new(
        &signer,
        AdmittedRuntimeKey::new(key.key_id(), key.public_key()),
        AuthorityResolution::Recovery,
        RegistryAttempts,
        NoControlState,
    );
    answer(&responder, &stream, accepted)
}

/// `/run/pigloros/sandbox-selector-recovery/<id>.sock` for exactly 32
/// lowercase hexadecimal digits.
fn endpoint_path(endpoint_id: &OsStr) -> Result<PathBuf, RecoveryPeerError> {
    endpoint_id
        .to_str()
        .filter(|hex| {
            hex.len() == 32
                && hex
                    .bytes()
                    .all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(&digit))
        })
        .map(|hex| Path::new(RECOVERY_DIRECTORY).join(format!("{hex}.sock")))
        .ok_or(RecoveryPeerError::Arguments)
}

/// The one connection, accepted between the endpoint's checks once the
/// listener is readable within [`ACCEPT_BOUND`]. No connection in time, or an
/// accept that yields none, ends the peer, so it exits on every path even
/// without the unit's own bounds.
fn accept_one(endpoint: &ProviderEndpoint) -> Result<UnixStream, ProviderRuntimeError> {
    let mut ready = [PollFd::new(endpoint.listener(), PollFlags::IN)];
    poll(&mut ready, Some(&ACCEPT_BOUND))
        .map_err(unavailable)
        .and_then(|readable| {
            if readable == 0 {
                Err(ProviderRuntimeError::EndpointUnavailable)
            } else {
                endpoint.accept()
            }
        })
        .and_then(|accepted| accepted.ok_or(ProviderRuntimeError::EndpointUnavailable))
}

/// Whether the `SO_PEERCRED` UID of `stream`'s peer is `uid`.
fn peer_has_uid(stream: &UnixStream, uid: u32) -> bool {
    rustix::net::sockopt::socket_peercred(stream).is_ok_and(|peer| peer.uid.as_raw() == uid)
}

/// Answer the exchange within 100 ms of `accepted`, then send server EOF
/// after the RCA1.
fn answer(
    responder: &RevocationUpdateResponder<
        '_,
        KeyFileRuntimeSigner,
        RegistryAttempts,
        NoControlState,
    >,
    stream: &UnixStream,
    accepted: Instant,
) -> Result<(), RecoveryPeerError> {
    let deadline = exchange_deadline(accepted);
    match responder.respond(&mut Deadlined::until(stream, deadline), deadline) {
        ExchangeOutcome::Refused { .. } => Err(RecoveryPeerError::Refused),
        ExchangeOutcome::Acknowledged | ExchangeOutcome::Resent => stream
            .shutdown(Shutdown::Write)
            .map_err(unavailable)
            .map_err(RecoveryPeerError::Endpoint),
    }
}

/// The recovery peer's attempt state (R12 §5.1): the empty view, only when
/// the fixed registry, under its exclusive lock, holds no committed intent
/// and no temporary record. The lock is released before the view is
/// returned, so before RCA1 is written.
#[derive(Debug)]
struct RegistryAttempts;

impl AttemptStateSource for RegistryAttempts {
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send {
        let view = crate::SystemdAttemptRegistry::require_no_attempt_record()
            .ok()
            .map(|()| Vec::new());
        async move { view }
    }
}

/// The recovery peer has no control state to advance.
#[derive(Debug)]
struct NoControlState;

impl ExchangeObserver for NoControlState {
    fn fencing(&self) {}

    fn acknowledging(&self, _trust: &SandboxTrustSnapshot, _next: &SandboxRevocationSnapshot) {}
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
