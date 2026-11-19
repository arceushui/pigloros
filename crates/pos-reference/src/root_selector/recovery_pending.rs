//! The selector's `RecoveryPending` state (ADR-069 R12 §8).
//!
//! While a SIR1 is pending the selector exposes no evaluator pathname. Its
//! administrative listener stays bound and answers each root connection with
//! the mode-1 challenge of the pending transaction. Any SIU1 other than the
//! byte-identical pending one is rejected and changes nothing.
//!
//! The byte-identical SIU1 runs one new recovery operation with its own
//! 100 ms exchange (R12 §6, m6). It begins by loading SIR1 again. After its
//! durable completion the connection receives the exact RCA1 and server EOF,
//! and the selector opens normally from the next SIC1. Any failure closes the
//! connection without a reply, keeps SIR1 and stays in `RecoveryPending`; no
//! operation is retried automatically.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use super::{
    configure_update_stream, read_control_frame, require_stream_eof, root_peer,
    write_control_frame, NormalOpen, OwnedAdministratorListener, SelectorMode, ROOT_UID,
};
use crate::selector::installation::authority::AuthenticatedSelectorBootstrap;
use crate::selector::installation::{FixedInstallation, InstalledSelectorState};
use crate::selector::recovery::{
    CompletedRecovery, PendingRecoveryTarget, ProviderTerminationAuthority,
};
use crate::selector::runtime_lifecycle::ProviderLifecyclePort;
use crate::selector::SelectorBoundaryError;

/// Reopens the installation for a new recovery operation.
type InstallationOpener = Box<dyn Fn() -> Result<FixedInstallation, SelectorBoundaryError> + Send>;

/// One pending transaction and how the selector serves it.
pub(super) struct PendingRecovery {
    target: PendingRecoveryTarget,
    peer_uid: u32,
    reopen: InstallationOpener,
    authority: ProviderTerminationAuthority<dyn ProviderLifecyclePort + Send + Sync>,
    opening: NormalOpen,
}

impl PendingRecovery {
    /// The production state: root peers only, the fixed installation, and
    /// the termination authority over the selector's one lifecycle port.
    pub(super) fn fixed(target: PendingRecoveryTarget, opening: NormalOpen) -> Self {
        Self {
            target,
            peer_uid: ROOT_UID,
            reopen: Box::new(InstalledSelectorState::open_fixed),
            authority: opening.authority(),
            opening,
        }
    }

    /// Serves the administrative listener until one recovery operation
    /// completed durably, and returns the next state. Nothing is admitted
    /// meanwhile.
    ///
    /// # Errors
    /// Returns the listener's error when its pathname identity is lost or
    /// its accept loop fails.
    pub(super) fn serve(
        &self,
        listener: &OwnedAdministratorListener,
    ) -> Result<AuthenticatedSelectorBootstrap, SelectorBoundaryError> {
        loop {
            if let Some(bootstrap) = self.serve_once(listener)? {
                return Ok(bootstrap);
            }
        }
    }

    /// Normal open from the next state of a completed recovery.
    pub(super) fn open(
        &self,
        administrator: &OwnedAdministratorListener,
        bootstrap: AuthenticatedSelectorBootstrap,
    ) -> Result<SelectorMode, SelectorBoundaryError> {
        self.opening.open(administrator, bootstrap)
    }

    /// One poll of the administrative listener: answers a waiting connection,
    /// or sleeps briefly when none is waiting.
    ///
    /// # Errors
    /// Returns the listener's error when its pathname identity is lost or
    /// accepting fails. A connection's own failure never ends serving.
    fn serve_once(
        &self,
        listener: &OwnedAdministratorListener,
    ) -> Result<Option<AuthenticatedSelectorBootstrap>, SelectorBoundaryError> {
        listener
            .verify()
            .and_then(|()| listener.try_accept())
            .map(|accepted| {
                accepted.map_or_else(
                    || {
                        thread::sleep(Duration::from_millis(10));
                        None
                    },
                    |stream| self.answer(stream).ok(),
                )
            })
    }

    /// One administrative connection: the mode-1 challenge, then at most one
    /// framed SIU1 and client write EOF.
    ///
    /// # Errors
    /// A foreign peer, malformed framing, an expired challenge, or a SIU1
    /// other than the pending one is [`SelectorBoundaryError::ArtifactInvalid`]
    /// and closes the connection without a reply. The pending SIU1 runs one
    /// recovery operation; its failure also closes without a reply. After its
    /// durable completion the exact RCA1 and server EOF are sent, and the
    /// next state is returned even if that reply cannot be delivered.
    fn answer(
        &self,
        mut stream: UnixStream,
    ) -> Result<AuthenticatedSelectorBootstrap, SelectorBoundaryError> {
        if !root_peer(&stream, self.peer_uid) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        configure_update_stream(&stream)
            .and_then(|()| {
                let challenge = self.target.challenge();
                challenge
                    .to_canonical_cbor()
                    .and_then(|bytes| write_control_frame(&mut stream, &bytes))
                    .map(|()| challenge)
            })
            .and_then(|challenge| read_control_frame(&mut stream).map(|update| (challenge, update)))
            .and_then(|(challenge, update)| {
                require_stream_eof(&mut stream)
                    .and_then(|()| challenge.require_live())
                    .map(|()| update)
            })
            .and_then(|update| {
                if update == self.target.pending_update_bytes() {
                    self.begin_recovery_operation()
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
            .map(|completed| {
                let _reply =
                    write_control_frame(&mut stream, &completed.acknowledgement).and_then(|()| {
                        stream
                            .shutdown(Shutdown::Write)
                            .map_err(|_| SelectorBoundaryError::Io)
                    });
                completed.bootstrap
            })
    }

    /// Runs one new recovery operation. It reloads SIR1 from the
    /// installation, which must still name the pending transaction, and
    /// draws a fresh operation ID (R12 §4.1).
    ///
    /// # Errors
    /// Returns [`SelectorBoundaryError::ArtifactInvalid`] when SIR1 is gone,
    /// fails authentication, or names another transaction, and the
    /// operation's own failure otherwise. SIR1 then stays.
    pub(super) fn begin_recovery_operation(
        &self,
    ) -> Result<CompletedRecovery, SelectorBoundaryError> {
        (self.reopen)()
            .and_then(|installation| match installation {
                FixedInstallation::RecoveryPending(installed) => {
                    PendingRecoveryTarget::load(&installed).map_err(SelectorBoundaryError::from)
                }
                FixedInstallation::Admissible(_) => Err(SelectorBoundaryError::ArtifactInvalid),
            })
            .and_then(|operation| {
                if operation.identity() == self.target.identity() {
                    self.authority
                        .recover(operation)
                        .map_err(SelectorBoundaryError::from)
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs::{self, File};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use std::sync::Arc;

    use super::*;
    use crate::control_framing;
    use crate::evaluator_protocol::{array, decode_canonical, uint};
    use crate::root_selector::OwnedSelectorListener;
    use crate::selector::installation::tests::updates::{SuccessorRevocation, UpdateFixture};
    use crate::selector::recovery::tests::{
        peer_executable_digest, test_host, PeerPort, Reply, Script,
    };
    use crate::selector::runtime_lifecycle::ProviderLifecycleError;

    const RECOVERY_NAME: &str = "installation-update.cbor";

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const FRAME_LIMIT: usize = 16 * 1024 * 1024;

    /// The selector's result, the challenge the client read, and its reply.
    type Exchanged = (Result<(), SelectorBoundaryError>, Vec<u8>, Vec<u8>);

    /// A recovery directory and an empty cgroup2 stand-in for one test.
    struct Directories {
        recovery: tempfile::TempDir,
        cgroups: tempfile::TempDir,
    }

    impl Directories {
        fn new() -> TestResult<Self> {
            let recovery = tempfile::tempdir()?;
            fs::set_permissions(recovery.path(), fs::Permissions::from_mode(0o700))?;
            Ok(Self {
                recovery,
                cgroups: tempfile::tempdir()?,
            })
        }
    }

    /// A port whose every recovery operation fails at its first step.
    fn refusing() -> Script {
        Script {
            terminate: Reply::Refuse(ProviderLifecycleError::Unavailable),
            ..Script::default()
        }
    }

    fn opener(root: PathBuf) -> InstallationOpener {
        Box::new(move || {
            File::open(&root)
                .map_err(|_| SelectorBoundaryError::Io)
                .and_then(|root| InstalledSelectorState::open_fixed_at_for_test(&root))
        })
    }

    fn pending(
        fixture: &UpdateFixture,
        peer_uid: u32,
        directories: &Directories,
    ) -> TestResult<PendingRecovery> {
        pending_with(fixture, peer_uid, directories, refusing())
    }

    fn pending_with(
        fixture: &UpdateFixture,
        peer_uid: u32,
        directories: &Directories,
        script: Script,
    ) -> TestResult<PendingRecovery> {
        let reopen = opener(fixture.path().to_path_buf());
        let FixedInstallation::RecoveryPending(installed) = reopen()? else {
            return Err("no SIR1 is pending".into());
        };
        let port = Arc::new(PeerPort::new(directories.recovery.path(), script));
        let host = test_host(
            directories.recovery.path(),
            directories.cgroups.path(),
            port.clock(),
        )?;
        let opening = NormalOpen {
            recovery_directory: Arc::new(File::open(directories.recovery.path())?),
            port: Arc::clone(&port) as super::super::SelectorPort,
            executable_digest: peer_executable_digest,
            recovery_host: crate::selector::recovery::RecoveryHost::fixed,
        };
        Ok(PendingRecovery {
            target: PendingRecoveryTarget::load(&installed)?,
            peer_uid,
            reopen,
            authority: ProviderTerminationAuthority::new(port, host),
            opening,
        })
    }

    fn own_uid(path: &Path) -> TestResult<u32> {
        Ok(fs::metadata(path)?.uid())
    }

    /// Runs one connection: the client reads the challenge, sends `update`
    /// (if any) and write EOF, then reads everything the selector sent after
    /// the challenge.
    fn exchange(recovery: &PendingRecovery, update: Option<&[u8]>) -> TestResult<Exchanged> {
        let (mut client, server) = UnixStream::pair()?;
        let update = update.map(<[u8]>::to_vec);
        // A selector that closes early may reset the client, so the client
        // records what it received and ignores its own send failures.
        let client_thread = std::thread::spawn(move || {
            let challenge = control_framing::read_frame(&mut client, FRAME_LIMIT)
                .ok()
                .flatten()
                .unwrap_or_default();
            if let Some(update) = update {
                let _sent = control_framing::write_frame(&mut client, &update, FRAME_LIMIT);
            }
            let _closed = client.shutdown(std::net::Shutdown::Write);
            let mut reply = Vec::new();
            let _read = client.read_to_end(&mut reply);
            (challenge, reply)
        });
        let result = recovery.answer(server).map(drop);
        let (challenge, reply) = client_thread.join().map_err(|_| "client thread panicked")?;
        Ok((result, challenge, reply))
    }

    #[test]
    fn the_pending_update_starts_one_operation_and_stays_closed() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) = fixture.commit_pending_update(
            vec![[41; 16]],
            vec![[41; 16]],
            SuccessorRevocation::Nothing,
        )?;
        let directories = Directories::new()?;
        let recovery = pending(&fixture, own_uid(fixture.path())?, &directories)?;

        let (result, challenge, reply) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::SelectorUnavailable));
        assert!(reply.is_empty());
        let challenge = decode_canonical(&challenge)?;
        assert_eq!(uint(&array(&challenge, 5)?[4])?, 1);
        assert!(fixture.path().join(RECOVERY_NAME).exists());

        // An exact retry is again a new operation, never a stale success.
        let (result, _, reply) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::SelectorUnavailable));
        assert!(reply.is_empty());
        Ok(())
    }

    #[test]
    fn any_other_update_or_peer_is_rejected_without_a_reply() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) =
            fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
        let uid = own_uid(fixture.path())?;
        let directories = Directories::new()?;
        let recovery = pending(&fixture, uid, &directories)?;

        let mut changed = request.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let (result, _, reply) = exchange(&recovery, Some(&changed))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(reply.is_empty());

        let (result, _, reply) = exchange(&recovery, None)?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(reply.is_empty());

        let foreign = pending(&fixture, uid.wrapping_add(1), &directories)?;
        let (result, challenge, _) = exchange(&foreign, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(challenge.is_empty());

        let (client, server) = UnixStream::pair()?;
        drop(client);
        assert!(recovery.answer(server).is_err());
        Ok(())
    }

    /// Each poll waits when no client is queued, answers a queued client, and
    /// stops once the listener's pathname is gone. Driving `serve_once`
    /// directly covers every branch without racing the loop in `serve`.
    #[test]
    fn each_poll_waits_answers_or_stops_serving() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) =
            fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
        let directories = Directories::new()?;
        let recovery = pending(&fixture, own_uid(fixture.path())?, &directories)?;
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("administrator.sock");
        let listener = OwnedAdministratorListener {
            inner: OwnedSelectorListener::bind_path(&socket, own_uid(directory.path())?)?,
        };
        listener.set_nonblocking()?;

        assert!(recovery.serve_once(&listener)?.is_none());

        // The client queues its whole request first, so one thread suffices.
        let mut client = UnixStream::connect(&socket)?;
        control_framing::write_frame(&mut client, &request, FRAME_LIMIT)
            .map_err(|_| "the client could not send its update")?;
        client.shutdown(std::net::Shutdown::Write)?;
        assert!(recovery.serve_once(&listener)?.is_none());
        let challenge = control_framing::read_frame(&mut client, FRAME_LIMIT)
            .ok()
            .flatten()
            .ok_or("the selector sent no challenge")?;
        assert_eq!(uint(&array(&decode_canonical(&challenge)?, 5)?[4])?, 1);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply)?;
        assert!(reply.is_empty());

        fs::remove_file(&socket)?;
        assert!(recovery.serve_once(&listener).is_err());
        assert!(recovery.serve(&listener).is_err());
        Ok(())
    }

    #[test]
    fn an_operation_requires_the_same_pending_transaction() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) =
            fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
        let directories = Directories::new()?;
        let recovery = pending(&fixture, own_uid(fixture.path())?, &directories)?;
        let recovery_path = fixture.path().join(RECOVERY_NAME);

        fs::remove_file(&recovery_path)?;
        let (result, _, _) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));

        // Another transaction over the same previous SIC1.
        fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
        let (result, _, _) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));

        fs::remove_file(&recovery_path)?;
        let mut garbage = File::create(&recovery_path)?;
        garbage.write_all(b"not a SIR1")?;
        let (result, _, _) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        Ok(())
    }

    /// R12 §8 and I13: the byte-identical SIU1 runs one operation; only after
    /// its durable completion does the client receive the exact RCA1 and
    /// server EOF. A retry after completion is stale.
    #[test]
    fn the_pending_update_completes_recovery_and_receives_the_exact_rca1() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) = fixture.commit_pending_update(
            vec![[41; 16]],
            vec![[41; 16]],
            SuccessorRevocation::Nothing,
        )?;
        let directories = Directories::new()?;
        let uid = own_uid(fixture.path())?;
        let recovery = pending_with(&fixture, uid, &directories, Script::default())?;

        let (result, _, reply) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Ok(()));
        let mut framed = reply.as_slice();
        let acknowledgement = control_framing::read_frame(&mut framed, FRAME_LIMIT)
            .ok()
            .flatten()
            .ok_or("no RCA1 frame")?;
        assert!(framed.is_empty(), "anything after the RCA1 frame");
        let rca1 = recovery
            .target
            .authenticate_recovery_acknowledgement(&acknowledgement)?;
        assert_eq!(rca1.cancelled_attempt_ids(), [[41; 16]]);
        assert!(!fixture.path().join(RECOVERY_NAME).exists());

        let (result, _, reply) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(reply.is_empty());
        Ok(())
    }

    /// Serving stops at the first durable completion, and the selector then
    /// opens normally from the next state; here that open fails closed, since
    /// the port cannot start a runtime.
    #[test]
    fn serving_ends_at_completion_and_opens_from_the_next_state() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) =
            fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
        let directories = Directories::new()?;
        let recovery = pending_with(
            &fixture,
            own_uid(fixture.path())?,
            &directories,
            Script::default(),
        )?;
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("administrator.sock");
        let listener = OwnedAdministratorListener {
            inner: OwnedSelectorListener::bind_path(&socket, own_uid(directory.path())?)?,
        };
        listener.set_nonblocking()?;
        let client = std::thread::spawn(move || -> Result<Vec<u8>, String> {
            let mut client = UnixStream::connect(&socket).map_err(|error| error.to_string())?;
            control_framing::write_frame(&mut client, &request, FRAME_LIMIT)
                .map_err(|_| "the client could not send its update")?;
            client
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| error.to_string())?;
            let mut received = Vec::new();
            client
                .read_to_end(&mut received)
                .map_err(|error| error.to_string())?;
            Ok(received)
        });
        assert!(SelectorMode::RecoveryPending(recovery)
            .serve(listener)
            .is_err());
        let received = client.join().map_err(|_| "client thread panicked")??;
        let mut framed = received.as_slice();
        let challenge = control_framing::read_frame(&mut framed, FRAME_LIMIT)
            .ok()
            .flatten()
            .ok_or("no challenge")?;
        assert_eq!(uint(&array(&decode_canonical(&challenge)?, 5)?[4])?, 1);
        assert!(control_framing::read_frame(&mut framed, FRAME_LIMIT)
            .ok()
            .flatten()
            .is_some());
        assert!(!fixture.path().join(RECOVERY_NAME).exists());
        Ok(())
    }
}
