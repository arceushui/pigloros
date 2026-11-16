//! The selector's `RecoveryPending` state (ADR-069 R12 §8).
//!
//! While a SIR1 is pending the selector exposes no evaluator pathname. Its
//! administrative listener stays bound and answers each root connection with
//! the mode-1 challenge of the pending transaction. Any SIU1 other than the
//! byte-identical pending one is rejected and changes nothing.
//!
//! The byte-identical SIU1 starts one new recovery operation, which begins
//! by loading SIR1 again (R12 §6). This slice ends the operation there: the
//! termination, recovery-peer and completion steps are later slices on the
//! same seam, so the connection closes without a reply, SIR1 stays, and the
//! selector stays in `RecoveryPending`.

use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use super::{
    configure_update_stream, read_control_frame, require_stream_eof, root_peer,
    write_control_frame, OwnedAdministratorListener, ROOT_UID,
};
use crate::selector::installation::{FixedInstallation, InstalledSelectorState};
use crate::selector::recovery::PendingRecoveryTarget;
use crate::selector::SelectorBoundaryError;

/// Reopens the installation for a new recovery operation.
type InstallationOpener = Box<dyn Fn() -> Result<FixedInstallation, SelectorBoundaryError> + Send>;

/// One pending transaction and how the selector serves it.
pub(super) struct PendingRecovery {
    target: PendingRecoveryTarget,
    peer_uid: u32,
    reopen: InstallationOpener,
}

impl PendingRecovery {
    /// The production state: root peers only, and the fixed installation.
    pub(super) fn fixed(target: PendingRecoveryTarget) -> Self {
        Self {
            target,
            peer_uid: ROOT_UID,
            reopen: Box::new(InstalledSelectorState::open_fixed),
        }
    }

    /// Serves the administrative listener until its pathname identity is
    /// lost or its accept loop fails. Nothing is ever admitted.
    pub(super) fn serve(
        &self,
        listener: &OwnedAdministratorListener,
    ) -> Result<(), SelectorBoundaryError> {
        loop {
            match listener.verify().and_then(|()| listener.try_accept()) {
                Ok(Some(stream)) => {
                    let _retry_result = self.answer(stream);
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => return Err(error),
            }
        }
    }

    /// One administrative connection: the mode-1 challenge, then at most one
    /// framed SIU1 and client write EOF.
    ///
    /// # Errors
    /// Every outcome closes the connection without a reply. A foreign peer,
    /// malformed framing, an expired challenge, or a SIU1 other than the
    /// pending one is [`SelectorBoundaryError::ArtifactInvalid`]. The pending
    /// SIU1 starts a recovery operation, which stops closed.
    fn answer(&self, mut stream: UnixStream) -> Result<(), SelectorBoundaryError> {
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
    }

    /// A new recovery operation reloads SIR1 from the installation, which
    /// must still name the pending transaction.
    ///
    /// # Errors
    /// Returns [`SelectorBoundaryError::ArtifactInvalid`] when SIR1 is gone,
    /// fails authentication, or names another transaction. Otherwise returns
    /// [`SelectorBoundaryError::SelectorUnavailable`]: the operation's
    /// remaining steps are not available, so it stops closed.
    fn begin_recovery_operation(&self) -> Result<(), SelectorBoundaryError> {
        (self.reopen)()
            .and_then(|installation| match installation {
                FixedInstallation::RecoveryPending(installed) => {
                    PendingRecoveryTarget::load(&installed).map_err(SelectorBoundaryError::from)
                }
                FixedInstallation::Admissible(_) => Err(SelectorBoundaryError::ArtifactInvalid),
            })
            .and_then(|operation| {
                Err(if operation.identity() == self.target.identity() {
                    SelectorBoundaryError::SelectorUnavailable
                } else {
                    SelectorBoundaryError::ArtifactInvalid
                })
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs::{self, File};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::control_framing;
    use crate::evaluator_protocol::{array, decode_canonical, uint};
    use crate::selector::installation::tests::updates::UpdateFixture;

    const RECOVERY_NAME: &str = "installation-update.cbor";

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const FRAME_LIMIT: usize = 16 * 1024 * 1024;

    /// The selector's result, the challenge the client read, and its reply.
    type Exchanged = (Result<(), SelectorBoundaryError>, Vec<u8>, Vec<u8>);

    fn opener(root: PathBuf) -> InstallationOpener {
        Box::new(move || {
            File::open(&root)
                .map_err(|_| SelectorBoundaryError::Io)
                .and_then(|root| InstalledSelectorState::open_fixed_at_for_test(&root))
        })
    }

    fn pending(fixture: &UpdateFixture, peer_uid: u32) -> TestResult<PendingRecovery> {
        let reopen = opener(fixture.path().to_path_buf());
        let FixedInstallation::RecoveryPending(installed) = reopen()? else {
            return Err("no SIR1 is pending".into());
        };
        Ok(PendingRecovery {
            target: PendingRecoveryTarget::load(&installed)?,
            peer_uid,
            reopen,
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
        let result = recovery.answer(server);
        let (challenge, reply) = client_thread.join().map_err(|_| "client thread panicked")?;
        Ok((result, challenge, reply))
    }

    #[test]
    fn the_pending_update_starts_one_operation_and_stays_closed() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) =
            fixture.commit_pending_update(vec![[41; 16]], vec![[41; 16]], false)?;
        let recovery = pending(&fixture, own_uid(fixture.path())?)?;

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
        let (_committed, request) = fixture.commit_pending_update(Vec::new(), Vec::new(), false)?;
        let uid = own_uid(fixture.path())?;
        let recovery = pending(&fixture, uid)?;

        let mut changed = request.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let (result, _, reply) = exchange(&recovery, Some(&changed))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(reply.is_empty());

        let (result, _, reply) = exchange(&recovery, None)?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(reply.is_empty());

        let foreign = pending(&fixture, uid.wrapping_add(1))?;
        let (result, challenge, _) = exchange(&foreign, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(challenge.is_empty());

        let (client, server) = UnixStream::pair()?;
        drop(client);
        assert!(recovery.answer(server).is_err());
        Ok(())
    }

    #[test]
    fn an_operation_requires_the_same_pending_transaction() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) = fixture.commit_pending_update(Vec::new(), Vec::new(), false)?;
        let recovery = pending(&fixture, own_uid(fixture.path())?)?;
        let recovery_path = fixture.path().join(RECOVERY_NAME);

        fs::remove_file(&recovery_path)?;
        let (result, _, _) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));

        // Another transaction over the same previous SIC1.
        fixture.commit_pending_update(Vec::new(), Vec::new(), false)?;
        let (result, _, _) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));

        fs::remove_file(&recovery_path)?;
        let mut garbage = File::create(&recovery_path)?;
        garbage.write_all(b"not a SIR1")?;
        let (result, _, _) = exchange(&recovery, Some(&request))?;
        assert_eq!(result, Err(SelectorBoundaryError::ArtifactInvalid));
        Ok(())
    }
}
