//! Process-private lifecycle for the ADR-109 pathname listener and the one
//! erasure host it shares with the HTTP Gateway (ADR-109 revision 9,
//! Decision 1 items 7 and 8).

use std::{
    fs,
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use piglor_ledger::LedgerView;
use pos_core::ForkAdmissionHostRecordV1;
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{
    sqlite::SqliteStore, ForkAdmissionAuthoritySessionV1, ForkEventAuthorityErrorV1,
    ForkEventPermitIssuerV1, StoreConfig,
};

use crate::{
    executor::ForkAdmissionSlotV1,
    local_fork_authentication::{
        LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1,
    },
    local_fork_classifier_profile::ForkClassifierProfileV1,
    local_fork_coordinator::{
        open_fork_admission_session, reconcile_startup, LocalForkAdmissionCoordinatorV1,
    },
    local_fork_listener::bind_pathname_listener,
    router_for_addr,
    startup::{
        announce_listening, open_recovered_erasure_host, stop_after_bind_failure,
        GatewayHostStoreV1,
    },
    AppState, Gateway, LedgerWriteMode, OwnTracksOwnerKey,
};

type ServeError = Box<dyn std::error::Error + Send + Sync>;

/// The private paths of one local Fork-admission deployment.
#[derive(Clone, Copy, Debug)]
pub struct LocalForkAdmissionPathsV1<'a> {
    /// The one `SQLite` database the HTTP Gateway and the listener share.
    pub sqlite_path: &'a str,
    /// The ADR-109 pathname socket.
    pub socket_path: &'a Path,
    /// The validated systemd credential directory.
    pub credential_directory: &'a Path,
}

/// Running local Fork-admission listener owned by the Gateway process.
///
/// The type exposes lifecycle only; its credential, session, journal, and
/// protocol values remain private to this crate.
pub(super) struct LocalForkAdmissionListenerV1 {
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    socket_path: Option<PathBuf>,
}

/// How long shutdown waits for the listener thread to finish its in-flight
/// request (ADR-109 revision 9, Decision 1 item 8 step 2).
///
/// It covers one worst-case request so a legitimate one is not truncated: the
/// 5 s frame read, up to four 5 s executor admission waits (claim, execute,
/// cancel or recover, mark), and the 5 s response write.
const LISTENER_STOP_DEADLINE: Duration = Duration::from_secs(30);

impl LocalForkAdmissionListenerV1 {
    /// Stop accepting new local admission requests, join the worker, and
    /// unlink the socket pathname this listener bound (ADR-109 revision 9,
    /// Decision 1 item 8 step 2).
    ///
    /// An in-flight request finishes its remaining commands first, because
    /// the executor is still open, and a started executor command is awaited
    /// to completion (Decision 1 item 5). Only this join is bounded: it runs on
    /// a detached joiner thread, so a wedged worker cannot hang process
    /// shutdown; after `LISTENER_STOP_DEADLINE` the socket is unlinked anyway
    /// and the stop reports `TimedOut`.
    pub(super) async fn stop(self) -> io::Result<()> {
        self.stop_within(LISTENER_STOP_DEADLINE).await
    }

    async fn stop_within(mut self, deadline: Duration) -> io::Result<()> {
        self.stopping.store(true, Ordering::Release);
        let worker = self.worker.take();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // The joiner is detached on purpose: if the worker is wedged past the
        // deadline, the joiner stays blocked on it until process exit rather
        // than holding up shutdown. A late send to the dropped receiver is
        // ignored.
        drop(thread::spawn(move || {
            drop(sender.send(join_listener_worker(worker)));
        }));
        let joined = tokio::time::timeout(deadline, receiver)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Fork-admission listener did not stop",
                )
            })
            .and_then(|received| received.map_err(io::Error::other).flatten());
        let unlinked = self.socket_path.take().map_or(Ok(()), fs::remove_file);
        joined.and(unlinked)
    }
}

fn join_listener_worker(worker: Option<JoinHandle<()>>) -> io::Result<()> {
    worker.map_or(Ok(()), |worker| {
        worker
            .join()
            .map_err(|_| io::Error::other("Fork-admission listener worker panicked"))
    })
}

impl Drop for LocalForkAdmissionListenerV1 {
    /// Never blocks: a listener dropped without `stop` (a cancelled
    /// serve future or an unwinding panic) signals stop, detaches a worker
    /// that is still running (it exits after its in-flight request), and
    /// removes the pathname at most once. After `stop` both are already gone.
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        drop(self.worker.take());
        drop(self.socket_path.take().map(fs::remove_file));
    }
}

/// Provision the empty `SQLite` store with the host credentials in one protected
/// systemd credential directory.
///
/// # Errors
/// Returns an error when the credentials are unavailable or invalid, or when
/// the store cannot be opened or provisioned.
pub fn provision_local_fork_admission_authority(
    sqlite_path: &str,
    credential_directory: &Path,
) -> io::Result<()> {
    let credentials = credentials(credential_directory)?;
    provision_with_credentials(sqlite_path, &credentials)
}

fn provision_with_credentials(
    sqlite_path: &str,
    credentials: &LocalForkAuthenticationCredentialsV1,
) -> io::Result<()> {
    let mut store = SqliteStore::open(sqlite_path).map_err(io::Error::other)?;
    credentials
        .provision_authority(&mut store)
        .map(|_| ())
        .map_err(io::Error::other)
}

/// Serve the HTTP Gateway and the local Fork-admission listener over the one
/// erasure host of `paths.sqlite_path` (ADR-109 revision 9, Decision 1).
///
/// Startup fails closed in this order, and no listener binds before its
/// last step: the three managed credentials (FACR1, FAHK1, and the FCP1
/// classifier profile) are validated and decoded before the database opens;
/// the host recovers a verified inventory with `composition`; the read-only
/// FCP1 preflight and then the FAO1 open proof run on the host's own adapter;
/// the journal is reconciled there; the host and the Fork-admission slot,
/// which alone holds the session's permit issuer and the profile, move into
/// one `StoreExecutor`; then TCP and, last, the Unix pathname socket bind
/// (ADR-109 revision 12). Shutdown stops TCP, then the
/// listener, then drains the executor. The binary passes the closed
/// composition; no flag, environment variable, or credential selects another.
///
/// # Errors
/// Returns the first startup, serve, listener, or executor shutdown error.
pub async fn serve_local_fork_admission(
    addr: SocketAddr,
    paths: LocalForkAdmissionPathsV1<'_>,
    owntracks_owner_key: Option<&OwnTracksOwnerKey>,
    composition: &ErasureCoordinatorCompositionV1,
    shutdown: impl Future<Output = ()> + Send + 'static,
    ledger: (LedgerView, LedgerWriteMode),
) -> Result<(), ServeError> {
    let managed = managed_credentials(paths.credential_directory)?;
    let started =
        open_with_credentials(paths.sqlite_path, managed, owntracks_owner_key, composition)?;
    serve_started(addr, started, paths.socket_path, shutdown, ledger).await
}

/// Startup steps 2 to 5: open the one host with `composition`, preflight the
/// FCP1 profile and open the ADR-106 session on its adapter, reconcile the
/// journal there, and move the host with its Fork-admission slot into the
/// Gateway's `StoreExecutor`.
fn open_with_credentials(
    sqlite_path: &str,
    (credentials, profile): (
        LocalForkAuthenticationCredentialsV1,
        ForkClassifierProfileV1,
    ),
    owntracks_owner_key: Option<&OwnTracksOwnerKey>,
    composition: &ErasureCoordinatorCompositionV1,
) -> io::Result<(Gateway, LocalForkAdmissionCoordinatorV1)> {
    // Startup step 2: the one read-write adapter and erasure host of the store.
    let store = if owntracks_owner_key.is_some() {
        GatewayHostStoreV1::OwnTracks
    } else {
        GatewayHostStoreV1::Standard
    };
    let mut host = open_recovered_erasure_host(
        StoreConfig::Sqlite {
            path: sqlite_path.to_owned(),
        },
        store,
        composition,
    )?;
    let (session, issuer, record) = open_profiled_session(&mut host, &credentials, &profile)?;
    let tuples = host.reconcile_fork_delivery_journal(&session);
    reconcile_startup(
        &credentials,
        (record, session.identity()),
        tuples,
        |tuple, proof| host.reconcile_fork_delivery_startup(&session, tuple, proof),
    )
    .map_err(io::Error::other)?;
    let session_identity = session.identity();
    let slot = ForkAdmissionSlotV1::new(
        session,
        issuer,
        credentials.policy().clone(),
        profile.into_sources(),
    );
    let (gateway, submitter) =
        Gateway::new_with_fork_admission_erasure_host(host, owntracks_owner_key, slot)
            .map_err(io::Error::other)?;
    let coordinator = LocalForkAdmissionCoordinatorV1::new(
        credentials,
        record,
        session_identity,
        Box::new(submitter),
    );
    Ok((gateway, coordinator))
}

/// ADR-109 revision 12 startup steps 2a and 3: run the read-only FCP1
/// preflight on the host adapter, then the FAO1 open proof, and take the new
/// session's one permit issuer for the executor slot.
fn open_profiled_session(
    host: &mut ErasureExecutionHostV1,
    credentials: &LocalForkAuthenticationCredentialsV1,
    profile: &ForkClassifierProfileV1,
) -> io::Result<(
    ForkAdmissionAuthoritySessionV1,
    ForkEventPermitIssuerV1,
    ForkAdmissionHostRecordV1,
)> {
    host.preflight_fork_classifier_profile(profile.sources())
        .map_err(preflight_error)
        .and_then(|()| open_fork_admission_session(host, credentials))
        .and_then(|(mut session, record)| {
            session
                .take_event_permit_issuer()
                .map(|issuer| (session, issuer, record))
                .ok_or(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        })
        .map_err(io::Error::other)
}

/// Map a read-only FCP1 preflight failure to the activation outcome.
///
/// Only an indeterminate storage read is retryable; every other outcome means
/// the durable FCS1 rows disagree with the profile, so the profile is invalid.
const fn preflight_error(error: ForkEventAuthorityErrorV1) -> LocalForkAuthenticationErrorV1 {
    match error {
        ForkEventAuthorityErrorV1::StorageIndeterminate => {
            LocalForkAuthenticationErrorV1::CredentialUnavailable
        }
        _ => LocalForkAuthenticationErrorV1::CredentialInvalid,
    }
}

/// Startup step 6 and the shutdown order of Decision 1 item 8.
///
/// The shutdown order (TCP, listener, executor) is this function's linear
/// sequence of awaits; no test seam observes its interleaving inside
/// `axum::serve`. The load-bearing property, that the listener finishes an
/// in-flight request while the executor is still open, is asserted on the
/// same two calls by the A8 test.
async fn serve_started(
    addr: SocketAddr,
    (gateway, coordinator): (Gateway, LocalForkAdmissionCoordinatorV1),
    socket_path: &Path,
    shutdown: impl Future<Output = ()> + Send + 'static,
    (ledger_view, ledger_write): (LedgerView, LedgerWriteMode),
) -> Result<(), ServeError> {
    let app = router_for_addr(
        addr,
        AppState {
            gateway: gateway.clone(),
            ledger_view,
            ledger_write,
        },
    );
    let tcp = match tokio::net::TcpListener::bind(addr).await {
        Ok(tcp) => tcp,
        Err(error) => return stop_after_bind_failure(&gateway, error).await,
    };
    let listener = match start_listener(coordinator, socket_path) {
        Ok(listener) => listener,
        Err(error) => return stop_after_bind_failure(&gateway, error).await,
    };
    announce_listening(addr);
    let serve_result = axum::serve(tcp, app).with_graceful_shutdown(shutdown).await;
    let stop_result = listener.stop().await;
    let shutdown_result = gateway.shutdown().await.map_err(ServeError::from);
    serve_result
        .and(stop_result)
        .map_err(ServeError::from)
        .and(shutdown_result)
}

/// Bind the Unix pathname socket last and spawn the listener thread.
fn start_listener(
    mut coordinator: LocalForkAdmissionCoordinatorV1,
    socket_path: &Path,
) -> io::Result<LocalForkAdmissionListenerV1> {
    let listener = bind_pathname_listener(socket_path)
        .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))?;
    let stopping = Arc::new(AtomicBool::new(false));
    let worker_stopping = Arc::clone(&stopping);
    thread::Builder::new()
        .name("piglor-fork-admission".to_owned())
        .spawn(move || {
            while !worker_stopping.load(Ordering::Acquire) {
                // An idle listener (WouldBlock) and a disconnected peer both
                // back off briefly; neither can stop future local admissions.
                if coordinator.serve_one(&listener).is_err() {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        })
        .map_err(io::Error::other)
        .map(|worker| LocalForkAdmissionListenerV1 {
            stopping,
            worker: Some(worker),
            socket_path: Some(socket_path.to_path_buf()),
        })
}

fn credentials(directory: &Path) -> io::Result<LocalForkAuthenticationCredentialsV1> {
    LocalForkAuthenticationCredentialsV1::load(directory, rustix::process::geteuid().as_raw())
        .map_err(io::Error::other)
}

/// ADR-107 r6 startup step 1: exactly FACR1, FAHK1, and the FCP1 profile.
fn managed_credentials(
    directory: &Path,
) -> io::Result<(
    LocalForkAuthenticationCredentialsV1,
    ForkClassifierProfileV1,
)> {
    LocalForkAuthenticationCredentialsV1::load_managed(
        directory,
        rustix::process::geteuid().as_raw(),
    )
    .map_err(io::Error::other)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        executor::{ForkAdmissionSubmissionErrorV1, ForkAdmissionSubmissionV1, StoreExecutor},
        local_fork_authentication::{
            test_credential_bytes_for_service, test_credentials_for_current_peer_with_seeds,
        },
        local_fork_classifier_profile::{
            test_profile_bytes, test_profile_source, CLASSIFIER_PROFILE_CREDENTIAL_NAME,
            MAX_CLASSIFIER_PROFILE_BYTES,
        },
        local_fork_coordinator::LocalForkDeliveryJournalV1,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ciborium::value::Value;
    use pos_core::erasure::target_closure_digest;
    use pos_core::{
        ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
        ErasureApplicabilityDecisionV1, ErasureArtifactClassV1,
        ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
        ErasureAtomicFreezeResultV1, ErasureAuthorizationDecisionV1, ErasureCorrectionProvenanceV1,
        ErasureDestructionCommandV1, ErasureErrorV1, ErasureForkAdmissionInputV1,
        ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceInputV1,
        ErasureFreezeAdmissionEvidenceV1, ErasureFreezeApplicabilityRowV1,
        ErasureFreezeAuthorizationEvidenceInputV1, ErasureFreezeAuthorizationEvidenceV1,
        ErasureFreezeAuthorizationVerifierV1, ErasureInventoryCategoryV1, ErasureKeyRoleV1,
        ErasureLifecycleV1, ErasureObligationInputV1, ErasureObligationSetInputV1,
        ErasureObligationSetV1, ErasureObligationV1, ErasureReceiptInputV1,
        ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1, ErasureRequestInputV1,
        ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeCommitmentInputV1,
        ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1, ErasureScopeExtensionV1,
        ErasureScopeV1, ErasureStateTransitionV1, ErasureVerifiedTopologyObservationV1,
        EventStore as _, TimelineId, TimelineMeta,
    };
    use pos_runtime::{ErasureCoordinatorAuthorityV1, ErasureExecutionHostV1, ErasureHostStatusV1};
    use rusqlite::{params, OptionalExtension as _};
    use std::{
        collections::BTreeMap,
        io::{Read as _, Write as _},
        net::Shutdown,
        os::unix::{fs::PermissionsExt as _, net::UnixStream},
        sync::{atomic::AtomicBool, Mutex, PoisonError},
        time::Instant,
    };
    use tower::ServiceExt as _;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const BIND_OK: [u8; 10] = [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82];

    fn rejected(code: u8) -> Vec<u8> {
        vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, code, 0xf6]
    }

    // -----------------------------------------------------------------
    // Credentials, sockets, and FAL1 frames.
    // -----------------------------------------------------------------

    fn protected_credential_file(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        let path = directory.join(name);
        if path.exists() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
    }

    fn protected_credentials(
        directory: &Path,
        adapter_seed: [u8; 32],
        host_seed: [u8; 32],
    ) -> io::Result<()> {
        let service_uid = rustix::process::geteuid().as_raw();
        let (auth, host) = test_credential_bytes_for_service(service_uid, adapter_seed, host_seed)
            .map_err(io::Error::other)?;
        protected_credential_file(directory, "pigloros.fork-admission-auth", &auth)?;
        protected_credential_file(directory, "pigloros.fork-admission-host-signer", &host)
    }

    fn protected_credential_directory(parent: &Path) -> io::Result<PathBuf> {
        let directory = parent.join("credentials");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn current_peer_credentials() -> io::Result<LocalForkAuthenticationCredentialsV1> {
        test_credentials_for_current_peer_with_seeds([7; 32], [8; 32]).map_err(io::Error::other)
    }

    /// Canonical FCP1 bytes with one empty-route row per descriptor byte.
    fn profile_bytes(descriptors: &[u8]) -> io::Result<Vec<u8>> {
        descriptors
            .iter()
            .map(|descriptor| test_profile_source(*descriptor, Vec::new()))
            .collect::<Result<Vec<_>, _>>()
            .map(|rows| test_profile_bytes(&rows))
            .map_err(io::Error::other)
    }

    fn profile_from(descriptors: &[u8]) -> io::Result<ForkClassifierProfileV1> {
        ForkClassifierProfileV1::from_canonical_cbor(&profile_bytes(descriptors)?)
            .map_err(io::Error::other)
    }

    /// The startup-step-1 inputs of the fixtures: the current-peer
    /// credentials and an FCP1 row for the FAL1 Fork descriptor `[7; 32]`.
    fn current_peer_managed() -> io::Result<(
        LocalForkAuthenticationCredentialsV1,
        ForkClassifierProfileV1,
    )> {
        Ok((current_peer_credentials()?, profile_from(&[7])?))
    }

    /// Add the ADR-107 r6 third managed credential, the FCP1 profile.
    fn install_profile(directory: &Path, profile: &[u8]) -> io::Result<()> {
        protected_credential_file(directory, CLASSIFIER_PROFILE_CREDENTIAL_NAME, profile)
    }

    /// The ADR-107 r6 managed-service directory: FACR1, FAHK1, and FCP1.
    fn managed_credentials(
        directory: &Path,
        (adapter_seed, host_seed): ([u8; 32], [u8; 32]),
        profile: &[u8],
    ) -> io::Result<()> {
        protected_credentials(directory, adapter_seed, host_seed)?;
        install_profile(directory, profile)
    }

    fn bind_payload(operation: u8) -> Vec<u8> {
        [0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20]
            .into_iter()
            .chain([operation; 32])
            .collect()
    }

    fn fork_payload(operation: u8, parent: TimelineId) -> io::Result<Vec<u8>> {
        let value = Value::Array(vec![
            Value::Text("FAL1".to_owned()),
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Bytes(vec![operation; 32]),
                Value::Bytes(parent.inner().to_bytes().to_vec()),
                Value::Integer(0.into()),
                Value::Bytes(vec![7; 32]),
                Value::Bytes(vec![8; 32]),
                Value::Bool(false),
                Value::Text("listener-child".to_owned()),
            ]),
        ]);
        let mut payload = Vec::new();
        ciborium::into_writer(&value, &mut payload).map_err(io::Error::other)?;
        Ok(payload)
    }

    fn frame(payload: &[u8]) -> io::Result<Vec<u8>> {
        let length = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "test FAL1 too large"))?;
        Ok([length.to_be_bytes().as_slice(), payload].concat())
    }

    fn request(socket: &Path, payload: &[u8], fragmented: bool) -> io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(socket)?;
        let frame = frame(payload)?;
        if fragmented {
            for fragment in frame.chunks(3) {
                stream.write_all(fragment)?;
            }
        } else {
            stream.write_all(&frame)?;
        }
        stream.shutdown(Shutdown::Write)?;
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
        let mut response = vec![0; length];
        stream.read_exact(&mut response)?;
        Ok(response)
    }

    fn disconnect_after_complete_request(socket: &Path, payload: &[u8]) -> io::Result<()> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(&frame(payload)?)?;
        stream.shutdown(Shutdown::Both)
    }

    fn request_without_half_close(socket: &Path, payload: &[u8]) -> io::Result<()> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(&frame(payload)?)?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(())
            }
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "listener closed an incomplete request before its EOF",
            )),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "listener answered before the request half-close",
            )),
            Err(error) => Err(error),
        }
    }

    fn trailing_byte_request(socket: &Path, payload: &[u8]) -> io::Result<()> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(&frame(payload)?)?;
        stream.write_all(&[0])?;
        stream.shutdown(Shutdown::Write)?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte)? {
            0 => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "listener answered a request with trailing bytes",
            )),
        }
    }

    /// The child and admission digest of a successful FARL1 Fork result.
    fn fork_result(response: &[u8]) -> io::Result<(TimelineId, [u8; 32])> {
        let invalid =
            |message: &str| io::Error::new(io::ErrorKind::InvalidData, message.to_owned());
        let Value::Array(fields) = ciborium::from_reader(response).map_err(io::Error::other)?
        else {
            return Err(invalid("FARL1 must be an array"));
        };
        let [Value::Text(marker), Value::Integer(version), Value::Integer(code), Value::Array(result)] =
            fields.as_slice()
        else {
            return Err(invalid("invalid FARL1 fields"));
        };
        if marker != "FARL1" || *version != 1.into() || *code != 0.into() {
            return Err(invalid("FARL1 is not successful"));
        }
        let [Value::Integer(kind), Value::Bytes(child), Value::Bytes(admission)] =
            result.as_slice()
        else {
            return Err(invalid("FARL1 is not a Fork result"));
        };
        if *kind != 2.into() {
            return Err(invalid("FARL1 kind is not Fork"));
        }
        let child: [u8; 16] = child
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid Fork child ID"))?;
        let admission = admission
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid admission digest"))?;
        Ok((
            TimelineId::from_ulid(ulid::Ulid::from_bytes(child)),
            admission,
        ))
    }

    // -----------------------------------------------------------------
    // One provisioned database and its independent observers.
    // -----------------------------------------------------------------

    struct World {
        _directory: tempfile::TempDir,
        runtime: tempfile::TempDir,
        database: PathBuf,
        socket: PathBuf,
    }

    impl World {
        fn path(&self) -> io::Result<&str> {
            self.database
                .to_str()
                .ok_or_else(|| io::Error::other("temporary database path is not UTF-8"))
        }
    }

    fn unprovisioned_world() -> io::Result<World> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let database = directory.path().join("gateway.db");
        let socket = runtime.path().join("fork-admission.sock");
        Ok(World {
            _directory: directory,
            runtime,
            database,
            socket,
        })
    }

    /// A database with FAH1 provisioned for the current-peer credentials and
    /// one root Timeline per name.
    fn provisioned_world(parents: &[&str]) -> TestResult<(World, Vec<TimelineId>)> {
        let world = unprovisioned_world()?;
        let mut store = SqliteStore::open(world.path()?)?;
        let parents = parents
            .iter()
            .map(|name| store.create_timeline(name).map(|timeline| timeline.id()))
            .collect::<Result<Vec<_>, _>>()?;
        drop(store);
        provision_with_credentials(world.path()?, &current_peer_credentials()?)?;
        Ok((world, parents))
    }

    fn start(
        world: &World,
        composition: &ErasureCoordinatorCompositionV1,
    ) -> TestResult<(Gateway, LocalForkAdmissionListenerV1)> {
        let (gateway, coordinator) =
            open_with_credentials(world.path()?, current_peer_managed()?, None, composition)?;
        let listener = start_listener(coordinator, &world.socket)?;
        Ok((gateway, listener))
    }

    async fn stop(
        world: &World,
        gateway: Gateway,
        listener: LocalForkAdmissionListenerV1,
    ) -> TestResult {
        listener.stop().await?;
        assert!(!world.socket.exists());
        gateway.shutdown().await?;
        Ok(())
    }

    /// Timelines, FAR1, operation rows, POB1 rows, and the wall fence, read
    /// through an independent connection.
    fn graph_rows(world: &World) -> rusqlite::Result<[i64; 5]> {
        let connection = rusqlite::Connection::open(&world.database)?;
        let mut rows = [0; 5];
        for (slot, query) in rows.iter_mut().zip([
            "SELECT COUNT(*) FROM timelines",
            "SELECT COUNT(*) FROM fork_admissions",
            "SELECT COUNT(*) FROM fork_admission_operations",
            "SELECT COUNT(*) FROM fork_principal_owner_bindings",
            "SELECT last_authority_wall_time FROM fork_admission_authority WHERE singleton = 1",
        ]) {
            *slot = connection.query_row(query, [], |row| row.get(0))?;
        }
        Ok(rows)
    }

    fn delivery_state(world: &World, operation: u8) -> rusqlite::Result<Option<i64>> {
        rusqlite::Connection::open(&world.database)?
            .query_row(
                "SELECT state FROM fork_delivery_journal WHERE operation_id = ?1",
                params![[operation; 32].as_slice()],
                |row| row.get(0),
            )
            .optional()
    }

    fn wait_for_delivery_state(world: &World, operation: u8, expected: i64) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = delivery_state(world, operation);
            if matches!(observed, Ok(Some(state)) if state == expected) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("expected durable delivery state {expected}, observed {observed:?}"),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    async fn http(gateway: &Gateway, request: Request<Body>) -> TestResult<StatusCode> {
        let app = crate::router(AppState {
            gateway: gateway.clone(),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        let response = app.oneshot(request).await?;
        Ok(response.status())
    }

    async fn health(gateway: &Gateway) -> TestResult<StatusCode> {
        let request = Request::builder().uri("/health").body(Body::empty())?;
        let status = http(gateway, request).await?;
        Ok(status)
    }

    async fn read_status(gateway: &Gateway, timeline: TimelineId) -> TestResult<StatusCode> {
        let request = Request::builder()
            .uri(format!("/v1/timelines/{timeline}/events"))
            .body(Body::empty())?;
        let status = http(gateway, request).await?;
        Ok(status)
    }

    async fn append_status(gateway: &Gateway, timeline: TimelineId) -> TestResult<StatusCode> {
        let body = serde_json::json!({
            "entity_id": pos_core::EntityId::new().to_string(),
            "dimension": "trust",
            "value": 0.4,
        });
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/timelines/{timeline}/signals"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let status = http(gateway, request).await?;
        Ok(status)
    }

    async fn inventory_generation(
        gateway: &Gateway,
        timeline: TimelineId,
    ) -> TestResult<Option<ErasureReferenceV1>> {
        let timeline = timeline.to_string();
        let page = gateway
            .read_events_page_at_generation(&timeline, 0, 1, None)
            .await?;
        Ok(page.inventory_generation)
    }

    // -----------------------------------------------------------------
    // Test-only erasure authority (equivalent to the Gateway integration
    // test `HealthAuthority`), injected only through the startup seam.
    // -----------------------------------------------------------------

    const fn reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    fn persistence_request() -> Result<ErasureRequestV1, ErasureErrorV1> {
        ErasureRequestV1::new(ErasureRequestInputV1 {
            request: reference(1),
            subject: reference(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors: vec![reference(3)],
            requester: reference(4),
            authorization: reference(5),
            policy: reference(6),
            request_position: 9,
            horizon_position: 20,
            provenance: reference(7),
        })
    }

    const fn persistence_target() -> ErasureRequiredTargetV1 {
        ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: reference(10),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: reference(11),
            replica_set: reference(12),
            replica_id: reference(13),
        }
    }

    fn obligation(
        request: ErasureReferenceV1,
        target: ErasureRequiredTargetV1,
    ) -> Result<ErasureObligationV1, ErasureErrorV1> {
        ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target,
            owner: target.replica_id,
            command_identity: pos_core::destruction_command_reference(request, target),
        })
    }

    const fn freeze_transition() -> ErasureStateTransitionV1 {
        ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: pos_core::ErasureReplayClaimV1::Exact,
            provenance: reference(11),
        }
    }

    fn freeze_evidence(
        request: ErasureReferenceV1,
        scope_commitment: ErasureReferenceV1,
        (obligation_set, targets, obligations): (
            &ErasureObligationSetV1,
            &[ErasureRequiredTargetV1],
            &[ErasureObligationV1],
        ),
        (freeze_position, evidence): (u64, &[u8]),
    ) -> Result<
        (
            ErasureFreezeAdmissionEvidenceV1,
            ErasureFreezeAuthorizationEvidenceV1,
        ),
        ErasureErrorV1,
    > {
        let owners = obligations
            .iter()
            .map(|obligation| {
                (
                    (obligation.category(), obligation.target()),
                    obligation.owner(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut applicability_matrix = Vec::new();
        for category in ErasureInventoryCategoryV1::CANONICAL {
            for (target_index, target) in targets.iter().enumerate() {
                let owner = owners.get(&(category, *target)).copied();
                applicability_matrix.push(ErasureFreezeApplicabilityRowV1::new(
                    category,
                    u64::try_from(target_index).map_err(|_| ErasureErrorV1::ScopeInvalid)?,
                    if owner.is_some() {
                        ErasureApplicabilityDecisionV1::Applicable
                    } else {
                        ErasureApplicabilityDecisionV1::Inapplicable
                    },
                    owner,
                )?);
            }
        }
        let admission_input = ErasureFreezeAdmissionEvidenceInputV1 {
            request,
            scope_commitment,
            obligation_set: obligation_set.reference(),
            applicability_matrix,
            freeze_position,
            policy: obligation_set.policy(),
            trust: obligation_set.trust(),
            authorization_provenance: reference(0),
        };
        let provisional = ErasureFreezeAdmissionEvidenceV1::new(admission_input.clone())?;
        let authorization =
            ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
                admission_body_digest: provisional.authorization_body_digest()?,
                policy: obligation_set.policy(),
                trust: obligation_set.trust(),
                evidence: evidence.to_vec(),
            })?;
        let admission =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                authorization_provenance: authorization.reference(),
                ..admission_input
            })?;
        Ok((admission, authorization))
    }

    /// Classifies every tracked Timeline as unaffected until the request's
    /// access freeze commits `scope`; afterwards `scope` is its included
    /// scope. A candidate child is tracked when it is first observed.
    #[derive(Default)]
    struct ForkTestAuthority {
        timelines: Mutex<Vec<TimelineId>>,
        scope: Mutex<Vec<TimelineId>>,
        frozen: AtomicBool,
        deny_topology: AtomicBool,
    }

    impl ForkTestAuthority {
        fn track(&self, timeline: TimelineId) {
            let mut timelines = self
                .timelines
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !timelines.contains(&timeline) {
                timelines.push(timeline);
            }
        }

        fn scope(&self, timeline: TimelineId) {
            self.track(timeline);
            self.scope
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(timeline);
        }

        fn observation(
            &self,
            manifest: ErasureReferenceV1,
        ) -> Result<ErasureVerifiedTopologyObservationV1, ErasureErrorV1> {
            if self.deny_topology.load(Ordering::Acquire) {
                return Err(ErasureErrorV1::TrustSnapshotInvalid);
            }
            let scope = if self.frozen.load(Ordering::Acquire) {
                self.scope
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            } else {
                Vec::new()
            };
            let (bindings, unaffected): (Vec<_>, Vec<_>) = self
                .timelines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .copied()
                .partition(|timeline| scope.contains(timeline));
            Ok(ErasureVerifiedTopologyObservationV1::new(
                manifest,
                bindings
                    .into_iter()
                    .map(|timeline| (timeline, reference(9)))
                    .collect(),
                unaffected,
            ))
        }
    }

    impl ErasureFreezeAuthorizationVerifierV1 for ForkTestAuthority {
        fn validate_freeze_authorization(
            &self,
            admission: &ErasureFreezeAdmissionEvidenceV1,
            authorization: &ErasureFreezeAuthorizationEvidenceV1,
        ) -> Result<(), ErasureErrorV1> {
            authorization.verify_admission_body_binding(admission)
        }
    }

    impl ErasureRecoveryAuthorizationVerifierV1 for ForkTestAuthority {
        fn validate_scope_extension(
            &self,
            _extension: &ErasureScopeExtensionV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn validate_administrative_resolution(
            &self,
            _resolution: &ErasureAdministrativeResolutionV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }
    }

    impl ErasureCoordinatorAuthorityV1 for ForkTestAuthority {
        fn verified_topology_observation(
            &self,
            _request: ErasureReferenceV1,
            manifest_digest: ErasureReferenceV1,
        ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
            self.observation(manifest_digest).map(Some)
        }

        fn verified_topology_observation_for_candidate(
            &self,
            _request: ErasureReferenceV1,
            manifest_digest: ErasureReferenceV1,
            candidate: &TimelineMeta,
        ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
            self.track(candidate.id);
            self.observation(manifest_digest).map(Some)
        }

        fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn admit_authorization(
            &self,
            _request: ErasureReferenceV1,
            _provenance: ErasureReferenceV1,
            decision: ErasureAuthorizationDecisionV1,
        ) -> Result<(), ErasureErrorV1> {
            (decision == ErasureAuthorizationDecisionV1::Authorized)
                .then_some(())
                .ok_or(ErasureErrorV1::Unauthorized)
        }

        fn admit_corrected_submission(
            &self,
            _request: &ErasureRequestV1,
            _correction: &ErasureCorrectionProvenanceV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn admit_atomic_freeze(
            &self,
            request: ErasureReferenceV1,
            requested: &ErasureStateTransitionV1,
        ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
            let target = persistence_target();
            let targets = vec![target];
            let obligations = vec![obligation(request, target)?];
            let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
                request,
                obligations: obligations
                    .iter()
                    .map(ErasureObligationV1::reference)
                    .collect(),
                policy: reference(6),
                trust: reference(8),
            })?;
            let mut scope_timeline_ids = self
                .scope
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            scope_timeline_ids.sort_unstable();
            let scope = ErasureScopeCommitmentInputV1 {
                request,
                scope_members: vec![reference(9)],
                scope_timeline_ids,
                target_closure: target_closure_digest(&targets),
                lineage_rule: Some(reference(100)),
            };
            let scope_commitment = ErasureScopeCommitmentV1::new(scope.clone())?;
            let freeze_position = requested
                .freeze_position
                .ok_or(ErasureErrorV1::ScopeInvalid)?;
            let evidence = requested.provenance.digest();
            let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence(
                request,
                scope_commitment.reference(),
                (&obligation_set, &targets, &obligations),
                (freeze_position, &evidence),
            )?;
            let admission =
                ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
                    targets,
                    scope,
                    obligations,
                    obligation_set,
                    freeze_position,
                    freeze_admission_evidence,
                    freeze_authorization_evidence,
                })?;
            self.frozen.store(true, Ordering::Release);
            Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(admission)))
        }

        fn admit_scope_extension(
            &self,
            _extension: &ErasureScopeExtensionV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn admit_fork_scope_extension(
            &self,
            _extension: &ErasureScopeExtensionV1,
            _input: &ErasureForkAdmissionInputV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn resolve_fork_child_scope(
            &self,
            _parent: TimelineId,
            _child: &TimelineMeta,
        ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
            Ok(reference(19))
        }

        fn resolve_fork_scope_extension(
            &self,
            requirement: ErasureForkScopeRequirementV1,
            input: &ErasureForkAdmissionInputV1,
        ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
            ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
                request: requirement.request(),
                scope_commitment: requirement.scope_commitment(),
                fork: input.child_scope,
                child_timeline: input.child.id,
                lineage_rule: requirement.lineage_rule(),
                predecessor_extension: requirement.predecessor_extension(),
                admission_provenance: reference(20),
            })
        }

        fn admit_administrative_resolution(
            &self,
            _resolution: &ErasureAdministrativeResolutionV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn dispatch_destruction(
            &self,
            _request: ErasureReferenceV1,
            _commands: &[ErasureDestructionCommandV1],
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn admit_attempt(
            &self,
            admission: &pos_core::ErasureRetryAdmissionV1,
        ) -> Result<pos_core::ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
            Ok(pos_core::ErasureAttemptQuotaReservationV1::new(
                admission.reference(),
                reference(50),
            ))
        }

        fn admit_acknowledgement(
            &self,
            _acknowledgement: &ErasureAcknowledgementProvenanceV1,
        ) -> Result<(), ErasureErrorV1> {
            Ok(())
        }

        fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
            Ok(())
        }
    }

    fn test_composition(
        authority: &Arc<ForkTestAuthority>,
    ) -> TestResult<ErasureCoordinatorCompositionV1> {
        let plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
        let composition = ErasureCoordinatorCompositionV1::new(plugin, reference(30))?;
        Ok(composition)
    }

    fn open_test_host(
        world: &World,
        composition: &ErasureCoordinatorCompositionV1,
    ) -> TestResult<ErasureExecutionHostV1> {
        let host = ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite {
                path: world.path()?.to_owned(),
            },
            composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        Ok(host)
    }

    /// Submit and authorize the one erasure request of the test authority
    /// through a separate, already dropped host session.
    fn authorize_request(
        world: &World,
        composition: &ErasureCoordinatorCompositionV1,
    ) -> TestResult {
        let mut host = open_test_host(world, composition)?;
        let request = persistence_request()?;
        let mut commands = host.command_sender()?;
        commands.submit_erasure_request(request.clone(), request.provenance())?;
        commands.authorize_erasure_request(request.reference(), reference(32))?;
        Ok(())
    }

    /// Commit the access freeze of the authorized request.
    fn freeze_request(world: &World, composition: &ErasureCoordinatorCompositionV1) -> TestResult {
        let mut host = open_test_host(world, composition)?;
        let mut commands = host.command_sender()?;
        let frozen =
            commands.freeze_access(persistence_request()?.reference(), &freeze_transition())?;
        assert_eq!(frozen.lifecycle(), ErasureLifecycleV1::AccessFrozen);
        Ok(())
    }

    /// A world whose `parents[0]` is in the scope of one access-frozen
    /// request and whose other parents are proven unaffected.
    fn frozen_world(
        parents: &[&str],
    ) -> TestResult<(
        World,
        Vec<TimelineId>,
        Arc<ForkTestAuthority>,
        ErasureCoordinatorCompositionV1,
    )> {
        let (world, parents) = provisioned_world(parents)?;
        let authority = Arc::new(ForkTestAuthority::default());
        for parent in &parents {
            authority.track(*parent);
        }
        authority.scope(parents[0]);
        let composition = test_composition(&authority)?;
        authorize_request(&world, &composition)?;
        freeze_request(&world, &composition)?;
        Ok((world, parents, authority, composition))
    }

    // -----------------------------------------------------------------
    // ADR-109 revision 9 acceptance vectors A1 to A12 (Gateway part).
    //
    // A3 ("parent affected by an active, not yet frozen request") is not
    // constructible through durable state: an erasure request's included
    // scope is committed only by its access freeze, and pos-core
    // `validate_committed_scope_timeline_bindings` rejects included bindings
    // before it, so every included classification a host recovers is
    // frozen. The verdict for an affected-but-unfrozen parent is covered
    // only at gate/context level: pos-core
    // `admitted_fork_context_binds_one_fcc1_and_its_fenced_parent_verdict`
    // (ADR-106 r3 T2; see also the #474 note in pos-runtime
    // `erasure_coordinator_host_public::assert_host_admitted_fork_contract`).
    // A11 is covered by the pos-store and pos-runtime delivery tests, and
    // A12 by the unchanged ADR-109 golden tests in `local_fork_listener`.
    // -----------------------------------------------------------------

    /// A1: a proven-unaffected parent on a Ready host (closed composition,
    /// verified-empty inventory) is admitted with code 0; the successor is
    /// published before the response, so the child is readable over HTTP at
    /// once, and the journal ends Delivered. An exact retry returns the same
    /// receipt through FRP1.
    #[tokio::test]
    async fn listener_creates_one_fork_and_retries_its_result_for_the_same_principal() -> TestResult
    {
        let (world, parents) = provisioned_world(&["listener Fork parent"])?;
        let (gateway, listener) = start(&world, &ErasureCoordinatorCompositionV1::closed())?;
        assert_eq!(
            &request(&world.socket, &bind_payload(5), false)?[..10],
            &BIND_OK
        );
        let payload = fork_payload(6, parents[0])?;
        let first = fork_result(&request(&world.socket, &payload, false)?)?;
        assert_eq!(read_status(&gateway, first.0).await?, StatusCode::OK);
        wait_for_delivery_state(&world, 6, 3)?;
        let retry = fork_result(&request(&world.socket, &payload, false)?)?;
        assert_eq!(first, retry);
        assert_ne!(first.1, [0; 32]);
        assert_eq!(graph_rows(&world)?[..4], [2, 1, 2, 1]);
        assert_eq!(health(&gateway).await?, StatusCode::OK);
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    /// A2: a parent in a frozen scope is code 5 with zero child, FAR1,
    /// operation-row or wall-fence change; Pending is deleted atomically, the
    /// installed inventory generation is unchanged, and the host stays Ready.
    #[tokio::test]
    async fn listener_rejects_a_frozen_parent_without_writes_or_generation_change() -> TestResult {
        let (world, parents, _authority, composition) =
            frozen_world(&["a2 frozen parent", "a2 open parent"])?;
        let (gateway, listener) = start(&world, &composition)?;
        assert_eq!(
            &request(&world.socket, &bind_payload(9), false)?[..10],
            &BIND_OK
        );
        let generation = inventory_generation(&gateway, parents[1]).await?;
        assert!(generation.is_some());
        let before = graph_rows(&world)?;
        let payload = fork_payload(10, parents[0])?;
        assert_eq!(request(&world.socket, &payload, false)?, rejected(5));
        assert_eq!(graph_rows(&world)?, before);
        assert_eq!(delivery_state(&world, 10)?, None);
        assert_eq!(
            inventory_generation(&gateway, parents[1]).await?,
            generation
        );
        assert_eq!(gateway.erasure_status().await?, ErasureHostStatusV1::Ready);
        assert_eq!(health(&gateway).await?, StatusCode::OK);
        // The deleted Pending tuple answers the retry again, never Busy.
        assert_eq!(request(&world.socket, &payload, false)?, rejected(5));
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    fn assert_single_host_connection_structure() {
        // Everything before the unit-test module, including test-only
        // production helpers such as `map_journal_for_test`, is scanned.
        let production =
            |source: &'static str| source.split("\nmod tests {").next().unwrap_or(source);
        let coordinator = production(include_str!("local_fork_coordinator.rs"));
        let listener = production(include_str!("local_fork_listener.rs"));
        let service = production(include_str!("local_fork_service.rs"));
        for source in [coordinator, listener] {
            assert!(!source.contains("SqliteStore"));
            assert!(!source.contains("MemoryStore"));
        }
        // Only one-shot provisioning (ADR-107) opens a store on the path.
        assert_eq!(service.matches("SqliteStore::open").count(), 1);
    }

    /// Protected HTTP read and append on `timeline`, and `/health`, all
    /// available (never 503).
    async fn assert_http(gateway: &Gateway, timeline: TimelineId) -> TestResult {
        assert_eq!(read_status(gateway, timeline).await?, StatusCode::OK);
        assert_eq!(append_status(gateway, timeline).await?, StatusCode::CREATED);
        assert_eq!(health(gateway).await?, StatusCode::OK);
        Ok(())
    }

    /// A4 (`data_version` regression): a Bind, a committed Fork, a code-5
    /// rejection, and every journal transition leave HTTP protected reads
    /// and appends on a pre-existing Timeline available, because the serve
    /// path opens exactly one read-write adapter per database.
    #[tokio::test]
    async fn listener_writes_leave_http_protected_operations_available() -> TestResult {
        assert_single_host_connection_structure();
        let (world, parents, _authority, composition) = frozen_world(&[
            "a4 frozen parent",
            "a4 unaffected parent",
            "a4 http timeline",
        ])?;
        let (frozen, unaffected, timeline) = (parents[0], parents[1], parents[2]);
        let (gateway, listener) = start(&world, &composition)?;
        assert_http(&gateway, timeline).await?;
        assert_eq!(
            &request(&world.socket, &bind_payload(11), false)?[..10],
            &BIND_OK
        );
        assert_http(&gateway, timeline).await?;
        fork_result(&request(
            &world.socket,
            &fork_payload(12, unaffected)?,
            false,
        )?)?;
        wait_for_delivery_state(&world, 12, 3)?;
        assert_http(&gateway, timeline).await?;
        assert_eq!(
            request(&world.socket, &fork_payload(13, frozen)?, false)?,
            rejected(5)
        );
        assert_http(&gateway, timeline).await?;
        // Pending -> Uncertain, a failed response write, then Delivered.
        let uncertain = fork_payload(14, unaffected)?;
        disconnect_after_complete_request(&world.socket, &uncertain)?;
        wait_for_delivery_state(&world, 14, 2)?;
        assert_http(&gateway, timeline).await?;
        fork_result(&request(&world.socket, &uncertain, false)?)?;
        wait_for_delivery_state(&world, 14, 3)?;
        assert_http(&gateway, timeline).await?;
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    /// A5: commit, then freeze the parent, then an exact FAL1 retry returns
    /// the original receipt through FRP1 with zero writes; a new Fork of the
    /// now-frozen parent is contained.
    #[tokio::test]
    async fn exact_retry_returns_the_original_receipt_after_the_parent_is_frozen() -> TestResult {
        let (world, parents) = provisioned_world(&["a5 parent", "a5 other"])?;
        let authority = Arc::new(ForkTestAuthority::default());
        authority.scope(parents[0]);
        authority.track(parents[1]);
        let composition = test_composition(&authority)?;
        authorize_request(&world, &composition)?;
        let (gateway, listener) = start(&world, &composition)?;
        assert_eq!(
            &request(&world.socket, &bind_payload(15), false)?[..10],
            &BIND_OK
        );
        let payload = fork_payload(16, parents[0])?;
        let original = fork_result(&request(&world.socket, &payload, false)?)?;
        wait_for_delivery_state(&world, 16, 3)?;
        stop(&world, gateway, listener).await?;

        freeze_request(&world, &composition)?;
        let (gateway, listener) = start(&world, &composition)?;
        let before = graph_rows(&world)?;
        assert_eq!(
            fork_result(&request(&world.socket, &payload, false)?)?,
            original
        );
        assert_eq!(graph_rows(&world)?, before);
        assert_eq!(
            request(&world.socket, &fork_payload(17, parents[0])?, false)?,
            rejected(5)
        );
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    /// Start a listener over a Ready host with one authorized request, then
    /// fail the successor publication of a committed Fork: the response is
    /// code 6, the host is Poisoned, and `/health` is 503.
    async fn poisoned_listener() -> TestResult<(
        World,
        Vec<TimelineId>,
        Arc<ForkTestAuthority>,
        ErasureCoordinatorCompositionV1,
        (Gateway, LocalForkAdmissionListenerV1),
    )> {
        let (world, parents) = provisioned_world(&["poisoned parent", "poisoned other"])?;
        let authority = Arc::new(ForkTestAuthority::default());
        for parent in &parents {
            authority.track(*parent);
        }
        let composition = test_composition(&authority)?;
        authorize_request(&world, &composition)?;
        let (gateway, listener) = start(&world, &composition)?;
        assert_eq!(
            &request(&world.socket, &bind_payload(21), false)?[..10],
            &BIND_OK
        );
        authority.deny_topology.store(true, Ordering::Release);
        assert_eq!(
            request(&world.socket, &fork_payload(22, parents[0])?, false)?,
            rejected(6)
        );
        assert_eq!(delivery_state(&world, 22)?, Some(2));
        assert_eq!(
            gateway.erasure_status().await?,
            ErasureHostStatusV1::Poisoned
        );
        assert_eq!(health(&gateway).await?, StatusCode::SERVICE_UNAVAILABLE);
        Ok((world, parents, authority, composition, (gateway, listener)))
    }

    /// A6: a post-commit successor publication failure is code 6 and poisons
    /// the host; after a restart the exact retry returns the original
    /// receipt with code 0 and the host is Ready again.
    #[tokio::test]
    async fn publication_failure_is_uncertain_and_recovers_after_restart() -> TestResult {
        let (world, parents, authority, composition, (gateway, listener)) =
            poisoned_listener().await?;
        stop(&world, gateway, listener).await?;
        authority.deny_topology.store(false, Ordering::Release);
        let (gateway, listener) = start(&world, &composition)?;
        let payload = fork_payload(22, parents[0])?;
        let recovered = fork_result(&request(&world.socket, &payload, false)?)?;
        assert_eq!(read_status(&gateway, recovered.0).await?, StatusCode::OK);
        assert_eq!(
            fork_result(&request(&world.socket, &payload, false)?)?,
            recovered
        );
        assert_eq!(health(&gateway).await?, StatusCode::OK);
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    /// A10: with no Ready host a new FCC1 fails closed with code 5 and its
    /// Pending tuple deleted, a POC1 still commits with code 0, and an exact
    /// retry of a committed Fork returns code 0 through fence-free FRP1.
    #[tokio::test]
    async fn production_listener_fails_new_forks_closed_without_an_erasure_gate() -> TestResult {
        let (world, parents, _authority, _composition, (gateway, listener)) =
            poisoned_listener().await?;
        let payload = fork_payload(23, parents[1])?;
        let before = graph_rows(&world)?;
        assert_eq!(request(&world.socket, &payload, false)?, rejected(5));
        assert_eq!(graph_rows(&world)?, before);
        assert_eq!(delivery_state(&world, 23)?, None);
        assert_eq!(request(&world.socket, &payload, false)?, rejected(5));
        assert_eq!(
            &request(&world.socket, &bind_payload(24), false)?[..10],
            &BIND_OK
        );
        let recovered = fork_result(&request(
            &world.socket,
            &fork_payload(22, parents[0])?,
            false,
        )?)?;
        assert_ne!(recovered.1, [0; 32]);
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    /// Forwards to the executor's journal, except that the execute command
    /// meets a worker blocked by a test gate and a saturated queue; the gate
    /// opens only after the bounded admission wait has refused it.
    struct SaturatedExecuteJournal {
        inner: Box<dyn LocalForkDeliveryJournalV1>,
        executor: StoreExecutor,
    }

    impl LocalForkDeliveryJournalV1 for SaturatedExecuteJournal {
        fn claim(
            &mut self,
            tuple: pos_store::ForkDeliveryTupleV1,
        ) -> ForkAdmissionSubmissionV1<pos_store::ForkDeliveryClaimOutcomeV1> {
            self.inner.claim(tuple)
        }

        fn cancel(
            &mut self,
            claim: pos_store::ForkDeliveryClaimV1,
        ) -> ForkAdmissionSubmissionV1<()> {
            self.inner.cancel(claim)
        }

        fn execute(
            &mut self,
            claim: pos_store::ForkDeliveryClaimV1,
            command: &pos_core::ForkAdmissionHostCommandV1,
        ) -> ForkAdmissionSubmissionV1<pos_store::ForkDeliveryExecutionV1> {
            // A7 saturates only a Fork (FCC1) execute; a POC1 Bind passes through.
            if command.validated_command_facts().fork_target().is_none() {
                return self.inner.execute(claim, command);
            }
            let Ok(release) = self.executor.block_worker_for_test() else {
                return Err(ForkAdmissionSubmissionErrorV1::Unavailable);
            };
            assert!(self.executor.saturate_for_test() > 0);
            let refused = self.inner.execute(claim, command);
            drop(release);
            refused
        }

        fn recover(
            &mut self,
            tuple: pos_store::ForkDeliveryTupleV1,
            proof: &pos_core::ForkAdmissionRecoveryProofV1,
            principal: pos_core::Hash,
        ) -> ForkAdmissionSubmissionV1<pos_core::ForkAdmissionOperationResultV1> {
            self.inner.recover(tuple, proof, principal)
        }

        fn mark(
            &mut self,
            claim: pos_store::ForkDeliveryClaimV1,
            mark: crate::executor::ForkDeliveryMarkV1,
        ) -> ForkAdmissionSubmissionV1<()> {
            self.inner.mark(claim, mark)
        }

        fn register(
            &mut self,
            child: TimelineId,
            admission_digest: pos_core::Hash,
        ) -> ForkAdmissionSubmissionV1<crate::executor::ForkClassifierRegistrationV1> {
            self.inner.register(child, admission_digest)
        }
    }

    /// A7: an executor saturated before the claim, or between the claim and
    /// the execute (test gate on the worker), answers code 6 after the
    /// bounded admission wait; no journal row and no FAC1 remain.
    #[tokio::test]
    async fn saturated_executor_answers_busy_without_journal_rows() -> TestResult {
        let (world, parents) = provisioned_world(&["a7 parent"])?;
        let (gateway, coordinator) = open_with_credentials(
            world.path()?,
            current_peer_managed()?,
            None,
            &ErasureCoordinatorCompositionV1::closed(),
        )?;
        let executor = gateway.store.clone();
        let coordinator = coordinator.map_journal_for_test(|inner| {
            Box::new(SaturatedExecuteJournal {
                inner,
                executor: executor.clone(),
            })
        });
        let listener = start_listener(coordinator, &world.socket)?;
        assert_eq!(
            &request(&world.socket, &bind_payload(31), false)?[..10],
            &BIND_OK
        );
        let before = graph_rows(&world)?;
        assert_eq!(
            request(&world.socket, &fork_payload(32, parents[0])?, false)?,
            rejected(6)
        );
        assert_eq!(delivery_state(&world, 32)?, None);

        let release = executor
            .block_worker_for_test()
            .map_err(|error| format!("{error:?}"))?;
        assert!(executor.saturate_for_test() > 0);
        drop(executor);
        let saturated = request(&world.socket, &fork_payload(33, parents[0])?, false)?;
        drop(release);
        assert_eq!(saturated, rejected(6));
        assert_eq!(delivery_state(&world, 33)?, None);
        assert_eq!(graph_rows(&world)?, before);
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    /// A8: a request in flight when shutdown starts completes with its real
    /// code before the executor drains; the socket is unlinked and executor
    /// shutdown succeeds. A submission to a closed executor is code 5 with
    /// zero writes.
    #[tokio::test]
    async fn shutdown_completes_in_flight_requests_and_closed_submissions_are_code_five(
    ) -> TestResult {
        let (world, _) = provisioned_world(&[])?;
        let (gateway, listener) = start(&world, &ErasureCoordinatorCompositionV1::closed())?;
        let release = gateway
            .store
            .block_worker_for_test()
            .map_err(|error| format!("{error:?}"))?;
        let socket = world.socket.clone();
        let client = thread::spawn(move || request(&socket, &bind_payload(41), false));
        let deadline = Instant::now() + Duration::from_secs(5);
        while gateway.store.admitted_for_test() < 2 {
            assert!(
                Instant::now() < deadline,
                "the in-flight claim was not queued"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let stopping = tokio::spawn(listener.stop());
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(release);
        let answered = client
            .join()
            .map_err(|_| io::Error::other("in-flight client panicked"))??;
        assert_eq!(&answered[..10], &BIND_OK);
        stopping.await??;
        assert!(!world.socket.exists());
        assert_eq!(delivery_state(&world, 41)?, Some(3));
        gateway.shutdown().await?;

        let (gateway, listener) = start(&world, &ErasureCoordinatorCompositionV1::closed())?;
        gateway.shutdown().await?;
        let before = graph_rows(&world)?;
        assert_eq!(
            request(&world.socket, &bind_payload(42), false)?,
            rejected(5)
        );
        assert_eq!(graph_rows(&world)?, before);
        assert_eq!(delivery_state(&world, 42)?, None);
        listener.stop().await?;
        assert!(!world.socket.exists());
        Ok(())
    }

    fn authority_rows(world: &World) -> rusqlite::Result<Vec<Vec<u8>>> {
        let connection = rusqlite::Connection::open(&world.database)?;
        let mut statement = connection.prepare("SELECT * FROM fork_admission_authority")?;
        let columns = statement.column_count();
        let rows = statement.query_map([], |row| {
            (0..columns)
                .map(|column| {
                    row.get_ref(column)
                        .map(|value| format!("{value:?}").into_bytes())
                })
                .collect::<rusqlite::Result<Vec<_>>>()
                .map(|values| values.concat())
        })?;
        rows.collect()
    }

    /// A9: a host that cannot open (a non-empty inventory with the closed
    /// composition, or an unopenable file), an absent FAH1, and a failed
    /// journal reconciliation all stop startup before any bind, with no FAO1,
    /// journal, or topology mutation from the failed step onward.
    #[tokio::test]
    async fn startup_fails_closed_before_any_bind() -> TestResult {
        let closed = ErasureCoordinatorCompositionV1::closed();
        let (world, parents) = provisioned_world(&["a9 parent"])?;
        let authority = Arc::new(ForkTestAuthority::default());
        authority.track(parents[0]);
        authorize_request(&world, &test_composition(&authority)?)?;
        let authority_before = authority_rows(&world)?;
        let graph_before = graph_rows(&world)?;
        assert!(
            open_with_credentials(world.path()?, current_peer_managed()?, None, &closed).is_err()
        );
        assert_eq!(authority_rows(&world)?, authority_before);
        assert_eq!(graph_rows(&world)?, graph_before);

        let unopenable = world
            .runtime
            .path()
            .to_str()
            .ok_or("runtime path is not UTF-8")?;
        assert!(open_with_credentials(unopenable, current_peer_managed()?, None, &closed).is_err());

        let unprovisioned = unprovisioned_world()?;
        assert!(open_with_credentials(
            unprovisioned.path()?,
            current_peer_managed()?,
            None,
            &closed
        )
        .is_err());
        assert_eq!(
            row_count(&unprovisioned, "SELECT COUNT(*) FROM timelines")?,
            0
        );
        assert_eq!(
            row_count(&unprovisioned, "SELECT COUNT(*) FROM fork_delivery_journal")?,
            0
        );

        let (corrupt, _) = provisioned_world(&[])?;
        let connection = rusqlite::Connection::open(&corrupt.database)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(
            "INSERT INTO fork_delivery_journal (host_request_id, kind, operation_id, state, owner_fence) VALUES (?1, 1, ?2, 0, 1)",
            params![[51_u8; 32].as_slice(), [52_u8; 32].as_slice()],
        )?;
        drop(connection);
        assert!(
            open_with_credentials(corrupt.path()?, current_peer_managed()?, None, &closed).is_err()
        );
        assert_eq!(delivery_state(&corrupt, 52)?, Some(0));
        for failed in [&world, &unprovisioned, &corrupt] {
            assert!(!failed.socket.exists());
        }
        Ok(())
    }

    fn row_count(world: &World, query: &str) -> rusqlite::Result<i64> {
        rusqlite::Connection::open(&world.database)?.query_row(query, [], |row| row.get(0))
    }

    // -----------------------------------------------------------------
    // Credential, lifecycle, and framing boundaries.
    // -----------------------------------------------------------------

    #[test]
    fn provision_rejects_missing_protected_credentials() -> TestResult {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let credentials = directory.path().join("missing-credentials");
        assert!(provision_local_fork_admission_authority(
            &database.display().to_string(),
            &credentials,
        )
        .is_err());
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn provision_rejects_missing_or_swapped_credential_files_before_database_open() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("gateway.db");

        let service_uid = rustix::process::geteuid().as_raw();
        let (auth_credential, host_credential) =
            test_credential_bytes_for_service(service_uid, [7; 32], [8; 32])?;
        protected_credential_file(
            directory.path(),
            "pigloros.fork-admission-auth",
            &host_credential,
        )?;
        assert!(provision_local_fork_admission_authority(
            &database.display().to_string(),
            directory.path(),
        )
        .is_err());
        assert!(!database.exists());

        protected_credential_file(
            directory.path(),
            "pigloros.fork-admission-host-signer",
            &auth_credential,
        )?;
        assert!(provision_local_fork_admission_authority(
            &database.display().to_string(),
            directory.path(),
        )
        .is_err());
        assert!(!database.exists());
        Ok(())
    }

    fn paths<'a>(
        world: &'a World,
        credentials: &'a Path,
    ) -> io::Result<LocalForkAdmissionPathsV1<'a>> {
        Ok(LocalForkAdmissionPathsV1 {
            sqlite_path: world.path()?,
            socket_path: &world.socket,
            credential_directory: credentials,
        })
    }

    async fn serve_for_test(
        paths: LocalForkAdmissionPathsV1<'_>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ServeError> {
        let addr = "127.0.0.1:0".parse()?;
        let composition = ErasureCoordinatorCompositionV1::closed();
        let ledger = (LedgerView::default(), LedgerWriteMode::Disabled);
        serve_local_fork_admission(addr, paths, None, &composition, shutdown, ledger).await?;
        Ok(())
    }

    /// Step 1 and step 3: missing credentials fail before the database is
    /// opened, and an uninitialized or unequal FAH1 fails before any bind.
    #[tokio::test]
    async fn serve_rejects_missing_credentials_and_uninitialized_or_mismatched_authority(
    ) -> TestResult {
        let world = unprovisioned_world()?;
        let missing = world.runtime.path().join("missing-credentials");
        assert!(serve_for_test(paths(&world, &missing)?, async {})
            .await
            .is_err());
        assert!(!world.database.exists());
        assert!(!world.socket.exists());

        let credentials = protected_credential_directory(world.runtime.path())?;
        let profile = profile_bytes(&[7])?;
        managed_credentials(&credentials, ([7; 32], [8; 32]), &profile)?;
        assert!(serve_for_test(paths(&world, &credentials)?, async {})
            .await
            .is_err());
        assert!(!world.socket.exists());

        // FCP1 is not a provisioning input: the provisioner accepts only the
        // two key credentials (ADR-107 r6).
        assert!(provision_local_fork_admission_authority(world.path()?, &credentials).is_err());
        fs::remove_file(credentials.join(CLASSIFIER_PROFILE_CREDENTIAL_NAME))?;
        provision_local_fork_admission_authority(world.path()?, &credentials)?;
        install_profile(&credentials, &profile)?;
        for (adapter, host) in [([9; 32], [8; 32]), ([7; 32], [9; 32])] {
            protected_credentials(&credentials, adapter, host)?;
            assert!(serve_for_test(paths(&world, &credentials)?, async {})
                .await
                .is_err());
            assert!(!world.socket.exists());
        }
        Ok(())
    }

    /// The managed deployment opens one provisioned database for the HTTP
    /// Gateway and the listener, binds the socket last, and unlinks it on
    /// shutdown.
    #[tokio::test]
    async fn managed_fork_listener_and_gateway_open_one_provisioned_database() -> TestResult {
        let world = unprovisioned_world()?;
        let credentials = protected_credential_directory(world.runtime.path())?;
        protected_credentials(&credentials, [7; 32], [8; 32])?;
        provision_local_fork_admission_authority(world.path()?, &credentials)?;
        install_profile(&credentials, &profile_bytes(&[7])?)?;
        let socket = world.socket.clone();
        serve_for_test(paths(&world, &credentials)?, async move {
            assert!(socket.exists());
        })
        .await?;
        assert!(!world.socket.exists());
        Ok(())
    }

    /// Step 6: a TCP or Unix bind failure stops the executor and leaves no
    /// socket.
    #[tokio::test]
    async fn bind_failures_stop_what_was_started() -> TestResult {
        let (world, _) = provisioned_world(&[])?;
        let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
        let started = open_with_credentials(
            world.path()?,
            current_peer_managed()?,
            None,
            &ErasureCoordinatorCompositionV1::closed(),
        )?;
        let gateway = started.0.clone();
        let ledger = (LedgerView::default(), LedgerWriteMode::Disabled);
        assert!(serve_started(
            occupied.local_addr()?,
            started,
            &world.socket,
            async {},
            ledger
        )
        .await
        .is_err());
        assert!(!gateway.is_ready());
        drop(gateway);
        assert!(!world.socket.exists());

        fs::set_permissions(world.runtime.path(), fs::Permissions::from_mode(0o777))?;
        let started = open_with_credentials(
            world.path()?,
            current_peer_managed()?,
            None,
            &ErasureCoordinatorCompositionV1::closed(),
        )?;
        let gateway = started.0.clone();
        let ledger = (LedgerView::default(), LedgerWriteMode::Disabled);
        assert!(serve_started(
            "127.0.0.1:0".parse()?,
            started,
            &world.socket,
            async {},
            ledger
        )
        .await
        .is_err());
        assert!(!gateway.is_ready());
        drop(gateway);
        assert!(!world.socket.exists());
        Ok(())
    }

    #[tokio::test]
    async fn owntracks_deployments_share_the_one_gateway_host() -> TestResult {
        let (world, _) = provisioned_world(&[])?;
        let owner_key_path = world.runtime.path().join("owner.key");
        crate::owntracks::create_or_load_owner_key(&owner_key_path)?;
        let owner_key = OwnTracksOwnerKey::load(&owner_key_path)?;
        let (gateway, coordinator) = open_with_credentials(
            world.path()?,
            current_peer_managed()?,
            Some(&owner_key),
            &ErasureCoordinatorCompositionV1::closed(),
        )?;
        let listener = start_listener(coordinator, &world.socket)?;
        assert_eq!(
            &request(&world.socket, &bind_payload(61), false)?[..10],
            &BIND_OK
        );
        assert_eq!(health(&gateway).await?, StatusCode::OK);
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    #[tokio::test]
    async fn listener_retains_post_commit_disconnect_as_uncertain_for_same_principal_retry(
    ) -> TestResult {
        let (world, _) = provisioned_world(&[])?;
        let (gateway, listener) = start(&world, &ErasureCoordinatorCompositionV1::closed())?;
        let payload = bind_payload(1);
        disconnect_after_complete_request(&world.socket, &payload)?;
        wait_for_delivery_state(&world, 1, 2)?;
        assert_eq!(&request(&world.socket, &payload, false)?[..10], &BIND_OK);
        wait_for_delivery_state(&world, 1, 3)?;
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    #[tokio::test]
    async fn listener_accepts_fragmented_frames_and_refuses_unclosed_or_trailing_input(
    ) -> TestResult {
        let (world, _) = provisioned_world(&[])?;
        let (gateway, listener) = start(&world, &ErasureCoordinatorCompositionV1::closed())?;
        assert_eq!(
            &request(&world.socket, &bind_payload(2), true)?[..10],
            &BIND_OK
        );
        request_without_half_close(&world.socket, &bind_payload(3))?;
        trailing_byte_request(&world.socket, &bind_payload(4))?;
        // The first Bind already owns this Principal; a later distinct Bind
        // resolves to that binding, and the listener still answers after a
        // bad frame.
        assert_eq!(
            &request(&world.socket, &bind_payload(4), false)?[..10],
            &BIND_OK
        );
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    #[tokio::test]
    async fn listener_rejects_a_fork_before_principal_ownership_is_bound() -> TestResult {
        let (world, parents) = provisioned_world(&["unbound Fork parent"])?;
        let (gateway, listener) = start(&world, &ErasureCoordinatorCompositionV1::closed())?;
        // An unbound Principal is a semantic rejection (#465 InvalidRequest).
        assert_eq!(
            request(&world.socket, &fork_payload(6, parents[0])?, false)?,
            rejected(7)
        );
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    #[tokio::test]
    async fn stopped_listener_without_worker_is_a_noop() -> TestResult {
        let listener = LocalForkAdmissionListenerV1 {
            stopping: Arc::new(AtomicBool::new(false)),
            worker: None,
            socket_path: None,
        };
        listener.stop().await?;
        Ok(())
    }

    /// A worker wedged on a started command cannot hang shutdown: the join is
    /// bounded, the socket pathname is still unlinked, and the stop reports
    /// `TimedOut`.
    #[tokio::test]
    async fn stopped_listener_bounds_the_join_of_a_wedged_worker() -> TestResult {
        let world = unprovisioned_world()?;
        fs::write(&world.socket, [])?;
        let (release, wedged) = std::sync::mpsc::channel::<()>();
        let listener = LocalForkAdmissionListenerV1 {
            stopping: Arc::new(AtomicBool::new(false)),
            worker: Some(thread::spawn(move || {
                let _released = wedged.recv();
            })),
            socket_path: Some(world.socket.clone()),
        };
        let stopped = listener.stop_within(Duration::from_millis(50)).await;
        assert_eq!(
            stopped.err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(!world.socket.exists());
        drop(release);
        Ok(())
    }

    #[tokio::test]
    async fn stopped_listener_reports_a_panicked_worker() {
        let listener = LocalForkAdmissionListenerV1 {
            stopping: Arc::new(AtomicBool::new(false)),
            worker: Some(thread::spawn(|| {
                std::panic::resume_unwind(Box::new("test worker panic"))
            })),
            socket_path: None,
        };
        assert!(listener.stop().await.is_err());
    }

    // -----------------------------------------------------------------
    // ADR-109 revision 12: FCP1 startup and classifier registration.
    // -----------------------------------------------------------------

    fn classifier_rows(world: &World) -> rusqlite::Result<[i64; 2]> {
        Ok([
            row_count(world, "SELECT COUNT(*) FROM fork_classifier_sources")?,
            row_count(world, "SELECT COUNT(*) FROM fork_classifier_registrations")?,
        ])
    }

    fn start_profiled(
        world: &World,
        descriptors: &[u8],
    ) -> TestResult<(Gateway, LocalForkAdmissionListenerV1)> {
        let (gateway, coordinator) = open_with_credentials(
            world.path()?,
            (current_peer_credentials()?, profile_from(descriptors)?),
            None,
            &ErasureCoordinatorCompositionV1::closed(),
        )?;
        let listener = start_listener(coordinator, &world.socket)?;
        Ok((gateway, listener))
    }

    /// The executor registers the FCS1 row that the committed FAR1 selects.
    /// A Fork whose descriptor has no row is held at code 6 and stays
    /// Uncertain, never rejected; a restart whose FCP1 adds the row recovers
    /// and registers it; a later FCP1 without that durable row fails the
    /// read-only preflight before any bind.
    #[tokio::test]
    async fn listener_registers_the_profile_selected_classifier_across_restarts() -> TestResult {
        let (world, parents) = provisioned_world(&["classified parent"])?;
        let payload = fork_payload(6, parents[0])?;

        let (gateway, listener) = start_profiled(&world, &[9])?;
        assert_eq!(
            &request(&world.socket, &bind_payload(5), false)?[..10],
            &BIND_OK
        );
        for _ in 0..2 {
            assert_eq!(request(&world.socket, &payload, false)?, rejected(6));
        }
        assert_eq!(delivery_state(&world, 6)?, Some(2));
        assert_eq!(graph_rows(&world)?[1], 1);
        assert_eq!(classifier_rows(&world)?, [0, 0]);
        stop(&world, gateway, listener).await?;

        let (gateway, listener) = start_profiled(&world, &[7, 9])?;
        let first = fork_result(&request(&world.socket, &payload, false)?)?;
        wait_for_delivery_state(&world, 6, 3)?;
        assert_eq!(classifier_rows(&world)?, [1, 1]);
        assert_eq!(
            fork_result(&request(&world.socket, &payload, false)?)?,
            first
        );
        assert_eq!(classifier_rows(&world)?, [1, 1]);
        stop(&world, gateway, listener).await?;

        let authority_before = authority_rows(&world)?;
        assert!(open_with_credentials(
            world.path()?,
            (current_peer_credentials()?, profile_from(&[9])?),
            None,
            &ErasureCoordinatorCompositionV1::closed(),
        )
        .is_err());
        assert_eq!(authority_rows(&world)?, authority_before);
        assert!(!world.socket.exists());

        let (gateway, listener) = start_profiled(&world, &[7])?;
        assert_eq!(
            fork_result(&request(&world.socket, &payload, false)?)?,
            first
        );
        assert_eq!(classifier_rows(&world)?, [1, 1]);
        stop(&world, gateway, listener).await?;
        Ok(())
    }

    #[test]
    fn preflight_failures_map_to_retryable_or_invalid_activation() {
        for (error, expected) in [
            (
                ForkEventAuthorityErrorV1::StorageIndeterminate,
                LocalForkAuthenticationErrorV1::CredentialUnavailable,
            ),
            (
                ForkEventAuthorityErrorV1::CorruptAuthority,
                LocalForkAuthenticationErrorV1::CredentialInvalid,
            ),
            (
                ForkEventAuthorityErrorV1::Conflict,
                LocalForkAuthenticationErrorV1::CredentialInvalid,
            ),
        ] {
            assert_eq!(preflight_error(error), expected);
        }
    }

    /// One named managed-credential fixture writer.
    type CredentialCase<'a> = (&'a str, &'a dyn Fn(&Path) -> io::Result<()>);

    /// Write the managed set, then leave one credential writable (mode 0600).
    fn writable(directory: &Path, name: &str, profile: &[u8]) -> io::Result<()> {
        managed_credentials(directory, ([7; 32], [8; 32]), profile)?;
        fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
    }

    /// ADR-107 r6 startup step 1: a missing, extra, renamed, unreadable,
    /// oversized, or malformed managed credential fails before the database
    /// is opened or created and before any listener binds.
    #[tokio::test]
    async fn serve_rejects_each_invalid_managed_credential_set_before_database_open() -> TestResult
    {
        let world = unprovisioned_world()?;
        let profile = profile_bytes(&[7])?;
        let cases: [CredentialCase<'_>; 9] = [
            ("missing-profile", &|path| {
                protected_credentials(path, [7; 32], [8; 32])
            }),
            ("extra", &|path| {
                managed_credentials(path, ([7; 32], [8; 32]), &profile)?;
                protected_credential_file(path, "pigloros.extra", b"x")
            }),
            ("renamed", &|path| {
                protected_credentials(path, [7; 32], [8; 32])?;
                protected_credential_file(path, "pigloros.fork-classifier-profiles", &profile)
            }),
            ("malformed", &|path| {
                managed_credentials(path, ([7; 32], [8; 32]), b"FCP1")
            }),
            ("oversized", &|path| {
                managed_credentials(
                    path,
                    ([7; 32], [8; 32]),
                    &vec![0; MAX_CLASSIFIER_PROFILE_BYTES + 1],
                )
            }),
            ("reused-seed", &|path| {
                managed_credentials(path, ([7; 32], [7; 32]), &profile)
            }),
            ("writable-auth", &|path| {
                writable(path, "pigloros.fork-admission-auth", &profile)
            }),
            ("writable-host", &|path| {
                writable(path, "pigloros.fork-admission-host-signer", &profile)
            }),
            ("writable-profile", &|path| {
                writable(path, CLASSIFIER_PROFILE_CREDENTIAL_NAME, &profile)
            }),
        ];
        for (name, write) in cases {
            let credentials = world.runtime.path().join(name);
            fs::create_dir(&credentials)?;
            fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700))?;
            write(credentials.as_path())?;
            assert!(
                serve_for_test(paths(&world, &credentials)?, async {})
                    .await
                    .is_err(),
                "{name} must fail closed"
            );
            assert!(
                !world.database.exists(),
                "{name} must not open the database"
            );
            assert!(!world.socket.exists(), "{name} must not bind the listener");
        }
        Ok(())
    }
}
