//! Final composition and activation for ADR-069's root-owned selector.
//!
//! This module owns no caller-configurable authority. It opens exactly one
//! SIC1 state, fails closed while SIR1 recovery is pending, binds the fixed
//! administrative listener before the evaluator listener, and keeps both
//! pathname identities under one admission lifetime.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use rustix::fs::{chmodat, statat, unlinkat, AtFlags, FileType, Mode};
use rustix::net::sockopt::socket_peercred;

use crate::provider_transport::{
    AuthenticatedProviderExecution, AuthenticatedProviderTerminal, PostAdmissionProviderFailure,
    ProviderTransport, ProviderTransportError, ReadSeek,
};
use crate::sandbox_provider_protocol::{
    AdmittedSandboxImage, ExecuteAuthority, LaunchPolicy, RequestAuthority, SandboxExecuteRequest,
    SandboxLocalError, SandboxLocalErrorCode, SandboxLocalErrorPhase, SandboxProviderError,
    SandboxProviderErrorCode, SandboxProviderOperation, SignedImageManifest,
};
#[cfg(test)]
use crate::selector::installation::authority::ProviderRuntimeSlot;
use crate::selector::installation::authority::{
    fresh_selector_id, AdmittedProviderRuntime, AdmittedSelectorProvider,
    AuthenticatedSelectorBootstrap, InstallationRecoverySnapshot,
};
use crate::selector::installation::{
    open_directory_chain, InstallationObjectKind, InstalledSelectorState,
};
use crate::selector::SelectorBoundaryError;
#[cfg(test)]
use crate::selector_protocol::decode_request;
use crate::selector_protocol::{
    decode_staged_request, encode_authenticated_reply, encode_local_error_reply,
    AuthenticatedSelectorReply, DecodedSelectorRequest, EncodedSelectorReply,
    SelectorProviderTerminal,
};

const CONTROL_LIMIT: u32 = 16 * 1024 * 1024;
const CONTROL_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const SELECTOR_INPUT_LIMIT: u64 = 128 * 1024 * 1024;
const CONTROL_ARTIFACT_LIMIT: u64 = 16 * 1024 * 1024;
const IMAGE_ARTIFACT_LIMIT: u64 = 1024 * 1024 * 1024;
const MAX_RETAINED_EVALUATION_NAMESPACES: usize = 256;
const ROOT_UID: u32 = 0;
const INITIAL_IO_TIMEOUT: Duration = Duration::from_secs(30);
const LIVE_UPDATE_TIMEOUT: Duration = Duration::from_millis(100);
const SELECTOR_SOCKET_MODE: u32 = 0o600;
#[cfg(test)]
const SELECTOR_PARENT_MODE: u32 = 0o700;
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const SANDBOX_SELECTOR_SOCKET_RELATIVE: &str = "run/pigloros/sandbox-provider.sock";

fn artifact_invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn selector_unavailable<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::SelectorUnavailable
}

fn io_error<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

fn map_to_unit_error<T>(_: T) {}

/// Authenticated selector composition before fixed runtime activation.
///
/// Pending SIR1 deliberately remains unavailable: `InstalledSelectorState::open`
/// rejects it before any capability can be returned. [`RootSelectorRuntime`]
/// owns the only production activation path.
pub struct RootSelectorComposition {
    service: RootSelectorService<ProviderTransport>,
    updates: Mutex<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

struct OwnedSocketPath {
    parent: File,
    parent_path: PathBuf,
    leaf: OsString,
    identity: SocketIdentity,
    owner_uid: u32,
}

impl OwnedSocketPath {
    fn capture(
        parent: File,
        parent_path: PathBuf,
        leaf: OsString,
        owner_uid: u32,
    ) -> Result<Self, SelectorBoundaryError> {
        let (identity, _) = named_socket(&parent, &leaf, owner_uid)?;
        Ok(Self {
            parent,
            parent_path,
            leaf,
            identity,
            owner_uid,
        })
    }

    fn finish_setup(&self, parent_path: &Path) -> Result<(), SelectorBoundaryError> {
        if parent_path != self.parent_path {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        chmodat(
            &self.parent,
            Path::new(&self.leaf),
            Mode::from_raw_mode(SELECTOR_SOCKET_MODE),
            AtFlags::empty(),
        )
        .map_err(io_error)?;
        self.verify()
    }

    fn verify(&self) -> Result<(), SelectorBoundaryError> {
        validate_listener_parent(&self.parent_path, &self.parent, self.owner_uid)?;
        let current = listener_socket_identity(&self.parent, &self.leaf, self.owner_uid)?;
        require_same_socket(current, self.identity)
    }

    fn remove(&self) -> Result<(), SelectorBoundaryError> {
        self.verify()?;
        remove_matching_socket(&self.parent, &self.leaf, self.identity, self.owner_uid)
    }
}

/// Identity-bound owner of the fixed evaluator listener.
///
/// Constructing this type is the activation step owned by #359. Merely opening
/// [`RootSelectorComposition`] never binds the fixed endpoint. Cleanup retains
/// the root-owned parent directory and removes the pathname only while it still
/// names the socket inode created by this owner.
pub struct OwnedSelectorListener {
    listener: UnixListener,
    path: OwnedSocketPath,
    owned: bool,
}

/// Identity-bound owner of the fixed root-administrator listener.
pub struct OwnedAdministratorListener {
    inner: OwnedSelectorListener,
}

/// Fully activated root selector with both fixed listeners owned together.
pub struct RootSelectorRuntime {
    composition: RootSelectorComposition,
    administrator: OwnedAdministratorListener,
    evaluator: OwnedSelectorListener,
}

impl OwnedSelectorListener {
    /// Bind and own the fixed evaluator listener.
    ///
    /// # Errors
    ///
    /// Returns a closed boundary error if the root-owned runtime directory is
    /// unsafe, the endpoint already exists, or the bound socket cannot be
    /// authenticated through the retained parent directory.
    pub fn bind() -> Result<Self, SelectorBoundaryError> {
        Self::bind_beneath(
            Path::new("/"),
            Path::new(SANDBOX_SELECTOR_SOCKET_RELATIVE),
            ROOT_UID,
        )
    }

    #[cfg(test)]
    fn bind_path(path: &Path, expected_uid: u32) -> Result<Self, SelectorBoundaryError> {
        let parent_path = path
            .parent()
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let leaf = path
            .file_name()
            .map(OsString::from)
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let parent = File::open(parent_path).map_err(io_error)?;
        Self::bind_in_parent(path, parent, leaf, expected_uid)
    }

    fn bind_beneath(
        ancestry_root: &Path,
        relative_path: &Path,
        expected_uid: u32,
    ) -> Result<Self, SelectorBoundaryError> {
        let parent_relative = relative_path
            .parent()
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let leaf = relative_path
            .file_name()
            .map(OsString::from)
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let root = File::open(ancestry_root).map_err(io_error)?;
        let parent = open_directory_chain(root, parent_relative, expected_uid)?;
        let path = ancestry_root.join(relative_path);
        Self::bind_in_parent(&path, parent, leaf, expected_uid)
    }

    fn bind_in_parent(
        path: &Path,
        parent: File,
        leaf: OsString,
        expected_uid: u32,
    ) -> Result<Self, SelectorBoundaryError> {
        let parent_path = path
            .parent()
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        validate_listener_parent(parent_path, &parent, expected_uid)?;
        match statat(&parent, Path::new(&leaf), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(SelectorBoundaryError::ArtifactInvalid),
        }
        let listener = UnixListener::bind(path).map_err(io_error)?;
        Self::from_bound(
            listener,
            parent,
            parent_path.to_path_buf(),
            leaf,
            expected_uid,
        )
        .and_then(|owned| owned.finish_setup(parent_path))
    }

    fn from_bound(
        listener: UnixListener,
        parent: File,
        parent_path: PathBuf,
        leaf: OsString,
        expected_uid: u32,
    ) -> Result<Self, SelectorBoundaryError> {
        // Without a captured pathname identity there is no safe basis for
        // unlinking after an observation failure. Retaining a fail-closed stale
        // node is preferable to removing a possible replacement.
        let path = OwnedSocketPath::capture(parent, parent_path, leaf, expected_uid)?;
        Ok(Self {
            listener,
            path,
            owned: true,
        })
    }

    fn finish_setup(self, parent_path: &Path) -> Result<Self, SelectorBoundaryError> {
        self.path.finish_setup(parent_path)?;
        Ok(self)
    }

    /// Accept one evaluator connection without interpreting its authority.
    ///
    /// The returned stream is passed to
    /// [`RootSelectorComposition::evaluate_root_connection`], which performs
    /// the required peer authentication and protocol handling.
    ///
    /// # Errors
    /// Returns a closed I/O error when the listener cannot accept a stream.
    pub fn accept(&self) -> Result<UnixStream, SelectorBoundaryError> {
        self.path.verify()?;
        self.listener
            .accept()
            .map(|(stream, _)| stream)
            .map_err(io_error)
    }

    fn set_nonblocking(&self) -> Result<(), SelectorBoundaryError> {
        self.listener.set_nonblocking(true).map_err(io_error)
    }

    fn try_accept(&self) -> Result<Option<UnixStream>, SelectorBoundaryError> {
        self.path.verify()?;
        match self.listener.accept() {
            Ok((stream, _)) => Ok(Some(stream)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(io_error(error)),
        }
    }

    /// Remove the exact owned socket and consume the listener.
    ///
    /// # Errors
    /// Returns a closed identity error if the pathname is absent or has been
    /// replaced. A replacement is never removed.
    pub fn close(mut self) -> Result<(), SelectorBoundaryError> {
        let result = self.remove_owned_socket();
        if result.is_ok() {
            self.owned = false;
        }
        result
    }

    fn remove_owned_socket(&self) -> Result<(), SelectorBoundaryError> {
        self.path.remove()
    }
}

impl OwnedAdministratorListener {
    fn bind() -> Result<Self, SelectorBoundaryError> {
        OwnedSelectorListener::bind_path(
            Path::new(crate::selector::installation::SANDBOX_ADMIN_SOCKET),
            ROOT_UID,
        )
        .map(|inner| Self { inner })
    }

    fn set_nonblocking(&self) -> Result<(), SelectorBoundaryError> {
        self.inner.set_nonblocking()
    }

    fn try_accept(&self) -> Result<Option<UnixStream>, SelectorBoundaryError> {
        self.inner.try_accept()
    }
}

impl RootSelectorRuntime {
    /// Authenticate the fixed installation and expose both listeners in safe order.
    ///
    /// # Errors
    /// Returns a closed boundary error unless provider synchronization succeeds,
    /// the administrative listener is valid first, and the evaluator listener
    /// can then be bound without replacing any existing node.
    pub fn activate() -> Result<Self, SelectorBoundaryError> {
        RootSelectorComposition::open().and_then(Self::from_composition)
    }

    fn from_composition(
        composition: RootSelectorComposition,
    ) -> Result<Self, SelectorBoundaryError> {
        let administrator = OwnedAdministratorListener::bind()?;
        let evaluator = OwnedSelectorListener::bind()?;
        administrator.set_nonblocking()?;
        evaluator.set_nonblocking()?;
        Ok(Self {
            composition,
            administrator,
            evaluator,
        })
    }

    /// Serve both fixed root-only endpoints until a listener invariant fails.
    ///
    /// Administrative transactions are serialized; evaluator connections may
    /// overlap and are fenced by the root-owned admission registry.
    ///
    /// # Errors
    /// Returns after closing admission when either fixed listener loses its
    /// retained pathname identity or its accept loop encounters a local error.
    pub fn serve(self) -> Result<(), SelectorBoundaryError> {
        let Self {
            composition,
            administrator,
            evaluator,
        } = self;
        let composition = Arc::new(composition);
        let stopped = Arc::new(AtomicBool::new(false));
        let (completed, completion) = std::sync::mpsc::channel();
        thread::scope(|scope| {
            let admin_composition = Arc::clone(&composition);
            let admin_stopped = Arc::clone(&stopped);
            let admin_completed = completed.clone();
            let admin = scope.spawn(move || {
                let result =
                    serve_administrator(&administrator, &admin_composition, &admin_stopped);
                drop(admin_completed.send(result));
                result
            });

            let evaluator_composition = Arc::clone(&composition);
            let evaluator_stopped = Arc::clone(&stopped);
            let evaluator_completed = completed.clone();
            let evaluator_thread = scope.spawn(move || {
                let result =
                    serve_evaluator(&evaluator, &evaluator_composition, &evaluator_stopped);
                drop(evaluator_completed.send(result));
                result
            });
            drop(completed);

            let first = completion
                .recv()
                .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
            composition.service.admission.close()?;
            stopped.store(true, Ordering::Release);
            let admin = admin
                .join()
                .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
            let evaluator = evaluator_thread
                .join()
                .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
            first.and(admin).and(evaluator)
        })
    }
}

fn serve_administrator(
    listener: &OwnedAdministratorListener,
    composition: &RootSelectorComposition,
    stopped: &AtomicBool,
) -> Result<(), SelectorBoundaryError> {
    while !stopped.load(Ordering::Acquire) {
        if let Some(stream) = listener.try_accept()? {
            drop(composition.update_installation(stream));
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
}

fn serve_evaluator(
    listener: &OwnedSelectorListener,
    composition: &Arc<RootSelectorComposition>,
    stopped: &AtomicBool,
) -> Result<(), SelectorBoundaryError> {
    while !stopped.load(Ordering::Acquire) {
        if let Some(stream) = listener.try_accept()? {
            let composition = Arc::clone(composition);
            drop(thread::spawn(move || {
                drop(composition.evaluate_root_connection(stream));
            }));
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
}

impl Drop for OwnedSelectorListener {
    fn drop(&mut self) {
        if self.owned {
            let _cleanup_result = self.remove_owned_socket();
        }
    }
}

fn validate_listener_parent(
    path: &Path,
    parent: &File,
    expected_uid: u32,
) -> Result<(), SelectorBoundaryError> {
    validate_listener_parent_with(path, parent, expected_uid, File::metadata)
}

fn validate_listener_parent_with(
    path: &Path,
    parent: &File,
    expected_uid: u32,
    held_metadata: impl FnOnce(&File) -> std::io::Result<std::fs::Metadata>,
) -> Result<(), SelectorBoundaryError> {
    let held = held_metadata(parent).map_err(io_error)?;
    let named = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !held.is_dir()
        || !named.is_dir()
        || held.uid() != expected_uid
        || held.mode() & GROUP_OR_OTHER_WRITE != 0
        || held.dev() != named.dev()
        || held.ino() != named.ino()
    {
        Err(SelectorBoundaryError::ArtifactInvalid)
    } else {
        Ok(())
    }
}

fn listener_socket_identity(
    parent: &File,
    leaf: &OsString,
    expected_uid: u32,
) -> Result<SocketIdentity, SelectorBoundaryError> {
    let (identity, mode) = named_socket(parent, leaf, expected_uid)?;
    if mode != SELECTOR_SOCKET_MODE {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(identity)
}

fn named_socket(
    parent: &File,
    leaf: &OsString,
    expected_uid: u32,
) -> Result<(SocketIdentity, u32), SelectorBoundaryError> {
    let metadata =
        statat(parent, Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW).map_err(artifact_invalid)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
        || metadata.st_uid != expected_uid
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok((
        SocketIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        },
        metadata.st_mode & 0o777,
    ))
}

fn require_same_socket(
    current: SocketIdentity,
    expected: SocketIdentity,
) -> Result<(), SelectorBoundaryError> {
    if current == expected {
        Ok(())
    } else {
        Err(SelectorBoundaryError::ArtifactInvalid)
    }
}

fn remove_matching_socket(
    parent: &File,
    leaf: &OsString,
    expected: SocketIdentity,
    expected_uid: u32,
) -> Result<(), SelectorBoundaryError> {
    let metadata =
        statat(parent, Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW).map_err(artifact_invalid)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
        || metadata.st_uid != expected_uid
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    require_same_socket(
        SocketIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        },
        expected,
    )?;
    unlinkat(parent, Path::new(leaf), AtFlags::empty()).map_err(io_error)
}

impl RootSelectorComposition {
    /// Opens and authenticates the exact fixed installation and selected provider.
    ///
    /// # Errors
    ///
    /// Returns a closed boundary error for missing, invalid, pending-recovery,
    /// or unavailable installation/provider state.
    pub fn open() -> Result<Self, SelectorBoundaryError> {
        InstalledSelectorState::open()
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(AuthenticatedSelectorBootstrap::admit_provider)
            .and_then(|admitted| {
                connect_fixed_provider(&admitted).map(|(transport, runtime)| Self {
                    service: RootSelectorService {
                        admission: SelectorAdmission::new(admitted, runtime),
                        transport,
                        peer_uid: ROOT_UID,
                        evaluation_namespaces: EvaluationNamespaceBindings::default(),
                    },
                    updates: Mutex::new(()),
                })
            })
    }

    /// Evaluates one already-accepted root peer without binding any socket.
    ///
    /// # Errors
    ///
    /// Returns a closed boundary error when the stream cannot be authenticated,
    /// decoded, executed, or answered. Protocol-level failures are encoded in
    /// the selector reply where the request identity permits one.
    pub fn evaluate_root_connection(
        &self,
        stream: UnixStream,
    ) -> Result<(), SelectorBoundaryError> {
        self.service.handle_connection(stream)
    }

    /// Process one root-administrator SICN1/SIU1 transaction.
    ///
    /// The connection receives one challenge, may submit one framed SIU1 and
    /// write EOF, and receives the exact provider RCA1 only after durable
    /// successor publication and successor admission have completed.
    ///
    /// # Errors
    /// Returns a closed boundary error for a foreign peer, malformed framing,
    /// invalid authority, failed durability, timeout, or provider rejection.
    pub fn update_installation(&self, mut stream: UnixStream) -> Result<(), SelectorBoundaryError> {
        if !root_peer(&stream, ROOT_UID) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        stream
            .set_read_timeout(Some(INITIAL_IO_TIMEOUT))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(INITIAL_IO_TIMEOUT))
            .map_err(io_error)?;
        let _serialized = self.updates.lock().map_err(selector_unavailable)?;
        let current = self.service.admission.current()?;
        let challenge = current.bootstrap().issue_update_challenge()?;
        write_control_frame(&mut stream, &challenge.to_canonical_cbor()?)?;
        let update_bytes = read_control_frame(&mut stream)?;
        require_stream_eof(&mut stream)?;
        let closed = self.service.admission.close_and_snapshot()?;
        let committed = match prepare_live_update(&closed, challenge, &update_bytes) {
            Ok(committed) => committed,
            Err(error) => {
                self.service.admission.reopen_previous(&closed.admitted)?;
                return Err(error);
            }
        };
        let (successor, acknowledgement) = self
            .service
            .transport
            .complete_committed_update(committed, LIVE_UPDATE_TIMEOUT)?;
        self.service
            .admission
            .admit_successor(&closed.admitted, successor)?;
        write_control_frame(&mut stream, &acknowledgement)?;
        stream.shutdown(std::net::Shutdown::Write).map_err(io_error)
    }
}

fn prepare_live_update(
    closed: &ClosedSelectorAdmission,
    challenge: crate::selector::installation::authority::InstallationChallenge,
    update_bytes: &[u8],
) -> Result<
    crate::selector::installation::authority::CommittedInstallationUpdate,
    SelectorBoundaryError,
> {
    let update = closed
        .admitted
        .bootstrap()
        .validate_update(challenge, update_bytes)?;
    let snapshot = InstallationRecoverySnapshot::seal(
        &closed.admitted,
        &closed.runtime,
        closed.live_attempt_ids.clone(),
        closed.live_attempt_ids.clone(),
    )?;
    Arc::clone(&closed.admitted).commit_update(update, snapshot)
}

fn write_control_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<(), SelectorBoundaryError> {
    let length = framed_control_length(bytes.len())?;
    if length == 0 {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    stream.write_all(&length.to_be_bytes()).map_err(io_error)?;
    stream.write_all(bytes).map_err(io_error)
}

fn read_control_frame(stream: &mut impl Read) -> Result<Vec<u8>, SelectorBoundaryError> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).map_err(io_error)?;
    let length = u32::from_be_bytes(prefix);
    if length == 0 || length > CONTROL_LIMIT {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let mut bytes = vec![0; usize::try_from(length).map_err(artifact_invalid)?];
    stream.read_exact(&mut bytes).map_err(io_error)?;
    Ok(bytes)
}

fn require_stream_eof(stream: &mut impl Read) -> Result<(), SelectorBoundaryError> {
    let mut extra = [0];
    match stream.read(&mut extra) {
        Ok(0) => Ok(()),
        _ => Err(SelectorBoundaryError::ArtifactInvalid),
    }
}

fn connect_fixed_provider(
    admitted: &AdmittedSelectorProvider,
) -> Result<(ProviderTransport, AdmittedProviderRuntime), SelectorBoundaryError> {
    let transport = connect_and_synchronize(
        admitted,
        ProviderTransport::from_admitted,
        fresh_selector_id,
        synchronize_fixed_provider,
    )?;
    let runtime = transport.admit_runtime(admitted)?;
    Ok((transport, runtime))
}

fn synchronize_fixed_provider(
    transport: &ProviderTransport,
    admitted: &AdmittedSelectorProvider,
    request_id: [u8; 16],
    nonce: [u8; 16],
) -> Result<(), SelectorBoundaryError> {
    transport.synchronize_revocation(admitted.provider(), request_id, nonce, INITIAL_IO_TIMEOUT)
}

fn connect_and_synchronize<Admitted, Transport, Error>(
    admitted: &Admitted,
    connect: impl FnOnce(&Admitted) -> Result<Transport, Error>,
    mut nonce: impl FnMut() -> Result<[u8; 16], Error>,
    synchronize: impl FnOnce(&Transport, &Admitted, [u8; 16], [u8; 16]) -> Result<(), Error>,
) -> Result<Transport, Error> {
    let transport = connect(admitted)?;
    let request_id = nonce()?;
    let challenge = nonce()?;
    synchronize(&transport, admitted, request_id, challenge)?;
    Ok(transport)
}

trait ProviderExecutor {
    fn execute(
        &self,
        admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
        commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
        spx1: &[u8],
        input: &mut dyn ReadSeek,
        watchdog: Duration,
    ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError>;
}

impl ProviderExecutor for ProviderTransport {
    fn execute(
        &self,
        admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
        commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
        spx1: &[u8],
        input: &mut dyn ReadSeek,
        watchdog: Duration,
    ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
        Self::execute_staged(self, admitted, commitment, spx1, input, watchdog)
    }
}

struct RootSelectorService<T = ProviderTransport> {
    admission: SelectorAdmission,
    transport: T,
    peer_uid: u32,
    evaluation_namespaces: EvaluationNamespaceBindings,
}

struct SelectorAdmission {
    state: Mutex<SelectorAdmissionState>,
}

struct SelectorAdmissionState {
    admitted: Arc<AdmittedSelectorProvider>,
    runtime: AdmittedProviderRuntime,
    open: bool,
    live_attempts: BTreeMap<[u8; 16], usize>,
}

struct SelectorAdmissionLease<'a> {
    owner: &'a SelectorAdmission,
    admitted: Arc<AdmittedSelectorProvider>,
    attempt_id: [u8; 16],
}

struct ClosedSelectorAdmission {
    admitted: Arc<AdmittedSelectorProvider>,
    runtime: AdmittedProviderRuntime,
    live_attempt_ids: Vec<[u8; 16]>,
}

impl SelectorAdmission {
    fn new(admitted: AdmittedSelectorProvider, runtime: AdmittedProviderRuntime) -> Self {
        Self {
            state: Mutex::new(SelectorAdmissionState {
                admitted: Arc::new(admitted),
                runtime,
                open: true,
                live_attempts: BTreeMap::new(),
            }),
        }
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn for_test(admitted: AdmittedSelectorProvider) -> Result<Self, SelectorBoundaryError> {
        let runtime = ProviderRuntimeSlot::allocate(&admitted)?.bind_observed_process(1, 1)?;
        Ok(Self::new(admitted, runtime))
    }

    fn acquire(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<SelectorAdmissionLease<'_>, SelectorBoundaryError> {
        if attempt_id == [0; 16] {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let mut state = self.state.lock().map_err(selector_unavailable)?;
        if !state.open {
            return Err(SelectorBoundaryError::SelectorUnavailable);
        }
        if !state.live_attempts.contains_key(&attempt_id)
            && state.live_attempts.len() >= MAX_RETAINED_EVALUATION_NAMESPACES
        {
            return Err(SelectorBoundaryError::SelectorUnavailable);
        }
        *state.live_attempts.entry(attempt_id).or_default() += 1;
        let admitted = Arc::clone(&state.admitted);
        drop(state);
        Ok(SelectorAdmissionLease {
            owner: self,
            admitted,
            attempt_id,
        })
    }

    fn current(&self) -> Result<Arc<AdmittedSelectorProvider>, SelectorBoundaryError> {
        let state = self.state.lock().map_err(selector_unavailable)?;
        state
            .open
            .then(|| Arc::clone(&state.admitted))
            .ok_or(SelectorBoundaryError::SelectorUnavailable)
    }

    fn close(&self) -> Result<(), SelectorBoundaryError> {
        let mut state = self.state.lock().map_err(selector_unavailable)?;
        state.open = false;
        Ok(())
    }

    fn close_and_snapshot(&self) -> Result<ClosedSelectorAdmission, SelectorBoundaryError> {
        let mut state = self.state.lock().map_err(selector_unavailable)?;
        if !state.open {
            return Err(SelectorBoundaryError::SelectorUnavailable);
        }
        state.open = false;
        Ok(ClosedSelectorAdmission {
            admitted: Arc::clone(&state.admitted),
            runtime: state.runtime.clone(),
            live_attempt_ids: state.live_attempts.keys().copied().collect(),
        })
    }

    fn reopen_previous(
        &self,
        previous: &Arc<AdmittedSelectorProvider>,
    ) -> Result<(), SelectorBoundaryError> {
        let mut state = self.state.lock().map_err(selector_unavailable)?;
        if state.open || !Arc::ptr_eq(&state.admitted, previous) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        state.open = true;
        drop(state);
        Ok(())
    }

    fn admit_successor(
        &self,
        previous: &Arc<AdmittedSelectorProvider>,
        successor: AdmittedSelectorProvider,
    ) -> Result<(), SelectorBoundaryError> {
        let mut state = self.state.lock().map_err(selector_unavailable)?;
        if state.open || !Arc::ptr_eq(&state.admitted, previous) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        state.admitted = Arc::new(successor);
        state.open = true;
        drop(state);
        Ok(())
    }

    fn release(&self, attempt_id: [u8; 16]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let std::collections::btree_map::Entry::Occupied(mut entry) =
            state.live_attempts.entry(attempt_id)
        {
            if *entry.get() > 1 {
                *entry.get_mut() -= 1;
            } else {
                entry.remove();
            }
        }
    }
}

impl Drop for SelectorAdmissionLease<'_> {
    fn drop(&mut self) {
        self.owner.release(self.attempt_id);
    }
}

struct StagedSelectorRequest {
    decoded: DecodedSelectorRequest,
    input: tempfile::NamedTempFile,
}

#[derive(Default)]
struct EvaluationNamespaceBindings {
    // A namespace stays bound only while a matching request is live or the
    // provider has authenticated retained state. #359 may release retained
    // bindings after its durable attempt snapshot and reconciliation proof.
    states: Mutex<BTreeMap<[u8; 14], EvaluationNamespaceState>>,
    changed: Condvar,
    #[cfg(test)]
    waiting: AtomicUsize,
}

struct EvaluationNamespaceState {
    request_digest: [u8; 32],
    live_requests: usize,
    retained: bool,
}

struct EvaluationNamespaceExecution {
    conflict: bool,
    result: Result<AuthenticatedProviderTerminal, ProviderTransportError>,
}

#[derive(Clone, Copy)]
struct EvaluationNamespaceLease {
    namespace: [u8; 14],
    request_digest: [u8; 32],
    conflict: bool,
}

impl EvaluationNamespaceBindings {
    fn execute_ordered(
        &self,
        request: &crate::evaluator_protocol::EvaluationRequest,
        execute: impl FnOnce() -> Result<AuthenticatedProviderTerminal, ProviderTransportError>,
    ) -> Result<EvaluationNamespaceExecution, SelectorBoundaryError> {
        let lease = self.acquire(request)?;
        let result = execute();
        self.release(lease, provider_retains_namespace(&result))
            .map(|()| EvaluationNamespaceExecution {
                conflict: lease.conflict,
                result,
            })
    }

    fn acquire(
        &self,
        request: &crate::evaluator_protocol::EvaluationRequest,
    ) -> Result<EvaluationNamespaceLease, SelectorBoundaryError> {
        let mut namespace = [0; 14];
        namespace.copy_from_slice(&request.request_id[..14]);
        let mut states = self.states.lock().map_err(selector_unavailable)?;
        loop {
            if let Some(state) = states.get_mut(&namespace) {
                if state.request_digest == request.request_digest {
                    state.live_requests += 1;
                    let lease = EvaluationNamespaceLease {
                        namespace,
                        request_digest: request.request_digest,
                        conflict: false,
                    };
                    drop(states);
                    return Ok(lease);
                }
                if state.retained {
                    let lease = EvaluationNamespaceLease {
                        namespace,
                        request_digest: request.request_digest,
                        conflict: true,
                    };
                    drop(states);
                    return Ok(lease);
                }
                #[cfg(test)]
                self.waiting.fetch_add(1, Ordering::Release);
                let waited = self.changed.wait(states);
                #[cfg(test)]
                self.waiting.fetch_sub(1, Ordering::Release);
                states = waited.map_err(selector_unavailable)?;
            } else {
                if states.len() >= MAX_RETAINED_EVALUATION_NAMESPACES {
                    drop(states);
                    return Err(SelectorBoundaryError::SelectorUnavailable);
                }
                states.insert(
                    namespace,
                    EvaluationNamespaceState {
                        request_digest: request.request_digest,
                        live_requests: 1,
                        retained: false,
                    },
                );
                let lease = EvaluationNamespaceLease {
                    namespace,
                    request_digest: request.request_digest,
                    conflict: false,
                };
                drop(states);
                return Ok(lease);
            }
        }
    }

    fn release(
        &self,
        lease: EvaluationNamespaceLease,
        provider_retained: bool,
    ) -> Result<(), SelectorBoundaryError> {
        if lease.conflict {
            return Ok(());
        }
        let mut states = self.states.lock().map_err(selector_unavailable)?;
        let remove = {
            let state = states
                .get_mut(&lease.namespace)
                .filter(|state| state.request_digest == lease.request_digest)
                .ok_or(SelectorBoundaryError::SelectorUnavailable)?;
            state.live_requests -= 1;
            state.retained |= provider_retained;
            state.live_requests == 0 && !state.retained
        };
        if remove {
            states.remove(&lease.namespace);
        }
        drop(states);
        self.changed.notify_all();
        Ok(())
    }
}

fn provider_retains_namespace(
    result: &Result<AuthenticatedProviderTerminal, ProviderTransportError>,
) -> bool {
    match result {
        Ok(AuthenticatedProviderTerminal::Execution(_))
        | Err(ProviderTransportError::AfterAdmission { .. }) => true,
        Ok(AuthenticatedProviderTerminal::Error(error)) => {
            match SandboxProviderError::from_canonical_cbor(error) {
                Ok(error) => error.code == SandboxProviderErrorCode::RequestIdentityConflict,
                Err(_) => true,
            }
        }
        Err(ProviderTransportError::BeforeAdmission) => false,
    }
}

impl<T: ProviderExecutor> RootSelectorService<T> {
    fn handle_connection(&self, mut stream: UnixStream) -> Result<(), SelectorBoundaryError> {
        if !root_peer(&stream, self.peer_uid) {
            return Ok(());
        }
        stream
            .set_read_timeout(Some(INITIAL_IO_TIMEOUT))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(INITIAL_IO_TIMEOUT))
            .map_err(io_error)?;
        let Ok(StagedSelectorRequest { decoded, mut input }) = read_selector_request(&mut stream)
        else {
            return write_unidentified_request_error(&mut stream);
        };
        self.handle_decoded_request(&mut stream, &decoded, input.as_file_mut())
    }

    fn handle_decoded_request(
        &self,
        stream: &mut UnixStream,
        decoded: &DecodedSelectorRequest,
        input: &mut dyn ReadSeek,
    ) -> Result<(), SelectorBoundaryError> {
        let Ok(admission) = self.admission.acquire(decoded.attempt_id) else {
            return write_provider_unavailable(stream, decoded);
        };
        let admitted = admission.admitted.as_ref();
        let Some(requirement) = decoded.request.sandbox_requirement.as_ref() else {
            return write_policy_error(stream, decoded);
        };
        let ordinal = u16::from_be_bytes([
            decoded.provider_request_id[14],
            decoded.provider_request_id[15],
        ]);
        let resolved = match admitted
            .bootstrap()
            .resolve_installed_case(&decoded.request, ordinal)
        {
            Ok(resolved) if resolved.attempt() == &decoded.attempt => resolved,
            Ok(_) | Err(_) => return write_authority_mismatch(stream, decoded),
        };
        let io_timeout = Some(Duration::from_millis(resolved.attempt().watchdog_ms));
        stream.set_read_timeout(io_timeout).map_err(io_error)?;
        stream.set_write_timeout(io_timeout).map_err(io_error)?;
        let Ok((image, launch)) = selected_image_and_launch(admitted, requirement) else {
            return write_policy_error(stream, decoded);
        };
        let Ok(commitment) = admitted.provider().derive_selector_grant_commitment(
            &image,
            &launch,
            &decoded.request,
            resolved.attempt(),
            &[],
        ) else {
            return write_authority_mismatch(stream, decoded);
        };
        let Ok(spx1) = selector_execute_bytes(admitted, decoded, &resolved, requirement) else {
            return write_authority_mismatch(stream, decoded);
        };
        // The same EVR1 legitimately derives one ID per selected case and exact
        // retries remain provider-idempotent. Only a namespace bound to another
        // EVR1 digest is a conflict.
        let namespace_execution =
            self.evaluation_namespaces
                .execute_ordered(&decoded.request, || {
                    self.transport.execute(
                        admitted.provider(),
                        &commitment,
                        &spx1,
                        input,
                        Duration::from_millis(resolved.attempt().watchdog_ms),
                    )
                })?;
        let terminal = match namespace_execution.result {
            Ok(terminal) => terminal,
            Err(ProviderTransportError::BeforeAdmission) => {
                return write_provider_unavailable(stream, decoded);
            }
            Err(ProviderTransportError::AfterAdmission { agr1_digest, .. })
                if namespace_execution.conflict =>
            {
                return write_post_admission_provider_failure(
                    stream,
                    decoded,
                    agr1_digest,
                    PostAdmissionProviderFailure::EvidenceInvalid,
                );
            }
            Err(ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure,
            }) => {
                return write_post_admission_provider_failure(
                    stream,
                    decoded,
                    agr1_digest,
                    failure,
                );
            }
        };
        write_provider_terminal(
            stream,
            decoded,
            &spx1,
            terminal,
            namespace_execution.conflict,
        )
    }
}

fn write_provider_terminal(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    terminal: AuthenticatedProviderTerminal,
    namespace_conflict: bool,
) -> Result<(), SelectorBoundaryError> {
    if namespace_conflict {
        return write_namespace_conflict_terminal(stream, decoded, spx1, terminal);
    }
    match terminal {
        AuthenticatedProviderTerminal::Execution(mut execution) => {
            match write_authenticated_execution(stream, decoded, spx1, &mut execution) {
                Ok(()) => Ok(()),
                Err(()) => write_post_admission_provider_failure(
                    stream,
                    decoded,
                    execution.agr1_digest(),
                    PostAdmissionProviderFailure::EvidenceInvalid,
                ),
            }
        }
        AuthenticatedProviderTerminal::Error(error) => {
            write_authenticated_error(stream, decoded, spx1, &error)
        }
    }
}

fn write_namespace_conflict_terminal(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    terminal: AuthenticatedProviderTerminal,
) -> Result<(), SelectorBoundaryError> {
    match terminal {
        AuthenticatedProviderTerminal::Error(error)
            if SandboxProviderError::from_canonical_cbor(&error).is_ok_and(|error| {
                error.code == SandboxProviderErrorCode::RequestIdentityConflict
            }) =>
        {
            write_authenticated_error(stream, decoded, spx1, &error)
        }
        AuthenticatedProviderTerminal::Error(_) => write_local_error(
            stream,
            &SandboxLocalError {
                phase: SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
                operation: Some(SandboxProviderOperation::Execute),
                request_id: Some(decoded.provider_request_id),
                attempt_id: Some(decoded.attempt_id),
                agr1_digest: None,
                code: SandboxLocalErrorCode::ProviderEvidenceInvalid,
                safe_detail: None,
            },
        ),
        AuthenticatedProviderTerminal::Execution(execution) => {
            write_post_admission_provider_failure(
                stream,
                decoded,
                execution.agr1_digest(),
                PostAdmissionProviderFailure::EvidenceInvalid,
            )
        }
    }
}

fn selected_image_and_launch(
    admitted: &AdmittedSelectorProvider,
    requirement: &crate::evaluator_protocol::SandboxRequirement,
) -> Result<(AdmittedSandboxImage, LaunchPolicy), SelectorBoundaryError> {
    let installed = admitted.bootstrap().installed();
    read_installed(
        installed,
        InstallationObjectKind::IMAGE_MANIFEST,
        requirement.sim1_digest,
        CONTROL_ARTIFACT_LIMIT,
    )
    .and_then(|sim1| {
        SignedImageManifest::from_canonical_cbor(&sim1)
            .map_err(artifact_invalid)
            .map(|manifest| (sim1, manifest))
    })
    .and_then(|(sim1, manifest)| {
        read_installed(
            installed,
            InstallationObjectKind::ROOT_IMAGE,
            manifest.root_image_blake3_digest,
            IMAGE_ARTIFACT_LIMIT,
        )
        .map(|root_image| (sim1, manifest, root_image))
    })
    .and_then(|(sim1, manifest, root_image)| {
        read_installed(
            installed,
            InstallationObjectKind::SUBJECT_EXECUTABLE,
            manifest.executable_blake3_digest,
            IMAGE_ARTIFACT_LIMIT,
        )
        .map(|executable| (sim1, root_image, executable))
    })
    .and_then(|(sim1, root_image, executable)| {
        admitted
            .provider()
            .admit_image(&sim1, &root_image, &executable)
            .map_err(artifact_invalid)
    })
    .and_then(|image| {
        read_installed(
            installed,
            InstallationObjectKind::LAUNCH_POLICY,
            requirement.lps1_digest,
            CONTROL_ARTIFACT_LIMIT,
        )
        .map(|lps1| (image, lps1))
    })
    .and_then(|(image, lps1)| {
        admitted
            .provider()
            .admit_launch_policy(&lps1, &image)
            .map(|launch| (image, launch))
            .map_err(artifact_invalid)
    })
}

fn read_installed(
    installed: &InstalledSelectorState,
    kind: InstallationObjectKind,
    identity: [u8; 32],
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    installed.artifact(kind, identity)?.read_control(limit)
}

fn selector_execute_bytes(
    admitted: &AdmittedSelectorProvider,
    decoded: &DecodedSelectorRequest,
    resolved: &crate::selector::installation::ResolvedInstalledCase,
    requirement: &crate::evaluator_protocol::SandboxRequirement,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let bootstrap = admitted.bootstrap();
    let provider = admitted.provider();
    let authority = ExecuteAuthority {
        evr1_digest: decoded.request.request_digest,
        cpf1_digest: resolved.profile_digest(),
        cfb1_digest: resolved.bundle_digest(),
        fixture_contract_digest: resolved.fixture_contract_digest(),
        fixture_digest: resolved.attempt().fixture_digest,
        execution_profile_digest: decoded.request.execution_profile_digest,
        lps1_digest: requirement.lps1_digest,
        sim1_digest: requirement.sim1_digest,
        apt1_digest: requirement.apt1_digest,
        trs1_digest: bootstrap.trust().snapshot_digest(),
        rvs1_digest: bootstrap.revocation().snapshot_digest(),
        spm1_digest: provider.manifest().manifest_digest,
        pcf1_digest: provider.manifest().pcf1_digest,
        pcr1_digest: provider.conformance_report().report_digest,
        hcp1_digest: provider.host_profile().profile_digest,
    };
    let request = SandboxExecuteRequest::for_selector(
        RequestAuthority {
            request_id: decoded.provider_request_id,
            apt1_digest: requirement.apt1_digest,
            policy_epoch: requirement.policy_epoch,
            nonce: fresh_selector_id()?,
        },
        decoded.attempt_id,
        authority,
        resolved.attempt().capability_ids.clone(),
        decoded.input_descriptor(),
        Vec::new(),
    )
    .map_err(artifact_invalid)?;
    request.to_canonical_cbor().map_err(artifact_invalid)
}

fn write_authenticated_execution(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    execution: &mut AuthenticatedProviderExecution,
) -> Result<(), ()> {
    let staged = execution.with_verified_reply_output(
        |result, grant, receipt, audit_records, descriptor, reader| {
            encode_authenticated_reply(
                decoded,
                AuthenticatedSelectorReply {
                    execute_request: spx1,
                    terminal: SelectorProviderTerminal::StagedResult {
                        result,
                        grant: Some(grant),
                        receipt: Some(receipt),
                        audit_records,
                        output: Some(descriptor),
                    },
                },
            )
            .map_err(artifact_invalid)
            .and_then(|reply| {
                write_reply_with_trailing(stream, &reply, reader, descriptor.byte_length)
            })
        },
    );
    match staged.map_err(map_to_unit_error)? {
        Some(()) => Ok(()),
        None => encode_authenticated_reply(
            decoded,
            AuthenticatedSelectorReply {
                execute_request: spx1,
                terminal: SelectorProviderTerminal::StagedResult {
                    result: execution.spy1_bytes(),
                    grant: Some(execution.agr1_bytes()),
                    receipt: Some(execution.spr1_bytes()),
                    audit_records: execution.sau1_frames(),
                    output: None,
                },
            },
        )
        .map_err(map_to_unit_error)
        .and_then(|reply| write_reply(stream, &reply).map_err(map_to_unit_error)),
    }
}

fn write_authenticated_error(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    spx1: &[u8],
    error: &[u8],
) -> Result<(), SelectorBoundaryError> {
    encode_authenticated_reply(
        decoded,
        AuthenticatedSelectorReply {
            execute_request: spx1,
            terminal: SelectorProviderTerminal::Error { error },
        },
    )
    .map_err(artifact_invalid)
    .and_then(|reply| write_reply(stream, &reply))
}

fn write_unidentified_request_error(stream: &mut UnixStream) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        &SandboxLocalError {
            phase: SandboxLocalErrorPhase::BeforeSpx1,
            operation: None,
            request_id: None,
            attempt_id: None,
            agr1_digest: None,
            code: SandboxLocalErrorCode::InvalidSelectorRequest,
            safe_detail: None,
        },
    )
}

fn write_policy_error(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
) -> Result<(), SelectorBoundaryError> {
    write_pre_admission_error(
        stream,
        decoded,
        SandboxLocalErrorPhase::BeforeSpx1,
        SandboxLocalErrorCode::PolicyUnavailable,
    )
}

fn write_authority_mismatch(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
) -> Result<(), SelectorBoundaryError> {
    write_pre_admission_error(
        stream,
        decoded,
        SandboxLocalErrorPhase::BeforeSpx1,
        SandboxLocalErrorCode::RequestAuthorityMismatch,
    )
}

fn write_provider_unavailable(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
) -> Result<(), SelectorBoundaryError> {
    write_pre_admission_error(
        stream,
        decoded,
        SandboxLocalErrorPhase::AfterSpx1BeforeAdmission,
        SandboxLocalErrorCode::ProviderUnavailable,
    )
}

fn write_pre_admission_error(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    phase: SandboxLocalErrorPhase,
    code: SandboxLocalErrorCode,
) -> Result<(), SelectorBoundaryError> {
    write_local_error(
        stream,
        &SandboxLocalError {
            phase,
            operation: Some(SandboxProviderOperation::Execute),
            request_id: Some(decoded.provider_request_id),
            attempt_id: Some(decoded.attempt_id),
            agr1_digest: None,
            code,
            safe_detail: None,
        },
    )
}

fn write_post_admission_provider_failure(
    stream: &mut UnixStream,
    decoded: &DecodedSelectorRequest,
    agr1_digest: [u8; 32],
    failure: PostAdmissionProviderFailure,
) -> Result<(), SelectorBoundaryError> {
    let code = match failure {
        PostAdmissionProviderFailure::TerminalUnavailable => {
            SandboxLocalErrorCode::ProviderTerminalUnavailable
        }
        PostAdmissionProviderFailure::EvidenceInvalid => {
            SandboxLocalErrorCode::ProviderEvidenceInvalid
        }
    };
    let error = post_admission_provider_error(
        decoded.provider_request_id,
        decoded.attempt_id,
        agr1_digest,
        code,
    );
    write_local_error(stream, &error)
}

const fn post_admission_provider_error(
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
    code: SandboxLocalErrorCode,
) -> SandboxLocalError {
    SandboxLocalError {
        phase: SandboxLocalErrorPhase::AfterAdmission,
        operation: Some(SandboxProviderOperation::Execute),
        request_id: Some(request_id),
        attempt_id: Some(attempt_id),
        agr1_digest: Some(agr1_digest),
        code,
        safe_detail: None,
    }
}

fn write_local_error(
    stream: &mut UnixStream,
    error: &SandboxLocalError,
) -> Result<(), SelectorBoundaryError> {
    encode_local_error_reply(error)
        .map_err(artifact_invalid)
        .and_then(|reply| write_reply(stream, &reply))
}

fn write_reply(
    stream: &mut impl Write,
    reply: &EncodedSelectorReply,
) -> Result<(), SelectorBoundaryError> {
    let length = framed_control_length(reply.control.len())?;
    stream.write_all(&length.to_be_bytes()).map_err(io_error)?;
    stream.write_all(&reply.control).map_err(io_error)?;
    stream.write_all(&reply.trailing).map_err(io_error)
}

fn write_reply_with_trailing(
    stream: &mut impl Write,
    reply: &EncodedSelectorReply,
    trailing: &mut dyn Read,
    expected_length: u64,
) -> Result<(), SelectorBoundaryError> {
    let length = framed_control_length(reply.control.len())?;
    stream.write_all(&length.to_be_bytes()).map_err(io_error)?;
    stream.write_all(&reply.control).map_err(io_error)?;
    let copied = std::io::copy(
        &mut trailing.take(expected_length.saturating_add(1)),
        stream,
    )
    .map_err(io_error)?;
    (copied == expected_length)
        .then_some(())
        .ok_or(SelectorBoundaryError::ArtifactInvalid)
}

fn framed_control_length(length: usize) -> Result<u32, SelectorBoundaryError> {
    if length > CONTROL_LIMIT_BYTES {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    u32::try_from(length).map_err(artifact_invalid)
}

fn read_selector_request<R: Read>(stream: &mut R) -> Result<StagedSelectorRequest, ()> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(map_to_unit_error)?;
    let length = u32::from_be_bytes(prefix);
    if length == 0 || length > CONTROL_LIMIT {
        return Err(());
    }
    let length = usize::try_from(length).unwrap_or_default();
    let mut control = vec![0_u8; length];
    stream.read_exact(&mut control).map_err(map_to_unit_error)?;
    let mut input = tempfile::NamedTempFile::new().map_err(map_to_unit_error)?;
    let (input_length, input_digest) = stage_selector_input(stream, input.as_file_mut())?;
    input
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(map_to_unit_error)?;
    decode_staged_request(&control, input.as_file_mut(), input_length, input_digest)
        .map(|decoded| StagedSelectorRequest { decoded, input })
        .map_err(map_to_unit_error)
}

fn stage_selector_input(
    input: &mut dyn Read,
    staged: &mut dyn Write,
) -> Result<(u64, [u8; 32]), ()> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SandboxInputBytes.v1\0");
    let mut length = 0_u64;
    let mut buffer = [0; 16 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(map_to_unit_error)?;
        if read == 0 {
            return Ok((length, *hasher.finalize().as_bytes()));
        }
        length = checked_staged_input_length(length, read)?;
        hasher.update(&buffer[..read]);
        staged
            .write_all(&buffer[..read])
            .map_err(map_to_unit_error)?;
    }
}

fn checked_staged_input_length(current: u64, read: usize) -> Result<u64, ()> {
    let read = read as u64;
    let length = current.checked_add(read).ok_or(())?;
    if length > SELECTOR_INPUT_LIMIT {
        return Err(());
    }
    Ok(length)
}

fn root_peer(stream: &UnixStream, expected_uid: u32) -> bool {
    socket_peercred(stream.as_fd())
        .is_ok_and(|credentials| credentials.uid.as_raw() == expected_uid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    const PRIVILEGED_COMPOSITION_TEST: &str = "PIGLOROS_PRIVILEGED_COMPOSITION_TEST";
    const INSTALLATION_PARENT: &str = "/var/lib/pigloros";
    const RUNTIME_DIRECTORY: &str = "/run/pigloros";
    const SOCKET_MODE: u32 = 0o600;

    struct ListenerTestDirectory {
        directory: tempfile::TempDir,
        socket: std::path::PathBuf,
        uid: u32,
    }

    impl ListenerTestDirectory {
        fn create() -> TestResult<Self> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(
                directory.path(),
                fs::Permissions::from_mode(SELECTOR_PARENT_MODE),
            )?;
            let uid = fs::metadata(directory.path())?.uid();
            let socket = directory.path().join("selector.sock");
            Ok(Self {
                directory,
                socket,
                uid,
            })
        }
    }

    #[test]
    fn owned_selector_listener_accepts_and_removes_only_its_socket() -> TestResult {
        assert_eq!(
            Path::new("/").join(SANDBOX_SELECTOR_SOCKET_RELATIVE),
            Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET)
        );
        let fixture = ListenerTestDirectory::create()?;
        let listener = OwnedSelectorListener::bind_path(&fixture.socket, fixture.uid)?;
        let client = UnixStream::connect(&fixture.socket)?;
        let accepted = listener.accept()?;
        drop(accepted);
        drop(client);
        listener.close()?;
        assert!(!fixture.socket.exists());
        Ok(())
    }

    #[test]
    fn owned_selector_listener_rejects_a_symlink_ancestor() -> TestResult {
        let root = tempfile::tempdir()?;
        fs::set_permissions(
            root.path(),
            fs::Permissions::from_mode(SELECTOR_PARENT_MODE),
        )?;
        let uid = fs::metadata(root.path())?.uid();
        assert!(OwnedSelectorListener::bind_beneath(root.path(), Path::new(""), uid).is_err());
        assert!(OwnedSelectorListener::bind_beneath(root.path(), Path::new("."), uid).is_err());
        assert!(OwnedSelectorListener::bind_beneath(
            &root.path().join("missing"),
            Path::new("runtime/selector.sock"),
            uid,
        )
        .is_err());
        assert!(OwnedSelectorListener::bind_in_parent(
            Path::new("/"),
            File::open(root.path())?,
            OsString::from("selector.sock"),
            uid,
        )
        .is_err());
        let parent = root.path().join("runtime");
        fs::create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(SELECTOR_PARENT_MODE))?;

        let relative = Path::new("runtime/selector.sock");
        OwnedSelectorListener::bind_beneath(root.path(), relative, uid)?.close()?;

        fs::remove_dir(&parent)?;
        let replacement = root.path().join("replacement");
        fs::create_dir(&replacement)?;
        fs::set_permissions(
            &replacement,
            fs::Permissions::from_mode(SELECTOR_PARENT_MODE),
        )?;
        std::os::unix::fs::symlink("replacement", &parent)?;
        assert!(matches!(
            OwnedSelectorListener::bind_beneath(root.path(), relative, uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn owned_selector_listener_preserves_a_replacement_socket() -> TestResult {
        let fixture = ListenerTestDirectory::create()?;
        let listener = OwnedSelectorListener::bind_path(&fixture.socket, fixture.uid)?;
        fs::remove_file(&fixture.socket)?;
        let replacement = UnixListener::bind(&fixture.socket)?;
        fs::set_permissions(
            &fixture.socket,
            fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        assert!(matches!(
            listener.accept(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        drop(listener);
        assert!(fs::symlink_metadata(&fixture.socket)?
            .file_type()
            .is_socket());
        drop(replacement);
        fs::remove_file(&fixture.socket)?;
        Ok(())
    }

    #[test]
    fn owned_selector_listener_rejects_unsafe_or_occupied_parents() -> TestResult {
        let fixture = ListenerTestDirectory::create()?;
        fs::set_permissions(fixture.directory.path(), fs::Permissions::from_mode(0o775))?;
        assert!(matches!(
            OwnedSelectorListener::bind_path(&fixture.socket, fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        fs::set_permissions(
            fixture.directory.path(),
            fs::Permissions::from_mode(SELECTOR_PARENT_MODE),
        )?;
        fs::write(&fixture.socket, b"occupied")?;
        assert!(matches!(
            OwnedSelectorListener::bind_path(&fixture.socket, fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        assert!(matches!(
            OwnedSelectorListener::bind_path(Path::new("/"), fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        let child = fixture.directory.path().join("child");
        fs::create_dir(&child)?;
        fs::set_permissions(&child, fs::Permissions::from_mode(SELECTOR_PARENT_MODE))?;
        assert!(matches!(
            OwnedSelectorListener::bind_path(&child.join(".."), fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        assert!(matches!(
            OwnedSelectorListener::bind_path(
                &fixture
                    .directory
                    .path()
                    .join("missing")
                    .join("selector.sock"),
                fixture.uid,
            ),
            Err(SelectorBoundaryError::Io)
        ));
        let long_socket = fixture.directory.path().join("s".repeat(200));
        assert!(matches!(
            OwnedSelectorListener::bind_path(&long_socket, fixture.uid),
            Err(SelectorBoundaryError::Io)
        ));
        Ok(())
    }

    #[test]
    fn listener_identity_helpers_reject_every_unsafe_shape() -> TestResult {
        let fixture = ListenerTestDirectory::create()?;
        let foreign_uid = fixture.uid ^ 1;
        let leaf = fixture
            .socket
            .file_name()
            .ok_or("socket leaf missing")?
            .to_os_string();
        let parent = File::open(fixture.directory.path())?;

        assert!(matches!(
            listener_socket_identity(&parent, &leaf, fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::write(&fixture.socket, b"not a socket")?;
        assert!(matches!(
            listener_socket_identity(&parent, &leaf, fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::remove_file(&fixture.socket)?;

        let listener = UnixListener::bind(&fixture.socket)?;
        fs::set_permissions(&fixture.socket, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            listener_socket_identity(&parent, &leaf, fixture.uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::set_permissions(
            &fixture.socket,
            fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        assert!(matches!(
            listener_socket_identity(&parent, &leaf, foreign_uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        let identity = listener_socket_identity(&parent, &leaf, fixture.uid)?;
        assert_eq!(named_socket(&parent, &leaf, fixture.uid)?.0, identity);
        assert_eq!(require_same_socket(identity, identity), Ok(()));
        assert!(matches!(
            require_same_socket(
                identity,
                SocketIdentity {
                    device: identity.device,
                    inode: identity.inode.wrapping_add(1),
                },
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        assert!(matches!(
            remove_matching_socket(&parent, &leaf, identity, foreign_uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        assert!(matches!(
            remove_matching_socket(
                &parent,
                &leaf,
                SocketIdentity {
                    device: identity.device,
                    inode: identity.inode.wrapping_add(1),
                },
                fixture.uid,
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        drop(listener);
        fs::remove_file(&fixture.socket)?;

        let listener = OwnedSelectorListener::bind_path(&fixture.socket, fixture.uid)?;
        fs::remove_file(&fixture.socket)?;
        fs::write(&fixture.socket, b"replacement")?;
        assert!(matches!(
            listener.close(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        assert_eq!(fs::read(&fixture.socket)?, b"replacement");
        Ok(())
    }

    fn capture_test_listener(path: &Path, uid: u32) -> TestResult<OwnedSelectorListener> {
        let listener = UnixListener::bind(path)?;
        let parent = File::open(path.parent().ok_or("listener parent missing")?)?;
        let leaf = path
            .file_name()
            .ok_or("listener leaf missing")?
            .to_os_string();
        OwnedSelectorListener::from_bound(
            listener,
            parent,
            path.parent()
                .ok_or("listener parent missing")?
                .to_path_buf(),
            leaf,
            uid,
        )
        .map_err(Into::into)
    }

    #[test]
    fn listener_setup_and_cleanup_propagate_each_identity_failure() -> TestResult {
        let fixture = ListenerTestDirectory::create()?;

        let owned = capture_test_listener(&fixture.socket, fixture.uid)?;
        assert!(matches!(
            owned.path.finish_setup(Path::new("/different-parent")),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        owned.path.finish_setup(fixture.directory.path())?;
        owned.close()?;

        let listener = UnixListener::bind(&fixture.socket)?;
        let parent = File::open(fixture.directory.path())?;
        assert!(matches!(
            OwnedSelectorListener::from_bound(
                listener,
                parent,
                fixture.directory.path().to_path_buf(),
                OsString::from("missing.sock"),
                fixture.uid,
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::remove_file(&fixture.socket)?;

        let owned = capture_test_listener(&fixture.socket, fixture.uid)?;
        fs::remove_file(&fixture.socket)?;
        assert!(matches!(
            owned.finish_setup(fixture.directory.path()),
            Err(SelectorBoundaryError::Io)
        ));

        let owned = capture_test_listener(&fixture.socket, fixture.uid)?;
        fs::remove_file(&fixture.socket)?;
        fs::write(&fixture.socket, b"replacement")?;
        assert!(matches!(
            owned.finish_setup(fixture.directory.path()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::remove_file(&fixture.socket)?;

        let owned = capture_test_listener(&fixture.socket, fixture.uid)?;
        fs::remove_file(&fixture.socket)?;
        let replacement = UnixListener::bind(&fixture.socket)?;
        assert!(matches!(
            owned.finish_setup(fixture.directory.path()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        drop(replacement);
        fs::remove_file(&fixture.socket)?;

        let owned = capture_test_listener(&fixture.socket, fixture.uid)?;
        let moved_parent = fixture.directory.path().with_extension("held");
        fs::rename(fixture.directory.path(), &moved_parent)?;
        fs::create_dir(fixture.directory.path())?;
        fs::set_permissions(
            fixture.directory.path(),
            fs::Permissions::from_mode(SELECTOR_PARENT_MODE),
        )?;
        assert!(matches!(
            owned.finish_setup(fixture.directory.path()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::remove_file(moved_parent.join("selector.sock"))?;
        fs::remove_dir(moved_parent)?;

        let listener = OwnedSelectorListener::bind_path(&fixture.socket, fixture.uid)?;
        fs::remove_file(&fixture.socket)?;
        assert!(matches!(
            listener.close(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn listener_parent_validation_rejects_each_identity_boundary() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("parent");
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(SELECTOR_PARENT_MODE))?;
        let uid = fs::metadata(&path)?.uid();
        let held = File::open(&path)?;
        assert!(matches!(
            validate_listener_parent_with(&path, &held, uid, |_| {
                Err(std::io::Error::other("injected metadata failure"))
            }),
            Err(SelectorBoundaryError::Io)
        ));
        assert!(matches!(
            validate_listener_parent(&path, &held, uid ^ 1),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        validate_listener_parent(&path, &held, uid)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o775))?;
        assert!(matches!(
            validate_listener_parent(&path, &held, uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(SELECTOR_PARENT_MODE))?;

        let moved = temporary.path().join("held-parent");
        fs::rename(&path, &moved)?;
        assert!(matches!(
            validate_listener_parent(&path, &held, uid),
            Err(SelectorBoundaryError::Io)
        ));
        fs::write(&path, b"replacement")?;
        assert!(matches!(
            validate_listener_parent(&path, &held, uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(SELECTOR_PARENT_MODE))?;
        assert!(matches!(
            validate_listener_parent(&path, &held, uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let regular = temporary.path().join("regular");
        fs::write(&regular, b"regular")?;
        let regular_file = File::open(&regular)?;
        assert!(matches!(
            validate_listener_parent(&regular, &regular_file, uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    struct FixedCompositionFixture {
        installation: Option<SocketIdentity>,
        runtime: Option<SocketIdentity>,
    }

    impl FixedCompositionFixture {
        fn create() -> TestResult<Self> {
            if Path::new(INSTALLATION_PARENT).exists() || Path::new(RUNTIME_DIRECTORY).exists() {
                return Err("fixed selector test paths already exist".into());
            }
            fs::create_dir(INSTALLATION_PARENT)?;
            let mut fixture = Self {
                installation: Some(path_identity(Path::new(INSTALLATION_PARENT))?),
                runtime: None,
            };
            fs::set_permissions(INSTALLATION_PARENT, fs::Permissions::from_mode(0o700))?;
            fs::create_dir(crate::selector::installation::SANDBOX_ARTIFACT_ROOT)?;
            fs::set_permissions(
                crate::selector::installation::SANDBOX_ARTIFACT_ROOT,
                fs::Permissions::from_mode(0o700),
            )?;
            fs::create_dir(RUNTIME_DIRECTORY)?;
            fixture.runtime = Some(path_identity(Path::new(RUNTIME_DIRECTORY))?);
            fs::set_permissions(RUNTIME_DIRECTORY, fs::Permissions::from_mode(0o700))?;
            Ok(fixture)
        }
    }

    impl Drop for FixedCompositionFixture {
        fn drop(&mut self) {
            remove_owned_test_tree(Path::new(RUNTIME_DIRECTORY), self.runtime);
            remove_owned_test_tree(Path::new(INSTALLATION_PARENT), self.installation);
        }
    }

    fn path_identity(path: &Path) -> TestResult<SocketIdentity> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn remove_owned_test_tree(path: &Path, expected: Option<SocketIdentity>) {
        let matches = expected.is_some_and(|expected| {
            fs::symlink_metadata(path).is_ok_and(|metadata| {
                metadata.is_dir()
                    && metadata.dev() == expected.device
                    && metadata.ino() == expected.inode
            })
        });
        if matches {
            drop(fs::remove_dir_all(path));
        }
    }

    enum IsolatedCompositionRole {
        Delegated,
        ExecuteBody,
    }

    fn run_isolated_test(test_name: &str) -> TestResult {
        let runner =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
        let output = Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg(test_name)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "isolated test {test_name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn isolated_composition_role() -> TestResult<IsolatedCompositionRole> {
        if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_some() {
            if rustix::process::geteuid().as_raw() != ROOT_UID {
                return Err("isolated selector composition child is not root".into());
            }
            return Ok(IsolatedCompositionRole::ExecuteBody);
        }
        run_isolated_test("root_selector::tests::activated_public_composition_authenticates_sly1")?;
        Ok(IsolatedCompositionRole::Delegated)
    }

    fn serve_control_responses(
        listener: &UnixListener,
        fixture: &crate::selector_transport_test_fixture::TransportAdmissionFixture,
        provider: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
    ) -> TestResult {
        let mut stream = accept_test_connection(listener)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))?;
        let mut request = vec![0; length];
        stream.read_exact(&mut request)?;
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing)?;
        if !trailing.is_empty() {
            return Err("describe request contained trailing bytes".into());
        }
        let response = fixture.describe_response_for_provider(&request, provider)?;
        stream.write_all(&u32::try_from(response.len())?.to_be_bytes())?;
        stream.write_all(&response)?;
        stream.shutdown(std::net::Shutdown::Write)?;

        let mut stream = accept_test_connection(listener)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let context = read_frame(&mut stream)?;
        let update = read_frame(&mut stream)?;
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing)?;
        if !trailing.is_empty() {
            return Err("revocation update contained trailing bytes".into());
        }
        let acknowledgement =
            crate::selector::installation::tests::updates::acknowledgement_for_control_frames(
                &context, &update,
            )?;
        write_frame(&mut stream, &acknowledgement)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    fn accept_test_connection(listener: &UnixListener) -> TestResult<UnixStream> {
        listener.set_nonblocking(true)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err("timed out waiting for provider test connection".into());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn read_frame(stream: &mut UnixStream) -> TestResult<Vec<u8>> {
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let mut frame = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        stream.read_exact(&mut frame)?;
        Ok(frame)
    }

    fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> TestResult {
        stream.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
        stream.write_all(frame)?;
        Ok(())
    }

    fn output_descriptor(
        output: &[u8],
    ) -> TestResult<crate::sandbox_provider_protocol::PayloadDescriptor> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.SandboxOutputBytes.v1\0");
        hasher.update(output);
        Ok(crate::sandbox_provider_protocol::PayloadDescriptor {
            byte_length: u64::try_from(output.len())?,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    fn evaluate_composition_request(
        composition: &RootSelectorComposition,
        request: &crate::evaluator_protocol::EvaluationRequest,
        attempt: &crate::evaluator::CaseAttempt,
    ) -> TestResult<(
        crate::selector_protocol::EncodedSelectorRequest,
        crate::selector_protocol::DecodedSelectorReply,
    )> {
        let encoded = encoded_request(request, attempt)?;
        let (mut client, server) = UnixStream::pair()?;
        write_frame(&mut client, &encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        composition.evaluate_root_connection(server)?;
        let control = read_frame(&mut client)?;
        let mut trailing = Vec::new();
        client.read_to_end(&mut trailing)?;
        if let Ok(local) = SandboxLocalError::from_canonical_cbor(&control) {
            return Err(format!("composition returned local selector failure: {local:?}").into());
        }
        let reply = crate::selector_protocol::decode_reply(
            &control,
            &trailing,
            &encoded,
            request.request_digest,
            SELECTOR_INPUT_LIMIT,
        )?;
        Ok((encoded, reply))
    }

    fn serve_execution_responses(
        listener: &UnixListener,
        fixture: &crate::selector_transport_test_fixture::TransportAdmissionFixture,
        provider: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
        commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
        epochs: [u64; 3],
    ) -> TestResult {
        for identity_conflict in [false, true] {
            let mut stream = accept_test_connection(listener)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let spx1 = read_frame(&mut stream)?;
            let mut input_frames = Vec::new();
            stream.read_to_end(&mut input_frames)?;
            if input_frames.is_empty() {
                return Err("provider input frames missing".into());
            }
            let responses = if identity_conflict {
                vec![fixture.request_identity_conflict_for(&spx1)?]
            } else {
                fixture.execution_response_for(provider, &spx1, commitment, epochs)?
            };
            for response in responses {
                write_frame(&mut stream, &response)?;
            }
            stream.shutdown(std::net::Shutdown::Write)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn activated_public_composition_authenticates_sly1() -> TestResult {
        if matches!(
            isolated_composition_role()?,
            IsolatedCompositionRole::Delegated
        ) {
            return Ok(());
        }

        let _paths = FixedCompositionFixture::create()?;
        assert!(RootSelectorComposition::open().is_err());
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let admitted = crate::selector::installation::tests::materialize_root_selector_state(
            Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT),
        )?;
        let update_fixture = crate::selector::installation::tests::updates::UpdateFixture::at(
            Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT),
        )?;
        let control_fixture =
            crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let execute_fixture =
            crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let requirement = request
            .sandbox_requirement
            .as_ref()
            .ok_or("sandbox requirement missing")?;
        let (image, launch) = selected_image_and_launch(&admitted, requirement)?;
        let commitment = admitted.provider().derive_selector_grant_commitment(
            &image,
            &launch,
            &request,
            resolved.attempt(),
            &[],
        )?;
        let epochs = [
            admitted.bootstrap().trust().trust_epoch(),
            admitted.bootstrap().revocation().revocation_epoch() + 1,
            admitted.bootstrap().policy().policy_epoch() + 1,
        ];
        let execute_provider_identity = admitted.provider().clone();

        let execute_listener = UnixListener::bind("/run/pigloros/provider-execute.sock")?;
        fs::set_permissions(
            "/run/pigloros/provider-execute.sock",
            fs::Permissions::from_mode(SOCKET_MODE),
        )?;
        let control_listener = UnixListener::bind("/run/pigloros/provider-control.sock")?;
        fs::set_permissions(
            "/run/pigloros/provider-control.sock",
            fs::Permissions::from_mode(SOCKET_MODE),
        )?;
        let control_provider = std::thread::spawn(move || {
            serve_control_responses(&control_listener, &control_fixture, admitted.provider())
                .map_err(|error| error.to_string())
        });
        let execute_provider = std::thread::spawn(move || {
            serve_execution_responses(
                &execute_listener,
                &execute_fixture,
                &execute_provider_identity,
                &commitment,
                epochs,
            )
            .map_err(|error| error.to_string())
        });
        let composition = RootSelectorComposition::open()?;
        assert!(!Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET).exists());
        assert!(!Path::new(crate::selector::installation::SANDBOX_ADMIN_SOCKET).exists());
        let runtime = RootSelectorRuntime::from_composition(composition)?;
        assert!(Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET).exists());
        assert!(Path::new(crate::selector::installation::SANDBOX_ADMIN_SOCKET).exists());

        let (mut administrator, selector) = UnixStream::pair()?;
        std::thread::scope(|scope| -> TestResult {
            let update = scope.spawn(|| {
                runtime
                    .composition
                    .update_installation(selector)
                    .map_err(|error| error.to_string())
            });
            let challenge = read_frame(&mut administrator)?;
            let siu1 = update_fixture.request_from_challenge(&challenge, None)?;
            write_frame(&mut administrator, &siu1)?;
            administrator.shutdown(std::net::Shutdown::Write)?;
            let acknowledgement = read_frame(&mut administrator)?;
            let mut trailing = Vec::new();
            administrator.read_to_end(&mut trailing)?;
            assert!(!acknowledgement.is_empty());
            assert!(trailing.is_empty());
            update.join().map_err(|_| "selector update panicked")??;
            Ok(())
        })?;

        let (_, reply) =
            evaluate_composition_request(&runtime.composition, &request, resolved.attempt())?;
        assert_eq!(
            reply.observation,
            Ok(crate::evaluator::SubjectObservation {
                result: crate::evaluator::SubjectResult::Unavailable,
                usage: crate::evaluator::ResourceUsage::default(),
            })
        );
        assert!(reply.provenance.is_some());

        let mut conflicting_request = request.clone();
        conflicting_request.implementation.organization_id = Some("conflicting-owner".to_owned());
        refresh_request_digest(&mut conflicting_request)?;
        let (_, reply) = evaluate_composition_request(
            &runtime.composition,
            &conflicting_request,
            resolved.attempt(),
        )?;
        assert_eq!(
            reply.observation,
            Err(crate::evaluator::AdapterError::ProtocolFailure)
        );
        assert_eq!(reply.provenance, None);
        control_provider
            .join()
            .map_err(|_| "provider control thread panicked")??;
        execute_provider
            .join()
            .map_err(|_| "provider execute thread panicked")??;
        drop(runtime);
        assert!(!Path::new(crate::selector::SANDBOX_SELECTOR_SOCKET).exists());
        assert!(!Path::new(crate::selector::installation::SANDBOX_ADMIN_SOCKET).exists());
        Ok(())
    }

    #[test]
    fn provider_connection_requires_two_nonces_and_completed_synchronization() {
        let mut nonces = [[3; 16], [4; 16]].into_iter();
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Ok::<_, ()>(2),
                || nonces.next().ok_or(()),
                |transport, admitted, request_id, challenge| {
                    assert_eq!((*transport, *admitted), (2, 1));
                    assert_eq!((request_id, challenge), ([3; 16], [4; 16]));
                    Ok(())
                },
            ),
            Ok(2)
        );
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Err::<u8, _>(()),
                || Ok([1; 16]),
                |_, _, _, _| { Ok(()) }
            ),
            Err(())
        );

        let mut missing_first = std::iter::empty();
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Ok::<_, ()>(2),
                || missing_first.next().ok_or(()),
                |_, _, _, _| Ok(()),
            ),
            Err(())
        );
        let mut missing_second = std::iter::once([1; 16]);
        assert_eq!(
            connect_and_synchronize(
                &1,
                |_| Ok::<_, ()>(2),
                || missing_second.next().ok_or(()),
                |_, _, _, _| Ok(()),
            ),
            Err(())
        );
        assert_eq!(
            connect_and_synchronize(&1, |_| Ok::<_, ()>(2), || Ok([1; 16]), |_, _, _, _| Err(()),),
            Err(())
        );
    }

    #[test]
    fn closed_helpers_cover_error_mapping_randomness_and_input_bounds() {
        assert_eq!(artifact_invalid(()), SelectorBoundaryError::ArtifactInvalid);
        assert_eq!(
            selector_unavailable(()),
            SelectorBoundaryError::SelectorUnavailable
        );
        assert_eq!(io_error(()), SelectorBoundaryError::Io);
        map_to_unit_error(());
        assert_eq!(checked_staged_input_length(0, 0), Ok(0));
        assert_eq!(framed_control_length(1), Ok(1));
        assert_eq!(
            framed_control_length(usize::MAX),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(checked_staged_input_length(u64::MAX, 1), Err(()));
        assert_eq!(
            checked_staged_input_length(SELECTOR_INPUT_LIMIT, 1),
            Err(())
        );

        let bindings = EvaluationNamespaceBindings::default();
        assert_eq!(
            bindings.release(
                EvaluationNamespaceLease {
                    namespace: [0; 14],
                    request_digest: [0; 32],
                    conflict: true,
                },
                false,
            ),
            Ok(())
        );
        assert_eq!(
            bindings.release(
                EvaluationNamespaceLease {
                    namespace: [0; 14],
                    request_digest: [0; 32],
                    conflict: false,
                },
                false,
            ),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
    }

    #[test]
    fn administrative_framing_requires_one_bounded_frame_and_eof() -> TestResult {
        let mut framed = Vec::new();
        write_control_frame(&mut framed, b"update")?;
        let mut input = std::io::Cursor::new(framed);
        assert_eq!(read_control_frame(&mut input)?, b"update");
        require_stream_eof(&mut input)?;

        assert!(write_control_frame(&mut Vec::new(), &[]).is_err());
        for length in [0, CONTROL_LIMIT + 1] {
            assert!(read_control_frame(&mut std::io::Cursor::new(length.to_be_bytes())).is_err());
        }
        assert!(read_control_frame(&mut std::io::Cursor::new([0, 0, 0, 1])).is_err());
        assert!(require_stream_eof(&mut std::io::Cursor::new([1])).is_err());
        Ok(())
    }

    #[test]
    fn selector_admission_closes_with_one_sorted_live_attempt_snapshot() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let admission = SelectorAdmission::for_test(admitted)?;
        let second = admission.acquire([2; 16])?;
        let first = admission.acquire([1; 16])?;
        let duplicate = admission.acquire([2; 16])?;
        let closed = admission.close_and_snapshot()?;
        assert_eq!(closed.live_attempt_ids, vec![[1; 16], [2; 16]]);
        assert!(admission.current().is_err());
        assert!(admission.acquire([3; 16]).is_err());
        assert!(admission.close_and_snapshot().is_err());

        drop(first);
        drop(second);
        drop(duplicate);
        admission.reopen_previous(&closed.admitted)?;
        assert!(Arc::ptr_eq(&admission.current()?, &closed.admitted));
        assert!(admission.acquire([0; 16]).is_err());
        Ok(())
    }

    #[test]
    fn selector_admission_reopens_only_with_the_exact_successor_transition() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let admission = SelectorAdmission::for_test(admitted)?;
        let closed = admission.close_and_snapshot()?;
        let (_, foreign, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let foreign = Arc::new(foreign);
        assert!(admission.reopen_previous(&foreign).is_err());
        let (_, successor, _) = crate::selector::installation::tests::root_selector_fixture()?;
        admission.admit_successor(&closed.admitted, successor)?;
        assert!(!Arc::ptr_eq(&admission.current()?, &closed.admitted));
        assert!(admission.reopen_previous(&closed.admitted).is_err());
        Ok(())
    }

    #[test]
    fn evaluation_namespace_binding_tracks_only_live_or_retained_requests() -> TestResult {
        let (request, _, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let bindings = EvaluationNamespaceBindings::default();
        let execution =
            bindings.execute_ordered(&request, || Err(ProviderTransportError::BeforeAdmission))?;
        assert!(!execution.conflict);
        assert!(matches!(
            execution.result,
            Err(ProviderTransportError::BeforeAdmission)
        ));

        let mut conflicting = request.clone();
        conflicting.implementation.organization_id = Some("conflicting-owner".to_owned());
        refresh_request_digest(&mut conflicting)?;
        let execution = bindings.execute_ordered(&conflicting, || {
            Err(ProviderTransportError::AfterAdmission {
                agr1_digest: [90; 32],
                failure: PostAdmissionProviderFailure::TerminalUnavailable,
            })
        })?;
        assert!(!execution.conflict);
        let execution = bindings.execute_ordered(&conflicting, || {
            Err(ProviderTransportError::BeforeAdmission)
        })?;
        assert!(!execution.conflict);
        let execution =
            bindings.execute_ordered(&request, || Err(ProviderTransportError::BeforeAdmission))?;
        assert!(execution.conflict);

        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        assert!(!provider_retains_namespace(&Ok(
            AuthenticatedProviderTerminal::Error(fixture.spe1.clone())
        )));
        assert!(provider_retains_namespace(&Ok(
            AuthenticatedProviderTerminal::Error(
                fixture.request_identity_conflict_for(&fixture.spx1)?
            )
        )));
        assert!(provider_retains_namespace(&Ok(
            AuthenticatedProviderTerminal::Error(b"invalid".to_vec())
        )));
        Ok(())
    }

    #[test]
    fn evaluation_namespace_binding_wakes_a_waiting_conflict() -> TestResult {
        let (request, _, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let bindings = std::sync::Arc::new(EvaluationNamespaceBindings::default());
        let lease = bindings.acquire(&request)?;
        let mut next_request = request;
        next_request.implementation.organization_id = Some("next-owner".to_owned());
        refresh_request_digest(&mut next_request)?;

        let waiting_bindings = std::sync::Arc::clone(&bindings);
        let waiter = std::thread::spawn(move || {
            let lease = waiting_bindings.acquire(&next_request)?;
            waiting_bindings.release(lease, false)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while bindings.waiting.load(Ordering::Acquire) == 0 {
            if std::time::Instant::now() >= deadline {
                return Err("namespace waiter did not block".into());
            }
            std::thread::yield_now();
        }
        bindings.release(lease, false)?;
        waiter.join().map_err(|_| "namespace waiter panicked")??;
        Ok(())
    }

    #[test]
    fn poisoned_namespace_state_fails_closed_on_acquire_and_release() -> TestResult {
        let (request, _, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let acquire_bindings = EvaluationNamespaceBindings::default();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = acquire_bindings
                .states
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new(()));
        }))
        .is_err());
        assert!(matches!(
            acquire_bindings.acquire(&request),
            Err(SelectorBoundaryError::SelectorUnavailable)
        ));

        let release_bindings = EvaluationNamespaceBindings::default();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = release_bindings
                .states
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new(()));
        }))
        .is_err());
        let mut namespace = [0; 14];
        namespace.copy_from_slice(&request.request_id[..14]);
        assert_eq!(
            release_bindings.release(
                EvaluationNamespaceLease {
                    namespace,
                    request_digest: request.request_digest,
                    conflict: false,
                },
                false,
            ),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        Ok(())
    }

    #[test]
    fn evaluation_namespace_binding_is_bounded() -> TestResult {
        let (mut request, _, _) = crate::selector::installation::tests::root_selector_fixture()?;
        request.request_id[..14].fill(u8::MAX);
        let states = (0..MAX_RETAINED_EVALUATION_NAMESPACES)
            .map(|index| {
                let mut namespace = [0; 14];
                namespace[..8].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
                Ok((
                    namespace,
                    EvaluationNamespaceState {
                        request_digest: [1; 32],
                        live_requests: 0,
                        retained: true,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
        let bindings = EvaluationNamespaceBindings {
            states: Mutex::new(states),
            changed: Condvar::new(),
            waiting: AtomicUsize::new(0),
        };
        assert!(matches!(
            bindings.execute_ordered(&request, || Err(ProviderTransportError::BeforeAdmission)),
            Err(SelectorBoundaryError::SelectorUnavailable)
        ));
        Ok(())
    }

    struct FixedProviderExecutor(
        RefCell<Option<Result<AuthenticatedProviderTerminal, ProviderTransportError>>>,
    );

    impl ProviderExecutor for FixedProviderExecutor {
        fn execute(
            &self,
            _admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
            _commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
            _spx1: &[u8],
            _input: &mut dyn ReadSeek,
            _watchdog: Duration,
        ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
            self.0
                .borrow_mut()
                .take()
                .ok_or(ProviderTransportError::BeforeAdmission)?
        }
    }

    struct SequencedProviderExecutor(
        Mutex<VecDeque<Result<AuthenticatedProviderTerminal, ProviderTransportError>>>,
    );

    impl ProviderExecutor for SequencedProviderExecutor {
        fn execute(
            &self,
            _admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
            _commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
            _spx1: &[u8],
            _input: &mut dyn ReadSeek,
            _watchdog: Duration,
        ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
            self.0
                .lock()
                .map_err(|_| ProviderTransportError::BeforeAdmission)?
                .pop_front()
                .ok_or(ProviderTransportError::BeforeAdmission)?
        }
    }

    struct OrderedProviderExecutor {
        first_digest: [u8; 32],
        entered: std::sync::mpsc::Sender<[u8; 32]>,
        release_first: std::sync::Arc<(Mutex<bool>, Condvar)>,
    }

    impl ProviderExecutor for OrderedProviderExecutor {
        fn execute(
            &self,
            _admitted: &crate::sandbox_provider_protocol::AdmittedSandboxProvider,
            _commitment: &crate::sandbox_provider_protocol::SelectorGrantCommitment,
            spx1: &[u8],
            _input: &mut dyn ReadSeek,
            _watchdog: Duration,
        ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
            let request = SandboxExecuteRequest::from_canonical_cbor(spx1)
                .map_err(|_| ProviderTransportError::BeforeAdmission)?;
            let digest = request.authority.evr1_digest;
            self.entered
                .send(digest)
                .map_err(|_| ProviderTransportError::BeforeAdmission)?;
            if digest == self.first_digest {
                let (released, changed) = &*self.release_first;
                let mut released = released
                    .lock()
                    .map_err(|_| ProviderTransportError::BeforeAdmission)?;
                while !*released {
                    released = changed
                        .wait(released)
                        .map_err(|_| ProviderTransportError::BeforeAdmission)?;
                }
                drop(released);
                return Err(ProviderTransportError::AfterAdmission {
                    agr1_digest: [93; 32],
                    failure: PostAdmissionProviderFailure::TerminalUnavailable,
                });
            }
            Err(ProviderTransportError::BeforeAdmission)
        }
    }

    #[test]
    fn provider_synchronization_fails_closed_when_host_state_is_lost() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        assert!(connect_fixed_provider(&admitted).is_err());
        let sync_directory = tempfile::tempdir()?;
        let sync_path = sync_directory.path().join("provider-control.sock");
        let sync_listener = UnixListener::bind(&sync_path)?;
        fs::set_permissions(&sync_path, fs::Permissions::from_mode(SOCKET_MODE))?;
        let sync_provider = std::thread::spawn(move || -> std::io::Result<()> {
            let (stream, _) = sync_listener.accept()?;
            drop(stream);
            Ok(())
        });
        let sync_transport = ProviderTransport::from_path_for_test(&sync_path)?;
        assert!(synchronize_fixed_provider(
            &sync_transport,
            &admitted,
            rand::random(),
            rand::random(),
        )
        .is_err());
        sync_provider
            .join()
            .map_err(|_| "provider synchronization thread panicked")??;
        Ok(())
    }

    #[test]
    fn request_reader_covers_the_normal_framed_boundary() -> TestResult {
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&u32::try_from(encoded.control.len())?.to_be_bytes())?;
        client.write_all(&encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        let StagedSelectorRequest { decoded, mut input } =
            read_selector_request(&mut server).map_err(|()| "read failed")?;
        assert_eq!(decoded.request.request_digest, request.request_digest);
        let mut staged = Vec::new();
        input.as_file_mut().seek(SeekFrom::Start(0))?;
        input.as_file_mut().read_to_end(&mut staged)?;
        assert_eq!(staged, encoded.attempt_stream);
        Ok(())
    }

    #[test]
    fn post_admission_provider_failures_retain_the_authenticated_grant(
    ) -> Result<(), crate::evaluator::AdapterError> {
        for code in [
            SandboxLocalErrorCode::ProviderTerminalUnavailable,
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
        ] {
            let error = post_admission_provider_error([1; 16], [2; 16], [3; 32], code);
            assert_eq!(error.phase, SandboxLocalErrorPhase::AfterAdmission);
            assert_eq!(error.operation, Some(SandboxProviderOperation::Execute));
            assert_eq!(error.request_id, Some([1; 16]));
            assert_eq!(error.attempt_id, Some([2; 16]));
            assert_eq!(error.agr1_digest, Some([3; 32]));
            assert_eq!(error.code, code);
            let encoded = encode_local_error_reply(&error)?;
            assert!(encoded.trailing.is_empty());
            assert_eq!(
                SandboxLocalError::from_canonical_cbor(&encoded.control)
                    .map_err(|_| crate::evaluator::AdapterError::ProtocolFailure)?,
                error
            );
        }
        Ok(())
    }

    #[test]
    fn selector_execute_request_binds_every_root_owned_authority() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let requirement = request
            .sandbox_requirement
            .as_ref()
            .ok_or("sandbox requirement missing")?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let decoded = decode_request(&encoded.control, &encoded.attempt_stream)
            .map_err(|error| format!("selector request decode failed: {error:?}"))?;
        let bytes = selector_execute_bytes(&admitted, &decoded, &resolved, requirement)?;
        let execute = SandboxExecuteRequest::from_canonical_cbor(&bytes)?;

        assert_eq!(execute.request.request_id, decoded.provider_request_id);
        assert_eq!(execute.request.apt1_digest, requirement.apt1_digest);
        assert_eq!(execute.request.policy_epoch, requirement.policy_epoch);
        assert_ne!(execute.request.nonce, [0; 16]);
        assert_eq!(execute.attempt_id, decoded.attempt_id);
        assert_eq!(execute.authority.evr1_digest, request.request_digest);
        assert_eq!(execute.authority.cpf1_digest, resolved.profile_digest());
        assert_eq!(execute.authority.cfb1_digest, resolved.bundle_digest());
        assert_eq!(
            execute.authority.fixture_contract_digest,
            resolved.fixture_contract_digest()
        );
        assert_eq!(
            execute.authority.fixture_digest,
            resolved.attempt().fixture_digest
        );
        assert_eq!(
            execute.authority.execution_profile_digest,
            request.execution_profile_digest
        );
        assert_eq!(execute.capability_ids, resolved.attempt().capability_ids);
        assert_eq!(execute.adapter_input, decoded.input_descriptor());
        let selected = selected_image_and_launch(&admitted, requirement)?;
        assert_eq!(
            selected.0.manifest().manifest_digest,
            requirement.sim1_digest
        );
        assert_ne!(fresh_selector_id()?, [0; 16]);

        let mut missing_image = requirement.clone();
        missing_image.sim1_digest = [0; 32];
        assert!(selected_image_and_launch(&admitted, &missing_image).is_err());
        let mut missing_policy = requirement.clone();
        missing_policy.lps1_digest = [0; 32];
        assert!(selected_image_and_launch(&admitted, &missing_policy).is_err());
        Ok(())
    }

    #[test]
    fn selector_service_returns_closed_errors_before_provider_execution() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let provider_directory = tempfile::tempdir()?;
        let provider_path = provider_directory.path().join("provider.sock");
        let provider_listener = UnixListener::bind(&provider_path)?;
        let transport = ProviderTransport::from_path_for_test(&provider_path)?;
        let service = RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport,
            peer_uid: fs::metadata(".")?.uid(),
            evaluation_namespaces: EvaluationNamespaceBindings::default(),
        };

        let mut without_requirement = request.clone();
        without_requirement.sandbox_requirement = None;
        refresh_request_digest(&mut without_requirement)?;
        assert_service_error(
            &service,
            &without_requirement,
            resolved.attempt(),
            SandboxLocalErrorCode::PolicyUnavailable,
        )?;

        let mut foreign_attempt = resolved.attempt().clone();
        foreign_attempt.case_id = "foreign-case".to_owned();
        assert_service_error(
            &service,
            &request,
            &foreign_attempt,
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        )?;

        let mut missing_image = request.clone();
        missing_image
            .sandbox_requirement
            .as_mut()
            .ok_or("sandbox requirement missing")?
            .sim1_digest = [99; 32];
        refresh_request_digest(&mut missing_image)?;
        assert_service_error(
            &service,
            &missing_image,
            resolved.attempt(),
            SandboxLocalErrorCode::PolicyUnavailable,
        )?;

        let mut foreign_capability = request.clone();
        foreign_capability
            .sandbox_requirement
            .as_mut()
            .ok_or("sandbox requirement missing")?
            .required_provider_capability
            .capability_id = "foreign-capability".to_owned();
        refresh_request_digest(&mut foreign_capability)?;
        assert_service_error(
            &service,
            &foreign_capability,
            resolved.attempt(),
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        )?;

        drop(provider_listener);
        assert_service_error(
            &service,
            &request,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderUnavailable,
        )?;
        Ok(())
    }

    #[test]
    fn selector_service_maps_each_provider_transport_failure_class() -> TestResult {
        let cases: [(
            Result<AuthenticatedProviderTerminal, ProviderTransportError>,
            SandboxLocalErrorCode,
        ); 3] = [
            (
                Err(ProviderTransportError::BeforeAdmission),
                SandboxLocalErrorCode::ProviderUnavailable,
            ),
            (
                Err(ProviderTransportError::AfterAdmission {
                    agr1_digest: [91; 32],
                    failure: PostAdmissionProviderFailure::TerminalUnavailable,
                }),
                SandboxLocalErrorCode::ProviderTerminalUnavailable,
            ),
            (
                Err(ProviderTransportError::AfterAdmission {
                    agr1_digest: [92; 32],
                    failure: PostAdmissionProviderFailure::EvidenceInvalid,
                }),
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
            ),
        ];
        for (result, expected) in cases {
            let (request, admitted, resolved) =
                crate::selector::installation::tests::root_selector_fixture()?;
            let service = RootSelectorService {
                admission: SelectorAdmission::for_test(admitted)?,
                transport: FixedProviderExecutor(RefCell::new(Some(result))),
                peer_uid: fs::metadata(".")?.uid(),
                evaluation_namespaces: EvaluationNamespaceBindings::default(),
            };
            assert_service_error(&service, &request, resolved.attempt(), expected)?;
        }
        Ok(())
    }

    #[test]
    fn selector_service_releases_namespace_after_pre_admission_failure() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let mut conflicting = request.clone();
        conflicting.implementation.organization_id = Some("conflicting-owner".to_owned());
        refresh_request_digest(&mut conflicting)?;
        let transport = SequencedProviderExecutor(Mutex::new(VecDeque::from([
            Err(ProviderTransportError::BeforeAdmission),
            Err(ProviderTransportError::AfterAdmission {
                agr1_digest: [94; 32],
                failure: PostAdmissionProviderFailure::TerminalUnavailable,
            }),
        ])));
        let service = RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport,
            peer_uid: fs::metadata(".")?.uid(),
            evaluation_namespaces: EvaluationNamespaceBindings::default(),
        };
        assert_service_error(
            &service,
            &request,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderUnavailable,
        )?;
        assert_service_error(
            &service,
            &conflicting,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderTerminalUnavailable,
        )?;
        Ok(())
    }

    #[test]
    fn selector_service_orders_conflicting_namespaces_before_provider_dispatch() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let mut conflicting = request.clone();
        conflicting.implementation.organization_id = Some("conflicting-owner".to_owned());
        refresh_request_digest(&mut conflicting)?;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release_first = std::sync::Arc::new((Mutex::new(false), Condvar::new()));
        let service = std::sync::Arc::new(RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport: OrderedProviderExecutor {
                first_digest: request.request_digest,
                entered: entered_tx,
                release_first: std::sync::Arc::clone(&release_first),
            },
            peer_uid: fs::metadata(".")?.uid(),
            evaluation_namespaces: EvaluationNamespaceBindings::default(),
        });

        std::thread::scope(|scope| -> TestResult {
            let first_service = std::sync::Arc::clone(&service);
            let first_request = &request;
            let attempt = resolved.attempt();
            let first = scope.spawn(move || {
                assert_service_error(
                    &first_service,
                    first_request,
                    attempt,
                    SandboxLocalErrorCode::ProviderTerminalUnavailable,
                )
                .map_err(|error| error.to_string())
            });
            let first_entered = entered_rx.recv_timeout(Duration::from_secs(1));
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let conflicting_service = std::sync::Arc::clone(&service);
            let conflicting_request = &conflicting;
            let contender = scope.spawn(move || {
                started_tx.send(()).map_err(|error| error.to_string())?;
                assert_service_error(
                    &conflicting_service,
                    conflicting_request,
                    attempt,
                    SandboxLocalErrorCode::ProviderUnavailable,
                )
                .map_err(|error| error.to_string())
            });
            let contender_started = started_rx.recv_timeout(Duration::from_secs(1));
            let overtaking = entered_rx.recv_timeout(Duration::from_millis(100));
            let (released, changed) = &*release_first;
            *released.lock().map_err(|_| "release lock poisoned")? = true;
            changed.notify_all();
            assert_eq!(first_entered?, request.request_digest);
            contender_started?;
            assert!(overtaking.is_err());
            assert_eq!(
                entered_rx.recv_timeout(Duration::from_secs(1))?,
                conflicting.request_digest
            );
            first.join().map_err(|_| "first request panicked")??;
            contender
                .join()
                .map_err(|_| "conflicting request panicked")??;
            Ok(())
        })
    }

    #[test]
    fn namespace_conflict_rejects_provider_admission_as_invalid_evidence() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let evaluation_namespaces = EvaluationNamespaceBindings::default();
        let execution = evaluation_namespaces.execute_ordered(&request, || {
            Err(ProviderTransportError::AfterAdmission {
                agr1_digest: [93; 32],
                failure: PostAdmissionProviderFailure::TerminalUnavailable,
            })
        })?;
        assert!(!execution.conflict);
        let mut conflicting = request;
        conflicting.implementation.organization_id = Some("conflicting-owner".to_owned());
        refresh_request_digest(&mut conflicting)?;
        let service = RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport: FixedProviderExecutor(RefCell::new(Some(Err(
                ProviderTransportError::AfterAdmission {
                    agr1_digest: [94; 32],
                    failure: PostAdmissionProviderFailure::TerminalUnavailable,
                },
            )))),
            peer_uid: fs::metadata(".")?.uid(),
            evaluation_namespaces,
        };
        assert_service_error(
            &service,
            &conflicting,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
        )?;
        Ok(())
    }

    #[test]
    fn selector_service_closes_an_invalid_authenticated_execution() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1,
            fixture.spr1,
            fixture.spy1,
            fixture.sau1,
            None,
        );
        let service = RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport: FixedProviderExecutor(RefCell::new(Some(Ok(
                AuthenticatedProviderTerminal::Execution(execution),
            )))),
            peer_uid: fs::metadata(".")?.uid(),
            evaluation_namespaces: EvaluationNamespaceBindings::default(),
        };
        assert_service_error(
            &service,
            &request,
            resolved.attempt(),
            SandboxLocalErrorCode::ProviderEvidenceInvalid,
        )?;
        Ok(())
    }

    #[test]
    fn selector_service_writes_an_authenticated_provider_error() -> TestResult {
        let (request, admitted, resolved) =
            crate::selector::installation::tests::root_selector_fixture()?;
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let service = RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport: FixedProviderExecutor(RefCell::new(Some(Ok(
                AuthenticatedProviderTerminal::Error(fixture.spe1),
            )))),
            peer_uid: fs::metadata(".")?.uid(),
            evaluation_namespaces: EvaluationNamespaceBindings::default(),
        };
        let encoded = encoded_request(&request, resolved.attempt())?;
        let (mut client, server) = UnixStream::pair()?;
        client.write_all(&u32::try_from(encoded.control.len())?.to_be_bytes())?;
        client.write_all(&encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.handle_connection(server)?;
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix)?;
        let mut control = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        client.read_exact(&mut control)?;
        assert!(!control.is_empty());
        Ok(())
    }

    #[test]
    fn selector_service_closes_unidentified_and_foreign_peer_connections() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let provider_directory = tempfile::tempdir()?;
        let provider_path = provider_directory.path().join("provider.sock");
        let _provider_listener = UnixListener::bind(&provider_path)?;
        let owner = fs::metadata(".")?.uid();
        let mut service = RootSelectorService {
            admission: SelectorAdmission::for_test(admitted)?,
            transport: ProviderTransport::from_path_for_test(&provider_path)?,
            peer_uid: owner ^ 1,
            evaluation_namespaces: EvaluationNamespaceBindings::default(),
        };

        let (client, server) = UnixStream::pair()?;
        service.handle_connection(server)?;
        drop(client);

        service.peer_uid = owner;
        let (mut client, server) = UnixStream::pair()?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.handle_connection(server)?;
        assert_eq!(
            read_local_error(&mut client)?.code,
            SandboxLocalErrorCode::InvalidSelectorRequest
        );
        Ok(())
    }

    #[test]
    fn authenticated_terminal_writers_preserve_result_error_and_output() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let transport_request = SandboxExecuteRequest::from_canonical_cbor(&fixture.spx1)?;
        let decoded = crate::selector_protocol::decoded_request_for_execute_test(
            request,
            resolved.attempt().clone(),
            &transport_request,
        );
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"output")?;
        let descriptor = output_descriptor(b"output")?;
        let mut execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1.clone(),
            fixture.spr1.clone(),
            fixture.spy1.clone(),
            fixture.sau1.clone(),
            Some((file, descriptor)),
        );
        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_authenticated_execution(&mut reply_writer, &decoded, &fixture.spx1, &mut execution)
            .map_err(|()| "authenticated result composition failed")?;
        reply_writer.shutdown(std::net::Shutdown::Write)?;
        assert!(!read_frame(&mut reply_reader)?.is_empty());
        let mut trailing = Vec::new();
        reply_reader.read_to_end(&mut trailing)?;
        assert_eq!(trailing, b"output");

        let mut short_execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1.clone(),
            fixture.spr1.clone(),
            fixture.spy1.clone(),
            fixture.sau1.clone(),
            Some((
                tempfile::NamedTempFile::new()?,
                output_descriptor(b"output")?,
            )),
        );
        let (_, mut short_writer) = UnixStream::pair()?;
        assert!(write_authenticated_execution(
            &mut short_writer,
            &decoded,
            &fixture.spx1,
            &mut short_execution,
        )
        .is_err());

        let mut no_output = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1,
            fixture.spr1,
            fixture.spy1,
            fixture.sau1,
            None,
        );
        let (_, mut no_output_writer) = UnixStream::pair()?;
        assert!(write_authenticated_execution(
            &mut no_output_writer,
            &decoded,
            &fixture.spx1,
            &mut no_output,
        )
        .is_err());

        let (mut root, _) = UnixStream::pair()?;
        assert!(
            write_authenticated_error(&mut root, &decoded, &fixture.spx1, b"unsigned error")
                .is_err()
        );
        let (mut root, mut client) = UnixStream::pair()?;
        write_authenticated_error(&mut root, &decoded, &fixture.spx1, &fixture.spe1)?;
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix)?;
        let mut control = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        client.read_exact(&mut control)?;
        assert!(!control.is_empty());
        Ok(())
    }

    #[test]
    fn provider_terminal_writes_authenticated_execution_and_error() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let transport_request = SandboxExecuteRequest::from_canonical_cbor(&fixture.spx1)?;
        let decoded = crate::selector_protocol::decoded_request_for_execute_test(
            request,
            resolved.attempt().clone(),
            &transport_request,
        );
        let mut staged = tempfile::NamedTempFile::new()?;
        staged.write_all(b"output")?;
        let complete = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1,
            fixture.spr1,
            fixture.spy1,
            fixture.sau1,
            Some((staged, output_descriptor(b"output")?)),
        );
        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Execution(complete),
            false,
        )?;
        let mut length = [0; 4];
        reply_reader.read_exact(&mut length)?;
        assert_ne!(u32::from_be_bytes(length), 0);

        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Error(fixture.spe1),
            false,
        )?;
        reply_reader.read_exact(&mut length)?;
        assert_ne!(u32::from_be_bytes(length), 0);
        Ok(())
    }

    #[test]
    fn namespace_conflict_requires_the_authenticated_provider_rejection() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let required_error = fixture.request_identity_conflict_for(&fixture.spx1)?;
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let transport_request = SandboxExecuteRequest::from_canonical_cbor(&fixture.spx1)?;
        let decoded = crate::selector_protocol::decoded_request_for_execute_test(
            request,
            resolved.attempt().clone(),
            &transport_request,
        );

        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Error(required_error),
            true,
        )?;
        let mut length = [0; 4];
        reply_reader.read_exact(&mut length)?;
        assert_ne!(u32::from_be_bytes(length), 0);

        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Error(fixture.spe1.clone()),
            true,
        )?;
        assert_eq!(
            read_local_error(&mut reply_reader)?.code,
            SandboxLocalErrorCode::ProviderEvidenceInvalid
        );

        let unexpected_execution = AuthenticatedProviderExecution::from_test_frames(
            fixture.agr1,
            fixture.spr1,
            fixture.spy1,
            fixture.sau1,
            None,
        );
        let (mut reply_reader, mut reply_writer) = UnixStream::pair()?;
        write_provider_terminal(
            &mut reply_writer,
            &decoded,
            &fixture.spx1,
            AuthenticatedProviderTerminal::Execution(unexpected_execution),
            true,
        )?;
        let local = read_local_error(&mut reply_reader)?;
        assert_eq!(local.phase, SandboxLocalErrorPhase::AfterAdmission);
        assert_eq!(local.code, SandboxLocalErrorCode::ProviderEvidenceInvalid);
        Ok(())
    }

    #[test]
    fn local_error_writers_preserve_each_failure_phase() -> TestResult {
        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let decoded = decode_request(&encoded.control, &encoded.attempt_stream)
            .map_err(|error| format!("selector request decode failed: {error:?}"))?;

        assert_written_error(
            write_unidentified_request_error,
            SandboxLocalErrorCode::InvalidSelectorRequest,
        )?;
        assert_written_error(
            |stream| write_policy_error(stream, &decoded),
            SandboxLocalErrorCode::PolicyUnavailable,
        )?;
        assert_written_error(
            |stream| write_authority_mismatch(stream, &decoded),
            SandboxLocalErrorCode::RequestAuthorityMismatch,
        )?;
        assert_written_error(
            |stream| write_provider_unavailable(stream, &decoded),
            SandboxLocalErrorCode::ProviderUnavailable,
        )?;
        for (failure, code) in [
            (
                PostAdmissionProviderFailure::TerminalUnavailable,
                SandboxLocalErrorCode::ProviderTerminalUnavailable,
            ),
            (
                PostAdmissionProviderFailure::EvidenceInvalid,
                SandboxLocalErrorCode::ProviderEvidenceInvalid,
            ),
        ] {
            assert_written_error(
                |stream| write_post_admission_provider_failure(stream, &decoded, [91; 32], failure),
                code,
            )?;
        }
        Ok(())
    }

    #[test]
    fn selector_request_reader_rejects_invalid_frame_boundaries() -> TestResult {
        for prefix in [0_u32, CONTROL_LIMIT + 1] {
            let (mut client, mut server) = UnixStream::pair()?;
            client.write_all(&prefix.to_be_bytes())?;
            client.shutdown(std::net::Shutdown::Write)?;
            assert!(read_selector_request(&mut server).is_err());
        }
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&4_u32.to_be_bytes())?;
        client.write_all(&[1, 2])?;
        client.shutdown(std::net::Shutdown::Write)?;
        assert!(read_selector_request(&mut server).is_err());

        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&1_u32.to_be_bytes())?;
        client.write_all(&[0xff])?;
        client.shutdown(std::net::Shutdown::Write)?;
        assert!(read_selector_request(&mut server).is_err());

        let (request, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let encoded = encoded_request(&request, resolved.attempt())?;
        let mut framed = u32::try_from(encoded.control.len())?.to_be_bytes().to_vec();
        framed.extend_from_slice(&encoded.control);
        let mut failing_input = std::io::Cursor::new(framed).chain(FailingReader);
        assert!(read_selector_request(&mut failing_input).is_err());
        Ok(())
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected input read failure"))
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected input write failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct NthFailWriter {
        writes: usize,
        fail_at: usize,
    }

    impl Write for NthFailWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes == self.fail_at {
                Err(std::io::Error::other("injected reply write failure"))
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn selector_input_staging_covers_success_and_io_failures() {
        assert!(stage_selector_input(&mut FailingReader, &mut Vec::new()).is_err());
        assert!(
            stage_selector_input(&mut std::io::Cursor::new(b"input"), &mut FailingWriter,).is_err()
        );
        let mut staged = Vec::new();
        assert_eq!(
            stage_selector_input(&mut std::io::Cursor::new(b"input"), &mut staged)
                .map(|(length, _)| length),
            Ok(5)
        );
        assert_eq!(staged, b"input");
    }

    #[test]
    fn reply_writers_close_each_output_boundary() {
        let reply = EncodedSelectorReply {
            control: b"control".to_vec(),
            trailing: b"trailing".to_vec(),
        };
        for fail_at in 1..=3 {
            let mut writer = NthFailWriter { writes: 0, fail_at };
            assert_eq!(
                write_reply(&mut writer, &reply),
                Err(SelectorBoundaryError::Io)
            );
        }
        for fail_at in 1..=3 {
            let mut writer = NthFailWriter { writes: 0, fail_at };
            assert_eq!(
                write_reply_with_trailing(
                    &mut writer,
                    &reply,
                    &mut std::io::Cursor::new(b"output"),
                    6,
                ),
                Err(SelectorBoundaryError::Io)
            );
        }

        let mut exact = Vec::new();
        assert_eq!(
            write_reply_with_trailing(&mut exact, &reply, &mut std::io::Cursor::new(b"output"), 6,),
            Ok(())
        );
        assert_eq!(&exact[4 + reply.control.len()..], b"output");
        assert_eq!(
            write_reply_with_trailing(
                &mut Vec::new(),
                &reply,
                &mut std::io::Cursor::new(b"short"),
                6,
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            write_reply_with_trailing(
                &mut Vec::new(),
                &reply,
                &mut std::io::Cursor::new(b"output"),
                5,
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );

        let oversized = EncodedSelectorReply {
            control: vec![0; CONTROL_LIMIT_BYTES + 1],
            trailing: Vec::new(),
        };
        assert_eq!(
            write_reply(&mut Vec::new(), &oversized),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            write_reply_with_trailing(&mut Vec::new(), &oversized, &mut std::io::empty(), 0,),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
    }

    #[test]
    fn peer_identity_uses_the_explicit_service_owner() -> TestResult {
        let (peer, _) = UnixStream::pair()?;
        let owner = fs::metadata(".")?.uid();
        assert!(root_peer(&peer, owner));
        assert!(!root_peer(&peer, owner ^ 1));
        Ok(())
    }

    fn encoded_request(
        request: &crate::evaluator_protocol::EvaluationRequest,
        attempt: &crate::evaluator::CaseAttempt,
    ) -> TestResult<crate::selector_protocol::EncodedSelectorRequest> {
        let request_bytes = request.to_canonical_cbor()?;
        crate::selector_protocol::encode_request(request, &request_bytes, attempt, 0)
            .map_err(|error| format!("selector request encode failed: {error:?}").into())
    }

    fn refresh_request_digest(
        request: &mut crate::evaluator_protocol::EvaluationRequest,
    ) -> TestResult {
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
        Ok(())
    }

    fn assert_service_error<T: ProviderExecutor>(
        service: &RootSelectorService<T>,
        request: &crate::evaluator_protocol::EvaluationRequest,
        attempt: &crate::evaluator::CaseAttempt,
        expected: SandboxLocalErrorCode,
    ) -> TestResult {
        let encoded = encoded_request(request, attempt)?;
        let (mut client, server) = UnixStream::pair()?;
        let control_length = u32::try_from(encoded.control.len())?;
        client.write_all(&control_length.to_be_bytes())?;
        client.write_all(&encoded.control)?;
        client.write_all(&encoded.attempt_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        service.handle_connection(server)?;
        let error = read_local_error(&mut client)?;
        assert_eq!(error.code, expected);
        if expected == SandboxLocalErrorCode::PolicyUnavailable {
            assert_eq!(error.request_id, Some(encoded.provider_request_id));
            assert_eq!(error.attempt_id, Some(encoded.attempt_id));
        }
        Ok(())
    }

    fn assert_written_error(
        write: impl FnOnce(&mut UnixStream) -> Result<(), SelectorBoundaryError>,
        expected: SandboxLocalErrorCode,
    ) -> TestResult {
        let (mut root, mut client) = UnixStream::pair()?;
        write(&mut root)?;
        let error = read_local_error(&mut client)?;
        assert_eq!(error.code, expected);
        if expected == SandboxLocalErrorCode::PolicyUnavailable {
            assert!(error.request_id.is_some());
            assert!(error.attempt_id.is_some());
        }
        Ok(())
    }

    fn read_local_error(stream: &mut UnixStream) -> TestResult<SandboxLocalError> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))?;
        let mut control = vec![0_u8; length];
        stream.read_exact(&mut control)?;
        SandboxLocalError::from_canonical_cbor(&control).map_err(Into::into)
    }
}
