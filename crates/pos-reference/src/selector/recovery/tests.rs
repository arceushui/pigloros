//! Root-owned recovery through its public seams (ADR-069 R12 §11).

use std::fs::File;

use super::*;
use crate::selector::installation::tests::updates::{SuccessorRevocation, UpdateFixture};
use crate::selector::installation::FixedInstallation;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn pending_target(fixture: &UpdateFixture) -> TestResult<PendingRecoveryTarget> {
    match InstalledSelectorState::open_fixed_at_for_test(&File::open(fixture.path())?)? {
        FixedInstallation::RecoveryPending(installed) => {
            Ok(PendingRecoveryTarget::load(&installed)?)
        }
        FixedInstallation::Admissible(_) => Err("no SIR1 is pending".into()),
    }
}

#[test]
fn a_reloaded_target_names_the_same_transaction() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let (committed, request) = fixture.commit_pending_update(
        vec![[41; 16], [42; 16]],
        vec![[42; 16]],
        SuccessorRevocation::Nothing,
    )?;
    let first = pending_target(&fixture)?;
    let second = pending_target(&fixture)?;
    assert_eq!(first.identity(), second.identity());
    assert_eq!(first.identity().sir1_digest, committed.sir1_digest());
    assert_eq!(
        first.identity().previous_provider_binding_digest,
        committed
            .cancellation_context()?
            .previous_provider_binding_digest
    );
    assert_eq!(
        first.identity().previous_live_attempt_ids,
        vec![[41; 16], [42; 16]]
    );
    assert_eq!(first.pending_update_bytes(), request);
    Ok(())
}

#[test]
fn identity_equality_compares_every_element() -> TestResult {
    let fixture = UpdateFixture::new()?;
    fixture.commit_pending_update(vec![[41; 16]], vec![[41; 16]], SuccessorRevocation::Nothing)?;
    let reference = pending_target(&fixture)?.identity;
    let mutations: [fn(&mut RecoveryTransactionIdentity); 6] = [
        |identity| identity.sir1_digest[0] ^= 1,
        |identity| identity.previous_provider_binding_digest[0] ^= 1,
        |identity| identity.previous_runtime_instance_id[0] ^= 1,
        |identity| identity.previous_lifecycle_scope_id[0] ^= 1,
        |identity| identity.previous_live_attempt_ids.push([99; 16]),
        |identity| identity.recovery_peer_slot[2][0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = pending_target(&fixture)?.identity;
        assert_eq!(changed, reference);
        mutate(&mut changed);
        assert_ne!(changed, reference);
    }
    Ok(())
}

#[test]
fn the_mode_one_challenge_names_the_pending_transaction() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let (_committed, request) =
        fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
    let target = pending_target(&fixture)?;
    let challenge =
        crate::evaluator_protocol::decode_canonical(&target.challenge().to_canonical_cbor()?)?;
    let fields = crate::evaluator_protocol::array(&challenge, 5)?;
    let update = crate::evaluator_protocol::decode_canonical(&request)?;
    let update_fields = crate::evaluator_protocol::array(&update, 5)?;
    assert_eq!(fields[0], ciborium::value::Value::Text("SICN1".to_owned()));
    assert_eq!(fields[2], update_fields[2]);
    assert_eq!(crate::evaluator_protocol::uint(&fields[4])?, 1);
    let ciborium::value::Value::Bytes(rcu1) = &update_fields[4] else {
        return Err("SIU1 RCU1 is not bytes".into());
    };
    let rcu1 = crate::evaluator_protocol::decode_canonical(rcu1)?;
    let rcu1_fields =
        crate::evaluator_protocol::array(&crate::evaluator_protocol::array(&rcu1, 3)?[0], 8)?;
    assert_eq!(fields[3], rcu1_fields[6]);
    Ok(())
}

#[test]
fn recovery_errors_close_as_boundary_errors() {
    assert_eq!(
        SelectorBoundaryError::from(RecoveryError::from(SelectorBoundaryError::Io)),
        SelectorBoundaryError::Io
    );
    assert_eq!(
        SelectorBoundaryError::from(RecoveryError::EvaluatorEndpointPresent),
        SelectorBoundaryError::ArtifactInvalid
    );
}

#[test]
fn any_node_at_the_evaluator_endpoint_stops_recovery_and_is_kept() -> TestResult {
    let directory = tempfile::tempdir()?;
    let endpoint = directory.path().join("sandbox-provider.sock");
    require_absent_evaluator_endpoint(&endpoint)?;

    drop(std::os::unix::net::UnixListener::bind(&endpoint)?);
    assert_eq!(
        require_absent_evaluator_endpoint(&endpoint),
        Err(RecoveryError::EvaluatorEndpointPresent)
    );
    assert!(endpoint.exists());
    std::fs::remove_file(&endpoint)?;

    std::os::unix::fs::symlink("missing-target", &endpoint)?;
    assert_eq!(
        require_absent_evaluator_endpoint(&endpoint),
        Err(RecoveryError::EvaluatorEndpointPresent)
    );
    assert!(std::fs::symlink_metadata(&endpoint).is_ok());

    // A parent that is not a directory cannot be inspected.
    let file = directory.path().join("file");
    std::fs::write(&file, b"")?;
    assert_eq!(
        require_absent_evaluator_endpoint(&file.join("sandbox-provider.sock")),
        Err(RecoveryError::Boundary(SelectorBoundaryError::Io))
    );
    Ok(())
}

// --- The recovery operation (ADR-069 R12 §6, I3 to I11) ---

use std::io::{Read as _, Write as _};
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::control_framing;
use crate::selector::installation::tests::updates::acknowledgement_for_control_frames;
use crate::selector::runtime_lifecycle::{CgroupPath, ObservationChallenge};

const FRAME_LIMIT: usize = 16 * 1024 * 1024;

/// One port call and the deadline it was given.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Call {
    Terminate(Instant),
    Reconcile(Instant),
    Start(Instant),
}

/// How the fake adapter answers one operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Reply {
    /// An honest observation.
    #[default]
    Echo,
    /// Another challenge.
    WrongChallenge,
    /// Another lifecycle scope.
    WrongScope,
    /// This port error.
    Refuse(ProviderLifecycleError),
    /// Reconciled attempts out of canonical order.
    Unsorted,
    /// A reconciled attempt twice.
    Duplicated,
    /// A reconciled attempt outside the previous-live set.
    Foreign,
    /// A control group that is not the started peer's.
    OtherCgroup,
    /// Another main PID.
    OtherPid,
    /// Other start ticks.
    OtherTicks,
    /// Bind and close the leaf, then unwind.
    Panic,
}

/// What the in-process recovery peer does with its one connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Peer {
    /// A valid RCA1, then server EOF.
    #[default]
    Acknowledges,
    /// A frame that is no RCA1.
    Garbage,
    /// A valid RCA1 with one byte changed.
    Tampered,
    /// A valid RCA1 followed by another frame.
    ExtraFrame,
    /// No frame at all.
    ClosesEarly,
    /// A valid RCA1, but no server EOF before the deadline.
    HoldsOpen,
    /// The selector's clock passes the 100 ms deadline once the peer has
    /// the request; then a valid RCA1.
    Late,
    /// No listener on the leaf: the peer is not ready.
    NotListening,
}

/// One scripted fake adapter.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Script {
    pub(crate) terminate: Reply,
    /// The reply of each slot reconciliation, from the first.
    pub(crate) reconcile: [Reply; 2],
    pub(crate) start: Reply,
    pub(crate) peer: Peer,
    /// How far the selector's clock advances, in milliseconds, during the
    /// termination of the previous runtime.
    pub(crate) terminate_advance_ms: u64,
    /// How far it advances during each slot reconciliation.
    pub(crate) reconcile_advance_ms: [u64; 2],
    /// The recent-activation wait the termination reports, in milliseconds.
    pub(crate) activation_wait_ms: u64,
    /// How many first terminations are refused before `terminate` applies.
    pub(crate) refused_terminations: usize,
}

/// A fake lifecycle adapter whose recovery peer is a thread of this process
/// listening on the recovery leaf of `directory`.
pub(crate) struct PeerPort {
    directory: PathBuf,
    script: Script,
    clock: Arc<AtomicU64>,
    base: Instant,
    calls: Mutex<Vec<Call>>,
    peer: Mutex<Option<(PathBuf, JoinHandle<()>)>>,
    reconciles: AtomicUsize,
    terminations: AtomicUsize,
}

impl PeerPort {
    pub(crate) fn new(directory: &Path, script: Script) -> Self {
        Self {
            directory: directory.to_path_buf(),
            script,
            clock: Arc::new(AtomicU64::new(0)),
            base: Instant::now(),
            calls: Mutex::new(Vec::new()),
            peer: Mutex::new(None),
            reconciles: AtomicUsize::new(0),
            terminations: AtomicUsize::new(0),
        }
    }

    /// The selector clock this port can advance: frozen at the port's
    /// creation plus every advance.
    pub(crate) fn clock(&self) -> RecoveryClockFn {
        let offset = Arc::clone(&self.clock);
        let base = self.base;
        Arc::new(move || base + Duration::from_millis(offset.load(Ordering::SeqCst)))
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }

    fn record(&self, call: Call) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }

    /// The peer has ended, as a stopped unit's process has.
    fn stop_peer(&self) {
        let peer = self.peer.lock().ok().and_then(|mut peer| peer.take());
        if let Some((leaf, thread)) = peer {
            // A peer still waiting for its connection gets one and exits.
            drop(UnixStream::connect(&leaf));
            drop(thread.join());
        }
    }
}

pub(crate) type RecoveryClockFn = Arc<dyn Fn() -> Instant + Send + Sync>;

fn own_pid() -> NonZeroU64 {
    NonZeroU64::new(u64::from(std::process::id())).unwrap_or(NonZeroU64::MIN)
}

fn own_cgroup() -> Result<CgroupPath, ProviderLifecycleError> {
    crate::selector::runtime_lifecycle::process_control_group(own_pid())
        .map_err(|_| ProviderLifecycleError::Contradiction)
        .and_then(|cgroup| CgroupPath::new(&cgroup))
}

const fn challenge_of(reply: Reply, challenge: ObservationChallenge) -> ObservationChallenge {
    match reply {
        Reply::WrongChallenge => ObservationChallenge::for_test([0xee; 16]),
        _ => challenge,
    }
}

const fn scope_of(reply: Reply, scope: [u8; 16]) -> [u8; 16] {
    match reply {
        Reply::WrongScope => [0xee; 16],
        _ => scope,
    }
}

impl ProviderLifecyclePort for PeerPort {
    fn terminate_stale_runtimes(
        &self,
        _challenge: ObservationChallenge,
        _deadline: Instant,
    ) -> Result<crate::selector::runtime_lifecycle::StaleUnitsObservation, ProviderLifecycleError>
    {
        Err(ProviderLifecycleError::Unavailable)
    }

    fn start_provider_runtime(
        &self,
        _slot: &crate::selector::runtime_lifecycle::RuntimeSlotTarget<'_>,
        _deadline: Instant,
    ) -> Result<crate::selector::runtime_lifecycle::StartedRuntimeObservation, ProviderLifecycleError>
    {
        Err(ProviderLifecycleError::Unavailable)
    }

    fn terminate_previous_runtime(
        &self,
        target: &PreviousRuntimeTarget<'_>,
        deadline: Instant,
    ) -> Result<PreviousRuntimeObservation, ProviderLifecycleError> {
        self.record(Call::Terminate(deadline));
        if self.terminations.fetch_add(1, Ordering::SeqCst) < self.script.refused_terminations {
            return Err(ProviderLifecycleError::Unavailable);
        }
        // A new operation: its first slot reconciliation comes next.
        self.reconciles.store(0, Ordering::SeqCst);
        self.clock
            .fetch_add(self.script.terminate_advance_ms, Ordering::SeqCst);
        let reply = self.script.terminate;
        if let Reply::Refuse(error) = reply {
            return Err(error);
        }
        let mut reconciled = target.previous_live_attempt_ids().to_vec();
        match reply {
            Reply::Unsorted => reconciled.reverse(),
            Reply::Duplicated => reconciled.push(reconciled[0]),
            Reply::Foreign => reconciled.push([0xff; 16]),
            _ => {}
        }
        Ok(PreviousRuntimeObservation::new(
            challenge_of(reply, target.challenge()),
            scope_of(reply, target.lifecycle_scope_id()),
            CgroupPath::new("/system.slice/previous.service")?,
            reconciled,
            Duration::from_millis(self.script.activation_wait_ms),
        ))
    }

    fn reconcile_recovery_slot(
        &self,
        target: &RecoverySlotTarget<'_>,
        deadline: Instant,
    ) -> Result<RecoverySlotObservation, ProviderLifecycleError> {
        self.record(Call::Reconcile(deadline));
        self.stop_peer();
        let index = self.reconciles.fetch_add(1, Ordering::SeqCst);
        self.clock.fetch_add(
            self.script.reconcile_advance_ms[index.min(1)],
            Ordering::SeqCst,
        );
        let reply = self.script.reconcile[index.min(1)];
        if let Reply::Refuse(error) = reply {
            return Err(error);
        }
        let control_group = if reply == Reply::OtherCgroup {
            CgroupPath::new("/system.slice/other.service")?
        } else {
            own_cgroup()?
        };
        Ok(RecoverySlotObservation::new(
            challenge_of(reply, target.challenge()),
            scope_of(reply, target.recovery_lifecycle_scope_id()),
            control_group,
        ))
    }

    fn start_recovery_peer(
        &self,
        launch: &RecoveryPeerLaunch<'_>,
        deadline: Instant,
    ) -> Result<RecoveryPeerObservation, ProviderLifecycleError> {
        self.record(Call::Start(deadline));
        let reply = self.script.start;
        if let Reply::Refuse(error) = reply {
            return Err(error);
        }
        let leaf = self
            .directory
            .join(format!("{}.sock", hex(&launch.recovery_endpoint_id())));
        let listener = bind_leaf(&leaf)?;
        if reply == Reply::Panic {
            drop(listener);
            std::panic::resume_unwind(Box::new("injected unwinding after the peer start"));
        }
        if self.script.peer == Peer::NotListening {
            drop(listener);
        } else {
            let behaviour = self.script.peer;
            let clock = Arc::clone(&self.clock);
            let thread = std::thread::spawn(move || serve_peer(&listener, behaviour, &clock));
            let locked = self.peer.lock();
            if let Ok(mut peer) = locked {
                *peer = Some((leaf, thread));
            }
        }
        let ticks = crate::selector::runtime_lifecycle::process_start_time_ticks(own_pid())?;
        let (pid, ticks) = match reply {
            Reply::OtherPid => (NonZeroU64::MIN, ticks),
            Reply::OtherTicks => (own_pid(), ticks + 1),
            _ => (own_pid(), ticks),
        };
        let control_group = if reply == Reply::OtherCgroup {
            CgroupPath::new("/system.slice/other.service")?
        } else {
            own_cgroup()?
        };
        Ok(RecoveryPeerObservation::new(
            challenge_of(reply, launch.challenge()),
            scope_of(reply, launch.slot().recovery_lifecycle_scope_id()),
            pid,
            ticks,
            control_group,
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _written = write!(hex, "{byte:02x}");
        hex
    })
}

/// Bind the leaf as the peer does: `listen()` itself, then mode `0600`.
fn bind_leaf(leaf: &Path) -> Result<UnixListener, ProviderLifecycleError> {
    UnixListener::bind(leaf)
        .and_then(|listener| {
            std::fs::set_permissions(leaf, std::fs::Permissions::from_mode(0o600))
                .map(|()| listener)
        })
        .map_err(|_| ProviderLifecycleError::Unavailable)
}

/// The peer's one connection: RCC1, RCU1 and client EOF, then the reply
/// `behaviour` asks for.
fn serve_peer(listener: &UnixListener, behaviour: Peer, clock: &AtomicU64) {
    let Ok((mut stream, _)) = listener.accept() else {
        return;
    };
    let context = control_framing::read_frame(&mut stream, FRAME_LIMIT)
        .ok()
        .flatten();
    let update = control_framing::read_frame(&mut stream, FRAME_LIMIT)
        .ok()
        .flatten();
    let (Some(context), Some(update)) = (context, update) else {
        return;
    };
    let Ok(mut acknowledgement) = acknowledgement_for_control_frames(&context, &update) else {
        return;
    };
    match behaviour {
        Peer::Garbage => acknowledgement = b"not an RCA1".to_vec(),
        Peer::Tampered => {
            let last = acknowledgement.len() - 1;
            acknowledgement[last] ^= 1;
        }
        Peer::ClosesEarly => return,
        Peer::Late => {
            clock.fetch_add(1_000, Ordering::SeqCst);
        }
        _ => {}
    }
    let _sent = control_framing::write_frame(&mut stream, &acknowledgement, FRAME_LIMIT);
    match behaviour {
        Peer::ExtraFrame => {
            let _extra = control_framing::write_frame(&mut stream, &acknowledgement, FRAME_LIMIT);
        }
        Peer::HoldsOpen => std::thread::sleep(Duration::from_millis(400)),
        _ => {}
    }
    drop(stream.shutdown(std::net::Shutdown::Write));
}

/// The digest of the recovery peer's executable: the fixture's provider
/// binary, for this test process only.
pub(crate) fn peer_executable_digest(
    pid: NonZeroU64,
    _length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    if pid == own_pid() {
        Ok(*blake3::hash(b"exact provider binary").as_bytes())
    } else {
        Err(SelectorBoundaryError::ArtifactInvalid)
    }
}

fn other_executable_digest(
    pid: NonZeroU64,
    length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    peer_executable_digest(pid, length).map(|_| [7; 32])
}

/// One recovery operation's environment: the installation with a pending
/// SIR1, a private recovery directory and an empty cgroup2 stand-in.
struct Operation {
    fixture: UpdateFixture,
    request: Vec<u8>,
    recovery: tempfile::TempDir,
    cgroups: tempfile::TempDir,
}

impl Operation {
    fn new(previous_live: Vec<[u8; 16]>, revocation: SuccessorRevocation) -> TestResult<Self> {
        Self::of((100, 200), previous_live, revocation)
    }

    fn of(
        process: (u64, u64),
        previous_live: Vec<[u8; 16]>,
        revocation: SuccessorRevocation,
    ) -> TestResult<Self> {
        let fixture = UpdateFixture::new()?;
        let required = previous_live.clone();
        let (_committed, request) =
            fixture.commit_pending_update_of(process, previous_live, required, revocation)?;
        let recovery = tempfile::tempdir()?;
        std::fs::set_permissions(recovery.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            fixture,
            request,
            recovery,
            cgroups: tempfile::tempdir()?,
        })
    }

    fn port(&self, script: Script) -> Arc<PeerPort> {
        Arc::new(PeerPort::new(self.recovery.path(), script))
    }

    fn host(&self, port: &PeerPort, digest: ExecutableDigestFn) -> TestResult<RecoveryHost> {
        Ok(RecoveryHost::for_test(
            Arc::new(File::open(self.recovery.path())?),
            std::fs::metadata(self.recovery.path())?.uid(),
            (self.cgroups.path().to_path_buf(), |_| true),
            digest,
            port.clock(),
        ))
    }

    fn standard_host(&self, port: &PeerPort) -> TestResult<RecoveryHost> {
        test_host(self.recovery.path(), self.cgroups.path(), port.clock())
    }

    fn authority(
        &self,
        port: &Arc<PeerPort>,
    ) -> TestResult<ProviderTerminationAuthority<PeerPort>> {
        Ok(ProviderTerminationAuthority::new(
            Arc::clone(port),
            self.standard_host(port)?,
        ))
    }

    fn target(&self) -> TestResult<PendingRecoveryTarget> {
        pending_target(&self.fixture)
    }

    fn sir1(&self) -> PathBuf {
        self.fixture.path().join("installation-update.cbor")
    }

    fn leaves(&self) -> TestResult<usize> {
        Ok(std::fs::read_dir(self.recovery.path())?.count())
    }
}

type ExecutableDigestFn = fn(NonZeroU64, u64) -> Result<[u8; 32], SelectorBoundaryError>;

/// A recovery host over `recovery` (owned by this process) and the cgroup2
/// stand-in `cgroups`, which holds no control group, on `clock`.
pub(crate) fn test_host(
    recovery: &Path,
    cgroups: &Path,
    clock: RecoveryClockFn,
) -> TestResult<RecoveryHost> {
    Ok(RecoveryHost::for_test(
        Arc::new(File::open(recovery)?),
        std::fs::metadata(recovery)?.uid(),
        (cgroups.to_path_buf(), |_| true),
        peer_executable_digest,
        clock,
    ))
}

use std::os::unix::fs::MetadataExt as _;

/// Runs one whole operation under `script`.
fn recover(
    operation: &Operation,
    script: Script,
) -> TestResult<(Result<CompletedRecovery, RecoveryError>, Arc<PeerPort>)> {
    let port = operation.port(script);
    let authority = operation.authority(&port)?;
    let result = authority.recover(operation.target()?);
    Ok((result, port))
}

fn starts(calls: &[Call]) -> usize {
    calls
        .iter()
        .filter(|call| matches!(call, Call::Start(_)))
        .count()
}

#[test]
fn one_operation_terminates_exchanges_cleans_and_publishes_the_successor() -> TestResult {
    let operation = Operation::new(vec![[41; 16], [42; 16]], SuccessorRevocation::Nothing)?;
    let next = operation.target()?;
    let (result, port) = recover(&operation, Script::default())?;
    let completed = result?;
    // Steps 1, 4, 7 and 12, each under its bound on the selector's clock.
    let base = port.base;
    assert_eq!(
        port.calls(),
        vec![
            Call::Terminate(base + Duration::from_secs(10)),
            Call::Reconcile(base + Duration::from_secs(5)),
            Call::Start(base + Duration::from_secs(5)),
            Call::Reconcile(base + Duration::from_secs(5)),
        ]
    );
    // Steps 16 and 17: SIR1 is gone and the next SIC1 is current.
    assert!(!operation.sir1().exists());
    assert_eq!(operation.leaves()?, 0);
    assert_ne!(
        completed.bootstrap.installed().manifest().digest(),
        next.previous_installation_digest
    );
    // The exact RCA1 the peer sent authenticates for the pending transaction.
    let acknowledgement = next.authenticate_recovery_acknowledgement(&completed.acknowledgement)?;
    assert_eq!(
        acknowledgement.cancelled_attempt_ids(),
        [[41; 16], [42; 16]]
    );
    // A second operation on the completed transaction finds no SIR1.
    assert!(operation.target().is_err());
    Ok(())
}

#[test]
fn a_revoked_runtime_key_still_acknowledges_and_a_published_successor_is_verified() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::RuntimeKey)?;
    // Crash row 7: the next SIC1 is already current; SIR1 is still pending.
    publish_next(&operation)?;
    let (result, _port) = recover(&operation, Script::default())?;
    result?;
    assert!(!operation.sir1().exists());
    Ok(())
}

#[test]
fn forged_previous_runtime_observations_mint_no_proof() -> TestResult {
    let operation = Operation::new(vec![[41; 16], [42; 16]], SuccessorRevocation::Nothing)?;
    for (reply, expected) in [
        (Reply::WrongChallenge, RecoveryError::Observation),
        (Reply::WrongScope, RecoveryError::Observation),
        (Reply::Unsorted, RecoveryError::Observation),
        (Reply::Duplicated, RecoveryError::Observation),
        (Reply::Foreign, RecoveryError::Observation),
        (
            Reply::Refuse(ProviderLifecycleError::Unavailable),
            RecoveryError::Lifecycle(ProviderLifecycleError::Unavailable),
        ),
        (
            Reply::Refuse(ProviderLifecycleError::ResidualResource),
            RecoveryError::Lifecycle(ProviderLifecycleError::ResidualResource),
        ),
        (
            Reply::Refuse(ProviderLifecycleError::ForeignResource),
            RecoveryError::Lifecycle(ProviderLifecycleError::ForeignResource),
        ),
        (
            Reply::Refuse(ProviderLifecycleError::Contradiction),
            RecoveryError::Lifecycle(ProviderLifecycleError::Contradiction),
        ),
        (
            Reply::Refuse(ProviderLifecycleError::DeadlineExceeded),
            RecoveryError::Lifecycle(ProviderLifecycleError::DeadlineExceeded),
        ),
    ] {
        let port = operation.port(Script {
            terminate: reply,
            ..Script::default()
        });
        let authority = operation.authority(&port)?;
        let target = operation.target()?;
        assert_eq!(
            authority.terminate_previous_runtime(&target).err(),
            Some(expected),
            "{reply:?}"
        );
        assert_eq!(port.calls().len(), 1, "{reply:?}");
    }
    // The slot reconciliation's observation is checked the same way.
    for reply in [Reply::WrongChallenge, Reply::WrongScope] {
        let port = operation.port(Script {
            reconcile: [reply, Reply::Echo],
            ..Script::default()
        });
        let target = operation.target()?;
        assert_eq!(
            operation
                .authority(&port)?
                .terminate_previous_runtime(&target)
                .err(),
            Some(RecoveryError::Observation)
        );
    }
    assert!(operation.sir1().exists());
    Ok(())
}

#[test]
fn a_live_previous_process_fails_closed_and_a_recycled_pid_does_not() -> TestResult {
    let pid = own_pid();
    let ticks = crate::selector::runtime_lifecycle::process_start_time_ticks(pid)?;
    let alive = Operation::of((pid.get(), ticks), Vec::new(), SuccessorRevocation::Nothing)?;
    let port = alive.port(Script::default());
    let target = alive.target()?;
    assert_eq!(
        alive
            .authority(&port)?
            .terminate_previous_runtime(&target)
            .err(),
        Some(RecoveryError::ProcessAlive)
    );
    // The same PID with other start ticks is another process: the original
    // is absent and nothing blocks.
    let recycled = Operation::of(
        (pid.get(), ticks + 1),
        Vec::new(),
        SuccessorRevocation::Nothing,
    )?;
    let port = recycled.port(Script::default());
    let target = recycled.target()?;
    recycled
        .authority(&port)?
        .terminate_previous_runtime(&target)?;
    // A malformed stat record never proves absence.
    assert_eq!(
        host::stat_start_time_ticks("1 (init) S"),
        Err(RecoveryError::ProcessAlive)
    );
    Ok(())
}

#[test]
fn a_remaining_control_group_or_a_foreign_mount_fails_closed() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let previous = operation
        .cgroups
        .path()
        .join("system.slice/previous.service");
    std::fs::create_dir_all(&previous)?;
    let port = operation.port(Script::default());
    let target = operation.target()?;
    assert_eq!(
        operation
            .authority(&port)?
            .terminate_previous_runtime(&target)
            .err(),
        Some(RecoveryError::CgroupPresent)
    );
    std::fs::remove_dir(&previous)?;

    // The production view: the real cgroup2 mount holds this process's own
    // cgroup and no made-up one; a mount that is not cgroup2 proves nothing.
    let directory = Arc::new(File::open(operation.recovery.path())?);
    let fixed = RecoveryHost::fixed(Arc::clone(&directory), peer_executable_digest);
    assert_eq!(
        fixed.require_cgroup_absent(&own_cgroup()?),
        Err(RecoveryError::CgroupPresent)
    );
    fixed.require_cgroup_absent(&CgroupPath::new("/pigloros-recovery-test-absent.service")?)?;
    assert_eq!(
        fixed.require_cgroup_absent(&CgroupPath::new("/")?),
        Err(RecoveryError::CgroupPresent)
    );
    let not_cgroup2 = RecoveryHost::for_test(
        directory,
        0,
        (operation.cgroups.path().to_path_buf(), host::is_cgroup2),
        peer_executable_digest,
        Arc::new(Instant::now),
    );
    assert_eq!(
        not_cgroup2.require_cgroup_absent(&CgroupPath::new("/absent")?),
        Err(RecoveryError::CgroupPresent)
    );
    let missing_mount = RecoveryHost::for_test(
        Arc::new(File::open(operation.recovery.path())?),
        0,
        (operation.cgroups.path().join("missing"), |_| true),
        peer_executable_digest,
        Arc::new(Instant::now),
    );
    assert_eq!(
        missing_mount.require_cgroup_absent(&CgroupPath::new("/absent")?),
        Err(RecoveryError::CgroupPresent)
    );
    Ok(())
}

#[test]
fn only_the_exact_refusing_leaf_is_removed() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let port = operation.port(Script::default());
    let host = operation.host(&port, peer_executable_digest)?;
    let endpoint = [0xab; 16];
    let leaf = operation
        .recovery
        .path()
        .join(format!("{}.sock", hex(&endpoint)));
    // Absent: nothing to do.
    host.remove_stale_leaf(endpoint)?;
    // A regular file, a symlink and a socket of mode 0644 are kept.
    std::fs::write(&leaf, b"")?;
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(host.remove_stale_leaf(endpoint), Err(RecoveryError::Leaf));
    std::fs::remove_file(&leaf)?;
    std::os::unix::fs::symlink("elsewhere", &leaf)?;
    assert_eq!(host.remove_stale_leaf(endpoint), Err(RecoveryError::Leaf));
    std::fs::remove_file(&leaf)?;
    drop(UnixListener::bind(&leaf)?);
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))?;
    assert_eq!(host.remove_stale_leaf(endpoint), Err(RecoveryError::Leaf));
    assert!(leaf.exists());
    // A socket that still accepts is kept.
    std::fs::remove_file(&leaf)?;
    let listening = bind_leaf(&leaf)?;
    assert_eq!(host.remove_stale_leaf(endpoint), Err(RecoveryError::Leaf));
    assert!(leaf.exists());
    // The exact refusing socket is removed.
    drop(listening);
    host.remove_stale_leaf(endpoint)?;
    assert!(std::fs::symlink_metadata(&leaf).is_err());
    // A recovery directory with another mode refuses every leaf.
    std::fs::set_permissions(
        operation.recovery.path(),
        std::fs::Permissions::from_mode(0o755),
    )?;
    assert_eq!(host.remove_stale_leaf(endpoint), Err(RecoveryError::Leaf));
    Ok(())
}

#[test]
fn a_peer_that_is_not_the_observed_process_is_refused_and_cleaned() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    for start in [
        Reply::OtherPid,
        Reply::OtherTicks,
        Reply::OtherCgroup,
        Reply::WrongChallenge,
        Reply::WrongScope,
    ] {
        let script = Script {
            start,
            // The cleanup's observation names the started peer's cgroup.
            reconcile: [Reply::Echo, Reply::Echo],
            ..Script::default()
        };
        let (result, port) = recover(&operation, script)?;
        let expected = if matches!(start, Reply::WrongChallenge | Reply::WrongScope) {
            RecoveryError::Observation
        } else {
            RecoveryError::PeerBinding
        };
        assert_eq!(result.err(), Some(expected), "{start:?}");
        assert!(
            matches!(port.calls().last(), Some(Call::Reconcile(_))),
            "{start:?}"
        );
        assert_eq!(operation.leaves()?, 0, "{start:?}");
        assert!(operation.sir1().exists());
    }
    // The executable is not the SIR1 binary.
    let port = operation.port(Script::default());
    let authority = ProviderTerminationAuthority::new(
        Arc::clone(&port),
        operation.host(&port, other_executable_digest)?,
    );
    assert_eq!(
        authority.recover(operation.target()?).err(),
        Some(RecoveryError::PeerBinding)
    );
    assert_eq!(operation.leaves()?, 0);
    // The peer is not ready on its leaf.
    let (result, _port) = recover(
        &operation,
        Script {
            peer: Peer::NotListening,
            ..Script::default()
        },
    )?;
    assert_eq!(result.err(), Some(RecoveryError::Exchange));
    assert_eq!(operation.leaves()?, 0);
    Ok(())
}

#[test]
fn every_exchange_failure_yields_no_proof_and_cleans_the_slot() -> TestResult {
    let operation = Operation::new(vec![[41; 16]], SuccessorRevocation::Nothing)?;
    for (peer, expected) in [
        (Peer::Garbage, RecoveryError::Acknowledgement),
        (Peer::Tampered, RecoveryError::Acknowledgement),
        (Peer::ExtraFrame, RecoveryError::Exchange),
        (Peer::ClosesEarly, RecoveryError::Exchange),
        (Peer::HoldsOpen, RecoveryError::Exchange),
        (Peer::Late, RecoveryError::Exchange),
    ] {
        let (result, port) = recover(
            &operation,
            Script {
                peer,
                ..Script::default()
            },
        )?;
        assert_eq!(result.err(), Some(expected), "{peer:?}");
        let calls = port.calls();
        assert_eq!(starts(&calls), 1, "{peer:?}");
        assert!(matches!(calls.last(), Some(Call::Reconcile(_))), "{peer:?}");
        assert_eq!(operation.leaves()?, 0, "{peer:?}");
        assert!(operation.sir1().exists(), "{peer:?}");
    }
    Ok(())
}

#[test]
fn a_failed_start_or_cleanup_yields_no_proof() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    for (script, expected) in [
        (
            Script {
                start: Reply::Refuse(ProviderLifecycleError::DeadlineExceeded),
                ..Script::default()
            },
            RecoveryError::Lifecycle(ProviderLifecycleError::DeadlineExceeded),
        ),
        (
            Script {
                reconcile: [
                    Reply::Echo,
                    Reply::Refuse(ProviderLifecycleError::ResidualResource),
                ],
                ..Script::default()
            },
            RecoveryError::Lifecycle(ProviderLifecycleError::ResidualResource),
        ),
        (
            Script {
                reconcile: [Reply::Echo, Reply::OtherCgroup],
                ..Script::default()
            },
            RecoveryError::Observation,
        ),
        (
            Script {
                reconcile_advance_ms: [0, 10_000],
                ..Script::default()
            },
            RecoveryError::DeadlineExceeded,
        ),
    ] {
        let (result, port) = recover(&operation, script)?;
        assert_eq!(result.err(), Some(expected), "{script:?}");
        assert!(matches!(port.calls().last(), Some(Call::Reconcile(_))));
        assert!(operation.sir1().exists());
    }
    Ok(())
}

#[test]
fn an_unwinding_start_still_reconciles_the_slot_once_more() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let port = operation.port(Script {
        start: Reply::Panic,
        ..Script::default()
    });
    let authority = operation.authority(&port)?;
    let target = operation.target()?;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authority
            .terminate_previous_runtime(&target)
            .and_then(|proof| authority.start_recovery_peer(&target, proof))
            .and_then(RecoveryPeerSession::conclude)
            .map(drop)
    }));
    assert!(unwound.is_err());
    let calls = port.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(matches!(calls[3], Call::Reconcile(_)));
    assert_eq!(operation.leaves()?, 0);
    assert!(operation.sir1().exists());
    Ok(())
}

#[test]
fn a_proof_authorizes_only_its_own_operation_and_an_unchanged_binary() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let port = operation.port(Script::default());
    let authority = operation.authority(&port)?;
    let first = operation.target()?;
    let second = operation.target()?;
    assert_eq!(first.identity(), second.identity());
    assert_ne!(first.operation, second.operation);
    let proof = authority.terminate_previous_runtime(&first)?;
    assert_eq!(
        authority.start_recovery_peer(&second, proof).err(),
        Some(RecoveryError::Mismatch)
    );
    // The previous provider binary changed under its held descriptor.
    let proof = authority.terminate_previous_runtime(&first)?;
    let binary = operation
        .fixture
        .path()
        .join("providers")
        .join(hex(blake3::hash(b"exact provider binary").as_bytes()));
    let mut permissions = std::fs::metadata(&binary)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&binary, permissions)?;
    std::fs::write(&binary, b"other provider binary")?;
    assert_eq!(
        authority.start_recovery_peer(&first, proof).err(),
        Some(RecoveryError::Binary)
    );
    // No peer was started.
    assert_eq!(starts(&port.calls()), 0);
    Ok(())
}

/// Two concluded sessions of two operations on one SIR1.
fn concluded_twice(
    operation: &Operation,
) -> TestResult<[(PendingRecoveryTarget, ConcludedRecovery); 2]> {
    let mut concluded = Vec::new();
    for _ in 0..2 {
        let port = operation.port(Script::default());
        let authority = operation.authority(&port)?;
        let target = operation.target()?;
        let session = authority
            .terminate_previous_runtime(&target)
            .and_then(|proof| authority.start_recovery_peer(&target, proof))?;
        let pair = session.conclude()?;
        concluded.push((target, pair));
    }
    concluded
        .try_into()
        .map_err(|_| "two sessions concluded".into())
}

#[test]
fn completion_requires_the_evidence_of_one_operation() -> TestResult {
    let operation = Operation::new(vec![[41; 16]], SuccessorRevocation::Nothing)?;
    // Proofs of the first operation never complete the second.
    let [(first, (consumed, acknowledgement, peer)), (second, (other_consumed, other_ack, other_peer))] =
        concluded_twice(&operation)?;
    assert_eq!(
        complete_recovery(second, consumed, acknowledgement, other_peer).err(),
        Some(RecoveryError::Mismatch)
    );
    let [(_, _), (second, _)] = concluded_twice(&operation)?;
    assert_eq!(
        complete_recovery(second, other_consumed, other_ack, peer).err(),
        Some(RecoveryError::Mismatch)
    );
    // Every element of the identity is bound (I3).
    let mutations: [fn(&mut RecoveryTransactionIdentity); 6] = [
        |identity| identity.sir1_digest[0] ^= 1,
        |identity| identity.previous_provider_binding_digest[0] ^= 1,
        |identity| identity.previous_runtime_instance_id[0] ^= 1,
        |identity| identity.previous_lifecycle_scope_id[0] ^= 1,
        |identity| identity.previous_live_attempt_ids.push([99; 16]),
        |identity| identity.recovery_peer_slot[2][0] ^= 1,
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        for in_peer_proof in [false, true] {
            let [(target, (mut consumed, acknowledgement, mut peer)), _] =
                concluded_twice(&operation)?;
            if in_peer_proof {
                mutate(&mut peer.identity);
            } else {
                mutate(&mut consumed.identity);
            }
            assert_eq!(
                complete_recovery(target, consumed, acknowledgement, peer).err(),
                Some(RecoveryError::Mismatch),
                "{index} {in_peer_proof}"
            );
        }
    }
    // A peer proof with another RCA1 digest, and an RCA1 of another SIR1.
    let [(target, (consumed, acknowledgement, mut peer)), _] = concluded_twice(&operation)?;
    peer.acknowledgement_digest[0] ^= 1;
    assert_eq!(
        complete_recovery(target, consumed, acknowledgement, peer).err(),
        Some(RecoveryError::Mismatch)
    );
    let other = Operation::new(vec![[41; 16]], SuccessorRevocation::Nothing)?;
    let [(_, (_, foreign, _)), _] = concluded_twice(&other)?;
    let [(target, (consumed, _, mut peer)), _] = concluded_twice(&operation)?;
    peer.acknowledgement_digest = foreign.acknowledgement_digest();
    assert_eq!(
        complete_recovery(target, consumed, foreign, peer).err(),
        Some(RecoveryError::Mismatch)
    );
    assert!(operation.sir1().exists());
    drop(first);
    Ok(())
}

#[test]
fn a_changed_recovery_floor_keeps_sir1() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let [(target, (consumed, acknowledgement, peer)), _] = concluded_twice(&operation)?;
    // SIR1 is replaced by an identical copy: another inode.
    let sir1 = operation.sir1();
    let bytes = std::fs::read(&sir1)?;
    std::fs::remove_file(&sir1)?;
    std::fs::write(&sir1, &bytes)?;
    std::fs::set_permissions(&sir1, std::fs::Permissions::from_mode(0o400))?;
    assert!(matches!(
        complete_recovery(target, consumed, acknowledgement, peer),
        Err(RecoveryError::Boundary(_))
    ));
    assert!(sir1.exists());
    Ok(())
}

#[test]
fn recovery_failures_close_with_their_boundary_errors() {
    for (error, expected) in [
        (
            RecoveryError::Lifecycle(ProviderLifecycleError::Unavailable),
            SelectorBoundaryError::SelectorUnavailable,
        ),
        (
            RecoveryError::Exchange,
            SelectorBoundaryError::SelectorUnavailable,
        ),
        (
            RecoveryError::DeadlineExceeded,
            SelectorBoundaryError::SelectorUnavailable,
        ),
        (
            RecoveryError::Observation,
            SelectorBoundaryError::ArtifactInvalid,
        ),
        (
            RecoveryError::ProcessAlive,
            SelectorBoundaryError::ArtifactInvalid,
        ),
        (
            RecoveryError::CgroupPresent,
            SelectorBoundaryError::ArtifactInvalid,
        ),
        (RecoveryError::Leaf, SelectorBoundaryError::ArtifactInvalid),
        (
            RecoveryError::PeerBinding,
            SelectorBoundaryError::ArtifactInvalid,
        ),
        (
            RecoveryError::Binary,
            SelectorBoundaryError::ArtifactInvalid,
        ),
        (
            RecoveryError::Acknowledgement,
            SelectorBoundaryError::ArtifactInvalid,
        ),
        (
            RecoveryError::Mismatch,
            SelectorBoundaryError::ArtifactInvalid,
        ),
    ] {
        assert_eq!(SelectorBoundaryError::from(error), expected, "{error}");
    }
}

#[test]
fn targets_and_observations_carry_exactly_what_they_name() -> TestResult {
    let challenge = ObservationChallenge::for_test([3; 16]);
    let live = [[1; 16], [2; 16]];
    let previous =
        PreviousRuntimeTarget::for_test(challenge, "provider", [[4; 16], [5; 16], [6; 16]], &live);
    assert_eq!(previous.challenge(), challenge);
    assert_eq!(previous.provider_id(), "provider");
    assert_eq!(previous.provider_binary_digest(), [0; 32]);
    assert_eq!(previous.runtime_instance_id(), [4; 16]);
    assert_eq!(previous.lifecycle_scope_id(), [5; 16]);
    assert_eq!(previous.recovery_lifecycle_scope_id(), [6; 16]);
    assert_eq!(previous.previous_live_attempt_ids(), live);
    let binary = VerifiedProviderBinary::for_test("/path".to_owned(), [7; 32]);
    let launch = RecoveryPeerLaunch::for_test(
        RecoverySlotTarget::for_test(challenge, [8; 16]),
        [9; 16],
        &binary,
    );
    assert_eq!(launch.challenge(), challenge);
    assert_eq!(launch.slot().challenge(), challenge);
    assert_eq!(launch.slot().recovery_lifecycle_scope_id(), [8; 16]);
    assert_eq!(launch.recovery_endpoint_id(), [9; 16]);
    assert_eq!(launch.provider_binary().path(), "/path");
    assert_eq!(launch.provider_binary().digest(), [7; 32]);
    let cgroup = CgroupPath::new("/system.slice/x.service")?;
    let observed = PreviousRuntimeObservation::new(
        challenge,
        [5; 16],
        cgroup.clone(),
        live.to_vec(),
        Duration::from_secs(3),
    );
    assert_eq!(observed.activation_wait(), Duration::from_secs(3));
    assert_eq!(observed.challenge(), challenge);
    assert_eq!(observed.lifecycle_scope_id(), [5; 16]);
    assert_eq!(observed.control_group(), &cgroup);
    assert_eq!(observed.reconciled_attempt_ids(), live);
    let slot = RecoverySlotObservation::new(challenge, [8; 16], cgroup.clone());
    assert_eq!(
        (
            slot.challenge(),
            slot.recovery_lifecycle_scope_id(),
            slot.control_group()
        ),
        (challenge, [8; 16], &cgroup)
    );
    let pid = NonZeroU64::new(41).ok_or("zero pid")?;
    let peer = RecoveryPeerObservation::new(challenge, [8; 16], pid, 77, cgroup.clone());
    assert_eq!(
        (
            peer.challenge(),
            peer.recovery_lifecycle_scope_id(),
            peer.main_pid(),
            peer.main_start_time_ticks(),
            peer.control_group()
        ),
        (challenge, [8; 16], pid, 77, &cgroup)
    );
    Ok(())
}

#[test]
fn the_exchange_stream_refuses_io_past_its_deadline() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let port = operation.port(Script::default());
    let host = operation.host(&port, peer_executable_digest)?;
    let (mut client, server) = UnixStream::pair()?;
    let deadline = host.now() + Duration::from_millis(100);
    let mut clocked = host.clocked(&server, deadline);
    client.write_all(b"x")?;
    let mut byte = [0; 1];
    assert_eq!(clocked.read(&mut byte)?, 1);
    clocked.write_all(b"y")?;
    clocked.flush()?;
    assert!(clocked.within_deadline());
    port.clock.fetch_add(100, Ordering::SeqCst);
    assert!(!clocked.within_deadline());
    assert_eq!(
        clocked.read(&mut byte).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::TimedOut)
    );
    assert_eq!(
        clocked.write(b"z").map_err(|error| error.kind()),
        Err(std::io::ErrorKind::TimedOut)
    );
    client.read_exact(&mut byte)?;
    Ok(())
}

/// Review M2 and the cleanup bound: every port result is checked against
/// its deadline on the selector's clock, exactly at the deadline it passes
/// and one millisecond later it yields no proof. The previous-runtime
/// termination may outlast its 10 s bound only by the D2 wait the port
/// reports it applied, at most 70 s.
#[test]
fn every_port_deadline_holds_exactly_at_and_fails_one_past() -> TestResult {
    for (script, expected) in [
        // Without a recent activation the termination keeps its 10 s.
        (
            Script {
                terminate_advance_ms: 10_000,
                ..Script::default()
            },
            None,
        ),
        (
            Script {
                terminate_advance_ms: 10_001,
                ..Script::default()
            },
            Some(RecoveryError::DeadlineExceeded),
        ),
        // A reported recent-activation wait extends it by that wait only.
        (
            Script {
                terminate_advance_ms: 80_000,
                activation_wait_ms: 70_000,
                ..Script::default()
            },
            None,
        ),
        (
            Script {
                terminate_advance_ms: 40_001,
                activation_wait_ms: 30_000,
                ..Script::default()
            },
            Some(RecoveryError::DeadlineExceeded),
        ),
        // A reported wait beyond 70 s is refused.
        (
            Script {
                activation_wait_ms: 70_001,
                ..Script::default()
            },
            Some(RecoveryError::Observation),
        ),
        (
            Script {
                reconcile_advance_ms: [5_000, 0],
                ..Script::default()
            },
            None,
        ),
        (
            Script {
                reconcile_advance_ms: [5_001, 0],
                ..Script::default()
            },
            Some(RecoveryError::DeadlineExceeded),
        ),
        (
            Script {
                reconcile_advance_ms: [0, 5_000],
                ..Script::default()
            },
            None,
        ),
        (
            Script {
                reconcile_advance_ms: [0, 5_001],
                ..Script::default()
            },
            Some(RecoveryError::DeadlineExceeded),
        ),
        // Before the peer starts, any control group may be reported; after
        // it started, only the peer's.
        (
            Script {
                reconcile: [Reply::OtherCgroup, Reply::Echo],
                ..Script::default()
            },
            None,
        ),
    ] {
        let operation = Operation::new(vec![[41; 16]], SuccessorRevocation::Nothing)?;
        let (result, _port) = recover(&operation, script)?;
        assert_eq!(result.err(), expected, "{script:?}");
        assert_eq!(operation.sir1().exists(), expected.is_some(), "{script:?}");
    }
    Ok(())
}

#[test]
fn the_peer_credentials_must_be_the_owner_and_the_observed_process() -> TestResult {
    let pid = NonZeroU64::new(41).ok_or("zero pid")?;
    assert!(host::peer_matches((7, 41), 7, pid));
    assert!(!host::peer_matches((8, 41), 7, pid));
    assert!(!host::peer_matches((7, 42), 7, pid));
    assert!(!host::peer_matches((8, 42), 7, pid));
    Ok(())
}

#[test]
fn a_leaf_replaced_after_readiness_or_its_probe_is_refused_and_kept() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let port = operation.port(Script::default());
    let host = operation.standard_host(&port)?;
    let endpoint = [0xcd; 16];
    let leaf = operation
        .recovery
        .path()
        .join(format!("{}.sock", hex(&endpoint)));
    let first = bind_leaf(&leaf)?;
    let ready = host.ready_leaf(endpoint)?;
    host.require_same_leaf(endpoint, ready)?;
    // I8: another inode between readiness and connect. A second hard link
    // keeps the first inode allocated, so the replacement cannot reuse its
    // number (a freed socket inode may be reused at once).
    drop(first);
    let kept = operation.recovery.path().join("kept-first-inode");
    std::fs::hard_link(&leaf, &kept)?;
    std::fs::remove_file(&leaf)?;
    let second = bind_leaf(&leaf)?;
    assert_ne!(host.ready_leaf(endpoint)?, ready);
    assert_eq!(
        host.require_same_leaf(endpoint, ready),
        Err(RecoveryError::Leaf)
    );
    // A refusing leaf whose (dev, ino) changed since it was probed is kept.
    drop(second);
    assert_eq!(
        host.remove_refusing_leaf(&host::leaf_name(endpoint), ready),
        Err(RecoveryError::Leaf)
    );
    assert!(leaf.exists());
    // An absent leaf is never ready.
    std::fs::remove_file(&leaf)?;
    std::fs::remove_file(&kept)?;
    assert_eq!(host.ready_leaf(endpoint), Err(RecoveryError::Leaf));
    Ok(())
}

/// Set once the exiting thread may end.
static THREAD_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A digest of the fixture binary for any PID, that first ends the thread
/// it was asked about and waits until the kernel no longer lists it.
fn exiting_thread_digest(pid: NonZeroU64, _length: u64) -> Result<[u8; 32], SelectorBoundaryError> {
    THREAD_EXIT.store(true, Ordering::SeqCst);
    let stat = format!("/proc/{pid}/stat");
    let started = Instant::now();
    while Path::new(&stat).exists() && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(1));
    }
    if Path::new(&stat).exists() {
        Err(SelectorBoundaryError::SelectorUnavailable)
    } else {
        Ok(*blake3::hash(b"exact provider binary").as_bytes())
    }
}

/// A digest of the fixture binary for any live task of this host.
fn any_executable_digest(pid: NonZeroU64, _length: u64) -> Result<[u8; 32], SelectorBoundaryError> {
    std::fs::metadata(format!("/proc/{pid}/stat"))
        .map(|_| *blake3::hash(b"exact provider binary").as_bytes())
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

/// The observed process must still be the same one after its executable
/// was hashed: a thread observed alive, whose task ends while it is
/// hashed, is refused by the second start-ticks check only.
#[test]
fn the_peer_must_outlive_the_hash_of_its_executable() -> TestResult {
    let operation = Operation::new(Vec::new(), SuccessorRevocation::Nothing)?;
    let digest = *blake3::hash(b"exact provider binary").as_bytes();
    let (sender, receiver) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        // `/proc/thread-self` names `<pid>/task/<tid>`.
        let tid = std::fs::read_link("/proc/thread-self")
            .ok()
            .and_then(|link| link.file_name()?.to_str()?.parse::<u64>().ok());
        let _sent = sender.send(tid);
        while !THREAD_EXIT.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let tid = receiver
        .recv()?
        .and_then(NonZeroU64::new)
        .ok_or("no thread ID")?;
    let ticks = crate::selector::runtime_lifecycle::process_start_time_ticks(tid)?;
    let cgroup = CgroupPath::new(&crate::selector::runtime_lifecycle::process_control_group(
        tid,
    )?)?;
    let port = operation.port(Script::default());
    let live = operation.host(&port, any_executable_digest)?;
    live.verify_peer_process(tid, ticks, &cgroup, (digest, 0))?;
    let exiting = operation.host(&port, exiting_thread_digest)?;
    assert_eq!(
        exiting.verify_peer_process(tid, ticks, &cgroup, (digest, 0)),
        Err(RecoveryError::PeerBinding)
    );
    thread.join().map_err(|_| "the exiting thread panicked")?;
    Ok(())
}

/// The next SIC1 of `operation`, published as the current one (crash row 7).
fn publish_next(operation: &Operation) -> TestResult {
    let update = crate::evaluator_protocol::decode_canonical(&operation.request)?;
    let ciborium::value::Value::Bytes(next) = &crate::evaluator_protocol::array(&update, 5)?[3]
    else {
        return Err("SIU1 successor manifest is not bytes".into());
    };
    let manifest = operation
        .fixture
        .path()
        .join(crate::selector::installation::MANIFEST_NAME);
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&manifest, next)?;
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

/// One crash boundary of R12 §9 as durable state.
#[derive(Clone, Copy, Debug)]
enum Row {
    /// 2 and 6: SIR1 committed, current = previous, the slot empty.
    Committed,
    /// 3 and 5: the peer's leaf survived, refusing (its unit is gone).
    PeerLeaf,
    /// 4: a failed exchange left the leaf and the RCA1 was never valid.
    FailedExchange,
    /// 7: the next SIC1 is current, SIR1 still pending.
    NextCurrent,
}

/// R12 I12: each crash row is durable state plus a fake-port state. The
/// full sequence runs from it; its idempotent first steps run twice first,
/// as after a second crash at the same boundary. Row 8 is the completed
/// state: no SIR1, the normal open of the next SIC1.
#[test]
fn every_crash_row_recovers_from_its_durable_state() -> TestResult {
    for row in [
        Row::Committed,
        Row::PeerLeaf,
        Row::FailedExchange,
        Row::NextCurrent,
    ] {
        let operation = Operation::new(vec![[41; 16]], SuccessorRevocation::Nothing)?;
        let target = operation.target()?;
        let leaf = operation
            .recovery
            .path()
            .join(format!("{}.sock", hex(&target.endpoint_id())));
        match row {
            Row::Committed => {}
            Row::PeerLeaf => drop(bind_leaf(&leaf)?),
            Row::FailedExchange => {
                let (failed, _port) = recover(
                    &operation,
                    Script {
                        peer: Peer::Garbage,
                        reconcile: [
                            Reply::Echo,
                            Reply::Refuse(ProviderLifecycleError::ResidualResource),
                        ],
                        ..Script::default()
                    },
                )?;
                assert!(failed.is_err(), "{row:?}");
                assert!(leaf.exists(), "{row:?}: the failed cleanup kept the leaf");
            }
            Row::NextCurrent => publish_next(&operation)?,
        }
        let port = operation.port(Script::default());
        let authority = operation.authority(&port)?;
        for _ in 0..2 {
            drop(authority.terminate_previous_runtime(&operation.target()?)?);
            assert!(!leaf.exists(), "{row:?}");
        }
        authority.recover(operation.target()?)?;
        assert!(!operation.sir1().exists(), "{row:?}");
        // Row 8, twice: no SIR1 is pending any more.
        for _ in 0..2 {
            assert!(operation.target().is_err(), "{row:?}");
        }
    }
    Ok(())
}
