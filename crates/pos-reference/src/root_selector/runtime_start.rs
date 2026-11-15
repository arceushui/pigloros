//! The selector side of starting one provider runtime (ADR-069 R11 §5.0).
//!
//! With no SIR1 pending, the selector:
//!
//! 1. has the port stop every stale runtime and recovery unit (step 2);
//! 2. removes a stale endpoint leaf only when it is a root-owned mode-0600
//!    socket that refuses connections, re-checking its parent and its device
//!    and inode before `unlinkat` (step 3, owner decision O3);
//! 3. allocates the runtime slot before any provider process exists (step 4);
//! 4. has the port start the slot's unit and wait for readiness (steps 5, 6);
//! 5. checks the reported main process against the kernel: its start ticks,
//!    its cgroup, and the BLAKE3 digest of its executable against the SIC1
//!    kind-11 digest (step 7);
//! 6. connects, requires every peer to be that main process, sends `describe`
//!    and binds the slot to the process (step 8).
//!
//! Every failure keeps admission closed. Nothing here creates a process:
//! systemd starts the runtime when the port asks it to (ADR-087 A.3).

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{statat, AtFlags};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use super::{
    artifact_invalid, fresh_synchronization_ids, io_error, listener_socket_identity,
    remove_matching_socket, selector_unavailable, synchronize_fixed_provider,
    validate_listener_parent, SocketIdentity, ROOT_UID,
};
use crate::provider_admission::{admitted_provider_binary, AdmittedProviderBinary};
use crate::provider_transport::{process_start_time_ticks, ProviderTransport};
use crate::selector::installation::authority::{
    AdmittedProviderRuntime, AdmittedSelectorProvider, ProviderRuntimeSlot,
};
use crate::selector::installation::open_directory_chain;
use crate::selector::runtime_lifecycle::{
    ObservationChallenge, ProviderLifecyclePort, RuntimeSlotTarget, StartedRuntimeObservation,
};
use crate::selector::SelectorBoundaryError;

/// The bound of the whole stale-unit termination: ADR-069 §9's 10 s restart
/// bound. The adapter's fixed per-unit stop phases fit inside §9's 5 s
/// forced-cleanup ceiling (owner reading, 2026-11-15).
const STALE_TERMINATION_BOUND: Duration = Duration::from_secs(10);
/// systemd fails the start job after the unit's 30 s `TimeoutStartUSec`; the
/// selector waits 2 s longer, so the manager's own timeout ends the job first
/// (owner decision, 2026-11-15).
const RUNTIME_START_BOUND: Duration = Duration::from_secs(32);

/// The BLAKE3 digest of a process's executable, read at most `length + 1`
/// bytes deep. Production uses [`proc_executable_digest`].
pub(super) type ExecutableDigest = fn(NonZeroU64, u64) -> Result<[u8; 32], SelectorBoundaryError>;

/// Start the selected provider's runtime and admit exactly its main process.
pub(super) fn start_provider_runtime(
    port: &dyn ProviderLifecyclePort,
    admitted: &AdmittedSelectorProvider,
    executable_digest: ExecutableDigest,
) -> Result<(ProviderTransport, AdmittedProviderRuntime), SelectorBoundaryError> {
    terminate_stale_runtimes(port)
        .and_then(|()| remove_stale_endpoints(admitted))
        .and_then(|()| ProviderRuntimeSlot::allocate(admitted))
        .and_then(|slot| admitted_provider_binary(admitted).map(|binary| (slot, binary)))
        .and_then(|(slot, binary)| {
            start_slot(port, &slot, &binary)
                .and_then(|observed| {
                    verify_started_process(&observed, &binary, executable_digest).map(|()| observed)
                })
                .and_then(|observed| admit_started_runtime(admitted, slot, &observed))
        })
}

fn deadline_after(bound: Duration) -> Result<Instant, SelectorBoundaryError> {
    Instant::now()
        .checked_add(bound)
        .ok_or(SelectorBoundaryError::SelectorUnavailable)
}

const fn require(condition: bool) -> Result<(), SelectorBoundaryError> {
    if condition {
        Ok(())
    } else {
        Err(SelectorBoundaryError::ArtifactInvalid)
    }
}

fn terminate_stale_runtimes(port: &dyn ProviderLifecyclePort) -> Result<(), SelectorBoundaryError> {
    ObservationChallenge::fresh()
        .and_then(|challenge| {
            deadline_after(STALE_TERMINATION_BOUND).map(|deadline| (challenge, deadline))
        })
        .and_then(|(challenge, deadline)| {
            port.terminate_stale_runtimes(challenge, deadline)
                .map_err(selector_unavailable)
                .and_then(|observed| require(observed.challenge() == challenge))
        })
}

fn start_slot(
    port: &dyn ProviderLifecyclePort,
    slot: &ProviderRuntimeSlot,
    binary: &AdmittedProviderBinary,
) -> Result<StartedRuntimeObservation, SelectorBoundaryError> {
    ObservationChallenge::fresh()
        .and_then(|challenge| {
            deadline_after(RUNTIME_START_BOUND).map(|deadline| (challenge, deadline))
        })
        .and_then(|(challenge, deadline)| {
            port.start_provider_runtime(&RuntimeSlotTarget::new(challenge, slot, binary), deadline)
                .map_err(selector_unavailable)
                .and_then(|observed| {
                    require(
                        observed.challenge() == challenge
                            && observed.lifecycle_scope_id() == slot.lifecycle_scope_id(),
                    )
                    .map(|()| observed)
                })
        })
}

/// R11 §5.0 step 7: the observed main process, as the kernel reports it.
fn verify_started_process(
    observed: &StartedRuntimeObservation,
    binary: &AdmittedProviderBinary,
    executable_digest: ExecutableDigest,
) -> Result<(), SelectorBoundaryError> {
    let pid = observed.main_pid();
    let ticks = observed.main_start_time_ticks();
    let same_process = || process_start_time_ticks(pid).and_then(|now| require(now == ticks));
    same_process()
        .and_then(|()| process_control_group(pid))
        .and_then(|cgroup| require(cgroup == observed.control_group().as_str()))
        .and_then(|()| executable_digest(pid, binary.length()))
        .and_then(|digest| require(digest == binary.digest()))
        // The same process, not a recycled PID, owned the executable just hashed.
        .and_then(|()| same_process())
}

pub(super) fn process_control_group(pid: NonZeroU64) -> Result<String, SelectorBoundaryError> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(artifact_invalid)
        .and_then(|text| unified_cgroup(&text).map(str::to_owned))
}

/// The one cgroup2 membership line `0::<path>` of a cgroup2-only host.
fn unified_cgroup(text: &str) -> Result<&str, SelectorBoundaryError> {
    text.strip_prefix("0::")
        .and_then(|rest| rest.strip_suffix('\n'))
        .filter(|path| !path.contains('\n'))
        .ok_or(SelectorBoundaryError::ArtifactInvalid)
}

/// The BLAKE3 digest of `/proc/<pid>/exe`, the process's own executable.
pub(super) fn proc_executable_digest(
    pid: NonZeroU64,
    length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    File::open(format!("/proc/{pid}/exe"))
        .map_err(artifact_invalid)
        .and_then(|executable| bounded_digest(executable, length))
}

fn bounded_digest(source: impl Read, length: u64) -> Result<[u8; 32], SelectorBoundaryError> {
    let mut hasher = blake3::Hasher::new();
    let mut bounded = source.take(length.saturating_add(1));
    let copied = io::copy(&mut bounded, &mut hasher);
    copied
        .map_err(io_error)
        .and_then(|copied| require(copied == length))
        .map(|()| *hasher.finalize().as_bytes())
}

fn remove_stale_endpoints(
    admitted: &AdmittedSelectorProvider,
) -> Result<(), SelectorBoundaryError> {
    let (execute, control) = admitted.selected_provider_sockets();
    remove_stale_endpoint(Path::new("/"), execute, ROOT_UID)
        .and_then(|()| remove_stale_endpoint(Path::new("/"), control, ROOT_UID))
}

/// R11 §5.0 step 3: remove one stale endpoint leaf, or prove none exists.
fn remove_stale_endpoint(
    ancestry_root: &Path,
    endpoint: &Path,
    owner: u32,
) -> Result<(), SelectorBoundaryError> {
    endpoint
        .strip_prefix("/")
        .ok()
        .and_then(|relative| {
            relative
                .parent()
                .zip(relative.file_name().map(OsString::from))
                .map(|(parent_relative, leaf)| (relative, parent_relative, leaf))
        })
        .ok_or(SelectorBoundaryError::ArtifactInvalid)
        .and_then(|(relative, parent_relative, leaf)| {
            File::open(ancestry_root)
                .map_err(io_error)
                .and_then(|root| open_directory_chain(root, parent_relative, owner))
                .and_then(|parent| {
                    stale_socket(&parent, &leaf, owner).and_then(|stale| {
                        stale.map_or(Ok(()), |identity| {
                            require_refused(&ancestry_root.join(relative))
                                .and_then(|()| {
                                    validate_listener_parent(
                                        &ancestry_root.join(parent_relative),
                                        &parent,
                                        owner,
                                    )
                                })
                                .and_then(|()| {
                                    remove_matching_socket(&parent, &leaf, identity, owner)
                                })
                        })
                    })
                })
        })
}

/// `None` when the leaf is absent; otherwise its identity, which must be a
/// socket with the expected owner and mode `0600`.
fn stale_socket(
    parent: &File,
    leaf: &OsString,
    owner: u32,
) -> Result<Option<SocketIdentity>, SelectorBoundaryError> {
    match statat(parent, Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(None),
        _ => listener_socket_identity(parent, leaf, owner).map(Some),
    }
}

/// A non-blocking `connect()` must fail with exactly `ECONNREFUSED`: no
/// process listens on the leaf any more.
fn require_refused(path: &Path) -> Result<(), SelectorBoundaryError> {
    SocketAddrUnix::new(path)
        .map_err(artifact_invalid)
        .and_then(|address| {
            socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC.union(SocketFlags::NONBLOCK),
                None,
            )
            .map_err(io_error)
            .and_then(|socket| match connect(&socket, &address) {
                Err(rustix::io::Errno::CONNREFUSED) => Ok(()),
                _ => Err(SelectorBoundaryError::ArtifactInvalid),
            })
        })
}

/// R11 §5.0 step 8: only the observed main process may answer.
fn admit_started_runtime(
    admitted: &AdmittedSelectorProvider,
    slot: ProviderRuntimeSlot,
    observed: &StartedRuntimeObservation,
) -> Result<(ProviderTransport, AdmittedProviderRuntime), SelectorBoundaryError> {
    let pid = observed.main_pid().get();
    let ticks = observed.main_start_time_ticks();
    ProviderTransport::for_started_runtime(admitted, pid, ticks)
        .and_then(|transport| {
            fresh_synchronization_ids()
                .and_then(|ids| synchronize_fixed_provider(&transport, admitted, ids))
                .map(|()| transport)
        })
        .and_then(|transport| {
            slot.bind_observed_process(pid, ticks)
                .map(|runtime| (transport, runtime))
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, FileTypeExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;

    use super::*;
    use crate::root_selector::tests::own_runtime_observation;
    use crate::selector::runtime_lifecycle::{
        CgroupPath, ProviderLifecycleError, StaleUnitsObservation,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[derive(Clone, Copy)]
    enum Reply {
        Echo,
        WrongChallenge,
        WrongScope,
        Refuse,
    }

    struct ScriptedPort {
        stale: Reply,
        start: Reply,
        stale_deadlines: Mutex<Vec<Instant>>,
        start_deadlines: Mutex<Vec<Instant>>,
    }

    impl ScriptedPort {
        const fn new(stale: Reply, start: Reply) -> Self {
            Self {
                stale,
                start,
                stale_deadlines: Mutex::new(Vec::new()),
                start_deadlines: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProviderLifecyclePort for ScriptedPort {
        fn terminate_stale_runtimes(
            &self,
            challenge: ObservationChallenge,
            deadline: Instant,
        ) -> Result<StaleUnitsObservation, ProviderLifecycleError> {
            self.stale_deadlines
                .lock()
                .map_err(|_| ProviderLifecycleError::Unavailable)?
                .push(deadline);
            match self.stale {
                Reply::Echo | Reply::WrongScope => Ok(StaleUnitsObservation::new(challenge, 1)),
                Reply::WrongChallenge => Ok(StaleUnitsObservation::new(
                    ObservationChallenge::for_test([9; 16]),
                    1,
                )),
                Reply::Refuse => Err(ProviderLifecycleError::ResidualResource),
            }
        }

        fn start_provider_runtime(
            &self,
            slot: &RuntimeSlotTarget<'_>,
            deadline: Instant,
        ) -> Result<StartedRuntimeObservation, ProviderLifecycleError> {
            self.start_deadlines
                .lock()
                .map_err(|_| ProviderLifecycleError::Unavailable)?
                .push(deadline);
            let own = own_runtime_observation(slot)?;
            let challenge = match self.start {
                Reply::WrongChallenge => ObservationChallenge::for_test([9; 16]),
                _ => own.challenge(),
            };
            let scope = match self.start {
                Reply::WrongScope => [9; 16],
                _ => own.lifecycle_scope_id(),
            };
            match self.start {
                Reply::Refuse => Err(ProviderLifecycleError::Unavailable),
                _ => Ok(StartedRuntimeObservation::new(
                    challenge,
                    scope,
                    own.main_pid(),
                    own.main_start_time_ticks(),
                    own.control_group().clone(),
                )),
            }
        }
    }

    fn fixture() -> TestResult<(
        AdmittedSelectorProvider,
        ProviderRuntimeSlot,
        AdmittedProviderBinary,
    )> {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let slot = ProviderRuntimeSlot::allocate(&admitted)?;
        let binary = admitted_provider_binary(&admitted)?;
        Ok((admitted, slot, binary))
    }

    fn within(deadline: Instant, bound: Duration, before: Instant) -> bool {
        deadline >= before + bound && deadline <= Instant::now() + bound
    }

    #[test]
    fn stale_termination_is_bounded_and_must_echo_its_challenge() -> TestResult {
        let before = Instant::now();
        let echo = ScriptedPort::new(Reply::Echo, Reply::Echo);
        assert_eq!(terminate_stale_runtimes(&echo), Ok(()));
        let deadlines = echo.stale_deadlines.lock().map_err(|_| "poisoned")?;
        assert_eq!(deadlines.len(), 1);
        assert!(within(deadlines[0], Duration::from_secs(10), before));
        drop(deadlines);
        assert_eq!(
            terminate_stale_runtimes(&ScriptedPort::new(Reply::WrongChallenge, Reply::Echo)),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            terminate_stale_runtimes(&ScriptedPort::new(Reply::Refuse, Reply::Echo)),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        Ok(())
    }

    #[test]
    fn a_started_slot_must_echo_its_challenge_and_scope() -> TestResult {
        let (_, slot, binary) = fixture()?;
        let before = Instant::now();
        let echo = ScriptedPort::new(Reply::Echo, Reply::Echo);
        let observed = start_slot(&echo, &slot, &binary)?;
        assert_eq!(observed.lifecycle_scope_id(), slot.lifecycle_scope_id());
        let deadlines = echo.start_deadlines.lock().map_err(|_| "poisoned")?;
        assert_eq!(deadlines.len(), 1);
        assert!(within(deadlines[0], Duration::from_secs(32), before));
        drop(deadlines);
        for (reply, expected) in [
            (
                Reply::WrongChallenge,
                SelectorBoundaryError::ArtifactInvalid,
            ),
            (Reply::WrongScope, SelectorBoundaryError::ArtifactInvalid),
            (Reply::Refuse, SelectorBoundaryError::SelectorUnavailable),
        ] {
            assert_eq!(
                start_slot(&ScriptedPort::new(Reply::Echo, reply), &slot, &binary).err(),
                Some(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn a_failed_stale_termination_starts_nothing() -> TestResult {
        let (admitted, _, _) = fixture()?;
        let port = ScriptedPort::new(Reply::Refuse, Reply::Echo);
        assert_eq!(
            start_provider_runtime(&port, &admitted, proc_executable_digest).err(),
            Some(SelectorBoundaryError::SelectorUnavailable)
        );
        assert!(port
            .start_deadlines
            .lock()
            .map_err(|_| "poisoned")?
            .is_empty());
        Ok(())
    }

    fn fixture_digest() -> [u8; 32] {
        *blake3::hash(b"exact provider binary").as_bytes()
    }

    const BINARY_DIGEST: ExecutableDigest = |_, _| Ok(fixture_digest());
    const OTHER_DIGEST: ExecutableDigest = |_, _| Ok([0; 32]);

    fn failing_digest(_: NonZeroU64, _: u64) -> Result<[u8; 32], SelectorBoundaryError> {
        Err(SelectorBoundaryError::Io)
    }

    #[test]
    fn the_main_process_must_match_the_kernel_and_the_admitted_binary() -> TestResult {
        let (_, slot, binary) = fixture()?;
        assert_eq!(binary.digest(), BINARY_DIGEST(NonZeroU64::MIN, 0)?);
        let observed = start_slot(&ScriptedPort::new(Reply::Echo, Reply::Echo), &slot, &binary)?;
        verify_started_process(&observed, &binary, BINARY_DIGEST)?;
        assert_eq!(
            verify_started_process(&observed, &binary, OTHER_DIGEST),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            verify_started_process(&observed, &binary, failing_digest),
            Err(SelectorBoundaryError::Io)
        );
        let pid = observed.main_pid();
        let ticks = observed.main_start_time_ticks();
        let cgroup = observed.control_group().clone();
        for changed in [
            StartedRuntimeObservation::new(
                observed.challenge(),
                observed.lifecycle_scope_id(),
                pid,
                ticks + 1,
                cgroup.clone(),
            ),
            StartedRuntimeObservation::new(
                observed.challenge(),
                observed.lifecycle_scope_id(),
                pid,
                ticks,
                CgroupPath::new("/pigloros-elsewhere.slice")?,
            ),
        ] {
            assert_eq!(
                verify_started_process(&changed, &binary, BINARY_DIGEST),
                Err(SelectorBoundaryError::ArtifactInvalid)
            );
        }
        let absent = StartedRuntimeObservation::new(
            observed.challenge(),
            observed.lifecycle_scope_id(),
            NonZeroU64::new(u64::from(u32::MAX)).ok_or("zero pid")?,
            ticks,
            cgroup,
        );
        assert_eq!(
            verify_started_process(&absent, &binary, BINARY_DIGEST),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    #[test]
    fn only_a_single_unified_cgroup_line_is_accepted() {
        assert_eq!(
            unified_cgroup("0::/system.slice/a.service\n"),
            Ok("/system.slice/a.service")
        );
        assert_eq!(unified_cgroup("0::/\n"), Ok("/"));
        for invalid in [
            "",
            "0::/a",
            "1::/a\n",
            "0::/a\n0::/b\n",
            "12:pids:/a\n0::/a\n",
        ] {
            assert_eq!(
                unified_cgroup(invalid),
                Err(SelectorBoundaryError::ArtifactInvalid),
                "{invalid:?}"
            );
        }
        assert_eq!(
            process_control_group(NonZeroU64::new(u64::from(u32::MAX)).unwrap_or(NonZeroU64::MIN)),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
    }

    #[test]
    fn the_executable_digest_is_bounded_by_the_admitted_length() -> TestResult {
        let bytes = b"provider";
        let length = u64::try_from(bytes.len())?;
        assert_eq!(
            bounded_digest(bytes.as_slice(), length),
            Ok(*blake3::hash(bytes).as_bytes())
        );
        assert_eq!(
            bounded_digest(bytes.as_slice(), length - 1),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            bounded_digest(bytes.as_slice(), length + 1),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );

        let own = NonZeroU64::new(u64::from(std::process::id())).ok_or("zero pid")?;
        let executable = fs::read(std::env::current_exe()?)?;
        assert_eq!(
            proc_executable_digest(own, u64::try_from(executable.len())?),
            Ok(*blake3::hash(&executable).as_bytes())
        );
        assert_eq!(
            proc_executable_digest(NonZeroU64::new(u64::from(u32::MAX)).ok_or("zero pid")?, 1),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    struct EndpointFixture {
        root: tempfile::TempDir,
        owner: u32,
    }

    impl EndpointFixture {
        fn new() -> TestResult<Self> {
            let root = tempfile::tempdir()?;
            fs::create_dir(root.path().join("run"))?;
            fs::set_permissions(root.path().join("run"), fs::Permissions::from_mode(0o700))?;
            let owner = rustix::process::geteuid().as_raw();
            Ok(Self { root, owner })
        }

        fn leaf(&self) -> std::path::PathBuf {
            self.root.path().join("run/provider.sock")
        }

        fn remove(&self) -> Result<(), SelectorBoundaryError> {
            remove_stale_endpoint(
                self.root.path(),
                Path::new("/run/provider.sock"),
                self.owner,
            )
        }

        fn refusing_socket(&self, mode: u32) -> TestResult {
            drop(UnixListener::bind(self.leaf())?);
            fs::set_permissions(self.leaf(), fs::Permissions::from_mode(mode))?;
            Ok(())
        }
    }

    #[test]
    fn an_absent_endpoint_needs_no_removal() -> TestResult {
        let fixture = EndpointFixture::new()?;
        assert_eq!(fixture.remove(), Ok(()));
        assert!(!fixture.leaf().exists());
        Ok(())
    }

    #[test]
    fn a_refusing_root_owned_socket_is_removed() -> TestResult {
        let fixture = EndpointFixture::new()?;
        fixture.refusing_socket(0o600)?;
        assert_eq!(fixture.remove(), Ok(()));
        assert!(fs::symlink_metadata(fixture.leaf()).is_err());
        Ok(())
    }

    #[test]
    fn any_other_endpoint_node_fails_closed_and_is_kept() -> TestResult {
        let listening = EndpointFixture::new()?;
        let listener = UnixListener::bind(listening.leaf())?;
        fs::set_permissions(listening.leaf(), fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            listening.remove(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert!(fs::symlink_metadata(listening.leaf())?
            .file_type()
            .is_socket());
        drop(listener);

        let wrong_mode = EndpointFixture::new()?;
        wrong_mode.refusing_socket(0o644)?;
        assert_eq!(
            wrong_mode.remove(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert!(fs::symlink_metadata(wrong_mode.leaf()).is_ok());

        let file = EndpointFixture::new()?;
        fs::write(file.leaf(), b"not a socket")?;
        fs::set_permissions(file.leaf(), fs::Permissions::from_mode(0o600))?;
        assert_eq!(file.remove(), Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(file.leaf().is_file());

        let link = EndpointFixture::new()?;
        let target = link.root.path().join("target.sock");
        drop(UnixListener::bind(&target)?);
        symlink(&target, link.leaf())?;
        assert_eq!(link.remove(), Err(SelectorBoundaryError::ArtifactInvalid));
        assert!(fs::symlink_metadata(link.leaf())?.file_type().is_symlink());

        let foreign = EndpointFixture::new()?;
        foreign.refusing_socket(0o600)?;
        assert_eq!(
            remove_stale_endpoint(
                foreign.root.path(),
                Path::new("/run/provider.sock"),
                foreign.owner + 1
            ),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert!(fs::symlink_metadata(foreign.leaf()).is_ok());
        Ok(())
    }

    #[test]
    fn endpoint_paths_must_be_absolute_with_a_parent() -> TestResult {
        let fixture = EndpointFixture::new()?;
        for endpoint in ["run/provider.sock", "/"] {
            assert_eq!(
                remove_stale_endpoint(fixture.root.path(), Path::new(endpoint), fixture.owner),
                Err(SelectorBoundaryError::ArtifactInvalid),
                "{endpoint}"
            );
        }
        assert_eq!(
            remove_stale_endpoint(
                &fixture.root.path().join("missing"),
                Path::new("/run/provider.sock"),
                fixture.owner
            ),
            Err(SelectorBoundaryError::Io)
        );
        Ok(())
    }

    #[test]
    fn connect_refusal_is_the_only_accepted_probe_result() -> TestResult {
        let fixture = EndpointFixture::new()?;
        assert_eq!(
            require_refused(&fixture.leaf()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        let long = fixture.root.path().join("x".repeat(200));
        assert_eq!(
            require_refused(&long),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        fixture.refusing_socket(0o600)?;
        assert_eq!(require_refused(&fixture.leaf()), Ok(()));
        Ok(())
    }
}
