//! R11 §5.1 steps 7 and 9 to 11 and §5.3: the staging directory and its
//! sweep, the opened ledger, and restart reconciliation over a fake systemd
//! manager and fake network ports, as root in the isolated container
//! (invariants 4 and 14).

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::future::Future;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::selector::installation::{InstalledSelectorState, SANDBOX_ARTIFACT_ROOT};
use tokio::time::Instant;
use zbus::OwnedObjectPath;

use super::{
    capture_store_over, ledger, open_capture_store, open_staging, prepare_host, prepare_with,
    retained_floor, sweep_captures, sweep_staging, HostReconciliation, Reconcile, ReconcileError,
    ROOT,
};
use crate::provider_runtime::tests::{
    bind_as_provider, in_isolated_root, install_spi1, spi1, TestResult, RUNTIME_SEED,
};
use crate::provider_runtime::{serve_with, ProviderRuntimeError, RuntimeAuthority};
use crate::test_fixtures::peer_connections;
use crate::{
    ControlFloor, EgressProbe, EgressPropertyProbe, NetworkRange, OrphanNetworkCleanup,
    RestartReconciliationError, StagingLimits, SystemdAttemptRegistry,
    SystemdTransientUnitTransport,
};

/// A staged input's name: 32 lowercase hexadecimal characters.
const STAGED: &str = "0123456789abcdef0123456789abcdef";

/// A private temporary directory and its owner.
fn private_directory() -> TestResult<(tempfile::TempDir, File, u32)> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let held = File::open(directory.path())?;
    let owner = held.metadata()?.uid();
    Ok((directory, held, owner))
}

#[test]
fn the_staging_directory_is_created_private_and_refused_when_unsafe() -> TestResult {
    let (directory, held, owner) = private_directory()?;
    let staging = directory.path().join("staging");
    // Absent: created with mode 0700, then reopened as it is.
    let created = open_staging(&held, owner).ok_or("not created")?;
    assert_eq!(created.metadata()?.mode() & 0o7777, 0o700);
    assert_eq!(
        open_staging(&held, owner)
            .ok_or("not reopened")?
            .metadata()?
            .ino(),
        created.metadata()?.ino()
    );
    // Another owner, another mode, a symlink and a regular file are refused.
    assert!(open_staging(&held, owner + 1).is_none());
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o750))?;
    assert!(open_staging(&held, owner).is_none());
    fs::remove_dir(&staging)?;
    let target = directory.path().join("target");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
    symlink(&target, &staging)?;
    assert!(open_staging(&held, owner).is_none());
    fs::remove_file(&staging)?;
    fs::write(&staging, b"")?;
    assert!(open_staging(&held, owner).is_none());
    assert!(staging.is_file());
    Ok(())
}

#[test]
fn the_sweep_removes_staged_inputs_and_refuses_anything_else() -> TestResult {
    let (directory, held, owner) = private_directory()?;
    let staging = open_staging(&held, owner).ok_or("not created")?;
    let path = directory.path().join("staging");
    // Empty, then two staged inputs.
    sweep_staging(&staging)?;
    for name in [STAGED, "ffffffffffffffffffffffffffffffff"] {
        fs::write(path.join(name), b"input")?;
    }
    sweep_staging(&staging)?;
    assert_eq!(fs::read_dir(&path)?.count(), 0);
    // Any other name or kind fails closed and is kept.
    let short = &STAGED[1..];
    let upper = STAGED.to_uppercase();
    for name in ["notes", short, upper.as_str()] {
        fs::write(path.join(name), b"")?;
        assert!(matches!(
            sweep_staging(&staging),
            Err(ReconcileError::Staging)
        ));
        assert!(path.join(name).is_file());
        fs::remove_file(path.join(name))?;
    }
    fs::create_dir(path.join(STAGED))?;
    assert!(matches!(
        sweep_staging(&staging),
        Err(ReconcileError::Staging)
    ));
    fs::remove_dir(path.join(STAGED))?;
    symlink(directory.path(), path.join(STAGED))?;
    assert!(matches!(
        sweep_staging(&staging),
        Err(ReconcileError::Staging)
    ));
    assert!(path.join(STAGED).is_symlink());
    // A descriptor that is no directory cannot be listed.
    fs::write(directory.path().join("file"), b"")?;
    assert!(matches!(
        sweep_staging(&File::open(directory.path().join("file"))?),
        Err(ReconcileError::Staging)
    ));
    assert_eq!(
        ReconcileError::Staging.to_string(),
        "the provider staging directory could not be swept"
    );
    Ok(())
}

/// A published capture's name: 64 lowercase hexadecimal characters.
fn published() -> String {
    "5e".repeat(32)
}

/// A crash temporary of the published capture.
fn temporary() -> String {
    format!(".partial-{}-{}", published(), "0a".repeat(16))
}

#[test]
fn the_capture_store_opens_only_private_retention_directories() -> TestResult {
    // The root's own checks are `open_capture_store_root`'s (pos-reference).
    let (directory, held, _) = private_directory()?;
    // Both retention directories are created with mode 0700 over the held
    // root, then reopened as they are.
    let (root, _store) = capture_store_over(held.try_clone()?).ok_or("not created")?;
    assert_eq!(root.metadata()?.ino(), held.metadata()?.ino());
    for child in ["responses", "transcripts"] {
        let path = directory.path().join(child);
        assert_eq!(fs::metadata(&path)?.mode() & 0o7777, 0o700);
    }
    capture_store_over(held.try_clone()?).ok_or("not reopened")?;
    // A retention directory of another mode, a symlink or a file is refused.
    for child in ["responses", "transcripts"] {
        let path = directory.path().join(child);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        assert!(capture_store_over(held.try_clone()?).is_none());
        fs::remove_dir(&path)?;
        symlink(directory.path(), &path)?;
        assert!(capture_store_over(held.try_clone()?).is_none());
        fs::remove_file(&path)?;
        fs::write(&path, b"")?;
        assert!(capture_store_over(held.try_clone()?).is_none());
        fs::remove_file(&path)?;
    }
    Ok(())
}

#[test]
fn the_capture_sweep_removes_temporaries_keeps_records_and_refuses_the_rest() -> TestResult {
    let (directory, _, owner) = private_directory()?;
    let path = directory.path().join("captures");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let (root, store) = capture_store_over(File::open(&path)?).ok_or("not created")?;
    sweep_captures(&root, &store, owner)?;
    // A temporary is unlinked; a published record is kept byte for byte.
    let record = path.join("transcripts").join(published());
    fs::write(&record, b"record")?;
    fs::set_permissions(&record, fs::Permissions::from_mode(0o400))?;
    for child in ["responses", "transcripts"] {
        fs::write(path.join(child).join(temporary()), b"partial")?;
    }
    sweep_captures(&root, &store, owner)?;
    assert_eq!(fs::read_dir(path.join("responses"))?.count(), 0);
    assert_eq!(fs::read(&record)?, b"record");
    // A record of another owner fails closed and is kept.
    assert!(matches!(
        sweep_captures(&root, &store, owner.wrapping_add(1)),
        Err(ReconcileError::Captures)
    ));
    assert_eq!(fs::read(&record)?, b"record");
    // Any other entry of the root or of a retention directory fails closed
    // and is kept.
    for name in ["notes", "staging"] {
        fs::write(path.join(name), b"")?;
        assert!(matches!(
            sweep_captures(&root, &store, owner),
            Err(ReconcileError::Captures)
        ));
        assert!(path.join(name).is_file());
        fs::remove_file(path.join(name))?;
    }
    fs::write(path.join("responses").join("notes"), b"")?;
    assert!(matches!(
        sweep_captures(&root, &store, owner),
        Err(ReconcileError::Captures)
    ));
    assert!(path.join("responses").join("notes").is_file());
    // A root descriptor that is no directory cannot be listed.
    fs::write(directory.path().join("file"), b"")?;
    assert!(matches!(
        sweep_captures(&File::open(directory.path().join("file"))?, &store, owner),
        Err(ReconcileError::Captures)
    ));
    assert_eq!(
        ReconcileError::Captures.to_string(),
        "the network capture store could not be swept"
    );
    Ok(())
}

#[test]
fn the_ledger_opens_with_the_spi1_cap_and_the_retained_floor() -> TestResult {
    let floor = ControlFloor {
        revocation_epoch: 3,
        policy_epoch: 4,
    };
    let opened = ledger(
        StagingLimits {
            aggregate_bytes: 10,
        },
        floor,
    );
    assert_eq!(opened.usage().floor, floor);
    let charge = opened.reserve_storage(10)?;
    assert!(opened.reserve_storage(1).is_err());
    drop(charge);
    Ok(())
}

type UnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// A systemd manager with no attempt unit loaded, counting the
/// subscriptions and the listings.
struct Manager {
    calls: Arc<[AtomicUsize; 2]>,
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    fn subscribe(&self) {
        self.calls[0].fetch_add(1, Ordering::SeqCst);
    }

    fn list_units_by_patterns(&self, states: Vec<String>, patterns: Vec<String>) -> Vec<UnitRow> {
        // The interface macro reads every argument, so an underscore name is
        // refused; the filters are owned and unused.
        drop((states, patterns));
        self.calls[1].fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }
}

/// A transport over a fake manager whose connection `servers` keeps.
async fn fake_bus(
    servers: &Mutex<Vec<zbus::Connection>>,
    calls: &Arc<[AtomicUsize; 2]>,
) -> TestResult<SystemdTransientUnitTransport> {
    let manager = Manager {
        calls: Arc::clone(calls),
    };
    let (server, client) =
        peer_connections(|server| server.serve_at("/org/freedesktop/systemd1", manager)).await?;
    servers
        .lock()
        .map_err(|_| "the server list is poisoned")?
        .push(server);
    Ok(SystemdTransientUnitTransport::from_connection(client).await?)
}

#[derive(Debug, thiserror::Error)]
#[error("injected network failure")]
struct Injected;

/// An orphan sweep that removes everything unless it `fails`.
struct Network {
    fails: bool,
}

impl OrphanNetworkCleanup for Network {
    type Error = Injected;

    fn remove_orphans(&self) -> impl Future<Output = Result<(), Injected>> + Send {
        std::future::ready(if self.fails { Err(Injected) } else { Ok(()) })
    }
}

/// An egress probe that observes the property.
struct Egress;

impl EgressPropertyProbe for Egress {
    type Error = Injected;

    fn probe_egress(&self) -> impl Future<Output = Result<(), Injected>> + Send {
        std::future::ready(Ok(()))
    }
}

/// An orphan sweep and egress probe that both succeed.
const fn clean_network(_: NetworkRange, _: EgressProbe) -> (Network, Egress) {
    (Network { fails: false }, Egress)
}

/// Create `path` as a root directory of `mode`.
fn directory(path: &str, mode: u32) -> TestResult {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// The provider state directories a reconciling host holds.
fn provider_state() -> TestResult {
    directory("/run/pigloros", 0o755)?;
    for path in [
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/registry",
        "/run/pigloros/sandbox/attempts",
    ] {
        directory(path, 0o700)?;
    }
    directory(&format!("{SANDBOX_ARTIFACT_ROOT}/images"), 0o755)
}

/// Under a umask that strips the owner's bits, the store root and both
/// retention directories are still created with mode exactly 0700. The
/// isolated test is the only one in its process, so the umask is its own.
fn creates_a_private_store_under_a_strict_umask(
    installed: &InstalledSelectorState,
    captures: &Path,
) -> TestResult {
    let umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o277));
    let opened = open_capture_store(installed, ROOT);
    rustix::process::umask(umask);
    drop(opened.ok_or("the capture store was not created")?);
    for path in [
        captures.to_owned(),
        captures.join("responses"),
        captures.join("transcripts"),
    ] {
        assert_eq!(fs::metadata(path)?.mode() & 0o7777, 0o700);
    }
    Ok(())
}

/// One unsafe capture store: `break_store` makes it from a sound store,
/// `repair` restores the sound store, and `through_startup` runs the whole
/// `provider-runtime` startup over it instead of step 7 alone.
struct UnsafeStore {
    break_store: fn(&Path) -> std::io::Result<()>,
    repair: fn(&Path) -> std::io::Result<()>,
    through_startup: bool,
}

/// Invariant 38's unsafe stores: a root or a retention directory of another
/// mode, a symlinked root and a non-directory root.
const UNSAFE_STORES: [UnsafeStore; 4] = [
    UnsafeStore {
        break_store: |captures| fs::set_permissions(captures, fs::Permissions::from_mode(0o755)),
        repair: |captures| fs::set_permissions(captures, fs::Permissions::from_mode(0o700)),
        through_startup: false,
    },
    UnsafeStore {
        break_store: |captures| {
            fs::set_permissions(
                captures.join("responses"),
                fs::Permissions::from_mode(0o755),
            )
        },
        repair: |captures| {
            fs::set_permissions(
                captures.join("responses"),
                fs::Permissions::from_mode(0o700),
            )
        },
        through_startup: false,
    },
    UnsafeStore {
        break_store: |captures| {
            fs::rename(captures, moved(captures)).and_then(|()| symlink(moved(captures), captures))
        },
        repair: restore_root,
        through_startup: true,
    },
    UnsafeStore {
        break_store: |captures| {
            fs::rename(captures, moved(captures)).and_then(|()| fs::write(captures, b""))
        },
        repair: restore_root,
        through_startup: false,
    },
];

/// Where a test moves the sound store root aside.
fn moved(captures: &Path) -> std::path::PathBuf {
    captures.with_file_name("moved")
}

/// Replace whatever is at `captures` by the root moved aside.
fn restore_root(captures: &Path) -> std::io::Result<()> {
    fs::remove_file(captures).and_then(|()| fs::rename(moved(captures), captures))
}

/// Invariant 38: every unsafe store fails step 7 closed, and is left sound.
fn refuses_an_unsafe_store(
    authority: &RuntimeAuthority,
    captures: &Path,
    servers: &Mutex<Vec<zbus::Connection>>,
    calls: &Arc<[AtomicUsize; 2]>,
) -> TestResult {
    UNSAFE_STORES
        .iter()
        .try_for_each(|store| refuses_one(store, authority, captures, (servers, calls)))
}

/// Break the store as `store` says, check step 7 refuses it, then repair it.
fn refuses_one(
    store: &UnsafeStore,
    authority: &RuntimeAuthority,
    captures: &Path,
    (servers, calls): (&Mutex<Vec<zbus::Connection>>, &Arc<[AtomicUsize; 2]>),
) -> TestResult {
    (store.break_store)(captures)?;
    let refused = if store.through_startup {
        serves_nothing_over_an_unsafe_store(servers, calls)
    } else {
        step_7_refuses(authority, servers, calls)
    };
    (store.repair)(captures)?;
    refused
}

/// Step 7 alone refuses with `HostUnavailable`.
fn step_7_refuses(
    authority: &RuntimeAuthority,
    servers: &Mutex<Vec<zbus::Connection>>,
    calls: &Arc<[AtomicUsize; 2]>,
) -> TestResult {
    matches!(
        prepare_with(authority, || true, fake_bus(servers, calls), clean_network),
        Err(ProviderRuntimeError::HostUnavailable)
    )
    .then_some(())
    .ok_or_else(|| "step 7 accepted an unsafe capture store".into())
}

/// The abstract notification socket a refused startup must never notify.
const NOTIFY: &str = "@pigloros-capture-store-notify";

/// A service manager listening on [`NOTIFY`], waiting 200 ms for a datagram.
fn notify_manager() -> std::io::Result<UnixDatagram> {
    SocketAddr::from_abstract_name(&NOTIFY[1..])
        .and_then(|address| UnixDatagram::bind_addr(&address))
        .and_then(|manager| {
            manager
                .set_read_timeout(Some(Duration::from_millis(200)))
                .map(|()| manager)
        })
}

/// Run the whole `provider-runtime` startup over a capture store step 7
/// refuses: it exits with `HostUnavailable`, binds neither endpoint and
/// never sends `READY=1` (invariant 38).
fn serves_nothing_over_an_unsafe_store(
    servers: &Mutex<Vec<zbus::Connection>>,
    calls: &Arc<[AtomicUsize; 2]>,
) -> TestResult {
    let manager = notify_manager()?;
    let authority = bind_as_provider()??;
    let (execute, control) = authority
        .0
        .bootstrap()
        .installed()
        .manifest()
        .provider_sockets();
    let endpoints = [execute.to_owned(), control.to_owned()];
    assert_eq!(
        serve_with(
            move || Ok(authority),
            |authority| prepare_with(authority, || true, fake_bus(servers, calls), clean_network),
            Some(OsStr::new(NOTIFY)),
        ),
        ProviderRuntimeError::HostUnavailable
    );
    assert!(endpoints.iter().all(|endpoint| !endpoint.exists()));
    assert!(manager.recv(&mut [0; 16]).is_err(), "READY=1 was sent");
    Ok(())
}

/// Step 7 over a host whose sysctl probe passes and whose network is clean.
fn prepare_clean(
    authority: &RuntimeAuthority,
    servers: &Mutex<Vec<zbus::Connection>>,
    calls: &Arc<[AtomicUsize; 2]>,
) -> Result<HostReconciliation<Network, Egress>, ProviderRuntimeError> {
    prepare_with(authority, || true, fake_bus(servers, calls), clean_network)
}

/// ADR-069 R14 N12: a host whose fallback-tunnel sysctl probe fails is
/// refused before the bus is connected or any port is built.
fn refuses_a_host_without_the_sysctl(
    authority: &RuntimeAuthority,
    servers: &Mutex<Vec<zbus::Connection>>,
    calls: &Arc<[AtomicUsize; 2]>,
) -> TestResult {
    let built = Cell::new(false);
    assert!(matches!(
        prepare_with(
            authority,
            || false,
            fake_bus(servers, calls),
            |range, probe| {
                built.set(true);
                clean_network(range, probe)
            }
        ),
        Err(ProviderRuntimeError::HostUnavailable)
    ));
    assert!(!built.get());
    assert!(servers.lock().map_err(|_| "poisoned")?.is_empty());
    assert_eq!(
        calls.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [0, 0]
    );
    Ok(())
}

#[test]
fn reconciliation_opens_admission_only_over_a_clean_host() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::reconcile::tests::reconciliation_opens_admission_only_over_a_clean_host",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution()?;
    install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
    let authority = bind_as_provider()??;
    let (admitted, installation, _) = &authority;
    let captures = Path::new(SANDBOX_ARTIFACT_ROOT).join("captures");
    // Step 7 here has no system bus, and creates no capture store.
    let host = prepare_host(&authority);
    assert!(matches!(host, Err(ProviderRuntimeError::HostUnavailable)));
    assert!(!captures.exists(), "the capture store was created");
    creates_a_private_store_under_a_strict_umask(admitted.bootstrap().installed(), &captures)?;
    provider_state()?;
    let staging = Path::new("/run/pigloros/sandbox/staging");
    let servers = Mutex::new(Vec::new());
    let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    refuses_a_host_without_the_sysctl(&authority, &servers, &calls)?;
    // A failed orphan sweep keeps admission closed; staging is not swept.
    let built = Cell::new(None);
    let failing = |range, probe| {
        built.set(Some((range, probe)));
        (Network { fails: true }, Egress)
    };
    let host = prepare_with(&authority, || true, fake_bus(&servers, &calls), failing)?;
    // The ports are built for the SPI1 attempt range and egress probe.
    assert_eq!(
        built.get(),
        Some((installation.attempt_range(), installation.egress_probe()))
    );
    // The SPI1 grace, shutdown, unit-absent and released phases (500, 1500,
    // 3000 and 5000 ms) start when reconciliation does, within the fixed
    // 10 s bound.
    let now = Instant::now();
    let (cleanup, deadline) = host.restart_bounds(now);
    assert_eq!(
        (
            cleanup.shutdown().grace(),
            cleanup.shutdown().overall(),
            cleanup.unit_absent(),
            cleanup.released(),
            deadline
        ),
        (
            now + Duration::from_millis(500),
            now + Duration::from_millis(1500),
            now + Duration::from_secs(3),
            now + Duration::from_secs(5),
            now + Duration::from_secs(10)
        )
    );
    assert_eq!(host.limits, installation.staging_limits());
    assert_eq!(host.floor, retained_floor(admitted));
    assert_eq!(
        fs::metadata(staging)?.mode() & 0o7777,
        0o700,
        "step 7 creates the staging directory"
    );
    fs::write(staging.join(STAGED), b"input")?;
    let refused = host.reconcile();
    assert!(matches!(
        refused,
        Err(ReconcileError::Restart(
            RestartReconciliationError::Network(_)
        ))
    ));
    assert_eq!(
        refused.err().as_ref().map(ToString::to_string),
        Some("orphaned network state could not be removed".to_owned())
    );
    assert!(staging.join(STAGED).is_file());
    // An entry that is no staged input fails reconciliation closed.
    fs::create_dir(staging.join("directory"))?;
    let host = prepare_clean(&authority, &servers, &calls)?;
    assert!(matches!(host.reconcile(), Err(ReconcileError::Staging)));
    fs::remove_dir(staging.join("directory"))?;
    refuses_an_unsafe_store(&authority, &captures, &servers, &calls)?;
    // An entry of the capture store that is neither a published record nor
    // a temporary fails reconciliation closed, after the staging sweep.
    // Invariant 39: a published record survives every sweep.
    let record = captures.join("transcripts").join(published());
    fs::write(&record, b"record")?;
    fs::set_permissions(&record, fs::Permissions::from_mode(0o400))?;
    fs::write(captures.join("responses").join(temporary()), b"partial")?;
    fs::write(captures.join("notes"), b"")?;
    let host = prepare_clean(&authority, &servers, &calls)?;
    assert!(matches!(host.reconcile(), Err(ReconcileError::Captures)));
    assert!(captures.join("notes").is_file());
    fs::remove_file(captures.join("notes"))?;
    // A clean host: the staging directory is emptied, the capture temporary
    // removed, the published record kept byte for byte, and the lifecycle
    // holds the registry for the life of the process.
    let host = prepare_clean(&authority, &servers, &calls)?;
    let lifecycle = host.reconcile()?;
    // Each step 7 subscribed, and each reconciliation listed the units.
    assert_eq!(
        calls.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [8, 4]
    );
    assert_eq!(fs::read_dir(staging)?.count(), 0);
    assert_eq!(fs::read_dir(captures.join("responses"))?.count(), 0);
    assert_eq!(fs::read(&record)?, b"record");
    assert_eq!(fs::metadata(&record)?.mode() & 0o7777, 0o400);
    assert_eq!(fs::read_dir(captures.join("transcripts"))?.count(), 1);
    assert!(SystemdAttemptRegistry::open().is_err());
    drop(lifecycle);
    assert!(SystemdAttemptRegistry::open().is_ok());
    drop(servers);
    drop(authority);
    drop(staged);
    Ok(())
}

/// ADR-069 R12 §7.1 steps 3 to 7 and I19, as the root selector runs them
/// on this host: the SPI1 cleanup budget, the exclusive registry, the
/// foreign-intent check before any cleanup, `reconcile_cleanup` and never the
/// egress probe, and the registry lock free as soon as it returns.
#[test]
fn the_selector_cleanup_refuses_foreign_intents_and_releases_the_lock() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::reconcile::tests::the_selector_cleanup_refuses_foreign_intents_and_releases_the_lock",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution()?;
    install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
    directory("/run/pigloros", 0o755)?;
    for path in [
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/registry",
        "/run/pigloros/sandbox/attempts",
    ] {
        directory(path, 0o700)?;
    }
    directory(&format!("{SANDBOX_ARTIFACT_ROOT}/images"), 0o755)?;
    let servers = Mutex::new(Vec::new());
    let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let transport = runtime.block_on(fake_bus(&servers, &calls))?;
    let registry = Path::new("/run/pigloros/sandbox/registry");
    let lock_is_free = || -> TestResult<bool> {
        Ok(rustix::fs::flock(
            &File::open(registry)?,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .is_ok())
    };
    let cleanup = |live: &[[u8; 16]], fails: bool| {
        runtime.block_on(crate::provider_lifecycle::host_cleanup(
            &transport,
            live,
            Instant::now() + Duration::from_secs(10),
            Network { fails },
        ))
    };

    // An intent of an attempt SIR1 does not name is refused before any
    // cleanup step, and the lock is released.
    SystemdAttemptRegistry::open()?
        .commit_planned(&crate::PlannedAttemptIntent::new([9; 16], [2; 32])?)?;
    let records = fs::read_dir(registry)?.count();
    assert_eq!(
        cleanup(&[], false),
        Err(pos_reference::selector::runtime_lifecycle::ProviderLifecycleError::ForeignResource)
    );
    assert_eq!(fs::read_dir(registry)?.count(), records);
    assert!(lock_is_free()?);
    assert_eq!(calls[1].load(Ordering::SeqCst), 0, "no unit was listed");
    for entry in fs::read_dir(registry)? {
        let entry = entry?;
        if entry.file_name() != "activation" {
            fs::remove_file(entry.path())?;
        }
    }

    // A failed orphan sweep is a residue.
    assert_eq!(
        cleanup(&[], true),
        Err(pos_reference::selector::runtime_lifecycle::ProviderLifecycleError::ResidualResource)
    );
    assert!(lock_is_free()?);
    // A clean host reconciles nothing, and the lock is free at once.
    // No activation was recorded, so no wait was applied.
    assert_eq!(cleanup(&[[9; 16]], false), Ok((Vec::new(), Duration::ZERO)));
    assert!(lock_is_free()?);
    assert!(SystemdAttemptRegistry::open().is_ok());
    drop(servers);
    drop(staged);
    Ok(())
}
