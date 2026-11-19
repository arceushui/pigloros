//! R11 §5.1 steps 7 and 9 to 11 and §5.3: the staging directory and its
//! sweep, the opened ledger, and restart reconciliation over a fake systemd
//! manager and fake network ports, as root in the isolated container
//! (invariants 4 and 14).

use std::cell::Cell;
use std::fs::{self, File};
use std::future::Future;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT;
use tokio::time::Instant;
use zbus::OwnedObjectPath;

use super::{
    ledger, open_staging, prepare_host, prepare_with, retained_floor, sweep_staging, Reconcile,
    ReconcileError,
};
use crate::provider_runtime::tests::{
    bind_as_provider, in_isolated_root, install_spi1, spi1, TestResult, RUNTIME_SEED,
};
use crate::provider_runtime::ProviderRuntimeError;
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
    // Step 7 on this host: the container has no system bus.
    assert!(matches!(
        prepare_host(&authority),
        Err(ProviderRuntimeError::HostUnavailable)
    ));
    directory("/run/pigloros", 0o755)?;
    for path in [
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/registry",
        "/run/pigloros/sandbox/attempts",
    ] {
        directory(path, 0o700)?;
    }
    directory(&format!("{SANDBOX_ARTIFACT_ROOT}/images"), 0o755)?;
    let staging = Path::new("/run/pigloros/sandbox/staging");
    let servers = Mutex::new(Vec::new());
    let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    // A failed orphan sweep keeps admission closed; the staging directory
    // step 7 created is not swept.
    let (admitted, installation, _) = &authority;
    let built = Cell::new(None);
    let host = prepare_with(&authority, fake_bus(&servers, &calls), |range, probe| {
        built.set(Some((range, probe)));
        (Network { fails: true }, Egress)
    })?;
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
    let host = prepare_with(&authority, fake_bus(&servers, &calls), clean_network)?;
    assert!(matches!(host.reconcile(), Err(ReconcileError::Staging)));
    fs::remove_dir(staging.join("directory"))?;
    // A clean host: the staging directory is emptied and the lifecycle
    // holds the registry for the life of the process.
    let host = prepare_with(&authority, fake_bus(&servers, &calls), clean_network)?;
    let lifecycle = host.reconcile()?;
    // Each step 7 subscribed, and each reconciliation listed the units.
    assert_eq!(
        calls.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [3, 3]
    );
    assert_eq!(fs::read_dir(staging)?.count(), 0);
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
            || Network { fails },
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
