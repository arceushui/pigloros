//! The pin, the activation anchor and the terminal reads over one fake
//! manager connection (ADR-069 R9 §4.6.5 to §4.6.7).

use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::sync::{Arc, Mutex};

use zbus::{fdo, OwnedObjectPath};

use super::*;
use crate::system_bus::test_support::peer_connections;
use crate::system_bus::SystemdStartJob;
use crate::{
    AttemptLimitEventCounter, CgroupRoot, SystemdManagerReadback,
    SystemdManagerReadbackOnlyProperty, SystemdServiceResult,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/attempt";
const ACTIVATED_US: u64 = 1_234_567;
const INVOCATION: [u8; 16] = [0x21; 16];

#[derive(Debug, Default)]
struct Bus {
    /// `RefUnit` and `UnrefUnit` calls, in order.
    calls: Vec<String>,
    refuse_ref: bool,
    refuse_unref: bool,
    /// Successive `ActiveState` reads; the last one repeats.
    states: VecDeque<String>,
    activated_us: u64,
}

type Shared = Arc<Mutex<Bus>>;

fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}

struct Manager(Shared);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    async fn ref_unit(&self, name: String) -> fdo::Result<()> {
        let mut bus = self.0.lock().map_err(failed)?;
        bus.calls.push(format!("ref {name}"));
        if bus.refuse_ref {
            Err(fdo::Error::AccessDenied("ref refused".to_owned()))
        } else {
            Ok(())
        }
    }

    async fn unref_unit(&self, name: String) -> fdo::Result<()> {
        let mut bus = self.0.lock().map_err(failed)?;
        bus.calls.push(format!("unref {name}"));
        if bus.refuse_unref {
            Err(fdo::Error::Failed("not referenced".to_owned()))
        } else {
            Ok(())
        }
    }
}

struct Unit(Shared);

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl Unit {
    #[zbus(property, name = "ActiveState")]
    fn active_state(&self) -> fdo::Result<String> {
        let mut bus = self.0.lock().map_err(failed)?;
        let state = if bus.states.len() > 1 {
            bus.states.pop_front()
        } else {
            bus.states.front().cloned()
        };
        state.ok_or_else(|| failed("no ActiveState"))
    }

    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        INVOCATION.to_vec()
    }

    #[zbus(property, name = "ActiveEnterTimestampMonotonic")]
    fn active_enter_timestamp_monotonic(&self) -> fdo::Result<u64> {
        Ok(self.0.lock().map_err(failed)?.activated_us)
    }
}

struct Service;

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl Service {
    #[zbus(property, name = "Result")]
    fn result(&self) -> String {
        "success".to_owned()
    }

    #[zbus(property, name = "ExecMainCode")]
    fn exec_main_code(&self) -> i32 {
        1
    }

    #[zbus(property, name = "ExecMainStatus")]
    fn exec_main_status(&self) -> i32 {
        0
    }
}

/// A fake manager peer, its transport, and a bound cgroup whose sources are
/// all present.
struct Fixture {
    bus: Shared,
    _server: zbus::Connection,
    transport: SystemdTransientUnitTransport,
    started: SystemdVerifiedStart,
    cgroup: BoundAttemptCgroup,
    directory: std::path::PathBuf,
    _root: tempfile::TempDir,
}

const CGROUP_SOURCES: [(&str, &[u8]); 8] = [
    ("memory.events.local", b"low 0\nmax 0\noom_kill 0\n"),
    ("memory.swap.events", b"max 0\nfail 0\n"),
    ("pids.events.local", b"max 0\n"),
    (
        "cpu.stat",
        b"usage_usec 9\nnr_throttled 0\nthrottled_usec 0\n",
    ),
    ("memory.max", b"max\n"),
    ("memory.swap.max", b"0\n"),
    ("pids.max", b"64\n"),
    ("cpu.max", b"50000 100000\n"),
];

impl Fixture {
    async fn new(states: &[&str]) -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("attempt");
        fs::create_dir(&directory)?;
        fs::write(directory.join("cgroup.events"), b"populated 0\n")?;
        for (name, bytes) in CGROUP_SOURCES {
            fs::write(directory.join(name), bytes)?;
        }
        let unit_name = TransientServiceUnitName::from_attempt_id([0x40; 16])?;
        let cgroup = BoundAttemptCgroup::open(
            CgroupRoot::for_test(fs::File::open(root.path())?),
            unit_name.clone(),
            OwnedObjectPath::try_from(UNIT_PATH)?,
            "/attempt".to_owned(),
        )?;
        let bus = Arc::new(Mutex::new(Bus {
            states: states.iter().map(|state| (*state).to_owned()).collect(),
            activated_us: ACTIVATED_US,
            ..Bus::default()
        }));
        let (server, client) = peer_connections(|server| {
            server
                .serve_at("/org/freedesktop/systemd1", Manager(Arc::clone(&bus)))
                .serve_at(UNIT_PATH, Unit(Arc::clone(&bus)))
                .serve_at(UNIT_PATH, Service)
        })
        .await?;
        let started = SystemdVerifiedStart {
            unit_name,
            job: SystemdStartJob(OwnedObjectPath::try_from(
                "/org/freedesktop/systemd1/job/7",
            )?),
            unit_path: OwnedObjectPath::try_from(UNIT_PATH)?,
            requested_readback: Vec::new(),
            manager_readback: SystemdManagerReadback::new(
                SystemdManagerReadbackOnlyProperty::RootImagePolicy,
                "",
            ),
            requested: Vec::new(),
        };
        Ok(Self {
            bus,
            _server: server,
            transport: SystemdTransientUnitTransport { connection: client },
            started,
            cgroup,
            directory,
            _root: root,
        })
    }

    fn calls(&self) -> TestResult<Vec<String>> {
        Ok(self.bus.lock().map_err(|_| "poisoned")?.calls.clone())
    }

    fn set(&self, change: impl FnOnce(&mut Bus)) -> TestResult {
        change(&mut *self.bus.lock().map_err(|_| "poisoned")?);
        Ok(())
    }

    fn unit(&self) -> &TransientServiceUnitName {
        &self.started.unit_name
    }

    async fn conclude(&self, started: Option<&SystemdVerifiedStart>) -> TerminalResources {
        let settle_by = Instant::now() + Duration::from_millis(200);
        self.transport
            .conclude(self.unit(), started, &self.cgroup, None, settle_by)
            .await
    }
}

fn named(call: &str, unit: &TransientServiceUnitName) -> String {
    format!("{call} {}", unit.as_str())
}

#[tokio::test]
async fn the_unit_is_referenced_before_its_cgroup_is_bound() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    let bound = fixture
        .transport
        .pinned(fixture.unit(), async { Ok(7) })
        .await?;
    assert_eq!(bound, 7);
    assert_eq!(fixture.calls()?, [named("ref", fixture.unit())]);
    Ok(())
}

#[tokio::test]
async fn a_failed_bind_releases_the_reference_it_took() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    let bound = fixture
        .transport
        .pinned(fixture.unit(), async {
            Err::<(), _>(SystemdTransientUnitTransportError::CgroupUnitMismatch)
        })
        .await;
    assert!(matches!(
        bound,
        Err(SystemdTransientUnitTransportError::CgroupUnitMismatch)
    ));
    assert_eq!(
        fixture.calls()?,
        [named("ref", fixture.unit()), named("unref", fixture.unit())]
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_reference_binds_nothing() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    fixture.set(|bus| bus.refuse_ref = true)?;
    let bound = fixture
        .transport
        .pinned(fixture.unit(), async {
            Err::<(), _>(SystemdTransientUnitTransportError::CgroupUnitMismatch)
        })
        .await;
    assert!(matches!(
        bound,
        Err(SystemdTransientUnitTransportError::UnitRef(_))
    ));
    assert_eq!(fixture.calls()?, [named("ref", fixture.unit())]);
    Ok(())
}

#[tokio::test]
async fn an_unbuildable_manager_proxy_neither_pins_nor_unpins() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    let unit = fixture.unit();
    assert!(matches!(
        pin_with(Err(zbus::Error::InvalidReply), unit).await,
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));
    assert!(matches!(
        unpin_with(Err(zbus::Error::InvalidReply), unit).await,
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));
    assert!(fixture.calls()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn the_release_evidence_is_the_activation_and_the_cgroup_before_release() -> TestResult {
    let fixture = Fixture::new(&["active"]).await?;
    let (activated, resources) = fixture
        .transport
        .release_resources(&fixture.started, &fixture.cgroup)
        .await?;
    assert_eq!(activated, ACTIVATED_US * NANOSECONDS_PER_MICROSECOND);
    assert_eq!(resources.activated_monotonic_ns(), activated);
    assert_eq!(
        resources
            .baseline()
            .counter(AttemptLimitEventCounter::PidsMax),
        0
    );
    assert_eq!(
        resources.effective().cgroup_identity(),
        resources.baseline().cgroup_identity()
    );
    Ok(())
}

#[tokio::test]
async fn an_unset_activation_is_missing_evidence() -> TestResult {
    let fixture = Fixture::new(&["active"]).await?;
    fixture.set(|bus| bus.activated_us = 0)?;
    let read = fixture
        .transport
        .release_resources(&fixture.started, &fixture.cgroup)
        .await;
    assert!(matches!(
        read,
        Err(SystemdTransientUnitTransportError::ActivationUnset)
    ));
    fixture.set(|bus| bus.activated_us = u64::MAX)?;
    let read = fixture
        .transport
        .release_resources(&fixture.started, &fixture.cgroup)
        .await;
    assert!(matches!(
        read,
        Err(SystemdTransientUnitTransportError::ActivationUnset)
    ));
    Ok(())
}

#[tokio::test]
async fn an_unreadable_activation_is_missing_evidence() -> TestResult {
    let mut fixture = Fixture::new(&["active"]).await?;
    fixture.started.unit_path = OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/gone")?;
    let read = fixture
        .transport
        .release_resources(&fixture.started, &fixture.cgroup)
        .await;
    assert!(matches!(
        read,
        Err(SystemdTransientUnitTransportError::PropertyReadback {
            property: "ActiveEnterTimestampMonotonic",
            ..
        })
    ));
    assert!(matches!(
        activated_with(Err(zbus::Error::InvalidReply)).await,
        Err(SystemdTransientUnitTransportError::ServiceProxy(_))
    ));
    Ok(())
}

#[tokio::test]
async fn unreadable_cgroup_sources_are_missing_evidence() -> TestResult {
    let fixture = Fixture::new(&["active"]).await?;
    fs::remove_file(fixture.directory.join("memory.max"))?;
    let read = fixture
        .transport
        .release_resources(&fixture.started, &fixture.cgroup)
        .await;
    assert!(matches!(
        read,
        Err(SystemdTransientUnitTransportError::EffectiveLimits(_))
    ));
    fs::remove_file(fixture.directory.join("pids.events.local"))?;
    let read = fixture
        .transport
        .release_resources(&fixture.started, &fixture.cgroup)
        .await;
    assert!(matches!(
        read,
        Err(SystemdTransientUnitTransportError::CgroupKernel(_))
    ));
    Ok(())
}

#[tokio::test]
async fn an_exited_unit_is_measured_read_and_then_unpinned() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    let work = fs::File::open("/dev/shm")?;
    let settle_by = Instant::now() + Duration::from_millis(200);
    let terminal = fixture
        .transport
        .conclude(
            fixture.unit(),
            Some(&fixture.started),
            &fixture.cgroup,
            Some(&work),
            settle_by,
        )
        .await;
    let snapshot = terminal
        .terminal()
        .as_ref()
        .map_err(|error| error.to_string())?;
    assert_eq!(snapshot.counter(AttemptLimitEventCounter::MemoryOomKill), 0);
    assert!(matches!(terminal.work_after(), Some(Ok(_))));
    let service = terminal
        .service()
        .as_ref()
        .map_err(|error| error.to_string())?;
    assert_eq!(service.result(), SystemdServiceResult::Success);
    assert!(terminal.unpinned().is_ok());
    assert_eq!(fixture.calls()?, [named("unref", fixture.unit())]);
    Ok(())
}

#[tokio::test]
async fn a_unit_that_settles_late_is_read_once_settled() -> TestResult {
    let fixture = Fixture::new(&["deactivating", "deactivating", "inactive"]).await?;
    let terminal = fixture.conclude(Some(&fixture.started)).await;
    assert!(terminal.service().is_ok());
    Ok(())
}

#[tokio::test]
async fn a_unit_that_never_settles_has_no_result() -> TestResult {
    let fixture = Fixture::new(&["deactivating"]).await?;
    let terminal = fixture.conclude(Some(&fixture.started)).await;
    assert!(matches!(
        terminal.service(),
        Err(TerminalServiceError::Read(
            SystemdUnitResultError::NotSettled { .. }
        ))
    ));
    // The pin is released all the same, so the teardown can see it unloaded.
    assert!(terminal.unpinned().is_ok());
    Ok(())
}

#[tokio::test]
async fn a_failure_before_a_verified_start_has_no_result_to_read() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    fixture.set(|bus| bus.refuse_unref = true)?;
    let terminal = fixture.conclude(None).await;
    assert!(matches!(
        terminal.service(),
        Err(TerminalServiceError::Unstarted)
    ));
    assert!(terminal.work_after().is_none());
    assert!(matches!(
        terminal.unpinned(),
        Err(SystemdTransientUnitTransportError::UnitUnref(_))
    ));
    Ok(())
}

/// R9 §4.6.7: the pin lives with the connection that took it. Once that
/// connection is lost, a successful unit may already be collected, so its
/// result is missing evidence; nothing reads it over another connection.
#[tokio::test]
async fn a_lost_connection_leaves_the_result_missing() -> TestResult {
    let fixture = Fixture::new(&["inactive"]).await?;
    fixture.transport.connection.clone().close().await?;
    let terminal = fixture.conclude(Some(&fixture.started)).await;
    assert!(matches!(
        terminal.service(),
        Err(TerminalServiceError::Read(_))
    ));
    assert!(terminal.unpinned().is_err());
    // The kernel counters do not depend on the connection.
    assert!(terminal.terminal().is_ok());
    Ok(())
}
