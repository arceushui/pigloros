use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    sync::MutexGuard,
};

use rustix::io::Errno;

use super::*;
use crate::namespace_network::{
    FirewallTableFamily, IpPrefix, LinkKind, ObservedAddress, ObservedLink, ObservedNamespace,
    ObservedRoute, ObservedTable,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// What the fake kernel was asked to do.
#[derive(Debug, Default)]
struct Journal {
    installed: Vec<String>,
    removed: Vec<String>,
}

/// A kernel that installs exactly what it is asked to, pinning each
/// namespace in `pins` as this process's own, or refuses to install or to
/// remove.
#[derive(Debug, Default)]
struct FakeControl {
    journal: Arc<Mutex<Journal>>,
    pins: Option<std::path::PathBuf>,
    refuse: bool,
    refuse_removal: bool,
    gate: Option<RemovalGate>,
    current: Mutex<Option<ExpectedNamespace>>,
}

/// Holds a removal until another task lets it proceed.
#[derive(Debug)]
struct RemovalGate {
    started: std::sync::mpsc::Sender<()>,
    proceed: Mutex<std::sync::mpsc::Receiver<()>>,
}

fn entries(journal: &Mutex<Journal>) -> MutexGuard<'_, Journal> {
    journal.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The read-back of exactly `expected`.
fn observed_for(expected: &ExpectedNamespace) -> ObservedNamespace {
    let link = |index, name: &LinkName, peer_index, peer| ObservedLink {
        index,
        name: name.as_str().to_owned(),
        kind: LinkKind::Veth {
            peer_index,
            peer_netnsid: Some(peer),
        },
        up: true,
    };
    let on = |link_index, prefixes: &[IpPrefix]| {
        prefixes
            .iter()
            .map(|&address| ObservedAddress {
                link_index,
                address,
            })
            .collect()
    };
    ObservedNamespace {
        links: vec![
            ObservedLink {
                index: 1,
                name: "lo".to_owned(),
                kind: LinkKind::Loopback,
                up: false,
            },
            link(2, &expected.inner_link, 3, 0),
        ],
        addresses: on(2, &expected.inner_addresses),
        routes: expected
            .routes
            .iter()
            .map(|&route| ObservedRoute {
                link_index: 2,
                route,
            })
            .collect(),
        tables: vec![ObservedTable {
            family: FirewallTableFamily::Inet,
            name: expected.table.clone(),
            flags: 0,
            chains: expected.chains.clone(),
        }],
        host_link: Some(link(3, &expected.host_link, 2, 1)),
        host_addresses: on(3, &expected.host_addresses),
        namespace_netnsid: 1,
        host_netnsid: 0,
    }
}

impl NamespaceControl for FakeControl {
    type Error = NetlinkError;

    fn install(&self, expected: &ExpectedNamespace) -> Result<(), NetlinkError> {
        entries(&self.journal)
            .installed
            .push(expected.host_link.as_str().to_owned());
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Some(expected.clone());
        let pinned = self.pins.as_ref().map_or(Ok(()), |pins| {
            std::os::unix::fs::symlink("/proc/self/ns/net", pins.join(expected.name.as_str()))
        });
        (!self.refuse && pinned.is_ok())
            .then_some(())
            .ok_or(NetlinkError::Kernel(-1))
    }

    fn observe(
        &self,
        _name: &NamespaceName,
        _host_link: &LinkName,
    ) -> Result<ObservedNamespace, NetlinkError> {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(observed_for)
            .ok_or(NetlinkError::Unexpected)
    }

    fn remove(&self, name: &NamespaceName, host_link: &LinkName) -> Result<(), NetlinkError> {
        entries(&self.journal)
            .removed
            .push(host_link.as_str().to_owned());
        if let Some(pins) = &self.pins {
            // A pin that was never made is not there to remove.
            std::fs::remove_file(pins.join(name.as_str())).ok();
        }
        let released = self.gate.as_ref().map_or(Ok(()), |gate| {
            gate.started.send(()).ok();
            gate.proceed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv_timeout(Duration::from_secs(2))
        });
        (!self.refuse_removal && released.is_ok())
            .then_some(())
            .ok_or(NetlinkError::Kernel(-16))
    }
}

fn range(ipv4_length: u8, ipv6_length: u8) -> TestResult<NetworkRange> {
    Ok(NetworkRange::new(
        Ipv4Addr::new(10, 213, 0, 0),
        ipv4_length,
        Ipv6Addr::new(0xfd00, 0x913, 0, 0, 0, 0, 0, 0),
        ipv6_length,
    )?)
}

const ENDPOINT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);

/// A network over `control`, whose namespaces are pinned in `directory`.
fn network(
    directory: &std::path::Path,
    control: FakeControl,
    ipv4_length: u8,
) -> TestResult<(NamespacedLocalNetwork<FakeControl>, Arc<Mutex<Journal>>)> {
    let journal = Arc::clone(&control.journal);
    Ok((
        NamespacedLocalNetwork::new(
            control,
            NetworkNamespaces::pinned_under(directory),
            range(ipv4_length, 120)?,
        ),
        journal,
    ))
}

/// A kernel that pins every namespace it installs in `directory`.
fn pinning(directory: &std::path::Path) -> FakeControl {
    FakeControl {
        pins: Some(directory.to_owned()),
        ..FakeControl::default()
    }
}

#[test]
fn an_established_network_holds_its_slot_until_its_connector_is_dropped() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let first = network.establish([1; 16], &[ENDPOINT]);
    // An attempt holds one network at a time.
    let again = network.establish([1; 16], &[ENDPOINT]);
    let second = network.establish([2; 16], &[ENDPOINT]);
    let removed_while_held = entries(&journal).removed.clone();
    let held = first.is_ok() && second.is_ok();
    drop(first);
    // The freed slot is the lowest again.
    let third = network.establish([3; 16], &[ENDPOINT]);
    assert!(held && third.is_ok());
    assert!(matches!(again, Err(AttemptNetworkError::InUse)));
    assert!(removed_while_held.is_empty());
    assert_eq!(
        entries(&journal).installed,
        ["piglor-h0", "piglor-h1", "piglor-h0"]
    );
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    Ok(())
}

#[test]
fn an_existing_namespace_of_the_attempt_is_neither_installed_nor_removed() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::os::unix::fs::symlink(
        "/proc/self/ns/net",
        directory
            .path()
            .join(NamespaceName::for_attempt([1; 16]).as_str()),
    )?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let existing = network.establish([1; 16], &[ENDPOINT]);
    assert!(matches!(existing, Err(AttemptNetworkError::Exists)));
    assert!(entries(&journal).installed.is_empty());
    assert!(entries(&journal).removed.is_empty());
    Ok(())
}

#[test]
fn a_full_range_bad_endpoints_and_a_refusing_kernel_establish_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    // One /30 holds one slot.
    let (single, _) = network(directory.path(), FakeControl::default(), 30)?;
    let refusing_kernel = FakeControl {
        refuse: true,
        ..FakeControl::default()
    };
    let (refusing, journal) = network(directory.path(), refusing_kernel, 24)?;
    let taken = single.slots.take([9; 16]);
    let exhausted = single.establish([1; 16], &[ENDPOINT]);
    drop(taken);
    let unroutable = single.establish([1; 16], &[SocketAddr::from(([192, 0, 2, 10], 0))]);
    let refused = refusing.establish([1; 16], &[ENDPOINT]);
    // Without a pin, the installed namespace cannot be opened, and is
    // removed again.
    let unpinned = single.establish([1; 16], &[ENDPOINT]);
    assert!(matches!(exhausted, Err(AttemptNetworkError::Exhausted)));
    assert!(matches!(
        unroutable,
        Err(AttemptNetworkError::Plan(NetworkPlanError::Endpoint))
    ));
    assert!(matches!(refused, Err(AttemptNetworkError::Establish(_))));
    assert!(matches!(
        unpinned,
        Err(AttemptNetworkError::Open(NetlinkError::Io(Errno::NOENT)))
    ));
    // The refused installation is removed, and the slot is free again.
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    assert!(single
        .slots
        .take([1; 16])
        .is_ok_and(|lease| lease.slot == 0));
    Ok(())
}

#[test]
fn an_install_that_cannot_be_undone_quarantines_its_slot() -> TestResult {
    let directory = tempfile::tempdir()?;
    let broken = FakeControl {
        refuse: true,
        refuse_removal: true,
        ..FakeControl::default()
    };
    let (network, _) = network(directory.path(), broken, 24)?;
    let failed = network.establish([1; 16], &[ENDPOINT]).map(drop);
    assert!(
        matches!(&failed, Err(AttemptNetworkError::Establish(error)) if error.removal.is_some()),
        "{failed:?}"
    );
    assert!(matches!(
        network.establish([2; 16], &[ENDPOINT]),
        Err(AttemptNetworkError::Quarantined { slot: 0, .. })
    ));
    Ok(())
}

#[test]
fn a_failed_removal_quarantines_its_slot_and_closes_the_port() -> TestResult {
    let directory = tempfile::tempdir()?;
    let stuck = FakeControl {
        refuse_removal: true,
        ..pinning(directory.path())
    };
    let (network, journal) = network(directory.path(), stuck, 24)?;
    let established = network.establish([1; 16], &[ENDPOINT]).map(drop);
    let refused = network.establish([2; 16], &[ENDPOINT]);
    assert!(established.is_ok(), "{established:?}");
    assert!(
        matches!(
            &refused,
            Err(AttemptNetworkError::Quarantined { slot: 0, .. })
        ),
        "{refused:?}"
    );
    assert_eq!(
        refused.map(drop).map_err(|error| error.to_string()).err(),
        Some(
            "the attempt namespace of slot 0 could not be removed (the kernel refused a \
             netlink request with error -16); restart reconciliation must remove it"
                .to_owned()
        )
    );
    // Nothing more was installed, and the slot stays taken.
    assert_eq!(entries(&journal).installed, ["piglor-h0"]);
    assert!(network.slots.holders().attempts.contains_key(&0));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connector_dropped_on_a_runtime_worker_is_removed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    drop(network.establish([1; 16], &[ENDPOINT]));
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    Ok(())
}

/// A network whose removals wait until the returned sender lets them
/// proceed, and the receiver that reports each removal starting.
type GatedNetwork = (
    NamespacedLocalNetwork<FakeControl>,
    Arc<Mutex<Journal>>,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
);

fn gated(directory: &std::path::Path) -> TestResult<GatedNetwork> {
    let (started, removal_started) = std::sync::mpsc::channel();
    let (let_proceed, proceed) = std::sync::mpsc::channel();
    let control = FakeControl {
        gate: Some(RemovalGate {
            started,
            proceed: Mutex::new(proceed),
        }),
        ..pinning(directory)
    };
    let (network, journal) = network(directory, control, 24)?;
    Ok((network, journal, removal_started, let_proceed))
}

/// Let a removal proceed once it has started, from another task.
async fn release(
    removal_started: std::sync::mpsc::Receiver<()>,
    let_proceed: std::sync::mpsc::Sender<()>,
) {
    while removal_started.try_recv().is_err() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let_proceed.send(()).ok();
}

// A removal on the runtime's only worker hands the worker's other tasks to
// another thread, so the task that lets the removal finish still runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_blocked_removal_leaves_the_worker_to_other_tasks() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal, removal_started, let_proceed) = gated(directory.path())?;
    let established = network.establish([1; 16], &[ENDPOINT]);
    let removal = tokio::spawn(async move { drop(established) });
    let released = tokio::spawn(release(removal_started, let_proceed));
    let joined = (removal.await, released.await);
    assert!(matches!(joined, (Ok(()), Ok(()))));
    // The removal succeeded, so the slot is free, not quarantined.
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    assert!(network.establish([2; 16], &[ENDPOINT]).is_ok());
    Ok(())
}

// A current-thread runtime has no other worker to hand its tasks to, so
// removal runs in place there.
#[tokio::test]
async fn a_connector_dropped_on_a_current_thread_runtime_is_removed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    drop(network.establish([1; 16], &[ENDPOINT]));
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    Ok(())
}

#[test]
fn a_connector_that_cannot_enter_its_namespace_fails_the_connection() -> TestResult {
    let control = Arc::new(FakeControl::default());
    let slots = Arc::new(Slots {
        count: 1,
        holders: Mutex::new(Holders::default()),
    });
    let mut connector = NamespaceConnector {
        namespace: std::fs::File::open("/proc/self/ns/net").map(OwnedFd::from)?,
        _teardown: Teardown {
            control: Arc::clone(&control),
            name: NamespaceName::for_attempt([1; 16]),
            host_link: LinkName::new("piglor-h0")?,
            slot: slots.take([1; 16])?,
        },
    };
    // Entering a namespace needs `CAP_SYS_ADMIN`, which the workspace tests
    // do not have.
    let connected = connector.connect(ENDPOINT, Duration::from_millis(10));
    drop(connector);
    assert_eq!(
        connected.map_err(|error| error.kind()).err(),
        Some(io::ErrorKind::Other)
    );
    assert_eq!(entries(&control.journal).removed, ["piglor-h0"]);
    assert!(slots.take([1; 16]).is_ok());
    Ok(())
}

#[test]
fn errors_say_what_failed() {
    for (error, message) in [
        (
            AttemptNetworkError::Exhausted,
            "every slot of the reserved attempt range is taken",
        ),
        (
            AttemptNetworkError::Plan(NetworkPlanError::Slot),
            "the attempt's endpoints cannot form its namespace",
        ),
        (
            AttemptNetworkError::Open(NetlinkError::Unexpected),
            "the attempt namespace could not be opened",
        ),
        (
            AttemptNetworkError::InUse,
            "the attempt holds an attempt network already",
        ),
        (
            AttemptNetworkError::Exists,
            "an attempt namespace of this name exists",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

/// Tests that need `NET_ADMIN`, `SYS_ADMIN` and mounts. Each re-runs itself
/// in the isolated container that grants exactly those, and runs its body
/// there, where the container's own network namespace is the host's.
mod privileged {
    use std::net::TcpListener;
    use std::process::Command;

    use super::*;
    use crate::namespace_network::netlink::{NetlinkSession, ROUTE};
    use crate::namespace_network::{route, NetlinkNamespaceControl};

    /// Whether this process is the isolated one; otherwise run `name` there
    /// and require it to pass.
    fn isolated(name: &str) -> TestResult<bool> {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
            return Ok(true);
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-with-net-admin-test.sh");
        let output = Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg(format!(
                "namespace_network::attempt_network::tests::privileged::{name}"
            ))
            .output()?;
        assert!(
            output.status.success(),
            "isolated namespace test failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }

    /// A listener on [`ENDPOINT`], whose address the host's loopback holds.
    fn endpoint_listener() -> TestResult<TcpListener> {
        let loopback = LinkName::new("lo")?;
        let added = NetlinkSession::open(ROUTE).and_then(|session| {
            route::link_reply(session.request(route::get_link(&loopback)))
                .and_then(|link| link.ok_or(NetlinkError::Unexpected))
                .and_then(|link| {
                    session.execute(vec![route::address(
                        link.index,
                        IpPrefix {
                            address: ENDPOINT.ip(),
                            length: 32,
                        },
                    )])
                })
        });
        added?;
        Ok(TcpListener::bind(ENDPOINT)?)
    }

    #[test]
    fn a_connection_reaches_exactly_the_admitted_endpoint() -> TestResult {
        if !isolated("a_connection_reaches_exactly_the_admitted_endpoint")? {
            return Ok(());
        }
        let _listener = endpoint_listener()?;
        let namespaces = NetworkNamespaces::system();
        let network = NamespacedLocalNetwork::new(
            NetlinkNamespaceControl::new(namespaces.clone()),
            namespaces.clone(),
            range(24, 120)?,
        );
        let name = NamespaceName::for_attempt([6; 16]);
        let outcomes = network
            .connector([6; 16], &[ENDPOINT])
            .map(|mut connector| {
                let timeout = Duration::from_millis(500);
                let admitted = connector.connect(ENDPOINT, timeout).map(drop);
                let other_port = SocketAddr::new(ENDPOINT.ip(), 444);
                let refused = connector.connect(other_port, timeout).map(drop);
                (admitted, refused)
            });
        // Dropping the connector removed the namespace.
        let removed = matches!(namespaces.open(&name), Ok(None));
        assert!(matches!(&outcomes, Ok((Ok(()), Err(_)))), "{outcomes:?}");
        assert!(removed);
        Ok(())
    }
}
