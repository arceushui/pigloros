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
#[derive(Default)]
struct Journal {
    installed: Vec<String>,
    removed: Vec<String>,
}

/// A kernel that installs exactly what it is asked to, or refuses.
#[derive(Default)]
struct FakeControl {
    journal: Arc<Mutex<Journal>>,
    refuse: bool,
    current: Mutex<Option<ExpectedNamespace>>,
}

fn journal(journal: &Mutex<Journal>) -> MutexGuard<'_, Journal> {
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
        journal(&self.journal)
            .installed
            .push(expected.host_link.as_str().to_owned());
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Some(expected.clone());
        (!self.refuse).then_some(()).ok_or(NetlinkError::Kernel(-1))
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

    fn remove(&self, _name: &NamespaceName, host_link: &LinkName) -> Result<(), NetlinkError> {
        journal(&self.journal)
            .removed
            .push(host_link.as_str().to_owned());
        Ok(())
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

/// A network over a fake kernel whose namespaces are pinned in `directory`.
fn network(
    directory: &std::path::Path,
    refuse: bool,
    ipv4_length: u8,
) -> TestResult<(NamespacedLocalNetwork<FakeControl>, Arc<Mutex<Journal>>)> {
    let control = FakeControl {
        refuse,
        ..FakeControl::default()
    };
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

#[test]
fn an_established_network_holds_its_slot_until_its_connector_is_dropped() -> TestResult {
    let directory = tempfile::tempdir()?;
    // The fake kernel pins nothing, so the pin of the first attempt is this
    // process's own namespace, and the second attempt has none.
    std::os::unix::fs::symlink(
        "/proc/self/ns/net",
        directory
            .path()
            .join(NamespaceName::for_attempt([1; 16]).as_str()),
    )?;
    let (network, journal) = network(directory.path(), false, 24)?;
    let first = network.establish([1; 16], &[ENDPOINT]);
    // The second attempt takes the next slot; without a pin it is removed
    // and its slot freed at once.
    let second = network.establish([2; 16], &[ENDPOINT]);
    let removed_while_held = journal(&journal).removed.clone();
    let first_established = first.is_ok();
    drop(first);
    let third = network.establish([2; 16], &[ENDPOINT]);
    assert!(first_established);
    assert!(matches!(
        second,
        Err(AttemptNetworkError::Open(NetlinkError::Io(Errno::NOENT)))
    ));
    assert!(matches!(third, Err(AttemptNetworkError::Open(_))));
    assert_eq!(removed_while_held, ["piglor-h1"]);
    let journal = journal(&journal);
    assert_eq!(journal.installed, ["piglor-h0", "piglor-h1", "piglor-h0"]);
    assert_eq!(journal.removed, ["piglor-h1", "piglor-h0", "piglor-h0"]);
    Ok(())
}

#[test]
fn a_full_range_bad_endpoints_and_a_refusing_kernel_establish_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    // One /30 holds one slot.
    let (single, _) = network(directory.path(), false, 30)?;
    let (refusing, journal) = network(directory.path(), true, 24)?;
    let taken = single.slots.take();
    let exhausted = single.establish([1; 16], &[ENDPOINT]);
    drop(taken);
    let unroutable = single.establish([1; 16], &[SocketAddr::from(([192, 0, 2, 10], 0))]);
    let refused = refusing.establish([1; 16], &[ENDPOINT]);
    assert!(matches!(exhausted, Err(AttemptNetworkError::Exhausted)));
    assert!(matches!(
        unroutable,
        Err(AttemptNetworkError::Plan(NetworkPlanError::Endpoint))
    ));
    assert!(matches!(refused, Err(AttemptNetworkError::Establish(_))));
    // The refused installation is removed, and the slot is free again.
    assert_eq!(journal(&journal).removed, ["piglor-h0"]);
    assert!(single.slots.take().is_some_and(|lease| lease.slot == 0));
    Ok(())
}

#[test]
fn a_connector_that_cannot_enter_its_namespace_fails_the_connection() -> TestResult {
    let control = Arc::new(FakeControl::default());
    let slots = Arc::new(Slots {
        count: 1,
        taken: Mutex::new(BTreeSet::new()),
    });
    let mut connector = NamespaceConnector {
        namespace: std::fs::File::open("/proc/self/ns/net").map(OwnedFd::from)?,
        _teardown: Teardown {
            control: Arc::clone(&control),
            name: NamespaceName::for_attempt([1; 16]),
            host_link: LinkName::new("piglor-h0")?,
            _slot: slots.take().ok_or("no slot")?,
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
    assert_eq!(journal(&control.journal).removed, ["piglor-h0"]);
    assert!(slots.take().is_some());
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
