use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    sync::MutexGuard,
};

use netlink_packet_core::{
    DoneMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_MULTIPART,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::RouteNetlinkMessage;

use rustix::io::Errno;

use super::*;
use crate::namespace_network::netlink::{NetlinkSession, NetlinkTransport};
use crate::namespace_network::{
    FirewallTableFamily, IpPrefix, LinkKind, LinkName, NamespaceName, ObservedAddress,
    ObservedLink, ObservedNamespace, ObservedRoute, ObservedTable,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// What the fake kernel was asked to do.
#[derive(Debug, Default)]
struct Journal {
    installed: Vec<String>,
    removed: Vec<String>,
    egress: Vec<String>,
    endpoints: Vec<Vec<SocketAddr>>,
}

/// Host egress that records what it is asked to do, or refuses.
#[derive(Debug, Default)]
struct FakeEgress {
    journal: Arc<Mutex<Journal>>,
    refuse_admission: bool,
    refuse_install: bool,
    refuse_removal: bool,
}

impl FakeEgress {
    fn record(&self, event: &str, refuse: bool) -> Result<(), HostEgressError> {
        entries(&self.journal).egress.push(event.to_owned());
        (!refuse).then_some(()).ok_or(HostEgressError::Readback)
    }
}

impl EgressControl for FakeEgress {
    fn admit(&self, endpoints: &[SocketAddr]) -> Result<(), HostEgressError> {
        entries(&self.journal).endpoints.push(endpoints.to_vec());
        self.record("admit", self.refuse_admission)
    }

    fn install(&self, attempt: &AttemptEgress) -> Result<(), HostEgressError> {
        entries(&self.journal)
            .endpoints
            .push(attempt.endpoints.clone());
        self.record(
            &format!("install {}", attempt.host_link.as_str()),
            self.refuse_install,
        )
    }

    fn remove(&self, attempt: &AttemptEgress) -> Result<(), HostEgressError> {
        self.record(
            &format!("remove {}", attempt.host_link.as_str()),
            self.refuse_removal,
        )
    }
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

/// A network over fakes, with the journal they share.
type FakeNetwork = (
    NamespacedLocalNetwork<FakeControl, FakeEgress>,
    Arc<Mutex<Journal>>,
);

/// A network over `control` and an egress refusing as `egress` does, which
/// share one journal, whose namespaces are pinned in `directory`.
fn network_with(
    directory: &std::path::Path,
    control: FakeControl,
    egress: &FakeEgress,
    ipv4_length: u8,
) -> TestResult<FakeNetwork> {
    let journal = Arc::clone(&control.journal);
    let egress = FakeEgress {
        journal: Arc::clone(&journal),
        refuse_admission: egress.refuse_admission,
        refuse_install: egress.refuse_install,
        refuse_removal: egress.refuse_removal,
    };
    Ok((
        NamespacedLocalNetwork::new(
            control,
            egress,
            NetworkNamespaces::pinned_under(directory),
            range(ipv4_length, 120)?,
        ),
        journal,
    ))
}

/// A network over `control` and an egress that grants everything.
fn network(
    directory: &std::path::Path,
    control: FakeControl,
    ipv4_length: u8,
) -> TestResult<FakeNetwork> {
    network_with(directory, control, &FakeEgress::default(), ipv4_length)
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

#[test]
fn egress_is_admitted_first_installed_last_and_removed_first() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    drop(network.establish([1; 16], &[ENDPOINT])?);
    assert_eq!(
        entries(&journal).egress,
        ["admit", "install piglor-h0", "remove piglor-h0"]
    );
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    Ok(())
}

#[test]
fn host_egress_sees_an_ipv4_mapped_endpoint_as_ipv4() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let mapped = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped(), 443));
    drop(network.establish([1; 16], &[mapped])?);
    assert_eq!(
        entries(&journal).endpoints,
        [vec![ENDPOINT], vec![ENDPOINT]]
    );
    Ok(())
}

#[test]
fn refused_egress_establishes_nothing_and_a_failed_egress_removal_quarantines() -> TestResult {
    let directory = tempfile::tempdir()?;
    let unadmitted = FakeEgress {
        refuse_admission: true,
        ..FakeEgress::default()
    };
    let (refusing, journal) =
        network_with(directory.path(), pinning(directory.path()), &unadmitted, 24)?;
    let refused = refusing.establish([1; 16], &[ENDPOINT]).map(drop);
    // Nothing was installed for an endpoint the host cannot reach.
    assert!(matches!(refused, Err(AttemptNetworkError::Egress(_))));
    assert!(entries(&journal).installed.is_empty());
    let uninstallable = FakeEgress {
        refuse_install: true,
        ..FakeEgress::default()
    };
    let (failing, journal) = network_with(
        directory.path(),
        pinning(directory.path()),
        &uninstallable,
        24,
    )?;
    let failed = failing.establish([2; 16], &[ENDPOINT]).map(drop);
    assert!(matches!(failed, Err(AttemptNetworkError::Egress(_))));
    // The partial egress and the namespace were removed.
    assert_eq!(
        entries(&journal).egress.last().map(String::as_str),
        Some("remove piglor-h0")
    );
    assert_eq!(entries(&journal).removed, ["piglor-h0"]);
    let unremovable = FakeEgress {
        refuse_removal: true,
        ..FakeEgress::default()
    };
    let (stuck, _) = network_with(
        directory.path(),
        pinning(directory.path()),
        &unremovable,
        24,
    )?;
    drop(stuck.establish([3; 16], &[ENDPOINT])?);
    assert!(matches!(
        stuck.establish([4; 16], &[ENDPOINT]),
        Err(AttemptNetworkError::Quarantined { slot: 0, .. })
    ));
    Ok(())
}

/// The probe of the /30 at `198.18.0.4`, whose target listens on port 7000.
fn probe_network() -> TestResult<EgressProbe> {
    Ok(EgressProbe::new(Ipv4Addr::new(198, 18, 0, 4), 7000)?)
}

#[test]
fn a_probe_network_inside_the_attempt_range_is_refused_before_anything_changes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    for inside in [Ipv4Addr::new(10, 213, 0, 0), Ipv4Addr::new(10, 213, 0, 252)] {
        let probed = network.probe_egress(EgressProbe::new(inside, 7000)?);
        assert!(
            matches!(probed, Err(EgressProbeError::Network)),
            "{probed:?}"
        );
    }
    assert!(entries(&journal).installed.is_empty());
    Ok(())
}

#[tokio::test]
async fn restart_reconciliation_probes_the_port_attempts_use() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    // A /30 inside the attempt range is refused before the host is read, so
    // the probe's outcome reaches reconciliation from the blocking pool
    // without touching the kernel.
    let probe = LocalEgressProbe::new(
        Arc::new(network),
        EgressProbe::new(Ipv4Addr::new(10, 213, 0, 4), 7000)?,
    );
    let probed = crate::EgressPropertyProbe::probe_egress(&probe).await;
    assert!(
        matches!(probed, Err(EgressProbeError::Network)),
        "{probed:?}"
    );
    assert!(entries(&journal).installed.is_empty());
    Ok(())
}

/// A network whose port is quarantined: its one attempt network's egress
/// could not be removed.
fn quarantined(
    directory: &std::path::Path,
) -> TestResult<NamespacedLocalNetwork<FakeControl, FakeEgress>> {
    let unremovable = FakeEgress {
        refuse_removal: true,
        ..FakeEgress::default()
    };
    let (stuck, _) = network_with(directory, pinning(directory), &unremovable, 24)?;
    drop(stuck.establish([3; 16], &[ENDPOINT])?);
    Ok(stuck)
}

#[test]
fn a_quarantined_port_fails_the_probe_first() -> TestResult {
    let directory = tempfile::tempdir()?;
    let stuck = quarantined(directory.path())?;
    // However far the probe gets on this host, the quarantine, which
    // outlasts every other failure, is what it reports.
    let probed = stuck.probe_egress_through(
        || Ok(host_with(&[Ipv4Addr::new(10, 0, 0, 1)])),
        probe_network()?,
    );
    assert!(
        matches!(
            &probed,
            Err(EgressProbeError::Quarantined { slot: 0, reason, probe: Some(_) })
                if reason == &HostEgressError::Readback.to_string()
        ),
        "{probed:?}"
    );
    Ok(())
}

#[test]
fn a_quarantine_keeps_the_probes_own_failure_as_its_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let stuck = quarantined(directory.path())?;
    // The host cannot be read: the probe fails there on any host, with or
    // without privileges, before anything is set up.
    let probed = stuck.probe_egress_through(
        || -> Result<NetlinkSession<HostReplies>, _> { Err(NetlinkError::Unexpected) },
        probe_network()?,
    );
    assert!(
        matches!(
            &probed,
            Err(EgressProbeError::Quarantined { slot: 0, probe: Some(outcome), .. })
                if matches!(**outcome, EgressProbeError::Target(NetlinkError::Unexpected))
        ),
        "{probed:?}"
    );
    // The quarantine's `source()` is the probe's `Target` failure, whose own
    // `source()` is the host read's failure.
    let source = probed
        .as_ref()
        .err()
        .and_then(std::error::Error::source)
        .ok_or("the quarantine has no source")?;
    // thiserror exposes the `Option<Box<_>>` source as the `Box` itself.
    let target = source
        .downcast_ref::<Box<EgressProbeError>>()
        .map(|boxed| &**boxed)
        .ok_or("the quarantine's source is not the probe's failure")?;
    assert!(
        matches!(target, EgressProbeError::Target(NetlinkError::Unexpected)),
        "{target:?}"
    );
    assert_eq!(
        source.to_string(),
        "the egress probe's target could not be set up or removed"
    );
    assert_eq!(
        source.source().map(ToString::to_string),
        Some(NetlinkError::Unexpected.to_string())
    );
    Ok(())
}

#[test]
fn a_panicking_probe_lets_the_next_one_run() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, _journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let probe = probe_network()?;
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        network.probe_egress_through(
            || -> Result<NetlinkSession<HostReplies>, NetlinkError> {
                std::panic::resume_unwind(Box::new("the host read panicked"))
            },
            probe,
        )
    }));
    assert!(panicked.is_err());
    // The panic released the claim: the next probe runs, and fails only on
    // the unreadable host.
    let next = network.probe_egress_through(
        || -> Result<NetlinkSession<HostReplies>, _> { Err(NetlinkError::Unexpected) },
        probe,
    );
    assert!(
        matches!(
            next,
            Err(EgressProbeError::Target(NetlinkError::Unexpected))
        ),
        "{next:?}"
    );
    Ok(())
}

/// A host route session that answers with scripted datagrams, then fails.
struct HostReplies(RefCell<VecDeque<Vec<u8>>>);

impl NetlinkTransport for HostReplies {
    fn send(&self, _datagram: &[u8]) -> Result<(), NetlinkError> {
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, NetlinkError> {
        self.0
            .borrow_mut()
            .pop_front()
            .ok_or(NetlinkError::Truncated)
    }
}

/// One message of host dump `sequence`.
fn dumped(sequence: u32, payload: NetlinkPayload<RouteNetlinkMessage>) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    header.flags = NLM_F_MULTIPART;
    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

/// A host whose address dump reports exactly `addresses` and whose route
/// dump reports none.
fn host_with(addresses: &[Ipv4Addr]) -> NetlinkSession<HostReplies> {
    let done = |sequence| dumped(sequence, NetlinkPayload::Done(DoneMessage::default()));
    let mut replies: VecDeque<Vec<u8>> = addresses
        .iter()
        .map(|&address| {
            let mut message = AddressMessage::default();
            message.attributes = vec![AddressAttribute::Local(std::net::IpAddr::V4(address))];
            dumped(
                1,
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(message)),
            )
        })
        .collect();
    replies.extend([done(1), done(2)]);
    NetlinkSession::new(HostReplies(RefCell::new(replies)))
}

#[test]
fn a_probe_network_the_host_uses_is_refused_before_anything_changes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let probe = probe_network()?;
    let used = Ipv4Addr::new(198, 18, 0, 5);
    let probed = network.probe_egress_through(|| Ok(host_with(&[used])), probe);
    assert!(
        matches!(probed, Err(EgressProbeError::Network)),
        "{probed:?}"
    );
    // A host that cannot be read fails closed as well.
    let unread = network.probe_egress_through(
        || -> Result<NetlinkSession<HostReplies>, _> { Err(NetlinkError::Unexpected) },
        probe,
    );
    assert!(
        matches!(
            unread,
            Err(EgressProbeError::Target(NetlinkError::Unexpected))
        ),
        "{unread:?}"
    );
    assert!(entries(&journal).installed.is_empty());
    assert!(std::fs::read_dir(directory.path())?.next().is_none());
    Ok(())
}

#[test]
fn a_probe_that_cannot_create_its_target_fails_closed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let probe = probe_network()?;
    // Unsharing a namespace needs `CAP_SYS_ADMIN`; the host has no address
    // in the probe's /30.
    let probed =
        network.probe_egress_through(|| Ok(host_with(&[Ipv4Addr::new(10, 0, 0, 1)])), probe);
    assert!(
        matches!(probed, Err(EgressProbeError::Target(_))),
        "{probed:?}"
    );
    assert!(entries(&journal).installed.is_empty());
    Ok(())
}

#[test]
fn probe_errors_say_what_failed() {
    for (error, message) in [
        (
            EgressProbeError::Target(NetlinkError::Unexpected),
            "the egress probe's target could not be set up or removed",
        ),
        (
            EgressProbeError::Listen(io::ErrorKind::AddrInUse.into()),
            "the egress probe's target could not listen",
        ),
        (
            EgressProbeError::Establish(AttemptNetworkError::InUse),
            "the egress probe's attempt network could not be established",
        ),
        (
            EgressProbeError::Blocked(io::ErrorKind::TimedOut.into()),
            "forwarded sandbox traffic did not pass the host",
        ),
        (
            EgressProbeError::NotMasqueraded,
            "forwarded sandbox traffic was not masqueraded",
        ),
        (
            EgressProbeError::Network,
            "the egress probe's /30 overlaps the attempt range or a host address or route",
        ),
        (
            EgressProbeError::Interrupted,
            "the egress probe did not run to completion",
        ),
        (
            EgressProbeError::InFlight,
            "an earlier egress probe is still running",
        ),
        (
            EgressProbeError::Quarantined {
                slot: 2,
                reason: "busy".to_owned(),
                probe: None,
            },
            "the attempt network port is quarantined at slot 2 (busy)",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

/// A network whose removals wait until the returned sender lets them
/// proceed, and the receiver that reports each removal starting.
type GatedNetwork = (
    NamespacedLocalNetwork<FakeControl, FakeEgress>,
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
            egress: Arc::new(FakeEgress::default()),
            attempt: AttemptEgress {
                namespace: NamespaceName::for_attempt([1; 16]),
                host_link: LinkName::new("piglor-h0")?,
                endpoints: vec![ENDPOINT],
            },
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
    use crate::namespace_network::{route, ForwardingRecords, NetlinkNamespaceControl};

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
            HostEgress::new(),
            namespaces.clone(),
            range(24, 120)?,
        );
        let name = NamespaceName::for_attempt([6; 16]);
        let outcomes = network
            .connector([6; 16], &[ENDPOINT])
            .map(|mut connector| {
                let timeout = Duration::from_millis(500);
                let admitted = connector.connect(ENDPOINT, timeout).map(drop);
                // The IPv4-mapped form of the endpoint reaches it as IPv4.
                let mapped = SocketAddr::from((
                    Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped(),
                    ENDPOINT.port(),
                ));
                let mapped = connector.connect(mapped, timeout).map(drop);
                let other_port = SocketAddr::new(ENDPOINT.ip(), 444);
                let refused = connector.connect(other_port, timeout).map(drop);
                (admitted, mapped, refused)
            });
        // Dropping the connector removed the namespace.
        let removed = matches!(namespaces.open(&name), Ok(None));
        assert!(
            matches!(&outcomes, Ok((Ok(()), Ok(()), Err(_)))),
            "{outcomes:?}"
        );
        assert!(removed);
        Ok(())
    }

    /// The off-host endpoint, in a target namespace behind the host, on an
    /// unprivileged port: the target's fresh namespace keeps the default
    /// `ip_unprivileged_port_start`, and the container grants no
    /// `CAP_NET_BIND_SERVICE`.
    const TARGET: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 8443);

    /// Give link `name` of the session's namespace `address` and bring it up.
    fn link_up<T: crate::namespace_network::netlink::NetlinkTransport>(
        session: &NetlinkSession<T>,
        name: &LinkName,
        address: IpPrefix,
    ) -> Result<(), NetlinkError> {
        route::link_reply(session.request(route::get_link(name)))
            .and_then(|link| link.ok_or(NetlinkError::Unexpected))
            .and_then(|link| {
                session.execute(vec![route::address(link.index, address), route::up(name)])
            })
    }

    /// The host's end of the target's veth pair, `tgt-h0`, with the
    /// target's other end in `target`.
    fn host_side(target: std::os::fd::BorrowedFd<'_>) -> TestResult {
        let (host, inner) = (LinkName::new("tgt-h0")?, LinkName::new("tgt-n0")?);
        let address = IpPrefix {
            address: std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            length: 24,
        };
        NetlinkSession::open(ROUTE)
            .and_then(|session| {
                session
                    .execute(vec![route::veth_pair(&host, &inner, target)])
                    .and_then(|()| link_up(&session, &host, address))
            })
            .map_err(Into::into)
    }

    /// A listener on [`TARGET`] inside `target`.
    fn target_listener(target: std::os::fd::BorrowedFd<'_>) -> TestResult<TcpListener> {
        let inner = LinkName::new("tgt-n0")?;
        let address = IpPrefix {
            address: TARGET.ip(),
            length: 24,
        };
        let listener = in_namespace(target, || {
            NetlinkSession::open(ROUTE)
                .and_then(|session| link_up(&session, &inner, address))
                .map_err(|error| error.to_string())
                .and_then(|()| TcpListener::bind(TARGET).map_err(|error| error.to_string()))
        })?;
        Ok(listener?)
    }

    /// The chains of the host egress table, or `None` without it.
    fn host_chains() -> Result<Option<Vec<String>>, NetlinkError> {
        NetlinkSession::open(crate::namespace_network::netlink::NETFILTER)
            .and_then(|session| crate::namespace_network::host_egress::host_chains(&session))
    }

    /// Whether host link `name` forwards IPv4.
    fn forwarding_of(name: &str) -> TestResult<bool> {
        let link = LinkName::new(name)?;
        let forwarding = NetlinkSession::open(ROUTE).and_then(|session| {
            session
                .request(route::get_link(&link))
                .and_then(crate::namespace_network::host_egress::link_forwarding)
        })?;
        Ok(forwarding.1)
    }

    /// Turn forwarding on or off for host link `name`.
    fn set_forwarding_of(name: &str, on: bool) -> TestResult {
        let link = LinkName::new(name)?;
        NetlinkSession::open(ROUTE).and_then(|session| {
            route::link_reply(session.request(route::get_link(&link)))
                .and_then(|found| found.ok_or(NetlinkError::Unexpected))
                .and_then(|found| {
                    session.execute(vec![crate::namespace_network::host_egress::set_forwarding(
                        found.index,
                        on,
                    )])
                })
        })?;
        Ok(())
    }

    #[test]
    fn a_device_that_already_forwarded_is_left_forwarding() -> TestResult {
        if !isolated("a_device_that_already_forwarded_is_left_forwarding")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let target = namespaces.create(&NamespaceName::for_attempt([0xee; 16]))?;
        host_side(target.as_fd())?;
        set_forwarding_of("tgt-h0", true)?;
        let network = NamespacedLocalNetwork::new(
            NetlinkNamespaceControl::new(namespaces.clone()),
            HostEgress::new(),
            namespaces,
            range(24, 120)?,
        );
        let established = network.connector([9; 16], &[TARGET]).map(drop);
        assert!(established.is_ok(), "{established:?}");
        assert!(forwarding_of("tgt-h0")?);
        assert!(ForwardingRecords::default().recorded()?.is_empty());
        Ok(())
    }

    #[test]
    fn the_sweep_restores_recorded_forwarding() -> TestResult {
        if !isolated("the_sweep_restores_recorded_forwarding")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let target = namespaces.create(&NamespaceName::for_attempt([0xee; 16]))?;
        host_side(target.as_fd())?;
        // A crash after the record and the change, before the teardown.
        let session = NetlinkSession::open(ROUTE)?;
        let link = route::link_reply(session.request(route::get_link(&LinkName::new("tgt-h0")?)))?
            .ok_or("no such link")?;
        ForwardingRecords::default().record(link.index, "tgt-h0")?;
        set_forwarding_of("tgt-h0", true)?;
        let swept = NetlinkNamespaceControl::new(namespaces).remove_orphans();
        assert!(swept.is_ok(), "{swept:?}");
        assert!(!forwarding_of("tgt-h0")?);
        assert!(ForwardingRecords::default().recorded()?.is_empty());
        Ok(())
    }

    #[test]
    fn an_off_host_ipv6_endpoint_is_refused_before_anything_is_installed() -> TestResult {
        if !isolated("an_off_host_ipv6_endpoint_is_refused_before_anything_is_installed")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let target = namespaces.create(&NamespaceName::for_attempt([0xee; 16]))?;
        host_side(target.as_fd())?;
        // The host routes the endpoint's network, so only admission refuses
        // it.
        let routed = IpPrefix {
            address: std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
            length: 64,
        };
        let host = LinkName::new("tgt-h0")?;
        NetlinkSession::open(ROUTE).and_then(|session| {
            route::link_reply(session.request(route::get_link(&host)))
                .and_then(|link| link.ok_or(NetlinkError::Unexpected))
                .and_then(|link| session.execute(vec![route::address(link.index, routed)]))
        })?;
        let network = NamespacedLocalNetwork::new(
            NetlinkNamespaceControl::new(namespaces.clone()),
            HostEgress::new(),
            namespaces.clone(),
            range(24, 120)?,
        );
        let endpoint = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10), 8443));
        let refused = network.connector([8; 16], &[endpoint]).map(drop);
        assert!(
            matches!(
                refused,
                Err(AttemptNetworkError::Egress(HostEgressError::Ipv6Egress))
            ),
            "{refused:?}"
        );
        assert!(matches!(
            namespaces.open(&NamespaceName::for_attempt([8; 16])),
            Ok(None)
        ));
        Ok(())
    }

    #[test]
    fn a_forwarded_connection_is_masqueraded_to_exactly_its_endpoint() -> TestResult {
        if !isolated("a_forwarded_connection_is_masqueraded_to_exactly_its_endpoint")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let target = namespaces.create(&NamespaceName::for_attempt([0xee; 16]))?;
        host_side(target.as_fd())?;
        // A new link inherits the namespace's default forwarding, which a
        // host that already routes has on; start from off so the provider
        // has to turn it on and back off.
        set_forwarding_of("tgt-h0", false)?;
        let listener = target_listener(target.as_fd())?;
        let control = NetlinkNamespaceControl::new(namespaces.clone());
        let network = NamespacedLocalNetwork::new(
            control.clone(),
            HostEgress::new(),
            namespaces,
            range(24, 120)?,
        );
        let outcome = network.connector([7; 16], &[TARGET]).map(|mut connector| {
            let connected = connector.connect(TARGET, Duration::from_secs(5)).map(drop);
            // The target sees the host's address: the attempt's was
            // masqueraded, so the reply needs no route to the attempt range.
            let peer = listener.accept().map(|(_, peer)| peer.ip());
            (connected, peer)
        });
        // Dropping the connector took the attempt's chain away again, and
        // turned the target link's forwarding back off.
        let left = host_chains();
        let forwarding = forwarding_of("tgt-h0");
        let records = ForwardingRecords::default()
            .recorded()
            .map_err(|error| error.to_string());
        let swept = control.remove_orphans();
        assert!(
            matches!(&outcome, Ok((Ok(()), Ok(peer))) if *peer == std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            "{outcome:?}"
        );
        assert_eq!(
            left.map_err(|error| error.to_string()),
            Ok(Some(vec!["forward".to_owned(), "postrouting".to_owned()]))
        );
        assert!(matches!(forwarding, Ok(false)), "{forwarding:?}");
        assert_eq!(records, Ok(Vec::new()));
        assert!(swept.is_ok(), "{swept:?}");
        assert!(matches!(host_chains(), Ok(None)));
        Ok(())
    }

    /// A network over the real kernel, pinned in `/run/netns`.
    fn real_network() -> TestResult<NamespacedLocalNetwork<NetlinkNamespaceControl>> {
        let namespaces = NetworkNamespaces::system();
        Ok(NamespacedLocalNetwork::new(
            NetlinkNamespaceControl::new(namespaces.clone()),
            HostEgress::new(),
            namespaces,
            range(24, 120)?,
        ))
    }

    /// The kernel adapter, whose every removal removes and then reports a
    /// failure, as a removal that left something behind would.
    #[derive(Debug)]
    struct FailingRemoval(NetlinkNamespaceControl);

    impl NamespaceControl for FailingRemoval {
        type Error = NetlinkError;

        fn install(&self, expected: &ExpectedNamespace) -> Result<(), NetlinkError> {
            self.0.install(expected)
        }

        fn observe(
            &self,
            name: &NamespaceName,
            host_link: &LinkName,
        ) -> Result<ObservedNamespace, NetlinkError> {
            self.0.observe(name, host_link)
        }

        fn remove(&self, name: &NamespaceName, host_link: &LinkName) -> Result<(), NetlinkError> {
            self.0
                .remove(name, host_link)
                .and(Err(NetlinkError::Residual))
        }
    }

    #[test]
    fn a_probe_whose_attempt_network_is_not_removed_fails() -> TestResult {
        if !isolated("a_probe_whose_attempt_network_is_not_removed_fails")? {
            return Ok(());
        }
        let namespaces = NetworkNamespaces::system();
        let network = NamespacedLocalNetwork::new(
            FailingRemoval(NetlinkNamespaceControl::new(namespaces.clone())),
            HostEgress::new(),
            namespaces,
            range(24, 120)?,
        );
        let probed = network.probe_egress(probe_network()?);
        assert!(
            matches!(probed, Err(EgressProbeError::Quarantined { slot: 0, .. })),
            "{probed:?}"
        );
        Ok(())
    }

    /// Probe twice through the adapter on `runtime`: the first probe's
    /// claim ends with it, so the second runs too, and neither leaves a
    /// namespace behind.
    fn probe_twice_on(runtime: &tokio::runtime::Runtime) -> TestResult {
        let probe = LocalEgressProbe::new(Arc::new(real_network()?), probe_network()?);
        for _ in 0..2 {
            let probed = runtime.block_on(crate::EgressPropertyProbe::probe_egress(&probe));
            assert!(probed.is_ok(), "{probed:?}");
            let left = NetworkNamespaces::system().attempt_names();
            assert!(matches!(&left, Ok(names) if names.is_empty()), "{left:?}");
        }
        Ok(())
    }

    #[test]
    fn restart_reconciliation_probes_egress_end_to_end() -> TestResult {
        if !isolated("restart_reconciliation_probes_egress_end_to_end")? {
            return Ok(());
        }
        probe_twice_on(&tokio::runtime::Builder::new_current_thread().build()?)
    }

    /// On a multi-threaded runtime, as in production, the probe's teardown
    /// takes the `block_in_place` path.
    #[test]
    fn restart_reconciliation_probes_egress_end_to_end_on_worker_threads() -> TestResult {
        if !isolated("restart_reconciliation_probes_egress_end_to_end_on_worker_threads")? {
            return Ok(());
        }
        probe_twice_on(
            &tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()?,
        )
    }

    #[test]
    fn a_probe_past_its_deadline_releases_the_network_when_it_ends() -> TestResult {
        if !isolated("a_probe_past_its_deadline_releases_the_network_when_it_ends")? {
            return Ok(());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()?;
        let probe = LocalEgressProbe::new(Arc::new(real_network()?), probe_network()?);
        // No time at all: the probe starts on the blocking pool and is no
        // longer awaited, as at the reconciliation deadline.
        let late = runtime.block_on(tokio::time::timeout(
            Duration::ZERO,
            crate::EgressPropertyProbe::probe_egress(&probe),
        ));
        assert!(late.is_err(), "{late:?}");
        // A retry is refused while the earlier probe runs, and runs once it
        // has ended.
        let retried = runtime.block_on(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let probed = crate::EgressPropertyProbe::probe_egress(&probe).await;
                if !matches!(probed, Err(EgressProbeError::InFlight))
                    || tokio::time::Instant::now() >= deadline
                {
                    return probed;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        assert!(retried.is_ok(), "{retried:?}");
        let left = NetworkNamespaces::system().attempt_names();
        assert!(matches!(&left, Ok(names) if names.is_empty()), "{left:?}");
        Ok(())
    }

    #[test]
    fn the_egress_probe_passes_and_leaves_nothing() -> TestResult {
        if !isolated("the_egress_probe_passes_and_leaves_nothing")? {
            return Ok(());
        }
        let probed = real_network()?.probe_egress(probe_network()?);
        assert!(probed.is_ok(), "{probed:?}");
        let left = NetworkNamespaces::system().attempt_names();
        assert!(matches!(&left, Ok(names) if names.is_empty()), "{left:?}");
        Ok(())
    }

    #[test]
    fn a_foreign_forward_drop_fails_the_egress_probe() -> TestResult {
        if !isolated("a_foreign_forward_drop_fails_the_egress_probe")? {
            return Ok(());
        }
        // Another owner's table, as Docker or ufw would install it.
        let foreign = crate::namespace_network::FirewallChain {
            name: "forward".to_owned(),
            base: Some(crate::namespace_network::FirewallBaseChain {
                hook: crate::namespace_network::FirewallHook::Forward,
                priority: 0,
                policy: crate::namespace_network::FirewallVerdict::Drop,
            }),
            rules: Vec::new(),
        };
        let installed = NetlinkSession::open(crate::namespace_network::netlink::NETFILTER)
            .and_then(|session| {
                session.execute(crate::namespace_network::firewall::install(
                    "foreign",
                    &[foreign],
                ))
            });
        let probed = real_network()?.probe_egress(probe_network()?);
        assert!(installed.is_ok(), "{installed:?}");
        assert!(
            matches!(probed, Err(EgressProbeError::Blocked(_))),
            "{probed:?}"
        );
        Ok(())
    }
}

#[test]
fn an_ipv4_mapped_endpoint_establishes_the_namespace_of_the_ipv4_it_maps() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (network, _journal) = network(directory.path(), pinning(directory.path()), 24)?;
    let mapped = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped(), 443));
    drop(network.establish([1; 16], &[mapped])?);
    let installed = network
        .control
        .current
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let ipv4 = ExpectedNamespace::for_attempt([1; 16], &range(24, 120)?, 0, &[ENDPOINT])?;
    assert_eq!(installed, Some(ipv4));
    Ok(())
}
