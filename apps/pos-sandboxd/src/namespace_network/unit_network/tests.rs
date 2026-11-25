use std::{cell::RefCell, collections::VecDeque, error::Error, fs::File, os::fd::AsFd};

use netlink_packet_core::NLM_F_MULTIPART;
use netlink_packet_core::{DoneMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkHeader, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};

use rustix::io::Errno;

use super::super::{IpPrefix, NamespaceRoute};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A transport that replays scripted datagrams, then fails.
struct Scripted(RefCell<VecDeque<Vec<u8>>>);

impl NetlinkTransport for Scripted {
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

/// One reply message.
fn message(sequence: u32, payload: NetlinkPayload<RouteNetlinkMessage>) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    header.flags = NLM_F_MULTIPART;
    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

/// A dump answer to request `sequence`: each of `replies`, then done.
fn dump(sequence: u32, replies: Vec<RouteNetlinkMessage>) -> Vec<u8> {
    let mut datagram: Vec<u8> = replies
        .into_iter()
        .flat_map(|reply| message(sequence, NetlinkPayload::InnerMessage(reply)))
        .collect();
    datagram.extend(message(
        sequence,
        NetlinkPayload::Done(DoneMessage::default()),
    ));
    datagram
}

fn link_message(index: u32, flags: LinkFlags, name: &str) -> RouteNetlinkMessage {
    let mut link = LinkMessage::default();
    link.header = LinkHeader {
        index,
        flags,
        ..LinkHeader::default()
    };
    link.attributes = vec![LinkAttribute::IfName(name.to_owned())];
    RouteNetlinkMessage::NewLink(link)
}

fn loopback() -> RouteNetlinkMessage {
    link_message(1, LinkFlags::Loopback | LinkFlags::Up, "lo")
}

/// A main-table route through link `index`.
fn route_message(kind: RouteType, family: AddressFamily, index: u32) -> RouteNetlinkMessage {
    let mut route = RouteMessage::default();
    route.header.address_family = family;
    route.header.table = RouteHeader::RT_TABLE_MAIN;
    route.header.kind = kind;
    route.attributes = vec![RouteAttribute::Oif(index)];
    if family == AddressFamily::Inet6 {
        route.header.destination_prefix_length = 128;
        route
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                std::net::Ipv6Addr::LOCALHOST,
            )));
    }
    RouteNetlinkMessage::NewRoute(route)
}

/// The unit view a session reads when the kernel answers `links` then
/// `routes`.
fn viewed(
    links: Vec<RouteNetlinkMessage>,
    routes: Vec<RouteNetlinkMessage>,
) -> Result<UnitView, NetlinkError> {
    unit_view(&NetlinkSession::new(Scripted(RefCell::new(
        VecDeque::from([dump(1, links), dump(2, routes)]),
    ))))
}

fn observed_link(index: u32, name: &str, kind: LinkKind) -> ObservedLink {
    ObservedLink {
        index,
        name: name.to_owned(),
        kind,
        up: true,
    }
}

fn observed_route(link_index: u32) -> ObservedRoute {
    ObservedRoute {
        link_index,
        route: NamespaceRoute {
            destination: IpPrefix {
                address: std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                length: 128,
            },
            gateway: None,
        },
    }
}

#[test]
fn a_fresh_unit_namespace_reads_as_its_loopback_and_the_route_the_kernel_installs() -> TestResult {
    // systemd brings `lo` up, and the kernel installs `::1/128` on it.
    let (links, routes) = viewed(
        vec![loopback()],
        vec![route_message(RouteType::Unicast, AddressFamily::Inet6, 1)],
    )?;
    assert_eq!(links, [observed_link(1, "lo", LinkKind::Loopback)]);
    assert_eq!(routes, [observed_route(1)]);
    assert!(only_loopback(&links, &routes));
    assert_eq!(classified(Ok(Ok((links, routes)))), Ok(()));
    Ok(())
}

#[test]
fn the_routes_of_other_tables_are_not_the_namespaces_routes() -> TestResult {
    let mut local = route_message(RouteType::Local, AddressFamily::Inet, 1);
    if let RouteNetlinkMessage::NewRoute(route) = &mut local {
        route.header.table = 255;
    }
    let (_, routes) = viewed(vec![loopback()], vec![local])?;
    assert!(routes.is_empty());
    Ok(())
}

#[test]
fn a_route_without_an_output_link_is_not_read_and_fails_the_check() {
    // A blackhole, prohibit or unreachable route has no output link: the
    // decoder refuses it, which is the check's failure.
    for kind in [
        RouteType::BlackHole,
        RouteType::Prohibit,
        RouteType::Unreachable,
    ] {
        let mut route = RouteMessage::default();
        route.header.address_family = AddressFamily::Inet;
        route.header.table = RouteHeader::RT_TABLE_MAIN;
        route.header.kind = kind;
        let read = viewed(vec![loopback()], vec![RouteNetlinkMessage::NewRoute(route)]);
        assert!(
            matches!(read, Err(NetlinkError::Unrepresentable)),
            "{kind:?}"
        );
        assert_eq!(classified(Ok(read)), Err(UnitNetworkError::Changed));
    }
}

#[test]
fn only_the_loopback_named_lo_with_routes_through_it_is_isolated() {
    let lo = observed_link(1, "lo", LinkKind::Loopback);
    assert!(only_loopback(std::slice::from_ref(&lo), &[]));
    assert!(only_loopback(
        std::slice::from_ref(&lo),
        &[observed_route(1), observed_route(1)]
    ));
    // A route off `lo`, even among routes through it.
    assert!(!only_loopback(
        std::slice::from_ref(&lo),
        &[observed_route(1), observed_route(2)]
    ));
    // No link, or any link beside `lo`: the fallback tunnel devices.
    assert!(!only_loopback(&[], &[]));
    for beside in ["sit0", "tunl0", "gre0", "ip6tnl0", "ip_vti0"] {
        let tunnel = observed_link(2, beside, LinkKind::Other);
        assert!(
            !only_loopback(&[lo.clone(), tunnel.clone()], &[]),
            "{beside}"
        );
        assert!(!only_loopback(&[tunnel, lo.clone()], &[]), "{beside}");
    }
    // One link that is not the loopback `lo`.
    assert!(!only_loopback(
        &[observed_link(1, "eth0", LinkKind::Other)],
        &[]
    ));
    assert!(!only_loopback(
        &[observed_link(1, "lo", LinkKind::Other)],
        &[]
    ));
    assert!(!only_loopback(
        &[observed_link(1, "lo0", LinkKind::Loopback)],
        &[]
    ));
}

#[test]
fn transit_failures_are_transport_and_everything_else_is_a_change() {
    for error in [
        NetlinkError::Io(Errno::TIMEDOUT),
        NetlinkError::Io(Errno::INVAL),
        NetlinkError::Interrupted,
        NetlinkError::Torn,
    ] {
        assert_eq!(classify(&error), UnitNetworkError::Transport, "{error:?}");
    }
    for error in [
        NetlinkError::Io(Errno::NOENT),
        NetlinkError::Empty,
        NetlinkError::Truncated,
        NetlinkError::Decode,
        NetlinkError::Kernel(-1),
        NetlinkError::Unexpected,
        NetlinkError::Unrepresentable,
        NetlinkError::Panicked,
        NetlinkError::Residual,
    ] {
        assert_eq!(classify(&error), UnitNetworkError::Changed, "{error:?}");
    }
}

#[test]
fn entering_or_reading_the_namespace_fails_by_class() {
    let view = || (vec![observed_link(1, "lo", LinkKind::Loopback)], Vec::new());
    assert_eq!(classified(Ok(Ok(view()))), Ok(()));
    assert_eq!(
        classified(Err(NetlinkError::Io(Errno::PERM))),
        Err(UnitNetworkError::Transport)
    );
    assert_eq!(
        classified(Ok(Err(NetlinkError::Io(Errno::PERM)))),
        Err(UnitNetworkError::Transport)
    );
    assert_eq!(
        classified(Ok(Err(NetlinkError::Kernel(-1)))),
        Err(UnitNetworkError::Changed)
    );
    assert_eq!(
        classified(Err(NetlinkError::Panicked)),
        Err(UnitNetworkError::Changed)
    );
    let (mut links, routes) = view();
    links.push(observed_link(2, "sit0", LinkKind::Other));
    assert_eq!(
        classified(Ok(Ok((links, routes)))),
        Err(UnitNetworkError::Changed)
    );
}

#[test]
fn a_descriptor_that_is_no_namespace_is_a_transport_failure() -> TestResult {
    let null = File::open("/dev/null")?;
    assert_eq!(
        NetlinkUnitNetwork.check(null.as_fd()),
        Err(UnitNetworkError::Transport)
    );
    Ok(())
}

#[test]
fn a_route_session_opens_and_the_view_is_read_through_it() -> TestResult {
    // A runner that blocks netlink sockets refuses with an I/O error.
    assert!(matches!(open_route(), Ok(_) | Err(NetlinkError::Io(_))));
    let opened = std::cell::Cell::new(0);
    let sessions = || {
        opened.set(opened.get() + 1);
        let transport = Scripted(RefCell::new(VecDeque::from([
            dump(1, vec![loopback()]),
            dump(2, Vec::new()),
        ])));
        Ok(NetlinkSession::new(transport))
    };
    let (links, routes) = read_through(sessions)?;
    assert_eq!(links, [observed_link(1, "lo", LinkKind::Loopback)]);
    assert!(routes.is_empty());
    assert_eq!(opened.get(), 1);
    // A session that cannot open ends the read at once.
    let failing = || -> Result<NetlinkSession<Scripted>, NetlinkError> {
        opened.set(opened.get() + 1);
        Err(NetlinkError::Io(Errno::MFILE))
    };
    assert!(matches!(
        read_through(failing),
        Err(NetlinkError::Io(Errno::MFILE))
    ));
    assert_eq!(opened.get(), 2);
    Ok(())
}

#[test]
fn the_probe_requires_the_sysctl_to_be_at_least_one() -> TestResult {
    let directory = tempfile::tempdir()?;
    let probe = |text: &str| -> TestResult<bool> {
        let path = directory.path().join("sysctl");
        std::fs::write(&path, text)?;
        Ok(fb_tunnels_isolated(&path))
    };
    assert!(!probe("0\n")?);
    assert!(probe("1\n")?);
    assert!(probe("2\n")?);
    assert!(probe("1")?);
    assert!(!probe("")?);
    assert!(!probe("\n")?);
    assert!(!probe("on\n")?);
    assert!(!probe("-1\n")?);
    assert!(!fb_tunnels_isolated(&directory.path().join("absent")));
    assert!(!fb_tunnels_isolated(directory.path()));
    Ok(())
}

#[test]
fn the_unit_network_errors_say_what_failed() {
    assert_eq!(
        UnitNetworkError::Transport.to_string(),
        "the unit network namespace could not be read"
    );
    assert_eq!(
        UnitNetworkError::Changed.to_string(),
        "the unit network namespace holds more than lo"
    );
}

#[test]
fn the_shipped_sysctl_drop_in_sets_the_probed_key_to_one() -> TestResult {
    let drop_in = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/sysctl.d/60-piglor-sandbox.conf"),
    )?;
    let key = FB_TUNNELS_SYSCTL
        .strip_prefix("/proc/sys/")
        .ok_or("not under /proc/sys")?
        .replace('/', ".");
    let settings: Vec<&str> = drop_in
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect();
    assert_eq!(settings, [format!("{key} = 1")]);
    Ok(())
}

#[test]
fn the_calling_threads_namespace_is_read_through_the_real_route_session() {
    // Whatever the host refuses (blocked netlink sockets, a route the
    // decoder cannot represent, a dump that stays torn) is an error of its
    // own; otherwise the thread's own namespace holds a loopback link, so a
    // view that is always empty is told apart from a real one.
    if let Ok((links, _routes)) = read_unit_view() {
        assert!(links.iter().any(|link| link.kind == LinkKind::Loopback));
    }
}
