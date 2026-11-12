use std::{error::Error, fs::File, os::fd::AsFd};

use netlink_packet_route::address::AddressScope;
use netlink_packet_route::route::{RouteMetric, RouteScope};

use super::*;
use crate::namespace_network::LinkKind;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn link(name: &str) -> TestResult<LinkName> {
    Ok(LinkName::new(name)?)
}

fn named(name: &str, attributes: Vec<LinkAttribute>) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.attributes = std::iter::once(LinkAttribute::IfName(name.to_owned()))
        .chain(attributes)
        .collect();
    message
}

fn v4(octets: [u8; 4]) -> IpAddr {
    IpAddr::from(octets)
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
}

#[test]
fn a_veth_pair_is_created_whole_with_its_peer_in_the_namespace() -> TestResult {
    let namespace = File::open("/dev/null")?;
    let request = veth_pair(&link("piglor-h3")?, &link("piglor-n3")?, namespace.as_fd());
    let peer = named(
        "piglor-n3",
        vec![LinkAttribute::NetNsFd(namespace.as_raw_fd())],
    );
    let pair = named(
        "piglor-h3",
        vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer))),
        ])],
    );
    assert_eq!(request.message, RouteNetlinkMessage::NewLink(pair));
    assert_eq!(request.flags, NLM_F_CREATE | NLM_F_EXCL);
    assert!(request.acknowledged);
    Ok(())
}

#[test]
fn link_settings_name_the_link() -> TestResult {
    let name = link("piglor-n3")?;
    let generation = no_address_generation(&name);
    assert_eq!(
        generation.message,
        RouteNetlinkMessage::SetLink(named(
            "piglor-n3",
            vec![LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(
                vec![AfSpecInet6::AddrGenMode(In6AddrGenMode::None)]
            )])]
        ))
    );
    let mut raised = named("piglor-n3", Vec::new());
    raised.header.flags = LinkFlags::Up;
    raised.header.change_mask = LinkFlags::Up;
    assert_eq!(up(&name).message, RouteNetlinkMessage::SetLink(raised));
    let mut deleted = LinkMessage::default();
    deleted.header.index = 9;
    assert_eq!(
        delete_link(9).message,
        RouteNetlinkMessage::DelLink(deleted)
    );
    assert_eq!(
        get_link(&name),
        RouteNetlinkMessage::GetLink(named("piglor-n3", Vec::new()))
    );
    for request in [generation, up(&name), delete_link(9)] {
        assert_eq!((request.flags, request.acknowledged), (0, true));
    }
    Ok(())
}

#[test]
fn addresses_are_added_exclusively_without_duplicate_detection() {
    let unicast_request = address(
        4,
        IpPrefix {
            address: v4([10, 213, 0, 14]),
            length: 30,
        },
    );
    let mut expected = AddressMessage::default();
    expected.header.family = AddressFamily::Inet;
    expected.header.prefix_len = 30;
    expected.header.flags = AddressHeaderFlags::Nodad;
    expected.header.scope = AddressScope::Universe;
    expected.header.index = 4;
    expected.attributes = vec![
        AddressAttribute::Local(v4([10, 213, 0, 14])),
        AddressAttribute::Address(v4([10, 213, 0, 14])),
    ];
    assert_eq!(
        unicast_request.message,
        RouteNetlinkMessage::NewAddress(expected.clone())
    );
    assert_eq!(unicast_request.flags, NLM_F_CREATE | NLM_F_EXCL);
    let unique_request = address(
        4,
        IpPrefix {
            address: v6([0xfd00, 0x913, 0, 0, 0, 0, 0, 7]),
            length: 127,
        },
    );
    expected.header.family = AddressFamily::Inet6;
    expected.header.prefix_len = 127;
    expected.attributes = vec![AddressAttribute::Address(v6([
        0xfd00, 0x913, 0, 0, 0, 0, 0, 7,
    ]))];
    assert_eq!(
        unique_request.message,
        RouteNetlinkMessage::NewAddress(expected)
    );
    assert!(unique_request.acknowledged);
}

#[test]
fn only_gateway_routes_are_added_and_through_the_link() {
    let connected = NamespaceRoute {
        destination: IpPrefix {
            address: v4([10, 213, 0, 12]),
            length: 30,
        },
        gateway: None,
    };
    assert!(route(4, &connected).is_none());
    let endpoint = NamespaceRoute {
        destination: IpPrefix {
            address: v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10]),
            length: 128,
        },
        gateway: Some(v6([0xfd00, 0x913, 0, 0, 0, 0, 0, 6])),
    };
    let mut expected = RouteMessage::default();
    expected.header.address_family = AddressFamily::Inet6;
    expected.header.destination_prefix_length = 128;
    expected.header.table = RouteHeader::RT_TABLE_MAIN;
    expected.header.protocol = RouteProtocol::Static;
    expected.header.scope = RouteScope::Universe;
    expected.header.kind = RouteType::Unicast;
    expected.attributes = vec![
        RouteAttribute::Destination(RouteAddress::Inet6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10,
        ))),
        RouteAttribute::Gateway(RouteAddress::Inet6(Ipv6Addr::new(
            0xfd00, 0x913, 0, 0, 0, 0, 0, 6,
        ))),
        RouteAttribute::Oif(4),
    ];
    let added = route(4, &endpoint);
    assert_eq!(
        added
            .as_ref()
            .map(|request| (&request.message, request.flags)),
        Some((
            &RouteNetlinkMessage::NewRoute(expected),
            NLM_F_CREATE | NLM_F_EXCL
        ))
    );
}

#[test]
fn namespace_identifiers_are_assigned_and_read_by_descriptor() -> TestResult {
    let namespace = File::open("/dev/null")?;
    let fd = namespace.as_raw_fd().unsigned_abs();
    let assigned = assign_nsid(namespace.as_fd());
    let mut expected = NsidMessage::default();
    expected.attributes = vec![NsidAttribute::Fd(fd), NsidAttribute::Id(-1)];
    assert_eq!(assigned.message, RouteNetlinkMessage::NewNsId(expected));
    assert_eq!((assigned.flags, assigned.acknowledged), (0, true));
    let mut query = NsidMessage::default();
    query.attributes = vec![NsidAttribute::Fd(fd)];
    assert_eq!(
        get_nsid(namespace.as_fd()),
        RouteNetlinkMessage::GetNsId(query)
    );
    Ok(())
}

#[test]
fn identifier_replies_decode_or_fail() {
    let mut reply = NsidMessage::default();
    reply.attributes = vec![NsidAttribute::Pid(1), NsidAttribute::Id(4)];
    assert_eq!(
        nsid_reply(RouteNetlinkMessage::NewNsId(reply)).ok(),
        Some(4)
    );
    assert!(matches!(
        nsid_reply(RouteNetlinkMessage::NewNsId(NsidMessage::default())),
        Err(NetlinkError::Unrepresentable)
    ));
    assert!(matches!(
        nsid_reply(addresses()),
        Err(NetlinkError::Unexpected)
    ));
}

#[test]
fn link_replies_decode_a_missing_link_as_none() {
    let veth = named(
        "piglor-h3",
        vec![
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)]),
            LinkAttribute::Link(2),
            LinkAttribute::LinkNetNsId(0),
        ],
    );
    let decoded = link_reply(Ok(RouteNetlinkMessage::NewLink(veth)));
    assert!(matches!(
        decoded,
        Ok(Some(ObservedLink {
            kind: LinkKind::Veth {
                peer_index: 2,
                peer_netnsid: Some(0)
            },
            ..
        }))
    ));
    assert!(matches!(
        link_reply(Err(NetlinkError::Kernel(-19))),
        Ok(None)
    ));
    assert!(matches!(
        link_reply(Err(NetlinkError::Kernel(-1))),
        Err(NetlinkError::Kernel(-1))
    ));
    assert!(matches!(
        link_reply(Ok(routes())),
        Err(NetlinkError::Unexpected)
    ));
}

fn address_reply(
    family: AddressFamily,
    flags: AddressHeaderFlags,
    attributes: Vec<AddressAttribute>,
) -> RouteNetlinkMessage {
    let mut message = AddressMessage::default();
    message.header.family = family;
    message.header.prefix_len = 30;
    message.header.flags = flags;
    message.header.index = 5;
    message.attributes = attributes;
    RouteNetlinkMessage::NewAddress(message)
}

#[test]
fn addresses_decode_their_local_address_and_prefix() -> TestResult {
    let local = v4([10, 213, 0, 14]);
    let unique = v6([0xfd00, 0x913, 0, 0, 0, 0, 0, 7]);
    let observed = observed_addresses(vec![
        address_reply(
            AddressFamily::Inet,
            AddressHeaderFlags::Permanent,
            vec![
                AddressAttribute::Address(local),
                AddressAttribute::Local(local),
                AddressAttribute::Label("piglor-n3".to_owned()),
            ],
        ),
        address_reply(
            AddressFamily::Inet6,
            AddressHeaderFlags::empty(),
            vec![
                AddressAttribute::Address(unique),
                AddressAttribute::Flags(AddressFlags::Nodad | AddressFlags::Permanent),
            ],
        ),
    ])?;
    let prefix = |address| IpPrefix {
        address,
        length: 30,
    };
    assert_eq!(
        observed,
        [
            ObservedAddress {
                link_index: 5,
                address: prefix(local),
            },
            ObservedAddress {
                link_index: 5,
                address: prefix(unique),
            },
        ]
    );
    Ok(())
}

#[test]
fn peer_tentative_and_addressless_replies_fail() {
    let local = v4([10, 213, 0, 14]);
    let unique = v6([0xfd00, 0x913, 0, 0, 0, 0, 0, 7]);
    let undecodable = [
        address_reply(
            AddressFamily::Inet,
            AddressHeaderFlags::empty(),
            vec![
                AddressAttribute::Local(local),
                AddressAttribute::Address(v4([10, 213, 0, 13])),
            ],
        ),
        address_reply(
            AddressFamily::Inet6,
            AddressHeaderFlags::Tentative,
            vec![AddressAttribute::Address(unique)],
        ),
        address_reply(
            AddressFamily::Inet6,
            AddressHeaderFlags::empty(),
            vec![
                AddressAttribute::Address(unique),
                AddressAttribute::Flags(AddressFlags::Dadfailed),
            ],
        ),
        address_reply(
            AddressFamily::Inet,
            AddressHeaderFlags::empty(),
            vec![AddressAttribute::Local(local)],
        ),
        address_reply(AddressFamily::Inet, AddressHeaderFlags::empty(), Vec::new()),
    ];
    for reply in undecodable {
        assert!(matches!(
            observed_addresses(vec![reply]),
            Err(NetlinkError::Unrepresentable)
        ));
    }
    assert!(matches!(
        observed_addresses(vec![routes()]),
        Err(NetlinkError::Unexpected)
    ));
}

fn route_reply(family: AddressFamily, length: u8, attributes: Vec<RouteAttribute>) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = family;
    message.header.destination_prefix_length = length;
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.kind = RouteType::Unicast;
    message.attributes = attributes;
    message
}

#[test]
fn main_table_routes_decode_and_others_are_left_out() -> TestResult {
    let connected = route_reply(
        AddressFamily::Inet,
        30,
        vec![
            RouteAttribute::Table(254),
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(10, 213, 0, 12))),
            RouteAttribute::PrefSource(RouteAddress::Inet(Ipv4Addr::new(10, 213, 0, 14))),
            RouteAttribute::Oif(5),
        ],
    );
    let endpoint = route_reply(
        AddressFamily::Inet6,
        128,
        vec![
            RouteAttribute::Destination(RouteAddress::Inet6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10,
            ))),
            RouteAttribute::Gateway(RouteAddress::Inet6(Ipv6Addr::new(
                0xfd00, 0x913, 0, 0, 0, 0, 0, 6,
            ))),
            RouteAttribute::Oif(5),
            RouteAttribute::Priority(1024),
            RouteAttribute::Metrics(vec![RouteMetric::Mtu(1500)]),
        ],
    );
    // A default route has no destination attribute.
    let default = route_reply(AddressFamily::Inet, 0, vec![RouteAttribute::Oif(5)]);
    let mut local = route_reply(AddressFamily::Inet, 32, vec![RouteAttribute::Oif(5)]);
    local.header.table = 255;
    let mut beyond = route_reply(AddressFamily::Inet, 32, vec![RouteAttribute::Table(1000)]);
    beyond.header.table = 252;
    let other_family = route_reply(AddressFamily::Mpls, 20, Vec::new());
    let observed = observed_routes(
        [connected, endpoint, default, local, beyond, other_family]
            .into_iter()
            .map(RouteNetlinkMessage::NewRoute)
            .collect(),
    )?;
    let route = |address, length, gateway| ObservedRoute {
        link_index: 5,
        route: NamespaceRoute {
            destination: IpPrefix { address, length },
            gateway,
        },
    };
    assert_eq!(
        observed,
        [
            route(v4([10, 213, 0, 12]), 30, None),
            route(
                v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10]),
                128,
                Some(v6([0xfd00, 0x913, 0, 0, 0, 0, 0, 6]))
            ),
            route(v4([0, 0, 0, 0]), 0, None),
        ]
    );
    Ok(())
}

#[test]
fn unusual_main_table_routes_fail() {
    let mut blackhole = route_reply(AddressFamily::Inet, 32, vec![RouteAttribute::Oif(5)]);
    blackhole.header.kind = RouteType::BlackHole;
    let mut sourced = route_reply(AddressFamily::Inet6, 128, vec![RouteAttribute::Oif(5)]);
    sourced.header.source_prefix_length = 64;
    let mut tos = route_reply(AddressFamily::Inet, 32, vec![RouteAttribute::Oif(5)]);
    tos.header.tos = 4;
    let undecodable = [
        blackhole,
        sourced,
        tos,
        route_reply(AddressFamily::Inet, 32, Vec::new()),
        route_reply(
            AddressFamily::Inet,
            32,
            vec![RouteAttribute::Oif(5), RouteAttribute::Mark(1)],
        ),
        route_reply(
            AddressFamily::Inet,
            32,
            vec![
                RouteAttribute::Oif(5),
                RouteAttribute::Destination(RouteAddress::Other(vec![1])),
            ],
        ),
        route_reply(
            AddressFamily::Inet,
            32,
            vec![
                RouteAttribute::Oif(5),
                RouteAttribute::Gateway(RouteAddress::Other(vec![1])),
            ],
        ),
    ];
    for reply in undecodable {
        assert!(matches!(
            observed_routes(vec![RouteNetlinkMessage::NewRoute(reply)]),
            Err(NetlinkError::Unrepresentable)
        ));
    }
    assert!(matches!(
        observed_routes(vec![addresses()]),
        Err(NetlinkError::Unexpected)
    ));
}

/// A tentative link-local address of link `index`.
fn tentative_on(index: u32) -> RouteNetlinkMessage {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet6;
    message.header.prefix_len = 64;
    message.header.flags = AddressHeaderFlags::Tentative;
    message.header.index = index;
    message.attributes = vec![AddressAttribute::Address(v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]))];
    RouteNetlinkMessage::NewAddress(message)
}

#[test]
fn the_host_read_back_keeps_only_its_own_links_addresses() {
    let kept = of_link(vec![tentative_on(3), tentative_on(4), routes()], Some(4));
    assert_eq!(kept, [tentative_on(4), routes()]);
    assert_eq!(of_link(vec![tentative_on(4)], None), []);
}

#[test]
fn dumps_ask_for_every_address_and_route() {
    assert_eq!(
        addresses(),
        RouteNetlinkMessage::GetAddress(AddressMessage::default())
    );
    assert_eq!(
        routes(),
        RouteNetlinkMessage::GetRoute(RouteMessage::default())
    );
}
