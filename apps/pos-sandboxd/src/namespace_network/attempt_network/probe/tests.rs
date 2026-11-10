use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::route::RouteMessage;

use super::*;

const PROBE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 4);

fn address(address: Ipv4Addr) -> RouteNetlinkMessage {
    let mut message = AddressMessage::default();
    message.attributes = vec![AddressAttribute::Local(IpAddr::V4(address))];
    RouteNetlinkMessage::NewAddress(message)
}

fn route(destination: Ipv4Addr, length: u8) -> RouteNetlinkMessage {
    let mut message = RouteMessage::default();
    message.header.destination_prefix_length = length;
    message.attributes = vec![RouteAttribute::Destination(RouteAddress::Inet(destination))];
    RouteNetlinkMessage::NewRoute(message)
}

#[test]
fn prefixes_overlap_the_probe_network_when_they_share_its_bits() {
    assert!(overlaps(Ipv4Addr::new(198, 18, 0, 6), 32, PROBE));
    assert!(overlaps(Ipv4Addr::new(198, 18, 0, 0), 16, PROBE));
    assert!(overlaps(Ipv4Addr::new(198, 18, 0, 4), 30, PROBE));
    assert!(!overlaps(Ipv4Addr::new(198, 18, 0, 8), 30, PROBE));
    assert!(!overlaps(Ipv4Addr::new(198, 18, 0, 3), 32, PROBE));
    assert!(!overlaps(Ipv4Addr::new(10, 0, 0, 0), 8, PROBE));
}

#[test]
fn a_host_address_or_route_in_the_probe_network_conflicts() {
    let elsewhere = [address(Ipv4Addr::new(10, 0, 0, 1))];
    let routes = [
        route(Ipv4Addr::new(10, 0, 0, 0), 8),
        route(Ipv4Addr::UNSPECIFIED, 0),
    ];
    // A default route covers everything and is no conflict.
    assert!(!conflicts(PROBE, &elsewhere, &routes));
    assert!(conflicts(
        PROBE,
        &[address(Ipv4Addr::new(198, 18, 0, 5))],
        &routes
    ));
    // A peer address counts as much as a local one.
    let mut peer = AddressMessage::default();
    peer.attributes = vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 6))),
    ];
    assert!(conflicts(
        PROBE,
        &[RouteNetlinkMessage::NewAddress(peer)],
        &routes
    ));
    assert!(conflicts(
        PROBE,
        &elsewhere,
        &[route(Ipv4Addr::new(198, 16, 0, 0), 12)]
    ));
    // Other replies say nothing.
    assert!(!conflicts(PROBE, &[route(PROBE, 30)], &[address(PROBE)]));
}

#[test]
fn the_probes_veth_ends_are_valid_interface_names() {
    for name in [PROBE_HOST_LINK, PROBE_TARGET_LINK] {
        assert_eq!(LinkName::new(name), Ok(probe_link(name)));
    }
}
