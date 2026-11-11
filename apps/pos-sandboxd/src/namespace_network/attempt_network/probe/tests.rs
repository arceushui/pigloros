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

#[test]
fn only_an_aligned_unicast_slash_30_with_a_port_is_a_probe() {
    for accepted in [
        PROBE,
        Ipv4Addr::new(1, 0, 0, 0),
        Ipv4Addr::new(10, 254, 0, 0),
        Ipv4Addr::new(126, 255, 255, 252),
        Ipv4Addr::new(128, 0, 0, 0),
        Ipv4Addr::new(169, 0, 0, 4),
        Ipv4Addr::new(169, 253, 0, 0),
        Ipv4Addr::new(169, 255, 0, 0),
        Ipv4Addr::new(223, 255, 255, 252),
    ] {
        let probe = EgressProbe::new(accepted, 1);
        assert_eq!(
            probe,
            Ok(EgressProbe {
                network: accepted,
                port: 1
            }),
            "{accepted}"
        );
    }
    for misaligned in [
        Ipv4Addr::new(198, 18, 0, 5),
        Ipv4Addr::new(198, 18, 0, 6),
        Ipv4Addr::new(198, 18, 0, 7),
        Ipv4Addr::LOCALHOST,
    ] {
        assert_eq!(
            EgressProbe::new(misaligned, 7000),
            Err(InvalidEgressProbe::Misaligned),
            "{misaligned}"
        );
    }
    for special in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(0, 255, 255, 252),
        Ipv4Addr::new(127, 0, 0, 0),
        Ipv4Addr::new(169, 254, 0, 0),
        Ipv4Addr::new(224, 0, 0, 0),
        Ipv4Addr::new(240, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 252),
    ] {
        assert_eq!(
            EgressProbe::new(special, 7000),
            Err(InvalidEgressProbe::SpecialPurpose),
            "{special}"
        );
    }
    assert_eq!(EgressProbe::new(PROBE, 0), Err(InvalidEgressProbe::Port));
}

#[test]
fn invalid_probe_configurations_say_what_is_wrong() {
    for (error, message) in [
        (
            InvalidEgressProbe::Misaligned,
            "the egress probe's network is not the network address of an IPv4 /30",
        ),
        (
            InvalidEgressProbe::SpecialPurpose,
            "the egress probe's /30 lies in 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 or 224.0.0.0/3",
        ),
        (
            InvalidEgressProbe::Port,
            "the egress probe's target port is zero",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn the_host_and_the_target_take_the_first_two_host_addresses() -> Result<(), InvalidEgressProbe> {
    assert_eq!(
        EgressProbe::new(PROBE, 7000)?.addresses(),
        (
            Ipv4Addr::new(198, 18, 0, 5),
            SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 6), 7000)
        )
    );
    assert_eq!(
        EgressProbe::new(Ipv4Addr::new(223, 255, 255, 252), 1)?.addresses(),
        (
            Ipv4Addr::new(223, 255, 255, 253),
            SocketAddrV4::new(Ipv4Addr::new(223, 255, 255, 254), 1)
        )
    );
    Ok(())
}

#[tokio::test]
async fn a_probe_on_the_blocking_pool_reports_its_outcome_or_its_interruption() {
    assert!(on_blocking_pool(|| Ok(())).await.is_ok());
    let blocked = on_blocking_pool(|| Err(EgressProbeError::NotMasqueraded)).await;
    assert!(
        matches!(blocked, Err(EgressProbeError::NotMasqueraded)),
        "{blocked:?}"
    );
    let panicked =
        on_blocking_pool(|| std::panic::resume_unwind(Box::new("the probe panicked"))).await;
    assert!(
        matches!(panicked, Err(EgressProbeError::Interrupted)),
        "{panicked:?}"
    );
}

#[test]
fn only_one_probe_is_marked_running_at_a_time() {
    let running = Arc::default();
    let first = Running::claim(&running);
    assert!(first.is_some());
    assert!(Running::claim(&running).is_none());
    drop(first);
    assert!(Running::claim(&running).is_some());
}

#[tokio::test]
async fn a_probe_is_refused_while_an_earlier_one_runs() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let namespaces = NetworkNamespaces::pinned_under(directory.path());
    let range = crate::NetworkRange::new(
        Ipv4Addr::new(10, 213, 0, 0),
        24,
        std::net::Ipv6Addr::new(0xfd00, 0x913, 0, 0, 0, 0, 0, 0),
        120,
    )?;
    let network = NamespacedLocalNetwork::new(
        crate::NetlinkNamespaceControl::new(namespaces.clone()),
        HostEgress::new(),
        namespaces,
        range,
    );
    let probe = LocalEgressProbe::new(Arc::new(network), EgressProbe::new(PROBE, 7000)?);
    let earlier = Running::claim(&probe.running);
    let refused = crate::EgressPropertyProbe::probe_egress(&probe).await;
    assert!(
        matches!(refused, Err(EgressProbeError::InFlight)),
        "{refused:?}"
    );
    assert!(earlier.is_some());
    // Nothing was started: the pinning directory is still empty.
    assert!(std::fs::read_dir(directory.path())?.next().is_none());
    Ok(())
}
