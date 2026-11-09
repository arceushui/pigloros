use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ATTEMPT: [u8; 16] = [7; 16];

const fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

const fn v6(first: u16, second: u16, last: u16) -> Ipv6Addr {
    Ipv6Addr::new(first, second, 0, 0, 0, 0, 0, last)
}

/// 64 IPv4 slots and 128 IPv6 slots.
fn range() -> TestResult<NetworkRange> {
    NetworkRange::new(v4(10, 77, 0, 0), 24, v6(0xfd00, 0x77, 0), 120).map_err(Into::into)
}

const fn on(address: IpAddr, length: u8) -> IpPrefix {
    IpPrefix { address, length }
}

#[test]
fn ranges_hold_the_smaller_of_their_slot_counts() -> TestResult {
    assert_eq!(range()?.slots(), 64);
    let ipv6_bound = NetworkRange::new(v4(10, 0, 0, 0), 8, v6(0xfd00, 0, 0), 124)?;
    assert_eq!(ipv6_bound.slots(), 8);
    let single = NetworkRange::new(v4(192, 168, 9, 4), 30, v6(0xfc00, 0, 2), 127)?;
    assert_eq!(single.slots(), 1);
    Ok(())
}

#[test]
fn ipv4_ranges_must_be_aligned_private_and_hold_a_slot() {
    let ipv6 = v6(0xfd00, 0, 0);
    for (address, length) in [
        (v4(10, 77, 0, 0), 31),
        (v4(10, 77, 0, 1), 24),
        (v4(192, 0, 2, 0), 24),
        // The first address is private, the last is not.
        (v4(10, 0, 0, 0), 7),
        // The last address is private, the first is not.
        (v4(172, 0, 0, 0), 11),
        (v4(0, 0, 0, 0), 0),
    ] {
        assert_eq!(
            NetworkRange::new(address, length, ipv6, 64),
            Err(NetworkPlanError::Ipv4Range),
            "{address}/{length}"
        );
    }
    assert_eq!(
        NetworkRange::new(v4(1, 0, 0, 0), 31, ipv6, 128),
        Err(NetworkPlanError::Ipv4Range)
    );
}

#[test]
fn ipv6_ranges_must_be_aligned_unique_local_and_hold_a_slot() {
    let ipv4 = v4(10, 0, 0, 0);
    for (address, length) in [
        (v6(0xfd00, 0, 0), 128),
        (v6(0xfd00, 0, 1), 120),
        (v6(0x2001, 0xdb8, 0), 64),
        (v6(0xfc00, 0, 0), 6),
        (Ipv6Addr::UNSPECIFIED, 0),
    ] {
        assert_eq!(
            NetworkRange::new(ipv4, 8, address, length),
            Err(NetworkPlanError::Ipv6Range),
            "{address}/{length}"
        );
    }
}

#[test]
fn a_slot_owns_its_ipv4_slash_30_and_ipv6_slash_127() -> TestResult {
    let endpoint = SocketAddr::new(IpAddr::V4(v4(192, 168, 1, 10)), 8443);
    let expected = ExpectedNamespace::for_attempt(ATTEMPT, &range()?, 3, &[endpoint])?;
    assert_eq!(expected.name, NamespaceName::for_attempt(ATTEMPT));
    assert_eq!(expected.inner_link.as_str(), "piglor-n3");
    assert_eq!(expected.host_link.as_str(), "piglor-h3");
    assert_eq!(
        expected.inner_addresses,
        [
            on(IpAddr::V4(v4(10, 77, 0, 14)), 30),
            on(IpAddr::V6(v6(0xfd00, 0x77, 7)), 127),
        ]
    );
    assert_eq!(
        expected.host_addresses,
        [
            on(IpAddr::V4(v4(10, 77, 0, 13)), 30),
            on(IpAddr::V6(v6(0xfd00, 0x77, 6)), 127),
        ]
    );
    assert_eq!(expected.table, NAMESPACE_TABLE);
    Ok(())
}

#[test]
fn only_the_endpoints_are_routed_and_allowed() -> TestResult {
    let ipv4 = IpAddr::V4(v4(192, 168, 1, 10));
    let ipv6 = v6(0xfd12, 0, 5);
    let endpoints = [
        SocketAddr::new(ipv4, 8443),
        SocketAddr::new(ipv4, 9000),
        SocketAddr::V6(SocketAddrV6::new(ipv6, 443, 9, 7)),
    ];
    let expected = ExpectedNamespace::for_attempt(ATTEMPT, &range()?, 0, &endpoints)?;
    let host_v4 = IpAddr::V4(v4(10, 77, 0, 1));
    let host_v6 = IpAddr::V6(v6(0xfd00, 0x77, 0));
    let mut routes = expected.routes.clone();
    routes.sort_unstable();
    let mut wanted = vec![
        NamespaceRoute {
            destination: on(IpAddr::V4(v4(10, 77, 0, 0)), 30),
            gateway: None,
        },
        NamespaceRoute {
            destination: on(host_v6, 127),
            gateway: None,
        },
        NamespaceRoute {
            destination: on(ipv4, 32),
            gateway: Some(host_v4),
        },
        NamespaceRoute {
            destination: on(IpAddr::V6(ipv6), 128),
            gateway: Some(host_v6),
        },
    ];
    wanted.sort_unstable();
    assert_eq!(routes, wanted);
    let drop = |hook| {
        Some(FirewallBaseChain {
            hook,
            priority: 0,
            policy: FirewallVerdict::Drop,
        })
    };
    assert_eq!(
        expected.chains,
        [
            FirewallChain {
                name: "input".to_owned(),
                base: drop(FirewallHook::Input),
                rules: vec![
                    FirewallRule::AcceptEstablished,
                    FirewallRule::AcceptNeighbourDiscovery,
                ],
            },
            FirewallChain {
                name: "forward".to_owned(),
                base: drop(FirewallHook::Forward),
                rules: Vec::new(),
            },
            FirewallChain {
                name: "output".to_owned(),
                base: drop(FirewallHook::Output),
                rules: vec![
                    FirewallRule::SendNeighbourDiscovery {
                        destination: SOLICITED_NODE,
                        length: 104,
                    },
                    FirewallRule::SendNeighbourDiscovery {
                        destination: v6(0xfd00, 0x77, 0),
                        length: 128,
                    },
                    FirewallRule::AcceptTcp(endpoints[0]),
                    FirewallRule::AcceptTcp(endpoints[1]),
                    FirewallRule::AcceptTcp(SocketAddr::new(IpAddr::V6(ipv6), 443)),
                ],
            },
        ]
    );
    Ok(())
}

#[test]
fn an_attempt_without_endpoints_reaches_nothing() -> TestResult {
    let expected = ExpectedNamespace::for_attempt(ATTEMPT, &range()?, 1, &[])?;
    assert_eq!(expected.routes.len(), 2);
    assert!(expected.routes.iter().all(|route| route.gateway.is_none()));
    // Slot 1's host end is `fd00:77::2`.
    assert_eq!(
        expected.chains[2].rules,
        [
            FirewallRule::SendNeighbourDiscovery {
                destination: SOLICITED_NODE,
                length: 104,
            },
            FirewallRule::SendNeighbourDiscovery {
                destination: v6(0xfd00, 0x77, 2),
                length: 128,
            },
        ]
    );
    Ok(())
}

#[test]
fn slots_outside_the_range_are_refused() -> TestResult {
    let range = range()?;
    assert!(ExpectedNamespace::for_attempt(ATTEMPT, &range, 63, &[]).is_ok());
    assert_eq!(
        ExpectedNamespace::for_attempt(ATTEMPT, &range, 64, &[]),
        Err(NetworkPlanError::Slot)
    );
    Ok(())
}

#[test]
fn the_highest_slot_name_fits_an_interface_name() -> TestResult {
    let range = NetworkRange::new(v4(10, 0, 0, 0), 14, v6(0xfd00, 0, 0), 111)?;
    assert_eq!(range.slots(), 65_536);
    let expected = ExpectedNamespace::for_attempt(ATTEMPT, &range, u16::MAX, &[])?;
    assert_eq!(
        expected.host_addresses[0],
        on(IpAddr::V4(v4(10, 3, 255, 253)), 30)
    );
    assert_eq!(expected.inner_link, LinkName::new("piglor-n65535")?);
    assert_eq!(expected.host_link, LinkName::new("piglor-h65535")?);
    assert_eq!(
        expected.inner_addresses,
        [
            on(IpAddr::V4(v4(10, 3, 255, 254)), 30),
            on(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 1, 0xffff)),
                127
            ),
        ]
    );
    assert_eq!(
        expected.host_addresses[1],
        on(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 1, 0xfffe)),
            127
        )
    );
    Ok(())
}

#[test]
fn endpoints_inside_the_range_are_refused() -> TestResult {
    let range = range()?;
    for endpoint in [
        SocketAddr::new(IpAddr::V4(v4(10, 77, 0, 200)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfd00, 0x77, 0xff)), 80),
    ] {
        assert_eq!(
            ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &[endpoint]),
            Err(NetworkPlanError::EndpointInRange)
        );
    }
    for endpoint in [
        SocketAddr::new(IpAddr::V4(v4(10, 77, 1, 0)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfd00, 0x77, 0x100)), 80),
    ] {
        assert!(ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &[endpoint]).is_ok());
    }
    Ok(())
}

#[test]
fn endpoints_listed_twice_are_refused() -> TestResult {
    let range = range()?;
    let ipv4 = SocketAddr::new(IpAddr::V4(v4(192, 168, 1, 10)), 8443);
    let ipv6 = v6(0xfd12, 0, 5);
    for endpoints in [
        [ipv4, ipv4],
        [
            SocketAddr::V6(SocketAddrV6::new(ipv6, 443, 0, 1)),
            SocketAddr::V6(SocketAddrV6::new(ipv6, 443, 0, 2)),
        ],
    ] {
        assert_eq!(
            ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &endpoints),
            Err(NetworkPlanError::DuplicateEndpoint)
        );
    }
    Ok(())
}

#[test]
fn plan_errors_say_what_is_wrong() {
    for (error, message) in [
        (
            NetworkPlanError::Ipv4Range,
            "the IPv4 range is not an aligned private network of at least four addresses",
        ),
        (
            NetworkPlanError::Ipv6Range,
            "the IPv6 range is not an aligned unique local network of at least two addresses",
        ),
        (
            NetworkPlanError::Slot,
            "the attempt slot lies outside the reserved range",
        ),
        (
            NetworkPlanError::Endpoint,
            "an endpoint is not a reachable unicast address and port",
        ),
        (
            NetworkPlanError::EndpointInRange,
            "an endpoint lies inside the reserved range",
        ),
        (
            NetworkPlanError::DuplicateEndpoint,
            "an endpoint is listed twice",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn other_private_ipv4_blocks_and_unique_local_edges_are_ranges() {
    let ipv6 = v6(0xfd00, 0, 0);
    for (address, length) in [(v4(172, 16, 0, 0), 12), (v4(192, 168, 0, 0), 16)] {
        assert!(
            NetworkRange::new(address, length, ipv6, 64).is_ok(),
            "{address}"
        );
    }
    let ipv4 = v4(10, 0, 0, 0);
    let top = Ipv6Addr::new(0xfdff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0);
    for (address, length) in [(v6(0xfc00, 0, 0), 64), (top, 64), (v6(0xfc00, 0, 0), 7)] {
        assert!(
            NetworkRange::new(ipv4, 8, address, length).is_ok(),
            "{address}"
        );
    }
    for address in [v6(0xfbff, 0, 0), v6(0xfe00, 0, 0)] {
        assert_eq!(
            NetworkRange::new(ipv4, 8, address, 64),
            Err(NetworkPlanError::Ipv6Range),
            "{address}"
        );
    }
}

#[test]
fn slots_beyond_a_smaller_ipv6_side_are_refused() -> TestResult {
    let range = NetworkRange::new(v4(10, 0, 0, 0), 8, v6(0xfd00, 0, 0), 125)?;
    assert_eq!(range.slots(), 4);
    assert!(ExpectedNamespace::for_attempt(ATTEMPT, &range, 3, &[]).is_ok());
    assert_eq!(
        ExpectedNamespace::for_attempt(ATTEMPT, &range, 4, &[]),
        Err(NetworkPlanError::Slot)
    );
    Ok(())
}

#[test]
fn endpoints_at_the_range_edges_are_refused() -> TestResult {
    let range = range()?;
    for endpoint in [
        SocketAddr::new(IpAddr::V4(v4(10, 77, 0, 0)), 80),
        SocketAddr::new(IpAddr::V4(v4(10, 77, 0, 255)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfd00, 0x77, 0)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfd00, 0x77, 0xff)), 80),
        // IPv4-mapped IPv6 is the IPv4 address it maps.
        SocketAddr::new(IpAddr::V6(v4(10, 77, 0, 1).to_ipv6_mapped()), 80),
    ] {
        assert_eq!(
            ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &[endpoint]),
            Err(NetworkPlanError::EndpointInRange),
            "{endpoint}"
        );
    }
    let below_ipv6 = Ipv6Addr::new(0xfd00, 0x76, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);
    for endpoint in [
        SocketAddr::new(IpAddr::V4(v4(10, 76, 255, 255)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfd00, 0x76, 0xffff)), 80),
        // Adjacent to the range: just below its first and above its last
        // address.
        SocketAddr::new(IpAddr::V6(below_ipv6), 80),
        SocketAddr::new(IpAddr::V4(v4(10, 77, 1, 0)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfd00, 0x77, 0x100)), 80),
    ] {
        assert!(ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &[endpoint]).is_ok());
    }
    Ok(())
}

#[test]
fn a_mapped_endpoint_is_allowed_as_its_ipv4_address() -> TestResult {
    let mapped = SocketAddr::new(IpAddr::V6(v4(192, 168, 1, 10).to_ipv6_mapped()), 443);
    let expected = ExpectedNamespace::for_attempt(ATTEMPT, &range()?, 0, &[mapped])?;
    let plain = SocketAddr::new(IpAddr::V4(v4(192, 168, 1, 10)), 443);
    assert_eq!(
        expected.chains[2].rules.last(),
        Some(&FirewallRule::AcceptTcp(plain))
    );
    assert!(expected.routes.contains(&NamespaceRoute {
        destination: on(plain.ip(), 32),
        gateway: Some(IpAddr::V4(v4(10, 77, 0, 1))),
    }));
    Ok(())
}

#[test]
fn unreachable_endpoints_are_refused() -> TestResult {
    let range = range()?;
    for endpoint in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
        SocketAddr::new(IpAddr::V4(v4(224, 0, 0, 1)), 80),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 80),
        SocketAddr::new(IpAddr::V4(v4(169, 254, 1, 1)), 80),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80),
        SocketAddr::new(IpAddr::V6(v6(0xff02, 0, 1)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfe80, 0, 1)), 80),
        SocketAddr::new(IpAddr::V4(v4(192, 168, 1, 10)), 0),
        SocketAddr::new(IpAddr::V6(v6(0xfd12, 0, 5)), 0),
        // A mapped loopback address is loopback.
        SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 80),
        // "This network", reserved space and IPv4-compatible IPv6.
        SocketAddr::new(IpAddr::V4(v4(0, 1, 2, 3)), 80),
        SocketAddr::new(IpAddr::V4(v4(240, 0, 0, 1)), 80),
        SocketAddr::new(IpAddr::V4(v4(255, 255, 255, 254)), 80),
        SocketAddr::new(IpAddr::V6(v4(192, 168, 1, 10).to_ipv6_compatible()), 80),
    ] {
        assert_eq!(
            ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &[endpoint]),
            Err(NetworkPlanError::Endpoint),
            "{endpoint}"
        );
    }
    Ok(())
}

#[test]
fn unicast_neighbours_of_refused_blocks_are_reachable() -> TestResult {
    let range = range()?;
    for endpoint in [
        SocketAddr::new(IpAddr::V4(v4(1, 0, 0, 0)), 80),
        SocketAddr::new(IpAddr::V4(v4(223, 255, 255, 255)), 80),
        SocketAddr::new(IpAddr::V4(v4(126, 255, 255, 255)), 80),
        SocketAddr::new(IpAddr::V4(v4(169, 253, 255, 255)), 80),
        // The first address above `::/96`.
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 1, 0, 0)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfe7f, 0, 1)), 80),
        SocketAddr::new(IpAddr::V6(v6(0xfec0, 0, 1)), 80),
    ] {
        assert!(
            ExpectedNamespace::for_attempt(ATTEMPT, &range, 0, &[endpoint]).is_ok(),
            "{endpoint}"
        );
    }
    Ok(())
}

#[test]
fn refusals_follow_their_documented_order() -> TestResult {
    let range = range()?;
    let unreachable = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
    let inside = SocketAddr::new(IpAddr::V4(v4(10, 77, 0, 9)), 80);
    let outside = SocketAddr::new(IpAddr::V4(v4(192, 168, 1, 10)), 80);
    let cases = [
        (vec![inside, unreachable], 0, NetworkPlanError::Endpoint),
        (
            vec![outside, outside, inside],
            64,
            NetworkPlanError::EndpointInRange,
        ),
        (
            vec![outside, outside],
            64,
            NetworkPlanError::DuplicateEndpoint,
        ),
        (vec![outside], 64, NetworkPlanError::Slot),
    ];
    for (endpoints, slot, error) in cases {
        assert_eq!(
            ExpectedNamespace::for_attempt(ATTEMPT, &range, slot, &endpoints),
            Err(error)
        );
    }
    Ok(())
}
