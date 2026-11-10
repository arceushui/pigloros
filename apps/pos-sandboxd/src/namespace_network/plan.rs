//! The exact namespace one Local attempt receives, derived from the
//! installation's reserved address range, the attempt's slot in it and the
//! authenticated endpoints the attempt may reach (#911; owner decision
//! 2026-11-09).
//!
//! Slot `k` of the range owns the IPv4 /30 at offset `4k` and the IPv6 /127
//! at offset `2k`. The host veth end takes the lower usable address and the
//! namespace's end the next one. Inside the namespace, only the
//! authenticated endpoints are routed, through the host end, and the
//! firewall drops everything except TCP to those endpoints, return traffic of
//! connections the namespace opened, and IPv6 neighbour discovery with the
//! host end.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{
    ExpectedNamespace, FirewallBaseChain, FirewallChain, FirewallHook, FirewallRule,
    FirewallVerdict, IpPrefix, LinkName, NamespaceName, NamespaceRoute,
};

/// The name of the one nftables table inside every attempt namespace.
pub const NAMESPACE_TABLE: &str = "piglor_attempt";

/// The installation-configured private address range reserved for attempt
/// namespaces: one IPv4 network inside RFC 1918 space and one IPv6 network
/// inside unique local space (`fc00::/7`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkRange {
    ipv4: Ipv4Addr,
    ipv4_length: u8,
    ipv6: Ipv6Addr,
    ipv6_length: u8,
}

/// Why a range, slot or endpoint set cannot produce an attempt namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkPlanError {
    /// The IPv4 network is not an aligned network of at most /30 inside
    /// RFC 1918 space.
    #[error("the IPv4 range is not an aligned private network of at least four addresses")]
    Ipv4Range,
    /// The IPv6 network is not an aligned network of at most /127 inside
    /// unique local space.
    #[error("the IPv6 range is not an aligned unique local network of at least two addresses")]
    Ipv6Range,
    /// The slot lies outside the range.
    #[error("the attempt slot lies outside the reserved range")]
    Slot,
    /// An endpoint is not a reachable unicast address: it is loopback,
    /// unspecified, multicast, broadcast or link-local, or its port is zero.
    #[error("an endpoint is not a reachable unicast address and port")]
    Endpoint,
    /// An endpoint lies inside the reserved range.
    #[error("an endpoint lies inside the reserved range")]
    EndpointInRange,
    /// An endpoint is listed twice.
    #[error("an endpoint is listed twice")]
    DuplicateEndpoint,
}

impl NetworkRange {
    /// Reserve `ipv4/ipv4_length` and `ipv6/ipv6_length` for attempt
    /// namespaces.
    ///
    /// # Errors
    /// Rejects a network whose host bits are not zero, one too small for a
    /// single slot, and one that leaves private (IPv4) or unique local (IPv6)
    /// space.
    pub fn new(
        ipv4: Ipv4Addr,
        ipv4_length: u8,
        ipv6: Ipv6Addr,
        ipv6_length: u8,
    ) -> Result<Self, NetworkPlanError> {
        let v4 = u32::from(ipv4);
        let v4_hosts = u32::MAX.checked_shr(u32::from(ipv4_length)).unwrap_or(0);
        let v4_valid = ipv4_length <= 30
            && v4 & v4_hosts == 0
            && ipv4.is_private()
            && Ipv4Addr::from(v4 | v4_hosts).is_private();
        let v6 = u128::from(ipv6);
        let v6_hosts = u128::MAX.checked_shr(u32::from(ipv6_length)).unwrap_or(0);
        // An aligned network whose last address is unique local lies inside
        // `fc00::/7`: every larger aligned network ends at `ffff::`.
        let v6_valid = ipv6_length <= 127 && v6 & v6_hosts == 0 && unique_local(v6 | v6_hosts);
        match (v4_valid, v6_valid) {
            (false, _) => Err(NetworkPlanError::Ipv4Range),
            (true, false) => Err(NetworkPlanError::Ipv6Range),
            (true, true) => Ok(Self {
                ipv4,
                ipv4_length,
                ipv6,
                ipv6_length,
            }),
        }
    }

    /// How many slots the range holds: the smaller of its /30 and /127
    /// counts.
    #[must_use]
    pub fn slots(&self) -> u128 {
        let v4 = 1_u128 << (30 - self.ipv4_length);
        let v6 = 1_u128 << (127 - self.ipv6_length);
        v4.min(v6)
    }

    /// The host and namespace addresses of `slot`, and the networks they
    /// share.
    fn slot(&self, slot: u16) -> Result<SlotAddresses, NetworkPlanError> {
        if u128::from(slot) < self.slots() {
            let v4 = u32::from(self.ipv4) + 4 * u32::from(slot);
            let v6 = u128::from(self.ipv6) + 2 * u128::from(slot);
            Ok(SlotAddresses {
                ipv4: Ipv4Addr::from(v4),
                ipv6: Ipv6Addr::from(v6),
            })
        } else {
            Err(NetworkPlanError::Slot)
        }
    }

    /// Whether `address` lies inside the reserved range.
    pub(super) fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => {
                let hosts = u32::MAX
                    .checked_shr(u32::from(self.ipv4_length))
                    .unwrap_or(0);
                u32::from(address) & !hosts == u32::from(self.ipv4)
            }
            IpAddr::V6(address) => {
                let hosts = u128::MAX
                    .checked_shr(u32::from(self.ipv6_length))
                    .unwrap_or(0);
                u128::from(address) & !hosts == u128::from(self.ipv6)
            }
        }
    }
}

/// Whether `address` lies in `fc00::/7`.
const fn unique_local(address: u128) -> bool {
    // The top seven bits of `fc00::/7` are `1111110`.
    address >> 121 == 0x7e
}

/// The networks of one slot.
struct SlotAddresses {
    /// The slot's IPv4 /30 network address.
    ipv4: Ipv4Addr,
    /// The slot's IPv6 /127 network address.
    ipv6: Ipv6Addr,
}

impl SlotAddresses {
    fn host_ipv4(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(u32::from(self.ipv4) + 1))
    }

    fn inner_ipv4(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(u32::from(self.ipv4) + 2))
    }

    const fn host_ipv6(&self) -> IpAddr {
        IpAddr::V6(self.ipv6)
    }

    fn inner_ipv6(&self) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(u128::from(self.ipv6) + 1))
    }
}

/// A prefix of `length` bits at `address`.
const fn prefix(address: IpAddr, length: u8) -> IpPrefix {
    IpPrefix { address, length }
}

/// A drop-policy base chain at `hook` named after it.
fn drop_chain(name: &str, hook: FirewallHook, rules: Vec<FirewallRule>) -> FirewallChain {
    FirewallChain {
        name: name.to_owned(),
        base: Some(FirewallBaseChain {
            hook,
            priority: 0,
            policy: FirewallVerdict::Drop,
        }),
        rules,
    }
}

impl ExpectedNamespace {
    /// The namespace of `attempt_id` in `slot` of `range`, reaching exactly
    /// `endpoints`.
    ///
    /// Endpoints are canonicalised first: an IPv4-mapped IPv6 address is the
    /// IPv4 address it maps, and IPv6 flow information and scope, which the
    /// kernel does not read back, are dropped.
    ///
    /// # Errors
    /// Rejects, in this order, an endpoint that is not a reachable unicast
    /// address and port, an endpoint inside the range, an endpoint listed
    /// twice and a slot outside the range.
    pub fn for_attempt(
        attempt_id: [u8; 16],
        range: &NetworkRange,
        slot: u16,
        endpoints: &[SocketAddr],
    ) -> Result<Self, NetworkPlanError> {
        let endpoints: Vec<SocketAddr> = endpoints
            .iter()
            .map(|endpoint| SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()))
            .collect();
        let distinct: BTreeSet<&SocketAddr> = endpoints.iter().collect();
        let checked = if endpoints.iter().any(|endpoint| !reachable(endpoint)) {
            Err(NetworkPlanError::Endpoint)
        } else if endpoints
            .iter()
            .any(|endpoint| range.contains(endpoint.ip()))
        {
            Err(NetworkPlanError::EndpointInRange)
        } else if distinct.len() == endpoints.len() {
            range.slot(slot)
        } else {
            Err(NetworkPlanError::DuplicateEndpoint)
        };
        checked.map(|addresses| Self::slot_namespace(attempt_id, slot, &addresses, &endpoints))
    }

    fn slot_namespace(
        attempt_id: [u8; 16],
        slot: u16,
        addresses: &SlotAddresses,
        endpoints: &[SocketAddr],
    ) -> Self {
        let gateway = |endpoint: IpAddr| match endpoint {
            IpAddr::V4(_) => addresses.host_ipv4(),
            IpAddr::V6(_) => addresses.host_ipv6(),
        };
        let endpoint_routes: BTreeSet<NamespaceRoute> = endpoints
            .iter()
            .map(|endpoint| NamespaceRoute {
                destination: prefix(endpoint.ip(), host_length(endpoint.ip())),
                gateway: Some(gateway(endpoint.ip())),
            })
            .collect();
        let mut routes = vec![
            NamespaceRoute {
                destination: prefix(IpAddr::V4(addresses.ipv4), 30),
                gateway: None,
            },
            NamespaceRoute {
                destination: prefix(IpAddr::V6(addresses.ipv6), 127),
                gateway: None,
            },
        ];
        routes.extend(endpoint_routes);
        let mut output = vec![
            FirewallRule::SendNeighbourDiscovery {
                destination: SOLICITED_NODE,
                length: 104,
            },
            FirewallRule::SendNeighbourDiscovery {
                destination: addresses.ipv6,
                length: 128,
            },
        ];
        output.extend(endpoints.iter().copied().map(FirewallRule::AcceptTcp));
        Self {
            name: NamespaceName::for_attempt(attempt_id),
            inner_link: slot_link('n', slot),
            host_link: slot_link('h', slot),
            inner_addresses: vec![
                prefix(addresses.inner_ipv4(), 30),
                prefix(addresses.inner_ipv6(), 127),
            ],
            host_addresses: vec![
                prefix(addresses.host_ipv4(), 30),
                prefix(addresses.host_ipv6(), 127),
            ],
            routes,
            table: NAMESPACE_TABLE.to_owned(),
            chains: vec![
                drop_chain(
                    "input",
                    FirewallHook::Input,
                    vec![
                        FirewallRule::AcceptEstablished,
                        FirewallRule::AcceptNeighbourDiscovery,
                    ],
                ),
                drop_chain("forward", FirewallHook::Forward, Vec::new()),
                drop_chain("output", FirewallHook::Output, output),
            ],
        }
    }
}

/// The solicited-node multicast network `ff02::1:ff00:0/104`, to which the
/// namespace sends its neighbour solicitations.
const SOLICITED_NODE: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0);

/// Whether `endpoint` is a unicast address and nonzero port a route through
/// the host end can reach.
///
/// IPv4 refuses `0.0.0.0/8` ("this network"), loopback, link-local,
/// multicast, and `240.0.0.0/4` with the broadcast address. IPv6 refuses
/// `::/96`, which holds the unspecified, loopback and deprecated
/// IPv4-compatible addresses, link-local unicast and multicast.
const fn reachable(endpoint: &SocketAddr) -> bool {
    let unicast = match endpoint.ip() {
        IpAddr::V4(address) => {
            let first = address.octets()[0];
            first != 0 && first < 224 && !(address.is_loopback() || address.is_link_local())
        }
        IpAddr::V6(address) => {
            address.to_bits() >> 32 != 0
                && !(address.is_multicast() || address.is_unicast_link_local())
        }
    };
    unicast && endpoint.port() != 0
}

/// The prefix length of a single host of `address`'s family.
const fn host_length(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// The veth end of `slot` on `side`: `piglor-n<slot>` inside the namespace
/// and `piglor-h<slot>` on the host, at most 13 bytes.
fn slot_link(side: char, slot: u16) -> LinkName {
    LinkName(format!("piglor-{side}{slot}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
