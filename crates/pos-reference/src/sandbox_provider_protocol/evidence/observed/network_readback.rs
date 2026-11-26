//! KOE1 `network-readback`: the canonical Local network readback of
//! ADR-069 R14 §3.1, and the R14 §3.5 rule 4 checks.
//!
//! The record alone decides the types, bounds and order, that the attempt
//! namespace is neither the unit's nor the provider's network namespace, the
//! veth cross-links, and that the link names and addresses are one slot's.
//! The routes, the chains and the egress lists follow the planned endpoints,
//! which only a verifier holding AGR1, its plans and LPS1 knows
//! ([`LocalNetworkReadback::planned`]).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;

use ciborium::value::Value;

use super::super::{code, code_value, optional, optional_value, u32_in, Result};
use super::NamespaceIdentity;
use crate::sandbox_provider_protocol::codec::{
    array, byte_string, bytes_value, encode, require_canonical_order, text, text_value, uint,
    uint_value,
};
use crate::sandbox_provider_protocol::SandboxProviderProtocolError;

/// The largest `NETNSA_NSID` and interface index: both are positive `s32`.
const MAX_KERNEL_ID: u32 = 2_147_483_647;
const MAX_CHAIN_NAME_BYTES: usize = 64;
/// The prefix of every slot link name, before `n` or `h` and the slot.
const LINK_PREFIX: &str = "piglor-";
const INNER_LINK_PREFIX: &str = "piglor-n";
const HOST_LINK_PREFIX: &str = "piglor-h";
const IPV4_SLOT_LENGTH: u8 = 30;
const IPV6_SLOT_LENGTH: u8 = 127;
/// The solicited-node multicast range the namespace sends neighbour
/// discovery to: `ff02::1:ff00:0/104`.
const SOLICITED_NODE: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0);
const SOLICITED_NODE_LENGTH: u8 = 104;

/// An address with its prefix length, in network byte order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadbackPrefix {
    /// The address.
    pub address: IpAddr,
    /// The prefix length, at most the address width.
    pub length: u8,
}

impl ReadbackPrefix {
    const fn new(address: IpAddr, length: u8) -> Self {
        Self { address, length }
    }

    fn value(self) -> Value {
        Value::Array(vec![
            address_value(self.address),
            uint_value(u64::from(self.length)),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [address, length] = array::<2>(value)?;
        let address = ip_address(address)?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        u8_in(length, width).map(|length| Self { address, length })
    }
}

/// One end of the attempt's veth pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadbackVethEnd {
    /// Its interface index.
    pub index: u32,
    /// Its name, `piglor-n<slot>` inside the namespace or `piglor-h<slot>`
    /// in the host namespace.
    pub name: String,
    /// The other end's interface index.
    pub peer_index: u32,
    /// The NSID, as this end's namespace names it, of the other end's
    /// namespace.
    pub peer_netnsid: u32,
}

impl ReadbackVethEnd {
    fn value(&self) -> Value {
        Value::Array(vec![
            uint_value(u64::from(self.index)),
            text_value(&self.name),
            uint_value(u64::from(self.peer_index)),
            uint_value(u64::from(self.peer_netnsid)),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [index, name, peer_index, peer_netnsid] = array::<4>(value)?;
        Ok(Self {
            index: interface_index(index)?,
            name: link_name(name)?,
            peer_index: interface_index(peer_index)?,
            peer_netnsid: netnsid(peer_netnsid)?,
        })
    }
}

/// One main-table route of the attempt namespace.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadbackRoute {
    /// The destination.
    pub destination: ReadbackPrefix,
    /// The next hop; `None` for a connected route.
    pub gateway: Option<IpAddr>,
}

impl ReadbackRoute {
    fn value(self) -> Value {
        Value::Array(vec![
            self.destination.value(),
            optional_value(self.gateway, address_value),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [destination, gateway] = array::<2>(value)?;
        Ok(Self {
            destination: ReadbackPrefix::decode(destination)?,
            gateway: optional(gateway, ip_address)?,
        })
    }
}

/// The netfilter hook of a base chain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ReadbackFirewallHook {
    /// 0: packets addressed to the namespace.
    Input = 0,
    /// 1: packets routed through the namespace.
    Forward = 1,
    /// 2: packets the namespace sends.
    Output = 2,
}

/// The policy of a base chain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ReadbackFirewallPolicy {
    /// 0: accept a packet no rule decides.
    Accept = 0,
    /// 1: drop a packet no rule decides.
    Drop = 1,
}

/// The hook, priority and policy of a base chain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadbackFirewallBase {
    /// Where the chain is attached.
    pub hook: ReadbackFirewallHook,
    /// Its priority at that hook.
    pub priority: i32,
    /// Its policy.
    pub policy: ReadbackFirewallPolicy,
}

impl ReadbackFirewallBase {
    /// A priority 0 base chain that drops what no rule accepts, as every
    /// attempt-namespace chain is.
    const fn dropping(hook: ReadbackFirewallHook) -> Self {
        Self {
            hook,
            priority: 0,
            policy: ReadbackFirewallPolicy::Drop,
        }
    }

    fn value(self) -> Value {
        Value::Array(vec![
            code_value(self.hook),
            Value::Integer(self.priority.into()),
            code_value(self.policy),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [hook, priority, policy] = array::<3>(value)?;
        Ok(Self {
            hook: code(hook)?,
            priority: integer(priority).and_then(|priority| {
                i32::try_from(priority).map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
            })?,
            policy: code(policy)?,
        })
    }
}

/// One rule of the attempt namespace's firewall: kinds 0 to 3, the
/// provider's `FirewallRule` variants in declaration order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReadbackFirewallRule {
    /// 0: accept return traffic of a connection the namespace opened.
    AcceptEstablished,
    /// 1: accept neighbour discovery arriving on the veth.
    AcceptNeighbourDiscovery,
    /// 2: send neighbour discovery only to `destination/length`.
    SendNeighbourDiscovery {
        /// The destination network.
        destination: Ipv6Addr,
        /// Its prefix length, at most 128.
        length: u8,
    },
    /// 3: accept TCP to exactly this endpoint.
    AcceptTcp(SocketAddr),
}

impl ReadbackFirewallRule {
    fn value(self) -> Value {
        Value::Array(match self {
            Self::AcceptEstablished => vec![uint_value(0)],
            Self::AcceptNeighbourDiscovery => vec![uint_value(1)],
            Self::SendNeighbourDiscovery {
                destination,
                length,
            } => vec![
                uint_value(2),
                bytes_value(&destination.octets()),
                uint_value(u64::from(length)),
            ],
            Self::AcceptTcp(endpoint) => vec![
                uint_value(3),
                address_value(endpoint.ip()),
                uint_value(u64::from(endpoint.port())),
            ],
        })
    }

    fn decode(value: &Value) -> Result<Self> {
        let items = items(value, 1..=3)?;
        match (uint(&items[0])?, &items[1..]) {
            (0, []) => Ok(Self::AcceptEstablished),
            (1, []) => Ok(Self::AcceptNeighbourDiscovery),
            (2, [destination, length]) => Ok(Self::SendNeighbourDiscovery {
                destination: <[u8; 16]>::try_from(byte_string(destination)?)
                    .map(Ipv6Addr::from)
                    .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?,
                length: u8_in(length, 128)?,
            }),
            (3, [address, port]) => endpoint_parts(address, port).map(Self::AcceptTcp),
            (0..=3, _) => Err(SandboxProviderProtocolError::InvalidEncoding),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
        }
    }
}

/// One nftables chain of the attempt namespace.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadbackFirewallChain {
    /// The chain name, 1 to 64 bytes.
    pub name: String,
    /// The hook, priority and policy of a base chain; `None` for a regular
    /// chain.
    pub base: Option<ReadbackFirewallBase>,
    /// The rules, in kernel evaluation order.
    pub rules: Vec<ReadbackFirewallRule>,
}

impl ReadbackFirewallChain {
    fn value(&self) -> Value {
        Value::Array(vec![
            text_value(&self.name),
            optional_value(self.base, ReadbackFirewallBase::value),
            list_value(&self.rules, |rule| rule.value()),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [name, base, rules] = array::<3>(value)?;
        let name = text(name)?;
        if !(1..=MAX_CHAIN_NAME_BYTES).contains(&name.len()) {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        Ok(Self {
            name: name.to_owned(),
            base: optional(base, ReadbackFirewallBase::decode)?,
            rules: items(rules, 0..=usize::MAX)?
                .iter()
                .map(ReadbackFirewallRule::decode)
                .collect::<Result<_>>()?,
        })
    }

    /// A priority 0 dropping base chain named `name` at `hook`.
    fn dropping(name: &str, hook: ReadbackFirewallHook, rules: Vec<ReadbackFirewallRule>) -> Self {
        Self {
            name: name.to_owned(),
            base: Some(ReadbackFirewallBase::dropping(hook)),
            rules,
        }
    }
}

/// KOE1 `network-readback`: the canonical readback of a Local attempt's
/// provider-side network namespace and of its slice of the host table
/// (ADR-069 R14 §3.1).
///
/// The address, route, chain and egress lists are sorted and unique in
/// canonical encoding order; each chain's rules keep kernel evaluation
/// order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNetworkReadback {
    /// The nsfs identity of the attempt namespace.
    pub namespace: NamespaceIdentity,
    /// The host's NSID for the attempt namespace.
    pub namespace_netnsid: u32,
    /// The attempt namespace's NSID for the host.
    pub host_netnsid: u32,
    /// The attempt namespace's loopback interface index.
    pub loopback_index: u32,
    /// The veth end inside the attempt namespace.
    pub inner: ReadbackVethEnd,
    /// The veth end in the host namespace.
    pub host: ReadbackVethEnd,
    /// The inner end's IPv4 and IPv6 addresses.
    pub inner_addresses: Vec<ReadbackPrefix>,
    /// The host end's IPv4 and IPv6 addresses.
    pub host_addresses: Vec<ReadbackPrefix>,
    /// The attempt namespace's main-table routes.
    pub routes: Vec<ReadbackRoute>,
    /// The attempt namespace's `NFTA_GEN_ID`.
    pub firewall_generation: u32,
    /// The attempt namespace's three base chains.
    pub chains: Vec<ReadbackFirewallChain>,
    /// The endpoints this attempt's host-table chain accepts.
    pub egress_allowed: Vec<SocketAddr>,
    /// The endpoints this attempt's host-table postrouting masquerades.
    pub egress_masqueraded: Vec<SocketAddr>,
}

/// One slot's IPv4 network `N` and IPv6 network `M`.
#[derive(Clone, Copy)]
struct Slot {
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
}

impl Slot {
    /// The address `offset` above the IPv4 network, as a `/30` prefix.
    fn ipv4(self, offset: u32) -> ReadbackPrefix {
        ReadbackPrefix::new(
            IpAddr::V4(Ipv4Addr::from(u32::from(self.ipv4).wrapping_add(offset))),
            IPV4_SLOT_LENGTH,
        )
    }

    /// The address `offset` above the IPv6 network, as a `/127` prefix.
    fn ipv6(self, offset: u128) -> ReadbackPrefix {
        ReadbackPrefix::new(
            IpAddr::V6(Ipv6Addr::from(u128::from(self.ipv6).wrapping_add(offset))),
            IPV6_SLOT_LENGTH,
        )
    }

    /// A 4-aligned IPv4 network in one RFC 1918 block and a 2-aligned IPv6
    /// network in `fc00::/7`.
    fn allocatable(self) -> bool {
        u32::from(self.ipv4) % 4 == 0
            && self.ipv4.is_private()
            && u128::from(self.ipv6) % 2 == 0
            && self.ipv6.is_unique_local()
    }
}

impl LocalNetworkReadback {
    /// The readback with every list in canonical encoding order (R9 §4.1
    /// bytewise order, so text is length-first): the order the decoder
    /// requires. Each chain's rules keep kernel evaluation order.
    #[must_use]
    pub fn canonicalized(mut self) -> Self {
        // A value that cannot be encoded sorts first; the decoder then
        // refuses the record, so it is never accepted.
        self.inner_addresses
            .sort_by_cached_key(|prefix| encode(&prefix.value()).ok());
        self.host_addresses
            .sort_by_cached_key(|prefix| encode(&prefix.value()).ok());
        self.routes
            .sort_by_cached_key(|route| encode(&route.value()).ok());
        self.chains
            .sort_by_cached_key(|chain| encode(&chain.value()).ok());
        self.egress_allowed
            .sort_by_cached_key(|endpoint| encode(&endpoint_value(*endpoint)).ok());
        self.egress_masqueraded
            .sort_by_cached_key(|endpoint| encode(&endpoint_value(*endpoint)).ok());
        self
    }

    pub(super) fn value(&self) -> Value {
        Value::Array(vec![
            self.namespace.value(),
            uint_value(u64::from(self.namespace_netnsid)),
            uint_value(u64::from(self.host_netnsid)),
            uint_value(u64::from(self.loopback_index)),
            self.inner.value(),
            self.host.value(),
            list_value(&self.inner_addresses, |prefix| prefix.value()),
            list_value(&self.host_addresses, |prefix| prefix.value()),
            list_value(&self.routes, |route| route.value()),
            uint_value(u64::from(self.firewall_generation)),
            list_value(&self.chains, ReadbackFirewallChain::value),
            list_value(&self.egress_allowed, |endpoint| endpoint_value(*endpoint)),
            list_value(&self.egress_masqueraded, |endpoint| {
                endpoint_value(*endpoint)
            }),
        ])
    }

    /// Decode, and apply the rule 4 checks the record alone decides
    /// against the unit's and the provider's network namespaces.
    pub(super) fn decode(
        value: &Value,
        unit_network: NamespaceIdentity,
        provider_network: NamespaceIdentity,
    ) -> Result<Self> {
        let fields = array::<13>(value)?;
        let readback = Self {
            namespace: NamespaceIdentity::decode(&fields[0])?,
            namespace_netnsid: netnsid(&fields[1])?,
            host_netnsid: netnsid(&fields[2])?,
            loopback_index: interface_index(&fields[3])?,
            inner: ReadbackVethEnd::decode(&fields[4])?,
            host: ReadbackVethEnd::decode(&fields[5])?,
            inner_addresses: sorted(&fields[6], 2..=2, ReadbackPrefix::decode)?,
            host_addresses: sorted(&fields[7], 2..=2, ReadbackPrefix::decode)?,
            routes: sorted(&fields[8], 2..=usize::MAX, ReadbackRoute::decode)?,
            firewall_generation: u32_in(&fields[9], 0..=u32::MAX)?,
            chains: sorted(&fields[10], 3..=3, ReadbackFirewallChain::decode)?,
            egress_allowed: sorted(&fields[11], 0..=usize::MAX, endpoint)?,
            egress_masqueraded: sorted(&fields[12], 0..=usize::MAX, endpoint)?,
        };
        if readback.namespace == unit_network
            || readback.namespace == provider_network
            || !readback.cross_linked()
            || !readback.slot_named()
            || readback.slot().is_none()
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        Ok(readback)
    }

    /// Each veth end names the other and the other's namespace.
    const fn cross_linked(&self) -> bool {
        self.inner.peer_index == self.host.index
            && self.host.peer_index == self.inner.index
            && self.inner.peer_netnsid == self.host_netnsid
            && self.host.peer_netnsid == self.namespace_netnsid
    }

    /// The links are `piglor-n<k>` and `piglor-h<k>` for one `k`.
    fn slot_named(&self) -> bool {
        self.inner
            .name
            .strip_prefix(INNER_LINK_PREFIX)
            .is_some_and(|slot| self.host.name.strip_prefix(HOST_LINK_PREFIX) == Some(slot))
    }

    /// The slot the host end's addresses name, when they and the inner
    /// end's addresses are exactly one allocatable slot's: host `N+1/30`
    /// and `M/127`, inner `N+2/30` and `M+1/127`.
    fn slot(&self) -> Option<Slot> {
        let [ReadbackPrefix {
            address: IpAddr::V4(host_ipv4),
            length: IPV4_SLOT_LENGTH,
        }, ReadbackPrefix {
            address: IpAddr::V6(host_ipv6),
            length: IPV6_SLOT_LENGTH,
        }] = self.host_addresses.as_slice()
        else {
            return None;
        };
        let slot = Slot {
            ipv4: Ipv4Addr::from(u32::from(*host_ipv4).wrapping_sub(1)),
            ipv6: *host_ipv6,
        };
        (slot.allocatable() && self.inner_addresses == [slot.ipv4(2), slot.ipv6(1)]).then_some(slot)
    }

    /// The rule 4 checks that follow the planned endpoints: the endpoints
    /// of the LPS1 `network-capability` records the AGR1-bound plans name,
    /// in any order. IPv4-mapped addresses are mapped and duplicates
    /// dropped.
    ///
    /// The routes are the two connected routes and one host route per
    /// endpoint; the chains are exactly `input`, `forward` and `output`,
    /// whose rules end with one TCP accept per endpoint in endpoint order;
    /// and both egress lists are the IPv4 endpoints.
    pub(in crate::sandbox_provider_protocol::evidence) fn planned(
        &self,
        endpoints: &[SocketAddr],
    ) -> bool {
        // `SocketAddr` order is canonical encoding order: IPv4 first, then
        // the address bytes, then the port.
        let endpoints = endpoints
            .iter()
            .map(|endpoint| SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()))
            .collect::<BTreeSet<_>>();
        let ipv4 = endpoints
            .iter()
            .copied()
            .filter(SocketAddr::is_ipv4)
            .collect::<Vec<_>>();
        self.slot().is_some_and(|slot| {
            self.routes.iter().copied().collect::<BTreeSet<_>>() == routes(slot, &endpoints)
                && self.chains.iter().collect::<BTreeSet<_>>()
                    == chains(slot, &endpoints).iter().collect()
        }) && self.egress_allowed == ipv4
            && self.egress_masqueraded == ipv4
    }
}

/// The two connected routes, and a host route per endpoint via the host
/// end: `/32` via `N+1`, or `/128` via `M`.
fn routes(slot: Slot, endpoints: &BTreeSet<SocketAddr>) -> BTreeSet<ReadbackRoute> {
    let connected = [slot.ipv4(0), slot.ipv6(0)].map(|destination| ReadbackRoute {
        destination,
        gateway: None,
    });
    let hosts = endpoints.iter().map(|endpoint| {
        let (length, gateway) = match endpoint {
            SocketAddr::V4(_) => (32, slot.ipv4(1).address),
            SocketAddr::V6(_) => (128, IpAddr::V6(slot.ipv6)),
        };
        ReadbackRoute {
            destination: ReadbackPrefix::new(endpoint.ip(), length),
            gateway: Some(gateway),
        }
    });
    connected.into_iter().chain(hosts).collect()
}

/// `input` accepts return traffic and neighbour discovery, `forward`
/// accepts nothing, and `output` sends neighbour discovery and opens TCP to
/// each endpoint, all priority 0 and dropping.
fn chains(slot: Slot, endpoints: &BTreeSet<SocketAddr>) -> [ReadbackFirewallChain; 3] {
    let neighbour = |destination, length| ReadbackFirewallRule::SendNeighbourDiscovery {
        destination,
        length,
    };
    let output = [
        neighbour(SOLICITED_NODE, SOLICITED_NODE_LENGTH),
        neighbour(slot.ipv6, 128),
    ]
    .into_iter()
    .chain(
        endpoints
            .iter()
            .copied()
            .map(ReadbackFirewallRule::AcceptTcp),
    )
    .collect();
    [
        ReadbackFirewallChain::dropping(
            "input",
            ReadbackFirewallHook::Input,
            vec![
                ReadbackFirewallRule::AcceptEstablished,
                ReadbackFirewallRule::AcceptNeighbourDiscovery,
            ],
        ),
        ReadbackFirewallChain::dropping("forward", ReadbackFirewallHook::Forward, Vec::new()),
        ReadbackFirewallChain::dropping("output", ReadbackFirewallHook::Output, output),
    ]
}

/// An array whose length is within `count`.
fn items(value: &Value, count: RangeInclusive<usize>) -> Result<&[Value]> {
    let Value::Array(items) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    if count.contains(&items.len()) {
        Ok(items)
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

/// A list of `count` entries, each decoded, strictly increasing in
/// canonical encoding order.
fn sorted<T>(
    value: &Value,
    count: RangeInclusive<usize>,
    decode: impl Fn(&Value) -> Result<T>,
) -> Result<Vec<T>> {
    let items = items(value, count)?;
    let decoded = items.iter().map(decode).collect::<Result<Vec<_>>>()?;
    require_canonical_order(items).map(|()| decoded)
}

fn list_value<T>(items: &[T], value: impl Fn(&T) -> Value) -> Value {
    Value::Array(items.iter().map(value).collect())
}

/// A four- or sixteen-byte address.
fn ip_address(value: &Value) -> Result<IpAddr> {
    let bytes = byte_string(value)?;
    <[u8; 4]>::try_from(bytes)
        .map(IpAddr::from)
        .or_else(|_| <[u8; 16]>::try_from(bytes).map(IpAddr::from))
        .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
}

fn address_value(address: IpAddr) -> Value {
    match address {
        IpAddr::V4(address) => bytes_value(&address.octets()),
        IpAddr::V6(address) => bytes_value(&address.octets()),
    }
}

fn endpoint(value: &Value) -> Result<SocketAddr> {
    let [address, port] = array::<2>(value)?;
    endpoint_parts(address, port)
}

fn endpoint_parts(address: &Value, port: &Value) -> Result<SocketAddr> {
    let address = ip_address(address)?;
    uint(port).and_then(|port| {
        u16::try_from(port)
            .ok()
            .filter(|port| *port != 0)
            .map(|port| SocketAddr::new(address, port))
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
    })
}

fn endpoint_value(endpoint: SocketAddr) -> Value {
    Value::Array(vec![
        address_value(endpoint.ip()),
        uint_value(u64::from(endpoint.port())),
    ])
}

/// A small unsigned integer of at most `maximum`.
fn u8_in(value: &Value, maximum: u8) -> Result<u8> {
    uint(value).and_then(|number| {
        u8::try_from(number)
            .ok()
            .filter(|number| *number <= maximum)
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
    })
}

/// Any CBOR integer, signed or not.
fn integer(value: &Value) -> Result<i128> {
    let Value::Integer(number) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    Ok(i128::from(*number))
}

/// An assigned `NETNSA_NSID`, `0..=2147483647`; a negative one is out of
/// bounds.
fn netnsid(value: &Value) -> Result<u32> {
    integer(value).and_then(|number| {
        u32::try_from(number)
            .ok()
            .filter(|number| *number <= MAX_KERNEL_ID)
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
    })
}

fn interface_index(value: &Value) -> Result<u32> {
    u32_in(value, 1..=MAX_KERNEL_ID)
}

/// `piglor-n<k>` or `piglor-h<k>`, where `k` is `0` or up to five digits
/// without a leading zero.
fn link_name(value: &Value) -> Result<String> {
    let name = text(value)?;
    let slot = name
        .strip_prefix(LINK_PREFIX)
        .and_then(|end| end.strip_prefix(['n', 'h']));
    if slot.is_some_and(slot_number) {
        Ok(name.to_owned())
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

fn slot_number(digits: &str) -> bool {
    (1..=5).contains(&digits.len())
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
}
