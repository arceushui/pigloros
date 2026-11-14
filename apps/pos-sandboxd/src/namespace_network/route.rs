//! The route-netlink requests that build one attempt's links, addresses,
//! routes and namespace identifiers, and the decoders that read them back
//! (#911, owner decision 2026-11-09).
//!
//! Each builder returns one request for a
//! [`NetlinkSession`](super::netlink::NetlinkSession); each decoder
//! turns the kernel's replies into the port's observed types, and fails on
//! any state those types cannot represent: a point-to-point or tentative
//! address, or a main-table route that is not a plain unicast route through
//! one link.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd};

use netlink_packet_core::{NLM_F_CREATE, NLM_F_EXCL};
use netlink_packet_route::address::{
    AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage,
};
use netlink_packet_route::link::{
    AfSpecInet6, AfSpecUnspec, In6AddrGenMode, InfoData, InfoKind, InfoVeth, LinkAttribute,
    LinkFlags, LinkInfo, LinkMessage,
};
use netlink_packet_route::nsid::{NsidAttribute, NsidMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};

use super::netlink::{observed_link, NetlinkError, Request};
use super::{IpPrefix, LinkName, NamespaceRoute, ObservedAddress, ObservedLink, ObservedRoute};

/// `-ENODEV`: the kernel has no link of the requested name.
pub(super) const NO_SUCH_LINK: i32 = -19;
/// `RT_TABLE_MAIN`, as a 32-bit `RTA_TABLE` reports it.
const MAIN_TABLE: u32 = 254;
/// `NETNSA_NSID_NOT_ASSIGNED`: let the kernel choose the identifier.
const ANY_NSID: i32 = -1;
// The flags are disjoint single bits, so the sum is their union and, unlike
// `|`, no mutation of the operator leaves it unchanged.
/// Create an object, and fail if it exists.
const CREATE_NEW: u16 = NLM_F_CREATE + NLM_F_EXCL;
/// The states of an address that is not usable yet, or never will be.
const UNSETTLED: AddressFlags = AddressFlags::Tentative.union(AddressFlags::Dadfailed);

/// A link message for `name` with `attributes`.
fn named_link(name: &LinkName, attributes: Vec<LinkAttribute>) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.attributes = std::iter::once(LinkAttribute::IfName(name.as_str().to_owned()))
        .chain(attributes)
        .collect();
    message
}

/// Create the veth pair `host` and `inner` in one request, with `inner` in
/// `namespace`. `NLM_F_EXCL` refuses an existing `host`, so the pair is never
/// adopted.
pub(super) fn veth_pair(
    host: &LinkName,
    inner: &LinkName,
    namespace: BorrowedFd<'_>,
) -> Request<RouteNetlinkMessage> {
    let peer = named_link(inner, vec![LinkAttribute::NetNsFd(namespace.as_raw_fd())]);
    let pair = named_link(
        host,
        vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer))),
        ])],
    );
    Request::acknowledged(RouteNetlinkMessage::NewLink(pair), CREATE_NEW)
}

/// Set `addr_gen_mode` of link `name` to `none`, so bringing it up adds no
/// link-local address or route.
pub(super) fn no_address_generation(name: &LinkName) -> Request<RouteNetlinkMessage> {
    let spec = AfSpecUnspec::Inet6(vec![AfSpecInet6::AddrGenMode(In6AddrGenMode::None)]);
    Request::acknowledged(
        RouteNetlinkMessage::SetLink(named_link(
            name,
            vec![LinkAttribute::AfSpecUnspec(vec![spec])],
        )),
        0,
    )
}

/// Bring link `name` up.
pub(super) fn up(name: &LinkName) -> Request<RouteNetlinkMessage> {
    let mut message = named_link(name, Vec::new());
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;
    Request::acknowledged(RouteNetlinkMessage::SetLink(message), 0)
}

/// Delete the link with interface index `index`.
pub(super) fn delete_link(index: u32) -> Request<RouteNetlinkMessage> {
    let mut message = LinkMessage::default();
    message.header.index = index;
    Request::acknowledged(RouteNetlinkMessage::DelLink(message), 0)
}

/// Get the link named `name`.
pub(super) fn get_link(name: &LinkName) -> RouteNetlinkMessage {
    RouteNetlinkMessage::GetLink(named_link(name, Vec::new()))
}

/// The link a [`get_link`] reply reports, or `None` if no link has the
/// name.
///
/// # Errors
/// Fails on any other refusal, another reply, or a link the port cannot
/// represent.
pub(super) fn link_reply(
    reply: Result<RouteNetlinkMessage, NetlinkError>,
) -> Result<Option<ObservedLink>, NetlinkError> {
    match reply {
        Ok(RouteNetlinkMessage::NewLink(message)) => observed_link(message).map(Some),
        Err(NetlinkError::Kernel(NO_SUCH_LINK)) => Ok(None),
        Err(error) => Err(error),
        Ok(_) => Err(NetlinkError::Unexpected),
    }
}

/// The address family of `address`.
const fn family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

/// Add `prefix` to link `index` with `IFA_F_NODAD`, so it is never
/// tentative.
pub(super) fn address(index: u32, prefix: IpPrefix) -> Request<RouteNetlinkMessage> {
    let mut message = AddressMessage::default();
    message.header.family = family(prefix.address);
    message.header.prefix_len = prefix.length;
    message.header.flags = AddressHeaderFlags::Nodad;
    message.header.index = index;
    message.attributes = match prefix.address {
        IpAddr::V4(_) => vec![
            AddressAttribute::Local(prefix.address),
            AddressAttribute::Address(prefix.address),
        ],
        IpAddr::V6(_) => vec![AddressAttribute::Address(prefix.address)],
    };
    Request::acknowledged(RouteNetlinkMessage::NewAddress(message), CREATE_NEW)
}

/// Add `route` through link `index` to the main table, if it has a gateway.
/// The kernel adds each connected route itself, from the address that
/// covers it, once the link is up.
pub(super) fn route(index: u32, route: &NamespaceRoute) -> Option<Request<RouteNetlinkMessage>> {
    route.gateway.map(|gateway| {
        let mut message = RouteMessage::default();
        message.header.address_family = family(route.destination.address);
        message.header.destination_prefix_length = route.destination.length;
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.kind = RouteType::Unicast;
        message.attributes = vec![
            RouteAttribute::Destination(RouteAddress::from(route.destination.address)),
            RouteAttribute::Gateway(RouteAddress::from(gateway)),
            RouteAttribute::Oif(index),
        ];
        Request::acknowledged(RouteNetlinkMessage::NewRoute(message), CREATE_NEW)
    })
}

/// Assign an identifier, of the kernel's choice, to the namespace of
/// `namespace` in the session's namespace.
pub(super) fn assign_nsid(namespace: BorrowedFd<'_>) -> Request<RouteNetlinkMessage> {
    let mut message = NsidMessage::default();
    message.attributes = vec![
        NsidAttribute::Fd(namespace.as_raw_fd().unsigned_abs()),
        NsidAttribute::Id(ANY_NSID),
    ];
    Request::acknowledged(RouteNetlinkMessage::NewNsId(message), 0)
}

/// Get the identifier the session's namespace assigns to the namespace of
/// `namespace`.
pub(super) fn get_nsid(namespace: BorrowedFd<'_>) -> RouteNetlinkMessage {
    let mut message = NsidMessage::default();
    message.attributes = vec![NsidAttribute::Fd(namespace.as_raw_fd().unsigned_abs())];
    RouteNetlinkMessage::GetNsId(message)
}

/// The identifier a [`get_nsid`] reply reports; `-1` when none is assigned.
///
/// # Errors
/// Fails on another reply, or one without an identifier.
pub(super) fn nsid_reply(reply: RouteNetlinkMessage) -> Result<i32, NetlinkError> {
    match reply {
        RouteNetlinkMessage::NewNsId(message) => message
            .attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                NsidAttribute::Id(id) => Some(id),
                _ => None,
            })
            .ok_or(NetlinkError::Unrepresentable),
        _ => Err(NetlinkError::Unexpected),
    }
}

/// A dump of every address of the session's namespace.
pub(super) fn addresses() -> RouteNetlinkMessage {
    RouteNetlinkMessage::GetAddress(AddressMessage::default())
}

/// A dump of every route of the session's namespace.
pub(super) fn routes() -> RouteNetlinkMessage {
    RouteNetlinkMessage::GetRoute(RouteMessage::default())
}

/// The replies of an [`addresses`] dump that are not addresses of another
/// link than `index`, so another link's state, such as a tentative address
/// still in duplicate detection, never fails the read-back; no address is
/// kept when `index` is `None`.
pub(super) fn of_link(
    replies: Vec<RouteNetlinkMessage>,
    index: Option<u32>,
) -> Vec<RouteNetlinkMessage> {
    replies
        .into_iter()
        .filter(|reply| match reply {
            RouteNetlinkMessage::NewAddress(message) => Some(message.header.index) == index,
            _ => true,
        })
        .collect()
}

/// Every address an [`addresses`] dump reports.
///
/// # Errors
/// Fails on another reply, an address without exactly one local address,
/// and an address that is tentative or failed duplicate detection.
pub(super) fn observed_addresses(
    replies: Vec<RouteNetlinkMessage>,
) -> Result<Vec<ObservedAddress>, NetlinkError> {
    replies
        .into_iter()
        .map(|reply| match reply {
            RouteNetlinkMessage::NewAddress(message) => observed_address(message),
            _ => Err(NetlinkError::Unexpected),
        })
        .collect()
}

/// The address `message` reports.
fn observed_address(message: AddressMessage) -> Result<ObservedAddress, NetlinkError> {
    let mut flags = AddressFlags::from_bits_retain(u32::from(message.header.flags.bits()));
    let mut local = None;
    let mut address = None;
    for attribute in message.attributes {
        match attribute {
            AddressAttribute::Local(value) => local = Some(value),
            AddressAttribute::Address(value) => address = Some(value),
            AddressAttribute::Flags(value) => flags = value,
            _ => {}
        }
    }
    let settled = !flags.intersects(UNSETTLED);
    match (local, address) {
        // IPv4 reports the local address twice; IPv6 only as the address.
        // A different peer address is a point-to-point link.
        (Some(local), Some(address)) if local == address && settled => Ok(local),
        (None, Some(address)) if settled => Ok(address),
        _ => Err(NetlinkError::Unrepresentable),
    }
    .map(|address| ObservedAddress {
        link_index: message.header.index,
        address: IpPrefix {
            address,
            length: message.header.prefix_len,
        },
    })
}

/// Every main-table IPv4 and IPv6 route a [`routes`] dump reports. Routes
/// of other tables, such as the local table's, and of other families are
/// left out.
///
/// # Errors
/// Fails on another reply, and on a main-table route that is not a unicast
/// route through one link, without source or type-of-service selectors and
/// without attributes beyond its destination, gateway, link, preferred
/// source, metric, preference, metrics and cache information.
pub(super) fn observed_routes(
    replies: Vec<RouteNetlinkMessage>,
) -> Result<Vec<ObservedRoute>, NetlinkError> {
    replies
        .into_iter()
        .filter_map(|reply| match reply {
            RouteNetlinkMessage::NewRoute(message) => observed_route(message).transpose(),
            _ => Some(Err(NetlinkError::Unexpected)),
        })
        .collect()
}

/// The main-table route `message` reports, or `None` for another table or
/// family.
fn observed_route(message: RouteMessage) -> Result<Option<ObservedRoute>, NetlinkError> {
    let header = message.header;
    let unspecified = match header.address_family {
        AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        AddressFamily::Inet6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => return Ok(None),
    };
    let mut table = u32::from(header.table);
    let mut destination = Some(unspecified);
    let mut gateway = None;
    let mut link = None;
    let mut plain =
        header.kind == RouteType::Unicast && header.source_prefix_length == 0 && header.tos == 0;
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Table(value) => table = value,
            RouteAttribute::Destination(value) => destination = ip(&value),
            RouteAttribute::Gateway(value) => gateway = Some(ip(&value)),
            RouteAttribute::Oif(value) => link = Some(value),
            RouteAttribute::PrefSource(_)
            | RouteAttribute::Priority(_)
            | RouteAttribute::Preference(_)
            | RouteAttribute::Metrics(_)
            | RouteAttribute::CacheInfo(_) => {}
            _ => plain = false,
        }
    }
    match (table == MAIN_TABLE, plain, destination, gateway, link) {
        (false, ..) => Ok(None),
        (true, true, Some(address), None, Some(link_index)) => {
            Ok(Some((address, None, link_index)))
        }
        (true, true, Some(address), Some(Some(gateway)), Some(link_index)) => {
            Ok(Some((address, Some(gateway), link_index)))
        }
        _ => Err(NetlinkError::Unrepresentable),
    }
    .map(|route| {
        route.map(|(address, gateway, link_index)| ObservedRoute {
            link_index,
            route: NamespaceRoute {
                destination: IpPrefix {
                    address,
                    length: header.destination_prefix_length,
                },
                gateway,
            },
        })
    })
}

/// The IP address `address` holds, if any.
const fn ip(address: &RouteAddress) -> Option<IpAddr> {
    match *address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(address)),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
