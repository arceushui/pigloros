//! The startup egress probe (#911, owner decision 2026-11-10): prove that
//! forwarded sandbox traffic actually passes the host, so that a host
//! firewall the provider does not own (Docker's, ufw's, an `iptables`
//! FORWARD policy of DROP) can keep admission closed instead of silently
//! blocking attempts. Restart reconciliation runs it through
//! [`LocalEgressProbe`] once orphaned network state is removed, before
//! admission opens, and keeps admission closed on any error (#1200).
//!
//! The probe establishes a real attempt network, through the same path as
//! every attempt, for a reserved probe attempt whose one endpoint lies in a
//! target namespace behind the host on a dedicated veth pair. A TCP
//! connection from the probe's namespace must reach the target, arriving
//! from the host's address on that pair, which also proves masquerade. The
//! probe removes everything it made, and restart reconciliation removes any
//! remains (its names are the provider's own). It reads and changes no
//! table it does not own.
//!
//! The target sits behind a veth pair rather than the host's real uplink, so
//! a host rule that drops only traffic leaving by one particular uplink
//! passes the probe; the installation requirement still forbids such rules.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;
use std::time::Duration;

use pos_reference::sandbox_provider_protocol::NetworkEndpointConnector;

use super::{
    AttemptNetworkError, EgressControl, HostEgress, NamespacedLocalNetwork, NetworkNamespaces,
};
use crate::namespace_network::netlink::{
    in_namespace, NetlinkError, NetlinkSession, NetlinkTransport, ROUTE,
};
use crate::namespace_network::{route, IpPrefix, LinkName, NamespaceControl, NamespaceName};
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use netlink_packet_route::RouteNetlinkMessage;

/// The reserved attempt identity of the probe's attempt network.
const PROBE_ATTEMPT: [u8; 16] = [0xff; 16];
/// The reserved identity whose namespace holds the probe's target.
const PROBE_TARGET: [u8; 16] = [0xfe; 16];
/// The probe target's veth end in the host namespace.
pub(in crate::namespace_network) const PROBE_HOST_LINK: &str = "piglor-t0";
/// The probe target's veth end in its namespace.
const PROBE_TARGET_LINK: &str = "piglor-u0";
/// How long the probe's connection may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The installation-configured IPv4 /30 the probe's target lives in, and
/// the port the target listens on.
///
/// The host takes `network + 1` and the target `network + 2`. Only
/// [`EgressProbe::new`] makes one, so every probe's /30 is aligned ordinary
/// unicast space with a nonzero port. It must also lie outside the attempt
/// range and every address and route the host has; the probe checks those
/// against the live host and refuses it otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressProbe {
    network: Ipv4Addr,
    port: u16,
}

/// Why an installation's egress probe configuration was refused. Each
/// refusal keeps admission closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidEgressProbe {
    /// The network is not the network address of an IPv4 /30.
    #[error("the egress probe's network is not the network address of an IPv4 /30")]
    Misaligned,
    /// The /30 lies in `0.0.0.0/8`, loopback `127.0.0.0/8`, link-local
    /// `169.254.0.0/16`, multicast `224.0.0.0/4` or the reserved
    /// `240.0.0.0/4`, which includes the limited broadcast address: none of
    /// them can address a veth link.
    #[error("the egress probe's /30 is not ordinary unicast space")]
    SpecialPurpose,
    /// The target's port is zero.
    #[error("the egress probe's target port is zero")]
    Port,
}

impl EgressProbe {
    /// The probe of the /30 at `network`, whose target listens on `port`.
    ///
    /// # Errors
    /// Refuses a `network` that is not a /30's network address, a /30 in
    /// special-purpose space that cannot address a link, and port zero.
    pub fn new(network: Ipv4Addr, port: u16) -> Result<Self, InvalidEgressProbe> {
        let [first, second, ..] = network.octets();
        let special = first == 0 || first == 127 || first >= 224 || (first == 169 && second == 254);
        if network.to_bits().trailing_zeros() < 2 {
            Err(InvalidEgressProbe::Misaligned)
        } else if special {
            Err(InvalidEgressProbe::SpecialPurpose)
        } else if port == 0 {
            Err(InvalidEgressProbe::Port)
        } else {
            Ok(Self { network, port })
        }
    }

    /// The host's and the target's address: the /30's first and second
    /// host addresses. Neither overflows, since the /30 lies below
    /// `224.0.0.0`.
    pub(super) fn addresses(self) -> (Ipv4Addr, SocketAddrV4) {
        let network = self.network.to_bits();
        (
            Ipv4Addr::from_bits(network + 1),
            SocketAddrV4::new(Ipv4Addr::from_bits(network + 2), self.port),
        )
    }
}

/// Whether the prefix `address/length` overlaps the /30 at `network`.
fn overlaps(address: Ipv4Addr, length: u8, network: Ipv4Addr) -> bool {
    let shared = u32::from(length.min(30));
    let mask = u32::MAX.checked_shl(32 - shared).unwrap_or(0);
    address.to_bits() & mask == network.to_bits() & mask
}

/// Whether any IPv4 address or route the host's `addresses` and `routes`
/// dumps report lies in the /30 at `network`. A default route, which covers
/// everything, is no conflict.
fn conflicts(
    network: Ipv4Addr,
    addresses: &[RouteNetlinkMessage],
    routes: &[RouteNetlinkMessage],
) -> bool {
    let address_conflict = addresses.iter().any(|reply| match reply {
        RouteNetlinkMessage::NewAddress(message) => message.attributes.iter().any(|attribute| {
            matches!(
                attribute,
                AddressAttribute::Local(IpAddr::V4(address))
                    | AddressAttribute::Address(IpAddr::V4(address))
                    if overlaps(*address, 32, network)
            )
        }),
        _ => false,
    });
    let route_conflict = routes.iter().any(|reply| match reply {
        RouteNetlinkMessage::NewRoute(message) => {
            let length = message.header.destination_prefix_length;
            length > 0
                && message.attributes.iter().any(|attribute| {
                    matches!(
                        attribute,
                        RouteAttribute::Destination(RouteAddress::Inet(address))
                            if overlaps(*address, length, network)
                    )
                })
        }
        _ => false,
    });
    address_conflict || route_conflict
}

/// Check, through the host's route `session`, that the /30 at `network` is
/// free on the host.
fn unused_by_host<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    network: Ipv4Addr,
) -> Result<bool, NetlinkError> {
    session.dump(route::addresses()).and_then(|addresses| {
        session
            .dump(route::routes())
            .map(|routes| !conflicts(network, &addresses, &routes))
    })
}

/// Why the egress probe failed. Each failure must keep admission closed.
#[derive(Debug, thiserror::Error)]
pub enum EgressProbeError {
    /// The configured /30 overlaps the attempt range or a host address or
    /// route.
    #[error("the egress probe's /30 overlaps the attempt range or a host address or route")]
    Network,
    /// The probe's target could not be set up or removed.
    #[error("the egress probe's target could not be set up or removed")]
    Target(#[source] NetlinkError),
    /// The probe's target could not listen on its address.
    #[error("the egress probe's target could not listen")]
    Listen(#[source] io::Error),
    /// The probe's attempt network could not be established.
    #[error("the egress probe's attempt network could not be established")]
    Establish(#[source] AttemptNetworkError),
    /// Forwarded sandbox traffic did not reach the target.
    #[error("forwarded sandbox traffic did not pass the host")]
    Blocked(#[source] io::Error),
    /// The target saw the attempt's own address, not the host's.
    #[error("forwarded sandbox traffic was not masqueraded")]
    NotMasqueraded,
    /// The probe panicked, or its task was cancelled because the runtime
    /// shut down, so it never reported its outcome.
    #[error("the egress probe did not run to completion")]
    Interrupted,
}

/// The probe's addresses, checked.
#[derive(Clone, Copy)]
struct Placed {
    host: Ipv4Addr,
    target: SocketAddrV4,
}

/// Give link `name` of the session's namespace `address` and bring it up.
fn link_up<T: NetlinkTransport>(
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

/// An address of the probe's /30.
const fn on_probe_network(address: Ipv4Addr) -> IpPrefix {
    IpPrefix {
        address: IpAddr::V4(address),
        length: 30,
    }
}

/// One of the probe's own veth ends, [`PROBE_HOST_LINK`] or
/// [`PROBE_TARGET_LINK`], both valid interface names.
fn probe_link(name: &str) -> LinkName {
    LinkName(name.to_owned())
}

/// Create the target's veth pair with its far end in `target`, address
/// both ends, and listen on the target.
fn set_up_target(target: BorrowedFd<'_>, probe: Placed) -> Result<TcpListener, EgressProbeError> {
    let host_link = probe_link(PROBE_HOST_LINK);
    let target_link = probe_link(PROBE_TARGET_LINK);
    NetlinkSession::open(ROUTE)
        .and_then(|session| {
            session
                .execute(vec![route::veth_pair(&host_link, &target_link, target)])
                .and_then(|()| link_up(&session, &host_link, on_probe_network(probe.host)))
        })
        .and_then(|()| {
            in_namespace(target, || {
                NetlinkSession::open(ROUTE)
                    .and_then(|session| {
                        link_up(&session, &target_link, on_probe_network(*probe.target.ip()))
                    })
                    .map(|()| TcpListener::bind(probe.target))
            })
            .and_then(std::convert::identity)
        })
        .map_err(EgressProbeError::Target)
        .and_then(|bound| bound.map_err(EgressProbeError::Listen))
}

/// Remove the target's veth pair, if it exists, and its namespace.
fn remove_target(namespaces: &NetworkNamespaces) -> Result<(), NetlinkError> {
    let host_link = probe_link(PROBE_HOST_LINK);
    NetlinkSession::open(ROUTE)
        .and_then(|session| {
            route::link_reply(session.request(route::get_link(&host_link))).and_then(|link| {
                link.map_or(Ok(()), |link| {
                    session.execute(vec![route::delete_link(link.index)])
                })
            })
        })
        .and_then(|()| namespaces.delete(&NamespaceName::for_attempt(PROBE_TARGET)))
}

impl<C, E> NamespacedLocalNetwork<C, E>
where
    C: NamespaceControl<Error = NetlinkError>,
    E: EgressControl,
{
    /// Prove that forwarded sandbox traffic passes the host and is
    /// masqueraded, through a probe attempt to a target in `probe`'s /30.
    /// Restart reconciliation runs this through [`LocalEgressProbe`] before
    /// admission opens, and keeps admission closed on any error.
    ///
    /// # Errors
    /// Fails if the target or the probe's attempt network cannot be set up,
    /// the connection does not reach the target, the target sees an address
    /// other than the host's, or the target cannot be removed afterwards.
    pub fn probe_egress(&self, probe: EgressProbe) -> Result<(), EgressProbeError> {
        self.probe_egress_through(|| NetlinkSession::open(ROUTE), probe)
    }

    /// [`Self::probe_egress`], reading the host's addresses and routes
    /// through a session from `host_session`.
    pub(super) fn probe_egress_through<T: NetlinkTransport>(
        &self,
        host_session: impl FnOnce() -> Result<NetlinkSession<T>, NetlinkError>,
        probe: EgressProbe,
    ) -> Result<(), EgressProbeError> {
        // The range and the /30 are both aligned, so they overlap exactly
        // when the range holds the /30's network address.
        if self.range.contains(IpAddr::V4(probe.network)) {
            return Err(EgressProbeError::Network);
        }
        let (host, target) = probe.addresses();
        host_session()
            .and_then(|session| unused_by_host(&session, probe.network))
            .map_err(EgressProbeError::Target)
            .and_then(|unused| unused.then_some(()).ok_or(EgressProbeError::Network))?;
        let probe = Placed { host, target };
        let target_name = NamespaceName::for_attempt(PROBE_TARGET);
        let probed = self
            .namespaces
            .create(&target_name)
            .map_err(EgressProbeError::Target)
            .and_then(|target| set_up_target(target.as_fd(), probe))
            .and_then(|listener| {
                self.connector(PROBE_ATTEMPT, &[SocketAddr::V4(probe.target)])
                    .map_err(EgressProbeError::Establish)
                    .and_then(|mut connector| {
                        connector
                            .connect(SocketAddr::V4(probe.target), PROBE_TIMEOUT)
                            .and_then(|_| listener.accept())
                            .map_err(EgressProbeError::Blocked)
                    })
            })
            .and_then(|(_, peer)| {
                (peer.ip() == IpAddr::V4(probe.host))
                    .then_some(())
                    .ok_or(EgressProbeError::NotMasqueraded)
            });
        let removed = remove_target(&self.namespaces).map_err(EgressProbeError::Target);
        probed.and(removed)
    }
}

/// Run the blocking `probe` on Tokio's blocking pool. A probe that panics,
/// or whose task is cancelled because the runtime shuts down, fails as
/// [`EgressProbeError::Interrupted`]: the property is never reported present
/// unless the probe ran to completion.
async fn on_blocking_pool(
    probe: impl FnOnce() -> Result<(), EgressProbeError> + Send + 'static,
) -> Result<(), EgressProbeError> {
    tokio::task::spawn_blocking(probe)
        .await
        .unwrap_or(Err(EgressProbeError::Interrupted))
}

/// Restart reconciliation's egress probe (#1200): the installation's
/// configured [`EgressProbe`] through the Local network port that attempts
/// use, so the probe exercises exactly their path.
#[derive(Debug)]
pub struct LocalEgressProbe<C, E = HostEgress> {
    network: Arc<NamespacedLocalNetwork<C, E>>,
    probe: EgressProbe,
}

impl<C, E> LocalEgressProbe<C, E> {
    /// Probe `network`, the port admitted attempts will use, with `probe`.
    #[must_use]
    pub const fn new(network: Arc<NamespacedLocalNetwork<C, E>>, probe: EgressProbe) -> Self {
        Self { network, probe }
    }
}

/// The blocking [`NamespacedLocalNetwork::probe_egress`] on Tokio's blocking
/// pool, so the reconciling task's worker keeps running other tasks.
impl<C, E> crate::EgressPropertyProbe for LocalEgressProbe<C, E>
where
    C: NamespaceControl<Error = NetlinkError> + Send + Sync + 'static,
    E: EgressControl + Send + Sync + 'static,
{
    type Error = EgressProbeError;

    fn probe_egress(&self) -> impl Future<Output = Result<(), EgressProbeError>> + Send {
        let network = Arc::clone(&self.network);
        let probe = self.probe;
        on_blocking_pool(move || network.probe_egress(probe))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
