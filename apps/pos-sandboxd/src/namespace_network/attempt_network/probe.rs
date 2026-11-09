//! The startup egress probe (#911, owner decision 2026-11-10): before
//! admission opens, prove that forwarded sandbox traffic actually passes
//! the host, so a host firewall the provider does not own (Docker's, ufw's,
//! an `iptables` FORWARD policy of DROP) closes admission instead of
//! silently blocking attempts.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsFd, BorrowedFd};

use super::*;
use crate::namespace_network::netlink::{NetlinkSession, NetlinkTransport, ROUTE};
use crate::namespace_network::{route, IpPrefix};

/// The reserved attempt identity of the probe's attempt network.
const PROBE_ATTEMPT: [u8; 16] = [0xff; 16];
/// The reserved identity whose namespace holds the probe's target.
const PROBE_TARGET: [u8; 16] = [0xfe; 16];
/// The probe target's veth end in the host namespace.
const PROBE_HOST_LINK: &str = "piglor-t0";
/// The probe target's veth end in its namespace.
const PROBE_TARGET_LINK: &str = "piglor-u0";
/// How long the probe's connection may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The installation-configured IPv4 /30 the probe's target lives in: the
/// host takes `network + 1` and the target `network + 2`. It must lie
/// outside the attempt range and every network the host uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressProbe {
    /// The /30's network address.
    pub network: Ipv4Addr,
    /// The port the target listens on.
    pub port: u16,
}

impl EgressProbe {
    pub(super) fn host(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }

    pub(super) fn target(self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(u32::from(self.network) + 2), self.port)
    }
}

/// Why the egress probe failed. Each failure keeps admission closed.
#[derive(Debug, thiserror::Error)]
pub enum EgressProbeError {
    /// The probe's target could not be set up or removed.
    #[error("the egress probe's target could not be set up or removed")]
    Target(#[source] NetlinkError),
    /// The probe's attempt network could not be established.
    #[error("the egress probe's attempt network could not be established")]
    Establish(#[source] AttemptNetworkError),
    /// Forwarded sandbox traffic did not reach the target.
    #[error("forwarded sandbox traffic did not pass the host")]
    Blocked(#[source] io::Error),
    /// The target saw the attempt's own address, not the host's.
    #[error("forwarded sandbox traffic was not masqueraded")]
    NotMasqueraded,
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

/// Create the target's veth pair with its far end in `target`, address
/// both ends, and listen on the target.
fn set_up_target(target: BorrowedFd<'_>, probe: EgressProbe) -> Result<TcpListener, NetlinkError> {
    let host_link = LinkName::new(PROBE_HOST_LINK).map_err(|_| NetlinkError::Unrepresentable)?;
    let target_link =
        LinkName::new(PROBE_TARGET_LINK).map_err(|_| NetlinkError::Unrepresentable)?;
    NetlinkSession::open(ROUTE)
        .and_then(|session| {
            session
                .execute(vec![route::veth_pair(&host_link, &target_link, target)])
                .and_then(|()| link_up(&session, &host_link, on_probe_network(probe.host())))
        })
        .and_then(|()| {
            in_namespace(target, || {
                NetlinkSession::open(ROUTE)
                    .and_then(|session| {
                        link_up(
                            &session,
                            &target_link,
                            on_probe_network(*probe.target().ip()),
                        )
                    })
                    .and_then(|()| {
                        TcpListener::bind(probe.target()).map_err(|error| {
                            NetlinkError::Io(
                                rustix::io::Errno::from_io_error(&error)
                                    .unwrap_or(rustix::io::Errno::IO),
                            )
                        })
                    })
            })
            .and_then(std::convert::identity)
        })
}

/// Remove the target's veth pair, if it exists, and its namespace.
fn remove_target(namespaces: &NetworkNamespaces) -> Result<(), NetlinkError> {
    let host_link = LinkName::new(PROBE_HOST_LINK).map_err(|_| NetlinkError::Unrepresentable)?;
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
    /// The startup composition opens admission only once this succeeds.
    ///
    /// # Errors
    /// Fails if the target or the probe's attempt network cannot be set up,
    /// the connection does not reach the target, the target sees an address
    /// other than the host's, or the target cannot be removed afterwards.
    pub fn probe_egress(&self, probe: EgressProbe) -> Result<(), EgressProbeError> {
        let target_name = NamespaceName::for_attempt(PROBE_TARGET);
        let probed = self
            .namespaces
            .create(&target_name)
            .and_then(|target| set_up_target(target.as_fd(), probe))
            .map_err(EgressProbeError::Target)
            .and_then(|listener| {
                self.connector(PROBE_ATTEMPT, &[SocketAddr::V4(probe.target())])
                    .map_err(EgressProbeError::Establish)
                    .and_then(|mut connector| {
                        connector
                            .connect(SocketAddr::V4(probe.target()), PROBE_TIMEOUT)
                            .and_then(|_| listener.accept())
                            .map_err(EgressProbeError::Blocked)
                    })
            })
            .and_then(|(_, peer)| {
                (peer.ip() == IpAddr::V4(probe.host()))
                    .then_some(())
                    .ok_or(EgressProbeError::NotMasqueraded)
            });
        let removed = remove_target(&self.namespaces).map_err(EgressProbeError::Target);
        probed.and(removed)
    }
}
