//! The kernel adapter of [`NamespaceControl`]: one attempt's namespace,
//! veth pair, addresses, routes and firewall, installed, read back and
//! removed in-process over netlink (#911, owner decisions 2026-11-09).
//!
//! The provider's own network namespace is the host namespace. Work inside
//! the attempt namespace runs on a dedicated thread that entered it, so no
//! other thread's namespace changes. The installation order is the port's:
//! the namespace and both namespace identifiers, the firewall, the veth
//! pair, then each end's `addr_gen_mode`, addresses and link state, and the
//! namespace's routes once its end is up.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{open, Mode, OFlags};
use rustix::io::Errno;

use super::netlink::{
    consistent, in_namespace, links, NetlinkError, NetlinkSession, NetlinkSocket, NetlinkTransport,
    Request, NETFILTER, ROUTE,
};
use super::pinned::NetworkNamespaces;
use super::{
    firewall, route, ExpectedNamespace, IpPrefix, LinkKind, LinkName, NamespaceControl,
    NamespaceName, NamespaceRoute, ObservedAddress, ObservedLink, ObservedNamespace,
};

/// The calling thread's network namespace file.
const THREAD_NAMESPACE: &str = "/proc/thread-self/ns/net";

/// [`NamespaceControl`] over netlink, with namespaces pinned in `namespaces`.
#[derive(Clone, Debug)]
pub struct NetlinkNamespaceControl {
    namespaces: NetworkNamespaces,
}

impl NetlinkNamespaceControl {
    /// The adapter that pins attempt namespaces in `namespaces`.
    #[must_use]
    pub const fn new(namespaces: NetworkNamespaces) -> Self {
        Self { namespaces }
    }
}

/// A descriptor of the calling thread's network namespace.
fn host_namespace() -> Result<OwnedFd, NetlinkError> {
    open(
        THREAD_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(NetlinkError::from)
}

/// Run `work` with a new session of `protocol` in the calling thread's
/// namespace, which ends with `work`.
fn with_session<R>(
    protocol: rustix::net::Protocol,
    work: impl FnOnce(&NetlinkSession<NetlinkSocket>) -> Result<R, NetlinkError>,
) -> Result<R, NetlinkError> {
    NetlinkSession::open(protocol).and_then(|session| work(&session))
}

/// Run `work` on a thread inside `namespace`.
fn inside<R: Send>(
    namespace: BorrowedFd<'_>,
    work: impl FnOnce() -> Result<R, NetlinkError> + Send,
) -> Result<R, NetlinkError> {
    in_namespace(namespace, work).and_then(std::convert::identity)
}

/// Turn off address generation on `link`, then add `addresses`, bring it up
/// and add `routes` through it, all in the session's namespace.
fn configure<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    link: &LinkName,
    addresses: &[IpPrefix],
    routes: &[NamespaceRoute],
) -> Result<(), NetlinkError> {
    session
        .execute(vec![route::no_address_generation(link)])
        .and_then(|()| route::link_reply(session.request(route::get_link(link))))
        .and_then(|observed| {
            observed
                .map(|link| link.index)
                .ok_or(NetlinkError::Unexpected)
        })
        .and_then(|index| {
            let requests: Vec<Request<_>> = addresses
                .iter()
                .map(|address| route::address(index, *address))
                .chain([route::up(link)])
                .chain(
                    routes
                        .iter()
                        .filter_map(|destination| route::route(index, destination)),
                )
                .collect();
            session.execute(requests)
        })
}

/// Install `expected` into the new namespace `namespace`, seen from the
/// host namespace `host`.
fn install_into(
    namespace: BorrowedFd<'_>,
    host: BorrowedFd<'_>,
    expected: &ExpectedNamespace,
) -> Result<(), NetlinkError> {
    with_session(ROUTE, |session| {
        session.execute(vec![route::assign_nsid(namespace)])
    })
    .and_then(|()| {
        inside(namespace, || {
            with_session(ROUTE, |session| {
                session.execute(vec![route::assign_nsid(host)])
            })
            .and_then(|()| {
                with_session(NETFILTER, |session| {
                    session.execute(firewall::install(&expected.table, &expected.chains))
                })
            })
        })
    })
    .and_then(|()| {
        with_session(ROUTE, |session| {
            session
                .execute(vec![route::veth_pair(
                    &expected.host_link,
                    &expected.inner_link,
                    namespace,
                )])
                .and_then(|()| {
                    configure(session, &expected.host_link, &expected.host_addresses, &[])
                })
        })
    })
    .and_then(|()| {
        inside(namespace, || {
            with_session(ROUTE, |session| {
                configure(
                    session,
                    &expected.inner_link,
                    &expected.inner_addresses,
                    &expected.routes,
                )
            })
        })
    })
}

/// What the host namespace holds of an attempt: its veth end, that end's
/// addresses, and the identifier it assigns to the attempt namespace.
type HostView = (Option<ObservedLink>, Vec<ObservedAddress>, i32);

/// Read the host's view of `namespace` and of host link `host_link`.
fn host_view<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    namespace: BorrowedFd<'_>,
    host_link: &LinkName,
) -> Result<HostView, NetlinkError> {
    route::link_reply(session.request(route::get_link(host_link))).and_then(|link| {
        session
            .dump(route::addresses())
            .and_then(route::observed_addresses)
            .and_then(|addresses| {
                session
                    .request(route::get_nsid(namespace))
                    .and_then(route::nsid_reply)
                    .map(|netnsid| {
                        let index = link.as_ref().map(|link| link.index);
                        let addresses = addresses
                            .into_iter()
                            .filter(|address| Some(address.link_index) == index)
                            .collect();
                        (link, addresses, netnsid)
                    })
            })
    })
}

/// Read everything inside the session's namespace, which the thread entered,
/// into `observed`, with the identifier it assigns to the host namespace
/// `host`.
fn inner_view<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    host: BorrowedFd<'_>,
    mut observed: ObservedNamespace,
) -> Result<ObservedNamespace, NetlinkError> {
    links(session)
        .map(|links| observed.links = links)
        .and_then(|()| {
            session
                .dump(route::addresses())
                .and_then(route::observed_addresses)
        })
        .map(|addresses| observed.addresses = addresses)
        .and_then(|()| {
            session
                .dump(route::routes())
                .and_then(route::observed_routes)
        })
        .map(|routes| observed.routes = routes)
        .and_then(|()| {
            session
                .request(route::get_nsid(host))
                .and_then(route::nsid_reply)
        })
        .map(|netnsid| {
            observed.host_netnsid = netnsid;
            observed
        })
}

/// Read every nftables table of the session's namespace.
fn tables<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
) -> Result<Vec<super::ObservedTable>, NetlinkError> {
    let [tables, chains, rules] = firewall::dumps();
    session.dump(tables).and_then(|tables| {
        session.dump(chains).and_then(|chains| {
            session
                .dump(rules)
                .and_then(|rules| firewall::observed_tables(tables, chains, rules))
        })
    })
}

/// Read back namespace `namespace` and host link `host_link`, from the host
/// namespace `host`.
fn observe_from(
    namespace: BorrowedFd<'_>,
    host: BorrowedFd<'_>,
    host_link: &LinkName,
) -> Result<ObservedNamespace, NetlinkError> {
    consistent(|| with_session(ROUTE, |session| host_view(session, namespace, host_link))).and_then(
        |(host_link, host_addresses, namespace_netnsid)| {
            let observed = ObservedNamespace {
                links: Vec::new(),
                addresses: Vec::new(),
                routes: Vec::new(),
                tables: Vec::new(),
                host_link,
                host_addresses,
                namespace_netnsid,
                host_netnsid: -1,
            };
            inside(namespace, || {
                with_session(ROUTE, |session| inner_view(session, host, observed)).and_then(
                    |mut observed| {
                        with_session(NETFILTER, tables).map(|tables| {
                            observed.tables = tables;
                            observed
                        })
                    },
                )
            })
        },
    )
}

/// Delete host link `host_link` if it is a veth end whose peer lies in
/// `namespace`, and leave any other link of that name.
fn remove_attempt_link(
    namespace: BorrowedFd<'_>,
    host_link: &LinkName,
) -> Result<(), NetlinkError> {
    with_session(ROUTE, |session| {
        // Reading the link first makes the kernel assign the peer's
        // namespace an identifier, if it has none, before it is compared.
        route::link_reply(session.request(route::get_link(host_link))).and_then(|link| {
            session
                .request(route::get_nsid(namespace))
                .and_then(route::nsid_reply)
                .and_then(|netnsid| match link {
                    Some(ObservedLink {
                        index,
                        kind:
                            LinkKind::Veth {
                                peer_netnsid: Some(peer),
                                ..
                            },
                        ..
                    }) if netnsid >= 0 && peer == netnsid => {
                        session.execute(vec![route::delete_link(index)])
                    }
                    _ => Ok(()),
                })
        })
    })
}

impl NamespaceControl for NetlinkNamespaceControl {
    type Error = NetlinkError;

    fn install(&self, expected: &ExpectedNamespace) -> Result<(), NetlinkError> {
        self.namespaces
            .create(&expected.name)
            .and_then(|namespace| {
                host_namespace()
                    .and_then(|host| install_into(namespace.as_fd(), host.as_fd(), expected))
            })
    }

    fn observe(
        &self,
        name: &NamespaceName,
        host_link: &LinkName,
    ) -> Result<ObservedNamespace, NetlinkError> {
        self.namespaces
            .open(name)
            .and_then(|namespace| namespace.ok_or(NetlinkError::Io(Errno::NOENT)))
            .and_then(|namespace| {
                host_namespace()
                    .and_then(|host| observe_from(namespace.as_fd(), host.as_fd(), host_link))
            })
    }

    fn remove(&self, name: &NamespaceName, host_link: &LinkName) -> Result<(), NetlinkError> {
        self.namespaces
            .open(name)
            .and_then(|namespace| {
                namespace.map_or(Ok(()), |namespace| {
                    remove_attempt_link(namespace.as_fd(), host_link)
                })
            })
            .and_then(|()| self.namespaces.delete(name))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
