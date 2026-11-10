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

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{open, Mode};
use rustix::io::Errno;

use super::netlink::{
    consistent, in_namespace, links, NetlinkError, NetlinkSession, NetlinkSocket, NetlinkTransport,
    Request, NETFILTER, ROUTE,
};
use super::pinned::{NetworkNamespaces, READ_ONLY};
use super::{
    firewall, route, ExpectedNamespace, IpPrefix, LinkKind, LinkName, NamespaceControl,
    NamespaceName, NamespaceRoute, ObservedAddress, ObservedLink, ObservedNamespace, ObservedRoute,
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
    open(THREAD_NAMESPACE, READ_ONLY, Mode::empty()).map_err(NetlinkError::from)
}

/// Run `work` with a new session of `protocol` in the calling thread's
/// namespace, which ends with `work`.
fn with_session<R>(
    protocol: Option<rustix::net::Protocol>,
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
        let index = link.as_ref().map(|link| link.index);
        session
            .dump(route::addresses())
            .map(|replies| route::of_link(replies, index))
            .and_then(route::observed_addresses)
            .and_then(|addresses| {
                session
                    .request(route::get_nsid(namespace))
                    .and_then(route::nsid_reply)
                    .map(|netnsid| (link, addresses, netnsid))
            })
    })
}

/// What the attempt namespace holds, apart from its firewall: its links,
/// addresses and main-table routes, and the identifier it assigns to the
/// host namespace.
type InnerView = (
    Vec<ObservedLink>,
    Vec<ObservedAddress>,
    Vec<ObservedRoute>,
    i32,
);

/// Read the session's namespace, which the thread entered, and the
/// identifier it assigns to the host namespace `host`.
fn inner_view<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
    host: BorrowedFd<'_>,
) -> Result<InnerView, NetlinkError> {
    links(session).and_then(|links| {
        session
            .dump(route::addresses())
            .and_then(route::observed_addresses)
            .and_then(|addresses| {
                session
                    .dump(route::routes())
                    .and_then(route::observed_routes)
                    .and_then(|routes| {
                        session
                            .request(route::get_nsid(host))
                            .and_then(route::nsid_reply)
                            .map(|netnsid| (links, addresses, routes, netnsid))
                    })
            })
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
            inside(namespace, || {
                with_session(ROUTE, |session| inner_view(session, host))
                    .and_then(|inner| with_session(NETFILTER, tables).map(|tables| (inner, tables)))
            })
            .map(|((links, addresses, routes, host_netnsid), tables)| {
                ObservedNamespace {
                    links,
                    addresses,
                    routes,
                    tables,
                    host_link,
                    host_addresses,
                    namespace_netnsid,
                    host_netnsid,
                }
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

/// The prefix of every provider-owned host veth end.
const HOST_LINK_PREFIX: &str = "piglor-h";

/// Every provider-owned host veth end the session's namespace holds: each
/// attempt's `piglor-h…` and the egress probe's `piglor-t0`.
fn attempt_host_links<T: NetlinkTransport>(
    session: &NetlinkSession<T>,
) -> Result<Vec<ObservedLink>, NetlinkError> {
    links(session).map(|links| links.into_iter().filter(is_attempt_host_link).collect())
}

/// Whether `link` is a provider-owned host veth end.
fn is_attempt_host_link(link: &ObservedLink) -> bool {
    (link.name.starts_with(HOST_LINK_PREFIX)
        || link.name == super::attempt_network::PROBE_HOST_LINK)
        && matches!(link.kind, LinkKind::Veth { .. })
}

/// Why [`NetlinkNamespaceControl::remove_orphans`] failed.
#[derive(Debug, thiserror::Error)]
pub enum OrphanSweepError {
    /// A recorded egress device's IPv4 forwarding could not be restored. The
    /// host egress table, whose rule drops unmatched sandbox traffic, stays.
    #[error("a recorded egress device's forwarding could not be restored, so the host egress table stays")]
    Forwarding(#[source] super::host_egress::HostEgressError),
    /// The host egress table, a host link or a namespace could not be
    /// removed, or remained afterwards.
    #[error("orphaned provider network state could not be removed")]
    Netlink(#[from] NetlinkError),
}

/// `Ok` if neither `names` nor `links` remain.
fn none_remain(names: &[NamespaceName], links: &[ObservedLink]) -> Result<(), NetlinkError> {
    match (names, links) {
        ([], []) => Ok(()),
        _ => Err(NetlinkError::Residual),
    }
}

/// `deleted`, with a link that no longer exists counted as deleted.
const fn already_gone(deleted: Result<(), NetlinkError>) -> Result<(), NetlinkError> {
    match deleted {
        Err(NetlinkError::Kernel(route::NO_SUCH_LINK)) => Ok(()),
        other => other,
    }
}

impl NetlinkNamespaceControl {
    /// Restore every egress device's recorded forwarding, then remove the
    /// host egress table, every host veth end named `piglor-h…` and every
    /// attempt namespace pinned in this adapter's directory, whichever
    /// attempt owned them, and read their absence back.
    ///
    /// Only restart reconciliation may call this, before admission opens and
    /// once every attempt unit is known to be gone: it removes the network of
    /// any attempt, live or not.
    ///
    /// Forwarding goes first, so a device whose forwarding cannot be
    /// restored keeps the table's drop rule for unmatched sandbox traffic.
    /// Then the host links go. Unpinning a namespace lets the kernel destroy
    /// it, and its veth pair with it, asynchronously; a link that is already
    /// gone when its deletion arrives counts as removed.
    ///
    /// # Errors
    /// Fails with [`OrphanSweepError::Forwarding`] if a recorded device's
    /// forwarding cannot be restored, and otherwise if any of them cannot be
    /// removed, or remains afterwards.
    pub fn remove_orphans(&self) -> Result<(), OrphanSweepError> {
        self.remove_orphans_through(
            || NetlinkSession::open(ROUTE),
            || NetlinkSession::open(NETFILTER),
            &super::host_egress::ForwardingRecords::default(),
        )
    }

    /// [`Self::remove_orphans`], restoring the forwarding `records` hold
    /// through a session from `route_session` before the host egress table
    /// goes through sessions from `netfilter_session`.
    fn remove_orphans_through<R: NetlinkTransport, N: NetlinkTransport>(
        &self,
        route_session: impl FnOnce() -> Result<NetlinkSession<R>, NetlinkError>,
        netfilter_session: impl Fn() -> Result<NetlinkSession<N>, NetlinkError>,
        records: &super::host_egress::ForwardingRecords,
    ) -> Result<(), OrphanSweepError> {
        route_session()
            .map_err(OrphanSweepError::from)
            .and_then(|route| {
                super::host_egress::restore_forwarding(&route, records)
                    .map_err(OrphanSweepError::Forwarding)
            })
            .and_then(|()| {
                self.remove_orphaned_network(netfilter_session)
                    .map_err(OrphanSweepError::from)
            })
    }

    /// The host egress table, through sessions from `netfilter_session`,
    /// then the host links and namespaces of [`Self::remove_orphans`], read
    /// back as absent.
    fn remove_orphaned_network<N: NetlinkTransport>(
        &self,
        netfilter_session: impl Fn() -> Result<NetlinkSession<N>, NetlinkError>,
    ) -> Result<(), NetlinkError> {
        super::host_egress::remove_table(netfilter_session)
            .and_then(|()| consistent(|| with_session(ROUTE, attempt_host_links)))
            .and_then(|orphans| {
                orphans.iter().try_for_each(|link| {
                    already_gone(with_session(ROUTE, |session| {
                        session.execute(vec![route::delete_link(link.index)])
                    }))
                })
            })
            .and_then(|()| self.namespaces.attempt_names())
            .and_then(|names| {
                names
                    .iter()
                    .try_for_each(|name| self.namespaces.delete(name))
            })
            .and_then(|()| self.namespaces.attempt_names())
            .and_then(|names| {
                consistent(|| with_session(ROUTE, attempt_host_links)).map(|links| (names, links))
            })
            .and_then(|(names, links)| none_remain(&names, &links))
    }
}

/// Run the blocking `sweep` on Tokio's blocking pool. A sweep that panics,
/// or whose task is cancelled because the runtime shuts down, fails as
/// [`NetlinkError::Panicked`]: the sweep is never reported done unless it
/// ran to completion.
async fn on_blocking_pool(
    sweep: impl FnOnce() -> Result<(), OrphanSweepError> + Send + 'static,
) -> Result<(), OrphanSweepError> {
    tokio::task::spawn_blocking(sweep)
        .await
        .unwrap_or(Err(OrphanSweepError::Netlink(NetlinkError::Panicked)))
}

/// Restart reconciliation's network sweep (#1200): the blocking
/// [`NetlinkNamespaceControl::remove_orphans`] on Tokio's blocking pool, so
/// the reconciling task's worker keeps running other tasks.
impl crate::OrphanNetworkCleanup for NetlinkNamespaceControl {
    type Error = OrphanSweepError;

    fn remove_orphans(&self) -> impl Future<Output = Result<(), OrphanSweepError>> + Send {
        let control = self.clone();
        on_blocking_pool(move || control.remove_orphans())
    }
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
