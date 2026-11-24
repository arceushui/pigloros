//! The unit network namespace check and the host sysctl it relies on
//! (ADR-069 R14 N12, every execution mode).
//!
//! A unit runs with `PrivateNetwork=true`, so its own network namespace is
//! KOE1 `namespaces[5]`. Nothing but the provider's own check may call that
//! namespace isolated: [`UnitNetworkCheck::check`] enters the very namespace
//! descriptor the observation read the identity from, on a scoped thread, and
//! requires that it holds exactly one link, the loopback `lo`, and no
//! main-table route whose output link is not `lo`. A `blackhole`, `prohibit`
//! or `unreachable` route has no output link, so the route decoder refuses
//! it and the check fails.
//!
//! The check is sound only when the kernel creates no fallback tunnel
//! devices in new namespaces: with `net.core.fb_tunnels_only_for_init_net`
//! at 0, loading `sit`, `ipip`, `ip_gre`, `ip6_tunnel` or `ip_vti` gives
//! every new namespace down devices such as `sit0` and `tunl0`. The startup
//! probe [`fb_tunnels_isolated`] closes admission unless the sysctl is at
//! least 1.

use std::fs;
use std::os::fd::BorrowedFd;
use std::path::Path;

use rustix::io::Errno;

use super::netlink::{
    consistent, in_namespace, links, NetlinkError, NetlinkSession, NetlinkTransport, ROUTE,
};
use super::{route, LinkKind, ObservedLink, ObservedRoute};

/// The sysctl that stops the kernel creating fallback tunnel devices in new
/// network namespaces.
pub const FB_TUNNELS_SYSCTL: &str = "/proc/sys/net/core/fb_tunnels_only_for_init_net";

/// Why the unit's network namespace was not shown to hold only `lo`.
///
/// Either class is KOE1 status 2 at the first observation; at the release
/// recheck a transport failure is barrier failure 6 and a change is 7 (R14
/// §3.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnitNetworkError {
    /// A netlink exchange failed in transit: a socket error other than a
    /// missing object, a receive timeout, a failed `setns`, or three torn
    /// dumps.
    #[error("the unit network namespace could not be read")]
    Transport,
    /// The namespace was read, and holds more than `lo` or a route off `lo`,
    /// or the kernel's answer was not one the check understands.
    #[error("the unit network namespace holds more than lo")]
    Changed,
}

/// The check that a unit's network namespace holds only `lo`.
pub trait UnitNetworkCheck {
    /// Check the network namespace `namespace` names.
    ///
    /// # Errors
    /// [`UnitNetworkError::Transport`] when the namespace could not be read
    /// in transit, and [`UnitNetworkError::Changed`] for anything else that
    /// stops it being shown to hold only `lo`.
    fn check(&self, namespace: BorrowedFd<'_>) -> Result<(), UnitNetworkError>;
}

/// [`UnitNetworkCheck`] over route netlink on a thread inside the namespace.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetlinkUnitNetwork;

impl UnitNetworkCheck for NetlinkUnitNetwork {
    fn check(&self, namespace: BorrowedFd<'_>) -> Result<(), UnitNetworkError> {
        classified(in_namespace(namespace, read_unit_view))
    }
}

/// What a unit namespace holds: its links and its main-table routes.
type UnitView = (Vec<ObservedLink>, Vec<ObservedRoute>);

/// Read the calling thread's namespace, again while a dump is torn.
fn read_unit_view() -> Result<UnitView, NetlinkError> {
    consistent(|| NetlinkSession::open(ROUTE).and_then(|session| unit_view(&session)))
}

/// The links, then the main-table routes of both families, of the session's
/// namespace.
fn unit_view<T: NetlinkTransport>(session: &NetlinkSession<T>) -> Result<UnitView, NetlinkError> {
    links(session).and_then(|links| {
        session
            .dump(route::routes())
            .and_then(route::observed_routes)
            .map(|routes| (links, routes))
    })
}

/// The check's verdict on what entering the namespace and reading it gave.
fn classified(
    entered: Result<Result<UnitView, NetlinkError>, NetlinkError>,
) -> Result<(), UnitNetworkError> {
    entered
        .and_then(std::convert::identity)
        .map_err(|error| classify(&error))
        .and_then(|(links, routes)| {
            only_loopback(&links, &routes)
                .then_some(())
                .ok_or(UnitNetworkError::Changed)
        })
}

/// R14's error classes: transit failures are transport, everything else,
/// including a missing object, is a change.
fn classify(error: &NetlinkError) -> UnitNetworkError {
    match error {
        NetlinkError::Io(errno) if *errno != Errno::NOENT => UnitNetworkError::Transport,
        // `consistent` returns it only after three torn reads.
        NetlinkError::Interrupted => UnitNetworkError::Transport,
        _ => UnitNetworkError::Changed,
    }
}

/// Whether `links` is exactly the loopback `lo`, and every route of `routes`
/// leaves through it.
fn only_loopback(links: &[ObservedLink], routes: &[ObservedRoute]) -> bool {
    match links {
        [only] => {
            only.kind == LinkKind::Loopback
                && only.name == "lo"
                && routes.iter().all(|route| route.link_index == only.index)
        }
        _ => false,
    }
}

/// The startup probe: whether the sysctl file at `path` holds a value of at
/// least 1. A failed read, or a value that is not a number, closes admission.
#[must_use]
pub fn fb_tunnels_isolated(path: &Path) -> bool {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .is_some_and(|value| value >= 1)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
