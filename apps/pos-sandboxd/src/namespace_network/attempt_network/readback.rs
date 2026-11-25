//! The readback of one attempt's established network (ADR-069 R14 §3.2,
//! steps 1, 5 to 9; steps 2 to 4 and 7 are [`NamespaceControl::observe`]).
//!
//! The attempt's connector holds the namespace descriptor the proxy uses, so
//! the record names that namespace. The firewall of the namespace is read
//! bracketed by `NFT_MSG_GETGEN` and its generation is recorded; the
//! attempt's slice of the host table is read through
//! [`EgressControl::readback_slice`], under the host change lock. The typed
//! [`ObservedNamespace`] must verify exactly against what the attempt was
//! installed with, and only then is it canonicalized into
//! `local-network-readback`.
//!
//! Steps 2 to 4 read the namespace through [`NamespaceControl::observe`],
//! which opens it by name, not through the held descriptor. Step 6 closes
//! that gap: the name must still bind the descriptor of step 1. It cannot
//! tell a namespace that was re-pinned to another and back again (A, B, A)
//! from one that never moved, which needs a privileged writer of the pin
//! directory.
//!
//! The release deadline bounds the host slice (step 5): it is checked before
//! each of its reads, but a read in flight waits at most `RECEIVE_TIMEOUT`
//! (10 s) per datagram, and `HostEgress::readback_slice` takes the change
//! lock before it checks the deadline, so the recheck's own remaining-time
//! check is what bounds the whole readback. Steps 1 to 4 and 6 have no
//! deadline of their own.

use std::os::fd::{AsFd, BorrowedFd};
use std::time::Instant;

use pos_reference::sandbox_provider_protocol::{
    LocalNetworkReadback, NamespaceIdentity, ReadbackFirewallBase, ReadbackFirewallChain,
    ReadbackFirewallHook, ReadbackFirewallPolicy, ReadbackFirewallRule, ReadbackPrefix,
    ReadbackRoute, ReadbackVethEnd,
};
use rustix::fs::{fstat, fstatfs};

use super::{NamespaceConnector, NetworkNamespaces};
use crate::namespace_network::host_egress::{EgressControl, EgressSlice, HostEgressError};
use crate::namespace_network::netlink::NetlinkError;
use crate::namespace_network::pinned::NSFS_MAGIC;
use crate::namespace_network::{
    FirewallBaseChain, FirewallChain, FirewallHook, FirewallRule, FirewallVerdict, IpPrefix,
    LinkKind, NamespaceControl, NamespaceName, NamespaceRoute, ObservedLink, ObservedNamespace,
};
use crate::{KernelIdentity, NetworkReadback, ReadbackError};

impl<C, E> NetworkReadback for NamespaceConnector<C, E>
where
    C: NamespaceControl<Error = NetlinkError>,
    E: EgressControl,
{
    fn readback(&self, deadline: Instant) -> Result<LocalNetworkReadback, ReadbackError> {
        let held = identity(self.namespace.as_fd())?;
        let observed = self
            .teardown
            .control
            .observe(&self.expected.name, &self.expected.host_link)
            .map_err(|error| netlink_failure(&error))?;
        let slice = self
            .teardown
            .egress
            .readback_slice(&self.teardown.attempt, deadline)
            .map_err(egress_failure)?;
        same_namespace(&self.namespaces, &self.expected.name, held)?;
        self.expected
            .verify(&observed)
            .map_err(|_| ReadbackError::Changed)?;
        assemble(held, &observed, slice).ok_or(ReadbackError::Changed)
    }
}

/// The class of a netlink failure in steps 2 to 5 (R14 §3.2 error classes,
/// [`NetlinkError::is_transport`]).
pub(super) fn netlink_failure(error: &NetlinkError) -> ReadbackError {
    if error.is_transport() {
        ReadbackError::Transport
    } else {
        ReadbackError::Changed
    }
}

/// The class of anything that fails in steps 1 and 6, which R14 lists as a
/// change only: the namespace is gone, re-pinned or unreadable.
pub(super) fn changed<E>(failure: E) -> ReadbackError {
    drop(failure);
    ReadbackError::Changed
}

/// The class of a host egress failure: its netlink failure's, or a change.
pub(super) fn egress_failure(error: HostEgressError) -> ReadbackError {
    match error {
        HostEgressError::Netlink(error) => netlink_failure(&error),
        _ => ReadbackError::Changed,
    }
}

/// The nsfs identity of the namespace `namespace` holds (R14 §3.2 step 1):
/// `[major, minor]` of its `st_dev` and its inode.
///
/// # Errors
/// A descriptor that is no nsfs file, whose device the kernel cannot have
/// issued, or that cannot be examined, is a change (R14 lists only steps 2
/// to 5 as transport).
pub(super) fn identity(namespace: BorrowedFd<'_>) -> Result<NamespaceIdentity, ReadbackError> {
    fstatfs(namespace)
        .map_err(changed)
        .and_then(|filesystem| {
            (i128::from(filesystem.f_type) == NSFS_MAGIC)
                .then_some(())
                .ok_or(ReadbackError::Changed)
        })
        .and_then(|()| fstat(namespace).map_err(changed))
        .and_then(|status| KernelIdentity::of(status.st_dev, status.st_ino).map_err(changed))
        .map(KernelIdentity::namespace)
}

/// Whether the pin `name` still names the namespace of identity `held` (R14
/// §3.2 step 6). A pin that is gone, is no namespace file, cannot be opened
/// or names another namespace is a change.
fn same_namespace(
    namespaces: &NetworkNamespaces,
    name: &NamespaceName,
    held: NamespaceIdentity,
) -> Result<(), ReadbackError> {
    let pinned = namespaces
        .open(name)
        .map_err(changed)?
        .ok_or(ReadbackError::Changed)?;
    if identity(pinned.as_fd()) == Ok(held) {
        Ok(())
    } else {
        Err(ReadbackError::Changed)
    }
}

/// The canonical `local-network-readback` of a verified `observed`, with the
/// identity of its namespace and the attempt's host-table `slice`. `None`
/// if `observed` lacks a part the record needs, which a verified read never
/// does.
pub(super) fn assemble(
    namespace: NamespaceIdentity,
    observed: &ObservedNamespace,
    slice: EgressSlice,
) -> Option<LocalNetworkReadback> {
    let loopback = observed
        .links
        .iter()
        .find(|link| link.kind == LinkKind::Loopback)?;
    let inner = observed
        .links
        .iter()
        .find(|link| matches!(link.kind, LinkKind::Veth { .. }))?;
    let [table] = observed.tables.as_slice() else {
        return None;
    };
    Some(
        LocalNetworkReadback {
            namespace,
            namespace_netnsid: u32::try_from(observed.namespace_netnsid).ok()?,
            host_netnsid: u32::try_from(observed.host_netnsid).ok()?,
            loopback_index: loopback.index,
            inner: veth_end(inner)?,
            host: veth_end(observed.host_link.as_ref()?)?,
            inner_addresses: observed
                .addresses
                .iter()
                .map(|address| prefix(address.address))
                .collect(),
            host_addresses: observed
                .host_addresses
                .iter()
                .map(|address| prefix(address.address))
                .collect(),
            routes: observed
                .routes
                .iter()
                .map(|observed| route(observed.route))
                .collect(),
            firewall_generation: observed.firewall_generation,
            chains: table.chains.iter().map(chain).collect(),
            egress_allowed: slice.allowed,
            egress_masqueraded: slice.masqueraded,
        }
        .canonicalized(),
    )
}

/// One end of the veth pair, whose peer and the peer's namespace are known.
fn veth_end(link: &ObservedLink) -> Option<ReadbackVethEnd> {
    let LinkKind::Veth {
        peer_index,
        peer_netnsid: Some(peer_netnsid),
    } = link.kind
    else {
        return None;
    };
    Some(ReadbackVethEnd {
        index: link.index,
        name: link.name.clone(),
        peer_index,
        peer_netnsid: u32::try_from(peer_netnsid).ok()?,
    })
}

const fn prefix(prefix: IpPrefix) -> ReadbackPrefix {
    ReadbackPrefix {
        address: prefix.address,
        length: prefix.length,
    }
}

const fn route(route: NamespaceRoute) -> ReadbackRoute {
    ReadbackRoute {
        destination: prefix(route.destination),
        gateway: route.gateway,
    }
}

fn chain(chain: &FirewallChain) -> ReadbackFirewallChain {
    ReadbackFirewallChain {
        name: chain.name.clone(),
        base: chain.base.map(base),
        rules: chain.rules.iter().copied().map(rule).collect(),
    }
}

pub(super) const fn base(base: FirewallBaseChain) -> ReadbackFirewallBase {
    ReadbackFirewallBase {
        hook: match base.hook {
            FirewallHook::Input => ReadbackFirewallHook::Input,
            FirewallHook::Forward => ReadbackFirewallHook::Forward,
            FirewallHook::Output => ReadbackFirewallHook::Output,
        },
        priority: base.priority,
        policy: match base.policy {
            FirewallVerdict::Accept => ReadbackFirewallPolicy::Accept,
            FirewallVerdict::Drop => ReadbackFirewallPolicy::Drop,
        },
    }
}

pub(super) const fn rule(rule: FirewallRule) -> ReadbackFirewallRule {
    match rule {
        FirewallRule::AcceptEstablished => ReadbackFirewallRule::AcceptEstablished,
        FirewallRule::AcceptNeighbourDiscovery => ReadbackFirewallRule::AcceptNeighbourDiscovery,
        FirewallRule::SendNeighbourDiscovery {
            destination,
            length,
        } => ReadbackFirewallRule::SendNeighbourDiscovery {
            destination,
            length,
        },
        FirewallRule::AcceptTcp(endpoint) => ReadbackFirewallRule::AcceptTcp(endpoint),
    }
}
