//! The Local network port over real attempt namespaces (#911): each
//! established network owns one slot of the reserved range, its namespace,
//! veth pair and firewall, read back before it is returned, and a connector
//! that opens every connection from inside that namespace.
//!
//! Teardown is RAII. Dropping the connector removes the namespace and frees
//! the slot; a removal that fails leaves the state for restart
//! reconciliation, which sweeps every `piglor-` namespace and host link.

use std::collections::BTreeSet;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use pos_reference::sandbox_provider_protocol::NetworkEndpointConnector;

use super::netlink::{in_namespace, NetlinkError};
use super::pinned::NetworkNamespaces;
use super::{
    establish_namespace, EstablishError, ExpectedNamespace, LinkName, NamespaceControl,
    NamespaceName, NetworkPlanError, NetworkRange,
};
use crate::{EstablishedNetwork, LocalNetworkPort};

/// The slots of the reserved range that established networks hold.
#[derive(Debug)]
struct Slots {
    count: u16,
    taken: Mutex<BTreeSet<u16>>,
}

impl Slots {
    /// Take the lowest free slot.
    fn take(self: &Arc<Self>) -> Option<SlotLease> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = (0..self.count).find(|slot| !taken.contains(slot))?;
        taken.insert(slot);
        Some(SlotLease {
            slots: Arc::clone(self),
            slot,
        })
    }
}

/// One taken slot, freed when dropped.
#[derive(Debug)]
struct SlotLease {
    slots: Arc<Slots>,
    slot: u16,
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.slots
            .taken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.slot);
    }
}

/// Why an attempt network could not be established.
#[derive(Debug, thiserror::Error)]
pub enum AttemptNetworkError {
    /// Every slot of the reserved range is taken.
    #[error("every slot of the reserved attempt range is taken")]
    Exhausted,
    /// The endpoints cannot form an attempt namespace.
    #[error("the attempt's endpoints cannot form its namespace")]
    Plan(#[source] NetworkPlanError),
    /// The namespace could not be established and read back.
    #[error("the attempt namespace could not be established")]
    Establish(#[source] EstablishError<NetlinkError>),
    /// The established namespace could not be opened for its connector.
    #[error("the attempt namespace could not be opened")]
    Open(#[source] NetlinkError),
}

/// The Local network port over attempt namespaces that `control` installs,
/// addressed from `range` and pinned in `namespaces`.
#[derive(Debug)]
pub struct NamespacedLocalNetwork<C> {
    control: Arc<C>,
    namespaces: NetworkNamespaces,
    range: NetworkRange,
    slots: Arc<Slots>,
}

impl<C> NamespacedLocalNetwork<C> {
    /// Attempt networks of `range`, at most one per slot, installed through
    /// `control` and pinned in `namespaces`, the directory `control` pins
    /// them in.
    #[must_use]
    pub fn new(control: C, namespaces: NetworkNamespaces, range: NetworkRange) -> Self {
        let count = u16::try_from(range.slots()).unwrap_or(u16::MAX);
        Self {
            control: Arc::new(control),
            namespaces,
            range,
            slots: Arc::new(Slots {
                count,
                taken: Mutex::new(BTreeSet::new()),
            }),
        }
    }
}

/// Removes one attempt's namespace and frees its slot when dropped.
#[derive(Debug)]
struct Teardown<C: NamespaceControl> {
    control: Arc<C>,
    name: NamespaceName,
    host_link: LinkName,
    _slot: SlotLease,
}

impl<C: NamespaceControl> Drop for Teardown<C> {
    fn drop(&mut self) {
        // A removal that fails leaves the namespace to restart
        // reconciliation; the slot is free again either way, because a
        // reinstallation in it would fail on the remaining host link.
        self.control.remove(&self.name, &self.host_link).ok();
    }
}

/// Opens every connection from a thread inside one attempt's namespace, and
/// removes the namespace when dropped.
#[derive(Debug)]
pub struct NamespaceConnector<C: NamespaceControl> {
    namespace: OwnedFd,
    _teardown: Teardown<C>,
}

impl<C: NamespaceControl> NetworkEndpointConnector for NamespaceConnector<C> {
    fn connect(&mut self, endpoint: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        // The socket keeps the namespace it was created in after the thread
        // that created it ends.
        in_namespace(self.namespace.as_fd(), || {
            TcpStream::connect_timeout(&endpoint, timeout)
        })
        .map_err(io::Error::other)
        .and_then(std::convert::identity)
    }
}

impl<C> LocalNetworkPort for NamespacedLocalNetwork<C>
where
    C: NamespaceControl<Error = NetlinkError> + Send + Sync + 'static,
{
    type Connector = NamespaceConnector<C>;
    type Error = AttemptNetworkError;

    fn establish(
        &self,
        attempt_id: [u8; 16],
        endpoints: &[SocketAddr],
    ) -> Result<EstablishedNetwork<NamespaceConnector<C>>, AttemptNetworkError> {
        self.connector(attempt_id, endpoints)
            .map(|connector| EstablishedNetwork::new(attempt_id, connector))
    }
}

impl<C> NamespacedLocalNetwork<C>
where
    C: NamespaceControl<Error = NetlinkError>,
{
    /// Establish the namespace of `attempt_id`, reaching exactly
    /// `endpoints`, in the lowest free slot, and return the connector that
    /// owns it.
    fn connector(
        &self,
        attempt_id: [u8; 16],
        endpoints: &[SocketAddr],
    ) -> Result<NamespaceConnector<C>, AttemptNetworkError> {
        let slot = self.slots.take().ok_or(AttemptNetworkError::Exhausted)?;
        let expected =
            ExpectedNamespace::for_attempt(attempt_id, &self.range, slot.slot, endpoints)
                .map_err(AttemptNetworkError::Plan)?;
        establish_namespace(&*self.control, &expected).map_err(AttemptNetworkError::Establish)?;
        let teardown = Teardown {
            control: Arc::clone(&self.control),
            name: expected.name,
            host_link: expected.host_link,
            _slot: slot,
        };
        self.namespaces
            .open(&teardown.name)
            .and_then(|namespace| namespace.ok_or(NetlinkError::Io(rustix::io::Errno::NOENT)))
            .map(|namespace| NamespaceConnector {
                namespace,
                _teardown: teardown,
            })
            .map_err(AttemptNetworkError::Open)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
