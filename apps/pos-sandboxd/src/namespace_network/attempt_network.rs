//! The Local network port over real attempt namespaces (#911): each
//! established network owns one slot of the reserved range, its namespace,
//! veth pair and firewall, read back before it is returned, and a connector
//! that opens every connection from inside that namespace.
//!
//! Every attempt also gets host egress (`host_egress`) to exactly its
//! endpoints once its namespace is read back, and loses it first on teardown.
//!
//! Teardown is RAII. Dropping the connector removes the namespace and frees
//! the slot. A removal that fails quarantines the slot and closes the port:
//! every later establishment fails, naming the slot, until restart
//! reconciliation removes the remaining state (ADR-069 §1: an
//! ineffective property closes admission).

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use pos_reference::sandbox_provider_protocol::NetworkEndpointConnector;
use tokio::runtime::RuntimeFlavor;

use super::host_egress::{AttemptEgress, EgressControl, HostEgress, HostEgressError};
use super::netlink::{in_namespace, NetlinkError};
use super::pinned::NetworkNamespaces;
use super::{
    establish_namespace, EstablishError, ExpectedNamespace, NamespaceControl, NetworkPlanError,
    NetworkRange,
};
use crate::{EstablishedNetwork, LocalNetworkPort};

/// Which attempt holds each slot, and the first slot whose namespace could
/// not be removed.
#[derive(Debug, Default)]
struct Holders {
    attempts: BTreeMap<u16, [u8; 16]>,
    quarantined: Option<(u16, String)>,
}

/// The slots of the reserved range that established networks hold.
#[derive(Debug)]
struct Slots {
    count: u16,
    holders: Mutex<Holders>,
}

impl Slots {
    fn holders(&self) -> std::sync::MutexGuard<'_, Holders> {
        self.holders.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take the lowest free slot for `attempt_id`.
    ///
    /// # Errors
    /// Fails once a slot is quarantined, while `attempt_id` holds a slot
    /// already, and when every slot is taken.
    fn take(self: &Arc<Self>, attempt_id: [u8; 16]) -> Result<SlotLease, AttemptNetworkError> {
        let mut holders = self.holders();
        if let Some((slot, reason)) = &holders.quarantined {
            return Err(AttemptNetworkError::Quarantined {
                slot: *slot,
                reason: reason.clone(),
            });
        }
        if holders.attempts.values().any(|held| *held == attempt_id) {
            return Err(AttemptNetworkError::InUse);
        }
        let slot = (0..self.count)
            .find(|slot| !holders.attempts.contains_key(slot))
            .ok_or(AttemptNetworkError::Exhausted)?;
        holders.attempts.insert(slot, attempt_id);
        drop(holders);
        Ok(SlotLease {
            slots: Arc::clone(self),
            slot,
            quarantined: false,
        })
    }
}

/// One taken slot, freed when dropped unless it was quarantined.
#[derive(Debug)]
struct SlotLease {
    slots: Arc<Slots>,
    slot: u16,
    quarantined: bool,
}

impl SlotLease {
    /// Keep the slot taken, because its namespace could not be removed, and
    /// close the port with `error`.
    fn quarantine(&mut self, reason: String) {
        self.quarantined = true;
        self.slots
            .holders()
            .quarantined
            .get_or_insert((self.slot, reason));
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        if !self.quarantined {
            self.slots.holders().attempts.remove(&self.slot);
        }
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
    /// The host cannot give the attempt egress to its endpoints.
    #[error("the attempt's host egress failed")]
    Egress(#[source] HostEgressError),
    /// The attempt holds a slot already.
    #[error("the attempt holds an attempt network already")]
    InUse,
    /// A namespace of the attempt's name exists, so this establishment
    /// installed nothing and removes nothing.
    #[error("an attempt namespace of this name exists")]
    Exists,
    /// The namespace of `slot` could not be removed, so no attempt network
    /// is established until restart reconciliation removes it.
    #[error("the attempt namespace of slot {slot} could not be removed ({reason}); restart reconciliation must remove it")]
    Quarantined {
        /// The quarantined slot.
        slot: u16,
        /// Why its namespace could not be removed.
        reason: String,
    },
}

/// The Local network port over attempt namespaces that `control` installs,
/// addressed from `range` and pinned in `namespaces`.
#[derive(Debug)]
pub struct NamespacedLocalNetwork<C, E = HostEgress> {
    control: Arc<C>,
    egress: Arc<E>,
    namespaces: NetworkNamespaces,
    range: NetworkRange,
    slots: Arc<Slots>,
    /// Whether an egress probe of this port is running: at most one runs,
    /// whoever calls it, since every probe uses the same reserved names.
    probing: AtomicBool,
}

impl<C, E> NamespacedLocalNetwork<C, E> {
    /// Attempt networks of `range`, at most one per slot, installed through
    /// `control`, given host egress through `egress` and pinned in
    /// `namespaces`, the directory `control` pins them in.
    #[must_use]
    pub fn new(control: C, egress: E, namespaces: NetworkNamespaces, range: NetworkRange) -> Self {
        let count = u16::try_from(range.slots()).unwrap_or(u16::MAX);
        Self {
            control: Arc::new(control),
            egress: Arc::new(egress),
            namespaces,
            range,
            slots: Arc::new(Slots {
                count,
                holders: Mutex::new(Holders::default()),
            }),
            probing: AtomicBool::new(false),
        }
    }
}

/// Removes one attempt's egress and namespace and frees its slot when
/// dropped.
#[derive(Debug)]
struct Teardown<C: NamespaceControl, E: EgressControl> {
    control: Arc<C>,
    egress: Arc<E>,
    attempt: AttemptEgress,
    slot: SlotLease,
}

impl<C: NamespaceControl, E: EgressControl> Teardown<C, E> {
    /// Remove the egress, then the namespace, attempting both, and report
    /// the first failure.
    fn remove(&self) -> Result<(), String> {
        let egress = self
            .egress
            .remove(&self.attempt)
            .map_err(|error| error.to_string());
        let namespace = self
            .control
            .remove(&self.attempt.namespace, &self.attempt.host_link)
            .map_err(|error| error.to_string());
        egress.and(namespace)
    }
}

impl<C: NamespaceControl, E: EgressControl> Drop for Teardown<C, E> {
    fn drop(&mut self) {
        // Removal waits on the kernel, a few netlink replies each bounded by
        // the receive timeout. On a Tokio worker it gives the worker's other
        // tasks to another thread first.
        let removed = match tokio::runtime::Handle::try_current() {
            Ok(runtime) if runtime.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| self.remove())
            }
            _ => self.remove(),
        };
        if let Err(reason) = removed {
            self.slot.quarantine(reason);
        }
    }
}

/// Opens every connection from a thread inside one attempt's namespace, and
/// removes the namespace when dropped.
#[derive(Debug)]
pub struct NamespaceConnector<C: NamespaceControl, E: EgressControl = HostEgress> {
    namespace: OwnedFd,
    _teardown: Teardown<C, E>,
}

impl<C: NamespaceControl, E: EgressControl> NetworkEndpointConnector for NamespaceConnector<C, E> {
    fn connect(&mut self, endpoint: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        // An IPv4-mapped endpoint is reached as the IPv4 endpoint it maps,
        // as the plan admitted it.
        let endpoint = SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port());
        // The socket keeps the namespace it was created in after the thread
        // that created it ends.
        in_namespace(self.namespace.as_fd(), || {
            TcpStream::connect_timeout(&endpoint, timeout)
        })
        .map_err(io::Error::other)
        .and_then(std::convert::identity)
    }
}

impl<C, E> LocalNetworkPort for NamespacedLocalNetwork<C, E>
where
    C: NamespaceControl<Error = NetlinkError> + Send + Sync + 'static,
    E: EgressControl + Send + Sync + 'static,
{
    type Connector = NamespaceConnector<C, E>;
    type Error = AttemptNetworkError;

    fn establish(
        &self,
        attempt_id: [u8; 16],
        endpoints: &[SocketAddr],
    ) -> Result<EstablishedNetwork<NamespaceConnector<C, E>>, AttemptNetworkError> {
        self.connector(attempt_id, endpoints)
            .map(|connector| EstablishedNetwork::new(attempt_id, connector))
    }
}

impl<C, E> NamespacedLocalNetwork<C, E>
where
    C: NamespaceControl<Error = NetlinkError>,
    E: EgressControl,
{
    /// Establish the namespace of `attempt_id`, reaching exactly
    /// `endpoints`, in the lowest free slot, and return the connector that
    /// owns it.
    fn connector(
        &self,
        attempt_id: [u8; 16],
        endpoints: &[SocketAddr],
    ) -> Result<NamespaceConnector<C, E>, AttemptNetworkError> {
        // Host egress sees each endpoint as the plan does: an IPv4-mapped
        // IPv6 endpoint is the IPv4 endpoint it maps.
        let endpoints: Vec<SocketAddr> = endpoints
            .iter()
            .map(|endpoint| SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()))
            .collect();
        let endpoints = endpoints.as_slice();
        let mut slot = self.slots.take(attempt_id)?;
        let expected =
            ExpectedNamespace::for_attempt(attempt_id, &self.range, slot.slot, endpoints)
                .map_err(AttemptNetworkError::Plan)?;
        self.egress
            .admit(endpoints)
            .map_err(AttemptNetworkError::Egress)?;
        // An existing namespace of this name belongs to an earlier run of the
        // attempt that only restart reconciliation may remove: installing
        // would fail and the cleanup after it would delete that namespace.
        if self
            .namespaces
            .open(&expected.name)
            .map_err(AttemptNetworkError::Open)?
            .is_some()
        {
            return Err(AttemptNetworkError::Exists);
        }
        establish_namespace(&*self.control, &expected).map_err(|error| {
            // What could not be removed still holds the slot's names.
            if let Some(removal) = &error.removal {
                slot.quarantine(removal.to_string());
            }
            AttemptNetworkError::Establish(error)
        })?;
        let teardown = Teardown {
            control: Arc::clone(&self.control),
            egress: Arc::clone(&self.egress),
            attempt: AttemptEgress {
                namespace: expected.name,
                host_link: expected.host_link,
                endpoints: endpoints.to_vec(),
            },
            slot,
        };
        // Dropping the teardown on a failure removes whatever was installed.
        self.egress
            .install(&teardown.attempt)
            .map_err(AttemptNetworkError::Egress)?;
        self.namespaces
            .open(&teardown.attempt.namespace)
            .and_then(|namespace| namespace.ok_or(NetlinkError::Io(rustix::io::Errno::NOENT)))
            .map(|namespace| NamespaceConnector {
                namespace,
                _teardown: teardown,
            })
            .map_err(AttemptNetworkError::Open)
    }
}

mod probe;

pub(super) use probe::PROBE_HOST_LINK;
pub use probe::{EgressProbe, EgressProbeError, InvalidEgressProbe, LocalEgressProbe};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
