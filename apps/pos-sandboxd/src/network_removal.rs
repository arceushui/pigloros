//! Reporting the removal of a Local network (ADR-069 R14 N7).
//!
//! The execute path wraps each established connector in an
//! `OwnedConnector` tied to one `RemovalReport`. Dropping the connector
//! removes its network and records a failed removal, so every path that drops
//! the network, whichever it is, reports the result with the execution. The
//! report is fail closed: a connector still alive when it is read counts as a
//! removal that did not happen.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pos_reference::sandbox_provider_protocol::NetworkEndpointConnector;

use crate::{NetworkRemovalFailure, RemoveNetwork};

/// What one execution's connectors reported.
#[derive(Debug, Default)]
struct RemovalState {
    /// Connectors of the execution that were not dropped yet.
    owned: usize,
    /// The first removal failure.
    failure: Option<NetworkRemovalFailure>,
}

impl RemovalState {
    /// Keep `failure`, unless an earlier one is kept.
    fn keep(&mut self, failure: NetworkRemovalFailure) {
        self.failure.get_or_insert(failure);
    }
}

/// The first removal failure of one execution, collected from wherever its
/// network was dropped.
#[derive(Clone, Debug, Default)]
pub(crate) struct RemovalReport(Arc<Mutex<RemovalState>>);

impl RemovalReport {
    fn state(&self) -> MutexGuard<'_, RemovalState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keep `failure`, unless an earlier one is kept.
    pub(crate) fn record(&self, failure: NetworkRemovalFailure) {
        self.state().keep(failure);
    }

    /// The failure of the execution's network removal, leaving none.
    ///
    /// A connector that is still owned has not been removed, so it is a
    /// failure too: the report never reads "removed" for a network that may
    /// still exist.
    pub(crate) fn take(&self) -> Option<NetworkRemovalFailure> {
        let mut state = self.state();
        let still_owned = state.owned > 0;
        state.failure.take().or_else(|| {
            still_owned.then(|| {
                NetworkRemovalFailure::new("the network was still owned when the execution ended")
            })
        })
    }
}

/// A connector whose network is removed when it is dropped, with the result
/// recorded in the execution's `RemovalReport`.
#[derive(Debug)]
pub(crate) struct OwnedConnector<C: RemoveNetwork> {
    connector: C,
    report: RemovalReport,
}

impl<C: RemoveNetwork> OwnedConnector<C> {
    /// `connector`, whose removal result goes to `report`.
    pub(crate) fn new(connector: C, report: &RemovalReport) -> Self {
        report.state().owned += 1;
        Self {
            connector,
            report: report.clone(),
        }
    }
}

impl<C: NetworkEndpointConnector + RemoveNetwork> NetworkEndpointConnector for OwnedConnector<C> {
    fn connect(&mut self, endpoint: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        self.connector.connect(endpoint, timeout)
    }
}

impl<C: RemoveNetwork> Drop for OwnedConnector<C> {
    fn drop(&mut self) {
        let removed = self.connector.remove();
        let mut state = self.report.state();
        state.owned -= 1;
        if let Err(failure) = removed {
            state.keep(failure);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A connector whose removal fails when `fails`.
    struct Remover {
        fails: bool,
    }

    impl RemoveNetwork for Remover {
        fn remove(&mut self) -> Result<(), NetworkRemovalFailure> {
            if self.fails {
                Err(NetworkRemovalFailure::new("the kernel refused"))
            } else {
                Ok(())
            }
        }
    }

    impl NetworkEndpointConnector for Remover {
        fn connect(&mut self, _endpoint: SocketAddr, _timeout: Duration) -> io::Result<TcpStream> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }

    #[test]
    fn a_report_names_a_removal_that_failed_once_and_then_nothing() {
        let report = RemovalReport::default();
        drop(OwnedConnector::new(Remover { fails: false }, &report));
        assert_eq!(report.take(), None);
        drop(OwnedConnector::new(Remover { fails: true }, &report));
        assert_eq!(
            report.take(),
            Some(NetworkRemovalFailure::new("the kernel refused"))
        );
        assert_eq!(report.take(), None);
    }

    #[test]
    fn the_first_failure_is_the_one_kept() {
        let report = RemovalReport::default();
        report.record(NetworkRemovalFailure::new("first"));
        report.record(NetworkRemovalFailure::new("second"));
        drop(OwnedConnector::new(Remover { fails: true }, &report));
        assert_eq!(report.take(), Some(NetworkRemovalFailure::new("first")));
    }

    /// A network that is still owned when the report is read has not been
    /// removed, so the report never says it was.
    #[test]
    fn a_network_still_owned_is_a_failure_until_it_is_removed() {
        let report = RemovalReport::default();
        let owned = OwnedConnector::new(Remover { fails: false }, &report);
        assert!(report.take().is_some());
        drop(owned);
        assert_eq!(report.take(), None);
        // A recorded failure outranks the still-owned one.
        let owned = OwnedConnector::new(Remover { fails: false }, &report);
        report.record(NetworkRemovalFailure::new("recorded"));
        assert_eq!(report.take(), Some(NetworkRemovalFailure::new("recorded")));
        drop(owned);
    }

    #[test]
    fn an_owned_connector_connects_through_its_connector() {
        let report = RemovalReport::default();
        let mut owned = OwnedConnector::new(Remover { fails: false }, &report);
        let refused = owned.connect(SocketAddr::from(([127, 0, 0, 1], 9)), Duration::ZERO);
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }
}
